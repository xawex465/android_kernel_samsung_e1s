// SPDX-License-Identifier: GPL-2.0-only
/* exynos_drm_decon.c
 *
 * Copyright (C) 2018 Samsung Electronics Co.Ltd
 * Authors:
 *	Hyung-jun Kim <hyungjun07.kim@samsung.com>
 *	Seong-gyu Park <seongyu.park@samsung.com>
 *
 * This program is free software; you can redistribute  it and/or modify it
 * under  the terms of  the GNU General  Public License as published by the
 * Free Software Foundation;  either version 2 of the  License, or (at your
 * option) any later version.
 *
 */
#include <drm/drm_drv.h>
#include <drm/drm_atomic.h>
#include <drm/drm_atomic_helper.h>
#include <exynos_display_common.h>
#include <drm/drm_modeset_helper_vtables.h>
#include <drm/drm_vblank.h>
#include <drm/drm_blend.h>
#include <drm/drm_bridge.h>

#include <linux/clk.h>
#include <linux/component.h>
#include <linux/kernel.h>
#include <linux/kthread.h>
#include <linux/of.h>
#include <linux/of_address.h>
#include <linux/of_irq.h>
#include <linux/of_device.h>
#include <linux/of_gpio.h>
#include <linux/platform_device.h>
#include <linux/irq.h>
#include <linux/pm_runtime.h>
#include <linux/console.h>
#include <linux/pinctrl/consumer.h>

#include <dpu_trace.h>
#include <video/videomode.h>

#include <exynos_drm_crtc.h>
#include <exynos_drm_plane.h>
#include <exynos_drm_dpp.h>
#include <exynos_drm_drv.h>
#include <exynos_drm_fb.h>
#include <exynos_drm_decon.h>
#include <exynos_drm_writeback.h>
#include <exynos_drm_dqe.h>
#if IS_ENABLED(CONFIG_DRM_SAMSUNG_DP)
#include <exynos_drm_dp.h>
#endif
#include <exynos_drm_profiler.h>
#include <exynos_drm_freq_hop.h>
#include <exynos_drm_recovery.h>
#include <exynos_drm_partial.h>
#include <exynos_drm_tui.h>
#include <exynos_drm_sfr_dma.h>
#include <exynos_drm_hibernation.h>

#include <soc/samsung/exynos-pd.h>

#include <decon_cal.h>
#include <regs-decon.h>

#if IS_ENABLED(CONFIG_DRM_MCD_COMMON)
#include <mcd_drm_helper.h>
#endif

struct decon_device *decon_drvdata[MAX_DECON_CNT];
EXPORT_SYMBOL_FOR_DPU_TESTS_ONLY(decon_drvdata);

static int dpu_decon_log_level = 6;
module_param(dpu_decon_log_level, int, 0600);
MODULE_PARM_DESC(dpu_decon_log_level, "log level for dpu decon [default : 6]");

#define decon_info(decon, fmt, ...)	\
dpu_pr_info(drv_name((decon)), (decon)->id, dpu_decon_log_level, fmt, ##__VA_ARGS__)

#define decon_warn(decon, fmt, ...)	\
dpu_pr_warn(drv_name((decon)), (decon)->id, dpu_decon_log_level, fmt, ##__VA_ARGS__)

#define decon_err(decon, fmt, ...)	\
dpu_pr_err(drv_name((decon)), (decon)->id, dpu_decon_log_level, fmt, ##__VA_ARGS__)

#define decon_debug(decon, fmt, ...)	\
dpu_pr_debug(drv_name((decon)), (decon)->id, dpu_decon_log_level, fmt, ##__VA_ARGS__)

#define SHADOW_UPDATE_TIMEOUT_US	(300 * USEC_PER_MSEC) /* 300ms */

static const struct of_device_id decon_driver_dt_match[] = {
	{.compatible = "samsung,exynos-decon"},
	{},
};
MODULE_DEVICE_TABLE(of, decon_driver_dt_match);

static void __acquire_console_lock(bool *lock)
{
	*lock = console_trylock() ? true : false;
}

static void __release_console_lock(bool *lock)
{
	if (*lock)
		console_unlock();

	*lock = false;
}

void decon_dump(struct exynos_drm_crtc *exynos_crtc)
{
	int i;
	bool acquired = false;
	struct decon_device *d;
	struct decon_device *decon;
	struct dsim_device *dsim = NULL;

	if (!exynos_crtc)
		return;

	decon = exynos_crtc->ctx;

	/* add connector dump */
	for (i = 0; i < REGS_DECON_ID_MAX; ++i) {
		d = get_decon_drvdata(i);
		if (!d)
			continue;

		if (d->state != DECON_STATE_ON) {
			decon_info(d, "DECON disabled(%d)\n", d->state);
			continue;
		}

		__acquire_console_lock(&acquired);
		dsim = decon_get_dsim(d);
		if (dsim)
			dsim_dump(dsim);

		__decon_dump(d->id, &d->regs, d->config.dsc.enabled);
		exynos_dqe_dump(d->crtc->dqe);
		wb_dump(decon_get_wb(d));
		__release_console_lock(&acquired);
	}

	__acquire_console_lock(&acquired);
	dpp_dump(decon->dpp, decon->dpp_cnt);
	__release_console_lock(&acquired);


#if IS_ENABLED(CONFIG_DRM_SAMSUNG_DP)
	__acquire_console_lock(&acquired);
	if (decon_get_encoder(decon, DRM_MODE_ENCODER_TMDS))
		dp_debug_dump();
	__release_console_lock(&acquired);
#endif

	__acquire_console_lock(&acquired);
	if (decon->rcd)
		rcd_dump(decon->rcd);
	__release_console_lock(&acquired);
}
EXPORT_SYMBOL_FOR_DPU_TESTS_ONLY(decon_dump);

__weak void decon_reg_set_rcd_enable(u32 id, bool en) {}

static bool __is_recovery_supported(struct decon_device *decon)
{
	enum recovery_state state = exynos_recovery_get_state(decon);

	return ((state == RECOVERY_NOT_SUPPORTED) ? false : true);
}

#if defined(CONFIG_EXYNOS_UEVENT_RECOVERY_SOLUTION)
static bool __is_recovery_uevent(struct decon_device *decon)
{
	bool sent = false;
	enum recovery_state state = exynos_recovery_get_state(decon);

	if (state == RECOVERY_UEVENT)
		sent = true;

	return sent;
}

static bool __is_recovery_uevent_clear(struct decon_device *decon)
{
	bool sent = false;
	enum recovery_state state = exynos_recovery_get_state(decon);

	if (state == RECOVERY_UEVENT_CLEAR)
		sent = true;

	return sent;
}
#endif

static bool __is_recovery_begin(struct decon_device *decon)
{
	bool begin = false;
	enum recovery_state state = exynos_recovery_get_state(decon);

	if ((state == RECOVERY_TRIGGER) || (state == RECOVERY_BEGIN))
		begin = true;

#if defined(CONFIG_EXYNOS_UEVENT_RECOVERY_SOLUTION)
	if (!begin &&
		(state == RECOVERY_UEVENT || state == RECOVERY_UEVENT_CLEAR))
		begin = true;
#endif

	return begin;
}

static bool __is_recovery_running(struct decon_device *decon)
{
	bool recovering = false;
	enum recovery_state state = exynos_recovery_get_state(decon);

	if ((__is_recovery_begin(decon)) || (state == RECOVERY_RESTORE))
		recovering = true;

	return recovering;
}

void decon_emergency_off(struct exynos_drm_crtc *exynos_crtc)
{
	struct decon_device *decon = exynos_crtc->ctx;
	queue_work(system_highpri_wq, &decon->off_work);
}

int decon_trigger_recovery(struct exynos_drm_crtc *exynos_crtc, char *mode)
{
	struct decon_device *decon = exynos_crtc->ctx;
	struct exynos_recovery *recovery = &decon->recovery;

	if (!__is_recovery_supported(decon))
		goto exit;

	if (__is_recovery_running(decon))
		return 0;

	exynos_recovery_set_state(decon, RECOVERY_TRIGGER);
	if (exynos_recovery_set_mode(decon, mode) < 0) {
		exynos_recovery_set_state(decon, RECOVERY_IDLE);
		goto exit;
	}

	queue_work(system_highpri_wq, &recovery->work);

	return 0;
exit:
	decon_err(decon, "not a trigger condition (%s)\n", mode);
	return -EINVAL;
}
EXPORT_SYMBOL(decon_trigger_recovery);

bool decon_read_recovering(struct exynos_drm_crtc *exynos_crtc)
{
	struct decon_device *decon = exynos_crtc->ctx;

	return __is_recovery_running(decon);
}

static inline u32 win_start_pos(int x, int y)
{
	return (WIN_STRPTR_Y_F(y) | WIN_STRPTR_X_F(x));
}

static inline u32 win_end_pos(int x2, int y2)
{
	return (WIN_ENDPTR_Y_F(y2 - 1) | WIN_ENDPTR_X_F(x2 - 1));
}

/*
 * This function can be used in cases where all windows are disabled
 * but need something to be rendered for display. This will make a black
 * frame via decon using a single window with color map enabled.
 */
static void decon_set_color_map(struct decon_device *decon, u32 win_id,
				u32 hactive, u32 vactive, u32 colormap)
{
	struct decon_window_regs win_info;

	decon_debug(decon, "+ color(%#x)\n", colormap);

	memset(&win_info, 0, sizeof(struct decon_window_regs));
	win_info.start_pos = win_start_pos(0, 0);
	win_info.end_pos = win_end_pos(hactive, vactive);
	win_info.start_time = 0;
	win_info.colormap = colormap;
	win_info.blend = DECON_BLENDING_NONE;
	decon_reg_set_window_control(decon->id, win_id, &win_info, true);

	decon_debug(decon, "-\n");
}

static inline bool decon_is_te_enabled(const struct decon_device *decon)
{
	return (decon->config.mode.op_mode == DECON_COMMAND_MODE) &&
			(decon->config.mode.trig_mode == DECON_HW_TRIG);
}

static inline bool decon_is_svsync_supported(const struct decon_device *decon)
{
	return ((decon->config.out_type & DECON_OUT_DSI) &&
		(decon->config.mode.op_mode == DECON_COMMAND_MODE) &&
		decon->config.svsync_time);
}

static void
decon_pending_clear_before_enable_irq(struct exynos_drm_crtc *crtc)
{
	struct decon_device *decon = crtc->ctx;
	u32 clr;

	if (!crtc->d.eint_pend) {
		enable_irq(decon->irq_te);
		return;
	}

	clr = 0x1 << decon->pnum_te;

	if (!!readl(crtc->d.eint_pend))
		writel(clr, crtc->d.eint_pend);

	enable_irq(decon->irq_te);
}

static int decon_enable_vblank(struct exynos_drm_crtc *crtc)
{
	struct decon_device *decon = crtc->ctx;

	decon_debug(decon, "+\n");

	exynos_hibernation_queue_exit_work(crtc);
	if (decon_is_te_enabled(decon))
		decon_pending_clear_before_enable_irq(crtc);
	else /* use framestart interrupt to track vsyncs */
		enable_irq(decon->irq_fs);

	DPU_EVENT_LOG("VBLANK_ENABLE", crtc, 0, NULL);

	decon_debug(decon, "-\n");
	return 0;
}

static void decon_disable_vblank(struct exynos_drm_crtc *crtc)
{
	struct decon_device *decon = crtc->ctx;

	decon_debug(decon, "+\n");

	if (decon_is_te_enabled(decon))
		disable_irq_nosync(decon->irq_te);
	else
		disable_irq_nosync(decon->irq_fs);

	DPU_EVENT_LOG("VBLANK_DISABLE", crtc, 0, NULL);

	decon_debug(decon, "-\n");
}

static enum exynos_drm_writeback_type
decon_get_wb_type(struct drm_crtc_state *new_crtc_state)
{
	int i;
	struct drm_atomic_state *state = new_crtc_state->state;
	struct drm_connector_state *conn_state;
	struct drm_connector *conn;
	struct exynos_drm_writeback_state *wb_state;

	for_each_new_connector_in_state(state, conn, conn_state, i) {
		if (!(new_crtc_state->connector_mask &
					drm_connector_mask(conn)))
			continue;
		if (conn->connector_type == DRM_MODE_CONNECTOR_WRITEBACK) {
			wb_state = to_exynos_wb_state(conn_state);
			return wb_state->type;
		}
	}
	return EXYNOS_WB_NONE;
}

static void decon_get_crc_data(struct exynos_drm_crtc *exynos_crtc)
{
	struct decon_device *decon = exynos_crtc->ctx;
	u32 crc_data[3];

	decon_reg_get_crc_data(decon->id, crc_data);
	drm_crtc_add_crc_entry(&exynos_crtc->base, true, 0, crc_data);

	decon_debug(decon, "0x%08x, 0x%08x, 0x%08x\n", crc_data[0],
		 crc_data[1], crc_data[2]);

	exynos_crtc->crc_state = EXYNOS_DRM_CRC_REQ;
	decon_reg_set_start_crc(decon->id, 0);
}

static void decon_mode_update_bts_fps(struct exynos_drm_crtc *exynos_crtc)
{
	const struct drm_crtc *crtc = &exynos_crtc->base;
	struct exynos_drm_crtc_state *new_exynos_crtc_state =
				to_exynos_crtc_state(crtc->state);
	u32 bts_fps = crtc_get_bts_fps(crtc);

	exynos_crtc->bts->fps = max(bts_fps, new_exynos_crtc_state->boost_bts_fps);
#if IS_ENABLED(CONFIG_DRM_MCD_COMMON)
	{
		struct decon_device *decon = exynos_crtc->ctx;
		static u32 prev_bts_fps;
		static u32 prev_boost_bts_fps;

		if (decon->id == 0) {
			if (prev_bts_fps != exynos_crtc->bts->fps ||
					prev_boost_bts_fps != new_exynos_crtc_state->boost_bts_fps) {
				if (!new_exynos_crtc_state->boost_bts_fps)
					decon_info(decon, "bts.fps:%d\n", decon->bts.fps);
				else
					decon_info(decon, "bts.fps:%d(bts_fps:%d boost:%d)\n",
							decon->bts.fps, bts_fps,
							new_exynos_crtc_state->boost_bts_fps);
			}
			prev_bts_fps = exynos_crtc->bts->fps;
			prev_boost_bts_fps = new_exynos_crtc_state->boost_bts_fps;
		}
	}
#endif
}

static void decon_mode_update_bts(struct decon_device *decon,
				  const struct drm_display_mode *mode)
{
	struct videomode vm;
	const struct drm_crtc *crtc = &decon->crtc->base;
	const struct exynos_drm_crtc_state *exynos_crtc_state =
					to_exynos_crtc_state(crtc->state);
	int i;

	drm_display_mode_to_videomode(mode, &vm);

	decon->bts.vbp = vm.vback_porch;
	decon->bts.vfp = vm.vfront_porch;
	decon->bts.vsa = vm.vsync_len;
	decon_mode_update_bts_fps(decon->crtc);

	/* the bts.win_config should be intialized only at full modeset */
	if (!exynos_crtc_state->seamless_modeset) {
		for (i = 0; i < decon->win_cnt; i++) {
			decon->bts.win_config[i].state = DPU_WIN_STATE_DISABLED;
			decon->bts.win_config[i].dbg_dma_addr = 0;
		}
	}
}

static void decon_update_config(struct decon_config *config,
				const struct drm_display_mode *mode,
				const struct exynos_display_mode *exynos_mode)
{
	bool is_vid_mode;

	config->image_width = mode->hdisplay;
	config->image_height = mode->vdisplay;
#if IS_ENABLED(CONFIG_DRM_MCD_COMMON)
	config->fps = drm_mode_vrefresh(mode) * max_t(typeof(mode->vscan), mode->vscan, 1);
#else
	config->fps = drm_mode_vrefresh(mode);
#endif
	if (!exynos_mode) {
		struct decon_device *decon =
			container_of(config, struct decon_device, config);

		decon_debug(decon, "no private mode config\n");

		if (config->out_type & DECON_OUT_DP) {
			pr_err("DSC config is already done\n");
			return;
		}

		/* valid defaults (ex. for writeback) */
		config->dsc.enabled = false;
		config->out_bpc = 8; /* This is only used in DQE dither. */
		return;
	}

	config->dsc.enabled = exynos_mode->dsc.enabled;
	if (exynos_mode->dsc.enabled) {
		config->dsc.dsc_count = exynos_mode->dsc.dsc_count;
		config->dsc.slice_count = exynos_mode->dsc.slice_count;
		config->dsc.slice_height = exynos_mode->dsc.slice_height;
		config->dsc.slice_width = DIV_ROUND_UP(config->image_width,
				config->dsc.slice_count);
		memcpy(&config->dsc_cfg, &exynos_mode->dsc_cfg,
				sizeof(struct drm_dsc_config));
	}

	is_vid_mode = (exynos_mode->mode_flags & MIPI_DSI_MODE_VIDEO) != 0;
	config->mode.op_mode = is_vid_mode ? DECON_VIDEO_MODE : DECON_COMMAND_MODE;

	config->out_bpc = exynos_mode->bpc;

	config->mode.lp_mode = exynos_mode->is_lp_mode ? DECON_ENTER_LP : DECON_NORMAL;
}

static int decon_check_seamless_modeset(struct exynos_drm_crtc *exynos_crtc,
		struct drm_crtc_state *crtc_state,
		const struct exynos_drm_connector_state *exynos_conn_state)
{
	struct exynos_drm_crtc_state *exynos_crtc_state =
					to_exynos_crtc_state(crtc_state);

	if (!exynos_conn_state->seamless_modeset)
		return 0;

	/*
	 * If it needs to check whether to change the display mode seamlessly
	 * for decon, please add to here.
	 */
	exynos_crtc_state->seamless_modeset =
		exynos_conn_state->seamless_modeset;
	crtc_state->mode_changed = false;

	return 0;
}

static int decon_check_modeset(struct exynos_drm_crtc *exynos_crtc,
		struct drm_crtc_state *crtc_state)
{
	struct drm_atomic_state *state = crtc_state->state;
	const struct decon_device *decon = exynos_crtc->ctx;
	const struct exynos_drm_connector_state *exynos_conn_state;

	exynos_conn_state = crtc_get_exynos_connector_state(state, crtc_state,
						DRM_MODE_CONNECTOR_DSI);
	if (!exynos_conn_state)
		return 0;

	if (!(exynos_conn_state->exynos_mode.mode_flags & MIPI_DSI_MODE_VIDEO)) {
		if (!decon->irq_te || !decon->res.pinctrl) {
			decon_err(decon, "TE error: irq_te %d, te_pinctrl %p\n",
					decon->irq_te, decon->res.pinctrl);

			return -EINVAL;
		}
	}

	if (exynos_conn_state->exynos_mode.mode_flags & MIPI_DSI_MODE_VIDEO) {
		struct exynos_drm_crtc_state *exynos_crtc_state;

		exynos_crtc_state = to_exynos_crtc_state(crtc_state);
		/*
		 * In video mode,
		 * When there is no update window, preventing to disable all window
		 * Because Video mode MRES is not supported, It can do it.
		 */
		exynos_crtc_state->modeset_only = false;
	}

	return decon_check_seamless_modeset(exynos_crtc, crtc_state, exynos_conn_state);
}

static void decon_check_display_config(struct exynos_drm_crtc *exynos_crtc,
				       struct drm_atomic_state *state)
{
	int i;
	struct drm_connector *conn;
	struct exynos_drm_connector *exynos_conn;
	const struct drm_connector_state *new_conn_state;
	struct exynos_drm_connector_state *new_exynos_conn_state;
	struct drm_crtc_state *crtc_state =
		drm_atomic_get_new_crtc_state(state, &exynos_crtc->base);
	struct drm_crtc_state *old_crtc_state =
		drm_atomic_get_old_crtc_state(state, &exynos_crtc->base);
	struct exynos_drm_crtc_state *new_exynos_crtc_state =
				to_exynos_crtc_state(crtc_state);
	struct dsim_device *dsim = NULL;
	struct decon_device *decon = exynos_crtc->ctx;

	if ((__is_recovery_supported(decon) && __is_recovery_begin(decon)) ||
			 new_exynos_crtc_state->modeset_only ||
			(!crtc_state->planes_changed && (crtc_state->plane_mask != 0)))
				new_exynos_crtc_state->skip_frameupdate = true;

	for_each_new_connector_in_state(state, conn, new_conn_state, i) {
		if (new_conn_state->crtc != &exynos_crtc->base)
			continue;

		if (conn->connector_type == DRM_MODE_CONNECTOR_DSI) {
			exynos_conn = to_exynos_connector(conn);
			new_exynos_conn_state = to_exynos_connector_state(new_conn_state);

			if (__is_recovery_supported(decon) && __is_recovery_begin(decon) &&
					!need_panel_recovery(exynos_crtc, new_exynos_conn_state)) {
				new_exynos_conn_state->bypass_panel = true;
#if defined(CONFIG_EXYNOS_UEVENT_RECOVERY_SOLUTION)
				if (__is_recovery_uevent(decon) ||
						__is_recovery_uevent_clear(decon))
					new_exynos_conn_state->bypass_panel = false;
#endif
			} else if (is_tui_trans(crtc_state))
				new_exynos_conn_state->bypass_panel = true;

			if ((crtc_state->self_refresh_active !=
				old_crtc_state->self_refresh_active) && (
				crtc_state->active != old_crtc_state->active))
				new_exynos_conn_state->bypass_panel = true;

		} else if (conn->connector_type == DRM_MODE_CONNECTOR_WRITEBACK) {
			if ((crtc_state->active_changed || !crtc_state->plane_mask) &&
					crtc_state->active)
				new_exynos_crtc_state->skip_frameupdate = true;
		} else if (conn->connector_type == DRM_MODE_CONNECTOR_DisplayPort) {
			new_exynos_crtc_state->initial_commit_completed = true;
		}

		if (conn->connector_type != DRM_MODE_CONNECTOR_DSI)
			exynos_drm_sfr_dma_config(crtc_state->active_changed,
						crtc_state->active);
	}
	if (!crtc_state->active_changed && old_crtc_state->self_refresh_active &&
			!crtc_state->self_refresh_active)
		crtc_state->active_changed = true;

	if (!crtc_state->active)
		return;

	dsim = decon_get_dsim(decon);
	if (crtc_needs_colormap(crtc_state) && !dsim_is_fb_reserved(dsim) &&
			new_exynos_crtc_state->initial_commit_completed)
		new_exynos_crtc_state->need_colormap = true;
}

static int decon_atomic_check(struct exynos_drm_crtc *exynos_crtc,
			      struct drm_atomic_state *state)
{
	const struct decon_device *decon = exynos_crtc->ctx;
	struct drm_crtc_state *new_crtc_state =
			drm_atomic_get_new_crtc_state(state, &exynos_crtc->base);
	struct exynos_drm_crtc_state *new_exynos_crtc_state =
				to_exynos_crtc_state(new_crtc_state);
	const struct drm_crtc_state *old_crtc_state =
				drm_atomic_get_old_crtc_state(state, &exynos_crtc->base);
	struct drm_connector *conn =
				crtc_get_conn(new_crtc_state, DRM_MODE_CONNECTOR_DSI);
	const struct exynos_drm_connector *exynos_conn;
	struct drm_plane *plane;
	const struct drm_plane_state *plane_state;
	struct drm_crtc_state *crtc_state = exynos_crtc->base.state;
	int ret = 0;

	new_exynos_crtc_state->wb_type = decon_get_wb_type(new_crtc_state);

	if (conn) {
		exynos_conn = to_exynos_connector(conn);
		if (exynos_conn && (!exynos_conn->boost_expire_time || ktime_before(
				ktime_get(), exynos_conn->boost_expire_time)))
			new_exynos_crtc_state->boost_bts_fps =
						exynos_conn->boost_bts_fps;
	}

	new_crtc_state->no_vblank = false;
#if IS_ENABLED(CONFIG_DRM_MCD_COMMON)
	if (mcd_drm_check_commit_skip(exynos_crtc, __func__))
		new_crtc_state->no_vblank = true;
#endif
	if (decon->config.out_type == DECON_OUT_WB)
		new_crtc_state->no_vblank = true;

	if (decon->rcd) {
		uint32_t rcd_mask = new_crtc_state->plane_mask &
				    exynos_crtc->rcd_plane_mask;
		uint32_t old_rcd_mask = old_crtc_state->plane_mask &
					exynos_crtc->rcd_plane_mask;

		new_exynos_crtc_state->rcd_enabled = false;
		crtc_state->color_mgmt_changed |= rcd_mask != old_rcd_mask;

		if (rcd_mask) {
			drm_atomic_crtc_state_for_each_plane_state(
				plane, plane_state, new_crtc_state) {
				if (rcd_mask & drm_plane_mask(plane)) {
					new_exynos_crtc_state->rcd_enabled =
						plane_state->visible;
					break;
				}
			}
		}
	}

	if (new_crtc_state->mode_changed)
		ret = decon_check_modeset(exynos_crtc, new_crtc_state);

	decon_check_display_config(exynos_crtc, state);

	exynos_dqe_prepare(exynos_crtc->dqe, new_crtc_state);

	return ret;
}

static int decon_get_win_id(const struct drm_crtc_state *crtc_state, int zpos)
{
	const struct exynos_drm_crtc_state *exynos_crtc_state =
					to_exynos_crtc_state(crtc_state);
	const unsigned long win_mask = exynos_crtc_state->reserved_win_mask;
	int bit, i = 0;

	for_each_set_bit(bit, &win_mask, MAX_WIN_PER_DECON) {
		if (i == zpos)
			return bit;
		i++;
	}

	return -EINVAL;
}

static bool decon_is_win_used(const struct drm_crtc_state *crtc_state, int win_id)
{
	const struct exynos_drm_crtc_state *exynos_crtc_state =
					to_exynos_crtc_state(crtc_state);
	const unsigned long win_mask = exynos_crtc_state->visible_win_mask;

	if (win_id > MAX_WIN_PER_DECON)
		return false;

	return (BIT(win_id) & win_mask) != 0;
}

static void decon_disable_win(struct decon_device *decon, int win_id)
{
	const struct drm_crtc *crtc = &decon->crtc->base;

	decon_debug(decon, "disabling winid:%d\n", win_id);

	/*
	 * When disabling the plane, previously connected window (win_id) should be
	 * disabled, not the newly requested one. Only disable the old window if it
	 * was previously connected and it's not going to be used by any other plane.
	 */
	if (win_id < MAX_WIN_PER_DECON && !decon_is_win_used(crtc->state, win_id))
		decon_reg_set_win_enable(decon->id, win_id, 0);
}

static void _dpp_disable(struct exynos_drm_plane *exynos_plane)
{
	if (exynos_plane->is_win_connected) {
		exynos_plane->ops->atomic_disable(exynos_plane);
		exynos_plane->is_win_connected = false;
	} else if (exynos_plane->is_rcd) {
		exynos_plane->ops->atomic_disable(exynos_plane);
	}
}

static void decon_update_plane(struct exynos_drm_crtc *exynos_crtc,
			       struct exynos_drm_plane *exynos_plane,
			       struct drm_atomic_state *old_state)
{
	const struct drm_plane_state *plane_state =
		drm_atomic_get_new_plane_state(old_state, &exynos_plane->base);
	const struct exynos_drm_plane_state *exynos_plane_state =
			to_exynos_plane_state(plane_state);
	const struct drm_crtc_state *crtc_state =
		drm_atomic_get_new_crtc_state(old_state, &exynos_crtc->base);
	struct dpp_device *dpp = plane_to_dpp(exynos_plane);
	struct decon_device *decon = exynos_crtc->ctx;
	struct decon_window_regs win_info;
	unsigned int zpos;
	int win_id;
	bool is_colormap = false;
	u16 hw_alpha;
	unsigned int simplified_rot;

	decon_debug(decon, "+\n");

	dpp->decon_id = decon->id;
	if (exynos_plane->is_rcd) {
		exynos_plane->ops->atomic_update(exynos_plane,
						 exynos_plane_state);
		exynos_plane->win_id = MAX_WIN_PER_DECON;
		return;
	}

	zpos = plane_state->normalized_zpos;

	if (!exynos_plane->is_win_connected || crtc_state->zpos_changed) {
		win_id = decon_get_win_id(crtc_state, zpos);
		decon_debug(decon, "new win_id=%d zpos=%d mask=0x%x\n",
				win_id, zpos, crtc_state->plane_mask);
	} else {
		win_id = exynos_plane->win_id;
		decon_debug(decon, "reuse existing win_id=%d zpos=%d mask=0x%x\n",
				win_id, zpos, crtc_state->plane_mask);
	}

	if (WARN(win_id < 0 || win_id > MAX_WIN_PER_DECON,
		"couldn't find win id (%d) for zpos=%d plane_mask=0x%x\n",
		win_id, zpos, crtc_state->plane_mask))
		return;

	memset(&win_info, 0, sizeof(struct decon_window_regs));

	is_colormap = plane_state->fb && exynos_drm_fb_is_colormap(plane_state->fb);
	if (is_colormap)
		win_info.colormap = exynos_plane_state->colormap;

	win_info.start_pos = win_start_pos(plane_state->dst.x1,	plane_state->dst.y1);
	win_info.end_pos = win_end_pos(plane_state->dst.x2, plane_state->dst.y2);

	simplified_rot = drm_rotation_simplify(plane_state->rotation,
			DRM_MODE_ROTATE_0 | DRM_MODE_ROTATE_90 |
			DRM_MODE_REFLECT_X | DRM_MODE_REFLECT_Y);
	if ((plane_state->dst.y1 <= DECON_WIN_START_TIME) ||
		(simplified_rot & DRM_MODE_ROTATE_90))
		win_info.start_time = 0;
	else
		win_info.start_time = DECON_WIN_START_TIME;

	win_info.ch = dpp->id; /* DPP's id is DPP channel number */

	hw_alpha = DIV_ROUND_CLOSEST(plane_state->alpha * EXYNOS_PLANE_ALPHA_MAX,
			DRM_BLEND_ALPHA_OPAQUE);
	win_info.plane_alpha = hw_alpha;
	win_info.blend = plane_state->pixel_blend_mode;

	if (zpos == 0 && hw_alpha == EXYNOS_PLANE_ALPHA_MAX)
		win_info.blend = DRM_MODE_BLEND_PIXEL_NONE;

	/* disable previous window if zpos has changed */
	if (exynos_plane->win_id != win_id)
		decon_disable_win(decon, exynos_plane->win_id);

	decon_reg_set_window_control(decon->id, win_id, &win_info, is_colormap);

	if (!is_colormap) {
		exynos_plane->ops->atomic_update(exynos_plane, exynos_plane_state);
		exynos_plane->is_win_connected = true;
	} else {
		_dpp_disable(exynos_plane);
	}

	exynos_plane->win_id = win_id;

	DPU_EVENT_LOG("PLANE_UPDATE", exynos_crtc, 0, "CH:%2d, WIN:%2d",
			drm_plane_index(&exynos_plane->base), exynos_plane->win_id);
	decon_debug(decon, "plane idx[%d]: alpha(0x%x) hw alpha(0x%x)\n",
			drm_plane_index(&exynos_plane->base), plane_state->alpha,
			hw_alpha);
	decon_debug(decon, "blend_mode(%d) color(%s:0x%x)\n", win_info.blend,
			is_colormap ? "enable" : "disable", win_info.colormap);
	decon_debug(decon, "-\n");
}

static void decon_disable_plane(struct exynos_drm_crtc *exynos_crtc,
				struct exynos_drm_plane *exynos_plane)
{
	struct decon_device *decon = exynos_crtc->ctx;

	decon_debug(decon, "+\n");

	decon_disable_win(decon, exynos_plane->win_id);

	if (decon->config.mode.op_mode == DECON_VIDEO_MODE) {
		struct dsim_device *dsim = decon_get_dsim(decon);
		/* On first decon_disable_plane(), i.e at the
		 * end of the Bootanimation, the FB handover
		 * will be released and fb_handover.reserved
		 * is made equal false
		 */
		if (dsim_is_fb_reserved(dsim))
			dsim_free_fb_resource(dsim);
	}

	_dpp_disable(exynos_plane);

	DPU_EVENT_LOG("PLANE_DISABLE", exynos_crtc, 0, "CH:%2d, WIN:%2d",
			drm_plane_index(&exynos_plane->base), exynos_plane->win_id);
	decon_debug(decon, "-\n");
}

static void
decon_seamless_set_mode(struct drm_crtc_state *crtc_state,
					struct drm_atomic_state *old_state)
{
	struct drm_crtc *crtc = crtc_state->crtc;
	struct decon_device *decon = to_exynos_crtc(crtc)->ctx;
	struct drm_connector *conn;
	struct drm_connector_state *new_conn_state;
	const struct exynos_drm_connector_state *exynos_conn_state;
	const struct drm_crtc_helper_funcs *funcs;
	int i;

	funcs = crtc->helper_private;

	if (crtc_state->enable && funcs->mode_set_nofb) {
		decon_info(decon, "seamless modeset[%s] on [CRTC:%d:%s]\n",
			crtc_state->mode.name, crtc->base.id, crtc->name);

		exynos_conn_state = crtc_get_exynos_connector_state(old_state,
					crtc_state, DRM_MODE_CONNECTOR_DSI);

		decon_update_config(&decon->config, &crtc_state->adjusted_mode,
			&exynos_conn_state->exynos_mode);

		funcs->mode_set_nofb(crtc);
	}

	for_each_new_connector_in_state(old_state, conn, new_conn_state, i) {
		const struct drm_encoder_helper_funcs *funcs;
		struct drm_encoder *encoder;
		struct drm_display_mode *mode, *adjusted_mode;
		struct drm_bridge *bridge;

		if (!(crtc_state->connector_mask & drm_connector_mask(conn)))
			continue;

		if (!new_conn_state->best_encoder)
			continue;

		encoder = new_conn_state->best_encoder;
		funcs = encoder->helper_private;
		mode = &crtc_state->mode;
		adjusted_mode = &crtc_state->adjusted_mode;

		decon_info(decon, "seamless modeset[%s] on [ENCODER:%d:%s]\n",
				mode->name, encoder->base.id, encoder->name);

		bridge = drm_bridge_chain_get_first_bridge(encoder);
		drm_bridge_chain_mode_set(bridge, mode, adjusted_mode);

		if (funcs && funcs->atomic_mode_set) {
			funcs->atomic_mode_set(encoder, crtc_state,
					       new_conn_state);
		} else if (funcs && funcs->mode_set) {
			funcs->mode_set(encoder, mode, adjusted_mode);
		}
	}
}

static void decon_set_window_index_base(struct exynos_drm_crtc *exynos_crtc,
					struct drm_crtc_state *new_crtc_state)
{
	struct decon_device *decon = exynos_crtc->ctx;
	struct drm_device *dev = exynos_crtc->base.dev;
	struct exynos_drm_crtc_state *new_exynos_crtc_state =
					to_exynos_crtc_state(new_crtc_state);
	struct drm_plane *plane;
	int left_win = 0, right_win = 0;

	if (!is_dual_blender(&decon->config))
		return;

	if (new_exynos_crtc_state->need_colormap) {
		const int win_id = decon_get_win_id(new_crtc_state, 0);

		decon_reg_set_win_idx_base(decon->id, win_id - 1, win_id);
		return;
	}

	drm_for_each_plane_mask(plane, dev, new_crtc_state->plane_mask) {
		struct exynos_drm_plane_state *exynos_plane_state =
					to_exynos_plane_state(plane->state);
		if (exynos_plane_state->need_scaler_pos)
			right_win++;
		else
			left_win++;
	}

	if (left_win == 0) {
		decon_set_color_map(decon, MAX_WIN_PER_DECON - right_win - 1,
				decon->config.image_width / 2,
				decon->config.image_height,
				DECON_COLORMAP_BLACK);
		left_win++;
	} else if (right_win == 0) {
		decon_set_color_map(decon, MAX_WIN_PER_DECON - left_win - 1,
				decon->config.image_width / 2,
				decon->config.image_height,
				DECON_COLORMAP_BLACK);
		right_win++;
	}

	decon_reg_set_win_idx_base(decon->id, MAX_WIN_PER_DECON - left_win - right_win,
				MAX_WIN_PER_DECON - right_win);
}

static void decon_atomic_begin(struct exynos_drm_crtc *exynos_crtc,
			       struct drm_atomic_state *old_state)
{
	struct decon_device *decon = exynos_crtc->ctx;
	struct drm_crtc_state *old_crtc_state =
			drm_atomic_get_old_crtc_state(old_state, &exynos_crtc->base);
	struct drm_crtc_state *new_crtc_state =
			drm_atomic_get_new_crtc_state(old_state, &exynos_crtc->base);
	struct exynos_drm_crtc_state *new_exynos_crtc_state =
					to_exynos_crtc_state(new_crtc_state);
	struct exynos_drm_crtc_state *old_exynos_crtc_state =
					to_exynos_crtc_state(old_crtc_state);

	decon_debug(decon, "+\n");

	if (new_exynos_crtc_state->skip_update)
		return;

#if IS_ENABLED(CONFIG_DRM_MCD_COMMON)
	if (mcd_drm_check_commit_skip(exynos_crtc, __func__)) {
		return;
	}
#endif

	if (__is_recovery_supported(decon) && __is_recovery_begin(decon))
		decon_info(decon, "is skipped(recovery started)\n");
	else if (decon_reg_wait_update_done_and_mask(decon->id, &decon->config.mode,
				SHADOW_UPDATE_TIMEOUT_US)) {
		decon_err(decon, "decon update timeout\n");
		decon_dump(exynos_crtc);
	}

	if (new_exynos_crtc_state->wb_type == EXYNOS_WB_CWB)
		decon_reg_set_cwb_enable(decon->id, true);
	else if (old_exynos_crtc_state->wb_type == EXYNOS_WB_CWB)
		decon_reg_set_cwb_enable(decon->id, false);

	if (exynos_crtc->crc_state == EXYNOS_DRM_CRC_REQ) {
		if (!new_crtc_state->active_changed && new_crtc_state->active &&
		    new_crtc_state->plane_mask) {
			decon_reg_set_start_crc(decon->id, 1);
			exynos_crtc->crc_state = EXYNOS_DRM_CRC_START;
		}
	} else if (exynos_crtc->crc_state == EXYNOS_DRM_CRC_STOP)
		decon_reg_set_start_crc(decon->id, 0);

	decon->config.in_bpc = new_exynos_crtc_state->in_bpc;
	decon_reg_set_bpc_and_dither(decon->id, &decon->config);

	DPU_EVENT_LOG("ATOMIC_BEGIN", exynos_crtc, 0, NULL);

	decon_debug(decon, "-\n");
}
#if IS_ENABLED(CONFIG_USDM_PANEL_MASK_LAYER)
static void decon_fingerprint_mask(struct exynos_drm_crtc *crtc,
			struct drm_crtc_state *old_crtc_state, u32 after)
{
	struct drm_atomic_state *state;
	struct drm_connector *connector;
	struct drm_connector_state *conn_state;
	struct drm_encoder *encoder;
	struct drm_bridge *bridge;
	struct exynos_panel *ctx;
	struct decon_device *decon;
	const struct exynos_panel_funcs *funcs;
	int i = 0;

	if (!crtc) {
		pr_info("%s crtc is null.\n", __func__);
		return;
	}

	decon = crtc->ctx;

	if (!decon) {
		pr_info("%s decon is null.\n", __func__);
		return;
	}

	if (decon->id != 0)
		return;

	state = old_crtc_state->state;

	for_each_new_connector_in_state(state, connector, conn_state, i) {
		encoder = conn_state->best_encoder;
		if (!encoder) {
			decon_err(decon, "encoder is null.\n");
			return;
		}

		bridge = drm_bridge_chain_get_first_bridge(encoder);
		if (!bridge) {
			decon_err(decon, "bridge is null.\n");
			return;
		}

		ctx = bridge_to_exynos_panel(bridge);
		if (!ctx) {
			decon_err(decon, "ctx is null.\n");
			return;
		}

		funcs = ctx->desc->exynos_panel_func;
		if (!funcs) {
			decon_err(decon, "funcs is null.\n");
			return;
		}

		funcs->set_fingermask_layer(ctx, after);
	}
}
#endif
static void decon_atomic_flush(struct exynos_drm_crtc *exynos_crtc,
			       struct drm_atomic_state *old_state)
{
	struct decon_device *decon = exynos_crtc->ctx;
	struct drm_crtc_state *old_crtc_state =
			drm_atomic_get_old_crtc_state(old_state, &exynos_crtc->base);
	struct drm_crtc_state *new_crtc_state =
			drm_atomic_get_new_crtc_state(old_state, &exynos_crtc->base);
	struct exynos_drm_crtc_state *new_exynos_crtc_state =
					to_exynos_crtc_state(new_crtc_state);
	struct exynos_drm_crtc_state *old_exynos_crtc_state =
					to_exynos_crtc_state(old_crtc_state);
#if IS_ENABLED(CONFIG_DRM_MCD_COMMON)
	bool color_map = true;
#endif

	decon_debug(decon, "+\n");

	if (new_exynos_crtc_state->skip_update) {
		exynos_crtc_arm_event(exynos_crtc);
		return;
	}

	if (new_exynos_crtc_state->need_colormap) {
		const int win_id = decon_get_win_id(new_crtc_state, 0);

		if (win_id < 0) {
			decon_err(decon, "unable to get free win_id=%d mask=0x%x\n",
				win_id, new_exynos_crtc_state->reserved_win_mask);
			return;
		}
#if IS_ENABLED(CONFIG_DRM_MCD_COMMON)
		/* DECON_COMMAND_MODE */
		if ((decon->config.out_type & DECON_OUT_DSI) && (decon->config.mode.op_mode == DECON_COMMAND_MODE) &&
			(old_crtc_state->active == 0) && (new_crtc_state->active == 1)) {

			decon_info(decon, "skip color map\n");
			new_exynos_crtc_state->skip_frameupdate = true;
			color_map = false;
		}

		if (color_map) {
			if (is_dual_blender(&decon->config)) {
				decon_set_color_map(decon, win_id, decon->config.image_width / 2,
						decon->config.image_height, DECON_COLORMAP_BLACK);
				decon_set_color_map(decon, win_id - 1, decon->config.image_width / 2,
						decon->config.image_height, DECON_COLORMAP_BLACK);
				decon_debug(decon, "no planes, enable color map win_id=%d,%d\n", win_id - 1, win_id);
			} else {
				decon_set_color_map(decon, win_id, decon->config.image_width,
						decon->config.image_height, DECON_COLORMAP_BLACK);
				decon_debug(decon, "no planes, enable color map win_id=%d\n", win_id);
			}
		}
#else
		if (is_dual_blender(&decon->config)) {
			decon_set_color_map(decon, win_id, decon->config.image_width / 2,
					decon->config.image_height, DECON_COLORMAP_BLACK);
			decon_set_color_map(decon, win_id - 1, decon->config.image_width / 2,
					decon->config.image_height, DECON_COLORMAP_BLACK);
			decon_debug(decon, "no planes, enable color map win_id=%d,%d\n", win_id - 1, win_id);
		} else {
			decon_set_color_map(decon, win_id, decon->config.image_width,
					decon->config.image_height, DECON_COLORMAP_BLACK);
			decon_debug(decon, "no planes, enable color map win_id=%d\n", win_id);
		}
#endif
	}

	decon->config.rcd_en = new_exynos_crtc_state->rcd_enabled;
	exynos_dqe_update(exynos_crtc->dqe, new_crtc_state);

	if (decon->config.out_type & DECON_OUT_DSI)
		exynos_drm_sfr_dma_update();

	if (new_exynos_crtc_state->seamless_modeset)
		decon_seamless_set_mode(new_crtc_state, old_crtc_state->state);

	if (new_exynos_crtc_state->modeset_only) {
		int win_id;
		const unsigned long win_mask =
			new_exynos_crtc_state->reserved_win_mask;

		for_each_set_bit(win_id, &win_mask, MAX_WIN_PER_DECON)
			decon_reg_set_win_enable(decon->id, win_id, 0);
		decon_info(decon, "modeset_only\n");
	}

	/* only for video mode tui */
	exynos_tui_sec_win_shadow_update_req(decon,
			old_exynos_crtc_state, new_exynos_crtc_state);

	/* only for dual blender */
	decon_set_window_index_base(exynos_crtc, new_crtc_state);

#if IS_ENABLED(CONFIG_USDM_PANEL_MASK_LAYER)
	exynos_crtc->ops->set_fingerprint_mask(exynos_crtc, old_crtc_state, 0);
#endif

	decon_reg_all_win_shadow_update_req(decon->id);
	reinit_completion(&decon->framestart_done);

	if (exynos_crtc->ops->check_svsync_start)
		exynos_crtc->ops->check_svsync_start(exynos_crtc);

	decon_reg_start(decon->id, &decon->config);

	if (!new_crtc_state->no_vblank) {
		if ((decon->config.out_type & DECON_OUT_DSI) &&
			(decon->config.mode.op_mode == DECON_VIDEO_MODE)) {
			struct dsim_device *dsim = decon_get_dsim(decon);

			dsim_wait_pending_vblank(dsim);
		}

		exynos_crtc_arm_event(exynos_crtc);
	}

	exynos_profiler_update_ems_frame_cnt(exynos_crtc);

	/* only for video mode tui */
	exynos_tui_release_sec_buf(decon, old_exynos_crtc_state, new_exynos_crtc_state);

	DPU_EVENT_LOG("ATOMIC_FLUSH", exynos_crtc, 0, NULL);

	decon_debug(decon, "-\n");
}

static void decon_atomic_print_state(struct drm_printer *p,
		const struct exynos_drm_crtc *exynos_crtc)
{
	const struct decon_device *decon = exynos_crtc->ctx;
	const struct decon_config *cfg = &decon->config;

	drm_printf(p, "\tDecon #%d (state:%d)\n", decon->id, decon->state);
	drm_printf(p, "\t\ttype=0x%x\n", cfg->out_type);
	drm_printf(p, "\t\tsize=%dx%d\n", cfg->image_width, cfg->image_height);
	drm_printf(p, "\t\tmode=%s (%d)\n",
			cfg->mode.op_mode == DECON_VIDEO_MODE ? "video" : "cmd",
			cfg->mode.dsi_mode);
	drm_printf(p, "\t\tin_bpc=%d out_bpc=%d\n", cfg->in_bpc,
			cfg->out_bpc);
	drm_printf(p, "\t\tbts_fps=%d\n", decon->bts.fps);
}

static int decon_late_register(struct exynos_drm_crtc *exynos_crtc)
{
	struct decon_device *decon = exynos_crtc->ctx;
	struct drm_crtc *crtc = &exynos_crtc->base;
	struct dentry *urgent_dent;
	struct device_node *te_np;

	urgent_dent = debugfs_create_dir("urgent", crtc->debugfs_entry);
	if (!urgent_dent) {
		DRM_ERROR("failed to create debugfs urgent directory\n");
		return -ENOENT;
	}

	debugfs_create_u32("rd_en", 0664,
			urgent_dent, &decon->config.urgent.rd_en);

	debugfs_create_x32("rd_hi_thres", 0664,
			urgent_dent, &decon->config.urgent.rd_hi_thres);

	debugfs_create_x32("rd_lo_thres", 0664,
			urgent_dent, &decon->config.urgent.rd_lo_thres);

	debugfs_create_x32("rd_wait_cycle", 0664,
			urgent_dent, &decon->config.urgent.rd_wait_cycle);

	debugfs_create_u32("wr_en", 0664,
			urgent_dent, &decon->config.urgent.wr_en);

	debugfs_create_x32("wr_hi_thres", 0664,
			urgent_dent, &decon->config.urgent.wr_hi_thres);

	debugfs_create_x32("wr_lo_thres", 0664,
			urgent_dent, &decon->config.urgent.wr_lo_thres);

	debugfs_create_u32("dta_en", 0664,
			urgent_dent, &decon->config.urgent.dta_en);

	debugfs_create_x32("dta_hi_thres", 0664,
			urgent_dent, &decon->config.urgent.dta_hi_thres);

	debugfs_create_x32("dta_lo_thres", 0664,
			urgent_dent, &decon->config.urgent.dta_lo_thres);

	dpu_freq_hop_debugfs(exynos_crtc);

	te_np = of_get_child_by_name(decon->dev->of_node, "te_eint");
	if (te_np) {
		exynos_crtc->d.eint_pend = of_iomap(te_np, 0);
		if (!exynos_crtc->d.eint_pend)
			decon_err(decon, "failed to remap te eint pend\n");
	}

	return 0;
}

#define WAIT_FRAME_CNT (5)
#define DEFAULT_TIMEOUT_FPS (60)
static void decon_wait_framestart(struct exynos_drm_crtc *exynos_crtc)
{
	struct decon_device *decon = exynos_crtc->ctx;
	struct drm_crtc_state *crtc_state = exynos_crtc->base.state;
	struct exynos_drm_crtc_state *exynos_crtc_state =
					to_exynos_crtc_state(crtc_state);
	int fps;
	u32 framestart_timeout;

	if (exynos_crtc_state->skip_frameupdate)
		return;

	DPU_ATRACE_BEGIN(__func__);
	fps = decon->config.fps ?: DEFAULT_TIMEOUT_FPS;
	framestart_timeout = MSEC_PER_SEC * WAIT_FRAME_CNT / fps;

	if (IS_ENABLED(CONFIG_BOARD_EMULATOR))
		framestart_timeout *= 1000;

#if IS_ENABLED(CONFIG_DRM_MCD_COMMON)
	/* Code for bypass commit when panel was not connected */
	if (exynos_crtc->possible_type & EXYNOS_DISPLAY_TYPE_DSI) {
		if (crtc_state->no_vblank) {
			decon_debug(decon, "%s is skipped(no_vblank)\n", __func__);
			return;
		}
	}
#endif

	if (!wait_for_completion_timeout(&decon->framestart_done,
				msecs_to_jiffies(framestart_timeout))) {
		DPU_EVENT_LOG("FRAMESTART_TIMEOUT", exynos_crtc,
				EVENT_FLAG_ERROR, NULL);
		decon_err(decon, "framestart timeout\n");
	}
	DPU_ATRACE_END(__func__);
}

static bool __need_dpu_fault(struct decon_device *decon)
{
	if (decon->emul_mode)
		return false;

	if (__is_recovery_supported(decon) && __is_recovery_begin(decon)) {
		decon_info(decon, "is skipped(recovery started)\n");
		return false;
	}

#if IS_ENABLED(CONFIG_DRM_MCD_COMMON)
	if (mcd_drm_check_commit_skip(decon->crtc, __func__))
		return false;
#endif

	if (!decon_reg_wait_update_done_timeout(decon->id, SHADOW_UPDATE_TIMEOUT_US))
		return false;

	decon_err(decon, "decon update timeout\n");
	if (__is_recovery_supported(decon)) {
		if (decon_trigger_recovery(decon->crtc, "dsim|peri") < 0)
			return true;
		return false;
	}

	if (wb_notify_error(decon_get_wb(decon)))
		return false;

	return true;
}

static void decon_set_trigger(struct exynos_drm_crtc *exynos_crtc,
			struct exynos_drm_crtc_state *exynos_crtc_state)
{
	struct decon_device *decon = exynos_crtc->ctx;
	struct decon_mode *mode;

	if (__need_dpu_fault(decon))
		exynos_drm_report_dpu_fault(exynos_crtc);

	mode = &decon->config.mode;
#if IS_ENABLED(CONFIG_DRM_MCD_COMMON)
	/* Code for bypass commit when panel was not connected */
	if (mcd_drm_check_commit_skip(exynos_crtc, __func__)) {
		if (mode->op_mode == DECON_COMMAND_MODE)
			decon_reg_set_trigger(decon->id, mode, DECON_TRIG_MASK);
		return;
	}
#endif
	if (mode->op_mode == DECON_COMMAND_MODE &&
			exynos_crtc_state->dsr_status == false &&
			decon->dimming == false) {
		DPU_EVENT_LOG("DECON_TRIG_MASK", exynos_crtc, 0, NULL);
		decon_reg_set_trigger(decon->id, mode, DECON_TRIG_MASK);
	}
}

#if IS_ENABLED(CONFIG_EXYNOS_CMD_SVSYNC) || IS_ENABLED(CONFIG_EXYNOS_CMD_SVSYNC_ONOFF)
static bool dpu_svsync_log;
module_param_named(dpu_svsync_print, dpu_svsync_log, bool, 0600);
MODULE_PARM_DESC(dpu_svsync_print,
		"enable print when sv-sync mode works [default : false]");

static bool decon_check_svsync_start(struct exynos_drm_crtc *exynos_crtc)
{
	struct decon_device *decon = exynos_crtc->ctx;
	bool svsync = false;
	static u32 frame_cnt_a;
	static bool checked;

	if (decon_is_svsync_supported(decon)) {
		if (decon_reg_get_trigger_mask(decon->id)) {
			checked = true;
			frame_cnt_a = decon_reg_get_frame_cnt(decon->id);
		} else if (checked) {
			checked = false;
			if (frame_cnt_a < decon_reg_get_frame_cnt(decon->id))
				svsync = true;
		}
	}

	if (svsync) {
		DPU_EVENT_LOG("SVSYNC_TRIG", exynos_crtc, 0, NULL);
		if (dpu_svsync_log)
			decon_info(decon, "frame started due to svsync\n");
	}
	decon_debug(decon, "-\n");

	return svsync;
}
#endif

#if defined(CONFIG_EXYNOS_PLL_SLEEP)
/*
 * 1. need to mask PLL_SLEEP to avoid DPU stuck by cmd_lock
 *   add delay as much as the PLL lock time required for PLL_SLEEP exit.
 * 2. PLL_SLEEP_MASK_OUTIF is non-shadow
 *   set as soon as the value(1) is written. (mask)
 *   this prevents PLL_SLEEP at blank time.
 *
 * 3. need to unmask PLL_SLEEP when there is no pending command.
 * 4. PLL_SLEEP_MASK_OUTIF is non-shadow
 *    clear as soon as the value(0) is written. (unmask)
 */
static void
decon_pll_sleep_mask(struct exynos_drm_crtc *exynos_crtc, bool mask)
{
	struct decon_device *decon = exynos_crtc->ctx;
	struct decon_config *config;

	config = &decon->config;
	if (!(config->out_type & DECON_OUT_DSI) ||
			(config->mode.op_mode != DECON_COMMAND_MODE) ||
			(config->mode.dsi_mode == DSI_MODE_DUAL_DSI) ||
			__is_recovery_running(decon))
		return;

	decon_debug(decon, "+ decon_state(%d) mask(%d)\n", decon->state, mask);
	if (IS_DECON_OFF_STATE(decon)) {
		decon_debug(decon, "decon_state(%d) is not on\n", decon->state);
		return;
	}

	if (mask) {
		decon_set_pll_sleep_masked(decon, true);
		decon_reg_set_pll_wakeup(decon->id, 1);
	} else {
		if (decon_get_pll_sleep_masked(decon))
			decon_set_pll_sleep_masked(decon, false);
		else
			decon_reg_set_pll_wakeup(decon->id, 0);
	}
	decon_debug(decon, "-\n");
}
#endif

static void decon_print_config_info(struct decon_device *decon)
{
	char *str_output = NULL;
	char *str_trigger = NULL;

	if (decon->config.mode.trig_mode == DECON_HW_TRIG)
		str_trigger = "hw trigger.";
	else if (decon->config.mode.trig_mode == DECON_SW_TRIG)
		str_trigger = "sw trigger.";
	if (decon->config.mode.op_mode == DECON_VIDEO_MODE)
		str_trigger = "";

	if (decon->config.out_type == DECON_OUT_DSI)
		str_output = "Dual DSI";
	else if (decon->config.out_type & DECON_OUT_DSI0)
		str_output = "DSI0";
	else if  (decon->config.out_type & DECON_OUT_DSI1)
		str_output = "DSI1";
	else if  (decon->config.out_type & DECON_OUT_DP0)
		str_output = "DP0";
	else if  (decon->config.out_type & DECON_OUT_DP1)
		str_output = "DP1";
	else if  (decon->config.out_type & DECON_OUT_WB)
		str_output = "WB";

	decon_info(decon, "%s mode. %s %s output.(%dx%d@%dhz)\n",
			decon->config.mode.op_mode ? "command" : "video",
			str_trigger, str_output,
			decon->config.image_width, decon->config.image_height,
			decon->config.fps);
}

static void decon_set_te_pinctrl(struct decon_device *decon, bool en)
{
	int ret;

	if ((decon->config.mode.op_mode != DECON_COMMAND_MODE) ||
			(decon->config.mode.trig_mode != DECON_HW_TRIG))
		return;

	if (!decon->res.pinctrl || !decon->res.te_on)
		return;

	ret = pinctrl_select_state(decon->res.pinctrl,
			en ? decon->res.te_on : decon->res.te_off);
	if (ret)
		decon_err(decon, "failed to control decon TE(%d)\n", en);
}

static void decon_enable_irqs(struct decon_device *decon)
{
	enable_irq(decon->irq_fd);
	enable_irq(decon->irq_ext);
	if ((decon->irq_sramc_d) >= 0)
		enable_irq(decon->irq_sramc_d);
	if ((decon->irq_sramc1_d) >= 0)
		enable_irq(decon->irq_sramc1_d);
	if (decon_is_te_enabled(decon))
		enable_irq(decon->irq_fs);
}

static void _decon_enable(struct decon_device *decon)
{
	struct exynos_drm_crtc *exynos_crtc = decon->crtc;

	decon_reg_init(decon->id, &decon->config);
	exynos_dqe_enable(decon->crtc->dqe);
	decon_enable_irqs(decon);

	WARN_ON(drm_crtc_vblank_get(&exynos_crtc->base) != 0);
}

static void decon_mode_set(struct exynos_drm_crtc *crtc,
			   const struct drm_display_mode *mode,
			   const struct drm_display_mode *adjusted_mode)
{
	struct decon_device *decon = crtc->ctx;
	const struct drm_crtc_state *crtc_state = crtc->base.state;
	struct exynos_drm_crtc_state *new_exynos_crtc_state =
					to_exynos_crtc_state(crtc_state);

	decon_mode_update_bts(decon, adjusted_mode);

	if (!new_exynos_crtc_state->seamless_modeset || decon->state != DECON_STATE_ON)
		return;

	if (IS_ENABLED(CONFIG_EXYNOS_BTS)) {
		decon->bts.ops->calc_bw(crtc);
		decon->bts.ops->update_bw(crtc, false);
	}

	if (new_exynos_crtc_state->seamless_modeset & SEAMLESS_MODESET_MRES)
		decon_reg_set_mres(decon->id, &decon->config);
	if (new_exynos_crtc_state->seamless_modeset & SEAMLESS_MODESET_VREF)
		decon_reg_update_ewr_control(decon->id, decon->config.fps);
#if IS_ENABLED(CONFIG_EXYNOS_CMD_SVSYNC_ONOFF)
	if (new_exynos_crtc_state->seamless_modeset & SEAMLESS_MODESET_VREF) {
		bool svsync_on = false;
		if (decon->config.svsync_on_fps &&
			decon_is_svsync_supported(decon)) {
			if (decon->config.fps >= decon->config.svsync_on_fps)
				svsync_on = true;
			decon_reg_set_svsync_enable(decon->id, &decon->config,
				svsync_on);
			if (dpu_svsync_log)
				decon_info(decon, "svsync is %s (bts_fps:%d)\n",
					(svsync_on ? "on" : "off"), decon->bts.fps);
		}
	}
#endif
}

#if IS_ENABLED(CONFIG_EXYNOS_PD)
extern int exynos_pd_booton_rel(const char *pd_name);
#else
static int exynos_pd_booton_rel(const char *pd_name) { return 0; }
#endif

static void decon_pd_booton_rel(struct decon_device *decon)
{
	int i;

	for (i = 0; i < decon->pd_cnt; ++i)
		exynos_pd_booton_rel(decon->pd_names[i]);
}

static void
_decon_notify_pm_wakeup_signal(struct decon_device *decon, bool en)
{
	if (en)
		pm_stay_awake(decon->dev);
	else
		pm_relax(decon->dev);

	decon_info(decon, "pm_%s\n", en ? "stay_awake" : "relax");
#if IS_ENABLED(CONFIG_PM_SLEEP)
	decon_info(decon, "(active : %lu, relax : %lu)\n",
			decon->dev->power.wakeup->active_count,
			decon->dev->power.wakeup->relax_count);
#endif
}

static void _decon_notify_hiber_available_signal(struct decon_device *decon)
{
	struct exynos_drm_crtc *exynos_crtc = decon->crtc;
	struct exynos_hibernation *hibernation = exynos_crtc->hibernation;
	static unsigned int wakeup_mask = 0;
	static unsigned int hiber_available_mask = 0x3;

	/* if not dual-display, hiber operates same as before */
	if (decon->config.mode.dsi_mode != DSI_MODE_DUAL_DISPLAY)
		goto available;

	/* decon0/1 already wakeup */
	if (wakeup_mask == hiber_available_mask)
		goto available;

	/* even though hibernation is not supported, should check decon wakeup*/
	wakeup_mask |= BIT(decon->id);
	if (wakeup_mask != hiber_available_mask)
		return;

available:
	if (hibernation && !hibernation->available)
		hibernation->available = true;
}

static void
_decon_set_runtime_pm(struct decon_device *decon, bool en)
{
	if (is_tui_trans(decon->crtc->base.state)) {
		decon_info(decon, "tui transition : skip power/te ctrl\n");
		return;
	}

	if (en) {
		DO_ONCE(decon_pd_booton_rel, decon);
		pm_runtime_get_sync(decon->dev);
		decon_set_te_pinctrl(decon, en);
	} else {
		decon_set_te_pinctrl(decon, en);
		pm_runtime_put_sync(decon->dev);
	}

	if (__is_recovery_running(decon)) {
		decon_info(decon, "recovery running : skip pm wakeup event\n");
		return;
	}

	_decon_notify_pm_wakeup_signal(decon, en);

	if (en)
		_decon_notify_hiber_available_signal(decon);
}

static void _decon_disable_windows(struct decon_device *decon)
{
	int i;
	struct dsim_device *dsim = NULL;

	/*
	 * Make sure all window connections are disabled when getting enabled,
	 * in case there are any stale mappings from lk display.
	 * New mappings will happen later before atomic flush.
	 */
	dsim = decon_get_dsim(decon);
	for (i = 0; i < MAX_WIN_PER_DECON; ++i) {
		if (dsim_is_fb_reserved(dsim))
			/* Donot disable win(lk_fb_win_id) in video mode*/
			if (i == dsim->fb_handover.lk_fb_win_id)
				continue;

		decon_reg_set_win_enable(decon->id, i, 0);
	}
}

static void
decon_enable(struct exynos_drm_crtc *crtc, struct drm_atomic_state *old_state)
{
	const struct drm_crtc_state *new_crtc_state =
			drm_atomic_get_new_crtc_state(old_state, &crtc->base);
	struct decon_device *decon = crtc->ctx;

	if (drm_atomic_crtc_needs_modeset(new_crtc_state)) {
		const struct exynos_drm_connector_state *exynos_conn_state =
			crtc_get_exynos_connector_state(old_state, new_crtc_state,
					DRM_MODE_CONNECTOR_DSI);
		const struct exynos_display_mode *exynos_mode = NULL;

		if (exynos_conn_state)
			exynos_mode = &exynos_conn_state->exynos_mode;

		decon_update_config(&decon->config, &new_crtc_state->adjusted_mode,
				exynos_mode);
	}

	if (decon->state == DECON_STATE_ON) {
		decon_info(decon, "already enabled(%d)\n", decon->state);
		return;
	}

	decon_info(decon, "+\n");

#if defined(CONFIG_EXYNOS_UEVENT_RECOVERY_SOLUTION)
	if (__is_recovery_supported(decon) && __is_recovery_uevent_clear(decon))
		exynos_recovery_set_state(decon, RECOVERY_IDLE);
#endif

	_decon_set_runtime_pm(decon, true);

	if (decon->state == DECON_STATE_INIT)
		_decon_disable_windows(decon);

	_decon_enable(decon);

	decon_print_config_info(decon);

	decon->state = DECON_STATE_ON;

	DPU_EVENT_LOG("DECON_ENABLED", crtc, 0, NULL);

	decon_info(decon, "-\n");
}

static void decon_exit_hibernation(struct exynos_drm_crtc *crtc)
{
	struct decon_device *decon = crtc->ctx;

	if (decon->state != DECON_STATE_HIBERNATION)
		return;

	decon_debug(decon, "+\n");

	DPU_ATRACE_BEGIN(__func__);
	DPU_ATRACE_BEGIN("get_sync");
	pm_runtime_get_sync(decon->dev);
	DPU_ATRACE_END("get_sync");

	_decon_enable(decon);

	decon->state = DECON_STATE_ON;

	DPU_EVENT_LOG("DECON_EXIT_HIBER", decon->crtc, 0, NULL);
	decon_debug(decon, "-\n");
	DPU_ATRACE_END(__func__);
}

static void decon_disable_irqs(struct decon_device *decon)
{
	disable_irq(decon->irq_fd);
	disable_irq(decon->irq_ext);
	if ((decon->irq_sramc_d) >= 0)
		disable_irq(decon->irq_sramc_d);
	if ((decon->irq_sramc1_d) >= 0)
		disable_irq(decon->irq_sramc1_d);
	if (decon_is_te_enabled(decon))
		disable_irq(decon->irq_fs);
	if (decon->dimming) {
		decon_debug(decon, "dqe dimming clear\n");
		DPU_EVENT_LOG("DQE_DIMEND", decon->crtc, 0, NULL);
		decon->dimming = false;
	}
}

static void _decon_disable(struct decon_device *decon)
{
	decon_disable_irqs(decon);
	exynos_dqe_disable(decon->crtc->dqe);

	if (decon->rcd) {
		struct exynos_drm_plane *exynos_plane = decon->rcd->plane;
		exynos_plane->ops->atomic_disable(exynos_plane);
	}

	decon_reg_stop(decon->id, &decon->config, true, decon->config.fps);
	drm_crtc_vblank_put(&decon->crtc->base);
}

static void decon_enter_hibernation(struct exynos_drm_crtc *crtc)
{
	struct decon_device *decon = crtc->ctx;

	decon_debug(decon, "+\n");

	if (decon->state != DECON_STATE_ON)
		return;

	_decon_disable(decon);

	pm_runtime_put_sync(decon->dev);

	decon->state = DECON_STATE_HIBERNATION;

	DPU_EVENT_LOG("DECON_ENTER_HIBER", decon->crtc, 0, NULL);
	decon_debug(decon, "-\n");
}

static void decon_disable(struct exynos_drm_crtc *crtc)
{
	struct decon_device *decon = crtc->ctx;

	decon_debug(decon, "state(%d), lp_mode(%d)\n",
			decon->state, decon->config.mode.lp_mode);

	if (decon->state == DECON_STATE_OFF) {
		decon_info(decon, "already disabled(%d)\n", decon->state);
		return;
	} else if (decon->state == DECON_STATE_HIBERNATION) {
		_decon_notify_pm_wakeup_signal(decon, false);
		decon->state = DECON_STATE_OFF;
		return;
	}

	decon_info(decon, "+\n");

	_decon_disable(decon);

	_decon_set_runtime_pm(decon, false);

	decon->state = DECON_STATE_OFF;

	DPU_EVENT_LOG("DECON_DISABLED", crtc, 0, NULL);

#if defined(CONFIG_EXYNOS_UEVENT_RECOVERY_SOLUTION)
	if (__is_recovery_supported(decon) && __is_recovery_uevent(decon))
		exynos_recovery_set_state(decon, RECOVERY_UEVENT_CLEAR);
#endif

	decon_info(decon, "-\n");
}

static const struct exynos_drm_crtc_ops decon_crtc_ops = {
	.enable = decon_enable,
	.disable = decon_disable,
	.atomic_enter_hiber = decon_enter_hibernation,
	.atomic_exit_hiber = decon_exit_hibernation,
	.enable_vblank = decon_enable_vblank,
	.disable_vblank = decon_disable_vblank,
	.mode_set = decon_mode_set,
	.atomic_check = decon_atomic_check,
	.atomic_begin = decon_atomic_begin,
	.update_plane = decon_update_plane,
	.disable_plane = decon_disable_plane,
	.atomic_flush = decon_atomic_flush,
	.atomic_print_state = decon_atomic_print_state,
	.late_register = decon_late_register,
	.wait_framestart = decon_wait_framestart,
	.set_trigger = decon_set_trigger,
#if IS_ENABLED(CONFIG_EXYNOS_CMD_SVSYNC) || IS_ENABLED(CONFIG_EXYNOS_CMD_SVSYNC_ONOFF)
	.check_svsync_start = decon_check_svsync_start,
#endif
	.dump_register = decon_dump,
#if defined(CONFIG_EXYNOS_PLL_SLEEP)
	.pll_sleep_mask = decon_pll_sleep_mask,
#endif
	.recovery = decon_trigger_recovery,
	.is_recovering = decon_read_recovering,
	.update_bts_fps = decon_mode_update_bts_fps,
	.emergency_off = decon_emergency_off,
	.get_crc_data = decon_get_crc_data,
};

static int decon_bind(struct device *dev, struct device *master, void *data)
{
	struct decon_device *decon = dev_get_drvdata(dev);
	struct drm_device *drm_dev = data;
	struct exynos_drm_device *exynos_dev = to_exynos_drm(drm_dev);
	struct exynos_drm_crtc_config crtc_config;
	int i;

	decon->drm_dev = drm_dev;

	crtc_config.ctx = decon;
	crtc_config.default_plane = &decon->dpp[decon->id]->plane->base;
	crtc_config.op_mode = decon->config.mode.op_mode ?
		EXYNOS_COMMAND_MODE : EXYNOS_VIDEO_MODE;
	crtc_config.con_type = decon->con_type;
	crtc_config.res = &decon->restriction;
	decon->crtc = exynos_drm_crtc_create(drm_dev, decon->id,
			&crtc_config, &decon_crtc_ops);
	if (IS_ERR(decon->crtc))
		return PTR_ERR(decon->crtc);

	decon->crtc->bts = &decon->bts;
	decon->crtc->dev = dev;
	decon->crtc->partial = exynos_partial_register(decon->crtc);

	for (i = 0; i < decon->dpp_cnt; ++i) {
		struct dpp_device *dpp = decon->dpp[i];
		struct drm_plane *plane = &dpp->plane->base;

		plane->possible_crtcs |=
			drm_crtc_mask(&decon->crtc->base);
		decon_debug(decon, "plane possible_crtcs = 0x%x\n",
				plane->possible_crtcs);
	}

	if (decon->rcd) {
		struct dpp_device *rcd = decon->rcd;
		struct exynos_drm_plane *exynos_plane = rcd->plane;
		struct drm_plane *plane = &exynos_plane->base;

		plane->possible_crtcs |= drm_crtc_mask(&decon->crtc->base);
		decon_debug(decon, "plane possible_crtcs = 0x%x\n",
			    plane->possible_crtcs);
		decon->crtc->rcd_plane_mask |= drm_plane_mask(plane);
		exynos_plane->is_rcd = true;
	}

	if (!exynos_dev->iommu_client)
		exynos_dev->iommu_client = dev;

	if (IS_ENABLED(CONFIG_EXYNOS_BTS)) {
		decon->bts.ops = &dpu_bts_control;
		decon->bts.ops->init(decon->crtc);

		if ((decon->config.out_type & DECON_OUT_DSI)
				&& (decon->config.mode.op_mode == DECON_VIDEO_MODE)
				&& decon_reg_get_run_status(decon->id)) {
			if (exynos_pm_qos_request_active(&decon->bts.disp_qos)) {
				decon_info(decon, "request qos for fb handover\n");
				exynos_pm_qos_update_request(&decon->bts.disp_qos,
						decon->bts.dfs_lv[0]);
			} else
				decon_err(decon, "disp qos setting error\n");
		}
	}

	decon_debug(decon, "-\n");
	return 0;
}

static void decon_unbind(struct device *dev, struct device *master,
			void *data)
{
	struct decon_device *decon = dev_get_drvdata(dev);

	decon_debug(decon, "+\n");
	if (IS_ENABLED(CONFIG_EXYNOS_BTS))
		decon->bts.ops->deinit(decon->crtc);

	decon_disable(decon->crtc);
	decon_debug(decon, "-\n");
}

static const struct component_ops decon_component_ops = {
	.bind	= decon_bind,
	.unbind = decon_unbind,
};

static bool dpu_frame_time_check = false;
module_param(dpu_frame_time_check, bool, 0600);
MODULE_PARM_DESC(dpu_frame_time_check, "dpu frame time check for dpu bts [default : false]");

static bool dpu_sfr_dump = false;
module_param(dpu_sfr_dump, bool, 0600);
MODULE_PARM_DESC(dpu_sfr_dump, "dpu sfr dump [default : false, reset after sfr dumping]");
static irqreturn_t decon_irq_handler(int irq, void *dev_data)
{
	struct decon_device *decon = dev_data;
	struct exynos_drm_crtc *exynos_crtc = decon->crtc;
	u32 irq_sts_reg;
	u32 ext_irq = 0;
	struct timespec64 tv, tv_d;
	ktime_t timestamp_d;
	long elapsed_t;

	spin_lock(&decon->slock);

	if (IS_DECON_OFF_STATE(decon))
		goto irq_end;

	irq_sts_reg = decon_reg_get_interrupt_and_clear(decon->id, &ext_irq);

	decon_debug(decon, "irq_sts_reg = %x, ext_irq = %x\n", irq_sts_reg, ext_irq);

	if (irq_sts_reg & DPU_FRAME_START_INT_PEND) {
		decon->busy = true;
		complete(&decon->framestart_done);
		DPU_EVENT_LOG("DECON_FRAMESTART", exynos_crtc, 0, NULL);
		if ((decon->config.out_type & DECON_OUT_DSI) &&
			(decon->config.mode.op_mode == DECON_COMMAND_MODE)) {
			decon->timestamp_s = ktime_get();
			tv = ktime_to_timespec64(decon->timestamp_s);
			decon_debug(decon, "[%6lld.%06ld] frame start\n",
					tv.tv_sec, (tv.tv_nsec / 1000));
		} else
			decon_debug(decon, "frame start\n");
		if (dpu_sfr_dump) {
			decon_dump(exynos_crtc);
			dpu_sfr_dump = false;
		}

		if (exynos_crtc && exynos_crtc->crc_state == EXYNOS_DRM_CRC_START)
			exynos_crtc->crc_state = EXYNOS_DRM_CRC_PEND;
	}

	if (irq_sts_reg & DPU_FRAME_DONE_INT_PEND) {
		DPU_EVENT_LOG("DECON_FRAMEDONE", exynos_crtc, 0, NULL);
		decon->busy = false;
		wake_up_interruptible_all(&decon->framedone_wait);
		if (decon->timestamp_s &&
			(decon->config.out_type & DECON_OUT_DSI) &&
			(decon->config.mode.op_mode == DECON_COMMAND_MODE)) {
			timestamp_d = ktime_get();
			tv_d = ktime_to_timespec64(timestamp_d - decon->timestamp_s);
			tv = ktime_to_timespec64(timestamp_d);
			decon_debug(decon, "[%6lld.%06ld] frame done\n",
					tv.tv_sec, (tv.tv_nsec / 1000));
			/*
			 * Elapsed time is wanted under
			 * the calculated value based on 1.01 x fps.
			 * In addition, idle time should also be considered.
			 */
			elapsed_t = 1000000000L / decon->bts.fps * 100 / 101;
			elapsed_t = elapsed_t - 500000L;
			if (tv_d.tv_nsec > elapsed_t)
				decon_warn(decon, "elapsed(%3ld.%03ldmsec)\n",
						(tv_d.tv_nsec / 1000000U),
						(tv_d.tv_nsec % 1000000U));
			else if (dpu_frame_time_check)
				decon_info(decon, "elapsed(%3ld.%03ldmsec)\n",
						(tv_d.tv_nsec / 1000000U),
						(tv_d.tv_nsec % 1000000U));
			else
				decon_debug(decon, "elapsed(%3ld.%03ldmsec)\n",
						(tv_d.tv_nsec / 1000000U),
						(tv_d.tv_nsec % 1000000U));
		} else
			decon_debug(decon, "frame done\n");

		if (exynos_crtc && exynos_crtc->hibernation &&
				exynos_crtc->hibernation->profile.started)
			exynos_crtc->hibernation->profile.frame_cnt++;
	}

	if (irq_sts_reg & DPU_DQE_DIMMING_START_INT_PEND) {
		decon_debug(decon, "dqe dimming start\n");
		DPU_EVENT_LOG("DQE_DIMSTART", exynos_crtc, 0, NULL);
		decon->dimming = true;
	}

	if (irq_sts_reg & DPU_DQE_DIMMING_END_INT_PEND) {
		decon_debug(decon, "dqe dimming end\n");
		DPU_EVENT_LOG("DQE_DIMEND", exynos_crtc, 0, NULL);
		decon->dimming = false;
	}

	if (ext_irq & DPU_RESOURCE_CONFLICT_INT_PEND) {
		decon_debug(decon, "resource conflict\n");
		DPU_EVENT_LOG("RESOURCE_CONFLICT", exynos_crtc, EVENT_FLAG_ERROR, NULL);
	}

	if (ext_irq & DPU_TIME_OUT_INT_PEND) {
		decon_err(decon, "timeout irq occurs\n");
		DPU_EVENT_LOG("DECON_TIMEOUT", exynos_crtc, EVENT_FLAG_ERROR, NULL);
		decon_dump(exynos_crtc);
		WARN_ON(1);
	}

irq_end:
	spin_unlock(&decon->slock);
	return IRQ_HANDLED;
}

static void decon_parse_urgent_info(struct decon_device *decon, struct device_node *np)
{
	struct decon_urgent *urgent = &decon->config.urgent;

	if (of_property_read_u32(np, "rd_en", &urgent->rd_en))
		decon_warn(decon, "failed to parse urgent rd_en\n");

	if (of_property_read_u32(np, "rd_hi_thres", &urgent->rd_hi_thres))
		decon_warn(decon, "failed to parse urgent rd_hi_thres\n");

	if (of_property_read_u32(np, "rd_lo_thres", &urgent->rd_lo_thres))
		decon_warn(decon, "failed to parse urgent rd_lo_thres\n");

	if (of_property_read_u32(np, "rd_wait_cycle", &urgent->rd_wait_cycle))
		decon_warn(decon, "failed to parse urgent rd_wait_cycle\n");

	if (of_property_read_u32(np, "wr_en", &urgent->wr_en))
		decon_warn(decon, "failed to parse urgent wr_en\n");

	if (of_property_read_u32(np, "wr_hi_thres", &urgent->wr_hi_thres))
		decon_warn(decon, "failed to parse urgent wr_hi_thres\n");

	if (of_property_read_u32(np, "wr_lo_thres", &urgent->wr_lo_thres))
		decon_warn(decon, "failed to parse urgent wr_lo_thres\n");

	if (of_property_read_u32(np, "dta_en", &urgent->dta_en))
		decon_warn(decon, "failed to parse urgent dta_en\n");

	if (urgent->dta_en) {
		if (of_property_read_u32(np, "dta_hi_thres", &urgent->dta_hi_thres))
			decon_err(decon, "failed to parse dta_hi_thres\n");

		if (of_property_read_u32(np, "dta_lo_thres", &urgent->dta_lo_thres))
			decon_err(decon, "failed to parse dta_lo_thres\n");
	}
}

static int decon_parse_bts_info(struct decon_device *decon, struct device_node *np)
{
	int i, dfs_lv_cnt;
	u32 devfreq_idx[3];
	struct dpu_bts *bts = &decon->bts;
	char str_dfs[128];
	size_t remained;
	int n;

	if (of_property_read_u32(np, "ppc", (u32 *)&bts->ppc)) {
		bts->ppc = 2UL;
		decon_warn(decon, "WARN: ppc is not defined in DT.\n");
	}

	if (of_property_read_u32(np, "ppc_rotator", &bts->ppc_rotator)) {
		bts->ppc_rotator = 8U;
		decon_warn(decon, "WARN: rotator ppc is not defined in DT.\n");
	}

	if (of_property_read_u32(np, "ppc_scaler", &bts->ppc_scaler)) {
		bts->ppc_scaler = 4U;
		decon_warn(decon, "WARN: scaler ppc is not defined in DT.\n");
	}

	if (of_property_read_u32(np, "ppc_scaler_comp", &bts->ppc_scaler_comp)) {
		bts->ppc_scaler_comp = bts->ppc_scaler * BTS_DISP_FACTOR;
		decon_info(decon, "INFO: comp + scaler ppc is not defined in DT.\n");
	}

	if (of_property_read_u32(np, "delay_comp", &bts->delay_comp)) {
		bts->delay_comp = 4UL;
		decon_warn(decon, "WARN: comp line delay is not defined in DT.\n");
	}

	if (of_property_read_u32(np, "delay_scaler", &bts->delay_scaler)) {
		bts->delay_scaler = 2UL;
		decon_warn(decon, "WARN: scaler line delay is not defined in DT.\n");
	}

	if (of_property_read_u32(np, "inner_width", &bts->inner_width)) {
		bts->inner_width = 16UL;
		decon_warn(decon, "WARN: internal process width is not defined in DT.\n");
	}

	if (of_property_read_u32(np, "inner_util", &bts->inner_util)) {
		bts->inner_util = 65UL;
		decon_warn(decon, "WARN: internal util is not defined in DT.\n");
	}

	if (of_property_read_u32(np, "bus_width", &bts->bus_width)) {
		bts->bus_width = 32UL;
		decon_warn(decon, "WARN: bus width is not defined in DT.\n");
	}
	if (of_property_read_u32(np, "rot_util", &bts->rot_util)) {
		bts->rot_util = 60UL;
		decon_warn(decon, "WARN: rot util is not defined in DT.\n");
	}

	dfs_lv_cnt = of_property_count_u32_elems(np, "dfs_lv");
	if (dfs_lv_cnt < 0) {
		decon_err(decon, "DPU DFS Info is not defined in DT.\n");
		return -EINVAL;
	}
	bts->dfs_lv_cnt = dfs_lv_cnt;

	bts->dfs_lv = devm_kzalloc(decon->dev, bts->dfs_lv_cnt * sizeof(u32),
			GFP_KERNEL);
	if (of_property_read_u32_array(np, "dfs_lv", bts->dfs_lv, bts->dfs_lv_cnt)) {
		decon_err(decon, "failed to parse devfreq level\n");
		return -EINVAL;
	}

	if (IS_ENABLED(CONFIG_ARM_EXYNOS_DEVFREQ) && of_property_read_u32_array(np,
				"samsung,devfreq-idx", devfreq_idx, 3)) {
		decon_err(decon, "failed to parse devfreq-mif index\n");
		return -EINVAL;
	}

	bts->df_mif_idx = devfreq_idx[0];
	bts->df_int_idx = devfreq_idx[1];
	bts->df_disp_idx = devfreq_idx[2];

	decon_info(decon, "ppc(%u) rot_ppc(%u) scl_ppc(%u)\n",
		bts->ppc, bts->ppc_rotator, bts->ppc_scaler);
	decon_info(decon, "comp_line_delay(%u) scl_line_delay(%u)\n",
		bts->delay_comp, bts->delay_scaler);
	decon_info(decon, "inner_width(%u) inner_util(%u) bus_width(%u) rot_util(%u)\n",
		bts->inner_width, bts->inner_util, bts->bus_width, bts->rot_util);
	decon_info(decon, "devfreq: mif(%u) int(%u) disp(%u))\n",
		bts->df_mif_idx, bts->df_int_idx, bts->df_disp_idx);

	remained = sizeof(str_dfs);
	n = scnprintf(str_dfs, remained, "DPU DFS Level(Khz): ");
	for (i = 0; i < bts->dfs_lv_cnt; i++)
		n += scnprintf(str_dfs + n, remained - n, "%6d ", bts->dfs_lv[i]);
	decon_info(decon, "%s\n", str_dfs);

	return 0;
}

static int decon_parse_pd_names(struct decon_device *decon, struct device_node *np)
{
	int i, ret = 0;
	const char *cur_s;
	struct property *prop;

	if (!IS_ENABLED(CONFIG_EXYNOS_PD))
		return ret;

	decon->pd_cnt = of_property_count_strings(np, "dpuf,pd-names");
	if (decon->pd_cnt <= 0) {
		decon_info(decon, "failed to find dpuf,pd-names(optional)\n");
		decon->pd_cnt = 0;
		return ret;
	}

	decon->pd_names = devm_kmalloc(decon->dev,
			decon->pd_cnt * sizeof(char*), GFP_KERNEL);
	i = 0;
	of_property_for_each_string(np, "dpuf,pd-names", prop, cur_s) {
		decon_info(decon, "dpuf,pd-names[%d](%s)\n", i, cur_s);
		decon->pd_names[i] = devm_kstrdup(decon->dev, cur_s, GFP_KERNEL);
		if (!decon->pd_names[i]) {
			decon_err(decon, "failed to alloc pd_names[%d]\n", i);
			ret = -EINVAL;
		}
		++i;
	}

	return ret;
}

static int decon_parse_dpps(struct decon_device *decon, struct device_node *np)
{
	struct platform_device *dpp_pdev;
	struct device_node *dpp_np;
	int i, ret;

	ret = of_count_phandle_with_args(np, "dpps", NULL);
	if (ret <= 0) {
		decon_err(decon, "failed to get dpp_cnt\n");
		return -ENODEV;
	}
	decon->dpp_cnt = (u32)ret;

	for (i = 0; i < decon->dpp_cnt; ++i) {
		dpp_np = of_parse_phandle(np, "dpps", i);
		if (!dpp_np) {
			decon_err(decon, "can't find dpp%d node\n", i);
			return -EINVAL;
		}

		dpp_pdev = of_find_device_by_node(dpp_np);
		if (dpp_pdev)
			decon->dpp[i] = platform_get_drvdata(dpp_pdev);
		of_node_put(dpp_np);

		if (!dpp_pdev) {
			decon_err(decon, "can't find dpp%d device\n", i);
			return -EINVAL;
		}

		if (!decon->dpp[i]) {
			decon_err(decon, "can't find dpp%d structure\n", i);
			return -EINVAL;
		}
		decon_debug(decon, "found dpp%d\n", decon->dpp[i]->id);
	}

	dpp_np = of_parse_phandle(np, "rcd", 0);
	if (dpp_np && !decon->emul_mode) {
		dpp_pdev = of_find_device_by_node(dpp_np);
		if (dpp_pdev) {
			decon->rcd = platform_get_drvdata(dpp_pdev);
			decon_debug(decon, "found rcd: dpp%d\n", decon->rcd->id);
		}
		of_node_put(dpp_np);
	} else {
		decon_debug(decon, "can't find rcd node\n");
	}

	return 0;
}

static void decon_parse_restriction(struct decon_device *decon, struct device_node *np)
{
	struct decon_restrict *res = (struct decon_restrict*)&decon->restriction;

	/* TODO: delete magic num */
	res->id = decon->id;
	res->disp_max_clock = decon->bts.dfs_lv[0];
	res->disp_margin_pct = 110;
	res->disp_factor_pct = 100;
	res->ppc = decon->bts.ppc;
}

static int decon_parse_dt(struct decon_device *decon, struct device_node *np)
{
	struct property *prop;
	const __be32 *cur;
	int ret = 0;
	u32 val;

	of_property_read_u32(np, "decon,id", &decon->id);

	ret = of_property_read_u32(np, "max_win", &decon->win_cnt);
	if (ret) {
		decon_err(decon, "failed to parse max windows count\n");
		return ret;
	}

	ret = of_property_read_u32(np, "op_mode", &decon->config.mode.op_mode);
	if (ret) {
		decon_err(decon, "failed to parse operation mode(%d)\n", ret);
		return ret;
	}

	ret = of_property_read_u32(np, "trig_mode",
			&decon->config.mode.trig_mode);
	if (ret) {
		decon_err(decon, "failed to parse trigger mode(%d)\n", ret);
		return ret;
	}

	ret = of_property_read_u32(np, "out_type", &decon->config.out_type);
	if (ret) {
		decon_err(decon, "failed to parse output type(%d)\n", ret);
		return ret;
	}

	ret = of_property_read_u32(np, "default_max_bpc", &decon->config.default_max_bpc);
	if (ret) {
		decon_debug(decon, "failed to parse default max bpc(%d)\n", ret);
		decon->config.default_max_bpc = 8;
	}

	decon->config.vote_overlap_bw = of_property_read_bool(np, "vote-overlap-bw");

	if (decon->config.mode.trig_mode == DECON_HW_TRIG) {
		ret = of_property_read_u32(np, "te_from",
				&decon->config.te_from);
		if (ret) {
			decon_err(decon, "failed to get TE from DDI\n");
			return ret;
		}
		if (decon->config.te_from >= MAX_DECON_TE_FROM_DDI) {
			decon_err(decon, "TE from DDI is wrong(%d)\n",
					decon->config.te_from);
			return ret;
		}
		decon_info(decon, "TE from DDI%d\n", decon->config.te_from);
	} else {
		decon->config.te_from = MAX_DECON_TE_FROM_DDI;
		decon_info(decon, "TE from NONE\n");
	}

	if (!of_property_read_u32(np, "svsync_time_us",
					&decon->config.svsync_time)) {
		decon_info(decon, "svsync_time is defined as %dusec in DT.\n",
					decon->config.svsync_time);
		if (!IS_ENABLED(CONFIG_EXYNOS_CMD_SVSYNC) &&
			!IS_ENABLED(CONFIG_EXYNOS_CMD_SVSYNC_ONOFF))
			decon->config.svsync_time = 0;
	}

	if (!of_property_read_u32(np, "svsync_on_fps",
					&decon->config.svsync_on_fps)) {
		decon_info(decon, "svsync_on_fps is defined as %dHz in DT.\n",
					decon->config.svsync_on_fps);
		if (!IS_ENABLED(CONFIG_EXYNOS_CMD_SVSYNC_ONOFF))
			decon->config.svsync_on_fps = 0;
	}

#if IS_ENABLED(CONFIG_DRM_MCD_COMMON)
	if (!of_property_read_u32(np, "svsync_type", &decon->config.svsync_type)) {
		decon_info(decon, "svsync_type: %d\n", decon->config.svsync_type);

		if (IS_ENABLED(CONFIG_EXYNOS_CMD_SVSYNC)) {
			if (decon->config.svsync_type == SVSYNC_TE_SHIFT)
				decon_info(decon, "svsync_type: TE_SHIFT, partial update was disabled\n");
		} else
			decon->config.svsync_type = SVSYNC_NONE;
	}
#endif

	if (decon->config.out_type == DECON_OUT_DSI)
		decon->config.mode.dsi_mode = DSI_MODE_DUAL_DSI;
	else if (decon->config.out_type & (DECON_OUT_DSI0 | DECON_OUT_DSI1))
		decon->config.mode.dsi_mode = DSI_MODE_SINGLE;
	else
		decon->config.mode.dsi_mode = DSI_MODE_NONE;

	ret = of_property_read_u32(np, "decon,dual-display", &val);
	if (ret == 0 && val == 1) {
		decon->config.mode.dsi_mode = DSI_MODE_DUAL_DISPLAY;
		exynos_drm_sfr_dma_mode_switch(false);
	}

	ret = decon_parse_dpps(decon, np);
	if (ret)
		return ret;

	decon_parse_urgent_info(decon, np);
	ret = decon_parse_bts_info(decon, np);
	if (ret)
		return ret;

	ret = decon_parse_pd_names(decon, np);
	if (ret)
		return ret;

	decon_parse_restriction(decon, np);

	of_property_for_each_u32(np, "connector", prop, cur, val)
		decon->con_type |= val;

	ret = of_property_read_u32(np, "decon,emul-mode", &val);
	if (ret == -EINVAL || (ret == 0 && val == 0))
		decon->emul_mode = false;
	else
		decon->emul_mode = true;
	decon_info(decon, "emul_mode=%d\n", decon->emul_mode);

	return 0;
}

static int decon_remap_by_name(struct decon_device *decon, struct device_node *np,
		void __iomem **base, const char *reg_name, enum decon_regs_type type)
{
	int i, ret;
	struct resource res;

	i = of_property_match_string(np, "reg-names", reg_name);
	if (i < 0) {
		decon_info(decon, "failed to find %s SFR region\n", reg_name);
		return 0;
	}

	ret = of_address_to_resource(np, i, &res);
	if (ret)
		return ret;

	*base = devm_ioremap(decon->dev, res.start, resource_size(&res));
	if (!(*base)) {
		decon_err(decon, "failed to remap %s SFR region\n", reg_name);
		return -EINVAL;
	}
	decon_regs_desc_init(*base, reg_name, type, decon->id);

	return 0;
}

static int decon_remap_regs(struct decon_device *decon)
{
	struct device *dev = decon->dev;
	struct device_node *np = dev->of_node;
	struct device_node *sys_np = NULL;

	if (decon_remap_by_name(decon, np, &decon->regs.regs, "main", REGS_DECON))
		goto err;

	if (decon_remap_by_name(decon, np, &decon->regs.win_regs,"win",
				REGS_DECON_WIN))
		goto err;

	if (decon_remap_by_name(decon, np, &decon->regs.sub_regs, "sub",
				REGS_DECON_SUB))
		goto err;

	if (decon_remap_by_name(decon, np, &decon->regs.wincon_regs, "wincon",
				REGS_DECON_WINCON))
		goto err;

	if (decon_remap_by_name(decon, np, &decon->regs.sramc_d_regs[0],
				"sramc_d", REGS_DECON_SRAMC))
		goto err;

	if (decon_remap_by_name(decon, np, &decon->regs.sramc_d_regs[1],
				"sramc1_d", REGS_DECON_SRAMC1))
		goto err;

	sys_np = of_find_compatible_node(NULL, NULL, "samsung,exynos9-disp_ss");
	if (IS_ERR_OR_NULL(sys_np)) {
		decon_err(decon, "failed to find disp_ss node");
		goto err;
	}

	if (decon_remap_by_name(decon, sys_np, &decon->regs.ss_regs, "sys",
				REGS_DECON_SYS))
		goto err;

	of_node_put(sys_np);

	return 0;

err:
	of_node_put(sys_np);

	return -EINVAL;
}

static bool dpu_te_duration_check;
module_param(dpu_te_duration_check, bool, 0600);
MODULE_PARM_DESC(dpu_te_duration_check, "dpu te duration check [default : false]");
static irqreturn_t decon_te_irq_handler(int irq, void *dev_id)
{
	struct decon_device *decon = dev_id;
	struct exynos_hibernation *hibernation;
	struct exynos_drm_crtc *exynos_crtc;

	DPU_ATRACE_BEGIN("te_signal");
	if (!decon)
		goto end;

	exynos_crtc = decon->crtc;

	decon_debug(decon, "state(%d)\n", decon->state);
	if (dpu_te_duration_check) {
		static ktime_t timestamp_s;
		ktime_t timestamp_d = ktime_get();
		s64 diff_usec = ktime_to_us(ktime_sub(timestamp_d, timestamp_s));

		if (timestamp_s)
			decon_info(decon, "vsync elapsed(%3lld.%03lldmsec)\n",
					(diff_usec / USEC_PER_MSEC),
					(diff_usec % USEC_PER_MSEC));
		timestamp_s = timestamp_d;
	}

	if (decon->state != DECON_STATE_ON &&
			decon->state != DECON_STATE_HIBERNATION)
		goto end;

	DPU_EVENT_LOG("TE_INTERRUPT", exynos_crtc, EVENT_FLAG_REPEAT, NULL);

	exynos_profiler_update_vsync_cnt(exynos_crtc);

	hibernation = exynos_crtc->hibernation;

	if (hibernation && !is_hibernaton_blocked(hibernation)
			&& decon->state != DECON_STATE_HIBERNATION)
		kthread_queue_work(&exynos_crtc->worker, &hibernation->work);

	if (decon->config.mode.op_mode == DECON_COMMAND_MODE) {
		drm_crtc_handle_vblank(&exynos_crtc->base);
		DPU_EVENT_LOG("SIGNAL_CRTC_OUT_FENCE", exynos_crtc,
				EVENT_FLAG_REPEAT | EVENT_FLAG_FENCE, NULL);
	}

end:
	DPU_ATRACE_END("te_signal");
	return IRQ_HANDLED;
}

static irqreturn_t sramc_irq_handler(int irq, void *dev_data)
{
	struct decon_device *decon = dev_data;

	spin_lock(&decon->slock);
	if (decon->state != DECON_STATE_ON)
		goto irq_end;

	sramc_d_reg_get_irq_and_clear(decon->id);

	decon_err(decon, "sramc error irq occurs\n");
	if (IS_ENABLED(CONFIG_EXYNOS_BTS))
		decon->bts.ops->print_info(decon->crtc);

	decon_dump(decon->crtc);
	dbg_snapshot_expire_watchdog();
	WARN_ON(1);

irq_end:
	spin_unlock(&decon->slock);
	return IRQ_HANDLED;
}

static void
decon_parse_te_pin_num(struct device_node *np, struct decon_device *decon)
{
	u32 data[3];

	if (!of_property_read_u32_array(np, "gpios", data, 3))
		decon->pnum_te = data[1];
	else
		decon->pnum_te = 0;
}

static int decon_register_irqs(struct decon_device *decon)
{
	struct device *dev = decon->dev;
	struct device_node *np = dev->of_node;
	struct platform_device *pdev;
	int ret = 0;
	int gpio;

	pdev = to_platform_device(dev);

	/* 1: FRAME START */
	decon->irq_fs = of_irq_get_byname(np, "frame_start");
	ret = devm_request_irq(dev, decon->irq_fs, decon_irq_handler,
			0, pdev->name, decon);
	if (ret) {
		decon_err(decon, "failed to install FRAME START irq\n");
		return ret;
	}
	disable_irq(decon->irq_fs);

	/* 2: FRAME DONE */
	decon->irq_fd = of_irq_get_byname(np, "frame_done");
	ret = devm_request_irq(dev, decon->irq_fd, decon_irq_handler,
			0, pdev->name, decon);
	if (ret) {
		decon_err(decon, "failed to install FRAME DONE irq\n");
		return ret;
	}
	disable_irq(decon->irq_fd);

	/* 3: EXTRA: resource conflict, timeout and error irq */
	decon->irq_ext = of_irq_get_byname(np, "extra");
	ret = devm_request_irq(dev, decon->irq_ext, decon_irq_handler,
			0, pdev->name, decon);
	if (ret) {
		decon_err(decon, "failed to install EXTRA irq\n");
		return ret;
	}
	disable_irq(decon->irq_ext);

	/* 4: SRAMC_D: sram controller error irq */
	decon->irq_sramc_d = of_irq_get_byname(np, "sramc_d");
	if ((decon->irq_sramc_d) >= 0) {
		ret = devm_request_irq(dev, decon->irq_sramc_d, sramc_irq_handler,
				0, pdev->name, decon);
		if (ret) {
			decon_err(decon, "failed to install SRAMC_D irq\n");
			return ret;
		}
		disable_irq(decon->irq_sramc_d);
	}

	decon->irq_sramc1_d = of_irq_get_byname(np, "sramc1_d");
	if ((decon->irq_sramc1_d) >= 0) {
		ret = devm_request_irq(dev, decon->irq_sramc1_d, sramc_irq_handler,
				0, pdev->name, decon);
		if (ret) {
			decon_err(decon, "failed to install SRAMC1_D irq\n");
			return ret;
		}
		disable_irq(decon->irq_sramc1_d);
	}

	/*
	 * Get IRQ resource and register IRQ handler. Only enabled in command
	 * mode.
	 */
	if (decon_is_te_enabled(decon)) {
		if (of_get_property(dev->of_node, "gpios", NULL) != NULL) {
			gpio = of_get_gpio(dev->of_node, 0);
			if (gpio < 0) {
				decon_err(decon, "failed to get TE gpio\n");
				return -ENODEV;
			}
		} else {
			decon_debug(decon, "failed to find TE gpio node\n");
			return 0;
		}

		decon->irq_te = gpio_to_irq(gpio);
		decon_parse_te_pin_num(dev->of_node, decon);

		decon_info(decon, "TE irq number(%d)\n", decon->irq_te);
		irq_set_status_flags(decon->irq_te, IRQ_DISABLE_UNLAZY);
		ret = devm_request_irq(dev, decon->irq_te, decon_te_irq_handler,
				       IRQF_TRIGGER_RISING, pdev->name, decon);
		disable_irq(decon->irq_te);
	}

	return ret;
}

static int decon_get_pinctrl(struct decon_device *decon)
{
	int ret = 0;

	decon->res.pinctrl = devm_pinctrl_get(decon->dev);
	if (IS_ERR(decon->res.pinctrl)) {
		decon_debug(decon, "failed to get pinctrl\n");
		ret = PTR_ERR(decon->res.pinctrl);
		decon->res.pinctrl = NULL;
		/* optional in video mode */
		return 0;
	}

	decon->res.te_on = pinctrl_lookup_state(decon->res.pinctrl, "hw_te_on");
	if (IS_ERR(decon->res.te_on)) {
		decon_err(decon, "failed to get hw_te_on pin state\n");
		ret = PTR_ERR(decon->res.te_on);
		decon->res.te_on = NULL;
		goto err;
	}
	decon->res.te_off = pinctrl_lookup_state(decon->res.pinctrl,
			"hw_te_off");
	if (IS_ERR(decon->res.te_off)) {
		decon_err(decon, "failed to get hw_te_off pin state\n");
		ret = PTR_ERR(decon->res.te_off);
		decon->res.te_off = NULL;
		goto err;
	}

err:
	return ret;
}

#ifndef CONFIG_BOARD_EMULATOR
static int decon_get_clock(struct decon_device *decon)
{
	decon->res.aclk = devm_clk_get(decon->dev, "aclk");
	if (IS_ERR_OR_NULL(decon->res.aclk)) {
		decon_info(decon, "failed to get aclk(optional)\n");
		decon->res.aclk = NULL;
	}

	decon->res.aclk_disp = devm_clk_get(decon->dev, "aclk-disp");
	if (IS_ERR_OR_NULL(decon->res.aclk_disp)) {
		decon_info(decon, "failed to get aclk_disp(optional)\n");
		decon->res.aclk_disp = NULL;
	}

	return 0;
}
#else
static inline int decon_get_clock(struct decon_device *decon) { return 0; }
#endif

static int decon_init_resources(struct decon_device *decon)
{
	int ret = 0;

	ret = decon_remap_regs(decon);
	if (ret)
		goto err;

	ret = decon_register_irqs(decon);
	if (ret)
		goto err;

	ret = decon_get_pinctrl(decon);
	if (ret)
		goto err;

	ret = decon_get_clock(decon);
	if (ret)
		goto err;
err:
	return ret;
}

static void decon_emergency_off_handler(struct work_struct *work)
{
	struct decon_device *decon = container_of(work, struct decon_device, off_work);
	struct drm_crtc *crtc = &decon->crtc->base;
	struct drm_device *dev = crtc->dev;
	struct drm_atomic_state *state;
	struct drm_crtc_state *crtc_state;
	struct drm_modeset_acquire_ctx ctx;
	struct exynos_drm_crtc_state *exynos_crtc_state;
	int ret;

	decon_info(decon, "+\n");
	DRM_MODESET_LOCK_ALL_BEGIN(dev, ctx, 0, ret);

	state = drm_atomic_state_alloc(dev);
	if (!state) {
		decon_err(decon, "failed to alloc panel active off state\n");
		return;
	}

	state->acquire_ctx = &ctx;

	crtc_state = drm_atomic_get_crtc_state(state, crtc);
	if (IS_ERR(crtc_state)) {
		decon_err(decon, "failed to get crtc state\n");
		goto free;
	}

	ret = drm_atomic_add_affected_connectors(state, crtc);
	if (ret) {
		decon_err(decon, "failed to add afftected connectors \n");
		goto free;
	}

	crtc_state->active = false;
	exynos_crtc_state = to_exynos_crtc_state(crtc_state);
	exynos_crtc_state->dqe_fd = -1;

	ret = drm_atomic_commit(state);
	if (ret)
		decon_err(decon, "failed to commit emergency off\n");

free:
	drm_atomic_state_put(state);
	DRM_MODESET_LOCK_ALL_END(dev, ctx, ret);
}

static int decon_probe(struct platform_device *pdev)
{
	int ret = 0;
	struct decon_device *decon;
	struct device *dev = &pdev->dev;

	decon = devm_kzalloc(dev, sizeof(struct decon_device), GFP_KERNEL);
	if (!decon)
		return -ENOMEM;

	decon->dev = dev;

	ret = decon_parse_dt(decon, dev->of_node);
	if (ret)
		goto err;

	decon_drvdata[decon->id] = decon;

	spin_lock_init(&decon->slock);
	init_completion(&decon->framestart_done);
	complete(&decon->framestart_done);
	init_waitqueue_head(&decon->framedone_wait);

	pm_runtime_enable(decon->dev);

	/* prevent sleep enter during display(LCD, DP) on */
	ret = device_init_wakeup(decon->dev, true);
	if (ret) {
		dev_err(decon->dev, "failed to init wakeup device\n");
		goto err;
	}

	ret = decon_init_resources(decon);
	if (ret)
		goto err;

	/* set drvdata */
	platform_set_drvdata(pdev, decon);

	exynos_recovery_register(decon);

	ret = component_add(dev, &decon_component_ops);
	if (ret)
		goto err;

	if (decon_reg_get_run_status(decon->id))
		decon->state = DECON_STATE_INIT;
	else
		decon->state = DECON_STATE_OFF;

	INIT_WORK(&decon->off_work, decon_emergency_off_handler);

	decon_info(decon, "successfully probed");

err:
	return ret;
}

bool decon_condition_check(const struct drm_crtc *crtc)
{
	struct exynos_drm_crtc *exynos_crtc;
	struct decon_device *decon;
	bool ret = false;

	exynos_crtc = to_exynos_crtc(crtc);
	if (!exynos_crtc)
		goto exit;

	if (exynos_crtc)
		hibernation_block_exit(exynos_crtc->hibernation);

	decon = exynos_crtc->ctx;

	if (decon->state != DECON_STATE_ON)
		goto exit;

	ret = decon_reg_check_th_error(decon->id);

	if (exynos_crtc)
		hibernation_unblock(exynos_crtc->hibernation);
exit:
	return ret;
}

static int decon_remove(struct platform_device *pdev)
{
	pm_runtime_disable(&pdev->dev);
	component_del(&pdev->dev, &decon_component_ops);

	return 0;
}

#ifdef CONFIG_PM
static int decon_runtime_suspend(struct device *dev)
{
	struct decon_device *decon = dev_get_drvdata(dev);

	if (decon->res.aclk)
		clk_disable_unprepare(decon->res.aclk);

	if (decon->res.aclk_disp)
		clk_disable_unprepare(decon->res.aclk_disp);

	decon_debug(decon, "runtime suspended\n");

	return 0;
}

static int decon_runtime_resume(struct device *dev)
{
	struct decon_device *decon = dev_get_drvdata(dev);

	if (decon->res.aclk)
		clk_prepare_enable(decon->res.aclk);

	if (decon->res.aclk_disp)
		clk_prepare_enable(decon->res.aclk_disp);

	decon_debug(decon, "runtime resumed\n");

	return 0;
}

static int decon_suspend(struct device *dev)
{
	struct decon_device *decon = dev_get_drvdata(dev);

	exynos_dqe_suspend(decon->crtc->dqe);

	decon_debug(decon, "suspended\n");

	return 0;
}

static int decon_resume(struct device *dev)
{
	struct decon_device *decon = dev_get_drvdata(dev);

	exynos_dqe_resume(decon->crtc->dqe);

	decon_debug(decon, "resumed\n");

	return 0;
}

static const struct dev_pm_ops decon_pm_ops = {
	SET_RUNTIME_PM_OPS(decon_runtime_suspend, decon_runtime_resume, NULL)
	.suspend	= decon_suspend,
	.resume		= decon_resume,
};
#endif

struct platform_driver decon_driver = {
	.probe		= decon_probe,
	.remove		= decon_remove,
	.driver		= {
		.name	= "exynos-drmdecon",
#ifdef CONFIG_PM
		.pm	= &decon_pm_ops,
#endif
		.of_match_table = decon_driver_dt_match,
	},
};
EXPORT_SYMBOL(decon_driver);

MODULE_AUTHOR("Hyung-jun Kim <hyungjun07.kim@samsung.com>");
MODULE_AUTHOR("Seong-gyu Park <seongyu.park@samsung.com>");
MODULE_DESCRIPTION("Samsung SoC Display and Enhancement Controller");
MODULE_LICENSE("GPL v2");
