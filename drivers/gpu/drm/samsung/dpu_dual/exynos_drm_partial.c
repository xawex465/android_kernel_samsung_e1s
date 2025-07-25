// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2021 Samsung Electronics Co.Ltd
 *
 * This program is free software; you can redistribute  it and/or modify it
 * under  the terms of  the GNU General  Public License as published by the
 * Free Software Foundation;  either version 2 of the  License, or (at your
 * option) any later version.
 *
 */
#include <linux/device.h>
#include <linux/of.h>
#include <video/mipi_display.h>
#include <drm/drm_fourcc.h>
#include <drm/drm_blend.h>

#include <exynos_drm_partial.h>
#include <exynos_drm_crtc.h>
#include <exynos_drm_decon.h>
#include <exynos_drm_format.h>
#include <exynos_drm_dsim.h>
#include <exynos_drm_dqe.h>
#include <exynos_drm_connector.h>
#include <dsim_cal.h>

#if IS_ENABLED(CONFIG_DRM_MCD_COMMON)
#include <mcd_drm_helper.h>
#endif

#define MIN_WIN_BLOCK_WIDTH	8
#define MIN_WIN_BLOCK_HEIGHT	2

static int dpu_partial_log_level = 6;
module_param(dpu_partial_log_level, int, 0600);
MODULE_PARM_DESC(dpu_partial_log_level, "log level for partial_update [default : 6]");

#define PARTIAL_NAME "exynos-partial"
#define partial_info(partial, fmt, ...)	\
dpu_pr_info(PARTIAL_NAME, (partial)->id, dpu_partial_log_level, fmt, ##__VA_ARGS__)

#define partial_warn(partial, fmt, ...)	\
dpu_pr_warn(PARTIAL_NAME, (partial)->id, dpu_partial_log_level, fmt, ##__VA_ARGS__)

#define partial_err(partial, fmt, ...)	\
dpu_pr_err(PARTIAL_NAME, (partial)->id, dpu_partial_log_level, fmt, ##__VA_ARGS__)

#define partial_debug(partial, fmt, ...)	\
dpu_pr_debug(PARTIAL_NAME, (partial)->id, dpu_partial_log_level, fmt, ##__VA_ARGS__)

#define partial_debug_region(partial, str, r)	\
	partial_debug(partial, "%s["DRM_RECT_FMT"]\n", (str), DRM_RECT_ARG(r))

static int exynos_partial_init(struct exynos_partial *partial,
			const struct drm_display_mode *mode,
			const struct exynos_display_mode *exynos_mode)
{
	const struct exynos_display_dsc *dsc = &exynos_mode->dsc;

	if (dsc->enabled) {
		partial->min_w = DIV_ROUND_UP(mode->hdisplay, dsc->slice_count);
		if (dsc->slice_height % 2)
			partial->min_h = dsc->slice_height * 2;
		else
			partial->min_h = dsc->slice_height;
	} else {
		partial->min_w = MIN_WIN_BLOCK_WIDTH;
		partial->min_h = MIN_WIN_BLOCK_HEIGHT;
	}

	if ((mode->hdisplay % partial->min_w) ||
			(mode->vdisplay % partial->min_h)) {
		partial_err(partial, "cannot support partial update(%dx%d, %dx%d)\n",
				mode->hdisplay, mode->vdisplay,
				partial->min_w, partial->min_h);
		return -EINVAL;
	}

	return 0;
}

void exynos_partial_set_full(const struct drm_display_mode *mode,
		struct drm_rect *partial_r)
{
	partial_r->x1 = 0;
	partial_r->y1 = 0;
	partial_r->x2 = mode->hdisplay;
	partial_r->y2 = mode->vdisplay;
}

#define DISP_V_MARGIN	30	/* 30% considering porch and guard time */
static u32 exynos_partial_get_svsync_y1_max(struct exynos_partial *partial,
		const struct drm_display_mode *mode)
{
	struct decon_device *decon = partial->exynos_crtc->ctx;
	u32 one_fr_t, one_ln_t;
	u32 svsync_lns;

	one_fr_t = DIV_ROUND_UP(NSEC_PER_SEC, decon->bts.fps);

	if ((decon->config.svsync_time * NSEC_PER_USEC) > one_fr_t) {
		/* should check svsync_time */
		partial_err(partial, "svsync_time(%dusec) is over one frame time(%lusec)\n",
				decon->config.svsync_time, one_fr_t / NSEC_PER_USEC);
		return 0;
	}

	one_ln_t = one_fr_t / (mode->vdisplay * (100U + DISP_V_MARGIN) / 100U);
	svsync_lns = decon->config.svsync_time * NSEC_PER_USEC / one_ln_t;

	return (mode->vdisplay - svsync_lns);
}

static bool exynos_partial_check_svsync(struct exynos_partial *partial,
		const struct drm_display_mode *mode, int y1)
{
	struct decon_device *decon = partial->exynos_crtc->ctx;
	u32 svsync_y1_max;

	if (!decon->config.svsync_time)
		return true;

#if IS_ENABLED(CONFIG_DRM_MCD_COMMON)
	if (decon->config.svsync_type == SVSYNC_TE_SHIFT) {
		partial_debug(partial, "Partial update was enabled, but it will be disabled due to te_shfit of svsync.\n");
		return false;
	}
#endif

	svsync_y1_max = exynos_partial_get_svsync_y1_max(partial, mode);
	if (y1 >= svsync_y1_max) {
		partial_debug(partial, "partial y1(%d) is over svsync_y1_max(%d)\n",
				y1, svsync_y1_max);
		return false;
	} else
		return true;
}

static int exynos_partial_adjust_region(struct exynos_partial *partial,
		const struct drm_display_mode *mode,
		const struct drm_rect *req, struct drm_rect *r)
{
	partial_debug_region(partial, "requested update region", req);

	if (!req->x1 && !req->y1 && !req->x2 && !req->y2) {
		partial_debug_region(partial, "invalid partial update region", req);
		return -EINVAL;
	}

	if ((req->x2 > mode->hdisplay) || (req->y2 > mode->vdisplay)) {
		partial_debug(partial, "changed full: requested region is bigger\n");
		return -EINVAL;
	}

	/* adjusted update region */
	r->y1 = rounddown(req->y1, partial->min_h);
	r->y2 = roundup(req->y2, partial->min_h);

	/*
	 * If partial y1 is over the position considering te timing for svsync,
	 * tearing may occur on the screen.
	 */
	if (!exynos_partial_check_svsync(partial, mode, r->y1)) {
		partial_debug(partial, "changed full: after checking svsync_time\n");
		return -EINVAL;
	}

	/*
	 * TODO: Currently, partial width is fixed by LCD width. This will be
	 * changed to be configurable in the future.
	 */
	r->x1 = 0;
	r->x2 = mode->hdisplay;

	partial_debug_region(partial, "adjusted update region", r);

	return 0;
}

static void exynos_plane_print_info(struct exynos_partial *partial,
		const struct drm_plane_state *state)
{
	const struct drm_plane *plane = state->plane;
	const struct drm_rect src = drm_plane_state_src(state);
	const struct drm_rect dst = drm_plane_state_dest(state);
	const struct drm_rect *clipped_src = &state->src;
	const struct drm_rect *clipped_dst = &state->dst;

	partial_debug(partial, "plane%d/win%d src[" DRM_RECT_FP_FMT"] crtc=[" DRM_RECT_FMT"]\n",
			drm_plane_index(plane), state->normalized_zpos,
			DRM_RECT_FP_ARG(&src), DRM_RECT_ARG(&dst));

	partial_debug(partial, "\t\tclipped src["DRM_RECT_FP_FMT"] dst["DRM_RECT_FMT"]\n",
			DRM_RECT_FP_ARG(clipped_src), DRM_RECT_ARG(clipped_dst));
}

static inline bool
exynos_plane_state_rotation(const struct drm_plane_state *state)
{
	unsigned int simplified_rot;

	simplified_rot = drm_rotation_simplify(state->rotation,
			DRM_MODE_ROTATE_0 | DRM_MODE_ROTATE_90 |
			DRM_MODE_REFLECT_X | DRM_MODE_REFLECT_Y);

	return (simplified_rot & DRM_MODE_ROTATE_90) != 0;
}

static inline bool
exynos_plane_state_scaling(const struct drm_plane_state *state)
{
	return (state->src_w >> 16 != state->crtc_w) ||
		(state->src_h >> 16 != state->crtc_h);
}

static bool is_partial_supported(struct exynos_partial *partial,
		const struct drm_plane_state *state,
		struct drm_rect *crtc_r, const struct drm_rect *partial_r,
		const struct dpp_restrict *res)
{
	const struct dpu_fmt *fmt_info;
	unsigned int adj_src_x = 0, adj_src_y = 0;
	u32 format;
	int sz_align = 1;
	struct drm_rect src_r;

	if (exynos_plane_state_rotation(state)) {
		partial_debug(partial, "rotation is detected. partial->full\n");
		goto not_supported;
	}

	if (exynos_plane_state_scaling(state)) {
		partial_debug(partial, "scaling is detected. partial->full\n");
		goto not_supported;
	}

	format = state->fb->format->format;
	fmt_info = dpu_find_fmt_info(format);
	if (IS_YUV(fmt_info)) {
		adj_src_x = state->src_x >> 16;
		adj_src_y = state->src_y >> 16;
		sz_align = 2;

		if (partial_r->x1 > state->crtc_x)
			adj_src_x += partial_r->x1 - state->crtc_x;

		if (partial_r->y1 > state->crtc_y)
			adj_src_y += partial_r->y1 - state->crtc_y;

		/* YUV format must be aligned to 2 */
		if (!IS_ALIGNED(adj_src_x, sz_align) ||
				!IS_ALIGNED(adj_src_y, sz_align)) {
			partial_debug(partial, "align limitation. src_x/y[%d/%d] align[%d]\n",
					adj_src_x, adj_src_y, sz_align);
			goto not_supported;
		}
	}

	if ((drm_rect_width(crtc_r) < res->src_f_w.min * sz_align) ||
			(drm_rect_height(crtc_r) < res->src_f_h.min * sz_align)) {
		partial_debug(partial, "min size limitation. width[%d] height[%d]\n",
				drm_rect_width(crtc_r), drm_rect_height(crtc_r));
		goto not_supported;
	}

	src_r = drm_plane_state_src(state);
	*crtc_r = drm_plane_state_dest(state);
	if (drm_rect_clip_scaled(&src_r, crtc_r, partial_r)) {
		if (((drm_rect_height(&src_r) >> 16) < res->src_h.min * sz_align) ||
				(drm_rect_width(&src_r) >> 16) < res->src_w.min * sz_align) {
			partial_debug(partial, "src min size limitation. width[%d] height[%d]\n",
					drm_rect_width(&src_r), drm_rect_height(&src_r));
			goto not_supported;
		}
	}

	return true;

not_supported:
	exynos_plane_print_info(partial, state);
	return false;
}

static bool exynos_partial_check(struct exynos_partial *partial,
		struct exynos_drm_crtc_state *exynos_crtc_state)
{
	struct drm_crtc_state *crtc_state = &exynos_crtc_state->base;
	struct drm_plane *plane;
	const struct drm_plane_state *plane_state;
	const struct drm_rect *partial_r = &exynos_crtc_state->partial_region;
	struct drm_rect crtc_r;
	const struct dpp_device *dpp;

	drm_for_each_plane_mask(plane, crtc_state->state->dev, crtc_state->plane_mask) {
		plane_state = drm_atomic_get_plane_state(crtc_state->state, plane);

		if (IS_ERR(plane_state))
			return false;

		crtc_r = drm_plane_state_dest(plane_state);
		if (!drm_rect_intersect(&crtc_r, partial_r))
			continue;

		dpp = to_exynos_plane(plane)->ctx;
		partial_debug(partial, "checking plane%d ...\n", drm_plane_index(plane));

		if (!is_partial_supported(partial, plane_state, &crtc_r, partial_r,
					&dpp->restriction))
			return false;
	}
	return true;
}

static int exynos_partial_send_command(struct exynos_partial *partial,
		const struct drm_rect *partial_r)
{
	struct decon_device *decon = partial->exynos_crtc->ctx;
	struct dsim_device *dsim;
	int ret;

	partial_debug(partial, "partial command: [%d %d %d %d]\n",
			partial_r->x1, partial_r->y1,
			drm_rect_width(partial_r), drm_rect_height(partial_r));

	dsim = decon_get_dsim(decon);
	if (!dsim)
		return -ENODEV;

	ret = mipi_dsi_dcs_set_column_address(dsim->dsi_device, partial_r->x1,
			partial_r->x2 - 1);
	if (ret)
		return ret;

	ret = mipi_dsi_dcs_set_page_address(dsim->dsi_device, partial_r->y1,
			partial_r->y2 - 1);
	if (ret)
		return ret;

	return ret;
}

static void exynos_partial_find_included_slice(struct exynos_partial *partial,
		struct exynos_dsc *dsc,
		const struct drm_rect *rect, bool in_slice[])
{
	int slice_left, slice_right;
	int i;

	for (i = 0; i < dsc->slice_count; ++i) {
		slice_left = dsc->slice_width * i;
		slice_right = slice_left + dsc->slice_width;
		in_slice[i] = (slice_left >= rect->x1) && (slice_right <= rect->x2);

		partial_debug(partial, "slice left(%d) right(%d)\n", slice_left, slice_right);
		partial_debug(partial, "slice[%d] is %s\n", i, in_slice[i] ? "in" : "out");
	}
}

#define MAX_DSC_SLICE_CNT	4
static void exynos_partial_set_size(struct exynos_partial *partial,
		const struct drm_rect *partial_r)
{
	struct decon_device *decon = partial->exynos_crtc->ctx;
	struct dsim_device *dsim;
	struct dsim_reg_config dsim_config;
	bool in_slice[MAX_DSC_SLICE_CNT];
	bool dsc_en;
	u32 partial_w, partial_h;

	dsim = decon_get_dsim(decon);
	if (!dsim)
		return;

	dsc_en = dsim->config.dsc.enabled;
	partial_w = drm_rect_width(partial_r);
	partial_h = drm_rect_height(partial_r);

	memcpy(&dsim_config, &dsim->config, sizeof(struct dsim_reg_config));
	dsim_config.p_timing.hactive = partial_w;
	dsim_config.p_timing.vactive = partial_h;
	dsim_config.p_timing.hfp +=
		((dsim->config.p_timing.hactive - partial_w) / (dsc_en ? 3 : 1));
	dsim_config.p_timing.vfp +=
		(dsim->config.p_timing.vactive - partial_h);
	dsim_reg_set_partial_update(dsim->id, &dsim_config);

	exynos_partial_find_included_slice(partial, &decon->config.dsc, partial_r,
			in_slice);
	decon_reg_set_partial_update(decon->id, &decon->config, in_slice,
			partial_w, partial_h);

	partial_debug(partial, "partial[%dx%d] vporch[%d %d %d] hporch[%d %d %d]\n",
			partial_w, partial_h,
			dsim_config.p_timing.vbp, dsim_config.p_timing.vfp,
			dsim_config.p_timing.vsa, dsim_config.p_timing.hbp,
			dsim_config.p_timing.hfp, dsim_config.p_timing.hsa);
}

void exynos_partial_initialize(struct exynos_partial *partial,
			const struct drm_display_mode *mode,
			const struct exynos_display_mode *exynos_mode)
{
	int ret;

	ret = exynos_partial_init(partial, mode, exynos_mode);
	if (ret) {
		partial->enabled = false;
		partial_err(partial, "failed to initialize partial update\n");
	}
	partial->enabled = true;

	partial_debug(partial, "INIT: min rect(%dx%d)\n",
			partial->min_w, partial->min_h);
	DPU_EVENT_LOG("PARTIAL_INIT", partial->exynos_crtc, 0,
		"minimum rect size[%dx%d]", partial->min_w, partial->min_h);
}

static bool
exynos_partial_is_full(const struct drm_display_mode *mode, const struct drm_rect *rect)
{
	struct drm_rect full;

	exynos_partial_set_full(mode, &full);

	return drm_rect_equals(&full, rect);
}

static bool __is_atc_enabled(struct exynos_partial *partial)
{
	struct exynos_dqe *dqe = partial->exynos_crtc->dqe;
	bool atc_enabled = false;

	exynos_dqe_state(dqe, DQE_REG_ATC, &atc_enabled);

	return atc_enabled ? true : false;
}

static bool __is_colormap_enabled(struct drm_crtc_state *new_crtc_state)
{
	return !new_crtc_state->plane_mask;
}

static bool _is_partial_supported(struct exynos_partial *partial,
				  struct drm_crtc_state *old_crtc_state,
				  struct drm_crtc_state *new_crtc_state)
{
	if (__is_atc_enabled(partial) || __is_colormap_enabled(new_crtc_state))
		return false;

	if (new_crtc_state->connectors_changed || new_crtc_state->mode_changed)
		return false;

	if (new_crtc_state->active_changed && !is_crtc_psr_disabled(
			&partial->exynos_crtc->base, new_crtc_state->state))
		return false;

	return true;
}

void exynos_partial_prepare(struct exynos_partial *partial,
		struct exynos_drm_crtc_state *old_exynos_crtc_state,
		struct exynos_drm_crtc_state *new_exynos_crtc_state)
{
	struct drm_crtc_state *crtc_state = &new_exynos_crtc_state->base;
	struct drm_rect *partial_r = &new_exynos_crtc_state->partial_region;
	const struct drm_rect *old_partial_r =
				&old_exynos_crtc_state->partial_region;
	struct drm_clip_rect *req_region;
	struct drm_rect req;
	int ret = -ENOENT;
	bool region_changed = false;

	partial_debug(partial, "plane mask[0x%x]\n", crtc_state->plane_mask);

	new_exynos_crtc_state->needs_reconfigure = false;

	if (!_is_partial_supported(partial, &old_exynos_crtc_state->base, crtc_state)) {
		exynos_partial_set_full(&crtc_state->mode, partial_r);
		return;
	}

#if IS_ENABLED(CONFIG_DRM_MCD_COMMON)
	/* Code for bypass commit when panel was not connected */
	if (mcd_drm_check_commit_skip(partial->exynos_crtc, __func__)) {
		exynos_partial_set_full(&crtc_state->mode, partial_r);
		return;
	}
#endif

	if (old_exynos_crtc_state->partial != new_exynos_crtc_state->partial) {
		if (new_exynos_crtc_state->partial) {
			req_region = new_exynos_crtc_state->partial->data;
			req.x1 = req_region->x1;
			req.y1 = req_region->y1;
			req.x2 = req_region->x2;
			req.y2 = req_region->y2;

			/* find adjusted update region on LCD */
			ret = exynos_partial_adjust_region(partial,
					&crtc_state->mode, &req, partial_r);
		}
		if (ret)
			exynos_partial_set_full(&crtc_state->mode, partial_r);

		region_changed = !drm_rect_equals(partial_r, old_partial_r);
	}

	if (!region_changed) {
		if (!crtc_state->planes_changed) {
			new_exynos_crtc_state->needs_reconfigure =
				!exynos_partial_is_full(&crtc_state->mode, partial_r);
			return;
		} else if (exynos_partial_is_full(&crtc_state->mode, partial_r)) {
			return;
		}
	}

	/* check DPP hw limit if violated, update region is changed to full */
	if (!exynos_partial_check(partial, new_exynos_crtc_state))
		exynos_partial_set_full(&crtc_state->mode, partial_r);

	partial_debug_region(partial, "final update region", partial_r);

	/*
	 * If partial update region is requested, source and destination
	 * coordinates are needed to change if overlapped with update region.
	 */
	new_exynos_crtc_state->needs_reconfigure =
			!exynos_partial_is_full(&crtc_state->mode, partial_r);

	partial_debug(partial, "reconfigure(%d)\n", new_exynos_crtc_state->needs_reconfigure);

	DPU_EVENT_LOG("PARTIAL_PREPARE", partial->exynos_crtc, 0, "req["DRM_RECT_FMT
		"] adj["DRM_RECT_FMT"] prev["DRM_RECT_FMT"] reconfig(%d)",
		DRM_RECT_ARG(&req), DRM_RECT_ARG(partial_r), DRM_RECT_ARG(old_partial_r),
		new_exynos_crtc_state->needs_reconfigure);
}

void exynos_partial_reconfig_coords(struct exynos_partial *partial,
		struct drm_plane_state *plane_state,
		const struct drm_rect *partial_r)
{
	plane_state->visible = drm_rect_clip_scaled(&plane_state->src,
			&plane_state->dst, partial_r);
	if (!plane_state->visible)
		return;

	drm_rect_translate(&plane_state->dst, -(partial_r->x1), -(partial_r->y1));

	partial_debug(partial, "reconfigured coordinates:\n");
	exynos_plane_print_info(partial, plane_state);
}

void exynos_partial_update(struct exynos_partial *partial,
		const struct drm_rect *old_partial_region,
		struct drm_rect *new_partial_region)
{
	struct exynos_drm_crtc *exynos_crtc = partial->exynos_crtc;

	if (!exynos_crtc)
		return;

	if (drm_rect_equals(old_partial_region, new_partial_region))
		return;

	exynos_partial_send_command(partial, new_partial_region);
	exynos_partial_set_size(partial, new_partial_region);
	DPU_EVENT_LOG("PARTIAL_UPDATE", partial->exynos_crtc, 0, "["DRM_RECT_FMT"]",
			DRM_RECT_ARG(new_partial_region));
	partial_debug_region(partial, "applied partial region", new_partial_region);
}

void exynos_partial_restore(struct exynos_partial *partial)
{
	struct exynos_drm_crtc *exynos_crtc = partial->exynos_crtc;
	struct drm_crtc_state *crtc_state;
	struct exynos_drm_crtc_state *exynos_crtc_state;
	struct drm_rect *old_partial_region;

	if (!exynos_crtc)
		return;

	crtc_state = exynos_crtc->base.state;
	if (!crtc_state)
		return;

	exynos_crtc_state = to_exynos_crtc_state(crtc_state);
	old_partial_region = &exynos_crtc_state->partial_region;
	if (exynos_partial_is_full(&crtc_state->mode, old_partial_region))
		return;

	exynos_partial_set_size(partial, old_partial_region);
	DPU_EVENT_LOG("PARTIAL_RESTORE", partial->exynos_crtc, 0,
			"["DRM_RECT_FMT"]", DRM_RECT_ARG(old_partial_region));
	partial_debug_region(partial, "restored partial region", old_partial_region);
}

struct exynos_partial *
exynos_partial_register(struct exynos_drm_crtc *exynos_crtc)
{
	struct device_node *np;
	struct device *dev = exynos_crtc->dev;
	struct exynos_partial *partial;
	struct decon_device *decon = exynos_crtc->ctx;
	int ret = 0;
	u32 val = 1;

	np = dev->of_node;
	ret = of_property_read_u32(np, "partial-update", &val);
	if (ret == -EINVAL || (ret == 0 && val == 0)) {
		pr_info("partial update feature is not supported\n");
		return NULL;
	}

	if (decon->emul_mode) {
		pr_info("partial update disabled in emul-mode\n");
		return NULL;
	}

	partial = devm_kzalloc(dev, sizeof(struct exynos_partial), GFP_KERNEL);
	if (!partial)
		return NULL;

	partial->exynos_crtc = exynos_crtc;
	partial->id = decon->id;
	partial->enabled = false;

	partial_debug(partial, "partial update feature is supported\n");

	return partial;
}
