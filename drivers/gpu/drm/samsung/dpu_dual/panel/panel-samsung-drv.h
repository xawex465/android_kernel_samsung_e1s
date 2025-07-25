/* SPDX-License-Identifier: GPL-2.0-only
 *
 * MIPI-DSI based Samsung common panel driver header
 *
 * Copyright (c) 2019 Samsung Electronics Co., Ltd
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#ifndef _PANEL_SAMSUNG_DRV_
#define _PANEL_SAMSUNG_DRV_

#include <video/mipi_display.h>
#include <video/display_timing.h>
#include <linux/printk.h>
#include <linux/bits.h>
#include <linux/device.h>
#include <linux/delay.h>
#include <linux/regulator/consumer.h>
#include <linux/gpio/consumer.h>
#include <linux/backlight.h>

#include <drm/drm_bridge.h>
#include <drm/drm_connector.h>
#include <drm/drm_crtc.h>
#include <drm/drm_modes.h>
#include <drm/drm_panel.h>
#include <drm/drm_property.h>
#include <drm/drm_mipi_dsi.h>

#include "../exynos_drm_connector.h"
#include "../exynos_drm_debug.h"
#include "../exynos_drm_bridge.h"

#define MAX_CMDSET_NUM 32
#define MAX_CMDSET_PAYLOAD 2048
#define RECT_DESC_SIZE 4
#define POS_DESC_SIZE 2
#define EXYNOS_DRM_MODE_TYPE_IDLE	(0)

#if IS_ENABLED(CONFIG_DRM_PANEL_MCD_COMMON)
#include "../exynos_drm_drv.h"
#include "panel_drv.h"
#endif
#include "../exynos_drm_debug.h"

int get_panel_log_level(void);
#define panel_info(panel, fmt, ...)	\
dpu_pr_info(drv_name((panel)), (panel)->id, get_panel_log_level(), fmt, ##__VA_ARGS__)

#define panel_warn(panel, fmt, ...)	\
dpu_pr_warn(drv_name((panel)), (panel)->id, get_panel_log_level(), fmt, ##__VA_ARGS__)

#define panel_err(panel, fmt, ...)	\
dpu_pr_err(drv_name((panel)), (panel)->id, get_panel_log_level(), fmt, ##__VA_ARGS__)

#define panel_debug(panel, fmt, ...)	\
dpu_pr_debug(drv_name((panel)), (panel)->id, get_panel_log_level(), fmt, ##__VA_ARGS__)

#define MAX_CMDSET_NUM 32
#define MAX_CMDSET_PAYLOAD 2048

#define MAX_REGULATORS		3
#define MAX_HDR_FORMATS		4

#define exynos_connector_to_panel(c)			\
	container_of((c), struct exynos_panel, exynos_connector)
#define connector_to_exynos_panel(c)			\
	exynos_connector_to_panel(to_exynos_connector(c))
#define exynos_bridge_to_exynos_panel(b)			\
	container_of((b), struct exynos_panel, exynos_bridge)
#define bridge_to_exynos_panel(b)			\
	exynos_bridge_to_exynos_panel(to_exynos_bridge(b))
#define to_exynos_panel(p)			\
	container_of((p), struct exynos_panel, panel)
#define dev_to_exynos_panel(d)			\
	mipi_dsi_get_drvdata(to_mipi_dsi_device(d))

struct exynos_panel;

enum exynos_panel_state {
	EXYNOS_PANEL_STATE_INIT = 0,
	EXYNOS_PANEL_STATE_ON,
	EXYNOS_PANEL_STATE_IDLE,
	EXYNOS_PANEL_STATE_OFF,
};

#if IS_ENABLED(CONFIG_DRM_PANEL_MCD_COMMON)
enum exynos_panel_drm_state {
	PANEL_DRM_STATE_DISABLED,
	PANEL_DRM_STATE_ENABLED,
};

enum {
	MCD_DRM_DRV_WQ_VSYNC = 0,
	MCD_DRM_DRV_WQ_FSYNC = 1,
	MCD_DRM_DRV_WQ_DISPON = 2,
	MCD_DRM_DRV_WQ_PANEL_PROBE = 3,
	MCD_DRM_DRV_WQ_FIRST_FRAME = 4,
	MCD_DRM_DRV_WQ_MODESET_POST_WA = 5,
	MAX_MCD_DRM_DRV_WQ,
};

enum {
	PANEL_CMD_LOG_DSI_TX,
	PANEL_CMD_LOG_DSI_RX,
};

struct mcd_drm_drv_wq {
	int index;
	wait_queue_head_t wait;
	struct workqueue_struct *wq;
	struct delayed_work dwork;
	atomic_t count;
	void *data;
	int ret;
	char *name;
};

#define wq_to_exynos_panel(w)	\
	container_of(w, struct exynos_panel, wqs[((w)->index)])

extern int panel_cmd_log_level;
#endif

/* enum should sync-up with exynos_panel_cmd_string in panel-samsung-drv.c */
enum exynos_panel_cmd {
	PANEL_ON_CMDS,
	PANEL_DISP_ON_CMDS,
	PANEL_OFF_CMDS,
	PANEL_PRE_PPS_CMDS,
	PANEL_PPS_CMDS,
	PANEL_POST_PPS_CMDS,
	PANEL_MRES_CMDS,
	PANEL_VREF_CMDS,
	PANEL_TECTRL_CMDS,
	PANEL_LP_CMDS,
	PANEL_CLOSE_CMDS,
	PANEL_OPEN_CMDS,
	NUM_OF_CMDS,
};

struct exynos_videomode {
	char mode[DRM_DISPLAY_MODE_LEN];
	u32 type;
	u32 pixelclock;		/* pixelclock in Hz */

	u32 hactive;
	u32 hfront_porch;
	u32 hback_porch;
	u32 hsync_len;

	u32 vactive;
	u32 vfront_porch;
	u32 vback_porch;
	u32 vsync_len;
	u32 fps;
	u32 bts_fps;
	u32 skip;

	enum display_flags flags; /* display flags */

	u32 mode_flags;
	u32 is_lp_mode;
	u32 bpc;
	u32 dsc_enabled;
	u32 dsc_version;
	u32 dsc_bpc;
	u32 dsc_count;
	u32 dsc_slice_count;
	u32 dsc_slice_height;
};

struct exynos_mipi_dsi_msg {
	struct mipi_dsi_msg msg;
	u32 wait_ms;
};

struct exynos_display_cmd_set {
	int cmd_cnt;
	struct exynos_mipi_dsi_msg *emsg;
};

/*
 * struct exynos_panel_mode - panel mode info
 */
struct exynos_panel_mode {
	/* @mode: drm display mode info */
	struct drm_display_mode mode;
	/* @exynos_mode: exynos driver specific mode info */
	struct exynos_display_mode exynos_mode;
	struct exynos_display_cmd_set cmd_list[NUM_OF_CMDS];
};

struct exynos_panel_funcs {
	int (*set_brightness)(struct exynos_panel *exynos_panel, u16 br);

	/**
	 * @set_lp_mode:
	 *
	 * This callback is used to handle command sequences to enter low power modes.
	 */
	void (*set_lp_mode)(struct exynos_panel *exynos_panel,
			    const struct exynos_panel_mode *mode);

	/**
	 * @mode_set:
	 *
	 * This callback is used to perform driver specific logic for mode_set.
	 * This could be called while display is on or off, should check internal
	 * state to perform appropriate mode set configuration depending on this state.
	 */
	void (*mode_set)(struct exynos_panel *exynos_panel,
		const struct exynos_panel_mode *mode, unsigned int modeset_flags);
	int (*lastclose)(struct exynos_panel *exynos_panel, bool close);

#if IS_ENABLED(CONFIG_DRM_PANEL_MCD_COMMON)
	/*
	 *@ set_clcok_info:
	 *
	 */
	void (*req_set_clock)(struct exynos_panel *exynos_panel, void *arg);
	void (*set_uevent_recovery_state)(struct exynos_panel *exynos_panel, void *arg);
#endif
};

struct exynos_panel_func_set {
	const struct drm_panel_funcs *panel_func;
	const struct exynos_panel_funcs *exynos_panel_func;
};

struct exynos_panel_desc {
	u32 data_lane_cnt;
	u32 hdr_formats;	/* supported HDR formats bitmask */
	u32 max_luminance;
	u32 max_avg_luminance;
	u32 min_luminance;
	u32 max_brightness;
	u32 dft_brightness;	/* default brightness */
	u32 min_brightness;	/* min brightness */
	bool bl_endian_swap;
	u32 width_mm;		/* Physical width in mm */
	u32 height_mm;		/* Physical height in mm */
	size_t num_modes;
	const struct exynos_panel_mode *modes;
	const struct exynos_panel_mode *default_mode;
	const struct exynos_panel_mode *idle_mode;

	bool doze_supported;
	bool idle_state_supported;
	int reset_seq[3];
	int delay_before_reset;
	int reset_delay[3];
	enum exynos_bridge_reset_pos reset_pos;
#if IS_ENABLED(CONFIG_DRM_PANEL_MCD_COMMON)
	const char *xml_suffix;
#endif
};

/* Exynos specific panel structure. */
struct exynos_panel {
	int id;
	/* @dev: A back pointer of device. */
	struct device *dev;
	/* @panel: An embedded DRM core panel object. */
	struct drm_panel panel;
	struct gpio_desc *reset_gpio;
	struct gpio_desc *enable_gpio;
	struct gpio_desc *vddi_gpio;
	struct gpio_desc *vpos_gpio;
	struct gpio_desc *vneg_gpio;
	struct regulator *vci;
	struct regulator *vddi;
	struct regulator *blrdev;
	struct regulator *vddr;
	/* @exynos_connector: An embedded exynos_drm_connector object. */
	struct exynos_drm_connector exynos_connector;
	/* @exynos_bridge: An embedded exynos_drm_bridge object to execute callback. */
	struct exynos_drm_bridge exynos_bridge;
	/* @desc: A exynos specific panel descriptor. */
	struct exynos_panel_desc *desc;
	/* @func_set: The function set to control panel. */
	const struct exynos_panel_func_set *func_set;
	/* @bl: A back pointer of backlight device. */
	struct backlight_device *bl;

	/* @msg: The set of commands to be transferred at once by cmdset_transfer. */
	struct mipi_dsi_msg msg[MAX_CMDSET_NUM];
	/* @cmdset_msg_total: The total count of commands stacked in msg array. */
	int cmdset_msg_total;
	/* @cmdset_payload_total: The total length of the commands. */
	int cmdset_payload_total;

	/**
	 * @idle_work: A delayed work to update panel mode, this work is executed
	 * by system_highpri_wq.
	 */
	struct delayed_work idle_work;

	/* @mode_lock: A mutex lock to protect panel state and mode information. */
	struct mutex mode_lock;
	/* @state: A current panel state protected by mode_lock. */
	enum exynos_panel_state state;
	/**
	 * @self_refresh_active: An indicator of whether the DPU SR is activated.
	 * This is protected by mode_lock.
	 */
	bool self_refresh_active;
	/* @current_mode: A current panel mode protected by mode_lock. */
	const struct exynos_panel_mode *current_mode;
	/**
	 * @restore_mode: A panel mode saved by panel idle work.
	 * This is a mode to be restored when escaping from idle mode.
	 * This is protected by mode_lock.
	 */
	const struct exynos_panel_mode *restore_mode;
	/**
	 * @idle_timer_ms: the time(msec) for entering the panel idle mode
	 * requested by the user. This is protected by mode_lock.
	 */
	u32 idle_timer_ms;
	/**
	 * @last_psr_time_ms: the last time(msec) that DPU SR is activated.
	 * This is protected by mode_lock.
	 */
	u32 last_psr_time_ms;
	/**
	 * @adjusted_fps: applied fps value for display pipeline.
	 * This is protected by mode_lock.
	 */
	unsigned int adjusted_fps;
	bool lastclosed;

#if IS_ENABLED(CONFIG_DRM_PANEL_MCD_COMMON)
	bool enabled;
	bool mcd_panel_probed;
	struct mutex probe_lock;
	struct panel_device *mcd_panel_dev;
	enum exynos_panel_drm_state panel_drm_state;
	struct rw_semaphore panel_drm_state_lock;
	struct mcd_drm_drv_wq wqs[MAX_MCD_DRM_DRV_WQ];
	struct ddi_properties ddi_props;
#if IS_ENABLED(CONFIG_USDM_PANEL_MASK_LAYER)
	bool fingerprint_mask;
#endif
#endif
};

#define for_each_all_panel_mode(desc, pmode, i)				\
	for ((i) = 0; (i) < (desc)->num_modes; ++(i))			\
			for_each_if((pmode) = &(desc)->modes[i])

#define for_each_panel_lp_mode(desc, pmode, i)				\
	for_each_all_panel_mode(desc, pmode, i)				\
			for_each_if((pmode)->exynos_mode.is_lp_mode)

#define for_each_panel_normal_mode(desc, pmode, i)			\
	for_each_all_panel_mode(desc, pmode, i)				\
			for_each_if(!(pmode)->exynos_mode.is_lp_mode)

static inline int get_lp_mode_count(const struct exynos_panel_desc *desc)
{
	const struct exynos_panel_mode *pmode;
	int num = 0;
	int i;

	for_each_panel_lp_mode(desc, pmode, i)
		++num;

	return num;
}

static inline int exynos_dcs_write(struct exynos_panel *ctx, const void *data,
		size_t len)
{
	struct mipi_dsi_device *dsi = to_mipi_dsi_device(ctx->dev);

	return mipi_dsi_dcs_write_buffer(dsi, data, len);
}

/**
 * exynos_dcs_compression_mode() - sends a compression mode command
 * @ctx: exynos panel device
 * @enable: Whether to enable or disable the DSC
 *
 * Return: 0 on success or a negative error code on failure.
 */
static inline int exynos_dcs_compression_mode(struct exynos_panel *ctx, bool enable)
{
	struct mipi_dsi_device *dsi = to_mipi_dsi_device(ctx->dev);

	return mipi_dsi_compression_mode(dsi, enable);
}

static inline int exynos_dcs_set_brightness(struct exynos_panel *ctx, u16 br)
{
	struct mipi_dsi_device *dsi = to_mipi_dsi_device(ctx->dev);

	return mipi_dsi_dcs_set_display_brightness(dsi, br);
}

static inline int exynos_dcs_get_brightness(struct exynos_panel *ctx, u16 *br)
{
	struct mipi_dsi_device *dsi = to_mipi_dsi_device(ctx->dev);

	return mipi_dsi_dcs_get_display_brightness(dsi, br);
}

#define EXYNOS_DCS_WRITE_SEQ(ctx, seq...) do {				\
	u8 d[] = { seq };						\
	int ret;							\
	ret = exynos_dcs_write(ctx, d, ARRAY_SIZE(d));			\
	if (ret < 0)							\
		dev_err(ctx->dev, "failed to write cmd(%d)\n", ret);	\
} while (0)

#define EXYNOS_DCS_WRITE_SEQ_DELAY(ctx, delay, seq...) do {		\
	EXYNOS_DCS_WRITE_SEQ(ctx, seq);					\
	msleep(delay);							\
} while (0)

#define EXYNOS_DCS_WRITE_TABLE(ctx, table) do {				\
	int ret;							\
	ret = exynos_dcs_write(ctx, table, ARRAY_SIZE(table));		\
	if (ret < 0)							\
		dev_err(ctx->dev, "failed to write cmd(%d)\n", ret);	\
} while (0)

#define EXYNOS_PPS_LONG_WRITE_TABLE(ctx, table) do {			\
	struct mipi_dsi_device *dsi = to_mipi_dsi_device(ctx->dev);	\
	int ret;							\
	ret = mipi_dsi_picture_parameter_set(dsi,			\
			(struct drm_dsc_picture_parameter_set*)table);	\
	if (ret < 0)							\
		dev_err(ctx->dev, "failed to write cmd(%d)\n", ret);	\
} while (0)

void exynos_panel_active_off(struct exynos_panel *panel);
int exynos_panel_get_modes(struct drm_panel *panel, struct drm_connector *conn);
int exynos_panel_set_power(struct exynos_panel *ctx, bool on);
void exynos_panel_set_lp_mode(struct exynos_panel *ctx, const struct exynos_panel_mode *pmode);

int dsim_host_cmdset_transfer(struct mipi_dsi_host *host,
			      struct mipi_dsi_msg *msg, int cmd_cnt,
			      bool wait_vsync, bool wait_fifo);
int exynos_drm_cmdset_add(struct exynos_panel *ctx, u8 type, size_t size, const u8 *data);
int exynos_drm_cmdset_cleanup(struct exynos_panel *ctx);
int exynos_drm_cmdset_flush(struct exynos_panel *ctx, bool wait_vsync, bool wait_fifo);

int exynos_panel_probe(struct mipi_dsi_device *dsi);
void exynos_panel_remove(struct mipi_dsi_device *dsi);
void exynos_panel_shutdown(struct mipi_dsi_device *dsi);

#if defined(CONFIG_EXYNOS_DMA_DSIMFC)
int drm_mipi_fcmd_write(void *_ctx, const u8 *payload, int size, u32 align);
#endif

static inline bool is_panel_idle(struct exynos_panel *ctx)
{
	return ctx->state == EXYNOS_PANEL_STATE_IDLE;
}

static inline bool is_panel_active(struct exynos_panel *ctx)
{
	return ctx->state == EXYNOS_PANEL_STATE_ON;
}
#endif /* _PANEL_SAMSUNG_DRV_ */
