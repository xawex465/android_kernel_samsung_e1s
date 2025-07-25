/* SPDX-License-Identifier: GPL-2.0-only
 *
 * Copyright (c) 2020 Samsung Electronics Co., Ltd.
 *		http://www.samsung.com
 *
 * Samsung EXYNOS SoC DisplayPort EDID driver.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <linux/fb.h>
#include <linux/module.h>
#include <linux/list_sort.h>
#include <linux/bitmap.h>
#include <drm/drm_edid.h>
#include <exynos_drm_dp.h>
#ifdef CONFIG_SEC_DISPLAYPORT_SELFTEST
#include "../dp_ext_func/dp_self_test.h"
#endif

#define EDID_SEGMENT_ADDR	(0x60 >> 1)
#define EDID_ADDR		(0xA0 >> 1)
#define EDID_SEGMENT_IGNORE	(2)
#define EDID_BLOCK_SIZE		128
#define EDID_SEGMENT(x)		((x) >> 1)
#define EDID_OFFSET(x)		(((x) & 1) * EDID_BLOCK_SIZE)
#define EDID_EXTENSION_FLAG	0x7E
#define EDID_NATIVE_FORMAT	0x83
#define EDID_BASIC_AUDIO	(1 << 6)
#define EDID_COLOR_DEPTH	0x14

#define DETAILED_TIMING_DESCRIPTIONS_START	0x36

/* force set video format of resolution
 * 0	V640X480P60, V720X480P60, V720X576P50, V1280X800P60RB, 	V1280X720P50,
 * 5	V1280X720P60, V1366X768P60, V1280X1024P60, V1920X1080P24, V1920X1080P25,
 * 10	V1920X1080P30, V1600X900P59, V1600X900P60RB, V1920X1080P50, V1920X1080P59,
 * 15	V1920X1080P60, V2048X1536P60, V1920X1440P60, V2560X1440P59, V1440x2560P60,
 * 20	V1440x2560P75, V2560X1440P60, V3840X2160P24, V3840X2160P25, V3840X2160P30,
 * 25	V4096X2160P24, V4096X2160P25, V4096X2160P30, V3840X2160P59RB, V3840X2160P50,
 * 30	V3840X2160P60, V4096X2160P50, V4096X2160P60, V640X10P60SACRC,
 * RBR : V1920X1080P60,
 * HBR : V2560X1440P60,
 * HBR2: V3840X2160P60, V4096X2160P60,
 * HBR3: V3840X2160P60, V4096X2160P60,
 */
int forced_resolution = -1;
module_param(forced_resolution, int, 0644);

videoformat ud_mode_h14b_vsdb[] = {
	V3840X2160P30,
	V3840X2160P25,
	V3840X2160P24,
	V4096X2160P24
};

static struct v4l2_dv_timings preferred_preset = V4L2_DV_BT_DMT_640X480P60;
static u32 edid_misc;
static int audio_channels;
static int audio_bit_rates;
static int audio_sample_rates;
static int audio_speaker_alloc;

struct fb_audio test_audio_info;

void edid_check_set_i2c_capabilities(struct dp_device *dp)
{
	u8 val[1];

	dp_reg_dpcd_read(&dp->cal_res, DPCD_ADD_I2C_SPEED_CONTROL_CAPABILITES, 1, val);
	dp_info(dp, "DPCD_ADD_I2C_SPEED_CONTROL_CAPABILITES = 0x%x\n", val[0]);

	if (val[0] != 0) {
		if (val[0] & I2C_1Mbps)
			val[0] = I2C_1Mbps;
		else if (val[0] & I2C_400Kbps)
			val[0] = I2C_400Kbps;
		else if (val[0] & I2C_100Kbps)
			val[0] = I2C_100Kbps;
		else if (val[0] & I2C_10Kbps)
			val[0] = I2C_10Kbps;
		else if (val[0] & I2C_1Kbps)
			val[0] = I2C_1Kbps;
		else
			val[0] = I2C_400Kbps;

		dp_reg_dpcd_write(&dp->cal_res, DPCD_ADD_I2C_SPEED_CONTROL_STATUS, 1, val);
		dp_debug(dp, "DPCD_ADD_I2C_SPEED_CONTROL_STATUS = 0x%x\n", val[0]);
	}
}

static int edid_checksum(struct dp_device *dp, u8 *data, int block)
{
	int i;
	u8 sum = 0, all_null = 0;

	for (i = 0; i < EDID_BLOCK_SIZE; i++) {
		sum += data[i];
		all_null |= data[i];
	}

	if (sum || all_null == 0x0) {
		dp_err(dp, "checksum error block = %d sum = %02x\n", block, sum);
		return -EPROTO;
	}

	return 0;
}

#ifdef FEATURE_USE_DRM_EDID_PARSER
static int edid_read_block(struct dp_device *dp,
		int block, u8 *buf, size_t len)
{
	int ret = 0;

	if (len < EDID_BLOCK_SIZE)
		return -EINVAL;

	ret = dp_reg_edid_read(&dp->cal_res, (u8)block, EDID_BLOCK_SIZE, buf);
	if (ret)
		dp_edid_dump(dp, buf, EDID_BLOCK_SIZE);

	return ret;
}
#else
static int edid_read_block(struct dp_device *dp,
		int block, u8 *buf, size_t len)
{
	int ret = 0;
	u8 offset = EDID_OFFSET(block);

	if (len < EDID_BLOCK_SIZE)
		return -EINVAL;

	edid_check_set_i2c_capabilities(dp);

	ret = dp_reg_edid_read(&dp->cal_res, offset, EDID_BLOCK_SIZE, buf);
	if (ret)
		return ret;

	print_hex_dump(KERN_INFO, "EDID: ", DUMP_PREFIX_OFFSET, 16, 1,
					buf, 128, false);

	return 0;
}
#endif

#ifdef FEATURE_USE_DRM_EDID_PARSER
static int edid_check_extension_tag(struct dp_device *dp, u8 ext_tag)
{
	dp_debug(dp, "extension tag: 0x%x\n", ext_tag);

	switch (ext_tag) {
	case 0x02: /* CEA Ext */
	case 0xF0: /* Ext Block map */
	case 0x70: /* DisplayID */
		return 0;
	default:
		return -EINVAL;
	}
}

static struct drm_display_mode mode_vga[1] = {
	/* 1 - 640x480@60Hz 4:3 */
	{ DRM_MODE("640x480", DRM_MODE_TYPE_DRIVER, 25175, 640, 656,
		752, 800, 0, 480, 490, 492, 525, 0,
		DRM_MODE_FLAG_NHSYNC | DRM_MODE_FLAG_NVSYNC),
	.picture_aspect_ratio = HDMI_PICTURE_ASPECT_4_3, }
};

static int proaudio_support_vics[] = {
	4, /* 720P60 */
	34, /* 1920X1080P30 */
	16, /* 1920X1080P60 */
	95, /* 3840X2160P30 */
	97, /* 3840X2160P60 */
};
#ifdef FEATURE_DEX_SUPPORT
static struct dex_support_modes secdp_dex_resolution[] = {
	{1600,  900, MON_RATIO_16_9, DEX_FHD_SUPPORT},
	{1920, 1080, MON_RATIO_16_9, DEX_FHD_SUPPORT},
	{1920, 1200, MON_RATIO_16_10, DEX_WQHD_SUPPORT},
	{2560, 1080, MON_RATIO_21_9, DEX_WQHD_SUPPORT},
	{2560, 1440, MON_RATIO_16_9, DEX_WQHD_SUPPORT},
	{2560, 1600, MON_RATIO_16_10, DEX_WQHD_SUPPORT},
	{3440, 1440, MON_RATIO_21_9, DEX_WQHD_SUPPORT}
};

enum mon_aspect_ratio_t secdp_get_aspect_ratio(struct drm_display_mode *mode)
{
	enum mon_aspect_ratio_t aspect_ratio = MON_RATIO_NA;
	int hdisplay = mode->hdisplay;
	int vdisplay = mode->vdisplay;

	if ((hdisplay == 4096 && vdisplay == 2160) ||
		(hdisplay == 3840 && vdisplay == 2160) ||
		(hdisplay == 2560 && vdisplay == 1440) ||
		(hdisplay == 1920 && vdisplay == 1080) ||
		(hdisplay == 1600 && vdisplay ==  900) ||
		(hdisplay == 1366 && vdisplay ==  768) ||
		(hdisplay == 1280 && vdisplay ==  720))
		aspect_ratio = MON_RATIO_16_9;
	else if ((hdisplay == 2560 && vdisplay == 1600) ||
		(hdisplay  == 1920 && vdisplay == 1200) ||
		(hdisplay  == 1680 && vdisplay == 1050) ||
		(hdisplay  == 1440 && vdisplay ==  900) ||
		(hdisplay  == 1280 && vdisplay ==  800))
		aspect_ratio = MON_RATIO_16_10;
	else if ((hdisplay == 3840 && vdisplay == 1600) ||
		(hdisplay == 3440 && vdisplay == 1440) ||
		(hdisplay == 2560 && vdisplay == 1080))

		aspect_ratio = MON_RATIO_21_9;
	else if ((hdisplay == 1720 && vdisplay == 1440) ||
		(hdisplay == 1280 && vdisplay == 1080))
		aspect_ratio = MON_RATIO_10P5_9;
	else if (hdisplay == 2520 && vdisplay == 1200)
		aspect_ratio = MON_RATIO_21_10;
	else if (hdisplay == 1320 && vdisplay == 1200)
		aspect_ratio = MON_RATIO_11_10;
	else if ((hdisplay == 5120 && vdisplay == 1440) ||
		(hdisplay  == 3840 && vdisplay == 1080))
		aspect_ratio = MON_RATIO_32_9;
	else if (hdisplay == 3840 && vdisplay == 1200)
		aspect_ratio = MON_RATIO_32_10;
	else if ((hdisplay == 1280 && vdisplay == 1024) ||
		(hdisplay  ==  720 && vdisplay ==  576))
		aspect_ratio = MON_RATIO_5_4;
	else if (hdisplay == 1280 && vdisplay == 768)
		aspect_ratio = MON_RATIO_5_3;
	else if ((hdisplay == 1152 && vdisplay == 864) ||
		(hdisplay  == 1024 && vdisplay == 768) ||
		(hdisplay  ==  800 && vdisplay == 600) ||
		(hdisplay  ==  640 && vdisplay == 480))
		aspect_ratio = MON_RATIO_4_3;
	else if (hdisplay == 720 && vdisplay == 480)
		aspect_ratio = MON_RATIO_3_2;

	return aspect_ratio;
}

/*
 * mode comparison for Dex mode
 * from drm_mode_compare() at drm_modes.c
 *
 * Returns:
 * Negative if @lh_a is better than @lh_b, zero if they're equivalent, or
 * positive if @lh_b is better than @lh_a.
 */
int dp_mode_compare_for_dex(void *priv, const struct list_head *lh_a, const struct list_head *lh_b)
{
	struct dp_device *dp = (struct dp_device *)priv;
	struct drm_display_mode *a = list_entry(lh_a, struct drm_display_mode, head);
	struct drm_display_mode *b = list_entry(lh_b, struct drm_display_mode, head);
	enum mon_aspect_ratio_t ratio_p = secdp_get_aspect_ratio(&dp->pref_mode);
	enum mon_aspect_ratio_t ratio_a = secdp_get_aspect_ratio(a);
	enum mon_aspect_ratio_t ratio_b = secdp_get_aspect_ratio(b);
	int diff;
	int res_t = secdp_dex_resolution[0].active_h * secdp_dex_resolution[0].active_v;
	int res_a = a->hdisplay * a->vdisplay;
	int res_b = b->hdisplay * b->vdisplay;

	/* The same ratio as the preferred mode is better */
	/* but not for less resolution than min dex support mode*/
	if (dp->prefer_found) {
		if (res_a >= res_t && res_b >= res_t &&
			ratio_a != MON_RATIO_NA && ratio_b != MON_RATIO_NA) {
			diff = (ratio_p == ratio_b) - (ratio_p == ratio_a);
			if (diff)
				return diff;
		}
	}

	diff = res_b - res_a;
	if (diff)
		return diff;

	diff = drm_mode_vrefresh(b) - drm_mode_vrefresh(a);
	if (diff)
		return diff;

	diff = b->clock - a->clock;

	return diff;
}

/*
 * sort for dex mode as priority
 * 1. preferred ratio
 * 2. higher resolution
 * 3. higher fps
 * 4. higher pixel clock
 */
void dp_mode_sort_for_dex(struct dp_device *dp)
{
	dp_debug(dp, "%s\n", __func__);

	list_sort(dp, &dp->connector.base.probed_modes, dp_mode_compare_for_dex);
}

/* return -EINVAL: not support */
static int dp_mode_is_dex_support(struct dp_device *dp, struct drm_display_mode *mode)
{
	int i;
	int arr_size = ARRAY_SIZE(secdp_dex_resolution);
	int idx = -EINVAL;

	/* every modes under FHD support */
	if (mode->vdisplay * mode->hdisplay < 1920 * 1080)
		return 0;

	for (i = 0; i < arr_size; i++) {
		if (mode->hdisplay == secdp_dex_resolution[i].active_h &&
				mode->vdisplay == secdp_dex_resolution[i].active_v) {
			idx = i;
			break;
		}
	}

	return idx;
}

static bool dp_mode_check_adapter_type(struct dp_device *dp, int idx)
{
	if (idx >= ARRAY_SIZE(secdp_dex_resolution) || idx < 0)
		return false;

	if (secdp_dex_resolution[idx].support_type > dp->dex.adapter_type)
		return false;

	return true;
}
#endif

/* return true: modes's resolution are equal */
static bool dp_mode_resolution_match(struct drm_display_mode *ma, struct drm_display_mode *mb)
{
	if (ma->hdisplay == mb->hdisplay && ma->vdisplay == mb->vdisplay)
		return true;

	return false;
}

/*
 * mode comparison
 * from drm_mode_compare() at drm_modes.c
 * Returns:
 * Negative if @lh_a is better than @lh_b, zero if they're equivalent, or
 * positive if @lh_b is better than @lh_a.
 */
int dp_mode_compare_for_mirror(void *priv, const struct list_head *lh_a, const struct list_head *lh_b)
{
	struct dp_device *dp = (struct dp_device *)priv;
	struct drm_display_mode *a = list_entry(lh_a, struct drm_display_mode, head);
	struct drm_display_mode *b = list_entry(lh_b, struct drm_display_mode, head);
	int diff;

	if (dp->prefer_found) {
		/* The same resolution as the preferred mode is better */
		diff = dp_mode_resolution_match(&dp->pref_mode, b) -
				dp_mode_resolution_match(&dp->pref_mode, a);
		if (diff)
			return diff;

		/* do not compare preferred if both have the same resolution as the preferred */
		if (!dp_mode_resolution_match(&dp->pref_mode, a)) {
			diff = ((b->type & DRM_MODE_TYPE_PREFERRED) != 0) -
				((a->type & DRM_MODE_TYPE_PREFERRED) != 0);
			if (diff)
				return diff;
		}
	}

	diff = b->hdisplay * b->vdisplay - a->hdisplay * a->vdisplay;
	if (diff)
		return diff;

	diff = drm_mode_vrefresh(b) - drm_mode_vrefresh(a);
	if (diff)
		return diff;

	diff = b->clock - a->clock;
	return diff;
}

/*
 * sort for mirror mode as priority
 * 1. preferred resolution
 * 2. preferred type
 * 3. higher resolution
 * 4. higher fps
 * 5. higher pixel clock
 */
void dp_mode_sort_for_mirror(struct dp_device *dp)
{
	dp_debug(dp, "%s\n", __func__);
	list_sort(dp, &dp->connector.base.probed_modes, dp_mode_compare_for_mirror);
}

#ifdef FEATURE_HIGHER_RESOLUTION
/*
 * mode comparison
 * from drm_mode_compare() at drm_modes.c
 * Returns:
 * Negative if @lh_a is better than @lh_b, zero if they're equivalent, or
 * positive if @lh_b is better than @lh_a.
 */
int dp_mode_compare_for_higher(void *priv, const struct list_head *lh_a, const struct list_head *lh_b)
{
	struct drm_display_mode *a = list_entry(lh_a, struct drm_display_mode, head);
	struct drm_display_mode *b = list_entry(lh_b, struct drm_display_mode, head);
	int diff;

	diff = b->hdisplay * b->vdisplay - a->hdisplay * a->vdisplay;
	if (diff)
		return diff;

	diff = drm_mode_vrefresh(b) - drm_mode_vrefresh(a);
	if (diff)
		return diff;

	diff = b->clock - a->clock;
	return diff;
}

/*
 * sort for higher mode as priority
 * 1. higher resolution
 * 2. higher fps
 * 3. higher pixel clock
 */

void dp_mode_sort_for_higher(struct dp_device *dp)
{
	dp_debug(dp, "%s\n", __func__);
	list_sort(dp, &dp->connector.base.probed_modes, dp_mode_compare_for_higher);
}

#endif

void dp_mode_set_fail_safe(struct dp_device *dp)
{
	dp->cal_res.bpc = BPC_6;
	drm_mode_copy(&dp->cur_mode, mode_vga);
	drm_mode_copy(&dp->best_mode, mode_vga);
#ifdef FEATURE_DEX_SUPPORT
	drm_mode_copy(&dp->dex.best_mode, mode_vga);
#endif
	/*FEATURE_DSC_SUPPORT*/
	dp->dsc_en = false;
	dp->fail_safe = true;
}

static void dp_sad_to_audio_info(struct dp_device *dp, struct cea_sad *sads, int num)
{
	int i;

	for (i = 0; i < num; i++) {
		dp_info(dp, "audio format: %d, channels: %d, freq: %d, bit: %d\n",
			sads[i].format, sads[i].channels, sads[i].freq, sads[i].byte2);

		if (sads[i].format == HDMI_AUDIO_CODING_TYPE_PCM) {
			audio_channels |= 1 << sads[i].channels;
			audio_sample_rates |= sads[i].freq;
			audio_bit_rates |= sads[i].byte2;
		}
	}
}

#ifdef FEATURE_DSC_SUPPORT
u64 dp_get_dsc_pixclock(struct drm_display_mode *mode)
{
	u64 pixclock = (u64)mode->clock * 1000ULL;
	int total;
	int active;
	int dsc_active;
	int mul;

	total = mode->htotal * mode->vtotal;
	active = mode->hdisplay * mode->vdisplay;

	/* not support over 8k@30 */
	if (active * drm_mode_vrefresh(mode) > MODE_MAX_RESOLUTION)
		return pixclock;

	/* dsc 3:1 */
	mul = pixclock / total;
	dsc_active = (active + 2) / 3;
	pixclock = (u64)(total - active + dsc_active) * (u64)mul;

	return pixclock;
}
#endif

/* return true: support */
bool dp_mode_filter(struct dp_device *dp, struct drm_display_mode *mode, int flag)
{
	int refresh = drm_mode_vrefresh(mode);

	/* YCbCr420 but not preferred */
	if (!(mode->type & DRM_MODE_TYPE_PREFERRED) &&
			drm_mode_is_420_only(&dp->connector.base.display_info, mode))
		return false;

	/* interlace */
	if (mode->flags & DRM_MODE_FLAG_INTERLACE)
		return false;

	/* for test sink, do not apply filter */
	if (flag & MODE_FILTER_TEST_SINK) {
		if (dp->test_sink)
			return true;
	}

	/* max resolution */
	if (flag & MODE_FILTER_MAX_RESOLUTION) {
		if ((mode->hdisplay * mode->vdisplay * refresh) > MODE_MAX_RESOLUTION)
			return false;
	}

	if (flag & MODE_FILTER_PIXEL_CLOCK) {
		int clock = mode->clock;

#ifdef FEATURE_DSC_SUPPORT
		if (dp->sink_dsc_support && dp_check_dsc_capability(dp, mode))
			clock = dp_get_dsc_pixclock(mode) / 1000;
#endif
		if (dp->cur_pix_clk < clock)
			return false;
	}

	if (flag & MODE_FILTER_MIN_FPS) {
		if (refresh < MODE_MIN_FPS)
			return false;
	}

	if (flag & MODE_FILTER_MAX_FPS) {
		if (refresh > MODE_MAX_FPS)
			return false;
	}

#ifdef FEATURE_DEX_SUPPORT
	if (flag & MODE_FILTER_DEX_MODE) {
		int idx = dp_mode_is_dex_support(dp, mode);

		if (idx < 0)
			return false;

		if (flag & MODE_FILTER_DEX_ADAPTER) {
			if (!dp_mode_check_adapter_type(dp, idx))
				return false;
		}
	}
#endif

	return true;
}

/* return true: ma is better */
bool dp_mode_fps_compare(struct drm_display_mode *ma, struct drm_display_mode *mb)
{
	int a_fps = drm_mode_vrefresh(ma);
	int b_fps = drm_mode_vrefresh(mb);

	return a_fps - b_fps > 0 ? true : false;
}

/* set status to BAD until the best_mode then the best_mode will be chosen */
void dp_mode_filter_out(struct dp_device *dp, int mode_num)
{
	struct drm_display_mode *mode, *t;
	struct drm_connector *connector = &dp->connector.base;
	int bad_count = 0;
	bool is_dex = false;

	/* should use the same sort as connector driver */
	drm_mode_sort(&dp->connector.base.probed_modes);

#ifdef FEATURE_DEX_SUPPORT
#ifdef FEATURE_MANAGE_HMD_LIST
	mutex_lock(&dp->hmd_lock);
	if (dp->is_hmd_dev)
		is_dex = false;
	else if (dp->dex.ui_setting)
		is_dex = true;
	mutex_unlock(&dp->hmd_lock);
#endif
	if (dp->dex.ui_setting)
		is_dex = true;
#endif
	if (is_dex)
		drm_mode_copy(&dp->cur_mode, &dp->dex.best_mode);
	else
		drm_mode_copy(&dp->cur_mode, &dp->best_mode);

	list_for_each_entry_safe(mode, t, &connector->probed_modes, head) {
		if (mode->type & DRM_MODE_TYPE_PREFERRED &&
				drm_mode_is_420_only(&connector->display_info, mode)) {
			u8 vic = drm_match_cea_mode(mode);

			/* HACK: prevent preferred from becomming ycbcr420 */
			bitmap_clear(connector->display_info.hdmi.y420_vdb_modes, vic, 1);
			dp_info(dp, "unset ycbcr420 for prefer %s@%d vic %d\n",
				mode->name, drm_mode_vrefresh(mode), vic);
		}
		if (drm_mode_match(&dp->cur_mode, mode,
				DRM_MODE_MATCH_TIMINGS|DRM_MODE_MATCH_CLOCK))
			break;
		mode->status |= MODE_BAD;
		dp_debug(dp, "filter out: %s@%d, pclk:%d, stat: %d\n",
			mode->name, drm_mode_vrefresh(mode), mode->clock, mode->status);
		bad_count++;
	}

	if (bad_count >= mode_num)
		dp->fail_safe = true;

	dp_info(dp, "%d modes are removed\n", bad_count);
}

void dp_mode_clean_up(struct dp_device *dp)
{
	struct drm_display_mode *mode, *t;
	struct drm_connector *connector = &dp->connector.base;

	list_for_each_entry_safe(mode, t, &connector->probed_modes, head) {
		list_del(&mode->head);
		drm_mode_destroy(connector->dev, mode);
	}
}

#ifdef FEATURE_DEX_SUPPORT
void dp_find_best_mode_for_dex(struct dp_device *dp)
{
	struct drm_display_mode *mode, *t;
	struct drm_connector *connector = &dp->connector.base;
	int flag = MODE_FILTER_DEX | MODE_FILTER_DEX_ADAPTER;

#ifdef FEATURE_DEX_ADAPTER_TWEAK
	if (dp->dex.skip_adapter_check)
		flag &= ~MODE_FILTER_DEX_ADAPTER;
#endif
	dp_mode_sort_for_dex(dp);
	drm_mode_copy(&dp->dex.best_mode, mode_vga);

	list_for_each_entry_safe(mode, t, &connector->probed_modes, head) {
		if (dp_mode_filter(dp, mode, flag)) {
			drm_mode_copy(&dp->dex.best_mode, mode);
			break;
		}
	}
#ifdef FEATURE_DSC_SUPPORT
	if (dp->dex.ui_setting) {
		if (dp->sink_dsc_support && dp_check_dsc_capability(dp, &dp->dex.best_mode))
			dp->dsc_en = true;
		else
			dp->dsc_en = false;
	}
#endif
	dp_info(dp, "best mode for dex: %s@%d dsc_en:%d\n", dp->dex.best_mode.name,
		drm_mode_vrefresh(&dp->dex.best_mode), dp->dsc_en);
}
#endif

void dp_find_best_mode(struct dp_device *dp, int flag)
{
	struct drm_display_mode *mode, *t;
	struct drm_connector *connector = &dp->connector.base;
	bool found = false;

	list_for_each_entry_safe(mode, t, &connector->probed_modes, head) {
		if (dp_mode_filter(dp, mode, flag)) {
			if (!found && !dp->test_sink) { /* for link cts */
				drm_mode_copy(&dp->best_mode, mode);
				drm_mode_copy(&dp->cur_mode, mode);
				found = true;
			}
		} else {
			mode->status |= MODE_BAD;
		}

		if (flag & MODE_FILTER_PRINT && mode->status == 0) {
#ifdef FEATURE_DSC_SUPPORT
			dp_info(dp, "%s@%d, pclk:%d(%llu)\n",
				mode->name, drm_mode_vrefresh(mode), mode->clock,
				dp_get_dsc_pixclock(mode) / 1000);
#else
			dp_info(dp, "%s@%d, pclk:%d\n",
				mode->name, drm_mode_vrefresh(mode), mode->clock);
#endif
		}
	}
#ifdef FEATURE_DSC_SUPPORT
	if (dp->sink_dsc_support && dp_check_dsc_capability(dp, &dp->best_mode))
		dp->dsc_en = true;
	else
		dp->dsc_en = false;
#endif
	dp_info(dp, "best mode: %s@%d dsc_en:%d\n", dp->best_mode.name,
		drm_mode_vrefresh(&dp->best_mode), dp->dsc_en);
}

static int dp_mode_compare_timing(struct drm_display_mode *a, struct drm_display_mode *b)
{
	int diff;

	diff = b->hdisplay * b->vdisplay - a->hdisplay * a->vdisplay;
	if (diff)
		return diff;

	diff = drm_mode_vrefresh(b) - drm_mode_vrefresh(a);
	if (diff)
		return diff;

	diff = b->clock - a->clock;
	return diff;
}

#ifdef FEATURE_8K_PREFER_SUPPORT
bool dp_is_8k_resolution(struct drm_display_mode *mode)
{
	if (mode->hdisplay >= 7680 && mode->vdisplay >= 4320)
		return true;

	return false;
}
#endif

bool dp_find_prefer_mode(struct dp_device *dp, int flag)
{
	struct drm_display_mode *mode, *t, *best_pref_mode = NULL;
	struct drm_connector *connector = &dp->connector.base;

	dp->prefer_found = false;
	list_for_each_entry_safe(mode, t, &connector->probed_modes, head) {
#ifdef FEATURE_8K_PREFER_SUPPORT
		if (dp_is_8k_resolution(mode))
			mode->type |= DRM_MODE_TYPE_PREFERRED;
#endif
		if ((mode->type & DRM_MODE_TYPE_PREFERRED) &&
				dp_mode_filter(dp, mode, flag)) {
			dp_info(dp, "pref: %s@%d, type: %d, stat: %d, ratio: %d\n",
				mode->name, drm_mode_vrefresh(mode), mode->type,
				mode->status, mode->picture_aspect_ratio);
			if ((best_pref_mode == NULL) ||
					(dp_mode_compare_timing(best_pref_mode, mode) > 0))
				best_pref_mode = mode;
		}
	}

	if (best_pref_mode) {
		dp_info(dp, "best_pref: %s@%d, type: %d, stat: %d, ratio: %d\n",
			best_pref_mode->name, drm_mode_vrefresh(best_pref_mode), best_pref_mode->type,
			best_pref_mode->status, best_pref_mode->picture_aspect_ratio);
		drm_mode_copy(&dp->pref_mode, best_pref_mode);
		drm_mode_copy(&dp->cur_mode, best_pref_mode);
		drm_mode_copy(&dp->best_mode, best_pref_mode);
		dp->prefer_found = true;
	} else {
		dp_info(dp, "no prefer timing\n");
	}

	return (best_pref_mode != NULL);
}

void dp_mode_var_init(struct dp_device *dp)
{
	audio_channels = 0;
	audio_bit_rates = 0;
	audio_sample_rates = 0;
	audio_speaker_alloc = 0;
	dp->fail_safe = false;
	dp->test_sink = false;
	dp->prefer_found = false;
	dp->dsc_en = false;
	dp->sink_dsc_support = false;
	dp->rx_edid_data.hdr_support = false;
	/* set default mode to VGA */
	drm_mode_copy(&dp->pref_mode, mode_vga);
	drm_mode_copy(&dp->cur_mode, mode_vga);
	drm_mode_copy(&dp->best_mode, mode_vga);
#ifdef FEATURE_DEX_SUPPORT
	drm_mode_copy(&dp->dex.best_mode, mode_vga);
#endif
}

static void dp_check_test_device(struct dp_device *dp)
{
	if (!strcmp(dp->sink_info.monitor_name, "UNIGRAF TE") ||
			!strcmp(dp->sink_info.monitor_name, "UFG DPR-120") ||
			!strcmp(dp->sink_info.monitor_name, "UCD-400 DP") ||
			!strcmp(dp->sink_info.monitor_name, "AGILENT ATR") ||
			!strcmp(dp->sink_info.monitor_name, "UFG DP SINK")) {
		/* TODO: is this needed? */
		/* dp->bist_used = 1; */
		dp->test_sink = true;
	}
}

#ifdef FEATURE_MANAGE_HMD_LIST
static void dp_check_hmd_dev(struct dp_device *dp)
{
	struct secdp_sink_dev *hmd = dp->hmd_list;
	int i;

	mutex_lock(&dp->hmd_lock);
	dp->is_hmd_dev = false;
	for (i = 0; i < MAX_NUM_HMD; i++) {
		if (hmd[i].ven_id == 0 && hmd[i].prod_id == 0)
			continue;
		if (!strncmp(hmd[i].monitor_name, dp->sink_info.monitor_name, MON_NAME_LEN) &&
				hmd[i].ven_id == (u32)dp->sink_info.ven_id &&
				hmd[i].prod_id == (u32)dp->sink_info.prod_id) {
			dp_info(dp, "HMD %s\n", hmd[i].monitor_name);
			dp->is_hmd_dev = true;
			break;
		}
	}
	mutex_unlock(&dp->hmd_lock);
}
#endif

#ifdef FEATURE_DEX_SUPPORT
static void dp_get_dex_adapter_type(struct dp_device *dp)
{
#ifdef CONFIG_SEC_DISPLAYPORT_SELFTEST
	if (self_test_on_process()) {
		dp->dex.adapter_type = self_test_get_dp_adapter_type();
		return;
	}
#endif
	dp->dex.adapter_type = DEX_FHD_SUPPORT;

	if (dp->sink_info.ven_id != 0x04e8)
		return;

	switch (dp->sink_info.prod_id) {
	case 0xa029: /* PAD */
	case 0xa020: /* Station */
		dp->dex.adapter_type = DEX_WQHD_SUPPORT;
		break;
	};
}
#endif

static void dp_get_sink_info(struct dp_device *dp)
{
	struct edid *edid = (struct edid *)dp->rx_edid_data.edid_buf;
	u32 prod_id = 0;
	char *edid_vendor = dp->rx_edid_data.edid_manufacturer;

	edid_vendor[0] = ((edid->mfg_id[0] & 0x7c) >> 2) + '@';
	edid_vendor[1] = (((edid->mfg_id[0] & 0x3) << 3) |
				((edid->mfg_id[1] & 0xe0) >> 5)) + '@';
	edid_vendor[2] = (edid->mfg_id[1] & 0x1f) + '@';

	prod_id |= (edid->prod_code[0] << 8) | (edid->prod_code[1]);
	dp->rx_edid_data.edid_product = prod_id;

	dp->rx_edid_data.edid_serial = edid->serial;

	drm_edid_get_monitor_name(edid, dp->sink_info.monitor_name,
		sizeof(dp->sink_info.monitor_name));

#ifdef FEATURE_DEX_SUPPORT
	dp_get_dex_adapter_type(dp);
#endif
	dp_info(dp, "manufacturer: %s, product: %x, serial: %x\n",
			dp->rx_edid_data.edid_manufacturer,
			dp->rx_edid_data.edid_product,
			dp->rx_edid_data.edid_serial);
}

/*HDMI_EOTF_TRADITIONAL_GAMMA_HDR, HDMI_EOTF_SMPTE_ST2084, HDMI_EOTF_BT_2100_HLG*/
#define HDR_SUPPORT_TYPE (BIT(HDMI_EOTF_SMPTE_ST2084))
static void dp_check_hdr_support(struct dp_device *dp)
{
#ifdef FEATURE_HDR_SUPPORT
	u8 eotf = dp->connector.base.hdr_sink_metadata.hdmi_type1.eotf;
	struct hdr_static_metadata *hdmi_type1 = &dp->connector.base.hdr_sink_metadata.hdmi_type1;

	if ((eotf & HDR_SUPPORT_TYPE) != 0) {
		dp->rx_edid_data.hdr_support = true;
		dp->rx_edid_data.min_lumi_data = hdmi_type1->min_cll;
		dp->rx_edid_data.max_lumi_data = hdmi_type1->max_cll;
		dp->rx_edid_data.max_average_lumi_data = hdmi_type1->max_fall;
		dp_info(dp, "SINK supports HDR(max: %hu, max_fall: %hu, min: %hu)\n",
			hdmi_type1->max_cll, hdmi_type1->max_fall, hdmi_type1->min_cll);
	}
#endif
}

int edid_update_drm(struct dp_device *dp)
{
	struct edid *edid = (struct edid *)dp->rx_edid_data.edid_buf;
	struct cea_sad *sads;
	int ret;

#ifdef CONFIG_SEC_DISPLAYPORT_SELFTEST
	if (self_test_on_process()) {
		ret = self_test_get_edid(dp->rx_edid_data.edid_buf);
		dp_info(dp, "self test edid %d\n", ret);
	} else
#endif
#ifdef CONFIG_SEC_DISPLAYPORT_DBG
	if (dp->edid_test_enable) {
		ret = dp->rx_edid_data.edid_buf[0x7e] + 1;
		dp_info(dp, "test edid %d\n", ret);
	} else
#endif
	{
		memset(&dp->rx_edid_data, 0, sizeof(struct edid_data));
		ret = edid_read(dp);
	}
	if (ret < 1 || ret > 4) {
		dp_err(dp, "invalid EDID\n");
		return -EINVAL;
	}

	dp_edid_dump(dp, edid, ret * EDID_BLOCK_SIZE);

#ifdef FEATURE_DSC_SUPPORT
	dp_reg_dpcd_read_burst(&dp->cal_res, DP_DSC_SUPPORT, DP_DSC_RECEIVER_CAP_SIZE,
			&dp->dsc_dpcd[0]);
	dp->sink_dsc_support = drm_dp_sink_supports_dsc(dp->dsc_dpcd);
	dp_info(dp, "sink %s dsc\n", dp->sink_dsc_support ? "support" : "not support");
#endif

	mutex_lock(&dp->connector.base.dev->mode_config.mutex);
	dp_mode_clean_up(dp);
	ret = drm_add_edid_modes(&dp->connector.base, edid);
	mutex_unlock(&dp->connector.base.dev->mode_config.mutex);
	dp_info(dp, "mode num: %d\n", ret);
	if (ret) {
		int flag = MODE_FILTER_MAX_RESOLUTION |
				MODE_FILTER_PRINT | MODE_FILTER_TEST_SINK;

		/* get sink info */
		dp_get_sink_info(dp);
		dp_check_hdr_support(dp);

		/* check if sink is a test device */
		dp_check_test_device(dp);

#ifdef FEATURE_MANAGE_HMD_LIST
		/* check if sink is a HMD device */
		dp_check_hmd_dev(dp);
#endif
		dp_info(dp, "mon name: %s, bpc: %d, EOTF: %d\n",
				dp->sink_info.monitor_name,
				dp->connector.base.display_info.bpc,
				dp->connector.base.hdr_sink_metadata.hdmi_type1.eotf);

		/* need?: drm_mode_sort(&dp->connector.base.probed_modes); */
		dp_find_prefer_mode(dp, flag);
#ifdef FEATURE_HIGHER_RESOLUTION
		if (dp->higher_resolution == true)
			dp_mode_sort_for_higher(dp);
		else
#endif
			dp_mode_sort_for_mirror(dp);

		dp_find_best_mode(dp, flag);

		/* color depth */
		if (dp->connector.base.display_info.bpc == 6)
			dp->cal_res.bpc = BPC_6;

		/* audio info */
		ret = drm_edid_to_sad(edid, &sads);
		if (ret > 0) {
			dp_sad_to_audio_info(dp, sads, ret);
			kfree(sads);
		}
	}

	return ret;
}

#ifdef FEATURE_HF_EEODB_SUPPORT
/* from drm_edid.c */
#define CTA_DB_EXTENDED_TAG		7
#define CTA_EXT_DB_HF_EEODB		0x78

/* CTA-861-H section 7.4 CTA Data BLock Collection */
struct cea_db {
	u8 tag_length;
	u8 data[];
} __packed;

static int cea_db_tag(const struct cea_db *db)
{
	return db->tag_length >> 5;
}

static int cea_db_payload_len(const void *_db)
{
	/* FIXME: Transition to passing struct cea_db * everywhere. */
	const struct cea_db *db = _db;

	return db->tag_length & 0x1f;
}

static bool cea_db_is_extended_tag(const struct cea_db *db, int tag)
{
	return cea_db_tag(db) == CTA_DB_EXTENDED_TAG &&
		cea_db_payload_len(db) >= 1 &&
		db->data[0] == tag;
}

static bool cea_db_is_hdmi_forum_eeodb(const void *db)
{
	return cea_db_is_extended_tag(db, CTA_EXT_DB_HF_EEODB) &&
		cea_db_payload_len(db) >= 2;
}

static int cea_db_collection_size(const u8 *cta)
{
	u8 d = cta[2];

	if (d < 4 || d > 127)
		return 0;

	return d - 4;
}

static int cea_revision(const u8 *cea)
{
	/*
	 * FIXME is this correct for the DispID variant?
	 * The DispID spec doesn't really specify whether
	 * this is the revision of the CEA extension or
	 * the DispID CEA data block. And the only value
	 * given as an example is 0.
	 */
	return cea[1];
}

static int edid_block_tag(const void *_block)
{
	const u8 *block = _block;

	return block[0];
}

static const void *edid_block_data(const struct edid *edid, int index)
{
	BUILD_BUG_ON(sizeof(*edid) != EDID_LENGTH);

	return edid + index;
}

static const void *edid_extension_block_data(const struct edid *edid, int index)
{
	return edid_block_data(edid, index + 1);
}

static int edid_extension_block_count(const struct edid *edid)
{
	return edid->extensions;
}

static int edid_hfeeodb_extension_block_count(const struct edid *edid)
{
	const u8 *cta;

	/* No extensions according to base block, no HF-EEODB. */
	if (!edid_extension_block_count(edid))
		return 0;

	/* HF-EEODB is always in the first EDID extension block only */
	cta = edid_extension_block_data(edid, 0);
	if (edid_block_tag(cta) != CEA_EXT || cea_revision(cta) < 3)
		return 0;

	/* Need to have the data block collection, and at least 3 bytes. */
	if (cea_db_collection_size(cta) < 3)
		return 0;

	/*
	 * Sinks that include the HF-EEODB in their E-EDID shall include one and
	 * only one instance of the HF-EEODB in the E-EDID, occupying bytes 4
	 * through 6 of Block 1 of the E-EDID.
	 */
	if (!cea_db_is_hdmi_forum_eeodb(&cta[4]))
		return 0;

	return cta[4 + 2];
}

static int edid_hfeeodb_block_count(const struct edid *edid)
{
	int eeodb = edid_hfeeodb_extension_block_count(edid);

	return eeodb ? eeodb + 1 : 0;
}

/* drm use legacy extension to parse */
static void edid_hfeeodb_change_extension_count(u8 *edid_buf, int eeodb)
{
	u8 *extension = &edid_buf[0x7e];
	u8 *checksum = &edid_buf[0x7f];
	u16 count_diff = 0;

	count_diff = (u8)eeodb - *extension;
	*checksum = (*checksum + (u8)(0x100 - count_diff)) & 0xFF;
	*extension = eeodb;
}
#endif

int edid_read(struct dp_device *dp)
{
	int block = 0;
	int block_cnt = 0;
	int ret = 0;
	int retry_num = 5;
	u8 *edid_buf = dp->rx_edid_data.edid_buf;
#ifdef FEATURE_HF_EEODB_SUPPORT
	int eeodb_cnt = 0;
#endif

EDID_READ_RETRY:
	block = 0;
	block_cnt = 0;

	edid_check_set_i2c_capabilities(dp);
	ret = edid_read_block(dp, 0, edid_buf, EDID_BLOCK_SIZE);
	if (ret)
		return ret;

	ret = edid_checksum(dp, edid_buf, block);
	if (ret) {
		if (retry_num > 0) {
			msleep(100);
			retry_num--;
			goto EDID_READ_RETRY;
		} else {
			dp_err(dp, "edid read error\n");
			dp_edid_dump(dp, edid_buf, EDID_BLOCK_SIZE);
			return ret;
		}
	}

	block_cnt = edid_buf[EDID_EXTENSION_FLAG] + 1;
	dp_info(dp, "block_cnt = %d\n", block_cnt);
	if (block_cnt > 4) {
		dp_info(dp, "invalid ext block count %d\n", block_cnt);
		return 1;
	}

	while (++block < block_cnt) {
		u8 *edid_ext = edid_buf + (block * EDID_BLOCK_SIZE);

		ret = edid_read_block(dp, block, edid_ext, EDID_BLOCK_SIZE);

		/* check error, extension tag and checksum */
		if (ret || edid_check_extension_tag(dp, *edid_ext) ||
				edid_checksum(dp, edid_ext, block)) {
			dp_info(dp, "block_cnt:%d/%d, ret: %d\n", block, block_cnt, ret);
			return block;
		}
#ifdef FEATURE_HF_EEODB_SUPPORT
		if (block == 1) {
			eeodb_cnt = edid_hfeeodb_block_count((const struct edid *)edid_buf);
			if (eeodb_cnt > block_cnt && eeodb_cnt <= MAX_EDID_BLOCK) {
				dp_info(dp, "eeodb block_cnt = %d\n", eeodb_cnt);
				block_cnt = eeodb_cnt;
				/* edid parser still does not refer to the eeodb count so change ext count */
				edid_hfeeodb_change_extension_count(edid_buf, eeodb_cnt - 1);
			}
		}
#endif
	}

	return block_cnt;
}
#else
int edid_read(struct dp_device *dp)
{
	int block = 0;
	int block_cnt = 0;
	int ret = 0;
	int retry_num = 5;
	u8 *edid_buf = dp->rx_edid_data.edid_buf;

EDID_READ_RETRY:
	block = 0;
	block_cnt = 0;

	edid_check_set_i2c_capabilities(dp);
	ret = edid_read_block(dp, 0, edid_buf, EDID_BLOCK_SIZE);
	if (ret)
		return ret;

	ret = edid_checksum(dp, edid_buf, block);
	if (ret) {
		if (retry_num <= 0) {
			dp_err(dp, "edid read error\n");
			return ret;
		} else {
			msleep(100);
			retry_num--;
			goto EDID_READ_RETRY;
		}
	}

	block_cnt = edid_buf[EDID_EXTENSION_FLAG] + 1;
	dp_info(dp, "block_cnt = %d\n", block_cnt);

	while (++block < block_cnt) {
		ret = edid_read_block(dp, block,
					edid_buf + (block * EDID_BLOCK_SIZE),
					EDID_BLOCK_SIZE);

		/* check error, extension tag and checksum */
		if (ret || *(edid_buf + (block * EDID_BLOCK_SIZE)) != 0x02 ||
				edid_checksum(dp, edid_buf + (block * EDID_BLOCK_SIZE), block)) {
			dp_info(dp, "block_cnt:%d/%d, ret: %d\n", block, block_cnt, ret);
			return block;
		}
	}

	return block_cnt;
}
#endif

static int get_ud_timing(struct fb_vendor *vsdb, int vic_idx)
{
	unsigned char val = 0;
	int idx = -EINVAL;

	val = vsdb->vic_data[vic_idx];
	switch (val) {
	case 0x01:
		idx = 0;
		break;
	case 0x02:
		idx = 1;
		break;
	case 0x03:
		idx = 2;
		break;
	case 0x04:
		idx = 3;
		break;
	}

	return idx;
}

bool edid_find_max_resolution(const struct v4l2_dv_timings *t1,
			const struct v4l2_dv_timings *t2)
{
	if ((t1->bt.width * t1->bt.height < t2->bt.width * t2->bt.height) ||
		((t1->bt.width * t1->bt.height == t2->bt.width * t2->bt.height) &&
		(t1->bt.pixelclock < t2->bt.pixelclock)))
		return true;

	return false;
}

static void edid_find_preset(struct dp_device *dp,
		const struct fb_videomode *mode)
{
	int i;

	dp_debug(dp, "EDID: %ux%u@%u - %u(ps?), lm:%u, rm:%u, um:%u, lm:%u",
		mode->xres, mode->yres, mode->refresh, mode->pixclock,
		mode->left_margin, mode->right_margin, mode->upper_margin, mode->lower_margin);

	for (i = 0; i < supported_videos_pre_cnt; i++) {
		if ((mode->refresh == supported_videos[i].fps ||
			mode->refresh == supported_videos[i].fps - 1) &&
			mode->xres == supported_videos[i].dv_timings.bt.width &&
			mode->yres == supported_videos[i].dv_timings.bt.height &&
			mode->left_margin == supported_videos[i].dv_timings.bt.hbackporch &&
			mode->right_margin == supported_videos[i].dv_timings.bt.hfrontporch &&
			mode->upper_margin == supported_videos[i].dv_timings.bt.vbackporch &&
			mode->lower_margin == supported_videos[i].dv_timings.bt.vfrontporch) {
			if (supported_videos[i].edid_support_match == false) {
				dp_info(dp, "EDID: found: %s\n", supported_videos[i].name);

				supported_videos[i].edid_support_match = true;
				preferred_preset = supported_videos[i].dv_timings;

				if (dp->best_video < i)
					dp->best_video = i;
			}
		}
	}
}

void edid_use_default_preset(void)
{
	int i;

	if (forced_resolution >= 0)
		preferred_preset = supported_videos[forced_resolution].dv_timings;
	else
		preferred_preset = supported_videos[EDID_DEFAULT_TIMINGS_IDX].dv_timings;

	for (i = 0; i < supported_videos_pre_cnt; i++) {
		supported_videos[i].edid_support_match =
			v4l2_match_dv_timings(&supported_videos[i].dv_timings,
					&preferred_preset, 0, 0);
	}

	if (!test_audio_info.channel_count)
		audio_channels = 2;
}

void edid_set_preferred_preset(int mode)
{
	int i;

	preferred_preset = supported_videos[mode].dv_timings;
	for (i = 0; i < supported_videos_pre_cnt; i++) {
		supported_videos[i].edid_support_match =
			v4l2_match_dv_timings(&supported_videos[i].dv_timings,
					&preferred_preset, 0, 0);
	}
}

int edid_find_resolution(u16 xres, u16 yres, u16 refresh)
{
	int i;
	int ret=0;

	for (i = 0; i < supported_videos_pre_cnt; i++) {
		if (refresh == supported_videos[i].fps &&
			xres == supported_videos[i].dv_timings.bt.width &&
			yres == supported_videos[i].dv_timings.bt.height) {
			return i;
		}
	}
	return ret;
}

void edid_parse_hdmi14_vsdb(struct dp_device *dp,
		unsigned char *edid_ext_blk, struct fb_vendor *vsdb,
		int block_cnt)
{
	int i, j;
	int hdmi_vic_len;
	int vsdb_offset_calc = VSDB_VIC_FIELD_OFFSET;

	for (i = 0; i < (block_cnt - 1) * EDID_BLOCK_SIZE; i++) {
		if ((edid_ext_blk[i] & DATA_BLOCK_TAG_CODE_MASK)
			== (VSDB_TAG_CODE << DATA_BLOCK_TAG_CODE_BIT_POSITION)
				&& edid_ext_blk[i + IEEE_OUI_0_BYTE_NUM] == HDMI14_IEEE_OUI_0
				&& edid_ext_blk[i + IEEE_OUI_1_BYTE_NUM] == HDMI14_IEEE_OUI_1
				&& edid_ext_blk[i + IEEE_OUI_2_BYTE_NUM] == HDMI14_IEEE_OUI_2) {
			dp_debug(dp, "EDID: find VSDB for HDMI 1.4\n");

			if (edid_ext_blk[i + 8] & VSDB_HDMI_VIDEO_PRESETNT_MASK) {
				dp_debug(dp, "EDID: Find HDMI_Video_present in VSDB\n");

				if (!(edid_ext_blk[i + 8] & VSDB_LATENCY_FILEDS_PRESETNT_MASK)) {
					vsdb_offset_calc = vsdb_offset_calc - 2;
					dp_debug(dp, "EDID: Not support LATENCY_FILEDS_PRESETNT in VSDB\n");
				}

				if (!(edid_ext_blk[i + 8] & VSDB_I_LATENCY_FILEDS_PRESETNT_MASK)) {
					vsdb_offset_calc = vsdb_offset_calc - 2;
					dp_debug(dp, "EDID: Not support I_LATENCY_FILEDS_PRESETNT in VSDB\n");
				}

				hdmi_vic_len = (edid_ext_blk[i + vsdb_offset_calc]
						& VSDB_VIC_LENGTH_MASK) >> VSDB_VIC_LENGTH_BIT_POSITION;

				if (hdmi_vic_len > 0) {
					vsdb->vic_len = hdmi_vic_len;

					for (j = 0; j < hdmi_vic_len; j++)
						vsdb->vic_data[j] = edid_ext_blk[i + vsdb_offset_calc + j + 1];

					break;
				} else {
					vsdb->vic_len = 0;
					dp_debug(dp, "EDID: No hdmi vic data in VSDB\n");
					break;
				}
			} else
				dp_debug(dp, "EDID: Not support HDMI_Video_present in VSDB\n");
		}
	}

	if (i >= (block_cnt - 1) * EDID_BLOCK_SIZE) {
		vsdb->vic_len = 0;
		dp_debug(dp, "EDID: can't find VSDB for HDMI 1.4 block\n");
	}
}

int static dv_timing_to_fb_video(videoformat video, struct fb_videomode *fb)
{
	struct dp_supported_preset pre = supported_videos[video];

	fb->name = pre.name;
	fb->refresh = pre.fps;
	fb->xres = pre.dv_timings.bt.width;
	fb->yres = pre.dv_timings.bt.height;
	fb->pixclock = pre.dv_timings.bt.pixelclock;
	fb->left_margin = pre.dv_timings.bt.hbackporch;
	fb->right_margin = pre.dv_timings.bt.hfrontporch;
	fb->upper_margin = pre.dv_timings.bt.vbackporch;
	fb->lower_margin = pre.dv_timings.bt.vfrontporch;
	fb->hsync_len = pre.dv_timings.bt.hsync;
	fb->vsync_len = pre.dv_timings.bt.vsync;
	fb->sync = pre.v_sync_pol | pre.h_sync_pol;
	fb->vmode = FB_VMODE_NONINTERLACED;

	return 0;
}

void edid_find_hdmi14_vsdb_update(struct dp_device *dp,
		struct fb_vendor *vsdb)
{
	int udmode_idx, vic_idx;

	if (!vsdb)
		return;

	/* find UHD preset in HDMI 1.4 vsdb block*/
	if (vsdb->vic_len) {
		for (vic_idx = 0; vic_idx < vsdb->vic_len; vic_idx++) {
			udmode_idx = get_ud_timing(vsdb, vic_idx);

			dp_debug(dp, "EDID: udmode_idx = %d\n", udmode_idx);

			if (udmode_idx >= 0) {
				struct fb_videomode fb;

				dv_timing_to_fb_video(ud_mode_h14b_vsdb[udmode_idx], &fb);
				edid_find_preset(dp, &fb);
			}
		}
	}
}

void edid_parse_hdmi20_vsdb(struct dp_device *dp,
		unsigned char *edid_ext_blk, struct fb_vendor *vsdb,
		int block_cnt)
{
	int i;

	dp->rx_edid_data.max_support_clk = 0;
	dp->rx_edid_data.support_10bpc = 0;

	for (i = 0; i < (block_cnt - 1) * EDID_BLOCK_SIZE; i++) {
		if ((edid_ext_blk[i] & DATA_BLOCK_TAG_CODE_MASK)
				== (VSDB_TAG_CODE << DATA_BLOCK_TAG_CODE_BIT_POSITION)
				&& edid_ext_blk[i + IEEE_OUI_0_BYTE_NUM] == HDMI20_IEEE_OUI_0
				&& edid_ext_blk[i + IEEE_OUI_1_BYTE_NUM] == HDMI20_IEEE_OUI_1
				&& edid_ext_blk[i + IEEE_OUI_2_BYTE_NUM] == HDMI20_IEEE_OUI_2) {
			dp_debug(dp, "EDID: find VSDB for HDMI 2.0\n");

			/* Max_TMDS_Character_Rate * 5Mhz */
			dp->rx_edid_data.max_support_clk =
					edid_ext_blk[i + MAX_TMDS_RATE_BYTE_NUM] * 5;
			dp_info(dp, "EDID: Max_TMDS_Character_Rate = %d Mhz\n",
					dp->rx_edid_data.max_support_clk);

			if (edid_ext_blk[i + DC_SUPPORT_BYTE_NUM] & DC_30BIT)
				dp->rx_edid_data.support_10bpc = 1;
			else
				dp->rx_edid_data.support_10bpc = 0;

			dp_info(dp, "EDID: 10 bpc support = %d\n",
				dp->rx_edid_data.support_10bpc);

			break;
		}
	}

	if (i >= (block_cnt - 1) * EDID_BLOCK_SIZE) {
		vsdb->vic_len = 0;
		dp_debug(dp, "EDID: can't find VSDB for HDMI 2.0 block\n");
	}
}

void edid_parse_hdr_metadata(struct dp_device *dp,
		unsigned char *edid_ext_blk,  int block_cnt)
{
	int i;

	dp->rx_edid_data.hdr_support = false;
	dp->rx_edid_data.eotf = 0;
	dp->rx_edid_data.max_lumi_data = 0;
	dp->rx_edid_data.max_average_lumi_data = 0;
	dp->rx_edid_data.min_lumi_data = 0;

	for (i = 0; i < (block_cnt - 1) * EDID_BLOCK_SIZE; i++) {
		if ((edid_ext_blk[i] & DATA_BLOCK_TAG_CODE_MASK)
				== (USE_EXTENDED_TAG_CODE << DATA_BLOCK_TAG_CODE_BIT_POSITION)
				&& edid_ext_blk[i + EXTENDED_TAG_CODE_BYTE_NUM]
				== EXTENDED_HDR_TAG_CODE) {
			dp_debug(dp, "EDID: find HDR Metadata Data Block\n");

			dp->rx_edid_data.eotf =
				edid_ext_blk[i + SUPPORTED_EOTF_BYTE_NUM];
			dp_debug(dp, "EDID: SUPPORTED_EOTF = 0x%x\n",
				dp->rx_edid_data.eotf);

			if (dp->rx_edid_data.eotf & SMPTE_ST_2084) {
				dp->rx_edid_data.hdr_support = true;
				dp_info(dp, "EDID: SMPTE_ST_2084 support, but not now\n");
			}

			dp->rx_edid_data.max_lumi_data =
					edid_ext_blk[i + MAX_LUMI_BYTE_NUM];
			dp_debug(dp, "EDID: MAX_LUMI = 0x%x\n",
					dp->rx_edid_data.max_lumi_data);

			dp->rx_edid_data.max_average_lumi_data =
					edid_ext_blk[i + MAX_AVERAGE_LUMI_BYTE_NUM];
			dp_debug(dp, "EDID: MAX_AVERAGE_LUMI = 0x%x\n",
					dp->rx_edid_data.max_average_lumi_data);

			dp->rx_edid_data.min_lumi_data =
					edid_ext_blk[i + MIN_LUMI_BYTE_NUM];
			dp_debug(dp, "EDID: MIN_LUMI = 0x%x\n",
					dp->rx_edid_data.min_lumi_data);

			dp_info(dp, "HDR: EOTF(0x%X) ST2084(%u) GAMMA(%s|%s) LUMI(max:%u,avg:%u,min:%u)\n",
					dp->rx_edid_data.eotf,
					dp->rx_edid_data.hdr_support,
					dp->rx_edid_data.eotf & 0x1 ? "SDR" : "",
					dp->rx_edid_data.eotf & 0x2 ? "HDR" : "",
					dp->rx_edid_data.max_lumi_data,
					dp->rx_edid_data.max_average_lumi_data,
					dp->rx_edid_data.min_lumi_data);
			break;
		}
	}

	if (i >= (block_cnt - 1) * EDID_BLOCK_SIZE)
		dp_debug(dp, "EDID: can't find HDR Metadata Data Block\n");
}

void edid_find_preset_in_video_data_block(struct dp_device *dp, u8 vic)
{
	int i;

	for (i = 0; i < supported_videos_pre_cnt; i++) {
		if ((vic != 0) && (supported_videos[i].vic == vic) &&
				(supported_videos[i].edid_support_match == false)) {
			supported_videos[i].edid_support_match = true;

			if (dp->best_video < i)
				dp->best_video = i;

			dp_info(dp, "EDID: found(VDB): %s\n", supported_videos[i].name);
		}
	}
}

int edid_parse_audio_video_db(struct dp_device *dp,
		unsigned char *edid, struct fb_audio *sad)
{
	int i;
	u8 pos = 4;

	if (!edid)
		return -EINVAL;

	if (edid[0] != 0x2 || edid[1] != 0x3 ||
	    edid[2] < 4 || edid[2] > 128 - DETAILED_TIMING_DESCRIPTION_SIZE)
		return -EINVAL;

	if (!sad)
		return -EINVAL;

	while (pos < edid[2]) {
		u8 len = edid[pos] & DATA_BLOCK_LENGTH_MASK;
		u8 type = (edid[pos] >> DATA_BLOCK_TAG_CODE_BIT_POSITION) & 7;
		dp_debug(dp, "Data block %u of %u bytes\n", type, len);

		if (len == 0)
			break;

		pos++;
		if (type == AUDIO_DATA_BLOCK) {
			for (i = pos; i < pos + len; i += 3) {
				if (((edid[i] >> 3) & 0xf) != 1)
					continue; /* skip non-lpcm */

				dp_debug(dp, "LPCM ch=%d\n", (edid[i] & 7) + 1);

				sad->channel_count |= 1 << (edid[i] & 0x7);
				sad->sample_rates |= (edid[i + 1] & 0x7F);
				sad->bit_rates |= (edid[i + 2] & 0x7);

				dp_debug(dp, "ch:0x%X, sample:0x%X, bitrate:0x%X\n",
					sad->channel_count, sad->sample_rates, sad->bit_rates);
			}
		} else if (type == VIDEO_DATA_BLOCK) {
			for (i = pos; i < pos + len; i++) {
				u8 vic = edid[i] & SVD_VIC_MASK;
				edid_find_preset_in_video_data_block(dp, vic);
				dp_debug(dp, "EDID: Video data block vic:%d %s\n",
					vic, supported_videos[i].name);
			}
		} else if (type == SPEAKER_DATA_BLOCK) {
			sad->speaker |= edid[pos] & 0xff;
			dp_debug(dp, "EDID: speaker 0x%X\n", sad->speaker);
		}

		pos += len;
	}

	return 0;
}

void edid_check_detail_timing_desc1(struct dp_device *dp,
		struct fb_monspecs *specs, int modedb_len, u8 *edid)
{
	int i;
	struct fb_videomode *mode = NULL;
	u64 pixelclock = 0;
	u8 *block = edid + DETAILED_TIMING_DESCRIPTIONS_START;

	for (i = 0; i < modedb_len; i++) {
		mode = &(specs->modedb[i]);
		if (mode->flag == (FB_MODE_IS_FIRST | FB_MODE_IS_DETAILED))
			break;
	}

	if (i >= modedb_len)
		return;

	mode = &(specs->modedb[i]);
	pixelclock = (u64)((u32)block[1] << 8 | (u32)block[0]) * 10000;

	dp_info(dp, "detail_timing_desc1: %d*%d@%d (%lld, %dps)\n",
			mode->xres, mode->yres, mode->refresh, pixelclock, mode->pixclock);

	for (i = 0; i < supported_videos_pre_cnt; i++) {
		if (mode->vmode == FB_VMODE_NONINTERLACED &&
			(mode->refresh == supported_videos[i].fps ||
			 mode->refresh == supported_videos[i].fps - 1) &&
			mode->xres == supported_videos[i].dv_timings.bt.width &&
			mode->yres == supported_videos[i].dv_timings.bt.height) {
			if (supported_videos[i].edid_support_match == true) {
				dp_info(dp, "already found timing:%d\n", i);
				return;
			}

			break; /* matched but not found */
		}
	}

	/* check if index is valid and index is bigger than best video */
	if (i >= supported_videos_pre_cnt || i <= dp->best_video) {
		dp_info(dp, "invalid timing i:%d, best:%d\n",
				i, dp->best_video);
		return;
	}

	dp_info(dp, "find same supported timing: %d*%d@%d (%lld)\n",
			supported_videos[i].dv_timings.bt.width,
			supported_videos[i].dv_timings.bt.height,
			supported_videos[i].fps,
			supported_videos[i].dv_timings.bt.pixelclock);

	if (supported_videos[V640X480P60].dv_timings.bt.pixelclock >= pixelclock ||
			supported_videos[V4096X2160P60].dv_timings.bt.pixelclock <= pixelclock) {
		dp_info(dp, "EDID: invalid pixel clock\n");
		return;
	}

	dp->best_video = VDUMMYTIMING;
	supported_videos[VDUMMYTIMING].dv_timings.bt.width = mode->xres;
	supported_videos[VDUMMYTIMING].dv_timings.bt.height = mode->yres;
	supported_videos[VDUMMYTIMING].dv_timings.bt.interlaced = false;
	supported_videos[VDUMMYTIMING].dv_timings.bt.pixelclock = pixelclock;
	supported_videos[VDUMMYTIMING].dv_timings.bt.hfrontporch = mode->right_margin;
	supported_videos[VDUMMYTIMING].dv_timings.bt.hsync = mode->hsync_len;
	supported_videos[VDUMMYTIMING].dv_timings.bt.hbackporch = mode->left_margin;
	supported_videos[VDUMMYTIMING].dv_timings.bt.vfrontporch = mode->lower_margin;
	supported_videos[VDUMMYTIMING].dv_timings.bt.vsync = mode->vsync_len;
	supported_videos[VDUMMYTIMING].dv_timings.bt.vbackporch = mode->upper_margin;
	supported_videos[VDUMMYTIMING].fps = mode->refresh;
	supported_videos[VDUMMYTIMING].v_sync_pol = (mode->sync & FB_SYNC_VERT_HIGH_ACT);
	supported_videos[VDUMMYTIMING].h_sync_pol = (mode->sync & FB_SYNC_HOR_HIGH_ACT);
	supported_videos[VDUMMYTIMING].edid_support_match = true;
	preferred_preset = supported_videos[VDUMMYTIMING].dv_timings;

	dp_debug(dp, "EDID: modedb : %d*%d@%d (%lld)\n", mode->xres, mode->yres, mode->refresh,
			supported_videos[VDUMMYTIMING].dv_timings.bt.pixelclock);
	dp_debug(dp, "EDID: modedb : %d %d %d  %d %d %d  %d %d %d\n",
			mode->left_margin, mode->hsync_len, mode->right_margin,
			mode->upper_margin, mode->vsync_len, mode->lower_margin,
			mode->sync, mode->vmode, mode->flag);
	dp_info(dp, "EDID: %s edid_support_match = %d\n", supported_videos[VDUMMYTIMING].name,
			supported_videos[VDUMMYTIMING].edid_support_match);
}

#ifndef FEATURE_USE_DRM_EDID_PARSER
int edid_update(struct dp_device *dp)
{
	struct fb_monspecs specs;
	struct fb_vendor vsdb;
	struct fb_audio sad;
	u8 *edid = dp->rx_edid_data.edid_buf;
	int block_cnt = 0;
	int i;
	int basic_audio = 0;
	int modedb_len = 0;

	audio_channels = 0;
	audio_sample_rates = 0;
	audio_bit_rates = 0;
	audio_speaker_alloc = 0;

	edid_misc = 0;
	memset(&vsdb, 0, sizeof(vsdb));
	memset(&specs, 0, sizeof(specs));
	memset(&sad, 0, sizeof(sad));
	memset(&dp->rx_edid_data,
			0, sizeof(struct edid_data));

	preferred_preset = supported_videos[EDID_DEFAULT_TIMINGS_IDX].dv_timings;
	supported_videos[0].edid_support_match = true; /*default support VGA*/
	supported_videos[VDUMMYTIMING].dv_timings.bt.width = 0;
	supported_videos[VDUMMYTIMING].dv_timings.bt.height = 0;
	for (i = 1; i < supported_videos_pre_cnt; i++)
		supported_videos[i].edid_support_match = false;
	block_cnt = edid_read(dp);
	if (block_cnt < 0)
		goto out;

	dp->rx_edid_data.edid_data_size =
			EDID_BLOCK_SIZE * block_cnt;

	fb_edid_to_monspecs(edid, &specs);
	modedb_len = specs.modedb_len;

	dp_info(dp, "mon name: %s, gamma: %u.%u\n", specs.monitor,
			specs.gamma / 100, specs.gamma % 100);
	for (i = 1; i < block_cnt; i++)
		fb_edid_add_monspecs(edid + i * EDID_BLOCK_SIZE, &specs);

	/* find 2D preset */
	for (i = 0; i < specs.modedb_len; i++)
		edid_find_preset(dp, &specs.modedb[i]);

	/* color depth */
	if (edid[EDID_COLOR_DEPTH] & 0x80) {
		if (((edid[EDID_COLOR_DEPTH] & 0x70) >> 4) == 1)
			dp->cal_res.bpc = BPC_6;
	}

	/* vendro block */
	memcpy(dp->rx_edid_data.edid_manufacturer,
			specs.manufacturer, sizeof(specs.manufacturer));
	dp->rx_edid_data.edid_product = specs.model;
	dp->rx_edid_data.edid_serial = specs.serial;

	/* number of 128bytes blocks to follow */
	if (block_cnt <= 1)
		goto out;

	if (edid[EDID_NATIVE_FORMAT] & EDID_BASIC_AUDIO) {
		basic_audio = 1;
		edid_misc = FB_MISC_HDMI;
	}

	edid_parse_hdmi14_vsdb(dp, edid + EDID_BLOCK_SIZE, &vsdb, block_cnt);
	edid_find_hdmi14_vsdb_update(dp, &vsdb);
	edid_parse_hdmi20_vsdb(dp, edid + EDID_BLOCK_SIZE, &vsdb, block_cnt);
	edid_parse_hdr_metadata(dp,	edid + EDID_BLOCK_SIZE, block_cnt);

	for (i = 1; i < block_cnt; i++)
		edid_parse_audio_video_db(dp, edid + (EDID_BLOCK_SIZE * i), &sad);

	if (!edid_misc)
		edid_misc = specs.misc;

	if (edid_misc & FB_MISC_HDMI) {
		audio_speaker_alloc = sad.speaker;
		if (sad.channel_count) {
			audio_channels = sad.channel_count;
			audio_sample_rates = sad.sample_rates;
			audio_bit_rates = sad.bit_rates;
		} else if (basic_audio) {
			audio_channels = 2;
			audio_sample_rates = FB_AUDIO_48KHZ; /*default audio info*/
			audio_bit_rates = FB_AUDIO_16BIT;
		}
	}

	if (test_audio_info.channel_count != 0) {
		audio_channels = test_audio_info.channel_count;
		audio_sample_rates = test_audio_info.sample_rates;
		audio_bit_rates = test_audio_info.bit_rates;
		dp_info(dp, "test audio ch:0x%X, sample:0x%X, bit:0x%X\n",
			audio_channels, audio_sample_rates, audio_bit_rates);
	}

	dp_info(dp, "misc:0x%X, Audio ch:0x%X, sample:0x%X, bit:0x%X\n",
			edid_misc, audio_channels, audio_sample_rates, audio_bit_rates);

out:
	edid_check_detail_timing_desc1(dp, &specs, modedb_len, edid);

	/* No supported preset found, use default */
	if (forced_resolution >= 0) {
		dp_info(dp, "edid_use_default_preset\n");
		edid_use_default_preset();
	}

	if (block_cnt == -EPROTO)
		edid_misc = FB_MISC_HDMI;

	return block_cnt;
}
#endif

struct v4l2_dv_timings edid_preferred_preset(void)
{
	return preferred_preset;
}

bool edid_supports_hdmi(struct dp_device *dp)
{
	return edid_misc & FB_MISC_HDMI;
}

bool edid_support_pro_audio(void)
{
	if (audio_channels >= FB_AUDIO_8CH && audio_sample_rates >= FB_AUDIO_192KHZ)
		return true;

	return false;
}

#ifdef FEATURE_USE_DRM_EDID_PARSER
static bool dp_mode_check_proaud_support(int vic)
{
	int arr_size = ARRAY_SIZE(proaudio_support_vics);
	int i;

	for (i = 0; i < arr_size; i++) {
		if (vic == proaudio_support_vics[i])
			return true;
	}

	return false;
}
#endif

u32 edid_audio_informs(struct dp_device *dp)
{
	u32 value = 0, ch_info = 0;
	u32 link_rate = dp_reg_phy_get_link_bw(&dp->cal_res);

	if (audio_channels > 0)
		ch_info = audio_channels;


#ifdef FEATURE_USE_DRM_EDID_PARSER
	/* if cur_mode does not support pro audio, then reduce sample frequency. */
	if (!dp_mode_check_proaud_support(dp_get_vic(dp))) {
		dp_info(dp, "reduce SF(pro_aud:%d, link_rate:0x%X, ch:0x%X, sf:0x%X)\n",
				supported_videos[dp->cur_video].pro_audio_support, link_rate,
				ch_info, audio_sample_rates);
		audio_sample_rates &= 0x7; /* reduce to under 48KHz */
	}
#else
	/* if below conditions does not meet pro audio, then reduce sample frequency.
	 * 1. current video is not support pro audio
	 * 2. link rate is below HBR2
	 * 3. dex setting is not set
	 * 4. channel is over 2 and under 8.
	 * 5. channel is 8. And smaple freq is under 192KHz
	 */
	if ((!supported_videos[dp->cur_video].pro_audio_support ||
				link_rate < LINK_RATE_5_4Gbps)) {
		if ((ch_info > FB_AUDIO_1N2CH && ch_info < FB_AUDIO_8CH) ||
				(ch_info >= FB_AUDIO_8CH && audio_sample_rates < FB_AUDIO_192KHZ)) {
			dp_info(dp, "reduce SF(pro_aud:%d, link_rate:0x%X, ch:0x%X, sf:0x%X)\n",
					supported_videos[dp->cur_video].pro_audio_support, link_rate,
					ch_info, audio_sample_rates);
			audio_sample_rates &= 0x7; /* reduce to under 48KHz */
		}
	}
#endif
	value = ((audio_sample_rates << 19) | (audio_bit_rates << 16) |
			(audio_speaker_alloc << 8) | ch_info);
	value |= (1 << 26); /* 1: DP, 0: HDMI */

	dp_info(dp, "audio info = 0x%X\n", value);

	return value;
}

struct fb_audio *edid_get_test_audio_info(void)
{
	return &test_audio_info;
}

#ifdef FEATURE_USE_DRM_EDID_PARSER
u8 edid_read_checksum(struct dp_device *dp)
{
	int ret, i;
	u8 buf[EDID_BLOCK_SIZE * 4] = {0x0, };
	u8 sum = 0;
	int block = 0;
	u8 checksum = 0;

	ret = dp_reg_edid_read(&dp->cal_res, 0, EDID_BLOCK_SIZE, buf);
	if (ret)
		return ret;

	block = buf[0x7e];
	for (i = 1; i <= block; i++) {
		u8 *buf_offset = buf + (EDID_BLOCK_SIZE * i);

		ret = dp_reg_edid_read(&dp->cal_res, i, EDID_BLOCK_SIZE, buf_offset);
		if (ret)
			return ret;
	}

	for (i = 0; i < EDID_BLOCK_SIZE * block; i++)
		sum += buf[i];

	checksum = buf[EDID_BLOCK_SIZE * block + 0x7f];

	dp_info(dp, "edid checksum %02x, %02x\n", sum, checksum);

	return checksum;
}
#else
u8 edid_read_checksum(struct dp_device *dp)
{
	int ret, i;
	u8 buf[EDID_BLOCK_SIZE];
	u8 offset = EDID_OFFSET(0);
	int sum = 0;

	ret = dp_reg_edid_read(&dp->cal_res, offset, EDID_BLOCK_SIZE, buf);
	if (ret)
		return ret;

	for (i = 0; i < EDID_BLOCK_SIZE; i++)
		sum += buf[i];

	dp_info(dp, "edid_read_checksum %02x, %02x", sum%265, buf[EDID_BLOCK_SIZE-1]);

	return buf[EDID_BLOCK_SIZE-1];
}
#endif

