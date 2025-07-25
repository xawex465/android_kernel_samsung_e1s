// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2016 Samsung Electronics Co., Ltd.
 *		http://www.samsung.com
 *
 * BTS file for Samsung EXYNOS DPU driver
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <exynos_drm_decon.h>
#include <exynos_drm_dp.h>
#include <exynos_drm_bts.h>
#include <exynos_drm_crtc.h>
#include <exynos_drm_writeback.h>
#include <exynos_drm_format.h>
#include <exynos_drm_debug.h>

#include <soc/samsung/bts.h>
#if defined(CONFIG_CAL_IF)
#include <soc/samsung/cal-if.h>
#endif
#include <cal_common/dsim_cal.h>
#include <linux/sort.h>

#include <dpu_trace.h>

#define DISP_FACTOR            BTS_DISP_FACTOR
#define DISP_REFRESH_RATE	60U
#define MULTI_FACTOR		(1UL << 10)
#define ROT_READ_LINE		(32)

#define ACLK_100MHZ_PERIOD	10000UL
#define FRAME_TIME_NSEC		1000000000UL	/* 1sec */
#define BTS_INFO_PRINT_BLOCK_TIMEOUT (5000)

/* FHD x1.77 */
#define FHD_WIDTH 	1080U
#define FHD_MIN_RATIO	560U
#define FHD_MAX_RATIO	1667U

static int dpu_bts_log_level = 6;
module_param(dpu_bts_log_level, int, 0600);
MODULE_PARM_DESC(dpu_bts_log_level, "log level for dpu bts [default : 6]");

#define DPU_DEBUG_BTS(decon, fmt, ...)	\
	dpu_pr_debug("BTS", (decon)->id, dpu_bts_log_level, fmt, ##__VA_ARGS__)

#define DPU_WARN_BTS(decon, fmt, ...)	\
	dpu_pr_warn("BTS", (decon)->id, dpu_bts_log_level, fmt, ##__VA_ARGS__)

#define DPU_INFO_BTS(decon, fmt, ...)	\
	dpu_pr_info("BTS", (decon)->id, dpu_bts_log_level, fmt, ##__VA_ARGS__)

#define DPU_ERR_BTS(decon, fmt, ...)	\
	dpu_pr_err("BTS", (decon)->id, dpu_bts_log_level, fmt, ##__VA_ARGS__)

struct bts_overlay_private {
	u32 count[MAX_DPUF_CNT];
	u32 max_overlay[MAX_DPUF_CNT];
	u32 max_h[MAX_DPUF_CNT];

	u32 coord[MAX_DPUF_CNT][DPP_PER_DPUF * 2];
	u32 coord_cnt[MAX_DPUF_CNT];

	u32 max_range[MAX_DPUF_CNT][DPP_PER_DPUF][2];
	u32 max_range_cnt[MAX_DPUF_CNT];
};

/* unit : usec x 1000 -> 5592 (5.592us) for WQHD+ case */
static inline u32 dpu_bts_get_one_line_time(struct decon_device *decon)
{
	u32 tot_v;
	int tmp;

	tot_v = decon->bts.vbp + decon->bts.vfp + decon->bts.vsa;
	tot_v += decon->config.image_height;
	tmp = DIV_ROUND_UP(FRAME_TIME_NSEC, decon->bts.fps);

	return (tmp / tot_v);
}

/* lmc : line memory count (usually 4) */
static inline u32 dpu_bts_comp_latency(u32 src_w, u32 ppc, u32 lmc)
{
	return mult_frac(src_w, lmc, ppc);
}

/*
 * line memory max size : 4096
 * lmc : line memory count (usually 4)
 */
static inline u32 dpu_bts_scale_latency(u32 src_w, u32 dst_w,
		u32 ppc, u32 lmc)
{
	if (src_w > dst_w)
		return mult_frac(src_w * lmc, src_w, dst_w * ppc);
	else
		return DIV_ROUND_CLOSEST(src_w * lmc, ppc);
}

/*
 * 1-read
 *  - 8bit/10bit w/ compression : 32 line
 *  - 8bit w/o compression : 64 line
 *  - 10bit w/o compression : 32 line
 */
static inline u32
dpu_bts_rotate_read_line(bool is_comp, u32 format)
{
	const struct dpu_fmt *fmt_info = dpu_find_fmt_info(format);
	u32 read_line = ROT_READ_LINE;

	if (!is_comp && (fmt_info->bpc == 8))
		read_line = (2 * ROT_READ_LINE);

	return read_line;
}

/*
 * rotator ppc is usually 4 or 8
 */
static inline u32
dpu_bts_rotate_latency(u32 src_w, u32 r_ppc, bool is_comp, u32 format)
{
	u32 read_line;

	read_line = dpu_bts_rotate_read_line(is_comp, format);

	return (src_w * (read_line / r_ppc));
}

/*
 * [DSC]
 * Line memory is necessary like followings.
 *  1EA(1ppc) : 2-line for 2-slice, 1-line for 1-slice
 *  2EA(2ppc) : 3.5-line for 4-slice (DSCC 0.5-line + DSC 3-line)
 *        2.5-line for 2-slice (DSCC 0.5-line + DSC 2-line)
 *
 * [DECON] none
 * When 1H is filled at OUT_FIFO, it immediately transfers to DSIM.
 */
static inline u32
dpu_bts_dsc_latency(u32 slice_num, u32 dsc_cnt,
		u32 dst_w, u32 ppc)
{
	u32 lat_dsc = dst_w;

	switch (slice_num) {
	case 1:
		/* DSC: 1EA */
		lat_dsc = dst_w * 1;
		break;
	case 2:
		if (dsc_cnt == 1)
			lat_dsc = dst_w * 2;
		else
			lat_dsc = (dst_w * 25) / (10 * ppc);
		break;
	case 4:
		/* DSC: 2EA */
		lat_dsc = (dst_w * 35) / (10 * ppc);
		break;
	default:
		break;
	}

	return lat_dsc;
}

/*
 * unit : nsec x 1000
 * reference aclk : 100MHz (-> 10ns x 1000)
 * # cycles = usec * aclk_mhz
 */
static inline u32 dpu_bts_convert_aclk_to_ns(u32 aclk_mhz)
{
	return ((ACLK_100MHZ_PERIOD * 100) / aclk_mhz);
}

/*
 * This function is introduced due to VRR feature.
 * return : kHz value based on 1-pixel processing pipe-line
 */
static u64 dpu_bts_get_resol_clock(struct decon_device *decon)
{
	u64 margin;
	u64 resol_khz;
	u32 op_fps, xres, yres, fps;
	u32 slice_cnt;

	fps = decon->bts.fps;
	xres = decon->config.image_width;
	yres = decon->config.image_height;
	slice_cnt = decon->config.dsc.slice_count;

	/*
	 * check lower limit of fps
	 * this can be removed if there is no stuck issue
	 */
	op_fps = (fps < DISP_REFRESH_RATE) ? DISP_REFRESH_RATE : fps;

	/*
	 * aclk_khz = vclk_1pix * ( 1.1 + (48+20)/WIDTH ) : x1000
	 * @ (1.1)   : BUS Latency Considerable Margin (10%)
	 * @ (48+20) : HW bubble cycles
	 *      - 48 : 12 cycles per slice, total 4 slice
	 *      - 20 : hblank cycles for other HW module
	 */

	margin = 1100 + (12000 * slice_cnt + 20000) / xres;

	/* convert to kHz unit */
	resol_khz = (xres * yres * (u64)op_fps * margin / 1000) / 1000;

	return resol_khz;
}

static u32 dpu_bts_get_vblank_time_ns(struct decon_device *decon)
{
	u32 line_t_ns, v_blank_t_ns;

	line_t_ns = dpu_bts_get_one_line_time(decon);
	if (decon->config.mode.op_mode == DECON_VIDEO_MODE)
		v_blank_t_ns = (decon->bts.vbp + decon->bts.vfp) *
					line_t_ns;
	else {
		if (decon->bts.v_blank_t)
			v_blank_t_ns = decon->bts.v_blank_t * 1000U;
		else
			v_blank_t_ns = (decon->bts.vbp + decon->bts.vfp) *
					line_t_ns;
	}

	/* v_blank should be over minimum v total porch */
	if (v_blank_t_ns < (3 * line_t_ns)) {
		v_blank_t_ns = 3 * line_t_ns;
		DPU_DEBUG_BTS(decon, "\t-WARN: v_blank_t_ns is abnormal!(-> %d)\n",
				v_blank_t_ns);
	}

	DPU_DEBUG_BTS(decon, "\t-line_t_ns(%d) v_blank_t_ns(%d)\n",
			line_t_ns, v_blank_t_ns);

	return v_blank_t_ns;
}

static u32
dpu_bts_find_nearest_high_freq(struct decon_device *decon, u32 aclk_base)
{
	int i;

	for (i = (decon->bts.dfs_lv_cnt - 1); i >= 0; i--) {
		if (aclk_base <= decon->bts.dfs_lv[i])
			break;
	}
	if (i < 0) {
		DPU_DEBUG_BTS(decon, "\taclk_base is over L0 frequency!");
		i = 0;
	}
	DPU_DEBUG_BTS(decon, "\tNearest DFS: %d KHz @L%d\n", decon->bts.dfs_lv[i], i);

	return i;
}

/*
 * [caution] src_w/h is rotated size info
 * - src_w : src_h @original input image
 * - src_h : src_w @original input image
 */
static u64
dpu_bts_calc_rotate_cycle(struct decon_device *decon, u32 aclk_base,
		u32 ppc, u32 format, u32 src_w, u32 dst_w,
		bool is_comp, bool is_scale, bool is_dsc,
		u32 *module_cycle, u32 *basic_cycle)
{
	u32 dfs_idx = 0;
	u32 dsi_cycle, base_cycle, temp_cycle = 0;
	u32 comp_cycle = 0, rot_cycle = 0, scale_cycle = 0, dsc_cycle = 0;
	u64 dfs_aclk;

	DPU_DEBUG_BTS(decon, "BEFORE latency check\n");
	DPU_DEBUG_BTS(decon, "\tACLK: %d KHz\n", aclk_base);

	dfs_idx = dpu_bts_find_nearest_high_freq(decon, aclk_base);
	dfs_aclk = decon->bts.dfs_lv[dfs_idx];

	/* post DECON OUTFIFO based on 1H transfer */
	dsi_cycle = decon->config.image_width;

	/* get additional pipeline latency */
	rot_cycle = dpu_bts_rotate_latency(src_w,
		decon->bts.ppc_rotator, is_comp, format);
	DPU_DEBUG_BTS(decon, "\tROT: lat_cycle(%d)\n", rot_cycle);
	temp_cycle += rot_cycle;
	if (is_comp) {
		comp_cycle = dpu_bts_comp_latency(src_w, ppc,
			decon->bts.delay_comp);
		DPU_DEBUG_BTS(decon, "\tCOMP: lat_cycle(%d)\n", comp_cycle);
		temp_cycle += comp_cycle;
	}
	if (is_scale) {
		scale_cycle = dpu_bts_scale_latency(src_w, dst_w,
			decon->bts.ppc_scaler, decon->bts.delay_scaler);
		DPU_DEBUG_BTS(decon, "\tSCALE: lat_cycle(%d)\n", scale_cycle);
		temp_cycle += scale_cycle;
	}
	if (is_dsc) {
		dsc_cycle = dpu_bts_dsc_latency(decon->config.dsc.slice_count,
			decon->config.dsc.dsc_count, dst_w, ppc);
		DPU_DEBUG_BTS(decon, "\tDSC: lat_cycle(%d)\n", dsc_cycle);
		temp_cycle += dsc_cycle;
		dsi_cycle = (dsi_cycle + 2) / 3;
	}

	/*
	 * basic cycle(+ bubble: 10%) + additional cycle based on function
	 * cycle count increases when ACLK goes up due to other conditions
	 * At latency monitor experiment using unit test,
	 *  cycles at 400Mhz were increased by about 800 compared to 200Mhz.
	 * Here, (aclk_mhz * 2) cycles are reflected referring to the result
	 *  because the exact value is unknown.
	 */
	base_cycle = (decon->config.image_width * 11 / 10 + dsi_cycle) / ppc;

	DPU_DEBUG_BTS(decon, "AFTER latency check\n");
	DPU_DEBUG_BTS(decon, "\tACLK: %llu KHz\n", dfs_aclk);
	DPU_DEBUG_BTS(decon, "\tMODULE: module_cycle(%d)\n", temp_cycle);
	DPU_DEBUG_BTS(decon, "\tBASIC: basic_cycle(%d)\n", base_cycle);

	*module_cycle = temp_cycle;
	*basic_cycle = base_cycle;

	return dfs_aclk;
}

static u32
dpu_bts_get_rotate_tx_allow_t(struct decon_device *decon, u32 rot_clk,
		u32 module_cycle, u32 basic_cycle, u32 dst_y, u32 *dpu_lat_t)
{
	u32 dpu_cycle;
	u32 aclk_x_1k_ns, dpu_lat_t_ns, max_lat_t_ns, tx_allow_t_ns;
	s32 start_margin_t_ns;

	dpu_cycle = (basic_cycle + module_cycle) + rot_clk * 2 / 1000U;
	aclk_x_1k_ns = dpu_bts_convert_aclk_to_ns(rot_clk / 1000U);
	dpu_lat_t_ns = (dpu_cycle * aclk_x_1k_ns) / 1000U;
	start_margin_t_ns = (s32)dpu_bts_get_one_line_time(decon) * (dst_y - 1);
	max_lat_t_ns = dpu_bts_get_vblank_time_ns(decon) + start_margin_t_ns;
	if (max_lat_t_ns > dpu_lat_t_ns) {
		tx_allow_t_ns = max_lat_t_ns - dpu_lat_t_ns;
	} else {
		tx_allow_t_ns = max_lat_t_ns;
		DPU_DEBUG_BTS(decon,
				"\tWARN: latency calc result is over tx_allow_t_ns!\n");
	}
	tx_allow_t_ns = tx_allow_t_ns * decon->bts.rot_util / 100;
	DPU_DEBUG_BTS(decon, "\t-dpu_cycle(%d) aclk_x_1k_ns(%d)\n",
			dpu_cycle, aclk_x_1k_ns);
	DPU_DEBUG_BTS(decon, "\t-dpu_lat_t_ns(%d) tx_allow_t_ns(%d)\n",
			dpu_lat_t_ns, tx_allow_t_ns);

	*dpu_lat_t = dpu_lat_t_ns;
	return tx_allow_t_ns;
}

static u64 dpu_bts_calc_rotate_aclk(struct decon_device *decon, u32 aclk_base,
		u32 ppc, u32 format, u32 src_w, u32 dst_w, u32 dst_y,
		bool is_comp, bool is_scale, bool is_dsc)
{
	u32 dfs_idx = 0;
	const struct dpu_fmt *fmt_info = dpu_find_fmt_info(format);
	u32 bpp;
	u64 rot_clk;
	u32 module_cycle, basic_cycle;
	u32 rot_read_line;
	u32 rot_init_bw = 0;
	u64 rot_need_clk;
	u32 dpu_lat_t_ns, tx_allow_t_ns;
	u32 temp_clk;
	bool retry_flag = false;

	DPU_DEBUG_BTS(decon, "[ROT+] BEFORE latency check: %d KHz\n", aclk_base);

	dfs_idx = dpu_bts_find_nearest_high_freq(decon, aclk_base);
	bpp = fmt_info->bpp + fmt_info->padding;
	rot_clk = dpu_bts_calc_rotate_cycle(decon, aclk_base, ppc, format,
			src_w, dst_w, is_comp, is_scale, is_dsc,
			&module_cycle, &basic_cycle);
	rot_read_line = dpu_bts_rotate_read_line(is_comp, format);

retry_hi_freq:
	tx_allow_t_ns = dpu_bts_get_rotate_tx_allow_t(decon, rot_clk,
			module_cycle, basic_cycle, dst_y, &dpu_lat_t_ns);
	rot_init_bw = (u64)src_w * rot_read_line * bpp / 8 * 1000U * 1000U /
				tx_allow_t_ns;
	rot_need_clk = rot_init_bw / decon->bts.bus_width;

	if (rot_need_clk > rot_clk) {
		/* not max level */
		if ((int)dfs_idx > 0) {
			/* check if calc_clk is greater than 1-step */
			dfs_idx--;
			temp_clk = decon->bts.dfs_lv[dfs_idx];
			if ((rot_need_clk > temp_clk) && (!retry_flag)) {
				DPU_DEBUG_BTS(decon, "\t-allow_ns(%d) dpu_ns(%d)\n",
					tx_allow_t_ns, dpu_lat_t_ns);
				rot_clk = temp_clk;
				retry_flag = true;
				goto retry_hi_freq;
			}
		}
		rot_clk = rot_need_clk;
	}

	DPU_DEBUG_BTS(decon, "\t-rot_init_bw(%d) rot_need_clk(%d)\n",
			rot_init_bw, (u32)rot_need_clk);
	DPU_DEBUG_BTS(decon, "[ROT-] AFTER latency check: %d KHz\n", (u32)rot_clk);

	return rot_clk;
}

static u32 dpu_bts_calc_ppc(struct decon_device *decon)
{
	u32 ppc;

	if (decon->config.dsc.dsc_count == 1)
		ppc = ((decon->bts.ppc / 2U) >= 1U) ?
				(decon->bts.ppc / 2U) : 1U;
	else
		ppc = decon->bts.ppc;

	if (decon->bts.ppc_scaler && (decon->bts.ppc_scaler < ppc))
		ppc = decon->bts.ppc_scaler;

	return ppc;
}

static u32
dpu_bts_count_per_clk(struct decon_device *decon, u32 width, bool is_comp, bool is_rotate)
{
	u32 ppc;

	if (is_comp && !is_rotate)
		ppc = decon->bts.ppc_scaler_comp;
	else
		ppc = decon->bts.ppc_scaler * DISP_FACTOR;

	return (width * DISP_FACTOR / ppc);
}

u64 dpu_bts_calc_aclk_disp(struct decon_device *decon,
		struct dpu_bts_win_config *config, u64 resol_clk, u32 max_clk)
{
	u64 s_ratio_h, s_ratio_v;
	u64 aclk_disp = 0, aclk_base;
	u32 ppc, ppc_scaler;
	u32 src_w, src_h;
	bool is_rotate = config->is_rot;
	bool is_comp = config->is_comp;
	bool is_scale = false;
	bool is_dsc = false;
	bool mixed_scaler = false;

	if (config->is_rot) {
		src_w = config->src_h;
		src_h = config->src_w;
	} else {
		src_w = config->src_w;
		src_h = config->src_h;
	}

	s_ratio_h = (src_w <= config->dst_w) ? MULTI_FACTOR : MULTI_FACTOR * (u64)src_w / (u64)config->dst_w;
	s_ratio_v = (src_h <= config->dst_h) ? MULTI_FACTOR : MULTI_FACTOR * (u64)src_h / (u64)config->dst_h;

	if ((s_ratio_h != MULTI_FACTOR) || (s_ratio_v != MULTI_FACTOR))
		is_scale = true;

	ppc = dpu_bts_calc_ppc(decon);

	if (is_scale) {
		ppc_scaler = decon->bts.ppc_scaler ?: ppc;

		if (s_ratio_h != MULTI_FACTOR && s_ratio_v == MULTI_FACTOR) {
			if ((u64)src_h != (u64)config->dst_h)
				mixed_scaler = true;
		} else if (s_ratio_h == MULTI_FACTOR && s_ratio_v != MULTI_FACTOR) {
			if ((u64)src_w != (u64)config->dst_w)
				mixed_scaler = true;
		}

		if ((ppc == 1 && ppc_scaler == 2) ||
				(ppc == 2 && ppc_scaler == 4 && mixed_scaler == false)) {
			u32 line_a_ppc, line_b_ppc, cnt_per_clk;
			int diff_w_ppc, ratio_a, ratio_v;
			u32 mFactor = 1000;

			ratio_v = (src_h % config->dst_h) ?
					((src_h/config->dst_h) + 1) : (src_h/config->dst_h);
			/* ratio_a will be multiplied by mFactor to consider the decimal place for
			 * the calculation. At the end, it is divided by mFactor.
			 */
			if(((ratio_v * mFactor) - ((int)(src_h * mFactor)) / (int)(config->dst_h)) > 0)
				ratio_a = (ratio_v * mFactor) - ((src_h * mFactor) / (config->dst_h));
			else
				ratio_a = 0;

			if((((int)src_w / 2) - (int)config->dst_w) > 0)
				diff_w_ppc = (src_w / 2) - config->dst_w;
			else
				diff_w_ppc = 0;

			cnt_per_clk = dpu_bts_count_per_clk(decon, src_w, is_comp, is_rotate);

			line_a_ppc = ((ratio_v - 2) * cnt_per_clk) + max(cnt_per_clk, config->dst_w / ppc);
			if (ppc == 1)
				line_a_ppc = max(line_a_ppc, decon->config.image_width + diff_w_ppc);

			line_b_ppc = ((ratio_v - 1) * cnt_per_clk) + max(cnt_per_clk, config->dst_w / ppc);
			if (ppc == 1)
				line_b_ppc = max(line_b_ppc, decon->config.image_width + diff_w_ppc);

			aclk_disp = (((u64)line_a_ppc * ratio_a / mFactor) +
					(((u64)line_b_ppc * (mFactor - ratio_a)) / mFactor)) *
						decon->bts.resol_clk / decon->config.image_width;
			DPU_DEBUG_BTS(decon, "cnt_per_clk=%d, line_a_ppc=%d, line_b_ppc=%d, aclk_disp=%lld\n",
						cnt_per_clk, line_a_ppc, line_b_ppc, aclk_disp);
		} else {
			aclk_disp = resol_clk * s_ratio_h * s_ratio_v * DISP_FACTOR  / 100UL
				/ ppc_scaler / (MULTI_FACTOR * MULTI_FACTOR);
		}
	}

	if (aclk_disp < (resol_clk / ppc))
		aclk_disp = resol_clk / ppc;

	if (aclk_disp > max_clk)
		aclk_base = aclk_disp;
	else
		aclk_base = max_clk;

	if (is_scale) {
		DPU_DEBUG_BTS(decon, "[SCALE+] BEFORE scale check: %d KHz\n", max_clk);
		DPU_DEBUG_BTS(decon, "[SCALE-] AFTER scale check: %d KHz(mixed:%d)\n", (u32)aclk_base, mixed_scaler);
	}

	if (!is_rotate) {
		aclk_disp = aclk_base;
		goto out;
	}

	/* rotation case: check if latency conditions are met */
	if (decon->config.dsc.enabled)
		is_dsc = true;

	aclk_disp = dpu_bts_calc_rotate_aclk(decon, (u32)aclk_base,
			(u32)ppc, config->format, src_w, config->dst_w, config->dst_y,
			is_comp, is_scale, is_dsc);

out:
	return aclk_disp;
}

static void dpu_bts_sum_all_decon_bw(struct decon_device *decon, u32 ch_bw[])
{
	int i, j;

	if (decon->id >= MAX_DECON_CNT) {
		DPU_INFO_BTS(decon, "undefined decon id!\n");
		return;
	}

	for (i = 0; i < MAX_PORT_CNT; ++i)
		decon->bts.ch_bw[decon->id][i] = ch_bw[i];

	for (i = 0; i < MAX_DECON_CNT; ++i) {
		if (decon->id == i)
			continue;

		for (j = 0; j < MAX_PORT_CNT; ++j)
			ch_bw[j] += decon->bts.ch_bw[i][j];
	}
}

static u64 dpu_bts_calc_disp_with_full_size(struct decon_device *decon)
{
	u64 resol_clock;
	u32 ppc;

	if (decon->bts.resol_clk)
		resol_clock = decon->bts.resol_clk;
	else
		resol_clock = dpu_bts_get_resol_clock(decon);

	ppc = dpu_bts_calc_ppc(decon);

	return (resol_clock/ppc);
}

/* If you need to hold a minlock in a specific scenario, do it here. */
void dpu_bts_set_bus_qos(const struct exynos_drm_crtc *exynos_crtc)
{
	struct decon_device *decon = exynos_crtc->ctx;

	DPU_ATRACE_BEGIN(__func__);
	if (is_version_above(&decon->config.version, 7, 0)) {
		/*
		 * wqhd(+) high fps case
		 *  - INT min freq : 400Mhz
		 *  - MIF min freq : 546Mhz
		 */
		if ((decon->config.out_type & DECON_OUT_DSI)
				&& (decon->config.image_width >= 1440)
				&& (decon->config.image_height >= 2960)
				&& (decon->bts.fps >= 63)) {
			exynos_pm_qos_update_request(&decon->bts.int_qos, 400 * 1000);
			exynos_pm_qos_update_request(&decon->bts.mif_qos, 546 * 1000);
		}
	}
	DPU_ATRACE_END(__func__);
}

static void dpu_bts_dp_qos_update(struct decon_device *decon)
{
	s32 mif_qos = 0, int_qos = 0, disp_qos = 0;
	u64 dp_pixelclock = dp_reg_get_video_clk();

	if (dp_pixelclock >= 533000000) {
		mif_qos = 2028 * 1000;
		int_qos = 534 * 1000;
		disp_qos = 663 * 1000;
	} else if (dp_pixelclock >= 297000000) { /* V3840X2160P30 */
		mif_qos = 2028 * 1000;
		int_qos = 534 * 1000;
		disp_qos = 663 * 1000;
	} else if (dp_pixelclock > 148500000) {
		mif_qos = 2028 * 1000;
		int_qos = 534 * 1000;
		disp_qos = 400 * 1000;
	} else { /* dp_pixelclock <= 148500000 ? */
		mif_qos = 845 * 1000;
	}

	if (dp_pixelclock > 148500000) {
		if (exynos_pm_qos_request_active(&decon->bts.mif_qos))
			exynos_pm_qos_update_request(&decon->bts.mif_qos, mif_qos);
		else
			DPU_ERR_BTS(decon, "mif qos setting error\n");

		if (exynos_pm_qos_request_active(&decon->bts.int_qos))
			exynos_pm_qos_update_request(&decon->bts.int_qos, int_qos);
		else
			DPU_ERR_BTS(decon, "int qos setting error\n");

		if (exynos_pm_qos_request_active(&decon->bts.disp_qos)) {
			exynos_pm_qos_update_request(&decon->bts.disp_qos, disp_qos);
			decon->bts.prev_max_disp_freq = disp_qos;
		} else
			DPU_ERR_BTS(decon, "disp qos setting error\n");

		bts_add_scenario(decon->bts.scen_idx[DPU_BS_DP_DEFAULT]);
	} else { /* dp_pixelclock <= 148500000 ? */
		if (exynos_pm_qos_request_active(&decon->bts.mif_qos))
			exynos_pm_qos_update_request(&decon->bts.mif_qos, mif_qos);
		else
			DPU_ERR_BTS(decon, "mif qos setting error\n");
	}

	if (decon->bts.max_disp_freq < disp_qos)
		decon->bts.max_disp_freq = disp_qos;

	DPU_DEBUG_BTS(decon, "dp pixelclock(%llu)\n", dp_pixelclock);
}

static bool dpu_bts_sajc_avg_ppc;
module_param(dpu_bts_sajc_avg_ppc, bool, 0600);
MODULE_PARM_DESC(dpu_bts_sajc_avg_ppc, "whether to average the sajc ppc or not");

static u64 need_win_overlay_clk(struct decon_device *decon, struct bts_overlay_private *info,
			int max_overlay_cnt, u32 max_clk, u64 resol_clk, u32 *matrix, bool is_sajc)
{
	int i, fid;
	u32 max_tot_h = 0;
	u32 non_max_tot_h = 0;
	u64 need_clk = max_clk;
	u64 applied_ppc;

	for (fid = 0; fid < MAX_DPUF_CNT; fid++) {
		if (info->max_overlay[fid] >= max_overlay_cnt) {
			for (i = 0; i < info->max_range_cnt[fid]; i++) {
				info->max_h[fid] +=
					(info->max_range[fid][i][1] - info->max_range[fid][i][0]);
			}
			if (info->max_h[fid] > max_tot_h)
				max_tot_h = info->max_h[fid];
		}
	}
	non_max_tot_h = decon->config.image_height - max_tot_h;

	if (is_sajc && dpu_bts_sajc_avg_ppc) {
		applied_ppc = (((u64)max_tot_h * matrix[max_overlay_cnt])
				+ ((u64)non_max_tot_h * matrix[max_overlay_cnt - 1]))
				/ decon->config.image_height;
	} else
		applied_ppc = matrix[max_overlay_cnt];

	need_clk = resol_clk * DISP_FACTOR / applied_ppc;
	DPU_DEBUG_BTS(decon, "\tmax_tot_h: %d, non_max_tot_h: %d\n",
			max_tot_h, non_max_tot_h);
	DPU_DEBUG_BTS(decon, "[%s] applied_ppcx100: %llu\n", is_sajc ? "sajc" : "hdr", applied_ppc);

	return need_clk;
}

static void get_private_modify_matrix(struct decon_device *decon, u32 *matrix)
{
	int i;

	u32 decon_ppc_x_factor = dpu_bts_calc_ppc(decon) * DISP_FACTOR;
	for (i = 0; i < (MAX_SAJC_PER_DPUF + 1); i++) {
		if (decon_ppc_x_factor && (*(matrix + i) > decon_ppc_x_factor))
			*(matrix + i) = decon_ppc_x_factor;
	}
}

static u32 get_win_max_overlay_count(struct decon_device *decon,
					struct bts_overlay_private *info)
{
	int i, fid;
	u32 cnt, max_cnt;
	u32 max_overlay_cnt = 0;

	for (fid = 0; fid < MAX_DPUF_CNT; fid++) {
		cnt = 0;
		max_cnt = 0;
		info->max_range_cnt[fid] = 0;
		for (i = 0; i < info->coord_cnt[fid]; i++) {
			if (info->coord[fid][i] & 0x1)
				cnt--;
			else {
				cnt++;
				if (cnt > max_cnt) {
					max_cnt = cnt;
					info->max_range[fid][0][0] = (info->coord[fid][i] >> 1);
					info->max_range[fid][0][1] = (info->coord[fid][i + 1] >> 1) + 1;
					info->max_range_cnt[fid] = 1;
				} else if (cnt == max_cnt) {
					info->max_range[fid][info->max_range_cnt[fid]][0]
							= (info->coord[fid][i] >> 1);
					info->max_range[fid][info->max_range_cnt[fid]][1]
							= (info->coord[fid][i + 1] >> 1) + 1;
					info->max_range_cnt[fid]++;
				}
			}
		}
		info->max_overlay[fid] = max_cnt;
	}

	for (fid = 0; fid < MAX_DPUF_CNT; fid++) {
		DPU_DEBUG_BTS(decon, "\tcount[%d]: %d\n", fid, info->count[fid]);
		DPU_DEBUG_BTS(decon, "\tmax_overlay[%d]: %d\n",
					fid, info->max_overlay[fid]);
		for (i = 0; i < info->max_range_cnt[fid]; i++) {
			DPU_DEBUG_BTS(decon, "\tmax_overlay_range[%d]: [%d, %d]\n",
					fid, info->max_range[fid][i][0], info->max_range[fid][i][1]);
		}
	}

	for (fid = 0; fid < MAX_DPUF_CNT; fid++) {
		if (info->max_overlay[fid] > max_overlay_cnt)
			max_overlay_cnt = info->max_overlay[fid];
	}

	return max_overlay_cnt;
}

static void create_win_overlay_coordinate(int win_cnt, struct dpu_bts_win_config *config,
				struct bts_overlay_private *info, bool is_sajc)
{
	u32 fid, i, j;
	u32 start, end, temp;
	const struct dpu_fmt *fmt_info;
	bool is_matched = false;

	for (i = 0; i < win_cnt; i++) {
		if (config[i].state == DPU_WIN_STATE_DISABLED)
			continue;
		if (config[i].dst_h == 0)
			continue;

		fmt_info = dpu_find_fmt_info(config[i].format);
		is_matched = is_sajc ? config[i].is_comp && IS_RGB(fmt_info) :
				config[i].is_hdr;
		if (is_matched) {
			fid = config[i].dpp_ch / DPP_PER_DPUF;
			info->count[fid]++;
			start = ((u32)config[i].dst_y) << 1;
			end = (((u32)config[i].dst_y + config[i].dst_h - 1) << 1) | 1;

			info->coord[fid][info->coord_cnt[fid]] = start;
			info->coord_cnt[fid]++;
			for (j = info->coord_cnt[fid] - 1; j > 0; j--) {
				if (info->coord[fid][j] < info->coord[fid][j - 1]) {
					temp = info->coord[fid][j];
					info->coord[fid][j] = info->coord[fid][j - 1];
					info->coord[fid][j - 1] = temp;
				} else
					break;
			}
			info->coord[fid][info->coord_cnt[fid]] = end;
			info->coord_cnt[fid]++;
			for (j = info->coord_cnt[fid] - 1; j > 0; j--) {
				if (info->coord[fid][j] < info->coord[fid][j - 1]) {
					temp = info->coord[fid][j];
					info->coord[fid][j] = info->coord[fid][j - 1];
					info->coord[fid][j - 1] = temp;
				} else
					break;
			}
		}
	}
}

static u64
dpu_bts_calc_hdr_disp_freq(struct decon_device *decon, u64 resol_clk, u32 max_clk)
{
	struct dpu_bts_win_config *config = decon->bts.win_config;
	struct bts_overlay_private hdr_info;
	u32 hdr_tdm_ppc[DPP_PER_DPUF + 1] = {0,};
	u32 max_overlay_hdr_cnt = 0;
	u64 hdr_need_clk = max_clk;
	int i;

	memset(&hdr_info, 0, sizeof(struct bts_overlay_private));

	hdr_tdm_ppc[0] = 400;
	hdr_tdm_ppc[1] = 200;
	for (i = 2; i <= DPP_PER_DPUF; ++i) {
		hdr_tdm_ppc[i] = 400 / i;
	}

	create_win_overlay_coordinate(decon->win_cnt, config, &hdr_info, false);
	max_overlay_hdr_cnt = get_win_max_overlay_count(decon, &hdr_info);

	if (!max_overlay_hdr_cnt) {
		hdr_need_clk = resol_clk * DISP_FACTOR / hdr_tdm_ppc[0];
		return hdr_need_clk;
	} else if (max_overlay_hdr_cnt >= DPP_PER_DPUF) {
		DPU_ERR_BTS(decon, "\tmax_overlay_hdr_cnt: %d\n", max_overlay_hdr_cnt);
		hdr_need_clk = resol_clk * DISP_FACTOR / hdr_tdm_ppc[DPP_PER_DPUF];
		return hdr_need_clk;
	}

	return need_win_overlay_clk(decon, &hdr_info, max_overlay_hdr_cnt,
				max_clk, resol_clk, &hdr_tdm_ppc[0], false);
}

static u64
dpu_bts_calc_sajc_disp_freq(struct decon_device *decon, u64 resol_clk, u32 max_clk)
{
	struct dpu_bts_win_config *config = decon->bts.win_config;
	struct bts_overlay_private sajc_info;
	u32 *sajc_tdm_ppc;
	u32 sajc_tdm_ppc_0[MAX_SAJC_PER_DPUF + 1] = {400, 400, 170, 100, 67};
	u32 sajc_tdm_ppc_1[MAX_SAJC_PER_DPUF + 1] = {400, 400, 200, 133, 100};
	u32 max_overlay_sajc_cnt = 0;
	u64 sajc_need_clk = max_clk;

	memset(&sajc_info, 0, sizeof(struct bts_overlay_private));

	create_win_overlay_coordinate(decon->win_cnt, config, &sajc_info, true);
	max_overlay_sajc_cnt = get_win_max_overlay_count(decon, &sajc_info);
	if (!is_version_above(&decon->config.version, 7, 2))
		sajc_tdm_ppc = sajc_tdm_ppc_0;
	else
		sajc_tdm_ppc = sajc_tdm_ppc_1;
	get_private_modify_matrix(decon, sajc_tdm_ppc);

	if (!max_overlay_sajc_cnt) {
		sajc_need_clk = resol_clk * DISP_FACTOR / sajc_tdm_ppc[0];
		return sajc_need_clk;
	} else if (max_overlay_sajc_cnt >= MAX_SAJC_PER_DPUF) {
		DPU_DEBUG_BTS(decon, "\tmax_overlay_sajc_cnt: %d\n", max_overlay_sajc_cnt);
		sajc_need_clk = resol_clk * DISP_FACTOR / sajc_tdm_ppc[MAX_SAJC_PER_DPUF];
		return sajc_need_clk;
	}

	return need_win_overlay_clk(decon, &sajc_info, max_overlay_sajc_cnt,
				max_clk, resol_clk, sajc_tdm_ppc, true);
}

/*
 * When out_type is DSI,
 *  MIF must be 845Mhz or more for 120Hz support
 *  in the max disp frequency condition.
 * In addition, if MIF minlock is requested at 845Mhz,
 *  it is only when operating at 120Hz in a max disp freq. *
 */
static void dpu_bts_dsi_qos_update(struct decon_device *decon)
{
	s32 mif_qos_min = 845 * 1000;
	static int mif_qos_org = 0;

	if (is_version_above(&decon->config.version, 7, 0)) {
		if ((decon->bts.max_disp_freq > decon->bts.dfs_lv[1]) &&
				(decon->bts.fps >= 120)) {
			if (exynos_pm_qos_read_req_value(PM_QOS_BUS_THROUGHPUT,
						&decon->bts.mif_qos) != mif_qos_min) {
				mif_qos_org = exynos_pm_qos_read_req_value(
					PM_QOS_BUS_THROUGHPUT, &decon->bts.mif_qos);
				exynos_pm_qos_update_request(&decon->bts.mif_qos,
						mif_qos_min);
			}
		} else if (exynos_pm_qos_read_req_value(PM_QOS_BUS_THROUGHPUT,
					&decon->bts.mif_qos) == mif_qos_min)
			exynos_pm_qos_update_request(&decon->bts.mif_qos, mif_qos_org);
	}
}

static int cmp_dpp_vstart(const void *a, const void *b)
{
	struct dpu_bts_overlap *in_a = (struct dpu_bts_overlap *)a;
	struct dpu_bts_overlap *in_b = (struct dpu_bts_overlap *)b;

	if (in_a->pos == in_b->pos) {
		if (in_a->bw < in_b->bw)
			return -1;
		return 1;
	} else if (in_a->pos < in_b->pos)
		return -1;

	return 1;
}

#define WIN_START_TIME 20
static void dpu_bts_calc_overlap_bw(struct decon_device *decon)
{
	int i, idx;
	struct dpu_bts *bts = &decon->bts;
	struct bts_decon_info *bts_info = &bts->bts_info;
	struct dpu_bts_win_config *config = bts->win_config;
	struct dpu_bts_overlap line_bw[BTS_DPP_MAX*2];
	unsigned int cur_total = 0;
	unsigned int cur_port[MAX_PORT_CNT];
	unsigned int disp_ch_bw[MAX_PORT_CNT];
	int cnt = 0;

	memset(&line_bw, 0, sizeof(struct dpu_bts_overlap)*BTS_DPP_MAX*2);
	memset(&cur_port, 0, sizeof(int)*MAX_PORT_CNT);
	memset(&disp_ch_bw, 0, sizeof(int)*MAX_PORT_CNT);

	for (i = 0; i < decon->win_cnt; ++i) {
		if (config[i].state != DPU_WIN_STATE_BUFFER)
			continue;

		idx = config[i].dpp_ch;
		line_bw[cnt].pos =
			bts_info->dpp[idx].dst.y1 > WIN_START_TIME ?
				(bts_info->dpp[idx].dst.y1 - WIN_START_TIME) : 0;
		line_bw[cnt].bw = bts_info->dpp[idx].bw;
		line_bw[cnt].port = decon->bts.bw[idx].ch_num;
		cnt++;
		line_bw[cnt].pos = bts_info->dpp[idx].dst.y2;
		line_bw[cnt].bw = -bts_info->dpp[idx].bw;
		line_bw[cnt].port = decon->bts.bw[idx].ch_num;
		cnt++;
	}

	sort(line_bw, cnt, sizeof(struct dpu_bts_overlap), cmp_dpp_vstart,
	     NULL);

	bts->overlay_bw = 0;
	bts->overlay_peak = 0;
	for (i = 0; i < cnt; i++) {
		int port = line_bw[i].port;

		cur_total += line_bw[i].bw;
		cur_port[port] += line_bw[i].bw;

		bts->overlay_bw = max(bts->overlay_bw, cur_total);
		disp_ch_bw[port] = max(disp_ch_bw[port], cur_port[port]);
	}

	bts->overlay_bw += decon->bts.write_bw;
	dpu_bts_sum_all_decon_bw(decon, disp_ch_bw);
	for (i = 0; i < MAX_PORT_CNT; i++)
		bts->overlay_peak = max(bts->overlay_peak, disp_ch_bw[i]);

	if (decon->config.rcd_en)
		bts->overlay_bw += bts_info->vclk;

	DPU_DEBUG_BTS(decon, "\tTotal.BW(KB) = %d, Overlap.BW = %d\n",
		     decon->bts.total_bw, decon->bts.overlay_bw);
}

static bool
__check_suspicious_layer(u32 half_h, u32 full_w, struct dpu_bts_win_config *config)
{
	u32 min, max;
	u32 y, w, h, src_w, src_h;
	bool is_scale = false;

	y = config->dst_y;
	w = config->dst_w;
	h = config->dst_h;

	if (config->is_rot) {
		src_w = config->src_h;
		src_h = config->src_w;
	} else {
		src_w = config->src_w;
		src_h = config->src_h;
	}

	is_scale = (src_w > config->dst_w || src_h > config->dst_h) ? true : false;

	if (y > half_h)
		return false;

	if (!is_scale && w != full_w)
		return false;

	min = w * FHD_MIN_RATIO / 1000;
	max = w * FHD_MAX_RATIO / 1000;

	if (h > min && h < max)
		return true;

	return false;
}

static bool __check_boost_layer_bit(struct decon_device *decon, bool is_shadow)
{
	bool prev, cur;

	prev = !!(decon->bts.prev_boost_info & BIT(2));
	cur = !!(decon->bts.boost_info & BIT(2));

	if (prev == cur)
		return false;

	if (is_shadow) {
		if (prev && !cur)
			return true;
	} else {
		if (!prev && cur)
			return true;
	}

	return false;
}

static void dpu_bts_bandwidth_boost(struct decon_device *decon)
{
	int i;
	struct dpu_bts_win_config *config = decon->bts.win_config;
	const struct dpu_fmt *fmt_info;
	bool is_hdr, is_yuv, is_10bpc, is_comp, is_rot;
	u32 new_info = 0;
	u32 suspicious_layer_cnt = 0;
	u32 half = decon->config.image_height >> 1;

	for (i = 0; i < decon->win_cnt; ++i) {
		if (!is_version_above(&decon->config.version, 7, 3))
			continue;

		if (config[i].state == DPU_WIN_STATE_DISABLED)
			continue;

		if (config[i].state != DPU_WIN_STATE_BUFFER)
			continue;

		fmt_info = dpu_find_fmt_info(config[i].format);
		is_hdr = config[i].is_hdr;
		is_yuv = IS_YUV(fmt_info);
		is_10bpc = IS_10BPC(fmt_info);
		is_comp = config[i].is_comp;
		is_rot = config[i].is_rot;
		if (__check_suspicious_layer(half, decon->config.image_width, &config[i]))
			++suspicious_layer_cnt;

		DPU_DEBUG_BTS(decon, "\t [%d] (yuv:%d, hdr:%d, 10bit:%d, is_comp:%d, is_rot:%d, s:%u)\n",
			      i, is_yuv, is_hdr, is_10bpc, is_comp, is_rot, suspicious_layer_cnt);

		if (!is_yuv || !is_hdr)
			continue;

		if (config[i].src_h * config[i].src_w >= UHD_PIXELS) {
			new_info |= BIT(0);
			if (is_10bpc) {
				new_info |= BIT(1);
				if (!is_comp && is_rot) {
					new_info |= BIT(3);
					decon->bts.max_disp_freq = decon->bts.dfs_lv[0];
				}
			}
		}
	}

	if (suspicious_layer_cnt > 1)
		new_info |= BIT(2);

	if (new_info != decon->bts.boost_info) {
		decon->bts.boost_info = new_info;
		bts_update_type(decon->bts.bw_idx, decon->bts.boost_info);

		if ((decon->bts.boost_info & BIT(0))
				&& (decon->config.image_width >= 1080)
				&& (decon->config.image_height >= 2340)) {
			exynos_pm_qos_update_request(&decon->bts.mif_qos, 676 * 1000);

			if (decon->bts.boost_info & BIT(3)) {
				exynos_pm_qos_update_request(&decon->bts.mif_qos, 3738 * 1000);
				exynos_pm_qos_update_request(&decon->bts.int_qos, 664 * 1000);
			}
		}

		DPU_DEBUG_BTS(decon, "boost switching info - idx:%d, info:%u\n",
				decon->bts.bw_idx, decon->bts.boost_info);
	}
}

static void dpu_bts_find_max_disp_freq(struct decon_device *decon)
{
	int i;
	u64 disp_op_freq = 0, freq = 0, disp_min_freq = 0;
	struct dpu_bts_win_config *config = decon->bts.win_config;
	const struct dpu_fmt *fmt_info;
	bool is_sajc;
	bool is_hdr;
	struct dsim_device *dsim = NULL;
	struct dsim_reg_config *dsim_config = NULL;
	u32 wclk;
	int div = DSIM_CAL_CLK_DIVIDER_DPHY;

	if (decon->config.vote_overlap_bw) {
		dpu_bts_calc_overlap_bw(decon);
		decon->bts.peak = decon->bts.overlay_peak;
		decon->bts.total_bw = decon->bts.overlay_bw;
		decon->bts.read_bw = min(decon->bts.read_bw, decon->bts.total_bw);
	} else {
		u32 disp_ch_bw[MAX_PORT_CNT];
		u32 max_disp_ch_bw;
		int j;

		memset(disp_ch_bw, 0, sizeof(disp_ch_bw));

		for (i = 0; i < MAX_DPP_CNT; ++i)
			for (j = 0; j < MAX_PORT_CNT; ++j)
				if (decon->bts.bw[i].ch_num == j)
					disp_ch_bw[j] += decon->bts.bw[i].val;

		/* must be considered other decon's bw */
		dpu_bts_sum_all_decon_bw(decon, disp_ch_bw);

		for (i = 0; i < MAX_PORT_CNT; ++i)
			if (disp_ch_bw[i])
				DPU_DEBUG_BTS(decon, "\tAXI_DPU%d = %d\n", i,
					      disp_ch_bw[i]);

		max_disp_ch_bw = disp_ch_bw[0];
		for (i = 1; i < MAX_PORT_CNT; ++i)
			if (max_disp_ch_bw < disp_ch_bw[i])
				max_disp_ch_bw = disp_ch_bw[i];

		decon->bts.peak = max_disp_ch_bw;
	}

	if (decon->bts.peak < decon->bts.write_bw)
		decon->bts.peak = decon->bts.write_bw;

	decon->bts.max_disp_freq = decon->bts.peak / decon->bts.inner_width *
		100 / decon->bts.inner_util;
	disp_op_freq = decon->bts.max_disp_freq;

	for (i = 0; i < decon->win_cnt; ++i) {
		if (config[i].state == DPU_WIN_STATE_DISABLED)
			continue;

		freq = dpu_bts_calc_aclk_disp(decon, &config[i],
				(u64)decon->bts.resol_clk, disp_op_freq);
		if (disp_op_freq < freq)
			disp_op_freq = freq;
	}

	for (i = 0; i < decon->win_cnt; ++i) {
		if (!is_version_above(&decon->config.version, 7, 0))
			continue;

		if (config[i].state == DPU_WIN_STATE_DISABLED)
			continue;

		fmt_info = dpu_find_fmt_info(config[i].format);
		is_sajc = config[i].is_comp && IS_RGB(fmt_info);
		if (is_sajc) {
			DPU_DEBUG_BTS(decon, "BEFORE sajc check\n");
			DPU_DEBUG_BTS(decon, "\tdisp_op_freq: %llu KHz\n", disp_op_freq);
			freq = dpu_bts_calc_sajc_disp_freq(decon,
					(u64)decon->bts.resol_clk, disp_op_freq);
			if (disp_op_freq < freq)
				disp_op_freq = freq;
			DPU_DEBUG_BTS(decon, "AFTER sajc check\n");
			DPU_DEBUG_BTS(decon, "\tdisp_op_freq: %llu KHz\n", disp_op_freq);
			break;
		}
	}

	for (i = 0; i < decon->win_cnt; ++i) {
		if (!is_version_above(&decon->config.version, 7, 0))
			continue;

		if (config[i].state == DPU_WIN_STATE_DISABLED)
			continue;

		is_hdr = config[i].is_hdr;
		if (is_hdr) {
			DPU_DEBUG_BTS(decon, "BEFORE hdr check\n");
			DPU_DEBUG_BTS(decon, "\tdisp_op_freq: %llu KHz\n", disp_op_freq);
			freq = dpu_bts_calc_hdr_disp_freq(decon,
					(u64)decon->bts.resol_clk, disp_op_freq);
			if (disp_op_freq < freq)
				disp_op_freq = freq;
			DPU_DEBUG_BTS(decon, "AFTER hdr check\n");
			DPU_DEBUG_BTS(decon, "\tdisp_op_freq: %llu KHz\n", disp_op_freq);
			break;
		}
	}

	config = &decon->bts.wb_config;
	if (config->state != DPU_WIN_STATE_DISABLED) {
		freq = dpu_bts_calc_aclk_disp(decon, config,
				(u64)decon->bts.resol_clk, disp_op_freq);
		if (disp_op_freq < freq)
			disp_op_freq = freq;
	}

	/*
	 * At least one window is used for colormap if there is a request of
	 * disabling all windows. So, disp frequency for a window of LCD full
	 * size is necessary.
	 */
	disp_min_freq = dpu_bts_calc_disp_with_full_size(decon);
	if (disp_op_freq < disp_min_freq)
		disp_op_freq = disp_min_freq;

	if ((!decon->bts.prev_max_disp_freq) &&
			(decon->config.out_type & DECON_OUT_DP))
		dpu_bts_dp_qos_update(decon);

	DPU_DEBUG_BTS(decon, "\tDISP bus freq(%d), operating freq(%llu)\n",
			decon->bts.max_disp_freq, disp_op_freq);

	if (decon->bts.max_disp_freq < disp_op_freq)
		decon->bts.max_disp_freq = disp_op_freq;

	/*
	 * disp-aclk should be at least higher than wclk.
	 * otherwise, dsim link may mal-function.
	 */
	if (decon->config.out_type & DECON_OUT_DSI) {
		dsim = decon_get_dsim(decon);
		if (dsim) {
			dsim_config = &dsim->config;
			if (dsim_config && dsim_config->intf_type == DSIM_DSI_INTF_CPHY)
				div = DSIM_CAL_CLK_DIVIDER_CPHY;

			wclk = DIV_ROUND_UP(dsim->clk_param.hs_clk, div);
			if (decon->bts.max_disp_freq < wclk * 1000)
				decon->bts.max_disp_freq = wclk * 1000;
		}
	}

	if (decon->config.out_type & DECON_OUT_DP)
		if (decon->bts.max_disp_freq < 200000)
			decon->bts.max_disp_freq = 200000;

	if (decon->config.out_type & DECON_OUT_DSI)
		dpu_bts_dsi_qos_update(decon);

	if (decon->config.out_type & DECON_OUT_DSI)
		dpu_bts_bandwidth_boost(decon);

	if (decon->bts.max_disp_freq > decon->bts.dfs_lv[0])
		DPU_DEBUG_BTS(decon, "\tMAX DISP FREQ = %d => too high: over L0 freq!\n",
				decon->bts.max_disp_freq);
	else
		DPU_DEBUG_BTS(decon, "\tMAX DISP FREQ = %d\n", decon->bts.max_disp_freq);
}

static void dpu_bts_share_bw_info(int id)
{
	int i, j;
	struct decon_device *decon[MAX_DECON_CNT];

	for (i = 0; i < MAX_DECON_CNT; i++)
		decon[i] = NULL;

	for (i = 0; i < MAX_DECON_CNT; i++)
		decon[i] = get_decon_drvdata(i);

	for (i = 0; i < MAX_DECON_CNT; ++i) {
		if (id == i || decon[i] == NULL)
			continue;

		for (j = 0; j < MAX_PORT_CNT; ++j)
			decon[i]->bts.ch_bw[id][j] =
				decon[id]->bts.ch_bw[id][j];
	}
}

static void dpu_bts_convert_config_to_info(const struct decon_device *decon,
		struct bts_dpp_info *dpp, const struct dpu_bts_win_config *config)
{
	const struct dpu_fmt *fmt_info;

	dpp->used = true;
	fmt_info = dpu_find_fmt_info(config->format);
	dpp->bpp = fmt_info->bpp + fmt_info->padding;
	dpp->src_w = config->src_w;
	dpp->src_h = config->src_h;
	dpp->dst.x1 = config->dst_x;
	dpp->dst.x2 = config->dst_x + config->dst_w;
	dpp->dst.y1 = config->dst_y;
	dpp->dst.y2 = config->dst_y + config->dst_h;
	dpp->rotation = config->is_rot;
	dpp->compression = config->is_comp;
	dpp->fmt_name = fmt_info->name;
	dpp->hdr = config->is_hdr;

	DPU_DEBUG_BTS(decon,
			"\tDPP%d : bpp(%d) src w(%d) h(%d) rot(%d) comp(%d) fmt(%s)\n",
			config->dpp_ch, dpp->bpp, dpp->src_w, dpp->src_h,
			dpp->rotation, dpp->compression, dpp->fmt_name);
	DPU_DEBUG_BTS(decon,
			"\t\t\t\tdst x(%d) right(%d) y(%d) bottom(%d)\n",
			dpp->dst.x1, dpp->dst.x2, dpp->dst.y1, dpp->dst.y2);
}

static void
dpu_bts_calc_dpp_bw(struct decon_device *decon, struct bts_dpp_info *dpp,
				struct bts_decon_info *bts_info, u32 format, int idx)
{
	u64 ch_bw = 0, rot_bw;
	u32 src_w, src_h;
	u32 dst_w, dst_h;
	u64 s_ratio_h, s_ratio_v;
	u32 ppc;
	u32 aclk_base;
	bool is_comp, is_scale = false, is_dsc;
	u32 module_cycle, basic_cycle;
	u64 rot_clk;
	u32 dpu_lat_t_ns, tx_allow_ns;
	u32 rot_read_line;

	if (dpp->rotation) {
		src_w = dpp->src_h;
		src_h = dpp->src_w;
	} else {
		src_w = dpp->src_w;
		src_h = dpp->src_h;
	}
	dst_w = dpp->dst.x2 - dpp->dst.x1;
	dst_h = dpp->dst.y2 - dpp->dst.y1;
	if (!dst_w || !dst_h)
		goto out;

	s_ratio_h = (src_w <= dst_w) ? MULTI_FACTOR : MULTI_FACTOR * (u64)src_w / (u64)dst_w;
	s_ratio_v = (src_h <= dst_h) ? MULTI_FACTOR : MULTI_FACTOR * (u64)src_h / (u64)dst_h;

	/* BW(KB) : s_ratio_h * s_ratio_v * (bpp/8) * resol_clk (* dst_w / xres) */
	ch_bw = s_ratio_h * s_ratio_v * dpp->bpp / 8 * bts_info->vclk
		/ (MULTI_FACTOR * MULTI_FACTOR);
	if (decon->bts.fps <= DISP_REFRESH_RATE)
		ch_bw = ch_bw * (u64)dst_w / bts_info->lcd_w;

	if (dpp->rotation) {
		/* case for using dsc encoder 1ea at decon0 or decon1 */
		if (decon->config.dsc.dsc_count == 1)
			ppc = ((decon->bts.ppc / 2U) >= 1U) ?
					(decon->bts.ppc / 2U) : 1U;
		else
			ppc = decon->bts.ppc;
		if (decon->bts.ppc_scaler && (decon->bts.ppc_scaler < ppc))
			ppc = decon->bts.ppc_scaler;

		aclk_base = exynos_devfreq_get_domain_freq(decon->bts.df_disp_idx);
		if (aclk_base < (decon->bts.resol_clk / ppc))
			aclk_base = decon->bts.resol_clk / ppc;

		is_comp = dpp->compression;
		if ((s_ratio_h != MULTI_FACTOR) || (s_ratio_v != MULTI_FACTOR))
			is_scale = true;
		is_dsc = decon->config.dsc.enabled;

		rot_clk = dpu_bts_calc_rotate_cycle(decon, aclk_base, ppc, format,
				src_w, dst_w, is_comp, is_scale, is_dsc,
				&module_cycle, &basic_cycle);
		tx_allow_ns = dpu_bts_get_rotate_tx_allow_t(decon, (u32)rot_clk,
				module_cycle, basic_cycle, dpp->dst.y1, &dpu_lat_t_ns);

		rot_read_line = dpu_bts_rotate_read_line(is_comp, format);

		/* BW(KB) : sh * 32B * (bpp/8) / v_blank */
		rot_bw = (u64)src_w * rot_read_line * dpp->bpp / 8 * 1000000U /
				tx_allow_ns;
		DPU_DEBUG_BTS(decon, "\tDPP%d ch_bw(%llu), rot_bw(%llu)\n",
				idx, ch_bw, rot_bw);
		if (rot_bw > ch_bw)
			ch_bw = rot_bw;
	}

out:
	dpp->bw = (u32)ch_bw;

	DPU_DEBUG_BTS(decon, "\tDPP%d BW = %d\n", idx, dpp->bw);
}

void dpu_bts_calc_bw(struct exynos_drm_crtc *exynos_crtc)
{
	struct decon_device *decon = exynos_crtc->ctx;
	struct dpu_bts_win_config *config = decon->bts.win_config;
	struct bts_decon_info bts_info;
	int idx, i, wb_idx;
	u32 read_bw = 0, write_bw = 0;
	u64 resol_clock;

	if (!decon->bts.enabled)
		return;

	DPU_ATRACE_BEGIN(__func__);
	DPU_DEBUG_BTS(decon, "+\n");

	memset(&bts_info, 0, sizeof(struct bts_decon_info));

	if (decon->config.out_type == DECON_OUT_WB) {
		decon->config.image_width = decon->bts.wb_config.dst_w;
		decon->config.image_height = decon->bts.wb_config.dst_h;
	}

	resol_clock = dpu_bts_get_resol_clock(decon);
	decon->bts.resol_clk = (u32)resol_clock;
	DPU_DEBUG_BTS(decon, "[Run] resol clock = %d Khz @%d fps\n",
			decon->bts.resol_clk, decon->bts.fps);

	bts_info.vclk = decon->bts.resol_clk;
	bts_info.lcd_w = decon->config.image_width;
	bts_info.lcd_h = decon->config.image_height;

	/* read bw calculation */
	for (i = 0; i < decon->win_cnt; ++i) {
		if (config[i].state != DPU_WIN_STATE_BUFFER)
			continue;

		idx = config[i].dpp_ch;
		dpu_bts_convert_config_to_info(decon, &bts_info.dpp[idx], &config[i]);
		dpu_bts_calc_dpp_bw(decon, &bts_info.dpp[idx], &bts_info,
					config[i].format, idx);
		read_bw += bts_info.dpp[idx].bw;
	}

	if (decon->config.rcd_en) {
		DPU_DEBUG_BTS(decon, "additional BW for RCD\n");
		read_bw += bts_info.vclk;
	}

	/* write bw calculation */
	config = &decon->bts.wb_config;
	wb_idx = config->dpp_ch;
	if (config->state == DPU_WIN_STATE_BUFFER) {
		dpu_bts_convert_config_to_info(decon, &bts_info.dpp[wb_idx], config);
		dpu_bts_calc_dpp_bw(decon, &bts_info.dpp[wb_idx], &bts_info,
					config->format, wb_idx);
		write_bw += bts_info.dpp[wb_idx].bw;
	}

	for (i = 0; i < MAX_DPP_CNT; i++)
		decon->bts.bw[i].val = bts_info.dpp[i].bw;

	decon->bts.read_bw = read_bw;
	decon->bts.write_bw = write_bw;
	decon->bts.total_bw = read_bw + write_bw;
	memcpy(&decon->bts.bts_info, &bts_info, sizeof(struct bts_decon_info));

	DPU_DEBUG_BTS(decon, "\tTotal.BW(KB) = %d, Rd.BW = %d, Wr.BW = %d\n",
			decon->bts.total_bw, decon->bts.read_bw, decon->bts.write_bw);

	dpu_bts_find_max_disp_freq(decon);

	/* update bw for other decons */
	dpu_bts_share_bw_info(decon->id);

	DPU_EVENT_LOG("BTS_CALC_BW", exynos_crtc, 0, FREQ_FMT" calculated disp(%u)",
			FREQ_ARG(&decon->bts), decon->bts.max_disp_freq);
	DPU_DEBUG_BTS(decon, "-\n");
	DPU_ATRACE_END(__func__);
}

void dpu_bts_update_bw(struct exynos_drm_crtc *exynos_crtc, bool shadow_updated)
{
	struct decon_device *decon = exynos_crtc->ctx;
	struct bts_bw bw = { 0, };
	struct drm_crtc_state *new_crtc_state = exynos_crtc->base.state;
	struct exynos_drm_crtc_state *new_exynos_crtc_state =
					to_exynos_crtc_state(new_crtc_state);
	u64 system_disp = 0;
	u64 dp_pixelclock;

	if (!decon->bts.enabled)
		return;

	DPU_ATRACE_BEGIN(__func__);
	if (decon->config.out_type & DECON_OUT_DP)
		dp_pixelclock = dp_reg_get_video_clk();

	DPU_DEBUG_BTS(decon, "+\n");

	/* update peak & read bandwidth per DPU port */
	bw.peak = decon->bts.peak;
	bw.read = decon->bts.read_bw;
	bw.write = decon->bts.write_bw;
	DPU_DEBUG_BTS(decon, "\t(%s shadow_update) peak = %d, read = %d, write = %d\n",
		(shadow_updated ? "after" : "before"), bw.peak, bw.read, bw.write);

	if (shadow_updated) {
		/* after DECON h/w configs are updated to shadow SFR */
		DPU_EVENT_LOG("[S0] BTS_UPDATE_BW", exynos_crtc, 0,
				UPDATE_BW_FMT, UPDATE_BW_ARG_BTS(&decon->bts));
		if (decon->bts.total_bw < decon->bts.prev_total_bw ||
			__check_boost_layer_bit(decon, shadow_updated))
			bts_update_bw(decon->bts.bw_idx, bw);

		DPU_EVENT_LOG("[S1] BTS_UPDATE_BW", exynos_crtc, 0,
				UPDATE_BW_FMT, UPDATE_BW_ARG_BTS(&decon->bts));

		if ((decon->config.out_type & DECON_OUT_DP) &&
				IS_DP_ON_STATE() && dp_pixelclock >= 297000000) {
			decon->bts.prev_max_disp_freq = decon->bts.max_disp_freq;
			return;
		}

		DPU_EVENT_LOG("[S2] BTS_UPDATE_BW", exynos_crtc, 0,
				UPDATE_BW_FMT, UPDATE_BW_ARG_BTS(&decon->bts));

		if (decon->bts.max_disp_freq < decon->bts.prev_max_disp_freq) {
			exynos_pm_qos_update_request(&decon->bts.disp_qos,
					decon->bts.max_disp_freq);
			DPU_DEBUG_BTS(decon, "disp_qos_update_request(disp_qos=%d)\n",
						decon->bts.max_disp_freq);
		}
		decon->bts.prev_total_bw = decon->bts.total_bw;
		decon->bts.prev_max_disp_freq = decon->bts.max_disp_freq;
		decon->bts.prev_boost_info = decon->bts.boost_info;
	} else {
		DPU_EVENT_LOG("[C0] BTS_UPDATE_BW", exynos_crtc, 0,
				UPDATE_BW_FMT, UPDATE_BW_ARG_BTS(&decon->bts));
		if (decon->bts.total_bw > decon->bts.prev_total_bw ||
			__check_boost_layer_bit(decon, shadow_updated))
			bts_update_bw(decon->bts.bw_idx, bw);

		DPU_EVENT_LOG("[C1] BTS_UPDATE_BW", exynos_crtc, 0,
				UPDATE_BW_FMT, UPDATE_BW_ARG_BTS(&decon->bts));

		if (new_exynos_crtc_state->wb_type == EXYNOS_WB_CWB) {
			if (exynos_pm_qos_request_active(&decon->bts.int_qos))
				exynos_pm_qos_update_request(&decon->bts.int_qos, 663 * 1000);
			if (exynos_pm_qos_request_active(&decon->bts.mif_qos))
				exynos_pm_qos_update_request(&decon->bts.mif_qos, 845 * 1000);
		}

		if (decon->config.out_type & DECON_OUT_DP &&
				IS_DP_ON_STATE() && dp_pixelclock >= 297000000)
			return;

		DPU_EVENT_LOG("[C2] BTS_UPDATE_BW", exynos_crtc, 0,
				UPDATE_BW_FMT, UPDATE_BW_ARG_QOS(&decon->bts));
		system_disp = exynos_devfreq_get_domain_freq(decon->bts.df_disp_idx);
		if (system_disp < decon->bts.max_disp_freq ||
			decon->bts.max_disp_freq > decon->bts.prev_max_disp_freq) {

			if (system_disp < decon->bts.max_disp_freq)
				DPU_DEBUG_BTS(decon, "\tWARN: Applied disp clock is lower\n");

			exynos_pm_qos_update_request(&decon->bts.disp_qos,
					decon->bts.max_disp_freq);
			DPU_DEBUG_BTS(decon, "disp_qos_update_request(disp_qos=%d)\n",
						decon->bts.max_disp_freq);
		}

		if (new_exynos_crtc_state->wb_type == EXYNOS_WB_CWB)
			DPU_DEBUG_BTS(decon, "\tCWB: "FREQ_FMT"\n", FREQ_ARG(&decon->bts));
	}

	DPU_EVENT_LOG("BTS_UPDATE_BW", exynos_crtc, 0, FREQ_FMT, FREQ_ARG(&decon->bts));

	DPU_DEBUG_BTS(decon, "-\n");
	DPU_ATRACE_END(__func__);
}

void dpu_bts_release_bw(struct exynos_drm_crtc *exynos_crtc)
{
	struct decon_device *decon = exynos_crtc->ctx;
	struct bts_bw bw = { 0, };

	if (!decon->bts.enabled)
		return;

	DPU_DEBUG_BTS(decon, "+\n");

	if ((decon->config.out_type & DECON_OUT_DSI) ||
		(decon->config.out_type == DECON_OUT_WB)) {
		DPU_EVENT_LOG("[S] BTS_RELEASE_BW", exynos_crtc, 0, NULL);
		bts_update_bw(decon->bts.bw_idx, bw);
		decon->bts.prev_total_bw = 0;

		if (exynos_pm_qos_request_active(&decon->bts.mif_qos))
			exynos_pm_qos_update_request(&decon->bts.mif_qos, 0);
		else
			DPU_ERR_BTS(decon, "mif qos setting error\n");

		if (exynos_pm_qos_request_active(&decon->bts.int_qos))
			exynos_pm_qos_update_request(&decon->bts.int_qos, 0);
		else
			DPU_ERR_BTS(decon, "int qos setting error\n");

		if (exynos_pm_qos_request_active(&decon->bts.disp_qos))
			exynos_pm_qos_update_request(&decon->bts.disp_qos, 0);
		else
			DPU_ERR_BTS(decon, "disp qos setting error\n");

		if (decon->bts.boost_info > 0) {
			decon->bts.boost_info = 0;
			decon->bts.prev_boost_info = 0;
			DPU_DEBUG_BTS(decon, "release boosting - idx:%d, info:%u\n",
					decon->bts.bw_idx, decon->bts.boost_info);
			bts_update_type(decon->bts.bw_idx, decon->bts.boost_info);
		}
		decon->bts.prev_max_disp_freq = 0;
	} else if (decon->config.out_type & DECON_OUT_DP) {
		decon->bts.prev_total_bw = 0;
		if (exynos_pm_qos_request_active(&decon->bts.mif_qos))
			exynos_pm_qos_update_request(&decon->bts.mif_qos, 0);
		else
			DPU_ERR_BTS(decon, "mif qos setting error\n");

		if (exynos_pm_qos_request_active(&decon->bts.int_qos))
			exynos_pm_qos_update_request(&decon->bts.int_qos, 0);
		else
			DPU_ERR_BTS(decon, "int qos setting error\n");

		if (exynos_pm_qos_request_active(&decon->bts.disp_qos))
			exynos_pm_qos_update_request(&decon->bts.disp_qos, 0);
		else
			DPU_ERR_BTS(decon, "disp qos setting error\n");
		decon->bts.prev_max_disp_freq = 0;
		bts_del_scenario(decon->bts.scen_idx[DPU_BS_DP_DEFAULT]);
	}

	DPU_EVENT_LOG("BTS_RELEASE_BW", exynos_crtc, 0, FREQ_FMT, FREQ_ARG(&decon->bts));
	DPU_DEBUG_BTS(decon, "-\n");
}

#define MAX_IDX_NAME_SIZE	16
void dpu_bts_init(struct exynos_drm_crtc *exynos_crtc)
{
	int i;
	char bts_idx_name[MAX_IDX_NAME_SIZE];
	const struct drm_encoder *encoder;
	struct decon_device *decon = exynos_crtc->ctx;
	const char *scen_name[DPU_BS_MAX] = {
		"default",
		"mfc_uhd",
		"mfc_uhd_10bit",
		"dp_default",
		/* add scenario & update index of [bts.h] */
	};

	DPU_DEBUG_BTS(decon, "+\n");

	decon->bts.enabled = false;

	if ((!IS_ENABLED(CONFIG_EXYNOS_BTS) && !IS_ENABLED(CONFIG_EXYNOS_BTS_MODULE))
			|| (!IS_ENABLED(CONFIG_EXYNOS_PM_QOS) &&
				!IS_ENABLED(CONFIG_EXYNOS_PM_QOS_MODULE))) {
		DPU_ERR_BTS(decon, "bts feature is disabled\n");
		return;
	}

	memset(bts_idx_name, 0, MAX_IDX_NAME_SIZE);
	snprintf(bts_idx_name, MAX_IDX_NAME_SIZE, "DECON%d", decon->id);
	decon->bts.bw_idx = bts_get_bwindex(bts_idx_name);

	/*
	 * Get scenario index from BTS driver
	 * Don't try to get index value of "default" scenario
	 */
	for (i = 1; i < DPU_BS_MAX; i++) {
		if (scen_name[i] != NULL)
			decon->bts.scen_idx[i] =
				bts_get_scenindex(scen_name[i]);
	}

	for (i = 0; i < MAX_PORT_CNT; i++)
		decon->bts.ch_bw[decon->id][i] = 0;

	DPU_DEBUG_BTS(decon, "BTS_BW_TYPE(%d)\n", decon->bts.bw_idx);
	exynos_pm_qos_add_request(&decon->bts.mif_qos,
					PM_QOS_BUS_THROUGHPUT, 0);
	exynos_pm_qos_add_request(&decon->bts.int_qos,
					PM_QOS_DEVICE_THROUGHPUT, 0);
	exynos_pm_qos_add_request(&decon->bts.disp_qos,
					PM_QOS_DISPLAY_THROUGHPUT, 0);

	for (i = 0; i < decon->win_cnt; ++i) { /* dma type order */
		decon->bts.bw[i].ch_num = decon->dpp[i]->port;
		DPU_INFO_BTS(decon, "CH(%d) Port(%d)\n", i, decon->bts.bw[i].ch_num);
	}

	drm_for_each_encoder(encoder, decon->drm_dev) {
		const struct writeback_device *wb;

		if (encoder->encoder_type == DRM_MODE_ENCODER_VIRTUAL) {
			wb = enc_to_wb_dev(encoder);
			decon->bts.bw[wb->id].ch_num = wb->port;
			break;
		}
	}

	decon->bts.enabled = true;
	decon->bts.boost_info = 0;

	DPU_INFO_BTS(decon, "bts feature is enabled\n");
}

void dpu_bts_deinit(struct exynos_drm_crtc *exynos_crtc)
{
	struct decon_device *decon = exynos_crtc->ctx;

	if (!decon->bts.enabled)
		return;

	DPU_DEBUG_BTS(decon, "+\n");
	exynos_pm_qos_remove_request(&decon->bts.disp_qos);
	exynos_pm_qos_remove_request(&decon->bts.int_qos);
	exynos_pm_qos_remove_request(&decon->bts.mif_qos);
	DPU_DEBUG_BTS(decon, "-\n");
}

void dpu_bts_print_info(const struct exynos_drm_crtc *exynos_crtc)
{
	int i;
	struct decon_device *decon = exynos_crtc->ctx;
	const struct bts_decon_info *info = &decon->bts.bts_info;
	static ktime_t bts_info_print_block_ts;
	bool bts_info_print_blocked = true;

	if (!decon->bts.enabled)
		return;

	DPU_INFO_BTS(decon, "bw(prev:%u curr:%u), disp(prev:%u curr:%u), peak(%u), boost(%u)\n",
			decon->bts.prev_total_bw,
			decon->bts.total_bw, decon->bts.prev_max_disp_freq,
			decon->bts.max_disp_freq, decon->bts.peak, decon->bts.boost_info);

	DPU_INFO_BTS(decon, FREQ_FMT"\n", FREQ_ARG(&decon->bts));

	if (ktime_after(ktime_get(), bts_info_print_block_ts)) {
		bts_info_print_block_ts = ktime_add_ms(ktime_get(),
					BTS_INFO_PRINT_BLOCK_TIMEOUT);
		bts_info_print_blocked = false;
	}

	if (bts_info_print_blocked)
		return;

	show_exynos_pm_qos_data(PM_QOS_BUS_THROUGHPUT);
	show_exynos_pm_qos_data(PM_QOS_BUS_THROUGHPUT_MAX);
	show_exynos_pm_qos_data(PM_QOS_DISPLAY_THROUGHPUT);
	show_exynos_pm_qos_data(PM_QOS_DEVICE_THROUGHPUT);

	for (i = 0; i < MAX_DPP_CNT; ++i) {
		if (!info->dpp[i].used)
			continue;

		DPU_INFO_BTS(decon, "DPP[%d] bpp(%d) src(%d %d) dst(%d %d %d %d)\n",
				i, info->dpp[i].bpp,
				info->dpp[i].src_w, info->dpp[i].src_h,
				info->dpp[i].dst.x1, info->dpp[i].dst.x2,
				info->dpp[i].dst.y1, info->dpp[i].dst.y2);
		DPU_INFO_BTS(decon, "rot(%d) comp(%d) fmt(%s) hdr(%d)\n",
				info->dpp[i].rotation, info->dpp[i].compression,
				info->dpp[i].fmt_name, info->dpp[i].hdr);
	}
}

struct dpu_bts_ops dpu_bts_control = {
	.init		= dpu_bts_init,
	.calc_bw	= dpu_bts_calc_bw,
	.update_bw	= dpu_bts_update_bw,
	.release_bw	= dpu_bts_release_bw,
	.deinit		= dpu_bts_deinit,
	.print_info	= dpu_bts_print_info,
	.set_bus_qos    = dpu_bts_set_bus_qos,
};
