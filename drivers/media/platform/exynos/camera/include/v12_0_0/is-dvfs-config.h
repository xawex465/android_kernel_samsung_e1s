// SPDX-License-Identifier: GPL-2.0
/*
 * Samsung Exynos SoC series Pablo driver
 *
 * Copyright (c) 2022 Samsung Electronics Co., Ltd
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#ifndef IS_DVFS_CONFIG_H
#define IS_DVFS_CONFIG_H

#include "pablo-dvfs.h"

/* for backword compatibility with DVFS V1.0 */
#define IS_SN_MAX IS_DVFS_SN_MAX
#define IS_SN_END IS_DVFS_SN_END

/* Pablo DVFS SCENARIO enum */
enum IS_DVFS_SN {
	IS_DVFS_SN_DEFAULT,
	/* rear sensor scenarios */
	IS_DVFS_SN_REAR_SINGLE_PHOTO,
	IS_DVFS_SN_REAR_SINGLE_PHOTO_FULL,
	IS_DVFS_SN_REAR_SINGLE_CAPTURE,
	IS_DVFS_SN_REAR_SINGLE_VIDEO_FHD30,
	IS_DVFS_SN_REAR_SINGLE_VIDEO_FHD30_SUPERSTEADY,
	IS_DVFS_SN_REAR_SINGLE_VIDEO_FHD30_RECURSIVE,
	IS_DVFS_SN_REAR_SINGLE_VIDEO_FHD60,
	IS_DVFS_SN_REAR_SINGLE_VIDEO_FHD60_SUPERSTEADY,
	IS_DVFS_SN_REAR_SINGLE_VIDEO_FHD120,
	IS_DVFS_SN_REAR_SINGLE_VIDEO_FHD240,
	IS_DVFS_SN_REAR_SINGLE_VIDEO_FHD480,
	IS_DVFS_SN_REAR_SINGLE_VIDEO_UHD30,
	IS_DVFS_SN_REAR_SINGLE_VIDEO_UHD30_SUPERSTEADY,
	IS_DVFS_SN_REAR_SINGLE_VIDEO_UHD30_RECURSIVE,
	IS_DVFS_SN_REAR_SINGLE_VIDEO_UHD60,
	IS_DVFS_SN_REAR_SINGLE_VIDEO_UHD60_SUPERSTEADY,
	IS_DVFS_SN_REAR_SINGLE_VIDEO_UHD60_PSM,
	IS_DVFS_SN_REAR_SINGLE_VIDEO_UHD120,
	IS_DVFS_SN_REAR_SINGLE_VIDEO_8K24,
	IS_DVFS_SN_REAR_SINGLE_VIDEO_8K24_HF,
	IS_DVFS_SN_REAR_SINGLE_VIDEO_8K30,
	IS_DVFS_SN_REAR_SINGLE_VIDEO_8K30_HF,
	IS_DVFS_SN_REAR_SINGLE_REMOSAIC_PHOTO,
	IS_DVFS_SN_REAR_SINGLE_REMOSAIC_CAPTURE,
	IS_DVFS_SN_REAR_SINGLE_FASTAE,
	IS_DVFS_SN_REAR_SINGLE_SSM,
	IS_DVFS_SN_REAR_SINGLE_VT,
	/* dual sensor scenarios */
	IS_DVFS_SN_REAR_DUAL_PHOTO,
	IS_DVFS_SN_REAR_DUAL_CAPTURE,
	IS_DVFS_SN_REAR_DUAL_VIDEO_FHD30,
	IS_DVFS_SN_REAR_DUAL_VIDEO_UHD30,
	IS_DVFS_SN_REAR_DUAL_VIDEO_FHD60,
	IS_DVFS_SN_REAR_DUAL_VIDEO_UHD60,
	/* front sensor scenarios */
	IS_DVFS_SN_FRONT_SINGLE_PHOTO,
	IS_DVFS_SN_FRONT_SINGLE_PHOTO_FULL,
	IS_DVFS_SN_FRONT_SINGLE_CAPTURE,
	IS_DVFS_SN_FRONT_SINGLE_VIDEO_FHD30,
	IS_DVFS_SN_FRONT_SINGLE_VIDEO_FHD30_RECURSIVE,
	IS_DVFS_SN_FRONT_SINGLE_VIDEO_FHD60,
	IS_DVFS_SN_FRONT_SINGLE_VIDEO_FHD120,
	IS_DVFS_SN_FRONT_SINGLE_VIDEO_UHD30,
	IS_DVFS_SN_FRONT_SINGLE_VIDEO_UHD30_RECURSIVE,
	IS_DVFS_SN_FRONT_SINGLE_VIDEO_UHD60,
	IS_DVFS_SN_FRONT_SINGLE_VIDEO_UHD120,
	IS_DVFS_SN_FRONT_SINGLE_FASTAE,
	IS_DVFS_SN_FRONT_SINGLE_VT,
	/* pip scenarios */
	IS_DVFS_SN_PIP_DUAL_PHOTO,
	IS_DVFS_SN_PIP_DUAL_CAPTURE,
	IS_DVFS_SN_PIP_DUAL_VIDEO_FHD30,
	IS_DVFS_SN_PIP_DUAL_VIDEO_UHD30,
	/* triple scenarios */
	IS_DVFS_SN_TRIPLE_PHOTO,
	IS_DVFS_SN_TRIPLE_VIDEO_FHD30,
	IS_DVFS_SN_TRIPLE_VIDEO_UHD30,
	IS_DVFS_SN_TRIPLE_VIDEO_FHD60,
	IS_DVFS_SN_TRIPLE_VIDEO_UHD60,
	IS_DVFS_SN_TRIPLE_CAPTURE,
	/* sensor only scenarios */
	IS_DVFS_SN_SENSOR_ONLY_REAR_SINGLE,
	IS_DVFS_SN_SENSOR_ONLY_FRONT,
	IS_DVFS_SN_THROTTLING,
	IS_DVFS_SN_MAX,
	IS_DVFS_SN_END,
};

/* Tick count to get some time margin for DVFS scenario transition while streaming. */
#define KEEP_FRAME_TICK_DEFAULT (5)
#define IS_DVFS_CAPTURE_TICK (KEEP_FRAME_TICK_DEFAULT + 3)
#define IS_DVFS_RECURSIVE_TICK KEEP_FRAME_TICK_DEFAULT
#define IS_DVFS_DUAL_CAPTURE_TICK (2 * IS_DVFS_CAPTURE_TICK)

/* for DT parsing */
static struct is_dvfs_dt_t is_dvfs_dt_arr[IS_DVFS_SN_END] = {
	{
		.parse_scenario_nm = "default_",
		.scenario_id = IS_DVFS_SN_DEFAULT,
		.keep_frame_tick = -1,
	},
	/* rear sensor scenarios */
	{
		.parse_scenario_nm = "rear_single_photo_",
		.scenario_id = IS_DVFS_SN_REAR_SINGLE_PHOTO,
		.keep_frame_tick = -1,
	},
	{
		.parse_scenario_nm = "rear_single_photo_full_",
		.scenario_id = IS_DVFS_SN_REAR_SINGLE_PHOTO_FULL,
		.keep_frame_tick = -1,
	},
	{
		.parse_scenario_nm = "rear_single_capture_",
		.scenario_id = IS_DVFS_SN_REAR_SINGLE_CAPTURE,
		.keep_frame_tick = IS_DVFS_CAPTURE_TICK,
	},
	{
		.parse_scenario_nm = "rear_single_video_fhd30_",
		.scenario_id = IS_DVFS_SN_REAR_SINGLE_VIDEO_FHD30,
		.keep_frame_tick = -1,
	},
	{
		.parse_scenario_nm = "rear_single_video_fhd30_supersteady_",
		.scenario_id = IS_DVFS_SN_REAR_SINGLE_VIDEO_FHD30_SUPERSTEADY,
		.keep_frame_tick = -1,
	},
	{
		.parse_scenario_nm = "rear_single_video_fhd30_recursive_",
		.scenario_id = IS_DVFS_SN_REAR_SINGLE_VIDEO_FHD30_RECURSIVE,
		.keep_frame_tick = -1,
	},
	{
		.parse_scenario_nm = "rear_single_video_fhd60_",
		.scenario_id = IS_DVFS_SN_REAR_SINGLE_VIDEO_FHD60,
		.keep_frame_tick = -1,
	},
	{
		.parse_scenario_nm = "rear_single_video_fhd60_supersteady_",
		.scenario_id = IS_DVFS_SN_REAR_SINGLE_VIDEO_FHD60_SUPERSTEADY,
		.keep_frame_tick = -1,
	},
	{
		.parse_scenario_nm = "rear_single_video_fhd120_",
		.scenario_id = IS_DVFS_SN_REAR_SINGLE_VIDEO_FHD120,
		.keep_frame_tick = -1,
	},
	{
		.parse_scenario_nm = "rear_single_video_fhd240_",
		.scenario_id = IS_DVFS_SN_REAR_SINGLE_VIDEO_FHD240,
		.keep_frame_tick = -1,
	},
	{
		.parse_scenario_nm = "rear_single_video_fhd480_",
		.scenario_id = IS_DVFS_SN_REAR_SINGLE_VIDEO_FHD480,
		.keep_frame_tick = -1,
	},
	{
		.parse_scenario_nm = "rear_single_video_uhd30_",
		.scenario_id = IS_DVFS_SN_REAR_SINGLE_VIDEO_UHD30,
		.keep_frame_tick = -1,
	},
	{
		.parse_scenario_nm = "rear_single_video_uhd30_supersteady_",
		.scenario_id = IS_DVFS_SN_REAR_SINGLE_VIDEO_UHD30_SUPERSTEADY,
		.keep_frame_tick = -1,
	},
	{
		.parse_scenario_nm = "rear_single_video_uhd30_recursive_",
		.scenario_id = IS_DVFS_SN_REAR_SINGLE_VIDEO_UHD30_RECURSIVE,
		.keep_frame_tick = -1,
	},
	{
		.parse_scenario_nm = "rear_single_video_uhd60_",
		.scenario_id = IS_DVFS_SN_REAR_SINGLE_VIDEO_UHD60,
		.keep_frame_tick = -1,
	},
	{
		.parse_scenario_nm = "rear_single_video_uhd60_supersteady_",
		.scenario_id = IS_DVFS_SN_REAR_SINGLE_VIDEO_UHD60_SUPERSTEADY,
		.keep_frame_tick = -1,
	},
	{
		.parse_scenario_nm = "rear_single_video_uhd60_psm_",
		.scenario_id = IS_DVFS_SN_REAR_SINGLE_VIDEO_UHD60_PSM,
		.keep_frame_tick = -1,
	},
	{
		.parse_scenario_nm = "rear_single_video_uhd120_",
		.scenario_id = IS_DVFS_SN_REAR_SINGLE_VIDEO_UHD120,
		.keep_frame_tick = -1,
	},
	{
		.parse_scenario_nm = "rear_single_video_8k24_",
		.scenario_id = IS_DVFS_SN_REAR_SINGLE_VIDEO_8K24,
		.keep_frame_tick = -1,
	},
	{
		.parse_scenario_nm = "rear_single_video_8k24_hf_",
		.scenario_id = IS_DVFS_SN_REAR_SINGLE_VIDEO_8K24_HF,
		.keep_frame_tick = -1,
	},
	{
		.parse_scenario_nm = "rear_single_video_8k30_",
		.scenario_id = IS_DVFS_SN_REAR_SINGLE_VIDEO_8K30,
		.keep_frame_tick = -1,
	},
	{
		.parse_scenario_nm = "rear_single_video_8k30_hf_",
		.scenario_id = IS_DVFS_SN_REAR_SINGLE_VIDEO_8K30_HF,
		.keep_frame_tick = -1,
	},
	{
		.parse_scenario_nm = "rear_single_remosaic_photo_",
		.scenario_id = IS_DVFS_SN_REAR_SINGLE_REMOSAIC_PHOTO,
		.keep_frame_tick = -1,
	},
	{
		.parse_scenario_nm = "rear_single_remosaic_capture_",
		.scenario_id = IS_DVFS_SN_REAR_SINGLE_REMOSAIC_CAPTURE,
		.keep_frame_tick = IS_DVFS_CAPTURE_TICK,
	},
	{
		.parse_scenario_nm = "rear_single_fastae_",
		.scenario_id = IS_DVFS_SN_REAR_SINGLE_FASTAE,
		.keep_frame_tick = -1,
	},
	{
		.parse_scenario_nm = "rear_single_ssm_",
		.scenario_id = IS_DVFS_SN_REAR_SINGLE_SSM,
		.keep_frame_tick = -1,
	},
	{
		.parse_scenario_nm = "rear_single_vt_",
		.scenario_id = IS_DVFS_SN_REAR_SINGLE_VT,
		.keep_frame_tick = -1,
	},
	/* dual sensor scenarios */
	{
		.parse_scenario_nm = "rear_dual_photo_",
		.scenario_id = IS_DVFS_SN_REAR_DUAL_PHOTO,
		.keep_frame_tick = -1,
	},
	{
		.parse_scenario_nm = "rear_dual_capture_",
		.scenario_id = IS_DVFS_SN_REAR_DUAL_CAPTURE,
		.keep_frame_tick = IS_DVFS_DUAL_CAPTURE_TICK,
	},
	{
		.parse_scenario_nm = "rear_dual_video_fhd30_",
		.scenario_id = IS_DVFS_SN_REAR_DUAL_VIDEO_FHD30,
		.keep_frame_tick = -1,
	},
	{
		.parse_scenario_nm = "rear_dual_video_uhd30_",
		.scenario_id = IS_DVFS_SN_REAR_DUAL_VIDEO_UHD30,
		.keep_frame_tick = -1,
	},
	{
		.parse_scenario_nm = "rear_dual_video_fhd60_",
		.scenario_id = IS_DVFS_SN_REAR_DUAL_VIDEO_FHD60,
		.keep_frame_tick = -1,
	},
	{
		.parse_scenario_nm = "rear_dual_video_uhd60_",
		.scenario_id = IS_DVFS_SN_REAR_DUAL_VIDEO_UHD60,
		.keep_frame_tick = -1,
	},
	/* front sensor scenarios */
	{
		.parse_scenario_nm = "front_single_photo_",
		.scenario_id = IS_DVFS_SN_FRONT_SINGLE_PHOTO,
		.keep_frame_tick = -1,
	},
	{
		.parse_scenario_nm = "front_single_photo_full_",
		.scenario_id = IS_DVFS_SN_FRONT_SINGLE_PHOTO_FULL,
		.keep_frame_tick = -1,
	},
	{
		.parse_scenario_nm = "front_single_capture_",
		.scenario_id = IS_DVFS_SN_FRONT_SINGLE_CAPTURE,
		.keep_frame_tick = IS_DVFS_CAPTURE_TICK,
	},
	{
		.parse_scenario_nm = "front_single_video_fhd30_",
		.scenario_id = IS_DVFS_SN_FRONT_SINGLE_VIDEO_FHD30,
		.keep_frame_tick = -1,
	},
	{
		.parse_scenario_nm = "front_single_video_fhd30_recursive_",
		.scenario_id = IS_DVFS_SN_FRONT_SINGLE_VIDEO_FHD30_RECURSIVE,
		.keep_frame_tick = -1,
	},
	{
		.parse_scenario_nm = "front_single_video_fhd60_",
		.scenario_id = IS_DVFS_SN_FRONT_SINGLE_VIDEO_FHD60,
		.keep_frame_tick = -1,
	},
	{
		.parse_scenario_nm = "front_single_video_fhd120_",
		.scenario_id = IS_DVFS_SN_FRONT_SINGLE_VIDEO_FHD120,
		.keep_frame_tick = -1,
	},
	{
		.parse_scenario_nm = "front_single_video_uhd30_",
		.scenario_id = IS_DVFS_SN_FRONT_SINGLE_VIDEO_UHD30,
		.keep_frame_tick = -1,
	},
	{
		.parse_scenario_nm = "front_single_video_uhd30_recursive_",
		.scenario_id = IS_DVFS_SN_FRONT_SINGLE_VIDEO_UHD30_RECURSIVE,
		.keep_frame_tick = -1,
	},
	{
		.parse_scenario_nm = "front_single_video_uhd60_",
		.scenario_id = IS_DVFS_SN_FRONT_SINGLE_VIDEO_UHD60,
		.keep_frame_tick = -1,
	},
	{
		.parse_scenario_nm = "front_single_video_uhd120_",
		.scenario_id = IS_DVFS_SN_FRONT_SINGLE_VIDEO_UHD120,
		.keep_frame_tick = -1,
	},
	{
		.parse_scenario_nm = "front_single_fastae_",
		.scenario_id = IS_DVFS_SN_FRONT_SINGLE_FASTAE,
		.keep_frame_tick = -1,
	},
	{
		.parse_scenario_nm = "front_single_vt_",
		.scenario_id = IS_DVFS_SN_FRONT_SINGLE_VT,
		.keep_frame_tick = -1,
	},
	/* pip scenarios */
	{
		.parse_scenario_nm = "pip_dual_photo_",
		.scenario_id = IS_DVFS_SN_PIP_DUAL_PHOTO,
		.keep_frame_tick = -1,
	},
	{
		.parse_scenario_nm = "pip_dual_capture_",
		.scenario_id = IS_DVFS_SN_PIP_DUAL_CAPTURE,
		.keep_frame_tick = IS_DVFS_CAPTURE_TICK,
	},
	{
		.parse_scenario_nm = "pip_dual_video_fhd30_",
		.scenario_id = IS_DVFS_SN_PIP_DUAL_VIDEO_FHD30,
		.keep_frame_tick = -1,
	},
	{
		.parse_scenario_nm = "pip_dual_video_uhd30_",
		.scenario_id = IS_DVFS_SN_PIP_DUAL_VIDEO_UHD30,
		.keep_frame_tick = -1,
	},
	/* triple scenarios */
	{
		.parse_scenario_nm = "triple_photo_",
		.scenario_id = IS_DVFS_SN_TRIPLE_PHOTO,
		.keep_frame_tick = -1,
	},
	{
		.parse_scenario_nm = "triple_video_fhd30_",
		.scenario_id = IS_DVFS_SN_TRIPLE_VIDEO_FHD30,
		.keep_frame_tick = -1,
	},
	{
		.parse_scenario_nm = "triple_video_uhd30_",
		.scenario_id = IS_DVFS_SN_TRIPLE_VIDEO_UHD30,
		.keep_frame_tick = -1,
	},
	{
		.parse_scenario_nm = "triple_video_fhd60_",
		.scenario_id = IS_DVFS_SN_TRIPLE_VIDEO_FHD60,
		.keep_frame_tick = -1,
	},
	{
		.parse_scenario_nm = "triple_video_uhd60_",
		.scenario_id = IS_DVFS_SN_TRIPLE_VIDEO_UHD60,
		.keep_frame_tick = -1,
	},
	{
		.parse_scenario_nm = "triple_capture_",
		.scenario_id = IS_DVFS_SN_TRIPLE_CAPTURE,
		.keep_frame_tick = IS_DVFS_CAPTURE_TICK,
	},
	/* sensor only scenarios */
	{
		.parse_scenario_nm = "sensor_only_rear_single_",
		.scenario_id = IS_DVFS_SN_SENSOR_ONLY_REAR_SINGLE,
		.keep_frame_tick = -1,
	},
	{
		.parse_scenario_nm = "sensor_only_front_",
		.scenario_id = IS_DVFS_SN_SENSOR_ONLY_FRONT,
		.keep_frame_tick = -1,
	},
	{
		.parse_scenario_nm = "throttling_",
		.scenario_id = IS_DVFS_SN_THROTTLING,
		.keep_frame_tick = -1,
	},
	/* max scenario */
	{
		.parse_scenario_nm = "max_",
		.scenario_id = IS_DVFS_SN_MAX,
		.keep_frame_tick = -1,
	},
};

#endif /* IS_DVFS_CONFIG_H */
