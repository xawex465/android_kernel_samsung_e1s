// SPDX-License-Identifier: GPL-2.0
/*
 * Samsung Exynos SoC series Pablo driver
 *
 * Exynos Pablo DVFS v2 functions
 *
 * Copyright (c) 2022 Samsung Electronics Co., Ltd
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <dt-bindings/camera/exynos_is_dt.h>

#include "pablo-dvfs.h"
#include "is-core.h"
#include "is-hw-dvfs.h"
#include "is-param.h"
#include "is-resourcemgr.h"
#include "exynos-is.h"

static const char *str_face[IS_DVFS_FACE_END + 1] = {
	"REAR",
	"FRONT",
	"PIP",
	"INVALID",
};

static const char *str_num[IS_DVFS_NUM_END + 1] = {
	"SINGLE",
	"DUAL",
	"TRIPLE",
	"INVALID",
};

static const char *str_sensor[IS_DVFS_SENSOR_END + 1] = {
	"NORMAL",
	"FASTAE",
	"REMOSAIC",
	"VIDEOHDR",
	"SSM",
	"VT",
	"SECURE",
	"INVALID",
};

static const char *str_mode[IS_DVFS_MODE_END + 1] = {
	"PHOTO",
	"CAPTURE",
	"VIDEO",
	"SENSOR_ONLY",
	"INVALID",
};

static const char *str_resol[IS_DVFS_RESOL_END + 1] = {
	"FHD",
	"UHD",
	"8K",
	"FULL",
	"INVALID",
};

static const char *str_fps[IS_DVFS_FPS_END + 1] = {
	"24",
	"30",
	"60",
	"120",
	"240",
	"480",
	"INVALID",
};

static int is_hw_dvfs_get_face(
	struct is_device_ischain *device, struct is_dvfs_scenario_param *param)
{
	if (param->rear_face && param->front_face)
		return IS_DVFS_FACE_PIP;
	else if (param->rear_face)
		return IS_DVFS_FACE_REAR;
	else if (param->front_face)
		return IS_DVFS_FACE_FRONT;
	else
		return -EINVAL;
}

static int is_hw_dvfs_get_num(
	struct is_device_ischain *device, struct is_dvfs_scenario_param *param)
{
	unsigned int num = is_get_bit_count(param->sensor_active_map);

	if (num == 1)
		return IS_DVFS_NUM_SINGLE;
	else if (num == 2)
		return IS_DVFS_NUM_DUAL;
	else if (num == 3)
		return IS_DVFS_NUM_TRIPLE;
	else
		return -EINVAL;
}

static int is_hw_dvfs_get_sensor(
	struct is_device_ischain *device, struct is_dvfs_scenario_param *param)
{
	int vendor = (param->dvfs_scenario >> IS_DVFS_SCENARIO_VENDOR_SHIFT)
			& IS_DVFS_SCENARIO_VENDOR_MASK;

	if (param->sensor_mode == IS_SPECIAL_MODE_FASTAE)
		return IS_DVFS_SENSOR_FASTAE;

	if (param->sensor_mode == IS_SPECIAL_MODE_REMOSAIC)
		return IS_DVFS_SENSOR_REMOSAIC;

	if (vendor == IS_DVFS_SCENARIO_VENDOR_SSM)
		return IS_DVFS_SENSOR_SSM;

	if (vendor == IS_DVFS_SCENARIO_VENDOR_LOW_POWER || vendor == IS_DVFS_SCENARIO_VENDOR_VT ||
		vendor == IS_DVFS_SCENARIO_VENDOR_SENSING_CAMERA)
		return IS_DVFS_SENSOR_VT;

	if (param->secure == IS_SCENARIO_SECURE)
		return IS_DVFS_SENSOR_SECURE;

	return IS_DVFS_SENSOR_NORMAL;
}

static int is_hw_dvfs_get_mode(
	struct is_device_ischain *device, int flag_capture, struct is_dvfs_scenario_param *param)
{
	int common = param->dvfs_scenario & IS_DVFS_SCENARIO_COMMON_MODE_MASK;

	if (param->sensor_only)
		return IS_DVFS_MODE_SENSOR_ONLY;

	if (flag_capture)
		return IS_DVFS_MODE_CAPTURE;

	if (common == IS_DVFS_SCENARIO_COMMON_MODE_PHOTO)
		return IS_DVFS_MODE_PHOTO;
	else if (common == IS_DVFS_SCENARIO_COMMON_MODE_VIDEO)
		return IS_DVFS_MODE_VIDEO;
	else
		return -EINVAL;
}

static int is_hw_dvfs_get_resol(
	struct is_device_ischain *device, struct is_dvfs_scenario_param *param)
{
	struct is_resourcemgr *resourcemgr;
	struct is_dvfs_ctrl *dvfs_ctrl;
	int width, height, resol = 0;

	resourcemgr = device->resourcemgr;
	dvfs_ctrl = &resourcemgr->dvfs_ctrl;

	width = dvfs_ctrl->dvfs_rec_size & 0xffff;
	height = dvfs_ctrl->dvfs_rec_size >> IS_DVFS_SCENARIO_HEIGHT_SHIFT;
	mdbg_dvfs(1, "[DVFS] width: %d, height: %d\n", device, width, height);
	resol = width * height;

	if (param->mode == IS_DVFS_MODE_PHOTO && param->scen == IS_SCENARIO_FULL_SIZE)
		return IS_DVFS_RESOL_FULL;
	else if (resol < IS_DVFS_RESOL_FHD_TH)
		return IS_DVFS_RESOL_FHD;
	else if (resol < IS_DVFS_RESOL_UHD_TH)
		return IS_DVFS_RESOL_UHD;
	else if (resol < IS_DVFS_RESOL_8K_TH)
		return IS_DVFS_RESOL_8K;
	else
		return -EINVAL;
}

static int is_hw_dvfs_get_fps(
	struct is_device_ischain *device, struct is_dvfs_scenario_param *param)
{
	if (param->sensor_fps <= 24)
		return IS_DVFS_FPS_24;
	else if (param->sensor_fps <= 30)
		return IS_DVFS_FPS_30;
	else if (param->sensor_fps <= 60)
		return IS_DVFS_FPS_60;
	else if (param->sensor_fps <= 120)
		return IS_DVFS_FPS_120;
	else if (param->sensor_fps <= 240)
		return IS_DVFS_FPS_240;
	else if (param->sensor_fps <= 480)
		return IS_DVFS_FPS_480;
	else
		return -EINVAL;
}

static void is_hw_dvfs_init_face_mask(struct is_device_ischain *device,
	struct is_dvfs_scenario_param *param)
{
	int pos;

	pos = IS_DVFS_SENSOR_POSITION_WIDE;
	param->wide_mask = (pos < 0) ? 0 : (1 << pos);
	pos = IS_DVFS_SENSOR_POSITION_TELE;
	param->tele_mask = (pos < 0) ? 0 : (1 << pos);
	pos = IS_DVFS_SENSOR_POSITION_TELE2;
	param->tele2_mask = (pos < 0) ? 0 : (1 << pos);
	pos = IS_DVFS_SENSOR_POSITION_ULTRAWIDE;
	param->ultrawide_mask = (pos < 0) ? 0 : (1 << pos);
	pos = IS_DVFS_SENSOR_POSITION_MACRO;
	param->macro_mask = (pos < 0) ? 0 : (1 << pos);
	param->rear_mask = param->wide_mask | param->tele_mask | param->tele2_mask |
				param->ultrawide_mask | param->macro_mask;

	pos = IS_DVFS_SENSOR_POSITION_FRONT;
	param->front_sensor_mask = (pos < 0) ? 0 : (1 << pos);
	param->front_mask = param->front_sensor_mask;

	mdbg_dvfs(1, "[DVFS] %s() rear mask: 0x%x, front mask: 0x%x\n", device, __func__,
		  param->rear_mask, param->front_mask);
}

static int is_hw_dvfs_get_hf(struct is_device_ischain *device,
	struct is_dvfs_scenario_param *param)
{
	struct param_mcs_output *mcs_output;
	struct param_dma_output *rgbp_dma_hf_output;
	struct param_otf_output *rgbp_otf_hf_output;

	/* only wide single */
	if (!(param->num == IS_DVFS_NUM_SINGLE))
		return 0;

	mcs_output = is_itf_g_param(device, NULL, PARAM_MCS_OUTPUT5);
	rgbp_dma_hf_output = is_itf_g_param(device, NULL, PARAM_RGBP_HF);
	rgbp_otf_hf_output = is_itf_g_param(device, NULL, PARAM_RGBP_OTF_OUTPUT_HF);

	mdbg_dvfs(1, "[DVFS] %s() mcs_dma(%d) rgbp_dma(%d) rgbp_otf(%d)\n", device,
		__func__, mcs_output->dma_cmd,
		rgbp_dma_hf_output->cmd, rgbp_otf_hf_output->cmd);

	if (mcs_output->dma_cmd == DMA_OUTPUT_COMMAND_ENABLE		||
		rgbp_dma_hf_output->cmd == DMA_OUTPUT_COMMAND_ENABLE	||
		rgbp_otf_hf_output->cmd == OTF_OUTPUT_COMMAND_ENABLE)
		return 1;
	else
		return 0;
}

int is_hw_dvfs_get_scenario_param(struct is_device_ischain *device,
	int flag_capture, struct is_dvfs_scenario_param *param)
{
	struct is_device_sensor *sensor_device;
	struct is_resourcemgr *resourcemgr;
	struct is_dvfs_ctrl *dvfs_ctrl;
	struct is_device_sensor *ids;
	u32 device_id;

	sensor_device = device->sensor;
	resourcemgr = sensor_device->resourcemgr;
	dvfs_ctrl = &resourcemgr->dvfs_ctrl;

	is_hw_dvfs_init_face_mask(device, param);

	param->sensor_active_map = 0;
	param->sensor_mode = 0;
	param->sensor_fps = 0;
	param->secure = 0;
	for (device_id = 0; device_id < IS_SENSOR_COUNT; device_id++) {
		ids = is_get_sensor_device(device_id);
		if (!ids || !test_bit(IS_SENSOR_START, &ids->state))
			continue;

		if (ids->position > SENSOR_POSITION_MAX) {
			minfo("[DVFS]Invalid sensor position(%d)\n", ids, ids->position);
			continue;
		}

		param->sensor_active_map |= BIT(ids->position);
		param->sensor_only = test_bit(IS_SENSOR_ONLY, &ids->state);
		if (ids->cfg->special_mode)
			param->sensor_mode = ids->cfg->special_mode;
		if (param->sensor_fps < is_sensor_g_framerate(ids))
			param->sensor_fps = is_sensor_g_framerate(ids);
		if (ids->ex_scenario)
			param->secure = ids->ex_scenario;
		mdbg_dvfs(2, "[DVFS] %s() sensor_mode: %d, fps: %d, secure: %d\n", device, __func__,
			param->sensor_mode, param->sensor_fps, param->secure);
	}

	/* All sensor stop at close sqeunce */
	if (!param->sensor_active_map)
		return -EINVAL;

	param->rear_face = param->sensor_active_map & param->rear_mask;
	param->front_face = param->sensor_active_map & param->front_mask;
	mdbg_dvfs(1, "[DVFS] %s() sensor_active_map: 0x%x, rear: 0x%x, front: 0x%x\n", device,
		  __func__, param->sensor_active_map, param->rear_face, param->front_face);

	param->setfile = (device->setfile & IS_SETFILE_MASK);
	param->scen = (device->setfile & IS_SCENARIO_MASK) >> IS_SCENARIO_SHIFT;
	param->dvfs_scenario = dvfs_ctrl->dvfs_scenario;
	mdbg_dvfs(
		1,
		"[DVFS] %s() sensor_mode: %d, fps: %d, setfile: %d, scen: %d, dvfs_scenario: %x, secure: %d\n",
		device, __func__, param->sensor_mode, param->sensor_fps, param->setfile,
		param->scen, param->dvfs_scenario, param->secure);

	param->face = is_hw_dvfs_get_face(device, param);
	param->num = is_hw_dvfs_get_num(device, param);
	param->sensor = is_hw_dvfs_get_sensor(device, param);
	param->hf = is_hw_dvfs_get_hf(device, param);

	if (param->face > IS_DVFS_FACE_END || param->face < 0)
		param->face = IS_DVFS_FACE_END;
	if (param->num > IS_DVFS_NUM_END || param->num < 0)
		param->num = IS_DVFS_NUM_END;
	if (param->sensor > IS_DVFS_SENSOR_END || param->sensor < 0)
		param->sensor = IS_DVFS_SENSOR_END;

	param->recursive = dvfs_ctrl->rnr_mode.rnr;
	param->mode = is_hw_dvfs_get_mode(device, flag_capture, param);
	param->resol = is_hw_dvfs_get_resol(device, param);
	param->fps = is_hw_dvfs_get_fps(device, param);

	if (param->mode > IS_DVFS_MODE_END || param->mode < 0)
		param->mode = IS_DVFS_MODE_END;
	if (param->resol > IS_DVFS_RESOL_END || param->resol < 0)
		param->resol = IS_DVFS_RESOL_END;
	if (param->fps > IS_DVFS_FPS_END || param->fps < 0)
		param->fps = IS_DVFS_FPS_END;

	return 0;
}
KUNIT_EXPORT_SYMBOL(is_hw_dvfs_get_scenario_param);

static int is_hw_dvfs_get_rear_single_scenario(
	struct is_device_ischain *device, struct is_dvfs_scenario_param *param)
{
	int vendor = (param->dvfs_scenario >> IS_DVFS_SCENARIO_VENDOR_SHIFT) & IS_DVFS_SCENARIO_VENDOR_MASK;

	mdbg_dvfs(1, "[DVFS] %s() mode: %s, resol: %s, fps: %s\n", device, __func__,
		  str_mode[param->mode], str_resol[param->resol], str_fps[param->fps]);

	switch (param->mode) {
	case IS_DVFS_MODE_PHOTO:
		if (param->resol == IS_DVFS_RESOL_FULL)
			return IS_DVFS_SN_REAR_SINGLE_PHOTO_FULL;
		else
			return IS_DVFS_SN_REAR_SINGLE_PHOTO;
	case IS_DVFS_MODE_CAPTURE:
		return IS_DVFS_SN_REAR_SINGLE_CAPTURE;
	case IS_DVFS_MODE_VIDEO:
		switch (param->resol) {
		case IS_DVFS_RESOL_FHD:
			switch (param->fps) {
			case IS_DVFS_FPS_24:
			case IS_DVFS_FPS_30:
				if (param->recursive)
					return IS_DVFS_SN_REAR_SINGLE_VIDEO_FHD30_RECURSIVE;
				if (vendor == IS_DVFS_SCENARIO_VENDOR_SUPER_STEADY)
					return IS_DVFS_SN_REAR_SINGLE_VIDEO_FHD30_SUPERSTEADY;
				return IS_DVFS_SN_REAR_SINGLE_VIDEO_FHD30;
			case IS_DVFS_FPS_60:
				if (vendor == IS_DVFS_SCENARIO_VENDOR_SUPER_STEADY)
					return IS_DVFS_SN_REAR_SINGLE_VIDEO_FHD60_SUPERSTEADY;
				return IS_DVFS_SN_REAR_SINGLE_VIDEO_FHD60;
			case IS_DVFS_FPS_120:
				return IS_DVFS_SN_REAR_SINGLE_VIDEO_FHD120;
			case IS_DVFS_FPS_240:
				return IS_DVFS_SN_REAR_SINGLE_VIDEO_FHD240;
			case IS_DVFS_FPS_480:
				return IS_DVFS_SN_REAR_SINGLE_VIDEO_FHD480;
			default:
				goto dvfs_err;
			}
		case IS_DVFS_RESOL_UHD:
			switch (param->fps) {
			case IS_DVFS_FPS_24:
				return IS_DVFS_SN_REAR_SINGLE_VIDEO_UHD30;
			case IS_DVFS_FPS_30:
				if (param->recursive)
					return IS_DVFS_SN_REAR_SINGLE_VIDEO_UHD30_RECURSIVE;
				if (vendor == IS_DVFS_SCENARIO_VENDOR_SUPER_STEADY)
					return IS_DVFS_SN_REAR_SINGLE_VIDEO_UHD30_SUPERSTEADY;
				return IS_DVFS_SN_REAR_SINGLE_VIDEO_UHD30;
			case IS_DVFS_FPS_60:
				if (vendor == IS_DVFS_SCENARIO_VENDOR_SUPER_STEADY)
					return IS_DVFS_SN_REAR_SINGLE_VIDEO_UHD60_SUPERSTEADY;
				if (vendor == IS_DVFS_SCENARIO_VENDOR_PSM)
					return IS_DVFS_SN_REAR_SINGLE_VIDEO_UHD60_PSM;
				return IS_DVFS_SN_REAR_SINGLE_VIDEO_UHD60;
			case IS_DVFS_FPS_120:
				return IS_DVFS_SN_REAR_SINGLE_VIDEO_UHD120;
			default:
				goto dvfs_err;
			}
		case IS_DVFS_RESOL_8K:
			switch (param->fps) {
			case IS_DVFS_FPS_24:
				switch (param->hf) {
				case 0:
					return IS_DVFS_SN_REAR_SINGLE_VIDEO_8K24;
				case 1:
					return IS_DVFS_SN_REAR_SINGLE_VIDEO_8K24_HF;
				default:
					goto dvfs_err;
				}
			case IS_DVFS_FPS_30:
				switch (param->hf) {
				case 0:
					return IS_DVFS_SN_REAR_SINGLE_VIDEO_8K30;
				case 1:
					return IS_DVFS_SN_REAR_SINGLE_VIDEO_8K30_HF;
				default:
					goto dvfs_err;
				}
			default:
				goto dvfs_err;
			}
		default:
			goto dvfs_err;
		}
	case IS_DVFS_MODE_SENSOR_ONLY:
		return IS_DVFS_SN_SENSOR_ONLY_REAR_SINGLE;
	default:
		goto dvfs_err;
	}

dvfs_err:
	merr("[DVFS] %s fails. (mode: %s, resol: %s, fps: %s) not supported.", device, __func__,
	     str_mode[param->mode], str_resol[param->resol], str_fps[param->fps]);
	return -EINVAL;
}

static int is_hw_dvfs_get_rear_single_remosaic_scenario(
	struct is_device_ischain *device, struct is_dvfs_scenario_param *param)
{
	mdbg_dvfs(1, "[DVFS] %s() mode: %s, resol: %s, fps: %s\n", device, __func__,
		  str_mode[param->mode], str_resol[param->resol], str_fps[param->fps]);

	switch (param->mode) {
	case IS_DVFS_MODE_PHOTO:
		return IS_DVFS_SN_REAR_SINGLE_REMOSAIC_PHOTO;
	case IS_DVFS_MODE_CAPTURE:
		return IS_DVFS_SN_REAR_SINGLE_REMOSAIC_CAPTURE;
	case IS_DVFS_MODE_SENSOR_ONLY:
		return IS_DVFS_SN_SENSOR_ONLY_REAR_SINGLE;
	default:
		goto dvfs_err;
	}

dvfs_err:
	merr("[DVFS] %s fails. (mode: %s, resol: %s, fps: %s) not supported.", device, __func__,
	     str_mode[param->mode], str_resol[param->resol], str_fps[param->fps]);
	return -EINVAL;
}

static int is_hw_dvfs_get_rear_dual_scenario(
	struct is_device_ischain *device, struct is_dvfs_scenario_param *param)
{
	mdbg_dvfs(1, "[DVFS] %s() mode: %s, resol: %s, fps: %s\n", device, __func__,
		  str_mode[param->mode], str_resol[param->resol], str_fps[param->fps]);

	switch (param->mode) {
	case IS_DVFS_MODE_PHOTO:
		return IS_DVFS_SN_REAR_DUAL_PHOTO;
	case IS_DVFS_MODE_CAPTURE:
		return IS_DVFS_SN_REAR_DUAL_CAPTURE;
	case IS_DVFS_MODE_VIDEO:
		switch (param->resol) {
		case IS_DVFS_RESOL_FHD:
			switch (param->fps) {
			case IS_DVFS_FPS_24:
			case IS_DVFS_FPS_30:
				return IS_DVFS_SN_REAR_DUAL_VIDEO_FHD30;
			case IS_DVFS_FPS_60:
				return IS_DVFS_SN_REAR_DUAL_VIDEO_FHD60;
			default:
				goto dvfs_err;
			}
		case IS_DVFS_RESOL_UHD:
			switch (param->fps) {
			case IS_DVFS_FPS_24:
			case IS_DVFS_FPS_30:
				return IS_DVFS_SN_REAR_DUAL_VIDEO_UHD30;
			case IS_DVFS_FPS_60:
				return IS_DVFS_SN_REAR_DUAL_VIDEO_UHD60;
			default:
				goto dvfs_err;
			}
		default:
			goto dvfs_err;
		}
	default:
		goto dvfs_err;
	}

dvfs_err:
	merr("[DVFS] %s fails. (mode: %s, resol: %s, fps: %s) not supported.", device, __func__,
	     str_mode[param->mode], str_resol[param->resol], str_fps[param->fps]);
	return -EINVAL;
}

static int is_hw_dvfs_get_front_single_front_scenario(
	struct is_device_ischain *device, struct is_dvfs_scenario_param *param)
{
	mdbg_dvfs(1, "[DVFS] %s() mode: %s, resol: %s, fps: %s\n", device, __func__,
		  str_mode[param->mode], str_resol[param->resol], str_fps[param->fps]);

	switch (param->mode) {
	case IS_DVFS_MODE_PHOTO:
		if (param->resol == IS_DVFS_RESOL_FULL)
			return IS_DVFS_SN_FRONT_SINGLE_PHOTO_FULL;
		else
			return IS_DVFS_SN_FRONT_SINGLE_PHOTO;
	case IS_DVFS_MODE_CAPTURE:
		return IS_DVFS_SN_FRONT_SINGLE_CAPTURE;
	case IS_DVFS_MODE_VIDEO:
		switch (param->resol) {
		case IS_DVFS_RESOL_FHD:
			switch (param->fps) {
			case IS_DVFS_FPS_24:
			case IS_DVFS_FPS_30:
				if (param->recursive)
					return IS_DVFS_SN_FRONT_SINGLE_VIDEO_FHD30_RECURSIVE;
				return IS_DVFS_SN_FRONT_SINGLE_VIDEO_FHD30;
			case IS_DVFS_FPS_60:
				return IS_DVFS_SN_FRONT_SINGLE_VIDEO_FHD60;
			case IS_DVFS_FPS_120:
				return IS_DVFS_SN_FRONT_SINGLE_VIDEO_FHD120;
			default:
				goto dvfs_err;
			}
		case IS_DVFS_RESOL_UHD:
			switch (param->fps) {
			case IS_DVFS_FPS_24:
			case IS_DVFS_FPS_30:
				if (param->recursive)
					return IS_DVFS_SN_FRONT_SINGLE_VIDEO_UHD30_RECURSIVE;
				return IS_DVFS_SN_FRONT_SINGLE_VIDEO_UHD30;
			case IS_DVFS_FPS_60:
				return IS_DVFS_SN_FRONT_SINGLE_VIDEO_UHD60;
			case IS_DVFS_FPS_120:
				return IS_DVFS_SN_FRONT_SINGLE_VIDEO_UHD120;
			default:
				goto dvfs_err;
			}
		default:
			goto dvfs_err;
		}
	case IS_DVFS_MODE_SENSOR_ONLY:
		return IS_DVFS_SN_SENSOR_ONLY_FRONT;
	default:
		goto dvfs_err;
	}

dvfs_err:
	merr("[DVFS] %s fails. (mode: %s, resol: %s, fps: %s) not supported.", device, __func__,
	     str_mode[param->mode], str_resol[param->resol], str_fps[param->fps]);
	return -EINVAL;
}

static int is_hw_dvfs_get_pip_dual_scenario(
	struct is_device_ischain *device, struct is_dvfs_scenario_param *param)
{
	mdbg_dvfs(1, "[DVFS] %s() mode: %s, resol: %s, fps: %s\n", device, __func__,
		  str_mode[param->mode], str_resol[param->resol], str_fps[param->fps]);

	switch (param->mode) {
	case IS_DVFS_MODE_PHOTO:
		return IS_DVFS_SN_PIP_DUAL_PHOTO;
	case IS_DVFS_MODE_CAPTURE:
		return IS_DVFS_SN_PIP_DUAL_CAPTURE;
	case IS_DVFS_MODE_VIDEO:
		switch (param->resol) {
		case IS_DVFS_RESOL_FHD:
			return IS_DVFS_SN_PIP_DUAL_VIDEO_FHD30;
		case IS_DVFS_RESOL_UHD:
			return IS_DVFS_SN_PIP_DUAL_VIDEO_UHD30;
		default:
			goto dvfs_err;
		}
	default:
		goto dvfs_err;
	}

dvfs_err:
	merr("[DVFS] %s fails. (mode: %s, resol: %s, fps: %s) not supported.", device, __func__,
	     str_mode[param->mode], str_resol[param->resol], str_fps[param->fps]);
	return -EINVAL;
}

static int is_hw_dvfs_get_triple_scenario(
	struct is_device_ischain *device, struct is_dvfs_scenario_param *param)
{
	mdbg_dvfs(1, "[DVFS] %s() mode: %s, resol: %s, fps: %s\n", device, __func__,
		  str_mode[param->mode], str_resol[param->resol], str_fps[param->fps]);

	switch (param->mode) {
	case IS_DVFS_MODE_PHOTO:
		return IS_DVFS_SN_TRIPLE_PHOTO;
	case IS_DVFS_MODE_CAPTURE:
		return IS_DVFS_SN_TRIPLE_CAPTURE;
	case IS_DVFS_MODE_VIDEO:
		switch (param->resol) {
		case IS_DVFS_RESOL_FHD:
			switch (param->fps) {
			case IS_DVFS_FPS_24:
			case IS_DVFS_FPS_30:
				return IS_DVFS_SN_TRIPLE_VIDEO_FHD30;
			case IS_DVFS_FPS_60:
				return IS_DVFS_SN_TRIPLE_VIDEO_FHD60;
			default:
				goto dvfs_err;
			}
		case IS_DVFS_RESOL_UHD:
			switch (param->fps) {
			case IS_DVFS_FPS_24:
			case IS_DVFS_FPS_30:
				return IS_DVFS_SN_TRIPLE_VIDEO_UHD30;
			case IS_DVFS_FPS_60:
				return IS_DVFS_SN_TRIPLE_VIDEO_UHD60;
			default:
				goto dvfs_err;
			}
		default:
			goto dvfs_err;
		}
	default:
		goto dvfs_err;
	}

dvfs_err:
	merr("[DVFS] %s fails. (mode: %s, resol: %s, fps: %s) not supported.", device, __func__,
	     str_mode[param->mode], str_resol[param->resol], str_fps[param->fps]);
	return -EINVAL;
}

int is_hw_dvfs_get_scenario(struct is_device_ischain *device, int flag_capture)
{
	struct is_dvfs_scenario_param param;
	int vendor;

	if (!IS_ENABLED(ENABLE_DVFS))
		return IS_DVFS_SN_DEFAULT;

	if (is_hw_dvfs_get_scenario_param(device, flag_capture, &param))
		return IS_DVFS_SN_DEFAULT;

	minfo("[DVFS] scenario - [%s_%s_%s_%s_%s%s]\n", device, str_face[param.face],
		str_num[param.num], str_sensor[param.sensor], str_mode[param.mode],
		str_resol[param.resol], str_fps[param.fps]);

	vendor = (param.dvfs_scenario >> IS_DVFS_SCENARIO_VENDOR_SHIFT) &
		 IS_DVFS_SCENARIO_VENDOR_MASK;

	switch (param.num) {
	case IS_DVFS_NUM_SINGLE:
		switch (param.face) {
		case IS_DVFS_FACE_REAR:
			switch (param.sensor) {
			case IS_DVFS_SENSOR_NORMAL:
				return is_hw_dvfs_get_rear_single_scenario(device, &param);
			case IS_DVFS_SENSOR_FASTAE:
				return IS_DVFS_SN_REAR_SINGLE_FASTAE;
			case IS_DVFS_SENSOR_REMOSAIC:
				return is_hw_dvfs_get_rear_single_remosaic_scenario(device, &param);
			case IS_DVFS_SENSOR_SSM:
				return IS_DVFS_SN_REAR_SINGLE_SSM;
			case IS_DVFS_SENSOR_VT:
				return IS_DVFS_SN_REAR_SINGLE_VT;
			default:
				goto dvfs_err;
			}
		case IS_DVFS_FACE_FRONT:
			switch (param.sensor) {
			case IS_DVFS_SENSOR_NORMAL:
				return is_hw_dvfs_get_front_single_front_scenario(device, &param);
			case IS_DVFS_SENSOR_FASTAE:
				return IS_DVFS_SN_FRONT_SINGLE_FASTAE;
			case IS_DVFS_SENSOR_SECURE:
				return IS_DVFS_SN_FRONT_SINGLE_PHOTO;
			case IS_DVFS_SENSOR_VT:
				return IS_DVFS_SN_FRONT_SINGLE_VT;
			default:
				goto dvfs_err;
			}
		default:
			goto dvfs_err;
		}
	case IS_DVFS_NUM_DUAL:
		switch (param.face) {
		case IS_DVFS_FACE_REAR:
			if (vendor == IS_DVFS_SCENARIO_VENDOR_PIP)
				return is_hw_dvfs_get_pip_dual_scenario(device, &param);
			return is_hw_dvfs_get_rear_dual_scenario(device, &param);
		case IS_DVFS_FACE_PIP:
			return is_hw_dvfs_get_pip_dual_scenario(device, &param);
		default:
			goto dvfs_err;
		}
		break;
	case IS_DVFS_NUM_TRIPLE:
		return is_hw_dvfs_get_triple_scenario(device, &param);
	default:
		goto dvfs_err;
	}

dvfs_err:
	merr("[DVFS] %s fails.", device, __func__);
	return -EINVAL;
}
KUNIT_EXPORT_SYMBOL(is_hw_dvfs_get_scenario);

static struct v4l2_fract sw_margin = {
	.numerator = 100,
	.denominator = 70,
};

/* CSIS, CSTAT */
static inline u32 get_mbps(u32 mipi_speed, u32 lanes, u32 cphy)
{
	u32 ratio = cphy ? 7 : 16;

	return mipi_speed * lanes * 16 / ratio;
}

static inline u32 is_hw_dvfs_get_csis_clk(u32 mbps, u32 bpc)
{
	return mbps / bpc;
}

static inline bool is_hw_dvfs_get_packed(u32 hw_format, u32 pixel_size, u32 memory_bitwidth)
{
	bool is_pack;

	is_pack = (hw_format == DMA_INOUT_FORMAT_BAYER_PACKED
			|| hw_format == DMA_INOUT_FORMAT_YUV422_PACKED) ? true : false;
	is_pack |= (pixel_size == memory_bitwidth) ? true : false;

	return is_pack;
}

static u32 is_hw_dvfs_get_csis(struct is_sensor_cfg *cfg, struct is_device_sensor *ids)
{
	struct is_subdev *dma_subdev;
	struct is_device_csi *csi;
	struct sensor_dma_output *dma_output;
	struct is_fmt *format;
	u32 lanes, cphy, bit_per_cycle;
	u32 clk_csis, max_clk_csis = 0;
	u32 link_vc, idx_wdma, wdma_vc, outbpp, out_bitwidth, hw_format;
	bool pack;
	u32 mbps;

	lanes = cfg->lanes + 1;
	cphy = ids->pdata->use_cphy;
	mbps = get_mbps(cfg->mipi_speed, lanes, cphy);

	csi = (struct is_device_csi *)v4l2_get_subdevdata(ids->subdev_csi);

	for (idx_wdma = 0; idx_wdma < cfg->dma_num; idx_wdma++) {
		for (wdma_vc = DMA_VIRTUAL_CH_0; wdma_vc < DMA_VIRTUAL_CH_MAX; wdma_vc++) {
			if (cfg->output[idx_wdma][wdma_vc].hwformat == HW_FORMAT_UNKNOWN)
				continue;

			link_vc = cfg->link_vc[idx_wdma][wdma_vc];
			dma_output = &ids->dma_output[link_vc];
			format = &dma_output->fmt;
			if (format->hw_format) {
				/* for LVN */
				outbpp = format->bitsperpixel[0];
				out_bitwidth = format->hw_bitwidth;
				hw_format = format->hw_format;
			} else {
				dma_subdev = csi->dma_subdev[idx_wdma][wdma_vc];
				if (!dma_subdev)
					continue;

				if (test_bit(IS_SUBDEV_INTERNAL_USE, &dma_subdev->state)) {
					outbpp = csi_hw_g_bpp(
						cfg->output[idx_wdma][wdma_vc].hwformat);
					out_bitwidth = dma_subdev->memory_bitwidth;
					hw_format = DMA_INOUT_FORMAT_MAX;
				} else {
					continue;
				}
			}

			pack = is_hw_dvfs_get_packed(hw_format, outbpp, out_bitwidth);
			bit_per_cycle = CHECK_POTF_EN(cfg->output[idx_wdma][wdma_vc].extformat) ?
						IS_DVFS_POTF_BIT :
						outbpp * IS_DVFS_OTF_PPC;

			/* a. check LINK CLK */
			clk_csis = is_hw_dvfs_get_csis_clk(mbps, bit_per_cycle);

			max_clk_csis = MAX(max_clk_csis, clk_csis);

			if (!pack && CHECK_POTF_EN(cfg->output[idx_wdma][wdma_vc].extformat)) {
				/* b. check pOTF unpack factor */
				clk_csis = clk_csis * out_bitwidth / outbpp;
				max_clk_csis = MAX(max_clk_csis, clk_csis);

				/* c. check pOTF unpack limitation(70%) */
				bit_per_cycle = bit_per_cycle * 70 / 100;
				clk_csis = is_hw_dvfs_get_csis_clk(mbps, bit_per_cycle);
				max_clk_csis = MAX(max_clk_csis, clk_csis);
			}
		}
	}
	return max_clk_csis;
}

static u32 _get_csis_lv(struct is_dvfs_ctrl *dvfs_ctrl)
{
	struct is_device_sensor *ids;
	struct is_sensor_cfg *cfg;
	u32 device_id;
	u32 clk_csis = 0, lv_csis, clk, lv, t_clk;

	for (device_id = 0; device_id < IS_SENSOR_COUNT; device_id++) {
		ids = is_get_sensor_device(device_id);
		if (!test_bit(IS_SENSOR_START, &ids->state))
			continue;

		cfg = ids->cfg;
		if (!cfg) {
			mwarn("[DVFS] sensor_cfg is NULL.", ids);
			continue;
		}

		if (cfg->dvfs_lv_csis < IS_DVFS_LV_END)
			return cfg->dvfs_lv_csis;

		/* CSIS CLK */
		t_clk = is_hw_dvfs_get_csis(cfg, ids);
		if (t_clk)
			clk_csis += t_clk;
	}

	clk_csis = GET_CLK_MARGIN(clk_csis, IS_DVFS_CSIS_MARGIN);

	lv_csis = 0;
	if (clk_csis) {
		for (lv = 0; lv < IS_DVFS_LV_END; lv++) {
			clk = dvfs_ctrl->dvfs_info.qos_tb[IS_DVFS_CSIS][lv][IS_DVFS_VAL_FRQ];

			if (clk >= clk_csis)
				lv_csis = lv;
			else
				break;
		}
	} else {
		warn("[DVFS] There is no active stream.");
	}

	dbg_dvfs(1, "CSIS clk(%d) lv(%d)\n", clk_csis, lv_csis);

	return lv_csis;
}

/* BYRP, RGBP, MCSC, GDC */
static u32 _get_cam_lv(struct is_dvfs_ctrl *dvfs_ctrl)
{
	struct is_device_sensor *ids;
	struct is_device_ischain *idi;
	struct is_sensor_cfg *cfg;
	struct is_group *child;
	struct is_subdev *ldr;
	u32 clk_cam = 0, lv_cam = 0, clk, lv;
	u32 w = 0, h = 0;
	u32 max_fps, device_id;
	u32 ppc = IS_DVFS_M2M_PPC;

	for (device_id = 0; device_id < IS_SENSOR_COUNT; device_id++) {
		ids = is_get_sensor_device(device_id);
		if (!test_bit(IS_SENSOR_FRONT_START, &ids->state))
			continue;

		cfg = ids->cfg;
		max_fps = cfg->max_fps;
		idi = ids->ischain;

		if (!idi)
			continue;

		child = idi->group[GROUP_SLOT_BYRP];
		while (child) {
			ldr = &child->leader;
			w = MAX(w, ldr->input.width);
			h = MAX(h, ldr->input.height);

			child = child->child;
		}

		clk_cam += w * h * max_fps / ppc / MHZ
			* sw_margin.numerator / sw_margin.denominator;
	}

	for (lv = 0; lv < IS_DVFS_LV_END; lv++) {
		clk = dvfs_ctrl->dvfs_info.qos_tb[IS_DVFS_CAM][lv][IS_DVFS_VAL_FRQ];

		if (clk >= clk_cam)
			lv_cam = lv;
		else
			break;
	}

	dbg_dvfs(1, "clk(cam:%d MHz) lv(%d)\n", clk_cam, lv_cam);

	return lv_cam;
}

/* MCFP, YUVP */
static u32 _get_isp_lv(struct is_dvfs_ctrl *dvfs_ctrl)
{
	struct is_device_sensor *ids;
	struct is_device_ischain *idi;
	struct is_sensor_cfg *cfg;
	struct is_group *child;
	struct is_subdev *ldr;
	u32 clk_isp = 0, lv_isp = 0, clk, lv;
	u32 w = 0, h = 0;
	u32 max_fps, device_id;
	u32 ppc = IS_DVFS_M2M_PPC;

	for (device_id = 0; device_id < IS_SENSOR_COUNT; device_id++) {
		ids = is_get_sensor_device(device_id);
		if (!test_bit(IS_SENSOR_FRONT_START, &ids->state))
			continue;

		cfg = ids->cfg;
		max_fps = cfg->max_fps;
		idi = ids->ischain;

		if (!idi)
			continue;

		child = idi->group[GROUP_SLOT_MCFP];
		while (child) {
			ldr = &child->leader;
			w = MAX(w, ldr->input.width);
			h = MAX(h, ldr->input.height);

			child = child->child;
		}

		clk_isp += w * h * max_fps / ppc / MHZ
			* sw_margin.numerator / sw_margin.denominator;
	}

	for (lv = 0; lv < IS_DVFS_LV_END; lv++) {
		clk = dvfs_ctrl->dvfs_info.qos_tb[IS_DVFS_ISP][lv][IS_DVFS_VAL_FRQ];

		if (clk >= clk_isp)
			lv_isp = lv;
		else
			break;
	}

	dbg_dvfs(1, "clk(isp:%d MHz) lv(%d)\n", clk_isp, lv_isp);

	return lv_isp;
}

/* LME */
static u32 _get_int_cam_lv(struct is_dvfs_ctrl *dvfs_ctrl)
{
	struct is_device_sensor *ids;
	struct is_device_ischain *idi;
	struct is_sensor_cfg *cfg;
	struct is_group *child;
	struct is_subdev *ldr;
	u32 clk_int_cam = 0, lv_int_cam = 0, clk, lv;
	u32 w = 0, h = 0;
	u32 max_fps, device_id;

	for (device_id = 0; device_id < IS_SENSOR_COUNT; device_id++) {
		ids = is_get_sensor_device(device_id);
		if (!test_bit(IS_SENSOR_FRONT_START, &ids->state))
			continue;

		cfg = ids->cfg;
		max_fps = cfg->max_fps;
		idi = ids->ischain;

		if (!idi)
			continue;

		child = idi->group[GROUP_SLOT_LME];
		while (child) {
			ldr = &child->leader;
			w = MAX(w, ldr->input.width);
			h = MAX(h, ldr->input.height);

			child = child->child;
		}

		/* 0.45 PPC */
		clk_int_cam += w * h * max_fps / 45 * 100 / MHZ
			* sw_margin.numerator / sw_margin.denominator;
	}

	for (lv = 0; lv < IS_DVFS_LV_END; lv++) {
		clk = dvfs_ctrl->dvfs_info.qos_tb[IS_DVFS_INT_CAM][lv][IS_DVFS_VAL_FRQ];

		if (clk >= clk_int_cam)
			lv_int_cam = lv;
		else
			break;
	}

	dbg_dvfs(1, "clk(int_cam:%d MHz) lv(%d)\n", clk_int_cam, lv_int_cam);

	return lv_int_cam;
}

u32 is_hw_dvfs_get_lv(struct is_dvfs_ctrl *dvfs_ctrl, u32 type)
{
	u32 lv;

	if (!dvfs_ctrl) {
		warn("[DVFS] dvfs_ctrl is null.");
		return 0;
	}

	switch (type) {
	case IS_DVFS_CSIS:
		lv = _get_csis_lv(dvfs_ctrl);
		break;
	case IS_DVFS_CAM:
		lv = _get_cam_lv(dvfs_ctrl);
		break;
	case IS_DVFS_ISP:
		lv = _get_isp_lv(dvfs_ctrl);
		break;
	case IS_DVFS_INT_CAM:
		lv = _get_int_cam_lv(dvfs_ctrl);
		break;
	default:
		return 0;
	}

	return lv;
}
KUNIT_EXPORT_SYMBOL(is_hw_dvfs_get_lv);

bool is_hw_dvfs_restore_static(struct is_device_ischain *device)
{
	struct is_resourcemgr *resourcemgr;
	struct is_dvfs_ctrl *dvfs_ctrl;
	struct is_dvfs_scenario_ctrl *dynamic_ctrl;
	struct is_dvfs_rnr_mode *rnr_mode;
	struct is_dvfs_psm_mode *psm_mode;
	int scenario_id;

	resourcemgr = device->resourcemgr;
	dvfs_ctrl = &resourcemgr->dvfs_ctrl;
	dynamic_ctrl = dvfs_ctrl->dynamic_ctrl;
	rnr_mode = &dvfs_ctrl->rnr_mode;
	psm_mode = &dvfs_ctrl->psm_mode;

	if (dynamic_ctrl->cur_frame_tick == 0)
		return true;

	if (rnr_mode->changed && !rnr_mode->rnr) {
		rnr_mode->changed = 0;
		dynamic_ctrl->cur_frame_tick = KEEP_FRAME_TICK_ITERATION;
		dynamic_ctrl->cur_scenario_id = -1;
		scenario_id = is_hw_dvfs_get_scenario(device, IS_DVFS_STATIC);
		is_dvfs_sel_static(dvfs_ctrl, scenario_id);
		mdbg_dvfs(1, "[DVFS] recursiveNr off after %d tick\n", device,
			dynamic_ctrl->cur_frame_tick);
	}

	if (psm_mode->changed && !psm_mode->psm) {
		psm_mode->changed = 0;
		dynamic_ctrl->cur_frame_tick = -1;
		dynamic_ctrl->cur_scenario_id = -1;
		scenario_id = is_hw_dvfs_get_scenario(device, IS_DVFS_STATIC);
		is_dvfs_sel_static(dvfs_ctrl, scenario_id);
		mdbg_dvfs(1, "[DVFS] psm off\n", device);
		return true;
	}

	return false;
}
KUNIT_EXPORT_SYMBOL(is_hw_dvfs_restore_static);

void is_hw_dvfs_get_qos_throughput(u32 *qos_thput)
{
	qos_thput[IS_DVFS_INT_CAM] = PM_QOS_INTCAM_THROUGHPUT;
	qos_thput[IS_DVFS_TNR] = 0;
	qos_thput[IS_DVFS_CSIS] = PM_QOS_CSIS_THROUGHPUT;
	qos_thput[IS_DVFS_ISP] = PM_QOS_ISP_THROUGHPUT;
	qos_thput[IS_DVFS_INT] = PM_QOS_DEVICE_THROUGHPUT;
	qos_thput[IS_DVFS_MIF] = PM_QOS_BUS_THROUGHPUT;
	qos_thput[IS_DVFS_CAM] = PM_QOS_CAM_THROUGHPUT;
	qos_thput[IS_DVFS_M2M] = 0;
	qos_thput[IS_DVFS_ICPU] = PM_QOS_ICPU_THROUGHPUT;
}
KUNIT_EXPORT_SYMBOL(is_hw_dvfs_get_qos_throughput);

bool is_hw_dvfs_get_fast_launch(struct is_dvfs_ctrl *dvfs_ctrl)
{
	int vendor = (dvfs_ctrl->dvfs_scenario >> IS_DVFS_SCENARIO_VENDOR_SHIFT) &
		     IS_DVFS_SCENARIO_VENDOR_MASK;

	if (vendor == IS_DVFS_SCENARIO_VENDOR_SENSING_CAMERA)
		return false;

	return true;
}
KUNIT_EXPORT_SYMBOL(is_hw_dvfs_get_fast_launch);

#if IS_ENABLED(CONFIG_PABLO_KUNIT_TEST)
static struct pablo_kunit_hw_dvfs_function hw_dvfs_func = {
	.get_rear_single_scenario = is_hw_dvfs_get_rear_single_scenario,
};

struct pablo_kunit_hw_dvfs_function *pablo_kunit_get_hw_dvfs_func(void)
{
	return &hw_dvfs_func;
}
KUNIT_EXPORT_SYMBOL(pablo_kunit_get_hw_dvfs_func);
#endif
