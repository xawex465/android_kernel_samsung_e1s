// SPDX-License-Identifier: GPL-2.0
/*
 * Samsung Exynos SoC series Pablo IS driver
 *
 * Exynos Pablo IS CSI HW control functions
 *
 * Copyright (c) 2022 Samsung Electronics Co., Ltd
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <linux/module.h>
#include <linux/delay.h>
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/platform_device.h>
#include <linux/io.h>

#include "pablo-hw-api-common.h"
#include "pablo-smc.h"
#include "is-config.h"
#include "is-type.h"
#include "is-hw-api-csi.h"
#include "is-hw-csi-v6_0.h"
#include "is-device-sensor.h"
#include "is-core.h"
#include "is-hw-common-dma.h"

#define ENABLE_CSIS_DMA_DBG_CNT	1
#define IGNORE_CSIS_DMA_FIFO_FULL 1

/*
 * [00]: OTF0 VC0~3
 * ...
 * [08]: OTF0 VC2~5
 * ...
 */
#define DMA_MUX_VAL_BASE_LC_0_3		0x0
#define DMA_MUX_VAL_BASE_LC_2_5		0x8

u32 csi_hw_get_version(u32 __iomem *base_reg)
{
	return is_hw_get_reg(base_reg, &csi_regs[CSIS_R_CSIS_VERSION]);
}

u32 csi_hw_s_fcount(u32 __iomem *base_reg, u32 vc, u32 count)
{
	is_hw_set_reg(base_reg, &csi_regs[CSIS_R_FRM_CNT_CH0 + vc], count);

	return is_hw_get_reg(base_reg, &csi_regs[CSIS_R_FRM_CNT_CH0 + vc]);
}

u32 csi_hw_g_fcount(u32 __iomem *base_reg, u32 vc)
{
	return is_hw_get_reg(base_reg, &csi_regs[CSIS_R_FRM_CNT_CH0 + vc]);
}

int csi_hw_reset(u32 __iomem *base_reg)
{
	int ret = 0;
	u32 retry = 10;

	is_hw_set_field(base_reg, &csi_regs[CSIS_R_CSIS_CMN_CTRL],
			&csi_fields[CSIS_F_SW_RESET], 1);

	while (--retry) {
		udelay(10);
		if (is_hw_get_field(base_reg, &csi_regs[CSIS_R_CSIS_CMN_CTRL],
			&csi_fields[CSIS_F_SW_RESET]) != 1)
			break;
	}

	/* Q-channel enable */
#ifdef ENABLE_HWACG_CONTROL
	is_hw_set_field(base_reg, &csi_regs[CSIS_R_CSIS_CMN_CTRL],
			&csi_fields[CSIS_F_QCHANNEL_EN], 1);
#endif

	if (!retry) {
		err("reset is fail(%d)", retry);
		ret = -EINVAL;
	}

	return ret;
}

int csi_hw_fifo_reset(u32 __iomem *base_reg, u32 ch)
{
	return 0;
}

int csi_hw_s_lane(u32 __iomem *base_reg, u32 lanes, u32 use_cphy)
{
	u32 lane;

	/* lane number */
	is_hw_set_field(base_reg, &csi_regs[CSIS_R_CSIS_CMN_CTRL],
			&csi_fields[CSIS_F_LANE_NUMBER], lanes);

	if (use_cphy) {
		/* TO DO: set valid lane values for Cphy */
		switch (lanes) {
		case CSI_DATA_LANES_1:
			/* lane 0 */
			lane = (0x3);
			break;
		case CSI_DATA_LANES_2:
			/* lane 0 + lane 1 */
			lane = (0x3);
			break;
		case CSI_DATA_LANES_3:
			/* lane 0 + lane 1 + lane 2 */
			lane = (0xF);
			break;
		default:
			err("lanes is invalid(%d)", lanes);
			lane = (0xF);
			break;
		}
	} else {
		switch (lanes) {
		case CSI_DATA_LANES_1:
			/* lane 0 */
			lane = (0x1);
			break;
		case CSI_DATA_LANES_2:
			/* lane 0 + lane 1 */
			lane = (0x3);
			break;
		case CSI_DATA_LANES_3:
			/* lane 0 + lane 1 + lane 2 */
			lane = (0x7);
			break;
		case CSI_DATA_LANES_4:
			/* lane 0 + lane 1 + lane 2 + lane 3 */
			lane = (0xF);
			break;
		default:
			err("lanes is invalid(%d)", lanes);
			lane = (0xF);
			break;
		}
	}

	is_hw_set_field(base_reg, &csi_regs[CSIS_R_PHY_CMN_CTRL],
			&csi_fields[CSIS_F_ENABLE_DAT], lane);

	return 0;
}

int csi_hw_s_control(u32 __iomem *base_reg, u32 id, u32 value)
{
	switch (id) {
	case CSIS_CTRL_INTERLEAVE_MODE:
		/* interleave mode */
		is_hw_set_field(base_reg, &csi_regs[CSIS_R_CSIS_CMN_CTRL],
				&csi_fields[CSIS_F_INTERLEAVE_MODE], value);
		break;
	case CSIS_CTRL_LINE_RATIO:
		/* line irq ratio */
		is_hw_set_field(base_reg, &csi_regs[CSIS_R_LINE_INTR_CH0],
				&csi_fields[CSIS_F_LINE_INTR_CHX], value);
		break;
	case CSIS_CTRL_DMA_ABORT_REQ:
		/* dma abort req */
		is_hw_set_field(base_reg, &csi_dmax_regs[CSIS_DMAX_R_CMN_CTRL],
				&csi_dmax_fields[CSIS_DMAX_F_DMA_ABORT_REQ], value);
		break;
	case CSIS_CTRL_ENABLE_LINE_IRQ:
		if (!value) {
			is_hw_set_field(base_reg, &csi_regs[CSIS_R_CSIS_INT_MSK1],
					&csi_fields[CSIS_F_MSK_LINE_END], 0x0);
		} else {
			is_hw_set_field(base_reg, &csi_regs[CSIS_R_CSIS_INT_MSK1],
					&csi_fields[CSIS_F_MSK_LINE_END], 0x1);
			is_hw_set_field(base_reg, &csi_regs[CSIS_R_LINE_END_MSK],
					&csi_fields[CSIS_F_MSK_LINE_END_CH], value);
		}
		break;
	case CSIS_CTRL_PIXEL_ALIGN_MODE:
		is_hw_set_field(base_reg, &csi_regs[CSIS_R_DBG_OPTION_SUITE],
				&csi_fields[CSIS_F_DBG_PIXEL_ALIGN_EN], value);
		break;
	case CSIS_CTRL_LRTE:
		is_hw_set_field(base_reg, &csi_regs[CSIS_R_LRTE_CONFIG],
				&csi_fields[CSIS_F_EPD_EN], value);
		break;
	case CSIS_CTRL_DESCRAMBLE:
		is_hw_set_field(base_reg, &csi_regs[CSIS_R_CSIS_CMN_CTRL],
				&csi_fields[CSIS_F_DESCRAMBLE_EN], value);
		break;
	default:
		err("control id is invalid(%d)", id);
		break;
	}

	return 0;
}

int csi_hw_s_config(u32 __iomem *base_reg,
	u32 vc, struct is_vci_config *config, u32 width, u32 height, bool potf)
{
	u32 val;
	u32 parallel = CSIS_PARALLEL_MODE_OFF;
	u32 pixel_mode = CSIS_PIXEL_MODE_OCTA;

	if (vc >= CSI_VIRTUAL_CH_MAX) {
		err("invalid vc(%d)", vc);
		return -EINVAL;
	}

	/* The HW guided configuration for POTF */
	if (potf || CHECK_POTF_EN(config->extformat))
		parallel = CSIS_PARALLEL_MODE_128BIT;

	val = is_hw_get_reg(base_reg, &csi_regs[CSIS_R_ISP_CONFIG_CH0 + (vc * 3)]);
	val = is_hw_set_field_value(val, &csi_fields[CSIS_F_VIRTUAL_CHANNEL], config->map);
	val = is_hw_set_field_value(val, &csi_fields[CSIS_F_DATAFORMAT], config->hwformat);
	val = is_hw_set_field_value(val, &csi_fields[CSIS_F_DECOMP_EN],
		config->hwformat >> DECOMP_EN_BIT);
	val = is_hw_set_field_value(val, &csi_fields[CSIS_F_DECOMP_PREDICT],
		config->hwformat >> DECOMP_PREDICT_BIT);
	val = is_hw_set_field_value(val, &csi_fields[CSIS_F_PARALLEL_MODE], parallel);
	val = is_hw_set_field_value(val, &csi_fields[CSIS_F_PIXEL_MODE], pixel_mode);
	is_hw_set_reg(base_reg, &csi_regs[CSIS_R_ISP_CONFIG_CH0 + (vc * 3)], val);

	val = is_hw_get_reg(base_reg, &csi_regs[CSIS_R_ISP_RESOL_CH0 + (vc * 3)]);
	val = is_hw_set_field_value(val, &csi_fields[CSIS_F_VRESOL], height);
	val = is_hw_set_field_value(val, &csi_fields[CSIS_F_HRESOL], width);
	is_hw_set_reg(base_reg, &csi_regs[CSIS_R_ISP_RESOL_CH0 + (vc * 3)], val);

	if (config->hwformat & (1 << DECOMP_EN_BIT))
		is_hw_set_field(base_reg, &csi_regs[CSIS_R_ISP_SYNC_CH0 + (vc * 3)],
			&csi_fields[CSIS_F_HSYNC_LINTV], 7);

	return 0;
}

static void csi_hw_s_sbwc_ctrl(u32 __iomem *ctl_reg,
		u32 sbwc_en, u32 sbwc_type, u32 comp_64b_align)
{
	u32 val;

	val = is_hw_get_reg(ctl_reg, &csi_dmax_regs[CSIS_DMAX_R_SBWC_CTRL]);
	val = is_hw_set_field_value(val, &csi_dmax_fields[CSIS_DMAX_F_SBWC_ENABLE],
				sbwc_type);

	if (sbwc_en)
		val = is_hw_set_field_value(val, &csi_dmax_fields[CSIS_DMAX_F_SBWC_64B_ZERO_PAD_EN],
					comp_64b_align);

	is_hw_set_reg(ctl_reg, &csi_dmax_regs[CSIS_DMAX_R_SBWC_CTRL], val);
}

int csi_hw_s_config_dma(u32 __iomem *ctl_reg, u32 __iomem *vc_reg,
		u32 vc, struct is_frame_cfg *cfg, u32 hwformat, u32 *stride)
{
	int ret = 0;
	u32 val;
	u32 dim, hw_format, dma_format;
	u32 h_stride;
	u32 pixel_size, bitwidth;
	u32 sbwc_type, comp_64b_align, sbwc_en;

	if (vc >= DMA_VIRTUAL_CH_MAX) {
		err("invalid vc(%d)", vc);
		ret = -EINVAL;
		goto p_err;
	}

	if (!cfg->format) {
		err("cfg->format is null");
		ret = -EINVAL;
		goto p_err;
	}

	pixel_size = cfg->format->bitsperpixel[0];
	sbwc_type = cfg->format->sbwc_type;

	switch (cfg->format->pixelformat) {
	case V4L2_PIX_FMT_SGRBG8:
	case V4L2_PIX_FMT_SBGGR8:
		dim = CSIS_REG_DMA_1D_DMA;
		hw_format = DMA_INOUT_FORMAT_BAYER_PACKED;
		break;
	case V4L2_PIX_FMT_SBGGR10:
	case V4L2_PIX_FMT_SBGGR12:
	case V4L2_PIX_FMT_SBGGR16:
		dim = CSIS_REG_DMA_2D_DMA;
		hw_format = DMA_INOUT_FORMAT_BAYER;
		break;
	case V4L2_PIX_FMT_SBGGR10P:
	case V4L2_PIX_FMT_SBGGR12P:
	case V4L2_PIX_FMT_PRIV_MAGIC:
		dim = CSIS_REG_DMA_2D_DMA;
		hw_format = DMA_INOUT_FORMAT_BAYER_PACKED;
		break;
	default:
		dim = CSIS_REG_DMA_2D_DMA;
		hw_format = DMA_INOUT_FORMAT_BAYER;
		break;
	}

	switch (hwformat) {
	case HW_FORMAT_RAW8:
	case HW_FORMAT_RAW8_SDC:
	case HW_FORMAT_RAW10_SDC:
		if (hw_format == DMA_INOUT_FORMAT_BAYER_PACKED) {
			dma_format = CSIS_DMA_FMT_U8BIT_PACK;
			bitwidth = cfg->format->hw_bitwidth;
		} else {
			dma_format = CSIS_DMA_FMT_U8BIT_UNPACK_MSB_ZERO;
			bitwidth = 16;
		}
		break;
	case HW_FORMAT_RAW10:
	case HW_FORMAT_RAW10_POTF:
	case HW_FORMAT_RAW10_POTF_PACK:
		if (hw_format == DMA_INOUT_FORMAT_BAYER_PACKED) {
			dma_format = CSIS_DMA_FMT_U10BIT_PACK;
			bitwidth = 10;
		} else {
			dma_format = CSIS_DMA_FMT_U10BIT_UNPACK_MSB_ZERO;
			bitwidth = 16;
		}
		break;
	case HW_FORMAT_RAW12:
		if (hw_format == DMA_INOUT_FORMAT_BAYER_PACKED) {
			dma_format = CSIS_DMA_FMT_U12BIT_PACK;
			bitwidth = 12;
		} else {
			dma_format = CSIS_DMA_FMT_U12BIT_UNPACK_MSB_ZERO;
			bitwidth = 16;
		}
		break;
	case HW_FORMAT_RAW14:
		if (hw_format == DMA_INOUT_FORMAT_BAYER_PACKED) {
			dma_format = CSIS_DMA_FMT_U14BIT_PACK;
			bitwidth = 14;
		} else {
			dma_format = CSIS_DMA_FMT_U14BIT_UNPACK_MSB_ZERO;
			bitwidth = 16;
		}
		break;
	case HW_FORMAT_USER:
	case HW_FORMAT_USER1:
	case HW_FORMAT_USER2:
	case HW_FORMAT_EMBEDDED_8BIT:
	case HW_FORMAT_EMBEDDED_8BIT_POTF:
	case HW_FORMAT_YUV420_8BIT:
	case HW_FORMAT_YUV420_10BIT:
	case HW_FORMAT_YUV422_8BIT:
	case HW_FORMAT_YUV422_10BIT:
	case HW_FORMAT_RGB565:
	case HW_FORMAT_RGB666:
	case HW_FORMAT_RGB888:
	case HW_FORMAT_RAW6:
	case HW_FORMAT_RAW7:
		dma_format = CSIS_DMA_FMT_U8BIT_PACK;
		bitwidth = 8;
		break;
	case HW_FORMAT_AND10:
		if (hw_format == DMA_INOUT_FORMAT_BAYER_PACKED) {
			dma_format = CSIS_DMA_FMT_ANDROID10;
			bitwidth = 10;
		} else {
			dma_format = CSIS_DMA_FMT_U10BIT_UNPACK_MSB_ZERO;
			bitwidth = 16;
		}
		break;
	default:
		warn("[VC%d] invalid data format (%02X)", vc, hwformat);
		ret = -EINVAL;
		goto p_err;
	}

	val = is_hw_get_reg(vc_reg, &csi_dmax_chx_regs[CSIS_DMAX_CHX_R_FMT]);
	val = is_hw_set_field_value(val, &csi_dmax_chx_fields[CSIS_DMAX_CHX_F_DIM], dim);
	val = is_hw_set_field_value(val, &csi_dmax_chx_fields[CSIS_DMAX_CHX_F_DATAFORMAT],
			dma_format);
	is_hw_set_reg(vc_reg, &csi_dmax_chx_regs[CSIS_DMAX_CHX_R_FMT], val);

	val = is_hw_get_reg(vc_reg, &csi_dmax_chx_regs[CSIS_DMAX_CHX_R_RESOL]);
	val = is_hw_set_field_value(val, &csi_dmax_chx_fields[CSIS_DMAX_CHX_F_HRESOL],
								ALIGN(cfg->width, 8));
	/* It indicates lines of VOTF transaction. */
	val = is_hw_set_field_value(val, &csi_dmax_chx_fields[CSIS_DMAX_CHX_F_VRESOL], cfg->height);
	is_hw_set_reg(vc_reg, &csi_dmax_chx_regs[CSIS_DMAX_CHX_R_RESOL], val);

	/* VC0 only has SBWC configuration */
	if (vc == CSI_VIRTUAL_CH_0) {
		if (sbwc_type)
			sbwc_type |= SBWC_BASE_ALIGN_MASK_LLC_OFF;

		sbwc_en = is_hw_dma_get_comp_sbwc_en(sbwc_type, &comp_64b_align);

		switch (sbwc_en) {
		case COMP:
			h_stride = is_hw_dma_get_header_stride(cfg->width, CSIS_COMP_BLOCK_WIDTH,
								32);
			is_hw_set_reg(ctl_reg, &csi_dmax_regs[CSIS_DMAX_R_SBWC_HEADER_STRIDE],
					h_stride);
			break;
		case COMP_LOSS:
			/*
			0: quality prioritized mode(default),
			1: normal mode
			*/
			is_hw_set_field(ctl_reg, &csi_dmax_regs[CSIS_DMAX_R_LOSSY_QUALITY_CONTROL],
					&csi_dmax_fields[CSIS_DMAX_F_LOSSY_DMA_COMP_LOSSY_QUALITY_CONTROL],
					0);
			break;
		default:
			sbwc_en = NONE;
			sbwc_type = DMA_OUTPUT_SBWC_DISABLE;
			break;
		}
		csi_hw_s_sbwc_ctrl(ctl_reg, sbwc_en, sbwc_type, comp_64b_align);
	}

	*stride = csi_hw_g_img_stride(cfg->width, pixel_size, bitwidth, sbwc_type);
	is_hw_set_reg(vc_reg, &csi_dmax_chx_regs[CSIS_DMAX_CHX_R_STRIDE], *stride);

p_err:
	return ret;
}

int csi_hw_s_irq_msk(u32 __iomem *base_reg, bool on, bool f_id_dec)
{
	u32 otf_msk;
	u32 otf_msk1;

	/* default setting */
	if (on) {
		/* base interrupt setting */
		if (f_id_dec) {
			/*
			 * If FRO mode is enable, start & end of CSIS link is not used.
			 * Instead of CSIS link interrupt, CSIS WDMA interrupt is used.
			 * So, only error interrupt is enable.
			 */
			otf_msk = CSIS_ERR_MASK0;
			otf_msk1 = CSIS_ERR_MASK1;
		} else {
			otf_msk = CSIS_IRQ_MASK0;
			otf_msk1 = CSIS_IRQ_MASK1;
		}
	} else {
		otf_msk = 0;
		otf_msk1 = 0;
	}

	is_hw_set_reg(base_reg, &csi_regs[CSIS_R_CSIS_INT_MSK0], otf_msk);
	is_hw_set_reg(base_reg, &csi_regs[CSIS_R_CSIS_INT_MSK1], otf_msk1);
	is_hw_set_reg(base_reg, &csi_regs[CSIS_R_DBG_INTR_MSK], 0x0000ff00);

	return 0;
}

static inline void csi_hw_g_err0_types(u32 __iomem *base_reg, u32 err_src0, ulong *err_id)
{
	int i;
	u32 sot_hs_err;
	u32 ovf_err;
	u32 wrong_cfg_err;
	u32 err_ecc_err;
	u32 crc_err;
	u32 err_id_err;
	u32 mal_crc_err;
	u32 inval_code_hs;
	u32 sot_sync_hs;
	u32 crc_err_cphy;
	u32 err_skew, err_deskew_over;

	/* Link error info */
	sot_sync_hs   = is_hw_get_field_value(err_src0, &csi_fields[CSIS_F_ERRSOTSYNCHS]);
	sot_hs_err    = is_hw_get_field_value(err_src0, &csi_fields[CSIS_F_ERR_SOT_HS]);
	inval_code_hs = is_hw_get_field_value(err_src0, &csi_fields[CSIS_F_RXINVALIDCODEHS]);
	err_deskew_over = is_hw_get_field_value(err_src0, &csi_fields[CSIS_F_ERR_DESKEW_OVER]);
	err_skew      = is_hw_get_field_value(err_src0, &csi_fields[CSIS_F_ERR_SKEW]);
	mal_crc_err   = is_hw_get_field_value(err_src0, &csi_fields[CSIS_F_MAL_CRC]);
	crc_err_cphy  = is_hw_get_field_value(err_src0, &csi_fields[CSIS_F_ERR_CRC_PH]);
	ovf_err       = is_hw_get_field_value(err_src0, &csi_fields[CSIS_F_ERR_OVER]);
	wrong_cfg_err = is_hw_get_field_value(err_src0, &csi_fields[CSIS_F_ERR_WRONG_CFG]);
	err_ecc_err   = is_hw_get_field_value(err_src0, &csi_fields[CSIS_F_ERR_ECC]);
	crc_err       = is_hw_get_field_value(err_src0, &csi_fields[CSIS_F_ERR_CRC]);
	err_id_err    = is_hw_get_field_value(err_src0, &csi_fields[CSIS_F_ERR_ID]);

	for (i = 0; i < CSI_DATA_LANES_MAX; i++) {
		/* Per data lane[i] */
		err_id[i] |= (BIT(i) & sot_sync_hs)	? BIT(CSIS_ERR_SOT_SYNC_HS) : 0;
		err_id[i] |= (BIT(i) & sot_hs_err)	? BIT(CSIS_ERR_SOT_VC) : 0;
		err_id[i] |= (BIT(i) & inval_code_hs)	? BIT(CSIS_ERR_INVALID_CODE_HS) : 0;
	}

	/* All data lane */
	err_id[0] |= err_deskew_over	? BIT(CSIS_ERR_DESKEW_OVER) : 0;
	err_id[0] |= err_skew		? BIT(CSIS_ERR_SKEW) : 0;
	err_id[0] |= mal_crc_err	? BIT(CSIS_ERR_MAL_CRC) : 0;
	err_id[0] |= crc_err_cphy	? BIT(CSIS_ERR_CRC_CPHY) : 0;
	err_id[0] |= ovf_err		? BIT(CSIS_ERR_OVERFLOW_VC) : 0;
	err_id[0] |= wrong_cfg_err	? BIT(CSIS_ERR_WRONG_CFG) : 0;
	err_id[0] |= err_ecc_err	? BIT(CSIS_ERR_ECC) : 0;
	err_id[0] |= crc_err		? BIT(CSIS_ERR_CRC) : 0;
	err_id[0] |= err_id_err		? BIT(CSIS_ERR_ID) : 0;
}

static inline void csi_hw_g_err1_types(u32 __iomem *base_reg, struct csis_irq_src *src)
{
	int i;

	src->dbg.lost_fs = is_hw_get_reg(base_reg, &csi_regs[CSIS_R_ERR_LOST_FS]);
	src->dbg.lost_fe = is_hw_get_reg(base_reg, &csi_regs[CSIS_R_ERR_LOST_FE]);
	src->dbg.vresol = is_hw_get_reg(base_reg, &csi_regs[CSIS_R_ERR_VRESOL]);
	src->dbg.hresol = is_hw_get_reg(base_reg, &csi_regs[CSIS_R_ERR_HRESOL]);

	/* clear */
	is_hw_set_reg(base_reg, &csi_regs[CSIS_R_ERR_LOST_FS], src->dbg.lost_fs);
	is_hw_set_reg(base_reg, &csi_regs[CSIS_R_ERR_LOST_FE], src->dbg.lost_fe);
	is_hw_set_reg(base_reg, &csi_regs[CSIS_R_ERR_VRESOL], src->dbg.vresol);
	is_hw_set_reg(base_reg, &csi_regs[CSIS_R_ERR_HRESOL], src->dbg.hresol);

	for (i = 0; i < CSI_VIRTUAL_CH_MAX; i++) {
		/* Per VC[i] */
		src->err_id[i] |= (BIT(i) & src->dbg.lost_fs) ? BIT(CSIS_ERR_LOST_FS_VC) : 0;
		src->err_id[i] |= (BIT(i) & src->dbg.lost_fe) ? BIT(CSIS_ERR_LOST_FE_VC) : 0;
		src->err_id[i] |= (BIT(i) & src->dbg.vresol) ? BIT(CSIS_ERR_VRESOL_MISMATCH) : 0;
		src->err_id[i] |= (BIT(i) & src->dbg.hresol) ? BIT(CSIS_ERR_HRESOL_MISMATCH) : 0;
	}
}

int csi_hw_g_irq_src(u32 __iomem *base_reg, struct csis_irq_src *src, bool clear)
{
	u32 otf_src0, otf_src1, dbg_src;
	u32 fs_val, fe_val, line_val;

	otf_src0 = is_hw_get_reg(base_reg, &csi_regs[CSIS_R_CSIS_INT_SRC0]);
	otf_src1 = is_hw_get_reg(base_reg, &csi_regs[CSIS_R_CSIS_INT_SRC1]);
	dbg_src  = is_hw_get_reg(base_reg, &csi_regs[CSIS_R_DBG_INTR_SRC]);

	fs_val   = is_hw_get_reg(base_reg, &csi_regs[CSIS_R_FS_INT_SRC]);
	fe_val   = is_hw_get_reg(base_reg, &csi_regs[CSIS_R_FE_INT_SRC]);
	line_val = is_hw_get_reg(base_reg, &csi_regs[CSIS_R_LINE_END]);

	if (clear) {
		if (otf_src0)
			is_hw_set_reg(base_reg, &csi_regs[CSIS_R_CSIS_INT_SRC0], otf_src0);
		if (otf_src1)
			is_hw_set_reg(base_reg, &csi_regs[CSIS_R_CSIS_INT_SRC1], otf_src1);
		if (dbg_src)
			is_hw_set_reg(base_reg, &csi_regs[CSIS_R_DBG_INTR_SRC], dbg_src);
		if (fs_val)
			is_hw_set_reg(base_reg, &csi_regs[CSIS_R_FS_INT_SRC], fs_val);
		if (fe_val)
			is_hw_set_reg(base_reg, &csi_regs[CSIS_R_FE_INT_SRC], fe_val);
		if (line_val)
			is_hw_set_reg(base_reg, &csi_regs[CSIS_R_LINE_END], line_val);
	}

	src->dbg.err_src0 = (otf_src0 & CSIS_ERR_MASK0);
	if (src->dbg.err_src0)
		csi_hw_g_err0_types(base_reg, src->dbg.err_src0, src->err_id);

	src->dbg.err_src1 = (otf_src1 & CSIS_ERR_MASK1);
	if (src->dbg.err_src1)
		csi_hw_g_err1_types(base_reg, src);

	src->otf_dbg = dbg_src;
	src->otf_start = fs_val;
	src->otf_end = fe_val;
	src->line_end = line_val;
	src->err_flag = (src->dbg.err_src0 || src->dbg.err_src1) ? true : false;

	return 0;
}

void csi_hw_dma_reset(u32 __iomem *base_reg)
{
	/*
	 * Any other registers are not controlled by 2 instance as well as DMA off,
	 * because DMA cannot be shared between 1 more instance.
	 */
	is_hw_set_reg(base_reg, &csi_dmax_chx_regs[CSIS_DMAX_CHX_R_CTRL], 0);
	is_hw_set_reg(base_reg, &csi_dmax_chx_regs[CSIS_DMAX_CHX_R_FCNTSEQ], 0);
	is_hw_set_reg(base_reg, &csi_dmax_chx_regs[CSIS_DMAX_CHX_R_FRO_FRM], 0);

	/* For debugging purpose */
	if (IS_ENABLED(ENABLE_CSIS_DMA_DBG_CNT))
		is_hw_set_reg(base_reg, &csi_dmax_chx_regs[CSIS_DMAX_CHX_R_ADDR32], 0);
}

void csi_hw_s_frameptr(u32 __iomem *base_reg, u32 vc, u32 number, bool clear)
{
	u32 frame_ptr = number;
	u32 val = is_hw_get_reg(base_reg, &csi_dmax_chx_regs[CSIS_DMAX_CHX_R_CTRL]);

	val = is_hw_set_field_value(val, &csi_dmax_chx_fields[CSIS_DMAX_CHX_F_UPDT_PTR_EN], 1);
	val = is_hw_set_field_value(val,
		&csi_dmax_chx_fields[CSIS_DMAX_CHX_F_UPDT_FRAMEPTR], frame_ptr);
	is_hw_set_reg(base_reg, &csi_dmax_chx_regs[CSIS_DMAX_CHX_R_CTRL], val);
}

u32 csi_hw_g_frameptr(u32 __iomem *base_reg, u32 vc)
{
	return is_hw_get_field(base_reg, &csi_dmax_chx_regs[CSIS_DMAX_CHX_R_ACT_CTRL],
		&csi_dmax_chx_fields[CSIS_DMAX_CHX_F_ACTIVE_FRAMEPTR]);
}

u32 csi_hw_g_dma_sbwc_type(u32 __iomem *ctl_reg)
{
	return is_hw_get_field(ctl_reg, &csi_dmax_regs[CSIS_DMAX_R_SBWC_CTRL],
				&csi_dmax_fields[CSIS_DMAX_F_SBWC_ENABLE]);
}

static const char * const sbwc_type_names[] = { "disable", "lossless", "lossy",
						"N/S", "N/S", "lossless 64B", "N/S" };
const char *csi_hw_g_dma_sbwc_name(u32 __iomem *ctl_reg)
{
	u32 type = csi_hw_g_dma_sbwc_type(ctl_reg);

	if (type < ARRAY_SIZE(sbwc_type_names))
		return sbwc_type_names[type];
	else
		return NULL;
}

void csi_hw_s_multibuf_dma_fcntseq(u32 __iomem *vc_reg, u32 buffer_num, dma_addr_t addr, bool clear)
{
	u32 val;
	unsigned long tmp;
	int i;
	int bit = 0;

	/* find buffer index */
	for (i = 0; i < buffer_num; i++) {
		val = is_hw_get_reg(vc_reg, &csi_dmax_chx_regs[CSIS_DMAX_CHX_R_ADDR1+i]);
		if (DVA_36BIT_HIGH(addr) == val) {
			bit = i;
			break;
		}
	}

	if (i == buffer_num) {
		err("Cannot find buffer addr:%pad", &addr);
		for (i = 0; i < buffer_num ; i++)
			err("[%d]:0x%x", i,
				is_hw_get_reg(vc_reg, &csi_dmax_chx_regs[CSIS_DMAX_CHX_R_ADDR1+i]));
		return;
	}

	val = is_hw_get_reg(vc_reg, &csi_dmax_chx_regs[CSIS_DMAX_CHX_R_FCNTSEQ]);
	tmp = val;
	if (clear) {
		if (!test_and_clear_bit(bit, &tmp))
			err("Already using buffer:%d FCNTSEQ:%d", bit, val);
	} else {
		if (test_and_set_bit(bit, &tmp))
			err("Already free buffer:%d FCNTSEQ:%d", bit, val);
	}
	val = tmp;
	is_hw_set_reg(vc_reg, &csi_dmax_chx_regs[CSIS_DMAX_CHX_R_FCNTSEQ], val);
}

void csi_hw_s_dma_addr(u32 __iomem *ctl_reg, u32 __iomem *vc_reg,
		u32 vc, u32 number, dma_addr_t addr)
{
	u32 val = DVA_36BIT_HIGH(addr);

	/* LSB(4bits) is automatically padded to 0 */
	is_hw_set_reg(vc_reg, &csi_dmax_chx_regs[CSIS_DMAX_CHX_R_ADDR1 + number], val);

	val = is_hw_get_reg(vc_reg, &csi_dmax_chx_regs[CSIS_DMAX_CHX_R_FCNTSEQ]);
	val |= 1 << number;
	is_hw_set_reg(vc_reg, &csi_dmax_chx_regs[CSIS_DMAX_CHX_R_FCNTSEQ], val);
}

u32 csi_hw_g_img_stride(u32 width, u32 bpp, u32 bitwidth, u32 sbwc_type)
{
	u32 stride, sbwc_en, comp_64b_align, hw_format, quality_control = 0;

	if (sbwc_type) {
		sbwc_type |= SBWC_BASE_ALIGN_MASK_LLC_OFF;
		sbwc_en = is_hw_dma_get_comp_sbwc_en(sbwc_type, &comp_64b_align);
		stride = is_hw_dma_get_payload_stride(sbwc_en,
				bpp, width, comp_64b_align,
				quality_control, CSIS_COMP_BLOCK_WIDTH, CSIS_COMP_BLOCK_HEIGHT);
	} else {
		if (bpp == bitwidth)
			hw_format = DMA_INOUT_FORMAT_BAYER_PACKED;
		else
			hw_format = DMA_INOUT_FORMAT_BAYER;

		stride = is_hw_dma_get_img_stride(bitwidth, bpp,
				hw_format, width, 32, true);
	}

	return stride;
}

void csi_hw_s_dma_header_addr(u32 __iomem *ctl_reg, u32 __iomem *vc_reg,
		u32 buf_i, dma_addr_t dva)
{
	u32 val = DVA_36BIT_HIGH(dva);

	/* LSB(4bits) is automatically padded to 0 */
	is_hw_set_reg(ctl_reg,
			&csi_dmax_regs[CSIS_DMAX_R_SBWC_HEADER_ADDR1 + buf_i], val);
}

void csi_hw_s_multibuf_dma_addr(u32 __iomem *ctl_reg, u32 __iomem *vc_reg,
		u32 vc, u32 number, dma_addr_t addr)
{
	csi_hw_s_dma_addr(ctl_reg, vc_reg, vc, number, addr);
}

#define DMA_START_DBG_CNT_POS	0
#define DMA_END_DBG_CNT_POS	8
#define DMA_ERR_DBG_CNT_POS	16
#define DMA_IRQ_DBG_CNT_POS	24
void csi_hw_s_dma_dbg_cnt(u32 __iomem *vc_reg, struct csis_dma_irq_src *src, u32 vc)
{
	u32 val, ds_cnt, de_cnt, err_cnt, irq_cnt;

	if (!IS_ENABLED(ENABLE_CSIS_DMA_DBG_CNT))
		return;

	/* Check whether the dbg_cnt register(ADDR32) is being used */
	val = is_hw_get_reg(vc_reg, &csi_dmax_chx_regs[CSIS_DMAX_CHX_R_FCNTSEQ]);
	if (val & BIT(31))
		return;

	val = is_hw_get_reg(vc_reg, &csi_dmax_chx_regs[CSIS_DMAX_CHX_R_ADDR32]);

	ds_cnt = (val >> DMA_START_DBG_CNT_POS) & GENMASK(7, 0);
	de_cnt = (val >> DMA_END_DBG_CNT_POS) & GENMASK(7, 0);
	err_cnt = (val >> DMA_ERR_DBG_CNT_POS) & GENMASK(7, 0);
	irq_cnt = (val >> DMA_IRQ_DBG_CNT_POS) & GENMASK(7, 0);

	if (src->dma_start & BIT(vc))
		ds_cnt++;

	if (src->dma_end & BIT(vc))
		de_cnt++;

	if (src->err_flag)
		err_cnt++;

	irq_cnt++;

	val = ((ds_cnt & GENMASK(7, 0)) << DMA_START_DBG_CNT_POS)
		| ((de_cnt & GENMASK(7, 0)) << DMA_END_DBG_CNT_POS)
		| ((err_cnt & GENMASK(7, 0)) << DMA_ERR_DBG_CNT_POS)
		| ((++irq_cnt & GENMASK(7, 0)) << DMA_IRQ_DBG_CNT_POS);

	is_hw_set_reg(vc_reg, &csi_dmax_chx_regs[CSIS_DMAX_CHX_R_ADDR32], val);
}

void csi_hw_s_output_dma(u32 __iomem *base_reg, u32 vc, bool enable)
{
	if (enable) {
		is_hw_set_field(base_reg, &csi_dmax_chx_regs[CSIS_DMAX_CHX_R_CTRL],
			&csi_dmax_chx_fields[CSIS_DMAX_CHX_F_SBWC_OVERLAP_AUTOFLUSH_ENABLE], 1);
		is_hw_set_field(base_reg, &csi_dmax_chx_regs[CSIS_DMAX_CHX_R_CTRL],
			&csi_dmax_chx_fields[CSIS_DMAX_CHX_F_ADDRESS_VIOLATION_AUTOFLUSH_ENABLE], 1);
		is_hw_set_field(base_reg, &csi_dmax_chx_regs[CSIS_DMAX_CHX_R_CTRL],
			&csi_dmax_chx_fields[CSIS_DMAX_CHX_F_OVERLAP_AUTOFLUSH_EN], 1);
	}

	is_hw_set_field(base_reg, &csi_dmax_chx_regs[CSIS_DMAX_CHX_R_CTRL],
		 &csi_dmax_chx_fields[CSIS_DMAX_CHX_F_DMA_ENABLE], enable);
}

bool csi_hw_g_output_dma_enable(u32 __iomem *base_reg, u32 vc)
{
	/* if DMA_DISABLE field value is 1, this means dma output is disabled */
	if (is_hw_get_field(base_reg, &csi_dmax_chx_regs[CSIS_DMAX_CHX_R_CTRL],
			&csi_dmax_chx_fields[CSIS_DMAX_CHX_F_DMA_ENABLE]))
		return true;
	else
		return false;
}

bool csi_hw_g_output_cur_dma_enable(u32 __iomem *base_reg, u32 vc)
{
	/* if DMA_ENABLE field value is 1, this means dma output is enabled */
	return (bool)is_hw_get_field(base_reg, &csi_dmax_chx_regs[CSIS_DMAX_CHX_R_ACT_CTRL],
		&csi_dmax_chx_fields[CSIS_DMAX_CHX_F_ACTIVE_ENABLE]);
}

void csi_hw_dma_common_reset(u32 __iomem *base_reg, bool on)
{
	u32 val;
	u32 retry = 10;


	if (!on) {
		/* SW Reset */
		is_hw_set_field(base_reg,
				&csi_dma_cmn_regs[CSIS_DMA_CMN_R_CSIS_CMN_DMA_CTRL],
				&csi_dma_cmn_fields[CSIS_DMA_CMN_F_SW_RESET], 1);

		while (--retry) {
			if (is_hw_get_field(base_reg,
			    &csi_dma_cmn_regs[CSIS_DMA_CMN_R_CSIS_CMN_DMA_CTRL],
			    &csi_dma_cmn_fields[CSIS_DMA_CMN_F_SW_RESET]) != 1)
				break;

			udelay(10);
		}

		if (!retry)
			err("[CSI DMA TOP] reset is fail(%d)", retry);
	}

	/*
	 * Common DMA Control register/
	 * CSIS_DMA_F_IP_PROCESSING : 1 = Q-channel clock enable
	 * CSIS_DMA_F_IP_PROCESSING : 0 = Q-channel clock disable
	 * The ip_processing should be 0 for safe power-off.
	 */
	is_hw_set_field(base_reg, &csi_dma_cmn_regs[CSIS_DMA_CMN_R_CSIS_CMN_DMA_CTRL],
		&csi_dma_cmn_fields[CSIS_DMA_CMN_F_IP_PROCESSING], on);

	/* Common DMA debug register */
	val = is_hw_get_reg(base_reg, &csi_dma_cmn_regs[CSIS_DMA_CMN_R_CSIS_CMN_DEBUG_EN]);
	val = is_hw_set_field_value(val, &csi_dma_cmn_fields[CSIS_DMA_CMN_F_DMA_CAPTURE_ONCE], on);
	val = is_hw_set_field_value(val, &csi_dma_cmn_fields[CSIS_DMA_CMN_F_DMA_DEBUG_ENABLE], on);
	is_hw_set_reg(base_reg, &csi_dma_cmn_regs[CSIS_DMA_CMN_R_CSIS_CMN_DEBUG_EN], val);

	/* Common DMA overflow int enable [11:0] */
	is_hw_set_reg(base_reg,
			&csi_dma_cmn_regs[CSIS_DMA_CMN_R_CSIS_CMN_OVERFLOW_INT_ENABLE], 0xfff);

	/* Common DMA QURGENT enable */
	is_hw_set_field(base_reg,
			&csi_dma_cmn_regs[CSIS_DMA_CMN_R_CSIS_CMN_QURGENT_EN],
			&csi_dma_cmn_fields[CSIS_DMA_CMN_F_DMA_QURGENT_EN], on);

	info("[CSI DMA TOP] %s: %d\n", __func__, on);
}

int csi_hw_s_dma_common_dynamic(u32 __iomem *base_reg, size_t size, unsigned int dma_ch)
{
	/* No ops */
	return 0;
}

int csi_hw_s_dma_common_pattern_enable(u32 __iomem *base_reg,
	u32 width, u32 height, u32 fps, u32 clk)
{
	u32 val;
	int clk_mhz;
	int vvalid;
	int vblank;
	int vblank_size;
	u32 hblank = 0xFF;	/* This value should be guided according to 3AA HW constrain. */
	u32 v_to_hblank = 0x14;	/* This value should be guided according to 3AA HW constrain. */
	u32 h_to_vblank = 0x28;	/* This value should be guided according to 3AA HW constrain. */

	if (!width || (width % 8 != 0)) {
		err("A width(%d) is not aligned to 8", width);
		return -EINVAL;
	}

	clk_mhz = clk / 1000000;

	/*
	 * V-valid Calculation:
	 * The unit of v-valid is usec.
	 * 2 means 2ppc.
	 */
	vvalid = (width * height) / (clk_mhz * 2);

	/*
	 * Adjust Test Pattern's hvalid length:
	 * Because the post IP(CSIS_DMA, PDP, CSTAT) work with 8ppc,
	 * the Hvalid of test pattern should be half.
	 */
	width /= 2;

	/*
	 * V-blank Calculation:
	 * The unit of v-blank is usec.
	 * v-blank operates with 1ppc.
	 */
	vblank = ((1000000 / fps) - vvalid);
	if (vblank < 0) {
		vblank = 1000; /* 1000 us */
		info("FPS is too high. So, FPS is adjusted forcely. vvalid(%d us), vblank(%d us)\n",
			vvalid, vblank);
	}
	vblank_size = vblank * clk_mhz;

	val = is_hw_get_reg(base_reg,
		&csi_dma_cmn_regs[CSIS_DMA_CMN_R_CSIS_CMN_TEST_PATTERN_CTRL]);
	val = is_hw_set_field_value(val,
		&csi_dma_cmn_fields[CSIS_DMA_CMN_F_VTOHBLANK], v_to_hblank);
	val = is_hw_set_field_value(val,
		&csi_dma_cmn_fields[CSIS_DMA_CMN_F_HBLANK], hblank);
	val = is_hw_set_field_value(val,
		&csi_dma_cmn_fields[CSIS_DMA_CMN_F_HTOVBLANK], h_to_vblank);
	is_hw_set_reg(base_reg,
		&csi_dma_cmn_regs[CSIS_DMA_CMN_R_CSIS_CMN_TEST_PATTERN_CTRL], val);

	val = is_hw_get_reg(base_reg,
		&csi_dma_cmn_regs[CSIS_DMA_CMN_R_CSIS_CMN_TEST_PATTERN_SIZE]);
	val = is_hw_set_field_value(val,
		&csi_dma_cmn_fields[CSIS_DMA_CMN_F_TP_VSIZE], height);
	val = is_hw_set_field_value(val,
		&csi_dma_cmn_fields[CSIS_DMA_CMN_F_TP_HSIZE], width);
	is_hw_set_reg(base_reg,
		&csi_dma_cmn_regs[CSIS_DMA_CMN_R_CSIS_CMN_TEST_PATTERN_SIZE], val);

	val = is_hw_get_reg(base_reg,
		&csi_dma_cmn_regs[CSIS_DMA_CMN_R_CSIS_CMN_TEST_PATTERN_ON]);
	val = is_hw_set_field_value(val,
		&csi_dma_cmn_fields[CSIS_DMA_CMN_F_PPCMODE], CSIS_PIXEL_MODE_DUAL);
	val = is_hw_set_field_value(val,
		&csi_dma_cmn_fields[CSIS_DMA_CMN_F_VBLANK], vblank_size);
	is_hw_set_reg(base_reg,
		&csi_dma_cmn_regs[CSIS_DMA_CMN_R_CSIS_CMN_TEST_PATTERN_ON], val);

	is_hw_set_field(base_reg, &csi_dma_cmn_regs[CSIS_DMA_CMN_R_CSIS_CMN_TEST_PATTERN_ON],
			&csi_dma_cmn_fields[CSIS_DMA_CMN_F_TESTPATTERN], 1);

	info("Enable Pattern Generator: size(%d x %d)"
		", fps(%d), clk(%d Hz), vvalid(%d us), vblank(%d us)\n",
		width, height, fps, clk, vvalid, vblank);

	return 0;
}

void csi_hw_s_dma_common_pattern_disable(u32 __iomem *base_reg)
{
	is_hw_set_field(base_reg, &csi_dma_cmn_regs[CSIS_DMA_CMN_R_CSIS_CMN_TEST_PATTERN_ON],
		&csi_dma_cmn_fields[CSIS_DMA_CMN_F_TESTPATTERN], 0);
}

int csi_hw_s_dma_common_votf_cfg(u32 __iomem *base_reg, u32 width, u32 dma_ch, u32 vc, bool on)
{
	u32 val;
	u32 cache_hint;

	if (vc >= MAX_NUM_VOTF_VC || dma_ch >= CSIS_MAX_NUM_DMA_HW) {
		err("invalid dma_ch(%d) or vc(%d)", dma_ch, vc);
		return -EINVAL;
	}

	val = is_hw_get_reg(base_reg,
		&csi_dma_cmn_regs[CSIS_DMA_CMN_R_CSIS_CMN_DMA_CFG_CSIS0 + dma_ch]);

	/* CSIS_DMA_CMN_F_VOTF_EN_CH3 ~ CSIS_DMA_CMN_F_VOTF_EN_CH0 */
	val = is_hw_set_field_value(val,
		&csi_dma_cmn_fields[CSIS_DMA_CMN_F_VOTF_EN_CH3 + ((MAX_NUM_VOTF_VC - 1) - vc)], on);

	/* cache_hint[6:4] vOTF-type for DRAM update mode */
	cache_hint = on ? IS_LLC_CACHE_HINT_VOTF_TYPE : IS_LLC_CACHE_HINT_INVALID;
	val = is_hw_set_field_value(val, &csi_dma_cmn_fields[CSIS_DMA_CMN_F_BUSINFO],
					(cache_hint << 4));

	is_hw_set_reg(base_reg,
		&csi_dma_cmn_regs[CSIS_DMA_CMN_R_CSIS_CMN_DMA_CFG_CSIS0 + dma_ch], val);

	return 0;
}

int csi_hw_s_dma_common_frame_id_decoder(u32 __iomem *base_reg, u32 dma_ch,
		u32 enable)
{
	u32 val;

	val = is_hw_get_reg(base_reg,
		&csi_dma_cmn_regs[CSIS_DMA_CMN_R_CSIS_CMN_FRO_CSIS_MODE]);
	val = is_hw_set_field_value(val,
		&csi_dma_cmn_fields[CSIS_DMA_CMN_F_FRO_CSIS_SEL], dma_ch);
	val = is_hw_set_field_value(val,
		&csi_dma_cmn_fields[CSIS_DMA_CMN_F_FRO_CSIS_MODE], enable);
	is_hw_set_reg(base_reg,
		&csi_dma_cmn_regs[CSIS_DMA_CMN_R_CSIS_CMN_FRO_CSIS_MODE], val);

	return 0;
}

int csi_hw_g_dma_common_frame_id(u32 __iomem *base_reg, u32 batch_num, u32 *frame_id)
{
	u32 prev_f_id_0, prev_f_id_1;
	u32 cur_f_id_0, cur_f_id_1;
	u64 prev_f_id, sub_f_id, merge_f_id;
	u32 cnt, i;

	prev_f_id_0 = is_hw_get_reg(base_reg,
		&csi_dma_cmn_regs[CSIS_DMA_CMN_R_CSIS_CMN_FRO_PREV_FRAME_ID0]);
	prev_f_id_1 = is_hw_get_reg(base_reg,
		&csi_dma_cmn_regs[CSIS_DMA_CMN_R_CSIS_CMN_FRO_PREV_FRAME_ID1]);

	cur_f_id_0 = is_hw_get_reg(base_reg,
		&csi_dma_cmn_regs[CSIS_DMA_CMN_R_CSIS_CMN_FRO_CUR_FRAME_ID0]);
	cur_f_id_1 = is_hw_get_reg(base_reg,
		&csi_dma_cmn_regs[CSIS_DMA_CMN_R_CSIS_CMN_FRO_CUR_FRAME_ID1]);

	frame_id[0] = prev_f_id_0;
	frame_id[1] = prev_f_id_1;

	/* make sub frame id */
	prev_f_id =  ((u64)prev_f_id_1 << 32) | (u64)prev_f_id_0;
	for (cnt = 0; cnt < 16; cnt++) {
		sub_f_id = (prev_f_id >> (cnt * F_ID_SIZE));
		if (!sub_f_id)
			break;
	}

	if (!cnt) {
		err("[CSI] There is no frame_id");
		return -ENOEXEC;
	}

	if (cnt != 1 && cnt != batch_num)
		err("[CSI] mismatch FRO buf cnt(batch:%d != hw_cnt:%d), prev(%x, %x)",
			batch_num, cnt, prev_f_id_0, prev_f_id_1);

	sub_f_id = (prev_f_id >> ((cnt - 1) * F_ID_SIZE));

	merge_f_id = sub_f_id;

	if (sub_f_id != 1) {
		for (i = 1; i < batch_num; i++)
			merge_f_id |= (sub_f_id + 1) << (i * F_ID_SIZE);
	}

	frame_id[0] = merge_f_id & GENMASK(31, 0);
	frame_id[1] = merge_f_id >> 32;
	dbg_common(is_get_debug_param(IS_DEBUG_PARAM_CSI),
		"[CSI]", " f_id_dec: cnt(%d), prev(%x, %x), cur(%x, %x), merge(%llx)\n",
		cnt, prev_f_id_0, prev_f_id_1, cur_f_id_0, cur_f_id_1, merge_f_id);

	return 0;
}

void csi_hw_s_dma_common_sbwc_ch(u32 __iomem *top_reg, u32 dma_ch)
{
	is_hw_set_field(top_reg,
			&csi_dma_cmn_regs[CSIS_DMA_CMN_R_CSIS_CMN_SBWC_SEL],
			&csi_dma_cmn_fields[CSIS_DMA_CMN_F_SBWC_SEL_F0], dma_ch);
	is_hw_set_field(top_reg,
			&csi_dma_cmn_regs[CSIS_DMA_CMN_R_CSIS_CMN_SBWC_SEL],
			&csi_dma_cmn_fields[CSIS_DMA_CMN_F_SBWC_SEL_F1], dma_ch);
	is_hw_set_field(top_reg,
			&csi_dma_cmn_regs[CSIS_DMA_CMN_R_CSIS_CMN_SBWC_SEL],
			&csi_dma_cmn_fields[CSIS_DMA_CMN_F_SBWC_SEL_F2], dma_ch);
	is_hw_set_field(top_reg,
			&csi_dma_cmn_regs[CSIS_DMA_CMN_R_CSIS_CMN_SBWC_SEL],
			&csi_dma_cmn_fields[CSIS_DMA_CMN_F_SBWC_SEL_F3], dma_ch);
	is_hw_set_field(top_reg,
			&csi_dma_cmn_regs[CSIS_DMA_CMN_R_CSIS_CMN_SBWC_SEL],
			&csi_dma_cmn_fields[CSIS_DMA_CMN_F_SBWC_SEL_F4], dma_ch);
	is_hw_set_field(top_reg,
			&csi_dma_cmn_regs[CSIS_DMA_CMN_R_CSIS_CMN_SBWC_SEL],
			&csi_dma_cmn_fields[CSIS_DMA_CMN_F_SBWC_SEL_F5], dma_ch);
	is_hw_set_field(top_reg,
			&csi_dma_cmn_regs[CSIS_DMA_CMN_R_CSIS_CMN_SBWC_SEL],
			&csi_dma_cmn_fields[CSIS_DMA_CMN_F_SBWC_SEL_F6], dma_ch);
	is_hw_set_field(top_reg,
			&csi_dma_cmn_regs[CSIS_DMA_CMN_R_CSIS_CMN_SBWC_SEL],
			&csi_dma_cmn_fields[CSIS_DMA_CMN_F_SBWC_SEL_F7], dma_ch);
}

int csi_hw_clear_fro_count(u32 __iomem *dma_top_reg, u32 __iomem *vc_reg)
{
	u32 seq, seq_stat;
	u32 prev_f_id_0, prev_f_id_1;

	if (!dma_top_reg || !vc_reg)
		return -EFAULT;

	seq = is_hw_get_reg(vc_reg, &csi_dmax_chx_regs[CSIS_DMAX_CHX_R_FCNTSEQ]);
	seq_stat = is_hw_get_reg(vc_reg, &csi_dmax_chx_regs[CSIS_DMAX_CHX_R_FCNTSEQ_STAT]);

	dbg_common(is_get_debug_param(IS_DEBUG_PARAM_CSI), "[CSI]", " FCNTSEQ_STAT(%x, %x)\n", seq,
		seq_stat);

	prev_f_id_0 = is_hw_get_reg(dma_top_reg,
		&csi_dma_cmn_regs[CSIS_DMA_CMN_R_CSIS_CMN_FRO_PREV_FRAME_ID0]);
	prev_f_id_1 = is_hw_get_reg(dma_top_reg,
		&csi_dma_cmn_regs[CSIS_DMA_CMN_R_CSIS_CMN_FRO_PREV_FRAME_ID1]);

	/*
	 * HACK:
	 * The shadowing is not applied at start interrupt
	 * of only prevew frame id but at every start interrupt.
	 * So, for applying shadowning at only preview frame,
	 * both legacy FRO and frame id decoder must be used.
	 * And current FRO count must be also reset at 60 fps mode
	 * for stating width "0" for FRO count at next frame.
	 */
	if (CHECK_ID_60FPS(prev_f_id_0) || CHECK_ID_60FPS(prev_f_id_1))
		is_hw_set_reg(vc_reg, &csi_dmax_chx_regs[CSIS_DMAX_CHX_R_FRO_FRM], 0);

	return 0;
}

int csi_hw_s_fro_count(u32 __iomem *vc_cmn_reg, u32 batch_num, u32 vc)
{
	u32 ch_num;

	if (!batch_num) {
		err("batch_num is invalid(%d)", batch_num);
		return -EINVAL;
	}

	switch (vc) {
	case DMA_VIRTUAL_CH_0:
		ch_num = CSIS_DMAX_F_FRO_FRAME_NUM_CH0;
		break;
	case DMA_VIRTUAL_CH_1:
		ch_num = CSIS_DMAX_F_FRO_FRAME_NUM_CH1;
		break;
	case DMA_VIRTUAL_CH_2:
		ch_num = CSIS_DMAX_F_FRO_FRAME_NUM_CH2;
		break;
	case DMA_VIRTUAL_CH_3:
		ch_num = CSIS_DMAX_F_FRO_FRAME_NUM_CH3;
		break;
	default:
		err("vc is invalid(%d)", vc);
		return -EINVAL;
	}

	is_hw_set_field(vc_cmn_reg, &csi_dmax_regs[CSIS_DMAX_R_FRO_INT_FRAME_NUM],
		&csi_dmax_fields[ch_num], batch_num - 1);

	return 0;
}

int csi_hw_enable(u32 __iomem *base_reg, u32 use_cphy)
{
	/* update shadow */
	is_hw_set_field(base_reg, &csi_regs[CSIS_R_CSIS_UPD_SDW],
			&csi_fields[CSIS_F_UPDATE_SHADOW], 0xFFFFFFFF);

	/* PHY selection */
	if (use_cphy) {
		is_hw_set_field(base_reg, &csi_regs[CSIS_R_CSIS_CMN_CTRL],
				&csi_fields[CSIS_F_PHY_SEL], 1);
	} else {
		is_hw_set_field(base_reg, &csi_regs[CSIS_R_CSIS_CMN_CTRL],
				&csi_fields[CSIS_F_PHY_SEL], 0);
	}

	/* PHY on */
	is_hw_set_field(base_reg, &csi_regs[CSIS_R_PHY_CMN_CTRL],
			&csi_fields[CSIS_F_ENABLE_CLK], 1);

	/* Q-channel disable */
#ifdef ENABLE_HWACG_CONTROL
	is_hw_set_field(base_reg, &csi_regs[CSIS_R_CSIS_CMN_CTRL],
			&csi_fields[CSIS_F_QCHANNEL_EN], 0);
#endif

	/* csi enable */
	is_hw_set_field(base_reg, &csi_regs[CSIS_R_CSIS_CMN_CTRL],
			&csi_fields[CSIS_F_CSI_EN], 1);
	pr_info("%s: CSIRX_PHY_CMN_CTRL[enable_clk] set, CSIRX_PHY_CMN_CTRL[qch_en] clear, CSIRX_CMN_CFG[csi_en] set\n",
		__func__);
	return 0;
}

int csi_hw_disable(u32 __iomem *base_reg)
{
	/* PHY off */
	is_hw_set_field(base_reg, &csi_regs[CSIS_R_PHY_CMN_CTRL],
			&csi_fields[CSIS_F_ENABLE_CLK], 0);
	is_hw_set_field(base_reg, &csi_regs[CSIS_R_PHY_CMN_CTRL],
			&csi_fields[CSIS_F_ENABLE_DAT], 0);

	/* csi disable */
	is_hw_set_field(base_reg, &csi_regs[CSIS_R_CSIS_CMN_CTRL],
			&csi_fields[CSIS_F_CSI_EN], 0);

	/* Q-channel enable */
#ifdef ENABLE_HWACG_CONTROL
	is_hw_set_field(base_reg, &csi_regs[CSIS_R_CSIS_CMN_CTRL],
			&csi_fields[CSIS_F_QCHANNEL_EN], 1);
#endif
	pr_info("%s: CSIRX_PHY_CMN_CTRL[enable_clk] & CSIRX_PHY_CMN_CTRL[enable_data] clear, CSIRX_CMN_CFG[csi_en] clear, CSIRX_PHY_CMN_CTRL[qch_en] set\n",
		__func__);
	return 0;
}

int csi_hw_dump(u32 __iomem *base_reg)
{
	u32 csis_ver = csi_hw_get_version(base_reg);

	info("CSIS_LINK REG DUMP (v%d.%d.%d.%d)\n",
			(csis_ver >> 24) & 0xFF,
			(csis_ver >> 16) & 0xFF,
			(csis_ver >> 8) & 0xFF,
			(csis_ver >> 0) & 0xFF);

	is_hw_dump_regs(base_reg, csi_regs, CSIS_REG_CNT);

	return 0;
}

int csi_hw_vcdma_dump(u32 __iomem *base_reg)
{
	info("CSIS_DMAX_CHX REG DUMP\n");

	is_hw_dump_regs(base_reg, csi_dmax_chx_regs, CSIS_DMAX_CHX_REG_CNT);

	return 0;
}

int csi_hw_vcdma_cmn_dump(u32 __iomem *base_reg)
{
	is_hw_dump_regs(base_reg, csi_dmax_regs, CSIS_DMAX_REG_CNT);

	return 0;
}

int csi_hw_phy_dump(u32 __iomem *base_reg, u32 instance)
{
	if (IS_ENABLED(CONFIG_CAMERA_CIS_ZEBU_OBJ))
		return 0;

	info("MIPI_PHY S%d REG DUMP\n", instance);

	is_hw_dump_regs(base_reg, phy_regs[instance], PHY_REG_CNT);

	return 0;
}

int csi_hw_common_dma_dump(u32 __iomem *base_reg)
{
	info("CSIS_DMA_CMN REG DUMP\n");

	is_hw_dump_regs(base_reg, csi_dma_cmn_regs, CSIS_DMA_CMN_REG_CNT);

	return 0;
}

int csi_hw_mcb_dump(u32 __iomem *base_reg)
{
	info("MCB REG DUMP\n");

	is_hw_dump_regs(base_reg, csi_mcb_regs, CSIS_MCB_REG_CNT);

	return 0;
}

int csi_hw_ebuf_dump(u32 __iomem *base_reg)
{
	return 0;
}

int csi_hw_cdump(u32 __iomem *base_reg)
{
	u32 csis_ver = csi_hw_get_version(base_reg);

	info("CSIS_LINK REG DUMP (v%d.%d.%d.%d)\n",
			(csis_ver >> 24) & 0xFF,
			(csis_ver >> 16) & 0xFF,
			(csis_ver >> 8) & 0xFF,
			(csis_ver >> 0) & 0xFF);

	is_hw_cdump_regs(base_reg, csi_regs, CSIS_REG_CNT);

	return 0;
}

int csi_hw_vcdma_cdump(u32 __iomem *base_reg)
{
	info("CSIS_DMAX_CHX REG DUMP\n");

	is_hw_cdump_regs(base_reg, csi_dmax_chx_regs, CSIS_DMAX_CHX_REG_CNT);

	return 0;
}

int csi_hw_vcdma_cmn_cdump(u32 __iomem *base_reg)
{
	info("CSIS_DMAX_CMN REG DUMP\n");

	is_hw_cdump_regs(base_reg, csi_dmax_regs, CSIS_DMAX_REG_CNT);

	return 0;
}

int csi_hw_phy_cdump(u32 __iomem *base_reg, u32 instance)
{
	if (IS_ENABLED(CONFIG_CAMERA_CIS_ZEBU_OBJ))
		return 0;

	info("MIPI_PHY S%d SFR DUMP\n", instance);

	is_hw_cdump_regs(base_reg, phy_regs[instance], PHY_REG_CNT);

	return 0;
}

int csi_hw_common_dma_cdump(u32 __iomem *base_reg)
{
	info("CSIS_DMA_CMN REG DUMP\n");

	is_hw_cdump_regs(base_reg, csi_dma_cmn_regs, CSIS_DMA_CMN_REG_CNT);

	return 0;
}

int csi_hw_mcb_cdump(u32 __iomem *base_reg)
{
	info("MCB REG DUMP\n");

	is_hw_cdump_regs(base_reg, csi_mcb_regs, CSIS_MCB_REG_CNT);

	return 0;
}

int csi_hw_ebuf_cdump(u32 __iomem *base_reg)
{
	return 0;
}

int csi_hw_s_dma_irq_msk(u32 __iomem *base_reg, bool on)
{
	u32 dma_msk;

	/* default setting */
	if (on) {
		/* base interrupt setting */
		dma_msk = CSIS_DMA_IRQ_MASK;
	} else {
		dma_msk = 0;
	}

	is_hw_set_reg(base_reg, &csi_dmax_regs[CSIS_DMAX_R_INT_ENABLE], dma_msk);

	return 0;
}

int csi_hw_g_dma_irq_src_vc(u32 __iomem *base_reg, struct csis_dma_irq_src *src, u32 idx_wdma,
			    u32 vc_phys, bool clear)
{
	u32 dma_src, vc;

	dma_src = is_hw_get_reg(base_reg, &csi_dmax_regs[CSIS_DMAX_R_INT_SRC]);

	if (clear)
		is_hw_set_reg(base_reg, &csi_dmax_regs[CSIS_DMAX_R_INT_SRC], dma_src);

	src->dma_start = (dma_src >> CSIS_INT_DMA_FRAME_START) & GENMASK(DMA_VIRTUAL_CH_MAX - 1, 0);
	src->dma_end = (dma_src >> CSIS_INT_DMA_FRAME_END) & GENMASK(DMA_VIRTUAL_CH_MAX - 1, 0);
	src->dma_abort = (dma_src >> CSIS_INT_DMA_ABORT_DONE) & BIT(0);

	src->err_flag = false;

	/* each VC[i] */
	for (vc = DMA_VIRTUAL_CH_0; vc < DMA_VIRTUAL_CH_MAX; vc++) {
		src->err_id[idx_wdma][vc] = (BIT(vc) & (dma_src >> CSIS_INT_DMA_FRAME_DROP)) ?
						    BIT(CSIS_ERR_DMA_FRAME_DROP_VC) :
						    0;
		src->err_id[idx_wdma][vc] |= (BIT(vc) & (dma_src >> CSIS_INT_DMA_OVERLAP)) ?
						     BIT(CSIS_ERR_DMA_OTF_OVERLAP_VC) :
						     0;
		src->err_id[idx_wdma][vc] |= (BIT(vc) & (dma_src >> CSIS_INT_DMA_FSTART_IN_FLUSH)) ?
						     BIT(CSIS_ERR_DMA_FSTART_IN_FLUSH_VC) :
						     0;
		src->err_id[idx_wdma][vc] |=
			(BIT(vc) & (dma_src >> CSIS_INT_DMA_C2COM_LOST_FLUSH)) ?
				BIT(CSIS_ERR_DMA_C2COM_LOST_FLUSH_VC) :
				0;

		if (src->err_id[idx_wdma][vc])
			src->err_flag = true;
	}

	/* Not each VC[i] */
	/**
	 * Ignore CSIS DMA FIFO FULL error interrupt.
	 * CSI v6.0 has large size immunity buffer in IBUF
	 * and it will still assert overflow error interrupt
	 * when it gets the stall signal from CSIS DMA
	 * until it exceeds its own immunity buffer.
	 */
	if (!IS_ENABLED(IGNORE_CSIS_DMA_FIFO_FULL))
		src->err_id[idx_wdma][DMA_VIRTUAL_CH_0] |= (dma_src & BIT(CSIS_INT_DMA_FIFO_FULL)) ?
								   BIT(CSIS_ERR_DMA_DMAFIFO_FULL) :
								   0;
	src->err_id[idx_wdma][DMA_VIRTUAL_CH_0] |=
		(dma_src & BIT(CSIS_INT_DMA_LASTDATA_OR_LASTADDR_ERR)) ?
			BIT(CSIS_ERR_DMA_LASTDATA_LASTADDR_ERROR) :
			0;

	if (src->err_id[idx_wdma][DMA_VIRTUAL_CH_0])
		src->err_flag = true;

	/**
	 * Not HW error
	 * Since DMA abort_done is triggered by SW,
	 * Doing additional error handling is meaningless.
	 */
	src->err_id[idx_wdma][DMA_VIRTUAL_CH_0] |=
		(dma_src & BIT(CSIS_INT_DMA_ABORT_DONE)) ?
			BIT(CSIS_ERR_DMA_ABORT_DONE) :
			0;

	return 0;
}

int csi_hw_s_config_dma_cmn(u32 __iomem *base_reg, u32 vc, u32 extformat, u32 hwformat, bool potf)
{
	int ret = 0;
	u32 val;
	u32 dma_input_path;
	u32 f_input_path;

	if (vc >= CSI_VIRTUAL_CH_MAX) {
		err("invalid vc(%d)", vc);
		return -EINVAL;
	}

	if (vc == DMA_VIRTUAL_CH_0 || vc == DMA_VIRTUAL_CH_1) {
		if (potf || CHECK_POTF_EN(extformat))
			dma_input_path = CSIS_REG_DMA_INPUT_PRL;
		else
			dma_input_path = CSIS_REG_DMA_INPUT_OTF;

		val = is_hw_get_reg(base_reg, &csi_dmax_regs[CSIS_DMAX_R_DATA_CTRL]);

		f_input_path = (vc == DMA_VIRTUAL_CH_0) ?
			CSIS_DMAX_F_DMA_INPUT_PATH_CH0 : CSIS_DMAX_F_DMA_INPUT_PATH_CH1;
		val = is_hw_set_field_value(val, &csi_dmax_fields[f_input_path], dma_input_path);
		is_hw_set_reg(base_reg, &csi_dmax_regs[CSIS_DMAX_R_DATA_CTRL], val);
	}

	return ret;
}

u32 csi_hw_g_mapped_phy_port(u32 csi_ch)
{
	return csi_ch;
}

void csi_hw_s_mcb_qch(u32 __iomem *base_reg, bool on)
{
	is_hw_set_field(base_reg, &csi_mcb_cmn_regs[CSIS_MCB_CMN_R_QCH],
			&csi_mcb_cmn_fields[CSIS_MCB_CMN_F_MCB_FORCE_BUS_ACT_ON], on);
	is_hw_set_field(base_reg, &csi_mcb_cmn_regs[CSIS_MCB_CMN_R_QCH],
			&csi_mcb_cmn_fields[CSIS_MCB_CMN_F_MCB_QACTIVE_ON], on);
}

void csi_hw_s_potf_ctrl(u32 __iomem *base_reg)
{
}

void csi_hw_s_ebuf_enable(u32 __iomem *base_reg, bool on, u32 ebuf_ch, int mode,
			u32 num_of_ebuf, u32 offset_fake_frame_done)
{
}

int csi_hw_s_cfg_ebuf(u32 __iomem *base_reg, u32 ebuf_ch, u32 vc, u32 width,
		u32 height)
{
	return 0;
}

void csi_hw_g_ebuf_irq_src(u32 __iomem *base_reg, struct csis_irq_src *src, int ebuf_ch,
			unsigned int offset_fake_frame_done)
{
}

void csi_hw_s_ebuf_fake_sign(u32 __iomem *base_reg, u32 ebuf_ch)
{
}

static u32 csi_hw_g_bns_scale_factor(u32 in, u32 out)
{
	u32 factor;

	/* scale ratio should have x0.5 step */
	if ((in * 2) % out)
		return 0;

	factor = (in * 2) / out;

	/* Valid scale ratio: x1.0, x1.5, x2.0 */
	if (factor > 4 || factor < 2)
		return 0;

	return factor;
}

static const u32 bns_weight_lut[][5] = {
	{ 64,  64, 128, 128, 128}, /* factor 0: Not used */
	{ 64,  64, 128, 128, 128}, /* factor 1: Not used */
	{ 64,  64, 128, 128, 128}, /* factor 2: ratio x1.0 */
	{ 64,  64, 128, 128, 128}, /* factor 3: ratio x1.5 */
	{ 64,  64, 128,   0,   0}, /* factor 4: ratio x2.0 */
};

bool csi_hw_s_bns_cfg(u32 __iomem *reg, struct is_sensor_cfg *sensor_cfg,
		u32 *width, u32 *height)
{
	u32 in_width, in_height;
	u32 out_width, out_height;
	u32 link_vc, wdma_vc;
	u32 factor_x, factor_y, bittage;
	u32 val;

	link_vc = CSI_VIRTUAL_CH_0;
	wdma_vc = DMA_VIRTUAL_CH_0;

	in_width = sensor_cfg->input[link_vc].width;
	in_height = sensor_cfg->input[link_vc].height;
	out_width = sensor_cfg->output[CSI_OTF_OUT_SINGLE][wdma_vc].width;
	out_height = sensor_cfg->output[CSI_OTF_OUT_SINGLE][wdma_vc].height;

	/* BNS only support down scaling */
	if (in_width <= out_width && in_height <= out_height)
		return false;

	/* Get scale factor */
	factor_x = csi_hw_g_bns_scale_factor(in_width, out_width);
	if (!factor_x)
		return false;

	factor_y = csi_hw_g_bns_scale_factor(in_height, out_height);
	if (!factor_y)
		return false;

	switch (sensor_cfg->input[link_vc].hwformat) {
	case HW_FORMAT_RAW10:
		bittage = 10;
		break;
	case HW_FORMAT_RAW12:
		bittage = 12;
		break;
	case HW_FORMAT_RAW14:
		bittage = 14;
		break;
	default:
		warn("[@][BNS][VC%d] Invalid data format 0x%x", link_vc,
		     sensor_cfg->input[link_vc].hwformat);
		return false;
	}

	val = 0;
	val = is_hw_set_field_value(val,
			&csi_bns_fields[CSIS_BNS_F_BNS_FACTOR_X],
			factor_x);
	val = is_hw_set_field_value(val,
			&csi_bns_fields[CSIS_BNS_F_BNS_FACTOR_Y],
			factor_y);
	val = is_hw_set_field_value(val,
			&csi_bns_fields[CSIS_BNS_F_BNS_BITTAGE],
			bittage);
	is_hw_set_reg(reg, &csi_bns_regs[CSIS_BNS_R_BYR_BNS_CONFIG], val);

	val = 0;
	val = is_hw_set_field_value(val,
			&csi_bns_fields[CSIS_BNS_F_BNS_INPUT_TOTAL_WIDTH],
			in_width);
	val = is_hw_set_field_value(val,
			&csi_bns_fields[CSIS_BNS_F_BNS_INPUT_TOTAL_HEIGHT],
			in_height);
	is_hw_set_reg(reg, &csi_bns_regs[CSIS_BNS_R_BYR_BNS_INPUTSIZE], val);

	val = 0;
	val = is_hw_set_field_value(val,
			&csi_bns_fields[CSIS_BNS_F_BNS_OUTPUT_TOTAL_WIDTH],
			out_width);
	val = is_hw_set_field_value(val,
			&csi_bns_fields[CSIS_BNS_F_BNS_OUTPUT_TOTAL_HEIGHT],
			out_height);
	is_hw_set_reg(reg, &csi_bns_regs[CSIS_BNS_R_BYR_BNS_OUTPUTSIZE], val);

	/* Weight X */
	val = 0;
	val = is_hw_set_field_value(val,
			&csi_bns_fields[CSIS_BNS_F_BNS_WEIGHT_0_0],
			bns_weight_lut[factor_x][0]);
	val = is_hw_set_field_value(val,
			&csi_bns_fields[CSIS_BNS_F_BNS_WEIGHT_0_1],
			bns_weight_lut[factor_x][1]);
	val = is_hw_set_field_value(val,
			&csi_bns_fields[CSIS_BNS_F_BNS_WEIGHT_0_2],
			bns_weight_lut[factor_x][2]);
	val = is_hw_set_field_value(val,
			&csi_bns_fields[CSIS_BNS_F_BNS_WEIGHT_0_3],
			bns_weight_lut[factor_x][3]);
	is_hw_set_reg(reg, &csi_bns_regs[CSIS_BNS_R_BYR_BNS_WEIGHT_X_0], val);
	is_hw_set_field(reg,
			&csi_bns_regs[CSIS_BNS_R_BYR_BNS_WEIGHT_X_4],
			&csi_bns_fields[CSIS_BNS_F_BNS_WEIGHT_0_4],
			bns_weight_lut[factor_x][4]);

	/* Weight Y */
	val = 0;
	val = is_hw_set_field_value(val,
			&csi_bns_fields[CSIS_BNS_F_BNS_WEIGHT_0_0],
			bns_weight_lut[factor_y][0]);
	val = is_hw_set_field_value(val,
			&csi_bns_fields[CSIS_BNS_F_BNS_WEIGHT_0_1],
			bns_weight_lut[factor_y][1]);
	val = is_hw_set_field_value(val,
			&csi_bns_fields[CSIS_BNS_F_BNS_WEIGHT_0_2],
			bns_weight_lut[factor_y][2]);
	val = is_hw_set_field_value(val,
			&csi_bns_fields[CSIS_BNS_F_BNS_WEIGHT_0_3],
			bns_weight_lut[factor_y][3]);
	is_hw_set_reg(reg, &csi_bns_regs[CSIS_BNS_R_BYR_BNS_WEIGHT_Y_0], val);
	is_hw_set_field(reg,
			&csi_bns_regs[CSIS_BNS_R_BYR_BNS_WEIGHT_Y_4],
			&csi_bns_fields[CSIS_BNS_F_BNS_WEIGHT_0_4],
			bns_weight_lut[factor_y][4]);

	info("[BNS][VC%d] %dx%d -> %dx%d %dbit factor %dx%d\n", link_vc, in_width, in_height,
	     out_width, out_height, bittage, factor_x, factor_y);

	*width = out_width;
	*height = out_height;

	is_hw_set_field(reg,
			&csi_bns_regs[CSIS_BNS_R_BYR_BNS_STREAM_CRC],
			&csi_bns_fields[CSIS_BNS_F_BNS_CRC_SEED],
			55);

	is_hw_set_field(reg,
			&csi_bns_regs[CSIS_BNS_R_BYR_BNS_BYPASS],
			&csi_bns_fields[CSIS_BNS_F_BNS_BYPASS],
			0);

	return true;
}

void csi_hw_s_bns_ch(u32 __iomem *reg, u32 ch)
{
	writel(ch, reg);
}

void csi_hw_reset_bns(u32 __iomem *reg)
{
	is_hw_set_field(reg,
			&csi_bns_regs[CSIS_BNS_R_BYR_BNS_BYPASS],
			&csi_bns_fields[CSIS_BNS_F_BNS_BYPASS],
			1);
}

int csi_hw_bns_dump(u32 __iomem *reg)
{
	info("CSIS_BNS REG DUMP\n");

	if (!reg)
		return -EFAULT;

	is_hw_dump_regs(reg, csi_bns_regs, CSIS_BNS_REG_CNT);

	return 0;
}

static void _csi_hw_s_dma_input_mux(void __iomem *mux_regs, u32 idx_wdma, u32 wdma_index,
		int otf_ch, bool mux_en, bool bns_en, u32 bns_mux_val, int otf_out_id,
		int* link_vc_list, struct is_wdma_info* wdma_info)
{
	u32 mux_val, wdma_vc, lc, lc_start, lc_end, mux_val_base;
	int link_vc;

	if (!mux_en) {
		mux_val = 0xFFFFFFFF; /* reset value */
	} else if (bns_en) {
		mux_val = bns_mux_val;
	} else {
		wdma_vc = 0;

		if (otf_out_id == CSI_OTF_OUT_SINGLE || otf_out_id == CSI_OTF_OUT_SHORT) {
			mux_val_base = DMA_MUX_VAL_BASE_LC_0_3;
			lc_start = 0;
			lc_end = 3;
		} else { /* CSI_OTF_OUT_MID */
			mux_val_base = DMA_MUX_VAL_BASE_LC_2_5;
			lc_start = 2;
			lc_end = 5;
		}

		mux_val = mux_val_base + otf_ch;
		if (link_vc_list && wdma_info) {
			for (lc = lc_start; lc <= lc_end; lc++) {
				link_vc = link_vc_list[lc];
				if (link_vc < 0)
					break;

				wdma_info->wdma_idx[link_vc] = idx_wdma;
				wdma_info->wdma_vc[link_vc] = wdma_vc++;
			}
			wdma_info->set_info = true;
		}
	}

	info("OTF%d -> %sWDMA%d %s\n", otf_ch, bns_en ? "BNS -> " : "", wdma_index,
			mux_en ? "ON" : "OFF");

	writel(mux_val, mux_regs);

	return;
}

void csi_hw_s_dma_input_mux(void __iomem *mux_regs, u32 idx_wdma,
		u32 wdma_index, bool bns_en, u32 bns_dma_mux_val,
		u32 csi_ch, int otf_ch, int otf_out_id,
		int* link_vc_list, struct is_wdma_info* wdma_info)
{
	_csi_hw_s_dma_input_mux(mux_regs, idx_wdma, wdma_index, otf_ch, true, bns_en, bns_dma_mux_val,
			otf_out_id, link_vc_list, wdma_info);
}

void csi_hw_s_init_input_mux(void __iomem *mux_regs, u32 idx_wdma, u32 index)
{
	_csi_hw_s_dma_input_mux(mux_regs, idx_wdma, index, 0, false, false, 0, 0, 0, 0);
}

void csi_hw_s_otf_preview_only(u32 __iomem *reg, u32 otf_ch, u32 en)
{
	u32 val;

	val = en ? (u32) BIT(otf_ch) : 0;

	is_hw_set_field(reg,
			&csi_fro_regs[CSIS_FRO_R_FRO_VOTF_VVALID_N_NORMAL_FLAG_CTRL],
			&csi_fro_fields[CSIS_FRO_F_PDP_PATH_NORMAL_FLAG_EN],
			val);
	is_hw_set_field(reg,
			&csi_fro_regs[CSIS_FRO_R_FRO_VOTF_VVALID_N_NORMAL_FLAG_CTRL],
			&csi_fro_fields[CSIS_FRO_F_CSTAT_PATH_NORMAL_FLAG_EN],
			val);
}

int csi_hw_fro_dump(u32 __iomem *reg)
{
	info("CSIS_FRO REG DUMP\n");

	if (!reg)
		return -EFAULT;

	is_hw_dump_regs(reg, csi_fro_regs, CSIS_FRO_REG_CNT);

	return 0;
}

#if IS_ENABLED(CONFIG_PABLO_KUNIT_TEST)
static struct pablo_kunit_hw_csi_func pablo_kunit_hw_csi = {
	.csi_hw_bns_dump = csi_hw_bns_dump,
	.csi_hw_clear_fro_count = csi_hw_clear_fro_count,
	.csi_hw_fro_dump = csi_hw_fro_dump,
	.csi_hw_g_bns_scale_factor = csi_hw_g_bns_scale_factor,
	.csi_hw_g_dma_common_frame_id = csi_hw_g_dma_common_frame_id,
	.csi_hw_g_ebuf_irq_src = csi_hw_g_ebuf_irq_src,
	.csi_hw_g_irq_src = csi_hw_g_irq_src,
	.csi_hw_g_frameptr = csi_hw_g_frameptr,
	.csi_hw_g_mapped_phy_port = csi_hw_g_mapped_phy_port,
	.csi_hw_g_output_cur_dma_enable = csi_hw_g_output_cur_dma_enable,
	.csi_hw_reset_bns = csi_hw_reset_bns,
	.csi_hw_s_bns_ch = csi_hw_s_bns_ch,
	.csi_hw_s_cfg_ebuf = csi_hw_s_cfg_ebuf,
	.csi_hw_s_dma_common_dynamic = csi_hw_s_dma_common_dynamic,
	.csi_hw_s_dma_common_pattern_enable = csi_hw_s_dma_common_pattern_enable,
	.csi_hw_s_dma_common_pattern_disable = csi_hw_s_dma_common_pattern_disable,
	.csi_hw_s_dma_input_mux = csi_hw_s_dma_input_mux,
	.csi_hw_s_init_input_mux = csi_hw_s_init_input_mux,
	.csi_hw_s_sbwc_ctrl = csi_hw_s_sbwc_ctrl,
};

struct pablo_kunit_hw_csi_func *pablo_kunit_get_hw_csi_test(void) {
	return &pablo_kunit_hw_csi;
}
KUNIT_EXPORT_SYMBOL(pablo_kunit_get_hw_csi_test);
#endif
