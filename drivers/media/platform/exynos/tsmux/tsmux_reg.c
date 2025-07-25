/*
 * copyright (c) 2017 Samsung Electronics Co., Ltd.
 *		http://www.samsung.com
 *
 * Core file for Samsung EXYNOS TSMUX driver
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <linux/delay.h>

#include <media/wfd_logger.h>
#include "tsmux_dev.h"
#include "tsmux_reg.h"
#include "tsmux_dbg.h"

#define TSMUX_READL(offset)	\
	(readl(tsmux_dev->regs_base + (offset)))
#define TSMUX_WRITEL(data, offset)	\
	(writel((data), tsmux_dev->regs_base + (offset)))
#define TSMUX_MASK(data, mask)		(data & mask)

#define TSMUX_PKT_CTRL_ADDR			(0)
#define TSMUX_PKT_CTRL_RESET_VALUE		(0x3800)
#define TSMUX_PKT_CTRL_SW_RESET_SHIFT		(31)
#define TSMUX_PKT_CTRL_SW_RESET_MASK		(0x80000000)
#define TSMUX_PKT_CTRL_PSI_EN_SHIFT		(28)
#define TSMUX_PKT_CTRL_PSI_EN_MASK		(0x10000000)
#define TSMUX_PKT_CTRL_TSP_CONTINUITY_CNT_INIT_SHIFT	(27)
#define TSMUX_PKT_CTRL_TSP_CONTINUITY_CNT_INIT_MASK		(0x8000000)
#define TSMUX_PKT_CTRL_RTP_SIZE_SHIFT		(11)
#define TSMUX_PKT_CTRL_RTP_SIZE_MASK		(0x07FFF800)
#define TSMUX_PKT_CTRL_RTP_SEQ_OVER_SHIFT	(10)
#define TSMUX_PKT_CTRL_RTP_SEQ_OVER_MASK	(0x00000400)
#define TSMUX_PKT_CTRL_PES_STUF_NUM_SHIFT	(4)
#define TSMUX_PKT_CTRL_PES_STUF_NUM_MASK	(0x000003F0)
#define TSMUX_PKT_CTRL_MODE_SHIFT		(3)
#define TSMUX_PKT_CTRL_MODE_MASK		(0x00000008)
#define TSMUX_PKT_CTRL_ID_SHIFT			(1)
#define TSMUX_PKT_CTRL_ID_MASK			(0x00000006)
#define TSMUX_PKT_CTRL_ENQUEUE_SHIFT		(0)
#define TSMUX_PKT_CTRL_ENQUEUE_MASK		(0x00000001)

#define TSMUX_SRC_BASE_ADDR			(0x0004)
#define TSMUX_SRC_BASE_RESET_VALUE		(0x0)

#define TSMUX_SRC_LEN_ADDR			(0x0008)
#define TSMUX_SRC_LEN_RESET_VALUE		(0x0)

#define TSMUX_DST_BASE_ADDR			(0x000C)
#define TSMUX_DST_BASE_RESET_VALUE		(0x0)

#define TSMUX_PES_HDR0_ADDR			(0x0010)
#define TSMUX_PES_HDR0_RESET_VALUE		(0x0)
#define TSMUX_PES_HDR0_CODE_VALUE		(0x000001)
#define TSMUX_PES_HDR0_CODE_SHIFT		(8)
#define TSMUX_PES_HDR0_CODE_MASK		(0xFFFFFF00)
#define TSMUX_PES_HDR0_STREAM_ID_SHIFT		(0)
#define TSMUX_PES_HDR0_STREAM_ID_MASK		(0xFF)

#define TSMUX_PES_HDR1_ADDR			(0x0014)
#define TSMUX_PES_HDR1_RESET_VALUE		(0x0)
#define TSMUX_PES_HDR1_PKT_LEN_SHIFT		(16)
#define TSMUX_PES_HDR1_PKT_LEN_MASK		(0xFFFF0000)
#define TSMUX_PES_HDR1_MARKER_VALUE		(2)
#define TSMUX_PES_HDR1_MARKER_SHIFT		(14)
#define TSMUX_PES_HDR1_MARKER_MASK		(0x0000C000)
#define TSMUX_PES_HDR1_SCRAMBLE_SHIFT		(12)
#define TSMUX_PES_HDR1_SCRAMBLE_MASK		(0x00003000)
#define TSMUX_PES_HDR1_PRIORITY_SHIFT		(11)
#define TSMUX_PES_HDR1_PRIORITY_MASK		(0x00000800)
#define TSMUX_PES_HDR1_ALIGNMENT_SHIFT		(10)
#define TSMUX_PES_HDR1_ALIGNMENT_MASK		(0x00000400)
#define TSMUX_PES_HDR1_COPYRIGHT_SHIFT		(9)
#define TSMUX_PES_HDR1_COPYRIGHT_MASK		(0x00000200)
#define TSMUX_PES_HDR1_ORIGINAL_SHIFT		(8)
#define TSMUX_PES_HDR1_ORIGINAL_MASK		(0x00000100)
#define TSMUX_PES_HDR1_FLAGS_PTS_VALUE		(0x00000080)
#define TSMUX_PES_HDR1_FLAGS_EXT_VALUE		(0x00000001)
#define TSMUX_PES_HDR1_FLAGS_MASK		(0x000000FF)

#define TSMUX_PES_HDR2_ADDR			(0x0018)
#define TSMUX_PES_HDR2_RESET_VALUE		(0x0)
#define TSMUX_PES_HDR2_HDR_LEN_SHIFT		(24)
#define TSMUX_PES_HDR2_HDR_LEN_MASK		(0xFF000000)
#define TSMUX_PES_HDR2_PTS39_16_SHIFT		(0)
#define TSMUX_PES_HDR2_PTS39_16_MASK		(0x00FFFFFF)

#define TSMUX_PES_HDR3_ADDR			(0x001C)
#define TSMUX_PES_HDR3_RESET_VALUE		(0x0)
#define TSMUX_PES_HDR3_PTS15_0_SHIFT		(16)
#define TSMUX_PES_HDR3_PTS15_0_MASK		(0xFFFF0000)

#define TSMUX_TSP_HDR_ADDR			(0x0020)
#define TSMUX_TSP_HDR_RESET_VALUE		(0x0)
#define TSMUX_TSP_HDR_SYNC_VALUE		(0x47)
#define TSMUX_TSP_HDR_SYNC_SHIFT		(24)
#define TSMUX_TSP_HDR_SYNC_MASK			(0xFF000000)
#define TSMUX_TSP_HDR_ERROR_SHIFT		(23)
#define TSMUX_TSP_HDR_ERROR_MASK		(0x00800000)
#define TSMUX_TSP_HDR_PRIORITY_SHIFT		(21)
#define TSMUX_TSP_HDR_PRIORITY_MASK		(0x00200000)
#define TSMUX_TSP_HDR_PID_SHIFT			(8)
#define TSMUX_TSP_HDR_PID_MASK			(0x001FFF00)
#define TSMUX_TSP_HDR_SCRAMBLE_SHIFT		(0x6)
#define TSMUX_TSP_HDR_SCRAMBLE_MASK		(0x000000C0)
#define TSMUX_TSP_HDR_ADAPT_CTRL_SHIFT		(0x4)
#define TSMUX_TSP_HDR_ADAPT_CTRL_MASK		(0x00000030)
#define TSMUX_TSP_HDR_CONT_CNT_SHIFT		(0x0)
#define TSMUX_TSP_HDR_CONT_CNT_MASK		(0x0000000F)

#define TSMUX_RTP_HDR0_ADDR			(0x0024)
#define TSMUX_RTP_HDR0_RESET_VALUE		(0x0)
#define TSMUX_RTP_HDR0_VER_VALUE		(2)
#define TSMUX_RTP_HDR0_VER_SHIFT		(30)
#define TSMUX_RTP_HDR0_VER_MASK			(0xC0000000)
#define TSMUX_RTP_HDR0_PAD_SHIFT		(29)
#define TSMUX_RTP_HDR0_PAD_MASK			(0x20000000)
#define TSMUX_RTP_HDR0_EXT_SHIFT		(28)
#define TSMUX_RTP_HDR0_EXT_MASK			(0x10000000)
#define TSMUX_RTP_HDR0_CSRC_CNT_SHIFT		(24)
#define TSMUX_RTP_HDR0_CSRC_CNT_MASK		(0x0F000000)
#define TSMUX_RTP_HDR0_MARKER_SHIFT		(23)
#define TSMUX_RTP_HDR0_MARKER_MASK		(0x00800000)
#define TSMUX_RTP_HDR0_PL_TYPE_SHIFT		(16)
#define TSMUX_RTP_HDR0_PL_TYPE_MASK		(0x007F0000)
#define TSMUX_RTP_HDR0_SEQ_SHIFT		(0)
#define TSMUX_RTP_HDR0_SEQ_MASK			(0x0000FFFF)

#define TSMUX_RTP_HDR2_ADDR			(0x002C)
#define TSMUX_RTP_HDR2_RESET_VALUE		(0x0)
#define TSMUX_RTP_HDR2_SSRC_SHIFT		(0x0)
#define TSMUX_RTP_HDR2_SSRC_MASK		(0xFFFFFFFF)

#define TSMUX_SWAP_CTRL_ADDR			(0x0030)
#define TSMUX_SWAP_CTRL_RESET_VALUE		(0x0)
#define TSMUX_SWAP_CTRL_INVERT_OUT4_SHIFT	(3)
#define TSMUX_SWAP_CTRL_INVERT_OUT4_MASK	(0x00000008)
#define TSMUX_SWAP_CTRL_INVERT_OUT1_SHIFT	(2)
#define TSMUX_SWAP_CTRL_INVERT_OUT1_MASK	(0x00000004)
#define TSMUX_SWAP_CTRL_INVERT_IN4_SHIFT	(1)
#define TSMUX_SWAP_CTRL_INVERT_IN4_MASK		(0x00000002)
#define TSMUX_SWAP_CTRL_INVERT_IN1_SHIFT	(0)
#define TSMUX_SWAP_CTRL_INVERT_IN1_MASK		(0x00000001)

#define TSMUX_PSI_LEN_ADDR			(0x0034)
#define TSMUX_PSI_LEN_RESET_VALUE		(0x0)
#define TSMUX_PSI_LEN_PCR_LEN_SHIFT		(16)
#define TSMUX_PSI_LEN_PCR_LEN_MASK		(0x00FF0000)
#define TSMUX_PSI_LEN_PMT_LEN_SHIFT		(8)
#define TSMUX_PSI_LEN_PMT_LEN_MASK		(0x0000FF00)
#define TSMUX_PSI_LEN_PAT_LEN_SHIFT		(0)
#define TSMUX_PSI_LEN_PAT_LEN_MASK		(0x000000FF)

#define TSMUX_PSI_DATA_NUM			(64)
#define TSMUX_PSI_DATA0_ADDR			(0x0038)
#define TSMUX_PSI_DATA0_RESET_VALUE		(0x0)

#define TSMUX_INT_EN_ADDR			(0x0138)
#define TSMUX_INT_EN_RESET_VALUE		(0x0)
#define TSMUX_INT_EN_PART_DONE			(0x4)
#define TSMUX_INT_EN_TIEM_OUT			(0x2)
#define TSMUX_INT_EN_JOB_DONE			(0x1)

#define TSMUX_INT_STAT_ADDR			(0x013C)
#define TSMUX_INT_STAT_RESET_VALUE		(0x0)
#define TSMUX_INT_STAT_PART_DONE_SHIFT		(5)
#define TSMUX_INT_STAT_PART_DONE_MASK		(0x000001E0)
#define TSMUX_INT_STAT_PART_ID_0_DONE		(0x00000020)
#define TSMUX_INT_STAT_PART_ID_1_DONE		(0x00000040)
#define TSMUX_INT_STAT_PART_ID_2_DONE		(0x00000080)
#define TSMUX_INT_STAT_PART_ID_3_DONE		(0x00000100)
#define TSMUX_INT_STAT_TIMEOUT_SHIFT		(4)
#define TSMUX_INT_STAT_TIMEOUT_MASK		(0x00000010)
#define TSMUX_INT_STAT_JOB_DONE_SHIFT		(0)
#define TSMUX_INT_STAT_JOB_DONE_MASK		(0x0000000F)
#define TSMUX_INT_STAT_JOB_ID_0_DONE		(0x00000001)
#define TSMUX_INT_STAT_JOB_ID_1_DONE		(0x00000002)
#define TSMUX_INT_STAT_JOB_ID_2_DONE		(0x00000004)
#define TSMUX_INT_STAT_JOB_ID_3_DONE		(0x00000008)

#define TSMUX_DBG_SEL_ADDR			(0x0140)
#define TSMUX_DBG_INFO_ADDR			(0x0144)

#define TSMUX_TIMEOUT_TH_ADDR			(0x0148)

#define TSMUX_CMD_CTRL_ADDR			(0x014C)
#define TSMUX_CMD_CTRL_RESET_VALUE		(0x0)
#define TSMUX_CMD_CTRL_MODE_SHIFT		(1)
#define TSMUX_CMD_CTRL_MODE_MASK		(0x2)
#define TSMUX_CMD_CTRL_MODE_CONSECUTIVE		(0)
#define TSMUX_CMD_CTRL_MODE_DEBUG		(0)
#define TSMUX_CMD_CTRL_CLEAR_SHIFT		(0)
#define TSMUX_CMD_CTRL_CLEAR_MASK		(0x1)

#define TSMUX_EXEC_CTRL_ADDR			(0x0150)
#define TSMUX_EXEC_CTRL_RESET_VALUE		(0x0)
#define TSMUX_EXEC_CTRL_NEXT_SHIFT		(0)
#define TSMUX_EXEC_CTRL_NEXT_MASK		(0x1)

#define TSMUX_PART_TH_ADDR			(0x0154)
#define TSMUX_DST_LEN0_ADDR			(0x0158)
#define TSMUX_DST_LEN1_ADDR			(0x015C)
#define TSMUX_DST_LEN2_ADDR			(0x0160)
#define TSMUX_DST_LEN3_ADDR			(0x0164)

#define TSMUX_LH_CTRL_ADDR			(0x0168)
#define TSMUX_LH_CTRL_RESET_VALUE		(0x0)
#define TSMUX_LH_CTRL_SYNCREQ_SHIFT		(0)
#define TSMUX_LH_CTRL_SYNCREQ_MASK		(0x3)

#define TSMUX_SHD_PKT_CTRL_ADDR			(0x0800)
#define TSMUX_SHD_SRC_BASE_ADDR			(0x0804)
#define TSMUX_SHD_SRC_LEN_ADDR			(0x0808)
#define TSMUX_SHD_DST_BASE_ADDR			(0x080C)
#define TSMUX_SHD_PES_HDR0_ADDR			(0x0810)
#define TSMUX_SHD_PES_HDR1_ADDR			(0x0814)
#define TSMUX_SHD_PES_HDR2_ADDR			(0x0818)
#define TSMUX_SHD_PES_HDR3_ADDR			(0x081C)
#define TSMUX_SHD_TS_HDR_ADDR			(0x0820)
#define TSMUX_SHD_RTP_HDR0_ADDR			(0x0824)
#define TSMUX_SHD_RTP_HDR2_ADDR			(0x082C)

#if defined(CONFIG_SOC_EXYNOS9820)
#include "cmu_mfc/exynos9820_cmu_mfc.h"
#elif defined(CONFIG_SOC_EXYNOS9830)
#include "cmu_mfc/exynos9830_cmu_mfc.h"
#elif defined(CONFIG_SOC_EXYNOS2100)
#include "cmu_mfc/exynos2100_cmu_mfc.h"
#elif defined(CONFIG_SOC_S5E9925)
#include "cmu_mfc/s5e9925_cmu_mfc.h"
#elif defined(CONFIG_SOC_S5E9935)
#include "cmu_mfc/s5e9935_cmu_mfc.h"
#elif defined(CONFIG_SOC_S5E9945)
#include "cmu_mfc/s5e9945_cmu_mfc.h"
#endif

#define MAX_OFFSET_CMU_MFC_SFR		0x8000
#define TSMUX_CMU_MFC_READL(offset)    \
	(readl(tsmux_dev->regs_base_cmu_mfc + (offset)))

static int g_tsmux_log_level;
static int g_tsmux_debug_level;
static void *g_tsmux_sfr_dump_addr = NULL;
static int g_enable_partial_done;
static int g_rtp_pkt_count_per_partial_data;
extern struct wfd_logger_info *g_tsmux_logger;

void tsmux_set_partial_done_info(
		int enable_partial_done,
		int rtp_pkt_count_per_partial_data)
{
	print_tsmux_wfdlogger(TSMUX_INFO, "enable_partial_done: %d, rtp_pkt_count_per_partial_data: %d\n",
			enable_partial_done, rtp_pkt_count_per_partial_data);
	g_enable_partial_done = enable_partial_done;
	g_rtp_pkt_count_per_partial_data = rtp_pkt_count_per_partial_data;
}

void tsmux_set_log_level(int log_level)
{
	g_tsmux_log_level = log_level;
}

void tsmux_set_debug_level(int debug_level)
{
	g_tsmux_debug_level = debug_level;
}

void tsmux_set_sfr_dump_addr(void *sfr_dump_addr)
{
	g_tsmux_sfr_dump_addr = sfr_dump_addr;
}

void tsmux_ioremap_cmu_mfc_sfr(struct tsmux_device *tsmux_dev) {
	if (tsmux_dev == NULL) {
		print_tsmux(TSMUX_ERR, "tsmux_dev is NULL\n");
		return;
	}

	tsmux_dev->regs_base_cmu_mfc = ioremap(
		tsmux_cmu_mfc_sfr_list[0].base_pa, MAX_OFFSET_CMU_MFC_SFR);
	if (tsmux_dev->regs_base_cmu_mfc == NULL)
		print_tsmux(TSMUX_ERR, "ioremap(tsmux_cmu_mfc_sfr_list[0].base_pa) failed\n");
}

void tsmux_print_cmu_mfc_sfr(struct tsmux_device *tsmux_dev) {
	int i;
	u32 cmu_mfc_sfr;

	if (tsmux_dev == NULL) {
		print_tsmux_wfdlogger(TSMUX_ERR, "tsmux_dev is NULL\n");
		return;
	}

	if (tsmux_dev->regs_base_cmu_mfc == NULL) {
		print_tsmux_wfdlogger(TSMUX_ERR, "regs_base_cmu_mfc is null\n");
		return;
	}

	print_tsmux_wfdlogger(TSMUX_DBG_SFR, "tsmux_cmu_mfc_sfr_list_size %d\n", tsmux_cmu_mfc_sfr_list_size);
	print_tsmux_wfdlogger(TSMUX_DBG_SFR, "cmu_mfc base addr: offset: value, name\n");

	for (i = 0; i < tsmux_cmu_mfc_sfr_list_size; i++) {
		cmu_mfc_sfr = TSMUX_CMU_MFC_READL(tsmux_cmu_mfc_sfr_list[i].offset);
		print_tsmux_wfdlogger(TSMUX_DBG_SFR, "%.8llx: %.8x: %.8x, %s\n",
			tsmux_cmu_mfc_sfr_list[i].base_pa,
			tsmux_cmu_mfc_sfr_list[i].offset,
			cmu_mfc_sfr,
			tsmux_cmu_mfc_sfr_list[i].sfr_name);
	}

}

uint32_t tsmux_get_hw_version(struct tsmux_device *tsmux_dev)
{
	uint32_t version = 0;

	if (tsmux_dev == NULL)
		return 0;

	TSMUX_WRITEL(0xE1, TSMUX_DBG_SEL_ADDR);
	udelay(10);
	version = TSMUX_READL(TSMUX_DBG_INFO_ADDR);
	print_tsmux(TSMUX_INFO, "hw version: 0x%.8x\n", version);

	return version;
}

void tsmux_print_dbg_info(struct tsmux_device *tsmux_dev,
	u32 dbg_sel_reg)
{
	u32 dbg_info_reg;

	if (tsmux_dev == NULL)
		return;

	TSMUX_WRITEL(dbg_sel_reg, TSMUX_DBG_SEL_ADDR);
	udelay(10);
	dbg_info_reg = TSMUX_READL(TSMUX_DBG_INFO_ADDR);
	print_tsmux_wfdlogger(TSMUX_DBG_SFR, "dbg_sel_reg 0x%.2x, dbg_info_reg 0x%.8x\n",
		dbg_sel_reg, dbg_info_reg);
}

void tsmux_print_dbg_info_all(struct tsmux_device *tsmux_dev)
{
	if (tsmux_dev == NULL)
		return;

	tsmux_print_dbg_info(tsmux_dev, 0x00);
	tsmux_print_dbg_info(tsmux_dev, 0x01);
	tsmux_print_dbg_info(tsmux_dev, 0x02);
	tsmux_print_dbg_info(tsmux_dev, 0x03);
	tsmux_print_dbg_info(tsmux_dev, 0x04);
	tsmux_print_dbg_info(tsmux_dev, 0x05);
	tsmux_print_dbg_info(tsmux_dev, 0x10);
	tsmux_print_dbg_info(tsmux_dev, 0x11);
	tsmux_print_dbg_info(tsmux_dev, 0x20);
	tsmux_print_dbg_info(tsmux_dev, 0x21);
	tsmux_print_dbg_info(tsmux_dev, 0x22);
	tsmux_print_dbg_info(tsmux_dev, 0x23);
	tsmux_print_dbg_info(tsmux_dev, 0x30);
	tsmux_print_dbg_info(tsmux_dev, 0x40);
	tsmux_print_dbg_info(tsmux_dev, 0x50);
	tsmux_print_dbg_info(tsmux_dev, 0x60);
	tsmux_print_dbg_info(tsmux_dev, 0x70);
	tsmux_print_dbg_info(tsmux_dev, 0x80);
	tsmux_print_dbg_info(tsmux_dev, 0x90);
	tsmux_print_dbg_info(tsmux_dev, 0xA0);
	tsmux_print_dbg_info(tsmux_dev, 0xB0);
	tsmux_print_dbg_info(tsmux_dev, 0xB1);
	tsmux_print_dbg_info(tsmux_dev, 0xC0);
	tsmux_print_dbg_info(tsmux_dev, 0xD0);
	tsmux_print_dbg_info(tsmux_dev, 0xD1);
	tsmux_print_dbg_info(tsmux_dev, 0xD2);
	tsmux_print_dbg_info(tsmux_dev, 0xD3);
	tsmux_print_dbg_info(tsmux_dev, 0xE0);
	tsmux_print_dbg_info(tsmux_dev, 0xE1);
	tsmux_print_dbg_info(tsmux_dev, 0xE2);
	tsmux_print_dbg_info(tsmux_dev, 0xE3);
	tsmux_print_dbg_info(tsmux_dev, 0xE4);
	tsmux_print_dbg_info(tsmux_dev, 0xE5);
	tsmux_print_dbg_info(tsmux_dev, 0xF0);
}

static inline void tsmux_print_tsmux_wfdlogger_sfr_range(
	struct tsmux_device *tsmux_dev, u32 start, u32 end, bool dump)
{
	u32 i;
	u32 sfr1, sfr2, sfr3, sfr4;

	for (i = start; i <= end; i += 16) {
		sfr1 = TSMUX_READL(i);
		sfr2 = TSMUX_READL(i + 4);
		sfr3 = TSMUX_READL(i + 8);
		sfr4 = TSMUX_READL(i + 12);
		print_tsmux_wfdlogger(TSMUX_DBG_SFR, "%.8x: %.8x %.8x %.8x %.8x\n",
			i, sfr1, sfr2, sfr3, sfr4);

		if (dump && g_tsmux_sfr_dump_addr) {
			*((u32 *)g_tsmux_sfr_dump_addr + i) = sfr1;
			*((u32 *)g_tsmux_sfr_dump_addr + i + 4) = sfr2;
			*((u32 *)g_tsmux_sfr_dump_addr + i + 8) = sfr3;
			*((u32 *)g_tsmux_sfr_dump_addr + i + 12) = sfr4;
		}
	}
}

void tsmux_print_tsmux_sfr(struct tsmux_device *tsmux_dev)
{
	if (tsmux_dev == NULL)
		return;

	tsmux_print_tsmux_wfdlogger_sfr_range(tsmux_dev, TSMUX_PKT_CTRL_ADDR,
		TSMUX_LH_CTRL_ADDR, true /* dump */);
	tsmux_print_tsmux_wfdlogger_sfr_range(tsmux_dev, TSMUX_SHD_PKT_CTRL_ADDR,
		TSMUX_SHD_RTP_HDR2_ADDR, false /* dump */);
}

void tsmux_set_psi_info(struct tsmux_device *tsmux_dev,
	struct tsmux_psi_info *psi_info)
{
	u32 psi_len_reg;
	int i;

	print_tsmux_wfdlogger(TSMUX_DBG_SFR, "++\n");

	if (tsmux_dev == NULL || psi_info == NULL)
		return;

	print_tsmux_wfdlogger(TSMUX_DBG_SFR, "pcr_len %d, pmt_len %d, pat_len %d\n",
		psi_info->pcr_len, psi_info->pmt_len, psi_info->pat_len);

	/* set psi_leng */
	psi_len_reg = TSMUX_PSI_LEN_PCR_LEN_MASK &
		(psi_info->pcr_len << TSMUX_PSI_LEN_PCR_LEN_SHIFT);

	psi_len_reg |= TSMUX_PSI_LEN_PMT_LEN_MASK &
		(psi_info->pmt_len << TSMUX_PSI_LEN_PMT_LEN_SHIFT);

	psi_len_reg |= TSMUX_PSI_LEN_PAT_LEN_MASK &
		(psi_info->pat_len << TSMUX_PSI_LEN_PAT_LEN_SHIFT);

	print_tsmux_wfdlogger(TSMUX_DBG_SFR, "psi_len_reg 0x%x\n", psi_len_reg);

	TSMUX_WRITEL(psi_len_reg, TSMUX_PSI_LEN_ADDR);

	print_tsmux_wfdlogger(TSMUX_DBG_SFR, "psi_len_reg 0x%x\n", psi_len_reg);

	/* set psi_data */
	for (i = 0; i < TSMUX_PSI_SIZE; i++) {
		print_tsmux_wfdlogger(TSMUX_DBG_SFR, "psi_data[%d] %u\n", i,
			psi_info->psi_data[i]);
		TSMUX_WRITEL(psi_info->psi_data[i],
			TSMUX_PSI_DATA0_ADDR + i * 4);
	}

	print_tsmux_wfdlogger(TSMUX_DBG_SFR, "--\n");
}

void tsmux_set_pkt_ctrl(struct tsmux_device *tsmux_dev,
	struct tsmux_pkt_ctrl *pkt_ctrl)
{
	u32 pkt_ctrl_reg;
	int32_t tsp_continuity_cnt_init = 1;

	print_tsmux_wfdlogger(TSMUX_DBG_SFR, "++\n");

	if (tsmux_dev == NULL || pkt_ctrl == NULL)
		return;

	/* set pck_ctrl */
	pkt_ctrl_reg = TSMUX_READL(TSMUX_PKT_CTRL_ADDR);
	print_tsmux_wfdlogger(TSMUX_DBG_SFR, "pkt_ctrl_reg 0x%x\n", pkt_ctrl_reg);

	pkt_ctrl_reg &= ~(TSMUX_PKT_CTRL_PSI_EN_MASK);
	pkt_ctrl_reg |= TSMUX_PKT_CTRL_PSI_EN_MASK &
		(pkt_ctrl->psi_en << TSMUX_PKT_CTRL_PSI_EN_SHIFT);
	print_tsmux_wfdlogger(TSMUX_DBG_SFR, "PKT_CTRL_PSI_EN %d\n", pkt_ctrl->psi_en);
	print_tsmux_wfdlogger(TSMUX_DBG_SFR, "pkt_ctrl_reg 0x%x\n", pkt_ctrl_reg);

	pkt_ctrl_reg &= ~(TSMUX_PKT_CTRL_TSP_CONTINUITY_CNT_INIT_MASK);
	pkt_ctrl_reg |= TSMUX_PKT_CTRL_TSP_CONTINUITY_CNT_INIT_MASK &
		(tsp_continuity_cnt_init << TSMUX_PKT_CTRL_TSP_CONTINUITY_CNT_INIT_SHIFT);
	print_tsmux_wfdlogger(TSMUX_DBG_SFR, "PKT_CTRL_TSP_CONTINUITY_CNT_INIT %d\n", tsp_continuity_cnt_init);
	print_tsmux_wfdlogger(TSMUX_DBG_SFR, "pkt_ctrl_reg 0x%x\n", pkt_ctrl_reg);

	pkt_ctrl_reg &= ~(TSMUX_PKT_CTRL_RTP_SIZE_MASK);
	pkt_ctrl_reg |= TSMUX_PKT_CTRL_RTP_SIZE_MASK &
		(pkt_ctrl->rtp_size << TSMUX_PKT_CTRL_RTP_SIZE_SHIFT);
	print_tsmux_wfdlogger(TSMUX_DBG_SFR, "PKT_CTRL_RTP_SIZE %d\n",
		pkt_ctrl->rtp_size);
	print_tsmux_wfdlogger(TSMUX_DBG_SFR, "pkt_ctrl_reg 0x%x\n", pkt_ctrl_reg);

	pkt_ctrl_reg &= ~(TSMUX_PKT_CTRL_RTP_SEQ_OVER_MASK);
	pkt_ctrl_reg |= TSMUX_PKT_CTRL_RTP_SEQ_OVER_MASK &
		(pkt_ctrl->rtp_seq_override <<
		TSMUX_PKT_CTRL_RTP_SEQ_OVER_SHIFT);
	print_tsmux_wfdlogger(TSMUX_DBG_SFR, "PKT_CTRL_RTP_SEQ_OVER %d\n",
		pkt_ctrl->rtp_seq_override);
	print_tsmux_wfdlogger(TSMUX_DBG_SFR, "pkt_ctrl_reg 0x%x\n", pkt_ctrl_reg);

	pkt_ctrl_reg &= ~(TSMUX_PKT_CTRL_PES_STUF_NUM_MASK);
	pkt_ctrl_reg |= TSMUX_PKT_CTRL_PES_STUF_NUM_MASK &
		(pkt_ctrl->pes_stuffing_num <<
		TSMUX_PKT_CTRL_PES_STUF_NUM_SHIFT);
	print_tsmux_wfdlogger(TSMUX_DBG_SFR, "TSMUX_PKT_CTRL_PES_STUF %d\n",
		pkt_ctrl->pes_stuffing_num);
	print_tsmux_wfdlogger(TSMUX_DBG_SFR, "pkt_ctrl_reg 0x%x\n", pkt_ctrl_reg);

	pkt_ctrl_reg &= ~(TSMUX_PKT_CTRL_MODE_MASK);
	pkt_ctrl_reg |= TSMUX_PKT_CTRL_MODE_MASK &
		(pkt_ctrl->mode << TSMUX_PKT_CTRL_MODE_SHIFT);
	print_tsmux_wfdlogger(TSMUX_DBG_SFR, "PKT_CTRL_MODE %d\n", pkt_ctrl->mode);
	print_tsmux_wfdlogger(TSMUX_DBG_SFR, "pkt_ctrl_reg 0x%x\n", pkt_ctrl_reg);

	pkt_ctrl_reg &= ~(TSMUX_PKT_CTRL_ID_MASK);
	pkt_ctrl_reg |= TSMUX_PKT_CTRL_ID_MASK &
		(pkt_ctrl->id << TSMUX_PKT_CTRL_ID_SHIFT);
	print_tsmux_wfdlogger(TSMUX_DBG_SFR, "TSMUX_PKT_CTRL_ID %d\n", pkt_ctrl->id);
	print_tsmux_wfdlogger(TSMUX_DBG_SFR, "pkt_ctrl_reg 0x%x\n", pkt_ctrl_reg);

	TSMUX_WRITEL(pkt_ctrl_reg, TSMUX_PKT_CTRL_ADDR);

	print_tsmux_wfdlogger(TSMUX_DBG_SFR, "--\n");
}

void tsmux_set_pes_hdr(struct tsmux_device *tsmux_dev,
	struct tsmux_pes_hdr *pes_hdr)
{
	u32 pes_hdr0_reg, pes_hdr1_reg, pes_hdr2_reg, pes_hdr3_reg;

	print_tsmux_wfdlogger(TSMUX_DBG_SFR, "++\n");

	if (tsmux_dev == NULL || pes_hdr == NULL)
		return;

	/* set pes_hdr0 */
	pes_hdr0_reg = TSMUX_PES_HDR0_CODE_MASK &
		(pes_hdr->code << TSMUX_PES_HDR0_CODE_SHIFT);

	pes_hdr0_reg &= ~(TSMUX_PES_HDR0_STREAM_ID_MASK);
	pes_hdr0_reg |= TSMUX_PES_HDR0_STREAM_ID_MASK &
		(pes_hdr->stream_id << TSMUX_PES_HDR0_STREAM_ID_SHIFT);
	print_tsmux_wfdlogger(TSMUX_DBG_SFR, "PES_HDR0_STREAM_ID %d\n", pes_hdr->stream_id);

	TSMUX_WRITEL(pes_hdr0_reg, TSMUX_PES_HDR0_ADDR);
	print_tsmux_wfdlogger(TSMUX_DBG_SFR, "pes_hdr0_reg 0x%x\n", pes_hdr0_reg);

	/* set pes_hdr1 */
	pes_hdr1_reg = TSMUX_PES_HDR1_PKT_LEN_MASK &
		(pes_hdr->pkt_len << TSMUX_PES_HDR1_PKT_LEN_SHIFT);
	print_tsmux_wfdlogger(TSMUX_DBG_SFR, "PES_HDR1_PKT_LEN %d\n", pes_hdr->pkt_len);

	pes_hdr1_reg &= ~(TSMUX_PES_HDR1_MARKER_MASK);
	pes_hdr1_reg |= TSMUX_PES_HDR1_MARKER_MASK &
		(pes_hdr->marker << TSMUX_PES_HDR1_MARKER_SHIFT);
	print_tsmux_wfdlogger(TSMUX_DBG_SFR, "PES_HDR1_MARKER %d\n", pes_hdr->marker);

	pes_hdr1_reg &= ~(TSMUX_PES_HDR1_SCRAMBLE_MASK);
	pes_hdr1_reg |= TSMUX_PES_HDR1_SCRAMBLE_MASK &
		(pes_hdr->scramble << TSMUX_PES_HDR1_SCRAMBLE_SHIFT);
	print_tsmux_wfdlogger(TSMUX_DBG_SFR, "PES_HDR1_SCRAMBLE %d\n", pes_hdr->scramble);

	pes_hdr1_reg &= ~(TSMUX_PES_HDR1_PRIORITY_MASK);
	pes_hdr1_reg |= TSMUX_PES_HDR1_PRIORITY_MASK &
		(pes_hdr->priority << TSMUX_PES_HDR1_PRIORITY_SHIFT);
	print_tsmux_wfdlogger(TSMUX_DBG_SFR, "PES_HDR1_PRIORITY %d\n", pes_hdr->priority);

	pes_hdr1_reg &= ~(TSMUX_PES_HDR1_ALIGNMENT_MASK);
	pes_hdr1_reg |= TSMUX_PES_HDR1_ALIGNMENT_MASK &
		(pes_hdr->alignment << TSMUX_PES_HDR1_ALIGNMENT_SHIFT);
	print_tsmux_wfdlogger(TSMUX_DBG_SFR, "PES_HDR1_ALIGNMENT %d\n", pes_hdr->alignment);

	pes_hdr1_reg &= ~(TSMUX_PES_HDR1_COPYRIGHT_MASK);
	pes_hdr1_reg |= TSMUX_PES_HDR1_COPYRIGHT_MASK &
		(pes_hdr->copyright << TSMUX_PES_HDR1_COPYRIGHT_SHIFT);
	print_tsmux_wfdlogger(TSMUX_DBG_SFR, "PES_HDR1_COPYRIGHT %d\n", pes_hdr->copyright);

	pes_hdr1_reg &= ~(TSMUX_PES_HDR1_ORIGINAL_MASK);
	pes_hdr1_reg |= TSMUX_PES_HDR1_ORIGINAL_MASK &
		(pes_hdr->original << TSMUX_PES_HDR1_ORIGINAL_SHIFT);
	print_tsmux_wfdlogger(TSMUX_DBG_SFR, "PES_HDR1_ORIGINAL %d\n", pes_hdr->original);

	pes_hdr1_reg &= ~(TSMUX_PES_HDR1_FLAGS_MASK);
	pes_hdr1_reg |= TSMUX_PES_HDR1_FLAGS_MASK & (pes_hdr->flags);
	print_tsmux_wfdlogger(TSMUX_DBG_SFR, "PES_HDR1_FLAGS_PTS %d\n", pes_hdr->flags);

	TSMUX_WRITEL(pes_hdr1_reg, TSMUX_PES_HDR1_ADDR);
	print_tsmux_wfdlogger(TSMUX_DBG_SFR, "pes_hdr1_reg 0x%x\n", pes_hdr1_reg);

	/* set pes_hdr2 */
	pes_hdr2_reg = TSMUX_PES_HDR2_HDR_LEN_MASK &
		(pes_hdr->hdr_len << TSMUX_PES_HDR2_HDR_LEN_SHIFT);
	print_tsmux_wfdlogger(TSMUX_DBG_SFR, "PES_HDR2_HDR_LEN %d\n", pes_hdr->hdr_len);

	pes_hdr2_reg &= ~(TSMUX_PES_HDR2_PTS39_16_MASK);
	pes_hdr2_reg |= TSMUX_PES_HDR2_PTS39_16_MASK &
		(pes_hdr->pts39_16 << TSMUX_PES_HDR2_PTS39_16_SHIFT);
	print_tsmux_wfdlogger(TSMUX_DBG_SFR, "PES_HDR2_PTS39_16 %u\n", pes_hdr->pts39_16);

	TSMUX_WRITEL(pes_hdr2_reg, TSMUX_PES_HDR2_ADDR);
	print_tsmux_wfdlogger(TSMUX_DBG_SFR, "pes_hdr2_reg 0x%x\n", pes_hdr2_reg);

	/* set pes_hdr3 */
	pes_hdr3_reg = TSMUX_PES_HDR3_PTS15_0_MASK &
		(pes_hdr->pts15_0 << TSMUX_PES_HDR3_PTS15_0_SHIFT);
	print_tsmux_wfdlogger(TSMUX_DBG_SFR, "PES_HDR2_PTS15_0 %u\n", pes_hdr->pts15_0);

	TSMUX_WRITEL(pes_hdr3_reg, TSMUX_PES_HDR3_ADDR);
	print_tsmux_wfdlogger(TSMUX_DBG_SFR, "pes_hdr3_reg 0x%x\n", pes_hdr3_reg);

	print_tsmux_wfdlogger(TSMUX_DBG_SFR, "--\n");
}

void tsmux_set_ts_hdr(struct tsmux_device *tsmux_dev,
	struct tsmux_ts_hdr *ts_hdr)
{
	u32 ts_hdr_reg;

	print_tsmux_wfdlogger(TSMUX_DBG_SFR, "++\n");

	if (tsmux_dev == NULL || ts_hdr == NULL)
		return;

	ts_hdr_reg = TSMUX_TSP_HDR_SYNC_MASK &
		(ts_hdr->sync << TSMUX_TSP_HDR_SYNC_SHIFT);

	ts_hdr_reg &= ~(TSMUX_TSP_HDR_ERROR_MASK);
	ts_hdr_reg |= TSMUX_TSP_HDR_ERROR_MASK &
		(ts_hdr->error << TSMUX_TSP_HDR_ERROR_SHIFT);
	print_tsmux_wfdlogger(TSMUX_DBG_SFR, "TSP_HDR_ERROR %d\n", ts_hdr->error);

	ts_hdr_reg &= ~(TSMUX_TSP_HDR_PRIORITY_MASK);
	ts_hdr_reg |= TSMUX_TSP_HDR_PRIORITY_MASK &
		(ts_hdr->priority << TSMUX_TSP_HDR_PRIORITY_SHIFT);
	print_tsmux_wfdlogger(TSMUX_DBG_SFR, "TSP_HDR_PRIORITY %d\n", ts_hdr->priority);

	ts_hdr_reg &= ~(TSMUX_TSP_HDR_PID_MASK);
	ts_hdr_reg |= TSMUX_TSP_HDR_PID_MASK &
		(ts_hdr->pid << TSMUX_TSP_HDR_PID_SHIFT);
	print_tsmux_wfdlogger(TSMUX_DBG_SFR, "TSP_HDR_PID %d\n", ts_hdr->pid);

	ts_hdr_reg &= ~(TSMUX_TSP_HDR_SCRAMBLE_MASK);
	ts_hdr_reg |= TSMUX_TSP_HDR_SCRAMBLE_MASK &
		(ts_hdr->scramble << TSMUX_TSP_HDR_SCRAMBLE_SHIFT);
	print_tsmux_wfdlogger(TSMUX_DBG_SFR, "TSP_HDR_SCRAMBLE %d\n", ts_hdr->scramble);

	ts_hdr_reg &= ~(TSMUX_TSP_HDR_ADAPT_CTRL_MASK);
	ts_hdr_reg |= TSMUX_TSP_HDR_ADAPT_CTRL_MASK &
		(ts_hdr->adapt_ctrl << TSMUX_TSP_HDR_ADAPT_CTRL_SHIFT);
	print_tsmux_wfdlogger(TSMUX_DBG_SFR, "TSP_HDR_ADAPT_CTRL %d\n", ts_hdr->adapt_ctrl);

	ts_hdr_reg &= ~(TSMUX_TSP_HDR_CONT_CNT_MASK);
	ts_hdr_reg |= TSMUX_TSP_HDR_CONT_CNT_MASK &
		(ts_hdr->continuity_counter << TSMUX_TSP_HDR_CONT_CNT_SHIFT);
	print_tsmux_wfdlogger(TSMUX_DBG_SFR, "TSP_HDR_CONTINUITY_COUNTER %d\n",
		ts_hdr->continuity_counter);

	TSMUX_WRITEL(ts_hdr_reg, TSMUX_TSP_HDR_ADDR);
	print_tsmux_wfdlogger(TSMUX_DBG_SFR, "ts_hdr_reg 0x%x\n", ts_hdr_reg);

	print_tsmux_wfdlogger(TSMUX_DBG_SFR, "--\n");
}

void tsmux_set_rtp_hdr(struct tsmux_device *tsmux_dev,
	struct tsmux_rtp_hdr *rtp_hdr)
{
	u32 rtp_hdr0_reg, rtp_hdr2_reg;

	print_tsmux_wfdlogger(TSMUX_DBG_SFR, "++\n");

	if (tsmux_dev == NULL || rtp_hdr == NULL)
		return;

	/* set rtp_hdr0 */
	rtp_hdr0_reg = TSMUX_RTP_HDR0_VER_MASK &
		(rtp_hdr->ver << TSMUX_RTP_HDR0_VER_SHIFT);
	print_tsmux_wfdlogger(TSMUX_DBG_SFR, "RTP_HDR0_VER %d\n", rtp_hdr->ver);

	rtp_hdr0_reg &= ~(TSMUX_RTP_HDR0_PAD_MASK);
	rtp_hdr0_reg |= TSMUX_RTP_HDR0_PAD_MASK &
		(rtp_hdr->pad << TSMUX_RTP_HDR0_PAD_SHIFT);
	print_tsmux_wfdlogger(TSMUX_DBG_SFR, "RTP_HDR0_PAD %d\n", rtp_hdr->pad);

	rtp_hdr0_reg &= ~(TSMUX_RTP_HDR0_MARKER_MASK);
	rtp_hdr0_reg |= TSMUX_RTP_HDR0_MARKER_MASK &
		(rtp_hdr->marker << TSMUX_RTP_HDR0_MARKER_SHIFT);
	print_tsmux_wfdlogger(TSMUX_DBG_SFR, "RTP_HDR0_MARKER %d\n", rtp_hdr->marker);

	rtp_hdr0_reg &= ~(TSMUX_RTP_HDR0_PL_TYPE_MASK);
	rtp_hdr0_reg |= TSMUX_RTP_HDR0_PL_TYPE_MASK &
		(rtp_hdr->pl_type <<
		TSMUX_RTP_HDR0_PL_TYPE_SHIFT);
	print_tsmux_wfdlogger(TSMUX_DBG_SFR, "RTP_HDR0_PL_TYPE %d\n", rtp_hdr->pl_type);

	rtp_hdr0_reg &= ~(TSMUX_RTP_HDR0_SEQ_MASK);
	rtp_hdr0_reg |= TSMUX_RTP_HDR0_SEQ_MASK &
		(rtp_hdr->seq << TSMUX_RTP_HDR0_SEQ_SHIFT);
	print_tsmux_wfdlogger(TSMUX_DBG_SFR, "RTP_HDR0_SEQ %d\n", rtp_hdr->seq);

	TSMUX_WRITEL(rtp_hdr0_reg, TSMUX_RTP_HDR0_ADDR);
	print_tsmux_wfdlogger(TSMUX_DBG_SFR, "rtp_hdr0_reg 0x%x\n", rtp_hdr0_reg);

	/* set rtp_hdr2 */
	rtp_hdr2_reg = TSMUX_RTP_HDR2_SSRC_MASK &
		(rtp_hdr->ssrc << TSMUX_RTP_HDR2_SSRC_SHIFT);
	print_tsmux_wfdlogger(TSMUX_DBG_SFR, "RTP_HDR2_SSRC %u\n", rtp_hdr->ssrc);

	TSMUX_WRITEL(rtp_hdr2_reg, TSMUX_RTP_HDR2_ADDR);
	print_tsmux_wfdlogger(TSMUX_DBG_SFR, "rtp_hdr2_reg 0x%x\n", rtp_hdr2_reg);

	print_tsmux_wfdlogger(TSMUX_DBG_SFR, "--\n");
}

void tsmux_set_swp_ctrl(struct tsmux_device *tsmux_dev,
	struct tsmux_swp_ctrl *swp_ctrl)
{
	u32 swap_ctrl_reg;

	print_tsmux_wfdlogger(TSMUX_DBG_SFR, "++\n");

	if (tsmux_dev == NULL || swp_ctrl == NULL)
		return;

	/* set swap_ctrl reg*/
	swap_ctrl_reg = TSMUX_SWAP_CTRL_INVERT_OUT4_MASK &
		(swp_ctrl->swap_ctrl_out4 << TSMUX_SWAP_CTRL_INVERT_OUT4_SHIFT);
	swap_ctrl_reg |= TSMUX_SWAP_CTRL_INVERT_OUT1_MASK &
		(swp_ctrl->swap_ctrl_out1 << TSMUX_SWAP_CTRL_INVERT_OUT1_SHIFT);
	swap_ctrl_reg |= TSMUX_SWAP_CTRL_INVERT_IN4_MASK &
		(swp_ctrl->swap_ctrl_in4 << TSMUX_SWAP_CTRL_INVERT_IN4_SHIFT);
	swap_ctrl_reg |= TSMUX_SWAP_CTRL_INVERT_IN1_MASK &
		(swp_ctrl->swap_ctrl_in1 << TSMUX_SWAP_CTRL_INVERT_IN1_SHIFT);

	TSMUX_WRITEL(swap_ctrl_reg, TSMUX_SWAP_CTRL_ADDR);
	print_tsmux_wfdlogger(TSMUX_DBG_SFR, "swap_ctrl_reg 0x%x\n", swap_ctrl_reg);

	print_tsmux_wfdlogger(TSMUX_DBG_SFR, "--\n");
}

#include <soc/samsung/exynos-smc.h>
void tsmux_clear_hex_ctrl(void)
{
	unsigned long ret;

	print_tsmux(TSMUX_DBG_SFR, "++\n");

	/* exynos_smc(0x82004014, m2m/otf mode, 0, enabled) */
	ret = exynos_smc(0x82004014, 1, 0, 0);
	if (ret)
		print_tsmux(TSMUX_ERR, "exynos_smc() ret %lu\n", ret);

	print_tsmux(TSMUX_DBG_SFR, "--\n");
}

void tsmux_set_hex_ctrl(struct tsmux_context *ctx,
	struct tsmux_hex_ctrl *hex_ctrl)
{
	unsigned long ret;

	print_tsmux_wfdlogger(TSMUX_DBG_SFR, "++\n");

	if (hex_ctrl->m2m_enable == 0 && hex_ctrl->otf_enable == 0) {
		print_tsmux_wfdlogger(TSMUX_DBG_SFR, "--\n");
		return;
	}

	if (ctx->set_hex_info) {
		/* exynos_smc(0x82004014, m2m/otf mode, 0, enabled) */
		ret = exynos_smc(0x82004014, 1, 0, 1);
		if (ret)
			print_tsmux_wfdlogger(TSMUX_ERR, "exynos_smc ret %lu\n", ret);
		print_tsmux_wfdlogger(TSMUX_DBG_SFR, "TSMUX_HEX_OTF_CTRL %u\n", hex_ctrl->otf_enable);
		ctx->set_hex_info = false;
	}

	print_tsmux_wfdlogger(TSMUX_DBG_SFR, "--\n");
}

void tsmux_set_src_addr(struct tsmux_device *tsmux_dev,
	struct tsmux_buffer_info *buf_info)
{
	print_tsmux_wfdlogger(TSMUX_DBG_SFR, "++\n");

	if (tsmux_dev == NULL || buf_info == NULL)
		return;

	TSMUX_WRITEL(buf_info->dma_addr, TSMUX_SRC_BASE_ADDR);
	print_tsmux_wfdlogger(TSMUX_DBG_SFR, "src_addr 0x%llx\n", buf_info->dma_addr);

	print_tsmux_wfdlogger(TSMUX_DBG_SFR, "--\n");
}

void tsmux_set_src_len(struct tsmux_device *tsmux_dev, int src_len)
{
	print_tsmux_wfdlogger(TSMUX_DBG_SFR, "++\n");

	if (tsmux_dev == NULL)
		return;

	TSMUX_WRITEL(src_len, TSMUX_SRC_LEN_ADDR);
	print_tsmux_wfdlogger(TSMUX_DBG_SFR, "src_len %d\n", src_len);

	print_tsmux_wfdlogger(TSMUX_DBG_SFR, "--\n");
}

void tsmux_set_dst_addr(struct tsmux_device *tsmux_dev,
	struct tsmux_buffer_info *buf_info)
{
	print_tsmux_wfdlogger(TSMUX_DBG_SFR, "++\n");

	if (tsmux_dev == NULL || buf_info == NULL)
		return;

	TSMUX_WRITEL(buf_info->dma_addr, TSMUX_DST_BASE_ADDR);
	print_tsmux_wfdlogger(TSMUX_DBG_SFR, "dst_addr 0x%llx\n", buf_info->dma_addr);

	print_tsmux_wfdlogger(TSMUX_DBG_SFR, "--\n");
}

void tsmux_job_queue_pkt_ctrl(struct tsmux_device *tsmux_dev)
{
	int total_udelay;
	u32 pkt_ctrl_reg;

	print_tsmux_wfdlogger(TSMUX_DBG_SFR, "++\n");

	if (tsmux_dev == NULL)
		return;

	/* set pkt_ctrl_reg */
	pkt_ctrl_reg = TSMUX_READL(TSMUX_PKT_CTRL_ADDR);
	total_udelay = 0;
	while ((pkt_ctrl_reg & TSMUX_PKT_CTRL_ENQUEUE_MASK) &&
		total_udelay < 1000) {
		udelay(100);
		total_udelay += 100;
	}

	if (g_tsmux_debug_level >= TSMUX_DBG_SFR) {
		tsmux_print_tsmux_sfr(tsmux_dev);
		tsmux_print_dbg_info_all(tsmux_dev);
	}

	pkt_ctrl_reg &= ~(TSMUX_PKT_CTRL_ENQUEUE_MASK);
	pkt_ctrl_reg |= TSMUX_PKT_CTRL_ENQUEUE_MASK *
		(1 << TSMUX_PKT_CTRL_ENQUEUE_SHIFT);
	TSMUX_WRITEL(pkt_ctrl_reg, TSMUX_PKT_CTRL_ADDR);
	print_tsmux_wfdlogger(TSMUX_DBG_SFR, "write pkt_ctrl_reg 0x%x\n", pkt_ctrl_reg);

	print_tsmux_wfdlogger(TSMUX_DBG_SFR, "--\n");
}

bool tsmux_reset_pkt_ctrl(struct tsmux_device *tsmux_dev)
{
	u32 pkt_ctrl_reg;
	u32 cmd_ctrl_reg;
	int total_udelay = 0;
	bool ret = false;

	print_tsmux(TSMUX_DBG_SFR, "++\n");

	if (tsmux_dev == NULL)
		return ret;

	pkt_ctrl_reg = TSMUX_READL(TSMUX_PKT_CTRL_ADDR);
	print_tsmux(TSMUX_DBG_SFR, "read pkt_ctrl_reg 0x%x\n", pkt_ctrl_reg);

	pkt_ctrl_reg |= TSMUX_PKT_CTRL_SW_RESET_MASK &
		(1 << TSMUX_PKT_CTRL_SW_RESET_SHIFT);
	TSMUX_WRITEL(pkt_ctrl_reg, TSMUX_PKT_CTRL_ADDR);
	print_tsmux(TSMUX_DBG_SFR, "TSMUX_PKT_CTRL_SW_RESET\n");
	print_tsmux(TSMUX_DBG_SFR, "write pkt_ctrl_reg 0x%x\n", pkt_ctrl_reg);

	/* default is CONSECUTIVE mode */
	while (total_udelay < 1000) {
		TSMUX_WRITEL(TSMUX_CMD_CTRL_RESET_VALUE, TSMUX_CMD_CTRL_ADDR);
		cmd_ctrl_reg = TSMUX_READL(TSMUX_CMD_CTRL_ADDR);
		if (cmd_ctrl_reg == TSMUX_CMD_CTRL_RESET_VALUE) {
			ret = true;
			break;
		}
		udelay(100);
		total_udelay += 100;
		print_tsmux(TSMUX_ERR, "delay to set cmd_ctrl_reg\n");
	}
	print_tsmux(TSMUX_DBG_SFR, "write cmd_ctrl_reg 0x%x\n", cmd_ctrl_reg);

	print_tsmux(TSMUX_DBG_SFR, "--\n");

	return ret;
}

void tsmux_enable_int_job_done(struct tsmux_device *tsmux_dev, bool need_partial_done)
{
	u32 int_en_reg;
	u32 partial_data_size = 0;

	print_tsmux_wfdlogger(TSMUX_DBG_SFR, "++\n");

	if (tsmux_dev == NULL)
		return;

	/* enable interrupt */
	int_en_reg = TSMUX_READL(TSMUX_INT_EN_ADDR);
	int_en_reg |= TSMUX_INT_EN_JOB_DONE;

	if (need_partial_done && g_enable_partial_done) {
		int_en_reg |= TSMUX_INT_EN_PART_DONE;
		partial_data_size = (RTP_HEADER_SIZE + TS_PACKET_SIZE * TS_PKT_COUNT_PER_RTP)
			* g_rtp_pkt_count_per_partial_data;
		TSMUX_WRITEL(partial_data_size, TSMUX_PART_TH_ADDR);
		partial_data_size = TSMUX_READL(TSMUX_PART_TH_ADDR);
		print_tsmux_wfdlogger(TSMUX_DBG_SFR, "read part_th 0x%x\n", partial_data_size);
	} else {
		int_en_reg &= ~(TSMUX_INT_EN_PART_DONE);
	}
	TSMUX_WRITEL(int_en_reg, TSMUX_INT_EN_ADDR);
	print_tsmux_wfdlogger(TSMUX_DBG_SFR, "write int_en_reg 0x%x\n", int_en_reg);
	int_en_reg = TSMUX_READL(TSMUX_INT_EN_ADDR);
	print_tsmux_wfdlogger(TSMUX_DBG_SFR, "read int_en_reg 0x%x\n", int_en_reg);

	print_tsmux_wfdlogger(TSMUX_DBG_SFR, "--\n");
}

void tsmux_disable_int_job_done(struct tsmux_device *tsmux_dev)
{
	u32 int_en_reg;

	print_tsmux_wfdlogger(TSMUX_DBG_SFR, "++\n");

	if (tsmux_dev == NULL)
		return;

	/* enable interrupt */
	int_en_reg = TSMUX_READL(TSMUX_INT_EN_ADDR);
	print_tsmux_wfdlogger(TSMUX_DBG_SFR, "read int_en_reg 0x%x\n", int_en_reg);

	int_en_reg &= ~(TSMUX_INT_EN_JOB_DONE);
	TSMUX_WRITEL(int_en_reg, TSMUX_INT_EN_ADDR);
	print_tsmux_wfdlogger(TSMUX_DBG_SFR, "write int_en_reg 0x%x\n", int_en_reg);
	int_en_reg = TSMUX_READL(TSMUX_INT_EN_ADDR);
	print_tsmux_wfdlogger(TSMUX_DBG_SFR, "read int_en_reg 0x%x\n", int_en_reg);

	print_tsmux_wfdlogger(TSMUX_DBG_SFR, "--\n");
}

void tsmux_set_cmd_ctrl(struct tsmux_device *tsmux_dev, int mode)
{
	u32 cmd_ctrl_reg;

	print_tsmux_wfdlogger(TSMUX_DBG_SFR, "++\n");

	if (tsmux_dev == NULL)
		return;

	cmd_ctrl_reg = TSMUX_READL(TSMUX_CMD_CTRL_ADDR);
	print_tsmux_wfdlogger(TSMUX_DBG_SFR, "read cmd_ctrl_reg 0x%x\n", cmd_ctrl_reg);

	cmd_ctrl_reg = TSMUX_CMD_CTRL_MODE_MASK &
		(mode << TSMUX_CMD_CTRL_MODE_SHIFT);
	TSMUX_WRITEL(cmd_ctrl_reg, TSMUX_CMD_CTRL_ADDR);
	print_tsmux_wfdlogger(TSMUX_DBG_SFR, "write cmd_ctrl_reg 0x%x\n", cmd_ctrl_reg);

	print_tsmux_wfdlogger(TSMUX_DBG_SFR, "--\n");
}

bool tsmux_check_interrupt_stat(struct tsmux_device *tsmux_dev, int job_id, bool partial)
{
	u32 int_stat_reg;
	bool ret = false;

	print_tsmux_wfdlogger(TSMUX_DBG_SFR, "++\n");

	if (tsmux_dev == NULL)
		return ret;

	int_stat_reg = TSMUX_READL(TSMUX_INT_STAT_ADDR);
	print_tsmux_wfdlogger(TSMUX_DBG_SFR, "job_id %d, read int_stat_reg 0x%x\n", job_id, int_stat_reg);

	if (partial)  {
		switch(job_id) {
		case 0:
			if (int_stat_reg & TSMUX_INT_STAT_PART_ID_0_DONE)
				ret = true;
			break;
		case 1:
			if (int_stat_reg & TSMUX_INT_STAT_PART_ID_1_DONE)
				ret = true;
			break;
		case 2:
			if (int_stat_reg & TSMUX_INT_STAT_PART_ID_2_DONE)
				ret = true;
			break;
		case 3:
			if (int_stat_reg & TSMUX_INT_STAT_PART_ID_3_DONE)
				ret = true;
			break;
		}
	} else {
		switch(job_id) {
		case 0:
			if (int_stat_reg & TSMUX_INT_STAT_JOB_ID_0_DONE)
				ret = true;
			break;
		case 1:
			if (int_stat_reg & TSMUX_INT_STAT_JOB_ID_1_DONE)
				ret = true;
			break;
		case 2:
			if (int_stat_reg & TSMUX_INT_STAT_JOB_ID_2_DONE)
				ret = true;
			break;
		case 3:
			if (int_stat_reg & TSMUX_INT_STAT_JOB_ID_3_DONE)
				ret = true;
			break;
		}
	}

	print_tsmux_wfdlogger(TSMUX_DBG_SFR, "--\n");

	return ret;
}

bool tsmux_is_job_done_id_0(struct tsmux_device *tsmux_dev)
{
	return tsmux_check_interrupt_stat(tsmux_dev, 0, false /* job done */);
}

bool tsmux_is_job_done_id_1(struct tsmux_device *tsmux_dev)
{
	return tsmux_check_interrupt_stat(tsmux_dev, 1, false /* job done */);
}

bool tsmux_is_job_done_id_2(struct tsmux_device *tsmux_dev)
{
	return tsmux_check_interrupt_stat(tsmux_dev, 2, false /* job done */);
}

bool tsmux_is_job_done_id_3(struct tsmux_device *tsmux_dev)
{
	return tsmux_check_interrupt_stat(tsmux_dev, 3, false /* job done */);
}

void tsmux_clear_job_done(struct tsmux_device *tsmux_dev, int job_id)
{
	u32 int_stat_reg;

	print_tsmux_wfdlogger(TSMUX_DBG_SFR, "++\n");

	if (tsmux_dev == NULL)
		return;

	int_stat_reg = TSMUX_INT_STAT_JOB_DONE_MASK & (1 << job_id);
	TSMUX_WRITEL(int_stat_reg, TSMUX_INT_STAT_ADDR);
	int_stat_reg = TSMUX_READL(TSMUX_INT_STAT_ADDR);
	print_tsmux_wfdlogger(TSMUX_DBG_SFR, "read int_stat_reg 0x%x\n", int_stat_reg);

	print_tsmux_wfdlogger(TSMUX_DBG_SFR, "--\n");
}

bool tsmux_is_partial_done_id_0(struct tsmux_device *tsmux_dev)
{
	return tsmux_check_interrupt_stat(tsmux_dev, 0, true /* partial done */);
}

bool tsmux_is_partial_done_id_1(struct tsmux_device *tsmux_dev)
{
	return tsmux_check_interrupt_stat(tsmux_dev, 1, true /* partial done */);
}

bool tsmux_is_partial_done_id_2(struct tsmux_device *tsmux_dev)
{
	return tsmux_check_interrupt_stat(tsmux_dev, 2, true /* partial done */);
}

bool tsmux_is_partial_done_id_3(struct tsmux_device *tsmux_dev)
{
	return tsmux_check_interrupt_stat(tsmux_dev, 3, true /* partial done */);
}

void tsmux_clear_partial_done(struct tsmux_device *tsmux_dev, u32 job_id)
{
	u32 int_stat_reg;
	u32 value;

	print_tsmux_wfdlogger(TSMUX_DBG_SFR, "++\n");

	if (tsmux_dev == NULL)
		return;

	value = 0x1 << TSMUX_INT_STAT_PART_DONE_SHIFT;
	value = value << job_id;
	int_stat_reg = TSMUX_INT_STAT_PART_DONE_MASK & value;
	print_tsmux_wfdlogger(TSMUX_DBG_SFR, "write int_stat_reg 0x%x\n", int_stat_reg);
	TSMUX_WRITEL(int_stat_reg, TSMUX_INT_STAT_ADDR);
	int_stat_reg = TSMUX_READL(TSMUX_INT_STAT_ADDR);
	print_tsmux_wfdlogger(TSMUX_DBG_SFR, "read int_stat_reg 0x%x\n", int_stat_reg);

	print_tsmux_wfdlogger(TSMUX_DBG_SFR, "--\n");
}

int tsmux_get_dst_len(struct tsmux_device *tsmux_dev, int job_id)
{
	u32 dst_len_reg = 0;

	print_tsmux_wfdlogger(TSMUX_DBG_SFR, "++\n");

	if (tsmux_dev == NULL)
		return dst_len_reg;

	dst_len_reg = TSMUX_READL(TSMUX_DST_LEN0_ADDR + job_id * 4);
	print_tsmux_wfdlogger(TSMUX_DBG_SFR, "read dst_len_reg 0x%x, job_id %d\n",
		dst_len_reg, job_id);

	print_tsmux_wfdlogger(TSMUX_DBG_SFR, "--\n");

	return dst_len_reg;
}

#ifdef ASB_TEST
void tsmux_set_normal_sfr_cmd(
		struct tsmux_device *tsmux_dev, struct tsmux_reg *cmd, int count)
{
	int i;

	print_tsmux(TSMUX_DBG_SFR, "++\n");

	if (tsmux_dev == NULL)
		return;

	for (i = 0; i < count; i++) {
		print_tsmux(TSMUX_DBG_SFR, "addr 0x%.8x, value 0x%.8x\n", cmd[i].addr, cmd[i].value);
		TSMUX_WRITEL(cmd[i].value, cmd[i].addr);
	}
	print_tsmux(TSMUX_DBG_SFR, "--\n");
}

void tsmux_set_secure_sfr_cmd(
		struct tsmux_device *tsmux_dev, struct tsmux_reg *cmd, int count)
{
	int i;
	int ret;

	print_tsmux(TSMUX_DBG_SFR, "++: count: %d\n", count);

	if (tsmux_dev == NULL)
		return;

	for (i = 0; i < count; i++) {
		print_tsmux(TSMUX_DBG_SFR, "addr 0x%.8x, value 0x%.8x, i: %d\n", cmd[i].addr, cmd[i].value, i);
		ret = exynos_smc(0x82004007, TSMUX_HEX_BASE_ADDR + cmd[i].addr, cmd[i].value, 0);
		print_tsmux(TSMUX_DBG_SFR, "smc call ret: %x\n", ret);
	}

	print_tsmux(TSMUX_DBG_SFR, "--\n");
}
#endif
