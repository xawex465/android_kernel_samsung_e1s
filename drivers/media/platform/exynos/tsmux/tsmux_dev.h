/*
 * Copyright (c) 2017 Samsung Electronics Co., Ltd.
 * http://www.samsung.com
 *
 * Header file for Exynos TSMUX driver
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#ifndef TSMUX_DEV_H
#define TSMUX_DEV_H

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/device.h>
#include <linux/version.h>
#include <linux/platform_device.h>
#include <linux/miscdevice.h>
#include <linux/types.h>
#include <linux/dma-buf.h>
#include <linux/iosys-map.h>
#include <linux/wait.h>
#include <media/exynos_tsmux.h>
#if IS_ENABLED(CONFIG_EXYNOS_ITMON) || IS_ENABLED(CONFIG_EXYNOS_ITMON_V2)
#include <soc/samsung/exynos/exynos-itmon.h>
#define CONFIG_EXYNOS_ITMON
#endif

#include "tsmux.h"

#define MAX_SHARED_BUFFER_NUM		3

/* When testing ASB, Enable ASB_TEST and define HEX register */
//#define ASB_TEST
//#define TSMUX_HEX_BASE_ADDR (0xFFFFFFFF)

#define TS_PKT_COUNT_PER_RTP    7
#define RTP_HEADER_SIZE     12
#define TS_PACKET_SIZE      188

enum error_info {
	TSMUX_OK,
	TSMUX_ERR_TEST,
	TSMUX_ERR_ITMON,
	TSMUX_ERR_SYSMMU,
	TSMUX_ERR_WATCHDOG,
};

enum otf_buf_state {
	BUF_FREE,
	BUF_PART_DONE,
	BUF_JOB_DONE,
	BUF_DQ,
	BUF_Q,
};

struct tsmux_buffer_info {
	struct dma_buf *dmabuf;
	struct dma_buf_attachment *dmabuf_att;
	struct sg_table *sgt;
	dma_addr_t dma_addr;
	struct iosys_map map;
	void *vaddr;
	enum otf_buf_state buf_state;
};

struct tsmux_watchdog_tick {
	atomic_t watchdog_tick_running;
	atomic_t watchdog_tick_count;
};

struct tsmux_device {
	struct miscdevice misc_dev;
	struct device *dev;

	uint32_t hw_version;
	void __iomem *regs_base;
	void __iomem *regs_base_cmu_mfc;
	struct resource *tsmux_mem;
	struct clk *tsmux_clock;
	int irq;

	spinlock_t device_spinlock;

	atomic_t ctx_num;

#ifdef CONFIG_EXYNOS_ITMON
	struct notifier_block itmon_nb;
#endif
	struct timer_list watchdog_timer;
	struct work_struct watchdog_work;
	struct tsmux_watchdog_tick watchdog_tick[TSMUX_MAX_CMD_QUEUE_NUM];

	struct tsmux_context *ctx[TSMUX_MAX_CONTEXTS_NUM];

	enum error_info error;
};

struct tsmux_context {
	struct tsmux_device *tsmux_dev;

	struct tsmux_psi_info psi_info;
	struct tsmux_m2m_cmd_queue m2m_cmd_queue;
	struct tsmux_otf_cmd_queue otf_cmd_queue;

	struct tsmux_buffer_info m2m_inbuf_info[TSMUX_MAX_M2M_CMD_QUEUE_NUM];
	struct tsmux_buffer_info m2m_outbuf_info[TSMUX_MAX_M2M_CMD_QUEUE_NUM];
	struct tsmux_buffer_info otf_outbuf_info[TSMUX_OUT_BUF_CNT];
	struct tsmux_buffer_info sfr_dump_buf_info;

	struct tsmux_rtp_ts_info rtp_ts_info;

	int es_size;
	bool set_hex_info;

	bool otf_psi_enabled[TSMUX_OUT_BUF_CNT];
	bool otf_buf_mapped;
	bool otf_dummy_ts_packet;

	wait_queue_head_t m2m_wait_queue;
	wait_queue_head_t otf_wait_queue;
	bool m2m_job_done[TSMUX_MAX_M2M_CMD_QUEUE_NUM];

	uint64_t audio_frame_count;
	uint64_t video_frame_count;
	uint64_t otf_job_queued_count;
	uint64_t otf_job_done_count;

	uint64_t blending_start_stamp[MAX_SHARED_BUFFER_NUM];
	uint64_t blending_end_stamp[MAX_SHARED_BUFFER_NUM];
	uint32_t mfc_encoding_index;
	uint64_t mfc_start_stamp;
	uint64_t mfc_end_stamp;
	uint64_t tsmux_start_stamp;
	uint64_t tsmux_end_stamp;

	/* log level */
	int remain_logging_frame;

#ifdef ASB_TEST
	struct tsmux_asb_job asb_job;
#endif
};

#define NODE_NAME		"tsmux"
#define MODULE_NAME		"exynos-tsmux"

#define TSMUX_TIMEOUT		1000

#endif /* TSMUX_DEV_H */
