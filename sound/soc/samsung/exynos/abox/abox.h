/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * ALSA SoC - Samsung Abox driver
 *
 * Copyright (c) 2016 Samsung Electronics Co. Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#ifndef __SND_SOC_ABOX_H
#define __SND_SOC_ABOX_H

#include <sound/samsung/abox.h>
#include <linux/miscdevice.h>
#include <linux/dma-direction.h>
#include <soc/samsung/exynos/memlogger.h>
#include <soc/samsung/exynos/sysevent.h>
#include "abox_qos.h"

#define DEFAULT_CPU_GEAR_ID		(0xAB0CDEFA)
#define TEST_CPU_GEAR_ID		(DEFAULT_CPU_GEAR_ID + 1)
#define DEFAULT_LIT_FREQ_ID		DEFAULT_CPU_GEAR_ID
#define DEFAULT_BIG_FREQ_ID		DEFAULT_CPU_GEAR_ID
#define DEFAULT_HMP_BOOST_ID		DEFAULT_CPU_GEAR_ID
#define DEFAULT_INT_FREQ_ID		DEFAULT_CPU_GEAR_ID
#define DEFAULT_MIF_FREQ_ID		DEFAULT_CPU_GEAR_ID
#define DEFAULT_SYS_POWER_ID		DEFAULT_CPU_GEAR_ID

#define BUFFER_BYTES_MIN		(SZ_64K)
#define BUFFER_BYTES_MAX		(SZ_1M)
#define BUFFER_BYTES_DEEP		(SZ_256K)
#define PERIOD_BYTES_MIN		(SZ_16)
#define PERIOD_BYTES_MAX		(BUFFER_BYTES_MAX / 2)

#define SRAM_FIRMWARE_SIZE              CONFIG_SND_SOC_SAMSUNG_ABOX_SRAM_SIZE
#define DRAM_FIRMWARE_SIZE		CONFIG_SND_SOC_SAMSUNG_ABOX_DRAM_SIZE
#define DRAM_PARAMETER_SIZE		CONFIG_SND_SOC_SAMSUNG_ABOX_PARAM_SIZE
#define IOVA_DRAM_PARAMETER		(0x70000000)
#define IOVA_DRAM_FIRMWARE		(0x80000000)
#define IOVA_RDMA_BUFFER_BASE		(0x91000000)
#define IOVA_RDMA_BUFFER(x)		(IOVA_RDMA_BUFFER_BASE + (SZ_1M * (x)))
#define IOVA_WDMA_BUFFER_BASE		(0x92000000)
#define IOVA_WDMA_BUFFER(x)		(IOVA_WDMA_BUFFER_BASE + (SZ_1M * (x)))
#define IOVA_COMPR_BUFFER_BASE		(0x93000000)
#define IOVA_COMPR_BUFFER(x)		(IOVA_COMPR_BUFFER_BASE + (SZ_1M * (x)))
#define IOVA_VDMA_BUFFER_BASE		(0x94000000)
#define IOVA_VDMA_BUFFER(x)		(IOVA_VDMA_BUFFER_BASE + (SZ_1M * (x)))
#define IOVA_DUAL_BUFFER_BASE		(0x98000000)
#define IOVA_DUAL_BUFFER(x)		(IOVA_DUAL_BUFFER_BASE + (SZ_1M * (x)))
#define IOVA_DDMA_BUFFER_BASE		(0x99000000)
#define IOVA_DDMA_BUFFER(x)		(IOVA_DDMA_BUFFER_BASE + (SZ_1M * (x)))
#define IOVA_UDMA_RD_BUFFER_BASE	(0x9C000000)
#define IOVA_UDMA_RD_BUFFER(x)		(IOVA_UDMA_RD_BUFFER_BASE + \
	(SZ_1M * (x)))
#define IOVA_UDMA_WR_BUFFER_BASE	(0x9C400000)
#define IOVA_UDMA_WR_BUFFER(x)		(IOVA_UDMA_WR_BUFFER_BASE + \
	(SZ_1M * (x)))
#define IOVA_UDMA_WR_DUAL_BUFFER_BASE	(0x9C800000)
#define IOVA_UDMA_WR_DUAL_BUFFER(x)	(IOVA_UDMA_WR_DUAL_BUFFER_BASE + \
	(SZ_1M * (x)))
#define IOVA_UDMA_WR_DBG_BUFFER_BASE	(0x9CC00000)
#define IOVA_UDMA_WR_DBG_BUFFER(x)	(IOVA_UDMA_WR_DBG_BUFFER_BASE + \
	(SZ_1M * (x)))
#define IOVA_VSS_FIRMWARE		(0xA0000000)
#define IOVA_VSS_FIRMWARE_WIFI		(0xA0600000)
#define IOVA_VSS_PARAMETER		(0xA1000000)
#define IOVA_VSS_PCI			(0xA2000000)
#define IOVA_VSS_PCI_DOORBELL		(0xA3000000)
#define IOVA_DUMP_BUFFER		(0xD0000000)
#define IOVA_SILENT_LOG			(0xE0000000)
#define PHSY_VSS_FIRMWARE		(0xFEE00000)
#if IS_ENABLED(CONFIG_SOC_S5E8845)
#define PHSY_VSS_SIZE                   (0x700000)
#else
#define PHSY_VSS_SIZE			(SZ_8M)
#endif

#define ABOX_LOG_OFFSET			(0xb00000)
#define ABOX_LOG_MAJOR_OFFSET		(0x900000)
#define ABOX_LOG_SIZE			(SZ_1M)
#define ABOX_SLOG_OFFSET		(9 * SZ_1M)
#define ABOX_SLOG_DATA_OFFSET		(ABOX_SLOG_OFFSET + 0x10)
#define ABOX_PCI_DOORBELL_OFFSET	(0x10000)
#define ABOX_PCI_DOORBELL_SIZE		(SZ_64K)

#define LIMIT_IN_JIFFIES		(msecs_to_jiffies(1000))

#define ABOX_CPU_GEAR_CALL_VSS		(0xCA11)
#define ABOX_CPU_GEAR_CALL_KERNEL	(0xCA12)
#define ABOX_CPU_GEAR_CALL		ABOX_CPU_GEAR_CALL_VSS
#define ABOX_CPU_GEAR_ABSOLUTE		(0xABC0ABC0)
#define ABOX_CPU_GEAR_BOOT		(0xB00D)
#define ABOX_CPU_GEAR_MAX		(1)
#define ABOX_CPU_GEAR_MIN		(100)
#define ABOX_CPU_GEAR_DAI		0xDA100000

#define ABOX_SAMPLING_RATES (SNDRV_PCM_RATE_KNOT)
#define ABOX_SAMPLE_FORMATS (SNDRV_PCM_FMTBIT_S16\
		| SNDRV_PCM_FMTBIT_S24\
		| SNDRV_PCM_FMTBIT_S24_3LE\
		| SNDRV_PCM_FMTBIT_S32)

#define ABOX_SUPPLEMENT_SIZE (SZ_128)
#define ABOX_IPC_QUEUE_SIZE (SZ_128)

#define CALLIOPE_VERSION(class, year, month, minor) \
		((class << 24) | \
		((year - 1 + 'A') << 16) | \
		((month - 1 + 'A') << 8) | \
		((minor + '0') << 0))

#define ABOX_QUIRK_BIT_ARAM_MODE	BIT(0)
#define ABOX_QUIRK_STR_ARAM_MODE	"aram mode"
#define ABOX_QUIRK_BIT_INT_SKEW		BIT(1)
#define ABOX_QUIRK_STR_INT_SKEW		"int skew"
#define ABOX_QUIRK_BIT_SILENT_RESET	BIT(2)
#define ABOX_QUIRK_STR_SILENT_RESET	"silent reset"

enum abox_dai {
	ABOX_NONE,
	ABOX_SIFSM,
	ABOX_SIFST,
	ABOX_RDMA0 = 0x10,
	ABOX_RDMA1,
	ABOX_RDMA2,
	ABOX_RDMA3,
	ABOX_RDMA4,
	ABOX_RDMA5,
	ABOX_RDMA6,
	ABOX_RDMA7,
	ABOX_RDMA8,
	ABOX_RDMA9,
	ABOX_RDMA10,
	ABOX_RDMA11,
	ABOX_RDMA12,
	ABOX_RDMA13,
	ABOX_RDMA14,
	ABOX_RDMA15,
	ABOX_WDMA0 = 0x20,
	ABOX_WDMA1,
	ABOX_WDMA2,
	ABOX_WDMA3,
	ABOX_WDMA4,
	ABOX_WDMA5,
	ABOX_WDMA6,
	ABOX_WDMA7,
	ABOX_WDMA8,
	ABOX_WDMA9,
	ABOX_WDMA10,
	ABOX_WDMA11,
	ABOX_WDMA0_DUAL = 0x30,
	ABOX_WDMA1_DUAL,
	ABOX_WDMA2_DUAL,
	ABOX_WDMA3_DUAL,
	ABOX_WDMA4_DUAL,
	ABOX_WDMA5_DUAL,
	ABOX_WDMA6_DUAL,
	ABOX_WDMA7_DUAL,
	ABOX_WDMA8_DUAL,
	ABOX_WDMA9_DUAL,
	ABOX_WDMA10_DUAL,
	ABOX_WDMA11_DUAL,
	ABOX_DDMA0 = 0x40,
	ABOX_DDMA1,
	ABOX_DDMA2,
	ABOX_DDMA3,
	ABOX_DDMA4,
	ABOX_DDMA5,
	ABOX_UAIF0 = 0x50,
	ABOX_UAIF1,
	ABOX_UAIF2,
	ABOX_UAIF3,
	ABOX_UAIF4,
	ABOX_UAIF5,
	ABOX_UAIF6,
	ABOX_DSIF,
	ABOX_SPDY,
	ABOX_RDMA0_BE = 0x60,
	ABOX_RDMA1_BE,
	ABOX_RDMA2_BE,
	ABOX_RDMA3_BE,
	ABOX_RDMA4_BE,
	ABOX_RDMA5_BE,
	ABOX_RDMA6_BE,
	ABOX_RDMA7_BE,
	ABOX_RDMA8_BE,
	ABOX_RDMA9_BE,
	ABOX_RDMA10_BE,
	ABOX_RDMA11_BE,
	ABOX_RDMA12_BE,
	ABOX_RDMA13_BE,
	ABOX_RDMA14_BE,
	ABOX_RDMA15_BE,
	ABOX_WDMA0_BE = 0x70,
	ABOX_WDMA1_BE,
	ABOX_WDMA2_BE,
	ABOX_WDMA3_BE,
	ABOX_WDMA4_BE,
	ABOX_WDMA5_BE,
	ABOX_WDMA6_BE,
	ABOX_WDMA7_BE,
	ABOX_WDMA8_BE,
	ABOX_WDMA9_BE,
	ABOX_WDMA10_BE,
	ABOX_WDMA11_BE,
	ABOX_SIFS0 = 0x80, /* Virtual DAI */
	ABOX_SIFS1, /* Virtual DAI */
	ABOX_SIFS2, /* Virtual DAI */
	ABOX_SIFS3, /* Virtual DAI */
	ABOX_SIFS4, /* Virtual DAI */
	ABOX_SIFS5, /* Virtual DAI */
	ABOX_SIFS6, /* Virtual DAI */
	ABOX_SIFS7, /* Virtual DAI */
	ABOX_NSRC0 = 0x90, /* Virtual DAI */
	ABOX_NSRC1, /* Virtual DAI */
	ABOX_NSRC2, /* Virtual DAI */
	ABOX_NSRC3, /* Virtual DAI */
	ABOX_NSRC4, /* Virtual DAI */
	ABOX_NSRC5, /* Virtual DAI */
	ABOX_NSRC6, /* Virtual DAI */
	ABOX_NSRC7, /* Virtual DAI */
	ABOX_NSRC8, /* Virtual DAI */
	ABOX_NSRC9, /* Virtual DAI */
	ABOX_NSRC10, /* Virtual DAI */
	ABOX_NSRC11, /* Virtual DAI */
	ABOX_USB = 0xA0, /* Virtual DAI */
	ABOX_FWD, /* Virtual DAI */
	ABOX_UDMA_RD0 = 0xC0,
	ABOX_UDMA_RD1,
	ABOX_UDMA_WR0,
	ABOX_UDMA_WR1,
	ABOX_UDMA_WR0_DUAL,
	ABOX_UDMA_WR1_DUAL,
	ABOX_UDMA_WR_DBG0,
};

/* SIFS should be treated as DAI to manage bclk usage and count value */
#define ABOX_DAI_COUNT (ABOX_NSRC0 - ABOX_UAIF0 + 1)

enum abox_widget {
	ABOX_WIDGET_SPUS_IN0,
	ABOX_WIDGET_SPUS_IN1,
	ABOX_WIDGET_SPUS_IN2,
	ABOX_WIDGET_SPUS_IN3,
	ABOX_WIDGET_SPUS_IN4,
	ABOX_WIDGET_SPUS_IN5,
	ABOX_WIDGET_SPUS_IN6,
	ABOX_WIDGET_SPUS_IN7,
	ABOX_WIDGET_SPUS_IN8,
	ABOX_WIDGET_SPUS_IN9,
	ABOX_WIDGET_SPUS_IN10,
	ABOX_WIDGET_SPUS_IN11,
	ABOX_WIDGET_SPUS_IN12,
	ABOX_WIDGET_SPUS_IN13,
	ABOX_WIDGET_SPUS_IN14,
	ABOX_WIDGET_SPUS_IN15,
	ABOX_WIDGET_SPUS_ASRC0,
	ABOX_WIDGET_SPUS_ASRC1,
	ABOX_WIDGET_SPUS_ASRC2,
	ABOX_WIDGET_SPUS_ASRC3,
	ABOX_WIDGET_SPUS_ASRC4,
	ABOX_WIDGET_SPUS_ASRC5,
	ABOX_WIDGET_SPUS_ASRC6,
	ABOX_WIDGET_SPUS_ASRC7,
	ABOX_WIDGET_SIFS0,
	ABOX_WIDGET_SIFS1,
	ABOX_WIDGET_SIFS2,
	ABOX_WIDGET_SIFS3,
	ABOX_WIDGET_SIFS4,
	ABOX_WIDGET_SIFS5,
	ABOX_WIDGET_SIFS6,
	ABOX_WIDGET_SIFS7,
	ABOX_WIDGET_SPUS_SSRC0,
	ABOX_WIDGET_SPUS_SSRC1,
	ABOX_WIDGET_SPUS_SSRC2,
	ABOX_WIDGET_SPUS_SSRC3,
	ABOX_WIDGET_NSRC0,
	ABOX_WIDGET_NSRC1,
	ABOX_WIDGET_NSRC2,
	ABOX_WIDGET_NSRC3,
	ABOX_WIDGET_NSRC4,
	ABOX_WIDGET_NSRC5,
	ABOX_WIDGET_NSRC6,
	ABOX_WIDGET_NSRC7,
	ABOX_WIDGET_NSRC8,
	ABOX_WIDGET_NSRC9,
	ABOX_WIDGET_NSRC10,
	ABOX_WIDGET_NSRC11,
	ABOX_WIDGET_SPUM_ASRC0,
	ABOX_WIDGET_SPUM_ASRC1,
	ABOX_WIDGET_SPUM_ASRC2,
	ABOX_WIDGET_SPUM_ASRC3,
	ABOX_WIDGET_UDMA_RD0,
	ABOX_WIDGET_UDMA_RD1,
	ABOX_WIDGET_UDMA_WR0,
	ABOX_WIDGET_UDMA_WR1,
	ABOX_WIDGET_COUNT,
};

enum calliope_state {
	CALLIOPE_DISABLED,
	CALLIOPE_DISABLING,
	CALLIOPE_ENABLING,
	CALLIOPE_ENABLED,
	CALLIOPE_STATE_COUNT,
};

enum system_state {
	SYSTEM_CALL,
	SYSTEM_OFFLOAD,
	SYSTEM_IDLE,
	SYSTEM_STATE_COUNT
};

enum audio_mode {
	MODE_NORMAL,
	MODE_RINGTONE,
	MODE_IN_CALL,
	MODE_IN_COMMUNICATION,
	MODE_IN_VIDEOCALL,
	MODE_RESERVED0,
	MODE_RESERVED1,
	MODE_IN_LOOPBACK,
};

enum sound_type {
	SOUND_TYPE_VOICE,
	SOUND_TYPE_SPEAKER,
	SOUND_TYPE_HEADSET,
	SOUND_TYPE_BTVOICE,
	SOUND_TYPE_USB,
	SOUND_TYPE_CALLFWD,
};

enum qchannel {
	ABOX_CCLK_CORE,
	ABOX_ACLK,
	ABOX_BCLK_UAIF0,
	ABOX_BCLK_UAIF1,
	ABOX_BCLK_UAIF2,
	ABOX_BCLK_UAIF3,
	ABOX_BCLK_UAIF4,
	ABOX_BCLK_UAIF5,
	ABOX_BCLK_UAIF6,
	ABOX_BCLK_RESERVED,
	ABOX_BCLK_DSIF,
	ABOX_CCLK_ASB = 16,
	ABOX_PCMC_CLK,
	ABOX_XCLK0,
	ABOX_XCLK1,
	ABOX_XCLK2,
	ABOX_CCLK_ACP,
};

enum mux_pcmc {
	ABOX_PCMC_OSC,
	ABOX_PCMC_CP,
	ABOX_PCMC_AUD,
	ABOX_PCMC_COUNT,
};

enum debug_mode {
	DEBUG_MODE_NONE,
	DEBUG_MODE_DRAM,
	DEBUG_MODE_FILE,
	DEBUG_MODE_COUNT,
};

enum offset_mask { OFFSET, MASK, OFFSET_MASK };

struct abox_ipc {
	struct device *dev;
	int hw_irq;
	unsigned long long put_time;
	unsigned long long get_time;
	size_t size;
	ABOX_IPC_MSG msg;
};

struct abox_ipc_action {
	struct list_head list;
	const struct device *dev;
	int ipc_id;
	abox_ipc_handler_t handler;
	void *data;
};

struct abox_iommu_mapping {
	struct list_head list;
	unsigned long iova;	/* IO virtual address */
	unsigned char *area;	/* virtual pointer */
	dma_addr_t addr;	/* physical address */
	size_t bytes;		/* buffer size in bytes */
};

struct abox_dram_request {
	unsigned int id;
	bool on;
	unsigned long long updated;
};

struct abox_extra_firmware {
	struct list_head list;
	struct mutex lock;
	const struct firmware *firmware;
	char name[SZ_32];
	unsigned int idx;
	unsigned int area;
	unsigned int offset;
	unsigned int iova;
	bool changeable;
};

struct abox_event_notifier {
	void *priv;
	int (*notify)(void *priv, bool en);
};

struct abox_component {
	struct ABOX_COMPONENT_DESCRIPTIOR *desc;
	bool registered;
	struct list_head value_list;
};

struct abox_component_kcontrol_value {
	struct ABOX_COMPONENT_DESCRIPTIOR *desc;
	struct ABOX_COMPONENT_CONTROL *control;
	struct list_head list;
	bool cache_only;
	int cache[];
};

struct abox_conf_tuple {
	struct list_head list;
	const char *name;
	const char *value;
};

struct abox_conf_node {
	struct list_head list;
	const char *name;
	const char *compatible;
	struct list_head tuples;
};

struct abox_conf {
	char *buffer;
	struct list_head nodes;
};

struct abox_sram_vts {
	struct device *dev;
	bool enable;
	bool enabled;
	struct work_struct request_work;
};

struct abox_pcmc {
	struct clk *clk_cp_pcmc;
	struct clk *clk_aud_pcmc;
	enum mux_pcmc next;
	enum mux_pcmc cur;
	unsigned long rate_osc;
	unsigned long rate_cp_pcmc;
	unsigned long rate_aud_pcmc;
	struct work_struct request_work;
};

struct abox_data {
	struct device *dev;
	struct snd_soc_component *cmpnt;
	struct regmap *regmap;
	struct regmap *timer_regmap;
	void __iomem *sfr_base;
	void __iomem *sysreg_base;
	void __iomem *sram_base;
	void __iomem *timer_base;
	phys_addr_t sfr_phys;
	size_t sfr_size;
	phys_addr_t sysreg_phys;
	size_t sysreg_size;
	phys_addr_t sram_phys;
	void *dram_base;
	dma_addr_t dram_phys;
	void *dram_para_base;
	dma_addr_t dram_para_phys;
	void *dump_base;
	phys_addr_t dump_phys;
	void *slog_base;
	phys_addr_t slog_phys;
	size_t slog_size;
	struct iommu_domain *iommu_domain;
	void *ipc_tx_addr;
	size_t ipc_tx_size;
	void *ipc_rx_addr;
	size_t ipc_rx_size;
	unsigned int log_addr;
	unsigned int log_major_addr;
	void *shm_addr;
	size_t shm_size;
	struct abox2host_hndshk_tag *hndshk_tag;
	unsigned int bootargs_offset;
	unsigned int slogargs_offset;
	unsigned int if_count;
	unsigned int rdma_count;
	unsigned int wdma_count;
	unsigned int udma_rd_count;
	unsigned int udma_wr_count;
	unsigned int calliope_version;
	struct abox_conf conf;
	struct list_head firmware_extra;
	const char *bootargs;
	const char *file_name[2];
	struct device *dev_gic;
	struct device *dev_if[9];
	struct device *dev_rdma[16];
	struct device *dev_wdma[16];
	struct device *dev_udma_rd[4];
	struct device *dev_udma_wr[4];
	struct workqueue_struct *ipc_workqueue;
	struct work_struct ipc_work;
	struct abox_ipc ipc_queue[ABOX_IPC_QUEUE_SIZE];
	int ipc_queue_start;
	int ipc_queue_end;
	spinlock_t ipc_queue_lock;
	wait_queue_head_t ipc_wait_queue;
	wait_queue_head_t boot_wait_queue;
	wait_queue_head_t wait_queue;
	wait_queue_head_t offline_poll_wait;
	wait_queue_head_t udma_fade_done;
	struct clk *clk_pll;
	struct clk *clk_pll1;
	struct clk *clk_audif;
	struct clk *clk_cpu;
	struct clk *clk_dmic;
	struct clk *clk_bus;
	struct clk *clk_cnt;
	struct clk *clk_sclk;
	unsigned int uaif_max_div;
	struct pinctrl *pinctrl;
	unsigned long quirks;
	unsigned int cpu_gear_min;
	struct abox_dram_request dram_requests[16];
	unsigned long audif_rates[ABOX_DAI_COUNT];
	unsigned int sif_rate[SET_SIFS0_FORMAT - SET_SIFS0_RATE];
	snd_pcm_format_t sif_format[SET_SIFS0_FORMAT - SET_SIFS0_RATE];
	unsigned int sif_channels[SET_SIFS0_FORMAT - SET_SIFS0_RATE];
	struct abox_event_notifier event_notifier[ABOX_WIDGET_COUNT];
	int apf_coef[2][16];
	struct work_struct add_extra_firmware_controls_work;
	struct work_struct register_component_work;
	struct abox_component components[16];
	struct list_head ipc_actions;
	struct list_head iommu_maps;
	spinlock_t iommu_lock;
	bool enabled;
	bool restored;
	bool no_profiling;
	enum debug_mode debug_mode;
	bool vss_disabled;
	bool system_state[SYSTEM_STATE_COUNT];
	bool sifs_cnt_dirty[SET_SIFM0_RATE - SET_SIFS0_RATE];
	enum calliope_state calliope_state;
	bool failsafe;
	bool error;
	bool pad_ret_skip;
	bool probed;
	bool udma_stop;
	bool rebooting;
	struct work_struct notify_bargein_detect_work;
	struct notifier_block qos_nb;
	struct notifier_block pm_nb;
	struct notifier_block itmon_nb;
	int pm_qos_int[5];
	int pm_qos_aud[16];
	unsigned int pm_qos_stable_min;
	unsigned int pmu_pad_ret[OFFSET_MASK];
	unsigned int pmu_silent_rst[OFFSET_MASK];
	unsigned int sys_acp_con[OFFSET_MASK];
	unsigned int rate_pcmc[ABOX_PCMC_COUNT];
	struct work_struct restore_data_work;
	struct work_struct boot_done_work;
	struct delayed_work boot_clear_work;
	struct delayed_work wdt_work;
	unsigned long long audio_mode_time;
	enum audio_mode audio_mode;
	enum sound_type sound_type;
	struct wakeup_source *ws;
	struct memlog *drvlog_desc;
	struct memlog_obj *drv_log_file_obj;
	struct memlog_obj *drv_log_obj;
	struct memlog *dump_desc;
	struct sysevent_desc sysevent_desc;
	struct sysevent_device *sysevent_dev;
	struct abox_sram_vts sram_vts;
	struct abox_pcmc pcmc;
};

/* sub-driver list */
extern struct platform_driver samsung_abox_debug_driver;
extern struct platform_driver samsung_abox_pci_driver;
extern struct platform_driver samsung_abox_core_driver;
extern struct platform_driver samsung_abox_dump_driver;
extern struct platform_driver samsung_abox_dma_driver;
extern struct platform_driver samsung_abox_vdma_driver;
extern struct platform_driver samsung_abox_wdma_driver;
extern struct platform_driver samsung_abox_rdma_driver;
extern struct platform_driver samsung_abox_if_driver;
extern struct platform_driver samsung_abox_vss_driver;
extern struct platform_driver samsung_abox_effect_driver;
extern struct platform_driver samsung_abox_tplg_driver;

/**
 * Test quirk
 * @param[in]	data	pointer to abox_data structure
 * @param[in]	quirk	quirk bit
 * @return	true or false
 */
static inline bool abox_test_quirk(struct abox_data *data, unsigned long quirk)
{
	return !!(data->quirks & quirk);
}

/**
 * Get SFR of sample format
 * @param[in]	width		count of bit in sample
 * @param[in]	channel		count of channel
 * @return	SFR of sample format
 */
static inline u32 abox_get_format(u32 width, u32 channels)
{
	return ((((width / 8) - 1) << 3) | (channels - 1));
}

/**
 * Get channel from sample format
 * @param[in]	format		SFR of sample format
 * @return	count of channel
 */
static inline u32 abox_get_channels(u32 format)
{
	return ((format & 0x7) + 1);
}

/**
 * Get width from sample format
 * @param[in]	format		SFR of sample format
 * @return	count of bit in sample
 */
static inline u32 abox_get_width(u32 format)
{
	return (((format >> 3) + 1) * 8);
}

/**
 * Get enum IPC_ID from SNDRV_PCM_STREAM_*
 * @param[in]	stream	SNDRV_PCM_STREAM_*
 * @return	IPC_PCMPLAYBACK or IPC_PCMCAPTURE
 */
static inline enum IPC_ID abox_stream_to_ipcid(int stream)
{
	if (stream == SNDRV_PCM_STREAM_PLAYBACK)
		return IPC_PCMPLAYBACK;
	else if (stream == SNDRV_PCM_STREAM_CAPTURE)
		return IPC_PCMCAPTURE;
	else
		return -EINVAL;
}

/**
 * Get SNDRV_PCM_STREAM_* from enum IPC_ID
 * @param[in]	ipcid	IPC_PCMPLAYBACK or IPC_PCMCAPTURE
 * @return	SNDRV_PCM_STREAM_*
 */
static inline int abox_ipcid_to_stream(enum IPC_ID ipcid)
{
	if (ipcid == IPC_PCMPLAYBACK)
		return SNDRV_PCM_STREAM_PLAYBACK;
	else if (ipcid == IPC_PCMCAPTURE)
		return SNDRV_PCM_STREAM_CAPTURE;
	else
		return -EINVAL;
}

/**
 * set magic value for the firmware
 * @param[in]	data	pointer to abox_data structure
 * @param[in]	val	magic value
 */
extern void abox_set_magic(struct abox_data *data, unsigned int val);

/**
 * test given device is abox or not
 * @param[in]
 * @return	true or false
 */
extern bool is_abox(struct device *dev);

/**
 * get pointer to abox_data
 * @param[in]	dev	pointer to struct dev which invokes this API
 * @return		pointer to abox_data
 */
extern struct abox_data *abox_get_data(struct device *dev);

/**
 * get physical address from abox virtual address
 * @param[in]	data	pointer to abox_data structure
 * @param[in]	addr	abox virtual address
 * @return	physical address
 */
extern phys_addr_t abox_addr_to_phys_addr(struct abox_data *data,
		unsigned int addr);

/**
 * get kernel address from abox virtual address
 * @param[in]	data	pointer to abox_data structure
 * @param[in]	addr	abox virtual address
 * @return	kernel address
 */
extern void *abox_addr_to_kernel_addr(struct abox_data *data,
		unsigned int addr);

/**
 * parse address and size from the offset based description
 * @param[in]	data	pointer to abox_data structure
 * @param[in]	np	device node which contains the property
 * @param[in]	name	name of the property
 * @param[out]	addr	virtual address
 * @param[out]	dma	dma address
 * @param[out]	size	size
 * @return	0 or error code
 */
extern int abox_of_get_addr(struct abox_data *data, struct device_node *np,
		const char *name, void **addr, dma_addr_t *dma, size_t *size);

/**
 * Check specific cpu gear request is idle
 * @param[in]	dev		pointer to struct dev which invokes this API
 * @param[in]	id		key which is used as unique handle
 * @return	true if it is idle or not has been requested, false on otherwise
 */
extern bool abox_cpu_gear_idle(struct device *dev, unsigned int id);

/**
 * Request abox cpu clock level
 * @param[in]	dev		pointer to struct dev which invokes this API
 * @param[in]	data		pointer to abox_data structure
 * @param[in]	id		key which is used as unique handle
 * @param[in]	level		gear level or frequency in kHz
 * @param[in]	name		cookie for logging
 * @return	error code if any
 */
extern int abox_request_cpu_gear(struct device *dev, struct abox_data *data,
		unsigned int id, unsigned int level, const char *name);

/**
 * Wait for pending cpu gear change
 */
extern void abox_cpu_gear_barrier(void);

/**
 * Request abox cpu clock level synchronously
 * @param[in]	dev		pointer to struct dev which invokes this API
 * @param[in]	data		pointer to abox_data structure
 * @param[in]	id		key which is used as unique handle
 * @param[in]	level		gear level or frequency in kHz
 * @param[in]	name		cookie for logging
 * @return	error code if any
 */
extern int abox_request_cpu_gear_sync(struct device *dev,
		struct abox_data *data, unsigned int id, unsigned int level,
		const char *name);

/**
 * Clear abox cpu clock requests
 * @param[in]	dev		pointer to struct dev which invokes this API
 */
extern void abox_clear_cpu_gear_requests(struct device *dev);

/**
 * Clear mif clock requests
 * @param[in]	dev		pointer to struct dev which invokes this API
 */
extern void abox_clear_mif_requests(struct device *dev);

/**
 * Request abox cpu clock level with dai
 * @param[in]	dev		pointer to struct dev which invokes this API
 * @param[in]	data		pointer to abox_data structure
 * @param[in]	dai		DAI which is used as unique handle
 * @param[in]	level		gear level or frequency in kHz
 * @return	error code if any
 */
static inline int abox_request_cpu_gear_dai(struct device *dev,
		struct abox_data *data, struct snd_soc_dai *dai,
		unsigned int level)
{
	unsigned int id = ABOX_CPU_GEAR_DAI | dai->id;

	return abox_request_cpu_gear(dev, data, id, level, dai->name);
}

/**
 * Request cluster 0 clock level with DAI
 * @param[in]	dev		pointer to struct dev which invokes this API
 * @param[in]	dai		DAI which is used as unique handle
 * @param[in]	freq		frequency in kHz
 * @return	error code if any
 */
static inline int abox_request_cl0_freq_dai(struct device *dev,
		struct snd_soc_dai *dai, unsigned int freq)
{
	unsigned int id = ABOX_CPU_GEAR_DAI | dai->id;

	return abox_qos_request_cl0(dev, id, freq, dai->name);
}

/**
 * Request cluster 1 clock level with DAI
 * @param[in]	dev		pointer to struct dev which invokes this API
 * @param[in]	dai		DAI which is used as unique handle
 * @param[in]	freq		frequency in kHz
 * @return	error code if any
 */
static inline int abox_request_cl1_freq_dai(struct device *dev,
		struct snd_soc_dai *dai, unsigned int freq)
{
	unsigned int id = ABOX_CPU_GEAR_DAI | dai->id;

	return abox_qos_request_cl1(dev, id, freq, dai->name);
}

/**
 * Request cluster 2 clock level with DAI
 * @param[in]	dev		pointer to struct dev which invokes this API
 * @param[in]	dai		DAI which is used as unique handle
 * @param[in]	freq		frequency in kHz
 * @return	error code if any
 */
static inline int abox_request_cl2_freq_dai(struct device *dev,
		struct snd_soc_dai *dai, unsigned int freq)
{
	unsigned int id = ABOX_CPU_GEAR_DAI | dai->id;

	return abox_qos_request_cl2(dev, id, freq, dai->name);
}

/**
 * Register an notifier to power change notification chain
 * @param[in]	nb		new entry in notifier chain
 * @return	error code if any
 */
int abox_power_notifier_register(struct notifier_block *nb);

/**
 * Unregister an notifier from power change notification chain
 * @param[in]	nb		entry in notifier chain
 * @return	error code if any
 */
int abox_power_notifier_unregister(struct notifier_block *nb);

/**
 * Register uaif to abox
 * @param[in]	dev		pointer to struct dev which invokes this API
 * @param[in]	data		pointer to abox_data structure
 * @param[in]	id		id of the uaif
 * @param[in]	rate		sampling rate
 * @param[in]	channels	number of channels
 * @param[in]	width		number of bit in sample
 * @return	error code if any
 */
extern int abox_register_bclk_usage(struct device *dev, struct abox_data *data,
		enum abox_dai id, unsigned int rate, unsigned int channels,
		unsigned int width);

/**
 * disable or enable qchannel of a clock
 * @param[in]	dev		pointer to struct dev which invokes this API
 * @param[in]	data		pointer to abox_data structure
 * @param[in]	clk		clock id
 * @param[in]	disable		disable or enable
 */
extern int abox_disable_qchannel(struct device *dev, struct abox_data *data,
		enum qchannel clk, int disable);

/**
 * wait for restoring abox from suspend
 * @param[in]	data		pointer to abox_data structure
 */
extern void abox_wait_restored(struct abox_data *data);

/**
 * register sound card with specific order
 * @param[in]	dev		calling device
 * @param[in]	card		sound card to register
 * @param[in]	idx		order of the sound card
 * @return	0 or error code
 */
extern int abox_register_extra_sound_card(struct device *dev,
		struct snd_soc_card *card, unsigned int idx);

/**
 * add or update extra firmware
 * @param[in]	dev		calling device
 * @param[in]	data		pointer to abox_data structure
 * @param[in]	name		name of firmware
 * @param[in]	area		download area of firmware
 * @param[in]	offset		offset of firmware
 * @param[in]	changeable	changeable of firmware
 * @return	0 or error code
 */
extern int abox_add_extra_firmware(struct device *dev, struct abox_data *data,
		const char *name, unsigned int area,
		unsigned int offset, bool changeable);
/**
 * abox silent reset for abox recovery
 * @param[in]	data		pointer to abox_data structure
 * @param[in]	reset		whether abox silent reset is required
 */
extern void abox_silent_reset(struct abox_data *data, bool reset);

/**
 * wait until abox is booted
 * @param[in]	data		pointer to abox_data structure
 * @param[in]	jiffies		timeout in jiffies
 * @return	if the time is elapsed, 0 or 1. if not, remaining jiffies.
 * 		refer to the wait_event_timeout().
 */
extern long abox_wait_for_boot(struct abox_data *data, unsigned long jiffies);

/**
 * get waiting time in nano seconds
 * @param[in]	coarse		parameter to determine time
 */
extern unsigned long abox_get_waiting_ns(bool coarse);

/**
 * get waiting time in jiffies
 * @param[in]	coarse		parameter to determine time
 */
static inline unsigned long abox_get_waiting_jiffies(bool coarse)
{
	return nsecs_to_jiffies(abox_get_waiting_ns(coarse));
}

/**
 * print power usage count
 * @param[in]	dev		calling device
 * @param[in]	data		pointer to abox_data structure
 *
*/
extern int abox_print_power_usage(struct device *dev, void *data);

#endif /* __SND_SOC_ABOX_H */
