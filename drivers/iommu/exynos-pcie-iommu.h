/*
 * Copyright (c) 2012 Samsung Electronics Co., Ltd.
 *		http://www.samsung.com
 *
 * Data structure definition for Exynos IOMMU driver
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */
#ifndef _EXYNOS_IOMMU_H_
#define _EXYNOS_IOMMU_H_

#include <linux/kernel.h>
#include <linux/spinlock.h>
#include <linux/list.h>
#include <linux/device.h>
#include <linux/platform_device.h>
#include <linux/genalloc.h>
#include <linux/iommu.h>
#include <linux/irq.h>
#include <linux/clk.h>
#include <soc/samsung/exynos/memlogger.h>

typedef u64 sysmmu_iova_t;
typedef u32 sysmmu_pte_t;

#define SYSMMU_MASK_VMID	0x1
#define PMMU_MAX_NUM		8

#define IOVM_NUM_PAGES(vmsize) (vmsize / PAGE_SIZE)
#define IOVM_BITMAP_SIZE(vmsize) \
		((IOVM_NUM_PAGES(vmsize) + BITS_PER_BYTE) / BITS_PER_BYTE)

#define SECT_ORDER 20
#define LPAGE_ORDER 16
#define SPAGE_ORDER 12

#define SECT_SIZE (1 << SECT_ORDER)
#define LPAGE_SIZE (1 << LPAGE_ORDER)
#define SPAGE_SIZE (1 << SPAGE_ORDER)

#define SECT_MASK (~(SECT_SIZE - 1))
#define LPAGE_MASK (~(LPAGE_SIZE - 1))
#define SPAGE_MASK (~(SPAGE_SIZE - 1))

#define SECT_ENT_MASK	~((SECT_SIZE >> PG_ENT_SHIFT) - 1)
#define LPAGE_ENT_MASK	~((LPAGE_SIZE >> PG_ENT_SHIFT) - 1)
#define SPAGE_ENT_MASK	~((SPAGE_SIZE >> PG_ENT_SHIFT) - 1)

#define SPAGES_PER_LPAGE	(LPAGE_SIZE / SPAGE_SIZE)

#define PGBASE_TO_PHYS(pgent)	((phys_addr_t)(pgent) << PG_ENT_SHIFT)

/* NUM_LV1ENTRIES = 2^36 / 1MB */
#define NUM_LV1ENTRIES	65536
#define NUM_LV2ENTRIES (SECT_SIZE / SPAGE_SIZE)
#define LV2TABLE_SIZE (NUM_LV2ENTRIES * sizeof(sysmmu_pte_t))

#define lv1ent_offset(iova) ((iova) >> SECT_ORDER)
#define lv2ent_offset(iova) ((iova & ~SECT_MASK) >> SPAGE_ORDER)

#define PG_ENT_SHIFT	4
#define lv1ent_fault(sent)	((*(sent) & 7) == 0)
#define lv1ent_page(sent)	((*(sent) & 7) == 1)

#define FLPD_FLAG_MASK	7
#define SLPD_FLAG_MASK	3

#define SECT_FLAG	2
#define SLPD_FLAG	1

#define LPAGE_FLAG	1
#define SPAGE_FLAG	2

#define ENT_TO_PHYS(ent) (phys_addr_t)(*(ent))
#define section_phys(sent) PGBASE_TO_PHYS(ENT_TO_PHYS(sent) & SECT_ENT_MASK)
#define section_offs(iova) ((iova) & (SECT_SIZE - 1))
#define lpage_phys(pent) PGBASE_TO_PHYS(ENT_TO_PHYS(pent) & LPAGE_ENT_MASK)
#define lpage_offs(iova) ((iova) & (LPAGE_SIZE - 1))
#define spage_phys(pent) PGBASE_TO_PHYS(ENT_TO_PHYS(pent) & SPAGE_ENT_MASK)
#define spage_offs(iova) ((iova) & (SPAGE_SIZE - 1))

#define lv1ent_section(sent) ((*(sent) & FLPD_FLAG_MASK) == SECT_FLAG)
#define lv2table_base(sent)	((phys_addr_t)(*(sent) & ~0x3F) << PG_ENT_SHIFT)
#define lv2ent_fault(pent) ((*(pent) & SLPD_FLAG_MASK) == 0)
#define lv2ent_small(pent) ((*(pent) & SLPD_FLAG_MASK) == SPAGE_FLAG)
#define lv2ent_large(pent) ((*(pent) & SLPD_FLAG_MASK) == LPAGE_FLAG)

#define mk_lv1ent_sect(pa) ((sysmmu_pte_t) ((pa) >> PG_ENT_SHIFT) | 2)
#define mk_lv1ent_page(pa) ((sysmmu_pte_t) ((pa) >> PG_ENT_SHIFT) | 1)
#define mk_lv2ent_lpage(pa) ((sysmmu_pte_t) ((pa) >> PG_ENT_SHIFT) | 1)
#define mk_lv2ent_spage(pa) ((sysmmu_pte_t) ((pa) >> PG_ENT_SHIFT) | 2)
#define set_lv1ent_shareable(sent) (*(sent) |= (1 << 6))
#define set_lv2ent_shareable(sent) (*(sent) |= (1 << 4))
#define mk_lv2ent_pfnmap(pent) (*(pent) |= (1 << 5)) /* unused field */
#define lv2ent_pfnmap(pent) ((*(pent) & (1 << 5)) == (1 << 5))

#define SYSMMU_BLOCK_POLLING_COUNT 4096

#define REG_MMU_CTRL		0x000
#define REG_MMU_CFG		0x004
#define REG_MMU_STATUS		0x008
#define REG_MMU_VERSION		0x034

#define CTRL_ENABLE	0x5
#define CTRL_BLOCK	0x7
#define CTRL_DISABLE	0x0
#define CTRL_BLOCK_DISABLE 0x3

#define CTRL_MMU_ENABLE			BIT(0)
#define CTRL_INT_ENABLE 		BIT(2)
#define CTRL_FAULT_STALL_MODE		BIT(3)

#define MMU_STREAM_CFG_STLB_ID(val)		(((val) >> 24) & 0xFF)
#define MMU_STREAM_CFG_PTLB_ID(val)		(((val) >> 16) & 0xFF)

#define MMU_SET_PMMU_INDICATOR(val)		((val) & 0xF)

#define CFG_MASK	0x301F1F8C	/* Bit 29-28, 20-16, 12-7, 3-2 */
#define CFG_ACGEN	(1 << 24)
#define CFG_FLPDCACHE	(1 << 20)
#define CFG_QOS_OVRRIDE (1 << 11)
#define CFG_QOS(n)      (((n) & 0xF) << 7)

#define MMU_WAY_CFG_MASK_PREFETCH	(1 << 1)
#define MMU_WAY_CFG_MASK_PREFETCH_DIR	(3 << 2)
#define MMU_WAY_CFG_MASK_MATCH_METHOD	(1 << 4)
#define MMU_WAY_CFG_MASK_FETCH_SIZE	(7 << 5)
#define MMU_WAY_CFG_MASK_TARGET_CH	(3 << 8)

#define MMU_WAY_CFG_ID_MATCHING		(1 << 4)
#define MMU_WAY_CFG_ADDR_MATCHING	(0 << 4)
#define MMU_WAY_CFG_PRIVATE_ENABLE	(1 << 0)

#define MMU_PUBLIC_WAY_MASK	(MMU_WAY_CFG_MASK_PREFETCH |	\
		MMU_WAY_CFG_MASK_PREFETCH_DIR | MMU_WAY_CFG_MASK_FETCH_SIZE)
#define MMU_PRIVATE_WAY_MASK	(MMU_PUBLIC_WAY_MASK |		\
		MMU_WAY_CFG_MASK_MATCH_METHOD | MMU_WAY_CFG_MASK_TARGET_CH)

#define REG_MMU_CAPA			0x030
#define REG_MMU_CAPA_1			0x038
#define REG_INT_CLEAR			0x064
#define REG_MMU_CTRL_VID(n)		(0x8000 + ((n) * 0x1000))
#define REG_MMU_CFG_VID(n)		(0x8004 + ((n) * 0x1000))

#define REG_FAULT_STATUS_VID(n)		(0x8060 + ((n) * 0x1000))
#define REG_FAULT_CLEAR_VID(n)		(0x8064 + ((n) * 0x1000))
#define REG_FAULT_VA_VID(n)		(0x8070 + ((n) * 0x1000))
#define REG_FAULT_INFO0_VID(n)		(0x8074 + ((n) * 0x1000))
#define REG_FAULT_INFO1_VID(n)		(0x8078 + ((n) * 0x1000))
#define REG_FAULT_INFO2_VID(n)		(0x807C + ((n) * 0x1000))

#define MMU_FAULT_INFO0_VA_36(reg)	(((reg) >> 21) & 0x1)
#define MMU_FAULT_INFO0_VA_HIGH(reg)	(((u64)(reg) & 0x3C00000) << 10)
#define MMU_FAULT_INFO0_LEN(reg)	(((reg) >> 16) & 0xF)
#define MMU_FAULT_INFO0_ASID(reg)	((reg) & 0xFFFF)
#define MMU_FAULT_INFO1_AXID(reg)	(reg)
#define MMU_FAULT_INFO2_PMMU_ID(reg)	(((reg) >> 24) & 0xFF)
#define MMU_FAULT_INFO2_STREAM_ID(reg)	((reg) & 0xFFFFFF)

#define REG_PT_BASE_PPN_VID(n)		(0x8404 + ((n) * 0x1000))
#define REG_CONTEXT_CFG_ATTR_VID(n)	(0x8408 + ((n) * 0x1000))

#define REG_MMU_FLUSH_VID(n)		(0x8010 + ((n) * 0x1000))
#define REG_MMU_FLUSH_ENTRY_VID(n)	(0x8014 + ((n) * 0x1000))
#define REG_MMU_FLUSH_RANGE_VID(n)	(0x8018 + ((n) * 0x1000))
#define REG_FLUSH_RANGE_START_VID(n)	(0x8020 + ((n) * 0x1000))
#define REG_FLUSH_RANGE_END_VID(n)	(0x8024 + ((n) * 0x1000))
#define TLB_INVALIDATE			BIT(0)

#define VID_CFG_PT_CACHEABLE_MASK	GENMASK(19, 16)
#define VID_CFG_PT_CACHEABLE_CACHEABLE	(0x2 << 16)
#define VID_CFG_SHAREABLE      (1 << 29)
#define VID_CFG_SHAREABLE_OVRD (1 << 28)
#define VID_CFG_USE_MASTER_SHA (1 << 27)

#define REG_FAULT_AR_ADDR	0x070
#define REG_FAULT_AR_TRANS_INFO	0x078
#define REG_FAULT_AW_ADDR	0x080
#define REG_FAULT_AW_TRANS_INFO	0x088

#define REG_L2TLB_CFG		0x200

/* For SysMMU v7.x */
#define REG_MMU_CAPA_V7		0x870
#define REG_PUBLIC_WAY_CFG	0x120
#define REG_PRIVATE_WAY_CFG(n)		(0x200 + ((n) * 0x10))
#define REG_PRIVATE_ADDR_START(n)	(0x204 + ((n) * 0x10))
#define REG_PRIVATE_ADDR_END(n)		(0x208 + ((n) * 0x10))
#define REG_PRIVATE_ID(n)		(0x20C + ((n) * 0x10))
#define REG_FAULT_ADDR_VA	0x1010
#define REG_FAULT_INFO0		0x1014
#define REG_FAULT_INFO1		0x1018
/*
#define REG_TLB_READ		0x1000
#define REG_TLB_VPN		0x1004
#define REG_TLB_PPN		0x1008
#define REG_TLB_ATTR		0x100C
#define REG_SBB_READ		0x1100
#define REG_SBB_VPN		0x1104
#define REG_SBB_LINK		0x1108
#define REG_SBB_ATTR		0x110C
*/

#define MMU_CAPA_NUM_SBB_ENTRY(reg)	((reg >> 12) & 0xF)
#define MMU_CAPA_NUM_TLB_SET(reg)	((reg >> 8) & 0xF)
#define MMU_CAPA_NUM_TLB_WAY(reg)	((reg) & 0xFF)
#define MMU_SET_TLB_READ_ENTRY(set, way, line)		\
			((set) | ((way) << 8) | ((line) << 16))
#define MMU_TLB_ENTRY_VALID(reg)	((reg) >> 28)
#define MMU_SBB_ENTRY_VALID(reg)	((reg) >> 28)

#define MMU_FAULT_INFO_READ_REQUEST	0
#define MMU_FAULT_INFO_WRITE_REQUEST	1
#define MMU_IS_READ_FAULT(reg)		\
		((((reg) >> 20) & 0x1) == MMU_FAULT_INFO_READ_REQUEST)

#define MMU_HAVE_PB(reg)	(!!((reg >> 20) & 0xF))
#define MMU_IS_TLB_CONFIGURABLE(reg)	(!!((reg >> 16) & 0xFF))

#define MMU_MASK_LINE_SIZE	0x7
#define MMU_DEFAULT_LINE_SIZE	(0x2 << 4)

#define MMU_MAJ_VER(val)	((val) >> 12)
#define MMU_MIN_VER(val)	((val >> 8) & 0xF)
#define MMU_REV_VER(val)	((val) & 0xFF)
#define MMU_RAW_VER(reg)	(((reg) >> 16) & 0xFFFF)

#define REG_MMU_NUM_CONTEXT	0x0100

#define REG_MMU_STREAM_CFG(n)			(0x2000 + ((n) * 0x10))
#define REG_MMU_STREAM_MATCH_CFG(n)		(0x2000 + ((n) * 0x10) + 0x4)
#define REG_MMU_STREAM_MATCH_SID_VALUE(n)	(0x2000 + ((n) * 0x10) + 0x8)
#define REG_MMU_STREAM_MATCH_SID_MASK(n)	(0x2000 + ((n) * 0x10) + 0xC)

#define MMU_STREAM_CFG_S2_PREFETCH_EN		(0x1 << 8)
#define MMU_STREAM_CFG_MASK(old_reg ,reg)	((old_reg) & MMU_STREAM_CFG_S2_PREFETCH_EN) |	\
						((reg) & (GENMASK(31, 16) | GENMASK(6, 0)))
#define MMU_STREAM_MATCH_CFG_MASK(reg)		((reg) & (GENMASK(9, 8) | 0x1))

#define REG_MMU_PMMU_INDICATOR			0x2FFC
#define REG_MMU_PMMU_INFO			0x3000
#define REG_MMU_SWALKER_INFO			0x3004

#define MMU_NUM_CONTEXT(reg)	((reg) & 0x1F)

#define VA_WIDTH_32BIT		0x0
#define VA_WIDTH_36BIT		0x1

#define SET_PMMU_INDICATOR(val)			((val) & 0xF)
#define MMU_PMMU_INFO_VA_WIDTH(reg)		((reg) & 0x1)
#define MMU_PMMU_INFO_NUM_STREAM_TABLE(reg)	(((reg) >> 16) & 0xFFFF)

#define DEFAULT_QOS_VALUE	-1
#define DEFAULT_STREAM_NONE	~0U
#define UNUSED_STREAM_INDEX	~0U

#define SYSMMU_FAULT_BITS       4
#define SYSMMU_FAULT_SHIFT      16
#define SYSMMU_FAULT_MASK       ((1 << SYSMMU_FAULT_BITS) - 1)
#define SYSMMU_FAULT_FLAG(id) (((id) & SYSMMU_FAULT_MASK) << SYSMMU_FAULT_SHIFT)
#define SYSMMU_FAULT_ID(fg)   (((fg) >> SYSMMU_FAULT_SHIFT) & SYSMMU_FAULT_MASK)

#define SYSMMU_FAULT_PTW_ACCESS		0
#define SYSMMU_FAULT_PAGE		1
#define SYSMMU_FAULT_ACCESS		2
#define SYSMMU_FAULT_CONTEXT		3
#define SYSMMU_FAULT_UNKNOWN		4
#define SYSMMU_FAULTS_NUM		(SYSMMU_FAULT_UNKNOWN + 1)

#define SYSMMU_4KB_MASK		0xfff

#define SYSMMU_FAULTS_NUM         (SYSMMU_FAULT_UNKNOWN + 1)

#define DUPLMEM_ENTRY_NUM	4096

#define SYSMMU_PCIE_CH0			(0)
#define SYSMMU_PCIE_CH1			(1)

/* For SysMMU v7.1 */
#define REG_MMU_CAPA0_V7	0x870
#define REG_MMU_CAPA1_V7	0x874
#define MMU_CAPA1_NUM_TLB(reg)	((reg >> 4) & 0xFF)
#define MMU_CAPA1_NUM_PORT(reg)	((reg) & 0xF)
#define MMU_TLB_INFO(n)		(0x2000 + ((n) * 0x20))
#define MMU_CAPA1_NUM_TLB_SET(reg)	((reg >> 16) & 0xFF)
#define MMU_CAPA1_NUM_TLB_WAY(reg)	((reg) & 0xFF)
#define REG_MMU_TLB_CFG(n)		(0x2000 + ((n) * 0x20) + 0x4)
#define REG_MMU_TLB_MATCH_CFG(n)	(0x2000 + ((n) * 0x20) + 0x8)
#define REG_MMU_TLB_MATCH_SVA(n)	(0x2000 + ((n) * 0x20) + 0xC)
#define REG_MMU_TLB_MATCH_EVA(n)	(0x2000 + ((n) * 0x20) + 0x10)
#define REG_MMU_TLB_MATCH_ID(n)		(0x2000 + ((n) * 0x20) + 0x14)
#define REG_CAPA1_TLB_READ		0x3000
#define REG_CAPA1_TLB_VPN		0x3004
#define REG_CAPA1_TLB_PPN		0x3008
#define REG_CAPA1_TLB_ATTR		0x300C
#define REG_CAPA1_SBB_READ		0x3020
#define REG_CAPA1_SBB_VPN		0x3024
#define REG_CAPA1_SBB_LINK		0x3028
#define REG_CAPA1_SBB_ATTR		0x302C
#define REG_SLOT_RSV(n)			(0x4000 + ((n) * 0x20))
#define MMU_CAPA1_SET_TLB_READ_ENTRY(tid, set, way, line)		\
			((set) | ((way) << 8) | ((line) << 16) | ((tid) << 20))
#define MMU_TLB_CFG_MASK(reg)		((reg) & ((0x7 << 5) | (0x3 << 2) | (0x1 << 1)))
#define MMU_TLB_MATCH_CFG_MASK(reg)	((reg) & ((0xFFFF << 16) | (0x3 << 8)))

#define TLB_USED_ALL_PCIE_PORT		(0x3 << 16)
#define TLB_USED_RW_REQ			(0x3 << 8)

#define MAX_EXT_BUFF_NUM		(400)
#define LV2_GENPOOL_SZIE		(SZ_1M * 3)
/* Level2 table size + reference counter region */
#define LV2TABLE_AND_REFBUF_SZ		(LV2TABLE_SIZE * 2)
#define NUM_DRAM_REGION			(10)
#define SYSMMU_NO_PANIC			(1)

#define SYSMMU_PANIC_BY_DEV		(3)

/* For SysMMU v9 */
#define REG_MMU_PMMU_PTLB_INFO(n)		(0x3400 + ((n) * 0x4))
#define REG_MMU_STLB_INFO(n)			(0x3800 + ((n) * 0x4))
#define REG_MMU_S1L1TLB_INFO			0x3C00

#define REG_MMU_READ_PTLB			0x9800
#define REG_MMU_READ_PTLB_TPN			0x9804
#define REG_MMU_READ_PTLB_PPN			0x9808
#define REG_MMU_READ_PTLB_ATTRIBUTE		0x980C

#define REG_MMU_READ_STLB			0x9810
#define REG_MMU_READ_STLB_TPN			0x9814
#define REG_MMU_READ_STLB_PPN			0x9818
#define REG_MMU_READ_STLB_ATTRIBUTE		0x981C

#define REG_MMU_READ_S1L1TLB			0x9820
#define REG_MMU_READ_S1L1TLB_VPN		0x9824
#define REG_MMU_READ_S1L1TLB_SLPT_OR_PPN	0x9828
#define REG_MMU_READ_S1L1TLB_ATTRIBUTE		0x982C

#define REG_MMU_FAULT_STATUS_VM			0x8060
#define REG_MMU_FAULT_CLEAR_VM			0x8064
#define REG_MMU_FAULT_VA_VM			0x8070
#define REG_MMU_FAULT_INFO0_VM			0x8074
#define REG_MMU_FAULT_INFO1_VM			0x8078
#define REG_MMU_FAULT_INFO2_VM			0x807C
#define REG_MMU_FAULT_RW_MASK			GENMASK(20, 20)
#define IS_READ_FAULT(x)			(((x) & REG_MMU_FAULT_RW_MASK) == 0)

#define MMU_PMMU_PTLB_INFO_NUM_WAY(reg)			(((reg) >> 16) & 0xFFFF)
#define MMU_PMMU_PTLB_INFO_NUM_SET(reg)			((reg) & 0xFFFF)
#define MMU_READ_PTLB_TPN_VALID(reg)			(((reg) >> 28) & 0x1)
#define MMU_READ_PTLB_TPN_S1_ENABLE(reg)		(((reg) >> 24) & 0x1)
#define MMU_VADDR_FROM_PTLB(reg)			(((reg) & 0xFFFFFF) << SPAGE_ORDER)
#define MMU_PADDR_FROM_PTLB(reg)			(((reg) & 0xFFFFFF) << SPAGE_ORDER)
#define MMU_SET_READ_PTLB_ENTRY(way, set, ptlb, pmmu)	((pmmu) | ((ptlb) << 4) |		\
							((set) << 16) | ((way) << 24))

#define MMU_SWALKER_INFO_NUM_STLB(reg)			(((reg) >> 16) & 0xFFFF)
#define MMU_SWALKER_INFO_NUM_PMMU(reg)			((reg) & 0xF)
#define MMU_STLB_INFO_NUM_WAY(reg)			(((reg) >> 16) & 0xFFFF)
#define MMU_STLB_INFO_NUM_SET(reg)			((reg) & 0xFFFF)
#define MMU_READ_STLB_TPN_VALID(reg)			(((reg) >> 28) & 0x1)
#define MMU_READ_STLB_TPN_S1_ENABLE(reg)		(((reg) >> 24) & 0x1)
#define MMU_VADDR_FROM_STLB(reg)			(((reg) & 0xFFFFFF) << SPAGE_ORDER)
#define MMU_PADDR_FROM_STLB(reg)			(((reg) & 0xFFFFFF) << SPAGE_ORDER)
#define MMU_SET_READ_STLB_ENTRY(way, set, stlb, line)	((set) | ((way) << 8) |			\
							((line) << 16) | ((stlb) << 20))

#define MMU_S1L1TLB_INFO_NUM_SET(reg)			(((reg) >> 16) & 0xFFFF)
#define MMU_S1L1TLB_INFO_NUM_WAY(reg)			(((reg) >> 12) & 0xF)
#define MMU_SET_READ_S1L1TLB_ENTRY(way, set)		((set) | ((way) << 8))
#define MMU_READ_S1L1TLB_VPN_VALID(reg)			(((reg) >> 28) & 0x1)
#define MMU_VADDR_FROM_S1L1TLB(reg)			(((reg) & 0xFFFFFF) << SPAGE_ORDER)
#define MMU_PADDR_FROM_S1L1TLB_PPN(reg)			(((reg) & 0xFFFFFF) << SPAGE_ORDER)
#define MMU_PADDR_FROM_S1L1TLB_BASE(reg)		(((reg) & 0x3FFFFFF) << 10)
#define MMU_S1L1TLB_ATTRIBUTE_PS(reg)			(((reg) >> 8) & 0x7)

#define MMU_FAULT_INFO0_VA_36(reg)			(((reg) >> 21) & 0x1)
#define MMU_FAULT_INFO0_VA_HIGH(reg)			(((u64)(reg) & 0x3C00000) << 10)
#define MMU_FAULT_INFO0_LEN(reg)			(((reg) >> 16) & 0xF)
#define MMU_FAULT_INFO0_ASID(reg)			((reg) & 0xFFFF)
#define MMU_FAULT_INFO1_AXID(reg)			(reg)
#define MMU_FAULT_INFO2_PMMU_ID(reg)			(((reg) >> 24) & 0xFF)
#define MMU_FAULT_INFO2_STREAM_ID(reg)			((reg) & 0xFFFFFF)

#define SLPT_BASE_FLAG		0x6

#define sysmmu_dump(fmt, args...)				\
	exynos_sysmmu_memlog_print(g_sysmmu_drvdata,		\
			MEMLOG_LEVEL_ERR,			\
			fmt, ##args);				\

static char *pmmu_default_stream[PMMU_MAX_NUM] = {
	"pmmu0,default_stream",
	"pmmu1,default_stream",
	"pmmu2,default_stream",
	"pmmu3,default_stream",
	"pmmu4,default_stream",
	"pmmu5,default_stream",
	"pmmu6,default_stream",
	"pmmu7,default_stream"
};

static char *pmmu_stream_property[PMMU_MAX_NUM] = {
	"pmmu0,stream_property",
	"pmmu1,stream_property",
	"pmmu2,stream_property",
	"pmmu3,stream_property",
	"pmmu4,stream_property",
	"pmmu5,stream_property",
	"pmmu6,stream_property",
	"pmmu7,stream_property"
};

enum pcie_sysmmu_vid {
	PCIE_SYSMMU_NOT_USED, /* For unused VID */
	PCIE_SYSMMU_VID_CH0,
	PCIE_SYSMMU_VID_CH1,
	PCIE_SYSMMU_VID_MAX,
};

#define SYSMMU_PCIE_VID_OFFSET		(PCIE_SYSMMU_VID_CH0 - PCIE_SYSMMU_NOT_USED)

struct ext_buff {
	int index;
	int used;
	sysmmu_pte_t* buff;
};

struct dram_region {
	phys_addr_t start;
	phys_addr_t end;
};

#define MAX_HISTORY_BUFF		(10240)

struct history_buff {
	unsigned long tv_kernel[MAX_HISTORY_BUFF];
	unsigned long rem_nsec[MAX_HISTORY_BUFF];
	unsigned long save_addr[MAX_HISTORY_BUFF];
	unsigned long paddr[MAX_HISTORY_BUFF];
	unsigned long orig_addr[MAX_HISTORY_BUFF];
	u32 size[MAX_HISTORY_BUFF];
	u32 orig_size[MAX_HISTORY_BUFF];
	u32 refcnt[MAX_HISTORY_BUFF];
	u8 mu[MAX_HISTORY_BUFF]; // 0: unmap, 1: map
	u16 index;
};

/*
 * This structure exynos specific generalization of struct iommu_domain.
 * It contains list of all master devices represented by owner, which has
 * been attached to this domain and page tables of IO address space defined by
 * it. It is usually referenced by 'domain' pointer.
 */
struct exynos_iommu_domain {
	struct iommu_domain domain;	/* generic domain data structure */
	sysmmu_pte_t *pgtable;	/* lv1 page table, 16KB */
	spinlock_t pgtablelock;	/* lock for modifying page table */
	struct list_head clients_list;	/* list of exynos_iommu_owner.client */
	atomic_t *lv2entcnt;	/* free lv2 entry counter for each section */
	spinlock_t lock;		/* lock for modifying clients_list */
	unsigned long pgsize_bitmap;
#ifdef USE_DYNAMIC_MEM_ALLOC
	struct ext_buff ext_buff[MAX_EXT_BUFF_NUM];
#endif
};

/*
 * This structure is attached to dev.archdata.iommu of the master device
 * on device add, contains a list of SYSMMU controllers defined by device tree,
 * which are bound to given master device. It is usually referenced by 'owner'
 * pointer.
 */
struct exynos_iommu_owner {
	struct exynos_iommu_owner *next;
	struct list_head sysmmu_list;	/* list of sysmmu_drvdata */
	spinlock_t lock;		/* lock for modifying sysmmu_list */
	struct iommu_domain *domain;	/* domain of owner */
	struct device *master;		/* master device */
	struct list_head client;	/* node for owner clients_list */
	struct exynos_iovmm *vmm_data;
	iommu_fault_handler_t fault_handler;
	void *token;
};

struct tlb_priv_addr {
	unsigned int cfg;
};

struct tlb_priv_id {
	unsigned int cfg;
	unsigned int id;
};

#define TLB_WAY_PRIVATE_ID	(1 << 0)
#define TLB_WAY_PRIVATE_ADDR	(1 << 1)
#define TLB_WAY_PUBLIC		(1 << 2)
struct tlb_props {
	int flags;
	int priv_id_cnt;
	int priv_addr_cnt;
	unsigned int public_cfg;
	struct tlb_priv_id *priv_id_cfg;
	struct tlb_priv_addr *priv_addr_cfg;
};

struct stream_config {
	unsigned int index;
	u32 cfg;
	u32 match_cfg;
	u32 match_id_value;
	u32 match_id_mask;
};

struct stream_props {
	int id_cnt;
	u32 default_cfg;
	struct stream_config *cfg;
};

/*
 * This structure hold all data of a single SYSMMU controller, this includes
 * hw resources like registers and clocks, pointers and list nodes to connect
 * it to all other structures, internal state and parameters read from device
 * tree. It is usually referenced by 'data' pointer.
 */
struct sysmmu_drvdata {
	struct sysmmu_drvdata *next;
	struct device *dev;		/* SYSMMU controller device */
	void __iomem *sfrbase;		/* our registers */
	struct clk *clk;		/* SYSMMU's clock */
	u32 activations;		/* SysMMU activation for each VID */
	int runtime_active;	/* Runtime PM activated count from master */
	spinlock_t lock;		/* lock for modyfying state */
	phys_addr_t pgtable[2];		/* assigned page table structure */
	int qos;
	int securebase;
	struct atomic_notifier_head fault_notifiers;
	struct tlb_props tlb_props;
	bool is_suspended;

	struct exynos_iommu_domain *domain[2]; /* iommu domain for this iovmm */
	int pcie_use_iocc[2];

	spinlock_t mmu_ctrl_lock; /* Global Register Control lock */
	int irq_num;

	u32 version;
	u32 va_width;
	u32 max_vm;
	u32 vmid_mask;
	int num_pmmu;

	struct stream_props *props;
	struct memlog *log_desc;
	struct memlog_obj *log_obj;
};

struct exynos_vm_region {
	struct list_head node;
	u32 start;
	u32 size;
	u32 section_off;
	u32 dummy_size;
};

struct exynos_iovmm {
	struct iommu_domain *domain;	/* iommu domain for this iovmm */
	size_t iovm_size;		/* iovm bitmap size per plane */
	u32 iova_start;			/* iovm start address per plane */
	unsigned long *vm_map;		/* iovm biatmap per plane */
	struct list_head regions_list;	/* list of exynos_vm_region */
	spinlock_t vmlist_lock;		/* lock for updating regions_list */
	spinlock_t bitmap_lock;		/* lock for manipulating bitmaps */
	struct device *dev;	/* peripheral device that has this iovmm */
	size_t allocated_size;
	int num_areas;
	unsigned int num_map;
	unsigned int num_unmap;
	const char *domain_name;
	struct iommu_group *group;
};

static void exynos_sysmmu_tlb_invalidate(dma_addr_t d_start, size_t size,
					enum pcie_sysmmu_vid pcie_vid);
int exynos_iommu_add_fault_handler(struct device *dev,
				iommu_fault_handler_t handler, void *token);

static inline bool get_sysmmu_runtime_active(struct sysmmu_drvdata *data)
{
	return ++data->runtime_active == 1;
}

static inline bool put_sysmmu_runtime_active(struct sysmmu_drvdata *data)
{
	BUG_ON(data->runtime_active < 1);
	return --data->runtime_active == 0;
}

static inline bool is_sysmmu_runtime_active(struct sysmmu_drvdata *data)
{
	return data->runtime_active > 0;
}

static inline bool set_sysmmu_active(struct sysmmu_drvdata *data,
					enum pcie_sysmmu_vid pcie_vid)
{
	/* return true if the System MMU was not active previously
	 * and it needs to be initialized
	 */

	data->activations |= (0x1 << pcie_vid);

	return 1;
}

static inline bool set_sysmmu_inactive(struct sysmmu_drvdata *data,
					enum pcie_sysmmu_vid pcie_vid)
{
	/* return true if the System MMU is needed to be disabled */
	data->activations &= ~(0x1 << pcie_vid);

	return 0;
}

static inline bool is_sysmmu_active(struct sysmmu_drvdata *data)
{
	return data->activations > 0;
}

static inline void __raw_sysmmu_enable(void __iomem *sfrbase)
{
	__raw_writel(CTRL_ENABLE, sfrbase + REG_MMU_CTRL);
}

#define sysmmu_unblock __raw_sysmmu_enable

void dump_sysmmu_tlb_pb(void __iomem *sfrbase);

static inline bool sysmmu_block(void __iomem *sfrbase)
{
	int i = SYSMMU_BLOCK_POLLING_COUNT;

	__raw_writel(CTRL_BLOCK, sfrbase + REG_MMU_CTRL);
	while ((i > 0) && !(__raw_readl(sfrbase + REG_MMU_STATUS) & 1))
		--i;

	if (!(__raw_readl(sfrbase + REG_MMU_STATUS) & 1)) {
		/*
		 * TODO: dump_sysmmu_tlb_pb(sfrbase);
		 */
		panic("Failed to block System MMU!");
		sysmmu_unblock(sfrbase);
		return false;
	}

	return true;
}

static inline sysmmu_pte_t *page_entry(sysmmu_pte_t *sent, sysmmu_iova_t iova)
{
	return (sysmmu_pte_t *)(phys_to_virt(lv2table_base(sent))) +
				lv2ent_offset(iova);
}

static inline sysmmu_pte_t *section_entry(
				sysmmu_pte_t *pgtable, sysmmu_iova_t iova)
{
	return (sysmmu_pte_t *)(pgtable + lv1ent_offset(iova));
}

#if IS_ENABLED(CONFIG_EXYNOS_IOVMM)
static inline struct exynos_iovmm *exynos_get_iovmm(struct device *dev)
{
	if (!dev->archdata.iommu) {
		dev_err(dev, "%s: System MMU is not configured\n", __func__);
		return NULL;
	}

	return ((struct exynos_iommu_owner *)dev->archdata.iommu)->vmm_data;
}

struct exynos_vm_region *find_iovm_region(struct exynos_iovmm *vmm,
						dma_addr_t iova);

struct exynos_iovmm *exynos_create_single_iovmm(const char *name,
					unsigned int start, unsigned int end);
#else
static inline struct exynos_iovmm *exynos_get_iovmm(struct device *dev)
{
	return NULL;
}

struct exynos_vm_region *find_iovm_region(struct exynos_iovmm *vmm,
						dma_addr_t iova)
{
	return NULL;
}

static inline struct exynos_iovmm *exynos_create_single_iovmm(const char *name,
					unsigned int start, unsigned int end)
{
	return NULL;
}
#endif /* CONFIG_EXYNOS_IOVMM */

extern void get_atomic_pool_info(dma_addr_t *paddr, size_t *size);

#endif /* _EXYNOS_IOMMU_H_ */
