/*
 * Copyright 2008-2021 Advanced Micro Devices, Inc.
 * Copyright 2008 Red Hat Inc.
 * Copyright 2009 Jerome Glisse.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL
 * THE COPYRIGHT HOLDER(S) OR AUTHOR(S) BE LIABLE FOR ANY CLAIM, DAMAGES OR
 * OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
 * ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 *
 * Authors: Dave Airlie
 *          Alex Deucher
 *          Jerome Glisse
 */
#include <linux/power_supply.h>
#include <linux/kthread.h>
#include <linux/module.h>
#include <linux/console.h>
#include <linux/slab.h>
#include <linux/devfreq.h>

#include <drm/drm_atomic_helper.h>
#include <drm/drm_probe_helper.h>
#include <drm/sgpu_drm.h>
#include <linux/vgaarb.h>
#include <linux/efi.h>
#include "amdgpu.h"
#include "amdgpu_trace.h"
#include "amdgpu_i2c.h"
#include "atom.h"
#include "amdgpu_atombios.h"
#include "amdgpu_atomfirmware.h"
#include "amd_pcie.h"
#include "soc15.h"
#include "nv.h"
#include "bif/bif_4_1_d.h"
#include <linux/pci.h>
#include <linux/firmware.h>
#include "amdgpu_vf_error.h"

#include "amdgpu_pm.h"

#include "amdgpu_pmu.h"
#include "amdgpu_fru_eeprom.h"
#include "amdgpu_sws.h"
#include "amdgpu_cwsr.h"

#include <linux/suspend.h>
#include <drm/task_barrier.h>
#include <linux/pm_runtime.h>

#include "vangogh_lite_m0_gpu_info.h"
#include "vangogh_lite_m1_gpu_info.h"
#include "vangogh_lite_m2_gpu_info.h"
#include "vangogh_lite_m1_mid_gpu_info.h"

#ifdef CONFIG_DRM_SGPU_EXYNOS
#include "exynos_gpu_interface.h"
#endif /* CONFIG_DRM_SGPU_EXYNOS */

#define AMDGPU_RESUME_MS		2000

char *enable_all_vd = "all";

const char *amdgpu_asic_name[] = {
	"TAHITI",
	"PITCAIRN",
	"VERDE",
	"OLAND",
	"HAINAN",
	"BONAIRE",
	"KAVERI",
	"KABINI",
	"HAWAII",
	"MULLINS",
	"TOPAZ",
	"TONGA",
	"FIJI",
	"CARRIZO",
	"STONEY",
	"POLARIS10",
	"POLARIS11",
	"POLARIS12",
	"VEGAM",
	"VEGA10",
	"VEGA12",
	"VEGA20",
	"RAVEN",
	"ARCTURUS",
	"RENOIR",
	"NAVI10",
	"NAVI14",
	"NAVI12",
	"SIENNA_CICHLID",
	"NAVY_FLOUNDER",
	"LAST",
};
static int amdgpu_device_fw_loading(struct amdgpu_device *adev);
static void sgpu_page_fault_recovery(struct work_struct *work);

/* default poll interval is 100 ms */
static unsigned int fault_detect_interval_ms = 100;

static ssize_t fault_detect_interval_ms_store(struct device *dev,
			   struct device_attribute *attr,
			   const char *buf, size_t size)
{
	unsigned long new;
	int ret;

	ret = kstrtoul(buf, 0, &new);
	if (ret)
		return ret;

	fault_detect_interval_ms = new;

	/* Always return full write size even if we didn't consume all */
	return size;
}

static ssize_t fault_detect_interval_ms_show(struct device *dev,
			  struct device_attribute *attr,
			  char *buf)
{
	return snprintf(buf, PAGE_SIZE, "%d\n", fault_detect_interval_ms);
}

static DEVICE_ATTR_RW(fault_detect_interval_ms);

static int amdgpu_device_fault_detect_init(struct amdgpu_device *adev);
static int amdgpu_device_fault_detect_fini(struct amdgpu_device *adev);

/**
 * DOC: pcie_replay_count
 *
 * The amdgpu driver provides a sysfs API for reporting the total number
 * of PCIe replays (NAKs)
 * The file pcie_replay_count is used for this and returns the total
 * number of replays as a sum of the NAKs generated and NAKs received
 */

static ssize_t amdgpu_device_get_pcie_replay_count(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	struct drm_device *ddev = dev_get_drvdata(dev);
	struct amdgpu_device *adev = drm_to_adev(ddev);
	uint64_t cnt = amdgpu_asic_get_pcie_replay_count(adev);

	return snprintf(buf, PAGE_SIZE, "%llu\n", cnt);
}

static DEVICE_ATTR(pcie_replay_count, S_IRUGO,
		amdgpu_device_get_pcie_replay_count, NULL);

static void amdgpu_device_get_pcie_info(struct amdgpu_device *adev);

/**
 * DOC: product_name
 *
 * The amdgpu driver provides a sysfs API for reporting the product name
 * for the device
 * The file serial_number is used for this and returns the product name
 * as returned from the FRU.
 * NOTE: This is only available for certain server cards
 */

static ssize_t amdgpu_device_get_product_name(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	struct drm_device *ddev = dev_get_drvdata(dev);
	struct amdgpu_device *adev = drm_to_adev(ddev);

	return snprintf(buf, PAGE_SIZE, "%s\n", adev->product_name);
}

static DEVICE_ATTR(product_name, S_IRUGO,
		amdgpu_device_get_product_name, NULL);

/**
 * DOC: product_number
 *
 * The amdgpu driver provides a sysfs API for reporting the part number
 * for the device
 * The file serial_number is used for this and returns the part number
 * as returned from the FRU.
 * NOTE: This is only available for certain server cards
 */

static ssize_t amdgpu_device_get_product_number(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	struct drm_device *ddev = dev_get_drvdata(dev);
	struct amdgpu_device *adev = drm_to_adev(ddev);

	return snprintf(buf, PAGE_SIZE, "%s\n", adev->product_number);
}

static DEVICE_ATTR(product_number, S_IRUGO,
		amdgpu_device_get_product_number, NULL);

/**
 * DOC: serial_number
 *
 * The amdgpu driver provides a sysfs API for reporting the serial number
 * for the device
 * The file serial_number is used for this and returns the serial number
 * as returned from the FRU.
 * NOTE: This is only available for certain server cards
 */

static ssize_t amdgpu_device_get_serial_number(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	struct drm_device *ddev = dev_get_drvdata(dev);
	struct amdgpu_device *adev = drm_to_adev(ddev);

	return snprintf(buf, PAGE_SIZE, "%s\n", adev->serial);
}

static DEVICE_ATTR(serial_number, S_IRUGO,
		amdgpu_device_get_serial_number, NULL);

/**
 * amdgpu_device_supports_boco - Is the device a dGPU with HG/PX power control
 *
 * @dev: drm_device pointer
 *
 * Returns true if the device is a dGPU with HG/PX power control,
 * otherwise return false.
 */
bool amdgpu_device_supports_boco(struct drm_device *dev)
{
	struct amdgpu_device *adev = drm_to_adev(dev);

	if (adev->flags & AMD_IS_PX)
		return true;
	return false;
}

/**
 * amdgpu_device_supports_baco - Does the device support BACO
 *
 * @dev: drm_device pointer
 *
 * Returns true if the device supporte BACO,
 * otherwise return false.
 */
bool amdgpu_device_supports_baco(struct drm_device *dev)
{
	struct amdgpu_device *adev = drm_to_adev(dev);

	return amdgpu_asic_supports_baco(adev);
}

/*
 * VRAM access helper functions
 */

/**
 * amdgpu_device_vram_access - read/write a buffer in vram
 *
 * @adev: amdgpu_device pointer
 * @pos: offset of the buffer in vram
 * @buf: virtual address of the buffer in system memory
 * @size: read/write size, sizeof(@buf) must > @size
 * @write: true - write to vram, otherwise - read from vram
 */
void amdgpu_device_vram_access(struct amdgpu_device *adev, loff_t pos,
			       uint32_t *buf, size_t size, bool write)
{
	unsigned long flags;
	uint32_t hi = ~0;
	uint64_t last;


#ifdef CONFIG_64BIT
	last = min(pos + size, adev->gmc.visible_vram_size);
	if (last > pos) {
		void __iomem *addr = adev->mman.aper_base_kaddr + pos;
		size_t count = last - pos;

		if (write) {
			memcpy_toio(addr, buf, count);
			mb();
			amdgpu_asic_flush_hdp(adev, NULL);
		} else {
			amdgpu_asic_invalidate_hdp(adev, NULL);
			mb();
			memcpy_fromio(buf, addr, count);
		}

		if (count == size)
			return;

		pos += count;
		buf += count / 4;
		size -= count;
	}
#endif

	spin_lock_irqsave(&adev->mmio_idx_lock, flags);
	for (last = pos + size; pos < last; pos += 4) {
		uint32_t tmp = pos >> 31;

		WREG32_NO_KIQ(mmMM_INDEX, ((uint32_t)pos) | 0x80000000);
		if (tmp != hi) {
			WREG32_NO_KIQ(mmMM_INDEX_HI, tmp);
			hi = tmp;
		}
		if (write)
			WREG32_NO_KIQ(mmMM_DATA, *buf++);
		else
			*buf++ = RREG32_NO_KIQ(mmMM_DATA);
	}
	spin_unlock_irqrestore(&adev->mmio_idx_lock, flags);
}

/*
 * register access helper functions.
 */
/**
 * amdgpu_device_rreg - read a memory mapped IO or indirect register
 *
 * @adev: amdgpu_device pointer
 * @reg: dword aligned register offset
 * @acc_flags: access flags which require special behavior
 *
 * Returns the 32 bit value from the offset specified.
 */
uint32_t amdgpu_device_rreg(struct amdgpu_device *adev,
			    uint32_t reg, uint32_t acc_flags)
{
	uint32_t ret;

	if (sgpu_no_hw_access)
		return 0;

	if ((reg * 4) < adev->rmmio_size) {
		if (!(acc_flags & AMDGPU_REGS_NO_KIQ) &&
		    amdgpu_sriov_runtime(adev) &&
		    down_read_trylock(&adev->reset_sem)) {
			ret = amdgpu_kiq_rreg(adev, reg);
			up_read(&adev->reset_sem);
		} else {
			ret = readl(((void __iomem *)adev->rmmio) + (reg * 4));
		}
	} else {
		ret = adev->pcie_rreg(adev, reg * 4);
	}

	trace_amdgpu_device_rreg(adev->pldev->dev.id, reg, ret);

	return ret;
}

/*
 * MMIO register read with bytes helper functions
 * @offset:bytes offset from MMIO start
 *
*/

/**
 * amdgpu_mm_rreg8 - read a memory mapped IO register
 *
 * @adev: amdgpu_device pointer
 * @offset: byte aligned register offset
 *
 * Returns the 8 bit value from the offset specified.
 */
uint8_t amdgpu_mm_rreg8(struct amdgpu_device *adev, uint32_t offset)
{
	if (sgpu_no_hw_access)
		return 0;

	if (offset < adev->rmmio_size)
		return (readb(adev->rmmio + offset));
	BUG();
}

/*
 * MMIO register write with bytes helper functions
 * @offset:bytes offset from MMIO start
 * @value: the value want to be written to the register
 *
*/
/**
 * amdgpu_mm_wreg8 - read a memory mapped IO register
 *
 * @adev: amdgpu_device pointer
 * @offset: byte aligned register offset
 * @value: 8 bit value to write
 *
 * Writes the value specified to the offset specified.
 */
void amdgpu_mm_wreg8(struct amdgpu_device *adev, uint32_t offset, uint8_t value)
{
	if (sgpu_no_hw_access)
		return;

	if (offset < adev->rmmio_size)
		writeb(value, adev->rmmio + offset);
	else
		BUG();
}

/**
 * amdgpu_device_wreg - write to a memory mapped IO or indirect register
 *
 * @adev: amdgpu_device pointer
 * @reg: dword aligned register offset
 * @v: 32 bit value to write to the register
 * @acc_flags: access flags which require special behavior
 *
 * Writes the value specified to the offset specified.
 */
void amdgpu_device_wreg(struct amdgpu_device *adev,
			uint32_t reg, uint32_t v,
			uint32_t acc_flags)
{
	if (sgpu_no_hw_access)
		return;

	if ((reg * 4) < adev->rmmio_size) {
		if (!(acc_flags & AMDGPU_REGS_NO_KIQ) &&
		    amdgpu_sriov_runtime(adev) &&
		    down_read_trylock(&adev->reset_sem)) {
			amdgpu_kiq_wreg(adev, reg, v);
			up_read(&adev->reset_sem);
		} else {
			writel(v, ((void __iomem *)adev->rmmio) + (reg * 4));
		}
	} else {
		adev->pcie_wreg(adev, reg * 4, v);
	}

	trace_amdgpu_device_wreg(adev->pldev->dev.id, reg, v);
}

/*
 * amdgpu_mm_wreg_mmio_rlc -  write register either with mmio or with RLC path if in range
 *
 * this function is invoked only the debugfs register access
 * */
void amdgpu_mm_wreg_mmio_rlc(struct amdgpu_device *adev,
			     uint32_t reg, uint32_t v)
{
	if (sgpu_no_hw_access)
		return;

	if (amdgpu_sriov_fullaccess(adev) &&
	    adev->gfx.rlc.funcs &&
	    adev->gfx.rlc.funcs->is_rlcg_access_range) {
		if (adev->gfx.rlc.funcs->is_rlcg_access_range(adev, reg))
			return adev->gfx.rlc.funcs->rlcg_wreg(adev, reg, v);
	} else {
		writel(v, ((void __iomem *)adev->rmmio) + (reg * 4));
	}
}

/**
 * amdgpu_io_rreg - read an IO register
 *
 * @adev: amdgpu_device pointer
 * @reg: dword aligned register offset
 *
 * Returns the 32 bit value from the offset specified.
 */
u32 amdgpu_io_rreg(struct amdgpu_device *adev, u32 reg)
{
	if (sgpu_no_hw_access)
		return 0;

	if ((reg * 4) < adev->rio_mem_size)
		return ioread32(adev->rio_mem + (reg * 4));
	else {
		iowrite32((reg * 4), adev->rio_mem + (mmMM_INDEX * 4));
		return ioread32(adev->rio_mem + (mmMM_DATA * 4));
	}
}

/**
 * amdgpu_io_wreg - write to an IO register
 *
 * @adev: amdgpu_device pointer
 * @reg: dword aligned register offset
 * @v: 32 bit value to write to the register
 *
 * Writes the value specified to the offset specified.
 */
void amdgpu_io_wreg(struct amdgpu_device *adev, u32 reg, u32 v)
{
	if (sgpu_no_hw_access)
		return;

	if ((reg * 4) < adev->rio_mem_size)
		iowrite32(v, adev->rio_mem + (reg * 4));
	else {
		iowrite32((reg * 4), adev->rio_mem + (mmMM_INDEX * 4));
		iowrite32(v, adev->rio_mem + (mmMM_DATA * 4));
	}
}

/**
 * amdgpu_mm_rdoorbell - read a doorbell dword
 *
 * @adev: amdgpu_device pointer
 * @index: doorbell index
 *
 * Returns the value in the doorbell aperture at the
 * requested doorbell index (CIK).
 */
u32 amdgpu_mm_rdoorbell(struct amdgpu_device *adev, u32 index)
{
	if (sgpu_no_hw_access)
		return 0;

	if (index < adev->doorbell.num_doorbells) {
		return readl(adev->doorbell.ptr + index);
	} else {
		DRM_ERROR("reading beyond doorbell aperture: 0x%08x!\n", index);
		return 0;
	}
}

/**
 * amdgpu_mm_wdoorbell - write a doorbell dword
 *
 * @adev: amdgpu_device pointer
 * @index: doorbell index
 * @v: value to write
 *
 * Writes @v to the doorbell aperture at the
 * requested doorbell index (CIK).
 */
void amdgpu_mm_wdoorbell(struct amdgpu_device *adev, u32 index, u32 v)
{
	if (sgpu_no_hw_access)
		return;

	if (index < adev->doorbell.num_doorbells) {
		writel(v, adev->doorbell.ptr + index);
	} else {
		DRM_ERROR("writing beyond doorbell aperture: 0x%08x!\n", index);
	}
}

/**
 * amdgpu_mm_rdoorbell64 - read a doorbell Qword
 *
 * @adev: amdgpu_device pointer
 * @index: doorbell index
 *
 * Returns the value in the doorbell aperture at the
 * requested doorbell index (VEGA10+).
 */
u64 amdgpu_mm_rdoorbell64(struct amdgpu_device *adev, u32 index)
{
	if (sgpu_no_hw_access)
		return 0;

	if (index < adev->doorbell.num_doorbells) {
		return atomic64_read((atomic64_t *)(adev->doorbell.ptr + index));
	} else {
		DRM_ERROR("reading beyond doorbell aperture: 0x%08x!\n", index);
		return 0;
	}
}

/**
 * amdgpu_mm_wdoorbell64 - write a doorbell Qword
 *
 * @adev: amdgpu_device pointer
 * @index: doorbell index
 * @v: value to write
 *
 * Writes @v to the doorbell aperture at the
 * requested doorbell index (VEGA10+).
 */
void amdgpu_mm_wdoorbell64(struct amdgpu_device *adev, u32 index, u64 v)
{
	if (sgpu_no_hw_access)
		return;

	if (index < adev->doorbell.num_doorbells) {
		atomic64_set((atomic64_t *)(adev->doorbell.ptr + index), v);
	} else {
		DRM_ERROR("writing beyond doorbell aperture: 0x%08x!\n", index);
	}
}

/**
 * amdgpu_device_indirect_rreg - read an indirect register
 *
 * @adev: amdgpu_device pointer
 * @pcie_index: mmio register offset
 * @pcie_data: mmio register offset
 *
 * Returns the value of indirect register @reg_addr
 */
u32 amdgpu_device_indirect_rreg(struct amdgpu_device *adev,
				u32 pcie_index, u32 pcie_data,
				u32 reg_addr)
{
	unsigned long flags;
	u32 r;
	void __iomem *pcie_index_offset;
	void __iomem *pcie_data_offset;

	spin_lock_irqsave(&adev->pcie_idx_lock, flags);
	pcie_index_offset = (void __iomem *)adev->rmmio + pcie_index * 4;
	pcie_data_offset = (void __iomem *)adev->rmmio + pcie_data * 4;

	writel(reg_addr, pcie_index_offset);
	readl(pcie_index_offset);
	r = readl(pcie_data_offset);
	spin_unlock_irqrestore(&adev->pcie_idx_lock, flags);

	return r;
}

/**
 * amdgpu_device_indirect_rreg64 - read a 64bits indirect register
 *
 * @adev: amdgpu_device pointer
 * @pcie_index: mmio register offset
 * @pcie_data: mmio register offset
 *
 * Returns the value of indirect register @reg_addr
 */
u64 amdgpu_device_indirect_rreg64(struct amdgpu_device *adev,
				  u32 pcie_index, u32 pcie_data,
				  u32 reg_addr)
{
	unsigned long flags;
	u64 r;
	void __iomem *pcie_index_offset;
	void __iomem *pcie_data_offset;

	spin_lock_irqsave(&adev->pcie_idx_lock, flags);
	pcie_index_offset = (void __iomem *)adev->rmmio + pcie_index * 4;
	pcie_data_offset = (void __iomem *)adev->rmmio + pcie_data * 4;

	/* read low 32 bits */
	writel(reg_addr, pcie_index_offset);
	readl(pcie_index_offset);
	r = readl(pcie_data_offset);
	/* read high 32 bits */
	writel(reg_addr + 4, pcie_index_offset);
	readl(pcie_index_offset);
	r |= ((u64)readl(pcie_data_offset) << 32);
	spin_unlock_irqrestore(&adev->pcie_idx_lock, flags);

	return r;
}

/**
 * amdgpu_device_indirect_wreg - write an indirect register address
 *
 * @adev: amdgpu_device pointer
 * @pcie_index: mmio register offset
 * @pcie_data: mmio register offset
 * @reg_addr: indirect register offset
 * @reg_data: indirect register data
 *
 */
void amdgpu_device_indirect_wreg(struct amdgpu_device *adev,
				 u32 pcie_index, u32 pcie_data,
				 u32 reg_addr, u32 reg_data)
{
	unsigned long flags;
	void __iomem *pcie_index_offset;
	void __iomem *pcie_data_offset;

	spin_lock_irqsave(&adev->pcie_idx_lock, flags);
	pcie_index_offset = (void __iomem *)adev->rmmio + pcie_index * 4;
	pcie_data_offset = (void __iomem *)adev->rmmio + pcie_data * 4;

	writel(reg_addr, pcie_index_offset);
	readl(pcie_index_offset);
	writel(reg_data, pcie_data_offset);
	readl(pcie_data_offset);
	spin_unlock_irqrestore(&adev->pcie_idx_lock, flags);
}

/**
 * amdgpu_device_indirect_wreg64 - write a 64bits indirect register address
 *
 * @adev: amdgpu_device pointer
 * @pcie_index: mmio register offset
 * @pcie_data: mmio register offset
 * @reg_addr: indirect register offset
 * @reg_data: indirect register data
 *
 */
void amdgpu_device_indirect_wreg64(struct amdgpu_device *adev,
				   u32 pcie_index, u32 pcie_data,
				   u32 reg_addr, u64 reg_data)
{
	unsigned long flags;
	void __iomem *pcie_index_offset;
	void __iomem *pcie_data_offset;

	spin_lock_irqsave(&adev->pcie_idx_lock, flags);
	pcie_index_offset = (void __iomem *)adev->rmmio + pcie_index * 4;
	pcie_data_offset = (void __iomem *)adev->rmmio + pcie_data * 4;

	/* write low 32 bits */
	writel(reg_addr, pcie_index_offset);
	readl(pcie_index_offset);
	writel((u32)(reg_data & 0xffffffffULL), pcie_data_offset);
	readl(pcie_data_offset);
	/* write high 32 bits */
	writel(reg_addr + 4, pcie_index_offset);
	readl(pcie_index_offset);
	writel((u32)(reg_data >> 32), pcie_data_offset);
	readl(pcie_data_offset);
	spin_unlock_irqrestore(&adev->pcie_idx_lock, flags);
}

/**
 * amdgpu_invalid_rreg - dummy reg read function
 *
 * @adev: amdgpu_device pointer
 * @reg: offset of register
 *
 * Dummy register read function.  Used for register blocks
 * that certain asics don't have (all asics).
 * Returns the value in the register.
 */
static uint32_t amdgpu_invalid_rreg(struct amdgpu_device *adev, uint32_t reg)
{
	DRM_ERROR("Invalid callback to read register 0x%04X\n", reg);
	BUG();
	return 0;
}

/**
 * amdgpu_invalid_wreg - dummy reg write function
 *
 * @adev: amdgpu_device pointer
 * @reg: offset of register
 * @v: value to write to the register
 *
 * Dummy register read function.  Used for register blocks
 * that certain asics don't have (all asics).
 */
static void amdgpu_invalid_wreg(struct amdgpu_device *adev, uint32_t reg, uint32_t v)
{
	DRM_ERROR("Invalid callback to write register 0x%04X with 0x%08X\n",
		  reg, v);
	BUG();
}

/**
 * amdgpu_invalid_rreg64 - dummy 64 bit reg read function
 *
 * @adev: amdgpu_device pointer
 * @reg: offset of register
 *
 * Dummy register read function.  Used for register blocks
 * that certain asics don't have (all asics).
 * Returns the value in the register.
 */
static uint64_t amdgpu_invalid_rreg64(struct amdgpu_device *adev, uint32_t reg)
{
	DRM_ERROR("Invalid callback to read 64 bit register 0x%04X\n", reg);
	BUG();
	return 0;
}

/**
 * amdgpu_invalid_wreg64 - dummy reg write function
 *
 * @adev: amdgpu_device pointer
 * @reg: offset of register
 * @v: value to write to the register
 *
 * Dummy register read function.  Used for register blocks
 * that certain asics don't have (all asics).
 */
static void amdgpu_invalid_wreg64(struct amdgpu_device *adev, uint32_t reg, uint64_t v)
{
	DRM_ERROR("Invalid callback to write 64 bit register 0x%04X with 0x%08llX\n",
		  reg, v);
	BUG();
}

/**
 * amdgpu_block_invalid_rreg - dummy reg read function
 *
 * @adev: amdgpu_device pointer
 * @block: offset of instance
 * @reg: offset of register
 *
 * Dummy register read function.  Used for register blocks
 * that certain asics don't have (all asics).
 * Returns the value in the register.
 */
static uint32_t amdgpu_block_invalid_rreg(struct amdgpu_device *adev,
					  uint32_t block, uint32_t reg)
{
	DRM_ERROR("Invalid callback to read register 0x%04X in block 0x%04X\n",
		  reg, block);
	BUG();
	return 0;
}

/**
 * amdgpu_block_invalid_wreg - dummy reg write function
 *
 * @adev: amdgpu_device pointer
 * @block: offset of instance
 * @reg: offset of register
 * @v: value to write to the register
 *
 * Dummy register read function.  Used for register blocks
 * that certain asics don't have (all asics).
 */
static void amdgpu_block_invalid_wreg(struct amdgpu_device *adev,
				      uint32_t block,
				      uint32_t reg, uint32_t v)
{
	DRM_ERROR("Invalid block callback to write register 0x%04X in block 0x%04X with 0x%08X\n",
		  reg, block, v);
	BUG();
}

/**
 * amdgpu_device_asic_init - Wrapper for atom asic_init
 *
 * @adev: amdgpu_device pointer
 *
 * Does any asic specific work and then calls atom asic init.
 */
static int amdgpu_device_asic_init(struct amdgpu_device *adev)
{
	amdgpu_asic_pre_asic_init(adev);

	return 0;
}

/**
 * amdgpu_device_vram_scratch_init - allocate the VRAM scratch page
 *
 * @adev: amdgpu_device pointer
 *
 * Allocates a scratch page of VRAM for use by various things in the
 * driver.
 */
static int amdgpu_device_vram_scratch_init(struct amdgpu_device *adev)
{
	return amdgpu_bo_create_kernel(adev, AMDGPU_GPU_PAGE_SIZE,
				       PAGE_SIZE, AMDGPU_GEM_DOMAIN_VRAM,
				       &adev->vram_scratch.robj,
				       &adev->vram_scratch.gpu_addr,
				       (void **)&adev->vram_scratch.ptr);
}

/**
 * amdgpu_device_sysram_scratch_init - allocate the System RAM scratch page
 *
 * @adev: amdgpu device pointer
 *
 * Allocates a scratch page of System Ram for use by various things in the
 * driver.
 */
static int amdgpu_device_sysram_scratch_init(struct amdgpu_device *adev)
{
	void *va;

	if (!adev->sysram_scratch_p) {
		va = dma_alloc_coherent(adev->dev,
					PAGE_SIZE,
					&adev->sysram_scratch_p,
					GFP_KERNEL);

		if (va) {
			adev->sysram_scratch_v = va;
		} else {
			dev_err(adev->dev,
				"Failed to allocate sysram_scratch buffer\n");
			return -ENOMEM;
		}
	}

	return 0;
}

/**
 * amdgpu_device_vram_scratch_fini - Free the VRAM scratch page
 *
 * @adev: amdgpu_device pointer
 *
 * Frees the VRAM scratch page.
 */
static void amdgpu_device_vram_scratch_fini(struct amdgpu_device *adev)
{
	amdgpu_bo_free_kernel(&adev->vram_scratch.robj, NULL, NULL);
}

/**
 * amdgpu_device_sysram_scratch_fini - Free the sysram scratch page
 *
 * @adev: amdgpu device pointer
 *
 * Frees the sysram scratch page.
 */
static void amdgpu_device_sysram_scratch_fini(struct amdgpu_device *adev)
{
	if (adev->sysram_scratch_p) {
		dma_free_coherent(adev->dev,
				  PAGE_SIZE,
				  adev->sysram_scratch_v,
				  adev->sysram_scratch_p);
		adev->sysram_scratch_p = 0;
		adev->sysram_scratch_v = NULL;
	}
}

/**
 * amdgpu_device_program_register_sequence - program an array of registers.
 *
 * @adev: amdgpu_device pointer
 * @registers: pointer to the register array
 * @array_size: size of the register array
 *
 * Programs an array or registers with and and or masks.
 * This is a helper for setting golden registers.
 */
void amdgpu_device_program_register_sequence(struct amdgpu_device *adev,
					     const u32 *registers,
					     const u32 array_size)
{
	u32 tmp, reg, and_mask, or_mask;
	int i;

	if (array_size % 3)
		return;

	for (i = 0; i < array_size; i +=3) {
		reg = registers[i + 0];
		and_mask = registers[i + 1];
		or_mask = registers[i + 2];

		if (and_mask == 0xffffffff) {
			tmp = or_mask;
		} else {
			tmp = RREG32(reg);
			tmp &= ~and_mask;
			if (adev->family >= AMDGPU_FAMILY_AI)
				tmp |= (or_mask & and_mask);
			else
				tmp |= or_mask;
		}
		WREG32(reg, tmp);
	}
}

/**
 * amdgpu_device_pci_config_reset - reset the GPU
 *
 * @adev: amdgpu_device pointer
 *
 * Resets the GPU using the pci config reset sequence.
 * Only applicable to asics prior to vega10.
 */
void amdgpu_device_pci_config_reset(struct amdgpu_device *adev)
{
	pci_write_config_dword(adev->pdev, 0x7c, AMDGPU_ASIC_RESET_DATA);
}

/*
 * GPU doorbell aperture helpers function.
 */
/**
 * amdgpu_device_doorbell_init - Init doorbell driver information.
 *
 * @adev: amdgpu_device pointer
 *
 * Init doorbell driver information (CIK)
 * Returns 0 on success, error on failure.
 */
static int amdgpu_device_doorbell_init(struct amdgpu_device *adev)
{

	/* No doorbell on SI hardware generation */
	if (adev->asic_type < CHIP_BONAIRE) {
		adev->doorbell.base = 0;
		adev->doorbell.size = 0;
		adev->doorbell.num_doorbells = 0;
		adev->doorbell.ptr = NULL;
		return 0;
	}

	if (adev->pdev && pci_resource_flags(adev->pdev, 2) & IORESOURCE_UNSET)
		return -EINVAL;

	amdgpu_asic_init_doorbell_index(adev);

	/* doorbell bar mapping */
	if (adev->pdev) {
		adev->doorbell.base = pci_resource_start(adev->pdev, 2);
		adev->doorbell.size = pci_resource_len(adev->pdev, 2);
	} else {
		struct resource *res;

		res = platform_get_resource_byname(adev->pldev, IORESOURCE_MEM, "doorbell");
		adev->doorbell.size = resource_size(res);
		adev->doorbell.base = res->start;
	}

	adev->doorbell.num_doorbells = min_t(u32, adev->doorbell.size / sizeof(u32),
					     adev->doorbell_index.max_assignment+1);
	if (adev->doorbell.num_doorbells == 0)
		return -EINVAL;

	/* For Vega, reserve and map two pages on doorbell BAR since SDMA
	 * paging queue doorbell use the second page. The
	 * AMDGPU_DOORBELL64_MAX_ASSIGNMENT definition assumes all the
	 * doorbells are in the first page. So with paging queue enabled,
	 * the max num_doorbells should + 1 page (0x400 in dword)
	 */
	if (adev->asic_type >= CHIP_VEGA10)
		adev->doorbell.num_doorbells += 0x400;

	adev->doorbell.ptr = devm_ioremap(&adev->pldev->dev,
					  adev->doorbell.base,
					  adev->doorbell.num_doorbells *
					  sizeof(u32));
	if (adev->doorbell.ptr == NULL)
		return -ENOMEM;

	return 0;
}

/**
 * amdgpu_device_doorbell_fini - Tear down doorbell driver information.
 *
 * @adev: amdgpu_device pointer
 *
 * Tear down doorbell driver information (CIK)
 */
static void amdgpu_device_doorbell_fini(struct amdgpu_device *adev)
{
	devm_iounmap(&adev->pldev->dev, adev->doorbell.ptr);
	adev->doorbell.ptr = NULL;
}



/*
 * amdgpu_device_wb_*()
 * Writeback is the method by which the GPU updates special pages in memory
 * with the status of certain GPU events (fences, ring pointers,etc.).
 */

/**
 * amdgpu_device_wb_fini - Disable Writeback and free memory
 *
 * @adev: amdgpu_device pointer
 *
 * Disables Writeback and frees the Writeback memory (all asics).
 * Used at driver shutdown.
 */
static void amdgpu_device_wb_fini(struct amdgpu_device *adev)
{
	if (adev->wb.wb_obj) {
		amdgpu_bo_free_kernel(&adev->wb.wb_obj,
				      &adev->wb.gpu_addr,
				      (void **)&adev->wb.wb);
		adev->wb.wb_obj = NULL;
	}
}

/**
 * amdgpu_device_wb_init- Init Writeback driver info and allocate memory
 *
 * @adev: amdgpu_device pointer
 *
 * Initializes writeback and allocates writeback memory (all asics).
 * Used at driver startup.
 * Returns 0 on success or an -error on failure.
 */
static int amdgpu_device_wb_init(struct amdgpu_device *adev)
{
	int r;

	if (adev->wb.wb_obj == NULL) {
		/* AMDGPU_MAX_WB * sizeof(uint32_t) * 8 = AMDGPU_MAX_WB 256bit slots */
		r = amdgpu_bo_create_kernel(adev, AMDGPU_MAX_WB * sizeof(uint32_t) * 8,
					    PAGE_SIZE, AMDGPU_GEM_DOMAIN_GTT,
					    &adev->wb.wb_obj, &adev->wb.gpu_addr,
					    (void **)&adev->wb.wb);
		if (r) {
			dev_warn(adev->dev, "(%d) create WB bo failed\n", r);
			return r;
		}

		adev->wb.num_wb = AMDGPU_MAX_WB;
		memset(&adev->wb.used, 0, sizeof(adev->wb.used));

		/* clear wb memory */
		memset((char *)adev->wb.wb, 0, AMDGPU_MAX_WB * sizeof(uint32_t) * 8);
	}

	return 0;
}

/**
 * amdgpu_device_wb_get - Allocate a wb entry
 *
 * @adev: amdgpu_device pointer
 * @wb: wb index
 *
 * Allocate a wb slot for use by the driver (all asics).
 * Returns 0 on success or -EINVAL on failure.
 */
int amdgpu_device_wb_get(struct amdgpu_device *adev, u32 *wb)
{
	unsigned long offset = find_first_zero_bit(adev->wb.used, adev->wb.num_wb);

	if (offset < adev->wb.num_wb) {
		__set_bit(offset, adev->wb.used);
		*wb = offset << 3; /* convert to dw offset */
		return 0;
	} else {
		return -EINVAL;
	}
}

/**
 * amdgpu_device_wb_free - Free a wb entry
 *
 * @adev: amdgpu_device pointer
 * @wb: wb index
 *
 * Free a wb slot allocated for use by the driver (all asics)
 */
void amdgpu_device_wb_free(struct amdgpu_device *adev, u32 wb)
{
	wb >>= 3;
	if (wb < adev->wb.num_wb)
		__clear_bit(wb, adev->wb.used);
}

/**
 * amdgpu_device_resize_fb_bar - try to resize FB BAR
 *
 * @adev: amdgpu_device pointer
 *
 * Try to resize FB BAR to make all VRAM CPU accessible. We try very hard not
 * to fail, but if any of the BARs is not accessible after the size we abort
 * driver loading by returning -ENODEV.
 */
int amdgpu_device_resize_fb_bar(struct amdgpu_device *adev)
{
	u64 space_needed = roundup_pow_of_two(adev->gmc.real_vram_size);
	u32 rbar_size = order_base_2(((space_needed >> 20) | 1)) - 1;
	struct pci_bus *root;
	struct resource *res;
	unsigned i;
	u16 cmd;
	int r;

	/* Bypass for VF */
	if (amdgpu_sriov_vf(adev))
		return 0;

	/* skip if the bios has already enabled large BAR */
	if (adev->gmc.real_vram_size &&
	    (pci_resource_len(adev->pdev, 0) >= adev->gmc.real_vram_size))
		return 0;

	/* Check if the root BUS has 64bit memory resources */
	root = adev->pdev->bus;
	while (root->parent)
		root = root->parent;

	pci_bus_for_each_resource(root, res, i) {
		if (res && res->flags & (IORESOURCE_MEM | IORESOURCE_MEM_64) &&
		    res->start > 0x100000000ull)
			break;
	}

	/* Trying to resize is pointless without a root hub window above 4GB */
	if (!res)
		return 0;

	/* Disable memory decoding while we change the BAR addresses and size */
	pci_read_config_word(adev->pdev, PCI_COMMAND, &cmd);
	pci_write_config_word(adev->pdev, PCI_COMMAND,
			      cmd & ~PCI_COMMAND_MEMORY);

	/* Free the VRAM and doorbell BAR, we most likely need to move both. */
	amdgpu_device_doorbell_fini(adev);
	if (adev->asic_type >= CHIP_BONAIRE)
		pci_release_resource(adev->pdev, 2);

	pci_release_resource(adev->pdev, 0);

	r = pci_resize_resource(adev->pdev, 0, rbar_size);
	if (r == -ENOSPC)
		DRM_INFO("Not enough PCI address space for a large BAR.");
	else if (r && r != -ENOTSUPP)
		DRM_ERROR("Problem resizing BAR0 (%d).", r);

	pci_assign_unassigned_bus_resources(adev->pdev->bus);

	/* When the doorbell or fb BAR isn't available we have no chance of
	 * using the device.
	 */
	r = amdgpu_device_doorbell_init(adev);
	if (r || (pci_resource_flags(adev->pdev, 0) & IORESOURCE_UNSET))
		return -ENODEV;

	pci_write_config_word(adev->pdev, PCI_COMMAND, cmd);

	return 0;
}

/*
 * GPU helpers function.
 */
/**
 * amdgpu_device_need_post - check if the hw need post or not
 *
 * @adev: amdgpu_device pointer
 *
 * Check if the asic has been initialized (all asics) at driver startup
 * or post is needed if  hw reset is performed.
 * Returns true if need or false if not.
 */
bool amdgpu_device_need_post(struct amdgpu_device *adev)
{
	uint32_t reg;

	if (!adev->pdev)
		return false;

	if (amdgpu_sriov_vf(adev))
		return false;

	if (adev->has_hw_reset) {
		adev->has_hw_reset = false;
		return true;
	}

	/* bios scratch used on CIK+ */
	if (adev->asic_type >= CHIP_BONAIRE)
		return amdgpu_atombios_scratch_need_asic_init(adev);

	/* check MEM_SIZE for older asics */
	reg = amdgpu_asic_get_config_memsize(adev);

	if ((reg != 0) && (reg != 0xffffffff))
		return false;

	return true;
}

/* if we get transitioned to only one device, take VGA back */
/**
 * amdgpu_device_vga_set_decode - enable/disable vga decode
 *
 * @pdev: PCI device pointer
 * @state: enable/disable vga decode
 *
 * Enable/disable vga decode (all asics).
 * Returns VGA resource flags.
 */
static unsigned int amdgpu_device_vga_set_decode(struct pci_dev *pdev, bool state)
{
	struct amdgpu_device *adev = drm_to_adev(pci_get_drvdata(pdev));
	amdgpu_asic_set_vga_state(adev, state);
	if (state)
		return VGA_RSRC_LEGACY_IO | VGA_RSRC_LEGACY_MEM |
		       VGA_RSRC_NORMAL_IO | VGA_RSRC_NORMAL_MEM;
	else
		return VGA_RSRC_NORMAL_IO | VGA_RSRC_NORMAL_MEM;
}

/**
 * amdgpu_device_check_block_size - validate the vm block size
 *
 * @adev: amdgpu_device pointer
 *
 * Validates the vm block size specified via module parameter.
 * The vm block size defines number of bits in page table versus page directory,
 * a page is 4KB so we have 12 bits offset, minimum 9 bits in the
 * page table and the remaining bits are in the page directory.
 */
static void amdgpu_device_check_block_size(struct amdgpu_device *adev)
{
	/* defines number of bits in page table versus page directory,
	 * a page is 4KB so we have 12 bits offset, minimum 9 bits in the
	 * page table and the remaining bits are in the page directory */
	if (amdgpu_vm_block_size == -1)
		return;

	if (amdgpu_vm_block_size < 9) {
		dev_warn(adev->dev, "VM page table size (%d) too small\n",
			 amdgpu_vm_block_size);
		amdgpu_vm_block_size = -1;
	}
}

/**
 * amdgpu_device_check_vm_size - validate the vm size
 *
 * @adev: amdgpu_device pointer
 *
 * Validates the vm size in GB specified via module parameter.
 * The VM size is the size of the GPU virtual memory space in GB.
 */
static void amdgpu_device_check_vm_size(struct amdgpu_device *adev)
{
	/* no need to check the default value */
	if (amdgpu_vm_size == -1)
		return;

	if (amdgpu_vm_size < 1) {
		dev_warn(adev->dev, "VM size (%d) too small, min is 1GB\n",
			 amdgpu_vm_size);
		amdgpu_vm_size = -1;
	}
}

static void amdgpu_device_check_smu_prv_buffer_size(struct amdgpu_device *adev)
{
	struct sysinfo si;
	bool is_os_64 = (sizeof(void *) == 8);
	uint64_t total_memory;
	uint64_t dram_size_seven_GB = 0x1B8000000;
	uint64_t dram_size_three_GB = 0xB8000000;

	if (amdgpu_smu_memory_pool_size == 0)
		return;

	if (!is_os_64) {
		DRM_WARN("Not 64-bit OS, feature not supported\n");
		goto def_value;
	}
	si_meminfo(&si);
	total_memory = (uint64_t)si.totalram * si.mem_unit;

	if ((amdgpu_smu_memory_pool_size == 1) ||
		(amdgpu_smu_memory_pool_size == 2)) {
		if (total_memory < dram_size_three_GB)
			goto def_value1;
	} else if ((amdgpu_smu_memory_pool_size == 4) ||
		(amdgpu_smu_memory_pool_size == 8)) {
		if (total_memory < dram_size_seven_GB)
			goto def_value1;
	} else {
		DRM_WARN("Smu memory pool size not supported\n");
		goto def_value;
	}
	adev->pm.smu_prv_buffer_size = amdgpu_smu_memory_pool_size << 28;

	return;

def_value1:
	DRM_WARN("No enough system memory\n");
def_value:
	adev->pm.smu_prv_buffer_size = 0;
}

/**
 * amdgpu_device_check_arguments - validate module params
 *
 * @adev: amdgpu_device pointer
 *
 * Validates certain module parameters and updates
 * the associated values used by the driver (all asics).
 */
static int amdgpu_device_check_arguments(struct amdgpu_device *adev)
{
	if (adev->asic_type == CHIP_VANGOGH_LITE) {
		amdgpu_discovery = 0;
		amdgpu_pp_feature_mask = 0;
		amdgpu_async_gfx_ring = 1;
		amdgpu_dpm = 0;
		amdgpu_vm_update_mode = 3;
	}

	if (amdgpu_sched_jobs < 4) {
		dev_warn(adev->dev, "sched jobs (%d) must be at least 4\n",
			 amdgpu_sched_jobs);
		amdgpu_sched_jobs = 4;
	} else if (!is_power_of_2(amdgpu_sched_jobs)){
		dev_warn(adev->dev, "sched jobs (%d) must be a power of 2\n",
			 amdgpu_sched_jobs);
		amdgpu_sched_jobs = roundup_pow_of_two(amdgpu_sched_jobs);
	}

	if (amdgpu_gart_size != -1 && amdgpu_gart_size < 32) {
		/* gart size must be greater or equal to 32M */
		dev_warn(adev->dev, "gart size (%d) too small\n",
			 amdgpu_gart_size);
		amdgpu_gart_size = -1;
	}

	if (amdgpu_gtt_size != -1 && amdgpu_gtt_size < 32) {
		/* gtt size must be greater or equal to 32M */
		dev_warn(adev->dev, "gtt size (%d) too small\n",
				 amdgpu_gtt_size);
		amdgpu_gtt_size = -1;
	}

	/* valid range is between 4 and 9 inclusive */
	if (amdgpu_vm_fragment_size != -1 &&
	    (amdgpu_vm_fragment_size > 9 || amdgpu_vm_fragment_size < 4)) {
		dev_warn(adev->dev, "valid range is between 4 and 9\n");
		amdgpu_vm_fragment_size = -1;
	}

	if (amdgpu_sched_hw_submission < 2) {
		dev_warn(adev->dev, "sched hw submission jobs (%d) must be at least 2\n",
			 amdgpu_sched_hw_submission);
		amdgpu_sched_hw_submission = 2;
	} else if (!is_power_of_2(amdgpu_sched_hw_submission)) {
		dev_warn(adev->dev, "sched hw submission jobs (%d) must be a power of 2\n",
			 amdgpu_sched_hw_submission);
		amdgpu_sched_hw_submission = roundup_pow_of_two(amdgpu_sched_hw_submission);
	}

	if (amdgpu_reset_method < -1 || amdgpu_reset_method > 5) {
		dev_warn(adev->dev, "invalid option for reset method, reverting to default\n");
		amdgpu_reset_method = -1;
	}

	amdgpu_device_check_smu_prv_buffer_size(adev);

	amdgpu_device_check_vm_size(adev);

	amdgpu_device_check_block_size(adev);

	adev->firmware.load_type = amdgpu_ucode_get_load_type(adev, amdgpu_fw_load_type);

	amdgpu_gmc_tmz_set(adev);

	if (amdgpu_num_kcq == -1) {
		amdgpu_num_kcq = 8;
	} else if (amdgpu_num_kcq > 8 || amdgpu_num_kcq < 0) {
		amdgpu_num_kcq = 8;
		dev_warn(adev->dev, "set kernel compute queue number to 8 due to invalid parameter provided by user\n");
	}

	amdgpu_gmc_noretry_set(adev);

	return 0;
}

/**
 * amdgpu_device_ip_set_clockgating_state - set the CG state
 *
 * @dev: amdgpu_device pointer
 * @block_type: Type of hardware IP (SMU, GFX, UVD, etc.)
 * @state: clockgating state (gate or ungate)
 *
 * Sets the requested clockgating state for all instances of
 * the hardware IP specified.
 * Returns the error code from the last instance.
 */
int amdgpu_device_ip_set_clockgating_state(void *dev,
					   enum amd_ip_block_type block_type,
					   enum amd_clockgating_state state)
{
	struct amdgpu_device *adev = dev;
	int i, r = 0;

	for (i = 0; i < adev->num_ip_blocks; i++) {
		if (!adev->ip_blocks[i].status.valid)
			continue;
		if (adev->ip_blocks[i].version->type != block_type)
			continue;
		if (!adev->ip_blocks[i].version->funcs->set_clockgating_state)
			continue;
		r = adev->ip_blocks[i].version->funcs->set_clockgating_state(
			(void *)adev, state);
		if (r)
			DRM_ERROR("set_clockgating_state of IP block <%s> failed %d\n",
				  adev->ip_blocks[i].version->funcs->name, r);
	}
	return r;
}

/**
 * amdgpu_device_ip_set_powergating_state - set the PG state
 *
 * @dev: amdgpu_device pointer
 * @block_type: Type of hardware IP (SMU, GFX, UVD, etc.)
 * @state: powergating state (gate or ungate)
 *
 * Sets the requested powergating state for all instances of
 * the hardware IP specified.
 * Returns the error code from the last instance.
 */
int amdgpu_device_ip_set_powergating_state(void *dev,
					   enum amd_ip_block_type block_type,
					   enum amd_powergating_state state)
{
	struct amdgpu_device *adev = dev;
	int i, r = 0;

	for (i = 0; i < adev->num_ip_blocks; i++) {
		if (!adev->ip_blocks[i].status.valid)
			continue;
		if (adev->ip_blocks[i].version->type != block_type)
			continue;
		if (!adev->ip_blocks[i].version->funcs->set_powergating_state)
			continue;
		r = adev->ip_blocks[i].version->funcs->set_powergating_state(
			(void *)adev, state);
		if (r)
			DRM_ERROR("set_powergating_state of IP block <%s> failed %d\n",
				  adev->ip_blocks[i].version->funcs->name, r);
	}
	return r;
}

/**
 * amdgpu_device_ip_get_clockgating_state - get the CG state
 *
 * @adev: amdgpu_device pointer
 * @flags: clockgating feature flags
 *
 * Walks the list of IPs on the device and updates the clockgating
 * flags for each IP.
 * Updates @flags with the feature flags for each hardware IP where
 * clockgating is enabled.
 */
void amdgpu_device_ip_get_clockgating_state(struct amdgpu_device *adev,
					    u32 *flags)
{
	int i;

	for (i = 0; i < adev->num_ip_blocks; i++) {
		if (!adev->ip_blocks[i].status.valid)
			continue;
		if (adev->ip_blocks[i].version->funcs->get_clockgating_state)
			adev->ip_blocks[i].version->funcs->get_clockgating_state((void *)adev, flags);
	}
}

/**
 * amdgpu_device_ip_wait_for_idle - wait for idle
 *
 * @adev: amdgpu_device pointer
 * @block_type: Type of hardware IP (SMU, GFX, UVD, etc.)
 *
 * Waits for the request hardware IP to be idle.
 * Returns 0 for success or a negative error code on failure.
 */
int amdgpu_device_ip_wait_for_idle(struct amdgpu_device *adev,
				   enum amd_ip_block_type block_type)
{
	int i, r;

	for (i = 0; i < adev->num_ip_blocks; i++) {
		if (!adev->ip_blocks[i].status.valid)
			continue;
		if (adev->ip_blocks[i].version->type == block_type) {
			r = adev->ip_blocks[i].version->funcs->wait_for_idle((void *)adev);
			if (r)
				return r;
			break;
		}
	}
	return 0;

}

/**
 * amdgpu_device_ip_is_idle - is the hardware IP idle
 *
 * @adev: amdgpu_device pointer
 * @block_type: Type of hardware IP (SMU, GFX, UVD, etc.)
 *
 * Check if the hardware IP is idle or not.
 * Returns true if it the IP is idle, false if not.
 */
bool amdgpu_device_ip_is_idle(struct amdgpu_device *adev,
			      enum amd_ip_block_type block_type)
{
	int i;

	for (i = 0; i < adev->num_ip_blocks; i++) {
		if (!adev->ip_blocks[i].status.valid)
			continue;
		if (adev->ip_blocks[i].version->type == block_type)
			return adev->ip_blocks[i].version->funcs->is_idle((void *)adev);
	}
	return true;

}

/**
 * amdgpu_device_ip_get_ip_block - get a hw IP pointer
 *
 * @adev: amdgpu_device pointer
 * @type: Type of hardware IP (SMU, GFX, UVD, etc.)
 *
 * Returns a pointer to the hardware IP block structure
 * if it exists for the asic, otherwise NULL.
 */
struct amdgpu_ip_block *
amdgpu_device_ip_get_ip_block(struct amdgpu_device *adev,
			      enum amd_ip_block_type type)
{
	int i;

	for (i = 0; i < adev->num_ip_blocks; i++)
		if (adev->ip_blocks[i].version->type == type)
			return &adev->ip_blocks[i];

	return NULL;
}

/**
 * amdgpu_device_ip_block_version_cmp
 *
 * @adev: amdgpu_device pointer
 * @type: enum amd_ip_block_type
 * @major: major version
 * @minor: minor version
 *
 * return 0 if equal or greater
 * return 1 if smaller or the ip_block doesn't exist
 */
int amdgpu_device_ip_block_version_cmp(struct amdgpu_device *adev,
				       enum amd_ip_block_type type,
				       u32 major, u32 minor)
{
	struct amdgpu_ip_block *ip_block = amdgpu_device_ip_get_ip_block(adev, type);

	if (ip_block && ((ip_block->version->major > major) ||
			((ip_block->version->major == major) &&
			(ip_block->version->minor >= minor))))
		return 0;

	return 1;
}

/**
 * amdgpu_device_ip_block_add
 *
 * @adev: amdgpu_device pointer
 * @ip_block_version: pointer to the IP to add
 *
 * Adds the IP block driver information to the collection of IPs
 * on the asic.
 */
int amdgpu_device_ip_block_add(struct amdgpu_device *adev,
			       const struct amdgpu_ip_block_version *ip_block_version)
{
	if (!ip_block_version)
		return -EINVAL;

	DRM_INFO("add ip block number %d <%s>\n", adev->num_ip_blocks,
		  ip_block_version->funcs->name);

	adev->ip_blocks[adev->num_ip_blocks++].version = ip_block_version;

	return 0;
}

/**
 * amdgpu_device_enable_virtual_display - enable virtual display feature
 *
 * @adev: amdgpu_device pointer
 *
 * Enabled the virtual display feature if the user has enabled it via
 * the module parameter virtual_display.  This feature provides a virtual
 * display hardware on headless boards or in virtualized environments.
 * This function parses and validates the configuration string specified by
 * the user and configues the virtual display configuration (number of
 * virtual connectors, crtcs, etc.) specified.
 */
static void amdgpu_device_enable_virtual_display(struct amdgpu_device *adev)
{
	adev->enable_virtual_display = false;

	if (amdgpu_virtual_display) {
		const char *pci_address_name = pci_name(adev->pdev);
		char *pciaddstr, *pciaddstr_tmp, *pciaddname_tmp, *pciaddname;

		pciaddstr = kstrdup(amdgpu_virtual_display, GFP_KERNEL);
		pciaddstr_tmp = pciaddstr;
		while ((pciaddname_tmp = strsep(&pciaddstr_tmp, ";"))) {
			pciaddname = strsep(&pciaddname_tmp, ",");
			if (!strcmp("all", pciaddname)
			    || !strcmp(pci_address_name, pciaddname)) {
				long num_crtc;
				int res = -1;

				adev->enable_virtual_display = true;

				if (pciaddname_tmp)
					res = kstrtol(pciaddname_tmp, 10,
						      &num_crtc);

				if (!res) {
					if (num_crtc < 1)
						num_crtc = 1;
					if (num_crtc > 6)
						num_crtc = 6;
					adev->mode_info.num_crtc = num_crtc;
				} else {
					adev->mode_info.num_crtc = 1;
				}
				break;
			}
		}

		DRM_INFO("virtual display string:%s, %s:virtual_display:%d, num_crtc:%d\n",
			 amdgpu_virtual_display, pci_address_name,
			 adev->enable_virtual_display, adev->mode_info.num_crtc);

		kfree(pciaddstr);
	}
}

/**
 * amdgpu_device_parse_gpu_info_fw - parse gpu info firmware
 *
 * @adev: amdgpu_device pointer
 *
 * Parses the asic configuration parameters specified in the gpu info
 * firmware and makes them availale to the driver for use in configuring
 * the asic.
 * Returns 0 on success, -EINVAL on failure.
 */
static int amdgpu_device_parse_gpu_info_fw(struct amdgpu_device *adev)
{
	int err = 0;
	const struct gpu_info_firmware_header_v1_0 *hdr;
	char *gpu_info_bin = NULL;

	adev->firmware.gpu_info_fw = NULL;

	if (adev->mman.discovery_bin) {
		amdgpu_discovery_get_gfx_info(adev);

		return 0;
	}

	if (AMDGPU_IS_MGFX0(adev->grbm_chip_rev))
		gpu_info_bin = (char *)vangogh_lite_m0_gpu_info_bin;
	else if (AMDGPU_IS_MGFX1(adev->grbm_chip_rev))
		gpu_info_bin = (char *)vangogh_lite_m1_gpu_info_bin;
	else if (AMDGPU_IS_MGFX2(adev->grbm_chip_rev))
		gpu_info_bin = (char *)vangogh_lite_m2_gpu_info_bin;
	else if (AMDGPU_IS_MGFX1_MID(adev->grbm_chip_rev))
		gpu_info_bin = (char *)vangogh_lite_m1_1_gpu_info_bin;
	else {
		dev_err(adev->dev,
			"Unsupported HW version %#10x\n", adev->grbm_chip_rev);
		err = -EINVAL;
		goto out;
	}

	hdr = (const struct gpu_info_firmware_header_v1_0 *)gpu_info_bin;
	amdgpu_ucode_print_gpu_info_hdr(&hdr->header);

	switch (hdr->version_major) {
	case 1:
	{
		const struct gpu_info_firmware_v1_0 *gpu_info_fw =
			(const struct gpu_info_firmware_v1_0 *)((const u8 *)gpu_info_bin +
								le32_to_cpu(hdr->header.ucode_array_offset_bytes));

		adev->gfx.config.max_shader_engines = le32_to_cpu(gpu_info_fw->gc_num_se);
		adev->gfx.config.max_cu_per_sh = le32_to_cpu(gpu_info_fw->gc_num_cu_per_sh);
		adev->gfx.config.max_sh_per_se = le32_to_cpu(gpu_info_fw->gc_num_sh_per_se);
		adev->gfx.config.max_backends_per_se = le32_to_cpu(gpu_info_fw->gc_num_rb_per_se);
		adev->gfx.config.max_texture_channel_caches =
			le32_to_cpu(gpu_info_fw->gc_num_tccs);
		adev->gfx.config.max_gprs = le32_to_cpu(gpu_info_fw->gc_num_gprs);
		adev->gfx.config.max_gs_threads = le32_to_cpu(gpu_info_fw->gc_num_max_gs_thds);
		adev->gfx.config.gs_vgt_table_depth = le32_to_cpu(gpu_info_fw->gc_gs_table_depth);
		adev->gfx.config.gs_prim_buffer_depth = le32_to_cpu(gpu_info_fw->gc_gsprim_buff_depth);
		adev->gfx.config.double_offchip_lds_buf =
			le32_to_cpu(gpu_info_fw->gc_double_offchip_lds_buffer);
		adev->gfx.cu_info.wave_front_size = le32_to_cpu(gpu_info_fw->gc_wave_size);
		adev->gfx.cu_info.max_waves_per_simd =
			le32_to_cpu(gpu_info_fw->gc_max_waves_per_simd);
		adev->gfx.cu_info.max_scratch_slots_per_cu =
			le32_to_cpu(gpu_info_fw->gc_max_scratch_slots_per_cu);
		adev->gfx.cu_info.lds_size = le32_to_cpu(gpu_info_fw->gc_lds_size);
		if (hdr->version_minor >= 1) {
			const struct gpu_info_firmware_v1_1 *gpu_info_fw =
				(const struct gpu_info_firmware_v1_1 *)((const u8 *)gpu_info_bin +
									le32_to_cpu(hdr->header.ucode_array_offset_bytes));
			adev->gfx.config.num_sc_per_sh =
				le32_to_cpu(gpu_info_fw->num_sc_per_sh);
			adev->gfx.config.num_packer_per_sc =
				le32_to_cpu(gpu_info_fw->num_packer_per_sc);
		}

		break;
	}
	default:
		dev_err(adev->dev,
			"Unsupported gpu_info table %d\n", hdr->header.ucode_version);
		err = -EINVAL;
		goto out;
	}
out:
	return err;
}

/**
 * amdgpu_device_ip_early_init - run early init for hardware IPs
 *
 * @adev: amdgpu_device pointer
 *
 * Early initialization pass for hardware IPs.  The hardware IPs that make
 * up each asic are discovered each IP's early_init callback is run.  This
 * is the first stage in initializing the asic.
 * Returns 0 on success, negative error code on failure.
 */
static int amdgpu_device_ip_early_init(struct amdgpu_device *adev)
{
	int i, r;

	amdgpu_device_enable_virtual_display(adev);

	if (amdgpu_sriov_vf(adev)) {
		r = amdgpu_virt_request_full_gpu(adev, true);
		if (r)
			return r;
	}

	switch (adev->asic_type) {
	case  CHIP_VANGOGH_LITE:
		r = nv_set_ip_blocks(adev);
		if (r)
			return r;
		break;
	default:
		/* FIXME: not supported yet */
		return -EINVAL;
	}

	adev->pm.pp_feature = amdgpu_pp_feature_mask;
	if (amdgpu_sriov_vf(adev))
		adev->pm.pp_feature &= ~PP_GFXOFF_MASK;

	for (i = 0; i < adev->num_ip_blocks; i++) {
		if ((amdgpu_ip_block_mask & (1 << i)) == 0) {
			DRM_ERROR("disabled ip block: %d <%s>\n",
				  i, adev->ip_blocks[i].version->funcs->name);
			adev->ip_blocks[i].status.valid = false;
		} else {
			if (adev->ip_blocks[i].version->funcs->early_init) {
				r = adev->ip_blocks[i].version->funcs->early_init((void *)adev);
				if (r == -ENOENT) {
					adev->ip_blocks[i].status.valid = false;
				} else if (r) {
					DRM_ERROR("early_init of IP block <%s> failed %d\n",
						  adev->ip_blocks[i].version->funcs->name, r);
					return r;
				} else {
					adev->ip_blocks[i].status.valid = true;
				}
			} else {
				adev->ip_blocks[i].status.valid = true;
			}
		}
		/* get the vbios after the asic_funcs are set up */
		if (adev->ip_blocks[i].version->type == AMD_IP_BLOCK_TYPE_COMMON) {
			r = amdgpu_device_parse_gpu_info_fw(adev);
			if (r)
				return r;

			/* Read BIOS */
			if (adev->asic_type != CHIP_VANGOGH_LITE) {
				if (!amdgpu_get_bios(adev))
					return -EINVAL;

				r = amdgpu_atombios_init(adev);
				if (r) {
					dev_err(adev->dev, "amdgpu_atombios_init failed\n");
					amdgpu_vf_error_put(adev, AMDGIM_ERROR_VF_ATOMBIOS_INIT_FAIL, 0, 0);
					return r;
				}
			}
		}
	}

	adev->cg_flags &= (GENMASK_ULL(63,32) | amdgpu_cg_mask);
	adev->pg_flags &= amdgpu_pg_mask;

	return 0;
}

static int amdgpu_device_ip_hw_init_phase1(struct amdgpu_device *adev)
{
	int i, r;

	for (i = 0; i < adev->num_ip_blocks; i++) {
		if (!adev->ip_blocks[i].status.sw)
			continue;
		if (adev->ip_blocks[i].status.hw)
			continue;
		if (adev->ip_blocks[i].version->type == AMD_IP_BLOCK_TYPE_COMMON ||
		    (amdgpu_sriov_vf(adev) && (adev->ip_blocks[i].version->type == AMD_IP_BLOCK_TYPE_PSP)) ||
		    adev->ip_blocks[i].version->type == AMD_IP_BLOCK_TYPE_IH) {
			r = adev->ip_blocks[i].version->funcs->hw_init(adev);
			if (r) {
				DRM_ERROR("hw_init of IP block <%s> failed %d\n",
					  adev->ip_blocks[i].version->funcs->name, r);
				return r;
			}
			adev->ip_blocks[i].status.hw = true;
		}
	}

	return 0;
}

static int amdgpu_device_ip_hw_init_phase2(struct amdgpu_device *adev)
{
	int i, r;

	for (i = 0; i < adev->num_ip_blocks; i++) {
		if (!adev->ip_blocks[i].status.sw)
			continue;
		if (adev->ip_blocks[i].status.hw)
			continue;
		r = adev->ip_blocks[i].version->funcs->hw_init(adev);
		if (r) {
			DRM_ERROR("hw_init of IP block <%s> failed %d\n",
				  adev->ip_blocks[i].version->funcs->name, r);
			return r;
		}
		adev->ip_blocks[i].status.hw = true;
	}

	return 0;
}

static int amdgpu_device_fw_loading(struct amdgpu_device *adev)
{
	int r = 0;
	int i;


	for (i = 0; i < adev->num_ip_blocks; i++) {
		if (!adev->ip_blocks[i].version->funcs->fw_init)
			continue;

		/* separate firmware related register access
		 * from hardware init
		 */
		if (adev->ip_blocks[i].status.hw)
			continue;

		r = adev->ip_blocks[i].version->funcs->fw_init(adev);
		if (r) {
			DRM_ERROR("HW defect detected : fw_init of IP block <%s> failed %d\n",
				  adev->ip_blocks[i].version->funcs->name, r);
			sgpu_debug_snapshot_expire_watchdog();
			return r;
		}
		break;
	}

	if (amdgpu_emu_mode == 1) {
		/* post the asic on emulation mode */
		emu_soc_asic_init(adev);
	}

	return 0;
}

/**
 * amdgpu_device_ip_init - run init for hardware IPs
 *
 * @adev: amdgpu_device pointer
 *
 * Main initialization pass for hardware IPs.  The list of all the hardware
 * IPs that make up the asic is walked and the sw_init and hw_init callbacks
 * are run.  sw_init initializes the software state associated with each IP
 * and hw_init initializes the hardware associated with each IP.
 * Returns 0 on success, negative error code on failure.
 */
static int amdgpu_device_ip_init(struct amdgpu_device *adev)
{
	int i, r;
	u32 domain;

	for (i = 0; i < adev->num_ip_blocks; i++) {
		if (!adev->ip_blocks[i].status.valid)
			continue;
		r = adev->ip_blocks[i].version->funcs->sw_init((void *)adev);
		if (r) {
			DRM_ERROR("sw_init of IP block <%s> failed %d\n",
				  adev->ip_blocks[i].version->funcs->name, r);
			goto init_failed;
		}
		adev->ip_blocks[i].status.sw = true;

		/* need to do gmc hw init early so we can allocate gpu mem */
		if (adev->ip_blocks[i].version->type == AMD_IP_BLOCK_TYPE_GMC) {
			if (amdgpu_force_gtt)
				r = amdgpu_device_sysram_scratch_init(adev);
			else
				r = amdgpu_device_vram_scratch_init(adev);

			if (r) {
				DRM_ERROR("amdgpu_vram_scratch_init failed %d\n", r);
				goto init_failed;
			}
			r = adev->ip_blocks[i].version->funcs->hw_init((void *)adev);
			if (r) {
				DRM_ERROR("hw_init %d failed %d\n", i, r);
				goto init_failed;
			}
			r = amdgpu_device_wb_init(adev);
			if (r) {
				DRM_ERROR("amdgpu_device_wb_init failed %d\n", r);
				goto init_failed;
			}
			adev->ip_blocks[i].status.hw = true;

			/* right after GMC hw init, we create CSA */
			if (amdgpu_mcbp || amdgpu_sriov_vf(adev)) {
				if (amdgpu_force_gtt)
					domain = AMDGPU_GEM_DOMAIN_GTT;
				else
					domain = AMDGPU_GEM_DOMAIN_VRAM;

				/* Allocate CSA for each HW Queue */
				r = amdgpu_allocate_static_csa(adev,
							&adev->virt.csa_obj,
							domain,
							AMDGPU_CSA_SIZE * adev->gfx.num_gfx_rings);
				if (r) {
					DRM_ERROR("allocate CSA failed %d\n", r);
					goto init_failed;
				}
			}
		}
	}

	if (amdgpu_sriov_vf(adev))
		amdgpu_virt_init_data_exchange(adev);

	r = amdgpu_ib_pool_init(adev);
	if (r) {
		dev_err(adev->dev, "IB initialization failed (%d).\n", r);
		amdgpu_vf_error_put(adev, AMDGIM_ERROR_VF_IB_INIT_FAIL, 0, r);
		goto init_failed;
	}

	r = amdgpu_ucode_create_bo(adev); /* create ucode bo when sw_init complete*/
	if (r)
		goto init_failed;

	r = amdgpu_device_ip_hw_init_phase1(adev);
	if (r)
		goto init_failed;

	r = amdgpu_device_ip_hw_init_phase2(adev);
	if (r)
		goto init_failed;

	amdgpu_fru_get_product_info(adev);

init_failed:
	if (amdgpu_sriov_vf(adev))
		amdgpu_virt_release_full_gpu(adev, true);

	return r;
}

/**
 * amdgpu_device_fill_reset_magic - writes reset magic to gart pointer
 *
 * @adev: amdgpu_device pointer
 *
 * Writes a reset magic value to the gart pointer in VRAM.  The driver calls
 * this function before a GPU reset.  If the value is retained after a
 * GPU reset, VRAM has not been lost.  Some GPU resets may destry VRAM contents.
 */
static void amdgpu_device_fill_reset_magic(struct amdgpu_device *adev)
{
	memcpy(adev->reset_magic, adev->gart.ptr, AMDGPU_RESET_MAGIC_NUM);
}

/**
 * amdgpu_device_check_vram_lost - check if vram is valid
 *
 * @adev: amdgpu_device pointer
 *
 * Checks the reset magic value written to the gart pointer in VRAM.
 * The driver calls this after a GPU reset to see if the contents of
 * VRAM is lost or now.
 * returns true if vram is lost, false if not.
 */
static bool amdgpu_device_check_vram_lost(struct amdgpu_device *adev)
{
	if (memcmp(adev->gart.ptr, adev->reset_magic,
			AMDGPU_RESET_MAGIC_NUM))
		return true;

	if (!amdgpu_in_reset(adev))
		return false;

	/*
	 * For all ASICs with baco/mode1 reset, the VRAM is
	 * always assumed to be lost.
	 */
	switch (amdgpu_asic_reset_method(adev)) {
	case AMD_RESET_METHOD_BACO:
	case AMD_RESET_METHOD_MODE1:
		return true;
	default:
		return false;
	}
}

/**
 * amdgpu_device_set_cg_state - set clockgating for amdgpu device
 *
 * @adev: amdgpu_device pointer
 * @state: clockgating state (gate or ungate)
 *
 * The list of all the hardware IPs that make up the asic is walked and the
 * set_clockgating_state callbacks are run.
 * Late initialization pass enabling clockgating for hardware IPs.
 * Fini or suspend, pass disabling clockgating for hardware IPs.
 * Returns 0 on success, negative error code on failure.
 */

static int amdgpu_device_set_cg_state(struct amdgpu_device *adev,
						enum amd_clockgating_state state)
{
	int i, j, r;

	for (j = 0; j < adev->num_ip_blocks; j++) {
		i = state == AMD_CG_STATE_GATE ? j : adev->num_ip_blocks - j - 1;
		if (!adev->ip_blocks[i].status.late_initialized)
			continue;
		if (adev->ip_blocks[i].version->funcs->set_clockgating_state) {
			/* enable clockgating to save power */
			r = adev->ip_blocks[i].version->funcs->set_clockgating_state((void *)adev,
										     state);
			if (r) {
				DRM_ERROR("set_clockgating_state(gate) of IP block <%s> failed %d\n",
					  adev->ip_blocks[i].version->funcs->name, r);
				return r;
			}
		}
	}

	return 0;
}

static int amdgpu_device_set_pg_state(struct amdgpu_device *adev, enum amd_powergating_state state)
{
	int i, j, r;

	if (amdgpu_emu_mode == 1)
		return 0;

	for (j = 0; j < adev->num_ip_blocks; j++) {
		i = state == AMD_PG_STATE_GATE ? j : adev->num_ip_blocks - j - 1;
		if (!adev->ip_blocks[i].status.late_initialized)
			continue;
		if (adev->ip_blocks[i].version->funcs->set_powergating_state) {
			/* enable powergating to save power */
			r = adev->ip_blocks[i].version->funcs->set_powergating_state((void *)adev,
											state);
			if (r) {
				DRM_ERROR("set_powergating_state(gate) of IP block <%s> failed %d\n",
					  adev->ip_blocks[i].version->funcs->name, r);
				return r;
			}
		}
	}
	return 0;
}

/**
 * amdgpu_device_ip_late_init - run late init for hardware IPs
 *
 * @adev: amdgpu_device pointer
 *
 * Late initialization pass for hardware IPs.  The list of all the hardware
 * IPs that make up the asic is walked and the late_init callbacks are run.
 * late_init covers any special initialization that an IP requires
 * after all of the have been initialized or something that needs to happen
 * late in the init process.
 * Returns 0 on success, negative error code on failure.
 */
static int amdgpu_device_ip_late_init(struct amdgpu_device *adev)
{
	int i = 0, r;

	for (i = 0; i < adev->num_ip_blocks; i++) {
		if (!adev->ip_blocks[i].status.hw)
			continue;
		if (adev->ip_blocks[i].version->funcs->late_init) {
			r = adev->ip_blocks[i].version->funcs->late_init((void *)adev);
			if (r) {
				DRM_ERROR("late_init of IP block <%s> failed %d\n",
					  adev->ip_blocks[i].version->funcs->name, r);
				return r;
			}
		}
		adev->ip_blocks[i].status.late_initialized = true;
	}

	amdgpu_device_set_cg_state(adev, AMD_CG_STATE_GATE);
	amdgpu_device_set_pg_state(adev, AMD_PG_STATE_GATE);

	/* IFPO setting should be located after enabling CGCG */
	sgpu_ifpo_enable(adev);

	amdgpu_device_fill_reset_magic(adev);

	return 0;
}

/**
 * amdgpu_device_ip_fini - run fini for hardware IPs
 *
 * @adev: amdgpu_device pointer
 *
 * Main teardown pass for hardware IPs.  The list of all the hardware
 * IPs that make up the asic is walked and the hw_fini and sw_fini callbacks
 * are run.  hw_fini tears down the hardware associated with each IP
 * and sw_fini tears down any software state associated with each IP.
 * Returns 0 on success, negative error code on failure.
 */
static int amdgpu_device_ip_fini(struct amdgpu_device *adev)
{
	int i, r;

	amdgpu_device_set_pg_state(adev, AMD_PG_STATE_UNGATE);
	amdgpu_device_set_cg_state(adev, AMD_CG_STATE_UNGATE);

	/* need to disable SMC first */
	for (i = 0; i < adev->num_ip_blocks; i++) {
		if (!adev->ip_blocks[i].status.hw)
			continue;
		if (adev->ip_blocks[i].version->type == AMD_IP_BLOCK_TYPE_SMC) {
			r = adev->ip_blocks[i].version->funcs->hw_fini((void *)adev);
			/* XXX handle errors */
			if (r) {
				DRM_DEBUG("hw_fini of IP block <%s> failed %d\n",
					  adev->ip_blocks[i].version->funcs->name, r);
			}
			adev->ip_blocks[i].status.hw = false;
			break;
		}
	}

	for (i = adev->num_ip_blocks - 1; i >= 0; i--) {
		if (!adev->ip_blocks[i].status.hw)
			continue;

		r = adev->ip_blocks[i].version->funcs->hw_fini((void *)adev);
		/* XXX handle errors */
		if (r) {
			DRM_DEBUG("hw_fini of IP block <%s> failed %d\n",
				  adev->ip_blocks[i].version->funcs->name, r);
		}

		adev->ip_blocks[i].status.hw = false;
	}


	for (i = adev->num_ip_blocks - 1; i >= 0; i--) {
		if (!adev->ip_blocks[i].status.sw)
			continue;

		if (adev->ip_blocks[i].version->type == AMD_IP_BLOCK_TYPE_GMC) {
			amdgpu_ucode_free_bo(adev);
			amdgpu_free_static_csa(&adev->virt.csa_obj);
			amdgpu_device_wb_fini(adev);
			if (amdgpu_force_gtt)
				amdgpu_device_sysram_scratch_fini(adev);
			else
				amdgpu_device_vram_scratch_fini(adev);
			amdgpu_ib_pool_fini(adev);
		}

		r = adev->ip_blocks[i].version->funcs->sw_fini((void *)adev);
		/* XXX handle errors */
		if (r) {
			DRM_DEBUG("sw_fini of IP block <%s> failed %d\n",
				  adev->ip_blocks[i].version->funcs->name, r);
		}
		adev->ip_blocks[i].status.sw = false;
		adev->ip_blocks[i].status.valid = false;
	}

	for (i = adev->num_ip_blocks - 1; i >= 0; i--) {
		if (!adev->ip_blocks[i].status.late_initialized)
			continue;
		if (adev->ip_blocks[i].version->funcs->late_fini)
			adev->ip_blocks[i].version->funcs->late_fini((void *)adev);
		adev->ip_blocks[i].status.late_initialized = false;
	}

	if (amdgpu_sriov_vf(adev))
		if (amdgpu_virt_release_full_gpu(adev, false))
			DRM_ERROR("failed to release exclusive mode on fini\n");

	return 0;
}

/**
 * amdgpu_device_delayed_init_work_handler - work handler for IB tests
 *
 * @work: work_struct.
 */
static void amdgpu_device_delayed_init_work_handler(struct work_struct *work)
{
	struct amdgpu_device *adev =
		container_of(work, struct amdgpu_device, delayed_init_work.work);
	int r;

	r = amdgpu_ib_ring_tests(adev);
	if (r)
		DRM_ERROR("ib ring test failed (%d).\n", r);
}

static void amdgpu_device_delay_enable_gfx_off(struct work_struct *work)
{
	struct amdgpu_device *adev =
		container_of(work, struct amdgpu_device, gfx.gfx_off_delay_work.work);

	mutex_lock(&adev->gfx.gfx_off_mutex);
	if (!adev->gfx.gfx_off_state && !adev->gfx.gfx_off_req_count) {
			adev->gfx.gfx_off_state = true;
	}
	mutex_unlock(&adev->gfx.gfx_off_mutex);
}

/**
 * amdgpu_device_ip_suspend_phase1 - run suspend for hardware IPs (phase 1)
 *
 * @adev: amdgpu_device pointer
 *
 * Main suspend function for hardware IPs.  The list of all the hardware
 * IPs that make up the asic is walked, clockgating is disabled and the
 * suspend callbacks are run.  suspend puts the hardware and software state
 * in each IP into a state suitable for suspend.
 * Returns 0 on success, negative error code on failure.
 */
static int amdgpu_device_ip_suspend_phase1(struct amdgpu_device *adev)
{
	int i, r;

	for (i = adev->num_ip_blocks - 1; i >= 0; i--) {
		if (!adev->ip_blocks[i].status.valid)
			continue;

		/* displays are handled separately */
		if (adev->ip_blocks[i].version->type != AMD_IP_BLOCK_TYPE_DCE)
			continue;

		/* XXX handle errors */
		r = adev->ip_blocks[i].version->funcs->suspend(adev);
		/* XXX handle errors */
		if (r) {
			DRM_ERROR("suspend of IP block <%s> failed %d\n",
				  adev->ip_blocks[i].version->funcs->name, r);
			return r;
		}

		adev->ip_blocks[i].status.hw = false;
	}

	return 0;
}

/**
 * amdgpu_device_ip_suspend_phase2 - run suspend for hardware IPs (phase 2)
 *
 * @adev: amdgpu_device pointer
 *
 * Main suspend function for hardware IPs.  The list of all the hardware
 * IPs that make up the asic is walked, clockgating is disabled and the
 * suspend callbacks are run.  suspend puts the hardware and software state
 * in each IP into a state suitable for suspend.
 * Returns 0 on success, negative error code on failure.
 */
static int amdgpu_device_ip_suspend_phase2(struct amdgpu_device *adev)
{
	int i, r;

	for (i = adev->num_ip_blocks - 1; i >= 0; i--) {
		if (!adev->ip_blocks[i].status.valid)
			continue;
		/* displays are handled in phase1 */
		if (adev->ip_blocks[i].version->type == AMD_IP_BLOCK_TYPE_DCE)
			continue;
		/* XXX handle errors */
		r = adev->ip_blocks[i].version->funcs->suspend(adev);
		/* XXX handle errors */
		if (r) {
			DRM_ERROR("suspend of IP block <%s> failed %d\n",
				  adev->ip_blocks[i].version->funcs->name, r);
		}
		adev->ip_blocks[i].status.hw = false;
		/* handle putting the SMC in the appropriate state */
		if(!amdgpu_sriov_vf(adev)){
			if (adev->ip_blocks[i].version->type == AMD_IP_BLOCK_TYPE_SMC) {
				r = amdgpu_dpm_set_mp1_state(adev, adev->mp1_state);
				if (r) {
					DRM_ERROR("SMC failed to set mp1 state %d, %d\n",
							adev->mp1_state, r);
					return r;
				}
			}
		}
		adev->ip_blocks[i].status.hw = false;
	}

	return 0;
}

/**
 * amdgpu_device_ip_suspend - run suspend for hardware IPs
 *
 * @adev: amdgpu_device pointer
 *
 * Main suspend function for hardware IPs.  The list of all the hardware
 * IPs that make up the asic is walked, clockgating is disabled and the
 * suspend callbacks are run.  suspend puts the hardware and software state
 * in each IP into a state suitable for suspend.
 * Returns 0 on success, negative error code on failure.
 */
int amdgpu_device_ip_suspend(struct amdgpu_device *adev)
{
	int r;

	if (amdgpu_sriov_vf(adev))
		amdgpu_virt_request_full_gpu(adev, false);

	r = amdgpu_device_ip_suspend_phase1(adev);
	if (r)
		return r;
	r = amdgpu_device_ip_suspend_phase2(adev);

	if (amdgpu_sriov_vf(adev))
		amdgpu_virt_release_full_gpu(adev, false);

	return r;
}

static int amdgpu_device_ip_reinit_early_sriov(struct amdgpu_device *adev)
{
	int i, r;

	static enum amd_ip_block_type ip_order[] = {
		AMD_IP_BLOCK_TYPE_GMC,
		AMD_IP_BLOCK_TYPE_COMMON,
		AMD_IP_BLOCK_TYPE_PSP,
		AMD_IP_BLOCK_TYPE_IH,
	};

	for (i = 0; i < ARRAY_SIZE(ip_order); i++) {
		int j;
		struct amdgpu_ip_block *block;

		block = &adev->ip_blocks[i];
		block->status.hw = false;

		for (j = 0; j < ARRAY_SIZE(ip_order); j++) {

			if (block->version->type != ip_order[j] ||
				!block->status.valid)
				continue;

			r = block->version->funcs->hw_init(adev);
			DRM_INFO("RE-INIT-early: %s %s\n", block->version->funcs->name, r?"failed":"succeeded");
			if (r)
				return r;
			block->status.hw = true;
		}
	}

	return 0;
}

static int amdgpu_device_ip_reinit_late_sriov(struct amdgpu_device *adev)
{
	int i, r;

	static enum amd_ip_block_type ip_order[] = {
		AMD_IP_BLOCK_TYPE_SMC,
		AMD_IP_BLOCK_TYPE_DCE,
		AMD_IP_BLOCK_TYPE_GFX,
		AMD_IP_BLOCK_TYPE_SDMA,
		AMD_IP_BLOCK_TYPE_UVD,
		AMD_IP_BLOCK_TYPE_VCE,
		AMD_IP_BLOCK_TYPE_VCN
	};

	for (i = 0; i < ARRAY_SIZE(ip_order); i++) {
		int j;
		struct amdgpu_ip_block *block;

		for (j = 0; j < adev->num_ip_blocks; j++) {
			block = &adev->ip_blocks[j];

			if (block->version->type != ip_order[i] ||
				!block->status.valid ||
				block->status.hw)
				continue;

			if (block->version->type == AMD_IP_BLOCK_TYPE_SMC)
				r = block->version->funcs->resume(adev);
			else
				r = block->version->funcs->hw_init(adev);

			DRM_INFO("RE-INIT-late: %s %s\n", block->version->funcs->name, r?"failed":"succeeded");
			if (r)
				return r;
			block->status.hw = true;
		}
	}

	return 0;
}

/**
 * amdgpu_device_ip_resume_phase1 - run resume for hardware IPs
 *
 * @adev: amdgpu_device pointer
 *
 * First resume function for hardware IPs.  The list of all the hardware
 * IPs that make up the asic is walked and the resume callbacks are run for
 * COMMON, GMC, and IH.  resume puts the hardware into a functional state
 * after a suspend and updates the software state as necessary.  This
 * function is also used for restoring the GPU after a GPU reset.
 * Returns 0 on success, negative error code on failure.
 */
static int amdgpu_device_ip_resume_phase1(struct amdgpu_device *adev)
{
	int i, r;

	for (i = 0; i < adev->num_ip_blocks; i++) {
		if (!adev->ip_blocks[i].status.valid || adev->ip_blocks[i].status.hw)
			continue;
		if (adev->ip_blocks[i].version->type == AMD_IP_BLOCK_TYPE_COMMON ||
		    adev->ip_blocks[i].version->type == AMD_IP_BLOCK_TYPE_GMC ||
		    adev->ip_blocks[i].version->type == AMD_IP_BLOCK_TYPE_IH) {

			r = adev->ip_blocks[i].version->funcs->resume(adev);
			if (r) {
				DRM_ERROR("resume of IP block <%s> failed %d\n",
					  adev->ip_blocks[i].version->funcs->name, r);
				return r;
			}
			adev->ip_blocks[i].status.hw = true;
		}
	}

	return 0;
}

/**
 * amdgpu_device_ip_resume_phase2 - run resume for hardware IPs
 *
 * @adev: amdgpu_device pointer
 *
 * First resume function for hardware IPs.  The list of all the hardware
 * IPs that make up the asic is walked and the resume callbacks are run for
 * all blocks except COMMON, GMC, and IH.  resume puts the hardware into a
 * functional state after a suspend and updates the software state as
 * necessary.  This function is also used for restoring the GPU after a GPU
 * reset.
 * Returns 0 on success, negative error code on failure.
 */
static int amdgpu_device_ip_resume_phase2(struct amdgpu_device *adev)
{
	int i, r;

	for (i = 0; i < adev->num_ip_blocks; i++) {
		if (!adev->ip_blocks[i].status.valid || adev->ip_blocks[i].status.hw)
			continue;
		if (adev->ip_blocks[i].version->type == AMD_IP_BLOCK_TYPE_COMMON ||
		    adev->ip_blocks[i].version->type == AMD_IP_BLOCK_TYPE_GMC ||
		    adev->ip_blocks[i].version->type == AMD_IP_BLOCK_TYPE_IH ||
		    adev->ip_blocks[i].version->type == AMD_IP_BLOCK_TYPE_PSP)
			continue;
		r = adev->ip_blocks[i].version->funcs->resume(adev);
		if (r) {
			DRM_ERROR("resume of IP block <%s> failed %d\n",
				  adev->ip_blocks[i].version->funcs->name, r);
			return r;
		}
		adev->ip_blocks[i].status.hw = true;
	}

	return 0;
}

/**
 * amdgpu_device_ip_resume - run resume for hardware IPs
 *
 * @adev: amdgpu_device pointer
 *
 * Main resume function for hardware IPs.  The hardware IPs
 * are split into two resume functions because they are
 * are also used in in recovering from a GPU reset and some additional
 * steps need to be take between them.  In this case (S3/S4) they are
 * run sequentially.
 * Returns 0 on success, negative error code on failure.
 */
static int amdgpu_device_ip_resume(struct amdgpu_device *adev)
{
	int r;

	r = amdgpu_device_ip_resume_phase1(adev);
	if (r)
		return r;

	r = amdgpu_device_ip_resume_phase2(adev);

	return r;
}

/**
 * amdgpu_device_detect_sriov_bios - determine if the board supports SR-IOV
 *
 * @adev: amdgpu_device pointer
 *
 * Query the VBIOS data tables to determine if the board supports SR-IOV.
 */
static void amdgpu_device_detect_sriov_bios(struct amdgpu_device *adev)
{
	if (amdgpu_sriov_vf(adev)) {
		if (adev->is_atom_fw) {
			if (amdgpu_atomfirmware_gpu_supports_virtualization(adev))
				adev->virt.caps |= AMDGPU_SRIOV_CAPS_SRIOV_VBIOS;
		} else {
			if (amdgpu_atombios_has_gpu_virtualization_table(adev))
				adev->virt.caps |= AMDGPU_SRIOV_CAPS_SRIOV_VBIOS;
		}

		if (!(adev->virt.caps & AMDGPU_SRIOV_CAPS_SRIOV_VBIOS))
			amdgpu_vf_error_put(adev, AMDGIM_ERROR_VF_NO_VBIOS, 0, 0);
	}
}

static int amdgpu_device_get_job_timeout_settings(struct amdgpu_device *adev)
{
	char *input = amdgpu_lockup_timeout;
	char *timeout_setting = NULL;
	int index = 0;
	long timeout;
	int ret = 0;

	/*
	 * By default timeout for non compute jobs is 10000.
	 * And there is no timeout enforced on compute jobs.
	 * In SR-IOV or passthrough mode, timeout for compute
	 * jobs are 60000 by default.
	 */
	adev->gfx_timeout = msecs_to_jiffies(5000);
	adev->sdma_timeout = adev->video_timeout = adev->gfx_timeout;
	if (amdgpu_sriov_vf(adev) || amdgpu_passthrough(adev))
		adev->compute_timeout =  msecs_to_jiffies(60000);
	else
		adev->compute_timeout = msecs_to_jiffies(20000);

	if (strnlen(input, AMDGPU_MAX_TIMEOUT_PARAM_LENGTH)) {
		while ((timeout_setting = strsep(&input, ",")) &&
				strnlen(timeout_setting, AMDGPU_MAX_TIMEOUT_PARAM_LENGTH)) {
			ret = kstrtol(timeout_setting, 0, &timeout);
			if (ret)
				return ret;

			if (timeout == 0) {
				index++;
				continue;
			} else if (timeout < 0) {
				timeout = MAX_SCHEDULE_TIMEOUT;
			} else {
				timeout = msecs_to_jiffies(timeout);
			}

			switch (index++) {
			case 0:
				adev->gfx_timeout = timeout;
				break;
			case 1:
				adev->compute_timeout = timeout;
				break;
			case 2:
				adev->sdma_timeout = timeout;
				break;
			case 3:
				adev->video_timeout = timeout;
				break;
			default:
				break;
			}
		}
		/*
		 * There is only one value specified and
		 * it should apply to all non-compute jobs.
		 */
		if (index == 1) {
			adev->sdma_timeout = adev->video_timeout = adev->gfx_timeout;
			if (amdgpu_sriov_vf(adev) || amdgpu_passthrough(adev))
				adev->compute_timeout = adev->gfx_timeout;
		}
	}

	return ret;
}

static const struct attribute *amdgpu_dev_attributes[] = {
	&dev_attr_product_name.attr,
	&dev_attr_product_number.attr,
	&dev_attr_serial_number.attr,
	&dev_attr_pcie_replay_count.attr,
	NULL
};

/*
 * The latest engine allocation on gfx9/10 is:
 * Engine 2, 3: firmware
 * Engine 0, 1, 4~16: amdgpu ring,
 *                    subject to change when ring number changes
 * Engine 17: Gart flushes
 */
#define GFXHUB_FREE_VM_INV_ENGS_BITMAP		0x1FFF3
#define MMHUB_FREE_VM_INV_ENGS_BITMAP		0x1FFF3

/**
 * amdgpu_device_init - initialize the driver
 *
 * @adev: amdgpu_device pointer
 * @flags: driver flags
 *
 * Initializes the driver info and hw (all asics).
 * Returns 0 for success or an error on failure.
 * Called at driver startup.
 */
int amdgpu_device_init(struct amdgpu_device *adev,
		       uint32_t flags)
{
	struct drm_device *ddev = adev_to_drm(adev);
	struct pci_dev *pdev = adev->pdev;
	int r, i;
	bool boco = false;
	u32 max_MBps;

	adev->shutdown = false;
	adev->flags = flags;

	if (amdgpu_force_asic_type >= 0 && amdgpu_force_asic_type < CHIP_LAST)
		adev->asic_type = amdgpu_force_asic_type;
	else
		adev->asic_type = flags & AMD_ASIC_MASK;

	adev->usec_timeout = AMDGPU_MAX_USEC_TIMEOUT;
	if (sgpu_no_timeout != 0)
		adev->usec_timeout = INT_MAX;
	else if (amdgpu_emu_mode == 1 || IS_ENABLED(CONFIG_DRM_SGPU_EMULATOR_WORKAROUND))
		adev->usec_timeout *= 10;
	adev->gmc.gart_size = 512 * 1024 * 1024;
	adev->accel_working = false;
	adev->num_rings = 0;
	adev->num_kernel_pages = 0;
	adev->mman.buffer_funcs = NULL;
	adev->mman.buffer_funcs_ring = NULL;
	adev->vm_manager.vm_pte_funcs = NULL;
	adev->vm_manager.vm_pte_num_scheds = 0;
	adev->gmc.gmc_funcs = NULL;
	adev->fence_context = dma_fence_context_alloc(AMDGPU_MAX_RINGS);
	bitmap_zero(adev->gfx.pipe_reserve_bitmap, AMDGPU_MAX_COMPUTE_QUEUES);
	adev->vm_inv_engs[AMDGPU_GFXHUB_0] = GFXHUB_FREE_VM_INV_ENGS_BITMAP;
	adev->vm_inv_engs[AMDGPU_MMHUB_0] = MMHUB_FREE_VM_INV_ENGS_BITMAP;
	adev->vm_inv_engs[AMDGPU_MMHUB_1] = GFXHUB_FREE_VM_INV_ENGS_BITMAP;

	adev->smc_rreg = &amdgpu_invalid_rreg;
	adev->smc_wreg = &amdgpu_invalid_wreg;
	adev->pcie_rreg = &amdgpu_invalid_rreg;
	adev->pcie_wreg = &amdgpu_invalid_wreg;
	adev->pciep_rreg = &amdgpu_invalid_rreg;
	adev->pciep_wreg = &amdgpu_invalid_wreg;
	adev->pcie_rreg64 = &amdgpu_invalid_rreg64;
	adev->pcie_wreg64 = &amdgpu_invalid_wreg64;
	adev->didt_rreg = &amdgpu_invalid_rreg;
	adev->didt_wreg = &amdgpu_invalid_wreg;
	adev->gc_cac_rreg = &amdgpu_invalid_rreg;
	adev->gc_cac_wreg = &amdgpu_invalid_wreg;
	adev->audio_endpt_rreg = &amdgpu_block_invalid_rreg;
	adev->audio_endpt_wreg = &amdgpu_block_invalid_wreg;

	if (pdev)
		DRM_INFO("initializing kernel modesetting (%s 0x%04X:0x%04X 0x%04X:0x%04X 0x%02X).\n",
			 amdgpu_asic_name[adev->asic_type], pdev->vendor, pdev->device,
			 pdev->subsystem_vendor, pdev->subsystem_device, pdev->revision);

	/* mutex initialization are all done here so we
	 * can recall function without having locking issues */
	atomic_set(&adev->irq.ih.lock, 0);
	atomic_set(&adev->pc_count, 0);
	atomic_set(&adev->sqtt_count, 0);
	mutex_init(&adev->firmware.mutex);
	mutex_init(&adev->pm.mutex);
	mutex_init(&adev->gfx.gpu_clock_mutex);
	mutex_init(&adev->srbm_mutex);
	mutex_init(&adev->gfx.pipe_reserve_mutex);
	mutex_init(&adev->gfx.gfx_off_mutex);
	mutex_init(&adev->grbm_idx_mutex);
	mutex_init(&adev->mn_lock);
	mutex_init(&adev->virt.vf_errors.lock);
	hash_init(adev->mn_hash);
	atomic_set(&adev->in_gpu_reset, 0);
	init_rwsem(&adev->reset_sem);
	mutex_init(&adev->pc_sqtt_mutex);
	mutex_init(&adev->notifier_lock);
	mutex_init(&adev->recovery_mutex);

	r = amdgpu_device_check_arguments(adev);
	if (r)
		return r;

	spin_lock_init(&adev->mmio_idx_lock);
	spin_lock_init(&adev->smc_idx_lock);
	spin_lock_init(&adev->pcie_idx_lock);
	spin_lock_init(&adev->didt_idx_lock);
	spin_lock_init(&adev->gc_cac_idx_lock);
	spin_lock_init(&adev->se_cac_idx_lock);
	spin_lock_init(&adev->audio_endpt_idx_lock);
	spin_lock_init(&adev->mm_stats.lock);
	adev->page_faulted_vmid = SGPU_INVALID_VMID;

	INIT_LIST_HEAD(&adev->shadow_list);
	mutex_init(&adev->shadow_list_lock);

	INIT_DELAYED_WORK(&adev->delayed_init_work,
			  amdgpu_device_delayed_init_work_handler);
	INIT_DELAYED_WORK(&adev->gfx.gfx_off_delay_work,
			  amdgpu_device_delay_enable_gfx_off);
	INIT_DELAYED_WORK(&adev->page_fault_work, sgpu_page_fault_recovery);

	adev->gfx.gfx_off_req_count = 1;
	adev->pm.ac_power = power_supply_is_system_supplied() > 0;

	atomic_set(&adev->throttling_logging_enabled, 1);
	/*
	 * If throttling continues, logging will be performed every minute
	 * to avoid log flooding. "-1" is subtracted since the thermal
	 * throttling interrupt comes every second. Thus, the total logging
	 * interval is 59 seconds(retelimited printk interval) + 1(waiting
	 * for throttling interrupt) = 60 seconds.
	 */
	ratelimit_state_init(&adev->throttling_logging_rs, (60 - 1) * HZ, 1);
	ratelimit_set_flags(&adev->throttling_logging_rs, RATELIMIT_MSG_ON_RELEASE);

	/* Registers mapping */
	if (pdev) {
		/* TODO: block userspace mapping of io register */
		if (adev->asic_type >= CHIP_BONAIRE) {
			adev->rmmio_base = pci_resource_start(adev->pdev, 5);
			adev->rmmio_size = pci_resource_len(adev->pdev, 5);
		} else {
			adev->rmmio_base = pci_resource_start(adev->pdev, 2);
			adev->rmmio_size = pci_resource_len(adev->pdev, 2);
		}

		adev->rmmio = devm_ioremap(&pdev->dev,
					   adev->rmmio_base, adev->rmmio_size);
		if (adev->rmmio == NULL) {
			return -ENOMEM;
		}
		DRM_INFO("register mmio base: 0x%08X\n", (uint32_t)adev->rmmio_base);
		DRM_INFO("register mmio size: %u\n", (unsigned)adev->rmmio_size);

		/* io port mapping */
		for (i = 0; i < DEVICE_COUNT_RESOURCE; i++) {
			if (pci_resource_flags(adev->pdev, i) & IORESOURCE_IO) {
				adev->rio_mem_size = pci_resource_len(adev->pdev, i);
				adev->rio_mem = pci_iomap(adev->pdev, i, adev->rio_mem_size);
				break;
			}
		}
		if (adev->rio_mem == NULL)
			DRM_INFO("PCI I/O BAR is not found.\n");

		/* enable PCIE atomic ops */
		r = pci_enable_atomic_ops_to_root(adev->pdev,
						  PCI_EXP_DEVCAP2_ATOMIC_COMP32 |
						  PCI_EXP_DEVCAP2_ATOMIC_COMP64);
		if (r) {
			adev->have_atomics_support = false;
			DRM_INFO("PCIE atomic ops is not supported\n");
		} else {
			adev->have_atomics_support = true;
		}

		amdgpu_device_get_pcie_info(adev);

	} else {
		struct resource *res;

		res = platform_get_resource_byname(adev->pldev, IORESOURCE_MEM, "gpu");
		adev->rmmio_size = resource_size(res);
		adev->rmmio_base = res->start;
		adev->rmmio = devm_ioremap_resource(&adev->pldev->dev, res);
		if (IS_ERR(adev->rmmio))
			return PTR_ERR(adev->rmmio);

		DRM_INFO("register mmio base: 0x%08X\n", (uint32_t)adev->rmmio_base);
		DRM_INFO("register mmio size: %u\n", (unsigned)adev->rmmio_size);

#ifdef CONFIG_DRM_SGPU_EXYNOS
		if (sgpu_exynos_pm) {
			adev->pm.pmu_mmio = devm_platform_ioremap_resource_byname(adev->pldev,
										  "pwrctl");
			if (IS_ERR(adev->pm.pmu_mmio))
				return PTR_ERR(adev->pm.pmu_mmio);

			adev->pm.sysreg_mmio = devm_platform_ioremap_resource_byname(adev->pldev,
										     "sysreg");
			if (IS_ERR(adev->pm.sysreg_mmio))
				return PTR_ERR(adev->pm.sysreg_mmio);

			vangogh_lite_gc_gpu_power_up(adev);

			/* MGCG clock setting for POR */
			vangogh_lite_gc_set_sysregs(adev);
		}
#endif
	}

	if (amdgpu_mcbp)
		DRM_INFO("%s MCBP is enabled\n",
			(amdgpu_mcbp == 1) ?
			"Priority Based" : "Quantum Timer Based");

	if (adev->asic_type != CHIP_VANGOGH_LITE)
		/* detect hw virtualization here */
		amdgpu_detect_virtualization(adev);

	r = amdgpu_device_get_job_timeout_settings(adev);
	if (r) {
		dev_err(adev->dev, "invalid lockup_timeout parameter syntax\n");
		goto failed_unmap;
	}

	/* early init functions */
	r = amdgpu_device_ip_early_init(adev);
	if (r)
		goto failed_unmap;

	/* doorbell bar mapping and doorbell index init*/
	amdgpu_device_doorbell_init(adev);

	/* if we have > 1 VGA cards, then disable the amdgpu VGA resources */
	/* this will fail for cards that aren't VGA class devices, just
	 * ignore it */
	vga_client_register(adev->pdev, amdgpu_device_vga_set_decode);

	if (amdgpu_device_supports_boco(ddev))
		boco = true;

	r = amdgpu_device_fw_loading(adev);
	if (r)
		goto failed;

	/* lock before IFPO default enable to prevent power down */
	sgpu_ifpo_lock(adev);

	if (amdgpu_emu_mode == 1 || adev->asic_type == CHIP_VANGOGH_LITE) {
		goto fence_driver_init;
	}

	/* detect if we are with an SRIOV vbios */
	amdgpu_device_detect_sriov_bios(adev);

	/* check if we need to reset the asic
	 *  E.g., driver was not cleanly unloaded previously, etc.
	 */
	if (!amdgpu_sriov_vf(adev) && amdgpu_asic_need_reset_on_init(adev)) {
		r = amdgpu_asic_reset(adev);
		if (r) {
			dev_err(adev->dev, "asic reset on init failed\n");
			goto failed;
		}
	}

	pci_enable_pcie_error_reporting(adev->pdev);

	/* Post card if necessary */
	if (amdgpu_device_need_post(adev)) {
		if (!adev->bios) {
			dev_err(adev->dev, "no vBIOS found\n");
			r = -EINVAL;
			goto failed;
		}
		DRM_INFO("GPU posting now...\n");
		r = amdgpu_device_asic_init(adev);
		if (r) {
			dev_err(adev->dev, "gpu post error!\n");
			goto failed;
		}
	}

	if (adev->is_atom_fw) {
		/* Initialize clocks */
		r = amdgpu_atomfirmware_get_clock_info(adev);
		if (r) {
			dev_err(adev->dev, "amdgpu_atomfirmware_get_clock_info failed\n");
			amdgpu_vf_error_put(adev, AMDGIM_ERROR_VF_ATOMBIOS_GET_CLOCK_FAIL, 0, 0);
			goto failed;
		}
	} else {
		/* Initialize clocks */
		r = amdgpu_atombios_get_clock_info(adev);
		if (r) {
			dev_err(adev->dev, "amdgpu_atombios_get_clock_info failed\n");
			amdgpu_vf_error_put(adev, AMDGIM_ERROR_VF_ATOMBIOS_GET_CLOCK_FAIL, 0, 0);
			goto failed;
		}
		/* init i2c buses */
		amdgpu_atombios_i2c_init(adev);
	}

fence_driver_init:
	/* Fence driver */
	r = amdgpu_fence_driver_init(adev);
	if (r) {
		dev_err(adev->dev, "amdgpu_fence_driver_init failed\n");
		amdgpu_vf_error_put(adev, AMDGIM_ERROR_VF_FENCE_INIT_FAIL, 0, 0);
		goto failed;
	}

	/* init the mode config */
	drm_mode_config_init(adev_to_drm(adev));

	r = amdgpu_device_ip_init(adev);
	if (r) {
		/* failed in exclusive mode due to timeout */
		if (amdgpu_sriov_vf(adev) &&
		    !amdgpu_sriov_runtime(adev) &&
		    amdgpu_virt_mmio_blocked(adev) &&
		    !amdgpu_virt_wait_reset(adev)) {
			dev_err(adev->dev, "VF exclusive mode timeout\n");
			/* Don't send request since VF is inactive. */
			adev->virt.caps &= ~AMDGPU_SRIOV_CAPS_RUNTIME;
			adev->virt.ops = NULL;
			r = -EAGAIN;
			goto failed;
		}
		dev_err(adev->dev, "amdgpu_device_ip_init failed\n");
		amdgpu_vf_error_put(adev, AMDGIM_ERROR_VF_AMDGPU_INIT_FAIL, 0, 0);
		goto failed;
	}

	if (MGFX_MOD(adev->grbm_chip_rev) == 0x60)
		DRM_INFO("amdgpu HW revision: MGFX%u EVT%u.%u",
			MGFX_GEN(adev->grbm_chip_rev),
			MGFX_EVT(adev->grbm_chip_rev) - 1,
			MGFX_MINOR(adev->grbm_chip_rev));
	else if(MGFX_MOD(adev->grbm_chip_rev) == 0x30)
		DRM_INFO("amdgpu HW revision: MGFX%u MID EVT%u.%u",
                        MGFX_GEN(adev->grbm_chip_rev),
                        MGFX_EVT(adev->grbm_chip_rev) - 1,
                        MGFX_MINOR(adev->grbm_chip_rev));
	else
		DRM_INFO("invalid amdgpu HW revision: %#10x", adev->grbm_chip_rev);

	dev_info(adev->dev,
		"SE %d, SH per SE %d, CU per SH %d, active_cu_number %d\n",
			adev->gfx.config.max_shader_engines,
			adev->gfx.config.max_sh_per_se,
			adev->gfx.config.max_cu_per_sh,
			adev->gfx.cu_info.number);

	amdgpu_device_fault_detect_init(adev);

	adev->accel_working = true;

#ifdef CONFIG_DRM_SGPU_DVFS
	r = sgpu_devfreq_init(adev);
	if (r) {
		dev_err(adev->dev, "sgpu_devfreq_init failed\n");
		goto failed;
	}
#endif /* CONFIG_DRM_SGPU_DVFS */

	amdgpu_vm_check_compute_bug(adev);

	/* Initialize the buffer migration limit. */
	if (amdgpu_moverate >= 0)
		max_MBps = amdgpu_moverate;
	else
		max_MBps = 8; /* Allow 8 MB/s. */
	/* Get a log2 for easy divisions. */
	adev->mm_stats.log2_max_MBps = ilog2(max(1u, max_MBps));

	if (adev->asic_type != CHIP_VANGOGH_LITE)
		amdgpu_fbdev_init(adev);

	r = amdgpu_pm_sysfs_init(adev);
	if (r) {
		adev->pm_sysfs_en = false;
		DRM_ERROR("registering pm debugfs failed (%d).\n", r);
	} else
		adev->pm_sysfs_en = true;

	r = amdgpu_ucode_sysfs_init(adev);
	if (r) {
		adev->ucode_sysfs_en = false;
		DRM_ERROR("Creating firmware sysfs failed (%d).\n", r);
	} else
		adev->ucode_sysfs_en = true;

	if ((amdgpu_testing & 1)) {
		if (adev->accel_working)
			amdgpu_test_moves(adev);
		else
			DRM_INFO("amdgpu: acceleration disabled, skipping move tests\n");
	}
	if (amdgpu_benchmarking) {
		if (adev->accel_working)
			amdgpu_benchmark(adev, amdgpu_benchmarking);
		else
			DRM_INFO("amdgpu: acceleration disabled, skipping benchmarks\n");
	}

	if (adev->asic_type != CHIP_VANGOGH_LITE)
		amdgpu_register_gpu_instance(adev);

	/* enable clockgating, etc. after ib tests, etc. since some blocks require
	 * explicit gating rather than handling it automatically.
	 */
	r = amdgpu_device_ip_late_init(adev);
	if (r) {
		dev_err(adev->dev, "amdgpu_device_ip_late_init failed\n");
		amdgpu_vf_error_put(adev, AMDGIM_ERROR_VF_AMDGPU_LATE_INIT_FAIL, 0, r);
		goto failed;
	}

	queue_delayed_work(system_wq, &adev->delayed_init_work,
			   msecs_to_jiffies(AMDGPU_RESUME_MS));

	if (amdgpu_sriov_vf(adev))
		flush_delayed_work(&adev->delayed_init_work);

	r = sysfs_create_files(&adev->dev->kobj, amdgpu_dev_attributes);
	if (r)
		dev_err(adev->dev, "Could not create amdgpu device attr\n");

	if (IS_ENABLED(CONFIG_PERF_EVENTS))
		r = amdgpu_pmu_init(adev);
	if (r)
		dev_err(adev->dev, "amdgpu_pmu_init failed\n");

	/* Have stored pci confspace at hand for restore in sudden PCI error */
	if (adev->pdev && amdgpu_device_cache_pci_state(adev->pdev))
		pci_restore_state(pdev);

#if IS_ENABLED(CONFIG_SEC_GPUINFO)
	adev->gpu_cur_stats[GPU_HANG] = &adev->gpu_reset_counter;
	adev->gpu_cur_stats[GPU_PAGE_FAULT] = &adev->gpu_page_fault_counter;
	adev->gpu_cur_stats[GPU_TIMEOUT] = &adev->gpu_job_timeout_counter;
	adev->gpu_cur_stats[GPU_CPU_PAGE_FAULT] = &adev->gpu_vram_cpu_page_fault_counter;
	adev->gpu_cur_stats[GPU_RETRY_HANG_DETECT] = &adev->gpu_retry_counter;
	adev->gpu_cur_stats[GPU_RING_TEST_FAIL] = &adev->gpu_ring_test_fail_counter;
#endif

	/* unlock to be able to go to IFPO power off */
	sgpu_ifpo_unlock(adev);

	adev->probe_done = true;

	ddev->switch_power_state = DRM_SWITCH_POWER_ON;

	return 0;

failed:
	amdgpu_vf_error_trans_all(adev);

failed_unmap:
	devm_iounmap(pdev ? &pdev->dev : &adev->pldev->dev, adev->rmmio);
	adev->rmmio = NULL;

	return r;
}

/**
 * amdgpu_device_fini - tear down the driver
 *
 * @adev: amdgpu_device pointer
 *
 * Tear down the driver info (all asics).
 * Called at driver shutdown.
 */
void amdgpu_device_fini(struct amdgpu_device *adev)
{
	dev_info(adev->dev, "amdgpu: finishing device.\n");
	flush_delayed_work(&adev->delayed_init_work);
	adev->shutdown = true;

	kfree(adev->pci_state);

	/* make sure IB test finished before entering exclusive mode
	 * to avoid preemption on IB test
	 * */
	if (amdgpu_sriov_vf(adev)) {
		amdgpu_virt_request_full_gpu(adev, false);
		amdgpu_virt_fini_data_exchange(adev);
	}

	/* disable all interrupts */
	amdgpu_irq_disable_all(adev);
	if (adev->mode_info.mode_config_initialized){
		drm_helper_force_disable_all(adev_to_drm(adev));
	}
	amdgpu_fence_driver_fini(adev);
#ifdef CONFIG_DRM_SGPU_DVFS
	devfreq_remove_device(adev->devfreq);
#endif /* CONFIG_DRM_SGPU_DVFS */
	if (adev->pm_sysfs_en)
		amdgpu_pm_sysfs_fini(adev);
	amdgpu_fbdev_fini(adev);
	amdgpu_device_ip_fini(adev);
	release_firmware(adev->firmware.gpu_info_fw);
	adev->firmware.gpu_info_fw = NULL;
	adev->accel_working = false;
	/* free i2c buses */
	amdgpu_i2c_fini(adev);

	if (amdgpu_emu_mode != 1)
		amdgpu_atombios_fini(adev);

	kfree(adev->bios);
	adev->bios = NULL;
	vga_client_register(adev->pdev, NULL);
	if (adev->pdev && adev->rio_mem)
		pci_iounmap(adev->pdev, adev->rio_mem);
	adev->rio_mem = NULL;
	devm_iounmap(&adev->pldev->dev, adev->rmmio);
	adev->rmmio = NULL;
#ifdef CONFIG_DRM_SGPU_EXYNOS
	if (sgpu_exynos_pm) {
		devm_iounmap(&adev->pldev->dev, adev->pm.pmu_mmio);
		adev->pm.pmu_mmio = NULL;
		devm_iounmap(&adev->pldev->dev, adev->pm.sysreg_mmio);
		adev->pm.sysreg_mmio = NULL;
	}
#endif
	amdgpu_device_doorbell_fini(adev);

	if (adev->ucode_sysfs_en)
		amdgpu_ucode_sysfs_fini(adev);

	sysfs_remove_files(&adev->dev->kobj, amdgpu_dev_attributes);
	if (IS_ENABLED(CONFIG_PERF_EVENTS))
		amdgpu_pmu_fini(adev);

	adev->secure_ring = NULL;
	sgpu_debugfs_bpmd_cleanup(adev);
	if (adev->mman.discovery_bin)
		amdgpu_discovery_fini(adev);

	amdgpu_device_fault_detect_fini(adev);
}

/*
 * Suspend & resume.
 */
/**
 * amdgpu_device_suspend - initiate device suspend
 *
 * @dev: drm dev pointer
 * @fbcon : notify the fbdev of suspend
 *
 * Puts the hw in the suspend state (all asics).
 * Returns 0 for success or an error on failure.
 * Called at driver suspend.
 */
int amdgpu_device_suspend(struct drm_device *dev, bool fbcon)
{
	struct amdgpu_device *adev;
	int r, need_to_reset;

	trace_amdgpu_device_suspend_start(0);
	adev = drm_to_adev(dev);

	if (dev->switch_power_state == DRM_SWITCH_POWER_OFF) {
		DRM_INFO("skip suspend by drm switch_power_state");
		return 0;
	}

	if (adev->in_suspend == true)
		return 0;

	/* BG3D_DVFS_CTL 0x058 disable */
	writel(0x0, adev->pm.pmu_mmio + 0x58);

	sgpu_ifpo_suspend(adev);

	adev->in_suspend = true;
	drm_kms_helper_poll_disable(dev);

	if (fbcon)
		amdgpu_fbdev_set_suspend(adev, 1);

	cancel_delayed_work_sync(&adev->delayed_init_work);

	r = amdgpu_device_ip_suspend_phase1(adev);

	/* evict vram memory */
	if (adev->gmc.real_vram_size)
		amdgpu_bo_evict_vram(adev);

	need_to_reset = amdgpu_fence_driver_suspend(adev);

#ifdef CONFIG_DRM_SGPU_DVFS
	sgpu_afm_suspend(adev);
	r = devfreq_suspend_device(adev->devfreq);
	if (r)
		dev_err(adev->dev, "devfreq_suspend_device failed\n");
	exynos_dvfs_postclear(adev->devfreq);
#endif /* CONFIG_DRM_SGPU_DVFS */

	r = amdgpu_device_ip_suspend_phase2(adev);

	if (need_to_reset) {
		DRM_INFO("do hard reset, all fences has not been signaled\n");
		vangogh_lite_gpu_quiesce(adev);
		amdgpu_do_hard_reset(adev);
	}

	/* evict remaining vram memory
	 * This second call to evict vram is to evict the gart page table
	 * using the CPU.
	 */
	if (adev->gmc.real_vram_size)
		amdgpu_bo_evict_vram(adev);

	dev->switch_power_state = DRM_SWITCH_POWER_DYNAMIC_OFF;
	trace_amdgpu_device_suspend_end(0);
	sgpu_pm_monitor_update(adev, SGPU_POWER_STATE_SUSPEND);
	SGPU_LOG(adev, DMSG_INFO, DMSG_POWER, "%s end", __func__);
	return 0;
}

/**
 * amdgpu_device_resume - initiate device resume
 *
 * @dev: drm dev pointer
 * @fbcon : notify the fbdev of resume
 *
 * Bring the hw back to operating state (all asics).
 * Returns 0 for success or an error on failure.
 * Called at driver resume.
 */
int amdgpu_device_resume(struct drm_device *dev, bool fbcon)
{
	struct amdgpu_device *adev = drm_to_adev(dev);
	int r = 0;

	trace_amdgpu_device_resume_start(0);

	if (!adev->probe_done)
		return 0;

	if (dev->switch_power_state == DRM_SWITCH_POWER_OFF) {
		DRM_INFO("skip resume by drm switch_power_state");
		return 0;
	}

	sgpu_pm_monitor_update(adev, SGPU_POWER_STATE_ON);

	r = amdgpu_device_fw_loading(adev);
	if (r)
		return r;

	/* reset counters before use of IFPO functions */
	sgpu_ifpo_resume(adev);
	/* lock before IFPO default enable to prevent power down */
	sgpu_ifpo_lock(adev);

	/* post card */
	if (amdgpu_device_need_post(adev)) {
		r = amdgpu_device_asic_init(adev);
		if (r)
			dev_err(adev->dev, "amdgpu asic init failed\n");
	}

	r = amdgpu_device_ip_resume(adev);
	if (r) {
		dev_err(adev->dev, "amdgpu_device_ip_resume failed (%d).\n", r);
		goto resume_fail;
	}

#ifdef CONFIG_DRM_SGPU_DVFS
	exynos_dvfs_preset(adev->devfreq);
	r = devfreq_resume_device(adev->devfreq);
	if (r) {
		exynos_dvfs_postclear(adev->devfreq);
		DRM_ERROR("devfreq_resume_device failed (%d).\n", r);
		goto resume_fail;
	}
	sgpu_afm_resume(adev);
#endif /* CONFIG_DRM_SGPU_DVFS */

	amdgpu_fence_driver_resume(adev);


	r = amdgpu_device_ip_late_init(adev);
	if (r)
		goto resume_fail;

	/* Make sure IB tests flushed */
	flush_delayed_work(&adev->delayed_init_work);

	if (fbcon)
		amdgpu_fbdev_set_suspend(adev, 0);

	drm_kms_helper_poll_enable(dev);

	/*
	 * Most of the connector probing functions try to acquire runtime pm
	 * refs to ensure that the GPU is powered on when connector polling is
	 * performed. Since we're calling this from a runtime PM callback,
	 * trying to acquire rpm refs will cause us to deadlock.
	 *
	 * Since we're guaranteed to be holding the rpm lock, it's safe to
	 * temporarily disable the rpm helpers so this doesn't deadlock us.
	 */
	drm_helper_hpd_irq_event(dev);

	/* gpu self-throttling DIDT/EDC */
	vangogh_lite_didt_edc_init(adev);
	sgpu_devfreq_set_didt_edc(adev, 0);

	/* BG3D_DVFS_CTL 0x058 disable */
	writel(0x1, adev->pm.pmu_mmio + 0x58);

	/* unlock to be able to go to IFPO power off */
	sgpu_ifpo_unlock(adev);

	dev->switch_power_state = DRM_SWITCH_POWER_ON;
	adev->in_suspend = false;
	trace_amdgpu_device_resume_end(0);

	return 0;

resume_fail:
	/* unlock to be able to go to IFPO power off */
	sgpu_ifpo_unlock(adev);

	return r;
}

/**
 * amdgpu_device_ip_check_soft_reset - did soft reset succeed
 *
 * @adev: amdgpu_device pointer
 *
 * The list of all the hardware IPs that make up the asic is walked and
 * the check_soft_reset callbacks are run.  check_soft_reset determines
 * if the asic is still hung or not.
 * Returns true if any of the IPs are still in a hung state, false if not.
 */
static bool amdgpu_device_ip_check_soft_reset(struct amdgpu_device *adev)
{
	int i;
	bool asic_hang = false;

	if (amdgpu_sriov_vf(adev))
		return true;

	if (amdgpu_asic_need_full_reset(adev))
		return true;

	for (i = 0; i < adev->num_ip_blocks; i++) {
		if (!adev->ip_blocks[i].status.valid)
			continue;
		if (adev->ip_blocks[i].version->funcs->check_soft_reset)
			adev->ip_blocks[i].status.hang =
				adev->ip_blocks[i].version->funcs->check_soft_reset(adev);
		if (adev->ip_blocks[i].status.hang) {
			dev_info(adev->dev, "IP block:%s is hung!\n", adev->ip_blocks[i].version->funcs->name);
			asic_hang = true;
		}
	}
	return asic_hang;
}

/**
 * amdgpu_device_ip_pre_soft_reset - prepare for soft reset
 *
 * @adev: amdgpu_device pointer
 *
 * The list of all the hardware IPs that make up the asic is walked and the
 * pre_soft_reset callbacks are run if the block is hung.  pre_soft_reset
 * handles any IP specific hardware or software state changes that are
 * necessary for a soft reset to succeed.
 * Returns 0 on success, negative error code on failure.
 */
static int amdgpu_device_ip_pre_soft_reset(struct amdgpu_device *adev)
{
	int i, r = 0;

	for (i = 0; i < adev->num_ip_blocks; i++) {
		if (!adev->ip_blocks[i].status.valid)
			continue;
		if (adev->ip_blocks[i].status.hang &&
		    adev->ip_blocks[i].version->funcs->pre_soft_reset) {
			r = adev->ip_blocks[i].version->funcs->pre_soft_reset(adev);
			if (r)
				return r;
		}
	}

	return 0;
}

/**
 * amdgpu_device_ip_need_full_reset - check if a full asic reset is needed
 *
 * @adev: amdgpu_device pointer
 *
 * Some hardware IPs cannot be soft reset.  If they are hung, a full gpu
 * reset is necessary to recover.
 * Returns true if a full asic reset is required, false if not.
 */
static bool amdgpu_device_ip_need_full_reset(struct amdgpu_device *adev)
{
	int i;

	if (amdgpu_asic_need_full_reset(adev))
		return true;

	for (i = 0; i < adev->num_ip_blocks; i++) {
		if (!adev->ip_blocks[i].status.valid)
			continue;
		if ((adev->ip_blocks[i].version->type == AMD_IP_BLOCK_TYPE_GMC) ||
		    (adev->ip_blocks[i].version->type == AMD_IP_BLOCK_TYPE_SMC) ||
		    (adev->ip_blocks[i].version->type == AMD_IP_BLOCK_TYPE_ACP) ||
		    (adev->ip_blocks[i].version->type == AMD_IP_BLOCK_TYPE_DCE) ||
		    (adev->ip_blocks[i].version->type == AMD_IP_BLOCK_TYPE_GFX) ||
		     adev->ip_blocks[i].version->type == AMD_IP_BLOCK_TYPE_PSP) {
			if (adev->ip_blocks[i].status.hang) {
				dev_info(adev->dev, "Some block need full reset!\n");
				return true;
			}
		}
	}
	return false;
}

/**
 * amdgpu_device_ip_soft_reset - do a soft reset
 *
 * @adev: amdgpu_device pointer
 *
 * The list of all the hardware IPs that make up the asic is walked and the
 * soft_reset callbacks are run if the block is hung.  soft_reset handles any
 * IP specific hardware or software state changes that are necessary to soft
 * reset the IP.
 * Returns 0 on success, negative error code on failure.
 */
static int amdgpu_device_ip_soft_reset(struct amdgpu_device *adev)
{
	int i, r = 0;

	for (i = 0; i < adev->num_ip_blocks; i++) {
		if (!adev->ip_blocks[i].status.valid)
			continue;
		if (adev->ip_blocks[i].status.hang &&
		    adev->ip_blocks[i].version->funcs->soft_reset) {
			r = adev->ip_blocks[i].version->funcs->soft_reset(adev);
			if (r)
				return r;
		}
	}

	return 0;
}

/**
 * amdgpu_device_ip_post_soft_reset - clean up from soft reset
 *
 * @adev: amdgpu_device pointer
 *
 * The list of all the hardware IPs that make up the asic is walked and the
 * post_soft_reset callbacks are run if the asic was hung.  post_soft_reset
 * handles any IP specific hardware or software state changes that are
 * necessary after the IP has been soft reset.
 * Returns 0 on success, negative error code on failure.
 */
static int amdgpu_device_ip_post_soft_reset(struct amdgpu_device *adev)
{
	int i, r = 0;

	for (i = 0; i < adev->num_ip_blocks; i++) {
		if (!adev->ip_blocks[i].status.valid)
			continue;
		if (adev->ip_blocks[i].status.hang &&
		    adev->ip_blocks[i].version->funcs->post_soft_reset)
			r = adev->ip_blocks[i].version->funcs->post_soft_reset(adev);
		if (r)
			return r;
	}

	return 0;
}

/**
 * amdgpu_device_recover_vram - Recover some VRAM contents
 *
 * @adev: amdgpu_device pointer
 *
 * Restores the contents of VRAM buffers from the shadows in GTT.  Used to
 * restore things like GPUVM page tables after a GPU reset where
 * the contents of VRAM might be lost.
 *
 * Returns:
 * 0 on success, negative error code on failure.
 */
static int amdgpu_device_recover_vram(struct amdgpu_device *adev)
{
	struct dma_fence *fence = NULL, *next = NULL;
	struct amdgpu_bo *shadow;
	long r = 1, tmo;

	if (amdgpu_sriov_runtime(adev))
		tmo = msecs_to_jiffies(8000);
	else
		tmo = msecs_to_jiffies(100);

	dev_info(adev->dev, "recover vram bo from shadow start\n");
	mutex_lock(&adev->shadow_list_lock);
	list_for_each_entry(shadow, &adev->shadow_list, shadow_list) {

		/* No need to recover an evicted BO */
		if (shadow->tbo.resource->mem_type != TTM_PL_TT ||
		    shadow->tbo.resource->start == AMDGPU_BO_INVALID_OFFSET ||
		    shadow->parent->tbo.resource->mem_type != TTM_PL_VRAM)
			continue;

		r = amdgpu_bo_restore_shadow(shadow, &next);
		if (r)
			break;

		if (fence) {
			tmo = dma_fence_wait_timeout(fence, false, tmo);
			dma_fence_put(fence);
			fence = next;
			if (tmo == 0) {
				r = -ETIMEDOUT;
				break;
			} else if (tmo < 0) {
				r = tmo;
				break;
			}
		} else {
			fence = next;
		}
	}
	mutex_unlock(&adev->shadow_list_lock);

	if (fence)
		tmo = dma_fence_wait_timeout(fence, false, tmo);
	dma_fence_put(fence);

	if (r < 0 || tmo <= 0) {
		dev_err(adev->dev, "recover vram bo from shadow failed, r is %ld, tmo is %ld\n", r, tmo);
		return -EIO;
	}

	dev_info(adev->dev, "recover vram bo from shadow done\n");
	return 0;
}


/**
 * amdgpu_device_reset_sriov - reset ASIC for SR-IOV vf
 *
 * @adev: amdgpu_device pointer
 * @from_hypervisor: request from hypervisor
 *
 * do VF FLR and reinitialize Asic
 * return 0 means succeeded otherwise failed
 */
static int amdgpu_device_reset_sriov(struct amdgpu_device *adev,
				     bool from_hypervisor)
{
	int r;

	if (from_hypervisor)
		r = amdgpu_virt_request_full_gpu(adev, true);
	else
		r = amdgpu_virt_reset_gpu(adev);
	if (r)
		return r;

	/* Resume IP prior to SMC */
	r = amdgpu_device_ip_reinit_early_sriov(adev);
	if (r)
		goto error;

	amdgpu_virt_init_data_exchange(adev);

	r = amdgpu_device_fw_loading(adev);
	if (r)
		return r;

	/* now we are okay to resume SMC/CP/SDMA */
	r = amdgpu_device_ip_reinit_late_sriov(adev);
	if (r)
		goto error;

	amdgpu_irq_gpu_reset_resume_helper(adev);
	r = amdgpu_ib_ring_tests(adev);

error:
	amdgpu_virt_release_full_gpu(adev, true);
	if (!r && adev->virt.gim_feature & AMDGIM_FEATURE_GIM_FLR_VRAMLOST) {
		amdgpu_inc_vram_lost(adev);
		r = amdgpu_device_recover_vram(adev);
	}

	return r;
}

/**
 * amdgpu_device_has_job_running - check if there is any job in mirror list
 *
 * @adev: amdgpu_device pointer
 *
 * check if there is any job in mirror list
 */
bool amdgpu_device_has_job_running(struct amdgpu_device *adev)
{
	int i;
	struct drm_sched_job *job;

	for (i = 0; i < AMDGPU_MAX_RINGS; ++i) {
		struct amdgpu_ring *ring = adev->rings[i];

		if (!ring || !ring->sched.thread)
			continue;

		spin_lock(&ring->sched.job_list_lock);
		job = list_first_entry_or_null(&ring->sched.pending_list,
					       struct drm_sched_job, list);
		spin_unlock(&ring->sched.job_list_lock);
		if (job)
			return true;
	}
	return false;
}

/**
 * amdgpu_device_should_recover_gpu - check if we should try GPU recovery
 *
 * @adev: amdgpu_device pointer
 *
 * Check amdgpu_gpu_recovery and SRIOV status to see if we should try to recover
 * a hung GPU.
 */
bool amdgpu_device_should_recover_gpu(struct amdgpu_device *adev)
{
	if (amdgpu_gpu_recovery == 0)
		goto disabled;

	if (!amdgpu_device_ip_check_soft_reset(adev)) {
		dev_info(adev->dev, "Timeout, but no hardware hang detected.\n");
		return false;
	}

	if (amdgpu_sriov_vf(adev))
		return true;

	if (amdgpu_gpu_recovery == -1) {
		switch (adev->asic_type) {
		case CHIP_BONAIRE:
		case CHIP_HAWAII:
		case CHIP_VANGOGH_LITE:
			break;
		default:
			goto disabled;
		}
	}

	return true;

disabled:
		dev_info(adev->dev, "GPU recovery disabled.\n");
		return false;
}


static int amdgpu_device_pre_asic_reset(struct amdgpu_device *adev,
					struct amdgpu_job *job,
					bool *need_full_reset_arg)
{
	int i, r = 0;
	bool need_full_reset  = *need_full_reset_arg;

	if (amdgpu_sriov_vf(adev)) {
		/* stop the data exchange thread */
		amdgpu_virt_fini_data_exchange(adev);
	}

	// GL2ACEM_RST.SRT_CP == 1 wait for bus to be quiesce
	// After SRT_CP ==1 driver cleans up any software state
	vangogh_lite_gpu_quiesce(adev);

	amdgpu_fence_driver_isr_toggle(adev, true);

	/* block all schedulers and reset given job's ring */
	for (i = 0; i < AMDGPU_MAX_RINGS; ++i) {
		struct amdgpu_ring *ring = adev->rings[i];

		if (!ring || !ring->sched.thread)
			continue;

		/* after all hw jobs are reset, hw fence is meaningless, so force_completion */
		amdgpu_fence_driver_force_completion(ring);
	}

	amdgpu_fence_driver_isr_toggle(adev, false);

	/* job timeout, Not page fault case */
	if (job && adev->page_faulted_vmid == SGPU_INVALID_VMID) {
		DRM_INFO("set_error: pid %d timedout job %llu vmid %d finished=0x%p\n",
				job->vm->task_info.tgid, job->base.id, job->vmid,
				&job->base.s_fence->finished);
		if (dma_fence_is_signaled_locked(&job->base.s_fence->finished))
			DRM_ERROR("%llu job fence signaled\n", job->base.id);
		else
			dma_fence_set_error(&job->base.s_fence->finished, -ECANCELED);
	}

	/* Don't suspend on bare metal if we are not going to HW reset the ASIC */
	if (!amdgpu_sriov_vf(adev)) {

		if (!need_full_reset)
			need_full_reset = amdgpu_device_ip_need_full_reset(adev);

		if (!need_full_reset) {
			/* disable GfxOff */
			amdgpu_device_ip_set_powergating_state(adev, AMD_IP_BLOCK_TYPE_GFX,
							       AMD_PG_STATE_UNGATE);
			amdgpu_device_ip_pre_soft_reset(adev);
			r = amdgpu_device_ip_soft_reset(adev);
			amdgpu_device_ip_post_soft_reset(adev);
			if (r || amdgpu_device_ip_check_soft_reset(adev)) {
				dev_info(adev->dev, "soft reset failed, will fallback to full reset!\n");
				need_full_reset = true;
			}
			/* Enable GfxOff */
			amdgpu_device_ip_set_powergating_state(adev, AMD_IP_BLOCK_TYPE_GFX,
							       AMD_PG_STATE_GATE);
		}

		if (need_full_reset)
			r = amdgpu_device_ip_suspend(adev);

		*need_full_reset_arg = need_full_reset;
	}

	return r;
}

static int amdgpu_do_asic_reset(struct amdgpu_hive_info *hive,
				   struct amdgpu_device *adev,
			       bool *need_full_reset_arg,
			       bool skip_hw_reset)
{
	bool need_full_reset = *need_full_reset_arg, vram_lost = false;
	int r = 0;

	/*
	 * ASIC reset has to be done on all HGMI hive nodes ASAP
	 * to allow proper links negotiation in FW (within 1 sec)
	 */
	if (!skip_hw_reset && need_full_reset) {
		/* For XGMI run all resets in parallel to speed up the process */
		r = amdgpu_asic_reset(adev);

		if (r)
			dev_err(adev->dev, "ASIC reset failed with error, %d for drm dev, %s",
					r, adev_to_drm(adev)->unique);
	}

	if (need_full_reset) {
		/* post card */
		if (amdgpu_emu_mode == 1)
			emu_soc_asic_init(adev);
		else
			if (amdgpu_device_asic_init(adev))
				dev_warn(adev->dev,
						"asic atom init failed!");

		if (!r) {
			dev_info(adev->dev, "GPU reset succeeded, trying to resume\n");
			r = amdgpu_device_fw_loading(adev);
			if (r)
				goto out;

			r = amdgpu_device_ip_resume_phase1(adev);
			if (r)
				goto out;

			vram_lost = amdgpu_device_check_vram_lost(adev);
			if (vram_lost) {
				DRM_INFO("VRAM is lost due to GPU reset!\n");
				amdgpu_inc_vram_lost(adev);
			}

			r = amdgpu_device_ip_resume_phase2(adev);
			if (r)
				goto out;

			if (vram_lost)
				amdgpu_device_fill_reset_magic(adev);

			/*
			 * Add this ASIC as tracked as reset was already
			 * complete successfully.
			 */
			if (adev->asic_type != CHIP_VANGOGH_LITE)
				amdgpu_register_gpu_instance(adev);

			r = amdgpu_device_ip_late_init(adev);
			if (r)
				goto out;
		}

out:
		if (!r) {
			amdgpu_irq_gpu_reset_resume_helper(adev);
			r = amdgpu_ib_ring_tests(adev);
			if (r) {
				dev_err(adev->dev, "ib ring test failed (%d).\n", r);
#if IS_ENABLED(CONFIG_SEC_GPUINFO)
				sgpu_hqm_log_event(adev, GPU_RING_TEST_FAIL);
#endif
				r = amdgpu_device_ip_suspend(adev);
				need_full_reset = true;
				r = -EAGAIN;
				goto end;
			}
		}

		if (!r)
			r = amdgpu_device_recover_vram(adev);
		else
			adev->asic_reset_res = r;
	}

end:
	*need_full_reset_arg = need_full_reset;
	return r;
}

void amdgpu_do_hard_reset(struct amdgpu_device *adev)
{
	sgpu_ifpo_reset(adev);

	// issue a soft-reset to GRBM
	vangogh_lite_gpu_soft_reset(adev);

	// touch the cpl_RESETn
	vangogh_lite_gpu_hard_reset(adev);
}

bool amdgpu_device_lock_adev(struct amdgpu_device *adev,
				struct amdgpu_hive_info *hive)
{
	struct amdgpu_sws *sws;

	sws = &adev->sws;

	if (atomic_cmpxchg(&adev->in_gpu_reset, 0, 1) != 0)
		return false;

	down_write(&adev->reset_sem);

	switch (amdgpu_asic_reset_method(adev)) {
	case AMD_RESET_METHOD_MODE1:
		adev->mp1_state = PP_MP1_STATE_SHUTDOWN;
		break;
	case AMD_RESET_METHOD_MODE2:
		adev->mp1_state = PP_MP1_STATE_RESET;
		break;
	default:
		adev->mp1_state = PP_MP1_STATE_NONE;
		break;
	}

	if (cwsr_enable)
		drain_workqueue(sws->sched);

	return true;
}

void amdgpu_device_unlock_adev(struct amdgpu_device *adev)
{
	amdgpu_vf_error_trans_all(adev);
	adev->mp1_state = PP_MP1_STATE_NONE;
	atomic_set(&adev->in_gpu_reset, 0);
	up_write(&adev->reset_sem);
}

static int amdgpu_device_suspend_display_audio(struct amdgpu_device *adev)
{
	enum amd_reset_method reset_method;
	struct pci_dev *p = NULL;
	u64 expires;

	/*
	 * For now, only BACO and mode1 reset are confirmed
	 * to suffer the audio issue without proper suspended.
	 */
	reset_method = amdgpu_asic_reset_method(adev);
	if ((reset_method != AMD_RESET_METHOD_BACO) &&
	     (reset_method != AMD_RESET_METHOD_MODE1))
		return -EINVAL;

	p = pci_get_domain_bus_and_slot(pci_domain_nr(adev->pdev->bus),
			adev->pdev->bus->number, 1);
	if (!p)
		return -ENODEV;

	expires = pm_runtime_autosuspend_expiration(&(p->dev));
	if (!expires)
		/*
		 * If we cannot get the audio device autosuspend delay,
		 * a fixed 4S interval will be used. Considering 3S is
		 * the audio controller default autosuspend delay setting.
		 * 4S used here is guaranteed to cover that.
		 */
		expires = ktime_get_mono_fast_ns() + NSEC_PER_SEC * 4ULL;

	while (!pm_runtime_status_suspended(&(p->dev))) {
		if (!pm_runtime_suspend(&(p->dev)))
			break;

		if (expires < ktime_get_mono_fast_ns()) {
			dev_warn(adev->dev, "failed to suspend display audio\n");
			/* TODO: abort the succeeding gpu reset? */
			return -ETIMEDOUT;
		}
	}

	pm_runtime_disable(&(p->dev));

	return 0;
}

enum fault_detect_wakeup_event {

	/* There is at-least one job pushed to GPU, start fault detection */
	WAKEUP_EVENT_START			= 0,

	/* Poll Timer expiry, Poll GPU registers for fault detection */
	WAKEUP_EVENT_POLL			= 1,

	/* There are no active job on GPU, stop fault detection */
	WAKEUP_EVENT_STOP			= 2,

	/* We got fence job Timeout, indicate that to fault detection logic */
	WAKEUP_EVENT_JOB_TIMEOUT		= 3,

	/*
	 * These events are not useful for fault detection logic
	 * however, we kept it for debugging purpose
	 */

	/* fault detection can ignore this event */
	WAKEUP_EVENT_IGNORE			= 4,

	/* wait was interrupted by signal */
	WAKEUP_EVENT_SIGNAL			= 5,

	/* Unexpected event detected in current state */
	WAKEUP_EVENT_ERR			= 6,

};

static enum fault_detect_wakeup_event fault_detect_get_event(
		struct amdgpu_device *adev)
{
	static unsigned int timeout_ms;
	int ret;

	if (timeout_ms == 0) {
		ret = wait_event_interruptible(adev->fault_detect_wake_up,
				(test_bit(FAULT_DETECT_WAKEUP,
						&adev->fault_detect_flags)
						|| kthread_should_stop()
						|| kthread_should_park()));
	} else {
		ret = wait_event_interruptible_timeout(
				adev->fault_detect_wake_up,
				(test_bit(FAULT_DETECT_WAKEUP,
						&adev->fault_detect_flags)
						|| kthread_should_stop()
						|| kthread_should_park())
				, msecs_to_jiffies(timeout_ms));
	}
	clear_bit(FAULT_DETECT_WAKEUP, &adev->fault_detect_flags);

	/*
	 * We maintain two state, whether fault detection is running or not,
	 * based on current state, we interpret return value differently.
	 *
	 * ret < 0 indicates the wait was interrupted due to some SIGNAL
	 * ret = 0 indicates time to poll for GPU registers for fault detection
	 * ret > 0 indicates wait was interrupted because, we got some event
	 * to be processed
	 */

	if (test_bit(FAULT_DETECT_RUNNING, &adev->fault_detect_flags)) {

		/*
		 * Fault detection is ongoing, watch out if we need to stop due
		 * to GPU idle or need to poll for register status
		 */

		if (ret < 0) {
			return WAKEUP_EVENT_SIGNAL;
		} else if (ret == 0) {
			return WAKEUP_EVENT_POLL;
		} else {
			/*
			 * If both GFX and Compute jobs are done stop fault
			 * detection
			 */
			if (!test_bit(FAULT_DETECT_GFX_ACTIVE,
					&adev->fault_detect_flags) &&
					!test_bit(FAULT_DETECT_COMPUTE_ACTIVE,
						&adev->fault_detect_flags)) {

				clear_bit(FAULT_DETECT_RUNNING,
						&adev->fault_detect_flags);
				timeout_ms = 0;
				return WAKEUP_EVENT_STOP;
			}

			if (test_bit(FAULT_DETECT_JOB_TIMEOUT,
					&adev->fault_detect_flags))

				return WAKEUP_EVENT_JOB_TIMEOUT;
		}


	} else {

		/*
		 * Fault detection is not running now, watch out if
		 * we need to start if any job submitted to GPU
		 */
		if (ret < 0) {
			return WAKEUP_EVENT_SIGNAL;
		} else if (ret == 0) {

			/*
			 * If any of the GFX/Compute jobs starts, start
			 * the fault detection
			 */
			if (test_bit(FAULT_DETECT_GFX_ACTIVE,
					&adev->fault_detect_flags) ||
					test_bit(FAULT_DETECT_COMPUTE_ACTIVE,
						&adev->fault_detect_flags)) {

				set_bit(FAULT_DETECT_RUNNING,
						&adev->fault_detect_flags);
				timeout_ms = fault_detect_interval_ms;
				return WAKEUP_EVENT_START;
			}

			/* this is unexpected if fault detect is not running */
			if (test_bit(FAULT_DETECT_JOB_TIMEOUT,
					&adev->fault_detect_flags))
				return WAKEUP_EVENT_ERR;

		} else {
			/* this is unexpected if fault detect is not running */
			return WAKEUP_EVENT_ERR;
		}
	}

	/*
	 * There are cases when sometimes we land here, say for example, when
	 * GFX job starts it sets GFX ACTIVE bit and signals this thread to
	 * wakeup, but even before this thread wakes up and check for
	 * GFX ACTIVE (when fault detection is not running), GFX job finishes
	 * and clears out GFX ACTIVE, in this situation, none of the checks
	 * will get satisfied and we land here. In these cases, we need to
	 * ignore the event
	 */
	return WAKEUP_EVENT_IGNORE;
}

static int amdgpu_fault_detect_main(void *param)
{
	struct amdgpu_device *adev = (struct amdgpu_device *)param;
	bool (*fault_detect_pfn)(void *handle, unsigned long flags) = NULL;
	enum fault_detect_wakeup_event event;
	int fault_cnt = 0, i;

	/* save GFX IP block for future use */
	for (i = 0; i < adev->num_ip_blocks; i++) {

		if (adev->ip_blocks[i].version->type !=
				AMD_IP_BLOCK_TYPE_GFX)
			continue;

		fault_detect_pfn =
			adev->ip_blocks[i].version->funcs->fault_detect;
		break;
	}


	/*
	 * @TODO
	 * struct sched_param sparam = {.sched_priority = 1};
	 * sched_setscheduler(current, SCHED_FIFO, &sparam);
	 */

	while (!kthread_should_stop()) {

		event = fault_detect_get_event(adev);

		if (kthread_should_park())
			kthread_parkme();

		if (!kthread_should_stop()) {
			unsigned long flags = 0;
			bool fault = false;

			trace_amdgpu_fault_detect_log("event", event);

			switch (event) {

			case WAKEUP_EVENT_START:
			case WAKEUP_EVENT_POLL:
				if (test_bit(FAULT_DETECT_GFX_ACTIVE,
						&adev->fault_detect_flags))
					set_bit(FAULT_DETECT_FLAG_GFX, &flags);

				if (test_bit(FAULT_DETECT_COMPUTE_ACTIVE,
						&adev->fault_detect_flags))
					set_bit(FAULT_DETECT_FLAG_COMPUTE,
							&flags);

				/* Fall through */
				fallthrough;
			case WAKEUP_EVENT_STOP:
				if (fault_detect_pfn)
					fault = fault_detect_pfn(adev, flags);

				if (fault) {
					fault_cnt++;
					dev_warn(adev->dev,
						"Fault detected cnt : %d\n",
						fault_cnt);
					trace_amdgpu_fault_detect_log
					("Fault detected cnt", fault_cnt);
				}
				break;

			case WAKEUP_EVENT_IGNORE:
				break;

			case WAKEUP_EVENT_JOB_TIMEOUT:
			case WAKEUP_EVENT_SIGNAL:
			case WAKEUP_EVENT_ERR:
			default:
				dev_warn(adev->dev,
					"fault detect event : %d\n",
					event);
				break;
			}
		}
	}

	return 0;
}

static int amdgpu_device_fault_detect_init(struct amdgpu_device *adev)
{
	int ret = 0;

	if (!amdgpu_fault_detect)
		return ret;

	init_waitqueue_head(&adev->fault_detect_wake_up);
	atomic_set(&adev->gfx_job_cnt, 0);
	atomic_set(&adev->compute_job_cnt, 0);
	adev->fault_detect_flags = 0;

	ret = device_create_file(adev->dev,
			&dev_attr_fault_detect_interval_ms);

	if (ret) {
		dev_err(adev->dev,
			"Could not create fault_detect_interval_ms");
		return ret;
	}

	adev->fault_detect_thread = kthread_run(
			amdgpu_fault_detect_main, adev, "amdgpu_fault_detect");

	if (IS_ERR(adev->fault_detect_thread)) {
		ret = PTR_ERR(adev->fault_detect_thread);
		adev->fault_detect_thread = NULL;
		DRM_ERROR("Failed to create fault detect thread for\n");

		/* cleanup on error*/
		device_remove_file(adev->dev,
				&dev_attr_fault_detect_interval_ms);
	}

	return ret;
}

static int amdgpu_device_fault_detect_fini(struct amdgpu_device *adev)
{
	if (!amdgpu_fault_detect)
		return 0;

	device_remove_file(adev->dev, &dev_attr_fault_detect_interval_ms);

	if (adev->fault_detect_thread)
		kthread_stop(adev->fault_detect_thread);

	return 0;
}

void amdgpu_device_skip_page_faulted_job(struct amdgpu_device *adev,
				struct amdgpu_ring *ring, signed int page_faulted_vmid)
{
	struct drm_sched_job *s_job;
	struct amdgpu_job *amd_job = NULL;
	struct drm_gpu_scheduler *sched = &ring->sched;

	spin_lock(&sched->job_list_lock);
	list_for_each_entry(s_job, &sched->pending_list, list) {
		struct drm_sched_fence *s_fence = s_job->s_fence;

		amd_job = to_amdgpu_job(s_job);

		if (amd_job && page_faulted_vmid != SGPU_INVALID_VMID &&
			page_faulted_vmid == amd_job->vmid) {
			DRM_INFO("set_error: faulted job %llu vmid %d ring %s\n",
				s_job->id, amd_job->vmid, ring->name);

			if (dma_fence_is_signaled_locked(&s_fence->finished))
				DRM_ERROR("%llu job fence signaled\n", s_job->id);
			else
				dma_fence_set_error(&s_fence->finished, -ECANCELED);
		}
	}
	spin_unlock(&sched->job_list_lock);
}

/**
 * amdgpu_device_gpu_recover - reset the asic and recover scheduler
 *
 * @adev: amdgpu_device pointer
 * @job: which job trigger hang
 *
 * Attempt to reset the GPU if it has hung (all asics).
 * Attempt to do soft-reset or full-reset and reinitialize Asic
 * Returns 0 for success or an error on failure.
 */

int amdgpu_device_gpu_recover(struct amdgpu_device *adev,
			      struct amdgpu_job *job)
{
	bool need_full_reset = false;
	bool job_signaled = false;
	struct amdgpu_hive_info *hive = NULL;
	int i, r = 0, dec_cnt = 0;
	bool audio_suspended = false;
	int page_faulted_vmid = SGPU_INVALID_VMID;
	uint32_t sync_seq, last_seq;

	dev_info(adev->dev, "GPU %s begin!\n", __func__);

	atomic_inc(&adev->in_gpu_reset);
	atomic_inc(&adev->gpu_reset_counter);

	/*
	 * Try to put the audio codec into suspend state
	 * before gpu reset started.
	 *
	 * Due to the power domain of the graphics device
	 * is shared with AZ power domain. Without this,
	 * we may change the audio hardware from behind
	 * the audio driver's back. That will trigger
	 * some audio codec errors.
	 */
	if (!amdgpu_device_suspend_display_audio(adev))
		audio_suspended = true;

	cancel_delayed_work_sync(&adev->delayed_init_work);

	for (i = 0; i < AMDGPU_MAX_RINGS; ++i) {
		struct amdgpu_ring *ring = adev->rings[i];

		if (!ring || !ring->sched.thread)
			continue;

		/*
		 * Before calling drm_sched_stop(), it should be guaranteed that
		 * there is no running work for job timeout of all rings so that
		 * all fence callbacks to jobs in pending_list will be
		 * successfully removed.
		 */
		if (!job || &ring->sched != job->base.sched)
			cancel_delayed_work_sync(&ring->sched.work_tdr);

		drm_sched_stop(&ring->sched, job ? &job->base : NULL);
	}

retry:	/* Rest of adevs pre asic reset from XGMI hive. */
	r = amdgpu_device_pre_asic_reset(adev, job,
			&need_full_reset);
	/*TODO Should we stop ?*/
	if (r) {
		dev_err(adev->dev, "GPU pre asic reset failed with err, %d for drm dev, %s ",
				r, adev_to_drm(adev)->unique);
		adev->asic_reset_res = r;
	}

	amdgpu_do_hard_reset(adev);

	/* Actual ASIC resets if needed.*/
	/* TODO Implement XGMI hive reset logic for SRIOV */
	if (amdgpu_sriov_vf(adev)) {
		r = amdgpu_device_reset_sriov(adev, job ? false : true);
		if (r)
			adev->asic_reset_res = r;
	} else {
		r  = amdgpu_do_asic_reset(hive, adev, &need_full_reset, false);
		if (r && r == -EAGAIN)
			goto retry;
	}

	/* recover PM counters */
	for (i = 0; i < AMDGPU_MAX_RINGS; ++i) {
		struct amdgpu_ring *ring = adev->rings[i];
		struct amdgpu_fence_driver *drv;

		if (!ring || !ring->sched.thread)
			continue;

		drv = &ring->fence_drv;
		sync_seq = drv->sync_seq & drv->num_fences_mask;
		last_seq = atomic_read(&drv->last_seq) & drv->num_fences_mask;
		dec_cnt = 0;

		while (last_seq != sync_seq) {
			++dec_cnt;
			++last_seq;
			last_seq &= drv->num_fences_mask;

			sgpu_ifpo_unlock(adev);
			pm_runtime_put(adev->ddev.dev);
		}

		dev_info(adev->dev,
			"PM recovery : %s : remain_fence(%d) ifpo_sw(%d) ifpo_hw(%u) rpm(%d)",
			ring->name, dec_cnt, atomic_read(&adev->ifpo.count),
			sgpu_ifpo_get_hw_lock_value(adev),
			atomic_read(&adev->dev->power.usage_count));
	}

	sgpu_worktime_cleanup(adev);

	/* Post ASIC reset for all devs .*/
	page_faulted_vmid = adev->page_faulted_vmid;
	adev->page_faulted_vmid = SGPU_INVALID_VMID;
	for (i = 0; i < AMDGPU_MAX_RINGS; ++i) {
		struct amdgpu_ring *ring = adev->rings[i];

		if (!ring || !ring->sched.thread)
			continue;

		/* No point to resubmit jobs if we didn't HW reset*/
		if (!adev->asic_reset_res && !job_signaled) {
			/* set error on jobs which have same page_faulted_vmid in pending list */
			amdgpu_device_skip_page_faulted_job(adev, ring, page_faulted_vmid);
			drm_sched_resubmit_jobs(&ring->sched);
		}

		drm_sched_start(&ring->sched, !adev->asic_reset_res);
	}

	/* page_faulted_vmid reset after recovering job */
	if (adev->runpm && (page_faulted_vmid != SGPU_INVALID_VMID))
		pm_runtime_put_autosuspend(adev->ddev.dev);

	adev->asic_reset_res = 0;

	if (r) {
		/* bad news, how to tell it to userspace ? */
		dev_info(adev->dev, "GPU reset(%d) failed\n", atomic_read(&adev->gpu_reset_counter));
		amdgpu_vf_error_put(adev, AMDGIM_ERROR_VF_GPU_RESET_FAIL, 0, r);
	} else {
		dev_info(adev->dev, "GPU reset(%d) succeeded!\n", atomic_read(&adev->gpu_reset_counter));
		SGPU_LOG(adev, DMSG_INFO, DMSG_ETC,
				"GPU reset(%d) succeeded!\n", atomic_read(&adev->gpu_reset_counter));
	}

	amdgpu_sws_clear_broken_queue(adev);
	atomic_dec(&adev->in_gpu_reset);

	if (r)
		dev_info(adev->dev, "GPU reset end with ret = %d\n", r);
	return r;
}

static void sgpu_page_fault_recovery(struct work_struct *work)
{
	struct amdgpu_device *adev = container_of(work, struct amdgpu_device, page_fault_work.work);
	bool found = false;
	int i;

	if(!mutex_trylock(&adev->recovery_mutex)){
		DRM_ERROR("SGPU is already in recovery");
		return;
	}

	/* If work_tdr is called first than this work, skip recovery */
	if (adev->page_faulted_vmid == SGPU_INVALID_VMID) {
		DRM_ERROR("page faulted vmid is invalid, skip recovery");
		goto skip_recovery;
	}

	if (adev->runpm) {
		if (pm_runtime_get_sync(adev->ddev.dev) < 0)
			goto pm_put;
	}
	sgpu_ifpo_lock(adev);

	amdgpu_cancel_all_tdr(adev);

	/* Check all rings if it has jobs with page_faulted_vmid */
	DRM_ERROR("Check all rings for vmid=%d", adev->page_faulted_vmid);

	for (i = 0; i < adev->num_rings; ++i) {
		struct amdgpu_ring *ring = adev->rings[i];
		struct drm_gpu_scheduler *sched = &ring->sched;
		struct drm_sched_job *s_job;
		struct amdgpu_job *a_job, *bad_job = NULL;

		if (!ring || !ring->sched.thread)
			continue;

		spin_lock(&sched->job_list_lock);
		list_for_each_entry(s_job, &sched->pending_list, list) {
			a_job = to_amdgpu_job(s_job);

			if(a_job->vmid == adev->page_faulted_vmid) {
				bad_job = a_job;
				found = true;
				break;
			}
		}
		spin_unlock(&sched->job_list_lock);

		if (bad_job && ring->funcs->check_ring_done)
			ring->funcs->check_ring_done(ring);
	}

	if (!found)
		DRM_ERROR("No bad job with vmid=%d found, but keep going",
				adev->page_faulted_vmid);

	if (adev->sgpu_debug.pagefault_to_panic)
		sgpu_debug_snapshot_expire_watchdog();

	adev->job_hang = true;
	amdgpu_device_gpu_recover(adev, NULL);
	adev->job_hang = false;

	sgpu_ifpo_unlock(adev);
pm_put:
	if (adev->runpm)
		pm_runtime_put_autosuspend(adev->ddev.dev);

skip_recovery:
	mutex_unlock(&adev->recovery_mutex);
}

/**
 * amdgpu_device_get_pcie_info - fence pcie info about the PCIE slot
 *
 * @adev: amdgpu_device pointer
 *
 * Fetchs and stores in the driver the PCIE capabilities (gen speed
 * and lanes) of the slot the device is in. Handles APUs and
 * virtualized environments where PCIE config space may not be available.
 */
static void amdgpu_device_get_pcie_info(struct amdgpu_device *adev)
{
	struct pci_dev *pdev;
	enum pci_bus_speed speed_cap, platform_speed_cap;
	enum pcie_link_width platform_link_width;

	if (amdgpu_pcie_gen_cap)
		adev->pm.pcie_gen_mask = amdgpu_pcie_gen_cap;

	if (amdgpu_pcie_lane_cap)
		adev->pm.pcie_mlw_mask = amdgpu_pcie_lane_cap;

	/* covers APUs as well */
	if (pci_is_root_bus(adev->pdev->bus)) {
		if (adev->pm.pcie_gen_mask == 0)
			adev->pm.pcie_gen_mask = AMDGPU_DEFAULT_PCIE_GEN_MASK;
		if (adev->pm.pcie_mlw_mask == 0)
			adev->pm.pcie_mlw_mask = AMDGPU_DEFAULT_PCIE_MLW_MASK;
		return;
	}

	if (adev->pm.pcie_gen_mask && adev->pm.pcie_mlw_mask)
		return;

	pcie_bandwidth_available(adev->pdev, NULL,
				 &platform_speed_cap, &platform_link_width);

	if (adev->pm.pcie_gen_mask == 0) {
		/* asic caps */
		pdev = adev->pdev;
		speed_cap = pcie_get_speed_cap(pdev);
		if (speed_cap == PCI_SPEED_UNKNOWN) {
			adev->pm.pcie_gen_mask |= (CAIL_ASIC_PCIE_LINK_SPEED_SUPPORT_GEN1 |
						  CAIL_ASIC_PCIE_LINK_SPEED_SUPPORT_GEN2 |
						  CAIL_ASIC_PCIE_LINK_SPEED_SUPPORT_GEN3);
		} else {
			if (speed_cap == PCIE_SPEED_16_0GT)
				adev->pm.pcie_gen_mask |= (CAIL_ASIC_PCIE_LINK_SPEED_SUPPORT_GEN1 |
							  CAIL_ASIC_PCIE_LINK_SPEED_SUPPORT_GEN2 |
							  CAIL_ASIC_PCIE_LINK_SPEED_SUPPORT_GEN3 |
							  CAIL_ASIC_PCIE_LINK_SPEED_SUPPORT_GEN4);
			else if (speed_cap == PCIE_SPEED_8_0GT)
				adev->pm.pcie_gen_mask |= (CAIL_ASIC_PCIE_LINK_SPEED_SUPPORT_GEN1 |
							  CAIL_ASIC_PCIE_LINK_SPEED_SUPPORT_GEN2 |
							  CAIL_ASIC_PCIE_LINK_SPEED_SUPPORT_GEN3);
			else if (speed_cap == PCIE_SPEED_5_0GT)
				adev->pm.pcie_gen_mask |= (CAIL_ASIC_PCIE_LINK_SPEED_SUPPORT_GEN1 |
							  CAIL_ASIC_PCIE_LINK_SPEED_SUPPORT_GEN2);
			else
				adev->pm.pcie_gen_mask |= CAIL_ASIC_PCIE_LINK_SPEED_SUPPORT_GEN1;
		}
		/* platform caps */
		if (platform_speed_cap == PCI_SPEED_UNKNOWN) {
			adev->pm.pcie_gen_mask |= (CAIL_PCIE_LINK_SPEED_SUPPORT_GEN1 |
						   CAIL_PCIE_LINK_SPEED_SUPPORT_GEN2);
		} else {
			if (platform_speed_cap == PCIE_SPEED_16_0GT)
				adev->pm.pcie_gen_mask |= (CAIL_PCIE_LINK_SPEED_SUPPORT_GEN1 |
							   CAIL_PCIE_LINK_SPEED_SUPPORT_GEN2 |
							   CAIL_PCIE_LINK_SPEED_SUPPORT_GEN3 |
							   CAIL_PCIE_LINK_SPEED_SUPPORT_GEN4);
			else if (platform_speed_cap == PCIE_SPEED_8_0GT)
				adev->pm.pcie_gen_mask |= (CAIL_PCIE_LINK_SPEED_SUPPORT_GEN1 |
							   CAIL_PCIE_LINK_SPEED_SUPPORT_GEN2 |
							   CAIL_PCIE_LINK_SPEED_SUPPORT_GEN3);
			else if (platform_speed_cap == PCIE_SPEED_5_0GT)
				adev->pm.pcie_gen_mask |= (CAIL_PCIE_LINK_SPEED_SUPPORT_GEN1 |
							   CAIL_PCIE_LINK_SPEED_SUPPORT_GEN2);
			else
				adev->pm.pcie_gen_mask |= CAIL_PCIE_LINK_SPEED_SUPPORT_GEN1;

		}
	}
	if (adev->pm.pcie_mlw_mask == 0) {
		if (platform_link_width == PCIE_LNK_WIDTH_UNKNOWN) {
			adev->pm.pcie_mlw_mask |= AMDGPU_DEFAULT_PCIE_MLW_MASK;
		} else {
			switch (platform_link_width) {
			case PCIE_LNK_X32:
				adev->pm.pcie_mlw_mask = (CAIL_PCIE_LINK_WIDTH_SUPPORT_X32 |
							  CAIL_PCIE_LINK_WIDTH_SUPPORT_X16 |
							  CAIL_PCIE_LINK_WIDTH_SUPPORT_X12 |
							  CAIL_PCIE_LINK_WIDTH_SUPPORT_X8 |
							  CAIL_PCIE_LINK_WIDTH_SUPPORT_X4 |
							  CAIL_PCIE_LINK_WIDTH_SUPPORT_X2 |
							  CAIL_PCIE_LINK_WIDTH_SUPPORT_X1);
				break;
			case PCIE_LNK_X16:
				adev->pm.pcie_mlw_mask = (CAIL_PCIE_LINK_WIDTH_SUPPORT_X16 |
							  CAIL_PCIE_LINK_WIDTH_SUPPORT_X12 |
							  CAIL_PCIE_LINK_WIDTH_SUPPORT_X8 |
							  CAIL_PCIE_LINK_WIDTH_SUPPORT_X4 |
							  CAIL_PCIE_LINK_WIDTH_SUPPORT_X2 |
							  CAIL_PCIE_LINK_WIDTH_SUPPORT_X1);
				break;
			case PCIE_LNK_X12:
				adev->pm.pcie_mlw_mask = (CAIL_PCIE_LINK_WIDTH_SUPPORT_X12 |
							  CAIL_PCIE_LINK_WIDTH_SUPPORT_X8 |
							  CAIL_PCIE_LINK_WIDTH_SUPPORT_X4 |
							  CAIL_PCIE_LINK_WIDTH_SUPPORT_X2 |
							  CAIL_PCIE_LINK_WIDTH_SUPPORT_X1);
				break;
			case PCIE_LNK_X8:
				adev->pm.pcie_mlw_mask = (CAIL_PCIE_LINK_WIDTH_SUPPORT_X8 |
							  CAIL_PCIE_LINK_WIDTH_SUPPORT_X4 |
							  CAIL_PCIE_LINK_WIDTH_SUPPORT_X2 |
							  CAIL_PCIE_LINK_WIDTH_SUPPORT_X1);
				break;
			case PCIE_LNK_X4:
				adev->pm.pcie_mlw_mask = (CAIL_PCIE_LINK_WIDTH_SUPPORT_X4 |
							  CAIL_PCIE_LINK_WIDTH_SUPPORT_X2 |
							  CAIL_PCIE_LINK_WIDTH_SUPPORT_X1);
				break;
			case PCIE_LNK_X2:
				adev->pm.pcie_mlw_mask = (CAIL_PCIE_LINK_WIDTH_SUPPORT_X2 |
							  CAIL_PCIE_LINK_WIDTH_SUPPORT_X1);
				break;
			case PCIE_LNK_X1:
				adev->pm.pcie_mlw_mask = CAIL_PCIE_LINK_WIDTH_SUPPORT_X1;
				break;
			default:
				break;
			}
		}
	}
}

int amdgpu_device_baco_enter(struct drm_device *dev)
{
	struct amdgpu_device *adev = drm_to_adev(dev);

	if (!amdgpu_device_supports_baco(adev_to_drm(adev)))
		return -ENOTSUPP;

	return amdgpu_dpm_baco_enter(adev);
}

int amdgpu_device_baco_exit(struct drm_device *dev)
{
	struct amdgpu_device *adev = drm_to_adev(dev);
	int ret = 0;

	if (!amdgpu_device_supports_baco(adev_to_drm(adev)))
		return -ENOTSUPP;

	ret = amdgpu_dpm_baco_exit(adev);
	if (ret)
		return ret;

	return 0;
}

void amdgpu_cancel_all_tdr(struct amdgpu_device *adev)
{
	int i;

	for (i = 0; i < adev->num_rings; ++i) {
		struct amdgpu_ring *ring = adev->rings[i];

		if (!ring || !ring->sched.thread)
			continue;

		cancel_delayed_work_sync(&ring->sched.work_tdr);
	}
}

/**
 * amdgpu_pci_error_detected - Called when a PCI error is detected.
 * @pdev: PCI device struct
 * @state: PCI channel state
 *
 * Description: Called when a PCI error is detected.
 *
 * Return: PCI_ERS_RESULT_NEED_RESET or PCI_ERS_RESULT_DISCONNECT.
 */
pci_ers_result_t amdgpu_pci_error_detected(struct pci_dev *pdev, pci_channel_state_t state)
{
	struct drm_device *dev = pci_get_drvdata(pdev);
	struct amdgpu_device *adev = drm_to_adev(dev);
	int i;

	DRM_INFO("PCI error: detected callback, state(%d)!!\n", state);

	switch (state) {
	case pci_channel_io_normal:
		return PCI_ERS_RESULT_CAN_RECOVER;
	/* Fatal error, prepare for slot reset */
	case pci_channel_io_frozen:
		/*
		 * Cancel and wait for all TDRs in progress if failing to
		 * set  adev->in_gpu_reset in amdgpu_device_lock_adev
		 *
		 * Locking adev->reset_sem will prevent any external access
		 * to GPU during PCI error recovery
		 */
		while (!amdgpu_device_lock_adev(adev, NULL))
			amdgpu_cancel_all_tdr(adev);
		atomic_inc(&adev->gpu_reset_counter);

		/*
		 * Block any work scheduling as we do for regular GPU reset
		 * for the duration of the recovery
		 */
		for (i = 0; i < AMDGPU_MAX_RINGS; ++i) {
			struct amdgpu_ring *ring = adev->rings[i];

			if (!ring || !ring->sched.thread)
				continue;

			drm_sched_stop(&ring->sched, NULL);
		}
		return PCI_ERS_RESULT_NEED_RESET;
	case pci_channel_io_perm_failure:
		/* Permanent error, prepare for device removal */
		return PCI_ERS_RESULT_DISCONNECT;
	}

	return PCI_ERS_RESULT_NEED_RESET;
}

/**
 * amdgpu_pci_mmio_enabled - Enable MMIO and dump debug registers
 * @pdev: pointer to PCI device
 */
pci_ers_result_t amdgpu_pci_mmio_enabled(struct pci_dev *pdev)
{

	DRM_INFO("PCI error: mmio enabled callback!!\n");

	/* TODO - dump whatever for debugging purposes */

	/* This called only if amdgpu_pci_error_detected returns
	 * PCI_ERS_RESULT_CAN_RECOVER. Read/write to the device still
	 * works, no need to reset slot.
	 */

	return PCI_ERS_RESULT_RECOVERED;
}

/**
 * amdgpu_pci_slot_reset - Called when PCI slot has been reset.
 * @pdev: PCI device struct
 *
 * Description: This routine is called by the pci error recovery
 * code after the PCI slot has been reset, just before we
 * should resume normal operations.
 */
pci_ers_result_t amdgpu_pci_slot_reset(struct pci_dev *pdev)
{
	struct drm_device *dev = pci_get_drvdata(pdev);
	struct amdgpu_device *adev = drm_to_adev(dev);
	int r, i;
	bool need_full_reset = true;
	u32 memsize;
	struct list_head device_list;

	DRM_INFO("PCI error: slot reset callback!!\n");

	INIT_LIST_HEAD(&device_list);

	/* wait for asic to come out of reset */
	msleep(500);

	/* Restore PCI confspace */
	amdgpu_device_load_pci_state(pdev);

	/* confirm  ASIC came out of reset */
	for (i = 0; i < adev->usec_timeout; i++) {
		memsize = amdgpu_asic_get_config_memsize(adev);

		if (memsize != 0xffffffff)
			break;
		udelay(1);
	}
	if (memsize == 0xffffffff) {
		r = -ETIME;
		goto out;
	}

	adev->in_pci_err_recovery = true;
	r = amdgpu_device_pre_asic_reset(adev, NULL, &need_full_reset);
	adev->in_pci_err_recovery = false;
	if (r)
		goto out;

	r = amdgpu_do_asic_reset(NULL, adev, &need_full_reset, true);

out:
	if (!r) {
		if (adev->pdev && amdgpu_device_cache_pci_state(adev->pdev))
			pci_restore_state(adev->pdev);

		DRM_INFO("PCIe error recovery succeeded\n");
	} else {
		DRM_ERROR("PCIe error recovery failed, err:%d", r);
		amdgpu_device_unlock_adev(adev);
	}

	return r ? PCI_ERS_RESULT_DISCONNECT : PCI_ERS_RESULT_RECOVERED;
}

/**
 * amdgpu_pci_resume() - resume normal ops after PCI reset
 * @pdev: pointer to PCI device
 *
 * Called when the error recovery driver tells us that its
 * OK to resume normal operation. Use completion to allow
 * halted scsi ops to resume.
 */
void amdgpu_pci_resume(struct pci_dev *pdev)
{
	struct drm_device *dev = pci_get_drvdata(pdev);
	struct amdgpu_device *adev = drm_to_adev(dev);
	int i;


	DRM_INFO("PCI error: resume callback!!\n");

	for (i = 0; i < AMDGPU_MAX_RINGS; ++i) {
		struct amdgpu_ring *ring = adev->rings[i];

		if (!ring || !ring->sched.thread)
			continue;


		drm_sched_resubmit_jobs(&ring->sched);
		drm_sched_start(&ring->sched, true);
	}

	amdgpu_device_unlock_adev(adev);
}

bool amdgpu_device_cache_pci_state(struct pci_dev *pdev)
{
	struct drm_device *dev = pci_get_drvdata(pdev);
	struct amdgpu_device *adev = drm_to_adev(dev);
	int r;

	r = pci_save_state(pdev);
	if (!r) {
		kfree(adev->pci_state);

		adev->pci_state = pci_store_saved_state(pdev);

		if (!adev->pci_state) {
			DRM_ERROR("Failed to store PCI saved state");
			return false;
		}
	} else {
		DRM_WARN("Failed to save PCI state, err:%d\n", r);
		return false;
	}

	return true;
}

bool amdgpu_device_load_pci_state(struct pci_dev *pdev)
{
	struct drm_device *dev = pci_get_drvdata(pdev);
	struct amdgpu_device *adev = drm_to_adev(dev);
	int r;

	if (!adev->pci_state)
		return false;

	r = pci_load_saved_state(pdev, adev->pci_state);

	if (!r) {
		pci_restore_state(pdev);
	} else {
		DRM_WARN("Failed to load PCI state, err:%d\n", r);
		return false;
	}

	return true;
}


