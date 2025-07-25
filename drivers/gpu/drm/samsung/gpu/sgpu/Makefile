#
# Copyright 2017-2021 Advanced Micro Devices, Inc.
#
# Permission is hereby granted, free of charge, to any person obtaining a
# copy of this software and associated documentation files (the "Software"),
# to deal in the Software without restriction, including without limitation
# the rights to use, copy, modify, merge, publish, distribute, sublicense,
# and/or sell copies of the Software, and to permit persons to whom the
# Software is furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL
# THE COPYRIGHT HOLDER(S) OR AUTHOR(S) BE LIABLE FOR ANY CLAIM, DAMAGES OR
# OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
# ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
# OTHER DEALINGS IN THE SOFTWARE.
#
#
# Makefile for the drm device driver.  This driver provides support for the
# Direct Rendering Infrastructure (DRI) in XFree86 4.1.0 and higher.

FULL_AMD_PATH=$(srctree)/drivers/gpu/drm/amd
FULL_SGPU_PATH=$(srctree)/$(src)/..
DISPLAY_FOLDER_NAME=display
FULL_AMD_DISPLAY_PATH = $(FULL_AMD_PATH)/$(DISPLAY_FOLDER_NAME)

ccflags-y := -I$(FULL_SGPU_PATH)/include/asic_reg \
	-I$(FULL_SGPU_PATH)/include \
	-I$(FULL_SGPU_PATH)/sgpu\
	-I$(FULL_SGPU_PATH)/pm/inc \
	-I$(FULL_AMD_PATH)/acp/include

ifneq ($(CONFIG_GPU_THERMAL), )
ccflags-y += -I$(srctree)/drivers/thermal/samsung/
endif

ifneq ($(CONFIG_PM_DEVFREQ), )
ccflags-y += -I$(srctree)/drivers/devfreq/
endif

sgpu-y := amdgpu_drv.o

# add KMS driver
sgpu-y += amdgpu_device.o amdgpu_kms.o \
	amdgpu_atombios.o atombios_crtc.o amdgpu_connectors.o \
	atom.o amdgpu_fence.o amdgpu_ttm.o amdgpu_object.o amdgpu_gart.o \
	amdgpu_encoders.o amdgpu_display.o amdgpu_i2c.o \
	amdgpu_fb.o amdgpu_gem.o amdgpu_ring.o \
	amdgpu_cs.o amdgpu_bios.o amdgpu_benchmark.o amdgpu_test.o \
	atombios_dp.o amdgpu_afmt.o amdgpu_trace_points.o \
	atombios_encoders.o amdgpu_sa.o atombios_i2c.o \
	amdgpu_dma_buf.o amdgpu_vm.o amdgpu_ib.o amdgpu_pll.o \
	amdgpu_ucode.o amdgpu_bo_list.o amdgpu_ctx.o amdgpu_sync.o \
	amdgpu_gtt_mgr.o amdgpu_vram_mgr.o amdgpu_virt.o amdgpu_atomfirmware.o \
	amdgpu_vf_error.o amdgpu_sched.o amdgpu_debugfs.o amdgpu_ids.o \
	amdgpu_gmc.o amdgpu_csa.o amdgpu_vm_cpu.o \
	amdgpu_vm_sdma.o amdgpu_discovery.o \
	amdgpu_fru_eeprom.o

sgpu-$(CONFIG_PERF_EVENTS) += amdgpu_pmu.o
sgpu-$(CONFIG_DEBUG_FS) += sgpu_debugfs.o

sgpu-y += \
	soc15.o emu_soc.o mxgpu_ai.o \
	nbio_v2_3.o nv.o \
	mxgpu_nv.o vangogh_lite_reg_init.o \
	vangogh_lite_gc.o

# add GMC block
sgpu-y += \
	mmhub_v2_0.o gmc_v10_0.o gfxhub_v2_1.o

# add IH block
sgpu-y += \
	amdgpu_irq.o \
	amdgpu_ih.o \
	vangogh_lite_ih.o

# add DCE block
sgpu-y += \
	dce_virtual.o

# add GFX block
sgpu-y += \
	amdgpu_gfx.o \
	amdgpu_rlc.o \
	gfx_v10_0.o \
	amdgpu_cwsr.o \
	amdgpu_tmz.o \
	amdgpu_sws.o

# add async DMA block
sgpu-y += \
	amdgpu_sdma.o

# add ATHUB block
sgpu-y += \
	athub_v2_0.o

# add cgs
sgpu-y += amdgpu_cgs.o

# GPU scheduler
sgpu-y += amdgpu_job.o

# ACP componet
ifneq ($(CONFIG_DRM_AMD_ACP),)
sgpu-y += amdgpu_acp.o

AMDACPPATH := ../acp
include $(FULL_AMD_PATH)/acp/Makefile

sgpu-y += $(AMD_ACP_FILES)
endif

sgpu-$(CONFIG_COMPAT) += amdgpu_ioc32.o
sgpu-$(CONFIG_ACPI) += amdgpu_acpi.o

include $(FULL_SGPU_PATH)/pm/Makefile

sgpu-y += $(AMD_POWERPLAY_FILES)

sgpu-$(CONFIG_DRM_SGPU_BPMD) += \
	sgpu_bpmd.o \
	sgpu_bpmd_layout_common.o \
	sgpu_bpmd_layout.o

sgpu-$(CONFIG_DRM_SGPU_BPMD_MEMLOGGER_TEXT) += \
	sgpu_bpmd_log.o

# add pm dvfs block
sgpu-$(CONFIG_DRM_SGPU_DVFS) += \
	sgpu_utilization.o sgpu_governor.o sgpu_user_interface.o sgpu_devfreq.o

# add Vangogh lite hw counter
sgpu-y += \
	vangogh_lite_hw_counter.o

# add afm driver
sgpu-$(CONFIG_DRM_SGPU_AFM) += sgpu_afm.o

# sgpu debug information
sgpu-$(CONFIG_DRM_SGPU_EXYNOS) += sgpu_debug.o

# add Exynos interface api
sgpu-$(CONFIG_DRM_SGPU_DVFS) += exynos_gpu_interface.o
sgpu-$(CONFIG_DRM_SGPU_GRAPHIC_MEMORY_RECLAIM) += sgpu_swap.o

# add GPU Profiler api
ifeq ($(CONFIG_EXYNOS_GPU_PROFILER), m)
ifeq ($(CONFIG_EXYNOS_PROFILER_LEGACY), y)
	PROFILER_VERSION=0
else
	PROFILER_VERSION=2
endif
	sgpu-$(CONFIG_DRM_SGPU_DVFS) += sgpu_profiler_v${PROFILER_VERSION}.o
	sgpu-$(CONFIG_DRM_SGPU_DVFS) += sgpu_profiler_external_v${PROFILER_VERSION}.o
endif

# add IFPO functions
sgpu-$(CONFIG_DRM_SGPU_EXYNOS) += sgpu_ifpo.o

# add pm monitor functions
sgpu-$(CONFIG_DRM_SGPU_EXYNOS) += sgpu_pm_monitor.o

# add SGPU Debug messages
sgpu-y += sgpu_dmsg.o

# add gpu_work_period tracepoint
sgpu-$(CONFIG_DRM_SGPU_WORKTIME) += sgpu_worktime.o

# add sgpu_power_tracepoint
sgpu-y += sgpu_power_trace_points.o

obj-$(CONFIG_DRM_SGPU)+= sgpu.o
