/*
 * Samsung Exynos5 SoC series FIMC-IS driver
 *
 * exynos5 fimc-is video functions
 *
 * Copyright (c) 2011 Samsung Electronics Co., Ltd
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <linux/module.h>
#include <linux/delay.h>
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/interrupt.h>
#include <linux/device.h>
#include <linux/platform_device.h>
#include <linux/slab.h>
#include <asm/cacheflush.h>
#include <asm/pgtable.h>
#include <linux/firmware.h>
#include <linux/dma-mapping.h>
#include <linux/scatterlist.h>
#include <linux/videodev2.h>
#include <videodev2_exynos_camera.h>
#include <linux/videodev2_exynos_media.h>
#include <linux/v4l2-mediabus.h>
#include <linux/vmalloc.h>
#include <linux/kthread.h>
#include <linux/syscalls.h>
#include <linux/bug.h>
#ifndef CAMERA_BLOCK_PCIE_L1SS_CTRL
#if IS_ENABLED(CONFIG_PCI_EXYNOS)
#include <linux/exynos-pci-ctrl.h>
#endif
#endif

#include <linux/regulator/consumer.h>
#include <linux/pinctrl/consumer.h>
#include <linux/gpio.h>

#include "pablo-dvfs.h"
#include "pablo-lib.h"
#include "pablo-binary.h"
#include "is-time.h"
#include "is-core.h"
#include "is-param.h"
#include "is-cmd.h"
#include "is-err.h"
#include "is-video.h"
#include "is-hw.h"
#include "is-spi.h"
#include "is-groupmgr.h"
#include "is-interface-wrap.h"
#include "is-device-ischain.h"
#include "exynos-is-module.h"
#include "./sensor/module_framework/modules/is-device-module-base.h"
#include "is-vendor-private.h"
#include "pablo-device-iommu-group.h"
#include "pablo-obte.h"
#include "pablo-interface-irta.h"
#include "pablo-icpu-adapter.h"
#include "exynos-is.h"
#include "is-devicemgr.h"
#include "is-hw-dvfs.h"
#include "is-interface-library.h"
#include "is-device-sensor-peri.h"

static const struct pablo_device_ischain_ops dev_ischain_ops;
static int is_ischain_group_shot(struct is_device_ischain *device,
	struct is_group *group,
	struct is_frame *frame);

static int is_ischain_load_setfile(struct is_device_sensor *ids, struct is_module_enum *module)
{
	int ret;
	const struct firmware *setfile = NULL;

	ret = request_firmware(&setfile, module->setfile_name, &ids->pdev->dev);
	if (ret) {
		err("failed to get %s(%d)", module->setfile_name, ret);
		return ret;
	}

	ret = is_hardware_parse_setfile(
		&is_get_is_core()->hardware, (ulong)setfile->data, module->position);
	if (ret) {
		err("failed to parse setfile for %s(%d), size: 0x%zx", module->setfile_name, ret,
			setfile->size);
		release_firmware(setfile);
		return ret;
	}

	carve_binary_version(IS_BIN_SETFILE, module->position, setfile->data, setfile->size);

	module->setfile_size = setfile->size;

	release_firmware(setfile);

	return ret;
}

static int is_ischain_open_setfile(struct is_device_ischain *device)
{
	int ret;
	struct is_device_sensor *ids = device->sensor;
	u32 position = ids->position;
	struct is_minfo *im = is_get_is_minfo();
	struct is_module_enum *module;
	ktime_t time_to_ready;
	bool pinned;

	mdbgd_ischain("%s\n", device, __func__);

	ret = is_sensor_g_module(ids, &module);
	if (ret) {
		merr("is_sensor_g_module is fail(%d)", device, ret);
		return ret;
	}

	pinned = module->setfile_pinned && !is_get_debug_param(IS_DEBUG_PARAM_ICPU_RELOAD);

	time_to_ready = ktime_get();

	/* a module has pinned setfile */
	if (!im->loaded_setfile[position]) {
		/* a module has preloaded setfile */
		if (module->setfile_size) {
			im->loaded_setfile[position] = true;
			im->pinned_setfile[position] = pinned;
			im->name_setfile[position] = module->setfile_name;
			if (!im->pinned_setfile[position])
				refcount_set(&im->refcount_setfile[position], 1);

			minfo("preloaded(%lldus) %s is ready to use, size: 0x%zx\n", device,
							PABLO_KTIME_US_DELTA_NOW(time_to_ready),
							module->setfile_name,
							module->setfile_size);
		} else {
			ret = is_ischain_load_setfile(ids, module);
			if (ret)
				return ret;

			im->pinned_setfile[position] = pinned;
			im->name_setfile[position] = module->setfile_name;
			if (!im->pinned_setfile[position])
				refcount_set(&im->refcount_setfile[position], 1);

			im->loaded_setfile[position] = true;

			minfo("reloaded(%lldus) %s is ready to use, size: 0x%zx\n", device,
				PABLO_KTIME_US_DELTA_NOW(time_to_ready),
				im->name_setfile[position],
				module->setfile_size);
		}
	} else {
		if (!im->pinned_setfile[position])
			refcount_inc(&im->refcount_setfile[position]);

		minfo("pinned(%lldus) %s is ready to use\n", device,
					PABLO_KTIME_US_DELTA_NOW(time_to_ready),
					im->name_setfile[position]);
	}

	return 0;
}

static void is_ischain_close_setfile(struct is_device_ischain *device)
{
	struct is_device_sensor *ids = device->sensor;
	u32 position = ids->position;
	struct is_minfo *im = is_get_is_minfo();
	struct is_priv_buf *ipb;
	bool loaded = im->loaded_setfile[position];
	bool pinned = im->pinned_setfile[position];
	struct is_module_enum *module;
	int hw_slot;
	struct is_hw_ip *hw_ip;
	struct is_core *core;

	mdbgd_ischain("%s\n", device, __func__);

	if (!pinned && test_bit(IS_ISCHAIN_INIT, &device->state) &&
			refcount_dec_and_test(&im->refcount_setfile[position]) &&
			loaded) {
		minfo("[MEM] free %s\n", device, im->name_setfile[position]);
		core = is_get_is_core();

		for (hw_slot = 0; hw_slot < HW_SLOT_MAX; hw_slot++) {
			hw_ip = &core->hardware.hw_ip[hw_slot];
			ipb = hw_ip->pb_setfile[position];
			if (ipb)
				CALL_VOID_BUFOP(ipb, free, ipb);

			hw_ip->pb_setfile[position] = NULL;
			memset(&hw_ip->setfile[position], 0x00, sizeof(struct is_hw_ip_setfile));
		}
		im->name_setfile[position] = NULL;
		im->loaded_setfile[position] = false;
	}

	/* release the preloaded buffer of the module also */
	if (!pinned && !is_search_sensor_module_with_position(ids, position, &module))
		module->setfile_size = 0;
}

int is_itf_s_param(struct is_device_ischain *device,
	struct is_frame *frame,
	IS_DECLARE_PMAP(pmap))
{
	int ret = 0;
	u32 pi;
	ulong dst_base, src_base;

	FIMC_BUG(!device);

	if (frame) {
		IS_OR_PMAP(frame->pmap, pmap);

		dst_base = (ulong)&device->is_region->parameter;
		src_base = (ulong)frame->parameter;

		for (pi = 0; !IS_EMPTY_PMAP(pmap) && (pi < IS_PARAM_NUM); pi++) {
			if (test_bit(pi, pmap))
				memcpy((ulong *)(dst_base + (pi * PARAMETER_MAX_SIZE)),
						(ulong *)(src_base + (pi * PARAMETER_MAX_SIZE)),
						PARAMETER_MAX_SIZE);
		}
	} else {
		if (!IS_EMPTY_PMAP(pmap))
			ret = is_itf_s_param_wrap(device, pmap);
	}

	return ret;
}

void * is_itf_g_param(struct is_device_ischain *device,
	struct is_frame *frame,
	u32 index)
{
	ulong dst_base, src_base, dst_param, src_param;

	FIMC_BUG_NULL(!device);

	if (frame) {
		dst_base = (ulong)frame->parameter;
		dst_param = (dst_base + (index * PARAMETER_MAX_SIZE));
		src_base = (ulong)&device->is_region->parameter;
		src_param = (src_base + (index * PARAMETER_MAX_SIZE));

		memcpy((ulong *)dst_param, (ulong *)src_param, PARAMETER_MAX_SIZE);
	} else {
		dst_base = (ulong)&device->is_region->parameter;
		dst_param = (dst_base + (index * PARAMETER_MAX_SIZE));
	}

	return (void *)dst_param;
}

static int is_itf_open(struct is_device_ischain *device, u32 flag)
{
	int ret = 0;
	struct is_region *region;

	FIMC_BUG(!device);
	FIMC_BUG(!device->is_region);
	FIMC_BUG(!device->sensor);

	if (test_bit(IS_ISCHAIN_OPEN_STREAM, &device->state)) {
		merr("stream is already open", device);
		ret = -EINVAL;
		goto p_err;
	}

	region = device->is_region;

	memset(&region->fd_info, 0x0, sizeof(struct nfd_info));
	memset(&region->od_info, 0x0, sizeof(struct od_info));

	ret = is_itf_open_wrap(device, flag);
	if (ret)
		goto p_err;

	set_bit(IS_ISCHAIN_OPEN_STREAM, &device->state);

p_err:
	return ret;
}

static int is_itf_close(struct is_device_ischain *device)
{
	int ret;

	if (!test_bit(IS_ISCHAIN_OPEN_STREAM, &device->state)) {
		mwarn("stream is already close", device);
		return 0;
	}

	ret = is_itf_close_wrap(device);

	if (!IS_ENABLED(SKIP_SETFILE_LOAD))
		is_ischain_close_setfile(device);

	clear_bit(IS_ISCHAIN_OPEN_STREAM, &device->state);

	return ret;
}

static DEFINE_MUTEX(setf_lock);
static int is_itf_setfile(struct is_device_ischain *device)
{
	int ret = 0;

	mutex_lock(&setf_lock);

	if (!IS_ENABLED(SKIP_SETFILE_LOAD)) {
		ret = is_ischain_open_setfile(device);
		if (ret) {
			merr("is_ischain_loadsetf is fail(%d)", device, ret);
			goto p_err;
		}
	}

	ret = is_itf_setfile_wrap(device);
	if (ret)
		goto p_err;

p_err:
	mutex_unlock(&setf_lock);
	return ret;
}

int is_itf_preload_setfile(void)
{
	struct is_core *core;
	struct is_device_sensor *device = NULL;
	struct is_module_enum *module;
	u32 i;
	int ret = 0;
	u32 mindex, mmax;

	core = pablo_get_core_async();
	if (!core) {
		err("Camera core is NULL");
		return -ENODEV;
	}

	mutex_lock(&setf_lock);

	for (i = 0; i < IS_SENSOR_COUNT; i++) {
		device = &core->sensor[i];
		if (!device) {
			warn("%s: device(NULL)", __func__);
			continue;
		}

		if (test_bit(IS_SENSOR_PROBE, &device->state)) {
			mmax = atomic_read(&device->module_count);
			for (mindex = 0; mindex < mmax; mindex++) {
				module = &device->module_enum[mindex];
				if (!module->setfile_size) {
					ret = is_ischain_load_setfile(device, module);
					if (!ret)
						info("%s is preloaded, size: 0x%zx\n",
							module->setfile_name, module->setfile_size);
				}
			}
		}
	}

	mutex_unlock(&setf_lock);
	return ret;
}

static void pablo_ischain_set_global_param(struct is_device_ischain *device, bool set)
{
	struct is_resourcemgr *resourcemgr = device->resourcemgr;
	struct is_group *group = device->group[GROUP_SLOT_3AA];
	struct is_device_sensor *sensor = device->sensor;
	struct is_lic_sram *lic_sram = &resourcemgr->lic_sram;

	resourcemgr->dev_resource.setfile = device->setfile;
	resourcemgr->dev_resource.llc_mode = device->llc_mode;
	resourcemgr->dev_resource.instance = device->instance;

	if (set)
		is_resource_set_global_param(resourcemgr, device);
	else
		is_resource_clear_global_param(resourcemgr, device);


	if (!test_bit(IS_GROUP_OPEN, &group->state)) {
		mwarn("[RSC] group_3aa is closed", device);
		return;
	}

	/* In case of remosic capture that is not use PDP & 3AA, it is returned. */
	if (sensor && !test_bit(IS_SENSOR_OTF_OUTPUT, &sensor->state))
		goto p_skip_update_sram;

	resourcemgr->dev_resource.taa_id = group->id - GROUP_ID_3AA0;
	resourcemgr->dev_resource.width = sensor->sensor_width;
	is_resource_update_lic_sram(resourcemgr, set);

p_skip_update_sram:
	minfo("[RSC] LIC taa_sram([0]%zu, [1]%zu, [2]%zu, [3]%zu, [sum]%d)\n", device,
	      lic_sram->taa_sram[0], lic_sram->taa_sram[1], lic_sram->taa_sram[2],
	      lic_sram->taa_sram[3], atomic_read(&lic_sram->taa_sram_sum));
}

int is_itf_stream_on(struct is_device_ischain *device)
{
	int ret = 0;
	struct device *dev = is_get_is_dev();
	struct exynos_platform_is *pdata = dev_get_platdata(dev);

	FIMC_BUG(!device);
	FIMC_BUG(!device->resourcemgr);

	pablo_ischain_set_global_param(device, true);
	if (is_get_debug_param(IS_DEBUG_PARAM_CLK) > 0)
		pdata->clk_print(dev);

	ret = is_itf_stream_on_wrap(device);

	return ret;
}

int is_itf_stream_off(struct is_device_ischain *device)
{
	int ret = 0;
	struct is_resourcemgr *resourcemgr;

	FIMC_BUG(!device);

	minfo("[ISC:D] stream off ready\n", device);

	ret = is_itf_stream_off_wrap(device);

	resourcemgr = device->resourcemgr;
	pablo_ischain_set_global_param(device, false);

	return ret;
}

int is_itf_process_start(struct is_device_ischain *device, struct is_group *head)
{
	return is_itf_process_on_wrap(device, head);
}

int is_itf_process_stop(struct is_device_ischain *device, struct is_group *head, u32 fstop)
{
	return is_itf_process_off_wrap(device, head, fstop);
}

static int is_itf_init_process_start(struct is_device_ischain *device)
{
	struct is_group *head = get_ischain_leader_group(device->instance);

	return is_itf_process_on_wrap(device, head);
}

static int is_itf_sensor_mode(struct is_device_ischain *device)
{
	int ret = 0;
	struct is_device_sensor *sensor;
	struct is_sensor_cfg *cfg;

	FIMC_BUG(!device);
	FIMC_BUG(!device->sensor);

	if (test_bit(IS_ISCHAIN_REPROCESSING, &device->state))
		goto p_err;

	sensor = device->sensor;

	cfg = is_sensor_g_mode(sensor);
	if (!cfg) {
		merr("is_sensor_g_mode is fail", device);
		ret = -EINVAL;
		goto p_err;
	}

	ret = is_itf_sensor_mode_wrap(device, cfg);
	if (ret)
		goto p_err;

p_err:
	return ret;
}

int is_itf_grp_shot(struct is_device_ischain *device,
	struct is_group *group,
	struct is_frame *frame)
{
	int ret = 0;
	unsigned long flags;
	struct is_group *head;
	struct is_framemgr *framemgr;
	bool is_remosaic_preview = false;

	mgrdbgs(1, " SHOT(%d)\n", group, group, frame, frame->index);

#ifdef ENABLE_MODECHANGE_CAPTURE
	if (!test_bit(IS_GROUP_REPROCESSING, &group->state)
		&& is_vendor_check_remosaic_mode_change(frame))
		is_remosaic_preview = true;
#endif

	head = GET_HEAD_GROUP_IN_DEVICE(IS_DEVICE_ISCHAIN, group);
	if (head && !is_remosaic_preview) {
		ret = is_itf_shot_wrap(group, frame);
	} else {
		framemgr = GET_HEAD_GROUP_FRAMEMGR(group);
		if (!framemgr) {
			merr("framemgr is NULL", group);
			ret = -EINVAL;
			goto p_err;
		}

		set_bit(group->leader.id, &frame->out_flag);
		framemgr_e_barrier_irqs(framemgr, FMGR_IDX_25, flags);
		trans_frame(framemgr, frame, FS_PROCESS);
		framemgr_x_barrier_irqr(framemgr, FMGR_IDX_25, flags);
	}

p_err:
	return ret;
}

int is_ischain_runtime_suspend(struct device *dev)
{
	int ret = 0;
	struct platform_device *pdev = to_platform_device(dev);
	struct is_core *core = (struct is_core *)dev_get_drvdata(dev);
	struct exynos_platform_is *pdata;
	int refcount;
	pdata = dev_get_platdata(dev);

	FIMC_BUG(!pdata);
	FIMC_BUG(!pdata->clk_off);

	info("FIMC_IS runtime suspend in\n");

#ifndef CAMERA_BLOCK_PCIE_L1SS_CTRL
#if IS_ENABLED(CONFIG_PCI_EXYNOS)
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0))
	exynos_pcie_l1ss_ctrl(1, PCIE_L1SS_CTRL_CAMERA, 0);
#else
	exynos_pcie_l1ss_ctrl(1, PCIE_L1SS_CTRL_CAMERA);
#endif
#endif
#endif

	ret = pdata->clk_off(&pdev->dev);
	if (ret)
		err("clk_off is fail(%d)", ret);

	refcount = atomic_dec_return(&core->resourcemgr.qos_refcount);
	if (refcount == 0)
		is_remove_dvfs(&core->resourcemgr.dvfs_ctrl, START_DVFS_LEVEL_SN);

	info("FIMC_IS runtime suspend out\n");
	return 0;
}

int is_ischain_runtime_resume(struct device *dev)
{
	int ret = 0;
	struct platform_device *pdev = to_platform_device(dev);
	struct is_core *core = (struct is_core *)dev_get_drvdata(dev);
	struct exynos_platform_is *pdata;
	int refcount;
	pdata = dev_get_platdata(dev);

	FIMC_BUG(!pdata);
	FIMC_BUG(!pdata->clk_cfg);
	FIMC_BUG(!pdata->clk_on);

	info("FIMC_IS runtime resume in\n");

	ret = pdata->clk_cfg(&pdev->dev);
	if (ret) {
		err("clk_cfg is fail(%d)", ret);
		goto p_err;
	}

	/*
	 * DVFS level should be locked after power on.
	 */
	refcount = atomic_inc_return(&core->resourcemgr.qos_refcount);
	if (refcount == 1) {
		u32 qos_thput[IS_DVFS_END];

		if (IS_ENABLED(CONFIG_EXYNOS_PM_QOS))
			is_hw_dvfs_get_qos_throughput(qos_thput);

		is_add_dvfs(&core->resourcemgr.dvfs_ctrl, START_DVFS_LEVEL_SN, qos_thput);
	}

	/* Clock on */
	ret = pdata->clk_on(&pdev->dev);
	if (ret) {
		err("clk_on is fail(%d)", ret);
		goto p_err;
	}

#ifndef CAMERA_BLOCK_PCIE_L1SS_CTRL
#if IS_ENABLED(CONFIG_PCI_EXYNOS)
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0))
		exynos_pcie_l1ss_ctrl(0, PCIE_L1SS_CTRL_CAMERA, 0);
#else
		exynos_pcie_l1ss_ctrl(0, PCIE_L1SS_CTRL_CAMERA);
#endif
#endif
#endif

p_err:
	info("FIMC-IS runtime resume out\n");
	return ret;
}

int is_ischain_power(struct is_device_ischain *device, int on)
{
	int ret = 0;
	int retry = 4;
	struct device *dev;
	struct is_core *core;
	struct is_vendor *vendor;
	int i;
	struct pablo_device_iommu_group_module *iommu_group_module;

	FIMC_BUG(!device);

	dev = &device->pdev->dev;
	core = (struct is_core *)dev_get_drvdata(dev);
	vendor = &core->vendor;

	if (on) {
		/* runtime suspend callback can be called lately because of power relationship */
		while (test_bit(IS_ISCHAIN_POWER_ON, &device->state) && (retry > 0)) {
			mwarn("sensor is not yet power off", device);
			msleep(500);
			--retry;
		}
		if (!retry) {
			ret = -EBUSY;
			goto p_err;
		}

		/* 2. FIMC-IS local power enable */
#if defined(CONFIG_PM)
		mdbgd_ischain("pm_runtime_suspended = %d\n", device, pm_runtime_suspended(dev));
		ret = pm_runtime_get_sync(dev);
		if (ret < 0)
			merr("pm_runtime_get_sync() return error: %d", device, ret);

		iommu_group_module = pablo_iommu_group_module_get();
		if (iommu_group_module) {
			for (i = 0; i < iommu_group_module->num_of_groups; i++) {
				ret = pm_runtime_get_sync(iommu_group_module->iommu_group[i]->dev);
				if (ret < 0)
					merr("pm_runtime_get_sync(iommu_group[%d]) is fail(%d)",
						device, i, ret);
			}
		}
#else
		is_ischain_runtime_resume(dev);
		minfo("%s(%d) - is runtime resume complete\n", device, __func__, on);
#endif

		ret = is_ischain_runtime_resume_post(dev);
		if (ret)
			merr("is_runtime_suspend_post is fail(%d)", device, ret);

		set_bit(IS_ISCHAIN_LOADED, &device->state);
		set_bit(IS_ISCHAIN_POWER_ON, &device->state);
	} else {
		/* FIMC-IS local power down */
		ret = is_ischain_runtime_suspend_post(dev);
		if (ret)
			merr("is_runtime_suspend_post is fail(%d)", device, ret);

#if defined(CONFIG_PM)
		ret = pm_runtime_put_sync(dev);
		if (ret)
			merr("pm_runtime_put_sync is fail(%d)", device, ret);

		iommu_group_module = pablo_iommu_group_module_get();
		if (iommu_group_module) {
			for (i = 0; i < iommu_group_module->num_of_groups; i++) {
				ret = pm_runtime_put_sync(iommu_group_module->iommu_group[i]->dev);
				if (ret < 0)
					merr("pm_runtime_put_sync(iommu_group[%d]) is fail(%d)",
						device, i, ret);
			}
		}
#else
		ret = is_ischain_runtime_suspend(dev);
		if (ret)
			merr("is_runtime_suspend is fail(%d)", device, ret);
#endif

		clear_bit(IS_ISCHAIN_POWER_ON, &device->state);
	}

p_err:

	minfo("%s(%d):%d\n", device, __func__, on, ret);
	return ret;
}

static int is_ischain_s_sensor_size(struct is_device_ischain *device, IS_DECLARE_PMAP(pmap))
{
	int ret = 0;
	struct param_sensor_config *sensor_config;
	struct is_device_sensor *sensor = device->sensor;
	struct is_device_sensor_peri *sensor_peri;
	struct is_cis *cis;
	struct is_module_enum *module;
	struct is_sensor_cfg *cfg;
	u32 binning, bns_binning;
	u32 sensor_width, sensor_height;
	u32 bns_width, bns_height;
	u32 framerate;
	u32 ex_mode;
	u32 pixel_order = 0; /* 0: GRBG, 1: RGGB, 2: BGGR, 3: GBRG */
	u32 mono_en;

	FIMC_BUG(!sensor);

	ret = is_sensor_g_module(sensor, &module);
	if (ret) {
		merr("is_sensor_g_module is fail(%d)", device, ret);
		return -EINVAL;
	}

	sensor_peri = (struct is_device_sensor_peri *)module->private_data;
	if (!sensor_peri) {
		mwarn("sensor_peri is null", device);
		return -EINVAL;
	}
	cis = &sensor_peri->cis;

	if (!module->pdata) {
		merr("module pdata is NULL", device);
		goto p_sensor_config;
	}

	if (module->pdata->sensor_module_type == SENSOR_TYPE_MONO)
		mono_en = 1;
	else
		mono_en = 0;
	minfo("[ISC:D] mono sensor(%d)\n", device, mono_en);


	if (sensor->obte_config & BIT(OBTE_CONFIG_BIT_BAYER_ORDER_EN))
		pixel_order = (sensor->obte_config & (BIT(OBTE_CONFIG_BIT_BAYER_ORDER_LSB) |
				BIT(OBTE_CONFIG_BIT_BAYER_ORDER_MSB))) >>
				OBTE_CONFIG_BIT_BAYER_ORDER_LSB;
	else
		pixel_order = cis->bayer_order;

p_sensor_config:
	cfg = is_sensor_g_mode(sensor);
	if (!cfg) {
		merr("is_sensor_g_mode is fail", device);
		return -EINVAL;
	}

	if (sensor->obte_config & BIT(OBTE_CONFIG_BIT_SENSOR_BINNING_EN)) {
		sensor->cfg->binning =
				(u32)OBTE_CONFIG_GET_SENSOR_BINNING_RATIO(sensor->obte_config);
		minfo("[ISC:D] binning(%u) changed by OBTE\n", device, sensor->cfg->binning);
	}

	binning = is_sensor_g_bratio(sensor);
	sensor_width = is_sensor_g_width(sensor);
	sensor_height = is_sensor_g_height(sensor);
	bns_width = is_sensor_g_bns_width(sensor);
	bns_height = is_sensor_g_bns_height(sensor);
	framerate = is_sensor_g_framerate(sensor);
	ex_mode = is_sensor_g_ex_mode(sensor);

	minfo("[ISC:D] binning(%u)\n", device, binning);

	if (test_bit(IS_ISCHAIN_REPROCESSING, &device->state))
		bns_binning = 1000;
	else
		bns_binning = is_sensor_g_bns_ratio(sensor);

	sensor_config = is_itf_g_param(device, NULL, PARAM_SENSOR_CONFIG);
	sensor_config->width = sensor_width;
	sensor_config->height = sensor_height;
	sensor_config->calibrated_width = module->pixel_width;
	sensor_config->calibrated_height = module->pixel_height;
	sensor_config->sensor_binning_ratio_x = binning;
	sensor_config->sensor_binning_ratio_y = binning;
	sensor_config->bns_binning_ratio_x = bns_binning;
	sensor_config->bns_binning_ratio_y = bns_binning;
	sensor_config->bns_margin_left = 0;
	sensor_config->bns_margin_top = 0;
	sensor_config->bns_output_width = bns_width;
	sensor_config->bns_output_height = bns_height;
	sensor_config->frametime = 10 * 1000 * 1000; /* max exposure time */
	sensor_config->pixel_order = pixel_order;
	sensor_config->vvalid_time = cfg->vvalid_time;
	sensor_config->req_vvalid_time = cfg->req_vvalid_time;
	sensor_config->scenario = sensor->ex_scenario;
	sensor_config->freeform_sensor_crop_enable = cis->freeform_sensor_crop.enable;
	sensor_config->freeform_sensor_crop_offset_x = cis->freeform_sensor_crop.x_start;
	sensor_config->freeform_sensor_crop_offset_y = cis->freeform_sensor_crop.y_start;

	if (IS_ENABLED(FIXED_FPS_DEBUG)) {
		sensor_config->min_target_fps = FIXED_MAX_FPS_VALUE;
		sensor_config->max_target_fps = FIXED_MAX_FPS_VALUE;
	} else {
		if (sensor->min_target_fps > 0)
			sensor_config->min_target_fps = sensor->min_target_fps;
		if (sensor->max_target_fps > 0)
			sensor_config->max_target_fps = sensor->max_target_fps;
	}

	if (is_sensor_g_fast_mode(sensor) == 1)
		sensor_config->early_config_lock = 1;
	else
		sensor_config->early_config_lock = 0;

	sensor_config->mono_mode = mono_en;

	set_bit(PARAM_SENSOR_CONFIG, pmap);

	return ret;
}

static bool __is_repeating_same_frame(struct is_frame *frame) {
	if (frame->stripe_info.region_num
	    && frame->stripe_info.region_id < frame->stripe_info.region_num - 1)
		return true;

	if (frame->repeat_info.num
	    && frame->repeat_info.idx < frame->repeat_info.num - 1)
		return true;

	return false;
}

int is_ischain_g_ddk_capture_meta_update(struct is_group *group, struct is_device_ischain *device,
	u32 fcount, u32 size, ulong addr)
{
	struct is_core *core = is_get_is_core();

	return  is_hardware_capture_meta_request(&core->hardware, group, device->instance, fcount, size, addr);
}

int is_ischain_g_ddk_setfile_version(struct is_device_ischain *device,
	void *user_ptr)
{
	int ret = 0;
	int position;
	struct ddk_setfile_ver *version_info;

	version_info = vzalloc(sizeof(struct ddk_setfile_ver));
	if (!version_info) {
		merr("version_info is NULL", device);
		ret = -ENOMEM;
		goto p_err;
	}

	strncpy(version_info->ddk_version, get_binary_version(IS_BIN_LIBRARY, IS_BIN_LIB_HINT_DDK), 60);
	position = device->sensor->position;
	strncpy(version_info->setfile_version, get_binary_version(IS_BIN_SETFILE, position), 60);
	version_info->header1 = SETFILE_VERSION_INFO_HEADER1;
	version_info->header2 = SETFILE_VERSION_INFO_HEADER2;

	ret = copy_to_user(user_ptr, version_info, sizeof(struct ddk_setfile_ver));

	vfree(version_info);
p_err:
	return ret;
}

int is_ischain_probe(struct is_device_ischain *device,
	struct is_resourcemgr *resourcemgr,
	struct platform_device *pdev,
	u32 instance)
{
	int ret, slot;

	FIMC_BUG(!pdev);
	FIMC_BUG(!device);

	device->pdev		= pdev;
	device->instance	= instance;
	device->resourcemgr	= resourcemgr;
	device->is_region	= (struct is_region *)((is_get_is_minfo())->kvaddr_region
					+ (device->instance * PARAM_REGION_SIZE));
	device->sensor		= NULL;
	device->setfile		= 0;
	device->state		= 0UL;
	device->ops = &dev_ischain_ops;

	atomic_set(&device->group_open_cnt, 0);
	atomic_set(&device->open_cnt, 0);
	atomic_set(&device->init_cnt, 0);

	for (slot = GROUP_SLOT_PAF; slot < GROUP_SLOT_MAX; slot++) {
		ret = is_group_probe(NULL, device, is_ischain_group_shot, slot);
		if (ret) {
			merr("failed ot is_group_probe(slot(%d))", device, slot);
			goto err_group_probe;
		}
	}

	return 0;

err_group_probe:
	while (--slot >= GROUP_SLOT_PAF)
		is_group_release(device, slot);

	return ret;
}
KUNIT_EXPORT_SYMBOL(is_ischain_probe);

void is_ischain_remove(struct is_device_ischain *device)
{
	int slot;

	FIMC_BUG_VOID(!device);

	for (slot = GROUP_SLOT_PAF; slot < GROUP_SLOT_MAX; slot++)
		is_group_release(device, slot);
}
KUNIT_EXPORT_SYMBOL(is_ischain_remove);

static int is_ischain_open(struct is_device_ischain *device)
{
	int ret = 0;

	if (!test_bit(IS_ISCHAIN_OPENING, &device->state)) {
		merr("It is not IS_ISCHAIN_OPENING.", device);
		return -EINVAL;
	}

	/* 2. Init variables */
	memset(&device->is_region->parameter, 0x0, sizeof(struct is_param_region));

	/* initial state, it's real apply to setting when opening */
	atomic_set(&device->init_cnt, 0);
	device->sensor = NULL;
	device->llc_mode = false;
	device->yuv_max_width = 0;
	device->yuv_max_height = 0;
	device->setfile = 0;

	spin_lock_init(&device->is_region->fd_info_slock);

	ret = is_devicemgr_open((void *)device, IS_DEVICE_ISCHAIN);
	if (ret) {
		err("is_devicemgr_open is fail(%d)", ret);
		goto p_err;
	}

	device->pii = pablo_interface_irta_get(device->instance);
	if (device->pii)
		pablo_interface_irta_open(device->pii, device);

	/* for mediaserver force close */
	ret = is_resource_get(device->resourcemgr, RESOURCE_TYPE_ISCHAIN);
	if (ret) {
		merr("is_resource_get is fail", device);
		goto p_err;
	}


p_err:
	clear_bit(IS_ISCHAIN_OPENING, &device->state);
	set_bit(IS_ISCHAIN_OPEN, &device->state);

	minfo("[ISC:D] %s():%d\n", device, __func__, ret);
	return ret;
}

int is_ischain_open_wrap(struct is_device_ischain *device, bool EOS)
{
	int ret = 0;
	struct is_core *core;
	struct is_device_ischain *ischain;
	u32 stream;

	FIMC_BUG(!device);

	if (test_bit(IS_ISCHAIN_CLOSING, &device->state)) {
		merr("open is invalid on closing", device);
		ret = -EPERM;
		goto p_err;
	}

	if (test_bit(IS_ISCHAIN_OPEN, &device->state)) {
		merr("already open", device);
		ret = -EMFILE;
		goto p_err;
	}

	if (atomic_read(&device->open_cnt) > ENTRY_END) {
		merr("open count is invalid(%d)", device, atomic_read(&device->open_cnt));
		ret = -EMFILE;
		goto p_err;
	}

	if (EOS) {
		ret = is_ischain_open(device);
		if (ret) {
			merr("is_chain_open is fail(%d)", device, ret);
			goto p_err;
		}

		/* Check other ischain device for multi_channel */
		core = is_get_is_core();
		for (stream = 0; stream < IS_STREAM_COUNT; ++stream) {
			ischain = &core->ischain[stream];

			if (!test_bit(IS_ISCHAIN_MULTI_CH, &ischain->state) ||
					!test_bit(ischain->instance, &device->ginstance_map))
				continue;

			set_bit(IS_ISCHAIN_OPEN, &ischain->state);
		}
	} else {
		atomic_inc(&device->open_cnt);
		set_bit(IS_ISCHAIN_OPENING, &device->state);
	}

p_err:
	return ret;
}

static int is_ischain_close(struct is_device_ischain *device)
{
	int ret = 0;

	FIMC_BUG(!device);

	if (!test_bit(IS_ISCHAIN_OPEN, &device->state)) {
		mwarn("this chain has not been opened", device);
		goto p_err;
	}

	ret = is_itf_close(device);
	if (ret)
		merr("is_itf_close is fail", device);

	if (device->pii) {
		pablo_interface_irta_close(device->pii);
		device->pii = NULL;
	}

	/* for mediaserver force close */
	ret = is_resource_put(device->resourcemgr, RESOURCE_TYPE_ISCHAIN);
	if (ret)
		merr("is_resource_put is fail", device);

	ret = is_devicemgr_close((void *)device, IS_DEVICE_ISCHAIN);
	if (ret) {
		err("is_devicemgr_close is fail(%d)", ret);
		goto p_err;
	}

	atomic_set(&device->open_cnt, 0);
	device->state = 0UL;

	minfo("[ISC:D] %s():%d\n", device, __func__, ret);

p_err:
	pablo_lib_set_stream_prefix(device->instance, "");

	return ret;
}

int is_ischain_close_wrap(struct is_device_ischain *device)
{
	int ret = 0;
	struct is_core *core;
	struct is_device_ischain *ischain;
	u32 stream;

	FIMC_BUG(!device);

	if (test_bit(IS_ISCHAIN_OPENING, &device->state)) {
		mwarn("close on opening", device);
		clear_bit(IS_ISCHAIN_OPENING, &device->state);
	}

	if (!atomic_read(&device->open_cnt)) {
		merr("open count is invalid(%d)", device, atomic_read(&device->open_cnt));
		ret = -ENOENT;
		goto p_err;
	}

	atomic_dec(&device->open_cnt);
	set_bit(IS_ISCHAIN_CLOSING, &device->state);

	if (!atomic_read(&device->open_cnt)) {
		ret = is_ischain_close(device);
		if (ret) {
			merr("is_chain_close is fail(%d)", device, ret);
			goto p_err;
		}

		clear_bit(IS_ISCHAIN_CLOSING, &device->state);
		clear_bit(IS_ISCHAIN_OPEN, &device->state);
		clear_bit(device->instance, &device->ginstance_map);

		/* Close another ischain device for multi_channel. */
		core = is_get_is_core();

		for (stream = 0; stream < IS_STREAM_COUNT; ++stream) {
			ischain = &core->ischain[stream];

			if (!test_bit(IS_ISCHAIN_MULTI_CH, &ischain->state) ||
					!test_bit(ischain->instance, &device->ginstance_map))
				continue;

			clear_bit(IS_ISCHAIN_MULTI_CH, &ischain->state);
			clear_bit(IS_ISCHAIN_OPEN, &ischain->state);
			clear_bit(ischain->instance, &device->ginstance_map);
		}
	}

p_err:
	return ret;
}

static int is_ischain_init(struct is_device_ischain *device)
{
	int ret = 0;
	struct is_core *core;
	struct is_module_enum *module;
	struct is_device_sensor *sensor;
	struct is_vendor *vendor;
	u32 flag;
	ulong kvaddr_cal;

	FIMC_BUG(!device);
	FIMC_BUG(!device->sensor);

	mdbgd_ischain("%s\n", device, __func__);

	sensor = device->sensor;
	core = is_get_is_core();
	vendor = &core->vendor;

	if (test_bit(IS_ISCHAIN_INIT, &device->state)) {
		minfo("stream is already initialized", device);
		goto p_err;
	}

	if (!test_bit(IS_SENSOR_S_INPUT, &sensor->state)) {
		merr("I2C gpio is not yet set", device);
		ret = -EINVAL;
		goto p_err;
	}

	ret = is_sensor_g_module(sensor, &module);
	if (ret) {
		merr("is_sensor_g_module is fail(%d)", device, ret);
		goto p_err;
	}

	kvaddr_cal = is_get_is_minfo()->kvaddr_cal[module->position];
	if (!test_bit(IS_ISCHAIN_REPROCESSING, &device->state)) {
		if (kvaddr_cal) {
			ret = is_vendor_cal_load(vendor, module);
			if (ret) {
				merr("is_vendor_cal_load is fail(%d)", device, ret);
				goto p_err;
			}
		} else {
			ret = is_vendor_cal_verify(vendor, module);
			if (ret) {
				merr("is_vendor_cal_verify is fail(%d)", device, ret);
				goto p_err;
			}
		}
	}

	ret = is_vendor_setfile_sel(vendor, module->setfile_name, module->position);
	if (ret) {
		merr("is_vendor_setfile_sel is fail(%d)", device, ret);
		goto p_err;
	}

	flag = test_bit(IS_ISCHAIN_REPROCESSING, &device->state) ? 1 : 0;

	flag |= (sensor->pdata->scenario == SENSOR_SCENARIO_STANDBY) ? (0x1 << 16) : (0x0 << 16);

	ret = is_itf_open(device, flag);
	if (ret) {
		merr("open fail", device);
		goto p_err;
	}

	ret = is_itf_setfile(device);
	if (ret) {
		merr("setfile fail", device);
		goto p_err;
	}

	clear_bit(IS_ISCHAIN_INITING, &device->state);
	set_bit(IS_ISCHAIN_INIT, &device->state);

p_err:
	return ret;
}

static int is_ischain_init_wrap(struct is_device_ischain *device,
	u32 stream_type,
	u32 position)
{
	int ret = 0;
	u32 sindex;
	struct is_core *core;
	struct is_device_sensor *sensor;
	struct is_module_enum *module;

	FIMC_BUG(!device);

	if (!test_bit(IS_ISCHAIN_OPEN, &device->state)) {
		merr("NOT yet open", device);
		ret = -EMFILE;
		goto p_err;
	}

	if (test_bit(IS_ISCHAIN_START, &device->state)) {
		merr("already start", device);
		ret = -EINVAL;
		goto p_err;
	}

	if (atomic_read(&device->init_cnt) >= atomic_read(&device->group_open_cnt)) {
		merr("init count value(%d) is invalid", device, atomic_read(&device->init_cnt));
		ret = -EINVAL;
		goto p_err;
	}

	core = is_get_is_core();
	atomic_inc(&device->init_cnt);
	set_bit(IS_ISCHAIN_INITING, &device->state);
	mdbgd_ischain("%s(%d, %d)\n", device, __func__,
		atomic_read(&device->init_cnt), atomic_read(&device->group_open_cnt));

	if (atomic_read(&device->init_cnt) == atomic_read(&device->group_open_cnt)) {
		for (sindex = 0; sindex < IS_SENSOR_COUNT; ++sindex) {
			sensor = &core->sensor[sindex];

			if (!test_bit(IS_SENSOR_OPEN, &sensor->state))
				continue;

			if (!test_bit(IS_SENSOR_S_INPUT, &sensor->state))
				continue;

			if (test_bit(IS_SENSOR_SUSPEND, &sensor->state))
				continue;

			ret = is_sensor_g_module(sensor, &module);
			if (ret) {
				merr("is_sensor_g_module is fail(%d)", device, ret);
				goto p_err;
			}

			ret = is_search_sensor_module_with_position(sensor, position, &module);
			if (!ret) {
				unsigned long i;

				for_each_set_bit(i, &device->ginstance_map, IS_STREAM_COUNT)
					core->ischain[i].sensor = sensor;

				minfo("%s: pos(%d)", device, __func__, position);
				break;
			}
		}

		if (ret) {
			merr("position(%d) is not supported.", device, position);
			goto p_err;
		}

		if (sindex >= IS_SENSOR_COUNT) {
			merr("position(%d) is invalid", device, position);
			ret = -EINVAL;
			goto p_err;
		}

		if (!sensor || !sensor->pdata) {
			merr("sensor is NULL", device);
			ret = -EINVAL;
			goto p_err;
		}

		if (stream_type) {
			set_bit(IS_ISCHAIN_REPROCESSING, &device->state);
			pablo_lib_set_stream_prefix(device->instance, "%s_R", sensor->sensor_name);
		} else {
			if (sensor->instance != device->instance) {
				merr("instance is mismatched (!= %d)[SS%d]", device, sensor->instance,
					sensor->device_id);
				ret = -EINVAL;
				goto p_err;
			}

			clear_bit(IS_ISCHAIN_REPROCESSING, &device->state);
			sensor->ischain = device;
		}

		ret = is_groupmgr_init(device);
		if (ret) {
			merr("is_groupmgr_init is fail(%d)", device, ret);
			goto p_err;
		}

		/* register sensor(DDK, RTA)/preporcessor interface*/
			if (!test_bit(IS_SENSOR_ITF_REGISTER, &sensor->state)) {
			ret = is_sensor_register_itf(sensor);
			if (ret) {
				merr("is_sensor_register_itf fail(%d)", device, ret);
				goto p_err;
			}

			set_bit(IS_SENSOR_ITF_REGISTER, &sensor->state);
		}

		ret = is_ischain_init(device);
		if (ret) {
			merr("is_ischain_init is fail(%d)", device, ret);
			goto p_err;
		}

		atomic_set(&device->init_cnt, 0);

		ret = is_devicemgr_binding(sensor, device, IS_DEVICE_ISCHAIN);
		if (ret) {
			merr("is_devicemgr_binding is fail", device);
			goto p_err;
		}
	}

p_err:
	return ret;
}

static void is_fastctl_manager_init(struct is_device_ischain *device)
{
	int i;
	unsigned long flags;
	struct fast_control_mgr *fastctlmgr;
	struct is_fast_ctl *fast_ctl;

	fastctlmgr = &device->fastctlmgr;

	spin_lock_init(&fastctlmgr->slock);
	fastctlmgr->fast_capture_count = 0;

	spin_lock_irqsave(&fastctlmgr->slock, flags);

	for (i = 0; i < IS_FAST_CTL_STATE; i++) {
		fastctlmgr->queued_count[i] = 0;
		INIT_LIST_HEAD(&fastctlmgr->queued_list[i]);
	}

	for (i = 0; i < MAX_NUM_FAST_CTL; i++) {
		fast_ctl = &fastctlmgr->fast_ctl[i];
		fast_ctl->state = IS_FAST_CTL_FREE;
		list_add_tail(&fast_ctl->list, &fastctlmgr->queued_list[IS_FAST_CTL_FREE]);
		fastctlmgr->queued_count[IS_FAST_CTL_FREE]++;
	}

	spin_unlock_irqrestore(&fastctlmgr->slock, flags);
}

static int is_ischain_start(struct is_device_ischain *device)
{
	int ret = 0;
	IS_DECLARE_PMAP(pmap);

	FIMC_BUG(!device);
	FIMC_BUG(!device->sensor);

	IS_INIT_PMAP(pmap);

	ret = is_hw_ischain_cfg((void *)device);
	if (ret) {
		merr("hw init fail", device);
		goto p_err;
	}

	ret = is_ischain_s_sensor_size(device, pmap);
	if (ret) {
		merr("is_ischain_s_sensor_size is fail(%d)", device, ret);
		goto p_err;
	}

	is_fastctl_manager_init(device);

	ret = is_itf_sensor_mode(device);
	if (ret) {
		merr("is_itf_sensor_mode is fail(%d)", device, ret);
		goto p_err;
	}

#if IS_ENABLED(SOC_30S)
	if (device->sensor->scene_mode >= AA_SCENE_MODE_DISABLED)
		device->is_region->parameter.taa.vdma1_input.scene_mode = device->sensor->scene_mode;
#endif

	ret = is_itf_s_param(device, NULL, pmap);
	if (ret) {
		merr("is_itf_s_param is fail(%d)", device, ret);
		goto p_err;
	}

	ret = is_itf_init_process_start(device);
	if (ret) {
		merr("is_itf_init_process_start is fail(%d)", device, ret);
		goto p_err;
	}

	set_bit(IS_ISCHAIN_START, &device->state);

p_err:
	minfo("[ISC:D] %s(%d):%d\n", device, __func__,
		device->setfile & IS_SETFILE_MASK, ret);

	return ret;
}

int is_ischain_start_wrap(struct is_device_ischain *device,
	struct is_group *group)
{
	int ret = 0;
	struct is_group *leader;

	if (!test_bit(IS_ISCHAIN_INIT, &device->state)) {
		merr("device is not yet init", device);
		ret = -EINVAL;
		goto p_err;
	}

	leader = get_leader_group(device->instance);
	if (leader != group)
		goto p_err;

	if (test_bit(IS_ISCHAIN_START, &device->state)) {
		merr("already start", device);
		ret = -EINVAL;
		goto p_err;
	}

	ret = is_groupmgr_start(device);
	if (ret) {
		merr("is_groupmgr_start is fail(%d)", device, ret);
		goto p_err;
	}

	ret = is_ischain_start(device);
	if (ret) {
		merr("is_chain_start is fail(%d)", device, ret);
		goto p_err;
	}

p_err:
	return ret;
}

int is_ischain_stop_wrap(struct is_device_ischain *device,
	struct is_group *group)
{
	int ret = 0;
	struct is_group *leader;

	leader = get_leader_group(device->instance);
	if (leader != group)
		goto p_err;

	if (!test_bit(IS_ISCHAIN_START, &device->state)) {
		mwarn("already stop", device);
		ret = -EINVAL;
		goto p_err;
	}

	is_groupmgr_stop(device);

	ret = is_itf_icpu_stop_wrap(device);
	if (ret) {
		merr("is_itf_icpu_stop_wrap is fail(%d)", device, ret);
		goto p_err;
	}

	clear_bit(IS_ISCHAIN_START, &device->state);

p_err:
	return ret;
}

static int change_vctx_group(struct is_device_ischain *device,
			struct is_video_ctx *ivc)
{
	struct is_device_ischain *ischain;
	struct is_core *core = is_get_is_core();
	u32 stream;

	for (stream = 0; stream < IS_STREAM_COUNT; ++stream) {
		ischain = &core->ischain[stream];

		if (ischain->instance == device->instance)
			continue;

		if (!test_bit(IS_ISCHAIN_OPEN, &ischain->state))
			break;
	}

	if (stream == IS_STREAM_COUNT) {
		merr("could not find ischain device", device);
		return -ENODEV;
	}

	ivc->group = ischain->group[ivc->group->slot];
	set_bit(IS_GROUP_USE_MULTI_CH, &ivc->group->state);
	set_bit(IS_ISCHAIN_MULTI_CH, &ischain->state);
	minfo("use ischain(%d) group for V%02d",
			device, ischain->instance, ivc->video->id);

	return 0;
}

int is_ischain_group_open(struct is_device_ischain *device,
			struct is_video_ctx *vctx, u32 group_id)
{
	int ret = 0;
	int ret_err = 0;

	FIMC_BUG(!device);
	FIMC_BUG(!vctx);

retry_group_open:
	ret = CALL_GROUP_OPS(vctx->group, open, group_id, vctx);
	if (ret) {
		if (ret == -EAGAIN) {
			ret = change_vctx_group(device, vctx);
			if (ret) {
				merr("change_vctx_group is fail(%d)", device, ret);
				goto err_group_open;
			}
			goto retry_group_open;
		} else {
			merr("is_group_open is fail(%d)", device, ret);
			goto err_group_open;
		}
	}

	ret = is_ischain_open_wrap(device, false);
	if (ret) {
		merr("is_ischain_open_wrap is fail(%d)", device, ret);
		goto err_ischain_open;
	}

	set_bit(vctx->group->instance, &device->ginstance_map);
	atomic_inc(&device->group_open_cnt);

	return 0;

err_ischain_open:
	ret_err = CALL_GROUP_OPS(vctx->group, close);
	if (ret_err)
		merr("is_group_close is fail(%d)", device, ret_err);
err_group_open:
	return ret;
}

static int is_ischain_group_start(struct is_device_ischain *idi, struct is_group *ig)
{
	int ret;

	ret = CALL_GROUP_OPS(ig, start);
	if (ret) {
		merr("is_group_start is fail(%d)", idi, ret);
		return ret;
	}

	ret = is_ischain_start_wrap(idi, ig);
	if (ret) {
		merr("is_ischain_start_wrap is fail(%d)", idi, ret);
		return ret;
	}

	return 0;
}

static int is_ischain_group_stop(struct is_device_ischain *idi, struct is_group *ig)
{
	int ret = 0;

	if (!test_bit(IS_GROUP_INIT, &ig->state)) {
		mgwarn("group is not initialized yet", ig, ig);
		goto err_group_init;
	}

	ret = CALL_GROUP_OPS(ig, stop);
	if (ret) {
		if (ret == -EPERM)
			ret = 0;
		else
			merr("is_group_stop is fail(%d)", idi, ret);
		goto err_group_stop;
	}

	ret = is_ischain_stop_wrap(idi, ig);
	if (ret) {
		merr("is_ischain_stop_wrap is fail(%d)", idi, ret);
		goto err_ischain_stop;
	}

err_ischain_stop:
err_group_stop:
err_group_init:
	mginfo("%s, group->scount: %d (%d)\n", idi, ig,  __func__,
					atomic_read(&ig->scount), ret);

	return ret;
}

static int is_ischain_group_s_fmt(struct is_device_ischain *idi,
					struct is_queue *iq, struct is_group *ig)
{
	struct is_subdev *leader = &ig->leader;

	leader->input.width = iq->framecfg.width;
	leader->input.height = iq->framecfg.height;

	leader->input.crop.x = 0;
	leader->input.crop.y = 0;
	leader->input.crop.w = leader->input.width;
	leader->input.crop.h = leader->input.height;

	return 0;
}

int is_ischain_group_close(struct is_device_ischain *device, struct is_group *group)
{
	int ret;
	struct is_sysfs_debug *sysfs_debug = is_get_sysfs_debug();

	/* for mediaserver dead */
	if (test_bit(IS_GROUP_START, &group->state)) {
		mgwarn("sudden group close", device, group);
		if (!test_bit(IS_ISCHAIN_REPROCESSING, &device->state))
			is_itf_sudden_stop_wrap(device, device->instance, group);
		set_bit(IS_GROUP_REQUEST_FSTOP, &group->state);
		if (test_bit(IS_HAL_DEBUG_SUDDEN_DEAD_DETECT, &sysfs_debug->hal_debug_mode)) {
			msleep(sysfs_debug->hal_debug_delay);
			panic("HAL sudden group close #1");
		}
	}

	if (group->head && test_bit(IS_GROUP_START, &group->head->state)) {
		mgwarn("sudden group close", device, group);
		if (!test_bit(IS_ISCHAIN_REPROCESSING, &device->state))
			is_itf_sudden_stop_wrap(device, device->instance, group);
		set_bit(IS_GROUP_REQUEST_FSTOP, &group->state);
		if (test_bit(IS_HAL_DEBUG_SUDDEN_DEAD_DETECT, &sysfs_debug->hal_debug_mode)) {
			msleep(sysfs_debug->hal_debug_delay);
			panic("HAL sudden group close #2");
		}
	}

	ret = is_ischain_group_stop(device, group);
	if (ret)
		merr("is_ischain_group_stop is fail", device);

	ret = is_ischain_close_wrap(device);
	if (ret)
		merr("is_ischain_close_wrap is fail(%d)", device, ret);

	ret = CALL_GROUP_OPS(group, close);
	if (ret)
		merr("is_group_close is fail", device);

	atomic_dec(&device->group_open_cnt);

	return ret;
}

int is_ischain_group_s_input(struct is_device_ischain *device,
	struct is_group *group,
	u32 stream_type,
	u32 position,
	u32 input_type,
	u32 stream_leader)
{
	int ret;

	mdbgd_ischain("%s()\n", device, __func__);

	ret = CALL_GROUP_OPS(group, init, input_type, stream_leader, stream_type);
	if (ret) {
		merr("is_group_init is fail(%d)", device, ret);
		goto err_initialize_group;
	}

	ret = is_ischain_init_wrap(device, stream_type, position);
	if (ret) {
		merr("is_ischain_init_wrap is fail(%d)", device, ret);
		goto err_initialize_ischain;
	}

err_initialize_ischain:
err_initialize_group:
	return ret;
}

static int is_ischain_device_start(void *device, struct is_queue *iq)
{
	struct is_video_ctx *ivc = iq->vbq->drv_priv;

	return is_ischain_group_start((struct is_device_ischain *)device, ivc->group);
}

static int is_ischain_device_stop(void *device, struct is_queue *iq)
{
	struct is_video_ctx *ivc = iq->vbq->drv_priv;

	return is_ischain_group_stop((struct is_device_ischain *)device, ivc->group);
}

static int is_ischain_device_s_fmt(void *device, struct is_queue *iq)
{
	struct is_video_ctx *ivc = iq->vbq->drv_priv;

	return is_ischain_group_s_fmt((struct is_device_ischain *)device, iq, ivc->group);
}

static struct is_queue_ops is_ischain_device_qops = {
	.start_streaming	= is_ischain_device_start,
	.stop_streaming		= is_ischain_device_stop,
	.s_fmt			= is_ischain_device_s_fmt,
};

struct is_queue_ops *is_get_ischain_device_qops(void)
{
	return &is_ischain_device_qops;
}

static struct is_frame *is_ischain_check_frame(struct is_group *group,
						struct is_frame *check_frame)
{
	struct is_frame *frame;
	struct is_framemgr *framemgr;

	framemgr = GET_HEAD_GROUP_FRAMEMGR(group);
	if (!framemgr) {
		mgerr("framemgr is NULL", group, group);
		return ERR_PTR(-EINVAL);
	}

	if (check_frame->state != FS_REQUEST && check_frame->state != FS_REPEAT_PROCESS) {
		mgerr("check_frame state is invalid(%d)", group, group, check_frame->state);
		return ERR_PTR(-EINVAL);
	}

	frame = peek_frame(framemgr, check_frame->state);
	if (unlikely(!frame)) {
		mgerr("frame is NULL", group, group);
		return ERR_PTR(-EINVAL);
	}

	if (unlikely(frame != check_frame)) {
		mgerr("frame checking is fail(%p != %p)", group, group, frame, check_frame);
		return ERR_PTR(-EINVAL);
	}

	if (unlikely(!frame->shot)) {
		mgerr("frame->shot is NULL", group, group);
		return ERR_PTR(-EINVAL);
	}

	PROGRAM_COUNT(8);

	return frame;
}

static void is_ischain_update_setfile(struct is_device_ischain *device,
	struct is_group *group,
	struct is_frame *frame)
{
	int ret;
	bool update_condition = false;
	u32 setfile_save = device->setfile;
	struct is_group *group_leader = get_ischain_leader_group(device->instance);

	/*
	 * Initial update condition.
	 * This condition is applied for both preview and reprocessing stream.
	 */
	if (!atomic_read(&group_leader->scount))
		update_condition = true;

	/*
	 * In case of reprocessing stream, meta data value is prior to "device->setfile"
	 * because of supporting dynamic setfile change.
	 */
	if (test_bit(IS_ISCHAIN_REPROCESSING, &device->state) &&
	    (frame->shot_ext->setfile != device->setfile)) {
		update_condition = true;
		device->setfile = frame->shot_ext->setfile;
	}

	if (update_condition) {
		mgrinfo(" setfile change at shot(%d -> %d)\n", device, group, frame,
			setfile_save, device->setfile & IS_SETFILE_MASK);

		ret = is_itf_chg_setfile(device);
		if (ret) {
			merr("is_ischain_chg_setfile is fail", device);
			device->setfile = setfile_save;
		}
	}

	PROGRAM_COUNT(9);
}

static int is_ischain_child_tag(struct is_device_ischain *device,
				struct is_group *group,
				struct is_frame *frame)
{
	int ret = 0;
	struct is_group *child, *pnext;
	struct camera2_node_group *node_group;
	struct camera2_node ldr_node = {0, };

	node_group = &frame->shot_ext->node_group;

	ldr_node.pixelformat = node_group->leader.pixelformat;
	ldr_node.pixelsize = node_group->leader.pixelsize;

	TRANS_CROP(ldr_node.input.cropRegion,
		node_group->leader.input.cropRegion);
	TRANS_CROP(ldr_node.output.cropRegion,
		ldr_node.input.cropRegion);

	child = group;
	pnext = group->head->pnext;
	while (child) {
		TRANS_CROP(ldr_node.input.cropRegion, ldr_node.output.cropRegion);
		TRANS_CROP(ldr_node.output.cropRegion, ldr_node.input.cropRegion);

		ret = CALL_SOPS(&child->leader, tag, device, frame, &ldr_node);
		if (ret) {
			mgerr("leader tag ops is fail(%d)", child, child, ret);
			goto p_err;
		}

		child = child->child;
		if (!child) {
			child = pnext;
			pnext = NULL;
		}
	}

p_err:
	PROGRAM_COUNT(10);

	return ret;
}

static void is_ischain_update_shot(struct is_device_ischain *device,
	struct is_frame *frame)
{
	struct fast_control_mgr *fastctlmgr = &device->fastctlmgr;
	struct is_fast_ctl *fast_ctl = NULL;
	struct camera2_shot *shot = frame->shot;
	unsigned long flags;
	u32 state;

	spin_lock_irqsave(&fastctlmgr->slock, flags);

	state = IS_FAST_CTL_REQUEST;
	if (fastctlmgr->queued_count[state]) {
		/* get req list */
		fast_ctl = list_first_entry(&fastctlmgr->queued_list[state],
			struct is_fast_ctl, list);
		list_del(&fast_ctl->list);
		fastctlmgr->queued_count[state]--;

		/* Read fast_ctl: lens */
		if (fast_ctl->lens_pos_flag) {
			shot->uctl.lensUd.pos = fast_ctl->lens_pos;
			shot->uctl.lensUd.posSize = 12; /* fixed value: bit size(12 bit) */
			shot->uctl.lensUd.direction = 0; /* fixed value: 0(infinite), 1(macro) */
			shot->uctl.lensUd.slewRate = 0; /* fixed value: only DW actuator speed */
			shot->ctl.aa.afMode = AA_AFMODE_OFF;
			fast_ctl->lens_pos_flag = false;
		}

		/* set free list */
		state = IS_FAST_CTL_FREE;
		fast_ctl->state = state;
		list_add_tail(&fast_ctl->list, &fastctlmgr->queued_list[state]);
		fastctlmgr->queued_count[state]++;
	}

	spin_unlock_irqrestore(&fastctlmgr->slock, flags);

	if (fast_ctl)
		mrinfo("fast_ctl: uctl.lensUd.pos(%d)\n", device, frame, shot->uctl.lensUd.pos);
}

static void is_ischain_update_otf_data(struct is_device_ischain *device,
					struct is_group *group,
					struct is_frame *frame)
{
	struct is_resourcemgr *resourcemgr = device->resourcemgr;
	struct is_device_sensor *sensor = device->sensor;
	struct is_vb2_buf *vbuf;

	is_vendor_update_otf_data(group, frame);

	if (sensor->exposure_fcount[frame->fcount % IS_EXP_BACKUP_COUNT] == (frame->fcount - SENSOR_REQUEST_DELAY)
		&& sensor->exposure_value[frame->fcount % IS_EXP_BACKUP_COUNT] >= ((SHOT_TIMEOUT * 1000) - 1000000)) {
		resourcemgr->shot_timeout =
			(sensor->exposure_value[frame->fcount % IS_EXP_BACKUP_COUNT] / 1000) + SHOT_TIMEOUT;
		resourcemgr->shot_timeout_tick = KEEP_FRAME_TICK_DEFAULT;
	} else if (resourcemgr->shot_timeout_tick > 0) {
		resourcemgr->shot_timeout_tick--;
	} else {
		resourcemgr->shot_timeout = SHOT_TIMEOUT;
	}

	mdbgd_ischain("[%s] fcount(%d), exposure_fcount(%d), exposure_value(%d), shot_timeout(%d), tick(%d)\n",
		device, __func__, frame->fcount, sensor->exposure_fcount[frame->fcount % IS_EXP_BACKUP_COUNT],
		sensor->exposure_value[frame->fcount % IS_EXP_BACKUP_COUNT],
		resourcemgr->shot_timeout, resourcemgr->shot_timeout_tick);

	is_ischain_update_shot(device, frame);

	if (!IS_ENABLED(ICPU_IO_COHERENCY)) {
		vbuf = frame->vbuf;
		if (vbuf)
			vbuf->ops->plane_sync_for_device(vbuf);
	}
}

static inline void is_ischain_sbuf_tag(struct is_group *group, struct is_frame *frame)
{
	int i, ret;
	struct is_sub_frame *sframe;
	dma_addr_t *dva;
	u64 *kva;

	for (i = 0; i < CAPTURE_NODE_MAX; i++) {
		sframe = &frame->cap_node.sframe[i];
		if (!sframe->id)
			continue;

		if (IS_SENSOR_LVN_VID(sframe->id) || IS_MULTI_CH_LVN_VID(sframe->id))
			continue;

		ret = is_hw_get_capture_slot(frame, &dva, &kva, sframe->id);
		if (ret) {
			mrerr("Invalid capture slot(%d)", group, frame, sframe->id);
			continue;
		}

		if (dva)
			memcpy(dva, sframe->dva, sizeof(dma_addr_t) * sframe->num_planes);

		if (kva)
			memcpy(kva, sframe->kva, sizeof(u64) * sframe->num_planes);
	}
}

static int is_ischain_group_shot(struct is_device_ischain *device,
	struct is_group *group,
	struct is_frame *check_frame)
{
	int ret = 0;
	unsigned long flags;
	struct is_framemgr *framemgr;
	struct is_frame *frame;
	enum is_frame_state next_state = FS_PROCESS;

	mgrdbgs(4, "[i:%d] %s\n", group, group, check_frame, check_frame->index, __func__);

	frame = is_ischain_check_frame(group, check_frame);
	if (IS_ERR_OR_NULL(frame)) {
		mgerr("is_ischain_check_frame is fail", group, group);
		return -EINVAL;
	}

	is_ischain_update_setfile(device, group, frame);

	if (test_bit(IS_GROUP_OTF_INPUT, &group->state))
		is_ischain_update_otf_data(device, group, frame);

	if (!atomic_read(&group->head->scount)) /* first shot */
		set_bit(IS_SUBDEV_FORCE_SET, &group->head->leader.state);
	else
		clear_bit(IS_SUBDEV_FORCE_SET, &group->head->leader.state);

	ret = is_ischain_child_tag(device, group, frame);
	if (ret) {
		mgerr("is_ischain_child_tag is fail(%d)", group, group, ret);
		goto p_err;
	}

	is_ischain_sbuf_tag(group, frame);

p_err:
	if (__is_repeating_same_frame(frame))
		next_state = FS_REPEAT_PROCESS;

	if (ret) {
		mgrerr(" SKIP(%d) : %d\n", group, group, check_frame, check_frame->index, ret);
	} else {
		framemgr = GET_HEAD_GROUP_FRAMEMGR(group);
		if (!framemgr) {
			mgerr("[F%d] Failed to get head framemgr", group, group, check_frame->fcount);
			return -EINVAL;
		}

		set_bit(group->leader.id, &frame->out_flag);
		framemgr_e_barrier_irqs(framemgr, FMGR_IDX_26, flags);
		trans_frame(framemgr, frame, next_state);

		if (IS_ENABLED(SENSOR_REQUEST_DELAY)
		    && test_bit(IS_GROUP_OTF_INPUT, &group->state)) {
			if (framemgr->queued_count[FS_REQUEST] < SENSOR_REQUEST_DELAY)
				mgrwarn(" late sensor control shot", group, group, frame);
		}

		framemgr_x_barrier_irqr(framemgr, FMGR_IDX_26, flags);
	}

	return ret;
}

static const struct pablo_device_ischain_ops dev_ischain_ops = {
	.power = is_ischain_power,
};

#if IS_ENABLED(CONFIG_PABLO_KUNIT_TEST)
static struct pablo_kunit_device_ischain_func device_ischain_func = {
	.itf_open = is_itf_open,
	.itf_close = is_itf_close,
	.itf_setfile = is_itf_setfile,
	.g_ddk_capture_meta_update = is_ischain_g_ddk_capture_meta_update,
	.g_ddk_setfile_version = is_ischain_g_ddk_setfile_version,
	.open = is_ischain_open,
	.close = is_ischain_close,
	.change_vctx_group = change_vctx_group,
	.group_open = is_ischain_group_open,
	.group_close = is_ischain_group_close,
	.group_s_input = is_ischain_group_s_input,
	.get_device_qops = is_get_ischain_device_qops,
};

struct pablo_kunit_device_ischain_func *pablo_kunit_get_device_ischain_func(void)
{
	return &device_ischain_func;
}
KUNIT_EXPORT_SYMBOL(pablo_kunit_get_device_ischain_func);
#endif
