/*
 * drivers/media/platform/exynos/mfc/mfc_core_ops.c
 *
 * Copyright (c) 2020 Samsung Electronics Co., Ltd.
 *		http://www.samsung.com/
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <soc/samsung/exynos/exynos-hvc.h>
#if IS_ENABLED(CONFIG_EXYNOS_IMGLOADER)
#include <soc/samsung/exynos/imgloader.h>
#endif

#include "mfc_core_ops.h"

#include "mfc_core_hwlock.h"
#include "mfc_core_run.h"
#include "mfc_core_nal_q.h"
#include "mfc_core_pm.h"
#include "mfc_core_otf.h"
#include "mfc_core_sync.h"

#include "mfc_core_perf_measure.h"
#include "mfc_core_hw_reg_api.h"

#include "base/mfc_sched.h"
#include "base/mfc_llc.h"
#include "base/mfc_qos.h"
#include "base/mfc_meminfo.h"
#include "base/mfc_buf.h"
#include "base/mfc_utils.h"
#include "base/mfc_queue.h"
#include "base/mfc_mem.h"

#if IS_ENABLED(CONFIG_EXYNOS_CONTENT_PATH_PROTECTION)
static int __mfc_core_prot_firmware(struct mfc_core *core)
{
	phys_addr_t protdesc_phys;
	dma_addr_t protdesc_daddr;
	int ret = 0;

	mfc_core_debug_enter();

	if (!core->drm_fw_buf.sgt) {
		mfc_core_err("DRM F/W buffer is not allocated\n");
	} else {
		core->drm_fw_prot = kzalloc(sizeof(struct mfc_buffer_prot_info), GFP_KERNEL);
		if (!core->drm_fw_prot) {
			mfc_core_err("no memory for drm_fw_prot\n");
			return -ENOMEM;
		}

		/* Request buffer Secure-DVA set */
		core->drm_fw_prot->chunk_count = core->drm_fw_buf.sgt->orig_nents;

		if (core->dev->pdata->dma_bit_mask == MFC_MIN_BITMASK)
			core->drm_fw_prot->dma_addr = core->drm_fw_buf.daddr;
		else
			core->drm_fw_prot->dma_addr = (core->drm_fw_buf.daddr >> 4);

		core->drm_fw_prot->protect_id = EXYNOS_SECBUF_VIDEO_FW_PROT_ID;
		core->drm_fw_prot->chunk_size = core->drm_fw_buf.size;
		core->drm_fw_prot->paddr = core->drm_fw_buf.paddr;

		/* We must cache flush for secure world cache */
		protdesc_phys = virt_to_phys(core->drm_fw_prot);
		protdesc_daddr = phys_to_dma(core->dev->cache_op_dev, protdesc_phys);

		dma_sync_single_for_device(core->dev->cache_op_dev, protdesc_daddr,
				sizeof(struct mfc_buffer_prot_info), DMA_TO_DEVICE);

		/* Request buffer protection for DRM F/W */
		ret = exynos_hvc(HVC_DRM_TZMP2_MFCFW_PROT, protdesc_phys,
				core->id * PROT_MFC1, 0, 0);
		if (ret != HVC_OK) {
			mfc_core_err("failed MFC DRM F/W prot(%#x)\n", ret);
			call_dop(core, dump_and_stop_debug_mode, core);
			kfree(core->drm_fw_prot);
			core->drm_fw_prot = NULL;
			return -EACCES;
		} else {
			mfc_core_debug(2, "DRM F/W region protected\n");
		}
	}

	mfc_core_change_fw_state(core, 1, MFC_FW_PROTECTED, 1);
	mfc_core_debug_leave();

	return 0;
}

static void __mfc_core_unprot_firmware(struct mfc_core *core)
{
	phys_addr_t protdesc_phys;
	int ret = 0;

	mfc_core_debug_enter();

	if (!(core->fw.drm_status & MFC_FW_PROTECTED)) {
		mfc_core_info("DRM F/W region already unprotected\n");
		return;
	}

	/* Request buffer unprotection for DRM F/W */
	protdesc_phys = virt_to_phys(core->drm_fw_prot);
	ret = exynos_hvc(HVC_DRM_TZMP2_MFCFW_UNPROT, protdesc_phys,
			core->id * PROT_MFC1, 0, 0);
	if (ret != HVC_OK) {
		mfc_core_err("failed MFC DRM F/W unprot(%#x)\n", ret);
		call_dop(core, dump_and_stop_debug_mode, core);
	}

	kfree(core->drm_fw_prot);
	core->drm_fw_prot = NULL;
	mfc_core_change_fw_state(core, 1, MFC_FW_PROTECTED, 0);

	mfc_core_debug_leave();
}
#endif

#if IS_ENABLED(CONFIG_EXYNOS_S2MPU)
int __mfc_verify_fw(struct mfc_core *core, struct mfc_special_buf *fw_buf)
{
	uint64_t ret64 = 0;

	/* Request F/W verification. This must be requested after power on */
	ret64 = exynos_verify_subsystem_fw(fw_buf->name, 0,
				fw_buf->paddr, core->fw.fw_size, fw_buf->size);
	if (ret64) {
		mfc_core_err("Failed F/W verification, ret=%llu\n", ret64);
		return -EIO;
	}

	ret64 = exynos_request_fw_stage2_ap(fw_buf->name);
	if (ret64) {
		mfc_core_err("Failed F/W verification to S2MPU, ret=%llu\n", ret64);
		return -EIO;
	}

	if (fw_buf->buftype == MFCBUF_NORMAL_FW)
		mfc_core_change_fw_state(core, 0, MFC_FW_VERIFIED, 1);
	else
		mfc_core_change_fw_state(core, 1, MFC_FW_VERIFIED, 1);

	return 0;
}
#endif

static void __mfc_core_init(struct mfc_core *core, struct mfc_ctx *ctx)
{
	struct mfc_dev *dev = core->dev;

	/* set meerkat timer */
	mod_timer(&core->meerkat_timer, jiffies + msecs_to_jiffies(MEERKAT_TICK_INTERVAL));

	/* set MFC idle timer */
	atomic_set(&core->hw_run_bits, 0);
	mfc_core_change_idle_mode(core, MFC_IDLE_MODE_NONE);

	if (!dev->fw_date)
		dev->fw_date = core->fw.date;
	else if (dev->fw_date > core->fw.date)
		dev->fw_date = core->fw.date;

	if (core->has_llc && (core->llc_on_status == 0))
		mfc_llc_enable(core);

	if (MFC_FEATURE_SUPPORT(dev, dev->pdata->nal_q)) {
		core->nal_q_handle = mfc_core_nal_q_create(core);
		if (core->nal_q_handle == NULL)
			mfc_core_err("[NALQ] Can't create nal q\n");
	}

	if (dev->debugfs.perf_boost_mode)
		mfc_qos_perf_boost_enable(core);

	mfc_perf_init(core);
}

static int __mfc_wait_close_inst(struct mfc_core *core, struct mfc_ctx *ctx)
{
	struct mfc_core_ctx *core_ctx = core->core_ctx[ctx->num];
	int ret = 0;

	if (core->state == MFCCORE_ERROR) {
		mfc_info("[MSR] Couldn't close inst. It's Error state\n");
		return 0;
	}

	if (atomic_read(&core->meerkat_run)) {
		mfc_err("meerkat already running!\n");
		return 0;
	}

	if (core_ctx->state <= MFCINST_INIT) {
		mfc_debug(2, "mfc instance didn't opend or already closed\n");
		return 0;
	}

	mfc_clean_core_ctx_int_flags(core_ctx);
	mfc_change_state(core_ctx, MFCINST_RETURN_INST);
	core->sched->set_work(core, core_ctx);

	/* To issue the command 'CLOSE_INSTANCE' */
	if (mfc_core_just_run(core, ctx->num)) {
		mfc_err("failed to run MFC, state: %d\n", core_ctx->state);
		MFC_TRACE_CTX_LT("[ERR][Release] failed to run MFC, state: %d\n", core_ctx->state);
		return -EIO;
	}

	/* Wait until instance is returned or timeout occured */
	ret = mfc_wait_for_done_core_ctx(core_ctx, MFC_REG_R2H_CMD_CLOSE_INSTANCE_RET);
	if (ret == 1) {
		mfc_err("failed to wait CLOSE_INSTANCE(timeout)\n");

		if (mfc_wait_for_done_core_ctx(core_ctx,
					MFC_REG_R2H_CMD_CLOSE_INSTANCE_RET)) {
			mfc_err("waited once more but failed to wait CLOSE_INSTANCE\n");
			core->logging_data->cause |= (1 << MFC_CAUSE_FAIL_CLOSE_INST);
			call_dop(core, dump_and_stop_always, core);
		}
	} else if (ret == -1) {
		mfc_err("failed to wait CLOSE_INSTANCE(err)\n");
		call_dop(core, dump_and_stop_debug_mode, core);
	}

	return 0;
}

static int __mfc_core_deinit(struct mfc_core *core, struct mfc_ctx *ctx)
{
	struct mfc_core_ctx *core_ctx = core->core_ctx[ctx->num];
	int ret = 0;

	core->sched->clear_work(core, core_ctx);

	ret = __mfc_wait_close_inst(core, ctx);
	if (ret) {
		mfc_err("Failed to close instance\n");
		return ret;
	}

	if (ctx->gdc_votf || (ctx->otf_handle && core->has_dpu_votf && core->has_mfc_votf)) {
		mfc_core_clear_votf(core);
		mfc_core_votf_deinit(ctx);
	}

	if (ctx->is_drm)
		core->num_drm_inst--;
	core->num_inst--;

	/* Last normal instance */
	if (!ctx->is_drm && ((core->num_inst - core->num_drm_inst) == 0)) {
		/*
		 * This is to cache flush the normal FW that will disappear(un-load)
		 * for the next DRM operation after normal FW + HW operation.
		 * But if curr_core_ctx_is_drm is already DRM,
		 * there is no need to do it because DRM instance has already operated.
		 */
		if (!core->curr_core_ctx_is_drm) {
			core->curr_core_ctx = ctx->num;
			mfc_core_pm_clock_on(core, 0);
			mfc_core_run_cache_flush(core, ctx->is_drm, MFC_CACHEFLUSH, 0, 0);
			mfc_core_pm_clock_off(core, 0);
		}
		mfc_core_change_fw_state(core, 0, MFC_FW_INITIALIZED, 0);
#if IS_ENABLED(CONFIG_EXYNOS_IMGLOADER)
		imgloader_shutdown(&core->mfc_imgloader_desc);
#else
#if IS_ENABLED(CONFIG_EXYNOS_S2MPU)
		mfc_release_verify_fw(core, &core->fw_buf);
#endif
#endif
		mfc_core_change_fw_state(core, 0, MFC_FW_LOADED, 0);
	}

	/* Last DRM instance */
	if (ctx->is_drm && (core->num_drm_inst == 0)) {
		/*
		 * This is to cache flush the DRM FW that will disappear(un-load)
		 * for the next normal operation after DRM FW + HW operation.
		 * But if curr_core_ctx_is_drm is already normal,
		 * there is no need to do it because normal instance has already operated.
		 */
		if (core->curr_core_ctx_is_drm) {
			core->curr_core_ctx = ctx->num;
			mfc_core_pm_clock_on(core, 0);
			mfc_core_run_cache_flush(core, ctx->is_drm, MFC_CACHEFLUSH, 0, 0);
			mfc_core_pm_clock_off(core, 0);
			mfc_core_protection_off(core, 1);
		}

		mfc_core_change_fw_state(core, 1, MFC_FW_INITIALIZED, 0);
#if IS_ENABLED(CONFIG_EXYNOS_IMGLOADER)
		imgloader_shutdown(&core->mfc_imgloader_desc_drm);
#else
#if IS_ENABLED(CONFIG_EXYNOS_S2MPU)
		mfc_release_verify_fw(core, &core->drm_fw_buf);
#endif
#endif
#if IS_ENABLED(CONFIG_EXYNOS_CONTENT_PATH_PROTECTION)
		__mfc_core_unprot_firmware(core);
#endif
		mfc_core_change_attribute(core, 0);
		mfc_core_change_fw_state(core, 1, MFC_FW_LOADED, 0);
	}

	if (core->num_inst == 0) {
		mfc_core_run_deinit_hw(core);

		if (core->dev->debugfs.perf_boost_mode)
			mfc_qos_perf_boost_disable(core);

		del_timer(&core->meerkat_timer);
		del_timer(&core->mfc_idle_timer);

		flush_workqueue(core->butler_wq);

		mfc_debug(2, "power off\n");
		mfc_core_pm_power_off(core);

		if (core->dev->debugfs.dbg_enable)
			mfc_release_dbg_info_buffer(core);

		if (core->nal_q_handle)
			mfc_core_nal_q_destroy(core, core->nal_q_handle);

		if (core->state == MFCCORE_ERROR) {
			mfc_core_change_state(core, MFCCORE_INIT);
			mfc_info("[MSR] MFC-%d will be reset\n", core->id);
		}
	}

	mfc_qos_off(core, ctx);

	if (core->has_llc && core->llc_on_status) {
		mfc_llc_flush(core);

		if (core->num_inst == 0)
			mfc_llc_disable(core);
		else
			if (ctx->is_8k)
				mfc_llc_update_size(core, false, ctx->type);
	}

	return 0;
}

static int __mfc_force_close_inst(struct mfc_core *core, struct mfc_ctx *ctx)
{
	struct mfc_core_ctx *core_ctx = core->core_ctx[ctx->num];
	enum mfc_inst_state prev_state;

	if (core_ctx->state == MFCINST_FREE)
		return 0;

	prev_state = core_ctx->state;
	mfc_change_state(core_ctx, MFCINST_RETURN_INST);
	mfc_change_op_mode(ctx, MFC_OP_SINGLE);
	core->sched->set_work(core, core_ctx);
	mfc_clean_core_ctx_int_flags(core_ctx);
	if (mfc_core_just_run(core, ctx->num)) {
		mfc_err("Failed to run MFC\n");
		mfc_change_state(core_ctx, prev_state);
		return -EIO;
	}

	/* Wait until instance is returned or timeout occured */
	if (mfc_wait_for_done_core_ctx(core_ctx,
				MFC_REG_R2H_CMD_CLOSE_INSTANCE_RET)) {
		mfc_err("Waiting for CLOSE_INSTANCE timed out\n");
		mfc_change_state(core_ctx, prev_state);
		return -EIO;
	}

	/* Free resources */
	mfc_release_instance_context(core_ctx);

	return 0;
}

int __mfc_core_instance_init(struct mfc_core *core, struct mfc_ctx *ctx)
{
	struct mfc_core_ctx *core_ctx = NULL;
	int ret = 0;
	enum mfc_fw_status fw_status;
	struct mfc_special_buf *fw_buf;

	if (core->state == MFCCORE_ERROR) {
		mfc_ctx_err("MFC-%d is ERROR state\n", core->id);
		return -EBUSY;
	}

	core->num_inst++;
	if (ctx->is_drm)
		core->num_drm_inst++;

	/* Allocate memory for core context */
	core_ctx = kzalloc(sizeof(*core_ctx), GFP_KERNEL);
	if (!core_ctx) {
		mfc_core_err("Not enough memory\n");
		ret = -ENOMEM;
		goto err_init_inst;
	}

	core_ctx->core = core;
	core_ctx->ctx = ctx;
	core_ctx->num = ctx->num;
	core_ctx->is_drm = ctx->is_drm;
	core_ctx->inst_no = MFC_NO_INSTANCE_SET;
	core->core_ctx[core_ctx->num] = core_ctx;

	init_waitqueue_head(&core_ctx->cmd_wq);
	mfc_core_init_listable_wq_ctx(core_ctx);
	spin_lock_init(&core_ctx->buf_queue_lock);
	core->sched->clear_work(core, core_ctx);
	INIT_LIST_HEAD(&core_ctx->qos_list);
	INIT_LIST_HEAD(&core_ctx->mb_list);

	mfc_create_queue(&core_ctx->src_buf_queue);

	if (core->num_inst == 1) {
		mfc_debug(2, "it is first instance in to core-%d\n", core->id);

		mfc_debug(2, "power on\n");
		ret = mfc_core_pm_power_on(core);
		if (ret) {
			mfc_err("Failed block power on, ret=%d\n", ret);
			goto err_power_on;
		}

		if (core->dev->debugfs.sched_type)
			mfc_sched_change_type(core);

		if (core->dev->debugfs.dbg_enable)
			mfc_alloc_dbg_info_buffer(core);
	}

	/* Load and verify the FW */
	if (ctx->is_drm) {
		fw_buf = &core->drm_fw_buf;
		fw_status = core->fw.drm_status;
	} else {
		fw_buf = &core->fw_buf;
		fw_status = core->fw.status;
	}

	if (!(fw_status & MFC_FW_LOADED)) {
		ret = mfc_request_load_firmware(core, fw_buf);
		if (ret)
			goto err_fw_load;
	}

#if !IS_ENABLED(CONFIG_EXYNOS_IMGLOADER)
#if IS_ENABLED(CONFIG_EXYNOS_S2MPU)
	if (!(fw_status & MFC_FW_VERIFIED)) {
		ret = __mfc_verify_fw(core, fw_buf);
		if (ret < 0)
			goto err_verify_fw;
	}
#endif
#endif

#if IS_ENABLED(CONFIG_EXYNOS_CONTENT_PATH_PROTECTION)
	if (ctx->is_drm && !(fw_status & MFC_FW_PROTECTED)) {
		ret = __mfc_core_prot_firmware(core);
		if (ret)
			goto err_fw_prot;
	}
#endif

	if (!(fw_status & MFC_FW_INITIALIZED)) {
		core->curr_core_ctx = ctx->num;
		core->preempt_core_ctx = MFC_NO_INSTANCE_SET;

		ret = mfc_core_run_init_hw(core, ctx->is_drm);
		if (ret)
			goto err_init_hw;
	}

	if (core->num_inst == 1)
		__mfc_core_init(core, ctx);

	return 0;

err_init_hw:
#if IS_ENABLED(CONFIG_EXYNOS_CONTENT_PATH_PROTECTION)
	if (ctx->is_drm)
		__mfc_core_unprot_firmware(core);

err_fw_prot:
#endif
#if !IS_ENABLED(CONFIG_EXYNOS_IMGLOADER)
#if IS_ENABLED(CONFIG_EXYNOS_S2MPU)
	mfc_release_verify_fw(core, fw_buf);

err_verify_fw:
#endif
#endif
#if IS_ENABLED(CONFIG_EXYNOS_IMGLOADER)
	if (!ctx->is_drm)
		imgloader_shutdown(&core->mfc_imgloader_desc);
	else
		imgloader_shutdown(&core->mfc_imgloader_desc_drm);
#endif
	mfc_core_change_fw_state(core, ctx->is_drm, MFC_FW_LOADED, 0);

err_fw_load:
	if (core->dev->debugfs.dbg_enable)
		mfc_release_dbg_info_buffer(core);
	if (core->num_inst == 1) {
		if (mfc_core_get_pwr_ref_cnt(core))
			mfc_core_pm_power_off(core);
	}
err_power_on:
	core->core_ctx[ctx->num] = 0;
	kfree(core->core_ctx[ctx->num]);

err_init_inst:
	core->num_inst--;
	if (ctx->is_drm)
		core->num_drm_inst--;

	return ret;
}

int mfc_core_instance_init(struct mfc_core *core, struct mfc_ctx *ctx)
{
	int ret = 0;

	mfc_core_debug_enter();

	ret = mfc_core_get_hwlock_dev(core);
	if (ret < 0) {
		mfc_core_err("Failed to get hwlock\n");
		mfc_core_err("dev.hwlock.dev = 0x%lx, bits = 0x%lx, owned_by_irq = %d, wl_count = %d, transfer_owner = %d\n",
				core->hwlock.dev, core->hwlock.bits, core->hwlock.owned_by_irq,
				core->hwlock.wl_count, core->hwlock.transfer_owner);
		return ret;
	}

	ret = __mfc_core_instance_init(core, ctx);
	if (ret)
		mfc_core_err("Failed to core instance init\n");

	mfc_core_release_hwlock_dev(core);

	mfc_core_debug_leave();

	return ret;
}

int mfc_core_instance_deinit(struct mfc_core *core, struct mfc_ctx *ctx)
{
	struct mfc_core_ctx *core_ctx = core->core_ctx[ctx->num];
	int ret = 0;

	if (!core_ctx) {
		mfc_core_err("There is no instance\n");
		return -EINVAL;
	}

	core->sched->clear_work(core, core_ctx);

	/* If a H/W operation is in progress, wait for it complete */
	if (need_to_wait_nal_abort(core_ctx)) {
		if (mfc_wait_for_done_core_ctx(core_ctx, MFC_REG_R2H_CMD_NAL_ABORT_RET)) {
			mfc_err("Failed to wait nal abort\n");
			core->sched->yield_work(core, core_ctx);
		}
	}

	ret = mfc_core_get_hwlock_ctx(core_ctx);
	if (ret < 0) {
		mfc_err("Failed to get hwlock\n");
		MFC_TRACE_CTX_LT("[ERR][Release] failed to get hwlock (shutdown: %d)\n", core->shutdown);
		return -EBUSY;
	}

	/* If instance was initialised then return instance and free reosurces */
	ret = __mfc_core_deinit(core, ctx);
	if (ret)
		goto err_release_try;

	mfc_release_metadata_buffer(ctx);
	mfc_release_codec_buffers(core_ctx);
	mfc_release_instance_context(core_ctx);

	mfc_core_release_hwlock_ctx(core_ctx);
	mfc_core_destroy_listable_wq_ctx(core_ctx);

	if (ctx->type == MFCINST_ENCODER)
		mfc_release_enc_roi_buffer(core_ctx);

	mfc_delete_queue(&core_ctx->src_buf_queue);

	core->core_ctx[core_ctx->num] = 0;
	kfree(core_ctx);

	mfc_perf_print(core);

	return 0;

err_release_try:
	mfc_core_release_hwlock_ctx(core_ctx);
	core->sched->yield_work(core, core_ctx);
	return ret;
}

static int __mfc_core_instance_open_dec(struct mfc_ctx *ctx,
				struct mfc_core_ctx *core_ctx)
{
	struct mfc_core *core = core_ctx->core;
	struct mfc_dev *dev = core->dev;
	struct mfc_dec *dec = ctx->dec_priv;
	int ret = 0;

	/* In case of calling s_fmt twice or more */
	ret = __mfc_force_close_inst(core, ctx);
	if (ret) {
		mfc_err("Failed to close already opening instance\n");
		mfc_core_release_hwlock_ctx(core_ctx);
		core->sched->yield_work(core, core_ctx);
		return -EIO;
	}

	ret = mfc_alloc_instance_context(core_ctx);
	if (ret) {
		mfc_err("Failed to allocate dec instance[%d] buffers\n",
				ctx->num);
		mfc_core_release_hwlock_ctx(core_ctx);
		return -ENOMEM;
	}

	if (MFC_FEATURE_SUPPORT(dev, dev->pdata->metadata_interface)) {
		ret = mfc_alloc_metadata_buffer(ctx);
		if (ret) {
			mfc_err("Failed to allocate metadata buffer\n");
			ret = 0;
		}
	}

	/* sh_handle: HDR10+ (HEVC or AV1) SEI meta */
	if ((IS_HEVC_DEC(ctx) || IS_AV1_DEC(ctx))) {
		if (MFC_FEATURE_SUPPORT(dev, dev->pdata->hdr10_plus_full) && dec->sh_handle_hdr.vaddr) {
			dec->hdr10_plus_full = vmalloc(dec->sh_handle_hdr.data_size);
			if (!dec->hdr10_plus_full)
				mfc_err("failed to allocate hdr10 plus full information data");
		} else if (dec->sh_handle_hdr.vaddr) {
			dec->hdr10_plus_info = vmalloc(dec->sh_handle_hdr.data_size);
			if (!dec->hdr10_plus_info)
				mfc_err("failed to allocate hdr10 plus information data");
		}
	}

	/* sh_handle: AV1 Film Grain SEI meta */
	if (MFC_FEATURE_SUPPORT(dev, dev->pdata->av1_film_grain) &&
			IS_AV1_DEC(ctx)) {
		if (dec->sh_handle_av1_film_grain.vaddr) {
			dec->av1_film_grain_info = vmalloc(dec->sh_handle_av1_film_grain.data_size);
			if (!dec->av1_film_grain_info)
				mfc_err("failed to allocate AV1 film grain information data");
		}
	}

	return 0;
}

static int __mfc_core_instance_open_enc(struct mfc_ctx *ctx,
				struct mfc_core_ctx *core_ctx)
{
	int ret = 0;

	ret = mfc_alloc_instance_context(core_ctx);
	if (ret) {
		mfc_err("Failed to allocate enc instance[%d] buffers\n",
				core_ctx->num);
		mfc_core_release_hwlock_ctx(core_ctx);
		return -ENOMEM;
	}

	ctx->capture_state = QUEUE_FREE;

	ret = mfc_alloc_enc_roi_buffer(core_ctx);
	if (ret) {
		mfc_err("[ROI] Failed to allocate ROI buffers\n");
		mfc_release_instance_context(core_ctx);
		mfc_core_release_hwlock_ctx(core_ctx);
		return -ENOMEM;
	}

	return 0;
}

int mfc_core_instance_open(struct mfc_core *core, struct mfc_ctx *ctx)
{
	struct mfc_core_ctx *core_ctx = core->core_ctx[ctx->num];
	int ret = 0;

	if (!core_ctx) {
		mfc_core_err("There is no instance\n");
		return -EINVAL;
	}

	ret = mfc_core_get_hwlock_ctx(core_ctx);
	if (ret < 0) {
		mfc_err("Failed to get hwlock\n");
		return ret;
	}

	if (ctx->type == MFCINST_DECODER) {
		if (__mfc_core_instance_open_dec(ctx, core_ctx))
			return -EAGAIN;
	} else if (ctx->type == MFCINST_ENCODER) {
		if (__mfc_core_instance_open_enc(ctx, core_ctx))
			return -EAGAIN;
	} else {
		mfc_err("invalid codec type: %d\n", ctx->type);
		return -EINVAL;
	}

	mfc_change_state(core_ctx, MFCINST_INIT);
	core->sched->set_work(core, core_ctx);
	ret = mfc_core_just_run(core, ctx->num);
	if (ret) {
		mfc_err("Failed to run MFC\n");
		goto err_open;
	}

	if (mfc_wait_for_done_core_ctx(core_ctx,
			MFC_REG_R2H_CMD_OPEN_INSTANCE_RET)) {
		mfc_err("failed to wait OPEN_INSTANCE\n");
		mfc_change_state(core_ctx, MFCINST_FREE);
		ret = -EIO;
		goto err_open;
	}

	mfc_core_release_hwlock_ctx(core_ctx);

	mfc_debug(2, "Got instance number inst_no: %d\n", core_ctx->inst_no);

	core->sched->enqueue_work(core, core_ctx);
	if (ctx->otf_handle)
		core->sched->enqueue_otf_work(core, core_ctx, true);
	if (core->sched->is_work(core))
		core->sched->queue_work(core);

	return ret;

err_open:
	mfc_core_release_hwlock_ctx(core_ctx);
	core->sched->yield_work(core, core_ctx);
	mfc_release_instance_context(core_ctx);
	if (ctx->type == MFCINST_ENCODER)
		mfc_release_enc_roi_buffer(core_ctx);

	return ret;
}

void mfc_core_instance_cache_flush(struct mfc_core *core, struct mfc_ctx *ctx)
{
	int drm_switch = 0;

	if (core->state == MFCCORE_ERROR) {
		mfc_core_info("[MSR] Couldn't cache flush. It's Error state\n");
		return;
	}

	core->curr_core_ctx = ctx->num;
	if (core->curr_core_ctx_is_drm != ctx->is_drm)
		drm_switch = 1;

	mfc_core_pm_clock_on(core, 0);
	mfc_core_run_cache_flush(core, ctx->is_drm,
			core->last_cmd_has_cache_flush ? MFC_NO_CACHEFLUSH : MFC_CACHEFLUSH,
			drm_switch, 0);
	mfc_core_pm_clock_off(core, 0);
}

int mfc_core_instance_move_to(struct mfc_core *core, struct mfc_ctx *ctx)
{
	int ret = 0;

	ret = __mfc_core_instance_init(core, ctx);
	if (ret) {
		mfc_core_err("Failed to core instance init\n");
		return ret;
	}

	if (core->num_inst > 1) {
		mfc_ctx_debug(2, "to core-%d already working, send cache_flush only\n", core->id);
		mfc_core_instance_cache_flush(core, ctx);
	}

	mfc_ctx_info("to core-%d is ready to move\n", core->id);

	return 0;
}

int mfc_core_instance_move_from(struct mfc_core *core, struct mfc_ctx *ctx)
{
	struct mfc_core_ctx *core_ctx = core->core_ctx[ctx->num];
	int ret = 0;
	int inst_no;

	mfc_clean_core_ctx_int_flags(core_ctx);
	core->sched->set_work(core, core_ctx);

	ret = mfc_core_just_run(core, ctx->num);
	if (ret) {
		mfc_err("Failed to run MFC\n");
		return ret;
	}

	if (mfc_wait_for_done_core_ctx(core_ctx, MFC_REG_R2H_CMD_MOVE_INSTANCE_RET)) {
		mfc_err("time out during move instance\n");
		core->logging_data->cause |= (1 << MFC_CAUSE_FAIL_MOVE_INST);
		call_dop(core, dump_and_stop_always, core);
		return -EFAULT;
	}
	inst_no = mfc_core_get_inst_no();

	ret = __mfc_core_deinit(core, ctx);
	if (ret) {
		mfc_err("Failed to close instance\n");
		return ret;
	}

	mfc_info("inst_no.%d will be changed to no.%d\n", core_ctx->inst_no, inst_no);
	core_ctx->inst_no = inst_no;

	return ret;
}

static void __mfc_core_cancel_drc(struct mfc_core *core, struct mfc_core_ctx *core_ctx)
{
	struct mfc_ctx *ctx = core_ctx->ctx;

	mfc_info("[DRC] DRC is running yet (state: %d) cancel DRC\n", core_ctx->state);

	mutex_lock(&ctx->drc_wait_mutex);

	ctx->wait_state &= ~(WAIT_STOP);
	mfc_debug(2, "clear WAIT_STOP %d\n", ctx->wait_state);
	MFC_TRACE_CORE_CTX("** DEC clear WAIT_STOP(wait_state %d)\n",
			ctx->wait_state);

	if (ctx->wait_state != WAIT_G_FMT) {
		ctx->wait_state = WAIT_G_FMT;
		mfc_debug(2, "set WAIT_G_FMT only for inform to user that needs g_fmt\n");
	}
	mutex_unlock(&ctx->drc_wait_mutex);
}

void mfc_core_instance_dpb_flush(struct mfc_core *core, struct mfc_ctx *ctx)
{
	struct mfc_dec *dec = ctx->dec_priv;
	struct mfc_core_ctx *core_ctx = core->core_ctx[ctx->num];
	int index = 0, i, ret;
	int prev_state;

	if ((core->state == MFCCORE_ERROR) || (core_ctx->state == MFCINST_ERROR))
		goto cleanup;

	ret = mfc_core_get_hwlock_ctx(core_ctx);
	if (ret < 0) {
		mfc_err("Failed to get hwlock\n");
		MFC_TRACE_CTX_LT("[ERR][Release] failed to get hwlock (shutdown: %d)\n",
				core->shutdown);
		if (core->shutdown)
			goto cleanup;
		return;
	}

	if (core_ctx->state == MFCINST_RES_CHANGE_INIT ||
			core_ctx->state == MFCINST_RES_CHANGE_FLUSH ||
			core_ctx->state == MFCINST_RES_CHANGE_FLUSH_FINISHED)
		__mfc_core_cancel_drc(core, core_ctx);

	mfc_cleanup_queue(&ctx->buf_queue_lock, &ctx->dst_buf_queue);
	mfc_cleanup_queue(&ctx->buf_queue_lock, &ctx->err_buf_queue);

	mutex_lock(&dec->dpb_mutex);
	for (i = 0; i < MFC_MAX_DPBS; i++)
		dec->dpb[i].queued = 0;
	mutex_unlock(&dec->dpb_mutex);

	dec->queued_dpb = 0;
	ctx->is_dpb_realloc = 0;
	dec->y_addr_for_pb = 0;
	dec->last_dpb_max_index = 0;

	if (!dec->inter_res_change) {
		dec->dpb_table_used = 0;
		dec->dynamic_used = 0;
		if (dec->is_dynamic_dpb) {
			mfc_cleanup_iovmm(ctx);
			dec->dynamic_set = 0;
			core_ctx->dynamic_set = 0;
		} else {
			dec->dynamic_set = MFC_ALL_AVAILABLE_DPB;
		}
	} else {
		mfc_cleanup_iovmm_except_used(ctx);
		mfc_print_dpb_table(ctx);
	}

	while (index < MFC_MAX_BUFFERS) {
		index = find_next_bit(ctx->dst_ctrls_avail, MFC_MAX_BUFFERS, index);
		if (index < MFC_MAX_BUFFERS)
			call_cop(ctx, reset_buf_ctrls, &ctx->dst_ctrls[index]);
		index++;
	}

	mutex_lock(&ctx->drc_wait_mutex);
	if (ctx->wait_state & WAIT_STOP) {
		ctx->wait_state &= ~(WAIT_STOP);
		mfc_debug(2, "clear WAIT_STOP %d\n", ctx->wait_state);
		MFC_TRACE_CORE_CTX("** DEC clear WAIT_STOP(wait_state %d)\n",
				ctx->wait_state);
	}
	mutex_unlock(&ctx->drc_wait_mutex);

	if (core_ctx->state == MFCINST_FINISHING)
		mfc_change_state(core_ctx, MFCINST_RUNNING);

	if (need_to_dpb_flush(core_ctx) && !ctx->dec_priv->inter_res_change) {
		prev_state = core_ctx->state;
		mfc_change_state(core_ctx, MFCINST_DPB_FLUSHING);
		core->sched->set_work(core, core_ctx);
		mfc_clean_core_ctx_int_flags(core_ctx);
		mfc_info("try to DPB flush\n");
		ret = mfc_core_just_run(core, ctx->num);
		if (ret) {
			mfc_err("Failed to run MFC\n");
			mfc_core_release_hwlock_ctx(core_ctx);
			core->sched->yield_work(core, core_ctx);
			return;
		}

		if (mfc_wait_for_done_core_ctx(core_ctx, MFC_REG_R2H_CMD_DPB_FLUSH_RET)) {
			mfc_err("time out during DPB flush\n");
			core->logging_data->cause |= (1 << MFC_CAUSE_FAIL_DPB_FLUSH);
			call_dop(core, dump_and_stop_always, core);
		}

		mfc_change_state(core_ctx, prev_state);
	}

	mfc_debug(2, "decoder destination stop sequence done\n");

	core->sched->clear_work(core, core_ctx);
	mfc_core_release_hwlock_ctx(core_ctx);

	core->sched->enqueue_work(core, core_ctx);
	if (core->sched->is_work(core))
		core->sched->queue_work(core);

	return;

cleanup:
	mfc_core_info("[MSR] Cleanup dst buffers. It's Error state\n");
	mfc_cleanup_queue(&ctx->buf_queue_lock, &ctx->dst_buf_queue);
	mfc_cleanup_queue(&ctx->buf_queue_lock, &ctx->err_buf_queue);
}

void mfc_core_instance_csd_parsing(struct mfc_core *core, struct mfc_ctx *ctx)
{
	struct mfc_dec *dec = ctx->dec_priv;
	struct mfc_core_ctx *core_ctx = core->core_ctx[ctx->num];
	struct mfc_buf *src_mb;
	int index = 0, csd, condition = 0, ret = 0;
	enum mfc_inst_state prev_state = MFCINST_FREE;

	if ((core->state == MFCCORE_ERROR) || (core_ctx->state == MFCINST_ERROR))
		goto cleanup;

	ret = mfc_core_get_hwlock_ctx(core_ctx);
	if (ret < 0) {
		mfc_err("Failed to get hwlock\n");
		MFC_TRACE_CTX_LT("[ERR][Release] failed to get hwlock (shutdown: %d)\n", core->shutdown);
		if (core->shutdown)
			goto cleanup;
		return;
	}

	if (core_ctx->state == MFCINST_RES_CHANGE_INIT ||
			core_ctx->state == MFCINST_RES_CHANGE_FLUSH ||
			core_ctx->state == MFCINST_RES_CHANGE_FLUSH_FINISHED)
		__mfc_core_cancel_drc(core, core_ctx);

	/* Header parsed buffer is in src_buf_ready_queue */
	mfc_move_buf_all(ctx, &core_ctx->src_buf_queue,
			&ctx->src_buf_ready_queue, MFC_QUEUE_ADD_BOTTOM);
	MFC_TRACE_CORE_CTX("CSD: Move all src to queue\n");

	while (1) {
		csd = mfc_check_buf_mb_flag(core_ctx, MFC_FLAG_CSD);
		if (csd == 1) {
			mfc_clean_core_ctx_int_flags(core_ctx);
			if (need_to_special_parsing(core_ctx)) {
				prev_state = core_ctx->state;
				mfc_change_state(core_ctx, MFCINST_SPECIAL_PARSING);
				condition = MFC_REG_R2H_CMD_SEQ_DONE_RET;
				mfc_info("try to special parsing! (before NAL_START)\n");
			} else if (need_to_special_parsing_nal(core_ctx)) {
				prev_state = core_ctx->state;
				mfc_change_state(core_ctx, MFCINST_SPECIAL_PARSING_NAL);
				condition = MFC_REG_R2H_CMD_FRAME_DONE_RET;
				mfc_info("try to special parsing! (after NAL_START)\n");
			} else {
				mfc_info("can't parsing CSD!, state = %d\n",
						core_ctx->state);
			}

			if (condition) {
				core->sched->set_work(core, core_ctx);

				ret = mfc_core_just_run(core, core_ctx->num);
				if (ret) {
					mfc_err("Failed to run MFC\n");
					mfc_change_state(core_ctx, prev_state);
				} else {
					if (mfc_wait_for_done_core_ctx(core_ctx, condition))
						mfc_err("special parsing time out\n");
				}
			}
		}

		src_mb = mfc_get_del_buf(ctx, &core_ctx->src_buf_queue,
				MFC_BUF_NO_TOUCH_USED);
		if (!src_mb)
			break;
		else
			MFC_TRACE_CORE_CTX("CSD: src[%d] DQ\n", src_mb->src_index);

		mfc_debug(2, "src index %d(%d) DQ\n", src_mb->vb.vb2_buf.index,
				src_mb->src_index);
		vb2_set_plane_payload(&src_mb->vb.vb2_buf, 0, 0);
		vb2_buffer_done(&src_mb->vb.vb2_buf, VB2_BUF_STATE_ERROR);
	}

	dec->consumed = 0;
	core_ctx->check_dump = 0;
	ctx->curr_src_index = -1;

	mutex_lock(&ctx->op_mode_mutex);
	ctx->serial_src_index = 0;
	mutex_unlock(&ctx->op_mode_mutex);

	if (!list_empty(&core_ctx->src_buf_queue.head)) {
		mfc_err("core_ctx->src_buf_queue is not empty\n");
		mfc_cleanup_queue(&ctx->buf_queue_lock,
				&core_ctx->src_buf_queue);
	}
	if (!list_empty(&ctx->src_buf_ready_queue.head)) {
		mfc_err("ctx->src_buf_ready_queue is not empty\n");
		mfc_cleanup_queue(&ctx->buf_queue_lock,
				&ctx->src_buf_ready_queue);
	}
	mfc_init_queue(&core_ctx->src_buf_queue);
	mfc_init_queue(&ctx->src_buf_ready_queue);

	if (core->dev->debugfs.meminfo_enable == 1)
		mfc_meminfo_cleanup_inbuf_q(ctx);

	while (index < MFC_MAX_BUFFERS) {
		index = find_next_bit(ctx->src_ctrls_avail, MFC_MAX_BUFFERS, index);
		if (index < MFC_MAX_BUFFERS)
			call_cop(ctx, reset_buf_ctrls, &ctx->src_ctrls[index]);
		index++;
	}

	if (core_ctx->state == MFCINST_FINISHING)
		mfc_change_state(core_ctx, MFCINST_RUNNING);

	mfc_debug(2, "decoder source stop sequence done\n");

	core->sched->clear_work(core, core_ctx);
	mfc_core_release_hwlock_ctx(core_ctx);

	core->sched->enqueue_work(core, core_ctx);
	if (core->sched->is_work(core))
		core->sched->queue_work(core);

	return;

cleanup:
	mfc_info("[MSR] Cleanup src buffers. It's Error state\n");
	mfc_cleanup_queue(&ctx->buf_queue_lock, &core_ctx->src_buf_queue);
	mfc_cleanup_queue(&ctx->buf_queue_lock, &ctx->src_buf_ready_queue);
}

int mfc_core_instance_init_buf(struct mfc_core *core, struct mfc_ctx *ctx)
{
	struct mfc_core_ctx *core_ctx = core->core_ctx[ctx->num];

	core->sched->set_work(core, core_ctx);
	mfc_clean_core_ctx_int_flags(core_ctx);
	if (mfc_core_just_run(core, ctx->num)) {
		mfc_err("Failed to run MFC\n");
		return -EIO;
	}

	if (mfc_wait_for_done_core_ctx(core_ctx, MFC_REG_R2H_CMD_INIT_BUFFERS_RET)) {
		mfc_err("[RM] init buffer timeout\n");
		return -EIO;
	}

	return 0;
}

void mfc_core_instance_q_flush(struct mfc_core *core, struct mfc_ctx *ctx)
{
	struct mfc_core_ctx *core_ctx = core->core_ctx[ctx->num];
	int index = 0;
	int ret = 0;

	/* If a H/W operation is in progress, wait for it complete */
	if (need_to_wait_nal_abort(core_ctx)) {
		if (mfc_wait_for_done_core_ctx(core_ctx, MFC_REG_R2H_CMD_NAL_ABORT_RET)) {
			mfc_err("time out during nal abort\n");
			core->sched->yield_work(core, core_ctx);
		}
	}

	ret = mfc_core_get_hwlock_ctx(core_ctx);
	if (ret < 0) {
		mfc_err("Failed to get hwlock\n");
		MFC_TRACE_CTX_LT("[ERR][Release] failed to get hwlock (shutdown: %d)\n", core->shutdown);
		return;
	}

	mfc_cleanup_queue(&ctx->buf_queue_lock, &ctx->dst_buf_queue);
	if (core->dev->debugfs.meminfo_enable == 1)
		mfc_meminfo_cleanup_outbuf_q(ctx);

	while (index < MFC_MAX_BUFFERS) {
		index = find_next_bit(ctx->dst_ctrls_avail, MFC_MAX_BUFFERS, index);
		if (index < MFC_MAX_BUFFERS)
			call_cop(ctx, reset_buf_ctrls, &ctx->dst_ctrls[index]);
		index++;
	}

	if (core_ctx->state == MFCINST_FINISHING)
		mfc_change_state(core_ctx, MFCINST_FINISHED);

	mfc_debug(2, "encoder destination stop sequence done\n");

	core->sched->clear_work(core, core_ctx);
	mfc_core_release_hwlock_ctx(core_ctx);

	core->sched->enqueue_work(core, core_ctx);
	if (core->sched->is_work(core))
		core->sched->queue_work(core);
}

void mfc_core_instance_finishing(struct mfc_core *core, struct mfc_ctx *ctx)
{
	struct mfc_core_ctx *core_ctx = core->core_ctx[ctx->num];
	int index = 0;
	int ret = 0;

	/* If a H/W operation is in progress, wait for it complete */
	if (need_to_wait_nal_abort(core_ctx)) {
		if (mfc_wait_for_done_core_ctx(core_ctx, MFC_REG_R2H_CMD_NAL_ABORT_RET)) {
			mfc_err("time out during nal abort\n");
			core->sched->yield_work(core, core_ctx);
		}
	}

	ret = mfc_core_get_hwlock_ctx(core_ctx);
	if (ret < 0) {
		mfc_err("Failed to get hwlock\n");
		MFC_TRACE_CTX_LT("[ERR][Release] failed to get hwlock (shutdown: %d)\n", core->shutdown);
		return;
	}

	if (core_ctx->state == MFCINST_RUNNING || core_ctx->state == MFCINST_FINISHING) {
		mfc_change_state(core_ctx, MFCINST_FINISHING);
		core->sched->set_work(core, core_ctx);

		while (core_ctx->state != MFCINST_FINISHED) {
			ret = mfc_core_just_run(core, ctx->num);
			if (ret) {
				mfc_err("Failed to run MFC\n");
				break;
			}
			if (mfc_wait_for_done_core_ctx(core_ctx,
					MFC_REG_R2H_CMD_FRAME_DONE_RET)) {
				mfc_err("Waiting for LAST_SEQ timed out\n");
				break;
			}
		}
	}

	ctx->serial_src_index = 0;
	mfc_move_buf_all(ctx, &core_ctx->src_buf_queue,
			&ctx->ref_buf_queue, MFC_QUEUE_ADD_BOTTOM);
	mfc_move_buf_all(ctx, &core_ctx->src_buf_queue,
			&ctx->src_buf_ready_queue, MFC_QUEUE_ADD_BOTTOM);
	mfc_cleanup_enc_src_queue(core_ctx);
	mfc_cleanup_queue(&ctx->buf_queue_lock, &ctx->err_buf_queue);
	if (core->dev->debugfs.meminfo_enable == 1)
		mfc_meminfo_cleanup_inbuf_q(ctx);

	while (index < MFC_MAX_BUFFERS) {
		index = find_next_bit(ctx->src_ctrls_avail, MFC_MAX_BUFFERS, index);
		if (index < MFC_MAX_BUFFERS)
			call_cop(ctx, reset_buf_ctrls, &ctx->src_ctrls[index]);
		index++;
	}

	if (core_ctx->state == MFCINST_FINISHING
			|| core_ctx->state == MFCINST_GOT_INST
			|| core_ctx->state == MFCINST_HEAD_PARSED) {
		mfc_debug(2, "%d status can continue encoding without CLOSE_INSTANCE\n",
				core_ctx->state);
		mfc_change_state(core_ctx, MFCINST_FINISHED);
	}

	mfc_debug(2, "encoder source stop sequence done\n");

	core->sched->clear_work(core, core_ctx);
	mfc_core_release_hwlock_ctx(core_ctx);

	core->sched->enqueue_work(core, core_ctx);
	if (core->sched->is_work(core))
		core->sched->queue_work(core);

}

int mfc_core_request_work(struct mfc_core *core, enum mfc_request_work work,
		struct mfc_ctx *ctx)
{
	switch (work) {
	case MFC_WORK_BUTLER:
		mfc_core_debug(3, "request_work: butler\n");
		if (core->sched->is_work(core))
			core->sched->queue_work(core);
		break;
	case MFC_WORK_TRY:
		mfc_core_debug(3, "request_work: try_run\n");
		mfc_core_try_run(core);
		break;
	default:
		mfc_core_err("not supported request work type: %#x\n", work);
		return -EINVAL;
	}

	return 0;
}

#if IS_ENABLED(CONFIG_EXYNOS_IMGLOADER)
int mfc_imgloader_mem_setup(struct imgloader_desc *desc, const u8 *fw_data, size_t fw_size,
	phys_addr_t *fw_phys_base, size_t *fw_bin_size, size_t *fw_mem_size)
{
	struct mfc_core *core = (struct mfc_core *)desc->dev->driver_data;
	struct mfc_special_buf *fw_buf;
	int ret = 0;

	mfc_core_debug_enter();

	if (strncmp(core->fw_buf.name, desc->name, MFC_NUM_SPECIAL_BUF_NAME) == 0) {
		fw_buf = &core->fw_buf;
	} else if (strncmp(core->drm_fw_buf.name, desc->name, MFC_NUM_SPECIAL_BUF_NAME) == 0) {
		fw_buf = &core->drm_fw_buf;
	} else {
		mfc_core_debug(2, "[F/W] desc name (%s) is wrong\n", desc->name);
		return -EINVAL;
	}

	ret = mfc_load_firmware(core, fw_buf, fw_data, fw_size);
	if (ret)
		return ret;

	*fw_phys_base = fw_buf->paddr;
	*fw_bin_size = fw_size;
	*fw_mem_size = fw_buf->size;

	mfc_core_debug_leave();

	return 0;
}

int mfc_imgloader_verify_fw(struct imgloader_desc *desc, phys_addr_t fw_phys_base,
	size_t fw_bin_size, size_t fw_mem_size)
{
	struct mfc_core *core = (struct mfc_core *)desc->dev->driver_data;
	struct mfc_special_buf *fw_buf;
	int ret = 0;

	mfc_core_debug_enter();

	if (!mfc_core_get_pwr_ref_cnt(core)) {
		mfc_core_debug(2, "power on\n");
		ret = mfc_core_pm_power_on(core);
		if (ret) {
			mfc_core_err("Failed block power on, ret=%d\n", ret);
			return ret;
		}
	}

	if (strncmp(core->fw_buf.name, desc->name, MFC_NUM_SPECIAL_BUF_NAME) == 0) {
		fw_buf = &core->fw_buf;
	} else if (strncmp(core->drm_fw_buf.name, desc->name, MFC_NUM_SPECIAL_BUF_NAME) == 0) {
		fw_buf = &core->drm_fw_buf;
	} else {
		mfc_core_debug(2, "[F/W] desc name (%s) is wrong\n", desc->name);
		return -EINVAL;
	}

#if IS_ENABLED(CONFIG_EXYNOS_S2MPU)
	ret = __mfc_verify_fw(core, fw_buf);
#endif
	if (ret)
		mfc_core_pm_power_off(core);

	mfc_core_debug_leave();

	return ret;
}

int mfc_imgloader_blk_pwron(struct imgloader_desc *desc)
{
	struct mfc_core *core = (struct mfc_core *)desc->dev->driver_data;
	int ret = 0;

	mfc_core_debug_enter();

	if (!mfc_core_get_pwr_ref_cnt(core)) {
		mfc_core_debug(2, "power on\n");
		ret = mfc_core_pm_power_on(core);
		if (ret) {
			mfc_core_err("Failed block power on, ret=%d\n", ret);
			return ret;
		}
	}

	mfc_core_debug_leave();

	return 0;
}

int mfc_imgloader_deinit_image(struct imgloader_desc *desc)
{
	struct mfc_core *core = (struct mfc_core *)desc->dev->driver_data;

	mfc_core_debug_enter();

	if (mfc_core_get_pwr_ref_cnt(core)) {
		mfc_core_debug(2, "power off\n");
		mfc_core_pm_power_off(core);
	}

	mfc_core_debug_leave();

	return 0;
}

int mfc_imgloader_shutdown(struct imgloader_desc *desc)
{
	struct mfc_core *core = (struct mfc_core *)desc->dev->driver_data;

	mfc_core_debug(2, "[F/W] release verify fw\n");

	if (strncmp(core->fw_buf.name, desc->name, MFC_NUM_SPECIAL_BUF_NAME) == 0)
		mfc_core_change_fw_state(core, 0, MFC_FW_VERIFIED, 0);
	else if (strncmp(core->drm_fw_buf.name, desc->name, MFC_NUM_SPECIAL_BUF_NAME) == 0)
		mfc_core_change_fw_state(core, 1, MFC_FW_VERIFIED, 0);
	else
		mfc_core_debug(2, "[F/W] desc name (%s) is wrong\n", desc->name);

	return 0;
}

struct imgloader_ops mfc_imgloader_ops = {
	.mem_setup = mfc_imgloader_mem_setup,
	.verify_fw = mfc_imgloader_verify_fw,
	.blk_pwron = mfc_imgloader_blk_pwron,
	.deinit_image = mfc_imgloader_deinit_image,
	.shutdown = mfc_imgloader_shutdown,
};

#else
#if IS_ENABLED(CONFIG_EXYNOS_S2MPU)
int mfc_release_verify_fw(struct mfc_core *core, struct mfc_special_buf *fw_buf)
{
	/* release the permission for fw region */
	exynos_s2mpu_release_fw_stage2_ap(fw_buf->name, 0);

	mfc_core_debug(2, "[F/W] release verify fw\n");
	if (strncmp(core->fw_buf.name, fw_buf->name, MFC_NUM_SPECIAL_BUF_NAME) == 0)
		mfc_core_change_fw_state(core, 0, MFC_FW_VERIFIED, 0);
	else
		mfc_core_change_fw_state(core, 1, MFC_FW_VERIFIED, 0);

	return 0;
}
#endif
#endif
