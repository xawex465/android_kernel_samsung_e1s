/*
 * drivers/media/platform/exynos/mfc/mfc_core_nal_q.c
 *
 * Copyright (c) 2020 Samsung Electronics Co., Ltd.
 *		http://www.samsung.com/
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include "mfc_rm.h"

#include "mfc_core_nal_q.h"
#include "mfc_core_pm.h"
#include "mfc_core_otf.h"
#include "mfc_core_sync.h"

#include "mfc_core_reg_api.h"
#include "mfc_core_hw_reg_api.h"

#include "base/mfc_sched.h"
#include "base/mfc_rate_calculate.h"
#include "base/mfc_qos.h"
#include "base/mfc_queue.h"
#include "base/mfc_mem.h"

#define CBR_I_LIMIT_MAX			5
int mfc_core_nal_q_check_enable(struct mfc_core *core)
{
	struct mfc_dev *dev = core->dev;
	struct mfc_ctx *ctx;
	struct mfc_core_ctx *core_ctx;
	struct mfc_dec *dec = NULL;
	struct mfc_enc *enc = NULL;
	struct mfc_enc_params *p = NULL;
	int i;

	mfc_core_debug_enter();

	if (dev->debugfs.nal_q_disable)
		return 0;

	for (i = 0; i < MFC_NUM_CONTEXTS; i++) {
		ctx = dev->ctx[i];
		core_ctx = core->core_ctx[i];
		if (core_ctx && ctx) {
			/* NAL-Q doesn't support 2 core mode */
			if (!IS_SINGLE_MODE(ctx)) {
				core->nal_q_stop_cause |= (1 << NALQ_STOP_2CORE);
				mfc_debug(2, "2 Core mode. Can't start NAL-Q\n");
				return 0;
			}
			/* NAL-Q doesn't support drm */
			if (ctx->is_drm) {
				core->nal_q_stop_cause |= (1 << NALQ_STOP_DRM);
				mfc_debug(2, "There is a drm ctx. Can't start NAL-Q\n");
				return 0;
			}
			/* NAL-Q can be enabled when all ctx are in running state */
			if (core_ctx->state != MFCINST_RUNNING) {
				core->nal_q_stop_cause |= (1 << NALQ_STOP_NO_RUNNING);
				mfc_debug(2, "There is a ctx which is not in running state. "
						"index: %d, state: %d\n", i, core_ctx->state);
				return 0;
			}
			/* NAL-Q can't use the command about last frame */
			if (mfc_check_buf_mb_flag(core_ctx, MFC_FLAG_LAST_FRAME) == 1) {
				core->nal_q_stop_cause |= (1 << NALQ_STOP_LAST_FRAME);
				mfc_debug(2, "There is a last frame. ctx: %d\n", i);
				return 0;
			}
			/* NAL-Q doesn't support OTF mode */
			if (ctx->otf_handle || ctx->gdc_votf) {
				core->nal_q_stop_cause |= (1 << NALQ_STOP_OTF);
				mfc_debug(2, "There is a OTF node\n");
				return 0;
			}
			/* NAL-Q doesn't support BPG */
			if (IS_BPG_DEC(ctx) || IS_BPG_ENC(ctx)) {
				core->nal_q_stop_cause |= (1 << NALQ_STOP_BPG);
				mfc_debug(2, "BPG codec type\n");
				return 0;
			}
			/* NAL-Q doesn't support multi-frame, interlaced, black bar */
			if (ctx->type == MFCINST_DECODER) {
				dec = ctx->dec_priv;
				if (!dec) {
					core->nal_q_stop_cause |= (1 << NALQ_STOP_NO_STRUCTURE);
					mfc_debug(2, "There is no dec\n");
					return 0;
				}
				if ((dec->has_multiframe && CODEC_MULTIFRAME(ctx)) || dec->consumed) {
					core->nal_q_stop_cause |= (1 << NALQ_STOP_MULTI_FRAME);
					mfc_debug(2, "[MULTIFRAME] There is a multi frame or consumed header\n");
					return 0;
				}
				if (dec->is_multiframe && ctx->plugin_type) {
					core->nal_q_stop_cause |= (1 << NALQ_STOP_MULTI_FRAME);
					mfc_debug(2, "[MULTIFRAME] There is a multi frame to the end\n");
					return 0;
				}
				if (dec->is_dpb_full) {
					core->nal_q_stop_cause |= (1 << NALQ_STOP_DPB_FULL);
					mfc_debug(2, "[DPB] All buffers are referenced\n");
					return 0;
				}
				if (dec->is_interlaced) {
					core->nal_q_stop_cause |= (1 << NALQ_STOP_INTERLACE);
					mfc_debug(2, "[INTERLACE] There is a interlaced stream\n");
					return 0;
				}
				if (dec->detect_black_bar ||
					(dev->debugfs.feature_option & MFC_OPTION_BLACK_BAR_ENABLE)) {
					core->nal_q_stop_cause |= (1 << NALQ_STOP_BLACK_BAR);
					mfc_debug(2, "[BLACKBAR] black bar detection is enabled\n");
					return 0;
				}
				if (dec->inter_res_change) {
					core->nal_q_stop_cause |= (1 << NALQ_STOP_INTER_DRC);
					mfc_debug(2, "[DRC] interframe resolution is changed\n");
					return 0;
				}
			/* NAL-Q doesn't support fixed byte(slice mode), CBR_VT(rc mode) */
			} else if (ctx->type == MFCINST_ENCODER) {
				enc = ctx->enc_priv;
				if (!enc) {
					core->nal_q_stop_cause |= (1 << NALQ_STOP_NO_STRUCTURE);
					mfc_debug(2, "There is no enc\n");
					return 0;
				}
				if (enc->slice_mode == V4L2_MPEG_VIDEO_MULTI_SLICE_MODE_MAX_FIXED_BYTES) {
					core->nal_q_stop_cause |= (1 << NALQ_STOP_SLICE_MODE);
					mfc_debug(2, "There is fixed bytes option(slice mode)\n");
					return 0;
				}
				p = &enc->params;
				if (p->rc_reaction_coeff <= CBR_I_LIMIT_MAX) {
					core->nal_q_stop_cause |= (1 << NALQ_STOP_RC_MODE);
					mfc_debug(2, "There is CBR_VT option(rc mode)\n");
					return 0;
				}
			}
			mfc_debug(2, "There is a ctx in running state. index: %d\n", i);
		}
	}

	mfc_core_debug(2, "All working ctx are in running state!\n");

	mfc_core_debug_leave();

	return 1;
}

void mfc_core_nal_q_clock_on(struct mfc_core *core, nal_queue_handle *nal_q_handle)
{
	unsigned long flags;
	int clk_on = 0;

	mfc_core_debug_enter();

	spin_lock_irqsave(&nal_q_handle->lock, flags);

	mfc_core_debug(2, "[NALQ] continue_clock_on = %d, nal_q_clk_cnt = %d\n",
			core->continue_clock_on, nal_q_handle->nal_q_clk_cnt);

	if (!core->continue_clock_on && !nal_q_handle->nal_q_clk_cnt) {
		mfc_core_pm_clock_on(core, 0);
		clk_on = 1;
	}

	nal_q_handle->nal_q_clk_cnt++;
	core->continue_clock_on = false;

	mfc_core_debug(2, "[NALQ] nal_q_clk_cnt = %d\n", nal_q_handle->nal_q_clk_cnt);

	spin_unlock_irqrestore(&nal_q_handle->lock, flags);

	if (clk_on && (atomic_read(&core->clk_ref) == 1))
		mfc_qos_update(core, 1);

	mfc_core_debug_leave();
}

void mfc_core_nal_q_clock_off(struct mfc_core *core, nal_queue_handle *nal_q_handle)
{
	unsigned long flags;
	int clk_off = 0;

	mfc_core_debug_enter();

	spin_lock_irqsave(&nal_q_handle->lock, flags);

	mfc_core_debug(2, "[NALQ] nal_q_clk_cnt = %d\n", nal_q_handle->nal_q_clk_cnt);

	if (!nal_q_handle->nal_q_clk_cnt) {
		spin_unlock_irqrestore(&nal_q_handle->lock, flags);
		mfc_core_err("[NALQ] nal_q_clk_cnt is already zero\n");
		return;
	}

	nal_q_handle->nal_q_clk_cnt--;

	if (!nal_q_handle->nal_q_clk_cnt) {
		mfc_core_wait_bus(core);
		mfc_core_pm_clock_off(core, 0);
		clk_off = 1;
	}

	mfc_core_debug(2, "[NALQ] nal_q_clk_cnt = %d\n", nal_q_handle->nal_q_clk_cnt);

	spin_unlock_irqrestore(&nal_q_handle->lock, flags);

	if (clk_off && (atomic_read(&core->clk_ref) == 0))
		mfc_qos_update(core, 0);

	mfc_core_debug_leave();
}

void mfc_core_nal_q_cleanup_clock(struct mfc_core *core)
{
	unsigned long flags;

	mfc_core_debug_enter();

	spin_lock_irqsave(&core->nal_q_handle->lock, flags);

	core->nal_q_handle->nal_q_clk_cnt = 0;

	spin_unlock_irqrestore(&core->nal_q_handle->lock, flags);

	mfc_core_debug_leave();
}

static int __mfc_core_nal_q_find_ctx(struct mfc_core *core, EncoderOutputStr *pOutputStr)
{
	struct mfc_dev *dev = core->dev;
	struct mfc_core_ctx *core_ctx = NULL;
	int i;

	mfc_core_debug_enter();

	for (i = 0; i < MFC_NUM_CONTEXTS; i++) {
		core_ctx = core->core_ctx[i];
		if (core_ctx) {
			mfc_debug(4, "core_ctx[%d] inst_no: %d\n", i,
					core_ctx->inst_no);
			if (dev->ctx[i] && (core_ctx->inst_no == pOutputStr->InstanceId))
				return i;
		}
	}

	mfc_core_debug_leave();

	return -1;
}

static nal_queue_in_handle* __mfc_core_nal_q_create_in_q(struct mfc_core *core,
		nal_queue_handle *nal_q_handle)
{
	nal_queue_in_handle *nal_q_in_handle;

	mfc_core_debug_enter();

	nal_q_in_handle = kzalloc(sizeof(*nal_q_in_handle), GFP_KERNEL);
	if (!nal_q_in_handle) {
		mfc_core_err("[NALQ] Failed to get memory for nal_queue_in_handle\n");
		return NULL;
	}

	nal_q_in_handle->nal_q_handle = nal_q_handle;
	nal_q_in_handle->in_buf.buftype = MFCBUF_NORMAL;
	/*
	 * Total nal_q buf size = entry size * num slot * max instance
	 * ex) entry size is 768 byte
	 *     768 byte * 4 slot * 32 instance = 96KB
	 * Plus 1 is needed for margin, because F/W exceeds sometimes.
	 */
	nal_q_in_handle->in_buf.size = core->dev->pdata->nal_q_entry_size * (NAL_Q_QUEUE_SIZE + 1);
	snprintf(nal_q_in_handle->in_buf.name, MFC_NUM_SPECIAL_BUF_NAME,
			"MFC%d NAL_Q in", core->id);
	if (mfc_mem_special_buf_alloc(core->dev, &nal_q_in_handle->in_buf)) {
		mfc_core_err("[NALQ] failed to get memory\n");
		kfree(nal_q_in_handle);
		return NULL;
	}

	if (mfc_iova_pool_alloc(core->dev, &nal_q_in_handle->in_buf)) {
		mfc_core_err("[NALQ][POOL] failed to get iova\n");
		mfc_mem_special_buf_free(core->dev, &nal_q_in_handle->in_buf);
		kfree(nal_q_in_handle);
		return NULL;
	}

	nal_q_in_handle->nal_q_in_addr = nal_q_in_handle->in_buf.vaddr;

	mfc_core_debug_leave();

	return nal_q_in_handle;
}

static nal_queue_out_handle* __mfc_core_nal_q_create_out_q(struct mfc_core *core,
		nal_queue_handle *nal_q_handle)
{
	nal_queue_out_handle *nal_q_out_handle;

	mfc_core_debug_enter();

	nal_q_out_handle = kzalloc(sizeof(*nal_q_out_handle), GFP_KERNEL);
	if (!nal_q_out_handle) {
		mfc_core_err("[NALQ] failed to get memory for nal_queue_out_handle\n");
		return NULL;
	}

	nal_q_out_handle->nal_q_handle = nal_q_handle;
	nal_q_out_handle->out_buf.buftype = MFCBUF_NORMAL;
	/*
	 * Total nal_q buf size = entry size * num slot * max instance
	 * ex) entry size is 768 byte
	 *     768 byte * 4 slot * 32 instance = 96KB
	 * Plus 1 is needed for margin, because F/W exceeds sometimes.
	 */
	nal_q_out_handle->out_buf.size = core->dev->pdata->nal_q_entry_size * (NAL_Q_QUEUE_SIZE + 1);
	snprintf(nal_q_out_handle->out_buf.name, MFC_NUM_SPECIAL_BUF_NAME,
			"MFC%d NAL_Q out", core->id);
	if (mfc_mem_special_buf_alloc(core->dev, &nal_q_out_handle->out_buf)) {
		mfc_core_err("[NALQ] failed to get memory\n");
		kfree(nal_q_out_handle);
		return NULL;
	}

	if (mfc_iova_pool_alloc(core->dev, &nal_q_out_handle->out_buf)) {
		mfc_core_err("[NALQ][POOL] failed to get iova\n");
		mfc_mem_special_buf_free(core->dev, &nal_q_out_handle->out_buf);
		kfree(nal_q_out_handle);
		return NULL;
	}

	nal_q_out_handle->nal_q_out_addr = nal_q_out_handle->out_buf.vaddr;

	mfc_core_debug_leave();

	return nal_q_out_handle;
}

static void __mfc_core_nal_q_destroy_in_q(struct mfc_core *core,
			nal_queue_in_handle *nal_q_in_handle)
{
	mfc_core_debug_enter();

	mfc_iova_pool_free(core->dev, &nal_q_in_handle->in_buf);

	if (nal_q_in_handle) {
		mfc_mem_special_buf_free(core->dev, &nal_q_in_handle->in_buf);
		kfree(nal_q_in_handle);
	}

	mfc_core_debug_leave();
}

static void __mfc_core_nal_q_destroy_out_q(struct mfc_core *core,
			nal_queue_out_handle *nal_q_out_handle)
{
	mfc_core_debug_enter();

	mfc_iova_pool_free(core->dev, &nal_q_out_handle->out_buf);

	if (nal_q_out_handle) {
		mfc_mem_special_buf_free(core->dev, &nal_q_out_handle->out_buf);
		kfree(nal_q_out_handle);
	}

	mfc_core_debug_leave();
}

/*
 * This function should be called after mfc_alloc_firmware() being called.
 */
nal_queue_handle *mfc_core_nal_q_create(struct mfc_core *core)
{
	nal_queue_handle *nal_q_handle;

	mfc_core_debug_enter();

	nal_q_handle = kzalloc(sizeof(*nal_q_handle), GFP_KERNEL);
	if (!nal_q_handle) {
		mfc_core_err("[NALQ] no nal_q_handle\n");
		return NULL;
	}

	nal_q_handle->nal_q_in_handle = __mfc_core_nal_q_create_in_q(core, nal_q_handle);
	if (!nal_q_handle->nal_q_in_handle) {
		kfree(nal_q_handle);
		mfc_core_err("[NALQ] no nal_q_in_handle\n");
		return NULL;
	}

	nal_q_handle->nal_q_out_handle = __mfc_core_nal_q_create_out_q(core, nal_q_handle);
	if (!nal_q_handle->nal_q_out_handle) {
		__mfc_core_nal_q_destroy_in_q(core, nal_q_handle->nal_q_in_handle);
		kfree(nal_q_handle);
		mfc_core_err("[NALQ] no nal_q_out_handle\n");
		return NULL;
	}

	spin_lock_init(&nal_q_handle->lock);

	if ((core->sched_type == MFC_SCHED_PRIO) &&
			MFC_FEATURE_SUPPORT(core->dev, core->dev->pdata->nal_q_ll))
		nal_q_handle->nal_q_ll = 1;
	mfc_core_debug(2, "[NALQ][LL] LL mode is %s, sched type is %s, feature %d\n",
			nal_q_handle->nal_q_ll ? "enabled" : "disabled",
			(core->sched_type == MFC_SCHED_RR) ? "RR" : "PRIO",
			MFC_FEATURE_SUPPORT(core->dev, core->dev->pdata->nal_q_ll));

	nal_q_handle->nal_q_state = NAL_Q_STATE_CREATED;
	MFC_TRACE_CORE("** NAL Q state : %d\n", nal_q_handle->nal_q_state);
	mfc_core_debug(2, "[NALQ] handle created, state = %d\n", nal_q_handle->nal_q_state);

	mfc_core_debug_leave();

	return nal_q_handle;
}

void mfc_core_nal_q_destroy(struct mfc_core *core, nal_queue_handle *nal_q_handle)
{
	mfc_core_debug_enter();

	if (nal_q_handle->nal_q_out_handle)
		__mfc_core_nal_q_destroy_out_q(core, nal_q_handle->nal_q_out_handle);

	if (nal_q_handle->nal_q_in_handle)
		__mfc_core_nal_q_destroy_in_q(core, nal_q_handle->nal_q_in_handle);

	kfree(nal_q_handle);
	core->nal_q_handle = NULL;

	mfc_core_debug_leave();
}

void mfc_core_nal_q_init(struct mfc_core *core, nal_queue_handle *nal_q_handle)
{
	mfc_core_debug_enter();

	if (!nal_q_handle) {
		mfc_core_err("[NALQ] There is no nal_q_handle\n");
		return;
	}

	if ((nal_q_handle->nal_q_state != NAL_Q_STATE_CREATED)
		&& (nal_q_handle->nal_q_state != NAL_Q_STATE_STOPPED)) {
		mfc_core_err("[NALQ] State is wrong, state: %d\n", nal_q_handle->nal_q_state);
		return;
	}

	mfc_core_reset_nal_queue_registers(core);

	nal_q_handle->nal_q_in_handle->in_exe_count = 0;
	nal_q_handle->nal_q_out_handle->out_exe_count = 0;

	mfc_core_debug(2, "[NALQ] MFC_REG_NAL_QUEUE_INPUT_COUNT=%d\n",
		mfc_core_get_nal_q_input_count());
	mfc_core_debug(2, "[NALQ] MFC_REG_NAL_QUEUE_OUTPUT_COUNT=%d\n",
		mfc_core_get_nal_q_output_count());
	mfc_core_debug(2, "[NALQ] MFC_REG_NAL_QUEUE_INPUT_EXE_COUNT=%d\n",
		mfc_core_get_nal_q_input_exe_count());
	mfc_core_debug(2, "[NALQ] MFC_REG_NAL_QUEUE_INFO=%d\n",
		mfc_core_get_nal_q_info());

	nal_q_handle->nal_q_exception = 0;
	core->nal_q_stop_cause = 0;

	if (nal_q_handle->nal_q_ll) {
		/* index 0 is for HEAD and should not be used */
		nal_q_handle->in_avail_slot[0] = ((~0UL) & ~(0x1));
		nal_q_handle->in_avail_slot[1] = ~0UL;
	}

	mfc_core_debug_leave();

	return;
}

void mfc_core_nal_q_start(struct mfc_core *core, nal_queue_handle *nal_q_handle)
{
	EncoderInputStr *pStr;
	dma_addr_t addr;

	mfc_core_debug_enter();

	if (!nal_q_handle) {
		mfc_core_err("[NALQ] There is no nal_q_handle\n");
		return;
	}

	if (nal_q_handle->nal_q_state != NAL_Q_STATE_CREATED) {
		mfc_core_err("[NALQ] State is wrong, state: %d\n", nal_q_handle->nal_q_state);
		return;
	}

	addr = nal_q_handle->nal_q_in_handle->in_buf.daddr;

	mfc_core_update_nal_queue_input(core, addr, core->dev->pdata->nal_q_entry_size * NAL_Q_QUEUE_SIZE);

	mfc_core_debug(2, "[NALQ] MFC_REG_NAL_QUEUE_INPUT_ADDR=0x%x\n",
		mfc_core_get_nal_q_input_addr());
	mfc_core_debug(2, "[NALQ] MFC_REG_NAL_QUEUE_INPUT_SIZE=%d\n",
		mfc_core_get_nal_q_input_size());

	addr = nal_q_handle->nal_q_out_handle->out_buf.daddr;

	mfc_core_update_nal_queue_output(core, addr, core->dev->pdata->nal_q_entry_size * NAL_Q_QUEUE_SIZE);

	mfc_core_debug(2, "[NALQ] MFC_REG_NAL_QUEUE_OUTPUT_ADDR=0x%x\n",
		mfc_core_get_nal_q_output_addr());
	mfc_core_debug(2, "[NALQ] MFC_REG_NAL_QUEUE_OUTPUT_SIZE=%d\n",
		mfc_core_get_nal_q_output_ize());

	nal_q_handle->nal_q_state = NAL_Q_STATE_STARTED;
	MFC_TRACE_CORE("** NAL Q state : %d\n", nal_q_handle->nal_q_state);
	mfc_core_debug(2, "[NALQ] started, state = %d\n", nal_q_handle->nal_q_state);

	if (core->dev->debugfs.sfr_dump & MFC_DUMP_ALL_INFO)
		call_dop(core, dump_and_broadcast, core);

	if (nal_q_handle->nal_q_ll) {
		pStr = (EncoderInputStr *)(nal_q_handle->nal_q_in_handle->nal_q_in_addr);
		if (pStr->NextListIndex) {
			mfc_core_err("[NALQ][LL] The HEAD's nextListIndex is not cleared.\n");
			call_dop(core->dev, dump_and_stop_debug_mode, core->dev);
			pStr->NextListIndex = 0;
		}
		mfc_core_cmd_host2risc(core, MFC_REG_H2R_CMD_NAL_LL);
	} else {
		mfc_core_cmd_host2risc(core, MFC_REG_H2R_CMD_NAL_QUEUE);
	}

	mfc_core_debug_leave();

	return;
}

void mfc_core_nal_q_stop(struct mfc_core *core, nal_queue_handle *nal_q_handle)
{
	mfc_core_debug_enter();

	if (!nal_q_handle) {
		mfc_core_err("[NALQ] There is no nal_q_handle\n");
		return;
	}

	if (nal_q_handle->nal_q_state != NAL_Q_STATE_STARTED) {
		mfc_core_err("[NALQ] State is wrong, state: %d\n", nal_q_handle->nal_q_state);
		return;
	}

	mfc_core_nal_q_clock_on(core, nal_q_handle);

	if (mfc_core_wait_nal_q_status(core)) {
		mfc_core_err("[NALQ] Failed to wait status\n");
		call_dop(core, dump_and_stop_always, core);
	}

	nal_q_handle->nal_q_state = NAL_Q_STATE_STOPPED;
	MFC_TRACE_CORE("** NAL Q state : %d\n", nal_q_handle->nal_q_state);
	mfc_core_debug(2, "[NALQ] stopped, state = %d\n", nal_q_handle->nal_q_state);

	mfc_core_clean_dev_int_flags(core);

	mfc_core_cmd_host2risc(core, MFC_REG_H2R_CMD_STOP_QUEUE);

	mfc_core_debug_leave();

	return;
}

void mfc_core_nal_q_stop_if_started(struct mfc_core *core)
{
	nal_queue_handle *nal_q_handle;

	mfc_core_debug_enter();

	nal_q_handle = core->nal_q_handle;
	if (!nal_q_handle) {
		mfc_core_err("[NALQ] There is no nal_q_handle\n");
		return;
	}

	if (nal_q_handle->nal_q_state != NAL_Q_STATE_STARTED) {
		mfc_core_debug(3, "[NALQ] it is not running, state: %d\n",
				nal_q_handle->nal_q_state);
		return;
	}

	mfc_core_nal_q_stop(core, nal_q_handle);
	mfc_core_info("[NALQ] stop NAL QUEUE during get hwlock\n");
	if (mfc_wait_for_done_core(core,
				MFC_REG_R2H_CMD_COMPLETE_QUEUE_RET)) {
		mfc_core_err("[NALQ] Failed to stop qeueue during get hwlock\n");
		core->logging_data->cause |= (1 << MFC_CAUSE_FAIL_STOP_NAL_Q_FOR_OTHER);
		call_dop(core, dump_and_stop_debug_mode, core);
		nal_q_handle->nal_q_state = NAL_Q_STATE_CREATED;
		mfc_core_nal_q_cleanup_queue(core);
		mfc_core_nal_q_cleanup_clock(core);
	}

	mfc_core_debug_leave();
	return;
}

void mfc_core_nal_q_cleanup_queue(struct mfc_core *core)
{
	struct mfc_core_ctx *core_ctx;
	int i;

	mfc_core_debug_enter();

	for(i = 0; i < MFC_NUM_CONTEXTS; i++) {
		core_ctx = core->core_ctx[i];
		if (core_ctx) {
			mfc_cleanup_nal_queue(core_ctx);
			if (core->sched->enqueue_work(core, core_ctx))
				mfc_debug(2, "[NALQ] set work_bits after cleanup,"
						" ctx: %d\n", core_ctx->num);
		}
	}

	mfc_core_debug_leave();

	return;
}

static void __mfc_core_nal_q_set_slice_mode(struct mfc_ctx *ctx, EncoderInputStr *pInStr)
{
	struct mfc_enc *enc = ctx->enc_priv;

	/* multi-slice control */
	if (enc->slice_mode == V4L2_MPEG_VIDEO_MULTI_SLICE_MODE_MAX_BYTES)
		pInStr->MsliceMode = enc->slice_mode + 0x4;
	else if (enc->slice_mode == V4L2_MPEG_VIDEO_MULTI_SLICE_MODE_MAX_MB_ROW)
		pInStr->MsliceMode = enc->slice_mode - 0x2;
	else if (enc->slice_mode == V4L2_MPEG_VIDEO_MULTI_SLICE_MODE_MAX_FIXED_BYTES)
		pInStr->MsliceMode = enc->slice_mode + 0x3;
	else
		pInStr->MsliceMode = enc->slice_mode;

	/* multi-slice MB number or bit size */
	if ((enc->slice_mode == V4L2_MPEG_VIDEO_MULTI_SLICE_MODE_MAX_MB) ||
			(enc->slice_mode == V4L2_MPEG_VIDEO_MULTI_SLICE_MODE_MAX_MB_ROW)) {
		pInStr->MsliceSizeMb = enc->slice_size_mb;
	} else if ((enc->slice_mode == V4L2_MPEG_VIDEO_MULTI_SLICE_MODE_MAX_BYTES) ||
			(enc->slice_mode == V4L2_MPEG_VIDEO_MULTI_SLICE_MODE_MAX_FIXED_BYTES)){
		pInStr->MsliceSizeBits = enc->slice_size_bits;
	} else {
		pInStr->MsliceSizeMb = 0;
		pInStr->MsliceSizeBits = 0;
	}
}

static void __mfc_core_nal_q_set_enc_config_qp(struct mfc_ctx *ctx,
		EncoderInputStr *pInStr)
{
	struct mfc_enc *enc = ctx->enc_priv;
	struct mfc_enc_params *p = &enc->params;

	if (!p->rc_frame && !p->rc_mb && p->dynamic_qp) {
		pInStr->FixedPictureQp &= ~(0xFF000000);
		pInStr->FixedPictureQp |= (enc->config_qp & 0xFF) << 24;
		mfc_ctx_debug(6, "[NALQ][CTRLS] Dynamic QP changed %#x\n",
				pInStr->FixedPictureQp);
	}
}

static void __mfc_core_nal_q_set_enc_ts_delta(struct mfc_ctx *ctx, EncoderInputStr *pInStr)
{
	struct mfc_enc *enc = ctx->enc_priv;
	struct mfc_enc_params *p = &enc->params;
	int ts_delta;

	ts_delta = mfc_enc_get_ts_delta(ctx);

	pInStr->TimeStampDelta &= ~(0xFFFF);
	pInStr->TimeStampDelta |= (ts_delta & 0xFFFF);

	if (ctx->src_ts.ts_last_interval)
		mfc_ctx_debug(3, "[NALQ][DFR] fps %d -> %ld, delta: %d, reg: %#x\n",
				p->rc_framerate, USEC_PER_SEC / ctx->src_ts.ts_last_interval,
				ts_delta, pInStr->TimeStampDelta);
	else
		mfc_ctx_debug(3, "[NALQ][DFR] fps %d -> 0, delta: %d, reg: %#x\n",
				p->rc_framerate, ts_delta, pInStr->TimeStampDelta);
}

static void __mfc_core_nal_q_get_dec_metadata_sei_nal(struct mfc_core *core, struct mfc_ctx *ctx,
					DecoderOutputStr *pOutStr, unsigned int index)
{
	struct mfc_dec *dec = ctx->dec_priv;
	dma_addr_t buf_addr;
	dma_addr_t offset;
	unsigned int *sei_addr = NULL;
	unsigned int *addr;
	int buf_size, sei_size;

	addr = HDR10_PLUS_ADDR(dec->hdr10_plus_full, index);

	buf_addr = pOutStr->MetadataAddrSeiMb;
	buf_size = pOutStr->MetadataSizeSeiMb;
	if (!buf_addr) {
		mfc_ctx_err("[NALQ][META] The metadata address is NULL\n");
		return;
	}

	if (buf_addr < ctx->metadata_buf.daddr) {
		mfc_ctx_err("[NALQ][HDR+][META] The meta daddr %#llx is less than base %#llx\n",
				buf_addr, ctx->metadata_buf.daddr);
		return;
	}

	offset = buf_addr - ctx->metadata_buf.daddr;
	/* SEI data - 0x0: payload type, 0x4: payload size, 0x8: payload data */
	sei_addr = ctx->metadata_buf.vaddr + offset + MFC_META_SEI_NAL_SIZE_OFFSET;
	sei_size = *sei_addr;

	/* If there is other SEI data, need to use it for purpose */
	if (sei_size != (buf_size - MFC_META_SEI_NAL_PAYLOAD_OFFSET))
		mfc_ctx_err("[NALQ][HDR+][META] There is another SEI data (%d / %d)\n",
				sei_size, buf_size);

	/* HAL needs SEI data size info "size(4 bytes) + SEI data" */
	sei_size += MFC_META_SEI_NAL_SIZE_OFFSET;
	mfc_ctx_debug(2, "[NALQ][HDR+][META] copy metadata offset %#llx size: %d / %d\n",
			offset, sei_size, buf_size);

	memcpy(addr, sei_addr, sei_size);

	if (core->dev->debugfs.hdr_dump == 1) {
		mfc_ctx_err("[NALQ][HDR+][DUMP] F/W data (offset %#llx)....\n", offset);
		print_hex_dump(KERN_ERR, "", DUMP_PREFIX_OFFSET, 32, 4,
				(ctx->metadata_buf.vaddr + offset),
				buf_size, false);
		mfc_ctx_err("[NALQ][HDR+][DUMP] DRV data (idx %d)....\n", index);
		print_hex_dump(KERN_ERR, "", DUMP_PREFIX_OFFSET, 32, 4, addr,
				sei_size, false);
	}
}

static void __mfc_core_nal_q_get_hdr_plus_info(struct mfc_core *core, struct mfc_ctx *ctx,
			DecoderOutputStr *pOutStr, struct hdr10_plus_meta *sei_meta)
{
	struct mfc_dev *dev = ctx->dev;
	unsigned int upper_value, lower_value;
	int num_win, num_distribution;
	int i, j;

	if (dev->pdata->nal_q_entry_size < NAL_Q_ENTRY_SIZE_FOR_HDR10) {
		mfc_ctx_err("[NALQ][HDR+] insufficient NAL-Q entry size\n");
		return;
	}

	sei_meta->valid = 1;

	/* iru_t_t35 */
	sei_meta->t35_country_code = pOutStr->St2094_40sei[0] & 0xFF;
	sei_meta->t35_terminal_provider_code = pOutStr->St2094_40sei[0] >> 8 & 0xFF;
	upper_value = pOutStr->St2094_40sei[0] >> 24 & 0xFF;
	lower_value = pOutStr->St2094_40sei[1] & 0xFF;
	sei_meta->t35_terminal_provider_oriented_code = (upper_value << 8) | lower_value;

	/* application */
	sei_meta->application_identifier = pOutStr->St2094_40sei[1] >> 8 & 0xFF;
	sei_meta->application_version = pOutStr->St2094_40sei[1] >> 16 & 0xFF;

	/* window information */
	sei_meta->num_windows = pOutStr->St2094_40sei[1] >> 24 & 0x3;
	num_win = sei_meta->num_windows;
	if (num_win > dev->pdata->max_hdr_win) {
		mfc_ctx_err("NAL Q:[HDR+] num_window(%d) is exceeded supported max_num_window(%d)\n",
				num_win, dev->pdata->max_hdr_win);
		num_win = dev->pdata->max_hdr_win;
	}

	/* luminance */
	sei_meta->target_maximum_luminance = pOutStr->St2094_40sei[2] & 0x7FFFFFF;
	sei_meta->target_actual_peak_luminance_flag = pOutStr->St2094_40sei[2] >> 27 & 0x1;
	sei_meta->mastering_actual_peak_luminance_flag = pOutStr->St2094_40sei[22] >> 10 & 0x1;

	/* per window setting */
	for (i = 0; i < num_win; i++) {
		/* scl */
		for (j = 0; j < HDR_MAX_SCL; j++) {
			sei_meta->win_info[i].maxscl[j] =
				pOutStr->St2094_40sei[3 + j] & 0x1FFFF;
		}
		sei_meta->win_info[i].average_maxrgb =
			pOutStr->St2094_40sei[6] & 0x1FFFF;

		/* distribution */
		sei_meta->win_info[i].num_distribution_maxrgb_percentiles =
			pOutStr->St2094_40sei[6] >> 17 & 0xF;
		num_distribution = sei_meta->win_info[i].num_distribution_maxrgb_percentiles;
		for (j = 0; j < num_distribution; j++) {
			sei_meta->win_info[i].distribution_maxrgb_percentages[j] =
				pOutStr->St2094_40sei[7 + j] & 0x7F;
			sei_meta->win_info[i].distribution_maxrgb_percentiles[j] =
				pOutStr->St2094_40sei[7 + j] >> 7 & 0x1FFFF;
		}

		/* bright pixels */
		sei_meta->win_info[i].fraction_bright_pixels =
			pOutStr->St2094_40sei[22] & 0x3FF;

		/* tone mapping */
		sei_meta->win_info[i].tone_mapping_flag =
			pOutStr->St2094_40sei[22] >> 11 & 0x1;
		if (sei_meta->win_info[i].tone_mapping_flag) {
			sei_meta->win_info[i].knee_point_x =
				pOutStr->St2094_40sei[23] & 0xFFF;
			sei_meta->win_info[i].knee_point_y =
				pOutStr->St2094_40sei[23] >> 12 & 0xFFF;
			sei_meta->win_info[i].num_bezier_curve_anchors =
				pOutStr->St2094_40sei[23] >> 24 & 0xF;
			for (j = 0; j < HDR_MAX_BEZIER_CURVES / 3; j++) {
				sei_meta->win_info[i].bezier_curve_anchors[j * 3] =
					pOutStr->St2094_40sei[24 + j] & 0x3FF;
				sei_meta->win_info[i].bezier_curve_anchors[j * 3 + 1] =
					pOutStr->St2094_40sei[24 + j] >> 10 & 0x3FF;
				sei_meta->win_info[i].bezier_curve_anchors[j * 3 + 2] =
					pOutStr->St2094_40sei[24 + j] >> 20 & 0x3FF;
			}
		}

		/* color saturation */
		sei_meta->win_info[i].color_saturation_mapping_flag =
			pOutStr->St2094_40sei[29] & 0x1;
		if (sei_meta->win_info[i].color_saturation_mapping_flag)
			sei_meta->win_info[i].color_saturation_weight =
				pOutStr->St2094_40sei[29] >> 1 & 0x3F;
	}

	if (dev->debugfs.debug_level >= 5)
		mfc_core_print_hdr_plus_info(core, ctx, sei_meta);
}

static void __mfc_core_nal_q_set_hdr_plus_info(struct mfc_core *core, struct mfc_ctx *ctx,
			EncoderInputStr *pInStr, struct hdr10_plus_meta *sei_meta)
{
	struct mfc_dev *dev = ctx->dev;
	unsigned int val = 0;
	int num_win, num_distribution;
	int i, j;

	if (dev->pdata->nal_q_entry_size < NAL_Q_ENTRY_SIZE_FOR_HDR10) {
		mfc_ctx_err("[NALQ][HDR+] insufficient NAL-Q entry size\n");
		return;
	}

	pInStr->HevcNalControl &= ~(sei_meta->valid << 6);
	pInStr->HevcNalControl |= ((sei_meta->valid & 0x1) << 6);

	/* iru_t_t35 */
	val = 0;
	val |= (sei_meta->t35_country_code & 0xFF);
	val |= ((sei_meta->t35_terminal_provider_code & 0xFF) << 8);
	val |= (((sei_meta->t35_terminal_provider_oriented_code >> 8) & 0xFF) << 24);
	pInStr->St2094_40sei[0] = val;

	/* window information */
	num_win = (sei_meta->num_windows & 0x3);
	if (!num_win || (num_win > dev->pdata->max_hdr_win)) {
		mfc_ctx_debug(3, "NAL Q:[HDR+] num_window is only supported till %d\n",
				dev->pdata->max_hdr_win);
		num_win = dev->pdata->max_hdr_win;
		sei_meta->num_windows = num_win;
	}

	/* application */
	val = 0;
	val |= (sei_meta->t35_terminal_provider_oriented_code & 0xFF);
	val |= ((sei_meta->application_identifier & 0xFF) << 8);
	val |= ((sei_meta->application_version & 0xFF) << 16);
	val |= ((sei_meta->num_windows & 0x3) << 24);
	pInStr->St2094_40sei[1] = val;

	/* luminance */
	val = 0;
	val |= (sei_meta->target_maximum_luminance & 0x7FFFFFF);
	val |= ((sei_meta->target_actual_peak_luminance_flag & 0x1) << 27);
	pInStr->St2094_40sei[2] = val;

	/* per window setting */
	for (i = 0; i < num_win; i++) {
		/* scl */
		for (j = 0; j < HDR_MAX_SCL; j++)
			pInStr->St2094_40sei[3 + j] = (sei_meta->win_info[i].maxscl[j] & 0x1FFFF);

		/* distribution */
		val = 0;
		val |= (sei_meta->win_info[i].average_maxrgb & 0x1FFFF);
		val |= ((sei_meta->win_info[i].num_distribution_maxrgb_percentiles & 0xF) << 17);
		pInStr->St2094_40sei[6] = val;
		num_distribution = (sei_meta->win_info[i].num_distribution_maxrgb_percentiles & 0xF);
		for (j = 0; j < num_distribution; j++) {
			val = 0;
			val |= (sei_meta->win_info[i].distribution_maxrgb_percentages[j] & 0x7F);
			val |= ((sei_meta->win_info[i].distribution_maxrgb_percentiles[j] & 0x1FFFF) << 7);
			pInStr->St2094_40sei[7 + j] = val;
		}

		/* bright pixels, luminance */
		val = 0;
		val |= (sei_meta->win_info[i].fraction_bright_pixels & 0x3FF);
		val |= ((sei_meta->mastering_actual_peak_luminance_flag & 0x1) << 10);

		/* tone mapping */
		val |= ((sei_meta->win_info[i].tone_mapping_flag & 0x1) << 11);
		pInStr->St2094_40sei[22] = val;
		if (sei_meta->win_info[i].tone_mapping_flag & 0x1) {
			val = 0;
			val |= (sei_meta->win_info[i].knee_point_x & 0xFFF);
			val |= ((sei_meta->win_info[i].knee_point_y & 0xFFF) << 12);
			val |= ((sei_meta->win_info[i].num_bezier_curve_anchors & 0xF) << 24);
			pInStr->St2094_40sei[23] = val;
			for (j = 0; j < HDR_MAX_BEZIER_CURVES / 3; j++) {
				val = 0;
				val |= (sei_meta->win_info[i].bezier_curve_anchors[j * 3] & 0x3FF);
				val |= ((sei_meta->win_info[i].bezier_curve_anchors[j * 3 + 1] & 0x3FF) << 10);
				val |= ((sei_meta->win_info[i].bezier_curve_anchors[j * 3 + 2] & 0x3FF) << 20);
				pInStr->St2094_40sei[24 + j] = val;
			}

		}

		/* color saturation */
		if (sei_meta->win_info[i].color_saturation_mapping_flag & 0x1) {
			val = 0;
			val |= (sei_meta->win_info[i].color_saturation_mapping_flag & 0x1);
			val |= ((sei_meta->win_info[i].color_saturation_weight & 0x3F) << 1);
			pInStr->St2094_40sei[29] = val;
		}
	}

	if (dev->debugfs.debug_level >= 5)
		mfc_core_print_hdr_plus_info(core, ctx, sei_meta);
}

static void __mfc_core_nal_q_set_hdr10_plus_stat_info(struct mfc_core *core, struct mfc_ctx *ctx,
		EncoderInputStr *pInStr, unsigned int index)
{
	struct mfc_enc *enc = ctx->enc_priv;
	dma_addr_t stat_info_daddr, stat_info_buf_raw;

	if (enc->hdr10_plus_stat_gen) {
		pInStr->HevcNalControl &= ~(0x1 << 7);
		pInStr->HevcNalControl |= (0x1 << 7);

		stat_info_daddr = enc->hdr10_plus_stat_info_buf.daddr +
			(sizeof(struct hdr10_plus_stat_info) * index);

		stat_info_buf_raw = stat_info_daddr + offsetof(struct hdr10_plus_stat_info, stat_raw);

		pInStr->SourceStatAddr = MFC_NALQ_DMA_WRITEL(stat_info_buf_raw);
		mfc_ctx_debug(2, "[NALQ][MEMINFO][HDR+] stat info buf 0x%llx\n", stat_info_buf_raw);
	} else {
		pInStr->HevcNalControl &= ~(0x1 << 7);

		mfc_ctx_debug(3, "[HDR+] stat info gen is not enabled by user\n");
	}
}

/*
 *
 * pOutStr->FilmGrain[1] [15:8]  = POINT_Y_VALUE_0
 * pOutStr->FilmGrain[1] [23:16] = POINT_Y_VALUE_1
 * pOutStr->FilmGrain[1] [24:31] = POINT_Y_VALUE_2
 * pOutStr->FilmGrain[2] [7:0]   = POINT_Y_VALUE_3
 *
 * av1_bitmask_shift[] has L-shift value.
 *
 */
static void __get_nal_q_av1_point_value_info(struct mfc_core *core, struct mfc_ctx *ctx,
	DecoderOutputStr *pOutStr, unsigned char *sei_meta, int num, unsigned int start_addr)
{
	int i, j = start_addr;
	unsigned int reg = 0;

	mfc_ctx_debug(5, "[NALQ][FILMGR] GET point Value info START\n");
	reg = pOutStr->FilmGrain[j];
	mfc_ctx_debug(5, "[NALQ][FILMGR] GET point value addr: [%#x], val: %#x\n", j, reg);
	for (i = 1; i <= num; i++) {
		if ((i % 4) == 0) {
			j++;
			reg = pOutStr->FilmGrain[j];
			mfc_ctx_debug(5, "[NALQ][FILMGR] GET point value addr: [%#x], val: %#x\n",
				j, reg);
		}
		sei_meta[i - 1] = (reg >> av1_bitmask_shift[i]) & 0xFF;
	}
}

/*
 *
 * pOutStr->FilmGrain[5] [7:0]   = POINT_Y_SCALING_0
 * pOutStr->FilmGrain[5] [15:8]  = POINT_Y_SCALING_1
 * pOutStr->FilmGrain[5] [23:16] = POINT_Y_SCALING_2
 * pOutStr->FilmGrain[5] [24:31] = POINT_Y_SCALING_3
 * pOutStr->FilmGrain[6] [7:0]   = POINT_Y_SCALING_4
 *
 * av1_bitmask_shift[] has L-shift value.
 *
 */
static void __get_nal_q_av1_point_scaling_info(struct mfc_core *core, struct mfc_ctx *ctx,
	DecoderOutputStr *pOutStr, char *sei_meta, int num, unsigned int start_addr)
{
	int i, j = start_addr;
	unsigned int reg = 0;

	mfc_ctx_debug(5, "[NALQ][FILMGR] GET scaling Value info START\n");
	for (i = 0; i < num; i++) {
		if ((i % 4) == 0) {
			reg = pOutStr->FilmGrain[j];
			mfc_ctx_debug(5, "[NALQ][FILMGR] GET scaling value addr: [%#x], val: %#x\n",
				j, reg);
			j++;
		}
		sei_meta[i] = (reg >> av1_bitmask_shift[i]) & 0xFF;
	}
}

static void __get_nal_q_av1_coeffs_info(struct mfc_core *core, struct mfc_ctx *ctx,
	DecoderOutputStr *pOutStr, char *sei_meta, int num, unsigned int start_addr)
{
	int i, j, k = start_addr;
	unsigned int reg = 0;

	mfc_ctx_debug(5, "[NALQ][FILMGR] GET coeffs Value info START\n");
	for (i = 0; i < num; i++) {
		j = i % 4;
		if (j == 0) {
			reg = pOutStr->FilmGrain[k];
			mfc_ctx_debug(5, "[NALQ][FILMGR] GET coeffes value addr: [%#x], val: %#x\n",
				k, reg);
			k++;
		}
		sei_meta[i] = (reg >> av1_bitmask_shift[j]) & 0xFF;
	}
}

static void __mfc_core_nal_q_get_film_grain_info(struct mfc_core *core, struct mfc_ctx *ctx,
			DecoderOutputStr *pOutStr, struct av1_film_grain_meta *sei_meta)
{
	unsigned int reg = 0;

	/* from the DecoderOutputStr */
	reg = pOutStr->FilmGrain[0];
	mfc_ctx_debug(5, "[NALQ][FILMGR] D_FILM_GRAIN_[0], val: %#x\n", reg);
	sei_meta->apply_grain = reg & 0x1;
	sei_meta->grain_seed = (reg >> 1) & 0xFFFF;

	sei_meta->num_y_points = pOutStr->FilmGrain[1] & 0xF;
	mfc_ctx_debug(5, "[NALQ][FILMGR] D_FILM_GRAIN_[1], val: %#x\n", pOutStr->FilmGrain[1]);
	sei_meta->num_cb_points = pOutStr->FilmGrain[9] & 0xF;
	mfc_ctx_debug(5, "[NALQ][FILMGR] D_FILM_GRAIN_[9], val: %#x\n", pOutStr->FilmGrain[9]);
	sei_meta->num_cr_points = pOutStr->FilmGrain[15] & 0xF;
	mfc_ctx_debug(5, "[NALQ][FILMGR] D_FILM_GRAIN_[15], val: %#x\n", pOutStr->FilmGrain[15]);

	reg = pOutStr->FilmGrain[8];
	mfc_ctx_debug(5, "[NALQ][FILMGR] D_FILM_GRAIN_[8], val: %#x\n", reg);
	sei_meta->chroma_scaling_from_luma = (reg >> 16) & 0x1;

	reg = pOutStr->FilmGrain[21];
	mfc_ctx_debug(5, "[NALQ][FILMGR] D_FILM_GRAIN_[21], val: %#x\n", reg);
	sei_meta->grain_scaling_minus_8 = reg & 0x3;
	sei_meta->ar_coeff_lag = (reg >> 0x2) & 0x3;

	reg = pOutStr->FilmGrain[42];
	mfc_ctx_debug(5, "[NALQ][FILMGR] D_FILM_GRAIN_[42], val: %#x\n", reg);
	sei_meta->ar_coeff_shift_minus_6 = reg & 0x3;
	sei_meta->grain_scale_shift = (reg >> 2) & 0x3;
	sei_meta->cb_mult = (reg >> 4) & 0xFF;
	sei_meta->cb_luma_mult = (reg >> 12) & 0xFF;
	sei_meta->cb_offset = (reg >> 20) & 0x1FF;

	reg = pOutStr->FilmGrain[43];
	mfc_ctx_debug(5, "[NALQ][FILMGR] D_FILM_GRAIN_[43], val: %#x\n", reg);
	sei_meta->cr_mult = reg & 0xFF;
	sei_meta->cr_luma_mult = (reg >> 8) & 0xFF;
	sei_meta->cr_offset = (reg >> 16) & 0x1FF;
	sei_meta->overlap_flag = (reg >> 25) & 0x1;
	sei_meta->clip_to_restricted_range = (reg >> 26) & 0x1;
	sei_meta->mc_identity = (reg >> 27) & 0x1;

	__get_nal_q_av1_point_value_info(core, ctx, pOutStr,
		&sei_meta->point_y_value[0], AV1_FG_LUM_POS_SIZE, 1);
	__get_nal_q_av1_point_value_info(core, ctx, pOutStr,
		&sei_meta->point_cb_value[0], AV1_FG_CHR_POS_SIZE, 9);
	__get_nal_q_av1_point_value_info(core, ctx, pOutStr,
		&sei_meta->point_cr_value[0], AV1_FG_CHR_POS_SIZE, 15);

	__get_nal_q_av1_point_scaling_info(core, ctx, pOutStr,
		&sei_meta->point_y_scaling[0], AV1_FG_LUM_POS_SIZE, 5);
	__get_nal_q_av1_point_scaling_info(core, ctx, pOutStr,
		&sei_meta->point_cb_scaling[0], AV1_FG_CHR_POS_SIZE, 12);
	__get_nal_q_av1_point_scaling_info(core, ctx, pOutStr,
		&sei_meta->point_cr_scaling[0], AV1_FG_CHR_POS_SIZE, 18);

	__get_nal_q_av1_coeffs_info(core, ctx, pOutStr,
		&sei_meta->ar_coeffs_y_plus_128[0], AV1_FG_LUM_AR_COEF_SIZE, 22);
	__get_nal_q_av1_coeffs_info(core, ctx, pOutStr,
		&sei_meta->ar_coeffs_cb_plus_128[0], AV1_FG_CHR_AR_COEF_SIZE, 28);
	__get_nal_q_av1_coeffs_info(core, ctx, pOutStr,
		&sei_meta->ar_coeffs_cr_plus_128[0], AV1_FG_CHR_AR_COEF_SIZE, 35);

	if (core->dev->debugfs.debug_level >= 5)
		mfc_core_print_film_grain_info(core, ctx, sei_meta);
}

static void __mfc_core_nal_q_get_film_grain_raw(DecoderOutputStr *pOutStr, struct mfc_ctx *ctx,
		int index)
{
	struct mfc_dec *dec = ctx->dec_priv;
	int i;

	for (i = 0; i < 44; i++)
		dec->FilmGrain[index][i] = pOutStr->FilmGrain[i];

	if (ctx->dev->debugfs.debug_level >= 5)
		print_hex_dump(KERN_ERR, "[FILMGR get] ", DUMP_PREFIX_OFFSET, 32, 4,
				&pOutStr->FilmGrain[i], 0xB0, false);
}

static int __mfc_core_nal_q_run_in_buf_enc(struct mfc_core *core, struct mfc_core_ctx *core_ctx,
			EncoderInputStr *pInStr)
{
	struct mfc_ctx *ctx = core_ctx->ctx;
	struct mfc_dev *dev = ctx->dev;
	struct mfc_enc *enc = ctx->enc_priv;
	struct mfc_buf *src_mb, *dst_mb;
	struct mfc_raw_info *raw = NULL;
	struct hdr10_plus_meta dst_sei_meta, *src_sei_meta;
	dma_addr_t src_addr[3] = {0, 0, 0};
	dma_addr_t addr_2bit[2] = {0, 0};
	unsigned int index, i;
	int is_uncomp = 0;
	u32 timeout_value = MFC_TIMEOUT_VALUE;

	mfc_debug_enter();

	pInStr->StartCode = NAL_Q_ENCODER_MARKER;
	pInStr->CommandId = mfc_core_get_nal_q_input_count();
	pInStr->InstanceId = core_ctx->inst_no;

	raw = &ctx->raw_buf;

	if (IS_BUFFER_BATCH_MODE(ctx)) {
		src_mb = mfc_get_buf(ctx, &core_ctx->src_buf_queue, MFC_BUF_SET_USED);
		if (!src_mb) {
			mfc_err("[NALQ][BUFCON] no src buffers\n");
			return -EAGAIN;
		}

		/* last image in a buffer container */
		/* move src_queue -> src_queue_nal_q */
		if (src_mb->next_index == (src_mb->num_valid_bufs - 1)) {
			src_mb = mfc_get_move_buf(ctx, &ctx->src_buf_nal_queue, &core_ctx->src_buf_queue,
					MFC_BUF_SET_USED, MFC_QUEUE_ADD_BOTTOM);
			if (!src_mb) {
				mfc_err("[NALQ][BUFCON] no src buffers\n");
				return -EAGAIN;
			}
		}

		index = src_mb->vb.vb2_buf.index;
		for (i = 0; i < raw->num_planes; i++) {
			src_addr[i] = src_mb->addr[src_mb->next_index][i];
			mfc_debug(2, "[NALQ][BUFCON][BUFINFO] set src index: %d, batch[%d], addr[%d]: 0x%08llx\n",
					index, src_mb->next_index, i, src_addr[i]);
		}
		src_mb->next_index++;
	} else {
		/* move src_queue -> src_queue_nal_q */
		src_mb = mfc_get_move_buf(ctx, &ctx->src_buf_nal_queue, &core_ctx->src_buf_queue,
				MFC_BUF_SET_USED, MFC_QUEUE_ADD_BOTTOM);
		if (!src_mb) {
			mfc_err("[NALQ] no src buffers\n");
			return -EAGAIN;
		}

		index = src_mb->vb.vb2_buf.index;
		for (i = 0; i < raw->num_planes; i++) {
			src_addr[i] = src_mb->addr[0][i];
			mfc_debug(2, "[NALQ][BUFINFO] set src index: %d(%d), addr[%d]: 0x%08llx\n",
					index, src_mb->src_index, i, src_addr[i]);
		}
	}

	for (i = 0; i < raw->num_planes; i++)
		pInStr->FrameAddr[i] = MFC_NALQ_DMA_WRITEL(src_addr[i]);

	if (IS_2BIT_NEED(ctx)) {
		for (i = 0; i < raw->num_planes; i++) {
			addr_2bit[i] = src_addr[i] + raw->plane_size[i];
			pInStr->Frame2bitAddr[i] = MFC_NALQ_DMA_WRITEL(addr_2bit[i]);
			mfc_debug(2, "[NALQ][BUFINFO] ctx[%d] set src 2bit addr[%d]: 0x%08llx\n",
					ctx->num, i, addr_2bit[i]);
		}
	}

	/* Support per-frame SBWC change for encoder source */
	if (MFC_FEATURE_SUPPORT(dev, dev->pdata->sbwc_enc_src_ctrl)
			&& ctx->is_sbwc) {
		pInStr->ParamChange &= ~(0xf << 14);

		if (mfc_check_mb_flag(src_mb, MFC_FLAG_ENC_SRC_UNCOMP)) {
			mfc_debug(2, "[NALQ][SBWC] src is uncomp\n");
			is_uncomp = 1;
			pInStr->ParamChange |= (MFC_ENC_SRC_SBWC_OFF << 14);
		} else {
			is_uncomp = 0;
			pInStr->ParamChange |= (MFC_ENC_SRC_SBWC_ON << 14);
		}

		mfc_set_linear_stride_size(ctx, &ctx->raw_buf,
				(is_uncomp ? enc->uncomp_fmt : ctx->src_fmt));

		for (i = 0; i < raw->num_planes; i++) {
			pInStr->SourcePlaneStride[i] = raw->stride[i];
			mfc_debug(2, "[NALQ][FRAME] enc src plane[%d] stride: %d\n",
					i, raw->stride[i]);
			if (!is_uncomp) {
				pInStr->SourcePlane2BitStride[i] = raw->stride_2bits[i];
				mfc_debug(2, "[NALQ][FRAME] enc src plane[%d] 2bit stride: %d\n",
						i, raw->stride_2bits[i]);
			}
		}
	}

	/* Support per-frame vOTF change for encoder source */
	if (ctx->gdc_votf) {
		pInStr->ParamChange &= ~(0x3 << 18);

		if (mfc_check_mb_flag(src_mb, MFC_FLAG_ENC_SRC_VOTF)) {
			mfc_debug(2, "[NALQ][vOTF] Source(GDC) is vOTF\n");
			if (mfc_core_votf_run(ctx, &ctx->src_buf_nal_queue, src_mb->i_ino)) {
				src_mb = mfc_get_move_buf_ino(ctx, &core_ctx->src_buf_queue,
						&ctx->src_buf_nal_queue, src_mb->i_ino, MFC_QUEUE_ADD_TOP);
				if (src_mb)
					mfc_debug(4, "[NALQ][vOTF] src buf(inode: %lu) retry\n",
							src_mb->i_ino);
				return -EAGAIN;
			}
			pInStr->ParamChange |= (MFC_ENC_SRC_VOTF_ON << 18);
		} else {
			mfc_debug(3, "[NALQ][vOTF] Source(GDC) is not vOTF. OFF\n");
			pInStr->ParamChange |= (MFC_ENC_SRC_VOTF_OFF << 18);
		}
	}

	if (mfc_check_mb_flag(src_mb, MFC_FLAG_ENC_SRC_FAKE)) {
		enc->fake_src = 1;
		mfc_debug(2, "[NALQ] src is fake\n");
	}

	/* HDR10+ sei meta */
	index = src_mb->vb.vb2_buf.index;
	if (MFC_FEATURE_SUPPORT(dev, dev->pdata->hdr10_plus)) {
		if (enc->sh_handle_hdr.fd == -1) {
			mfc_debug(3, "[NALQ][HDR+] there is no handle for SEI meta\n");
		} else {
			src_sei_meta = (struct hdr10_plus_meta *)enc->sh_handle_hdr.vaddr + index;
			if (src_sei_meta->valid) {
				mfc_debug(3, "[NALQ][HDR+] there is valid SEI meta data in buf[%d]\n",
						index);
				memcpy(&dst_sei_meta, src_sei_meta, sizeof(struct hdr10_plus_meta));
				__mfc_core_nal_q_set_hdr_plus_info(core, ctx, pInStr, &dst_sei_meta);
			}
		}
	}

	/* move dst_queue -> dst_queue_nal_q */
	dst_mb = mfc_get_move_buf(ctx, &ctx->dst_buf_nal_queue, &ctx->dst_buf_queue,
			MFC_BUF_SET_USED, MFC_QUEUE_ADD_BOTTOM);
	if (!dst_mb) {
		mfc_err("[NALQ] no dst buffers\n");
		return -EAGAIN;
	}

	pInStr->StreamBufferAddr = MFC_NALQ_DMA_WRITEL(dst_mb->addr[0][0]);
	pInStr->StreamBufferSize = (unsigned int)vb2_plane_size(&dst_mb->vb.vb2_buf, 0);
	pInStr->StreamBufferSize = ALIGN(pInStr->StreamBufferSize,
						STREAM_BUF_ALIGN);

	if (call_bop(ctx, core_set_buf_ctrls_nal_q_enc, ctx, &ctx->src_ctrls[index], pInStr) < 0)
		mfc_err("[NALQ] failed in core_set_buf_ctrls_nal_q_enc\n");

	mfc_debug(2, "[NALQ][BUFINFO] set dst index: %d, addr: 0x%llx\n",
			dst_mb->vb.vb2_buf.index,
			MFC_NALQ_DMA_READL(pInStr->StreamBufferAddr));
	mfc_debug(2, "[NALQ] input queue, src_buf_queue -> src_buf_nal_queue, index:%d\n",
			src_mb->vb.vb2_buf.index);
	mfc_debug(2, "[NALQ] input queue, dst_buf_queue -> dst_buf_nal_queue, index:%d\n",
			dst_mb->vb.vb2_buf.index);

	__mfc_core_nal_q_set_slice_mode(ctx, pInStr);
	__mfc_core_nal_q_set_enc_config_qp(ctx, pInStr);
	__mfc_core_nal_q_set_enc_ts_delta(ctx, pInStr);

	/* HDR10+ statistic info */
	index = dst_mb->vb.vb2_buf.index;
	if (MFC_FEATURE_SUPPORT(dev, dev->pdata->hdr10_plus_stat_info)) {
		if (enc->sh_handle_hdr10_plus_stat.fd == -1)
			mfc_debug(3, "[HDR+] there is no handle for stat info\n");
		else
			__mfc_core_nal_q_set_hdr10_plus_stat_info(core, ctx, pInStr, index);
	}

	if (core->last_mfc_freq)
		timeout_value = (core->last_mfc_freq * MFC_TIMEOUT_VALUE_IN_MSEC);
	mfc_debug(2, "[NALQ] Last MFC Freq: %d, Timeout Value: %d\n",
			core->last_mfc_freq, timeout_value);
	MFC_CORE_WRITEL(timeout_value, MFC_REG_TIMEOUT_VALUE);

	mfc_debug_leave();

	return 0;
}

static int __mfc_core_nal_q_run_in_buf_dec(struct mfc_core *core, struct mfc_core_ctx *core_ctx,
			DecoderInputStr *pInStr)
{
	struct mfc_ctx *ctx = core_ctx->ctx;
	struct mfc_buf *src_mb, *dst_mb;
	struct mfc_dec *dec = ctx->dec_priv;
	struct mfc_raw_info *raw;
	dma_addr_t buf_addr;
	unsigned int strm_size, offset;
	struct vb2_buffer *vb;
	int src_index, dst_index;
	size_t need_cpb_buf_size = 0, buf_size = 0;
	int i;
	u32 timeout_value = MFC_TIMEOUT_VALUE;
	unsigned long dynamic_set;

	mfc_debug_enter();

	if (mfc_is_queue_count_same(&ctx->buf_queue_lock, &ctx->dst_buf_queue, 0)) {
		mfc_err("[NALQ] no dst buffers\n");
		return -EAGAIN;
	}

	if (mfc_is_queue_count_same(&ctx->buf_queue_lock, &core_ctx->src_buf_queue, 0)) {
		mfc_err("[NALQ] no src buffers\n");
		return -EAGAIN;
	}

	pInStr->StartCode = NAL_Q_DECODER_MARKER;
	pInStr->CommandId = mfc_core_get_nal_q_input_count();
	pInStr->InstanceId = core_ctx->inst_no;
	pInStr->NalStartOptions = 0;

	/* Control compressor */
	if (ctx->is_sbwc) {
		mfc_check_sbwc_per_frame(ctx);

		if (ctx->sbwc_disabled)
			pInStr->NalStartOptions |=
				(1 << MFC_REG_D_NAL_START_OPT_DIS_COMPRESSOR_SHIFT);
	}

	/* Try to use the non-referenced DPB on dst-queue */
	if (dec->is_dynamic_dpb) {
		dst_mb = mfc_search_move_dpb_nal_q(core_ctx);
		if (!dst_mb) {
			mfc_debug(2, "[NALQ][DPB] couldn't find dst buffers\n");
			return -EAGAIN;
		}
	} else {
		dst_mb = mfc_get_move_buf(ctx, &ctx->dst_buf_nal_queue, &ctx->dst_buf_queue,
				MFC_BUF_NO_TOUCH_USED, MFC_QUEUE_ADD_BOTTOM);
		if (!dst_mb) {
			mfc_err("[NALQ] no dst buffers\n");
			return -EAGAIN;
		}
	}

	/* move src_queue -> src_queue_nal_q */
	src_mb = mfc_get_move_buf(ctx, &ctx->src_buf_nal_queue, &core_ctx->src_buf_queue,
			MFC_BUF_SET_USED, MFC_QUEUE_ADD_BOTTOM);
	if (!src_mb) {
		mfc_err("[NALQ] no src buffers\n");
		return -EAGAIN;
	}

	/* src buffer setting */
	vb = &src_mb->vb.vb2_buf;
	src_index = vb->index;
	buf_addr = src_mb->addr[0][0];
	strm_size = mfc_dec_get_strm_size(ctx, src_mb);
	offset = mfc_dec_get_strm_offset(ctx, src_mb);
	if (core->dev->pdata->stream_buf_limit) {
		need_cpb_buf_size = ALIGN(strm_size + 511, STREAM_BUF_ALIGN);
		buf_size = src_mb->sg_size;
	} else {
		need_cpb_buf_size = strm_size;
		buf_size = vb->planes[0].dbuf->size;
	}

	if (buf_size < need_cpb_buf_size)
		mfc_info("[NALQ] Decrease buffer size: %zu(need) -> %zu(alloc)\n",
				need_cpb_buf_size, buf_size);

	mfc_debug(2, "[NALQ][BUFINFO] set src index: %d(%d), addr: 0x%08llx\n",
			src_index, src_mb->src_index, buf_addr);
	mfc_debug(2, "[NALQ][STREAM] strm_size, %#x,%d, offset %d, need_buf_size, %zu, buf_size, %zu\n",
			strm_size, strm_size, offset, need_cpb_buf_size, buf_size);

	if (strm_size == 0)
		mfc_info("[NALQ] stream size is 0\n");

	pInStr->StreamDataSize = strm_size;
	pInStr->CpbBufferAddr = MFC_NALQ_DMA_WRITEL(buf_addr);
	pInStr->CpbBufferSize = buf_size;
	pInStr->CpbBufferOffset = offset;
	ctx->last_src_addr = buf_addr;

	/* dst buffer setting */
	if (dec->is_dynamic_dpb) {
		raw = &ctx->raw_buf;
		dst_index = dst_mb->dpb_index;
		core_ctx->dynamic_set = 1UL << dst_index;
		dynamic_set = core_ctx->dynamic_set;

		for (i = 0; i < raw->num_planes; i++) {
			pInStr->FrameSize[i] = raw->plane_size[i];
			pInStr->FrameAddr[i] = MFC_NALQ_DMA_WRITEL(dst_mb->addr[0][i]);
			ctx->last_dst_addr[i] = dst_mb->addr[0][i];
			if (IS_2BIT_NEED(ctx))
				pInStr->Frame2BitSize[i] = raw->plane_size_2bits[i];
			mfc_debug(2, "[NALQ][BUFINFO][DPB] set dst index: [%d][%d], addr[%d]: 0x%08llx, fd: %d, size: %d\n",
					dst_mb->vb.vb2_buf.index, dst_mb->dpb_index,
					i, dst_mb->addr[0][i], dst_mb->vb.vb2_buf.planes[0].m.fd,
					pInStr->FrameSize[i]);
		}

		MFC_TRACE_CTX("Set dst[%d] fd: %d, %#llx / used %#lx\n",
				dst_index, dst_mb->vb.vb2_buf.planes[0].m.fd,
				dst_mb->addr[0][0], dec->dynamic_used);
	} else {
		raw = &ctx->internal_raw_buf;
		dynamic_set = dec->dynamic_set;
		for (i = 0; i < raw->num_planes; i++) {
			pInStr->FrameSize[i] = raw->plane_size[i];
			pInStr->FrameAddr[i] = 0;
			ctx->last_dst_addr[i] = 0;
		}
	}

	pInStr->ScratchBufAddr = MFC_NALQ_DMA_WRITEL(core_ctx->codec_buf.daddr);
	pInStr->ScratchBufSize = ctx->scratch_buf_size;

	if (call_bop(ctx, core_set_buf_ctrls_nal_q_dec, ctx,
				&ctx->src_ctrls[src_index], pInStr) < 0)
		mfc_err("[NALQ] failed in core_set_buf_ctrls_nal_q_dec\n");
	if (pInStr->PictureTag != ctx->stored_tag) {
		mfc_debug(2, "[NALQ] reused src's tag is different so update to %d\n",
				ctx->stored_tag);
		pInStr->PictureTag = ctx->stored_tag;
	}

	pInStr->DynamicDpbFlagUpper = mfc_get_upper(dynamic_set);
	pInStr->DynamicDpbFlagLower = mfc_get_lower(dynamic_set);

	/* use dynamic_set value to available dpb in NAL Q */
	pInStr->AvailableDpbFlagLower = mfc_get_lower(dynamic_set);
	pInStr->AvailableDpbFlagUpper = mfc_get_upper(dynamic_set);

	if (core->last_mfc_freq)
		timeout_value = (core->last_mfc_freq * MFC_TIMEOUT_VALUE_IN_MSEC);
	mfc_debug(2, "[NALQ] Last MFC Freq: %d, Timeout Value: %d\n",
			core->last_mfc_freq, timeout_value);
	MFC_CORE_WRITEL(timeout_value, MFC_REG_TIMEOUT_VALUE);

	mfc_debug_leave();

	return 0;
}

static void __mfc_core_nal_q_get_enc_frame_buffer(struct mfc_ctx *ctx,
		dma_addr_t addr[], int num_planes, EncoderOutputStr *pOutStr)
{
	unsigned long enc_recon_y_addr, enc_recon_c_addr;
	int i;

	for (i = 0; i < num_planes; i++)
		addr[i] = MFC_NALQ_DMA_READL(pOutStr->EncodedFrameAddr[i]);

	enc_recon_y_addr = MFC_NALQ_DMA_WRITEL(pOutStr->ReconLumaDpbAddr);
	enc_recon_c_addr = MFC_NALQ_DMA_WRITEL(pOutStr->ReconChromaDpbAddr);

	mfc_ctx_debug(2, "[NALQ][MEMINFO] recon y: 0x%08lx c: 0x%08lx\n",
			enc_recon_y_addr, enc_recon_c_addr);
}

static void __mfc_core_nal_q_handle_error_input(struct mfc_core *core, struct mfc_ctx *ctx,
		EncoderOutputStr *pOutStr)
{
	struct mfc_buf *mfc_buf = NULL;
	int index;

	while (1) {
		mfc_buf = mfc_get_del_buf(ctx, &ctx->err_buf_queue, MFC_BUF_NO_TOUCH_USED);
		if (!mfc_buf)
			break;

		index = mfc_buf->vb.vb2_buf.index;

		if (call_bop(ctx, core_get_buf_ctrls_nal_q_enc, ctx,
					&ctx->src_ctrls[index], pOutStr) < 0)
			mfc_ctx_err("[NALQ] failed in core_get_buf_ctrls_nal_q_enc\n");

		mfc_ctx_info("[NALQ] find src buf(fd: %d) in err_queue\n",
				mfc_buf->vb.vb2_buf.planes[0].m.fd);
		mfc_clear_mb_flag(mfc_buf);
		mfc_set_mb_flag(mfc_buf, MFC_FLAG_CONSUMED_ONLY);
		vb2_buffer_done(&mfc_buf->vb.vb2_buf, VB2_BUF_STATE_ERROR);
	}
}

static void __mfc_core_nal_q_handle_stream_copy_timestamp(struct mfc_ctx *ctx, struct mfc_buf *src_mb)
{
	struct mfc_enc *enc = ctx->enc_priv;
	struct mfc_enc_params *p = &enc->params;
	struct mfc_buf *dst_mb;
	u64 interval;
	u64 start_timestamp;
	u64 new_timestamp;

	start_timestamp = src_mb->vb.vb2_buf.timestamp;
	interval = NSEC_PER_SEC / p->rc_framerate;
	if (ctx->dev->debugfs.debug_ts == 1)
		mfc_ctx_info("[NALQ][BUFCON][TS] %dfps, start timestamp: %lld, base interval: %lld\n",
				p->rc_framerate, start_timestamp, interval);

	new_timestamp = start_timestamp + (interval * src_mb->done_index);
	if (ctx->dev->debugfs.debug_ts == 1)
		mfc_ctx_info("[NALQ][BUFCON][TS] new timestamp: %lld, interval: %lld\n",
				new_timestamp, interval * src_mb->done_index);

	/* Get the destination buffer */
	dst_mb = mfc_get_buf(ctx, &ctx->dst_buf_nal_queue, MFC_BUF_NO_TOUCH_USED);
	if (dst_mb)
		dst_mb->vb.vb2_buf.timestamp = new_timestamp;
}

static void __mfc_core_nal_q_handle_stream_hdr10_plus_stat_info(struct mfc_ctx *ctx,
		EncoderOutputStr *pOutStr, int index)
{
	struct mfc_enc *enc = ctx->enc_priv;
	unsigned int is_hdr10_plus_stat_info = 0;
	struct hdr10_plus_stat_info *stat_info;

	is_hdr10_plus_stat_info =
		(((pOutStr->Hdr10PlusInfo) >> MFC_REG_E_HDR10_PLUS_INFO_STAT_DONE_SHIFT)
					& MFC_REG_E_HDR10_PLUS_INFO_STAT_DONE_MASK);

	if (is_hdr10_plus_stat_info) {
		stat_info = ((struct hdr10_plus_stat_info *)
				enc->sh_handle_hdr10_plus_stat.vaddr + index);

		stat_info->hdr10_plus_stat_done = 1;
		stat_info->hdr10_plus_stat_sei_size =
			(((pOutStr->Hdr10PlusInfo) >> MFC_REG_E_HDR10_PLUS_INFO_SEI_SIZE_SHIFT)
						& MFC_REG_E_HDR10_PLUS_INFO_SEI_SIZE_MASK);
		stat_info->hdr10_plus_stat_offset =
			(((pOutStr->Hdr10PlusInfo) >> MFC_REG_E_HDR10_PLUS_INFO_OFFSET_SHIFT)
						& MFC_REG_E_HDR10_PLUS_INFO_OFFSET_MASK);

		mfc_ctx_debug(2, "[HDR+] stat info SEI size: %#x, SEI offset: %#x\n",
	                stat_info->hdr10_plus_stat_sei_size, stat_info->hdr10_plus_stat_offset);
	}
}

static void __mfc_core_nal_q_handle_stream_input(struct mfc_core_ctx *core_ctx,
			EncoderOutputStr *pOutStr, int consumed_only)
{
	struct mfc_ctx *ctx = core_ctx->ctx;
	struct mfc_buf *src_mb, *ref_mb;
	dma_addr_t enc_addr[3] = { 0, 0, 0 };
	struct mfc_raw_info *raw;
	struct mfc_enc *enc = ctx->enc_priv;
	int found_in_src_queue = 0;
	unsigned int i, index;

	raw = &ctx->raw_buf;

	__mfc_core_nal_q_get_enc_frame_buffer(ctx, &enc_addr[0], raw->num_planes, pOutStr);
	if (enc_addr[0] == 0) {
		mfc_debug(3, "[NALQ] no encoded src\n");

		if (enc->fake_src && mfc_is_enc_bframe(ctx)) {
			mfc_change_state(core_ctx, MFCINST_FINISHING);
			enc->fake_src = 0;
			mfc_debug(2, "[NALQ] clear fake_src and change to FINISHING\n");
		}

		goto move_buf;
	}

	for (i = 0; i < raw->num_planes; i++)
		mfc_debug(2, "[NALQ][BUFINFO] ctx[%d] get src addr[%d]: 0x%08llx\n",
				ctx->num, i, enc_addr[i]);

	if (IS_BUFFER_BATCH_MODE(ctx)) {
		src_mb = mfc_find_first_buf(ctx, &core_ctx->src_buf_queue, enc_addr[0]);
		if (src_mb) {
			found_in_src_queue = 1;

			__mfc_core_nal_q_handle_stream_copy_timestamp(ctx, src_mb);
			src_mb->done_index++;
			mfc_debug(4, "[NALQ][BUFCON] batch buf done_index: %d\n", src_mb->done_index);
		} else {
			src_mb = mfc_find_first_buf(ctx, &ctx->src_buf_nal_queue, enc_addr[0]);
			if (src_mb) {
				found_in_src_queue = 1;

				__mfc_core_nal_q_handle_stream_copy_timestamp(ctx, src_mb);
				src_mb->done_index++;
				mfc_debug(4, "[NALQ][BUFCON] batch buf done_index: %d\n", src_mb->done_index);

				/* last image in a buffer container */
				if (src_mb->done_index == src_mb->num_valid_bufs) {
					src_mb = mfc_find_del_buf(ctx, &ctx->src_buf_nal_queue, enc_addr[0]);
					if (src_mb) {
						for (i = 0; i < raw->num_planes; i++)
							mfc_bufcon_put_daddr(ctx, src_mb, i);
						vb2_buffer_done(&src_mb->vb.vb2_buf, VB2_BUF_STATE_DONE);
					}
				}
			}
		}
	} else {
		src_mb = mfc_find_del_buf(ctx, &ctx->src_buf_nal_queue, enc_addr[0]);
		if (src_mb) {
			mfc_debug(3, "[NALQ] find src buf in src_queue\n");
			found_in_src_queue = 1;
			index = src_mb->vb.vb2_buf.index;
			if (consumed_only) {
				mfc_clear_mb_flag(src_mb);
				mfc_set_mb_flag(src_mb, MFC_FLAG_CONSUMED_ONLY);
			}

			if (call_bop(ctx, core_recover_buf_ctrls_nal_q, ctx,
						&ctx->src_ctrls[index]) < 0)
				mfc_err("[NALQ] failed in core_recover_buf_ctrls_nal_q\n");

			if (call_bop(ctx, core_get_buf_ctrls_nal_q_enc, ctx,
						&ctx->src_ctrls[index], pOutStr) < 0)
				mfc_err("[NALQ] failed in core_get_buf_ctrls_nal_q_enc\n");

			vb2_buffer_done(&src_mb->vb.vb2_buf, VB2_BUF_STATE_DONE);
		} else {
			mfc_debug(3, "[NALQ] no src buf in src_queue\n");
			ref_mb = mfc_find_del_buf(ctx, &ctx->ref_buf_queue, enc_addr[0]);
			if (ref_mb) {
				index = ref_mb->vb.vb2_buf.index;
				if (consumed_only) {
					mfc_clear_mb_flag(ref_mb);
					mfc_set_mb_flag(ref_mb, MFC_FLAG_CONSUMED_ONLY);
				}

				if (call_bop(ctx, core_recover_buf_ctrls_nal_q, ctx,
							&ctx->src_ctrls[index]) < 0)
					mfc_err("[NALQ] failed in core_recover_buf_ctrls_nal_q\n");

				if (call_bop(ctx, core_get_buf_ctrls_nal_q_enc, ctx,
							&ctx->src_ctrls[index], pOutStr) < 0)
					mfc_err("[NALQ] failed in core_get_buf_ctrls_nal_q_enc\n");

				mfc_debug(3, "[NALQ] find src buf in ref_queue\n");
				vb2_buffer_done(&ref_mb->vb.vb2_buf, VB2_BUF_STATE_DONE);
			} else {
				mfc_err("[NALQ] couldn't find src buffer\n");
			}
		}
	}

move_buf:
	/* move enqueued src buffer: src nal queue -> ref queue */
	if (!found_in_src_queue) {
		src_mb = mfc_get_move_buf_used(ctx, &ctx->ref_buf_queue, &ctx->src_buf_nal_queue);
		if (!src_mb)
			mfc_err("[NALQ] no src buffers\n");

		mfc_debug(2, "[NALQ] enc src_buf_nal_queue(%d) -> ref_buf_queue(%d)\n",
				mfc_get_queue_count(&ctx->buf_queue_lock, &ctx->src_buf_nal_queue),
				mfc_get_queue_count(&ctx->buf_queue_lock, &ctx->ref_buf_queue));
	}
}

static void __mfc_core_nal_q_handle_stream_output(struct mfc_ctx *ctx, int slice_type,
				unsigned int strm_size, EncoderOutputStr *pOutStr)
{
	struct mfc_dev *dev = ctx->dev;
	struct mfc_buf *dst_mb;
	unsigned int index, idr_flag = 1;

	if (strm_size == 0) {
		mfc_ctx_debug(3, "[NALQ] no encoded dst (reuse)\n");
		dst_mb = mfc_get_move_buf(ctx, &ctx->dst_buf_queue, &ctx->dst_buf_nal_queue,
				MFC_BUF_RESET_USED, MFC_QUEUE_ADD_TOP);
		if (!dst_mb) {
			mfc_ctx_err("[NALQ] no dst buffers\n");
			return;
		}

		mfc_ctx_debug(2, "[NALQ] no output, dst_buf_nal_queue(%d) -> dst_buf_queue(%d) index:[%d][%d]\n",
				mfc_get_queue_count(&ctx->buf_queue_lock, &ctx->dst_buf_nal_queue),
				mfc_get_queue_count(&ctx->buf_queue_lock, &ctx->dst_buf_queue),
				dst_mb->vb.vb2_buf.index, dst_mb->dpb_index);
		return;
	}

	/* at least one more dest. buffers exist always  */
	dst_mb = mfc_get_del_buf(ctx, &ctx->dst_buf_nal_queue, MFC_BUF_NO_TOUCH_USED);
	if (!dst_mb) {
		mfc_ctx_err("[NALQ] no dst buffers\n");
		return;
	}

	mfc_ctx_debug(2, "[NALQ][BUFINFO] ctx[%d] get dst addr: 0x%08llx\n",
			ctx->num, dst_mb->addr[0][0]);

	if (MFC_FEATURE_SUPPORT(dev, dev->pdata->enc_idr_flag))
		idr_flag = ((pOutStr->NalDoneInfo >> MFC_REG_E_NAL_DONE_INFO_IDR_SHIFT)
				& MFC_REG_E_NAL_DONE_INFO_IDR_MASK);

	mfc_clear_mb_flag(dst_mb);
	dst_mb->vb.flags &= ~(V4L2_BUF_FLAG_KEYFRAME |
				V4L2_BUF_FLAG_PFRAME |
				V4L2_BUF_FLAG_BFRAME);

	switch (slice_type) {
	case MFC_REG_E_SLICE_TYPE_I:
		dst_mb->vb.flags |= V4L2_BUF_FLAG_KEYFRAME;
		if (!(CODEC_HAS_IDR(ctx) && !idr_flag)) {
			mfc_set_mb_flag(dst_mb, MFC_FLAG_SYNC_FRAME);
			mfc_ctx_debug(2, "[NALQ][STREAM] syncframe IDR\n");
		}
		break;
	case MFC_REG_E_SLICE_TYPE_P:
		dst_mb->vb.flags |= V4L2_BUF_FLAG_PFRAME;
		break;
	case MFC_REG_E_SLICE_TYPE_B:
		dst_mb->vb.flags |= V4L2_BUF_FLAG_BFRAME;
		break;
	default:
		dst_mb->vb.flags |= V4L2_BUF_FLAG_KEYFRAME;
		break;
	}
	mfc_ctx_debug(2, "[NALQ][STREAM] Slice type flag: %d\n", dst_mb->vb.flags);

	vb2_set_plane_payload(&dst_mb->vb.vb2_buf, 0, strm_size);
	mfc_rate_update_bitrate(ctx, strm_size);
	mfc_rate_update_framerate(ctx);

	index = dst_mb->vb.vb2_buf.index;
	if (call_bop(ctx, core_get_buf_ctrls_nal_q_enc, ctx,
				&ctx->dst_ctrls[index], pOutStr) < 0)
		mfc_ctx_err("[NALQ] failed in core_get_buf_ctrls_nal_q_enc\n");

	if (MFC_FEATURE_SUPPORT(dev, dev->pdata->hdr10_plus_stat_info))
		__mfc_core_nal_q_handle_stream_hdr10_plus_stat_info(ctx, pOutStr, index);

	vb2_buffer_done(&dst_mb->vb.vb2_buf, VB2_BUF_STATE_DONE);
	mfc_rate_update_bufq_framerate(ctx, MFC_TS_DST_DQ);
}

static void __mfc_core_nal_q_handle_stream(struct mfc_core *core, struct mfc_core_ctx *core_ctx,
			EncoderOutputStr *pOutStr)
{
	struct mfc_ctx *ctx = core_ctx->ctx;
	struct mfc_enc *enc = ctx->enc_priv;
	int slice_type, consumed_only = 0;
	unsigned int strm_size;
	unsigned int pic_count;
	unsigned int sbwc_err;

	mfc_debug_enter();

	slice_type = (pOutStr->SliceType & MFC_REG_E_SLICE_TYPE_MASK);
	strm_size = pOutStr->StreamSize;
	pic_count = pOutStr->EncCnt;

	mfc_debug(2, "[NALQ][STREAM] encoded slice type: %d, size: %d, display order: %d\n",
			slice_type, strm_size, pic_count);

	/* buffer full handling */
	if (core_ctx->state == MFCINST_RUNNING_BUF_FULL)
		mfc_change_state(core_ctx, MFCINST_RUNNING);

	/* set encoded frame type */
	enc->frame_type = slice_type;
	ctx->sequence++;

	if (mfc_qos_mb_calculate(core, core_ctx, pOutStr->MfcProcessingCycle, slice_type))
		mfc_qos_on(core, ctx);

	if (strm_size == 0) {
		mfc_debug(2, "[NALQ][STREAM] dst buffer is not returned\n");
		consumed_only = 1;
	}

	sbwc_err = ((pOutStr->NalDoneInfo >> MFC_REG_E_NAL_DONE_INFO_COMP_ERR_SHIFT)
				& MFC_REG_E_NAL_DONE_INFO_COMP_ERR_MASK);
	if (sbwc_err) {
		mfc_err("[NALQ][SBWC] Compressor error detected (Source: %d, DPB: %d)\n",
				(sbwc_err >> 1) & 0x1, sbwc_err & 0x1);
		mfc_err("[NALQ][SBWC] sbwc: %d, lossy: %d(%d), option: %d, FORMAT: %#x, OPTIONS: %#x\n",
				ctx->is_sbwc, ctx->is_sbwc_lossy, ctx->sbwcl_ratio, enc->sbwc_option,
				MFC_CORE_READL(MFC_REG_PIXEL_FORMAT),
				MFC_CORE_READL(MFC_REG_E_ENC_OPTIONS));
	}

	/* handle input buffer */
	__mfc_core_nal_q_handle_stream_input(core_ctx, pOutStr, consumed_only);

	/* handle output buffer */
	__mfc_core_nal_q_handle_stream_output(ctx, slice_type, strm_size, pOutStr);

	/* handle error buffer */
	__mfc_core_nal_q_handle_error_input(core, ctx, pOutStr);

	mfc_debug_leave();

	return;
}

static void __mfc_core_nal_q_handle_reuse_buffer(struct mfc_ctx *ctx, DecoderOutputStr *pOutStr)
{
	struct mfc_buf *dst_mb;
	dma_addr_t disp_addr;
	unsigned long used_flag = ((unsigned long)(pOutStr->UsedDpbFlagUpper) << 32) |
				(pOutStr->UsedDpbFlagLower & 0xffffffff);

	/* reuse not used buf: dst_buf_nal_queue -> dst_queue */
	disp_addr = MFC_NALQ_DMA_READL(pOutStr->DisplayAddr[0]);
	if (disp_addr) {
		mfc_ctx_debug(2, "[NALQ][DPB] disp addr: 0x%llx will be reuse\n", disp_addr);
		dst_mb = mfc_get_move_buf_addr(ctx, &ctx->dst_buf_queue,
				&ctx->dst_buf_nal_queue, disp_addr, used_flag);
		if (dst_mb) {
			mfc_ctx_debug(2, "[NALQ][DPB] buf[%d][%d] will reused. addr: 0x%08llx\n",
					dst_mb->vb.vb2_buf.index, dst_mb->dpb_index, disp_addr);
			dst_mb->used = 0;
		} else {
			mfc_ctx_debug(2, "[NALQ][DPB] couldn't find DPB 0x%08llx\n",
								disp_addr);
			mfc_print_dpb_table(ctx);
		}
	}
}

static void __mfc_core_nal_q_handle_frame_unused_output(struct mfc_ctx *ctx,
			DecoderOutputStr *pOutStr)
{
	struct mfc_dec *dec = ctx->dec_priv;
	struct mfc_buf *mfc_buf = NULL;
	unsigned int index;

	while (1) {
		mfc_buf = mfc_get_del_buf(ctx, &ctx->err_buf_queue, MFC_BUF_NO_TOUCH_USED);
		if (!mfc_buf)
			break;

		index = mfc_buf->vb.vb2_buf.index;

		mfc_clear_mb_flag(mfc_buf);
		mfc_buf->vb.flags &= ~(V4L2_BUF_FLAG_KEYFRAME |
					V4L2_BUF_FLAG_PFRAME |
					V4L2_BUF_FLAG_BFRAME |
					V4L2_BUF_FLAG_ERROR);

		if (call_bop(ctx, core_get_buf_ctrls_nal_q_dec, ctx,
					&ctx->dst_ctrls[index], pOutStr) < 0)
			mfc_ctx_err("[NALQ] failed in core_get_buf_ctrls_nal_q_dec\n");

		call_cop(ctx, update_buf_val, ctx, &ctx->dst_ctrls[index],
				V4L2_CID_MPEG_MFC51_VIDEO_DISPLAY_STATUS,
				MFC_REG_DEC_STATUS_DECODING_ONLY);

		call_cop(ctx, update_buf_val, ctx, &ctx->dst_ctrls[index],
				V4L2_CID_MPEG_MFC51_VIDEO_FRAME_TAG, UNUSED_TAG);

		dec->ref_buf[dec->refcnt].fd[0] = mfc_buf->vb.vb2_buf.planes[0].m.fd;
		dec->refcnt++;

		vb2_buffer_done(&mfc_buf->vb.vb2_buf, VB2_BUF_STATE_DONE);
		mfc_ctx_debug(2, "[NALQ][DPB] dst index [%d][%d] fd: %d is buffer done (not used)\n",
				mfc_buf->vb.vb2_buf.index, mfc_buf->dpb_index,
				mfc_buf->vb.vb2_buf.planes[0].m.fd);
	}
}

static void __mfc_core_nal_q_handle_frame_all_extracted(struct mfc_ctx *ctx, DecoderOutputStr *pOutStr)
{
	struct mfc_dec *dec = ctx->dec_priv;
	struct mfc_buf *dst_mb;
	int index, i, is_first = 1;

	mfc_ctx_debug(2, "[NALQ] Decided to finish\n");
	ctx->sequence++;

	while (1) {
		dst_mb = mfc_get_del_buf(ctx, &ctx->dst_buf_nal_queue, MFC_BUF_NO_TOUCH_USED);
		if (!dst_mb)
			break;

		mfc_ctx_debug(2, "[NALQ] Cleaning up buffer: [%d][%d]\n",
					  dst_mb->vb.vb2_buf.index, dst_mb->dpb_index);

		index = dst_mb->vb.vb2_buf.index;

		for (i = 0; i < ctx->dst_fmt->mem_planes; i++)
			vb2_set_plane_payload(&dst_mb->vb.vb2_buf, i, 0);

		dst_mb->vb.sequence = (ctx->sequence++);
		mfc_clear_mb_flag(dst_mb);

		if (call_bop(ctx, core_get_buf_ctrls_nal_q_dec, ctx,
					&ctx->dst_ctrls[index], pOutStr) < 0)
			mfc_ctx_err("[NALQ] failed in core_get_buf_ctrls_nal_q_dec\n");

		if (is_first) {
			call_cop(ctx, update_buf_val, ctx, &ctx->dst_ctrls[index],
				V4L2_CID_MPEG_MFC51_VIDEO_FRAME_TAG, ctx->stored_tag);
			is_first = 0;
		} else {
			call_cop(ctx, update_buf_val, ctx, &ctx->dst_ctrls[index],
				V4L2_CID_MPEG_MFC51_VIDEO_FRAME_TAG, DEFAULT_TAG);
			call_cop(ctx, update_buf_val, ctx, &ctx->dst_ctrls[index],
				V4L2_CID_MPEG_VIDEO_H264_SEI_FP_AVAIL, 0);
		}

		mutex_lock(&dec->dpb_mutex);

		index = dst_mb->dpb_index;
		dec->dpb[index].queued = 0;
		clear_bit(index, &dec->queued_dpb);

		mutex_unlock(&dec->dpb_mutex);

		vb2_buffer_done(&dst_mb->vb.vb2_buf, VB2_BUF_STATE_DONE);
		mfc_ctx_debug(2, "[NALQ][DPB] Cleand up index = %d, used_flag = %#lx, queued = %#lx\n",
				index, dec->dynamic_used, dec->queued_dpb);
	}

	/* dequeue unused DPB */
	__mfc_core_nal_q_handle_frame_unused_output(ctx, pOutStr);

	mfc_ctx_debug(2, "[NALQ] After cleanup\n");
}

static void __mfc_core_nal_q_handle_ref_info(struct mfc_ctx *ctx, struct mfc_buf *mfc_buf,
		unsigned int err)
{
	struct mfc_dec *dec = ctx->dec_priv;
	struct dec_dpb_ref_info *ref_info = NULL;
	int i;

	if (!mfc_buf) {
		for (i = 0; i < dec->refcnt; i++)
			mfc_ctx_debug(2, "[NALQ][REFINFO] Released FD = %d will update with display buffer\n",
					dec->ref_buf[i].fd[0]);
		return;
	}

	ref_info = &dec->ref_info[mfc_buf->vb.vb2_buf.index];
	if (ctx->plugin_type) {
		/*
		 * Selected DPB(mfc_buf) can be delivered to the user
		 * as a released fd by ref_info because User's DPB
		 * is not referenced always when dynamic_dpb is disabled.
		 */
		/* unused buffer */
		for (i = 0; i < dec->refcnt; i++)
			ref_info->dpb[i].fd[0] = dec->ref_buf[i].fd[0];
		/* selected user's DPB */
		ref_info->dpb[i++].fd[0] = mfc_buf->vb.vb2_buf.planes[0].m.fd;
		if (dec->refcnt != MFC_MAX_BUFFERS)
			ref_info->dpb[i].fd[0] = MFC_INFO_INIT_FD;
		dec->refcnt = 0;

		mfc_ctx_debug(2, "[PLUGIN] dst index [%d] fd: %d is buffer done in MFC only\n",
				mfc_buf->vb.vb2_buf.index,
				mfc_buf->vb.vb2_buf.planes[0].m.fd);
	} else {
		ref_info = &dec->ref_info[mfc_buf->vb.vb2_buf.index];
		for (i = 0; i < dec->refcnt; i++)
			ref_info->dpb[i].fd[0] = dec->ref_buf[i].fd[0];
		if (dec->refcnt != MFC_MAX_BUFFERS)
			ref_info->dpb[i].fd[0] = MFC_INFO_INIT_FD;
		dec->refcnt = 0;

		mfc_ctx_debug(2, "[NALQ][DPB] dst index [%d][%d] fd: %d is buffer done\n",
				mfc_buf->vb.vb2_buf.index, mfc_buf->dpb_index,
				mfc_buf->vb.vb2_buf.planes[0].m.fd);
		vb2_buffer_done(&mfc_buf->vb.vb2_buf, mfc_get_warn(err) ?
				VB2_BUF_STATE_ERROR : VB2_BUF_STATE_DONE);
	}
}

static void __mfc_core_nal_q_handle_plugin_buf(struct mfc_ctx *ctx, struct mfc_buf *mfc_buf)
{
	struct mfc_dec *dec = ctx->dec_priv;

	if (!mfc_buf)
		return;

	if (mfc_buf->dpb_index != -1) {
		mutex_lock(&dec->dpb_mutex);
		dec->dynamic_set &= ~(1UL << mfc_buf->dpb_index);
		dec->dpb_table_used |= (1UL << mfc_buf->dpb_index);
		mfc_ctx_debug(2, "[PLUGIN] src index: %d used %#lx, dst index %d used %#lx\n",
				mfc_buf->dpb_index, dec->dpb_table_used,
				mfc_buf->vb.vb2_buf.index, dec->plugin_used);
		mutex_unlock(&dec->dpb_mutex);

		mfc_buf = mfc_get_move_buf_index(ctx, &ctx->plugin_buf_queue,
				&ctx->dst_buf_nal_queue, mfc_buf->dpb_index,
				MFC_BUF_RESET_USED);
		if (!mfc_buf) {
			mfc_ctx_err("[PLUGIN] there is no buffer for post processing\n");
			return;
		}

		mfc_rm_request_work(ctx->dev, MFC_WORK_POST_PROCESSING, ctx);
	} else {
		mfc_ctx_debug(3, "[PLUGIN] src index for post processing is invalid\n");
	}
}

static void __mfc_core_nal_q_handle_frame_copy_timestamp(struct mfc_ctx *ctx,
			DecoderOutputStr *pOutStr)
{
	struct mfc_buf *dst_mb, *src_mb;
	dma_addr_t dec_y_addr;
	int dpb_index;

	mfc_ctx_debug_enter();

	dec_y_addr = MFC_NALQ_DMA_READL(pOutStr->DecodedAddr[0]);

	/* Get the next source buffer */
	src_mb = mfc_get_buf(ctx, &ctx->src_buf_nal_queue, MFC_BUF_NO_TOUCH_USED);
	if (!src_mb) {
		mfc_ctx_err("[NALQ][TS] no src buffers\n");
		return;
	}

	if (ctx->plugin_type) {
		dpb_index = mfc_find_buf_dpb_table(ctx, dec_y_addr);
		if (dpb_index >= 0)
			ctx->dec_priv->internal_dpb[dpb_index].priv_data =
				src_mb->vb.vb2_buf.timestamp;
	} else {
		dst_mb = mfc_find_buf(ctx, &ctx->dst_buf_nal_queue, dec_y_addr);
		if (!dst_mb)
			dst_mb = mfc_find_buf(ctx, &ctx->dst_buf_queue, dec_y_addr);
		if (dst_mb)
			dst_mb->vb.vb2_buf.timestamp = src_mb->vb.vb2_buf.timestamp;
	}

	mfc_ctx_debug_leave();
}

static void __mfc_core_nal_q_get_img_size(struct mfc_core *core, struct mfc_ctx *ctx,
			DecoderOutputStr *pOutStr, enum mfc_get_img_size img_size)
{
	struct mfc_dec *dec = ctx->dec_priv;
	unsigned int w, h;
	int i;

	w = ctx->img_width;
	h = ctx->img_height;

	ctx->img_width = pOutStr->DisplayFrameWidth;
	ctx->img_height = pOutStr->DisplayFrameHeight;
	ctx->crop_width = ctx->img_width;
	ctx->crop_height = ctx->img_height;

	for (i = 0; i < ctx->dst_fmt->num_planes; i++) {
		ctx->raw_buf.stride[i] = pOutStr->DpbStrideSize[i];
		if (IS_2BIT_NEED(ctx))
			ctx->raw_buf.stride_2bits[i] = pOutStr->Dpb2bitStrideSize[i];
	}

	mfc_ctx_debug(2, "[NALQ][FRAME][DRC] resolution changed, %dx%d => %dx%d (stride: %d)\n", w, h,
			ctx->img_width, ctx->img_height, ctx->raw_buf.stride[0]);

	if (img_size == MFC_GET_RESOL_SIZE) {
		dec->disp_drc.width[dec->disp_drc.push_idx] = ctx->img_width;
		dec->disp_drc.height[dec->disp_drc.push_idx] = ctx->img_height;
		dec->disp_drc.disp_res_change++;
		mfc_ctx_debug(3, "[NALQ][DRC] disp_res_change[%d] count %d\n",
				dec->disp_drc.push_idx, dec->disp_drc.disp_res_change);
		dec->disp_drc.push_idx = ++dec->disp_drc.push_idx % MFC_MAX_DRC_FRAME;
	} else if (img_size == MFC_GET_RESOL_DPB_SIZE) {
		ctx->scratch_buf_size = mfc_core_get_scratch_size();
		for (i = 0; i < ctx->dst_fmt->num_planes; i++) {
			ctx->min_dpb_size[i] = mfc_core_get_min_dpb_size(i);
			if (IS_2BIT_NEED(ctx))
				ctx->min_dpb_size_2bits[i] = mfc_core_get_min_dpb_size_2bit(i);
		}
		mfc_ctx_debug(2, "[NALQ][FRAME] DPB count %d, min_dpb_size %d(%#x) min_dpb_size_2bits %d scratch %zu(%#zx)\n",
			ctx->dpb_count, ctx->min_dpb_size[0], ctx->min_dpb_size[0], ctx->min_dpb_size_2bits[0],
			ctx->scratch_buf_size, ctx->scratch_buf_size);
	}
}

static struct mfc_buf *__mfc_core_nal_q_handle_frame_output_del(struct mfc_core *core,
		struct mfc_ctx *ctx, DecoderOutputStr *pOutStr)
{
	struct mfc_dec *dec = ctx->dec_priv;
	struct mfc_dev *dev = ctx->dev;
	struct mfc_raw_info *raw = &ctx->raw_buf;
	struct mfc_buf *dst_mb = NULL;
	dma_addr_t dspl_y_addr;
	unsigned int frame_type;
	unsigned int dst_frame_status;
	unsigned int is_video_signal_type = 0, is_colour_description = 0;
	unsigned int is_content_light = 0, is_display_colour = 0;
	unsigned int is_hdr10_plus_sei = 0, is_av1_film_grain_sei = 0;
	unsigned int is_disp_res_change = 0;
	unsigned int is_hdr10_plus_full = 0;
	unsigned int is_uncomp = 0;
	int i, index, idr_flag;

	if (MFC_FEATURE_SUPPORT(dev, dev->pdata->color_aspect_dec)) {
		is_video_signal_type = ((pOutStr->VideoSignalType
					>> MFC_REG_D_VIDEO_SIGNAL_TYPE_FLAG_SHIFT)
					& MFC_REG_D_VIDEO_SIGNAL_TYPE_FLAG_MASK);
		is_colour_description = ((pOutStr->VideoSignalType
					>> MFC_REG_D_COLOUR_DESCRIPTION_FLAG_SHIFT)
					& MFC_REG_D_COLOUR_DESCRIPTION_FLAG_MASK);
	}

	if (MFC_FEATURE_SUPPORT(dev, dev->pdata->static_info_dec)) {
		is_content_light = ((pOutStr->SeiAvail >> MFC_REG_D_SEI_AVAIL_CONTENT_LIGHT_SHIFT)
					& MFC_REG_D_SEI_AVAIL_CONTENT_LIGHT_MASK);
		is_display_colour = ((pOutStr->SeiAvail >> MFC_REG_D_SEI_AVAIL_MASTERING_DISPLAY_SHIFT)
					& MFC_REG_D_SEI_AVAIL_MASTERING_DISPLAY_MASK);
	}

	if (MFC_FEATURE_SUPPORT(dev, dev->pdata->hdr10_plus))
		is_hdr10_plus_sei = ((pOutStr->SeiAvail >> MFC_REG_D_SEI_AVAIL_ST_2094_40_SHIFT)
					& MFC_REG_D_SEI_AVAIL_ST_2094_40_MASK);

	if (MFC_FEATURE_SUPPORT(dev, dev->pdata->hdr10_plus_full))
		is_hdr10_plus_full = ((pOutStr->MetadataStatus >> MFC_REG_SEI_NAL_STATUS_SHIFT)
					& MFC_REG_SEI_NAL_STATUS_MASK);

	if (dec->av1_film_grain_present)
		is_av1_film_grain_sei = ((pOutStr->SeiAvail >> MFC_REG_D_SEI_AVAIL_FILM_GRAIN_SHIFT)
					& MFC_REG_D_SEI_AVAIL_FILM_GRAIN_MASK);

	if (dec->immediate_display == 1) {
		dspl_y_addr = MFC_NALQ_DMA_READL(pOutStr->DecodedAddr[0]);
		frame_type = pOutStr->DecodedFrameType & MFC_REG_DECODED_FRAME_MASK;
		idr_flag = ((pOutStr->DecodedFrameType
				>> MFC_REG_DECODED_IDR_FLAG_SHIFT)
				& MFC_REG_DECODED_IDR_FLAG_MASK);
	} else {
		dspl_y_addr = MFC_NALQ_DMA_READL(pOutStr->DisplayAddr[0]);
		frame_type = pOutStr->DisplayFrameType & MFC_REG_DISPLAY_FRAME_MASK;
		idr_flag = ((pOutStr->DisplayFrameType
				>> MFC_REG_DISPLAY_IDR_FLAG_SHIFT)
				& MFC_REG_DISPLAY_IDR_FLAG_MASK);
	}

	if (MFC_FEATURE_SUPPORT(dev, dev->pdata->sbwc_uncomp) && ctx->is_sbwc)
		is_uncomp = (pOutStr->DisplayStatus
				>> MFC_REG_DISP_STATUS_UNCOMP_SHIFT)
				& MFC_REG_DISP_STATUS_UNCOMP_MASK;

	if (ctx->plugin_type) {
		/*
		 * If plugin type is attached,
		 * dst buffer is in dst_buf_queue not dst_buf_nal_queue
		 * even if it is NAL_Q mode.
		 */
		dst_mb = mfc_get_buf_no_used(ctx, &ctx->dst_buf_nal_queue, MFC_BUF_SET_USED);
		if (dst_mb) {
			dst_mb->dpb_index = mfc_find_buf_dpb_table(ctx, dspl_y_addr);
			if (dst_mb->dpb_index >= 0)
				dst_mb->vb.vb2_buf.timestamp =
					dec->internal_dpb[dst_mb->dpb_index].priv_data;
			else
				dst_mb = NULL;
		}
	} else {
		dst_mb = mfc_find_del_buf(ctx, &ctx->dst_buf_nal_queue, dspl_y_addr);
		if (!dst_mb) {
			/*
			 * A buffer that was not displayed during NAL_START mode
			 * can be displayed after changing to NAL_QUEUE mode
			 * and it exists in dst_buf_queue.
			 * So, here tries to find the buffer also in dst_buf_queue.
			 */
			dst_mb = mfc_find_del_buf(ctx, &ctx->dst_buf_queue, dspl_y_addr);
			mfc_ctx_debug(2, "[NALQ][BUFINFO] disp buffer %#llx %ssearch in dst_q also\n",
					dspl_y_addr, dst_mb? "" : "couldn't ");
		}
	}
	if (dst_mb) {
		index = dst_mb->vb.vb2_buf.index;

		/* Check if this is the buffer we're looking for */
		if (ctx->plugin_type)
			mfc_ctx_debug(2, "[NALQ][BUFINFO][PLUGIN] src index: %d, %#llx, dst index: %d, %#llx\n",
					dst_mb->dpb_index, dspl_y_addr,
					index, dst_mb->addr[0][0]);
		else
			mfc_ctx_debug(2, "[NALQ][BUFINFO][DPB] ctx[%d] get dst index: [%d][%d], addr[0]: 0x%08llx\n",
					ctx->num, index, dst_mb->dpb_index, dst_mb->addr[0][0]);

		if (dec->crc_enable && dec->crc &&
				(ctx->dev->debugfs.sfr_dump & MFC_DUMP_DEC_CRC)) {
			if (dec->crc_idx < SZ_1K) {
				dec->crc[dec->crc_idx++] = pOutStr->DisplayFirstCrc;
				dec->crc[dec->crc_idx++] = pOutStr->DisplaySecondCrc;
			} else {
				mfc_ctx_debug(2, "[NALQ][CRC] couldn't store CRC dump (idx: %d)\n",
						dec->crc_idx);
			}
		}

		dst_mb->vb.sequence = ctx->sequence;

		/* Set reserved2 bits in order to inform SEI information */
		mfc_clear_mb_flag(dst_mb);

		if (is_content_light) {
			mfc_set_mb_flag(dst_mb, MFC_FLAG_HDR_CONTENT_LIGHT);
			mfc_ctx_debug(2, "[NALQ][HDR] content light level parsed\n");
		}
		if (is_display_colour) {
			mfc_set_mb_flag(dst_mb, MFC_FLAG_HDR_DISPLAY_COLOUR);
			mfc_ctx_debug(2, "[NALQ][HDR] mastering display colour parsed\n");
		}
		if (is_video_signal_type) {
			mfc_set_mb_flag(dst_mb, MFC_FLAG_HDR_VIDEO_SIGNAL_TYPE);
			mfc_ctx_debug(2, "[NALQ][HDR] video signal type parsed\n");
			if (is_colour_description) {
				mfc_set_mb_flag(dst_mb, MFC_FLAG_HDR_MAXTIX_COEFF);
				mfc_ctx_debug(2, "[NALQ][HDR] matrix coefficients parsed\n");
				mfc_set_mb_flag(dst_mb, MFC_FLAG_HDR_COLOUR_DESC);
				mfc_ctx_debug(2, "[NALQ][HDR] colour description parsed\n");
			}
		}

		if (IS_VP9_DEC(ctx) && MFC_FEATURE_SUPPORT(dev, dev->pdata->color_aspect_dec)) {
			if (dec->color_space != MFC_REG_D_COLOR_UNKNOWN) {
				mfc_set_mb_flag(dst_mb, MFC_FLAG_HDR_COLOUR_DESC);
				mfc_ctx_debug(2, "[NALQ][HDR] color space parsed\n");
			}
			mfc_set_mb_flag(dst_mb, MFC_FLAG_HDR_VIDEO_SIGNAL_TYPE);
			mfc_ctx_debug(2, "[NALQ][HDR] color range parsed\n");
		}

		if (IS_VP9_DEC(ctx)) {
			is_disp_res_change = ((pOutStr->Vp9Info
						>> MFC_REG_D_VP9_INFO_DISP_RES_SHIFT)
						& MFC_REG_D_VP9_INFO_DISP_RES_MASK);
		} else if (IS_AV1_DEC(ctx)) {
			is_disp_res_change = ((pOutStr->AV1Info
						>> MFC_REG_D_AV1_INFO_DISP_RES_SHIFT)
						& MFC_REG_D_AV1_INFO_DISP_RES_MASK);
		}

		if (is_disp_res_change) {
			mfc_ctx_info("[NALQ][FRAME][DRC] display resolution changed\n");
			mutex_lock(&ctx->drc_wait_mutex);
			ctx->wait_state = WAIT_G_FMT;
			__mfc_core_nal_q_get_img_size(core, ctx, pOutStr, MFC_GET_RESOL_SIZE);
			mfc_set_mb_flag(dst_mb, MFC_FLAG_DISP_RES_CHANGE);
			mutex_unlock(&ctx->drc_wait_mutex);
		}

		if (is_hdr10_plus_sei) {
			if (dec->hdr10_plus_info) {
				__mfc_core_nal_q_get_hdr_plus_info(core, ctx, pOutStr, &dec->hdr10_plus_info[index]);
				mfc_set_mb_flag(dst_mb, MFC_FLAG_HDR_PLUS);
				mfc_ctx_debug(2, "[NALQ][HDR+] HDR10 plus dyanmic SEI metadata parsed\n");
			} else {
				mfc_ctx_err("[NALQ][HDR+] HDR10 plus cannot be copied\n");
			}
		} else {
			if (dec->hdr10_plus_info)
				dec->hdr10_plus_info[index].valid = 0;
		}

		if (is_hdr10_plus_full) {
			if (dec->hdr10_plus_full) {
				__mfc_core_nal_q_get_dec_metadata_sei_nal(core, ctx, pOutStr,
						index);
				mfc_set_mb_flag(dst_mb, MFC_FLAG_HDR_PLUS);
				mfc_ctx_debug(2, "[NALQ][HDR+] HDR10 plus full SEI metadata parsed\n");
			} else {
				mfc_ctx_err("[NALQ][HDR+] HDR10 plus full cannot be copied\n");
			}
		}

		if (is_av1_film_grain_sei) {
			if (dec->av1_film_grain_info) {
				if (ctx->plugin_type == MFC_PLUGIN_FILM_GRAIN) {
					__mfc_core_nal_q_get_film_grain_raw(pOutStr, ctx, index);
				} else {
					__mfc_core_nal_q_get_film_grain_info(core, ctx,
							pOutStr, &dec->av1_film_grain_info[index]);
					mfc_set_mb_flag(dst_mb, MFC_FLAG_AV1_FILM_GRAIN);
				}
				mfc_ctx_debug(2, "[NALQ][FILMGR] AV1 Film Grain SEI metadata parsed\n");
			} else {
				mfc_ctx_err("[NALQ][FILMGR] AV1 Film Grain cannot be copied\n");
			}
		} else {
			if (dec->av1_film_grain_info)
				dec->av1_film_grain_info[index].apply_grain = 0;
		}

		if (is_uncomp) {
			mfc_set_mb_flag(dst_mb, MFC_FLAG_UNCOMP);
			mfc_ctx_debug(2, "[NALQ][SBWC] Uncompressed\n");
		}

		if (ctx->update_framerate) {
			mfc_set_mb_flag(dst_mb, MFC_FLAG_FRAMERATE_CH);
			ctx->update_framerate = false;
			mfc_ctx_debug(2, "[NALQ][QoS] framerate changed\n");
		}

		if ((IS_VP9_DEC(ctx) || IS_AV1_DEC(ctx)) && dec->has_multiframe) {
			mfc_set_mb_flag(dst_mb, MFC_FLAG_MULTIFRAME);
			mfc_ctx_debug(2, "[MULTIFRAME] multiframe detected\n");
		}

		for (i = 0; i < raw->num_planes; i++)
			vb2_set_plane_payload(&dst_mb->vb.vb2_buf, i,
					raw->plane_size[i]);

		dst_mb->vb.flags &= ~(V4L2_BUF_FLAG_KEYFRAME |
					V4L2_BUF_FLAG_PFRAME |
					V4L2_BUF_FLAG_BFRAME |
					V4L2_BUF_FLAG_ERROR);

		switch (frame_type) {
			case MFC_REG_DISPLAY_FRAME_I:
				dst_mb->vb.flags |= V4L2_BUF_FLAG_KEYFRAME;
				if (!(CODEC_HAS_IDR(ctx) && !idr_flag)) {
					mfc_set_mb_flag(dst_mb, MFC_FLAG_SYNC_FRAME);
					mfc_ctx_debug(2, "[NALQ][FRAME] syncframe IDR\n");
				}
				break;
			case MFC_REG_DISPLAY_FRAME_P:
				dst_mb->vb.flags |= V4L2_BUF_FLAG_PFRAME;
				break;
			case MFC_REG_DISPLAY_FRAME_B:
				dst_mb->vb.flags |= V4L2_BUF_FLAG_BFRAME;
				break;
			default:
				break;
		}

		if (mfc_get_warn(pOutStr->ErrorCode)) {
			mfc_ctx_info("[NALQ] Warning for displayed frame: %d\n",
					mfc_get_warn(pOutStr->ErrorCode));
			dst_mb->vb.flags |= V4L2_BUF_FLAG_ERROR;
		}

		if (call_bop(ctx, core_get_buf_ctrls_nal_q_dec, ctx,
					&ctx->dst_ctrls[index], pOutStr) < 0)
			mfc_ctx_err("[NALQ] failed in core_get_buf_ctrls_nal_q_dec\n");

		if (dec->immediate_display == 1) {
			dst_frame_status = pOutStr->DecodedStatus
				& MFC_REG_DEC_STATUS_DECODED_STATUS_MASK;

			call_cop(ctx, update_buf_val, ctx, &ctx->dst_ctrls[index],
					V4L2_CID_MPEG_MFC51_VIDEO_DISPLAY_STATUS,
					dst_frame_status);

			call_cop(ctx, update_buf_val, ctx, &ctx->dst_ctrls[index],
					V4L2_CID_MPEG_MFC51_VIDEO_FRAME_TAG, ctx->stored_tag);

			dec->immediate_display = 0;
		}

		mfc_rate_update_last_framerate(ctx, dst_mb->vb.vb2_buf.timestamp);

		if (ctx->plugin_type) {
			set_bit(index, &dec->plugin_used);
		} else {
			mutex_lock(&dec->dpb_mutex);

			dec->dpb[dst_mb->dpb_index].queued = 0;
			clear_bit(dst_mb->dpb_index, &dec->queued_dpb);
			dec->display_index = dst_mb->dpb_index;

			mutex_unlock(&dec->dpb_mutex);
		}
	} else {
		if (IS_AV1_DEC(ctx) && ((pOutStr->AV1Info
					>> MFC_REG_D_AV1_INFO_MULTIPLE_SHOW_SHIFT)
					& MFC_REG_D_AV1_INFO_MULTIPLE_SHOW_MASK))
			dec->is_multiple_show = 1;
		mfc_print_dpb_queue_with_lock(core->core_ctx[ctx->num], dec);
	}

	return dst_mb;
}

static void __mfc_core_nal_q_move_released_buf(struct mfc_ctx *ctx, unsigned long released_flag)
{
	struct mfc_dec *dec = ctx->dec_priv;
	struct mfc_buf *dst_mb;
	int i;

	if (!released_flag)
		return;

	for (i = 0; i < MFC_MAX_DPBS; i++) {
		if (released_flag & (1UL << i) && dec->dpb[i].queued) {
			dst_mb = mfc_get_move_buf_index(ctx, &ctx->dst_buf_queue,
					&ctx->dst_buf_nal_queue, i, MFC_BUF_RESET_USED);
			if (dst_mb)
				mfc_ctx_debug(2, "[NALQ][DPB] buf[%d][%d] released will be reused. addr: 0x%08llx\n",
						dst_mb->vb.vb2_buf.index, dst_mb->dpb_index, dst_mb->addr[0][0]);
			else
				mfc_ctx_debug(2, "[NALQ][DPB] buf[%d] couldn't search in dst_nal\n", i);
		}
	}
}

static void __mfc_core_nal_q_handle_released_buf(struct mfc_core *core, struct mfc_ctx *ctx,
			DecoderOutputStr *pOutStr)
{
	struct mfc_dec *dec = ctx->dec_priv;
	unsigned long prev_flag, cur_flag, released_flag = 0;
	unsigned long flag;
	int i;

	mutex_lock(&dec->dpb_mutex);

	prev_flag = dec->dynamic_used;
	cur_flag = ((unsigned long)(pOutStr->UsedDpbFlagUpper) << 32) | (pOutStr->UsedDpbFlagLower & 0xffffffff);
	released_flag = prev_flag & (~cur_flag);

	mfc_ctx_debug(2, "[NALQ][DPB] Used flag: old = %#lx, new = %#lx, released = %#lx, queued = %#lx\n",
			prev_flag, cur_flag, released_flag, dec->queued_dpb);

	if (ctx->plugin_type) {
		mutex_unlock(&dec->dpb_mutex);
		return;
	}

	__mfc_core_nal_q_move_released_buf(ctx, released_flag);
	dec->dynamic_used = cur_flag;

	flag = dec->dynamic_used | released_flag;
	for (i = __ffs(flag); i < MFC_MAX_DPBS;) {
		if (dec->dynamic_used & (1UL << i)) {
			dec->dpb[i].ref = 1;
			if (dec->dpb[i].mapcnt == 0) {
				mfc_ctx_err("[NALQ][DPB] %d index is no dpb table\n", i);
				call_dop(core, dump_and_stop_debug_mode, core);
			}
		}
		if (released_flag & (1UL << i)) {
			dec->dpb[i].ref = 0;
			if (dec->dpb[i].queued && (dec->dpb[i].new_fd != -1)) {
				dec->ref_buf[dec->refcnt].fd[0] = dec->dpb[i].fd[0];
				dec->refcnt++;
				mfc_ctx_debug(3, "[NALQ][REFINFO] Queued DPB[%d] released fd: %d\n",
						i, dec->dpb[i].fd[0]);
				dec->dpb[i].fd[0] = dec->dpb[i].new_fd;
				dec->dpb[i].new_fd = -1;
				mfc_ctx_debug(3, "[NALQ][REFINFO] Queued DPB[%d] reused fd: %d\n",
						i, dec->dpb[i].fd[0]);
			} else if (!dec->dpb[i].queued) {
				dec->ref_buf[dec->refcnt].fd[0] = dec->dpb[i].fd[0];
				dec->refcnt++;
				mfc_ctx_debug(3, "[NALQ][REFINFO] Dqueued DPB[%d] released fd: %d\n",
						i, dec->dpb[i].fd[0]);
				/*
				 * Except queued buffer,
				 * the released DPB is deleted from dpb_table
				 */
				dec->dpb_table_used &= ~(1UL << i);
				mfc_put_iovmm(ctx, dec->dpb, ctx->dst_fmt->mem_planes, i);
			} else {
				mfc_ctx_debug(3, "[NALQ][REFINFO] Queued DPB[%d] reused fd: %d\n",
						i, dec->dpb[i].fd[0]);
			}
		}
		flag &= ~(1UL << i);
		if (flag == 0)
			break;
		i = __ffs(flag);
	}

	/* The displayed and not referenced buffer must be freed from dpb_table */
	if (dec->display_index >= 0) {
		i = dec->display_index;
		if (!(dec->dynamic_used & (1UL << i)) && dec->dpb[i].mapcnt
				&& !dec->dpb[i].queued) {
			dec->ref_buf[dec->refcnt].fd[0] = dec->dpb[i].fd[0];
			dec->refcnt++;
			mfc_ctx_debug(3, "[NALQ][REFINFO] display DPB[%d] released fd: %d\n",
					i, dec->dpb[i].fd[0]);
			dec->dpb_table_used &= ~(1UL << i);
			mfc_put_iovmm(ctx, dec->dpb, ctx->dst_fmt->mem_planes, i);
		}
		dec->display_index = -1;
	}
	mfc_print_dpb_table(ctx);

	mutex_unlock(&dec->dpb_mutex);
}

static struct mfc_buf *__mfc_core_nal_q_handle_frame_output(struct mfc_core *core,
		struct mfc_ctx *ctx, DecoderOutputStr *pOutStr)
{
	struct mfc_dec *dec = ctx->dec_priv;
	dma_addr_t dspl_y_addr;
	unsigned int frame_type;

	frame_type = pOutStr->DisplayFrameType & MFC_REG_DISPLAY_FRAME_MASK;

	ctx->sequence++;

	dspl_y_addr = MFC_NALQ_DMA_READL(pOutStr->DisplayAddr[0]);

	if (dec->immediate_display == 1) {
		dspl_y_addr = MFC_NALQ_DMA_READL(pOutStr->DecodedAddr[0]);
		frame_type = pOutStr->DecodedFrameType & MFC_REG_DECODED_FRAME_MASK;
	}

	mfc_ctx_debug(2, "[NALQ][FRAME] frame type: %d\n", frame_type);

	/* If frame is same as previous then skip and do not dequeue */
	if (frame_type == MFC_REG_DISPLAY_FRAME_NOT_CODED) {
		if (!CODEC_NOT_CODED(ctx))
			return NULL;
	}

	/* Dequeued display buffer for user */
	return __mfc_core_nal_q_handle_frame_output_del(core, ctx, pOutStr);
}

static void __mfc_core_nal_q_handle_frame_input(struct mfc_core *core, struct mfc_ctx *ctx,
			unsigned int err, DecoderOutputStr *pOutStr)
{
	struct mfc_dev *dev = ctx->dev;
	struct mfc_dec *dec = ctx->dec_priv;
	struct mfc_buf *src_mb;
	unsigned int index;
	int deleted = 0;
	unsigned int consumed;
	unsigned int dst_frame_status;

	/* If there is consumed byte, it is abnormal status,
	 * We have to return remained stream buffer
	 */
	if (dec->consumed) {
		mfc_ctx_err("[NALQ] previous buffer was not fully consumed\n");
		src_mb = mfc_get_del_buf(ctx, &ctx->src_buf_nal_queue, MFC_BUF_NO_TOUCH_USED);
		if (src_mb)
			vb2_buffer_done(&src_mb->vb.vb2_buf, VB2_BUF_STATE_DONE);
		dec->consumed = 0;
	}

	/* Check multi-frame */
	consumed = pOutStr->DecodedNalSize;
	src_mb = mfc_get_del_if_consumed(ctx, &ctx->src_buf_nal_queue,
			consumed, STUFF_BYTE, err, &deleted);
	if (!src_mb) {
		mfc_ctx_err("[NALQ] no src buffers\n");
		return;
	}

	index = src_mb->vb.vb2_buf.index;
	mfc_ctx_debug(2, "[NALQ][BUFINFO] ctx[%d] get src index: %d, addr: 0x%08llx\n",
			ctx->num, index, src_mb->addr[0][0]);

	if (!deleted) {
		/* Run MFC again on the same buffer */
		mfc_ctx_debug(2, "[NALQ][MULTIFRAME] Running again the same buffer\n");

		if (CODEC_MULTIFRAME(ctx))
			dec->y_addr_for_pb = MFC_NALQ_DMA_READL(pOutStr->DecodedAddr[0]);

		dec->consumed += consumed;
		dec->has_multiframe = 1;
		core->nal_q_stop_cause |= (1 << NALQ_EXCEPTION_MULTI_FRAME);
		core->nal_q_handle->nal_q_exception = 1;

		MFC_TRACE_CTX("** consumed:%d, remained:%d, addr:0x%08llx\n",
			dec->consumed, mfc_dec_get_strm_size(ctx, src_mb), dec->y_addr_for_pb);
		/* Do not move src buffer to done_list */
		return;
	}

	mfc_clear_mb_flag(src_mb);

	dst_frame_status = pOutStr->DisplayStatus
		& MFC_REG_DISP_STATUS_DISPLAY_STATUS_MASK;

	if ((IS_VP9_DEC(ctx) || IS_AV1_DEC(ctx)) && dec->has_multiframe &&
		(dst_frame_status == MFC_REG_DEC_STATUS_DECODING_ONLY)) {
		mfc_set_mb_flag(src_mb, MFC_FLAG_CONSUMED_ONLY);
		mfc_ctx_debug(2, "[NALQ][STREAM][MULTIFRAME] last frame is decoding only\n");
	}

	/*
	 * VP8/VP9 decoder has decoding only frame,
	 * it will be used for reference frame only not displayed.
	 * So, driver inform to user this input has no destination.
	 */
	if ((IS_VP8_DEC(ctx) || IS_VP9_DEC(ctx)) &&
		(dst_frame_status == MFC_REG_DEC_STATUS_DECODING_ONLY)) {
		mfc_set_mb_flag(src_mb, MFC_FLAG_CONSUMED_ONLY);
		mfc_ctx_debug(2, "[NALQ][STREAM] decoding only stream has no buffer to DQ\n");
	}

	/*
	 * Because AV1 has a no show frame, there are two cases that
	 * driver should inform to user this input has no destination buffer.
	 * 1) If it's decoding only and it's not showable frame,
	 *   it will be used for reference frame only not displayed.
	 * 2) If the buffer that has already DQ to display comes to new display,
	 *   it is multiple show frame.
	 */
	if (IS_AV1_DEC(ctx)) {
		if ((dst_frame_status == MFC_REG_DEC_STATUS_DECODING_ONLY) &&
			!((pOutStr->AV1Info >> MFC_REG_D_AV1_INFO_SHOWABLE_FRAME_SHIFT)
					& MFC_REG_D_AV1_INFO_SHOWABLE_FRAME_MASK)) {
			mfc_set_mb_flag(src_mb, MFC_FLAG_CONSUMED_ONLY);
			mfc_ctx_debug(2, "[NALQ][STREAM] AV1 no showable frame has no buffer to DQ\n");
		}
		if (dec->is_multiple_show) {
			mfc_set_mb_flag(src_mb, MFC_FLAG_CONSUMED_ONLY);
			dec->is_multiple_show = 0;
			mfc_ctx_info("[NALQ][STREAM] AV1 multiple show frame has no buffer to DQ\n");
		}
	}

	/* If pic_output_flag is 0 in HEVC, it is no destination buffer */
	if (IS_HEVC_DEC(ctx) &&
			MFC_FEATURE_SUPPORT(dev, dev->pdata->hevc_pic_output_flag) &&
			!((pOutStr->HevcInfo >> MFC_REG_D_HEVC_INFO_PIC_OUTPUT_FLAG_SHIFT)
				& MFC_REG_D_HEVC_INFO_PIC_OUTPUT_FLAG_MASK)) {
		mfc_set_mb_flag(src_mb, MFC_FLAG_CONSUMED_ONLY);
		mfc_ctx_debug(2, "[NALQ][STREAM] HEVC pic_output_flag off has no buffer to DQ\n");
	}

	if ((dst_frame_status == MFC_REG_DEC_STATUS_DECODING_ONLY) &&
			(MFC_NALQ_DMA_READL(pOutStr->DecodedAddr[0]) == 0)) {
		mfc_set_mb_flag(src_mb, MFC_FLAG_CONSUMED_ONLY);
		mfc_ctx_debug(2, "[NALQ][STREAM] decoding only but there is no address\n");
	}

	if (call_bop(ctx, core_recover_buf_ctrls_nal_q, ctx,
				&ctx->src_ctrls[index]) < 0)
		mfc_ctx_err("[NALQ] failed in core_recover_buf_ctrls_nal_q\n");

	if (call_bop(ctx, core_get_buf_ctrls_nal_q_dec, ctx,
				&ctx->src_ctrls[index], pOutStr) < 0)
		mfc_ctx_err("[NALQ] failed in core_get_buf_ctrls_nal_q_dec\n");

	dec->consumed = 0;
	if (IS_VP9_DEC(ctx) || IS_AV1_DEC(ctx))
		dec->has_multiframe = 0;

	vb2_buffer_done(&src_mb->vb.vb2_buf, VB2_BUF_STATE_DONE);
}

void __mfc_core_nal_q_handle_frame(struct mfc_core *core, struct mfc_core_ctx *core_ctx,
			DecoderOutputStr *pOutStr)
{
	struct mfc_ctx *ctx = core_ctx->ctx;
	struct mfc_dec *dec = ctx->dec_priv;
	unsigned int dst_frame_status, sei_avail_status, need_empty_dpb;
	unsigned int res_change, need_dpb_change, need_scratch_change;
	unsigned int is_interlaced, err;
	struct mfc_buf *mfc_buf = NULL;
	bool qos_update = false;

	mfc_debug_enter();

	dst_frame_status = pOutStr->DisplayStatus
				& MFC_REG_DISP_STATUS_DISPLAY_STATUS_MASK;
	need_empty_dpb = (pOutStr->DisplayStatus
				>> MFC_REG_DISP_STATUS_NEED_EMPTY_DPB_SHIFT)
				& MFC_REG_DISP_STATUS_NEED_EMPTY_DPB_MASK;
	res_change = (pOutStr->DisplayStatus
				>> MFC_REG_DISP_STATUS_RES_CHANGE_SHIFT)
				& MFC_REG_DISP_STATUS_RES_CHANGE_MASK;
	need_dpb_change = (pOutStr->DisplayStatus
				>> MFC_REG_DISP_STATUS_NEED_DPB_CHANGE_SHIFT)
				& MFC_REG_DISP_STATUS_NEED_DPB_CHANGE_MASK;
	need_scratch_change = (pOutStr->DisplayStatus
				 >> MFC_REG_DISP_STATUS_NEED_SCRATCH_CHANGE_SHIFT)
				& MFC_REG_DISP_STATUS_NEED_SCRATCH_CHANGE_MASK;
	is_interlaced = (pOutStr->DecodedStatus
				>> MFC_REG_DEC_STATUS_INTERLACE_SHIFT)
				& MFC_REG_DEC_STATUS_INTERLACE_MASK;
	sei_avail_status = pOutStr->SeiAvail;
	err = pOutStr->ErrorCode;

	if (dec->immediate_display == 1)
		dst_frame_status = pOutStr->DecodedStatus
				& MFC_REG_DEC_STATUS_DECODED_STATUS_MASK;

	mfc_qos_get_disp_ratio(ctx, pOutStr->DecodedFrameCnt, pOutStr->DisplayFrameCnt);
	qos_update = mfc_qos_mb_calculate(core, core_ctx, pOutStr->MfcProcessingCycle,
			pOutStr->DecodedFrameType & MFC_REG_DECODED_FRAME_MASK);

	mfc_debug(2, "[NALQ][FRAME] frame status: %d\n", dst_frame_status);
	mfc_debug(2, "[NALQ][FRAME] display status: %d, type: %d, yaddr: %#llx\n",
			pOutStr->DisplayStatus & MFC_REG_DISP_STATUS_DISPLAY_STATUS_MASK,
			pOutStr->DisplayFrameType & MFC_REG_DISPLAY_FRAME_MASK,
			MFC_NALQ_DMA_READL(pOutStr->DisplayAddr[0]));
	mfc_debug(2, "[NALQ][FRAME] decoded status: %d, type: %d, yaddr: %#llx\n",
			pOutStr->DecodedStatus & MFC_REG_DEC_STATUS_DECODED_STATUS_MASK,
			pOutStr->DecodedFrameType & MFC_REG_DECODED_FRAME_MASK,
			MFC_NALQ_DMA_READL(pOutStr->DecodedAddr[0]));
	mfc_debug(4, "[NALQ][HDR] SEI available status: %#x\n", sei_avail_status);

	if (core_ctx->state == MFCINST_RES_CHANGE_INIT) {
		mfc_debug(2, "[NALQ][DRC] return until NAL-Q stopped in try_run\n");
		goto leave_handle_frame;
	}
	if (res_change) {
		mfc_debug(2, "[NALQ][DRC] Resolution change set to %d\n", res_change);
		mutex_lock(&ctx->drc_wait_mutex);
		mfc_change_state(core_ctx, MFCINST_RES_CHANGE_INIT);
		ctx->handle_drc_multi_mode = 0;
		ctx->wait_state = WAIT_G_FMT | WAIT_STOP;
		core->nal_q_stop_cause |= (1 << NALQ_EXCEPTION_DRC);
		core->nal_q_handle->nal_q_exception = 1;
		mfc_info("[NALQ][DRC] nal_q_exception is set (res change)\n");
		mutex_unlock(&ctx->drc_wait_mutex);
		goto leave_handle_frame;
	}
	if (need_empty_dpb) {
		mfc_debug(2, "[NALQ][MULTIFRAME] There is multi-frame. consumed:%d\n", dec->consumed);
		dec->has_multiframe = 1;
		core->nal_q_stop_cause |= (1 << NALQ_EXCEPTION_NEED_DPB);
		core->nal_q_handle->nal_q_exception = 1;
		if (dec->is_multiframe)
			mfc_debug(2, "[NALQ][MULTIFRAME] nal_q_exception is set\n");
		else
			mfc_info("[NALQ][MULTIFRAME] nal_q_exception is set\n");
		dec->is_multiframe = 1;
		goto leave_handle_frame;
	}
	if (need_dpb_change || need_scratch_change) {
		mfc_info("[NALQ][DRC] Interframe resolution changed\n");
		mutex_lock(&ctx->drc_wait_mutex);
		ctx->wait_state = WAIT_G_FMT | WAIT_STOP;
		__mfc_core_nal_q_get_img_size(core, ctx, pOutStr, MFC_GET_RESOL_DPB_SIZE);
		dec->inter_res_change = 1;
		mfc_info("[NALQ][DRC] nal_q_exception is set (interframe res change)\n");
		core->nal_q_stop_cause |= (1 << NALQ_EXCEPTION_INTER_DRC);
		core->nal_q_handle->nal_q_exception = 2;
		mutex_unlock(&ctx->drc_wait_mutex);
		goto leave_handle_frame;
	}
	if (is_interlaced && ctx->is_sbwc) {
		mfc_err("[NALQ][SBWC] interlace during decoding is not supported\n");
		dec->is_interlaced = is_interlaced;
		core->nal_q_stop_cause |= (1 << NALQ_EXCEPTION_SBWC_INTERLACE);
		core->nal_q_handle->nal_q_exception = 1;
		mfc_info("[NALQ][SBWC] nal_q_exception is set (interlaced)\n");
		goto leave_handle_frame;
	}
	/*
	 * H264/VC1/MPEG2/MPEG4 can have interlace type
	 * Only MPEG4 can continue to use NALQ
	 * because MPEG4 doesn't handle field unit.
	 */
	if (is_interlaced && !IS_MPEG4_DEC(ctx)) {
		mfc_debug(2, "[NALQ][INTERLACE] Progressive -> Interlaced\n");
		dec->is_interlaced = is_interlaced;
		core->nal_q_stop_cause |= (1 << NALQ_EXCEPTION_INTERLACE);
		core->nal_q_handle->nal_q_exception = 1;
		mfc_info("[NALQ][INTERLACE] nal_q_exception is set\n");
		goto leave_handle_frame;
	}

	if (mfc_is_queue_count_same(&ctx->buf_queue_lock, &ctx->src_buf_nal_queue, 0) &&
		mfc_is_queue_count_same(&ctx->buf_queue_lock, &ctx->dst_buf_nal_queue, 0)) {
		mfc_err("[NALQ] Queue count is zero for src/dst\n");
		goto leave_handle_frame;
	}

	/* Detection for QoS weight */
	if (!dec->num_of_tile_over_4 && !IS_HEVC_DEC(ctx) &&
				(((pOutStr->DisplayStatus
				>> MFC_REG_DEC_STATUS_NUM_OF_TILE_SHIFT)
				& MFC_REG_DEC_STATUS_NUM_OF_TILE_MASK) >= 4)) {
		dec->num_of_tile_over_4 = 1;
		qos_update = true;
	}
	if (!dec->super64_bframe && IS_SUPER64_BFRAME(ctx,
				(pOutStr->HevcInfo & MFC_REG_D_HEVC_INFO_LCU_SIZE_MASK),
				(pOutStr->DecodedFrameType & MFC_REG_DECODED_FRAME_MASK))) {
		dec->super64_bframe = 1;
		qos_update = true;
	}

	if (qos_update)
		mfc_qos_on(core, ctx);

	switch (dst_frame_status) {
	case MFC_REG_DEC_STATUS_DECODING_DISPLAY:
		/* copy decoded timestamp */
		__mfc_core_nal_q_handle_frame_copy_timestamp(ctx, pOutStr);
		break;
	case MFC_REG_DEC_STATUS_DECODING_ONLY:
		/* move dst buffer from dst_nal_queue to dst_queue for reuse */
		__mfc_core_nal_q_handle_reuse_buffer(ctx, pOutStr);
		break;
	default:
		break;
	}

	/* Mark source buffer as complete */
	if (dst_frame_status != MFC_REG_DEC_STATUS_DISPLAY_ONLY)
		__mfc_core_nal_q_handle_frame_input(core, ctx, err, pOutStr);
	else
		mfc_debug(2, "[NALQ][DPB] can't support display only in NAL-Q, is_dpb_full: %d\n",
				dec->is_dpb_full);

	/* A frame has been decoded and is in the buffer  */
	if (mfc_dec_status_display(dst_frame_status))
		mfc_buf = __mfc_core_nal_q_handle_frame_output(core, ctx, pOutStr);

	/* arrangement of assigned dpb table */
	__mfc_core_nal_q_handle_released_buf(core, ctx, pOutStr);

	/* dequeue unused DPB */
	__mfc_core_nal_q_handle_frame_unused_output(ctx, pOutStr);

	/* There is display buffer for user, update reference information */
	__mfc_core_nal_q_handle_ref_info(ctx, mfc_buf, err);

	/* Handle post processing with plugin driver */
	if (ctx->plugin_type)
		__mfc_core_nal_q_handle_plugin_buf(ctx, mfc_buf);

	mfc_rate_update_bufq_framerate(ctx, MFC_TS_DST_DQ);

leave_handle_frame:
	if (core->nal_q_handle->nal_q_exception == 2)
		__mfc_core_nal_q_handle_frame_all_extracted(ctx, pOutStr);

	mfc_debug_leave();
}

int __mfc_core_nal_q_handle_error(struct mfc_core *core, struct mfc_core_ctx *core_ctx,
			EncoderOutputStr *pOutStr, int err)
{
	struct mfc_ctx *ctx = core_ctx->ctx;
	struct mfc_dec *dec;
	struct mfc_enc *enc;
	struct mfc_buf *src_mb;
	int stop_nal_q = 1;
	unsigned int index;

	mfc_debug_enter();

	core->nal_q_stop_cause |= (1 << NALQ_EXCEPTION_ERROR);
	core->nal_q_handle->nal_q_exception = 1;
	mfc_info("[NALQ] nal_q_exception is set (error %d)\n", err);

	if (ctx->type == MFCINST_DECODER) {
		dec = ctx->dec_priv;
		if (!dec) {
			mfc_err("[NALQ] no mfc decoder to run\n");
			goto end;
		}
		src_mb = mfc_get_del_buf(ctx, &ctx->src_buf_nal_queue, MFC_BUF_NO_TOUCH_USED);

		if (!src_mb) {
			mfc_err("[NALQ] no src buffers\n");
		} else {
			index = src_mb->vb.vb2_buf.index;
			if (call_bop(ctx, core_recover_buf_ctrls, core, ctx,
						&ctx->src_ctrls[index]) < 0)
				mfc_err("failed in core_recover_buf_ctrls\n");

			mfc_debug(2, "[NALQ] MFC needs next buffer\n");
			dec->consumed = 0;
			mfc_clear_mb_flag(src_mb);
			mfc_set_mb_flag(src_mb, MFC_FLAG_CONSUMED_ONLY);

			if (call_bop(ctx, core_get_buf_ctrls, core, ctx,
						&ctx->src_ctrls[index]) < 0)
				mfc_err("failed in core_get_buf_ctrls\n");

			vb2_buffer_done(&src_mb->vb.vb2_buf, VB2_BUF_STATE_ERROR);
		}
	} else if (ctx->type == MFCINST_ENCODER) {
		enc = ctx->enc_priv;
		if (!enc) {
			mfc_err("[NALQ] no mfc encoder to run\n");
			goto end;
		}

		/*
		 * If the buffer full error occurs in NAL-Q mode,
		 * one input buffer is returned and the NAL-Q mode continues.
		 */
		if (err == MFC_REG_ERR_BUFFER_FULL) {
			mfc_err("[NALQ] stream buffer size(%d) isn't enough, skip (Bitrate: %d)\n",
				pOutStr->StreamSize,
				MFC_CORE_RAW_READL(MFC_REG_E_RC_BIT_RATE));

			src_mb = mfc_get_del_buf(ctx,&ctx->src_buf_nal_queue, MFC_BUF_NO_TOUCH_USED);

			if (!src_mb)
				mfc_err("[NALQ] no src buffers\n");
			else
				vb2_buffer_done(&src_mb->vb.vb2_buf, VB2_BUF_STATE_ERROR);

			core->nal_q_handle->nal_q_exception = 0;
			stop_nal_q = 0;
		}
	}

end:
	mfc_debug_leave();

	return stop_nal_q;
}

int mfc_core_nal_q_handle_out_buf(struct mfc_core *core, EncoderOutputStr *pOutStr)
{
	struct mfc_core_ctx *core_ctx;
	struct mfc_ctx *ctx;
	struct mfc_enc *enc;
	struct mfc_dec *dec;
	int ctx_num;
	u32 err;

	mfc_core_debug_enter();

	ctx_num = core->nal_q_handle->nal_q_out_handle->nal_q_ctx;
	if (ctx_num < 0) {
		mfc_core_err("[NALQ] Can't find ctx in nal q\n");
		return -EINVAL;
	}

	core_ctx = core->core_ctx[ctx_num];
	if (!core_ctx) {
		mfc_core_err("[NALQ] no mfc context to run\n");
		return -EINVAL;
	}
	ctx = core_ctx->ctx;

	mfc_debug(2, "[NALQ] Int ctx is %d(%s)\n", ctx_num,
			 ctx->type == MFCINST_ENCODER ? "enc" : "dec");

	err = mfc_get_err(pOutStr->ErrorCode);
	if ((err > MFC_REG_ERR_INVALID) && (err < MFC_REG_ERR_FRAME_CONCEAL))
		if (__mfc_core_nal_q_handle_error(core, core_ctx, pOutStr, err))
			return 0;

	if (ctx->type == MFCINST_ENCODER) {
		enc = ctx->enc_priv;
		if (!enc) {
			mfc_err("[NALQ] no mfc encoder to run\n");
			return -EINVAL;
		}
		__mfc_core_nal_q_handle_stream(core, core_ctx, pOutStr);
	} else if (ctx->type == MFCINST_DECODER) {
		dec = ctx->dec_priv;
		if (!dec) {
			mfc_err("[NALQ] no mfc decoder to run\n");
			return -EINVAL;
		}
		__mfc_core_nal_q_handle_frame(core, core_ctx, (DecoderOutputStr *)pOutStr);
	}

	mfc_core_debug_leave();

	return 0;
}

static int __mfc_core_nal_q_find_avail_slot(struct mfc_core *core)
{
	int index = 0;

	if (core->nal_q_handle->in_avail_slot[0] == 0) {
		if (core->nal_q_handle->in_avail_slot[1] == 0) {
			mfc_core_err("[NALQ][LL] in_avail_slot is full. (all zero)\n");
			return -EINVAL;
		}
		index = __ffs(core->nal_q_handle->in_avail_slot[1]);
		index += NAL_Q_IN_AVAIL_SLOT_SIZE;
	} else {
		index = __ffs(core->nal_q_handle->in_avail_slot[0]);
	}
	mfc_core_debug(3, "[NALQ][LL] index %d is found. slot[0] %#lx slot[1] %#lx\n",
			index, core->nal_q_handle->in_avail_slot[0],
			core->nal_q_handle->in_avail_slot[1]);

	return index;
}

static void __mfc_core_nal_q_use_avail_slot(struct mfc_core *core, int index)
{
	int slot;
	unsigned long bit;

	slot = (index / NAL_Q_IN_AVAIL_SLOT_SIZE);
	bit = ((unsigned long)(1) << (index % NAL_Q_IN_AVAIL_SLOT_SIZE));

	core->nal_q_handle->in_avail_slot[slot] &= ~(bit);
	mfc_core_debug(2, "[NALQ][LL] index %d is used. slot[0] %#lx slot[1] %#lx\n",
			index, core->nal_q_handle->in_avail_slot[0],
			core->nal_q_handle->in_avail_slot[1]);
}

static void __mfc_core_nal_q_update_avail_slot(struct mfc_core *core)
{
	int index, slot;
	unsigned long bit;
	unsigned int output_cmd_count = 0;

	index = mfc_core_get_nal_q_exe_nal_ll();
	slot = (index / NAL_Q_IN_AVAIL_SLOT_SIZE);
	bit = ((unsigned long)(1) << (index % NAL_Q_IN_AVAIL_SLOT_SIZE));

	if ((index == 0) || (index >= (NAL_Q_IN_AVAIL_SLOT_SIZE * 2))) {
		mfc_core_err("[NALQ][LL] index range is wrong %d\n", index);
		call_dop(core, dump_and_stop_debug_mode, core);
	} else if (core->nal_q_handle->in_avail_slot[slot] & bit) {
		/* The number of execution for the same input */
		output_cmd_count = mfc_core_get_nal_q_out_cmd_cnt();
		if (output_cmd_count) {
			mfc_core_debug(2, "[NALQ][LL] same index %d is freed.\n", index);
		} else {
			mfc_core_err("[NALQ][LL] index is wrong (not used) %d\n", index);
			call_dop(core, dump_and_stop_debug_mode, core);
		}
	} else {
		core->nal_q_handle->in_avail_slot[slot] |= bit;
		mfc_core_debug(2, "[NALQ][LL] index %d is freed. slot[0] %#lx slot[1] %#lx\n",
				index, core->nal_q_handle->in_avail_slot[0],
				core->nal_q_handle->in_avail_slot[1]);
	}
}

/* NAL Linked List */
static inline int __mfc_core_nal_ll_get_lock(struct mfc_core *core)
{
	unsigned int turn;
	unsigned long timeout;

	timeout = jiffies + msecs_to_jiffies(MFC_BW_TIMEOUT);

	/* Use Dekker's algorithm for synchronization between drv and fw to access linked list */
	MFC_CORE_WRITEL(0x1, MFC_REG_NAL_LL_IN_USE_BY_DRV);

	/*
	 * USE_BY_DRV: driver's flag to access critical section
	 * USE_BY_MFC: MFC's flag to access critical section
	 * TURN(0: DRV, 1: MFC): When out of the critical section, set flag
	 */
	while (MFC_CORE_READL(MFC_REG_NAL_LL_IN_USE_BY_MFC) & 0x1) {
		turn = MFC_CORE_READL(MFC_REG_NAL_LL_TURN);
		/* When FW release lock, will set TURN 0 and then USE_BY_MFC 0 */
		if ((turn & 0x1) == 0) {
			if (time_after(jiffies, timeout)) {
				mfc_core_err("Timeout while waiting MFC F/W turn\n");
				call_dop(core, dump_and_stop_debug_mode, core);
				return -EIO;
			}
			continue;
		}
		mfc_core_debug(2, "[NALQ][LL] MFC locked turn %#x\n", turn);
		MFC_TRACE_CORE("** MFC locked turn\n");
		MFC_CORE_WRITEL(0x0, MFC_REG_NAL_LL_IN_USE_BY_DRV);

		do {
			if (time_after(jiffies, timeout)) {
				mfc_core_err("Timeout while waiting MFC F/W done\n");
				call_dop(core, dump_and_stop_debug_mode, core);
				return -EIO;
			}
			turn = MFC_CORE_READL(MFC_REG_NAL_LL_TURN);
		} while (turn & 0x1);

		MFC_CORE_WRITEL(0x1, MFC_REG_NAL_LL_IN_USE_BY_DRV);
	}

	return 0;
}

static inline void __mfc_core_nal_ll_release_lock(struct mfc_core *core)
{
	MFC_CORE_WRITEL(0x1, MFC_REG_NAL_LL_TURN);
	MFC_CORE_WRITEL(0x0, MFC_REG_NAL_LL_IN_USE_BY_DRV);
}

static inline EncoderInputStr* __mfc_core_nal_ll_get_inputStr(struct mfc_core *core,
		nal_queue_in_handle *nal_q_in_handle, int index)
{
	return (EncoderInputStr *)(nal_q_in_handle->nal_q_in_addr +
			core->dev->pdata->nal_q_entry_size * index);
}

static void __mfc_core_nal_ll_set_nextListIndex(struct mfc_core *core,
	nal_queue_in_handle *nal_q_in_handle, int cur_index, int next_index)
{
	EncoderInputStr *pStr;

	pStr = __mfc_core_nal_ll_get_inputStr(core, nal_q_in_handle, cur_index);
	pStr->NextListIndex = next_index;
}

static void __mfc_core_nal_ll_show_list(struct mfc_core *core, nal_queue_in_handle *nal_q_in_handle)
{
	struct mfc_dev *dev = core->dev;
	EncoderInputStr *pStr;
	int offset, index, count = 0;

	if (!dev->debugfs.nal_q_dump)
		return;

	pStr = (EncoderInputStr *)(nal_q_in_handle->nal_q_in_addr);
	offset = 0;
	mfc_core_info("[NALQ][LL] Linked List status----------------------\n");
	do {
		index = pStr->NextListIndex;
		offset = dev->pdata->nal_q_entry_size * index;
		pStr = (EncoderInputStr *)(nal_q_in_handle->nal_q_in_addr + offset);
		mfc_core_info("[NALQ][LL][c:%d] index %d, prio %d, NextListIndex %d\n",
				pStr->InstanceId, index,
				pStr->Priority, pStr->NextListIndex);
		count++;
		if (count > 31) {
			mfc_core_info("[NALQ][LL] forcely stop to show list\n");
			call_dop(core->dev, dump_and_stop_debug_mode, core->dev);
			break;
		}
	} while (pStr->NextListIndex);
}

static int __mfc_core_nal_ll_check_perf_all(struct mfc_core *core, struct mfc_inst_perf *inst_perf)
{
	struct mfc_core_ctx *core_ctx;
	int max_runtime = 0, runtime;
	int i, inst_cnt = 0, num;

	if (core->dev->debugfs.sched_perf_disable)
		return 0;

	if (core->num_inst <= 1)
		return core->num_inst;

	for (i = 0; i < MFC_NUM_CONTEXTS; i++) {
		core_ctx = core->core_ctx[i];
		if (!core_ctx)
			continue;
		/* if runtime is 0, use default 30fps (33msec) */
		runtime = core_ctx->avg_runtime ? core_ctx->avg_runtime : MFC_DEFAULT_RUNTIME;
		if (runtime > max_runtime) {
			max_runtime = runtime;
			num = i;
		}
	}

	if (max_runtime)
		mfc_core_debug(2, "[NALQ][LL][c:%d] max runtime is %d usec\n", num, max_runtime);

	for (i = 0; i < MFC_NUM_CONTEXTS; i++) {
		core_ctx = core->core_ctx[i];
		if (!core_ctx)
			continue;

		if (mfc_get_queue_count(&core_ctx->ctx->buf_queue_lock,
					&core_ctx->ctx->src_buf_nal_queue)) {
			inst_perf[inst_cnt].num = core_ctx->inst_no;
			inst_perf[inst_cnt].perf = mfc_rate_check_perf_ctx(core_ctx->ctx, max_runtime);
			mfc_debug(2, "[NALQ][LL][c:%d] inst_no: %d, perf: %s\n",
					core_ctx->num, core_ctx->inst_no,
					inst_perf[inst_cnt].perf ? "enough" : "not enough");
			inst_cnt++;
		}
	}

	return inst_cnt;
}

static int __mfc_core_nal_ll_update_prio(struct mfc_core *core, struct mfc_core_ctx *core_ctx,
	nal_queue_in_handle *nal_q_in_handle, int cur_index)
{
	struct mfc_ctx *ctx = core_ctx->ctx;
	EncoderInputStr *pStr;
	int prev_index = 0, index = 0, prio;
	unsigned long flags;

	spin_lock_irqsave(&core->prio_work_lock, flags);

	/*
	 * If the priority is changed, do not enqueue in NALQ.
	 * Because the changed priority does not guarantee input sequence.
	 */
	if (core->nal_q_handle->nal_q_exception &&
			(core->nal_q_stop_cause & (1 << NALQ_EXCEPTION_PRIO_CHANGE))) {
		spin_unlock_irqrestore(&core->prio_work_lock, flags);
		return -EINVAL;
	}

	prio = mfc_get_prio(core, ctx->rt, ctx->prio);
	spin_unlock_irqrestore(&core->prio_work_lock, flags);

	pStr = (EncoderInputStr *)(nal_q_in_handle->nal_q_in_addr);
	do {
		prev_index = index;
		index = pStr->NextListIndex;
		pStr = __mfc_core_nal_ll_get_inputStr(core, nal_q_in_handle, index);
	} while (index && (pStr->Priority <= prio));

	__mfc_core_nal_ll_set_nextListIndex(core, nal_q_in_handle, prev_index, cur_index);
	__mfc_core_nal_ll_set_nextListIndex(core, nal_q_in_handle, cur_index, index);

	/* Save the priority of current index */
	pStr = __mfc_core_nal_ll_get_inputStr(core, nal_q_in_handle, cur_index);
	pStr->Priority = prio;

	__mfc_core_nal_ll_show_list(core, nal_q_in_handle);

	return 0;
}

static void __mfc_core_nal_ll_update_perf(struct mfc_core *core,
		nal_queue_in_handle *nal_q_in_handle, struct mfc_inst_perf *inst_perf, int inst_cnt)
{
	EncoderInputStr *pStr;
	int first_index = 0, prev_index, next_index, index = 0;
	int prev_inst;
	int i;

	pStr = (EncoderInputStr *)(nal_q_in_handle->nal_q_in_addr);
	while (pStr->NextListIndex) {
		prev_inst = pStr->InstanceId;
		prev_index = index;

		index = pStr->NextListIndex;
		pStr = __mfc_core_nal_ll_get_inputStr(core, nal_q_in_handle, index);

		/* If inst is same with the prevous inst except HEAD, skip to check perf */
		if ((prev_index != 0) && (prev_inst == pStr->InstanceId))
			continue;

		/* Save the head->next index */
		if (prev_index == 0)
			first_index = index;

		for (i = 0; i < inst_cnt; i++) {
			if (inst_perf[i].num == pStr->InstanceId) {
				if (inst_perf[i].perf == 0) {
					if (first_index == index)
						return;
					/* If the perf is not satisfied, move to head->next */
					mfc_core_debug(2, "[NALQ][LL] inst (%d) goes to HEAD->next Priority %d->0\n",
							pStr->InstanceId, pStr->Priority);

					pStr->Priority = 0;
					next_index = pStr->NextListIndex;

					goto update;
				}
				break;
			}
		}
	}
	return;

update:
	/* Update prev_index -> next_index */
	__mfc_core_nal_ll_set_nextListIndex(core, nal_q_in_handle, prev_index, next_index);

	/* Update head->next to this and this->next to first */
	__mfc_core_nal_ll_set_nextListIndex(core, nal_q_in_handle, 0, index);
	__mfc_core_nal_ll_set_nextListIndex(core, nal_q_in_handle, index, first_index);

	__mfc_core_nal_ll_show_list(core, nal_q_in_handle);
}

/*
 * This function should be called in NAL_Q_STATE_STARTED state.
 */
int mfc_core_nal_q_enqueue_in_buf(struct mfc_core *core, struct mfc_core_ctx *core_ctx,
	nal_queue_in_handle *nal_q_in_handle)
{
	struct mfc_dev *dev = core->dev;
	struct mfc_ctx *ctx = core_ctx->ctx;
	struct mfc_inst_perf inst_perf[MFC_NUM_CONTEXTS];
	unsigned long flags;
	unsigned int input_count = 0;
	unsigned int input_exe_count = 0;
	int input_diff = 0;
	unsigned int index = 0, offset = 0;
	EncoderInputStr *pStr = NULL;
	int queued_inst, ret = 0;

	mfc_debug_enter();

	if (!nal_q_in_handle) {
		mfc_err("[NALQ] There is no nal_q_handle\n");
		return -EINVAL;
	}

	if (nal_q_in_handle->nal_q_handle->nal_q_state != NAL_Q_STATE_STARTED) {
		mfc_err("[NALQ] State is wrong, state: %d\n",
				nal_q_in_handle->nal_q_handle->nal_q_state);
		return -EINVAL;
	}

	mfc_core_nal_q_clock_on(core, core->nal_q_handle);

	spin_lock_irqsave(&nal_q_in_handle->nal_q_handle->lock, flags);

	input_count = mfc_core_get_nal_q_input_count();
	input_exe_count = mfc_core_get_nal_q_input_exe_count();
	nal_q_in_handle->in_exe_count = input_exe_count;
	input_diff = input_count - input_exe_count;

	/*
	 * meaning of the variable input_diff
	 * 0:				number of available slots = NAL_Q_QUEUE_SIZE
	 * 1:				number of available slots = NAL_Q_QUEUE_SIZE - 1
	 * ...
	 * NAL_Q_QUEUE_SIZE-1:		number of available slots = 1
	 * NAL_Q_QUEUE_SIZE:		number of available slots = 0
	 */

	mfc_debug(2, "[NALQ] input_diff = %d(in: %d, exe: %d)\n",
			input_diff, input_count, input_exe_count);

	if ((input_diff < 0) || (input_diff >= NAL_Q_QUEUE_SIZE)) {
		mfc_err("[NALQ] No available input slot(%d)\n", input_diff);
		ret = -EINVAL;
		goto err_out;
	}

	if (core->nal_q_handle->nal_q_ll) {
		index = __mfc_core_nal_q_find_avail_slot(core);
		if (index <= 0) {
			mfc_err("[NALQ][LL] No available input slot\n");
			ret = -EINVAL;
			goto err_out;
		}
		offset = dev->pdata->nal_q_entry_size * index;
	} else {
		index = input_count % NAL_Q_QUEUE_SIZE;
		offset = dev->pdata->nal_q_entry_size * index;
	}
	pStr = (EncoderInputStr *)(nal_q_in_handle->nal_q_in_addr + offset);

	memset(pStr, 0, dev->pdata->nal_q_entry_size);

	if (ctx->type == MFCINST_ENCODER)
		ret = __mfc_core_nal_q_run_in_buf_enc(core, core_ctx, pStr);
	else if (ctx->type == MFCINST_DECODER)
		ret = __mfc_core_nal_q_run_in_buf_dec(core, core_ctx, (DecoderInputStr *)pStr);

	if (ret != 0) {
		mfc_ctx_debug(2, "[NALQ] Failed to set input queue\n");
		goto err_out;
	}

	if (core->nal_q_handle->nal_q_ll) {
		queued_inst = __mfc_core_nal_ll_check_perf_all(core, inst_perf);

		ret = __mfc_core_nal_ll_get_lock(core);
		if (ret) {
			mfc_err("[NALQ][LL] Failed to get NAL LL lock\n");
			goto err_out;
		}
		ret = __mfc_core_nal_ll_update_prio(core, core_ctx, nal_q_in_handle, index);
		if (ret) {
			mfc_debug(2, "[NALQ][LL] There is priority change. Can't start NAL-Q\n");
			__mfc_core_nal_ll_release_lock(core);
			goto err_out;
		}
		if (queued_inst > 1)
			__mfc_core_nal_ll_update_perf(core, nal_q_in_handle, inst_perf, queued_inst);
		__mfc_core_nal_ll_release_lock(core);

		__mfc_core_nal_q_use_avail_slot(core, index);
	}

	if (dev->debugfs.nal_q_dump == 1) {
		mfc_err("[NAL-Q][DUMP][%s INPUT][c: %d] diff: %d, count: %d, exe: %d\n",
				ctx->type == MFCINST_ENCODER ? "ENC" : "DEC", core->curr_core_ctx,
				input_diff, input_count, input_exe_count);
		print_hex_dump(KERN_ERR, "", DUMP_PREFIX_OFFSET, 32, 4,
				(int *)pStr, dev->pdata->nal_q_dump_size, false);
		mfc_err("...\n");

		if (core->nal_q_handle->nal_q_ll) {
			pStr = (EncoderInputStr *)(nal_q_in_handle->nal_q_in_addr);
			mfc_err("[NAL-Q][DUMP][%s INPUT][HEAD] last 32 bytes\n",
					ctx->type == MFCINST_ENCODER ? "ENC" : "DEC");
			print_hex_dump(KERN_ERR, "", DUMP_PREFIX_OFFSET, 32, 4,
					(char *)pStr + (dev->pdata->nal_q_entry_size - 32), 32, false);
			mfc_err("...\n");
		}
	}
	input_count++;

	mfc_core_update_nal_queue_input_count(core, input_count);

	if (input_diff == 0)
		mfc_core_meerkat_start_tick(core);
	MFC_TRACE_LOG_CORE("N%d", input_diff);

	spin_unlock_irqrestore(&nal_q_in_handle->nal_q_handle->lock, flags);

	MFC_TRACE_CTX("NAL %s in: diff %d count %d exe %d\n",
			ctx->type == MFCINST_ENCODER ? "ENC" : "DEC",
			input_diff, input_count, input_exe_count);

	mfc_debug_leave();

	return ret;

err_out:
	spin_unlock_irqrestore(&nal_q_in_handle->nal_q_handle->lock, flags);
	mfc_core_nal_q_clock_off(core, core->nal_q_handle);
	return ret;
}

/*
 * This function should be called in NAL_Q_STATE_STARTED state.
 */
EncoderOutputStr *mfc_core_nal_q_dequeue_out_buf(struct mfc_core *core,
	nal_queue_out_handle *nal_q_out_handle, unsigned int *reason)
{
	struct mfc_dev *dev = core->dev;
	struct mfc_core_ctx *core_ctx;
	struct mfc_ctx *ctx;
	unsigned long flags;
	unsigned int output_count = 0;
	unsigned int output_exe_count = 0;
	int input_diff = 0;
	int output_diff = 0;
	unsigned int index = 0, offset = 0;
	EncoderOutputStr *pStr = NULL;
	unsigned int err, warn;

	mfc_core_debug_enter();

	if (!nal_q_out_handle || !nal_q_out_handle->nal_q_out_addr) {
		mfc_core_err("[NALQ] There is no handle\n");
		return pStr;
	}

	spin_lock_irqsave(&nal_q_out_handle->nal_q_handle->lock, flags);

	output_count = mfc_core_get_nal_q_output_count();
	output_exe_count = nal_q_out_handle->out_exe_count;
	output_diff = output_count - output_exe_count;

	/*
	 * meaning of the variable output_diff
	 * 0:				number of output slots = 0
	 * 1:				number of output slots = 1
	 * ...
	 * NAL_Q_QUEUE_SIZE-1:		number of output slots = NAL_Q_QUEUE_SIZE - 1
	 * NAL_Q_QUEUE_SIZE:		number of output slots = NAL_Q_QUEUE_SIZE
	 */

	mfc_core_debug(2, "[NALQ] output_diff = %d(out: %d, exe: %d)\n",
			output_diff, output_count, output_exe_count);
	if ((output_diff <= 0) || (output_diff > NAL_Q_QUEUE_SIZE)) {
		spin_unlock_irqrestore(&nal_q_out_handle->nal_q_handle->lock, flags);
		mfc_core_debug(2, "[NALQ] No available output slot(%d)\n", output_diff);
		return pStr;
	}

	if (core->nal_q_handle->nal_q_ll)
		__mfc_core_nal_q_update_avail_slot(core);

	index = output_exe_count % NAL_Q_QUEUE_SIZE;
	offset = dev->pdata->nal_q_entry_size * index;
	pStr = (EncoderOutputStr *)(nal_q_out_handle->nal_q_out_addr + offset);

	nal_q_out_handle->nal_q_ctx = __mfc_core_nal_q_find_ctx(core, pStr);
	if (nal_q_out_handle->nal_q_ctx < 0) {
		spin_unlock_irqrestore(&nal_q_out_handle->nal_q_handle->lock, flags);
		mfc_core_err("[NALQ] Can't find ctx in nal q\n");
		pStr = NULL;
		return pStr;
	}

	core_ctx = core->core_ctx[nal_q_out_handle->nal_q_ctx];
	ctx = core_ctx->ctx;
	if (dev->debugfs.nal_q_dump == 1) {
		mfc_err("[NALQ][DUMP][%s OUTPUT][c: %d] diff: %d, count: %d, exe: %d\n",
				ctx->type == MFCINST_ENCODER ? "ENC" : "DEC",
				nal_q_out_handle->nal_q_ctx,
				output_diff, output_count, output_exe_count);
		print_hex_dump(KERN_ERR, "", DUMP_PREFIX_OFFSET, 32, 4,
				(int *)pStr, dev->pdata->nal_q_dump_size, false);
		mfc_err("...\n");
	}
	nal_q_out_handle->out_exe_count++;

	if (pStr->ErrorCode) {
		*reason = MFC_REG_R2H_CMD_ERR_RET;
		err = mfc_get_err(pStr->ErrorCode);
		warn = mfc_get_warn(pStr->ErrorCode);

		if (((err >= MFC_REG_ERR_FRAME_CONCEAL) && (err <= MFC_REG_ERR_WARNINGS_END)) ||
			((warn >= MFC_REG_ERR_FRAME_CONCEAL) && (warn <= MFC_REG_ERR_WARNINGS_END)))
			mfc_info("[NALQ] Interrupt Warn: display: %d, decoded: %d\n",
					warn, err);
		else
			mfc_err("[NALQ] Interrupt Error: display: %d, decoded: %d\n", warn, err);
	}

	input_diff = mfc_core_get_nal_q_input_count() - mfc_core_get_nal_q_input_exe_count();
	if (input_diff == 0)
		mfc_core_meerkat_stop_tick(core);
	else if (input_diff > 0)
		mfc_core_meerkat_reset_tick(core);

	spin_unlock_irqrestore(&nal_q_out_handle->nal_q_handle->lock, flags);

	MFC_TRACE_CTX("NAL %s out: diff %d count %d exe %d\n",
			ctx->type == MFCINST_ENCODER ? "ENC" : "DEC",
			output_diff, output_count, output_exe_count);

	mfc_core_debug_leave();

	return pStr;
}
