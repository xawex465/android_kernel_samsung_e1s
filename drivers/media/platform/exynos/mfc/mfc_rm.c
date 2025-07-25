/*
 * drivers/media/platform/exynos/mfc/mfc_rm.c
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

#include "mfc_core_hwlock.h"
#include "mfc_core_intlock.h"
#include "mfc_core_reg_api.h"
#include "mfc_core_hw_reg_api.h"
#include "mfc_core_pm.h"

#include "base/mfc_qos.h"
#include "base/mfc_buf.h"
#include "base/mfc_queue.h"
#include "base/mfc_utils.h"
#include "base/mfc_mem.h"

static void __mfc_rm_request_butler(struct mfc_dev *dev, struct mfc_ctx *ctx)
{
	struct mfc_core *core;
	struct mfc_core_ctx *core_ctx;
	int i;

	if (ctx) {
		/* main core first if it is working */
		for (i = 0; i < MFC_CORE_TYPE_NUM; i++) {
			if (ctx->op_core_num[i] == MFC_CORE_INVALID)
				break;

			core = dev->core[ctx->op_core_num[i]];
			if (!core) {
				mfc_ctx_err("[RM] There is no core[%d]\n",
						ctx->op_core_num[i]);
				return;
			}

			core_ctx = core->core_ctx[ctx->num];
			if (core->sched->enqueue_work(core, core_ctx))
				core->core_ops->request_work(core,
						MFC_WORK_BUTLER, ctx);
		}
	} else {
		/* all of alive core */
		for (i = 0; i < dev->num_core; i++) {
			core = dev->core[i];
			if (!core) {
				mfc_dev_debug(2, "[RM] There is no core[%d]\n", i);
				continue;
			}

			core->core_ops->request_work(core, MFC_WORK_BUTLER, NULL);
		}
	}
}

static void __mfc_rm_update_core_load(struct mfc_ctx *ctx, int move_core, int multi_mode)
{
	struct mfc_dev *dev = ctx->dev;
	struct mfc_core *core;
	int i;

	/*
	 * @move_core
	 * 0: no move of core.
	 * 1: update the load to the moving core, because have to move the main core.
	 */
	if (move_core)
		core = dev->core[ctx->move_core_num[MFC_CORE_MAIN]];
	else
		core = mfc_get_main_core(dev, ctx);
	if (!core) {
		mfc_ctx_err("[RM] There is no main core\n");
		return;
	}

	/*
	 * @multi_core
	 * 0: no multi core mode (single core).
	 * 1: update the load separately, because it works in multi core mode.
	 */
	if (multi_mode) {
		for (i = 0; i < dev->num_core; i++)
			dev->core[i]->total_mb += (ctx->weighted_mb / dev->num_core);
	} else {
		core->total_mb += ctx->weighted_mb;
	}

	mfc_ctx_debug(3, "[RMLB] load(%lu) balanced to %s core-%d (total load: [0] %lu, [1] %lu)\n",
			ctx->weighted_mb,
			multi_mode ? "multi" : "single", core->id,
			dev->core[0]->total_mb,	dev->core[1]->total_mb);
	MFC_TRACE_RM("[c:%d] load(%lu) balanced to %s core-%d (total load: [0] %lu, [1] %lu)\n",
			ctx->num, ctx->weighted_mb,
			multi_mode ? "multi" : "single", core->id,
			dev->core[0]->total_mb,	dev->core[1]->total_mb);
}

static int __mfc_rm_get_core_num_by_load(struct mfc_dev *dev, struct mfc_ctx *ctx,
					int default_core)
{
	struct mfc_core *core;
	int total_load[MFC_NUM_CORE];
	int core_num, surplus_core;
	int curr_load;

	if (default_core == MFC_DEC_DEFAULT_CORE)
		surplus_core = MFC_SURPLUS_CORE;
	else
		surplus_core = MFC_DEC_DEFAULT_CORE;
	mfc_ctx_debug(2, "[RMLB] default core-%d, surplus core-%d\n",
			default_core, surplus_core);

	if (!dev->core[default_core]->total_mb && !dev->core[surplus_core]->total_mb) {
		mfc_ctx_debug(2, "[RMLB] there is no instance, use the default core\n");
		return default_core;
	}

	core = dev->core[default_core];
	total_load[default_core] = core->total_mb * 100 / core->core_pdata->max_mb;
	core = dev->core[surplus_core];
	total_load[surplus_core] = core->total_mb * 100 / core->core_pdata->max_mb;

	curr_load = ctx->weighted_mb * 100 / core->core_pdata->max_mb;
	mfc_ctx_debug(2, "[RMLB] load%s fixed (curr mb: %ld, load: %d%%)\n",
			ctx->src_ts.ts_is_full ? " " : " not", ctx->weighted_mb, curr_load);

	if (dev->debugfs.core_balance)
		dev->core_balance = dev->debugfs.core_balance;
	else if (dev->num_enc_inst)
		dev->core_balance = MFC_MAX_CORE_BALANCE;
	else
		dev->core_balance = dev->pdata->core_balance;

	/* 1) Default core: Default core has not yet been balanced */
	if ((total_load[default_core] + curr_load) <= dev->core_balance) {
		core_num = default_core;
		goto fix_core;
	/* 2) Surplus core: Default core has been balanced already */
	} else if ((total_load[default_core] > dev->core_balance) &&
			(total_load[surplus_core] < dev->core_balance)) {
		core_num = surplus_core;
		goto fix_core;
	}

	/* 3) Core with lower load */
	if (total_load[default_core] > total_load[surplus_core])
		core_num = surplus_core;
	else
		core_num = default_core;

fix_core:
	mfc_ctx_debug(2, "[RMLB] total load: [0] %ld(%d%%), [1] %ld(%d%%), curr_load: %ld(%d%%), select core: %d\n",
			dev->core[0]->total_mb, total_load[0],
			dev->core[1]->total_mb, total_load[1],
			ctx->weighted_mb, curr_load, core_num);
	MFC_TRACE_RM("[c:%d] load [0] %ld(%d) [1] %ld(%d) curr %ld(%d) select %d\n",
			ctx->num,
			dev->core[0]->total_mb, total_load[0],
			dev->core[1]->total_mb, total_load[1],
			ctx->weighted_mb, curr_load, core_num);

	return core_num;
}

static int __mfc_rm_get_core_num(struct mfc_ctx *ctx, int curr_core_num)
{
	struct mfc_dev *dev = ctx->dev;
	int core_num;

	/* Default core according to standard */
	core_num = ctx->op_core_type;

	if (dev->debugfs.core_balance)
		dev->pdata->core_balance = dev->debugfs.core_balance;

	if (dev->pdata->core_balance == 100) {
		mfc_ctx_debug(4, "[RMLB] do not want to load balancing\n");
		if (ctx->op_core_type == MFC_OP_CORE_ALL)
			core_num = curr_core_num;
		return core_num;
	}

	/* Change core according to load */
	if (ctx->op_core_type == MFC_OP_CORE_ALL)
		core_num = __mfc_rm_get_core_num_by_load(dev, ctx, MFC_DEC_DEFAULT_CORE);

	return core_num;
}

static int __mfc_rm_move_core_open(struct mfc_ctx *ctx, int to_core_num, int from_core_num)
{
	struct mfc_dev *dev = ctx->dev;
	struct mfc_core *to_core = dev->core[to_core_num];
	struct mfc_core *from_core = dev->core[from_core_num];
	int ret = 0;

	mfc_ctx_info("[RMLB] open core changed MFC%d -> MFC%d\n",
			from_core_num, to_core_num);
	MFC_TRACE_RM("[c:%d] open core changed MFC%d -> MFC%d\n",
			ctx->num, from_core_num, to_core_num);

	ret = from_core->core_ops->instance_deinit(from_core, ctx);
	if (ret) {
		mfc_ctx_err("[RMLB] Failed to deinit\n");
		return ret;
	}

	if (from_core->sched->is_work(from_core))
		from_core->sched->queue_work(from_core);

	ctx->op_core_num[MFC_CORE_MAIN] = to_core_num;

	ret = to_core->core_ops->instance_init(to_core, ctx);
	if (ret) {
		ctx->op_core_num[MFC_CORE_MAIN] = MFC_CORE_INVALID;
		mfc_ctx_err("[RMLB] Failed to init\n");
		return ret;
	}

	return ret;
}

static int __mfc_rm_move_core_running(struct mfc_ctx *ctx, int to_core_num, int from_core_num)
{
	struct mfc_dev *dev = ctx->dev;
	struct mfc_core *to_core = dev->core[to_core_num];
	struct mfc_core *from_core = dev->core[from_core_num];
	struct mfc_core *maincore = dev->core[MFC_CORE_MAIN];
	struct mfc_core *subcore = dev->core[MFC_CORE_SUB];
	struct mfc_core_ctx *core_ctx;
	int is_to_core = 0;
	int ret = 0;

	core_ctx = from_core->core_ctx[ctx->num];
	if (!core_ctx) {
		mfc_ctx_err("there is no core_ctx\n");
		return -EINVAL;
	}

	if (!maincore || !subcore) {
		mfc_ctx_err("The core is invalid(main: %p, sub: %p)\n",
			    maincore, subcore);
		return -EINVAL;
	}

	ret = mfc_get_corelock_migrate(ctx);
	if (ret < 0) {
		mfc_err("[RMLB] failed to get corelock\n");
		return -EAGAIN;
	}

	/* 1. Change state on from_core */
	ret = mfc_core_get_hwlock_dev(maincore);
	if (ret < 0) {
		mfc_ctx_err("Failed to get hwlock of maincore\n");
		mfc_release_corelock_migrate(ctx);
		return ret;
	}

	ret = mfc_core_get_hwlock_dev(subcore);
	if (ret < 0) {
		mfc_err("Failed to get hwlock of subcore\n");
		goto err_state;
	}
	is_to_core = 1;

	if (core_ctx->state != MFCINST_RUNNING) {
		mfc_debug(3, "[RMLB] it is not running state: %d\n", core_ctx->state);
		goto err_state;
	}

	if (IS_MULTI_MODE(ctx)) {
		mfc_err("[RMLB] multi core mode couldn't migration, need to switch to single\n");
		goto err_state;
	}

	mfc_change_state(core_ctx, MFCINST_MOVE_INST);

	/* 2. Cache flush on to_core */

	if (from_core->sleep || to_core->sleep) {
		mfc_err("Failed to move inst. Sleep was called\n");
		ret = -EAGAIN;
		goto err_migrate;
	}

	ret = to_core->core_ops->instance_move_to(to_core, ctx);
	if (ret) {
		mfc_err("Failed to instance move init\n");
		goto err_migrate;
	}

	kfree(to_core->core_ctx[ctx->num]);
	ctx->op_core_num[MFC_CORE_MAIN] = MFC_CORE_INVALID;

	/* 3. Enable the clock of to_core because from_core accesses to_core */
	mfc_core_pm_clock_on(to_core, 0);

	/* 4. Set F/W and ctx address on MFC1 */
	if (ctx->is_drm)
		mfc_core_set_migration_addr(dev->core[1], ctx, dev->core[0]->drm_fw_buf.daddr,
				dev->core[0]->drm_common_ctx_buf.daddr);
	else
		mfc_core_set_migration_addr(dev->core[1], ctx, dev->core[0]->fw_buf.daddr,
				dev->core[0]->common_ctx_buf.daddr);

	/* 5. Move and close instance on from_core */
	ret = from_core->core_ops->instance_move_from(from_core, ctx);
	if (ret) {
		mfc_err("Failed to instance move\n");
		MFC_TRACE_RM("[c:%d] instance_move_from fail\n", ctx->num);
		goto err_move;
	}
	mfc_debug(3, "[RMLB] move and close instance on from_core-%d\n", from_core->id);
	MFC_TRACE_RM("[c:%d] move and close inst_no %d\n", ctx->num, core_ctx->inst_no);

	/* 6. Clean up */
	ctx->op_core_num[MFC_CORE_MAIN] = to_core->id;
	to_core->core_ctx[ctx->num] = core_ctx;
	core_ctx->core = to_core;

	from_core->sched->clear_work(from_core, core_ctx);
	from_core->core_ctx[core_ctx->num] = 0;
	mfc_core_pm_clock_off(to_core, 0);

	mfc_core_move_hwlock_ctx(to_core, from_core, core_ctx);
	mfc_core_release_hwlock_dev(subcore);
	mfc_core_release_hwlock_dev(maincore);

	mfc_change_state(core_ctx, MFCINST_RUNNING);
	mfc_qos_on(to_core, ctx);

	mfc_release_corelock_migrate(ctx);

	mfc_debug(2, "[RMLB] ctx[%d] migration finished. op_core:%d \n", ctx->num, to_core->id);

	__mfc_rm_request_butler(dev, ctx);

	return 0;

err_move:
	mfc_core_pm_clock_off(to_core, 0);
err_migrate:
	mfc_change_state(core_ctx, MFCINST_RUNNING);
err_state:
	if (is_to_core)
		mfc_core_release_hwlock_dev(subcore);
	mfc_core_release_hwlock_dev(maincore);

	mfc_release_corelock_migrate(ctx);

	return ret;
}

static struct mfc_core *__mfc_rm_switch_to_single_mode(struct mfc_ctx *ctx, int need_lock,
				enum mfc_op_core_type op_core_type)
{
	struct mfc_dev *dev = ctx->dev;
	struct mfc_core *maincore;
	struct mfc_core *subcore;
	struct mfc_core_ctx *core_ctx;
	struct mfc_buf *src_mb = NULL;
	int last_op_core, switch_single_core;
	int ret;

	maincore = mfc_get_main_core(ctx->dev, ctx);
	if (!maincore) {
		mfc_ctx_err("[RM] There is no main core\n");
		return NULL;
	}

	core_ctx = maincore->core_ctx[ctx->num];
	if (!core_ctx) {
		mfc_ctx_err("[RM] There is no main core_ctx\n");
		return NULL;
	}

	subcore = mfc_get_sub_core(ctx->dev, ctx);
	if (!subcore) {
		mfc_info("[RM] There is no sub core for switch single, use main core\n");
		return maincore;
	}

	core_ctx = subcore->core_ctx[ctx->num];
	if (!core_ctx) {
		mfc_ctx_info("[RM] There is no sub core_ctx for switch single, use main core\n");
		return maincore;
	}

	ret = mfc_core_get_hwlock_dev(maincore);
	if (ret < 0) {
		mfc_err("Failed to get main core hwlock\n");
		return NULL;
	}

	ret = mfc_core_get_hwlock_dev(subcore);
	if (ret < 0) {
		mfc_err("Failed to get sub core hwlock\n");
		mfc_core_release_hwlock_dev(maincore);
		return NULL;
	}

	if (need_lock)
		mutex_lock(&ctx->op_mode_mutex);

	if (IS_SWITCH_SINGLE_MODE(ctx) || IS_SINGLE_MODE(ctx)) {
		mfc_core_release_hwlock_dev(maincore);
		mfc_core_release_hwlock_dev(subcore);

		/*
		 * This(Here) means that it has already been switched to single mode
		 * while waiting for op_mode_mutex.
		 * Select a new maincore because the maincore may have been different
		 * from the maincore before waiting.
		 */
		maincore = mfc_get_main_core(ctx->dev, ctx);
		if (!maincore)
			mfc_err("[RM] There is no main core\n");
		if (need_lock)
			mutex_unlock(&ctx->op_mode_mutex);
		return maincore;
	}

	mfc_change_op_mode(ctx, MFC_OP_SWITCHING);

	/* need to cleanup src buffer */
	mfc_return_buf_to_ready_queue(ctx, &maincore->core_ctx[ctx->num]->src_buf_queue,
			&subcore->core_ctx[ctx->num]->src_buf_queue);
	mfc_debug(2, "[RM] op_mode %d change to switch to single\n", ctx->stream_op_mode);
	MFC_TRACE_RM("[c:%d] op_mode %d->4: Move src all\n", ctx->num, ctx->stream_op_mode);

	core_ctx = maincore->core_ctx[ctx->num];
	if (core_ctx->state == MFCINST_FINISHING) {
		mfc_change_state(core_ctx, MFCINST_RUNNING);
	} else if (core_ctx->state == MFCINST_BUF_INIT_BUT_MULTI_MODE_NOT_CHECKED_YET) {
		mfc_change_state(core_ctx, MFCINST_RUNNING);

		core_ctx = subcore->core_ctx[ctx->num];
		mfc_change_state(core_ctx, MFCINST_RUNNING);
	}

	/*
	 * Select switch to single core number
	 * If the op_core_type of the instance that caused switch_to_single
	 * is only MFC_OP_CORE_FIXED_(N), select the other core.
	 * Otherwise, select a lower load core.
	 */
	if (ctx->cmd_counter == 0)
		switch_single_core = ctx->last_op_core;
	else if ((ctx->stream_op_mode == MFC_OP_TWO_MODE2) &&
		 (ctx->curr_src_index != -1))
		switch_single_core = ctx->curr_src_index % ctx->dev->num_core;
	else if (ctx->op_core_type == MFC_OP_CORE_FIXED_0)
		switch_single_core = 0;
	else if (ctx->op_core_type == MFC_OP_CORE_FIXED_1)
		switch_single_core = 1;
	else if (op_core_type == MFC_OP_CORE_FIXED_1)
		switch_single_core = 0;
	else if (op_core_type == MFC_OP_CORE_FIXED_0)
		switch_single_core = 1;
	else
		switch_single_core = __mfc_rm_get_core_num_by_load(dev, ctx, MFC_SURPLUS_CORE);
	mfc_debug(2, "[RM] switch to single to core: %d\n", switch_single_core);
	MFC_TRACE_RM("[c:%d] switch to single to core: %d\n", ctx->num, switch_single_core);

	mfc_rm_set_core_num(ctx, switch_single_core);
	maincore = mfc_get_main_core(ctx->dev, ctx);
	if (!maincore) {
		mfc_err("[RM] There is no main core\n");
		if (need_lock)
			mutex_unlock(&ctx->op_mode_mutex);
		return NULL;
	}
	subcore = mfc_get_sub_core(dev, ctx);
	if (!subcore) {
		mfc_err("[RM] There is no sub core\n");
		if (need_lock)
			mutex_unlock(&ctx->op_mode_mutex);
		return NULL;
	}

	/* main core should have one src buffer */
	core_ctx = maincore->core_ctx[ctx->num];
	if (mfc_get_queue_count(&ctx->buf_queue_lock, &core_ctx->src_buf_queue) == 0) {
		src_mb = mfc_get_move_buf(ctx, &core_ctx->src_buf_queue,
				&ctx->src_buf_ready_queue,
				MFC_BUF_NO_TOUCH_USED, MFC_QUEUE_ADD_BOTTOM);
		if (src_mb) {
			mfc_debug(2, "[RM][BUFINFO] MFC-%d uses src index: %d(%d)\n",
					maincore->id, src_mb->vb.vb2_buf.index,
					src_mb->src_index);
			MFC_TRACE_RM("[c:%d] MFC-%d uses src index: %d(%d)\n",
					ctx->num, maincore->id, src_mb->vb.vb2_buf.index,
					src_mb->src_index);
		}
	} else {
		mfc_debug(2, "[RM][BUFINFO] MFC-%d has src buffer already\n", maincore->id);
	}

	mfc_change_op_mode(ctx, MFC_OP_SWITCH_TO_SINGLE);
	if ((ctx->stream_op_mode == MFC_OP_TWO_MODE2) && (ctx->curr_src_index != -1)) {
		last_op_core = ctx->curr_src_index % ctx->dev->num_core;
		if (last_op_core != switch_single_core) {
			mfc_debug(2, "[RM] last op core-%d but switch core-%d, should operate once with mode2\n",
					last_op_core, switch_single_core);
			mfc_change_op_mode(ctx, MFC_OP_SWITCH_BUT_MODE2);
		}
	}

	/* for check whether command is sent during switch to single */
	ctx->cmd_counter = 0;

	if (need_lock)
		mutex_unlock(&ctx->op_mode_mutex);

	mfc_core_release_hwlock_dev(maincore);
	mfc_core_release_hwlock_dev(subcore);
	mfc_qos_off(subcore, ctx);
	mfc_qos_on(maincore, ctx);

	mfc_debug(2, "[RM] switch single mode run with core%d\n", maincore->id);

	return maincore;
}

static int __mfc_rm_check_multi_core_mode(struct mfc_dev *dev, enum mfc_op_core_type op_core_type)
{
	struct mfc_core *core = NULL;
	struct mfc_core_ctx *core_ctx = NULL;
	struct mfc_ctx *ctx = NULL;
	int i;

	for (i = 0; i < MFC_NUM_CONTEXTS; i++) {
		if (test_bit(i, &dev->multi_core_inst_bits)) {
			MFC_TRACE_RM("[c:%d] multi core instance\n", i);
			ctx = dev->ctx[i];
			if (!ctx) {
				mfc_dev_err("[RM] There is no ctx\n");
				continue;
			}

			if (!IS_MULTI_MODE(ctx)) {
				mfc_ctx_debug(3, "[RM] already switched to single\n");
				continue;
			}

			if (!mfc_rm_query_state(ctx, EQUAL, MFCINST_RUNNING) &&
			    !mfc_rm_query_state(ctx, EQUAL, MFCINST_BUF_INIT_BUT_MULTI_MODE_NOT_CHECKED_YET)) {
				mfc_ctx_debug(2, "[RM] op_mode%d but setup of 2core is not yet done\n",
						ctx->op_mode);
				continue;
			}

			/* multi mode instance should be switch to single mode */
			core = __mfc_rm_switch_to_single_mode(ctx, 1, op_core_type);
			if (!core)
				return -EINVAL;

			mfc_ctx_debug(2, "[RM][2CORE] switch single for multi instance op_mode: %d\n",
					ctx->op_mode);
			MFC_TRACE_RM("[c:%d] switch to single for multi inst\n", i);

			core_ctx = core->core_ctx[ctx->num];
			if (core->sched->enqueue_work(core, core_ctx))
				core->core_ops->request_work(core, MFC_WORK_BUTLER, ctx);
		}
	}

	return 0;
}

static void __mfc_rm_move_buf_ready_set_bit(struct mfc_ctx *ctx)
{
	struct mfc_dev *dev = ctx->dev;
	struct mfc_core *core = NULL;
	struct mfc_core_ctx *core_ctx = NULL;
	struct mfc_buf *src_mb = NULL;
	unsigned int num;

	mutex_lock(&ctx->op_mode_mutex);

	/* search for next running core */
	src_mb = mfc_get_buf(ctx, &ctx->src_buf_ready_queue,
			MFC_BUF_NO_TOUCH_USED);
	if (!src_mb) {
		mfc_ctx_debug(3, "[RM][2CORE] there is no src buffer\n");
		mutex_unlock(&ctx->op_mode_mutex);
		return;
	}

	/* handle last frame with switch_to_single mode */
	if (mfc_check_mb_flag(src_mb, MFC_FLAG_LAST_FRAME)) {
		ctx->serial_src_index = 0;
		mfc_ctx_debug(2, "[RM][2CORE] EOS, reset serial src index\n");
		MFC_TRACE_RM("[c:%d] EOS: Reset serial src index\n", ctx->num);

		if (ctx->curr_src_index < src_mb->src_index -1) {
			mfc_ctx_debug(2, "[RM][2CORE] waiting src index %d, curr src index %d is working\n",
					src_mb->src_index,
					ctx->curr_src_index);
			goto butler;
		}

		core = __mfc_rm_switch_to_single_mode(ctx, 0, ctx->op_core_type);
		if (!core) {
			mutex_unlock(&ctx->op_mode_mutex);
			return;
		} else {
			mfc_ctx_debug(2, "[RM][2CORE] switch single for LAST FRAME(EOS) op_mode: %d\n",
					ctx->op_mode);
		}
		goto butler;
	}

	if (ctx->curr_src_index == src_mb->src_index - 1) {
		num = src_mb->src_index % dev->num_core;
		core = dev->core[num];
		mfc_ctx_debug(2, "[RM][2CORE] src index %d(%d) run in MFC-%d, curr: %d\n",
				src_mb->vb.vb2_buf.index,
				src_mb->src_index, num,
				ctx->curr_src_index);
	} else {
		mfc_ctx_debug(2, "[RM][2CORE] waiting src index %d, curr src index %d is working\n",
				src_mb->src_index,
				ctx->curr_src_index);
		goto butler;
	}

	/* move src buffer to src_buf_queue from src_buf_ready_queue */
	core_ctx = core->core_ctx[ctx->num];
	src_mb = mfc_get_move_buf(ctx, &core_ctx->src_buf_queue,
			&ctx->src_buf_ready_queue,
			MFC_BUF_NO_TOUCH_USED, MFC_QUEUE_ADD_BOTTOM);
	if (src_mb) {
		mfc_debug(2, "[RM][BUFINFO] MFC-%d uses src index: %d(%d)\n",
				core->id, src_mb->vb.vb2_buf.index,
				src_mb->src_index);
		MFC_TRACE_RM("[c:%d] READY: Move src[%d] to MFC-%d\n",
				ctx->num, src_mb->src_index, core->id);
	}

butler:
	mutex_unlock(&ctx->op_mode_mutex);
	__mfc_rm_request_butler(dev, ctx);
}

void __mfc_rm_migrate_all_to_one_core(struct mfc_dev *dev)
{
	int i, ret, total_load[MFC_NUM_CORE];
	struct mfc_ctx *tmp_ctx, *ctx;
	unsigned long flags;
	int core_num, to_core_num, from_core_num;
	int op_core_fixed0 = 0, op_core_fixed1 = 0;
	int op_core0 = 0, op_core1 = 0;

	if (dev->move_ctx_cnt) {
		mfc_dev_debug(4, "[RMLB] instance migration working yet, move_ctx: %d\n",
				dev->move_ctx_cnt);
		return;
	}

	spin_lock_irqsave(&dev->ctx_list_lock, flags);

	if (list_empty(&dev->ctx_list)) {
		mfc_dev_debug(2, "[RMLB] there is no ctx for load balancing\n");
		spin_unlock_irqrestore(&dev->ctx_list_lock, flags);
		return;
	}

	list_for_each_entry(tmp_ctx, &dev->ctx_list, list) {
		if (!IS_SINGLE_MODE(tmp_ctx)) {
			mfc_dev_info("[RMLB] there is multi core ctx:%d, op_mode :%d\n",
					tmp_ctx->num, tmp_ctx->op_mode);
			MFC_TRACE_RM("there is multi core ctx:%d, op_mode :%d\n",
					tmp_ctx->num, tmp_ctx->op_mode);
			spin_unlock_irqrestore(&dev->ctx_list_lock, flags);
			return;
		}
		/* op core type */
		if (tmp_ctx->op_core_type == MFC_OP_CORE_FIXED_0)
			op_core_fixed0++;
		else if (tmp_ctx->op_core_type == MFC_OP_CORE_FIXED_1)
			op_core_fixed1++;
		/* op main core */
		if (tmp_ctx->op_core_num[MFC_CORE_MAIN] == MFC_DEC_DEFAULT_CORE)
			op_core0++;
		else if (tmp_ctx->op_core_num[MFC_CORE_MAIN] == MFC_SURPLUS_CORE)
			op_core1++;
		mfc_dev_debug(3, "[RMLB] ctx[%d] op_core_type: %d (fixed0: %d, fixed1: %d)\n",
				tmp_ctx->num, tmp_ctx->op_core_type,
				op_core_fixed0, op_core_fixed1);
	}

	if (op_core_fixed0 && op_core_fixed1) {
		mfc_dev_info("[RMLB] all instance should be work with fixed core\n");
		spin_unlock_irqrestore(&dev->ctx_list_lock, flags);
		return;
	} else if ((!op_core_fixed0 && !op_core_fixed1) &&
			((op_core0 && !op_core1) || (!op_core0 && op_core1))) {
		mfc_dev_debug(3, "[RMLB] all instance already worked in one core\n");
		spin_unlock_irqrestore(&dev->ctx_list_lock, flags);
		return;
	} else if (op_core_fixed0 && !op_core_fixed1) {
		core_num = MFC_OP_CORE_FIXED_0;
	} else {
		core_num = MFC_OP_CORE_FIXED_1;
	}

	for (i = 0; i < dev->num_core; i++) {
		total_load[i] = dev->core[i]->total_mb * 100 / dev->core[i]->core_pdata->max_mb;
		mfc_dev_debug(3, "[RMLB] core-%d total load: %d%% (mb: %lu)\n",
				i, total_load[i], dev->core[i]->total_mb);
		dev->core[i]->total_mb = 0;
	}

	mfc_dev_info("[RMLB] load balance all to core-%d for multi core mode instance\n",
			core_num);
	MFC_TRACE_RM("load balance all to core-%d\n", core_num);
	dev->move_ctx_cnt = 0;
	list_for_each_entry(tmp_ctx, &dev->ctx_list, list) {
		if (tmp_ctx->op_core_num[MFC_CORE_MAIN] != core_num) {
			mfc_dev_debug(3, "[RMLB] ctx[%d] move to core-%d\n",
					tmp_ctx->num, core_num);
			MFC_TRACE_RM("[c:%d] move to core-%d (mb: %lu)\n",
					tmp_ctx->num, core_num, tmp_ctx->weighted_mb);
			tmp_ctx->move_core_num[MFC_CORE_MAIN] = core_num;
			dev->move_ctx[dev->move_ctx_cnt++] = tmp_ctx;
			__mfc_rm_update_core_load(tmp_ctx, 1, 0);
		} else {
			mfc_dev_debug(3, "[RMLB] ctx[%d] keep core%d (mb: %lu)\n",
					tmp_ctx->num, core_num, tmp_ctx->weighted_mb);
			__mfc_rm_update_core_load(tmp_ctx, 0, 0);
		}
	}
	spin_unlock_irqrestore(&dev->ctx_list_lock, flags);

	/*
	 * For sequential work, migration is performed directly without queue_work.
	 * This is because switch_to_single() should get the hwlock
	 * after migration_to_one_core().
	 */
	for (i = 0; i < dev->move_ctx_cnt; i++) {
		mutex_lock(&dev->mfc_migrate_mutex);
		ctx = dev->move_ctx[i];
		dev->move_ctx[i] = NULL;

		from_core_num = ctx->op_core_num[MFC_CORE_MAIN];
		to_core_num = ctx->move_core_num[MFC_CORE_MAIN];
		mfc_ctx_debug(2, "[RMLB] ctx[%d] will be moved MFC%d -> MFC%d\n",
				ctx->num, from_core_num, to_core_num);
		MFC_TRACE_RM("[c:%d] will be moved MFC%d -> MFC%d\n",
				ctx->num, from_core_num, to_core_num);
		ret = __mfc_rm_move_core_running(ctx, to_core_num, from_core_num);
		if (ret) {
			mfc_ctx_info("[RMLB] migration stopped by ctx[%d]\n",
					ctx->num);
			MFC_TRACE_RM("migration fail by ctx[%d]\n", ctx->num);
		}
		mutex_unlock(&dev->mfc_migrate_mutex);
	}

	mfc_dev_debug(2, "[RMLB] all instance migration finished\n");
	dev->move_ctx_cnt = 0;
}

static void __mfc_rm_guarantee_init_buf(struct mfc_ctx *ctx)
{
	struct mfc_dev *dev = ctx->dev;
	struct mfc_core *maincore;
	struct mfc_core *subcore;
	struct mfc_core_ctx *core_ctx;
	int ret;

	/* Check only ready, do not set bit to work_bits */
	if (mfc_is_queue_count_same(&ctx->buf_queue_lock, &ctx->dst_buf_queue, 0)) {
		mfc_ctx_debug(3, "[RM] ctx is not ready for INIT_BUF\n");
		return;
	}

	maincore = mfc_get_main_core(ctx->dev, ctx);
	if (!maincore) {
		mfc_ctx_err("[RM] There is no main core\n");
		return;
	}

	subcore = mfc_get_sub_core(ctx->dev, ctx);
	if (!subcore) {
		mfc_ctx_err("[RM] There is no sub core for switch single\n");
		return;
	}

	/*
	 * No other command should be sent
	 * while sending INIT_BUFFER command to 2 core in mode2
	 */
	ret = mfc_core_get_hwlock_dev(maincore);
	if (ret < 0) {
		mfc_ctx_err("Failed to get main core hwlock\n");
		return;
	}

	ret = mfc_core_get_hwlock_dev(subcore);
	if (ret < 0) {
		mfc_ctx_err("Failed to get sub core hwlock\n");
		mfc_core_release_hwlock_dev(maincore);
		return;
	}

	/* main core ready set bit*/
	core_ctx = maincore->core_ctx[ctx->num];
	if (!maincore->sched->enqueue_work(maincore, core_ctx)) {
		mfc_core_release_hwlock_dev(maincore);
		mfc_core_release_hwlock_dev(subcore);
		return;
	}

	/* sub core ready set bit*/
	core_ctx = subcore->core_ctx[ctx->num];
	if (IS_TWO_MODE2(ctx)) {
		if (!subcore->sched->enqueue_work(subcore, core_ctx)) {
			mfc_core_release_hwlock_dev(maincore);
			mfc_core_release_hwlock_dev(subcore);
			return;
		}
	}

	/*
	 * In order not to perform MFC_OFF register control(HWACG) when multi core mode,
	 * synchronize MFC_OFF register to zero.
	 */
	mfc_core_mfc_on(maincore);
	mfc_core_mfc_on(subcore);

	/* multi_core_inst_bits is set after completing SEQ_START on both cores */
	set_bit(ctx->num, &dev->multi_core_inst_bits);

	/*
	 * If Normal <-> Secure switch,
	 * sub core need to cache flush without other command.
	 */
	if (IS_TWO_MODE1(ctx)) {
		if (subcore->curr_core_ctx_is_drm != ctx->is_drm) {
			mfc_debug(2, "[RM] sub core need to cache flush for op_mode 1\n");
			subcore->core_ops->instance_cache_flush(subcore, ctx);
		}
	}

	MFC_TRACE_RM("[c:%d] op_mode %d try INIT_BUFFER\n", ctx->num, ctx->op_mode);
	mfc_debug(3, "[RM] op_mode %d try INIT_BUFFER\n", ctx->op_mode);
	ret = maincore->core_ops->instance_init_buf(maincore, ctx);
	if (ret < 0) {
		mfc_err("failed main core init buffer\n");
		mfc_core_release_hwlock_dev(maincore);
		mfc_core_release_hwlock_dev(subcore);
		return;
	}

	if (IS_TWO_MODE2(ctx)) {
		ret = subcore->core_ops->instance_init_buf(subcore, ctx);
		if (ret < 0) {
			mfc_err("failed sub core init buffer\n");
			mfc_core_release_hwlock_dev(maincore);
			mfc_core_release_hwlock_dev(subcore);
			return;
		}
	}
	/*
	 * When mode1, sub core run without command but
	 * clk_enable is needed because clk mux set to OSC by clk_disable.
	 * Also, turn off the idle timer because hw_run_bits are not set.
	 */
	if (IS_TWO_MODE1(ctx)) {
		mfc_change_state(core_ctx, MFCINST_BUF_INIT_BUT_MULTI_MODE_NOT_CHECKED_YET);
		del_timer(&subcore->mfc_idle_timer);
		mfc_core_pm_clock_on(subcore, 0);
	}

	if (dev->num_inst == 1) {
		core_ctx = maincore->core_ctx[ctx->num];
		mfc_change_state(core_ctx, MFCINST_RUNNING);

		core_ctx = subcore->core_ctx[ctx->num];
		mfc_change_state(core_ctx, MFCINST_RUNNING);
	}

	mfc_core_release_hwlock_dev(maincore);
	mfc_core_release_hwlock_dev(subcore);

	mfc_debug(2, "[RM][2CORE] multi core mode setup done, check multi inst\n");
	MFC_TRACE_RM("[c:%d] mode2 setup done\n", ctx->num);
	if (dev->num_inst > 1) {
		/*
		 * If the load is already distributed in two cores,
		 * need to move to one core for multi core mode(8K) instance.
		 */
		if (IS_8K_RES(ctx) && (dev->num_inst > 2))
			__mfc_rm_migrate_all_to_one_core(dev);
		__mfc_rm_check_multi_core_mode(dev, ctx->op_core_type);

		__mfc_rm_request_butler(dev, NULL);
	}
}

static void __mfc_rm_move_buf_request_work(struct mfc_ctx *ctx, enum mfc_request_work work)
{
	struct mfc_dev *dev = ctx->dev;
	struct mfc_core *core;
	struct mfc_core_ctx *core_ctx;
	int i;

	if (mfc_rm_query_state(ctx, EQUAL, MFCINST_RUNNING)) {
		/* search for next running core and running */
		__mfc_rm_move_buf_ready_set_bit(ctx);
	} else if (mfc_rm_query_state(ctx, EQUAL, MFCINST_HEAD_PARSED)) {
		__mfc_rm_guarantee_init_buf(ctx);
	} else {
		/*
		 * If it is not RUNNING,
		 * each core can work a given job individually.
		 */
		for (i = 0; i < MFC_CORE_TYPE_NUM; i++) {
			if (ctx->op_core_num[i] == MFC_CORE_INVALID)
				break;

			core = dev->core[ctx->op_core_num[i]];
			if (!core) {
				mfc_ctx_err("[RM] There is no core[%d]\n",
						ctx->op_core_num[i]);
				return;
			}
			mfc_ctx_debug(2, "[RM] request work to MFC-%d\n", core->id);

			core_ctx = core->core_ctx[ctx->num];
			if (!core_ctx || (core_ctx && core_ctx->state < MFCINST_GOT_INST))
				continue;

			if (core->sched->enqueue_work(core, core_ctx))
				if (core->core_ops->request_work(core, work, ctx))
					mfc_debug(3, "[RM] failed to request_work\n");
		}
	}

	return;
}

static void __mfc_rm_rearrange_cpb(struct mfc_core *maincore, struct mfc_core_ctx *core_ctx)
{
	struct mfc_ctx *ctx = core_ctx->ctx;
	struct mfc_dev *dev = ctx->dev;
	struct mfc_buf *src_mb;
	unsigned long flags;

	/* re-arrangement cpb for mode2 */
	mfc_debug(2, "[RM][2CORE] main core-%d src count %d\n",
			maincore->id, core_ctx->src_buf_queue.count);
	MFC_TRACE_RM("[c:%d] main core-%d src count %d\n", ctx->num,
			maincore->id, core_ctx->src_buf_queue.count);

	mfc_move_buf_all(ctx, &ctx->src_buf_ready_queue,
			&core_ctx->src_buf_queue, MFC_QUEUE_ADD_TOP);

	mfc_debug(2, "[RM][2CORE] ready %d maincore %d\n",
			ctx->src_buf_ready_queue.count,
			maincore->core_ctx[ctx->num]->src_buf_queue.count);
	MFC_TRACE_RM("[c:%d] ready %d maincore %d\n", ctx->num,
			ctx->src_buf_ready_queue.count,
			maincore->core_ctx[ctx->num]->src_buf_queue.count);

	ctx->serial_src_index = 0;
	ctx->curr_src_index = -1;

	spin_lock_irqsave(&ctx->buf_queue_lock, flags);
	if (!list_empty(&ctx->src_buf_ready_queue.head)) {
		list_for_each_entry(src_mb, &ctx->src_buf_ready_queue.head, list) {
			if (src_mb) {
				mfc_debug(2, "[RM][2CORE] src index(%d) changed to %d\n",
						src_mb->src_index, ctx->serial_src_index);
				MFC_TRACE_RM("[c:%d] src index(%d) changed to %d\n",
						ctx->num, src_mb->src_index,
						ctx->serial_src_index);
				src_mb->src_index = ctx->serial_src_index++;
				src_mb->used = 0;
			}
		}
	} else {
		mfc_debug(2, "[RM][2CORE] there is no src in ready(%d)\n",
				ctx->src_buf_ready_queue.count);
		MFC_TRACE_RM("[c:%d] there is no src in ready(%d)\n", ctx->num,
				ctx->src_buf_ready_queue.count);
	}
	spin_unlock_irqrestore(&ctx->buf_queue_lock, flags);
}

static int __mfc_rm_switch_to_multi_mode(struct mfc_ctx *ctx)
{
	struct mfc_dev *dev = ctx->dev;
	struct mfc_core *maincore;
	struct mfc_core *subcore;
	struct mfc_core_ctx *core_ctx;
	int ret;
	struct mfc_core *changed_subcore;

	maincore = mfc_get_main_core(ctx->dev, ctx);
	if (!maincore) {
		mfc_ctx_err("[RM] There is no main core\n");
		return -EINVAL;
	}

	core_ctx = maincore->core_ctx[ctx->num];
	if (!core_ctx) {
		mfc_ctx_err("[RM] There is no main core_ctx\n");
		return -EINVAL;
	}

	if (!maincore->sched->enqueue_work(maincore, core_ctx)) {
		mfc_ctx_debug(2, "[RM] there is no work to do after switch_to_multi\n");
		MFC_TRACE_RM("no work after swith to multi\n");
		return -EINVAL;
	}

	subcore = mfc_get_sub_core(ctx->dev, ctx);
	if (!subcore) {
		mfc_ctx_err("[RM] There is no sub core for switch single\n");
		return -EINVAL;
	}

	ret = mfc_core_get_hwlock_dev(maincore);
	if (ret < 0) {
		mfc_ctx_err("Failed to get main core hwlock\n");
		return -EINVAL;
	}

	ret = mfc_core_get_hwlock_dev(subcore);
	if (ret < 0) {
		mfc_ctx_err("Failed to get sub core hwlock\n");
		mfc_core_release_hwlock_dev(maincore);
		return -EINVAL;
	}

	mutex_lock(&ctx->op_mode_mutex);

	if (ctx->op_mode == MFC_OP_SWITCH_BUT_MODE2) {
		mfc_ctx_debug(2, "[RMLB] just go to mode2\n");
	} else {
		if (!ctx->cmd_counter || ctx->handle_drc_multi_mode) {
			mfc_ctx_err("Skip op mode change, counter(%d), drc_multi(%d)",
				ctx->cmd_counter, ctx->handle_drc_multi_mode);
			mfc_core_release_hwlock_dev(maincore);
			mfc_core_release_hwlock_dev(subcore);
			mutex_unlock(&ctx->op_mode_mutex);
			__mfc_rm_request_butler(ctx->dev, ctx);
			return -EINVAL;
		}

		mfc_change_op_mode(ctx, MFC_OP_SWITCHING);
		__mfc_rm_rearrange_cpb(maincore, core_ctx);
	}

	/* main core number of multi core mode should MFC-0 */
	mfc_rm_set_core_num(ctx, MFC_DEC_DEFAULT_CORE);

	/* Change done, it will be work with multi core mode */
	mfc_change_op_mode(ctx, ctx->stream_op_mode);
	mfc_ctx_debug(2, "[RM][2CORE] reset multi core op_mode: %d\n", ctx->op_mode);

	changed_subcore = mfc_get_sub_core(ctx->dev, ctx);
	if (!changed_subcore) {
		mfc_ctx_err("[RM] There is no sub core for flushing context\n");
		mutex_unlock(&ctx->op_mode_mutex);
		mfc_core_release_hwlock_dev(maincore);
		mfc_core_release_hwlock_dev(subcore);
		return -EINVAL;
	}
	mfc_core_clear_main_core_context_flush_done(changed_subcore);

	/* for check whether command is sent during switch to multi */
	ctx->cmd_counter = 0;

	mutex_unlock(&ctx->op_mode_mutex);

	mfc_core_release_hwlock_dev(maincore);
	mfc_core_release_hwlock_dev(subcore);
	mfc_qos_on(maincore, ctx);
	mfc_qos_on(subcore, ctx);

	__mfc_rm_move_buf_ready_set_bit(ctx);

	return 0;
}

static void __mfc_rm_check_instance(struct mfc_ctx *ctx)
{
	struct mfc_dev *dev = ctx->dev;
	int ret;

	if (!IS_MULTI_CORE_DEVICE(dev))
		return;

	if (dev->num_inst == 1 && IS_SWITCH_SINGLE_MODE(ctx)
			&& !(IS_VP9_DEC(ctx) && ctx->is_10bit)) {
		/*
		 * If there is only one instance and it is still switch to single mode,
		 * switch to multi core mode again.
		 */
		ret = __mfc_rm_switch_to_multi_mode(ctx);
		if (ret)
			mfc_ctx_info("[RM] Keep switch to single mode\n");
	} else if (dev->num_inst > 1) {
		/*
		 * If there are more than one instance and it is still multi core mode,
		 * switch to single mode.
		 */
		ret = __mfc_rm_check_multi_core_mode(dev, ctx->op_core_type);
		if (ret < 0)
			mfc_ctx_err("[RM] failed multi core instance switching\n");
	}
}

void mfc_rm_migration_worker(struct work_struct *work)
{
	struct mfc_dev *dev;
	struct mfc_ctx *ctx;
	int to_core_num, from_core_num;
	int i, ret = 0;

	dev = container_of(work, struct mfc_dev, migration_work);

	for (i = 0; i < dev->move_ctx_cnt; i++) {
		mutex_lock(&dev->mfc_migrate_mutex);
		ctx = dev->move_ctx[i];
		dev->move_ctx[i] = NULL;

		/*
		 * If one instance fails migration,
		 * the rest of instnaces will not migrate.
		 */
		if (ret || !ctx) {
			MFC_TRACE_RM("migration fail\n");
			mutex_unlock(&dev->mfc_migrate_mutex);
			continue;
		}

		if (IS_SWITCH_SINGLE_MODE(ctx)) {
			mutex_unlock(&dev->mfc_migrate_mutex);
			mfc_ctx_debug(2, "[RMLB][2CORE] ctx[%d] will change op_mode: %d -> %d\n",
					ctx->num, ctx->op_mode, ctx->stream_op_mode);
			MFC_TRACE_RM("[c:%d] will change op_mode: %d -> %d\n",
					ctx->num, ctx->op_mode, ctx->stream_op_mode);
			ret = __mfc_rm_switch_to_multi_mode(ctx);
			if (dev->move_ctx_cnt > 1) {
				mfc_ctx_err("[RMLB] there shouldn't be another instance because of mode2\n");
				MFC_TRACE_RM("[c:%d] no another inst for mode2\n", ctx->num);
				ret = -EINVAL;
			}
			continue;
		}

		from_core_num = ctx->op_core_num[MFC_CORE_MAIN];
		to_core_num = ctx->move_core_num[MFC_CORE_MAIN];
		mfc_ctx_debug(2, "[RMLB] ctx[%d] will be moved MFC%d -> MFC%d\n",
				ctx->num, from_core_num, to_core_num);
		MFC_TRACE_RM("[c:%d] will be moved MFC%d -> MFC%d\n",
				ctx->num, from_core_num, to_core_num);
		ret = __mfc_rm_move_core_running(ctx, to_core_num, from_core_num);
		if (ret) {
			mfc_ctx_info("[RMLB] migration stopped by ctx[%d]\n",
					ctx->num);
			MFC_TRACE_RM("migration fail by ctx[%d]\n", ctx->num);
		}
		mutex_unlock(&dev->mfc_migrate_mutex);
	}

	mfc_dev_debug(2, "[RMLB] all instance migration finished\n");
	dev->move_ctx_cnt = 0;

	__mfc_rm_request_butler(dev, NULL);
}

static int __mfc_rm_load_delete(struct mfc_ctx *ctx)
{
	struct mfc_dev *dev = ctx->dev;
	struct mfc_ctx *mfc_ctx, *tmp_ctx;

	list_for_each_entry_safe(mfc_ctx, tmp_ctx, &dev->ctx_list, list) {
		if (mfc_ctx == ctx) {
			list_del(&mfc_ctx->list);
			mfc_ctx_debug(3, "[RMLB] ctx[%d] is deleted from list\n", ctx->num);
			MFC_TRACE_RM("[c:%d] load delete\n", ctx->num);
			return 0;
		}
	}

	return 1;
}

static int __mfc_rm_load_add(struct mfc_ctx *ctx)
{
	struct mfc_dev *dev = ctx->dev;
	struct mfc_ctx *tmp_ctx;

	/* list create */
	if (list_empty(&dev->ctx_list)) {
		list_add(&ctx->list, &dev->ctx_list);
		MFC_TRACE_RM("[c:%d] load add first\n", ctx->num);
		return 1;
	}

	/* If ctx has already added, delete for reordering */
	__mfc_rm_load_delete(ctx);

	/* dev->ctx_list is aligned in descending order of load */
	list_for_each_entry_reverse(tmp_ctx, &dev->ctx_list, list) {
		if (tmp_ctx->weighted_mb > ctx->weighted_mb) {
			list_add(&ctx->list, &tmp_ctx->list);
			mfc_ctx_debug(3, "[RMLB] ctx[%d] is added to list\n", ctx->num);
			MFC_TRACE_RM("[c:%d] load add\n", ctx->num);
			return 0;
		}
	}

	/* add to the front of dev->list */
	list_add(&ctx->list, &dev->ctx_list);
	mfc_ctx_debug(3, "[RMLB] ctx[%d] is added to list\n", ctx->num);
	MFC_TRACE_RM("[c:%d] load add\n", ctx->num);

	return 0;
}

int __mfc_rm_check_load_balancing_condition(struct mfc_ctx *ctx, int load_add)
{
	struct mfc_dev *dev = ctx->dev;
	int i;

	if (!IS_MULTI_CORE_DEVICE(dev)) {
		mfc_ctx_debug(4, "[RMLB] it is not multi core device\n");
		return 1;
	}

	if (!ctx->src_ts.ts_is_full && (load_add == MFC_RM_LOAD_ADD)) {
		mfc_ctx_debug(2, "[RMLB] instance load is not yet fixed\n");
		return 1;
	}

	if (ctx->boosting_time && (load_add == MFC_RM_LOAD_ADD)) {
		mfc_ctx_debug(2, "[RMLB] instance is boosting\n");
		return 1;
	}

	if (dev->move_ctx_cnt || (load_add == MFC_RM_LOAD_DELETE) ||
			((dev->num_inst == 1) && (load_add == MFC_RM_LOAD_ADD))) {
		mfc_ctx_debug(4, "[RMLB] instance migration isn't need (num_inst: %d, move_ctx: %d)\n",
				dev->num_inst, dev->move_ctx_cnt);
		return 1;
	}

	if (list_empty(&dev->ctx_list)) {
		for (i = 0; i < dev->num_core; i++)
			dev->core[i]->total_mb = 0;
		mfc_ctx_debug(2, "[RMLB] there is no ctx for load balancing\n");
		return 1;
	}

	return 0;
}

void mfc_rm_load_balancing(struct mfc_ctx *ctx, int load_add)
{
	struct mfc_dev *dev = ctx->dev;
	struct mfc_ctx *tmp_ctx;
	unsigned long flags;
	int i, core_num, ret = 0;

	if (dev->pdata->core_balance == 100) {
		mfc_ctx_debug(4, "[RMLB] do not want to load balancing\n");
		return;
	}

	spin_lock_irqsave(&dev->ctx_list_lock, flags);
	if (load_add == MFC_RM_LOAD_ADD)
		ret = __mfc_rm_load_add(ctx);
	else
		ret = __mfc_rm_load_delete(ctx);
	if (ret) {
		spin_unlock_irqrestore(&dev->ctx_list_lock, flags);
		return;
	}

	/* check the MFC IOVA and control lazy unmap */
	mfc_check_iova(dev);

	/* check if load balancing is not required */
	if (__mfc_rm_check_load_balancing_condition(ctx, load_add)) {
		spin_unlock_irqrestore(&dev->ctx_list_lock, flags);
		return;
	}

	/* Clear total mb each core for load re-calculation */
	for (i = 0; i < dev->num_core; i++)
		dev->core[i]->total_mb = 0;

	/* 1) Load balancing of instance with fixed core */
	list_for_each_entry(tmp_ctx, &dev->ctx_list, list) {
		if (tmp_ctx->idle_mode == MFC_IDLE_MODE_IDLE) {
			mfc_ctx_debug(3, "[RMLB][MFCIDLE] idle ctx[%d] excluded from load balancing\n",
					tmp_ctx->num);
			continue;
		}
		if ((tmp_ctx->op_core_type == MFC_OP_CORE_FIXED_0) ||
				(tmp_ctx->op_core_type == MFC_OP_CORE_FIXED_1))
			__mfc_rm_update_core_load(tmp_ctx, 0, 0);
	}

	/* 2) Load balancing of instance with not-fixed core */
	list_for_each_entry(tmp_ctx, &dev->ctx_list, list) {
		if (tmp_ctx->idle_mode == MFC_IDLE_MODE_IDLE) {
			mfc_ctx_debug(3, "[RMLB][MFCIDLE] idle ctx[%d] excluded from load balancing\n",
					tmp_ctx->num);
			continue;
		}
		if (tmp_ctx->op_core_type != MFC_OP_CORE_ALL) {
			mfc_ctx_debug(3, "[RMLB] fixed core ctx[%d] can't be moved\n",
					tmp_ctx->num);
			continue;
		}

		if (IS_MULTI_MODE(tmp_ctx)) {
			__mfc_rm_update_core_load(tmp_ctx, 0, 1);
			continue;
		} else if (IS_SWITCH_SINGLE_MODE(tmp_ctx) && (dev->num_inst == 1)
				&& !(IS_VP9_DEC(tmp_ctx) && tmp_ctx->is_10bit)) {
			mfc_ctx_debug(2, "[RMLB] ctx[%d] can be changed to mode%d\n",
					tmp_ctx->num, tmp_ctx->stream_op_mode);
			MFC_TRACE_RM("[c:%d] can be changed to mode%d\n",
					tmp_ctx->num, tmp_ctx->stream_op_mode);
			dev->move_ctx[dev->move_ctx_cnt++] = tmp_ctx;
			__mfc_rm_update_core_load(tmp_ctx, 0, 1);
			continue;
		}

		core_num = __mfc_rm_get_core_num_by_load(dev, tmp_ctx, MFC_DEC_DEFAULT_CORE);
		if (IS_SWITCH_SINGLE_MODE(tmp_ctx) ||
				(core_num == tmp_ctx->op_core_num[MFC_CORE_MAIN])) {
			mfc_ctx_debug(3, "[RMLB] ctx[%d] keep core%d\n", tmp_ctx->num,
					tmp_ctx->op_core_num[MFC_CORE_MAIN]);
			__mfc_rm_update_core_load(tmp_ctx, 0, 0);
		} else {
			/* Instance should move */
			mfc_ctx_debug(3, "[RMLB] ctx[%d] move to core-%d\n", tmp_ctx->num, core_num);
			MFC_TRACE_RM("[c:%d] move to core-%d\n", tmp_ctx->num, core_num);
			tmp_ctx->move_core_num[MFC_CORE_MAIN] = core_num;
			dev->move_ctx[dev->move_ctx_cnt++] = tmp_ctx;
			__mfc_rm_update_core_load(tmp_ctx, 1, 0);
		}
	}

	/* For debugging */
	mfc_ctx_debug(3, "[RMLB] ===================ctx list===================\n");
	list_for_each_entry(tmp_ctx, &dev->ctx_list, list)
		mfc_show_ctx_info(tmp_ctx);

	mfc_ctx_debug(3, "[RMLB] >>>> core balance %d%%\n", dev->core_balance);
	for (i = 0; i < dev->num_core; i++)
		mfc_ctx_debug(3, "[RMLB] >> MFC-%d total load: %lu%%\n", i,
				dev->core[i]->total_mb * 100 / dev->core[i]->core_pdata->max_mb);
	mfc_ctx_debug(3, "[RMLB] ==============================================\n");

	spin_unlock_irqrestore(&dev->ctx_list_lock, flags);

	if (dev->move_ctx_cnt)
		queue_work(dev->migration_wq, &dev->migration_work);

	return;
}

int mfc_rm_instance_init(struct mfc_dev *dev, struct mfc_ctx *ctx)
{
	struct mfc_core *core;
	int num_qos_steps;
	int i, ret;
	enum mfc_fw_status fw_status;

	mfc_ctx_debug_enter();

	mfc_get_corelock_ctx(ctx);

	/*
	 * The FW memory for all cores is allocated in advance.
	 * (Only once at first time)
	 * Because FW base address should be the lowest address
	 * than all DVA that FW approaches.
	 */
	for (i = 0; i < dev->num_core; i++) {
		core = dev->core[i];
		if (!core) {
			mfc_ctx_err("[RM] There is no MFC-%d\n", i);
			continue;
		}

		if (!(core->fw.status & MFC_FW_ALLOC)) {
			ret = mfc_alloc_firmware(core);
			if (ret)
				goto err_inst_init;
		}

		fw_status = ctx->is_drm ? core->fw.drm_status : core->fw.status;
		if (!(fw_status & MFC_CTX_ALLOC)) {
			ret = mfc_alloc_common_context(core, ctx->is_drm);
			if (ret)
				goto err_inst_init;
		}
	}

	mfc_change_op_mode(ctx, MFC_OP_SINGLE);
	ctx->op_core_type = MFC_OP_CORE_NOT_FIXED;
	if (ctx->type == MFCINST_DECODER)
		ctx->op_core_num[MFC_CORE_MAIN] = MFC_DEC_DEFAULT_CORE;
	else
		ctx->op_core_num[MFC_CORE_MAIN] = MFC_ENC_DEFAULT_CORE;

	core = mfc_get_main_core(dev, ctx);
	if (!core) {
		mfc_ctx_err("[RM] There is no main core\n");
		ret = -EINVAL;
		goto err_inst_init;
	}

	mfc_ctx_debug(2, "[RM] init instance core-%d\n",
			ctx->op_core_num[MFC_CORE_MAIN]);
	ret = core->core_ops->instance_init(core, ctx);
	if (ret) {
		ctx->op_core_num[MFC_CORE_MAIN] = MFC_CORE_INVALID;
		mfc_ctx_err("[RM] Failed to init\n");
	}

	/*
	 * QoS portion data should be allocated
	 * only once per instance after maincore is determined.
	 */
	if (ctx->type == MFCINST_ENCODER)
		num_qos_steps = core->core_pdata->num_encoder_qos_steps;
	else
		num_qos_steps = core->core_pdata->num_default_qos_steps;
	ctx->mfc_qos_portion = vmalloc(sizeof(unsigned int) * num_qos_steps);
	if (!ctx->mfc_qos_portion)
		mfc_ctx_err("failed to allocate qos portion data\n");

err_inst_init:
	mfc_release_corelock_ctx(ctx);

	mfc_ctx_debug_leave();

	return ret;
}

int mfc_rm_instance_deinit(struct mfc_dev *dev, struct mfc_ctx *ctx)
{
	struct mfc_core *core = NULL, *subcore;
	int i, ret = 0;

	mfc_ctx_debug_enter();

	mfc_get_corelock_ctx(ctx);

	/* reset original stream mode */
	mutex_lock(&ctx->op_mode_mutex);
	if (IS_SWITCH_SINGLE_MODE(ctx)) {
		mfc_rm_set_core_num(ctx, MFC_DEC_DEFAULT_CORE);
		mfc_change_op_mode(ctx, ctx->stream_op_mode);
	}
	mutex_unlock(&ctx->op_mode_mutex);

	if (IS_TWO_MODE1(ctx)) {
		subcore = mfc_get_sub_core(dev, ctx);
		if (!subcore)
			mfc_ctx_err("[RM] There is no sub core for clock off\n");
		else
			mfc_core_pm_clock_off(subcore, 0);
	}

	for (i = (MFC_CORE_TYPE_NUM - 1); i >= 0; i--) {
		if (ctx->op_core_num[i] == MFC_CORE_INVALID)
			continue;

		core = dev->core[ctx->op_core_num[i]];
		if (!core) {
			mfc_ctx_err("[RM] There is no core[%d]\n",
					ctx->op_core_num[i]);
			ret = -EINVAL;
			goto err_inst_deinit;
		}

		mfc_core_debug(2, "[RM] core%d will be deinit, ctx[%d]\n",
				i, ctx->num);
		ret = core->core_ops->instance_deinit(core, ctx);
		if (ret)
			mfc_core_err("[RM] Failed to deinit\n");
	}

	clear_bit(ctx->num, &dev->multi_core_inst_bits);
	mfc_change_op_mode(ctx, MFC_OP_SINGLE);
	ctx->op_core_type = MFC_OP_CORE_NOT_FIXED;

err_inst_deinit:
	if (core)
		mfc_qos_get_portion(core, ctx);
	vfree(ctx->mfc_qos_portion);
	mfc_release_corelock_ctx(ctx);

	mfc_ctx_debug_leave();

	return ret;
}

int mfc_rm_instance_open(struct mfc_dev *dev, struct mfc_ctx *ctx)
{
	struct mfc_core *core;
	int ret = 0, core_num;
	int is_corelock = 0;

	mfc_ctx_debug_enter();

	ctx->op_core_type = dev->pdata->mfc_resource[ctx->codec_mode].op_core_type;
	mfc_qos_get_weighted_mb(ctx, ctx->rt);

	core = mfc_get_main_core(dev, ctx);
	if (!core) {
		mfc_ctx_err("[RM] There is no main core\n");
		ret = -EINVAL;
		goto err_inst_open;
	}

	if (IS_MULTI_CORE_DEVICE(dev)) {
		mfc_get_corelock_ctx(ctx);
		is_corelock = 1;

		if (ctx->gdc_votf || ctx->otf_handle) {
			if (!dev->core[MFC_CORE_SUB]->has_mfc_votf) {
				ctx->op_core_type = MFC_OP_CORE_FIXED_0;
			} else if (!dev->core[MFC_CORE_MAIN]->has_mfc_votf) {
				ctx->op_core_type = MFC_OP_CORE_FIXED_1;
			}
		}

		/* Core balance by both standard and load */
		core_num = __mfc_rm_get_core_num(ctx, core->id);
		if (core_num != core->id) {
			ret = __mfc_rm_move_core_open(ctx, core_num, core->id);
			if (ret)
				goto err_inst_open;

			core = mfc_get_main_core(dev, ctx);
			if (!core) {
				mfc_ctx_err("[RM] There is no main core\n");
				ret = -EINVAL;
				goto err_inst_open;
			}
		}

		/*
		 * When there is instance of multi core mode,
		 * other instance should be open in MFC-0
		 */
		ret = __mfc_rm_check_multi_core_mode(dev, ctx->op_core_type);
		if (ret < 0) {
			mfc_ctx_err("[RM] failed multi core instance switching\n");
			goto err_inst_open;
		}
	}

	ret = core->core_ops->instance_open(core, ctx);
	if (ret) {
		mfc_core_err("[RM] Failed to open\n");
		goto err_inst_open;
	}

err_inst_open:
	if (is_corelock)
		mfc_release_corelock_ctx(ctx);

	mfc_ctx_debug_leave();

	return ret;
}

/* For 2core DRC.
 * 1) CACHE_FLUSH(main) -> CLOSE_INST(sub) -> CACHE_FLUSH(sub)
 * 2) Clear multi_core_inst_bits
 * 3) Change state to MFCINST_RES_CHANGE_END
 */
static void __mfc_rm_handle_drc_sub_core_deinit(struct mfc_ctx *ctx)
{
	struct mfc_core *core;
	struct mfc_core_ctx *core_ctx;
	struct mfc_core *subcore;
	int ret;

	mutex_lock(&ctx->op_mode_mutex);

	core = mfc_get_main_core(ctx->dev, ctx);
	if (!core)
		return;

	core_ctx = core->core_ctx[ctx->num];

	subcore = mfc_get_sub_core(ctx->dev, ctx);
	if (!subcore) {
		mutex_unlock(&ctx->op_mode_mutex);
		return;
	}

	if (IS_SINGLE_MODE(ctx)) {
		mutex_unlock(&ctx->op_mode_mutex);
		return;
	}

	ctx->subcore_inst_no = MFC_NO_INSTANCE_SET;
	ctx->op_core_num[MFC_CORE_SUB] = MFC_CORE_INVALID;
	ctx->op_core_type = MFC_OP_CORE_ALL;

	ctx->stream_op_mode = MFC_OP_SINGLE;
	mfc_change_op_mode(ctx, MFC_OP_SINGLE);

	mfc_ctx_debug(2, "[RM][2CORE][DRC] DRC update op_mode: %d\n", ctx->op_mode);

	mutex_unlock(&ctx->op_mode_mutex);

        /* deinit subcore, this instance will be operate with single core */
	if (IS_TWO_MODE1(ctx))
		mfc_core_pm_clock_off(subcore, 0);

	/* If 2-core mode, cache_flush(MAIN) is needed
	 * after LAST_FRAME(MAIN) & before CLOSE_INST(SUB)
	 */
	core->core_ops->instance_cache_flush(core, ctx);

	ret = subcore->core_ops->instance_deinit(subcore, ctx);

	mutex_lock(&ctx->op_mode_mutex);
	clear_bit(ctx->num, &ctx->dev->multi_core_inst_bits);
	mfc_change_state(core_ctx, MFCINST_RES_CHANGE_END);
	ctx->handle_drc_multi_mode = 0;
	mutex_unlock(&ctx->op_mode_mutex);

	if (ret) {
		mfc_core_err("[RM][2CORE][DRC] Failed to deinit\n");
		call_dop(core, dump_and_broadcast, core);
	}
}

static void __mfc_rm_inst_dec_dst_stop(struct mfc_dev *dev, struct mfc_ctx *ctx)
{
	struct mfc_core *maincore;
	struct mfc_core *subcore;
	struct mfc_core_ctx *core_ctx;
	int ret;

	mfc_ctx_debug(3, "op_mode: %d\n", ctx->op_mode);

	mfc_get_corelock_ctx(ctx);

	if (IS_TWO_MODE2(ctx) || IS_SWITCH_SINGLE_MODE(ctx)) {
		/* After sub core operation, dpb flush from main core */
		subcore = mfc_get_sub_core(dev, ctx);
		if (!subcore) {
			mfc_ctx_err("[RM] There is no sub core for switch single\n");
			goto err_dst_stop;
		}
		ret = mfc_core_get_hwlock_dev(subcore);
		if (ret < 0) {
			mfc_ctx_err("Failed to get sub core hwlock\n");
			goto err_dst_stop;
		}
		mfc_core_release_hwlock_dev(subcore);

		maincore = mfc_get_main_core(ctx->dev, ctx);
		if (!maincore) {
			mfc_ctx_err("[RM] There is no main core\n");
			goto err_dst_stop;
		}
		maincore->core_ops->instance_dpb_flush(maincore, ctx);
		/* Check one more time, because sub core could be denit-ed by DRC */
		if (IS_TWO_MODE2(ctx) || IS_SWITCH_SINGLE_MODE(ctx)) {
			/* If drc is running yet, we need to deinit first. */
			core_ctx = subcore->core_ctx[ctx->num];
			if (core_ctx->state == MFCINST_RES_CHANGE_INIT ||
					core_ctx->state == MFCINST_RES_CHANGE_FLUSH ||
					core_ctx->state == MFCINST_RES_CHANGE_FLUSH_FINISHED)
				__mfc_rm_handle_drc_sub_core_deinit(ctx);
			else
				subcore->core_ops->instance_dpb_flush(subcore, ctx);
		}
	} else {
		maincore = mfc_get_main_core(dev, ctx);
		if (!maincore) {
			mfc_ctx_err("[RM] There is no main core\n");
			goto err_dst_stop;
		}

		maincore->core_ops->instance_dpb_flush(maincore, ctx);
	}

	mfc_clear_core_intlock(ctx);

err_dst_stop:
	mfc_release_corelock_ctx(ctx);
}

static void __mfc_rm_inst_dec_src_stop(struct mfc_dev *dev, struct mfc_ctx *ctx)
{
	struct mfc_core *core;
	struct mfc_core *maincore;
	struct mfc_core *subcore;

	mfc_ctx_debug(2, "op_mode: %d\n", ctx->op_mode);

	mfc_get_corelock_ctx(ctx);

	if (IS_TWO_MODE2(ctx)) {
		core = __mfc_rm_switch_to_single_mode(ctx, 1, MFC_OP_CORE_FIXED_1);
		if (!core) {
			mfc_ctx_err("[RM][2CORE] failed to switch to single for stop\n");
			goto err_src_stop;
		} else {
			mfc_ctx_debug(2, "[RM][2CORE] switch single for CSD parsing op_mode: %d\n",
					ctx->op_mode);
		}
		core->core_ops->instance_csd_parsing(core, ctx);

		/* reset original stream mode */
		if (!need_to_special_parsing_nal(core->core_ctx[ctx->num])) {
			mutex_lock(&ctx->op_mode_mutex);
			mfc_rm_set_core_num(ctx, MFC_DEC_DEFAULT_CORE);
			mfc_change_op_mode(ctx, ctx->stream_op_mode);
			maincore = mfc_get_main_core(ctx->dev, ctx);
			if (!maincore) {
				mfc_ctx_err("[RM] There is no main core\n");
				mutex_unlock(&ctx->op_mode_mutex);
				goto err_src_stop;
			}
			subcore = mfc_get_sub_core(dev, ctx);
			if (!subcore) {
				mfc_ctx_err("[RM] There is no sub core\n");
				mutex_unlock(&ctx->op_mode_mutex);
				goto err_src_stop;
			}
			mutex_unlock(&ctx->op_mode_mutex);

			mfc_qos_on(maincore, ctx);
			mfc_qos_on(subcore, ctx);
		}
	} else {
		core = mfc_get_main_core(dev, ctx);
		if (!core) {
			mfc_ctx_err("[RM] There is no main core\n");
			goto err_src_stop;
		}
		core->core_ops->instance_csd_parsing(core, ctx);
	}

err_src_stop:
	mfc_release_corelock_ctx(ctx);
}

void mfc_rm_instance_dec_stop(struct mfc_dev *dev, struct mfc_ctx *ctx,
			unsigned int type)
{

	mfc_ctx_debug_enter();

	if (type == V4L2_BUF_TYPE_VIDEO_CAPTURE_MPLANE)
		__mfc_rm_inst_dec_dst_stop(dev, ctx);
	else if (type == V4L2_BUF_TYPE_VIDEO_OUTPUT_MPLANE)
		__mfc_rm_inst_dec_src_stop(dev, ctx);

	mfc_ctx_debug_leave();
}

void mfc_rm_instance_enc_stop(struct mfc_dev *dev, struct mfc_ctx *ctx,
			unsigned int type)
{
	struct mfc_core *core;

	mfc_ctx_debug_enter();

	mfc_get_corelock_ctx(ctx);

	core = mfc_get_main_core(dev, ctx);
	if (!core) {
		mfc_ctx_err("[RM] There is no main core\n");
		mfc_release_corelock_ctx(ctx);
		return;
	}

	if (type == V4L2_BUF_TYPE_VIDEO_CAPTURE_MPLANE)
		core->core_ops->instance_q_flush(core, ctx);
	else if (type == V4L2_BUF_TYPE_VIDEO_OUTPUT_MPLANE)
		core->core_ops->instance_finishing(core, ctx);

	mfc_release_corelock_ctx(ctx);

	mfc_ctx_debug_leave();
}

int mfc_rm_instance_setup(struct mfc_dev *dev, struct mfc_ctx *ctx)
{
	struct mfc_core *maincore, *core;
	struct mfc_core_ctx *core_ctx, *maincore_ctx;
	struct mfc_buf_queue *from_queue;
	struct mfc_buf *src_mb = NULL;
	int ret = 0;

	if (ctx->op_core_num[MFC_CORE_SUB] != MFC_CORE_INVALID) {
		mfc_ctx_info("[RM] sub core already setup\n");
		return 0;
	}

	mfc_rm_set_core_num(ctx, ctx->op_core_num[MFC_CORE_MAIN]);

	maincore = mfc_get_main_core(dev, ctx);
	if (!maincore) {
		mfc_ctx_err("[RM] There is no main core\n");
		return -EINVAL;
	}
	maincore_ctx = maincore->core_ctx[ctx->num];

	core = mfc_get_sub_core(dev, ctx);
	if (!core) {
		mfc_ctx_err("[RM] There is no sub core\n");
		return -EINVAL;
	}

	ret = core->core_ops->instance_init(core, ctx);
	if (ret) {
		mfc_ctx_err("[RM] sub core init failed\n");
		goto fail_init;
	}
	core_ctx = core->core_ctx[ctx->num];

	ret = core->core_ops->instance_open(core, ctx);
	if (ret) {
		mfc_err("[RM] sub core open failed\n");
		goto fail_open;
	}

	from_queue = &maincore_ctx->src_buf_queue;

	src_mb = mfc_get_buf(ctx, from_queue, MFC_BUF_NO_TOUCH_USED);
	if (!src_mb) {
		mfc_err("[RM] there is no header buffers\n");
		ret = -EAGAIN;
		goto fail_open;
	}

	mutex_lock(&ctx->op_mode_mutex);
	/* When DRC case, it needs to rearrange src buffer for mode1,2 */
	if (ctx->wait_state) {
		if (ctx->stream_op_mode == MFC_OP_TWO_MODE2) {
			__mfc_rm_rearrange_cpb(maincore, maincore_ctx);
			from_queue = &ctx->src_buf_ready_queue;
		}
		if (ctx->stream_op_mode == MFC_OP_TWO_MODE1) {
			mfc_move_buf_all(ctx, &ctx->src_buf_ready_queue,
					&maincore_ctx->src_buf_queue, MFC_QUEUE_ADD_TOP);
			from_queue = &ctx->src_buf_ready_queue;
		}
	}
	mutex_unlock(&ctx->op_mode_mutex);

	/* Move the header buffer to sub core */
	src_mb = mfc_get_move_buf(ctx, &core_ctx->src_buf_queue, from_queue,
			MFC_BUF_NO_TOUCH_USED, MFC_QUEUE_ADD_TOP);
	if (!src_mb) {
		mfc_err("[RM] there is no header buffers\n");
		ret = -EAGAIN;
		goto fail_open;
	} else {
		MFC_TRACE_RM("[c:%d] SETUP: Move src[%d] to queue\n",
				ctx->num, src_mb->src_index);
	}

	if (ctx->dec_priv->consumed) {
		mfc_debug(2, "[STREAM][2CORE] src should be without consumed\n");
		ctx->dec_priv->consumed = 0;
	}

	if (core->sched->enqueue_work(core, core_ctx))
		core->core_ops->request_work(core, MFC_WORK_BUTLER, ctx);

	mfc_debug(2, "[RM] waiting for header parsing of sub core\n");
	if (mfc_wait_for_done_core_ctx(core_ctx,
				MFC_REG_R2H_CMD_SEQ_DONE_RET)) {
		mfc_err("[RM] sub core header parsing failed\n");
		ret = -EAGAIN;
		goto fail_open;
	}

	/* Move back the header buffer to ready_queue */
	mfc_get_move_buf(ctx, &ctx->src_buf_ready_queue,
			&core_ctx->src_buf_queue,
			MFC_BUF_RESET_USED, MFC_QUEUE_ADD_TOP);

	/* main core number of multi core mode should MFC-0 */
	if (ctx->op_core_num[MFC_CORE_SUB] == MFC_DEC_DEFAULT_CORE) {
		mfc_rm_set_core_num(ctx, MFC_DEC_DEFAULT_CORE);
		mfc_debug(2, "[RM] main core changed to MFC0\n");

		core = mfc_get_sub_core(dev, ctx);
		if (!core) {
			mfc_err("[RM] There is no sub core\n");
			return -EINVAL;
		}

		/* sub core inst_no is needed at INIT_BUF */
		ctx->subcore_inst_no = core->core_ctx[ctx->num]->inst_no;
		mfc_debug(2, "[RM] sub core setup inst_no: %d\n", ctx->subcore_inst_no);
	} else {
		/* sub core inst_no is needed at INIT_BUF */
		ctx->subcore_inst_no = core_ctx->inst_no;
		mfc_debug(2, "[RM] sub core setup inst_no: %d\n", ctx->subcore_inst_no);
	}

	mfc_change_op_mode(ctx, ctx->stream_op_mode);

	return ret;

fail_open:
	if (core->core_ops->instance_deinit(core, ctx))
		mfc_ctx_err("[RMLB] Failed to deinit\n");
fail_init:
	ctx->op_core_num[MFC_CORE_SUB] = MFC_CORE_INVALID;

	return ret;
}

void mfc_rm_request_work(struct mfc_dev *dev, enum mfc_request_work work,
		struct mfc_ctx *ctx)
{
	struct mfc_core *core, *plugin;
	struct mfc_core_ctx *core_ctx;
	int is_corelock = 0;

	/* This is a request that may not be struct mfc_ctx */
	if (work == MFC_WORK_BUTLER) {
		__mfc_rm_request_butler(dev, ctx);
		return;
	}

	if (!ctx) {
		mfc_dev_err("[RM] ctx is needed (request work: %#x)\n", work);
		return;
	}

	if (work == MFC_WORK_POST_PROCESSING) {
		plugin = dev->plugin;
		core_ctx = plugin->core_ctx[ctx->num];
		if (core_ctx) {
			plugin->sched->enqueue_work(plugin, core_ctx);
			plugin->core_ops->request_work(plugin, MFC_WORK_TRY, ctx);
		}
		return;
	}

	if (mfc_rm_query_state(ctx, EQUAL_OR, MFCINST_RES_CHANGE_INIT) && !IS_SINGLE_MODE(ctx)) {
		/* When 2-core DRC, switch_to_single is needed */
		__mfc_rm_switch_to_single_mode(ctx, 1, ctx->op_core_type);
	}

        /* If 2core DRC, CACHE_FLUSH of main core and deinit of sub core are needed.
	 * If not 2core DRC, just change the state to MFCINST_RES_CHANGE_END.
	 */
	if (ctx->handle_drc_multi_mode &&
            mfc_rm_query_state(ctx, EQUAL_OR, MFCINST_RES_CHANGE_FLUSH_FINISHED))
		__mfc_rm_handle_drc_sub_core_deinit(ctx);

	if (IS_TWO_MODE2(ctx)) {
		__mfc_rm_move_buf_request_work(ctx, work);
		return;
	} else if (IS_MODE_SWITCHING(ctx)) {
		mfc_ctx_debug(3, "[RM] mode switching op_mode: %d\n", ctx->op_mode);
		MFC_TRACE_RM("[c:%d] mode switching op_mode: %d\n", ctx->num, ctx->op_mode);
		return;
	} else {
		if (IS_TWO_MODE1(ctx) &&
				mfc_rm_query_state(ctx, EQUAL, MFCINST_HEAD_PARSED)) {
			__mfc_rm_guarantee_init_buf(ctx);
			return;
		}
		mfc_get_corelock_ctx(ctx);
		is_corelock = 1;
	}

	mutex_lock(&ctx->op_mode_mutex);

	core = mfc_get_main_core(dev, ctx);
	if (!core) {
		mutex_unlock(&ctx->op_mode_mutex);
		goto err_req_work;
	}

	if (IS_TWO_MODE2(ctx) || IS_MODE_SWITCHING(ctx)) {
		/* do not move the src buffer */
		mfc_ctx_debug(2, "[RM] mode was changed op_mode: %d\n", ctx->op_mode);
		MFC_TRACE_RM("[c:%d] mode was changed op_mode: %d\n", ctx->num, ctx->op_mode);
		mutex_unlock(&ctx->op_mode_mutex);
		goto err_req_work;
	} else {
		/* move src buffer to src_buf_queue from src_buf_ready_queue */
		core_ctx = core->core_ctx[ctx->num];
		mfc_move_buf_all(ctx, &core_ctx->src_buf_queue,
				&ctx->src_buf_ready_queue, MFC_QUEUE_ADD_BOTTOM);
	}

	/*
	 * When op_mode is changed at that time,
	 * if the two cores are not RUNNING state, they are not ready.
	 */
	if (IS_MULTI_MODE(ctx) && !mfc_rm_query_state(ctx, EQUAL_BIGGER, MFCINST_RUNNING)) {
		mfc_ctx_debug(2, "[RM] op_mode%d set but not ready\n", ctx->op_mode);
		MFC_TRACE_RM("[c:%d] op_mode%d set but not ready\n", ctx->num, ctx->op_mode);
		mutex_unlock(&ctx->op_mode_mutex);
		goto err_req_work;
	}

	mutex_unlock(&ctx->op_mode_mutex);

	mutex_lock(&ctx->drc_wait_mutex);
	if (ctx->wait_state == WAIT_G_FMT &&
			(mfc_get_queue_count(&ctx->buf_queue_lock, &ctx->dst_buf_queue) > 0))
		mfc_dec_drc_find_del_buf(core_ctx);
	mutex_unlock(&ctx->drc_wait_mutex);

	/* set core context work bit if it is ready */
	if (core->sched->enqueue_work(core, core_ctx))
		if (core->core_ops->request_work(core, work, ctx))
			mfc_ctx_debug(3, "[RM] failed to request_work\n");

err_req_work:
	if (is_corelock)
		mfc_release_corelock_ctx(ctx);
}

void mfc_rm_qos_control(struct mfc_ctx *ctx, enum mfc_qos_control qos_control)
{
	struct mfc_dev *dev = ctx->dev;
	struct mfc_core *core;
	bool update_idle = 0;

	mfc_get_corelock_ctx(ctx);

	core = mfc_get_main_core(dev, ctx);
	if (!core) {
		mfc_ctx_debug(2, "[RM] There is no main core\n");
		goto release_corelock;
	}

	switch (qos_control) {
	case MFC_QOS_ON:
		mfc_qos_on(core, ctx);
		if (IS_MULTI_MODE(ctx)) {
			core = mfc_get_sub_core(dev, ctx);
			if (!core) {
				mfc_ctx_err("[RM] There is no sub core\n");
				goto release_corelock;
			}

			mfc_qos_on(core, ctx);
		}

		mfc_rm_load_balancing(ctx, MFC_RM_LOAD_ADD);
		__mfc_rm_check_instance(ctx);
		break;
	case MFC_QOS_OFF:
		mfc_qos_off(core, ctx);
		if (IS_MULTI_MODE(ctx)) {
			core = mfc_get_sub_core(dev, ctx);
			if (!core) {
				mfc_ctx_err("[RM] There is no sub core\n");
				goto release_corelock;
			}

			mfc_qos_off(core, ctx);
		}
		break;
	case MFC_QOS_TRIGGER:
		update_idle = mfc_qos_idle_trigger(core, ctx);
		if (ctx->update_framerate)
			mfc_qos_get_weighted_mb(ctx, ctx->rt);
		if (update_idle || ctx->update_bitrate || ctx->update_framerate)
			mfc_qos_on(core, ctx);
		if (IS_MULTI_MODE(ctx)) {
			core = mfc_get_sub_core(dev, ctx);
			if (!core) {
				mfc_ctx_err("[RM] There is no sub core\n");
				goto release_corelock;
			}

			update_idle = mfc_qos_idle_trigger(core, ctx);
			if (update_idle || ctx->update_bitrate || ctx->update_framerate)
				mfc_qos_on(core, ctx);
		}

		if (ctx->update_framerate)
			mfc_rm_load_balancing(ctx, MFC_RM_LOAD_ADD);

		ctx->update_bitrate = false;
		if (ctx->type == MFCINST_ENCODER)
			ctx->update_framerate = false;
		break;
	default:
		mfc_ctx_err("[RM] not supported QoS control type: %#x\n",
				qos_control);
	}

release_corelock:
	mfc_release_corelock_ctx(ctx);
}

int mfc_rm_query_state(struct mfc_ctx *ctx, enum mfc_inst_state_query query,
			enum mfc_inst_state state)
{
	struct mfc_dev *dev = ctx->dev;
	struct mfc_core *core;
	struct mfc_core_ctx *core_ctx;
	enum mfc_inst_state maincore_state = MFCINST_FREE;
	enum mfc_inst_state subcore_state = MFCINST_FREE;
	int maincore_condition = 0, subcore_condition = 0;
	int ret = 0;

	mfc_get_corelock_ctx(ctx);

	core = mfc_get_main_core(dev, ctx);
	if (!core) {
		mfc_ctx_debug(3, "[RM] There is no main core\n");
		goto err_query_state;
	}

	core_ctx = core->core_ctx[ctx->num];
	maincore_state = core_ctx->state;

	if (IS_MULTI_MODE(ctx)) {
		core = mfc_get_sub_core(dev, ctx);
		if (!core) {
			mfc_ctx_debug(4, "[RM] There is no sub core\n");
			goto err_query_state;
		}

		core_ctx = core->core_ctx[ctx->num];
		if (!core_ctx) {
			mfc_ctx_debug(4, "[RM] There is no sub core_ctx\n");
			goto err_query_state;
		}
		subcore_state = core_ctx->state;
	}

	switch (query) {
	case EQUAL:
		if (maincore_state == state)
			maincore_condition = 1;
		if (subcore_state == state)
			subcore_condition = 1;
		break;
	case BIGGER:
		if (maincore_state > state)
			maincore_condition = 1;
		if (subcore_state > state)
			subcore_condition = 1;
		break;
	case SMALLER:
		if (maincore_state < state)
			maincore_condition = 1;
		if (subcore_state < state)
			subcore_condition = 1;
		break;
	case EQUAL_BIGGER:
		if (maincore_state >= state)
			maincore_condition = 1;
		if (subcore_state >= state)
			subcore_condition = 1;
		break;
	case EQUAL_SMALLER:
		if (maincore_state <= state)
			maincore_condition = 1;
		if (subcore_state <= state)
			subcore_condition = 1;
		break;
	case EQUAL_OR:
		if ((maincore_state == state) || (subcore_state == state)) {
			maincore_condition = 1;
			subcore_condition = 1;
		}
		break;
	default:
		mfc_err("[RM] not supported state query type: %d\n", query);
		goto err_query_state;
	}

	if (IS_MULTI_MODE(ctx)) {
		if (maincore_condition && subcore_condition)
			ret = 1;
		else
			mfc_debug(2, "[RM] multi core main core state: %d, sub core state: %d\n",
					maincore_state, subcore_state);
	} else {
		if (maincore_condition)
			ret = 1;
		else
			mfc_debug(2, "[RM] single core main core state: %d\n",
					maincore_state);
	}

err_query_state:
	mfc_release_corelock_ctx(ctx);

	return ret;
}

int __mfc_rm_check_real_time_resource(struct mfc_ctx *ctx)
{
	struct mfc_dev *dev = ctx->dev;
	struct mfc_ctx *tmp_ctx;
	struct mfc_ctx *rt_ctx[MFC_NUM_CONTEXTS];
	unsigned long flags;
	unsigned long fix_rt_mb[MFC_NUM_CORE], all_rt_mb = 0;
	unsigned long fix_rt_mb_sum = 0, max_avail_mb = 0;
	int i, cnt = 0;

	for (i = 0; i < dev->num_core; i++) {
		max_avail_mb += dev->core[i]->core_pdata->max_mb;
		fix_rt_mb[i] = 0;
	}

	/* 1. Calculation of RT instance load in operation */
	spin_lock_irqsave(&dev->ctx_list_lock, flags);
	list_for_each_entry(tmp_ctx, &dev->ctx_list, list) {
		if (tmp_ctx == ctx) {
			mfc_ctx_debug(4, "[RT] already reserved resource\n");
			spin_unlock_irqrestore(&dev->ctx_list_lock, flags);
			return 0;
		}
		if (tmp_ctx->rt != MFC_RT) {
			mfc_ctx_debug(4, "[RM][c:%d] This is not RT (%d)\n",
					tmp_ctx->num, tmp_ctx->rt);
			continue;
		}
		if (tmp_ctx->idle_mode == MFC_IDLE_MODE_IDLE) {
			mfc_ctx_debug(3, "[RT][MFCIDLE] idle ctx[%d] excluded\n", tmp_ctx->num);
			continue;
		}
		/*
		 * - fix_rt_mb[]: RT MB that must operate in a fixed core
		 * - all_rt_mb: RT MB that operable in all cores
		 */
		if ((tmp_ctx->op_core_type == MFC_OP_CORE_FIXED_0) ||
				(tmp_ctx->op_core_type == MFC_OP_CORE_FIXED_1))
			fix_rt_mb[tmp_ctx->op_core_type] += tmp_ctx->weighted_mb;
		else
			all_rt_mb += tmp_ctx->weighted_mb;
		rt_ctx[cnt++] = tmp_ctx;
		mfc_show_ctx_info(tmp_ctx);
	}
	spin_unlock_irqrestore(&dev->ctx_list_lock, flags);

	mfc_ctx_debug(3, "[RM] ===== RT MB in operation\n");
	for (i = 0; i < dev->num_core; i++) {
		fix_rt_mb_sum += fix_rt_mb[i];
		mfc_ctx_debug(3, "[RM] core%d RT MB %lu / %u\n",
				i, fix_rt_mb[i], dev->core[i]->core_pdata->max_mb);
	}
	mfc_ctx_debug(3, "[RM] other RT MB %lu / %lu\n", all_rt_mb, max_avail_mb - fix_rt_mb_sum);

	/* 2. Adds current instance load */
	if ((ctx->op_core_type == MFC_OP_CORE_FIXED_0) ||
		(ctx->op_core_type == MFC_OP_CORE_FIXED_1)) {
		fix_rt_mb[ctx->op_core_type] += ctx->weighted_mb;
	} else {
		/* Only one instance can be operated in multi core mode */
		if ((dev->num_inst == 1) && IS_MULTI_MODE_RES(ctx)) {
			for (i = 0; i < dev->num_core; i++)
				fix_rt_mb[i] += (ctx->weighted_mb / 2);
		} else {
			all_rt_mb += ctx->weighted_mb;
		}
	}

	mfc_ctx_debug(2, "[RM] ===== RT MB after adding curr load %lu\n", ctx->weighted_mb);
	fix_rt_mb_sum = 0;
	for (i = 0; i < dev->num_core; i++) {
		fix_rt_mb_sum += fix_rt_mb[i];
		mfc_ctx_debug(2, "[RM] core%d RT MB %lu / %u\n",
				i, fix_rt_mb[i], dev->core[i]->core_pdata->max_mb);
	}
	mfc_ctx_debug(3, "[RM] other RT MB %lu / %lu\n", all_rt_mb, max_avail_mb - fix_rt_mb_sum);


	/* 3. Check whether the current RT ctx resource reservation */
	for (i = 0; i < dev->num_core; i++) {
		if (fix_rt_mb[i] > dev->core[i]->core_pdata->max_mb) {
			mfc_ctx_info("[RM] core%d RT resource is full for %lu (mb %lu / %u)\n",
					i, ctx->weighted_mb, fix_rt_mb[i],
					dev->core[i]->core_pdata->max_mb);
			goto fail_reserve;
		}
	}

	if ((all_rt_mb + fix_rt_mb_sum) > max_avail_mb) {
		mfc_ctx_info("[RM] RT resource is full for %lu, fixed %lu + others %lu (mb %lu / %lu)\n",
				ctx->weighted_mb, fix_rt_mb_sum, all_rt_mb,
				fix_rt_mb_sum + all_rt_mb, max_avail_mb);
		goto fail_reserve;
	}

	/* 4. Add reserved resource to load list */
	mfc_rm_load_balancing(ctx, MFC_RM_LOAD_ADD);
	mfc_ctx_debug(2, "[RM] RT resource is reserved for %lu, fixed %lu + others %lu (mb %lu / %lu)\n",
			ctx->weighted_mb, fix_rt_mb_sum, all_rt_mb,
			fix_rt_mb_sum + all_rt_mb, max_avail_mb);

	return 0;

fail_reserve:
	for (i = 0; i < cnt; i++) {
		if (!rt_ctx[i])
			continue;
		mfc_print_ctx_info(rt_ctx[i]);
	}
	mfc_ctx_info(":: Current instance\n");
	mfc_print_ctx_info(ctx);
	return -EBUSY;
}

void mfc_rm_update_real_time(struct mfc_ctx *ctx)
{
	struct mfc_core *core;
	int cur_rt, cur_prio, new_rt, new_prio, ret;

	mfc_ctx_debug_enter();

	new_prio = ctx->user_prio;

	if (ctx->operating_framerate > 0) {
		if (new_prio == 0) {
			new_rt = MFC_RT;
		} else if (new_prio >= 1) {
			new_rt = MFC_RT_CON;
		} else {
			/* Undefined is handled like RT_LOW (priority 1) */
			new_prio = 1;
			new_rt = MFC_RT_LOW;
		}
	} else {
		if (new_prio == 0) {
			if ((ctx->type == MFCINST_ENCODER) &&
				(ctx->enc_priv->params.rc_framerate))
				new_rt = MFC_RT;
			else {
				/* In case of google photo app, user sets priority 0 */
				new_prio = 1;
				new_rt = MFC_RT_LOW;
			}
		} else if (new_prio >= 1) {
			new_rt = MFC_NON_RT;
		} else {
			/* Undefined is handled like RT_LOW (priority 1) */
			new_prio = 1;
			new_rt = MFC_RT_UNDEFINED;
		}
	}

	mfc_ctx_debug(2, "[PRIO] update rt: %d -> %d, operating fps: %lu, prio: %d->%d\n",
			ctx->rt, new_rt, (ctx->operating_framerate / 1000),
			ctx->prio, new_prio);
	MFC_TRACE_CTX("[PRIO] update rt: %d -> %d, operating fps: %lu, prio: %d->%d\n",
			ctx->rt, new_rt, (ctx->operating_framerate / 1000),
			ctx->prio, new_prio);

	mfc_qos_get_weighted_mb(ctx, new_rt);

	if (new_rt == MFC_RT) {
		ret = __mfc_rm_check_real_time_resource(ctx);
		if (ret) {
			new_prio = 1;
			mfc_ctx_debug(2, "[PRIO] RT resource is full so update prio: %d->%d\n",
					ctx->prio, new_prio);
		}
	}

	if ((new_rt != ctx->rt) || (new_prio != ctx->prio)) {
		cur_rt = ctx->rt;
		cur_prio = ctx->prio;
		core = mfc_get_main_core_lock(ctx->dev, ctx);
		if (core) {
			ret = core->sched->change_prio_work(core, ctx, cur_rt, cur_prio, new_rt, new_prio);
		} else {
			mfc_ctx_err("[PRIO] There is no main core\n");
			ret = -EINVAL;
		}
		if (ret) {
			ctx->prio = new_prio;
			ctx->rt = new_rt;
		}

		if (!IS_SINGLE_MODE(ctx)) {
			core = mfc_get_sub_core_lock(ctx->dev, ctx);
			if (core)
				core->sched->change_prio_work(core, ctx, cur_rt, cur_prio, new_rt, new_prio);
			else
				mfc_ctx_err("[PRIO] There is no sub core\n");
		}
	}

	mfc_ctx_debug_leave();
}
