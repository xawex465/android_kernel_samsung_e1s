/*
 * drivers/media/platform/exynos/mfc/base/mfc_qos.c
 *
 * Copyright (c) 2016 Samsung Electronics Co., Ltd.
 *		http://www.samsung.com/
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <linux/err.h>
#include <soc/samsung/freq-qos-tracer.h>

#include "mfc_qos.h"
#include "mfc_utils.h"
#include "mfc_queue.h"
#include "mfc_rate_calculate.h"

static inline unsigned long __mfc_qos_add_weight(struct mfc_ctx *ctx, unsigned long mb)
{
	struct mfc_enc *enc = ctx->enc_priv;
	struct mfc_dec *dec = ctx->dec_priv;
	struct mfc_enc_params *p;
	struct mfc_qos_weight *qos_weight = &ctx->dev->pdata->qos_weight;
	u32 num_planes = ctx->dst_fmt->num_planes;
	int weight = 1000;
	unsigned long weighted_mb;

	switch (ctx->codec_mode) {
	case MFC_REG_CODEC_H264_DEC:
	case MFC_REG_CODEC_H264_MVC_DEC:
	case MFC_REG_CODEC_H264_ENC:
	case MFC_REG_CODEC_H264_MVC_ENC:
		weight = (weight * 100) / qos_weight->weight_h264_hevc;
		mfc_ctx_debug(3, "[QoS] h264, hevc codec, weight: %d\n", weight / 10);
		if (num_planes == 3) {
			weight = (weight * 100) / qos_weight->weight_3plane;
			mfc_ctx_debug(3, "[QoS] 3 plane, weight: %d\n", weight / 10);
		}
		break;

	case MFC_REG_CODEC_VP8_DEC:
	case MFC_REG_CODEC_VP8_ENC:
		weight = (weight * 100) / qos_weight->weight_vp8_vp9;
		mfc_ctx_debug(3, "[QoS] vp8, vp9 codec, weight: %d\n", weight / 10);
		if (num_planes == 3) {
			weight = (weight * 100) / qos_weight->weight_3plane;
			mfc_ctx_debug(3, "[QoS] 3 plane, weight: %d\n", weight / 10);
		}
		break;

	case MFC_REG_CODEC_HEVC_DEC:
	case MFC_REG_CODEC_HEVC_ENC:
	case MFC_REG_CODEC_BPG_DEC:
	case MFC_REG_CODEC_BPG_ENC:
		weight = (weight * 100) / qos_weight->weight_h264_hevc;
		mfc_ctx_debug(3, "[QoS] h264, hevc codec, weight: %d\n", weight / 10);
		if (num_planes == 3) {
			weight = (weight * 100) / qos_weight->weight_3plane;
			mfc_ctx_debug(3, "[QoS] 3 plane, weight: %d\n", weight / 10);
		} else {
			if (ctx->is_422) {
				weight = (weight * 100) / qos_weight->weight_422;
				mfc_ctx_debug(3, "[QoS] 422foramt, weight: %d\n", weight / 10);
			} else if (ctx->is_10bit) {
				if (!ctx->mem_type_10bit && dec && dec->super64_bframe) {
					weight = (weight * 100) / qos_weight->weight_super64_bframe;
					mfc_ctx_debug(3, "[QoS] super64 B frame, weight: %d\n", weight / 10);
				} else {
					weight = (weight * 100) / qos_weight->weight_10bit;
					mfc_ctx_debug(3, "[QoS] 10bit, weight: %d\n", weight / 10);
				}
			}
		}
		break;

	case MFC_REG_CODEC_AV1_DEC:
		weight = (weight * 100) / qos_weight->weight_av1;
		mfc_ctx_debug(3, "[QoS] av1 codec, weight: %d\n", weight / 10);

		if (ctx->is_10bit) {
			weight = (weight * 100) / qos_weight->weight_10bit;
			mfc_ctx_debug(3, "[QoS] 10bit, weight: %d\n", weight / 10);
		}
		break;
	case MFC_REG_CODEC_VP9_DEC:
	case MFC_REG_CODEC_VP9_ENC:
		weight = (weight * 100) / qos_weight->weight_vp8_vp9;
		mfc_ctx_debug(3, "[QoS] vp8, vp9 codec, weight: %d\n", weight / 10);

		if (num_planes == 3) {
			weight = (weight * 100) / qos_weight->weight_3plane;
			mfc_ctx_debug(3, "[QoS] 3 plane, weight: %d\n", weight / 10);
		} else {
			if (ctx->is_422) {
				weight = (weight * 100) / qos_weight->weight_422;
				mfc_ctx_debug(3, "[QoS] 422foramt, weight: %d\n", weight / 10);
			} else if (ctx->is_10bit) {
				weight = (weight * 100) / qos_weight->weight_10bit;
				mfc_ctx_debug(3, "[QoS] 10bit, weight: %d\n", weight / 10);
			}
		}
		break;

	case MFC_REG_CODEC_MPEG4_DEC:
	case MFC_REG_CODEC_FIMV1_DEC:
	case MFC_REG_CODEC_FIMV2_DEC:
	case MFC_REG_CODEC_FIMV3_DEC:
	case MFC_REG_CODEC_FIMV4_DEC:
	case MFC_REG_CODEC_H263_DEC:
	case MFC_REG_CODEC_VC1_RCV_DEC:
	case MFC_REG_CODEC_VC1_DEC:
	case MFC_REG_CODEC_MPEG2_DEC:
	case MFC_REG_CODEC_MPEG4_ENC:
	case MFC_REG_CODEC_H263_ENC:
		weight = (weight * 100) / qos_weight->weight_other_codec;
		mfc_ctx_debug(3, "[QoS] other codec, weight: %d\n", weight / 10);
		break;

	default:
		mfc_ctx_err("[QoS] wrong codec_mode (%d), no weight\n", ctx->codec_mode);
	}

	if (enc) {
		p = &enc->params;
		if (mfc_is_enc_bframe(ctx)) {
			weight = (weight * 100) / qos_weight->weight_bframe;
			mfc_ctx_debug(3, "[QoS] B frame encoding, weight: %d\n", weight / 10);
		} else if ((IS_H264_ENC(ctx) || IS_HEVC_ENC(ctx) || IS_VP8_ENC(ctx) ||
					IS_VP9_ENC(ctx)) && (p->num_refs_for_p >= 2)) {
			weight = (weight * 100) / qos_weight->weight_num_of_ref;
			mfc_ctx_debug(3, "[QoS] num of ref >= 2, weight: %d\n", weight / 10);
		} else if (IS_HEVC_ENC(ctx) && p->codec.hevc.general_pb_enable) {
			weight = (weight * 100) / qos_weight->weight_gpb;
			mfc_ctx_debug(3, "[QoS] Genaral PB, weight: %d\n", weight / 10);
		}
	}
	if (dec) {
		if (dec->num_of_tile_over_4) {
			weight = (weight * 100) / qos_weight->weight_num_of_tile;
			mfc_ctx_debug(3, "[QoS] num of tile >= 4, weight: %d\n", weight / 10);
		}
		if (dec->is_mbaff) {
			weight = (weight * 100) / qos_weight->weight_mbaff;
			mfc_ctx_debug(3, "[QoS] MBAFF, weight: %d\n", weight / 10);
		}
	}

	weighted_mb = (mb * weight) / 1000;
	mfc_ctx_debug(3, "[QoS] weight: %d, codec: %d, num planes: %d, "
			"10bit: %d, 422format: %d (mb: %ld)\n",
			weight / 10, ctx->codec_mode,
			num_planes, ctx->is_10bit, ctx->is_422,
			weighted_mb);


	return weighted_mb;
}

void mfc_qos_get_weighted_mb(struct mfc_ctx *ctx, enum mfc_real_time rt)
{
	unsigned long mb;
	unsigned int max_mb = ctx->dev->core[MFC_DEC_DEFAULT_CORE]->core_pdata->max_mb;

	ctx->mb_width = WIDTH_MB(ctx->img_width);
	ctx->mb_height = HEIGHT_MB(ctx->img_height);
	mb = ctx->mb_width * ctx->mb_height * (mfc_rate_get_rt_framerate(ctx, rt) / 1000);

	/* Instance individual load regardless of operating in the multi core */
	ctx->weighted_mb = __mfc_qos_add_weight(ctx, mb);
	ctx->load = ctx->weighted_mb * 100 / max_mb;
}

#ifdef CONFIG_MFC_USE_BUS_DEVFREQ
enum {
	MFC_QOS_ADD = 0,
	MFC_QOS_UPDATE,
	MFC_QOS_REMOVE,
	MFC_QOS_BW,
};

enum {
	MFC_PERF_BOOST_DVFS	= (1 << 0),
	MFC_PERF_BOOST_MO	= (1 << 1),
	MFC_PERF_BOOST_CPU	= (1 << 2),
};

void __mfc_qos_cpu_boost_enable(struct mfc_core *core)
{
	struct mfc_core_platdata *pdata = core->core_pdata;
	struct mfc_qos_boost *qos_boost_table = pdata->qos_boost_table;
	struct cpufreq_policy *policy;
	int i;

	for (i = 0; i < qos_boost_table->num_cluster; i++) {
		policy = cpufreq_cpu_get(qos_boost_table->num_cpu[i]);
		if (policy) {
			freq_qos_tracer_add_request(&policy->constraints,
				&core->qos_req_cluster[i], FREQ_QOS_MIN,
				qos_boost_table->freq_cluster[i]);
			mfc_core_debug(2, "[QoS][BOOST] CPU cluster[%d]: %d\n",
				i, qos_boost_table->freq_cluster[i]);
		}
	}

	core->cpu_boost_enable = 1;
}

void __mfc_qos_cpu_boost_disable(struct mfc_core *core)
{
	struct mfc_core_platdata *pdata = core->core_pdata;
	struct mfc_qos_boost *qos_boost_table = pdata->qos_boost_table;
	int i;

	for (i = 0; i < qos_boost_table->num_cluster; i++) {
		freq_qos_tracer_remove_request(&core->qos_req_cluster[i]);
		mfc_core_debug(2, "[QoS][BOOST] CPU cluster[%d] off\n", i);
	}

	core->cpu_boost_enable = 0;
}

void mfc_qos_perf_boost_enable(struct mfc_core *core)
{
	struct mfc_core_platdata *pdata = core->core_pdata;
	struct mfc_qos_boost *qos_boost_table = pdata->qos_boost_table;

	if (core->dev->debugfs.perf_boost_mode & MFC_PERF_BOOST_DVFS) {
		core->last_mfc_freq = qos_boost_table->freq_mfc;
		if (pdata->mfc_freq_control)
			exynos_pm_qos_add_request(&core->qos_req_mfc, pdata->pm_qos_id,
					qos_boost_table->freq_mfc);
		exynos_pm_qos_add_request(&core->qos_req_int, PM_QOS_DEVICE_THROUGHPUT,
				qos_boost_table->freq_int);
		exynos_pm_qos_add_request(&core->qos_req_mif, PM_QOS_BUS_THROUGHPUT,
				qos_boost_table->freq_mif);
		mfc_core_debug(2, "[QoS][BOOST] DVFS mfc: %d, int:%d, mif:%d\n",
				qos_boost_table->freq_mfc, qos_boost_table->freq_int,
				qos_boost_table->freq_mif);
	}

#ifdef CONFIG_MFC_USE_BTS
	if (core->dev->debugfs.perf_boost_mode & MFC_PERF_BOOST_MO) {
		if (pdata->mo_control) {
#ifdef CONFIG_MFC_NO_RENEWAL_BTS
			bts_update_scen(BS_MFC_UHD_10BIT, 1);
			mfc_core_debug(2, "[QoS][BOOST] BTS(MO): UHD_10BIT\n");
#else
			__mfc_bts_add_scenario(core, qos_boost_table->bts_scen_idx);
			mfc_core_debug(2, "[QoS][BOOST] BTS(MO) add idx %d (%s)\n",
					qos_boost_table->bts_scen_idx, qos_boost_table->name);
#endif
		}
	}
#endif

	if (core->dev->debugfs.perf_boost_mode & MFC_PERF_BOOST_CPU)
		__mfc_qos_cpu_boost_enable(core);
}

void mfc_qos_perf_boost_disable(struct mfc_core *core)
{
	struct mfc_core_platdata *pdata = core->core_pdata;

	if (core->dev->debugfs.perf_boost_mode & MFC_PERF_BOOST_DVFS) {
		if (pdata->mfc_freq_control)
			exynos_pm_qos_remove_request(&core->qos_req_mfc);
		exynos_pm_qos_remove_request(&core->qos_req_int);
		exynos_pm_qos_remove_request(&core->qos_req_mif);
		mfc_core_debug(3, "[QoS][BOOST] DVFS off\n");
	}

#ifdef CONFIG_MFC_USE_BTS
	if (core->dev->debugfs.perf_boost_mode & MFC_PERF_BOOST_MO) {
		if (pdata->mo_control) {
#ifdef CONFIG_MFC_NO_RENEWAL_BTS
			bts_update_scen(BS_MFC_UHD_10BIT, 0);
			mfc_core_debug(3, "[QoS][BOOST] BTS(MO) off\n");
#else
			__mfc_bts_del_scenario(core, pdata->qos_boost_table->bts_scen_idx);
			mfc_core_debug(3, "[QoS][BOOST] BTS(MO) del idx %d (%s)\n",
					pdata->qos_boost_table->bts_scen_idx,
					pdata->qos_boost_table->name);
#endif
		}
	}
#endif

	if (core->dev->debugfs.perf_boost_mode & MFC_PERF_BOOST_CPU)
		__mfc_qos_cpu_boost_disable(core);
}

void mfc_qos_set_portion(struct mfc_core *core, struct mfc_ctx *ctx)
{
	int idx;

	/*
	 * When only it is single instance,
	 * there is an exact meaning in the qos portion.
	 */
	if (!ctx->mfc_qos_portion || core->num_inst > 1)
		return;

	idx = atomic_read(&core->qos_req_cur) - 1;
	if (idx == -1)
		return;

	ctx->mfc_qos_portion[idx]++;
}

void mfc_qos_get_portion(struct mfc_core *core, struct mfc_ctx *ctx)
{
	struct mfc_qos *qos_table;
	int num_qos_steps;
	int i, sum = 0;
	int table_type;

	if (!ctx->mfc_qos_portion)
		return;

	if (ctx->type == MFCINST_ENCODER)
		table_type = MFC_QOS_TABLE_TYPE_ENCODER;
	else
		table_type = MFC_QOS_TABLE_TYPE_DEFAULT;

	num_qos_steps = __mfc_core_get_qos_steps(core, table_type);
	qos_table = __mfc_core_get_qos_table(core, table_type);

	for (i = 0; i < num_qos_steps; i++) {
		sum += ctx->mfc_qos_portion[i];
		mfc_ctx_debug(2, "[QoS][portion] lv%d: %d frame, %d%% (type: %d, mfc: %d, int: %d, mif: %d, mo: %s)\n",
				i, ctx->mfc_qos_portion[i],
				ctx->mfc_qos_portion[i] * 100 / ctx->frame_cnt,
				core->last_table_type,
				qos_table[i].freq_mfc, qos_table[i].freq_int,
				qos_table[i].freq_mif, qos_table[i].name);
	}
	mfc_ctx_debug(2, "[QoS][portion] total %d frame (recorded %d)\n",
			ctx->frame_cnt, sum);
}

bool mfc_qos_mb_calculate(struct mfc_core *core, struct mfc_core_ctx *core_ctx,
		unsigned int processing_cycle, unsigned int frame_type)
{
	struct mfc_ctx *ctx = core_ctx->ctx;
	struct list_head *head = &core_ctx->mb_list;
	struct mfc_mb_control *temp_mb;
	struct mfc_mb_control *new_mb;
	unsigned int avg_fps, need_fps, total_fps = 0;
	unsigned long hwfw_time, hw_mb, need_mb, avg_mb, base_mb, margin_mb, total_mb = 0;
	u64 drv_time = 0;
	long weight;
	int count = 0;
	bool update = false;

	if (!core->dev->pdata->dynamic_weight ||
			(core->dev->debugfs.feature_option & MFC_OPTION_USE_FIXED_WEIGHT))
		return update;

	if ((ctx->frame_cnt < (MFC_MIN_FPS / 1000)) || (ctx->framerate > MFC_MAX_FPS)
			|| (core->dev->num_inst > 1)) {
		core_ctx->dynamic_weight_mb = 0;
		core_ctx->dynamic_weight_started = 0;
		return update;
	}

	if (ctx->boosting_time) {
		core_ctx->dynamic_weight_mb = 0;
		core_ctx->dynamic_weight_started = 0;
		mfc_debug(4, "[QoS] seeking boosting\n");
		return update;
	}

	if (frame_type == 7) {
		mfc_debug(4, "[QoS] Empty decoding\n");
		return update;
	}

	mutex_lock(&core->qos_mutex);

	if (!core_ctx->dynamic_weight_mb && !core_ctx->dynamic_weight_started) {
		mfc_debug(4, "[QoS] Clear MB list, dynamic mb: %ld, started: %u\n",
				core_ctx->dynamic_weight_mb, core_ctx->dynamic_weight_started);

		while (!list_empty(head)) {
			temp_mb = list_entry(head->next, struct mfc_mb_control, list);
			list_del(&temp_mb->list);
		}

		core_ctx->mb_index = 0;
		core_ctx->mb_is_full = 0;
		core_ctx->mb_not_coded_time = 0;
		core_ctx->mb_not_coded_mode1_time = 0;
		core_ctx->dynamic_weight_started = 1;
		core_ctx->mb_update_time = MFC_MAX_MB_TABLE;
	}

	new_mb = &core_ctx->mb_table[core_ctx->mb_index];

	/* setup macroblock table list */
	if (core_ctx->mb_is_full && !core_ctx->mb_not_coded_time) {
		temp_mb = list_entry(head->next, struct mfc_mb_control, list);
		list_del(&temp_mb->list);
	}

	hw_mb = ((ctx->crop_width + 15) / 16) * ((ctx->crop_height + 15) / 16);
	hwfw_time = processing_cycle / (core->last_mfc_freq / 1000);
	if (IS_TWO_MODE1(ctx)) {
		core_ctx->mb_end = ktime_get();
		drv_time = ktime_to_us(core_ctx->mb_end) - ktime_to_us(core_ctx->mb_begin);
	}

	if (core_ctx->mb_not_coded_time) {
		mfc_debug(4, "[QoS] Add not coded time. %lu + %lu(drv: %llu + %llu)\n",
				hwfw_time, core_ctx->mb_not_coded_time,
				drv_time, core_ctx->mb_not_coded_mode1_time);
		hwfw_time += core_ctx->mb_not_coded_time;
		drv_time += core_ctx->mb_not_coded_mode1_time;
		core_ctx->mb_not_coded_time = 0;
		core_ctx->mb_not_coded_mode1_time = 0;
	} else {
		list_add_tail(&new_mb->list, head);
	}

	if (frame_type == 0) {
		mfc_debug(4, "[QoS] Not coded frame type. it accumulated to next frame\n");
		if (drv_time)
			core_ctx->mb_not_coded_mode1_time = drv_time;
		if (hwfw_time)
			core_ctx->mb_not_coded_time = hwfw_time;
		else
			core_ctx->mb_not_coded_time = 1;
		goto qos_end;
	}

	if (drv_time) {
		new_mb->mb_per_sec = (1000000 * hw_mb) / drv_time;
		new_mb->fps = 1000000 / drv_time;
	} else if (hwfw_time) {
		new_mb->mb_per_sec = (1000000 * hw_mb) / hwfw_time;
		new_mb->fps = 1000000 / hwfw_time;
	} else {
		new_mb->mb_per_sec = 0;
		new_mb->fps = 0;
	}

	mfc_debug(4, "[QoS] hw_mb: %ld, cycle: %d, t: %ld(d:%lld), mb: %ld, fps: %d, freq: %d\n",
			hw_mb, processing_cycle, hwfw_time, drv_time, new_mb->mb_per_sec,
			new_mb->fps, core->last_mfc_freq);

	mfc_debug(4, "[QoS] -------------- mb_table (MFC: %dKHz)\n", core->last_mfc_freq);
	list_for_each_entry(temp_mb, head, list) {
		mfc_debug(4, "[QoS][%d] %lu MB/sec, %u fps\n",
				count, temp_mb->mb_per_sec, temp_mb->fps);
		total_mb += temp_mb->mb_per_sec;
		total_fps += temp_mb->fps;
		count++;
	}

	if (count == 0) {
		mfc_err("[QoS] There is no list for MB\n");
		goto qos_end;
	}

	core_ctx->mb_index++;
	if (core_ctx->mb_index == MFC_MAX_MB_TABLE) {
		core_ctx->mb_is_full = 1;
		core_ctx->mb_index = 0;
	}

	/* Skip additional updates until the changed QoS is reflected */
	if (core_ctx->mb_update_time)
 		core_ctx->mb_update_time--;


	/* Calculate macroblock average */
	if (ctx->disp_ratio)
		need_fps = ((ctx->framerate / 1000) * ctx->disp_ratio) / 100;
	else
		need_fps = ctx->framerate / 1000;
	if (IS_TWO_MODE2(ctx))
		need_fps = need_fps / core->dev->num_core;
	need_mb = hw_mb * need_fps;
	avg_mb = total_mb / count;
	avg_fps = total_fps / count;
	core_ctx->avg_runtime = avg_fps ? (1000000 / avg_fps) : 0;

	mfc_debug(2, "[QoS] MB/sec op: %lu, need: %lu, cur: %lu, fps op: %lu, need: %u cur: %u\n",
			hw_mb * ctx->framerate / 1000, need_mb, avg_mb,
			ctx->framerate / 1000, need_fps, avg_fps);

	/* Calculate dynamic macroblock weight, it can be minus value */
	if (need_mb < MFC_MB_PER_TABLE)
		margin_mb = need_mb / 2;
	else if (ctx->type == MFCINST_ENCODER)
		margin_mb = MFC_MB_PER_TABLE / 2;
	else if ((need_mb > core->core_pdata->max_mb) ||
			((ctx->stream_op_mode == MFC_OP_TWO_MODE1 || ctx->stream_op_mode == MFC_OP_TWO_MODE2)
			&& IS_MFC_MAX_PERF(ctx, need_fps)))
		margin_mb = MFC_MB_PER_TABLE * core->dev->num_core;
	else
		margin_mb = MFC_MB_PER_TABLE;

	if (ctx->type == MFCINST_DECODER && (new_mb->mb_per_sec < need_mb + margin_mb)) {
		base_mb = need_mb + margin_mb;
		weight = base_mb - new_mb->mb_per_sec;
		mfc_debug(2, "[QoS] per frame perf is insufficient (weight %ld)\n", weight);
		update = true;
	} else if (avg_mb < need_mb + margin_mb) {
		base_mb = need_mb + margin_mb;
		weight = base_mb - avg_mb;
		mfc_debug(2, "[QoS] perf is insufficient (weight %ld)\n", weight);
		update = true;
	} else if (avg_mb > need_mb + (2 * margin_mb)) {
		if (!core_ctx->mb_update_time) {
			base_mb = need_mb + (2 * margin_mb);
			weight = -min(avg_mb - base_mb, margin_mb);
			mfc_debug(2, "[QoS] perf is enough (weight %ld)\n", weight);
			update = true;
		}
	} else {
		if (!core_ctx->mb_update_time)
			mfc_debug(2, "[QoS] perf is suitable\n");
	}

	if (update) {
		/* dynamic_weight_mb is accumulated after first time */
		if (IS_TWO_MODE1(ctx))
			need_mb /= core->dev->num_core;
		if (!core_ctx->dynamic_weight_mb)
			core_ctx->dynamic_weight_mb = __mfc_qos_add_weight(ctx, need_mb) + weight;
		else
			core_ctx->dynamic_weight_mb += weight;

		/* If dynamic_weight_mb is minus, use need_mb because perf is enough */
		if (core_ctx->dynamic_weight_mb <= 0)
			core_ctx->dynamic_weight_mb = need_mb;
		else if (core_ctx->dynamic_weight_mb > core->core_pdata->max_mb)
			core_ctx->dynamic_weight_mb = core->core_pdata->max_mb;

		while (!list_empty(head)) {
			temp_mb = list_entry(head->next, struct mfc_mb_control, list);
			list_del(&temp_mb->list);
		}

		core_ctx->mb_index = 0;
		core_ctx->mb_is_full = 0;
		core_ctx->mb_update_time = MFC_MAX_MB_TABLE;
		mfc_debug(2, "[QoS] dynamic weight mb: %ld\n", core_ctx->dynamic_weight_mb);
	}

qos_end:
	mutex_unlock(&core->qos_mutex);

	return update;
}

static void __mfc_qos_operate(struct mfc_core *core, int opr_type, int table_type, int idx)
{
	struct mfc_core_platdata *pdata = core->core_pdata;
	struct mfc_qos *qos_table;
	int freq_mfc;

	qos_table = __mfc_core_get_qos_table(core, table_type);
	/* When removing QoS, do not update because the table_type is not accurate. */
	if (opr_type != MFC_QOS_REMOVE)
		core->last_table_type = table_type;

	if (core->mfc_freq_by_bps > qos_table[idx].freq_mfc)
		freq_mfc = core->mfc_freq_by_bps;
	else
		freq_mfc = qos_table[idx].freq_mfc;

	switch (opr_type) {
	case MFC_QOS_ADD:
		core->last_mfc_freq = freq_mfc;
		if (pdata->mfc_freq_control)
			exynos_pm_qos_add_request(&core->qos_req_mfc, pdata->pm_qos_id,
					freq_mfc);
		exynos_pm_qos_add_request(&core->qos_req_int, PM_QOS_DEVICE_THROUGHPUT,
				qos_table[idx].freq_int);
		exynos_pm_qos_add_request(&core->qos_req_mif, PM_QOS_BUS_THROUGHPUT,
				qos_table[idx].freq_mif);

#ifdef CONFIG_MFC_USE_BTS
		if (pdata->mo_control) {
#ifdef CONFIG_MFC_NO_RENEWAL_BTS
			bts_update_scen(BS_MFC_UHD_ENC60, qos_table[idx].mo_uhd_enc60_value);
			bts_update_scen(BS_MFC_UHD_10BIT, qos_table[idx].mo_10bit_value);
			bts_update_scen(BS_MFC_UHD, qos_table[idx].mo_value);
			MFC_TRACE_CORE("BTS(MO) update - uhd:%d, uhd_10bit:%d, uhd_enc60:%d\n",
					qos_table[idx].mo_value, qos_table[idx].mo_10bit_value,
					qos_table[idx].mo_uhd_enc60_value);
			mfc_core_debug(2, "[QoS] BTS(MO) update - uhd:%d, uhd_10bit:%d, uhd_enc60:%d\n",
					qos_table[idx].mo_value, qos_table[idx].mo_10bit_value,
					qos_table[idx].mo_uhd_enc60_value);
#else
			__mfc_bts_add_scenario(core, qos_table[idx].bts_scen_idx);
			core->prev_bts_scen_idx = qos_table[idx].bts_scen_idx;
			MFC_TRACE_CORE("BTS(MO) add idx %d (%s)\n",
					qos_table[idx].bts_scen_idx, qos_table[idx].name);
			mfc_core_debug(2, "[QoS] BTS(MO) add idx %d (%s)\n",
					qos_table[idx].bts_scen_idx, qos_table[idx].name);
#endif
		}
#endif

		atomic_set(&core->qos_req_cur, idx + 1);
		MFC_TRACE_CORE("QoS add[%d] - mfc:%d(%s), int:%d, mif:%d\n",
				idx, freq_mfc, pdata->mfc_freq_control ? "used" : "un-used",
				qos_table[idx].freq_int, qos_table[idx].freq_mif);
		mfc_core_debug(2, "[QoS] QoS add[%d] - mfc:%d(%s), int:%d, mif:%d\n",
				idx, freq_mfc, pdata->mfc_freq_control ? "used" : "un-used",
				 qos_table[idx].freq_int, qos_table[idx].freq_mif);
		break;
	case MFC_QOS_UPDATE:
		core->last_mfc_freq = freq_mfc;
		if (pdata->mfc_freq_control)
			exynos_pm_qos_update_request(&core->qos_req_mfc, freq_mfc);
		exynos_pm_qos_update_request(&core->qos_req_int, qos_table[idx].freq_int);
		exynos_pm_qos_update_request(&core->qos_req_mif, qos_table[idx].freq_mif);

#ifdef CONFIG_MFC_USE_BTS
		if (pdata->mo_control) {
#ifdef CONFIG_MFC_NO_RENEWAL_BTS
			bts_update_scen(BS_MFC_UHD_ENC60, qos_table[idx].mo_uhd_enc60_value);
			bts_update_scen(BS_MFC_UHD_10BIT, qos_table[idx].mo_10bit_value);
			bts_update_scen(BS_MFC_UHD, qos_table[idx].mo_value);
			MFC_TRACE_CORE("BTS(MO) update - uhd:%d, uhd_10bit:%d, uhd_enc60:%d\n",
					qos_table[idx].mo_value, qos_table[idx].mo_10bit_value,
					qos_table[idx].mo_uhd_enc60_value);
			mfc_core_debug(2, "[QoS] BTS(MO) update - uhd:%d, uhd_10bit:%d, uhd_enc60:%d\n",
					qos_table[idx].mo_value, qos_table[idx].mo_10bit_value,
					qos_table[idx].mo_uhd_enc60_value);
#else
			__mfc_bts_add_scenario(core, qos_table[idx].bts_scen_idx);
			__mfc_bts_del_scenario(core, core->prev_bts_scen_idx);
			core->prev_bts_scen_idx = qos_table[idx].bts_scen_idx;
			MFC_TRACE_CORE("BTS(MO) update idx %d (%s)\n",
					qos_table[idx].bts_scen_idx, qos_table[idx].name);
			mfc_core_debug(2, "[QoS] BTS(MO) update idx %d (%s)\n",
					qos_table[idx].bts_scen_idx, qos_table[idx].name);
#endif
		}
#endif

		atomic_set(&core->qos_req_cur, idx + 1);
		MFC_TRACE_CORE("QoS update[%d] - mfc:%d(%s), int:%d, mif:%d\n",
				idx, freq_mfc, pdata->mfc_freq_control ? "used" : "un-used",
				qos_table[idx].freq_int, qos_table[idx].freq_mif);
		mfc_core_debug(2, "[QoS] QoS update[%d] - mfc:%d(%s), int:%d, mif:%d\n",
				idx, freq_mfc, pdata->mfc_freq_control ? "used" : "un-used",
				qos_table[idx].freq_int, qos_table[idx].freq_mif);
		break;
	case MFC_QOS_REMOVE:
		core->last_mfc_freq = 0;
		if (atomic_read(&core->qos_req_cur) == 0) {
			MFC_TRACE_CORE("QoS already removed\n");
			mfc_core_debug(2, "[QoS] QoS already removed\n");
			break;
		}

		mutex_lock(&core->pm_qos_mutex);
		if (pdata->mfc_freq_control)
			exynos_pm_qos_remove_request(&core->qos_req_mfc);
		exynos_pm_qos_remove_request(&core->qos_req_int);
		exynos_pm_qos_remove_request(&core->qos_req_mif);

#ifdef CONFIG_MFC_USE_BTS
		if (pdata->mo_control) {
#ifdef CONFIG_MFC_NO_RENEWAL_BTS
			bts_update_scen(BS_MFC_UHD_ENC60, 0);
			bts_update_scen(BS_MFC_UHD_10BIT, 0);
			bts_update_scen(BS_MFC_UHD, 0);
#else
			__mfc_bts_del_scenario(core, core->prev_bts_scen_idx);
			MFC_TRACE_CORE("BTS(MO) del idx %d\n", core->prev_bts_scen_idx);
			mfc_core_debug(2, "[QoS] BTS(MO) del idx %d\n", core->prev_bts_scen_idx);
#endif
		}

		if (pdata->bw_control) {
			core->mfc_bw.peak = 0;
			core->mfc_bw.read = 0;
			core->mfc_bw.write = 0;
			bts_update_bw(core->core_pdata->mfc_bw_index, core->mfc_bw);
		}
#endif

		atomic_set(&core->qos_req_cur, 0);
		MFC_TRACE_CORE("QoS remove\n");
		mfc_core_debug(2, "[QoS] QoS remove\n");
		mutex_unlock(&core->pm_qos_mutex);
		break;
	case MFC_QOS_BW:
#ifdef CONFIG_MFC_USE_BTS
		if (atomic_read(&core->qos_req_cur) == 0) {
			MFC_TRACE_CORE("BTS(BW) already removed\n");
			mfc_core_debug(2, "[QoS] BTS(BW) already removed\n");
			break;
		}

		if (pdata->bw_control) {
			bts_update_bw(core->core_pdata->mfc_bw_index, core->mfc_bw);
			MFC_TRACE_CORE("BTS(BW) update (peak: %d, read: %d, write: %d)\n",
					core->mfc_bw.peak, core->mfc_bw.read, core->mfc_bw.write);
			mfc_core_debug(2, "[QoS] BTS(BW) update (peak: %d, read: %d, write: %d)\n",
					core->mfc_bw.peak, core->mfc_bw.read, core->mfc_bw.write);
		}
#endif
		break;
	default:
		mfc_core_err("[QoS] Unknown request for opr [%d]\n", opr_type);
		break;
	}
}

#ifdef CONFIG_MFC_USE_BTS
static void __mfc_qos_set(struct mfc_core *core, struct mfc_ctx *ctx,
		struct bts_bw *curr_mfc_bw, int table_type, int i)
#else
static void __mfc_qos_set(struct mfc_core *core, struct mfc_ctx *ctx,
		int table_type, int i)
#endif
{
	struct mfc_core_platdata *pdata = core->core_pdata;
	struct mfc_qos *qos_table;
	int num_qos_steps;
	int freq_mfc;

	num_qos_steps = __mfc_core_get_qos_steps(core, table_type);
	qos_table = __mfc_core_get_qos_table(core, table_type);

	mfc_ctx_debug(2, "[QoS] %s table[%d] covered mb %d ~ %d (mfc: %d, int:%d, mif:%d)\n",
			table_type ? "enc" : "default", i, qos_table[i].threshold_mb,
			i == num_qos_steps - 1 ? pdata->max_mb : qos_table[i + 1].threshold_mb,
			qos_table[i].freq_mfc, qos_table[i].freq_int,
			qos_table[i].freq_mif);

	if (atomic_read(&core->qos_req_cur) == 0) {
		__mfc_qos_operate(core, MFC_QOS_ADD, table_type, i);
	} else {
		/*
		 * 1) QoS level is changed
		 * 2) MFC freq should be high regardless of QoS level
		 */
		if (atomic_read(&core->qos_req_cur) != (i + 1)) {
			__mfc_qos_operate(core, MFC_QOS_UPDATE, table_type, i);
		} else {
			if (core->mfc_freq_by_bps > qos_table[i].freq_mfc)
				freq_mfc = core->mfc_freq_by_bps;
			else
				freq_mfc = qos_table[i].freq_mfc;
			if (freq_mfc != core->last_mfc_freq) {
				mfc_ctx_debug(2, "[QoS] mfc freq changed (last: %d, by bps: %d, QoS table: %d)\n",
						core->last_mfc_freq,
						core->mfc_freq_by_bps,
						qos_table[i].freq_mfc);
				__mfc_qos_operate(core, MFC_QOS_UPDATE, table_type, i);
			}
		}
	}

#ifdef CONFIG_MFC_USE_BTS
	if (curr_mfc_bw->peak != core->mfc_bw.peak) {
		core->mfc_bw.peak = curr_mfc_bw->peak;
		core->mfc_bw.read = curr_mfc_bw->read;
		core->mfc_bw.write = curr_mfc_bw->write;
		__mfc_qos_operate(core, MFC_QOS_BW, table_type, i);
	}
#endif
}


static inline unsigned long __mfc_qos_get_mb_per_second(struct mfc_core *core,
		struct mfc_core_ctx *core_ctx, unsigned int max_mb)
{
	struct mfc_dev *dev = core->dev;
	struct mfc_ctx *ctx = core_ctx->ctx;
	unsigned long mb_width, mb_height, fps, frame_mb, mb, qos_weighted_mb;

	mb_width = (ctx->crop_width + 15) / 16;
	mb_height = (ctx->crop_height + 15) / 16;
	frame_mb = mb_width * mb_height;
	if (IS_MULTI_MODE(ctx))
		fps = ctx->framerate / 1000 / dev->num_core;
	else
		fps = ctx->framerate / 1000;

	/* If decoder resolution is larger than HD and smaller than FHD, apply FHD for perf */
	if ((ctx->type == MFCINST_DECODER) && (frame_mb > MFC_HD_RES_MB) &&
			(frame_mb < MFC_FHD_RES_MB)) {
		mfc_debug(3, "[QoS] frame MB size is changed %lu -> %d (%dx%d)\n",
				frame_mb, MFC_FHD_RES_MB,
				ctx->crop_width, ctx->crop_height);
		frame_mb = MFC_FHD_RES_MB;
	}

	mb = frame_mb * fps;
	qos_weighted_mb = __mfc_qos_add_weight(ctx, mb);

	mfc_debug(3, "[QoS] ctx[%d:%s] %d x %d @ %ld fps (mb: %ld), %dKbps\n",
			ctx->num, ctx->type == MFCINST_ENCODER ? "ENC" : "DEC",
			ctx->crop_width, ctx->crop_height, fps, mb, ctx->Kbps);

	if (ctx->boosting_time || ctx->update_framerate) {
		core_ctx->dynamic_weight_mb = 0;
		core_ctx->dynamic_weight_started = 0;
		ctx->dynamic_weight_mb = 0;
		mfc_debug(4, "[QoS] clear dynamic weight, boost: %s, update_framerate: %d\n",
			ctx->boosting_time ? "on" : "off", ctx->update_framerate);
	}

	if (!core_ctx->dynamic_weight_mb || (dev->num_inst > 1)) {
		mfc_debug(4, "[QoS] fixed weight (hw_mb: %lu)\n", qos_weighted_mb);
		return qos_weighted_mb;
	}

	mfc_debug(4, "[QoS] dynamic weight (hw_mb: %ld)\n", core_ctx->dynamic_weight_mb);
	return core_ctx->dynamic_weight_mb;
}

#ifdef CONFIG_MFC_USE_BTS
static void __mfc_qos_get_bw_per_second(struct mfc_ctx *ctx, struct bts_bw *curr_mfc_bw_ctx)
{
	struct mfc_bw_data bw_data;
	struct mfc_bw_info *bw_info = NULL;
	unsigned long mb_width, mb_height, fps, mb;
	unsigned long peak_bw_per_sec;
	unsigned long read_bw_per_sec;
	unsigned long write_bw_per_sec;
	unsigned long add_bw_per_sec = 0;
	unsigned long mb_count_per_uhd_frame = MB_COUNT_PER_UHD_FRAME;
	unsigned long max_fps_per_uhd_frame = MAX_FPS_PER_UHD_FRAME;

	mb_width = (ctx->crop_width + 15) / 16;
	mb_height = (ctx->crop_height + 15) / 16;
	fps = ctx->framerate / 1000;

	mb = mb_width * mb_height * fps;

	if (ctx->is_sbwc || ctx->is_sbwc_lossy)
		bw_info = &ctx->dev->pdata->mfc_bw_info_sbwc;
	else
		bw_info = &ctx->dev->pdata->mfc_bw_info;

	switch (ctx->codec_mode) {
	case MFC_REG_CODEC_H264_DEC:
	case MFC_REG_CODEC_H264_MVC_DEC:
		bw_data = bw_info->bw_dec_h264;
		break;
	case MFC_REG_CODEC_H264_ENC:
	case MFC_REG_CODEC_H264_MVC_ENC:
		bw_data = bw_info->bw_enc_h264;
		break;
	case MFC_REG_CODEC_HEVC_DEC:
	case MFC_REG_CODEC_BPG_DEC:
		if (ctx->is_10bit)
			bw_data = bw_info->bw_dec_hevc_10bit;
		else
			bw_data = bw_info->bw_dec_hevc;
		break;
	case MFC_REG_CODEC_HEVC_ENC:
	case MFC_REG_CODEC_BPG_ENC:
		if (ctx->is_10bit)
			bw_data = bw_info->bw_enc_hevc_10bit;
		else
			bw_data = bw_info->bw_enc_hevc;
		break;
	case MFC_REG_CODEC_MPEG4_DEC:
	case MFC_REG_CODEC_FIMV1_DEC:
	case MFC_REG_CODEC_FIMV2_DEC:
	case MFC_REG_CODEC_FIMV3_DEC:
	case MFC_REG_CODEC_FIMV4_DEC:
	case MFC_REG_CODEC_H263_DEC:
	case MFC_REG_CODEC_VC1_RCV_DEC:
	case MFC_REG_CODEC_VC1_DEC:
	case MFC_REG_CODEC_MPEG2_DEC:
		bw_data = bw_info->bw_dec_mpeg4;
		break;
	case MFC_REG_CODEC_VP8_DEC:
		bw_data = bw_info->bw_dec_vp8;
		break;
	case MFC_REG_CODEC_VP9_DEC:
		if (ctx->is_10bit)
			bw_data = bw_info->bw_dec_vp9_10bit;
		else
			bw_data = bw_info->bw_dec_vp9;
		break;
	case MFC_REG_CODEC_AV1_DEC:
		if (ctx->is_10bit)
			bw_data = bw_info->bw_dec_av1_10bit;
		else
			bw_data = bw_info->bw_dec_av1;
		break;
	case MFC_REG_CODEC_MPEG4_ENC:
	case MFC_REG_CODEC_H263_ENC:
		bw_data = bw_info->bw_enc_mpeg4;
		break;
	case MFC_REG_CODEC_VP8_ENC:
		bw_data = bw_info->bw_enc_vp8;
		break;
	case MFC_REG_CODEC_VP9_ENC:
		if (ctx->is_10bit)
			bw_data = bw_info->bw_enc_vp9_10bit;
		else
			bw_data = bw_info->bw_enc_vp9;
		break;
	default:
		bw_data.peak = 0;
		bw_data.read = 0;
		bw_data.write = 0;
		mfc_ctx_err("[QoS] wrong codec_mode (%d)\n", ctx->codec_mode);
	}

	if (mb > (mb_count_per_uhd_frame * max_fps_per_uhd_frame)) {
		mfc_ctx_debug(4, "[QoS] fix upper mb bound (mb: %ld, fps: %ld)\n", mb, fps);
		mb = mb_count_per_uhd_frame * max_fps_per_uhd_frame;
	}

	if (ctx->rgb_bpp > 12) {
		add_bw_per_sec = (((ctx->rgb_bpp - 12) / 8) * (ctx->crop_width * ctx->crop_height) * fps) / 1024;
		mfc_ctx_debug(4, "[QoS] additional BW %ldKB for RGB format\n", add_bw_per_sec);
	}

	peak_bw_per_sec = ((bw_data.peak * mb) / mb_count_per_uhd_frame) + add_bw_per_sec;
	read_bw_per_sec = ((bw_data.read * mb) / mb_count_per_uhd_frame) + add_bw_per_sec;
	write_bw_per_sec = ((bw_data.write * mb) / mb_count_per_uhd_frame) + add_bw_per_sec;

	if (peak_bw_per_sec == 0) {
		mfc_ctx_debug(4, "[QoS] fix lower peak bound (mb: %ld, fps: %ld)\n", mb, fps);
		peak_bw_per_sec = MIN_BW_PER_SEC;
	}
	if (read_bw_per_sec == 0) {
		mfc_ctx_debug(4, "[QoS] fix lower read bound (mb: %ld, fps: %ld)\n", mb, fps);
		read_bw_per_sec = MIN_BW_PER_SEC;
	}
	if (write_bw_per_sec == 0) {
		mfc_ctx_debug(4, "[QoS] fix lower write bound (mb: %ld, fps: %ld)\n", mb, fps);
		write_bw_per_sec = MIN_BW_PER_SEC;
	}

	curr_mfc_bw_ctx->peak = (unsigned int)peak_bw_per_sec;
	curr_mfc_bw_ctx->read = (unsigned int)read_bw_per_sec;
	curr_mfc_bw_ctx->write = (unsigned int)write_bw_per_sec;
}
#endif

void __mfc_qos_calculate(struct mfc_core *core, struct mfc_ctx *ctx, int delete)
{
	struct mfc_core_platdata *pdata = core->core_pdata;
	struct mfc_qos *qos_table;
	struct mfc_ctx *qos_ctx;
	struct mfc_core_ctx *qos_core_ctx;
	unsigned long hw_mb = 0, total_mb = 0, total_fps = 0;
	int total_bps = 0, mfc_freq_idx;
	unsigned int fw_time, sw_time;
	int i, qos_count = 0, found = 0, dec_found = 0, heif_found = 0, slowmotion_found = 0;
	int table_type = MFC_QOS_TABLE_TYPE_DEFAULT, num_qos_steps;
#ifdef CONFIG_MFC_USE_BTS
	struct bts_bw mfc_bw, curr_mfc_bw_ctx;
#endif

#ifdef CONFIG_MFC_USE_BTS
	mfc_bw.peak = 0;
	mfc_bw.read = 0;
	mfc_bw.write = 0;
#endif

	/* get the hw macroblock */
	list_for_each_entry(qos_core_ctx, &core->qos_queue, qos_list) {
		if (delete && (qos_core_ctx == core->core_ctx[ctx->num])) {
			found = 1;
			continue;
		}

		qos_ctx = qos_core_ctx->ctx;
		if (qos_ctx->idle_mode == MFC_IDLE_MODE_IDLE) {
			mfc_ctx_debug(3, "[QoS][MFCIDLE] skip idle ctx [%d]\n", qos_ctx->num);
			continue;
		}
		if (qos_ctx->is_heif_mode)
			heif_found += 1;
		if ((qos_ctx->type == MFCINST_ENCODER) && UNDER_FHD_RES(qos_ctx) &&
			(qos_ctx->operating_framerate == qos_ctx->framerate) &&
			(qos_ctx->operating_framerate / 1000 == 240))
			slowmotion_found += 1;

		if (qos_ctx->type == MFCINST_DECODER)
			dec_found += 1;
		hw_mb += __mfc_qos_get_mb_per_second(core, qos_core_ctx, pdata->max_mb);
		total_fps += (qos_ctx->framerate / 1000);
		total_bps += qos_ctx->Kbps;
#ifdef CONFIG_MFC_USE_BTS
		__mfc_qos_get_bw_per_second(qos_ctx, &curr_mfc_bw_ctx);
		mfc_bw.peak += curr_mfc_bw_ctx.peak;
		mfc_bw.read += curr_mfc_bw_ctx.read;
		mfc_bw.write += curr_mfc_bw_ctx.write;
#endif
		qos_count++;
	}

	if (found)
		list_del(&core->core_ctx[ctx->num]->qos_list);

	if (dec_found)
		table_type = MFC_QOS_TABLE_TYPE_DEFAULT;
	else
		table_type = MFC_QOS_TABLE_TYPE_ENCODER;

	num_qos_steps = __mfc_core_get_qos_steps(core, table_type);
	qos_table = __mfc_core_get_qos_table(core, table_type);

	/* search the suitable qos table */
	for (i = num_qos_steps - 1; i >= 0; i--) {
		fw_time = qos_table[i].time_fw;
		sw_time = (MFC_DRV_TIME + fw_time);

		if ((total_fps * sw_time) >= 1000000)
			total_mb = pdata->max_mb;
		else
			total_mb = ((1000000 * hw_mb) / (1000000 - (total_fps * sw_time)));

		mfc_ctx_debug(4, "[QoS] %s table[%d] fw_time: %dus, hw_mb: %ld, "
				"sw_time: %d, total_fps: %ld, total_mb: %ld\n",
				table_type ? "enc" : "default",
				i, fw_time, hw_mb, sw_time, total_fps, total_mb);

		if ((total_mb > qos_table[i].threshold_mb) || (total_mb == 0) || (i == 0))
			break;
	}

	if (total_mb > pdata->max_mb)
		mfc_ctx_debug(4, "[QoS] overspec mb %ld > %d\n", total_mb, pdata->max_mb);

	/* search the suitable independent mfc freq using bps */
	mfc_freq_idx = mfc_rate_get_bps_section_by_bps(core->dev, total_bps, core->dev->max_Kbps);
	core->mfc_freq_by_bps = core->dev->pdata->mfc_freqs[mfc_freq_idx];

	if (delete && (list_empty(&core->qos_queue) || total_mb == 0)) {
		if (core->cpu_boost_enable)
			__mfc_qos_cpu_boost_disable(core);
		__mfc_qos_operate(core, MFC_QOS_REMOVE, table_type, 0);
	} else {
		if (heif_found) {
			i = num_qos_steps - 1;
			mfc_ctx_debug(2, "[QoS][BOOST] use max level for HEIF\n");
			if (!core->cpu_boost_enable)
				__mfc_qos_cpu_boost_enable(core);
		} else if (slowmotion_found && qos_count == 1) {
			mfc_ctx_debug(2, "[QoS] use 332MHz for FHD 240fps encoding\n");
			i = 3;
		}
#ifdef CONFIG_MFC_USE_BTS
		__mfc_qos_set(core, ctx, &mfc_bw, table_type, i);
#else
		__mfc_qos_set(core, ctx, table_type, i);
#endif
	}
}

void mfc_qos_on(struct mfc_core *core, struct mfc_ctx *ctx)
{
	struct mfc_core_ctx *qos_core_ctx;
	int found = 0;

	if (core->dev->debugfs.perf_boost_mode) {
		mfc_ctx_info("[QoS][BOOST] skip control\n");
		return;
	}

	if (core->core_ctx[ctx->num] && core->core_ctx[ctx->num]->state == MFCINST_FREE) {
		mfc_ctx_info("[QoS] instance not started yet\n");
		return;
	}

	mutex_lock(&core->qos_mutex);
	list_for_each_entry(qos_core_ctx, &core->qos_queue, qos_list)
		if (qos_core_ctx == core->core_ctx[ctx->num])
			found = 1;

	if (!found)
		list_add_tail(&core->core_ctx[ctx->num]->qos_list,
				&core->qos_queue);

	__mfc_qos_calculate(core, ctx, MFC_QOS_ADD);

	mutex_unlock(&core->qos_mutex);
}

void mfc_qos_off(struct mfc_core *core, struct mfc_ctx *ctx)
{
	int table_type = MFC_QOS_TABLE_TYPE_DEFAULT;

	if (core->dev->debugfs.perf_boost_mode) {
		mfc_ctx_info("[QoS][BOOST] skip control\n");
		return;
	}

	mutex_lock(&core->qos_mutex);

	if (list_empty(&core->qos_queue)) {
		if (atomic_read(&core->qos_req_cur) != 0) {
			mfc_ctx_err("[QoS] MFC request count is wrong!\n");
			if (core->cpu_boost_enable)
				__mfc_qos_cpu_boost_disable(core);
			__mfc_qos_operate(core, MFC_QOS_REMOVE, table_type, 0);
		}
		goto out;
	}

	if (ON_RES_CHANGE(core->core_ctx[ctx->num]))
		goto out;

	__mfc_qos_calculate(core, ctx, MFC_QOS_REMOVE);

out:
	mutex_unlock(&core->qos_mutex);
}

void mfc_qos_update(struct mfc_core *core, int on)
{
	struct mfc_platdata *pdata = core->dev->pdata;
	struct mfc_platdata *dev_pdata = core->dev->pdata;
	unsigned int mfc_freq;
	int qos, i;

	if (core->dev->debugfs.feature_option & MFC_OPTION_DYNAMIC_QOS_DISABLE)
		return;

	mfc_core_debug_enter();

	mutex_lock(&core->qos_mutex);

	if ((atomic_read(&core->qos_req_cur) <= 1) ||
			(atomic_read(&core->qos_req_cur) > (dev_pdata->qos_ctrl_level + 1)) ||
			(core->last_table_type != MFC_QOS_TABLE_TYPE_DEFAULT)) {
		mutex_unlock(&core->qos_mutex);
		return;
	}

	if (on) {
		qos = atomic_read(&core->qos_req_cur) - 1;
		mfc_freq = core->last_mfc_freq;
		mfc_core_debug(3, "[QoS] ON: QoS update[%d], mfc freq %d\n",
				qos, mfc_freq);
	} else {
		qos = 0;
		mfc_freq = pdata->mfc_freqs[0];
		mfc_core_debug(3, "[QoS] OFF: QoS update[%d], mfc freq %d\n",
				qos, mfc_freq);
	}

	i = core->qos_ctrl_last_idx;
	core->qos_ctrl[i].idx = qos;
	core->qos_ctrl[i].table_type = core->last_table_type;
	core->qos_ctrl[i].mfc_freq = mfc_freq;
	core->qos_ctrl_last_idx++;
	if (core->qos_ctrl_last_idx >= MAX_NUM_QOS_DYNAMIC)
		core->qos_ctrl_last_idx = 0;

	mutex_unlock(&core->qos_mutex);

	queue_work(core->qos_ctrl_wq, &core->qos_ctrl_work);

	mfc_core_debug_leave();
}

void mfc_qos_ctrl_worker(struct work_struct *work)
{
	struct mfc_core *core;
	struct mfc_core_platdata *pdata;
	struct mfc_platdata *dev_pdata;
	struct mfc_qos *qos_table;
	int idx, i;

	core = container_of(work, struct mfc_core, qos_ctrl_work);
	pdata = core->core_pdata;
	dev_pdata = core->dev->pdata;

	mutex_lock(&core->qos_mutex);

	if (!core->qos_ctrl_last_idx) {
		mutex_unlock(&core->qos_mutex);
		return;
	}

	i = core->qos_ctrl_last_idx;
	do {
		core->qos_ctrl_last_idx = 0;

		if ((atomic_read(&core->qos_req_cur) > (dev_pdata->qos_ctrl_level + 1)) ||
				(atomic_read(&core->qos_req_cur) <= 1)) {
			mutex_unlock(&core->qos_mutex);
			return;
		}

		i--;
		idx = core->qos_ctrl[i].idx;
		qos_table = __mfc_core_get_qos_table(core, core->qos_ctrl[i].table_type);

		mutex_unlock(&core->qos_mutex);

		/* use pm_qos_mutex to reduce pm_qos_update latency */
		mutex_lock(&core->pm_qos_mutex);
		if (atomic_read(&core->qos_req_cur) == 0) {
			mutex_unlock(&core->pm_qos_mutex);
			return;
		}

		if (pdata->mfc_freq_control)
			exynos_pm_qos_update_request(&core->qos_req_mfc, core->qos_ctrl[i].mfc_freq);
		exynos_pm_qos_update_request(&core->qos_req_int, qos_table[idx].freq_int);
		exynos_pm_qos_update_request(&core->qos_req_mif, qos_table[idx].freq_mif);
		mfc_core_debug(3, "[QoS] WORKER: QoS update[%d], mfc freq %d\n",
				idx, core->qos_ctrl[i].mfc_freq);

		mutex_unlock(&core->pm_qos_mutex);

		mutex_lock(&core->qos_mutex);
		i = core->qos_ctrl_last_idx;
	} while (i);

	mutex_unlock(&core->qos_mutex);
}

void __mfc_qos_on_idle(struct mfc_core *core)
{
	struct mfc_ctx *ctx;
	int i;

	mutex_lock(&core->dev->mfc_migrate_mutex);
	if (!core->num_inst) {
		mutex_unlock(&core->dev->mfc_migrate_mutex);
		return;
	}

	for (i = 0; i < MFC_NUM_CONTEXTS; i++) {
		if (core->core_ctx[i]) {
			ctx = core->core_ctx[i]->ctx;
			mfc_qos_on(core, ctx);
			break;
		}
	}
	mutex_unlock(&core->dev->mfc_migrate_mutex);
}

void __mfc_qos_off_all(struct mfc_core *core)
{
	struct mfc_core_ctx *qos_core_ctx, *tmp_core_ctx;

	mutex_lock(&core->qos_mutex);
	if (list_empty(&core->qos_queue)) {
		mfc_core_err("[QoS][MFCIDLE] MFC QoS list already empty (%d)\n",
				atomic_read(&core->qos_req_cur));
		mutex_unlock(&core->qos_mutex);
		return;
	}

	/* Delete all of QoS list */
	list_for_each_entry_safe(qos_core_ctx, tmp_core_ctx, &core->qos_queue, qos_list)
		list_del(&qos_core_ctx->qos_list);

	/* Select the opend ctx structure for QoS remove */
	if (core->cpu_boost_enable)
		__mfc_qos_cpu_boost_disable(core);
	__mfc_qos_operate(core, MFC_QOS_REMOVE, MFC_QOS_TABLE_TYPE_DEFAULT, 0);
	mutex_unlock(&core->qos_mutex);
}
#else
bool mfc_qos_mb_calculate(struct mfc_core *core, struct mfc_core_ctx *core_ctx,
		unsigned int processing_cycle, unsigned int frame_type)
{
	return false;
}
#endif

void mfc_qos_idle_worker(struct work_struct *work)
{
	struct mfc_core *core;
	struct mfc_core_ctx *core_ctx;
	struct mfc_ctx *ctx;
	int is_idle = 0, qos_num_inst = 0;

	core = container_of(work, struct mfc_core, mfc_idle_work);

	mutex_lock(&core->dev->mfc_mutex);

	mutex_lock(&core->idle_qos_mutex);

	/* Check idle mode for all context */
	mutex_lock(&core->qos_mutex);
	list_for_each_entry(core_ctx, &core->qos_queue, qos_list) {
		ctx = core_ctx->ctx;
		qos_num_inst++;
		if (((atomic_read(&core->hw_run_bits) & (1 << ctx->num)) == 0) &&
				((atomic_read(&core->dev->queued_bits) & (1 << ctx->num)) == 0)) {
			mfc_ctx_change_idle_mode(ctx, MFC_IDLE_MODE_IDLE);
			mfc_debug(3, "[MFCIDLE] ctx[%d] is idle (hw %#x Q %#x)\n", ctx->num,
					atomic_read(&core->hw_run_bits),
					atomic_read(&core->dev->queued_bits));
			ctx->boosting_time = 0;
			is_idle = 1;
		} else {
			mfc_ctx_change_idle_mode(ctx, MFC_IDLE_MODE_NONE);
		}
	}
	mutex_unlock(&core->qos_mutex);

	if (core->idle_mode == MFC_IDLE_MODE_CANCEL) {
		mfc_core_change_idle_mode(core, MFC_IDLE_MODE_NONE);
		mfc_core_debug(2, "[QoS][MFCIDLE] idle mode is canceled\n");
		goto ctx_idle;
	} else if (core->idle_mode == MFC_IDLE_MODE_NONE) {
		mfc_core_idle_checker_start_tick(core);
		goto ctx_idle;
	}

#ifdef CONFIG_MFC_USE_BUS_DEVFREQ
	__mfc_qos_off_all(core);
#endif
	if (qos_num_inst == 1) {
		mfc_core_info("[QoS][MFCIDLE] go to idle mode (src %d(ready %d), dst %d, src_nal %d, dst_nal %d, framecnt %d)\n",
				mfc_get_queue_count(&ctx->buf_queue_lock, &core_ctx->src_buf_queue),
				mfc_get_queue_count(&ctx->buf_queue_lock, &ctx->src_buf_ready_queue),
				mfc_get_queue_count(&ctx->buf_queue_lock, &ctx->dst_buf_queue),
				mfc_get_queue_count(&ctx->buf_queue_lock, &ctx->src_buf_nal_queue),
				mfc_get_queue_count(&ctx->buf_queue_lock, &ctx->dst_buf_nal_queue),
				ctx->frame_cnt);
	} else {
		mfc_core_info("[QoS][MFCIDLE] go to idle mode\n");
	}

	mfc_core_change_idle_mode(core, MFC_IDLE_MODE_IDLE);
	mutex_unlock(&core->idle_qos_mutex);
	mutex_unlock(&core->dev->mfc_mutex);
	return;

ctx_idle:
#ifdef CONFIG_MFC_USE_BUS_DEVFREQ
	if (is_idle) {
		mfc_core_debug(2, "[QoS][MFCIDLE] idle mode is for ctx\n");
		__mfc_qos_on_idle(core);
	}
#endif
	mutex_unlock(&core->idle_qos_mutex);
	mutex_unlock(&core->dev->mfc_mutex);
}

bool mfc_qos_idle_trigger(struct mfc_core *core, struct mfc_ctx *ctx)
{
	bool update_idle = false;

	mutex_lock(&core->idle_qos_mutex);
	if (core->idle_mode == MFC_IDLE_MODE_IDLE) {
		mfc_ctx_debug(2, "[QoS][MFCIDLE] restart QoS control\n");
		mfc_core_change_idle_mode(core, MFC_IDLE_MODE_NONE);
		update_idle = true;
	} else if (core->idle_mode == MFC_IDLE_MODE_RUNNING) {
		mfc_ctx_debug(2, "[QoS][MFCIDLE] restart QoS control, cancel idle\n");
		mfc_core_change_idle_mode(core, MFC_IDLE_MODE_CANCEL);
		update_idle = true;
	}

	if (ctx->idle_mode == MFC_IDLE_MODE_IDLE) {
		mfc_ctx_debug(2, "[QoS][MFCIDLE] restart QoS control for ctx\n");
		mfc_ctx_change_idle_mode(ctx, MFC_IDLE_MODE_NONE);
		update_idle = true;
	}
	mutex_unlock(&core->idle_qos_mutex);

	return update_idle;
}

void mfc_qos_update_boosting(struct mfc_core *core, struct mfc_core_ctx *core_ctx)
{
	struct mfc_ctx *ctx = core_ctx->ctx;
	unsigned int queue_cnt = 0, src_queue_cnt = 0;

	if (!ctx->boosting_time)
		return;

	src_queue_cnt += mfc_get_queue_count(&ctx->buf_queue_lock, &core_ctx->src_buf_queue);
	queue_cnt += mfc_get_queue_count(&ctx->buf_queue_lock, &ctx->src_buf_ready_queue);
	queue_cnt += mfc_get_queue_count(&ctx->buf_queue_lock, &ctx->src_buf_nal_queue);

	queue_cnt += mfc_get_queue_count(&ctx->buf_queue_lock, &ctx->dst_buf_queue);
	queue_cnt += mfc_get_queue_count(&ctx->buf_queue_lock, &ctx->dst_buf_nal_queue);

	if (ctx->boosting_time && ((src_queue_cnt + queue_cnt) <= 1)) {
		u64 ktime = ktime_get_ns();
		if ((ctx->boosting_time <= ktime) ||
			(ctx->boosting_time - ktime) < MFC_BOOST_OFF_TIME) {
			mfc_debug(2, "[BOOST] seeking booster terminated %llu.%06llu\n",
				(ktime / NSEC_PER_SEC),
				(ktime - ((ktime / NSEC_PER_SEC) * NSEC_PER_SEC)) / NSEC_PER_USEC);

			ctx->boosting_time = 0;
			ctx->framerate = ctx->last_framerate;
			mfc_qos_on(core, ctx);
		}
	}
}
