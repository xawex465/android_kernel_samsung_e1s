/*
 * drivers/media/platform/exynos/mfc/mfc.c
 *
 * Copyright (c) 2016 Samsung Electronics Co., Ltd.
 *		http://www.samsung.com/
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <linux/module.h>
#include <linux/device.h>
#include <linux/platform_device.h>
#include <linux/of_address.h>
#include <linux/of_platform.h>
#include <linux/of.h>
#include <linux/of_reserved_mem.h>
#include <soc/samsung/exynos-smc.h>
#include <linux/debugfs.h>
#include <linux/seq_file.h>
#include <linux/poll.h>
#include <linux/iommu.h>
#if IS_ENABLED(CONFIG_EXYNOS_THERMAL_V2)
#include <soc/samsung/tmu.h>
#include <soc/samsung/isp_cooling.h>
#endif
#include <soc/samsung/exynos/exynos-soc.h>

#include "mfc_dec_v4l2.h"
#include "mfc_dec_internal.h"
#include "mfc_enc_v4l2.h"
#include "mfc_enc_internal.h"
#include "mfc_rm.h"
#include "mfc_debugfs.h"

#include "mfc_core_hwlock.h"
#include "mfc_core_run.h"
#include "mfc_core_otf.h"
#include "mfc_core_sync.h"

#include "mfc_core_hw_reg_api.h"

#include "base/mfc_llc.h"
#include "base/mfc_rate_calculate.h"
#include "base/mfc_qos.h"

#include "base/mfc_common.h"
#include "base/mfc_meminfo.h"
#include "base/mfc_memlog.h"
#include "base/mfc_queue.h"
#include "base/mfc_utils.h"
#include "base/mfc_buf.h"
#include "base/mfc_mem.h"

#define MFC_NAME			"s5p-mfc"
#define MFC_DEC_NAME			"s5p-mfc-dec"
#define MFC_ENC_NAME			"s5p-mfc-enc"
#define MFC_DEC_DRM_NAME		"s5p-mfc-dec-secure"
#define MFC_ENC_DRM_NAME		"s5p-mfc-enc-secure"
#define MFC_ENC_OTF_NAME		"s5p-mfc-enc-otf"
#define MFC_ENC_OTF_DRM_NAME		"s5p-mfc-enc-otf-secure"

struct _mfc_trace g_mfc_trace[MFC_TRACE_COUNT_MAX];
struct _mfc_trace g_mfc_trace_rm[MFC_TRACE_COUNT_MAX];
struct _mfc_trace g_mfc_trace_longterm[MFC_TRACE_COUNT_MAX];
struct mfc_dev *g_mfc_dev;

void mfc_butler_worker(struct work_struct *work)
{
	struct mfc_dev *dev;
	struct mfc_ctx *ctx;
	int i;

	dev = container_of(work, struct mfc_dev, butler_work);

	/* If there is multi core instance, it has high priority */
	if (dev->multi_core_inst_bits) {
		i = __ffs(dev->multi_core_inst_bits);
		ctx = dev->ctx[i];
		if (!ctx) {
			mfc_dev_err("[RM] There is no ctx\n");
			return;
		}

		/* [DRC] In the case of MFC_OP_SWITCH_TO_SINGLE,
		 * also need to request with MFC_WORK_TRY.
		 * Because op_mode is maintained as MFC_OP_SWITCH_TO_SINGLE before subcore_deinit.
		 * And, subcore_deinit can be started by MFC_WORK_TRY.
		 */
		if (!(IS_MULTI_MODE(ctx) || ctx->op_mode == MFC_OP_SWITCH_TO_SINGLE))
			return;

		mfc_rm_request_work(dev, MFC_WORK_TRY, ctx);
	} else {
		mfc_rm_request_work(dev, MFC_WORK_BUTLER, NULL);
	}
}

static void __mfc_deinit_dec_ctx(struct mfc_ctx *ctx)
{
	struct mfc_dec *dec = ctx->dec_priv;
	unsigned int size;

	if (dec->crc && (ctx->dev->debugfs.sfr_dump & MFC_DUMP_DEC_CRC)) {
		if (dec->crc_idx * 4 > SZ_1K)
			size = SZ_1K;
		else
			size = dec->crc_idx * 4;
		print_hex_dump(KERN_ERR, "CRC: ", DUMP_PREFIX_OFFSET, 32, 1,
				dec->crc, size, false);
		vfree(dec->crc);
	}

	mfc_cleanup_iovmm(ctx);

	mfc_delete_queue(&ctx->src_buf_ready_queue);
	mfc_delete_queue(&ctx->dst_buf_queue);
	mfc_delete_queue(&ctx->src_buf_nal_queue);
	mfc_delete_queue(&ctx->dst_buf_nal_queue);
	mfc_delete_queue(&ctx->plugin_buf_queue);
	mfc_delete_queue(&ctx->err_buf_queue);
	mfc_delete_queue(&ctx->meminfo_inbuf_q);

	mfc_dec_defer_delete_timer(ctx);

	if (ctx->plugin_type)
		mfc_release_internal_dpb(ctx);

	mfc_mem_cleanup_user_shared_handle(ctx, &dec->sh_handle_dpb);
	mfc_mem_cleanup_user_shared_handle(ctx, &dec->sh_handle_hdr);
	mfc_mem_cleanup_user_shared_handle(ctx, &dec->sh_handle_av1_film_grain);

	if (dec->ref_info)
		vfree(dec->ref_info);

	if (dec->hdr10_plus_full)
		vfree(dec->hdr10_plus_full);

	if (dec->hdr10_plus_info)
		vfree(dec->hdr10_plus_info);

	if (dec->av1_film_grain_info)
		vfree(dec->av1_film_grain_info);

	kfree(dec);
}

static int __mfc_init_dec_ctx(struct mfc_ctx *ctx)
{
	struct mfc_dec *dec;
	int ret = 0;
	int i;

	dec = kzalloc(sizeof(struct mfc_dec), GFP_KERNEL);
	if (!dec) {
		mfc_ctx_err("failed to allocate decoder private data\n");
		return -ENOMEM;
	}
	ctx->dec_priv = dec;

	ctx->subcore_inst_no = MFC_NO_INSTANCE_SET;
	ctx->curr_src_index = -1;
	ctx->user_prio = -1;

	mfc_create_queue(&ctx->src_buf_ready_queue);
	mfc_create_queue(&ctx->dst_buf_queue);
	mfc_create_queue(&ctx->src_buf_nal_queue);
	mfc_create_queue(&ctx->dst_buf_nal_queue);
	mfc_create_queue(&ctx->plugin_buf_queue);
	mfc_create_queue(&ctx->err_buf_queue);
	mfc_create_queue(&ctx->meminfo_inbuf_q);

	for (i = 0; i < MFC_MAX_BUFFERS; i++) {
		INIT_LIST_HEAD(&ctx->src_ctrls[i]);
		INIT_LIST_HEAD(&ctx->dst_ctrls[i]);
	}
	bitmap_zero(ctx->src_ctrls_avail, MFC_MAX_BUFFERS);
	bitmap_zero(ctx->dst_ctrls_avail, MFC_MAX_BUFFERS);

	ctx->capture_state = QUEUE_FREE;
	ctx->output_state = QUEUE_FREE;

	ctx->type = MFCINST_DECODER;
	ctx->c_ops = &mfc_ctrls_ops;
	ctx->b_ops = &mfc_bufs_ops;

	mfc_dec_set_default_format(ctx);
	mfc_rate_reset_framerate(ctx);

	ctx->qos_ratio = 100;
	INIT_LIST_HEAD(&ctx->bitrate_list);
	INIT_LIST_HEAD(&ctx->src_ts.ts_list);

	dec->display_delay = -1;
	dec->is_interlaced = 0;
	dec->immediate_display = 0;
	dec->is_dts_mode = 0;
	dec->inter_res_change = 0;
	dec->disp_drc.disp_res_change = 0;
	dec->disp_drc.push_idx = 0;
	dec->disp_drc.pop_idx = 0;

	dec->is_dynamic_dpb = 1;
	dec->dynamic_used = 0;
	dec->is_dpb_full = 0;
	dec->queued_dpb = 0;
	dec->display_index = -1;
	dec->dpb_table_used = 0;
	dec->sh_handle_dpb.fd = -1;
	mutex_init(&dec->dpb_mutex);

	dec->defer_dec = 0;
	dec->defer_frame_cnt = 0;
	spin_lock_init(&dec->defer_dec_lock);
	timer_setup(&ctx->src_buf_timer, mfc_dec_defer_src_checker, 0);
	timer_setup(&ctx->dst_buf_timer, mfc_dec_defer_dst_checker, 0);

	mfc_init_dpb_table(ctx);

	dec->sh_handle_dpb.data_size = sizeof(struct dec_dpb_ref_info) * MFC_MAX_BUFFERS;
	dec->ref_info = vmalloc(dec->sh_handle_dpb.data_size);
	if (!dec->ref_info) {
		mfc_ctx_err("failed to allocate decoder information data\n");
		ret = -ENOMEM;
		goto fail_dec_init;
	}
	for (i = 0; i < MFC_MAX_BUFFERS; i++)
		dec->ref_info[i].dpb[0].fd[0] = MFC_INFO_INIT_FD;

	dec->sh_handle_hdr.fd = -1;

	if (ctx->dev->debugfs.sfr_dump & MFC_DUMP_DEC_CRC) {
		dec->crc = vmalloc(SZ_1K);
		if (!dec->crc)
			mfc_ctx_err("[CRC] failed to allocate CRC dump buffer\n");
		dec->crc_idx = 0;
	}

	/* Init videobuf2 queue for OUTPUT */
	ctx->vq_src.type = V4L2_BUF_TYPE_VIDEO_OUTPUT_MPLANE;
	ctx->vq_src.drv_priv = ctx;
	ctx->vq_src.buf_struct_size = (unsigned int)sizeof(struct mfc_buf);
	ctx->vq_src.io_modes = VB2_USERPTR | VB2_DMABUF;
	ctx->vq_src.ops = &mfc_dec_qops;
	ctx->vq_src.mem_ops = mfc_mem_ops();
	ctx->vq_src.timestamp_flags = V4L2_BUF_FLAG_TIMESTAMP_COPY;
	ret = vb2_queue_init(&ctx->vq_src);
	if (ret) {
		mfc_ctx_err("Failed to initialize videobuf2 queue(output)\n");
		goto fail_dec_init;
	}
	/* Init videobuf2 queue for CAPTURE */
	ctx->vq_dst.type = V4L2_BUF_TYPE_VIDEO_CAPTURE_MPLANE;
	ctx->vq_dst.drv_priv = ctx;
	ctx->vq_dst.buf_struct_size = (unsigned int)sizeof(struct mfc_buf);
	ctx->vq_dst.io_modes = VB2_USERPTR | VB2_DMABUF;
	ctx->vq_dst.ops = &mfc_dec_qops;
	ctx->vq_dst.mem_ops = mfc_mem_ops();
	ctx->vq_dst.timestamp_flags = V4L2_BUF_FLAG_TIMESTAMP_COPY;
	ret = vb2_queue_init(&ctx->vq_dst);
	if (ret) {
		mfc_ctx_err("Failed to initialize videobuf2 queue(capture)\n");
		goto fail_dec_init;
	}

	return ret;

fail_dec_init:
	__mfc_deinit_dec_ctx(ctx);
	return ret;
}

static void __mfc_deinit_enc_ctx(struct mfc_ctx *ctx)
{
	struct mfc_enc *enc = ctx->enc_priv;

	mfc_delete_queue(&ctx->src_buf_ready_queue);
	mfc_delete_queue(&ctx->dst_buf_queue);
	mfc_delete_queue(&ctx->src_buf_nal_queue);
	mfc_delete_queue(&ctx->dst_buf_nal_queue);
	mfc_delete_queue(&ctx->ref_buf_queue);
	mfc_delete_queue(&ctx->err_buf_queue);
	mfc_delete_queue(&ctx->meminfo_inbuf_q);
	mfc_delete_queue(&ctx->meminfo_outbuf_q);

	mfc_mem_cleanup_user_shared_handle(ctx, &enc->sh_handle_svc);
	mfc_mem_cleanup_user_shared_handle(ctx, &enc->sh_handle_roi);
	mfc_mem_cleanup_user_shared_handle(ctx, &enc->sh_handle_hdr);

	if (enc->sh_handle_hdr10_plus_stat.fd != -1)
		mfc_put_iovmm_from_fd(ctx, &enc->hdr10_plus_stat_info_buf,
				enc->sh_handle_hdr10_plus_stat.fd);
	mfc_mem_cleanup_user_shared_handle(ctx, &enc->sh_handle_hdr10_plus_stat);
	kfree(enc);
}

static int __mfc_init_enc_ctx(struct mfc_ctx *ctx)
{
	struct mfc_enc *enc;
	struct mfc_enc_params *p;
	int ret = 0;
	int i;

	enc = kzalloc(sizeof(struct mfc_enc), GFP_KERNEL);
	if (!enc) {
		mfc_ctx_err("failed to allocate encoder private data\n");
		return -ENOMEM;
	}
	ctx->enc_priv = enc;
	ctx->user_prio = -1;

	mfc_create_queue(&ctx->src_buf_ready_queue);
	mfc_create_queue(&ctx->dst_buf_queue);
	mfc_create_queue(&ctx->src_buf_nal_queue);
	mfc_create_queue(&ctx->dst_buf_nal_queue);
	mfc_create_queue(&ctx->ref_buf_queue);
	mfc_create_queue(&ctx->err_buf_queue);
	mfc_create_queue(&ctx->meminfo_inbuf_q);
	mfc_create_queue(&ctx->meminfo_outbuf_q);

	for (i = 0; i < MFC_MAX_BUFFERS; i++) {
		INIT_LIST_HEAD(&ctx->src_ctrls[i]);
		INIT_LIST_HEAD(&ctx->dst_ctrls[i]);
	}
	bitmap_zero(ctx->src_ctrls_avail, MFC_MAX_BUFFERS);
	bitmap_zero(ctx->dst_ctrls_avail, MFC_MAX_BUFFERS);

	ctx->type = MFCINST_ENCODER;
	ctx->c_ops = &mfc_ctrls_ops;
	ctx->b_ops = &mfc_bufs_ops;

	mfc_enc_set_default_format(ctx);
	mfc_rate_reset_framerate(ctx);

	ctx->qos_ratio = 100;

	/* disable IVF header by default (VP8, VP9) */
	p = &enc->params;
	p->ivf_header_disable = 1;

	INIT_LIST_HEAD(&ctx->bitrate_list);
	INIT_LIST_HEAD(&ctx->src_ts.ts_list);

	enc->sh_handle_svc.fd = -1;
	enc->sh_handle_roi.fd = -1;
	enc->sh_handle_hdr.fd = -1;
	enc->sh_handle_hdr10_plus_stat.fd = -1;
	enc->sh_handle_svc.data_size = sizeof(struct temporal_layer_info);
	enc->sh_handle_roi.data_size = sizeof(struct mfc_enc_roi_info);
	enc->sh_handle_hdr.data_size = sizeof(struct hdr10_plus_meta) * MFC_MAX_BUFFERS;
	enc->sh_handle_hdr10_plus_stat.data_size =
		sizeof(struct hdr10_plus_stat_info) * MFC_MAX_BUFFERS;

	/* Init videobuf2 queue for OUTPUT */
	ctx->vq_src.type = V4L2_BUF_TYPE_VIDEO_OUTPUT_MPLANE;
	ctx->vq_src.drv_priv = ctx;
	ctx->vq_src.buf_struct_size = (unsigned int)sizeof(struct mfc_buf);
	ctx->vq_src.io_modes = VB2_USERPTR | VB2_DMABUF;
	ctx->vq_src.ops = &mfc_enc_qops;
	ctx->vq_src.mem_ops = mfc_mem_ops();
	ctx->vq_src.timestamp_flags = V4L2_BUF_FLAG_TIMESTAMP_COPY;
	ret = vb2_queue_init(&ctx->vq_src);
	if (ret) {
		mfc_ctx_err("Failed to initialize videobuf2 queue(output)\n");
		goto fail_enc_init;
	}

	/* Init videobuf2 queue for CAPTURE */
	ctx->vq_dst.type = V4L2_BUF_TYPE_VIDEO_CAPTURE_MPLANE;
	ctx->vq_dst.drv_priv = ctx;
	ctx->vq_dst.buf_struct_size = (unsigned int)sizeof(struct mfc_buf);
	ctx->vq_dst.io_modes = VB2_USERPTR | VB2_DMABUF;
	ctx->vq_dst.ops = &mfc_enc_qops;
	ctx->vq_dst.mem_ops = mfc_mem_ops();
	ctx->vq_dst.timestamp_flags = V4L2_BUF_FLAG_TIMESTAMP_COPY;
	ret = vb2_queue_init(&ctx->vq_dst);
	if (ret) {
		mfc_ctx_err("Failed to initialize videobuf2 queue(capture)\n");
		goto fail_enc_init;
	}

	return 0;

fail_enc_init:
	__mfc_deinit_enc_ctx(ctx);
	return 0;
}

/* Open an MFC node */
static int mfc_open(struct file *file)
{
	struct mfc_ctx *ctx = NULL;
	struct mfc_dev *dev = video_drvdata(file);
	int i, ret = 0;
	enum mfc_node_type node;
	struct video_device *vdev = NULL;
	unsigned long total_mb = 0, max_hw_mb = 0;

	if (!dev) {
		mfc_pr_err("no mfc device to run\n");
		goto err_no_device;
	}

	mfc_dev_debug(2, "mfc driver open called\n");

	if (mutex_lock_interruptible(&dev->mfc_mutex))
		return -ERESTARTSYS;

	/* Check mfc_open() of spec over */
	for (i = 0; i < dev->num_core; i++)
		max_hw_mb += dev->core[i]->core_pdata->max_hw_mb;
	for (i = 0; i < MFC_NUM_CONTEXTS; i++) {
		if (!dev->ctx[i])
			continue;
		total_mb += dev->ctx[i]->weighted_mb;
		mfc_show_ctx_info(dev->ctx[i]);
	}
	if (total_mb >= max_hw_mb) {
		mfc_dev_info("[RM] now MFC work with full spec(mb: %lu / %lu)\n",
				total_mb, max_hw_mb);
		for (i = 0; i < MFC_NUM_CONTEXTS; i++) {
			if (!dev->ctx[i])
				continue;
			mfc_print_ctx_info(dev->ctx[i]);
		}
	}

	node = mfc_get_node_type(file);
	if (node == MFCNODE_INVALID) {
		mfc_dev_err("cannot specify node type\n");
		ret = -ENOENT;
		goto err_node_type;
	}

	dev->num_inst++;	/* It is guarded by mfc_mutex in vfd */

	/* Allocate memory for context */
	ctx = kzalloc(sizeof(*ctx), GFP_KERNEL);
	if (!ctx) {
		mfc_dev_err("Not enough memory\n");
		ret = -ENOMEM;
		goto err_ctx_alloc;
	}

	switch (node) {
	case MFCNODE_DECODER:
		vdev = dev->vfd_dec;
		break;
	case MFCNODE_ENCODER:
		vdev = dev->vfd_enc;
		break;
	case MFCNODE_DECODER_DRM:
		vdev = dev->vfd_dec_drm;
		break;
	case MFCNODE_ENCODER_DRM:
		vdev = dev->vfd_enc_drm;
		break;
	case MFCNODE_ENCODER_OTF:
		vdev = dev->vfd_enc_otf;
		break;
	case MFCNODE_ENCODER_OTF_DRM:
		vdev = dev->vfd_enc_otf_drm;
		break;
	default:
		mfc_dev_err("Invalid node(%d)\n", node);
		break;
	}

	if (!vdev)
		goto err_vdev;

	v4l2_fh_init(&ctx->fh, vdev);
	file->private_data = &ctx->fh;
	v4l2_fh_add(&ctx->fh);

	ctx->dev = dev;

	/* Get context number */
	ctx->num = 0;
	while (dev->ctx[ctx->num]) {
		ctx->num++;
		if (ctx->num >= MFC_NUM_CONTEXTS) {
			mfc_ctx_err("Too many open contexts\n");
			mfc_ctx_err("Print information to check if there was an error or not\n");
			call_dop(dev, dump_info_context, dev);
			ret = -EBUSY;
			goto err_ctx_num;
		}
	}

	spin_lock_init(&ctx->buf_queue_lock);
	spin_lock_init(&ctx->meminfo_queue_lock);
	spin_lock_init(&ctx->corelock.lock);
	spin_lock_init(&ctx->src_ts.ts_lock);
	spin_lock_init(&ctx->dst_q_ts.ts_lock);
	spin_lock_init(&ctx->dst_dq_ts.ts_lock);
	spin_lock_init(&ctx->src_q_ts.ts_lock);
	mutex_init(&ctx->intlock.core_mutex);
	mutex_init(&ctx->op_mode_mutex);
	mutex_init(&ctx->drc_wait_mutex);
	init_waitqueue_head(&ctx->corelock.wq);
	init_waitqueue_head(&ctx->corelock.migrate_wq);
	INIT_LIST_HEAD(&ctx->dst_q_ts.ts_list);
	INIT_LIST_HEAD(&ctx->dst_dq_ts.ts_list);
	INIT_LIST_HEAD(&ctx->src_q_ts.ts_list);

	mfc_ctx_change_idle_mode(ctx, MFC_IDLE_MODE_NONE);

	if (mfc_is_decoder_node(node)) {
		ret = __mfc_init_dec_ctx(ctx);
		dev->num_dec_inst++;
	} else {
		ret = __mfc_init_enc_ctx(ctx);
		dev->num_enc_inst++;
	}
	if (ret)
		goto err_ctx_init;

	if (dev->num_inst == 1) {
		/* regression test val */
		if (dev->debugfs.regression_option) {
			dev->regression_val = vmalloc(SZ_1M);
			if (!dev->regression_val)
				mfc_ctx_err("[MFCREGRESSION] failed to allocate regression result data\n");
		}

		/* all of the ctx list */
		INIT_LIST_HEAD(&dev->ctx_list);
		spin_lock_init(&dev->ctx_list_lock);
		/* idle mode */
		spin_lock_init(&dev->idle_bits_lock);
	}

	ret = call_cop(ctx, init_ctx_ctrls, ctx);
	if (ret) {
		mfc_ctx_err("failed in init_ctx_ctrls\n");
		goto err_ctx_ctrls;
	}

	if (mfc_is_drm_node(node)) {
#if IS_ENABLED(CONFIG_EXYNOS_CONTENT_PATH_PROTECTION)
		if (dev->num_drm_inst < dev->pdata->max_num_drm_inst) {
			dev->num_drm_inst++;
			ctx->is_drm = 1;

			mfc_ctx_info("DRM %s instance is opened [%d:%d]\n",
					ctx->type == MFCINST_DECODER ? "Decoder" : "Encoder",
					dev->num_drm_inst, dev->num_inst);
		} else {
			mfc_ctx_err("Too many instance are opened for DRM\n");
			mfc_ctx_err("Print information to check if there was an error or not\n");
			call_dop(dev, dump_info_context, dev);
			ret = -EINVAL;
			goto err_drm_start;
		}
#else
		mfc_ctx_err("DRM %s instance couldn't opened [%d:%d]\n",
				ctx->type == MFCINST_DECODER ? "Decoder" : "Encoder",
				dev->num_drm_inst, dev->num_inst);
		ret = -EINVAL;
		goto err_drm_start;
#endif
	} else {
		mfc_ctx_info("NORMAL %s instance is opened [%d:%d]\n",
				ctx->type == MFCINST_DECODER ? "Decoder" : "Encoder",
				dev->num_drm_inst, dev->num_inst);
	}

	/* Mark context as idle */
	dev->ctx[ctx->num] = ctx;
	for (i = 0; i < MFC_NUM_CORE; i++)
		ctx->op_core_num[i] = MFC_CORE_INVALID;

	ret = mfc_rm_instance_init(dev, ctx);
	if (ret) {
		mfc_ctx_err("rm_instance_init failed\n");
		goto err_drm_start;
	}

#if IS_ENABLED(CONFIG_VIDEO_EXYNOS_REPEATER)
	if (mfc_is_encoder_otf_node(node)) {
		ret = mfc_core_otf_create(ctx);
		if (ret)
			mfc_ctx_err("[OTF] otf_create failed\n");
	}
#endif

	mfc_ctx_info("MFC open completed [%d:%d] version = %d\n",
			dev->num_drm_inst, dev->num_inst, MFC_DRIVER_INFO);
	MFC_TRACE_CTX_LT("[INFO] %s %s opened (ctx:%d, total:%d)\n", ctx->is_drm ? "DRM" : "Normal",
			mfc_is_decoder_node(node) ? "DEC" : "ENC", ctx->num, dev->num_inst);

	queue_work(dev->butler_wq, &dev->butler_work);

	mutex_unlock(&dev->mfc_mutex);
	return ret;

	/* Deinit when failure occured */
err_drm_start:
	call_cop(ctx, cleanup_ctx_ctrls, ctx);

err_ctx_ctrls:
	if ((dev->num_inst == 0) && dev->regression_val)
		vfree(dev->regression_val);

err_ctx_init:
	if (mfc_is_decoder_node(node))
		dev->num_dec_inst--;
	else
		dev->num_enc_inst--;
	dev->ctx[ctx->num] = 0;

err_ctx_num:
	v4l2_fh_del(&ctx->fh);
	v4l2_fh_exit(&ctx->fh);

err_vdev:
	kfree(ctx);

err_ctx_alloc:
	dev->num_inst--;

err_node_type:
	mfc_dev_err("MFC driver open is failed [%d:%d]\n",
			dev->num_drm_inst, dev->num_inst);
	mutex_unlock(&dev->mfc_mutex);

err_no_device:

	return ret;
}

/* Release MFC context */
static int mfc_release(struct file *file)
{
	struct mfc_ctx *ctx = fh_to_mfc_ctx(file->private_data);
	struct mfc_dev *dev = ctx->dev;
	struct mfc_ctx *move_ctx;
	int ret = 0;
	int i;

	mutex_lock(&dev->mfc_mutex);
	mutex_lock(&dev->mfc_migrate_mutex);

	mfc_ctx_info("%s %s instance release is called [%d:%d], is_drm(%d)\n",
			ctx->is_drm ? "DRM" : "NORMAL",
			ctx->type == MFCINST_DECODER ? "Decoder" : "Encoder",
			dev->num_drm_inst, dev->num_inst, ctx->is_drm);

	MFC_TRACE_CTX_LT("[INFO] release is called (ctx:%d, total:%d)\n", ctx->num, dev->num_inst);

#if IS_ENABLED(CONFIG_VIDEO_EXYNOS_REPEATER)
	if (ctx->otf_handle) {
		mfc_core_otf_unregister_cb(ctx);
		clear_bit(ctx->num, &dev->otf_inst_bits);
	}
#endif

	/* Free resources */
	v4l2_fh_del(&ctx->fh);
	v4l2_fh_exit(&ctx->fh);

	/*
	 * mfc_release() can be called without a streamoff
	 * when the application is forcibly terminated.
	 * At that time, stop_streaming() is called by vb2_queue_release.
	 * So, we need to performed stop_streaming
	 * before instance de-init(CLOSE_INSTANCE).
	 */
	vb2_queue_release(&ctx->vq_src);
	vb2_queue_release(&ctx->vq_dst);

	call_cop(ctx, cleanup_ctx_ctrls, ctx);

	ret = mfc_rm_instance_deinit(dev, ctx);
	if (ret) {
		mfc_dev_err("failed to rm_instance_deinit\n");
		goto end_release;
	}

	if (ctx->is_drm)
		dev->num_drm_inst--;
	dev->num_inst--;
	dev->regression_cnt = 0;

	if (IS_MULTI_CORE_DEVICE(dev))
		mfc_rm_load_balancing(ctx, MFC_RM_LOAD_DELETE_UPDATE);

	mfc_meminfo_cleanup_inbuf_q(ctx);
	if (ctx->type == MFCINST_ENCODER)
		mfc_meminfo_cleanup_outbuf_q(ctx);

	if (dev->num_inst == 0)
		if (dev->regression_val && dev->debugfs.regression_option)
			vfree(dev->regression_val);

	if (ctx->type == MFCINST_DECODER) {
		__mfc_deinit_dec_ctx(ctx);
		dev->num_dec_inst--;
	} else if (ctx->type == MFCINST_ENCODER) {
		__mfc_deinit_enc_ctx(ctx);
		dev->num_enc_inst--;
	}

#if IS_ENABLED(CONFIG_VIDEO_EXYNOS_REPEATER)
	if (ctx->otf_handle) {
		mfc_core_otf_deinit(ctx);
		mfc_core_otf_destroy(ctx);
	}
#endif

	MFC_TRACE_CTX_LT("[INFO] Release finished (ctx:%d, total:%d)\n", ctx->num, dev->num_inst);

	/* If ctx is move_ctx in migration worker, clear move_ctx */
	for (i = 0; i < dev->move_ctx_cnt; i++) {
		move_ctx = dev->move_ctx[i];
		if (move_ctx && (move_ctx->num == ctx->num)) {
			dev->move_ctx[i] = NULL;
			break;
		}
	}

	dev->ctx[ctx->num] = NULL;
	kfree(ctx);

	mfc_dev_info("mfc driver release finished [%d:%d]\n", dev->num_drm_inst, dev->num_inst);

	queue_work(dev->butler_wq, &dev->butler_work);

end_release:
	mutex_unlock(&dev->mfc_migrate_mutex);
	mutex_unlock(&dev->mfc_mutex);
	return ret;
}

/* Poll */
static __poll_t mfc_poll(struct file *file,
				 struct poll_table_struct *wait)
{
	struct mfc_ctx *ctx = fh_to_mfc_ctx(file->private_data);
	unsigned long req_events = poll_requested_events(wait);
	__poll_t ret = 0;

	mfc_ctx_debug_enter();

	if (mfc_rm_query_state(ctx, EQUAL, MFCINST_ERROR)) {
		if (req_events & (POLLOUT | POLLWRNORM))
			mfc_ctx_err("SRC: Call on POLL after unrecoverable error\n");
		else
			mfc_ctx_err("DST: Call on POLL after unrecoverable error\n");
		return EPOLLERR;
	}

	if (req_events & (POLLOUT | POLLWRNORM)) {
		mfc_ctx_debug(2, "wait source buffer\n");
		ret = vb2_poll(&ctx->vq_src, file, wait);
	} else if (req_events & (POLLIN | POLLRDNORM)) {
		mfc_ctx_debug(2, "wait destination buffer\n");
		ret = vb2_poll(&ctx->vq_dst, file, wait);
	}

	mfc_ctx_debug_leave();
	return ret;
}

/* v4l2 ops */
static const struct v4l2_file_operations mfc_fops = {
	.owner = THIS_MODULE,
	.open = mfc_open,
	.release = mfc_release,
	.poll = mfc_poll,
	.unlocked_ioctl = video_ioctl2,
};

static void __mfc_parse_dt_resource(struct mfc_dev *dev, struct device_node *np)
{
	struct device_node *np_resource;
	struct device_node *np_tmp;
	int idx = 0;
	struct mfc_resource *resource;
	unsigned int codec_mode;

	/* Initialization */
	for (idx = 0; idx < MFC_MAX_CODEC_TYPE; idx++) {
		resource = &dev->pdata->mfc_resource[idx];
		resource->op_core_type = MFC_OP_CORE_NOT_FIXED;
	}

	np_resource = of_get_child_by_name(np, "mfc_resource");
	if (!np_resource) {
		dev_err(dev->device, "there is no mfc_resource\n");
		return;
	}

	/* Parse resource infomation */
	for_each_child_of_node(np_resource, np_tmp) {
		idx = 0;
		of_property_read_u32_index(np_tmp, "info", idx++, &codec_mode);
		resource = &dev->pdata->mfc_resource[codec_mode];
		of_property_read_u32_index(np_tmp, "info", idx++, &resource->op_core_type);
		of_property_read_u32_index(np_tmp, "info", idx++, &resource->max_Kbps);
		if (resource->max_Kbps > dev->max_Kbps)
			dev->max_Kbps = resource->max_Kbps;
	}
}

static int __mfc_parse_dt(struct device_node *np, struct mfc_dev *mfc)
{
	struct mfc_platdata *pdata = mfc->pdata;

	if (!np) {
		dev_err(mfc->device, "there is no device node\n");
		return -EINVAL;
	}

	/* MFC DVA reservation start address and DMA bit mask */
	of_property_read_u32(np, "reserved_start", &pdata->reserved_start);
	of_property_read_u32(np, "dma_bit_mask", &pdata->dma_bit_mask);

	/* MFC version */
	of_property_read_u32(np, "ip_ver", &pdata->ip_ver);

	/* DRM registers */
	of_property_read_u32(np, "drm_regs", &pdata->drm_regs);

	/* Debug mode */
	of_property_read_u32(np, "debug_mode", &pdata->debug_mode);

	/* Max num secure DRM instance */
	of_property_read_u32(np, "max_num_drm_inst", &pdata->max_num_drm_inst);

	/* NAL-Q size */
	of_property_read_u32(np, "nal_q_entry_size", &pdata->nal_q_entry_size);
	of_property_read_u32(np, "nal_q_dump_size", &pdata->nal_q_dump_size);

	/* Resource of standard */
	__mfc_parse_dt_resource(mfc, np);

	/* Features */
	of_property_read_u32_array(np, "nal_q", &pdata->nal_q.support, 2);
	of_property_read_u32_array(np, "nal_q_ll", &pdata->nal_q_ll.support, 2);
	of_property_read_u32_array(np, "skype", &pdata->skype.support, 2);
	of_property_read_u32_array(np, "black_bar",
			&pdata->black_bar.support, 2);
	of_property_read_u32_array(np, "color_aspect_dec",
			&pdata->color_aspect_dec.support, 2);
	of_property_read_u32_array(np, "static_info_dec",
			&pdata->static_info_dec.support, 2);
	of_property_read_u32_array(np, "color_aspect_enc",
			&pdata->color_aspect_enc.support, 2);
	of_property_read_u32_array(np, "static_info_enc",
			&pdata->static_info_enc.support, 2);
	of_property_read_u32_array(np, "hdr10_plus",
			&pdata->hdr10_plus.support, 2);
	of_property_read_u32_array(np, "vp9_stride_align",
			&pdata->vp9_stride_align.support, 2);
	of_property_read_u32_array(np, "sbwc_uncomp",
			&pdata->sbwc_uncomp.support, 2);
	of_property_read_u32_array(np, "mem_clear",
			&pdata->mem_clear.support, 2);
	of_property_read_u32_array(np, "wait_fw_status",
			&pdata->wait_fw_status.support, 2);
	of_property_read_u32_array(np, "wait_nalq_status",
			&pdata->wait_nalq_status.support, 2);
	of_property_read_u32_array(np, "drm_switch_predict",
			&pdata->drm_switch_predict.support, 2);
	of_property_read_u32_array(np, "sbwc_enc_src_ctrl",
			&pdata->sbwc_enc_src_ctrl.support, 2);
	of_property_read_u32_array(np, "metadata_interface",
			&pdata->metadata_interface.support, 2);
	of_property_read_u32_array(np, "hdr10_plus_full",
			&pdata->hdr10_plus_full.support, 2);
	of_property_read_u32_array(np, "average_qp",
			&pdata->average_qp.support, 2);
	of_property_read_u32_array(np, "mv_search_mode",
			&pdata->mv_search_mode.support, 2);
	of_property_read_u32_array(np, "hdr10_plus_stat_info",
			&pdata->hdr10_plus_stat_info.support, 2);
	of_property_read_u32_array(np, "enc_idr_flag",
			&pdata->enc_idr_flag.support, 2);
	of_property_read_u32_array(np, "min_quality_mode",
			&pdata->min_quality_mode.support, 2);
	of_property_read_u32_array(np, "enc_capability",
			&pdata->enc_capability.support, 2);
	of_property_read_u32_array(np, "enc_ts_delta",
			&pdata->enc_ts_delta.support, 2);
	of_property_read_u32_array(np, "wfd_rc_mode",
			&pdata->wfd_rc_mode.support, 2);
	of_property_read_u32_array(np, "max_i_frame_size",
			&pdata->max_i_frame_size.support, 2);
	of_property_read_u32_array(np, "hevc_pic_output_flag",
			&pdata->hevc_pic_output_flag.support, 2);

	/* Determine whether to enable AV1 decoder */
	of_property_read_u32_array(np, "av1_film_grain",
			&pdata->av1_film_grain.support, 2);
	/* Plug-in: Whether to compress internal DPB (1: SBWC, 0: YUV) */
	of_property_read_u32(np, "internal_fmt_comp", &pdata->internal_fmt_comp);
	of_property_read_u32(np, "support_fg_shadow", &pdata->support_fg_shadow);

	/* H/W limitation or option */
	of_property_read_u32(np, "P010_decoding", &pdata->P010_decoding);
	of_property_read_u32(np, "dithering_enable", &pdata->dithering_enable);
	of_property_read_u32(np, "stride_align", &pdata->stride_align);
	of_property_read_u32(np, "stride_type", &pdata->stride_type);
	of_property_read_u32(np, "stream_buf_limit", &pdata->stream_buf_limit);
	of_property_read_u32(np, "support_8K_cavlc", &pdata->support_8K_cavlc);

	/* Formats */
	of_property_read_u32(np, "support_10bit", &pdata->support_10bit);
	of_property_read_u32(np, "support_422", &pdata->support_422);
	of_property_read_u32(np, "support_rgb", &pdata->support_rgb);

	/* Resolution */
	of_property_read_u32(np, "support_check_res", &pdata->support_check_res);

	/* SBWC */
	of_property_read_u32(np, "support_sbwc", &pdata->support_sbwc);
	of_property_read_u32(np, "support_sbwcl", &pdata->support_sbwcl);
	of_property_read_u32(np, "support_sbwcl40", &pdata->support_sbwcl40);
	of_property_read_u32(np, "support_sbwclh", &pdata->support_sbwclh);
	of_property_read_u32(np, "support_sbwc_gpu", &pdata->support_sbwc_gpu);

	/* SBWC */
	of_property_read_u32(np, "sbwc_dec_max_width", &pdata->sbwc_dec_max_width);
	of_property_read_u32(np, "sbwc_dec_max_height", &pdata->sbwc_dec_max_height);
	of_property_read_u32(np, "sbwc_dec_max_inst_num", &pdata->sbwc_dec_max_inst_num);
	of_property_read_u32(np, "sbwc_dec_max_framerate", &pdata->sbwc_dec_max_framerate);
	of_property_read_u32(np, "sbwc_dec_hdr10_off", &pdata->sbwc_dec_hdr10_off);

	/* HDR10+ num max window */
	of_property_read_u32(np, "max_hdr_win", &pdata->max_hdr_win);

	/* Default HDR10+ Profile for SEI */
	of_property_read_u32(np, "hdr10_plus_profile", &pdata->hdr10_plus_profile);

	/* HDR10+ num max window */
	of_property_read_u32(np, "display_err_type", &pdata->display_err_type);

	/* security ctrl */
	of_property_read_u32(np, "security_ctrl", &pdata->security_ctrl);

	/* output buffer Q framerate */
	of_property_read_u32(np, "display_framerate", &pdata->display_framerate);

	/* Encoder default parameter */
	of_property_read_u32(np, "enc_param_num", &pdata->enc_param_num);
	if (pdata->enc_param_num) {
		of_property_read_u32_array(np, "enc_param_addr",
				pdata->enc_param_addr, pdata->enc_param_num);
		of_property_read_u32_array(np, "enc_param_val",
				pdata->enc_param_val, pdata->enc_param_num);
	}

	/* MFC bandwidth information */
	of_property_read_u32_array(np, "bw_enc_h264",
			&pdata->mfc_bw_info.bw_enc_h264.peak, 3);
	of_property_read_u32_array(np, "bw_enc_hevc",
			&pdata->mfc_bw_info.bw_enc_hevc.peak, 3);
	of_property_read_u32_array(np, "bw_enc_hevc_10bit",
			&pdata->mfc_bw_info.bw_enc_hevc_10bit.peak, 3);
	of_property_read_u32_array(np, "bw_enc_vp8",
			&pdata->mfc_bw_info.bw_enc_vp8.peak, 3);
	of_property_read_u32_array(np, "bw_enc_vp9",
			&pdata->mfc_bw_info.bw_enc_vp9.peak, 3);
	of_property_read_u32_array(np, "bw_enc_vp9_10bit",
			&pdata->mfc_bw_info.bw_enc_vp9_10bit.peak, 3);
	of_property_read_u32_array(np, "bw_enc_mpeg4",
			&pdata->mfc_bw_info.bw_enc_mpeg4.peak, 3);
	of_property_read_u32_array(np, "bw_dec_h264",
			&pdata->mfc_bw_info.bw_dec_h264.peak, 3);
	of_property_read_u32_array(np, "bw_dec_hevc",
			&pdata->mfc_bw_info.bw_dec_hevc.peak, 3);
	of_property_read_u32_array(np, "bw_dec_hevc_10bit",
			&pdata->mfc_bw_info.bw_dec_hevc_10bit.peak, 3);
	of_property_read_u32_array(np, "bw_dec_vp8",
			&pdata->mfc_bw_info.bw_dec_vp8.peak, 3);
	of_property_read_u32_array(np, "bw_dec_vp9",
			&pdata->mfc_bw_info.bw_dec_vp9.peak, 3);
	of_property_read_u32_array(np, "bw_dec_vp9_10bit",
			&pdata->mfc_bw_info.bw_dec_vp9_10bit.peak, 3);
	of_property_read_u32_array(np, "bw_dec_av1",
			&pdata->mfc_bw_info.bw_dec_av1.peak, 3);
	of_property_read_u32_array(np, "bw_dec_av1_10bit",
			&pdata->mfc_bw_info.bw_dec_av1_10bit.peak, 3);
	of_property_read_u32_array(np, "bw_dec_mpeg4",
			&pdata->mfc_bw_info.bw_dec_mpeg4.peak, 3);

	if (pdata->support_sbwc) {
		of_property_read_u32_array(np, "sbwc_bw_enc_h264",
			&pdata->mfc_bw_info_sbwc.bw_enc_h264.peak, 3);
		of_property_read_u32_array(np, "sbwc_bw_enc_hevc",
			&pdata->mfc_bw_info_sbwc.bw_enc_hevc.peak, 3);
		of_property_read_u32_array(np, "sbwc_bw_enc_hevc_10bit",
			&pdata->mfc_bw_info_sbwc.bw_enc_hevc_10bit.peak, 3);
		of_property_read_u32_array(np, "sbwc_bw_enc_vp8",
			&pdata->mfc_bw_info_sbwc.bw_enc_vp8.peak, 3);
		of_property_read_u32_array(np, "sbwc_bw_enc_vp9",
			&pdata->mfc_bw_info_sbwc.bw_enc_vp9.peak, 3);
		of_property_read_u32_array(np, "sbwc_bw_enc_vp9_10bit",
			&pdata->mfc_bw_info_sbwc.bw_enc_vp9_10bit.peak, 3);
		of_property_read_u32_array(np, "sbwc_bw_enc_mpeg4",
			&pdata->mfc_bw_info_sbwc.bw_enc_mpeg4.peak, 3);
		of_property_read_u32_array(np, "sbwc_bw_dec_h264",
			&pdata->mfc_bw_info_sbwc.bw_dec_h264.peak, 3);
		of_property_read_u32_array(np, "sbwc_bw_dec_hevc",
			&pdata->mfc_bw_info_sbwc.bw_dec_hevc.peak, 3);
		of_property_read_u32_array(np, "sbwc_bw_dec_hevc_10bit",
			&pdata->mfc_bw_info_sbwc.bw_dec_hevc_10bit.peak, 3);
		of_property_read_u32_array(np, "sbwc_bw_dec_vp8",
			&pdata->mfc_bw_info_sbwc.bw_dec_vp8.peak, 3);
		of_property_read_u32_array(np, "sbwc_bw_dec_vp9",
			&pdata->mfc_bw_info_sbwc.bw_dec_vp9.peak, 3);
		of_property_read_u32_array(np, "sbwc_bw_dec_vp9_10bit",
			&pdata->mfc_bw_info_sbwc.bw_dec_vp9_10bit.peak, 3);
		of_property_read_u32_array(np, "sbwc_bw_dec_mpeg4",
			&pdata->mfc_bw_info_sbwc.bw_dec_mpeg4.peak, 3);
	}

	/* QoS weight */
	of_property_read_u32(np, "dynamic_weight", &pdata->dynamic_weight);
	of_property_read_u32(np, "qos_weight_h264_hevc",
			&pdata->qos_weight.weight_h264_hevc);
	of_property_read_u32(np, "qos_weight_vp8_vp9",
			&pdata->qos_weight.weight_vp8_vp9);
	of_property_read_u32(np, "qos_weight_av1",
			&pdata->qos_weight.weight_av1);
	of_property_read_u32(np, "qos_weight_other_codec",
			&pdata->qos_weight.weight_other_codec);
	of_property_read_u32(np, "qos_weight_3plane",
			&pdata->qos_weight.weight_3plane);
	of_property_read_u32(np, "qos_weight_10bit",
			&pdata->qos_weight.weight_10bit);
	of_property_read_u32(np, "qos_weight_422",
			&pdata->qos_weight.weight_422);
	of_property_read_u32(np, "qos_weight_bframe",
			&pdata->qos_weight.weight_bframe);
	of_property_read_u32(np, "qos_weight_num_of_ref",
			&pdata->qos_weight.weight_num_of_ref);
	of_property_read_u32(np, "qos_weight_gpb",
			&pdata->qos_weight.weight_gpb);
	of_property_read_u32(np, "qos_weight_num_of_tile",
			&pdata->qos_weight.weight_num_of_tile);
	of_property_read_u32(np, "qos_weight_super64_bframe",
			&pdata->qos_weight.weight_super64_bframe);
	of_property_read_u32(np, "qos_weight_mbaff",
			&pdata->qos_weight.weight_mbaff);

	/* Bitrate control for QoS */
	of_property_read_u32(np, "num_mfc_freq", &pdata->num_mfc_freq);
	if (pdata->num_mfc_freq)
		of_property_read_u32_array(np, "mfc_freqs",
				pdata->mfc_freqs, pdata->num_mfc_freq);

	/* Core balance(%) for resource managing */
	of_property_read_u32(np, "core_balance", &pdata->core_balance);

	/* MFC IOVA threshold */
	of_property_read_u32(np, "iova_threshold", &pdata->iova_threshold);

	/* MFC idle clock control */
	of_property_read_u32(np, "idle_clk_ctrl", &pdata->idle_clk_ctrl);

	/* QoS level for pm_qos dynamic control */
	of_property_read_u32(np, "qos_ctrl_level", &pdata->qos_ctrl_level);

	/* Memlog size */
	of_property_read_u32(np, "memlog_size", &pdata->memlog_size);
	of_property_read_u32(np, "memlog_sfr_size", &pdata->memlog_sfr_size);

	/* offset for saving result of regression */
	of_property_read_u32(np, "reg_h264_loop_filter_disable", &pdata->reg_h264_loop_filter_disable);

	/* Scheduler */
	of_property_read_u32(np, "scheduler", &pdata->scheduler);
	of_property_read_u32(np, "pbs_num_prio", &pdata->pbs_num_prio);

	/* Encoder RGB CSC formula by VUI from F/W */
	of_property_read_u32(np, "enc_rgb_csc_by_fw", &pdata->enc_rgb_csc_by_fw);

	return 0;
}

static void *__mfc_get_drv_data(struct platform_device *pdev);

static struct video_device *__mfc_video_device_register(struct mfc_dev *dev,
				char *name, int node_num)
{
	struct video_device *vfd;
	int ret = 0;

	vfd = video_device_alloc();
	if (!vfd) {
		v4l2_err(&dev->v4l2_dev, "Failed to allocate video device\n");
		return NULL;
	}
	strncpy(vfd->name, name, sizeof(vfd->name) - 1);
	vfd->fops = &mfc_fops;
	vfd->minor = -1;
	vfd->release = video_device_release;

	if (IS_DEC_NODE(node_num))
		vfd->ioctl_ops = mfc_get_dec_v4l2_ioctl_ops();
	else if(IS_ENC_NODE(node_num))
		vfd->ioctl_ops = mfc_get_enc_v4l2_ioctl_ops();

	vfd->lock = &dev->mfc_mutex;
	vfd->v4l2_dev = &dev->v4l2_dev;
	vfd->vfl_dir = VFL_DIR_M2M;
	set_bit(V4L2_FL_QUIRK_INVERTED_CROP, &vfd->flags);
	vfd->device_caps = V4L2_CAP_VIDEO_CAPTURE
			| V4L2_CAP_VIDEO_OUTPUT
			| V4L2_CAP_VIDEO_CAPTURE_MPLANE
			| V4L2_CAP_VIDEO_OUTPUT_MPLANE
			| V4L2_CAP_STREAMING;

	ret = video_register_device(vfd, VFL_TYPE_VIDEO, node_num);
	if (ret) {
		v4l2_err(&dev->v4l2_dev, "Failed to register video device /dev/video%d\n", node_num);
		video_device_release(vfd);
		return NULL;
	}
	v4l2_info(&dev->v4l2_dev, "video device registered as /dev/video%d\n",
								vfd->num);
	video_set_drvdata(vfd, dev);

	return vfd;
}

#if IS_ENABLED(CONFIG_EXYNOS_THERMAL_V2)
#define TMU_UNLIMITED_FPS	60
static int __mfc_tmu_notifier(struct notifier_block *nb, unsigned long state,
				void *nb_data)
{
	struct mfc_dev *dev;
	int fps = 0;

	dev = container_of(nb, struct mfc_dev, tmu_nb);

	if (state == ISP_THROTTLING) {
		fps = isp_cooling_get_fps(0, *(unsigned long *)nb_data);

		if (fps >= TMU_UNLIMITED_FPS) {
			dev->tmu_fps = 0;
			mfc_dev_info("[TMU] THROTTLING: Unlimited FPS (%d)\n", fps);
		} else if (fps > 0) {
			dev->tmu_fps = fps * 1000;
			mfc_dev_info("[TMU] THROTTLING: Limited %d FPS\n", fps);
		} else {
			dev->tmu_fps = 0;
			mfc_dev_err("[TMU] THROTTLING: Wrong %d FPS\n", fps);
		}
	} else {
		mfc_dev_err("[TMU] Wrong TMU state %lu\n", state);
	}

	return 0;
}
#endif

/* MFC probe function */
static int mfc_probe(struct platform_device *pdev)
{
	struct device *device = &pdev->dev;
	struct device_node *np = device->of_node;
	struct mfc_dev *dev;
	int ret = -ENOENT;

	dev_info(&pdev->dev, "%s is called\n", __func__);

	dev = devm_kzalloc(&pdev->dev, sizeof(struct mfc_dev), GFP_KERNEL);
	if (!dev) {
		dev_err(&pdev->dev, "Not enough memory for MFC device\n");
		return -ENOMEM;
	}

	/* empty device for CPU cache flush with dma_sync_* API */
	dev->cache_op_dev = devm_kzalloc(&pdev->dev, sizeof(struct device), GFP_KERNEL);
	device_initialize(dev->cache_op_dev);
	dma_coerce_mask_and_coherent(dev->cache_op_dev, DMA_BIT_MASK(36));

	dev->device = &pdev->dev;
	dev->variant = __mfc_get_drv_data(pdev);
	platform_set_drvdata(pdev, dev);

	dev->pdata = devm_kzalloc(&pdev->dev, sizeof(struct mfc_platdata), GFP_KERNEL);
	if (!dev->pdata) {
		dev_err(&pdev->dev, "no memory for state\n");
		ret = -ENOMEM;
		goto err_res_mem;
	}

	ret = __mfc_parse_dt(dev->device->of_node, dev);
	if (ret)
		goto err_res_mem;

	mfc_dev_init_memlog(pdev);
	mfc_init_debugfs(dev);

	atomic_set(&dev->trace_ref, 0);
	atomic_set(&dev->trace_ref_longterm, 0);
	dev->mfc_trace = g_mfc_trace;
	dev->mfc_trace_rm = g_mfc_trace_rm;
	dev->mfc_trace_longterm = g_mfc_trace_longterm;

	if (dev->pdata->dma_bit_mask < MFC_MIN_BITMASK)
		dev->pdata->dma_bit_mask = MFC_MIN_BITMASK;
	dma_set_mask(&pdev->dev, DMA_BIT_MASK(dev->pdata->dma_bit_mask));

	mutex_init(&dev->mfc_mutex);
	mutex_init(&dev->mfc_migrate_mutex);

	ret = v4l2_device_register(&pdev->dev, &dev->v4l2_dev);
	if (ret)
		goto err_v4l2_dev;

	/* decoder */
	dev->vfd_dec = __mfc_video_device_register(dev, MFC_DEC_NAME,
			EXYNOS_VIDEONODE_MFC_DEC);
	if (!dev->vfd_dec) {
		ret = -ENOMEM;
		goto alloc_vdev_dec;
	}

	/* encoder */
	dev->vfd_enc = __mfc_video_device_register(dev, MFC_ENC_NAME,
			EXYNOS_VIDEONODE_MFC_ENC);
	if (!dev->vfd_enc) {
		ret = -ENOMEM;
		goto alloc_vdev_enc;
	}

	/* secure decoder */
	dev->vfd_dec_drm = __mfc_video_device_register(dev, MFC_DEC_DRM_NAME,
			EXYNOS_VIDEONODE_MFC_DEC_DRM);
	if (!dev->vfd_dec_drm) {
		ret = -ENOMEM;
		goto alloc_vdev_dec_drm;
	}

	/* secure encoder */
	dev->vfd_enc_drm = __mfc_video_device_register(dev, MFC_ENC_DRM_NAME,
			EXYNOS_VIDEONODE_MFC_ENC_DRM);
	if (!dev->vfd_enc_drm) {
		ret = -ENOMEM;
		goto alloc_vdev_enc_drm;
	}

	/* OTF encoder */
	dev->vfd_enc_otf = __mfc_video_device_register(dev, MFC_ENC_OTF_NAME,
			EXYNOS_VIDEONODE_MFC_ENC_OTF);
	if (!dev->vfd_enc_otf) {
		ret = -ENOMEM;
		goto alloc_vdev_enc_otf;
	}

	/* OTF secure encoder */
	dev->vfd_enc_otf_drm = __mfc_video_device_register(dev, MFC_ENC_OTF_DRM_NAME,
			EXYNOS_VIDEONODE_MFC_ENC_OTF_DRM);
	if (!dev->vfd_enc_otf_drm) {
		ret = -ENOMEM;
		goto alloc_vdev_enc_otf_drm;
	}
	/* end of node setting*/

	/* instance migration worker */
	dev->migration_wq = alloc_workqueue("mfc/inst_migration", WQ_UNBOUND
					| WQ_MEM_RECLAIM | WQ_HIGHPRI, 1);
	if (dev->migration_wq == NULL) {
		dev_err(&pdev->dev, "failed to create workqueue for migration wq\n");
		goto err_migration_work;
	}
	INIT_WORK(&dev->migration_work, mfc_rm_migration_worker);

	/* main butler worker */
	dev->butler_wq = alloc_workqueue("mfc/butler", WQ_UNBOUND
					| WQ_MEM_RECLAIM | WQ_HIGHPRI, 1);
	if (dev->butler_wq == NULL) {
		dev_err(&pdev->dev, "failed to create workqueue for butler\n");
		goto err_butler_wq;
	}
	INIT_WORK(&dev->butler_work, mfc_butler_worker);

	ret = of_reserved_mem_device_init(dev->device);
	if (ret)
		mfc_dev_err("Failed to get reserved memory region (%d)\n", ret);

	/* for DVA reservation */
	if (dev->pdata->reserved_start) {
		dev->domain = iommu_get_domain_for_dev(dev->device);
		ret = mfc_iova_pool_init(dev);
		if (ret) {
			mfc_dev_err("Failed to reserve memory (%d)\n", ret);
			goto err_iova_reserve;
		}
	}

#if defined(CONFIG_SOC_S5E9935) || defined(CONFIG_SOC_S5E9945)
	/* Whether GPU supports SBWC according to the revision */
	if (dev->pdata->support_sbwc_gpu && (exynos_soc_info.main_rev == 0))
		dev->pdata->support_sbwc_gpu = 0;
#endif

	/* dump information call-back function */
	dev->dump_ops = &mfc_dump_ops;

	g_mfc_dev = dev;

#if IS_ENABLED(CONFIG_EXYNOS_THERMAL_V2)
	dev->tmu_nb.notifier_call = __mfc_tmu_notifier;
	exynos_tmu_isp_add_notifier(&dev->tmu_nb);
#endif

	__platform_driver_register(&mfc_core_driver, THIS_MODULE);
	__platform_driver_register(&mfc_plugin_driver, THIS_MODULE);
	of_platform_populate(np, NULL, NULL, device);

	dev_info(&pdev->dev, "%s is completed\n", __func__);

	return 0;

/* Deinit MFC if probe had failed */
err_iova_reserve:
	destroy_workqueue(dev->butler_wq);
err_butler_wq:
	destroy_workqueue(dev->migration_wq);
err_migration_work:
	video_unregister_device(dev->vfd_enc_otf_drm);
alloc_vdev_enc_otf_drm:
	video_unregister_device(dev->vfd_enc_otf);
alloc_vdev_enc_otf:
	video_unregister_device(dev->vfd_enc_drm);
alloc_vdev_enc_drm:
	video_unregister_device(dev->vfd_dec_drm);
alloc_vdev_dec_drm:
	video_unregister_device(dev->vfd_enc);
alloc_vdev_enc:
	video_unregister_device(dev->vfd_dec);
alloc_vdev_dec:
	v4l2_device_unregister(&dev->v4l2_dev);
err_v4l2_dev:
	mutex_destroy(&dev->mfc_mutex);
	mutex_destroy(&dev->mfc_migrate_mutex);
err_res_mem:
	mfc_dev_deinit_memlog(dev);
	return ret;
}

/* Remove the driver */
static int mfc_remove(struct platform_device *pdev)
{
	struct mfc_dev *dev = platform_get_drvdata(pdev);

	mfc_dev_info("++MFC remove\n");

	platform_driver_unregister(&mfc_plugin_driver);
	platform_driver_unregister(&mfc_core_driver);

	of_reserved_mem_device_release(dev->device);
	flush_workqueue(dev->butler_wq);
	destroy_workqueue(dev->butler_wq);
	flush_workqueue(dev->migration_wq);
	destroy_workqueue(dev->migration_wq);

	mfc_deinit_debugfs(dev);
	video_unregister_device(dev->vfd_enc);
	video_unregister_device(dev->vfd_dec);
	video_unregister_device(dev->vfd_dec_drm);
	video_unregister_device(dev->vfd_enc_drm);
	video_unregister_device(dev->vfd_enc_otf);
	video_unregister_device(dev->vfd_enc_otf_drm);
	v4l2_device_unregister(&dev->v4l2_dev);

	mfc_dev_deinit_memlog(dev);

	mfc_dev_info("--MFC remove\n");
	return 0;
}

static void mfc_shutdown(struct platform_device *pdev)
{
	struct platform_driver *pcoredrv = &mfc_core_driver;
	struct mfc_dev *dev = platform_get_drvdata(pdev);
	struct mfc_core *core;
	int i;

	for (i = 0; i < dev->num_core; i++) {
		core = dev->core[i];
		if (!core) {
			mfc_dev_debug(2, "There is no core[%d]\n", i);
			continue;
		}

		if (!core->shutdown) {
			mfc_core_info("%s core shutdown was not performed\n", core->name);
			pcoredrv->shutdown(to_platform_device(core->device));
		}
	}

	mfc_dev_info("MFC shutdown is completed\n");
}

#if IS_ENABLED(CONFIG_PM_SLEEP)
static int mfc_suspend(struct device *device)
{
	struct mfc_dev *dev = platform_get_drvdata(to_platform_device(device));
	struct mfc_core *core[MFC_NUM_CORE];
	int i, ret;

	if (!dev) {
		dev_err(device, "no mfc device to run\n");
		return -EINVAL;
	}

	for (i = 0; i < dev->num_core; i++) {
		core[i] = dev->core[i];
		if (!core[i]) {
			dev_err(device, "no mfc core%d device to run\n", i);
			return -EINVAL;
		}

		if (core[i]->state == MFCCORE_ERROR) {
			dev_info(device, "[MSR] Couldn't sleep. It's Error state\n");
			return 0;
		}
	}

	/*
	 * Multi core mode instance can send sleep command
	 * when there are no H/W operation both two core.
	 */
	for (i = 0; i < dev->num_core; i++) {
		core[i] = dev->core[i];
		if (!core[i]) {
			dev_err(device, "no mfc core%d device to run\n", i);
			return -EINVAL;
		}

		if (core[i]->num_inst == 0) {
			core[i] = NULL;
			continue;
		}

		mfc_dev_info("MFC%d will suspend\n", i);

		ret = mfc_core_get_hwlock_dev(core[i]);
		if (ret < 0) {
			mfc_dev_err("Failed to get hwlock for MFC%d\n", i);
			mfc_dev_err("dev:0x%lx, bits:0x%lx, owned:%d, wl:%d, trans:%d\n",
					core[i]->hwlock.dev, core[i]->hwlock.bits,
					core[i]->hwlock.owned_by_irq,
					core[i]->hwlock.wl_count,
					core[i]->hwlock.transfer_owner);
			return -EBUSY;
		}

		if (!mfc_core_get_pwr_ref_cnt(core[i])) {
			mfc_dev_info("MFC%d power has not been turned on yet\n", i);
			mfc_core_release_hwlock_dev(core[i]);
			core[i] = NULL;
			continue;
		}
	}

	for (i = 0; i < dev->num_core; i++) {
		if (core[i]) {
			ret = mfc_core_run_sleep(core[i]);
			if (ret) {
				mfc_dev_err("Failed core_run_sleep for MFC%d\n", i);
				return -EFAULT;
			}

			if (core[i]->has_llc && core[i]->llc_on_status) {
				mfc_llc_flush(core[i]);
				mfc_llc_disable(core[i]);
			}

			mfc_core_release_hwlock_dev(core[i]);

			mfc_dev_info("MFC%d suspend is completed\n", i);
		}
	}

	return 0;
}

static int mfc_resume(struct device *device)
{
	struct mfc_dev *dev = platform_get_drvdata(to_platform_device(device));
	struct mfc_core *core;
	struct mfc_core_ctx *core_ctx;
	int i, ret;

	if (!dev) {
		dev_err(device, "no mfc device to run\n");
		return -EINVAL;
	}

	for (i = 0; i < dev->num_core; i++) {
		core = dev->core[i];
		if (!core) {
			dev_err(device, "no mfc core%d device to run\n", i);
			return -EINVAL;
		}

		if (core->state == MFCCORE_ERROR) {
			mfc_core_info("[MSR] Couldn't wakeup. It's Error state\n");
			return 0;
		}
	}

	for (i = 0; i < dev->num_core; i++) {
		core = dev->core[i];
		if (!core) {
			dev_err(device, "no mfc core%d device to run\n", i);
			return -EINVAL;
		}

		if (core->num_inst == 0)
			continue;

		mfc_dev_info("MFC%d will resume\n", i);

		ret = mfc_core_get_hwlock_dev(core);
		if (ret < 0) {
			mfc_dev_err("Failed to get hwlock for MFC%d\n", i);
			mfc_dev_err("dev:0x%lx, bits:0x%lx, owned:%d, wl:%d, trans:%d\n",
					core->hwlock.dev, core->hwlock.bits,
					core->hwlock.owned_by_irq,
					core->hwlock.wl_count,
					core->hwlock.transfer_owner);
			return -EBUSY;
		}

		if (core->has_llc && (core->llc_on_status == 0)) {
			mfc_llc_enable(core);

			core_ctx = core->core_ctx[core->curr_core_ctx];
			if (core_ctx)
				mfc_llc_handle_resol(core, core_ctx->ctx);
		}

		ret = mfc_core_run_wakeup(core);
		if (ret) {
			mfc_dev_err("Failed core_run_wakeup for MFC%d\n", i);
			return -EFAULT;
		}

		mfc_core_release_hwlock_dev(core);

		mfc_dev_info("MFC%d resume is completed\n", i);
	}

	return 0;
}
#endif

#if IS_ENABLED(CONFIG_PM)
static int mfc_runtime_suspend(struct device *device)
{
	struct mfc_dev *dev = platform_get_drvdata(to_platform_device(device));

	mfc_dev_debug(3, "mfc runtime suspend\n");

	return 0;
}

static int mfc_runtime_idle(struct device *dev)
{
	return 0;
}

static int mfc_runtime_resume(struct device *device)
{
	struct mfc_dev *dev = platform_get_drvdata(to_platform_device(device));

	mfc_dev_debug(3, "mfc runtime resume\n");

	return 0;
}
#endif

/* Power management */
static const struct dev_pm_ops mfc_pm_ops = {
	SET_SYSTEM_SLEEP_PM_OPS(mfc_suspend, mfc_resume)
	SET_RUNTIME_PM_OPS(
			mfc_runtime_suspend,
			mfc_runtime_resume,
			mfc_runtime_idle
	)
};

struct mfc_ctx_buf_size mfc_ctx_buf_size = {
	.dev_ctx	= PAGE_ALIGN(0x7800),	/*  30KB */
	.h264_dec_ctx	= PAGE_ALIGN(0x200000),	/* 1.6MB */
	.other_dec_ctx	= PAGE_ALIGN(0xF000),	/*  60KB */
	.h264_enc_ctx	= PAGE_ALIGN(0x19000),	/* 100KB */
	.hevc_enc_ctx	= PAGE_ALIGN(0xC800),	/*  50KB */
	.other_enc_ctx	= PAGE_ALIGN(0xC800),	/*  50KB */
	.dbg_info_buf	= PAGE_ALIGN(0x1000),	/* 4KB for DEBUG INFO */
};

struct mfc_buf_size mfc_buf_size = {
	.firmware_code	= PAGE_ALIGN(0x100000),	/* 1MB */
	.ctx_buf	= &mfc_ctx_buf_size,
};

static struct mfc_variant mfc_drvdata = {
	.buf_size = &mfc_buf_size,
	.num_entities = 2,
};

static const struct of_device_id exynos_mfc_match[] = {
	{
		.compatible = "samsung,exynos-mfc",
		.data = &mfc_drvdata,
	},
	{},
};
MODULE_DEVICE_TABLE(of, exynos_mfc_match);

static void *__mfc_get_drv_data(struct platform_device *pdev)
{
	struct mfc_variant *driver_data = NULL;

	if (pdev->dev.of_node) {
		const struct of_device_id *match;
		match = of_match_node(of_match_ptr(exynos_mfc_match),
				pdev->dev.of_node);
		if (match)
			driver_data = (struct mfc_variant *)match->data;
	} else {
		driver_data = (struct mfc_variant *)
			platform_get_device_id(pdev)->driver_data;
	}
	return driver_data;
}

static struct platform_driver mfc_driver = {
	.probe		= mfc_probe,
	.remove		= mfc_remove,
	.shutdown	= mfc_shutdown,
	.driver	= {
		.name	= MFC_NAME,
		.owner	= THIS_MODULE,
		.pm	= &mfc_pm_ops,
		.of_match_table = exynos_mfc_match,
		.suppress_bind_attrs = true,
	},
};

module_platform_driver(mfc_driver);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Kamil Debski <k.debski@samsung.com>");
