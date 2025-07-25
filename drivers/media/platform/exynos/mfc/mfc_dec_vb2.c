/*
 * drivers/media/platform/exynos/mfc/mfc_dec_vb2_ops.c
 *
 * Copyright (c) 2016 Samsung Electronics Co., Ltd.
 *		http://www.samsung.com/
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include "mfc_dec_v4l2.h"

#include "mfc_rm.h"

#include "mfc_core_sync.h"

#include "base/mfc_meminfo.h"
#include "base/mfc_queue.h"
#include "base/mfc_utils.h"
#include "base/mfc_buf.h"
#include "base/mfc_mem.h"

void mfc_dec_defer_disable(struct mfc_ctx *ctx, int del_timer)
{
	struct mfc_dec *dec = ctx->dec_priv;
	unsigned long flags;

	if (!dec)
		return;

	spin_lock_irqsave(&dec->defer_dec_lock, flags);
	mfc_dec_defer_disable_raw(ctx, del_timer);
	spin_unlock_irqrestore(&dec->defer_dec_lock, flags);

	mfc_rm_request_work(ctx->dev, MFC_WORK_BUTLER, ctx);
}

void mfc_dec_defer_src_checker(struct timer_list *t)
{
	struct mfc_ctx *ctx = from_timer(ctx, t, src_buf_timer);

	mfc_ctx_debug(2, "[DEFER] src buffer timeout\n");
	if (timer_pending(&ctx->dst_buf_timer)) {
		mfc_ctx_debug(2, "[DEFER] dst delete timer\n");
		del_timer(&ctx->dst_buf_timer);
	}

	mfc_dec_defer_disable(ctx, 0);
}

void mfc_dec_defer_dst_checker(struct timer_list *t)
{
	struct mfc_ctx *ctx = from_timer(ctx, t, dst_buf_timer);

	mfc_ctx_debug(2, "[DEFER] dst buffer timeout\n");
	if (timer_pending(&ctx->src_buf_timer)) {
		mfc_ctx_debug(2, "[DEFER] src delete timer\n");
		del_timer(&ctx->src_buf_timer);
	}

	mfc_dec_defer_disable(ctx, 0);
}

static int mfc_dec_queue_setup(struct vb2_queue *vq,
				unsigned int *buf_count, unsigned int *plane_count,
				unsigned int psize[], struct device *alloc_devs[])
{
	struct mfc_ctx *ctx = vq->drv_priv;
	struct mfc_dev *dev = ctx->dev;
	struct mfc_core *core;
	struct mfc_core_ctx *core_ctx;
	struct mfc_raw_info *raw;
	int i;

	mfc_ctx_debug_enter();

	raw = &ctx->raw_buf;

	/*
	 * During queue_setup,
	 * context information is need to for only main core
	 */
	core = mfc_get_main_core_lock(dev, ctx);
	core_ctx = core->core_ctx[ctx->num];

	/* Video output for decoding (source)
	 * this can be set after getting an instance */
	if (core_ctx->state == MFCINST_GOT_INST &&
		vq->type == V4L2_BUF_TYPE_VIDEO_OUTPUT_MPLANE) {
		mfc_debug(4, "dec src\n");
		/* A single plane is required for input */
		*plane_count = 1;
		if (*buf_count < 1)
			*buf_count = 1;
		if (*buf_count > MFC_MAX_BUFFERS)
			*buf_count = MFC_MAX_BUFFERS;

		/* need to use minimum size to prevent qbuf fail */
		psize[0] = 1;
		alloc_devs[0] = dev->device;
	/* Video capture for decoding (destination)
	 * this can be set after the header was parsed */
	} else if (core_ctx->state >= MFCINST_HEAD_PARSED &&
		vq->type == V4L2_BUF_TYPE_VIDEO_CAPTURE_MPLANE) {
		mfc_debug(4, "dec dst\n");
		/* Output plane count is different by the pixel format */
		*plane_count = ctx->dst_fmt->mem_planes;
		/* Setup buffer count */
		if (*buf_count < ctx->dpb_count)
			*buf_count = ctx->dpb_count;
		if (*buf_count > MFC_MAX_BUFFERS)
			*buf_count = MFC_MAX_BUFFERS;

		if (ctx->dst_fmt->mem_planes == 1) {
			psize[0] = raw->total_plane_size;
			alloc_devs[0] = dev->device;
		} else {
			for (i = 0; i < ctx->dst_fmt->num_planes; i++) {
				psize[i] = ctx->min_dpb_size[i];
				alloc_devs[i] = dev->device;
			}
		}
	} else {
		mfc_err("State seems invalid. State = %d, vq->type = %d\n",
							core_ctx->state, vq->type);
		return -EINVAL;
	}

	mfc_debug(2, "buf_count: %d, plane_count: %d, type: %#x\n",
			*buf_count, *plane_count, vq->type);
	for (i = 0; i < *plane_count; i++)
		mfc_debug(2, "plane[%d] size: %d\n", i, psize[i]);

	mfc_ctx_debug_leave();

	return 0;
}

static void mfc_dec_unlock(struct vb2_queue *q)
{
	struct mfc_ctx *ctx = q->drv_priv;
	struct mfc_dev *dev = ctx->dev;

	mutex_unlock(&dev->mfc_mutex);
}

static void mfc_dec_lock(struct vb2_queue *q)
{
	struct mfc_ctx *ctx = q->drv_priv;
	struct mfc_dev *dev = ctx->dev;

	mutex_lock(&dev->mfc_mutex);
}

static int mfc_dec_buf_init(struct vb2_buffer *vb)
{
	struct vb2_queue *vq = vb->vb2_queue;
	struct mfc_ctx *ctx = vq->drv_priv;
	struct mfc_buf *buf = vb_to_mfc_buf(vb);
	int ret;

	mfc_ctx_debug_enter();

	if (vq->type == V4L2_BUF_TYPE_VIDEO_CAPTURE_MPLANE) {
		ret = mfc_check_vb_with_fmt(ctx->dst_fmt, vb);
		if (ret < 0)
			return ret;
		mfc_calc_base_addr(ctx, vb, ctx->dst_fmt);

		buf->paddr = mfc_mem_get_paddr_vb(vb);
		mfc_ctx_debug(2, "[DPB] vb index [%d] vb paddr %#llx daddr %#llx\n",
				vb->index, buf->paddr, buf->addr[0][0]);

		if (call_cop(ctx, init_buf_ctrls, ctx, MFC_CTRL_TYPE_DST,
					vb->index) < 0)
			mfc_ctx_err("failed in init_buf_ctrls\n");
	} else if (vq->type == V4L2_BUF_TYPE_VIDEO_OUTPUT_MPLANE) {
		ret = mfc_check_vb_with_fmt(ctx->src_fmt, vb);
		if (ret < 0)
			return ret;

		buf->addr[0][0] = mfc_mem_get_daddr_vb(vb, 0);

		if (call_cop(ctx, init_buf_ctrls, ctx, MFC_CTRL_TYPE_SRC,
					vb->index) < 0)
			mfc_ctx_err("failed in init_buf_ctrls\n");
	} else {
		mfc_ctx_err("mfc_dec_buf_init: unknown queue type\n");
		return -EINVAL;
	}

	mfc_ctx_debug_leave();

	return 0;
}

static int mfc_dec_buf_prepare(struct vb2_buffer *vb)
{
	struct vb2_queue *vq = vb->vb2_queue;
	struct mfc_ctx *ctx = vq->drv_priv;
	struct mfc_buf *buf = vb_to_mfc_buf(vb);
	struct mfc_raw_info *raw;
	unsigned int index = vb->index;
	size_t buf_size;
	int i;

	if (vq->type == V4L2_BUF_TYPE_VIDEO_CAPTURE_MPLANE) {
		raw = &ctx->raw_buf;
		/* check the size per plane */
		if (ctx->dst_fmt->mem_planes == 1) {
			buf_size = vb2_plane_size(vb, 0);
			mfc_ctx_debug(2, "[FRAME] single plane vb size: %lu, calc size: %d\n",
					buf_size, raw->total_plane_size);
			if (buf_size < raw->total_plane_size) {
				mfc_ctx_err("[FRAME] single plane size(%lu) is smaller than (%d)\n",
						buf_size, raw->total_plane_size);
				return -EINVAL;
			}
		} else {
			for (i = 0; i < ctx->dst_fmt->mem_planes; i++) {
				buf_size = vb2_plane_size(vb, i);
				mfc_ctx_debug(2, "[FRAME] plane[%d] vb size: %lu, calc size: %d\n",
						i, buf_size, raw->plane_size[i]);
				if (buf_size < raw->plane_size[i]) {
					mfc_ctx_err("[FRAME] plane[%d] size(%lu) is smaller than (%d)\n",
							i, buf_size, raw->plane_size[i]);
					return -EINVAL;
				}
			}
		}
		/* Copy dst buffer flag to buf_ctrl */
		buf->flag = call_cop(ctx, get_buf_ctrl_val, ctx,
				&ctx->dst_ctrls[index],
				V4L2_CID_MPEG_VIDEO_DST_BUF_FLAG);

		mfc_mem_buf_prepare(vb, 0);
	} else if (vq->type == V4L2_BUF_TYPE_VIDEO_OUTPUT_MPLANE) {
		buf_size = vb2_plane_size(vb, 0);
		buf->sg_size = mfc_mem_get_sg_length(ctx->dev, vb2_dma_sg_plane_desc(vb, 0));
		mfc_ctx_debug(2, "[STREAM] vb size, %ld, dbuf size, %ld, sg_size, %zu\n",
				buf_size, vb->planes[0].dbuf->size, buf->sg_size);

		call_cop(ctx, to_buf_ctrls, ctx, &ctx->src_ctrls[index]);

		/* Copy src buffer flag to buf_ctrl */
		buf->flag = call_cop(ctx, get_buf_ctrl_val, ctx,
				&ctx->src_ctrls[index],
				V4L2_CID_MPEG_VIDEO_SRC_BUF_FLAG);

		mfc_mem_buf_prepare(vb, 1);
	}


	return 0;
}

static void mfc_dec_buf_finish(struct vb2_buffer *vb)
{
	struct vb2_queue *vq = vb->vb2_queue;
	struct mfc_ctx *ctx = vq->drv_priv;
	struct mfc_buf *buf = vb_to_mfc_buf(vb);
	unsigned int index = vb->index;
#if IS_ENABLED(CONFIG_MFC_USE_DMA_SKIP_LAZY_UNMAP)
	struct mfc_dev *dev = ctx->dev;
	int i;
#endif

	if (vq->type == V4L2_BUF_TYPE_VIDEO_CAPTURE_MPLANE) {
		/* Copy to dst buffer flag */
		call_cop(ctx, update_buf_val, ctx, &ctx->dst_ctrls[index],
				V4L2_CID_MPEG_VIDEO_DST_BUF_FLAG, buf->flag);
		mfc_ctx_debug(4, "[FLAG] dst update buf[%d] flag = %#x\n",
				index, buf->flag);

		call_cop(ctx, to_ctx_ctrls, ctx, &ctx->dst_ctrls[index]);

		mfc_mem_buf_finish(vb, 0);

#if IS_ENABLED(CONFIG_MFC_USE_DMA_SKIP_LAZY_UNMAP)
		if (dev->skip_lazy_unmap || ctx->skip_lazy_unmap) {
			for (i = 0; i < ctx->dst_fmt->mem_planes; i++) {
				vb2_dma_sg_set_map_attr(vb->planes[i].mem_priv,
							DMA_ATTR_SKIP_LAZY_UNMAP);
				mfc_ctx_debug(4, "[LAZY_UNMAP] skip for dst plane[%d]\n", i);
			}
		}
#endif
	} else if (vq->type == V4L2_BUF_TYPE_VIDEO_OUTPUT_MPLANE) {
		/* Copy to src buffer flag */
		call_cop(ctx, update_buf_val, ctx, &ctx->src_ctrls[index],
				V4L2_CID_MPEG_VIDEO_SRC_BUF_FLAG, buf->flag);
		mfc_ctx_debug(4, "[FLAG] src update buf[%d] flag = %#x\n",
				index, buf->flag);

		call_cop(ctx, to_ctx_ctrls, ctx, &ctx->src_ctrls[index]);

#if IS_ENABLED(CONFIG_MFC_USE_DMA_SKIP_LAZY_UNMAP)
		vb2_dma_sg_set_map_attr(vb->planes[0].mem_priv, DMA_ATTR_SKIP_LAZY_UNMAP);
		mfc_ctx_debug(4, "[LAZY_UNMAP] skip for src\n");
#endif
	}
}

static void mfc_dec_buf_cleanup(struct vb2_buffer *vb)
{
	struct vb2_queue *vq = vb->vb2_queue;
	struct mfc_ctx *ctx = vq->drv_priv;
	unsigned int index = vb->index;

	mfc_ctx_debug_enter();

	if (vq->type == V4L2_BUF_TYPE_VIDEO_CAPTURE_MPLANE) {
		if (call_cop(ctx, cleanup_buf_ctrls, ctx,
					MFC_CTRL_TYPE_DST, index) < 0)
			mfc_ctx_err("failed in cleanup_buf_ctrls\n");
	} else if (vq->type == V4L2_BUF_TYPE_VIDEO_OUTPUT_MPLANE) {
		if (call_cop(ctx, cleanup_buf_ctrls, ctx,
					MFC_CTRL_TYPE_SRC, index) < 0)
			mfc_ctx_err("failed in cleanup_buf_ctrls\n");
	} else {
		mfc_ctx_err("mfc_dec_buf_cleanup: unknown queue type\n");
	}

	mfc_ctx_debug_leave();
}

static int mfc_dec_start_streaming(struct vb2_queue *q, unsigned int count)
{
	struct mfc_ctx *ctx = q->drv_priv;
	struct mfc_dev *dev = ctx->dev;

	mfc_ctx_info("dec start_streaming is called, type : %d\n", q->type);
	MFC_TRACE_CTX("** DEC streamon(type:%d)\n", q->type);

	mfc_rm_update_real_time(ctx);

	if ((q->type == V4L2_BUF_TYPE_VIDEO_CAPTURE_MPLANE) && ctx->plugin_type)
		dev->plugin->core_ops->instance_init(dev->plugin, ctx);

	mfc_rm_request_work(dev, MFC_WORK_TRY, ctx);

	return 0;
}

static void mfc_dec_stop_streaming(struct vb2_queue *q)
{
	struct mfc_ctx *ctx = q->drv_priv;
	struct mfc_dev *dev = ctx->dev;

	mfc_ctx_info("dec stop_streaming is called, type : %d\n", q->type);
	MFC_TRACE_CTX("** DEC streamoff(type:%d)\n", q->type);

	mfc_dec_defer_disable(ctx, 1);

	if ((q->type == V4L2_BUF_TYPE_VIDEO_CAPTURE_MPLANE) && ctx->plugin_type)
		dev->plugin->core_ops->instance_deinit(dev->plugin, ctx);

	mfc_rm_instance_dec_stop(dev, ctx, q->type);
}

static void mfc_dec_buf_queue(struct vb2_buffer *vb)
{
	struct vb2_queue *vq = vb->vb2_queue;
	struct mfc_ctx *ctx = vq->drv_priv;
	struct mfc_dev *dev = ctx->dev;
	struct mfc_dec *dec = ctx->dec_priv;
	struct mfc_buf *buf = vb_to_mfc_buf(vb);
	int i;
	unsigned char *stream_vir = NULL;

	mfc_ctx_debug_enter();

	if (vq->type == V4L2_BUF_TYPE_VIDEO_OUTPUT_MPLANE) {
		mutex_lock(&ctx->op_mode_mutex);
		buf->src_index = ctx->serial_src_index++;
		mfc_ctx_debug(2, "[BUFINFO] ctx[%d] add src index: %d(%d), addr: 0x%08llx\n",
				ctx->num, vb->index, buf->src_index,
				buf->addr[0][0]);
		mutex_unlock(&ctx->op_mode_mutex);

		if (vb->memory == V4L2_MEMORY_DMABUF && !ctx->is_drm &&
			mfc_rm_query_state(ctx, SMALLER, MFCINST_HEAD_PARSED))
			stream_vir = vb2_plane_vaddr(vb, 0);

		buf->vir_addr[0] = stream_vir;

		mfc_add_tail_buf(ctx, &ctx->src_buf_ready_queue, buf);

		if (dev->debugfs.debug_ts == 1)
			mfc_ctx_info("[TS] framerate: %ld, timestamp: %lld\n",
					ctx->framerate, buf->vb.vb2_buf.timestamp);
		if (dev->debugfs.meminfo_enable == 1)
			mfc_meminfo_add_inbuf(ctx, vb);

		if (mfc_check_mb_flag(buf, MFC_FLAG_EMPTY_DATA) ||
			 mfc_check_mb_flag(buf, MFC_FLAG_LAST_FRAME))
			mfc_dec_defer_disable(ctx, 1);
		else
			mfc_dec_defer_src_update_timer(ctx);

		MFC_TRACE_CTX("Q src[%d](%d) fd: %d, %#llx\n",
				vb->index, buf->src_index, vb->planes[0].m.fd, buf->addr[0][0]);
	} else if (vq->type == V4L2_BUF_TYPE_VIDEO_CAPTURE_MPLANE) {
		for (i = 0; i < ctx->dst_fmt->mem_planes; i++) {
			if (!ctx->is_drm)
				buf->vir_addr[i] = vb2_plane_vaddr(vb, i);
			mfc_ctx_debug(2, "[BUFINFO] ctx[%d] add dst index: %d, addr[%d]: 0x%08llx\n",
					ctx->num, vb->index, i, buf->addr[0][i]);
		}
		mfc_store_dpb(ctx, vb);

		if ((vb->memory == V4L2_MEMORY_USERPTR || vb->memory == V4L2_MEMORY_DMABUF) &&
				mfc_is_queue_count_same(&ctx->buf_queue_lock,
					&ctx->dst_buf_queue, dec->total_dpb_count))
			ctx->capture_state = QUEUE_BUFS_MMAPED;

		mfc_dec_defer_dst_update_timer(ctx);

		MFC_TRACE_CTX("Q dst[%d][%d] fd: %d, %#llx / used %#lx\n",
				vb->index, buf->dpb_index, vb->planes[0].m.fd,
				buf->addr[0][0], dec->dynamic_used);
	} else {
		mfc_ctx_err("Unsupported buffer type (%d)\n", vq->type);
	}

	mfc_rm_request_work(dev, MFC_WORK_TRY, ctx);

	mfc_ctx_debug_leave();
}

const struct vb2_ops mfc_dec_qops = {
	.queue_setup		= mfc_dec_queue_setup,
	.wait_prepare		= mfc_dec_unlock,
	.wait_finish		= mfc_dec_lock,
	.buf_init		= mfc_dec_buf_init,
	.buf_prepare		= mfc_dec_buf_prepare,
	.buf_finish		= mfc_dec_buf_finish,
	.buf_cleanup		= mfc_dec_buf_cleanup,
	.start_streaming	= mfc_dec_start_streaming,
	.stop_streaming		= mfc_dec_stop_streaming,
	.buf_queue		= mfc_dec_buf_queue,
};
