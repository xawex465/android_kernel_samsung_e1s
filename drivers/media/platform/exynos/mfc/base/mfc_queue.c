/*
 * drivers/media/platform/exynos/mfc/mfc_queue.c
 *
 * Copyright (c) 2016 Samsung Electronics Co., Ltd.
 *		http://www.samsung.com/
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include "mfc_queue.h"

#include "mfc_utils.h"
#include "mfc_mem.h"

void mfc_add_tail_buf(struct mfc_ctx *ctx, struct mfc_buf_queue *queue,
		struct mfc_buf *mfc_buf)
{
	unsigned long flags;

	if (!mfc_buf) {
		mfc_ctx_err("mfc_buf is NULL!\n");
		return;
	}

	spin_lock_irqsave(&ctx->buf_queue_lock, flags);

	mfc_buf->used = 0;
	list_add_tail(&mfc_buf->list, &queue->head);
	queue->count++;

	spin_unlock_irqrestore(&ctx->buf_queue_lock, flags);
}

struct mfc_buf *mfc_get_buf_no_used(struct mfc_ctx *ctx, struct mfc_buf_queue *queue,
		enum mfc_queue_used_type used)
{
	unsigned long flags;
	struct mfc_buf *mfc_buf = NULL;

	spin_lock_irqsave(&ctx->buf_queue_lock, flags);

	if (list_empty(&queue->head)) {
		mfc_ctx_debug(2, "queue is empty\n");
		spin_unlock_irqrestore(&ctx->buf_queue_lock, flags);
		return NULL;
	}

	list_for_each_entry(mfc_buf, &queue->head, list) {
		if (mfc_buf->used)
			continue;

		if ((used == MFC_BUF_RESET_USED) || (used == MFC_BUF_SET_USED))
			mfc_buf->used = used;

		mfc_ctx_debug(2, "addr[0]: 0x%08llx\n", mfc_buf->addr[0][0]);
		spin_unlock_irqrestore(&ctx->buf_queue_lock, flags);
		return mfc_buf;
	}

	spin_unlock_irqrestore(&ctx->buf_queue_lock, flags);
	return NULL;
}

struct mfc_buf *mfc_get_buf(struct mfc_ctx *ctx, struct mfc_buf_queue *queue,
		enum mfc_queue_used_type used)
{
	unsigned long flags;
	struct mfc_buf *mfc_buf = NULL;

	spin_lock_irqsave(&ctx->buf_queue_lock, flags);

	if (list_empty(&queue->head)) {
		mfc_ctx_debug(2, "queue is empty\n");
		spin_unlock_irqrestore(&ctx->buf_queue_lock, flags);
		return NULL;
	}

	mfc_buf = list_entry(queue->head.next, struct mfc_buf, list);

	if ((used == MFC_BUF_RESET_USED) || (used == MFC_BUF_SET_USED))
		mfc_buf->used = used;

	mfc_ctx_debug(2, "addr[0]: 0x%08llx\n", mfc_buf->addr[0][0]);

	spin_unlock_irqrestore(&ctx->buf_queue_lock, flags);
	return mfc_buf;
}

struct mfc_buf *mfc_get_del_buf(struct mfc_ctx *ctx, struct mfc_buf_queue *queue,
		enum mfc_queue_used_type used)
{
	unsigned long flags;
	struct mfc_buf *mfc_buf = NULL;

	spin_lock_irqsave(&ctx->buf_queue_lock, flags);

	if (list_empty(&queue->head)) {
		mfc_ctx_debug(2, "queue is empty\n");
		spin_unlock_irqrestore(&ctx->buf_queue_lock, flags);
		return NULL;
	}

	mfc_buf = list_entry(queue->head.next, struct mfc_buf, list);

	if ((used == MFC_BUF_RESET_USED) || (used == MFC_BUF_SET_USED))
		mfc_buf->used = used;

	mfc_ctx_debug(2, "addr[0]: 0x%08llx\n", mfc_buf->addr[0][0]);

	list_del(&mfc_buf->list);
	queue->count--;

	spin_unlock_irqrestore(&ctx->buf_queue_lock, flags);
	return mfc_buf;
}

struct mfc_buf *mfc_get_del_if_consumed(struct mfc_ctx *ctx, struct mfc_buf_queue *queue,
		unsigned int consumed, unsigned int min_bytes, int error, int *deleted)
{
	unsigned long flags;
	struct mfc_buf *mfc_buf = NULL;
	unsigned int remained, strm_size;
	bool exceed = false;

	spin_lock_irqsave(&ctx->buf_queue_lock, flags);

	if (list_empty(&queue->head)) {
		mfc_ctx_debug(2, "queue is empty\n");
		spin_unlock_irqrestore(&ctx->buf_queue_lock, flags);
		return NULL;
	}

	mfc_buf = list_entry(queue->head.next, struct mfc_buf, list);

	mfc_ctx_debug(2, "addr[0]: 0x%08llx\n", mfc_buf->addr[0][0]);

	strm_size = mfc_dec_get_strm_size(ctx, mfc_buf);
	if (strm_size >= consumed) {
		remained = strm_size - consumed;
	} else {
		remained = 0;
		exceed = true;
		mfc_ctx_err("[MULTIFRAME] consumed (%d) exceeded the strm_size (%d)\n",
				consumed, strm_size);
	}

	if (remained && IS_MULTI_MODE(ctx) && !CODEC_MULTIFRAME(ctx)) {
		mfc_ctx_info("[2CORE][MULTIFRAME] multicore mode couldn't handle multiframe\n");
		remained = 0;
	}

	if ((consumed > 0) && (remained > min_bytes)
			&& (IS_NO_ERROR(error)) && (exceed == false)) {
		/* do not delete from queue */
		*deleted = 0;
	} else {
		list_del(&mfc_buf->list);
		queue->count--;

		*deleted = 1;
	}

	mfc_ctx_debug(2, "[MULTIFRAME] strm %d, consumed %d, remained %d, deleted %d, error %d, exceed %d\n",
			strm_size, consumed, remained, *deleted, error, exceed);

	spin_unlock_irqrestore(&ctx->buf_queue_lock, flags);
	return mfc_buf;
}

struct mfc_buf *mfc_get_move_buf(struct mfc_ctx *ctx, struct mfc_buf_queue *to_queue,
		struct mfc_buf_queue *from_queue, enum mfc_queue_used_type used,
		enum mfc_queue_top_type top)
{
	unsigned long flags;
	struct mfc_buf *mfc_buf = NULL;

	spin_lock_irqsave(&ctx->buf_queue_lock, flags);

	if (list_empty(&from_queue->head)) {
		mfc_ctx_debug(2, "from_queue is empty\n");
		spin_unlock_irqrestore(&ctx->buf_queue_lock, flags);
		return NULL;
	}

	mfc_buf = list_entry(from_queue->head.next, struct mfc_buf, list);

	if ((used == MFC_BUF_RESET_USED) || (used == MFC_BUF_SET_USED))
		mfc_buf->used = used;

	mfc_ctx_debug(2, "addr[0]: 0x%08llx\n", mfc_buf->addr[0][0]);

	list_del(&mfc_buf->list);
	from_queue->count--;

	if (top == MFC_QUEUE_ADD_TOP)
		list_add(&mfc_buf->list, &to_queue->head);
	else
		list_add_tail(&mfc_buf->list, &to_queue->head);

	to_queue->count++;

	spin_unlock_irqrestore(&ctx->buf_queue_lock, flags);
	return mfc_buf;
}

struct mfc_buf *mfc_get_move_buf_used(struct mfc_ctx *ctx,
		struct mfc_buf_queue *to_queue, struct mfc_buf_queue *from_queue)
{
	unsigned long flags;
	struct mfc_buf *mfc_buf = NULL;

	spin_lock_irqsave(&ctx->buf_queue_lock, flags);

	if (list_empty(&from_queue->head)) {
		mfc_ctx_debug(2, "from_queue is empty\n");
		spin_unlock_irqrestore(&ctx->buf_queue_lock, flags);
		return NULL;
	}

	mfc_buf = list_entry(from_queue->head.next, struct mfc_buf, list);

	if (mfc_buf->used) {
		mfc_ctx_debug(2, "addr[0]: 0x%08llx\n", mfc_buf->addr[0][0]);

		list_del(&mfc_buf->list);
		from_queue->count--;

		list_add_tail(&mfc_buf->list, &to_queue->head);
		to_queue->count++;

		spin_unlock_irqrestore(&ctx->buf_queue_lock, flags);
		return mfc_buf;
	} else {
		spin_unlock_irqrestore(&ctx->buf_queue_lock, flags);
		return NULL;
	}
}

struct mfc_buf *mfc_get_move_buf_addr(struct mfc_ctx *ctx,
		struct mfc_buf_queue *to_queue, struct mfc_buf_queue *from_queue,
		dma_addr_t addr, unsigned long used_flag)
{
	unsigned long flags;
	struct mfc_buf *mfc_buf = NULL;

	spin_lock_irqsave(&ctx->buf_queue_lock, flags);

	if (list_empty(&from_queue->head)) {
		mfc_ctx_debug(2, "[DPB] from_queue is empty\n");
		spin_unlock_irqrestore(&ctx->buf_queue_lock, flags);
		return NULL;
	}

	list_for_each_entry(mfc_buf, &from_queue->head, list) {
		if (mfc_buf->addr[0][0] == addr) {
			if (used_flag & (1UL << mfc_buf->dpb_index)) {
				mfc_ctx_debug(2, "[DPB] addr[0]: 0x%08llx still referenced\n",
						mfc_buf->addr[0][0]);
				spin_unlock_irqrestore(&ctx->buf_queue_lock, flags);
				return NULL;
			}

			mfc_ctx_debug(2, "[DPB] addr[0]: 0x%08llx\n", mfc_buf->addr[0][0]);

			list_del(&mfc_buf->list);
			from_queue->count--;

			list_add_tail(&mfc_buf->list, &to_queue->head);
			to_queue->count++;

			spin_unlock_irqrestore(&ctx->buf_queue_lock, flags);
			return mfc_buf;
		}
	}

	spin_unlock_irqrestore(&ctx->buf_queue_lock, flags);
	return NULL;
}

struct mfc_buf *mfc_get_move_buf_index(struct mfc_ctx *ctx,
		struct mfc_buf_queue *to_queue, struct mfc_buf_queue *from_queue,
		int index, enum mfc_queue_used_type used)
{
	struct mfc_buf *mfc_buf = NULL;
	unsigned long flags;

	spin_lock_irqsave(&ctx->buf_queue_lock, flags);

	mfc_ctx_debug(4, "Looking for this index: %d\n", index);
	list_for_each_entry(mfc_buf, &from_queue->head, list) {
		if (mfc_buf->dpb_index == index) {
			mfc_ctx_debug(2, "[DPB] buf[%d][%d] addr[0]: 0x%08llx\n",
					mfc_buf->vb.vb2_buf.index, mfc_buf->dpb_index, mfc_buf->addr[0][0]);

			list_del(&mfc_buf->list);
			from_queue->count--;

			list_add_tail(&mfc_buf->list, &to_queue->head);
			to_queue->count++;

			if ((used == MFC_BUF_RESET_USED) || (used == MFC_BUF_SET_USED))
				mfc_buf->used = used;

			spin_unlock_irqrestore(&ctx->buf_queue_lock, flags);
			return mfc_buf;
		}
	}

	spin_unlock_irqrestore(&ctx->buf_queue_lock, flags);
	return NULL;
}

struct mfc_buf *mfc_get_move_buf_ino(struct mfc_ctx *ctx, struct mfc_buf_queue *to_queue,
		struct mfc_buf_queue *from_queue, unsigned long i_ino, enum mfc_queue_top_type top)
{
	struct mfc_buf *mfc_buf = NULL;
	unsigned long flags;

	spin_lock_irqsave(&ctx->buf_queue_lock, flags);

	mfc_ctx_debug(4, "Looking for this ino: %lu\n", i_ino);
	list_for_each_entry(mfc_buf, &from_queue->head, list) {
		if (mfc_buf->i_ino == i_ino) {
			list_del(&mfc_buf->list);
			from_queue->count--;

			if (top == MFC_QUEUE_ADD_TOP)
				list_add(&mfc_buf->list, &to_queue->head);
			else
				list_add_tail(&mfc_buf->list, &to_queue->head);
			to_queue->count++;

			spin_unlock_irqrestore(&ctx->buf_queue_lock, flags);
			return mfc_buf;
		}
	}

	spin_unlock_irqrestore(&ctx->buf_queue_lock, flags);
	return NULL;
}

struct mfc_buf *mfc_find_first_buf(struct mfc_ctx *ctx, struct mfc_buf_queue *queue, dma_addr_t addr)
{
	unsigned long flags;
	struct mfc_buf *mfc_buf = NULL;
	dma_addr_t mb_addr;
	int i;

	spin_lock_irqsave(&ctx->buf_queue_lock, flags);

	if (list_empty(&queue->head)) {
		mfc_ctx_debug(2, "queue is empty\n");
		spin_unlock_irqrestore(&ctx->buf_queue_lock, flags);
		return mfc_buf;
	}

	mfc_ctx_debug(4, "Looking for this address: 0x%08llx\n", addr);
	mfc_buf = list_entry(queue->head.next, struct mfc_buf, list);
	if (mfc_buf->num_valid_bufs > 0) {
		for (i = 0; i < mfc_buf->num_valid_bufs; i++) {
			mb_addr = mfc_buf->addr[i][0];
			mfc_ctx_debug(4, "[BUFCON] batch[%d] addr[0]: 0x%08llx\n", i, mb_addr);
			if (addr == mb_addr) {
				spin_unlock_irqrestore(&ctx->buf_queue_lock, flags);
				return mfc_buf;
			}
		}
	} else {
		mb_addr = mfc_buf->addr[0][0];
		mfc_ctx_debug(4, "addr[0]: 0x%08llx\n", mb_addr);

		if (addr == mb_addr) {
			spin_unlock_irqrestore(&ctx->buf_queue_lock, flags);
			return mfc_buf;
		}
	}

	spin_unlock_irqrestore(&ctx->buf_queue_lock, flags);
	return NULL;
}

struct mfc_buf *mfc_find_buf(struct mfc_ctx *ctx, struct mfc_buf_queue *queue, dma_addr_t addr)
{
	unsigned long flags;
	struct mfc_buf *mfc_buf = NULL;
	dma_addr_t mb_addr;
	int i;

	spin_lock_irqsave(&ctx->buf_queue_lock, flags);

	mfc_ctx_debug(4, "Looking for this address: 0x%08llx\n", addr);
	list_for_each_entry(mfc_buf, &queue->head, list) {
		if (mfc_buf->num_valid_bufs > 0) {
			for (i = 0; i < mfc_buf->num_valid_bufs; i++) {
				mb_addr = mfc_buf->addr[i][0];
				mfc_ctx_debug(4, "[BUFCON] batch[%d] addr[0]: 0x%08llx\n", i, mb_addr);
				if (addr == mb_addr) {
					spin_unlock_irqrestore(&ctx->buf_queue_lock, flags);
					return mfc_buf;
				}
			}
		} else {
			mb_addr = mfc_buf->addr[0][0];
			mfc_ctx_debug(4, "addr[0]: 0x%08llx\n", mb_addr);

			if (addr == mb_addr) {
				spin_unlock_irqrestore(&ctx->buf_queue_lock, flags);
				return mfc_buf;
			}
		}
	}

	spin_unlock_irqrestore(&ctx->buf_queue_lock, flags);
	return NULL;
}

struct mfc_buf *mfc_find_buf_ino(struct mfc_ctx *ctx, struct mfc_buf_queue *queue, unsigned long i_ino)
{
	unsigned long flags;
	struct mfc_buf *mfc_buf = NULL;
	unsigned long mb_ino;

	spin_lock_irqsave(&ctx->buf_queue_lock, flags);

	mfc_ctx_debug(4, "Looking for this inode: %lu\n", i_ino);
	list_for_each_entry(mfc_buf, &queue->head, list) {
		mb_ino = mfc_buf->i_ino;
		mfc_ctx_debug(4, "inode: %lu, addr[0]: 0x%08llx\n", mb_ino, mfc_buf->addr[0][0]);
		if (i_ino == mb_ino) {
			spin_unlock_irqrestore(&ctx->buf_queue_lock, flags);
			return mfc_buf;
		}
	}

	spin_unlock_irqrestore(&ctx->buf_queue_lock, flags);
	return NULL;
}

struct mfc_buf *mfc_find_del_buf(struct mfc_ctx *ctx, struct mfc_buf_queue *queue, dma_addr_t addr)
{
	unsigned long flags;
	struct mfc_buf *mfc_buf = NULL;
	dma_addr_t mb_addr;
	int found = 0, i;

	spin_lock_irqsave(&ctx->buf_queue_lock, flags);

	mfc_ctx_debug(4, "Looking for this address: 0x%08llx\n", addr);
	list_for_each_entry(mfc_buf, &queue->head, list) {
		if (mfc_buf->num_valid_bufs > 0) {
			for (i = 0; i < mfc_buf->num_valid_bufs; i++) {
				mb_addr = mfc_buf->addr[i][0];
				mfc_ctx_debug(4, "batch buf[%d] plane[0] addr: 0x%08llx\n", i, mb_addr);

				if (addr == mb_addr) {
					found = 1;
					break;
				}
			}

			if (found)
				break;
		} else {
			mb_addr = mfc_buf->addr[0][0];
			mfc_ctx_debug(4, "addr[0]: 0x%08llx\n", mb_addr);

			if (addr == mb_addr) {
				found = 1;
				break;
			}
		}
	}

	if (found == 1) {
		list_del(&mfc_buf->list);
		queue->count--;

		spin_unlock_irqrestore(&ctx->buf_queue_lock, flags);
		return mfc_buf;
	} else {
		spin_unlock_irqrestore(&ctx->buf_queue_lock, flags);
		return NULL;
	}
}

void mfc_move_buf_all(struct mfc_ctx *ctx, struct mfc_buf_queue *to_queue,
		struct mfc_buf_queue *from_queue, enum mfc_queue_top_type top)
{
	unsigned long flags;
	struct mfc_buf *mfc_buf = NULL;

	spin_lock_irqsave(&ctx->buf_queue_lock, flags);

	if (top == MFC_QUEUE_ADD_TOP) {
		while (!list_empty(&from_queue->head)) {
			mfc_buf = list_entry(from_queue->head.prev, struct mfc_buf, list);

			list_del(&mfc_buf->list);
			from_queue->count--;

			list_add(&mfc_buf->list, &to_queue->head);
			to_queue->count++;
		}
	} else {
		while (!list_empty(&from_queue->head)) {
			mfc_buf = list_entry(from_queue->head.next, struct mfc_buf, list);

			list_del(&mfc_buf->list);
			from_queue->count--;

			list_add_tail(&mfc_buf->list, &to_queue->head);
			to_queue->count++;
		}
	}

	INIT_LIST_HEAD(&from_queue->head);
	from_queue->count = 0;

	spin_unlock_irqrestore(&ctx->buf_queue_lock, flags);
}

void mfc_return_buf_to_ready_queue(struct mfc_ctx *ctx, struct mfc_buf_queue *maincore_queue,
		struct mfc_buf_queue *subcore_queue)
{
	struct mfc_dev *dev = ctx->dev;
	struct mfc_buf_queue *to_queue = &ctx->src_buf_ready_queue;
	struct mfc_buf_queue *first_queue, *second_queue;
	unsigned long flags;
	struct mfc_buf *mfc_buf = NULL;
	int maincore_src_index = -1, subcore_src_index = -1;

	spin_lock_irqsave(&ctx->buf_queue_lock, flags);

	if (list_empty(&maincore_queue->head) && list_empty(&subcore_queue->head)) {
		mfc_ctx_debug(2, "all src queue of core_ctx is empty\n");
		spin_unlock_irqrestore(&ctx->buf_queue_lock, flags);
		return;
	}

	/* Search the last distributed src index */
	if (!list_empty(&maincore_queue->head)) {
		mfc_buf = list_entry(maincore_queue->head.prev, struct mfc_buf, list);
		maincore_src_index = mfc_buf->src_index;
		mfc_ctx_debug(4, "maincore src last buf src index: %d\n", maincore_src_index);
	}
	if (!list_empty(&subcore_queue->head)) {
		mfc_buf = list_entry(subcore_queue->head.prev, struct mfc_buf, list);
		subcore_src_index = mfc_buf->src_index;
		mfc_ctx_debug(4, "subcore src last buf src index: %d\n", subcore_src_index);
	}

	MFC_TRACE_RM("[c:%d] last src index maincore %d subcore %d\n",
			ctx->num, maincore_src_index, subcore_src_index);

	/* Select the core_ctx->src_buf_queue to take out first */
	if (maincore_src_index > subcore_src_index) {
		first_queue = maincore_queue;
		second_queue = subcore_queue;
		mfc_ctx_debug(2, "last src index (maincore:%d, subcore:%d) move first maincore\n",
				maincore_src_index, subcore_src_index);
	} else {
		first_queue = subcore_queue;
		second_queue = maincore_queue;
		mfc_ctx_debug(2, "last src index (maincore:%d, subcore:%d) move first subcore\n",
				maincore_src_index, subcore_src_index);
	}

	/* Src index is sequentially returned to ready_queue */
	while (1) {
		if (!list_empty(&first_queue->head)) {
			mfc_buf = list_entry(first_queue->head.prev, struct mfc_buf, list);

			list_del(&mfc_buf->list);
			first_queue->count--;

			list_add(&mfc_buf->list, &to_queue->head);
			to_queue->count++;
			mfc_ctx_debug(2, "first queue src[%d] move\n", mfc_buf->src_index);
			MFC_TRACE_RM("[c:%d] first queue src[%d] move\n", ctx->num,
					mfc_buf->src_index);
		}

		if (!list_empty(&second_queue->head)) {
			mfc_buf = list_entry(second_queue->head.prev, struct mfc_buf, list);

			list_del(&mfc_buf->list);
			second_queue->count--;

			list_add(&mfc_buf->list, &to_queue->head);
			to_queue->count++;
			mfc_ctx_debug(2, "second queue src[%d] move\n", mfc_buf->src_index);
			MFC_TRACE_RM("[c:%d] second queue src[%d] move\n", ctx->num,
					mfc_buf->src_index);
		}

		if (list_empty(&first_queue->head) && list_empty(&second_queue->head)) {
			mfc_ctx_debug(2, "all src of core_ctx return to ready_queue\n");
			mfc_ctx_debug(2, "ready %d maincore %d subcore %d\n",
					to_queue->count, maincore_queue->count,
					subcore_queue->count);
			MFC_TRACE_RM("[c:%d] all src return to ready\n", ctx->num);
			MFC_TRACE_RM("[c:%d] ready %d maincore %d subcore %d\n", ctx->num,
					to_queue->count, maincore_queue->count,
					subcore_queue->count);
			INIT_LIST_HEAD(&first_queue->head);
			first_queue->count = 0;
			INIT_LIST_HEAD(&second_queue->head);
			second_queue->count = 0;
			break;
		}
	}

	spin_unlock_irqrestore(&ctx->buf_queue_lock, flags);
}

void mfc_cleanup_queue(spinlock_t *plock, struct mfc_buf_queue *queue)
{
	unsigned long flags;
	struct mfc_buf *mfc_buf = NULL;
	int i;

	spin_lock_irqsave(plock, flags);

	while (!list_empty(&queue->head)) {
		mfc_buf = list_entry(queue->head.next, struct mfc_buf, list);

		for (i = 0; i < mfc_buf->vb.vb2_buf.num_planes; i++)
			vb2_set_plane_payload(&mfc_buf->vb.vb2_buf, i, 0);

		vb2_buffer_done(&mfc_buf->vb.vb2_buf, VB2_BUF_STATE_ERROR);
		list_del(&mfc_buf->list);
		queue->count--;
	}

	INIT_LIST_HEAD(&queue->head);
	queue->count = 0;

	spin_unlock_irqrestore(plock, flags);
}

void mfc_cleanup_enc_src_queue(struct mfc_core_ctx *core_ctx)
{
	struct mfc_ctx *ctx = core_ctx->ctx;
	unsigned long flags;
	struct mfc_buf *mfc_buf = NULL;
	struct mfc_buf_queue *queue = &core_ctx->src_buf_queue;
	int i;

	spin_lock_irqsave(&ctx->buf_queue_lock, flags);

	while (!list_empty(&queue->head)) {
		mfc_buf = list_entry(queue->head.next, struct mfc_buf, list);

		for (i = 0; i < mfc_buf->vb.vb2_buf.num_planes; i++) {
			if (IS_BUFFER_BATCH_MODE(ctx))
				mfc_bufcon_put_daddr(ctx, mfc_buf, i);
			vb2_set_plane_payload(&mfc_buf->vb.vb2_buf, i, 0);
		}

		vb2_buffer_done(&mfc_buf->vb.vb2_buf, VB2_BUF_STATE_ERROR);
		list_del(&mfc_buf->list);
		queue->count--;
	}

	INIT_LIST_HEAD(&queue->head);
	queue->count = 0;
	ctx->batch_mode = 0;

	spin_unlock_irqrestore(&ctx->buf_queue_lock, flags);
}

void mfc_print_dpb_queue(struct mfc_core_ctx *core_ctx, struct mfc_dec *dec)
{
	struct mfc_ctx *ctx = core_ctx->ctx;
	struct mfc_buf *mfc_buf = NULL;

	mfc_debug(2, "[DPB] src: %d(ready: %d), dst %d, src_nal %d, dst_nal %d, used %#lx, queued %#lx, set %#lx(dec: %#lx)\n",
			core_ctx->src_buf_queue.count,
			ctx->src_buf_ready_queue.count,
			ctx->dst_buf_queue.count,
			ctx->src_buf_nal_queue.count, ctx->dst_buf_nal_queue.count,
			dec->dynamic_used, dec->queued_dpb,
			core_ctx->dynamic_set, dec->dynamic_set);

	if (!list_empty(&ctx->dst_buf_queue.head))
		list_for_each_entry(mfc_buf, &ctx->dst_buf_queue.head, list)
			mfc_debug(2, "[DPB] dst[%d][%d] %#llx used: %d\n",
					mfc_buf->vb.vb2_buf.index,
					mfc_buf->dpb_index,
					mfc_buf->addr[0][0], mfc_buf->used);
	if (!list_empty(&ctx->dst_buf_nal_queue.head))
		list_for_each_entry(mfc_buf, &ctx->dst_buf_nal_queue.head, list)
			mfc_debug(2, "[DPB] dst_nal[%d][%d] %#llx used: %d\n",
					mfc_buf->vb.vb2_buf.index,
					mfc_buf->dpb_index,
					mfc_buf->addr[0][0], mfc_buf->used);
	if (!list_empty(&ctx->plugin_buf_queue.head))
		list_for_each_entry(mfc_buf, &ctx->plugin_buf_queue.head, list)
			mfc_debug(2, "[DPB] plugin_buf[%d][%d] %#llx used: %d\n",
					mfc_buf->vb.vb2_buf.index,
					mfc_buf->dpb_index,
					mfc_buf->addr[0][0], mfc_buf->used);
}

void mfc_print_dpb_queue_with_lock(struct mfc_core_ctx *core_ctx, struct mfc_dec *dec)
{
	struct mfc_ctx *ctx = core_ctx->ctx;
	unsigned long flags;

	spin_lock_irqsave(&ctx->buf_queue_lock, flags);
	mfc_print_dpb_queue(core_ctx, dec);
	spin_unlock_irqrestore(&ctx->buf_queue_lock, flags);
}

int mfc_get_available_dpb_count(struct mfc_core_ctx *core_ctx)
{
	struct mfc_ctx *ctx = core_ctx->ctx;
	struct mfc_dec *dec = ctx->dec_priv;
	struct mfc_buf *mfc_buf = NULL;
	unsigned long flags, used_flag_count;
	int cnt = 0;

	spin_lock_irqsave(&ctx->buf_queue_lock, flags);

	if (ctx->dst_buf_queue.count == 0) {
		spin_unlock_irqrestore(&ctx->buf_queue_lock, flags);
		return 0;
	}

	if (ctx->plugin_type) {
		list_for_each_entry(mfc_buf, &ctx->dst_buf_queue.head, list) {
			if (!mfc_buf->used)
				cnt++;
		}
		spin_unlock_irqrestore(&ctx->buf_queue_lock, flags);
		return cnt;
	}

	list_for_each_entry(mfc_buf, &ctx->dst_buf_queue.head, list) {
		if (IS_TWO_MODE2(ctx) && (dec->dynamic_set & (1UL << mfc_buf->dpb_index))) {
			mfc_debug(2, "[DPB] dst index %d already set\n",
					mfc_buf->dpb_index);
			continue;
		}
		if ((dec->dynamic_used & (1UL << mfc_buf->dpb_index)) == 0) {
			mfc_debug(2, "[DPB] There is available dpb(index:%d, used:%#lx)\n",
					mfc_buf->dpb_index, dec->dynamic_used);
			cnt++;
		}
	}

	if (cnt) {
		spin_unlock_irqrestore(&ctx->buf_queue_lock, flags);
		return cnt;
	}

	used_flag_count = hweight64(dec->dynamic_used);
	if (used_flag_count >= ctx->dpb_count) {
		mfc_debug(2, "[DPB] All DPB(%ld) of min count are referencing\n",
				used_flag_count);
		spin_unlock_irqrestore(&ctx->buf_queue_lock, flags);
		return 1;
	}

	mfc_debug(2, "[DPB] There is no available DPB\n");
	spin_unlock_irqrestore(&ctx->buf_queue_lock, flags);

	return 0;
}

/* Try to search non-referenced DPB on dst-queue */
struct mfc_buf *mfc_search_for_dpb(struct mfc_core_ctx *core_ctx)
{
	struct mfc_ctx *ctx = core_ctx->ctx;
	struct mfc_dec *dec = ctx->dec_priv;
	unsigned long flags, used_flag_count;
	struct mfc_buf *mfc_buf = NULL;

	spin_lock_irqsave(&ctx->buf_queue_lock, flags);
	list_for_each_entry(mfc_buf, &ctx->dst_buf_queue.head, list) {
		if (IS_TWO_MODE2(ctx) && (dec->dynamic_set & (1UL << mfc_buf->dpb_index))) {
			mfc_debug(2, "[DPB] dst index %d already set\n",
					mfc_buf->dpb_index);
			continue;
		}
		if ((dec->dynamic_used & (1UL << mfc_buf->dpb_index)) == 0) {
			mfc_buf->used = 1;
			dec->dynamic_set = 1UL << mfc_buf->dpb_index;
			core_ctx->dynamic_set = 1UL << mfc_buf->dpb_index;
			spin_unlock_irqrestore(&ctx->buf_queue_lock, flags);
			return mfc_buf;
		}
	}

	/*
	 * Bumping process
	 * In case of H.264/HEVC codec,
	 * all of the queued buffers can be referenced by F/W.
	 * At that time, we should set the any DPB to F/W,
	 * F/W will returns display only buffer whether if reference or not.
	 * In this way the reference can be released by circulating.
	 */
	used_flag_count = hweight64(dec->dynamic_used);
	if (used_flag_count >= ctx->dpb_count) {
		mfc_buf = list_entry(ctx->dst_buf_queue.head.next, struct mfc_buf, list);
		mfc_buf->used = 1;
		mfc_debug(2, "[DPB] All DPB(%ld) of min count are referencing. select buf[%d][%d]\n",
				used_flag_count, mfc_buf->vb.vb2_buf.index, mfc_buf->dpb_index);
		dec->dynamic_set = 1UL << mfc_buf->dpb_index;
		core_ctx->dynamic_set = 1UL << mfc_buf->dpb_index;
		spin_unlock_irqrestore(&ctx->buf_queue_lock, flags);
		return mfc_buf;
	}

	/*
	 * 1) ctx->dst_buf_queue.count >= (ctx->dpb_count + MFC_EXTRA_DPB): All DPBs queued in DRV
	 * 2) ctx->dst_buf_queue.count == 0: All DPBs dequeued to user
	 * we will wait
	 */
	mfc_debug(2, "[DPB] All enqueued DPBs are referencing or there's no DPB in DRV (in %d/total %d)\n",
			ctx->dst_buf_queue.count, ctx->dpb_count + MFC_EXTRA_DPB);
	if (!(dec->queued_dpb & ~dec->dynamic_used))
		mfc_debug(2, "[DPB] All enqueued DPBs are referencing\n");

	mfc_print_dpb_queue(core_ctx, dec);
	spin_unlock_irqrestore(&ctx->buf_queue_lock, flags);

	mutex_lock(&dec->dpb_mutex);
	mfc_print_dpb_table(ctx);
	mutex_unlock(&dec->dpb_mutex);

	return NULL;
}

struct mfc_buf *mfc_search_move_dpb_nal_q(struct mfc_core_ctx *core_ctx)
{
	struct mfc_ctx *ctx = core_ctx->ctx;
	struct mfc_dec *dec = ctx->dec_priv;
	struct mfc_buf *mfc_buf = NULL;
	unsigned long flags, used_flag_count;

	spin_lock_irqsave(&ctx->buf_queue_lock, flags);
	list_for_each_entry(mfc_buf, &ctx->dst_buf_queue.head, list) {
		if ((dec->dynamic_used & (1UL << mfc_buf->dpb_index)) == 0) {
			mfc_buf->used = 1;

			list_del(&mfc_buf->list);
			ctx->dst_buf_queue.count--;

			list_add_tail(&mfc_buf->list, &ctx->dst_buf_nal_queue.head);
			ctx->dst_buf_nal_queue.count++;

			spin_unlock_irqrestore(&ctx->buf_queue_lock, flags);
			return mfc_buf;
		}
	}

	/*
	 * Bumping process
	 * In case of H.264/HEVC codec,
	 * all of the queued buffers can be referenced by F/W.
	 * In NAL_Q mode, F/W couldn't know when the buffer
	 * that returned to the display index was displayed.
	 * Therefore, NAL_Q mode can't be continued.
	 */
	used_flag_count = hweight64(dec->dynamic_used);
	if (used_flag_count >= ctx->dpb_count) {
		dec->is_dpb_full = 1;
		mfc_debug(2, "[NALQ][DPB] All DPB(%ld) of min count are referencing\n",
				used_flag_count);
		spin_unlock_irqrestore(&ctx->buf_queue_lock, flags);
		return NULL;
	}

	/*
	 * 1) ctx->dst_buf_queue.count >= (ctx->dpb_count + MFC_EXTRA_DPB): All DPBs queued in DRV
	 * 2) ctx->dst_buf_queue.count == 0: All DPBs dequeued to user
	 * we will wait
	 */
	mfc_debug(2, "[NALQ][DPB] All enqueued DPBs are referencing or there's no DPB in DRV (in %d/total %d)\n",
			ctx->dst_buf_queue.count + ctx->dst_buf_nal_queue.count,
			ctx->dpb_count + MFC_EXTRA_DPB);
	if (!(dec->queued_dpb & ~dec->dynamic_used))
		mfc_debug(2, "[NALQ][DPB] All enqueued DPBs are referencing\n");

	mfc_print_dpb_queue(core_ctx, dec);
	spin_unlock_irqrestore(&ctx->buf_queue_lock, flags);

	mfc_print_dpb_table(ctx);

	return NULL;
}

int __mfc_assign_dpb_index(struct mfc_ctx *ctx, struct mfc_buf *mfc_buf)
{
	struct mfc_dec *dec = ctx->dec_priv;
	struct mfc_dev *dev = ctx->dev;
	unsigned long used;
	int index = -1;
	int i;

	/* case 1: dpb has same address with vb index */
	if (mfc_buf->paddr == dec->dpb[mfc_buf->vb.vb2_buf.index].paddr) {
		mfc_ctx_debug(2, "[DPB] vb index [%d] %#llx has same address\n",
				mfc_buf->vb.vb2_buf.index, mfc_buf->paddr);
		index = mfc_buf->vb.vb2_buf.index;
		return index;
	}

	/* case 2: dpb has same address with referenced buffer */
	used = dec->dynamic_used;
	if (used) {
		for (i = __ffs(used); i < MFC_MAX_DPBS;) {
			if (mfc_buf->paddr == dec->dpb[i].paddr) {
				mfc_ctx_debug(2, "[DPB] index [%d][%d] %#llx is referenced\n",
						mfc_buf->vb.vb2_buf.index, i, mfc_buf->paddr);
				index = i;
				return index;
			}
			used &= ~(1UL << i);
			if (used == 0)
				break;
			i = __ffs(used);
		}
	}

	/* case 3: allocate new dpb index */
	if (dec->dpb_table_used == ~0UL) {
		mfc_ctx_err("[DPB] index is full\n");
		call_dop(dev, dump_and_stop_debug_mode, dev);
		return 0;
	}
	index = __ffs(~dec->dpb_table_used);

	return index;
}

void __mfc_update_base_addr_dpb(struct mfc_ctx *ctx, struct mfc_buf *buf,
					int index)
{
	struct mfc_dec *dec = ctx->dec_priv;
	struct mfc_raw_info *raw;
	size_t offset = 0;
	int i;

	if (ctx->dst_fmt->mem_planes == 1) {
		raw = &ctx->raw_buf;
		for (i = 0; i < ctx->dst_fmt->num_planes; i++) {
			buf->addr[0][i] = dec->dpb[index].addr[0] + offset;
			offset += raw->plane_size[i];
			if (IS_2BIT_NEED(ctx))
				offset += raw->plane_size_2bits[i];
		}
	} else {
		for (i = 0; i < ctx->dst_fmt->mem_planes; i++)
			buf->addr[0][i] = dec->dpb[index].addr[i];
	}

	mfc_ctx_debug(2, "[DPB] index [%d] daddr plane[0] %#llx [1] %#llx [2] %#llx\n",
			index, buf->addr[0][0], buf->addr[0][1], buf->addr[0][2]);
}

int __mfc_update_dpb_fd(struct mfc_ctx *ctx, struct vb2_buffer *vb, int index)
{
	struct mfc_dec *dec = ctx->dec_priv;

	if (dec->dpb[index].queued) {
		mfc_ctx_err("[REFINFO] DPB[%d] is already queued\n", index);
		return -EINVAL;
	}

	if (dec->dpb[index].fd[0] == vb->planes[0].m.fd)
		mfc_ctx_debug(3, "[REFINFO] same dma_buf has same fd\n");

	dec->dpb[index].new_fd = vb->planes[0].m.fd;
	mfc_ctx_debug(3, "[REFINFO] index %d update fd: %d -> %d after release\n",
			vb->index, dec->dpb[index].fd[0],
			dec->dpb[index].new_fd);

	return 0;
}

void __mfc_store_dynamic_dpb(struct mfc_ctx *ctx, struct mfc_dec *dec, struct vb2_buffer *vb)
{
	struct mfc_dev *dev = ctx->dev;
	struct mfc_buf *mfc_buf;
	unsigned long flags;
	int index, plane, ret = 0;

	mfc_buf = vb_to_mfc_buf(vb);
	mfc_buf->used = 0;

	mutex_lock(&dec->dpb_mutex);
	mfc_buf->dpb_index = __mfc_assign_dpb_index(ctx, mfc_buf);
	mfc_ctx_debug(2, "[DPB] DPB vb_index %d -> dpb_index %d addr %#llx (used: %#lx)\n",
			vb->index, mfc_buf->dpb_index, mfc_buf->addr[0][0], dec->dynamic_used);

	index = mfc_buf->dpb_index;
	if (index > dec->last_dpb_max_index) {
		mfc_ctx_debug(3, "[DPB] last dpb max index update %d -> %d\n",
				dec->last_dpb_max_index, index);
		if (index > (dec->last_dpb_max_index + 1)) {
			mfc_ctx_err("[DPB] wrong dpb max index: %d max: %d\n",
					index, dec->last_dpb_max_index);
			MFC_TRACE_CTX("wrong dpb max index: %d max: %d\n",
					index, dec->last_dpb_max_index);
		}
		dec->last_dpb_max_index = index;
	}

	if (!dec->dpb[index].mapcnt) {
		mfc_get_iovmm(ctx, vb, dec->dpb);
	} else {
		if (dec->dpb[index].paddr == mfc_buf->paddr) {
			mfc_ctx_debug(2, "[DPB] DPB[%d] is same %#llx(used: %#lx)\n",
					index, dec->dpb[index].paddr, dec->dynamic_used);
			ret = __mfc_update_dpb_fd(ctx, vb, index);
		} else {
			mfc_ctx_err("[DPB] wrong assign dpb index\n");
			call_dop(dev, dump_and_stop_debug_mode, dev);
		}
	}

	if (ret) {
		/*
		 * Handling exception case that
		 * the queued buffer is same with already queued buffer's paddr.
		 * Driver cannot use that buffer so moves it to err_buf_queue
		 * and will dequeue in ISR.
		 */
		mutex_unlock(&dec->dpb_mutex);

		spin_lock_irqsave(&ctx->buf_queue_lock, flags);

		list_add_tail(&mfc_buf->list, &ctx->err_buf_queue.head);
		ctx->err_buf_queue.count++;
		mfc_ctx_debug(2, "[DPB] DPB[%d][%d] fd: %d will be not used %#llx %s %s (%d)\n",
				mfc_buf->vb.vb2_buf.index, index,
				mfc_buf->vb.planes[0].m.fd, mfc_buf->addr[0][0],
				(dec->dynamic_used & (1UL << index)) ? "ref" : "no-ref",
				dec->dpb[index].queued ? "q" : "dq",
				ctx->err_buf_queue.count);
		MFC_TRACE_CTX("unused DPB[%d][%d] fd: %d %#llx %s %s (%d)\n",
				mfc_buf->vb.vb2_buf.index, index,
				mfc_buf->vb.planes[0].m.fd, mfc_buf->addr[0][0],
				(dec->dynamic_used & (1UL << index)) ? "ref" : "no-ref",
				dec->dpb[index].queued ? "q" : "dq",
				ctx->err_buf_queue.count);

		spin_unlock_irqrestore(&ctx->buf_queue_lock, flags);
		return;
	}

	__mfc_update_base_addr_dpb(ctx, mfc_buf, index);

	dec->dpb[index].size = 0;
	for (plane = 0; plane < vb->num_planes; ++plane)
		dec->dpb[index].size += vb->planes[plane].length;

	dec->dpb[index].queued = 1;
	dec->dpb_table_used |= (1UL << index);
	mutex_unlock(&dec->dpb_mutex);

	spin_lock_irqsave(&ctx->buf_queue_lock, flags);

	list_add_tail(&mfc_buf->list, &ctx->dst_buf_queue.head);
	ctx->dst_buf_queue.count++;
	set_bit(index, &dec->queued_dpb);

	spin_unlock_irqrestore(&ctx->buf_queue_lock, flags);
}

void __mfc_store_plugin_dpb(struct mfc_ctx *ctx, struct mfc_dec *dec, struct vb2_buffer *vb)
{
	struct mfc_buf *mfc_buf;
	unsigned long flags;

	mfc_buf = vb_to_mfc_buf(vb);
	mfc_buf->used = 0;

	spin_lock_irqsave(&ctx->buf_queue_lock, flags);

	/*
	 * Handling exception case that
	 * the queued buffer is same with already queued buffer's index.
	 * There is no buffer referenced in this case, it should be the only one queued buffer
	 * Driver cannot use that buffer so moves it to err_buf_queue
	 * and will dequeue in ISR.
	 */
	if (dec->queued_dpb & (1UL << vb->index)) {
		list_add_tail(&mfc_buf->list, &ctx->err_buf_queue.head);
		ctx->err_buf_queue.count++;
		mfc_ctx_debug(2, "[PLUGIN] DPB[%d] fd: %d will be not used %#llx (%d)\n",
				vb->index,
				mfc_buf->vb.planes[0].m.fd, mfc_buf->addr[0][0],
				ctx->err_buf_queue.count);
		MFC_TRACE_CTX("unused DPB[%d] fd: %d %#llx (%d)\n",
				vb->index,
				mfc_buf->vb.planes[0].m.fd, mfc_buf->addr[0][0],
				ctx->err_buf_queue.count);

		spin_unlock_irqrestore(&ctx->buf_queue_lock, flags);
		return;
	}

	list_add_tail(&mfc_buf->list, &ctx->dst_buf_queue.head);
	ctx->dst_buf_queue.count++;
	set_bit(vb->index, &dec->queued_dpb);

	spin_unlock_irqrestore(&ctx->buf_queue_lock, flags);
}

/* Add dst buffer in dst_buf_queue */
void mfc_store_dpb(struct mfc_ctx *ctx, struct vb2_buffer *vb)
{
	struct mfc_dec *dec;

	dec = ctx->dec_priv;
	if (!dec) {
		mfc_ctx_err("[DPB] no mfc decoder to run\n");
		return;
	}

	if (ctx->plugin_type)
		__mfc_store_plugin_dpb(ctx, dec, vb);
	else
		__mfc_store_dynamic_dpb(ctx, dec, vb);
}

void mfc_cleanup_nal_queue(struct mfc_core_ctx *core_ctx)
{
	struct mfc_ctx *ctx = core_ctx->ctx;
	struct mfc_buf *src_mb, *dst_mb;
	unsigned long flags;
	unsigned int index;

	spin_lock_irqsave(&ctx->buf_queue_lock, flags);

	while (!list_empty(&ctx->src_buf_nal_queue.head)) {
		src_mb = list_entry(ctx->src_buf_nal_queue.head.prev, struct mfc_buf, list);

		index = src_mb->vb.vb2_buf.index;
		call_bop(ctx, core_restore_buf_ctrls, ctx, &ctx->src_ctrls[index]);

		src_mb->used = 0;

		/* If it is not buffer batch mode, index is always zero */
		if (src_mb->next_index > src_mb->done_index) {
			mfc_debug(2, "[NALQ][BUFCON] batch buf next index[%d] recover to [%d]\n",
					src_mb->next_index, src_mb->done_index);
			src_mb->next_index = src_mb->done_index;
		}

		list_del(&src_mb->list);
		ctx->src_buf_nal_queue.count--;

		list_add(&src_mb->list, &core_ctx->src_buf_queue.head);
		core_ctx->src_buf_queue.count++;

		mfc_debug(2, "[NALQ] cleanup, src_buf_nal_queue -> src_buf_queue, index:%d\n",
				src_mb->vb.vb2_buf.index);
	}

	while (!list_empty(&ctx->dst_buf_nal_queue.head)) {
		dst_mb = list_entry(ctx->dst_buf_nal_queue.head.prev, struct mfc_buf, list);

		dst_mb->used = 0;
		list_del(&dst_mb->list);
		ctx->dst_buf_nal_queue.count--;

		list_add(&dst_mb->list, &ctx->dst_buf_queue.head);
		ctx->dst_buf_queue.count++;

		mfc_debug(2, "[NALQ] cleanup, dst_buf_nal_queue -> dst_buf_queue, index:[%d][%d]\n",
				dst_mb->vb.vb2_buf.index, dst_mb->dpb_index);
	}

	spin_unlock_irqrestore(&ctx->buf_queue_lock, flags);
}

int mfc_check_buf_mb_flag(struct mfc_core_ctx *core_ctx, enum mfc_mb_flag f)
{
	unsigned long flags;
	struct mfc_buf *mfc_buf = NULL;

	spin_lock_irqsave(&core_ctx->buf_queue_lock, flags);

	if (list_empty(&core_ctx->src_buf_queue.head)) {
		mfc_debug(2, "src_buf_queue is empty\n");
		spin_unlock_irqrestore(&core_ctx->buf_queue_lock, flags);
		return -EINVAL;
	}

	mfc_buf = list_entry(core_ctx->src_buf_queue.head.next, struct mfc_buf, list);

	mfc_debug(2, "[BUFINFO] addr[0]: 0x%08llx\n", mfc_buf->addr[0][0]);

	if (mfc_check_mb_flag(mfc_buf, f)) {
		mfc_debug(2, "find flag %d\n", f);
		spin_unlock_irqrestore(&core_ctx->buf_queue_lock, flags);
		return 1;
	}

	mfc_debug(4, "no flag %d\n", f);
	spin_unlock_irqrestore(&core_ctx->buf_queue_lock, flags);

	return 0;
}

void mfc_dec_drc_find_del_buf(struct mfc_core_ctx *core_ctx)
{
	struct mfc_ctx *ctx = core_ctx->ctx;
	struct mfc_dec *dec = ctx->dec_priv;
	struct mfc_core *core = core_ctx->core;
	struct mfc_buf *dst_mb;
	int i;

	if (!dec || dec->disp_drc.disp_res_change)
		return;

	dst_mb = mfc_get_del_buf(ctx, &ctx->dst_buf_queue, MFC_BUF_NO_TOUCH_USED);
	if (!dst_mb)
		return;

	mfc_info("[DRC] already stopped and dqbuf with DRC\n");
	i = dst_mb->vb.vb2_buf.index;
	dst_mb->vb.flags |= V4L2_BUF_FLAG_PFRAME;

	mfc_clear_mb_flag(dst_mb);
	dst_mb->vb.flags &= ~(V4L2_BUF_FLAG_KEYFRAME |
			V4L2_BUF_FLAG_PFRAME |
			V4L2_BUF_FLAG_BFRAME |
			V4L2_BUF_FLAG_ERROR);

	if (call_bop(ctx, core_get_buf_ctrls, core, ctx, &ctx->dst_ctrls[i]) < 0)
		mfc_err("[DRC] failed in core_get_buf_ctrls\n");

	call_cop(ctx, update_buf_val, ctx, &ctx->dst_ctrls[i],
			V4L2_CID_MPEG_MFC51_VIDEO_DISPLAY_STATUS,
			MFC_REG_DEC_STATUS_DECODING_EMPTY);
	call_cop(ctx, update_buf_val, ctx, &ctx->dst_ctrls[i],
			V4L2_CID_MPEG_MFC51_VIDEO_FRAME_TAG, UNUSED_TAG);

	ctx->wait_state = WAIT_G_FMT | WAIT_STOP;
	mfc_debug(2, "[DRC] Decoding waiting again! : %d\n", ctx->wait_state);
	MFC_TRACE_CTX("[DRC] wait again\n");
	vb2_buffer_done(&dst_mb->vb.vb2_buf, VB2_BUF_STATE_DONE);
}
