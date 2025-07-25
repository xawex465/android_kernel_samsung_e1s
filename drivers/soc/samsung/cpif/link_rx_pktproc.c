// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2018-2019, Samsung Electronics.
 *
 */

#include <asm/cacheflush.h>
#include <net/ip.h>
#include <net/ipv6.h>
#include <net/ip6_checksum.h>
#include <net/udp.h>
#include <net/tcp.h>
#include <soc/samsung/shm_ipc.h>
#include "modem_prj.h"
#include "modem_utils.h"
#include "link_device_memory.h"
#include "dit.h"
#if IS_ENABLED(CONFIG_LINK_DEVICE_PCIE_IOMMU)
#include "link_device_pcie_iommu.h"
#endif

static struct pktproc_perftest_data perftest_data[PERFTEST_MODE_MAX] = {
	{
		/* empty */
	},
	{
		/* PERFTEST_MODE_IPV4
		 * port: 5000 -> 5001
		 * payload: 1464 (0x5b8)
		 */
		.header = {
			0x45, 0x00, 0x05, 0xB8, 0x00, 0x00, 0x40, 0x00,
			0x80, 0x11, 0x71, 0xDF, 0xC0, 0xA8, 0x01, 0x03,
			0xC0, 0xA8, 0x01, 0x02, 0x13, 0x88, 0x13, 0x89,
			0x05, 0xA4, 0x00, 0x00
		},
		.header_len = 28,
		.dst_port_offset = 22,
		.packet_len = 1464
	},
	{
		/* PERFTEST_MODE_CLAT
		 * port: 5000 -> 5001
		 * payload: 1444 (0x5a4)
		 */
		.header = {
			0x60, 0x0a, 0xf8, 0x0c, 0x05, 0xa4, 0x11, 0x40,
			0x00, 0x64, 0xff, 0x9b, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0xc0, 0x00, 0x00, 0x02,
			0x20, 0x01, 0x02, 0xd8, 0xe1, 0x43, 0x7b, 0xfb,
			0x1d, 0xda, 0x90, 0x9d, 0x8b, 0x8d, 0x05, 0xe7,
			0x13, 0x88, 0x13, 0x89, 0x05, 0xa4, 0x00, 0x00,
		},
		.header_len = 48,
		.dst_port_offset = 42,
		.packet_len = 1484
	},
	{
		/* PERFTEST_MODE_IPV6
		 * port: 5000 -> 5001
		 * payload: 1444 (0x5a4)
		 */
		.header = {
			0x60, 0x0a, 0xf8, 0x0c, 0x05, 0x90, 0x11, 0x40,
			0x20, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00, 0x01,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
			0x20, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00, 0x02,
			0x7d, 0xae, 0x3d, 0x4e, 0xac, 0xf2, 0x8a, 0x2b,
			0x13, 0x88, 0x13, 0x89, 0x05, 0x90, 0x00, 0x00,
		},
		.header_len = 48,
		.dst_port_offset = 42,
		.packet_len = 1464
	},
	{
		/* PERFTEST_MODE_IPV4_LRO (csum 1234)
		 * port: 5000 -> 5001
		 * payload: 1464 (0x5b8)
		 */
		.header = {
			0x45, 0x00, 0x05, 0xB8, 0x00, 0x00, 0x40, 0x00,
			0x80, 0x11, 0x00, 0x00, 0xC0, 0xA8, 0x01, 0x03,
			0xC0, 0xA8, 0x01, 0x02, 0x13, 0x88, 0x13, 0x89,
			0x05, 0xA4, 0x12, 0x34
		},
		.header_len = 28,
		.dst_port_offset = 22,
		.packet_len = 1464
	},
};

static bool pktproc_check_hw_checksum(u8 status)
{
	if (unlikely(status & PKTPROC_STATUS_IGNR))
		return false;
	if (unlikely(!(status & PKTPROC_STATUS_IPCS) || !(status & PKTPROC_STATUS_TCPC)))
		return false;
	if (unlikely((status & PKTPROC_STATUS_IPCSF) || (status & PKTPROC_STATUS_TCPCF)))
		return false;

	return true;
}

static void pktproc_set_pktgen_checksum(struct pktproc_queue *q, u8 *data)
{
	size_t off;
	struct udphdr *uh;

	switch (data[0] & 0xF0) {
	case 0x40:
		off = sizeof(struct iphdr);
		break;
	case 0x60:
		off = sizeof(struct ipv6hdr);
		break;
	default:
		return;
	}

	uh = (struct udphdr *)(data + off);
	uh->check = htons(0x1234);
}

static ssize_t pktgen_gro_store(struct device *dev,
		struct device_attribute *attr,
		const char *buf, size_t count)
{
	struct modem_ctl *mc = dev_get_drvdata(dev);
	struct link_device *ld = get_current_link(mc->iod);
	struct mem_link_device *mld = to_mem_link_device(ld);
	struct pktproc_adaptor *ppa = &mld->pktproc;
	unsigned int gro;
	int ret;

	ret = kstrtoint(buf, 0, &gro);
	if (ret)
		return -EINVAL;

	ppa->pktgen_gro = (gro > 0 ? true : false);

	return count;
}

static ssize_t pktgen_gro_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	struct modem_ctl *mc = dev_get_drvdata(dev);
	struct link_device *ld = get_current_link(mc->iod);
	struct mem_link_device *mld = to_mem_link_device(ld);
	struct pktproc_adaptor *ppa = &mld->pktproc;
	ssize_t count = 0;

	count += scnprintf(&buf[count], PAGE_SIZE - count, "pktgen gro:%d\n", ppa->pktgen_gro);

	return count;
}

/*
 * Get a packet: ringbuf mode
 */
static int pktproc_get_pkt_from_ringbuf_mode(struct pktproc_queue *q, struct sk_buff **new_skb)
{
	int ret = 0;
	u16 len;
	u16 ch_id;
	u8 *src;
	struct sk_buff *skb = NULL;
	struct link_device *ld = &q->mld->link_dev;
	struct pktproc_desc_ringbuf *desc = q->desc_ringbuf;

	if (!pktproc_check_active(q->ppa, q->q_idx)) {
		mif_err_limited("Queue %d not activated\n", q->q_idx);
		return -EACCES;
	}
	if (q->ppa->desc_mode != DESC_MODE_RINGBUF) {
		mif_err_limited("Invalid desc_mode %d\n", q->ppa->desc_mode);
		return -EINVAL;
	}

	/* Get data */
	len = desc[*q->rear_ptr].length;
	if (len > q->ppa->max_packet_size) {
		mif_err_limited("Length is invalid:%d\n", len);
		q->stat.err_len++;
		ret = -EPERM;
		goto rx_error_on_desc;
	}
	ch_id = desc[*q->rear_ptr].channel_id;
	if (ch_id == SIPC5_CH_ID_MAX) {
		mif_err_limited("Channel ID is invalid:%d\n", ch_id);
		q->stat.err_chid++;
		ret = -EPERM;
		goto rx_error_on_desc;
	}
	src = desc[*q->rear_ptr].cp_data_paddr - q->cp_buff_pbase + q->q_buff_vbase;
	if ((src < q->q_buff_vbase) || (src > q->q_buff_vbase + q->q_buff_size)) {
		mif_err_limited("Data address is invalid:%pK q_buff_vbase:%pK size:0x%08x\n",
						src, q->q_buff_vbase, q->q_buff_size);
		q->stat.err_addr++;
		ret = -EINVAL;
		goto rx_error_on_desc;
	}
	if (q->ppa->buff_rgn_cached && !q->ppa->use_hw_iocc)
		dma_sync_single_for_cpu(q->ppa->dev, virt_to_phys(src), len, DMA_FROM_DEVICE);
	pp_debug("len:%d ch_id:%d src:%pK\n", len, ch_id, src);

	/* Build skb */
	skb = napi_alloc_skb(q->napi_ptr, len);
	if (unlikely(!skb)) {
		mif_err_limited("alloc_skb() error\n");
		q->stat.err_nomem++;
		ret = -ENOMEM;
		goto rx_error;
	}
	skb_put(skb, len);
	skb_copy_to_linear_data(skb, src, len);
#ifdef PKTPROC_DEBUG_PKT
	pr_buffer("pktproc", (char *)skb->data, (size_t)len, (size_t)40);
#endif

	/* Set priv */
	skbpriv(skb)->lnk_hdr = 0;
	skbpriv(skb)->sipc_ch = ch_id;
	skbpriv(skb)->iod = link_get_iod_with_channel(ld, skbpriv(skb)->sipc_ch);
	skbpriv(skb)->ld = ld;
	skbpriv(skb)->napi = q->napi_ptr;

	switch (q->ppa->version) {
	case PKTPROC_V2:
		if (pktproc_check_hw_checksum(desc[*q->rear_ptr].status))
			skb->ip_summed = CHECKSUM_UNNECESSARY;
		else
			q->stat.err_csum++;
		break;
	default:
		break;
	}

	if (unlikely(q->ppa->pktgen_gro)) {
		pktproc_set_pktgen_checksum(q, skb->data);
		skb->ip_summed = CHECKSUM_UNNECESSARY;
	}

	*new_skb = skb;
	q->stat.pass_cnt++;
	*q->rear_ptr = circ_new_ptr(q->num_desc, *q->rear_ptr, 1);

	return 0;

rx_error_on_desc:
	mif_err_limited("Skip invalid descriptor at %d\n", *q->rear_ptr);
	*q->rear_ptr = circ_new_ptr(q->num_desc, *q->rear_ptr, 1);

rx_error:
	if (skb)
		dev_kfree_skb_any(skb);

	return ret;
}

/*
 * Get a packet : sktbuf mode on 32bit region
 */
static int pktproc_clear_data_addr(struct pktproc_queue *q)
{
	struct pktproc_desc_sktbuf *desc = q->desc_sktbuf;
	struct pktproc_adaptor *ppa = q->ppa;
	u32 fore;
	unsigned long flags;

	if (ppa->desc_mode != DESC_MODE_SKTBUF) {
		mif_err_limited("Invalid desc_mode %d\n", ppa->desc_mode);
		return -EINVAL;
	}

	if (!ppa->use_netrx_mng) {
		mif_err_limited("Buffer manager is not set\n");
		return -EPERM;
	}

	spin_lock_irqsave(&q->lock, flags);

	fore = *q->fore_ptr;

	mif_info("Unmap buffer from %d to %d\n", q->done_ptr, fore);

	while (fore != q->done_ptr) {
		if (ppa->buff_rgn_cached && !ppa->use_hw_iocc && q->dma_addr[q->done_ptr]) {
			dma_unmap_single_attrs(ppa->dev, q->dma_addr[q->done_ptr],
					ppa->max_packet_size, DMA_FROM_DEVICE, 0);
			q->dma_addr[q->done_ptr] = 0;
		}
		desc[q->done_ptr].cp_data_paddr = 0;
		q->done_ptr = circ_new_ptr(q->num_desc, q->done_ptr, 1);
	}

	memset(desc, 0, q->desc_size);

	cpif_init_netrx_mng(q->manager);

	spin_unlock_irqrestore(&q->lock, flags);

	return 0;
}

static int pktproc_clear_data_addr_without_bm(struct pktproc_queue *q)
{
	struct pktproc_desc_sktbuf *desc = q->desc_sktbuf;
	int i;

	if (q->ppa->desc_mode != DESC_MODE_SKTBUF) {
		mif_err_limited("Invalid desc_mode %d\n", q->ppa->desc_mode);
		return -EINVAL;
	}

	if (q->ppa->use_netrx_mng) {
		mif_err_limited("Buffer manager is set\n");
		return -EPERM;
	}

	mif_info("Unmap all buffers\n");
	for (i = 0; i < q->num_desc; i++) {
		if (q->ppa->buff_rgn_cached && !q->ppa->use_hw_iocc && q->dma_addr[i]) {
			dma_unmap_single_attrs(q->ppa->dev, q->dma_addr[i],
					q->ppa->max_packet_size, DMA_FROM_DEVICE, 0);
			q->dma_addr[i] = 0;
		}
	}
	memset(desc, 0, q->desc_size);

	return 0;
}

static int pktproc_fill_data_addr(struct pktproc_queue *q)
{
	struct pktproc_desc_sktbuf *desc = q->desc_sktbuf;
	struct pktproc_adaptor *ppa = q->ppa;
	u32 space;
	u32 fore;
	int i, ret = 0;
	unsigned long flags;

	if (ppa->desc_mode != DESC_MODE_SKTBUF) {
		mif_err_limited("Invalid desc_mode %d\n", ppa->desc_mode);
		return -EINVAL;
	}

	if (!ppa->use_netrx_mng) {
		mif_err_limited("Buffer manager is not set\n");
		return -EPERM;
	}

	spin_lock_irqsave(&q->lock, flags);

	fore = *q->fore_ptr;
	space = circ_get_space(q->num_desc, fore, q->done_ptr);
	pp_debug("Q%d:%d/%d/%d Space:%d\n",
		q->q_idx, fore, *q->rear_ptr, q->done_ptr, space);

	if (!(q->manager->data_pool->page_alloc_complete))
		cpif_page_pool_continue(NETRX_POOL_PAGE_SIZE, q->manager->data_pool);

	for (i = 0; i < space; i++) {
		struct cpif_addr_pair *addrpair = cpif_map_rx_buf(q->manager, fore);

		if (unlikely(!addrpair)) {
			mif_err_limited("skb alloc error due to no memory\n");
			q->stat.err_bm_nomem++;
			ret = -ENOMEM;
			goto done;
		}

		if (ppa->buff_rgn_cached && !ppa->use_hw_iocc) {
			q->dma_addr[fore] = dma_map_single_attrs(ppa->dev,
					(u8 *)addrpair->ap_addr + ppa->skb_padding_size,
					ppa->max_packet_size, DMA_FROM_DEVICE, 0);
			if (dma_mapping_error(ppa->dev, q->dma_addr[fore])) {
				mif_err_limited("dma_map_single_attrs() failed\n");
				q->dma_addr[fore] = 0;
				ret = -ENOMEM;
				goto done;
			}
		}

		desc[fore].cp_data_paddr = addrpair->cp_addr + ppa->skb_padding_size;

		if (fore == 0)
			desc[fore].control |= (1 << 7);	/* HEAD */

		if (fore == (q->num_desc - 1))
			desc[fore].control |= (1 << 3);	/* RINGEND */

		if (unlikely(desc[fore].reserved0 != 0)) { /* W/A to detect mem poison */
			mif_err("mem poison:0x%llX r0:%d c:%d s:%d l%d cl%d r1:%d\n",
					desc[fore].cp_data_paddr, desc[fore].reserved0,
					desc[fore].control, desc[fore].status,
					desc[fore].lro, desc[fore].clat, desc[fore].reserved1);
			panic("memory poison\n");
		}
		fore = circ_new_ptr(q->num_desc, fore, 1);
	}

	pp_debug("Q:%d fore/rear/done:%d/%d/%d\n",
			q->q_idx, fore, *q->rear_ptr, q->done_ptr);

done:
	*q->fore_ptr = fore;
	spin_unlock_irqrestore(&q->lock, flags);

	return ret;
}

static int pktproc_fill_data_addr_without_bm(struct pktproc_queue *q)
{
	struct pktproc_desc_sktbuf *desc = q->desc_sktbuf;
	unsigned long dst_paddr;
	u32 fore;
	int i;
	unsigned long flags;
	u32 space;
	u32 fore_inc = 1;

	if (q->ppa->desc_mode != DESC_MODE_SKTBUF) {
		mif_err_limited("Invalid desc_mode %d\n", q->ppa->desc_mode);
		return -EINVAL;
	}

	if (q->ppa->use_netrx_mng) {
		mif_err_limited("Buffer manager is set\n");
		return -EPERM;
	}

#if IS_ENABLED(CONFIG_LINK_DEVICE_PCIE_IOMMU)
	fore = q->ioc.curr_fore;
#else
	fore = *q->fore_ptr;
#endif

	pp_debug("Q%d:%d/%d/%d\n",
			q->q_idx, fore, *q->rear_ptr, q->done_ptr);

	spin_lock_irqsave(&q->lock, flags);

	if (q->ppa->buff_rgn_cached) {
		space = circ_get_space(q->num_desc, fore, q->done_ptr);
#if IS_ENABLED(CONFIG_LINK_DEVICE_PCIE_IOMMU)
		if (space > q->ppa->space_margin)
			space -= q->ppa->space_margin;
		else
			space = 0;
#endif
	} else {
		space = q->num_desc;
	}

	for (i = 0; i < space; i++) {
		u8 *dst_vaddr = NULL;

		dst_paddr = q->q_buff_pbase + (q->ppa->true_packet_size * fore);
		if (dst_paddr > (q->q_buff_pbase + q->q_buff_size))
			mif_err_limited("dst_paddr:0x%lx is over 0x%lx\n",
					dst_paddr, q->q_buff_pbase + q->q_buff_size);

		pp_debug("Q:%d fore_ptr:%d dst_paddr:0x%lx\n",
			q->q_idx, fore, dst_paddr);

#if IS_ENABLED(CONFIG_LINK_DEVICE_PCIE_IOMMU)
		dst_vaddr = cpif_pcie_iommu_map_va(q, dst_paddr, fore, &fore_inc);
		if (!dst_vaddr) {
			mif_err_limited("cpif_pcie_iommu_get_va() failed\n");
			spin_unlock_irqrestore(&q->lock, flags);
			return -ENOMEM;
		}
#endif

		if (q->ppa->buff_rgn_cached && !q->ppa->use_hw_iocc) {
			if (dst_vaddr)
				goto dma_map;

			dst_vaddr = q->q_buff_vbase + (q->ppa->true_packet_size * fore);
			if (dst_vaddr > (q->q_buff_vbase + q->q_buff_size))
				mif_err_limited("dst_vaddr:%pK is over %pK\n",
						dst_vaddr, q->q_buff_vbase + q->q_buff_size);

dma_map:
			q->dma_addr[fore] =
				dma_map_single_attrs(q->ppa->dev,
						     dst_vaddr + q->ppa->skb_padding_size,
						     q->ppa->max_packet_size, DMA_FROM_DEVICE, 0);
			if (dma_mapping_error(q->ppa->dev, q->dma_addr[fore])) {
				mif_err_limited("dma_map_single_attrs() failed\n");
				q->dma_addr[fore] = 0;
				spin_unlock_irqrestore(&q->lock, flags);
				return -ENOMEM;
			}
		}

		desc[fore].cp_data_paddr = (dst_paddr - q->q_buff_pbase) +
						q->cp_buff_pbase +
						q->ppa->skb_padding_size;

		if (fore == 0)
			desc[fore].control |= (1 << 7);	/* HEAD */

		if (fore == (q->num_desc - 1)) {
			desc[fore].control |= (1 << 3);	/* RINGEND */
			if (!q->ppa->buff_rgn_cached)
				continue;
		}

		if (fore_inc)
			*q->fore_ptr = circ_new_ptr(q->num_desc, *q->fore_ptr, fore_inc);
		fore = circ_new_ptr(q->num_desc, fore, 1);
#if IS_ENABLED(CONFIG_LINK_DEVICE_PCIE_IOMMU)
		q->ioc.curr_fore = fore;
#endif
	}

	pp_debug("Q:%d fore/rear/done:%d/%d/%d\n",
			q->q_idx, *q->fore_ptr, *q->rear_ptr, q->done_ptr);

	spin_unlock_irqrestore(&q->lock, flags);

	return 0;
}

static int pktproc_update_fore_ptr(struct pktproc_queue *q, u32 count)
{
	int ret = 0;
	unsigned long flags;

	if (!count)
		return 0;

	if (q->ppa->buff_rgn_cached) {
		ret = q->alloc_rx_buf(q);
		if (ret)
			mif_err_limited("alloc_rx_buf() error %d Q%d\n", ret, q->q_idx);
	} else {
		spin_lock_irqsave(&q->lock, flags);
		*q->fore_ptr = circ_new_ptr(q->num_desc, *q->fore_ptr, count);
		spin_unlock_irqrestore(&q->lock, flags);
	}

	return ret;
}

static bool is_desc_valid(struct pktproc_queue *q, struct pktproc_desc_sktbuf *desc)
{
	struct link_device *ld = &q->mld->link_dev;
	struct io_device *iod;

	if (desc->length > q->ppa->max_packet_size) {
		mif_err_limited("Length is invalid:%d\n", desc->length);
		q->stat.err_len++;
		return false;
	}

	iod = get_iod_with_channel(ld->msd, desc->channel_id);
	if (!iod || !is_ps_iod(iod)) {
		mif_err_limited("Channel ID is not for ps:%u\n", desc->channel_id);
		q->stat.err_chid++;
		return false;
	}

	return true;
}

static u8 *get_packet_vaddr(struct pktproc_queue *q, struct pktproc_desc_sktbuf *desc, u32 idx)
{
	u8 *ret;
	struct pktproc_adaptor *ppa = q->ppa;

	if (q->manager) {
		ret = (u8 *)cpif_unmap_rx_buf(q->manager, idx);
		if (!ret) {
			mif_err_limited("invalid data address. null given\n");
			q->stat.err_addr++;
			return NULL;
		}
	} else {
#if IS_ENABLED(CONFIG_LINK_DEVICE_PCIE_IOMMU)
		unsigned long src_paddr = desc->cp_data_paddr - q->cp_buff_pbase +
				q->q_buff_pbase - ppa->skb_padding_size;

		ret = (u8 *)q->ioc.pf_buf[q->done_ptr];
		cpif_pcie_iommu_try_ummap_va(q, src_paddr, ret, q->done_ptr);
#else
		ret = desc->cp_data_paddr - q->cp_buff_pbase +
				q->q_buff_vbase - ppa->skb_padding_size;

		if ((ret < q->q_buff_vbase) || (ret > q->q_buff_vbase + q->q_buff_size)) {
			mif_err_limited("Data address is invalid:%pK data:%pK size:0x%08x\n",
					ret, q->q_buff_vbase, q->q_buff_size);
			q->stat.err_addr++;
			return NULL;
		}
#endif
	}

	ret += ppa->skb_padding_size;

	if (ppa->buff_rgn_cached && !ppa->use_hw_iocc && q->dma_addr[q->done_ptr]) {
		dma_unmap_single_attrs(ppa->dev, q->dma_addr[q->done_ptr],
					ppa->max_packet_size, DMA_FROM_DEVICE, 0);
		q->dma_addr[q->done_ptr] = 0;
	}

	return ret;
}

static struct sk_buff *cpif_build_skb(struct pktproc_queue *q, u8 *src, u16 len,
		u16 front_pad_size, u16 rear_pad_size)
{
	struct sk_buff *skb;

	if (q->manager) {
		skb = napi_build_skb(src - front_pad_size, q->manager->frag_size);
		if (unlikely(!skb))
			goto error;

		skb_reserve(skb, front_pad_size);
	} else {
#if IS_ENABLED(CONFIG_LINK_DEVICE_PCIE_IOMMU)
		skb = napi_build_skb(src - front_pad_size, q->ppa->true_packet_size);
		if (unlikely(!skb))
			goto error;

		skb_reserve(skb, front_pad_size);
#else
		skb = napi_alloc_skb(q->napi_ptr, len);
		if (unlikely(!skb))
			goto error;

		skb_copy_to_linear_data(skb, src, len);
#endif
	}

	skb_put(skb, len);

	return skb;

error:
	mif_err_limited("getting skb failed\n");

	q->stat.err_nomem++;
	if (q->manager && !q->manager->already_retrieved)
		q->manager->already_retrieved = src;

	return NULL;
}

#if IS_ENABLED(CONFIG_CP_PKTPROC_LRO)
static u32 cpif_get_headlen(struct sk_buff *skb)
{
	size_t headlen;
	struct iphdr *iph = (struct iphdr *)skb->data;
	struct ipv6hdr *ipv6h;
	struct tcphdr *th = NULL;

	if (iph->version == 6) {
		ipv6h = (struct ipv6hdr *)skb->data;
		headlen = sizeof(struct ipv6hdr);
		if (ipv6h->nexthdr == NEXTHDR_TCP) {
			th = (struct tcphdr *)(skb->data + headlen);
			headlen += th->doff * 4;
		} else /* UDP */
			headlen += sizeof(struct udphdr);
	} else { /* ipv4 */
		headlen = sizeof(struct iphdr);
		if (iph->protocol == IPPROTO_TCP) {
			th = (struct tcphdr *)(skb->data + headlen);
			headlen += th->doff * 4;
		} else
			headlen += sizeof(struct udphdr);
	}

	return headlen;
}

static void finish_up_lro(struct sk_buff *skb)
{
	size_t headlen;
	struct iphdr *iph = (struct iphdr *)skb->data;
	struct ipv6hdr *ipv6h;
	struct tcphdr *th = NULL;
	struct udphdr *uh = NULL;
	int net_len;

	if (iph->version == 6) {
		ipv6h = (struct ipv6hdr *)skb->data;
		headlen = sizeof(struct ipv6hdr);
		net_len = ntohs(ipv6h->payload_len);
		if (ipv6h->nexthdr == NEXTHDR_TCP) {
			th = (struct tcphdr *)(skb->data + headlen);
			th->check = ~tcp_v6_check(net_len, &ipv6h->saddr, &ipv6h->daddr, 0);
			skb_shinfo(skb)->gso_type |= SKB_GSO_TCPV6;
		} else { /* UDP */
			uh = (struct udphdr *)(skb->data + headlen);
			uh->check = ~udp_v6_check(net_len, &ipv6h->saddr, &ipv6h->daddr, 0);
			skb_shinfo(skb)->gso_type |= SKB_GSO_UDP_L4;
		}
	} else { /* ipv4 */
		headlen = sizeof(struct iphdr);
		net_len = ntohs(iph->tot_len) - headlen;
		if (iph->protocol == IPPROTO_TCP) {
			th = (struct tcphdr *)(skb->data + headlen);
			th->check = ~tcp_v4_check(net_len, iph->saddr, iph->daddr, 0);
			skb_shinfo(skb)->gso_type |= SKB_GSO_TCPV4;
		} else {
			uh = (struct udphdr *)(skb->data +headlen);
			uh->check = ~udp_v4_check(net_len, iph->saddr, iph->daddr, 0);
			skb_shinfo(skb)->gso_type |= SKB_GSO_UDP_L4;
		}
	}

	if (th) {
		skb->csum_start = (unsigned char *)th - skb->head;
	        skb->csum_offset = offsetof(struct tcphdr, check);

	} else { /* uh */
		skb->csum_start = (unsigned char *)uh - skb->head;
		skb->csum_offset = offsetof(struct udphdr, check);
	}

	skb->ip_summed = CHECKSUM_PARTIAL;
}

static void modify_lro_len(u32 target_len, unsigned char *src)
{
	struct iphdr *iph = (struct iphdr *)src;
	struct ipv6hdr *ipv6h;
	struct udphdr *uh = NULL;
	size_t headlen;
	int net_len;

	if (iph->version == 4) {
		headlen = sizeof(struct iphdr);
		net_len = target_len - headlen;
		iph->tot_len = htons(target_len);
		if (iph->protocol == IPPROTO_UDP) {
			uh = (struct udphdr *)(src + sizeof(struct iphdr));
			uh->len = htons(net_len);
		}
	} else { /* ip version 6 */
		ipv6h = (struct ipv6hdr *)src;
		headlen = sizeof(struct ipv6hdr);
		net_len = target_len - headlen;
		ipv6h->payload_len = htons(net_len);
		if (ipv6h->nexthdr == NEXTHDR_UDP) {
			uh = (struct udphdr *)(src + headlen);
			uh->len = htons(net_len);
		}
	}
}
#endif /* end of CONFIG_CP_PKTPROC_LRO */

static int pktproc_get_pkt_from_sktbuf_mode(struct pktproc_queue *q, struct sk_buff **new_skb)
{
	int ret = 0;
	u16 len = 0;
	u8 ch_id;
	/* It will be the start of skb->data */
	u8 *src = 0;
#if IS_ENABLED(CONFIG_CP_PKTPROC_LRO)
	struct iphdr *iph;
	struct sk_buff *skb_head;
	struct skb_shared_info *pinfo_head;
	struct pktproc_lro_stream *stream;
	bool continue_lro = false;
#endif
	struct pktproc_adaptor *ppa = q->ppa;
	struct sk_buff *skb = NULL;
	struct pktproc_desc_sktbuf desc_done_ptr = q->desc_sktbuf[q->done_ptr];
	struct link_device *ld = &q->mld->link_dev;
	bool csum = false;

	if (!pktproc_check_active(ppa, q->q_idx)) {
		mif_err_limited("Queue %d not activated\n", q->q_idx);
		return -EACCES;
	}

	if (ppa->desc_mode != DESC_MODE_SKTBUF) {
		mif_err_limited("Invalid desc_mode %d\n", ppa->desc_mode);
		return -EINVAL;
	}

	if (!is_desc_valid(q, &desc_done_ptr)) {
		ret = -EINVAL;
		goto rx_error_on_desc;
	}

	src = get_packet_vaddr(q, &desc_done_ptr, q->done_ptr);
	if (!src) {
		ret = -EINVAL;
		goto rx_error_on_desc;
	}

	if (desc_done_ptr.itg == 1) {
		q->stat.err_itg++;
		if (q->manager) { /* should decrement ref count of used page */
			page_ref_dec(q->manager->apair_arr[q->done_ptr].page);
		}
		goto rx_error_drop;
	}

	len = desc_done_ptr.length;
	ch_id = desc_done_ptr.channel_id;
	csum = pktproc_check_hw_checksum(desc_done_ptr.status);
	if (!csum)
		q->stat.err_csum++;
	if (unlikely(ppa->pktgen_gro)) {
		pktproc_set_pktgen_checksum(q, src);
		csum = true;
	}

	pp_debug("Q:%d done_ptr:%d len:%d ch_id:%d src:%pK csum:%d\n",
			q->q_idx, q->done_ptr, len, ch_id, src, csum);

#ifdef PKTPROC_DEBUG_PKT
	pr_buffer("desc", (char *)&desc_done_ptr, (size_t)sizeof(struct pktproc_desc_sktbuf),
			(size_t)sizeof(struct pktproc_desc_sktbuf));
	pr_buffer("pktproc", (char *)src, (size_t)len, (size_t)40);
#endif

	if (dit_check_dir_use_queue(DIT_DIR_RX, q->q_idx)) {
#if IS_ENABLED(CONFIG_LINK_DEVICE_PCIE_IOMMU)
		unsigned long src_paddr = 0;
#else
		unsigned long src_paddr = desc_done_ptr.cp_data_paddr - q->cp_buff_pbase +
				q->q_buff_pbase;
#endif

		ret = dit_enqueue_src_desc_ring(DIT_DIR_RX,
			src, src_paddr, len, ch_id, csum);
		if (ret < 0) {
			mif_err_limited("Enqueue failed at fore/rear/done:%d/%d/%d, ret: %d\n",
				*q->fore_ptr, *q->rear_ptr, q->done_ptr, ret);

			q->stat.err_enqueue_dit++;
			goto rx_error;
		}

		q->stat.pass_cnt++;
		q->done_ptr = circ_new_ptr(q->num_desc, q->done_ptr, 1);

		return 1; /* dit cannot support LRO packets */
	}

#if IS_ENABLED(CONFIG_CP_PKTPROC_LRO)
	/* guaranteed that only TCP/IP, UDP/IP in this case */
	if (desc_done_ptr.lro == (LRO_MODE_ON | LRO_PACKET | LRO_FIRST_SEG)) {
		/* the first segment of LRO packet */
		u32 hdr_len;

		stream = &q->lro_stream[desc_done_ptr.lro_q_idx];

		if (!stream->empty) { /* SW W/A for HW bug caused by duplicate pkt */
			struct iphdr *iph;

			skb_head = stream->skb;
			iph = (struct iphdr *)skb_head->data;
			mif_err("stream %u is not empty: skb_len: %u protocol: %u\n",
					desc_done_ptr.lro_q_idx, stream->skb->len,
					iph->protocol);
			/* HW couldn't change header, SW fix instead */
			modify_lro_len(skb_head->len, skb_head->data);
			pinfo_head = skb_shinfo(skb_head);
			stream->bypass_lro = true;
			continue_lro = true;
			goto flush; /* need to flush LRO first */
		}
restart_lro:
		skb = cpif_build_skb(q, src, len, ppa->skb_padding_size,
					    sizeof(struct skb_shared_info));
		if (unlikely(!skb)) {
			ret = -ENOMEM;
			goto rx_error;
		}

		hdr_len = cpif_get_headlen(skb);
		skb_shinfo(skb)->gso_size = skb->len - hdr_len;
		skb_shinfo(skb)->gso_segs = 1;
		skb_frag_list_init(skb);
		skb->csum_level = 1;

		stream->empty = false;
		stream->skb = skb;
		stream->bypass_lro = false;
		skb = NULL;
	} else if (desc_done_ptr.lro & (LRO_MID_SEG | LRO_LAST_SEG)){
		/* turns out to be the middle or last of LRO packet*/
		struct skb_shared_info *pinfo;

		stream = &q->lro_stream[desc_done_ptr.lro_q_idx];

		if (stream->bypass_lro) /* should bypass since gathering broked*/
			goto non_lro;

		skb_head = stream->skb;
		if (!skb_head)
			mif_err("skb_head is null\n");
		pinfo_head = skb_shinfo(skb_head);
		iph = (struct iphdr *)skb_head->data;

		if (stream->empty) {
			mif_err("stream#%d is empty.\n", desc_done_ptr.lro_q_idx);
			ret = -EINVAL;
			goto rx_error_drop;
		}

		src += desc_done_ptr.lro_head_offset;
		len -= desc_done_ptr.lro_head_offset;

		if (pinfo_head->gso_size != len) {
			stream->bypass_lro = true;
			src -= desc_done_ptr.lro_head_offset;
			len += desc_done_ptr.lro_head_offset;
			modify_lro_len(skb_head->len, skb_head->data);
			goto flush; /* need to flush LRO first */
		}
		if (stream->last)
			skb = stream->last;
		else /* no skb in frag_list yet */
			skb = skb_head;

		pinfo = skb_shinfo(skb);
		if (pinfo->nr_frags < MAX_SKB_FRAGS) {
			struct page *page;
			skb_frag_t *frag = &pinfo->frags[pinfo->nr_frags];

			page = virt_to_head_page(src);

			__skb_frag_set_page(frag, page);
			skb_frag_off_set(frag, src - (u8 *)page_address(page));
			skb_frag_size_set(frag, len);
			pinfo->nr_frags++;
			if(skb != skb_head) {
				skb->truesize += len;
				skb->data_len += len;
				skb->len += len;
			}
			skb_head->truesize += len;
			skb_head->data_len += len;
			skb_head->len += len;
			skb_shinfo(skb_head)->gso_segs += 1;
		} else { /* need to generate new skb, and put it to fraglist */
			skb = cpif_build_skb(q, src, len,
					q->ppa->skb_padding_size +
					desc_done_ptr.lro_head_offset,
					sizeof(struct skb_shared_info));
			if (unlikely(!skb)) {
				ret = -ENOMEM;
				goto rx_error;
			}

			if (stream->last) { /* fraglist already exists */
				stream->last->next = skb;
			} else /* skb is the first one to put in frag_list of LRO packet */
				skb_shinfo(skb_head)->frag_list = skb;
			stream->last = skb;
			skb_head->data_len += skb->len;
			skb_head->truesize += skb->truesize;
			skb_head->len += skb->len;
			skb_shinfo(skb_head)->gso_segs += 1;
		}

		if (desc_done_ptr.lro & LRO_LAST_SEG) {
flush:
			if (pinfo_head->gso_segs != 1)
				finish_up_lro(skb_head);
			iph = (struct iphdr *)skb_head->data;
			if (iph->version == 4) /* ipv4 checksum will be done in kernel */ {
				iph->check = 0;
				iph->check = ip_fast_csum((unsigned char *)iph, iph->ihl);
			}
			csum = true; /* regardless of pktproc csums status, its always true */
			skb = skb_head;
			stream->empty = true;
			stream->skb = NULL;
			stream->last = NULL;
			q->stat.lro_cnt++;
			if (stream->bypass_lro) {
				if (pinfo_head->gso_segs == 1) { /* disable LRO */
					skb_shinfo(skb)->gso_size = 0;
					skb_shinfo(skb)->gso_segs = 0;
				}

				if (ppa->use_exclusive_irq)
					skb_record_rx_queue(skb, q->q_idx);

				/* Set priv */
				skbpriv(skb)->lnk_hdr = 0;
				skbpriv(skb)->sipc_ch = ch_id;
				skbpriv(skb)->iod = link_get_iod_with_channel(ld, ch_id);
				skbpriv(skb)->ld = ld;
				skbpriv(skb)->napi = q->napi_ptr;

				ret++;
				q->mld->pass_skb_to_net(q->mld, skb);
				if (continue_lro)
					goto restart_lro;
				else
					goto non_lro;
			}

		} else
			skb = NULL;
	} else {
non_lro:
		skb = cpif_build_skb(q, src, len, ppa->skb_padding_size,
					    sizeof(struct skb_shared_info));
		if (unlikely(!skb)) {
			ret = -ENOMEM;
			goto rx_error;
		}
	}
#else
	skb = cpif_build_skb(q, src, len, ppa->skb_padding_size,
				    sizeof(struct skb_shared_info));
	if (unlikely(!skb)) {
		ret = -ENOMEM;
		goto rx_error;
	}
#endif

	if (skb) {
		if (csum && skb->ip_summed != CHECKSUM_PARTIAL)
			skb->ip_summed = CHECKSUM_UNNECESSARY;

		if (ppa->use_exclusive_irq)
			skb_record_rx_queue(skb, q->q_idx);

		/* Set priv */
		skbpriv(skb)->lnk_hdr = 0;
		skbpriv(skb)->sipc_ch = ch_id;
		skbpriv(skb)->iod = link_get_iod_with_channel(ld, ch_id);
		skbpriv(skb)->ld = ld;
		skbpriv(skb)->napi = q->napi_ptr;

		*new_skb = skb;
		ret++;
	}

	q->stat.pass_cnt++;
	q->done_ptr = circ_new_ptr(q->num_desc, q->done_ptr, 1);

	return ret;

rx_error_on_desc:
	if (src && len) {
		pr_buffer("desc", (char *)&desc_done_ptr, (size_t)sizeof(struct pktproc_desc_sktbuf),
			(size_t)sizeof(struct pktproc_desc_sktbuf));
		pr_buffer("pktproc", (char *)src, (size_t)len, (size_t)40);
	}
	mif_err("Skip invalid descriptor at %d and crash\n", q->done_ptr);
	ld->link_trigger_cp_crash(q->mld, CRASH_REASON_MIF_RX_BAD_DATA,
				"invalid descriptor given");
rx_error_drop:
	q->done_ptr = circ_new_ptr(q->num_desc, q->done_ptr, 1);

rx_error:
	if (skb)
		dev_kfree_skb_any(skb);

	return ret;
}

/*
 * Clean RX ring
 */
int pktproc_get_usage(struct pktproc_queue *q)
{
	u32 usage = 0;

	switch (q->ppa->desc_mode) {
	case DESC_MODE_RINGBUF:
		usage = circ_get_usage(q->num_desc, *q->fore_ptr, *q->rear_ptr);
		break;
	case DESC_MODE_SKTBUF:
		usage = circ_get_usage(q->num_desc, *q->rear_ptr, q->done_ptr);
		break;
	default:
		usage = 0;
		break;
	}

	return usage;
}

int pktproc_get_usage_fore_rear(struct pktproc_queue *q)
{
	u32 usage = 0;

	switch (q->ppa->desc_mode) {
	case DESC_MODE_RINGBUF:
		usage = circ_get_usage(q->num_desc, *q->fore_ptr, *q->rear_ptr);
		break;
	case DESC_MODE_SKTBUF:
		usage = circ_get_usage(q->num_desc, *q->rear_ptr, *q->fore_ptr);
		break;
	default:
		usage = 0;
		break;
	}

	return usage;
}

static int pktproc_clean_rx_ring(struct pktproc_queue *q, int budget, int *work_done)
{
	int ret = 0;
	u32 num_frames = 0;
	u32 rcvd_total = 0;
	u32 budget_used = 0;

	if (!pktproc_check_active(q->ppa, q->q_idx))
		return -EACCES;

	num_frames = pktproc_get_usage(q);

	if (!num_frames)
		return 0;

	pp_debug("Q%d num_frames:%d fore/rear/done: %d/%d/%d\n",
			q->q_idx, num_frames,
			*q->fore_ptr, *q->rear_ptr, q->done_ptr);

	while (rcvd_total < num_frames && budget_used < budget) {
		struct sk_buff *skb = NULL;

		ret = q->get_packet(q, &skb);
		if (unlikely(ret < 0)) {
			mif_err_limited("get_packet() error %d\n", ret);
			break;
		}
		rcvd_total++;
		if (skb)
			budget_used += ret;
		else /* LRO packet is processed or itg failed */
			continue;
		ret = q->mld->pass_skb_to_net(q->mld, skb);
		if (ret < 0)
			break;
	}

#if IS_ENABLED(CONFIG_CPIF_TP_MONITOR)
	if (rcvd_total)
		tpmon_start();
#endif

	q->update_fore_ptr(q, rcvd_total);

	*work_done = rcvd_total;

	return ret;
}

/*
 * perftest
 */
static void pktproc_perftest_napi_schedule(void *arg)
{
	struct pktproc_queue *q = (struct pktproc_queue *)arg;

	if (!q) {
		mif_err_limited("q is null\n");
		return;
	}

	if (!pktproc_get_usage(q))
		return;

	napi_schedule(q->napi_ptr);
}

static unsigned int pktproc_perftest_gen_rx_packet_sktbuf_mode(
		struct pktproc_queue *q, int packet_num, int session)
{
	struct pktproc_desc_sktbuf *desc = q->desc_sktbuf;
	struct pktproc_perftest *perf = &q->ppa->perftest;
	u32 header_len = perftest_data[perf->mode].header_len;
	u32 packet_len = perftest_data[perf->mode].packet_len;
	u32 rear_ptr;
	unsigned int space, loop_count;
	u8 *src = NULL;
	u32 *seq;
	u16 *dst_port;
	u16 *dst_addr;
	int i, j;
#if IS_ENABLED(CONFIG_CP_PKTPROC_LRO)
	int total_length = 0;
	bool lro_start = true; /* this var used for LRO only */
	struct iphdr *iph = NULL;
	struct udphdr *uh = NULL;
#endif
	rear_ptr = *q->rear_ptr;
	space = circ_get_space(q->num_desc, rear_ptr, *q->fore_ptr);
	loop_count = min_t(unsigned int, space, packet_num);

	for (i = 0 ; i < loop_count ; i++) {
		/* set desc */
		desc[rear_ptr].status =
			PKTPROC_STATUS_DONE | PKTPROC_STATUS_TCPC | PKTPROC_STATUS_IPCS;
		desc[rear_ptr].length = packet_len;
		desc[rear_ptr].filter_result = 0x9;
		desc[rear_ptr].channel_id = perf->ch;

		/* set data */
#if IS_ENABLED(CONFIG_LINK_DEVICE_PCIE_IOMMU)
		src = q->ioc.pf_buf[rear_ptr] + q->ppa->skb_padding_size;
#elif IS_ENABLED(CONFIG_EXYNOS_CPIF_IOMMU) || IS_ENABLED(CONFIG_EXYNOS_CPIF_IOMMU_V9)
		src = q->manager->apair_arr[rear_ptr].ap_addr + q->ppa->skb_padding_size;
#else
		src = desc[rear_ptr].cp_data_paddr -
				q->cp_buff_pbase + q->q_buff_vbase;
#endif
		if (!src) {
			mif_err_limited("src is null\n");
			return -EINVAL;
		}
		memset(src, 0x0, desc[rear_ptr].length);
		memcpy(src, perftest_data[perf->mode].header, header_len);
		seq = (u32 *)(src + header_len);
		*seq = htonl(perf->seq_counter[session]++);
		dst_port = (u16 *)(src + perftest_data[perf->mode].dst_port_offset);
		*dst_port = htons(5001 + session);
		if (perf->mode == PERFTEST_MODE_CLAT) {
			for (j = 0 ; j < 8 ; j++) {
				dst_addr = (u16 *)(src + 24 + (j * 2));
				*dst_addr = htons(perf->clat_ipv6[j]);
			}
		}

#if IS_ENABLED(CONFIG_CP_PKTPROC_LRO)
		desc[rear_ptr].lro = LRO_MODE_ON; /* LRO on and packet is LRO */
		if (perf->mode == PERFTEST_MODE_IPV4_LRO) {
			desc[rear_ptr].lro |= LRO_PACKET;
			desc[rear_ptr].lro_q_idx = 0;
			desc[rear_ptr].lro_head_offset = header_len;

			if (lro_start) {
				total_length += packet_len;
				iph = (struct iphdr *)src;
				uh = (struct udphdr *)(src + sizeof(struct iphdr));
			} else
				total_length += packet_len - header_len;

			if ((i == (loop_count - 1)) || (total_length + (packet_len - header_len) > SZ_64K)) {
				desc[rear_ptr].lro |= LRO_LAST_SEG;
				iph->tot_len = htons(total_length);
				uh->len = htons(total_length - sizeof(struct iphdr));
				lro_start = true; // start another lro
				total_length = 0;
			} else if (lro_start) {
				desc[rear_ptr].lro |= LRO_FIRST_SEG;
				lro_start = false;
			} else /* MID segs */
				desc[rear_ptr].lro |= LRO_MID_SEG;
		}
#endif
		rear_ptr = circ_new_ptr(q->num_desc, rear_ptr, 1);
	}
	*q->rear_ptr = rear_ptr;

	return loop_count;
}

static int pktproc_perftest_thread(void *arg)
{
	struct mem_link_device *mld = (struct mem_link_device *) arg;
	struct pktproc_adaptor *ppa = &mld->pktproc;
	struct pktproc_queue *q = ppa->q[0];
	struct pktproc_perftest *perf = &ppa->perftest;
	bool session_queue = false;
	int i, pkts;

	if (ppa->use_exclusive_irq && (perf->session > 1) && (perf->session <= ppa->num_queue))
		session_queue = true;

	/* max 1023 packets per 1ms for 12Gbps */
	pkts = (perf->session > 0 ? (1023 / perf->session) : 0);
	do {
		for (i = 0 ; i < perf->session ; i++) {
			int napi_cpu = perf->ipi_cpu[0];

			if (session_queue)
				q = ppa->q[i];

			if (!pktproc_perftest_gen_rx_packet_sktbuf_mode(q, pkts, i))
				continue;

			if (session_queue)
				napi_cpu = perf->ipi_cpu[i];

			if (napi_cpu >= 0 && cpu_online(napi_cpu)) {
				smp_call_function_single(napi_cpu,
							 pktproc_perftest_napi_schedule,
							 (void *)q, 0);
			} else {
				pktproc_perftest_napi_schedule(q);
			}
		}

		udelay(perf->udelay);

		if (kthread_should_stop())
			break;
	} while (perf->test_run);

	return 0;
}

static ssize_t perftest_store(struct device *dev,
		struct device_attribute *attr,
		const char *buf, size_t count)
{
	struct modem_ctl *mc = dev_get_drvdata(dev);
	struct link_device *ld = get_current_link(mc->iod);
	struct mem_link_device *mld = to_mem_link_device(ld);
	struct pktproc_adaptor *ppa = &mld->pktproc;
	struct pktproc_perftest *perf = &ppa->perftest;
	unsigned int mode = 0, session, perf_cpu;

	static struct task_struct *worker_task;
	int ret;

	perf->ipi_cpu[0] = -1;
	if (ppa->use_exclusive_irq) {
		perf->ipi_cpu[0] = 4;
		perf->ipi_cpu[1] = 4;
		perf->ipi_cpu[2] = 4;
		perf->ipi_cpu[3] = 4;
	}

	switch (perf->mode) {
	case PERFTEST_MODE_CLAT:
		ret = sscanf(buf, "%d %d %hu %d %d %hx:%hx:%hx:%hx:%hx:%hx:%hx:%hx %d %d %d %d",
			     &mode, &session, &perf->ch, &perf_cpu, &perf->udelay,
			     &perf->clat_ipv6[0], &perf->clat_ipv6[1], &perf->clat_ipv6[2],
			     &perf->clat_ipv6[3], &perf->clat_ipv6[4], &perf->clat_ipv6[5],
			     &perf->clat_ipv6[6], &perf->clat_ipv6[7],
			     &perf->ipi_cpu[0], &perf->ipi_cpu[1], &perf->ipi_cpu[2],
			     &perf->ipi_cpu[3]);
		break;
	default:
		ret = sscanf(buf, "%d %d %hu %d %d %d %d %d %d",
			     &mode, &session, &perf->ch, &perf_cpu, &perf->udelay,
			     &perf->ipi_cpu[0], &perf->ipi_cpu[1], &perf->ipi_cpu[2],
			     &perf->ipi_cpu[3]);
		break;
	}

	if (ret < 1 || mode > PERFTEST_MODE_MAX)
		return -EINVAL;

	perf->mode = mode;
	perf->session = session > PKTPROC_MAX_QUEUE ? PKTPROC_MAX_QUEUE : session;
	perf->cpu = perf_cpu > num_possible_cpus() ? num_possible_cpus() - 1 : perf_cpu;

	switch (perf->mode) {
	case PERFTEST_MODE_STOP:
		if (perf->test_run)
			kthread_stop(worker_task);

		perf->seq_counter[0] = 0;
		perf->seq_counter[1] = 0;
		perf->seq_counter[2] = 0;
		perf->seq_counter[3] = 0;
		perf->test_run = false;
		break;
	case PERFTEST_MODE_IPV4:
#if IS_ENABLED(CONFIG_CP_PKTPROC_LRO)
	case PERFTEST_MODE_IPV4_LRO:
#endif
	case PERFTEST_MODE_CLAT:
	case PERFTEST_MODE_IPV6:
		if (perf->test_run)
			kthread_stop(worker_task);

		perf->test_run = true;
		worker_task = kthread_create_on_node(pktproc_perftest_thread,
			mld, cpu_to_node(perf->cpu), "perftest/%d", perf->cpu);
		kthread_bind(worker_task, perf->cpu);
		wake_up_process(worker_task);
		break;
	default:
		break;
	}

	return count;
}

static ssize_t perftest_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	struct modem_ctl *mc = dev_get_drvdata(dev);
	struct link_device *ld = get_current_link(mc->iod);
	struct mem_link_device *mld = to_mem_link_device(ld);
	struct pktproc_adaptor *ppa = &mld->pktproc;
	struct pktproc_perftest *perf = &ppa->perftest;
	ssize_t count = 0;

	count += scnprintf(&buf[count], PAGE_SIZE - count, "test_run:%d\n", perf->test_run);
	count += scnprintf(&buf[count], PAGE_SIZE - count, "mode:%d\n", perf->mode);
	count += scnprintf(&buf[count], PAGE_SIZE - count, "session:%d\n", perf->session);
	count += scnprintf(&buf[count], PAGE_SIZE - count, "ch:%d\n", perf->ch);
	count += scnprintf(&buf[count], PAGE_SIZE - count, "udelay:%d\n", perf->udelay);
	count += scnprintf(&buf[count], PAGE_SIZE - count, "cpu:%d\n", perf->cpu);

	if (ppa->use_exclusive_irq)
		count += scnprintf(&buf[count], PAGE_SIZE - count, "ipi cpu:%d %d %d %d\n",
			perf->ipi_cpu[0], perf->ipi_cpu[1], perf->ipi_cpu[2], perf->ipi_cpu[3]);

	if (perf->mode == PERFTEST_MODE_CLAT)
		count += scnprintf(&buf[count], PAGE_SIZE - count, "clat %x:%x:%x:%x:%x:%x:%x:%x\n",
			perf->clat_ipv6[0], perf->clat_ipv6[1], perf->clat_ipv6[2],
			perf->clat_ipv6[3], perf->clat_ipv6[4], perf->clat_ipv6[5],
			perf->clat_ipv6[6], perf->clat_ipv6[7]);

	return count;
}

/*
 * NAPI
 */
static int pktproc_poll(struct napi_struct *napi, int budget)
{
	struct pktproc_queue *q = container_of(napi, struct pktproc_queue, napi);
	struct mem_link_device *mld = q->mld;
	struct link_device *ld = &mld->link_dev;
	struct modem_ctl *mc = ld->mc;

	int ret;
	u32 rcvd = 0;

	if (unlikely(!cp_online(mc)))
		goto poll_exit;

	if (!pktproc_check_active(q->ppa, q->q_idx))
		goto poll_exit;

	ret = q->clean_rx_ring(q, budget, &rcvd);
	if ((ret == -EBUSY) || (ret == -ENOMEM))
		goto poll_retry;

	if (atomic_read(&q->stop_napi_poll)) {
		atomic_set(&q->stop_napi_poll, 0);
		goto poll_exit;
	}

	if (rcvd < budget) {
		napi_complete_done(napi, rcvd);
		return rcvd;
	}

poll_retry:
	return budget;

poll_exit:
	napi_complete(napi);

	return 0;
}

/*
 * IRQ handler
 */
static irqreturn_t pktproc_irq_handler(int irq, void *arg)
{
	struct pktproc_queue *q = (struct pktproc_queue *)arg;

	if (!q) {
		mif_err_limited("q is null\n");
		return IRQ_HANDLED;
	}

	if (!pktproc_get_usage(q))
		return IRQ_HANDLED;

#if IS_ENABLED(CONFIG_CPIF_TP_MONITOR)
	tpmon_start();
#endif

#if IS_ENABLED(CONFIG_CLO)
	q->flush_time = q->mld->link_dev.update_flush_time(q->flush_time);
#endif
	napi_schedule(q->napi_ptr);

	return IRQ_HANDLED;
}

/*
 * Debug
 */
static ssize_t region_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	struct modem_ctl *mc = dev_get_drvdata(dev);
	struct link_device *ld = get_current_link(mc->iod);
	struct mem_link_device *mld = to_mem_link_device(ld);
	struct pktproc_adaptor *ppa = &mld->pktproc;
	ssize_t count = 0;
	int i;

	count += scnprintf(&buf[count], PAGE_SIZE - count, "Version:%d\n", ppa->version);
	count += scnprintf(&buf[count], PAGE_SIZE - count, "CP base:0x%08llx\n", ppa->cp_base);
	count += scnprintf(&buf[count], PAGE_SIZE - count, "Descriptor mode:%d\n", ppa->desc_mode);
	count += scnprintf(&buf[count], PAGE_SIZE - count, "Num of queue:%d\n", ppa->num_queue);
	count += scnprintf(&buf[count], PAGE_SIZE - count, "NetRX manager:%d\n",
		ppa->use_netrx_mng);
	count += scnprintf(&buf[count], PAGE_SIZE - count, "Exclusive interrupt:%d\n",
		ppa->use_exclusive_irq);
	count += scnprintf(&buf[count], PAGE_SIZE - count, "HW cache coherency:%d\n",
		ppa->use_hw_iocc);
	count += scnprintf(&buf[count], PAGE_SIZE - count, "Max packet size:%d\n",
		ppa->max_packet_size);
	if (ppa->true_packet_size != ppa->max_packet_size) {
		count += scnprintf(&buf[count], PAGE_SIZE - count, "True packet size:%d\n",
			ppa->true_packet_size);
	}
	count += scnprintf(&buf[count], PAGE_SIZE - count, "Padding size:%d\n",
		ppa->skb_padding_size);
	count += scnprintf(&buf[count], PAGE_SIZE - count, "Dedicated BAAW:%d\n",
		ppa->use_dedicated_baaw);
	count += scnprintf(&buf[count], PAGE_SIZE - count, "info:%s desc:%s/buff:%s\n",
		ppa->info_rgn_cached ? "C" : "NC",
		ppa->desc_rgn_cached ? "C" : "NC",
		ppa->buff_rgn_cached ? "C" : "NC");
	count += scnprintf(&buf[count], PAGE_SIZE - count, "\n");

	for (i = 0; i < ppa->num_queue; i++) {
		struct pktproc_queue *q = ppa->q[i];

		if (!pktproc_check_active(ppa, q->q_idx)) {
			count += scnprintf(&buf[count], PAGE_SIZE - count,
				"Queue %d is not active\n", i);
			continue;
		}

		count += scnprintf(&buf[count], PAGE_SIZE - count, "Queue%d\n", i);
		count += scnprintf(&buf[count], PAGE_SIZE - count, "  num_desc:%d(0x%08x)\n",
			q->q_info_ptr->num_desc, q->q_info_ptr->num_desc);
		count += scnprintf(&buf[count], PAGE_SIZE - count, "  cp_desc_pbase:0x%08x\n",
			q->q_info_ptr->cp_desc_pbase);
		count += scnprintf(&buf[count], PAGE_SIZE - count, "  desc_size:0x%08x\n",
			q->desc_size);
		count += scnprintf(&buf[count], PAGE_SIZE - count, "  cp_buff_pbase:0x%08x\n",
			q->q_info_ptr->cp_buff_pbase);
		count += scnprintf(&buf[count], PAGE_SIZE - count, "  q_buff_size:0x%08x\n",
			q->q_buff_size);
		count += scnprintf(&buf[count], PAGE_SIZE - count, "  DIT:%d\n",
			dit_check_dir_use_queue(DIT_DIR_RX, q->q_idx));

		if (q->manager) {
			count += scnprintf(&buf[count], PAGE_SIZE - count,
					"Buffer manager\n");
			count += scnprintf(&buf[count], PAGE_SIZE - count,
					"  total number of packets:%llu\n",
				q->manager->num_packet);
			count += scnprintf(&buf[count], PAGE_SIZE - count,
					"  frag size:%llu\n",
				q->manager->frag_size);
			count += scnprintf(&buf[count], PAGE_SIZE - count, "\n");
		}
	}

	return count;
}

static ssize_t status_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	struct modem_ctl *mc = dev_get_drvdata(dev);
	struct link_device *ld = get_current_link(mc->iod);
	struct mem_link_device *mld = to_mem_link_device(ld);
	struct pktproc_adaptor *ppa = &mld->pktproc;
	ssize_t count = 0;
	int i;

	for (i = 0; i < ppa->num_queue; i++) {
		struct pktproc_queue *q = ppa->q[i];

		if (!pktproc_check_active(ppa, q->q_idx)) {
			count += scnprintf(&buf[count], PAGE_SIZE - count,
				"Queue %d is not active\n", i);
			continue;
		}

		count += scnprintf(&buf[count], PAGE_SIZE - count, "Queue%d\n", i);
		count += scnprintf(&buf[count], PAGE_SIZE - count, "  num_desc:%d\n",
			q->num_desc);
		switch (ppa->desc_mode) {
		case DESC_MODE_RINGBUF:
			count += scnprintf(&buf[count], PAGE_SIZE - count, "  fore/rear:%d/%d\n",
				*q->fore_ptr, *q->rear_ptr);
			count += scnprintf(&buf[count], PAGE_SIZE - count, "  fore~rear:%d\n",
				circ_get_usage(q->num_desc, *q->fore_ptr, *q->rear_ptr));
			break;
		case DESC_MODE_SKTBUF:
			count += scnprintf(&buf[count], PAGE_SIZE - count,
				"  fore/rear/done:%d/%d/%d\n",
				*q->fore_ptr, *q->rear_ptr, q->done_ptr);
			count += scnprintf(&buf[count], PAGE_SIZE - count,
				"  fore~rear:%d rear~done:%d rear~fore:%d\n",
				circ_get_usage(q->num_desc, *q->fore_ptr, *q->rear_ptr),
				circ_get_usage(q->num_desc, *q->rear_ptr, q->done_ptr),
				circ_get_usage(q->num_desc, *q->rear_ptr, *q->fore_ptr));
#if IS_ENABLED(CONFIG_LINK_DEVICE_PCIE_IOMMU)
			count += scnprintf(&buf[count], PAGE_SIZE - count,
				"  iommu_mapped cnt:%u size:0x%llX\n",
				q->ioc.mapped_cnt, q->ioc.mapped_size);
#endif
			break;
		default:
			break;
		}

		count += scnprintf(&buf[count], PAGE_SIZE - count, "  pass:%lld lro:%lld\n",
			q->stat.pass_cnt, q->stat.lro_cnt);
		count += scnprintf(&buf[count], PAGE_SIZE - count,
			"  fail:len%lld chid%lld addr%lld nomem%lld bmnomem%lld csum%lld itg%lld\n",
			q->stat.err_len, q->stat.err_chid, q->stat.err_addr,
			q->stat.err_nomem, q->stat.err_bm_nomem, q->stat.err_csum, q->stat.err_itg);
		if (dit_check_dir_use_queue(DIT_DIR_RX, q->q_idx))
			count += scnprintf(&buf[count], PAGE_SIZE - count,
				"  fail:enqueue_dit%lld\n",
				q->stat.err_enqueue_dit);
	}

	return count;
}

static DEVICE_ATTR_RO(region);
static DEVICE_ATTR_RO(status);
static DEVICE_ATTR_RW(perftest);
static DEVICE_ATTR_RW(pktgen_gro);

static struct attribute *pktproc_attrs[] = {
	&dev_attr_region.attr,
	&dev_attr_status.attr,
	&dev_attr_perftest.attr,
	&dev_attr_pktgen_gro.attr,
	NULL,
};

static const struct attribute_group pktproc_group = {
	.attrs = pktproc_attrs,
	.name = "pktproc",
};

/*
 * Initialize PktProc
 */
int pktproc_init(struct pktproc_adaptor *ppa)
{
	int i;
	int ret = 0;
	struct mem_link_device *mld;

	if (!ppa) {
		mif_err("ppa is null\n");
		return -EPERM;
	}

	if (!pktproc_check_support(ppa))
		return 0;

	mld = container_of(ppa, struct mem_link_device, pktproc);

	mif_info("version:%d cp_base:0x%08llx desc_mode:%d num_queue:%d\n",
		ppa->version, ppa->cp_base, ppa->desc_mode, ppa->num_queue);
	mif_info("interrupt:%d iocc:%d max_packet_size:%d\n",
		ppa->use_exclusive_irq, ppa->use_hw_iocc, ppa->max_packet_size);

	for (i = 0; i < ppa->num_queue; i++) {
		struct pktproc_queue *q = ppa->q[i];
#if IS_ENABLED(CONFIG_CP_PKTPROC_LRO)
		int j;
#endif

		mif_info("Q%d\n", i);

		napi_synchronize(&q->napi);

		switch (ppa->desc_mode) {
		case DESC_MODE_SKTBUF:
#if IS_ENABLED(CONFIG_LINK_DEVICE_PCIE_IOMMU)
			cpif_pcie_iommu_reset(q);
#endif
			if (q->manager && !(q->manager->data_pool->page_alloc_complete))
				cpif_page_pool_continue(NETRX_POOL_PAGE_SIZE, q->manager->data_pool);

			if (pktproc_check_active(q->ppa, q->q_idx))
				q->clear_data_addr(q);
			if (q->manager)
				mif_info("num packets:%llu frag size:%llu\n",
					q->manager->num_packet,
					q->manager->frag_size);
			break;
		default:
			break;
		}

#if IS_ENABLED(CONFIG_CP_PKTPROC_LRO)
		for (j = 0; j < MAX_NUM_LRO_STREAM; j++) {
			q->lro_stream[j].skb = NULL;
			q->lro_stream[j].last = NULL;
			q->lro_stream[j].empty = true;
			q->lro_stream[j].bypass_lro = false;

		}
#endif
		*q->fore_ptr = 0;
		*q->rear_ptr = 0;
		q->done_ptr = 0;

		if (mld->pktproc_use_36bit_addr) {
			q->q_info_ptr->cp_desc_pbase = q->cp_desc_pbase >> 4;
			q->q_info_ptr->cp_buff_pbase = q->cp_buff_pbase >> 4;
		} else {
			q->q_info_ptr->cp_desc_pbase = q->cp_desc_pbase;
			q->q_info_ptr->cp_buff_pbase = q->cp_buff_pbase;
		}

		q->q_info_ptr->num_desc = q->num_desc;

		memset(&q->stat, 0, sizeof(struct pktproc_statistics));

		switch (ppa->desc_mode) {
		case DESC_MODE_SKTBUF:
#if IS_ENABLED(CONFIG_LINK_DEVICE_PCIE_IOMMU)
			ret = cpif_pcie_iommu_init(q);
			if (ret) {
				mif_err("cpif_pcie_iommu_init() error %d Q%d\n", ret, q->q_idx);
				continue;
			}
#endif
			ret = q->alloc_rx_buf(q);
			if (ret) {
				mif_err("alloc_rx_buf() error %d Q%d\n", ret, q->q_idx);
				continue;
			}
			break;
		default:
			break;
		}

		mif_info("num_desc:0x%08x cp_desc_pbase:0x%08x desc_size:0x%08x\n",
				q->q_info_ptr->num_desc, q->q_info_ptr->cp_desc_pbase,
				q->desc_size);
		mif_info("cp_buff_pbase:0x%08llx q_buff_size:0x%08x\n",
				q->cp_buff_pbase, q->q_buff_size);
		mif_info("fore:%d rear:%d done:%d\n",
				*q->fore_ptr, *q->rear_ptr, q->done_ptr);

		atomic_set(&q->active, 1);
	}

	return 0;
}

/*
 * Create PktProc
 */
static int pktproc_create_buffer_manager(struct pktproc_queue *q, u64 ap_desc_pbase)
{
	struct pktproc_adaptor *ppa;
	unsigned int desc_total_size = 0;
	struct cpif_addr_pair desc_addr_pair;
	u64 frag_size = 0; /* size of fragmenting a page */

	if (!q) {
		mif_err("q is null\n");
		return -EINVAL;
	}

	desc_total_size = q->num_desc * sizeof(struct pktproc_desc_sktbuf);
	ppa = q->ppa;
	if (!ppa) {
		mif_err("ppa is null\n");
		return -EINVAL;
	}

	if (!ppa->use_netrx_mng) {
		mif_err("use_netrx_mng is not set\n");
		return -EINVAL;
	}

	if (q->manager != NULL) {
		mif_info("buffer manager is already initialized\n");
		return 0;
	}

	desc_addr_pair.cp_addr = q->cp_desc_pbase;
	desc_addr_pair.ap_addr = phys_to_virt(ap_desc_pbase);
	frag_size = SKB_DATA_ALIGN(ppa->max_packet_size + ppa->skb_padding_size)
				+ SKB_DATA_ALIGN(sizeof(struct skb_shared_info));
	mif_info("about to init netrx mng: cp_addr: 0x%llX ap_addr: %pK frag_size: %llu\n",
			q->cp_desc_pbase, q->desc_sktbuf, frag_size);
	mif_info("desc_total_size:%d cp_buff_pbase: 0x%llX num_desc: %d\n",
			desc_total_size, q->cp_buff_pbase, q->num_desc);
	q->manager = cpif_create_netrx_mng(&desc_addr_pair, desc_total_size,
					q->cp_buff_pbase, frag_size,
					q->num_desc);
	if (!q->manager) {
		mif_err("cpif_create_netrx_mng() error\n");
		return -ENOMEM;
	}

	return 0;
}

static void pktproc_adjust_size(struct pktproc_adaptor *ppa)
{
#if IS_ENABLED(CONFIG_LINK_DEVICE_PCIE_IOMMU)
	ppa->skb_padding_size = SKB_FRONT_PADDING;
#else
	if (ppa->use_netrx_mng)
		ppa->skb_padding_size = SKB_FRONT_PADDING;
	else
		ppa->skb_padding_size = 0;
#endif

	ppa->true_packet_size = ppa->max_packet_size;
#if IS_ENABLED(CONFIG_LINK_DEVICE_PCIE_IOMMU)
	ppa->true_packet_size += ppa->skb_padding_size;
	ppa->true_packet_size += SKB_DATA_ALIGN(sizeof(struct skb_shared_info));

	mif_info("adjusted iommu required:%u true_packet_size:%lu\n",
		 ppa->true_packet_size, roundup_pow_of_two(ppa->true_packet_size));
	ppa->true_packet_size = roundup_pow_of_two(ppa->true_packet_size);
	ppa->space_margin = PAGE_FRAG_CACHE_MAX_SIZE / ppa->true_packet_size;
#endif
}

static int pktproc_get_info(struct pktproc_adaptor *ppa, struct device_node *np)
{
	mif_dt_read_u64(np, "pktproc_cp_base", ppa->cp_base);
	mif_dt_read_u32(np, "pktproc_dl_version", ppa->version);

	switch (ppa->version) {
	case PKTPROC_V1:
		ppa->desc_mode = DESC_MODE_RINGBUF;
		ppa->num_queue = 1;
		ppa->use_exclusive_irq = 0;
		break;
	case PKTPROC_V2:
		mif_dt_read_u32(np, "pktproc_dl_desc_mode", ppa->desc_mode);
		mif_dt_read_u32(np, "pktproc_dl_num_queue", ppa->num_queue);
#if IS_ENABLED(CONFIG_EXYNOS_CPIF_IOMMU) || IS_ENABLED(CONFIG_EXYNOS_CPIF_IOMMU_V9)
		mif_dt_read_u32(np, "pktproc_dl_use_netrx_mng", ppa->use_netrx_mng);
		mif_dt_read_u32(np, "pktproc_dl_netrx_capacity", ppa->netrx_capacity);
#else
		ppa->use_netrx_mng = 0;
		ppa->netrx_capacity = 0;
#endif
		mif_dt_read_u32(np, "pktproc_dl_use_exclusive_irq", ppa->use_exclusive_irq);
#if IS_ENABLED(CONFIG_MCU_IPC)
		if (ppa->use_exclusive_irq) {
			int ret;

			ret = of_property_read_u32_array(np, "pktproc_dl_exclusive_irq_idx",
							ppa->exclusive_irq_idx, ppa->num_queue);
			if (ret) {
				mif_err("pktproc_dl_exclusive_irq_idx error:%d\n", ret);
				return ret;
			}
		}
#endif
		break;
	default:
		mif_err("Unsupported version:%d\n", ppa->version);
		return -EINVAL;
	}

	mif_info("version:%d cp_base:0x%08llx mode:%d num_queue:%d\n",
		ppa->version, ppa->cp_base, ppa->desc_mode, ppa->num_queue);
	mif_info("use_netrx_mng:%d netrx_capacity:%d exclusive_irq:%d\n",
		ppa->use_netrx_mng, ppa->netrx_capacity, ppa->use_exclusive_irq);

	mif_dt_read_u32(np, "pktproc_dl_use_hw_iocc", ppa->use_hw_iocc);
	mif_dt_read_u32(np, "pktproc_dl_max_packet_size", ppa->max_packet_size);
	mif_dt_read_u32(np, "pktproc_dl_use_dedicated_baaw", ppa->use_dedicated_baaw);
	mif_info("iocc:%d max_packet_size:%d baaw:%d\n",
		ppa->use_hw_iocc, ppa->max_packet_size, ppa->use_dedicated_baaw);

	mif_dt_read_u32(np, "pktproc_dl_info_rgn_offset", ppa->info_rgn_offset);
	mif_dt_read_u32(np, "pktproc_dl_info_rgn_size", ppa->info_rgn_size);
	mif_dt_read_u32(np, "pktproc_dl_desc_rgn_offset", ppa->desc_rgn_offset);
	mif_dt_read_u32(np, "pktproc_dl_desc_rgn_size", ppa->desc_rgn_size);
	mif_dt_read_u32(np, "pktproc_dl_buff_rgn_offset", ppa->buff_rgn_offset);
	mif_dt_read_u32(np, "pktproc_dl_buff_rgn_size", ppa->buff_rgn_size);
	mif_info("info_rgn 0x%08x 0x%08x desc_rgn 0x%08x 0x%08x %u buff_rgn 0x%08x 0x%08x\n",
		ppa->info_rgn_offset, ppa->info_rgn_size,
		ppa->desc_rgn_offset, ppa->desc_rgn_size,
		ppa->desc_num_ratio_percent,
		ppa->buff_rgn_offset, ppa->buff_rgn_size);

	mif_dt_read_u32(np, "pktproc_dl_info_rgn_cached", ppa->info_rgn_cached);
	mif_dt_read_u32(np, "pktproc_dl_desc_rgn_cached", ppa->desc_rgn_cached);
	mif_dt_read_u32(np, "pktproc_dl_buff_rgn_cached", ppa->buff_rgn_cached);
	mif_info("cached:%d/%d/%d\n", ppa->info_rgn_cached, ppa->desc_rgn_cached,
			ppa->buff_rgn_cached);
	if (ppa->use_netrx_mng && !ppa->buff_rgn_cached) {
		mif_err("Buffer manager requires cached buff region\n");
		return -EINVAL;
	}
#if IS_ENABLED(CONFIG_LINK_DEVICE_PCIE_IOMMU)
	if (ppa->use_netrx_mng || !ppa->buff_rgn_cached || ppa->desc_mode != DESC_MODE_SKTBUF) {
		mif_err("not compatible with pcie iommu\n");
		return -EINVAL;
	}
#endif

	pktproc_adjust_size(ppa);

	return 0;
}

int pktproc_create(struct platform_device *pdev, struct mem_link_device *mld,
					unsigned long memaddr, u32 memsize)
{
	struct device_node *np = pdev->dev.of_node;
	struct pktproc_adaptor *ppa = &mld->pktproc;
	u32 buff_size_by_q, accum_buff_size;
	u32 alloc_size;
	int i;
	int ret = 0;

	if (!np) {
		mif_err("of_node is null\n");
		return -EINVAL;
	}
	if (!ppa) {
		mif_err("ppa is null\n");
		return -EINVAL;
	}

	ppa->dev = &pdev->dev;

	mif_dt_read_u32_noerr(np, "pktproc_dl_support", ppa->support);
	if (!ppa->support) {
		mif_info("pktproc_support is 0. Just return\n");
		return 0;
	}

	/* Get info */
	ret = pktproc_get_info(ppa, np);
	if (ret != 0) {
		mif_err("pktproc_get_dt() error %d\n", ret);
		return ret;
	}

	if (!ppa->use_hw_iocc && ppa->info_rgn_cached) {
		mif_err("cannot support sw iocc based caching on info region\n");
		return -EINVAL;
	}

	if (!ppa->use_hw_iocc && ppa->desc_rgn_cached) {
		mif_err("cannot support sw iocc based caching on desc region\n");
		return -EINVAL;
	}

	/* Get base addr */
	mif_info("memaddr:0x%lx memsize:0x%08x\n", memaddr, memsize);

	if (ppa->info_rgn_cached)
		ppa->info_vbase = phys_to_virt(memaddr + ppa->info_rgn_offset);
	else {
		ppa->info_vbase = cp_shmem_get_nc_region(memaddr + ppa->info_rgn_offset,
				ppa->info_rgn_size);
		if (!ppa->info_vbase) {
			mif_err("ppa->info_base error\n");
			return -ENOMEM;
		}
	}

	if (ppa->desc_rgn_cached)
		ppa->desc_vbase = phys_to_virt(memaddr + ppa->desc_rgn_offset);
	else {
		ppa->desc_vbase = cp_shmem_get_nc_region(memaddr + ppa->desc_rgn_offset,
				ppa->desc_rgn_size);
		if (!ppa->desc_vbase) {
			mif_err("ppa->desc_base error\n");
			return -ENOMEM;
		}
	}
	memset(ppa->info_vbase, 0, ppa->info_rgn_size);
	memset(ppa->desc_vbase, 0, ppa->desc_rgn_size);
	mif_info("info + desc size:0x%08x\n", ppa->info_rgn_size + ppa->desc_rgn_size);

	if (!ppa->use_netrx_mng) {
		buff_size_by_q = ppa->buff_rgn_size / ppa->num_queue;
#if IS_ENABLED(CONFIG_LINK_DEVICE_PCIE_IOMMU)
		mif_info("Rounded down queue size from 0x%08x to 0x%08x\n",
			 buff_size_by_q, rounddown(buff_size_by_q, SZ_4K));
		buff_size_by_q = rounddown(buff_size_by_q, SZ_4K);
#endif
		ppa->buff_pbase = memaddr + ppa->buff_rgn_offset;
		if (ppa->buff_rgn_cached) {
			ppa->buff_vbase = phys_to_virt(ppa->buff_pbase);
#if IS_ENABLED(CONFIG_LINK_DEVICE_PCIE_IOMMU)
			mif_info("release iommu buffer region offset:0x%08x\n",
				 ppa->buff_rgn_offset);
			cp_shmem_release_rmem(SHMEM_PKTPROC, ppa->buff_rgn_offset);
#endif
		} else {
			ppa->buff_vbase = cp_shmem_get_nc_region(ppa->buff_pbase,
								 ppa->buff_rgn_size);
		}
		mif_info("Total buff buffer size:0x%08x Queue:%d Size by queue:0x%08x\n",
			 ppa->buff_rgn_size, ppa->num_queue, buff_size_by_q);
	} else
		accum_buff_size = 0;

	/* Create queue */
	for (i = 0; i < ppa->num_queue; i++) {
		struct pktproc_queue *q;

		mif_info("Create queue %d\n", i);

		ppa->q[i] = kzalloc(sizeof(struct pktproc_queue), GFP_ATOMIC);
		if (ppa->q[i] == NULL) {
			mif_err_limited("kzalloc() error %d\n", i);
			ret = -ENOMEM;
			goto create_error;
		}
		q = ppa->q[i];
		q->ppa = ppa;

		atomic_set(&q->active, 0);
		atomic_set(&q->stop_napi_poll, 0);

		/* Info region */
		switch (ppa->version) {
		case PKTPROC_V1:
			q->info_v1 = (struct pktproc_info_v1 *)ppa->info_vbase;
			q->q_info_ptr = &q->info_v1->q_info;
			break;
		case PKTPROC_V2:
			q->info_v2 = (struct pktproc_info_v2 *)ppa->info_vbase;
			q->info_v2->num_queues = ppa->num_queue;
			q->info_v2->desc_mode = ppa->desc_mode;
			q->info_v2->irq_mode = ppa->use_exclusive_irq;
			q->info_v2->max_packet_size = ppa->max_packet_size;
			q->q_info_ptr = &q->info_v2->q_info[i];
			break;
		default:
			mif_err("Unsupported version:%d\n", ppa->version);
			ret = -EINVAL;
			goto create_error;
		}

		/* Descriptor, data buffer region */
		switch (ppa->desc_mode) {
		case DESC_MODE_RINGBUF:
			q->q_buff_pbase = ppa->buff_pbase + (i * buff_size_by_q);
			q->q_buff_vbase = ppa->buff_vbase + (i * buff_size_by_q);
			q->cp_buff_pbase = ppa->cp_base + ppa->buff_rgn_offset +
				(i * buff_size_by_q);
			if (mld->pktproc_use_36bit_addr)
				q->q_info_ptr->cp_buff_pbase = q->cp_buff_pbase >> 4;
			else
				q->q_info_ptr->cp_buff_pbase = q->cp_buff_pbase;
			q->q_buff_size = buff_size_by_q;
			if (ppa->buff_rgn_cached && !ppa->use_hw_iocc)
				dma_sync_single_for_device(ppa->dev,
						q->q_buff_pbase, q->q_buff_size, DMA_FROM_DEVICE);

			q->num_desc = buff_size_by_q / ppa->true_packet_size;
			q->q_info_ptr->num_desc = q->num_desc;

			q->desc_ringbuf = ppa->desc_vbase +
					(i * sizeof(struct pktproc_desc_ringbuf) *
					 q->num_desc);
			q->cp_desc_pbase = ppa->cp_base + ppa->desc_rgn_offset +
					(i * sizeof(struct pktproc_desc_ringbuf) *
					 q->num_desc);
			if (mld->pktproc_use_36bit_addr)
				q->q_info_ptr->cp_desc_pbase = q->cp_desc_pbase >> 4;
			else
				q->q_info_ptr->cp_desc_pbase = q->cp_desc_pbase;
			q->desc_size = sizeof(struct pktproc_desc_ringbuf) * q->num_desc;

			q->get_packet = pktproc_get_pkt_from_ringbuf_mode;
			q->irq_handler = pktproc_irq_handler;
			break;
		case DESC_MODE_SKTBUF:
			if (ppa->use_netrx_mng) {
				q->num_desc = ppa->netrx_capacity;
				q->alloc_rx_buf = pktproc_fill_data_addr;
				q->clear_data_addr = pktproc_clear_data_addr;
				q->cp_buff_pbase = ppa->cp_base + ppa->buff_rgn_offset
							+ accum_buff_size;

			} else {
				q->q_buff_pbase = ppa->buff_pbase + (i * buff_size_by_q);
				q->q_buff_vbase = ppa->buff_vbase + (i * buff_size_by_q);
				q->cp_buff_pbase = ppa->cp_base + ppa->buff_rgn_offset +
					(i * buff_size_by_q);
				q->q_buff_size = buff_size_by_q;
				q->num_desc = buff_size_by_q / ppa->true_packet_size;
				q->alloc_rx_buf = pktproc_fill_data_addr_without_bm;
				q->clear_data_addr = pktproc_clear_data_addr_without_bm;
			}

			if (mld->pktproc_use_36bit_addr)
				q->q_info_ptr->cp_buff_pbase = q->cp_buff_pbase >> 4;
			else
				q->q_info_ptr->cp_buff_pbase = q->cp_buff_pbase;

			q->q_info_ptr->num_desc = q->num_desc;

			q->desc_sktbuf = ppa->desc_vbase +
					(i * sizeof(struct pktproc_desc_sktbuf) *
					 q->num_desc);
			q->cp_desc_pbase = ppa->cp_base + ppa->desc_rgn_offset +
					(i * sizeof(struct pktproc_desc_sktbuf) *
					 q->num_desc);
			if (mld->pktproc_use_36bit_addr)
				q->q_info_ptr->cp_desc_pbase = q->cp_desc_pbase >> 4;
			else
				q->q_info_ptr->cp_desc_pbase = q->cp_desc_pbase;

			mif_info("cp_desc_pbase - 36bit addr: 0x%08llx, 32bit addr: 0x%08x\n",
				q->cp_desc_pbase, q->q_info_ptr->cp_desc_pbase);

			q->desc_size = sizeof(struct pktproc_desc_sktbuf) * q->num_desc;

			alloc_size = sizeof(dma_addr_t) * q->num_desc;
			q->dma_addr = kzalloc(alloc_size, GFP_KERNEL);
			if (!q->dma_addr) {
				mif_err("kzalloc() dma_addr failed\n");
				ret = -ENOMEM;
				goto create_error;
			}

			if (ppa->use_netrx_mng) {
				/* to make phys_to_virt macro operable */
				u64 ap_desc_pbase = memaddr + ppa->desc_rgn_offset +
						(i * sizeof(struct pktproc_desc_sktbuf)
						 * q->num_desc);
				mif_info("create buffer manager\n");
				ret = pktproc_create_buffer_manager(q, ap_desc_pbase);
				if (ret < 0) {
					mif_err("failed to create netrx mng:%d\n", ret);
					goto create_error;
				}
				accum_buff_size += q->manager->total_buf_size;
			}

			q->get_packet = pktproc_get_pkt_from_sktbuf_mode;
			q->irq_handler = pktproc_irq_handler;
			q->update_fore_ptr = pktproc_update_fore_ptr;
			break;
		default:
			mif_err("Unsupported version:%d\n", ppa->version);
			ret = -EINVAL;
			goto create_error;
		}

		if ((!q->manager) &&
				(q->cp_desc_pbase + q->desc_size) > q->cp_buff_pbase) {
			mif_err("Descriptor overflow:0x%08llx 0x%08x 0x%08llx\n",
				q->cp_desc_pbase, q->desc_size, q->cp_buff_pbase);
			ret = -EINVAL;
			goto create_error;
		}

		spin_lock_init(&q->lock);

		q->clean_rx_ring = pktproc_clean_rx_ring;

		q->q_idx = i;
		q->mld = mld;

		/* NAPI */
		if (ppa->use_exclusive_irq) {
			init_dummy_netdev(&q->netdev);
			netif_napi_add(&q->netdev, &q->napi, pktproc_poll);
			napi_enable(&q->napi);
			q->napi_ptr = &q->napi;
		} else {
			q->napi_ptr = &q->mld->mld_napi;
		}

		/* IRQ handler */
		if (ppa->use_exclusive_irq) {
#if IS_ENABLED(CONFIG_MCU_IPC)
			q->irq_idx = ppa->exclusive_irq_idx[q->q_idx];
			ret = cp_mbox_register_handler(q->irq_idx,
							mld->irq_cp2ap_msg, q->irq_handler, q);
			if (ret) {
				mif_err("cp_mbox_register_handler() error:%d\n", ret);
				goto create_error;
			}
#endif
#if IS_ENABLED(CONFIG_LINK_DEVICE_PCIE)
			/* Set by request_pcie_msi_int() */
#endif
		}

		q->q_info_ptr->fore_ptr = 0;
		q->q_info_ptr->rear_ptr = 0;

		q->fore_ptr = &q->q_info_ptr->fore_ptr;
		q->rear_ptr = &q->q_info_ptr->rear_ptr;
		q->done_ptr = *q->rear_ptr;

		mif_info("num_desc:%d cp_desc_pbase:0x%08llx desc_size:0x%08x\n",
			q->num_desc, q->cp_desc_pbase, q->desc_size);
		if (!q->manager)
			mif_info("cp_buff_pbase:0x%08llx buff_size:0x%08x\n",
				q->cp_buff_pbase, q->q_buff_size);

#if IS_ENABLED(CONFIG_EXYNOS_DIT)
		if (q->q_idx == 0) {
			ret = dit_set_pktproc_queue_num(DIT_DIR_RX, q->q_idx);
			if (ret)
				mif_err("dit_set_buf_size() error:%d\n", ret);

			ret = dit_set_buf_size(DIT_DIR_RX, ppa->max_packet_size);
			if (ret)
				mif_err("dit_set_buf_size() error:%d\n", ret);

			ret = dit_set_desc_ring_len(DIT_DIR_RX, q->num_desc - 1);
			if (ret)
				mif_err("dit_set_desc_ring_len() error:%d\n", ret);
		}
#endif
	}

	/* Debug */
	ret = sysfs_create_group(&pdev->dev.kobj, &pktproc_group);
	if (ret != 0) {
		mif_err("sysfs_create_group() error %d\n", ret);
		goto create_error;
	}

	return 0;

create_error:
	for (i = 0; i < ppa->num_queue; i++) {
		if (!ppa->q[i])
			continue;

		if (ppa->q[i]->manager)
			cpif_exit_netrx_mng(ppa->q[i]->manager);

		kfree(ppa->q[i]->dma_addr);
		kfree(ppa->q[i]);
	}

	if (!ppa->info_rgn_cached && ppa->info_vbase)
		vunmap(ppa->info_vbase);
	if (!ppa->desc_rgn_cached && ppa->desc_vbase)
		vunmap(ppa->desc_vbase);
	if (!ppa->buff_rgn_cached && ppa->buff_vbase)
		vunmap(ppa->buff_vbase);

	return ret;
}
