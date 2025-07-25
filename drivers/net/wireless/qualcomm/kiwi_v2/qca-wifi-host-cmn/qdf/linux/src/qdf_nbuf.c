/*
 * Copyright (c) 2014-2021 The Linux Foundation. All rights reserved.
 * Copyright (c) 2021-2024 Qualcomm Innovation Center, Inc. All rights reserved.
 *
 * Permission to use, copy, modify, and/or distribute this software for
 * any purpose with or without fee is hereby granted, provided that the
 * above copyright notice and this permission notice appear in all
 * copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL
 * WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE
 * AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL
 * DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR
 * PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER
 * TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 * PERFORMANCE OF THIS SOFTWARE.
 */

/**
 * DOC: qdf_nbuf.c
 * QCA driver framework(QDF) network buffer management APIs
 */
#include <linux/hashtable.h>
#include <linux/kernel.h>
#include <linux/version.h>
#include <linux/skbuff.h>
#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/inetdevice.h>
#include <qdf_atomic.h>
#include <qdf_debugfs.h>
#include <qdf_lock.h>
#include <qdf_mem.h>
#include <qdf_module.h>
#include <qdf_nbuf.h>
#include <qdf_status.h>
#include "qdf_str.h"
#include <qdf_trace.h>
#include "qdf_tracker.h"
#include <qdf_types.h>
#include <net/ieee80211_radiotap.h>
#include <pld_common.h>
#include <qdf_crypto.h>
#include <linux/igmp.h>
#include <net/mld.h>

#if defined(FEATURE_TSO)
#include <net/ipv6.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/if_vlan.h>
#include <linux/ip.h>
#endif /* FEATURE_TSO */

#ifdef IPA_OFFLOAD
#include <i_qdf_ipa_wdi3.h>
#endif /* IPA_OFFLOAD */
#include "qdf_ssr_driver_dump.h"

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 13, 0)

#define qdf_nbuf_users_inc atomic_inc
#define qdf_nbuf_users_dec atomic_dec
#define qdf_nbuf_users_set atomic_set
#define qdf_nbuf_users_read atomic_read
#else
#define qdf_nbuf_users_inc refcount_inc
#define qdf_nbuf_users_dec refcount_dec
#define qdf_nbuf_users_set refcount_set
#define qdf_nbuf_users_read refcount_read
#endif /* KERNEL_VERSION(4, 13, 0) */

#define IEEE80211_RADIOTAP_VHT_BW_20	0
#define IEEE80211_RADIOTAP_VHT_BW_40	1
#define IEEE80211_RADIOTAP_VHT_BW_80	2
#define IEEE80211_RADIOTAP_VHT_BW_160	3

#define RADIOTAP_VHT_BW_20	0
#define RADIOTAP_VHT_BW_40	1
#define RADIOTAP_VHT_BW_80	4
#define RADIOTAP_VHT_BW_160	11

/* tx status */
#define RADIOTAP_TX_STATUS_FAIL		1
#define RADIOTAP_TX_STATUS_NOACK	2

/* channel number to freq conversion */
#define CHANNEL_NUM_14 14
#define CHANNEL_NUM_15 15
#define CHANNEL_NUM_27 27
#define CHANNEL_NUM_35 35
#define CHANNEL_NUM_182 182
#define CHANNEL_NUM_197 197
#define CHANNEL_FREQ_2484 2484
#define CHANNEL_FREQ_2407 2407
#define CHANNEL_FREQ_2512 2512
#define CHANNEL_FREQ_5000 5000
#define CHANNEL_FREQ_4000 4000
#define CHANNEL_FREQ_5150 5150
#define FREQ_MULTIPLIER_CONST_5MHZ 5
#define FREQ_MULTIPLIER_CONST_20MHZ 20
#define RADIOTAP_5G_SPECTRUM_CHANNEL 0x0100
#define RADIOTAP_2G_SPECTRUM_CHANNEL 0x0080
#define RADIOTAP_CCK_CHANNEL 0x0020
#define RADIOTAP_OFDM_CHANNEL 0x0040

#ifdef FEATURE_NBUFF_REPLENISH_TIMER
#include <qdf_mc_timer.h>

struct qdf_track_timer {
	qdf_mc_timer_t track_timer;
	qdf_atomic_t alloc_fail_cnt;
};

static struct qdf_track_timer alloc_track_timer;

#define QDF_NBUF_ALLOC_EXPIRE_TIMER_MS  5000
#define QDF_NBUF_ALLOC_EXPIRE_CNT_THRESHOLD  50
#endif

#ifdef NBUF_MEMORY_DEBUG
/* SMMU crash indication*/
static qdf_atomic_t smmu_crashed;
/* Number of nbuf not added to history*/
unsigned long g_histroy_add_drop;
#endif

/* Packet Counter */
static uint32_t nbuf_tx_mgmt[QDF_NBUF_TX_PKT_STATE_MAX];
static uint32_t nbuf_tx_data[QDF_NBUF_TX_PKT_STATE_MAX];
#ifdef QDF_NBUF_GLOBAL_COUNT
#define NBUF_DEBUGFS_NAME      "nbuf_counters"
static qdf_atomic_t nbuf_count;
#endif

#if defined(NBUF_MEMORY_DEBUG) || defined(QDF_NBUF_GLOBAL_COUNT)
static bool is_initial_mem_debug_disabled;
#endif

/**
 *  __qdf_nbuf_get_ip_offset() - Get IPV4/V6 header offset
 * @data: Pointer to network data buffer
 *
 * Get the IP header offset in case of 8021Q and 8021AD
 * tag is present in L2 header.
 *
 * Return: IP header offset
 */
static inline uint8_t __qdf_nbuf_get_ip_offset(uint8_t *data)
{
	uint16_t ether_type;

	ether_type = *(uint16_t *)(data +
				   QDF_NBUF_TRAC_ETH_TYPE_OFFSET);

	if (unlikely(ether_type == QDF_SWAP_U16(QDF_ETH_TYPE_8021Q)))
		return QDF_NBUF_TRAC_VLAN_IP_OFFSET;
	else if (unlikely(ether_type == QDF_SWAP_U16(QDF_ETH_TYPE_8021AD)))
		return QDF_NBUF_TRAC_DOUBLE_VLAN_IP_OFFSET;

	return QDF_NBUF_TRAC_IP_OFFSET;
}

/**
 *  __qdf_nbuf_get_ether_type() - Get the ether type
 * @data: Pointer to network data buffer
 *
 * Get the ether type in case of 8021Q and 8021AD tag
 * is present in L2 header, e.g for the returned ether type
 * value, if IPV4 data ether type 0x0800, return 0x0008.
 *
 * Return ether type.
 */
static inline uint16_t __qdf_nbuf_get_ether_type(uint8_t *data)
{
	uint16_t ether_type;

	ether_type = *(uint16_t *)(data +
				   QDF_NBUF_TRAC_ETH_TYPE_OFFSET);

	if (unlikely(ether_type == QDF_SWAP_U16(QDF_ETH_TYPE_8021Q)))
		ether_type = *(uint16_t *)(data +
				QDF_NBUF_TRAC_VLAN_ETH_TYPE_OFFSET);
	else if (unlikely(ether_type == QDF_SWAP_U16(QDF_ETH_TYPE_8021AD)))
		ether_type = *(uint16_t *)(data +
				QDF_NBUF_TRAC_DOUBLE_VLAN_ETH_TYPE_OFFSET);

	return ether_type;
}

void qdf_nbuf_tx_desc_count_display(void)
{
	qdf_debug("Current Snapshot of the Driver:");
	qdf_debug("Data Packets:");
	qdf_debug("HDD %d TXRX_Q %d TXRX %d HTT %d",
		  nbuf_tx_data[QDF_NBUF_TX_PKT_HDD] -
		  (nbuf_tx_data[QDF_NBUF_TX_PKT_TXRX] +
		  nbuf_tx_data[QDF_NBUF_TX_PKT_TXRX_ENQUEUE] -
		  nbuf_tx_data[QDF_NBUF_TX_PKT_TXRX_DEQUEUE]),
		  nbuf_tx_data[QDF_NBUF_TX_PKT_TXRX_ENQUEUE] -
		  nbuf_tx_data[QDF_NBUF_TX_PKT_TXRX_DEQUEUE],
		  nbuf_tx_data[QDF_NBUF_TX_PKT_TXRX] -
		  nbuf_tx_data[QDF_NBUF_TX_PKT_HTT],
		  nbuf_tx_data[QDF_NBUF_TX_PKT_HTT]  -
		  nbuf_tx_data[QDF_NBUF_TX_PKT_HTC]);
	qdf_debug(" HTC %d  HIF %d CE %d TX_COMP %d",
		  nbuf_tx_data[QDF_NBUF_TX_PKT_HTC] -
		  nbuf_tx_data[QDF_NBUF_TX_PKT_HIF],
		  nbuf_tx_data[QDF_NBUF_TX_PKT_HIF] -
		  nbuf_tx_data[QDF_NBUF_TX_PKT_CE],
		  nbuf_tx_data[QDF_NBUF_TX_PKT_CE] -
		  nbuf_tx_data[QDF_NBUF_TX_PKT_FREE],
		  nbuf_tx_data[QDF_NBUF_TX_PKT_FREE]);
	qdf_debug("Mgmt Packets:");
	qdf_debug("TXRX_Q %d TXRX %d HTT %d HTC %d HIF %d CE %d TX_COMP %d",
		  nbuf_tx_mgmt[QDF_NBUF_TX_PKT_TXRX_ENQUEUE] -
		  nbuf_tx_mgmt[QDF_NBUF_TX_PKT_TXRX_DEQUEUE],
		  nbuf_tx_mgmt[QDF_NBUF_TX_PKT_TXRX] -
		  nbuf_tx_mgmt[QDF_NBUF_TX_PKT_HTT],
		  nbuf_tx_mgmt[QDF_NBUF_TX_PKT_HTT] -
		  nbuf_tx_mgmt[QDF_NBUF_TX_PKT_HTC],
		  nbuf_tx_mgmt[QDF_NBUF_TX_PKT_HTC] -
		  nbuf_tx_mgmt[QDF_NBUF_TX_PKT_HIF],
		  nbuf_tx_mgmt[QDF_NBUF_TX_PKT_HIF] -
		  nbuf_tx_mgmt[QDF_NBUF_TX_PKT_CE],
		  nbuf_tx_mgmt[QDF_NBUF_TX_PKT_CE] -
		  nbuf_tx_mgmt[QDF_NBUF_TX_PKT_FREE],
		  nbuf_tx_mgmt[QDF_NBUF_TX_PKT_FREE]);
}
qdf_export_symbol(qdf_nbuf_tx_desc_count_display);

/**
 * qdf_nbuf_tx_desc_count_update() - Updates the layer packet counter
 * @packet_type   : packet type either mgmt/data
 * @current_state : layer at which the packet currently present
 *
 * Return: none
 */
static inline void qdf_nbuf_tx_desc_count_update(uint8_t packet_type,
			uint8_t current_state)
{
	switch (packet_type) {
	case QDF_NBUF_TX_PKT_MGMT_TRACK:
		nbuf_tx_mgmt[current_state]++;
		break;
	case QDF_NBUF_TX_PKT_DATA_TRACK:
		nbuf_tx_data[current_state]++;
		break;
	default:
		break;
	}
}

void qdf_nbuf_tx_desc_count_clear(void)
{
	memset(nbuf_tx_mgmt, 0, sizeof(nbuf_tx_mgmt));
	memset(nbuf_tx_data, 0, sizeof(nbuf_tx_data));
}
qdf_export_symbol(qdf_nbuf_tx_desc_count_clear);

void qdf_nbuf_set_state(qdf_nbuf_t nbuf, uint8_t current_state)
{
	/*
	 * Only Mgmt, Data Packets are tracked. WMI messages
	 * such as scan commands are not tracked
	 */
	uint8_t packet_type;

	packet_type = QDF_NBUF_CB_TX_PACKET_TRACK(nbuf);

	if ((packet_type != QDF_NBUF_TX_PKT_DATA_TRACK) &&
		(packet_type != QDF_NBUF_TX_PKT_MGMT_TRACK)) {
		return;
	}
	QDF_NBUF_CB_TX_PACKET_STATE(nbuf) = current_state;
	qdf_nbuf_tx_desc_count_update(packet_type,
					current_state);
}
qdf_export_symbol(qdf_nbuf_set_state);

#ifdef FEATURE_NBUFF_REPLENISH_TIMER
/**
 * __qdf_nbuf_start_replenish_timer() - Start alloc fail replenish timer
 *
 * This function starts the alloc fail replenish timer.
 *
 * Return: void
 */
static inline void __qdf_nbuf_start_replenish_timer(void)
{
	qdf_atomic_inc(&alloc_track_timer.alloc_fail_cnt);
	if (qdf_mc_timer_get_current_state(&alloc_track_timer.track_timer) !=
	    QDF_TIMER_STATE_RUNNING)
		qdf_mc_timer_start(&alloc_track_timer.track_timer,
				   QDF_NBUF_ALLOC_EXPIRE_TIMER_MS);
}

/**
 * __qdf_nbuf_stop_replenish_timer() - Stop alloc fail replenish timer
 *
 * This function stops the alloc fail replenish timer.
 *
 * Return: void
 */
static inline void __qdf_nbuf_stop_replenish_timer(void)
{
	if (qdf_atomic_read(&alloc_track_timer.alloc_fail_cnt) == 0)
		return;

	qdf_atomic_set(&alloc_track_timer.alloc_fail_cnt, 0);
	if (qdf_mc_timer_get_current_state(&alloc_track_timer.track_timer) ==
	    QDF_TIMER_STATE_RUNNING)
		qdf_mc_timer_stop(&alloc_track_timer.track_timer);
}

/**
 * qdf_replenish_expire_handler() - Replenish expire handler
 * @arg: unused callback argument
 *
 * This function triggers when the alloc fail replenish timer expires.
 *
 * Return: void
 */
static void qdf_replenish_expire_handler(void *arg)
{
	if (qdf_atomic_read(&alloc_track_timer.alloc_fail_cnt) >
	    QDF_NBUF_ALLOC_EXPIRE_CNT_THRESHOLD) {
		qdf_print("ERROR: NBUF allocation timer expired Fail count %d",
			  qdf_atomic_read(&alloc_track_timer.alloc_fail_cnt));

		/* Error handling here */
	}
}

void __qdf_nbuf_init_replenish_timer(void)
{
	qdf_mc_timer_init(&alloc_track_timer.track_timer, QDF_TIMER_TYPE_SW,
			  qdf_replenish_expire_handler, NULL);
}

void __qdf_nbuf_deinit_replenish_timer(void)
{
	__qdf_nbuf_stop_replenish_timer();
	qdf_mc_timer_destroy(&alloc_track_timer.track_timer);
}

void qdf_nbuf_stop_replenish_timer(void)
{
	__qdf_nbuf_stop_replenish_timer();
}
#else

static inline void __qdf_nbuf_start_replenish_timer(void) {}
static inline void __qdf_nbuf_stop_replenish_timer(void) {}
void qdf_nbuf_stop_replenish_timer(void)
{
}
#endif

/* globals do not need to be initialized to NULL/0 */
qdf_nbuf_trace_update_t qdf_trace_update_cb;
qdf_nbuf_free_t nbuf_free_cb;

#ifdef QDF_NBUF_GLOBAL_COUNT

int __qdf_nbuf_count_get(void)
{
	return qdf_atomic_read(&nbuf_count);
}
qdf_export_symbol(__qdf_nbuf_count_get);

void __qdf_nbuf_count_inc(qdf_nbuf_t nbuf)
{
	int num_nbuf = 1;
	qdf_nbuf_t ext_list;

	if (qdf_likely(is_initial_mem_debug_disabled))
		return;

	ext_list = qdf_nbuf_get_ext_list(nbuf);

	/* Take care to account for frag_list */
	while (ext_list) {
		++num_nbuf;
		ext_list = qdf_nbuf_queue_next(ext_list);
	}

	qdf_atomic_add(num_nbuf, &nbuf_count);
}
qdf_export_symbol(__qdf_nbuf_count_inc);

void __qdf_nbuf_count_dec(__qdf_nbuf_t nbuf)
{
	qdf_nbuf_t ext_list;
	int num_nbuf;

	if (qdf_likely(is_initial_mem_debug_disabled))
		return;

	if (qdf_nbuf_get_users(nbuf) > 1)
		return;

	num_nbuf = 1;

	/* Take care to account for frag_list */
	ext_list = qdf_nbuf_get_ext_list(nbuf);
	while (ext_list) {
		if (qdf_nbuf_get_users(ext_list) == 1)
			++num_nbuf;
		ext_list = qdf_nbuf_queue_next(ext_list);
	}

	qdf_atomic_sub(num_nbuf, &nbuf_count);
}
qdf_export_symbol(__qdf_nbuf_count_dec);
#endif

#ifdef NBUF_FRAG_MEMORY_DEBUG
void qdf_nbuf_frag_count_inc(qdf_nbuf_t nbuf)
{
	qdf_nbuf_t ext_list;
	uint32_t num_nr_frags;
	uint32_t total_num_nr_frags;

	if (qdf_likely(is_initial_mem_debug_disabled))
		return;

	num_nr_frags = qdf_nbuf_get_nr_frags(nbuf);
	qdf_assert_always(num_nr_frags <= QDF_NBUF_MAX_FRAGS);

	total_num_nr_frags = num_nr_frags;

	/* Take into account the frags attached to frag_list */
	ext_list = qdf_nbuf_get_ext_list(nbuf);
	while (ext_list) {
		num_nr_frags = qdf_nbuf_get_nr_frags(ext_list);
		qdf_assert_always(num_nr_frags <= QDF_NBUF_MAX_FRAGS);
		total_num_nr_frags += num_nr_frags;
		ext_list = qdf_nbuf_queue_next(ext_list);
	}

	qdf_frag_count_inc(total_num_nr_frags);
}

qdf_export_symbol(qdf_nbuf_frag_count_inc);

void  qdf_nbuf_frag_count_dec(qdf_nbuf_t nbuf)
{
	qdf_nbuf_t ext_list;
	uint32_t num_nr_frags;
	uint32_t total_num_nr_frags;

	if (qdf_likely(is_initial_mem_debug_disabled))
		return;

	if (qdf_nbuf_get_users(nbuf) > 1)
		return;

	num_nr_frags = qdf_nbuf_get_nr_frags(nbuf);
	qdf_assert_always(num_nr_frags <= QDF_NBUF_MAX_FRAGS);

	total_num_nr_frags = num_nr_frags;

	/* Take into account the frags attached to frag_list */
	ext_list = qdf_nbuf_get_ext_list(nbuf);
	while (ext_list) {
		if (qdf_nbuf_get_users(ext_list) == 1) {
			num_nr_frags = qdf_nbuf_get_nr_frags(ext_list);
			qdf_assert_always(num_nr_frags <= QDF_NBUF_MAX_FRAGS);
			total_num_nr_frags += num_nr_frags;
		}
		ext_list = qdf_nbuf_queue_next(ext_list);
	}

	qdf_frag_count_dec(total_num_nr_frags);
}

qdf_export_symbol(qdf_nbuf_frag_count_dec);

#endif

static inline void
qdf_nbuf_set_defaults(struct sk_buff *skb, int align, int reserve)
{
	unsigned long offset;

	memset(skb->cb, 0x0, sizeof(skb->cb));
	skb->dev = NULL;

	/*
	 * The default is for netbuf fragments to be interpreted
	 * as wordstreams rather than bytestreams.
	 */
	QDF_NBUF_CB_TX_EXTRA_FRAG_WORDSTR_EFRAG(skb) = 1;
	QDF_NBUF_CB_TX_EXTRA_FRAG_WORDSTR_NBUF(skb) = 1;

	/*
	 * XXX:how about we reserve first then align
	 * Align & make sure that the tail & data are adjusted properly
	 */

	if (align) {
		offset = ((unsigned long)skb->data) % align;
		if (offset)
			skb_reserve(skb, align - offset);
	}

	/*
	 * NOTE:alloc doesn't take responsibility if reserve unaligns the data
	 * pointer
	 */
	skb_reserve(skb, reserve);
	qdf_nbuf_count_inc(skb);
}

#if defined(CONFIG_WIFI_EMULATION_WIFI_3_0) && defined(BUILD_X86) && \
	!defined(QCA_WIFI_QCN9000)
struct sk_buff *__qdf_nbuf_alloc(qdf_device_t osdev, size_t size, int reserve,
				 int align, int prio, const char *func,
				 uint32_t line)
{
	struct sk_buff *skb;
	uint32_t lowmem_alloc_tries = 0;

	if (align)
		size += (align - 1);

realloc:
	skb = dev_alloc_skb(size);

	if (skb)
		goto skb_alloc;

	skb = pld_nbuf_pre_alloc(size);

	if (!skb) {
		qdf_rl_nofl_err("NBUF alloc failed %zuB @ %s:%d",
				size, func, line);
		return NULL;
	}

skb_alloc:
	/* Hawkeye M2M emulation cannot handle memory addresses below 0x50000040
	 * Though we are trying to reserve low memory upfront to prevent this,
	 * we sometimes see SKBs allocated from low memory.
	 */
	if (virt_to_phys(qdf_nbuf_data(skb)) < 0x50000040) {
		lowmem_alloc_tries++;
		if (lowmem_alloc_tries > 100) {
			qdf_nofl_err("NBUF alloc failed %zuB @ %s:%d",
				     size, func, line);
			return NULL;
		} else {
			/* Not freeing to make sure it
			 * will not get allocated again
			 */
			goto realloc;
		}
	}

	qdf_nbuf_set_defaults(skb, align, reserve);

	return skb;
}
#else

#ifdef QCA_DP_NBUF_FAST_RECYCLE_CHECK
struct sk_buff *__qdf_nbuf_alloc(qdf_device_t osdev, size_t size, int reserve,
				 int align, int prio, const char *func,
				 uint32_t line)
{
	return __qdf_nbuf_frag_alloc(osdev, size, reserve, align, prio, func,
				     line);
}

#else
struct sk_buff *__qdf_nbuf_alloc(qdf_device_t osdev, size_t size, int reserve,
				 int align, int prio, const char *func,
				 uint32_t line)
{
	struct sk_buff *skb;
	int flags = GFP_KERNEL;

	if (align)
		size += (align - 1);

	if (in_interrupt() || irqs_disabled() || in_atomic()) {
		flags = GFP_ATOMIC;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 4, 0)
		/*
		 * Observed that kcompactd burns out CPU to make order-3 page.
		 *__netdev_alloc_skb has 4k page fallback option just in case of
		 * failing high order page allocation so we don't need to be
		 * hard. Make kcompactd rest in piece.
		 */
		flags = flags & ~__GFP_KSWAPD_RECLAIM;
#endif
	}

	skb =  alloc_skb(size, flags);

	if (skb)
		goto skb_alloc;

	skb = pld_nbuf_pre_alloc(size);

	if (!skb) {
		qdf_rl_nofl_err("NBUF alloc failed %zuB @ %s:%d",
				size, func, line);
		__qdf_nbuf_start_replenish_timer();
		return NULL;
	}

	__qdf_nbuf_stop_replenish_timer();

skb_alloc:
	qdf_nbuf_set_defaults(skb, align, reserve);

	return skb;
}
#endif

#endif
qdf_export_symbol(__qdf_nbuf_alloc);

struct sk_buff *__qdf_nbuf_frag_alloc(qdf_device_t osdev, size_t size,
				      int reserve, int align, int prio,
				      const char *func, uint32_t line)
{
	struct sk_buff *skb;
	int flags = GFP_KERNEL & ~__GFP_DIRECT_RECLAIM;
	bool atomic = false;

	if (align)
		size += (align - 1);

	if (in_interrupt() || irqs_disabled() || in_atomic()) {
		atomic = true;
		flags = GFP_ATOMIC;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 4, 0)
		/*
		 * Observed that kcompactd burns out CPU to make order-3 page.
		 *__netdev_alloc_skb has 4k page fallback option just in case of
		 * failing high order page allocation so we don't need to be
		 * hard. Make kcompactd rest in piece.
		 */
		flags = flags & ~__GFP_KSWAPD_RECLAIM;
#endif
	}

	skb = __netdev_alloc_skb(NULL, size, flags);
	if (skb)
		goto skb_alloc;

	/* 32k page frag alloc failed, try page slab allocation */
	if (likely(!atomic))
		flags |= __GFP_DIRECT_RECLAIM;

	skb = alloc_skb(size, flags);
	if (skb)
		goto skb_alloc;

	skb = pld_nbuf_pre_alloc(size);

	if (!skb) {
		qdf_rl_nofl_err("NBUF alloc failed %zuB @ %s:%d",
				size, func, line);
		__qdf_nbuf_start_replenish_timer();
		return NULL;
	}

	__qdf_nbuf_stop_replenish_timer();

skb_alloc:
	qdf_nbuf_set_defaults(skb, align, reserve);

	return skb;
}

qdf_export_symbol(__qdf_nbuf_frag_alloc);

__qdf_nbuf_t __qdf_nbuf_alloc_no_recycler(size_t size, int reserve, int align,
					  const char *func, uint32_t line)
{
	qdf_nbuf_t nbuf;
	unsigned long offset;

	if (align)
		size += (align - 1);

	nbuf = alloc_skb(size, GFP_ATOMIC);
	if (!nbuf)
		goto ret_nbuf;

	memset(nbuf->cb, 0x0, sizeof(nbuf->cb));

	skb_reserve(nbuf, reserve);

	if (align) {
		offset = ((unsigned long)nbuf->data) % align;
		if (offset)
			skb_reserve(nbuf, align - offset);
	}

	qdf_nbuf_count_inc(nbuf);

ret_nbuf:
	return nbuf;
}

qdf_export_symbol(__qdf_nbuf_alloc_no_recycler);

void __qdf_nbuf_free(struct sk_buff *skb)
{
	if (pld_nbuf_pre_alloc_free(skb))
		return;

	qdf_nbuf_frag_count_dec(skb);

	qdf_nbuf_count_dec(skb);
	if (nbuf_free_cb)
		nbuf_free_cb(skb);
	else
		dev_kfree_skb_any(skb);
}

qdf_export_symbol(__qdf_nbuf_free);

__qdf_nbuf_t __qdf_nbuf_clone(__qdf_nbuf_t skb)
{
	qdf_nbuf_t skb_new = NULL;

	skb_new = skb_clone(skb, GFP_ATOMIC);
	if (skb_new) {
		qdf_nbuf_frag_count_inc(skb_new);
		qdf_nbuf_count_inc(skb_new);
	}
	return skb_new;
}

qdf_export_symbol(__qdf_nbuf_clone);

struct sk_buff *
__qdf_nbuf_page_frag_alloc(qdf_device_t osdev, size_t size, int reserve,
			   int align, __qdf_frag_cache_t *pf_cache,
			   const char *func, uint32_t line)
{
	struct sk_buff *skb;
	qdf_frag_t frag_data;
	size_t orig_size = size;
	int flags = GFP_KERNEL;

	if (align)
		size += (align - 1);

	size += NET_SKB_PAD;
	size += SKB_DATA_ALIGN(sizeof(struct skb_shared_info));
	size = SKB_DATA_ALIGN(size);

	if (in_interrupt() || irqs_disabled() || in_atomic())
		flags = GFP_ATOMIC;

	frag_data = page_frag_alloc(pf_cache, size, flags);
	if (!frag_data) {
		qdf_rl_nofl_err("page frag alloc failed %zuB @ %s:%d",
				size, func, line);
		return __qdf_nbuf_alloc(osdev, orig_size, reserve, align, 0,
					func, line);
	}

	skb = build_skb(frag_data, size);
	if (skb) {
		skb_reserve(skb, NET_SKB_PAD);
		goto skb_alloc;
	}

	/* Free the data allocated from pf_cache */
	page_frag_free(frag_data);

	size = orig_size + align - 1;

	skb = pld_nbuf_pre_alloc(size);
	if (!skb) {
		qdf_rl_nofl_err("NBUF alloc failed %zuB @ %s:%d",
				size, func, line);
		__qdf_nbuf_start_replenish_timer();
		return NULL;
	}

	__qdf_nbuf_stop_replenish_timer();

skb_alloc:
	qdf_nbuf_set_defaults(skb, align, reserve);

	return skb;
}

qdf_export_symbol(__qdf_nbuf_page_frag_alloc);

#ifdef QCA_DP_TX_NBUF_LIST_FREE
void
__qdf_nbuf_dev_kfree_list(__qdf_nbuf_queue_head_t *nbuf_queue_head)
{
	dev_kfree_skb_list_fast(nbuf_queue_head);
}
#else
void
__qdf_nbuf_dev_kfree_list(__qdf_nbuf_queue_head_t *nbuf_queue_head)
{
}
#endif

qdf_export_symbol(__qdf_nbuf_dev_kfree_list);

#ifdef NBUF_MEMORY_DEBUG
struct qdf_nbuf_event {
	qdf_nbuf_t nbuf;
	char func[QDF_MEM_FUNC_NAME_SIZE];
	uint32_t line;
	enum qdf_nbuf_event_type type;
	uint64_t timestamp;
	qdf_dma_addr_t iova;
};

#ifndef QDF_NBUF_HISTORY_SIZE
#define QDF_NBUF_HISTORY_SIZE 4096
#endif
static qdf_atomic_t qdf_nbuf_history_index;
static struct qdf_nbuf_event qdf_nbuf_history[QDF_NBUF_HISTORY_SIZE];

void qdf_nbuf_ssr_register_region(void)
{
	qdf_ssr_driver_dump_register_region("qdf_nbuf_history",
					    qdf_nbuf_history,
					    sizeof(qdf_nbuf_history));
}

qdf_export_symbol(qdf_nbuf_ssr_register_region);

void qdf_nbuf_ssr_unregister_region(void)
{
	qdf_ssr_driver_dump_unregister_region("qdf_nbuf_history");
}

qdf_export_symbol(qdf_nbuf_ssr_unregister_region);

static int32_t qdf_nbuf_circular_index_next(qdf_atomic_t *index, int size)
{
	int32_t next = qdf_atomic_inc_return(index);

	if (next == size)
		qdf_atomic_sub(size, index);

	return next % size;
}

void
qdf_nbuf_history_add(qdf_nbuf_t nbuf, const char *func, uint32_t line,
		     enum qdf_nbuf_event_type type)
{
	int32_t idx = qdf_nbuf_circular_index_next(&qdf_nbuf_history_index,
						   QDF_NBUF_HISTORY_SIZE);
	struct qdf_nbuf_event *event = &qdf_nbuf_history[idx];

	if (qdf_atomic_read(&smmu_crashed)) {
		g_histroy_add_drop++;
		return;
	}

	event->nbuf = nbuf;
	qdf_str_lcopy(event->func, func, QDF_MEM_FUNC_NAME_SIZE);
	event->line = line;
	event->type = type;
	event->timestamp = qdf_get_log_timestamp();
	if (type == QDF_NBUF_MAP || type == QDF_NBUF_UNMAP ||
	    type == QDF_NBUF_SMMU_MAP || type == QDF_NBUF_SMMU_UNMAP)
		event->iova = QDF_NBUF_CB_PADDR(nbuf);
	else
		event->iova = 0;
}

void qdf_set_smmu_fault_state(bool smmu_fault_state)
{
	qdf_atomic_set(&smmu_crashed, smmu_fault_state);
	if (!smmu_fault_state)
		g_histroy_add_drop = 0;
}
qdf_export_symbol(qdf_set_smmu_fault_state);
#endif /* NBUF_MEMORY_DEBUG */

#ifdef NBUF_SMMU_MAP_UNMAP_DEBUG
#define qdf_nbuf_smmu_map_tracker_bits 11 /* 2048 buckets */
qdf_tracker_declare(qdf_nbuf_smmu_map_tracker, qdf_nbuf_smmu_map_tracker_bits,
		    "nbuf map-no-unmap events", "nbuf map", "nbuf unmap");

static void qdf_nbuf_smmu_map_tracking_init(void)
{
	qdf_tracker_init(&qdf_nbuf_smmu_map_tracker);
}

static void qdf_nbuf_smmu_map_tracking_deinit(void)
{
	qdf_tracker_deinit(&qdf_nbuf_smmu_map_tracker);
}

static QDF_STATUS
qdf_nbuf_track_smmu_map(qdf_nbuf_t nbuf, const char *func, uint32_t line)
{
	if (is_initial_mem_debug_disabled)
		return QDF_STATUS_SUCCESS;

	return qdf_tracker_track(&qdf_nbuf_smmu_map_tracker, nbuf, func, line);
}

static void
qdf_nbuf_untrack_smmu_map(qdf_nbuf_t nbuf, const char *func, uint32_t line)
{
	if (is_initial_mem_debug_disabled)
		return;

	qdf_nbuf_history_add(nbuf, func, line, QDF_NBUF_SMMU_UNMAP);
	qdf_tracker_untrack(&qdf_nbuf_smmu_map_tracker, nbuf, func, line);
}

void qdf_nbuf_map_check_for_smmu_leaks(void)
{
	qdf_tracker_check_for_leaks(&qdf_nbuf_smmu_map_tracker);
}

#ifdef IPA_OFFLOAD
QDF_STATUS qdf_nbuf_smmu_map_debug(qdf_nbuf_t nbuf,
				   uint8_t hdl,
				   uint8_t num_buffers,
				   qdf_mem_info_t *info,
				   const char *func,
				   uint32_t line)
{
	QDF_STATUS status;

	status = qdf_nbuf_track_smmu_map(nbuf, func, line);
	if (QDF_IS_STATUS_ERROR(status))
		return status;

	status = __qdf_ipa_wdi_create_smmu_mapping(hdl, num_buffers, info);

	if (QDF_IS_STATUS_ERROR(status)) {
		qdf_nbuf_untrack_smmu_map(nbuf, func, line);
	} else {
		if (!is_initial_mem_debug_disabled)
			qdf_nbuf_history_add(nbuf, func, line, QDF_NBUF_MAP);
		qdf_net_buf_debug_update_smmu_map_node(nbuf, info->iova,
						       info->pa, func, line);
	}

	return status;
}

qdf_export_symbol(qdf_nbuf_smmu_map_debug);

QDF_STATUS qdf_nbuf_smmu_unmap_debug(qdf_nbuf_t nbuf,
				     uint8_t hdl,
				     uint8_t num_buffers,
				     qdf_mem_info_t *info,
				     const char *func,
				     uint32_t line)
{
	QDF_STATUS status;

	qdf_nbuf_untrack_smmu_map(nbuf, func, line);
	status = __qdf_ipa_wdi_release_smmu_mapping(hdl, num_buffers, info);
	qdf_net_buf_debug_update_smmu_unmap_node(nbuf, info->iova,
						 info->pa, func, line);
	return status;
}

qdf_export_symbol(qdf_nbuf_smmu_unmap_debug);
#endif /* IPA_OFFLOAD */

static void qdf_nbuf_panic_on_free_if_smmu_mapped(qdf_nbuf_t nbuf,
						  const char *func,
						  uint32_t line)
{
	char map_func[QDF_TRACKER_FUNC_SIZE];
	uint32_t map_line;

	if (!qdf_tracker_lookup(&qdf_nbuf_smmu_map_tracker, nbuf,
				&map_func, &map_line))
		return;

	QDF_MEMDEBUG_PANIC("Nbuf freed @ %s:%u while mapped from %s:%u",
			   func, line, map_func, map_line);
}

static inline void qdf_net_buf_update_smmu_params(QDF_NBUF_TRACK *p_node)
{
	p_node->smmu_unmap_line_num = 0;
	p_node->is_nbuf_smmu_mapped = false;
	p_node->smmu_map_line_num = 0;
	p_node->smmu_map_func_name[0] = '\0';
	p_node->smmu_unmap_func_name[0] = '\0';
	p_node->smmu_unmap_iova_addr = 0;
	p_node->smmu_unmap_pa_addr = 0;
	p_node->smmu_map_iova_addr = 0;
	p_node->smmu_map_pa_addr = 0;
}
#else /* !NBUF_SMMU_MAP_UNMAP_DEBUG */
#ifdef NBUF_MEMORY_DEBUG
static void qdf_nbuf_smmu_map_tracking_init(void)
{
}

static void qdf_nbuf_smmu_map_tracking_deinit(void)
{
}

static void qdf_nbuf_panic_on_free_if_smmu_mapped(qdf_nbuf_t nbuf,
						  const char *func,
						  uint32_t line)
{
}

static inline void qdf_net_buf_update_smmu_params(QDF_NBUF_TRACK *p_node)
{
}
#endif /* NBUF_MEMORY_DEBUG */

#ifdef IPA_OFFLOAD
QDF_STATUS qdf_nbuf_smmu_map_debug(qdf_nbuf_t nbuf,
				   uint8_t hdl,
				   uint8_t num_buffers,
				   qdf_mem_info_t *info,
				   const char *func,
				   uint32_t line)
{
	return  __qdf_ipa_wdi_create_smmu_mapping(hdl, num_buffers, info);
}

qdf_export_symbol(qdf_nbuf_smmu_map_debug);

QDF_STATUS qdf_nbuf_smmu_unmap_debug(qdf_nbuf_t nbuf,
				     uint8_t hdl,
				     uint8_t num_buffers,
				     qdf_mem_info_t *info,
				     const char *func,
				     uint32_t line)
{
	return __qdf_ipa_wdi_release_smmu_mapping(hdl, num_buffers, info);
}

qdf_export_symbol(qdf_nbuf_smmu_unmap_debug);
#endif /* IPA_OFFLOAD */
#endif /* NBUF_SMMU_MAP_UNMAP_DEBUG */

#ifdef NBUF_MAP_UNMAP_DEBUG
#define qdf_nbuf_map_tracker_bits 11 /* 2048 buckets */
qdf_tracker_declare(qdf_nbuf_map_tracker, qdf_nbuf_map_tracker_bits,
		    "nbuf map-no-unmap events", "nbuf map", "nbuf unmap");

static void qdf_nbuf_map_tracking_init(void)
{
	qdf_tracker_init(&qdf_nbuf_map_tracker);
}

static void qdf_nbuf_map_tracking_deinit(void)
{
	qdf_tracker_deinit(&qdf_nbuf_map_tracker);
}

static QDF_STATUS
qdf_nbuf_track_map(qdf_nbuf_t nbuf, const char *func, uint32_t line)
{
	if (is_initial_mem_debug_disabled)
		return QDF_STATUS_SUCCESS;

	return qdf_tracker_track(&qdf_nbuf_map_tracker, nbuf, func, line);
}

static void
qdf_nbuf_untrack_map(qdf_nbuf_t nbuf, const char *func, uint32_t line)
{
	if (is_initial_mem_debug_disabled)
		return;

	qdf_nbuf_history_add(nbuf, func, line, QDF_NBUF_UNMAP);
	qdf_tracker_untrack(&qdf_nbuf_map_tracker, nbuf, func, line);
}

void qdf_nbuf_map_check_for_leaks(void)
{
	qdf_tracker_check_for_leaks(&qdf_nbuf_map_tracker);
}

QDF_STATUS qdf_nbuf_map_debug(qdf_device_t osdev,
			      qdf_nbuf_t buf,
			      qdf_dma_dir_t dir,
			      const char *func,
			      uint32_t line)
{
	QDF_STATUS status;

	status = qdf_nbuf_track_map(buf, func, line);
	if (QDF_IS_STATUS_ERROR(status))
		return status;

	status = __qdf_nbuf_map(osdev, buf, dir);
	if (QDF_IS_STATUS_ERROR(status)) {
		qdf_nbuf_untrack_map(buf, func, line);
	} else {
		if (!is_initial_mem_debug_disabled)
			qdf_nbuf_history_add(buf, func, line, QDF_NBUF_MAP);
		qdf_net_buf_debug_update_map_node(buf, func, line);
	}

	return status;
}

qdf_export_symbol(qdf_nbuf_map_debug);

void qdf_nbuf_unmap_debug(qdf_device_t osdev,
			  qdf_nbuf_t buf,
			  qdf_dma_dir_t dir,
			  const char *func,
			  uint32_t line)
{
	qdf_nbuf_untrack_map(buf, func, line);
	__qdf_nbuf_unmap_single(osdev, buf, dir);
	qdf_net_buf_debug_update_unmap_node(buf, func, line);
}

qdf_export_symbol(qdf_nbuf_unmap_debug);

QDF_STATUS qdf_nbuf_map_single_debug(qdf_device_t osdev,
				     qdf_nbuf_t buf,
				     qdf_dma_dir_t dir,
				     const char *func,
				     uint32_t line)
{
	QDF_STATUS status;

	status = qdf_nbuf_track_map(buf, func, line);
	if (QDF_IS_STATUS_ERROR(status))
		return status;

	status = __qdf_nbuf_map_single(osdev, buf, dir);
	if (QDF_IS_STATUS_ERROR(status)) {
		qdf_nbuf_untrack_map(buf, func, line);
	} else {
		if (!is_initial_mem_debug_disabled)
			qdf_nbuf_history_add(buf, func, line, QDF_NBUF_MAP);
		qdf_net_buf_debug_update_map_node(buf, func, line);
	}

	return status;
}

qdf_export_symbol(qdf_nbuf_map_single_debug);

void qdf_nbuf_unmap_single_debug(qdf_device_t osdev,
				 qdf_nbuf_t buf,
				 qdf_dma_dir_t dir,
				 const char *func,
				 uint32_t line)
{
	qdf_nbuf_untrack_map(buf, func, line);
	__qdf_nbuf_unmap_single(osdev, buf, dir);
	qdf_net_buf_debug_update_unmap_node(buf, func, line);
}

qdf_export_symbol(qdf_nbuf_unmap_single_debug);

QDF_STATUS qdf_nbuf_map_nbytes_debug(qdf_device_t osdev,
				     qdf_nbuf_t buf,
				     qdf_dma_dir_t dir,
				     int nbytes,
				     const char *func,
				     uint32_t line)
{
	QDF_STATUS status;

	status = qdf_nbuf_track_map(buf, func, line);
	if (QDF_IS_STATUS_ERROR(status))
		return status;

	status = __qdf_nbuf_map_nbytes(osdev, buf, dir, nbytes);
	if (QDF_IS_STATUS_ERROR(status)) {
		qdf_nbuf_untrack_map(buf, func, line);
	} else {
		if (!is_initial_mem_debug_disabled)
			qdf_nbuf_history_add(buf, func, line, QDF_NBUF_MAP);
		qdf_net_buf_debug_update_map_node(buf, func, line);
	}

	return status;
}

qdf_export_symbol(qdf_nbuf_map_nbytes_debug);

void qdf_nbuf_unmap_nbytes_debug(qdf_device_t osdev,
				 qdf_nbuf_t buf,
				 qdf_dma_dir_t dir,
				 int nbytes,
				 const char *func,
				 uint32_t line)
{
	qdf_nbuf_untrack_map(buf, func, line);
	__qdf_nbuf_unmap_nbytes(osdev, buf, dir, nbytes);
	qdf_net_buf_debug_update_unmap_node(buf, func, line);
}

qdf_export_symbol(qdf_nbuf_unmap_nbytes_debug);

QDF_STATUS qdf_nbuf_map_nbytes_single_debug(qdf_device_t osdev,
					    qdf_nbuf_t buf,
					    qdf_dma_dir_t dir,
					    int nbytes,
					    const char *func,
					    uint32_t line)
{
	QDF_STATUS status;

	status = qdf_nbuf_track_map(buf, func, line);
	if (QDF_IS_STATUS_ERROR(status))
		return status;

	status = __qdf_nbuf_map_nbytes_single(osdev, buf, dir, nbytes);
	if (QDF_IS_STATUS_ERROR(status)) {
		qdf_nbuf_untrack_map(buf, func, line);
	} else {
		if (!is_initial_mem_debug_disabled)
			qdf_nbuf_history_add(buf, func, line, QDF_NBUF_MAP);
		qdf_net_buf_debug_update_map_node(buf, func, line);
	}

	return status;
}

qdf_export_symbol(qdf_nbuf_map_nbytes_single_debug);

void qdf_nbuf_unmap_nbytes_single_debug(qdf_device_t osdev,
					qdf_nbuf_t buf,
					qdf_dma_dir_t dir,
					int nbytes,
					const char *func,
					uint32_t line)
{
	qdf_nbuf_untrack_map(buf, func, line);
	__qdf_nbuf_unmap_nbytes_single(osdev, buf, dir, nbytes);
	qdf_net_buf_debug_update_unmap_node(buf, func, line);
}

qdf_export_symbol(qdf_nbuf_unmap_nbytes_single_debug);

void qdf_nbuf_unmap_nbytes_single_paddr_debug(qdf_device_t osdev,
					      qdf_nbuf_t buf,
					      qdf_dma_addr_t phy_addr,
					      qdf_dma_dir_t dir, int nbytes,
					      const char *func, uint32_t line)
{
	qdf_nbuf_untrack_map(buf, func, line);
	__qdf_record_nbuf_nbytes(__qdf_nbuf_get_end_offset(buf), dir, false);
	__qdf_mem_unmap_nbytes_single(osdev, phy_addr, dir, nbytes);
	qdf_net_buf_debug_update_unmap_node(buf, func, line);
}

qdf_export_symbol(qdf_nbuf_unmap_nbytes_single_paddr_debug);

static void qdf_nbuf_panic_on_free_if_mapped(qdf_nbuf_t nbuf,
					     const char *func,
					     uint32_t line)
{
	char map_func[QDF_TRACKER_FUNC_SIZE];
	uint32_t map_line;

	if (!qdf_tracker_lookup(&qdf_nbuf_map_tracker, nbuf,
				&map_func, &map_line))
		return;

	QDF_MEMDEBUG_PANIC("Nbuf freed @ %s:%u while mapped from %s:%u",
			   func, line, map_func, map_line);
}
#else
static inline void qdf_nbuf_map_tracking_init(void)
{
}

static inline void qdf_nbuf_map_tracking_deinit(void)
{
}

static inline void qdf_nbuf_panic_on_free_if_mapped(qdf_nbuf_t nbuf,
						    const char *func,
						    uint32_t line)
{
}
#endif /* NBUF_MAP_UNMAP_DEBUG */

#ifdef QDF_OS_DEBUG
QDF_STATUS
__qdf_nbuf_map(qdf_device_t osdev, struct sk_buff *skb, qdf_dma_dir_t dir)
{
	struct skb_shared_info *sh = skb_shinfo(skb);

	qdf_assert((dir == QDF_DMA_TO_DEVICE)
			|| (dir == QDF_DMA_FROM_DEVICE));

	/*
	 * Assume there's only a single fragment.
	 * To support multiple fragments, it would be necessary to change
	 * qdf_nbuf_t to be a separate object that stores meta-info
	 * (including the bus address for each fragment) and a pointer
	 * to the underlying sk_buff.
	 */
	qdf_assert(sh->nr_frags == 0);

	return __qdf_nbuf_map_single(osdev, skb, dir);
}
qdf_export_symbol(__qdf_nbuf_map);

#else
QDF_STATUS
__qdf_nbuf_map(qdf_device_t osdev, struct sk_buff *skb, qdf_dma_dir_t dir)
{
	return __qdf_nbuf_map_single(osdev, skb, dir);
}
qdf_export_symbol(__qdf_nbuf_map);
#endif

void
__qdf_nbuf_unmap(qdf_device_t osdev, struct sk_buff *skb,
			qdf_dma_dir_t dir)
{
	qdf_assert((dir == QDF_DMA_TO_DEVICE)
		   || (dir == QDF_DMA_FROM_DEVICE));

	/*
	 * Assume there's a single fragment.
	 * If this is not true, the assertion in __qdf_nbuf_map will catch it.
	 */
	__qdf_nbuf_unmap_single(osdev, skb, dir);
}
qdf_export_symbol(__qdf_nbuf_unmap);

#if defined(A_SIMOS_DEVHOST) || defined(HIF_USB) || defined(HIF_SDIO)
QDF_STATUS
__qdf_nbuf_map_single(qdf_device_t osdev, qdf_nbuf_t buf, qdf_dma_dir_t dir)
{
	qdf_dma_addr_t paddr;

	QDF_NBUF_CB_PADDR(buf) = paddr = (uintptr_t)buf->data;
	BUILD_BUG_ON(sizeof(paddr) < sizeof(buf->data));
	BUILD_BUG_ON(sizeof(QDF_NBUF_CB_PADDR(buf)) < sizeof(buf->data));
	return QDF_STATUS_SUCCESS;
}
qdf_export_symbol(__qdf_nbuf_map_single);
#else
QDF_STATUS
__qdf_nbuf_map_single(qdf_device_t osdev, qdf_nbuf_t buf, qdf_dma_dir_t dir)
{
	qdf_dma_addr_t paddr;

	/* assume that the OS only provides a single fragment */
	QDF_NBUF_CB_PADDR(buf) = paddr =
		dma_map_single(osdev->dev, buf->data,
				skb_end_pointer(buf) - buf->data,
				__qdf_dma_dir_to_os(dir));
	__qdf_record_nbuf_nbytes(
		__qdf_nbuf_get_end_offset(buf), dir, true);
	return dma_mapping_error(osdev->dev, paddr)
		? QDF_STATUS_E_FAILURE
		: QDF_STATUS_SUCCESS;
}
qdf_export_symbol(__qdf_nbuf_map_single);
#endif

#if defined(A_SIMOS_DEVHOST) || defined(HIF_USB) || defined(HIF_SDIO)
void __qdf_nbuf_unmap_single(qdf_device_t osdev, qdf_nbuf_t buf,
				qdf_dma_dir_t dir)
{
}
#else
void __qdf_nbuf_unmap_single(qdf_device_t osdev, qdf_nbuf_t buf,
					qdf_dma_dir_t dir)
{
	if (QDF_NBUF_CB_PADDR(buf)) {
		__qdf_record_nbuf_nbytes(
			__qdf_nbuf_get_end_offset(buf), dir, false);
		dma_unmap_single(osdev->dev, QDF_NBUF_CB_PADDR(buf),
			skb_end_pointer(buf) - buf->data,
			__qdf_dma_dir_to_os(dir));
	}
}
#endif
qdf_export_symbol(__qdf_nbuf_unmap_single);

QDF_STATUS
__qdf_nbuf_set_rx_cksum(struct sk_buff *skb, qdf_nbuf_rx_cksum_t *cksum)
{
	switch (cksum->l4_result) {
	case QDF_NBUF_RX_CKSUM_NONE:
		skb->ip_summed = CHECKSUM_NONE;
		break;
	case QDF_NBUF_RX_CKSUM_TCP_UDP_UNNECESSARY:
		skb->ip_summed = CHECKSUM_UNNECESSARY;
		skb->csum_level = cksum->csum_level;
		break;
	case QDF_NBUF_RX_CKSUM_TCP_UDP_HW:
		skb->ip_summed = CHECKSUM_PARTIAL;
		skb->csum = cksum->val;
		break;
	default:
		pr_err("Unknown checksum type\n");
		qdf_assert(0);
		return QDF_STATUS_E_NOSUPPORT;
	}
	return QDF_STATUS_SUCCESS;
}
qdf_export_symbol(__qdf_nbuf_set_rx_cksum);

qdf_nbuf_tx_cksum_t __qdf_nbuf_get_tx_cksum(struct sk_buff *skb)
{
	switch (skb->ip_summed) {
	case CHECKSUM_NONE:
		return QDF_NBUF_TX_CKSUM_NONE;
	case CHECKSUM_PARTIAL:
		return QDF_NBUF_TX_CKSUM_TCP_UDP;
	case CHECKSUM_COMPLETE:
		return QDF_NBUF_TX_CKSUM_TCP_UDP_IP;
	default:
		return QDF_NBUF_TX_CKSUM_NONE;
	}
}
qdf_export_symbol(__qdf_nbuf_get_tx_cksum);

uint8_t __qdf_nbuf_get_tid(struct sk_buff *skb)
{
	return skb->priority;
}
qdf_export_symbol(__qdf_nbuf_get_tid);

void __qdf_nbuf_set_tid(struct sk_buff *skb, uint8_t tid)
{
	skb->priority = tid;
}
qdf_export_symbol(__qdf_nbuf_set_tid);

uint8_t __qdf_nbuf_get_exemption_type(struct sk_buff *skb)
{
	return QDF_NBUF_EXEMPT_NO_EXEMPTION;
}
qdf_export_symbol(__qdf_nbuf_get_exemption_type);

void __qdf_nbuf_reg_trace_cb(qdf_nbuf_trace_update_t cb_func_ptr)
{
	qdf_trace_update_cb = cb_func_ptr;
}
qdf_export_symbol(__qdf_nbuf_reg_trace_cb);

enum qdf_proto_subtype
__qdf_nbuf_data_get_dhcp_subtype(uint8_t *data)
{
	enum qdf_proto_subtype subtype = QDF_PROTO_INVALID;

	if ((data[QDF_DHCP_OPTION53_OFFSET] == QDF_DHCP_OPTION53) &&
		(data[QDF_DHCP_OPTION53_LENGTH_OFFSET] ==
					QDF_DHCP_OPTION53_LENGTH)) {

		switch (data[QDF_DHCP_OPTION53_STATUS_OFFSET]) {
		case QDF_DHCP_DISCOVER:
			subtype = QDF_PROTO_DHCP_DISCOVER;
			break;
		case QDF_DHCP_REQUEST:
			subtype = QDF_PROTO_DHCP_REQUEST;
			break;
		case QDF_DHCP_OFFER:
			subtype = QDF_PROTO_DHCP_OFFER;
			break;
		case QDF_DHCP_ACK:
			subtype = QDF_PROTO_DHCP_ACK;
			break;
		case QDF_DHCP_NAK:
			subtype = QDF_PROTO_DHCP_NACK;
			break;
		case QDF_DHCP_RELEASE:
			subtype = QDF_PROTO_DHCP_RELEASE;
			break;
		case QDF_DHCP_INFORM:
			subtype = QDF_PROTO_DHCP_INFORM;
			break;
		case QDF_DHCP_DECLINE:
			subtype = QDF_PROTO_DHCP_DECLINE;
			break;
		default:
			break;
		}
	}

	return subtype;
}

#define EAPOL_WPA_KEY_INFO_ACK BIT(7)
#define EAPOL_WPA_KEY_INFO_MIC BIT(8)
#define EAPOL_WPA_KEY_INFO_ENCR_KEY_DATA BIT(12) /* IEEE 802.11i/RSN only */

/**
 * __qdf_nbuf_data_get_eapol_key() - Get EAPOL key
 * @data: Pointer to EAPOL packet data buffer
 *
 * We can distinguish M1/M3 from M2/M4 by the ack bit in the keyinfo field
 * The ralationship between the ack bit and EAPOL type is as follows:
 *
 *  EAPOL type  |   M1    M2   M3  M4
 * --------------------------------------
 *     Ack      |   1     0    1   0
 * --------------------------------------
 *
 * Then, we can differentiate M1 from M3, M2 from M4 by below methods:
 * M2/M4: by keyDataLength or Nonce value being 0 for M4.
 * M1/M3: by the mic/encrKeyData bit in the keyinfo field.
 *
 * Return: subtype of the EAPOL packet.
 */
static inline enum qdf_proto_subtype
__qdf_nbuf_data_get_eapol_key(uint8_t *data)
{
	uint16_t key_info, key_data_length;
	enum qdf_proto_subtype subtype;
	uint64_t *key_nonce;

	key_info = qdf_ntohs((uint16_t)(*(uint16_t *)
			(data + EAPOL_KEY_INFO_OFFSET)));

	key_data_length = qdf_ntohs((uint16_t)(*(uint16_t *)
				(data + EAPOL_KEY_DATA_LENGTH_OFFSET)));
	key_nonce = (uint64_t *)(data + EAPOL_WPA_KEY_NONCE_OFFSET);

	if (key_info & EAPOL_WPA_KEY_INFO_ACK)
		if (key_info &
		    (EAPOL_WPA_KEY_INFO_MIC | EAPOL_WPA_KEY_INFO_ENCR_KEY_DATA))
			subtype = QDF_PROTO_EAPOL_M3;
		else
			subtype = QDF_PROTO_EAPOL_M1;
	else
		if (key_data_length == 0 ||
		    !((*key_nonce) || (*(key_nonce + 1)) ||
		      (*(key_nonce + 2)) || (*(key_nonce + 3))))
			subtype = QDF_PROTO_EAPOL_M4;
		else
			subtype = QDF_PROTO_EAPOL_M2;

	return subtype;
}

/**
 * __qdf_nbuf_data_get_exp_msg_type() - Get EAP expanded msg type
 * @data: Pointer to EAPOL packet data buffer
 * @code: EAP code
 *
 * Return: subtype of the EAPOL packet.
 */
static inline enum qdf_proto_subtype
__qdf_nbuf_data_get_exp_msg_type(uint8_t *data, uint8_t code)
{
	uint8_t msg_type;
	uint8_t opcode = *(data + EAP_EXP_MSG_OPCODE_OFFSET);

	switch (opcode) {
	case WSC_START:
		return QDF_PROTO_EAP_WSC_START;
	case WSC_ACK:
		return QDF_PROTO_EAP_WSC_ACK;
	case WSC_NACK:
		return QDF_PROTO_EAP_WSC_NACK;
	case WSC_MSG:
		msg_type = *(data + EAP_EXP_MSG_TYPE_OFFSET);
		switch (msg_type) {
		case EAP_EXP_TYPE_M1:
			return QDF_PROTO_EAP_M1;
		case EAP_EXP_TYPE_M2:
			return QDF_PROTO_EAP_M2;
		case EAP_EXP_TYPE_M3:
			return QDF_PROTO_EAP_M3;
		case EAP_EXP_TYPE_M4:
			return QDF_PROTO_EAP_M4;
		case EAP_EXP_TYPE_M5:
			return QDF_PROTO_EAP_M5;
		case EAP_EXP_TYPE_M6:
			return QDF_PROTO_EAP_M6;
		case EAP_EXP_TYPE_M7:
			return QDF_PROTO_EAP_M7;
		case EAP_EXP_TYPE_M8:
			return QDF_PROTO_EAP_M8;
		default:
			break;
		}
		break;
	case WSC_DONE:
		return QDF_PROTO_EAP_WSC_DONE;
	case WSC_FRAG_ACK:
		return QDF_PROTO_EAP_WSC_FRAG_ACK;
	default:
		break;
	}
	switch (code) {
	case QDF_EAP_REQUEST:
		return QDF_PROTO_EAP_REQUEST;
	case QDF_EAP_RESPONSE:
		return QDF_PROTO_EAP_RESPONSE;
	default:
		return QDF_PROTO_INVALID;
	}
}

/**
 * __qdf_nbuf_data_get_eap_type() - Get EAP type
 * @data: Pointer to EAPOL packet data buffer
 * @code: EAP code
 *
 * Return: subtype of the EAPOL packet.
 */
static inline enum qdf_proto_subtype
__qdf_nbuf_data_get_eap_type(uint8_t *data, uint8_t code)
{
	uint8_t type = *(data + EAP_TYPE_OFFSET);

	switch (type) {
	case EAP_PACKET_TYPE_EXP:
		return __qdf_nbuf_data_get_exp_msg_type(data, code);
	case EAP_PACKET_TYPE_ID:
		switch (code) {
		case QDF_EAP_REQUEST:
			return QDF_PROTO_EAP_REQ_ID;
		case QDF_EAP_RESPONSE:
			return QDF_PROTO_EAP_RSP_ID;
		default:
			return QDF_PROTO_INVALID;
		}
	default:
		switch (code) {
		case QDF_EAP_REQUEST:
			return QDF_PROTO_EAP_REQUEST;
		case QDF_EAP_RESPONSE:
			return QDF_PROTO_EAP_RESPONSE;
		default:
			return QDF_PROTO_INVALID;
		}
	}
}

/**
 * __qdf_nbuf_data_get_eap_code() - Get EAPOL code
 * @data: Pointer to EAPOL packet data buffer
 *
 * Return: subtype of the EAPOL packet.
 */
static inline enum qdf_proto_subtype
__qdf_nbuf_data_get_eap_code(uint8_t *data)
{
	uint8_t code = *(data + EAP_CODE_OFFSET);

	switch (code) {
	case QDF_EAP_REQUEST:
	case QDF_EAP_RESPONSE:
		return __qdf_nbuf_data_get_eap_type(data, code);
	case QDF_EAP_SUCCESS:
		return QDF_PROTO_EAP_SUCCESS;
	case QDF_EAP_FAILURE:
		return QDF_PROTO_EAP_FAILURE;
	case QDF_EAP_INITIATE:
		return QDF_PROTO_EAP_INITIATE;
	case QDF_EAP_FINISH:
		return QDF_PROTO_EAP_FINISH;
	default:
		return QDF_PROTO_INVALID;
	}
}

enum qdf_proto_subtype
__qdf_nbuf_data_get_eapol_subtype(uint8_t *data)
{
	uint8_t pkt_type = *(data + EAPOL_PACKET_TYPE_OFFSET);

	switch (pkt_type) {
	case EAPOL_PACKET_TYPE_EAP:
		return __qdf_nbuf_data_get_eap_code(data);
	case EAPOL_PACKET_TYPE_START:
		return QDF_PROTO_EAPOL_START;
	case EAPOL_PACKET_TYPE_LOGOFF:
		return QDF_PROTO_EAPOL_LOGOFF;
	case EAPOL_PACKET_TYPE_KEY:
		return __qdf_nbuf_data_get_eapol_key(data);
	case EAPOL_PACKET_TYPE_ASF:
		return QDF_PROTO_EAPOL_ASF;
	default:
		return QDF_PROTO_INVALID;
	}
}

qdf_export_symbol(__qdf_nbuf_data_get_eapol_subtype);

enum qdf_proto_subtype
__qdf_nbuf_data_get_arp_subtype(uint8_t *data)
{
	uint16_t subtype;
	enum qdf_proto_subtype proto_subtype = QDF_PROTO_INVALID;

	subtype = (uint16_t)(*(uint16_t *)
			(data + ARP_SUB_TYPE_OFFSET));

	switch (QDF_SWAP_U16(subtype)) {
	case ARP_REQUEST:
		proto_subtype = QDF_PROTO_ARP_REQ;
		break;
	case ARP_RESPONSE:
		proto_subtype = QDF_PROTO_ARP_RES;
		break;
	default:
		break;
	}

	return proto_subtype;
}

enum qdf_proto_subtype
__qdf_nbuf_data_get_icmp_subtype(uint8_t *data)
{
	uint8_t subtype;
	enum qdf_proto_subtype proto_subtype = QDF_PROTO_INVALID;

	subtype = (uint8_t)(*(uint8_t *)
			(data + ICMP_SUBTYPE_OFFSET));

	switch (subtype) {
	case ICMP_REQUEST:
		proto_subtype = QDF_PROTO_ICMP_REQ;
		break;
	case ICMP_RESPONSE:
		proto_subtype = QDF_PROTO_ICMP_RES;
		break;
	default:
		break;
	}

	return proto_subtype;
}

enum qdf_proto_subtype
__qdf_nbuf_data_get_icmpv6_subtype(uint8_t *data)
{
	uint8_t subtype;
	enum qdf_proto_subtype proto_subtype = QDF_PROTO_INVALID;

	subtype = (uint8_t)(*(uint8_t *)
			(data + ICMPV6_SUBTYPE_OFFSET));

	switch (subtype) {
	case ICMPV6_REQUEST:
		proto_subtype = QDF_PROTO_ICMPV6_REQ;
		break;
	case ICMPV6_RESPONSE:
		proto_subtype = QDF_PROTO_ICMPV6_RES;
		break;
	case ICMPV6_RS:
		proto_subtype = QDF_PROTO_ICMPV6_RS;
		break;
	case ICMPV6_RA:
		proto_subtype = QDF_PROTO_ICMPV6_RA;
		break;
	case ICMPV6_NS:
		proto_subtype = QDF_PROTO_ICMPV6_NS;
		break;
	case ICMPV6_NA:
		proto_subtype = QDF_PROTO_ICMPV6_NA;
		break;
	default:
		break;
	}

	return proto_subtype;
}

bool
__qdf_nbuf_is_ipv4_last_fragment(struct sk_buff *skb)
{
	if (((ntohs(ip_hdr(skb)->frag_off) & ~IP_OFFSET) & IP_MF) == 0)
		return true;

	return false;
}

void
__qdf_nbuf_data_set_ipv4_tos(uint8_t *data, uint8_t tos)
{
	*(uint8_t *)(data + QDF_NBUF_TRAC_IPV4_TOS_OFFSET) = tos;
}

uint8_t
__qdf_nbuf_data_get_ipv4_tos(uint8_t *data)
{
	uint8_t tos;

	tos = (uint8_t)(*(uint8_t *)(data +
			QDF_NBUF_TRAC_IPV4_TOS_OFFSET));
	return tos;
}

uint8_t
__qdf_nbuf_data_get_ipv4_proto(uint8_t *data)
{
	uint8_t proto_type;

	proto_type = (uint8_t)(*(uint8_t *)(data +
				QDF_NBUF_TRAC_IPV4_PROTO_TYPE_OFFSET));
	return proto_type;
}

uint8_t
__qdf_nbuf_data_get_ipv6_tc(uint8_t *data)
{
	struct ipv6hdr *hdr;

	hdr =  (struct ipv6hdr *)(data + QDF_NBUF_TRAC_IPV6_OFFSET);
	return ip6_tclass(ip6_flowinfo(hdr));
}

void
__qdf_nbuf_data_set_ipv6_tc(uint8_t *data, uint8_t tc)
{
	struct ipv6hdr *hdr;

	hdr =  (struct ipv6hdr *)(data + QDF_NBUF_TRAC_IPV6_OFFSET);
	ip6_flow_hdr(hdr, tc, ip6_flowlabel(hdr));
}

uint8_t
__qdf_nbuf_data_get_ipv6_proto(uint8_t *data)
{
	uint8_t proto_type;

	proto_type = (uint8_t)(*(uint8_t *)(data +
				QDF_NBUF_TRAC_IPV6_PROTO_TYPE_OFFSET));
	return proto_type;
}

bool __qdf_nbuf_data_is_ipv4_pkt(uint8_t *data)
{
	uint16_t ether_type;

	ether_type = (uint16_t)(*(uint16_t *)(data +
				QDF_NBUF_TRAC_ETH_TYPE_OFFSET));

	if (ether_type == QDF_SWAP_U16(QDF_NBUF_TRAC_IPV4_ETH_TYPE))
		return true;
	else
		return false;
}
qdf_export_symbol(__qdf_nbuf_data_is_ipv4_pkt);

bool __qdf_nbuf_data_is_ipv4_dhcp_pkt(uint8_t *data)
{
	uint16_t sport;
	uint16_t dport;
	uint8_t ipv4_offset;
	uint8_t ipv4_hdr_len;
	struct iphdr *iphdr;

	if (__qdf_nbuf_get_ether_type(data) !=
	    QDF_SWAP_U16(QDF_NBUF_TRAC_IPV4_ETH_TYPE))
		return false;

	ipv4_offset = __qdf_nbuf_get_ip_offset(data);
	iphdr = (struct iphdr *)(data + ipv4_offset);
	ipv4_hdr_len = iphdr->ihl * QDF_NBUF_IPV4_HDR_SIZE_UNIT;

	sport = *(uint16_t *)(data + ipv4_offset + ipv4_hdr_len);
	dport = *(uint16_t *)(data + ipv4_offset + ipv4_hdr_len +
			      sizeof(uint16_t));

	if (((sport == QDF_SWAP_U16(QDF_NBUF_TRAC_DHCP_SRV_PORT)) &&
	     (dport == QDF_SWAP_U16(QDF_NBUF_TRAC_DHCP_CLI_PORT))) ||
	    ((sport == QDF_SWAP_U16(QDF_NBUF_TRAC_DHCP_CLI_PORT)) &&
	     (dport == QDF_SWAP_U16(QDF_NBUF_TRAC_DHCP_SRV_PORT))))
		return true;
	else
		return false;
}
qdf_export_symbol(__qdf_nbuf_data_is_ipv4_dhcp_pkt);

/**
 * qdf_is_eapol_type() - check if packet is EAPOL
 * @type: Packet type
 *
 * This api is to check if frame is EAPOL packet type.
 *
 * Return: true if it is EAPOL frame
 *         false otherwise.
 */
#ifdef BIG_ENDIAN_HOST
static inline bool qdf_is_eapol_type(uint16_t type)
{
	return (type == QDF_NBUF_TRAC_EAPOL_ETH_TYPE);
}
#else
static inline bool qdf_is_eapol_type(uint16_t type)
{
	return (type == QDF_SWAP_U16(QDF_NBUF_TRAC_EAPOL_ETH_TYPE));
}
#endif

bool __qdf_nbuf_data_is_ipv4_eapol_pkt(uint8_t *data)
{
	uint16_t ether_type;

	ether_type = __qdf_nbuf_get_ether_type(data);

	return qdf_is_eapol_type(ether_type);
}
qdf_export_symbol(__qdf_nbuf_data_is_ipv4_eapol_pkt);

bool __qdf_nbuf_is_ipv4_wapi_pkt(struct sk_buff *skb)
{
	uint16_t ether_type;

	ether_type = (uint16_t)(*(uint16_t *)(skb->data +
				QDF_NBUF_TRAC_ETH_TYPE_OFFSET));

	if (ether_type == QDF_SWAP_U16(QDF_NBUF_TRAC_WAPI_ETH_TYPE))
		return true;
	else
		return false;
}
qdf_export_symbol(__qdf_nbuf_is_ipv4_wapi_pkt);

/**
 * qdf_nbuf_is_ipv6_vlan_pkt() - check whether packet is vlan IPV6
 * @data: Pointer to network data buffer
 *
 * This api is for vlan header included ipv6 packet.
 *
 * Return: true if packet is vlan header included IPV6
 *	   false otherwise.
 */
static bool qdf_nbuf_is_ipv6_vlan_pkt(uint8_t *data)
{
	uint16_t ether_type;

	ether_type = *(uint16_t *)(data + QDF_NBUF_TRAC_ETH_TYPE_OFFSET);

	if (unlikely(ether_type == QDF_SWAP_U16(QDF_ETH_TYPE_8021Q))) {
		ether_type = *(uint16_t *)(data +
					   QDF_NBUF_TRAC_VLAN_ETH_TYPE_OFFSET);

		if (ether_type == QDF_SWAP_U16(QDF_NBUF_TRAC_IPV6_ETH_TYPE))
			return true;
	}
	return false;
}

/**
 * qdf_nbuf_is_ipv4_vlan_pkt() - check whether packet is vlan IPV4
 * @data: Pointer to network data buffer
 *
 * This api is for vlan header included ipv4 packet.
 *
 * Return: true if packet is vlan header included IPV4
 *	   false otherwise.
 */
static bool qdf_nbuf_is_ipv4_vlan_pkt(uint8_t *data)
{
	uint16_t ether_type;

	ether_type = *(uint16_t *)(data + QDF_NBUF_TRAC_ETH_TYPE_OFFSET);

	if (unlikely(ether_type == QDF_SWAP_U16(QDF_ETH_TYPE_8021Q))) {
		ether_type = *(uint16_t *)(data +
					   QDF_NBUF_TRAC_VLAN_ETH_TYPE_OFFSET);

		if (ether_type == QDF_SWAP_U16(QDF_NBUF_TRAC_IPV4_ETH_TYPE))
			return true;
	}
	return false;
}

bool __qdf_nbuf_data_is_ipv4_igmp_pkt(uint8_t *data)
{
	uint8_t pkt_type;

	if (__qdf_nbuf_data_is_ipv4_pkt(data)) {
		pkt_type = (uint8_t)(*(uint8_t *)(data +
				QDF_NBUF_TRAC_IPV4_PROTO_TYPE_OFFSET));
		goto is_igmp;
	}

	if (qdf_nbuf_is_ipv4_vlan_pkt(data)) {
		pkt_type = (uint8_t)(*(uint8_t *)(
				data +
				QDF_NBUF_TRAC_VLAN_IPV4_PROTO_TYPE_OFFSET));
		goto is_igmp;
	}

	return false;
is_igmp:
	if (pkt_type == QDF_NBUF_TRAC_IGMP_TYPE)
		return true;

	return false;
}

qdf_export_symbol(__qdf_nbuf_data_is_ipv4_igmp_pkt);

bool __qdf_nbuf_data_is_ipv6_igmp_pkt(uint8_t *data)
{
	uint8_t pkt_type;
	uint8_t next_hdr;

	if (__qdf_nbuf_data_is_ipv6_pkt(data)) {
		pkt_type = (uint8_t)(*(uint8_t *)(data +
				QDF_NBUF_TRAC_IPV6_PROTO_TYPE_OFFSET));
		next_hdr = (uint8_t)(*(uint8_t *)(
				data +
				QDF_NBUF_TRAC_IPV6_OFFSET +
				QDF_NBUF_TRAC_IPV6_HEADER_SIZE));
		goto is_mld;
	}

	if (qdf_nbuf_is_ipv6_vlan_pkt(data)) {
		pkt_type = (uint8_t)(*(uint8_t *)(
				data +
				QDF_NBUF_TRAC_VLAN_IPV6_PROTO_TYPE_OFFSET));
		next_hdr = (uint8_t)(*(uint8_t *)(
				data +
				QDF_NBUF_TRAC_VLAN_IPV6_OFFSET +
				QDF_NBUF_TRAC_IPV6_HEADER_SIZE));
		goto is_mld;
	}

	return false;
is_mld:
	if (pkt_type == QDF_NBUF_TRAC_ICMPV6_TYPE)
		return true;
	if ((pkt_type == QDF_NBUF_TRAC_HOPOPTS_TYPE) &&
	    (next_hdr == QDF_NBUF_TRAC_ICMPV6_TYPE))
		return true;

	return false;
}

qdf_export_symbol(__qdf_nbuf_data_is_ipv6_igmp_pkt);

bool __qdf_nbuf_is_ipv4_igmp_leave_pkt(__qdf_nbuf_t buf)
{
	qdf_ether_header_t *eh = NULL;
	uint16_t ether_type;
	uint8_t eth_hdr_size = sizeof(qdf_ether_header_t);

	eh = (qdf_ether_header_t *)qdf_nbuf_data(buf);
	ether_type = eh->ether_type;

	if (ether_type == htons(ETH_P_8021Q)) {
		struct vlan_ethhdr *veth =
				(struct vlan_ethhdr *)qdf_nbuf_data(buf);
		ether_type = veth->h_vlan_encapsulated_proto;
		eth_hdr_size = sizeof(struct vlan_ethhdr);
	}

	if (ether_type == QDF_SWAP_U16(QDF_NBUF_TRAC_IPV4_ETH_TYPE)) {
		struct iphdr *iph = NULL;
		struct igmphdr *ih = NULL;

		iph = (struct iphdr *)(qdf_nbuf_data(buf) + eth_hdr_size);
		ih = (struct igmphdr *)((uint8_t *)iph + iph->ihl * 4);
		switch (ih->type) {
		case IGMP_HOST_LEAVE_MESSAGE:
			return true;
		case IGMPV3_HOST_MEMBERSHIP_REPORT:
		{
			struct igmpv3_report *ihv3 = (struct igmpv3_report *)ih;
			struct igmpv3_grec *grec = NULL;
			int num = 0;
			int i = 0;
			int len = 0;
			int type = 0;

			num = ntohs(ihv3->ngrec);
			for (i = 0; i < num; i++) {
				grec = (void *)((uint8_t *)(ihv3->grec) + len);
				type = grec->grec_type;
				if ((type == IGMPV3_MODE_IS_INCLUDE) ||
				    (type == IGMPV3_CHANGE_TO_INCLUDE))
					return true;

				len += sizeof(struct igmpv3_grec);
				len += ntohs(grec->grec_nsrcs) * 4;
			}
			break;
		}
		default:
			break;
		}
	}

	return false;
}

qdf_export_symbol(__qdf_nbuf_is_ipv4_igmp_leave_pkt);

bool __qdf_nbuf_is_ipv6_igmp_leave_pkt(__qdf_nbuf_t buf)
{
	qdf_ether_header_t *eh = NULL;
	uint16_t ether_type;
	uint8_t eth_hdr_size = sizeof(qdf_ether_header_t);

	eh = (qdf_ether_header_t *)qdf_nbuf_data(buf);
	ether_type = eh->ether_type;

	if (ether_type == htons(ETH_P_8021Q)) {
		struct vlan_ethhdr *veth =
				(struct vlan_ethhdr *)qdf_nbuf_data(buf);
		ether_type = veth->h_vlan_encapsulated_proto;
		eth_hdr_size = sizeof(struct vlan_ethhdr);
	}

	if (ether_type == QDF_SWAP_U16(QDF_NBUF_TRAC_IPV6_ETH_TYPE)) {
		struct ipv6hdr *ip6h = NULL;
		struct icmp6hdr *icmp6h = NULL;
		uint8_t nexthdr;
		uint16_t frag_off = 0;
		int offset;
		qdf_nbuf_t buf_copy = NULL;

		ip6h = (struct ipv6hdr *)(qdf_nbuf_data(buf) + eth_hdr_size);
		if (ip6h->nexthdr != IPPROTO_HOPOPTS ||
		    ip6h->payload_len == 0)
			return false;

		buf_copy = qdf_nbuf_copy(buf);
		if (qdf_likely(!buf_copy))
			return false;

		nexthdr = ip6h->nexthdr;
		offset = ipv6_skip_exthdr(buf_copy,
					  eth_hdr_size + sizeof(*ip6h),
					  &nexthdr,
					  &frag_off);
		qdf_nbuf_free(buf_copy);
		if (offset < 0 || nexthdr != IPPROTO_ICMPV6)
			return false;

		icmp6h = (struct icmp6hdr *)(qdf_nbuf_data(buf) + offset);

		switch (icmp6h->icmp6_type) {
		case ICMPV6_MGM_REDUCTION:
			return true;
		case ICMPV6_MLD2_REPORT:
		{
			struct mld2_report *mh = NULL;
			struct mld2_grec *grec = NULL;
			int num = 0;
			int i = 0;
			int len = 0;
			int type = -1;

			mh = (struct mld2_report *)icmp6h;
			num = ntohs(mh->mld2r_ngrec);
			for (i = 0; i < num; i++) {
				grec = (void *)(((uint8_t *)mh->mld2r_grec) +
						len);
				type = grec->grec_type;
				if ((type == MLD2_MODE_IS_INCLUDE) ||
				    (type == MLD2_CHANGE_TO_INCLUDE))
					return true;
				else if (type == MLD2_BLOCK_OLD_SOURCES)
					return true;

				len += sizeof(struct mld2_grec);
				len += ntohs(grec->grec_nsrcs) *
						sizeof(struct in6_addr);
			}
			break;
		}
		default:
			break;
		}
	}

	return false;
}

qdf_export_symbol(__qdf_nbuf_is_ipv6_igmp_leave_pkt);

bool __qdf_nbuf_is_ipv4_tdls_pkt(struct sk_buff *skb)
{
	uint16_t ether_type;

	ether_type = *(uint16_t *)(skb->data +
				QDF_NBUF_TRAC_ETH_TYPE_OFFSET);

	if (ether_type == QDF_SWAP_U16(QDF_NBUF_TRAC_TDLS_ETH_TYPE))
		return true;
	else
		return false;
}
qdf_export_symbol(__qdf_nbuf_is_ipv4_tdls_pkt);

bool __qdf_nbuf_data_is_ipv4_arp_pkt(uint8_t *data)
{
	uint16_t ether_type;

	ether_type = __qdf_nbuf_get_ether_type(data);

	if (ether_type == QDF_SWAP_U16(QDF_NBUF_TRAC_ARP_ETH_TYPE))
		return true;
	else
		return false;
}
qdf_export_symbol(__qdf_nbuf_data_is_ipv4_arp_pkt);

bool __qdf_nbuf_data_is_arp_req(uint8_t *data)
{
	uint16_t op_code;

	op_code = (uint16_t)(*(uint16_t *)(data +
				QDF_NBUF_PKT_ARP_OPCODE_OFFSET));

	if (op_code == QDF_SWAP_U16(QDF_NBUF_PKT_ARPOP_REQ))
		return true;
	return false;
}

bool __qdf_nbuf_data_is_arp_rsp(uint8_t *data)
{
	uint16_t op_code;

	op_code = (uint16_t)(*(uint16_t *)(data +
				QDF_NBUF_PKT_ARP_OPCODE_OFFSET));

	if (op_code == QDF_SWAP_U16(QDF_NBUF_PKT_ARPOP_REPLY))
		return true;
	return false;
}

uint32_t  __qdf_nbuf_get_arp_src_ip(uint8_t *data)
{
	uint32_t src_ip;

	src_ip = (uint32_t)(*(uint32_t *)(data +
				QDF_NBUF_PKT_ARP_SRC_IP_OFFSET));

	return src_ip;
}

uint32_t  __qdf_nbuf_get_arp_tgt_ip(uint8_t *data)
{
	uint32_t tgt_ip;

	tgt_ip = (uint32_t)(*(uint32_t *)(data +
				QDF_NBUF_PKT_ARP_TGT_IP_OFFSET));

	return tgt_ip;
}

uint8_t *__qdf_nbuf_get_dns_domain_name(uint8_t *data, uint32_t len)
{
	uint8_t *domain_name;

	domain_name = (uint8_t *)
			(data + QDF_NBUF_PKT_DNS_NAME_OVER_UDP_OFFSET);
	return domain_name;
}

bool __qdf_nbuf_data_is_dns_query(uint8_t *data)
{
	uint16_t op_code;
	uint16_t tgt_port;

	tgt_port = (uint16_t)(*(uint16_t *)(data +
				QDF_NBUF_PKT_DNS_DST_PORT_OFFSET));
	/* Standard DNS query always happen on Dest Port 53. */
	if (tgt_port == QDF_SWAP_U16(QDF_NBUF_PKT_DNS_STANDARD_PORT)) {
		op_code = (uint16_t)(*(uint16_t *)(data +
				QDF_NBUF_PKT_DNS_OVER_UDP_OPCODE_OFFSET));
		if ((QDF_SWAP_U16(op_code) & QDF_NBUF_PKT_DNSOP_BITMAP) ==
				QDF_NBUF_PKT_DNSOP_STANDARD_QUERY)
			return true;
	}
	return false;
}

bool __qdf_nbuf_data_is_dns_response(uint8_t *data)
{
	uint16_t op_code;
	uint16_t src_port;

	src_port = (uint16_t)(*(uint16_t *)(data +
				QDF_NBUF_PKT_DNS_SRC_PORT_OFFSET));
	/* Standard DNS response always comes on Src Port 53. */
	if (src_port == QDF_SWAP_U16(QDF_NBUF_PKT_DNS_STANDARD_PORT)) {
		op_code = (uint16_t)(*(uint16_t *)(data +
				QDF_NBUF_PKT_DNS_OVER_UDP_OPCODE_OFFSET));

		if ((QDF_SWAP_U16(op_code) & QDF_NBUF_PKT_DNSOP_BITMAP) ==
				QDF_NBUF_PKT_DNSOP_STANDARD_RESPONSE)
			return true;
	}
	return false;
}

bool __qdf_nbuf_data_is_tcp_fin(uint8_t *data)
{
	uint8_t op_code;

	op_code = (uint8_t)(*(uint8_t *)(data +
				QDF_NBUF_PKT_TCP_OPCODE_OFFSET));

	if (op_code == QDF_NBUF_PKT_TCPOP_FIN)
		return true;

	return false;
}

bool __qdf_nbuf_data_is_tcp_fin_ack(uint8_t *data)
{
	uint8_t op_code;

	op_code = (uint8_t)(*(uint8_t *)(data +
				QDF_NBUF_PKT_TCP_OPCODE_OFFSET));

	if (op_code == QDF_NBUF_PKT_TCPOP_FIN_ACK)
		return true;

	return false;
}

bool __qdf_nbuf_data_is_tcp_syn(uint8_t *data)
{
	uint8_t op_code;

	op_code = (uint8_t)(*(uint8_t *)(data +
				QDF_NBUF_PKT_TCP_OPCODE_OFFSET));

	if (op_code == QDF_NBUF_PKT_TCPOP_SYN)
		return true;
	return false;
}

bool __qdf_nbuf_data_is_tcp_syn_ack(uint8_t *data)
{
	uint8_t op_code;

	op_code = (uint8_t)(*(uint8_t *)(data +
				QDF_NBUF_PKT_TCP_OPCODE_OFFSET));

	if (op_code == QDF_NBUF_PKT_TCPOP_SYN_ACK)
		return true;
	return false;
}

bool __qdf_nbuf_data_is_tcp_rst(uint8_t *data)
{
	uint8_t op_code;

	op_code = (uint8_t)(*(uint8_t *)(data +
				QDF_NBUF_PKT_TCP_OPCODE_OFFSET));

	if (op_code == QDF_NBUF_PKT_TCPOP_RST)
		return true;

	return false;
}

bool __qdf_nbuf_data_is_tcp_ack(uint8_t *data)
{
	uint8_t op_code;

	op_code = (uint8_t)(*(uint8_t *)(data +
				QDF_NBUF_PKT_TCP_OPCODE_OFFSET));

	if (op_code == QDF_NBUF_PKT_TCPOP_ACK)
		return true;
	return false;
}

uint16_t __qdf_nbuf_data_get_tcp_src_port(uint8_t *data)
{
	uint16_t src_port;

	src_port = (uint16_t)(*(uint16_t *)(data +
				QDF_NBUF_PKT_TCP_SRC_PORT_OFFSET));

	return src_port;
}

uint16_t __qdf_nbuf_data_get_tcp_dst_port(uint8_t *data)
{
	uint16_t tgt_port;

	tgt_port = (uint16_t)(*(uint16_t *)(data +
				QDF_NBUF_PKT_TCP_DST_PORT_OFFSET));

	return tgt_port;
}

bool __qdf_nbuf_data_is_icmpv4_req(uint8_t *data)
{
	uint8_t op_code;

	op_code = (uint8_t)(*(uint8_t *)(data +
				QDF_NBUF_PKT_ICMPv4_OPCODE_OFFSET));

	if (op_code == QDF_NBUF_PKT_ICMPv4OP_REQ)
		return true;
	return false;
}

bool __qdf_nbuf_data_is_icmpv4_rsp(uint8_t *data)
{
	uint8_t op_code;

	op_code = (uint8_t)(*(uint8_t *)(data +
				QDF_NBUF_PKT_ICMPv4_OPCODE_OFFSET));

	if (op_code == QDF_NBUF_PKT_ICMPv4OP_REPLY)
		return true;
	return false;
}

bool __qdf_nbuf_data_is_icmpv4_redirect(uint8_t *data)
{
	uint8_t op_code;

	op_code = (uint8_t)(*(uint8_t *)(data +
				QDF_NBUF_PKT_ICMPv4_OPCODE_OFFSET));

	if (op_code == QDF_NBUF_PKT_ICMPV4_REDIRECT)
		return true;
	return false;
}

qdf_export_symbol(__qdf_nbuf_data_is_icmpv4_redirect);

bool __qdf_nbuf_data_is_icmpv6_redirect(uint8_t *data)
{
	uint8_t subtype;

	subtype = (uint8_t)(*(uint8_t *)(data + ICMPV6_SUBTYPE_OFFSET));

	if (subtype == ICMPV6_REDIRECT)
		return true;
	return false;
}

qdf_export_symbol(__qdf_nbuf_data_is_icmpv6_redirect);

uint32_t __qdf_nbuf_get_icmpv4_src_ip(uint8_t *data)
{
	uint32_t src_ip;

	src_ip = (uint32_t)(*(uint32_t *)(data +
				QDF_NBUF_PKT_ICMPv4_SRC_IP_OFFSET));

	return src_ip;
}

uint32_t __qdf_nbuf_get_icmpv4_tgt_ip(uint8_t *data)
{
	uint32_t tgt_ip;

	tgt_ip = (uint32_t)(*(uint32_t *)(data +
				QDF_NBUF_PKT_ICMPv4_TGT_IP_OFFSET));

	return tgt_ip;
}

bool __qdf_nbuf_data_is_ipv6_pkt(uint8_t *data)
{
	uint16_t ether_type;

	ether_type = (uint16_t)(*(uint16_t *)(data +
				QDF_NBUF_TRAC_ETH_TYPE_OFFSET));

	if (ether_type == QDF_SWAP_U16(QDF_NBUF_TRAC_IPV6_ETH_TYPE))
		return true;
	else
		return false;
}
qdf_export_symbol(__qdf_nbuf_data_is_ipv6_pkt);

bool __qdf_nbuf_data_is_ipv6_dhcp_pkt(uint8_t *data)
{
	uint16_t sport;
	uint16_t dport;
	uint8_t ipv6_offset;

	if (!__qdf_nbuf_data_is_ipv6_pkt(data))
		return false;

	ipv6_offset = __qdf_nbuf_get_ip_offset(data);
	sport = *(uint16_t *)(data + ipv6_offset +
			      QDF_NBUF_TRAC_IPV6_HEADER_SIZE);
	dport = *(uint16_t *)(data + ipv6_offset +
			      QDF_NBUF_TRAC_IPV6_HEADER_SIZE +
			      sizeof(uint16_t));

	if (((sport == QDF_SWAP_U16(QDF_NBUF_TRAC_DHCP6_SRV_PORT)) &&
	     (dport == QDF_SWAP_U16(QDF_NBUF_TRAC_DHCP6_CLI_PORT))) ||
	    ((sport == QDF_SWAP_U16(QDF_NBUF_TRAC_DHCP6_CLI_PORT)) &&
	     (dport == QDF_SWAP_U16(QDF_NBUF_TRAC_DHCP6_SRV_PORT))))
		return true;
	else
		return false;
}
qdf_export_symbol(__qdf_nbuf_data_is_ipv6_dhcp_pkt);

bool __qdf_nbuf_data_is_ipv6_mdns_pkt(uint8_t *data)
{
	uint16_t sport;
	uint16_t dport;

	sport = *(uint16_t *)(data + QDF_NBUF_TRAC_IPV6_OFFSET +
				QDF_NBUF_TRAC_IPV6_HEADER_SIZE);
	dport = *(uint16_t *)(data + QDF_NBUF_TRAC_IPV6_OFFSET +
					QDF_NBUF_TRAC_IPV6_HEADER_SIZE +
					sizeof(uint16_t));

	if (sport == QDF_SWAP_U16(QDF_NBUF_TRAC_MDNS_SRC_N_DST_PORT) &&
	    dport == sport)
		return true;
	else
		return false;
}

qdf_export_symbol(__qdf_nbuf_data_is_ipv6_mdns_pkt);

bool __qdf_nbuf_data_is_ipv4_mcast_pkt(uint8_t *data)
{
	if (__qdf_nbuf_data_is_ipv4_pkt(data)) {
		uint32_t *dst_addr =
		      (uint32_t *)(data + QDF_NBUF_TRAC_IPV4_DEST_ADDR_OFFSET);

		/*
		 * Check first word of the IPV4 address and if it is
		 * equal to 0xE then it represents multicast IP.
		 */
		if ((*dst_addr &
		     QDF_SWAP_U32(QDF_NBUF_TRAC_IPV4_ADDR_BCAST_MASK)) ==
		     QDF_SWAP_U32(QDF_NBUF_TRAC_IPV4_ADDR_MCAST_MASK))
			return true;
		else
			return false;
	} else
		return false;
}

bool __qdf_nbuf_data_is_ipv6_mcast_pkt(uint8_t *data)
{
	if (__qdf_nbuf_data_is_ipv6_pkt(data)) {
		uint16_t *dst_addr;

		dst_addr = (uint16_t *)
			(data + QDF_NBUF_TRAC_IPV6_DEST_ADDR_OFFSET);

		/*
		 * Check first byte of the IP address and if it
		 * 0xFF then it is a IPV6 mcast packet.
		 */
		if ((*dst_addr & QDF_SWAP_U16(QDF_NBUF_TRAC_IPV6_DEST_ADDR)) ==
		    QDF_SWAP_U16(QDF_NBUF_TRAC_IPV6_DEST_ADDR))
			return true;
		else
			return false;
	} else
		return false;
}

bool __qdf_nbuf_data_is_icmp_pkt(uint8_t *data)
{
	if (__qdf_nbuf_data_is_ipv4_pkt(data)) {
		uint8_t pkt_type;

		pkt_type = (uint8_t)(*(uint8_t *)(data +
				QDF_NBUF_TRAC_IPV4_PROTO_TYPE_OFFSET));

		if (pkt_type == QDF_NBUF_TRAC_ICMP_TYPE)
			return true;
		else
			return false;
	} else
		return false;
}

qdf_export_symbol(__qdf_nbuf_data_is_icmp_pkt);

bool __qdf_nbuf_data_is_icmpv6_pkt(uint8_t *data)
{
	if (__qdf_nbuf_data_is_ipv6_pkt(data)) {
		uint8_t pkt_type;

		pkt_type = (uint8_t)(*(uint8_t *)(data +
				QDF_NBUF_TRAC_IPV6_PROTO_TYPE_OFFSET));

		if (pkt_type == QDF_NBUF_TRAC_ICMPV6_TYPE)
			return true;
		else
			return false;
	} else
		return false;
}

qdf_export_symbol(__qdf_nbuf_data_is_icmpv6_pkt);

bool __qdf_nbuf_data_is_ipv4_udp_pkt(uint8_t *data)
{
	if (__qdf_nbuf_data_is_ipv4_pkt(data)) {
		uint8_t pkt_type;

		pkt_type = (uint8_t)(*(uint8_t *)(data +
				QDF_NBUF_TRAC_IPV4_PROTO_TYPE_OFFSET));

		if (pkt_type == QDF_NBUF_TRAC_UDP_TYPE)
			return true;
		else
			return false;
	} else
		return false;
}

bool __qdf_nbuf_data_is_ipv4_tcp_pkt(uint8_t *data)
{
	if (__qdf_nbuf_data_is_ipv4_pkt(data)) {
		uint8_t pkt_type;

		pkt_type = (uint8_t)(*(uint8_t *)(data +
				QDF_NBUF_TRAC_IPV4_PROTO_TYPE_OFFSET));

		if (pkt_type == QDF_NBUF_TRAC_TCP_TYPE)
			return true;
		else
			return false;
	} else
		return false;
}

bool __qdf_nbuf_data_is_ipv6_udp_pkt(uint8_t *data)
{
	if (__qdf_nbuf_data_is_ipv6_pkt(data)) {
		uint8_t pkt_type;

		pkt_type = (uint8_t)(*(uint8_t *)(data +
				QDF_NBUF_TRAC_IPV6_PROTO_TYPE_OFFSET));

		if (pkt_type == QDF_NBUF_TRAC_UDP_TYPE)
			return true;
		else
			return false;
	} else
		return false;
}

bool __qdf_nbuf_data_is_ipv6_tcp_pkt(uint8_t *data)
{
	if (__qdf_nbuf_data_is_ipv6_pkt(data)) {
		uint8_t pkt_type;

		pkt_type = (uint8_t)(*(uint8_t *)(data +
				QDF_NBUF_TRAC_IPV6_PROTO_TYPE_OFFSET));

		if (pkt_type == QDF_NBUF_TRAC_TCP_TYPE)
			return true;
		else
			return false;
	} else
		return false;
}

bool __qdf_nbuf_is_bcast_pkt(qdf_nbuf_t nbuf)
{
	struct ethhdr *eh = (struct ethhdr *)qdf_nbuf_data(nbuf);
	return qdf_is_macaddr_broadcast((struct qdf_mac_addr *)eh->h_dest);
}
qdf_export_symbol(__qdf_nbuf_is_bcast_pkt);

bool __qdf_nbuf_is_mcast_replay(qdf_nbuf_t nbuf)
{
	struct sk_buff *skb = (struct sk_buff *)nbuf;
	struct ethhdr *eth = eth_hdr(skb);

	if (qdf_likely(skb->pkt_type != PACKET_MULTICAST))
		return false;

	if (qdf_unlikely(ether_addr_equal(eth->h_source, skb->dev->dev_addr)))
		return true;

	return false;
}

bool __qdf_nbuf_is_arp_local(struct sk_buff *skb)
{
	struct arphdr *arp;
	struct in_ifaddr **ifap = NULL;
	struct in_ifaddr *ifa = NULL;
	struct in_device *in_dev;
	unsigned char *arp_ptr;
	__be32 tip;

	arp = (struct arphdr *)skb->data;
	if (arp->ar_op == htons(ARPOP_REQUEST)) {
		/* if fail to acquire rtnl lock, assume it's local arp */
		if (!rtnl_trylock())
			return true;

		in_dev = __in_dev_get_rtnl(skb->dev);
		if (in_dev) {
			for (ifap = &in_dev->ifa_list; (ifa = *ifap) != NULL;
				ifap = &ifa->ifa_next) {
				if (!strcmp(skb->dev->name, ifa->ifa_label))
					break;
			}
		}

		if (ifa && ifa->ifa_local) {
			arp_ptr = (unsigned char *)(arp + 1);
			arp_ptr += (skb->dev->addr_len + 4 +
					skb->dev->addr_len);
			memcpy(&tip, arp_ptr, 4);
			qdf_debug("ARP packet: local IP: %x dest IP: %x",
				  ifa->ifa_local, tip);
			if (ifa->ifa_local == tip) {
				rtnl_unlock();
				return true;
			}
		}
		rtnl_unlock();
	}

	return false;
}

/**
 * __qdf_nbuf_data_get_tcp_hdr_len() - get TCP header length
 * @data: pointer to data of network buffer
 * @tcp_hdr_len_offset: bytes offset for tcp header length of ethernet packets
 *
 * Return: TCP header length in unit of byte
 */
static inline
uint8_t __qdf_nbuf_data_get_tcp_hdr_len(uint8_t *data,
					uint8_t tcp_hdr_len_offset)
{
	uint8_t tcp_hdr_len;

	tcp_hdr_len =
		*((uint8_t *)(data + tcp_hdr_len_offset));

	tcp_hdr_len = ((tcp_hdr_len & QDF_NBUF_PKT_TCP_HDR_LEN_MASK) >>
		       QDF_NBUF_PKT_TCP_HDR_LEN_LSB) *
		       QDF_NBUF_PKT_TCP_HDR_LEN_UNIT;

	return tcp_hdr_len;
}

bool __qdf_nbuf_is_ipv4_v6_pure_tcp_ack(struct sk_buff *skb)
{
	bool is_tcp_ack = false;
	uint8_t op_code, tcp_hdr_len;
	uint16_t ip_payload_len;
	uint8_t *data = skb->data;

	/*
	 * If packet length > TCP ACK max length or it's nonlinearized,
	 * then it must not be TCP ACK.
	 */
	if (qdf_nbuf_len(skb) > QDF_NBUF_PKT_TCP_ACK_MAX_LEN ||
	    qdf_nbuf_is_nonlinear(skb))
		return false;

	if (qdf_nbuf_is_ipv4_tcp_pkt(skb)) {
		ip_payload_len =
			QDF_SWAP_U16(*((uint16_t *)(data +
				     QDF_NBUF_TRAC_IPV4_TOTAL_LEN_OFFSET)))
					- QDF_NBUF_TRAC_IPV4_HEADER_SIZE;

		tcp_hdr_len = __qdf_nbuf_data_get_tcp_hdr_len(
					data,
					QDF_NBUF_PKT_IPV4_TCP_HDR_LEN_OFFSET);

		op_code = (uint8_t)(*(uint8_t *)(data +
				QDF_NBUF_PKT_IPV4_TCP_OPCODE_OFFSET));

		if (ip_payload_len == tcp_hdr_len &&
		    op_code == QDF_NBUF_PKT_TCPOP_ACK)
			is_tcp_ack = true;

	} else if (qdf_nbuf_is_ipv6_tcp_pkt(skb)) {
		ip_payload_len =
			QDF_SWAP_U16(*((uint16_t *)(data +
				QDF_NBUF_TRAC_IPV6_PAYLOAD_LEN_OFFSET)));

		tcp_hdr_len = __qdf_nbuf_data_get_tcp_hdr_len(
					data,
					QDF_NBUF_PKT_IPV6_TCP_HDR_LEN_OFFSET);
		op_code = (uint8_t)(*(uint8_t *)(data +
				QDF_NBUF_PKT_IPV6_TCP_OPCODE_OFFSET));

		if (ip_payload_len == tcp_hdr_len &&
		    op_code == QDF_NBUF_PKT_TCPOP_ACK)
			is_tcp_ack = true;
	}

	return is_tcp_ack;
}

#ifdef QCA_DP_NBUF_FAST_RECYCLE_CHECK
bool qdf_nbuf_fast_xmit(qdf_nbuf_t nbuf)
{
	return nbuf->fast_xmit;
}

qdf_export_symbol(qdf_nbuf_fast_xmit);

void qdf_nbuf_set_fast_xmit(qdf_nbuf_t nbuf, int value)
{
	nbuf->fast_xmit = value;
}

qdf_export_symbol(qdf_nbuf_set_fast_xmit);
#else
bool qdf_nbuf_fast_xmit(qdf_nbuf_t nbuf)
{
	return false;
}

qdf_export_symbol(qdf_nbuf_fast_xmit);

void qdf_nbuf_set_fast_xmit(qdf_nbuf_t nbuf, int value)
{
}

qdf_export_symbol(qdf_nbuf_set_fast_xmit);
#endif

#ifdef NBUF_MEMORY_DEBUG

static spinlock_t g_qdf_net_buf_track_lock[QDF_NET_BUF_TRACK_MAX_SIZE];

static QDF_NBUF_TRACK *gp_qdf_net_buf_track_tbl[QDF_NET_BUF_TRACK_MAX_SIZE];
static struct kmem_cache *nbuf_tracking_cache;
static QDF_NBUF_TRACK *qdf_net_buf_track_free_list;
static spinlock_t qdf_net_buf_track_free_list_lock;
static uint32_t qdf_net_buf_track_free_list_count;
static uint32_t qdf_net_buf_track_used_list_count;
static uint32_t qdf_net_buf_track_max_used;
static uint32_t qdf_net_buf_track_max_free;
static uint32_t qdf_net_buf_track_max_allocated;
static uint32_t qdf_net_buf_track_fail_count;

/**
 * update_max_used() - update qdf_net_buf_track_max_used tracking variable
 *
 * tracks the max number of network buffers that the wlan driver was tracking
 * at any one time.
 *
 * Return: none
 */
static inline void update_max_used(void)
{
	int sum;

	if (qdf_net_buf_track_max_used <
	    qdf_net_buf_track_used_list_count)
		qdf_net_buf_track_max_used = qdf_net_buf_track_used_list_count;
	sum = qdf_net_buf_track_free_list_count +
		qdf_net_buf_track_used_list_count;
	if (qdf_net_buf_track_max_allocated < sum)
		qdf_net_buf_track_max_allocated = sum;
}

/**
 * update_max_free() - update qdf_net_buf_track_free_list_count
 *
 * tracks the max number tracking buffers kept in the freelist.
 *
 * Return: none
 */
static inline void update_max_free(void)
{
	if (qdf_net_buf_track_max_free <
	    qdf_net_buf_track_free_list_count)
		qdf_net_buf_track_max_free = qdf_net_buf_track_free_list_count;
}

/**
 * qdf_nbuf_track_alloc() - allocate a cookie to track nbufs allocated by wlan
 *
 * This function pulls from a freelist if possible and uses kmem_cache_alloc.
 * This function also ads fexibility to adjust the allocation and freelist
 * scheems.
 *
 * Return: a pointer to an unused QDF_NBUF_TRACK structure may not be zeroed.
 */
static QDF_NBUF_TRACK *qdf_nbuf_track_alloc(void)
{
	int flags = GFP_KERNEL;
	unsigned long irq_flag;
	QDF_NBUF_TRACK *new_node = NULL;

	spin_lock_irqsave(&qdf_net_buf_track_free_list_lock, irq_flag);
	qdf_net_buf_track_used_list_count++;
	if (qdf_net_buf_track_free_list) {
		new_node = qdf_net_buf_track_free_list;
		qdf_net_buf_track_free_list =
			qdf_net_buf_track_free_list->p_next;
		qdf_net_buf_track_free_list_count--;
	}
	update_max_used();
	spin_unlock_irqrestore(&qdf_net_buf_track_free_list_lock, irq_flag);

	if (new_node)
		return new_node;

	if (in_interrupt() || irqs_disabled() || in_atomic())
		flags = GFP_ATOMIC;

	return kmem_cache_alloc(nbuf_tracking_cache, flags);
}

/* FREEQ_POOLSIZE initial and minimum desired freelist poolsize */
#define FREEQ_POOLSIZE 2048

/**
 * qdf_nbuf_track_free() - free the nbuf tracking cookie.
 * @node: nbuf tracking node
 *
 * Matches calls to qdf_nbuf_track_alloc.
 * Either frees the tracking cookie to kernel or an internal
 * freelist based on the size of the freelist.
 *
 * Return: none
 */
static void qdf_nbuf_track_free(QDF_NBUF_TRACK *node)
{
	unsigned long irq_flag;

	if (!node)
		return;

	/* Try to shrink the freelist if free_list_count > than FREEQ_POOLSIZE
	 * only shrink the freelist if it is bigger than twice the number of
	 * nbufs in use. If the driver is stalling in a consistent bursty
	 * fashion, this will keep 3/4 of thee allocations from the free list
	 * while also allowing the system to recover memory as less frantic
	 * traffic occurs.
	 */

	spin_lock_irqsave(&qdf_net_buf_track_free_list_lock, irq_flag);

	qdf_net_buf_track_used_list_count--;
	if (qdf_net_buf_track_free_list_count > FREEQ_POOLSIZE &&
	   (qdf_net_buf_track_free_list_count >
	    qdf_net_buf_track_used_list_count << 1)) {
		kmem_cache_free(nbuf_tracking_cache, node);
	} else {
		node->p_next = qdf_net_buf_track_free_list;
		qdf_net_buf_track_free_list = node;
		qdf_net_buf_track_free_list_count++;
	}
	update_max_free();
	spin_unlock_irqrestore(&qdf_net_buf_track_free_list_lock, irq_flag);
}

/**
 * qdf_nbuf_track_prefill() - prefill the nbuf tracking cookie freelist
 *
 * Removes a 'warmup time' characteristic of the freelist.  Prefilling
 * the freelist first makes it performant for the first iperf udp burst
 * as well as steady state.
 *
 * Return: None
 */
static void qdf_nbuf_track_prefill(void)
{
	int i;
	QDF_NBUF_TRACK *node, *head;

	/* prepopulate the freelist */
	head = NULL;
	for (i = 0; i < FREEQ_POOLSIZE; i++) {
		node = qdf_nbuf_track_alloc();
		if (!node)
			continue;
		node->p_next = head;
		head = node;
	}
	while (head) {
		node = head->p_next;
		qdf_nbuf_track_free(head);
		head = node;
	}

	/* prefilled buffers should not count as used */
	qdf_net_buf_track_max_used = 0;
}

/**
 * qdf_nbuf_track_memory_manager_create() - manager for nbuf tracking cookies
 *
 * This initializes the memory manager for the nbuf tracking cookies.  Because
 * these cookies are all the same size and only used in this feature, we can
 * use a kmem_cache to provide tracking as well as to speed up allocations.
 * To avoid the overhead of allocating and freeing the buffers (including SLUB
 * features) a freelist is prepopulated here.
 *
 * Return: None
 */
static void qdf_nbuf_track_memory_manager_create(void)
{
	spin_lock_init(&qdf_net_buf_track_free_list_lock);
	nbuf_tracking_cache = kmem_cache_create("qdf_nbuf_tracking_cache",
						sizeof(QDF_NBUF_TRACK),
						0, 0, NULL);

	qdf_nbuf_track_prefill();
}

/**
 * qdf_nbuf_track_memory_manager_destroy() - manager for nbuf tracking cookies
 *
 * Empty the freelist and print out usage statistics when it is no longer
 * needed. Also the kmem_cache should be destroyed here so that it can warn if
 * any nbuf tracking cookies were leaked.
 *
 * Return: None
 */
static void qdf_nbuf_track_memory_manager_destroy(void)
{
	QDF_NBUF_TRACK *node, *tmp;
	unsigned long irq_flag;

	spin_lock_irqsave(&qdf_net_buf_track_free_list_lock, irq_flag);
	node = qdf_net_buf_track_free_list;

	if (qdf_net_buf_track_max_used > FREEQ_POOLSIZE * 4)
		qdf_print("%s: unexpectedly large max_used count %d",
			  __func__, qdf_net_buf_track_max_used);

	if (qdf_net_buf_track_max_used < qdf_net_buf_track_max_allocated)
		qdf_print("%s: %d unused trackers were allocated",
			  __func__,
			  qdf_net_buf_track_max_allocated -
			  qdf_net_buf_track_max_used);

	if (qdf_net_buf_track_free_list_count > FREEQ_POOLSIZE &&
	    qdf_net_buf_track_free_list_count > 3*qdf_net_buf_track_max_used/4)
		qdf_print("%s: check freelist shrinking functionality",
			  __func__);

	QDF_TRACE(QDF_MODULE_ID_QDF, QDF_TRACE_LEVEL_INFO,
		  "%s: %d residual freelist size",
		  __func__, qdf_net_buf_track_free_list_count);

	QDF_TRACE(QDF_MODULE_ID_QDF, QDF_TRACE_LEVEL_INFO,
		  "%s: %d max freelist size observed",
		  __func__, qdf_net_buf_track_max_free);

	QDF_TRACE(QDF_MODULE_ID_QDF, QDF_TRACE_LEVEL_INFO,
		  "%s: %d max buffers used observed",
		  __func__, qdf_net_buf_track_max_used);

	QDF_TRACE(QDF_MODULE_ID_QDF, QDF_TRACE_LEVEL_INFO,
		  "%s: %d max buffers allocated observed",
		  __func__, qdf_net_buf_track_max_allocated);

	while (node) {
		tmp = node;
		node = node->p_next;
		kmem_cache_free(nbuf_tracking_cache, tmp);
		qdf_net_buf_track_free_list_count--;
	}

	if (qdf_net_buf_track_free_list_count != 0)
		qdf_info("%d unfreed tracking memory lost in freelist",
			 qdf_net_buf_track_free_list_count);

	if (qdf_net_buf_track_used_list_count != 0)
		qdf_info("%d unfreed tracking memory still in use",
			 qdf_net_buf_track_used_list_count);

	spin_unlock_irqrestore(&qdf_net_buf_track_free_list_lock, irq_flag);
	kmem_cache_destroy(nbuf_tracking_cache);
	qdf_net_buf_track_free_list = NULL;
}

void qdf_net_buf_debug_init(void)
{
	uint32_t i;

	is_initial_mem_debug_disabled = qdf_mem_debug_config_get();

	if (is_initial_mem_debug_disabled)
		return;

	qdf_atomic_set(&qdf_nbuf_history_index, -1);

	qdf_nbuf_map_tracking_init();
	qdf_nbuf_smmu_map_tracking_init();
	qdf_nbuf_track_memory_manager_create();

	for (i = 0; i < QDF_NET_BUF_TRACK_MAX_SIZE; i++) {
		gp_qdf_net_buf_track_tbl[i] = NULL;
		spin_lock_init(&g_qdf_net_buf_track_lock[i]);
	}
}
qdf_export_symbol(qdf_net_buf_debug_init);

void qdf_net_buf_debug_exit(void)
{
	uint32_t i;
	uint32_t count = 0;
	unsigned long irq_flag;
	QDF_NBUF_TRACK *p_node;
	QDF_NBUF_TRACK *p_prev;

	if (is_initial_mem_debug_disabled)
		return;

	for (i = 0; i < QDF_NET_BUF_TRACK_MAX_SIZE; i++) {
		spin_lock_irqsave(&g_qdf_net_buf_track_lock[i], irq_flag);
		p_node = gp_qdf_net_buf_track_tbl[i];
		while (p_node) {
			p_prev = p_node;
			p_node = p_node->p_next;
			count++;
			qdf_info("SKB buf memory Leak@ Func %s, @Line %d, size %zu, nbuf %pK",
				 p_prev->func_name, p_prev->line_num,
				 p_prev->size, p_prev->net_buf);
			qdf_info("SKB leak map %s, line %d, unmap %s line %d mapped=%d",
				 p_prev->map_func_name,
				 p_prev->map_line_num,
				 p_prev->unmap_func_name,
				 p_prev->unmap_line_num,
				 p_prev->is_nbuf_mapped);
			qdf_nbuf_track_free(p_prev);
		}
		spin_unlock_irqrestore(&g_qdf_net_buf_track_lock[i], irq_flag);
	}

	qdf_nbuf_track_memory_manager_destroy();
	qdf_nbuf_map_tracking_deinit();
	qdf_nbuf_smmu_map_tracking_deinit();

#ifdef CONFIG_HALT_KMEMLEAK
	if (count) {
		qdf_err("%d SKBs leaked .. please fix the SKB leak", count);
		QDF_BUG(0);
	}
#endif
}
qdf_export_symbol(qdf_net_buf_debug_exit);

/**
 * qdf_net_buf_debug_hash() - hash network buffer pointer
 * @net_buf: network buffer
 *
 * Return: hash value
 */
static uint32_t qdf_net_buf_debug_hash(qdf_nbuf_t net_buf)
{
	uint32_t i;

	i = (uint32_t) (((uintptr_t) net_buf) >> 4);
	i += (uint32_t) (((uintptr_t) net_buf) >> 14);
	i &= (QDF_NET_BUF_TRACK_MAX_SIZE - 1);

	return i;
}

/**
 * qdf_net_buf_debug_look_up() - look up network buffer in debug hash table
 * @net_buf: network buffer
 *
 * Return: If skb is found in hash table then return pointer to network buffer
 *	else return %NULL
 */
static QDF_NBUF_TRACK *qdf_net_buf_debug_look_up(qdf_nbuf_t net_buf)
{
	uint32_t i;
	QDF_NBUF_TRACK *p_node;

	i = qdf_net_buf_debug_hash(net_buf);
	p_node = gp_qdf_net_buf_track_tbl[i];

	while (p_node) {
		if (p_node->net_buf == net_buf)
			return p_node;
		p_node = p_node->p_next;
	}

	return NULL;
}

void qdf_net_buf_debug_add_node(qdf_nbuf_t net_buf, size_t size,
				const char *func_name, uint32_t line_num)
{
	uint32_t i;
	unsigned long irq_flag;
	QDF_NBUF_TRACK *p_node;
	QDF_NBUF_TRACK *new_node;

	if (is_initial_mem_debug_disabled)
		return;

	new_node = qdf_nbuf_track_alloc();

	i = qdf_net_buf_debug_hash(net_buf);
	spin_lock_irqsave(&g_qdf_net_buf_track_lock[i], irq_flag);

	p_node = qdf_net_buf_debug_look_up(net_buf);

	if (p_node) {
		qdf_print("Double allocation of skb ! Already allocated from %pK %s %d current alloc from %pK %s %d",
			  p_node->net_buf, p_node->func_name, p_node->line_num,
			  net_buf, func_name, line_num);
		qdf_nbuf_track_free(new_node);
	} else {
		p_node = new_node;
		if (p_node) {
			p_node->net_buf = net_buf;
			qdf_str_lcopy(p_node->func_name, func_name,
				      QDF_MEM_FUNC_NAME_SIZE);
			p_node->line_num = line_num;
			p_node->is_nbuf_mapped = false;
			p_node->map_line_num = 0;
			p_node->unmap_line_num = 0;
			p_node->map_func_name[0] = '\0';
			p_node->unmap_func_name[0] = '\0';
			p_node->size = size;
			p_node->time = qdf_get_log_timestamp();
			qdf_net_buf_update_smmu_params(p_node);
			qdf_mem_skb_inc(size);
			p_node->p_next = gp_qdf_net_buf_track_tbl[i];
			gp_qdf_net_buf_track_tbl[i] = p_node;
		} else {
			qdf_net_buf_track_fail_count++;
			qdf_print(
				  "Mem alloc failed ! Could not track skb from %s %d of size %zu",
				  func_name, line_num, size);
		}
	}

	spin_unlock_irqrestore(&g_qdf_net_buf_track_lock[i], irq_flag);
}
qdf_export_symbol(qdf_net_buf_debug_add_node);

void qdf_net_buf_debug_update_node(qdf_nbuf_t net_buf, const char *func_name,
				   uint32_t line_num)
{
	uint32_t i;
	unsigned long irq_flag;
	QDF_NBUF_TRACK *p_node;

	if (is_initial_mem_debug_disabled)
		return;

	i = qdf_net_buf_debug_hash(net_buf);
	spin_lock_irqsave(&g_qdf_net_buf_track_lock[i], irq_flag);

	p_node = qdf_net_buf_debug_look_up(net_buf);

	if (p_node) {
		qdf_str_lcopy(p_node->func_name, kbasename(func_name),
			      QDF_MEM_FUNC_NAME_SIZE);
		p_node->line_num = line_num;
	}

	spin_unlock_irqrestore(&g_qdf_net_buf_track_lock[i], irq_flag);
}

qdf_export_symbol(qdf_net_buf_debug_update_node);

void qdf_net_buf_debug_update_map_node(qdf_nbuf_t net_buf,
				       const char *func_name,
				       uint32_t line_num)
{
	uint32_t i;
	unsigned long irq_flag;
	QDF_NBUF_TRACK *p_node;

	if (is_initial_mem_debug_disabled)
		return;

	i = qdf_net_buf_debug_hash(net_buf);
	spin_lock_irqsave(&g_qdf_net_buf_track_lock[i], irq_flag);

	p_node = qdf_net_buf_debug_look_up(net_buf);

	if (p_node) {
		qdf_str_lcopy(p_node->map_func_name, func_name,
			      QDF_MEM_FUNC_NAME_SIZE);
		p_node->map_line_num = line_num;
		p_node->is_nbuf_mapped = true;
	}
	spin_unlock_irqrestore(&g_qdf_net_buf_track_lock[i], irq_flag);
}

#ifdef NBUF_SMMU_MAP_UNMAP_DEBUG
void qdf_net_buf_debug_update_smmu_map_node(qdf_nbuf_t nbuf,
					    unsigned long iova,
					    unsigned long pa,
					    const char *func,
					    uint32_t line)
{
	uint32_t i;
	unsigned long irq_flag;
	QDF_NBUF_TRACK *p_node;

	if (is_initial_mem_debug_disabled)
		return;

	i = qdf_net_buf_debug_hash(nbuf);
	spin_lock_irqsave(&g_qdf_net_buf_track_lock[i], irq_flag);

	p_node = qdf_net_buf_debug_look_up(nbuf);

	if (p_node) {
		qdf_str_lcopy(p_node->smmu_map_func_name, func,
			      QDF_MEM_FUNC_NAME_SIZE);
		p_node->smmu_map_line_num = line;
		p_node->is_nbuf_smmu_mapped = true;
		p_node->smmu_map_iova_addr = iova;
		p_node->smmu_map_pa_addr = pa;
	}
	spin_unlock_irqrestore(&g_qdf_net_buf_track_lock[i], irq_flag);
}

void qdf_net_buf_debug_update_smmu_unmap_node(qdf_nbuf_t nbuf,
					      unsigned long iova,
					      unsigned long pa,
					      const char *func,
					      uint32_t line)
{
	uint32_t i;
	unsigned long irq_flag;
	QDF_NBUF_TRACK *p_node;

	if (is_initial_mem_debug_disabled)
		return;

	i = qdf_net_buf_debug_hash(nbuf);
	spin_lock_irqsave(&g_qdf_net_buf_track_lock[i], irq_flag);

	p_node = qdf_net_buf_debug_look_up(nbuf);

	if (p_node) {
		qdf_str_lcopy(p_node->smmu_unmap_func_name, func,
			      QDF_MEM_FUNC_NAME_SIZE);
		p_node->smmu_unmap_line_num = line;
		p_node->is_nbuf_smmu_mapped = false;
		p_node->smmu_unmap_iova_addr = iova;
		p_node->smmu_unmap_pa_addr = pa;
	}
	spin_unlock_irqrestore(&g_qdf_net_buf_track_lock[i], irq_flag);
}
#endif

void qdf_net_buf_debug_update_unmap_node(qdf_nbuf_t net_buf,
					 const char *func_name,
					 uint32_t line_num)
{
	uint32_t i;
	unsigned long irq_flag;
	QDF_NBUF_TRACK *p_node;

	if (is_initial_mem_debug_disabled)
		return;

	i = qdf_net_buf_debug_hash(net_buf);
	spin_lock_irqsave(&g_qdf_net_buf_track_lock[i], irq_flag);

	p_node = qdf_net_buf_debug_look_up(net_buf);

	if (p_node) {
		qdf_str_lcopy(p_node->unmap_func_name, func_name,
			      QDF_MEM_FUNC_NAME_SIZE);
		p_node->unmap_line_num = line_num;
		p_node->is_nbuf_mapped = false;
	}
	spin_unlock_irqrestore(&g_qdf_net_buf_track_lock[i], irq_flag);
}

void qdf_net_buf_debug_delete_node(qdf_nbuf_t net_buf)
{
	uint32_t i;
	QDF_NBUF_TRACK *p_head;
	QDF_NBUF_TRACK *p_node = NULL;
	unsigned long irq_flag;
	QDF_NBUF_TRACK *p_prev;

	if (is_initial_mem_debug_disabled)
		return;

	i = qdf_net_buf_debug_hash(net_buf);
	spin_lock_irqsave(&g_qdf_net_buf_track_lock[i], irq_flag);

	p_head = gp_qdf_net_buf_track_tbl[i];

	/* Unallocated SKB */
	if (!p_head)
		goto done;

	p_node = p_head;
	/* Found at head of the table */
	if (p_head->net_buf == net_buf) {
		gp_qdf_net_buf_track_tbl[i] = p_node->p_next;
		goto done;
	}

	/* Search in collision list */
	while (p_node) {
		p_prev = p_node;
		p_node = p_node->p_next;
		if ((p_node) && (p_node->net_buf == net_buf)) {
			p_prev->p_next = p_node->p_next;
			break;
		}
	}

done:
	spin_unlock_irqrestore(&g_qdf_net_buf_track_lock[i], irq_flag);

	if (p_node) {
		qdf_mem_skb_dec(p_node->size);
		qdf_nbuf_track_free(p_node);
	} else {
		if (qdf_net_buf_track_fail_count) {
			qdf_print("Untracked net_buf free: %pK with tracking failures count: %u",
				  net_buf, qdf_net_buf_track_fail_count);
		} else
			QDF_MEMDEBUG_PANIC("Unallocated buffer ! Double free of net_buf %pK ?",
					   net_buf);
	}
}
qdf_export_symbol(qdf_net_buf_debug_delete_node);

void qdf_net_buf_debug_acquire_skb(qdf_nbuf_t net_buf,
				   const char *func_name, uint32_t line_num)
{
	qdf_nbuf_t ext_list = qdf_nbuf_get_ext_list(net_buf);

	if (is_initial_mem_debug_disabled)
		return;

	while (ext_list) {
		/*
		 * Take care to add if it is Jumbo packet connected using
		 * frag_list
		 */
		qdf_nbuf_t next;

		next = qdf_nbuf_queue_next(ext_list);
		qdf_net_buf_debug_add_node(ext_list, 0, func_name, line_num);
		ext_list = next;
	}
	qdf_net_buf_debug_add_node(net_buf, 0, func_name, line_num);
}
qdf_export_symbol(qdf_net_buf_debug_acquire_skb);

void qdf_net_buf_debug_release_skb(qdf_nbuf_t net_buf)
{
	qdf_nbuf_t ext_list;

	if (is_initial_mem_debug_disabled)
		return;

	ext_list = qdf_nbuf_get_ext_list(net_buf);
	while (ext_list) {
		/*
		 * Take care to free if it is Jumbo packet connected using
		 * frag_list
		 */
		qdf_nbuf_t next;

		next = qdf_nbuf_queue_next(ext_list);

		if (qdf_nbuf_get_users(ext_list) > 1) {
			ext_list = next;
			continue;
		}

		qdf_net_buf_debug_delete_node(ext_list);
		ext_list = next;
	}

	if (qdf_nbuf_get_users(net_buf) > 1)
		return;

	qdf_net_buf_debug_delete_node(net_buf);
}
qdf_export_symbol(qdf_net_buf_debug_release_skb);

qdf_nbuf_t qdf_nbuf_alloc_debug(qdf_device_t osdev, qdf_size_t size,
				int reserve, int align, int prio,
				const char *func, uint32_t line)
{
	qdf_nbuf_t nbuf;

	if (is_initial_mem_debug_disabled)
		return __qdf_nbuf_alloc(osdev, size,
					reserve, align,
					prio, func, line);

	nbuf = __qdf_nbuf_alloc(osdev, size, reserve, align, prio, func, line);

	/* Store SKB in internal QDF tracking table */
	if (qdf_likely(nbuf)) {
		qdf_net_buf_debug_add_node(nbuf, size, func, line);
		qdf_nbuf_history_add(nbuf, func, line, QDF_NBUF_ALLOC);
	} else {
		qdf_nbuf_history_add(nbuf, func, line, QDF_NBUF_ALLOC_FAILURE);
	}

	return nbuf;
}
qdf_export_symbol(qdf_nbuf_alloc_debug);

qdf_nbuf_t qdf_nbuf_frag_alloc_debug(qdf_device_t osdev, qdf_size_t size,
				     int reserve, int align, int prio,
				     const char *func, uint32_t line)
{
	qdf_nbuf_t nbuf;

	if (is_initial_mem_debug_disabled)
		return __qdf_nbuf_frag_alloc(osdev, size,
					reserve, align,
					prio, func, line);

	nbuf = __qdf_nbuf_frag_alloc(osdev, size, reserve, align, prio,
				     func, line);

	/* Store SKB in internal QDF tracking table */
	if (qdf_likely(nbuf)) {
		qdf_net_buf_debug_add_node(nbuf, size, func, line);
		qdf_nbuf_history_add(nbuf, func, line, QDF_NBUF_ALLOC);
	} else {
		qdf_nbuf_history_add(nbuf, func, line, QDF_NBUF_ALLOC_FAILURE);
	}

	return nbuf;
}

qdf_export_symbol(qdf_nbuf_frag_alloc_debug);

qdf_nbuf_t qdf_nbuf_alloc_no_recycler_debug(size_t size, int reserve, int align,
					    const char *func, uint32_t line)
{
	qdf_nbuf_t nbuf;

	if (is_initial_mem_debug_disabled)
		return __qdf_nbuf_alloc_no_recycler(size, reserve, align, func,
						    line);

	nbuf = __qdf_nbuf_alloc_no_recycler(size, reserve, align, func, line);

	/* Store SKB in internal QDF tracking table */
	if (qdf_likely(nbuf)) {
		qdf_net_buf_debug_add_node(nbuf, size, func, line);
		qdf_nbuf_history_add(nbuf, func, line, QDF_NBUF_ALLOC);
	} else {
		qdf_nbuf_history_add(nbuf, func, line, QDF_NBUF_ALLOC_FAILURE);
	}

	return nbuf;
}

qdf_export_symbol(qdf_nbuf_alloc_no_recycler_debug);

void qdf_nbuf_free_debug(qdf_nbuf_t nbuf, const char *func, uint32_t line)
{
	qdf_nbuf_t ext_list;
	qdf_frag_t p_frag;
	uint32_t num_nr_frags;
	uint32_t idx = 0;

	if (qdf_unlikely(!nbuf))
		return;

	if (is_initial_mem_debug_disabled)
		goto free_buf;

	if (qdf_nbuf_get_users(nbuf) > 1)
		goto free_buf;

	/* Remove SKB from internal QDF tracking table */
	qdf_nbuf_panic_on_free_if_smmu_mapped(nbuf, func, line);
	qdf_nbuf_panic_on_free_if_mapped(nbuf, func, line);
	qdf_net_buf_debug_delete_node(nbuf);
	qdf_nbuf_history_add(nbuf, func, line, QDF_NBUF_FREE);

	/* Take care to delete the debug entries for frags */
	num_nr_frags = qdf_nbuf_get_nr_frags(nbuf);

	qdf_assert_always(num_nr_frags <= QDF_NBUF_MAX_FRAGS);

	while (idx < num_nr_frags) {
		p_frag = qdf_nbuf_get_frag_addr(nbuf, idx);
		if (qdf_likely(p_frag))
			qdf_frag_debug_refcount_dec(p_frag, func, line);
		idx++;
	}

	/*
	 * Take care to update the debug entries for frag_list and also
	 * for the frags attached to frag_list
	 */
	ext_list = qdf_nbuf_get_ext_list(nbuf);
	while (ext_list) {
		if (qdf_nbuf_get_users(ext_list) == 1) {
			qdf_nbuf_panic_on_free_if_smmu_mapped(ext_list, func,
							      line);
			qdf_nbuf_panic_on_free_if_mapped(ext_list, func, line);
			idx = 0;
			num_nr_frags = qdf_nbuf_get_nr_frags(ext_list);
			qdf_assert_always(num_nr_frags <= QDF_NBUF_MAX_FRAGS);
			while (idx < num_nr_frags) {
				p_frag = qdf_nbuf_get_frag_addr(ext_list, idx);
				if (qdf_likely(p_frag))
					qdf_frag_debug_refcount_dec(p_frag,
								    func, line);
				idx++;
			}
			qdf_net_buf_debug_delete_node(ext_list);
		}

		ext_list = qdf_nbuf_queue_next(ext_list);
	}

free_buf:
	__qdf_nbuf_free(nbuf);
}
qdf_export_symbol(qdf_nbuf_free_debug);

struct sk_buff *__qdf_nbuf_alloc_simple(qdf_device_t osdev, size_t size,
					const char *func, uint32_t line)
{
	struct sk_buff *skb;
	int flags = GFP_KERNEL;

	if (in_interrupt() || irqs_disabled() || in_atomic()) {
		flags = GFP_ATOMIC;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 4, 0)
		/*
		 * Observed that kcompactd burns out CPU to make order-3 page.
		 *__netdev_alloc_skb has 4k page fallback option just in case of
		 * failing high order page allocation so we don't need to be
		 * hard. Make kcompactd rest in piece.
		 */
		flags = flags & ~__GFP_KSWAPD_RECLAIM;
#endif
	}

	skb = __netdev_alloc_skb(NULL, size, flags);


	if (qdf_likely(is_initial_mem_debug_disabled)) {
		if (qdf_likely(skb))
			qdf_nbuf_count_inc(skb);
	} else {
		if (qdf_likely(skb)) {
			qdf_nbuf_count_inc(skb);
			qdf_net_buf_debug_add_node(skb, size, func, line);
			qdf_nbuf_history_add(skb, func, line, QDF_NBUF_ALLOC);
		} else {
			qdf_nbuf_history_add(skb, func, line, QDF_NBUF_ALLOC_FAILURE);
		}
	}


	return skb;
}

qdf_export_symbol(__qdf_nbuf_alloc_simple);

void qdf_nbuf_free_debug_simple(qdf_nbuf_t nbuf, const char *func,
				uint32_t line)
{
	if (qdf_likely(nbuf)) {
		if (is_initial_mem_debug_disabled) {
			dev_kfree_skb_any(nbuf);
		} else {
			qdf_nbuf_free_debug(nbuf, func, line);
		}
	}
}

qdf_export_symbol(qdf_nbuf_free_debug_simple);

qdf_nbuf_t qdf_nbuf_clone_debug(qdf_nbuf_t buf, const char *func, uint32_t line)
{
	uint32_t num_nr_frags;
	uint32_t idx = 0;
	qdf_nbuf_t ext_list;
	qdf_frag_t p_frag;

	qdf_nbuf_t cloned_buf = __qdf_nbuf_clone(buf);

	if (is_initial_mem_debug_disabled)
		return cloned_buf;

	if (qdf_unlikely(!cloned_buf))
		return NULL;

	/* Take care to update the debug entries for frags */
	num_nr_frags = qdf_nbuf_get_nr_frags(cloned_buf);

	qdf_assert_always(num_nr_frags <= QDF_NBUF_MAX_FRAGS);

	while (idx < num_nr_frags) {
		p_frag = qdf_nbuf_get_frag_addr(cloned_buf, idx);
		if (qdf_likely(p_frag))
			qdf_frag_debug_refcount_inc(p_frag, func, line);
		idx++;
	}

	/* Take care to update debug entries for frags attached to frag_list */
	ext_list = qdf_nbuf_get_ext_list(cloned_buf);
	while (ext_list) {
		idx = 0;
		num_nr_frags = qdf_nbuf_get_nr_frags(ext_list);

		qdf_assert_always(num_nr_frags <= QDF_NBUF_MAX_FRAGS);

		while (idx < num_nr_frags) {
			p_frag = qdf_nbuf_get_frag_addr(ext_list, idx);
			if (qdf_likely(p_frag))
				qdf_frag_debug_refcount_inc(p_frag, func, line);
			idx++;
		}
		ext_list = qdf_nbuf_queue_next(ext_list);
	}

	/* Store SKB in internal QDF tracking table */
	qdf_net_buf_debug_add_node(cloned_buf, 0, func, line);
	qdf_nbuf_history_add(cloned_buf, func, line, QDF_NBUF_ALLOC_CLONE);

	return cloned_buf;
}
qdf_export_symbol(qdf_nbuf_clone_debug);

qdf_nbuf_t
qdf_nbuf_page_frag_alloc_debug(qdf_device_t osdev, qdf_size_t size, int reserve,
			       int align, __qdf_frag_cache_t *pf_cache,
			       const char *func, uint32_t line)
{
	qdf_nbuf_t nbuf;

	if (is_initial_mem_debug_disabled)
		return __qdf_nbuf_page_frag_alloc(osdev, size, reserve, align,
						  pf_cache, func, line);

	nbuf = __qdf_nbuf_page_frag_alloc(osdev, size, reserve, align,
					  pf_cache, func, line);

	/* Store SKB in internal QDF tracking table */
	if (qdf_likely(nbuf)) {
		qdf_net_buf_debug_add_node(nbuf, size, func, line);
		qdf_nbuf_history_add(nbuf, func, line, QDF_NBUF_ALLOC);
	} else {
		qdf_nbuf_history_add(nbuf, func, line, QDF_NBUF_ALLOC_FAILURE);
	}

	return nbuf;
}

qdf_export_symbol(qdf_nbuf_page_frag_alloc_debug);

qdf_nbuf_t qdf_nbuf_copy_debug(qdf_nbuf_t buf, const char *func, uint32_t line)
{
	qdf_nbuf_t copied_buf = __qdf_nbuf_copy(buf);

	if (is_initial_mem_debug_disabled)
		return copied_buf;

	if (qdf_unlikely(!copied_buf))
		return NULL;

	/* Store SKB in internal QDF tracking table */
	qdf_net_buf_debug_add_node(copied_buf, 0, func, line);
	qdf_nbuf_history_add(copied_buf, func, line, QDF_NBUF_ALLOC_COPY);

	return copied_buf;
}
qdf_export_symbol(qdf_nbuf_copy_debug);

qdf_nbuf_t
qdf_nbuf_copy_expand_debug(qdf_nbuf_t buf, int headroom, int tailroom,
			   const char *func, uint32_t line)
{
	qdf_nbuf_t copied_buf = __qdf_nbuf_copy_expand(buf, headroom, tailroom);

	if (qdf_unlikely(!copied_buf))
		return NULL;

	if (is_initial_mem_debug_disabled)
		return copied_buf;

	/* Store SKB in internal QDF tracking table */
	qdf_net_buf_debug_add_node(copied_buf, 0, func, line);
	qdf_nbuf_history_add(copied_buf, func, line,
			     QDF_NBUF_ALLOC_COPY_EXPAND);

	return copied_buf;
}

qdf_export_symbol(qdf_nbuf_copy_expand_debug);

qdf_nbuf_t
qdf_nbuf_unshare_debug(qdf_nbuf_t buf, const char *func_name,
		       uint32_t line_num)
{
	qdf_nbuf_t unshared_buf;
	qdf_frag_t p_frag;
	uint32_t num_nr_frags;
	uint32_t idx = 0;
	qdf_nbuf_t ext_list, next;

	if (is_initial_mem_debug_disabled)
		return __qdf_nbuf_unshare(buf);

	/* Not a shared buffer, nothing to do */
	if (!qdf_nbuf_is_cloned(buf))
		return buf;

	if (qdf_nbuf_get_users(buf) > 1)
		goto unshare_buf;

	/* Take care to delete the debug entries for frags */
	num_nr_frags = qdf_nbuf_get_nr_frags(buf);

	while (idx < num_nr_frags) {
		p_frag = qdf_nbuf_get_frag_addr(buf, idx);
		if (qdf_likely(p_frag))
			qdf_frag_debug_refcount_dec(p_frag, func_name,
						    line_num);
		idx++;
	}

	qdf_net_buf_debug_delete_node(buf);

	 /* Take care of jumbo packet connected using frag_list and frags */
	ext_list = qdf_nbuf_get_ext_list(buf);
	while (ext_list) {
		idx = 0;
		next = qdf_nbuf_queue_next(ext_list);
		num_nr_frags = qdf_nbuf_get_nr_frags(ext_list);

		if (qdf_nbuf_get_users(ext_list) > 1) {
			ext_list = next;
			continue;
		}

		while (idx < num_nr_frags) {
			p_frag = qdf_nbuf_get_frag_addr(ext_list, idx);
			if (qdf_likely(p_frag))
				qdf_frag_debug_refcount_dec(p_frag, func_name,
							    line_num);
			idx++;
		}

		qdf_net_buf_debug_delete_node(ext_list);
		ext_list = next;
	}

unshare_buf:
	unshared_buf = __qdf_nbuf_unshare(buf);

	if (qdf_likely(unshared_buf))
		qdf_net_buf_debug_add_node(unshared_buf, 0, func_name,
					   line_num);

	return unshared_buf;
}

qdf_export_symbol(qdf_nbuf_unshare_debug);

void
qdf_nbuf_dev_kfree_list_debug(__qdf_nbuf_queue_head_t *nbuf_queue_head,
			      const char *func, uint32_t line)
{
	qdf_nbuf_t  buf;

	if (qdf_nbuf_queue_empty(nbuf_queue_head))
		return;

	if (is_initial_mem_debug_disabled)
		return __qdf_nbuf_dev_kfree_list(nbuf_queue_head);

	while ((buf = qdf_nbuf_queue_head_dequeue(nbuf_queue_head)) != NULL)
		qdf_nbuf_free_debug(buf, func, line);
}

qdf_export_symbol(qdf_nbuf_dev_kfree_list_debug);
#endif /* NBUF_MEMORY_DEBUG */

#if defined(QCA_DP_NBUF_FAST_PPEDS)
#if defined(NBUF_MEMORY_DEBUG)
struct sk_buff *__qdf_nbuf_alloc_ppe_ds(qdf_device_t osdev, size_t size,
					const char *func, uint32_t line)
{
	struct sk_buff *skb;
	int flags = GFP_KERNEL;

	if (in_interrupt() || irqs_disabled() || in_atomic()) {
		flags = GFP_ATOMIC;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 4, 0)
		/*
		 * Observed that kcompactd burns out CPU to make order-3
		 * page.__netdev_alloc_skb has 4k page fallback option
		 * just in case of
		 * failing high order page allocation so we don't need
		 * to be hard. Make kcompactd rest in piece.
		 */
		flags = flags & ~__GFP_KSWAPD_RECLAIM;
#endif
	}
	skb = __netdev_alloc_skb_no_skb_reset(NULL, size, flags);
	if (qdf_likely(is_initial_mem_debug_disabled)) {
		if (qdf_likely(skb))
			qdf_nbuf_count_inc(skb);
	} else {
		if (qdf_likely(skb)) {
			qdf_nbuf_count_inc(skb);
			qdf_net_buf_debug_add_node(skb, size, func, line);
			qdf_nbuf_history_add(skb, func, line,
					     QDF_NBUF_ALLOC);
		} else {
			qdf_nbuf_history_add(skb, func, line,
					     QDF_NBUF_ALLOC_FAILURE);
		}
	}
	return skb;
}
#else
struct sk_buff *__qdf_nbuf_alloc_ppe_ds(qdf_device_t osdev, size_t size,
					const char *func, uint32_t line)
{
	struct sk_buff *skb;
	int flags = GFP_KERNEL;

	if (in_interrupt() || irqs_disabled() || in_atomic()) {
		flags = GFP_ATOMIC;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 4, 0)
		/*
		 * Observed that kcompactd burns out CPU to make order-3
		 * page.__netdev_alloc_skb has 4k page fallback option
		 * just in case of
		 * failing high order page allocation so we don't need
		 * to be hard. Make kcompactd rest in piece.
		 */
		flags = flags & ~__GFP_KSWAPD_RECLAIM;
#endif
	}
	skb = __netdev_alloc_skb_no_skb_reset(NULL, size, flags);
	if (qdf_likely(skb))
		qdf_nbuf_count_inc(skb);

	return skb;
}
#endif
qdf_export_symbol(__qdf_nbuf_alloc_ppe_ds);
#endif

#if defined(FEATURE_TSO)

/**
 * struct qdf_tso_cmn_seg_info_t - TSO common info structure
 *
 * @ethproto: ethernet type of the msdu
 * @ip_tcp_hdr_len: ip + tcp length for the msdu
 * @l2_len: L2 length for the msdu
 * @eit_hdr: pointer to EIT header
 * @eit_hdr_len: EIT header length for the msdu
 * @eit_hdr_dma_map_addr: dma addr for EIT header
 * @tcphdr: pointer to tcp header
 * @ipv4_csum_en: ipv4 checksum enable
 * @tcp_ipv4_csum_en: TCP ipv4 checksum enable
 * @tcp_ipv6_csum_en: TCP ipv6 checksum enable
 * @ip_id: IP id
 * @tcp_seq_num: TCP sequence number
 *
 * This structure holds the TSO common info that is common
 * across all the TCP segments of the jumbo packet.
 */
struct qdf_tso_cmn_seg_info_t {
	uint16_t ethproto;
	uint16_t ip_tcp_hdr_len;
	uint16_t l2_len;
	uint8_t *eit_hdr;
	uint32_t eit_hdr_len;
	qdf_dma_addr_t eit_hdr_dma_map_addr;
	struct tcphdr *tcphdr;
	uint16_t ipv4_csum_en;
	uint16_t tcp_ipv4_csum_en;
	uint16_t tcp_ipv6_csum_en;
	uint16_t ip_id;
	uint32_t tcp_seq_num;
};

/**
 * qdf_nbuf_adj_tso_frag() - adjustment for buffer address of tso fragment
 * @skb: network buffer
 *
 * Return: byte offset length of 8 bytes aligned.
 */
#ifdef FIX_TXDMA_LIMITATION
static uint8_t qdf_nbuf_adj_tso_frag(struct sk_buff *skb)
{
	uint32_t eit_hdr_len;
	uint8_t *eit_hdr;
	uint8_t byte_8_align_offset;

	eit_hdr = skb->data;
	eit_hdr_len = (skb_transport_header(skb)
		 - skb_mac_header(skb)) + tcp_hdrlen(skb);
	byte_8_align_offset = ((unsigned long)(eit_hdr) + eit_hdr_len) & 0x7L;
	if (qdf_unlikely(byte_8_align_offset)) {
		TSO_DEBUG("%pK,Len %d %d",
			  eit_hdr, eit_hdr_len, byte_8_align_offset);
		if (unlikely(skb_headroom(skb) < byte_8_align_offset)) {
			TSO_DEBUG("[%d]Insufficient headroom,[%pK],[%pK],[%d]",
				  __LINE__, skb->head, skb->data,
				 byte_8_align_offset);
			return 0;
		}
		qdf_nbuf_push_head(skb, byte_8_align_offset);
		qdf_mem_move(skb->data,
			     skb->data + byte_8_align_offset,
			     eit_hdr_len);
		skb->len -= byte_8_align_offset;
		skb->mac_header -= byte_8_align_offset;
		skb->network_header -= byte_8_align_offset;
		skb->transport_header -= byte_8_align_offset;
	}
	return byte_8_align_offset;
}
#else
static uint8_t qdf_nbuf_adj_tso_frag(struct sk_buff *skb)
{
	return 0;
}
#endif

#ifdef CONFIG_WLAN_SYSFS_MEM_STATS
void qdf_record_nbuf_nbytes(
	uint32_t nbytes, qdf_dma_dir_t dir, bool is_mapped)
{
	__qdf_record_nbuf_nbytes(nbytes, dir, is_mapped);
}

qdf_export_symbol(qdf_record_nbuf_nbytes);

#endif /* CONFIG_WLAN_SYSFS_MEM_STATS */

/**
 * qdf_nbuf_tso_map_frag() - Map TSO segment
 * @osdev: qdf device handle
 * @tso_frag_vaddr: addr of tso fragment
 * @nbytes: number of bytes
 * @dir: direction
 *
 * Map TSO segment and for MCL record the amount of memory mapped
 *
 * Return: DMA address of mapped TSO fragment in success and
 * NULL in case of DMA mapping failure
 */
static inline qdf_dma_addr_t qdf_nbuf_tso_map_frag(
	qdf_device_t osdev, void *tso_frag_vaddr,
	uint32_t nbytes, qdf_dma_dir_t dir)
{
	qdf_dma_addr_t tso_frag_paddr = 0;

	tso_frag_paddr = dma_map_single(osdev->dev, tso_frag_vaddr,
					nbytes, __qdf_dma_dir_to_os(dir));
	if (unlikely(dma_mapping_error(osdev->dev, tso_frag_paddr))) {
		qdf_err("DMA mapping error!");
		qdf_assert_always(0);
		return 0;
	}
	qdf_record_nbuf_nbytes(nbytes, dir, true);
	return tso_frag_paddr;
}

/**
 * qdf_nbuf_tso_unmap_frag() - Unmap TSO segment
 * @osdev: qdf device handle
 * @tso_frag_paddr: DMA addr of tso fragment
 * @dir: direction
 * @nbytes: number of bytes
 *
 * Unmap TSO segment and for MCL record the amount of memory mapped
 *
 * Return: None
 */
static inline void qdf_nbuf_tso_unmap_frag(
	qdf_device_t osdev, qdf_dma_addr_t tso_frag_paddr,
	uint32_t nbytes, qdf_dma_dir_t dir)
{
	qdf_record_nbuf_nbytes(nbytes, dir, false);
	dma_unmap_single(osdev->dev, tso_frag_paddr,
			 nbytes, __qdf_dma_dir_to_os(dir));
}

/**
 * __qdf_nbuf_get_tso_cmn_seg_info() - get TSO common
 * information
 * @osdev: qdf device handle
 * @skb: skb buffer
 * @tso_info: Parameters common to all segments
 *
 * Get the TSO information that is common across all the TCP
 * segments of the jumbo packet
 *
 * Return: 0 - success 1 - failure
 */
static uint8_t __qdf_nbuf_get_tso_cmn_seg_info(qdf_device_t osdev,
			struct sk_buff *skb,
			struct qdf_tso_cmn_seg_info_t *tso_info)
{
	/* Get ethernet type and ethernet header length */
	tso_info->ethproto = vlan_get_protocol(skb);

	/* Determine whether this is an IPv4 or IPv6 packet */
	if (tso_info->ethproto == htons(ETH_P_IP)) { /* IPv4 */
		/* for IPv4, get the IP ID and enable TCP and IP csum */
		struct iphdr *ipv4_hdr = ip_hdr(skb);

		tso_info->ip_id = ntohs(ipv4_hdr->id);
		tso_info->ipv4_csum_en = 1;
		tso_info->tcp_ipv4_csum_en = 1;
		if (qdf_unlikely(ipv4_hdr->protocol != IPPROTO_TCP)) {
			qdf_err("TSO IPV4 proto 0x%x not TCP",
				ipv4_hdr->protocol);
			return 1;
		}
	} else if (tso_info->ethproto == htons(ETH_P_IPV6)) { /* IPv6 */
		/* for IPv6, enable TCP csum. No IP ID or IP csum */
		tso_info->tcp_ipv6_csum_en = 1;
	} else {
		qdf_err("TSO: ethertype 0x%x is not supported!",
			tso_info->ethproto);
		return 1;
	}
	tso_info->l2_len = (skb_network_header(skb) - skb_mac_header(skb));
	tso_info->tcphdr = tcp_hdr(skb);
	tso_info->tcp_seq_num = ntohl(tcp_hdr(skb)->seq);
	/* get pointer to the ethernet + IP + TCP header and their length */
	tso_info->eit_hdr = skb->data;
	tso_info->eit_hdr_len = (skb_transport_header(skb)
		 - skb_mac_header(skb)) + tcp_hdrlen(skb);
	tso_info->eit_hdr_dma_map_addr = qdf_nbuf_tso_map_frag(
						osdev, tso_info->eit_hdr,
						tso_info->eit_hdr_len,
						QDF_DMA_TO_DEVICE);
	if (qdf_unlikely(!tso_info->eit_hdr_dma_map_addr))
		return 1;

	if (tso_info->ethproto == htons(ETH_P_IP)) {
		/* include IPv4 header length for IPV4 (total length) */
		tso_info->ip_tcp_hdr_len =
			tso_info->eit_hdr_len - tso_info->l2_len;
	} else if (tso_info->ethproto == htons(ETH_P_IPV6)) {
		/* exclude IPv6 header length for IPv6 (payload length) */
		tso_info->ip_tcp_hdr_len = tcp_hdrlen(skb);
	}
	/*
	 * The length of the payload (application layer data) is added to
	 * tso_info->ip_tcp_hdr_len before passing it on to the msdu link ext
	 * descriptor.
	 */

	TSO_DEBUG("%s seq# %u eit hdr len %u l2 len %u  skb len %u\n", __func__,
		tso_info->tcp_seq_num,
		tso_info->eit_hdr_len,
		tso_info->l2_len,
		skb->len);
	return 0;
}


/**
 * __qdf_nbuf_fill_tso_cmn_seg_info() - Init function for each TSO nbuf segment
 *
 * @curr_seg: Segment whose contents are initialized
 * @tso_cmn_info: Parameters common to all segments
 *
 * Return: None
 */
static inline void __qdf_nbuf_fill_tso_cmn_seg_info(
				struct qdf_tso_seg_elem_t *curr_seg,
				struct qdf_tso_cmn_seg_info_t *tso_cmn_info)
{
	/* Initialize the flags to 0 */
	memset(&curr_seg->seg, 0x0, sizeof(curr_seg->seg));

	/*
	 * The following fields remain the same across all segments of
	 * a jumbo packet
	 */
	curr_seg->seg.tso_flags.tso_enable = 1;
	curr_seg->seg.tso_flags.ipv4_checksum_en =
		tso_cmn_info->ipv4_csum_en;
	curr_seg->seg.tso_flags.tcp_ipv6_checksum_en =
		tso_cmn_info->tcp_ipv6_csum_en;
	curr_seg->seg.tso_flags.tcp_ipv4_checksum_en =
		tso_cmn_info->tcp_ipv4_csum_en;
	curr_seg->seg.tso_flags.tcp_flags_mask = 0x1FF;

	/* The following fields change for the segments */
	curr_seg->seg.tso_flags.ip_id = tso_cmn_info->ip_id;
	tso_cmn_info->ip_id++;

	curr_seg->seg.tso_flags.syn = tso_cmn_info->tcphdr->syn;
	curr_seg->seg.tso_flags.rst = tso_cmn_info->tcphdr->rst;
	curr_seg->seg.tso_flags.ack = tso_cmn_info->tcphdr->ack;
	curr_seg->seg.tso_flags.urg = tso_cmn_info->tcphdr->urg;
	curr_seg->seg.tso_flags.ece = tso_cmn_info->tcphdr->ece;
	curr_seg->seg.tso_flags.cwr = tso_cmn_info->tcphdr->cwr;

	curr_seg->seg.tso_flags.tcp_seq_num = tso_cmn_info->tcp_seq_num;

	/*
	 * First fragment for each segment always contains the ethernet,
	 * IP and TCP header
	 */
	curr_seg->seg.tso_frags[0].vaddr = tso_cmn_info->eit_hdr;
	curr_seg->seg.tso_frags[0].length = tso_cmn_info->eit_hdr_len;
	curr_seg->seg.total_len = curr_seg->seg.tso_frags[0].length;
	curr_seg->seg.tso_frags[0].paddr = tso_cmn_info->eit_hdr_dma_map_addr;

	TSO_DEBUG("%s %d eit hdr %pK eit_hdr_len %d tcp_seq_num %u tso_info->total_len %u\n",
		   __func__, __LINE__, tso_cmn_info->eit_hdr,
		   tso_cmn_info->eit_hdr_len,
		   curr_seg->seg.tso_flags.tcp_seq_num,
		   curr_seg->seg.total_len);
	qdf_tso_seg_dbg_record(curr_seg, TSOSEG_LOC_FILLCMNSEG);
}

uint32_t __qdf_nbuf_get_tso_info(qdf_device_t osdev, struct sk_buff *skb,
		struct qdf_tso_info_t *tso_info)
{
	/* common across all segments */
	struct qdf_tso_cmn_seg_info_t tso_cmn_info;
	/* segment specific */
	void *tso_frag_vaddr;
	qdf_dma_addr_t tso_frag_paddr = 0;
	uint32_t num_seg = 0;
	struct qdf_tso_seg_elem_t *curr_seg;
	struct qdf_tso_num_seg_elem_t *total_num_seg;
	skb_frag_t *frag = NULL;
	uint32_t tso_frag_len = 0; /* tso segment's fragment length*/
	uint32_t skb_frag_len = 0; /* skb's fragment length (contiguous memory)*/
	uint32_t skb_proc = skb->len; /* bytes of skb pending processing */
	uint32_t tso_seg_size = skb_shinfo(skb)->gso_size;
	int j = 0; /* skb fragment index */
	uint8_t byte_8_align_offset;

	memset(&tso_cmn_info, 0x0, sizeof(tso_cmn_info));
	total_num_seg = tso_info->tso_num_seg_list;
	curr_seg = tso_info->tso_seg_list;
	total_num_seg->num_seg.tso_cmn_num_seg = 0;

	byte_8_align_offset = qdf_nbuf_adj_tso_frag(skb);

	if (qdf_unlikely(__qdf_nbuf_get_tso_cmn_seg_info(osdev,
						skb, &tso_cmn_info))) {
		qdf_warn("TSO: error getting common segment info");
		return 0;
	}

	/* length of the first chunk of data in the skb */
	skb_frag_len = skb_headlen(skb);

	/* the 0th tso segment's 0th fragment always contains the EIT header */
	/* update the remaining skb fragment length and TSO segment length */
	skb_frag_len -= tso_cmn_info.eit_hdr_len;
	skb_proc -= tso_cmn_info.eit_hdr_len;

	/* get the address to the next tso fragment */
	tso_frag_vaddr = skb->data +
			 tso_cmn_info.eit_hdr_len +
			 byte_8_align_offset;
	/* get the length of the next tso fragment */
	tso_frag_len = min(skb_frag_len, tso_seg_size);

	if (tso_frag_len != 0) {
		tso_frag_paddr = qdf_nbuf_tso_map_frag(
					osdev, tso_frag_vaddr, tso_frag_len,
					QDF_DMA_TO_DEVICE);
		if (qdf_unlikely(!tso_frag_paddr))
			return 0;
	}

	TSO_DEBUG("%s[%d] skb frag len %d tso frag len %d\n", __func__,
		__LINE__, skb_frag_len, tso_frag_len);
	num_seg = tso_info->num_segs;
	tso_info->num_segs = 0;
	tso_info->is_tso = 1;

	while (num_seg && curr_seg) {
		int i = 1; /* tso fragment index */
		uint8_t more_tso_frags = 1;

		curr_seg->seg.num_frags = 0;
		tso_info->num_segs++;
		total_num_seg->num_seg.tso_cmn_num_seg++;

		__qdf_nbuf_fill_tso_cmn_seg_info(curr_seg,
						 &tso_cmn_info);

		/* If TCP PSH flag is set, set it in the last or only segment */
		if (num_seg == 1)
			curr_seg->seg.tso_flags.psh = tso_cmn_info.tcphdr->psh;

		if (unlikely(skb_proc == 0))
			return tso_info->num_segs;

		curr_seg->seg.tso_flags.ip_len = tso_cmn_info.ip_tcp_hdr_len;
		curr_seg->seg.tso_flags.l2_len = tso_cmn_info.l2_len;
		/* frag len is added to ip_len in while loop below*/

		curr_seg->seg.num_frags++;

		while (more_tso_frags) {
			if (tso_frag_len != 0) {
				curr_seg->seg.tso_frags[i].vaddr =
					tso_frag_vaddr;
				curr_seg->seg.tso_frags[i].length =
					tso_frag_len;
				curr_seg->seg.total_len += tso_frag_len;
				curr_seg->seg.tso_flags.ip_len +=  tso_frag_len;
				curr_seg->seg.num_frags++;
				skb_proc = skb_proc - tso_frag_len;

				/* increment the TCP sequence number */

				tso_cmn_info.tcp_seq_num += tso_frag_len;
				curr_seg->seg.tso_frags[i].paddr =
					tso_frag_paddr;

				qdf_assert_always(curr_seg->seg.tso_frags[i].paddr);
			}

			TSO_DEBUG("%s[%d] frag %d frag len %d total_len %u vaddr %pK\n",
					__func__, __LINE__,
					i,
					tso_frag_len,
					curr_seg->seg.total_len,
					curr_seg->seg.tso_frags[i].vaddr);

			/* if there is no more data left in the skb */
			if (!skb_proc)
				return tso_info->num_segs;

			/* get the next payload fragment information */
			/* check if there are more fragments in this segment */
			if (tso_frag_len < tso_seg_size) {
				more_tso_frags = 1;
				if (tso_frag_len != 0) {
					tso_seg_size = tso_seg_size -
						tso_frag_len;
					i++;
					if (curr_seg->seg.num_frags ==
								FRAG_NUM_MAX) {
						more_tso_frags = 0;
						/*
						 * reset i and the tso
						 * payload size
						 */
						i = 1;
						tso_seg_size =
							skb_shinfo(skb)->
								gso_size;
					}
				}
			} else {
				more_tso_frags = 0;
				/* reset i and the tso payload size */
				i = 1;
				tso_seg_size = skb_shinfo(skb)->gso_size;
			}

			/* if the next fragment is contiguous */
			if ((tso_frag_len != 0)  && (tso_frag_len < skb_frag_len)) {
				tso_frag_vaddr = tso_frag_vaddr + tso_frag_len;
				skb_frag_len = skb_frag_len - tso_frag_len;
				tso_frag_len = min(skb_frag_len, tso_seg_size);

			} else { /* the next fragment is not contiguous */
				if (skb_shinfo(skb)->nr_frags == 0) {
					qdf_info("TSO: nr_frags == 0!");
					qdf_assert(0);
					return 0;
				}
				if (j >= skb_shinfo(skb)->nr_frags) {
					qdf_info("TSO: nr_frags %d j %d",
						 skb_shinfo(skb)->nr_frags, j);
					qdf_assert(0);
					return 0;
				}
				frag = &skb_shinfo(skb)->frags[j];
				skb_frag_len = skb_frag_size(frag);
				tso_frag_len = min(skb_frag_len, tso_seg_size);
				tso_frag_vaddr = skb_frag_address_safe(frag);
				j++;
			}

			TSO_DEBUG("%s[%d] skb frag len %d tso frag %d len tso_seg_size %d\n",
				__func__, __LINE__, skb_frag_len, tso_frag_len,
				tso_seg_size);

			if (!(tso_frag_vaddr)) {
				TSO_DEBUG("%s: Fragment virtual addr is NULL",
						__func__);
				return 0;
			}

			tso_frag_paddr = qdf_nbuf_tso_map_frag(
						osdev, tso_frag_vaddr,
						tso_frag_len,
						QDF_DMA_TO_DEVICE);
			if (qdf_unlikely(!tso_frag_paddr))
				return 0;
		}
		TSO_DEBUG("%s tcp_seq_num: %u", __func__,
				curr_seg->seg.tso_flags.tcp_seq_num);
		num_seg--;
		/* if TCP FIN flag was set, set it in the last segment */
		if (!num_seg)
			curr_seg->seg.tso_flags.fin = tso_cmn_info.tcphdr->fin;

		qdf_tso_seg_dbg_record(curr_seg, TSOSEG_LOC_GETINFO);
		curr_seg = curr_seg->next;
	}
	return tso_info->num_segs;
}
qdf_export_symbol(__qdf_nbuf_get_tso_info);

void __qdf_nbuf_unmap_tso_segment(qdf_device_t osdev,
			  struct qdf_tso_seg_elem_t *tso_seg,
			  bool is_last_seg)
{
	uint32_t num_frags = 0;

	if (tso_seg->seg.num_frags > 0)
		num_frags = tso_seg->seg.num_frags - 1;

	/*Num of frags in a tso seg cannot be less than 2 */
	if (num_frags < 1) {
		/*
		 * If Num of frags is 1 in a tso seg but is_last_seg true,
		 * this may happen when qdf_nbuf_get_tso_info failed,
		 * do dma unmap for the 0th frag in this seg.
		 */
		if (is_last_seg && tso_seg->seg.num_frags == 1)
			goto last_seg_free_first_frag;

		qdf_assert(0);
		qdf_err("ERROR: num of frags in a tso segment is %d",
			(num_frags + 1));
		return;
	}

	while (num_frags) {
		/*Do dma unmap the tso seg except the 0th frag */
		if (0 ==  tso_seg->seg.tso_frags[num_frags].paddr) {
			qdf_err("ERROR: TSO seg frag %d mapped physical address is NULL",
				num_frags);
			qdf_assert(0);
			return;
		}
		qdf_nbuf_tso_unmap_frag(
			osdev,
			tso_seg->seg.tso_frags[num_frags].paddr,
			tso_seg->seg.tso_frags[num_frags].length,
			QDF_DMA_TO_DEVICE);
		tso_seg->seg.tso_frags[num_frags].paddr = 0;
		num_frags--;
		qdf_tso_seg_dbg_record(tso_seg, TSOSEG_LOC_UNMAPTSO);
	}

last_seg_free_first_frag:
	if (is_last_seg) {
		/*Do dma unmap for the tso seg 0th frag */
		if (0 ==  tso_seg->seg.tso_frags[0].paddr) {
			qdf_err("ERROR: TSO seg frag 0 mapped physical address is NULL");
			qdf_assert(0);
			return;
		}
		qdf_nbuf_tso_unmap_frag(osdev,
					tso_seg->seg.tso_frags[0].paddr,
					tso_seg->seg.tso_frags[0].length,
					QDF_DMA_TO_DEVICE);
		tso_seg->seg.tso_frags[0].paddr = 0;
		qdf_tso_seg_dbg_record(tso_seg, TSOSEG_LOC_UNMAPLAST);
	}
}
qdf_export_symbol(__qdf_nbuf_unmap_tso_segment);

size_t __qdf_nbuf_get_tcp_payload_len(struct sk_buff *skb)
{
	size_t packet_len;

	packet_len = skb->len -
		((skb_transport_header(skb) - skb_mac_header(skb)) +
		 tcp_hdrlen(skb));

	return packet_len;
}

qdf_export_symbol(__qdf_nbuf_get_tcp_payload_len);

#ifndef BUILD_X86
uint32_t __qdf_nbuf_get_tso_num_seg(struct sk_buff *skb)
{
	uint32_t tso_seg_size = skb_shinfo(skb)->gso_size;
	uint32_t remainder, num_segs = 0;
	uint8_t skb_nr_frags = skb_shinfo(skb)->nr_frags;
	uint8_t frags_per_tso = 0;
	uint32_t skb_frag_len = 0;
	uint32_t eit_hdr_len = (skb_transport_header(skb)
			 - skb_mac_header(skb)) + tcp_hdrlen(skb);
	skb_frag_t *frag = NULL;
	int j = 0;
	uint32_t temp_num_seg = 0;

	/* length of the first chunk of data in the skb minus eit header*/
	skb_frag_len = skb_headlen(skb) - eit_hdr_len;

	/* Calculate num of segs for skb's first chunk of data*/
	remainder = skb_frag_len % tso_seg_size;
	num_segs = skb_frag_len / tso_seg_size;
	/*
	 * Remainder non-zero and nr_frags zero implies end of skb data.
	 * In that case, one more tso seg is required to accommodate
	 * remaining data, hence num_segs++. If nr_frags is non-zero,
	 * then remaining data will be accommodated while doing the calculation
	 * for nr_frags data. Hence, frags_per_tso++.
	 */
	if (remainder) {
		if (!skb_nr_frags)
			num_segs++;
		else
			frags_per_tso++;
	}

	while (skb_nr_frags) {
		if (j >= skb_shinfo(skb)->nr_frags) {
			qdf_info("TSO: nr_frags %d j %d",
				 skb_shinfo(skb)->nr_frags, j);
			qdf_assert(0);
			return 0;
		}
		/*
		 * Calculate the number of tso seg for nr_frags data:
		 * Get the length of each frag in skb_frag_len, add to
		 * remainder.Get the number of segments by dividing it to
		 * tso_seg_size and calculate the new remainder.
		 * Decrement the nr_frags value and keep
		 * looping all the skb_fragments.
		 */
		frag = &skb_shinfo(skb)->frags[j];
		skb_frag_len = skb_frag_size(frag);
		temp_num_seg = num_segs;
		remainder += skb_frag_len;
		num_segs += remainder / tso_seg_size;
		remainder = remainder % tso_seg_size;
		skb_nr_frags--;
		if (remainder) {
			if (num_segs > temp_num_seg)
				frags_per_tso = 0;
			/*
			 * increment the tso per frags whenever remainder is
			 * positive. If frags_per_tso reaches the (max-1),
			 * [First frags always have EIT header, therefore max-1]
			 * increment the num_segs as no more data can be
			 * accommodated in the curr tso seg. Reset the remainder
			 * and frags per tso and keep looping.
			 */
			frags_per_tso++;
			if (frags_per_tso == FRAG_NUM_MAX - 1) {
				num_segs++;
				frags_per_tso = 0;
				remainder = 0;
			}
			/*
			 * If this is the last skb frag and still remainder is
			 * non-zero(frags_per_tso is not reached to the max-1)
			 * then increment the num_segs to take care of the
			 * remaining length.
			 */
			if (!skb_nr_frags && remainder) {
				num_segs++;
				frags_per_tso = 0;
			}
		} else {
			 /* Whenever remainder is 0, reset the frags_per_tso. */
			frags_per_tso = 0;
		}
		j++;
	}

	return num_segs;
}
#elif !defined(QCA_WIFI_QCN9000)
uint32_t __qdf_nbuf_get_tso_num_seg(struct sk_buff *skb)
{
	uint32_t i, gso_size, tmp_len, num_segs = 0;
	skb_frag_t *frag = NULL;

	/*
	 * Check if the head SKB or any of frags are allocated in < 0x50000000
	 * region which cannot be accessed by Target
	 */
	if (virt_to_phys(skb->data) < 0x50000040) {
		TSO_DEBUG("%s %d: Invalid Address nr_frags = %d, paddr = %pK \n",
				__func__, __LINE__, skb_shinfo(skb)->nr_frags,
				virt_to_phys(skb->data));
		goto fail;

	}

	for (i = 0; i < skb_shinfo(skb)->nr_frags; i++) {
		frag = &skb_shinfo(skb)->frags[i];

		if (!frag)
			goto fail;

		if (virt_to_phys(skb_frag_address_safe(frag)) < 0x50000040)
			goto fail;
	}


	gso_size = skb_shinfo(skb)->gso_size;
	tmp_len = skb->len - ((skb_transport_header(skb) - skb_mac_header(skb))
			+ tcp_hdrlen(skb));
	while (tmp_len) {
		num_segs++;
		if (tmp_len > gso_size)
			tmp_len -= gso_size;
		else
			break;
	}

	return num_segs;

	/*
	 * Do not free this frame, just do socket level accounting
	 * so that this is not reused.
	 */
fail:
	if (skb->sk)
		atomic_sub(skb->truesize, &(skb->sk->sk_wmem_alloc));

	return 0;
}
#else
uint32_t __qdf_nbuf_get_tso_num_seg(struct sk_buff *skb)
{
	uint32_t i, gso_size, tmp_len, num_segs = 0;
	skb_frag_t *frag = NULL;

	for (i = 0; i < skb_shinfo(skb)->nr_frags; i++) {
		frag = &skb_shinfo(skb)->frags[i];

		if (!frag)
			goto fail;
	}

	gso_size = skb_shinfo(skb)->gso_size;
	tmp_len = skb->len - ((skb_transport_header(skb) - skb_mac_header(skb))
			+ tcp_hdrlen(skb));
	while (tmp_len) {
		num_segs++;
		if (tmp_len > gso_size)
			tmp_len -= gso_size;
		else
			break;
	}

	return num_segs;

	/*
	 * Do not free this frame, just do socket level accounting
	 * so that this is not reused.
	 */
fail:
	if (skb->sk)
		atomic_sub(skb->truesize, &(skb->sk->sk_wmem_alloc));

	return 0;
}
#endif
qdf_export_symbol(__qdf_nbuf_get_tso_num_seg);

#endif /* FEATURE_TSO */

void __qdf_dmaaddr_to_32s(qdf_dma_addr_t dmaaddr,
			  uint32_t *lo, uint32_t *hi)
{
	if (sizeof(dmaaddr) > sizeof(uint32_t)) {
		*lo = lower_32_bits(dmaaddr);
		*hi = upper_32_bits(dmaaddr);
	} else {
		*lo = dmaaddr;
		*hi = 0;
	}
}

qdf_export_symbol(__qdf_dmaaddr_to_32s);

struct sk_buff *__qdf_nbuf_inc_users(struct sk_buff *skb)
{
	qdf_nbuf_users_inc(&skb->users);
	return skb;
}
qdf_export_symbol(__qdf_nbuf_inc_users);

int __qdf_nbuf_get_users(struct sk_buff *skb)
{
	return qdf_nbuf_users_read(&skb->users);
}
qdf_export_symbol(__qdf_nbuf_get_users);

void __qdf_nbuf_ref(struct sk_buff *skb)
{
	skb_get(skb);
}
qdf_export_symbol(__qdf_nbuf_ref);

int __qdf_nbuf_shared(struct sk_buff *skb)
{
	return skb_shared(skb);
}
qdf_export_symbol(__qdf_nbuf_shared);

QDF_STATUS
__qdf_nbuf_dmamap_create(qdf_device_t osdev, __qdf_dma_map_t *dmap)
{
	QDF_STATUS error = QDF_STATUS_SUCCESS;
	/*
	 * driver can tell its SG capability, it must be handled.
	 * Bounce buffers if they are there
	 */
	(*dmap) = kzalloc(sizeof(struct __qdf_dma_map), GFP_KERNEL);
	if (!(*dmap))
		error = QDF_STATUS_E_NOMEM;

	return error;
}
qdf_export_symbol(__qdf_nbuf_dmamap_create);

void
__qdf_nbuf_dmamap_destroy(qdf_device_t osdev, __qdf_dma_map_t dmap)
{
	kfree(dmap);
}
qdf_export_symbol(__qdf_nbuf_dmamap_destroy);

#ifdef QDF_OS_DEBUG
QDF_STATUS
__qdf_nbuf_map_nbytes(
	qdf_device_t osdev,
	struct sk_buff *skb,
	qdf_dma_dir_t dir,
	int nbytes)
{
	struct skb_shared_info  *sh = skb_shinfo(skb);

	qdf_assert((dir == QDF_DMA_TO_DEVICE) || (dir == QDF_DMA_FROM_DEVICE));

	/*
	 * Assume there's only a single fragment.
	 * To support multiple fragments, it would be necessary to change
	 * adf_nbuf_t to be a separate object that stores meta-info
	 * (including the bus address for each fragment) and a pointer
	 * to the underlying sk_buff.
	 */
	qdf_assert(sh->nr_frags == 0);

	return __qdf_nbuf_map_nbytes_single(osdev, skb, dir, nbytes);
}
qdf_export_symbol(__qdf_nbuf_map_nbytes);
#else
QDF_STATUS
__qdf_nbuf_map_nbytes(
	qdf_device_t osdev,
	struct sk_buff *skb,
	qdf_dma_dir_t dir,
	int nbytes)
{
	return __qdf_nbuf_map_nbytes_single(osdev, skb, dir, nbytes);
}
qdf_export_symbol(__qdf_nbuf_map_nbytes);
#endif
void
__qdf_nbuf_unmap_nbytes(
	qdf_device_t osdev,
	struct sk_buff *skb,
	qdf_dma_dir_t dir,
	int nbytes)
{
	qdf_assert((dir == QDF_DMA_TO_DEVICE) || (dir == QDF_DMA_FROM_DEVICE));

	/*
	 * Assume there's a single fragment.
	 * If this is not true, the assertion in __adf_nbuf_map will catch it.
	 */
	__qdf_nbuf_unmap_nbytes_single(osdev, skb, dir, nbytes);
}
qdf_export_symbol(__qdf_nbuf_unmap_nbytes);

void
__qdf_nbuf_dma_map_info(__qdf_dma_map_t bmap, qdf_dmamap_info_t *sg)
{
	qdf_assert(bmap->mapped);
	qdf_assert(bmap->nsegs <= QDF_MAX_SCATTER);

	memcpy(sg->dma_segs, bmap->seg, bmap->nsegs *
			sizeof(struct __qdf_segment));
	sg->nsegs = bmap->nsegs;
}
qdf_export_symbol(__qdf_nbuf_dma_map_info);

#if defined(__QDF_SUPPORT_FRAG_MEM)
void
__qdf_nbuf_frag_info(struct sk_buff *skb, qdf_sglist_t  *sg)
{
	qdf_assert(skb);
	sg->sg_segs[0].vaddr = skb->data;
	sg->sg_segs[0].len   = skb->len;
	sg->nsegs            = 1;

	for (int i = 1; i <= sh->nr_frags; i++) {
		skb_frag_t    *f        = &sh->frags[i - 1];

		sg->sg_segs[i].vaddr    = (uint8_t *)(page_address(f->page) +
			f->page_offset);
		sg->sg_segs[i].len      = f->size;

		qdf_assert(i < QDF_MAX_SGLIST);
	}
	sg->nsegs += i;

}
qdf_export_symbol(__qdf_nbuf_frag_info);
#else
#ifdef QDF_OS_DEBUG
void
__qdf_nbuf_frag_info(struct sk_buff *skb, qdf_sglist_t  *sg)
{

	struct skb_shared_info  *sh = skb_shinfo(skb);

	qdf_assert(skb);
	sg->sg_segs[0].vaddr = skb->data;
	sg->sg_segs[0].len   = skb->len;
	sg->nsegs            = 1;

	qdf_assert(sh->nr_frags == 0);
}
qdf_export_symbol(__qdf_nbuf_frag_info);
#else
void
__qdf_nbuf_frag_info(struct sk_buff *skb, qdf_sglist_t  *sg)
{
	sg->sg_segs[0].vaddr = skb->data;
	sg->sg_segs[0].len   = skb->len;
	sg->nsegs            = 1;
}
qdf_export_symbol(__qdf_nbuf_frag_info);
#endif
#endif
uint32_t
__qdf_nbuf_get_frag_size(__qdf_nbuf_t nbuf, uint32_t cur_frag)
{
	struct skb_shared_info  *sh = skb_shinfo(nbuf);
	const skb_frag_t *frag = sh->frags + cur_frag;

	return skb_frag_size(frag);
}
qdf_export_symbol(__qdf_nbuf_get_frag_size);

#ifdef A_SIMOS_DEVHOST
QDF_STATUS __qdf_nbuf_frag_map(
	qdf_device_t osdev, __qdf_nbuf_t nbuf,
	int offset, qdf_dma_dir_t dir, int cur_frag)
{
	int32_t paddr, frag_len;

	QDF_NBUF_CB_PADDR(nbuf) = paddr = nbuf->data;
	return QDF_STATUS_SUCCESS;
}
qdf_export_symbol(__qdf_nbuf_frag_map);
#else
QDF_STATUS __qdf_nbuf_frag_map(
	qdf_device_t osdev, __qdf_nbuf_t nbuf,
	int offset, qdf_dma_dir_t dir, int cur_frag)
{
	dma_addr_t paddr, frag_len;
	struct skb_shared_info *sh = skb_shinfo(nbuf);
	const skb_frag_t *frag = sh->frags + cur_frag;

	frag_len = skb_frag_size(frag);

	QDF_NBUF_CB_TX_EXTRA_FRAG_PADDR(nbuf) = paddr =
		skb_frag_dma_map(osdev->dev, frag, offset, frag_len,
					__qdf_dma_dir_to_os(dir));
	return dma_mapping_error(osdev->dev, paddr) ?
			QDF_STATUS_E_FAULT : QDF_STATUS_SUCCESS;
}
qdf_export_symbol(__qdf_nbuf_frag_map);
#endif
void
__qdf_nbuf_dmamap_set_cb(__qdf_dma_map_t dmap, void *cb, void *arg)
{
	return;
}
qdf_export_symbol(__qdf_nbuf_dmamap_set_cb);

/**
 * __qdf_nbuf_sync_single_for_cpu() - nbuf sync
 * @osdev: os device
 * @buf: sk buff
 * @dir: direction
 *
 * Return: none
 */
#if defined(A_SIMOS_DEVHOST)
static void __qdf_nbuf_sync_single_for_cpu(
	qdf_device_t osdev, qdf_nbuf_t buf, qdf_dma_dir_t dir)
{
	return;
}
#else
static void __qdf_nbuf_sync_single_for_cpu(
	qdf_device_t osdev, qdf_nbuf_t buf, qdf_dma_dir_t dir)
{
	if (0 ==  QDF_NBUF_CB_PADDR(buf)) {
		qdf_err("ERROR: NBUF mapped physical address is NULL");
		return;
	}
	dma_sync_single_for_cpu(osdev->dev, QDF_NBUF_CB_PADDR(buf),
		skb_end_offset(buf) - skb_headroom(buf),
		__qdf_dma_dir_to_os(dir));
}
#endif

void
__qdf_nbuf_sync_for_cpu(qdf_device_t osdev,
	struct sk_buff *skb, qdf_dma_dir_t dir)
{
	qdf_assert(
	(dir == QDF_DMA_TO_DEVICE) || (dir == QDF_DMA_FROM_DEVICE));

	/*
	 * Assume there's a single fragment.
	 * If this is not true, the assertion in __adf_nbuf_map will catch it.
	 */
	__qdf_nbuf_sync_single_for_cpu(osdev, skb, dir);
}
qdf_export_symbol(__qdf_nbuf_sync_for_cpu);

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0))
/**
 * qdf_nbuf_update_radiotap_vht_flags() - Update radiotap header VHT flags
 * @rx_status: Pointer to rx_status.
 * @rtap_buf: Buf to which VHT info has to be updated.
 * @rtap_len: Current length of radiotap buffer
 *
 * Return: Length of radiotap after VHT flags updated.
 */
static unsigned int qdf_nbuf_update_radiotap_vht_flags(
					struct mon_rx_status *rx_status,
					int8_t *rtap_buf,
					uint32_t rtap_len)
{
	uint16_t vht_flags = 0;
	struct mon_rx_user_status *rx_user_status = rx_status->rx_user_status;

	rtap_len = qdf_align(rtap_len, 2);

	/* IEEE80211_RADIOTAP_VHT u16, u8, u8, u8[4], u8, u8, u16 */
	vht_flags |= IEEE80211_RADIOTAP_VHT_KNOWN_STBC |
		IEEE80211_RADIOTAP_VHT_KNOWN_GI |
		IEEE80211_RADIOTAP_VHT_KNOWN_LDPC_EXTRA_OFDM_SYM |
		IEEE80211_RADIOTAP_VHT_KNOWN_BEAMFORMED |
		IEEE80211_RADIOTAP_VHT_KNOWN_BANDWIDTH |
		IEEE80211_RADIOTAP_VHT_KNOWN_GROUP_ID;
	put_unaligned_le16(vht_flags, &rtap_buf[rtap_len]);
	rtap_len += 2;

	rtap_buf[rtap_len] |=
		(rx_status->is_stbc ?
		 IEEE80211_RADIOTAP_VHT_FLAG_STBC : 0) |
		(rx_status->sgi ? IEEE80211_RADIOTAP_VHT_FLAG_SGI : 0) |
		(rx_status->ldpc ?
		 IEEE80211_RADIOTAP_VHT_FLAG_LDPC_EXTRA_OFDM_SYM : 0) |
		(rx_status->beamformed ?
		 IEEE80211_RADIOTAP_VHT_FLAG_BEAMFORMED : 0);
	rtap_len += 1;

	if (!rx_user_status) {
		switch (rx_status->vht_flag_values2) {
		case IEEE80211_RADIOTAP_VHT_BW_20:
			rtap_buf[rtap_len] = RADIOTAP_VHT_BW_20;
			break;
		case IEEE80211_RADIOTAP_VHT_BW_40:
			rtap_buf[rtap_len] = RADIOTAP_VHT_BW_40;
			break;
		case IEEE80211_RADIOTAP_VHT_BW_80:
			rtap_buf[rtap_len] = RADIOTAP_VHT_BW_80;
			break;
		case IEEE80211_RADIOTAP_VHT_BW_160:
			rtap_buf[rtap_len] = RADIOTAP_VHT_BW_160;
			break;
		}
		rtap_len += 1;
		rtap_buf[rtap_len] = (rx_status->vht_flag_values3[0]);
		rtap_len += 1;
		rtap_buf[rtap_len] = (rx_status->vht_flag_values3[1]);
		rtap_len += 1;
		rtap_buf[rtap_len] = (rx_status->vht_flag_values3[2]);
		rtap_len += 1;
		rtap_buf[rtap_len] = (rx_status->vht_flag_values3[3]);
		rtap_len += 1;
		rtap_buf[rtap_len] = (rx_status->vht_flag_values4);
		rtap_len += 1;
		rtap_buf[rtap_len] = (rx_status->vht_flag_values5);
		rtap_len += 1;
		put_unaligned_le16(rx_status->vht_flag_values6,
				   &rtap_buf[rtap_len]);
		rtap_len += 2;
	} else {
		switch (rx_user_status->vht_flag_values2) {
		case IEEE80211_RADIOTAP_VHT_BW_20:
			rtap_buf[rtap_len] = RADIOTAP_VHT_BW_20;
			break;
		case IEEE80211_RADIOTAP_VHT_BW_40:
			rtap_buf[rtap_len] = RADIOTAP_VHT_BW_40;
			break;
		case IEEE80211_RADIOTAP_VHT_BW_80:
			rtap_buf[rtap_len] = RADIOTAP_VHT_BW_80;
			break;
		case IEEE80211_RADIOTAP_VHT_BW_160:
			rtap_buf[rtap_len] = RADIOTAP_VHT_BW_160;
			break;
		}
		rtap_len += 1;
		rtap_buf[rtap_len] = (rx_user_status->vht_flag_values3[0]);
		rtap_len += 1;
		rtap_buf[rtap_len] = (rx_user_status->vht_flag_values3[1]);
		rtap_len += 1;
		rtap_buf[rtap_len] = (rx_user_status->vht_flag_values3[2]);
		rtap_len += 1;
		rtap_buf[rtap_len] = (rx_user_status->vht_flag_values3[3]);
		rtap_len += 1;
		rtap_buf[rtap_len] = (rx_user_status->vht_flag_values4);
		rtap_len += 1;
		rtap_buf[rtap_len] = (rx_user_status->vht_flag_values5);
		rtap_len += 1;
		put_unaligned_le16(rx_user_status->vht_flag_values6,
				   &rtap_buf[rtap_len]);
		rtap_len += 2;
	}

	return rtap_len;
}

/**
 * qdf_nbuf_update_radiotap_he_flags() - Update radiotap header from rx_status
 * @rx_status: Pointer to rx_status.
 * @rtap_buf: buffer to which radiotap has to be updated
 * @rtap_len: radiotap length
 *
 * API update high-efficiency (11ax) fields in the radiotap header
 *
 * Return: length of rtap_len updated.
 */
static unsigned int
qdf_nbuf_update_radiotap_he_flags(struct mon_rx_status *rx_status,
				     int8_t *rtap_buf, uint32_t rtap_len)
{
	/*
	 * IEEE80211_RADIOTAP_HE u16, u16, u16, u16, u16, u16
	 * Enable all "known" HE radiotap flags for now
	 */

	rtap_len = qdf_align(rtap_len, 2);

	put_unaligned_le16(rx_status->he_data1, &rtap_buf[rtap_len]);
	rtap_len += 2;

	put_unaligned_le16(rx_status->he_data2, &rtap_buf[rtap_len]);
	rtap_len += 2;

	put_unaligned_le16(rx_status->he_data3, &rtap_buf[rtap_len]);
	rtap_len += 2;

	put_unaligned_le16(rx_status->he_data4, &rtap_buf[rtap_len]);
	rtap_len += 2;

	put_unaligned_le16(rx_status->he_data5, &rtap_buf[rtap_len]);
	rtap_len += 2;

	put_unaligned_le16(rx_status->he_data6, &rtap_buf[rtap_len]);
	rtap_len += 2;

	return rtap_len;
}


/**
 * qdf_nbuf_update_radiotap_he_mu_flags() - update he-mu radiotap flags
 * @rx_status: Pointer to rx_status.
 * @rtap_buf: buffer to which radiotap has to be updated
 * @rtap_len: radiotap length
 *
 * API update HE-MU fields in the radiotap header
 *
 * Return: length of rtap_len updated.
 */
static unsigned int
qdf_nbuf_update_radiotap_he_mu_flags(struct mon_rx_status *rx_status,
				     int8_t *rtap_buf, uint32_t rtap_len)
{
	struct mon_rx_user_status *rx_user_status = rx_status->rx_user_status;

	rtap_len = qdf_align(rtap_len, 2);

	/*
	 * IEEE80211_RADIOTAP_HE_MU u16, u16, u8[4]
	 * Enable all "known" he-mu radiotap flags for now
	 */

	if (!rx_user_status) {
		put_unaligned_le16(rx_status->he_flags1, &rtap_buf[rtap_len]);
		rtap_len += 2;

		put_unaligned_le16(rx_status->he_flags2, &rtap_buf[rtap_len]);
		rtap_len += 2;

		rtap_buf[rtap_len] = rx_status->he_RU[0];
		rtap_len += 1;

		rtap_buf[rtap_len] = rx_status->he_RU[1];
		rtap_len += 1;

		rtap_buf[rtap_len] = rx_status->he_RU[2];
		rtap_len += 1;

		rtap_buf[rtap_len] = rx_status->he_RU[3];
		rtap_len += 1;
	} else {
		put_unaligned_le16(rx_user_status->he_flags1,
				   &rtap_buf[rtap_len]);
		rtap_len += 2;

		put_unaligned_le16(rx_user_status->he_flags2,
				   &rtap_buf[rtap_len]);
		rtap_len += 2;

		rtap_buf[rtap_len] = rx_user_status->he_RU[0];
		rtap_len += 1;

		rtap_buf[rtap_len] = rx_user_status->he_RU[1];
		rtap_len += 1;

		rtap_buf[rtap_len] = rx_user_status->he_RU[2];
		rtap_len += 1;

		rtap_buf[rtap_len] = rx_user_status->he_RU[3];
		rtap_len += 1;
		qdf_debug("he_flags %x %x he-RU %x %x %x %x",
			  rx_user_status->he_flags1,
			  rx_user_status->he_flags2, rx_user_status->he_RU[0],
			  rx_user_status->he_RU[1], rx_user_status->he_RU[2],
			  rx_user_status->he_RU[3]);
	}

	return rtap_len;
}

/**
 * qdf_nbuf_update_radiotap_he_mu_other_flags() - update he_mu_other flags
 * @rx_status: Pointer to rx_status.
 * @rtap_buf: buffer to which radiotap has to be updated
 * @rtap_len: radiotap length
 *
 * API update he-mu-other fields in the radiotap header
 *
 * Return: length of rtap_len updated.
 */
static unsigned int
qdf_nbuf_update_radiotap_he_mu_other_flags(struct mon_rx_status *rx_status,
				     int8_t *rtap_buf, uint32_t rtap_len)
{
	struct mon_rx_user_status *rx_user_status = rx_status->rx_user_status;

	rtap_len = qdf_align(rtap_len, 2);

	/*
	 * IEEE80211_RADIOTAP_HE-MU-OTHER u16, u16, u8, u8
	 * Enable all "known" he-mu-other radiotap flags for now
	 */
	if (!rx_user_status) {
		put_unaligned_le16(rx_status->he_per_user_1,
				   &rtap_buf[rtap_len]);
		rtap_len += 2;

		put_unaligned_le16(rx_status->he_per_user_2,
				   &rtap_buf[rtap_len]);
		rtap_len += 2;

		rtap_buf[rtap_len] = rx_status->he_per_user_position;
		rtap_len += 1;

		rtap_buf[rtap_len] = rx_status->he_per_user_known;
		rtap_len += 1;
	} else {
		put_unaligned_le16(rx_user_status->he_per_user_1,
				   &rtap_buf[rtap_len]);
		rtap_len += 2;

		put_unaligned_le16(rx_user_status->he_per_user_2,
				   &rtap_buf[rtap_len]);
		rtap_len += 2;

		rtap_buf[rtap_len] = rx_user_status->he_per_user_position;
		rtap_len += 1;

		rtap_buf[rtap_len] = rx_user_status->he_per_user_known;
		rtap_len += 1;
	}

	return rtap_len;
}

/**
 * qdf_nbuf_update_radiotap_usig_flags() - Update radiotap header with USIG data
 *						from rx_status
 * @rx_status: Pointer to rx_status.
 * @rtap_buf: buffer to which radiotap has to be updated
 * @rtap_len: radiotap length
 *
 * API update Extra High Throughput (11be) fields in the radiotap header
 *
 * Return: length of rtap_len updated.
 */
static unsigned int
qdf_nbuf_update_radiotap_usig_flags(struct mon_rx_status *rx_status,
				    int8_t *rtap_buf, uint32_t rtap_len)
{
	/*
	 * IEEE80211_RADIOTAP_USIG:
	 *		u32, u32, u32
	 */
	rtap_len = qdf_align(rtap_len, 4);

	put_unaligned_le32(rx_status->usig_common, &rtap_buf[rtap_len]);
	rtap_len += 4;

	put_unaligned_le32(rx_status->usig_value, &rtap_buf[rtap_len]);
	rtap_len += 4;

	put_unaligned_le32(rx_status->usig_mask, &rtap_buf[rtap_len]);
	rtap_len += 4;

	qdf_rl_debug("U-SIG data %x %x %x",
		     rx_status->usig_common, rx_status->usig_value,
		     rx_status->usig_mask);

	return rtap_len;
}

/**
 * qdf_nbuf_update_radiotap_eht_flags() - Update radiotap header with EHT data
 *					from rx_status
 * @rx_status: Pointer to rx_status.
 * @rtap_buf: buffer to which radiotap has to be updated
 * @rtap_len: radiotap length
 *
 * API update Extra High Throughput (11be) fields in the radiotap header
 *
 * Return: length of rtap_len updated.
 */
static unsigned int
qdf_nbuf_update_radiotap_eht_flags(struct mon_rx_status *rx_status,
				   int8_t *rtap_buf, uint32_t rtap_len)
{
	uint32_t user;

	/*
	 * IEEE80211_RADIOTAP_EHT:
	 *		u32, u32, u32, u32, u32, u32, u32, u16, [u32, u32, u32]
	 */
	rtap_len = qdf_align(rtap_len, 4);

	put_unaligned_le32(rx_status->eht_known, &rtap_buf[rtap_len]);
	rtap_len += 4;

	put_unaligned_le32(rx_status->eht_data[0], &rtap_buf[rtap_len]);
	rtap_len += 4;

	put_unaligned_le32(rx_status->eht_data[1], &rtap_buf[rtap_len]);
	rtap_len += 4;

	put_unaligned_le32(rx_status->eht_data[2], &rtap_buf[rtap_len]);
	rtap_len += 4;

	put_unaligned_le32(rx_status->eht_data[3], &rtap_buf[rtap_len]);
	rtap_len += 4;

	put_unaligned_le32(rx_status->eht_data[4], &rtap_buf[rtap_len]);
	rtap_len += 4;

	put_unaligned_le32(rx_status->eht_data[5], &rtap_buf[rtap_len]);
	rtap_len += 4;

	for (user = 0; user < EHT_USER_INFO_LEN &&
	     rx_status->num_eht_user_info_valid &&
	     user < rx_status->num_eht_user_info_valid; user++) {
		put_unaligned_le32(rx_status->eht_user_info[user],
				   &rtap_buf[rtap_len]);
		rtap_len += 4;
	}

	qdf_rl_debug("EHT data %x %x %x %x %x %x %x",
		     rx_status->eht_known, rx_status->eht_data[0],
		     rx_status->eht_data[1], rx_status->eht_data[2],
		     rx_status->eht_data[3], rx_status->eht_data[4],
		     rx_status->eht_data[5]);

	return rtap_len;
}

#define IEEE80211_RADIOTAP_TX_STATUS 0
#define IEEE80211_RADIOTAP_RETRY_COUNT 1
#define IEEE80211_RADIOTAP_EXTENSION2 2
uint8_t ATH_OUI[] = {0x00, 0x03, 0x7f}; /* Atheros OUI */

/**
 * qdf_nbuf_update_radiotap_ampdu_flags() - Update radiotap header ampdu flags
 * @rx_status: Pointer to rx_status.
 * @rtap_buf: Buf to which AMPDU info has to be updated.
 * @rtap_len: Current length of radiotap buffer
 *
 * Return: Length of radiotap after AMPDU flags updated.
 */
static unsigned int qdf_nbuf_update_radiotap_ampdu_flags(
					struct mon_rx_status *rx_status,
					uint8_t *rtap_buf,
					uint32_t rtap_len)
{
	/*
	 * IEEE80211_RADIOTAP_AMPDU_STATUS u32 u16 u8 u8
	 * First 32 bits of AMPDU represents the reference number
	 */

	uint32_t ampdu_reference_num = rx_status->ppdu_id;
	uint16_t ampdu_flags = 0;
	uint16_t ampdu_reserved_flags = 0;

	rtap_len = qdf_align(rtap_len, 4);

	put_unaligned_le32(ampdu_reference_num, &rtap_buf[rtap_len]);
	rtap_len += 4;
	put_unaligned_le16(ampdu_flags, &rtap_buf[rtap_len]);
	rtap_len += 2;
	put_unaligned_le16(ampdu_reserved_flags, &rtap_buf[rtap_len]);
	rtap_len += 2;

	return rtap_len;
}

#ifdef DP_MON_RSSI_IN_DBM
#define QDF_MON_STATUS_GET_RSSI_IN_DBM(rx_status) \
(rx_status->rssi_comb)
#else
#ifdef QCA_RSSI_DB2DBM
#define QDF_MON_STATUS_GET_RSSI_IN_DBM(rx_status) \
(((rx_status)->rssi_dbm_conv_support) ? \
((rx_status)->rssi_comb + (rx_status)->rssi_offset) :\
((rx_status)->rssi_comb + (rx_status)->chan_noise_floor))
#else
#define QDF_MON_STATUS_GET_RSSI_IN_DBM(rx_status) \
(rx_status->rssi_comb + rx_status->chan_noise_floor)
#endif
#endif

/**
 * qdf_nbuf_update_radiotap_tx_flags() - Update radiotap header tx flags
 * @rx_status: Pointer to rx_status.
 * @rtap_buf: Buf to which tx info has to be updated.
 * @rtap_len: Current length of radiotap buffer
 *
 * Return: Length of radiotap after tx flags updated.
 */
static unsigned int qdf_nbuf_update_radiotap_tx_flags(
						struct mon_rx_status *rx_status,
						uint8_t *rtap_buf,
						uint32_t rtap_len)
{
	/*
	 * IEEE80211_RADIOTAP_TX_FLAGS u16
	 */

	uint16_t tx_flags = 0;

	rtap_len = qdf_align(rtap_len, 2);

	switch (rx_status->tx_status) {
	case RADIOTAP_TX_STATUS_FAIL:
		tx_flags |= IEEE80211_RADIOTAP_F_TX_FAIL;
		break;
	case RADIOTAP_TX_STATUS_NOACK:
		tx_flags |= IEEE80211_RADIOTAP_F_TX_NOACK;
		break;
	}
	put_unaligned_le16(tx_flags, &rtap_buf[rtap_len]);
	rtap_len += 2;

	return rtap_len;
}

unsigned int qdf_nbuf_update_radiotap(struct mon_rx_status *rx_status,
				      qdf_nbuf_t nbuf, uint32_t headroom_sz)
{
	uint8_t rtap_buf[RADIOTAP_HEADER_LEN] = {0};
	struct ieee80211_radiotap_header *rthdr =
		(struct ieee80211_radiotap_header *)rtap_buf;
	uint32_t rtap_hdr_len = sizeof(struct ieee80211_radiotap_header);
	uint32_t rtap_len = rtap_hdr_len;
	uint8_t length = rtap_len;
	struct qdf_radiotap_vendor_ns_ath *radiotap_vendor_ns_ath;
	struct qdf_radiotap_ext2 *rtap_ext2;
	struct mon_rx_user_status *rx_user_status = rx_status->rx_user_status;

	/* per user info */
	qdf_le32_t *it_present;
	uint32_t it_present_val;
	bool radiotap_ext1_hdr_present = false;

	it_present = &rthdr->it_present;

	/* Adding Extended Header space */
	if (rx_status->add_rtap_ext || rx_status->add_rtap_ext2 ||
	    rx_status->usig_flags || rx_status->eht_flags) {
		rtap_hdr_len += RADIOTAP_HEADER_EXT_LEN;
		rtap_len = rtap_hdr_len;
		radiotap_ext1_hdr_present = true;
	}

	length = rtap_len;

	/* IEEE80211_RADIOTAP_TSFT              __le64       microseconds*/
	it_present_val = (1 << IEEE80211_RADIOTAP_TSFT);
	put_unaligned_le64(rx_status->tsft, &rtap_buf[rtap_len]);
	rtap_len += 8;

	/* IEEE80211_RADIOTAP_FLAGS u8 */
	it_present_val |= (1 << IEEE80211_RADIOTAP_FLAGS);

	if (rx_status->rs_fcs_err)
		rx_status->rtap_flags |= IEEE80211_RADIOTAP_F_BADFCS;

	rtap_buf[rtap_len] = rx_status->rtap_flags;
	rtap_len += 1;

	/* IEEE80211_RADIOTAP_RATE  u8           500kb/s */
	if (!rx_status->ht_flags && !rx_status->vht_flags &&
	    !rx_status->he_flags && !rx_status->eht_flags) {
		it_present_val |= (1 << IEEE80211_RADIOTAP_RATE);
		rtap_buf[rtap_len] = rx_status->rate;
	} else
		rtap_buf[rtap_len] = 0;
	rtap_len += 1;

	/* IEEE80211_RADIOTAP_CHANNEL 2 x __le16   MHz, bitmap */
	it_present_val |= (1 << IEEE80211_RADIOTAP_CHANNEL);
	put_unaligned_le16(rx_status->chan_freq, &rtap_buf[rtap_len]);
	rtap_len += 2;
	/* Channel flags. */
	if (rx_status->chan_freq > CHANNEL_FREQ_5150)
		rx_status->chan_flags = RADIOTAP_5G_SPECTRUM_CHANNEL;
	else
		rx_status->chan_flags = RADIOTAP_2G_SPECTRUM_CHANNEL;
	if (rx_status->cck_flag)
		rx_status->chan_flags |= RADIOTAP_CCK_CHANNEL;
	if (rx_status->ofdm_flag)
		rx_status->chan_flags |= RADIOTAP_OFDM_CHANNEL;
	put_unaligned_le16(rx_status->chan_flags, &rtap_buf[rtap_len]);
	rtap_len += 2;

	/* IEEE80211_RADIOTAP_DBM_ANTSIGNAL s8  decibels from one milliwatt
	 *					(dBm)
	 */
	it_present_val |= (1 << IEEE80211_RADIOTAP_DBM_ANTSIGNAL);
	/*
	 * rssi_comb is int dB, need to convert it to dBm.
	 * normalize value to noise floor of -96 dBm
	 */
	rtap_buf[rtap_len] = QDF_MON_STATUS_GET_RSSI_IN_DBM(rx_status);
	rtap_len += 1;

	/* RX signal noise floor */
	it_present_val |= (1 << IEEE80211_RADIOTAP_DBM_ANTNOISE);
	rtap_buf[rtap_len] = (uint8_t)rx_status->chan_noise_floor;
	rtap_len += 1;

	/* IEEE80211_RADIOTAP_ANTENNA   u8      antenna index */
	it_present_val |= (1 << IEEE80211_RADIOTAP_ANTENNA);
	rtap_buf[rtap_len] = rx_status->nr_ant;
	rtap_len += 1;

	if ((rtap_len - length) > RADIOTAP_FIXED_HEADER_LEN) {
		qdf_print("length is greater than RADIOTAP_FIXED_HEADER_LEN");
		return 0;
	}

	/* update tx flags for pkt capture*/
	if (rx_status->add_rtap_ext) {
		it_present_val |=
			cpu_to_le32(1 << IEEE80211_RADIOTAP_TX_FLAGS);
		rtap_len = qdf_nbuf_update_radiotap_tx_flags(rx_status,
							     rtap_buf,
							     rtap_len);

		if ((rtap_len - length) > RADIOTAP_TX_FLAGS_LEN) {
			qdf_print("length is greater than RADIOTAP_TX_FLAGS_LEN");
			return 0;
		}
	}

	if (rx_status->ht_flags) {
		length = rtap_len;
		/* IEEE80211_RADIOTAP_VHT u8, u8, u8 */
		it_present_val |= (1 << IEEE80211_RADIOTAP_MCS);
		rtap_buf[rtap_len] = IEEE80211_RADIOTAP_MCS_HAVE_BW |
					IEEE80211_RADIOTAP_MCS_HAVE_MCS |
					IEEE80211_RADIOTAP_MCS_HAVE_GI;
		rtap_len += 1;

		if (rx_status->sgi)
			rtap_buf[rtap_len] |= IEEE80211_RADIOTAP_MCS_SGI;
		if (rx_status->bw)
			rtap_buf[rtap_len] |= IEEE80211_RADIOTAP_MCS_BW_40;
		else
			rtap_buf[rtap_len] |= IEEE80211_RADIOTAP_MCS_BW_20;
		rtap_len += 1;

		rtap_buf[rtap_len] = rx_status->ht_mcs;
		rtap_len += 1;

		if ((rtap_len - length) > RADIOTAP_HT_FLAGS_LEN) {
			qdf_print("length is greater than RADIOTAP_HT_FLAGS_LEN");
			return 0;
		}
	}

	if (rx_status->rs_flags & IEEE80211_AMPDU_FLAG) {
		/* IEEE80211_RADIOTAP_AMPDU_STATUS u32 u16 u8 u8 */
		it_present_val |= (1 << IEEE80211_RADIOTAP_AMPDU_STATUS);
		rtap_len = qdf_nbuf_update_radiotap_ampdu_flags(rx_status,
								rtap_buf,
								rtap_len);
	}

	if (rx_status->vht_flags) {
		length = rtap_len;
		/* IEEE80211_RADIOTAP_VHT u16, u8, u8, u8[4], u8, u8, u16 */
		it_present_val |= (1 << IEEE80211_RADIOTAP_VHT);
		rtap_len = qdf_nbuf_update_radiotap_vht_flags(rx_status,
								rtap_buf,
								rtap_len);

		if ((rtap_len - length) > RADIOTAP_VHT_FLAGS_LEN) {
			qdf_print("length is greater than RADIOTAP_VHT_FLAGS_LEN");
			return 0;
		}
	}

	if (rx_status->he_flags) {
		length = rtap_len;
		/* IEEE80211_RADIOTAP_HE */
		it_present_val |= (1 << IEEE80211_RADIOTAP_HE);
		rtap_len = qdf_nbuf_update_radiotap_he_flags(rx_status,
								rtap_buf,
								rtap_len);

		if ((rtap_len - length) > RADIOTAP_HE_FLAGS_LEN) {
			qdf_print("length is greater than RADIOTAP_HE_FLAGS_LEN");
			return 0;
		}
	}

	if (rx_status->he_mu_flags) {
		length = rtap_len;
		/* IEEE80211_RADIOTAP_HE-MU */
		it_present_val |= (1 << IEEE80211_RADIOTAP_HE_MU);
		rtap_len = qdf_nbuf_update_radiotap_he_mu_flags(rx_status,
								rtap_buf,
								rtap_len);

		if ((rtap_len - length) > RADIOTAP_HE_MU_FLAGS_LEN) {
			qdf_print("length is greater than RADIOTAP_HE_MU_FLAGS_LEN");
			return 0;
		}
	}

	if (rx_status->he_mu_other_flags) {
		length = rtap_len;
		/* IEEE80211_RADIOTAP_HE-MU-OTHER */
		it_present_val |= (1 << IEEE80211_RADIOTAP_HE_MU_OTHER);
		rtap_len =
			qdf_nbuf_update_radiotap_he_mu_other_flags(rx_status,
								rtap_buf,
								rtap_len);

		if ((rtap_len - length) > RADIOTAP_HE_MU_OTHER_FLAGS_LEN) {
			qdf_print("length is greater than RADIOTAP_HE_MU_OTHER_FLAGS_LEN");
			return 0;
		}
	}

	rtap_len = qdf_align(rtap_len, 2);
	/*
	 * Radiotap Vendor Namespace
	 */
	it_present_val |= (1 << IEEE80211_RADIOTAP_VENDOR_NAMESPACE);
	radiotap_vendor_ns_ath = (struct qdf_radiotap_vendor_ns_ath *)
					(rtap_buf + rtap_len);
	/*
	 * Copy Atheros OUI - 3 bytes (4th byte is 0)
	 */
	qdf_mem_copy(radiotap_vendor_ns_ath->hdr.oui, ATH_OUI, sizeof(ATH_OUI));
	/*
	 * Name space selector = 0
	 * We only will have one namespace for now
	 */
	radiotap_vendor_ns_ath->hdr.selector = 0;
	radiotap_vendor_ns_ath->hdr.skip_length = cpu_to_le16(
					sizeof(*radiotap_vendor_ns_ath) -
					sizeof(radiotap_vendor_ns_ath->hdr));
	radiotap_vendor_ns_ath->device_id = cpu_to_le32(rx_status->device_id);
	radiotap_vendor_ns_ath->lsig = cpu_to_le32(rx_status->l_sig_a_info);
	radiotap_vendor_ns_ath->lsig_b = cpu_to_le32(rx_status->l_sig_b_info);
	radiotap_vendor_ns_ath->ppdu_start_timestamp =
				cpu_to_le32(rx_status->ppdu_timestamp);
	rtap_len += sizeof(*radiotap_vendor_ns_ath);

	/* Move to next it_present */
	if (radiotap_ext1_hdr_present) {
		it_present_val |= (1 << IEEE80211_RADIOTAP_EXT);
		put_unaligned_le32(it_present_val, it_present);
		it_present_val = 0;
		it_present++;
	}

	/* Add Extension to Radiotap Header & corresponding data */
	if (rx_status->add_rtap_ext) {
		it_present_val |= (1 << IEEE80211_RADIOTAP_TX_STATUS);
		it_present_val |= (1 << IEEE80211_RADIOTAP_RETRY_COUNT);

		rtap_buf[rtap_len] = rx_status->tx_status;
		rtap_len += 1;
		rtap_buf[rtap_len] = rx_status->tx_retry_cnt;
		rtap_len += 1;
	}

	/* Add Extension2 to Radiotap Header */
	if (rx_status->add_rtap_ext2) {
		it_present_val |= (1 << IEEE80211_RADIOTAP_EXTENSION2);

		rtap_ext2 = (struct qdf_radiotap_ext2 *)(rtap_buf + rtap_len);
		rtap_ext2->ppdu_id = rx_status->ppdu_id;
		rtap_ext2->prev_ppdu_id = rx_status->prev_ppdu_id;
		if (!rx_user_status) {
			rtap_ext2->tid = rx_status->tid;
			rtap_ext2->start_seq = rx_status->start_seq;
			qdf_mem_copy(rtap_ext2->ba_bitmap,
				     rx_status->ba_bitmap,
				     8 * (sizeof(uint32_t)));
		} else {
			uint8_t ba_bitmap_sz = rx_user_status->ba_bitmap_sz;

			/* set default bitmap sz if not set */
			ba_bitmap_sz = ba_bitmap_sz ? ba_bitmap_sz : 8;
			rtap_ext2->tid = rx_user_status->tid;
			rtap_ext2->start_seq = rx_user_status->start_seq;
			qdf_mem_copy(rtap_ext2->ba_bitmap,
				     rx_user_status->ba_bitmap,
				     ba_bitmap_sz * (sizeof(uint32_t)));
		}

		rtap_len += sizeof(*rtap_ext2);
	}

	if (rx_status->usig_flags) {
		length = rtap_len;
		/* IEEE80211_RADIOTAP_USIG */
		it_present_val |= (1 << IEEE80211_RADIOTAP_EXT1_USIG);
		rtap_len = qdf_nbuf_update_radiotap_usig_flags(rx_status,
							       rtap_buf,
							       rtap_len);

		if ((rtap_len - length) > RADIOTAP_EHT_FLAGS_LEN) {
			qdf_print("length is greater than RADIOTAP_EHT_FLAGS_LEN");
			return 0;
		}
	}

	if (rx_status->eht_flags) {
		length = rtap_len;
		/* IEEE80211_RADIOTAP_EHT */
		it_present_val |= (1 << IEEE80211_RADIOTAP_EXT1_EHT);
		rtap_len = qdf_nbuf_update_radiotap_eht_flags(rx_status,
							      rtap_buf,
							      rtap_len);

		if ((rtap_len - length) > RADIOTAP_EHT_FLAGS_LEN) {
			qdf_print("length is greater than RADIOTAP_EHT_FLAGS_LEN");
			return 0;
		}
	}

	put_unaligned_le32(it_present_val, it_present);
	rthdr->it_len = cpu_to_le16(rtap_len);

	if (headroom_sz < rtap_len) {
		qdf_debug("DEBUG: Not enough space to update radiotap");
		return 0;
	}

	qdf_nbuf_push_head(nbuf, rtap_len);
	qdf_mem_copy(qdf_nbuf_data(nbuf), rtap_buf, rtap_len);
	return rtap_len;
}
#else
static unsigned int qdf_nbuf_update_radiotap_vht_flags(
					struct mon_rx_status *rx_status,
					int8_t *rtap_buf,
					uint32_t rtap_len)
{
	qdf_err("ERROR: struct ieee80211_radiotap_header not supported");
	return 0;
}

unsigned int qdf_nbuf_update_radiotap_he_flags(struct mon_rx_status *rx_status,
				      int8_t *rtap_buf, uint32_t rtap_len)
{
	qdf_err("ERROR: struct ieee80211_radiotap_header not supported");
	return 0;
}

static unsigned int qdf_nbuf_update_radiotap_ampdu_flags(
					struct mon_rx_status *rx_status,
					uint8_t *rtap_buf,
					uint32_t rtap_len)
{
	qdf_err("ERROR: struct ieee80211_radiotap_header not supported");
	return 0;
}

unsigned int qdf_nbuf_update_radiotap(struct mon_rx_status *rx_status,
				      qdf_nbuf_t nbuf, uint32_t headroom_sz)
{
	qdf_err("ERROR: struct ieee80211_radiotap_header not supported");
	return 0;
}
#endif
qdf_export_symbol(qdf_nbuf_update_radiotap);

void __qdf_nbuf_reg_free_cb(qdf_nbuf_free_t cb_func_ptr)
{
	nbuf_free_cb = cb_func_ptr;
}

qdf_export_symbol(__qdf_nbuf_reg_free_cb);

void qdf_nbuf_classify_pkt(struct sk_buff *skb)
{
	struct ethhdr *eh = (struct ethhdr *)skb->data;

	/* check destination mac address is broadcast/multicast */
	if (is_broadcast_ether_addr((uint8_t *)eh))
		QDF_NBUF_CB_SET_BCAST(skb);
	else if (is_multicast_ether_addr((uint8_t *)eh))
		QDF_NBUF_CB_SET_MCAST(skb);

	if (qdf_nbuf_is_ipv4_arp_pkt(skb))
		QDF_NBUF_CB_GET_PACKET_TYPE(skb) =
			QDF_NBUF_CB_PACKET_TYPE_ARP;
	else if (qdf_nbuf_is_ipv4_dhcp_pkt(skb))
		QDF_NBUF_CB_GET_PACKET_TYPE(skb) =
			QDF_NBUF_CB_PACKET_TYPE_DHCP;
	else if (qdf_nbuf_is_ipv4_eapol_pkt(skb))
		QDF_NBUF_CB_GET_PACKET_TYPE(skb) =
			QDF_NBUF_CB_PACKET_TYPE_EAPOL;
	else if (qdf_nbuf_is_ipv4_wapi_pkt(skb))
		QDF_NBUF_CB_GET_PACKET_TYPE(skb) =
			QDF_NBUF_CB_PACKET_TYPE_WAPI;
}
qdf_export_symbol(qdf_nbuf_classify_pkt);

void __qdf_nbuf_init(__qdf_nbuf_t nbuf)
{
	qdf_nbuf_users_set(&nbuf->users, 1);
	nbuf->data = nbuf->head + NET_SKB_PAD;
	skb_reset_tail_pointer(nbuf);
}
qdf_export_symbol(__qdf_nbuf_init);

#ifdef WLAN_FEATURE_FASTPATH
void qdf_nbuf_init_fast(qdf_nbuf_t nbuf)
{
	qdf_nbuf_users_set(&nbuf->users, 1);
	skb_reset_tail_pointer(nbuf);
}
qdf_export_symbol(qdf_nbuf_init_fast);
#endif /* WLAN_FEATURE_FASTPATH */


#ifdef QDF_NBUF_GLOBAL_COUNT
void __qdf_nbuf_mod_init(void)
{
	is_initial_mem_debug_disabled = qdf_mem_debug_config_get();
	qdf_atomic_init(&nbuf_count);
	qdf_debugfs_create_atomic(NBUF_DEBUGFS_NAME, S_IRUSR, NULL, &nbuf_count);
}

void __qdf_nbuf_mod_exit(void)
{
}
#endif

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(5, 4, 0))
QDF_STATUS __qdf_nbuf_move_frag_page_offset(__qdf_nbuf_t nbuf, uint8_t idx,
					    int offset)
{
	unsigned int frag_offset;
	skb_frag_t *frag;

	if (qdf_unlikely(idx >= __qdf_nbuf_get_nr_frags(nbuf)))
		return QDF_STATUS_E_FAILURE;

	frag = &skb_shinfo(nbuf)->frags[idx];
	frag_offset = skb_frag_off(frag);

	frag_offset += offset;
	skb_frag_off_set(frag, frag_offset);

	__qdf_nbuf_trim_add_frag_size(nbuf, idx, -(offset), 0);

	return QDF_STATUS_SUCCESS;
}

#else
QDF_STATUS __qdf_nbuf_move_frag_page_offset(__qdf_nbuf_t nbuf, uint8_t idx,
					    int offset)
{
	uint16_t frag_offset;
	skb_frag_t *frag;

	if (qdf_unlikely(idx >= __qdf_nbuf_get_nr_frags(nbuf)))
		return QDF_STATUS_E_FAILURE;

	frag = &skb_shinfo(nbuf)->frags[idx];
	frag_offset = frag->page_offset;

	frag_offset += offset;
	frag->page_offset = frag_offset;

	__qdf_nbuf_trim_add_frag_size(nbuf, idx, -(offset), 0);

	return QDF_STATUS_SUCCESS;
}
#endif

qdf_export_symbol(__qdf_nbuf_move_frag_page_offset);

void __qdf_nbuf_remove_frag(__qdf_nbuf_t nbuf,
			    uint16_t idx,
			    uint16_t truesize)
{
	struct page *page;
	uint16_t frag_len;

	page = skb_frag_page(&skb_shinfo(nbuf)->frags[idx]);

	if (qdf_unlikely(!page))
		return;

	frag_len = qdf_nbuf_get_frag_size_by_idx(nbuf, idx);
	put_page(page);
	nbuf->len -= frag_len;
	nbuf->data_len -= frag_len;
	nbuf->truesize -= truesize;
	skb_shinfo(nbuf)->nr_frags--;
}

qdf_export_symbol(__qdf_nbuf_remove_frag);

void __qdf_nbuf_add_rx_frag(__qdf_frag_t buf, __qdf_nbuf_t nbuf,
			    int offset, int frag_len,
			    unsigned int truesize, bool take_frag_ref)
{
	struct page *page;
	int frag_offset;
	uint8_t nr_frag;

	nr_frag = __qdf_nbuf_get_nr_frags(nbuf);
	qdf_assert_always(nr_frag < QDF_NBUF_MAX_FRAGS);

	page = virt_to_head_page(buf);
	frag_offset = buf - page_address(page);

	skb_add_rx_frag(nbuf, nr_frag, page,
			(frag_offset + offset),
			frag_len, truesize);

	if (unlikely(take_frag_ref)) {
		qdf_frag_count_inc(QDF_NBUF_FRAG_DEBUG_COUNT_ONE);
		skb_frag_ref(nbuf, nr_frag);
	}
}

qdf_export_symbol(__qdf_nbuf_add_rx_frag);

#ifdef NBUF_FRAG_MEMORY_DEBUG

QDF_STATUS qdf_nbuf_move_frag_page_offset_debug(qdf_nbuf_t nbuf, uint8_t idx,
						int offset, const char *func,
						uint32_t line)
{
	QDF_STATUS result;
	qdf_frag_t p_fragp, n_fragp;

	p_fragp = qdf_nbuf_get_frag_addr(nbuf, idx);
	result = __qdf_nbuf_move_frag_page_offset(nbuf, idx, offset);

	if (qdf_likely(is_initial_mem_debug_disabled))
		return result;

	n_fragp = qdf_nbuf_get_frag_addr(nbuf, idx);

	/*
	 * Update frag address in frag debug tracker
	 * when frag offset is successfully changed in skb
	 */
	if (result == QDF_STATUS_SUCCESS)
		qdf_frag_debug_update_addr(p_fragp, n_fragp, func, line);

	return result;
}

qdf_export_symbol(qdf_nbuf_move_frag_page_offset_debug);

void qdf_nbuf_add_rx_frag_debug(qdf_frag_t buf, qdf_nbuf_t nbuf,
				int offset, int frag_len,
				unsigned int truesize, bool take_frag_ref,
				const char *func, uint32_t line)
{
	qdf_frag_t fragp;
	uint32_t num_nr_frags;

	__qdf_nbuf_add_rx_frag(buf, nbuf, offset,
			       frag_len, truesize, take_frag_ref);

	if (qdf_likely(is_initial_mem_debug_disabled))
		return;

	num_nr_frags = qdf_nbuf_get_nr_frags(nbuf);

	qdf_assert_always(num_nr_frags <= QDF_NBUF_MAX_FRAGS);

	fragp = qdf_nbuf_get_frag_addr(nbuf, num_nr_frags - 1);

	/* Update frag address in frag debug tracking table */
	if (fragp != buf && !take_frag_ref)
		qdf_frag_debug_update_addr(buf, fragp, func, line);

	/* Update frag refcount in frag debug tracking table */
	qdf_frag_debug_refcount_inc(fragp, func, line);
}

qdf_export_symbol(qdf_nbuf_add_rx_frag_debug);

void qdf_net_buf_debug_acquire_frag(qdf_nbuf_t buf, const char *func,
				    uint32_t line)
{
	uint32_t num_nr_frags;
	uint32_t idx = 0;
	qdf_nbuf_t ext_list;
	qdf_frag_t p_frag;

	if (qdf_likely(is_initial_mem_debug_disabled))
		return;

	if (qdf_unlikely(!buf))
		return;

	/* Take care to update the refcount in the debug entries for frags */
	num_nr_frags = qdf_nbuf_get_nr_frags(buf);

	qdf_assert_always(num_nr_frags <= QDF_NBUF_MAX_FRAGS);

	while (idx < num_nr_frags) {
		p_frag = qdf_nbuf_get_frag_addr(buf, idx);
		if (qdf_likely(p_frag))
			qdf_frag_debug_refcount_inc(p_frag, func, line);
		idx++;
	}

	/*
	 * Take care to update the refcount in the debug entries for the
	 * frags attached to frag_list
	 */
	ext_list = qdf_nbuf_get_ext_list(buf);
	while (ext_list) {
		idx = 0;
		num_nr_frags = qdf_nbuf_get_nr_frags(ext_list);

		qdf_assert_always(num_nr_frags <= QDF_NBUF_MAX_FRAGS);

		while (idx < num_nr_frags) {
			p_frag = qdf_nbuf_get_frag_addr(ext_list, idx);
			if (qdf_likely(p_frag))
				qdf_frag_debug_refcount_inc(p_frag, func, line);
			idx++;
		}
		ext_list = qdf_nbuf_queue_next(ext_list);
	}
}

qdf_export_symbol(qdf_net_buf_debug_acquire_frag);

void qdf_net_buf_debug_release_frag(qdf_nbuf_t buf, const char *func,
				    uint32_t line)
{
	uint32_t num_nr_frags;
	qdf_nbuf_t ext_list;
	uint32_t idx = 0;
	qdf_frag_t p_frag;

	if (qdf_likely(is_initial_mem_debug_disabled))
		return;

	if (qdf_unlikely(!buf))
		return;

	/*
	 * Decrement refcount for frag debug nodes only when last user
	 * of nbuf calls this API so as to avoid decrementing refcount
	 * on every call expect the last one in case where nbuf has multiple
	 * users
	 */
	if (qdf_nbuf_get_users(buf) > 1)
		return;

	/* Take care to update the refcount in the debug entries for frags */
	num_nr_frags = qdf_nbuf_get_nr_frags(buf);

	qdf_assert_always(num_nr_frags <= QDF_NBUF_MAX_FRAGS);

	while (idx < num_nr_frags) {
		p_frag = qdf_nbuf_get_frag_addr(buf, idx);
		if (qdf_likely(p_frag))
			qdf_frag_debug_refcount_dec(p_frag, func, line);
		idx++;
	}

	/* Take care to update debug entries for frags attached to frag_list */
	ext_list = qdf_nbuf_get_ext_list(buf);
	while (ext_list) {
		if (qdf_nbuf_get_users(ext_list) == 1) {
			idx = 0;
			num_nr_frags = qdf_nbuf_get_nr_frags(ext_list);
			qdf_assert_always(num_nr_frags <= QDF_NBUF_MAX_FRAGS);
			while (idx < num_nr_frags) {
				p_frag = qdf_nbuf_get_frag_addr(ext_list, idx);
				if (qdf_likely(p_frag))
					qdf_frag_debug_refcount_dec(p_frag,
								    func, line);
				idx++;
			}
		}
		ext_list = qdf_nbuf_queue_next(ext_list);
	}
}

qdf_export_symbol(qdf_net_buf_debug_release_frag);

QDF_STATUS
qdf_nbuf_remove_frag_debug(qdf_nbuf_t nbuf,
			   uint16_t idx,
			   uint16_t truesize,
			   const char *func,
			   uint32_t line)
{
	uint16_t num_frags;
	qdf_frag_t frag;

	if (qdf_unlikely(!nbuf))
		return QDF_STATUS_E_INVAL;

	num_frags = qdf_nbuf_get_nr_frags(nbuf);
	if (idx >= num_frags)
		return QDF_STATUS_E_INVAL;

	if (qdf_likely(is_initial_mem_debug_disabled)) {
		__qdf_nbuf_remove_frag(nbuf, idx, truesize);
		return QDF_STATUS_SUCCESS;
	}

	frag = qdf_nbuf_get_frag_addr(nbuf, idx);
	if (qdf_likely(frag))
		qdf_frag_debug_refcount_dec(frag, func, line);

	__qdf_nbuf_remove_frag(nbuf, idx, truesize);

	return QDF_STATUS_SUCCESS;
}

qdf_export_symbol(qdf_nbuf_remove_frag_debug);

#endif /* NBUF_FRAG_MEMORY_DEBUG */

qdf_nbuf_t qdf_get_nbuf_valid_frag(qdf_nbuf_t nbuf)
{
	qdf_nbuf_t last_nbuf;
	uint32_t num_frags;

	if (qdf_unlikely(!nbuf))
		return NULL;

	num_frags = qdf_nbuf_get_nr_frags(nbuf);

	/* Check nbuf has enough memory to store frag memory */
	if (num_frags < QDF_NBUF_MAX_FRAGS)
		return nbuf;

	if (!__qdf_nbuf_has_fraglist(nbuf))
		return NULL;

	last_nbuf = __qdf_nbuf_get_last_frag_list_nbuf(nbuf);
	if (qdf_unlikely(!last_nbuf))
		return NULL;

	num_frags = qdf_nbuf_get_nr_frags(last_nbuf);
	if (num_frags < QDF_NBUF_MAX_FRAGS)
		return last_nbuf;

	return NULL;
}

qdf_export_symbol(qdf_get_nbuf_valid_frag);

QDF_STATUS
qdf_nbuf_add_frag_debug(qdf_device_t osdev, qdf_frag_t buf,
			qdf_nbuf_t nbuf, int offset,
			int frag_len, unsigned int truesize,
			bool take_frag_ref, unsigned int minsize,
			const char *func, uint32_t line)
{
	qdf_nbuf_t cur_nbuf;
	qdf_nbuf_t this_nbuf;

	cur_nbuf = nbuf;
	this_nbuf = nbuf;

	if (qdf_unlikely(!frag_len || !buf)) {
		qdf_nofl_err("%s : %d frag[ buf[%pK] len[%d]] not valid\n",
			     func, line,
			     buf, frag_len);
		return QDF_STATUS_E_INVAL;
	}

	this_nbuf = qdf_get_nbuf_valid_frag(this_nbuf);

	if (this_nbuf) {
		cur_nbuf = this_nbuf;
	} else {
		/* allocate a dummy mpdu buffer of 64 bytes headroom */
		this_nbuf = qdf_nbuf_alloc(osdev, minsize, minsize, 4, false);
		if (qdf_unlikely(!this_nbuf)) {
			qdf_nofl_err("%s : %d no memory to allocate\n",
				     func, line);
			return QDF_STATUS_E_NOMEM;
		}
	}

	qdf_nbuf_add_rx_frag(buf, this_nbuf, offset, frag_len, truesize,
			     take_frag_ref);

	if (this_nbuf != cur_nbuf) {
		/* add new skb to frag list */
		qdf_nbuf_append_ext_list(nbuf, this_nbuf,
					 qdf_nbuf_len(this_nbuf));
	}

	return QDF_STATUS_SUCCESS;
}

qdf_export_symbol(qdf_nbuf_add_frag_debug);

#ifdef MEMORY_DEBUG
void qdf_nbuf_acquire_track_lock(uint32_t index,
				 unsigned long irq_flag)
{
	spin_lock_irqsave(&g_qdf_net_buf_track_lock[index],
			  irq_flag);
}

void qdf_nbuf_release_track_lock(uint32_t index,
				 unsigned long irq_flag)
{
	spin_unlock_irqrestore(&g_qdf_net_buf_track_lock[index],
			       irq_flag);
}

QDF_NBUF_TRACK *qdf_nbuf_get_track_tbl(uint32_t index)
{
	return gp_qdf_net_buf_track_tbl[index];
}
#endif /* MEMORY_DEBUG */

#ifdef ENHANCED_OS_ABSTRACTION
void qdf_nbuf_set_timestamp(qdf_nbuf_t buf)
{
	__qdf_nbuf_set_timestamp(buf);
}

qdf_export_symbol(qdf_nbuf_set_timestamp);

uint64_t qdf_nbuf_get_timestamp(qdf_nbuf_t buf)
{
	return __qdf_nbuf_get_timestamp(buf);
}

qdf_export_symbol(qdf_nbuf_get_timestamp);

uint64_t qdf_nbuf_get_timestamp_us(qdf_nbuf_t buf)
{
	return __qdf_nbuf_get_timestamp_us(buf);
}

qdf_export_symbol(qdf_nbuf_get_timestamp_us);

uint64_t qdf_nbuf_get_timedelta_us(qdf_nbuf_t buf)
{
	return __qdf_nbuf_get_timedelta_us(buf);
}

qdf_export_symbol(qdf_nbuf_get_timedelta_us);

uint64_t qdf_nbuf_get_timedelta_ms(qdf_nbuf_t buf)
{
	return __qdf_nbuf_get_timedelta_ms(buf);
}

qdf_export_symbol(qdf_nbuf_get_timedelta_ms);

qdf_ktime_t qdf_nbuf_net_timedelta(qdf_ktime_t t)
{
	return __qdf_nbuf_net_timedelta(t);
}

qdf_export_symbol(qdf_nbuf_net_timedelta);
#endif
