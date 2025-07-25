// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2010 Samsung Electronics.
 *
 */

#include <linux/irq.h>
#include <linux/time.h>
#include <linux/interrupt.h>
#include <linux/timer.h>
#include <linux/delay.h>
#include <linux/wait.h>
#include <linux/sched.h>
#include <linux/vmalloc.h>
#include <linux/platform_device.h>
#include <linux/kallsyms.h>
#include <linux/suspend.h>
#include <linux/reboot.h>
#include <linux/pci.h>
#include <linux/of_reserved_mem.h>
#if IS_ENABLED(CONFIG_ECT)
#include <soc/samsung/ect_parser.h>
#endif
#include <soc/samsung/shm_ipc.h>
#include "mcu_ipc.h"
#include <soc/samsung/cal-if.h>
#include <soc/samsung/exynos-smc.h>
#if IS_ENABLED(CONFIG_CP_LLC)
#include <soc/samsung/exynos-sci.h>
#endif
#if IS_ENABLED(CONFIG_LINK_DEVICE_SHMEM)
#include <soc/samsung/esca.h>
#endif
#include <trace/events/napi.h>
#include "modem_prj.h"
#include "modem_utils.h"
#include "link_device.h"
#include "modem_ctrl.h"
#include "modem_notifier.h"
#if IS_ENABLED(CONFIG_LINK_DEVICE_PCIE)
#include "s51xx_pcie.h"
#endif
#include "dit.h"
#include "direct_dm.h"
#if IS_ENABLED(CONFIG_CLO)
#include "../../../clo/clo.h"
#endif

#define MIF_TX_QUOTA 64

enum smc_error_flag {
	CP_NO_ERROR = 0,
	CP_NOT_ALIGN_64KB,
	CP_MEM_TOO_BIG,
	CP_FLAG_OUT_RANGE,
	CP_WRONG_TZASC_REGION_NUM,
	CP_WRONG_BL_SIZE = 5,
	CP_MEM_OUT_OF_RANGE,
	CP_NOT_ALIGN_16B,
	CP_MEM_IN_SECURE_DRAM,
	CP_ASP_ENABLE_FAIL,
	CP_ASP_DISABLE_FAIL = 10,
	CP_NOT_WORKING,
	CP_ALREADY_WORKING,
	CP_ALREADY_DUMP_MODE,
	CP_NOT_VALID_MAGIC,
	CP_SHOULD_BE_DISABLE = 15,
	CP_ALREADY_ENABLE_CPMEM_ON,
	CP_ALREADY_SET_WND,
	CP_FAIL_TO_SET_WND,
	CP_INVALID_CP_BASE,
	CP_CORRUPTED_CP_MEM_INFO = 20,
	CP_WHILE_CHECKING_SIGN,
	CP_NOT_WHILE_CHECKING_SIGN,
	CP_IS_IN_INVALID_STATE,
	CP_IS_IN_INVALID_STATE2,
	CP_ERR_WHILE_CP_SIGN_CHECK,

	CP_CHECK_SIGN_NOT_FINISH = 0x100
};

static inline void start_tx_timer(struct mem_link_device *mld,
				  struct hrtimer *timer);

#if IS_ENABLED(CONFIG_EXYNOS_CPIF_IOMMU) || IS_ENABLED(CONFIG_EXYNOS_CPIF_IOMMU_V9)
#define SYSMMU_BAAW_SIZE	0x8000000
#endif

#if IS_ENABLED(CONFIG_CP_LLC)
enum cp_llc_target {
	LLC_CP_CPU = 0,
	LLC_CP_MAXTP,
	LLC_CP_PKTPROC,
	LLC_CP_MAX,
};

enum cp_llc_request {
	LLC_REQUEST_ALLOC = 0,
	LLC_REQUEST_GET,
	LLC_REQUEST_MAX,
};

enum cp_llc_configuration {
	LLC_ALLOC = 0,
	LLC_WAY,
	MAX_LLC_CONF,
};

enum cp_llc_return {
	LLC_ALLOC_FAIL = 0,
	LLC_ALLOC_SUCCESS,
	LLC_DEALLOC_FAIL,
	LLC_DEALLOC_SUCCESS,
	LLC_GET_SUCCESS,
	LLC_GET_FAIL,
	LLC_RETURN_CLEAR_BY_CP = 0xF,
	MAX_LLC_RETURN,
};

static int cp_llc_arr[LLC_CP_MAX][MAX_LLC_CONF];

static int alloc_llc_to_cp(enum cp_llc_target target, int alloc, int way)
{
	enum exynos_sci_llc_region_index sci_index;
	int original_alloc, original_way;
	int ret;

	original_alloc = cp_llc_arr[target][LLC_ALLOC];
	original_way = cp_llc_arr[target][LLC_WAY];

	if (alloc == original_alloc) {
		mif_err("Multiple %s not allowed. way:%d",
			alloc ? "alloc" : "dealloc", way);
		return -EINVAL;
	} else if (alloc == 0 && way != 0) {
		mif_err("When dealloc, please put way to 0 instead of %d\n", way);
		return -EINVAL;
	}

	switch(target) {
	case LLC_CP_CPU:
		sci_index = LLC_REGION_CPCPU;
		break;
	case LLC_CP_MAXTP:
		sci_index = LLC_REGION_CP_MAX_TP;
		break;
	case LLC_CP_PKTPROC:
		sci_index = LLC_REGION_CPD2;
		break;
	default:
		mif_err("Target not available:%d", target);
		return -EINVAL;
	}

	ret = llc_region_alloc(sci_index, alloc, way);
	if (ret != 0) {
		mif_err("LLC %s request failed: target %d error:%d alloc:%d way:%d\n",
				alloc ? "alloc" : "dealloc", target, ret, alloc, way);
		return -EINVAL;
	}
	ret = llc_get_region_info(sci_index);
	if (ret != way) {
		mif_err("LLC is not properly %s for target %d req way:%d actual way:%d",
				alloc ? "allocated" : "deallocated", target, way, ret);
		return -EPERM;
	}

	cp_llc_arr[target][LLC_ALLOC] = alloc;
	cp_llc_arr[target][LLC_WAY] = way;

	mif_info("LLC %s to target %d with way %d\n",
			alloc ? "applied" : "disabled", target, way);

	return ret;
}
#endif /* end of CONFIG_CP_LLC */
/*============================================================================*/
static inline void purge_txq(struct mem_link_device *mld)
{
	int i;
#if IS_ENABLED(CONFIG_LINK_DEVICE_WITH_SBD_ARCH)
	struct link_device *ld = &mld->link_dev;

	/* Purge the skb_txq in every rb */
	if (ld->sbd_ipc) {
		struct sbd_link_device *sl = &mld->sbd_link_dev;

		for (i = 0; i < sl->num_channels; i++) {
			struct sbd_ring_buffer *rb = sbd_id2rb(sl, i, TX);

			skb_queue_purge(&rb->skb_q);
		}
	}
#endif

	/* Purge the skb_txq in every IPC device
	 * (IPC_MAP_FMT, IPC_MAP_NORM_RAW, etc.)
	 */
	for (i = 0; i < IPC_MAP_MAX; i++) {
		struct legacy_ipc_device *dev = mld->legacy_link_dev.dev[i];

		skb_queue_purge(dev->skb_txq);
	}
}

/*============================================================================*/
static void shmem_handle_cp_crash(struct mem_link_device *mld,
		enum modem_state state)
{
	struct link_device *ld = &mld->link_dev;
	struct modem_ctl *mc = ld->mc;

	/* Disable normal IPC */
	iowrite32(ld->magic_crash, mld->legacy_link_dev.magic);
	iowrite32(0, mld->legacy_link_dev.mem_access);

#if IS_ENABLED(CONFIG_CPIF_TP_MONITOR)
	tpmon_stop();
#endif

	stop_net_ifaces(ld, 0);
	purge_txq(mld);

	if (cp_online(mc)) {
		switch (state) {
		case STATE_CRASH_RESET:
			modem_notify_event(MODEM_EVENT_RESET, mc);
			break;
		case STATE_CRASH_EXIT:
			modem_notify_event(MODEM_EVENT_EXIT, mc);
			break;
		case STATE_CRASH_WATCHDOG:
			modem_notify_event(MODEM_EVENT_WATCHDOG, mc);
			break;
		default:
			mif_err("Invalid state to notify\n");
			break;
		}
	}

	if (cp_online(mc) || cp_booting(mc))
		change_modem_state(mc, state);

	atomic_set(&mld->forced_cp_crash, 0);
}

static void handle_no_cp_crash_ack(struct timer_list *t)
{
	struct mem_link_device *mld = from_timer(mld, t, crash_ack_timer);
	struct link_device *ld = &mld->link_dev;
	struct modem_ctl *mc = ld->mc;

#if IS_ENABLED(CONFIG_LINK_DEVICE_PCIE) && IS_ENABLED(CONFIG_CP_WRESET_WA)
	if (ld->link_type == LINKDEV_PCIE) {
		if (mif_gpio_get_value(&mc->cp_gpio[CP_GPIO_CP2AP_CP_ACTIVE], true) == 0)
			mc->s5100_cp_reset_required = false;
		else
			mc->s5100_cp_reset_required = true;

		mif_info("Set s5100_cp_reset_required to %u\n", mc->s5100_cp_reset_required);
	}
#endif

	if (cp_crashed(mc))
		mif_debug("%s: STATE_CRASH_EXIT without CRASH_ACK\n", ld->name);
	else {
		mif_err("%s: ERR! No CRASH_ACK from CP\n", ld->name);
		shmem_handle_cp_crash(mld, STATE_CRASH_EXIT);
	}
}

static void link_trigger_cp_crash(struct mem_link_device *mld, u32 crash_type,
		char *reason)
{
	struct link_device *ld = &mld->link_dev;
	struct modem_ctl *mc = ld->mc;

	if (!cp_online(mc) && !cp_booting(mc)) {
		mif_err("%s: %s.state %s != ONLINE <%ps>\n",
				ld->name, mc->name, mc_state(mc), CALLER);
		return;
	}

	if (atomic_inc_return(&mld->forced_cp_crash) > 1) {
		mif_err("%s: ALREADY in progress <%ps>\n", ld->name, CALLER);
		return;
	}

	/* Disable normal IPC */
	iowrite32(ld->magic_crash, mld->legacy_link_dev.magic);
	iowrite32(0, mld->legacy_link_dev.mem_access);

	mif_stop_logging();
	mif_stop_ap_ppmu_logging();

	memset(ld->crash_reason.string, 0, CP_CRASH_INFO_SIZE);

	switch (ld->protocol) {
	case PROTOCOL_SIPC:
	case PROTOCOL_SIT:
		break;
	default:
		mif_err("ERR - unknown protocol\n");
		goto set_type;
	}

	switch (crash_type) {
	case CRASH_REASON_MIF_TX_ERR:
	case CRASH_REASON_MIF_RIL_BAD_CH:
	case CRASH_REASON_MIF_RX_BAD_DATA:
	case CRASH_REASON_MIF_FORCED:
		break;
	case CRASH_REASON_USER:
	case CRASH_REASON_CLD:
		if (ld->protocol != PROTOCOL_SIPC)
			goto set_type;
		break;
	case CRASH_REASON_RIL_TRIGGER_CP_CRASH:
		if (ld->protocol != PROTOCOL_SIT)
			goto set_type;
		break;
	default:
		goto set_type;
	}

	if (reason && reason[0] != '\0')
		strlcpy(ld->crash_reason.string, reason, CP_CRASH_INFO_SIZE);

set_type:
	ld->crash_reason.type = crash_type;

	stop_net_ifaces(ld, 0);

	if (mld->debug_info)
		mld->debug_info();

	/**
	 * If there is no CRASH_ACK from CP in a timeout,
	 * handle_no_cp_crash_ack() will be executed.
	 */
	mif_add_timer(&mld->crash_ack_timer, FORCE_CRASH_ACK_TIMEOUT,
		      handle_no_cp_crash_ack);

	update_ctrl_msg(&mld->ap2cp_united_status, ld->crash_reason.type,
			mc->sbi_crash_type_mask, mc->sbi_crash_type_pos);

#if IS_ENABLED(CONFIG_LINK_DEVICE_SHMEM)
	if (ld->interrupt_types == INTERRUPT_MAILBOX) {
		/* Send CRASH_EXIT command to a CP */
		send_ipc_irq_debug(mld, cmd2int(CMD_CRASH_EXIT));
	}
#endif

#if IS_ENABLED(CONFIG_SEC_MODEM_S5100) || IS_ENABLED(CONFIG_SEC_MODEM_S5400)
	if (ld->interrupt_types == INTERRUPT_GPIO)
		/* Raise DUMP_NOTI GPIO to CP */
		s5100_send_dump_noti(mc);
#endif

	mif_err("%s->%s: CP_CRASH_REQ by %d, %s <%ps>\n",
				ld->name, mc->name, ld->crash_reason.type,
				ld->crash_reason.string, CALLER);
}

static bool rild_ready(struct link_device *ld, u64 *delta_time)
{
	int opened_cnt = 0;
	int ds_det = 0;
	struct io_device *iod_fmt0 = link_get_iod_with_channel(ld, SIPC5_CH_ID_FMT_0);
	struct io_device *iod_fmt1 = link_get_iod_with_channel(ld, SIPC5_CH_ID_FMT_1);
	struct io_device *iod_rfs0 = link_get_iod_with_channel(ld, SIPC5_CH_ID_RFS_0);

	switch (ld->protocol) {
	case PROTOCOL_SIT:
		return true;
	case PROTOCOL_SIPC:
		if (iod_rfs0 && !atomic_read(&iod_rfs0->opened)) {
			mif_err_limited("%s: %s is not opened\n", ld->name, iod_rfs0->name);
			return false;
		}

		if (iod_fmt0 && atomic_read(&iod_fmt0->opened))
			opened_cnt++;
		if (iod_fmt1 && atomic_read(&iod_fmt1->opened))
			opened_cnt++;

		if (opened_cnt == 2) {
			if (ktime_after(iod_fmt0->opened_time, iod_fmt1->opened_time))
				*delta_time = ktime_ms_delta(iod_fmt0->opened_time, iod_fmt1->opened_time);
			else
				*delta_time = ktime_ms_delta(iod_fmt1->opened_time, iod_fmt0->opened_time);
		}

		ds_det = get_ds_detect();

		if (iod_fmt0 && (ds_det + 1) == 2 && opened_cnt == 1)
			mif_err_limited("%s: only umts_ipc%d is opened\n",
					ld->name, atomic_read(&iod_fmt0->opened) ? 0 : 1);

		mif_info_limited("%s: opened_cnt: %d, sim count: %d\n", ld->name, opened_cnt, (ds_det + 1));

		if (opened_cnt == (ds_det + 1))
			return true;

		return false;
	default:
		mif_err("%s: undefined protocol: %d\n", ld->name, ld->protocol);
		return false;
	}

	return false;
}

static void write_clk_table_to_shmem(struct mem_link_device *mld)
{
	struct clock_table *clk_tb;
	u32 *clk_data;
	int i, j;

	if (mld->clk_table == NULL) {
		mif_err("clk_table is not defined\n");
		return;
	}

	clk_tb = (struct clock_table *)mld->clk_table;

	strcpy(clk_tb->parser_version, "CT1");
	clk_tb->total_table_count = mld->total_freq_table_count;

	memcpy(clk_tb->table_info[0].table_name, "MIF\0", 4);
	clk_tb->table_info[0].table_count = mld->mif_table.num_of_table;

	memcpy(clk_tb->table_info[1].table_name, "CP_C", 4);
	clk_tb->table_info[1].table_count = mld->cp_cpu_table.num_of_table;

	memcpy(clk_tb->table_info[2].table_name, "CP\0", 4);
	clk_tb->table_info[2].table_count = mld->cp_table.num_of_table;

	memcpy(clk_tb->table_info[3].table_name, "CP_E", 4);
	clk_tb->table_info[3].table_count = mld->cp_em_table.num_of_table;

	memcpy(clk_tb->table_info[4].table_name, "CP_M", 4);
	clk_tb->table_info[4].table_count = mld->cp_mcw_table.num_of_table;


	clk_data = (u32 *)&(clk_tb->table_info[clk_tb->total_table_count]);

	/* MIF */
	for (i = 0; i < mld->mif_table.num_of_table; i++) {
		*clk_data = mld->mif_table.freq[i];
		clk_data++;
	}

	/* CP_CPU */
	for (i = 0; i < mld->cp_cpu_table.num_of_table; i++) {
		*clk_data = mld->cp_cpu_table.freq[i];
		clk_data++;
	}

	/* CP */
	for (i = 0; i < mld->cp_table.num_of_table; i++) {
		*clk_data = mld->cp_table.freq[i];
		clk_data++;
	}

	/* CP_EM */
	for (i = 0; i < mld->cp_em_table.num_of_table; i++) {
		*clk_data = mld->cp_em_table.freq[i];
		clk_data++;
	}

	/* CP_MCW */
	for (i = 0; i < mld->cp_mcw_table.num_of_table; i++) {
		*clk_data = mld->cp_mcw_table.freq[i];
		clk_data++;
	}

	mif_info("PARSER_VERSION: %s\n", clk_tb->parser_version);
	mif_info("TOTAL_TABLE_COUNT: %d\n", clk_tb->total_table_count);

	for (i = 0; i < clk_tb->total_table_count; i++) {
		mif_info("TABLE_NAME[%d] : %s\n", i+1,
			clk_tb->table_info[i].table_name);
		mif_info("TABLE_COUNT[%d]: %d\n", i+1,
			clk_tb->table_info[i].table_count);
	}

	clk_data = (u32 *)&(clk_tb->table_info[clk_tb->total_table_count]);

	for (i = 0; i < clk_tb->total_table_count; i++) {
		for (j = 0; j < clk_tb->table_info[i].table_count; j++) {
			mif_info("CLOCK_TABLE[%d][%d] : %d\n",
				i+1, j+1, *clk_data);
			clk_data++;
		}
	}
}

static void set_ap_capabilities(struct mem_link_device *mld)
{
	int part;

#if IS_ENABLED(CONFIG_CP_PKTPROC_UL)
	cpif_set_bit(mld->ap_capability[0], AP_CAP_0_PKTPROC_UL_BIT);
#endif
#if IS_ENABLED(CONFIG_CH_EXTENSION)
	cpif_set_bit(mld->ap_capability[0], AP_CAP_0_CH_EXTENSION_BIT);
#endif
	if (mld->pktproc_use_36bit_addr)
		cpif_set_bit(mld->ap_capability[0], AP_CAP_0_PKTPROC_36BIT_ADDR_BIT);

	for (part = 0; part < AP_CP_CAP_PARTS; part++) {
		iowrite32(mld->ap_capability[part], mld->ap_capability_offset[part]);

		mif_info("capability part:%d AP:0x%08x\n", part, mld->ap_capability[part]);
	}
}

static int init_ap_capabilities(struct mem_link_device *mld, int part)
{
	int cap;
	int ret = 0;

	if (!mld->ap_capability[part])
		goto out;

	for (cap = 0; cap < AP_CP_CAP_BIT_MAX; cap++) {
		if (!cpif_check_bit(mld->ap_capability[part], cap))
			continue;

		/* should handle the matched capability */
		ret = -EINVAL;

		if (part == 0) {
			switch (cap) {
			case AP_CAP_0_PKTPROC_UL_BIT:
#if IS_ENABLED(CONFIG_CP_PKTPROC_UL)
				ret = pktproc_init_ul(&mld->pktproc_ul);
				if (ret)
					mif_err("pktproc_init_ul() ret:%d\n", ret);
#endif
				break;
			case AP_CAP_0_CH_EXTENSION_BIT:
			case AP_CAP_0_PKTPROC_36BIT_ADDR_BIT:
				ret = 0;
				break;
			default:
				mif_err("unsupported capability part:%d cap:%d\n", part, cap);
				break;
			}
		}

		if (ret)
			break;
	}

out:
	return ret;
}

static void cmd_init_start_handler(struct mem_link_device *mld)
{
	struct link_device *ld = &mld->link_dev;
	struct modem_ctl *mc = ld->mc;
	int err;

	mif_info("%s: INIT_START <- %s (%s.state:%s init_end_cnt:%d)\n",
		ld->name, mc->name, mc->name, mc_state(mc),
		atomic_read(&mld->init_end_cnt));

#if IS_ENABLED(CONFIG_CP_PKTPROC)
	err = pktproc_init(&mld->pktproc);
	if (err < 0) {
		mif_err("pktproc_init() error %d\n", err);
		return;
	}
#endif

#if IS_ENABLED(CONFIG_EXYNOS_DIT)
	err = dit_init(ld, DIT_INIT_NORMAL, DIT_STORE_NONE);
	if ((err < 0) && (err != -EPERM)) {
		mif_err("dit_init() error %d\n", err);
		return;
	}
#endif

#if IS_ENABLED(CONFIG_CPIF_DIRECT_DM)
	err = direct_dm_init(ld);
	if (err < 0) {
		mif_err("direct_dm_init() error %d\n", err);
		return;
	}
#endif

#if IS_ENABLED(CONFIG_CPIF_TP_MONITOR)
	tpmon_init();
#endif

	toe_dev_init(mld);

	if (ld->capability_check)
		set_ap_capabilities(mld);

#if IS_ENABLED(CONFIG_LINK_DEVICE_WITH_SBD_ARCH)
	if (ld->sbd_ipc) {
		mif_info("%s: LINK_ATTR_SBD_IPC is set\n", ld->name);

		err = init_sbd_link(&mld->sbd_link_dev);
		if (err < 0) {
			mif_err("%s: init_sbd_link fail(%d)\n", ld->name, err);
			return;
		}

		if (mld->attrs & LINK_ATTR_IPC_ALIGNED)
			ld->aligned = true;
		else
			ld->aligned = false;

		sbd_activate(&mld->sbd_link_dev);
	}
#endif

	send_ipc_irq(mld, cmd2int(CMD_PIF_INIT_DONE));

	mif_info("%s: PIF_INIT_DONE -> %s\n", ld->name, mc->name);
}

#define PHONE_START_IRQ_MARGIN	4
#define PHONE_START_ACK_MARGIN	5
static void cmd_phone_start_handler(struct mem_link_device *mld)
{
	static int phone_start_count;
	struct link_device *ld = &mld->link_dev;
	struct modem_ctl *mc = ld->mc;
	unsigned long flags;
	u64 delta_time = 0;
	int err;

	mif_info_limited("%s: PHONE_START <- %s (%s.state:%s init_end_cnt:%d)\n",
			 ld->name, mc->name, mc->name, mc_state(mc),
			 atomic_read(&mld->init_end_cnt));

	if (mld->state == LINK_STATE_OFFLINE)
		phone_start_count = 0;

	if (atomic_read(&mld->init_end_cnt)) {
		mif_err_limited("Abnormal PHONE_START from CP\n");

		if (++phone_start_count > PHONE_START_IRQ_MARGIN) {
			int ack_count = phone_start_count -
				PHONE_START_IRQ_MARGIN;

			if (ack_count > PHONE_START_ACK_MARGIN) {
				link_trigger_cp_crash(mld,
						      CRASH_REASON_CP_RSV_0,
						      "Abnormal PHONE_START from CP");
				return;
			}

			mif_err("%s: CMD(0x%x) -> %s\n", ld->name,
				cmd2int(ack_count), mc->name);
			send_ipc_irq_debug(mld, cmd2int(ack_count));

			return;
		}
	}

	spin_lock_irqsave(&mld->state_lock, flags);

	if (mld->state == LINK_STATE_IPC) {
		/*
		 * If there is no INIT_END command from AP, CP sends a CP_START
		 * command to AP periodically until it receives INIT_END from AP
		 * even though it has already been in ONLINE state.
		 */
		if (rild_ready(ld, &delta_time)) {
			mif_info("%s: INIT_END -> %s, %llums delayed\n", ld->name, mc->name, delta_time);
			atomic_inc(&mld->init_end_cnt);
			send_ipc_irq_debug(mld, cmd2int(CMD_INIT_END));
		}
		goto exit;
	}

	if (ld->capability_check) {
		int part;

		for (part = 0; part < AP_CP_CAP_PARTS; part++) {
			/* get cp_capability */
			mld->cp_capability[part] = ioread32(mld->cp_capability_offset[part]);

			if ((mld->ap_capability[part] ^ mld->cp_capability[part]) &
			    mld->ap_capability[part]) {
				/* if at least one feature is owned by AP only, crash CP */
				mif_err("ERR! capability part:%d AP:0x%08x CP:0x%08x\n",
					part, mld->ap_capability[part], mld->cp_capability[part]);
				goto capability_failed;
			}

			mif_info("capability part:%d AP:0x%08x CP:0x%08x\n",
				 part, mld->ap_capability[part], mld->cp_capability[part]);

			err = init_ap_capabilities(mld, part);
			if (err) {
				mif_err("%s: init_ap_capabilities part:%d fail(%d)\n",
					ld->name, part, err);
				goto exit;
			}
		}
	}

	err = init_legacy_link(&mld->legacy_link_dev);
	if (err) {
		mif_err("%s: init_legacy_link fail(%d)\n", ld->name, err);
		goto exit;
	}

	atomic_set(&ld->netif_stopped, 0);
	ld->tx_flowctrl_mask = 0;
	ld->dup_count_suspend = 0;
	ld->dup_count_resume = 0;

	if (rild_ready(ld, &delta_time)) {
		mif_info("%s: INIT_END -> %s, %llums delayed\n", ld->name, mc->name, delta_time);
		atomic_inc(&mld->init_end_cnt);
		send_ipc_irq_debug(mld, cmd2int(CMD_INIT_END));
	}

#if IS_ENABLED(CONFIG_MCU_IPC)
	if (mld->ap2cp_msg.type == MAILBOX_SR)
		cp_mbox_dump_sr();
#endif

	ld->crash_reason.type = CRASH_REASON_NONE;
	memset(ld->crash_reason.string, 0, CP_CRASH_INFO_SIZE);
	mif_info("Set crash_reason type:%d\n", ld->crash_reason.type);

	if ((ld->protocol == PROTOCOL_SIT) && (ld->link_type == LINKDEV_SHMEM))
		write_clk_table_to_shmem(mld);

	mld->state = LINK_STATE_IPC;
	complete_all(&mc->init_cmpl);
	modem_notify_event(MODEM_EVENT_ONLINE, mc);

exit:
#if IS_ENABLED(CONFIG_LINK_DEVICE_WITH_SBD_ARCH)
	if (ld->sbd_ipc)
		start_tx_timer(mld, &mld->sbd_print_timer);
#endif
	spin_unlock_irqrestore(&mld->state_lock, flags);
	return;

capability_failed:
	spin_unlock_irqrestore(&mld->state_lock, flags);
	link_trigger_cp_crash(mld, CRASH_REASON_MIF_FORCED, "CP lacks capability\n");
	return;
}

static void cmd_crash_reset_handler(struct mem_link_device *mld)
{
	struct link_device *ld = &mld->link_dev;
	struct modem_ctl *mc = ld->mc;
	unsigned long flags;

	spin_lock_irqsave(&mld->state_lock, flags);
	mld->state = LINK_STATE_OFFLINE;
	if (ld->crash_reason.type == CRASH_REASON_NONE)
		ld->crash_reason.type = CRASH_REASON_CP_ACT_CRASH;
	spin_unlock_irqrestore(&mld->state_lock, flags);

	mif_err("%s<-%s: ERR! CP_CRASH_RESET\n", ld->name, mc->name);

	shmem_handle_cp_crash(mld, STATE_CRASH_RESET);
}

static void cmd_crash_exit_handler(struct mem_link_device *mld)
{
	struct link_device *ld = &mld->link_dev;
	struct modem_ctl *mc = ld->mc;
	unsigned long flags;

	mif_stop_logging();
	mif_stop_ap_ppmu_logging();

	spin_lock_irqsave(&mld->state_lock, flags);
	mld->state = LINK_STATE_CP_CRASH;
	if (ld->crash_reason.type == CRASH_REASON_NONE)
		ld->crash_reason.type = CRASH_REASON_CP_ACT_CRASH;
	spin_unlock_irqrestore(&mld->state_lock, flags);

	if (timer_pending(&mld->crash_ack_timer))
		del_timer(&mld->crash_ack_timer);

	if (atomic_read(&mld->forced_cp_crash))
		mif_err("%s<-%s: CP_CRASH_ACK\n", ld->name, mc->name);
	else
		mif_err("%s<-%s: ERR! CP_CRASH_EXIT\n", ld->name, mc->name);

#if IS_ENABLED(CONFIG_LINK_DEVICE_PCIE) && IS_ENABLED(CONFIG_CP_WRESET_WA)
	if (ld->link_type == LINKDEV_PCIE) {
		if (mif_gpio_get_value(&mc->cp_gpio[CP_GPIO_CP2AP_CP_ACTIVE], true) == 0)
			mc->s5100_cp_reset_required = false;
		else
			mc->s5100_cp_reset_required = true;

		mif_info("Set s5100_cp_reset_required to %u\n", mc->s5100_cp_reset_required);
	}
#endif

	shmem_handle_cp_crash(mld, STATE_CRASH_EXIT);
}

static void shmem_cmd_handler(struct mem_link_device *mld, u16 cmd)
{
	struct link_device *ld = &mld->link_dev;

	switch (cmd) {
	case CMD_INIT_START:
		cmd_init_start_handler(mld);
		break;

	case CMD_PHONE_START:
		cmd_phone_start_handler(mld);
		break;

	case CMD_CRASH_RESET:
		cmd_crash_reset_handler(mld);
		break;

	case CMD_CRASH_EXIT:
		cmd_crash_exit_handler(mld);
		break;

	default:
		mif_err("%s: Unknown command 0x%04X\n", ld->name, cmd);
		break;
	}
}

/*============================================================================*/
static inline int check_txq_space(struct mem_link_device *mld,
				  struct legacy_ipc_device *dev,
				  unsigned int qsize, unsigned int in,
				  unsigned int out, unsigned int count)
{
	struct link_device *ld = &mld->link_dev;
	struct modem_ctl *mc = ld->mc;
	unsigned int space;

	if (!circ_valid(qsize, in, out)) {
		mif_err_limited("%s: ERR! Invalid %s_TXQ{qsize:%d in:%d out:%d}\n",
			ld->name, dev->name, qsize, in, out);
		return -EIO;
	}

	space = circ_get_space(qsize, in, out);
	if (unlikely(space < count)) {
		if (cp_online(mc)) {
			mif_err_limited("%s: NOSPC %s_TX{qsize:%d in:%d out:%d space:%d len:%d}\n",
				ld->name, dev->name, qsize,
				in, out, space, count);
		}
		return -ENOSPC;
	}

	return space;
}

static int txq_write(struct mem_link_device *mld, struct legacy_ipc_device *dev,
		     struct sk_buff *skb)
{
	char *src = skb->data;
	unsigned int count = skb->len;
	char *dst = get_txq_buff(dev);
	unsigned int qsize = get_txq_buff_size(dev);
	unsigned int in = get_txq_head(dev);
	unsigned int out = get_txq_tail(dev);
	int space;

	space = check_txq_space(mld, dev, qsize, in, out, count);
	if (unlikely(space < 0))
		return space;

	barrier();

	circ_write(dst, src, qsize, in, count);

	barrier();

	set_txq_head(dev, circ_new_ptr(qsize, in, count));

	/* Commit the item before incrementing the head */
	smp_mb();

	return count;
}

static int tx_frames_to_dev(struct mem_link_device *mld,
			    struct legacy_ipc_device *dev)
{
	struct sk_buff_head *skb_txq = dev->skb_txq;
	int tx_bytes = 0;
	int ret = 0;

	while (1) {
		struct sk_buff *skb;

		skb = skb_dequeue(skb_txq);
		if (unlikely(!skb))
			break;

		ret = txq_write(mld, dev, skb);
		if (unlikely(ret < 0)) {
			/* Take the skb back to the skb_txq */
			skb_queue_head(skb_txq, skb);
			break;
		}

		tx_bytes += ret;

#ifdef DEBUG_MODEM_IF_LINK_TX
		mif_pkt("LNK-TX", skb);
#endif

		dev_consume_skb_any(skb);
	}

	return (ret < 0) ? ret : tx_bytes;
}

static enum hrtimer_restart tx_timer_func(struct hrtimer *timer)
{
	struct mem_link_device *mld;
	struct link_device *ld;
	struct modem_ctl *mc;
	int i;
	bool need_schedule;
	u16 mask;
	unsigned long flags;

	mld = container_of(timer, struct mem_link_device, tx_timer);
	ld = &mld->link_dev;
	mc = ld->mc;

	need_schedule = false;
	mask = 0;

	spin_lock_irqsave(&mc->lock, flags);
	if (unlikely(!ipc_active(mld)))
		goto exit;

	for (i = 0; i < IPC_MAP_MAX; i++) {
		struct legacy_ipc_device *dev = mld->legacy_link_dev.dev[i];
		int ret;

		ret = txq_check_busy(mld, dev);
		if (ret) {
			need_schedule = true;
			continue;
		}

		ret = tx_frames_to_dev(mld, dev);
		if (unlikely(ret < 0)) {
			if (ret == -EBUSY || ret == -ENOSPC) {
				need_schedule = true;
				txq_stop(mld, dev);
				/* If txq has 2 or more packet and 2nd packet
				 * has -ENOSPC return, It request irq to consume
				 * the TX ring-buffer from CP
				 */
				mask |= msg_mask(dev);
				continue;
			} else {
				link_trigger_cp_crash(mld, CRASH_REASON_MIF_TX_ERR,
					"tx_frames_to_dev error");
				need_schedule = false;
				goto exit;
			}
		}

		if (ret > 0)
			mask |= msg_mask(dev);

		if (!skb_queue_empty(dev->skb_txq))
			need_schedule = true;
	}

	if (mask)
		send_ipc_irq(mld, mask2int(mask));

exit:
	if (need_schedule) {
		ktime_t ktime = ktime_set(0, mld->tx_period_ms * NSEC_PER_MSEC);

		hrtimer_start(timer, ktime, HRTIMER_MODE_REL);
	}
	spin_unlock_irqrestore(&mc->lock, flags);

	return HRTIMER_NORESTART;
}

static int tx_func(struct mem_link_device *mld, struct hrtimer *timer,
					  struct legacy_ipc_device *dev, struct sk_buff *skb)
{
	struct link_device *ld = &mld->link_dev;
	struct modem_ctl *mc = ld->mc;
	struct sk_buff_head *skb_txq = dev->skb_txq;
	bool need_schedule = false;
	u16 mask = msg_mask(dev);
	unsigned long flags;
	int ret = 0;

	spin_lock_irqsave(&mc->lock, flags);
	if (unlikely(!ipc_active(mld))) {
		spin_unlock_irqrestore(&mc->lock, flags);
		dev_kfree_skb_any(skb);
		goto exit;
	}
	spin_unlock_irqrestore(&mc->lock, flags);

	ret = txq_write(mld, dev, skb);
	if (unlikely(ret < 0)) {
		if (ret == -EBUSY || ret == -ENOSPC) {
			skb_queue_head(skb_txq, skb);
			need_schedule = true;
			txq_stop(mld, dev);
			/* If txq has 2 or more packet and 2nd packet
			 * has -ENOSPC return, It request irq to consume
			 * the TX ring-buffer from CP
			 */
			send_ipc_irq(mld, mask2int(mask));
		} else {
			link_trigger_cp_crash(mld, CRASH_REASON_MIF_TX_ERR,
					"tx_frames_to_dev error");
			need_schedule = false;
		}
		goto exit;
	}

#ifdef DEBUG_MODEM_IF_LINK_TX
	mif_pkt("LNK-TX", skb);
#endif

	dev_consume_skb_any(skb);

	send_ipc_irq(mld, mask2int(mask));

exit:
	if (need_schedule) {
		ktime_t ktime = ktime_set(0, mld->tx_period_ms * NSEC_PER_MSEC);

		hrtimer_start(timer, ktime, HRTIMER_MODE_REL);

		return -1;
	} else
		return 1;
}

static inline void start_tx_timer(struct mem_link_device *mld,
				  struct hrtimer *timer)
{
	struct link_device *ld = &mld->link_dev;
	struct modem_ctl *mc = ld->mc;
	unsigned long flags;

	spin_lock_irqsave(&mc->lock, flags);
	if (unlikely(cp_offline(mc))) {
		spin_unlock_irqrestore(&mc->lock, flags);
		return;
	}
	spin_unlock_irqrestore(&mc->lock, flags);

	spin_lock_irqsave(&mc->tx_timer_lock, flags);
	if (!hrtimer_is_queued(timer)) {
		ktime_t ktime = ktime_set(0, mld->tx_period_ms * NSEC_PER_MSEC);

		hrtimer_start(timer, ktime, HRTIMER_MODE_REL);
	}
	spin_unlock_irqrestore(&mc->tx_timer_lock, flags);
}

static inline void shmem_start_timers(struct mem_link_device *mld)
{
#if IS_ENABLED(CONFIG_CP_PKTPROC_UL)
	start_tx_timer(mld, &mld->pktproc_tx_timer);
#endif

#if IS_ENABLED(CONFIG_LINK_DEVICE_WITH_SBD_ARCH)
	if (sbd_active(&mld->sbd_link_dev))
		start_tx_timer(mld, &mld->sbd_tx_timer);
#endif

	start_tx_timer(mld, &mld->tx_timer);
}

static inline void cancel_tx_timer(struct mem_link_device *mld,
				   struct hrtimer *timer)
{
	struct link_device *ld = &mld->link_dev;
	struct modem_ctl *mc = ld->mc;
	unsigned long flags;

	spin_lock_irqsave(&mc->tx_timer_lock, flags);
	if (hrtimer_active(timer))
		hrtimer_cancel(timer);
	spin_unlock_irqrestore(&mc->tx_timer_lock, flags);
}

static inline void shmem_stop_timers(struct mem_link_device *mld)
{
#if IS_ENABLED(CONFIG_CP_PKTPROC_UL)
	cancel_tx_timer(mld, &mld->pktproc_tx_timer);
#endif

#if IS_ENABLED(CONFIG_LINK_DEVICE_WITH_SBD_ARCH)
	if (sbd_active(&mld->sbd_link_dev))
		cancel_tx_timer(mld, &mld->sbd_tx_timer);
#endif

	cancel_tx_timer(mld, &mld->tx_timer);
}

#if IS_ENABLED(CONFIG_LINK_DEVICE_WITH_SBD_ARCH)
static int tx_frames_to_rb(struct sbd_ring_buffer *rb)
{
	struct sk_buff_head *skb_txq = &rb->skb_q;
	int tx_bytes = 0;
	int ret = 0;

	while (1) {
		struct sk_buff *skb;

		skb = skb_dequeue(skb_txq);
		if (unlikely(!skb))
			break;

		ret = sbd_pio_tx(rb, skb);
		if (unlikely(ret < 0)) {
			/* Take the skb back to the skb_txq */
			skb_queue_head(skb_txq, skb);
			break;
		}

		tx_bytes += ret;
#ifdef DEBUG_MODEM_IF_LINK_TX
		mif_pkt("LNK-TX", skb);
#endif
		dev_consume_skb_any(skb);
	}

	return (ret < 0) ? ret : tx_bytes;
}

static enum hrtimer_restart sbd_tx_timer_func(struct hrtimer *timer)
{
	struct mem_link_device *mld =
		container_of(timer, struct mem_link_device, sbd_tx_timer);
	struct link_device *ld = &mld->link_dev;
	struct modem_ctl *mc = ld->mc;
	struct sbd_link_device *sl = &mld->sbd_link_dev;
	int i;
	bool need_schedule = false;
	u16 mask = 0;
	unsigned long flags = 0;

	spin_lock_irqsave(&mc->lock, flags);
	if (unlikely(!ipc_active(mld))) {
		spin_unlock_irqrestore(&mc->lock, flags);
		goto exit;
	}
	spin_unlock_irqrestore(&mc->lock, flags);

	for (i = 0; i < sl->num_channels; i++) {
		struct sbd_ring_buffer *rb = sbd_id2rb(sl, i, TX);
		int ret;

		ret = sbd_txq_check_busy(rb);
		if (ret) {
			need_schedule = true;
			continue;
		}

		ret = tx_frames_to_rb(rb);
		if (unlikely(ret < 0)) {
			if (ret == -EBUSY || ret == -ENOSPC) {
				need_schedule = true;
				sbd_txq_stop(rb);
				mask = MASK_SEND_DATA;
				continue;
			} else {
				link_trigger_cp_crash(mld, CRASH_REASON_MIF_TX_ERR,
					"tx_frames_to_rb error");
				need_schedule = false;
				goto exit;
			}
		}

		if (ret > 0)
			mask = MASK_SEND_DATA;

		if (!skb_queue_empty(&rb->skb_q))
			need_schedule = true;
	}

	if (mask) {
		spin_lock_irqsave(&mc->lock, flags);
		if (unlikely(!ipc_active(mld))) {
			spin_unlock_irqrestore(&mc->lock, flags);
			need_schedule = false;
			goto exit;
		}
		send_ipc_irq(mld, mask2int(mask));
		spin_unlock_irqrestore(&mc->lock, flags);
	}

exit:
	if (need_schedule) {
		ktime_t ktime = ktime_set(0, mld->tx_period_ms * NSEC_PER_MSEC);

		hrtimer_start(timer, ktime, HRTIMER_MODE_REL);
	}

	return HRTIMER_NORESTART;
}

static int sbd_tx_func(struct mem_link_device *mld, struct hrtimer *timer,
		    struct sbd_ring_buffer *rb, struct sk_buff *skb)
{
	struct link_device *ld = &mld->link_dev;
	struct modem_ctl *mc = ld->mc;
	bool need_schedule = false;
	u16 mask = MASK_SEND_DATA;
	unsigned long flags = 0;
	int ret = 0;

	spin_lock_irqsave(&mc->lock, flags);
	if (unlikely(!ipc_active(mld))) {
		spin_unlock_irqrestore(&mc->lock, flags);
		dev_kfree_skb_any(skb);
		goto exit;
	}
	spin_unlock_irqrestore(&mc->lock, flags);

	ret = sbd_pio_tx(rb, skb);
	if (unlikely(ret < 0)) {
		if (ret == -EBUSY || ret == -ENOSPC) {
			skb_queue_head(&rb->skb_q, skb);
			need_schedule = true;
			send_ipc_irq(mld, mask2int(mask));
		} else {
			link_trigger_cp_crash(mld, CRASH_REASON_MIF_TX_ERR,
					"tx_frames_to_rb error");
			need_schedule = false;
		}
		goto exit;
	}

#ifdef DEBUG_MODEM_IF_LINK_TX
	mif_pkt("LNK-TX", skb);
#endif
	dev_consume_skb_any(skb);

	spin_lock_irqsave(&mc->lock, flags);
	if (unlikely(!ipc_active(mld))) {
		spin_unlock_irqrestore(&mc->lock, flags);
		need_schedule = false;
		goto exit;
	}
	send_ipc_irq(mld, mask2int(mask));
	spin_unlock_irqrestore(&mc->lock, flags);

exit:
	if (need_schedule) {
		ktime_t ktime = ktime_set(0, mld->tx_period_ms * NSEC_PER_MSEC);

		hrtimer_start(timer, ktime, HRTIMER_MODE_REL);
		return -1;
	} else
		return 1;
}
#endif /* CONFIG_LINK_DEVICE_WITH_SBD_ARCH */

#if IS_ENABLED(CONFIG_CP_PKTPROC_UL)
static enum hrtimer_restart pktproc_tx_timer_func(struct hrtimer *timer)
{
	struct mem_link_device *mld = container_of(timer, struct mem_link_device, pktproc_tx_timer);
	struct pktproc_adaptor_ul *ppa_ul = &mld->pktproc_ul;
	struct modem_ctl *mc = mld->link_dev.mc;
	struct link_device *ld = &mld->link_dev;
	bool need_schedule = false;
	bool need_irq = false;
	bool need_dit = false;
	unsigned long flags;
	unsigned int count;
	int ret, i;

	if (ld->tx_flowctrl_mask) {
		mif_err_limited("flowctrl=0x%04lx\n", ld->tx_flowctrl_mask);
		cpif_wake_lock_timeout(mc->iod->ws, msecs_to_jiffies(5));
	}

	for (i = 0; i < ppa_ul->num_queue; i++) {
		struct pktproc_queue_ul *q = ppa_ul->q[i];

		ret = pktproc_ul_q_check_busy(q);
		if (ret) {
			need_schedule = true;
			continue;
		}

		do {
			if (dit_check_dir_use_queue(DIT_DIR_TX, q->q_idx)) {
				if (circ_empty(q->done_ptr, q->q_info->fore_ptr))
					break;

				need_dit = true;
			} else {
				count = circ_get_usage(q->q_info->num_desc,
					q->done_ptr, q->q_info->fore_ptr);
				if (count == 0)
					break;

				q->update_fore_ptr(q, count);
				need_irq = true;
			}
			need_schedule = true;
		} while (0);
	}

	/* irq will be raised after dit_kick() */
	if (need_dit) {
		dit_kick(DIT_DIR_TX, false);
	} else if (need_irq) {
		spin_lock_irqsave(&mc->lock, flags);
		if (ipc_active(mld))
			send_ipc_irq(mld, mask2int(MASK_SEND_DATA));
		spin_unlock_irqrestore(&mc->lock, flags);
	}

	if (need_schedule) {
		ktime_t ktime = ktime_set(0, mld->tx_period_ms * NSEC_PER_MSEC);

		hrtimer_start(timer, ktime, HRTIMER_MODE_REL);
	}

	return HRTIMER_NORESTART;
}

static int xmit_ipc_to_pktproc(struct mem_link_device *mld, struct sk_buff *skb)
{
	struct pktproc_adaptor_ul *ppa_ul = &mld->pktproc_ul;
	struct pktproc_queue_ul *q;
	int len;
	int ret = -EBUSY;
	unsigned long flags;

	if (ppa_ul->num_queue == 1)
		q = ppa_ul->q[PKTPROC_UL_QUEUE_0];
	else if (skb->queue_mapping == 1)
		q = ppa_ul->q[PKTPROC_UL_HIPRIO];
	else
		q = ppa_ul->q[PKTPROC_UL_NORM];

	if (ppa_ul->padding_required)
		len = skb->len + CP_PADDING;
	else
		len = skb->len;

	if (len > q->max_packet_size) {
		mif_err_limited("ERR! PKTPROC UL QUEUE[%d] skb len:%d too large (max:%u)\n",
				q->q_idx, len, q->max_packet_size);
		return -EINVAL;
	}

	if (spin_trylock_irqsave(&q->lock, flags)) {
		ret = q->send_packet(q, skb);
		spin_unlock_irqrestore(&q->lock, flags);
	}

	if (unlikely(ret < 0)) {
		if ((ret != -EBUSY) && (ret != -ENOSPC)) {
			link_trigger_cp_crash(mld, CRASH_REASON_MIF_TX_ERR,
				"tx_frames_to_pktproc error");
			return ret;
		}

		send_ipc_irq(mld, mask2int(MASK_SEND_DATA));
		pktproc_ul_q_stop(q);
		goto exit;
	} else if (!hrtimer_active(&mld->pktproc_tx_timer)) {
		q->update_fore_ptr(q, 1);
		send_ipc_irq(mld, mask2int(MASK_SEND_DATA));
	}

	if (!dit_check_dir_use_queue(DIT_DIR_TX, q->q_idx))
		dev_consume_skb_any(skb);

exit:
	/* start timer even on error */
	if (ret)
		start_tx_timer(mld, &mld->pktproc_tx_timer);

	return ret;
}
#endif /* CONFIG_CP_PKTPROC_UL */

#if IS_ENABLED(CONFIG_LINK_DEVICE_WITH_SBD_ARCH)
static int xmit_ipc_to_rb(struct mem_link_device *mld, u8 ch,
			  struct sk_buff *skb)
{
	int ret, ret2;
	struct link_device *ld = &mld->link_dev;
	struct io_device *iod = skbpriv(skb)->iod;
	struct modem_ctl *mc = ld->mc;
	struct sbd_ring_buffer *rb = sbd_ch2rb_with_skb(&mld->sbd_link_dev, ch, TX, skb);
	struct sk_buff_head *skb_txq;
	unsigned long flags = 0;
	int quota = MIF_TX_QUOTA;

	if (!rb) {
		mif_err("%s: %s->%s: ERR! NO SBD RB {ch:%d}\n",
			ld->name, iod->name, mc->name, ch);
		return -ENODEV;
	}

	skb_txq = &rb->skb_q;

	if (unlikely(skb_txq->qlen >= MAX_SKB_TXQ_DEPTH)) {
		mif_err_limited("%s: %s->%s: ERR! {ch:%d} skb_txq.len %d >= limit %d\n",
				ld->name, iod->name, mc->name, ch,
				skb_txq->qlen, MAX_SKB_TXQ_DEPTH);
		ret = -EBUSY;
	} else {
		skb->len = min_t(int, skb->len, rb->buff_size);
		ret = skb->len;

		skb_queue_tail(skb_txq, skb);

		if (hrtimer_active(&mld->sbd_tx_timer)) {
			start_tx_timer(mld, &mld->sbd_tx_timer);
		} else if (spin_trylock_irqsave(&rb->lock, flags)) {
			do {
				skb = skb_dequeue(skb_txq);
				if (!skb)
					break;

				ret2 = sbd_tx_func(mld, &mld->sbd_tx_timer, rb, skb);
				if (ret2 < 0)
					break;
			} while (--quota);

			spin_unlock_irqrestore(&rb->lock, flags);
		}
	}

	return ret;
}
#endif

bool check_mem_link_tx_pending(struct mem_link_device *mld)
{
#if IS_ENABLED(CONFIG_LINK_DEVICE_WITH_SBD_ARCH)
	struct sbd_link_device *sl = &mld->sbd_link_dev;

	if (sbd_active(sl))
		return check_sbd_tx_pending(mld);
#endif

	return check_legacy_tx_pending(mld);
}

static int xmit_ipc_to_dev(struct mem_link_device *mld, u8 ch, struct sk_buff *skb,
		enum legacy_ipc_map legacy_buffer_index)
{
	int ret, ret2;
	struct link_device *ld = &mld->link_dev;
	struct io_device *iod = skbpriv(skb)->iod;
	struct modem_ctl *mc = ld->mc;
	struct legacy_ipc_device *dev = mld->legacy_link_dev.dev[legacy_buffer_index];
	struct sk_buff_head *skb_txq;
	unsigned long flags = 0;
	int quota = MIF_TX_QUOTA;

	if (!dev) {
		mif_err("%s: %s->%s: ERR! NO IPC DEV {ch:%d}\n",
			ld->name, iod->name, mc->name, ch);
		return -ENODEV;
	}

	skb_txq = dev->skb_txq;

	if (unlikely(skb_txq->qlen >= MAX_SKB_TXQ_DEPTH)) {
		mif_err_limited("%s: %s->%s: ERR! %s TXQ.qlen %d >= limit %d\n",
				ld->name, iod->name, mc->name, dev->name,
				skb_txq->qlen, MAX_SKB_TXQ_DEPTH);
		ret = -EBUSY;
	} else {
		ret = skb->len;

		skb_queue_tail(skb_txq, skb);

		if (hrtimer_active(&mld->tx_timer)) {
			start_tx_timer(mld, &mld->tx_timer);
		} else if (spin_trylock_irqsave(&dev->tx_lock, flags)) {
			do {
				skb = skb_dequeue(skb_txq);
				if (!skb)
					break;

				ret2 = tx_func(mld, &mld->tx_timer, dev, skb);
				if (ret2 < 0)
					break;
			} while (--quota);

			spin_unlock_irqrestore(&dev->tx_lock, flags);
		}
	}

	return ret;
}

static int xmit_to_cp(struct mem_link_device *mld, struct io_device *iod, struct sk_buff *skb)
{
#if IS_ENABLED(CONFIG_LINK_DEVICE_WITH_SBD_ARCH)
	struct link_device *ld = &mld->link_dev;
#endif
	u8 ch = iod->ch;

	/* for boot/dump
	 * 1) assume that link (ex. PCI) is ready
	 * 2) do not need send_ipc_irq()
	 */
	if (is_boot_iod(iod) || is_dump_iod(iod))
		return xmit_to_legacy_link(mld, skb, IPC_MAP_NORM_RAW);

	if (unlikely(!ipc_active(mld)))
		return -EIO;

#if IS_ENABLED(CONFIG_CP_PKTPROC_UL)
	if (is_ps_iod(iod))
		return xmit_ipc_to_pktproc(mld, skb);
#endif

#if IS_ENABLED(CONFIG_LINK_DEVICE_WITH_SBD_ARCH)
	if (ld->sbd_ipc && iod->sbd_ipc) {
		if (likely(sbd_active(&mld->sbd_link_dev)))
			return xmit_ipc_to_rb(mld, ch, skb);
		else
			return -ENODEV;
	}
#endif
	if (is_fmt_iod(iod))
		return xmit_ipc_to_dev(mld, ch, skb, IPC_MAP_FMT);
#if IS_ENABLED(CONFIG_MODEM_IF_LEGACY_QOS)
	if (skb->queue_mapping == 1)
		return xmit_ipc_to_dev(mld, ch, skb, IPC_MAP_HPRIO_RAW);
#endif
	return xmit_ipc_to_dev(mld, ch, skb, IPC_MAP_NORM_RAW);
}

/*============================================================================*/
static int pass_skb_to_demux(struct mem_link_device *mld, struct sk_buff *skb)
{
	struct link_device *ld = &mld->link_dev;
	struct io_device *iod = skbpriv(skb)->iod;
	int ret = 0;

	if (unlikely(!iod)) {
		mif_err("%s: ERR! No IOD for CH.%d\n", ld->name, skbpriv(skb)->sipc_ch);
		dev_kfree_skb_any(skb);
		link_trigger_cp_crash(mld, CRASH_REASON_MIF_RIL_BAD_CH,
			"ERR! No IOD for CH.XX");
		return -EACCES;
	}

#ifdef DEBUG_MODEM_IF_LINK_RX
	mif_pkt("LNK-RX", skb);
#endif

	ret = iod->recv_skb_single(iod, ld, skb);
	if (unlikely(ret < 0)) {
		struct modem_ctl *mc = ld->mc;

		mif_err_limited("%s: %s<-%s: ERR! %s->recv_skb fail (%d)\n",
				ld->name, iod->name, mc->name, iod->name, ret);
		dev_kfree_skb_any(skb);
	}

	return ret;
}

static int pass_skb_to_net(struct mem_link_device *mld, struct sk_buff *skb)
{
	struct link_device *ld = &mld->link_dev;
	struct io_device *iod = skbpriv(skb)->iod;
	struct modem_ctl *mc = ld->mc;
	int ret = 0;

	if (unlikely(!cp_online(mc))) {
		mif_err_limited("ERR! CP not online!, skb:%pK\n", skb);
		dev_kfree_skb_any(skb);
		return -EACCES;
	}

	if (unlikely(!iod)) {
		mif_err("%s: ERR! No IOD in skb@%pK\n", ld->name, skb);
		dev_kfree_skb_any(skb);
		link_trigger_cp_crash(mld, CRASH_REASON_MIF_RX_BAD_DATA,
			"ERR! No IOD");
		return -EIO;
	}

#ifdef DEBUG_MODEM_IF_LINK_RX
	mif_pkt("LNK-RX", skb);
#endif

	ret = iod->recv_net_skb(iod, ld, skb);
	if (unlikely(ret < 0)) {
		struct modem_ctl *mc = ld->mc;

		mif_err_limited("%s: %s<-%s: ERR! %s->recv_net_skb fail (%d)\n",
				ld->name, iod->name, mc->name, iod->name, ret);
		dev_kfree_skb_any(skb);
	}

	return ret;
}

#if IS_ENABLED(CONFIG_LINK_DEVICE_WITH_SBD_ARCH)
static int rx_net_frames_from_rb(struct sbd_ring_buffer *rb, int budget,
		int *work_done)
{
	int rcvd = 0;
	struct link_device *ld = rb->ld;
	struct mem_link_device *mld = ld_to_mem_link_device(ld);
	unsigned int num_frames;
	int ret = 0;

	num_frames = min_t(unsigned int, rb_usage(rb), budget);

	while (rcvd < num_frames) {
		struct sk_buff *skb = NULL;

		ret = sbd_pio_rx(rb, &skb);
		if (unlikely(ret))
			return ret;

		/* The $rcvd must be accumulated here, because $skb can be freed
		 * in pass_skb_to_net().
		 */
		rcvd++;

		ret = pass_skb_to_net(mld, skb);
		if (ret < 0)
			break;
	}

	if (ret != -EBUSY && rcvd < num_frames) {
		struct io_device *iod = rb->iod;
		struct link_device *ld = rb->ld;
		struct modem_ctl *mc = ld->mc;

		mif_err("%s: %s<-%s: WARN! rcvd %d < num_frames %d\n",
			ld->name, iod->name, mc->name, rcvd, num_frames);
	}

	*work_done = rcvd;

	return ret;
}

static int rx_ipc_frames_from_rb(struct sbd_ring_buffer *rb)
{
	int rcvd = 0;
	struct link_device *ld = rb->ld;
	struct mem_link_device *mld = ld_to_mem_link_device(ld);
	unsigned int qlen = rb->len;
	unsigned int in = *rb->wp;
	unsigned int out = *rb->rp;
	unsigned int num_frames = circ_get_usage(qlen, in, out);
	int ret = 0;

	while (rcvd < num_frames) {
		struct sk_buff *skb = NULL;

		ret = sbd_pio_rx(rb, &skb);
		if (unlikely(ret))
			return ret;

		/* The $rcvd must be accumulated here, because $skb can be freed
		 * in pass_skb_to_demux().
		 */
		rcvd++;

		if (skbpriv(skb)->lnk_hdr) {
			u8 ch = rb->ch;
			u8 fch = ld->get_ch(skb->data);

			if (fch != ch) {
				mif_err("frm.ch:%d != rb.ch:%d\n", fch, ch);
				pr_skb("CRASH", skb, ld);
				dev_kfree_skb_any(skb);
				link_trigger_cp_crash(mld, CRASH_REASON_MIF_RX_BAD_DATA,
					"frm.ch is not same with rb.ch");
				continue;
			}
		}

		pass_skb_to_demux(mld, skb);
	}

	if (rcvd < num_frames) {
		struct io_device *iod = rb->iod;
		struct modem_ctl *mc = ld->mc;

		mif_err("%s: %s<-%s: WARN! rcvd %d < num_frames %d\n",
			ld->name, iod->name, mc->name, rcvd, num_frames);
	}
	return rcvd;
}

static int sbd_ipc_rx_func_napi(struct link_device *ld, struct io_device *iod,
		int budget, int *work_done)
{
	struct mem_link_device *mld = to_mem_link_device(ld);
	struct sbd_ring_buffer *rb = sbd_ch2rb(&mld->sbd_link_dev, iod->ch, RX);
	int rcvd = 0;
	int ret;

	ret = rx_net_frames_from_rb(rb, budget, &rcvd);

	if (IS_ERR_VALUE((unsigned long)ret) && (ret != -EBUSY))
		mif_err_limited("RX error (%d)\n", ret);

	*work_done = rcvd;
	return ret;
}
#endif /* CONFIG_LINK_DEVICE_WITH_SBD_ARCH */

static int legacy_ipc_rx_func_napi(struct mem_link_device *mld, struct legacy_ipc_device *dev,
		int budget, int *work_done)
{
	struct link_device *ld = &mld->link_dev;
	struct modem_data *modem = ld->mdm_data;
	unsigned int qsize = get_rxq_buff_size(dev);
	unsigned int in = get_rxq_head(dev);
	unsigned int out = get_rxq_tail(dev);
	unsigned int size = circ_get_usage(qsize, in, out);
	int rcvd = 0;
	int err = 0;

	if (unlikely(circ_empty(in, out)))
		return 0;

	if (modem->legacy_raw_rx_buffer_cached && dev->id == IPC_MAP_NORM_RAW) {
		char *src = get_rxq_buff(dev);

		if (!src) {
			mif_err_limited("get_rxq_buff() error\n");
			return -EINVAL;
		}

		if ((out + size) <= qsize)
			dma_sync_single_for_cpu(ld->dev, virt_to_phys(src + out), size,
					DMA_FROM_DEVICE);
		else {
			dma_sync_single_for_cpu(ld->dev, virt_to_phys(src + out), qsize - out,
					DMA_FROM_DEVICE);
			dma_sync_single_for_cpu(ld->dev, virt_to_phys(src), size - (qsize - out),
					DMA_FROM_DEVICE);
		}
	}

	while ((budget != 0) && (rcvd < size)) {
		struct sk_buff *skb;
		u8 ch;
		struct io_device *iod;

		skb = recv_from_legacy_link(mld, dev, in, &err);
		if (err)
			return err;

		ch = ld->get_ch(skb->data);
		iod = link_get_iod_with_channel(ld, ch);
		if (!iod) {
			mif_err("%s: ERR! [%s]No IOD for CH.%d(out:%u)\n",
				ld->name, dev->name, ch, get_rxq_tail(dev));
			pr_skb("CRASH", skb, ld);
			dev_kfree_skb_any(skb);
			link_trigger_cp_crash(mld, CRASH_REASON_MIF_RX_BAD_DATA,
				"ERR! No IOD from CP");
			break;
		}

		/* Record the IO device and the link device into the &skb->cb */
		skbpriv(skb)->iod = iod;
		skbpriv(skb)->ld = ld;

		skbpriv(skb)->lnk_hdr = iod->link_header;
		skbpriv(skb)->sipc_ch = ch;
		skbpriv(skb)->napi = &mld->mld_napi;
		/* The $rcvd must be accumulated here, because $skb can be freed
		 * in pass_skb_to_demux().
		 */
		rcvd += skb->len;

		if (is_ps_iod(iod)) {
			budget--;
			*work_done += 1;
		}

		pass_skb_to_demux(mld, skb);
	}

	if ((budget != 0) && (rcvd < size)) {
		struct link_device *ld = &mld->link_dev;

		mif_err("%s: WARN! rcvd %d < size %d\n", ld->name, rcvd, size);
	}

	return 0;
}

static int legacy_ipc_rx_func(struct mem_link_device *mld, struct legacy_ipc_device *dev)
{
	struct link_device *ld = &mld->link_dev;
	struct modem_data *modem = ld->mdm_data;
	unsigned int qsize = get_rxq_buff_size(dev);
	unsigned int in = get_rxq_head(dev);
	unsigned int out = get_rxq_tail(dev);
	unsigned int size = circ_get_usage(qsize, in, out);
	int rcvd = 0;
	int err = 0;

	if (unlikely(circ_empty(in, out)))
		return 0;

	if (modem->legacy_raw_rx_buffer_cached && dev->id == IPC_MAP_NORM_RAW) {
		char *src = get_rxq_buff(dev);

		if (!src) {
			mif_err_limited("get_rxq_buff() error\n");
			return -EINVAL;
		}

		if ((out + size) <= qsize)
			dma_sync_single_for_cpu(ld->dev, virt_to_phys(src + out), size,
					DMA_FROM_DEVICE);
		else {
			dma_sync_single_for_cpu(ld->dev, virt_to_phys(src + out), qsize - out,
					DMA_FROM_DEVICE);
			dma_sync_single_for_cpu(ld->dev, virt_to_phys(src), size - (qsize - out),
					DMA_FROM_DEVICE);
		}
	}

	while (rcvd < size) {
		struct sk_buff *skb;
		u8 ch;
		struct io_device *iod;

		skb = recv_from_legacy_link(mld, dev, in, &err);
		if (err)
			return err;

		ch = ld->get_ch(skb->data);
		iod = link_get_iod_with_channel(ld, ch);
		if (!iod) {
			mif_err("%s: ERR! [%s]No IOD for CH.%d(out:%u)\n",
				ld->name, dev->name, ch, get_rxq_tail(dev));
			pr_skb("CRASH", skb, ld);
			dev_kfree_skb_any(skb);
			link_trigger_cp_crash(mld, CRASH_REASON_MIF_RX_BAD_DATA,
				"ERR! No IOD from CP in rx_frames_from_dev()");
			break;
		}

		/* Record the IO device and the link device into the &skb->cb */
		skbpriv(skb)->iod = iod;
		skbpriv(skb)->ld = ld;

		skbpriv(skb)->lnk_hdr = iod->link_header;
		skbpriv(skb)->sipc_ch = ch;

		skbpriv(skb)->napi = NULL;

		/* The $rcvd must be accumulated here, because $skb can be freed
		 * in pass_skb_to_demux().
		 */
		rcvd += skb->len;
		pass_skb_to_demux(mld, skb);
	}

	if (rcvd < size) {
		struct link_device *ld = &mld->link_dev;

		mif_err("%s: WARN! rcvd %d < size %d\n", ld->name, rcvd, size);
	}

	return rcvd;
}

static int bootdump_rx_func(struct mem_link_device *mld)
{
	int ret = 0;
	struct legacy_ipc_device *dev = mld->legacy_link_dev.dev[IPC_MAP_NORM_RAW];

	u32 qlen = mld->msb_rxq.qlen;

	while (qlen-- > 0) {
		struct mst_buff *msb;
		u16 intr;

		msb = msb_dequeue(&mld->msb_rxq);
		if (!msb)
			break;
		intr = msb->snapshot.int2ap;
		if (cmd_valid(intr))
			mld->cmd_handler(mld, int2cmd(intr));
		msb_free(msb);
	}

	/* recv frames from RAW buffer which should contain bootdump frames */
	ret = legacy_ipc_rx_func(mld, dev);
	if (ret == -ENOMEM) {
		if (!work_pending(&mld->page_reclaim_work)) {
			struct link_device *ld = &mld->link_dev;

			mif_err_limited("Rx ENOMEM, try reclaim work\n");
			queue_work(ld->rx_wq,
					&mld->page_reclaim_work);
		}
	}

	return ret;
}

static void bootdump_oom_handler_work(struct work_struct *ws)
{
	struct mem_link_device *mld =
		container_of(ws, struct mem_link_device, page_reclaim_work);
	struct sk_buff *skb;

	/* try to page reclaim with GFP_KERNEL */
	skb = alloc_skb(PAGE_SIZE - 512, GFP_KERNEL);
	if (skb)
		dev_kfree_skb_any(skb);

	/* need to disable the RX irq ?? */
	msleep(200);

	mif_info("trigger the rx task again\n");
	bootdump_rx_func(mld);
}

static void bootdump_rx_work(struct work_struct *ws)
{
	struct mem_link_device *mld;

	mld = container_of(ws, struct mem_link_device, bootdump_rx_dwork.work);

	bootdump_rx_func(mld);
}

/*============================================================================*/
static int shmem_init_comm(struct link_device *ld, struct io_device *iod)
{
	struct mem_link_device *mld = to_mem_link_device(ld);
	struct modem_ctl *mc = ld->mc;
	u64 delta_time = 0;

	if (atomic_read(&mld->init_end_cnt))
		return 0;

	if (ld->protocol == PROTOCOL_SIT)
		return 0;

	if (!is_fmt_iod(iod) && !is_rfs_iod(iod))
		return 0;

	if (rild_ready(ld, &delta_time)) {
		if (ld->link_type == LINKDEV_SHMEM)
			write_clk_table_to_shmem(mld);
		if (cp_online(mc) && !atomic_read(&mld->init_end_cnt)) {
			mif_err("%s: %s -> INIT_END -> %s, %llums delayed\n",
					ld->name, iod->name, mc->name, delta_time);
			atomic_inc(&mld->init_end_cnt);
			send_ipc_irq(mld, cmd2int(CMD_INIT_END));
		}
	}

	return 0;
}

static int shmem_send(struct link_device *ld, struct io_device *iod,
		    struct sk_buff *skb)
{
	struct mem_link_device *mld = to_mem_link_device(ld);

	return xmit_to_cp(mld, iod, skb);
}

static void link_prepare_normal_boot(struct link_device *ld, struct io_device *iod)
{
	struct mem_link_device *mld = to_mem_link_device(ld);
	unsigned long flags;

	atomic_set(&mld->init_end_cnt, 0);
	atomic_set(&mld->init_end_busy, 0);
	mld->last_init_end_cnt = 0;

	iod->opened_time = ktime_set(0, 0);

	spin_lock_irqsave(&mld->state_lock, flags);
	mld->state = LINK_STATE_OFFLINE;
	spin_unlock_irqrestore(&mld->state_lock, flags);

	cancel_tx_timer(mld, &mld->tx_timer);

#if IS_ENABLED(CONFIG_LINK_DEVICE_WITH_SBD_ARCH)
	if (ld->sbd_ipc)
		cancel_tx_timer(mld, &mld->sbd_tx_timer);
#endif

#if IS_ENABLED(CONFIG_CP_PKTPROC_UL)
	cancel_tx_timer(mld, &mld->pktproc_tx_timer);
#endif

	purge_txq(mld);
}

static int link_load_cp_image(struct link_device *ld, struct io_device *iod,
		     unsigned long arg)
{
	struct mem_link_device *mld = to_mem_link_device(ld);
	void __iomem *dst;
	void __user *src;
	struct cp_image img;
	void __iomem *v_base;
	size_t valid_space;
	int ret = 0;

	/**
	 * Get the information about the boot image
	 */
	memset(&img, 0, sizeof(struct cp_image));

	ret = copy_from_user(&img, (const void __user *)arg, sizeof(img));
	if (ret) {
		mif_err("%s: ERR! INFO copy_from_user fail\n", ld->name);
		return -EFAULT;
	}

	mutex_lock(&mld->vmap_lock);

	if (mld->attrs & LINK_ATTR_XMIT_BTDLR_PCIE) {
		struct modem_data *modem = mld->link_dev.mdm_data;

		/*
		 * Copy boot img to data buffer for keeping the IPC region integrity.
		 * boot_img_offset should be 64KB aligned.
		 */
		mld->boot_img_offset = round_up(modem->legacy_raw_buffer_offset, SZ_64K);
		mld->boot_img_size = img.size;

		valid_space = mld->size - mld->boot_img_offset;
		v_base = mld->base + mld->boot_img_offset;

		goto check_img;
	}

	if (mld->boot_base == NULL) {
		mld->boot_base = cp_shmem_get_nc_region(cp_shmem_get_base(SHMEM_CP),
			mld->boot_size);
		if (!mld->boot_base) {
			mif_err("Failed to vmap boot_region\n");
			ret = -EINVAL;
			goto out;
		}
	}

	/* Calculate size of valid space which BL will download */
	valid_space = (img.mode) ? mld->size : mld->boot_size;
	/* Calculate base address (0: BOOT_MODE, 1: DUMP_MODE) */
	v_base = (img.mode) ? mld->base : mld->boot_base;

check_img:
	/**
	 * Check the size of the boot image
	 * fix the integer overflow of "img.m_offset + img.len" from Jose Duart
	 */
	if (img.size > valid_space || img.len > valid_space
			|| img.m_offset > valid_space - img.len) {
		mif_err("%s: ERR! Invalid args: size %x, offset %x, len %x\n",
			ld->name, img.size, img.m_offset, img.len);
		ret = -EINVAL;
		goto out;
	}

	dst = (void __iomem *)(v_base + img.m_offset);
	src = (void __user *)((unsigned long)img.binary);
	ret = copy_from_user_memcpy_toio(dst, src, img.len);
	if (ret) {
		mif_err("%s: ERR! BOOT copy_from_user fail\n", ld->name);
		goto out;
	}

out:
	mutex_unlock(&mld->vmap_lock);

	return ret;
}

static int link_load_gnss_image(struct link_device *ld,
	struct io_device *iod, unsigned long arg)
{
	struct gnss_image img;
	void __iomem *dst;
	void __user *src;

	int ret = 0;
	struct mem_link_device *mld = to_mem_link_device(ld);

	memset(&img, 0, sizeof(struct gnss_image));

	mif_info("Load GNSS images\n");

	if (!mld->gnss_v_base) {
		mld->gnss_v_base = cp_shmem_get_nc_region(
			cp_shmem_get_base(SHMEM_GNSS_FW),
			cp_shmem_get_size(SHMEM_GNSS_FW));
		if (!mld->gnss_v_base) {
			mif_err("cp_shmem_get_nc_region() fail\n");
			return -ENOMEM;
		}
	}

	ret = copy_from_user(&img, (const void __user *)arg, sizeof(img));
	if (ret) {
		mif_err("copy_from_user() fail:%d\n", ret);
		return ret;
	}

	if (img.firmware_size > cp_shmem_get_size(SHMEM_GNSS_FW) ||
		(img.offset > cp_shmem_get_size(SHMEM_GNSS_FW) - img.firmware_size)) {
		mif_err("offset:%d size:%d error\n",
			img.offset, img.firmware_size);
		return -EFAULT;
	}

	dst = (void __iomem *)(mld->gnss_v_base + img.offset);
	src = (void __user *)((unsigned long)img.firmware_bin);
	ret = copy_from_user_memcpy_toio(dst, src, img.firmware_size);
	if (ret) {
		mif_err("copy_from_user_memcpy_toio() fail:%d\n", ret);
		return ret;
	}

	return ret;
}

static int link_read_gnss_image(struct link_device *ld,
	struct io_device *iod, unsigned long arg)
{
	struct gnss_image img;
	int err = 0;
	struct mem_link_device *mld = to_mem_link_device(ld);

	memset(&img, 0, sizeof(struct gnss_image));
	err = copy_from_user(&img, (const void __user *)arg,
			sizeof(struct gnss_image));
	if (err) {
		mif_err("copy_from_user fail:%d\n", err);
		return err;
	}

	if (img.firmware_size > cp_shmem_get_size(SHMEM_GNSS_FW) ||
		(img.offset > cp_shmem_get_size(SHMEM_GNSS_FW) - img.firmware_size)) {
		mif_err("offset:%d size:%d error\n",
			img.offset, img.firmware_size);
		return -EFAULT;
	}

	err = copy_to_user(img.firmware_bin,
		mld->gnss_v_base + img.offset, img.firmware_size);
	if (err) {
		mif_err("copy_to_user fail:%d\n", err);
		return err;
	}

	return 0;
}


int shm_get_security_param2(unsigned long mode, u32 bl_size,
		unsigned long *param)
{
	int ret = 0;

	switch (mode) {
	case CP_BOOT_MODE_NORMAL:
	case CP_BOOT_MODE_DUMP:
		*param = bl_size;
		break;
	case CP_BOOT_RE_INIT:
		*param = 0;
		break;
	case CP_BOOT_MODE_MANUAL:
#if IS_ENABLED(CONFIG_VERIFY_VSS)
	case CP_BOOT_MODE_VSS:
#endif
		*param = cp_shmem_get_base(SHMEM_CP) + bl_size;
		break;
	default:
		mif_info("Invalid sec_mode(%lu)\n", mode);
		ret = -EINVAL;
		break;
	}
	return ret;
}

int shm_get_security_param3(unsigned long mode, u32 main_size,
		unsigned long *param)
{
	int ret = 0;

	switch (mode) {
	case CP_BOOT_MODE_NORMAL:
		*param = main_size;
		break;
	case CP_BOOT_MODE_DUMP:
#ifdef CP_NONSECURE_BOOT
		*param = cp_shmem_get_base(SHMEM_CP);
#else
		*param = cp_shmem_get_base(SHMEM_IPC);
#endif
		break;
	case CP_BOOT_RE_INIT:
		*param = 0;
		break;
	case CP_BOOT_MODE_MANUAL:
		*param = main_size;
		break;
#if IS_ENABLED(CONFIG_VERIFY_VSS)
	case CP_BOOT_MODE_VSS:
		*param = (((unsigned long)cp_shmem_get_size(SHMEM_VSS) << 32)
				| (unsigned long)main_size);
		break;
#endif
	default:
		mif_info("Invalid sec_mode(%lu)\n", mode);
		ret = -EINVAL;
		break;
	}
	return ret;
}

#define MAX_TRY_CNT			0x1000
#define MODE_CP_CHECK_CONTINUE		0x8

static int shmem_security_request(struct link_device *ld, struct io_device *iod,
				unsigned long arg)
{
	unsigned long mode, param2, param3;
	int err = 0;
	struct modem_sec_req msr;
#if IS_ENABLED(CONFIG_CP_SECURE_BOOT)
	uint32_t try_cnt = 0;
#endif
#if IS_ENABLED(CONFIG_REINIT_VSS)
	static bool first_boot = true;
	unsigned long remain;
	struct modem_ctl *mc = ld->mc;
	unsigned long timeout = msecs_to_jiffies(400);
#endif

	struct mem_link_device *mld = ld->mdm_data->mld;
#if IS_ENABLED(CONFIG_CP_PKTPROC)
#if IS_ENABLED(CONFIG_EXYNOS_CPIF_IOMMU) || IS_ENABLED(CONFIG_EXYNOS_CPIF_IOMMU_V9)
	struct pktproc_adaptor *ppa = &mld->pktproc;
#endif
#endif

	err = copy_from_user(&msr, (const void __user *)arg, sizeof(msr));
	if (err) {
		mif_err("%s: ERR! copy_from_user fail\n", ld->name);
		err = -EFAULT;
		goto exit;
	}

	mode = (unsigned long)msr.mode;
	err = shm_get_security_param2(mode, msr.param2, &param2);
	if (err) {
		mif_err("%s: ERR! parameter2 is invalid\n", ld->name);
		goto exit;
	}
	err = shm_get_security_param3(mode, msr.param3, &param3);
	if (err) {
		mif_err("%s: ERR! parameter3 is invalid\n", ld->name);
		goto exit;
	}

#if IS_ENABLED(CONFIG_REINIT_VSS)
	if (first_boot == false) {
		if (mode == CP_BOOT_RE_INIT) {
			mif_info("wait 400ms until vss stop\n");
			remain = wait_for_completion_timeout(&mc->vss_stop, timeout);
			if (remain == 0)
				mif_err("ERROR: there was no answer from vss\n");
		}
	} else {
		mif_info("first boot - skip waiting vss\n");
		first_boot = false;
	}
#endif

	mutex_lock(&mld->vmap_lock);
	if (mld->boot_base != NULL) {
		/* boot_base is in no use at this point */
		vunmap(mld->boot_base);
		mld->boot_base = NULL;
	}
	mutex_unlock(&mld->vmap_lock);

#if IS_ENABLED(CONFIG_CP_SECURE_BOOT)
	exynos_smc(SMC_ID_CLK, SSS_CLK_ENABLE, 0, 0);
	if ((mode == CP_BOOT_MODE_NORMAL) && cp_shmem_get_mem_map_on_cp_flag())
		mode |= cp_shmem_get_base(SHMEM_CP);

	mif_info("mode:0x%lx, param2=0x%lx, param3=0x%lx, cp_base_addr=0x%lx\n",
			mode, param2, param3, cp_shmem_get_base(SHMEM_CP));
	err = (int)exynos_smc(SMC_ID, mode, param2, param3);

	while (err == CP_CHECK_SIGN_NOT_FINISH && try_cnt < MAX_TRY_CNT) {
		try_cnt++;
		err = (int)exynos_smc(SMC_ID, MODE_CP_CHECK_CONTINUE, 0x0, 0x0);
	}

	exynos_smc(SMC_ID_CLK, SSS_CLK_DISABLE, 0, 0);

	if (try_cnt >= MAX_TRY_CNT)
		mif_info("%s: it fails to check signature of main binary.\n", ld->name);

	mif_info("%s: return_value=%d\n", ld->name, err);
#endif

#if IS_ENABLED(CONFIG_CP_PKTPROC)
	if ((mode == CP_BOOT_RE_INIT) && mld->pktproc.use_dedicated_baaw) {
		mif_info("memaddr:0x%lx memsize:0x%08x\n",
				cp_shmem_get_base(SHMEM_PKTPROC),
				cp_shmem_get_size(SHMEM_PKTPROC)
#if IS_ENABLED(CONFIG_CP_PKTPROC_UL)
				+ cp_shmem_get_size(SHMEM_PKTPROC_UL));
#else
				);
#endif

		exynos_smc(SMC_ID_CLK, SSS_CLK_ENABLE, 0, 0);
#if IS_ENABLED(CONFIG_EXYNOS_CPIF_IOMMU) || IS_ENABLED(CONFIG_EXYNOS_CPIF_IOMMU_V9)
		err = (int)exynos_smc(SMC_ID, CP_BOOT_EXT_BAAW,
			ppa->cp_base, SYSMMU_BAAW_SIZE);
#else
		err = (int)exynos_smc(SMC_ID, CP_BOOT_EXT_BAAW,
			(unsigned long)cp_shmem_get_base(SHMEM_PKTPROC),
			(unsigned long)cp_shmem_get_size(SHMEM_PKTPROC)
#if IS_ENABLED(CONFIG_CP_PKTPROC_UL)
			+ (unsigned long)cp_shmem_get_size(SHMEM_PKTPROC_UL));
#else
			);
#endif
#endif

		exynos_smc(SMC_ID_CLK, SSS_CLK_DISABLE, 0, 0);
		if (err)
			mif_err("ERROR: SMC call failure:%d\n", err);
	}
#endif

exit:
	return err;
}

#if IS_ENABLED(CONFIG_CLO)
static void gro_flush_timer(struct link_device *ld, struct napi_struct *napi)
{
	struct mem_link_device *mld = to_mem_link_device(ld);
	struct timespec64 curr, diff;

	if (!clo_gro_flush_time) {
		napi_gro_flush(napi, false);
		return;
	}

	if (unlikely(mld->flush_time.tv_sec == 0)) {
		ktime_get_real_ts64(&mld->flush_time);
	} else {
		ktime_get_real_ts64(&(curr));
		diff = timespec64_sub(curr, mld->flush_time);
		if ((diff.tv_sec > 0) || (diff.tv_nsec > clo_gro_flush_time)) {
			napi_gro_flush(napi, false);
			ktime_get_real_ts64(&mld->flush_time);
		}
	}
}

static struct timespec64 update_flush_time(struct timespec64 org_flush_time)
{
	struct timespec64 curr, diff, ret;

	ktime_get_real_ts64(&curr);
	if (unlikely(org_flush_time.tv_sec == 0)) {
		ktime_get_real_ts64(&ret);
		return ret;
	}
	diff = timespec64_sub(curr, org_flush_time);
	if (diff.tv_nsec > clo_gro_flush_time)
		ktime_get_real_ts64(&ret);
	else
		ret = org_flush_time;

	return ret;
}
#endif

#if IS_ENABLED(CONFIG_LINK_DEVICE_WITH_SBD_ARCH)
static int sbd_link_rx_func_napi(struct sbd_link_device *sl, struct link_device *ld, int budget,
		int *work_done)
{
	int i = 0;
	int ret = 0;

	for (i = 0; i < sl->num_channels ; i++) {
		struct sbd_ring_buffer *rb = sbd_id2rb(sl, i, RX);
		int ps_rcvd = 0;

		if (unlikely(rb_empty(rb)))
			continue;
		if (budget <= 0 && is_ps_iod(rb->iod))
			continue;
		if (!is_ps_iod(rb->iod))
			ret = rx_ipc_frames_from_rb(rb);
		else /* ps channels */
			ret = sbd_ipc_rx_func_napi(ld, rb->iod, budget, &ps_rcvd);
		if ((ret == -EBUSY) || (ret == -ENOMEM) || (ret == -EFAULT))
			break;
		if (is_ps_iod(rb->iod)) {
			/* count budget only for ps frames */
			budget -= ps_rcvd;
			*work_done += ps_rcvd;
		}
	}
	return ret;
}
#endif

static int legacy_link_rx_func_napi(struct mem_link_device *mld, int budget, int *work_done)
{
	int i = 0;
	int ret = 0;

	for (i = 0; i < IPC_MAP_MAX; i++) {
		struct legacy_ipc_device *dev = mld->legacy_link_dev.dev[i];
		int ps_rcvd = 0;

		if (unlikely(circ_empty(get_rxq_head(dev), get_rxq_tail(dev))))
			continue; /* go to next device */
		if (budget <= 0)
			break;
		ret = legacy_ipc_rx_func_napi(mld, dev, budget, &ps_rcvd);
		if ((ret == -EBUSY) || (ret == -ENOMEM))
			break;
		/* count budget for all frames */
		budget -= ps_rcvd;
		*work_done += ps_rcvd;

	}

#if IS_ENABLED(CONFIG_CPIF_TP_MONITOR)
	tpmon_add_legacy_packet_count(*work_done);
#endif

	return ret;
}

static int shmem_enqueue_snapshot(struct mem_link_device *mld);

/*
 * mld_rx_int_poll
 *
 * This NAPI poll function does not handle reception of any network frames.
 * It is used for servicing CP2AP commands and FMT RX frames while the RX
 * mailbox interrupt is masked. When the mailbox interrupt is masked, CP can
 * set the interrupt but the AP will not react. However, the interrupt status
 * bit will still be set, so we can poll the status bit to handle new RX
 * interrupts.
 * If the RAW NAPI functions are no longer scheduled at the end of this poll
 * function, we can enable the mailbox interrupt and stop polling.
 */
static int mld_rx_int_poll(struct napi_struct *napi, int budget)
{
	struct mem_link_device *mld = container_of(napi, struct mem_link_device,
			mld_napi);
	struct link_device *ld = &mld->link_dev;
	struct modem_ctl *mc = ld->mc;
	int total_ps_rcvd = 0;
	int ps_rcvd = 0;
	int ret = 0;
	int total_budget = budget;
	u32 qlen = 0;

	mld->rx_poll_count++;

	if (shmem_enqueue_snapshot(mld))
		goto dummy_poll_complete;

	qlen = mld->msb_rxq.qlen;

	if (unlikely(!cp_online(mc))) { /* for boot and dump sequences */
		queue_delayed_work(ld->rx_wq, &mld->bootdump_rx_dwork, 0);
		goto dummy_poll_complete;
	}

	while (qlen-- > 0) {
		struct mst_buff *msb;
		u16 intr;

		msb = msb_dequeue(&mld->msb_rxq);
		if (!msb)
			break;
		intr = msb->snapshot.int2ap;
		if (cmd_valid(intr))
			mld->cmd_handler(mld, int2cmd(intr));
		msb_free(msb);
	}

#if IS_ENABLED(CONFIG_LINK_DEVICE_WITH_SBD_ARCH)
	if (sbd_active(&mld->sbd_link_dev)) {
		struct sbd_link_device *sl = &mld->sbd_link_dev;

		ret = sbd_link_rx_func_napi(sl, ld, budget, &ps_rcvd);
		if (ret == -EFAULT) { /* unrecoverable error */
			link_trigger_cp_crash(mld, CRASH_REASON_MIF_RX_BAD_DATA,
					"rp exceeds ring buffer size");
			goto dummy_poll_complete;
		}
	} else {
		ret = legacy_link_rx_func_napi(mld, budget, &ps_rcvd);
	}
#else
	ret = legacy_link_rx_func_napi(mld, budget, &ps_rcvd);
#endif

	if ((ret == -EBUSY) || (ret == -ENOMEM))
		goto keep_poll;

	budget -= ps_rcvd;
	total_ps_rcvd += ps_rcvd;
	ps_rcvd = 0;

#if IS_ENABLED(CONFIG_CP_PKTPROC)
	if (pktproc_check_support(&mld->pktproc) && !mld->pktproc.use_exclusive_irq) {
		int i;

		for (i = 0; i < mld->pktproc.num_queue; i++) {
			if (!pktproc_check_active(&mld->pktproc, i))
				continue;

			ret = mld->pktproc.q[i]->clean_rx_ring(mld->pktproc.q[i], budget, &ps_rcvd);
			if ((ret == -EBUSY) || (ret == -ENOMEM))
				goto keep_poll;

			budget -= ps_rcvd;
			total_ps_rcvd += ps_rcvd;
			ps_rcvd = 0;
		}
	}
#endif

#if IS_ENABLED(CONFIG_CPIF_TP_MONITOR)
	if (total_ps_rcvd)
		tpmon_start();
#endif

	if (atomic_read(&mld->stop_napi_poll)) {
		atomic_set(&mld->stop_napi_poll, 0);
		goto dummy_poll_complete;
	}

	if (total_ps_rcvd < total_budget) {
		napi_complete_done(napi, total_ps_rcvd);
		return total_ps_rcvd;
	}

keep_poll:
	return total_budget;

dummy_poll_complete:
	napi_complete(napi);

	return 0;
}

static void sync_net_dev(struct link_device *ld)
{
	struct mem_link_device *mld = to_mem_link_device(ld);

	napi_synchronize(&mld->mld_napi);
	mif_info("%s\n", netdev_name(&mld->dummy_net));
}

static int link_start_normal_boot(struct link_device *ld, struct io_device *iod)
{
	struct mem_link_device *mld = to_mem_link_device(ld);

#if IS_ENABLED(CONFIG_LINK_DEVICE_WITH_SBD_ARCH)
	if (ld->sbd_ipc && mld->attrs & LINK_ATTR_MEM_DUMP)
		sbd_deactivate(&mld->sbd_link_dev);
#endif

	sync_net_dev(ld);

	init_legacy_link(&mld->legacy_link_dev);
	skb_queue_purge(&iod->sk_rx_q);

	if (mld->attrs & LINK_ATTR_BOOT_ALIGNED)
		ld->aligned = true;
	else
		ld->aligned = false;

	if (mld->dpram_magic) {
		unsigned int magic;

		iowrite32(ld->magic_boot, mld->legacy_link_dev.magic);
		magic = ioread32(mld->legacy_link_dev.magic);
		if (magic != ld->magic_boot) {
			mif_err("%s: ERR! magic 0x%08X != BOOT_MAGIC 0x%08X\n",
				ld->name, magic, ld->magic_boot);
			return -EFAULT;
		}
		mif_info("%s: magic == 0x%08X\n", ld->name, magic);
	}

	return 0;
}

static int link_start_dump_boot(struct link_device *ld, struct io_device *iod)
{
	struct mem_link_device *mld = to_mem_link_device(ld);

#if IS_ENABLED(CONFIG_LINK_DEVICE_WITH_SBD_ARCH)
	if (ld->sbd_ipc && mld->attrs & LINK_ATTR_MEM_DUMP)
		sbd_deactivate(&mld->sbd_link_dev);
#endif

	sync_net_dev(ld);

	init_legacy_link(&mld->legacy_link_dev);
	skb_queue_purge(&iod->sk_rx_q);

	if (mld->attrs & LINK_ATTR_DUMP_ALIGNED)
		ld->aligned = true;
	else
		ld->aligned = false;

	if (mld->dpram_magic) {
		unsigned int magic, magic_cmp;

		magic = ld->minidump_mode ? ld->magic_minidump : ld->magic_dump;
		iowrite32(magic, mld->legacy_link_dev.magic);
		magic_cmp = ioread32(mld->legacy_link_dev.magic);
		if (magic_cmp != magic) {
			mif_err("%s: ERR! magic_cmp 0x%08X != magic 0x%08X\n",
				ld->name, magic_cmp, magic);
			return -EFAULT;
		}
		mif_info("%s: magic == 0x%08X\n", ld->name, magic);
	}

	return 0;
}

static void shmem_close_tx(struct link_device *ld)
{
	struct mem_link_device *mld = to_mem_link_device(ld);
	unsigned long flags;

	spin_lock_irqsave(&mld->state_lock, flags);
	mld->state = LINK_STATE_OFFLINE;
	spin_unlock_irqrestore(&mld->state_lock, flags);

	if (timer_pending(&mld->crash_ack_timer))
		del_timer(&mld->crash_ack_timer);

	stop_net_ifaces(ld, 0);
	purge_txq(mld);
}

static int get_cp_crash_reason(struct link_device *ld, struct io_device *iod,
		unsigned long arg)
{
	int ret;

	ret = copy_to_user((void __user *)arg, &ld->crash_reason,
		sizeof(struct crash_reason));
	if (ret) {
		mif_err("ERR! copy_to_user fail!\n");
		return -EFAULT;
	}

	return 0;
}
/*============================================================================*/


#if IS_ENABLED(CONFIG_LINK_DEVICE_SHMEM)
static u16 shmem_recv_cp2ap_irq(struct mem_link_device *mld)
{
	return get_ctrl_msg(&mld->cp2ap_msg);
}

static u16 shmem_recv_cp2ap_status(struct mem_link_device *mld)
{
	return (u16)extract_ctrl_msg(&mld->cp2ap_united_status, mld->sbi_cp_status_mask,
			mld->sbi_cp_status_pos);
}

static void shmem_send_ap2cp_irq(struct mem_link_device *mld, u16 mask)
{
	set_ctrl_msg(&mld->ap2cp_msg, mask);

	cp_mbox_set_interrupt(CP_MBOX_IRQ_IDX_0, mld->int_ap2cp_msg);
}

static inline u16 shmem_read_ap2cp_irq(struct mem_link_device *mld)
{
	return (u16)get_ctrl_msg(&mld->ap2cp_msg);
}
#endif

#if IS_ENABLED(CONFIG_LINK_DEVICE_PCIE)
static u16 pcie_recv_cp2ap_irq(struct mem_link_device *mld)
{
	return (u16)get_ctrl_msg(&mld->cp2ap_msg);
}

static u16 pcie_recv_cp2ap_status(struct mem_link_device *mld)
{
	return (u16)get_ctrl_msg(&mld->cp2ap_united_status);
}

static void pcie_send_ap2cp_irq(struct mem_link_device *mld, u16 mask)
{
	struct link_device *ld = &mld->link_dev;
	struct modem_ctl *mc = ld->mc;
	unsigned long flags;
	bool force_crash = false;

	spin_lock_irqsave(&mc->pcie_tx_lock, flags);

	if (mutex_is_locked(&mc->pcie_onoff_lock)) {
		mif_info_limited("Reserve doorbell interrupt: PCI on/off working\n");
		set_ctrl_msg(&mld->ap2cp_msg, mask);
		mc->reserve_doorbell_int = true;
		goto exit;
	}

	if (!mc->pcie_powered_on) {
		mif_info_limited("Reserve doorbell interrupt: PCI not powered on\n");
		set_ctrl_msg(&mld->ap2cp_msg, mask);
		mc->reserve_doorbell_int = true;
		s5100_try_gpio_cp_wakeup(mc);
		goto exit;
	}

	set_ctrl_msg(&mld->ap2cp_msg, mask);
	mc->reserve_doorbell_int = false;
	if (s51xx_pcie_send_doorbell_int(mc->s51xx_pdev, mld->intval_ap2cp_msg) != 0)
		force_crash = true;

exit:
	spin_unlock_irqrestore(&mc->pcie_tx_lock, flags);

	if (unlikely(force_crash))
		modem_force_crash_exit(mc);
}

static inline u16 pcie_read_ap2cp_irq(struct mem_link_device *mld)
{
	return (u16)get_ctrl_msg(&mld->ap2cp_msg);
}
#endif

struct shmem_srinfo {
	unsigned int size;
	char buf[0];
};

#if IS_ENABLED(CONFIG_SBD_BOOTLOG)
static void shmem_clr_sbdcplog(struct mem_link_device *mld)
{
	u8 __iomem *base = mld->base + mld->size - SHMEM_BOOTSBDLOG_SIZE;

	memset(base, 0, SHMEM_BOOTSBDLOG_SIZE);
}

void shmem_pr_sbdcplog(struct timer_list *t)
{
	struct link_device *ld = from_timer(ld, t, cplog_timer);
	struct mem_link_device *mld = ld_to_mem_link_device(ld);
	u8 __iomem *base = mld->base + mld->size - SHMEM_BOOTSBDLOG_SIZE;
	u8 __iomem *offset;
	int i;

	mif_info("dump cp logs: size: 0x%x, base: %p\n", (unsigned int)mld->size, base);

	for (i = 0; i * 32 < SHMEM_BOOTSBDLOG_SIZE; i++) {
		offset = base + i * 32;
		mif_info("%6X: %*ph\n", (unsigned int)(offset - mld->base), 32, offset);
	}

	shmem_clr_sbdcplog(mld);
}
#endif

/* not in use */
static int shmem_ioctl(struct link_device *ld, struct io_device *iod,
		       unsigned int cmd, unsigned long arg)
{
	struct mem_link_device *mld = ld_to_mem_link_device(ld);

	mif_info("%s: cmd 0x%08X\n", ld->name, cmd);
	switch (cmd) {
	case IOCTL_GET_SRINFO:
	{
		struct shmem_srinfo __user *sr_arg =
			(struct shmem_srinfo __user *)arg;
		unsigned int count, size = mld->srinfo_size;

		if (copy_from_user(&count, &sr_arg->size, sizeof(unsigned int)))
			return -EFAULT;

		mif_info("get srinfo:%s, size = %d\n", iod->name, count);

		size = min(size, count);
		if (copy_to_user(&sr_arg->size, &size, sizeof(unsigned int)))
			return -EFAULT;

		if (copy_to_user(sr_arg->buf, mld->srinfo_base, size))
			return -EFAULT;
		break;
	}

	case IOCTL_SET_SRINFO:
	{
		struct shmem_srinfo __user *sr_arg =
			(struct shmem_srinfo __user *)arg;
		unsigned int count, size = mld->srinfo_size;

		if (copy_from_user(&count, &sr_arg->size, sizeof(unsigned int)))
			return -EFAULT;

		mif_info("set srinfo:%s, size = %d\n", iod->name, count);

		if (copy_from_user(mld->srinfo_base, sr_arg->buf, min(count, size)))
			return -EFAULT;
		break;
	}

	case IOCTL_GET_CP_BOOTLOG:
	{
#if !IS_ENABLED(CONFIG_SBD_BOOTLOG)
		u8 __iomem *base = mld->base + SHMEM_BOOTLOG_BASE;
		char str[SHMEM_BOOTLOG_BUFF];
		unsigned int size = base[0]        + (base[1] << 8)
				 + (base[2] << 16) + (base[3] << 24);

		if (size <= 0 || size > SHMEM_BOOTLOG_BUFF - SHMEM_BOOTLOG_OFFSET) {
			mif_info("Invalid CP boot log[%d]\n", size);
			return -EINVAL;
		}

		strncpy(str, base + SHMEM_BOOTLOG_OFFSET, size);
		mif_info("CP boot log[%d] : %s\n", size, str);
#else
		mif_add_timer(&ld->cplog_timer, 0, shmem_pr_sbdcplog);
#endif
		break;
	}

	case IOCTL_CLR_CP_BOOTLOG:
	{
#if !IS_ENABLED(CONFIG_SBD_BOOTLOG)
		u8 __iomem *base = mld->base + SHMEM_BOOTLOG_BASE;

		mif_info("Clear CP boot log\n");
		memset(base, 0, SHMEM_BOOTLOG_BUFF);
#endif
		break;
	}

	default:
		mif_err("%s: ERR! invalid cmd 0x%08X\n", ld->name, cmd);
		return -EINVAL;
	}

	return 0;
}

irqreturn_t shmem_tx_state_handler(int irq, void *data)
{
#define TX_FLOWCTL_RESUME_ACK	0
#define TX_FLOWCTL_SUSPEND_ACK	1

	struct mem_link_device *mld = (struct mem_link_device *)data;
	struct link_device *ld = &mld->link_dev;
	struct modem_ctl *mc = ld->mc;
	u16 int2ap_status;
	int ret;

	int2ap_status = mld->recv_cp2ap_status(mld);

	/* Change SHM_FLOWCTL to MASK_TX_FLOWCTRL */
	int2ap_status = (int2ap_status & SHM_FLOWCTL_BIT) << 2;

	ret = extract_ctrl_msg(&mld->ap2cp_united_status,
		mc->sbi_tx_flowctl_mask, mc->sbi_tx_flowctl_pos);

	switch (int2ap_status & (SHM_FLOWCTL_BIT << 2)) {
	case MASK_TX_FLOWCTL_SUSPEND:
		if (ret == TX_FLOWCTL_SUSPEND_ACK)
			ld->dup_count_suspend++;

		if (!chk_same_cmd(mld, int2ap_status)) {
			tx_flowctrl_suspend(mld);
			update_ctrl_msg(&mld->ap2cp_united_status, TX_FLOWCTL_SUSPEND_ACK,
				mc->sbi_tx_flowctl_mask, mc->sbi_tx_flowctl_pos);
			ld->dup_count_suspend = 0;
		}
		break;

	case MASK_TX_FLOWCTL_RESUME:
		if (ret == TX_FLOWCTL_RESUME_ACK)
			ld->dup_count_resume++;

		if (!chk_same_cmd(mld, int2ap_status)) {
			tx_flowctrl_resume(mld);
			update_ctrl_msg(&mld->ap2cp_united_status, TX_FLOWCTL_RESUME_ACK,
				mc->sbi_tx_flowctl_mask, mc->sbi_tx_flowctl_pos);
			ld->dup_count_resume = 0;
		}
		break;

	default:
		break;
	}

	if (unlikely(!rx_possible(mc))) {
		mif_err("%s: ERR! %s.state == %s\n", ld->name, mc->name,
			mc_state(mc));
	}

	return IRQ_HANDLED;
}

static int shmem_enqueue_snapshot(struct mem_link_device *mld)
{
	struct mst_buff *msb;
	struct link_device *ld = &mld->link_dev;
	struct modem_ctl *mc = ld->mc;

	msb = mem_take_snapshot(mld, RX);
	if (!msb)
		return -ENOMEM;

	if (unlikely(!int_valid(msb->snapshot.int2ap))) {
		mif_err("%s: ERR! invalid intr 0x%X\n",
				ld->name, msb->snapshot.int2ap);
		msb_free(msb);
		return -EINVAL;
	}

	if (unlikely(!rx_possible(mc))) {
		mif_err("%s: ERR! %s.state == %s\n", ld->name, mc->name,
			mc_state(mc));
		msb_free(msb);
		return -EINVAL;
	}

	msb_queue_tail(&mld->msb_rxq, msb);

	return 0;
}

irqreturn_t shmem_irq_handler(int irq, void *data)
{
	struct mem_link_device *mld = (struct mem_link_device *)data;
#if IS_ENABLED(CONFIG_CLO)
	struct link_device *ld = &mld->link_dev;

	mld->flush_time = ld->update_flush_time(mld->flush_time);
#endif

	mld->rx_int_count++;
	napi_schedule(&mld->mld_napi);

	return IRQ_HANDLED;
}

#if IS_ENABLED(CONFIG_MCU_IPC)
static irqreturn_t shmem_cp2ap_wakelock_handler(int irq, void *data)
{
	struct mem_link_device *mld = (struct mem_link_device *)data;
	unsigned int req;

	mif_info("%s\n", __func__);

	req = extract_ctrl_msg(&mld->cp2ap_united_status, mld->sbi_cp2ap_wakelock_mask,
			mld->sbi_cp2ap_wakelock_pos);

	if (req == 0) {
		if (cpif_wake_lock_active(mld->ws)) {
			cpif_wake_unlock(mld->ws);
			mif_info("cp_wakelock unlocked\n");
		} else {
			mif_info("cp_wakelock already unlocked\n");
		}
	} else if (req == 1) {
		if (cpif_wake_lock_active(mld->ws)) {
			mif_info("cp_wakelock already unlocked\n");
		} else {
			cpif_wake_lock(mld->ws);
			mif_info("cp_wakelock locked\n");
		}
	} else {
		mif_err("unsupported request: cp_wakelock\n");
	}

	return IRQ_HANDLED;
}
#endif

#if IS_ENABLED(CONFIG_MCU_IPC) && IS_ENABLED(CONFIG_LINK_DEVICE_PCIE)
static irqreturn_t shmem_cp2ap_rat_mode_handler(int irq, void *data)
{
	struct mem_link_device *mld = (struct mem_link_device *)data;
	unsigned int req;

	req = extract_ctrl_msg(&mld->cp2ap_united_status, mld->sbi_cp_rat_mode_mask,
			mld->sbi_cp_rat_mode_pos);

	mif_info("value: %u\n", req);

	if (req) {
		s51xx_pcie_l1ss_ctrl(0);
		mif_info("cp requests pcie l1ss disable\n");
	} else {
		s51xx_pcie_l1ss_ctrl(1);
		mif_info("cp requests pcie l1ss enable\n");
	}

	return IRQ_HANDLED;
}
#endif

#if IS_ENABLED(CONFIG_MCU_IPC) && IS_ENABLED(CONFIG_CP_LLC)
static irqreturn_t shmem_cp2ap_llc_handler(int irq, void *data)
{
	struct mem_link_device *mld = (struct mem_link_device *)data;
	enum cp_llc_request request;
	enum cp_llc_target target;
	unsigned int alloc;
	unsigned int way;
	int err;
	enum cp_llc_return ret;

	request = extract_ctrl_msg(&mld->cp2ap_llc_status, mld->sbi_cp_llc_request_mask,
			mld->sbi_cp_llc_request_pos);
	target = extract_ctrl_msg(&mld->cp2ap_llc_status, mld->sbi_cp_llc_target_mask,
			mld->sbi_cp_llc_target_pos);
	alloc = extract_ctrl_msg(&mld->cp2ap_llc_status, mld->sbi_cp_llc_alloc_mask,
			mld->sbi_cp_llc_alloc_pos);
	way = extract_ctrl_msg(&mld->cp2ap_llc_status, mld->sbi_cp_llc_way_mask,
			mld->sbi_cp_llc_way_pos);

	switch (request) {
	case LLC_REQUEST_ALLOC:
		mif_info("CP requests LLC %s on target:%u way:%u val:0x%08X\n",
				alloc ? "alloc" : "dealloc", target, way,
				ioread32(mld->cp2ap_llc_status.addr));
		err = alloc_llc_to_cp(target, alloc, way);
		if (err >= 0)
			ret = alloc ? LLC_ALLOC_SUCCESS : LLC_DEALLOC_SUCCESS;
		else
			ret = alloc ? LLC_ALLOC_FAIL : LLC_DEALLOC_FAIL;
		break;
	case LLC_REQUEST_GET:
		mif_info("CP requests LLC status of target: %u val:0x%08X\n",
				target, ioread32(mld->cp2ap_llc_status.addr));
		err = llc_get_region_info(target ? LLC_REGION_CP_MAX_TP : LLC_REGION_CPCPU);
		if (err < 0) {
			ret = LLC_GET_FAIL;
			alloc = 0;
			way = 0;
		} else {
			ret = LLC_GET_SUCCESS;
			alloc = err ? 1 : 0;
			way = err;
		}
		break;
	default:
		mif_err("wrong request came from CP: %d\n", request);
		return IRQ_HANDLED;
	}

	/* send setting noti to CP */
	update_ctrl_msg(&mld->ap2cp_llc_status, request,
			mld->sbi_ap_llc_request_mask,
			mld->sbi_ap_llc_request_pos);
	update_ctrl_msg(&mld->ap2cp_llc_status, target,
			mld->sbi_ap_llc_target_mask,
			mld->sbi_ap_llc_target_pos);
	update_ctrl_msg(&mld->ap2cp_llc_status, ret,
			mld->sbi_ap_llc_return_mask,
			mld->sbi_ap_llc_return_pos);

	if (err >= 0) {
		update_ctrl_msg(&mld->ap2cp_llc_status, alloc,
				mld->sbi_ap_llc_alloc_mask,
				mld->sbi_ap_llc_alloc_pos);
		update_ctrl_msg(&mld->ap2cp_llc_status, way,
				mld->sbi_ap_llc_way_mask,
				mld->sbi_ap_llc_way_pos);
	}

	cp_mbox_set_interrupt(CP_MBOX_IRQ_IDX_0, mld->int_ap2cp_llc_status);

	mif_info("done processing CP LLC (%s) request:%u target:%u return: %u alloc:%u way:%u\n",
		err >= 0 ? "success" : "fail", request, target, ret, alloc, way);

	return IRQ_HANDLED;
}
#endif

#if IS_ENABLED(CONFIG_ECT)
static int parse_ect(struct mem_link_device *mld, char *dvfs_domain_name)
{
	int i, counter = 0;
	u32 mif_max_freq, mif_max_num_of_table = 0;
	void *dvfs_block;
	struct ect_dvfs_domain *dvfs_domain;

	dvfs_block = ect_get_block(BLOCK_DVFS);
	if (dvfs_block == NULL)
		return -ENODEV;

	dvfs_domain = ect_dvfs_get_domain(dvfs_block, (char *)dvfs_domain_name);
	if (dvfs_domain == NULL)
		return -ENODEV;

	if (!strcmp(dvfs_domain_name, "MIF")) {
		mld->mif_table.num_of_table = dvfs_domain->num_of_level;
		mif_max_num_of_table = dvfs_domain->num_of_level;
		mld->total_freq_table_count++;

		if (mld->mif_table.use_dfs_max_freq) {
			mif_info("use dfs max freq\n");
			mif_max_freq = cal_dfs_get_max_freq(mld->mif_table.cal_id_mif);

			for (i = 0; i < mif_max_num_of_table; i++) {
				if (dvfs_domain->list_level[i].level == mif_max_freq) {
					mif_max_num_of_table = mif_max_num_of_table - i;
					counter = i;
					break;
				}

				mld->mif_table.freq[mif_max_num_of_table - 1 - i] = mif_max_freq;
				mif_info("MIF_LEV[%d] : %u\n",
					mif_max_num_of_table - i, mif_max_freq);
			}
		}

		for (i = mif_max_num_of_table - 1; i >= 0; i--) {
			mld->mif_table.freq[i] =
				dvfs_domain->list_level[counter++].level;
			mif_info("MIF_LEV[%d] : %u\n", i + 1,
					mld->mif_table.freq[i]);
		}
	} else if (!strcmp(dvfs_domain_name, "CP_CPU")) {
		mld->cp_cpu_table.num_of_table = dvfs_domain->num_of_level;
		mld->total_freq_table_count++;
		for (i = dvfs_domain->num_of_level - 1; i >= 0; i--) {
			mld->cp_cpu_table.freq[i] =
				dvfs_domain->list_level[counter++].level;
			mif_info("CP_CPU_LEV[%d] : %u\n", i + 1,
					mld->cp_cpu_table.freq[i]);
		}
	} else if (!strcmp(dvfs_domain_name, "CP")) {
		mld->cp_table.num_of_table = dvfs_domain->num_of_level;
		mld->total_freq_table_count++;
		for (i = dvfs_domain->num_of_level - 1; i >= 0; i--) {
			mld->cp_table.freq[i] =
				dvfs_domain->list_level[counter++].level;
			mif_info("CP_LEV[%d] : %u\n", i + 1,
					mld->cp_table.freq[i]);
		}
	} else if (!strcmp(dvfs_domain_name, "CP_EM")) {
		mld->cp_em_table.num_of_table = dvfs_domain->num_of_level;
		mld->total_freq_table_count++;
		for (i = dvfs_domain->num_of_level - 1; i >= 0; i--) {
			mld->cp_em_table.freq[i] =
				dvfs_domain->list_level[counter++].level;
			mif_info("CP_LEV[%d] : %u\n", i + 1,
					mld->cp_em_table.freq[i]);
		}
	} else if (!strcmp(dvfs_domain_name, "CP_MCW")) {
		mld->cp_mcw_table.num_of_table = dvfs_domain->num_of_level;
		mld->total_freq_table_count++;
		for (i = dvfs_domain->num_of_level - 1; i >= 0; i--) {
			mld->cp_mcw_table.freq[i] =
				dvfs_domain->list_level[counter++].level;
			mif_info("CP_LEV[%d] : %u\n", i + 1,
					mld->cp_mcw_table.freq[i]);
		}
	}

	return 0;
}
#else
static int parse_ect(struct mem_link_device *mld, char *dvfs_domain_name)
{
	mif_err("ECT is not defined(%s)\n", __func__);

	mld->mif_table.num_of_table = 0;
	mld->cp_cpu_table.num_of_table = 0;
	mld->cp_table.num_of_table = 0;
	mld->cp_em_table.num_of_table = 0;
	mld->cp_mcw_table.num_of_table = 0;

	return 0;
}
#endif

static int shmem_rx_setup(struct link_device *ld)
{
	ld->rx_wq = alloc_workqueue(
			"mem_rx_work", WQ_HIGHPRI | WQ_CPU_INTENSIVE, 1);
	if (!ld->rx_wq) {
		mif_err("%s: ERR! fail to create rx_wq\n", ld->name);
		return -ENOMEM;
	}

	return 0;
}

/* sysfs */
static ssize_t tx_period_ms_show(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	struct modem_data *modem;

	modem = (struct modem_data *)dev->platform_data;
	return scnprintf(buf, PAGE_SIZE, "%d\n", modem->mld->tx_period_ms);
}

static ssize_t tx_period_ms_store(struct device *dev,
		struct device_attribute *attr,
		const char *buf, size_t count)
{
	int ret;
	struct modem_data *modem;

	modem = (struct modem_data *)dev->platform_data;

	ret = kstrtouint(buf, 0, &modem->mld->tx_period_ms);
	if (ret)
		return -EINVAL;

	ret = count;
	return ret;
}

static ssize_t info_region_show(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	struct modem_data *modem;
	struct mem_link_device *mld;
	ssize_t count = 0;

	modem = (struct modem_data *)dev->platform_data;
	mld = modem->mld;

	if (modem->offset_ap_version)
		count += scnprintf(&buf[count], PAGE_SIZE - count, "ap_version:0x%08X\n",
			ioread32(mld->ap_version));

	if (modem->offset_cp_version)
		count += scnprintf(&buf[count], PAGE_SIZE - count, "cp_version:0x%08X\n",
			ioread32(mld->cp_version));

	if (modem->offset_cmsg_offset)
		count += scnprintf(&buf[count], PAGE_SIZE - count, "cmsg_offset:0x%08X\n",
			ioread32(mld->cmsg_offset));

	if (modem->offset_srinfo_offset)
		count += scnprintf(&buf[count], PAGE_SIZE - count, "srinfo_offset:0x%08X\n",
			ioread32(mld->srinfo_offset));

	if (modem->offset_clk_table_offset)
		count += scnprintf(&buf[count], PAGE_SIZE - count, "clk_table_offset:0x%08X\n",
			ioread32(mld->clk_table_offset));

	if (modem->offset_buff_desc_offset)
		count += scnprintf(&buf[count], PAGE_SIZE - count, "buff_desc_offset:0x%08X\n",
			ioread32(mld->buff_desc_offset));

	if (modem->offset_capability_offset) {
		int part;

		count += scnprintf(&buf[count], PAGE_SIZE - count,
				"capability_offset:0x%08X\n",
				ioread32(mld->capability_offset));

		for (part = 0; part < AP_CP_CAP_PARTS; part++) {
			count += scnprintf(&buf[count], PAGE_SIZE - count,
					"ap_capability_offset[%d]:0x%08X\n", part,
					ioread32(mld->ap_capability_offset[part]));
			count += scnprintf(&buf[count], PAGE_SIZE - count,
					"cp_capability_offset[%d]:0x%08X\n", part,
					ioread32(mld->cp_capability_offset[part]));
		}
	}

	count += scnprintf(&buf[count], PAGE_SIZE - count, "ap2cp_msg:0x%08X\n",
		get_ctrl_msg(&mld->ap2cp_msg));
	count += scnprintf(&buf[count], PAGE_SIZE - count, "cp2ap_msg:0x%08X\n",
		get_ctrl_msg(&mld->cp2ap_msg));
	count += scnprintf(&buf[count], PAGE_SIZE - count, "ap2cp_united_status:0x%08X\n",
		get_ctrl_msg(&mld->ap2cp_united_status));
	count += scnprintf(&buf[count], PAGE_SIZE - count, "cp2ap_united_status:0x%08X\n",
		get_ctrl_msg(&mld->cp2ap_united_status));
#if IS_ENABLED(CONFIG_CP_BTL)
	count += scnprintf(&buf[count], PAGE_SIZE - count, "ap2cp_btl_size:0x%08X\n",
		get_ctrl_msg(&mld->ap2cp_btl_size));
#endif
	count += scnprintf(&buf[count], PAGE_SIZE - count, "ap2cp_kerneltime:0x%08X\n",
		get_ctrl_msg(&mld->ap2cp_kerneltime));
	count += scnprintf(&buf[count], PAGE_SIZE - count, "ap2cp_kerneltime_sec:0x%08X\n",
		get_ctrl_msg(&mld->ap2cp_kerneltime_sec));
	count += scnprintf(&buf[count], PAGE_SIZE - count, "ap2cp_kerneltime_usec:0x%08X\n",
		get_ctrl_msg(&mld->ap2cp_kerneltime_usec));

	return count;
}

#if IS_ENABLED(CONFIG_CP_LLC)
static ssize_t cp_llc_status_store(struct device *dev, struct device_attribute *attr, const char *buf, size_t count)
{
	unsigned int target;
	int alloc;
	int way;
	int ret;

	ret = sscanf(buf, "%u %d %d", &target, &alloc, &way);
	if (ret < 1) {
		mif_err("invalid input values. ret:%d\n", ret);
		return -EINVAL;
	}

	if (target >= LLC_CP_MAX) {
		mif_err("target should be in range. input:%u\n", target);
		return -EINVAL;
	}

	ret = alloc_llc_to_cp(target, alloc, way);

	mif_info("alloc_llc_to_cp() %s: alloc:%u way:%u\n",
		ret >= 0 ? "success" : "fail", alloc, way);

	return count;
}

static ssize_t cp_llc_status_show(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	ssize_t count = 0;

	count += scnprintf(&buf[count], PAGE_SIZE - count, "LLC_CP_CPU: Allocated %d way %d\n",
			cp_llc_arr[LLC_CP_CPU][LLC_ALLOC], cp_llc_arr[LLC_CP_CPU][LLC_WAY]);
	count += scnprintf(&buf[count], PAGE_SIZE - count, "LLC_CP_MAXTP: Allocated %d way %d\n",
			cp_llc_arr[LLC_CP_MAXTP][LLC_ALLOC], cp_llc_arr[LLC_CP_MAXTP][LLC_WAY]);
	count += scnprintf(&buf[count], PAGE_SIZE - count, "LLC_CP_PKTPROC: Allocated %d way %d\n",
			cp_llc_arr[LLC_CP_PKTPROC][LLC_ALLOC], cp_llc_arr[LLC_CP_PKTPROC][LLC_WAY]);

	return count;
}
#endif /* end of CONFIG_CP_LLC */

static DEVICE_ATTR_RW(tx_period_ms);
static DEVICE_ATTR_RO(info_region);
#if IS_ENABLED(CONFIG_CP_LLC)
static DEVICE_ATTR_RW(cp_llc_status);
#endif

static struct attribute *link_device_attrs[] = {
	&dev_attr_tx_period_ms.attr,
	&dev_attr_info_region.attr,
#if IS_ENABLED(CONFIG_CP_LLC)
	&dev_attr_cp_llc_status.attr,
#endif
	NULL,
};

static const struct attribute_group link_device_group = {
	.attrs = link_device_attrs,
};

/* sysfs for napi */
static ssize_t rx_napi_list_show(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	struct modem_data *modem;
	struct napi_struct *n;
	struct net_device *netdev;
	ssize_t count = 0;

	modem = (struct modem_data *)dev->platform_data;
	netdev = &modem->mld->dummy_net;

	count += scnprintf(&buf[count], PAGE_SIZE - count, "[%s's napi_list]\n",
		netdev_name(netdev));
	list_for_each_entry(n, &netdev->napi_list, dev_list)
		count += scnprintf(&buf[count], PAGE_SIZE - count,
			"state: %s(%ld), weight: %d, poll: 0x%pK\n",
			test_bit(NAPI_STATE_SCHED, &n->state) ?
			"NAPI_STATE_SCHED" : "NAPI_STATE_COMPLETE",
			n->state, n->weight, (void *)n->poll);

	return count;
}

static ssize_t rx_int_enable_show(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	struct modem_data *modem;

	modem = (struct modem_data *)dev->platform_data;
	return scnprintf(buf, PAGE_SIZE, "%d\n", modem->mld->rx_int_enable);
}

static ssize_t rx_int_count_show(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	struct modem_data *modem;

	modem = (struct modem_data *)dev->platform_data;
	return scnprintf(buf, PAGE_SIZE, "%d\n", modem->mld->rx_int_count);
}

static ssize_t rx_int_count_store(struct device *dev,
		struct device_attribute *attr,
		const char *buf, size_t count)
{
	struct modem_data *modem;
	unsigned int val = 0;
	int ret;

	modem = (struct modem_data *)dev->platform_data;
	ret = kstrtouint(buf, 0, &val);

	if (val == 0)
		modem->mld->rx_int_count = 0;
	return count;
}

static ssize_t rx_poll_count_show(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	struct modem_data *modem;
	struct mem_link_device *mld;

	modem = (struct modem_data *)dev->platform_data;
	mld = modem->mld;

	return scnprintf(buf, PAGE_SIZE, "%s: %d\n", netdev_name(&mld->dummy_net),
		mld->rx_poll_count);
}

static ssize_t rx_poll_count_store(struct device *dev,
		struct device_attribute *attr,
		const char *buf, size_t count)
{
	struct modem_data *modem;
	struct mem_link_device *mld;

	modem = (struct modem_data *)dev->platform_data;
	mld = modem->mld;

	mld->rx_poll_count = 0;
	return count;
}

static ssize_t rx_int_disabled_time_show(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	struct modem_data *modem;

	modem = (struct modem_data *)dev->platform_data;
	return scnprintf(buf, PAGE_SIZE, "%lld\n", modem->mld->rx_int_disabled_time);
}

static ssize_t rx_int_disabled_time_store(struct device *dev,
		struct device_attribute *attr,
		const char *buf, size_t count)
{
	struct modem_data *modem;
	unsigned int val = 0;
	int ret;

	modem = (struct modem_data *)dev->platform_data;
	ret = kstrtouint(buf, 0, &val);

	if (val == 0)
		modem->mld->rx_int_disabled_time = 0;
	return count;
}

static DEVICE_ATTR_RO(rx_napi_list);
static DEVICE_ATTR_RO(rx_int_enable);
static DEVICE_ATTR_RW(rx_int_count);
static DEVICE_ATTR_RW(rx_poll_count);
static DEVICE_ATTR_RW(rx_int_disabled_time);

static struct attribute *napi_attrs[] = {
	&dev_attr_rx_napi_list.attr,
	&dev_attr_rx_int_enable.attr,
	&dev_attr_rx_int_count.attr,
	&dev_attr_rx_poll_count.attr,
	&dev_attr_rx_int_disabled_time.attr,
	NULL,
};

static const struct attribute_group napi_group = {
	.attrs = napi_attrs,
	.name = "napi",
};

#if IS_ENABLED(CONFIG_LINK_DEVICE_WITH_SBD_ARCH)
#if IS_ENABLED(CONFIG_CP_PKTPROC)
static u32 p_pktproc[3];
static u32 c_pktproc[3];

static void pktproc_print(struct mem_link_device *mld)
{
	struct pktproc_adaptor *ppa = &mld->pktproc;
	int i;
	struct pktproc_queue *q;

	for (i = 0; i < ppa->num_queue; i++) {
		q = ppa->q[i];

		c_pktproc[0] = *q->fore_ptr;
		c_pktproc[1] = *q->rear_ptr;
		c_pktproc[2] = q->done_ptr;

		if (memcmp(p_pktproc, c_pktproc, sizeof(u32)*3)) {
			mif_err("Queue:%d fore:%d rear:%d done:%d\n",
				i, c_pktproc[0], c_pktproc[1], c_pktproc[2]);
			memcpy(p_pktproc, c_pktproc, sizeof(u32)*3);
		}
	}
}
#endif

#define BUFF_SIZE 256
static u32 p_rwpointer[4];
static u32 c_rwpointer[4];

static enum hrtimer_restart sbd_print(struct hrtimer *timer)
{
	struct mem_link_device *mld = container_of(timer, struct mem_link_device, sbd_print_timer);
	struct sbd_link_device *sl = &mld->sbd_link_dev;
	u16 id;
	struct sbd_ring_buffer *rb[ULDL];
	struct io_device *iod;
	char buf[BUFF_SIZE] = { 0, };
	int len = 0;
	unsigned long flags;

#if IS_ENABLED(CONFIG_CP_PKTPROC)
	pktproc_print(mld);
#endif

	if (likely(sbd_active(sl))) {
		id = sbd_ch2id(sl, QOS_HIPRIO);
		rb[TX] = &sl->ipc_dev[id].rb[TX];
		rb[RX] = &sl->ipc_dev[id].rb[RX];

		c_rwpointer[0] = *(u32 *)rb[TX]->rp;
		c_rwpointer[1] = *(u32 *)rb[TX]->wp;
		c_rwpointer[2] = *(u32 *)rb[RX]->rp;
		c_rwpointer[3] = *(u32 *)rb[RX]->wp;

		if (memcmp(p_rwpointer, c_rwpointer, sizeof(u32)*4)) {
			mif_err("TX %04d/%04d %04d/%04d RX %04d/%04d %04d/%04d\n",
				c_rwpointer[0] & 0xFFFF, c_rwpointer[1] & 0xFFFF,
				c_rwpointer[0] >> 16, c_rwpointer[1] >> 16,
				c_rwpointer[2] & 0xFFFF, c_rwpointer[3] & 0xFFFF,
				c_rwpointer[2] >> 16, c_rwpointer[3] >> 16);
			memcpy(p_rwpointer, c_rwpointer, sizeof(u32)*4);

			spin_lock_irqsave(&rb[TX]->iod->msd->active_list_lock, flags);
			list_for_each_entry(iod, &rb[TX]->iod->msd->activated_ndev_list,
					    node_ndev) {
				len += snprintf(buf + len, BUFF_SIZE - len, "%s: %lu/%lu ",
						iod->name, iod->ndev->stats.tx_packets,
						iod->ndev->stats.rx_packets);
			}
			spin_unlock_irqrestore(&rb[TX]->iod->msd->active_list_lock, flags);

			mif_err("%s\n", buf);
		}
	}

	hrtimer_forward_now(timer, ms_to_ktime(1000));

	return HRTIMER_RESTART;
}
#endif

static int set_protocol_attr(struct link_device *ld)
{
	switch (ld->protocol) {
	case PROTOCOL_SIPC:
		ld->magic_boot = MEM_BOOT_MAGIC;
		ld->magic_crash = MEM_CRASH_MAGIC;
		ld->magic_dump = MEM_DUMP_MAGIC;
		ld->magic_ipc = MEM_IPC_MAGIC;
		ld->magic_minidump = MEM_MINIDUMP_MAGIC;

		ld->is_start_valid = sipc5_start_valid;
		ld->is_padding_exist = sipc5_padding_exist;
		ld->is_multi_frame = sipc5_multi_frame;
		ld->has_ext_len = sipc5_ext_len;
		ld->get_ch = sipc5_get_ch;
		ld->get_ctrl = sipc5_get_ctrl;
		ld->calc_padding_size = sipc5_calc_padding_size;
		ld->get_hdr_len = sipc5_get_hdr_len;
		ld->get_frame_len = sipc5_get_frame_len;
		ld->get_total_len = sipc5_get_total_len;
		ld->is_csd_ch = sipc_csd_ch;
		ld->is_log_ch = sipc_log_ch;
		ld->is_router_ch = sipc_router_ch;
		ld->is_misc_ch = sipc_misc_ch;
		break;
	case PROTOCOL_SIT:
		ld->magic_boot = SHM_BOOT_MAGIC;
		ld->magic_crash = SHM_DUMP_MAGIC;
		ld->magic_dump = SHM_DUMP_MAGIC;
		ld->magic_ipc = SHM_IPC_MAGIC;
		ld->magic_minidump = SHM_MINIDUMP_MAGIC;

		ld->is_start_valid = exynos_start_valid;
		ld->is_padding_exist = exynos_padding_exist;
		ld->is_multi_frame = exynos_multi_frame;
		ld->has_ext_len = exynos_ext_len;
		ld->get_ch = exynos_get_ch;
		ld->get_ctrl = exynos_get_ctrl;
		ld->calc_padding_size = exynos_calc_padding_size;
		ld->get_hdr_len = exynos_get_hdr_len;
		ld->get_frame_len = exynos_get_frame_len;
		ld->get_total_len = exynos_get_total_len;
		ld->is_csd_ch = exynos_rcs_ch;
		ld->is_log_ch = exynos_log_ch;
		ld->is_router_ch = exynos_router_ch;
		break;
	default:
		mif_err("protocol error %d\n", ld->protocol);
		return -EINVAL;
	}

	return 0;
}

static int set_ld_attr(struct platform_device *pdev,
	u32 link_type, struct modem_data *modem,
	struct mem_link_device *mld, struct link_device *ld)
{
	int err = 0;

	ld->name = modem->link_name;

	if (mld->attrs & LINK_ATTR_SBD_IPC) {
		mif_info("%s<->%s: LINK_ATTR_SBD_IPC\n", ld->name, modem->name);
		ld->sbd_ipc = true;
	}

	if (mld->attrs & LINK_ATTR_IPC_ALIGNED) {
		mif_info("%s<->%s: LINK_ATTR_IPC_ALIGNED\n",
			ld->name, modem->name);
		ld->aligned = true;
	}

	ld->interrupt_types = modem->interrupt_types;

	ld->mdm_data = modem;

	ld->dev = &pdev->dev;

	/*
	 * Set up link device methods
	 */
	ld->ioctl = shmem_ioctl;

	ld->init_comm = shmem_init_comm;
	ld->terminate_comm = NULL;
	ld->send = shmem_send;

	ld->link_prepare_normal_boot = link_prepare_normal_boot;
	ld->link_trigger_cp_crash = link_trigger_cp_crash;

	do {
		if (!(mld->attrs & LINK_ATTR_MEM_BOOT))
			break;

		ld->link_start_normal_boot = link_start_normal_boot;
		if (link_type == LINKDEV_SHMEM)
			ld->security_req = shmem_security_request;

		if (!(mld->attrs & LINK_ATTR_XMIT_BTDLR))
			break;

		ld->load_cp_image = link_load_cp_image;
		if (mld->attrs & LINK_ATTR_XMIT_BTDLR_SPI) {
			ld->load_cp_image = cpboot_spi_load_cp_image;

			mld->spi_bus_num = -1;
			mif_dt_read_u32_noerr(pdev->dev.of_node, "cpboot_spi_bus_num",
					      mld->spi_bus_num);
			if (mld->spi_bus_num < 0) {
				mif_err("cpboot_spi_bus_num error\n");
				err = -ENODEV;
				goto error;
			}
		}

		if (mld->attrs & LINK_ATTR_XMIT_BTDLR_GNSS) {
			ld->load_gnss_image = link_load_gnss_image;
			ld->read_gnss_image = link_read_gnss_image;
		}
	} while (0);

	if (mld->attrs & LINK_ATTR_MEM_DUMP)
		ld->link_start_dump_boot = link_start_dump_boot;

	ld->close_tx = shmem_close_tx;
	ld->get_cp_crash_reason = get_cp_crash_reason;

#if IS_ENABLED(CONFIG_CLO)
	ld->gro_flush = gro_flush_timer;
	ld->update_flush_time = update_flush_time;
#endif

	ld->protocol = modem->protocol;
	ld->capability_check = modem->capability_check;

	err = set_protocol_attr(ld);
	if (err)
		goto error;

	ld->start_timers = shmem_start_timers;
	ld->stop_timers = shmem_stop_timers;

	return 0;

error:
	mif_err("xxx\n");
	return err;
}

static int init_shmem_maps(u32 link_type, struct modem_data *modem,
	struct mem_link_device *mld, struct link_device *ld)
{
	int err = 0;

#if IS_ENABLED(CONFIG_LINK_DEVICE_SHMEM)
	if (link_type == LINKDEV_SHMEM) {
		mld->boot_size = cp_shmem_get_size(SHMEM_CP) +
			cp_shmem_get_size(SHMEM_VSS);
		mld->boot_base = NULL;
		mif_info("boot_base=NULL, boot_size=%lu\n",
			(unsigned long)mld->boot_size);
	}
#endif

	/*
	 * Initialize SHMEM maps for IPC (physical map -> logical map)
	 */
	mld->size = cp_shmem_get_size(SHMEM_IPC);
	if (modem->legacy_raw_rx_buffer_cached)
		mld->base = cp_shmem_get_nc_region(cp_shmem_get_base(SHMEM_IPC),
			modem->legacy_raw_buffer_offset + modem->legacy_raw_txq_size);
	else
		mld->base = cp_shmem_get_region(SHMEM_IPC);

#if IS_ENABLED(CONFIG_MODEM_IF_LEGACY_QOS)
	mld->hiprio_base = cp_shmem_get_nc_region(cp_shmem_get_base(SHMEM_IPC)
			+ modem->legacy_raw_qos_buffer_offset, modem->legacy_raw_qos_txq_size
			+ modem->legacy_raw_qos_rxq_size);
#endif
	if (!mld->base) {
		mif_err("Failed to vmap ipc_region\n");
		err = -ENOMEM;
		goto error;
	}
	mif_info("ipc_base=%pK, ipc_size=%lu\n",
		mld->base, (unsigned long)mld->size);

#if IS_ENABLED(CONFIG_LINK_DEVICE_SHMEM)
	if (link_type == LINKDEV_SHMEM) {
		struct device_node *np_acpm;

		/*
		 * Initialize SHMEM maps for VSS (physical map -> logical map)
		 */
		mld->vss_base = cp_shmem_get_region(SHMEM_VSS);
		if (!mld->vss_base) {
			mif_err("Failed to vmap vss_region\n");
			err = -ENOMEM;
			goto error;
		}
		mif_info("vss_base=%pK\n", mld->vss_base);

		/*
		 * Initialize memory maps for ACPM (physical map -> logical map)
		 * This addr is an optional and for dump only.
		 */
		np_acpm = of_find_node_by_name(NULL, "acpm_ipc");
		if (np_acpm) {
			u32 acpm_addr;

			mif_dt_read_u32(np_acpm, "dump-base", acpm_addr);
			mif_dt_read_u32(np_acpm, "dump-size", mld->acpm_size);
			mld->acpm_base = devm_ioremap(ld->dev, acpm_addr, mld->acpm_size);
			if (!mld->acpm_base) {
				mif_err("Failed to devm_ioremap acpm_region\n");
				err = -ENOMEM;
				goto error;
			}
			mif_info("acpm_base=%pK acpm_size:0x%X\n", mld->acpm_base, mld->acpm_size);
		} else {
			int i;

			mld->esca_num_dump = get_esca_phy_num();
			mif_info("esca_num_dump:%d\n", mld->esca_num_dump);

			mld->esca_dump_addrs = kzalloc(sizeof(void __iomem *) *
				mld->esca_num_dump, GFP_KERNEL);
			if (!mld->esca_dump_addrs) {
				mif_err("esca_dump_addrs kzalloc fail\n");
				err = -ENOMEM;
				goto error;
			}
			mld->esca_dump_sizes = kzalloc(sizeof(unsigned int) *
				mld->esca_num_dump, GFP_KERNEL);
			if (!mld->esca_dump_sizes) {
				mif_err("esca_dump_sizes kzalloc fail\n");
				err = -ENOMEM;
				goto error;
			}

			for (i = 0; i < mld->esca_num_dump; i++) {
				mld->esca_dump_addrs[i] = get_esca_dump_addr(i);
				mld->esca_dump_sizes[i] = get_esca_dump_size(i);
				mif_info("esca num:%d addr:%llx size:%d\n",
					i, (u64)mld->esca_dump_addrs[i], mld->esca_dump_sizes[i]);
			}
		}
	}
#endif

	ld->link_type = link_type;
	create_legacy_link_device(mld);

#if IS_ENABLED(CONFIG_LINK_DEVICE_WITH_SBD_ARCH)
	if (ld->sbd_ipc) {
		hrtimer_init(&mld->sbd_tx_timer,
				CLOCK_MONOTONIC, HRTIMER_MODE_REL);
		mld->sbd_tx_timer.function = sbd_tx_timer_func;

		hrtimer_init(&mld->sbd_print_timer,
				CLOCK_MONOTONIC, HRTIMER_MODE_REL);
		mld->sbd_print_timer.function = sbd_print;

		err = create_sbd_link_device(ld,
				&mld->sbd_link_dev, mld->base, mld->size);
		if (err < 0)
			goto error;
	}
#endif

	return 0;

error:
	mif_err("xxx\n");
	return err;
}

static int init_info_region(struct modem_data *modem,
	struct mem_link_device *mld, struct link_device *ld)
{
	u8 __iomem *cmsg_base;
	int part;

	if (modem->offset_ap_version)
		mld->ap_version = (u32 __iomem *)(mld->base + modem->offset_ap_version);
	if (modem->offset_cp_version)
		mld->cp_version = (u32 __iomem *)(mld->base + modem->offset_cp_version);
	if (modem->offset_cmsg_offset) {
		mld->cmsg_offset = (u32 __iomem *)(mld->base + modem->offset_cmsg_offset);
		cmsg_base = mld->base + modem->cmsg_offset;
		iowrite32(modem->cmsg_offset, mld->cmsg_offset);
	} else {
		cmsg_base = mld->base;
	}

	if (modem->offset_srinfo_offset) {
		mld->srinfo_offset = (u32 __iomem *)(mld->base + modem->offset_srinfo_offset);
		iowrite32(modem->srinfo_offset, mld->srinfo_offset);
	}
	if (modem->offset_clk_table_offset) {
		mld->clk_table_offset = (u32 __iomem *)(mld->base + modem->offset_clk_table_offset);
		iowrite32(modem->clk_table_offset, mld->clk_table_offset);
	}
	if (modem->offset_buff_desc_offset) {
		mld->buff_desc_offset = (u32 __iomem *)(mld->base + modem->offset_buff_desc_offset);
		iowrite32(modem->buff_desc_offset, mld->buff_desc_offset);
	}

	mld->srinfo_base = (u32 __iomem *)(mld->base + modem->srinfo_offset);
	mld->srinfo_size = modem->srinfo_size;
	mld->clk_table = (u32 __iomem *)(mld->base + modem->clk_table_offset);

	if (ld->capability_check) {
		u8 __iomem *offset;

		/* AP/CP capability */
		offset = mld->base + modem->offset_capability_offset;
		mld->capability_offset = (u32 __iomem *)(offset);
		iowrite32(modem->capability_offset, mld->capability_offset);

		offset = mld->base + modem->capability_offset;
		for (part = 0; part < AP_CP_CAP_PARTS; part++) {
			mld->ap_capability_offset[part] =
				(u32 __iomem *)(offset + (AP_CP_CAP_PART_LEN * 2 * part));
			mld->cp_capability_offset[part] =
				(u32 __iomem *)(offset + (AP_CP_CAP_PART_LEN * 2 * part) +
				AP_CP_CAP_PART_LEN);

			/* Initial values */
			iowrite32(0, mld->ap_capability_offset[part]);
			iowrite32(0, mld->cp_capability_offset[part]);
		}
	}

	construct_ctrl_msg(&mld->cp2ap_msg, modem->cp2ap_msg, cmsg_base);
	construct_ctrl_msg(&mld->ap2cp_msg, modem->ap2cp_msg, cmsg_base);
	construct_ctrl_msg(&mld->cp2ap_united_status, modem->cp2ap_united_status, cmsg_base);
	construct_ctrl_msg(&mld->ap2cp_united_status, modem->ap2cp_united_status, cmsg_base);
#if IS_ENABLED(CONFIG_CP_LLC)
	construct_ctrl_msg(&mld->cp2ap_llc_status, modem->cp2ap_llc_status, cmsg_base);
	construct_ctrl_msg(&mld->ap2cp_llc_status, modem->ap2cp_llc_status, cmsg_base);
#endif
#if IS_ENABLED(CONFIG_CP_BTL)
	construct_ctrl_msg(&mld->ap2cp_btl_size, modem->ap2cp_btl_size, cmsg_base);
#endif
	construct_ctrl_msg(&mld->ap2cp_kerneltime, modem->ap2cp_kerneltime, cmsg_base);
	construct_ctrl_msg(&mld->ap2cp_kerneltime_sec, modem->ap2cp_kerneltime_sec, cmsg_base);
	construct_ctrl_msg(&mld->ap2cp_kerneltime_usec, modem->ap2cp_kerneltime_usec, cmsg_base);

	for (part = 0; part < AP_CP_CAP_PARTS; part++)
		mld->ap_capability[part] = modem->ap_capability[part];

	return 0;
}

#if IS_ENABLED(CONFIG_MCU_IPC)
static int register_irq_handler(struct modem_data *modem,
	struct mem_link_device *mld, struct link_device *ld)
{
	unsigned int irq_num;
	int err;

	if (ld->interrupt_types != INTERRUPT_MAILBOX) {
		err = -EPERM;
		goto error;
	}

	irq_num = mld->irq_cp2ap_msg;
	err = cp_mbox_register_handler(CP_MBOX_IRQ_IDX_0, irq_num,
				       shmem_irq_handler, mld);
	if (err)
		goto irq_error;

	/**
	 * Retrieve SHMEM MBOX# and IRQ# for wakelock
	 */
	mld->ws = cpif_wake_lock_register(ld->dev, ld->name);
	if (mld->ws == NULL) {
		mif_err("%s: wakeup_source_register fail\n", ld->name);
		err = -EINVAL;
		goto error;
	}

	irq_num = mld->irq_cp2ap_wakelock;
	err = cp_mbox_register_handler(CP_MBOX_IRQ_IDX_0, irq_num,
				       shmem_cp2ap_wakelock_handler, mld);
	if (err)
		goto irq_error;

	/**
	 * Retrieve SHMEM MBOX# and IRQ# for RAT_MODE
	 */
#if IS_ENABLED(CONFIG_LINK_DEVICE_PCIE)
	irq_num = mld->irq_cp2ap_rat_mode;
	err = cp_mbox_register_handler(CP_MBOX_IRQ_IDX_0, irq_num,
				       shmem_cp2ap_rat_mode_handler, mld);
	if (err)
		goto irq_error;
#endif

#if IS_ENABLED(CONFIG_CP_LLC)
	irq_num = mld->irq_cp2ap_llc_status;
	err = cp_mbox_register_handler(CP_MBOX_IRQ_IDX_0, irq_num,
				       shmem_cp2ap_llc_handler, mld);
	if (err)
		goto irq_error;
#endif

	irq_num = mld->irq_cp2ap_status;
	err = cp_mbox_register_handler(CP_MBOX_IRQ_IDX_0, irq_num,
				       shmem_tx_state_handler, mld);
	if (err)
		goto irq_error;

	return 0;

irq_error:
	mif_err("%s: ERR! cp_mbox_register_handler(MBOX_IRQ_IDX_0, %u) fail (%d)\n",
		ld->name, irq_num, err);

error:
	mif_err("xxx\n");

	return err;
}
#endif

static int parse_ect_tables(struct platform_device *pdev,
	struct mem_link_device *mld)
{
	int err = 0;

	err = of_property_read_u32(pdev->dev.of_node,
		"devfreq_use_dfs_max_freq", &mld->mif_table.use_dfs_max_freq);
	if (err) {
		mif_err("devfreq_use_dfs_max_freq error:%d\n", err);
		return err;
	}

	if (mld->mif_table.use_dfs_max_freq) {
		err = of_property_read_u32(pdev->dev.of_node,
			"devfreq_cal_id_mif", &mld->mif_table.cal_id_mif);
		if (err) {
			mif_err("devfreq_cal_id_mif error:%d\n", err);
			return err;
		}
	}

	/* Parsing devfreq, cpufreq table from ECT */
	mif_info("Parsing MIF frequency table...\n");
	err = parse_ect(mld, "MIF");
	if (err < 0)
		mif_err("Can't get MIF frequency table!!!!!\n");

	mif_info("Parsing CP_CPU frequency table...\n");
	err = parse_ect(mld, "CP_CPU");
	if (err < 0)
		mif_err("Can't get CP_CPU frequency table!!!!!\n");

	mif_info("Parsing CP frequency table...\n");
	err = parse_ect(mld, "CP");
	if (err < 0)
		mif_err("Can't get CP frequency table!!!!!\n");

	mif_info("Parsing CP_EM frequency table...\n");
	err = parse_ect(mld, "CP_EM");
	if (err < 0)
		mif_err("Can't get CP_EM frequency table!!!!!\n");

	mif_info("Parsing CP_MCW frequency table...\n");
	err = parse_ect(mld, "CP_MCW");
	if (err < 0)
		mif_err("Can't get CP_MCW frequency table!!!!!\n");

	return 0;
}

struct link_device *create_link_device(struct platform_device *pdev, u32 link_type)
{
	struct modem_data *modem;
	struct mem_link_device *mld;
	struct link_device *ld;
	int err;

	mif_info("+++\n");

	/**
	 * Get the modem (platform) data
	 */
	modem = (struct modem_data *)pdev->dev.platform_data;
	if (!modem) {
		mif_err("ERR! modem == NULL\n");
		return NULL;
	}

	if (!modem->mbx) {
		mif_err("%s: ERR! mbx == NULL\n", modem->link_name);
		return NULL;
	}

	mif_info("MODEM:%s LINK:%s\n", modem->name, modem->link_name);

	/*
	 * Alloc an instance of mem_link_device structure
	 */
	mld = kzalloc(sizeof(struct mem_link_device), GFP_KERNEL);
	if (!mld) {
		mif_err("%s<->%s: ERR! mld kzalloc fail\n",
			modem->link_name, modem->name);
		return NULL;
	}

	/*
	 * Retrieve modem-specific attributes value
	 */
	mld->attrs = modem->link_attrs;
	mif_info("link_attrs:0x%08lx\n", mld->attrs);

	/*====================================================================
	 *	Initialize "memory snapshot buffer (MSB)" framework
	 *====================================================================
	 */
	if (msb_init() < 0) {
		mif_err("%s<->%s: ERR! msb_init() fail\n",
			modem->link_name, modem->name);
		goto error;
	}

	/*====================================================================
	 *	Set attributes as a "link_device"
	 *====================================================================
	 */
	ld = &mld->link_dev;
	err = set_ld_attr(pdev, link_type, modem, mld, ld);
	if (err)
		goto error;

	init_dummy_netdev(&mld->dummy_net);
	netif_napi_add(&mld->dummy_net, &mld->mld_napi, mld_rx_int_poll);
	napi_enable(&mld->mld_napi);
	atomic_set(&mld->stop_napi_poll, 0);

	INIT_LIST_HEAD(&ld->list);

	spin_lock_init(&ld->netif_lock);
	atomic_set(&ld->netif_stopped, 0);
	ld->tx_flowctrl_mask = 0;
	ld->dup_count_suspend = 0;
	ld->dup_count_resume = 0;

	if (shmem_rx_setup(ld) < 0)
		goto error;

	if (mld->attrs & LINK_ATTR_DPRAM_MAGIC) {
		mif_info("%s<->%s: LINK_ATTR_DPRAM_MAGIC\n",
			ld->name, modem->name);
		mld->dpram_magic = true;
	}

	mld->cmd_handler = shmem_cmd_handler;

	spin_lock_init(&mld->state_lock);
	mutex_init(&mld->vmap_lock);

	mld->state = LINK_STATE_OFFLINE;

	/*
	 * Initialize variables for TX & RX
	 */
	msb_queue_head_init(&mld->msb_rxq);
	msb_queue_head_init(&mld->msb_log);

	hrtimer_init(&mld->tx_timer, CLOCK_MONOTONIC, HRTIMER_MODE_REL);
	mld->tx_timer.function = tx_timer_func;

	INIT_WORK(&mld->page_reclaim_work, bootdump_oom_handler_work);

	/*
	 * Initialize variables for CP booting and crash dump
	 */
	INIT_DELAYED_WORK(&mld->bootdump_rx_dwork, bootdump_rx_work);

	/*
	 * Link local functions to the corresponding function pointers that are
	 * mandatory for all memory-type link devices
	 */
#if IS_ENABLED(CONFIG_LINK_DEVICE_PCIE)
	if (link_type == LINKDEV_PCIE) {
		mld->recv_cp2ap_irq = pcie_recv_cp2ap_irq;
		mld->send_ap2cp_irq = pcie_send_ap2cp_irq;
		mld->recv_cp2ap_status = pcie_recv_cp2ap_status;
	}
#endif
#if IS_ENABLED(CONFIG_LINK_DEVICE_SHMEM)
	if (link_type == LINKDEV_SHMEM) {
		mld->recv_cp2ap_irq = shmem_recv_cp2ap_irq;
		mld->send_ap2cp_irq = shmem_send_ap2cp_irq;
		mld->recv_cp2ap_status = shmem_recv_cp2ap_status;
	}
#endif

	/*
	 * Link local functions to the corresponding function pointers that are
	 * optional for some memory-type link devices
	 */
#if IS_ENABLED(CONFIG_LINK_DEVICE_PCIE)
	if (link_type == LINKDEV_PCIE)
		mld->read_ap2cp_irq = pcie_read_ap2cp_irq;
#endif
#if IS_ENABLED(CONFIG_LINK_DEVICE_SHMEM)
	if (link_type == LINKDEV_SHMEM)
		mld->read_ap2cp_irq = shmem_read_ap2cp_irq;
#endif

	/*
	 * Initialize SHMEM maps for BOOT (physical map -> logical map)
	 */
	err = init_shmem_maps(link_type, modem, mld, ld);
	if (err)
		goto error;

	/*
	 * Info region
	 */
	err = init_info_region(modem, mld, ld);
	if (err)
		goto error;

	/*
	 * Retrieve SHMEM MBOX#, IRQ#, etc.
	 */
	mld->int_ap2cp_msg = modem->mbx->int_ap2cp_msg;
	mld->irq_cp2ap_msg = modem->mbx->irq_cp2ap_msg;

	mld->sbi_cp_status_mask = modem->sbi_cp_status_mask;
	mld->sbi_cp_status_pos = modem->sbi_cp_status_pos;
	mld->irq_cp2ap_status = modem->mbx->irq_cp2ap_status;

	mld->sbi_cp2ap_wakelock_mask = modem->sbi_cp2ap_wakelock_mask;
	mld->sbi_cp2ap_wakelock_pos = modem->sbi_cp2ap_wakelock_pos;
	mld->irq_cp2ap_wakelock = modem->mbx->irq_cp2ap_wakelock;

	mld->sbi_cp_rat_mode_mask = modem->sbi_cp2ap_rat_mode_mask;
	mld->sbi_cp_rat_mode_pos = modem->sbi_cp2ap_rat_mode_pos;
	mld->irq_cp2ap_rat_mode = modem->mbx->irq_cp2ap_rat_mode;

#if IS_ENABLED(CONFIG_CP_LLC)
	mld->int_ap2cp_llc_status = modem->mbx->int_ap2cp_llc_status;
	mld->irq_cp2ap_llc_status = modem->mbx->irq_cp2ap_llc_status;

	mld->sbi_ap_llc_request_mask = modem->sbi_ap_llc_request_mask;
	mld->sbi_ap_llc_request_pos = modem->sbi_ap_llc_request_pos;
	mld->sbi_ap_llc_target_mask = modem->sbi_ap_llc_target_mask;
	mld->sbi_ap_llc_target_pos = modem->sbi_ap_llc_target_pos;
	mld->sbi_ap_llc_way_mask = modem->sbi_ap_llc_way_mask;
	mld->sbi_ap_llc_way_pos = modem->sbi_ap_llc_way_pos;
	mld->sbi_ap_llc_alloc_mask = modem->sbi_ap_llc_alloc_mask;
	mld->sbi_ap_llc_alloc_pos = modem->sbi_ap_llc_alloc_pos;
	mld->sbi_ap_llc_return_mask = modem->sbi_ap_llc_return_mask;
	mld->sbi_ap_llc_return_pos = modem->sbi_ap_llc_return_pos;
	mld->sbi_cp_llc_request_mask = modem->sbi_cp_llc_request_mask;
	mld->sbi_cp_llc_request_pos = modem->sbi_cp_llc_request_pos;
	mld->sbi_cp_llc_target_mask = modem->sbi_cp_llc_target_mask;
	mld->sbi_cp_llc_target_pos = modem->sbi_cp_llc_target_pos;
	mld->sbi_cp_llc_way_mask = modem->sbi_cp_llc_way_mask;
	mld->sbi_cp_llc_way_pos = modem->sbi_cp_llc_way_pos;
	mld->sbi_cp_llc_alloc_mask = modem->sbi_cp_llc_alloc_mask;
	mld->sbi_cp_llc_alloc_pos = modem->sbi_cp_llc_alloc_pos;
	mld->sbi_cp_llc_return_mask = modem->sbi_cp_llc_return_mask;
	mld->sbi_cp_llc_return_pos = modem->sbi_cp_llc_return_pos;
#endif
	mld->pktproc_use_36bit_addr = modem->pktproc_use_36bit_addr;

	/**
	 * For TX Flow-control command from CP
	 */
	mld->tx_flowctrl_cmd = 0;

	/* Link mem_link_device to modem_data */
	modem->mld = mld;

	mld->tx_period_ms = TX_PERIOD_MS;

	mld->pass_skb_to_net = pass_skb_to_net;
	mld->pass_skb_to_demux = pass_skb_to_demux;

	/*
	 * Register interrupt handlers
	 */
#if IS_ENABLED(CONFIG_MCU_IPC)
	err = register_irq_handler(modem, mld, ld);
	if (err) {
		mif_err("register_irq_handler() error %d\n", err);
		goto error;
	}
#endif

	if (ld->link_type == LINKDEV_SHMEM) {
		err = parse_ect_tables(pdev, mld);
		if (err)
			goto error;
	}

#if IS_ENABLED(CONFIG_CP_PKTPROC)
	err = pktproc_create(pdev, mld, cp_shmem_get_base(SHMEM_PKTPROC),
			cp_shmem_get_size(SHMEM_PKTPROC));
	if (err < 0) {
		mif_err("pktproc_create() error %d\n", err);
		goto error;
	}
#endif

#if IS_ENABLED(CONFIG_CP_PKTPROC_UL)
	err = pktproc_create_ul(pdev, mld, cp_shmem_get_base(SHMEM_PKTPROC),
			cp_shmem_get_size(SHMEM_PKTPROC_UL));
	if (err < 0) {
		mif_err("pktproc_create_ul() error %d\n", err);
		goto error;
	}
	hrtimer_init(&mld->pktproc_tx_timer, CLOCK_MONOTONIC, HRTIMER_MODE_REL);
	mld->pktproc_tx_timer.function = pktproc_tx_timer_func;
#endif

#if IS_ENABLED(CONFIG_CPIF_TP_MONITOR)
	err = tpmon_create(pdev, ld);
	if (err < 0) {
		mif_err("tpmon_create() error %d\n", err);
		goto error;
	}
#endif

	/* sysfs */
	if (sysfs_create_group(&pdev->dev.kobj, &link_device_group))
		mif_err("failed to create sysfs node related link_device\n");

	if (sysfs_create_group(&pdev->dev.kobj, &napi_group))
		mif_err("failed to create sysfs node related napi\n");

	mif_info("---\n");
	return ld;

error:
	kfree(mld);
	mif_err("xxx\n");
	return NULL;
}
