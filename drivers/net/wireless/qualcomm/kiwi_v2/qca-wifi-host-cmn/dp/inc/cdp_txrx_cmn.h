/*
 * Copyright (c) 2011-2021 The Linux Foundation. All rights reserved.
 * Copyright (c) 2021-2023 Qualcomm Innovation Center, Inc. All rights reserved.
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
 * DOC: cdp_txrx_cmn.h
 * Define the host data path converged API functions
 * called by the host control SW and the OS interface module
 */
#ifndef _CDP_TXRX_CMN_H_
#define _CDP_TXRX_CMN_H_

#include "qdf_types.h"
#include "qdf_nbuf.h"
#include "cdp_txrx_ops.h"
#include "cdp_txrx_handle.h"
#include "cdp_txrx_cmn_struct.h"
#include "wlan_objmgr_global_obj.h"

#ifdef ENABLE_VERBOSE_DEBUG
extern bool is_dp_verbose_debug_enabled;
#endif

/******************************************************************************
 *
 * Common Data Path Header File
 *
 *****************************************************************************/
#define dp_alert(params...) QDF_TRACE_FATAL(QDF_MODULE_ID_DP, params)
#define dp_err(params...) QDF_TRACE_ERROR(QDF_MODULE_ID_DP, params)
#define dp_warn(params...) QDF_TRACE_WARN(QDF_MODULE_ID_DP, params)
#define dp_info(params...) \
	__QDF_TRACE_FL(QDF_TRACE_LEVEL_INFO_HIGH, QDF_MODULE_ID_DP, ## params)
#define dp_debug(params...) QDF_TRACE_DEBUG(QDF_MODULE_ID_DP, params)

#ifdef DP_PRINT_NO_CONSOLE
#define dp_err_log(params...) \
	__QDF_TRACE_FL(QDF_TRACE_LEVEL_INFO_HIGH, QDF_MODULE_ID_DP, ## params)
#define dp_info_rl(params...) \
	__QDF_TRACE_RL(QDF_TRACE_LEVEL_INFO_HIGH, QDF_MODULE_ID_DP, ## params)
#else
#define dp_err_log(params...) QDF_TRACE_ERROR(QDF_MODULE_ID_DP, params)
#define dp_info_rl(params...) QDF_TRACE_INFO_RL(QDF_MODULE_ID_DP, params)
#endif /* DP_PRINT_NO_CONSOLE */

#ifdef ENABLE_VERBOSE_DEBUG
/**
 * enum verbose_debug_module -
 * if INI "enable_verbose_debug" has to set following bit positions to enable
 * respective module's excessive logging,
 *
 * @hif_verbose_debug_mask: 1st bit [0th index] is  for HIF module
 * @hal_verbose_debug_mask: 2nd bit [1st index] is for HAL module
 * @dp_verbose_debug_mask:  3rd bit [2nd index] is for DP module
 */
enum verbose_debug_module {
	hif_verbose_debug_mask   = 1 << 0,
	hal_verbose_debug_mask   = 1 << 1,
	dp_verbose_debug_mask    = 1 << 2,
};

/* legacy misspelled enumerator */
#define hif_vebose_debug_mask hif_verbose_debug_mask

#define dp_verbose_debug(params...) \
		if (unlikely(is_dp_verbose_debug_enabled)) \
			do {\
				QDF_TRACE_DEBUG(QDF_MODULE_ID_DP, params); \
			} while (0)
#else
#define dp_verbose_debug(params...) QDF_TRACE_DEBUG(QDF_MODULE_ID_DP, params)
#endif

#define dp_nofl_alert(params...) \
	QDF_TRACE_FATAL_NO_FL(QDF_MODULE_ID_DP, params)
#define dp_nofl_err(params...) \
	QDF_TRACE_ERROR_NO_FL(QDF_MODULE_ID_DP, params)
#define dp_nofl_warn(params...) \
	QDF_TRACE_WARN_NO_FL(QDF_MODULE_ID_DP, params)
#define dp_nofl_info(params...) \
	QDF_TRACE_INFO_NO_FL(QDF_MODULE_ID_DP, params)
#define dp_nofl_debug(params...) \
	QDF_TRACE_DEBUG_NO_FL(QDF_MODULE_ID_DP, params)

#define dp_alert_rl(params...) QDF_TRACE_FATAL_RL(QDF_MODULE_ID_DP, params)
#define dp_err_rl(params...) QDF_TRACE_ERROR_RL(QDF_MODULE_ID_DP, params)
#define dp_warn_rl(params...) QDF_TRACE_WARN_RL(QDF_MODULE_ID_DP, params)
#define dp_debug_rl(params...) QDF_TRACE_DEBUG_RL(QDF_MODULE_ID_DP, params)

#define dp_cdp_alert(params...) QDF_TRACE_FATAL(QDF_MODULE_ID_DP_CDP, params)
#define dp_cdp_err(params...) QDF_TRACE_ERROR(QDF_MODULE_ID_DP_CDP, params)
#define dp_cdp_warn(params...) QDF_TRACE_WARN(QDF_MODULE_ID_DP_CDP, params)
#define dp_cdp_info(params...) \
	__QDF_TRACE_FL(QDF_TRACE_LEVEL_INFO_HIGH, QDF_MODULE_ID_DP_CDP, ## params)
#define dp_cdp_debug(params...) QDF_TRACE_DEBUG(QDF_MODULE_ID_DP_CDP, params)

#define dp_cdp_nofl_alert(params...) \
	QDF_TRACE_FATAL_NO_FL(QDF_MODULE_ID_DP_CDP, params)
#define dp_cdp_nofl_err(params...) \
	QDF_TRACE_ERROR_NO_FL(QDF_MODULE_ID_DP_CDP, params)
#define dp_cdp_nofl_warn(params...) \
	QDF_TRACE_WARN_NO_FL(QDF_MODULE_ID_DP_CDP, params)
#define dp_cdp_nofl_info(params...) \
	QDF_TRACE_DEBUG_NO_FL(QDF_MODULE_ID_DP_CDP, params)
#define dp_cdp_nofl_debug(params...) \
	QDF_TRACE_DEBUG_NO_FL(QDF_MODULE_ID_DP_CDP, params)

#define DP_PEER_INFO_PARAMS_INIT(peer_info, _vdev_id, \
				_peer_mac, _addr_align, _peer_type) \
({	typeof(peer_info) _peer_info = (peer_info); \
	do {								\
		(_peer_info)->vdev_id = (_vdev_id);			\
		(_peer_info)->mac_addr = (_peer_mac);			\
		(_peer_info)->mac_addr_is_aligned = (_addr_align);	\
		(_peer_info)->peer_type = (_peer_type);			\
	} while (0); })

#ifdef WLAN_FEATURE_11BE_MLO
#define CDP_RX_ML_PEER_VALID_MASK  (0x00002000)
#define CDP_RX_ML_PEER_VALID_SHIFT (13)
#define CDP_RX_GET_ML_PEER_VALID(skb) \
	((QDF_NBUF_CB_RX_PEER_ID(skb) & \
	  CDP_RX_ML_PEER_VALID_MASK) >> CDP_RX_ML_PEER_VALID_SHIFT)
#endif

/**
 * enum vdev_host_stats_id -
 * host stats update from CDP have to set one of the following stats ID
 *
 * @DP_VDEV_STATS_PKT_CNT_ONLY: update Tx packet count only
 * @DP_VDEV_STATS_TX_ME: update Tx ingress stats
 */
enum vdev_host_stats_id {
	DP_VDEV_STATS_PKT_CNT_ONLY,
	DP_VDEV_STATS_TX_ME,
};

/*
 * BW types used for RX PPDU
 */
enum rx_tlv_bw {
	RX_TLV_BW_20MHZ,
	RX_TLV_BW_40MHZ,
	RX_TLV_BW_80MHZ,
	RX_TLV_BW_160MHZ,
	RX_TLV_BW_320MHZ,
	RX_TLV_BW_240MHZ,
	RX_TLV_BW_CNT,
};

/**
 * typedef ipa_uc_op_cb_type() - Register OP handler function
 * @op_msg: message
 * @osif_ctxt: OSIF context
 */
typedef void (*ipa_uc_op_cb_type)(uint8_t *op_msg,
				  void *osif_ctxt);

#ifdef QCA_SUPPORT_DP_GLOBAL_CTX
/* Global level structure for win contexts */
struct dp_global_context {
	struct dp_rx_fst *fst_ctx;
	struct dp_tx_desc_pool_s *tx_desc[2][4];
	struct dp_hw_cookie_conversion_t *tx_cc_ctx[4];
	struct dp_tx_desc_pool_s *spcl_tx_desc[2][4];
	struct dp_hw_cookie_conversion_t *spcl_tx_cc_ctx[4];
	qdf_atomic_t rx_fst_ref_cnt;
	qdf_atomic_t global_descriptor_in_use;
	int tx_cookie_ctx_alloc_cnt;
	int tx_desc_pool_alloc_cnt[2];
	int tx_desc_pool_init_cnt[2];
	int spcl_tx_cookie_ctx_alloc_cnt;
	int spcl_tx_desc_pool_alloc_cnt[2];
	int spcl_tx_desc_pool_init_cnt[2];
};

/**
 * cdp_global_ctx_init() - to initialise global context for tx descriptors
 *
 * Return: QDF_STATUS on success
 */
static inline QDF_STATUS cdp_global_ctx_init(void)
{
	struct dp_global_context *dp_global;
	QDF_STATUS status = QDF_STATUS_SUCCESS;

	if (wlan_objmgr_get_global_ctx()) {
		dp_err("Global object is already created");
		return QDF_STATUS_SUCCESS;
	}

	dp_global =  (struct dp_global_context *)
			qdf_mem_malloc(sizeof(*dp_global));

	if (!dp_global)
		return QDF_STATUS_E_FAILURE;

	qdf_mem_zero(dp_global, sizeof(*dp_global));
	wlan_objmgr_set_global_ctx(dp_global);
	qdf_atomic_set(&dp_global->global_descriptor_in_use, 0);
	dp_global->fst_ctx = NULL;
	qdf_atomic_set(&dp_global->rx_fst_ref_cnt, 0);

	return status;
}

/**
 * cdp_global_ctx_deinit() - to deinitialise global context for tx descriptors
 *
 * Return: SUCCESS status on success
 */
static inline QDF_STATUS cdp_global_ctx_deinit(void)
{
	struct dp_global_context *dp_global = wlan_objmgr_get_global_ctx();
	QDF_STATUS status = QDF_STATUS_SUCCESS;

	if (!dp_global)
		return QDF_STATUS_SUCCESS;

	qdf_mem_free(dp_global);
	wlan_objmgr_set_global_ctx(NULL);

	return status;
}
#else
static inline QDF_STATUS cdp_global_ctx_init(void)
{
	return QDF_STATUS_SUCCESS;
}

static inline QDF_STATUS cdp_global_ctx_deinit(void)
{
	return QDF_STATUS_SUCCESS;
}
#endif

static inline QDF_STATUS
cdp_soc_attach_target(ol_txrx_soc_handle soc)
{
	if (!soc || !soc->ops) {
		dp_cdp_debug("Invalid Instance:");
		QDF_BUG(0);
		return QDF_STATUS_E_INVAL;
	}

	if (!soc->ops->cmn_drv_ops ||
	    !soc->ops->cmn_drv_ops->txrx_soc_attach_target)
		return QDF_STATUS_SUCCESS;

	return soc->ops->cmn_drv_ops->txrx_soc_attach_target(soc);

}

static inline QDF_STATUS
cdp_vdev_attach(ol_txrx_soc_handle soc, uint8_t pdev_id,
		struct cdp_vdev_info *vdev_info)
{
	if (!soc || !soc->ops) {
		dp_cdp_debug("Invalid Instance:");
		QDF_BUG(0);
		return QDF_STATUS_E_FAILURE;
	}

	if (!soc->ops->cmn_drv_ops ||
	    !soc->ops->cmn_drv_ops->txrx_vdev_attach)
		return QDF_STATUS_E_FAILURE;

	return soc->ops->cmn_drv_ops->txrx_vdev_attach(soc, pdev_id, vdev_info);
}

#ifdef DP_FLOW_CTL
/**
 * cdp_flow_pool_map() - Create flow pool for vdev
 * @soc: data path soc handle
 * @pdev_id: id of dp pdev handle
 * @vdev_id: vdev_id corresponding to vdev start
 *
 * Create per vdev flow pool.
 *
 * Return: QDF_STATUS
 */
static inline QDF_STATUS cdp_flow_pool_map(ol_txrx_soc_handle soc,
					   uint8_t pdev_id, uint8_t vdev_id)
{
	if (!soc || !soc->ops) {
		dp_cdp_debug("Invalid Instance:");
		QDF_BUG(0);
		return QDF_STATUS_E_INVAL;
	}

	if (!soc->ops->flowctl_ops ||
	    !soc->ops->flowctl_ops->flow_pool_map_handler)
		return QDF_STATUS_E_INVAL;

	return soc->ops->flowctl_ops->flow_pool_map_handler(soc, pdev_id,
							    vdev_id);
}

/**
 * cdp_flow_pool_unmap() - Delete flow pool
 * @soc: data path soc handle
 * @pdev_id: id of dp pdev handle
 * @vdev_id: vdev_id corresponding to vdev start
 *
 * Delete flow pool
 *
 * Return: none
 */
static inline void cdp_flow_pool_unmap(ol_txrx_soc_handle soc,
				       uint8_t pdev_id, uint8_t vdev_id)
{
	if (!soc || !soc->ops) {
		dp_cdp_debug("Invalid Instance:");
		QDF_BUG(0);
		return;
	}

	if (!soc->ops->flowctl_ops ||
	    !soc->ops->flowctl_ops->flow_pool_unmap_handler)
		return;

	return soc->ops->flowctl_ops->flow_pool_unmap_handler(soc, pdev_id,
							vdev_id);
}
#endif

static inline QDF_STATUS
cdp_vdev_detach(ol_txrx_soc_handle soc, uint8_t vdev_id,
		ol_txrx_vdev_delete_cb callback, void *cb_context)
{
	if (!soc || !soc->ops) {
		dp_cdp_debug("Invalid Instance:");
		QDF_BUG(0);
		return QDF_STATUS_E_FAILURE;
	}

	if (!soc->ops->cmn_drv_ops ||
	    !soc->ops->cmn_drv_ops->txrx_vdev_detach)
		return QDF_STATUS_E_FAILURE;

	return soc->ops->cmn_drv_ops->txrx_vdev_detach(soc, vdev_id,
						       callback, cb_context);
}

#if defined(WLAN_FEATURE_11BE_MLO) && defined(WLAN_MLO_MULTI_CHIP)
static inline void
cdp_vdev_recovery_flush_peers(ol_txrx_soc_handle soc,
			      uint8_t vdev_id,
			      bool mlo_peers_only)
{
	if (!soc || !soc->ops) {
		dp_cdp_debug("Invalid Instance:");
		QDF_BUG(0);
		return;
	}

	if (!soc->ops->cmn_drv_ops ||
	    !soc->ops->cmn_drv_ops->txrx_recovery_vdev_flush_peers)
		return;

	soc->ops->cmn_drv_ops->txrx_recovery_vdev_flush_peers(soc,
							      vdev_id,
							      mlo_peers_only);
}
#endif

static inline int
cdp_pdev_attach_target(ol_txrx_soc_handle soc, uint8_t pdev_id)
{
	if (!soc || !soc->ops) {
		dp_cdp_debug("Invalid Instance:");
		QDF_BUG(0);
		return 0;
	}

	if (!soc->ops->cmn_drv_ops ||
	    !soc->ops->cmn_drv_ops->txrx_pdev_attach_target)
		return 0;

	return soc->ops->cmn_drv_ops->txrx_pdev_attach_target(soc, pdev_id);
}

static inline QDF_STATUS cdp_pdev_attach
	(ol_txrx_soc_handle soc, struct cdp_pdev_attach_params *params)
{
	if (!soc || !soc->ops) {
		dp_cdp_debug("Invalid Instance:");
		QDF_BUG(0);
		return QDF_STATUS_E_FAILURE;
	}

	if (!soc->ops->cmn_drv_ops ||
	    !soc->ops->cmn_drv_ops->txrx_pdev_attach)
		return QDF_STATUS_E_FAILURE;

	return soc->ops->cmn_drv_ops->txrx_pdev_attach(soc, params);
}

/**
 * cdp_pdev_post_attach() - attach the data SW state
 * @soc: datapath soc handle
 * @pdev_id: the data physical device id being removed
 *
 * This function is used when the WLAN driver is being loaded to
 * attach the host data component within the driver.
 *
 * Return: 0 for success or error code
 */
static inline int cdp_pdev_post_attach(ol_txrx_soc_handle soc, uint8_t pdev_id)
{
	if (!soc || !soc->ops) {
		dp_cdp_debug("Invalid Instance:");
		QDF_BUG(0);
		return 0;
	}

	if (!soc->ops->cmn_drv_ops ||
	    !soc->ops->cmn_drv_ops->txrx_pdev_post_attach)
		return 0;

	return soc->ops->cmn_drv_ops->txrx_pdev_post_attach(soc, pdev_id);
}

/**
 * cdp_pdev_pre_detach() - detach the data SW state
 * @soc: datapath soc handle
 * @pdev_id: the data physical device id being removed
 * @force: delete the pdev (and its vdevs and peers) even if
 * there are outstanding references by the target to the vdevs
 * and peers within the pdev
 *
 * This function is used when the WLAN driver is being removed to
 * detach the host data component within the driver.
 *
 * Return: None
 */
static inline void
cdp_pdev_pre_detach(ol_txrx_soc_handle soc, uint8_t pdev_id, int force)
{
	if (!soc || !soc->ops) {
		dp_cdp_debug("Invalid Instance:");
		QDF_BUG(0);
		return;
	}

	if (!soc->ops->cmn_drv_ops ||
	    !soc->ops->cmn_drv_ops->txrx_pdev_pre_detach)
		return;

	soc->ops->cmn_drv_ops->txrx_pdev_pre_detach(soc, pdev_id, force);
}

static inline QDF_STATUS
cdp_pdev_detach(ol_txrx_soc_handle soc, uint8_t pdev_id, int force)
{
	if (!soc || !soc->ops) {
		dp_cdp_debug("Invalid Instance:");
		QDF_BUG(0);
		return QDF_STATUS_E_FAILURE;
	}

	if (!soc->ops->cmn_drv_ops ||
	    !soc->ops->cmn_drv_ops->txrx_pdev_detach)
		return QDF_STATUS_E_FAILURE;

	return soc->ops->cmn_drv_ops->txrx_pdev_detach(soc, pdev_id, force);
}

static inline void
cdp_pdev_deinit(ol_txrx_soc_handle soc, uint8_t pdev_id, int force)
{
	if (!soc || !soc->ops) {
		dp_cdp_debug("Invalid Instance:");
		QDF_BUG(0);
		return;
	}

	if (!soc->ops->cmn_drv_ops ||
	    !soc->ops->cmn_drv_ops->txrx_pdev_deinit)
		return;

	soc->ops->cmn_drv_ops->txrx_pdev_deinit(soc, pdev_id, force);
}

static inline QDF_STATUS cdp_peer_create
	(ol_txrx_soc_handle soc, uint8_t vdev_id,
	uint8_t *peer_mac_addr)
{
	if (!soc || !soc->ops) {
		dp_cdp_debug("Invalid Instance:");
		QDF_BUG(0);
		return QDF_STATUS_E_FAILURE;
	}

	if (!soc->ops->cmn_drv_ops ||
	    !soc->ops->cmn_drv_ops->txrx_peer_create)
		return QDF_STATUS_E_FAILURE;

	return soc->ops->cmn_drv_ops->txrx_peer_create(soc, vdev_id,
			peer_mac_addr, CDP_LINK_PEER_TYPE);
}

static inline  QDF_STATUS cdp_peer_setup
	(ol_txrx_soc_handle soc, uint8_t vdev_id, uint8_t *peer_mac,
	 struct cdp_peer_setup_info *setup_info)
{
	if (!soc || !soc->ops) {
		dp_cdp_debug("Invalid Instance:");
		QDF_BUG(0);
		return  QDF_STATUS_E_FAILURE;
	}

	if (!soc->ops->cmn_drv_ops ||
	    !soc->ops->cmn_drv_ops->txrx_peer_setup)
		return QDF_STATUS_E_FAILURE;

	return soc->ops->cmn_drv_ops->txrx_peer_setup(soc, vdev_id,
						      peer_mac, setup_info);
}

/**
 * cdp_cp_peer_del_response() - Call the peer delete response handler
 * @soc: Datapath SOC handle
 * @vdev_id: id of virtual device object
 * @peer_mac_addr: Mac address of the peer
 *
 * Return: void
 */
static inline QDF_STATUS cdp_cp_peer_del_response
	(ol_txrx_soc_handle soc,
	 uint8_t vdev_id,
	 uint8_t *peer_mac_addr)
{
	if (!soc || !soc->ops) {
		dp_cdp_debug("Invalid Instance:");
		QDF_BUG(0);
		return QDF_STATUS_E_FAILURE;
	}

	if (!soc->ops->cmn_drv_ops ||
	    !soc->ops->cmn_drv_ops->txrx_cp_peer_del_response)
		return QDF_STATUS_E_FAILURE;

	return soc->ops->cmn_drv_ops->txrx_cp_peer_del_response(soc,
								vdev_id,
								peer_mac_addr);
}
/**
 * cdp_peer_get_ast_info_by_soc() - search the soc AST hash table
 *                                  and return ast entry information
 *                                  of first ast entry found in the
 *                                  table with given mac address
 *
 * @soc: data path soc handle
 * @ast_mac_addr: AST entry mac address
 * @ast_entry_info: ast entry information
 *
 * return: true if ast entry found with ast_mac_addr
 *          false if ast entry not found
 */
static inline bool cdp_peer_get_ast_info_by_soc
	(ol_txrx_soc_handle soc, uint8_t *ast_mac_addr,
	 struct cdp_ast_entry_info *ast_entry_info)
{
	if (!soc || !soc->ops) {
		dp_cdp_debug("Invalid Instance:");
		QDF_BUG(0);
		return false;
	}

	if (!soc->ops->cmn_drv_ops ||
	    !soc->ops->cmn_drv_ops->txrx_peer_get_ast_info_by_soc)
		return false;

	return soc->ops->cmn_drv_ops->txrx_peer_get_ast_info_by_soc
					(soc, ast_mac_addr,
					 ast_entry_info);
}

/**
 * cdp_peer_get_ast_info_by_pdev() - search the soc AST hash table
 *                                   and return ast entry information
 *                                   if mac address and pdev_id matches
 *
 * @soc: data path soc handle
 * @ast_mac_addr: AST entry mac address
 * @pdev_id: pdev_id
 * @ast_entry_info: ast entry information
 *
 * return: true if ast entry found with ast_mac_addr
 *          false if ast entry not found
 */
static inline bool cdp_peer_get_ast_info_by_pdev
	(ol_txrx_soc_handle soc, uint8_t *ast_mac_addr,
	 uint8_t pdev_id,
	 struct cdp_ast_entry_info *ast_entry_info)
{
	if (!soc || !soc->ops) {
		dp_cdp_debug("Invalid Instance:");
		QDF_BUG(0);
		return false;
	}

	if (!soc->ops->cmn_drv_ops ||
	    !soc->ops->cmn_drv_ops->txrx_peer_get_ast_info_by_pdev)
		return false;

	return soc->ops->cmn_drv_ops->txrx_peer_get_ast_info_by_pdev
					(soc,
					 ast_mac_addr,
					 pdev_id,
					 ast_entry_info);
}

/**
 * cdp_peer_ast_delete_by_soc() - delete the ast entry from soc AST hash table
 *                                with given mac address
 *
 * @soc: data path soc handle
 * @ast_mac_addr: AST entry mac address
 * @callback: callback function to called on ast delete response from FW
 * @cookie: argument to be passed to callback
 *
 * return: QDF_STATUS_SUCCESS if ast entry found with ast_mac_addr and delete
 *          is sent
 *          QDF_STATUS_E_INVAL false if ast entry not found
 */
static inline QDF_STATUS cdp_peer_ast_delete_by_soc
	(ol_txrx_soc_handle soc, uint8_t *ast_mac_addr,
	 txrx_ast_free_cb callback,
	 void *cookie)
{
	if (!soc || !soc->ops) {
		dp_cdp_debug("Invalid Instance:");
		QDF_BUG(0);
		return QDF_STATUS_E_INVAL;
	}

	if (!soc->ops->cmn_drv_ops ||
	    !soc->ops->cmn_drv_ops->txrx_peer_ast_delete_by_soc)
		return QDF_STATUS_E_INVAL;

	return soc->ops->cmn_drv_ops->txrx_peer_ast_delete_by_soc
							(soc,
							 ast_mac_addr,
							 callback,
							 cookie);
}

/**
 * cdp_peer_ast_delete_by_pdev() - delete the ast entry from soc AST hash table
 *                                 if mac address and pdev_id matches
 *
 * @soc: data path soc handle
 * @ast_mac_addr: AST entry mac address
 * @pdev_id: pdev id
 * @callback: callback function to called on ast delete response from FW
 * @cookie: argument to be passed to callback
 *
 * return: QDF_STATUS_SUCCESS if ast entry found with ast_mac_addr and delete
 *          is sent
 *          QDF_STATUS_E_INVAL false if ast entry not found
 */
static inline QDF_STATUS cdp_peer_ast_delete_by_pdev
	(ol_txrx_soc_handle soc, uint8_t *ast_mac_addr,
	 uint8_t pdev_id, txrx_ast_free_cb callback,
	 void *cookie)
{
	if (!soc || !soc->ops) {
		dp_cdp_debug("Invalid Instance:");
		QDF_BUG(0);
		return QDF_STATUS_E_INVAL;
	}

	if (!soc->ops->cmn_drv_ops ||
	    !soc->ops->cmn_drv_ops->txrx_peer_ast_delete_by_pdev)
		return QDF_STATUS_E_INVAL;

	return soc->ops->cmn_drv_ops->txrx_peer_ast_delete_by_pdev
					(soc,
					 ast_mac_addr,
					 pdev_id,
					 callback,
					 cookie);
}

/**
 * cdp_peer_HMWDS_ast_delete() - delete the ast entry from soc AST hash table
 *                               for HMWDS rem-addr command
 *
 * @soc: data path soc handle
 * @vdev_id: vdev id
 * @dest_mac: AST entry mac address to delete
 * @type: cdp_txrx_ast_entry_type to send to FW
 * @delete_in_fw: flag to indicate AST entry deletion in FW
 *
 * Return: QDF_STATUS_SUCCESS if ast entry found with ast_mac_addr and delete
 *         is sent
 *         QDF_STATUS_E_INVAL false if ast entry not found
 */
static inline QDF_STATUS cdp_peer_HMWDS_ast_delete
	(ol_txrx_soc_handle soc, uint8_t vdev_id, uint8_t *dest_mac,
	 uint8_t type, uint8_t delete_in_fw)
{
	if (!soc || !soc->ops) {
		dp_cdp_debug("Invalid Instance:");
		QDF_BUG(0);
		return QDF_STATUS_E_INVAL;
	}

	if (!soc->ops->cmn_drv_ops ||
	    !soc->ops->cmn_drv_ops->txrx_peer_HMWDS_ast_delete)
		return QDF_STATUS_E_INVAL;

	return soc->ops->cmn_drv_ops->txrx_peer_HMWDS_ast_delete
					(soc,
					 vdev_id,
					 dest_mac,
					 type,
					 delete_in_fw);
}

static inline int cdp_peer_add_ast
	(ol_txrx_soc_handle soc, uint8_t vdev_id, uint8_t *peer_mac,
	uint8_t *mac_addr,
	enum cdp_txrx_ast_entry_type type, uint32_t flags)
{
	if (!soc || !soc->ops) {
		dp_cdp_debug("Invalid Instance:");
		QDF_BUG(0);
		return 0;
	}

	if (!soc->ops->cmn_drv_ops ||
	    !soc->ops->cmn_drv_ops->txrx_peer_add_ast)
		return 0;

	return soc->ops->cmn_drv_ops->txrx_peer_add_ast(soc,
							vdev_id,
							peer_mac,
							mac_addr,
							type,
							flags);
}

static inline QDF_STATUS cdp_peer_reset_ast
	(ol_txrx_soc_handle soc, uint8_t *wds_macaddr, uint8_t *peer_macaddr,
	 uint8_t vdev_id)
{

	if (!soc || !soc->ops) {
		dp_cdp_debug("Invalid Instance:");
		QDF_BUG(0);
		return QDF_STATUS_E_FAILURE;
	}
	if (!soc->ops->cmn_drv_ops ||
	    !soc->ops->cmn_drv_ops->txrx_peer_reset_ast)
		return QDF_STATUS_E_FAILURE;

	return soc->ops->cmn_drv_ops->txrx_peer_reset_ast(soc, wds_macaddr,
						   peer_macaddr, vdev_id);
}

static inline QDF_STATUS cdp_peer_reset_ast_table
	(ol_txrx_soc_handle soc, uint8_t vdev_id)
{
	if (!soc || !soc->ops) {
		dp_cdp_debug("Invalid Instance:");
		QDF_BUG(0);
		return QDF_STATUS_E_FAILURE;
	}

	if (!soc->ops->cmn_drv_ops ||
	    !soc->ops->cmn_drv_ops->txrx_peer_reset_ast_table)
		return QDF_STATUS_E_FAILURE;

	return soc->ops->cmn_drv_ops->txrx_peer_reset_ast_table(soc, vdev_id);
}

static inline void cdp_peer_flush_ast_table
	(ol_txrx_soc_handle soc)
{
	if (!soc || !soc->ops) {
		dp_cdp_debug("Invalid Instance:");
		QDF_BUG(0);
		return;
	}

	if (!soc->ops->cmn_drv_ops ||
	    !soc->ops->cmn_drv_ops->txrx_peer_flush_ast_table)
		return;

	soc->ops->cmn_drv_ops->txrx_peer_flush_ast_table(soc);
}

static inline int cdp_peer_update_ast
	(ol_txrx_soc_handle soc, uint8_t vdev_id, uint8_t *peer_mac,
	 uint8_t *wds_macaddr, uint32_t flags)
{
	if (!soc || !soc->ops) {
		dp_cdp_debug("Invalid Instance:");
		QDF_BUG(0);
		return 0;
	}

	if (!soc->ops->cmn_drv_ops ||
	    !soc->ops->cmn_drv_ops->txrx_peer_update_ast)
		return 0;


	return soc->ops->cmn_drv_ops->txrx_peer_update_ast(soc,
							vdev_id,
							peer_mac,
							wds_macaddr,
							flags);
}

static inline void cdp_peer_teardown
	(ol_txrx_soc_handle soc, uint8_t vdev_id, uint8_t *peer_mac)
{
	if (!soc || !soc->ops) {
		dp_cdp_debug("Invalid Instance:");
		QDF_BUG(0);
		return;
	}

	if (!soc->ops->cmn_drv_ops ||
	    !soc->ops->cmn_drv_ops->txrx_peer_teardown)
		return;

	soc->ops->cmn_drv_ops->txrx_peer_teardown(soc, vdev_id, peer_mac);
}

static inline void
cdp_peer_delete(ol_txrx_soc_handle soc, uint8_t vdev_id,
		uint8_t *peer_mac, uint32_t bitmap)
{
	if (!soc || !soc->ops) {
		dp_cdp_debug("Invalid Instance:");
		QDF_BUG(0);
		return;
	}

	if (!soc->ops->cmn_drv_ops ||
	    !soc->ops->cmn_drv_ops->txrx_peer_delete)
		return;

	soc->ops->cmn_drv_ops->txrx_peer_delete(soc, vdev_id, peer_mac,
						bitmap, CDP_LINK_PEER_TYPE);
}

#ifdef DP_RX_UDP_OVER_PEER_ROAM
static inline void
cdp_update_roaming_peer_in_vdev(ol_txrx_soc_handle soc, uint8_t vdev_id,
				uint8_t *peer_mac, uint32_t auth_status)
{
	if (!soc || !soc->ops) {
		QDF_TRACE(QDF_MODULE_ID_CDP, QDF_TRACE_LEVEL_DEBUG,
			  "%s: Invalid Instance:", __func__);
		QDF_BUG(0);
		return;
	}

	if (!soc->ops->cmn_drv_ops ||
	    !soc->ops->cmn_drv_ops->txrx_update_roaming_peer)
		return;

	soc->ops->cmn_drv_ops->txrx_update_roaming_peer(soc, vdev_id,
							peer_mac, auth_status);
}
#else
static inline void
cdp_update_roaming_peer_in_vdev(ol_txrx_soc_handle soc, uint8_t vdev_id,
				uint8_t *peer_mac, uint32_t auth_status)
{
}
#endif
/**
 * cdp_peer_delete_sync() - peer delete sync callback
 * @soc: datapath soc handle
 * @vdev_id: virtual device/interface id
 * @peer_mac: peer mac address
 * @delete_cb: peer delete sync cb.
 * @bitmap: bitmap indicating special handling of request.
 *
 * Return: None
 */
static inline void
cdp_peer_delete_sync(ol_txrx_soc_handle soc, uint8_t vdev_id, uint8_t *peer_mac,
		     QDF_STATUS(*delete_cb)(
				uint8_t vdev_id,
				uint32_t peerid_cnt,
				uint16_t *peerid_list),
		     uint32_t bitmap)
{
	if (!soc || !soc->ops) {
		dp_cdp_debug("Invalid Instance:");
		QDF_BUG(0);
		return;
	}

	if (!soc->ops->cmn_drv_ops ||
	    !soc->ops->cmn_drv_ops->txrx_peer_delete_sync)
		return;

	soc->ops->cmn_drv_ops->txrx_peer_delete_sync(soc, vdev_id, peer_mac,
						     delete_cb,
						     bitmap);
}

static inline int
cdp_set_monitor_mode(ol_txrx_soc_handle soc, uint8_t vdev_id,
		     uint8_t smart_monitor)
{
	if (!soc || !soc->ops) {
		dp_cdp_debug("Invalid Instance:");
		QDF_BUG(0);
		return 0;
	}

	if (!soc->ops->cmn_drv_ops ||
	    !soc->ops->cmn_drv_ops->txrx_set_monitor_mode)
		return 0;

	return soc->ops->cmn_drv_ops->txrx_set_monitor_mode(soc, vdev_id,
					smart_monitor);
}

static inline QDF_STATUS
cdp_set_curchan(ol_txrx_soc_handle soc,
	uint8_t pdev_id,
	uint32_t chan_mhz)
{
	if (!soc || !soc->ops) {
		dp_cdp_debug("Invalid Instance:");
		QDF_BUG(0);
		return QDF_STATUS_E_FAILURE;
	}

	if (!soc->ops->cmn_drv_ops ||
	    !soc->ops->cmn_drv_ops->txrx_set_curchan)
		return QDF_STATUS_E_FAILURE;

	return soc->ops->cmn_drv_ops->txrx_set_curchan(soc, pdev_id, chan_mhz);
}

static inline QDF_STATUS
cdp_set_privacy_filters(ol_txrx_soc_handle soc, uint8_t vdev_id,
			void *filter, uint32_t num)
{
	if (!soc || !soc->ops) {
		dp_cdp_debug("Invalid Instance:");
		QDF_BUG(0);
		return QDF_STATUS_E_FAILURE;
	}

	if (!soc->ops->cmn_drv_ops ||
	    !soc->ops->cmn_drv_ops->txrx_set_privacy_filters)
		return QDF_STATUS_E_FAILURE;

	return soc->ops->cmn_drv_ops->txrx_set_privacy_filters(soc, vdev_id,
			filter, num);
}

static inline int
cdp_set_monitor_filter(ol_txrx_soc_handle soc, uint8_t pdev_id,
		       struct cdp_monitor_filter *filter_val)
{
	if (soc->ops->mon_ops->txrx_set_advance_monitor_filter)
		return soc->ops->mon_ops->txrx_set_advance_monitor_filter(soc,
								pdev_id,
								filter_val);
	return 0;
}


/******************************************************************************
 * Data Interface (B Interface)
 *****************************************************************************/
static inline struct cdp_vdev *
cdp_vdev_register(ol_txrx_soc_handle soc, uint8_t vdev_id,
		  ol_osif_vdev_handle osif_vdev,
		  struct ol_txrx_ops *txrx_ops)
{
	if (!soc || !soc->ops) {
		dp_cdp_debug("Invalid Instance:");
		QDF_BUG(0);
		return NULL;
	}

	if (!soc->ops->cmn_drv_ops ||
	    !soc->ops->cmn_drv_ops->txrx_vdev_register)
		return NULL;

	return soc->ops->cmn_drv_ops->txrx_vdev_register(soc, vdev_id,
							 osif_vdev, txrx_ops);
}

static inline int
cdp_mgmt_send(ol_txrx_soc_handle soc, uint8_t vdev_id,
	      qdf_nbuf_t tx_mgmt_frm,	uint8_t type)
{
	if (!soc || !soc->ops) {
		dp_cdp_debug("Invalid Instance:");
		QDF_BUG(0);
		return 0;
	}

	if (!soc->ops->cmn_drv_ops ||
	    !soc->ops->cmn_drv_ops->txrx_mgmt_send)
		return 0;

	return soc->ops->cmn_drv_ops->txrx_mgmt_send(soc, vdev_id,
			tx_mgmt_frm, type);
}

static inline int
cdp_mgmt_send_ext(ol_txrx_soc_handle soc, uint8_t vdev_id,
		  qdf_nbuf_t tx_mgmt_frm, uint8_t type,
		  uint8_t use_6mbps, uint16_t chanfreq)
{
	if (!soc || !soc->ops) {
		dp_cdp_debug("Invalid Instance:");
		QDF_BUG(0);
		return 0;
	}

	if (!soc->ops->cmn_drv_ops ||
	    !soc->ops->cmn_drv_ops->txrx_mgmt_send_ext)
		return 0;

	return soc->ops->cmn_drv_ops->txrx_mgmt_send_ext
			(soc, vdev_id, tx_mgmt_frm, type, use_6mbps, chanfreq);
}


static inline QDF_STATUS
cdp_mgmt_tx_cb_set(ol_txrx_soc_handle soc, uint8_t pdev_id,
		   uint8_t type, ol_txrx_mgmt_tx_cb download_cb,
		   ol_txrx_mgmt_tx_cb ota_ack_cb, void *ctxt)
{
	if (!soc || !soc->ops) {
		dp_cdp_debug("Invalid Instance:");
		QDF_BUG(0);
		return QDF_STATUS_E_FAILURE;
	}

	if (!soc->ops->cmn_drv_ops ||
	    !soc->ops->cmn_drv_ops->txrx_mgmt_tx_cb_set)
		return QDF_STATUS_E_FAILURE;

	return soc->ops->cmn_drv_ops->txrx_mgmt_tx_cb_set
			(soc, pdev_id, type, download_cb, ota_ack_cb, ctxt);
}

/**
 * cdp_peer_unmap_sync_cb_set() - set peer unmap sync callback
 * @soc: datapath soc handle
 * @pdev_id: physical device instance id
 * @unmap_resp_cb: peer unmap sync callback
 *
 * Return: None
 */
static inline void
cdp_peer_unmap_sync_cb_set(ol_txrx_soc_handle soc,
			   uint8_t pdev_id,
			   QDF_STATUS(*unmap_resp_cb)(
					uint8_t vdev_id,
					uint32_t peerid_cnt,
					uint16_t *peerid_list))
{
	if (!soc || !soc->ops) {
		dp_cdp_debug("Invalid Instance:");
		QDF_BUG(0);
		return;
	}

	if (!soc->ops->cmn_drv_ops ||
	    !soc->ops->cmn_drv_ops->txrx_peer_unmap_sync_cb_set)
		return;

	soc->ops->cmn_drv_ops->txrx_peer_unmap_sync_cb_set(soc, pdev_id,
							   unmap_resp_cb);
}

/**
 * cdp_data_tx_cb_set(): set the callback for non standard tx
 * @soc: datapath soc handle
 * @vdev_id: virtual device/interface id
 * @callback: callback function
 * @ctxt: callback context
 *
 */
static inline void
cdp_data_tx_cb_set(ol_txrx_soc_handle soc, uint8_t vdev_id,
		   ol_txrx_data_tx_cb callback, void *ctxt)
{
	if (!soc || !soc->ops) {
		dp_cdp_debug("Invalid Instance:");
		QDF_BUG(0);
		return;
	}

	if (!soc->ops->cmn_drv_ops ||
	    !soc->ops->cmn_drv_ops->txrx_data_tx_cb_set)
		return;

	soc->ops->cmn_drv_ops->txrx_data_tx_cb_set(soc, vdev_id,
						   callback, ctxt);
}

/******************************************************************************
 * Statistics and Debugging Interface (C Interface)
 *****************************************************************************/
/*
 * External Device physical address types
 *
 * Currently, both MAC and IPA uController use the same size addresses
 * and descriptors are exchanged between these two depending on the mode.
 *
 * Rationale: qdf_dma_addr_t is the type used internally on the host for DMA
 *            operations. However, external device physical address sizes
 *            may be different from host-specific physical address sizes.
 *            This calls for the following definitions for target devices
 *            (MAC, IPA uc).
 */
#if HTT_PADDR64
typedef uint64_t target_paddr_t;
#else
typedef uint32_t target_paddr_t;
#endif /*HTT_PADDR64 */

static inline int
cdp_aggr_cfg(ol_txrx_soc_handle soc, uint8_t vdev_id,
	     int max_subfrms_ampdu,
	     int max_subfrms_amsdu)
{
	if (!soc || !soc->ops) {
		dp_cdp_debug("Invalid Instance:");
		QDF_BUG(0);
		return 0;
	}

	if (!soc->ops->cmn_drv_ops ||
	    !soc->ops->cmn_drv_ops->txrx_aggr_cfg)
		return 0;

	return soc->ops->cmn_drv_ops->txrx_aggr_cfg(soc, vdev_id,
			max_subfrms_ampdu, max_subfrms_amsdu);
}

static inline int
cdp_fw_stats_get(ol_txrx_soc_handle soc, uint8_t vdev_id,
		 struct ol_txrx_stats_req *req, bool per_vdev,
		 bool response_expected)
{
	if (!soc || !soc->ops) {
		dp_cdp_debug("Invalid Instance:");
		QDF_BUG(0);
		return 0;
	}

	if (!soc->ops->cmn_drv_ops ||
	    !soc->ops->cmn_drv_ops->txrx_fw_stats_get)
		return 0;

	return soc->ops->cmn_drv_ops->txrx_fw_stats_get(soc, vdev_id, req,
			per_vdev, response_expected);
}

static inline int
cdp_debug(ol_txrx_soc_handle soc, uint8_t vdev_id, int debug_specs)
{
	if (!soc || !soc->ops) {
		dp_cdp_debug("Invalid Instance:");
		QDF_BUG(0);
		return 0;
	}

	if (!soc->ops->cmn_drv_ops ||
	    !soc->ops->cmn_drv_ops->txrx_debug)
		return 0;

	return soc->ops->cmn_drv_ops->txrx_debug(soc, vdev_id, debug_specs);
}

static inline QDF_STATUS
cdp_fw_stats_cfg(ol_txrx_soc_handle soc,
		 uint8_t vdev_id, uint8_t cfg_stats_type, uint32_t cfg_val)
{
	if (!soc || !soc->ops) {
		dp_cdp_debug("Invalid Instance:");
		QDF_BUG(0);
		return QDF_STATUS_E_FAILURE;
	}

	if (!soc->ops->cmn_drv_ops ||
	    !soc->ops->cmn_drv_ops->txrx_fw_stats_cfg)
		return QDF_STATUS_E_FAILURE;

	return soc->ops->cmn_drv_ops->txrx_fw_stats_cfg(soc, vdev_id,
						 cfg_stats_type, cfg_val);
}

static inline void cdp_print_level_set(ol_txrx_soc_handle soc, unsigned level)
{
	if (!soc || !soc->ops) {
		dp_cdp_debug("Invalid Instance:");
		QDF_BUG(0);
		return;
	}

	if (!soc->ops->cmn_drv_ops ||
	    !soc->ops->cmn_drv_ops->txrx_print_level_set)
		return;

	soc->ops->cmn_drv_ops->txrx_print_level_set(level);
}

/**
 * cdp_get_vdev_mac_addr() - Detach txrx peer
 * @soc: Datapath soc handle
 * @vdev_id: virtual device/interface id
 *
 * Return: MAC address on success, NULL on failure.
 *
 */
static inline uint8_t *
cdp_get_vdev_mac_addr(ol_txrx_soc_handle soc, uint8_t vdev_id)
{
	if (!soc || !soc->ops) {
		dp_cdp_debug("Invalid Instance:");
		QDF_BUG(0);
		return NULL;
	}

	if (!soc->ops->cmn_drv_ops ||
	    !soc->ops->cmn_drv_ops->txrx_get_vdev_mac_addr)
		return NULL;

	return soc->ops->cmn_drv_ops->txrx_get_vdev_mac_addr(soc, vdev_id);

}

/**
 * cdp_get_os_rx_handles_from_vdev() - Return os rx handles for a vdev
 * @soc: ol_txrx_soc_handle handle
 * @vdev_id: vdev id for which os rx handles are needed
 * @stack_fn_p: pointer to stack function pointer
 * @osif_handle_p: pointer to ol_osif_vdev_handle
 *
 * Return: void
 */
static inline
void cdp_get_os_rx_handles_from_vdev(ol_txrx_soc_handle soc,
				     uint8_t vdev_id,
				     ol_txrx_rx_fp *stack_fn_p,
				     ol_osif_vdev_handle *osif_handle_p)
{
	if (!soc || !soc->ops) {
		dp_cdp_debug("Invalid Instance:");
		QDF_BUG(0);
		return;
	}

	if (!soc->ops->cmn_drv_ops ||
	    !soc->ops->cmn_drv_ops->txrx_get_os_rx_handles_from_vdev)
		return;

	soc->ops->cmn_drv_ops->txrx_get_os_rx_handles_from_vdev(soc, vdev_id,
								stack_fn_p,
								osif_handle_p);
}

/**
 * cdp_get_ctrl_pdev_from_vdev() - Return control pdev of vdev
 * @soc: datapath soc handle
 * @vdev_id: virtual device/interface id
 *
 * Return: Handle to control pdev
 */
static inline struct cdp_cfg *
cdp_get_ctrl_pdev_from_vdev(ol_txrx_soc_handle soc, uint8_t vdev_id)
{
	if (!soc || !soc->ops) {
		dp_cdp_debug("Invalid Instance:");
		QDF_BUG(0);
		return NULL;
	}

	if (!soc->ops->cmn_drv_ops ||
	    !soc->ops->cmn_drv_ops->txrx_get_ctrl_pdev_from_vdev)
		return NULL;

	return soc->ops->cmn_drv_ops->txrx_get_ctrl_pdev_from_vdev(soc,
								   vdev_id);
}

/**
 * cdp_get_mon_vdev_from_pdev() - Get vdev handle of monitor mode
 * @soc: datapath soc handle
 * @pdev_id: physical device instance id
 *
 * Return: virtual interface id
 */
static inline uint8_t
cdp_get_mon_vdev_from_pdev(ol_txrx_soc_handle soc, uint8_t pdev_id)
{
	if (!soc || !soc->ops) {
		dp_cdp_debug("Invalid Instance:");
		QDF_BUG(0);
		return -EINVAL;
	}

	if (!soc->ops->cmn_drv_ops ||
	    !soc->ops->cmn_drv_ops->txrx_get_mon_vdev_from_pdev)
		return -EINVAL;

	return soc->ops->cmn_drv_ops->txrx_get_mon_vdev_from_pdev(soc, pdev_id);
}

static inline void
cdp_soc_detach(ol_txrx_soc_handle soc)
{
	if (!soc || !soc->ops) {
		dp_cdp_debug("Invalid Instance:");
		QDF_BUG(0);
		return;
	}

	if (!soc->ops->cmn_drv_ops ||
	    !soc->ops->cmn_drv_ops->txrx_soc_detach)
		return;

	soc->ops->cmn_drv_ops->txrx_soc_detach(soc);
}

/**
 * cdp_soc_init() - Initialize txrx SOC
 * @soc: ol_txrx_soc_handle handle
 * @devid: Device ID
 * @hif_handle: Opaque HIF handle
 * @psoc: Opaque Objmgr handle
 * @htc_handle: Opaque HTC handle
 * @qdf_dev: QDF device
 * @dp_ol_if_ops: Offload Operations
 *
 * Return: DP SOC handle on success, NULL on failure
 */
static inline ol_txrx_soc_handle
cdp_soc_init(ol_txrx_soc_handle soc, u_int16_t devid,
	     void *hif_handle,
	     struct cdp_ctrl_objmgr_psoc *psoc,
	     HTC_HANDLE htc_handle, qdf_device_t qdf_dev,
	     struct ol_if_ops *dp_ol_if_ops)
{
	if (!soc || !soc->ops) {
		dp_cdp_debug("Invalid Instance:");
		QDF_BUG(0);
		return NULL;
	}

	if (!soc->ops->cmn_drv_ops ||
	    !soc->ops->cmn_drv_ops->txrx_soc_init)
		return NULL;

	return soc->ops->cmn_drv_ops->txrx_soc_init(soc, psoc,
						    hif_handle,
						    htc_handle, qdf_dev,
						    dp_ol_if_ops, devid);
}

/**
 * cdp_pdev_init() - Initialize txrx pdev
 * @soc: ol_txrx_soc_handle handle
 * @htc_handle: Opaque HTC handle
 * @qdf_dev: QDF device
 * @pdev_id: pdev id
 *
 * Return: DP SOC handle on success, NULL on failure
 */
static inline QDF_STATUS
cdp_pdev_init(ol_txrx_soc_handle soc,
	      HTC_HANDLE htc_handle, qdf_device_t qdf_dev,
	      uint8_t pdev_id)
{
	if (!soc || !soc->ops) {
		dp_cdp_debug("Invalid Instance:");
		QDF_BUG(0);
		return 0;
	}

	if (!soc->ops->cmn_drv_ops ||
	    !soc->ops->cmn_drv_ops->txrx_pdev_init)
		return 0;

	return soc->ops->cmn_drv_ops->txrx_pdev_init(soc,
						     htc_handle, qdf_dev,
						     pdev_id);
}

/**
 * cdp_soc_deinit() - Deinitialize txrx SOC
 * @soc: Opaque DP SOC handle
 *
 * Return: None
 */
static inline void
cdp_soc_deinit(ol_txrx_soc_handle soc)
{
	if (!soc || !soc->ops) {
		dp_cdp_debug("Invalid Instance:");
		QDF_BUG(0);
		return;
	}

	if (!soc->ops->cmn_drv_ops ||
	    !soc->ops->cmn_drv_ops->txrx_soc_deinit)
		return;

	soc->ops->cmn_drv_ops->txrx_soc_deinit(soc);
}

/**
 * cdp_tso_soc_attach() - TSO attach function
 * @soc: ol_txrx_soc_handle handle
 *
 * Reserve TSO descriptor buffers
 *
 * Return: QDF_STATUS_SUCCESS on Success or
 * QDF_STATUS_E_FAILURE on failure
 */
static inline QDF_STATUS
cdp_tso_soc_attach(ol_txrx_soc_handle soc)
{
	if (!soc || !soc->ops) {
		dp_cdp_debug("Invalid Instance:");
		QDF_BUG(0);
		return 0;
	}

	if (!soc->ops->cmn_drv_ops ||
	    !soc->ops->cmn_drv_ops->txrx_tso_soc_attach)
		return 0;

	return soc->ops->cmn_drv_ops->txrx_tso_soc_attach(soc);
}

/**
 * cdp_tso_soc_detach() - TSO detach function
 * @soc: ol_txrx_soc_handle handle
 *
 * Release TSO descriptor buffers
 *
 * Return: QDF_STATUS_SUCCESS on Success or
 * QDF_STATUS_E_FAILURE on failure
 */
static inline QDF_STATUS
cdp_tso_soc_detach(ol_txrx_soc_handle soc)
{
	if (!soc || !soc->ops) {
		dp_cdp_debug("Invalid Instance:");
		QDF_BUG(0);
		return 0;
	}

	if (!soc->ops->cmn_drv_ops ||
	    !soc->ops->cmn_drv_ops->txrx_tso_soc_detach)
		return 0;

	return soc->ops->cmn_drv_ops->txrx_tso_soc_detach(soc);
}

/**
 * cdp_tid_update_ba_win_size() - Update the DP tid BA window size
 * @soc: soc handle
 * @peer_mac: mac address of peer handle
 * @vdev_id: id of vdev handle
 * @tid: tid
 * @buffersize: BA window size
 *
 * Return: success/failure of tid update
 */
static inline QDF_STATUS
cdp_tid_update_ba_win_size(ol_txrx_soc_handle soc,
			   uint8_t *peer_mac, uint16_t vdev_id, uint8_t tid,
			   uint16_t buffersize)
{
	if (!soc || !soc->ops) {
		dp_cdp_debug("Invalid Instance:");
		QDF_BUG(0);
		return 0;
	}

	if (!soc->ops->cmn_drv_ops ||
	    !soc->ops->cmn_drv_ops->tid_update_ba_win_size)
		return 0;

	return soc->ops->cmn_drv_ops->tid_update_ba_win_size(soc, peer_mac,
							     vdev_id, tid,
							     buffersize);
}

/**
 * cdp_addba_resp_tx_completion() - Indicate addba response tx
 * completion to dp to change tid state.
 * @soc: soc handle
 * @peer_mac: mac address of peer handle
 * @vdev_id: id of vdev handle
 * @tid: tid
 * @status: Tx completion status
 *
 * Return: success/failure of tid update
 */
static inline int cdp_addba_resp_tx_completion(ol_txrx_soc_handle soc,
					       uint8_t *peer_mac,
					       uint16_t vdev_id,
					       uint8_t tid, int status)
{
	if (!soc || !soc->ops) {
		dp_cdp_debug("Invalid Instance:");
		QDF_BUG(0);
		return 0;
	}

	if (!soc->ops->cmn_drv_ops ||
	    !soc->ops->cmn_drv_ops->addba_resp_tx_completion)
		return 0;

	return soc->ops->cmn_drv_ops->addba_resp_tx_completion(soc, peer_mac,
					vdev_id, tid, status);
}

static inline int cdp_addba_requestprocess(ol_txrx_soc_handle soc,
	uint8_t *peer_mac, uint16_t vdev_id, uint8_t dialogtoken, uint16_t tid,
	uint16_t batimeout, uint16_t buffersize, uint16_t startseqnum)
{
	if (!soc || !soc->ops) {
		dp_cdp_debug("Invalid Instance:");
		QDF_BUG(0);
		return 0;
	}

	if (!soc->ops->cmn_drv_ops ||
	    !soc->ops->cmn_drv_ops->addba_requestprocess)
		return 0;

	return soc->ops->cmn_drv_ops->addba_requestprocess(soc, peer_mac,
			vdev_id, dialogtoken, tid, batimeout, buffersize,
			startseqnum);
}

static inline QDF_STATUS
cdp_addba_responsesetup(ol_txrx_soc_handle soc,
			uint8_t *peer_mac, uint16_t vdev_id,
			uint8_t tid, uint8_t *dialogtoken,
			uint16_t *statuscode, uint16_t *buffersize,
			uint16_t *batimeout)
{
	if (!soc || !soc->ops) {
		dp_cdp_debug("Invalid Instance:");
		QDF_BUG(0);
		return QDF_STATUS_E_FAILURE;
	}

	if (!soc->ops->cmn_drv_ops ||
	    !soc->ops->cmn_drv_ops->addba_responsesetup)
		return QDF_STATUS_E_FAILURE;

	return soc->ops->cmn_drv_ops->addba_responsesetup(soc, peer_mac,
			vdev_id, tid, dialogtoken, statuscode, buffersize,
			batimeout);
}

static inline int cdp_delba_process(ol_txrx_soc_handle soc, uint8_t *peer_mac,
				    uint16_t vdev_id, int tid,
				    uint16_t reasoncode)
{
	if (!soc || !soc->ops) {
		dp_cdp_debug("Invalid Instance:");
		QDF_BUG(0);
		return 0;
	}

	if (!soc->ops->cmn_drv_ops ||
	    !soc->ops->cmn_drv_ops->delba_process)
		return 0;

	return soc->ops->cmn_drv_ops->delba_process(soc, peer_mac,
						vdev_id, tid, reasoncode);
}

/**
 * cdp_delba_tx_completion() - Handle delba tx completion
 * to update stats and retry transmission if failed.
 * @soc: soc handle
 * @peer_mac: peer mac address
 * @vdev_id: id of vdev handle
 * @tid: Tid number
 * @status: Tx completion status
 *
 * Return: 0 on Success, 1 on failure
 */

static inline int cdp_delba_tx_completion(ol_txrx_soc_handle soc,
					  uint8_t *peer_mac,
					  uint16_t vdev_id,
					  uint8_t tid, int status)
{
	if (!soc || !soc->ops) {
		dp_cdp_debug("Invalid Instance:");
		QDF_BUG(0);
		return 0;
	}

	if (!soc->ops->cmn_drv_ops ||
	    !soc->ops->cmn_drv_ops->delba_tx_completion)
		return 0;

	return soc->ops->cmn_drv_ops->delba_tx_completion(soc, peer_mac,
							  vdev_id,
							  tid, status);
}

static inline QDF_STATUS
cdp_set_addbaresponse(ol_txrx_soc_handle soc,
		      uint8_t *peer_mac, uint16_t vdev_id, int tid,
		      uint16_t statuscode)
{
	if (!soc || !soc->ops) {
		dp_cdp_debug("Invalid Instance:");
		QDF_BUG(0);
		return QDF_STATUS_E_FAILURE;
	}

	if (!soc->ops->cmn_drv_ops ||
	    !soc->ops->cmn_drv_ops->set_addba_response)
		return QDF_STATUS_E_FAILURE;

	return soc->ops->cmn_drv_ops->set_addba_response(soc, peer_mac, vdev_id,
						  tid, statuscode);
}

/**
 * cdp_set_vdev_dscp_tid_map(): function to set DSCP-tid map in the vap
 * @soc : soc handle
 * @vdev_id: id of vdev handle
 * @map_id: id of the tid map
 *
 * Return: QDF_STATUS
 */
static inline QDF_STATUS
cdp_set_vdev_dscp_tid_map(ol_txrx_soc_handle soc,
			  uint8_t vdev_id, uint8_t map_id)
{
	if (!soc || !soc->ops) {
		dp_cdp_debug("Invalid Instance:");
		QDF_BUG(0);
		return QDF_STATUS_E_FAILURE;
	}

	if (!soc->ops->cmn_drv_ops ||
	    !soc->ops->cmn_drv_ops->set_vdev_dscp_tid_map)
		return QDF_STATUS_E_FAILURE;

	return soc->ops->cmn_drv_ops->set_vdev_dscp_tid_map(soc, vdev_id,
				map_id);
}

#ifdef QCA_MULTIPASS_SUPPORT
/**
 * cdp_set_vlan_groupkey(): function to set vlan ID - group key map in the vap
 * @soc : soc handle
 * @vdev_id: id of vdev handle
 * @vlan_id: vlan id
 * @group_key: corresponding group key to vlan ID
 *
 * Return: void
 */
static inline
QDF_STATUS cdp_set_vlan_groupkey(ol_txrx_soc_handle soc, uint8_t vdev_id,
				 uint16_t vlan_id, uint16_t group_key)
{
	if (!soc || !soc->ops) {
		dp_cdp_debug("Invalid Instance:");
		QDF_BUG(0);
		return 0;
	}

	if (!soc->ops->cmn_drv_ops ||
	    !soc->ops->cmn_drv_ops->set_vlan_groupkey)
		return 0;

	return soc->ops->cmn_drv_ops->set_vlan_groupkey(soc, vdev_id, vlan_id,
							group_key);
}
#endif

/**
 * cdp_ath_get_total_per(): function to get hw retries
 * @soc : soc handle
 * @pdev_id: id of pdev handle
 *
 * Return: get hw retries
 */
static inline
int cdp_ath_get_total_per(ol_txrx_soc_handle soc, uint8_t pdev_id)
{
	if (!soc || !soc->ops) {
		dp_cdp_debug("Invalid Instance:");
		QDF_BUG(0);
		return 0;
	}

	if (!soc->ops->cmn_drv_ops ||
	    !soc->ops->cmn_drv_ops->txrx_get_total_per)
		return 0;

	return soc->ops->cmn_drv_ops->txrx_get_total_per(soc, pdev_id);
}

/**
 * cdp_set_pdev_dscp_tid_map(): function to change tid values in DSCP-tid map
 * @soc: soc handle
 * @pdev_id: id of pdev handle
 * @map_id: id of the tid map
 * @tos: index value in map that needs to be changed
 * @tid: tid value passed by user
 *
 * Return: void
 */
static inline void cdp_set_pdev_dscp_tid_map(ol_txrx_soc_handle soc,
		uint8_t pdev_id, uint8_t map_id, uint8_t tos, uint8_t tid)
{
	if (!soc || !soc->ops) {
		dp_cdp_debug("Invalid Instance:");
		QDF_BUG(0);
		return;
	}

	if (!soc->ops->cmn_drv_ops ||
	    !soc->ops->cmn_drv_ops->set_pdev_dscp_tid_map)
		return;

	soc->ops->cmn_drv_ops->set_pdev_dscp_tid_map(soc, pdev_id,
			map_id, tos, tid);
}

/**
 * cdp_flush_cache_rx_queue() - flush cache rx queue frame
 * @soc: soc handle
 *
 * Return: None
 */
static inline void cdp_flush_cache_rx_queue(ol_txrx_soc_handle soc)
{
	if (!soc || !soc->ops) {
		dp_cdp_debug("Invalid Instance:");
		QDF_BUG(0);
		return;
	}

	if (!soc->ops->cmn_drv_ops ||
	    !soc->ops->cmn_drv_ops->flush_cache_rx_queue)
		return;
	soc->ops->cmn_drv_ops->flush_cache_rx_queue();
}

/**
 * cdp_txrx_stats_request(): function to map to host and firmware statistics
 * @soc: soc handle
 * @vdev_id: virtual device ID
 * @req: stats request container
 *
 * return: status
 */
static inline
int cdp_txrx_stats_request(ol_txrx_soc_handle soc, uint8_t vdev_id,
			   struct cdp_txrx_stats_req *req)
{
	if (!soc || !soc->ops || !soc->ops->cmn_drv_ops || !req) {
		dp_cdp_debug("Invalid Instance:");
		QDF_ASSERT(0);
		return 0;
	}

	if (soc->ops->cmn_drv_ops->txrx_stats_request)
		return soc->ops->cmn_drv_ops->txrx_stats_request(soc, vdev_id,
								 req);

	return 0;
}

/**
 * cdp_txrx_intr_attach(): function to attach and configure interrupt
 * @soc: soc handle
 */
static inline QDF_STATUS cdp_txrx_intr_attach(ol_txrx_soc_handle soc)
{
	if (!soc || !soc->ops) {
		dp_cdp_debug("Invalid Instance:");
		QDF_BUG(0);
		return 0;
	}

	if (!soc->ops->cmn_drv_ops ||
	    !soc->ops->cmn_drv_ops->txrx_intr_attach)
		return 0;

	return soc->ops->cmn_drv_ops->txrx_intr_attach(soc);
}

/**
 * cdp_txrx_intr_detach(): function to detach interrupt
 * @soc: soc handle
 */
static inline void cdp_txrx_intr_detach(ol_txrx_soc_handle soc)
{
	if (!soc || !soc->ops) {
		dp_cdp_debug("Invalid Instance:");
		QDF_BUG(0);
		return;
	}

	if (!soc->ops->cmn_drv_ops ||
	    !soc->ops->cmn_drv_ops->txrx_intr_detach)
		return;

	soc->ops->cmn_drv_ops->txrx_intr_detach(soc);
}

/**
 * cdp_txrx_ppeds_stop(): function to stop ppeds
 * @soc: soc handle
 */
static inline void cdp_txrx_ppeds_stop(ol_txrx_soc_handle soc)
{
	if (!soc || !soc->ops) {
		dp_cdp_debug("Invalid Instance:");
		QDF_BUG(0);
		return;
	}

	if (!soc->ops->cmn_drv_ops ||
	    !soc->ops->cmn_drv_ops->txrx_ppeds_stop)
		return;

	soc->ops->cmn_drv_ops->txrx_ppeds_stop(soc);
}

/**
 * cdp_txrx_umac_reset_init(): De-initialize UMAC HW reset module
 * @soc: soc handle
 */
static inline void cdp_txrx_umac_reset_init(ol_txrx_soc_handle soc)
{
	if (!soc || !soc->ops) {
		dp_cdp_debug("Invalid Instance:");
		QDF_BUG(0);
		return;
	}

	if (!soc->ops->cmn_drv_ops ||
	    !soc->ops->cmn_drv_ops->txrx_umac_reset_init)
		return;

	soc->ops->cmn_drv_ops->txrx_umac_reset_init(soc);
}

/**
 * cdp_txrx_umac_reset_deinit(): De-initialize UMAC HW reset module
 * @soc: soc handle
 */
static inline void cdp_txrx_umac_reset_deinit(ol_txrx_soc_handle soc)
{
	if (!soc || !soc->ops) {
		dp_cdp_debug("Invalid Instance:");
		QDF_BUG(0);
		return;
	}

	if (!soc->ops->cmn_drv_ops ||
	    !soc->ops->cmn_drv_ops->txrx_umac_reset_deinit)
		return;

	soc->ops->cmn_drv_ops->txrx_umac_reset_deinit(soc);
}

/**
 * cdp_notify_asserted_soc(): function to notify asserted SoC
 * @soc: soc handle
 *
 * Return: QDF_STATUS
 */
static inline QDF_STATUS
cdp_notify_asserted_soc(ol_txrx_soc_handle soc)
{
	if (!soc || !soc->ops) {
		dp_cdp_debug("Invalid Instance:");
		QDF_BUG(0);
		return QDF_STATUS_E_NULL_VALUE;
	}

	if (!soc->ops->cmn_drv_ops ||
	    !soc->ops->cmn_drv_ops->notify_asserted_soc)
		return QDF_STATUS_E_NULL_VALUE;

	return soc->ops->cmn_drv_ops->notify_asserted_soc(soc);
}

/**
 * cdp_display_stats(): function to map to dump stats
 * @soc: soc handle
 * @value: statistics option
 * @level: verbosity level
 */
static inline QDF_STATUS
cdp_display_stats(ol_txrx_soc_handle soc, uint16_t value,
		  enum qdf_stats_verbosity_level level)
{
	if (!soc || !soc->ops) {
		dp_cdp_debug("Invalid Instance:");
		QDF_BUG(0);
		return 0;
	}

	if (!soc->ops->cmn_drv_ops ||
	    !soc->ops->cmn_drv_ops->display_stats)
		return 0;

	return soc->ops->cmn_drv_ops->display_stats(soc, value, level);
}


/**
 * cdp_set_pn_check(): function to set pn check
 * @soc: soc handle
 * @vdev_id: id of virtual device
 * @peer_mac: mac address of peer
 * @sec_type: security type
 * @rx_pn: receive pn
 */
static inline int cdp_set_pn_check(ol_txrx_soc_handle soc,
		uint8_t vdev_id, uint8_t *peer_mac,
		enum cdp_sec_type sec_type,  uint32_t *rx_pn)
{
	if (!soc || !soc->ops) {
		dp_cdp_debug("Invalid Instance:");
		QDF_BUG(0);
		return 0;
	}

	if (!soc->ops->cmn_drv_ops ||
	    !soc->ops->cmn_drv_ops->set_pn_check)
		return 0;

	soc->ops->cmn_drv_ops->set_pn_check(soc, vdev_id, peer_mac,
			sec_type, rx_pn);
	return 0;
}

/**
 * cdp_set_key_sec_type(): function to set sec mode of key
 * @soc: soc handle
 * @vdev_id: id of virtual device
 * @peer_mac: mac address of peer
 * @sec_type: security type
 * @is_unicast: ucast or mcast
 */
static inline int cdp_set_key_sec_type(ol_txrx_soc_handle soc,
				       uint8_t vdev_id,
				       uint8_t *peer_mac,
				       enum cdp_sec_type sec_type,
				       bool is_unicast)
{
	if (!soc || !soc->ops) {
		dp_cdp_debug("Invalid Instance:");
		QDF_BUG(0);
		return 0;
	}

	if (!soc->ops->cmn_drv_ops ||
	    !soc->ops->cmn_drv_ops->set_key_sec_type)
		return 0;

	soc->ops->cmn_drv_ops->set_key_sec_type(soc, vdev_id,
			peer_mac, sec_type, is_unicast);
	return 0;
}

static inline QDF_STATUS
cdp_set_key(ol_txrx_soc_handle soc,
	    uint8_t vdev_id,
	    uint8_t *mac,
	    bool is_unicast, uint32_t *key)
{
	if (!soc || !soc->ops) {
		dp_cdp_debug("Invalid Instance:");
		QDF_BUG(0);
		return QDF_STATUS_E_FAILURE;
	}

	if (!soc->ops->ctrl_ops ||
	    !soc->ops->ctrl_ops->set_key)
		return QDF_STATUS_E_FAILURE;

	return soc->ops->ctrl_ops->set_key(soc, vdev_id, mac,
			is_unicast, key);
}

/**
 * cdp_update_config_parameters(): function to propagate configuration
 *                                 parameters to datapath
 * @soc: opaque soc handle
 * @cfg: configuration handle
 *
 * Return: status: 0 - Success, non-zero: Failure
 */
static inline
QDF_STATUS cdp_update_config_parameters(ol_txrx_soc_handle soc,
	struct cdp_config_params *cfg)
{
	struct cdp_soc *psoc = (struct cdp_soc *)soc;

	if (!soc || !soc->ops) {
		dp_cdp_debug("Invalid Instance:");
		QDF_BUG(0);
		return 0;
	}

	if (!soc->ops->cmn_drv_ops ||
	    !soc->ops->cmn_drv_ops->update_config_parameters)
		return QDF_STATUS_SUCCESS;

	return soc->ops->cmn_drv_ops->update_config_parameters(psoc,
								cfg);
}

/**
 * cdp_pdev_get_dp_txrx_handle() - get advanced dp handle from pdev
 * @soc: opaque soc handle
 * @pdev_id: id of data path pdev handle
 *
 * Return: opaque dp handle
 */
static inline void *
cdp_pdev_get_dp_txrx_handle(ol_txrx_soc_handle soc, uint8_t pdev_id)
{
	if (!soc || !soc->ops) {
		dp_cdp_debug("Invalid Instance:");
		QDF_BUG(0);
		return 0;
	}

	if (soc->ops->cmn_drv_ops->get_dp_txrx_handle)
		return soc->ops->cmn_drv_ops->get_dp_txrx_handle(soc, pdev_id);

	return 0;
}

/**
 * cdp_pdev_set_dp_txrx_handle() - set advanced dp handle in pdev
 * @soc: opaque soc handle
 * @pdev_id: id of data path pdev handle
 * @dp_hdl: opaque pointer for dp_txrx_handle
 *
 * Return: void
 */
static inline void
cdp_pdev_set_dp_txrx_handle(ol_txrx_soc_handle soc, uint8_t pdev_id,
			    void *dp_hdl)
{
	if (!soc || !soc->ops) {
		dp_cdp_debug("Invalid Instance:");
		QDF_BUG(0);
		return;
	}

	if (!soc->ops->cmn_drv_ops ||
			!soc->ops->cmn_drv_ops->set_dp_txrx_handle)
		return;

	soc->ops->cmn_drv_ops->set_dp_txrx_handle(soc, pdev_id, dp_hdl);
}

/**
 * cdp_vdev_get_dp_ext_txrx_handle() - get extended dp handle from vdev
 * @soc: opaque soc handle
 * @vdev_id: vdev id
 *
 * Return: opaque dp handle
 */
static inline void *
cdp_vdev_get_dp_ext_txrx_handle(ol_txrx_soc_handle soc, uint8_t vdev_id)
{
	if (!soc || !soc->ops) {
		dp_cdp_debug("Invalid Instance:");
		QDF_BUG(0);
		return 0;
	}

	if (soc->ops->cmn_drv_ops->get_vdev_dp_ext_txrx_handle)
		return soc->ops->cmn_drv_ops->get_vdev_dp_ext_txrx_handle(
							soc, vdev_id);

	return 0;
}

/**
 * cdp_vdev_set_dp_ext_txrx_handle() - set extended dp handle in vdev
 * @soc: opaque soc handle
 * @vdev_id: vdev id
 * @size: size of the advance dp handle
 *
 * Return: QDF_STATUS
 */
static inline QDF_STATUS
cdp_vdev_set_dp_ext_txrx_handle(ol_txrx_soc_handle soc, uint8_t vdev_id,
				uint16_t size)
{
	if (!soc || !soc->ops) {
		dp_cdp_debug("Invalid Instance:");
		QDF_BUG(0);
		return QDF_STATUS_E_FAILURE;
	}

	if (!soc->ops->cmn_drv_ops ||
	    !soc->ops->cmn_drv_ops->set_vdev_dp_ext_txrx_handle)
		return QDF_STATUS_E_FAILURE;

	return soc->ops->cmn_drv_ops->set_vdev_dp_ext_txrx_handle(soc,
								  vdev_id,
								  size);
}

/**
 * cdp_soc_get_dp_txrx_handle() - get extended dp handle from soc
 * @soc: opaque soc handle
 *
 * Return: opaque extended dp handle
 */
static inline void *
cdp_soc_get_dp_txrx_handle(ol_txrx_soc_handle soc)
{
	if (!soc || !soc->ops) {
		dp_cdp_debug("Invalid Instance:");
		QDF_BUG(0);
		return NULL;
	}

	if (soc->ops->cmn_drv_ops->get_soc_dp_txrx_handle)
		return soc->ops->cmn_drv_ops->get_soc_dp_txrx_handle(
				(struct cdp_soc *) soc);

	return NULL;
}

/**
 * cdp_soc_set_dp_txrx_handle() - set advanced dp handle in soc
 * @soc: opaque soc handle
 * @dp_handle: opaque pointer for dp_txrx_handle
 *
 * Return: void
 */
static inline void
cdp_soc_set_dp_txrx_handle(ol_txrx_soc_handle soc, void *dp_handle)
{
	if (!soc || !soc->ops) {
		dp_cdp_debug("Invalid Instance:");
		QDF_BUG(0);
		return;
	}

	if (!soc->ops->cmn_drv_ops ||
			!soc->ops->cmn_drv_ops->set_soc_dp_txrx_handle)
		return;

	soc->ops->cmn_drv_ops->set_soc_dp_txrx_handle((struct cdp_soc *)soc,
			dp_handle);
}

/**
 * cdp_soc_handle_mode_change() - Update pdev_id to lmac_id mapping
 * @soc: opaque soc handle
 * @pdev_id: id of data path pdev handle
 * @lmac_id: lmac id
 *
 * Return: QDF_STATUS
 */
static inline QDF_STATUS
cdp_soc_handle_mode_change(ol_txrx_soc_handle soc, uint8_t pdev_id,
			   uint32_t lmac_id)
{
	if (!soc || !soc->ops) {
		dp_cdp_debug("Invalid Instance:");
		QDF_BUG(0);
		return QDF_STATUS_E_FAILURE;
	}

	if (!soc->ops->cmn_drv_ops ||
	    !soc->ops->cmn_drv_ops->handle_mode_change)
		return QDF_STATUS_E_FAILURE;

	return soc->ops->cmn_drv_ops->handle_mode_change(soc, pdev_id,
							 lmac_id);
}

/**
 * cdp_soc_map_pdev_to_lmac() - Save pdev_id to lmac_id mapping
 * @soc: opaque soc handle
 * @pdev_id: id of data path pdev handle
 * @lmac_id: lmac id
 * Return: QDF_STATUS
 */
static inline QDF_STATUS
cdp_soc_map_pdev_to_lmac(ol_txrx_soc_handle soc, uint8_t pdev_id,
			 uint32_t lmac_id)
{
	if (!soc || !soc->ops) {
		dp_cdp_debug("Invalid Instance:");
		QDF_BUG(0);
		return QDF_STATUS_E_FAILURE;
	}

	if (!soc->ops->cmn_drv_ops ||
	    !soc->ops->cmn_drv_ops->map_pdev_to_lmac)
		return QDF_STATUS_E_FAILURE;

	return soc->ops->cmn_drv_ops->map_pdev_to_lmac(soc, pdev_id,
			lmac_id);
}

/**
 * cdp_txrx_set_pdev_status_down() - set pdev down/up status
 * @soc: soc opaque handle
 * @pdev_id: id of data path pdev handle
 * @is_pdev_down: pdev down/up status
 *
 * return: QDF_STATUS
 */
static inline QDF_STATUS
cdp_txrx_set_pdev_status_down(ol_txrx_soc_handle soc,
			      uint8_t pdev_id,
			      bool is_pdev_down)
{
	if (!soc || !soc->ops) {
		dp_cdp_debug("Invalid Instance:");
		QDF_BUG(0);
		return QDF_STATUS_E_FAILURE;
	}

	if (!soc->ops->cmn_drv_ops ||
	    !soc->ops->cmn_drv_ops->set_pdev_status_down)
		return QDF_STATUS_E_FAILURE;

	return soc->ops->cmn_drv_ops->set_pdev_status_down(soc, pdev_id,
						    is_pdev_down);
}

/**
 * cdp_set_tx_pause() - Pause or resume tx path
 * @soc: Datapath soc handle
 * @flag: set or clear is_tx_pause
 *
 * Return: None.
 */
static inline
void cdp_set_tx_pause(ol_txrx_soc_handle soc, bool flag)
{
	if (!soc || !soc->ops) {
		dp_cdp_debug("Invalid Instance:");
		QDF_BUG(0);
		return;
	}

	if (!soc->ops->cmn_drv_ops ||
				!soc->ops->cmn_drv_ops->set_tx_pause)
		return;

	soc->ops->cmn_drv_ops->set_tx_pause(soc, flag);
}

/**
 * cdp_tx_send() - enqueue frame for transmission
 * @soc: soc opaque handle
 * @vdev_id: id of VAP device
 * @nbuf: nbuf to be enqueued
 *
 * This API is used by Extended Datapath modules to enqueue frame for
 * transmission
 *
 * Return: void
 */
static inline void
cdp_tx_send(ol_txrx_soc_handle soc, uint8_t vdev_id, qdf_nbuf_t nbuf)
{
	if (!soc || !soc->ops) {
		dp_cdp_debug("Invalid Instance:");
		QDF_BUG(0);
		return;
	}

	if (!soc->ops->cmn_drv_ops ||
			!soc->ops->cmn_drv_ops->tx_send)
		return;

	soc->ops->cmn_drv_ops->tx_send(soc, vdev_id, nbuf);
}

/**
 * cdp_set_pdev_pcp_tid_map() - set pdev pcp-tid-map
 * @soc: opaque soc handle
 * @pdev_id: id of data path pdev handle
 * @pcp: pcp value
 * @tid: tid value
 *
 * This API is used to configure the pcp-to-tid mapping for a pdev.
 *
 * Return: QDF_STATUS_SUCCESS if value set successfully
 *          QDF_STATUS_E_INVAL false if error
 */
static inline
QDF_STATUS cdp_set_pdev_pcp_tid_map(ol_txrx_soc_handle soc,
				    uint8_t pdev_id,
				    uint32_t pcp, uint32_t tid)
{
	if (!soc || !soc->ops) {
		dp_cdp_debug("Invalid Instance");
		return QDF_STATUS_E_INVAL;
	}

	if (!soc->ops->cmn_drv_ops ||
	    !soc->ops->cmn_drv_ops->set_pdev_pcp_tid_map)
		return QDF_STATUS_E_INVAL;

	return soc->ops->cmn_drv_ops->set_pdev_pcp_tid_map(soc, pdev_id,
							   pcp, tid);
}

/**
 * cdp_get_peer_mac_from_peer_id() - get peer mac addr from peer id
 * @soc: opaque soc handle
 * @peer_id: data path peer id
 * @peer_mac: peer_mac
 *
 * Return: QDF_STATUS
 */
static inline
QDF_STATUS cdp_get_peer_mac_from_peer_id(ol_txrx_soc_handle soc,
					 uint32_t peer_id, uint8_t *peer_mac)
{
	if (soc->ops->cmn_drv_ops->txrx_get_peer_mac_from_peer_id)
		return soc->ops->cmn_drv_ops->txrx_get_peer_mac_from_peer_id(
				soc, peer_id, peer_mac);

	return QDF_STATUS_E_INVAL;
}

/**
 * cdp_vdev_tx_lock() - acquire lock
 * @soc: opaque soc handle
 * @vdev_id: id of data path vdev handle
 *
 * Return: void
 */
static inline
void cdp_vdev_tx_lock(ol_txrx_soc_handle soc,
		      uint8_t vdev_id)
{
	if (soc->ops->cmn_drv_ops->txrx_vdev_tx_lock)
		soc->ops->cmn_drv_ops->txrx_vdev_tx_lock(soc, vdev_id);
}

/**
 * cdp_vdev_tx_unlock() - release lock
 * @soc: opaque soc handle
 * @vdev_id: id of data path vdev handle
 *
 * Return: void
 */
static inline
void cdp_vdev_tx_unlock(ol_txrx_soc_handle soc,
			uint8_t vdev_id)
{
	if (soc->ops->cmn_drv_ops->txrx_vdev_tx_unlock)
		soc->ops->cmn_drv_ops->txrx_vdev_tx_unlock(soc, vdev_id);
}

/**
 * cdp_ath_getstats() - get updated athstats
 * @soc: opaque soc handle
 * @id: vdev_id/pdev_id based on type
 * @stats: cdp network device stats structure
 * @type: device type pdev/vdev
 *
 * Return: QDF_STATUS
 */
static inline QDF_STATUS
cdp_ath_getstats(ol_txrx_soc_handle soc,
		 uint8_t id, struct cdp_dev_stats *stats,
		 uint8_t type)
{
	if (soc && soc->ops && soc->ops->cmn_drv_ops->txrx_ath_getstats)
		return soc->ops->cmn_drv_ops->txrx_ath_getstats(soc, id,
								stats, type);

	return QDF_STATUS_E_FAILURE;
}

/**
 * cdp_set_gid_flag() - set groupid flag
 * @soc: opaque soc handle
 * @pdev_id: id of data path pdev handle
 * @mem_status: member status from grp management frame
 * @user_position: user position from grp management frame
 *
 * Return: QDF_STATUS
 */
static inline QDF_STATUS
cdp_set_gid_flag(ol_txrx_soc_handle soc,
		 uint8_t pdev_id, u_int8_t *mem_status,
		 u_int8_t *user_position)
{
	if (soc->ops->cmn_drv_ops->txrx_set_gid_flag)
		return soc->ops->cmn_drv_ops->txrx_set_gid_flag(soc, pdev_id,
							 mem_status,
							 user_position);
	return QDF_STATUS_E_FAILURE;
}

/**
 * cdp_fw_supported_enh_stats_version() - returns the fw enhanced stats version
 * @soc: opaque soc handle
 * @pdev_id: id of data path pdev handle
 *
 */
static inline
uint32_t cdp_fw_supported_enh_stats_version(ol_txrx_soc_handle soc,
					    uint8_t pdev_id)
{
	if (soc->ops->cmn_drv_ops->txrx_fw_supported_enh_stats_version)
		return soc->ops->cmn_drv_ops->txrx_fw_supported_enh_stats_version(soc, pdev_id);
	return 0;
}

/**
 * cdp_if_mgmt_drain() - Drain management frames
 * @soc: opaque soc handle
 * @vdev_id: id of vdev device
 * @force: number of frame in SW queue
 *
 * Return: void
 */
static inline
void cdp_if_mgmt_drain(ol_txrx_soc_handle soc,
		uint8_t vdev_id, int force)
{
	if (soc->ops->cmn_drv_ops->txrx_if_mgmt_drain)
		soc->ops->cmn_drv_ops->txrx_if_mgmt_drain(soc, vdev_id, force);
}

/**
 * cdp_peer_map_attach() - CDP API to allocate PEER map memory
 * @soc: opaque soc handle
 * @max_peers: number of peers created in FW
 * @max_ast_index: max number of AST index supported in FW
 * @peer_map_unmap_v: Indicates HTT peer map/unmap versions enabled in FW
 *
 * Return: QDF_STATUS
 */
static inline QDF_STATUS
cdp_peer_map_attach(ol_txrx_soc_handle soc, uint32_t max_peers,
		    uint32_t max_ast_index, uint8_t peer_map_unmap_v)
{
	if (soc && soc->ops && soc->ops->cmn_drv_ops &&
	    soc->ops->cmn_drv_ops->txrx_peer_map_attach)
		return soc->ops->cmn_drv_ops->txrx_peer_map_attach(soc,
							max_peers,
							max_ast_index,
							peer_map_unmap_v);

	return QDF_STATUS_SUCCESS;
}

/**
 * cdp_soc_set_param() - CDP API to set soc parameters
 * @soc: opaque soc handle
 * @param: parameter type
 * @value: parameter value
 *
 *
 * Return: QDF_STATUS
 */
static inline QDF_STATUS
cdp_soc_set_param(ol_txrx_soc_handle soc, enum cdp_soc_param_t param,
		  uint32_t value)
{
	if (soc && soc->ops && soc->ops->cmn_drv_ops &&
	    soc->ops->cmn_drv_ops->set_soc_param)
		return soc->ops->cmn_drv_ops->set_soc_param(soc, param,
							value);

	return QDF_STATUS_SUCCESS;
}

/**
 * cdp_txrx_classify_and_update() - To classify the packet and update stats
 * @soc: opaque soc handle
 * @vdev_id: vdev id
 * @skb: data
 * @dir: rx or tx packet
 * @nbuf_class: packet classification object
 *
 * Return: 1 on success else return 0
 */
static inline int
cdp_txrx_classify_and_update(ol_txrx_soc_handle soc,
			     uint8_t vdev_id, qdf_nbuf_t skb,
			     enum txrx_direction dir,
			     struct ol_txrx_nbuf_classify *nbuf_class)
{
	if (!soc || !soc->ops) {
		dp_cdp_debug("Invalid Instance");
		QDF_BUG(0);
		return 0;
	}

	if (!soc->ops->cmn_drv_ops ||
	    !soc->ops->cmn_drv_ops->txrx_classify_update)
		return 0;

	return soc->ops->cmn_drv_ops->txrx_classify_update(soc, vdev_id,
							   skb,
							   dir, nbuf_class);
}

/**
 * cdp_get_dp_capabilities() - get DP capabilities
 * @soc: opaque soc handle
 * @dp_caps: enum of DP capabilities
 *
 * Return: bool
 */
static inline bool
cdp_get_dp_capabilities(struct cdp_soc_t *soc, enum cdp_capabilities dp_caps)
{
	if (soc && soc->ops && soc->ops->cmn_drv_ops &&
	    soc->ops->cmn_drv_ops->get_dp_capabilities)
		return soc->ops->cmn_drv_ops->get_dp_capabilities(soc, dp_caps);

	qdf_err("invalid instance");
	return false;
}

#ifdef RECEIVE_OFFLOAD
/**
 * cdp_register_rx_offld_flush_cb() - register LRO/GRO flush cb function pointer
 * @soc: data path soc handle
 * @rx_ol_flush_cb: Flush callback function
 *
 * register rx offload flush callback function pointer
 *
 * Return: none
 */
static inline void cdp_register_rx_offld_flush_cb(ol_txrx_soc_handle soc,
						  void (rx_ol_flush_cb)(void *))
{
	if (!soc || !soc->ops || !soc->ops->rx_offld_ops) {
		QDF_TRACE(QDF_MODULE_ID_DP, QDF_TRACE_LEVEL_FATAL,
			  "%s invalid instance", __func__);
		return;
	}

	if (soc->ops->rx_offld_ops->register_rx_offld_flush_cb)
		return soc->ops->rx_offld_ops->register_rx_offld_flush_cb(
								rx_ol_flush_cb);
}

/**
 * cdp_deregister_rx_offld_flush_cb() - deregister Rx offld flush cb function
 * @soc: data path soc handle
 *
 * deregister rx offload flush callback function pointer
 *
 * Return: none
 */
static inline void cdp_deregister_rx_offld_flush_cb(ol_txrx_soc_handle soc)
{
	if (!soc || !soc->ops || !soc->ops->rx_offld_ops) {
		QDF_TRACE(QDF_MODULE_ID_DP, QDF_TRACE_LEVEL_FATAL,
			  "%s invalid instance", __func__);
		return;
	}

	if (soc->ops->rx_offld_ops->deregister_rx_offld_flush_cb)
		return soc->ops->rx_offld_ops->deregister_rx_offld_flush_cb();
}
#endif /* RECEIVE_OFFLOAD */

/**
 * cdp_set_ba_timeout() - set ba aging timeout per AC
 *
 * @soc: pointer to the soc
 * @value: timeout value in millisec
 * @ac: Access category
 *
 * Return: void
 */
static inline void cdp_set_ba_timeout(ol_txrx_soc_handle soc,
				      uint8_t ac, uint32_t value)
{
	if (!soc || !soc->ops) {
		dp_cdp_debug("Invalid Instance");
		QDF_BUG(0);
		return;
	}

	if (!soc->ops->cmn_drv_ops ||
	    !soc->ops->cmn_drv_ops->txrx_set_ba_aging_timeout)
		return;

	soc->ops->cmn_drv_ops->txrx_set_ba_aging_timeout(soc, ac, value);
}

/**
 * cdp_get_ba_timeout() - return ba aging timeout per AC
 *
 * @soc: pointer to the soc
 * @ac: access category
 * @value: timeout value in millisec
 *
 * Return: void
 */
static inline void cdp_get_ba_timeout(ol_txrx_soc_handle soc,
				      uint8_t ac, uint32_t *value)
{
	if (!soc || !soc->ops) {
		dp_cdp_debug("Invalid Instance");
		QDF_BUG(0);
		return;
	}

	if (!soc->ops->cmn_drv_ops ||
	    !soc->ops->cmn_drv_ops->txrx_get_ba_aging_timeout)
		return;

	soc->ops->cmn_drv_ops->txrx_get_ba_aging_timeout(soc, ac, value);
}

/**
 * cdp_cfg_get() - get cfg for dp enum
 *
 * @soc: pointer to the soc
 * @cfg: cfg enum
 *
 * Return: cfg value
 */
static inline uint32_t cdp_cfg_get(ol_txrx_soc_handle soc, enum cdp_dp_cfg cfg)
{
	if (!soc || !soc->ops) {
		dp_cdp_debug("Invalid Instance");
		return 0;
	}

	if (!soc->ops->cmn_drv_ops || !soc->ops->cmn_drv_ops->txrx_get_cfg)
		return 0;

	return soc->ops->cmn_drv_ops->txrx_get_cfg(soc, cfg);
}

/**
 * cdp_soc_set_rate_stats_ctx() - set rate stats context in soc
 * @soc: opaque soc handle
 * @ctx: rate stats context
 *
 * Return: void
 */
static inline void
cdp_soc_set_rate_stats_ctx(ol_txrx_soc_handle soc,
			   void *ctx)
{
	if (!soc || !soc->ops) {
		dp_cdp_debug("Invalid Instance:");
		QDF_BUG(0);
		return;
	}

	if (!soc->ops->cmn_drv_ops ||
	    !soc->ops->cmn_drv_ops->set_rate_stats_ctx)
		return;

	soc->ops->cmn_drv_ops->set_rate_stats_ctx((struct cdp_soc_t *)soc,
						  ctx);
}

/**
 * cdp_soc_get_rate_stats_ctx() - get rate stats context in soc
 * @soc: opaque soc handle
 *
 * Return: void
 */
static inline void*
cdp_soc_get_rate_stats_ctx(ol_txrx_soc_handle soc)
{
	if (!soc || !soc->ops) {
		dp_cdp_debug("Invalid Instance:");
		QDF_BUG(0);
		return NULL;
	}

	if (!soc->ops->cmn_drv_ops ||
	    !soc->ops->cmn_drv_ops->get_rate_stats_ctx)
		return NULL;

	return soc->ops->cmn_drv_ops->get_rate_stats_ctx(soc);
}

/**
 * cdp_peer_flush_rate_stats() - flush peer rate statistics
 * @soc: opaque soc handle
 * @pdev_id: id of pdev handle
 * @buf: stats buffer
 */
static inline void
cdp_peer_flush_rate_stats(ol_txrx_soc_handle soc, uint8_t pdev_id,
			  void *buf)
{
	if (!soc || !soc->ops) {
		dp_cdp_debug("Invalid Instance:");
		QDF_BUG(0);
		return;
	}

	if (!soc->ops->cmn_drv_ops ||
	    !soc->ops->cmn_drv_ops->txrx_peer_flush_rate_stats)
		return;

	soc->ops->cmn_drv_ops->txrx_peer_flush_rate_stats(soc, pdev_id, buf);
}

/**
 * cdp_peer_get_peerstats_ctx() - get peer stats context
 * @soc: opaque soc handle
 * @vdev_id: id of vdev handle
 * @mac_addr: peer mac address
 */
static inline void
*cdp_peer_get_peerstats_ctx(ol_txrx_soc_handle soc, uint8_t vdev_id,
			    uint8_t *mac_addr)
{
	if (!soc || !soc->ops) {
		dp_cdp_debug("Invalid Instance:");
		QDF_BUG(0);
		return NULL;
	}

	if (!soc->ops->cmn_drv_ops ||
	    !soc->ops->cmn_drv_ops->txrx_peer_get_peerstats_ctx)
		return NULL;

	return soc->ops->cmn_drv_ops->txrx_peer_get_peerstats_ctx(soc,
								  vdev_id,
								  mac_addr);
}

/**
 * cdp_flush_rate_stats_request() - request flush rate statistics
 * @soc: opaque soc handle
 * @pdev_id: id of pdev handle
 */
static inline QDF_STATUS
cdp_flush_rate_stats_request(struct cdp_soc_t *soc, uint8_t pdev_id)
{
	if (!soc || !soc->ops) {
		dp_cdp_debug("Invalid Instance:");
		QDF_BUG(0);
		return QDF_STATUS_E_FAILURE;
	}

	if (!soc->ops->cmn_drv_ops ||
	    !soc->ops->cmn_drv_ops->txrx_flush_rate_stats_request)
		return QDF_STATUS_E_FAILURE;

	return soc->ops->cmn_drv_ops->txrx_flush_rate_stats_request(soc,
								    pdev_id);
}

/**
 * cdp_set_vdev_pcp_tid_map() - set vdev pcp-tid-map
 * @soc: opaque soc handle
 * @vdev_id: id of data path vdev handle
 * @pcp: pcp value
 * @tid: tid value
 *
 * This API is used to configure the pcp-to-tid mapping for a pdev.
 *
 * Return: QDF_STATUS_SUCCESS if value set successfully
 *          QDF_STATUS_E_INVAL false if error
 */
static inline
QDF_STATUS cdp_set_vdev_pcp_tid_map(ol_txrx_soc_handle soc,
				    uint8_t vdev_id,
				    uint8_t pcp, uint8_t tid)
{
	if (!soc || !soc->ops) {
		dp_cdp_debug("Invalid Instance");
		return QDF_STATUS_E_INVAL;
	}

	if (!soc->ops->cmn_drv_ops ||
	    !soc->ops->cmn_drv_ops->set_vdev_pcp_tid_map)
		return QDF_STATUS_E_INVAL;

	return soc->ops->cmn_drv_ops->set_vdev_pcp_tid_map(soc, vdev_id,
							   pcp, tid);
}

/**
 * cdp_tx_send_exc() - Transmit a frame on a given vdev in exception path
 *
 * @soc: opaque soc handle
 * @vdev_id: vdev id
 * @nbuf: skb
 * @tx_exc_metadata: Handle that holds exception path meta data
 *
 * Return: NULL on success
 *         nbuf when it fails to send
 */
static inline qdf_nbuf_t
cdp_tx_send_exc(ol_txrx_soc_handle soc,
		uint8_t vdev_id,
		qdf_nbuf_t nbuf,
		struct cdp_tx_exception_metadata *tx_exc_metadata)
{
	if (!soc || !soc->ops) {
		dp_cdp_debug("Invalid Instance");
		QDF_BUG(0);
		return 0;
	}

	if (!soc->ops->cmn_drv_ops ||
	    !soc->ops->cmn_drv_ops->tx_send_exc)
		return 0;

	return soc->ops->cmn_drv_ops->tx_send_exc
			(soc, vdev_id, nbuf, tx_exc_metadata);
}

/**
 * cdp_vdev_get_peer_mac_list(): function to get peer mac list of vdev
 * @soc: Datapath soc handle
 * @vdev_id: vdev id
 * @newmac: Table of the clients mac
 * @mac_cnt: No. of MACs required
 * @limit: Limit the number of clients
 *
 * return: no of clients
 */
static inline uint16_t
cdp_vdev_get_peer_mac_list(ol_txrx_soc_handle soc,
			   uint8_t vdev_id,
			   uint8_t newmac[][QDF_MAC_ADDR_SIZE],
			   uint16_t mac_cnt, bool limit)
{
	if (!soc || !soc->ops) {
		dp_cdp_debug("Invalid Instance");
		QDF_BUG(0);
		return 0;
	}

	if (!soc->ops->cmn_drv_ops ||
	    !soc->ops->cmn_drv_ops->get_peer_mac_list)
		return 0;

	return soc->ops->cmn_drv_ops->get_peer_mac_list
			(soc, vdev_id, newmac, mac_cnt, limit);
}

/**
 * cdp_soc_config_full_mon_mode () - Configure Full monitor mode
 *
 * @soc: dp soc handle
 * @val: value to be configured val should be 0 or 1
 *
 * This API is used to enable/disable support for Full monitor mode feature
 *
 * Return: QDF_STATUS_SUCCESS if value set successfully
 *         QDF_STATUS_E_INVAL false if error
 */
static inline QDF_STATUS
cdp_soc_config_full_mon_mode(ol_txrx_soc_handle soc, uint8_t val)
{
	if (!soc || !soc->ops) {
		dp_cdp_debug("Invalid Instance");
		return QDF_STATUS_E_INVAL;
	}

	if (!soc->ops->mon_ops ||
	    !soc->ops->mon_ops->config_full_mon_mode)
		return QDF_STATUS_E_INVAL;

	return soc->ops->mon_ops->config_full_mon_mode(soc, val);
}

/**
 * cdp_rx_get_pending() - Get number of pending frames of RX threads
 * @soc: opaque soc handle
 * Return: number of pending frames
 */
static inline int
cdp_rx_get_pending(ol_txrx_soc_handle soc)
{
	if (!soc || !soc->ol_ops ||
	    !soc->ol_ops->dp_rx_get_pending)
		return 0;

	if (cdp_cfg_get(soc, cfg_dp_wow_check_rx_pending))
		return soc->ol_ops->dp_rx_get_pending(soc);
	else
		return 0;
}

static inline uint16_t
cdp_get_peer_id(ol_txrx_soc_handle soc, uint8_t vdev_id, uint8_t *mac)
{
	if (!soc || !soc->ops) {
		dp_cdp_debug("Invalid Instance");
		QDF_BUG(0);
		return 0;
	}

	if (!soc->ops->cmn_drv_ops ||
	    !soc->ops->cmn_drv_ops->get_peer_id)
		return 0;

	return soc->ops->cmn_drv_ops->get_peer_id
			(soc, vdev_id, mac);
}

#ifdef QCA_SUPPORT_WDS_EXTENDED
static inline QDF_STATUS
cdp_wds_ext_set_peer_rx(ol_txrx_soc_handle soc, uint8_t vdev_id,
			uint8_t *mac, ol_txrx_rx_fp rx,
			ol_osif_peer_handle osif_peer)
{
	if (!soc || !soc->ops) {
		dp_cdp_debug("Invalid Instance");
		QDF_BUG(0);
		return QDF_STATUS_E_FAULT;
	}

	if (!soc->ops->cmn_drv_ops ||
	    !soc->ops->cmn_drv_ops->set_wds_ext_peer_rx)
		return QDF_STATUS_E_FAULT;

	return soc->ops->cmn_drv_ops->set_wds_ext_peer_rx
			(soc, vdev_id, mac, rx, osif_peer);
}

static inline QDF_STATUS
cdp_wds_ext_get_peer_osif_handle(
			ol_txrx_soc_handle soc, uint8_t vdev_id,
			uint8_t *mac,
			ol_osif_peer_handle *osif_peer)
{
	if (!soc || !soc->ops) {
		dp_cdp_debug("Invalid Instance");
		QDF_BUG(0);
		return QDF_STATUS_E_FAULT;
	}

	if (!soc->ops->cmn_drv_ops ||
	    !soc->ops->cmn_drv_ops->get_wds_ext_peer_osif_handle)
		return QDF_STATUS_E_FAULT;

	return soc->ops->cmn_drv_ops->get_wds_ext_peer_osif_handle
			(soc, vdev_id, mac, osif_peer);
}

/**
 * cdp_wds_ext_set_bit() - set wds-ext peer bit
 * @soc: soc handle
 * @mac: peer mac address
 *
 * Return: QDF_STATUS
 */
static inline QDF_STATUS
cdp_wds_ext_set_bit(ol_txrx_soc_handle soc, uint8_t *mac)
{
	if (!soc || !soc->ops) {
		dp_cdp_debug("Invalid Instance");
		QDF_BUG(0);
		return QDF_STATUS_E_FAULT;
	}

	if (!soc->ops->cmn_drv_ops ||
	    !soc->ops->cmn_drv_ops->set_wds_ext_peer_bit)
		return QDF_STATUS_E_FAULT;

	return soc->ops->cmn_drv_ops->set_wds_ext_peer_bit(soc, mac);
}
#endif /* QCA_SUPPORT_WDS_EXTENDED */

/**
 * cdp_drain_txrx() - drain TX/RX SRNGs
 * @soc: opaque soc handle
 */
static inline void
cdp_drain_txrx(ol_txrx_soc_handle soc)
{
	if (!soc || !soc->ops) {
		dp_cdp_debug("Invalid Instance");
		QDF_BUG(0);
		return;
	}

	if (!soc->ops->cmn_drv_ops ||
	    !soc->ops->cmn_drv_ops->txrx_drain)
		return;

	return soc->ops->cmn_drv_ops->txrx_drain(soc);
}

/**
 * cdp_get_free_desc_poolsize() - get free desc pool size
 * @soc: opaque soc handle
 */
static inline int
cdp_get_free_desc_poolsize(ol_txrx_soc_handle soc)
{
	if (!soc || !soc->ops) {
		dp_cdp_debug("Invalid Instance");
		QDF_BUG(0);
		return 0;
	}

	if (!soc->ops->cmn_drv_ops ||
	    !soc->ops->cmn_drv_ops->get_free_desc_poolsize)
		return 0;

	return soc->ops->cmn_drv_ops->get_free_desc_poolsize(soc);
}

#ifdef WLAN_FEATURE_PKT_CAPTURE_V2
/**
 * cdp_set_pkt_capture_mode() - set pkt capture mode in dp ctx
 * @soc: opaque soc handle
 * @val: value to be set
 */
static inline void
cdp_set_pkt_capture_mode(ol_txrx_soc_handle soc, bool val)
{
	if (!soc || !soc->ops) {
		dp_cdp_debug("Invalid Instance");
		QDF_BUG(0);
		return;
	}

	if (!soc->ops->cmn_drv_ops ||
	    !soc->ops->cmn_drv_ops->set_pkt_capture_mode)
		return;

	soc->ops->cmn_drv_ops->set_pkt_capture_mode(soc, val);
}
#else
static inline void
cdp_set_pkt_capture_mode(ol_txrx_soc_handle soc, bool val)
{
}
#endif

/**
 * cdp_get_tx_inqueue() - Get number of Tx frames that are queued
 * @soc: opaque soc handle
 *
 * Return: number of queued frames
 */
static inline uint32_t
cdp_get_tx_inqueue(ol_txrx_soc_handle soc)
{
	if (!soc || !soc->ol_ops ||
	    !soc->ol_ops->dp_get_tx_inqueue)
		return 0;

	return soc->ol_ops->dp_get_tx_inqueue(soc);
}

#ifdef FEATURE_RUNTIME_PM

/**
 * cdp_set_rtpm_tput_policy_requirement() - Set RTPM throughput policy
 * @soc: opaque soc handle
 * @is_high_tput: flag indicating whether throughput requirement is high or not
 *
 * The functions sets RTPM throughput policy requirement. If 'is_high_tput' is
 * set, the expectation is that runtime_pm APIs will not be invoked per packet.
 */

static inline
void cdp_set_rtpm_tput_policy_requirement(ol_txrx_soc_handle soc,
					  bool is_high_tput)
{
	if (!soc || !soc->ops) {
		dp_cdp_debug("Invalid Instance");
		QDF_BUG(0);
		return;
	}

	if (!soc->ops->cmn_drv_ops ||
	    !soc->ops->cmn_drv_ops->set_rtpm_tput_policy)
		return;

	soc->ops->cmn_drv_ops->set_rtpm_tput_policy(soc, is_high_tput);
}
#else
static inline
void cdp_set_rtpm_tput_policy_requirement(ol_txrx_soc_handle soc,
					  bool is_high_tput)
{
}

#endif /* FEATURE_RUNTIME_PM */

/**
 * cdp_enable_mon_reap_timer() - enable/disable reap timer
 * @soc: Datapath soc handle
 * @source: monitor reap source
 * @enable: enable/disable reap timer of monitor status ring
 *
 * Return: true if timer start/stop is performed, false otherwise.
 */
static inline bool
cdp_enable_mon_reap_timer(ol_txrx_soc_handle soc,
			  enum cdp_mon_reap_source source,
			  bool enable)
{
	if (!soc || !soc->ops) {
		QDF_TRACE(QDF_MODULE_ID_DP, QDF_TRACE_LEVEL_FATAL,
			  "%s invalid instance", __func__);
		QDF_BUG(0);
		return false;
	}

	if (!soc->ops->mon_ops ||
	    !soc->ops->mon_ops->txrx_enable_mon_reap_timer)
		return false;

	return soc->ops->mon_ops->txrx_enable_mon_reap_timer(soc, source,
							     enable);
}

/**
 * cdp_get_tsf_time() - get tsf time
 * @soc: Datapath soc handle
 * @tsf_id:
 * @mac_id: mac_id
 * @tsf: pointer to update tsf value
 * @tsf_sync_soc_time: pointer to update tsf sync time
 *
 * Return: None.
 */
static inline void
cdp_get_tsf_time(ol_txrx_soc_handle soc, uint32_t tsf_id, uint32_t mac_id,
		 uint64_t *tsf, uint64_t *tsf_sync_soc_time)
{
	if (!soc) {
		dp_cdp_debug("Invalid Instance");
		return;
	}
	if (!soc->ops->cmn_drv_ops || !soc->ops->cmn_drv_ops->txrx_get_tsf_time)
		return;

	soc->ops->cmn_drv_ops->txrx_get_tsf_time(soc, tsf_id, mac_id, tsf,
						 tsf_sync_soc_time);
}

/**
 * cdp_get_tsf2_offset() - get tsf2 offset
 * @soc: Datapath soc handle
 * @mac_id: mac_id
 * @value: pointer to update tsf2 value
 *
 * Return: None.
 */
static inline void
cdp_get_tsf2_offset(ol_txrx_soc_handle soc, uint8_t mac_id, uint64_t *value)
{
	if (!soc) {
		dp_cdp_debug("Invalid Instance");
		return;
	}
	if (!soc->ops->cmn_drv_ops ||
	    !soc->ops->cmn_drv_ops->txrx_get_tsf2_offset)
		return;

	soc->ops->cmn_drv_ops->txrx_get_tsf2_offset(soc, mac_id, value);
}

/**
 * cdp_get_tqm_offset() - get tqm offset
 * @soc: Datapath soc handle
 * @value: pointer to update tqm value
 *
 * Return: None.
 */
static inline void
cdp_get_tqm_offset(ol_txrx_soc_handle soc, uint64_t *value)
{
	if (!soc) {
		dp_cdp_debug("Invalid Instance");
		return;
	}
	if (!soc->ops->cmn_drv_ops ||
	    !soc->ops->cmn_drv_ops->txrx_get_tqm_offset)
		return;

	soc->ops->cmn_drv_ops->txrx_get_tqm_offset(soc, value);
}

static inline uint64_t cdp_get_fst_cem_base(ol_txrx_soc_handle soc,
					    uint64_t size)
{
	if (!soc) {
		dp_cdp_debug("Invalid Instance");
		return 0;
	}

	if (!soc->ops->cmn_drv_ops ||
	    !soc->ops->cmn_drv_ops->get_fst_cmem_base)
		return 0;

	return soc->ops->cmn_drv_ops->get_fst_cmem_base(soc, size);
}

#if defined(WLAN_FEATURE_11BE_MLO)
/*
 * cdp_mlo_dev_ctxt_create - DP MLO Device context create
 * @soc: soc handle
 * @mld_mac_addr: MLD MAC Address
 *
 * return: QDF_STATUS
 */
static inline
QDF_STATUS cdp_mlo_dev_ctxt_create(ol_txrx_soc_handle soc,
				   uint8_t *mld_mac_addr)
{
	if (!soc || !soc->ops) {
		QDF_BUG(0);
		return QDF_STATUS_E_FAILURE;
	}

	if (!soc->ops->cmn_mlo_ops ||
	    !soc->ops->cmn_mlo_ops->mlo_dev_ctxt_create)
		return QDF_STATUS_E_FAILURE;

	return soc->ops->cmn_mlo_ops->mlo_dev_ctxt_create(soc, mld_mac_addr);
}

/*
 * cdp_mlo_dev_ctxt_destroy - DP MLO Device context destroy
 * @soc: soc handle
 * @mld_mac_addr: MLD MAC Address
 *
 * return: QDF_STATUS
 */
static inline
QDF_STATUS cdp_mlo_dev_ctxt_destroy(ol_txrx_soc_handle soc,
				    uint8_t *mld_mac_addr)
{
	if (!soc || !soc->ops) {
		QDF_BUG(0);
		return QDF_STATUS_E_FAILURE;
	}

	if (!soc->ops->cmn_mlo_ops ||
	    !soc->ops->cmn_mlo_ops->mlo_dev_ctxt_destroy)
		return QDF_STATUS_E_FAILURE;

	return soc->ops->cmn_mlo_ops->mlo_dev_ctxt_destroy(soc, mld_mac_addr);
}

/*
 * cdp_mlo_dev_ctxt_attach - DP MLO Device context attach vdev
 * @soc: soc handle
 * @vdev_id: vdev id
 * @mld_mac_addr: MLD MAC Address
 *
 * return: QDF_STATUS
 */
static inline
QDF_STATUS cdp_mlo_dev_ctxt_attach(ol_txrx_soc_handle soc,
				   uint8_t vdev_id,
				   uint8_t *mld_mac_addr)
{
	if (!soc || !soc->ops) {
		QDF_BUG(0);
		return QDF_STATUS_E_FAILURE;
	}

	if (!soc->ops->cmn_mlo_ops ||
	    !soc->ops->cmn_mlo_ops->mlo_dev_ctxt_attach)
		return QDF_STATUS_E_FAILURE;

	return soc->ops->cmn_mlo_ops->mlo_dev_ctxt_attach(soc, vdev_id,
							  mld_mac_addr);
}

/*
 * cdp_mlo_dev_ctxt_detach - DP MLO Device context detach vdev
 * @soc: soc handle
 * @vdev_id: vdev id
 * @mld_mac_addr: MLD MAC Address
 *
 * return: QDF_STATUS
 */
static inline
QDF_STATUS cdp_mlo_dev_ctxt_detach(ol_txrx_soc_handle soc,
				   uint8_t vdev_id,
				   uint8_t *mld_mac_addr)
{
	if (!soc || !soc->ops) {
		QDF_BUG(0);
		return QDF_STATUS_E_FAILURE;
	}

	if (!soc->ops->cmn_mlo_ops ||
	    !soc->ops->cmn_mlo_ops->mlo_dev_ctxt_detach)
		return QDF_STATUS_E_FAILURE;

	return soc->ops->cmn_mlo_ops->mlo_dev_ctxt_detach(soc, vdev_id,
							  mld_mac_addr);
}
#else
static inline
QDF_STATUS cdp_mlo_dev_ctxt_create(ol_txrx_soc_handle soc,
				   uint8_t *mld_mac_addr)
{
	return QDF_STATUS_SUCCESS;
}

static inline
QDF_STATUS cdp_mlo_dev_ctxt_destroy(ol_txrx_soc_handle soc,
				    uint8_t *mld_mac_addr)
{
	return QDF_STATUS_SUCCESS;
}

static inline
QDF_STATUS cdp_mlo_dev_ctxt_attach(ol_txrx_soc_handle soc,
				   uint8_t vdev_id,
				   uint8_t *mld_mac_addr)
{
	return QDF_STATUS_SUCCESS;
}

static inline
QDF_STATUS cdp_mlo_dev_ctxt_detach(ol_txrx_soc_handle soc,
				   uint8_t vdev_id,
				   uint8_t *mld_mac_addr)
{
	return QDF_STATUS_SUCCESS;
}
#endif /* WLAN_FEATURE_11BE_MLO */

#ifdef WLAN_SUPPORT_DPDK
/*
 * cdp_dpdk_get_ring_info - get dp ring info for dpdk
 * @soc: soc handle
 * @uio_info: pointer to fill dp ring info
 *
 * Return: none
 */
static inline void cdp_dpdk_get_ring_info(ol_txrx_soc_handle soc,
					  qdf_uio_info_t *uio_info)
{
	if (!soc) {
		dp_cdp_debug("Invalid Instance");
		return;
	}

	if (!soc->ops->cmn_drv_ops ||
	    !soc->ops->cmn_drv_ops->dpdk_get_ring_info)
		return;

	soc->ops->cmn_drv_ops->dpdk_get_ring_info(soc, uio_info);
}
#endif
#endif /* _CDP_TXRX_CMN_H_ */
