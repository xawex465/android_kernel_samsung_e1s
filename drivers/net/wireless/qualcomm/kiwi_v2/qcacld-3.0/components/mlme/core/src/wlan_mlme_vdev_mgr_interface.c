/*
 * Copyright (c) 2018-2021 The Linux Foundation. All rights reserved.
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
 * DOC: define internal APIs related to the mlme component, legacy APIs are
 *	called for the time being, but will be cleaned up after convergence
 */
#include "wlan_mlme_main.h"
#include "wlan_mlme_vdev_mgr_interface.h"
#include "lim_utils.h"
#include "wma_api.h"
#include "wma.h"
#include "lim_types.h"
#include <include/wlan_mlme_cmn.h>
#include <../../core/src/vdev_mgr_ops.h>
#include "wlan_psoc_mlme_api.h"
#include "target_if_cm_roam_offload.h"
#include "wlan_crypto_global_api.h"
#include "target_if_wfa_testcmd.h"
#include <../../core/src/wlan_cm_vdev_api.h>
#include "csr_api.h"
#include <cm_utf.h>
#include "target_if_cm_roam_event.h"
#include "wlan_cm_roam_api.h"
#include "wifi_pos_api.h"
#ifdef WLAN_FEATURE_11BE_MLO
#include <wlan_mlo_mgr_public_structs.h>
#include <wlan_mlo_mgr_cmn.h>
#include <lim_mlo.h>
#include "wlan_mlo_mgr_sta.h"
#endif
#include <wlan_lmac_if_def.h>
#include "target_if_mlme.h"

static struct vdev_mlme_ops sta_mlme_ops;
static struct vdev_mlme_ops ap_mlme_ops;
static struct vdev_mlme_ops mon_mlme_ops;
static struct mlme_ext_ops ext_ops;
#ifdef WLAN_FEATURE_11BE_MLO
static struct mlo_mlme_ext_ops mlo_ext_ops;
#endif

bool mlme_is_vdev_in_beaconning_mode(enum QDF_OPMODE vdev_opmode)
{
	switch (vdev_opmode) {
	case QDF_SAP_MODE:
	case QDF_P2P_GO_MODE:
	case QDF_IBSS_MODE:
	case QDF_NDI_MODE:
		return true;
	default:
		return false;
	}
}

/**
 * mlme_get_global_ops() - Register ext global ops
 *
 * Return: ext_ops global ops
 */
static struct mlme_ext_ops *mlme_get_global_ops(void)
{
	return &ext_ops;
}

QDF_STATUS mlme_register_mlme_ext_ops(void)
{
	mlme_set_ops_register_cb(mlme_get_global_ops);

	/* Overwrite with UTF cb if UTF enabled */
	cm_utf_set_mlme_ops(mlme_get_global_ops());
	return QDF_STATUS_SUCCESS;
}

#ifdef WLAN_FEATURE_11BE_MLO
QDF_STATUS mlme_register_mlo_ext_ops(void)
{
	QDF_STATUS status;
	struct mlo_mgr_context *mlo_ctx = wlan_objmgr_get_mlo_ctx();

	if (!mlo_ctx)
		return QDF_STATUS_E_FAILURE;

	mlo_reg_mlme_ext_cb(mlo_ctx, &mlo_ext_ops);

	status = mlo_mgr_register_link_switch_notifier(WLAN_UMAC_COMP_MLME,
						       wlan_cm_link_switch_notif_cb);
	if (status == QDF_STATUS_E_NOSUPPORT) {
		status = QDF_STATUS_SUCCESS;
		mlme_debug("Link switch not supported");
	} else if (QDF_IS_STATUS_ERROR(status)) {
		mlme_err("Failed to register link switch notifier for mlme!");
	}

	return status;
}

QDF_STATUS mlme_unregister_mlo_ext_ops(void)
{
	struct mlo_mgr_context *mlo_ctx = wlan_objmgr_get_mlo_ctx();

	if (mlo_ctx)
		mlo_unreg_mlme_ext_cb(mlo_ctx);

	return QDF_STATUS_SUCCESS;
}
#else
QDF_STATUS mlme_register_mlo_ext_ops(void)
{
	return QDF_STATUS_SUCCESS;
}

QDF_STATUS mlme_unregister_mlo_ext_ops(void)
{
	return QDF_STATUS_SUCCESS;
}
#endif
/**
 * mlme_register_vdev_mgr_ops() - Register vdev mgr ops
 * @vdev_mlme: vdev mlme object
 *
 * This function is called to register vdev manager operations
 *
 * Return: QDF_STATUS
 */
QDF_STATUS mlme_register_vdev_mgr_ops(struct vdev_mlme_obj *vdev_mlme)
{
	struct wlan_objmgr_vdev *vdev;

	vdev = vdev_mlme->vdev;

	if (mlme_is_vdev_in_beaconning_mode(vdev->vdev_mlme.vdev_opmode))
		vdev_mlme->ops = &ap_mlme_ops;
	else if (vdev->vdev_mlme.vdev_opmode == QDF_MONITOR_MODE)
		vdev_mlme->ops = &mon_mlme_ops;
	else
		vdev_mlme->ops = &sta_mlme_ops;

	return QDF_STATUS_SUCCESS;
}

/**
 * mlme_unregister_vdev_mgr_ops() - Unregister vdev mgr ops
 * @vdev_mlme: vdev mlme object
 *
 * This function is called to unregister vdev manager operations
 *
 * Return: QDF_STATUS
 */
QDF_STATUS mlme_unregister_vdev_mgr_ops(struct vdev_mlme_obj *vdev_mlme)
{
	return QDF_STATUS_SUCCESS;
}

/**
 * sta_mlme_vdev_start_send() - MLME vdev start callback
 * @vdev_mlme: vdev mlme object
 * @event_data_len: event data length
 * @event_data: event data
 *
 * This function is called to initiate actions of VDEV.start
 *
 * Return: QDF_STATUS
 */
static QDF_STATUS sta_mlme_vdev_start_send(struct vdev_mlme_obj *vdev_mlme,
					   uint16_t event_data_len,
					   void *event_data)
{
	mlme_legacy_debug("vdev id = %d ",
			  vdev_mlme->vdev->vdev_objmgr.vdev_id);
	return lim_sta_mlme_vdev_start_send(vdev_mlme, event_data_len,
					    event_data);
}

/**
 * sta_mlme_start_continue() - vdev start rsp callback
 * @vdev_mlme: vdev mlme object
 * @data_len: event data length
 * @data: event data
 *
 * This function is called to handle the VDEV START/RESTART callback
 *
 * Return: QDF_STATUS
 */
static QDF_STATUS sta_mlme_start_continue(struct vdev_mlme_obj *vdev_mlme,
					  uint16_t data_len, void *data)
{
	mlme_legacy_debug("vdev id = %d ",
			  vdev_mlme->vdev->vdev_objmgr.vdev_id);
	return wma_sta_mlme_vdev_start_continue(vdev_mlme, data_len, data);
}

/**
 * sta_mlme_vdev_restart_send() - MLME vdev restart send
 * @vdev_mlme: vdev mlme object
 * @event_data_len: event data length
 * @event_data: event data
 *
 * This function is called to initiate actions of VDEV.start
 *
 * Return: QDF_STATUS
 */
static QDF_STATUS sta_mlme_vdev_restart_send(struct vdev_mlme_obj *vdev_mlme,
					     uint16_t event_data_len,
					     void *event_data)
{
	mlme_legacy_debug("vdev id = %d ",
			  vdev_mlme->vdev->vdev_objmgr.vdev_id);
	return lim_sta_mlme_vdev_restart_send(vdev_mlme, event_data_len,
					    event_data);
}

/**
 * sta_mlme_vdev_start_req_failed() - MLME start fail callback
 * @vdev_mlme: vdev mlme object
 * @data_len: event data length
 * @data: event data
 *
 * This function is called to send the vdev stop to firmware
 *
 * Return: QDF_STATUS
 */
static QDF_STATUS sta_mlme_vdev_start_req_failed(struct vdev_mlme_obj *vdev_mlme,
						 uint16_t data_len,
						 void *data)
{
	mlme_legacy_debug("vdev id = %d ",
			  vdev_mlme->vdev->vdev_objmgr.vdev_id);
	return lim_sta_mlme_vdev_req_fail(vdev_mlme, data_len, data);
}

/**
 * sta_mlme_vdev_start_connection() - MLME vdev start callback
 * @vdev_mlme: vdev mlme object
 * @event_data_len: event data length
 * @event_data: event data
 *
 * This function is called to initiate actions of STA connection
 *
 * Return: QDF_STATUS
 */
static QDF_STATUS sta_mlme_vdev_start_connection(struct vdev_mlme_obj *vdev_mlme,
						 uint16_t event_data_len,
						 void *event_data)
{
	mlme_legacy_debug("vdev id = %d ",
			  vdev_mlme->vdev->vdev_objmgr.vdev_id);
	return QDF_STATUS_SUCCESS;
}

#if defined WLAN_FEATURE_SR
int mlme_sr_is_enable(struct wlan_objmgr_vdev *vdev)
{
	uint8_t sr_ctrl;

	sr_ctrl = wlan_vdev_mlme_get_sr_ctrl(vdev);
	return (!sr_ctrl || !(sr_ctrl & NON_SRG_PD_SR_DISALLOWED) ||
		(sr_ctrl & SRG_INFO_PRESENT));
}

/**
 * mlme_sr_handle_conc(): Handle concurrency scenario i.e Single MAC
 * concurrency is not supoprted for SR, Disable SR if it is enable on other
 * VDEV and enable it back once the once the concurrent vdev is down.
 *
 * @vdev: object manager vdev
 * @conc_vdev: cuncurrent vdev object
 * @en_sr_curr_vdev: indicates spatial reuse enable/disable
 *
 */
static void
mlme_sr_handle_conc(struct wlan_objmgr_vdev *vdev,
		    struct wlan_objmgr_vdev *conc_vdev, bool en_sr_curr_vdev)
{
	uint32_t val = 0;
	struct wlan_objmgr_pdev *pdev;
	struct wlan_objmgr_psoc *psoc;
	struct wlan_lmac_if_tx_ops *tx_ops;
	struct wlan_lmac_if_spatial_reuse_tx_ops *sr_tx_ops;
	uint8_t conc_vdev_id = wlan_vdev_get_id(conc_vdev);

	pdev = wlan_vdev_get_pdev(vdev);
	if (!pdev) {
		mlme_err("pdev is NULL");
		return;
	}

	psoc = wlan_vdev_get_psoc(vdev);
	tx_ops = wlan_psoc_get_lmac_if_txops(psoc);
	if (!tx_ops) {
		mlme_err("tx_ops is NULL");
		return;
	}

	sr_tx_ops = &tx_ops->spatial_reuse_tx_ops;
	if (en_sr_curr_vdev) {
		wlan_vdev_mlme_set_sr_disable_due_conc(vdev, true);
		wlan_vdev_mlme_set_sr_disable_due_conc(conc_vdev, true);

		if (!wlan_vdev_mlme_get_he_spr_enabled(conc_vdev))
			return;

		if (mlme_sr_is_enable(conc_vdev)) {
			if (sr_tx_ops->target_if_sr_update)
				sr_tx_ops->target_if_sr_update
						(pdev, conc_vdev_id, val);

			wlan_spatial_reuse_osif_event(conc_vdev,
						      SR_OPERATION_SUSPEND,
						   SR_REASON_CODE_CONCURRENCY);
		}
	} else if (wlan_vdev_mlme_is_sr_disable_due_conc(conc_vdev)) {
		wlan_vdev_mlme_set_sr_disable_due_conc(conc_vdev, false);

		if (!wlan_vdev_mlme_get_he_spr_enabled(conc_vdev))
			return;

		if (mlme_sr_is_enable(conc_vdev)) {
			wlan_mlme_update_sr_data(conc_vdev, &val, 0, 0, true);

			if (sr_tx_ops->target_if_sr_update)
				sr_tx_ops->target_if_sr_update
						(pdev, conc_vdev_id, val);

			wlan_spatial_reuse_osif_event(conc_vdev,
						      SR_OPERATION_RESUME,
						      SR_REASON_CODE_CONCURRENCY);
		} else {
			mlme_debug("SR Disabled in SR Control");
		}
	}
}

void mlme_sr_update(struct wlan_objmgr_vdev *vdev, bool enable)
{
	struct wlan_objmgr_vdev *conc_vdev;
	struct wlan_objmgr_psoc *psoc;
	struct wlan_objmgr_pdev *pdev;
	struct wlan_lmac_if_tx_ops *tx_ops;
	uint32_t conc_vdev_id;
	uint32_t val = 0;
	uint8_t vdev_id;
	uint8_t mac_id;

	if (!vdev) {
		mlme_err("vdev is NULL");
		return;
	}
	vdev_id = wlan_vdev_get_id(vdev);

	pdev = wlan_vdev_get_pdev(vdev);
	if (!pdev) {
		mlme_err("pdev is NULL");
		return;
	}

	psoc = wlan_vdev_get_psoc(vdev);
	if (!psoc) {
		mlme_err("psoc is NULL");
		return;
	}

	policy_mgr_get_mac_id_by_session_id(psoc, vdev_id, &mac_id);
	conc_vdev_id = policy_mgr_get_conc_vdev_on_same_mac(psoc, vdev_id,
							    mac_id);
	if (conc_vdev_id != WLAN_INVALID_VDEV_ID &&
	    !policy_mgr_sr_same_mac_conc_enabled(psoc)) {
		/*
		 * Single MAC concurrency is not supoprted for SR,
		 * Disable SR if it is enable on other VDEV and enable
		 * it back once the once the concurrent vdev is down.
		 */
		mlme_debug("SR with concurrency is not allowed");
		conc_vdev =
		wlan_objmgr_get_vdev_by_id_from_psoc(psoc, conc_vdev_id,
						     WLAN_MLME_SB_ID);
		if (!conc_vdev) {
			mlme_err("Can't get vdev by vdev_id:%d", conc_vdev_id);
		} else {
			mlme_sr_handle_conc(vdev, conc_vdev, enable);
			wlan_objmgr_vdev_release_ref(conc_vdev,
						     WLAN_MLME_SB_ID);
			goto err;
		}
	}

	if (!wlan_vdev_mlme_get_he_spr_enabled(vdev)) {
		mlme_err("Spatial Reuse disabled for vdev_id: %d", vdev_id);
		goto err;
	}

	if (mlme_sr_is_enable(vdev)) {
		if (enable) {
			wlan_mlme_update_sr_data(vdev, &val, 0, 0, true);
		} else {
			/* VDEV down, disable SR */
			wlan_vdev_mlme_set_he_spr_enabled(vdev, false);
			wlan_vdev_mlme_set_sr_ctrl(vdev, 0);
			wlan_vdev_mlme_set_non_srg_pd_offset(vdev, 0);
		}

		mlme_debug("SR param val: %x, Enable: %x", val, enable);

		tx_ops = wlan_psoc_get_lmac_if_txops(psoc);
		if (tx_ops && tx_ops->spatial_reuse_tx_ops.target_if_sr_update)
			tx_ops->spatial_reuse_tx_ops.target_if_sr_update
							(pdev, vdev_id, val);
	} else {
		mlme_debug("Spatial reuse is disabled in SR control");
	}
err:
	return;
}
#endif

/**
 * sta_mlme_vdev_up_send() - MLME vdev UP callback
 * @vdev_mlme: vdev mlme object
 * @event_data_len: event data length
 * @event_data: event data
 *
 * This function is called to send the vdev up command
 *
 * Return: QDF_STATUS
 */
static QDF_STATUS sta_mlme_vdev_up_send(struct vdev_mlme_obj *vdev_mlme,
					uint16_t event_data_len,
					void *event_data)
{
	QDF_STATUS status;

	mlme_legacy_debug("vdev id = %d ",
			  vdev_mlme->vdev->vdev_objmgr.vdev_id);
	status = wma_sta_vdev_up_send(vdev_mlme, event_data_len, event_data);

	if (QDF_IS_STATUS_SUCCESS(status))
		mlme_sr_update(vdev_mlme->vdev, true);

	return status;
}

/**
 * sta_mlme_vdev_notify_up_complete() - MLME vdev UP complete callback
 * @vdev_mlme: vdev mlme object
 * @event_data_len: event data length
 * @event_data: event data
 *
 * This function is called to VDEV MLME on moving
 *  to UP state
 *
 * Return: QDF_STATUS
 */
static QDF_STATUS sta_mlme_vdev_notify_up_complete(struct vdev_mlme_obj *vdev_mlme,
						   uint16_t event_data_len,
						   void *event_data)
{
	mlme_legacy_debug("vdev id = %d ",
			  vdev_mlme->vdev->vdev_objmgr.vdev_id);
	return QDF_STATUS_SUCCESS;
}

/**
 * sta_mlme_vdev_notify_roam_start() - MLME vdev Roam start callback
 * @vdev_mlme: vdev mlme object
 * @event_data_len: event data length
 * @event_data: event data
 *
 * This function is called to VDEV MLME on roaming
 *  to UP state
 *
 * Return: QDF_STATUS
 */
static
QDF_STATUS sta_mlme_vdev_notify_roam_start(struct vdev_mlme_obj *vdev_mlme,
					   uint16_t event_data_len,
					   void *event_data)
{
	mlme_legacy_debug("vdev id = %d ",
			  vdev_mlme->vdev->vdev_objmgr.vdev_id);
	return wlan_cm_sta_mlme_vdev_roam_notify(vdev_mlme, event_data_len,
						 event_data);
}

/**
 * sta_mlme_vdev_disconnect_bss() - MLME vdev disconnect bss callback
 * @vdev_mlme: vdev mlme object
 * @event_data_len: event data length
 * @event_data: event data
 * @is_disconnect_legacy_only: flag to indicate legacy disconnect
 *
 * This function is called to disconnect BSS/send deauth to AP
 *
 * Return: QDF_STATUS
 */
static QDF_STATUS sta_mlme_vdev_disconnect_bss(struct vdev_mlme_obj *vdev_mlme,
					       uint16_t event_data_len,
					       void *event_data,
					       bool is_disconnect_legacy_only)
{
	mlme_legacy_debug("vdev id = %d ",
			  vdev_mlme->vdev->vdev_objmgr.vdev_id);
	return lim_sta_mlme_vdev_disconnect_bss(vdev_mlme, event_data_len,
						event_data);
}

/**
 * sta_mlme_vdev_stop_send() - MLME vdev stop send callback
 * @vdev_mlme: vdev mlme object
 * @data_len: event data length
 * @data: event data
 *
 * This function is called to send the vdev stop to firmware
 *
 * Return: QDF_STATUS
 */
static QDF_STATUS sta_mlme_vdev_stop_send(struct vdev_mlme_obj *vdev_mlme,
					  uint16_t data_len,
					  void *data)
{
	mlme_legacy_debug("vdev id = %d ",
			  vdev_mlme->vdev->vdev_objmgr.vdev_id);
	return lim_sta_mlme_vdev_stop_send(vdev_mlme, data_len, data);
}

/**
 * sta_mlme_vdev_sta_disconnect_start() - MLME vdev disconnect send callback
 * @vdev_mlme: vdev mlme object
 * @data_len: event data length
 * @data: event data
 *
 * This function is called to trigger the vdev stop to firmware when
 * reassoc failure
 *
 * Return: QDF_STATUS
 */
static QDF_STATUS
sta_mlme_vdev_sta_disconnect_start(struct vdev_mlme_obj *vdev_mlme,
				   uint16_t data_len, void *data)
{
	mlme_legacy_debug("vdev id = %d ",
			  vdev_mlme->vdev->vdev_objmgr.vdev_id);
	return lim_sta_mlme_vdev_sta_disconnect_start(vdev_mlme, data_len,
						      data);
}

/**
 * vdevmgr_mlme_stop_continue() - MLME vdev stop send callback
 * @vdev_mlme: vdev mlme object
 * @data_len: event data length
 * @data: event data
 *
 * This function is called to initiate operations on
 * LMAC/FW stop response such as remove peer.
 *
 * Return: QDF_STATUS
 */
static QDF_STATUS vdevmgr_mlme_stop_continue(struct vdev_mlme_obj *vdev_mlme,
					     uint16_t data_len,
					     void *data)
{
	mlme_legacy_debug("vdev id = %d ",
			  vdev_mlme->vdev->vdev_objmgr.vdev_id);
	return wma_mlme_vdev_stop_continue(vdev_mlme, data_len, data);
}

/**
 * ap_mlme_vdev_start_send () - send vdev start req
 * @vdev_mlme: vdev mlme object
 * @data_len: event data length
 * @data: event data
 *
 * This function is called to initiate actions of VDEV start ie start bss
 *
 * Return: QDF_STATUS
 */
static QDF_STATUS ap_mlme_vdev_start_send(struct vdev_mlme_obj *vdev_mlme,
					  uint16_t data_len, void *data)
{
	mlme_legacy_debug("vdev id = %d ",
			  vdev_mlme->vdev->vdev_objmgr.vdev_id);
	return lim_ap_mlme_vdev_start_send(vdev_mlme, data_len, data);
}

/**
 * ap_mlme_start_continue () - vdev start rsp callback
 * @vdev_mlme: vdev mlme object
 * @data_len: event data length
 * @data: event data
 *
 * This function is called to handle the VDEV START/RESTART callback
 *
 * Return: QDF_STATUS
 */
static QDF_STATUS ap_mlme_start_continue(struct vdev_mlme_obj *vdev_mlme,
					 uint16_t data_len, void *data)
{
	mlme_legacy_debug("vdev id = %d ",
			  vdev_mlme->vdev->vdev_objmgr.vdev_id);
	mlme_set_notify_co_located_ap_update_rnr(vdev_mlme->vdev, true);

	return wma_ap_mlme_vdev_start_continue(vdev_mlme, data_len, data);
}

/**
 * ap_mlme_vdev_update_beacon() - callback to initiate beacon update
 * @vdev_mlme: vdev mlme object
 * @op: beacon operation
 * @data_len: event data length
 * @data: event data
 *
 * This function is called to update beacon
 *
 * Return: QDF_STATUS
 */
static QDF_STATUS ap_mlme_vdev_update_beacon(struct vdev_mlme_obj *vdev_mlme,
					     enum beacon_update_op op,
					     uint16_t data_len, void *data)
{
	mlme_legacy_debug("vdev id = %d ",
			  vdev_mlme->vdev->vdev_objmgr.vdev_id);
	return lim_ap_mlme_vdev_update_beacon(vdev_mlme, op, data_len, data);
}

/**
 * ap_mlme_vdev_up_send() - callback to send vdev up
 * @vdev_mlme: vdev mlme object
 * @data_len: event data length
 * @data: event data
 *
 * This function is called to send vdev up req
 *
 * Return: QDF_STATUS
 */
static QDF_STATUS ap_mlme_vdev_up_send(struct vdev_mlme_obj *vdev_mlme,
				       uint16_t data_len, void *data)
{
	mlme_legacy_debug("vdev id = %d ",
			  vdev_mlme->vdev->vdev_objmgr.vdev_id);
	return lim_ap_mlme_vdev_up_send(vdev_mlme, data_len, data);
}

#ifdef WLAN_FEATURE_11BE_MLO
void wlan_handle_emlsr_sta_concurrency(struct wlan_objmgr_psoc *psoc,
				       bool conc_con_coming_up,
				       bool emlsr_sta_coming_up)
{
	policy_mgr_handle_emlsr_sta_concurrency(psoc, conc_con_coming_up,
						emlsr_sta_coming_up);
}
#endif

/**
 * ap_mlme_vdev_notify_up_complete() - callback to notify up completion
 * @vdev_mlme: vdev mlme object
 * @data_len: event data length
 * @data: event data
 *
 * This function is called to indicate up is completed
 *
 * Return: QDF_STATUS
 */
static QDF_STATUS
ap_mlme_vdev_notify_up_complete(struct vdev_mlme_obj *vdev_mlme,
				uint16_t data_len, void *data)
{
	if (!vdev_mlme) {
		mlme_legacy_err("data is NULL");
		return QDF_STATUS_E_INVAL;
	}

	pe_debug("Vdev %d is up", wlan_vdev_get_id(vdev_mlme->vdev));

	return QDF_STATUS_SUCCESS;
}

/**
 * ap_mlme_vdev_disconnect_peers() - callback to disconnect all connected peers
 * @vdev_mlme: vdev mlme object
 * @data_len: event data length
 * @data: event data
 * @is_disconnect_legacy_only: flag to indicate is disconnect legacy
 *
 * This function is called to disconnect all connected peers
 *
 * Return: QDF_STATUS
 */
static QDF_STATUS ap_mlme_vdev_disconnect_peers(struct vdev_mlme_obj *vdev_mlme,
						uint16_t data_len, void *data,
						bool is_disconnect_legacy_only)
{
	mlme_legacy_debug("vdev id = %d ",
			  vdev_mlme->vdev->vdev_objmgr.vdev_id);
	return lim_ap_mlme_vdev_disconnect_peers(vdev_mlme, data_len, data);
}

/**
 * ap_mlme_vdev_stop_send() - callback to send stop vdev request
 * @vdev_mlme: vdev mlme object
 * @data_len: event data length
 * @data: event data
 *
 * This function is called to send stop vdev request
 *
 * Return: QDF_STATUS
 */
static QDF_STATUS ap_mlme_vdev_stop_send(struct vdev_mlme_obj *vdev_mlme,
					 uint16_t data_len, void *data)
{
	mlme_legacy_debug("vdev id = %d ",
			  vdev_mlme->vdev->vdev_objmgr.vdev_id);
	return lim_ap_mlme_vdev_stop_send(vdev_mlme, data_len, data);
}

/**
 * ap_mlme_vdev_is_newchan_no_cac - VDEV SM CSA complete notification
 * @vdev_mlme:  VDEV MLME comp object
 *
 * On CSA complete, checks whether Channel does not needs CAC period, if
 * it doesn't need cac return SUCCESS else FAILURE
 *
 * Return: SUCCESS if new channel doesn't need cac
 *         else FAILURE
 */
static QDF_STATUS
ap_mlme_vdev_is_newchan_no_cac(struct vdev_mlme_obj *vdev_mlme)
{
	bool cac_required;

	cac_required = mlme_get_cac_required(vdev_mlme->vdev);
	mlme_legacy_debug("vdev id = %d cac_required %d",
			  vdev_mlme->vdev->vdev_objmgr.vdev_id, cac_required);

	if (!cac_required)
		return QDF_STATUS_SUCCESS;

	mlme_set_cac_required(vdev_mlme->vdev, false);

	return QDF_STATUS_E_FAILURE;
}

/**
 * vdevmgr_mlme_vdev_down_send() - callback to send vdev down req
 * @vdev_mlme: vdev mlme object
 * @data_len: event data length
 * @data: event data
 *
 * This function is called to send vdev down req
 *
 * Return: QDF_STATUS
 */
static QDF_STATUS vdevmgr_mlme_vdev_down_send(struct vdev_mlme_obj *vdev_mlme,
					      uint16_t data_len, void *data)
{
	QDF_STATUS status;
	uint8_t vdev_id;

	vdev_id = wlan_vdev_get_id(vdev_mlme->vdev);

	mlme_legacy_debug("vdev id = %d ", vdev_id);
	status = wma_ap_mlme_vdev_down_send(vdev_mlme, data_len, data);
	if (QDF_IS_STATUS_SUCCESS(status))
		mlme_sr_update(vdev_mlme->vdev, false);

	return status;
}

/**
 * vdevmgr_notify_down_complete() - callback to indicate vdev down is completed
 * @vdev_mlme: vdev mlme object
 * @data_len: event data length
 * @data: event data
 *
 * This function is called to indicate vdev down is completed
 *
 * Return: QDF_STATUS
 */
static QDF_STATUS vdevmgr_notify_down_complete(struct vdev_mlme_obj *vdev_mlme,
					       uint16_t data_len, void *data)
{
	mlme_legacy_debug("vdev id = %d ",
			  vdev_mlme->vdev->vdev_objmgr.vdev_id);

	return wma_mlme_vdev_notify_down_complete(vdev_mlme, data_len, data);
}

/**
 * ap_mlme_vdev_start_req_failed () - vdev start req fail callback
 * @vdev_mlme: vdev mlme object
 * @data_len: event data length
 * @data: event data
 *
 * This function is called to handle vdev start req/rsp failure
 *
 * Return: QDF_STATUS
 */
static QDF_STATUS ap_mlme_vdev_start_req_failed(struct vdev_mlme_obj *vdev_mlme,
						uint16_t data_len, void *data)
{
	mlme_legacy_debug("vdev id = %d ",
			  vdev_mlme->vdev->vdev_objmgr.vdev_id);
	return lim_ap_mlme_vdev_start_req_failed(vdev_mlme, data_len, data);
}

/**
 * ap_mlme_vdev_restart_send() - a callback to send vdev restart
 * @vdev_mlme: vdev mlme object
 * @data_len: event data length
 * @data: event data
 *
 * This function is called to initiate and send vdev restart req
 *
 * Return: QDF_STATUS
 */
static QDF_STATUS ap_mlme_vdev_restart_send(struct vdev_mlme_obj *vdev_mlme,
					    uint16_t data_len, void *data)
{
	mlme_legacy_debug("vdev id = %d ",
			  vdev_mlme->vdev->vdev_objmgr.vdev_id);
	return lim_ap_mlme_vdev_restart_send(vdev_mlme, data_len, data);
}

/**
 * ap_mlme_vdev_stop_start_send() - handle vdev stop during start req
 * @vdev_mlme: vdev mlme object
 * @type: restart req or start req
 * @data_len: event data length
 * @data: event data
 *
 * This function is called to handle vdev stop during start req
 *
 * Return: QDF_STATUS
 */
static QDF_STATUS ap_mlme_vdev_stop_start_send(struct vdev_mlme_obj *vdev_mlme,
					       enum vdev_cmd_type type,
					       uint16_t data_len, void *data)
{
	mlme_legacy_debug("vdev id = %d ",
			  vdev_mlme->vdev->vdev_objmgr.vdev_id);
	return wma_ap_mlme_vdev_stop_start_send(vdev_mlme, type,
						data_len, data);
}

QDF_STATUS mlme_set_chan_switch_in_progress(struct wlan_objmgr_vdev *vdev,
					       bool val)
{
	struct mlme_legacy_priv *mlme_priv;

	mlme_priv = wlan_vdev_mlme_get_ext_hdl(vdev);
	if (!mlme_priv) {
		mlme_legacy_err("vdev legacy private object is NULL");
		return QDF_STATUS_E_FAILURE;
	}

	mlme_priv->chan_switch_in_progress = val;
	mlme_legacy_info("Set chan_switch_in_progress: %d vdev %d",
			 val, wlan_vdev_get_id(vdev));

	return QDF_STATUS_SUCCESS;
}

#ifdef WLAN_FEATURE_MSCS
QDF_STATUS mlme_set_is_mscs_req_sent(struct wlan_objmgr_vdev *vdev, bool val)
{
	struct mlme_legacy_priv *mlme_priv;

	mlme_priv = wlan_vdev_mlme_get_ext_hdl(vdev);
	if (!mlme_priv) {
		mlme_legacy_err("vdev legacy private object is NULL");
		return QDF_STATUS_E_FAILURE;
	}

	mlme_priv->mscs_req_info.is_mscs_req_sent = val;

	return QDF_STATUS_SUCCESS;
}

bool mlme_get_is_mscs_req_sent(struct wlan_objmgr_vdev *vdev)
{
	struct mlme_legacy_priv *mlme_priv;

	mlme_priv = wlan_vdev_mlme_get_ext_hdl(vdev);
	if (!mlme_priv) {
		mlme_legacy_err("vdev legacy private object is NULL");
		return false;
	}

	return mlme_priv->mscs_req_info.is_mscs_req_sent;
}
#endif

bool mlme_is_chan_switch_in_progress(struct wlan_objmgr_vdev *vdev)
{
	struct mlme_legacy_priv *mlme_priv;

	mlme_priv = wlan_vdev_mlme_get_ext_hdl(vdev);
	if (!mlme_priv) {
		mlme_legacy_err("vdev legacy private object is NULL");
		return false;
	}

	return mlme_priv->chan_switch_in_progress;
}

QDF_STATUS
ap_mlme_set_hidden_ssid_restart_in_progress(struct wlan_objmgr_vdev *vdev,
					    bool val)
{
	struct mlme_legacy_priv *mlme_priv;

	mlme_priv = wlan_vdev_mlme_get_ext_hdl(vdev);
	if (!mlme_priv) {
		mlme_legacy_err("vdev legacy private object is NULL");
		return QDF_STATUS_E_FAILURE;
	}

	mlme_priv->hidden_ssid_restart_in_progress = val;

	return QDF_STATUS_SUCCESS;
}

bool ap_mlme_is_hidden_ssid_restart_in_progress(struct wlan_objmgr_vdev *vdev)
{
	struct mlme_legacy_priv *mlme_priv;

	mlme_priv = wlan_vdev_mlme_get_ext_hdl(vdev);
	if (!mlme_priv) {
		mlme_legacy_err("vdev legacy private object is NULL");
		return false;
	}

	return mlme_priv->hidden_ssid_restart_in_progress;
}

QDF_STATUS mlme_set_bigtk_support(struct wlan_objmgr_vdev *vdev, bool val)
{
	struct mlme_legacy_priv *mlme_priv;

	mlme_priv = wlan_vdev_mlme_get_ext_hdl(vdev);
	if (!mlme_priv) {
		mlme_legacy_err("vdev legacy private object is NULL");
		return QDF_STATUS_E_FAILURE;
	}

	mlme_priv->bigtk_vdev_support = val;

	return QDF_STATUS_SUCCESS;
}

bool mlme_get_bigtk_support(struct wlan_objmgr_vdev *vdev)
{
	struct mlme_legacy_priv *mlme_priv;

	mlme_priv = wlan_vdev_mlme_get_ext_hdl(vdev);
	if (!mlme_priv) {
		mlme_legacy_err("vdev legacy private object is NULL");
		return false;
	}

	return mlme_priv->bigtk_vdev_support;
}

#ifdef FEATURE_WLAN_TDLS
QDF_STATUS
mlme_set_tdls_chan_switch_prohibited(struct wlan_objmgr_vdev *vdev, bool val)
{
	struct mlme_legacy_priv *mlme_priv;

	mlme_priv = wlan_vdev_mlme_get_ext_hdl(vdev);
	if (!mlme_priv) {
		mlme_legacy_err("vdev legacy private object is NULL");
		return QDF_STATUS_E_FAILURE;
	}

	mlme_priv->connect_info.tdls_chan_swit_prohibited = val;

	return QDF_STATUS_SUCCESS;
}

bool mlme_get_tdls_chan_switch_prohibited(struct wlan_objmgr_vdev *vdev)
{
	struct mlme_legacy_priv *mlme_priv;

	mlme_priv = wlan_vdev_mlme_get_ext_hdl(vdev);
	if (!mlme_priv) {
		mlme_legacy_err("vdev legacy private object is NULL");
		return false;
	}

	return mlme_priv->connect_info.tdls_chan_swit_prohibited;
}

QDF_STATUS
mlme_set_tdls_prohibited(struct wlan_objmgr_vdev *vdev, bool val)
{
	struct mlme_legacy_priv *mlme_priv;

	mlme_priv = wlan_vdev_mlme_get_ext_hdl(vdev);
	if (!mlme_priv) {
		mlme_legacy_err("vdev legacy private object is NULL");
		return QDF_STATUS_E_FAILURE;
	}

	mlme_priv->connect_info.tdls_prohibited = val;

	return QDF_STATUS_SUCCESS;
}

bool mlme_get_tdls_prohibited(struct wlan_objmgr_vdev *vdev)
{
	struct mlme_legacy_priv *mlme_priv;

	mlme_priv = wlan_vdev_mlme_get_ext_hdl(vdev);
	if (!mlme_priv) {
		mlme_legacy_err("vdev legacy private object is NULL");
		return false;
	}

	return mlme_priv->connect_info.tdls_prohibited;
}
#endif

QDF_STATUS
mlme_set_roam_reason_better_ap(struct wlan_objmgr_vdev *vdev, bool val)
{
	struct mlme_legacy_priv *mlme_priv;

	mlme_priv = wlan_vdev_mlme_get_ext_hdl(vdev);
	if (!mlme_priv) {
		mlme_legacy_err("vdev legacy private object is NULL");
		return QDF_STATUS_E_FAILURE;
	}

	mlme_priv->roam_reason_better_ap = val;

	return QDF_STATUS_SUCCESS;
}

bool mlme_get_roam_reason_better_ap(struct wlan_objmgr_vdev *vdev)
{
	struct mlme_legacy_priv *mlme_priv;

	mlme_priv = wlan_vdev_mlme_get_ext_hdl(vdev);
	if (!mlme_priv) {
		mlme_legacy_err("vdev legacy private object is NULL");
		return false;
	}

	return mlme_priv->roam_reason_better_ap;
}

QDF_STATUS
mlme_set_hb_ap_rssi(struct wlan_objmgr_vdev *vdev, uint32_t val)
{
	struct mlme_legacy_priv *mlme_priv;

	mlme_priv = wlan_vdev_mlme_get_ext_hdl(vdev);
	if (!mlme_priv) {
		mlme_legacy_err("vdev legacy private object is NULL");
		return QDF_STATUS_E_FAILURE;
	}

	mlme_priv->hb_failure_rssi = val;

	return QDF_STATUS_SUCCESS;
}

uint32_t mlme_get_hb_ap_rssi(struct wlan_objmgr_vdev *vdev)
{
	struct mlme_legacy_priv *mlme_priv;

	mlme_priv = wlan_vdev_mlme_get_ext_hdl(vdev);
	if (!mlme_priv) {
		mlme_legacy_err("vdev legacy private object is NULL");
		return 0;
	}

	return mlme_priv->hb_failure_rssi;
}


QDF_STATUS mlme_set_connection_fail(struct wlan_objmgr_vdev *vdev, bool val)
{
	struct mlme_legacy_priv *mlme_priv;

	mlme_priv = wlan_vdev_mlme_get_ext_hdl(vdev);
	if (!mlme_priv) {
		mlme_legacy_err("vdev legacy private object is NULL");
		return QDF_STATUS_E_FAILURE;
	}

	mlme_priv->connection_fail = val;

	return QDF_STATUS_SUCCESS;
}

bool mlme_is_connection_fail(struct wlan_objmgr_vdev *vdev)
{
	struct mlme_legacy_priv *mlme_priv;

	mlme_priv = wlan_vdev_mlme_get_ext_hdl(vdev);
	if (!mlme_priv) {
		mlme_legacy_err("vdev legacy private object is NULL");
		return false;
	}

	return mlme_priv->connection_fail;
}

#ifdef FEATURE_WLAN_WAPI
static void mlme_is_sta_vdev_wapi(struct wlan_objmgr_pdev *pdev,
			   void *object, void *arg)
{
	struct wlan_objmgr_vdev *vdev = (struct wlan_objmgr_vdev *)object;
	int32_t keymgmt;
	bool *is_wapi_sta_exist = (bool *)arg;
	QDF_STATUS status;

	if (*is_wapi_sta_exist)
		return;
	if (wlan_vdev_mlme_get_opmode(vdev) != QDF_STA_MODE)
		return;

	status = wlan_vdev_is_up(vdev);
	if (QDF_IS_STATUS_ERROR(status))
		return;

	keymgmt = wlan_crypto_get_param(vdev, WLAN_CRYPTO_PARAM_KEY_MGMT);
	if (keymgmt < 0)
		return;

	if (keymgmt & ((1 << WLAN_CRYPTO_KEY_MGMT_WAPI_PSK) |
		       (1 << WLAN_CRYPTO_KEY_MGMT_WAPI_CERT))) {
		*is_wapi_sta_exist = true;
		mlme_debug("wapi exist for Vdev: %d",
			   wlan_vdev_get_id(vdev));
	}
}

bool mlme_is_wapi_sta_active(struct wlan_objmgr_pdev *pdev)
{
	bool is_wapi_sta_exist = false;

	wlan_objmgr_pdev_iterate_obj_list(pdev,
					  WLAN_VDEV_OP,
					  mlme_is_sta_vdev_wapi,
					  &is_wapi_sta_exist, 0,
					  WLAN_MLME_OBJMGR_ID);

	return is_wapi_sta_exist;
}
#endif

QDF_STATUS mlme_set_assoc_type(struct wlan_objmgr_vdev *vdev,
			       enum vdev_assoc_type assoc_type)
{
	struct mlme_legacy_priv *mlme_priv;

	mlme_priv = wlan_vdev_mlme_get_ext_hdl(vdev);
	if (!mlme_priv) {
		mlme_legacy_err("vdev legacy private object is NULL");
		return QDF_STATUS_E_FAILURE;
	}

	mlme_priv->assoc_type = assoc_type;

	return QDF_STATUS_SUCCESS;
}

QDF_STATUS mlme_get_vdev_stop_type(struct wlan_objmgr_vdev *vdev,
				   uint32_t *vdev_stop_type)
{
	struct mlme_legacy_priv *mlme_priv;

	mlme_priv = wlan_vdev_mlme_get_ext_hdl(vdev);
	if (!mlme_priv) {
		mlme_legacy_err("vdev legacy private object is NULL");
		return QDF_STATUS_E_FAILURE;
	}

	*vdev_stop_type = mlme_priv->vdev_stop_type;

	return QDF_STATUS_SUCCESS;
}

QDF_STATUS mlme_set_vdev_stop_type(struct wlan_objmgr_vdev *vdev,
				   uint32_t vdev_stop_type)
{
	struct mlme_legacy_priv *mlme_priv;

	mlme_priv = wlan_vdev_mlme_get_ext_hdl(vdev);
	if (!mlme_priv) {
		mlme_legacy_err("vdev legacy private object is NULL");
		return QDF_STATUS_E_FAILURE;
	}

	mlme_priv->vdev_stop_type = vdev_stop_type;

	return QDF_STATUS_SUCCESS;
}

void mlme_set_notify_co_located_ap_update_rnr(struct wlan_objmgr_vdev *vdev,
					      bool upt_rnr)
{
	struct mlme_legacy_priv *mlme_priv;

	mlme_priv = wlan_vdev_mlme_get_ext_hdl(vdev);
	if (!mlme_priv) {
		mlme_legacy_err("vdev legacy private object is NULL");
		return;
	}

	mlme_priv->notify_co_located_ap_upt_rnr = upt_rnr;
}

bool mlme_is_notify_co_located_ap_update_rnr(struct wlan_objmgr_vdev *vdev)
{
	struct mlme_legacy_priv *mlme_priv;

	mlme_priv = wlan_vdev_mlme_get_ext_hdl(vdev);
	if (!mlme_priv) {
		mlme_legacy_err("vdev legacy private object is NULL");
		return false;
	}

	return mlme_priv->notify_co_located_ap_upt_rnr;
}

bool wlan_is_vdev_traffic_ll_ht(struct wlan_objmgr_vdev *vdev)
{
	struct mlme_legacy_priv *mlme_priv;

	mlme_priv = wlan_vdev_mlme_get_ext_hdl(vdev);
	if (!mlme_priv) {
		mlme_legacy_err("vdev legacy private object is NULL");
		return false;
	}

	if (mlme_priv->vdev_traffic_type & PM_VDEV_TRAFFIC_LOW_LATENCY ||
	    mlme_priv->vdev_traffic_type & PM_VDEV_TRAFFIC_HIGH_TPUT)
		return true;

	return false;
}

WMI_HOST_WIFI_STANDARD mlme_get_vdev_wifi_std(struct wlan_objmgr_vdev *vdev)
{
	struct mlme_legacy_priv *mlme_priv;

	mlme_priv = wlan_vdev_mlme_get_ext_hdl(vdev);
	if (!mlme_priv) {
		mlme_legacy_err("vdev legacy private object is NULL");
		return WMI_HOST_WIFI_STANDARD_7;
	}

	if (!mlme_priv->is_user_std_set)
		return WMI_HOST_WIFI_STANDARD_7;

	return mlme_priv->wifi_std;
}

enum vdev_assoc_type  mlme_get_assoc_type(struct wlan_objmgr_vdev *vdev)
{
	struct mlme_legacy_priv *mlme_priv;

	mlme_priv = wlan_vdev_mlme_get_ext_hdl(vdev);
	if (!mlme_priv) {
		mlme_legacy_err("vdev legacy private object is NULL");
		return false;
	}

	return mlme_priv->assoc_type;
}

QDF_STATUS
mlme_set_vdev_start_failed(struct wlan_objmgr_vdev *vdev, bool val)
{
	struct mlme_legacy_priv *mlme_priv;

	mlme_priv = wlan_vdev_mlme_get_ext_hdl(vdev);
	if (!mlme_priv) {
		mlme_legacy_err("vdev legacy private object is NULL");
		return QDF_STATUS_E_FAILURE;
	}

	mlme_priv->vdev_start_failed = val;

	return QDF_STATUS_SUCCESS;
}

bool mlme_get_vdev_start_failed(struct wlan_objmgr_vdev *vdev)
{
	struct mlme_legacy_priv *mlme_priv;

	mlme_priv = wlan_vdev_mlme_get_ext_hdl(vdev);
	if (!mlme_priv) {
		mlme_legacy_err("vdev legacy private object is NULL");
		return false;
	}

	return mlme_priv->vdev_start_failed;
}

QDF_STATUS mlme_set_cac_required(struct wlan_objmgr_vdev *vdev, bool val)
{
	struct mlme_legacy_priv *mlme_priv;

	mlme_priv = wlan_vdev_mlme_get_ext_hdl(vdev);
	if (!mlme_priv) {
		mlme_legacy_err("vdev legacy private object is NULL");
		return QDF_STATUS_E_FAILURE;
	}

	mlme_priv->cac_required_for_new_channel = val;

	return QDF_STATUS_SUCCESS;
}

bool mlme_get_cac_required(struct wlan_objmgr_vdev *vdev)
{
	struct mlme_legacy_priv *mlme_priv;

	mlme_priv = wlan_vdev_mlme_get_ext_hdl(vdev);
	if (!mlme_priv) {
		mlme_legacy_err("vdev legacy private object is NULL");
		return false;
	}

	return mlme_priv->cac_required_for_new_channel;
}

QDF_STATUS mlme_set_mbssid_info(struct wlan_objmgr_vdev *vdev,
				struct scan_mbssid_info *mbssid_info,
				qdf_freq_t freq)
{
	struct vdev_mlme_obj *vdev_mlme;
	struct vdev_mlme_mbss_11ax *mbss_11ax;
	struct qdf_mac_addr bssid;
	struct qdf_mac_addr bcast_addr = QDF_MAC_ADDR_BCAST_INIT;

	vdev_mlme = wlan_vdev_mlme_get_cmpt_obj(vdev);
	if (!vdev_mlme) {
		mlme_legacy_err("vdev component object is NULL");
		return QDF_STATUS_E_FAILURE;
	}

	mbss_11ax = &vdev_mlme->mgmt.mbss_11ax;
	mbss_11ax->profile_idx = mbssid_info->profile_num;
	mbss_11ax->profile_num = mbssid_info->profile_count;
	qdf_mem_copy(mbss_11ax->trans_bssid,
		     mbssid_info->trans_bssid, QDF_MAC_ADDR_SIZE);
	qdf_mem_copy(mbss_11ax->non_trans_bssid,
		     mbssid_info->non_trans_bssid, QDF_MAC_ADDR_SIZE);

	qdf_mem_copy(&bssid.bytes, vdev_mlme->mgmt.generic.bssid,
		     QDF_MAC_ADDR_SIZE);

	/*
	 * Consider the case of 5 GHz + non-tx 6 GHz MLO candidate.
	 * The scan entry might be generated from a ML-probe, which doesn't have
	 * the MBSSID info for the non-tx partner link. In this case, host has
	 * to identify if this link is MBSS or not. This is essential to receive
	 * traffic over this link.
	 *
	 * The below logic looks into the rnr db for the 6 GHz bssid and
	 * determines if the bssid is non-tx profile from the bss parameter
	 * saved by its neighbor. If this is a non-tx bssid, but trans_bssid
	 * info is not available from the scan entry, then set transmitted bssid
	 * to bcast address. Upon sending this bcast tx bssid to firmware, the
	 * firmware would auto-detect the tx bssid from the upcoming beacons
	 * and tunes the interface to proper bssid.
	 *
	 * Note: Always send bcast mac in trans_bssid if the host is unable
	 * to determine if a given BSS is part of an MBSS.
	 */
	if (freq != INVALID_CHANNEL_NUM && !mbss_11ax->profile_idx &&
	    qdf_is_macaddr_zero((struct qdf_mac_addr *)&mbss_11ax->trans_bssid) &&
	    util_is_bssid_non_tx(wlan_vdev_get_psoc(vdev), &bssid, freq))
		qdf_mem_copy(mbss_11ax->trans_bssid,
			     bcast_addr.bytes, QDF_MAC_ADDR_SIZE);

	return QDF_STATUS_SUCCESS;
}

void mlme_get_mbssid_info(struct wlan_objmgr_vdev *vdev,
			  struct vdev_mlme_mbss_11ax *mbss_11ax)
{
	struct vdev_mlme_obj *vdev_mlme;

	vdev_mlme = wlan_vdev_mlme_get_cmpt_obj(vdev);
	if (!vdev_mlme) {
		mlme_legacy_err("vdev component object is NULL");
		return;
	}

	mbss_11ax = &vdev_mlme->mgmt.mbss_11ax;
}

QDF_STATUS mlme_set_tx_power(struct wlan_objmgr_vdev *vdev,
			     int8_t tx_power)
{
	struct vdev_mlme_obj *vdev_mlme;

	vdev_mlme = wlan_vdev_mlme_get_cmpt_obj(vdev);

	if (!vdev_mlme) {
		mlme_legacy_err("vdev component object is NULL");
		return QDF_STATUS_E_FAILURE;
	}

	vdev_mlme->mgmt.generic.tx_power = tx_power;

	return QDF_STATUS_SUCCESS;
}

int8_t mlme_get_tx_power(struct wlan_objmgr_vdev *vdev)
{
	struct vdev_mlme_obj *vdev_mlme;

	vdev_mlme = wlan_vdev_mlme_get_cmpt_obj(vdev);
	if (!vdev_mlme) {
		mlme_legacy_err("vdev component object is NULL");
		return QDF_STATUS_E_INVAL;
	}

	return vdev_mlme->mgmt.generic.tx_power;
}

QDF_STATUS mlme_set_max_reg_power(struct wlan_objmgr_vdev *vdev,
				 int8_t max_reg_power)
{
	struct vdev_mlme_obj *vdev_mlme;

	vdev_mlme = wlan_vdev_mlme_get_cmpt_obj(vdev);

	if (!vdev_mlme) {
		mlme_legacy_err("vdev component object is NULL");
		return QDF_STATUS_E_FAILURE;
	}

	vdev_mlme->mgmt.generic.maxregpower = max_reg_power;

	return QDF_STATUS_SUCCESS;
}

int8_t mlme_get_max_reg_power(struct wlan_objmgr_vdev *vdev)
{
	struct vdev_mlme_obj *vdev_mlme;

	vdev_mlme = wlan_vdev_mlme_get_cmpt_obj(vdev);
	if (!vdev_mlme) {
		mlme_legacy_err("vdev component object is NULL");
		return QDF_STATUS_E_INVAL;
	}

	return vdev_mlme->mgmt.generic.maxregpower;
}

#if defined(WLAN_FEATURE_11BE_MLO) && defined(WLAN_FEATURE_ROAM_OFFLOAD)
QDF_STATUS
mlme_set_single_link_mlo_roaming(struct wlan_objmgr_vdev *vdev, bool val)
{
	struct mlme_legacy_priv *mlme_priv;

	mlme_priv = wlan_vdev_mlme_get_ext_hdl(vdev);
	if (!mlme_priv) {
		mlme_legacy_err("vdev legacy private object is NULL");
		return QDF_STATUS_E_FAILURE;
	}

	mlme_priv->is_single_link_mlo_roam = val;

	return QDF_STATUS_SUCCESS;
}

bool mlme_get_single_link_mlo_roaming(struct wlan_objmgr_vdev *vdev)
{
	struct mlme_legacy_priv *mlme_priv;

	mlme_priv = wlan_vdev_mlme_get_ext_hdl(vdev);
	if (!mlme_priv) {
		mlme_legacy_err("vdev legacy private object is NULL");
		return false;
	}

	return mlme_priv->is_single_link_mlo_roam;
}
#endif

/**
 * mlme_get_vdev_types() - get vdev type and subtype from its operation mode
 * @mode: operation mode of vdev
 * @type: type of vdev
 * @sub_type: sub_type of vdev
 *
 * This API is called to get vdev type and subtype from its operation mode.
 * Vdev operation modes are defined in enum QDF_OPMODE.
 *
 * Type of vdev are WLAN_VDEV_MLME_TYPE_AP, WLAN_VDEV_MLME_TYPE_STA,
 * WLAN_VDEV_MLME_TYPE_IBSS, ,WLAN_VDEV_MLME_TYPE_MONITOR,
 * WLAN_VDEV_MLME_TYPE_NAN, WLAN_VDEV_MLME_TYPE_OCB, WLAN_VDEV_MLME_TYPE_NDI
 *
 * Sub_types of vdev are WLAN_VDEV_MLME_SUBTYPE_P2P_DEVICE,
 * WLAN_VDEV_MLME_SUBTYPE_P2P_CLIENT, WLAN_VDEV_MLME_SUBTYPE_P2P_GO,
 * WLAN_VDEV_MLME_SUBTYPE_PROXY_STA, WLAN_VDEV_MLME_SUBTYPE_MESH
 * Return: QDF_STATUS
 */

static QDF_STATUS mlme_get_vdev_types(enum QDF_OPMODE mode, uint8_t *type,
				      uint8_t *sub_type)
{
	QDF_STATUS status = QDF_STATUS_SUCCESS;
	*type = 0;
	*sub_type = 0;

	switch (mode) {
	case QDF_STA_MODE:
		*type = WLAN_VDEV_MLME_TYPE_STA;
		break;
	case QDF_SAP_MODE:
		*type = WLAN_VDEV_MLME_TYPE_AP;
		break;
	case QDF_P2P_DEVICE_MODE:
		*type = WLAN_VDEV_MLME_TYPE_AP;
		*sub_type = WLAN_VDEV_MLME_SUBTYPE_P2P_DEVICE;
		break;
	case QDF_P2P_CLIENT_MODE:
		*type = WLAN_VDEV_MLME_TYPE_STA;
		*sub_type = WLAN_VDEV_MLME_SUBTYPE_P2P_CLIENT;
		break;
	case QDF_P2P_GO_MODE:
		*type = WLAN_VDEV_MLME_TYPE_AP;
		*sub_type = WLAN_VDEV_MLME_SUBTYPE_P2P_GO;
		break;
	case QDF_OCB_MODE:
		*type = WLAN_VDEV_MLME_TYPE_OCB;
		break;
	case QDF_IBSS_MODE:
		*type = WLAN_VDEV_MLME_TYPE_IBSS;
		break;
	case QDF_MONITOR_MODE:
		*type = WMI_HOST_VDEV_TYPE_MONITOR;
		break;
	case QDF_NDI_MODE:
		*type = WLAN_VDEV_MLME_TYPE_NDI;
		break;
	case QDF_NAN_DISC_MODE:
		*type = WLAN_VDEV_MLME_TYPE_NAN;
		break;
	default:
		mlme_err("Invalid device mode %d", mode);
		status = QDF_STATUS_E_INVAL;
		break;
	}
	return status;
}

#ifdef WLAN_FEATURE_FILS_SK
static inline void mlme_free_fils_info(struct mlme_connect_info *connect_info)
{
	qdf_mem_free(connect_info->fils_con_info);
	qdf_mem_free(connect_info->hlp_ie);
	connect_info->hlp_ie = NULL;
	connect_info->hlp_ie_len = 0;
	connect_info->fils_con_info = NULL;
}
#else
static inline void mlme_free_fils_info(struct mlme_connect_info *connect_info)
{}
#endif

static
void mlme_init_wait_for_key_timer(struct wlan_objmgr_vdev *vdev,
				  struct wait_for_key_timer *wait_key_timer)
{
	QDF_STATUS status;

	if (!vdev || !wait_key_timer) {
		mlme_err("vdev or wait for key is NULL");
		return;
	}

	wait_key_timer->vdev = vdev;
	status = qdf_mc_timer_init(&wait_key_timer->timer, QDF_TIMER_TYPE_SW,
				   cm_wait_for_key_time_out_handler,
				   wait_key_timer);
	if (QDF_IS_STATUS_ERROR(status))
		mlme_err("cannot allocate memory for WaitForKey time out timer");
}

static
void mlme_deinit_wait_for_key_timer(struct wait_for_key_timer *wait_key_timer)
{
	qdf_mc_timer_stop(&wait_key_timer->timer);
	qdf_mc_timer_destroy(&wait_key_timer->timer);
}

static void mlme_ext_handler_destroy(struct vdev_mlme_obj *vdev_mlme)
{
	if (!vdev_mlme || !vdev_mlme->ext_vdev_ptr)
		return;
	qdf_runtime_lock_deinit(
		&vdev_mlme->ext_vdev_ptr->bss_color_change_runtime_lock);
	qdf_wake_lock_destroy(
		&vdev_mlme->ext_vdev_ptr->bss_color_change_wakelock);
	qdf_runtime_lock_deinit(
		&vdev_mlme->ext_vdev_ptr->disconnect_runtime_lock);
	mlme_free_self_disconnect_ies(vdev_mlme->vdev);
	mlme_free_peer_disconnect_ies(vdev_mlme->vdev);
	mlme_free_sae_auth_retry(vdev_mlme->vdev);
	mlme_deinit_wait_for_key_timer(&vdev_mlme->ext_vdev_ptr->wait_key_timer);
	mlme_free_fils_info(&vdev_mlme->ext_vdev_ptr->connect_info);
	mlme_cm_free_roam_stats_info(vdev_mlme->ext_vdev_ptr);
	qdf_mem_free(vdev_mlme->ext_vdev_ptr);
	vdev_mlme->ext_vdev_ptr = NULL;
}

static QDF_STATUS
mlme_wma_vdev_detach_post_cb(struct scheduler_msg *msg)
{
	struct vdev_delete_response rsp = {0};

	if (!msg) {
		mlme_err("Msg is NULL");
		return QDF_STATUS_E_INVAL;
	}

	rsp.vdev_id = msg->bodyval;
	wma_vdev_detach_callback(&rsp);

	return QDF_STATUS_SUCCESS;
}

static void mlme_wma_vdev_detach_handler(uint8_t vdev_id)
{
	struct scheduler_msg msg = {0};

	msg.bodyptr = NULL;
	msg.bodyval = vdev_id;
	msg.callback = mlme_wma_vdev_detach_post_cb;

	if (scheduler_post_message(QDF_MODULE_ID_MLME,
				   QDF_MODULE_ID_TARGET_IF,
				   QDF_MODULE_ID_TARGET_IF, &msg) ==
				   QDF_STATUS_SUCCESS)
		return;

	mlme_err("Failed to post wma vdev detach");
}

/**
 * vdevmgr_mlme_ext_hdl_destroy () - Destroy mlme legacy priv object
 * @vdev_mlme: vdev mlme object
 *
 * Return: QDF_STATUS
 */
static
QDF_STATUS vdevmgr_mlme_ext_hdl_destroy(struct vdev_mlme_obj *vdev_mlme)
{
	QDF_STATUS status = QDF_STATUS_E_FAILURE;
	uint8_t vdev_id;

	vdev_id = vdev_mlme->vdev->vdev_objmgr.vdev_id;
	mlme_legacy_debug("Sending vdev delete to firmware for vdev id = %d ",
			  vdev_id);

	if (!vdev_mlme->ext_vdev_ptr)
		return status;

	status = vdev_mgr_delete_send(vdev_mlme);
	if (QDF_IS_STATUS_ERROR(status)) {
		mlme_err("Failed to send vdev delete to firmware");
		mlme_wma_vdev_detach_handler(vdev_id);
	}

	mlme_ext_handler_destroy(vdev_mlme);

	return QDF_STATUS_SUCCESS;
}

/**
 * vdevmgr_mlme_ext_hdl_create () - Create mlme legacy priv object
 * @vdev_mlme: vdev mlme object
 *
 * Return: QDF_STATUS
 */
static
QDF_STATUS vdevmgr_mlme_ext_hdl_create(struct vdev_mlme_obj *vdev_mlme)
{
	QDF_STATUS status;

	mlme_legacy_debug("vdev id = %d ",
			  vdev_mlme->vdev->vdev_objmgr.vdev_id);
	vdev_mlme->ext_vdev_ptr =
		qdf_mem_malloc(sizeof(struct mlme_legacy_priv));
	if (!vdev_mlme->ext_vdev_ptr)
		return QDF_STATUS_E_NOMEM;

	mlme_init_rate_config(vdev_mlme);
	mlme_init_connect_chan_info_config(vdev_mlme);
	mlme_cm_alloc_roam_stats_info(vdev_mlme);
	vdev_mlme->ext_vdev_ptr->connect_info.fils_con_info = NULL;
	mlme_init_wait_for_key_timer(vdev_mlme->vdev,
				     &vdev_mlme->ext_vdev_ptr->wait_key_timer);

	qdf_wake_lock_create(
			&vdev_mlme->ext_vdev_ptr->bss_color_change_wakelock,
			"bss_color_change_wakelock");
	qdf_runtime_lock_init(
		&vdev_mlme->ext_vdev_ptr->bss_color_change_runtime_lock);
	qdf_runtime_lock_init(
		&vdev_mlme->ext_vdev_ptr->disconnect_runtime_lock);

	sme_get_vdev_type_nss(wlan_vdev_mlme_get_opmode(vdev_mlme->vdev),
			      &vdev_mlme->proto.generic.nss_2g,
			      &vdev_mlme->proto.generic.nss_5g);

	status = mlme_get_vdev_types(wlan_vdev_mlme_get_opmode(vdev_mlme->vdev),
				     &vdev_mlme->mgmt.generic.type,
				     &vdev_mlme->mgmt.generic.subtype);
	if (QDF_IS_STATUS_ERROR(status)) {
		mlme_err("Get vdev type failed; status:%d", status);
		mlme_ext_handler_destroy(vdev_mlme);
		return status;
	}

	status = vdev_mgr_create_send(vdev_mlme);
	if (QDF_IS_STATUS_ERROR(status)) {
		mlme_err("Failed to create vdev for vdev id %d",
			 wlan_vdev_get_id(vdev_mlme->vdev));
		vdevmgr_mlme_ext_hdl_destroy(vdev_mlme);
		return status;
	}

	return status;
}

#ifdef WLAN_FEATURE_DYNAMIC_MAC_ADDR_UPDATE
static
QDF_STATUS vdevmgr_mlme_vdev_send_set_mac_addr(struct qdf_mac_addr mac_addr,
					       struct qdf_mac_addr mld_addr,
					       struct wlan_objmgr_vdev *vdev)
{
	return vdev_mgr_send_set_mac_addr(mac_addr, mld_addr, vdev);
}
#endif

/**
 * ap_vdev_dfs_cac_timer_stop() - callback to stop cac timer
 * @vdev_mlme: vdev mlme object
 * @event_data_len: event data length
 * @event_data: event data
 *
 * This function is called to stop cac timer
 *
 * Return: QDF_STATUS
 */
static QDF_STATUS ap_vdev_dfs_cac_timer_stop(struct vdev_mlme_obj *vdev_mlme,
					     uint16_t event_data_len,
					     void *event_data)
{
	mlme_legacy_debug("vdev id = %d ",
			  vdev_mlme->vdev->vdev_objmgr.vdev_id);
	return QDF_STATUS_SUCCESS;
}

/**
 * mon_mlme_vdev_start_restart_send () - send vdev start/restart req
 * @vdev_mlme: vdev mlme object
 * @data_len: event data length
 * @data: event data
 *
 * This function is called to initiate actions of VDEV start/restart
 *
 * Return: QDF_STATUS
 */
static QDF_STATUS mon_mlme_vdev_start_restart_send(
	struct vdev_mlme_obj *vdev_mlme,
	uint16_t data_len, void *data)
{
	mlme_legacy_debug("vdev id = %d",
			  vdev_mlme->vdev->vdev_objmgr.vdev_id);
	return lim_mon_mlme_vdev_start_send(vdev_mlme, data_len, data);
}

/**
 * mon_mlme_start_continue () - vdev start rsp callback
 * @vdev_mlme: vdev mlme object
 * @data_len: event data length
 * @data: event data
 *
 * This function is called to handle the VDEV START/RESTART callback
 *
 * Return: QDF_STATUS
 */
static QDF_STATUS mon_mlme_start_continue(struct vdev_mlme_obj *vdev_mlme,
					  uint16_t data_len, void *data)
{
	mlme_legacy_debug("vdev id = %d",
			  vdev_mlme->vdev->vdev_objmgr.vdev_id);
	return wma_mon_mlme_vdev_start_continue(vdev_mlme, data_len, data);
}

/**
 * mon_mlme_vdev_up_send() - callback to send vdev up
 * @vdev_mlme: vdev mlme object
 * @data_len: event data length
 * @data: event data
 *
 * This function is called to send vdev up req
 *
 * Return: QDF_STATUS
 */
static QDF_STATUS mon_mlme_vdev_up_send(struct vdev_mlme_obj *vdev_mlme,
					uint16_t data_len, void *data)
{
	mlme_legacy_debug("vdev id = %d",
			  vdev_mlme->vdev->vdev_objmgr.vdev_id);
	return wma_mon_mlme_vdev_up_send(vdev_mlme, data_len, data);
}

/**
 * mon_mlme_vdev_disconnect_peers() - callback to disconnect all connected peers
 * @vdev_mlme: vdev mlme object
 * @data_len: event data length
 * @data: event data
 * @is_disconnect_legacy_only: flag to indicate legacy disconnect
 *
 * montior mode no connected peers, only do VDEV state transition.
 *
 * Return: QDF_STATUS
 */
static QDF_STATUS mon_mlme_vdev_disconnect_peers(
		struct vdev_mlme_obj *vdev_mlme,
		uint16_t data_len, void *data,
		bool is_disconnect_legacy_only)
{
	mlme_legacy_debug("vdev id = %d",
			  vdev_mlme->vdev->vdev_objmgr.vdev_id);
	return wlan_vdev_mlme_sm_deliver_evt(
				vdev_mlme->vdev,
				WLAN_VDEV_SM_EV_DISCONNECT_COMPLETE,
				0, NULL);
}

/**
 * mon_mlme_vdev_stop_send() - callback to send stop vdev request
 * @vdev_mlme: vdev mlme object
 * @data_len: event data length
 * @data: event data
 *
 * This function is called to send stop vdev request
 *
 * Return: QDF_STATUS
 */
static QDF_STATUS mon_mlme_vdev_stop_send(struct vdev_mlme_obj *vdev_mlme,
					  uint16_t data_len, void *data)
{
	mlme_legacy_debug("vdev id = %d",
			  vdev_mlme->vdev->vdev_objmgr.vdev_id);
	return wma_mon_mlme_vdev_stop_send(vdev_mlme, data_len, data);
}

/**
 * mon_mlme_vdev_down_send() - callback to send vdev down req
 * @vdev_mlme: vdev mlme object
 * @data_len: event data length
 * @data: event data
 *
 * This function is called to send vdev down req
 *
 * Return: QDF_STATUS
 */
static QDF_STATUS mon_mlme_vdev_down_send(struct vdev_mlme_obj *vdev_mlme,
					  uint16_t data_len, void *data)
{
	mlme_legacy_debug("vdev id = %d",
			  vdev_mlme->vdev->vdev_objmgr.vdev_id);
	return wma_mon_mlme_vdev_down_send(vdev_mlme, data_len, data);
}

/**
 * vdevmgr_vdev_delete_rsp_handle() - callback to handle vdev delete response
 * @psoc: psoc object
 * @rsp: pointer to vdev delete response
 *
 * This function is called to handle vdev delete response and send result to
 * upper layer
 *
 * Return: QDF_STATUS
 */
static QDF_STATUS
vdevmgr_vdev_delete_rsp_handle(struct wlan_objmgr_psoc *psoc,
			       struct vdev_delete_response *rsp)
{
	mlme_legacy_debug("vdev id = %d ", rsp->vdev_id);
	return wma_vdev_detach_callback(rsp);
}

/**
 * vdevmgr_vdev_stop_rsp_handle() - callback to handle vdev stop response
 * @vdev_mlme: vdev mlme object
 * @rsp: pointer to vdev stop response
 *
 * This function is called to handle vdev stop response and send result to
 * upper layer
 *
 * Return: QDF_STATUS
 */
static QDF_STATUS
vdevmgr_vdev_stop_rsp_handle(struct vdev_mlme_obj *vdev_mlme,
			     struct vdev_stop_response *rsp)
{
	mlme_legacy_debug("vdev id = %d ",
			  vdev_mlme->vdev->vdev_objmgr.vdev_id);
	return wma_vdev_stop_resp_handler(vdev_mlme, rsp);
}

/**
 * psoc_mlme_ext_hdl_enable() - to enable mlme ext param handler
 * @psoc: psoc object
 *
 * Return: QDF_STATUS
 */
static QDF_STATUS psoc_mlme_ext_hdl_enable(struct wlan_objmgr_psoc *psoc)
{
	struct wlan_mlme_psoc_ext_obj *mlme_obj;

	mlme_obj = mlme_get_psoc_ext_obj(psoc);
	if (!mlme_obj)
		return QDF_STATUS_E_FAILURE;

	mlme_obj->scan_requester_id =
		wlan_scan_register_requester(psoc, "MLME_EXT",
					     wlan_mlme_chan_stats_scan_event_cb,
					     NULL);

	return QDF_STATUS_SUCCESS;
}

/**
 * psoc_mlme_ext_hdl_disable() - to disable mlme ext param handler
 * @psoc: psoc object
 *
 * Return: QDF_STATUS
 */
static QDF_STATUS psoc_mlme_ext_hdl_disable(struct wlan_objmgr_psoc *psoc)
{
	struct wlan_mlme_psoc_ext_obj *mlme_obj;

	mlme_obj = mlme_get_psoc_ext_obj(psoc);
	if (!mlme_obj)
		return QDF_STATUS_E_FAILURE;

	wlan_scan_unregister_requester(psoc, mlme_obj->scan_requester_id);

	return QDF_STATUS_SUCCESS;
}

/**
 * psoc_mlme_ext_hdl_create() - Create mlme legacy priv object
 * @psoc_mlme: psoc mlme object
 *
 * Return: QDF_STATUS
 */
static
QDF_STATUS psoc_mlme_ext_hdl_create(struct psoc_mlme_obj *psoc_mlme)
{
	psoc_mlme->ext_psoc_ptr =
		qdf_mem_malloc(sizeof(struct wlan_mlme_psoc_ext_obj));
	if (!psoc_mlme->ext_psoc_ptr)
		return QDF_STATUS_E_NOMEM;

	target_if_cm_roam_register_tx_ops(
			&psoc_mlme->ext_psoc_ptr->rso_tx_ops);

	target_if_wfatestcmd_register_tx_ops(
			&psoc_mlme->ext_psoc_ptr->wfa_testcmd.tx_ops);
	target_if_cm_roam_register_rx_ops(
			&psoc_mlme->ext_psoc_ptr->rso_rx_ops);
	wlan_mlme_register_rx_ops(&psoc_mlme->ext_psoc_ptr->mlme_rx_ops);

	target_if_mlme_register_tx_ops(
			&psoc_mlme->ext_psoc_ptr->mlme_tx_ops);

	return QDF_STATUS_SUCCESS;
}

/**
 * psoc_mlme_ext_hdl_destroy() - Destroy mlme legacy priv object
 * @psoc_mlme: psoc mlme object
 *
 * Return: QDF_STATUS
 */
static
QDF_STATUS psoc_mlme_ext_hdl_destroy(struct psoc_mlme_obj *psoc_mlme)
{
	if (!psoc_mlme) {
		mlme_err("PSOC MLME is NULL");
		return QDF_STATUS_E_FAILURE;
	}

	if (psoc_mlme->ext_psoc_ptr) {
		qdf_mem_free(psoc_mlme->ext_psoc_ptr);
		psoc_mlme->ext_psoc_ptr = NULL;
	}

	return QDF_STATUS_SUCCESS;
}

/**
 * vdevmgr_vdev_start_rsp_handle() - callback to handle vdev start response
 * @vdev_mlme: vdev mlme object
 * @rsp: pointer to vdev start response
 *
 * This function is called to handle vdev start response
 *
 * Return: QDF_STATUS
 */
static QDF_STATUS
vdevmgr_vdev_start_rsp_handle(struct vdev_mlme_obj *vdev_mlme,
			      struct vdev_start_response *rsp)
{
	QDF_STATUS status;

	mlme_legacy_debug("vdev id = %d ",
			  vdev_mlme->vdev->vdev_objmgr.vdev_id);
	status =  wma_vdev_start_resp_handler(vdev_mlme, rsp);

	return status;
}

/**
 * vdevmgr_vdev_peer_delete_all_rsp_handle() - callback to handle vdev delete
 *                                             all response
 * @vdev_mlme: vdev mlme object
 * @rsp: pointer to vdev delete response
 *
 * This function is called to handle vdev delete response and send result to
 * upper layer
 *
 * Return: QDF_STATUS
 */
static QDF_STATUS
vdevmgr_vdev_peer_delete_all_rsp_handle(struct vdev_mlme_obj *vdev_mlme,
					struct peer_delete_all_response *rsp)
{
	struct wlan_objmgr_psoc *psoc;
	struct wlan_lmac_if_wifi_pos_rx_ops *rx_ops;
	QDF_STATUS status;

	psoc = wlan_vdev_get_psoc(vdev_mlme->vdev);
	if (!psoc)
		return -QDF_STATUS_E_INVAL;

	if (QDF_HAS_PARAM(rsp->peer_type_bitmap, WLAN_PEER_RTT_PASN)) {
		rx_ops = wifi_pos_get_rx_ops(psoc);
		if (!rx_ops ||
		    !rx_ops->wifi_pos_vdev_delete_all_ranging_peers_rsp_cb) {
			mlme_err("rx_ops is NULL");
			return QDF_STATUS_E_FAILURE;
		}

		status = rx_ops->wifi_pos_vdev_delete_all_ranging_peers_rsp_cb(
							psoc, rsp->vdev_id);
		return status;
	}

	status = lim_process_mlm_del_all_sta_rsp(vdev_mlme, rsp);
	if (QDF_IS_STATUS_ERROR(status))
		mlme_err("Failed to call lim_process_mlm_del_all_sta_rsp");

	return status;
}

#ifdef WLAN_FEATURE_11BE_MLO
static QDF_STATUS vdevmgr_reconfig_req_cb(struct scheduler_msg *msg)
{
	struct wlan_objmgr_vdev *vdev = msg->bodyptr;
	struct wlan_objmgr_psoc *psoc;
	uint8_t vdev_id;

	if (!vdev) {
		mlme_err("vdev null");
		return QDF_STATUS_E_INVAL;
	}

	psoc = wlan_vdev_get_psoc(vdev);
	if (!psoc) {
		mlme_err("Failed to get psoc");
		return QDF_STATUS_E_INVAL;
	}

	vdev_id = wlan_vdev_get_id(vdev);
	if (!wlan_get_vdev_link_removed_flag_by_vdev_id(psoc, vdev_id))
		mlme_cm_osif_link_reconfig_notify(vdev);

	policy_mgr_handle_link_removal_on_vdev(vdev);
	mlo_sta_stop_reconfig_timer_by_vdev(vdev);

	wlan_objmgr_vdev_release_ref(vdev, WLAN_MLME_CM_ID);

	return QDF_STATUS_SUCCESS;
}

static QDF_STATUS vdevmgr_reconfig_req_flush_cb(struct scheduler_msg *msg)
{
	struct wlan_objmgr_vdev *vdev = msg->bodyptr;

	if (!vdev) {
		mlme_err("vdev null");
		return QDF_STATUS_E_INVAL;
	}
	wlan_objmgr_vdev_release_ref(vdev, WLAN_MLME_CM_ID);

	return QDF_STATUS_SUCCESS;
}

static QDF_STATUS
vdevmgr_vdev_reconfig_notify(struct vdev_mlme_obj *vdev_mlme,
			     uint16_t *tbtt_count, uint16_t bcn_int)
{
	struct wlan_objmgr_vdev *vdev = vdev_mlme->vdev;

	if (!vdev) {
		mlme_err("invalid vdev");
		return QDF_STATUS_E_INVAL;
	}
	mlme_debug("vdev %d link removal notify tbtt %d bcn_int %d",
		   wlan_vdev_get_id(vdev), *tbtt_count, bcn_int);
	if (*tbtt_count * bcn_int <= LINK_REMOVAL_MIN_TIMEOUT_MS)
		*tbtt_count = 0;
	else if (bcn_int)
		*tbtt_count -= LINK_REMOVAL_MIN_TIMEOUT_MS / bcn_int;

	return QDF_STATUS_SUCCESS;
}

static void
vdevmgr_vdev_reconfig_timer_complete(struct vdev_mlme_obj *vdev_mlme)
{
	struct wlan_objmgr_vdev *vdev = vdev_mlme->vdev;
	struct scheduler_msg msg = {0};
	QDF_STATUS ret;

	if (!vdev) {
		mlme_err("invalid vdev");
		return;
	}
	mlme_debug("vdev %d link removal timed out", wlan_vdev_get_id(vdev));

	msg.bodyptr = vdev;
	msg.callback = vdevmgr_reconfig_req_cb;
	msg.flush_callback = vdevmgr_reconfig_req_flush_cb;

	ret = wlan_objmgr_vdev_try_get_ref(vdev, WLAN_MLME_CM_ID);
	if (QDF_IS_STATUS_ERROR(ret))
		return;

	ret = scheduler_post_message(QDF_MODULE_ID_MLME,
				     QDF_MODULE_ID_TARGET_IF,
				     QDF_MODULE_ID_TARGET_IF, &msg);

	if (QDF_IS_STATUS_ERROR(ret)) {
		mlme_err("vdev %d failed to post scheduler_msg",
			 wlan_vdev_get_id(vdev));
		wlan_objmgr_vdev_release_ref(vdev, WLAN_MLME_CM_ID);
		return;
	}
}
#endif

QDF_STATUS mlme_vdev_self_peer_create(struct wlan_objmgr_vdev *vdev)
{
	struct vdev_mlme_obj *vdev_mlme;

	vdev_mlme = wlan_vdev_mlme_get_cmpt_obj(vdev);
	if (!vdev_mlme) {
		mlme_err("Failed to get vdev mlme obj for vdev id %d",
			 wlan_vdev_get_id(vdev));
		return QDF_STATUS_E_INVAL;
	}

	return wma_vdev_self_peer_create(vdev_mlme);
}

static
QDF_STATUS vdevmgr_mlme_ext_post_hdl_create(struct vdev_mlme_obj *vdev_mlme)
{
	return QDF_STATUS_SUCCESS;
}

bool mlme_vdev_uses_self_peer(uint32_t vdev_type, uint32_t vdev_subtype)
{
	switch (vdev_type) {
	case WMI_VDEV_TYPE_AP:
		return vdev_subtype == WMI_UNIFIED_VDEV_SUBTYPE_P2P_DEVICE;

	case WMI_VDEV_TYPE_MONITOR:
	case WMI_VDEV_TYPE_OCB:
		return true;

	default:
		return false;
	}
}

void mlme_vdev_del_resp(uint8_t vdev_id)
{
	sme_vdev_del_resp(vdev_id);
}

static
QDF_STATUS mlme_vdev_self_peer_delete_resp_flush_cb(struct scheduler_msg *msg)
{
	/*
	 * sme should be the last component to hold the reference invoke the
	 * same to release the reference gracefully
	 */
	sme_vdev_self_peer_delete_resp(msg->bodyptr);
	return QDF_STATUS_SUCCESS;
}

void mlme_vdev_self_peer_delete_resp(struct del_vdev_params *param)
{
	struct scheduler_msg peer_del_rsp = {0};
	QDF_STATUS status;

	peer_del_rsp.type = eWNI_SME_VDEV_DELETE_RSP;
	peer_del_rsp.bodyptr = param;
	peer_del_rsp.flush_callback = mlme_vdev_self_peer_delete_resp_flush_cb;

	status = scheduler_post_message(QDF_MODULE_ID_MLME,
					QDF_MODULE_ID_SME,
					QDF_MODULE_ID_SME, &peer_del_rsp);
	if (!QDF_IS_STATUS_SUCCESS(status)) {
		/* In the error cases release the final sme reference */
		wlan_objmgr_vdev_release_ref(param->vdev, WLAN_LEGACY_SME_ID);
		qdf_mem_free(param);
	}
}

QDF_STATUS mlme_vdev_self_peer_delete(struct scheduler_msg *self_peer_del_msg)
{
	QDF_STATUS status;
	struct del_vdev_params *del_vdev = self_peer_del_msg->bodyptr;

	if (!del_vdev) {
		mlme_err("Invalid del self peer params");
		return QDF_STATUS_E_INVAL;
	}

	status = wma_vdev_detach(del_vdev);
	if (QDF_IS_STATUS_ERROR(status))
		mlme_err("Failed to detach vdev");

	return status;
}

QDF_STATUS wlan_sap_disconnect_all_p2p_client(uint8_t vdev_id)
{
	return csr_mlme_vdev_disconnect_all_p2p_client_event(vdev_id);
}

QDF_STATUS wlan_sap_stop_bss(uint8_t vdev_id)
{
	return csr_mlme_vdev_stop_bss(vdev_id);
}

qdf_freq_t wlan_get_conc_freq(void)
{
	return csr_mlme_get_concurrent_operation_freq();
}

/**
 * ap_mlme_vdev_csa_complete() - callback to initiate csa complete
 *
 * @vdev_mlme: vdev mlme object
 *
 * This function is called for csa complete indication
 *
 * Return: QDF_STATUS
 */
static QDF_STATUS ap_mlme_vdev_csa_complete(struct vdev_mlme_obj *vdev_mlme)

{
	uint8_t vdev_id;

	vdev_id = wlan_vdev_get_id(vdev_mlme->vdev);
	mlme_legacy_debug("vdev id = %d ", vdev_id);

	if (lim_is_csa_tx_pending(vdev_id))
		lim_send_csa_tx_complete(vdev_id);
	else
		mlme_legacy_debug("CSAIE_TX_COMPLETE_IND already sent");

	return QDF_STATUS_SUCCESS;
}

#ifdef WLAN_FEATURE_LL_LT_SAP
QDF_STATUS
wlan_ll_sap_sort_channel_list(uint8_t vdev_id, qdf_list_t *list,
			      struct sap_sel_ch_info *ch_info)
{
	return wlansap_sort_channel_list(vdev_id, list, ch_info);
}
#endif

void
wlan_sap_get_user_config_acs_ch_list(uint8_t vdev_id,
				     struct scan_filter *filter)
{
	wlansap_get_user_config_acs_ch_list(vdev_id, filter);
}

static struct vdev_mlme_ops sta_mlme_ops = {
	.mlme_vdev_start_send = sta_mlme_vdev_start_send,
	.mlme_vdev_restart_send = sta_mlme_vdev_restart_send,
	.mlme_vdev_start_continue = sta_mlme_start_continue,
	.mlme_vdev_start_req_failed = sta_mlme_vdev_start_req_failed,
	.mlme_vdev_sta_conn_start = sta_mlme_vdev_start_connection,
	.mlme_vdev_up_send = sta_mlme_vdev_up_send,
	.mlme_vdev_notify_up_complete = sta_mlme_vdev_notify_up_complete,
	.mlme_vdev_notify_roam_start = sta_mlme_vdev_notify_roam_start,
	.mlme_vdev_disconnect_peers = sta_mlme_vdev_disconnect_bss,
	.mlme_vdev_stop_send = sta_mlme_vdev_stop_send,
	.mlme_vdev_stop_continue = vdevmgr_mlme_stop_continue,
	.mlme_vdev_down_send = vdevmgr_mlme_vdev_down_send,
	.mlme_vdev_notify_down_complete = vdevmgr_notify_down_complete,
	.mlme_vdev_ext_stop_rsp = vdevmgr_vdev_stop_rsp_handle,
	.mlme_vdev_ext_start_rsp = vdevmgr_vdev_start_rsp_handle,
	.mlme_vdev_sta_disconn_start = sta_mlme_vdev_sta_disconnect_start,
	.mlme_vdev_ext_peer_delete_all_rsp =
			vdevmgr_vdev_peer_delete_all_rsp_handle,
#ifdef WLAN_FEATURE_11BE_MLO
	.mlme_vdev_reconfig_notify =
			vdevmgr_vdev_reconfig_notify,
	.mlme_vdev_reconfig_timer_complete =
			vdevmgr_vdev_reconfig_timer_complete,
#endif
};

static struct vdev_mlme_ops ap_mlme_ops = {
	.mlme_vdev_start_send = ap_mlme_vdev_start_send,
	.mlme_vdev_restart_send = ap_mlme_vdev_restart_send,
	.mlme_vdev_stop_start_send = ap_mlme_vdev_stop_start_send,
	.mlme_vdev_start_continue = ap_mlme_start_continue,
	.mlme_vdev_start_req_failed = ap_mlme_vdev_start_req_failed,
	.mlme_vdev_up_send = ap_mlme_vdev_up_send,
	.mlme_vdev_notify_up_complete = ap_mlme_vdev_notify_up_complete,
	.mlme_vdev_update_beacon = ap_mlme_vdev_update_beacon,
	.mlme_vdev_disconnect_peers = ap_mlme_vdev_disconnect_peers,
	.mlme_vdev_dfs_cac_timer_stop = ap_vdev_dfs_cac_timer_stop,
	.mlme_vdev_stop_send = ap_mlme_vdev_stop_send,
	.mlme_vdev_stop_continue = vdevmgr_mlme_stop_continue,
	.mlme_vdev_down_send = vdevmgr_mlme_vdev_down_send,
	.mlme_vdev_notify_down_complete = vdevmgr_notify_down_complete,
	.mlme_vdev_is_newchan_no_cac = ap_mlme_vdev_is_newchan_no_cac,
	.mlme_vdev_ext_stop_rsp = vdevmgr_vdev_stop_rsp_handle,
	.mlme_vdev_ext_start_rsp = vdevmgr_vdev_start_rsp_handle,
	.mlme_vdev_ext_peer_delete_all_rsp =
				vdevmgr_vdev_peer_delete_all_rsp_handle,
	.mlme_vdev_csa_complete = ap_mlme_vdev_csa_complete,
};

static struct vdev_mlme_ops mon_mlme_ops = {
	.mlme_vdev_start_send = mon_mlme_vdev_start_restart_send,
	.mlme_vdev_restart_send = mon_mlme_vdev_start_restart_send,
	.mlme_vdev_start_continue = mon_mlme_start_continue,
	.mlme_vdev_up_send = mon_mlme_vdev_up_send,
	.mlme_vdev_disconnect_peers = mon_mlme_vdev_disconnect_peers,
	.mlme_vdev_stop_send = mon_mlme_vdev_stop_send,
	.mlme_vdev_down_send = mon_mlme_vdev_down_send,
	.mlme_vdev_ext_start_rsp = vdevmgr_vdev_start_rsp_handle,
};

static struct mlme_ext_ops ext_ops = {
	.mlme_psoc_ext_hdl_create = psoc_mlme_ext_hdl_create,
	.mlme_psoc_ext_hdl_destroy = psoc_mlme_ext_hdl_destroy,
	.mlme_vdev_ext_hdl_create = vdevmgr_mlme_ext_hdl_create,
	.mlme_vdev_ext_hdl_destroy = vdevmgr_mlme_ext_hdl_destroy,
	.mlme_vdev_ext_hdl_post_create = vdevmgr_mlme_ext_post_hdl_create,
	.mlme_vdev_ext_delete_rsp = vdevmgr_vdev_delete_rsp_handle,
	.mlme_cm_ext_hdl_create_cb = cm_ext_hdl_create,
	.mlme_cm_ext_hdl_destroy_cb = cm_ext_hdl_destroy,
	.mlme_cm_ext_connect_start_ind_cb = cm_connect_start_ind,
	.mlme_cm_ext_connect_req_cb = cm_handle_connect_req,
	.mlme_cm_ext_bss_peer_create_req_cb = cm_send_bss_peer_create_req,
	.mlme_cm_ext_connect_complete_ind_cb = cm_connect_complete_ind,
	.mlme_cm_ext_disconnect_start_ind_cb = cm_disconnect_start_ind,
	.mlme_cm_ext_disconnect_req_cb = cm_handle_disconnect_req,
	.mlme_cm_ext_bss_peer_delete_req_cb = cm_send_bss_peer_delete_req,
	.mlme_cm_ext_disconnect_complete_ind_cb = cm_disconnect_complete_ind,
	.mlme_cm_ext_vdev_down_req_cb = cm_send_vdev_down_req,
	.mlme_cm_ext_reassoc_req_cb = cm_handle_reassoc_req,
	.mlme_cm_ext_roam_start_ind_cb = cm_handle_roam_start,
	.mlme_psoc_ext_hdl_enable = psoc_mlme_ext_hdl_enable,
	.mlme_psoc_ext_hdl_disable = psoc_mlme_ext_hdl_disable,
#ifdef WLAN_FEATURE_DYNAMIC_MAC_ADDR_UPDATE
	.mlme_vdev_send_set_mac_addr = vdevmgr_mlme_vdev_send_set_mac_addr,
#endif
	.mlme_cm_ext_rso_stop_cb = cm_send_rso_stop,
};

#ifdef WLAN_FEATURE_11BE_MLO
static struct mlo_mlme_ext_ops mlo_ext_ops = {
	.mlo_mlme_ext_peer_create = lim_mlo_proc_assoc_req_frm,
	.mlo_mlme_ext_peer_delete = lim_mlo_cleanup_partner_peer,
	.mlo_mlme_ext_peer_assoc_fail = lim_mlo_ap_sta_assoc_fail,
	.mlo_mlme_ext_assoc_resp = lim_mlo_ap_sta_assoc_suc,
	.mlo_mlme_ext_handle_sta_csa_param = lim_handle_mlo_sta_csa_param,
};
#endif
