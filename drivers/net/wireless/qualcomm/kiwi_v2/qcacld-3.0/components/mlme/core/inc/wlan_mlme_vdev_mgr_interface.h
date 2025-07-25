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
 * DOC: declare VDEV Manager interface APIs exposed by the mlme component
 */

#ifndef _WLAN_MLME_VDEV_MGR_INT_API_H_
#define _WLAN_MLME_VDEV_MGR_INT_API_H_

#include <wlan_objmgr_vdev_obj.h>
#include "include/wlan_vdev_mlme.h"
#include "wlan_mlme_main.h"
#include "wma_if.h"

/**
 * mlme_register_mlme_ext_ops() - Register mlme ext ops
 *
 * This function is called to register mlme ext operations
 *
 * Return: QDF_STATUS
 */
QDF_STATUS mlme_register_mlme_ext_ops(void);

/**
 * mlme_register_mlo_ext_ops() - Register mlme mlo ext ops
 *
 * This function is called to register mlme mlo ext operations
 *
 * Return: QDF_STATUS
 */
QDF_STATUS mlme_register_mlo_ext_ops(void);

/**
 * mlme_unregister_mlo_ext_ops() - Unregister mlme mlo ext ops
 *
 * This function is called to unregister mlme mlo ext operations
 *
 * Return: QDF_STATUS
 */
QDF_STATUS mlme_unregister_mlo_ext_ops(void);

/**
 * mlme_register_vdev_mgr_ops() - Register vdev mgr ops
 * @vdev_mlme: vdev mlme object
 *
 * This function is called to register vdev manager operations
 *
 * Return: QDF_STATUS
 */
QDF_STATUS mlme_register_vdev_mgr_ops(struct vdev_mlme_obj *vdev_mlme);
/**
 * mlme_unregister_vdev_mgr_ops() - Unregister vdev mgr ops
 * @vdev_mlme: vdev mlme object
 *
 * This function is called to unregister vdev manager operations
 *
 * Return: QDF_STATUS
 */
QDF_STATUS mlme_unregister_vdev_mgr_ops(struct vdev_mlme_obj *vdev_mlme);

/**
 * mlme_set_chan_switch_in_progress() - set mlme priv restart in progress
 * @vdev: vdev pointer
 * @val: value to be set
 *
 * Return: QDF_STATUS
 */
QDF_STATUS mlme_set_chan_switch_in_progress(struct wlan_objmgr_vdev *vdev,
					       bool val);

#ifdef WLAN_FEATURE_MSCS
/**
 * mlme_set_is_mscs_req_sent() - set mscs frame req flag
 * @vdev: vdev pointer
 * @val: value to be set
 *
 * Return: QDF_STATUS
 */
QDF_STATUS mlme_set_is_mscs_req_sent(struct wlan_objmgr_vdev *vdev, bool val);

/**
 * mlme_get_is_mscs_req_sent() - get mscs frame req flag
 * @vdev: vdev pointer
 *
 * Return: value of mscs flag
 */
bool mlme_get_is_mscs_req_sent(struct wlan_objmgr_vdev *vdev);
#else
static inline
QDF_STATUS mlme_set_is_mscs_req_sent(struct wlan_objmgr_vdev *vdev, bool val)
{
	return QDF_STATUS_E_FAILURE;
}

static inline
bool mlme_get_is_mscs_req_sent(struct wlan_objmgr_vdev *vdev)
{
	return false;
}
#endif

/**
 * mlme_is_chan_switch_in_progress() - get mlme priv restart in progress
 * @vdev: vdev pointer
 *
 * Return: value of mlme priv restart in progress
 */
bool mlme_is_chan_switch_in_progress(struct wlan_objmgr_vdev *vdev);

/**
 * ap_mlme_set_hidden_ssid_restart_in_progress() - set mlme priv hidden ssid
 * restart in progress
 * @vdev: vdev pointer
 * @val: value to be set
 *
 * Return: QDF_STATUS
 */
QDF_STATUS
ap_mlme_set_hidden_ssid_restart_in_progress(struct wlan_objmgr_vdev *vdev,
					    bool val);

/**
 * ap_mlme_is_hidden_ssid_restart_in_progress() - get mlme priv hidden ssid
 * restart in progress
 * @vdev: vdev pointer
 *
 * Return: value of mlme priv hidden ssid restart in progress
 */
bool ap_mlme_is_hidden_ssid_restart_in_progress(struct wlan_objmgr_vdev *vdev);

/**
 * mlme_set_vdev_start_failed() - set mlme priv vdev restart fail flag
 * @vdev: vdev pointer
 * @val: value to be set
 *
 * Return: QDF_STATUS
 */
QDF_STATUS
mlme_set_vdev_start_failed(struct wlan_objmgr_vdev *vdev, bool val);

/**
 * mlme_is_connection_fail() - get connection fail flag
 * @vdev: vdev pointer
 *
 * Return: value of vdev connection failure flag
 */
bool mlme_is_connection_fail(struct wlan_objmgr_vdev *vdev);

/**
 * mlme_is_wapi_sta_active() - check sta with wapi security exists and is active
 * @pdev: pdev pointer
 *
 * Return: true if sta with wapi security exists
 */
#ifdef FEATURE_WLAN_WAPI
bool mlme_is_wapi_sta_active(struct wlan_objmgr_pdev *pdev);
#else
static inline bool mlme_is_wapi_sta_active(struct wlan_objmgr_pdev *pdev)
{
	return false;
}
#endif

QDF_STATUS mlme_set_bigtk_support(struct wlan_objmgr_vdev *vdev, bool val);

bool mlme_get_bigtk_support(struct wlan_objmgr_vdev *vdev);

#ifdef FEATURE_WLAN_TDLS
/**
 * mlme_set_tdls_chan_switch_prohibited() - set tdls chan switch prohibited
 * @vdev: vdev pointer
 * @val: value to be set
 *
 * Return: QDF_STATUS
 */
QDF_STATUS
mlme_set_tdls_chan_switch_prohibited(struct wlan_objmgr_vdev *vdev, bool val);

/**
 * mlme_get_tdls_chan_switch_prohibited() - get tdls chan switch prohibited
 * @vdev: vdev pointer
 *
 * Return: bool
 */
bool mlme_get_tdls_chan_switch_prohibited(struct wlan_objmgr_vdev *vdev);

/**
 * mlme_set_tdls_prohibited() - set tdls prohibited
 * @vdev: vdev pointer
 * @val: value to be set
 *
 * Return: QDF_STATUS
 */
QDF_STATUS
mlme_set_tdls_prohibited(struct wlan_objmgr_vdev *vdev, bool val);

/**
 * mlme_get_tdls_prohibited() - get tdls prohibited
 * @vdev: vdev pointer
 *
 * Return: bool
 */
bool mlme_get_tdls_prohibited(struct wlan_objmgr_vdev *vdev);
#else
static inline QDF_STATUS
mlme_set_tdls_chan_switch_prohibited(struct wlan_objmgr_vdev *vdev, bool val)
{
	return QDF_STATUS_SUCCESS;
}

static inline
bool mlme_get_tdls_chan_switch_prohibited(struct wlan_objmgr_vdev *vdev)
{
	return false;
}

static inline QDF_STATUS
mlme_set_tdls_prohibited(struct wlan_objmgr_vdev *vdev, bool val)
{
	return QDF_STATUS_SUCCESS;
}

static inline bool mlme_get_tdls_prohibited(struct wlan_objmgr_vdev *vdev)
{
	return false;
}
#endif
/**
 * mlme_set_roam_reason_better_ap() - set roam reason better AP
 * @vdev: vdev pointer
 * @val: value to be set
 *
 * Return: QDF_STATUS
 */
QDF_STATUS
mlme_set_roam_reason_better_ap(struct wlan_objmgr_vdev *vdev, bool val);

/**
 * mlme_get_roam_reason_better_ap() - get roam reason better AP
 * @vdev: vdev pointer
 *
 * Return: bool
 */
bool mlme_get_roam_reason_better_ap(struct wlan_objmgr_vdev *vdev);

/**
 * mlme_set_hb_ap_rssi() - set hb ap RSSI
 * @vdev: vdev pointer
 * @val: value to be set
 *
 * Return: QDF_STATUS
 */
QDF_STATUS mlme_set_hb_ap_rssi(struct wlan_objmgr_vdev *vdev, uint32_t val);

/**
 * mlme_get_hb_ap_rssi() - get HB AP RSSIc
 * @vdev: vdev pointer
 *
 * Return: rssi value
 */
uint32_t mlme_get_hb_ap_rssi(struct wlan_objmgr_vdev *vdev);

/**
 * mlme_set_connection_fail() - set connection failure flag
 * @vdev: vdev pointer
 * @val: value to be set
 *
 * Return: QDF_STATUS
 */
QDF_STATUS
mlme_set_connection_fail(struct wlan_objmgr_vdev *vdev, bool val);

/**
 * mlme_get_vdev_start_failed() - get mlme priv vdev restart fail flag
 * @vdev: vdev pointer
 *
 * Return: value of mlme priv vdev restart fail flag
 */
bool mlme_get_vdev_start_failed(struct wlan_objmgr_vdev *vdev);

/**
 * mlme_get_cac_required() - get if cac is required for new channel
 * @vdev: vdev pointer
 *
 * Return: if cac is required
 */
bool mlme_get_cac_required(struct wlan_objmgr_vdev *vdev);

/**
 * mlme_set_cac_required() - set if cac is required for new channel
 * @vdev: vdev pointer
 * @val: value to be set
 *
 * Return: QDF_STATUS
 */
QDF_STATUS
mlme_set_cac_required(struct wlan_objmgr_vdev *vdev, bool val);

/**
 * mlme_set_mbssid_info() - save mbssid info
 * @vdev: vdev pointer
 * @mbssid_info: mbssid info
 * @freq: current operating frequency
 *
 * Return: QDF_STATUS
 */
QDF_STATUS
mlme_set_mbssid_info(struct wlan_objmgr_vdev *vdev,
		     struct scan_mbssid_info *mbssid_info, qdf_freq_t freq);

/**
 * mlme_get_mbssid_info() - get mbssid info
 * @vdev: vdev pointer
 * @mbss_11ax: mbss 11ax info
 *
 * Return: None
 */
void mlme_get_mbssid_info(struct wlan_objmgr_vdev *vdev,
			  struct vdev_mlme_mbss_11ax *mbss_11ax);

/**
 * mlme_set_tx_power() - set tx power
 * @vdev: vdev pointer
 * @tx_power: tx power to be set
 *
 * Return: QDF_STATUS
 */
QDF_STATUS mlme_set_tx_power(struct wlan_objmgr_vdev *vdev,
			     int8_t tx_power);

/**
 * mlme_get_tx_power() - get tx power
 * @vdev: vdev pointer
 *
 * Return: current tx power
 */
int8_t mlme_get_tx_power(struct wlan_objmgr_vdev *vdev);

/**
 * mlme_get_max_reg_power() - get max reg power
 * @vdev: vdev pointer
 *
 * Return: max reg power
 */
int8_t mlme_get_max_reg_power(struct wlan_objmgr_vdev *vdev);

/**
 * mlme_set_max_reg_power() - set max reg power
 * @vdev: vdev pointer
 * @max_reg_power: max regulatory power to be set
 *
 * Return: QDF_STATUS
 */
QDF_STATUS mlme_set_max_reg_power(struct wlan_objmgr_vdev *vdev,
				 int8_t max_reg_power);

/**
 * mlme_is_vdev_in_beaconning_mode() - check if vdev is beaconing mode
 * @vdev_opmode: vdev opmode
 *
 * To check if vdev is operating in beaconing mode or not.
 *
 * Return: true or false
 */
bool mlme_is_vdev_in_beaconning_mode(enum QDF_OPMODE vdev_opmode);

/**
 * mlme_set_assoc_type() - set associate type
 * @vdev: vdev pointer
 * @assoc_type: type to be set
 *
 * Return: QDF_STATUS
 */
QDF_STATUS mlme_set_assoc_type(struct wlan_objmgr_vdev *vdev,
			       enum vdev_assoc_type assoc_type);

/**
 * mlme_get_vdev_stop_type() - to get vdev stop type
 * @vdev: vdev pointer
 * @vdev_stop_type: vdev stop type
 *
 * This API will get vdev stop type from mlme legacy priv.
 *
 * Return: QDF_STATUS
 */
QDF_STATUS mlme_get_vdev_stop_type(struct wlan_objmgr_vdev *vdev,
				   uint32_t *vdev_stop_type);

/**
 * mlme_set_vdev_stop_type() - to set vdev stop type
 * @vdev: vdev pointer
 * @vdev_stop_type: vdev stop type
 *
 * This API will set vdev stop type from mlme legacy priv.
 *
 * Return: QDF_STATUS
 */
QDF_STATUS mlme_set_vdev_stop_type(struct wlan_objmgr_vdev *vdev,
				   uint32_t vdev_stop_type);

/**
 * mlme_is_notify_co_located_ap_update_rnr() - Need co-located ap update rnr
 * @vdev: vdev pointer
 *
 * Return: True if vdev need notify co-located ap to update rnr.
 */
bool mlme_is_notify_co_located_ap_update_rnr(struct wlan_objmgr_vdev *vdev);

/**
 * mlme_set_notify_co_located_ap_update_rnr() - notify co-located ap to update
 *                                              rnr
 * @vdev: vdev pointer
 * @update_rnr: whether to notify co-located ap to update rnr
 *
 * Return: Void
 */
void mlme_set_notify_co_located_ap_update_rnr(struct wlan_objmgr_vdev *vdev,
					      bool update_rnr);

/**
 * wlan_is_vdev_traffic_ll_ht() - if vdev traffic type is low latency or high TP
 * @vdev: vdev pointer
 *
 * Return: true is LL or HT is set.
 */
bool wlan_is_vdev_traffic_ll_ht(struct wlan_objmgr_vdev *vdev);

/**
 * mlme_get_vdev_wifi_std() - get the wifi std version for the vdev
 * @vdev: vdev pointer
 *
 * Return: WMI_HOST_WIFI_STANDARD
 */
WMI_HOST_WIFI_STANDARD mlme_get_vdev_wifi_std(struct wlan_objmgr_vdev *vdev);

/**
 * mlme_get_assoc_type() - get associate type
 * @vdev: vdev pointer
 *
 * Return: associate type
 */
enum vdev_assoc_type  mlme_get_assoc_type(struct wlan_objmgr_vdev *vdev);

/**
 * mlme_vdev_self_peer_create() - function to send the vdev create self peer
 * @vdev: vdev pointer
 *
 * Return: QDF_STATUS_SUCCESS when the self peer is successfully created
 * to firmware or QDF_STATUS_E_** when there is a failure.
 */
QDF_STATUS mlme_vdev_self_peer_create(struct wlan_objmgr_vdev *vdev);

/**
 * mlme_vdev_self_peer_delete() - function to delete vdev self peer
 * @self_peer_del_msg: scheduler message containing the del_vdev_params
 *
 * Return: QDF_STATUS_SUCCESS when the self peer is successfully deleted
 * to firmware or QDF_STATUS_E_** when there is a failure.
 */
QDF_STATUS mlme_vdev_self_peer_delete(struct scheduler_msg *self_peer_del_msg);

/**
 * mlme_vdev_uses_self_peer() - does vdev use self peer?
 * @vdev_type: vdev type
 * @vdev_subtype: vdev subtype
 *
 * Return: true if the vdev type/subtype uses the self peer
 */
bool mlme_vdev_uses_self_peer(uint32_t vdev_type, uint32_t vdev_subtype);

/**
 * mlme_vdev_self_peer_delete_resp() - send vdev self peer delete resp to Upper
 * layer
 * @param: params of del vdev response
 *
 * Return: none
 */
void mlme_vdev_self_peer_delete_resp(struct del_vdev_params *param);

/**
 * mlme_vdev_del_resp() - send vdev delete resp to Upper layer
 * @vdev_id: vdev id for which del vdev response is received
 *
 * Return: none
 */
void mlme_vdev_del_resp(uint8_t vdev_id);

#if defined(WLAN_FEATURE_11BE_MLO) && defined(WLAN_FEATURE_ROAM_OFFLOAD)
/**
 * mlme_set_single_link_mlo_roaming() - to set single link mlo roaming
 * @vdev: vdev pointer
 * @val: single link mlo roaming value true/false
 *
 * This API will set single link mlo roaming value.
 *
 * Return: QDF_STATUS
 */
QDF_STATUS
mlme_set_single_link_mlo_roaming(struct wlan_objmgr_vdev *vdev, bool val);

/**
 * mlme_get_single_link_mlo_roaming() - get single link mlo roaming
 * @vdev: vdev pointer
 *
 * Return: single link mlo roaming boolean value true/false
 */
bool mlme_get_single_link_mlo_roaming(struct wlan_objmgr_vdev *vdev);
#endif
/**
 * wlan_sap_disconnect_all_p2p_client() - send SAP disconnect all P2P
 *	client event to the SAP event handler
 * @vdev_id: vdev id of SAP
 *
 * Return: QDF_STATUS
 */
QDF_STATUS wlan_sap_disconnect_all_p2p_client(uint8_t vdev_id);

/**
 * wlan_sap_stop_bss() - send SAP stop bss event to the SAP event
 *	handler
 * @vdev_id: vdev id of SAP
 *
 * Return: QDF_STATUS
 */
QDF_STATUS wlan_sap_stop_bss(uint8_t vdev_id);

/**
 * wlan_get_conc_freq() - get concurrent operation frequency
 *
 * Return: concurrent frequency
 */
qdf_freq_t wlan_get_conc_freq(void);

#ifdef WLAN_FEATURE_11BE_MLO
/**
 * wlan_handle_emlsr_sta_concurrency() - Handle concurrency scenarios with
 * EMLSR STA.
 * @psoc: pointer to psoc
 * @conc_con_coming_up: Carries true if any concurrent connection(STA/SAP/NAN)
 *			is comng up
 * @emlsr_sta_coming_up: Check if the new connection request is EMLSR STA
 *
 * The API handles concurrency scenarios with existing EMLSR connection when a
 * new connection request is received OR with an existing legacy connection when
 * an EMLSR sta comes up.
 *
 * Return: none
 */
void
wlan_handle_emlsr_sta_concurrency(struct wlan_objmgr_psoc *psoc,
				  bool conc_con_coming_up,
				  bool emlsr_sta_coming_up);
#else
static inline void
wlan_handle_emlsr_sta_concurrency(struct wlan_objmgr_psoc *psoc,
				  bool conc_con_coming_up,
				  bool emlsr_sta_coming_up)
{
}
#endif

#ifdef WLAN_FEATURE_LL_LT_SAP
/**
 * wlan_ll_sap_sort_channel_list() - Sort channel list
 * @vdev_id: Vdev Id
 * @list: Pointer to list
 * @ch_info: Pointer to ch_info
 *
 * Return: QDF_STATUS
 */
QDF_STATUS
wlan_ll_sap_sort_channel_list(uint8_t vdev_id, qdf_list_t *list,
			      struct sap_sel_ch_info *ch_info);
#endif

/**
 * wlan_sap_get_user_config_acs_ch_list: Get user configured channel list
 * @vdev_id: Vdev Id
 * @filter: Filter to apply to get scan result
 *
 * Return: None
 *
 */
void
wlan_sap_get_user_config_acs_ch_list(uint8_t vdev_id,
				     struct scan_filter *filter);
#endif
