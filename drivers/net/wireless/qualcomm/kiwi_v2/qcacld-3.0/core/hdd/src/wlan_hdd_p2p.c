/*
 * Copyright (c) 2012-2021 The Linux Foundation. All rights reserved.
 * Copyright (c) 2022-2023 Qualcomm Innovation Center, Inc. All rights reserved.
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
 * DOC: wlan_hdd_p2p.c
 *
 * WLAN Host Device Driver implementation for P2P commands interface
 */

#include "osif_sync.h"
#include <wlan_hdd_includes.h>
#include <wlan_hdd_hostapd.h>
#include <net/cfg80211.h>
#include "sme_api.h"
#include "sme_qos_api.h"
#include "wlan_hdd_p2p.h"
#include "sap_api.h"
#include "wlan_hdd_main.h"
#include "qdf_trace.h"
#include <linux/netdevice.h>
#include <linux/skbuff.h>
#include <linux/etherdevice.h>
#include <net/ieee80211_radiotap.h>
#include "wlan_hdd_tdls.h"
#include "wlan_hdd_trace.h"
#include "qdf_types.h"
#include "qdf_trace.h"
#include "cds_sched.h"
#include "wlan_policy_mgr_api.h"
#include "cds_utils.h"
#include "wlan_p2p_public_struct.h"
#include "wlan_p2p_ucfg_api.h"
#include "wlan_cfg80211_p2p.h"
#include "wlan_p2p_cfg_api.h"
#include "wlan_policy_mgr_ucfg.h"
#include "nan_ucfg_api.h"
#include "wlan_pkt_capture_ucfg_api.h"
#include "wlan_hdd_object_manager.h"
#include "wlan_hdd_pre_cac.h"
#include "wlan_pre_cac_ucfg_api.h"
#include "wlan_dp_ucfg_api.h"
#include "wlan_psoc_mlme_ucfg_api.h"
#include "os_if_dp_local_pkt_capture.h"

/* Ms to Time Unit Micro Sec */
#define MS_TO_TU_MUS(x)   ((x) * 1024)
#define MAX_MUS_VAL       (INT_MAX / 1024)

/* Clean up RoC context at hdd_stop_adapter*/
void
wlan_hdd_cleanup_remain_on_channel_ctx(struct wlan_hdd_link_info *link_info)
{
	struct wlan_objmgr_vdev *vdev;

	vdev = hdd_objmgr_get_vdev_by_user(link_info, WLAN_OSIF_P2P_ID);
	if (!vdev)
		return;

	ucfg_p2p_cleanup_roc_by_vdev(vdev);
	hdd_objmgr_put_vdev_by_user(vdev, WLAN_OSIF_P2P_ID);
}

void wlan_hdd_cleanup_actionframe(struct wlan_hdd_link_info *link_info)
{
	struct wlan_objmgr_vdev *vdev;

	vdev = hdd_objmgr_get_vdev_by_user(link_info, WLAN_OSIF_P2P_ID);
	if (!vdev)
		return;
	ucfg_p2p_cleanup_tx_by_vdev(vdev);
	hdd_objmgr_put_vdev_by_user(vdev, WLAN_OSIF_P2P_ID);
}

static int __wlan_hdd_cfg80211_remain_on_channel(struct wiphy *wiphy,
						 struct wireless_dev *wdev,
						 struct ieee80211_channel *chan,
						 unsigned int duration,
						 u64 *cookie)
{
	struct net_device *dev = wdev->netdev;
	struct hdd_adapter *adapter = WLAN_HDD_GET_PRIV_PTR(dev);
	struct hdd_context *hdd_ctx;
	struct wlan_objmgr_vdev *vdev;
	QDF_STATUS status;
	int ret;

	hdd_enter();

	hdd_ctx = WLAN_HDD_GET_CTX(adapter);
	ret = wlan_hdd_validate_context(hdd_ctx);
	if (0 != ret)
		return ret;

	if (QDF_GLOBAL_FTM_MODE == hdd_get_conparam()) {
		hdd_err("Command not allowed in FTM mode");
		return -EINVAL;
	}

	wlan_hdd_lpc_handle_concurrency(hdd_ctx, false);
	if (policy_mgr_is_sta_mon_concurrency(hdd_ctx->psoc) &&
	    !hdd_lpc_is_work_scheduled(hdd_ctx))
		return -EINVAL;

	if (wlan_hdd_validate_vdev_id(adapter->deflink->vdev_id))
		return -EINVAL;

	vdev = hdd_objmgr_get_vdev_by_user(adapter->deflink, WLAN_OSIF_P2P_ID);
	if (!vdev) {
		hdd_err("vdev is NULL");
		return -EINVAL;
	}

	if (!wlan_is_scan_allowed(vdev)) {
		wlan_objmgr_vdev_release_ref(vdev, WLAN_OSIF_P2P_ID);
		return -EBUSY;
	}

	/* Disable NAN Discovery if enabled */
	ucfg_nan_disable_concurrency(hdd_ctx->psoc);

	status = wlan_cfg80211_roc(vdev, chan, duration, cookie);
	hdd_objmgr_put_vdev_by_user(vdev, WLAN_OSIF_P2P_ID);
	hdd_debug("remain on channel request, status:%d, cookie:0x%llx",
		  status, *cookie);

	return qdf_status_to_os_return(status);
}

int wlan_hdd_cfg80211_remain_on_channel(struct wiphy *wiphy,
					struct wireless_dev *wdev,
					struct ieee80211_channel *chan,
					unsigned int duration, u64 *cookie)
{
	int errno;
	struct osif_vdev_sync *vdev_sync;

	errno = osif_vdev_sync_op_start(wdev->netdev, &vdev_sync);
	if (errno)
		return errno;

	errno = __wlan_hdd_cfg80211_remain_on_channel(wiphy, wdev, chan,
						      duration, cookie);

	osif_vdev_sync_op_stop(vdev_sync);

	return errno;
}

static int
__wlan_hdd_cfg80211_cancel_remain_on_channel(struct wiphy *wiphy,
					     struct wireless_dev *wdev,
					     u64 cookie)
{
	QDF_STATUS status;
	struct net_device *dev = wdev->netdev;
	struct hdd_adapter *adapter = WLAN_HDD_GET_PRIV_PTR(dev);
	struct wlan_objmgr_vdev *vdev;

	hdd_enter();

	if (QDF_GLOBAL_FTM_MODE == hdd_get_conparam()) {
		hdd_err("Command not allowed in FTM mode");
		return -EINVAL;
	}

	if (wlan_hdd_validate_vdev_id(adapter->deflink->vdev_id))
		return -EINVAL;

	vdev = hdd_objmgr_get_vdev_by_user(adapter->deflink, WLAN_OSIF_P2P_ID);
	if (!vdev) {
		hdd_err("vdev is NULL");
		return -EINVAL;
	}

	status = wlan_cfg80211_cancel_roc(vdev, cookie);
	hdd_objmgr_put_vdev_by_user(vdev, WLAN_OSIF_P2P_ID);

	hdd_debug("cancel remain on channel, status:%d", status);

	return 0;
}

int wlan_hdd_cfg80211_cancel_remain_on_channel(struct wiphy *wiphy,
					       struct wireless_dev *wdev,
					       u64 cookie)
{
	int errno;
	struct osif_vdev_sync *vdev_sync;

	errno = osif_vdev_sync_op_start(wdev->netdev, &vdev_sync);
	if (errno)
		return errno;

	errno = __wlan_hdd_cfg80211_cancel_remain_on_channel(wiphy, wdev,
							     cookie);

	osif_vdev_sync_op_stop(vdev_sync);

	return errno;
}

#define WLAN_AUTH_FRAME_MIN_LEN 2
static int __wlan_hdd_mgmt_tx(struct wiphy *wiphy, struct wireless_dev *wdev,
			      struct ieee80211_channel *chan, bool offchan,
			      unsigned int wait,
			      const u8 *buf, size_t len, bool no_cck,
			      bool dont_wait_for_ack, u64 *cookie)
{
	QDF_STATUS status;
	struct net_device *dev = wdev->netdev;
	struct hdd_adapter *adapter = WLAN_HDD_GET_PRIV_PTR(dev);
	struct hdd_context *hdd_ctx = WLAN_HDD_GET_CTX(adapter);
	struct wlan_objmgr_vdev *vdev;
	uint8_t type, sub_type;
	uint16_t auth_algo;
	QDF_STATUS qdf_status;
	int ret;
	uint32_t assoc_resp_len, ft_info_len = 0;
	const uint8_t  *assoc_resp;
	void *ft_info;
	struct hdd_ap_ctx *ap_ctx;

	if (QDF_GLOBAL_FTM_MODE == hdd_get_conparam()) {
		hdd_err("Command not allowed in FTM mode");
		return -EINVAL;
	}

	if (wlan_hdd_validate_vdev_id(adapter->deflink->vdev_id))
		return -EINVAL;

	ret = wlan_hdd_validate_context(hdd_ctx);
	if (ret)
		return ret;

	type = WLAN_HDD_GET_TYPE_FRM_FC(buf[0]);
	sub_type = WLAN_HDD_GET_SUBTYPE_FRM_FC(buf[0]);
	hdd_debug("type %d, sub_type %d", type, sub_type);

	/* When frame to be transmitted is auth mgmt, then trigger
	 * sme_send_mgmt_tx to send auth frame without need for policy manager.
	 * Where as wlan_cfg80211_mgmt_tx requires roc and requires approval
	 * from policy manager.
	 */
	if ((adapter->device_mode == QDF_STA_MODE ||
	     adapter->device_mode == QDF_SAP_MODE ||
	     adapter->device_mode == QDF_P2P_CLIENT_MODE ||
	     adapter->device_mode == QDF_P2P_GO_MODE ||
	     adapter->device_mode == QDF_NAN_DISC_MODE) &&
	    (type == SIR_MAC_MGMT_FRAME &&
	    sub_type == SIR_MAC_MGMT_AUTH)) {
		/* Request ROC for PASN authentication frame */
		if (len > (sizeof(struct wlan_frame_hdr) +
			   WLAN_AUTH_FRAME_MIN_LEN)) {
			auth_algo =
				*(uint16_t *)(buf +
					      sizeof(struct wlan_frame_hdr));
			if (auth_algo == eSIR_AUTH_TYPE_PASN)
				goto off_chan_tx;
			if ((auth_algo == eSIR_FT_AUTH) &&
			    (adapter->device_mode == QDF_SAP_MODE ||
			     adapter->device_mode == QDF_P2P_GO_MODE)) {
				ap_ctx = WLAN_HDD_GET_AP_CTX_PTR(adapter->deflink);
				ap_ctx->during_auth_offload = false;
			}
		}

		qdf_mtrace(QDF_MODULE_ID_HDD, QDF_MODULE_ID_SME,
			   TRACE_CODE_HDD_SEND_MGMT_TX,
			   adapter->deflink->vdev_id, 0);

		qdf_status = sme_send_mgmt_tx(hdd_ctx->mac_handle,
					      adapter->deflink->vdev_id,
					      buf, len);

		if (QDF_IS_STATUS_SUCCESS(qdf_status))
			return qdf_status_to_os_return(qdf_status);
		else
			return -EINVAL;
	}
	/* Only when SAP working on Fast BSS transition mode. Driver offload
	 * (re)assoc request to hostapd. Here driver receive (re)assoc response
	 * frame from hostapd.
	 */
	if ((adapter->device_mode == QDF_SAP_MODE ||
	     adapter->device_mode == QDF_P2P_GO_MODE) &&
	    (type == SIR_MAC_MGMT_FRAME) &&
	    (sub_type == SIR_MAC_MGMT_ASSOC_RSP ||
	     sub_type == SIR_MAC_MGMT_REASSOC_RSP)) {
		assoc_resp = &((struct ieee80211_mgmt *)buf)->u.assoc_resp.variable[0];
		assoc_resp_len = len - WLAN_ASSOC_RSP_IES_OFFSET
			   - sizeof(struct wlan_frame_hdr);
		if (!wlan_get_ie_ptr_from_eid(DOT11F_EID_FTINFO,
					      assoc_resp, assoc_resp_len)) {
			hdd_debug("No FT info in Assoc rsp, send it directly");
			goto off_chan_tx;
		}
		ft_info = hdd_filter_ft_info(assoc_resp, len, &ft_info_len);
		if (!ft_info || !ft_info_len)
			return -EINVAL;
		hdd_debug("get ft_info_len from Assoc rsp :%d", ft_info_len);
		ap_ctx = WLAN_HDD_GET_AP_CTX_PTR(adapter->deflink);
		qdf_status = wlansap_update_ft_info(ap_ctx->sap_context,
						    ((struct ieee80211_mgmt *)buf)->da,
						    ft_info, ft_info_len, 0);
		qdf_mem_free(ft_info);

		if (QDF_IS_STATUS_SUCCESS(qdf_status))
			return qdf_status_to_os_return(qdf_status);
		else
			return -EINVAL;
	}

off_chan_tx:
	vdev = hdd_objmgr_get_vdev_by_user(adapter->deflink, WLAN_OSIF_P2P_ID);
	if (!vdev) {
		hdd_err("vdev is NULL");
		return -EINVAL;
	}

	qdf_mtrace(QDF_MODULE_ID_HDD, QDF_MODULE_ID_OS_IF,
		   TRACE_CODE_HDD_SEND_MGMT_TX,
		   wlan_vdev_get_id(vdev), 0);

	status = wlan_cfg80211_mgmt_tx(vdev, chan, offchan, wait, buf,
				       len, no_cck, dont_wait_for_ack, cookie);
	hdd_objmgr_put_vdev_by_user(vdev, WLAN_OSIF_P2P_ID);
	hdd_debug("device_mode:%d type:%d sub_type:%d chan:%d wait:%d offchan:%d do_not_wait_ack:%d mgmt tx, status:%d, cookie:0x%llx",
		  adapter->device_mode, type, sub_type,
		  chan ? chan->center_freq : 0, wait, offchan,
		  dont_wait_for_ack, status, *cookie);

	return 0;
}

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3, 14, 0))
int wlan_hdd_mgmt_tx(struct wiphy *wiphy, struct wireless_dev *wdev,
		     struct cfg80211_mgmt_tx_params *params, u64 *cookie)
#else
int wlan_hdd_mgmt_tx(struct wiphy *wiphy, struct wireless_dev *wdev,
		     struct ieee80211_channel *chan, bool offchan,
		     unsigned int wait,
		     const u8 *buf, size_t len, bool no_cck,
		     bool dont_wait_for_ack, u64 *cookie)
#endif /* LINUX_VERSION_CODE */
{
	int errno;
	struct osif_vdev_sync *vdev_sync;

	errno = osif_vdev_sync_op_start(wdev->netdev, &vdev_sync);
	if (errno)
		return errno;

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3, 14, 0))
	errno = __wlan_hdd_mgmt_tx(wiphy, wdev, params->chan, params->offchan,
				   params->wait, params->buf, params->len,
				   params->no_cck, params->dont_wait_for_ack,
				   cookie);
#else
	errno = __wlan_hdd_mgmt_tx(wiphy, wdev, chan, offchan,
				   wait, buf, len, no_cck,
				   dont_wait_for_ack, cookie);
#endif /* LINUX_VERSION_CODE */

	osif_vdev_sync_op_stop(vdev_sync);

	return errno;
}

static int __wlan_hdd_cfg80211_mgmt_tx_cancel_wait(struct wiphy *wiphy,
						   struct wireless_dev *wdev,
						   u64 cookie)
{
	QDF_STATUS status;
	struct net_device *dev = wdev->netdev;
	struct hdd_adapter *adapter = WLAN_HDD_GET_PRIV_PTR(dev);
	struct wlan_objmgr_vdev *vdev;

	hdd_enter();

	if (QDF_GLOBAL_FTM_MODE == hdd_get_conparam()) {
		hdd_err("Command not allowed in FTM mode");
		return -EINVAL;
	}

	if (wlan_hdd_validate_vdev_id(adapter->deflink->vdev_id))
		return -EINVAL;

	vdev = hdd_objmgr_get_vdev_by_user(adapter->deflink, WLAN_OSIF_P2P_ID);
	if (!vdev) {
		hdd_err("vdev is NULL");
		return -EINVAL;
	}

	status = wlan_cfg80211_mgmt_tx_cancel(vdev, cookie);
	hdd_objmgr_put_vdev_by_user(vdev, WLAN_OSIF_P2P_ID);

	hdd_debug("cancel mgmt tx, status:%d", status);

	return 0;
}

int wlan_hdd_cfg80211_mgmt_tx_cancel_wait(struct wiphy *wiphy,
					  struct wireless_dev *wdev, u64 cookie)
{
	int errno;
	struct osif_vdev_sync *vdev_sync;

	errno = osif_vdev_sync_op_start(wdev->netdev, &vdev_sync);
	if (errno)
		return errno;

	errno = __wlan_hdd_cfg80211_mgmt_tx_cancel_wait(wiphy, wdev, cookie);

	osif_vdev_sync_op_stop(vdev_sync);

	return errno;
}

/**
 * hdd_set_p2p_noa() - Handle P2P_SET_NOA command
 * @dev: Pointer to net device structure
 * @command: Pointer to command
 *
 * This function is called from hdd_hostapd_ioctl function when Driver
 * get P2P_SET_NOA command from wpa_supplicant using private ioctl
 *
 * This function will construct the NoA Struct According to P2P Power
 * save Option and Pass it to SME layer
 *
 * Return: 0 on success, negative errno if error
 */

int hdd_set_p2p_noa(struct net_device *dev, uint8_t *command)
{
	struct hdd_adapter *adapter = WLAN_HDD_GET_PRIV_PTR(dev);
	struct p2p_ps_config noa = {0};
	int count, duration, interval, start = 0;
	char *param;
	int ret;

	param = strnchr(command, strlen(command), ' ');
	if (!param) {
		hdd_err("strnchr failed to find delimiter");
		return -EINVAL;
	}
	param++;
	ret = sscanf(param, "%d %d %d %d", &count, &start, &duration,
		     &interval);
	if (ret < 3) {
		hdd_err("P2P_SET GO noa: fail to read params, ret=%d",
			ret);
		return -EINVAL;
	}

	if (ret == 3)
		interval = 100;

	if (start < 0 || count < 0 || interval < 0 || duration < 0 ||
	    start > MAX_MUS_VAL || interval > MAX_MUS_VAL ||
	    duration > MAX_MUS_VAL) {
		hdd_err("Invalid NOA parameters");
		return -EINVAL;
	}
	hdd_debug("P2P_SET GO noa: count=%d interval=%d duration=%d start=%d",
		  count, interval, duration, start);
	duration = MS_TO_TU_MUS(duration);
	interval = MS_TO_TU_MUS(interval);
	/* PS Selection
	 * Periodic noa (2)
	 * Single NOA   (4)
	 */
	noa.opp_ps = 0;
	noa.ct_window = 0;
	if (count == 1) {
		if (duration > interval)
			duration = interval;
		noa.duration = 0;
		noa.single_noa_duration = duration;
		noa.ps_selection = P2P_POWER_SAVE_TYPE_SINGLE_NOA;
	} else {
		if (count && (duration >= interval)) {
			hdd_err("Duration should be less than interval");
			return -EINVAL;
		}
		noa.duration = duration;
		noa.single_noa_duration = 0;
		noa.ps_selection = P2P_POWER_SAVE_TYPE_PERIODIC_NOA;
	}

	noa.start = start;
	noa.interval = interval;
	noa.count = count;
	noa.vdev_id = adapter->deflink->vdev_id;

	hdd_debug("P2P_PS_ATTR:opp ps %d ct window %d count %d interval %d "
		  "duration %d start %d single noa duration %d "
		  "ps selection %x", noa.opp_ps, noa.ct_window, noa.count,
		  noa.interval, noa.duration, noa.start,
		  noa.single_noa_duration, noa.ps_selection);

	return wlan_hdd_set_power_save(adapter, &noa);
}

/**
 * hdd_set_p2p_opps() - Handle P2P_SET_PS command
 * @dev: Pointer to net device structure
 * @command: Pointer to command
 *
 * This function is called from hdd_hostapd_ioctl function when Driver
 * get P2P_SET_PS command from wpa_supplicant using private ioctl.
 *
 * This function will construct the NoA Struct According to P2P Power
 * save Option and Pass it to SME layer
 *
 * Return: 0 on success, negative errno if error
 */

int hdd_set_p2p_opps(struct net_device *dev, uint8_t *command)
{
	struct hdd_adapter *adapter = WLAN_HDD_GET_PRIV_PTR(dev);
	struct p2p_ps_config noa = {0};
	char *param;
	int legacy_ps, opp_ps, ctwindow;
	int ret;

	param = strnchr(command, strlen(command), ' ');
	if (!param) {
		hdd_err("strnchr failed to find delimiter");
		return -EINVAL;
	}
	param++;
	ret = sscanf(param, "%d %d %d", &legacy_ps, &opp_ps, &ctwindow);
	if (ret != 3) {
		hdd_err("P2P_SET GO PS: fail to read params, ret=%d", ret);
		return -EINVAL;
	}

	if ((opp_ps != -1) && (opp_ps != 0) && (opp_ps != 1)) {
		hdd_err("Invalid opp_ps value:%d", opp_ps);
		return -EINVAL;
	}

	/* P2P spec: 3.3.2 Power Management and discovery:
	 *     CTWindow should be at least 10 TU.
	 * P2P spec: Table 27 - CTWindow and OppPS Parameters field format:
	 *     CTWindow and OppPS Parameters together is 8 bits.
	 *     CTWindow uses 7 bits (0-6, Bit 7 is for OppPS)
	 * 0 indicates that there shall be no CTWindow
	 */
	if ((ctwindow != -1) && (ctwindow != 0) &&
	    (!((ctwindow >= 10) && (ctwindow <= 127)))) {
		hdd_err("Invalid CT window value:%d", ctwindow);
		return -EINVAL;
	}

	hdd_debug("P2P_SET GO PS: legacy_ps=%d opp_ps=%d ctwindow=%d",
		  legacy_ps, opp_ps, ctwindow);

	/* PS Selection
	 * Opportunistic Power Save (1)
	 */

	/* From wpa_cli user need to use separate command to set ct_window
	 * and Opps when user want to set ct_window during that time other
	 * parameters values are coming from wpa_supplicant as -1.
	 * Example : User want to set ct_window with 30 then wpa_cli command :
	 * P2P_SET ctwindow 30
	 * Command Received at hdd_hostapd_ioctl is as below:
	 * P2P_SET_PS -1 -1 30 (legacy_ps = -1, opp_ps = -1, ctwindow = 30)
	 *
	 * e.g., 1: P2P_SET_PS 1 1 30
	 * Driver sets the Opps and CTwindow as 30 and send it to FW.
	 * e.g., 2: P2P_SET_PS 1 -1 15
	 * Driver caches the CTwindow value but not send the command to FW.
	 * e.g., 3: P2P_SET_PS 1 1 -1
	 * Driver sends the command to FW with Opps enabled and CT window as
	 * 15 (last cached CTWindow value).
	 * (or) : P2P_SET_PS 1 1 20
	 * Driver sends the command to FW with opps enabled and CT window
	 * as 20.
	 *
	 * legacy_ps param remains unused until required in the future.
	 */
	if (ctwindow != -1)
		adapter->ctw = ctwindow;

	/* Send command to FW when OppPS is either enabled(1)/disabled(0) */
	if (opp_ps != -1) {
		adapter->ops = opp_ps;
		noa.opp_ps = adapter->ops;
		noa.ct_window = adapter->ctw;
		noa.duration = 0;
		noa.single_noa_duration = 0;
		noa.interval = 0;
		noa.count = 0;
		noa.ps_selection = P2P_POWER_SAVE_TYPE_OPPORTUNISTIC;
		noa.vdev_id = adapter->deflink->vdev_id;

		hdd_debug("P2P_PS_ATTR: opp ps %d ct window %d duration %d interval %d count %d single noa duration %d ps selection %x",
			noa.opp_ps, noa.ct_window,
			noa.duration, noa.interval, noa.count,
			noa.single_noa_duration,
			noa.ps_selection);

		wlan_hdd_set_power_save(adapter, &noa);
	}

	return 0;
}

int hdd_set_p2p_ps(struct net_device *dev, void *msgData)
{
	struct hdd_adapter *adapter = WLAN_HDD_GET_PRIV_PTR(dev);
	struct p2p_ps_config noa = {0};
	struct p2p_app_set_ps *pappnoa = (struct p2p_app_set_ps *) msgData;

	noa.opp_ps = pappnoa->opp_ps;
	noa.ct_window = pappnoa->ct_window;
	noa.duration = pappnoa->duration;
	noa.interval = pappnoa->interval;
	noa.count = pappnoa->count;
	noa.single_noa_duration = pappnoa->single_noa_duration;
	noa.ps_selection = pappnoa->ps_selection;
	noa.vdev_id = adapter->deflink->vdev_id;

	return wlan_hdd_set_power_save(adapter, &noa);
}

/**
 * __wlan_hdd_add_virtual_intf() - Add virtual interface
 * @wiphy: wiphy pointer
 * @name: User-visible name of the interface
 * @name_assign_type: the name of assign type of the netdev
 * @type: (virtual) interface types
 * @flags: monitor configuration flags
 * @params: virtual interface parameters (not used)
 *
 * Return: the pointer of wireless dev, otherwise ERR_PTR.
 */
static
struct wireless_dev *__wlan_hdd_add_virtual_intf(struct wiphy *wiphy,
						 const char *name,
						 unsigned char name_assign_type,
						 enum nl80211_iftype type,
						 u32 *flags,
						 struct vif_params *params)
{
	struct hdd_context *hdd_ctx = wiphy_priv(wiphy);
	struct hdd_adapter *adapter = NULL;
	bool p2p_dev_addr_admin = false;
	enum QDF_OPMODE mode;
	QDF_STATUS status;
	struct wlan_objmgr_vdev *vdev;
	int ret;
	struct hdd_adapter_create_param create_params = {0};
	uint8_t *device_address = NULL;

	hdd_enter();

	if (hdd_get_conparam() == QDF_GLOBAL_FTM_MODE) {
		hdd_err("Command not allowed in FTM mode");
		return ERR_PTR(-EINVAL);
	}

	if (cds_get_conparam() == QDF_GLOBAL_MONITOR_MODE) {
		hdd_err("Concurrency not allowed with standalone monitor mode");
		return ERR_PTR(-EINVAL);
	}

	ret = wlan_hdd_validate_context(hdd_ctx);
	if (ret)
		return ERR_PTR(ret);

	status = hdd_nl_to_qdf_iface_type(type, &mode);
	if (QDF_IS_STATUS_ERROR(status))
		return ERR_PTR(qdf_status_to_os_return(status));

	if (mode == QDF_MONITOR_MODE &&
	    !(QDF_MONITOR_FLAG_OTHER_BSS & *flags) &&
	    !os_if_lpc_mon_intf_creation_allowed(hdd_ctx->psoc))
		return ERR_PTR(-EOPNOTSUPP);

	wlan_hdd_lpc_handle_concurrency(hdd_ctx, true);

	if (policy_mgr_is_sta_mon_concurrency(hdd_ctx->psoc) &&
	    !hdd_lpc_is_work_scheduled(hdd_ctx))
		return ERR_PTR(-EINVAL);

	if (wlan_hdd_is_mon_concurrency())
		return ERR_PTR(-EINVAL);

	qdf_mtrace(QDF_MODULE_ID_HDD, QDF_MODULE_ID_HDD,
		   TRACE_CODE_HDD_ADD_VIRTUAL_INTF,
		   NO_SESSION, type);

	switch (mode) {
	case QDF_SAP_MODE:
	case QDF_P2P_GO_MODE:
	case QDF_P2P_CLIENT_MODE:
	case QDF_STA_MODE:
	case QDF_MONITOR_MODE:
		break;
	default:
		mode = QDF_STA_MODE;
		break;
	}

	create_params.is_add_virtual_iface = 1;

	adapter = hdd_get_adapter(hdd_ctx, QDF_STA_MODE);
	if (adapter && !wlan_hdd_validate_vdev_id(adapter->deflink->vdev_id)) {
		vdev = hdd_objmgr_get_vdev_by_user(adapter->deflink,
						   WLAN_OSIF_P2P_ID);
		if (vdev) {
			if (ucfg_scan_get_vdev_status(vdev) !=
							SCAN_NOT_IN_PROGRESS) {
				wlan_abort_scan(hdd_ctx->pdev, INVAL_PDEV_ID,
						adapter->deflink->vdev_id,
						INVALID_SCAN_ID, false);
			}
			hdd_objmgr_put_vdev_by_user(vdev, WLAN_OSIF_P2P_ID);
		} else {
			hdd_err("vdev is NULL");
		}
	}

	adapter = NULL;
	if (type == NL80211_IFTYPE_MONITOR) {
		/*
		 * if QDF_MONITOR_FLAG_OTHER_BSS bit is set in monitor flags
		 * driver will assume current mode as STA + Monitor Mode.
		 * So if QDF_MONITOR_FLAG_OTHER_BSS bit is set in monitor
		 * interface flag STA+MON concurrency is not supported
		 * reject the request.
		 **/
		if ((ucfg_dp_is_local_pkt_capture_enabled(hdd_ctx->psoc) &&
		     !(QDF_MONITOR_FLAG_OTHER_BSS & *flags)) ||
		    (ucfg_mlme_is_sta_mon_conc_supported(hdd_ctx->psoc) &&
		     (QDF_MONITOR_FLAG_OTHER_BSS & *flags)) ||
		    ucfg_pkt_capture_get_mode(hdd_ctx->psoc) !=
						PACKET_CAPTURE_MODE_DISABLE) {
			ret = wlan_hdd_add_monitor_check(hdd_ctx,
							 &adapter, name, true,
							 name_assign_type);
			if (ret)
				return ERR_PTR(-EINVAL);

			ucfg_dp_set_mon_conf_flags(hdd_ctx->psoc, *flags);

			if (adapter) {
				hdd_exit();
				return adapter->dev->ieee80211_ptr;
			}
		} else {
			hdd_err("Adding monitor interface not supported");
			return ERR_PTR(-EINVAL);
		}
	}

	adapter = NULL;
	cfg_p2p_get_device_addr_admin(hdd_ctx->psoc, &p2p_dev_addr_admin);
	if (p2p_dev_addr_admin &&
	    (mode == QDF_P2P_GO_MODE || mode == QDF_P2P_CLIENT_MODE)) {
		/*
		 * Generate the P2P Interface Address. this address must be
		 * different from the P2P Device Address.
		 */
		struct qdf_mac_addr p2p_device_address =
						hdd_ctx->p2p_device_address;
		p2p_device_address.bytes[4] ^= 0x80;
		adapter = hdd_open_adapter(hdd_ctx, mode, name,
					   p2p_device_address.bytes,
					   name_assign_type, true,
					   &create_params);
	} else {
		if (strnstr(name, "p2p", 3) && mode == QDF_STA_MODE) {
			hdd_debug("change mode to p2p device");
			mode = QDF_P2P_DEVICE_MODE;
		}

		device_address = wlan_hdd_get_intf_addr(hdd_ctx, mode);
		if (!device_address)
			return ERR_PTR(-EINVAL);

		adapter = hdd_open_adapter(hdd_ctx, mode, name,
					   device_address,
					   name_assign_type, true,
					   &create_params);
		if (!adapter)
			wlan_hdd_release_intf_addr(hdd_ctx, device_address);
	}

	if (!adapter) {
		hdd_err("hdd_open_adapter failed with iftype %d", type);
		return ERR_PTR(-ENOSPC);
	}

	adapter->delete_in_progress = false;

	/* ensure physical soc is up */
	ret = hdd_trigger_psoc_idle_restart(hdd_ctx);
	if (ret) {
		hdd_err("Failed to start the wlan_modules");
		goto close_adapter;
	}

	vdev = hdd_objmgr_get_vdev_by_user(adapter->deflink, WLAN_DP_ID);
	if (vdev) {
		ucfg_dp_try_send_rps_ind(vdev);
		hdd_objmgr_put_vdev_by_user(vdev, WLAN_DP_ID);
	}

	hdd_exit();

	return adapter->dev->ieee80211_ptr;

close_adapter:
	if (device_address)
		wlan_hdd_release_intf_addr(hdd_ctx, device_address);
	hdd_close_adapter(hdd_ctx, adapter, true);

	return ERR_PTR(-EINVAL);
}

static struct wireless_dev *
_wlan_hdd_add_virtual_intf(struct wiphy *wiphy,
			   const char *name,
			   unsigned char name_assign_type,
			   enum nl80211_iftype type,
			   u32 *flags,
			   struct vif_params *params)
{
	struct wireless_dev *wdev;
	struct osif_vdev_sync *vdev_sync;
	int errno;

	errno = osif_vdev_sync_create_and_trans(wiphy_dev(wiphy), &vdev_sync);
	if (errno)
		return ERR_PTR(errno);

	wdev = __wlan_hdd_add_virtual_intf(wiphy, name, name_assign_type,
					   type, flags, params);

	if (IS_ERR_OR_NULL(wdev))
		goto destroy_sync;

	osif_vdev_sync_register(wdev->netdev, vdev_sync);
	osif_vdev_sync_trans_stop(vdev_sync);

	return wdev;

destroy_sync:
	osif_vdev_sync_trans_stop(vdev_sync);
	osif_vdev_sync_destroy(vdev_sync);

	return wdev;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 12, 0)
struct wireless_dev *wlan_hdd_add_virtual_intf(struct wiphy *wiphy,
					       const char *name,
					       unsigned char name_assign_type,
					       enum nl80211_iftype type,
					       struct vif_params *params)
{
	return _wlan_hdd_add_virtual_intf(wiphy, name, name_assign_type,
					  type, &params->flags, params);
}
#elif (LINUX_VERSION_CODE >= KERNEL_VERSION(4, 1, 0)) || defined(WITH_BACKPORTS)
struct wireless_dev *wlan_hdd_add_virtual_intf(struct wiphy *wiphy,
					       const char *name,
					       unsigned char name_assign_type,
					       enum nl80211_iftype type,
					       u32 *flags,
					       struct vif_params *params)
{
	return _wlan_hdd_add_virtual_intf(wiphy, name, name_assign_type,
					  type, flags, params);
}
#else
struct wireless_dev *wlan_hdd_add_virtual_intf(struct wiphy *wiphy,
					       const char *name,
					       enum nl80211_iftype type,
					       u32 *flags,
					       struct vif_params *params)
{
	return _wlan_hdd_add_virtual_intf(wiphy, name, name_assign_type,
					  type, flags, params);
}
#endif

#if defined(WLAN_FEATURE_11BE_MLO) && defined(CFG80211_11BE_BASIC) && \
	!defined(WLAN_HDD_MULTI_VDEV_SINGLE_NDEV)
/**
 * hdd_deinit_mlo_interfaces() - De-initialize link adapters
 * @hdd_ctx: Pointer to hdd context
 * @adapter: Pointer to adapter
 * @rtnl_held: rtnl lock
 *
 * Return: None
 */
static void hdd_deinit_mlo_interfaces(struct hdd_context *hdd_ctx,
				      struct hdd_adapter *adapter,
				      bool rtnl_held)
{
	int i;
	struct hdd_mlo_adapter_info *mlo_adapter_info;
	struct hdd_adapter *link_adapter;

	mlo_adapter_info = &adapter->mlo_adapter_info;
	for (i = 0; i < WLAN_MAX_MLD; i++) {
		link_adapter = mlo_adapter_info->link_adapter[i];
		if (!link_adapter)
			continue;
		hdd_deinit_adapter(hdd_ctx, link_adapter, rtnl_held);
	}
}
#else
static inline
void hdd_deinit_mlo_interfaces(struct hdd_context *hdd_ctx,
			       struct hdd_adapter *adapter,
			       bool rtnl_held)
{
}
#endif

void hdd_clean_up_interface(struct hdd_context *hdd_ctx,
			    struct hdd_adapter *adapter)
{
	wlan_hdd_release_intf_addr(hdd_ctx,
				   adapter->mac_addr.bytes);
	hdd_stop_adapter(hdd_ctx, adapter);
	if (hdd_adapter_is_ml_adapter(adapter)) {
		hdd_deinit_mlo_interfaces(hdd_ctx, adapter, true);
		hdd_wlan_unregister_mlo_interfaces(adapter, true);
	}
	hdd_deinit_adapter(hdd_ctx, adapter, true);
	hdd_close_adapter(hdd_ctx, adapter, true);
}

int __wlan_hdd_del_virtual_intf(struct wiphy *wiphy, struct wireless_dev *wdev)
{
	struct net_device *dev = wdev->netdev;
	struct hdd_context *hdd_ctx = (struct hdd_context *) wiphy_priv(wiphy);
	struct hdd_adapter *adapter = WLAN_HDD_GET_PRIV_PTR(dev);
	int errno;

	hdd_enter();

	if (QDF_GLOBAL_FTM_MODE == hdd_get_conparam()) {
		hdd_err("Command not allowed in FTM mode");
		return -EINVAL;
	}

	/*
	 * Clear SOFTAP_INIT_DONE flag to mark SAP unload, so that we do
	 * not restart SAP after SSR as SAP is already stopped from user space.
	 */
	clear_bit(SOFTAP_INIT_DONE, &adapter->deflink->link_flags);

	qdf_mtrace(QDF_MODULE_ID_HDD, QDF_MODULE_ID_HDD,
		   TRACE_CODE_HDD_DEL_VIRTUAL_INTF,
		   adapter->deflink->vdev_id, adapter->device_mode);

	hdd_debug("Device_mode %s(%d)",
		  qdf_opmode_str(adapter->device_mode), adapter->device_mode);

	errno = wlan_hdd_validate_context(hdd_ctx);
	if (errno)
		return errno;

	/* ensure physical soc is up */
	errno = hdd_trigger_psoc_idle_restart(hdd_ctx);
	if (errno)
		return errno;

	if (wlan_hdd_is_session_type_monitor(adapter->device_mode))
		ucfg_dp_set_mon_conf_flags(hdd_ctx->psoc, 0);

	if (adapter->device_mode == QDF_SAP_MODE &&
	    ucfg_pre_cac_is_active(hdd_ctx->psoc)) {
		ucfg_pre_cac_clean_up(hdd_ctx->psoc);
		hdd_clean_up_interface(hdd_ctx, adapter);
	} else if (wlan_hdd_is_session_type_monitor(
					adapter->device_mode) &&
		   ucfg_pkt_capture_get_mode(hdd_ctx->psoc) !=
						PACKET_CAPTURE_MODE_DISABLE) {
		wlan_hdd_del_monitor(hdd_ctx, adapter, TRUE);
	} else {
		hdd_clean_up_interface(hdd_ctx, adapter);
	}

	if (!hdd_is_any_interface_open(hdd_ctx))
		hdd_psoc_idle_timer_start(hdd_ctx);
	hdd_exit();

	return 0;
}

int wlan_hdd_del_virtual_intf(struct wiphy *wiphy, struct wireless_dev *wdev)
{
	int errno;
	struct osif_vdev_sync *vdev_sync;
	struct hdd_adapter *adapter = WLAN_HDD_GET_PRIV_PTR(wdev->netdev);

	adapter->delete_in_progress = true;
	errno = osif_vdev_sync_trans_start_wait(wdev->netdev, &vdev_sync);
	if (errno)
		return errno;

	osif_vdev_sync_unregister(wdev->netdev);
	osif_vdev_sync_wait_for_ops(vdev_sync);

	adapter->is_virtual_iface = true;
	errno = __wlan_hdd_del_virtual_intf(wiphy, wdev);

	osif_vdev_sync_trans_stop(vdev_sync);
	osif_vdev_sync_destroy(vdev_sync);

	return errno;
}

/**
 * hdd_is_qos_action_frame() - check if frame is QOS action frame
 * @pb_frames: frame pointer
 * @frame_len: frame length
 *
 * Return: true if it is QOS action frame else false.
 */
static inline bool
hdd_is_qos_action_frame(uint8_t *pb_frames, uint32_t frame_len)
{
	if (frame_len <= WLAN_HDD_PUBLIC_ACTION_FRAME_OFFSET + 1) {
		hdd_debug("Not a QOS frame len: %d", frame_len);
		return false;
	}

	return ((pb_frames[WLAN_HDD_PUBLIC_ACTION_FRAME_OFFSET] ==
		 WLAN_HDD_QOS_ACTION_FRAME) &&
		(pb_frames[WLAN_HDD_PUBLIC_ACTION_FRAME_OFFSET + 1] ==
		 WLAN_HDD_QOS_MAP_CONFIGURE));
}

#if defined(WLAN_FEATURE_SAE) && defined(CFG80211_EXTERNAL_AUTH_AP_SUPPORT)
/**
 * wlan_hdd_set_rxmgmt_external_auth_flag() - Set the EXTERNAL_AUTH flag
 * @nl80211_flag: flags to be sent to nl80211 from enum nl80211_rxmgmt_flags
 *
 * Set the flag NL80211_RXMGMT_FLAG_EXTERNAL_AUTH if supported.
 */
static void
wlan_hdd_set_rxmgmt_external_auth_flag(enum nl80211_rxmgmt_flags *nl80211_flag)
{
		*nl80211_flag |= NL80211_RXMGMT_FLAG_EXTERNAL_AUTH;
}
#else
static void
wlan_hdd_set_rxmgmt_external_auth_flag(enum nl80211_rxmgmt_flags *nl80211_flag)
{
}
#endif

/**
 * wlan_hdd_cfg80211_convert_rxmgmt_flags() - Convert RXMGMT value
 * @nl80211_flag: Flags to be sent to nl80211 from enum nl80211_rxmgmt_flags
 * @flag: flags set by driver(SME/PE) from enum rxmgmt_flags
 *
 * Convert driver internal RXMGMT flag value to nl80211 defined RXMGMT flag
 * Return: void
 */
static void
wlan_hdd_cfg80211_convert_rxmgmt_flags(enum rxmgmt_flags flag,
				       enum nl80211_rxmgmt_flags *nl80211_flag)
{

	if (flag & RXMGMT_FLAG_EXTERNAL_AUTH) {
		wlan_hdd_set_rxmgmt_external_auth_flag(nl80211_flag);
	}

}

static void
__hdd_indicate_mgmt_frame_to_user(struct hdd_adapter *adapter,
				  uint32_t frm_len, uint8_t *pb_frames,
				  uint8_t frame_type, uint32_t rx_freq,
				  int8_t rx_rssi, enum rxmgmt_flags rx_flags)
{
	uint8_t type = 0;
	uint8_t sub_type = 0;
	struct hdd_context *hdd_ctx;
	uint8_t *dest_addr = NULL;
	uint16_t auth_algo;
	enum nl80211_rxmgmt_flags nl80211_flag = 0;
	bool is_pasn_auth_frame = false;
	struct hdd_adapter *assoc_adapter;
	bool eht_capab;
	struct hdd_ap_ctx *ap_ctx;
	struct action_frm_hdr *action_hdr;
	tpSirMacVendorSpecificPublicActionFrameHdr vendor_specific;

	hdd_debug("Frame Type = %d Frame Length = %d freq = %d",
		  frame_type, frm_len, rx_freq);

	if (!adapter) {
		hdd_err("adapter is NULL");
		return;
	}
	hdd_ctx = WLAN_HDD_GET_CTX(adapter);

	if (!frm_len) {
		hdd_err("Frame Length is Invalid ZERO");
		return;
	}

	if (!pb_frames) {
		hdd_err("pbFrames is NULL");
		return;
	}

	type = WLAN_HDD_GET_TYPE_FRM_FC(pb_frames[0]);
	sub_type = WLAN_HDD_GET_SUBTYPE_FRM_FC(pb_frames[0]);
	if (type == SIR_MAC_MGMT_FRAME &&
	    sub_type == SIR_MAC_MGMT_AUTH &&
	    frm_len > (sizeof(struct wlan_frame_hdr) +
		       WLAN_AUTH_FRAME_MIN_LEN)) {
		auth_algo = *(uint16_t *)(pb_frames +
					  sizeof(struct wlan_frame_hdr));
		if (auth_algo == eSIR_AUTH_TYPE_PASN) {
			is_pasn_auth_frame = true;
		} else if (auth_algo == eSIR_FT_AUTH &&
			   (adapter->device_mode == QDF_SAP_MODE ||
			    adapter->device_mode == QDF_P2P_GO_MODE)) {
			ap_ctx = WLAN_HDD_GET_AP_CTX_PTR(adapter->deflink);
			ap_ctx->during_auth_offload = true;
		}
	}

	if (type == WLAN_FC0_TYPE_MGMT && sub_type == WLAN_FC0_STYPE_ACTION &&
	    frm_len >= (sizeof(struct wlan_frame_hdr) +
			sizeof(*vendor_specific))) {
		action_hdr = (struct action_frm_hdr *)(pb_frames +
						sizeof(struct wlan_frame_hdr));
		vendor_specific =
			(tpSirMacVendorSpecificPublicActionFrameHdr)action_hdr;
		if (is_nan_oui(vendor_specific->Oui)) {
			adapter = hdd_get_adapter(hdd_ctx, QDF_NAN_DISC_MODE);
			if (!adapter) {
				hdd_err("NAN adapter is null");
				return;
			}

			goto check_adapter;
		}
	}

	/* Get adapter from Destination mac address of the frame */
	if (type == SIR_MAC_MGMT_FRAME &&
	    sub_type != SIR_MAC_MGMT_PROBE_REQ && !is_pasn_auth_frame &&
	    !qdf_is_macaddr_broadcast(
	     (struct qdf_mac_addr *)&pb_frames[WLAN_HDD_80211_FRM_DA_OFFSET])) {
		dest_addr = &pb_frames[WLAN_HDD_80211_FRM_DA_OFFSET];
		adapter = hdd_get_adapter_by_macaddr(hdd_ctx, dest_addr);
		if (!adapter)
			adapter = hdd_get_adapter_by_rand_macaddr(hdd_ctx,
								  dest_addr);
		if (!adapter) {
			/*
			 * Under assumption that we don't receive any action
			 * frame with BCST as destination,
			 * we are dropping action frame
			 */
			hdd_err("adapter for action frame is NULL Macaddr = "
				QDF_MAC_ADDR_FMT, QDF_MAC_ADDR_REF(dest_addr));
			hdd_debug("Frame Type = %d Frame Length = %d subType = %d",
				  frame_type, frm_len, sub_type);
			/*
			 * We will receive broadcast management frames
			 * in OCB mode
			 */
			adapter = hdd_get_adapter(hdd_ctx, QDF_OCB_MODE);
			if (!adapter || !qdf_is_macaddr_broadcast(
			    (struct qdf_mac_addr *)dest_addr)) {
				/*
				 * Under assumption that we don't
				 * receive any action frame with BCST
				 * as destination, we are dropping
				 * action frame
				 */
				return;
			}
		}
	}

check_adapter:
	if (!adapter->dev) {
		hdd_err("adapter->dev is NULL");
		return;
	}

	if (WLAN_HDD_ADAPTER_MAGIC != adapter->magic) {
		hdd_err("adapter has invalid magic");
		return;
	}

	/* Channel indicated may be wrong. TODO */
	/* Indicate an action frame. */

	if (hdd_is_qos_action_frame(pb_frames, frm_len))
		sme_update_dsc_pto_up_mapping(hdd_ctx->mac_handle,
					      adapter->dscp_to_up_map,
					      adapter->deflink->vdev_id);

	assoc_adapter = adapter;
	ucfg_psoc_mlme_get_11be_capab(hdd_ctx->psoc, &eht_capab);
	if (hdd_adapter_is_link_adapter(adapter) && eht_capab) {
		hdd_debug("adapter is not ml adapter move to ml adapter");
		assoc_adapter = hdd_adapter_get_mlo_adapter_from_link(adapter);
		if (!assoc_adapter) {
			hdd_err("Assoc adapter is NULL");
			return;
		}
	}

	/* Indicate Frame Over Normal Interface */
	hdd_debug("Indicate Frame over NL80211 sessionid : %d, idx :%d",
		   assoc_adapter->deflink->vdev_id,
		   assoc_adapter->dev->ifindex);

	wlan_hdd_cfg80211_convert_rxmgmt_flags(rx_flags, &nl80211_flag);

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3, 18, 0))
	cfg80211_rx_mgmt(assoc_adapter->dev->ieee80211_ptr,
			 rx_freq, rx_rssi * 100, pb_frames,
			 frm_len, NL80211_RXMGMT_FLAG_ANSWERED | nl80211_flag);
#elif (LINUX_VERSION_CODE >= KERNEL_VERSION(3, 12, 0))
	cfg80211_rx_mgmt(assoc_adapter->dev->ieee80211_ptr,
			 rx_freq, rx_rssi * 100, pb_frames,
			 frm_len, NL80211_RXMGMT_FLAG_ANSWERED,
			 GFP_ATOMIC);
#else
	cfg80211_rx_mgmt(assoc_adapter->dev->ieee80211_ptr, rx_freq,
			 rx_rssi * 100,
			 pb_frames, frm_len, GFP_ATOMIC);
#endif /* LINUX_VERSION_CODE */
}

void hdd_indicate_mgmt_frame_to_user(struct hdd_adapter *adapter,
				     uint32_t frm_len, uint8_t *pb_frames,
				     uint8_t frame_type, uint32_t rx_freq,
				     int8_t rx_rssi, enum rxmgmt_flags rx_flags)
{
	int errno;
	struct osif_vdev_sync *vdev_sync;

	errno = osif_vdev_sync_op_start(adapter->dev, &vdev_sync);
	if (errno)
		return;

	__hdd_indicate_mgmt_frame_to_user(adapter, frm_len, pb_frames,
					  frame_type, rx_freq,
					  rx_rssi, rx_flags);
	osif_vdev_sync_op_stop(vdev_sync);
}

int wlan_hdd_set_power_save(struct hdd_adapter *adapter,
	struct p2p_ps_config *ps_config)
{
	struct wlan_objmgr_psoc *psoc;
	struct hdd_context *hdd_ctx;
	QDF_STATUS status;

	if (!adapter || !ps_config) {
		hdd_err("null param, adapter:%pK, ps_config:%pK",
			adapter, ps_config);
		return -EINVAL;
	}

	hdd_ctx = WLAN_HDD_GET_CTX(adapter);
	psoc = hdd_ctx->psoc;
	if (!psoc) {
		hdd_err("psoc is null");
		return -EINVAL;
	}

	hdd_debug("opp ps:%d, ct window:%d, duration:%d, interval:%d, count:%d start:%d, single noa duration:%d, ps selection:%d, vdev id:%d",
		  ps_config->opp_ps, ps_config->ct_window,
		  ps_config->duration, ps_config->interval,
		  ps_config->count, ps_config->start,
		  ps_config->single_noa_duration,
		  ps_config->ps_selection, ps_config->vdev_id);

	status = ucfg_p2p_set_ps(psoc, ps_config);
	hdd_debug("p2p set power save, status:%d", status);

	/* P2P-GO-NOA and TWT do not go hand in hand */
	if (ps_config->duration) {
		hdd_send_twt_role_disable_cmd(hdd_ctx, TWT_RESPONDER);
	} else {
		hdd_send_twt_requestor_enable_cmd(hdd_ctx);
		hdd_send_twt_responder_enable_cmd(hdd_ctx);
	}

	return qdf_status_to_os_return(status);
}

/**
 * wlan_hdd_update_mcc_p2p_quota() - Function to Update P2P
 * quota to FW
 * @adapter:            Pointer to HDD adapter
 * @is_set:             0-reset, 1-set
 *
 * This function passes down the value of MAS to UMAC
 *
 * Return: none
 *
 */
static void wlan_hdd_update_mcc_p2p_quota(struct hdd_adapter *adapter,
					  bool is_set)
{

	hdd_info("Set/reset P2P quota: %d", is_set);
	if (is_set) {
		if (adapter->device_mode == QDF_STA_MODE)
			wlan_hdd_set_mcc_p2p_quota(adapter,
				100 - HDD_DEFAULT_MCC_P2P_QUOTA
			);
		else if (adapter->device_mode == QDF_P2P_GO_MODE)
			wlan_hdd_go_set_mcc_p2p_quota(adapter,
				HDD_DEFAULT_MCC_P2P_QUOTA);
		else
			wlan_hdd_set_mcc_p2p_quota(adapter,
				HDD_DEFAULT_MCC_P2P_QUOTA);
	} else {
		if (adapter->device_mode == QDF_P2P_GO_MODE)
			wlan_hdd_go_set_mcc_p2p_quota(adapter,
				HDD_RESET_MCC_P2P_QUOTA);
		else
			wlan_hdd_set_mcc_p2p_quota(adapter,
				HDD_RESET_MCC_P2P_QUOTA);
	}
}

int32_t wlan_hdd_set_mas(struct hdd_adapter *adapter, uint8_t mas_value)
{
	struct hdd_context *hdd_ctx;
	bool enable_mcc_adaptive_sch = false;

	if (!adapter) {
		hdd_err("Adapter is NULL");
		return -EINVAL;
	}

	hdd_ctx = WLAN_HDD_GET_CTX(adapter);
	if (!hdd_ctx) {
		hdd_err("HDD context is null");
		return -EINVAL;
	}

	if (mas_value) {
		hdd_info("Miracast is ON. Disable MAS and configure P2P quota");
		ucfg_policy_mgr_get_mcc_adaptive_sch(hdd_ctx->psoc,
						     &enable_mcc_adaptive_sch);
		if (enable_mcc_adaptive_sch) {
			ucfg_policy_mgr_set_dynamic_mcc_adaptive_sch(
							hdd_ctx->psoc, false);

			if (QDF_STATUS_SUCCESS != sme_set_mas(false)) {
				hdd_err("Failed to disable MAS");
				return -EAGAIN;
			}
		}

		/* Config p2p quota */
		wlan_hdd_update_mcc_p2p_quota(adapter, true);
	} else {
		hdd_info("Miracast is OFF. Enable MAS and reset P2P quota");
		wlan_hdd_update_mcc_p2p_quota(adapter, false);

		ucfg_policy_mgr_get_mcc_adaptive_sch(hdd_ctx->psoc,
						     &enable_mcc_adaptive_sch);
		if (enable_mcc_adaptive_sch) {
			ucfg_policy_mgr_set_dynamic_mcc_adaptive_sch(
							hdd_ctx->psoc, true);

			if (QDF_STATUS_SUCCESS != sme_set_mas(true)) {
				hdd_err("Failed to enable MAS");
				return -EAGAIN;
			}
		}
	}

	return 0;
}

/**
 * set_first_connection_operating_channel() - Function to set
 * first connection oerating channel
 * @hdd_ctx: Hdd context
 * @set_value: First connection operating channel
 * @dev_mode: Device operating mode
 *
 * This function is used to set the first adapter operating
 * channel
 *
 * Return: operating channel updated in set value
 *
 */
static uint32_t set_first_connection_operating_channel(
		struct hdd_context *hdd_ctx, uint32_t set_value,
		enum QDF_OPMODE dev_mode)
{
	uint8_t operating_channel;
	uint32_t oper_chan_freq;

	oper_chan_freq = hdd_get_operating_chan_freq(hdd_ctx, dev_mode);
	if (!oper_chan_freq) {
		hdd_err(" First adapter operating channel is invalid");
		return set_value;
	}
	operating_channel = wlan_reg_freq_to_chan(hdd_ctx->pdev,
						  oper_chan_freq);

	hdd_info("First connection channel No.:%d and quota:%dms",
		 operating_channel, set_value);
	/* Move the time quota for first channel to bits 15-8 */
	set_value = set_value << 8;

	/*
	 * Store the channel number of 1st channel at bits 7-0
	 * of the bit vector
	 */
	return set_value | operating_channel;
}

/**
 * set_second_connection_operating_channel() - Function to set
 * second connection oerating channel
 * @hdd_ctx: Hdd context
 * @set_value: Second connection operating channel
 * @vdev_id: vdev id
 *
 * This function is used to set the first adapter operating
 * channel
 *
 * Return: operating channel updated in set value
 *
 */
static uint32_t set_second_connection_operating_channel(
		struct hdd_context *hdd_ctx, uint32_t set_value,
		uint8_t vdev_id)
{
	uint8_t operating_channel;

	operating_channel = wlan_reg_freq_to_chan(hdd_ctx->pdev,
						  policy_mgr_get_mcc_operating_channel(
						  hdd_ctx->psoc, vdev_id));

	if (!operating_channel) {
		hdd_err("Second adapter operating channel is invalid");
		return set_value;
	}

	hdd_info("Second connection channel No.:%d and quota:%dms",
			operating_channel, set_value);
	/*
	 * Now move the time quota and channel number of the
	 * 1st adapter to bits 23-16 and bits 15-8 of the bit
	 * vector, respectively.
	 */
	set_value = set_value << 8;

	/*
	 * Set the channel number for 2nd MCC vdev at bits
	 * 7-0 of set_value
	 */
	return set_value | operating_channel;
}

/**
 * wlan_hdd_set_mcc_p2p_quota() - Function to set quota for P2P
 * @adapter: HDD adapter
 * @set_value: Quota value for the interface
 *
 * This function is used to set the quota for P2P cases
 *
 * Return: Configuration message posting status, SUCCESS or Fail
 *
 */
int wlan_hdd_set_mcc_p2p_quota(struct hdd_adapter *adapter,
			       uint32_t set_value)
{
	int32_t ret = 0;
	uint32_t concurrent_state;
	struct hdd_context *hdd_ctx;
	uint32_t sta_cli_bit_mask = QDF_STA_MASK | QDF_P2P_CLIENT_MASK;
	uint32_t sta_go_bit_mask = QDF_STA_MASK | QDF_P2P_GO_MASK;

	if (!adapter) {
		hdd_err("Invalid adapter");
		return -EFAULT;
	}
	hdd_ctx = WLAN_HDD_GET_CTX(adapter);
	if (!hdd_ctx) {
		hdd_err("HDD context is null");
		return -EINVAL;
	}

	concurrent_state = policy_mgr_get_concurrency_mode(
		hdd_ctx->psoc);
	/*
	 * Check if concurrency mode is active.
	 * Need to modify this code to support MCC modes other than STA/P2P
	 */
	if (((concurrent_state & sta_cli_bit_mask) == sta_cli_bit_mask) ||
	    ((concurrent_state & sta_go_bit_mask) == sta_go_bit_mask)) {
		hdd_info("STA & P2P are both enabled");

		/*
		 * The channel numbers for both adapters and the time
		 * quota for the 1st adapter, i.e., one specified in cmd
		 * are formatted as a bit vector then passed on to WMA
		 * +***********************************************************+
		 * |bit 31-24  | bit 23-16  |   bits 15-8   |   bits 7-0       |
		 * |  Unused   | Quota for  | chan. # for   |   chan. # for    |
		 * |           | 1st chan.  | 1st chan.     |   2nd chan.      |
		 * +***********************************************************+
		 */

		set_value = set_first_connection_operating_channel(
			hdd_ctx, set_value, adapter->device_mode);

		set_value = set_second_connection_operating_channel(
			hdd_ctx, set_value, adapter->deflink->vdev_id);

		ret = wlan_hdd_send_mcc_vdev_quota(adapter, set_value);
	} else {
		hdd_info("MCC is not active. Exit w/o setting latency");
	}

	return ret;
}

int wlan_hdd_go_set_mcc_p2p_quota(struct hdd_adapter *hostapd_adapter,
				  uint32_t set_value)
{
	return wlan_hdd_set_mcc_p2p_quota(hostapd_adapter, set_value);
}

void wlan_hdd_set_mcc_latency(struct hdd_adapter *adapter, int set_value)
{
	uint32_t concurrent_state;
	struct hdd_context *hdd_ctx;
	uint32_t sta_cli_bit_mask = QDF_STA_MASK | QDF_P2P_CLIENT_MASK;
	uint32_t sta_go_bit_mask = QDF_STA_MASK | QDF_P2P_GO_MASK;

	if (!adapter) {
		hdd_err("Invalid adapter");
		return;
	}

	hdd_ctx = WLAN_HDD_GET_CTX(adapter);
	if (!hdd_ctx) {
		hdd_err("HDD context is null");
		return;
	}

	concurrent_state = policy_mgr_get_concurrency_mode(
		hdd_ctx->psoc);
	/**
	 * Check if concurrency mode is active.
	 * Need to modify this code to support MCC modes other than STA/P2P
	 */
	if (((concurrent_state & sta_cli_bit_mask) == sta_cli_bit_mask) ||
	    ((concurrent_state & sta_go_bit_mask) == sta_go_bit_mask)) {
		hdd_info("STA & P2P are both enabled");
		/*
		 * The channel number and latency are formatted in
		 * a bit vector then passed on to WMA layer.
		 * +**********************************************+
		 * |bits 31-16 |      bits 15-8    |  bits 7-0    |
		 * |  Unused   | latency - Chan. 1 |  channel no. |
		 * +**********************************************+
		 */
		set_value = set_first_connection_operating_channel(
			hdd_ctx, set_value, adapter->device_mode);

		wlan_hdd_send_mcc_latency(adapter, set_value);
	} else {
		hdd_info("MCC is not active. Exit w/o setting latency");
	}
}
