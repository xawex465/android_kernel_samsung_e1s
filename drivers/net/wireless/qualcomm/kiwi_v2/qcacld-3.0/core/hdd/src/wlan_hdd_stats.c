/*
 * Copyright (c) 2012-2021 The Linux Foundation. All rights reserved.
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
 * DOC: wlan_hdd_stats.c
 *
 * WLAN Host Device Driver statistics related implementation
 *
 */

#include "wlan_hdd_stats.h"
#include "sme_api.h"
#include "cds_sched.h"
#include "osif_sync.h"
#include "wlan_hdd_trace.h"
#include "wlan_hdd_lpass.h"
#include "hif.h"
#include <qca_vendor.h>
#include "wma_api.h"
#include "wlan_hdd_hostapd.h"
#include "wlan_osif_request_manager.h"
#include "wlan_hdd_debugfs_llstat.h"
#include "wlan_hdd_debugfs_mibstat.h"
#include "wlan_reg_services_api.h"
#include <wlan_cfg80211_mc_cp_stats.h>
#include "wlan_cp_stats_mc_ucfg_api.h"
#include "wlan_mlme_ucfg_api.h"
#include "wlan_mlme_ucfg_api.h"
#include "wlan_hdd_sta_info.h"
#include "cdp_txrx_misc.h"
#include "cdp_txrx_host_stats.h"
#include "wlan_hdd_object_manager.h"
#include "wlan_hdd_eht.h"
#include "wlan_dp_ucfg_api.h"
#include "wlan_cm_roam_ucfg_api.h"

#if (LINUX_VERSION_CODE < KERNEL_VERSION(4, 0, 0)) && !defined(WITH_BACKPORTS)
#define HDD_INFO_SIGNAL                 STATION_INFO_SIGNAL
#define HDD_INFO_SIGNAL_AVG             STATION_INFO_SIGNAL_AVG
#define HDD_INFO_TX_PACKETS             STATION_INFO_TX_PACKETS
#define HDD_INFO_TX_RETRIES             STATION_INFO_TX_RETRIES
#define HDD_INFO_TX_FAILED              STATION_INFO_TX_FAILED
#define HDD_INFO_TX_BITRATE             STATION_INFO_TX_BITRATE
#define HDD_INFO_RX_BITRATE             STATION_INFO_RX_BITRATE
#define HDD_INFO_TX_BYTES               STATION_INFO_TX_BYTES
#define HDD_INFO_CHAIN_SIGNAL_AVG       STATION_INFO_CHAIN_SIGNAL_AVG
#define HDD_INFO_EXPECTED_THROUGHPUT    0
#define HDD_INFO_RX_BYTES               STATION_INFO_RX_BYTES
#define HDD_INFO_RX_PACKETS             STATION_INFO_RX_PACKETS
#define HDD_INFO_TX_BYTES64             0
#define HDD_INFO_RX_BYTES64             0
#define HDD_INFO_INACTIVE_TIME          0
#define HDD_INFO_CONNECTED_TIME         0
#define HDD_INFO_STA_FLAGS              0
#define HDD_INFO_RX_MPDUS               0
#define HDD_INFO_FCS_ERROR_COUNT        0
#else
#define HDD_INFO_SIGNAL                 BIT(NL80211_STA_INFO_SIGNAL)
#define HDD_INFO_SIGNAL_AVG             BIT(NL80211_STA_INFO_SIGNAL_AVG)
#define HDD_INFO_TX_PACKETS             BIT(NL80211_STA_INFO_TX_PACKETS)
#define HDD_INFO_TX_RETRIES             BIT(NL80211_STA_INFO_TX_RETRIES)
#define HDD_INFO_TX_FAILED              BIT(NL80211_STA_INFO_TX_FAILED)
#define HDD_INFO_TX_BITRATE             BIT(NL80211_STA_INFO_TX_BITRATE)
#define HDD_INFO_RX_BITRATE             BIT(NL80211_STA_INFO_RX_BITRATE)
#define HDD_INFO_TX_BYTES               BIT(NL80211_STA_INFO_TX_BYTES)
#define HDD_INFO_CHAIN_SIGNAL_AVG       BIT(NL80211_STA_INFO_CHAIN_SIGNAL_AVG)
#define HDD_INFO_EXPECTED_THROUGHPUT  BIT(NL80211_STA_INFO_EXPECTED_THROUGHPUT)
#define HDD_INFO_RX_BYTES               BIT(NL80211_STA_INFO_RX_BYTES)
#define HDD_INFO_RX_PACKETS             BIT(NL80211_STA_INFO_RX_PACKETS)
#define HDD_INFO_TX_BYTES64             BIT(NL80211_STA_INFO_TX_BYTES64)
#define HDD_INFO_RX_BYTES64             BIT(NL80211_STA_INFO_RX_BYTES64)
#define HDD_INFO_INACTIVE_TIME          BIT(NL80211_STA_INFO_INACTIVE_TIME)
#define HDD_INFO_CONNECTED_TIME         BIT(NL80211_STA_INFO_CONNECTED_TIME)
#define HDD_INFO_STA_FLAGS              BIT(NL80211_STA_INFO_STA_FLAGS)
#define HDD_INFO_RX_MPDUS             BIT_ULL(NL80211_STA_INFO_RX_MPDUS)
#define HDD_INFO_FCS_ERROR_COUNT      BIT_ULL(NL80211_STA_INFO_FCS_ERROR_COUNT)
#endif /* kernel version less than 4.0.0 && no_backport */

#define HDD_LINK_STATS_MAX		5
#define HDD_MAX_ALLOWED_LL_STATS_FAILURE	5

#define INVALID_PREAMBLE 0xFF

#define MAX_RSSI_MCS_INDEX 14

/* 11B, 11G Rate table include Basic rate and Extended rate
 * The IDX field is the rate index
 * The HI field is the rate when RSSI is strong or being ignored
 *  (in this case we report actual rate)
 * The MID field is the rate when RSSI is moderate
 * (in this case we cap 11b rates at 5.5 and 11g rates at 24)
 * The LO field is the rate when RSSI is low
 *  (in this case we don't report rates, actual current rate used)
 */
static const struct index_data_rate_type supported_data_rate[] = {
	/* IDX     HI  HM  LM LO (RSSI-based index */
	{2,   { 10,  10, 10, 0} },
	{4,   { 20,  20, 10, 0} },
	{11,  { 55,  20, 10, 0} },
	{12,  { 60,  55, 20, 0} },
	{18,  { 90,  55, 20, 0} },
	{22,  {110,  55, 20, 0} },
	{24,  {120,  90, 60, 0} },
	{36,  {180, 120, 60, 0} },
	{44,  {220, 180, 60, 0} },
	{48,  {240, 180, 90, 0} },
	{66,  {330, 180, 90, 0} },
	{72,  {360, 240, 90, 0} },
	{96,  {480, 240, 120, 0} },
	{108, {540, 240, 120, 0} }
};
/* MCS Based rate table HT MCS parameters with Nss = 1 */
static const struct index_data_rate_type supported_mcs_rate_nss1[] = {
/* MCS  L20   L40   S20  S40 */
	{0, {65, 135, 72, 150} },
	{1, {130, 270, 144, 300} },
	{2, {195, 405, 217, 450} },
	{3, {260, 540, 289, 600} },
	{4, {390, 810, 433, 900} },
	{5, {520, 1080, 578, 1200} },
	{6, {585, 1215, 650, 1350} },
	{7, {650, 1350, 722, 1500} }
};

/* HT MCS parameters with Nss = 2 */
static const struct index_data_rate_type supported_mcs_rate_nss2[] = {
/* MCS  L20    L40   S20   S40 */
	{0, {130, 270, 144, 300} },
	{1, {260, 540, 289, 600} },
	{2, {390, 810, 433, 900} },
	{3, {520, 1080, 578, 1200} },
	{4, {780, 1620, 867, 1800} },
	{5, {1040, 2160, 1156, 2400} },
	{6, {1170, 2430, 1300, 2700} },
	{7, {1300, 2700, 1444, 3000} }
};

/* MCS Based VHT rate table MCS parameters with Nss = 1*/
static const struct index_vht_data_rate_type supported_vht_mcs_rate_nss1[] = {
/* MCS  L80    S80     L40   S40    L20   S40*/
	{0, {293, 325}, {135, 150}, {65, 72} },
	{1, {585, 650}, {270, 300}, {130, 144} },
	{2, {878, 975}, {405, 450}, {195, 217} },
	{3, {1170, 1300}, {540, 600}, {260, 289} },
	{4, {1755, 1950}, {810, 900}, {390, 433} },
	{5, {2340, 2600}, {1080, 1200}, {520, 578} },
	{6, {2633, 2925}, {1215, 1350}, {585, 650} },
	{7, {2925, 3250}, {1350, 1500}, {650, 722} },
	{8, {3510, 3900}, {1620, 1800}, {780, 867} },
	{9, {3900, 4333}, {1800, 2000}, {780, 867} },
	{10, {4388, 4875}, {2025, 2250}, {975, 1083} },
	{11, {4875, 5417}, {2250, 2500}, {1083, 1203} }
};

/*MCS parameters with Nss = 2*/
static const struct index_vht_data_rate_type supported_vht_mcs_rate_nss2[] = {
/* MCS  L80    S80     L40   S40    L20   S40*/
	{0, {585, 650}, {270, 300}, {130, 144} },
	{1, {1170, 1300}, {540, 600}, {260, 289} },
	{2, {1755, 1950}, {810, 900}, {390, 433} },
	{3, {2340, 2600}, {1080, 1200}, {520, 578} },
	{4, {3510, 3900}, {1620, 1800}, {780, 867} },
	{5, {4680, 5200}, {2160, 2400}, {1040, 1156} },
	{6, {5265, 5850}, {2430, 2700}, {1170, 1300} },
	{7, {5850, 6500}, {2700, 3000}, {1300, 1444} },
	{8, {7020, 7800}, {3240, 3600}, {1560, 1733} },
	{9, {7800, 8667}, {3600, 4000}, {1730, 1920} },
	{10, {8775, 9750}, {4050, 4500}, {1950, 2167} },
	{11, {9750, 10833}, {4500, 5000}, {2167, 2407} }
};

/*array index points to MCS and array value points respective rssi*/
static int rssi_mcs_tbl[][MAX_RSSI_MCS_INDEX] = {
/*  MCS 0   1    2   3    4    5    6    7    8    9    10   11   12   13*/
	/* 20 */
	{-82, -79, -77, -74, -70, -66, -65, -64, -59, -57, -52, -48, -46, -42},
	/* 40 */
	{-79, -76, -74, -71, -67, -63, -62, -61, -56, -54, -49, -45, -43, -39},
	/* 80 */
	{-76, -73, -71, -68, -64, -60, -59, -58, -53, -51, -46, -42, -46, -36}
};

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(5, 4, 0))
static bool wlan_hdd_is_he_mcs_12_13_supported(uint16_t he_mcs_12_13_map)
{
	if (he_mcs_12_13_map)
		return true;
	else
		return false;
}
#else
static bool wlan_hdd_is_he_mcs_12_13_supported(uint16_t he_mcs_12_13_map)
{
	return false;
}
#endif

static bool get_station_fw_request_needed = true;

/*
 * copy_station_stats_to_adapter() - Copy station stats to adapter
 * @link_info: Pointer to link_info in adapter
 * @stats: Pointer to the station stats event
 *
 * Return: 0 if success, non-zero for failure
 */
static int copy_station_stats_to_adapter(struct wlan_hdd_link_info *link_info,
					 struct stats_event *stats)
{
	int ret = 0;
	struct wlan_mlme_nss_chains *dynamic_cfg;
	uint32_t tx_nss, rx_nss;
	struct wlan_objmgr_vdev *vdev;
	uint16_t he_mcs_12_13_map;
	bool is_he_mcs_12_13_supported;
	struct hdd_stats *hdd_stats;
	struct hdd_adapter *adapter = link_info->adapter;

	vdev = hdd_objmgr_get_vdev_by_user(link_info, WLAN_OSIF_STATS_ID);
	if (!vdev)
		return -EINVAL;

	hdd_stats = &link_info->hdd_stats;
	/* save summary stats to legacy location */
	qdf_mem_copy(hdd_stats->summary_stat.retry_cnt,
		     stats->vdev_summary_stats[0].stats.retry_cnt,
		     sizeof(hdd_stats->summary_stat.retry_cnt));
	qdf_mem_copy(hdd_stats->summary_stat.multiple_retry_cnt,
		     stats->vdev_summary_stats[0].stats.multiple_retry_cnt,
		     sizeof(hdd_stats->summary_stat.multiple_retry_cnt));
	qdf_mem_copy(hdd_stats->summary_stat.tx_frm_cnt,
		     stats->vdev_summary_stats[0].stats.tx_frm_cnt,
		     sizeof(hdd_stats->summary_stat.tx_frm_cnt));
	qdf_mem_copy(hdd_stats->summary_stat.fail_cnt,
		     stats->vdev_summary_stats[0].stats.fail_cnt,
		     sizeof(hdd_stats->summary_stat.fail_cnt));
	hdd_stats->summary_stat.snr = stats->vdev_summary_stats[0].stats.snr;
	hdd_stats->summary_stat.rssi = stats->vdev_summary_stats[0].stats.rssi;
	hdd_stats->summary_stat.rx_frm_cnt =
			stats->vdev_summary_stats[0].stats.rx_frm_cnt;
	hdd_stats->summary_stat.frm_dup_cnt =
			stats->vdev_summary_stats[0].stats.frm_dup_cnt;
	hdd_stats->summary_stat.rts_fail_cnt =
			stats->vdev_summary_stats[0].stats.rts_fail_cnt;
	hdd_stats->summary_stat.ack_fail_cnt =
			stats->vdev_summary_stats[0].stats.ack_fail_cnt;
	hdd_stats->summary_stat.rts_succ_cnt =
			stats->vdev_summary_stats[0].stats.rts_succ_cnt;
	hdd_stats->summary_stat.rx_discard_cnt =
			stats->vdev_summary_stats[0].stats.rx_discard_cnt;
	hdd_stats->summary_stat.rx_error_cnt =
			stats->vdev_summary_stats[0].stats.rx_error_cnt;
	hdd_stats->peer_stats.rx_count = stats->peer_adv_stats->rx_count;
	hdd_stats->peer_stats.rx_bytes = stats->peer_adv_stats->rx_bytes;
	hdd_stats->peer_stats.fcs_count = stats->peer_adv_stats->fcs_count;
	adapter->tx_power.tx_pwr = stats->pdev_stats->max_pwr;
	adapter->tx_power.tx_pwr_cached_timestamp =
			qdf_system_ticks_to_msecs(qdf_system_ticks());
	/* Copy vdev status info sent by FW */
	if (stats->vdev_extd_stats)
		link_info->is_mlo_vdev_active =
			stats->vdev_extd_stats[0].is_mlo_vdev_active;

	dynamic_cfg = mlme_get_dynamic_vdev_config(vdev);
	if (!dynamic_cfg) {
		hdd_err("nss chain dynamic config NULL");
		ret = -EINVAL;
		goto out;
	}

	switch (hdd_conn_get_connected_band(link_info)) {
	case BAND_2G:
		tx_nss = dynamic_cfg->tx_nss[NSS_CHAINS_BAND_2GHZ];
		rx_nss = dynamic_cfg->rx_nss[NSS_CHAINS_BAND_2GHZ];
		break;
	case BAND_5G:
		tx_nss = dynamic_cfg->tx_nss[NSS_CHAINS_BAND_5GHZ];
		rx_nss = dynamic_cfg->rx_nss[NSS_CHAINS_BAND_5GHZ];
		break;
	default:
		tx_nss = wlan_vdev_mlme_get_nss(vdev);
		rx_nss = wlan_vdev_mlme_get_nss(vdev);
	}

	/* Intersection of self and AP's NSS capability */
	if (tx_nss > wlan_vdev_mlme_get_nss(vdev))
		tx_nss = wlan_vdev_mlme_get_nss(vdev);

	if (rx_nss > wlan_vdev_mlme_get_nss(vdev))
		rx_nss = wlan_vdev_mlme_get_nss(vdev);

	/* save class a stats to legacy location */
	hdd_stats->class_a_stat.tx_nss = tx_nss;
	hdd_stats->class_a_stat.rx_nss = rx_nss;
	hdd_stats->class_a_stat.tx_rate = stats->tx_rate;
	hdd_stats->class_a_stat.rx_rate = stats->rx_rate;
	hdd_stats->class_a_stat.tx_rx_rate_flags = stats->tx_rate_flags;

	he_mcs_12_13_map = wlan_vdev_mlme_get_he_mcs_12_13_map(vdev);
	is_he_mcs_12_13_supported =
			wlan_hdd_is_he_mcs_12_13_supported(he_mcs_12_13_map);
	hdd_stats->class_a_stat.tx_mcs_index =
		sme_get_mcs_idx(stats->tx_rate, stats->tx_rate_flags,
				is_he_mcs_12_13_supported,
				&hdd_stats->class_a_stat.tx_nss,
				&hdd_stats->class_a_stat.tx_dcm,
				&hdd_stats->class_a_stat.tx_gi,
				&hdd_stats->class_a_stat.tx_mcs_rate_flags);
	hdd_stats->class_a_stat.rx_mcs_index =
		sme_get_mcs_idx(stats->rx_rate, stats->tx_rate_flags,
				is_he_mcs_12_13_supported,
				&hdd_stats->class_a_stat.rx_nss,
				&hdd_stats->class_a_stat.rx_dcm,
				&hdd_stats->class_a_stat.rx_gi,
				&hdd_stats->class_a_stat.rx_mcs_rate_flags);

	/* save per chain rssi to legacy location */
	qdf_mem_copy(hdd_stats->per_chain_rssi_stats.rssi,
		     stats->vdev_chain_rssi[0].chain_rssi,
		     sizeof(stats->vdev_chain_rssi[0].chain_rssi));
	hdd_stats->bcn_protect_stats = stats->bcn_protect_stats;
out:
	hdd_objmgr_put_vdev_by_user(vdev, WLAN_OSIF_STATS_ID);
	return ret;
}

#ifdef WLAN_FEATURE_BIG_DATA_STATS
/*
 * copy_station_big_data_stats_to_adapter() - Copy big data stats to adapter
 * @link_info: Link info pointer in HDD adapter.
 * @stats: Pointer to the big data stats event
 *
 * Return: 0 if success, non-zero for failure
 */
static void
copy_station_big_data_stats_to_adapter(struct wlan_hdd_link_info *link_info,
				       struct big_data_stats_event *stats)
{
	struct big_data_stats_event *big_data_stats =
						&link_info->big_data_stats;

	big_data_stats->vdev_id = stats->vdev_id;
	big_data_stats->tsf_out_of_sync = stats->tsf_out_of_sync;
	big_data_stats->ani_level = stats->ani_level;
	big_data_stats->last_data_tx_pwr = stats->last_data_tx_pwr;
	big_data_stats->target_power_dsss = stats->target_power_dsss;
	big_data_stats->target_power_ofdm = stats->target_power_ofdm;
	big_data_stats->last_tx_data_rix = stats->last_tx_data_rix;
	big_data_stats->last_tx_data_rate_kbps = stats->last_tx_data_rate_kbps;
}
#endif

#ifdef FEATURE_CLUB_LL_STATS_AND_GET_STATION
static void
hdd_update_station_stats_cached_timestamp(struct hdd_adapter *adapter)
{
	adapter->sta_stats_cached_timestamp =
				qdf_system_ticks_to_msecs(qdf_system_ticks());
}
#else
static void
hdd_update_station_stats_cached_timestamp(struct hdd_adapter *adapter)
{
}
#endif /* FEATURE_CLUB_LL_STATS_AND_GET_STATION */

#ifdef WLAN_FEATURE_WMI_SEND_RECV_QMI
/**
 * wlan_hdd_qmi_get_sync_resume() - Get operation to trigger RTPM
 * sync resume without WoW exit
 *
 * call qmi_get before sending qmi, and do qmi_put after all the
 * qmi response rececived from fw. so this request wlan host to
 * wait for the last qmi response, if it doesn't wait, qmi put
 * which cause MHI enter M3(suspend) before all the qmi response,
 * and MHI will trigger a RTPM resume, this violated design of by
 * sending cmd by qmi without wow resume.
 *
 * Returns: 0 for success, non-zero for failure
 */
int wlan_hdd_qmi_get_sync_resume(void)
{
	struct hdd_context *hdd_ctx = cds_get_context(QDF_MODULE_ID_HDD);
	qdf_device_t qdf_ctx = cds_get_context(QDF_MODULE_ID_QDF_DEVICE);

	if (wlan_hdd_validate_context(hdd_ctx))
		return -EINVAL;

	if (!hdd_ctx->config->is_qmi_stats_enabled) {
		hdd_debug("periodic stats over qmi is disabled");
		return 0;
	}

	if (!qdf_ctx) {
		hdd_err("qdf_ctx is null");
		return -EINVAL;
	}

	return pld_qmi_send_get(qdf_ctx->dev);
}

/**
 * wlan_hdd_qmi_put_suspend() - Put operation to trigger RTPM suspend
 * without WoW entry
 *
 * Returns: 0 for success, non-zero for failure
 */
int wlan_hdd_qmi_put_suspend(void)
{
	struct hdd_context *hdd_ctx = cds_get_context(QDF_MODULE_ID_HDD);
	qdf_device_t qdf_ctx = cds_get_context(QDF_MODULE_ID_QDF_DEVICE);

	if (wlan_hdd_validate_context(hdd_ctx))
		return -EINVAL;

	if (!hdd_ctx->config->is_qmi_stats_enabled) {
		hdd_debug("periodic stats over qmi is disabled");
		return 0;
	}

	if (!qdf_ctx) {
		hdd_err("qdf_ctx is null");
		return -EINVAL;
	}

	return pld_qmi_send_put(qdf_ctx->dev);
}
#else
int wlan_hdd_qmi_get_sync_resume(void)
{
	return 0;
}

int wlan_hdd_qmi_put_suspend(void)
{
	return 0;
}
#endif /* end if of WLAN_FEATURE_WMI_SEND_RECV_QMI */

static struct wlan_hdd_link_info *
hdd_get_link_info_by_bssid(struct hdd_context *hdd_ctx, const uint8_t *bssid)
{
	struct hdd_adapter *adapter, *next_adapter = NULL;
	struct hdd_station_ctx *sta_ctx;
	wlan_net_dev_ref_dbgid dbgid = NET_DEV_HOLD_GET_ADAPTER_BY_BSSID;
	struct wlan_hdd_link_info *link_info;

	if (qdf_is_macaddr_zero((struct qdf_mac_addr *)bssid))
		return NULL;

	hdd_for_each_adapter_dev_held_safe(hdd_ctx, adapter, next_adapter,
					   dbgid) {
		hdd_adapter_for_each_link_info(adapter, link_info) {
			sta_ctx = WLAN_HDD_GET_STATION_CTX_PTR(link_info);
			if (qdf_is_macaddr_equal((struct qdf_mac_addr *)bssid,
						 &sta_ctx->conn_info.bssid)) {
				hdd_adapter_dev_put_debug(adapter, dbgid);
				if (next_adapter)
					hdd_adapter_dev_put_debug(next_adapter,
								  dbgid);
				return link_info;
			}
		}
		hdd_adapter_dev_put_debug(adapter, dbgid);
	}
	return NULL;
}

#if defined(WLAN_FEATURE_11BE_MLO) && defined(CFG80211_11BE_BASIC)
#define WLAN_INVALID_RSSI_VALUE -128
/**
 * wlan_hdd_is_per_link_stats_supported - Check if FW supports per link stats
 * @hdd_ctx: Pointer to hdd context
 *
 * Return: true if FW supports, else False
 */
static bool
wlan_hdd_is_per_link_stats_supported(struct hdd_context *hdd_ctx)
{
	if (hdd_ctx->is_mlo_per_link_stats_supported)
		return true;

	hdd_debug("mlo per link stats is not supported by FW");
	return false;
}

/**
 * wlan_hdd_get_bss_peer_mld_mac() - get bss peer mld mac address
 * @link_info: Link info pointer in HDD adapter
 * @mld_mac: pointer to mld mac address
 *
 * Return: QDF_STATUS
 */
static QDF_STATUS
wlan_hdd_get_bss_peer_mld_mac(struct wlan_hdd_link_info *link_info,
			      struct qdf_mac_addr *mld_mac)
{
	struct wlan_objmgr_vdev *vdev;
	QDF_STATUS status;

	vdev = hdd_objmgr_get_vdev_by_user(link_info,
					   WLAN_OSIF_STATS_ID);
	if (!vdev)
		return QDF_STATUS_E_INVAL;

	if (!wlan_vdev_mlme_is_mlo_vdev(vdev)) {
		hdd_objmgr_put_vdev_by_user(vdev, WLAN_OSIF_STATS_ID);
		return QDF_STATUS_E_INVAL;
	}

	status = wlan_vdev_get_bss_peer_mld_mac(vdev, mld_mac);
	hdd_objmgr_put_vdev_by_user(vdev, WLAN_OSIF_STATS_ID);
	return status;
}

/**
 * wlan_hdd_copy_sinfo_to_link_info() - Copy sinfo to link_info
 * @link_info: Pointer to the hdd link info
 * @sinfo: Pointer to kernel station info struct
 *
 * Return: none
 */
static void
wlan_hdd_copy_sinfo_to_link_info(struct wlan_hdd_link_info *link_info,
				 struct station_info *sinfo)
{
	struct wlan_hdd_station_stats_info *hdd_sinfo;
	struct hdd_station_ctx *sta_ctx;
	uint8_t i, *link_mac;

	if (!wlan_hdd_is_mlo_connection(link_info))
		return;

	sta_ctx = WLAN_HDD_GET_STATION_CTX_PTR(link_info);

	hdd_sinfo = &link_info->hdd_sinfo;

	hdd_sinfo->signal = sinfo->signal;
	hdd_sinfo->signal_avg = sinfo->signal_avg;
	for (i = 0; i < IEEE80211_MAX_CHAINS; i++)
		hdd_sinfo->chain_signal_avg[i] = sinfo->chain_signal_avg[i];

	qdf_mem_copy(&hdd_sinfo->txrate,
		     &sinfo->txrate, sizeof(sinfo->txrate));

	qdf_mem_copy(&hdd_sinfo->rxrate,
		     &sinfo->rxrate, sizeof(sinfo->rxrate));
	hdd_sinfo->rx_bytes = sinfo->rx_bytes;
	hdd_sinfo->tx_bytes = sinfo->tx_bytes;
	hdd_sinfo->rx_packets = sinfo->rx_packets;
	hdd_sinfo->tx_packets = sinfo->tx_packets;
	hdd_sinfo->tx_retries = sinfo->tx_retries;
	hdd_sinfo->tx_failed = sinfo->tx_failed;
	hdd_sinfo->rx_mpdu_count = sinfo->rx_mpdu_count;
	hdd_sinfo->fcs_err_count = sinfo->fcs_err_count;

	link_mac = sta_ctx->conn_info.bssid.bytes;
	hdd_nofl_debug("copied sinfo for " QDF_MAC_ADDR_FMT " into link_info",
		       QDF_MAC_ADDR_REF(link_mac));
}

/**
 * wlan_hdd_copy_hdd_stats_to_sinfo() - Copy hdd station stats info to sinfo
 * @sinfo: Pointer to kernel station info struct
 * @hdd_sinfo: Pointer to the hdd station stats info struct
 *
 * Return: none
 */
static void
wlan_hdd_copy_hdd_stats_to_sinfo(struct station_info *sinfo,
				 struct wlan_hdd_station_stats_info *hdd_sinfo)
{
	uint8_t i;

	sinfo->signal = hdd_sinfo->signal;
	sinfo->signal_avg = hdd_sinfo->signal_avg;
	for (i = 0; i < IEEE80211_MAX_CHAINS; i++)
		sinfo->chain_signal_avg[i] = hdd_sinfo->chain_signal_avg[i];

	if (!hdd_sinfo->signal) {
		sinfo->signal = WLAN_INVALID_RSSI_VALUE;
		sinfo->signal_avg = WLAN_HDD_TGT_NOISE_FLOOR_DBM;
		for (i = 0; i < IEEE80211_MAX_CHAINS; i++)
			sinfo->chain_signal_avg[i] = WLAN_INVALID_RSSI_VALUE;
	}

	qdf_mem_copy(&sinfo->txrate,
		     &hdd_sinfo->txrate, sizeof(sinfo->txrate));

	qdf_mem_copy(&sinfo->rxrate,
		     &hdd_sinfo->rxrate, sizeof(sinfo->rxrate));
	sinfo->rx_bytes = hdd_sinfo->rx_bytes;
	sinfo->tx_bytes = hdd_sinfo->tx_bytes;
	sinfo->rx_packets = hdd_sinfo->rx_packets;
	sinfo->tx_packets = hdd_sinfo->tx_packets;
	sinfo->tx_retries = hdd_sinfo->tx_retries;
	sinfo->tx_failed = hdd_sinfo->tx_failed;
	sinfo->rx_mpdu_count = hdd_sinfo->rx_mpdu_count;
	sinfo->fcs_err_count = hdd_sinfo->fcs_err_count;
}

/**
 * wlan_hdd_update_sinfo() - Function to update station info structure
 * @sinfo: kernel station_info to populate
 * @link_info: Pointer to the hdd link info
 *
 * Return: None
 */
static void wlan_hdd_update_sinfo(struct station_info *sinfo,
				  struct wlan_hdd_link_info *link_info)
{
	uint8_t i;

	if (!link_info) {
		hdd_err("Invalid link_info");
		return;
	}

	wlan_hdd_copy_hdd_stats_to_sinfo(sinfo, &link_info->hdd_sinfo);

	if (link_info->vdev_id == WLAN_INVALID_VDEV_ID) {
		sinfo->signal = WLAN_INVALID_RSSI_VALUE;
		sinfo->signal_avg = WLAN_INVALID_RSSI_VALUE;
		for (i = 0; i < IEEE80211_MAX_CHAINS; i++)
			sinfo->chain_signal_avg[i] = WLAN_INVALID_RSSI_VALUE;
	}

	sinfo->filled |= HDD_INFO_SIGNAL | HDD_INFO_SIGNAL_AVG |
			HDD_INFO_CHAIN_SIGNAL_AVG | HDD_INFO_TX_PACKETS |
			HDD_INFO_TX_RETRIES | HDD_INFO_TX_FAILED |
			HDD_INFO_TX_BITRATE | HDD_INFO_RX_BITRATE |
			HDD_INFO_TX_BYTES | HDD_INFO_RX_BYTES |
			HDD_INFO_RX_PACKETS | HDD_INFO_FCS_ERROR_COUNT |
			HDD_INFO_RX_MPDUS;
}

static void
wlan_hdd_get_mlo_links_count(struct hdd_adapter *adapter, uint32_t *count)
{
	struct wlan_hdd_link_info *link_info;
	struct hdd_station_ctx *sta_ctx;
	u32 num_links = 0;

	hdd_adapter_for_each_link_info(adapter, link_info) {
		sta_ctx = WLAN_HDD_GET_STATION_CTX_PTR(link_info);
		if (sta_ctx->conn_info.ieee_link_id != WLAN_INVALID_LINK_ID)
			num_links++;
	}

	*count = num_links;
}

#else
static inline bool
wlan_hdd_is_per_link_stats_supported(struct hdd_context *hdd_ctx)
{
	return false;
}

static inline QDF_STATUS
wlan_hdd_get_bss_peer_mld_mac(struct wlan_hdd_link_info *link_info,
			      struct qdf_mac_addr *mld_mac)
{
	return QDF_STATUS_E_FAILURE;
}

static inline void
wlan_hdd_copy_sinfo_to_link_info(struct wlan_hdd_link_info *link_info,
				 struct station_info *sinfo)
{
}

static inline void
wlan_hdd_update_sinfo(struct station_info *sinfo,
		      struct wlan_hdd_link_info *link_info)
{
}

static inline void
wlan_hdd_get_mlo_links_count(struct hdd_adapter *adapter, uint32_t *count)
{
}
#endif

#ifdef WLAN_FEATURE_LINK_LAYER_STATS

/**
 * struct hdd_ll_stats - buffered hdd link layer stats
 * @ll_stats_node: pointer to next stats buffered in scheduler thread context
 * @result_param_id: Received link layer stats ID
 * @result: received stats from FW
 * @more_data: if more stats are pending
 * @stats_nradio_npeer: union of counts
 * @stats_nradio_npeer.no_of_radios: no of radios
 * @stats_nradio_npeer.no_of_peers: no of peers
 */
struct hdd_ll_stats {
	qdf_list_node_t ll_stats_node;
	u32 result_param_id;
	void *result;
	u32 more_data;
	union {
		u32 no_of_radios;
		u32 no_of_peers;
	} stats_nradio_npeer;
};

/**
 * struct hdd_ll_stats_priv - hdd link layer stats private
 * @ll_stats_q: head to different link layer stats received in scheduler
 *            thread context
 * @request_id: userspace-assigned link layer stats request id
 * @request_bitmap: userspace-assigned link layer stats request bitmap
 * @ll_stats_lock: Lock to serially access request_bitmap
 * @vdev_id: id of vdev handle
 * @is_mlo_req: is the request for mlo link layer stats
 * @mlo_vdev_id_bitmap: bitmap of all ml vdevs
 */
struct hdd_ll_stats_priv {
	qdf_list_t ll_stats_q;
	uint32_t request_id;
	uint32_t request_bitmap;
	qdf_spinlock_t ll_stats_lock;
	uint8_t vdev_id;
	bool is_mlo_req;
	uint32_t mlo_vdev_id_bitmap;
};

/*
 * Used to allocate the size of 4096 for the link layer stats.
 * The size of 4096 is considered assuming that all data per
 * respective event fit with in the limit.Please take a call
 * on the limit based on the data requirements on link layer
 * statistics.
 */
#define LL_STATS_EVENT_BUF_SIZE 4096

/**
 * put_wifi_rate_stat() - put wifi rate stats
 * @stats: Pointer to stats context
 * @vendor_event: Pointer to vendor event
 *
 * Return: bool
 */
static bool put_wifi_rate_stat(struct wifi_rate_stat *stats,
			       struct sk_buff *vendor_event)
{
	if (nla_put_u8(vendor_event,
		       QCA_WLAN_VENDOR_ATTR_LL_STATS_RATE_PREAMBLE,
		       stats->rate.preamble) ||
	    nla_put_u8(vendor_event,
		       QCA_WLAN_VENDOR_ATTR_LL_STATS_RATE_NSS,
		       stats->rate.nss) ||
	    nla_put_u8(vendor_event,
		       QCA_WLAN_VENDOR_ATTR_LL_STATS_RATE_BW,
		       stats->rate.bw) ||
	    nla_put_u8(vendor_event,
		       QCA_WLAN_VENDOR_ATTR_LL_STATS_RATE_MCS_INDEX,
		       stats->rate.rate_or_mcs_index) ||
	    nla_put_u32(vendor_event,
			QCA_WLAN_VENDOR_ATTR_LL_STATS_RATE_BIT_RATE,
			stats->rate.bitrate) ||
	    nla_put_u32(vendor_event,
			QCA_WLAN_VENDOR_ATTR_LL_STATS_RATE_TX_MPDU,
			stats->tx_mpdu) ||
	    nla_put_u32(vendor_event,
			QCA_WLAN_VENDOR_ATTR_LL_STATS_RATE_RX_MPDU,
			stats->rx_mpdu) ||
	    nla_put_u32(vendor_event,
			QCA_WLAN_VENDOR_ATTR_LL_STATS_RATE_MPDU_LOST,
			stats->mpdu_lost) ||
	    nla_put_u32(vendor_event,
			QCA_WLAN_VENDOR_ATTR_LL_STATS_RATE_RETRIES,
			stats->retries) ||
	    nla_put_u32(vendor_event,
			QCA_WLAN_VENDOR_ATTR_LL_STATS_RATE_RETRIES_SHORT,
			stats->retries_short) ||
	    nla_put_u32(vendor_event,
			QCA_WLAN_VENDOR_ATTR_LL_STATS_RATE_RETRIES_LONG,
			stats->retries_long)) {
		hdd_err("QCA_WLAN_VENDOR_ATTR put fail");
		return false;
	}

	return true;
}

/**
 * put_wifi_peer_rates() - put wifi peer rate info
 * @stats: Pointer to stats context
 * @vendor_event: Pointer to vendor event
 *
 * Return: bool
 */
static bool put_wifi_peer_rates(struct wifi_peer_info *stats,
				struct sk_buff *vendor_event)
{
	uint32_t i;
	struct wifi_rate_stat *rate_stat;
	int nest_id;
	struct nlattr *info;
	struct nlattr *rates;

	/* no rates is ok */
	if (!stats->num_rate)
		return true;

	nest_id = QCA_WLAN_VENDOR_ATTR_LL_STATS_PEER_INFO_RATE_INFO;
	info = nla_nest_start(vendor_event, nest_id);
	if (!info)
		return false;

	for (i = 0; i < stats->num_rate; i++) {
		rates = nla_nest_start(vendor_event, i);
		if (!rates)
			return false;
		rate_stat = &stats->rate_stats[i];
		if (!put_wifi_rate_stat(rate_stat, vendor_event)) {
			hdd_err("QCA_WLAN_VENDOR_ATTR put fail");
			return false;
		}
		nla_nest_end(vendor_event, rates);
	}
	nla_nest_end(vendor_event, info);

	return true;
}

#if defined(WLAN_FEATURE_11BE_MLO) && defined(CFG80211_11BE_BASIC)
/**
 * wlan_hdd_put_mlo_link_iface_info() - Send per mlo link info to framework
 * @info: Pointer to wlan_hdd_mlo_iface_stats_info struct
 * @skb: Pointer to data buffer
 *
 * Return: True on success, False on failure
 */
static bool
wlan_hdd_put_mlo_link_iface_info(struct wlan_hdd_mlo_iface_stats_info *info,
				 struct sk_buff *skb)
{
	if (nla_put_u8(skb,
		       QCA_WLAN_VENDOR_ATTR_LL_STATS_MLO_LINK_ID,
		       info->link_id) ||
	    nla_put_u32(skb,
			QCA_WLAN_VENDOR_ATTR_LL_STATS_RADIO_ID,
			info->radio_id) ||
	    nla_put_u32(skb,
			QCA_WLAN_VENDOR_ATTR_LL_STATS_CHANNEL_INFO_CENTER_FREQ,
			info->freq)) {
		hdd_err("wlan_hdd_put_mlo_link_iface_info failed");
		return false;
	}

	return true;
}

/**
 * wlan_hdd_get_connected_link_info() - Get connected links' id and frequency
 * @link_info: Link info pointerin adapter
 * @info: Pointer to wlan_hdd_mlo_iface_stats_info struct
 *
 * Return: True on success, False on failure
 */
static void
wlan_hdd_get_connected_link_info(struct wlan_hdd_link_info *link_info,
				 struct wlan_hdd_mlo_iface_stats_info *info)
{
	struct hdd_station_ctx *sta_ctx;

	if (!link_info) {
		hdd_err("Invalid link_info");
		info->link_id = WLAN_INVALID_LINK_ID;
		return;
	}

	sta_ctx = WLAN_HDD_GET_STATION_CTX_PTR(link_info);
	info->link_id = sta_ctx->conn_info.ieee_link_id;
	info->freq = sta_ctx->conn_info.chan_freq;
}
#endif

/**
 * put_wifi_peer_info() - put wifi peer info
 * @stats: Pointer to stats context
 * @vendor_event: Pointer to vendor event
 *
 * Return: bool
 */
static bool put_wifi_peer_info(struct wifi_peer_info *stats,
			       struct sk_buff *vendor_event)
{
	if (nla_put_u32(vendor_event,
			QCA_WLAN_VENDOR_ATTR_LL_STATS_PEER_INFO_TYPE,
			wmi_to_sir_peer_type(stats->type)) ||
	    nla_put(vendor_event,
		       QCA_WLAN_VENDOR_ATTR_LL_STATS_PEER_INFO_MAC_ADDRESS,
		       QDF_MAC_ADDR_SIZE, &stats->peer_macaddr.bytes[0]) ||
	    nla_put_u32(vendor_event,
			QCA_WLAN_VENDOR_ATTR_LL_STATS_PEER_INFO_CAPABILITIES,
			stats->capabilities) ||
	    nla_put_u32(vendor_event,
			QCA_WLAN_VENDOR_ATTR_LL_STATS_PEER_INFO_NUM_RATES,
			stats->num_rate)) {
		hdd_err("QCA_WLAN_VENDOR_ATTR put fail");
		return false;
	}

	return put_wifi_peer_rates(stats, vendor_event);
}

/**
 * put_wifi_wmm_ac_stat() - put wifi wmm ac stats
 * @stats: Pointer to stats context
 * @vendor_event: Pointer to vendor event
 *
 * Return: bool
 */
static bool put_wifi_wmm_ac_stat(wmi_wmm_ac_stats *stats,
				 struct sk_buff *vendor_event)
{
	if (nla_put_u32(vendor_event, QCA_WLAN_VENDOR_ATTR_LL_STATS_WMM_AC_AC,
			stats->ac_type) ||
	    nla_put_u32(vendor_event,
			QCA_WLAN_VENDOR_ATTR_LL_STATS_WMM_AC_TX_MPDU,
			stats->tx_mpdu) ||
	    nla_put_u32(vendor_event,
			QCA_WLAN_VENDOR_ATTR_LL_STATS_WMM_AC_RX_MPDU,
			stats->rx_mpdu) ||
	    nla_put_u32(vendor_event,
			QCA_WLAN_VENDOR_ATTR_LL_STATS_WMM_AC_TX_MCAST,
			stats->tx_mcast) ||
	    nla_put_u32(vendor_event,
			QCA_WLAN_VENDOR_ATTR_LL_STATS_WMM_AC_RX_MCAST,
			stats->rx_mcast) ||
	    nla_put_u32(vendor_event,
			QCA_WLAN_VENDOR_ATTR_LL_STATS_WMM_AC_RX_AMPDU,
			stats->rx_ampdu) ||
	    nla_put_u32(vendor_event,
			QCA_WLAN_VENDOR_ATTR_LL_STATS_WMM_AC_TX_AMPDU,
			stats->tx_ampdu) ||
	    nla_put_u32(vendor_event,
			QCA_WLAN_VENDOR_ATTR_LL_STATS_WMM_AC_MPDU_LOST,
			stats->mpdu_lost) ||
	    nla_put_u32(vendor_event,
			QCA_WLAN_VENDOR_ATTR_LL_STATS_WMM_AC_RETRIES,
			stats->retries) ||
	    nla_put_u32(vendor_event,
			QCA_WLAN_VENDOR_ATTR_LL_STATS_WMM_AC_RETRIES_SHORT,
			stats->retries_short) ||
	    nla_put_u32(vendor_event,
			QCA_WLAN_VENDOR_ATTR_LL_STATS_WMM_AC_RETRIES_LONG,
			stats->retries_long) ||
	    nla_put_u32(vendor_event,
			QCA_WLAN_VENDOR_ATTR_LL_STATS_WMM_AC_CONTENTION_TIME_MIN,
			stats->contention_time_min) ||
	    nla_put_u32(vendor_event,
			QCA_WLAN_VENDOR_ATTR_LL_STATS_WMM_AC_CONTENTION_TIME_MAX,
			stats->contention_time_max) ||
	    nla_put_u32(vendor_event,
			QCA_WLAN_VENDOR_ATTR_LL_STATS_WMM_AC_CONTENTION_TIME_AVG,
			stats->contention_time_avg) ||
	    nla_put_u32(vendor_event,
			QCA_WLAN_VENDOR_ATTR_LL_STATS_WMM_AC_CONTENTION_NUM_SAMPLES,
			stats->contention_num_samples)) {
		hdd_err("QCA_WLAN_VENDOR_ATTR put fail");
		return false;
	}

	return true;
}

/**
 * put_wifi_interface_info() - put wifi interface info
 * @stats: Pointer to stats context
 * @vendor_event: Pointer to vendor event
 *
 * Return: bool
 */
static bool put_wifi_interface_info(struct wifi_interface_info *stats,
				    struct sk_buff *vendor_event)
{
	if (nla_put_u32(vendor_event,
			QCA_WLAN_VENDOR_ATTR_LL_STATS_IFACE_INFO_MODE,
			stats->mode) ||
	    nla_put(vendor_event,
		    QCA_WLAN_VENDOR_ATTR_LL_STATS_IFACE_INFO_MAC_ADDR,
		    QDF_MAC_ADDR_SIZE, stats->macAddr.bytes) ||
	    nla_put_u32(vendor_event,
			QCA_WLAN_VENDOR_ATTR_LL_STATS_IFACE_INFO_STATE,
			stats->state) ||
	    nla_put_u32(vendor_event,
			QCA_WLAN_VENDOR_ATTR_LL_STATS_IFACE_INFO_ROAMING,
			stats->roaming) ||
	    nla_put_u32(vendor_event,
			QCA_WLAN_VENDOR_ATTR_LL_STATS_IFACE_INFO_CAPABILITIES,
			stats->capabilities) ||
	    nla_put(vendor_event,
		    QCA_WLAN_VENDOR_ATTR_LL_STATS_IFACE_INFO_SSID,
		    strlen(stats->ssid), stats->ssid) ||
	    nla_put(vendor_event,
		    QCA_WLAN_VENDOR_ATTR_LL_STATS_IFACE_INFO_BSSID,
		    QDF_MAC_ADDR_SIZE, stats->bssid.bytes) ||
	    nla_put(vendor_event,
		    QCA_WLAN_VENDOR_ATTR_LL_STATS_IFACE_INFO_AP_COUNTRY_STR,
		    REG_ALPHA2_LEN + 1, stats->apCountryStr) ||
	    nla_put(vendor_event,
		    QCA_WLAN_VENDOR_ATTR_LL_STATS_IFACE_INFO_COUNTRY_STR,
		    REG_ALPHA2_LEN + 1, stats->countryStr) ||
	    nla_put_u8(vendor_event,
		       QCA_WLAN_VENDOR_ATTR_LL_STATS_IFACE_INFO_TS_DUTY_CYCLE,
		       stats->time_slice_duty_cycle)) {
		hdd_err("QCA_WLAN_VENDOR_ATTR put fail");
		return false;
	}

	return true;
}

/**
 * put_wifi_iface_stats() - put wifi interface stats
 * @if_stat: Pointer to interface stats context
 * @num_peers: Number of peers
 * @vendor_event: Pointer to vendor event
 *
 * Return: bool
 */
static bool put_wifi_iface_stats(struct wifi_interface_stats *if_stat,
				 u32 num_peers, struct sk_buff *vendor_event)
{
	int i = 0;
	struct nlattr *wmm_info;
	struct nlattr *wmm_stats;
	u64 average_tsf_offset;
	wmi_iface_link_stats *link_stats = &if_stat->link_stats;

	if (!put_wifi_interface_info(&if_stat->info, vendor_event)) {
		hdd_err("QCA_WLAN_VENDOR_ATTR put fail");
		return false;

	}

	average_tsf_offset =  link_stats->avg_bcn_spread_offset_high;
	average_tsf_offset =  (average_tsf_offset << 32) |
		link_stats->avg_bcn_spread_offset_low;

	if (nla_put_u32(vendor_event,
			QCA_WLAN_VENDOR_ATTR_LL_STATS_TYPE,
			QCA_NL80211_VENDOR_SUBCMD_LL_STATS_TYPE_IFACE) ||
	    nla_put_u32(vendor_event,
			QCA_WLAN_VENDOR_ATTR_LL_STATS_IFACE_NUM_PEERS,
			num_peers) ||
	    nla_put_u32(vendor_event,
			QCA_WLAN_VENDOR_ATTR_LL_STATS_IFACE_BEACON_RX,
			link_stats->beacon_rx) ||
	    nla_put_u32(vendor_event,
			QCA_WLAN_VENDOR_ATTR_LL_STATS_IFACE_MGMT_RX,
			link_stats->mgmt_rx) ||
	    nla_put_u32(vendor_event,
			QCA_WLAN_VENDOR_ATTR_LL_STATS_IFACE_MGMT_ACTION_RX,
			link_stats->mgmt_action_rx) ||
	    nla_put_u32(vendor_event,
			QCA_WLAN_VENDOR_ATTR_LL_STATS_IFACE_MGMT_ACTION_TX,
			link_stats->mgmt_action_tx) ||
	    nla_put_u32(vendor_event,
			QCA_WLAN_VENDOR_ATTR_LL_STATS_IFACE_RSSI_MGMT,
			link_stats->rssi_mgmt) ||
	    nla_put_u32(vendor_event,
			QCA_WLAN_VENDOR_ATTR_LL_STATS_IFACE_RSSI_DATA,
			link_stats->rssi_data) ||
	    nla_put_u32(vendor_event,
			QCA_WLAN_VENDOR_ATTR_LL_STATS_IFACE_RSSI_ACK,
			link_stats->rssi_ack) ||
	    nla_put_u32(vendor_event,
			QCA_WLAN_VENDOR_ATTR_LL_STATS_IFACE_LEAKY_AP_DETECTED,
			link_stats->is_leaky_ap) ||
	    nla_put_u32(vendor_event,
			QCA_WLAN_VENDOR_ATTR_LL_STATS_IFACE_LEAKY_AP_AVG_NUM_FRAMES_LEAKED,
			link_stats->avg_rx_frms_leaked) ||
	    nla_put_u32(vendor_event,
			QCA_WLAN_VENDOR_ATTR_LL_STATS_IFACE_LEAKY_AP_GUARD_TIME,
			link_stats->rx_leak_window) ||
	    nla_put_s32(vendor_event,
			QCA_WLAN_VENDOR_ATTR_LL_STATS_IFACE_NF_CAL_VAL,
			link_stats->nf_cal_val) ||
	    hdd_wlan_nla_put_u64(vendor_event,
			QCA_WLAN_VENDOR_ATTR_LL_STATS_IFACE_AVERAGE_TSF_OFFSET,
			average_tsf_offset) ||
	    nla_put_u32(vendor_event,
			QCA_WLAN_VENDOR_ATTR_LL_STATS_IFACE_RTS_SUCC_CNT,
			if_stat->rts_succ_cnt) ||
	    nla_put_u32(vendor_event,
			QCA_WLAN_VENDOR_ATTR_LL_STATS_IFACE_RTS_FAIL_CNT,
			if_stat->rts_fail_cnt) ||
	    nla_put_u32(vendor_event,
			QCA_WLAN_VENDOR_ATTR_LL_STATS_IFACE_PPDU_SUCC_CNT,
			if_stat->ppdu_succ_cnt) ||
	    nla_put_u32(vendor_event,
			QCA_WLAN_VENDOR_ATTR_LL_STATS_IFACE_PPDU_FAIL_CNT,
			if_stat->ppdu_fail_cnt)) {
		hdd_err("QCA_WLAN_VENDOR_ATTR put fail");
		return false;
	}

	wmm_info = nla_nest_start(vendor_event,
				  QCA_WLAN_VENDOR_ATTR_LL_STATS_WMM_INFO);
	if (!wmm_info)
		return false;

	for (i = 0; i < WIFI_AC_MAX; i++) {
		wmm_stats = nla_nest_start(vendor_event, i);
		if (!wmm_stats)
			return false;

		if (!put_wifi_wmm_ac_stat(&if_stat->ac_stats[i],
					  vendor_event)) {
			hdd_err("put_wifi_wmm_ac_stat Fail");
			return false;
		}

		nla_nest_end(vendor_event, wmm_stats);
	}
	nla_nest_end(vendor_event, wmm_info);

	if (nla_put_u32(vendor_event,
			QCA_WLAN_VENDOR_ATTR_LL_STATS_TIM_BEACON,
			if_stat->powersave_stats.tot_tim_bcn) ||
	    nla_put_u32(vendor_event,
			QCA_WLAN_VENDOR_ATTR_LL_STATS_TIM_BEACON_ERR,
			if_stat->powersave_stats.tot_err_tim_bcn)) {
		hdd_err("QCA_WLAN_VENDOR_ATTR put powersave_stat fail");
		return false;
	}

	return true;
}

/**
 * hdd_map_device_to_ll_iface_mode() - map device to link layer interface mode
 * @device_mode: Device mode
 *
 * Return: interface mode
 */
static tSirWifiInterfaceMode hdd_map_device_to_ll_iface_mode(int device_mode)
{
	switch (device_mode) {
	case QDF_STA_MODE:
		return WIFI_INTERFACE_STA;
	case QDF_SAP_MODE:
		return WIFI_INTERFACE_SOFTAP;
	case QDF_P2P_CLIENT_MODE:
		return WIFI_INTERFACE_P2P_CLIENT;
	case QDF_P2P_GO_MODE:
		return WIFI_INTERFACE_P2P_GO;
	default:
		/* Return Interface Mode as STA for all the unsupported modes */
		return WIFI_INTERFACE_STA;
	}
}

bool hdd_get_interface_info(struct wlan_hdd_link_info *link_info,
			    struct wifi_interface_info *info)
{
	struct hdd_station_ctx *sta_ctx;
	struct sap_config *config;
	struct qdf_mac_addr *mac;
	struct hdd_adapter *adapter = link_info->adapter;

	info->mode = hdd_map_device_to_ll_iface_mode(adapter->device_mode);

	mac = hdd_adapter_get_link_mac_addr(link_info);
	if (!mac) {
		hdd_debug("Invalid HDD link info");
		return false;
	}

	qdf_copy_macaddr(&info->macAddr, mac);

	if (((QDF_STA_MODE == adapter->device_mode) ||
	     (QDF_P2P_CLIENT_MODE == adapter->device_mode) ||
	     (QDF_P2P_DEVICE_MODE == adapter->device_mode))) {
		sta_ctx = WLAN_HDD_GET_STATION_CTX_PTR(link_info);
		if (hdd_cm_is_disconnected(link_info))
			info->state = WIFI_DISCONNECTED;

		if (hdd_cm_is_connecting(link_info)) {
			hdd_debug("Session ID %d, Connection is in progress",
				  link_info->vdev_id);
			info->state = WIFI_ASSOCIATING;
		}
		if (hdd_cm_is_vdev_associated(link_info) &&
		    !sta_ctx->conn_info.is_authenticated) {
			hdd_err("client " QDF_MAC_ADDR_FMT
				" is in the middle of WPS/EAPOL exchange.",
				QDF_MAC_ADDR_REF(mac->bytes));
			info->state = WIFI_AUTHENTICATING;
		}
		if (hdd_cm_is_vdev_associated(link_info) ||
		    link_info->vdev_id == WLAN_INVALID_VDEV_ID) {
			info->state = WIFI_ASSOCIATED;
			qdf_copy_macaddr(&info->bssid,
					 &sta_ctx->conn_info.bssid);
			qdf_mem_copy(info->ssid,
				     sta_ctx->conn_info.ssid.SSID.ssId,
				     sta_ctx->conn_info.ssid.SSID.length);
			/*
			 * NULL Terminate the string
			 */
			info->ssid[sta_ctx->conn_info.ssid.SSID.length] = 0;
		}
	}

	if ((adapter->device_mode == QDF_SAP_MODE ||
	     adapter->device_mode == QDF_P2P_GO_MODE) &&
	    test_bit(SOFTAP_BSS_STARTED, &link_info->link_flags)) {
		config = &link_info->session.ap.sap_config;
		qdf_copy_macaddr(&info->bssid, &config->self_macaddr);
	}
	wlan_reg_get_cc_and_src(adapter->hdd_ctx->psoc, info->countryStr);
	wlan_reg_get_cc_and_src(adapter->hdd_ctx->psoc, info->apCountryStr);

	return true;
}

#if defined(WLAN_FEATURE_11BE_MLO) && defined(CFG80211_11BE_BASIC)
/**
 * hdd_cache_ll_iface_stats() - Caches ll_stats received from fw
 * @hdd_ctx: Pointer to hdd_context
 * @if_stat: Pointer to stats data
 *
 * After receiving Link Layer Interface statistics from FW.
 * This function caches them into wlan_hdd_link_info.
 *
 * Return: None
 */
static void
hdd_cache_ll_iface_stats(struct hdd_context *hdd_ctx,
			 struct wifi_interface_stats *if_stat)
{
	struct wlan_hdd_link_info *link_info;

	link_info = hdd_get_link_info_by_vdev(hdd_ctx, if_stat->vdev_id);
	if (!link_info) {
		hdd_err("Invalid link_info. Unable to cache mlo iface stats");
		return;
	}
	/*
	 * There is no need for wlan_hdd_validate_context here. This is a NB
	 * operation that will come with DSC synchronization. This ensures that
	 * no driver transition will take place as long as this operation is
	 * not complete. Thus the need to check validity of hdd_context is not
	 * required.
	 */
	hdd_nofl_debug("Copying iface stats for vdev_id[%u] into link_info",
		       link_info->vdev_id);
	link_info->ll_iface_stats = *if_stat;
}

/**
 * wlan_hdd_update_wmm_ac_stats() - Populate ll_iface ac stats
 * @link_info: Link info pointer of STA adapter
 * @if_stat: Pointer to wifi_interface_stats structure
 * @update_contention_stats: whether to update contention stats or not
 *
 * Return: none
 */
static void
wlan_hdd_update_wmm_ac_stats(struct wlan_hdd_link_info *link_info,
			     struct wifi_interface_stats *if_stat,
			     bool update_contention_stats)
{
	int i;
	wmi_wmm_ac_stats *hdd_ac_stats, *stats;

	for (i = 0; i < WIFI_AC_MAX; i++) {
		hdd_ac_stats = &link_info->ll_iface_stats.ac_stats[i];
		stats = &if_stat->ac_stats[i];
		stats->ac_type = hdd_ac_stats->ac_type;
		stats->tx_mpdu += hdd_ac_stats->tx_mpdu;
		stats->rx_mpdu += hdd_ac_stats->rx_mpdu;
		stats->tx_mcast += hdd_ac_stats->tx_mcast;
		stats->rx_mcast += hdd_ac_stats->rx_mcast;
		stats->rx_ampdu += hdd_ac_stats->rx_ampdu;
		stats->tx_ampdu += hdd_ac_stats->tx_ampdu;
		stats->mpdu_lost += hdd_ac_stats->mpdu_lost;
		stats->retries += hdd_ac_stats->retries;
		stats->retries_short += hdd_ac_stats->retries_short;
		stats->retries_long += hdd_ac_stats->retries_long;
		if (!update_contention_stats)
			continue;
		stats->contention_time_min = hdd_ac_stats->contention_time_min;
		stats->contention_time_max = hdd_ac_stats->contention_time_max;
		stats->contention_time_avg = hdd_ac_stats->contention_time_avg;
		stats->contention_num_samples =
					hdd_ac_stats->contention_num_samples;
	}
}

/**
 * wlan_hdd_update_iface_stats_info() - Populate ll_iface stats info
 * @link_info: Link info pointer of STA adapter
 * @if_stat: Pointer to wifi_interface_stats structure
 * @update_stats: whether to update iface stats
 *
 * Return: none
 */
static void
wlan_hdd_update_iface_stats_info(struct wlan_hdd_link_info *link_info,
				 struct wifi_interface_stats *if_stat,
				 bool update_stats)
{
	wmi_iface_link_stats *hdd_stats, *stats;

	hdd_stats = &link_info->ll_iface_stats.link_stats;
	stats = &if_stat->link_stats;

	if (!update_stats) {
		wlan_hdd_update_wmm_ac_stats(link_info, if_stat, update_stats);
		return;
	}

	stats->beacon_rx = hdd_stats->beacon_rx;
	stats->mgmt_rx = hdd_stats->mgmt_rx;
	stats->mgmt_action_rx = hdd_stats->mgmt_action_rx;
	stats->mgmt_action_tx = hdd_stats->mgmt_action_tx;
	stats->rssi_mgmt = hdd_stats->rssi_mgmt;
	stats->rssi_data = hdd_stats->rssi_data;
	stats->rssi_ack = hdd_stats->rssi_ack;
	stats->avg_bcn_spread_offset_low =
			hdd_stats->avg_bcn_spread_offset_low;
	stats->avg_bcn_spread_offset_high =
			hdd_stats->avg_bcn_spread_offset_high;
	stats->is_leaky_ap = hdd_stats->is_leaky_ap;
	stats->avg_rx_frms_leaked = hdd_stats->avg_rx_frms_leaked;
	stats->rx_leak_window = hdd_stats->rx_leak_window;
	stats->nf_cal_val = hdd_stats->nf_cal_val;
	stats->num_peers = hdd_stats->num_peers;
	stats->num_ac = hdd_stats->num_ac;

	if_stat->rts_succ_cnt = link_info->ll_iface_stats.rts_succ_cnt;
	if_stat->rts_fail_cnt = link_info->ll_iface_stats.rts_fail_cnt;
	if_stat->ppdu_succ_cnt = link_info->ll_iface_stats.ppdu_succ_cnt;
	if_stat->ppdu_fail_cnt = link_info->ll_iface_stats.ppdu_fail_cnt;

	if_stat->powersave_stats.tot_tim_bcn =
		link_info->ll_iface_stats.powersave_stats.tot_tim_bcn;
	if_stat->powersave_stats.tot_err_tim_bcn =
		link_info->ll_iface_stats.powersave_stats.tot_err_tim_bcn;

	wlan_hdd_update_wmm_ac_stats(link_info, if_stat, update_stats);
}

/**
 * wlan_hdd_copy_mlo_peer_stats() - copy mlo peer stats to link_info
 * @adapter: Pointer to HDD adapter
 * @peer_stat: Pointer to wifi_peer_stat
 *
 * Return: none
 */
static void
wlan_hdd_copy_mlo_peer_stats(struct hdd_adapter *adapter,
			     struct wifi_peer_stat *peer_stat)
{
	uint8_t i, j, num_rate;
	struct wifi_peer_info *peer_info = NULL;
	struct wifi_rate_stat *rate_stat;
	struct wlan_hdd_link_info *link_info;
	struct hdd_station_ctx *sta_ctx;

	if (!peer_stat) {
		hdd_err("Invalid mlo peer stats");
		return;
	}

	if (!peer_stat->num_peers) {
		hdd_err("No mlo peers");
		return;
	}

	/* Firmware doesn't send peer stats for stanby link, but we need to
	 * send peer stats for stanby link as well to userspace. So, in that
	 * case we fill partial values for stanby link and full stats received
	 * from firmware for active links and set the flag stats_cached in
	 * the link_info->mlo_peer_info structure.
	 */

	peer_info = (struct wifi_peer_info *)peer_stat->peer_info;

	hdd_adapter_for_each_link_info(adapter, link_info) {
		sta_ctx = WLAN_HDD_GET_STATION_CTX_PTR(link_info);
		link_info->mlo_peer_info.link_id =
						sta_ctx->conn_info.ieee_link_id;

		if (link_info->mlo_peer_info.stats_cached)
			continue;

		/* since for stanby link we don't have valid values from
		 * firmware, we just fill peer mac and link id.
		 */
		qdf_mem_copy(&link_info->mlo_peer_info.peer_mac,
			     &sta_ctx->conn_info.bssid, QDF_MAC_ADDR_SIZE);
		link_info->mlo_peer_info.type = peer_info->type;
		link_info->mlo_peer_info.num_rate = HDD_MAX_PER_PEER_RATES;
		for (j = 0; j < HDD_MAX_PER_PEER_RATES; j++)
			qdf_mem_zero(&link_info->mlo_peer_info.rate_stats[j],
				     sizeof(struct wifi_rate_stat));
		hdd_debug("Default values for standby link " QDF_MAC_ADDR_FMT,
			  QDF_MAC_ADDR_REF(sta_ctx->conn_info.bssid.bytes));
	}

	for (i = 1; i <= peer_stat->num_peers; i++) {
		link_info = hdd_get_link_info_by_bssid(adapter->hdd_ctx,
						peer_info->peer_macaddr.bytes);
		if (!link_info) {
			hdd_err("invalid link_info");
			continue;
		}

		num_rate = peer_info->num_rate;
		if (num_rate > HDD_MAX_PER_PEER_RATES) {
			hdd_err("For peer " QDF_MAC_ADDR_FMT " got %u rate stats, expected %d",
				QDF_MAC_ADDR_REF(peer_info->peer_macaddr.bytes),
				num_rate, HDD_MAX_PER_PEER_RATES);
			return;
		}

		link_info->mlo_peer_info.type = peer_info->type;
		qdf_mem_copy(&link_info->mlo_peer_info.peer_mac,
			     &peer_info->peer_macaddr, QDF_MAC_ADDR_SIZE);
		link_info->mlo_peer_info.capabilities = peer_info->capabilities;
		link_info->mlo_peer_info.num_rate = peer_info->num_rate;
		link_info->mlo_peer_info.power_saving = peer_info->power_saving;

		for (j = 0; j < num_rate; j++) {
			rate_stat = &peer_info->rate_stats[j];
			qdf_mem_copy(&link_info->mlo_peer_info.rate_stats[j],
				     rate_stat, sizeof(struct wifi_rate_stat));
		}

		/* peer stats for active link are cached in link_info
		 * so set the flag stats_cahed to true.
		 */
		link_info->mlo_peer_info.stats_cached = true;

		peer_info = (struct wifi_peer_info *)
				((uint8_t *)peer_stat->peer_info +
				(i * sizeof(struct wifi_peer_info)) +
				(num_rate * sizeof(struct wifi_rate_stat)));
	}
	hdd_debug_rl("Copied MLO Peer stats into link_info");
}

/**
 * wlan_hdd_put_mlo_peer_info() - send mlo peer info to userspace
 * @link_info: Link info pointer of STA adapter
 * @skb: Pointer to vendor event
 *
 * Return: none
 */
static bool wlan_hdd_put_mlo_peer_info(struct wlan_hdd_link_info *link_info,
				       struct sk_buff *skb)
{
	struct wifi_rate_stat *rate_stat;
	struct nlattr *rate_nest, *rates;
	int rate_nest_id = QCA_WLAN_VENDOR_ATTR_LL_STATS_PEER_INFO_RATE_INFO;
	uint8_t i;

	if (!link_info) {
		hdd_err("Invalid link_info");
		return false;
	}

	if (nla_put_u32(skb,
			QCA_WLAN_VENDOR_ATTR_LL_STATS_PEER_INFO_TYPE,
			wmi_to_sir_peer_type(link_info->mlo_peer_info.type)) ||
	    nla_put(skb, QCA_WLAN_VENDOR_ATTR_LL_STATS_PEER_INFO_MAC_ADDRESS,
		    QDF_MAC_ADDR_SIZE,
		    &link_info->mlo_peer_info.peer_mac.bytes[0]) ||
	    nla_put_u32(skb,
			QCA_WLAN_VENDOR_ATTR_LL_STATS_PEER_INFO_CAPABILITIES,
			link_info->mlo_peer_info.capabilities) ||
	    nla_put_u32(skb,
			QCA_WLAN_VENDOR_ATTR_LL_STATS_PEER_INFO_NUM_RATES,
			link_info->mlo_peer_info.num_rate) ||
	    nla_put_u8(skb,
		       QCA_WLAN_VENDOR_ATTR_LL_STATS_MLO_LINK_ID,
		       link_info->mlo_peer_info.link_id)) {
		hdd_err("put mlo peer info fail");
		return false;
	}

	/* no rates is ok */
	if (!link_info->mlo_peer_info.num_rate)
		return true;

	rate_nest = nla_nest_start(skb, rate_nest_id);
	if (!rate_nest)
		return false;

	for (i = 0; i < link_info->mlo_peer_info.num_rate; i++) {
		rates = nla_nest_start(skb, i);
		if (!rates)
			return false;
		rate_stat = &link_info->mlo_peer_info.rate_stats[i];
		if (!put_wifi_rate_stat(rate_stat, skb)) {
			hdd_err("QCA_WLAN_VENDOR_ATTR put fail");
			return false;
		}
		nla_nest_end(skb, rates);
	}
	nla_nest_end(skb, rate_nest);

	return true;
}

/**
 * wlan_hdd_send_mlo_ll_peer_stats_to_user() - send mlo ll peer stats to userspace
 * @adapter: Pointer to HDD adapter
 *
 * Return: none
 */
static void
wlan_hdd_send_mlo_ll_peer_stats_to_user(struct hdd_adapter *adapter)
{
	struct sk_buff *skb;
	struct nlattr *peers, *peer_nest;
	struct wlan_hdd_link_info *link_info;
	struct wlan_hdd_mlo_iface_stats_info info = {0};
	int peer_nest_id = QCA_WLAN_VENDOR_ATTR_LL_STATS_PEER_INFO;
	u32 num_peers;
	uint8_t i = 0;

	wlan_hdd_get_mlo_links_count(adapter, &num_peers);

	hdd_debug_rl("WMI_MLO_LINK_STATS_PEER. Num Peers: %u", num_peers);

	if (!num_peers) {
		hdd_err("No mlo peers");
		return;
	}

	skb = wlan_cfg80211_vendor_cmd_alloc_reply_skb(adapter->hdd_ctx->wiphy,
						       LL_STATS_EVENT_BUF_SIZE);
	if (!skb) {
		hdd_err("wlan_cfg80211_vendor_cmd_alloc_reply_skb failed");
		return;
	}

	if (nla_put_u32(skb,
			QCA_WLAN_VENDOR_ATTR_LL_STATS_TYPE,
			QCA_NL80211_VENDOR_SUBCMD_LL_STATS_TYPE_PEERS) ||
	    nla_put_u32(skb,
			QCA_WLAN_VENDOR_ATTR_LL_STATS_RESULTS_MORE_DATA,
			adapter->hdd_ctx->more_peer_data) ||
	    nla_put_u32(skb,
			QCA_WLAN_VENDOR_ATTR_LL_STATS_IFACE_NUM_PEERS,
			num_peers)) {
		hdd_err("QCA_WLAN_VENDOR_ATTR put fail");

		goto exit;
	}

	peer_nest = nla_nest_start(skb, peer_nest_id);
	if (!peer_nest) {
		hdd_err("nla_nest_start failed");
		goto exit;
	}

	hdd_adapter_for_each_link_info(adapter, link_info) {
		wlan_hdd_get_connected_link_info(link_info, &info);
		if (info.link_id == WLAN_INVALID_LINK_ID)
			continue;

		peers = nla_nest_start(skb, i);
		if (!peers) {
			hdd_err("nla_nest_start failed");
			goto exit;
		}

		if (!wlan_hdd_put_mlo_peer_info(link_info, skb)) {
			hdd_err("put_wifi_peer_info fail");
			goto exit;
		}
		nla_nest_end(skb, peers);
		i++;
	}
	nla_nest_end(skb, peer_nest);

	wlan_cfg80211_vendor_cmd_reply(skb);

	hdd_debug_rl("Sent %u MLO Peer stats to User Space", i);
	return;
exit:
	wlan_cfg80211_vendor_free_skb(skb);
}

#ifndef WLAN_HDD_MULTI_VDEV_SINGLE_NDEV
/**
 * wlan_hdd_get_iface_stats() - Get ll_iface stats info from link_info
 * @link_info: Link info pointer of STA adapter
 * @if_stat: Pointer to wifi_interface_stats structure
 *
 * Return: 0 on success, error on failure
 */
static int wlan_hdd_get_iface_stats(struct wlan_hdd_link_info *link_info,
				    struct wifi_interface_stats *if_stat)
{
	if (!link_info || !if_stat) {
		hdd_err("Invalid link_info or interface stats");
		return -EINVAL;
	}

	qdf_mem_copy(if_stat, &link_info->ll_iface_stats,
		     sizeof(link_info->ll_iface_stats));

	if (!hdd_get_interface_info(link_info, &if_stat->info)) {
		hdd_err("Unable to get iface info for vdev[%u]",
			if_stat->vdev_id);
		return -EINVAL;
	}

	return 0;
}

static bool
wlan_hdd_get_mlo_iface_info(struct hdd_context *hdd_ctx,
			    struct wifi_interface_stats *stats,
			    struct wlan_hdd_mlo_iface_stats_info *info)
{
	struct wlan_hdd_link_info *link_info;
	struct hdd_station_ctx *sta_ctx;

	if (!stats) {
		hdd_err("invalid wifi interface stats");
		return false;
	}

	link_info = hdd_get_link_info_by_bssid(hdd_ctx,
				(const uint8_t *)stats->info.bssid.bytes);

	if (!link_info) {
		hdd_err("invalid link_info");
		return false;
	}

	sta_ctx = WLAN_HDD_GET_STATION_CTX_PTR(link_info);
	info->link_id = sta_ctx->conn_info.ieee_link_id;
	info->freq = sta_ctx->conn_info.chan_freq;

	return true;
}

/**
 * wlan_hdd_send_mlo_ll_iface_stats_to_user() - send mlo ll stats to userspace
 * @adapter: Pointer to adapter
 *
 * Return: none
 */
static void
wlan_hdd_send_mlo_ll_iface_stats_to_user(struct hdd_adapter *adapter)
{
	struct hdd_mlo_adapter_info *mlo_adapter_info;
	struct hdd_adapter *link_adapter, *ml_adapter;
	struct hdd_context *hdd_ctx = WLAN_HDD_GET_CTX(adapter);
	u32 num_links, per_link_peers;
	uint8_t i, j = 0;
	int8_t rssi;
	struct wifi_interface_stats cumulative_if_stat = {0};
	struct wlan_hdd_mlo_iface_stats_info info = {0};
	struct wifi_interface_stats *link_if_stat;
	bool update_stats = false;
	QDF_STATUS status;
	struct nlattr *ml_iface_nest, *ml_iface_links;
	struct sk_buff *skb;
	struct wlan_hdd_link_info *link_info;
	struct qdf_mac_addr *netdev_addr;

	if (wlan_hdd_validate_context(hdd_ctx)) {
		hdd_err("Invalid hdd context");
		return;
	}

	ml_adapter = adapter;
	if (hdd_adapter_is_link_adapter(adapter))
		ml_adapter = hdd_adapter_get_mlo_adapter_from_link(adapter);

	link_info = ml_adapter->deflink;
	rssi = link_info->rssi;
	wlan_hdd_get_mlo_links_count(adapter, &num_links);

	skb = wlan_cfg80211_vendor_cmd_alloc_reply_skb(hdd_ctx->wiphy,
						       LL_STATS_EVENT_BUF_SIZE);

	if (!skb) {
		hdd_err("wlan_cfg80211_vendor_cmd_alloc_reply_skb failed");
		return;
	}

	link_if_stat = qdf_mem_malloc(sizeof(*link_if_stat) * num_links);
	if (!link_if_stat) {
		hdd_err("failed to allocate memory for link iface stat");
		goto err;
	}

	hdd_debug("WMI_MLO_LINK_STATS_IFACE Data. Num_links = %u", num_links);

	if (!hdd_get_interface_info(link_info, &cumulative_if_stat.info)) {
		hdd_err("hdd_get_interface_info get fail for ml_adapter");
		goto err;
	}

	wlan_hdd_update_iface_stats_info(link_info, &cumulative_if_stat,
					 true);

	mlo_adapter_info = &ml_adapter->mlo_adapter_info;
	for (i = 0; i < WLAN_MAX_MLD; i++) {
		link_adapter = mlo_adapter_info->link_adapter[i];

		if (!link_adapter)
			continue;

		link_info = link_adapter->deflink;
		if (!hdd_cm_is_vdev_associated(link_info)) {
			hdd_debug_rl("vdev_id[%u] is not associated\n",
				     link_info->vdev_id);
			continue;
		}

		if (hdd_adapter_is_associated_with_ml_adapter(link_adapter)) {
			if (wlan_hdd_get_iface_stats(ml_adapter->deflink,
						     &link_if_stat[j]))
				goto err;
			j++;
			if (j == num_links)
				break;
			continue;
		}

		if (wlan_hdd_get_iface_stats(link_info, &link_if_stat[j]))
			goto err;
		j++;
		if (j == num_links)
			break;

		if (rssi <= link_info->rssi) {
			rssi = link_info->rssi;
			update_stats = true;
		}

		wlan_hdd_update_iface_stats_info(link_info,
						 &cumulative_if_stat,
						 update_stats);
	}

	netdev_addr = hdd_adapter_get_netdev_mac_addr(ml_adapter);
	qdf_copy_macaddr(&cumulative_if_stat.info.macAddr, netdev_addr);

	status = wlan_hdd_get_bss_peer_mld_mac(ml_adapter->deflink,
					       &cumulative_if_stat.info.bssid);
	if (QDF_IS_STATUS_ERROR(status))
		hdd_err_rl("mlo_iface_stats: failed to get bss peer_mld_mac");

	if (!put_wifi_iface_stats(&cumulative_if_stat, num_links, skb)) {
		hdd_err("put_wifi_iface_stats fail");
		goto err;
	}

	ml_iface_nest = nla_nest_start(skb,
				       QCA_WLAN_VENDOR_ATTR_LL_STATS_MLO_LINK);
	if (!ml_iface_nest) {
		hdd_err("Nesting mlo iface stats info failed");
		goto err;
	}

	for (i = 0; i < num_links; i++) {
		ml_iface_links = nla_nest_start(skb, i);
		if (!ml_iface_links) {
			hdd_err("per link mlo iface stats failed");
			goto err;
		}

		per_link_peers =
			link_info->ll_iface_stats.link_stats.num_peers;

		if (!wlan_hdd_get_mlo_iface_info(hdd_ctx,
						 &link_if_stat[i], &info))
			goto err;

		if (!wlan_hdd_put_mlo_link_iface_info(&info, skb))
			goto err;

		if (!put_wifi_iface_stats(&link_if_stat[i],
					  per_link_peers, skb)) {
			hdd_err("put_wifi_iface_stats failed for link[%u]", i);
			goto err;
		}

		nla_nest_end(skb, ml_iface_links);
	}
	nla_nest_end(skb, ml_iface_nest);

	wlan_cfg80211_vendor_cmd_reply(skb);
	qdf_mem_free(link_if_stat);
	hdd_nofl_debug("Sent mlo interface stats to userspace");
	return;
err:
	wlan_cfg80211_vendor_free_skb(skb);
	qdf_mem_free(link_if_stat);
}
#else
static void
wlan_hdd_send_mlo_ll_iface_stats_to_user(struct hdd_adapter *adapter)
{
	struct hdd_context *hdd_ctx = WLAN_HDD_GET_CTX(adapter);
	u32 num_links, per_link_peers;
	uint8_t i = 0;
	int8_t rssi = WLAN_INVALID_RSSI_VALUE;
	struct wifi_interface_stats cumulative_if_stat = {0};
	struct wlan_hdd_mlo_iface_stats_info info = {0};
	struct wifi_interface_stats *stats;
	struct wifi_interface_info *iface_info;
	bool update_stats;
	QDF_STATUS status;
	struct nlattr *ml_iface_nest, *ml_iface_links;
	struct sk_buff *skb;
	struct wlan_hdd_link_info *link_info;
	struct qdf_mac_addr *netdev_addr;

	if (!wlan_hdd_is_mlo_connection(adapter->deflink))
		return;

	if (wlan_hdd_validate_context(hdd_ctx)) {
		hdd_err("Invalid hdd context");
		return;
	}

	skb = wlan_cfg80211_vendor_cmd_alloc_reply_skb(hdd_ctx->wiphy,
						       LL_STATS_EVENT_BUF_SIZE);

	if (!skb) {
		hdd_err("wlan_cfg80211_vendor_cmd_alloc_reply_skb failed");
		return;
	}

	wlan_hdd_get_mlo_links_count(adapter, &num_links);

	hdd_debug("WMI_MLO_LINK_STATS_IFACE Data. Num_links = %u", num_links);

	hdd_adapter_for_each_link_info(adapter, link_info) {
		wlan_hdd_get_connected_link_info(link_info, &info);
		if (info.link_id == WLAN_INVALID_LINK_ID)
			continue;

		if ((link_info->rssi != 0) && (rssi <= link_info->rssi)) {
			rssi = link_info->rssi;
			update_stats = true;
			if (!hdd_get_interface_info(link_info,
						    &cumulative_if_stat.info)) {
				hdd_err("failed to get iface info for link %u",
					info.link_id);
				goto err;
			}
		} else {
			update_stats = false;
		}

		iface_info = &link_info->ll_iface_stats.info;
		if (!hdd_get_interface_info(link_info, iface_info)) {
			hdd_err("get iface info failed for link %u", info.link_id);
			goto err;
		}

		wlan_hdd_update_iface_stats_info(link_info, &cumulative_if_stat,
						 update_stats);
	}

	netdev_addr = hdd_adapter_get_netdev_mac_addr(adapter);
	qdf_copy_macaddr(&cumulative_if_stat.info.macAddr, netdev_addr);

	status = wlan_hdd_get_bss_peer_mld_mac(adapter->deflink,
					       &cumulative_if_stat.info.bssid);
	if (QDF_IS_STATUS_ERROR(status))
		hdd_err_rl("mlo_iface_stats: failed to get bss peer_mld_mac");

	if (!put_wifi_iface_stats(&cumulative_if_stat, num_links, skb)) {
		hdd_err("put_wifi_iface_stats fail");
		goto err;
	}

	ml_iface_nest =
		nla_nest_start(skb, QCA_WLAN_VENDOR_ATTR_LL_STATS_MLO_LINK);

	if (!ml_iface_nest) {
		hdd_err("Nesting mlo iface stats info failed");
		goto err;
	}

	hdd_adapter_for_each_link_info(adapter, link_info) {
		wlan_hdd_get_connected_link_info(link_info, &info);
		if (info.link_id == WLAN_INVALID_LINK_ID)
			continue;

		ml_iface_links = nla_nest_start(skb, i);
		if (!ml_iface_links) {
			hdd_err("per link mlo iface stats failed");
			goto err;
		}

		stats = &link_info->ll_iface_stats;
		per_link_peers = stats->link_stats.num_peers;

		if (!wlan_hdd_put_mlo_link_iface_info(&info, skb))
			goto err;

		if (!put_wifi_iface_stats(stats, per_link_peers, skb)) {
			hdd_err("put iface stats failed for link[%u]", info.link_id);
			goto err;
		}

		nla_nest_end(skb, ml_iface_links);
		i++;
	}
	nla_nest_end(skb, ml_iface_nest);

	wlan_cfg80211_vendor_cmd_reply(skb);
	hdd_nofl_debug("Sent mlo interface stats to userspace");
	return;
err:
	wlan_cfg80211_vendor_free_skb(skb);
}
#endif
#else
static void
hdd_cache_ll_iface_stats(struct hdd_context *hdd_ctx,
			 struct wifi_interface_stats *if_stat)
{
}

static inline void
wlan_hdd_send_mlo_ll_iface_stats_to_user(struct hdd_adapter *adapter)
{
}

static inline void
wlan_hdd_send_mlo_ll_peer_stats_to_user(struct hdd_adapter *adapter)
{
}

static inline bool
wlan_hdd_copy_mlo_peer_stats(struct hdd_adapter *adapter,
			     struct wifi_peer_stat *peer_stat)
{
	return true;
}
#endif

/**
 * hdd_link_layer_process_peer_stats() - This function is called after
 * @adapter: Pointer to device adapter
 * @more_data: More data
 * @peer_stat: Pointer to stats data
 *
 * Receiving Link Layer Peer statistics from FW.This function converts
 * the firmware data to the NL data and sends the same to the kernel/upper
 * layers.
 *
 * Return: None
 */
static void hdd_link_layer_process_peer_stats(struct hdd_adapter *adapter,
					      u32 more_data,
					      struct wifi_peer_stat *peer_stat)
{
	struct hdd_context *hdd_ctx = WLAN_HDD_GET_CTX(adapter);
	struct wifi_peer_info *peer_info;
	struct sk_buff *skb;
	int i, nestid;
	struct nlattr *peers;
	int num_rate;

	if (wlan_hdd_validate_context(hdd_ctx))
		return;

	if ((adapter->device_mode == QDF_STA_MODE ||
	    adapter->device_mode == QDF_P2P_CLIENT_MODE) &&
	    wlan_hdd_is_mlo_connection(adapter->deflink)) {
		wlan_hdd_copy_mlo_peer_stats(adapter, peer_stat);
		return;
	}

	hdd_nofl_debug("LL_STATS_PEER_ALL : num_peers %u, more data = %u",
		       peer_stat->num_peers, more_data);

	/*
	 * Allocate a size of 4096 for the peer stats comprising
	 * each of size = sizeof (struct wifi_peer_info) + num_rate *
	 * sizeof (struct wifi_rate_stat).Each field is put with an
	 * NL attribute.The size of 4096 is considered assuming
	 * that number of rates shall not exceed beyond 50 with
	 * the sizeof (struct wifi_rate_stat) being 32.
	 */
	skb = wlan_cfg80211_vendor_cmd_alloc_reply_skb(hdd_ctx->wiphy,
						       LL_STATS_EVENT_BUF_SIZE);

	if (!skb) {
		hdd_err("wlan_cfg80211_vendor_cmd_alloc_reply_skb failed");
		return;
	}

	if (nla_put_u32(skb,
			QCA_WLAN_VENDOR_ATTR_LL_STATS_TYPE,
			QCA_NL80211_VENDOR_SUBCMD_LL_STATS_TYPE_PEERS) ||
	    nla_put_u32(skb,
			QCA_WLAN_VENDOR_ATTR_LL_STATS_RESULTS_MORE_DATA,
			more_data) ||
	    nla_put_u32(skb,
			QCA_WLAN_VENDOR_ATTR_LL_STATS_IFACE_NUM_PEERS,
			peer_stat->num_peers)) {
		hdd_err("QCA_WLAN_VENDOR_ATTR put fail");

		wlan_cfg80211_vendor_free_skb(skb);
		return;
	}

	peer_info = (struct wifi_peer_info *) ((uint8_t *)
					     peer_stat->peer_info);

	if (peer_stat->num_peers) {
		struct nlattr *peer_nest;

		nestid = QCA_WLAN_VENDOR_ATTR_LL_STATS_PEER_INFO;
		peer_nest = nla_nest_start(skb, nestid);
		if (!peer_nest) {
			hdd_err("nla_nest_start failed");
			wlan_cfg80211_vendor_free_skb(skb);
			return;
		}

		for (i = 1; i <= peer_stat->num_peers; i++) {
			peers = nla_nest_start(skb, i);
			if (!peers) {
				hdd_err("nla_nest_start failed");
				wlan_cfg80211_vendor_free_skb(skb);
				return;
			}

			num_rate = peer_info->num_rate;

			if (!put_wifi_peer_info(peer_info, skb)) {
				hdd_err("put_wifi_peer_info fail");
				wlan_cfg80211_vendor_free_skb(skb);
				return;
			}

			peer_info = (struct wifi_peer_info *)
				((uint8_t *)peer_stat->peer_info +
				 (i * sizeof(struct wifi_peer_info)) +
				 (num_rate * sizeof(struct wifi_rate_stat)));
			nla_nest_end(skb, peers);
		}
		nla_nest_end(skb, peer_nest);
	}

	wlan_cfg80211_vendor_cmd_reply(skb);
}

/**
 * hdd_link_layer_process_iface_stats() - This function is called after
 * @link_info: Link info pointer in HDD adapter
 * @if_stat: Pointer to stats data
 * @num_peers: Number of peers
 *
 * Receiving Link Layer Interface statistics from FW.This function converts
 * the firmware data to the NL data and sends the same to the kernel/upper
 * layers.
 *
 * Return: None
 */
static void
hdd_link_layer_process_iface_stats(struct wlan_hdd_link_info *link_info,
				   struct wifi_interface_stats *if_stat,
				   u32 num_peers)
{
	struct sk_buff *skb;
	struct hdd_context *hdd_ctx = WLAN_HDD_GET_CTX(link_info->adapter);

	if (wlan_hdd_is_mlo_connection(link_info)) {
		hdd_cache_ll_iface_stats(hdd_ctx, if_stat);
		return;
	}

	/*
	 * There is no need for wlan_hdd_validate_context here. This is a NB
	 * operation that will come with DSC synchronization. This ensures that
	 * no driver transition will take place as long as this operation is
	 * not complete. Thus the need to check validity of hdd_context is not
	 * required.
	 */

	/*
	 * Allocate a size of 4096 for the interface stats comprising
	 * sizeof (struct wifi_interface_stats *).The size of 4096 is considered
	 * assuming that all these fit with in the limit.Please take
	 * a call on the limit based on the data requirements on
	 * interface statistics.
	 */
	skb = wlan_cfg80211_vendor_cmd_alloc_reply_skb(hdd_ctx->wiphy,
						       LL_STATS_EVENT_BUF_SIZE);

	if (!skb) {
		hdd_err("wlan_cfg80211_vendor_cmd_alloc_reply_skb failed");
		return;
	}

	hdd_debug("WMI_LINK_STATS_IFACE Data");

	if (!hdd_get_interface_info(link_info, &if_stat->info)) {
		hdd_err("hdd_get_interface_info get fail");
		wlan_cfg80211_vendor_free_skb(skb);
		return;
	}

	if (!put_wifi_iface_stats(if_stat, num_peers, skb)) {
		hdd_err("put_wifi_iface_stats fail");
		wlan_cfg80211_vendor_free_skb(skb);
		return;
	}

	wlan_cfg80211_vendor_cmd_reply(skb);
}

/**
 * put_channel_stats_chload - put chload of channel stats
 * @vendor_event: vendor event
 * @channel_stats: Pointer to channel stats
 *
 * Return: bool
 */
static bool put_channel_stats_chload(struct sk_buff *vendor_event,
				     struct wifi_channel_stats *channel_stats)
{
	uint64_t txrx_time;
	uint32_t chload;

	if (!channel_stats->on_time)
		return true;

	txrx_time = (channel_stats->tx_time + channel_stats->rx_time) * 100;
	chload = qdf_do_div(txrx_time, channel_stats->on_time);

	if (nla_put_u8(vendor_event,
		       QCA_WLAN_VENDOR_ATTR_LL_STATS_CHANNEL_LOAD_PERCENTAGE,
		       chload))
		return false;

	return true;
}

/**
 * hdd_llstats_radio_fill_channels() - radio stats fill channels
 * @adapter: Pointer to device adapter
 * @radiostat: Pointer to stats data
 * @vendor_event: vendor event
 *
 * Return: 0 on success; errno on failure
 */
static int hdd_llstats_radio_fill_channels(struct hdd_adapter *adapter,
					   struct wifi_radio_stats *radiostat,
					   struct sk_buff *vendor_event)
{
	struct wifi_channel_stats *channel_stats;
	struct nlattr *chlist;
	struct nlattr *chinfo;
	int i;

	chlist = nla_nest_start(vendor_event,
				QCA_WLAN_VENDOR_ATTR_LL_STATS_CH_INFO);
	if (!chlist) {
		hdd_err("nla_nest_start failed, %u", radiostat->num_channels);
		return -EINVAL;
	}

	for (i = 0; i < radiostat->num_channels; i++) {
		channel_stats = (struct wifi_channel_stats *) ((uint8_t *)
				     radiostat->channels +
				     (i * sizeof(struct wifi_channel_stats)));

		chinfo = nla_nest_start(vendor_event, i);
		if (!chinfo) {
			hdd_err("nla_nest_start failed, chan number %u",
				radiostat->num_channels);
			return -EINVAL;
		}

		if (nla_put_u32(vendor_event,
				QCA_WLAN_VENDOR_ATTR_LL_STATS_CHANNEL_INFO_WIDTH,
				channel_stats->channel.width) ||
		    nla_put_u32(vendor_event,
				QCA_WLAN_VENDOR_ATTR_LL_STATS_CHANNEL_INFO_CENTER_FREQ,
				channel_stats->channel.center_freq) ||
		    nla_put_u32(vendor_event,
				QCA_WLAN_VENDOR_ATTR_LL_STATS_CHANNEL_INFO_CENTER_FREQ0,
				channel_stats->channel.center_freq0) ||
		    nla_put_u32(vendor_event,
				QCA_WLAN_VENDOR_ATTR_LL_STATS_CHANNEL_INFO_CENTER_FREQ1,
				channel_stats->channel.center_freq1) ||
		    nla_put_u32(vendor_event,
				QCA_WLAN_VENDOR_ATTR_LL_STATS_CHANNEL_ON_TIME,
				channel_stats->on_time) ||
		    nla_put_u32(vendor_event,
				QCA_WLAN_VENDOR_ATTR_LL_STATS_CHANNEL_CCA_BUSY_TIME,
				channel_stats->cca_busy_time)) {
			hdd_err("nla_put failed for channel info (%u, %d, %u)",
				radiostat->num_channels, i,
				channel_stats->channel.center_freq);
			return -EINVAL;
		}

		if (adapter->hdd_ctx &&
		    adapter->hdd_ctx->ll_stats_per_chan_rx_tx_time) {
			if (nla_put_u32(
				vendor_event,
				QCA_WLAN_VENDOR_ATTR_LL_STATS_CHANNEL_TX_TIME,
				channel_stats->tx_time) ||
			    nla_put_u32(
				vendor_event,
				QCA_WLAN_VENDOR_ATTR_LL_STATS_CHANNEL_RX_TIME,
				channel_stats->rx_time)) {
				hdd_err("nla_put failed for tx time (%u, %d)",
					radiostat->num_channels, i);
				return -EINVAL;
			}

			if (!put_channel_stats_chload(vendor_event,
						      channel_stats)) {
				hdd_err("nla_put failed for chload (%u, %d)",
					radiostat->num_channels, i);
				return -EINVAL;
			}
		}

		nla_nest_end(vendor_event, chinfo);
	}
	nla_nest_end(vendor_event, chlist);

	return 0;
}

/**
 * hdd_llstats_free_radio_stats() - free wifi_radio_stats member pointers
 * @radiostat: Pointer to stats data
 *
 * Return: void
 */
static void hdd_llstats_free_radio_stats(struct wifi_radio_stats *radiostat)
{
	if (radiostat->total_num_tx_power_levels &&
	    radiostat->tx_time_per_power_level) {
		qdf_mem_free(radiostat->tx_time_per_power_level);
		radiostat->tx_time_per_power_level = NULL;
	}
	if (radiostat->num_channels && radiostat->channels) {
		qdf_mem_free(radiostat->channels);
		radiostat->channels = NULL;
	}
}

/**
 * hdd_llstats_post_radio_stats() - post radio stats
 * @adapter: Pointer to device adapter
 * @more_data: More data
 * @radiostat: Pointer to stats data
 * @num_radio: Number of radios
 *
 * Return: void
 */
static void hdd_llstats_post_radio_stats(struct hdd_adapter *adapter,
					 u32 more_data,
					 struct wifi_radio_stats *radiostat,
					 u32 num_radio)
{
	struct sk_buff *vendor_event;
	struct hdd_context *hdd_ctx = WLAN_HDD_GET_CTX(adapter);
	int ret;

	/*
	 * Allocate a size of 4096 for the Radio stats comprising
	 * sizeof (struct wifi_radio_stats) + num_channels * sizeof
	 * (struct wifi_channel_stats).Each channel data is put with an
	 * NL attribute.The size of 4096 is considered assuming that
	 * number of channels shall not exceed beyond  60 with the
	 * sizeof (struct wifi_channel_stats) being 24 bytes.
	 */

	vendor_event = wlan_cfg80211_vendor_cmd_alloc_reply_skb(
					hdd_ctx->wiphy,
					LL_STATS_EVENT_BUF_SIZE);

	if (!vendor_event) {
		hdd_err("wlan_cfg80211_vendor_cmd_alloc_reply_skb failed");
		hdd_llstats_free_radio_stats(radiostat);
		goto failure;
	}

	if (nla_put_u32(vendor_event,
			QCA_WLAN_VENDOR_ATTR_LL_STATS_TYPE,
			QCA_NL80211_VENDOR_SUBCMD_LL_STATS_TYPE_RADIO) ||
	    nla_put_u32(vendor_event,
			QCA_WLAN_VENDOR_ATTR_LL_STATS_RESULTS_MORE_DATA,
			more_data) ||
	    nla_put_u32(vendor_event,
			QCA_WLAN_VENDOR_ATTR_LL_STATS_NUM_RADIOS,
			num_radio) ||
	    nla_put_u32(vendor_event,
			QCA_WLAN_VENDOR_ATTR_LL_STATS_RADIO_ID,
			radiostat->radio) ||
	    nla_put_u32(vendor_event,
			QCA_WLAN_VENDOR_ATTR_LL_STATS_RADIO_ON_TIME,
			radiostat->on_time) ||
	    nla_put_u32(vendor_event,
			QCA_WLAN_VENDOR_ATTR_LL_STATS_RADIO_TX_TIME,
			radiostat->tx_time) ||
	    nla_put_u32(vendor_event,
			QCA_WLAN_VENDOR_ATTR_LL_STATS_RADIO_RX_TIME,
			radiostat->rx_time) ||
	    nla_put_u32(vendor_event,
			QCA_WLAN_VENDOR_ATTR_LL_STATS_RADIO_ON_TIME_SCAN,
			radiostat->on_time_scan) ||
	    nla_put_u32(vendor_event,
			QCA_WLAN_VENDOR_ATTR_LL_STATS_RADIO_ON_TIME_NBD,
			radiostat->on_time_nbd) ||
	    nla_put_u32(vendor_event,
			QCA_WLAN_VENDOR_ATTR_LL_STATS_RADIO_ON_TIME_GSCAN,
			radiostat->on_time_gscan) ||
	    nla_put_u32(vendor_event,
			QCA_WLAN_VENDOR_ATTR_LL_STATS_RADIO_ON_TIME_ROAM_SCAN,
			radiostat->on_time_roam_scan) ||
	    nla_put_u32(vendor_event,
			QCA_WLAN_VENDOR_ATTR_LL_STATS_RADIO_ON_TIME_PNO_SCAN,
			radiostat->on_time_pno_scan) ||
	    nla_put_u32(vendor_event,
			QCA_WLAN_VENDOR_ATTR_LL_STATS_RADIO_ON_TIME_HS20,
			radiostat->on_time_hs20) ||
	    nla_put_u32(vendor_event,
			QCA_WLAN_VENDOR_ATTR_LL_STATS_RADIO_NUM_TX_LEVELS,
			radiostat->total_num_tx_power_levels)    ||
	    nla_put_u32(vendor_event,
			QCA_WLAN_VENDOR_ATTR_LL_STATS_RADIO_NUM_CHANNELS,
			radiostat->num_channels)) {
		hdd_err("QCA_WLAN_VENDOR_ATTR put fail");
		hdd_llstats_free_radio_stats(radiostat);

		goto failure;
	}

	if (radiostat->total_num_tx_power_levels) {
		ret =
		    nla_put(vendor_event,
			    QCA_WLAN_VENDOR_ATTR_LL_STATS_RADIO_TX_TIME_PER_LEVEL,
			    sizeof(u32) *
			    radiostat->total_num_tx_power_levels,
			    radiostat->tx_time_per_power_level);
		if (ret) {
			hdd_err("nla_put fail");
			goto failure;
		}
	}

	if (radiostat->num_channels) {
		ret = hdd_llstats_radio_fill_channels(adapter, radiostat,
						      vendor_event);
		if (ret)
			goto failure;
	}

	wlan_cfg80211_vendor_cmd_reply(vendor_event);
	hdd_llstats_free_radio_stats(radiostat);
	return;

failure:
	wlan_cfg80211_vendor_free_skb(vendor_event);
	hdd_llstats_free_radio_stats(radiostat);
}

/**
 * hdd_link_layer_process_radio_stats() - This function is called after
 * @adapter: Pointer to device adapter
 * @more_data: More data
 * @radio_stat: Pointer to stats data
 * @num_radio: Number of radios
 *
 * Receiving Link Layer Radio statistics from FW.This function converts
 * the firmware data to the NL data and sends the same to the kernel/upper
 * layers.
 *
 * Return: None
 */
static void
hdd_link_layer_process_radio_stats(struct hdd_adapter *adapter,
				   u32 more_data,
				   struct wifi_radio_stats *radio_stat,
				   u32 num_radio)
{
	int i, nr;
	struct wifi_radio_stats *radio_stat_save = radio_stat;

	/*
	 * There is no need for wlan_hdd_validate_context here. This is a NB
	 * operation that will come with DSC synchronization. This ensures that
	 * no driver transition will take place as long as this operation is
	 * not complete. Thus the need to check validity of hdd_context is not
	 * required.
	 */

	for (i = 0; i < num_radio; i++) {
		hdd_nofl_debug("LL_STATS_RADIO"
		       " radio: %u on_time: %u tx_time: %u rx_time: %u"
		       " on_time_scan: %u on_time_nbd: %u"
		       " on_time_gscan: %u on_time_roam_scan: %u"
		       " on_time_pno_scan: %u  on_time_hs20: %u"
		       " num_channels: %u total_num_tx_pwr_levels: %u"
		       " on_time_host_scan: %u, on_time_lpi_scan: %u",
		       radio_stat->radio, radio_stat->on_time,
		       radio_stat->tx_time, radio_stat->rx_time,
		       radio_stat->on_time_scan, radio_stat->on_time_nbd,
		       radio_stat->on_time_gscan,
		       radio_stat->on_time_roam_scan,
		       radio_stat->on_time_pno_scan,
		       radio_stat->on_time_hs20,
		       radio_stat->num_channels,
		       radio_stat->total_num_tx_power_levels,
		       radio_stat->on_time_host_scan,
		       radio_stat->on_time_lpi_scan);
		radio_stat++;
	}

	radio_stat = radio_stat_save;
	for (nr = 0; nr < num_radio; nr++) {
		hdd_llstats_post_radio_stats(adapter, more_data,
					     radio_stat, num_radio);
		radio_stat++;
	}

	hdd_exit();
}

static void hdd_process_ll_stats(tSirLLStatsResults *results,
				 struct osif_request *request)
{
	struct hdd_ll_stats_priv *priv = osif_request_priv(request);
	struct hdd_ll_stats *stats = NULL;
	size_t stat_size = 0;

	qdf_spin_lock(&priv->ll_stats_lock);

	if (!(priv->request_bitmap & results->paramId)) {
		qdf_spin_unlock(&priv->ll_stats_lock);
		return;
	}

	if (results->paramId & WMI_LINK_STATS_RADIO) {
		struct wifi_radio_stats *rs_results, *stat_result;
		u64 channel_size = 0, pwr_lvl_size = 0;
		int i;

		if (!results->num_radio)
			goto exit;

		stats = qdf_mem_malloc(sizeof(*stats));
		if (!stats)
			goto exit;

		stat_size = sizeof(struct wifi_radio_stats) *
			    results->num_radio;
		stats->result_param_id = WMI_LINK_STATS_RADIO;
		stat_result = qdf_mem_malloc(stat_size);
		if (!stat_result) {
			qdf_mem_free(stats);
			goto exit;
		}
		stats->result = stat_result;
		rs_results = (struct wifi_radio_stats *)results->results;
		qdf_mem_copy(stats->result, results->results, stat_size);
		for (i = 0; i < results->num_radio; i++) {
			channel_size = rs_results->num_channels *
				       sizeof(struct wifi_channel_stats);
			pwr_lvl_size = sizeof(uint32_t) *
				       rs_results->total_num_tx_power_levels;

			if (rs_results->total_num_tx_power_levels &&
			    rs_results->tx_time_per_power_level) {
				stat_result->tx_time_per_power_level =
						qdf_mem_malloc(pwr_lvl_size);
				if (!stat_result->tx_time_per_power_level) {
					while (i-- > 0) {
						stat_result--;
						qdf_mem_free(stat_result->
						    tx_time_per_power_level);
						qdf_mem_free(stat_result->
							     channels);
					}
					qdf_mem_free(stat_result);
					qdf_mem_free(stats);
					goto exit;
				}
			      qdf_mem_copy(stat_result->tx_time_per_power_level,
					   rs_results->tx_time_per_power_level,
					   pwr_lvl_size);
			}
			if (channel_size) {
				stat_result->channels =
						qdf_mem_malloc(channel_size);
				if (!stat_result->channels) {
					qdf_mem_free(stat_result->
						     tx_time_per_power_level);
					while (i-- > 0) {
						stat_result--;
						qdf_mem_free(stat_result->
						    tx_time_per_power_level);
						qdf_mem_free(stat_result->
							     channels);
					}
					qdf_mem_free(stats->result);
					qdf_mem_free(stats);
					goto exit;
				}
				qdf_mem_copy(stat_result->channels,
					     rs_results->channels,
					     channel_size);
			}
			rs_results++;
			stat_result++;
		}
		stats->stats_nradio_npeer.no_of_radios = results->num_radio;
		stats->more_data = results->moreResultToFollow;
		if (!results->moreResultToFollow)
			priv->request_bitmap &= ~stats->result_param_id;
	} else if (results->paramId & WMI_LINK_STATS_IFACE) {
		stats = qdf_mem_malloc(sizeof(*stats));
		if (!stats)
			goto exit;

		stats->result_param_id = WMI_LINK_STATS_IFACE;
		stats->stats_nradio_npeer.no_of_peers = results->num_peers;
		stats->result = qdf_mem_malloc(sizeof(struct
					       wifi_interface_stats));
		if (!stats->result) {
			qdf_mem_free(stats);
			goto exit;
		}
		qdf_mem_copy(stats->result, results->results,
			     sizeof(struct wifi_interface_stats));

		/* Firmware doesn't send peerstats event if no peers are
		 * connected. HDD should not wait for any peerstats in
		 * this case and return the status to middleware after
		 * receiving iface stats
		 */
		if (!results->num_peers)
			priv->request_bitmap &= ~(WMI_LINK_STATS_ALL_PEER);
		priv->request_bitmap &= ~stats->result_param_id;

		/* Firmware sends interface stats based on vdev_id_bitmap
		 * So, clear the mlo_vdev_id_bitmap in the host accordingly
		 */
		if (priv->is_mlo_req)
			priv->mlo_vdev_id_bitmap &= ~(1 << results->ifaceId);
	} else if (results->paramId & WMI_LINK_STATS_ALL_PEER) {
		struct wifi_peer_stat *peer_stat = (struct wifi_peer_stat *)
						   results->results;
		struct wifi_peer_info *peer_info = NULL;
		u64 num_rate = 0, peers, rates;
		int i;
		stats = qdf_mem_malloc(sizeof(*stats));
		if (!stats)
			goto exit;

		peer_info = (struct wifi_peer_info *)peer_stat->peer_info;
		for (i = 1; i <= peer_stat->num_peers; i++) {
			num_rate += peer_info->num_rate;
			peer_info = (struct wifi_peer_info *)((uint8_t *)
				    peer_info + sizeof(struct wifi_peer_info) +
				    (peer_info->num_rate *
				    sizeof(struct wifi_rate_stat)));
		}

		peers = sizeof(struct wifi_peer_info) * peer_stat->num_peers;
		rates = sizeof(struct wifi_rate_stat) * num_rate;
		stat_size = sizeof(struct wifi_peer_stat) + peers + rates;
		stats->result_param_id = WMI_LINK_STATS_ALL_PEER;

		stats->result = qdf_mem_malloc(stat_size);
		if (!stats->result) {
			qdf_mem_free(stats);
			goto exit;
		}

		qdf_mem_copy(stats->result, results->results, stat_size);
		stats->more_data = results->moreResultToFollow;
		if (!results->moreResultToFollow)
			priv->request_bitmap &= ~stats->result_param_id;
	} else {
		hdd_err("INVALID LL_STATS_NOTIFY RESPONSE");
	}
	/* send indication to caller thread */
	if (stats)
		qdf_list_insert_back(&priv->ll_stats_q, &stats->ll_stats_node);

	if (!priv->request_bitmap) {
		if (priv->is_mlo_req && priv->mlo_vdev_id_bitmap)
			goto out;
exit:
		qdf_spin_unlock(&priv->ll_stats_lock);

		/* Thread which invokes this function has allocated memory in
		 * WMA for radio stats, that memory should be freed from the
		 * same thread to avoid any race conditions between two threads
		 */
		sme_radio_tx_mem_free();
		osif_request_complete(request);
		return;
	}
out:
	qdf_spin_unlock(&priv->ll_stats_lock);
}

static void hdd_debugfs_process_ll_stats(struct wlan_hdd_link_info *link_info,
					 tSirLLStatsResults *results,
					 struct osif_request *request)
{
	struct hdd_adapter *adapter = link_info->adapter;
	struct hdd_ll_stats_priv *priv = osif_request_priv(request);

	if (results->paramId & WMI_LINK_STATS_RADIO) {
		hdd_debugfs_process_radio_stats(adapter,
						results->moreResultToFollow,
						results->results,
						results->num_radio);
		if (!results->moreResultToFollow)
			priv->request_bitmap &= ~(WMI_LINK_STATS_RADIO);
	} else if (results->paramId & WMI_LINK_STATS_IFACE) {
		hdd_debugfs_process_iface_stats(link_info, results->results,
						results->num_peers);

		/* Firmware doesn't send peerstats event if no peers are
		 * connected. HDD should not wait for any peerstats in
		 * this case and return the status to middleware after
		 * receiving iface stats
		 */

		if (!results->num_peers)
			priv->request_bitmap &= ~(WMI_LINK_STATS_ALL_PEER);

		priv->request_bitmap &= ~(WMI_LINK_STATS_IFACE);

		/* Firmware sends interface stats based on vdev_id_bitmap
		 * So, clear the mlo_vdev_id_bitmap in the host accordingly
		 */
		if (priv->is_mlo_req)
			priv->mlo_vdev_id_bitmap &= ~(1 << results->ifaceId);
	} else if (results->paramId & WMI_LINK_STATS_ALL_PEER) {
		hdd_debugfs_process_peer_stats(adapter, results->results);
		if (!results->moreResultToFollow)
			priv->request_bitmap &= ~(WMI_LINK_STATS_ALL_PEER);
	} else {
		hdd_err("INVALID LL_STATS_NOTIFY RESPONSE");
	}

	if (!priv->request_bitmap) {
		if (priv->is_mlo_req && priv->mlo_vdev_id_bitmap)
			return;
		/* Thread which invokes this function has allocated memory in
		 * WMA for radio stats, that memory should be freed from the
		 * same thread to avoid any race conditions between two threads
		 */
		sme_radio_tx_mem_free();
		osif_request_complete(request);
	}

}

static void
wlan_hdd_update_ll_stats_request_bitmap(struct hdd_context *hdd_ctx,
					struct osif_request *request,
					tSirLLStatsResults *results)
{
	struct hdd_ll_stats_priv *priv = osif_request_priv(request);
	bool is_mlo_link;

	if (!wlan_vdev_mlme_get_is_mlo_vdev(hdd_ctx->psoc, priv->vdev_id)) {
		hdd_nofl_debug("Can't update req_bitmap for non MLO case");
		return;
	}

	is_mlo_link = wlan_vdev_mlme_get_is_mlo_link(hdd_ctx->psoc,
						     results->ifaceId);
	/* In case of MLO Connection, set the request_bitmap */
	if (is_mlo_link && results->paramId == WMI_LINK_STATS_IFACE) {
		/* Set the request_bitmap for MLO link vdev iface stats */
		if (!(priv->request_bitmap & results->paramId))
			priv->request_bitmap |= results->paramId;

		hdd_nofl_debug("MLO_LL_STATS set request_bitmap = 0x%x",
			       priv->request_bitmap);
	}
}

void wlan_hdd_cfg80211_link_layer_stats_callback(hdd_handle_t hdd_handle,
						 int indication_type,
						 tSirLLStatsResults *results,
						 void *cookie)
{
	struct hdd_context *hdd_ctx = hdd_handle_to_context(hdd_handle);
	struct hdd_ll_stats_priv *priv;
	struct wlan_hdd_link_info *link_info;
	int status;
	struct osif_request *request;

	status = wlan_hdd_validate_context(hdd_ctx);
	if (status)
		return;

	switch (indication_type) {
	case SIR_HAL_LL_STATS_RESULTS_RSP:
	{
		hdd_nofl_debug("LL_STATS RESP paramID = 0x%x, ifaceId = %u, respId= %u , moreResultToFollow = %u, num radio = %u result = %pK",
			       results->paramId, results->ifaceId,
			       results->rspId, results->moreResultToFollow,
			       results->num_radio, results->results);

		request = osif_request_get(cookie);
		if (!request) {
			hdd_err("Obsolete request");
			return;
		}

		priv = osif_request_priv(request);

		/* validate response received from target */
		if (priv->request_id != results->rspId) {
			hdd_err("Request id %d response id %d request bitmap 0x%x response bitmap 0x%x",
				priv->request_id, results->rspId,
				priv->request_bitmap, results->paramId);
			osif_request_put(request);
			return;
		}

		link_info =
			hdd_get_link_info_by_vdev(hdd_ctx, results->ifaceId);
		if (!link_info) {
			hdd_debug_rl("invalid vdev_id %d sent by FW",
				     results->ifaceId);
			/* for peer stats FW doesn't update the vdev_id info*/
			link_info = hdd_get_link_info_by_vdev(hdd_ctx,
							      priv->vdev_id);
			if (!link_info) {
				hdd_err("invalid vdev %d", priv->vdev_id);
				osif_request_put(request);
				return;
			}
		}
		wlan_hdd_update_ll_stats_request_bitmap(hdd_ctx, request,
							results);
		if (results->rspId == DEBUGFS_LLSTATS_REQID) {
			hdd_debugfs_process_ll_stats(link_info,
						     results, request);
		 } else {
			hdd_process_ll_stats(results, request);
		}

		osif_request_put(request);
		break;
	}
	default:
		hdd_warn("invalid event type %d", indication_type);
		break;
	}
}

void hdd_lost_link_info_cb(hdd_handle_t hdd_handle,
			   struct sir_lost_link_info *lost_link_info)
{
	struct hdd_context *hdd_ctx = hdd_handle_to_context(hdd_handle);
	int status;
	struct wlan_hdd_link_info *link_info;
	struct hdd_station_ctx *sta_ctx;

	status = wlan_hdd_validate_context(hdd_ctx);
	if (status)
		return;

	if (!lost_link_info) {
		hdd_err("lost_link_info is NULL");
		return;
	}

	if (lost_link_info->rssi == 0) {
		hdd_debug_rl("Invalid rssi on disconnect sent by FW");
		return;
	}

	link_info = hdd_get_link_info_by_vdev(hdd_ctx, lost_link_info->vdev_id);
	if (!link_info) {
		hdd_err("invalid vdev");
		return;
	}

	sta_ctx = WLAN_HDD_GET_STATION_CTX_PTR(link_info);

	link_info->rssi_on_disconnect = lost_link_info->rssi;
	hdd_debug("rssi on disconnect %d", link_info->rssi_on_disconnect);

	sta_ctx->cache_conn_info.signal = lost_link_info->rssi;
}

const struct nla_policy qca_wlan_vendor_ll_set_policy[
			QCA_WLAN_VENDOR_ATTR_LL_STATS_SET_MAX + 1] = {
	[QCA_WLAN_VENDOR_ATTR_LL_STATS_SET_CONFIG_MPDU_SIZE_THRESHOLD]
						= { .type = NLA_U32 },
	[QCA_WLAN_VENDOR_ATTR_LL_STATS_SET_CONFIG_AGGRESSIVE_STATS_GATHERING]
						= { .type = NLA_U32 },
};

/**
 * __wlan_hdd_cfg80211_ll_stats_set() - set link layer stats
 * @wiphy: Pointer to wiphy
 * @wdev: Pointer to wdev
 * @data: Pointer to data
 * @data_len: Data length
 *
 * Return: int
 */
static int
__wlan_hdd_cfg80211_ll_stats_set(struct wiphy *wiphy,
				   struct wireless_dev *wdev,
				   const void *data,
				   int data_len)
{
	int status;
	struct nlattr *tb_vendor[QCA_WLAN_VENDOR_ATTR_LL_STATS_SET_MAX + 1];
	tSirLLStatsSetReq req;
	struct net_device *dev = wdev->netdev;
	struct hdd_adapter *adapter = WLAN_HDD_GET_PRIV_PTR(dev);
	struct hdd_context *hdd_ctx = wiphy_priv(wiphy);

	hdd_enter_dev(dev);

	if (QDF_GLOBAL_FTM_MODE == hdd_get_conparam()) {
		hdd_err("Command not allowed in FTM mode");
		return -EPERM;
	}

	status = wlan_hdd_validate_context(hdd_ctx);
	if (0 != status)
		return -EINVAL;

	if (hdd_validate_adapter(adapter))
		return -EINVAL;

	if (adapter->device_mode != QDF_STA_MODE &&
	    adapter->device_mode != QDF_SAP_MODE &&
	    adapter->device_mode != QDF_P2P_CLIENT_MODE &&
	    adapter->device_mode != QDF_P2P_GO_MODE) {
		hdd_debug("Cannot set LL_STATS for device mode %d",
			  adapter->device_mode);
		return -EINVAL;
	}

	if (wlan_cfg80211_nla_parse(tb_vendor,
				    QCA_WLAN_VENDOR_ATTR_LL_STATS_SET_MAX,
				    (struct nlattr *)data, data_len,
				    qca_wlan_vendor_ll_set_policy)) {
		hdd_err("maximum attribute not present");
		return -EINVAL;
	}

	if (!tb_vendor
	    [QCA_WLAN_VENDOR_ATTR_LL_STATS_SET_CONFIG_MPDU_SIZE_THRESHOLD]) {
		hdd_err("MPDU size Not present");
		return -EINVAL;
	}

	if (!tb_vendor
	    [QCA_WLAN_VENDOR_ATTR_LL_STATS_SET_CONFIG_AGGRESSIVE_STATS_GATHERING]) {
		hdd_err("Stats Gathering Not Present");
		return -EINVAL;
	}

	/* Shall take the request Id if the Upper layers pass. 1 For now. */
	req.reqId = 1;

	req.mpduSizeThreshold =
		nla_get_u32(tb_vendor
			    [QCA_WLAN_VENDOR_ATTR_LL_STATS_SET_CONFIG_MPDU_SIZE_THRESHOLD]);

	req.aggressiveStatisticsGathering =
		nla_get_u32(tb_vendor
			    [QCA_WLAN_VENDOR_ATTR_LL_STATS_SET_CONFIG_AGGRESSIVE_STATS_GATHERING]);

	req.staId = adapter->deflink->vdev_id;

	hdd_debug("LL_STATS_SET reqId = %d, staId = %d, mpduSizeThreshold = %d, Statistics Gathering = %d",
		req.reqId, req.staId,
		req.mpduSizeThreshold,
		req.aggressiveStatisticsGathering);

	if (QDF_STATUS_SUCCESS != sme_ll_stats_set_req(hdd_ctx->mac_handle,
						       &req)) {
		hdd_err("sme_ll_stats_set_req Failed");
		return -EINVAL;
	}

	adapter->is_link_layer_stats_set = true;
	hdd_exit();
	return 0;
}

/**
 * wlan_hdd_cfg80211_ll_stats_set() - set ll stats
 * @wiphy: Pointer to wiphy
 * @wdev: Pointer to wdev
 * @data: Pointer to data
 * @data_len: Data length
 *
 * Return: 0 if success, non-zero for failure
 */
int wlan_hdd_cfg80211_ll_stats_set(struct wiphy *wiphy,
					struct wireless_dev *wdev,
					const void *data,
					int data_len)
{
	int errno;
	struct osif_vdev_sync *vdev_sync;

	errno = osif_vdev_sync_op_start(wdev->netdev, &vdev_sync);
	if (errno)
		return errno;

	errno = __wlan_hdd_cfg80211_ll_stats_set(wiphy, wdev, data, data_len);

	osif_vdev_sync_op_stop(vdev_sync);

	return errno;
}

const struct nla_policy qca_wlan_vendor_ll_get_policy[
			QCA_WLAN_VENDOR_ATTR_LL_STATS_GET_MAX + 1] = {
	/* Unsigned 32bit value provided by the caller issuing the GET stats
	 * command. When reporting
	 * the stats results, the driver uses the same value to indicate
	 * which GET request the results
	 * correspond to.
	 */
	[QCA_WLAN_VENDOR_ATTR_LL_STATS_GET_CONFIG_REQ_ID] = {.type = NLA_U32},

	/* Unsigned 32bit value . bit mask to identify what statistics are
	 * requested for retrieval
	 */
	[QCA_WLAN_VENDOR_ATTR_LL_STATS_GET_CONFIG_REQ_MASK] = {.type = NLA_U32}
};

static void wlan_hdd_handle_ll_stats(struct wlan_hdd_link_info *link_info,
				     struct hdd_ll_stats *stats, int ret)
{
	struct hdd_adapter *adapter = link_info->adapter;

	switch (stats->result_param_id) {
	case WMI_LINK_STATS_RADIO:
	{
		struct wifi_radio_stats *radio_stat = stats->result;
		int i, num_radio = stats->stats_nradio_npeer.no_of_radios;

		if (ret == -ETIMEDOUT) {
			for (i = 0; i < num_radio; i++) {
				if (radio_stat->num_channels)
					qdf_mem_free(radio_stat->channels);
				if (radio_stat->total_num_tx_power_levels)
					qdf_mem_free(radio_stat->
						     tx_time_per_power_level);
				radio_stat++;
			}
			return;
		}
		hdd_link_layer_process_radio_stats(adapter, stats->more_data,
						   radio_stat, num_radio);
	}
		break;
	case WMI_LINK_STATS_IFACE:
		hdd_link_layer_process_iface_stats(link_info,
						   stats->result,
						   stats->stats_nradio_npeer.
						   no_of_peers);
		break;
	case WMI_LINK_STATS_ALL_PEER:
		hdd_link_layer_process_peer_stats(adapter,
						  stats->more_data,
						  stats->result);
		break;
	default:
		hdd_err("not requested event");
	}
}

static void wlan_hdd_dealloc_ll_stats(void *priv)
{
	struct hdd_ll_stats_priv *ll_stats_priv = priv;
	struct hdd_ll_stats *stats = NULL;
	QDF_STATUS status;
	qdf_list_node_t *ll_node;

	if (!ll_stats_priv)
		return;

	qdf_spin_lock(&ll_stats_priv->ll_stats_lock);
	status = qdf_list_remove_front(&ll_stats_priv->ll_stats_q, &ll_node);
	qdf_spin_unlock(&ll_stats_priv->ll_stats_lock);
	while (QDF_IS_STATUS_SUCCESS(status)) {
		stats =  qdf_container_of(ll_node, struct hdd_ll_stats,
					  ll_stats_node);

		if (stats->result_param_id == WMI_LINK_STATS_RADIO) {
			struct wifi_radio_stats *radio_stat = stats->result;
			int i;
			int num_radio = stats->stats_nradio_npeer.no_of_radios;

			for (i = 0; i < num_radio; i++) {
				if (radio_stat->num_channels)
					qdf_mem_free(radio_stat->channels);
				if (radio_stat->total_num_tx_power_levels)
					qdf_mem_free(radio_stat->
						tx_time_per_power_level);
				radio_stat++;
			}
		}

		qdf_mem_free(stats->result);
		qdf_mem_free(stats);
		qdf_spin_lock(&ll_stats_priv->ll_stats_lock);
		status = qdf_list_remove_front(&ll_stats_priv->ll_stats_q,
					       &ll_node);
		qdf_spin_unlock(&ll_stats_priv->ll_stats_lock);
	}
	qdf_list_destroy(&ll_stats_priv->ll_stats_q);
}

static QDF_STATUS
wlan_hdd_set_ll_stats_request_pending(struct hdd_adapter *adapter)
{
	if (qdf_atomic_read(&adapter->is_ll_stats_req_pending)) {
		hdd_nofl_debug("Previous ll_stats request is in progress");
		return QDF_STATUS_E_ALREADY;
	}

	qdf_atomic_set(&adapter->is_ll_stats_req_pending, 1);
	return QDF_STATUS_SUCCESS;
}

#ifdef FEATURE_CLUB_LL_STATS_AND_GET_STATION
/**
 * cache_station_stats_cb() - cache_station_stats_cb callback function
 * @ev: station stats buffer
 * @cookie: cookie that contains the address of the adapter corresponding to
 *          the request
 *
 * Return: None
 */
static void cache_station_stats_cb(struct stats_event *ev, void *cookie)
{
	struct hdd_adapter *adapter = cookie, *next_adapter = NULL;
	struct hdd_context *hdd_ctx = adapter->hdd_ctx;
	uint8_t vdev_id;
	wlan_net_dev_ref_dbgid dbgid = NET_DEV_HOLD_DISPLAY_TXRX_STATS;
	struct wlan_hdd_link_info *link_info;

	if (!ev->vdev_summary_stats || !ev->vdev_chain_rssi ||
	    !ev->peer_adv_stats || !ev->pdev_stats) {
		hdd_debug("Invalid stats");
		return;
	}

	vdev_id = ev->vdev_summary_stats->vdev_id;

	hdd_for_each_adapter_dev_held_safe(hdd_ctx, adapter, next_adapter,
					   dbgid) {
		hdd_adapter_for_each_active_link_info(adapter, link_info) {
			if (link_info->vdev_id != vdev_id)
				continue;

			copy_station_stats_to_adapter(link_info, ev);
			wlan_hdd_get_peer_rx_rate_stats(link_info);

			/* dev_put has to be done here */
			hdd_adapter_dev_put_debug(adapter, dbgid);
			if (next_adapter)
				hdd_adapter_dev_put_debug(next_adapter, dbgid);
			return;
		}
		hdd_adapter_dev_put_debug(adapter, dbgid);
	}
}

#ifdef WLAN_FEATURE_11BE_MLO
static QDF_STATUS
wlan_hdd_get_mlo_vdev_params(struct hdd_adapter *adapter,
			     struct request_info *req_info,
			     tSirLLStatsGetReq *req)
{
	struct wlan_objmgr_peer *peer;
	struct wlan_objmgr_vdev *vdev;
	struct wlan_objmgr_psoc *psoc = adapter->hdd_ctx->psoc;
	struct mlo_stats_vdev_params *info = &req_info->ml_vdev_info;
	int i;
	uint32_t bmap = 0;
	QDF_STATUS status;

	req->is_mlo_req = wlan_vdev_mlme_get_is_mlo_vdev(
					psoc, adapter->deflink->vdev_id);
	status = mlo_get_mlstats_vdev_params(psoc, info,
					     adapter->deflink->vdev_id);
	if (QDF_IS_STATUS_ERROR(status))
		return status;
	for (i = 0; i < info->ml_vdev_count; i++) {
		bmap |= (1 << info->ml_vdev_id[i]);

		vdev = wlan_objmgr_get_vdev_by_id_from_psoc(psoc,
							    info->ml_vdev_id[i],
							    WLAN_OSIF_STATS_ID);
		if (!vdev) {
			hdd_err("vdev object is NULL for vdev %d",
				info->ml_vdev_id[i]);
			return QDF_STATUS_E_INVAL;
		}

		peer = wlan_objmgr_vdev_try_get_bsspeer(vdev,
							WLAN_OSIF_STATS_ID);
		if (!peer) {
			hdd_err("peer is null");
			hdd_objmgr_put_vdev_by_user(vdev, WLAN_OSIF_STATS_ID);
			return QDF_STATUS_E_INVAL;
		}

		qdf_mem_copy(&(req_info->ml_peer_mac_addr[i][0]), peer->macaddr,
			     QDF_MAC_ADDR_SIZE);

		wlan_objmgr_peer_release_ref(peer, WLAN_OSIF_STATS_ID);
		hdd_objmgr_put_vdev_by_user(vdev, WLAN_OSIF_STATS_ID);
	}
	req->mlo_vdev_id_bitmap = bmap;
	return QDF_STATUS_SUCCESS;
}
#else
static QDF_STATUS
wlan_hdd_get_mlo_vdev_params(struct hdd_adapter *adapter,
			     struct request_info *req_info,
			     tSirLLStatsGetReq *req)
{
	return QDF_STATUS_SUCCESS;
}
#endif

static QDF_STATUS
wlan_hdd_set_station_stats_request_pending(struct wlan_hdd_link_info *link_info,
					   tSirLLStatsGetReq *req)
{
	struct wlan_objmgr_peer *peer;
	struct request_info info = {0};
	struct wlan_objmgr_vdev *vdev;
	struct hdd_adapter *adapter = link_info->adapter;
	struct wlan_objmgr_psoc *psoc = adapter->hdd_ctx->psoc;
	bool is_mlo_vdev = false;
	QDF_STATUS status;

	if (!adapter->hdd_ctx->is_get_station_clubbed_in_ll_stats_req)
		return QDF_STATUS_E_INVAL;

	vdev = hdd_objmgr_get_vdev_by_user(link_info, WLAN_OSIF_STATS_ID);
	if (!vdev)
		return QDF_STATUS_E_INVAL;

	info.cookie = adapter;
	info.u.get_station_stats_cb = cache_station_stats_cb;
	info.vdev_id = link_info->vdev_id;
	is_mlo_vdev = wlan_vdev_mlme_get_is_mlo_vdev(psoc, link_info->vdev_id);
	if (is_mlo_vdev) {
		status = wlan_hdd_get_mlo_vdev_params(adapter, &info, req);
		if (QDF_IS_STATUS_ERROR(status)) {
			hdd_err("unable to get vdev params for mlo stats");
			hdd_objmgr_put_vdev_by_user(vdev, WLAN_OSIF_STATS_ID);
			return status;
		}
	}

	info.pdev_id = wlan_objmgr_pdev_get_pdev_id(wlan_vdev_get_pdev(vdev));

	peer = wlan_objmgr_vdev_try_get_bsspeer(vdev, WLAN_OSIF_STATS_ID);
	if (!peer) {
		osif_err("peer is null");
		hdd_objmgr_put_vdev_by_user(vdev, WLAN_OSIF_STATS_ID);
		return QDF_STATUS_E_INVAL;
	}

	qdf_mem_copy(info.peer_mac_addr, peer->macaddr, QDF_MAC_ADDR_SIZE);

	wlan_objmgr_peer_release_ref(peer, WLAN_OSIF_STATS_ID);

	ucfg_mc_cp_stats_set_pending_req(psoc, TYPE_STATION_STATS, &info);

	hdd_objmgr_put_vdev_by_user(vdev, WLAN_OSIF_STATS_ID);
	return QDF_STATUS_SUCCESS;
}

static void
wlan_hdd_reset_station_stats_request_pending(struct wlan_objmgr_psoc *psoc,
					     struct hdd_adapter *adapter)
{
	QDF_STATUS status;
	struct request_info last_req = {0};
	bool pending = false;

	if (!adapter->hdd_ctx->is_get_station_clubbed_in_ll_stats_req)
		return;

	status = ucfg_mc_cp_stats_get_pending_req(psoc, TYPE_STATION_STATS,
						  &last_req);
	if (QDF_IS_STATUS_ERROR(status)) {
		hdd_err("ucfg_mc_cp_stats_get_pending_req failed");
		return;
	}

	ucfg_mc_cp_stats_reset_pending_req(psoc, TYPE_STATION_STATS,
					   &last_req, &pending);
}

static QDF_STATUS wlan_hdd_stats_request_needed(struct hdd_adapter *adapter)
{
	if (adapter->device_mode != QDF_STA_MODE)
		return QDF_STATUS_SUCCESS;

	if (!adapter->hdd_ctx->config) {
		hdd_err("Invalid hdd config");
		return QDF_STATUS_E_INVAL;
	}
	if (adapter->hdd_ctx->is_get_station_clubbed_in_ll_stats_req) {
		uint32_t stats_cached_duration;

		stats_cached_duration =
				qdf_system_ticks_to_msecs(qdf_system_ticks()) -
				adapter->sta_stats_cached_timestamp;
		if (stats_cached_duration <=
			adapter->hdd_ctx->config->sta_stats_cache_expiry_time)
			return QDF_STATUS_E_ALREADY;
	}
	return QDF_STATUS_SUCCESS;
}

#else
static inline QDF_STATUS
wlan_hdd_set_station_stats_request_pending(struct wlan_hdd_link_info *link_info,
					   tSirLLStatsGetReq *req)
{
	return QDF_STATUS_SUCCESS;
}

static void
wlan_hdd_reset_station_stats_request_pending(struct wlan_objmgr_psoc *psoc,
					     struct hdd_adapter *adapter)
{
}

static QDF_STATUS wlan_hdd_stats_request_needed(struct hdd_adapter *adapter)
{
	return QDF_STATUS_SUCCESS;
}
#endif /* FEATURE_CLUB_LL_STATS_AND_GET_STATION */

static void wlan_hdd_send_mlo_ll_stats_to_user(struct hdd_adapter *adapter)
{
	if (!wlan_hdd_is_mlo_connection(adapter->deflink))
		return;

	wlan_hdd_send_mlo_ll_iface_stats_to_user(adapter);
	wlan_hdd_send_mlo_ll_peer_stats_to_user(adapter);
}

static int wlan_hdd_send_ll_stats_req(struct wlan_hdd_link_info *link_info,
				      tSirLLStatsGetReq *req)
{
	int ret = 0;
	struct hdd_ll_stats_priv *priv;
	struct hdd_ll_stats *stats = NULL;
	struct osif_request *request;
	qdf_list_node_t *ll_node;
	QDF_STATUS status, vdev_req_status;
	struct hdd_adapter *adapter = link_info->adapter;
	struct hdd_context *hdd_ctx = WLAN_HDD_GET_CTX(adapter);
	void *cookie;
	static const struct osif_request_params params = {
		.priv_size = sizeof(*priv),
		.timeout_ms = WLAN_WAIT_TIME_LL_STATS,
		.dealloc = wlan_hdd_dealloc_ll_stats,
	};

	hdd_enter_dev(adapter->dev);

	status = wlan_hdd_set_ll_stats_request_pending(adapter);
	if (QDF_IS_STATUS_ERROR(status))
		return qdf_status_to_os_return(status);

	vdev_req_status = wlan_hdd_set_station_stats_request_pending(link_info,
								     req);
	if (QDF_IS_STATUS_ERROR(vdev_req_status))
		hdd_nofl_debug("Requesting LL_STATS only");

	/*
	 * FW can send radio stats with multiple events and for the first event
	 * host allocates memory in wma and processes the events, there is a
	 * possibility that host receives first event and gets timed out, on
	 * time out host frees the allocated memory. now if host receives
	 * remaining events it will again allocate memory and processes the
	 * stats, since this is not an allocation for new command, this will
	 * lead to out of order processing of the next event and this memory
	 * might not be freed, so free the already allocated memory from WMA
	 * before issuing any new ll stats request free memory allocated for
	 * previous command
	 */
	sme_radio_tx_mem_free();

	request = osif_request_alloc(&params);
	if (!request) {
		hdd_err("Request Allocation Failure");
		wlan_hdd_reset_station_stats_request_pending(hdd_ctx->psoc,
							     adapter);
		return -ENOMEM;
	}

	cookie = osif_request_cookie(request);

	priv = osif_request_priv(request);

	priv->request_id = req->reqId;
	priv->request_bitmap = req->paramIdMask;
	priv->vdev_id = link_info->vdev_id;
	priv->is_mlo_req = wlan_vdev_mlme_get_is_mlo_vdev(hdd_ctx->psoc,
							  link_info->vdev_id);
	if (priv->is_mlo_req)
		priv->mlo_vdev_id_bitmap = req->mlo_vdev_id_bitmap;

	qdf_spinlock_create(&priv->ll_stats_lock);
	qdf_list_create(&priv->ll_stats_q, HDD_LINK_STATS_MAX);

	status = sme_ll_stats_get_req(hdd_ctx->mac_handle, req, cookie);
	if (QDF_IS_STATUS_ERROR(status)) {
		hdd_err("sme_ll_stats_get_req Failed");
		ret = qdf_status_to_os_return(status);
		goto exit;
	}
	ret = osif_request_wait_for_response(request);
	if (ret) {
		adapter->ll_stats_failure_count++;
		hdd_err("Target response timed out request id %d request bitmap 0x%x ll_stats failure count %d",
			priv->request_id, priv->request_bitmap,
			adapter->ll_stats_failure_count);
		qdf_spin_lock(&priv->ll_stats_lock);
		priv->request_bitmap = 0;
		qdf_spin_unlock(&priv->ll_stats_lock);
		sme_radio_tx_mem_free();
		ret = -ETIMEDOUT;
	} else {
		if (QDF_IS_STATUS_SUCCESS(vdev_req_status))
			hdd_update_station_stats_cached_timestamp(adapter);

		adapter->ll_stats_failure_count = 0;
	}

	qdf_spin_lock(&priv->ll_stats_lock);
	status = qdf_list_remove_front(&priv->ll_stats_q, &ll_node);
	qdf_spin_unlock(&priv->ll_stats_lock);
	while (QDF_IS_STATUS_SUCCESS(status)) {
		stats =  qdf_container_of(ll_node, struct hdd_ll_stats,
					  ll_stats_node);
		wlan_hdd_handle_ll_stats(link_info, stats, ret);
		qdf_mem_free(stats->result);
		qdf_mem_free(stats);
		qdf_spin_lock(&priv->ll_stats_lock);
		status = qdf_list_remove_front(&priv->ll_stats_q, &ll_node);
		qdf_spin_unlock(&priv->ll_stats_lock);
	}
	qdf_list_destroy(&priv->ll_stats_q);

	if (!ret && req->reqId != DEBUGFS_LLSTATS_REQID)
		wlan_hdd_send_mlo_ll_stats_to_user(adapter);

exit:
	qdf_atomic_set(&adapter->is_ll_stats_req_pending, 0);
	wlan_hdd_reset_station_stats_request_pending(hdd_ctx->psoc, adapter);
	hdd_exit();
	osif_request_put(request);

	if (adapter->ll_stats_failure_count >=
					HDD_MAX_ALLOWED_LL_STATS_FAILURE) {
		cds_trigger_recovery(QDF_STATS_REQ_TIMEDOUT);
		adapter->ll_stats_failure_count = 0;
	}

	return ret;
}

int wlan_hdd_ll_stats_get(struct wlan_hdd_link_info *link_info,
			  uint32_t req_id, uint32_t req_mask)
{
	int errno;
	tSirLLStatsGetReq get_req;
	struct hdd_adapter *adapter = link_info->adapter;

	hdd_enter_dev(adapter->dev);

	if (QDF_GLOBAL_FTM_MODE == hdd_get_conparam()) {
		hdd_warn("Command not allowed in FTM mode");
		return -EPERM;
	}

	if (hdd_cm_is_vdev_roaming(link_info)) {
		hdd_debug("Roaming in progress, cannot process the request");
		return -EBUSY;
	}

	if (!adapter->is_link_layer_stats_set) {
		hdd_info("LL_STATs not set");
		return -EINVAL;
	}

	get_req.reqId = req_id;
	get_req.paramIdMask = req_mask;
	get_req.staId = link_info->vdev_id;

	rtnl_lock();
	errno = wlan_hdd_send_ll_stats_req(link_info, &get_req);
	rtnl_unlock();
	if (errno)
		hdd_err("Send LL stats req failed, id:%u, mask:%d, session:%d",
			req_id, req_mask, link_info->vdev_id);

	hdd_exit();

	return errno;
}

/**
 * __wlan_hdd_cfg80211_ll_stats_get() - get link layer stats
 * @wiphy: Pointer to wiphy
 * @wdev: Pointer to wdev
 * @data: Pointer to data
 * @data_len: Data length
 *
 * Return: int
 */
static int
__wlan_hdd_cfg80211_ll_stats_get(struct wiphy *wiphy,
				   struct wireless_dev *wdev,
				   const void *data,
				   int data_len)
{
	int ret;
	struct hdd_context *hdd_ctx = wiphy_priv(wiphy);
	struct nlattr *tb_vendor[QCA_WLAN_VENDOR_ATTR_LL_STATS_GET_MAX + 1];
	tSirLLStatsGetReq LinkLayerStatsGetReq;
	struct net_device *dev = wdev->netdev;
	struct hdd_adapter *adapter = WLAN_HDD_GET_PRIV_PTR(dev);
	struct wlan_hdd_link_info *link_info = adapter->deflink;

	hdd_enter_dev(dev);

	if (QDF_GLOBAL_FTM_MODE == hdd_get_conparam()) {
		hdd_err("Command not allowed in FTM mode");
		return -EPERM;
	}

	ret = wlan_hdd_validate_context(hdd_ctx);
	if (0 != ret)
		return -EINVAL;

	if (!adapter->is_link_layer_stats_set) {
		hdd_nofl_debug("is_link_layer_stats_set: %d",
			       adapter->is_link_layer_stats_set);
		return -EINVAL;
	}

	if (hdd_cm_is_vdev_roaming(link_info)) {
		hdd_debug("Roaming in progress, cannot process the request");
		return -EBUSY;
	}

	if (wlan_hdd_is_link_switch_in_progress(link_info)) {
		hdd_debug("Link Switch in progress, can't process the request");
		return -EBUSY;
	}

	if (wlan_cfg80211_nla_parse(tb_vendor,
				    QCA_WLAN_VENDOR_ATTR_LL_STATS_GET_MAX,
				    (struct nlattr *)data, data_len,
				    qca_wlan_vendor_ll_get_policy)) {
		hdd_err("max attribute not present");
		return -EINVAL;
	}

	if (!tb_vendor[QCA_WLAN_VENDOR_ATTR_LL_STATS_GET_CONFIG_REQ_ID]) {
		hdd_err("Request Id Not present");
		return -EINVAL;
	}

	if (!tb_vendor[QCA_WLAN_VENDOR_ATTR_LL_STATS_GET_CONFIG_REQ_MASK]) {
		hdd_err("Req Mask Not present");
		return -EINVAL;
	}

	LinkLayerStatsGetReq.reqId =
		nla_get_u32(tb_vendor
			    [QCA_WLAN_VENDOR_ATTR_LL_STATS_GET_CONFIG_REQ_ID]);
	LinkLayerStatsGetReq.paramIdMask =
		nla_get_u32(tb_vendor
			    [QCA_WLAN_VENDOR_ATTR_LL_STATS_GET_CONFIG_REQ_MASK]);

	LinkLayerStatsGetReq.staId = link_info->vdev_id;

	if (wlan_hdd_validate_vdev_id(link_info->vdev_id))
		return -EINVAL;

	ret = wlan_hdd_send_ll_stats_req(link_info, &LinkLayerStatsGetReq);
	if (0 != ret) {
		hdd_err("Failed to send LL stats request (id:%u)",
			LinkLayerStatsGetReq.reqId);
		return ret;
	}

	hdd_exit();
	return 0;
}

/**
 * wlan_hdd_cfg80211_ll_stats_get() - get ll stats
 * @wiphy: Pointer to wiphy
 * @wdev: Pointer to wdev
 * @data: Pointer to data
 * @data_len: Data length
 *
 * Return: 0 if success, non-zero for failure
 */
int wlan_hdd_cfg80211_ll_stats_get(struct wiphy *wiphy,
				   struct wireless_dev *wdev,
				   const void *data,
				   int data_len)
{
	struct hdd_context *hdd_ctx = wiphy_priv(wiphy);
	struct osif_vdev_sync *vdev_sync;
	int errno;

	errno = wlan_hdd_validate_context(hdd_ctx);
	if (0 != errno)
		return -EINVAL;

	errno = osif_vdev_sync_op_start(wdev->netdev, &vdev_sync);
	if (errno)
		return errno;

	errno = wlan_hdd_qmi_get_sync_resume();
	if (errno) {
		hdd_err("qmi sync resume failed: %d", errno);
		goto end;
	}

	errno = __wlan_hdd_cfg80211_ll_stats_get(wiphy, wdev, data, data_len);

	wlan_hdd_qmi_put_suspend();

end:
	osif_vdev_sync_op_stop(vdev_sync);

	return errno;
}

const struct
nla_policy
	qca_wlan_vendor_ll_clr_policy[QCA_WLAN_VENDOR_ATTR_LL_STATS_CLR_MAX + 1] = {
	[QCA_WLAN_VENDOR_ATTR_LL_STATS_CLR_CONFIG_REQ_MASK] = {.type = NLA_U32},
	[QCA_WLAN_VENDOR_ATTR_LL_STATS_CLR_CONFIG_STOP_REQ] = {.type = NLA_U8},
	[QCA_WLAN_VENDOR_ATTR_LL_STATS_CLR_CONFIG_RSP_MASK] = {.type = NLA_U32},
	[QCA_WLAN_VENDOR_ATTR_LL_STATS_CLR_CONFIG_STOP_RSP] = {.type = NLA_U8},
};

/**
 * __wlan_hdd_cfg80211_ll_stats_clear() - clear link layer stats
 * @wiphy: Pointer to wiphy
 * @wdev: Pointer to wdev
 * @data: Pointer to data
 * @data_len: Data length
 *
 * Return: int
 */
static int
__wlan_hdd_cfg80211_ll_stats_clear(struct wiphy *wiphy,
				    struct wireless_dev *wdev,
				    const void *data,
				    int data_len)
{
	struct hdd_context *hdd_ctx = wiphy_priv(wiphy);
	struct nlattr *tb_vendor[QCA_WLAN_VENDOR_ATTR_LL_STATS_CLR_MAX + 1];
	tSirLLStatsClearReq LinkLayerStatsClearReq;
	struct net_device *dev = wdev->netdev;
	struct hdd_adapter *adapter = WLAN_HDD_GET_PRIV_PTR(dev);
	u32 statsClearReqMask;
	u8 stopReq;
	int errno;
	QDF_STATUS status;
	struct sk_buff *skb;

	hdd_enter_dev(dev);

	if (QDF_GLOBAL_FTM_MODE == hdd_get_conparam()) {
		hdd_err("Command not allowed in FTM mode");
		return -EPERM;
	}

	errno = wlan_hdd_validate_context(hdd_ctx);
	if (errno)
		return -EINVAL;

	if (!adapter->is_link_layer_stats_set) {
		hdd_warn("is_link_layer_stats_set : %d",
			  adapter->is_link_layer_stats_set);
		return -EINVAL;
	}

	if (wlan_cfg80211_nla_parse(tb_vendor,
				    QCA_WLAN_VENDOR_ATTR_LL_STATS_CLR_MAX,
				    (struct nlattr *)data, data_len,
				    qca_wlan_vendor_ll_clr_policy)) {
		hdd_err("STATS_CLR_MAX is not present");
		return -EINVAL;
	}

	if (!tb_vendor[QCA_WLAN_VENDOR_ATTR_LL_STATS_CLR_CONFIG_REQ_MASK] ||
	    !tb_vendor[QCA_WLAN_VENDOR_ATTR_LL_STATS_CLR_CONFIG_STOP_REQ]) {
		hdd_err("Error in LL_STATS CLR CONFIG PARA");
		return -EINVAL;
	}

	statsClearReqMask = LinkLayerStatsClearReq.statsClearReqMask =
				    nla_get_u32(tb_vendor
						[QCA_WLAN_VENDOR_ATTR_LL_STATS_CLR_CONFIG_REQ_MASK]);

	stopReq = LinkLayerStatsClearReq.stopReq =
			  nla_get_u8(tb_vendor
				     [QCA_WLAN_VENDOR_ATTR_LL_STATS_CLR_CONFIG_STOP_REQ]);

	/*
	 * Shall take the request Id if the Upper layers pass. 1 For now.
	 */
	LinkLayerStatsClearReq.reqId = 1;

	LinkLayerStatsClearReq.staId = adapter->deflink->vdev_id;

	hdd_debug("LL_STATS_CLEAR reqId = %d, staId = %d, statsClearReqMask = 0x%X, stopReq = %d",
		LinkLayerStatsClearReq.reqId,
		LinkLayerStatsClearReq.staId,
		LinkLayerStatsClearReq.statsClearReqMask,
		LinkLayerStatsClearReq.stopReq);

	status = sme_ll_stats_clear_req(hdd_ctx->mac_handle,
					&LinkLayerStatsClearReq);
	if (QDF_IS_STATUS_ERROR(status)) {
		hdd_err("stats clear request failed, %d", status);
		return -EINVAL;
	}

	skb = wlan_cfg80211_vendor_cmd_alloc_reply_skb(wiphy,
						       2 * sizeof(u32) +
						       2 * NLMSG_HDRLEN);
	if (!skb) {
		hdd_err("skb allocation failed");
		return -ENOMEM;
	}

	if (nla_put_u32(skb,
			QCA_WLAN_VENDOR_ATTR_LL_STATS_CLR_CONFIG_RSP_MASK,
			statsClearReqMask) ||
	    nla_put_u32(skb,
			QCA_WLAN_VENDOR_ATTR_LL_STATS_CLR_CONFIG_STOP_RSP,
			stopReq)) {
		hdd_err("LL_STATS_CLR put fail");
		wlan_cfg80211_vendor_free_skb(skb);
		return -EINVAL;
	}

	/* If the ask is to stop the stats collection
	 * as part of clear (stopReq = 1), ensure
	 * that no further requests of get go to the
	 * firmware by having is_link_layer_stats_set set
	 * to 0.  However it the stopReq as part of
	 * the clear request is 0, the request to get
	 * the statistics are honoured as in this case
	 * the firmware is just asked to clear the
	 * statistics.
	 */
	if (stopReq == 1)
		adapter->is_link_layer_stats_set = false;

	hdd_exit();

	return wlan_cfg80211_vendor_cmd_reply(skb);
}

/**
 * wlan_hdd_cfg80211_ll_stats_clear() - clear ll stats
 * @wiphy: Pointer to wiphy
 * @wdev: Pointer to wdev
 * @data: Pointer to data
 * @data_len: Data length
 *
 * Return: 0 if success, non-zero for failure
 */
int wlan_hdd_cfg80211_ll_stats_clear(struct wiphy *wiphy,
					struct wireless_dev *wdev,
					const void *data,
					int data_len)
{
	int errno;
	struct osif_vdev_sync *vdev_sync;

	errno = osif_vdev_sync_op_start(wdev->netdev, &vdev_sync);
	if (errno)
		return errno;

	errno = __wlan_hdd_cfg80211_ll_stats_clear(wiphy, wdev, data, data_len);

	osif_vdev_sync_op_stop(vdev_sync);

	return errno;
}

/**
 * wlan_hdd_clear_link_layer_stats() - clear link layer stats
 * @adapter: pointer to adapter
 *
 * Wrapper function to clear link layer stats.
 * return - void
 */
void wlan_hdd_clear_link_layer_stats(struct hdd_adapter *adapter)
{
	tSirLLStatsClearReq link_layer_stats_clear_req;
	mac_handle_t mac_handle = adapter->hdd_ctx->mac_handle;

	link_layer_stats_clear_req.statsClearReqMask = WIFI_STATS_IFACE_AC |
		WIFI_STATS_IFACE_ALL_PEER | WIFI_STATS_IFACE_CONTENTION;
	link_layer_stats_clear_req.stopReq = 0;
	link_layer_stats_clear_req.reqId = 1;
	link_layer_stats_clear_req.staId = adapter->deflink->vdev_id;
	sme_ll_stats_clear_req(mac_handle, &link_layer_stats_clear_req);
}

/**
 * hdd_populate_per_peer_ps_info() - populate per peer sta's PS info
 * @wifi_peer_info: peer information
 * @vendor_event: buffer for vendor event
 *
 * Return: 0 success
 */
static inline int
hdd_populate_per_peer_ps_info(struct wifi_peer_info *wifi_peer_info,
			      struct sk_buff *vendor_event)
{
	if (!wifi_peer_info) {
		hdd_err("Invalid pointer to peer info.");
		return -EINVAL;
	}

	if (nla_put_u32(vendor_event,
			QCA_WLAN_VENDOR_ATTR_LL_STATS_EXT_PEER_PS_STATE,
			wifi_peer_info->power_saving) ||
	    nla_put(vendor_event,
		    QCA_WLAN_VENDOR_ATTR_LL_STATS_EXT_PEER_MAC_ADDRESS,
		    QDF_MAC_ADDR_SIZE, &wifi_peer_info->peer_macaddr)) {
		hdd_err("QCA_WLAN_VENDOR_ATTR put fail.");
		return -EINVAL;
	}
	return 0;
}

/**
 * hdd_populate_wifi_peer_ps_info() - populate peer sta's power state
 * @data: stats for peer STA
 * @vendor_event: buffer for vendor event
 *
 * Return: 0 success
 */
static int hdd_populate_wifi_peer_ps_info(struct wifi_peer_stat *data,
					  struct sk_buff *vendor_event)
{
	uint32_t peer_num, i;
	struct wifi_peer_info *wifi_peer_info;
	struct nlattr *peer_info, *peers;

	if (!data) {
		hdd_err("Invalid pointer to Wifi peer stat.");
		return -EINVAL;
	}

	peer_num = data->num_peers;
	if (peer_num == 0) {
		hdd_err("Peer number is zero.");
		return -EINVAL;
	}

	if (nla_put_u32(vendor_event,
			QCA_WLAN_VENDOR_ATTR_LL_STATS_EXT_PEER_NUM,
			peer_num)) {
		hdd_err("QCA_WLAN_VENDOR_ATTR put fail");
		return -EINVAL;
	}

	peer_info = nla_nest_start(vendor_event,
			       QCA_WLAN_VENDOR_ATTR_LL_STATS_EXT_PEER_PS_CHG);
	if (!peer_info) {
		hdd_err("nla_nest_start failed");
		return -EINVAL;
	}

	for (i = 0; i < peer_num; i++) {
		wifi_peer_info = &data->peer_info[i];
		peers = nla_nest_start(vendor_event, i);

		if (!peers) {
			hdd_err("nla_nest_start failed");
			return -EINVAL;
		}

		if (hdd_populate_per_peer_ps_info(wifi_peer_info, vendor_event))
			return -EINVAL;

		nla_nest_end(vendor_event, peers);
	}
	nla_nest_end(vendor_event, peer_info);

	return 0;
}

/**
 * hdd_populate_tx_failure_info() - populate TX failure info
 * @tx_fail: TX failure info
 * @skb: buffer for vendor event
 *
 * Return: 0 Success
 */
static inline int
hdd_populate_tx_failure_info(struct sir_wifi_iface_tx_fail *tx_fail,
			     struct sk_buff *skb)
{
	int status = 0;

	if (!tx_fail || !skb)
		return -EINVAL;

	if (nla_put_u32(skb, QCA_WLAN_VENDOR_ATTR_LL_STATS_EXT_TID,
			tx_fail->tid) ||
	    nla_put_u32(skb, QCA_WLAN_VENDOR_ATTR_LL_STATS_EXT_NUM_MSDU,
			tx_fail->msdu_num) ||
	    nla_put_u32(skb, QCA_WLAN_VENDOR_ATTR_LL_STATS_EXT_TX_STATUS,
			tx_fail->status)) {
		hdd_err("QCA_WLAN_VENDOR_ATTR put fail");
		status = -EINVAL;
	}

	return status;
}

/**
 * hdd_populate_wifi_channel_cca_info() - put channel cca info to vendor event
 * @cca: cca info array for all channels
 * @vendor_event: vendor event buffer
 *
 * Return: 0 Success, EINVAL failure
 */
static int
hdd_populate_wifi_channel_cca_info(struct sir_wifi_chan_cca_stats *cca,
				   struct sk_buff *vendor_event)
{
	/* There might be no CCA info for a channel */
	if (!cca)
		return 0;

	if (nla_put_u32(vendor_event,
			QCA_WLAN_VENDOR_ATTR_LL_STATS_EXT_IDLE_TIME,
			cca->idle_time) ||
	    nla_put_u32(vendor_event,
			QCA_WLAN_VENDOR_ATTR_LL_STATS_EXT_TX_TIME,
			cca->tx_time) ||
	    nla_put_u32(vendor_event,
			QCA_WLAN_VENDOR_ATTR_LL_STATS_EXT_IN_BSS_TIME,
			cca->rx_in_bss_time) ||
	    nla_put_u32(vendor_event,
			QCA_WLAN_VENDOR_ATTR_LL_STATS_EXT_OUT_BSS_TIME,
			cca->rx_out_bss_time) ||
	    nla_put_u32(vendor_event,
			QCA_WLAN_VENDOR_ATTR_LL_STATS_EXT_RX_BUSY,
			cca->rx_busy_time) ||
	    nla_put_u32(vendor_event,
			QCA_WLAN_VENDOR_ATTR_LL_STATS_EXT_RX_BAD,
			cca->rx_in_bad_cond_time) ||
	    nla_put_u32(vendor_event,
			QCA_WLAN_VENDOR_ATTR_LL_STATS_EXT_TX_BAD,
			cca->tx_in_bad_cond_time) ||
	    nla_put_u32(vendor_event,
			QCA_WLAN_VENDOR_ATTR_LL_STATS_EXT_NO_AVAIL,
			cca->wlan_not_avail_time) ||
	    nla_put_u32(vendor_event,
			QCA_WLAN_VENDOR_ATTR_LL_STATS_EXT_IFACE_ID,
			cca->vdev_id)) {
		hdd_err("QCA_WLAN_VENDOR_ATTR put fail");
		return -EINVAL;
	}
	return 0;
}

/**
 * hdd_populate_wifi_signal_info - put chain signal info
 * @peer_signal: RF chain signal info
 * @skb: vendor event buffer
 *
 * Return: 0 Success, EINVAL failure
 */
static int
hdd_populate_wifi_signal_info(struct sir_wifi_peer_signal_stats *peer_signal,
			      struct sk_buff *skb)
{
	uint32_t i, chain_count;
	struct nlattr *chains, *att;

	/* There might be no signal info for a peer */
	if (!peer_signal)
		return 0;

	chain_count = peer_signal->num_chain < WIFI_MAX_CHAINS ?
		      peer_signal->num_chain : WIFI_MAX_CHAINS;
	if (nla_put_u32(skb,
			QCA_WLAN_VENDOR_ATTR_LL_STATS_EXT_PEER_ANT_NUM,
			chain_count)) {
		hdd_err("QCA_WLAN_VENDOR_ATTR put fail");
		return -EINVAL;
	}

	att = nla_nest_start(skb,
			     QCA_WLAN_VENDOR_ATTR_LL_STATS_EXT_PEER_SIGNAL);
	if (!att) {
		hdd_err("nla_nest_start failed");
		return -EINVAL;
	}

	for (i = 0; i < chain_count; i++) {
		chains = nla_nest_start(skb, i);

		if (!chains) {
			hdd_err("nla_nest_start failed");
			return -EINVAL;
		}

		hdd_debug("SNR=%d, NF=%d, Rx=%d, Tx=%d",
			  peer_signal->per_ant_snr[i],
			  peer_signal->nf[i],
			  peer_signal->per_ant_rx_mpdus[i],
			  peer_signal->per_ant_tx_mpdus[i]);
		if (nla_put_u32(skb,
				QCA_WLAN_VENDOR_ATTR_LL_STATS_EXT_ANT_SNR,
				peer_signal->per_ant_snr[i]) ||
		    nla_put_u32(skb,
				QCA_WLAN_VENDOR_ATTR_LL_STATS_EXT_ANT_NF,
				peer_signal->nf[i]) ||
		    nla_put_u32(skb,
				QCA_WLAN_VENDOR_ATTR_LL_STATS_EXT_RX_MPDU,
				peer_signal->per_ant_rx_mpdus[i]) ||
		    nla_put_u32(skb,
				QCA_WLAN_VENDOR_ATTR_LL_STATS_EXT_TX_MPDU,
				peer_signal->per_ant_tx_mpdus[i])) {
			hdd_err("QCA_WLAN_VENDOR_ATTR put fail");
			return -EINVAL;
		}
		nla_nest_end(skb, chains);
	}
	nla_nest_end(skb, att);

	return 0;
}

/**
 * hdd_populate_wifi_wmm_ac_tx_info() - put AC TX info
 * @tx_stats: tx info
 * @skb: vendor event buffer
 *
 * Return: 0 Success, EINVAL failure
 */
static int
hdd_populate_wifi_wmm_ac_tx_info(struct sir_wifi_tx *tx_stats,
				 struct sk_buff *skb)
{
	uint32_t *agg_size, *succ_mcs, *fail_mcs, *delay;

	/* There might be no TX info for a peer */
	if (!tx_stats)
		return 0;

	agg_size = tx_stats->mpdu_aggr_size;
	succ_mcs = tx_stats->success_mcs;
	fail_mcs = tx_stats->fail_mcs;
	delay = tx_stats->delay;

	if (nla_put_u32(skb, QCA_WLAN_VENDOR_ATTR_LL_STATS_EXT_TX_MSDU,
			tx_stats->msdus) ||
	    nla_put_u32(skb, QCA_WLAN_VENDOR_ATTR_LL_STATS_EXT_TX_MPDU,
			tx_stats->mpdus) ||
	    nla_put_u32(skb, QCA_WLAN_VENDOR_ATTR_LL_STATS_EXT_TX_PPDU,
			tx_stats->ppdus) ||
	    nla_put_u32(skb,
			QCA_WLAN_VENDOR_ATTR_LL_STATS_EXT_TX_BYTES,
			tx_stats->bytes) ||
	    nla_put_u32(skb, QCA_WLAN_VENDOR_ATTR_LL_STATS_EXT_TX_DROP,
			tx_stats->drops) ||
	    nla_put_u32(skb,
			QCA_WLAN_VENDOR_ATTR_LL_STATS_EXT_TX_DROP_BYTES,
			tx_stats->drop_bytes) ||
	    nla_put_u32(skb, QCA_WLAN_VENDOR_ATTR_LL_STATS_EXT_TX_RETRY,
			tx_stats->retries) ||
	    nla_put_u32(skb, QCA_WLAN_VENDOR_ATTR_LL_STATS_EXT_TX_NO_ACK,
			tx_stats->failed) ||
	    nla_put_u32(skb, QCA_WLAN_VENDOR_ATTR_LL_STATS_EXT_TX_AGGR_NUM,
			tx_stats->aggr_len) ||
	    nla_put_u32(skb,
			QCA_WLAN_VENDOR_ATTR_LL_STATS_EXT_TX_SUCC_MCS_NUM,
			tx_stats->success_mcs_len) ||
	    nla_put_u32(skb,
			QCA_WLAN_VENDOR_ATTR_LL_STATS_EXT_TX_FAIL_MCS_NUM,
			tx_stats->fail_mcs_len) ||
	    nla_put_u32(skb,
			QCA_WLAN_VENDOR_ATTR_LL_STATS_EXT_DELAY_ARRAY_SIZE,
			tx_stats->delay_len))
		goto put_attr_fail;

	if (agg_size) {
		if (nla_put(skb,
			    QCA_WLAN_VENDOR_ATTR_LL_STATS_EXT_TX_AGGR,
			    tx_stats->aggr_len, agg_size))
			goto put_attr_fail;
	}

	if (succ_mcs) {
		if (nla_put(skb,
			    QCA_WLAN_VENDOR_ATTR_LL_STATS_EXT_TX_SUCC_MCS,
			    tx_stats->success_mcs_len, succ_mcs))
			goto put_attr_fail;
	}

	if (fail_mcs) {
		if (nla_put(skb,
			    QCA_WLAN_VENDOR_ATTR_LL_STATS_EXT_TX_FAIL_MCS,
			    tx_stats->fail_mcs_len, fail_mcs))
			goto put_attr_fail;
	}

	if (delay) {
		if (nla_put(skb,
			    QCA_WLAN_VENDOR_ATTR_LL_STATS_EXT_TX_DELAY,
			    tx_stats->delay_len, delay))
			goto put_attr_fail;
	}
	return 0;

put_attr_fail:
	hdd_err("QCA_WLAN_VENDOR_ATTR put fail");
	return -EINVAL;
}

/**
 * hdd_populate_wifi_wmm_ac_rx_info() - put AC RX info
 * @rx_stats: rx info
 * @skb: vendor event buffer
 *
 * Return: 0 Success, EINVAL failure
 */
static int
hdd_populate_wifi_wmm_ac_rx_info(struct sir_wifi_rx *rx_stats,
				 struct sk_buff *skb)
{
	uint32_t *mcs, *aggr;

	/* There might be no RX info for a peer */
	if (!rx_stats)
		return 0;

	aggr = rx_stats->mpdu_aggr;
	mcs = rx_stats->mcs;

	if (nla_put_u32(skb, QCA_WLAN_VENDOR_ATTR_LL_STATS_EXT_RX_MPDU,
			rx_stats->mpdus) ||
	    nla_put_u32(skb,
			QCA_WLAN_VENDOR_ATTR_LL_STATS_EXT_RX_MPDU_BYTES,
			rx_stats->bytes) ||
	    nla_put_u32(skb, QCA_WLAN_VENDOR_ATTR_LL_STATS_EXT_RX_PPDU,
			rx_stats->ppdus) ||
	    nla_put_u32(skb,
			QCA_WLAN_VENDOR_ATTR_LL_STATS_EXT_RX_PPDU_BYTES,
			rx_stats->ppdu_bytes) ||
	    nla_put_u32(skb, QCA_WLAN_VENDOR_ATTR_LL_STATS_EXT_RX_MPDU_LOST,
			rx_stats->mpdu_lost) ||
	    nla_put_u32(skb,
			QCA_WLAN_VENDOR_ATTR_LL_STATS_EXT_RX_MPDU_RETRY,
			rx_stats->mpdu_retry) ||
	    nla_put_u32(skb,
			QCA_WLAN_VENDOR_ATTR_LL_STATS_EXT_RX_MPDU_DUP,
			rx_stats->mpdu_dup) ||
	    nla_put_u32(skb,
			QCA_WLAN_VENDOR_ATTR_LL_STATS_EXT_RX_MPDU_DISCARD,
			rx_stats->mpdu_discard) ||
	    nla_put_u32(skb,
			QCA_WLAN_VENDOR_ATTR_LL_STATS_EXT_RX_AGGR_NUM,
			rx_stats->aggr_len) ||
	    nla_put_u32(skb,
			QCA_WLAN_VENDOR_ATTR_LL_STATS_EXT_RX_MCS_NUM,
			rx_stats->mcs_len))
		goto put_attr_fail;

	if (aggr) {
		if (nla_put(skb, QCA_WLAN_VENDOR_ATTR_LL_STATS_EXT_RX_AGGR,
			    rx_stats->aggr_len, aggr))
			goto put_attr_fail;
	}

	if (mcs) {
		if (nla_put(skb, QCA_WLAN_VENDOR_ATTR_LL_STATS_EXT_RX_MCS,
			    rx_stats->mcs_len, mcs))
			goto put_attr_fail;
	}

	return 0;

put_attr_fail:
	hdd_err("QCA_WLAN_VENDOR_ATTR put fail");
	return -EINVAL;
}

/**
 * hdd_populate_wifi_wmm_ac_info() - put WMM AC info
 * @ac_stats: per AC stats
 * @skb: vendor event buffer
 *
 * Return: 0 Success, EINVAL failure
 */
static int
hdd_populate_wifi_wmm_ac_info(struct sir_wifi_ll_ext_wmm_ac_stats *ac_stats,
			      struct sk_buff *skb)
{
	struct nlattr *wmm;

	wmm = nla_nest_start(skb, ac_stats->type);
	if (!wmm)
		goto nest_start_fail;

	if (hdd_populate_wifi_wmm_ac_tx_info(ac_stats->tx_stats, skb) ||
	    hdd_populate_wifi_wmm_ac_rx_info(ac_stats->rx_stats, skb))
		goto put_attr_fail;

	nla_nest_end(skb, wmm);
	return 0;

nest_start_fail:
	hdd_err("nla_nest_start failed");
	return -EINVAL;

put_attr_fail:
	hdd_err("QCA_WLAN_VENDOR_ATTR put fail");
	return -EINVAL;
}

/**
 * hdd_populate_wifi_ll_ext_peer_info() - put per peer info
 * @peers: peer stats
 * @skb: vendor event buffer
 *
 * Return: 0 Success, EINVAL failure
 */
static int
hdd_populate_wifi_ll_ext_peer_info(struct sir_wifi_ll_ext_peer_stats *peers,
				   struct sk_buff *skb)
{
	uint32_t i;
	struct nlattr *wmm_ac;

	if (nla_put_u32(skb,
			QCA_WLAN_VENDOR_ATTR_LL_STATS_EXT_PEER_ID,
			peers->peer_id) ||
	    nla_put_u32(skb,
			QCA_WLAN_VENDOR_ATTR_LL_STATS_EXT_IFACE_ID,
			peers->vdev_id) ||
	    nla_put_u32(skb,
			QCA_WLAN_VENDOR_ATTR_LL_STATS_EXT_PEER_PS_TIMES,
			peers->sta_ps_inds) ||
	    nla_put_u32(skb,
			QCA_WLAN_VENDOR_ATTR_LL_STATS_EXT_PEER_PS_DURATION,
			peers->sta_ps_durs) ||
	    nla_put_u32(skb,
			QCA_WLAN_VENDOR_ATTR_LL_STATS_EXT_RX_PROBE_REQ,
			peers->rx_probe_reqs) ||
	    nla_put_u32(skb,
			QCA_WLAN_VENDOR_ATTR_LL_STATS_EXT_RX_MGMT,
			peers->rx_oth_mgmts) ||
	    nla_put(skb, QCA_WLAN_VENDOR_ATTR_LL_STATS_EXT_PEER_MAC_ADDRESS,
		    QDF_MAC_ADDR_SIZE, peers->mac_address) ||
	    hdd_populate_wifi_signal_info(&peers->peer_signal_stats, skb)) {
		hdd_err("put peer signal attr failed");
		return -EINVAL;
	}

	wmm_ac = nla_nest_start(skb,
				QCA_WLAN_VENDOR_ATTR_LL_STATS_EXT_TX_STATUS);
	if (!wmm_ac) {
		hdd_err("nla_nest_start failed");
		return -EINVAL;
	}

	for (i = 0; i < WLAN_MAX_AC; i++) {
		if (hdd_populate_wifi_wmm_ac_info(&peers->ac_stats[i], skb)) {
			hdd_err("put WMM AC attr failed");
			return -EINVAL;
		}
	}

	nla_nest_end(skb, wmm_ac);
	return 0;
}

/**
 * hdd_populate_wifi_ll_ext_stats() - put link layer extension stats
 * @stats: link layer stats
 * @skb: vendor event buffer
 *
 * Return: 0 Success, EINVAL failure
 */
static int
hdd_populate_wifi_ll_ext_stats(struct sir_wifi_ll_ext_stats *stats,
			       struct sk_buff *skb)
{
	uint32_t i;
	struct nlattr *peer, *peer_info, *channels, *channel_info;

	if (nla_put_u32(skb, QCA_WLAN_VENDOR_ATTR_LL_STATS_EXT_EVENT_MODE,
			stats->trigger_cond_id) ||
	    nla_put_u32(skb,
			QCA_WLAN_VENDOR_ATTR_LL_STATS_EXT_CCA_BSS_BITMAP,
			stats->cca_chgd_bitmap) ||
	    nla_put_u32(skb,
			QCA_WLAN_VENDOR_ATTR_LL_STATS_EXT_SIGNAL_BITMAP,
			stats->sig_chgd_bitmap) ||
	    nla_put_u32(skb,
			QCA_WLAN_VENDOR_ATTR_LL_STATS_EXT_TX_BITMAP,
			stats->tx_chgd_bitmap) ||
	    nla_put_u32(skb,
			QCA_WLAN_VENDOR_ATTR_LL_STATS_EXT_RX_BITMAP,
			stats->rx_chgd_bitmap) ||
	    nla_put_u32(skb,
			QCA_WLAN_VENDOR_ATTR_LL_STATS_EXT_CHANNEL_NUM,
			stats->channel_num) ||
	    nla_put_u32(skb,
			QCA_WLAN_VENDOR_ATTR_LL_STATS_EXT_PEER_NUM,
			stats->peer_num)) {
		goto put_attr_fail;
	}

	channels = nla_nest_start(skb,
				  QCA_WLAN_VENDOR_ATTR_LL_STATS_EXT_CCA_BSS);
	if (!channels) {
		hdd_err("nla_nest_start failed");
		return -EINVAL;
	}

	for (i = 0; i < stats->channel_num; i++) {
		channel_info = nla_nest_start(skb, i);
		if (!channel_info) {
			hdd_err("nla_nest_start failed");
			return -EINVAL;
		}

		if (hdd_populate_wifi_channel_cca_info(&stats->cca[i], skb))
			goto put_attr_fail;
		nla_nest_end(skb, channel_info);
	}
	nla_nest_end(skb, channels);

	peer_info = nla_nest_start(skb,
				   QCA_WLAN_VENDOR_ATTR_LL_STATS_EXT_PEER);
	if (!peer_info) {
		hdd_err("nla_nest_start failed");
		return -EINVAL;
	}

	for (i = 0; i < stats->peer_num; i++) {
		peer = nla_nest_start(skb, i);
		if (!peer) {
			hdd_err("nla_nest_start failed");
			return -EINVAL;
		}

		if (hdd_populate_wifi_ll_ext_peer_info(&stats->peer_stats[i],
						       skb))
			goto put_attr_fail;
		nla_nest_end(skb, peer);
	}

	nla_nest_end(skb, peer_info);
	return 0;

put_attr_fail:
	hdd_err("QCA_WLAN_VENDOR_ATTR put fail");
	return -EINVAL;
}

/**
 * wlan_hdd_cfg80211_link_layer_stats_ext_callback() - Callback for LL ext
 * @ctx: HDD context
 * @rsp: msg from FW
 *
 * This function is an extension of
 * wlan_hdd_cfg80211_link_layer_stats_callback. It converts
 * monitoring parameters offloaded to NL data and send the same to the
 * kernel/upper layers.
 *
 * Return: None
 */
void wlan_hdd_cfg80211_link_layer_stats_ext_callback(hdd_handle_t ctx,
						     tSirLLStatsResults *rsp)
{
	struct hdd_context *hdd_ctx;
	struct sk_buff *skb;
	uint32_t param_id, index;
	struct wlan_hdd_link_info *link_info;
	struct wifi_peer_stat *peer_stats;
	uint8_t *results;
	int status;

	hdd_enter();

	if (!rsp) {
		hdd_err("Invalid result.");
		return;
	}

	hdd_ctx = hdd_handle_to_context(ctx);
	status = wlan_hdd_validate_context(hdd_ctx);
	if (0 != status)
		return;

	link_info = hdd_get_link_info_by_vdev(hdd_ctx, rsp->ifaceId);
	if (!link_info) {
		hdd_err("vdev_id %d does not exist with host.", rsp->ifaceId);
		return;
	}

	index = QCA_NL80211_VENDOR_SUBCMD_LL_STATS_EXT_INDEX;
	skb = wlan_cfg80211_vendor_event_alloc(hdd_ctx->wiphy, NULL,
					       LL_STATS_EVENT_BUF_SIZE +
					       NLMSG_HDRLEN,
					       index, GFP_KERNEL);
	if (!skb) {
		hdd_err("wlan_cfg80211_vendor_event_alloc failed.");
		return;
	}

	results = rsp->results;
	param_id = rsp->paramId;
	hdd_info("LL_STATS RESP paramID = 0x%x, ifaceId = %u, result = %pK",
		 rsp->paramId, rsp->ifaceId, rsp->results);
	if (param_id & WMI_LL_STATS_EXT_PS_CHG) {
		peer_stats = (struct wifi_peer_stat *)results;
		status = hdd_populate_wifi_peer_ps_info(peer_stats, skb);
	} else if (param_id & WMI_LL_STATS_EXT_TX_FAIL) {
		struct sir_wifi_iface_tx_fail *tx_fail;

		tx_fail = (struct sir_wifi_iface_tx_fail *)results;
		status = hdd_populate_tx_failure_info(tx_fail, skb);
	} else if (param_id & WMI_LL_STATS_EXT_MAC_COUNTER) {
		hdd_info("MAC counters stats");
		status = hdd_populate_wifi_ll_ext_stats(
				(struct sir_wifi_ll_ext_stats *)
				rsp->results, skb);
	} else {
		hdd_info("Unknown link layer stats");
		status = -EINVAL;
	}

	if (status == 0)
		wlan_cfg80211_vendor_event(skb, GFP_KERNEL);
	else
		wlan_cfg80211_vendor_free_skb(skb);
	hdd_exit();
}

const struct nla_policy
qca_wlan_vendor_ll_ext_policy[QCA_WLAN_VENDOR_ATTR_LL_STATS_EXT_MAX + 1] = {
	[QCA_WLAN_VENDOR_ATTR_LL_STATS_CFG_PERIOD] = {
		.type = NLA_U32
	},
	[QCA_WLAN_VENDOR_ATTR_LL_STATS_CFG_THRESHOLD] = {
		.type = NLA_U32
	},
	[QCA_WLAN_VENDOR_ATTR_LL_STATS_EXT_PEER_PS_CHG] = {
		.type = NLA_U32
	},
	[QCA_WLAN_VENDOR_ATTR_LL_STATS_EXT_TID] = {
		.type = NLA_U32
	},
	[QCA_WLAN_VENDOR_ATTR_LL_STATS_EXT_NUM_MSDU] = {
		.type = NLA_U32
	},
	[QCA_WLAN_VENDOR_ATTR_LL_STATS_EXT_TX_STATUS] = {
		.type = NLA_U32
	},
	[QCA_WLAN_VENDOR_ATTR_LL_STATS_EXT_PEER_PS_STATE] = {
		.type = NLA_U32
	},
	[QCA_WLAN_VENDOR_ATTR_LL_STATS_EXT_PEER_MAC_ADDRESS] = {
		.type = NLA_U32
	},
	[QCA_WLAN_VENDOR_ATTR_LL_STATS_EXT_GLOBAL] = {
		.type = NLA_U32
	},
	[QCA_WLAN_VENDOR_ATTR_LL_STATS_EXT_EVENT_MODE] = {
		.type = NLA_U32
	},
	[QCA_WLAN_VENDOR_ATTR_LL_STATS_EXT_IFACE_ID] = {
		.type = NLA_U32
	},
	[QCA_WLAN_VENDOR_ATTR_LL_STATS_EXT_PEER_ID] = {
		.type = NLA_U32
	},
	[QCA_WLAN_VENDOR_ATTR_LL_STATS_EXT_TX_BITMAP] = {
		.type = NLA_U32
	},
	[QCA_WLAN_VENDOR_ATTR_LL_STATS_EXT_RX_BITMAP] = {
		.type = NLA_U32
	},
	[QCA_WLAN_VENDOR_ATTR_LL_STATS_EXT_CCA_BSS_BITMAP] = {
		.type = NLA_U32
	},
	[QCA_WLAN_VENDOR_ATTR_LL_STATS_EXT_SIGNAL_BITMAP] = {
		.type = NLA_U32
	},
	[QCA_WLAN_VENDOR_ATTR_LL_STATS_EXT_PEER_NUM] = {
		.type = NLA_U32
	},
	[QCA_WLAN_VENDOR_ATTR_LL_STATS_EXT_CHANNEL_NUM] = {
		.type = NLA_U32
	},
	[QCA_WLAN_VENDOR_ATTR_LL_STATS_EXT_CCA_BSS] = {
		.type = NLA_U32
	},
	[QCA_WLAN_VENDOR_ATTR_LL_STATS_EXT_PEER] = {
		.type = NLA_U32
	},
	[QCA_WLAN_VENDOR_ATTR_LL_STATS_EXT_TX_MSDU] = {
		.type = NLA_U32
	},
	[QCA_WLAN_VENDOR_ATTR_LL_STATS_EXT_TX_MPDU] = {
		.type = NLA_U32
	},
	[QCA_WLAN_VENDOR_ATTR_LL_STATS_EXT_TX_PPDU] = {
		.type = NLA_U32
	},
	[QCA_WLAN_VENDOR_ATTR_LL_STATS_EXT_TX_BYTES] = {
		.type = NLA_U32
	},
	[QCA_WLAN_VENDOR_ATTR_LL_STATS_EXT_TX_DROP] = {
		.type = NLA_U32
	},
	[QCA_WLAN_VENDOR_ATTR_LL_STATS_EXT_TX_DROP_BYTES] = {
		.type = NLA_U32
	},
	[QCA_WLAN_VENDOR_ATTR_LL_STATS_EXT_TX_RETRY] = {
		.type = NLA_U32
	},
	[QCA_WLAN_VENDOR_ATTR_LL_STATS_EXT_TX_NO_ACK] = {
		.type = NLA_U32
	},
	[QCA_WLAN_VENDOR_ATTR_LL_STATS_EXT_TX_NO_BACK] = {
		.type = NLA_U32
	},
	[QCA_WLAN_VENDOR_ATTR_LL_STATS_EXT_TX_AGGR_NUM] = {
		.type = NLA_U32
	},
	[QCA_WLAN_VENDOR_ATTR_LL_STATS_EXT_TX_SUCC_MCS_NUM] = {
		.type = NLA_U32
	},
	[QCA_WLAN_VENDOR_ATTR_LL_STATS_EXT_TX_FAIL_MCS_NUM] = {
		.type = NLA_U32
	},
	[QCA_WLAN_VENDOR_ATTR_LL_STATS_EXT_TX_AGGR] = {
		.type = NLA_U32
	},
	[QCA_WLAN_VENDOR_ATTR_LL_STATS_EXT_TX_SUCC_MCS] = {
		.type = NLA_U32
	},
	[QCA_WLAN_VENDOR_ATTR_LL_STATS_EXT_TX_FAIL_MCS] = {
		.type = NLA_U32
	},
	[QCA_WLAN_VENDOR_ATTR_LL_STATS_EXT_DELAY_ARRAY_SIZE] = {
		.type = NLA_U32
	},
	[QCA_WLAN_VENDOR_ATTR_LL_STATS_EXT_TX_DELAY] = {
		.type = NLA_U32
	},
	[QCA_WLAN_VENDOR_ATTR_LL_STATS_EXT_RX_MPDU] = {
		.type = NLA_U32
	},
	[QCA_WLAN_VENDOR_ATTR_LL_STATS_EXT_RX_MPDU_BYTES] = {
		.type = NLA_U32
	},
	[QCA_WLAN_VENDOR_ATTR_LL_STATS_EXT_RX_PPDU] = {
		.type = NLA_U32
	},
	[QCA_WLAN_VENDOR_ATTR_LL_STATS_EXT_RX_PPDU_BYTES] = {
		.type = NLA_U32
	},
	[QCA_WLAN_VENDOR_ATTR_LL_STATS_EXT_RX_MPDU_LOST] = {
		.type = NLA_U32
	},
	[QCA_WLAN_VENDOR_ATTR_LL_STATS_EXT_RX_MPDU_RETRY] = {
		.type = NLA_U32
	},
	[QCA_WLAN_VENDOR_ATTR_LL_STATS_EXT_RX_MPDU_DUP] = {
		.type = NLA_U32
	},
	[QCA_WLAN_VENDOR_ATTR_LL_STATS_EXT_RX_MPDU_DISCARD] = {
		.type = NLA_U32
	},
	[QCA_WLAN_VENDOR_ATTR_LL_STATS_EXT_RX_AGGR_NUM] = {
		.type = NLA_U32
	},
	[QCA_WLAN_VENDOR_ATTR_LL_STATS_EXT_RX_MCS_NUM] = {
		.type = NLA_U32
	},
	[QCA_WLAN_VENDOR_ATTR_LL_STATS_EXT_RX_MCS] = {
		.type = NLA_U32
	},
	[QCA_WLAN_VENDOR_ATTR_LL_STATS_EXT_RX_AGGR] = {
		.type = NLA_U32
	},
	[QCA_WLAN_VENDOR_ATTR_LL_STATS_EXT_PEER_PS_TIMES] = {
		.type = NLA_U32
	},
	[QCA_WLAN_VENDOR_ATTR_LL_STATS_EXT_PEER_PS_DURATION] = {
		.type = NLA_U32
	},
	[QCA_WLAN_VENDOR_ATTR_LL_STATS_EXT_RX_PROBE_REQ] = {
		.type = NLA_U32
	},
	[QCA_WLAN_VENDOR_ATTR_LL_STATS_EXT_RX_MGMT] = {
		.type = NLA_U32
	},
	[QCA_WLAN_VENDOR_ATTR_LL_STATS_EXT_IDLE_TIME] = {
		.type = NLA_U32
	},
	[QCA_WLAN_VENDOR_ATTR_LL_STATS_EXT_TX_TIME] = {
		.type = NLA_U32
	},
	[QCA_WLAN_VENDOR_ATTR_LL_STATS_EXT_RX_TIME] = {
		.type = NLA_U32
	},
	[QCA_WLAN_VENDOR_ATTR_LL_STATS_EXT_RX_BUSY] = {
		.type = NLA_U32
	},
	[QCA_WLAN_VENDOR_ATTR_LL_STATS_EXT_RX_BAD] = {
		.type = NLA_U32
	},
	[QCA_WLAN_VENDOR_ATTR_LL_STATS_EXT_TX_BAD] = {
		.type = NLA_U32
	},
	[QCA_WLAN_VENDOR_ATTR_LL_STATS_EXT_NO_AVAIL] = {
		.type = NLA_U32
	},
	[QCA_WLAN_VENDOR_ATTR_LL_STATS_EXT_IN_BSS_TIME] = {
		.type = NLA_U32
	},
	[QCA_WLAN_VENDOR_ATTR_LL_STATS_EXT_OUT_BSS_TIME] = {
		.type = NLA_U32
	},
	[QCA_WLAN_VENDOR_ATTR_LL_STATS_EXT_PEER_ANT_NUM] = {
		.type = NLA_U32
	},
	[QCA_WLAN_VENDOR_ATTR_LL_STATS_EXT_PEER_SIGNAL] = {
		.type = NLA_U32
	},
	[QCA_WLAN_VENDOR_ATTR_LL_STATS_EXT_ANT_SNR] = {
		.type = NLA_U32
	},
	[QCA_WLAN_VENDOR_ATTR_LL_STATS_EXT_ANT_NF] = {
		.type = NLA_U32
	},
	[QCA_WLAN_VENDOR_ATTR_LL_STATS_EXT_IFACE_RSSI_BEACON] = {
		.type = NLA_U32
	},
	[QCA_WLAN_VENDOR_ATTR_LL_STATS_EXT_IFACE_SNR_BEACON] = {
		.type = NLA_U32
	},
};

/**
 * __wlan_hdd_cfg80211_ll_stats_ext_set_param - config monitor parameters
 * @wiphy: wiphy handle
 * @wdev: wdev handle
 * @data: user layer input
 * @data_len: length of user layer input
 *
 * this function is called in ssr protected environment.
 *
 * return: 0 success, none zero for failure
 */
static int __wlan_hdd_cfg80211_ll_stats_ext_set_param(struct wiphy *wiphy,
						      struct wireless_dev *wdev,
						      const void *data,
						      int data_len)
{
	QDF_STATUS status;
	int errno;
	uint32_t period;
	struct net_device *dev = wdev->netdev;
	struct hdd_adapter *adapter = WLAN_HDD_GET_PRIV_PTR(dev);
	struct hdd_context *hdd_ctx = wiphy_priv(wiphy);
	struct sir_ll_ext_stats_threshold thresh = {0,};
	struct nlattr *tb[QCA_WLAN_VENDOR_ATTR_LL_STATS_EXT_MAX + 1];

	hdd_enter_dev(dev);

	if (QDF_GLOBAL_FTM_MODE == hdd_get_conparam()) {
		hdd_warn("command not allowed in ftm mode");
		return -EPERM;
	}

	errno = wlan_hdd_validate_context(hdd_ctx);
	if (errno)
		return -EPERM;

	if (wlan_cfg80211_nla_parse(tb, QCA_WLAN_VENDOR_ATTR_LL_STATS_EXT_MAX,
				    (struct nlattr *)data, data_len,
				    qca_wlan_vendor_ll_ext_policy)) {
		hdd_err("maximum attribute not present");
		return -EPERM;
	}

	if (tb[QCA_WLAN_VENDOR_ATTR_LL_STATS_CFG_PERIOD]) {
		period = nla_get_u32(tb[
				QCA_WLAN_VENDOR_ATTR_LL_STATS_CFG_PERIOD]);

		if (period != 0 && period < LL_STATS_MIN_PERIOD)
			period = LL_STATS_MIN_PERIOD;

		/*
		 * Only enable/disable counters.
		 * Keep the last threshold settings.
		 */
		goto set_period;
	}

	/* global thresh is not enabled */
	if (!tb[QCA_WLAN_VENDOR_ATTR_LL_STATS_CFG_THRESHOLD]) {
		thresh.global = false;
		hdd_warn("global thresh is not set");
	} else {
		thresh.global_threshold = nla_get_u32(tb[
				QCA_WLAN_VENDOR_ATTR_LL_STATS_CFG_THRESHOLD]);
		thresh.global = true;
		hdd_debug("globle thresh is %d", thresh.global_threshold);
	}

	if (!tb[QCA_WLAN_VENDOR_ATTR_LL_STATS_EXT_GLOBAL]) {
		thresh.global = false;
		hdd_warn("global thresh is not enabled");
	} else {
		thresh.global = nla_get_u32(tb[
				QCA_WLAN_VENDOR_ATTR_LL_STATS_EXT_GLOBAL]);
		hdd_debug("global is %d", thresh.global);
	}

	thresh.enable_bitmap = false;
	if (tb[QCA_WLAN_VENDOR_ATTR_LL_STATS_EXT_TX_BITMAP]) {
		thresh.tx_bitmap = nla_get_u32(tb[
				QCA_WLAN_VENDOR_ATTR_LL_STATS_EXT_TX_BITMAP]);
		thresh.enable_bitmap = true;
	}

	if (tb[QCA_WLAN_VENDOR_ATTR_LL_STATS_EXT_RX_BITMAP]) {
		thresh.rx_bitmap = nla_get_u32(tb[
				QCA_WLAN_VENDOR_ATTR_LL_STATS_EXT_RX_BITMAP]);
		thresh.enable_bitmap = true;
	}

	if (tb[QCA_WLAN_VENDOR_ATTR_LL_STATS_EXT_CCA_BSS_BITMAP]) {
		thresh.cca_bitmap = nla_get_u32(tb[
			QCA_WLAN_VENDOR_ATTR_LL_STATS_EXT_CCA_BSS_BITMAP]);
		thresh.enable_bitmap = true;
	}

	if (tb[QCA_WLAN_VENDOR_ATTR_LL_STATS_EXT_SIGNAL_BITMAP]) {
		thresh.signal_bitmap = nla_get_u32(tb[
			QCA_WLAN_VENDOR_ATTR_LL_STATS_EXT_SIGNAL_BITMAP]);
		thresh.enable_bitmap = true;
	}

	if (!thresh.global && !thresh.enable_bitmap) {
		hdd_warn("threshold will be disabled.");
		thresh.enable = false;

		/* Just disable threshold */
		goto set_thresh;
	} else {
		thresh.enable = true;
	}

	if (tb[QCA_WLAN_VENDOR_ATTR_LL_STATS_EXT_TX_MSDU]) {
		thresh.tx.msdu = nla_get_u32(tb[
				QCA_WLAN_VENDOR_ATTR_LL_STATS_EXT_TX_MSDU]);
	}

	if (tb[QCA_WLAN_VENDOR_ATTR_LL_STATS_EXT_TX_MPDU]) {
		thresh.tx.mpdu = nla_get_u32(tb[
				QCA_WLAN_VENDOR_ATTR_LL_STATS_EXT_TX_MPDU]);
	}

	if (tb[QCA_WLAN_VENDOR_ATTR_LL_STATS_EXT_TX_PPDU]) {
		thresh.tx.ppdu = nla_get_u32(tb[
				QCA_WLAN_VENDOR_ATTR_LL_STATS_EXT_TX_PPDU]);
	}

	if (tb[QCA_WLAN_VENDOR_ATTR_LL_STATS_EXT_TX_BYTES]) {
		thresh.tx.bytes = nla_get_u32(tb[
				QCA_WLAN_VENDOR_ATTR_LL_STATS_EXT_TX_BYTES]);
	}

	if (tb[QCA_WLAN_VENDOR_ATTR_LL_STATS_EXT_TX_DROP]) {
		thresh.tx.msdu_drop = nla_get_u32(
			tb[QCA_WLAN_VENDOR_ATTR_LL_STATS_EXT_TX_DROP]);
	}

	if (tb[QCA_WLAN_VENDOR_ATTR_LL_STATS_EXT_TX_DROP_BYTES]) {
		thresh.tx.byte_drop = nla_get_u32(tb[
			QCA_WLAN_VENDOR_ATTR_LL_STATS_EXT_TX_DROP_BYTES]);
	}

	if (tb[QCA_WLAN_VENDOR_ATTR_LL_STATS_EXT_TX_RETRY]) {
		thresh.tx.mpdu_retry = nla_get_u32(tb[
				QCA_WLAN_VENDOR_ATTR_LL_STATS_EXT_TX_RETRY]);
	}

	if (tb[QCA_WLAN_VENDOR_ATTR_LL_STATS_EXT_TX_NO_ACK]) {
		thresh.tx.mpdu_fail = nla_get_u32(tb[
				QCA_WLAN_VENDOR_ATTR_LL_STATS_EXT_TX_NO_ACK]);
	}

	if (tb[QCA_WLAN_VENDOR_ATTR_LL_STATS_EXT_TX_NO_BACK]) {
		thresh.tx.ppdu_fail = nla_get_u32(tb[
				QCA_WLAN_VENDOR_ATTR_LL_STATS_EXT_TX_NO_BACK]);
	}

	if (tb[QCA_WLAN_VENDOR_ATTR_LL_STATS_EXT_TX_AGGR]) {
		thresh.tx.aggregation = nla_get_u32(tb[
				  QCA_WLAN_VENDOR_ATTR_LL_STATS_EXT_TX_AGGR]);
	}

	if (tb[QCA_WLAN_VENDOR_ATTR_LL_STATS_EXT_TX_SUCC_MCS]) {
		thresh.tx.succ_mcs = nla_get_u32(tb[
				QCA_WLAN_VENDOR_ATTR_LL_STATS_EXT_TX_SUCC_MCS]);
	}

	if (tb[QCA_WLAN_VENDOR_ATTR_LL_STATS_EXT_TX_FAIL_MCS]) {
		thresh.tx.fail_mcs = nla_get_u32(tb[
				QCA_WLAN_VENDOR_ATTR_LL_STATS_EXT_TX_FAIL_MCS]);
	}

	if (tb[QCA_WLAN_VENDOR_ATTR_LL_STATS_EXT_TX_DELAY]) {
		thresh.tx.delay = nla_get_u32(tb[
				QCA_WLAN_VENDOR_ATTR_LL_STATS_EXT_TX_DELAY]);
	}

	if (tb[QCA_WLAN_VENDOR_ATTR_LL_STATS_EXT_RX_MPDU]) {
		thresh.rx.mpdu = nla_get_u32(tb[
				QCA_WLAN_VENDOR_ATTR_LL_STATS_EXT_RX_MPDU]);
	}

	if (tb[QCA_WLAN_VENDOR_ATTR_LL_STATS_EXT_RX_MPDU_BYTES]) {
		thresh.rx.bytes = nla_get_u32(tb[
			QCA_WLAN_VENDOR_ATTR_LL_STATS_EXT_RX_MPDU_BYTES]);
	}

	if (tb[QCA_WLAN_VENDOR_ATTR_LL_STATS_EXT_RX_PPDU]) {
		thresh.rx.ppdu = nla_get_u32(tb[
				QCA_WLAN_VENDOR_ATTR_LL_STATS_EXT_RX_PPDU]);
	}

	if (tb[QCA_WLAN_VENDOR_ATTR_LL_STATS_EXT_RX_PPDU_BYTES]) {
		thresh.rx.ppdu_bytes = nla_get_u32(tb[
			QCA_WLAN_VENDOR_ATTR_LL_STATS_EXT_RX_PPDU_BYTES]);
	}

	if (tb[QCA_WLAN_VENDOR_ATTR_LL_STATS_EXT_RX_MPDU_LOST]) {
		thresh.rx.mpdu_lost = nla_get_u32(tb[
			QCA_WLAN_VENDOR_ATTR_LL_STATS_EXT_RX_MPDU_LOST]);
	}

	if (tb[QCA_WLAN_VENDOR_ATTR_LL_STATS_EXT_RX_MPDU_RETRY]) {
		thresh.rx.mpdu_retry = nla_get_u32(tb[
			QCA_WLAN_VENDOR_ATTR_LL_STATS_EXT_RX_MPDU_RETRY]);
	}

	if (tb[QCA_WLAN_VENDOR_ATTR_LL_STATS_EXT_RX_MPDU_DUP]) {
		thresh.rx.mpdu_dup = nla_get_u32(tb[
			QCA_WLAN_VENDOR_ATTR_LL_STATS_EXT_RX_MPDU_DUP]);
	}

	if (tb[QCA_WLAN_VENDOR_ATTR_LL_STATS_EXT_RX_MPDU_DISCARD]) {
		thresh.rx.mpdu_discard = nla_get_u32(tb[
			QCA_WLAN_VENDOR_ATTR_LL_STATS_EXT_RX_MPDU_DISCARD]);
	}

	if (tb[QCA_WLAN_VENDOR_ATTR_LL_STATS_EXT_RX_AGGR]) {
		thresh.rx.aggregation = nla_get_u32(tb[
			QCA_WLAN_VENDOR_ATTR_LL_STATS_EXT_RX_AGGR]);
	}

	if (tb[QCA_WLAN_VENDOR_ATTR_LL_STATS_EXT_RX_MCS]) {
		thresh.rx.mcs = nla_get_u32(tb[
			QCA_WLAN_VENDOR_ATTR_LL_STATS_EXT_RX_MCS]);
	}

	if (tb[QCA_WLAN_VENDOR_ATTR_LL_STATS_EXT_PEER_PS_TIMES]) {
		thresh.rx.ps_inds = nla_get_u32(tb[
			QCA_WLAN_VENDOR_ATTR_LL_STATS_EXT_PEER_PS_TIMES]);
	}

	if (tb[QCA_WLAN_VENDOR_ATTR_LL_STATS_EXT_PEER_PS_DURATION]) {
		thresh.rx.ps_durs = nla_get_u32(tb[
			QCA_WLAN_VENDOR_ATTR_LL_STATS_EXT_PEER_PS_DURATION]);
	}

	if (tb[QCA_WLAN_VENDOR_ATTR_LL_STATS_EXT_RX_PROBE_REQ]) {
		thresh.rx.probe_reqs = nla_get_u32(tb[
			QCA_WLAN_VENDOR_ATTR_LL_STATS_EXT_RX_PROBE_REQ]);
	}

	if (tb[QCA_WLAN_VENDOR_ATTR_LL_STATS_EXT_RX_MGMT]) {
		thresh.rx.other_mgmt = nla_get_u32(tb[
			QCA_WLAN_VENDOR_ATTR_LL_STATS_EXT_RX_MGMT]);
	}

	if (tb[QCA_WLAN_VENDOR_ATTR_LL_STATS_EXT_IDLE_TIME]) {
		thresh.cca.idle_time = nla_get_u32(tb[
			QCA_WLAN_VENDOR_ATTR_LL_STATS_EXT_IDLE_TIME]);
	}

	if (tb[QCA_WLAN_VENDOR_ATTR_LL_STATS_EXT_TX_TIME]) {
		thresh.cca.tx_time = nla_get_u32(tb[
			QCA_WLAN_VENDOR_ATTR_LL_STATS_EXT_TX_TIME]);
	}

	if (tb[QCA_WLAN_VENDOR_ATTR_LL_STATS_EXT_IN_BSS_TIME]) {
		thresh.cca.rx_in_bss_time = nla_get_u32(tb[
			QCA_WLAN_VENDOR_ATTR_LL_STATS_EXT_IN_BSS_TIME]);
	}

	if (tb[QCA_WLAN_VENDOR_ATTR_LL_STATS_EXT_OUT_BSS_TIME]) {
		thresh.cca.rx_out_bss_time = nla_get_u32(tb[
			QCA_WLAN_VENDOR_ATTR_LL_STATS_EXT_OUT_BSS_TIME]);
	}

	if (tb[QCA_WLAN_VENDOR_ATTR_LL_STATS_EXT_RX_BUSY]) {
		thresh.cca.rx_busy_time = nla_get_u32(tb[
			QCA_WLAN_VENDOR_ATTR_LL_STATS_EXT_RX_BUSY]);
	}

	if (tb[QCA_WLAN_VENDOR_ATTR_LL_STATS_EXT_RX_BAD]) {
		thresh.cca.rx_in_bad_cond_time = nla_get_u32(tb[
			QCA_WLAN_VENDOR_ATTR_LL_STATS_EXT_RX_BAD]);
	}

	if (tb[QCA_WLAN_VENDOR_ATTR_LL_STATS_EXT_TX_BAD]) {
		thresh.cca.tx_in_bad_cond_time = nla_get_u32(tb[
			QCA_WLAN_VENDOR_ATTR_LL_STATS_EXT_TX_BAD]);
	}

	if (tb[QCA_WLAN_VENDOR_ATTR_LL_STATS_EXT_NO_AVAIL]) {
		thresh.cca.wlan_not_avail_time = nla_get_u32(tb[
			QCA_WLAN_VENDOR_ATTR_LL_STATS_EXT_NO_AVAIL]);
	}

	if (tb[QCA_WLAN_VENDOR_ATTR_LL_STATS_EXT_ANT_SNR]) {
		thresh.signal.snr = nla_get_u32(tb[
			QCA_WLAN_VENDOR_ATTR_LL_STATS_EXT_ANT_SNR]);
	}

	if (tb[QCA_WLAN_VENDOR_ATTR_LL_STATS_EXT_ANT_NF]) {
		thresh.signal.nf = nla_get_u32(tb[
			QCA_WLAN_VENDOR_ATTR_LL_STATS_EXT_ANT_NF]);
	}

set_thresh:
	hdd_info("send thresh settings to target");
	status = sme_ll_stats_set_thresh(hdd_ctx->mac_handle, &thresh);
	if (QDF_IS_STATUS_ERROR(status)) {
		hdd_err("sme_ll_stats_set_thresh failed.");
		return -EINVAL;
	}
	return 0;

set_period:
	hdd_info("send period to target");
	errno = wma_cli_set_command(adapter->deflink->vdev_id,
				    wmi_pdev_param_stats_observation_period,
				    period, PDEV_CMD);
	if (errno) {
		hdd_err("wma_cli_set_command set_period failed.");
		return -EINVAL;
	}
	return 0;
}

/**
 * wlan_hdd_cfg80211_ll_stats_ext_set_param - config monitor parameters
 * @wiphy: wiphy handle
 * @wdev: wdev handle
 * @data: user layer input
 * @data_len: length of user layer input
 *
 * return: 0 success, einval failure
 */
int wlan_hdd_cfg80211_ll_stats_ext_set_param(struct wiphy *wiphy,
					     struct wireless_dev *wdev,
					     const void *data,
					     int data_len)
{
	int errno;
	struct osif_vdev_sync *vdev_sync;

	errno = osif_vdev_sync_op_start(wdev->netdev, &vdev_sync);
	if (errno)
		return errno;

	errno = __wlan_hdd_cfg80211_ll_stats_ext_set_param(wiphy, wdev,
							   data, data_len);

	osif_vdev_sync_op_stop(vdev_sync);

	return errno;
}

#else
static QDF_STATUS wlan_hdd_stats_request_needed(struct hdd_adapter *adapter)
{
	return QDF_STATUS_SUCCESS;
}
#endif /* WLAN_FEATURE_LINK_LAYER_STATS */

/**
 * __wlan_hdd_cfg80211_connected_chan_stats_request() - stats request for
 * currently connected channel
 * @wiphy: Pointer to wiphy
 * @wdev: Pointer to wdev
 * @data: Pointer to data
 * @data_len: Data length
 *
 * Return: int
 */
static int
__wlan_hdd_cfg80211_connected_chan_stats_request(struct wiphy *wiphy,
						 struct wireless_dev *wdev,
						 const void *data,
						 int data_len)
{
	struct net_device *dev = wdev->netdev;
	struct hdd_adapter *adapter = WLAN_HDD_GET_PRIV_PTR(dev);
	struct hdd_context *hdd_ctx = wiphy_priv(wiphy);
	bool is_vdev_connected;
	enum QDF_OPMODE mode;
	QDF_STATUS status;

	is_vdev_connected = hdd_cm_is_vdev_connected(adapter->deflink);
	mode = adapter->device_mode;

	if (mode != QDF_STA_MODE || !is_vdev_connected) {
		hdd_debug("vdev %d: reject chan stats req, mode:%d, conn:%d",
			  adapter->deflink->vdev_id, mode, is_vdev_connected);
		return -EPERM;
	}

	status = ucfg_mlme_connected_chan_stats_request(hdd_ctx->psoc,
					adapter->deflink->vdev_id);
	return qdf_status_to_os_return(status);
}

int wlan_hdd_cfg80211_connected_chan_stats_req(struct wiphy *wiphy,
					       struct wireless_dev *wdev,
					       const void *data,
					       int data_len)
{
	int errno;
	struct osif_vdev_sync *vdev_sync;

	errno = osif_vdev_sync_op_start(wdev->netdev, &vdev_sync);
	if (errno)
		return errno;

	errno = __wlan_hdd_cfg80211_connected_chan_stats_request(wiphy, wdev,
								 data,
								 data_len);

	osif_vdev_sync_op_stop(vdev_sync);

	return errno;
}

#ifdef WLAN_FEATURE_STATS_EXT
/**
 * __wlan_hdd_cfg80211_stats_ext_request() - ext stats request
 * @wiphy: Pointer to wiphy
 * @wdev: Pointer to wdev
 * @data: Pointer to data
 * @data_len: Data length
 *
 * Return: int
 */
static int __wlan_hdd_cfg80211_stats_ext_request(struct wiphy *wiphy,
						 struct wireless_dev *wdev,
						 const void *data,
						 int data_len)
{
	tStatsExtRequestReq stats_ext_req;
	struct net_device *dev = wdev->netdev;
	struct hdd_adapter *adapter = WLAN_HDD_GET_PRIV_PTR(dev);
	int ret_val;
	QDF_STATUS status;
	struct hdd_context *hdd_ctx = wiphy_priv(wiphy);
	ol_txrx_soc_handle soc = cds_get_context(QDF_MODULE_ID_SOC);
	struct cdp_txrx_stats_req txrx_req = {0};

	hdd_enter_dev(dev);

	ret_val = wlan_hdd_validate_context(hdd_ctx);
	if (ret_val)
		return ret_val;

	if (QDF_GLOBAL_FTM_MODE == hdd_get_conparam()) {
		hdd_err("Command not allowed in FTM mode");
		return -EPERM;
	}

	/**
	 * HTT_DBG_EXT_STATS_PDEV_RX
	 */
	txrx_req.stats = 2;
	/* default value of secondary parameter is 0(mac_id) */
	txrx_req.mac_id = 0;
	status = cdp_txrx_stats_request(soc, adapter->deflink->vdev_id,
					&txrx_req);
	if (QDF_STATUS_SUCCESS != status) {
		hdd_err_rl("Failed to get hw stats: %u", status);
		ret_val = -EINVAL;
	}

	stats_ext_req.request_data_len = data_len;
	stats_ext_req.request_data = (void *)data;

	status = cdp_request_rx_hw_stats(soc, adapter->deflink->vdev_id);

	if (QDF_STATUS_SUCCESS != status) {
		hdd_err_rl("Failed to get hw stats: %u", status);
		ret_val = -EINVAL;
	}

	status = sme_stats_ext_request(adapter->deflink->vdev_id,
				       &stats_ext_req);

	if (QDF_STATUS_SUCCESS != status) {
		hdd_err_rl("Failed to get fw stats: %u", status);
		ret_val = -EINVAL;
	}

	return ret_val;
}

/**
 * wlan_hdd_cfg80211_stats_ext_request() - ext stats request
 * @wiphy: Pointer to wiphy
 * @wdev: Pointer to wdev
 * @data: Pointer to data
 * @data_len: Data length
 *
 * Return: int
 */
int wlan_hdd_cfg80211_stats_ext_request(struct wiphy *wiphy,
					struct wireless_dev *wdev,
					const void *data,
					int data_len)
{
	int errno;
	struct osif_vdev_sync *vdev_sync;

	errno = osif_vdev_sync_op_start(wdev->netdev, &vdev_sync);
	if (errno)
		return errno;

	errno = __wlan_hdd_cfg80211_stats_ext_request(wiphy, wdev,
						      data, data_len);

	osif_vdev_sync_op_stop(vdev_sync);

	return errno;
}

void wlan_hdd_cfg80211_stats_ext_callback(hdd_handle_t hdd_handle,
					  struct stats_ext_event *data)
{
	struct hdd_context *hdd_ctx = hdd_handle_to_context(hdd_handle);
	struct sk_buff *vendor_event;
	int status;
	int ret_val;
	struct wlan_hdd_link_info *link_info;
	enum qca_nl80211_vendor_subcmds_index index =
		QCA_NL80211_VENDOR_SUBCMD_STATS_EXT_INDEX;

	status = wlan_hdd_validate_context(hdd_ctx);
	if (status)
		return;

	link_info = hdd_get_link_info_by_vdev(hdd_ctx, data->vdev_id);
	if (!link_info) {
		hdd_err("vdev_id %d does not exist with host", data->vdev_id);
		return;
	}

	vendor_event = wlan_cfg80211_vendor_event_alloc(hdd_ctx->wiphy, NULL,
							data->event_data_len +
							sizeof(uint32_t) +
							NLMSG_HDRLEN +
							NLMSG_HDRLEN,
							index, GFP_KERNEL);
	if (!vendor_event) {
		hdd_err("wlan_cfg80211_vendor_event_alloc failed");
		return;
	}

	ret_val = nla_put_u32(vendor_event, QCA_WLAN_VENDOR_ATTR_IFINDEX,
			      link_info->adapter->dev->ifindex);
	if (ret_val) {
		hdd_err("QCA_WLAN_VENDOR_ATTR_IFINDEX put fail");
		wlan_cfg80211_vendor_free_skb(vendor_event);

		return;
	}

	ret_val = nla_put(vendor_event, QCA_WLAN_VENDOR_ATTR_STATS_EXT,
			  data->event_data_len, data->event_data);

	if (ret_val) {
		hdd_err("QCA_WLAN_VENDOR_ATTR_STATS_EXT put fail");
		wlan_cfg80211_vendor_free_skb(vendor_event);

		return;
	}

	wlan_cfg80211_vendor_event(vendor_event, GFP_KERNEL);

}

void
wlan_hdd_cfg80211_stats_ext2_callback(hdd_handle_t hdd_handle,
				      struct sir_sme_rx_aggr_hole_ind *pmsg)
{
	struct hdd_context *hdd_ctx = hdd_handle_to_context(hdd_handle);
	int status;
	uint32_t data_size, hole_info_size;
	struct sk_buff *vendor_event;
	enum qca_nl80211_vendor_subcmds_index index =
		QCA_NL80211_VENDOR_SUBCMD_STATS_EXT_INDEX;

	status = wlan_hdd_validate_context(hdd_ctx);
	if (0 != status)
		return;

	if (!pmsg) {
		hdd_err("msg received here is null");
		return;
	}

	hole_info_size = (pmsg->hole_cnt)*sizeof(pmsg->hole_info_array[0]);
	data_size = sizeof(struct sir_sme_rx_aggr_hole_ind) + hole_info_size;

	vendor_event = wlan_cfg80211_vendor_event_alloc(hdd_ctx->wiphy, NULL,
							data_size +
							NLMSG_HDRLEN +
							NLMSG_HDRLEN,
							index, GFP_KERNEL);
	if (!vendor_event) {
		hdd_err("vendor_event_alloc failed for STATS_EXT2");
		return;
	}

	if (nla_put_u32(vendor_event,
			QCA_WLAN_VENDOR_ATTR_RX_AGGREGATION_STATS_HOLES_NUM,
			pmsg->hole_cnt)) {
		hdd_err("%s put fail",
			"QCA_WLAN_VENDOR_ATTR_RX_AGGREGATION_STATS_HOLES_NUM");
		wlan_cfg80211_vendor_free_skb(vendor_event);
		return;
	}
	if (nla_put(vendor_event,
		    QCA_WLAN_VENDOR_ATTR_RX_AGGREGATION_STATS_HOLES_INFO,
		    hole_info_size,
		    (void *)(pmsg->hole_info_array))) {
		hdd_err("%s put fail",
			"QCA_WLAN_VENDOR_ATTR_RX_AGGREGATION_STATS_HOLES_INFO");
		wlan_cfg80211_vendor_free_skb(vendor_event);
		return;
	}

	wlan_cfg80211_vendor_event(vendor_event, GFP_KERNEL);
}

#else
void wlan_hdd_cfg80211_stats_ext_callback(hdd_handle_t hdd_handle,
					  struct stats_ext_event *data)
{
}

void
wlan_hdd_cfg80211_stats_ext2_callback(hdd_handle_t hdd_handle,
				      struct sir_sme_rx_aggr_hole_ind *pmsg)
{
}
#endif /* End of WLAN_FEATURE_STATS_EXT */

#ifdef WLAN_FEATURE_ROAM_OFFLOAD
/**
 * enum roam_event_rt_info_reset - Reset the notif param value of struct
 * roam_event_rt_info to 0
 * @ROAM_EVENT_RT_INFO_RESET: Reset the value to 0
 */
enum roam_event_rt_info_reset {
	ROAM_EVENT_RT_INFO_RESET = 0,
};

/**
 * struct roam_ap - Roamed/Failed AP info
 * @num_cand: number of candidate APs
 * @bssid:    BSSID of roamed/failed AP
 * @rssi:     RSSI of roamed/failed AP
 * @freq:     Frequency of roamed/failed AP
 */
struct roam_ap {
	uint32_t num_cand;
	struct qdf_mac_addr bssid;
	int8_t rssi;
	uint16_t freq;
};

/**
 * hdd_get_roam_rt_stats_event_len() - calculate length of skb required for
 * sending roam events stats.
 * @roam_stats: pointer to roam_stats_event structure
 * @idx:          TLV index of roam stats event
 *
 * Return: length of skb
 */
static uint32_t
hdd_get_roam_rt_stats_event_len(struct roam_stats_event *roam_stats,
				uint8_t idx)
{
	uint32_t len = 0;
	uint8_t i = 0, num_cand = 0;

	/* QCA_WLAN_VENDOR_ATTR_ROAM_EVENTS_TRIGGER_REASON  */
	if (roam_stats->trigger[idx].present)
		len += nla_total_size(sizeof(uint32_t));

	/* QCA_WLAN_VENDOR_ATTR_ROAM_EVENTS_INVOKE_FAIL_REASON */
	if (roam_stats->roam_event_param.roam_invoke_fail_reason)
		len += nla_total_size(sizeof(uint32_t));

	/* QCA_WLAN_VENDOR_ATTR_ROAM_EVENTS_ROAM_SCAN_STATE */
	if (roam_stats->roam_event_param.roam_scan_state)
		len += nla_total_size(sizeof(uint8_t));

	if (roam_stats->scan[idx].present) {
		if (roam_stats->scan[idx].num_chan &&
		    roam_stats->scan[idx].type == ROAM_STATS_SCAN_TYPE_PARTIAL)
			for (i = 0; i < roam_stats->scan[idx].num_chan;)
				i++;

		/* QCA_WLAN_VENDOR_ATTR_ROAM_EVENTS_ROAM_SCAN_FREQ_LIST */
		len += (nla_total_size(sizeof(uint32_t)) * i);

		if (roam_stats->result[idx].present &&
		    roam_stats->result[idx].fail_reason) {
			num_cand++;
		} else if (roam_stats->trigger[idx].present) {
			for (i = 0; i < roam_stats->scan[idx].num_ap; i++) {
				if (roam_stats->scan[idx].ap[i].type == 2)
					num_cand++;
			}
		}
		/* QCA_WLAN_VENDOR_ATTR_ROAM_EVENTS_CANDIDATE_INFO */
		len += NLA_HDRLEN;
		/* QCA_WLAN_VENDOR_ATTR_ROAM_EVENTS_CANDIDATE_INFO_BSSID */
		len += (nla_total_size(QDF_MAC_ADDR_SIZE) * num_cand);
		/* QCA_WLAN_VENDOR_ATTR_ROAM_EVENTS_CANDIDATE_INFO_RSSI */
		len += (nla_total_size(sizeof(int32_t)) * num_cand);
		/* QCA_WLAN_VENDOR_ATTR_ROAM_EVENTS_CANDIDATE_INFO_FREQ */
		len += (nla_total_size(sizeof(uint32_t)) * num_cand);
		/* QCA_WLAN_VENDOR_ATTR_ROAM_EVENTS_CANDIDATE_INFO_FAIL_REASON */
		len += (nla_total_size(sizeof(uint32_t)) * num_cand);
	}

	/* QCA_WLAN_VENDOR_ATTR_ROAM_EVENTS_TYPE */
	if (len)
		len += nla_total_size(sizeof(uint32_t));

	return len;
}

#define SUBCMD_ROAM_EVENTS_INDEX \
	QCA_NL80211_VENDOR_SUBCMD_ROAM_EVENTS_INDEX
#define ROAM_SCAN_FREQ_LIST \
	QCA_WLAN_VENDOR_ATTR_ROAM_EVENTS_ROAM_SCAN_FREQ_LIST
#define ROAM_INVOKE_FAIL_REASON \
	QCA_WLAN_VENDOR_ATTR_ROAM_EVENTS_INVOKE_FAIL_REASON
#define ROAM_SCAN_STATE         QCA_WLAN_VENDOR_ATTR_ROAM_EVENTS_ROAM_SCAN_STATE
#define ROAM_EVENTS_CANDIDATE   QCA_WLAN_VENDOR_ATTR_ROAM_EVENTS_CANDIDATE_INFO
#define CANDIDATE_BSSID \
	QCA_WLAN_VENDOR_ATTR_ROAM_EVENTS_CANDIDATE_INFO_BSSID
#define CANDIDATE_RSSI \
	QCA_WLAN_VENDOR_ATTR_ROAM_EVENTS_CANDIDATE_INFO_RSSI
#define CANDIDATE_FREQ \
	QCA_WLAN_VENDOR_ATTR_ROAM_EVENTS_CANDIDATE_INFO_FREQ
#define ROAM_FAIL_REASON \
	QCA_WLAN_VENDOR_ATTR_ROAM_EVENTS_CANDIDATE_INFO_FAIL_REASON

/**
 * roam_rt_stats_fill_scan_freq() - Fill the scan frequency list from the
 * roam stats event.
 * @vendor_event: pointer to sk_buff structure
 * @idx:          TLV index of roam stats event
 * @roam_stats:   pointer to roam_stats_event structure
 *
 * Return: none
 */
static void
roam_rt_stats_fill_scan_freq(struct sk_buff *vendor_event, uint8_t idx,
			     struct roam_stats_event *roam_stats)
{
	struct nlattr *nl_attr;
	uint8_t i;

	nl_attr = nla_nest_start(vendor_event, ROAM_SCAN_FREQ_LIST);
	if (!nl_attr) {
		hdd_err("nla nest start fail");
		kfree_skb(vendor_event);
		return;
	}
	if (roam_stats->scan[idx].num_chan &&
	    roam_stats->scan[idx].type == ROAM_STATS_SCAN_TYPE_PARTIAL) {
		for (i = 0; i < roam_stats->scan[idx].num_chan; i++) {
			if (nla_put_u32(vendor_event, i,
					roam_stats->scan[idx].chan_freq[i])) {
				hdd_err("failed to put freq at index %d", i);
				kfree_skb(vendor_event);
				return;
			}
		}
	}
	nla_nest_end(vendor_event, nl_attr);
}

/**
 * roam_rt_stats_fill_cand_info() - Fill the roamed/failed AP info from the
 * roam stats event.
 * @vendor_event: pointer to sk_buff structure
 * @idx:          TLV index of roam stats event
 * @roam_stats:   pointer to roam_stats_event structure
 *
 * Return: none
 */
static void
roam_rt_stats_fill_cand_info(struct sk_buff *vendor_event, uint8_t idx,
			     struct roam_stats_event *roam_stats)
{
	struct nlattr *nl_attr, *nl_array;
	struct roam_ap cand_ap = {0};
	uint8_t i, num_cand = 0;

	if (roam_stats->result[idx].present &&
	    roam_stats->result[idx].fail_reason &&
	    roam_stats->result[idx].fail_reason != ROAM_FAIL_REASON_UNKNOWN) {
		num_cand++;
		for (i = 0; i < roam_stats->scan[idx].num_ap; i++) {
			if (roam_stats->scan[idx].ap[i].type == 0 &&
			    qdf_is_macaddr_equal(&roam_stats->
						 result[idx].fail_bssid,
						 &roam_stats->
						 scan[idx].ap[i].bssid)) {
				qdf_copy_macaddr(&cand_ap.bssid,
						 &roam_stats->
						 scan[idx].ap[i].bssid);
				cand_ap.rssi = roam_stats->scan[idx].ap[i].rssi;
				cand_ap.freq = roam_stats->scan[idx].ap[i].freq;
			}
		}
	} else if (roam_stats->trigger[idx].present) {
		for (i = 0; i < roam_stats->scan[idx].num_ap; i++) {
			if (roam_stats->scan[idx].ap[i].type == 2) {
				num_cand++;
				qdf_copy_macaddr(&cand_ap.bssid,
						 &roam_stats->
						 scan[idx].ap[i].bssid);
				cand_ap.rssi = roam_stats->scan[idx].ap[i].rssi;
				cand_ap.freq = roam_stats->scan[idx].ap[i].freq;
			}
		}
	}

	nl_array = nla_nest_start(vendor_event, ROAM_EVENTS_CANDIDATE);
	if (!nl_array) {
		hdd_err("nl array nest start fail");
		kfree_skb(vendor_event);
		return;
	}
	for (i = 0; i < num_cand; i++) {
		nl_attr = nla_nest_start(vendor_event, i);
		if (!nl_attr) {
			hdd_err("nl attr nest start fail");
			kfree_skb(vendor_event);
			return;
		}
		if (nla_put(vendor_event, CANDIDATE_BSSID,
			    sizeof(cand_ap.bssid), cand_ap.bssid.bytes)) {
			hdd_err("%s put fail",
				"ROAM_EVENTS_CANDIDATE_INFO_BSSID");
			kfree_skb(vendor_event);
			return;
		}
		if (nla_put_s32(vendor_event, CANDIDATE_RSSI, cand_ap.rssi)) {
			hdd_err("%s put fail",
				"ROAM_EVENTS_CANDIDATE_INFO_RSSI");
			kfree_skb(vendor_event);
			return;
		}
		if (nla_put_u32(vendor_event, CANDIDATE_FREQ, cand_ap.freq)) {
			hdd_err("%s put fail",
				"ROAM_EVENTS_CANDIDATE_INFO_FREQ");
			kfree_skb(vendor_event);
			return;
		}
		if (roam_stats->result[idx].present &&
		    roam_stats->result[idx].fail_reason) {
			if (nla_put_u32(vendor_event, ROAM_FAIL_REASON,
					roam_stats->result[idx].fail_reason)) {
				hdd_err("%s put fail",
					"ROAM_EVENTS_CANDIDATE_FAIL_REASON");
				kfree_skb(vendor_event);
				return;
			}
		}
		nla_nest_end(vendor_event, nl_attr);
	}
	nla_nest_end(vendor_event, nl_array);
}

void
wlan_hdd_cfg80211_roam_events_callback(struct roam_stats_event *roam_stats,
				       uint8_t idx)
{
	struct hdd_context *hdd_ctx = cds_get_context(QDF_MODULE_ID_HDD);
	int status;
	uint32_t data_size, roam_event_type = 0;
	struct sk_buff *vendor_event;
	struct wlan_hdd_link_info *link_info;

	status = wlan_hdd_validate_context(hdd_ctx);
	if (status) {
		hdd_err("Invalid hdd_ctx");
		return;
	}

	if (!roam_stats) {
		hdd_err("msg received here is null");
		return;
	}

	link_info = hdd_get_link_info_by_vdev(hdd_ctx, roam_stats->vdev_id);
	if (!link_info) {
		hdd_err("vdev_id %d does not exist with host",
			roam_stats->vdev_id);
		return;
	}

	data_size = hdd_get_roam_rt_stats_event_len(roam_stats, idx);
	if (!data_size) {
		hdd_err("No data requested");
		return;
	}

	data_size += NLMSG_HDRLEN;
	vendor_event =
		wlan_cfg80211_vendor_event_alloc(hdd_ctx->wiphy,
						 &link_info->adapter->wdev,
						 data_size,
						 SUBCMD_ROAM_EVENTS_INDEX,
						 GFP_KERNEL);

	if (!vendor_event) {
		hdd_err("vendor_event_alloc failed for ROAM_EVENTS_STATS");
		return;
	}

	if (roam_stats->scan[idx].present && roam_stats->trigger[idx].present) {
		roam_rt_stats_fill_scan_freq(vendor_event, idx, roam_stats);
		roam_rt_stats_fill_cand_info(vendor_event, idx, roam_stats);
	}

	if (roam_stats->roam_event_param.roam_scan_state) {
		roam_event_type |= QCA_WLAN_VENDOR_ROAM_EVENT_ROAM_SCAN_STATE;
		if (nla_put_u8(vendor_event, ROAM_SCAN_STATE,
			       roam_stats->roam_event_param.roam_scan_state)) {
			hdd_err("%s put fail",
				"VENDOR_ATTR_ROAM_EVENTS_ROAM_SCAN_STATE");
			wlan_cfg80211_vendor_free_skb(vendor_event);
			return;
		}
		roam_stats->roam_event_param.roam_scan_state =
						ROAM_EVENT_RT_INFO_RESET;
	}
	if (roam_stats->trigger[idx].present) {
		roam_event_type |= QCA_WLAN_VENDOR_ROAM_EVENT_TRIGGER_REASON;
		if (nla_put_u32(vendor_event,
				QCA_WLAN_VENDOR_ATTR_ROAM_EVENTS_TRIGGER_REASON,
				roam_stats->trigger[idx].trigger_reason)) {
			hdd_err("%s put fail",
				"VENDOR_ATTR_ROAM_EVENTS_TRIGGER_REASON");
			wlan_cfg80211_vendor_free_skb(vendor_event);
			return;
		}
	}
	if (roam_stats->roam_event_param.roam_invoke_fail_reason) {
		roam_event_type |=
			QCA_WLAN_VENDOR_ROAM_EVENT_INVOKE_FAIL_REASON;
		if (nla_put_u32(vendor_event, ROAM_INVOKE_FAIL_REASON,
				roam_stats->
				roam_event_param.roam_invoke_fail_reason)) {
			hdd_err("%s put fail",
				"VENDOR_ATTR_ROAM_EVENTS_INVOKE_FAIL_REASON");
			wlan_cfg80211_vendor_free_skb(vendor_event);
			return;
		}
		roam_stats->roam_event_param.roam_invoke_fail_reason =
						ROAM_EVENT_RT_INFO_RESET;
	}
	if (roam_stats->result[idx].present &&
	    roam_stats->result[idx].fail_reason)
		roam_event_type |= QCA_WLAN_VENDOR_ROAM_EVENT_FAIL_REASON;

	if (nla_put_u32(vendor_event, QCA_WLAN_VENDOR_ATTR_ROAM_EVENTS_TYPE,
			roam_event_type)) {
		hdd_err("%s put fail", "QCA_WLAN_VENDOR_ATTR_ROAM_EVENTS_TYPE");
			wlan_cfg80211_vendor_free_skb(vendor_event);
		return;
	}

	wlan_cfg80211_vendor_event(vendor_event, GFP_KERNEL);
}

#undef SUBCMD_ROAM_EVENTS_INDEX
#undef ROAM_SCAN_FREQ_LIST
#undef ROAM_INVOKE_FAIL_REASON
#undef ROAM_SCAN_STATE
#undef ROAM_EVENTS_CANDIDATE
#undef CANDIDATE_BSSID
#undef CANDIDATE_RSSI
#undef CANDIDATE_FREQ
#undef ROAM_FAIL_REASON
#endif /* End of WLAN_FEATURE_ROAM_OFFLOAD */

#ifdef LINKSPEED_DEBUG_ENABLED
#define linkspeed_dbg(format, args...) pr_info(format, ## args)
#else
#define linkspeed_dbg(format, args...)
#endif /* LINKSPEED_DEBUG_ENABLED */

/**
 * wlan_hdd_fill_summary_stats() - populate station_info summary stats
 * @stats: summary stats to use as a source
 * @info: kernel station_info struct to use as a destination
 * @vdev_id: stats get from which vdev id
 *
 * Return: None
 */
static void wlan_hdd_fill_summary_stats(tCsrSummaryStatsInfo *stats,
					struct station_info *info,
					uint8_t vdev_id)
{
	int i;
	struct cds_vdev_dp_stats dp_stats;
	uint32_t orig_cnt;
	uint32_t orig_fail_cnt;

	info->rx_packets = stats->rx_frm_cnt;
	info->tx_packets = 0;
	info->tx_retries = 0;
	info->tx_failed = 0;

	for (i = 0; i < WIFI_MAX_AC; ++i) {
		info->tx_packets += stats->tx_frm_cnt[i];
		info->tx_retries += stats->multiple_retry_cnt[i];
		info->tx_failed += stats->fail_cnt[i];
	}

	if (cds_dp_get_vdev_stats(vdev_id, &dp_stats)) {
		orig_cnt = info->tx_retries;
		orig_fail_cnt = info->tx_failed;
		info->tx_retries = dp_stats.tx_retries_mpdu;
		info->tx_failed += dp_stats.tx_mpdu_success_with_retries;
		hdd_debug("vdev %d tx retries adjust from %d to %d",
			  vdev_id, orig_cnt, info->tx_retries);
		hdd_debug("tx failed adjust from %d to %d",
			  orig_fail_cnt, info->tx_failed);
	}

	info->filled |= HDD_INFO_TX_PACKETS |
			HDD_INFO_TX_RETRIES |
			HDD_INFO_TX_FAILED;
}

/**
 * wlan_hdd_get_sap_stats() - get aggregate SAP stats
 * @link_info: Link info pointer in HDD adapter
 * @info: kernel station_info struct to populate
 *
 * Fetch the vdev-level aggregate stats for the given SAP adapter. This is to
 * support "station dump" and "station get" for SAP vdevs, even though they
 * aren't technically stations.
 *
 * Return: errno
 */
static int wlan_hdd_get_sap_stats(struct wlan_hdd_link_info *link_info,
				  struct station_info *info)
{
	int ret;

	ret = wlan_hdd_get_station_stats(link_info);
	if (ret) {
		hdd_err("Failed to get SAP stats; status:%d", ret);
		return ret;
	}

	wlan_hdd_fill_summary_stats(&link_info->hdd_stats.summary_stat,
				    info, link_info->vdev_id);

	return 0;
}

/**
 * hdd_get_max_rate_legacy() - get max rate for legacy mode
 * @stainfo: stainfo pointer
 * @rssidx: rssi index
 *
 * This function will get max rate for legacy mode
 *
 * Return: max rate on success, otherwise 0
 */
static uint32_t hdd_get_max_rate_legacy(struct hdd_station_info *stainfo,
					uint8_t rssidx)
{
	uint32_t maxrate = 0;
	/*Minimum max rate, 6Mbps*/
	int maxidx = 12;
	int i;

	/* check supported rates */
	if (stainfo->max_supp_idx != 0xff &&
	    maxidx < stainfo->max_supp_idx)
		maxidx = stainfo->max_supp_idx;

	/* check extended rates */
	if (stainfo->max_ext_idx != 0xff &&
	    maxidx < stainfo->max_ext_idx)
		maxidx = stainfo->max_ext_idx;

	for (i = 0; i < QDF_ARRAY_SIZE(supported_data_rate); i++) {
		if (supported_data_rate[i].beacon_rate_index == maxidx)
			maxrate =
				supported_data_rate[i].supported_rate[rssidx];
	}

	hdd_debug("maxrate %d", maxrate);

	return maxrate;
}

/**
 * hdd_get_max_rate_ht() - get max rate for ht mode
 * @stainfo: stainfo pointer
 * @stats: fw txrx status pointer
 * @rate_flags: rate flags
 * @nss: number of streams
 * @maxrate: returned max rate buffer pointer
 * @max_mcs_idx: max mcs idx
 * @report_max: report max rate or actual rate
 *
 * This function will get max rate for ht mode
 *
 * Return: None
 */
static void hdd_get_max_rate_ht(struct hdd_station_info *stainfo,
				struct hdd_fw_txrx_stats *stats,
				uint32_t rate_flags,
				uint8_t nss,
				uint32_t *maxrate,
				uint8_t *max_mcs_idx,
				bool report_max)
{
	struct index_data_rate_type *supported_mcs_rate;
	uint32_t tmprate;
	uint8_t flag = 0, mcsidx;
	int8_t rssi = stats->rssi;
	int mode;
	int i;

	if (rate_flags & TX_RATE_HT40)
		mode = 1;
	else
		mode = 0;

	if (rate_flags & TX_RATE_HT40)
		flag |= 1;
	if (rate_flags & TX_RATE_SGI)
		flag |= 2;

	supported_mcs_rate = (struct index_data_rate_type *)
		((nss == 1) ? &supported_mcs_rate_nss1 :
		 &supported_mcs_rate_nss2);

	if (stainfo->max_mcs_idx == 0xff) {
		hdd_err("invalid max_mcs_idx");
		/* report real mcs idx */
		mcsidx = stats->tx_rate.mcs;
	} else {
		mcsidx = stainfo->max_mcs_idx;
	}

	if (!report_max) {
		for (i = 0; i < mcsidx; i++) {
			if (rssi <= rssi_mcs_tbl[mode][i]) {
				mcsidx = i;
				break;
			}
		}
		if (mcsidx < stats->tx_rate.mcs)
			mcsidx = stats->tx_rate.mcs;
	}

	tmprate = supported_mcs_rate[mcsidx].supported_rate[flag];

	hdd_debug("tmprate %d mcsidx %d", tmprate, mcsidx);

	*maxrate = tmprate;
	*max_mcs_idx = mcsidx;
}

/**
 * hdd_get_max_rate_vht() - get max rate for vht mode
 * @stainfo: stainfo pointer
 * @stats: fw txrx status pointer
 * @rate_flags: rate flags
 * @nss: number of streams
 * @maxrate: returned max rate buffer pointer
 * @max_mcs_idx: max mcs idx
 * @report_max: report max rate or actual rate
 *
 * This function will get max rate for vht mode
 *
 * Return: None
 */
static void hdd_get_max_rate_vht(struct hdd_station_info *stainfo,
				 struct hdd_fw_txrx_stats *stats,
				 uint32_t rate_flags,
				 uint8_t nss,
				 uint32_t *maxrate,
				 uint8_t *max_mcs_idx,
				 bool report_max)
{
	struct index_vht_data_rate_type *supported_vht_mcs_rate;
	uint32_t tmprate = 0;
	uint32_t vht_max_mcs;
	uint8_t flag = 0, mcsidx = INVALID_MCS_IDX;
	int8_t rssi = stats->rssi;
	int mode;
	int i;

	supported_vht_mcs_rate = (struct index_vht_data_rate_type *)
		((nss == 1) ?
		 &supported_vht_mcs_rate_nss1 :
		 &supported_vht_mcs_rate_nss2);

	if (rate_flags & TX_RATE_VHT80)
		mode = 2;
	else if (rate_flags & TX_RATE_VHT40)
		mode = 1;
	else
		mode = 0;

	if (rate_flags &
	    (TX_RATE_VHT20 | TX_RATE_VHT40 | TX_RATE_VHT80)) {
		vht_max_mcs =
			(enum data_rate_11ac_max_mcs)
			(stainfo->tx_mcs_map & DATA_RATE_11AC_MCS_MASK);
		if (rate_flags & TX_RATE_SGI)
			flag |= 1;

		if (vht_max_mcs == DATA_RATE_11AC_MAX_MCS_7) {
			mcsidx = 7;
		} else if (vht_max_mcs == DATA_RATE_11AC_MAX_MCS_8) {
			mcsidx = 8;
		} else if (vht_max_mcs == DATA_RATE_11AC_MAX_MCS_9) {
			/*
			 * 'IEEE_P802.11ac_2013.pdf' page 325, 326
			 * - MCS9 is valid for VHT20 when Nss = 3 or Nss = 6
			 * - MCS9 is not valid for VHT20 when Nss = 1,2,4,5,7,8
			 */
			if ((rate_flags & TX_RATE_VHT20) &&
			    (nss != 3 && nss != 6))
				mcsidx = 8;
			else
				mcsidx = 9;
		} else {
			hdd_err("invalid vht_max_mcs");
			/* report real mcs idx */
			mcsidx = stats->tx_rate.mcs;
		}

		if (!report_max) {
			for (i = 0; i <= mcsidx && i < MAX_RSSI_MCS_INDEX; i++) {
				if (rssi <= rssi_mcs_tbl[mode][i]) {
					mcsidx = i;
					break;
				}
			}
			if (mcsidx < stats->tx_rate.mcs)
				mcsidx = stats->tx_rate.mcs;
		}

		if (rate_flags & TX_RATE_VHT80)
			tmprate =
		    supported_vht_mcs_rate[mcsidx].supported_VHT80_rate[flag];
		else if (rate_flags & TX_RATE_VHT40)
			tmprate =
		    supported_vht_mcs_rate[mcsidx].supported_VHT40_rate[flag];
		else if (rate_flags & TX_RATE_VHT20)
			tmprate =
		    supported_vht_mcs_rate[mcsidx].supported_VHT20_rate[flag];
	}

	hdd_debug("tmprate %d mcsidx %d", tmprate, mcsidx);

	*maxrate = tmprate;
	*max_mcs_idx = mcsidx;
}

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4, 0, 0))
#if defined(WLAN_FEATURE_11BE) && defined(CFG80211_11BE_BASIC)
static bool hdd_fill_eht_bw_mcs(struct rate_info *rate_info,
				enum tx_rate_info rate_flags,
				uint8_t mcsidx,
				uint8_t nss,
				uint8_t rate_info_flag)
{
	if (rate_info_flag == RATE_INFO_FLAGS_EHT_MCS) {
		rate_info->nss = nss;
		rate_info->mcs = mcsidx;
		rate_info->flags |= RATE_INFO_FLAGS_EHT_MCS;
		if (rate_flags & TX_RATE_EHT320)
			rate_info->bw = RATE_INFO_BW_320;
		else if (rate_flags & TX_RATE_EHT160)
			rate_info->bw = RATE_INFO_BW_160;
		else if (rate_flags & TX_RATE_EHT80)
			rate_info->bw = RATE_INFO_BW_80;
		else if (rate_flags & TX_RATE_EHT40)
			rate_info->bw = RATE_INFO_BW_40;
		else if (rate_flags & TX_RATE_EHT20)
			rate_info->bw = RATE_INFO_BW_20;

		return true;
	}

	return false;
}
#else
static inline bool hdd_fill_eht_bw_mcs(struct rate_info *rate_info,
				       enum tx_rate_info rate_flags,
				       uint8_t mcsidx,
				       uint8_t nss,
				       uint8_t rate_info_flag)
{
	return false;
}
#endif
/**
 * hdd_fill_bw_mcs() - fill ch width and mcs flags
 * @rate_info: pointer to struct rate_info
 * @rate_flags: HDD rate flags
 * @mcsidx: mcs index
 * @nss: number of streams
 * @rate_info_flag: rate info flags
 *
 * This function will fill ch width and mcs flags
 *
 * Return: None
 */
static void hdd_fill_bw_mcs(struct rate_info *rate_info,
			    enum tx_rate_info rate_flags,
			    uint8_t mcsidx,
			    uint8_t nss,
			    uint8_t rate_info_flag)
{
	if (hdd_fill_eht_bw_mcs(rate_info, rate_flags, mcsidx, nss,
				rate_info_flag))
		return;

	if (rate_info_flag == RATE_INFO_FLAGS_HE_MCS) {
		rate_info->nss = nss;
		rate_info->mcs = mcsidx;
		rate_info->flags |= RATE_INFO_FLAGS_HE_MCS;
		if (rate_flags & TX_RATE_HE160)
			rate_info->bw = RATE_INFO_BW_160;
		else if (rate_flags & TX_RATE_HE80)
			rate_info->bw = RATE_INFO_BW_80;
		else if (rate_flags & TX_RATE_HE40)
			rate_info->bw = RATE_INFO_BW_40;
		else if (rate_flags & TX_RATE_HE20)
			rate_info->bw = RATE_INFO_BW_20;
	} else if (rate_info_flag == RATE_INFO_FLAGS_VHT_MCS) {
		rate_info->nss = nss;
		rate_info->mcs = mcsidx;
		rate_info->flags |= RATE_INFO_FLAGS_VHT_MCS;
		if (rate_flags & TX_RATE_VHT160)
			rate_info->bw = RATE_INFO_BW_160;
		else if (rate_flags & TX_RATE_VHT80)
			rate_info->bw = RATE_INFO_BW_80;
		else if (rate_flags & TX_RATE_VHT40)
			rate_info->bw = RATE_INFO_BW_40;
		else if (rate_flags & TX_RATE_VHT20)
			rate_info->bw = RATE_INFO_BW_20;
	} else {
		rate_info->mcs = (nss - 1) << 3;
		rate_info->mcs |= mcsidx;
		rate_info->flags |= RATE_INFO_FLAGS_MCS;
		if (rate_flags & TX_RATE_HT40)
			rate_info->bw = RATE_INFO_BW_40;
	}
}
#else
/**
 * hdd_fill_bw_mcs() - fill ch width and mcs flags
 * @rate_info: pointer to struct rate_info
 * @rate_flags: HDD rate flags
 * @mcsidx: mcs index
 * @nss: number of streams
 * @rate_info_flag: rate info flags
 *
 * This function will fill ch width and mcs flags
 *
 * Return: None
 */
static void hdd_fill_bw_mcs(struct rate_info *rate_info,
			    enum tx_rate_info rate_flags,
			    uint8_t mcsidx,
			    uint8_t nss,
			    uint8_t rate_info_flag)
{
	if (rate_info_flag == RATE_INFO_FLAGS_VHT_MCS) {
		rate_info->nss = nss;
		rate_info->mcs = mcsidx;
		rate_info->flags |= RATE_INFO_FLAGS_VHT_MCS;
		if (rate_flags & TX_RATE_VHT80)
			rate_info->flags |= RATE_INFO_FLAGS_80_MHZ_WIDTH;
		else if (rate_flags & TX_RATE_VHT40)
			rate_info->flags |= RATE_INFO_FLAGS_40_MHZ_WIDTH;
		else if (rate_flags & TX_RATE_VHT20)
			rate_info->bw = RATE_INFO_BW_20;
	} else {
		rate_info->mcs = (nss - 1) << 3;
		rate_info->mcs |= mcsidx;
		rate_info->flags |= RATE_INFO_FLAGS_MCS;
		if (rate_flags & TX_RATE_HT40)
			rate_info->flags |= RATE_INFO_FLAGS_40_MHZ_WIDTH;
	}
}
#endif

#if defined(WLAN_FEATURE_11BE) && defined(CFG80211_11BE_BASIC)
static void hdd_fill_sinfo_eht_rate_info(struct rate_info *rate_info,
					 uint32_t rate_flags, uint8_t mcsidx,
					 uint8_t nss)
{
	if (rate_flags &
			(TX_RATE_EHT320 |
			 TX_RATE_EHT160 |
			 TX_RATE_EHT80 |
			 TX_RATE_EHT40 |
			 TX_RATE_EHT20)) {
		hdd_fill_bw_mcs(rate_info, rate_flags, mcsidx, nss,
				RATE_INFO_FLAGS_EHT_MCS);
	}
}
#else
static inline void hdd_fill_sinfo_eht_rate_info(struct rate_info *rate_info,
						uint32_t rate_flags,
						uint8_t mcsidx,
						uint8_t nss)
{
}
#endif

/**
 * hdd_fill_sinfo_rate_info() - fill rate info of sinfo struct
 * @sinfo: pointer to struct station_info
 * @rate_flags: HDD rate flags
 * @mcsidx: mcs index
 * @nss: number of streams
 * @rate: data rate (kbps)
 * @is_tx: flag to indicate whether it is tx or rx
 *
 * This function will fill rate info of sinfo struct
 *
 * Return: None
 */
static void hdd_fill_sinfo_rate_info(struct station_info *sinfo,
				     uint32_t rate_flags,
				     uint8_t mcsidx,
				     uint8_t nss,
				     uint32_t rate,
				     bool is_tx)
{
	struct rate_info *rate_info;

	if (is_tx)
		rate_info = &sinfo->txrate;
	else
		rate_info = &sinfo->rxrate;

	if (rate_flags & TX_RATE_LEGACY) {
		/* provide to the UI in units of 100kbps */
		rate_info->legacy = rate;
	} else {
		/* must be MCS */
		hdd_fill_sinfo_eht_rate_info(rate_info, rate_flags, mcsidx,
					     nss);

		if (rate_flags &
				(TX_RATE_HE160 |
				 TX_RATE_HE80 |
				 TX_RATE_HE40 |
				 TX_RATE_HE20)) {
			hdd_fill_bw_mcs(rate_info, rate_flags, mcsidx, nss,
					RATE_INFO_FLAGS_HE_MCS);
		}
		if (rate_flags &
				(TX_RATE_VHT160 |
				 TX_RATE_VHT80 |
				 TX_RATE_VHT40 |
				 TX_RATE_VHT20)) {
			hdd_fill_bw_mcs(rate_info, rate_flags, mcsidx, nss,
					RATE_INFO_FLAGS_VHT_MCS);
		}
		if (rate_flags & (TX_RATE_HT20 | TX_RATE_HT40)) {
			hdd_fill_bw_mcs(rate_info, rate_flags, mcsidx, nss,
					RATE_INFO_FLAGS_MCS);
		}
		if (rate_flags & TX_RATE_SGI) {
			if (!(rate_info->flags & RATE_INFO_FLAGS_VHT_MCS))
				rate_info->flags |= RATE_INFO_FLAGS_MCS;
			rate_info->flags |= RATE_INFO_FLAGS_SHORT_GI;
		}
	}

	hdd_debug("flag %x mcs %d legacy %d nss %d",
		  rate_info->flags,
		  rate_info->mcs,
		  rate_info->legacy,
		  rate_info->nss);

	if (is_tx)
		sinfo->filled |= HDD_INFO_TX_BITRATE;
	else
		sinfo->filled |= HDD_INFO_RX_BITRATE;
}

/**
 * hdd_fill_sta_flags() - fill sta flags of sinfo
 * @sinfo: station_info struct pointer
 * @stainfo: stainfo pointer
 *
 * This function will fill sta flags of sinfo
 *
 * Return: None
 */
static void hdd_fill_sta_flags(struct station_info *sinfo,
			       struct hdd_station_info *stainfo)
{
	sinfo->sta_flags.mask = NL80211_STA_FLAG_WME;

	if (stainfo->is_qos_enabled)
		sinfo->sta_flags.set |= NL80211_STA_FLAG_WME;
	else
		sinfo->sta_flags.set &= ~NL80211_STA_FLAG_WME;

	sinfo->filled |= HDD_INFO_STA_FLAGS;
}

/**
 * hdd_fill_per_chain_avg_signal() - fill per chain avg rssi of sinfo
 * @sinfo: station_info struct pointer
 * @stainfo: stainfo pointer
 *
 * This function will fill per chain avg rssi of sinfo
 *
 * Return: None
 */
static void hdd_fill_per_chain_avg_signal(struct station_info *sinfo,
					  struct hdd_station_info *stainfo)
{
	bool rssi_stats_valid = false;
	uint8_t i;

	sinfo->signal_avg = WLAN_HDD_TGT_NOISE_FLOOR_DBM;
	for (i = 0; i < IEEE80211_MAX_CHAINS; i++) {
		sinfo->chain_signal_avg[i] = stainfo->peer_rssi_per_chain[i];
		sinfo->chains |= 1 << i;
		if (sinfo->chain_signal_avg[i] > sinfo->signal_avg &&
		    sinfo->chain_signal_avg[i] != 0)
			sinfo->signal_avg = sinfo->chain_signal_avg[i];

		if (sinfo->chain_signal_avg[i])
			rssi_stats_valid = true;
	}

	if (rssi_stats_valid) {
		sinfo->filled |= HDD_INFO_CHAIN_SIGNAL_AVG;
		sinfo->filled |= HDD_INFO_SIGNAL_AVG;
	}
}

/**
 * hdd_fill_rate_info() - fill rate info of sinfo
 * @psoc: psoc context
 * @sinfo: station_info struct pointer
 * @stainfo: stainfo pointer
 * @stats: fw txrx status pointer
 *
 * This function will fill rate info of sinfo
 *
 * Return: None
 */
static void hdd_fill_rate_info(struct wlan_objmgr_psoc *psoc,
			       struct station_info *sinfo,
			       struct hdd_station_info *stainfo,
			       struct hdd_fw_txrx_stats *stats)
{
	enum tx_rate_info rate_flags;
	uint8_t mcsidx = 0xff;
	uint32_t tx_rate, rx_rate, maxrate, tmprate;
	int rssidx;
	int nss = 1;
	int link_speed_rssi_high = 0;
	int link_speed_rssi_mid = 0;
	int link_speed_rssi_low = 0;
	uint32_t link_speed_rssi_report = 0;

	ucfg_mlme_stats_get_cfg_values(psoc,
				       &link_speed_rssi_high,
				       &link_speed_rssi_mid,
				       &link_speed_rssi_low,
				       &link_speed_rssi_report);

	hdd_debug("reportMaxLinkSpeed %d", link_speed_rssi_report);

	/* convert to 100kbps expected in rate table */
	tx_rate = stats->tx_rate.rate / 100;
	rate_flags = stainfo->rate_flags;
	if (!(rate_flags & TX_RATE_LEGACY)) {
		nss = stainfo->nss;
		if (ucfg_mlme_stats_is_link_speed_report_actual(psoc)) {
			/* Get current rate flags if report actual */
			if (stats->tx_rate.rate_flags)
				rate_flags =
					stats->tx_rate.rate_flags;
			nss = stats->tx_rate.nss;
		}

		if (stats->tx_rate.mcs == INVALID_MCS_IDX)
			rate_flags = TX_RATE_LEGACY;
	}

	if (!ucfg_mlme_stats_is_link_speed_report_actual(psoc)) {
		/* we do not want to necessarily report the current speed */
		if (ucfg_mlme_stats_is_link_speed_report_max(psoc)) {
			/* report the max possible speed */
			rssidx = 0;
		} else if (ucfg_mlme_stats_is_link_speed_report_max_scaled(
					psoc)) {
			/* report the max possible speed with RSSI scaling */
			if (stats->rssi >= link_speed_rssi_high) {
				/* report the max possible speed */
				rssidx = 0;
			} else if (stats->rssi >= link_speed_rssi_mid) {
				/* report middle speed */
				rssidx = 1;
			} else if (stats->rssi >= link_speed_rssi_low) {
				/* report low speed */
				rssidx = 2;
			} else {
				/* report actual speed */
				rssidx = 3;
			}
		} else {
			/* unknown, treat as eHDD_LINK_SPEED_REPORT_MAX */
			hdd_err("Invalid value for reportMaxLinkSpeed: %u",
				link_speed_rssi_report);
			rssidx = 0;
		}

		maxrate = hdd_get_max_rate_legacy(stainfo, rssidx);

		/*
		 * Get MCS Rate Set --
		 * Only if we are connected in non legacy mode and not
		 * reporting actual speed
		 */
		if ((rssidx != 3) &&
		    !(rate_flags & TX_RATE_LEGACY)) {
			hdd_get_max_rate_vht(stainfo,
					     stats,
					     rate_flags,
					     nss,
					     &tmprate,
					     &mcsidx,
					     rssidx == 0);

			if (maxrate < tmprate &&
			    mcsidx != INVALID_MCS_IDX)
				maxrate = tmprate;

			if (mcsidx == INVALID_MCS_IDX)
				hdd_get_max_rate_ht(stainfo,
						    stats,
						    rate_flags,
						    nss,
						    &tmprate,
						    &mcsidx,
						    rssidx == 0);

			if (maxrate < tmprate &&
			    mcsidx != INVALID_MCS_IDX)
				maxrate = tmprate;
		} else if (!(rate_flags & TX_RATE_LEGACY)) {
			maxrate = tx_rate;
			mcsidx = stats->tx_rate.mcs;
		}

		/*
		 * make sure we report a value at least as big as our
		 * current rate
		 */
		if (maxrate < tx_rate || maxrate == 0) {
			maxrate = tx_rate;
			if (!(rate_flags & TX_RATE_LEGACY)) {
				mcsidx = stats->tx_rate.mcs;
				/*
				 * 'IEEE_P802.11ac_2013.pdf' page 325, 326
				 * - MCS9 is valid for VHT20 when Nss = 3 or
				 *   Nss = 6
				 * - MCS9 is not valid for VHT20 when
				 *   Nss = 1,2,4,5,7,8
				 */
				if ((rate_flags & TX_RATE_VHT20) &&
				    (mcsidx > 8) &&
				    (nss != 3 && nss != 6))
					mcsidx = 8;
			}
		}
	} else {
		/* report current rate instead of max rate */
		maxrate = tx_rate;
		if (!(rate_flags & TX_RATE_LEGACY))
			mcsidx = stats->tx_rate.mcs;
	}

	hdd_fill_sinfo_rate_info(sinfo, rate_flags, mcsidx, nss,
				 maxrate, true);

	/* convert to 100kbps expected in rate table */
	rx_rate = stats->rx_rate.rate / 100;

	/* report current rx rate*/
	rate_flags = stainfo->rate_flags;
	if (!(rate_flags & TX_RATE_LEGACY)) {
		if (stats->rx_rate.rate_flags)
			rate_flags = stats->rx_rate.rate_flags;
		nss = stats->rx_rate.nss;
		if (stats->rx_rate.mcs == INVALID_MCS_IDX)
			rate_flags = TX_RATE_LEGACY;
	}
	if (!(rate_flags & TX_RATE_LEGACY))
		mcsidx = stats->rx_rate.mcs;

	hdd_fill_sinfo_rate_info(sinfo, rate_flags, mcsidx, nss,
				 rx_rate, false);

	sinfo->expected_throughput = stainfo->max_phy_rate;
	sinfo->filled |= HDD_INFO_EXPECTED_THROUGHPUT;
}

/**
 * wlan_hdd_fill_station_info() - fill station_info struct
 * @psoc: psoc context
 * @adapter: The HDD adapter structure
 * @sinfo: station_info struct pointer
 * @stainfo: stainfo pointer
 * @stats: fw txrx status pointer
 *
 * This function will fill station_info struct
 *
 * Return: None
 */
static void wlan_hdd_fill_station_info(struct wlan_objmgr_psoc *psoc,
				       struct hdd_adapter *adapter,
				       struct station_info *sinfo,
				       struct hdd_station_info *stainfo,
				       struct hdd_fw_txrx_stats *stats)
{
	qdf_time_t curr_time, dur;
	struct cdp_peer_stats *peer_stats;
	QDF_STATUS status;

	peer_stats = qdf_mem_malloc(sizeof(*peer_stats));
	if (!peer_stats)
		return;

	status =
		cdp_host_get_peer_stats(cds_get_context(QDF_MODULE_ID_SOC),
					adapter->deflink->vdev_id,
					stainfo->sta_mac.bytes,
					peer_stats);

	if (QDF_IS_STATUS_ERROR(status)) {
		hdd_err("cdp_host_get_peer_stats failed. error: %u", status);
		qdf_mem_free(peer_stats);
		return;
	}

	stainfo->last_tx_rx_ts =
		peer_stats->tx.last_tx_ts > peer_stats->rx.last_rx_ts ?
		peer_stats->tx.last_tx_ts : peer_stats->rx.last_rx_ts;

	qdf_mem_free(peer_stats);

	curr_time = qdf_system_ticks();
	dur = curr_time - stainfo->assoc_ts;
	sinfo->connected_time = qdf_system_ticks_to_msecs(dur) / 1000;
	sinfo->filled |= HDD_INFO_CONNECTED_TIME;
	dur = curr_time - stainfo->last_tx_rx_ts;
	sinfo->inactive_time = qdf_system_ticks_to_msecs(dur);
	sinfo->filled |= HDD_INFO_INACTIVE_TIME;
	sinfo->signal = stats->rssi;
	sinfo->filled |= HDD_INFO_SIGNAL;
	sinfo->tx_bytes = stats->tx_bytes;
	sinfo->filled |= HDD_INFO_TX_BYTES | HDD_INFO_TX_BYTES64;
	sinfo->tx_packets = stats->tx_packets;
	sinfo->filled |= HDD_INFO_TX_PACKETS;
	sinfo->rx_bytes = stats->rx_bytes;
	sinfo->filled |= HDD_INFO_RX_BYTES | HDD_INFO_RX_BYTES64;
	sinfo->rx_packets = stats->rx_packets;
	sinfo->filled |= HDD_INFO_RX_PACKETS;
	sinfo->tx_failed = stats->tx_failed;
	sinfo->filled |= HDD_INFO_TX_FAILED;
	sinfo->tx_retries = stats->tx_retries;

	/* sta flags */
	hdd_fill_sta_flags(sinfo, stainfo);

	/* per chain avg rssi */
	hdd_fill_per_chain_avg_signal(sinfo, stainfo);

	/* tx / rx rate info */
	hdd_fill_rate_info(psoc, sinfo, stainfo, stats);

	/* assoc req ies */
	sinfo->assoc_req_ies = stainfo->assoc_req_ies.ptr;
	sinfo->assoc_req_ies_len = stainfo->assoc_req_ies.len;

	/* dump sta info*/
	hdd_debug("dump stainfo");
	hdd_debug("con_time %d inact_time %d tx_pkts %d rx_pkts %d",
		  sinfo->connected_time, sinfo->inactive_time,
		  sinfo->tx_packets, sinfo->rx_packets);
	hdd_debug("failed %d retries %d tx_bytes %lld rx_bytes %lld",
		  sinfo->tx_failed, sinfo->tx_retries,
		  sinfo->tx_bytes, sinfo->rx_bytes);
	hdd_debug("rssi %d tx mcs %d legacy %d nss %d flags %x",
		  sinfo->signal, sinfo->txrate.mcs,
		  sinfo->txrate.legacy, sinfo->txrate.nss,
		  sinfo->txrate.flags);
	hdd_debug("rx mcs %d legacy %d nss %d flags %x",
		  sinfo->rxrate.mcs, sinfo->rxrate.legacy,
		  sinfo->rxrate.nss, sinfo->rxrate.flags);
}

/**
 * hdd_get_rate_flags_ht() - get HT rate flags based on rate, nss and mcs
 * @rate: Data rate (100 kbps)
 * @nss: Number of streams
 * @mcs: HT mcs index
 *
 * This function is used to construct HT rate flag with rate, nss and mcs
 *
 * Return: rate flags for success, 0 on failure.
 */
static uint8_t hdd_get_rate_flags_ht(uint32_t rate,
				     uint8_t nss,
				     uint8_t mcs)
{
	struct index_data_rate_type *mcs_rate;
	uint8_t flags = 0;

	mcs_rate = (struct index_data_rate_type *)
		((nss == 1) ? &supported_mcs_rate_nss1 :
		 &supported_mcs_rate_nss2);

	if (rate == mcs_rate[mcs].supported_rate[0]) {
		flags |= TX_RATE_HT20;
	} else if (rate == mcs_rate[mcs].supported_rate[1]) {
		flags |= TX_RATE_HT40;
	} else if (rate == mcs_rate[mcs].supported_rate[2]) {
		flags |= TX_RATE_HT20;
		flags |= TX_RATE_SGI;
	} else if (rate == mcs_rate[mcs].supported_rate[3]) {
		flags |= TX_RATE_HT40;
		flags |= TX_RATE_SGI;
	} else {
		hdd_err("invalid params rate %d nss %d mcs %d",
			rate, nss, mcs);
	}

	return flags;
}

/**
 * hdd_get_rate_flags_vht() - get VHT rate flags based on rate, nss and mcs
 * @rate: Data rate (100 kbps)
 * @nss: Number of streams
 * @mcs: VHT mcs index
 *
 * This function is used to construct VHT rate flag with rate, nss and mcs
 *
 * Return: rate flags for success, 0 on failure.
 */
static uint8_t hdd_get_rate_flags_vht(uint32_t rate,
				      uint8_t nss,
				      uint8_t mcs)
{
	struct index_vht_data_rate_type *mcs_rate;
	uint8_t flags = 0;

	if (mcs >= ARRAY_SIZE(supported_vht_mcs_rate_nss1)) {
		hdd_err("Invalid mcs index %d", mcs);
		return flags;
	}

	mcs_rate = (struct index_vht_data_rate_type *)
		((nss == 1) ?
		 &supported_vht_mcs_rate_nss1 :
		 &supported_vht_mcs_rate_nss2);

	if (rate == mcs_rate[mcs].supported_VHT80_rate[0]) {
		flags |= TX_RATE_VHT80;
	} else if (rate == mcs_rate[mcs].supported_VHT80_rate[1]) {
		flags |= TX_RATE_VHT80;
		flags |= TX_RATE_SGI;
	} else if (rate == mcs_rate[mcs].supported_VHT40_rate[0]) {
		flags |= TX_RATE_VHT40;
	} else if (rate == mcs_rate[mcs].supported_VHT40_rate[1]) {
		flags |= TX_RATE_VHT40;
		flags |= TX_RATE_SGI;
	} else if (rate == mcs_rate[mcs].supported_VHT20_rate[0]) {
		flags |= TX_RATE_VHT20;
	} else if (rate == mcs_rate[mcs].supported_VHT20_rate[1]) {
		flags |= TX_RATE_VHT20;
		flags |= TX_RATE_SGI;
	} else {
		hdd_err("invalid params rate %d nss %d mcs %d",
			rate, nss, mcs);
	}

	return flags;
}

/**
 * hdd_get_rate_flags() - get HT/VHT rate flags based on rate, nss and mcs
 * @rate: Data rate (100 kbps)
 * @mode: Tx/Rx mode
 * @nss: Number of streams
 * @mcs: Mcs index
 *
 * This function is used to construct rate flag with rate, nss and mcs
 *
 * Return: rate flags for success, 0 on failure.
 */
static uint8_t hdd_get_rate_flags(uint32_t rate,
				  uint8_t mode,
				  uint8_t nss,
				  uint8_t mcs)
{
	uint8_t flags = 0;

	if (mode == SIR_SME_PHY_MODE_HT)
		flags = hdd_get_rate_flags_ht(rate, nss, mcs);
	else if (mode == SIR_SME_PHY_MODE_VHT)
		flags = hdd_get_rate_flags_vht(rate, nss, mcs);
	else
		hdd_debug("invalid mode param %d", mode);

	return flags;
}

/**
 * wlan_hdd_fill_rate_info() - fill HDD rate info from peer info
 * @txrx_stats: pointer to txrx stats to be filled with rate info
 * @peer_info: peer info pointer
 *
 * This function is used to fill HDD rate info from peer info
 *
 * Return: None
 */
static void wlan_hdd_fill_rate_info(struct hdd_fw_txrx_stats *txrx_stats,
				    struct peer_stats_info_ext_event *peer_info)
{
	uint8_t flags;
	uint32_t rate_code;

	/* tx rate info */
	txrx_stats->tx_rate.rate = peer_info->tx_rate;
	rate_code = peer_info->tx_rate_code;

	if ((WMI_GET_HW_RATECODE_PREAM_V1(rate_code)) ==
			WMI_RATE_PREAMBLE_HT)
		txrx_stats->tx_rate.mode = SIR_SME_PHY_MODE_HT;
	else if ((WMI_GET_HW_RATECODE_PREAM_V1(rate_code)) ==
			WMI_RATE_PREAMBLE_VHT)
		txrx_stats->tx_rate.mode = SIR_SME_PHY_MODE_VHT;
	else
		txrx_stats->tx_rate.mode = SIR_SME_PHY_MODE_LEGACY;

	txrx_stats->tx_rate.nss = WMI_GET_HW_RATECODE_NSS_V1(rate_code) + 1;
	txrx_stats->tx_rate.mcs = WMI_GET_HW_RATECODE_RATE_V1(rate_code);

	flags = hdd_get_rate_flags(txrx_stats->tx_rate.rate / 100,
				   txrx_stats->tx_rate.mode,
				   txrx_stats->tx_rate.nss,
				   txrx_stats->tx_rate.mcs);

	txrx_stats->tx_rate.rate_flags = flags;

	hdd_debug("tx: mode %d nss %d mcs %d rate_flags %x flags %x",
		  txrx_stats->tx_rate.mode,
		  txrx_stats->tx_rate.nss,
		  txrx_stats->tx_rate.mcs,
		  txrx_stats->tx_rate.rate_flags,
		  flags);

	/* rx rate info */
	txrx_stats->rx_rate.rate = peer_info->rx_rate;
	rate_code = peer_info->rx_rate_code;

	if ((WMI_GET_HW_RATECODE_PREAM_V1(rate_code)) ==
			WMI_RATE_PREAMBLE_HT)
		txrx_stats->rx_rate.mode = SIR_SME_PHY_MODE_HT;
	else if ((WMI_GET_HW_RATECODE_PREAM_V1(rate_code)) ==
			WMI_RATE_PREAMBLE_VHT)
		txrx_stats->rx_rate.mode = SIR_SME_PHY_MODE_VHT;
	else
		txrx_stats->rx_rate.mode = SIR_SME_PHY_MODE_LEGACY;

	txrx_stats->rx_rate.nss = WMI_GET_HW_RATECODE_NSS_V1(rate_code) + 1;
	txrx_stats->rx_rate.mcs = WMI_GET_HW_RATECODE_RATE_V1(rate_code);

	flags = hdd_get_rate_flags(txrx_stats->rx_rate.rate / 100,
				   txrx_stats->rx_rate.mode,
				   txrx_stats->rx_rate.nss,
				   txrx_stats->rx_rate.mcs);

	txrx_stats->rx_rate.rate_flags = flags;

	hdd_info("rx: mode %d nss %d mcs %d rate_flags %x flags %x",
		 txrx_stats->rx_rate.mode,
		 txrx_stats->rx_rate.nss,
		 txrx_stats->rx_rate.mcs,
		 txrx_stats->rx_rate.rate_flags,
		 flags);
}

/**
 * wlan_hdd_get_station_remote() - NL80211_CMD_GET_STATION handler for SoftAP
 * @wiphy: pointer to wiphy
 * @dev: pointer to net_device structure
 * @stainfo: request peer station info
 * @sinfo: pointer to station_info struct
 *
 * This function will get remote peer info from fw and fill sinfo struct
 *
 * Return: 0 on success, otherwise error value
 */
static int wlan_hdd_get_station_remote(struct wiphy *wiphy,
				       struct net_device *dev,
				       struct hdd_station_info *stainfo,
				       struct station_info *sinfo)
{
	struct hdd_adapter *adapter = WLAN_HDD_GET_PRIV_PTR(dev);
	struct hdd_context *hddctx = wiphy_priv(wiphy);
	struct stats_event *stats;
	struct hdd_fw_txrx_stats txrx_stats;
	int i, status;

	stats = wlan_cfg80211_mc_cp_stats_get_peer_stats(adapter->deflink->vdev,
							 stainfo->sta_mac.bytes,
							 &status);
	if (status || !stats) {
		wlan_cfg80211_mc_cp_stats_free_stats_event(stats);
		hdd_err("fail to get peer info from fw");
		return -EPERM;
	}

	for (i = 0; i < WMI_MAX_CHAINS; i++)
		stainfo->peer_rssi_per_chain[i] =
			    stats->peer_stats_info_ext->peer_rssi_per_chain[i];

	qdf_mem_zero(&txrx_stats, sizeof(txrx_stats));
	txrx_stats.tx_packets = stats->peer_stats_info_ext->tx_packets;
	txrx_stats.tx_bytes = stats->peer_stats_info_ext->tx_bytes;
	txrx_stats.rx_packets = stats->peer_stats_info_ext->rx_packets;
	txrx_stats.rx_bytes = stats->peer_stats_info_ext->rx_bytes;
	txrx_stats.tx_retries = stats->peer_stats_info_ext->tx_retries;
	txrx_stats.tx_failed = stats->peer_stats_info_ext->tx_failed;
	txrx_stats.tx_succeed = stats->peer_stats_info_ext->tx_succeed;
	txrx_stats.rssi = stats->peer_stats_info_ext->rssi;
	wlan_hdd_fill_rate_info(&txrx_stats, stats->peer_stats_info_ext);
	wlan_hdd_fill_station_info(hddctx->psoc, adapter,
				   sinfo, stainfo, &txrx_stats);
	wlan_cfg80211_mc_cp_stats_free_stats_event(stats);

	return status;
}

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4, 19, 0)) && \
	defined(WLAN_FEATURE_11AX)
/**
 * hdd_map_he_gi_to_os() - map txrate_gi to os guard interval
 * @guard_interval: guard interval get from fw rate
 *
 * Return: os guard interval value
 */
static inline uint8_t hdd_map_he_gi_to_os(enum txrate_gi guard_interval)
{
	switch (guard_interval) {
	case TXRATE_GI_0_8_US:
		return NL80211_RATE_INFO_HE_GI_0_8;
	case TXRATE_GI_1_6_US:
		return NL80211_RATE_INFO_HE_GI_1_6;
	case TXRATE_GI_3_2_US:
		return NL80211_RATE_INFO_HE_GI_3_2;
	default:
		return NL80211_RATE_INFO_HE_GI_0_8;
	}
}

/**
 * wlan_hdd_fill_os_he_rateflags() - Fill HE related rate_info
 * @os_rate: rate info for os
 * @rate_flags: rate flags
 * @dcm: dcm from rate
 * @guard_interval: guard interval from rate
 *
 * Return: none
 */
static void wlan_hdd_fill_os_he_rateflags(struct rate_info *os_rate,
					  enum tx_rate_info rate_flags,
					  uint8_t dcm,
					  enum txrate_gi guard_interval)
{
	/* as fw not yet report ofdma to host, so we doesn't
	 * fill RATE_INFO_BW_HE_RU.
	 */
	if (rate_flags & (TX_RATE_HE80 | TX_RATE_HE40 |
		TX_RATE_HE20 | TX_RATE_HE160)) {
		if (rate_flags & TX_RATE_HE160)
			hdd_set_rate_bw(os_rate, HDD_RATE_BW_160);
		else if (rate_flags & TX_RATE_HE80)
			hdd_set_rate_bw(os_rate, HDD_RATE_BW_80);
		else if (rate_flags & TX_RATE_HE40)
			hdd_set_rate_bw(os_rate, HDD_RATE_BW_40);

		os_rate->flags |= RATE_INFO_FLAGS_HE_MCS;

		os_rate->he_gi = hdd_map_he_gi_to_os(guard_interval);
		os_rate->he_dcm = dcm;
	}
}
#else
static void wlan_hdd_fill_os_he_rateflags(struct rate_info *os_rate,
					  enum tx_rate_info rate_flags,
					  uint8_t dcm,
					  enum txrate_gi guard_interval)
{}
#endif

/**
 * wlan_hdd_fill_os_rate_info() - Fill os related rate_info
 * @rate_flags: rate flags
 * @legacy_rate: 802.11abg rate
 * @os_rate: rate info for os
 * @mcs_index: mcs
 * @nss: number of spatial streams
 * @dcm: dcm from rate
 * @guard_interval: guard interval from rate
 *
 * Return: none
 */
static void wlan_hdd_fill_os_rate_info(enum tx_rate_info rate_flags,
				       uint16_t legacy_rate,
				       struct rate_info *os_rate,
				       uint8_t mcs_index, uint8_t nss,
				       uint8_t dcm,
				       enum txrate_gi guard_interval)
{
	os_rate->nss = nss;
	if (rate_flags & TX_RATE_LEGACY) {
		os_rate->legacy = legacy_rate;
		hdd_debug("Reporting legacy rate %d", os_rate->legacy);
		return;
	}

	/* assume basic BW. anything else will override this later */
	hdd_set_rate_bw(os_rate, HDD_RATE_BW_20);
	os_rate->mcs = mcs_index;

	wlan_hdd_fill_os_eht_rateflags(os_rate, rate_flags, dcm,
				       guard_interval);
	wlan_hdd_fill_os_he_rateflags(os_rate, rate_flags, dcm, guard_interval);

	if (rate_flags & (TX_RATE_VHT160 | TX_RATE_VHT80 | TX_RATE_VHT40 |
	    TX_RATE_VHT20)) {
		if (rate_flags & TX_RATE_VHT160)
			hdd_set_rate_bw(os_rate, HDD_RATE_BW_160);
		else if (rate_flags & TX_RATE_VHT80)
			hdd_set_rate_bw(os_rate, HDD_RATE_BW_80);
		else if (rate_flags & TX_RATE_VHT40)
			hdd_set_rate_bw(os_rate, HDD_RATE_BW_40);
		os_rate->flags |= RATE_INFO_FLAGS_VHT_MCS;
	}

	if (rate_flags & (TX_RATE_HT20 | TX_RATE_HT40)) {
		if (rate_flags & TX_RATE_HT40)
			hdd_set_rate_bw(os_rate,
					HDD_RATE_BW_40);
		os_rate->flags |= RATE_INFO_FLAGS_MCS;
	}

	if (rate_flags & TX_RATE_SGI)
		os_rate->flags |= RATE_INFO_FLAGS_SHORT_GI;
}

void hdd_get_max_tx_bitrate(struct wlan_hdd_link_info *link_info)
{
	struct hdd_context *hdd_ctx = link_info->adapter->hdd_ctx;
	struct station_info sinfo;
	enum tx_rate_info tx_rate_flags;
	uint8_t tx_mcs_index, tx_nss = 1;
	uint16_t my_tx_rate;
	struct hdd_station_ctx *hdd_sta_ctx;
	struct wlan_objmgr_vdev *vdev;

	hdd_sta_ctx = WLAN_HDD_GET_STATION_CTX_PTR(link_info);

	qdf_mem_zero(&sinfo, sizeof(struct station_info));

	sinfo.signal = link_info->rssi;
	tx_mcs_index = link_info->hdd_stats.class_a_stat.tx_mcs_index;
	my_tx_rate = link_info->hdd_stats.class_a_stat.tx_rate;
	tx_rate_flags = link_info->hdd_stats.class_a_stat.tx_rx_rate_flags;

	if (!(tx_rate_flags & TX_RATE_LEGACY)) {
		vdev = hdd_objmgr_get_vdev_by_user(link_info,
						   WLAN_OSIF_STATS_ID);
		if (vdev) {
			/*
			 * Take static NSS for reporting max rates.
			 * NSS from FW is not reliable as it changes
			 * as per the environment quality.
			 */
			tx_nss = wlan_vdev_mlme_get_nss(vdev);
			hdd_objmgr_put_vdev_by_user(vdev, WLAN_OSIF_STATS_ID);
		} else {
			tx_nss = link_info->hdd_stats.class_a_stat.tx_nss;
		}
		hdd_check_and_update_nss(hdd_ctx, &tx_nss, NULL);

		if (tx_mcs_index == INVALID_MCS_IDX)
			tx_mcs_index = 0;
	}

	if (hdd_report_max_rate(link_info, hdd_ctx->mac_handle, &sinfo.txrate,
				sinfo.signal, tx_rate_flags, tx_mcs_index,
				my_tx_rate, tx_nss)) {
		hdd_sta_ctx->cache_conn_info.max_tx_bitrate = sinfo.txrate;
		hdd_debug("Reporting max tx rate flags %d mcs %d nss %d bw %d",
			  sinfo.txrate.flags, sinfo.txrate.mcs,
			  sinfo.txrate.nss, sinfo.txrate.bw);
	}
}

bool hdd_report_max_rate(struct wlan_hdd_link_info *link_info,
			 mac_handle_t mac_handle,
			 struct rate_info *rate,
			 int8_t signal,
			 enum tx_rate_info rate_flags,
			 uint8_t mcs_index,
			 uint16_t fw_rate, uint8_t nss)
{
	uint8_t i, j, rssidx = 0;
	uint16_t max_rate = 0;
	uint32_t vht_mcs_map;
	bool is_vht20_mcs9 = false;
	uint16_t he_mcs_12_13_map = 0;
	uint16_t current_rate = 0;
	qdf_size_t or_leng;
	uint8_t operational_rates[CSR_DOT11_SUPPORTED_RATES_MAX];
	uint8_t extended_rates[CSR_DOT11_EXTENDED_SUPPORTED_RATES_MAX];
	qdf_size_t er_leng;
	uint8_t mcs_rates[SIZE_OF_BASIC_MCS_SET];
	qdf_size_t mcs_len;
	struct index_data_rate_type *supported_mcs_rate;
	enum data_rate_11ac_max_mcs vht_max_mcs;
	uint8_t max_mcs_idx = 0;
	uint8_t max_ht_mcs_idx;
	uint8_t rate_flag = 1;
	int mode = 0, max_ht_idx;
	QDF_STATUS stat = QDF_STATUS_E_FAILURE;
	struct hdd_context *hdd_ctx;
	int link_speed_rssi_high = 0;
	int link_speed_rssi_mid = 0;
	int link_speed_rssi_low = 0;
	uint32_t link_speed_rssi_report = 0;
	struct wlan_objmgr_vdev *vdev;

	hdd_ctx = cds_get_context(QDF_MODULE_ID_HDD);
	if (!hdd_ctx)
		return false;

	ucfg_mlme_stats_get_cfg_values(hdd_ctx->psoc,
				       &link_speed_rssi_high,
				       &link_speed_rssi_mid,
				       &link_speed_rssi_low,
				       &link_speed_rssi_report);

	if (ucfg_mlme_stats_is_link_speed_report_max_scaled(hdd_ctx->psoc)) {
		/* report the max possible speed with RSSI scaling */
		if (signal >= link_speed_rssi_high) {
			/* report the max possible speed */
			rssidx = 0;
		} else if (signal >= link_speed_rssi_mid) {
			/* report middle speed */
			rssidx = 1;
		} else if (signal >= link_speed_rssi_low) {
			/* report middle speed */
			rssidx = 2;
		} else {
			/* report actual speed */
			rssidx = 3;
		}
	}

	vdev = hdd_objmgr_get_vdev_by_user(link_info, WLAN_OSIF_STATS_ID);
	if (!vdev) {
		hdd_err("failed to get vdev");
		return false;
	}

	/* Get Basic Rate Set */
	or_leng = ucfg_mlme_get_opr_rate(vdev, operational_rates,
					 sizeof(operational_rates));
	for (i = 0; i < or_leng; i++) {
		for (j = 0; j < ARRAY_SIZE(supported_data_rate); j++) {
			/* Validate Rate Set */
			if (supported_data_rate[j].beacon_rate_index ==
				(operational_rates[i] & 0x7F)) {
				current_rate =
					supported_data_rate[j].
					supported_rate[rssidx];
				break;
			}
		}
		/* Update MAX rate */
		max_rate = (current_rate > max_rate) ? current_rate : max_rate;
	}

	/* Get Extended Rate Set */
	er_leng = ucfg_mlme_get_ext_opr_rate(vdev, extended_rates,
					     sizeof(extended_rates));
	he_mcs_12_13_map = wlan_vdev_mlme_get_he_mcs_12_13_map(vdev);

	hdd_objmgr_put_vdev_by_user(vdev, WLAN_OSIF_STATS_ID);
	for (i = 0; i < er_leng; i++) {
		for (j = 0; j < ARRAY_SIZE(supported_data_rate); j++) {
			if (supported_data_rate[j].beacon_rate_index ==
			    (extended_rates[i] & 0x7F)) {
				current_rate = supported_data_rate[j].
					       supported_rate[rssidx];
				break;
			}
		}
		/* Update MAX rate */
		max_rate = (current_rate > max_rate) ? current_rate : max_rate;
	}
	/* Get MCS Rate Set --
	 * Only if we are connected in non legacy mode and not reporting
	 * actual speed
	 */
	if ((3 != rssidx) && !(rate_flags & TX_RATE_LEGACY)) {
		rate_flag = 0;
		if (rate_flags & (TX_RATE_VHT80 | TX_RATE_HE80 |
				TX_RATE_HE160 | TX_RATE_VHT160 |
				TX_RATE_EHT80 | TX_RATE_EHT160 |
				TX_RATE_EHT320))
			mode = 2;
		else if (rate_flags & (TX_RATE_HT40 |
			 TX_RATE_VHT40 | TX_RATE_HE40 | TX_RATE_EHT40))
			mode = 1;
		else
			mode = 0;

		if (rate_flags & (TX_RATE_VHT20 | TX_RATE_VHT40 |
		    TX_RATE_VHT80 | TX_RATE_HE20 | TX_RATE_HE40 |
		    TX_RATE_HE80 | TX_RATE_HE160 | TX_RATE_VHT160 |
		    TX_RATE_EHT20 | TX_RATE_EHT40 | TX_RATE_EHT80 |
		    TX_RATE_EHT160 | TX_RATE_EHT320)) {
			stat = ucfg_mlme_cfg_get_vht_tx_mcs_map(hdd_ctx->psoc,
								&vht_mcs_map);
			if (QDF_IS_STATUS_ERROR(stat))
				hdd_err("failed to get tx_mcs_map");

			stat = ucfg_mlme_get_vht20_mcs9(hdd_ctx->psoc,
							&is_vht20_mcs9);
			if (QDF_IS_STATUS_ERROR(stat))
				hdd_err("Failed to get VHT20 MCS9 enable val");

			vht_max_mcs = (enum data_rate_11ac_max_mcs)
				(vht_mcs_map & DATA_RATE_11AC_MCS_MASK);
			if (rate_flags & TX_RATE_SGI)
				rate_flag |= 1;

			if (DATA_RATE_11AC_MAX_MCS_7 == vht_max_mcs) {
				max_mcs_idx = 7;
			} else if (DATA_RATE_11AC_MAX_MCS_8 == vht_max_mcs) {
				max_mcs_idx = 8;
			} else if (DATA_RATE_11AC_MAX_MCS_9 == vht_max_mcs) {
				/*
				 * If the ini enable_vht20_mcs9 is disabled,
				 * then max mcs index should not be set to 9
				 * for TX_RATE_VHT20
				 */
				if (!is_vht20_mcs9 &&
				    (rate_flags & TX_RATE_VHT20))
					max_mcs_idx = 8;
				else
					max_mcs_idx = 9;
			}

			if (rate_flags & (TX_RATE_EHT20 | TX_RATE_EHT40 |
			    TX_RATE_EHT80 | TX_RATE_EHT160 | TX_RATE_EHT320))
				max_mcs_idx = 13;

			if (rate_flags & (TX_RATE_HE20 | TX_RATE_HE40 |
			    TX_RATE_HE80 | TX_RATE_HE160)) {
				max_mcs_idx = 11;
				if (he_mcs_12_13_map)
					max_mcs_idx = 13;
			}

			if (rssidx != 0) {
				for (i = 0; i <= max_mcs_idx; i++) {
					if (signal <= rssi_mcs_tbl[mode][i]) {
						max_mcs_idx = i;
						break;
					}
				}
			}

			max_mcs_idx = (max_mcs_idx > mcs_index) ?
				max_mcs_idx : mcs_index;
		} else {
			mcs_len = ucfg_mlme_get_mcs_rate(link_info->vdev,
							 mcs_rates,
							 sizeof(mcs_rates));
			if (!mcs_len) {
				hdd_err("Failed to get current mcs rate set");
				/*To keep GUI happy */
				return false;
			}

			if (rate_flags & TX_RATE_HT40)
				rate_flag |= 1;
			if (rate_flags & TX_RATE_SGI)
				rate_flag |= 2;

			supported_mcs_rate =
				(struct index_data_rate_type *)
				((nss == 1) ? &supported_mcs_rate_nss1 :
				 &supported_mcs_rate_nss2);
			max_ht_mcs_idx =
				QDF_ARRAY_SIZE(supported_mcs_rate_nss1);
			max_ht_idx = max_ht_mcs_idx;
			if (rssidx != 0) {
				for (i = 0; i < max_ht_mcs_idx; i++) {
					if (signal <= rssi_mcs_tbl[mode][i]) {
						max_ht_idx = i + 1;
						break;
					}
				}
			}

			for (i = 0; i < mcs_len; i++) {
				for (j = 0; j < max_ht_idx; j++) {
					if (supported_mcs_rate[j].
						beacon_rate_index ==
						mcs_rates[i]) {
						current_rate =
						  supported_mcs_rate[j].
						  supported_rate
						  [rate_flag];
						max_mcs_idx =
						  supported_mcs_rate[j].
						  beacon_rate_index;
						break;
					}
				}

				if ((j < max_ht_mcs_idx) &&
				    (current_rate > max_rate))
					max_rate = current_rate;
			}

			if (nss == 2)
				max_mcs_idx += max_ht_mcs_idx;
			max_mcs_idx = (max_mcs_idx > mcs_index) ?
				max_mcs_idx : mcs_index;
		}
	}

	else if (!(rate_flags & TX_RATE_LEGACY)) {
		max_rate = fw_rate;
		max_mcs_idx = mcs_index;
	}
	/* report a value at least as big as current rate */
	if ((max_rate < fw_rate) || (0 == max_rate)) {
		max_rate = fw_rate;
	}
	hdd_debug("RLMS %u, rate_flags 0x%x, max_rate %d mcs %d nss %d",
		  link_speed_rssi_report, rate_flags,
		  max_rate, max_mcs_idx, nss);
	wlan_hdd_fill_os_rate_info(rate_flags, max_rate, rate,
				   max_mcs_idx, nss, 0, 0);

	return true;
}

/**
 * hdd_report_actual_rate() - Fill the actual rate stats.
 * @rate_flags: The rate flags computed from rate
 * @my_rate: The rate from fw stats
 * @rate: The station_info struct member struct rate_info to be filled
 * @mcs_index: The mcs index computed from rate
 * @nss: The NSS from fw stats
 * @dcm: the dcm computed from rate
 * @guard_interval: the guard interval computed from rate
 *
 * Return: None
 */
static void hdd_report_actual_rate(enum tx_rate_info rate_flags,
				   uint16_t my_rate,
				   struct rate_info *rate, uint8_t mcs_index,
				   uint8_t nss, uint8_t dcm,
				   enum txrate_gi guard_interval)
{
	/* report current rate instead of max rate */
	wlan_hdd_fill_os_rate_info(rate_flags, my_rate, rate,
				   mcs_index, nss, dcm, guard_interval);
}

/**
 * hdd_wlan_fill_per_chain_rssi_stats() - Fill per chain rssi stats
 *
 * @sinfo: The station_info structure to be filled.
 * @link_info: pointer to link_info struct in adapter
 *
 * Return: None
 */
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3, 14, 0))
static void
hdd_wlan_fill_per_chain_rssi_stats(struct station_info *sinfo,
				   struct wlan_hdd_link_info *link_info)
{
	bool rssi_stats_valid = false;
	uint8_t i;

	sinfo->signal_avg = WLAN_HDD_TGT_NOISE_FLOOR_DBM;
	for (i = 0; i < NUM_CHAINS_MAX; i++) {
		sinfo->chain_signal_avg[i] =
			   link_info->hdd_stats.per_chain_rssi_stats.rssi[i];
		sinfo->chains |= 1 << i;
		if (sinfo->chain_signal_avg[i] > sinfo->signal_avg &&
		    sinfo->chain_signal_avg[i] != 0)
			sinfo->signal_avg = sinfo->chain_signal_avg[i];

		hdd_debug("RSSI for chain %d, vdev_id %d is %d",
			  i, link_info->vdev_id, sinfo->chain_signal_avg[i]);

		if (!rssi_stats_valid && sinfo->chain_signal_avg[i])
			rssi_stats_valid = true;
	}

	if (rssi_stats_valid) {
		sinfo->filled |= HDD_INFO_CHAIN_SIGNAL_AVG;
		sinfo->filled |= HDD_INFO_SIGNAL_AVG;
	}
}
#else
static inline void
hdd_wlan_fill_per_chain_rssi_stats(struct station_info *sinfo,
				   struct wlan_hdd_link_info *link_info)
{
}
#endif

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4, 20, 0)) || \
	defined(CFG80211_RX_FCS_ERROR_REPORTING_SUPPORT)
static void hdd_fill_fcs_and_mpdu_count(struct wlan_hdd_link_info *link_info,
					struct station_info *sinfo)
{
	sinfo->rx_mpdu_count = link_info->hdd_stats.peer_stats.rx_count;
	sinfo->fcs_err_count = link_info->hdd_stats.peer_stats.fcs_count;
	hdd_debug("RX mpdu count %d fcs_err_count %d",
		  sinfo->rx_mpdu_count, sinfo->fcs_err_count);
	sinfo->filled |= HDD_INFO_FCS_ERROR_COUNT | HDD_INFO_RX_MPDUS;
}
#else
static void hdd_fill_fcs_and_mpdu_count(struct wlan_hdd_link_info *link_info,
					struct station_info *sinfo)
{
}
#endif

void hdd_check_and_update_nss(struct hdd_context *hdd_ctx,
			      uint8_t *tx_nss, uint8_t *rx_nss)
{
	if (tx_nss && (*tx_nss > 1) &&
	    policy_mgr_is_current_hwmode_dbs(hdd_ctx->psoc) &&
	    !policy_mgr_is_hw_dbs_2x2_capable(hdd_ctx->psoc)) {
		hdd_debug("Hw mode is DBS, Reduce tx nss(%d) to 1", *tx_nss);
		(*tx_nss)--;
	}

	if (rx_nss && (*rx_nss > 1) &&
	    policy_mgr_is_current_hwmode_dbs(hdd_ctx->psoc) &&
	    !policy_mgr_is_hw_dbs_2x2_capable(hdd_ctx->psoc)) {
		hdd_debug("Hw mode is DBS, Reduce rx nss(%d) to 1", *rx_nss);
		(*rx_nss)--;
	}
}

#ifdef FEATURE_RX_LINKSPEED_ROAM_TRIGGER
static void
wlan_hdd_refill_os_bw(struct rate_info *os_rate, enum rx_tlv_bw bw)
{
	if (bw == RX_TLV_BW_20MHZ)
		os_rate->bw = RATE_INFO_BW_20;
	else if (bw == RX_TLV_BW_40MHZ)
		os_rate->bw = RATE_INFO_BW_40;
	else if (bw == RX_TLV_BW_80MHZ)
		os_rate->bw = RATE_INFO_BW_80;
	else if (bw == RX_TLV_BW_160MHZ)
		os_rate->bw = RATE_INFO_BW_160;
	else
		wlan_hdd_refill_os_eht_bw(os_rate, bw);
}

static void
wlan_hdd_refill_os_rateflags(struct rate_info *os_rate, uint8_t preamble)
{
	if (preamble == DOT11_N)
		os_rate->flags |= RATE_INFO_FLAGS_MCS;
	else if (preamble == DOT11_AC)
		os_rate->flags |= RATE_INFO_FLAGS_VHT_MCS;
	else if (preamble == DOT11_AX)
		os_rate->flags |= RATE_INFO_FLAGS_HE_MCS;
	else
		wlan_hdd_refill_os_eht_rateflags(os_rate, preamble);
}

/**
 * wlan_hdd_refill_actual_rate() - Refill actual rates info stats
 * @sinfo: kernel station_info struct to populate
 * @link_info: pointer to link_info struct in adapter,
 *             where hdd_stats is located in this struct
 *
 * This function is to replace RX rates which was previously filled by fw.
 *
 * Return: None
 */
static void
wlan_hdd_refill_actual_rate(struct station_info *sinfo,
			    struct wlan_hdd_link_info *link_info)
{
	uint8_t preamble = link_info->hdd_stats.class_a_stat.rx_preamble;

	sinfo->rxrate.nss = link_info->hdd_stats.class_a_stat.rx_nss;
	if (preamble == DOT11_A || preamble == DOT11_B) {
		/* Clear rxrate which may have been set previously */
		qdf_mem_zero(&sinfo->rxrate, sizeof(sinfo->rxrate));
		sinfo->rxrate.legacy =
			link_info->hdd_stats.class_a_stat.rx_rate;
		hdd_debug("Reporting legacy rate %d", sinfo->rxrate.legacy);
		return;
	} else if (qdf_unlikely(preamble == INVALID_PREAMBLE)) {
		/*
		 * If preamble is invalid, it means that DP has not received
		 * a data frame since assoc or roaming so there is no rates.
		 * In this case, using FW rates which was set previously.
		 */
		hdd_debug("Driver failed to get rate, reporting FW rate");
		return;
	}

	wlan_hdd_refill_os_rateflags(&sinfo->rxrate, preamble);

	sinfo->rxrate.mcs = link_info->hdd_stats.class_a_stat.rx_mcs_index;

	wlan_hdd_refill_os_bw(&sinfo->rxrate,
			      link_info->hdd_stats.class_a_stat.rx_bw);
	/* Fill out gi and dcm in HE mode */
	sinfo->rxrate.he_gi =
		hdd_map_he_gi_to_os(link_info->hdd_stats.class_a_stat.rx_gi);
	sinfo->rxrate.he_dcm = 0;

	if (link_info->hdd_stats.class_a_stat.rx_gi == TXRATE_GI_0_4_US)
		sinfo->rxrate.flags |= RATE_INFO_FLAGS_SHORT_GI;

	hdd_debug("sgi=%d, preamble=%d, bw=%d, mcs=%d, nss=%d, rate_flag=0x%x",
		  link_info->hdd_stats.class_a_stat.rx_gi, preamble,
		  link_info->hdd_stats.class_a_stat.rx_bw,
		  link_info->hdd_stats.class_a_stat.rx_mcs_index,
		  link_info->hdd_stats.class_a_stat.rx_nss,
		  sinfo->rxrate.flags);
}
#else
static inline void
wlan_hdd_refill_actual_rate(struct station_info *sinfo,
			    struct wlan_hdd_link_info *link_info)
{
}
#endif

static void wlan_hdd_update_rssi(struct wlan_hdd_link_info *link_info,
				 struct station_info *sinfo)
{
	struct hdd_station_ctx *sta_ctx;
	int8_t snr;
	mac_handle_t mac_handle;

	mac_handle = hdd_adapter_get_mac_handle(link_info->adapter);
	if (!mac_handle) {
		hdd_err("mac ctx NULL");
		return;
	}

	sta_ctx = WLAN_HDD_GET_STATION_CTX_PTR(link_info);
	link_info->rssi = link_info->hdd_stats.summary_stat.rssi;
	link_info->snr = link_info->hdd_stats.summary_stat.snr;
	snr = link_info->snr;

	/* for new connection there might be no valid previous RSSI */
	if (!link_info->rssi) {
		hdd_get_rssi_snr_by_bssid(mac_handle,
					  sta_ctx->conn_info.bssid.bytes,
					  &link_info->rssi, &snr);
	}

	/* If RSSi is reported as positive then it is invalid */
	if (link_info->rssi > 0) {
		hdd_debug_rl("RSSI invalid %d", link_info->rssi);
		link_info->rssi = 0;
		link_info->hdd_stats.summary_stat.rssi = 0;
	}

	sinfo->signal = link_info->rssi;
	hdd_debug("snr: %d, rssi: %d",
		  link_info->hdd_stats.summary_stat.snr,
		  link_info->hdd_stats.summary_stat.rssi);
	sta_ctx->conn_info.signal = sinfo->signal;
	sta_ctx->conn_info.noise = sta_ctx->conn_info.signal - snr;
	sta_ctx->cache_conn_info.signal = sinfo->signal;
	sta_ctx->cache_conn_info.noise = sta_ctx->conn_info.noise;
	sinfo->filled |= HDD_INFO_SIGNAL;
}

static void
wlan_hdd_update_mlo_peer_stats(struct wlan_hdd_link_info *link_info,
			       struct station_info *sinfo)
{
	ol_txrx_soc_handle soc;
	uint8_t *peer_mac;
	struct cdp_peer_stats *peer_stats;
	struct hdd_context *hdd_ctx = WLAN_HDD_GET_CTX(link_info->adapter);

	if (wlan_hdd_validate_context(hdd_ctx)) {
		hdd_err("invalid hdd_ctx");
		return;
	}

	soc = cds_get_context(QDF_MODULE_ID_SOC);
	peer_mac = link_info->session.station.conn_info.bssid.bytes;

	if (!wlan_hdd_is_per_link_stats_supported(hdd_ctx))
		return;

	peer_stats = qdf_mem_malloc(sizeof(*peer_stats));
	if (!peer_stats) {
		hdd_err("Failed to allocated memory for peer_stats");
		return;
	}

	ucfg_dp_get_per_link_peer_stats(soc, link_info->vdev_id,
					peer_mac, peer_stats,
					CDP_WILD_PEER_TYPE,
					WLAN_MAX_MLD);

	sinfo->tx_bytes = peer_stats->tx.tx_success.bytes;
	sinfo->rx_bytes = peer_stats->rx.rcvd.bytes;
	sinfo->rx_packets = peer_stats->rx.rcvd.num;

	hdd_nofl_debug("Updated sinfo with per peer stats");
	qdf_mem_free(peer_stats);
}

static int wlan_hdd_update_rate_info(struct wlan_hdd_link_info *link_info,
				     struct station_info *sinfo)
{
	struct hdd_context *hdd_ctx = WLAN_HDD_GET_CTX(link_info->adapter);
	struct hdd_station_ctx *sta_ctx;
	mac_handle_t mac_handle;
	struct wlan_objmgr_vdev *vdev;
	enum tx_rate_info rate_flags, tx_rate_flags, rx_rate_flags;
	enum txrate_gi tx_gi, rx_gi;
	uint32_t link_speed_rssi_report = 0;
	int link_speed_rssi_high = 0;
	int link_speed_rssi_mid = 0;
	int link_speed_rssi_low = 0;
	uint16_t my_tx_rate, my_rx_rate;
	uint8_t tx_mcs_index, rx_mcs_index;
	uint8_t tx_nss = 1, rx_nss = 1, tx_dcm, rx_dcm;
	qdf_net_dev_stats stats = {0};
	struct hdd_stats *hdd_stats;

	sta_ctx = WLAN_HDD_GET_STATION_CTX_PTR(link_info);
	ucfg_mlme_stats_get_cfg_values(hdd_ctx->psoc,
				       &link_speed_rssi_high,
				       &link_speed_rssi_mid,
				       &link_speed_rssi_low,
				       &link_speed_rssi_report);

	hdd_stats = &link_info->hdd_stats;
	rate_flags = hdd_stats->class_a_stat.tx_rx_rate_flags;
	tx_rate_flags = rx_rate_flags = rate_flags;

	tx_mcs_index = hdd_stats->class_a_stat.tx_mcs_index;
	rx_mcs_index = hdd_stats->class_a_stat.rx_mcs_index;
	mac_handle = hdd_ctx->mac_handle;

	/* convert to the UI units of 100kbps */
	my_tx_rate = hdd_stats->class_a_stat.tx_rate;
	my_rx_rate = hdd_stats->class_a_stat.rx_rate;

	tx_dcm = hdd_stats->class_a_stat.tx_dcm;
	rx_dcm = hdd_stats->class_a_stat.rx_dcm;
	tx_gi = hdd_stats->class_a_stat.tx_gi;
	rx_gi = hdd_stats->class_a_stat.rx_gi;

	if (!(rate_flags & TX_RATE_LEGACY)) {
		tx_nss = hdd_stats->class_a_stat.tx_nss;
		rx_nss = hdd_stats->class_a_stat.rx_nss;

		hdd_check_and_update_nss(hdd_ctx, &tx_nss, &rx_nss);

		if (ucfg_mlme_stats_is_link_speed_report_actual(hdd_ctx->psoc)) {
			/* Get current rate flags if report actual */
			/* WMA fails to find mcs_index for legacy tx rates */
			if (tx_mcs_index == INVALID_MCS_IDX && my_tx_rate)
				tx_rate_flags = TX_RATE_LEGACY;
			else
				tx_rate_flags =
				    hdd_stats->class_a_stat.tx_mcs_rate_flags;

			if (rx_mcs_index == INVALID_MCS_IDX && my_rx_rate)
				rx_rate_flags = TX_RATE_LEGACY;
			else
				rx_rate_flags =
				    hdd_stats->class_a_stat.rx_mcs_rate_flags;
		}

		if (tx_mcs_index == INVALID_MCS_IDX)
			tx_mcs_index = 0;
		if (rx_mcs_index == INVALID_MCS_IDX)
			rx_mcs_index = 0;
	}

	hdd_debug("[RSSI %d, RLMS %u, rssi high %d, rssi mid %d, rssi low %d]-"
		  "[Rate info: TX: %d, RX: %d]-[Rate flags: TX: 0x%x, RX: 0x%x]"
		  "-[MCS Index: TX: %d, RX: %d]-[NSS: TX: %d, RX: %d]-"
		  "[dcm: TX: %d, RX: %d]-[guard interval: TX: %d, RX: %d",
		  sinfo->signal, link_speed_rssi_report,
		  link_speed_rssi_high, link_speed_rssi_mid,
		  link_speed_rssi_low, my_tx_rate, my_rx_rate,
		  (int)tx_rate_flags, (int)rx_rate_flags, (int)tx_mcs_index,
		  (int)rx_mcs_index, (int)tx_nss, (int)rx_nss,
		  (int)tx_dcm, (int)rx_dcm, (int)tx_gi, (int)rx_gi);

	vdev = hdd_objmgr_get_vdev_by_user(link_info, WLAN_OSIF_STATS_ID);

	if (!vdev) {
		hdd_nofl_debug("vdev object NULL");
		return -EINVAL;
	}

	if (!ucfg_mlme_stats_is_link_speed_report_actual(hdd_ctx->psoc)) {
		bool tx_rate_calc, rx_rate_calc;
		uint8_t tx_nss_max, rx_nss_max;

		/*
		 * Take static NSS for reporting max rates. NSS from the FW
		 * is not reliable as it changes as per the environment
		 * quality.
		 */
		tx_nss_max = wlan_vdev_mlme_get_nss(vdev);
		rx_nss_max = wlan_vdev_mlme_get_nss(vdev);

		hdd_check_and_update_nss(hdd_ctx, &tx_nss_max, &rx_nss_max);

		tx_rate_calc = hdd_report_max_rate(link_info, mac_handle,
						   &sinfo->txrate,
						   sinfo->signal,
						   tx_rate_flags,
						   tx_mcs_index,
						   my_tx_rate,
						   tx_nss_max);

		rx_rate_calc = hdd_report_max_rate(link_info, mac_handle,
						   &sinfo->rxrate,
						   sinfo->signal,
						   rx_rate_flags,
						   rx_mcs_index,
						   my_rx_rate,
						   rx_nss_max);

		if (!tx_rate_calc || !rx_rate_calc) {
			hdd_report_actual_rate(tx_rate_flags, my_tx_rate,
					       &sinfo->txrate, tx_mcs_index,
					       tx_nss, tx_dcm, tx_gi);

			hdd_report_actual_rate(rx_rate_flags, my_rx_rate,
					       &sinfo->rxrate, rx_mcs_index,
					       rx_nss, rx_dcm, rx_gi);
		}
	} else {
		/* Fill TX stats */
		hdd_report_actual_rate(tx_rate_flags, my_tx_rate,
				       &sinfo->txrate, tx_mcs_index,
				       tx_nss, tx_dcm, tx_gi);

		/* Fill RX stats */
		hdd_report_actual_rate(rx_rate_flags, my_rx_rate,
				       &sinfo->rxrate, rx_mcs_index,
				       rx_nss, rx_dcm, rx_gi);

		/* Using driver RX rate to replace the FW RX rate */
		wlan_hdd_refill_actual_rate(sinfo, link_info);
	}

	wlan_hdd_fill_summary_stats(&hdd_stats->summary_stat,
				    sinfo, link_info->vdev_id);

	ucfg_dp_get_net_dev_stats(vdev, &stats);
	sinfo->tx_bytes = stats.tx_bytes;
	sinfo->rx_bytes = stats.rx_bytes;
	sinfo->rx_packets = stats.rx_packets;
	wlan_hdd_update_mlo_peer_stats(link_info, sinfo);

	hdd_objmgr_put_vdev_by_user(vdev, WLAN_OSIF_STATS_ID);

	qdf_mem_copy(&sta_ctx->conn_info.txrate,
		     &sinfo->txrate, sizeof(sinfo->txrate));
	qdf_mem_copy(&sta_ctx->cache_conn_info.txrate,
		     &sinfo->txrate, sizeof(sinfo->txrate));

	qdf_mem_copy(&sta_ctx->conn_info.rxrate,
		     &sinfo->rxrate, sizeof(sinfo->rxrate));

	sinfo->filled |= HDD_INFO_TX_BITRATE |
			 HDD_INFO_RX_BITRATE |
			 HDD_INFO_TX_BYTES   |
			 HDD_INFO_RX_BYTES   |
			 HDD_INFO_RX_PACKETS;

	if (tx_rate_flags & TX_RATE_LEGACY) {
		hdd_debug("[TX: Reporting legacy rate %d pkt cnt %d]-"
			  "[RX: Reporting legacy rate %d pkt cnt %d]",
			  sinfo->txrate.legacy, sinfo->tx_packets,
			  sinfo->rxrate.legacy, sinfo->rx_packets);
	} else {
		hdd_debug("[TX: Reporting MCS rate %d, flags 0x%x pkt cnt %d, nss %d, bw %d]-"
			  "[RX: Reporting MCS rate %d, flags 0x%x pkt cnt %d, nss %d, bw %d]",
			  sinfo->txrate.mcs, sinfo->txrate.flags,
			  sinfo->tx_packets, sinfo->txrate.nss,
			  sinfo->txrate.bw, sinfo->rxrate.mcs,
			  sinfo->rxrate.flags, sinfo->rx_packets,
			  sinfo->rxrate.nss, sinfo->rxrate.bw);
	}

	return 0;
}

/**
 * wlan_hdd_get_sta_stats() - get aggregate STA stats
 * @link_info: Link info pointer of STA adapter to get stats for
 * @mac: mac address of sta
 * @sinfo: kernel station_info struct to populate
 *
 * Fetch the vdev-level aggregate stats for the given STA adapter. This is to
 * support "station dump" and "station get" for STA vdevs
 *
 * Return: errno
 */
static int wlan_hdd_get_sta_stats(struct wlan_hdd_link_info *link_info,
				  const uint8_t *mac,
				  struct station_info *sinfo)
{
	struct hdd_adapter *adapter = link_info->adapter;
	struct hdd_context *hdd_ctx = WLAN_HDD_GET_CTX(adapter);
	struct hdd_station_ctx *sta_ctx;
	uint8_t *link_mac;
	int32_t rcpi_value;

	qdf_mtrace(QDF_MODULE_ID_HDD, QDF_MODULE_ID_HDD,
		   TRACE_CODE_HDD_CFG80211_GET_STA,
		   link_info->vdev_id, 0);

	if (link_info->vdev_id == WLAN_UMAC_VDEV_ID_MAX) {
		wlan_hdd_update_sinfo(sinfo, link_info);
		hdd_debug_rl("Sending Cached stats for standby link");
		return 0;
	}

	if (!hdd_cm_is_vdev_associated(link_info)) {
		hdd_debug("Not associated");
		/*To keep GUI happy */
		return 0;
	}

	if (hdd_is_roam_sync_in_progress(hdd_ctx, link_info->vdev_id)) {
		hdd_debug("Roam sync is in progress, cannot continue with this request");
		/*
		 * supplicant reports very low rssi to upper layer
		 * and handover happens to cellular.
		 * send the cached rssi when get_station
		 */
		sinfo->signal = link_info->rssi;
		sinfo->filled |= HDD_INFO_SIGNAL;
		return 0;
	}

	if (hdd_ctx->rcpi_enabled)
		wlan_hdd_get_rcpi(adapter, (uint8_t *)mac, &rcpi_value,
				  RCPI_MEASUREMENT_TYPE_AVG_MGMT);

	wlan_hdd_get_station_stats(link_info);

	wlan_hdd_get_peer_rx_rate_stats(link_info);

	wlan_hdd_update_rssi(link_info, sinfo);

	/*
	 * we notify connect to lpass here instead of during actual
	 * connect processing because rssi info is not accurate during
	 * actual connection.  lpass will ensure the notification is
	 * only processed once per association.
	 */
	hdd_lpass_notify_connect(link_info);

	if (wlan_hdd_update_rate_info(link_info, sinfo))
		/* Keep GUI happy */
		return 0;

	hdd_fill_fcs_and_mpdu_count(link_info, sinfo);

	hdd_wlan_fill_per_chain_rssi_stats(sinfo, link_info);

	sta_ctx = WLAN_HDD_GET_STATION_CTX_PTR(link_info);
	link_mac = sta_ctx->conn_info.bssid.bytes;
	hdd_nofl_debug("Sending station stats for link " QDF_MAC_ADDR_FMT,
		       QDF_MAC_ADDR_REF(link_mac));

	wlan_hdd_copy_sinfo_to_link_info(link_info, sinfo);

	hdd_exit();

	return 0;
}

#if defined(WLAN_FEATURE_11BE_MLO) && defined(CFG80211_11BE_BASIC)
/*
 * wlan_hdd_update_mlo_rate_info() - Populate mlo station stats rate info
 * @hdd_sinfo: Pointer to hdd stats station info struct
 * @sinfo: Pointer to kernel station info struct
 *
 * Return: none
 */
static void
wlan_hdd_update_mlo_rate_info(struct wlan_hdd_station_stats_info *hdd_sinfo,
			      struct station_info *sinfo)
{
	uint8_t i;

	hdd_sinfo->signal = sinfo->signal;
	hdd_sinfo->signal_avg = sinfo->signal_avg;
	for (i = 0; i < IEEE80211_MAX_CHAINS; i++)
		hdd_sinfo->chain_signal_avg[i] = sinfo->chain_signal_avg[i];

	qdf_mem_copy(&hdd_sinfo->txrate,
		     &sinfo->txrate, sizeof(sinfo->txrate));

	qdf_mem_copy(&hdd_sinfo->rxrate,
		     &sinfo->rxrate, sizeof(sinfo->rxrate));
}

/*
 * wlan_hdd_update_mlo_sinfo() - Populate mlo stats station info
 * @link_info: Link info pointer of STA adapter
 * @hdd_sinfo: Pointer to hdd stats station info struct
 * @sinfo: Pointer to kernel station info struct
 *
 * Return: none
 */
static void
wlan_hdd_update_mlo_sinfo(struct wlan_hdd_link_info *link_info,
			  struct wlan_hdd_station_stats_info *hdd_sinfo,
			  struct station_info *sinfo)
{
	struct hdd_station_ctx *sta_ctx;

	sta_ctx = WLAN_HDD_GET_STATION_CTX_PTR(link_info);

	if (!link_info->is_mlo_vdev_active)
		hdd_nofl_debug("vdev_id[%d] is inactive", link_info->vdev_id);

	/* Update the rate info for link with best RSSI */
	if (sinfo->signal > hdd_sinfo->signal) {
		hdd_nofl_debug("Updating rates for link_id %d",
			       sta_ctx->conn_info.ieee_link_id);
		wlan_hdd_update_mlo_rate_info(hdd_sinfo, sinfo);
	}

	/* Send cumulative Tx/Rx packets and bytes data
	 * of all active links to userspace
	 */
	hdd_sinfo->rx_bytes += sinfo->rx_bytes;
	hdd_sinfo->tx_bytes += sinfo->tx_bytes;
	hdd_sinfo->rx_packets += sinfo->rx_packets;
	hdd_sinfo->tx_packets += sinfo->tx_packets;
	hdd_sinfo->tx_retries += sinfo->tx_retries;
	hdd_sinfo->tx_failed += sinfo->tx_failed;
	hdd_sinfo->rx_mpdu_count += sinfo->rx_mpdu_count;
	hdd_sinfo->fcs_err_count += sinfo->fcs_err_count;
}

#ifndef WLAN_HDD_MULTI_VDEV_SINGLE_NDEV
/**
 * wlan_hdd_get_mlo_sta_stats - get aggregate STA stats for MLO
 * @adapter: HDD adapter
 * @mac: mac address
 * @sinfo: kernel station_info struct to populate
 *
 * Return: 0 on success; errno on failure
 */
static int wlan_hdd_get_mlo_sta_stats(struct hdd_adapter *adapter,
				      const uint8_t *mac,
				      struct station_info *sinfo)
{
	struct hdd_adapter *ml_adapter, *link_adapter;
	struct hdd_mlo_adapter_info *mlo_adapter_info;
	struct wlan_hdd_station_stats_info hdd_sinfo = {0};
	uint8_t i;

	/* Initialize the signal value to a default RSSI of -128dBm */
	hdd_sinfo.signal = WLAN_INVALID_RSSI_VALUE;

	ml_adapter = adapter;
	if (hdd_adapter_is_link_adapter(ml_adapter))
		ml_adapter = hdd_adapter_get_mlo_adapter_from_link(adapter);

	wlan_hdd_get_sta_stats(ml_adapter->deflink, mac, sinfo);
	wlan_hdd_update_mlo_sinfo(ml_adapter->deflink, &hdd_sinfo, sinfo);

	mlo_adapter_info = &ml_adapter->mlo_adapter_info;
	for (i = 0; i < WLAN_MAX_MLD; i++) {
		link_adapter = mlo_adapter_info->link_adapter[i];
		if (!link_adapter ||
		    hdd_adapter_is_associated_with_ml_adapter(link_adapter))
			continue;

		wlan_hdd_get_sta_stats(link_adapter->deflink, mac, sinfo);
		wlan_hdd_update_mlo_sinfo(link_adapter->deflink, &hdd_sinfo,
					  sinfo);
	}

	wlan_hdd_copy_hdd_stats_to_sinfo(sinfo, &hdd_sinfo);
	hdd_nofl_debug("Sending aggregated mlo station stats");

	hdd_exit();

	return 0;
}
#else
static int wlan_hdd_get_mlo_sta_stats(struct hdd_adapter *adapter,
				      const uint8_t *mac,
				      struct station_info *sinfo)
{
	struct wlan_hdd_link_info *link_info;
	struct wlan_hdd_station_stats_info hdd_sinfo = {0};
	struct hdd_station_ctx *sta_ctx;

	/* Initialize the signal value to a default RSSI of -128dBm */
	hdd_sinfo.signal = WLAN_INVALID_RSSI_VALUE;

	hdd_adapter_for_each_link_info(adapter, link_info) {
		sta_ctx = WLAN_HDD_GET_STATION_CTX_PTR(link_info);
		if (sta_ctx->conn_info.ieee_link_id == WLAN_INVALID_LINK_ID)
			continue;
		wlan_hdd_get_sta_stats(link_info, mac, sinfo);
		wlan_hdd_update_mlo_sinfo(link_info, &hdd_sinfo, sinfo);
	}

	wlan_hdd_copy_hdd_stats_to_sinfo(sinfo, &hdd_sinfo);
	hdd_nofl_debug("Sending aggregated mlo station stats");

	hdd_exit();

	return 0;
}
#endif
#else
static int wlan_hdd_get_mlo_sta_stats(struct hdd_adapter *adapter,
				      const uint8_t *mac,
				      struct station_info *sinfo)
{
	return wlan_hdd_get_sta_stats(adapter->deflink, mac, sinfo);
}
#endif

/*
 * wlan_is_mlo_aggregated_stats_allowed() - Is aggregated stats requested
 * @adapter: HDD adapter
 * @mac: mac address
 *
 * Return: True if req is on mld_mac and FW supports per link stats, else False
 */
static bool
wlan_is_mlo_aggregated_stats_allowed(struct hdd_adapter *adapter,
				     const uint8_t *mac)
{
	struct hdd_context *hdd_ctx = WLAN_HDD_GET_CTX(adapter);
	bool is_mld_req = false;
	bool per_link_stats_cap = false;
	struct qdf_mac_addr peer_mld_mac;
	QDF_STATUS status;

	if (!hdd_ctx) {
		hdd_err("invalid hdd_ctx");
		return false;
	}

	status = wlan_hdd_get_bss_peer_mld_mac(adapter->deflink, &peer_mld_mac);
	if (QDF_IS_STATUS_ERROR(status)) {
		hdd_err_rl("mlo_vdev_stats: failed to get bss peer mld mac");
		return false;
	}

	is_mld_req = qdf_is_macaddr_equal(&peer_mld_mac,
					  (struct qdf_mac_addr *)mac);
	per_link_stats_cap = wlan_hdd_is_per_link_stats_supported(hdd_ctx);

	if (is_mld_req && per_link_stats_cap) {
		hdd_debug_rl("Fetching Aggregated station stats");
		return true;
	}

	return false;
}

/**
 * wlan_hdd_send_mlo_station_stats() - send station stats to userspace
 * @adapter: Pointer to hdd adapter
 * @hdd_ctx: Pointer to hdd context
 * @mac: mac address
 * @sinfo: kernel station_info struct to populate
 *
 * Return: 0 on success; errno on failure
 */
static int wlan_hdd_send_mlo_station_stats(struct hdd_adapter *adapter,
					   struct hdd_context *hdd_ctx,
					   const uint8_t *mac,
					   struct station_info *sinfo)
{
	struct wlan_hdd_link_info *link_info;

	if (!wlan_hdd_is_mlo_connection(adapter->deflink)) {
		hdd_nofl_debug("Fetching station stats for legacy connection");
		return wlan_hdd_get_sta_stats(adapter->deflink, mac, sinfo);
	}

	link_info = hdd_get_link_info_by_bssid(hdd_ctx, mac);
	if (!link_info) {
		if (wlan_is_mlo_aggregated_stats_allowed(adapter, mac))
			return wlan_hdd_get_mlo_sta_stats(adapter, mac, sinfo);

		hdd_debug_rl("Invalid bssid");
		return -EINVAL;
	}
	return wlan_hdd_get_sta_stats(link_info, mac, sinfo);
}

/**
 * __wlan_hdd_cfg80211_get_station() - get station statistics
 * @wiphy: Pointer to wiphy
 * @dev: Pointer to network device
 * @mac: Pointer to mac
 * @sinfo: Pointer to station info
 *
 * Return: 0 for success, non-zero for failure
 */
static int __wlan_hdd_cfg80211_get_station(struct wiphy *wiphy,
					   struct net_device *dev,
					   const uint8_t *mac,
					   struct station_info *sinfo)
{
	int errno;
	struct hdd_adapter *adapter = WLAN_HDD_GET_PRIV_PTR(dev);
	struct hdd_context *hdd_ctx = wiphy_priv(wiphy);
	struct hdd_station_info *stainfo;
	bool get_peer_info_enable;
	QDF_STATUS qdf_status;
	struct wlan_hdd_link_info *link_info = adapter->deflink;

	hdd_enter_dev(dev);

	if (QDF_GLOBAL_FTM_MODE == hdd_get_conparam()) {
		hdd_err("Command not allowed in FTM mode");
		return -EINVAL;
	}

	if (wlan_hdd_validate_context(hdd_ctx))
		return -EINVAL;

	if (wlan_hdd_validate_vdev_id(link_info->vdev_id))
		return -EINVAL;

	hdd_nofl_debug("Stats request on MAC: " QDF_MAC_ADDR_FMT,
		       QDF_MAC_ADDR_REF(mac));

	if (!mac || qdf_is_macaddr_zero((struct qdf_mac_addr *)mac)) {
		hdd_err("Invalid MAC addr");
		return -EINVAL;
	}

	if (adapter->device_mode == QDF_SAP_MODE ||
	    adapter->device_mode == QDF_P2P_GO_MODE) {
		qdf_status = ucfg_mlme_get_sap_get_peer_info(
				hdd_ctx->psoc, &get_peer_info_enable);
		if (qdf_status == QDF_STATUS_SUCCESS && get_peer_info_enable) {
			stainfo = hdd_get_sta_info_by_mac(
					&adapter->sta_info_list, mac,
					STA_INFO_WLAN_HDD_CFG80211_GET_STATION);
			if (!stainfo) {
				hdd_debug("Peer " QDF_MAC_ADDR_FMT " not found",
					  QDF_MAC_ADDR_REF(mac));
				return -EINVAL;
			}

			errno = wlan_hdd_get_station_remote(wiphy, dev,
							    stainfo, sinfo);
			hdd_put_sta_info_ref(&adapter->sta_info_list, &stainfo,
					     true,
					STA_INFO_WLAN_HDD_CFG80211_GET_STATION
					);
			if (!errno)
				return 0;
		}
		return wlan_hdd_get_sap_stats(link_info, sinfo);
	}

	return wlan_hdd_send_mlo_station_stats(adapter, hdd_ctx, mac, sinfo);
}

/**
 * _wlan_hdd_cfg80211_get_station() - get station statistics
 *
 * @wiphy: Pointer to wiphy
 * @dev: Pointer to network device
 * @mac: Pointer to mac
 * @sinfo: Pointer to station info
 *
 * This API tries runtime PM suspend right away after getting station
 * statistics.
 *
 * Return: 0 for success, non-zero for failure
 */
static int _wlan_hdd_cfg80211_get_station(struct wiphy *wiphy,
					  struct net_device *dev,
					  const uint8_t *mac,
					  struct station_info *sinfo)
{
	struct hdd_context *hdd_ctx = wiphy_priv(wiphy);
	struct hdd_adapter *adapter = WLAN_HDD_GET_PRIV_PTR(dev);
	int errno;
	QDF_STATUS status;

	errno = wlan_hdd_validate_context(hdd_ctx);
	if (errno)
		return errno;

	if (wlan_hdd_is_link_switch_in_progress(adapter->deflink)) {
		hdd_debug("Link Switch in progress, can't process request");
		return -EBUSY;
	}

	status = wlan_hdd_stats_request_needed(adapter);
	if (QDF_IS_STATUS_ERROR(status)) {
		if (status == QDF_STATUS_E_ALREADY)
			get_station_fw_request_needed = false;
		else
			return -EINVAL;
	}

	if (get_station_fw_request_needed) {
		errno = wlan_hdd_qmi_get_sync_resume();
		if (errno) {
			hdd_err("qmi sync resume failed: %d", errno);
			return errno;
		}
	}

	errno = __wlan_hdd_cfg80211_get_station(wiphy, dev, mac, sinfo);

	if (get_station_fw_request_needed)
		wlan_hdd_qmi_put_suspend();

	get_station_fw_request_needed = true;

	return errno;
}

/**
 * wlan_hdd_cfg80211_get_station() - get station statistics
 * @wiphy: Pointer to wiphy
 * @dev: Pointer to network device
 * @mac: Pointer to mac
 * @sinfo: Pointer to station info
 *
 * Return: 0 for success, non-zero for failure
 */
int wlan_hdd_cfg80211_get_station(struct wiphy *wiphy,
				  struct net_device *dev, const uint8_t *mac,
				  struct station_info *sinfo)
{
	int errno;
	struct osif_vdev_sync *vdev_sync;

	errno = osif_vdev_sync_op_start(dev, &vdev_sync);
	if (errno)
		return errno;

	errno = _wlan_hdd_cfg80211_get_station(wiphy, dev, mac, sinfo);

	osif_vdev_sync_op_stop(vdev_sync);

	return errno;
}

/**
 * __wlan_hdd_cfg80211_dump_station() - dump station statistics
 * @wiphy: Pointer to wiphy
 * @dev: Pointer to network device
 * @idx: variable to station index, kernel iterate all stations over idx
 * @mac: Pointer to mac
 * @sinfo: Pointer to station info
 *
 * Return: 0 for success, non-zero for failure
 */
static int __wlan_hdd_cfg80211_dump_station(struct wiphy *wiphy,
				struct net_device *dev,
				int idx, u8 *mac,
				struct station_info *sinfo)
{
	int errno;
	struct hdd_adapter *adapter = WLAN_HDD_GET_PRIV_PTR(dev);
	struct hdd_context *hdd_ctx = wiphy_priv(wiphy);
	struct hdd_station_info *stainfo;
	bool get_peer_info_enable;
	QDF_STATUS qdf_status;

	hdd_debug("idx: %d", idx);

	if (QDF_GLOBAL_FTM_MODE == hdd_get_conparam()) {
		hdd_err("Command not allowed in FTM mode");
		return -EINVAL;
	}

	if (wlan_hdd_validate_context(hdd_ctx))
		return -EINVAL;

	if (wlan_hdd_validate_vdev_id(adapter->deflink->vdev_id))
		return -EINVAL;

	if (wlan_hdd_is_link_switch_in_progress(adapter->deflink)) {
		hdd_debug("Link Switch in progress, can't process request");
		return -EBUSY;
	}

	if (adapter->device_mode == QDF_SAP_MODE ||
	    adapter->device_mode == QDF_P2P_GO_MODE) {
		qdf_status = ucfg_mlme_get_sap_get_peer_info(
				hdd_ctx->psoc, &get_peer_info_enable);
		if (qdf_status == QDF_STATUS_SUCCESS && get_peer_info_enable) {
			stainfo = hdd_get_sta_info_by_id(
					&adapter->sta_info_list,
					idx,
					STA_INFO_WLAN_HDD_CFG80211_DUMP_STATION
					);
			if (!stainfo) {
				hdd_err("peer idx %d NOT FOUND", idx);
				return -ENOENT;
			}

			qdf_mem_copy(mac, &stainfo->sta_mac.bytes,
				     QDF_MAC_ADDR_SIZE);
			errno = wlan_hdd_get_station_remote(wiphy, dev,
							    stainfo, sinfo);
			hdd_put_sta_info_ref(&adapter->sta_info_list, &stainfo,
					     true,
					STA_INFO_WLAN_HDD_CFG80211_DUMP_STATION
					);
		} else {
			errno = -EINVAL;
			hdd_err("sap get peer info disabled!");
		}
	} else {
		if (idx != 0)
			return -ENOENT;

		qdf_mem_copy(mac, dev->dev_addr, QDF_MAC_ADDR_SIZE);

		if (wlan_hdd_is_mlo_connection(adapter->deflink) &&
		    wlan_hdd_is_per_link_stats_supported(hdd_ctx))
			return wlan_hdd_get_mlo_sta_stats(adapter, mac, sinfo);

		hdd_nofl_debug("Sending Assoc Link stats");
		errno = wlan_hdd_get_sta_stats(adapter->deflink, mac, sinfo);
	}
	return errno;
}

/**
 * wlan_hdd_cfg80211_dump_station() - dump station statistics
 * @wiphy: Pointer to wiphy
 * @dev: Pointer to network device
 * @idx: variable to determine whether to get stats or not
 * @mac: Pointer to mac
 * @sinfo: Pointer to station info
 *
 * Return: 0 for success, non-zero for failure
 */
int wlan_hdd_cfg80211_dump_station(struct wiphy *wiphy,
				struct net_device *dev,
				int idx, u8 *mac,
				struct station_info *sinfo)
{
	int errno;
	struct osif_vdev_sync *vdev_sync;

	errno = osif_vdev_sync_op_start(dev, &vdev_sync);
	if (errno)
		return errno;

	errno = wlan_hdd_qmi_get_sync_resume();
	if (errno) {
		hdd_err("qmi sync resume failed: %d", errno);
		goto end;
	}

	errno = __wlan_hdd_cfg80211_dump_station(wiphy, dev, idx, mac, sinfo);

	wlan_hdd_qmi_put_suspend();

end:
	osif_vdev_sync_op_stop(vdev_sync);

	return errno;
}

/**
 * hdd_get_stats() - Function to retrieve interface statistics
 * @dev: pointer to network device
 *
 * This function is the ndo_get_stats method for all netdevs
 * registered with the kernel
 *
 * Return: pointer to net_device_stats structure
 */
struct net_device_stats *hdd_get_stats(struct net_device *dev)
{
	return (struct net_device_stats *)ucfg_dp_get_dev_stats(dev);
}

/*
 * FW sends value of cycle_count, rx_clear_count and tx_frame_count in usec.
 */
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4, 0, 0))
static bool wlan_fill_survey_result(struct survey_info *survey, int opfreq,
				    struct scan_chan_info *chan_info,
				    struct ieee80211_channel *channels)
{
	if (channels->center_freq != (uint16_t)chan_info->freq)
		return false;

	survey->channel = channels;
	survey->noise = chan_info->noise_floor;
	survey->filled = 0;

	if (chan_info->noise_floor)
		survey->filled |= SURVEY_INFO_NOISE_DBM;

	if (opfreq == chan_info->freq)
		survey->filled |= SURVEY_INFO_IN_USE;

	survey->time = chan_info->cycle_count;
	survey->time_busy = chan_info->rx_clear_count;
	survey->time_tx = chan_info->tx_frame_count;

	survey->filled |= SURVEY_INFO_TIME |
			  SURVEY_INFO_TIME_BUSY |
			  SURVEY_INFO_TIME_TX;
	return true;
}
#else
static bool wlan_fill_survey_result(struct survey_info *survey, int opfreq,
				    struct scan_chan_info *chan_info,
				    struct ieee80211_channel *channels)
{
	if (channels->center_freq != (uint16_t)chan_info->freq)
		return false;

	survey->channel = channels;
	survey->noise = chan_info->noise_floor;
	survey->filled = 0;

	if (chan_info->noise_floor)
		survey->filled |= SURVEY_INFO_NOISE_DBM;

	if (opfreq == chan_info->freq)
		survey->filled |= SURVEY_INFO_IN_USE;

	survey->channel_time = chan_info->cycle_count;
	survey->channel_time_busy = chan_info->rx_clear_count;
	survey->channel_time_tx = chan_info->tx_frame_count;

	survey->filled |= SURVEY_INFO_CHANNEL_TIME |
			  SURVEY_INFO_CHANNEL_TIME_BUSY |
			  SURVEY_INFO_CHANNEL_TIME_TX;
	return true;
}
#endif

static bool wlan_hdd_update_survey_info(struct wiphy *wiphy,
					struct hdd_adapter *adapter,
					struct survey_info *survey, int idx)
{
	bool filled = false;
	int i, j = 0;
	uint32_t opfreq = 0; /* Initialization Required */
	struct hdd_context *hdd_ctx;

	hdd_ctx = WLAN_HDD_GET_CTX(adapter);
	sme_get_operation_channel(hdd_ctx->mac_handle, &opfreq,
				  adapter->deflink->vdev_id);

	mutex_lock(&hdd_ctx->chan_info_lock);

	for (i = 0; i < HDD_NUM_NL80211_BANDS && !filled; i++) {
		if (!wiphy->bands[i])
			continue;

		for (j = 0; j < wiphy->bands[i]->n_channels && !filled; j++) {
			struct ieee80211_supported_band *band = wiphy->bands[i];

			filled = wlan_fill_survey_result(survey, opfreq,
				&hdd_ctx->chan_info[idx],
				&band->channels[j]);
		}
	}
	mutex_unlock(&hdd_ctx->chan_info_lock);

	return filled;
}

/**
 * __wlan_hdd_cfg80211_dump_survey() - get survey related info
 * @wiphy: Pointer to wiphy
 * @dev: Pointer to network device
 * @idx: Index
 * @survey: Pointer to survey info
 *
 * Return: 0 for success, non-zero for failure
 */
static int __wlan_hdd_cfg80211_dump_survey(struct wiphy *wiphy,
					   struct net_device *dev,
					   int idx, struct survey_info *survey)
{
	struct hdd_adapter *adapter = WLAN_HDD_GET_PRIV_PTR(dev);
	struct hdd_context *hdd_ctx;
	int status;
	bool filled = false;

	if (idx > NUM_CHANNELS - 1)
		return -ENOENT;

	hdd_ctx = WLAN_HDD_GET_CTX(adapter);
	status = wlan_hdd_validate_context(hdd_ctx);
	if (0 != status)
		return status;

	if (!hdd_ctx->chan_info) {
		hdd_debug("chan_info is NULL");
		return -EINVAL;
	}

	if (hdd_get_conparam() == QDF_GLOBAL_FTM_MODE) {
		hdd_err("Command not allowed in FTM mode");
		return -EINVAL;
	}

	if (!ucfg_scan_is_snr_monitor_enabled(hdd_ctx->psoc))
		return -ENONET;

	if (hdd_cm_is_vdev_roaming(adapter->deflink)) {
		hdd_debug("Roaming in progress, hence return");
		return -ENONET;
	}

	filled = wlan_hdd_update_survey_info(wiphy, adapter, survey, idx);

	if (!filled)
		return -ENOENT;

	return 0;
}

/**
 * wlan_hdd_cfg80211_dump_survey() - get survey related info
 * @wiphy: Pointer to wiphy
 * @dev: Pointer to network device
 * @idx: Index
 * @survey: Pointer to survey info
 *
 * Return: 0 for success, non-zero for failure
 */
int wlan_hdd_cfg80211_dump_survey(struct wiphy *wiphy,
				  struct net_device *dev,
				  int idx, struct survey_info *survey)
{
	int errno;
	struct osif_vdev_sync *vdev_sync;

	errno = osif_vdev_sync_op_start(dev, &vdev_sync);
	if (errno)
		return errno;

	errno = __wlan_hdd_cfg80211_dump_survey(wiphy, dev, idx, survey);

	osif_vdev_sync_op_stop(vdev_sync);

	return errno;
}

/**
 * hdd_display_hif_stats() - display hif stats
 *
 * Return: none
 *
 */
void hdd_display_hif_stats(void)
{
	void *hif_ctx = cds_get_context(QDF_MODULE_ID_HIF);

	if (!hif_ctx)
		return;

	hif_display_stats(hif_ctx);
}

/**
 * hdd_clear_hif_stats() - clear hif stats
 *
 * Return: none
 */
void hdd_clear_hif_stats(void)
{
	void *hif_ctx = cds_get_context(QDF_MODULE_ID_HIF);

	if (!hif_ctx)
		return;
	hif_clear_stats(hif_ctx);
}

/**
 * hdd_is_rcpi_applicable() - validates RCPI request
 * @adapter: adapter upon which the measurement is requested
 * @mac_addr: peer addr for which measurement is requested
 * @rcpi_value: pointer to where the RCPI should be returned
 * @reassoc: used to return cached RCPI during reassoc
 *
 * Return: true for success, false for failure
 */

static bool hdd_is_rcpi_applicable(struct hdd_adapter *adapter,
				   struct qdf_mac_addr *mac_addr,
				   int32_t *rcpi_value,
				   bool *reassoc)
{
	struct hdd_station_ctx *hdd_sta_ctx;

	if (adapter->device_mode == QDF_STA_MODE ||
	    adapter->device_mode == QDF_P2P_CLIENT_MODE) {
		hdd_sta_ctx = WLAN_HDD_GET_STATION_CTX_PTR(adapter->deflink);
		if (!hdd_cm_is_vdev_associated(adapter->deflink))
			return false;

		if (hdd_cm_is_vdev_roaming(adapter->deflink)) {
			/* return the cached rcpi, if mac addr matches */
			hdd_debug("Roaming in progress, return cached RCPI");
			if (!qdf_mem_cmp(&adapter->rcpi.mac_addr,
					 mac_addr, sizeof(*mac_addr))) {
				*rcpi_value = adapter->rcpi.rcpi;
				*reassoc = true;
				return true;
			}
			return false;
		}

		if (qdf_mem_cmp(mac_addr, &hdd_sta_ctx->conn_info.bssid,
				sizeof(*mac_addr))) {
			hdd_err("mac addr is different from bssid connected");
			return false;
		}
	} else if (adapter->device_mode == QDF_SAP_MODE ||
		   adapter->device_mode == QDF_P2P_GO_MODE) {
		if (!test_bit(SOFTAP_BSS_STARTED,
			      &adapter->deflink->link_flags)) {
			hdd_err("Invalid rcpi request, softap not started");
			return false;
		}

		/* check if peer mac addr is associated to softap */
		if (!hdd_is_peer_associated(adapter, mac_addr)) {
			hdd_err("invalid peer mac-addr: not associated");
			return false;
		}
	} else {
		hdd_err("Invalid rcpi request");
		return false;
	}

	*reassoc = false;
	return true;
}

/**
 * wlan_hdd_get_rcpi_cb() - callback function for rcpi response
 * @context: Pointer to rcpi context
 * @mac_addr: peer MAC address
 * @rcpi: RCPI response
 * @status: QDF_STATUS of the request
 *
 * Return: None
 */
static void wlan_hdd_get_rcpi_cb(void *context, struct qdf_mac_addr mac_addr,
				 int32_t rcpi, QDF_STATUS status)
{
	struct osif_request *request;
	struct rcpi_info *priv;

	if (!context) {
		hdd_err("No rcpi context");
		return;
	}

	request = osif_request_get(context);
	if (!request) {
		hdd_err("Obsolete RCPI request");
		return;
	}

	priv = osif_request_priv(request);
	priv->mac_addr = mac_addr;

	if (!QDF_IS_STATUS_SUCCESS(status)) {
		priv->rcpi = 0;
		hdd_err("Error in computing RCPI");
	} else {
		priv->rcpi = rcpi;
	}

	osif_request_complete(request);
	osif_request_put(request);
}

/**
 * wlan_hdd_get_rcpi() - local function to get RCPI
 * @adapter: adapter upon which the measurement is requested
 * @mac: peer addr for which measurement is requested
 * @rcpi_value: pointer to where the RCPI should be returned
 * @measurement_type: type of rcpi measurement
 *
 * Return: 0 for success, non-zero for failure
 */
int wlan_hdd_get_rcpi(struct hdd_adapter *adapter,
		      uint8_t *mac,
		      int32_t *rcpi_value,
		      enum rcpi_measurement_type measurement_type)
{
	struct hdd_context *hdd_ctx;
	int status = 0, ret = 0;
	struct qdf_mac_addr mac_addr;
	QDF_STATUS qdf_status = QDF_STATUS_SUCCESS;
	struct sme_rcpi_req *rcpi_req;
	void *cookie;
	struct rcpi_info *priv;
	struct osif_request *request;
	static const struct osif_request_params params = {
		.priv_size = sizeof(*priv),
		.timeout_ms = WLAN_WAIT_TIME_RCPI,
	};
	bool reassoc;

	hdd_enter();

	/* initialize the rcpi value to zero, useful in error cases */
	*rcpi_value = 0;

	if (hdd_get_conparam() == QDF_GLOBAL_FTM_MODE) {
		hdd_err("Command not allowed in FTM mode");
		return -EINVAL;
	}

	if (!adapter) {
		hdd_warn("adapter context is NULL");
		return -EINVAL;
	}

	hdd_ctx = WLAN_HDD_GET_CTX(adapter);
	status = wlan_hdd_validate_context(hdd_ctx);
	if (status)
		return -EINVAL;

	if (!hdd_ctx->rcpi_enabled) {
		hdd_debug("RCPI not supported");
		return -EINVAL;
	}

	if (!mac) {
		hdd_warn("RCPI peer mac-addr is NULL");
		return -EINVAL;
	}

	qdf_mem_copy(&mac_addr, mac, QDF_MAC_ADDR_SIZE);

	if (!hdd_is_rcpi_applicable(adapter, &mac_addr, rcpi_value, &reassoc))
		return -EINVAL;
	if (reassoc)
		return 0;

	rcpi_req = qdf_mem_malloc(sizeof(*rcpi_req));
	if (!rcpi_req)
		return -EINVAL;

	request = osif_request_alloc(&params);
	if (!request) {
		hdd_err("Request allocation failure");
		qdf_mem_free(rcpi_req);
		return -ENOMEM;
	}
	cookie = osif_request_cookie(request);

	rcpi_req->mac_addr = mac_addr;
	rcpi_req->session_id = adapter->deflink->vdev_id;
	rcpi_req->measurement_type = measurement_type;
	rcpi_req->rcpi_callback = wlan_hdd_get_rcpi_cb;
	rcpi_req->rcpi_context = cookie;

	qdf_status = sme_get_rcpi(hdd_ctx->mac_handle, rcpi_req);
	if (!QDF_IS_STATUS_SUCCESS(qdf_status)) {
		hdd_err("Unable to retrieve RCPI");
		status = qdf_status_to_os_return(qdf_status);
		goto out;
	}

	/* request was sent -- wait for the response */
	ret = osif_request_wait_for_response(request);
	if (ret) {
		hdd_err("SME timed out while retrieving RCPI");
		status = -EINVAL;
		goto out;
	}

	/* update the adapter with the fresh results */
	priv = osif_request_priv(request);
	adapter->rcpi.mac_addr = priv->mac_addr;
	adapter->rcpi.rcpi = priv->rcpi;
	if (qdf_mem_cmp(&mac_addr, &priv->mac_addr, sizeof(mac_addr))) {
		hdd_err("mis match of mac addr from call-back");
		status = -EINVAL;
		goto out;
	}

	*rcpi_value = adapter->rcpi.rcpi;
	hdd_debug("RCPI = %d", *rcpi_value);
out:
	qdf_mem_free(rcpi_req);
	osif_request_put(request);

	hdd_exit();
	return status;
}

#ifdef WLAN_FEATURE_MIB_STATS
QDF_STATUS wlan_hdd_get_mib_stats(struct hdd_adapter *adapter)
{
	int ret = 0;
	struct stats_event *stats;
	struct wlan_objmgr_vdev *vdev;

	if (!adapter) {
		hdd_err("Invalid context, adapter");
		return QDF_STATUS_E_FAULT;
	}

	vdev = hdd_objmgr_get_vdev_by_user(adapter->deflink,
					   WLAN_OSIF_STATS_ID);
	if (!vdev)
		return QDF_STATUS_E_FAULT;

	stats = wlan_cfg80211_mc_cp_stats_get_mib_stats(vdev, &ret);
	hdd_objmgr_put_vdev_by_user(vdev, WLAN_OSIF_STATS_ID);
	if (ret || !stats) {
		wlan_cfg80211_mc_cp_stats_free_stats_event(stats);
		return ret;
	}

	hdd_debugfs_process_mib_stats(adapter, stats);

	wlan_cfg80211_mc_cp_stats_free_stats_event(stats);
	return ret;
}
#endif

QDF_STATUS wlan_hdd_get_rssi(struct wlan_hdd_link_info *link_info,
			     int8_t *rssi_value)
{
	int ret = 0, i;
	struct hdd_station_ctx *sta_ctx;
	struct stats_event *rssi_info;
	struct wlan_objmgr_vdev *vdev;

	if (cds_is_driver_recovering() || cds_is_driver_in_bad_state()) {
		hdd_err("Recovery in Progress. State: 0x%x Ignore!!!",
			cds_get_driver_state());
		/* return a cached value */
		*rssi_value = link_info->rssi;
		return QDF_STATUS_SUCCESS;
	}

	sta_ctx = WLAN_HDD_GET_STATION_CTX_PTR(link_info);
	if (!hdd_cm_is_vdev_associated(link_info)) {
		hdd_debug("Not associated!, rssi on disconnect %d",
			  link_info->rssi_on_disconnect);
		*rssi_value = link_info->rssi_on_disconnect;
		return QDF_STATUS_SUCCESS;
	}

	if (hdd_cm_is_vdev_roaming(link_info)) {
		hdd_debug("Roaming in progress, return cached RSSI");
		*rssi_value = link_info->rssi;
		return QDF_STATUS_SUCCESS;
	}

	vdev = hdd_objmgr_get_vdev_by_user(link_info, WLAN_OSIF_STATS_ID);
	if (!vdev) {
		*rssi_value = link_info->rssi;
		return QDF_STATUS_SUCCESS;
	}

	rssi_info = wlan_cfg80211_mc_cp_stats_get_peer_rssi(
			vdev,
			sta_ctx->conn_info.bssid.bytes,
			&ret);
	hdd_objmgr_put_vdev_by_user(vdev, WLAN_OSIF_STATS_ID);
	if (ret || !rssi_info) {
		wlan_cfg80211_mc_cp_stats_free_stats_event(rssi_info);
		return ret;
	}

	for (i = 0; i < rssi_info->num_peer_stats; i++) {
		if (!qdf_mem_cmp(rssi_info->peer_stats[i].peer_macaddr,
				 sta_ctx->conn_info.bssid.bytes,
				 QDF_MAC_ADDR_SIZE)) {
			*rssi_value = rssi_info->peer_stats[i].peer_rssi;
			hdd_debug("RSSI = %d", *rssi_value);
			wlan_cfg80211_mc_cp_stats_free_stats_event(rssi_info);
			return QDF_STATUS_SUCCESS;
		}
	}

	wlan_cfg80211_mc_cp_stats_free_stats_event(rssi_info);
	hdd_err("bss peer not present in returned result");
	return QDF_STATUS_E_FAULT;
}

struct snr_priv {
	int8_t snr;
};

/**
 * hdd_get_snr_cb() - "Get SNR" callback function
 * @snr: Current SNR of the station
 * @context: opaque context originally passed to SME.  HDD always passes
 *	a cookie for the request context
 *
 * Return: None
 */
static void hdd_get_snr_cb(int8_t snr, void *context)
{
	struct osif_request *request;
	struct snr_priv *priv;

	request = osif_request_get(context);
	if (!request) {
		hdd_err("Obsolete request");
		return;
	}

	/* propagate response back to requesting thread */
	priv = osif_request_priv(request);
	priv->snr = snr;
	osif_request_complete(request);
	osif_request_put(request);
}

QDF_STATUS wlan_hdd_get_snr(struct wlan_hdd_link_info *link_info, int8_t *snr)
{
	struct hdd_context *hdd_ctx = WLAN_HDD_GET_CTX(link_info->adapter);
	struct hdd_station_ctx *sta_ctx;
	QDF_STATUS status;
	int ret;
	void *cookie;
	struct osif_request *request;
	struct snr_priv *priv;
	static const struct osif_request_params params = {
		.priv_size = sizeof(*priv),
		.timeout_ms = WLAN_WAIT_TIME_STATS,
	};

	hdd_enter();

	ret = wlan_hdd_validate_context(hdd_ctx);
	if (ret)
		return QDF_STATUS_E_FAULT;

	sta_ctx = WLAN_HDD_GET_STATION_CTX_PTR(link_info);

	request = osif_request_alloc(&params);
	if (!request) {
		hdd_err("Request allocation failure");
		return QDF_STATUS_E_FAULT;
	}
	cookie = osif_request_cookie(request);

	status = sme_get_snr(hdd_ctx->mac_handle, hdd_get_snr_cb,
			     sta_ctx->conn_info.bssid, cookie);
	if (QDF_STATUS_SUCCESS != status) {
		hdd_err("Unable to retrieve RSSI");
		/* we'll returned a cached value below */
	} else {
		/* request was sent -- wait for the response */
		ret = osif_request_wait_for_response(request);
		if (ret) {
			hdd_err("SME timed out while retrieving SNR");
			/* we'll now returned a cached value below */
		} else {
			/* update the adapter with the fresh results */
			priv = osif_request_priv(request);
			link_info->snr = priv->snr;
		}
	}

	/*
	 * either we never sent a request, we sent a request and
	 * received a response or we sent a request and timed out.
	 * regardless we are done with the request.
	 */
	osif_request_put(request);

	*snr = link_info->snr;
	hdd_exit();
	return QDF_STATUS_SUCCESS;
}

struct linkspeed_priv {
	struct link_speed_info linkspeed_info;
};

static void
hdd_get_link_speed_cb(struct link_speed_info *linkspeed_info, void *context)
{
	struct osif_request *request;
	struct linkspeed_priv *priv;

	if (!linkspeed_info) {
		hdd_err("NULL linkspeed");
		return;
	}

	request = osif_request_get(context);
	if (!request) {
		hdd_err("Obsolete request");
		return;
	}

	priv = osif_request_priv(request);
	priv->linkspeed_info = *linkspeed_info;
	osif_request_complete(request);
	osif_request_put(request);
}

int wlan_hdd_get_linkspeed_for_peermac(struct wlan_hdd_link_info *link_info,
				       struct qdf_mac_addr *mac_address,
				       uint32_t *linkspeed)
{
	int ret;
	QDF_STATUS status;
	void *cookie;
	struct link_speed_info *linkspeed_info;
	struct osif_request *request;
	struct linkspeed_priv *priv;
	struct hdd_adapter *adapter = link_info->adapter;
	static const struct osif_request_params params = {
		.priv_size = sizeof(*priv),
		.timeout_ms = WLAN_WAIT_TIME_STATS,
	};

	if (!linkspeed) {
		hdd_err("NULL argument");
		return -EINVAL;
	}

	request = osif_request_alloc(&params);
	if (!request) {
		hdd_err("Request allocation failure");
		ret = -ENOMEM;
		goto return_cached_value;
	}

	cookie = osif_request_cookie(request);
	priv = osif_request_priv(request);

	linkspeed_info = &priv->linkspeed_info;
	qdf_copy_macaddr(&linkspeed_info->peer_macaddr, mac_address);
	status = sme_get_link_speed(adapter->hdd_ctx->mac_handle,
				    linkspeed_info,
				    cookie, hdd_get_link_speed_cb);
	if (QDF_IS_STATUS_ERROR(status)) {
		hdd_err("Unable to retrieve statistics for link speed");
		ret = qdf_status_to_os_return(status);
		goto cleanup;
	}
	ret = osif_request_wait_for_response(request);
	if (ret) {
		hdd_err("SME timed out while retrieving link speed");
		goto cleanup;
	}
	link_info->estimated_linkspeed = linkspeed_info->estLinkSpeed;

cleanup:
	/*
	 * either we never sent a request, we sent a request and
	 * received a response or we sent a request and timed out.
	 * regardless we are done with the request.
	 */
	osif_request_put(request);

return_cached_value:
	*linkspeed = link_info->estimated_linkspeed;

	return ret;
}

static uint32_t
wlan_hdd_get_per_link_speed(struct wlan_hdd_link_info *link_info)
{
	uint32_t link_speed;
	struct qdf_mac_addr bssid;

	if (!hdd_cm_is_vdev_associated(link_info)) {
		/* we are not connected so we don't have a classAstats */
		hdd_debug("Not connected");
		return 0;
	}
	qdf_copy_macaddr(&bssid,
			 &link_info->session.station.conn_info.bssid);

	if (wlan_hdd_get_linkspeed_for_peermac(link_info,
					       &bssid, &link_speed)) {
		hdd_err("Unable to retrieve SME linkspeed");
		return 0;
	}
	hdd_debug("linkspeed = %d", link_speed);
	return link_speed;
}

#if defined(WLAN_FEATURE_11BE_MLO) && defined(CFG80211_11BE_BASIC)
#ifndef WLAN_HDD_MULTI_VDEV_SINGLE_NDEV
static uint32_t
wlan_hdd_get_mlo_link_speed(struct hdd_adapter *adapter)
{
	struct hdd_adapter *ml_adapter = NULL;
	struct hdd_adapter *link_adapter = NULL;
	struct hdd_mlo_adapter_info *mlo_adapter_info = NULL;
	uint32_t link_speed = 0;
	uint32_t per_speed;
	uint8_t link_id;

	ml_adapter = adapter;
	if (hdd_adapter_is_link_adapter(ml_adapter))
		ml_adapter = hdd_adapter_get_mlo_adapter_from_link(adapter);

	mlo_adapter_info = &ml_adapter->mlo_adapter_info;
	for (link_id = 0; link_id < WLAN_MAX_MLD; link_id++) {
		link_adapter = mlo_adapter_info->link_adapter[link_id];
		if (qdf_unlikely(!link_adapter)) {
			hdd_err("link_adapter[%d] is Null", link_id);
			continue;
		}
		per_speed = wlan_hdd_get_per_link_speed(ml_adapter->deflink);
		link_speed += per_speed;
		hdd_debug("Link%d speed=%d, total speed=%d",
			  link_id, per_speed, link_speed);
	}
	return link_speed;
}
#else
static uint32_t
wlan_hdd_get_mlo_link_speed(struct hdd_adapter *adapter)
{
	struct wlan_hdd_link_info *link_info = NULL;
	uint32_t link_speed = 0;
	uint32_t per_speed;

	hdd_adapter_for_each_active_link_info(adapter, link_info) {
		per_speed = wlan_hdd_get_per_link_speed(link_info);
		link_speed += per_speed;
		hdd_debug("per_speed=%d, link_speed=%d", per_speed, link_speed);
	}
	return link_speed;
}
#endif

#else
static uint32_t
wlan_hdd_get_mlo_link_speed(struct hdd_adapter *adapter)
{
	uint32_t link_speed = wlan_hdd_get_per_link_speed(adapter->deflink);

	hdd_debug("Not support MLO, linkspeed = %d", link_speed);
	return link_speed;
}
#endif

int wlan_hdd_get_link_speed(struct wlan_hdd_link_info *link_info,
			    uint32_t *link_speed)
{
	struct hdd_adapter *adapter =  link_info->adapter;
	struct hdd_context *hddctx = WLAN_HDD_GET_CTX(adapter);
	int ret;

	ret = wlan_hdd_validate_context(hddctx);
	if (ret)
		return ret;

	/* Linkspeed is allowed for CLIENT/STA mode */
	if (adapter->device_mode != QDF_P2P_CLIENT_MODE &&
	    adapter->device_mode != QDF_STA_MODE) {
		hdd_err("Link Speed is not allowed in Device mode %s(%d)",
			qdf_opmode_str(adapter->device_mode),
			adapter->device_mode);
		return -ENOTSUPP;
	}

	if (wlan_hdd_is_mlo_connection(link_info))
		*link_speed = wlan_hdd_get_mlo_link_speed(adapter);
	else
		*link_speed = wlan_hdd_get_per_link_speed(link_info);

	/* linkspeed in units of 500 kbps */
	*link_speed = (*link_speed) / 500;
	return 0;
}

#ifdef FEATURE_RX_LINKSPEED_ROAM_TRIGGER
/**
 * wlan_hdd_get_per_peer_stats - get per peer stats if supported by FW
 * @link_info: Link info pointer of STA adapter to get stats for
 * @peer_stats: Pointer to peer_stats
 *
 * Return: QDF_STATUS
 */
static QDF_STATUS
wlan_hdd_get_per_peer_stats(struct wlan_hdd_link_info *link_info,
			    struct cdp_peer_stats *peer_stats)
{
	QDF_STATUS status;
	ol_txrx_soc_handle soc;
	uint8_t *peer_mac;
	struct hdd_context *hdd_ctx = WLAN_HDD_GET_CTX(link_info->adapter);

	if (wlan_hdd_validate_context(hdd_ctx)) {
		hdd_err("invalid hdd_ctx");
		return QDF_STATUS_E_FAILURE;
	}

	soc = cds_get_context(QDF_MODULE_ID_SOC);
	peer_mac = link_info->session.station.conn_info.bssid.bytes;

	if (!wlan_hdd_is_per_link_stats_supported(hdd_ctx)) {
		hdd_debug("mlo per link stats is not supported by FW");
		status = cdp_host_get_peer_stats(soc, link_info->vdev_id,
						 peer_mac, peer_stats);
		return status;
	}

	status = ucfg_dp_get_per_link_peer_stats(soc, link_info->vdev_id,
						 peer_mac, peer_stats,
						 CDP_WILD_PEER_TYPE,
						 WLAN_MAX_MLD);
	return status;
}

void wlan_hdd_get_peer_rx_rate_stats(struct wlan_hdd_link_info *link_info)
{
	struct cdp_peer_stats *peer_stats;
	QDF_STATUS status;
	struct wlan_objmgr_psoc *psoc;
	struct hdd_stats *hdd_stats = &link_info->hdd_stats;

	psoc = link_info->adapter->hdd_ctx->psoc;
	if (!ucfg_mlme_stats_is_link_speed_report_actual(psoc))
		return;

	peer_stats = qdf_mem_malloc(sizeof(*peer_stats));
	if (!peer_stats) {
		hdd_err("Failed to malloc peer_stats");
		return;
	}

	/*
	 * If failed to get RX rates info, assign an invalid value to the
	 * preamble, used to tell driver to report max rates. The rx_rate
	 * and rx_mcs_index are also assigned with tx_rate and tx_mcs_index
	 * if they are invalid after ASSOC/REASSOC/ROAMING
	 */
	status = wlan_hdd_get_per_peer_stats(link_info, peer_stats);
	if (qdf_unlikely(QDF_IS_STATUS_ERROR(status)) ||
	    qdf_unlikely(peer_stats->rx.last_rx_rate == 0)) {
		hdd_debug("Driver failed to get rx rates, rx mcs=%d, status=%d",
			  hdd_stats->class_a_stat.rx_mcs_index, status);
		hdd_stats->class_a_stat.rx_preamble = INVALID_PREAMBLE;
		if (hdd_stats->class_a_stat.rx_mcs_index == INVALID_MCS_IDX) {
			hdd_stats->class_a_stat.rx_rate =
				hdd_stats->class_a_stat.tx_rate;
			hdd_stats->class_a_stat.rx_mcs_index =
				hdd_stats->class_a_stat.tx_mcs_index;
		}
		qdf_mem_free(peer_stats);
		return;
	}

	/*
	 * The linkspeed calculated by driver is in kbps so we
	 * convert it in units of 100 kbps expected by userspace
	 */
	hdd_stats->class_a_stat.rx_rate = peer_stats->rx.last_rx_rate / 100;
	hdd_stats->class_a_stat.rx_mcs_index = peer_stats->rx.mcs_info;
	hdd_stats->class_a_stat.rx_nss = peer_stats->rx.nss_info;
	hdd_stats->class_a_stat.rx_gi = peer_stats->rx.gi_info;
	hdd_stats->class_a_stat.rx_preamble = peer_stats->rx.preamble_info;
	hdd_stats->class_a_stat.rx_bw = peer_stats->rx.bw_info;

	qdf_mem_free(peer_stats);
}
#endif

int wlan_hdd_get_station_stats(struct wlan_hdd_link_info *link_info)
{
	int ret = 0;
	struct stats_event *stats;
	struct wlan_objmgr_vdev *vdev;

	if (!get_station_fw_request_needed) {
		hdd_debug("return cached get_station stats");
		return 0;
	}

	vdev = hdd_objmgr_get_vdev_by_user(link_info, WLAN_OSIF_STATS_ID);
	if (!vdev)
		return -EINVAL;

	stats = wlan_cfg80211_mc_cp_stats_get_station_stats(vdev, &ret);
	if (ret || !stats) {
		hdd_err("Invalid stats");
		goto out;
	}

	if (!stats->vdev_summary_stats || !stats->vdev_chain_rssi ||
	    !stats->peer_adv_stats || !stats->pdev_stats) {
		hdd_err("Invalid:%s%s%s%s",
			stats->vdev_summary_stats ? "" : " vdev_summary_stats",
			stats->vdev_chain_rssi ? "" : " vdev_chain_rssi",
			stats->peer_adv_stats ? "" : " peer_adv_stats",
			stats->pdev_stats ? "" : " pdev_stats");
		ret = -EINVAL;
		goto out;
	}

	/* update get stats cached time stamp */
	hdd_update_station_stats_cached_timestamp(link_info->adapter);
	copy_station_stats_to_adapter(link_info, stats);
out:
	wlan_cfg80211_mc_cp_stats_free_stats_event(stats);
	hdd_objmgr_put_vdev_by_user(vdev, WLAN_OSIF_STATS_ID);
	return ret;
}

#ifdef WLAN_FEATURE_BIG_DATA_STATS
int wlan_hdd_get_big_data_station_stats(struct wlan_hdd_link_info *link_info)
{
	int ret = 0;
	struct big_data_stats_event *big_data_stats;
	struct wlan_objmgr_vdev *vdev;

	vdev = hdd_objmgr_get_vdev_by_user(link_info, WLAN_OSIF_STATS_ID);
	if (!vdev)
		return -EINVAL;

	big_data_stats = wlan_cfg80211_mc_cp_get_big_data_stats(vdev, &ret);
	if (ret || !big_data_stats)
		goto out;

	copy_station_big_data_stats_to_adapter(link_info, big_data_stats);
out:
	if (big_data_stats)
		wlan_cfg80211_mc_cp_stats_free_big_data_stats_event(
								big_data_stats);
	hdd_objmgr_put_vdev_by_user(vdev, WLAN_OSIF_STATS_ID);
	return ret;
}
#endif

struct temperature_priv {
	int temperature;
};

/**
 * hdd_get_temperature_cb() - "Get Temperature" callback function
 * @temperature: measured temperature
 * @context: callback context
 *
 * This function is passed to sme_get_temperature() as the callback
 * function to be invoked when the temperature measurement is
 * available.
 *
 * Return: None
 */
static void hdd_get_temperature_cb(int temperature, void *context)
{
	struct osif_request *request;
	struct temperature_priv *priv;

	hdd_enter();

	request = osif_request_get(context);
	if (!request) {
		hdd_err("Obsolete request");
		return;
	}

	priv = osif_request_priv(request);
	priv->temperature = temperature;
	osif_request_complete(request);
	osif_request_put(request);
	hdd_exit();
}

int wlan_hdd_get_temperature(struct hdd_adapter *adapter, int *temperature)
{
	QDF_STATUS status;
	int ret;
	void *cookie;
	struct osif_request *request;
	struct temperature_priv *priv;
	static const struct osif_request_params params = {
		.priv_size = sizeof(*priv),
		.timeout_ms = WLAN_WAIT_TIME_STATS,
	};

	hdd_enter();
	if (!adapter) {
		hdd_err("adapter is NULL");
		return -EPERM;
	}

	if (!wlan_psoc_nif_fw_ext_cap_get(adapter->hdd_ctx->psoc,
					  WLAN_SOC_CEXT_TT_SUPPORT)) {
		hdd_err("WMI_SERVICE_THERM_THROT service from FW is disable");
		return -EINVAL;
	}

	request = osif_request_alloc(&params);
	if (!request) {
		hdd_err("Request allocation failure");
		return -ENOMEM;
	}
	cookie = osif_request_cookie(request);
	status = sme_get_temperature(adapter->hdd_ctx->mac_handle, cookie,
				     hdd_get_temperature_cb);
	if (QDF_STATUS_SUCCESS != status) {
		hdd_err("Unable to retrieve temperature");
	} else {
		ret = osif_request_wait_for_response(request);
		if (ret) {
			hdd_err("SME timed out while retrieving temperature");
		} else {
			/* update the adapter with the fresh results */
			priv = osif_request_priv(request);
			if (priv->temperature)
				adapter->temperature = priv->temperature;
		}
	}

	/*
	 * either we never sent a request, we sent a request and
	 * received a response or we sent a request and timed out.
	 * regardless we are done with the request.
	 */
	osif_request_put(request);

	*temperature = adapter->temperature;
	hdd_exit();
	return 0;
}

#ifdef TX_MULTIQ_PER_AC
void wlan_hdd_display_tx_multiq_stats(hdd_cb_handle context,
				      qdf_netdev_t netdev)
{
	struct hdd_adapter *adapter;
	struct wlan_hdd_link_info *link_info;
	struct hdd_tx_rx_stats *stats;
	uint32_t total_inv_sk_and_skb_hash = 0;
	uint32_t total_qselect_existing_skb_hash = 0;
	uint32_t total_qselect_sk_tx_map = 0;
	uint32_t total_qselect_skb_hash = 0;
	unsigned int i;

	adapter = WLAN_HDD_GET_PRIV_PTR(netdev);
	if (!adapter) {
		hdd_err("adapter is null");
		return;
	}

	link_info = adapter->deflink;

	stats = &link_info->hdd_stats.tx_rx_stats;

	for (i = 0; i < NUM_CPUS; i++) {
		total_inv_sk_and_skb_hash +=
					  stats->per_cpu[i].inv_sk_and_skb_hash;
		total_qselect_existing_skb_hash +=
				    stats->per_cpu[i].qselect_existing_skb_hash;
		total_qselect_sk_tx_map += stats->per_cpu[i].qselect_sk_tx_map;
		total_qselect_skb_hash +=
					stats->per_cpu[i].qselect_skb_hash_calc;
	}

	hdd_debug("TX_MULTIQ: INV %u skb_hash %u sk_tx_map %u skb_hash_calc %u",
		  total_inv_sk_and_skb_hash, total_qselect_existing_skb_hash,
		  total_qselect_sk_tx_map, total_qselect_skb_hash);
}
#endif

#ifdef QCA_SUPPORT_CP_STATS
/**
 * hdd_lost_link_cp_stats_info_cb() - callback function to get lost
 * link information
 * @stats_ev: Stats event pointer
 * FW sends vdev stats on vdev down, this callback is registered
 * with cp_stats component to get the last available vdev stats
 * From the FW.
 *
 * Return: None
 */

static void hdd_lost_link_cp_stats_info_cb(void *stats_ev)
{
	struct hdd_context *hdd_ctx = cds_get_context(QDF_MODULE_ID_HDD);
	struct stats_event *ev = stats_ev;
	uint8_t i, vdev_id;
	int8_t rssi;
	struct hdd_station_ctx *sta_ctx;
	struct wlan_hdd_link_info *link_info;
	struct qdf_mac_addr *mac_addr;

	if (wlan_hdd_validate_context(hdd_ctx))
		return;

	for (i = 0; i < ev->num_summary_stats; i++) {
		vdev_id = ev->vdev_summary_stats[i].vdev_id;
		link_info = hdd_get_link_info_by_vdev(hdd_ctx, vdev_id);
		if (!link_info) {
			hdd_debug("invalid vdev %d", vdev_id);
			continue;
		}

		sta_ctx = WLAN_HDD_GET_STATION_CTX_PTR(link_info);

		rssi = ev->vdev_summary_stats[i].stats.rssi;
		if (rssi == 0) {
			hdd_debug_rl("Invalid RSSI value sent by FW");
			return;
		}
		link_info->rssi_on_disconnect = rssi;
		sta_ctx->cache_conn_info.signal = rssi;

		mac_addr = hdd_adapter_get_link_mac_addr(link_info);
		if (!mac_addr)
			return;

		hdd_debug("rssi %d for " QDF_MAC_ADDR_FMT,
			  link_info->rssi_on_disconnect,
			  QDF_MAC_ADDR_REF(&mac_addr->bytes[0]));

	}
}

void wlan_hdd_register_cp_stats_cb(struct hdd_context *hdd_ctx)
{
	ucfg_mc_cp_stats_register_lost_link_info_cb(
					hdd_ctx->psoc,
					hdd_lost_link_cp_stats_info_cb);
}
#endif

#if defined(WLAN_FEATURE_ROAM_OFFLOAD) && defined(WLAN_FEATURE_ROAM_INFO_STATS)
#define ROAM_CACHED_STATS_MAX QCA_WLAN_VENDOR_ATTR_ROAM_CACHED_STATS_MAX

#define EVENTS_CONFIGURE QCA_WLAN_VENDOR_ATTR_ROAM_EVENTS_CONFIGURE
#define SUSPEND_STATE    QCA_WLAN_VENDOR_ATTR_ROAM_EVENTS_SUSPEND_STATE

#define ROAM_STATS_ROAM_TRIGGER_TIMESTAMP \
	QCA_WLAN_VENDOR_ATTR_ROAM_STATS_ROAM_TRIGGER_TIMESTAMP
#define ROAM_STATS_TRIGGER_REASON \
	QCA_WLAN_VENDOR_ATTR_ROAM_STATS_TRIGGER_REASON
#define ROAM_STATS_PER_RXRATE_THRESHOLD_PERCENT \
	QCA_WLAN_VENDOR_ATTR_ROAM_STATS_PER_RXRATE_THRESHOLD_PERCENT
#define ROAM_STATS_PER_TXRATE_THRESHOLD_PERCENT \
	QCA_WLAN_VENDOR_ATTR_ROAM_STATS_PER_TXRATE_THRESHOLD_PERCENT
#define ROAM_STATS_FINAL_BMISS_CNT \
	QCA_WLAN_VENDOR_ATTR_ROAM_STATS_FINAL_BMISS_CNT
#define ROAM_STATS_CONSECUTIVE_BMISS_CNT \
	QCA_WLAN_VENDOR_ATTR_ROAM_STATS_CONSECUTIVE_BMISS_CNT
#define ROAM_STATS_BMISS_QOS_NULL_SUCCESS \
	QCA_WLAN_VENDOR_ATTR_ROAM_STATS_BMISS_QOS_NULL_SUCCESS
#define ROAM_STATS_POOR_RSSI_CURRENT_RSSI \
	QCA_WLAN_VENDOR_ATTR_ROAM_STATS_POOR_RSSI_CURRENT_RSSI
#define ROAM_STATS_POOR_RSSI_ROAM_RSSI_THRESHOLD \
	QCA_WLAN_VENDOR_ATTR_ROAM_STATS_POOR_RSSI_ROAM_RSSI_THRESHOLD
#define ROAM_STATS_POOR_RSSI_RX_LINKSPEED_STATUS \
	QCA_WLAN_VENDOR_ATTR_ROAM_STATS_POOR_RSSI_RX_LINKSPEED_STATUS
#define ROAM_STATS_BETTER_RSSI_CURRENT_RSSI \
	QCA_WLAN_VENDOR_ATTR_ROAM_STATS_BETTER_RSSI_CURRENT_RSSI
#define ROAM_STATS_BETTER_RSSI_HIGH_RSSI_THRESHOLD \
	QCA_WLAN_VENDOR_ATTR_ROAM_STATS_BETTER_RSSI_HIGH_RSSI_THRESHOLD
#define ROAM_STATS_CONGESTION_RX_TPUT \
	QCA_WLAN_VENDOR_ATTR_ROAM_STATS_CONGESTION_RX_TPUT
#define ROAM_STATS_CONGESTION_TX_TPUT \
	QCA_WLAN_VENDOR_ATTR_ROAM_STATS_CONGESTION_TX_TPUT
#define ROAM_STATS_CONGESTION_ROAMABLE_CNT \
	QCA_WLAN_VENDOR_ATTR_ROAM_STATS_CONGESTION_ROAMABLE_CNT
#define ROAM_STATS_USER_TRIGGER_INVOKE_REASON \
	QCA_WLAN_VENDOR_ATTR_ROAM_STATS_USER_TRIGGER_INVOKE_REASON
#define ROAM_STATS_BTM_REQUEST_MODE \
	QCA_WLAN_VENDOR_ATTR_ROAM_STATS_BTM_REQUEST_MODE
#define ROAM_STATS_BTM_DISASSOC_IMMINENT_TIME \
	QCA_WLAN_VENDOR_ATTR_ROAM_STATS_BTM_DISASSOC_IMMINENT_TIME
#define ROAM_STATS_BTM_VALID_INTERNAL \
	QCA_WLAN_VENDOR_ATTR_ROAM_STATS_BTM_VALID_INTERNAL
#define ROAM_STATS_BTM_CANDIDATE_LIST_CNT \
	QCA_WLAN_VENDOR_ATTR_ROAM_STATS_BTM_CANDIDATE_LIST_CNT
#define ROAM_STATS_BTM_RESPONSE_STATUS_CODE \
	QCA_WLAN_VENDOR_ATTR_ROAM_STATS_BTM_RESPONSE_STATUS_CODE
#define ROAM_STATS_BTM_BSS_TERMINATION_TIMEOUT \
	QCA_WLAN_VENDOR_ATTR_ROAM_STATS_BTM_BSS_TERMINATION_TIMEOUT
#define ROAM_STATS_BTM_MBO_ASSOC_RETRY_TIMEOUT \
	QCA_WLAN_VENDOR_ATTR_ROAM_STATS_BTM_MBO_ASSOC_RETRY_TIMEOUT
#define ROAM_STATS_BTM_REQ_DIALOG_TOKEN \
	QCA_WLAN_VENDOR_ATTR_ROAM_STATS_BTM_REQ_DIALOG_TOKEN
#define ROAM_STATS_BSS_CU_LOAD \
	QCA_WLAN_VENDOR_ATTR_ROAM_STATS_BSS_CU_LOAD
#define ROAM_STATS_DISCONNECTION_TYPE \
	QCA_WLAN_VENDOR_ATTR_ROAM_STATS_DISCONNECTION_TYPE
#define ROAM_STATS_DISCONNECTION_REASON \
	QCA_WLAN_VENDOR_ATTR_ROAM_STATS_DISCONNECTION_REASON
#define ROAM_STATS_PERIODIC_TIMER_MS \
	QCA_WLAN_VENDOR_ATTR_ROAM_STATS_PERIODIC_TIMER_MS
#define ROAM_STATS_BACKGROUND_SCAN_CURRENT_RSSI \
	QCA_WLAN_VENDOR_ATTR_ROAM_STATS_BACKGROUND_SCAN_CURRENT_RSSI
#define ROAM_STATS_BACKGROUND_SCAN_DATA_RSSI \
	QCA_WLAN_VENDOR_ATTR_ROAM_STATS_BACKGROUND_SCAN_DATA_RSSI
#define ROAM_STATS_BACKGROUND_SCAN_DATA_RSSI_TH \
	QCA_WLAN_VENDOR_ATTR_ROAM_STATS_BACKGROUND_SCAN_DATA_RSSI_THRESH
#define ROAM_STATS_TX_FAILURES_THRESHOLD \
	QCA_WLAN_VENDOR_ATTR_ROAM_STATS_TX_FAILURES_THRESHOLD
#define ROAM_STATS_TX_FAILURES_REASON \
	QCA_WLAN_VENDOR_ATTR_ROAM_STATS_TX_FAILURES_REASON
#define ROAM_STATS_ABORT_REASON \
	QCA_WLAN_VENDOR_ATTR_ROAM_STATS_ABORT_REASON
#define ROAM_STATS_DATA_RSSI \
	QCA_WLAN_VENDOR_ATTR_ROAM_STATS_DATA_RSSI
#define ROAM_STATS_DATA_RSSI_THRESHOLD \
	QCA_WLAN_VENDOR_ATTR_ROAM_STATS_DATA_RSSI_THRESHOLD
#define ROAM_STATS_DATA_RX_LINKSPEED_STATUS \
	QCA_WLAN_VENDOR_ATTR_ROAM_STATS_DATA_RX_LINKSPEED_STATUS
#define ROAM_STATS_SCAN_TYPE \
	QCA_WLAN_VENDOR_ATTR_ROAM_STATS_SCAN_TYPE
#define ROAM_STATS_ROAM_STATUS \
	QCA_WLAN_VENDOR_ATTR_ROAM_STATS_ROAM_STATUS
#define ROAM_STATS_FAIL_REASON \
	QCA_WLAN_VENDOR_ATTR_ROAM_STATS_FAIL_REASON
#define ROAM_STATS_SCAN_CHAN_INFO \
	QCA_WLAN_VENDOR_ATTR_ROAM_STATS_SCAN_CHAN_INFO
#define ROAM_STATS_TOTAL_SCAN_TIME \
	QCA_WLAN_VENDOR_ATTR_ROAM_STATS_TOTAL_SCAN_TIME
#define ROAM_STATS_FRAME_INFO  \
	QCA_WLAN_VENDOR_ATTR_ROAM_STATS_FRAME_INFO
#define ROAM_STATS_SCAN_CHANNEL_FREQ \
	QCA_WLAN_VENDOR_ATTR_ROAM_STATS_SCAN_CHANNEL_FREQ
#define ROAM_STATS_SCAN_DWELL_TYPE \
	QCA_WLAN_VENDOR_ATTR_ROAM_STATS_SCAN_DWELL_TYPE
#define ROAM_STATS_MAX_DWELL_TIME \
	QCA_WLAN_VENDOR_ATTR_ROAM_STATS_MAX_DWELL_TIME
#define ROAM_STATS_FRAME_SUBTYPE \
	QCA_WLAN_VENDOR_ATTR_ROAM_STATS_FRAME_SUBTYPE
#define ROAM_STATS_FRAME_STATUS \
	QCA_WLAN_VENDOR_ATTR_ROAM_STATS_FRAME_STATUS
#define ROAM_STATS_FRAME_TIMESTAMP \
	QCA_WLAN_VENDOR_ATTR_ROAM_STATS_FRAME_TIMESTAMP

static enum qca_roam_reason
hdd_convert_roam_trigger_reason(enum roam_trigger_reason reason)
{
	switch (reason) {
	case ROAM_TRIGGER_REASON_NONE:
		return QCA_ROAM_REASON_UNKNOWN;
	case ROAM_TRIGGER_REASON_PER:
		return QCA_ROAM_REASON_PER;
	case ROAM_TRIGGER_REASON_BMISS:
		return QCA_ROAM_REASON_BEACON_MISS;
	case ROAM_TRIGGER_REASON_LOW_RSSI:
		return QCA_ROAM_REASON_POOR_RSSI;
	case ROAM_TRIGGER_REASON_HIGH_RSSI:
		return QCA_ROAM_REASON_BETTER_RSSI;
	case ROAM_TRIGGER_REASON_PERIODIC:
		return QCA_ROAM_REASON_PERIODIC_TIMER;
	case ROAM_TRIGGER_REASON_DENSE:
		return QCA_ROAM_REASON_CONGESTION;
	case ROAM_TRIGGER_REASON_BACKGROUND:
		return QCA_ROAM_REASON_BACKGROUND_SCAN;
	case ROAM_TRIGGER_REASON_FORCED:
		return QCA_ROAM_REASON_USER_TRIGGER;
	case ROAM_TRIGGER_REASON_BTM:
		return QCA_ROAM_REASON_BTM;
	case ROAM_TRIGGER_REASON_BSS_LOAD:
		return QCA_ROAM_REASON_BSS_LOAD;
	case ROAM_TRIGGER_REASON_DEAUTH:
		return QCA_ROAM_REASON_DISCONNECTION;
	case ROAM_TRIGGER_REASON_STA_KICKOUT:
		return QCA_ROAM_REASON_STA_KICKOUT;
	default:
		hdd_err("Invalid invoke reason received: %d", reason);
		break;
	}

	return QCA_ROAM_REASON_UNKNOWN;
}

static enum qca_wlan_roam_stats_invoke_reason
hdd_convert_roam_invoke_reason(enum roam_invoke_reason invoke)
{
	switch (invoke) {
	case WLAN_ROAM_STATS_INVOKE_REASON_UNDEFINED:
		return QCA_WLAN_ROAM_STATS_INVOKE_REASON_UNDEFINED;
	case WLAN_ROAM_STATS_INVOKE_REASON_NUD_FAILURE:
		return QCA_WLAN_ROAM_STATS_INVOKE_REASON_NUD_FAILURE;
	case WLAN_ROAM_STATS_INVOKE_REASON_USER_SPACE:
		return QCA_WLAN_ROAM_STATS_INVOKE_REASON_USER_SPACE;
	default:
		hdd_err("Invalid invoke reason received: %d", invoke);
		break;
	}

	return QCA_WLAN_ROAM_STATS_INVOKE_REASON_UNDEFINED;
}

static enum qca_wlan_roam_stats_tx_failures_reason
hdd_convert_roam_tx_failures_reason(enum roam_tx_failures_reason tx_failures)
{
	switch (tx_failures) {
	case WLAN_ROAM_STATS_KICKOUT_REASON_UNSPECIFIED:
		return QCA_WLAN_ROAM_STATS_KICKOUT_REASON_UNSPECIFIED;
	case WLAN_ROAM_STATS_KICKOUT_REASON_XRETRY:
		return QCA_WLAN_ROAM_STATS_KICKOUT_REASON_XRETRY;
	case WLAN_ROAM_STATS_KICKOUT_REASON_INACTIVITY:
		return QCA_WLAN_ROAM_STATS_KICKOUT_REASON_INACTIVITY;
	case WLAN_ROAM_STATS_KICKOUT_REASON_IBSS_DISCONNECT:
		return QCA_WLAN_ROAM_STATS_KICKOUT_REASON_IBSS_DISCONNECT;
	case WLAN_ROAM_STATS_KICKOUT_REASON_TDLS_DISCONNECT:
		return QCA_WLAN_ROAM_STATS_KICKOUT_REASON_TDLS_DISCONNECT;
	case WLAN_ROAM_STATS_KICKOUT_REASON_SA_QUERY_TIMEOUT:
		return QCA_WLAN_ROAM_STATS_KICKOUT_REASON_SA_QUERY_TIMEOUT;
	case WLAN_ROAM_STATS_KICKOUT_REASON_ROAMING_EVENT:
		return QCA_WLAN_ROAM_STATS_KICKOUT_REASON_ROAMING_EVENT;
	default:
		hdd_err("Invalid tx_failures reason received: %d", tx_failures);
		break;
	}

	return QCA_WLAN_ROAM_STATS_KICKOUT_REASON_UNSPECIFIED;
}

static enum qca_wlan_roam_stats_abort_reason
hdd_convert_roam_abort_reason(enum roam_abort_reason abort)
{
	switch (abort) {
	case WLAN_ROAM_STATS_ABORT_UNSPECIFIED:
		return QCA_WLAN_ROAM_STATS_ABORT_UNSPECIFIED;
	case WLAN_ROAM_STATS_ABORT_LOWRSSI_DATA_RSSI_HIGH:
		return QCA_WLAN_ROAM_STATS_ABORT_LOWRSSI_DATA_RSSI_HIGH;
	case WLAN_ROAM_STATS_ABORT_LOWRSSI_LINK_SPEED_GOOD:
		return QCA_WLAN_ROAM_STATS_ABORT_LOWRSSI_LINK_SPEED_GOOD;
	case WLAN_ROAM_STATS_ABORT_BG_DATA_RSSI_HIGH:
		return QCA_WLAN_ROAM_STATS_ABORT_BG_DATA_RSSI_HIGH;
	case WLAN_ROAM_STATS_ABORT_BG_RSSI_ABOVE_THRESHOLD:
		return QCA_WLAN_ROAM_STATS_ABORT_BG_RSSI_ABOVE_THRESHOLD;
	default:
		hdd_err("Invalid abort reason received: %d", abort);
		break;
	}

	return QCA_WLAN_ROAM_STATS_ABORT_UNSPECIFIED;
}

static enum qca_wlan_roam_stats_scan_type
hdd_convert_roam_scan_type(enum roam_stats_scan_type              type)
{
	switch (type) {
	case ROAM_STATS_SCAN_TYPE_PARTIAL:
		return QCA_WLAN_ROAM_STATS_SCAN_TYPE_PARTIAL;
	case ROAM_STATS_SCAN_TYPE_FULL:
		return QCA_WLAN_ROAM_STATS_SCAN_TYPE_FULL;
	case ROAM_STATS_SCAN_TYPE_NO_SCAN:
		return QCA_WLAN_ROAM_STATS_SCAN_TYPE_NO_SCAN;
	case ROAM_STATS_SCAN_TYPE_HIGHER_BAND_5GHZ_6GHZ:
		return QCA_WLAN_ROAM_STATS_SCAN_TYPE_HIGHER_BAND_5GHZ_6GHZ;
	case ROAM_STATS_SCAN_TYPE_HIGHER_BAND_6GHZ:
		return QCA_WLAN_ROAM_STATS_SCAN_TYPE_HIGHER_BAND_6GHZ;
	default:
		hdd_err("Invalid roam scan type received: %d", type);
		break;
	}

	return QCA_WLAN_ROAM_STATS_SCAN_TYPE_PARTIAL;
}

static enum qca_wlan_roam_stats_scan_dwell_type
hdd_convert_roam_chn_dwell_type(enum roam_scan_dwell_type type)
{
	switch (type) {
	case WLAN_ROAM_DWELL_TYPE_UNSPECIFIED:
		return QCA_WLAN_ROAM_STATS_DWELL_TYPE_UNSPECIFIED;
	case WLAN_ROAM_DWELL_ACTIVE_TYPE:
		return QCA_WLAN_ROAM_STATS_DWELL_TYPE_ACTIVE;
	case WLAN_ROAM_DWELL_PASSIVE_TYPE:
		return QCA_WLAN_ROAM_STATS_DWELL_TYPE_PASSIVE;
	default:
		hdd_err("Invalid abort reason received: %d", type);
		break;
	}

	return QCA_WLAN_ROAM_STATS_DWELL_TYPE_UNSPECIFIED;
}

static enum qca_wlan_roam_stats_frame_subtype
hdd_convert_roam_frame_type(enum eroam_frame_subtype type)
{
	switch (type) {
	case WLAN_ROAM_STATS_FRAME_SUBTYPE_PREAUTH:
		return QCA_WLAN_ROAM_STATS_FRAME_SUBTYPE_PREAUTH;
	case WLAN_ROAM_STATS_FRAME_SUBTYPE_REASSOC:
		return QCA_WLAN_ROAM_STATS_FRAME_SUBTYPE_REASSOC;
	case WLAN_ROAM_STATS_FRAME_SUBTYPE_EAPOL_M1:
		return QCA_WLAN_ROAM_STATS_FRAME_SUBTYPE_EAPOL_M1;
	case WLAN_ROAM_STATS_FRAME_SUBTYPE_EAPOL_M2:
		return QCA_WLAN_ROAM_STATS_FRAME_SUBTYPE_EAPOL_M2;
	case WLAN_ROAM_STATS_FRAME_SUBTYPE_EAPOL_M3:
		return QCA_WLAN_ROAM_STATS_FRAME_SUBTYPE_EAPOL_M3;
	case WLAN_ROAM_STATS_FRAME_SUBTYPE_EAPOL_M4:
		return QCA_WLAN_ROAM_STATS_FRAME_SUBTYPE_EAPOL_M4;
	case WLAN_ROAM_STATS_FRAME_SUBTYPE_EAPOL_GTK_M1:
		return QCA_WLAN_ROAM_STATS_FRAME_SUBTYPE_EAPOL_GTK_M1;
	case WLAN_ROAM_STATS_FRAME_SUBTYPE_EAPOL_GTK_M2:
		return QCA_WLAN_ROAM_STATS_FRAME_SUBTYPE_EAPOL_GTK_M2;
	default:
		hdd_err_rl("Invalid roam frame type received: %d", type);
		break;
	}

	return QCA_WLAN_ROAM_STATS_FRAME_SUBTYPE_PREAUTH;
};

static enum qca_wlan_roam_stats_frame_status
hdd_convert_roam_frame_status(enum eroam_frame_status status)
{
	switch (status) {
	case WLAN_ROAM_STATS_FRAME_STATUS_SUCCESS:
		return QCA_WLAN_ROAM_STATS_FRAME_STATUS_SUCCESS;
	case WLAN_ROAM_STATS_FRAME_STATUS_FAIL:
		return QCA_WLAN_ROAM_STATS_FRAME_STATUS_FAIL;
	default:
		hdd_err("Invalid roam frame status received: %d", status);
		break;
	}

	return QCA_WLAN_ROAM_STATS_FRAME_STATUS_FAIL;
};

static enum qca_vendor_roam_fail_reasons
hdd_convert_roam_failures_reason(enum wlan_roam_failure_reason_code fail)
{
	switch (fail) {
	case ROAM_FAIL_REASON_NO_SCAN_START:
		return QCA_ROAM_FAIL_REASON_SCAN_NOT_ALLOWED;
	case ROAM_FAIL_REASON_NO_AP_FOUND:
		return QCA_ROAM_FAIL_REASON_NO_AP_FOUND;
	case ROAM_FAIL_REASON_NO_CAND_AP_FOUND:
		return QCA_ROAM_FAIL_REASON_NO_CAND_AP_FOUND;
	case ROAM_FAIL_REASON_HOST:
		return QCA_ROAM_FAIL_REASON_HOST;
	case ROAM_FAIL_REASON_AUTH_SEND:
		return QCA_ROAM_FAIL_REASON_AUTH_SEND;
	case ROAM_FAIL_REASON_NO_AUTH_RESP:
		return QCA_ROAM_FAIL_REASON_NO_AUTH_RESP;
	case ROAM_FAIL_REASON_AUTH_RECV:
		return QCA_ROAM_FAIL_REASON_AUTH_RECV;
	case ROAM_FAIL_REASON_REASSOC_SEND:
		return QCA_ROAM_FAIL_REASON_REASSOC_SEND;
	case ROAM_FAIL_REASON_REASSOC_RECV:
		return QCA_ROAM_FAIL_REASON_REASSOC_RECV;
	case ROAM_FAIL_REASON_NO_REASSOC_RESP:
		return QCA_ROAM_FAIL_REASON_NO_REASSOC_RESP;
	case ROAM_FAIL_REASON_EAPOL_TIMEOUT:
		return QCA_ROAM_FAIL_REASON_EAPOL_M1_TIMEOUT;
	case ROAM_FAIL_REASON_SCAN_START:
		return QCA_ROAM_FAIL_REASON_SCAN_FAIL;
	case ROAM_FAIL_REASON_AUTH_NO_ACK:
		return QCA_ROAM_FAIL_REASON_AUTH_NO_ACK;
	case ROAM_FAIL_REASON_AUTH_INTERNAL_DROP:
		return QCA_ROAM_FAIL_REASON_AUTH_INTERNAL_DROP;
	case ROAM_FAIL_REASON_REASSOC_NO_ACK:
		return QCA_ROAM_FAIL_REASON_REASSOC_NO_ACK;
	case ROAM_FAIL_REASON_REASSOC_INTERNAL_DROP:
		return QCA_ROAM_FAIL_REASON_REASSOC_INTERNAL_DROP;
	case ROAM_FAIL_REASON_EAPOL_M2_SEND:
		return QCA_ROAM_FAIL_REASON_EAPOL_M2_SEND;
	case ROAM_FAIL_REASON_EAPOL_M2_INTERNAL_DROP:
		return QCA_ROAM_FAIL_REASON_EAPOL_M2_INTERNAL_DROP;
	case ROAM_FAIL_REASON_EAPOL_M2_NO_ACK:
		return QCA_ROAM_FAIL_REASON_EAPOL_M2_NO_ACK;
	case ROAM_FAIL_REASON_EAPOL_M3_TIMEOUT:
		return QCA_ROAM_FAIL_REASON_EAPOL_M3_TIMEOUT;
	case ROAM_FAIL_REASON_EAPOL_M4_SEND:
		return QCA_ROAM_FAIL_REASON_EAPOL_M4_SEND;
	case ROAM_FAIL_REASON_EAPOL_M4_INTERNAL_DROP:
		return QCA_ROAM_FAIL_REASON_EAPOL_M4_INTERNAL_DROP;
	case ROAM_FAIL_REASON_EAPOL_M4_NO_ACK:
		return QCA_ROAM_FAIL_REASON_EAPOL_M4_NO_ACK;
	case ROAM_FAIL_REASON_NO_SCAN_FOR_FINAL_BMISS:
		return QCA_ROAM_FAIL_REASON_NO_SCAN_FOR_FINAL_BEACON_MISS;
	case ROAM_FAIL_REASON_DISCONNECT:
		return QCA_ROAM_FAIL_REASON_DISCONNECT;
	case ROAM_FAIL_REASON_SYNC:
		return QCA_ROAM_FAIL_REASON_RESUME_ABORT;
	case ROAM_FAIL_REASON_SAE_INVALID_PMKID:
		return QCA_ROAM_FAIL_REASON_SAE_INVALID_PMKID;
	case ROAM_FAIL_REASON_SAE_PREAUTH_TIMEOUT:
		return QCA_ROAM_FAIL_REASON_SAE_PREAUTH_TIMEOUT;
	case ROAM_FAIL_REASON_SAE_PREAUTH_FAIL:
		return QCA_ROAM_FAIL_REASON_SAE_PREAUTH_FAIL;
	case ROAM_FAIL_REASON_CURR_AP_STILL_OK:
		return QCA_ROAM_FAIL_REASON_CURR_AP_STILL_OK;
	case ROAM_FAIL_REASON_MLME:
	case ROAM_FAIL_REASON_INTERNAL_ABORT:
	case ROAM_FAIL_REASON_UNABLE_TO_START_ROAM_HO:
	case ROAM_FAIL_REASON_NO_AP_FOUND_AND_FINAL_BMISS_SENT:
	case ROAM_FAIL_REASON_NO_CAND_AP_FOUND_AND_FINAL_BMISS_SENT:
	case ROAM_FAIL_REASON_SCAN_CANCEL:
	case ROAM_FAIL_REASON_SCREEN_ACTIVITY:
	case ROAM_FAIL_REASON_OTHER_PRIORITY_ROAM_SCAN:
	case ROAM_FAIL_REASON_UNKNOWN:
		hdd_err("Invalid roam failures reason");
		break;
	}

	return QCA_ROAM_FAIL_REASON_NONE;
}

/**
 * hdd_get_roam_stats_individual_record_len() - calculates the required length
 * of an individual record of roaming stats
 *
 * @roam_info: pointer to roam info
 * @index:     index of roam info cached in driver
 *
 * Return: required length of an individual record of roaming stats
 */
static uint32_t hdd_get_roam_stats_individual_record_len(struct enhance_roam_info *roam_info,
							 uint32_t index)
{
	struct enhance_roam_info *info;
	enum qca_roam_reason vendor_trigger_reason;
	uint32_t len, i;

	if (!roam_info) {
		hdd_err("invalid param");
		return 0;
	}

	info  = &roam_info[index];
	vendor_trigger_reason =
		hdd_convert_roam_trigger_reason(info->trigger.trigger_reason);

	len = 0;
	/* ROAM_STATS_ROAM_TRIGGER_TIMESTAMP */
	len += nla_total_size_64bit(sizeof(uint64_t));
	/* ROAM_STATS_TRIGGER_REASON */
	len += nla_total_size(sizeof(uint32_t));

	switch (vendor_trigger_reason) {
	case QCA_ROAM_REASON_PER:
		/* ROAM_STATS_PER_RXRATE_THRESHOLD_PERCENT */
		len += nla_total_size(sizeof(uint8_t));
		/* ROAM_STATS_PER_TXRATE_THRESHOLD_PERCENT */
		len += nla_total_size(sizeof(uint8_t));
		break;
	case QCA_ROAM_REASON_BEACON_MISS:
		/* ROAM_STATS_FINAL_BMISS_CNT */
		len += nla_total_size(sizeof(uint32_t));
		/* ROAM_STATS_CONSECUTIVE_BMISS_CNT */
		len += nla_total_size(sizeof(uint32_t));
		/* ROAM_STATS_BMISS_QOS_NULL_SUCCESS */
		len += nla_total_size(sizeof(uint8_t));
		break;
	case QCA_ROAM_REASON_POOR_RSSI:
		/* ROAM_STATS_POOR_RSSI_CURRENT_RSSI */
		len += nla_total_size(sizeof(int8_t));
		/* ROAM_STATS_POOR_RSSI_ROAM_RSSI_THRESHOLD */
		len += nla_total_size(sizeof(int8_t));
		/* ROAM_STATS_POOR_RSSI_RX_LINKSPEED_STATUS */
		len += nla_total_size(sizeof(uint8_t));
		break;
	case QCA_ROAM_REASON_BETTER_RSSI:
		/* ROAM_STATS_BETTER_RSSI_CURRENT_RSSI */
		len += nla_total_size(sizeof(int8_t));
		/* ROAM_STATS_BETTER_RSSI_HIGH_RSSI_THRESHOLD */
		len += nla_total_size(sizeof(int8_t));
		break;
	case QCA_ROAM_REASON_PERIODIC_TIMER:
		/* ROAM_STATS_PERIODIC_TIMER_MS */
		len += nla_total_size(sizeof(uint32_t));
		break;
	case QCA_ROAM_REASON_CONGESTION:
		/* ROAM_STATS_CONGESTION_RX_TPUT */
		len += nla_total_size(sizeof(uint32_t));
		/* ROAM_STATS_CONGESTION_TX_TPUT */
		len += nla_total_size(sizeof(uint32_t));
		/* ROAM_STATS_CONGESTION_ROAMABLE_CNT */
		len += nla_total_size(sizeof(uint8_t));
		break;
	case QCA_ROAM_REASON_BACKGROUND_SCAN:
		/* ROAM_STATS_BACKGROUND_SCAN_CURRENT_RSSI */
		len += nla_total_size(sizeof(int8_t));
		/* ROAM_STATS_BACKGROUND_SCAN_DATA_RSSI */
		len += nla_total_size(sizeof(int8_t));
		/* ROAM_STATS_BACKGROUND_SCAN_DATA_RSSI_TH */
		len += nla_total_size(sizeof(int8_t));
		break;
	case QCA_ROAM_REASON_USER_TRIGGER:
		/* ROAM_STATS_USER_TRIGGER_INVOKE_REASON */
		len += nla_total_size(sizeof(uint8_t));
		break;
	case QCA_ROAM_REASON_BTM:
		/* ROAM_STATS_BTM_REQUEST_MODE */
		len += nla_total_size(sizeof(uint8_t));
		/* ROAM_STATS_BTM_DISASSOC_IMMINENT_TIME */
		len += nla_total_size(sizeof(uint32_t));
		/* ROAM_STATS_BTM_VALID_INTERNAL */
		len += nla_total_size(sizeof(uint32_t));
		/* ROAM_STATS_BTM_CANDIDATE_LIST_CNT */
		len += nla_total_size(sizeof(uint8_t));
		/* ROAM_STATS_BTM_RESPONSE_STATUS_CODE */
		len += nla_total_size(sizeof(uint8_t));
		/* ROAM_STATS_BTM_BSS_TERMINATION_TIMEOUT */
		len += nla_total_size(sizeof(uint32_t));
		/* ROAM_STATS_BTM_MBO_ASSOC_RETRY_TIMEOUT */
		len += nla_total_size(sizeof(uint32_t));
		/* ROAM_STATS_BTM_REQ_DIALOG_TOKEN */
		len += nla_total_size(sizeof(uint8_t));
		break;
	case QCA_ROAM_REASON_BSS_LOAD:
		/* ROAM_STATS_BSS_CU_LOAD */
		len += nla_total_size(sizeof(uint8_t));
		break;
	case QCA_ROAM_REASON_DISCONNECTION:
		/* ROAM_STATS_DISCONNECTION_TYPE */
		len += nla_total_size(sizeof(uint8_t));
		/* ROAM_STATS_DISCONNECTION_REASON */
		len += nla_total_size(sizeof(uint16_t));
		break;
	case QCA_ROAM_REASON_STA_KICKOUT:
		/* ROAM_STATS_TX_FAILURES_THRESHOLD */
		len += nla_total_size(sizeof(uint32_t));
		/* ROAM_STATS_TX_FAILURES_REASON */
		len += nla_total_size(sizeof(uint8_t));
		break;
	default:
		break;
	}

	/* ROAM_STATS_SCAN_TYPE */
	len += nla_total_size(sizeof(uint8_t));
	/* ROAM_STATS_ROAM_STATUS */
	len += nla_total_size(sizeof(uint8_t));

	if (info->trigger.roam_status) {
		/* ROAM_STATS_FAIL_REASON */
		len += nla_total_size(sizeof(uint8_t));
		if (info->trigger.abort.abort_reason_code) {
			/* ROAM_STATS_ABORT_REASON */
			len += nla_total_size(sizeof(uint8_t));
			/* ROAM_STATS_DATA_RSSI */
			len += nla_total_size(sizeof(int8_t));
			/* ROAM_STATS_DATA_RSSI_THRESHOLD */
			len += nla_total_size(sizeof(int8_t));
			/* ROAM_STATS_DATA_RX_LINKSPEED_STATUS */
			len += nla_total_size(sizeof(uint8_t));
		}
	}

	/* ROAM_STATS_SCAN_CHAN_INFO */
	len += nla_total_size(0);
	for (i = 0; i < info->scan.num_channels; i++) {
		/* nest attribute */
		len += nla_total_size(0);
		/* ROAM_STATS_SCAN_CHANNEL_FREQ */
		len += nla_total_size(sizeof(uint32_t));
		/* ROAM_STATS_SCAN_DWELL_TYPE */
		len += nla_total_size(sizeof(uint32_t));
		/* ROAM_STATS_MAX_DWELL_TIME */
		len += nla_total_size(sizeof(uint32_t));
	}

	/* ROAM_STATS_TOTAL_SCAN_TIME */
	len += nla_total_size(sizeof(uint32_t));

	/* ROAM_STATS_FRAME_INFO */
	len += nla_total_size(0);
	for (i = 0; i < ROAM_FRAME_NUM; i++) {
		/* nest attribute */
		len += nla_total_size(0);
		/* ROAM_STATS_FRAME_SUBTYPE */
		len += nla_total_size(sizeof(uint8_t));
		/* ROAM_STATS_FRAME_STATUS */
		len += nla_total_size(sizeof(uint8_t));
		/* ROAM_STATS_FRAME_TIMESTAMP */
		len += nla_total_size_64bit(sizeof(uint64_t));
	}

	return len;
}

/**
 * hdd_get_roam_stats_info_len() - calculate the length required by skb
 * @roam_info: pointer to roam info
 * @roam_cache_num: roam cache number
 *
 * Calculate the required length to send roam stats to upper layer
 *
 * Return: required len
 */
static uint32_t
hdd_get_roam_stats_info_len(struct enhance_roam_info *roam_info,
			    uint8_t roam_cache_num)
{
	uint32_t len, i;

	len = 0;
	/* QCA_WLAN_VENDOR_ATTR_ROAM_STATS_INFO */
	len += nla_total_size(0);
	for (i = 0; i < roam_cache_num; i++) {
		/* nest attribute */
		len += nla_total_size(0);
		len += hdd_get_roam_stats_individual_record_len(roam_info, i);
	}

	return len;
}

/**
 * hdd_nla_put_roam_stats_info() - put roam statistics info attribute
 * values to userspace
 *
 * @skb:       pointer to sk buff
 * @roam_info: pointer to roam info
 * @index:     index of roam info cached in driver
 *
 * Return: 0 if success else error status
 */
static int hdd_nla_put_roam_stats_info(struct sk_buff *skb,
				       struct enhance_roam_info *roam_info,
				       uint32_t index)
{
	struct nlattr *roam_chn_info, *roam_chn;
	struct nlattr *roam_frame_info, *roam_frame;
	struct enhance_roam_info *info;
	enum roam_invoke_reason driver_invoke_reason;
	enum qca_wlan_roam_stats_invoke_reason vendor_invoke_reason;
	enum roam_tx_failures_reason driver_tx_failures_reason;
	enum qca_wlan_roam_stats_tx_failures_reason vendor_tx_failures_reason;
	enum roam_abort_reason driver_abort_reason;
	enum qca_wlan_roam_stats_abort_reason vendor_abort_reason;
	enum qca_wlan_roam_stats_scan_type vendor_scan_type;
	enum roam_scan_dwell_type driver_dwell_type;
	enum qca_wlan_roam_stats_scan_dwell_type vendor_dwell_type;
	enum eroam_frame_subtype driver_frame_type;
	enum qca_wlan_roam_stats_frame_subtype vendor_frame_type;
	enum eroam_frame_status driver_frame_status;
	enum qca_wlan_roam_stats_frame_status vendor_frame_status;
	enum qca_roam_reason vendor_trigger_reason;
	enum qca_vendor_roam_fail_reasons vendor_fail_reason;
	uint32_t i;
	int ret;

	if (!roam_info) {
		hdd_err("invalid param");
		return -EINVAL;
	}
	info  = &roam_info[index];

	vendor_trigger_reason =
		hdd_convert_roam_trigger_reason(info->trigger.trigger_reason);

	if (wlan_cfg80211_nla_put_u64(skb, ROAM_STATS_ROAM_TRIGGER_TIMESTAMP,
				      info->trigger.timestamp)) {
		hdd_err("timestamp put fail");
		return -EINVAL;
	}

	if (nla_put_u32(skb, ROAM_STATS_TRIGGER_REASON, vendor_trigger_reason)) {
		hdd_err(" put fail");
		return -EINVAL;
	}

	switch (vendor_trigger_reason) {
	case QCA_ROAM_REASON_PER:
		if (nla_put_u8(skb,  ROAM_STATS_PER_RXRATE_THRESHOLD_PERCENT,
			       info->trigger.condition.roam_per.rx_rate_thresh_percent)) {
			hdd_err("roam_per.rx_rate_thresh_percent put fail");
			return -EINVAL;
		}
		if (nla_put_u8(skb,  ROAM_STATS_PER_TXRATE_THRESHOLD_PERCENT,
			       info->trigger.condition.roam_per.tx_rate_thresh_percent)) {
			hdd_err("roam_per.rx_rate_thresh_percent put fail");
			return -EINVAL;
		}
		break;
	case QCA_ROAM_REASON_BEACON_MISS:
		if (nla_put_u32(skb, ROAM_STATS_FINAL_BMISS_CNT,
				info->trigger.condition.roam_bmiss.final_bmiss_cnt)) {
			hdd_err("roam_bmiss.final_bmiss_cnt put fail");
			return -EINVAL;
		}
		if (nla_put_u32(skb, ROAM_STATS_CONSECUTIVE_BMISS_CNT,
				info->trigger.condition.roam_bmiss.consecutive_bmiss_cnt)) {
			hdd_err("roam_bmiss.consecutive_bmiss_cnt put fail");
			return -EINVAL;
		}
		if (nla_put_u8(skb, ROAM_STATS_BMISS_QOS_NULL_SUCCESS,
			       info->trigger.condition.roam_bmiss.qos_null_success)) {
			hdd_err("roam_bmiss.qos_null_success put fail");
			return -EINVAL;
		}
		break;
	case QCA_ROAM_REASON_POOR_RSSI:
		if (nla_put_s8(skb, ROAM_STATS_POOR_RSSI_CURRENT_RSSI,
			       info->trigger.condition.roam_poor_rssi.current_rssi)) {
			hdd_err("roam_poor_rssi.current_rssi put fail");
			return -EINVAL;
		}
		if (nla_put_s8(skb, ROAM_STATS_POOR_RSSI_ROAM_RSSI_THRESHOLD,
			       info->trigger.condition.roam_poor_rssi.roam_rssi_threshold)) {
			hdd_err("roam_poor_rssi.roam_rssi_threshold put fail");
			return -EINVAL;
		}
		if (nla_put_u8(skb, ROAM_STATS_POOR_RSSI_RX_LINKSPEED_STATUS,
			       info->trigger.condition.roam_poor_rssi.rx_linkspeed_status)) {
			hdd_err("roam_poor_rssi.rx_linkspeed_status put fail");
			return -EINVAL;
		}
		break;
	case QCA_ROAM_REASON_BETTER_RSSI:
		if (nla_put_s8(skb, ROAM_STATS_BETTER_RSSI_CURRENT_RSSI,
			       info->trigger.condition.roam_better_rssi.current_rssi)) {
			hdd_err("roam_better_rssi.current_rssi put fail");
			return -EINVAL;
		}
		if (nla_put_s8(skb, ROAM_STATS_BETTER_RSSI_HIGH_RSSI_THRESHOLD,
			       info->trigger.condition.roam_better_rssi.hi_rssi_threshold)) {
			hdd_err("roam_better_rssi.hi_rssi_threshold put fail");
			return -EINVAL;
		}
		break;
	case QCA_ROAM_REASON_PERIODIC_TIMER:
		if (nla_put_u32(skb, ROAM_STATS_PERIODIC_TIMER_MS,
				info->trigger.condition.roam_periodic.periodic_timer_ms)) {
			hdd_err("roam_periodic.periodic_timer_ms put fail");
			return -EINVAL;
		}
		break;
	case QCA_ROAM_REASON_CONGESTION:
		if (nla_put_u32(skb, ROAM_STATS_CONGESTION_RX_TPUT,
				info->trigger.condition.roam_congestion.rx_tput)) {
			hdd_err("roam_congestion.rx_tput put fail");
			return -EINVAL;
		}
		if (nla_put_u32(skb, ROAM_STATS_CONGESTION_TX_TPUT,
				info->trigger.condition.roam_congestion.tx_tput)) {
			hdd_err("roam_congestion.tx_tput put fail");
			return -EINVAL;
		}
		if (nla_put_u8(skb, ROAM_STATS_CONGESTION_ROAMABLE_CNT,
			       info->trigger.condition.roam_congestion.roamable_count)) {
			hdd_err("roam_congestion.roamable_count put fail");
			return -EINVAL;
		}
		break;
	case QCA_ROAM_REASON_BACKGROUND_SCAN:
		if (nla_put_s8(skb, ROAM_STATS_BACKGROUND_SCAN_CURRENT_RSSI,
			       info->trigger.condition.roam_background.current_rssi)) {
			hdd_err("roam_background.current_rssi put fail");
			return -EINVAL;
		}
		if (nla_put_s8(skb, ROAM_STATS_BACKGROUND_SCAN_DATA_RSSI,
			       info->trigger.condition.roam_background.data_rssi)) {
			hdd_err("roam_background.data_rssi put fail");
			return -EINVAL;
		}
		if (nla_put_s8(skb, ROAM_STATS_BACKGROUND_SCAN_DATA_RSSI_TH,
			       info->trigger.condition.roam_background.data_rssi_threshold)) {
			hdd_err("roam_background.data_rssi_threshold put fail");
			return -EINVAL;
		}
		break;
	case QCA_ROAM_REASON_USER_TRIGGER:
		driver_invoke_reason =
			info->trigger.condition.roam_user_trigger.invoke_reason;
		vendor_invoke_reason = hdd_convert_roam_invoke_reason(driver_invoke_reason);
		if (nla_put_u8(skb, ROAM_STATS_USER_TRIGGER_INVOKE_REASON,
			       vendor_invoke_reason)) {
			hdd_err("roam_user_trigger.invoke_reason put fail");
			return -EINVAL;
		}
		break;
	case QCA_ROAM_REASON_BTM:
		if (nla_put_u8(skb, ROAM_STATS_BTM_REQUEST_MODE,
			       info->trigger.condition.roam_btm.btm_request_mode)) {
			hdd_err("roam_btm.btm_request_mode put fail");
			return -EINVAL;
		}
		if (nla_put_u32(skb, ROAM_STATS_BTM_DISASSOC_IMMINENT_TIME,
				info->trigger.condition.roam_btm.disassoc_imminent_timer)) {
			hdd_err("roam_btm.disassoc_imminent_timer put fail");
			return -EINVAL;
		}
		if (nla_put_u32(skb, ROAM_STATS_BTM_VALID_INTERNAL,
				info->trigger.condition.roam_btm.validity_internal)) {
			hdd_err("roam_btm.validity_internal put fail");
			return -EINVAL;
		}
		if (nla_put_u8(skb, ROAM_STATS_BTM_CANDIDATE_LIST_CNT,
			       info->trigger.condition.roam_btm.candidate_list_count)) {
			hdd_err("roam_btm.candidate_list_count put fail");
			return -EINVAL;
		}
		if (nla_put_u8(skb, ROAM_STATS_BTM_RESPONSE_STATUS_CODE,
			       info->trigger.condition.roam_btm.btm_response_status_code)) {
			hdd_err("roam_btm.btm_response_status_code put fail");
			return -EINVAL;
		}
		if (nla_put_u32(skb, ROAM_STATS_BTM_BSS_TERMINATION_TIMEOUT,
				info->trigger.condition.roam_btm.btm_bss_termination_timeout)) {
			hdd_err("roam btm_bss_termination_timeout put fail");
			return -EINVAL;
		}
		if (nla_put_u32(skb, ROAM_STATS_BTM_MBO_ASSOC_RETRY_TIMEOUT,
				info->trigger.condition.roam_btm.btm_mbo_assoc_retry_timeout)) {
			hdd_err("roam btm_mbo_assoc_retry_timeout put fail");
			return -EINVAL;
		}
		if (nla_put_u8(skb, ROAM_STATS_BTM_REQ_DIALOG_TOKEN,
			       info->trigger.condition.roam_btm.btm_req_dialog_token)) {
			hdd_err("roam_btm.btm_req_dialog_token put fail");
			return -EINVAL;
		}
		break;
	case QCA_ROAM_REASON_BSS_LOAD:
		if (nla_put_u8(skb, ROAM_STATS_BSS_CU_LOAD,
			       info->trigger.condition.roam_bss_load.cu_load)) {
			hdd_err("roam_bss_load.cu_load put fail");
			return -EINVAL;
		}
		break;
	case QCA_ROAM_REASON_DISCONNECTION:
		if (nla_put_u8(skb, ROAM_STATS_DISCONNECTION_TYPE,
			       info->trigger.condition.roam_disconnection.deauth_type)) {
			hdd_err("roam_disconnection.deauth_type put fail");
			return -EINVAL;
		}
		if (nla_put_u16(skb, ROAM_STATS_DISCONNECTION_REASON,
				info->trigger.condition.roam_disconnection.deauth_reason)) {
			hdd_err("roam_disconnection.deauth_reason put fail");
			return -EINVAL;
		}
		break;
	case QCA_ROAM_REASON_STA_KICKOUT:
		driver_tx_failures_reason =
			info->trigger.condition.roam_tx_failures.kickout_threshold;
		vendor_tx_failures_reason =
			hdd_convert_roam_tx_failures_reason(driver_tx_failures_reason);
		if (nla_put_u32(skb, ROAM_STATS_TX_FAILURES_THRESHOLD,
				vendor_tx_failures_reason)) {
			hdd_err("roam_tx_failures.kickout_threshold put fail");
			return -EINVAL;
		}
		if (nla_put_u8(skb, ROAM_STATS_TX_FAILURES_REASON,
			       info->trigger.condition.roam_tx_failures.kickout_reason)) {
			hdd_err("roam_tx_failures.kickout_reason put fail");
			return -EINVAL;
		}
		break;
	default:
		break;
	}

	vendor_scan_type = hdd_convert_roam_scan_type(info->trigger.roam_scan_type);
	if (nla_put_u8(skb, ROAM_STATS_SCAN_TYPE, vendor_scan_type)) {
		hdd_err("roam_scan_type put fail");
		return -EINVAL;
	}

	if (nla_put_u8(skb, ROAM_STATS_ROAM_STATUS,
		       info->trigger.roam_status)) {
		hdd_err("roam_status put fail");
		return -EINVAL;
	}

	if (info->trigger.roam_status) {
		vendor_fail_reason = hdd_convert_roam_failures_reason(info->trigger.roam_fail_reason);
		if (nla_put_u8(skb, ROAM_STATS_FAIL_REASON,
			       vendor_fail_reason)) {
			hdd_err("roam_fail_reason put fail");
			return -EINVAL;
		}

		driver_abort_reason = info->trigger.abort.abort_reason_code;
		vendor_abort_reason = hdd_convert_roam_abort_reason(driver_abort_reason);
		if (info->trigger.abort.abort_reason_code) {
			if (nla_put_u8(skb, ROAM_STATS_ABORT_REASON, vendor_abort_reason)) {
				hdd_err("abort.abort_reason_code put fail");
				return -EINVAL;
			}
			if (nla_put_s8(skb, ROAM_STATS_DATA_RSSI,
				       info->trigger.abort.data_rssi)) {
				hdd_err("abort.data_rssi put fail");
				return -EINVAL;
			}
			if (nla_put_s8(skb, ROAM_STATS_DATA_RSSI_THRESHOLD,
				       info->trigger.abort.data_rssi_threshold)) {
				hdd_err("abort.data_rssi_threshold put fail");
				return -EINVAL;
			}
			if (nla_put_u8(skb, ROAM_STATS_DATA_RX_LINKSPEED_STATUS,
				       info->trigger.abort.rx_linkspeed_status)) {
				hdd_err("abort.rx_linkspeed_status put fail");
				return -EINVAL;
			}
		}
	}

	roam_chn_info = nla_nest_start(skb, ROAM_STATS_SCAN_CHAN_INFO);
	if (!roam_chn_info) {
		hdd_err("nla_nest_start fail");
		return -EINVAL;
	}

	for (i = 0; i < info->scan.num_channels; i++) {
		roam_chn = nla_nest_start(skb, i);
		if (!roam_chn) {
			hdd_err("nla_nest_start fail");
			return -EINVAL;
		}

		if (nla_put_u32(skb, ROAM_STATS_SCAN_CHANNEL_FREQ,
				info->scan.roam_chn[i].chan_freq)) {
			hdd_err("roam_chn[%u].chan_freq put fail", i);
			return -EINVAL;
		}

		driver_dwell_type = info->scan.roam_chn[i].dwell_type;
		vendor_dwell_type = hdd_convert_roam_chn_dwell_type(driver_dwell_type);
		if (nla_put_u32(skb, ROAM_STATS_SCAN_DWELL_TYPE,
				vendor_dwell_type)) {
			hdd_err("roam_chn[%u].dwell_type put fail", i);
			return -EINVAL;
		}
		if (nla_put_u32(skb, ROAM_STATS_MAX_DWELL_TIME,
				info->scan.roam_chn[i].max_dwell_time)) {
			hdd_err("roam_chn[%u].max_dwell_time put fail", i);
			return -EINVAL;
		}
		nla_nest_end(skb, roam_chn);
	}
	nla_nest_end(skb, roam_chn_info);

	if (nla_put_u32(skb, ROAM_STATS_TOTAL_SCAN_TIME,
			info->scan.total_scan_time)) {
		hdd_err("roam_scan total_scan_time put fail");
		return -EINVAL;
	}

	roam_frame_info = nla_nest_start(skb, ROAM_STATS_FRAME_INFO);
	if (!roam_frame_info) {
		hdd_err("nla_nest_start fail");
		return -EINVAL;
	}

	for (i = 0; i < ROAM_FRAME_NUM; i++) {
		roam_frame = nla_nest_start(skb, i);
		if (!roam_frame) {
			hdd_err("nla_nest_start fail");
			return -EINVAL;
		}
		driver_frame_type = info->timestamp[i].frame_type;
		vendor_frame_type = hdd_convert_roam_frame_type(driver_frame_type);
		ret = nla_put_u8(skb, ROAM_STATS_FRAME_SUBTYPE,
				 vendor_frame_type);
		if (ret) {
			hdd_err("roam_frame[%u].type put fail %d", i, ret);
			return -EINVAL;
		}
		driver_frame_status = info->timestamp[i].status;
		vendor_frame_status = hdd_convert_roam_frame_status(driver_frame_status);
		ret = nla_put_u8(skb, ROAM_STATS_FRAME_STATUS,
				 vendor_frame_status);
		if (ret) {
			hdd_err("frame[%u].status put fail %d", i, ret);
			return -EINVAL;
		}
		ret = wlan_cfg80211_nla_put_u64(skb, ROAM_STATS_FRAME_TIMESTAMP,
						info->timestamp[i].timestamp);
		if (ret) {
			hdd_err("frame[%u].timestamp put fail %d", i, ret);
			return -EINVAL;
		}
		nla_nest_end(skb, roam_frame);
	}
	nla_nest_end(skb, roam_frame_info);

	if (nla_put(skb, QCA_WLAN_VENDOR_ATTR_ROAM_STATS_ORIGINAL_BSSID,
		    QDF_MAC_ADDR_SIZE, info->scan.original_bssid.bytes)) {
		hdd_err("roam original AP bssid put fail");
		return -EINVAL;
	}
	if (info->trigger.roam_status) {
		if (nla_put(skb, QCA_WLAN_VENDOR_ATTR_ROAM_STATS_CANDIDATE_BSSID,
			    QDF_MAC_ADDR_SIZE,
			    info->scan.candidate_bssid.bytes)) {
			hdd_err("roam candidate AP bssid put fail");
			return -EINVAL;
		}
	} else {
		if (nla_put(skb, QCA_WLAN_VENDOR_ATTR_ROAM_STATS_ROAMED_BSSID,
			    QDF_MAC_ADDR_SIZE, info->scan.roamed_bssid.bytes)) {
			hdd_err("roam roamed AP bssid put fail");
			return -EINVAL;
		}
	}

	return 0;
}

/**
 * hdd_get_roam_stats_info() - get roam statistics info to userspace,
 * for STA mode only
 * @skb:     pointer to sk buff
 * @hdd_ctx: pointer to hdd context
 * @roam_info: pointer to roam info
 * @roam_cache_num: roam cache number
 *
 * Return: 0 if success else error status
 */
static int hdd_get_roam_stats_info(struct sk_buff *skb,
				   struct hdd_context *hdd_ctx,
				   struct enhance_roam_info *roam_info,
				   uint32_t  roam_cache_num)
{
	struct nlattr *config, *roam_params;
	uint32_t i;
	int ret;

	config = nla_nest_start(skb, QCA_WLAN_VENDOR_ATTR_ROAM_STATS_INFO);
	if (!config) {
		hdd_err("nla nest start failure");
		return -EINVAL;
	}

	/* Send all driver cached roam info to user space one time,
	 * and don't flush them, since they will be cover by
	 * new roam event info.
	 */
	for (i = 0; i < roam_cache_num; i++) {
		roam_params = nla_nest_start(skb, i);
		if (!roam_params)
			return -EINVAL;

		ret = hdd_nla_put_roam_stats_info(skb, roam_info, i);
		if (ret) {
			hdd_err("nla put failure");
			return -EINVAL;
		}

		nla_nest_end(skb, roam_params);
	}
	nla_nest_end(skb, config);

	return 0;
}

/**
 * hdd_get_roam_stats() - send roam statistics info to userspace
 * @hdd_ctx: pointer to hdd context
 * @adapter: pointer to adapter
 *
 * Return: 0 if success else error status
 */
static int
hdd_get_roam_stats(struct hdd_context *hdd_ctx,
		   struct hdd_adapter *adapter)
{
	struct sk_buff *skb;
	uint32_t skb_len;
	int ret = 0;
	struct wlan_objmgr_vdev *vdev;
	QDF_STATUS status;
	struct enhance_roam_info *roam_info = NULL;
	uint32_t roam_num = 0;

	vdev = hdd_objmgr_get_vdev_by_user(adapter->deflink,
					   WLAN_OSIF_STATS_ID);
	if (!vdev)
		return -EINVAL;

	status = ucfg_cm_roam_stats_info_get(vdev, &roam_info, &roam_num);
	if (QDF_IS_STATUS_ERROR(status)) {
		hdd_err("Failed to get roam info : %d", status);
		wlan_objmgr_vdev_release_ref(vdev, WLAN_OSIF_STATS_ID);
		return qdf_status_to_os_return(status);
	}
	wlan_objmgr_vdev_release_ref(vdev, WLAN_OSIF_STATS_ID);

	skb_len = hdd_get_roam_stats_info_len(roam_info, roam_num);
	if (!skb_len) {
		hdd_err("No data requested");
		ucfg_cm_roam_stats_info_put(roam_info);
		return -EINVAL;
	}

	skb_len += NLMSG_HDRLEN;
	skb = wlan_cfg80211_vendor_cmd_alloc_reply_skb(hdd_ctx->wiphy, skb_len);
	if (!skb) {
		hdd_info("wlan_cfg80211_vendor_cmd_alloc_reply_skb failed");
		ucfg_cm_roam_stats_info_put(roam_info);
		return -ENOMEM;
	}

	ret = hdd_get_roam_stats_info(skb, hdd_ctx, roam_info, roam_num);
	if (ret) {
		hdd_info("get roam stats fail");
		wlan_cfg80211_vendor_free_skb(skb);
		ucfg_cm_roam_stats_info_put(roam_info);
		return -ENOMEM;
	}

	ucfg_cm_roam_stats_info_put(roam_info);

	return wlan_cfg80211_vendor_cmd_reply(skb);
}

/**
 * __wlan_hdd_cfg80211_get_roam_stats() - get roam statstics information
 * @wiphy: wiphy pointer
 * @wdev: pointer to struct wireless_dev
 * @data: pointer to incoming NL vendor data
 * @data_len: length of @data
 *
 * Return: 0 on success; error number otherwise.
 */
static int
__wlan_hdd_cfg80211_get_roam_stats(struct wiphy *wiphy,
				   struct wireless_dev *wdev,
				   const void *data,
				   int data_len)
{
	struct hdd_context *hdd_ctx = wiphy_priv(wiphy);
	struct net_device *dev = wdev->netdev;
	struct hdd_adapter *adapter = WLAN_HDD_GET_PRIV_PTR(dev);
	int32_t status;

	hdd_enter_dev(dev);

	if (hdd_get_conparam() == QDF_GLOBAL_FTM_MODE ||
	    hdd_get_conparam() == QDF_GLOBAL_MONITOR_MODE) {
		hdd_err_rl("Command not allowed in FTM / Monitor mode");
		status = -EPERM;
		goto out;
	}

	status = wlan_hdd_validate_context(hdd_ctx);
	if (status != 0)
		goto out;

	if (adapter->device_mode == QDF_STA_MODE) {
		status = hdd_get_roam_stats(hdd_ctx, adapter);
	} else {
		hdd_err_rl("Invalid device_mode: %d", adapter->device_mode);
		status = -EINVAL;
	}

	hdd_exit();
out:
	return status;
}

/**
 * wlan_hdd_cfg80211_get_roam_stats() - get roam statstics information
 * @wiphy: wiphy pointer
 * @wdev: pointer to struct wireless_dev
 * @data: pointer to incoming NL vendor data
 * @data_len: length of @data
 *
 * Return: 0 on success; error number otherwise.
 */
int wlan_hdd_cfg80211_get_roam_stats(struct wiphy *wiphy,
				     struct wireless_dev *wdev,
				     const void *data,
				     int data_len)
{
	int errno;
	struct osif_vdev_sync *vdev_sync;

	errno = osif_vdev_sync_op_start(wdev->netdev, &vdev_sync);
	if (errno)
		return errno;

	errno = __wlan_hdd_cfg80211_get_roam_stats(wiphy, wdev,
						   data, data_len);

	osif_vdev_sync_op_stop(vdev_sync);

	return errno;
}
#endif

#ifdef WLAN_FEATURE_TX_LATENCY_STATS
#define TX_LATENCY_BUCKET_DISTRIBUTION_LEN \
	(sizeof(uint32_t) * CDP_TX_LATENCY_TYPE_MAX)

#define TX_LATENCY_ATTR(_name) QCA_WLAN_VENDOR_ATTR_TX_LATENCY_ ## _name

static const struct nla_policy
tx_latency_bucket_policy[TX_LATENCY_ATTR(BUCKET_MAX) + 1] = {
	[TX_LATENCY_ATTR(BUCKET_TYPE)] = {.type = NLA_U8},
	[TX_LATENCY_ATTR(BUCKET_GRANULARITY)] = {.type = NLA_U32},
	[TX_LATENCY_ATTR(BUCKET_AVERAGE)] = {.type = NLA_U32},
	[TX_LATENCY_ATTR(BUCKET_DISTRIBUTION)] = {
		.type = NLA_BINARY, .len = TX_LATENCY_BUCKET_DISTRIBUTION_LEN},
};

static const struct nla_policy
tx_latency_link_policy[TX_LATENCY_ATTR(LINK_MAX) + 1] = {
	[TX_LATENCY_ATTR(LINK_MAC_REMOTE)] = {
		.type = NLA_BINARY, .len = QDF_MAC_ADDR_SIZE},
	[TX_LATENCY_ATTR(LINK_STAT_BUCKETS)] =
		VENDOR_NLA_POLICY_NESTED_ARRAY(tx_latency_bucket_policy),
};

const struct nla_policy
tx_latency_policy[TX_LATENCY_ATTR(MAX) + 1] = {
	[TX_LATENCY_ATTR(ACTION)] = {.type = NLA_U32},
	[TX_LATENCY_ATTR(PERIODIC_REPORT)] = {.type = NLA_FLAG},
	[TX_LATENCY_ATTR(PERIOD)] = {.type = NLA_U32 },
	[TX_LATENCY_ATTR(BUCKETS)] =
		VENDOR_NLA_POLICY_NESTED_ARRAY(tx_latency_bucket_policy),
	[TX_LATENCY_ATTR(LINKS)] =
		VENDOR_NLA_POLICY_NESTED_ARRAY(tx_latency_link_policy),
};

/**
 * struct tx_latency_link_node - Link info of remote peer
 * @node: list node for membership in the link list
 * @vdev_id: Unique value to identify VDEV
 * @mac_remote: link MAC address of the remote peer
 */
struct tx_latency_link_node {
	qdf_list_node_t node;
	uint8_t vdev_id;
	struct qdf_mac_addr mac_remote;
};

/**
 * hdd_tx_latency_set_for_link() - set tx latency stats config for a link
 * @link_info: link specific information
 * @config: pointer to tx latency stats config
 *
 * Return: QDF_STATUS
 */
static inline QDF_STATUS
hdd_tx_latency_set_for_link(struct wlan_hdd_link_info *link_info,
			    struct cdp_tx_latency_config *config)
{
	QDF_STATUS status;
	void *soc = cds_get_context(QDF_MODULE_ID_SOC);

	if (!soc)
		return QDF_STATUS_E_INVAL;

	if (wlan_hdd_validate_vdev_id(link_info->vdev_id))
		return QDF_STATUS_SUCCESS;

	status = cdp_host_tx_latency_stats_config(soc,
						  link_info->vdev_id,
						  config);
	if (QDF_IS_STATUS_ERROR(status)) {
		hdd_err_rl("failed to %s for vdev id %d, status %d",
			   config->enable ? "enable" : "disable",
			   link_info->vdev_id, status);
		return status;
	}

	return QDF_STATUS_SUCCESS;
}

/**
 * hdd_tx_latency_restore_config() - restore tx latency stats config for a link
 * @link_info: link specific information
 *
 * Return: QDF_STATUS
 */
QDF_STATUS
hdd_tx_latency_restore_config(struct wlan_hdd_link_info *link_info)
{
	QDF_STATUS status;
	void *soc = cds_get_context(QDF_MODULE_ID_SOC);
	struct cdp_tx_latency_config *config;

	if (!soc)
		return QDF_STATUS_E_INVAL;

	if (wlan_hdd_validate_vdev_id(link_info->vdev_id))
		return QDF_STATUS_SUCCESS;

	config = &link_info->adapter->tx_latency_cfg;
	status = cdp_host_tx_latency_stats_config(soc,
						  link_info->vdev_id,
						  config);
	if (QDF_IS_STATUS_ERROR(status)) {
		hdd_err_rl("failed to %s for vdev id %d, status %d",
			   config->enable ? "enable" : "disable",
			   link_info->vdev_id, status);
		return status;
	}

	return QDF_STATUS_SUCCESS;
}

/**
 * hdd_tx_latency_set() - restore tx latency stats config for a link
 * @adapter: pointer to hdd vdev/net_device context
 * @config: pointer to tx latency stats config
 *
 * Return: 0 on success; error number otherwise.
 */
static int
hdd_tx_latency_set(struct hdd_adapter *adapter,
		   struct cdp_tx_latency_config *config)
{
	int ret;
	struct wlan_hdd_link_info *link_info;
	QDF_STATUS status = QDF_STATUS_E_NOENT;

	ret = hdd_set_tsf_auto_report(adapter, config->enable,
				      HDD_TSF_AUTO_RPT_SOURCE_TX_LATENCY);
	if (ret) {
		hdd_err_rl("failed to %s tsf auto report, ret %d",
			   config->enable ? "enable" : "disable", ret);
		return ret;
	}

	hdd_adapter_for_each_link_info(adapter, link_info) {
		status = hdd_tx_latency_set_for_link(link_info, config);
		if (QDF_IS_STATUS_ERROR(status))
			break;
	}

	/* restore TSF auto report config on failure */
	if (QDF_IS_STATUS_ERROR(status))
		hdd_set_tsf_auto_report(adapter, !config->enable,
					HDD_TSF_AUTO_RPT_SOURCE_TX_LATENCY);
	else
		qdf_mem_copy(&adapter->tx_latency_cfg, config,
			     sizeof(*config));
	hdd_debug("enable %d status %d", config->enable, status);
	return qdf_status_to_os_return(status);
}

/**
 * hdd_tx_latency_fill_link_stats() - fill tx latency statistics info skb
 * @skb: skb to be filled
 * @latency: per link tx latency statistics
 * @idx: index of the nested attribute
 *
 * Return: 0 on success; error number otherwise.
 */
static int
hdd_tx_latency_fill_link_stats(struct sk_buff *skb,
			       struct cdp_tx_latency *latency, int idx)
{
	struct nlattr *link, *link_stat_buckets, *link_stat_bucket;
	uint32_t type;
	int ret = 0;

	link = nla_nest_start(skb, idx);
	if (!link) {
		ret = -ENOMEM;
		goto err;
	}

	if (nla_put(skb, TX_LATENCY_ATTR(LINK_MAC_REMOTE),
		    QDF_MAC_ADDR_SIZE, latency->mac_remote.bytes)) {
		ret = -ENOMEM;
		goto err;
	}

	hdd_debug_rl("idx %d link mac " QDF_MAC_ADDR_FMT,
		     idx, QDF_MAC_ADDR_REF(latency->mac_remote.bytes));
	link_stat_buckets =
		nla_nest_start(skb, TX_LATENCY_ATTR(LINK_STAT_BUCKETS));
	for (type = 0; type < CDP_TX_LATENCY_TYPE_MAX; type++) {
		link_stat_bucket = nla_nest_start(skb, type);
		if (!link_stat_bucket) {
			ret = -ENOMEM;
			goto err;
		}

		if (nla_put_u8(skb, TX_LATENCY_ATTR(BUCKET_TYPE), type)) {
			ret = -ENOMEM;
			goto err;
		}

		if (nla_put_u32(skb, TX_LATENCY_ATTR(BUCKET_GRANULARITY),
				latency->stats[type].granularity)) {
			ret = -ENOMEM;
			goto err;
		}

		if (nla_put_u32(skb, TX_LATENCY_ATTR(BUCKET_AVERAGE),
				latency->stats[type].average)) {
			ret = -ENOMEM;
			goto err;
		}

		if (nla_put(skb, TX_LATENCY_ATTR(BUCKET_DISTRIBUTION),
			    TX_LATENCY_BUCKET_DISTRIBUTION_LEN,
			    latency->stats[type].distribution)) {
			ret = -ENOMEM;
			goto err;
		}

		nla_nest_end(skb, link_stat_bucket);
		hdd_debug_rl("	type %u granularity %u average %u",
			     type, latency->stats[type].granularity,
			     latency->stats[type].average);
	}

	nla_nest_end(skb, link_stat_buckets);
	nla_nest_end(skb, link);

err:
	if (ret)
		hdd_err("failed for link " QDF_MAC_ADDR_FMT " ret: %d",
			QDF_MAC_ADDR_REF(latency->mac_remote.bytes), ret);
	return ret;
}

/**
 * hdd_tx_latency_get_skb_len() - get required skb length for vendor command
 * response/async event
 * @num: required number of entries
 *
 * Return: the required skb length
 */
static uint32_t hdd_tx_latency_get_skb_len(uint32_t num)
{
	int32_t peer_stat_sz = 0, per_bucket_len = 0, len;

	if (!num)
		return 0;

	/* QCA_WLAN_VENDOR_ATTR_TX_LATENCY_BUCKET_TYPE */
	per_bucket_len += nla_total_size(sizeof(uint8_t));
	/* QCA_WLAN_VENDOR_ATTR_TX_LATENCY_BUCKET_GRANULARITY */
	per_bucket_len += nla_total_size(sizeof(uint32_t));
	/* QCA_WLAN_VENDOR_ATTR_TX_LATENCY_BUCKET_DISTRIBUTION */
	per_bucket_len += nla_total_size(TX_LATENCY_BUCKET_DISTRIBUTION_LEN);
	/* Nested attr */
	per_bucket_len = nla_total_size(per_bucket_len);

	/* QCA_WLAN_VENDOR_ATTR_TX_LATENCY_LINK_MAC_REMOTE */
	peer_stat_sz += nla_total_size(QDF_MAC_ADDR_SIZE);
	/* QCA_WLAN_VENDOR_ATTR_TX_LATENCY_LINK_STAT_BUCKETS */
	peer_stat_sz +=
		nla_total_size(per_bucket_len * CDP_TX_LATENCY_TYPE_MAX);
	/* Nested attr */
	peer_stat_sz = nla_total_size(peer_stat_sz);

	/* QCA_WLAN_VENDOR_ATTR_TX_LATENCY_LINKS */
	len = nla_total_size(peer_stat_sz * num);
	len += NLMSG_HDRLEN;
	return len;
}

/**
 * hdd_tx_latency_link_list_free() - free all the nodes in the list
 * @list: list of the nodes for link info
 *
 * Return: None
 */
static void hdd_tx_latency_link_list_free(qdf_list_t *list)
{
	struct tx_latency_link_node *entry, *next;

	qdf_list_for_each_del(list, entry, next, node) {
		qdf_list_remove_node(list, &entry->node);
		qdf_mem_free(entry);
	}
}

/**
 * hdd_tx_latency_link_list_add() - add a new node to the list for tx latency
 * links
 * @list: list of the nodes for link info
 * @vdev_id: Unique value to identify VDEV
 * @mac: link mac address of the remote peer
 *
 * Return: 0 on success; error number otherwise.
 */
static int
hdd_tx_latency_link_list_add(qdf_list_t *list, uint8_t vdev_id, uint8_t *mac)
{
	struct tx_latency_link_node *link;

	link = (struct tx_latency_link_node *)qdf_mem_malloc(sizeof(*link));
	if (!link)
		return -ENOMEM;

	qdf_mem_copy(link->mac_remote.bytes, mac, QDF_MAC_ADDR_SIZE);
	link->vdev_id = vdev_id;
	qdf_list_insert_back(list, &link->node);
	return 0;
}

/**
 * hdd_tx_latency_get_links_from_attr() - parse information of the links from
 * attribute QCA_WLAN_VENDOR_ATTR_TX_LATENCY_LINKS
 * @adapter: pointer to hdd vdev/net_device context
 * @links_attr: pointer to attribute QCA_WLAN_VENDOR_ATTR_TX_LATENCY_LINKS
 * @list: list of the nodes for link info
 *
 * Return: 0 on success; error number otherwise.
 */
static int
hdd_tx_latency_get_links_from_attr(struct hdd_adapter *adapter,
				   struct nlattr *links_attr,
				   qdf_list_t *list)
{
	struct nlattr *attr, *link_mac_remote_attr;
	struct nlattr *tb[TX_LATENCY_ATTR(LINK_MAX) + 1];
	int ret = 0, rem;
	uint8_t vdev_id, *mac;

	if (!links_attr || !list)
		return -EINVAL;

	/* links for MLO STA are attached to different vdevs */
	vdev_id = (adapter->device_mode == QDF_STA_MODE ?
		   CDP_VDEV_ALL : adapter->deflink->vdev_id);

	nla_for_each_nested(attr, links_attr, rem) {
		ret = wlan_cfg80211_nla_parse(tb, TX_LATENCY_ATTR(LINK_MAX),
					      nla_data(attr), nla_len(attr),
					      tx_latency_link_policy);
		if (ret) {
			hdd_err("Attribute parse failed, ret %d", ret);
			ret = -EINVAL;
			goto out;
		}

		link_mac_remote_attr = tb[TX_LATENCY_ATTR(LINK_MAC_REMOTE)];
		if (!link_mac_remote_attr) {
			hdd_err("Missing link mac remote attribute");
			ret = -EINVAL;
			goto out;
		}

		if (nla_len(link_mac_remote_attr) < QDF_MAC_ADDR_SIZE) {
			hdd_err("Attribute link mac remote is invalid");
			ret = -EINVAL;
			goto out;
		}

		mac = (uint8_t *)nla_data(link_mac_remote_attr);
		ret = hdd_tx_latency_link_list_add(list, vdev_id, mac);
		if (ret)
			goto out;
	}

out:
	if (ret)
		hdd_tx_latency_link_list_free(list);

	return ret;
}

/**
 * hdd_tx_latency_get_links_for_sap() - get all the active links for SAP mode
 * @adapter: pointer to hdd vdev/net_device context
 * @list: list of the nodes for link info
 *
 * Return: 0 on success; error number otherwise.
 */
static int
hdd_tx_latency_get_links_for_sap(struct hdd_adapter *adapter, qdf_list_t *list)
{
	struct hdd_station_info *sta, *tmp = NULL;
	int ret = 0;

	hdd_for_each_sta_ref_safe(adapter->sta_info_list, sta, tmp,
				  STA_INFO_SOFTAP_GET_STA_INFO) {
		if (QDF_IS_ADDR_BROADCAST(sta->sta_mac.bytes)) {
			hdd_put_sta_info_ref(&adapter->sta_info_list,
					     &sta, true,
					     STA_INFO_SOFTAP_GET_STA_INFO);
			continue;
		}

		ret = hdd_tx_latency_link_list_add(list,
						   adapter->deflink->vdev_id,
						   sta->sta_mac.bytes);
		hdd_put_sta_info_ref(&adapter->sta_info_list, &sta, true,
				     STA_INFO_SOFTAP_GET_STA_INFO);
		if (ret)
			goto out;
	}

out:
	if (ret)
		hdd_tx_latency_link_list_free(list);

	return ret;
}

/**
 * hdd_tx_latency_get_links_for_sta() - get all the active links for station
 * mode
 * @adapter: pointer to hdd vdev/net_device context
 * @list: list of the nodes for link info
 *
 * Return: 0 on success; error number otherwise.
 */
static int
hdd_tx_latency_get_links_for_sta(struct hdd_adapter *adapter, qdf_list_t *list)
{
	struct wlan_hdd_link_info *link_info;
	struct hdd_station_ctx *ctx;
	int ret = 0;

	hdd_adapter_for_each_active_link_info(adapter, link_info) {
		if (wlan_hdd_validate_vdev_id(link_info->vdev_id))
			continue;

		ctx = WLAN_HDD_GET_STATION_CTX_PTR(link_info);
		if (!hdd_cm_is_vdev_associated(link_info))
			continue;

		ret = hdd_tx_latency_link_list_add(list, link_info->vdev_id,
						   ctx->conn_info.bssid.bytes);
		if (ret)
			goto out;
	}

out:
	if (ret)
		hdd_tx_latency_link_list_free(list);

	return ret;
}

/**
 * hdd_tx_latency_get_links() - get all the active links
 * @adapter: pointer to hdd vdev/net_device context
 * @links_attr: pointer to attribute QCA_WLAN_VENDOR_ATTR_TX_LATENCY_LINKS
 * @list: list of the nodes for link info
 *
 * Return: 0 on success; error number otherwise.
 */
static int
hdd_tx_latency_get_links(struct hdd_adapter *adapter,
			 struct nlattr *links_attr, qdf_list_t *list)
{
	if (!list)
		return -EINVAL;

	if (links_attr)
		return hdd_tx_latency_get_links_from_attr(adapter,
							  links_attr, list);

	if (adapter->device_mode == QDF_SAP_MODE ||
	    adapter->device_mode == QDF_P2P_GO_MODE)
		return hdd_tx_latency_get_links_for_sap(adapter, list);
	else if (adapter->device_mode == QDF_STA_MODE ||
		 adapter->device_mode == QDF_P2P_CLIENT_MODE)
		return hdd_tx_latency_get_links_for_sta(adapter, list);
	else
		return -ENOTSUPP;
}

/**
 * hdd_tx_latency_populate_links() - get per link tx latency stats and fill
 * into skb
 * @soc: pointer to soc context
 * @skb: skb for vendor command response/async event
 * @list: list of the nodes for link info
 *
 * Return: 0 on success; error number otherwise.
 */
static inline int
hdd_tx_latency_populate_links(void *soc, struct sk_buff *skb, qdf_list_t *list)
{
	struct nlattr *links;
	struct tx_latency_link_node *entry, *next;
	struct cdp_tx_latency latency = {0};
	int ret, idx = 0;
	uint8_t *mac;
	QDF_STATUS status;

	links = nla_nest_start(skb, TX_LATENCY_ATTR(LINKS));
	if (!links)
		return -ENOMEM;

	qdf_list_for_each_del(list, entry, next, node) {
		qdf_list_remove_node(list, &entry->node);
		mac = entry->mac_remote.bytes;
		status = cdp_host_tx_latency_stats_fetch(soc, entry->vdev_id,
							 mac, &latency);
		if (QDF_IS_STATUS_ERROR(status)) {
			qdf_mem_free(entry);
			return qdf_status_to_os_return(status);
		}

		ret = hdd_tx_latency_fill_link_stats(skb, &latency, idx);
		qdf_mem_free(entry);
		if (ret)
			return ret;

		idx++;
	}

	nla_nest_end(skb, links);
	return 0;
}

/**
 * hdd_tx_latency_get() - get per link tx latency stats
 * @wiphy: pointer to wiphy
 * @adapter: pointer to hdd vdev/net_device context
 * @links_attr: pointer to attribute QCA_WLAN_VENDOR_ATTR_TX_LATENCY_LINKS
 *
 * Return: 0 on success; error number otherwise.
 */
static int
hdd_tx_latency_get(struct wiphy *wiphy,
		   struct hdd_adapter *adapter, struct nlattr *links_attr)
{
	int ret;
	void *soc = cds_get_context(QDF_MODULE_ID_SOC);
	struct sk_buff *reply_skb = NULL;
	uint32_t skb_len, links_num = 0;
	qdf_list_t links_list;

	if (!soc)
		return -EINVAL;

	qdf_list_create(&links_list, 0);
	ret = hdd_tx_latency_get_links(adapter, links_attr, &links_list);
	if (ret)
		goto out;

	links_num = qdf_list_size(&links_list);
	if (!links_num) {
		hdd_err_rl("no valid peers");
		ret = -EINVAL;
		goto out;
	}

	skb_len = hdd_tx_latency_get_skb_len(links_num);
	reply_skb = wlan_cfg80211_vendor_cmd_alloc_reply_skb(wiphy, skb_len);
	if (!reply_skb) {
		ret = -ENOMEM;
		goto out;
	}

	ret = hdd_tx_latency_populate_links(soc, reply_skb, &links_list);
	if (ret)
		goto free_skb;

	ret = wlan_cfg80211_vendor_cmd_reply(reply_skb);
	/* skb has been consumed regardless of the return value */
	goto out;

free_skb:
	wlan_cfg80211_vendor_free_skb(reply_skb);
	hdd_tx_latency_link_list_free(&links_list);
out:
	qdf_list_destroy(&links_list);
	hdd_debug_rl("get stats with ret %d", ret);
	return ret;
}

/**
 * hdd_tx_latency_enable() - enable per link tx latency stats
 * @adapter: pointer to hdd vdev/net_device context
 * @period: statistical period for transmit latency
 * @periodic_report: whether driver needs to report transmit latency
 * statistics at the end of each period
 * @buckets_attr: pointer to attribute QCA_WLAN_VENDOR_ATTR_TX_LATENCY_BUCKETS
 *
 * Return: 0 on success; error number otherwise.
 */
static int
hdd_tx_latency_enable(struct hdd_adapter *adapter, uint32_t period,
		      bool periodic_report, struct nlattr *buckets_attr)
{
	struct nlattr *tb[TX_LATENCY_ATTR(BUCKET_MAX) + 1];
	struct nlattr *attr, *bucket_type_attr, *bucket_granularity_attr;
	int rem, ret;
	uint8_t bucket_type;
	struct cdp_tx_latency_config config = {0};

	nla_for_each_nested(attr, buckets_attr, rem) {
		ret = wlan_cfg80211_nla_parse(tb, TX_LATENCY_ATTR(BUCKET_MAX),
					      nla_data(attr), nla_len(attr),
					      tx_latency_bucket_policy);
		if (ret) {
			hdd_err_rl("Attribute parse failed, ret %d", ret);
			return -EINVAL;
		}

		bucket_type_attr = tb[TX_LATENCY_ATTR(BUCKET_TYPE)];
		if (!bucket_type_attr) {
			hdd_err_rl("Missing bucket type attribute");
			return -EINVAL;
		}

		bucket_granularity_attr =
			tb[TX_LATENCY_ATTR(BUCKET_GRANULARITY)];
		if (!bucket_granularity_attr) {
			hdd_err_rl("Missing bucket granularity attribute");
			return -EINVAL;
		}

		bucket_type = nla_get_u8(bucket_type_attr);
		if (bucket_type >= CDP_TX_LATENCY_TYPE_MAX) {
			hdd_err_rl("Invalid bucket type %u", bucket_type);
			return -EINVAL;
		}

		config.granularity[bucket_type] =
			nla_get_u32(bucket_granularity_attr);
		if (!config.granularity[bucket_type]) {
			hdd_err_rl("Invalid granularity for type %d",
				   bucket_type);
			return -EINVAL;
		}
	}

	for (rem = 0; rem < CDP_TX_LATENCY_TYPE_MAX; rem++) {
		if (config.granularity[rem])
			continue;

		hdd_err_rl("Invalid granularity for type %d", rem);
		return -EINVAL;
	}

	config.enable = true;
	config.report = periodic_report;
	config.period = period;
	return hdd_tx_latency_set(adapter, &config);
}

/**
 * hdd_tx_latency_disable() - disable per link tx latency stats
 * @adapter: pointer to hdd vdev/net_device context
 *
 * Return: 0 on success; error number otherwise.
 */
static int hdd_tx_latency_disable(struct hdd_adapter *adapter)
{
	struct cdp_tx_latency_config config = {0};

	return hdd_tx_latency_set(adapter, &config);
}

/**
 * __wlan_hdd_cfg80211_tx_latency - configure/retrieve per-link transmit
 * latency statistics
 * @wiphy: wiphy handle
 * @wdev: wdev handle
 * @data: user layer input
 * @data_len: length of user layer input
 *
 * this function is called in ssr protected environment.
 *
 * return: 0 success, none zero for failure
 */
static int
__wlan_hdd_cfg80211_tx_latency(struct wiphy *wiphy, struct wireless_dev *wdev,
			       const void *data, int data_len)
{
	int ret;
	uint32_t action, period;
	struct nlattr *period_attr, *buckets_attr, *links_attr;

	struct net_device *dev = wdev->netdev;
	struct hdd_adapter *adapter = WLAN_HDD_GET_PRIV_PTR(dev);
	struct hdd_context *hdd_ctx = wiphy_priv(wiphy);
	struct nlattr *tb[TX_LATENCY_ATTR(MAX) + 1];
	bool periodic_report;

	if (QDF_GLOBAL_FTM_MODE == hdd_get_conparam()) {
		hdd_warn("command not allowed in ftm mode");
		return -EPERM;
	}

	ret = wlan_hdd_validate_context(hdd_ctx);
	if (ret)
		return -EINVAL;

	if (wlan_cfg80211_nla_parse(tb, TX_LATENCY_ATTR(MAX),
				    data, data_len,
				    tx_latency_policy)) {
		hdd_err_rl("invalid attribute");
		return -EINVAL;
	}

	if (!tb[TX_LATENCY_ATTR(ACTION)]) {
		hdd_err_rl("no attr action");
		return -EINVAL;
	}

	action = nla_get_u32(tb[TX_LATENCY_ATTR(ACTION)]);
	switch (action) {
	case QCA_WLAN_VENDOR_TX_LATENCY_ACTION_DISABLE:
		if (!adapter->tx_latency_cfg.enable) {
			ret = 0;
			break;
		}

		ret = hdd_tx_latency_disable(adapter);
		break;
	case QCA_WLAN_VENDOR_TX_LATENCY_ACTION_ENABLE:
		period_attr = tb[TX_LATENCY_ATTR(PERIOD)];
		if (!period_attr) {
			hdd_err_rl("no attr period");
			return -EINVAL;
		}

		buckets_attr = tb[TX_LATENCY_ATTR(BUCKETS)];
		if (!buckets_attr) {
			hdd_err_rl("no attr buckets");
			return -EINVAL;
		}

		period = nla_get_u32(period_attr);
		if (!period) {
			hdd_err_rl("invalid period");
			return -EINVAL;
		}

		periodic_report =
			nla_get_flag(tb[TX_LATENCY_ATTR(PERIODIC_REPORT)]);
		ret = hdd_tx_latency_enable(adapter, period,
					    periodic_report, buckets_attr);
		break;
	case QCA_WLAN_VENDOR_TX_LATENCY_ACTION_GET:
		if (!adapter->tx_latency_cfg.enable) {
			hdd_err_rl("please enable the feature first");
			ret = -EINVAL;
			break;
		}

		links_attr = tb[TX_LATENCY_ATTR(LINKS)];
		ret = hdd_tx_latency_get(wiphy, adapter, links_attr);
		break;
	default:
		ret = -EINVAL;
		break;
	}

	return ret;
}

/**
 * wlan_hdd_cfg80211_tx_latency - configure/retrieve per-link transmit latency
 * statistics
 * @wiphy: wiphy handle
 * @wdev: wdev handle
 * @data: user layer input
 * @data_len: length of user layer input
 *
 * return: 0 success, einval failure
 */
int wlan_hdd_cfg80211_tx_latency(struct wiphy *wiphy,
				 struct wireless_dev *wdev,
				 const void *data, int data_len)
{
	int errno;
	struct osif_vdev_sync *vdev_sync;

	errno = osif_vdev_sync_op_start(wdev->netdev, &vdev_sync);
	if (errno)
		return errno;

	errno = __wlan_hdd_cfg80211_tx_latency(wiphy, wdev, data, data_len);
	osif_vdev_sync_op_stop(vdev_sync);
	return errno;
}

/**
 * hdd_tx_latency_stats_cb() - callback function for transmit latency stats
 * @vdev_id: Unique value to identify VDEV
 * @stats_list: list of the nodes for per-link transmit latency statistics
 *
 * Return: QDF_STATUS
 */
static QDF_STATUS
hdd_tx_latency_stats_cb(uint8_t vdev_id, qdf_list_t *stats_list)
{
	uint32_t len, stats_cnt;
	struct sk_buff *vendor_event;
	struct hdd_context *hdd_ctx = cds_get_context(QDF_MODULE_ID_HDD);
	struct wlan_hdd_link_info *link_info;
	struct cdp_tx_latency *entry, *next;
	struct nlattr *links;
	int ret, idx = 0, flags = cds_get_gfp_flags();
	int event_idx = QCA_NL80211_VENDOR_SUBCMD_TX_LATENCY_INDEX;

	if (!hdd_ctx) {
		hdd_err("HDD context is NULL");
		return QDF_STATUS_E_FAULT;
	}

	if (!stats_list || qdf_list_empty(stats_list)) {
		hdd_err("invalid stats list");
		return QDF_STATUS_E_INVAL;
	}

	link_info = hdd_get_link_info_by_vdev(hdd_ctx, vdev_id);
	if (!link_info) {
		hdd_err("adapter NULL for vdev id %d", vdev_id);
		return QDF_STATUS_E_INVAL;
	}

	stats_cnt = qdf_list_size(stats_list);
	len = hdd_tx_latency_get_skb_len(stats_cnt);
	hdd_debug_rl("vdev id %d stats cnt %d", vdev_id, stats_cnt);
	vendor_event =
		wlan_cfg80211_vendor_event_alloc(hdd_ctx->wiphy,
						 &link_info->adapter->wdev,
						 len, event_idx, flags);
	if (!vendor_event) {
		hdd_err("event alloc failed vdev id %d, len %d",
			vdev_id, len);
		return QDF_STATUS_E_NOMEM;
	}

	links = nla_nest_start(vendor_event, TX_LATENCY_ATTR(LINKS));
	if (!links) {
		wlan_cfg80211_vendor_free_skb(vendor_event);
		hdd_err("failed to put peers");
		return QDF_STATUS_E_NOMEM;
	}

	qdf_list_for_each_del(stats_list, entry, next, node) {
		qdf_list_remove_node(stats_list, &entry->node);
		ret = hdd_tx_latency_fill_link_stats(vendor_event, entry, idx);
		qdf_mem_free(entry);
		if (ret) {
			hdd_err("failed to populate stats for idx %d", idx);
			wlan_cfg80211_vendor_free_skb(vendor_event);
			return QDF_STATUS_E_NOMEM;
		}

		idx++;
	}

	nla_nest_end(vendor_event, links);
	wlan_cfg80211_vendor_event(vendor_event, flags);
	return QDF_STATUS_SUCCESS;
}

/**
 * hdd_tx_latency_register_cb() - register callback function for transmit
 * latency stats
 * @soc: pointer to soc context
 *
 * Return: QDF_STATUS
 */
QDF_STATUS hdd_tx_latency_register_cb(void *soc)
{
	hdd_debug("Register tx latency callback");
	return cdp_host_tx_latency_stats_register_cb(soc,
						     hdd_tx_latency_stats_cb);
}
#endif
