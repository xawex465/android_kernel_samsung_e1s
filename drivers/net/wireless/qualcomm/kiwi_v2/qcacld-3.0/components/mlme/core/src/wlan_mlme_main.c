/*
 * Copyright (c) 2018-2021 The Linux Foundation. All rights reserved.
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
 * DOC: define internal APIs related to the mlme component
 */

#include "wlan_mlme_main.h"
#include "include/wlan_vdev_mlme.h"
#include "cfg_ucfg_api.h"
#include "wmi_unified.h"
#include "wlan_scan_public_structs.h"
#include "wlan_psoc_mlme_api.h"
#include "wlan_vdev_mlme_api.h"
#include "wlan_mlme_api.h"
#include <wlan_crypto_global_api.h>
#include <wlan_mlo_mgr_cmn.h>
#include "wlan_mlme_ucfg_api.h"
#include "wifi_pos_ucfg_i.h"
#include "wlan_mlo_mgr_sta.h"
#include "twt/core/src/wlan_twt_cfg.h"
#include "wlan_scan_api.h"
#include "wlan_mlme_vdev_mgr_interface.h"
#include "wlan_vdev_mgr_utils_api.h"
#include <wmi_unified_priv.h>
#include <target_if.h>

#define NUM_OF_SOUNDING_DIMENSIONS     1 /*Nss - 1, (Nss = 2 for 2x2)*/

/* Time to passive scan dwell for scan to get channel stats, in milliseconds */
#define MLME_GET_CHAN_STATS_PASSIVE_SCAN_TIME 40
#define MLME_GET_CHAN_STATS_WIDE_BAND_PASSIVE_SCAN_TIME 110

struct wlan_mlme_rx_ops *
mlme_get_rx_ops(struct wlan_objmgr_psoc *psoc)
{
	struct wlan_mlme_psoc_ext_obj *psoc_ext_priv;

	if (!psoc) {
		mlme_err("psoc object is NULL");
		return NULL;
	}
	psoc_ext_priv = wlan_psoc_mlme_get_ext_hdl(psoc);
	if (!psoc_ext_priv) {
		mlme_err("psoc legacy private object is NULL");
		return NULL;
	}

	return &psoc_ext_priv->mlme_rx_ops;
}

void wlan_mlme_register_rx_ops(struct wlan_mlme_rx_ops *rx_ops)
{
	rx_ops->peer_oper_mode_eventid = wlan_mlme_set_peer_indicated_ch_width;
}

#ifdef SEC_CONFIG_PSM_SYSFS
extern int wlan_hdd_sec_get_psm(void);
#endif /* SEC_CONFIG_PSM_SYSFS */
struct wlan_mlme_psoc_ext_obj *mlme_get_psoc_ext_obj_fl(
			       struct wlan_objmgr_psoc *psoc,
			       const char *func, uint32_t line)
{

	return wlan_psoc_mlme_get_ext_hdl(psoc);
}

struct wlan_mlme_nss_chains *mlme_get_dynamic_vdev_config(
				struct wlan_objmgr_vdev *vdev)
{
	struct mlme_legacy_priv *mlme_priv;

	mlme_priv = wlan_vdev_mlme_get_ext_hdl(vdev);
	if (!mlme_priv) {
		mlme_legacy_err("vdev legacy private object is NULL");
		return NULL;
	}

	return &mlme_priv->dynamic_cfg;
}

/* Buffer len size to consider the 4 char freq, and a space, Total 5 */
#define MLME_CHAN_WEIGHT_CHAR_LEN 5
#define MLME_MAX_CHAN_TO_PRINT 39

/**
 * mlme_fill_freq_in_scan_start_request() - Fill frequencies in scan req
 * @vdev: vdev common object
 * @req: pointer to scan request
 *
 * Return: QDF_STATUS
 */
static QDF_STATUS
mlme_fill_freq_in_scan_start_request(struct wlan_objmgr_vdev *vdev,
				     struct scan_start_request *req)
{
	const struct bonded_channel_freq *range;
	struct mlme_legacy_priv *mlme_priv;
	enum phy_ch_width associated_ch_width;
	uint8_t i;
	struct chan_list *scan_chan_list;
	qdf_freq_t first_freq, operation_chan_freq, sec_2g_freq;
	char *chan_buff = NULL;
	uint32_t buff_len, buff_num = 0, chan_count = 0;

	mlme_priv = wlan_vdev_mlme_get_ext_hdl(vdev);
	if (!mlme_priv)
		return QDF_STATUS_E_FAILURE;

	operation_chan_freq = wlan_get_operation_chan_freq(vdev);
	associated_ch_width =
			mlme_priv->connect_info.assoc_chan_info.assoc_ch_width;
	if (associated_ch_width == CH_WIDTH_INVALID) {
		mlme_debug("vdev %d : Invalid associated ch width for freq %d",
			   req->scan_req.vdev_id, operation_chan_freq);
		return QDF_STATUS_E_FAILURE;
	}

	req->scan_req.dwell_time_passive =
			MLME_GET_CHAN_STATS_PASSIVE_SCAN_TIME;
	req->scan_req.dwell_time_passive_6g =
			MLME_GET_CHAN_STATS_PASSIVE_SCAN_TIME;

	if (associated_ch_width == CH_WIDTH_20MHZ) {
		mlme_debug("vdev %d :Trigger scan for associated freq %d bw %d",
			   req->scan_req.vdev_id, operation_chan_freq,
			   associated_ch_width);
		req->scan_req.chan_list.num_chan = 1;
		req->scan_req.chan_list.chan[0].freq = operation_chan_freq;
		return QDF_STATUS_SUCCESS;
	}

	if (wlan_reg_is_24ghz_ch_freq(operation_chan_freq) &&
	    associated_ch_width == CH_WIDTH_40MHZ) {
		sec_2g_freq =
			mlme_priv->connect_info.assoc_chan_info.sec_2g_freq;
		if (!sec_2g_freq) {
			mlme_debug("vdev %d : Invalid sec 2g freq for freq: %d",
				   req->scan_req.vdev_id, operation_chan_freq);
			return QDF_STATUS_E_FAILURE;
		}

		if (operation_chan_freq > sec_2g_freq) {
			req->scan_req.chan_list.chan[0].freq = sec_2g_freq;
			req->scan_req.chan_list.chan[1].freq =
							operation_chan_freq;
		} else {
			req->scan_req.chan_list.chan[0].freq =
							operation_chan_freq;
			req->scan_req.chan_list.chan[1].freq = sec_2g_freq;
		}

		req->scan_req.chan_list.num_chan = 2;
		return QDF_STATUS_SUCCESS;
	}

	range = wlan_reg_get_bonded_chan_entry(operation_chan_freq,
					       associated_ch_width, 0);
	if (!range) {
		mlme_debug("vdev %d: Invalid freq range for freq: %d bw: %d",
			   req->scan_req.vdev_id, operation_chan_freq,
			   associated_ch_width);
		return QDF_STATUS_E_FAILURE;
	}

	scan_chan_list = qdf_mem_malloc(sizeof(*scan_chan_list));
	if (!scan_chan_list)
		return QDF_STATUS_E_NOMEM;

	scan_chan_list->num_chan = 0;
	first_freq  = range->start_freq;
	for (; first_freq <= range->end_freq; first_freq += BW_20_MHZ) {
		scan_chan_list->chan[scan_chan_list->num_chan].freq =
								first_freq;
		scan_chan_list->num_chan++;
	}

	req->scan_req.chan_list.num_chan = scan_chan_list->num_chan;

	mlme_debug("vdev %d : freq %d bw %d, range [%d-%d], Total freq %d",
		   req->scan_req.vdev_id, operation_chan_freq,
		   associated_ch_width, range->start_freq,
		   range->end_freq, req->scan_req.chan_list.num_chan);

	buff_len = (QDF_MIN(req->scan_req.chan_list.num_chan,
		    MLME_MAX_CHAN_TO_PRINT) * MLME_CHAN_WEIGHT_CHAR_LEN) + 1;

	chan_buff = qdf_mem_malloc(buff_len);
	if (!chan_buff) {
		qdf_mem_free(scan_chan_list);
		return QDF_STATUS_E_NOMEM;
	}
	for (i = 0; i < req->scan_req.chan_list.num_chan; i++) {
		req->scan_req.chan_list.chan[i].freq =
					scan_chan_list->chan[i].freq;
		buff_num += qdf_scnprintf(chan_buff + buff_num,
					  buff_len - buff_num, " %d",
					  req->scan_req.chan_list.chan[i].freq);
		chan_count++;
		if (chan_count >= MLME_MAX_CHAN_TO_PRINT) {
			mlme_debug("Freq list: %s", chan_buff);
			buff_num = 0;
			chan_count = 0;
		}
	}

	if (buff_num)
		mlme_debug("Freq list: %s", chan_buff);

	qdf_mem_free(chan_buff);
	qdf_mem_free(scan_chan_list);

	return QDF_STATUS_SUCCESS;
}

#ifdef WLAN_FEATURE_11BE
static enum scan_phy_mode mlme_get_scan_phy_mode(void)
{
	return SCAN_PHY_MODE_11BE_EHT160;
}

static enum scan_phy_mode
wlan_scan_get_11be_scan_phy_mode(enum wlan_phymode ch_phymode)
{
	enum scan_phy_mode scan_phymode;

	switch (ch_phymode) {
	case WLAN_PHYMODE_11BEA_EHT20:
		scan_phymode = SCAN_PHY_MODE_11BE_EHT20;
		break;
	case WLAN_PHYMODE_11BEG_EHT20:
		scan_phymode = SCAN_PHY_MODE_11BE_EHT20_2G;
		break;
	case WLAN_PHYMODE_11BEA_EHT40:
		scan_phymode = SCAN_PHY_MODE_11BE_EHT40;
		break;
	case WLAN_PHYMODE_11BEG_EHT40:
		scan_phymode = SCAN_PHY_MODE_11BE_EHT40_2G;
		break;
	case WLAN_PHYMODE_11BEA_EHT80:
		scan_phymode = SCAN_PHY_MODE_11BE_EHT80;
		break;
	case WLAN_PHYMODE_11BEG_EHT80:
		scan_phymode = SCAN_PHY_MODE_11BE_EHT80_2G;
		break;
	case WLAN_PHYMODE_11BEA_EHT160:
		scan_phymode = SCAN_PHY_MODE_11BE_EHT160;
		break;
	case WLAN_PHYMODE_11BEA_EHT320:
		scan_phymode = SCAN_PHY_MODE_11BE_EHT320;
		break;
	default:
		scan_phymode = SCAN_PHY_MODE_UNKNOWN;
		break;
	}

	return scan_phymode;
}
#else
static inline enum scan_phy_mode mlme_get_scan_phy_mode(void)
{
	return SCAN_PHY_MODE_UNKNOWN;
}

static inline enum scan_phy_mode
wlan_scan_get_11be_scan_phy_mode(enum wlan_phymode ch_phymode)
{
	return SCAN_PHY_MODE_UNKNOWN;
}
#endif

/**
 * wlan_scan_get_scan_phy_mode() - get scan phymode from channel phy mode
 * @vdev: vdev common object
 * @op_freq: operational frequency
 * @vdev_id: vdev id
 *
 * Return: enum scan_phy_mode
 */
static enum scan_phy_mode
wlan_scan_get_scan_phy_mode(struct wlan_objmgr_vdev *vdev, qdf_freq_t op_freq,
			    uint32_t vdev_id)
{
	struct wlan_channel *des_chan;
	enum scan_phy_mode scan_phymode = SCAN_PHY_MODE_UNKNOWN;

	des_chan = wlan_vdev_mlme_get_des_chan(vdev);
	if (!des_chan) {
		mlme_debug("vdev %d : des_chan is null", vdev_id);
		return scan_phymode;
	}

	switch (des_chan->ch_phymode) {
	case WLAN_PHYMODE_11A:
		scan_phymode = SCAN_PHY_MODE_11A;
		break;
	case WLAN_PHYMODE_11B:
		scan_phymode = SCAN_PHY_MODE_11B;
		break;
	case WLAN_PHYMODE_11G:
		scan_phymode = SCAN_PHY_MODE_11G;
		break;
	case WLAN_PHYMODE_11G_ONLY:
		scan_phymode = SCAN_PHY_MODE_11GONLY;
		break;
	case WLAN_PHYMODE_11NA_HT20:
		scan_phymode = SCAN_PHY_MODE_11NA_HT20;
		break;
	case WLAN_PHYMODE_11NG_HT20:
		scan_phymode = SCAN_PHY_MODE_11NG_HT20;
		break;
	case WLAN_PHYMODE_11NA_HT40:
		scan_phymode = SCAN_PHY_MODE_11NA_HT40;
		break;
	case WLAN_PHYMODE_11NG_HT40:
		scan_phymode = SCAN_PHY_MODE_11NG_HT40;
		break;
	case WLAN_PHYMODE_11AC_VHT20:
		scan_phymode = SCAN_PHY_MODE_11AC_VHT20;
		break;
	case WLAN_PHYMODE_11AC_VHT40:
		scan_phymode = SCAN_PHY_MODE_11AC_VHT40;
		break;
	case WLAN_PHYMODE_11AC_VHT80:
		scan_phymode = SCAN_PHY_MODE_11AC_VHT80;
		break;
	case WLAN_PHYMODE_11AC_VHT20_2G:
		scan_phymode = SCAN_PHY_MODE_11AC_VHT20_2G;
		break;
	case WLAN_PHYMODE_11AC_VHT40_2G:
		scan_phymode = SCAN_PHY_MODE_11AC_VHT40_2G;
		break;
	case WLAN_PHYMODE_11AC_VHT80_2G:
		scan_phymode = SCAN_PHY_MODE_11AC_VHT80_2G;
		break;
	case WLAN_PHYMODE_11AC_VHT80_80:
		scan_phymode = SCAN_PHY_MODE_11AC_VHT80_80;
		break;
	case WLAN_PHYMODE_11AC_VHT160:
		scan_phymode = SCAN_PHY_MODE_11AC_VHT160;
		break;
	case WLAN_PHYMODE_11AXA_HE20:
		scan_phymode = SCAN_PHY_MODE_11AX_HE20;
		break;
	case WLAN_PHYMODE_11AXG_HE20:
		scan_phymode = SCAN_PHY_MODE_11AX_HE20_2G;
		break;
	case WLAN_PHYMODE_11AXA_HE40:
		scan_phymode = SCAN_PHY_MODE_11AX_HE40;
		break;
	case WLAN_PHYMODE_11AXG_HE40:
		scan_phymode = SCAN_PHY_MODE_11AX_HE40_2G;
		break;
	case WLAN_PHYMODE_11AXA_HE80:
		scan_phymode = SCAN_PHY_MODE_11AX_HE80;
		break;
	case WLAN_PHYMODE_11AXG_HE80:
		scan_phymode = SCAN_PHY_MODE_11AX_HE80_2G;
		break;
	case WLAN_PHYMODE_11AXA_HE80_80:
		scan_phymode = SCAN_PHY_MODE_11AX_HE80_80;
		break;
	case WLAN_PHYMODE_11AXA_HE160:
		scan_phymode = SCAN_PHY_MODE_11AX_HE160;
		break;
	default:
		scan_phymode = SCAN_PHY_MODE_UNKNOWN;
		break;
	}

	if (scan_phymode != SCAN_PHY_MODE_UNKNOWN)
		return scan_phymode;

	scan_phymode = wlan_scan_get_11be_scan_phy_mode(des_chan->ch_phymode);

	return scan_phymode;
}

#ifdef WLAN_FEATURE_11BE
/**
 * mlme_get_scan_phy_mode_for_chan_load() - get scan phymode from ch width
 * @scan_ch_width: channel width
 *
 * Return: enum scan_phy_mode
 */
static enum scan_phy_mode
mlme_get_scan_phy_mode_for_chan_load(enum phy_ch_width scan_ch_width)
{
	enum scan_phy_mode scan_phymode = SCAN_PHY_MODE_UNKNOWN;

	switch (scan_ch_width) {
	case CH_WIDTH_20MHZ:
		scan_phymode = SCAN_PHY_MODE_11BE_EHT20;
		break;
	case CH_WIDTH_40MHZ:
		scan_phymode = SCAN_PHY_MODE_11BE_EHT40;
		break;
	case CH_WIDTH_80MHZ:
		scan_phymode = SCAN_PHY_MODE_11BE_EHT80;
		break;
	case CH_WIDTH_160MHZ:
		scan_phymode = SCAN_PHY_MODE_11BE_EHT160;
		break;
	default:
		mlme_debug("Invalid scan_ch_width:%d", scan_ch_width);
		break;
	}

	return scan_phymode;
}
#else
static inline enum scan_phy_mode
mlme_get_scan_phy_mode_for_chan_load(enum phy_ch_width scan_ch_width)
{
	return SCAN_PHY_MODE_UNKNOWN;
}
#endif

QDF_STATUS
mlme_update_freq_in_scan_start_req(struct wlan_objmgr_vdev *vdev,
				   struct scan_start_request *req,
				   enum phy_ch_width scan_ch_width,
				   qdf_freq_t scan_freq,
				   qdf_freq_t cen320_freq)
{
	const struct bonded_channel_freq *range;
	uint8_t num_chan;
	qdf_freq_t op_freq, center_20_freq, start_freq, end_freq;
	enum scan_phy_mode phymode = SCAN_PHY_MODE_UNKNOWN;
	uint8_t vdev_id = vdev->vdev_objmgr.vdev_id;

	if (scan_freq != INVALID_CHANNEL)
		op_freq = scan_freq;
	else
		op_freq = wlan_get_operation_chan_freq(vdev);

	mlme_debug("vdev %d :op_freq:%d, cen320_freq:%d, scan_ch_width: %d",
		   vdev_id, op_freq, cen320_freq, scan_ch_width);

	if (scan_ch_width == CH_WIDTH_320MHZ) {
		if (!cen320_freq)
			return QDF_STATUS_E_FAILURE;
		range = wlan_reg_get_bonded_chan_entry(op_freq,
						       scan_ch_width,
						       cen320_freq);
		if (!range) {
			mlme_debug("vdev %d : range is null for freq %d",
				   vdev_id, op_freq);
			return QDF_STATUS_E_FAILURE;
		}

		phymode = mlme_get_scan_phy_mode();
		if (phymode == SCAN_PHY_MODE_UNKNOWN) {
			mlme_debug("vdev %d : invalid scan phymode for freq %d",
				   vdev_id, op_freq);
			return QDF_STATUS_E_FAILURE;
		}

		start_freq = range->start_freq;
		end_freq = range->end_freq;

		/* fill connected 6 GHz ML link freq in wide band scan list */
		center_20_freq = start_freq + (7 * BW_20_MHZ);
		if (op_freq > center_20_freq)
			end_freq = op_freq;
		else
			start_freq = op_freq;

		num_chan = req->scan_req.chan_list.num_chan;
		req->scan_req.chan_list.chan[num_chan].freq = start_freq;
		req->scan_req.chan_list.chan[num_chan].phymode = phymode;
		num_chan += 1;
		req->scan_req.chan_list.chan[num_chan].freq = end_freq;
		req->scan_req.chan_list.chan[num_chan].phymode = phymode;
		num_chan += 1;
		req->scan_req.chan_list.num_chan = num_chan;
	} else {
		if (scan_freq != INVALID_CHANNEL)
			phymode = mlme_get_scan_phy_mode_for_chan_load(scan_ch_width);
		else
			phymode = wlan_scan_get_scan_phy_mode(vdev, op_freq, vdev_id);

		if (phymode == SCAN_PHY_MODE_UNKNOWN) {
			mlme_debug("vdev %d : invalid scan phymode for freq %d",
				   vdev_id, op_freq);
			return QDF_STATUS_E_FAILURE;
		}

		num_chan = req->scan_req.chan_list.num_chan;
		req->scan_req.chan_list.chan[num_chan].freq = op_freq;
		req->scan_req.chan_list.chan[num_chan].phymode = phymode;
		req->scan_req.chan_list.num_chan += 1;
	}

	return QDF_STATUS_SUCCESS;
}

#ifdef WLAN_FEATURE_11BE_MLO
/**
 * mlme_update_freq_from_link_ctx() - This API updates scan request from
 * link context
 * @links_info: pointer to MLO link info
 * @req: pointer to scan request
 *
 * Return: QDF_STATUS
 */
static QDF_STATUS
mlme_update_freq_from_link_ctx(struct mlo_link_info *links_info,
			       struct scan_start_request *req)
{
	const struct bonded_channel_freq *range;
	uint8_t num_chan;
	qdf_freq_t op_freq, center_20_freq, start_freq, end_freq;
	enum scan_phy_mode phymode;
	enum phy_ch_width scan_ch_width;
	struct wlan_channel *link_chan_info = links_info->link_chan_info;

	if (!link_chan_info) {
		mlme_err("link chan info is null");
		return QDF_STATUS_E_NULL_VALUE;
	}

	op_freq = link_chan_info->ch_freq;
	phymode = wlan_scan_get_11be_scan_phy_mode(link_chan_info->ch_phymode);
	if (phymode == SCAN_PHY_MODE_UNKNOWN) {
		mlme_err("invalid scan phymode for freq %d", op_freq);
		return QDF_STATUS_E_INVAL;
	}

	scan_ch_width = wlan_mlme_get_ch_width_from_phymode(
						link_chan_info->ch_phymode);

	if (scan_ch_width == CH_WIDTH_320MHZ) {
		range = wlan_reg_get_bonded_chan_entry(op_freq, scan_ch_width,
						link_chan_info->ch_cfreq2);
		if (!range) {
			mlme_err("range is null for freq %d center freq %d",
				 op_freq, link_chan_info->ch_cfreq2);
			return QDF_STATUS_E_NULL_VALUE;
		}

		start_freq = range->start_freq;
		end_freq = range->end_freq;

		/* fill connected 6 GHz ML link freq in wide band scan list */
		center_20_freq = start_freq + (7 * BW_20_MHZ);
		if (op_freq > center_20_freq)
			end_freq = op_freq;
		else
			start_freq = op_freq;

		mlme_debug("op_freq:%d, c_freq:%d, start_freq:%d, end_freq:%d",
			   op_freq, center_20_freq, start_freq, end_freq);

		num_chan = req->scan_req.chan_list.num_chan;
		req->scan_req.chan_list.chan[num_chan].freq = start_freq;
		req->scan_req.chan_list.chan[num_chan].phymode = phymode;
		num_chan += 1;
		req->scan_req.chan_list.chan[num_chan].freq = end_freq;
		req->scan_req.chan_list.chan[num_chan].phymode = phymode;
		num_chan += 1;
		req->scan_req.chan_list.num_chan = num_chan;
	} else {
		num_chan = req->scan_req.chan_list.num_chan;
		req->scan_req.chan_list.chan[num_chan].freq = op_freq;
		req->scan_req.chan_list.chan[num_chan].phymode = phymode;
		req->scan_req.chan_list.num_chan += 1;
	}

	return QDF_STATUS_SUCCESS;
}

/**
 * mlme_fill_freq_in_mlo_wide_band_scan_start_req() - Fill frequencies in wide
 * band scan req for mlo connection
 * @vdev: vdev common object
 * @req: pointer to scan request
 *
 * Return: QDF_STATUS
 */
static QDF_STATUS
mlme_fill_freq_in_mlo_wide_band_scan_start_req(struct wlan_objmgr_vdev *vdev,
					struct scan_start_request *req)
{
	struct wlan_mlo_dev_context *mlo_dev_ctx;
	uint8_t i;
	QDF_STATUS status;
	struct mlo_link_switch_context *link_ctx;

	mlo_dev_ctx = vdev->mlo_dev_ctx;
	if (!mlo_dev_ctx) {
		mlme_err("vdev %d :mlo_dev_ctx is NULL", req->scan_req.vdev_id);
		return QDF_STATUS_E_NULL_VALUE;
	}

	link_ctx = mlo_dev_ctx->link_ctx;
	if (!link_ctx) {
		mlme_err("vdev %d :mlo_link_ctx is NULL",
			 req->scan_req.vdev_id);
		return QDF_STATUS_E_NULL_VALUE;
	}

	for (i = 0; i < WLAN_MAX_ML_BSS_LINKS  &&
	     link_ctx->links_info[i].link_id != WLAN_INVALID_LINK_ID; i++) {
		status = mlme_update_freq_from_link_ctx(
						&link_ctx->links_info[i], req);
		if (QDF_IS_STATUS_ERROR(status)) {
			mlme_debug("freq update fails for link id %d",
				   link_ctx->links_info[i].link_id);
			return status;
		}
	}

	mlme_debug("vdev %d :trigger wide band scan for mlo conn, num freq %d",
		   req->scan_req.vdev_id, req->scan_req.chan_list.num_chan);
	return QDF_STATUS_SUCCESS;
}
#else
static inline QDF_STATUS
mlme_fill_freq_in_mlo_wide_band_scan_start_req(struct wlan_objmgr_vdev *vdev,
					struct scan_start_request *req)
{
	return QDF_STATUS_E_FAILURE;
}
#endif

/**
 * mlme_fill_freq_in_wide_scan_start_request() - Fill frequencies in wide band
 * scan req
 * @vdev: vdev common object
 * @req: pointer to scan request
 *
 * Return: QDF_STATUS
 */
static QDF_STATUS
mlme_fill_freq_in_wide_scan_start_request(struct wlan_objmgr_vdev *vdev,
					  struct scan_start_request *req)
{
	struct mlme_legacy_priv *mlme_priv;
	enum phy_ch_width associated_ch_width;
	QDF_STATUS status;
	qdf_freq_t assoc_cen320_freq = 0;

	req->scan_req.chan_list.num_chan = 0;

	if (wlan_vdev_mlme_is_mlo_vdev(vdev)) {
		status = mlme_fill_freq_in_mlo_wide_band_scan_start_req(vdev,
						req);
		if (QDF_IS_STATUS_ERROR(status))
			return QDF_STATUS_E_FAILURE;
		goto update_param;
	}

	mlme_priv = wlan_vdev_mlme_get_ext_hdl(vdev);
	if (!mlme_priv)
		return QDF_STATUS_E_FAILURE;

	associated_ch_width =
		mlme_priv->connect_info.assoc_chan_info.assoc_ch_width;
	if (associated_ch_width == CH_WIDTH_INVALID) {
		mlme_debug("vdev %d :Invalid associated ch_width",
			   req->scan_req.vdev_id);
		return QDF_STATUS_E_FAILURE;
	}

	/* Set center frequency of complete 320MHz */
	assoc_cen320_freq = mlme_priv->connect_info.assoc_chan_info.cen320_freq;

	status = mlme_update_freq_in_scan_start_req(vdev, req,
						    associated_ch_width,
						    INVALID_CHANNEL,
						    assoc_cen320_freq);
	if (QDF_IS_STATUS_ERROR(status))
		return QDF_STATUS_E_FAILURE;

	mlme_debug("vdev %d :trigger wide band scan, num freq %d",
		   req->scan_req.vdev_id, req->scan_req.chan_list.num_chan);

update_param:
	req->scan_req.dwell_time_passive =
			MLME_GET_CHAN_STATS_WIDE_BAND_PASSIVE_SCAN_TIME;
	req->scan_req.dwell_time_passive_6g =
			MLME_GET_CHAN_STATS_WIDE_BAND_PASSIVE_SCAN_TIME;

	req->scan_req.scan_f_wide_band = true;
	/*
	 * FW report CCA busy for each possible 20Mhz subbands of the
	 * wideband scan channel if below flag is true
	 */
	req->scan_req.scan_f_report_cca_busy_for_each_20mhz = true;

	return QDF_STATUS_SUCCESS;
}

QDF_STATUS mlme_connected_chan_stats_request(struct wlan_objmgr_psoc *psoc,
					     uint8_t vdev_id)
{
	struct wlan_mlme_psoc_ext_obj *mlme_obj;
	QDF_STATUS status;
	struct wlan_objmgr_vdev *vdev;
	struct scan_start_request *req;

	mlme_obj = mlme_get_psoc_ext_obj(psoc);
	if (!mlme_obj) {
		mlme_debug("vdev %d : NULL mlme psoc object", vdev_id);
		return QDF_STATUS_E_FAILURE;
	}

	vdev = wlan_objmgr_get_vdev_by_id_from_psoc(psoc, vdev_id,
						    WLAN_MLME_NB_ID);
	if (!vdev) {
		mlme_debug("vdev %d : NULL vdev object", vdev_id);
		return QDF_STATUS_E_FAILURE;
	}

	req = qdf_mem_malloc(sizeof(*req));
	if (!req) {
		wlan_objmgr_vdev_release_ref(vdev, WLAN_MLME_NB_ID);
		return QDF_STATUS_E_NOMEM;
	}

	status = wlan_scan_init_default_params(vdev, req);
	if (QDF_IS_STATUS_ERROR(status))
		goto release;

	req->scan_req.scan_id = wlan_scan_get_scan_id(psoc);
	req->scan_req.scan_req_id = mlme_obj->scan_requester_id;
	req->scan_req.vdev_id = vdev_id;

	req->scan_req.scan_type = SCAN_TYPE_DEFAULT;

	/* Fill channel list as per fw capability */
	if (wlan_psoc_nif_fw_ext2_cap_get(psoc,
			WLAN_CCA_BUSY_INFO_FOREACH_20MHZ)) {
		status = mlme_fill_freq_in_wide_scan_start_request(vdev, req);
		if (QDF_IS_STATUS_ERROR(status))
			goto release;
	} else {
		status = mlme_fill_freq_in_scan_start_request(vdev, req);
		if (QDF_IS_STATUS_ERROR(status))
			goto release;
	}

	/* disable adatptive dwell time */
	req->scan_req.adaptive_dwell_time_mode = SCAN_DWELL_MODE_STATIC;
	/* to disable early 6Ghz scan bail out */
	req->scan_req.min_dwell_time_6g = 0;
	/* passive scan for CCA measurement */
	req->scan_req.scan_f_passive = true;
	/* Fw pause home channel when scan channel is same as home channel */
	req->scan_req.scan_f_pause_home_channel = true;

	status = wlan_scan_start(req);
	if (QDF_IS_STATUS_ERROR(status)) {
		mlme_debug("vdev %d :Failed to send scan req, status %d",
			   vdev_id, status);
		goto release;
	}

	wlan_objmgr_vdev_release_ref(vdev, WLAN_MLME_NB_ID);
	return status;
release:
	qdf_mem_free(req);
	wlan_objmgr_vdev_release_ref(vdev, WLAN_MLME_NB_ID);
	return status;
}

uint32_t mlme_get_vdev_he_ops(struct wlan_objmgr_psoc *psoc, uint8_t vdev_id)
{
	struct vdev_mlme_obj *mlme_obj;
	uint32_t he_ops = 0;
	struct wlan_objmgr_vdev *vdev;

	vdev = wlan_objmgr_get_vdev_by_id_from_psoc(psoc, vdev_id,
						    WLAN_MLME_NB_ID);
	if (!vdev)
		return he_ops;

	mlme_obj = wlan_vdev_mlme_get_cmpt_obj(vdev);
	if (!mlme_obj) {
		wlan_objmgr_vdev_release_ref(vdev, WLAN_MLME_NB_ID);
		mlme_legacy_err("Failed to get vdev MLME Obj");
		return he_ops;
	}

	he_ops = mlme_obj->proto.he_ops_info.he_ops;
	wlan_objmgr_vdev_release_ref(vdev, WLAN_MLME_NB_ID);

	return he_ops;
}

struct wlan_mlme_nss_chains *mlme_get_ini_vdev_config(
				struct wlan_objmgr_vdev *vdev)
{
	struct mlme_legacy_priv *mlme_priv;

	mlme_priv = wlan_vdev_mlme_get_ext_hdl(vdev);
	if (!mlme_priv) {
		mlme_legacy_err("vdev legacy private object is NULL");
		return NULL;
	}

	return &mlme_priv->ini_cfg;
}

uint8_t *mlme_get_dynamic_oce_flags(struct wlan_objmgr_vdev *vdev)
{
	struct mlme_legacy_priv *mlme_priv;

	mlme_priv = wlan_vdev_mlme_get_ext_hdl(vdev);
	if (!mlme_priv) {
		mlme_legacy_err("vdev legacy private object is NULL");
		return NULL;
	}

	return &mlme_priv->sta_dynamic_oce_value;
}

QDF_STATUS mlme_init_rate_config(struct vdev_mlme_obj *vdev_mlme)
{
	struct mlme_legacy_priv *mlme_priv;

	mlme_priv = vdev_mlme->ext_vdev_ptr;
	if (!mlme_priv) {
		mlme_legacy_err("vdev legacy private object is NULL");
		return QDF_STATUS_E_FAILURE;
	}

	mlme_priv->opr_rate_set.max_len =
		QDF_MIN(CFG_OPERATIONAL_RATE_SET_LEN, CFG_STR_DATA_LEN);
	mlme_priv->opr_rate_set.len = 0;
	mlme_priv->ext_opr_rate_set.max_len =
		QDF_MIN(CFG_EXTENDED_OPERATIONAL_RATE_SET_LEN,
			CFG_STR_DATA_LEN);
	mlme_priv->ext_opr_rate_set.len = 0;
	mlme_priv->mcs_rate_set.max_len =
		QDF_MIN(CFG_SUPPORTED_MCS_SET_LEN, CFG_STR_DATA_LEN);
	mlme_priv->mcs_rate_set.len = 0;

	return QDF_STATUS_SUCCESS;
}

QDF_STATUS mlme_init_connect_chan_info_config(struct vdev_mlme_obj *vdev_mlme)
{
	struct mlme_legacy_priv *mlme_priv;

	mlme_priv = vdev_mlme->ext_vdev_ptr;
	if (!mlme_priv) {
		mlme_legacy_err("vdev legacy private object is NULL");
		return QDF_STATUS_E_FAILURE;
	}

	mlme_priv->connect_info.assoc_chan_info.assoc_ch_width =
							CH_WIDTH_INVALID;
	mlme_priv->connect_info.assoc_chan_info.omn_ie_ch_width =
							CH_WIDTH_INVALID;
	mlme_priv->connect_info.assoc_chan_info.sec_2g_freq = 0;
	mlme_priv->connect_info.assoc_chan_info.cen320_freq = 0;

	return QDF_STATUS_SUCCESS;
}

QDF_STATUS mlme_get_peer_mic_len(struct wlan_objmgr_psoc *psoc, uint8_t pdev_id,
				 uint8_t *peer_mac, uint8_t *mic_len,
				 uint8_t *mic_hdr_len)
{
	struct wlan_objmgr_peer *peer;
	int32_t key_cipher;

	if (!psoc || !mic_len || !mic_hdr_len || !peer_mac) {
		mlme_legacy_debug("psoc/mic_len/mic_hdr_len/peer_mac null");
		return QDF_STATUS_E_NULL_VALUE;
	}

	peer = wlan_objmgr_get_peer(psoc, pdev_id,
				    peer_mac, WLAN_LEGACY_MAC_ID);
	if (!peer) {
		mlme_legacy_debug("Peer of peer_mac "QDF_MAC_ADDR_FMT" not found",
				  QDF_MAC_ADDR_REF(peer_mac));
		return QDF_STATUS_E_INVAL;
	}

	key_cipher =
		wlan_crypto_get_peer_param(peer,
					   WLAN_CRYPTO_PARAM_UCAST_CIPHER);

	wlan_objmgr_peer_release_ref(peer, WLAN_LEGACY_MAC_ID);

	if (key_cipher < 0) {
		mlme_legacy_err("Invalid mgmt cipher");
		return QDF_STATUS_E_INVAL;
	}

	if (key_cipher & (1 << WLAN_CRYPTO_CIPHER_AES_GCM) ||
	    key_cipher & (1 << WLAN_CRYPTO_CIPHER_AES_GCM_256)) {
		*mic_hdr_len = WLAN_IEEE80211_GCMP_HEADERLEN;
		*mic_len = WLAN_IEEE80211_GCMP_MICLEN;
	} else {
		*mic_hdr_len = IEEE80211_CCMP_HEADERLEN;
		*mic_len = IEEE80211_CCMP_MICLEN;
	}
	mlme_legacy_debug("peer "QDF_MAC_ADDR_FMT" hdr_len %d mic_len %d key_cipher 0x%x",
			  QDF_MAC_ADDR_REF(peer_mac),
			  *mic_hdr_len, *mic_len, key_cipher);

	return QDF_STATUS_SUCCESS;
}

void
wlan_acquire_peer_key_wakelock(struct wlan_objmgr_pdev *pdev, uint8_t *mac_addr)
{
	uint8_t pdev_id;
	struct wlan_objmgr_peer *peer;
	struct peer_mlme_priv_obj *peer_priv;
	struct wlan_objmgr_psoc *psoc;

	psoc = wlan_pdev_get_psoc(pdev);
	if (!psoc)
		return;

	pdev_id = wlan_objmgr_pdev_get_pdev_id(pdev);
	peer = wlan_objmgr_get_peer(psoc, pdev_id, mac_addr,
				    WLAN_LEGACY_MAC_ID);
	if (!peer)
		return;

	peer_priv = wlan_objmgr_peer_get_comp_private_obj(peer,
							  WLAN_UMAC_COMP_MLME);
	if (!peer_priv) {
		wlan_objmgr_peer_release_ref(peer, WLAN_LEGACY_MAC_ID);
		return;
	}

	if (peer_priv->is_key_wakelock_set) {
		wlan_objmgr_peer_release_ref(peer, WLAN_LEGACY_MAC_ID);
		return;
	}

	mlme_debug(QDF_MAC_ADDR_FMT ": Acquire set key wake lock for %d ms",
		   QDF_MAC_ADDR_REF(mac_addr),
		   MLME_PEER_SET_KEY_WAKELOCK_TIMEOUT);
	qdf_wake_lock_timeout_acquire(&peer_priv->peer_set_key_wakelock,
				      MLME_PEER_SET_KEY_WAKELOCK_TIMEOUT);
	qdf_runtime_pm_prevent_suspend(
			&peer_priv->peer_set_key_runtime_wakelock);
	peer_priv->is_key_wakelock_set = true;

	wlan_objmgr_peer_release_ref(peer, WLAN_LEGACY_MAC_ID);
}

void
wlan_release_peer_key_wakelock(struct wlan_objmgr_pdev *pdev, uint8_t *mac_addr)
{
	uint8_t pdev_id;
	struct wlan_objmgr_peer *peer;
	struct peer_mlme_priv_obj *peer_priv;
	struct wlan_objmgr_psoc *psoc;

	psoc = wlan_pdev_get_psoc(pdev);
	if (!psoc)
		return;

	pdev_id = wlan_objmgr_pdev_get_pdev_id(pdev);
	peer = wlan_objmgr_get_peer(psoc, pdev_id, mac_addr,
				    WLAN_LEGACY_MAC_ID);
	if (!peer)
		return;

	peer_priv = wlan_objmgr_peer_get_comp_private_obj(peer,
							  WLAN_UMAC_COMP_MLME);
	if (!peer_priv) {
		wlan_objmgr_peer_release_ref(peer, WLAN_LEGACY_MAC_ID);
		return;
	}

	if (!peer_priv->is_key_wakelock_set) {
		wlan_objmgr_peer_release_ref(peer, WLAN_LEGACY_MAC_ID);
		return;
	}

	peer_priv->is_key_wakelock_set = false;
	mlme_debug(QDF_MAC_ADDR_FMT ": Release set key wake lock",
		   QDF_MAC_ADDR_REF(mac_addr));
	qdf_wake_lock_release(&peer_priv->peer_set_key_wakelock,
			      WIFI_POWER_EVENT_WAKELOCK_WMI_CMD_RSP);
	qdf_runtime_pm_allow_suspend(
			&peer_priv->peer_set_key_runtime_wakelock);

	wlan_objmgr_peer_release_ref(peer, WLAN_LEGACY_MAC_ID);
}

QDF_STATUS
mlme_peer_object_created_notification(struct wlan_objmgr_peer *peer,
				      void *arg)
{
	struct peer_mlme_priv_obj *peer_priv;
	QDF_STATUS status;

	if (!peer) {
		mlme_legacy_err(" peer is NULL");
		return QDF_STATUS_E_FAILURE;
	}

	peer_priv = qdf_mem_malloc(sizeof(*peer_priv));
	if (!peer_priv)
		return QDF_STATUS_E_NOMEM;

	status = wlan_objmgr_peer_component_obj_attach(peer,
						       WLAN_UMAC_COMP_MLME,
						       (void *)peer_priv,
						       QDF_STATUS_SUCCESS);

	if (QDF_IS_STATUS_ERROR(status)) {
		mlme_legacy_err("unable to attach peer_priv obj to peer obj");
		qdf_mem_free(peer_priv);
		return status;
	}

	qdf_wake_lock_create(&peer_priv->peer_set_key_wakelock, "peer_set_key");
	qdf_runtime_lock_init(&peer_priv->peer_set_key_runtime_wakelock);
	peer_priv->is_key_wakelock_set = false;
	peer_priv->peer_ind_bw = CH_WIDTH_INVALID;

	return status;
}

QDF_STATUS
mlme_peer_object_destroyed_notification(struct wlan_objmgr_peer *peer,
					void *arg)
{
	struct peer_mlme_priv_obj *peer_priv;
	QDF_STATUS status;

	if (!peer) {
		mlme_legacy_err(" peer is NULL");
		return QDF_STATUS_E_FAILURE;
	}

	peer_priv = wlan_objmgr_peer_get_comp_private_obj(peer,
							  WLAN_UMAC_COMP_MLME);
	if (!peer_priv) {
		mlme_legacy_err(" peer MLME component object is NULL");
		return QDF_STATUS_E_FAILURE;
	}

	peer_priv->is_key_wakelock_set = false;
	qdf_runtime_lock_deinit(&peer_priv->peer_set_key_runtime_wakelock);
	qdf_wake_lock_destroy(&peer_priv->peer_set_key_wakelock);

	status = wlan_objmgr_peer_component_obj_detach(peer,
						       WLAN_UMAC_COMP_MLME,
						       peer_priv);

	if (QDF_IS_STATUS_ERROR(status))
		mlme_legacy_err("unable to detach peer_priv obj to peer obj");

	mlme_free_peer_assoc_rsp_ie(peer_priv);
	qdf_mem_free(peer_priv);

	return status;
}

static void mlme_init_chainmask_cfg(struct wlan_objmgr_psoc *psoc,
				    struct wlan_mlme_chainmask *chainmask_info)
{
	chainmask_info->txchainmask1x1 =
		cfg_get(psoc, CFG_VHT_ENABLE_1x1_TX_CHAINMASK);

	chainmask_info->rxchainmask1x1 =
		cfg_get(psoc, CFG_VHT_ENABLE_1x1_RX_CHAINMASK);

	chainmask_info->tx_chain_mask_cck =
		cfg_get(psoc, CFG_TX_CHAIN_MASK_CCK);

	chainmask_info->tx_chain_mask_1ss =
		cfg_get(psoc, CFG_TX_CHAIN_MASK_1SS);

	chainmask_info->num_11b_tx_chains =
		cfg_get(psoc, CFG_11B_NUM_TX_CHAIN);

	chainmask_info->num_11ag_tx_chains =
		cfg_get(psoc, CFG_11AG_NUM_TX_CHAIN);

	chainmask_info->tx_chain_mask_2g =
		cfg_get(psoc, CFG_TX_CHAIN_MASK_2G);

	chainmask_info->rx_chain_mask_2g =
		cfg_get(psoc, CFG_RX_CHAIN_MASK_2G);

	chainmask_info->tx_chain_mask_5g =
		cfg_get(psoc, CFG_TX_CHAIN_MASK_5G);

	chainmask_info->rx_chain_mask_5g =
		cfg_get(psoc, CFG_RX_CHAIN_MASK_5G);

	chainmask_info->enable_bt_chain_separation =
		cfg_get(psoc, CFG_ENABLE_BT_CHAIN_SEPARATION);
#ifdef SEC_CONFIG_PSM_SYSFS
	if (wlan_hdd_sec_get_psm()) {
		chainmask_info->num_11b_tx_chains = 2;
		printk("[WIFI] CFG_11B_NUM_TX_CHAIN : sec_control_psm = %u", chainmask_info->num_11b_tx_chains);
	}
#endif /* SEC_CONFIG_PSM_SYSFS */
}

static void mlme_init_ratemask_cfg(struct wlan_objmgr_psoc *psoc,
				   struct wlan_mlme_ratemask *ratemask_cfg)
{
	uint32_t masks[CFG_MLME_RATE_MASK_LEN] = { 0 };
	qdf_size_t len = 0;
	QDF_STATUS status;

	ratemask_cfg->type = cfg_get(psoc, CFG_RATEMASK_TYPE);
	if ((ratemask_cfg->type <= WLAN_MLME_RATEMASK_TYPE_NO_MASK) ||
	    (ratemask_cfg->type >= WLAN_MLME_RATEMASK_TYPE_MAX)) {
		mlme_legacy_debug("Ratemask disabled");
		return;
	}

	status = qdf_uint32_array_parse(cfg_get(psoc, CFG_RATEMASK_SET),
					masks,
					CFG_MLME_RATE_MASK_LEN,
					&len);

	if (status != QDF_STATUS_SUCCESS || len != CFG_MLME_RATE_MASK_LEN) {
		/* Do not enable ratemask if config is invalid */
		ratemask_cfg->type = WLAN_MLME_RATEMASK_TYPE_NO_MASK;
		mlme_legacy_err("Failed to parse ratemask");
		return;
	}

	ratemask_cfg->lower32 = masks[0];
	ratemask_cfg->higher32 = masks[1];
	ratemask_cfg->lower32_2 = masks[2];
	ratemask_cfg->higher32_2 = masks[3];
	mlme_legacy_debug("Ratemask type: %d, masks:0x%x, 0x%x, 0x%x, 0x%x",
			  ratemask_cfg->type, ratemask_cfg->lower32,
			  ratemask_cfg->higher32, ratemask_cfg->lower32_2,
			  ratemask_cfg->higher32_2);
}

static void mlme_init_pmf_cfg(struct wlan_objmgr_psoc *psoc,
			      struct wlan_mlme_generic *gen)
{
	gen->pmf_sa_query_max_retries =
		cfg_get(psoc, CFG_PMF_SA_QUERY_MAX_RETRIES);
	gen->pmf_sa_query_retry_interval =
		cfg_get(psoc, CFG_PMF_SA_QUERY_RETRY_INTERVAL);
}

#ifdef WLAN_FEATURE_LPSS
static inline void
mlme_init_lpass_support_cfg(struct wlan_objmgr_psoc *psoc,
			    struct wlan_mlme_generic *gen)
{
	gen->lpass_support = cfg_get(psoc, CFG_ENABLE_LPASS_SUPPORT);
}
#else
static inline void
mlme_init_lpass_support_cfg(struct wlan_objmgr_psoc *psoc,
			    struct wlan_mlme_generic *gen)
{
	gen->lpass_support = cfg_default(CFG_ENABLE_LPASS_SUPPORT);
}
#endif

#ifdef FEATURE_WDS
/**
 * mlme_init_wds_config_cfg() - initialize wds_mode flag
 * @psoc: Pointer to PSOC
 * @gen: pointer to generic CFG items
 *
 * Return: None
 */
static void mlme_init_wds_config_cfg(struct wlan_objmgr_psoc *psoc,
				     struct wlan_mlme_generic *gen)
{
	gen->wds_mode = cfg_get(psoc, CFG_WDS_MODE);
}
#else
static void mlme_init_wds_config_cfg(struct wlan_objmgr_psoc *psoc,
				     struct wlan_mlme_generic *gen)
{
}
#endif

#ifdef CONFIG_BAND_6GHZ
/**
 * mlme_init_disable_vlp_sta_conn_to_sp_ap() - initialize disable vlp STA
 *                                             connection to sp AP flag
 * @psoc: Pointer to PSOC
 * @gen: pointer to generic CFG items
 *
 * Return: None
 */
static void mlme_init_disable_vlp_sta_conn_to_sp_ap(
						struct wlan_objmgr_psoc *psoc,
						struct wlan_mlme_generic *gen)
{
	gen->disable_vlp_sta_conn_to_sp_ap =
		cfg_default(CFG_DISABLE_VLP_STA_CONN_TO_SP_AP);
}
#else
static void mlme_init_disable_vlp_sta_conn_to_sp_ap(
						struct wlan_objmgr_psoc *psoc,
						struct wlan_mlme_generic *gen)
{
}
#endif

#ifdef CONFIG_BAND_6GHZ
/**
 * mlme_init_standard_6ghz_conn_policy() - initialize standard 6GHz
 *                                         policy connection flag
 * @psoc: Pointer to PSOC
 * @gen: pointer to generic CFG items
 *
 * Return: None
 */
static void mlme_init_standard_6ghz_conn_policy(struct wlan_objmgr_psoc *psoc,
						struct wlan_mlme_generic *gen)
{
	gen->std_6ghz_conn_policy =
		cfg_get(psoc, CFG_6GHZ_STANDARD_CONNECTION_POLICY);
}
#else
static void mlme_init_standard_6ghz_conn_policy(struct wlan_objmgr_psoc *psoc,
						struct wlan_mlme_generic *gen)
{
}
#endif

/**
 * mlme_init_mgmt_hw_tx_retry_count_cfg() - initialize mgmt hw tx retry count
 * @psoc: Pointer to PSOC
 * @gen: pointer to generic CFG items
 *
 * Return: None
 */
static void mlme_init_mgmt_hw_tx_retry_count_cfg(
			struct wlan_objmgr_psoc *psoc,
			struct wlan_mlme_generic *gen)
{
	uint32_t i;
	qdf_size_t out_size = 0;
	uint8_t count_array[MGMT_FRM_HW_TX_RETRY_COUNT_STR_LEN];

	qdf_uint8_array_parse(cfg_get(psoc, CFG_MGMT_FRAME_HW_TX_RETRY_COUNT),
			      count_array,
			      MGMT_FRM_HW_TX_RETRY_COUNT_STR_LEN,
			      &out_size);

	for (i = 0; i + 1 < out_size; i += 2) {
		if (count_array[i] >= CFG_FRAME_TYPE_MAX) {
			mlme_legacy_debug("invalid frm type %d",
					  count_array[i]);
			continue;
		}
		if (count_array[i + 1] >= MAX_MGMT_HW_TX_RETRY_COUNT) {
			mlme_legacy_debug("mgmt hw tx retry count %d for frm %d, limit to %d",
					  count_array[i + 1],
					  count_array[i],
					  MAX_MGMT_HW_TX_RETRY_COUNT);
			gen->mgmt_hw_tx_retry_count[count_array[i]] =
						MAX_MGMT_HW_TX_RETRY_COUNT;
		} else {
			mlme_legacy_debug("mgmt hw tx retry count %d for frm %d",
					  count_array[i + 1],
					  count_array[i]);
			gen->mgmt_hw_tx_retry_count[count_array[i]] =
							count_array[i + 1];
		}
	}
}

#ifdef WLAN_FEATURE_11BE_MLO
/**
 * mlme_init_emlsr_mode() - initialize emlsr mode enable flag
 * @psoc: Pointer to PSOC
 * @gen: pointer to generic CFG items
 *
 * Return: None
 */
static void mlme_init_emlsr_mode(struct wlan_objmgr_psoc *psoc,
				 struct wlan_mlme_generic *gen)
{
	gen->enable_emlsr_mode = cfg_default(CFG_EMLSR_MODE_ENABLE);
}

/**
 * mlme_init_tl2m_negotiation_support() - initialize t2lm support
 * @psoc: Pointer to PSOC
 * @gen: pointer to generic CFG items
 *
 * Return: None
 */
static void mlme_init_tl2m_negotiation_support(struct wlan_objmgr_psoc *psoc,
						 struct wlan_mlme_generic *gen)
{
	gen->t2lm_negotiation_support = cfg_get(psoc,
						CFG_T2LM_NEGOTIATION_SUPPORT);
}
#else
static void mlme_init_emlsr_mode(struct wlan_objmgr_psoc *psoc,
				 struct wlan_mlme_generic *gen)
{
}

static void mlme_init_tl2m_negotiation_support(struct wlan_objmgr_psoc *psoc,
						 struct wlan_mlme_generic *gen)
{
}
#endif

#if defined(WLAN_FEATURE_SR)
/**
 * mlme_init_sr_ini_cfg() - initialize SR(Spatial Reuse) ini
 * @psoc: Pointer to PSOC
 * @gen: pointer to generic CFG items
 *
 * Return: None
 */
static void mlme_init_sr_ini_cfg(struct wlan_objmgr_psoc *psoc,
				 struct wlan_mlme_generic *gen)
{
	gen->sr_enable_modes = cfg_get(psoc, CFG_SR_ENABLE_MODES);
}
#else
static void mlme_init_sr_ini_cfg(struct wlan_objmgr_psoc *psoc,
				 struct wlan_mlme_generic *gen)
{}
#endif

static void mlme_init_generic_cfg(struct wlan_objmgr_psoc *psoc,
				  struct wlan_mlme_generic *gen)
{
	gen->rtt3_enabled = cfg_default(CFG_RTT3_ENABLE);
	gen->rtt_mac_randomization =
		cfg_get(psoc, CFG_ENABLE_RTT_MAC_RANDOMIZATION);
	gen->band_capability =
		cfg_get(psoc, CFG_BAND_CAPABILITY);
	if (!gen->band_capability)
		gen->band_capability = REG_BAND_MASK_ALL;
	gen->band = gen->band_capability;
	gen->select_5ghz_margin =
		cfg_get(psoc, CFG_SELECT_5GHZ_MARGIN);
	gen->sub_20_chan_width =
		cfg_get(psoc, CFG_SUB_20_CHANNEL_WIDTH);
	gen->ito_repeat_count =
		cfg_get(psoc, CFG_ITO_REPEAT_COUNT);
	gen->dropped_pkt_disconnect_thresh =
		cfg_get(psoc, CFG_DROPPED_PKT_DISCONNECT_THRESHOLD);
	gen->prevent_link_down =
		cfg_get(psoc, CFG_PREVENT_LINK_DOWN);
	gen->memory_deep_sleep =
		cfg_get(psoc, CFG_ENABLE_MEM_DEEP_SLEEP);
	gen->cck_tx_fir_override =
		cfg_get(psoc, CFG_ENABLE_CCK_TX_FIR_OVERRIDE);
	gen->crash_inject =
		cfg_get(psoc, CFG_ENABLE_CRASH_INJECT);
	gen->self_recovery =
		cfg_get(psoc, CFG_ENABLE_SELF_RECOVERY);
	gen->sap_dot11mc =
		cfg_get(psoc, CFG_SAP_DOT11MC);
	gen->fatal_event_trigger =
		cfg_get(psoc, CFG_ENABLE_FATAL_EVENT_TRIGGER);
	gen->optimize_ca_event =
		cfg_get(psoc, CFG_OPTIMIZE_CA_EVENT);
	gen->fw_timeout_crash =
		cfg_get(psoc, CFG_CRASH_FW_TIMEOUT);
	gen->debug_packet_log = cfg_get(psoc, CFG_ENABLE_DEBUG_PACKET_LOG);
	gen->enable_deauth_to_disassoc_map =
		cfg_get(psoc, CFG_ENABLE_DEAUTH_TO_DISASSOC_MAP);
	gen->wls_6ghz_capable = cfg_get(psoc, CFG_WLS_6GHZ_CAPABLE);
	mlme_init_pmf_cfg(psoc, gen);
	mlme_init_lpass_support_cfg(psoc, gen);
	gen->enabled_rf_test_mode = cfg_default(CFG_RF_TEST_MODE_SUPP_ENABLED);
	gen->enabled_11h = cfg_get(psoc, CFG_11H_SUPPORT_ENABLED);
	gen->enabled_11d = cfg_get(psoc, CFG_11D_SUPPORT_ENABLED);
	gen->enable_beacon_reception_stats =
		cfg_get(psoc, CFG_ENABLE_BEACON_RECEPTION_STATS);
	gen->disable_4way_hs_offload =
		cfg_get(psoc, CFG_DISABLE_4WAY_HS_OFFLOAD);
	gen->mgmt_retry_max = cfg_get(psoc, CFG_MGMT_RETRY_MAX);
	gen->bmiss_skip_full_scan = cfg_get(psoc, CFG_BMISS_SKIP_FULL_SCAN);
	gen->enable_ring_buffer = cfg_get(psoc, CFG_ENABLE_RING_BUFFER);
	gen->enable_peer_unmap_conf_support =
		cfg_get(psoc, CFG_DP_ENABLE_PEER_UMAP_CONF_SUPPORT);
	gen->dfs_chan_ageout_time =
		cfg_get(psoc, CFG_DFS_CHAN_AGEOUT_TIME);
	gen->sae_connect_retries =
		cfg_get(psoc, CFG_SAE_CONNECION_RETRIES);
	gen->monitor_mode_concurrency =
		cfg_get(psoc, CFG_MONITOR_MODE_CONCURRENCY);
	gen->tx_retry_multiplier = cfg_get(psoc, CFG_TX_RETRY_MULTIPLIER);
	gen->enable_he_mcs0_for_6ghz_mgmt =
		cfg_get(psoc, CFG_ENABLE_HE_MCS0_MGMT_6GHZ);
	mlme_init_sr_ini_cfg(psoc, gen);
	mlme_init_wds_config_cfg(psoc, gen);
	mlme_init_mgmt_hw_tx_retry_count_cfg(psoc, gen);
	mlme_init_emlsr_mode(psoc, gen);
	mlme_init_tl2m_negotiation_support(psoc, gen);
	mlme_init_standard_6ghz_conn_policy(psoc, gen);
	mlme_init_disable_vlp_sta_conn_to_sp_ap(psoc, gen);
}

static void mlme_init_edca_ani_cfg(struct wlan_objmgr_psoc *psoc,
				   struct wlan_mlme_edca_params *edca_params)
{
	/* initialize the max allowed array length for read/write */
	edca_params->ani_acbe_l.max_len = CFG_EDCA_DATA_LEN;
	edca_params->ani_acbk_l.max_len = CFG_EDCA_DATA_LEN;
	edca_params->ani_acvi_l.max_len = CFG_EDCA_DATA_LEN;
	edca_params->ani_acvo_l.max_len = CFG_EDCA_DATA_LEN;

	edca_params->ani_acbe_b.max_len = CFG_EDCA_DATA_LEN;
	edca_params->ani_acbk_b.max_len = CFG_EDCA_DATA_LEN;
	edca_params->ani_acvi_b.max_len = CFG_EDCA_DATA_LEN;
	edca_params->ani_acvo_b.max_len = CFG_EDCA_DATA_LEN;

	/* parse the ETSI edca parameters from cfg string for BK,BE,VI,VO ac */
	qdf_uint8_array_parse(cfg_get(psoc, CFG_EDCA_ANI_ACBK_LOCAL),
			      edca_params->ani_acbk_l.data,
			      CFG_EDCA_DATA_LEN,
			      &edca_params->ani_acbk_l.len);

	qdf_uint8_array_parse(cfg_get(psoc, CFG_EDCA_ANI_ACBE_LOCAL),
			      edca_params->ani_acbe_l.data,
			      CFG_EDCA_DATA_LEN,
			      &edca_params->ani_acbe_l.len);

	qdf_uint8_array_parse(cfg_get(psoc, CFG_EDCA_ANI_ACVI_LOCAL),
			      edca_params->ani_acvi_l.data,
			      CFG_EDCA_DATA_LEN,
			      &edca_params->ani_acvi_l.len);

	qdf_uint8_array_parse(cfg_get(psoc, CFG_EDCA_ANI_ACVO_LOCAL),
			      edca_params->ani_acvo_l.data,
			      CFG_EDCA_DATA_LEN,
			      &edca_params->ani_acvo_l.len);

	qdf_uint8_array_parse(cfg_get(psoc, CFG_EDCA_ANI_ACBK),
			      edca_params->ani_acbk_b.data,
			      CFG_EDCA_DATA_LEN,
			      &edca_params->ani_acbk_b.len);

	qdf_uint8_array_parse(cfg_get(psoc, CFG_EDCA_ANI_ACBE),
			      edca_params->ani_acbe_b.data,
			      CFG_EDCA_DATA_LEN,
			      &edca_params->ani_acbe_b.len);

	qdf_uint8_array_parse(cfg_get(psoc, CFG_EDCA_ANI_ACVI),
			      edca_params->ani_acvi_b.data,
			      CFG_EDCA_DATA_LEN,
			      &edca_params->ani_acvi_b.len);

	qdf_uint8_array_parse(cfg_get(psoc, CFG_EDCA_ANI_ACVO),
			      edca_params->ani_acvo_b.data,
			      CFG_EDCA_DATA_LEN,
			      &edca_params->ani_acvo_b.len);
}

static void mlme_init_edca_wme_cfg(struct wlan_objmgr_psoc *psoc,
				   struct wlan_mlme_edca_params *edca_params)
{
	/* initialize the max allowed array length for read/write */
	edca_params->wme_acbk_l.max_len = CFG_EDCA_DATA_LEN;
	edca_params->wme_acbe_l.max_len = CFG_EDCA_DATA_LEN;
	edca_params->wme_acvi_l.max_len = CFG_EDCA_DATA_LEN;
	edca_params->wme_acvo_l.max_len = CFG_EDCA_DATA_LEN;

	edca_params->wme_acbk_b.max_len = CFG_EDCA_DATA_LEN;
	edca_params->wme_acbe_b.max_len = CFG_EDCA_DATA_LEN;
	edca_params->wme_acvi_b.max_len = CFG_EDCA_DATA_LEN;
	edca_params->wme_acvo_b.max_len = CFG_EDCA_DATA_LEN;

	/* parse the WME edca parameters from cfg string for BK,BE,VI,VO ac */
	qdf_uint8_array_parse(cfg_get(psoc, CFG_EDCA_WME_ACBK_LOCAL),
			      edca_params->wme_acbk_l.data,
			      CFG_EDCA_DATA_LEN,
			      &edca_params->wme_acbk_l.len);

	qdf_uint8_array_parse(cfg_get(psoc, CFG_EDCA_WME_ACBE_LOCAL),
			      edca_params->wme_acbe_l.data,
			      CFG_EDCA_DATA_LEN,
			      &edca_params->wme_acbe_l.len);

	qdf_uint8_array_parse(cfg_get(psoc, CFG_EDCA_WME_ACVI_LOCAL),
			      edca_params->wme_acvi_l.data,
			      CFG_EDCA_DATA_LEN,
			      &edca_params->wme_acvi_l.len);

	qdf_uint8_array_parse(cfg_get(psoc, CFG_EDCA_WME_ACVO_LOCAL),
			      edca_params->wme_acvo_l.data,
			      CFG_EDCA_DATA_LEN,
			      &edca_params->wme_acvo_l.len);

	qdf_uint8_array_parse(cfg_get(psoc, CFG_EDCA_WME_ACBK),
			      edca_params->wme_acbk_b.data,
			      CFG_EDCA_DATA_LEN,
			      &edca_params->wme_acbk_b.len);

	qdf_uint8_array_parse(cfg_get(psoc, CFG_EDCA_WME_ACBE),
			      edca_params->wme_acbe_b.data,
			      CFG_EDCA_DATA_LEN,
			      &edca_params->wme_acbe_b.len);

	qdf_uint8_array_parse(cfg_get(psoc, CFG_EDCA_WME_ACVI),
			      edca_params->wme_acvi_b.data,
			      CFG_EDCA_DATA_LEN,
			      &edca_params->wme_acvi_b.len);

	qdf_uint8_array_parse(cfg_get(psoc, CFG_EDCA_WME_ACVO),
			      edca_params->wme_acvo_b.data,
			      CFG_EDCA_DATA_LEN,
			      &edca_params->wme_acvo_b.len);
}

static void mlme_init_edca_etsi_cfg(struct wlan_objmgr_psoc *psoc,
				    struct wlan_mlme_edca_params *edca_params)
{
	/* initialize the max allowed array length for read/write */
	edca_params->etsi_acbe_l.max_len = CFG_EDCA_DATA_LEN;
	edca_params->etsi_acbk_l.max_len = CFG_EDCA_DATA_LEN;
	edca_params->etsi_acvi_l.max_len = CFG_EDCA_DATA_LEN;
	edca_params->etsi_acvo_l.max_len = CFG_EDCA_DATA_LEN;

	edca_params->etsi_acbe_b.max_len = CFG_EDCA_DATA_LEN;
	edca_params->etsi_acbk_b.max_len = CFG_EDCA_DATA_LEN;
	edca_params->etsi_acvi_b.max_len = CFG_EDCA_DATA_LEN;
	edca_params->etsi_acvo_b.max_len = CFG_EDCA_DATA_LEN;

	/* parse the ETSI edca parameters from cfg string for BK,BE,VI,VO ac */
	qdf_uint8_array_parse(cfg_get(psoc, CFG_EDCA_ETSI_ACBK_LOCAL),
			      edca_params->etsi_acbk_l.data,
			      CFG_EDCA_DATA_LEN,
			      &edca_params->etsi_acbk_l.len);

	qdf_uint8_array_parse(cfg_get(psoc, CFG_EDCA_ETSI_ACBE_LOCAL),
			      edca_params->etsi_acbe_l.data,
			      CFG_EDCA_DATA_LEN,
			      &edca_params->etsi_acbe_l.len);

	qdf_uint8_array_parse(cfg_get(psoc, CFG_EDCA_ETSI_ACVI_LOCAL),
			      edca_params->etsi_acvi_l.data,
			      CFG_EDCA_DATA_LEN,
			      &edca_params->etsi_acvi_l.len);

	qdf_uint8_array_parse(cfg_get(psoc, CFG_EDCA_ETSI_ACVO_LOCAL),
			      edca_params->etsi_acvo_l.data,
			      CFG_EDCA_DATA_LEN,
			      &edca_params->etsi_acvo_l.len);

	qdf_uint8_array_parse(cfg_get(psoc, CFG_EDCA_ETSI_ACBK),
			      edca_params->etsi_acbk_b.data,
			      CFG_EDCA_DATA_LEN,
			      &edca_params->etsi_acbk_b.len);

	qdf_uint8_array_parse(cfg_get(psoc, CFG_EDCA_ETSI_ACBE),
			      edca_params->etsi_acbe_b.data,
			      CFG_EDCA_DATA_LEN,
			      &edca_params->etsi_acbe_b.len);

	qdf_uint8_array_parse(cfg_get(psoc, CFG_EDCA_ETSI_ACVI),
			      edca_params->etsi_acvi_b.data,
			      CFG_EDCA_DATA_LEN,
			      &edca_params->etsi_acvi_b.len);

	qdf_uint8_array_parse(cfg_get(psoc, CFG_EDCA_ETSI_ACVO),
			      edca_params->etsi_acvo_b.data,
			      CFG_EDCA_DATA_LEN,
			      &edca_params->etsi_acvo_b.len);
}

static void
mlme_init_qos_edca_params(struct wlan_objmgr_psoc *psoc,
			  struct wlan_mlme_edca_params *edca_params)
{
	edca_params->enable_edca_params =
			cfg_get(psoc, CFG_EDCA_ENABLE_PARAM);

	edca_params->enable_wmm_txop =
			cfg_get(psoc, CFG_ENABLE_WMM_TXOP);
	edca_params->edca_ac_vo.vo_cwmin =
			cfg_get(psoc, CFG_EDCA_VO_CWMIN);
	edca_params->edca_ac_vo.vo_cwmax =
			cfg_get(psoc, CFG_EDCA_VO_CWMAX);
	edca_params->edca_ac_vo.vo_aifs =
			cfg_get(psoc, CFG_EDCA_VO_AIFS);

	edca_params->edca_ac_vi.vi_cwmin =
			cfg_get(psoc, CFG_EDCA_VI_CWMIN);
	edca_params->edca_ac_vi.vi_cwmax =
			cfg_get(psoc, CFG_EDCA_VI_CWMAX);
	edca_params->edca_ac_vi.vi_aifs =
			cfg_get(psoc, CFG_EDCA_VI_AIFS);

	edca_params->edca_ac_bk.bk_cwmin =
			cfg_get(psoc, CFG_EDCA_BK_CWMIN);
	edca_params->edca_ac_bk.bk_cwmax =
			cfg_get(psoc, CFG_EDCA_BK_CWMAX);
	edca_params->edca_ac_bk.bk_aifs =
			cfg_get(psoc, CFG_EDCA_BK_AIFS);

	edca_params->edca_ac_be.be_cwmin =
			cfg_get(psoc, CFG_EDCA_BE_CWMIN);
	edca_params->edca_ac_be.be_cwmax =
			cfg_get(psoc, CFG_EDCA_BE_CWMAX);
	edca_params->edca_ac_be.be_aifs =
			cfg_get(psoc, CFG_EDCA_BE_AIFS);

	edca_params->edca_param_type =
			cfg_get(psoc, CFG_EDCA_PIFS_PARAM_TYPE);
}

static void mlme_init_edca_params(struct wlan_objmgr_psoc *psoc,
				  struct wlan_mlme_edca_params *edca_params)
{
	mlme_init_edca_ani_cfg(psoc, edca_params);
	mlme_init_edca_wme_cfg(psoc, edca_params);
	mlme_init_edca_etsi_cfg(psoc, edca_params);
	mlme_init_qos_edca_params(psoc, edca_params);
}

static void mlme_init_timeout_cfg(struct wlan_objmgr_psoc *psoc,
				  struct wlan_mlme_timeout *timeouts)
{
	timeouts->join_failure_timeout =
			cfg_get(psoc, CFG_JOIN_FAILURE_TIMEOUT);
	timeouts->join_failure_timeout_ori = timeouts->join_failure_timeout;
	timeouts->probe_req_retry_timeout = JOIN_PROBE_REQ_TIMER_MS;
	timeouts->auth_failure_timeout =
			cfg_get(psoc, CFG_AUTH_FAILURE_TIMEOUT);
	timeouts->auth_rsp_timeout =
			cfg_get(psoc, CFG_AUTH_RSP_TIMEOUT);
	timeouts->assoc_failure_timeout =
			cfg_get(psoc, CFG_ASSOC_FAILURE_TIMEOUT);
	timeouts->reassoc_failure_timeout =
			cfg_get(psoc, CFG_REASSOC_FAILURE_TIMEOUT);
	timeouts->olbc_detect_timeout =
			cfg_get(psoc, CFG_OLBC_DETECT_TIMEOUT);
	timeouts->addts_rsp_timeout =
			cfg_get(psoc, CFG_ADDTS_RSP_TIMEOUT);
	timeouts->heart_beat_threshold =
			cfg_get(psoc, CFG_HEART_BEAT_THRESHOLD);
	timeouts->ap_keep_alive_timeout =
			cfg_get(psoc, CFG_AP_KEEP_ALIVE_TIMEOUT);
	timeouts->ap_link_monitor_timeout =
			cfg_get(psoc, CFG_AP_LINK_MONITOR_TIMEOUT);
	timeouts->wmi_wq_watchdog_timeout =
			cfg_get(psoc, CFG_WMI_WQ_WATCHDOG);
	timeouts->sae_auth_failure_timeout =
			cfg_get(psoc, CFG_SAE_AUTH_FAILURE_TIMEOUT);
}

static void mlme_init_ht_cap_in_cfg(struct wlan_objmgr_psoc *psoc,
				    struct wlan_mlme_ht_caps *ht_caps)
{
	union {
		uint16_t val_16;
		struct mlme_ht_capabilities_info ht_cap_info;
	} u1;

	union {
		uint16_t val_16;
		struct mlme_ht_ext_cap_info ext_cap_info;
	} u2;

	union {
		uint8_t val_8;
		struct mlme_ht_info_field_1 info_field_1;
	} u3;

	union {
		uint16_t val_16;
		struct mlme_ht_info_field_2 info_field_2;
	} u4;

	union {
		uint16_t val_16;
		struct mlme_ht_info_field_3 info_field_3;
	} u5;

	/* HT Capabilities - HT Caps Info Field */
	u1.val_16 = (uint16_t)cfg_default(CFG_HT_CAP_INFO);
	u1.ht_cap_info.adv_coding_cap =
				cfg_get(psoc, CFG_RX_LDPC_ENABLE);
	u1.ht_cap_info.rx_stbc = cfg_get(psoc, CFG_RX_STBC_ENABLE);
	u1.ht_cap_info.tx_stbc = cfg_get(psoc, CFG_TX_STBC_ENABLE);
	u1.ht_cap_info.short_gi_20_mhz =
				cfg_get(psoc, CFG_SHORT_GI_20MHZ);
	u1.ht_cap_info.short_gi_40_mhz =
				cfg_get(psoc, CFG_SHORT_GI_40MHZ);
	ht_caps->ht_cap_info = u1.ht_cap_info;

	/* HT Capapabilties - AMPDU Params */
	ht_caps->ampdu_params.max_rx_ampdu_factor =
		cfg_get(psoc, CFG_MAX_RX_AMPDU_FACTOR);
	ht_caps->ampdu_params.mpdu_density =
		cfg_get(psoc, CFG_MPDU_DENSITY);
	ht_caps->ampdu_params.reserved = 0;

	/* HT Capabilities - Extended Capabilities field */
	u2.val_16 = (uint16_t)cfg_default(CFG_EXT_HT_CAP_INFO);
	ht_caps->ext_cap_info = u2.ext_cap_info;

	/* HT Operation - Information subset 1 of 3 */
	u3.val_8 = (uint8_t)cfg_default(CFG_HT_INFO_FIELD_1);
	ht_caps->info_field_1 = u3.info_field_1;

	/* HT Operation - Information subset 2 of 3 */
	u4.val_16 = (uint16_t)cfg_default(CFG_HT_INFO_FIELD_2);
	ht_caps->info_field_2 = u4.info_field_2;

	/* HT Operation - Information subset 3 of 3 */
	u5.val_16 = (uint16_t)cfg_default(CFG_HT_INFO_FIELD_3);
	ht_caps->info_field_3 = u5.info_field_3;

	ht_caps->short_preamble = cfg_get(psoc, CFG_SHORT_PREAMBLE);
	ht_caps->enable_ampdu_ps = cfg_get(psoc, CFG_ENABLE_AMPDUPS);
	ht_caps->enable_smps = cfg_get(psoc, CFG_ENABLE_HT_SMPS);
	ht_caps->smps = cfg_get(psoc, CFG_HT_SMPS_MODE);
	ht_caps->max_num_amsdu = cfg_get(psoc, CFG_MAX_AMSDU_NUM);
	ht_caps->tx_ldpc_enable = cfg_get(psoc, CFG_TX_LDPC_ENABLE);
	ht_caps->short_slot_time_enabled =
		cfg_get(psoc, CFG_SHORT_SLOT_TIME_ENABLED);
}

static void mlme_init_qos_cfg(struct wlan_objmgr_psoc *psoc,
			      struct wlan_mlme_qos *qos_aggr_params)
{
	qos_aggr_params->tx_aggregation_size =
				cfg_get(psoc, CFG_TX_AGGREGATION_SIZE);
	qos_aggr_params->tx_aggregation_size_be =
				cfg_get(psoc, CFG_TX_AGGREGATION_SIZEBE);
	qos_aggr_params->tx_aggregation_size_bk =
				cfg_get(psoc, CFG_TX_AGGREGATION_SIZEBK);
	qos_aggr_params->tx_aggregation_size_vi =
				cfg_get(psoc, CFG_TX_AGGREGATION_SIZEVI);
	qos_aggr_params->tx_aggregation_size_vo =
				cfg_get(psoc, CFG_TX_AGGREGATION_SIZEVO);
	qos_aggr_params->rx_aggregation_size =
				cfg_get(psoc, CFG_RX_AGGREGATION_SIZE);
	qos_aggr_params->tx_aggr_sw_retry_threshold_be =
				cfg_get(psoc, CFG_TX_AGGR_SW_RETRY_BE);
	qos_aggr_params->tx_aggr_sw_retry_threshold_bk =
				cfg_get(psoc, CFG_TX_AGGR_SW_RETRY_BK);
	qos_aggr_params->tx_aggr_sw_retry_threshold_vi =
				cfg_get(psoc, CFG_TX_AGGR_SW_RETRY_VI);
	qos_aggr_params->tx_aggr_sw_retry_threshold_vo =
				cfg_get(psoc, CFG_TX_AGGR_SW_RETRY_VO);
	qos_aggr_params->tx_aggr_sw_retry_threshold =
				cfg_get(psoc, CFG_TX_AGGR_SW_RETRY);
	qos_aggr_params->tx_non_aggr_sw_retry_threshold_be =
				cfg_get(psoc, CFG_TX_NON_AGGR_SW_RETRY_BE);
	qos_aggr_params->tx_non_aggr_sw_retry_threshold_bk =
				cfg_get(psoc, CFG_TX_NON_AGGR_SW_RETRY_BK);
	qos_aggr_params->tx_non_aggr_sw_retry_threshold_vi =
				cfg_get(psoc, CFG_TX_NON_AGGR_SW_RETRY_VI);
	qos_aggr_params->tx_non_aggr_sw_retry_threshold_vo =
				cfg_get(psoc, CFG_TX_NON_AGGR_SW_RETRY_VO);
	qos_aggr_params->tx_non_aggr_sw_retry_threshold =
				cfg_get(psoc, CFG_TX_NON_AGGR_SW_RETRY);
	qos_aggr_params->sap_max_inactivity_override =
				cfg_get(psoc, CFG_SAP_MAX_INACTIVITY_OVERRIDE);
	qos_aggr_params->sap_uapsd_enabled =
				cfg_get(psoc, CFG_SAP_QOS_UAPSD);
}

static void mlme_init_mbo_cfg(struct wlan_objmgr_psoc *psoc,
			      struct wlan_mlme_mbo *mbo_params)
{
	mbo_params->mbo_candidate_rssi_thres =
			cfg_get(psoc, CFG_MBO_CANDIDATE_RSSI_THRESHOLD);
	mbo_params->mbo_current_rssi_thres =
			cfg_get(psoc, CFG_MBO_CURRENT_RSSI_THRESHOLD);
	mbo_params->mbo_current_rssi_mcc_thres =
			cfg_get(psoc, CFG_MBO_CUR_RSSI_MCC_THRESHOLD);
	mbo_params->mbo_candidate_rssi_btc_thres =
			cfg_get(psoc, CFG_MBO_CAND_RSSI_BTC_THRESHOLD);
}

static void mlme_init_vht_cap_cfg(struct wlan_objmgr_psoc *psoc,
				  struct mlme_vht_capabilities_info
				  *vht_cap_info)
{
	vht_cap_info->supp_chan_width =
			cfg_default(CFG_VHT_SUPP_CHAN_WIDTH);
	vht_cap_info->num_soundingdim =
			cfg_default(CFG_VHT_NUM_SOUNDING_DIMENSIONS);
	vht_cap_info->htc_vhtc =
			cfg_default(CFG_VHT_HTC_VHTC);
	vht_cap_info->link_adap_cap =
			cfg_default(CFG_VHT_LINK_ADAPTATION_CAP);
	vht_cap_info->rx_antpattern =
			cfg_default(CFG_VHT_RX_ANT_PATTERN);
	vht_cap_info->tx_antpattern =
			cfg_default(CFG_VHT_TX_ANT_PATTERN);
	vht_cap_info->rx_supp_data_rate =
			cfg_default(CFG_VHT_RX_SUPP_DATA_RATE);
	vht_cap_info->tx_supp_data_rate =
			cfg_default(CFG_VHT_TX_SUPP_DATA_RATE);
	vht_cap_info->txop_ps =
			cfg_default(CFG_VHT_TXOP_PS);
	vht_cap_info->rx_mcs_map =
			CFG_VHT_RX_MCS_MAP_STADEF;
	vht_cap_info->tx_mcs_map =
			CFG_VHT_TX_MCS_MAP_STADEF;
	vht_cap_info->basic_mcs_set =
			CFG_VHT_BASIC_MCS_SET_STADEF;

	vht_cap_info->tx_bfee_ant_supp =
			cfg_get(psoc, CFG_VHT_BEAMFORMEE_ANT_SUPP);

	vht_cap_info->enable_txbf_20mhz =
			cfg_get(psoc, CFG_VHT_ENABLE_TXBF_IN_20MHZ);
	vht_cap_info->ampdu_len =
			cfg_get(psoc, CFG_VHT_MPDU_LEN);

	vht_cap_info->ldpc_coding_cap =
			cfg_get(psoc, CFG_RX_LDPC_ENABLE);
	vht_cap_info->short_gi_80mhz =
			cfg_get(psoc, CFG_SHORT_GI_40MHZ);
	vht_cap_info->short_gi_160mhz =
			cfg_get(psoc, CFG_SHORT_GI_40MHZ);
	vht_cap_info->tx_stbc =
			cfg_get(psoc, CFG_TX_STBC_ENABLE);
	vht_cap_info->rx_stbc =
			cfg_get(psoc, CFG_RX_STBC_ENABLE);

	vht_cap_info->su_bformee =
		cfg_get(psoc, CFG_VHT_SU_BEAMFORMEE_CAP);

	vht_cap_info->mu_bformer =
			cfg_default(CFG_VHT_MU_BEAMFORMER_CAP);

	vht_cap_info->enable_mu_bformee =
			cfg_get(psoc, CFG_VHT_ENABLE_MU_BFORMEE_CAP_FEATURE);
	vht_cap_info->ampdu_len_exponent =
			cfg_get(psoc, CFG_VHT_AMPDU_LEN_EXPONENT);
	vht_cap_info->channel_width =
			cfg_get(psoc, CFG_VHT_CHANNEL_WIDTH);
	vht_cap_info->rx_mcs =
			cfg_get(psoc, CFG_VHT_ENABLE_RX_MCS_8_9);
	vht_cap_info->tx_mcs =
			cfg_get(psoc, CFG_VHT_ENABLE_TX_MCS_8_9);
	vht_cap_info->rx_mcs2x2 =
			cfg_get(psoc, CFG_VHT_ENABLE_RX_MCS2x2_8_9);
	vht_cap_info->tx_mcs2x2 =
			cfg_get(psoc, CFG_VHT_ENABLE_TX_MCS2x2_8_9);
	vht_cap_info->enable_vht20_mcs9 =
			cfg_get(psoc, CFG_ENABLE_VHT20_MCS9);
	vht_cap_info->enable2x2 =
			cfg_get(psoc, CFG_VHT_ENABLE_2x2_CAP_FEATURE);
	vht_cap_info->enable_paid =
			cfg_get(psoc, CFG_VHT_ENABLE_PAID_FEATURE);
	vht_cap_info->enable_gid =
			cfg_get(psoc, CFG_VHT_ENABLE_GID_FEATURE);
	vht_cap_info->b24ghz_band =
			cfg_get(psoc, CFG_ENABLE_VHT_FOR_24GHZ);
	vht_cap_info->vendor_24ghz_band =
			cfg_get(psoc, CFG_ENABLE_VENDOR_VHT_FOR_24GHZ);
	vht_cap_info->tx_bfee_sap =
			cfg_get(psoc, CFG_VHT_ENABLE_TXBF_SAP_MODE);
	vht_cap_info->vendor_vhtie =
			cfg_get(psoc, CFG_ENABLE_SUBFEE_IN_VENDOR_VHTIE);

	if (vht_cap_info->enable2x2)
		vht_cap_info->su_bformer =
			cfg_get(psoc, CFG_VHT_ENABLE_TX_SU_BEAM_FORMER);

	if (vht_cap_info->enable2x2 && vht_cap_info->su_bformer)
		vht_cap_info->num_soundingdim = NUM_OF_SOUNDING_DIMENSIONS;

	vht_cap_info->tx_bf_cap = cfg_default(CFG_TX_BF_CAP);
	vht_cap_info->as_cap = cfg_default(CFG_AS_CAP);
	vht_cap_info->disable_ldpc_with_txbf_ap =
			cfg_get(psoc, CFG_DISABLE_LDPC_WITH_TXBF_AP);
}

static void mlme_init_rates_in_cfg(struct wlan_objmgr_psoc *psoc,
				   struct wlan_mlme_rates *rates)
{
	rates->cfp_period = cfg_default(CFG_CFP_PERIOD);
	rates->cfp_max_duration = cfg_default(CFG_CFP_MAX_DURATION);
	rates->max_htmcs_txdata = cfg_get(psoc, CFG_MAX_HT_MCS_FOR_TX_DATA);
	rates->disable_abg_rate_txdata = cfg_get(psoc,
					CFG_DISABLE_ABG_RATE_FOR_TX_DATA);
	rates->sap_max_mcs_txdata = cfg_get(psoc,
					CFG_SAP_MAX_MCS_FOR_TX_DATA);
	rates->disable_high_ht_mcs_2x2 = cfg_get(psoc,
					 CFG_DISABLE_HIGH_HT_RX_MCS_2x2);

	rates->supported_11b.max_len = CFG_SUPPORTED_RATES_11B_LEN;
	qdf_uint8_array_parse(cfg_default(CFG_SUPPORTED_RATES_11B),
			      rates->supported_11b.data,
			      sizeof(rates->supported_11b.data),
			      &rates->supported_11b.len);
	rates->supported_11a.max_len = CFG_SUPPORTED_RATES_11A_LEN;
	qdf_uint8_array_parse(cfg_default(CFG_SUPPORTED_RATES_11A),
			      rates->supported_11a.data,
			      sizeof(rates->supported_11a.data),
			      &rates->supported_11a.len);
	rates->supported_mcs_set.max_len = CFG_SUPPORTED_MCS_SET_LEN;
	qdf_uint8_array_parse(cfg_default(CFG_SUPPORTED_MCS_SET),
			      rates->supported_mcs_set.data,
			      sizeof(rates->supported_mcs_set.data),
			      &rates->supported_mcs_set.len);
	rates->basic_mcs_set.max_len = CFG_BASIC_MCS_SET_LEN;
	qdf_uint8_array_parse(cfg_default(CFG_BASIC_MCS_SET),
			      rates->basic_mcs_set.data,
			      sizeof(rates->basic_mcs_set.data),
			      &rates->basic_mcs_set.len);
	rates->current_mcs_set.max_len = CFG_CURRENT_MCS_SET_LEN;
	qdf_uint8_array_parse(cfg_default(CFG_CURRENT_MCS_SET),
			      rates->current_mcs_set.data,
			      sizeof(rates->current_mcs_set.data),
			      &rates->current_mcs_set.len);
}

static void mlme_init_passive_enable_in_cfg(struct wlan_objmgr_psoc *psoc,
					    struct wlan_mlme_cfg *mlme_cfg)
{
	mlme_cfg->passive_chan_discard_mode =
		cfg_get(psoc, CFG_DISCARD_PASSIVE_CHANNEL_FOR_MODE);
}

static void mlme_init_dfs_cfg(struct wlan_objmgr_psoc *psoc,
			      struct wlan_mlme_dfs_cfg *dfs_cfg)
{
	dfs_cfg->dfs_ignore_cac = cfg_get(psoc, CFG_IGNORE_CAC);
	dfs_cfg->dfs_master_capable =
		cfg_get(psoc, CFG_ENABLE_DFS_MASTER_CAPABILITY);
	dfs_cfg->dfs_disable_channel_switch =
		cfg_get(psoc, CFG_DISABLE_DFS_CH_SWITCH);
	dfs_cfg->dfs_filter_offload =
		cfg_get(psoc, CFG_ENABLE_DFS_PHYERR_FILTEROFFLOAD);
	dfs_cfg->dfs_prefer_non_dfs =
		cfg_get(psoc, CFG_ENABLE_NON_DFS_CHAN_ON_RADAR);
	dfs_cfg->dfs_beacon_tx_enhanced =
		cfg_get(psoc, CFG_DFS_BEACON_TX_ENHANCED);
	dfs_cfg->dfs_disable_japan_w53 =
		cfg_get(psoc, CFG_DISABLE_DFS_JAPAN_W53);
	dfs_cfg->sap_tx_leakage_threshold =
		cfg_get(psoc, CFG_SAP_TX_LEAKAGE_THRESHOLD);
	dfs_cfg->dfs_pri_multiplier =
		cfg_get(psoc, CFG_DFS_RADAR_PRI_MULTIPLIER);
	dfs_cfg->dfs_discard_mode =
		cfg_get(psoc, CFG_DISCARD_DFS_CHANNEL_FOR_MODE);
}

static void mlme_init_feature_flag_in_cfg(
				struct wlan_objmgr_psoc *psoc,
				struct wlan_mlme_feature_flag *feature_flags)
{
	feature_flags->accept_short_slot_assoc =
				cfg_default(CFG_ACCEPT_SHORT_SLOT_ASSOC_ONLY);
	feature_flags->enable_hcf = cfg_default(CFG_HCF_ENABLED);
	feature_flags->enable_rsn = cfg_default(CFG_RSN_ENABLED);
	feature_flags->enable_short_preamble_11g =
				cfg_default(CFG_11G_SHORT_PREAMBLE_ENABLED);
	feature_flags->enable_short_slot_time_11g =
				cfg_default(CFG_11G_SHORT_SLOT_TIME_ENABLED);
	feature_flags->channel_bonding_mode =
				cfg_default(CFG_CHANNEL_BONDING_MODE);
	feature_flags->enable_block_ack = cfg_default(CFG_BLOCK_ACK_ENABLED);
	feature_flags->enable_ampdu = cfg_get(psoc, CFG_ENABLE_AMPDUPS);
	feature_flags->mcc_rts_cts_prot = cfg_get(psoc,
						  CFG_FW_MCC_RTS_CTS_PROT);
	feature_flags->mcc_bcast_prob_rsp = cfg_get(psoc,
						    CFG_FW_MCC_BCAST_PROB_RESP);
	feature_flags->enable_mcc = cfg_get(psoc, CFG_MCC_FEATURE);
	feature_flags->channel_bonding_mode_24ghz =
			cfg_get(psoc, CFG_CHANNEL_BONDING_MODE_24GHZ);
	feature_flags->channel_bonding_mode_5ghz =
			cfg_get(psoc, CFG_CHANNEL_BONDING_MODE_5GHZ);
}

static void mlme_init_sap_protection_cfg(struct wlan_objmgr_psoc *psoc,
					 struct wlan_mlme_sap_protection
					 *sap_protection_params)
{
	sap_protection_params->protection_enabled =
				cfg_default(CFG_PROTECTION_ENABLED);
	sap_protection_params->protection_force_policy =
				cfg_default(CFG_FORCE_POLICY_PROTECTION);
	sap_protection_params->ignore_peer_ht_opmode =
				cfg_get(psoc, CFG_IGNORE_PEER_HT_MODE);
	sap_protection_params->enable_ap_obss_protection =
				cfg_get(psoc, CFG_AP_OBSS_PROTECTION_ENABLE);
	sap_protection_params->is_ap_prot_enabled =
				cfg_get(psoc, CFG_AP_ENABLE_PROTECTION_MODE);
	sap_protection_params->ap_protection_mode =
				cfg_get(psoc, CFG_AP_PROTECTION_MODE);
}

#ifdef WLAN_FEATURE_11AX

#define HE_MCS12_13_24G_INDEX 0
#define HE_MCS12_13_5G_INDEX 1
#define HE_MCS12_13_BITS 16

static void mlme_init_he_cap_in_cfg(struct wlan_objmgr_psoc *psoc,
				    struct wlan_mlme_cfg *mlme_cfg)
{
	uint32_t chan_width, mcs_12_13;
	uint16_t value = 0;
	struct wlan_mlme_he_caps *he_caps = &mlme_cfg->he_caps;
	bool is_twt_enabled = false;

	he_caps->dot11_he_cap.htc_he = cfg_default(CFG_HE_CONTROL);
	he_caps->dot11_he_cap.twt_request =
			cfg_get(psoc, CFG_TWT_REQUESTOR);
	he_caps->dot11_he_cap.twt_responder =
			cfg_get(psoc, CFG_TWT_RESPONDER);
	/*
	 * Broadcast TWT capability will be filled in
	 * populate_dot11f_he_caps() based on STA/SAP
	 * role and "twt_bcast_req_resp_config" ini
	 */
	he_caps->dot11_he_cap.broadcast_twt = 0;

	is_twt_enabled = wlan_twt_cfg_is_twt_enabled(psoc);

	if (is_twt_enabled)
		he_caps->dot11_he_cap.flex_twt_sched =
			cfg_default(CFG_HE_FLEX_TWT_SCHED);
	he_caps->dot11_he_cap.fragmentation =
			cfg_default(CFG_HE_FRAGMENTATION);
	he_caps->dot11_he_cap.max_num_frag_msdu_amsdu_exp =
			cfg_default(CFG_HE_MAX_FRAG_MSDU);
	he_caps->dot11_he_cap.min_frag_size = cfg_default(CFG_HE_MIN_FRAG_SIZE);
	he_caps->dot11_he_cap.trigger_frm_mac_pad =
		cfg_default(CFG_HE_TRIG_PAD);
	he_caps->dot11_he_cap.multi_tid_aggr_rx_supp =
		cfg_default(CFG_HE_MTID_AGGR_RX);
	he_caps->dot11_he_cap.he_link_adaptation =
		cfg_default(CFG_HE_LINK_ADAPTATION);
	he_caps->dot11_he_cap.all_ack = cfg_default(CFG_HE_ALL_ACK);
	he_caps->dot11_he_cap.trigd_rsp_sched =
			cfg_default(CFG_HE_TRIGD_RSP_SCHEDULING);
	he_caps->dot11_he_cap.a_bsr = cfg_default(CFG_HE_BUFFER_STATUS_RPT);
	he_caps->dot11_he_cap.ba_32bit_bitmap = cfg_default(CFG_HE_BA_32BIT);
	he_caps->dot11_he_cap.mu_cascade = cfg_default(CFG_HE_MU_CASCADING);
	he_caps->dot11_he_cap.ack_enabled_multitid =
			cfg_default(CFG_HE_MULTI_TID);
	he_caps->dot11_he_cap.omi_a_ctrl = cfg_default(CFG_HE_OMI);
	he_caps->dot11_he_cap.ofdma_ra = cfg_default(CFG_HE_OFDMA_RA);
	he_caps->dot11_he_cap.max_ampdu_len_exp_ext =
			cfg_default(CFG_HE_MAX_AMPDU_LEN);
	he_caps->dot11_he_cap.amsdu_frag = cfg_default(CFG_HE_AMSDU_FRAG);

	he_caps->dot11_he_cap.rx_ctrl_frame = cfg_default(CFG_HE_RX_CTRL);
	he_caps->dot11_he_cap.bsrp_ampdu_aggr =
			cfg_default(CFG_HE_BSRP_AMPDU_AGGR);
	he_caps->dot11_he_cap.qtp = cfg_default(CFG_HE_QTP);
	he_caps->dot11_he_cap.a_bqr = cfg_default(CFG_HE_A_BQR);
	he_caps->dot11_he_cap.spatial_reuse_param_rspder =
			cfg_default(CFG_HE_SR_RESPONDER);
	he_caps->dot11_he_cap.ndp_feedback_supp =
			cfg_default(CFG_HE_NDP_FEEDBACK_SUPP);
	he_caps->dot11_he_cap.ops_supp = cfg_default(CFG_HE_OPS_SUPP);
	he_caps->dot11_he_cap.amsdu_in_ampdu =
			cfg_default(CFG_HE_AMSDU_IN_AMPDU);

	chan_width = cfg_default(CFG_HE_CHAN_WIDTH);
	he_caps->dot11_he_cap.chan_width_0 = HE_CH_WIDTH_GET_BIT(chan_width, 0);
	he_caps->dot11_he_cap.chan_width_1 = HE_CH_WIDTH_GET_BIT(chan_width, 1);
	he_caps->dot11_he_cap.chan_width_2 = HE_CH_WIDTH_GET_BIT(chan_width, 2);
	he_caps->dot11_he_cap.chan_width_3 = HE_CH_WIDTH_GET_BIT(chan_width, 3);
	he_caps->dot11_he_cap.chan_width_4 = HE_CH_WIDTH_GET_BIT(chan_width, 4);
	he_caps->dot11_he_cap.chan_width_5 = HE_CH_WIDTH_GET_BIT(chan_width, 5);
	he_caps->dot11_he_cap.chan_width_6 = HE_CH_WIDTH_GET_BIT(chan_width, 6);

	he_caps->dot11_he_cap.multi_tid_aggr_tx_supp =
			cfg_default(CFG_HE_MTID_AGGR_TX);
	he_caps->dot11_he_cap.he_sub_ch_sel_tx_supp =
			cfg_default(CFG_HE_SUB_CH_SEL_TX);
	he_caps->dot11_he_cap.ul_2x996_tone_ru_supp =
			cfg_default(CFG_HE_UL_2X996_RU);
	he_caps->dot11_he_cap.om_ctrl_ul_mu_data_dis_rx =
			cfg_default(CFG_HE_OM_CTRL_UL_MU_DIS_RX);
	he_caps->dot11_he_cap.he_dynamic_smps =
			cfg_default(CFG_HE_DYNAMIC_SMPS);
	he_caps->dot11_he_cap.punctured_sounding_supp =
			cfg_default(CFG_HE_PUNCTURED_SOUNDING);
	he_caps->dot11_he_cap.ht_vht_trg_frm_rx_supp =
			cfg_default(CFG_HE_HT_VHT_TRG_FRM_RX);
	he_caps->dot11_he_cap.rx_pream_puncturing =
			cfg_get(psoc, CFG_HE_RX_PREAM_PUNC);
	he_caps->dot11_he_cap.device_class =
			cfg_default(CFG_HE_CLASS_OF_DEVICE);
	he_caps->dot11_he_cap.ldpc_coding = cfg_default(CFG_HE_LDPC);
	he_caps->dot11_he_cap.he_1x_ltf_800_gi_ppdu =
			cfg_default(CFG_HE_LTF_PPDU);
	he_caps->dot11_he_cap.midamble_tx_rx_max_nsts =
			cfg_default(CFG_HE_MIDAMBLE_RX_MAX_NSTS);
	he_caps->dot11_he_cap.he_4x_ltf_3200_gi_ndp =
			cfg_default(CFG_HE_LTF_NDP);
	he_caps->dot11_he_cap.tb_ppdu_tx_stbc_lt_80mhz =
			cfg_default(CFG_HE_TX_STBC_LT80);
	he_caps->dot11_he_cap.rx_stbc_lt_80mhz =
			cfg_default(CFG_HE_RX_STBC_LT80);
	he_caps->dot11_he_cap.doppler = cfg_default(CFG_HE_DOPPLER);
	he_caps->dot11_he_cap.ul_mu =
			cfg_get(psoc, CFG_HE_UL_MUMIMO);
	he_caps->dot11_he_cap.dcm_enc_tx = cfg_default(CFG_HE_DCM_TX);
	he_caps->dot11_he_cap.dcm_enc_rx = cfg_default(CFG_HE_DCM_RX);
	he_caps->dot11_he_cap.ul_he_mu = cfg_default(CFG_HE_MU_PPDU);
	he_caps->dot11_he_cap.su_beamformer = cfg_default(CFG_HE_SU_BEAMFORMER);
	he_caps->dot11_he_cap.su_beamformee = cfg_default(CFG_HE_SU_BEAMFORMEE);
	he_caps->dot11_he_cap.mu_beamformer = cfg_default(CFG_HE_MU_BEAMFORMER);
	he_caps->dot11_he_cap.bfee_sts_lt_80 =
			cfg_default(CFG_HE_BFEE_STS_LT80);
	he_caps->dot11_he_cap.bfee_sts_gt_80 =
			cfg_default(CFG_HE_BFEE_STS_GT80);
	he_caps->dot11_he_cap.num_sounding_lt_80 =
			cfg_default(CFG_HE_NUM_SOUND_LT80);
	he_caps->dot11_he_cap.num_sounding_gt_80 =
			cfg_default(CFG_HE_NUM_SOUND_GT80);
	he_caps->dot11_he_cap.su_feedback_tone16 =
			cfg_default(CFG_HE_SU_FEED_TONE16);
	he_caps->dot11_he_cap.mu_feedback_tone16 =
			cfg_default(CFG_HE_MU_FEED_TONE16);
	he_caps->dot11_he_cap.codebook_su = cfg_default(CFG_HE_CODEBOOK_SU);
	he_caps->dot11_he_cap.codebook_mu = cfg_default(CFG_HE_CODEBOOK_MU);
	he_caps->dot11_he_cap.beamforming_feedback =
			cfg_default(CFG_HE_BFRM_FEED);
	he_caps->dot11_he_cap.he_er_su_ppdu = cfg_default(CFG_HE_ER_SU_PPDU);
	he_caps->dot11_he_cap.dl_mu_mimo_part_bw =
			cfg_default(CFG_HE_DL_PART_BW);
	he_caps->dot11_he_cap.ppet_present = cfg_default(CFG_HE_PPET_PRESENT);
	he_caps->dot11_he_cap.srp = cfg_default(CFG_HE_SRP);
	he_caps->dot11_he_cap.power_boost = cfg_default(CFG_HE_POWER_BOOST);
	he_caps->dot11_he_cap.he_ltf_800_gi_4x = cfg_default(CFG_HE_4x_LTF_GI);
	he_caps->dot11_he_cap.max_nc = cfg_default(CFG_HE_MAX_NC);
	he_caps->dot11_he_cap.tb_ppdu_tx_stbc_gt_80mhz =
			cfg_default(CFG_HE_TX_STBC_GT80);
	he_caps->dot11_he_cap.rx_stbc_gt_80mhz =
			cfg_default(CFG_HE_RX_STBC_GT80);
	he_caps->dot11_he_cap.er_he_ltf_800_gi_4x =
			cfg_default(CFG_HE_ER_4x_LTF_GI);
	he_caps->dot11_he_cap.he_ppdu_20_in_40Mhz_2G =
			cfg_default(CFG_HE_PPDU_20_IN_40MHZ_2G);
	he_caps->dot11_he_cap.he_ppdu_20_in_160_80p80Mhz =
			cfg_default(CFG_HE_PPDU_20_IN_160_80P80MHZ);
	he_caps->dot11_he_cap.he_ppdu_80_in_160_80p80Mhz =
			cfg_default(CFG_HE_PPDU_80_IN_160_80P80MHZ);
		he_caps->dot11_he_cap.er_1x_he_ltf_gi =
			cfg_default(CFG_HE_ER_1X_HE_LTF_GI);
	he_caps->dot11_he_cap.midamble_tx_rx_1x_he_ltf =
			cfg_default(CFG_HE_MIDAMBLE_TXRX_1X_HE_LTF);
	he_caps->dot11_he_cap.dcm_max_bw = cfg_default(CFG_HE_DCM_MAX_BW);
	he_caps->dot11_he_cap.longer_than_16_he_sigb_ofdm_sym =
			cfg_default(CFG_HE_LONGER_16_SIGB_OFDM_SYM);
	he_caps->dot11_he_cap.non_trig_cqi_feedback =
			cfg_default(CFG_HE_NON_TRIG_CQI_FEEDBACK);
	he_caps->dot11_he_cap.tx_1024_qam_lt_242_tone_ru =
			cfg_default(CFG_HE_TX_1024_QAM_LT_242_RU);
	he_caps->dot11_he_cap.rx_1024_qam_lt_242_tone_ru =
			cfg_default(CFG_HE_RX_1024_QAM_LT_242_RU);
	he_caps->dot11_he_cap.rx_full_bw_su_he_mu_compress_sigb =
			cfg_default(CFG_HE_RX_FULL_BW_MU_CMPR_SIGB);
	he_caps->dot11_he_cap.rx_full_bw_su_he_mu_non_cmpr_sigb =
			cfg_default(CFG_HE_RX_FULL_BW_MU_NON_CMPR_SIGB);
	he_caps->dot11_he_cap.rx_he_mcs_map_lt_80 =
			cfg_get(psoc, CFG_HE_RX_MCS_MAP_LT_80);
	he_caps->dot11_he_cap.tx_he_mcs_map_lt_80 =
			cfg_get(psoc, CFG_HE_TX_MCS_MAP_LT_80);
	value = cfg_get(psoc, CFG_HE_RX_MCS_MAP_160);
	qdf_mem_copy(he_caps->dot11_he_cap.rx_he_mcs_map_160, &value,
		     sizeof(uint16_t));
	value = cfg_get(psoc, CFG_HE_TX_MCS_MAP_160);
	qdf_mem_copy(he_caps->dot11_he_cap.tx_he_mcs_map_160, &value,
		     sizeof(uint16_t));
	value = cfg_default(CFG_HE_RX_MCS_MAP_80_80);
	qdf_mem_copy(he_caps->dot11_he_cap.rx_he_mcs_map_80_80, &value,
		     sizeof(uint16_t));
	value = cfg_default(CFG_HE_TX_MCS_MAP_80_80);
	qdf_mem_copy(he_caps->dot11_he_cap.tx_he_mcs_map_80_80, &value,
		     sizeof(uint16_t));
	he_caps->he_ops_basic_mcs_nss = cfg_default(CFG_HE_OPS_BASIC_MCS_NSS);
	he_caps->he_dynamic_fragmentation =
			cfg_get(psoc, CFG_HE_DYNAMIC_FRAGMENTATION);
	he_caps->enable_ul_mimo =
			cfg_get(psoc, CFG_ENABLE_UL_MIMO);
	he_caps->enable_ul_ofdm =
			cfg_get(psoc, CFG_ENABLE_UL_OFDMA);
	he_caps->he_sta_obsspd =
			cfg_get(psoc, CFG_HE_STA_OBSSPD);
	qdf_mem_zero(he_caps->he_ppet_2g, MLME_HE_PPET_LEN);
	qdf_mem_zero(he_caps->he_ppet_5g, MLME_HE_PPET_LEN);

	mcs_12_13 = cfg_get(psoc, CFG_HE_MCS_12_13_SUPPORT);
	/* Get 2.4Ghz and 5Ghz value */
	mlme_cfg->he_caps.he_mcs_12_13_supp_2g =
		QDF_GET_BITS(mcs_12_13,
			     HE_MCS12_13_24G_INDEX * HE_MCS12_13_BITS,
			     HE_MCS12_13_BITS);
	mlme_cfg->he_caps.he_mcs_12_13_supp_5g =
		QDF_GET_BITS(mcs_12_13,
			     HE_MCS12_13_5G_INDEX * HE_MCS12_13_BITS,
			     HE_MCS12_13_BITS);
}
#else
static void mlme_init_he_cap_in_cfg(struct wlan_objmgr_psoc *psoc,
				    struct wlan_mlme_cfg *mlme_cfg)
{
}
#endif

#if defined(WLAN_SUPPORT_TWT) && defined(WLAN_TWT_CONV_SUPPORTED)
/**
 * mlme_init_disable_twt_info() - initialize disable twt info
 * @psoc: Pointer to PSOC
 * @twt_cfg: Pointer to twt_cfg
 *
 * Return: None
 */
static void mlme_init_disable_twt_info(struct wlan_objmgr_psoc *psoc,
				       struct wlan_mlme_cfg_twt *twt_cfg)
{
	twt_cfg->disable_twt_info_frame = cfg_get(psoc,
						  CFG_DISABLE_TWT_INFO_FRAME);
}
#elif defined(WLAN_SUPPORT_TWT)
static void mlme_init_disable_twt_info(struct wlan_objmgr_psoc *psoc,
				       struct wlan_mlme_cfg_twt *twt_cfg)
{
}

#endif

#ifdef WLAN_SUPPORT_TWT
static void mlme_init_twt_cfg(struct wlan_objmgr_psoc *psoc,
			      struct wlan_mlme_cfg_twt *twt_cfg)
{
	uint32_t bcast_conf = cfg_get(psoc, CFG_BCAST_TWT_REQ_RESP);

	twt_cfg->is_twt_enabled = cfg_get(psoc, CFG_ENABLE_TWT);
	twt_cfg->twt_congestion_timeout = cfg_get(psoc, CFG_TWT_CONGESTION_TIMEOUT);
	twt_cfg->enable_twt_24ghz = cfg_get(psoc, CFG_ENABLE_TWT_24GHZ);
	twt_cfg->is_bcast_requestor_enabled = CFG_TWT_GET_BCAST_REQ(bcast_conf);
	twt_cfg->is_bcast_responder_enabled = CFG_TWT_GET_BCAST_RES(bcast_conf);
	mlme_init_disable_twt_info(psoc, twt_cfg);
}
#else
static void mlme_init_twt_cfg(struct wlan_objmgr_psoc *psoc,
			      struct wlan_mlme_cfg_twt *twt_cfg)
{
}
#endif

#ifdef WLAN_FEATURE_11BE
static void mlme_init_eht_cap_in_cfg(struct wlan_objmgr_psoc *psoc,
				     struct wlan_mlme_cfg *mlme_cfg)
{
	struct wlan_mlme_eht_caps *eht_caps = &mlme_cfg->eht_caps;

	eht_caps->dot11_eht_cap.su_beamformer =
			cfg_default(CFG_EHT_SU_BEAMFORMER);
	eht_caps->dot11_eht_cap.su_beamformee =
			cfg_default(CFG_EHT_SU_BEAMFORMEE);
	eht_caps->dot11_eht_cap.mu_bformer_le_80mhz =
			cfg_default(CFG_EHT_MU_BFORMER_LE_80MHZ);
	eht_caps->dot11_eht_cap.mu_bformer_160mhz =
			cfg_default(CFG_EHT_MU_BFORMER_160MHZ);
	eht_caps->dot11_eht_cap.mu_bformer_320mhz =
			cfg_default(CFG_EHT_MU_BFORMER_320MHZ);
	eht_caps->dot11_eht_cap.bfee_ss_le_80mhz =
			cfg_default(CFG_EHT_BFEE_SS_LE_80MHZ);
	eht_caps->dot11_eht_cap.bfee_ss_160mhz =
			cfg_default(CFG_EHT_BFEE_SS_160MHZ);
	eht_caps->dot11_eht_cap.bfee_ss_320mhz =
			cfg_default(CFG_EHT_BFEE_SS_320MHZ);
	eht_caps->dot11_eht_cap.num_sounding_dim_le_80mhz =
			cfg_default(CFG_EHT_NUM_SOUNDING_DIM_LE_80MHZ);
	eht_caps->dot11_eht_cap.num_sounding_dim_160mhz =
			cfg_default(CFG_EHT_NUM_SOUNDING_DIM_160MHZ);
	eht_caps->dot11_eht_cap.num_sounding_dim_320mhz =
			cfg_default(CFG_EHT_NUM_SOUNDING_DIM_320MHZ);
}
#else
static void mlme_init_eht_cap_in_cfg(struct wlan_objmgr_psoc *psoc,
				     struct wlan_mlme_cfg *mlme_cfg)
{
}
#endif

#ifdef WLAN_FEATURE_SAE
static bool is_sae_sap_enabled(struct wlan_objmgr_psoc *psoc)
{
	return cfg_get(psoc, CFG_IS_SAP_SAE_ENABLED);
}

bool wlan_vdev_is_sae_auth_type(struct wlan_objmgr_vdev *vdev)
{
	int32_t auth_mode;

	auth_mode = wlan_crypto_get_param(vdev, WLAN_CRYPTO_PARAM_AUTH_MODE);

	if (auth_mode == -1)
		return false;

	if (QDF_HAS_PARAM(auth_mode, WLAN_CRYPTO_AUTH_SAE))
		return true;

	return false;
}
#else
static bool is_sae_sap_enabled(struct wlan_objmgr_psoc *psoc)
{
	return false;
}
#endif
uint16_t wlan_get_rand_from_lst_for_freq(uint16_t *freq_lst,
					 uint8_t num_chan)
{
	uint8_t i;
	uint32_t rand_byte = 0;

	if (!num_chan || !freq_lst) {
		mlme_legacy_debug("invalid param freq_lst %pK, num_chan = %d",
				  freq_lst, num_chan);
		return 0;
	}

	get_random_bytes((uint8_t *)&rand_byte, 1);
	i = (rand_byte + qdf_mc_timer_get_system_ticks()) % num_chan;

	return freq_lst[i];
}

static void mlme_init_sap_cfg(struct wlan_objmgr_psoc *psoc,
			      struct wlan_mlme_cfg_sap *sap_cfg)
{
	sap_cfg->beacon_interval = cfg_get(psoc, CFG_BEACON_INTERVAL);
	sap_cfg->dtim_interval = cfg_default(CFG_DTIM_PERIOD);
	sap_cfg->listen_interval = cfg_default(CFG_LISTEN_INTERVAL);
	sap_cfg->sap_11g_policy = cfg_default(CFG_11G_ONLY_POLICY);
	sap_cfg->assoc_sta_limit = cfg_default(CFG_ASSOC_STA_LIMIT);
	sap_cfg->enable_lte_coex = cfg_get(psoc, CFG_ENABLE_LTE_COEX);
	sap_cfg->rate_tx_mgmt = cfg_get(psoc, CFG_RATE_FOR_TX_MGMT);
	sap_cfg->rate_tx_mgmt_2g = cfg_get(psoc, CFG_RATE_FOR_TX_MGMT_2G);
	sap_cfg->rate_tx_mgmt_5g = cfg_get(psoc, CFG_RATE_FOR_TX_MGMT_5G);
	sap_cfg->tele_bcn_wakeup_en = cfg_get(psoc, CFG_TELE_BCN_WAKEUP_EN);
	sap_cfg->tele_bcn_max_li = cfg_get(psoc, CFG_TELE_BCN_MAX_LI);
	sap_cfg->sap_get_peer_info = cfg_get(psoc, CFG_SAP_GET_PEER_INFO);
	sap_cfg->sap_allow_all_chan_param_name =
			cfg_get(psoc, CFG_SAP_ALLOW_ALL_CHANNEL_PARAM);
	sap_cfg->sap_max_no_peers = cfg_get(psoc, CFG_SAP_MAX_NO_PEERS);
	sap_cfg->sap_max_offload_peers =
			cfg_get(psoc, CFG_SAP_MAX_OFFLOAD_PEERS);
	sap_cfg->sap_max_offload_reorder_buffs =
			cfg_get(psoc, CFG_SAP_MAX_OFFLOAD_REORDER_BUFFS);
	sap_cfg->sap_ch_switch_beacon_cnt =
			cfg_get(psoc, CFG_SAP_CH_SWITCH_BEACON_CNT);
	sap_cfg->sap_ch_switch_mode = cfg_get(psoc, CFG_SAP_CH_SWITCH_MODE);
	sap_cfg->sap_internal_restart =
			cfg_get(psoc, CFG_SAP_INTERNAL_RESTART);
	sap_cfg->chan_switch_hostapd_rate_enabled_name =
		cfg_get(psoc, CFG_CHAN_SWITCH_HOSTAPD_RATE_ENABLED_NAME);
	sap_cfg->reduced_beacon_interval =
		cfg_get(psoc, CFG_REDUCED_BEACON_INTERVAL);
	sap_cfg->max_li_modulated_dtim_time =
		cfg_get(psoc, CFG_MAX_LI_MODULATED_DTIM);
	sap_cfg->country_code_priority =
		cfg_get(psoc, CFG_COUNTRY_CODE_PRIORITY);
	sap_cfg->sap_pref_chan_location =
		cfg_get(psoc, CFG_SAP_PREF_CHANNEL_LOCATION);
	sap_cfg->sap_force_11n_for_11ac =
		cfg_get(psoc, CFG_SAP_FORCE_11N_FOR_11AC);
	sap_cfg->go_force_11n_for_11ac =
		cfg_get(psoc, CFG_GO_FORCE_11N_FOR_11AC);
	sap_cfg->ap_random_bssid_enable =
		cfg_get(psoc, CFG_AP_ENABLE_RANDOM_BSSID);
	sap_cfg->sap_mcc_chnl_avoid =
		cfg_get(psoc, CFG_SAP_MCC_CHANNEL_AVOIDANCE);
	sap_cfg->sap_11ac_override =
		cfg_get(psoc, CFG_SAP_11AC_OVERRIDE);
	sap_cfg->go_11ac_override =
		cfg_get(psoc, CFG_GO_11AC_OVERRIDE);
	sap_cfg->sap_sae_enabled = is_sae_sap_enabled(psoc);
	sap_cfg->is_sap_bcast_deauth_enabled =
		cfg_get(psoc, CFG_IS_SAP_BCAST_DEAUTH_ENABLED);
	sap_cfg->is_6g_sap_fd_enabled =
		cfg_get(psoc, CFG_6G_SAP_FILS_DISCOVERY_ENABLED);
	sap_cfg->disable_bcn_prot =
		cfg_get(psoc, CFG_DISABLE_SAP_BCN_PROT);
	sap_cfg->sap_ps_with_twt_enable =
		cfg_get(psoc, CFG_SAP_PS_WITH_TWT);
}

static void mlme_init_obss_ht40_cfg(struct wlan_objmgr_psoc *psoc,
				    struct wlan_mlme_obss_ht40 *obss_ht40)
{
	obss_ht40->active_dwelltime =
		cfg_get(psoc, CFG_OBSS_HT40_SCAN_ACTIVE_DWELL_TIME);
	obss_ht40->passive_dwelltime =
		cfg_get(psoc, CFG_OBSS_HT40_SCAN_PASSIVE_DWELL_TIME);
	obss_ht40->width_trigger_interval =
		cfg_get(psoc, CFG_OBSS_HT40_SCAN_WIDTH_TRIGGER_INTERVAL);
	obss_ht40->passive_per_channel = (uint32_t)
		cfg_default(CFG_OBSS_HT40_SCAN_PASSIVE_TOTAL_PER_CHANNEL);
	obss_ht40->active_per_channel = (uint32_t)
		cfg_default(CFG_OBSS_HT40_SCAN_ACTIVE_TOTAL_PER_CHANNEL);
	obss_ht40->width_trans_delay = (uint32_t)
		cfg_default(CFG_OBSS_HT40_WIDTH_CH_TRANSITION_DELAY);
	obss_ht40->scan_activity_threshold = (uint32_t)
		cfg_default(CFG_OBSS_HT40_SCAN_ACTIVITY_THRESHOLD);
	obss_ht40->is_override_ht20_40_24g =
		cfg_get(psoc, CFG_OBSS_HT40_OVERRIDE_HT40_20_24GHZ);
	obss_ht40->obss_detection_offload_enabled =
		(bool)cfg_default(CFG_OBSS_DETECTION_OFFLOAD);
	obss_ht40->obss_color_collision_offload_enabled =
		(bool)cfg_default(CFG_OBSS_COLOR_COLLISION_OFFLOAD);
	obss_ht40->bss_color_collision_det_sta =
		cfg_get(psoc, CFG_BSS_CLR_COLLISION_DETCN_STA);
}

static void mlme_init_threshold_cfg(struct wlan_objmgr_psoc *psoc,
				    struct wlan_mlme_threshold *threshold)
{
	threshold->rts_threshold = cfg_get(psoc, CFG_RTS_THRESHOLD);
	threshold->frag_threshold = cfg_get(psoc, CFG_FRAG_THRESHOLD);
}

static bool
mlme_is_freq_present_in_list(struct acs_weight *normalize_weight_chan_list,
			     uint8_t num_freq, uint32_t freq, uint8_t *index)
{
	uint8_t i;

	for (i = 0; i < num_freq && i < NUM_CHANNELS; i++) {
		if (normalize_weight_chan_list[i].chan_freq == freq) {
			*index = i;
			return true;
		}
	}

	return false;
}

static void
mlme_acs_parse_weight_list(struct wlan_objmgr_psoc *psoc,
			   struct wlan_mlme_acs *acs)
{
	char *acs_weight, *str1, *str2 = NULL, *acs_weight_temp, is_range = '-';
	int freq1, freq2, normalize_factor;
	uint8_t num_acs_weight = 0, num_acs_weight_range = 0, index = 0;
	struct acs_weight *weight_list = acs->normalize_weight_chan;
	struct acs_weight_range *range_list = acs->normalize_weight_range;

	if (!qdf_str_len(cfg_get(psoc, CFG_NORMALIZE_ACS_WEIGHT)))
		return;

	acs_weight = qdf_mem_malloc(ACS_WEIGHT_MAX_STR_LEN);
	if (!acs_weight)
		return;

	qdf_mem_copy(acs_weight, cfg_get(psoc, CFG_NORMALIZE_ACS_WEIGHT),
		     ACS_WEIGHT_MAX_STR_LEN);
	acs_weight_temp = acs_weight;

	while(acs_weight_temp) {
		str1 = strsep(&acs_weight_temp, ",");
		if (!str1)
			goto end;
		freq1 = 0;
		freq2 = 0;
		if (strchr(str1, is_range)) {
			str2 = strsep(&str1, "-");
			sscanf(str2, "%d", &freq1);
			sscanf(str1, "%d", &freq2);
			strsep(&str1, "=");
			if (!str1)
				goto end;
			sscanf(str1, "%d", &normalize_factor);

			if (num_acs_weight_range == MAX_ACS_WEIGHT_RANGE)
				continue;
			range_list[num_acs_weight_range].normalize_weight =
							normalize_factor;
			range_list[num_acs_weight_range].start_freq = freq1;
			range_list[num_acs_weight_range++].end_freq = freq2;
		} else {
			sscanf(str1, "%d", &freq1);
			strsep(&str1, "=");
			if (!str1 || !weight_list)
				goto end;
			sscanf(str1, "%d", &normalize_factor);
			if (mlme_is_freq_present_in_list(weight_list,
							 num_acs_weight, freq1,
							 &index)) {
				weight_list[index].normalize_weight =
							normalize_factor;
			} else {
				if (num_acs_weight == NUM_CHANNELS)
					continue;

				weight_list[num_acs_weight].chan_freq = freq1;
				weight_list[num_acs_weight++].normalize_weight =
							normalize_factor;
			}
		}
	}

	acs->normalize_weight_num_chan = num_acs_weight;
	acs->num_weight_range = num_acs_weight_range;

end:
	qdf_mem_free(acs_weight);
}

static void mlme_init_acs_cfg(struct wlan_objmgr_psoc *psoc,
			      struct wlan_mlme_acs *acs)
{
	acs->is_acs_with_more_param =
		cfg_get(psoc, CFG_ACS_WITH_MORE_PARAM);
	acs->auto_channel_select_weight =
		cfg_get(psoc, CFG_AUTO_CHANNEL_SELECT_WEIGHT);
	acs->is_vendor_acs_support =
		cfg_get(psoc, CFG_USER_AUTO_CHANNEL_SELECTION);
	acs->force_sap_start =
		cfg_get(psoc, CFG_ACS_FORCE_START_SAP);
	acs->is_acs_support_for_dfs_ltecoex =
		cfg_get(psoc, CFG_USER_ACS_DFS_LTE);
	acs->is_external_acs_policy =
		cfg_get(psoc, CFG_EXTERNAL_ACS_POLICY);
	acs->np_chan_weightage = cfg_get(psoc, CFG_ACS_NP_CHAN_WEIGHT);
	acs->acs_prefer_6ghz_psc = cfg_default(CFG_ACS_PREFER_6GHZ_PSC);
	mlme_acs_parse_weight_list(psoc, acs);
}

static void
mlme_init_product_details_cfg(struct wlan_mlme_product_details_cfg
			      *product_details)
{
	qdf_str_lcopy(product_details->manufacturer_name,
		      cfg_default(CFG_MFR_NAME),
		      sizeof(product_details->manufacturer_name));
	qdf_str_lcopy(product_details->manufacture_product_name,
		      cfg_default(CFG_MFR_PRODUCT_NAME),
		      sizeof(product_details->manufacture_product_name));
	qdf_str_lcopy(product_details->manufacture_product_version,
		      cfg_default(CFG_MFR_PRODUCT_VERSION),
		      sizeof(product_details->manufacture_product_version));
	qdf_str_lcopy(product_details->model_name,
		      cfg_default(CFG_MODEL_NAME),
		      sizeof(product_details->model_name));
	qdf_str_lcopy(product_details->model_number,
		      cfg_default(CFG_MODEL_NUMBER),
		      sizeof(product_details->model_number));
}

#ifdef WLAN_FEATURE_11BE_MLO
static void mlme_init_sta_mlo_cfg(struct wlan_objmgr_psoc *psoc,
				  struct wlan_mlme_sta_cfg *sta)
{
	sta->mlo_support_link_num =
		cfg_get(psoc, CFG_MLO_SUPPORT_LINK_NUM);
	sta->mlo_support_link_band =
		cfg_default(CFG_MLO_SUPPORT_LINK_BAND);
	sta->mlo_max_simultaneous_links =
		cfg_default(CFG_MLO_MAX_SIMULTANEOUS_LINKS);
	sta->mlo_prefer_percentage =
		cfg_get(psoc, CFG_MLO_PREFER_PERCENTAGE);
	sta->mlo_same_link_mld_address =
		cfg_default(CFG_MLO_SAME_LINK_MLD_ADDR);
	sta->mlo_5gl_5gh_mlsr =
		cfg_get(psoc, CFG_MLO_MLO_5GL_5GH_MLSR);
	sta->epcs_capability =
		cfg_get(psoc, CFG_MLO_EPCS_SUPPORT_ENABLE);
	mlme_debug("mlo_support_link_num: %d, mlo_support_link_band: 0x%x",
		   sta->mlo_support_link_num, sta->mlo_support_link_band);
}

static bool
wlan_get_vdev_link_removed_flag(struct wlan_objmgr_vdev *vdev)
{
	bool is_mlo_link_removed = false;
	uint8_t link_id;
	struct mlo_link_info *link_info;

	if (!mlo_is_mld_sta(vdev))
		return false;

	link_id = wlan_vdev_get_link_id(vdev);
	link_info = mlo_mgr_get_ap_link_by_link_id(vdev->mlo_dev_ctx, link_id);
	if (link_info)
		is_mlo_link_removed =
			!!qdf_atomic_test_bit(LS_F_AP_REMOVAL_BIT,
					      &link_info->link_status_flags);
	else
		mlme_legacy_err("link info null, id %d", link_id);

	return is_mlo_link_removed;
}

bool wlan_get_vdev_link_removed_flag_by_vdev_id(struct wlan_objmgr_psoc *psoc,
						uint8_t vdev_id)
{
	struct wlan_objmgr_vdev *vdev;
	bool is_mlo_link_removed;

	vdev = wlan_objmgr_get_vdev_by_id_from_psoc(psoc, vdev_id,
						    WLAN_MLME_OBJMGR_ID);
	if (!vdev) {
		mlme_legacy_err("get vdev failed for id %d", vdev_id);
		return false;
	}

	is_mlo_link_removed = wlan_get_vdev_link_removed_flag(vdev);
	wlan_objmgr_vdev_release_ref(vdev, WLAN_MLME_OBJMGR_ID);

	return is_mlo_link_removed;
}

static QDF_STATUS
wlan_set_vdev_link_removed_flag(struct wlan_objmgr_vdev *vdev, bool removed)
{
	uint8_t link_id;
	struct mlo_link_info *link_info;
	bool is_mlo_link_removed;

	if (!vdev) {
		mlme_legacy_err("vdev NULL");
		return QDF_STATUS_E_INVAL;
	}

	if (!mlo_is_mld_sta(vdev)) {
		mlme_legacy_debug("vdev not mld sta");
		return QDF_STATUS_E_INVAL;
	}

	link_id = wlan_vdev_get_link_id(vdev);
	link_info = mlo_mgr_get_ap_link_by_link_id(vdev->mlo_dev_ctx, link_id);
	if (!link_info) {
		mlme_legacy_err("link info null, id %d", link_id);
		return QDF_STATUS_E_INVAL;
	}
	is_mlo_link_removed =
		!!qdf_atomic_test_bit(LS_F_AP_REMOVAL_BIT,
				      &link_info->link_status_flags);
	if (removed == is_mlo_link_removed)
		return QDF_STATUS_SUCCESS;

	mlme_legacy_debug("mlo sta vdev %d link %d link removed flag %d",
			  wlan_vdev_get_id(vdev), link_id, removed);
	if (removed)
		qdf_atomic_set_bit(LS_F_AP_REMOVAL_BIT,
				   &link_info->link_status_flags);
	else
		qdf_atomic_clear_bit(LS_F_AP_REMOVAL_BIT,
				     &link_info->link_status_flags);

	return QDF_STATUS_SUCCESS;
}

QDF_STATUS
wlan_set_vdev_link_removed_flag_by_vdev_id(struct wlan_objmgr_psoc *psoc,
					   uint8_t vdev_id, bool removed)
{
	struct wlan_objmgr_vdev *vdev;
	QDF_STATUS status;

	vdev = wlan_objmgr_get_vdev_by_id_from_psoc(psoc, vdev_id,
						    WLAN_MLME_OBJMGR_ID);
	if (!vdev) {
		mlme_legacy_err("vdev null for id %d", vdev_id);
		return QDF_STATUS_E_INVAL;
	}

	if (!mlo_is_mld_sta(vdev)) {
		mlme_legacy_debug("vdev %d not mld sta", vdev_id);
		wlan_objmgr_vdev_release_ref(vdev, WLAN_MLME_OBJMGR_ID);
		return QDF_STATUS_E_INVAL;
	}

	status = wlan_set_vdev_link_removed_flag(vdev, removed);

	wlan_objmgr_vdev_release_ref(vdev, WLAN_MLME_OBJMGR_ID);

	return status;
}

void wlan_clear_mlo_sta_link_removed_flag(struct wlan_objmgr_vdev *vdev)
{
	uint8_t i;
	struct mlo_link_info *link_info;

	if (!vdev || !mlo_is_mld_sta(vdev))
		return;

	link_info = mlo_mgr_get_ap_link(vdev);
	if (!link_info)
		return;

	for (i = 0; i < WLAN_MAX_ML_BSS_LINKS; i++)
		qdf_atomic_clear_bit(LS_F_AP_REMOVAL_BIT,
				     &link_info[i].link_status_flags);
}

bool wlan_get_mlo_link_agnostic_flag(struct wlan_objmgr_vdev *vdev,
				     uint8_t *dest_addr)
{
	struct wlan_objmgr_peer *bss_peer = NULL;
	bool mlo_link_agnostic = false;
	uint8_t *peer_mld_addr = NULL;

	if (!wlan_vdev_mlme_is_mlo_vdev(vdev))
		return mlo_link_agnostic;

	bss_peer = wlan_objmgr_vdev_try_get_bsspeer(vdev, WLAN_MLME_OBJMGR_ID);
	if (bss_peer) {
		peer_mld_addr = wlan_peer_mlme_get_mldaddr(bss_peer);
		if (!qdf_mem_cmp(bss_peer->macaddr, dest_addr,
				 QDF_MAC_ADDR_SIZE) ||
		    (peer_mld_addr && !qdf_mem_cmp(peer_mld_addr, dest_addr,
						   QDF_MAC_ADDR_SIZE))) {
			mlme_legacy_debug("dest address" QDF_MAC_ADDR_FMT "bss peer address"
					  QDF_MAC_ADDR_FMT "mld addr" QDF_MAC_ADDR_FMT,
					  QDF_MAC_ADDR_REF(dest_addr),
					  QDF_MAC_ADDR_REF(bss_peer->macaddr),
					  QDF_MAC_ADDR_REF(peer_mld_addr));
			mlo_link_agnostic = true;
		}
		wlan_objmgr_peer_release_ref(bss_peer, WLAN_MLME_OBJMGR_ID);
	}
	return mlo_link_agnostic;
}

bool wlan_drop_mgmt_frame_on_link_removal(struct wlan_objmgr_vdev *vdev)
{
	if (!vdev || !mlo_is_mld_sta(vdev))
		return false;

	return wlan_get_vdev_link_removed_flag(vdev);
}
#else
static void mlme_init_sta_mlo_cfg(struct wlan_objmgr_psoc *psoc,
				  struct wlan_mlme_sta_cfg *sta)
{
}
#endif

static void mlme_init_sta_cfg(struct wlan_objmgr_psoc *psoc,
			      struct wlan_mlme_sta_cfg *sta)
{
	sta->sta_keep_alive_period =
		cfg_get(psoc, CFG_INFRA_STA_KEEP_ALIVE_PERIOD);
	sta->bss_max_idle_period =
		cfg_get(psoc, CFG_STA_BSS_MAX_IDLE_PERIOD);
	sta->tgt_gtx_usr_cfg =
		cfg_get(psoc, CFG_TGT_GTX_USR_CFG);
	sta->pmkid_modes =
		cfg_get(psoc, CFG_PMKID_MODES);
	sta->ignore_peer_erp_info =
		cfg_get(psoc, CFG_IGNORE_PEER_ERP_INFO);
	sta->sta_prefer_80mhz_over_160mhz =
		cfg_get(psoc, CFG_STA_PREFER_80MHZ_OVER_160MHZ);
	sta->enable_5g_ebt =
		cfg_get(psoc, CFG_PPS_ENABLE_5G_EBT);
	sta->deauth_before_connection =
		cfg_get(psoc, CFG_ENABLE_DEAUTH_BEFORE_CONNECTION);
	sta->dot11p_mode =
		cfg_get(psoc, CFG_DOT11P_MODE);
	sta->enable_go_cts2self_for_sta =
		cfg_get(psoc, CFG_ENABLE_GO_CTS2SELF_FOR_STA);
	sta->qcn_ie_support =
		cfg_get(psoc, CFG_QCN_IE_SUPPORT);
	sta->fils_max_chan_guard_time =
		cfg_get(psoc, CFG_FILS_MAX_CHAN_GUARD_TIME);
	sta->deauth_retry_cnt = cfg_get(psoc, CFG_DEAUTH_RETRY_CNT);
	sta->single_tid =
		cfg_get(psoc, CFG_SINGLE_TID_RC);
	sta->sta_miracast_mcc_rest_time =
		cfg_get(psoc, CFG_STA_MCAST_MCC_REST_TIME);
	sta->wait_cnf_timeout =
		(uint32_t)cfg_default(CFG_WT_CNF_TIMEOUT);
	sta->current_rssi =
		(uint32_t)cfg_default(CFG_CURRENT_RSSI);
	sta->allow_tpc_from_ap = cfg_get(psoc, CFG_TX_POWER_CTRL);
	sta->sta_keepalive_method =
		cfg_get(psoc, CFG_STA_KEEPALIVE_METHOD);
	sta->max_li_modulated_dtim_time_ms =
		cfg_get(psoc, CFG_MAX_LI_MODULATED_DTIM_MS);

	mlme_init_sta_mlo_cfg(psoc, sta);
	wlan_mlme_set_epcs_capability(psoc,
				      wlan_mlme_get_epcs_capability(psoc));
	wlan_mlme_set_usr_disable_sta_eht(psoc, false);
	wlan_mlme_set_eht_disable_punct_in_us_lpi(psoc,
						  cfg_default(CFG_EHT_DISABLE_PUNCT_IN_US_LPI));
}

static void mlme_init_stats_cfg(struct wlan_objmgr_psoc *psoc,
				struct wlan_mlme_stats_cfg *stats)
{
	stats->stats_periodic_display_time =
		cfg_get(psoc, CFG_PERIODIC_STATS_DISPLAY_TIME);
	stats->stats_link_speed_rssi_high =
		cfg_get(psoc, CFG_LINK_SPEED_RSSI_HIGH);
	stats->stats_link_speed_rssi_med =
		cfg_get(psoc, CFG_LINK_SPEED_RSSI_MID);
	stats->stats_link_speed_rssi_low =
		cfg_get(psoc, CFG_LINK_SPEED_RSSI_LOW);
	stats->stats_report_max_link_speed_rssi =
		cfg_get(psoc, CFG_REPORT_MAX_LINK_SPEED);
}

#ifdef WLAN_ADAPTIVE_11R
/**
 * mlme_init_adaptive_11r_cfg() - initialize enable_adaptive_11r
 * flag
 * @psoc: Pointer to PSOC
 * @lfr:  pointer to mlme lfr config
 *
 * Return: None
 */
static void
mlme_init_adaptive_11r_cfg(struct wlan_objmgr_psoc *psoc,
			   struct wlan_mlme_lfr_cfg *lfr)
{
	lfr->enable_adaptive_11r = cfg_get(psoc, CFG_ADAPTIVE_11R);
#ifdef SEC_CONFIG_PSM_SYSFS
	if (wlan_hdd_sec_get_psm()) {
		lfr->enable_adaptive_11r = 0;
		printk("[WIFI] CFG_ADAPTIVE_11R : sec_control_psm = %d", lfr->enable_adaptive_11r);
	}
#endif /* SEC_CONFIG_PSM_SYSFS */
}

#else
static inline void
mlme_init_adaptive_11r_cfg(struct wlan_objmgr_psoc *psoc,
			   struct wlan_mlme_lfr_cfg *lfr)
{
}
#endif

#if defined(WLAN_SAE_SINGLE_PMK) && defined(WLAN_FEATURE_ROAM_OFFLOAD)
/**
 * mlme_init_sae_single_pmk_cfg() - initialize sae_same_pmk_config
 * flag
 * @psoc: Pointer to PSOC
 * @lfr:  pointer to mlme lfr config
 *
 * Return: None
 */
static void
mlme_init_sae_single_pmk_cfg(struct wlan_objmgr_psoc *psoc,
			     struct wlan_mlme_lfr_cfg *lfr)
{
	lfr->sae_single_pmk_feature_enabled = cfg_get(psoc, CFG_SAE_SINGLE_PMK);
}

#else
static inline void
mlme_init_sae_single_pmk_cfg(struct wlan_objmgr_psoc *psoc,
			     struct wlan_mlme_lfr_cfg *lfr)
{
}
#endif

#ifdef WLAN_FEATURE_ROAM_OFFLOAD
static void mlme_init_roam_offload_cfg(struct wlan_objmgr_psoc *psoc,
				       struct wlan_mlme_lfr_cfg *lfr)
{
	bool val = false;

	lfr->lfr3_roaming_offload =
		cfg_get(psoc, CFG_LFR3_ROAMING_OFFLOAD);
	lfr->lfr3_dual_sta_roaming_enabled =
		cfg_get(psoc, CFG_ENABLE_DUAL_STA_ROAM_OFFLOAD);
	lfr->enable_self_bss_roam = cfg_get(psoc, CFG_LFR3_ENABLE_SELF_BSS_ROAM);
	lfr->enable_roam_reason_vsie =
		cfg_get(psoc, CFG_ENABLE_ROAM_REASON_VSIE);
	lfr->enable_disconnect_roam_offload =
		cfg_get(psoc, CFG_LFR_ENABLE_DISCONNECT_ROAM);
	lfr->enable_idle_roam =
		cfg_get(psoc, CFG_LFR_ENABLE_IDLE_ROAM);
	lfr->idle_roam_rssi_delta =
		cfg_get(psoc, CFG_LFR_IDLE_ROAM_RSSI_DELTA);
	lfr->roam_info_stats_num =
		cfg_get(psoc, CFG_LFR3_ROAM_INFO_STATS_NUM);

	ucfg_mlme_get_connection_roaming_ini_present(psoc, &val);
	if (val) {
		lfr->idle_roam_inactive_time =
			cfg_get(psoc, CFG_ROAM_IDLE_INACTIVE_TIME) * 1000;
	} else {
		lfr->idle_roam_inactive_time =
			cfg_get(psoc, CFG_LFR_IDLE_ROAM_INACTIVE_TIME);
	}

	lfr->idle_data_packet_count =
		cfg_get(psoc, CFG_LFR_IDLE_ROAM_PACKET_COUNT);
	lfr->idle_roam_min_rssi = cfg_get(psoc, CFG_LFR_IDLE_ROAM_MIN_RSSI);
	lfr->roam_trigger_bitmap =
		cfg_get(psoc, CFG_ROAM_TRIGGER_BITMAP);
	lfr->vendor_btm_param.user_roam_reason = DISABLE_VENDOR_BTM_CONFIG;

	lfr->idle_roam_band = cfg_get(psoc, CFG_LFR_IDLE_ROAM_BAND);
	lfr->sta_roam_disable = cfg_get(psoc, CFG_STA_DISABLE_ROAM);
	mlme_init_sae_single_pmk_cfg(psoc, lfr);
#ifdef SEC_CONFIG_PSM_SYSFS
	if (wlan_hdd_sec_get_psm()) {
		lfr->enable_idle_roam = 0;
		printk("[WIFI] CFG_LFR_ENABLE_IDLE_ROAM : sec_control_psm = %d", lfr->enable_idle_roam);

		lfr->enable_disconnect_roam_offload = 0;
		printk("[WIFI] CFG_LFR_ENABLE_DISCONNECT_ROAM : sec_control_psm = %d", lfr->enable_disconnect_roam_offload);

		lfr->lfr3_roaming_offload = 0;
		printk("[WIFI] CFG_LFR3_ROAMING_OFFLOAD : sec_control_psm = %d", lfr->lfr3_roaming_offload);
	}
#endif /* SEC_CONFIG_PSM_SYSFS */
	qdf_mem_zero(&lfr->roam_rt_stats, sizeof(lfr->roam_rt_stats));
}

void
wlan_mlme_defer_pmk_set_in_roaming(struct wlan_objmgr_psoc *psoc,
				   uint8_t vdev_id, bool set_pmk_pending)
{
	struct wlan_objmgr_vdev *vdev;
	struct mlme_legacy_priv *mlme_priv;

	if (set_pmk_pending && !MLME_IS_ROAM_SYNCH_IN_PROGRESS(psoc, vdev_id))
		return;

	vdev = wlan_objmgr_get_vdev_by_id_from_psoc(psoc, vdev_id,
						    WLAN_MLME_OBJMGR_ID);

	if (!vdev) {
		mlme_err("get vdev failed");
		return;
	}

	mlme_priv = wlan_vdev_mlme_get_ext_hdl(vdev);

	if (!mlme_priv) {
		wlan_objmgr_vdev_release_ref(vdev, WLAN_MLME_OBJMGR_ID);
		mlme_legacy_err("vdev legacy private object is NULL");
		return;
	}

	mlme_priv->mlme_roam.set_pmk_pending = set_pmk_pending;
	wlan_objmgr_vdev_release_ref(vdev, WLAN_MLME_OBJMGR_ID);
}

bool
wlan_mlme_is_pmk_set_deferred(struct wlan_objmgr_psoc *psoc,
			      uint8_t vdev_id)
{
	struct wlan_objmgr_vdev *vdev;
	struct mlme_legacy_priv *mlme_priv;
	bool set_pmk_pending;

	vdev = wlan_objmgr_get_vdev_by_id_from_psoc(psoc, vdev_id,
						    WLAN_MLME_OBJMGR_ID);

	if (!vdev) {
		mlme_err("get vdev failed");
		return false;
	}

	mlme_priv = wlan_vdev_mlme_get_ext_hdl(vdev);

	if (!mlme_priv) {
		wlan_objmgr_vdev_release_ref(vdev, WLAN_MLME_OBJMGR_ID);
		mlme_legacy_err("vdev legacy private object is NULL");
		return false;
	}

	set_pmk_pending = mlme_priv->mlme_roam.set_pmk_pending;
	wlan_objmgr_vdev_release_ref(vdev, WLAN_MLME_OBJMGR_ID);

	return set_pmk_pending;
}
#else
static void mlme_init_roam_offload_cfg(struct wlan_objmgr_psoc *psoc,
				       struct wlan_mlme_lfr_cfg *lfr)
{
}

#endif

#ifdef FEATURE_WLAN_ESE
static void mlme_init_ese_cfg(struct wlan_objmgr_psoc *psoc,
			      struct wlan_mlme_lfr_cfg *lfr)
{
	lfr->ese_enabled = cfg_get(psoc, CFG_LFR_ESE_FEATURE_ENABLED);
}
#else
static void mlme_init_ese_cfg(struct wlan_objmgr_psoc *psoc,
			      struct wlan_mlme_lfr_cfg *lfr)
{
}
#endif

#ifdef FEATURE_LFR_SUBNET_DETECTION
static void mlme_init_subnet_detection(struct wlan_objmgr_psoc *psoc,
				       struct wlan_mlme_lfr_cfg *lfr)
{
	lfr->enable_lfr_subnet_detection =
		cfg_get(psoc, CFG_LFR3_ENABLE_SUBNET_DETECTION);
}
#else
static void mlme_init_subnet_detection(struct wlan_objmgr_psoc *psoc,
				       struct wlan_mlme_lfr_cfg *lfr)
{
}
#endif

static void
mlme_init_bss_load_trigger_params(struct wlan_objmgr_psoc *psoc,
				  struct bss_load_trigger *bss_load_trig)
{
	bool val = false;

	bss_load_trig->enabled =
		cfg_get(psoc, CFG_ENABLE_BSS_LOAD_TRIGGERED_ROAM);
	bss_load_trig->threshold = cfg_get(psoc, CFG_BSS_LOAD_THRESHOLD);
	bss_load_trig->bss_load_alpha = cfg_get(psoc, CFG_BSS_LOAD_ALPHA);

	ucfg_mlme_get_connection_roaming_ini_present(psoc, &val);
	if (val)
		bss_load_trig->sample_time =
				cfg_get(psoc, CFG_ROAM_CU_MONITOR_TIME) * 1000;
	else
		bss_load_trig->sample_time = cfg_get(psoc,
						     CFG_BSS_LOAD_SAMPLE_TIME);

	bss_load_trig->rssi_threshold_6ghz =
			cfg_get(psoc, CFG_BSS_LOAD_TRIG_6G_RSSI_THRES);
	bss_load_trig->rssi_threshold_5ghz =
			cfg_get(psoc, CFG_BSS_LOAD_TRIG_5G_RSSI_THRES);
	bss_load_trig->rssi_threshold_24ghz =
			cfg_get(psoc, CFG_BSS_LOAD_TRIG_2G_RSSI_THRES);
#ifdef SEC_CONFIG_PSM_SYSFS
	if (wlan_hdd_sec_get_psm()) {
		bss_load_trig->enabled = 0;
		printk("[WIFI] CFG_ENABLE_BSS_LOAD_TRIGGERED_ROAM : sec_control_psm = %d", bss_load_trig->enabled);
	}
#endif /* SEC_CONFIG_PSM_SYSFS */
}

void mlme_reinit_control_config_lfr_params(struct wlan_objmgr_psoc *psoc,
					   struct wlan_mlme_lfr_cfg *lfr)
{
	/* Restore the params set through SETDFSSCANMODE */
	lfr->roaming_dfs_channel =
		cfg_get(psoc, CFG_LFR_ROAMING_DFS_CHANNEL);

	/* Restore the params set through SETWESMODE */
	lfr->wes_mode_enabled = cfg_get(psoc, CFG_LFR_ENABLE_WES_MODE);
}

#ifdef CONNECTION_ROAMING_CFG
/**
 * mlme_init_bmiss_timeout() - Init bmiss timeout
 * @psoc: Pointer to psoc
 * @lfr: Pointer to lfr config
 *
 * Return: None
 */
static void mlme_init_bmiss_timeout(struct wlan_objmgr_psoc *psoc,
				    struct wlan_mlme_lfr_cfg *lfr)
{
	lfr->beaconloss_timeout_onwakeup =
		cfg_get(psoc, CFG_LFR_BEACONLOSS_TIMEOUT_ON_WAKEUP) / 2;
	lfr->beaconloss_timeout_onsleep =
		cfg_get(psoc, CFG_LFR_BEACONLOSS_TIMEOUT_ON_SLEEP) / 2;
}
#else
static void mlme_init_bmiss_timeout(struct wlan_objmgr_psoc *psoc,
				    struct wlan_mlme_lfr_cfg *lfr)
{
	lfr->beaconloss_timeout_onwakeup =
		cfg_get(psoc, CFG_LFR_BEACONLOSS_TIMEOUT_ON_WAKEUP);
	lfr->beaconloss_timeout_onsleep =
		cfg_get(psoc, CFG_LFR_BEACONLOSS_TIMEOUT_ON_SLEEP);
}
#endif

static void mlme_init_lfr_cfg(struct wlan_objmgr_psoc *psoc,
			      struct wlan_mlme_lfr_cfg *lfr)
{
	qdf_size_t neighbor_scan_chan_list_num = 0;
	bool val = false;

	lfr->mawc_roam_enabled =
		cfg_get(psoc, CFG_LFR_MAWC_ROAM_ENABLED);
	lfr->enable_fast_roam_in_concurrency =
		cfg_get(psoc, CFG_LFR_ENABLE_FAST_ROAM_IN_CONCURRENCY);
	lfr->early_stop_scan_enable =
		cfg_get(psoc, CFG_LFR_EARLY_STOP_SCAN_ENABLE);
	lfr->enable_5g_band_pref =
		cfg_get(psoc, CFG_LFR_ENABLE_5G_BAND_PREF);
	lfr->lfr_enabled = cfg_get(psoc, CFG_LFR_FEATURE_ENABLED);
	lfr->mawc_enabled = cfg_get(psoc, CFG_LFR_MAWC_FEATURE_ENABLED);
	lfr->fast_transition_enabled =
		cfg_get(psoc, CFG_LFR_FAST_TRANSITION_ENABLED);
	lfr->wes_mode_enabled = cfg_get(psoc, CFG_LFR_ENABLE_WES_MODE);
	lfr->mawc_roam_traffic_threshold =
		cfg_get(psoc, CFG_LFR_MAWC_ROAM_TRAFFIC_THRESHOLD);
	lfr->mawc_roam_ap_rssi_threshold =
		cfg_get(psoc, CFG_LFR_MAWC_ROAM_AP_RSSI_THRESHOLD);
	lfr->mawc_roam_rssi_high_adjust =
		cfg_get(psoc, CFG_LFR_MAWC_ROAM_RSSI_HIGH_ADJUST);
	lfr->mawc_roam_rssi_low_adjust =
		cfg_get(psoc, CFG_LFR_MAWC_ROAM_RSSI_LOW_ADJUST);
	lfr->roam_rssi_abs_threshold =
		cfg_get(psoc, CFG_LFR_ROAM_RSSI_ABS_THRESHOLD);
	lfr->rssi_threshold_offset_5g =
		cfg_get(psoc, CFG_LFR_5G_RSSI_THRESHOLD_OFFSET);
	lfr->early_stop_scan_min_threshold =
		cfg_get(psoc, CFG_LFR_EARLY_STOP_SCAN_MIN_THRESHOLD);
	lfr->early_stop_scan_max_threshold =
		cfg_get(psoc, CFG_LFR_EARLY_STOP_SCAN_MAX_THRESHOLD);
	lfr->roam_dense_traffic_threshold =
		cfg_get(psoc, CFG_LFR_ROAM_DENSE_TRAFFIC_THRESHOLD);
	lfr->roam_dense_rssi_thre_offset =
		cfg_get(psoc, CFG_LFR_ROAM_DENSE_RSSI_THRE_OFFSET);
	lfr->roam_dense_min_aps =
		cfg_get(psoc, CFG_LFR_ROAM_DENSE_MIN_APS);
	lfr->roam_bg_scan_bad_rssi_threshold =
		cfg_get(psoc, CFG_LFR_ROAM_BG_SCAN_BAD_RSSI_THRESHOLD);
	lfr->roam_bg_scan_client_bitmap =
		cfg_get(psoc, CFG_LFR_ROAM_BG_SCAN_CLIENT_BITMAP);
	lfr->roam_bg_scan_bad_rssi_offset_2g =
		cfg_get(psoc, CFG_LFR_ROAM_BG_SCAN_BAD_RSSI_OFFSET_2G);
	lfr->roam_data_rssi_threshold_triggers =
		cfg_get(psoc, CFG_ROAM_DATA_RSSI_THRESHOLD_TRIGGERS);
	lfr->roam_data_rssi_threshold =
		cfg_get(psoc, CFG_ROAM_DATA_RSSI_THRESHOLD);
	lfr->rx_data_inactivity_time =
		cfg_get(psoc, CFG_RX_DATA_INACTIVITY_TIME);
	lfr->adaptive_roamscan_dwell_mode =
		cfg_get(psoc, CFG_LFR_ADAPTIVE_ROAMSCAN_DWELL_MODE);
	lfr->per_roam_enable =
		cfg_get(psoc, CFG_LFR_PER_ROAM_ENABLE);
	lfr->per_roam_config_high_rate_th =
		cfg_get(psoc, CFG_LFR_PER_ROAM_CONFIG_HIGH_RATE_TH);
	lfr->per_roam_config_low_rate_th =
		cfg_get(psoc, CFG_LFR_PER_ROAM_CONFIG_LOW_RATE_TH);
	lfr->per_roam_config_rate_th_percent =
		cfg_get(psoc, CFG_LFR_PER_ROAM_CONFIG_RATE_TH_PERCENT);
	lfr->per_roam_rest_time =
		cfg_get(psoc, CFG_LFR_PER_ROAM_REST_TIME);
	lfr->per_roam_monitor_time =
		cfg_get(psoc, CFG_LFR_PER_ROAM_MONITOR_TIME);
	lfr->per_roam_min_candidate_rssi =
		cfg_get(psoc, CFG_LFR_PER_ROAM_MIN_CANDIDATE_RSSI);
	lfr->lfr3_disallow_duration =
		cfg_get(psoc, CFG_LFR3_ROAM_DISALLOW_DURATION);
	lfr->lfr3_rssi_channel_penalization =
		cfg_get(psoc, CFG_LFR3_ROAM_RSSI_CHANNEL_PENALIZATION);
	lfr->lfr3_num_disallowed_aps =
		cfg_get(psoc, CFG_LFR3_ROAM_NUM_DISALLOWED_APS);

	if (lfr->enable_5g_band_pref) {
		lfr->rssi_boost_threshold_5g =
			cfg_get(psoc, CFG_LFR_5G_RSSI_BOOST_THRESHOLD);
		lfr->rssi_boost_factor_5g =
			cfg_get(psoc, CFG_LFR_5G_RSSI_BOOST_FACTOR);
		lfr->max_rssi_boost_5g =
			cfg_get(psoc, CFG_LFR_5G_MAX_RSSI_BOOST);
		lfr->rssi_penalize_threshold_5g =
			cfg_get(psoc, CFG_LFR_5G_RSSI_PENALIZE_THRESHOLD);
		lfr->rssi_penalize_factor_5g =
			cfg_get(psoc, CFG_LFR_5G_RSSI_PENALIZE_FACTOR);
		lfr->max_rssi_penalize_5g =
			cfg_get(psoc, CFG_LFR_5G_MAX_RSSI_PENALIZE);
	}

	lfr->max_num_pre_auth = (uint32_t)
		cfg_default(CFG_LFR_MAX_NUM_PRE_AUTH);
	lfr->roam_preauth_no_ack_timeout =
		cfg_get(psoc, CFG_LFR3_ROAM_PREAUTH_NO_ACK_TIMEOUT);
	lfr->roam_preauth_retry_count =
		cfg_get(psoc, CFG_LFR3_ROAM_PREAUTH_RETRY_COUNT);
	lfr->roam_rssi_diff = cfg_get(psoc, CFG_LFR_ROAM_RSSI_DIFF);
	lfr->roam_rssi_diff_6ghz = cfg_get(psoc, CFG_LFR_ROAM_RSSI_DIFF_6GHZ);
	lfr->bg_rssi_threshold = cfg_get(psoc, CFG_LFR_ROAM_BG_RSSI_TH);
	lfr->roam_scan_offload_enabled =
		cfg_get(psoc, CFG_LFR_ROAM_SCAN_OFFLOAD_ENABLED);
	lfr->neighbor_scan_timer_period =
		cfg_get(psoc, CFG_LFR_NEIGHBOR_SCAN_TIMER_PERIOD);
	lfr->neighbor_scan_min_timer_period =
		cfg_get(psoc, CFG_LFR_NEIGHBOR_SCAN_MIN_TIMER_PERIOD);
	lfr->neighbor_lookup_rssi_threshold =
		abs(cfg_get(psoc, CFG_LFR_NEIGHBOR_LOOKUP_RSSI_THRESHOLD));
	lfr->opportunistic_scan_threshold_diff =
		cfg_get(psoc, CFG_LFR_OPPORTUNISTIC_SCAN_THRESHOLD_DIFF);
	lfr->roam_rescan_rssi_diff =
		cfg_get(psoc, CFG_LFR_ROAM_RESCAN_RSSI_DIFF);
	lfr->neighbor_scan_min_chan_time =
		cfg_get(psoc, CFG_LFR_NEIGHBOR_SCAN_MIN_CHAN_TIME);
	lfr->neighbor_scan_max_chan_time =
		cfg_get(psoc, CFG_LFR_NEIGHBOR_SCAN_MAX_CHAN_TIME);
	lfr->passive_max_channel_time =
		cfg_get(psoc, CFG_ROAM_PASSIVE_MAX_CHANNEL_TIME);
	lfr->neighbor_scan_results_refresh_period =
		cfg_get(psoc, CFG_LFR_NEIGHBOR_SCAN_RESULTS_REFRESH_PERIOD);

	ucfg_mlme_get_connection_roaming_ini_present(psoc, &val);
	if (val)
		lfr->empty_scan_refresh_period =
			cfg_get(psoc, CFG_ROAM_SCAN_FIRST_TIMER) * 1000;
	else
		lfr->empty_scan_refresh_period =
			cfg_get(psoc, CFG_LFR_EMPTY_SCAN_REFRESH_PERIOD);
	lfr->roam_bmiss_first_bcnt =
		cfg_get(psoc, CFG_LFR_ROAM_BMISS_FIRST_BCNT);
	lfr->roam_bmiss_final_bcnt =
		cfg_get(psoc, CFG_LFR_ROAM_BMISS_FINAL_BCNT);
	lfr->roaming_dfs_channel =
		cfg_get(psoc, CFG_LFR_ROAMING_DFS_CHANNEL);
	lfr->roam_scan_hi_rssi_maxcount =
		cfg_get(psoc, CFG_LFR_ROAM_SCAN_HI_RSSI_MAXCOUNT);
	lfr->roam_scan_hi_rssi_delta =
		cfg_get(psoc, CFG_LFR_ROAM_SCAN_HI_RSSI_DELTA);
	lfr->roam_scan_hi_rssi_delay =
		cfg_get(psoc, CFG_LFR_ROAM_SCAN_HI_RSSI_DELAY);
	lfr->roam_scan_hi_rssi_ub =
		cfg_get(psoc, CFG_LFR_ROAM_SCAN_HI_RSSI_UB);
	lfr->roam_prefer_5ghz =
		cfg_get(psoc, CFG_LFR_ROAM_PREFER_5GHZ);
	lfr->roam_intra_band =
		cfg_get(psoc, CFG_LFR_ROAM_INTRA_BAND);
	lfr->roam_scan_home_away_time =
		cfg_get(psoc, CFG_LFR_ROAM_SCAN_HOME_AWAY_TIME);
	lfr->roam_scan_n_probes =
		cfg_get(psoc, CFG_LFR_ROAM_SCAN_N_PROBES);
	lfr->delay_before_vdev_stop =
		cfg_get(psoc, CFG_LFR_DELAY_BEFORE_VDEV_STOP);
	qdf_uint8_array_parse(cfg_get(psoc, CFG_LFR_NEIGHBOR_SCAN_CHANNEL_LIST),
			      lfr->neighbor_scan_channel_list,
			      CFG_VALID_CHANNEL_LIST_LEN,
			      &neighbor_scan_chan_list_num);
	lfr->neighbor_scan_channel_list_num =
				(uint8_t)neighbor_scan_chan_list_num;
	lfr->ho_delay_for_rx =
		cfg_get(psoc, CFG_LFR3_ROAM_HO_DELAY_FOR_RX);
	lfr->min_delay_btw_roam_scans =
		cfg_get(psoc, CFG_LFR_MIN_DELAY_BTW_ROAM_SCAN);
	lfr->roam_trigger_reason_bitmask =
		cfg_get(psoc, CFG_LFR_ROAM_SCAN_TRIGGER_REASON_BITMASK);
	lfr->enable_ftopen =
		cfg_get(psoc, CFG_LFR_ROAM_FT_OPEN_ENABLE);
	lfr->roam_force_rssi_trigger =
		cfg_get(psoc, CFG_LFR_ROAM_FORCE_RSSI_TRIGGER);
	lfr->roaming_scan_policy =
		cfg_get(psoc, CFG_ROAM_SCAN_SCAN_POLICY);

	if (val)
		lfr->roam_scan_inactivity_time =
			cfg_get(psoc, CFG_ROAM_SCAN_INACTIVE_TIMER) * 1000;
	else
		lfr->roam_scan_inactivity_time =
			cfg_get(psoc, CFG_ROAM_SCAN_INACTIVITY_TIME);

	lfr->roam_inactive_data_packet_count =
		cfg_get(psoc, CFG_ROAM_INACTIVE_COUNT);

	lfr->fw_akm_bitmap = 0;
	lfr->enable_ft_im_roaming = cfg_get(psoc, CFG_FT_IM_ROAMING);
	lfr->enable_ft_over_ds = !ENABLE_FT_OVER_DS;

	mlme_init_roam_offload_cfg(psoc, lfr);
	mlme_init_ese_cfg(psoc, lfr);
	mlme_init_bss_load_trigger_params(psoc, &lfr->bss_load_trig);
	mlme_init_adaptive_11r_cfg(psoc, lfr);
	mlme_init_subnet_detection(psoc, lfr);
	lfr->rso_user_config.cat_rssi_offset = DEFAULT_RSSI_DB_GAP;
#ifdef SEC_CONFIG_PSM_SYSFS
	if (wlan_hdd_sec_get_psm()) {
		lfr->lfr_enabled = 0;
		printk("[WIFI] CFG_LFR_FEATURE_ENABLED : sec_control_psm = %d", lfr->lfr_enabled);

		lfr->roam_force_rssi_trigger = 0;
		printk("[WIFI] CFG_LFR_ROAM_FORCE_RSSI_TRIGGER : sec_control_psm = %d", lfr->roam_force_rssi_trigger);

		lfr->enable_fast_roam_in_concurrency = 0;
		printk("[WIFI] CFG_LFR_ENABLE_FAST_ROAM_IN_CONCURRENCY : sec_control_psm = %d", lfr->enable_fast_roam_in_concurrency);

		lfr->roam_scan_offload_enabled = 0;
		printk("[WIFI] CFG_LFR_ROAM_SCAN_OFFLOAD_ENABLED : sec_control_psm = %d", lfr->roam_scan_offload_enabled);

        lfr->roam_bmiss_first_bcnt = 100;
		printk("[WIFI] CFG_LFR_ROAM_BMISS_FIRST_BCNT : sec_control_psm = %d", lfr->roam_bmiss_first_bcnt);

		lfr->roam_bmiss_final_bcnt = 100;
		printk("[WIFI] CFG_LFR_ROAM_BMISS_FINAL_BCNT : sec_control_psm = %d", lfr->roam_bmiss_final_bcnt);
	}
#endif /* SEC_CONFIG_PSM_SYSFS */
	mlme_init_bmiss_timeout(psoc, lfr);
	lfr->hs20_btm_offload_disable = cfg_get(psoc,
						CFG_HS_20_BTM_OFFLOAD_DISABLE);
}

static void mlme_init_power_cfg(struct wlan_objmgr_psoc *psoc,
				struct wlan_mlme_power *power)
{
	power->tx_power_2g = cfg_get(psoc, CFG_SET_TXPOWER_LIMIT2G);
	power->tx_power_5g = cfg_get(psoc, CFG_SET_TXPOWER_LIMIT5G);

	power->max_tx_power_24_chan.max_len = CFG_MAX_TX_POWER_2_4_LEN;
	qdf_uint8_array_parse(cfg_default(CFG_MAX_TX_POWER_2_4),
			      power->max_tx_power_24_chan.data,
			      sizeof(power->max_tx_power_24_chan.data),
			      &power->max_tx_power_24_chan.len);

	power->max_tx_power_5_chan.max_len = CFG_MAX_TX_POWER_5_LEN;
	qdf_uint8_array_parse(cfg_default(CFG_MAX_TX_POWER_5),
			      power->max_tx_power_5_chan.data,
			      sizeof(power->max_tx_power_5_chan.data),
			      &power->max_tx_power_5_chan.len);

	power->power_usage.max_len = CFG_POWER_USAGE_MAX_LEN;
	power->power_usage.len = CFG_POWER_USAGE_MAX_LEN;
	qdf_mem_copy(power->power_usage.data, cfg_get(psoc, CFG_POWER_USAGE),
		     power->power_usage.len);
	power->current_tx_power_level =
			(uint8_t)cfg_default(CFG_CURRENT_TX_POWER_LEVEL);
	power->local_power_constraint =
			(uint8_t)cfg_default(CFG_LOCAL_POWER_CONSTRAINT);
	power->skip_tpe = cfg_get(psoc, CFG_SKIP_TPE_CONSIDERATION);
}

static void mlme_init_roam_scoring_cfg(struct wlan_objmgr_psoc *psoc,
				struct wlan_mlme_roam_scoring_cfg *scoring_cfg)
{
	bool val = false;

	scoring_cfg->enable_scoring_for_roam =
		cfg_get(psoc, CFG_ENABLE_SCORING_FOR_ROAM);
	scoring_cfg->roam_trigger_bitmap =
			cfg_get(psoc, CFG_ROAM_SCORE_DELTA_TRIGGER_BITMAP);
	scoring_cfg->roam_score_delta = cfg_get(psoc, CFG_ROAM_SCORE_DELTA);
	scoring_cfg->apsd_enabled = (bool)cfg_default(CFG_APSD_ENABLED);

	ucfg_mlme_get_connection_roaming_ini_present(psoc, &val);
	if (val) {
		scoring_cfg->min_roam_score_delta =
			cfg_get(psoc, CFG_ROAM_COMMON_MIN_ROAM_DELTA) * 100;
	} else {
		scoring_cfg->min_roam_score_delta =
			cfg_get(psoc, CFG_CAND_MIN_ROAM_SCORE_DELTA);
	}
}

static void mlme_init_oce_cfg(struct wlan_objmgr_psoc *psoc,
			      struct wlan_mlme_oce *oce)
{
	uint8_t val;
	bool rssi_assoc_reject_enabled;
	bool probe_req_rate_enabled;
	bool probe_resp_rate_enabled;
	bool beacon_rate_enabled;
	bool probe_req_deferral_enabled;
	bool fils_discovery_sap_enabled;
	bool esp_for_roam_enabled;

	oce->enable_bcast_probe_rsp =
		cfg_get(psoc, CFG_ENABLE_BCAST_PROBE_RESP);
	oce->oce_sta_enabled = cfg_get(psoc, CFG_OCE_ENABLE_STA);
	oce->oce_sap_enabled = cfg_get(psoc, CFG_OCE_ENABLE_SAP);
	oce->fils_enabled = cfg_get(psoc, CFG_IS_FILS_ENABLED);

	rssi_assoc_reject_enabled =
		cfg_get(psoc, CFG_OCE_ENABLE_RSSI_BASED_ASSOC_REJECT);
	probe_req_rate_enabled = cfg_get(psoc, CFG_OCE_PROBE_REQ_RATE);
	probe_resp_rate_enabled = cfg_get(psoc, CFG_OCE_PROBE_RSP_RATE);
	beacon_rate_enabled = cfg_get(psoc, CFG_OCE_BEACON_RATE);
	probe_req_deferral_enabled =
		cfg_get(psoc, CFG_ENABLE_PROBE_REQ_DEFERRAL);
	fils_discovery_sap_enabled =
		cfg_get(psoc, CFG_ENABLE_FILS_DISCOVERY_SAP);
	esp_for_roam_enabled = cfg_get(psoc, CFG_ENABLE_ESP_FEATURE);

	if (!rssi_assoc_reject_enabled ||
	    !oce->enable_bcast_probe_rsp) {
		oce->oce_sta_enabled = 0;
	}

	val = (probe_req_rate_enabled *
	WMI_VDEV_OCE_PROBE_REQUEST_RATE_FEATURE_BITMAP) +
	(probe_resp_rate_enabled *
	WMI_VDEV_OCE_PROBE_RESPONSE_RATE_FEATURE_BITMAP) +
	(beacon_rate_enabled *
	WMI_VDEV_OCE_BEACON_RATE_FEATURE_BITMAP) +
	(probe_req_deferral_enabled *
	 WMI_VDEV_OCE_PROBE_REQUEST_DEFERRAL_FEATURE_BITMAP) +
	(fils_discovery_sap_enabled *
	 WMI_VDEV_OCE_FILS_DISCOVERY_FRAME_FEATURE_BITMAP) +
	(esp_for_roam_enabled *
	 WMI_VDEV_OCE_ESP_FEATURE_BITMAP) +
	(rssi_assoc_reject_enabled *
	 WMI_VDEV_OCE_REASSOC_REJECT_FEATURE_BITMAP);
	oce->feature_bitmap = val;
}

static void mlme_init_nss_chains(struct wlan_objmgr_psoc *psoc,
				 struct wlan_mlme_nss_chains *nss_chains)
{
	nss_chains->num_rx_chains[NSS_CHAINS_BAND_2GHZ] =
					    cfg_get(psoc, CFG_NUM_RX_CHAINS_2G);
	nss_chains->num_rx_chains[NSS_CHAINS_BAND_5GHZ] =
					    cfg_get(psoc, CFG_NUM_RX_CHAINS_5G);
	nss_chains->num_tx_chains[NSS_CHAINS_BAND_2GHZ] =
					    cfg_get(psoc, CFG_NUM_TX_CHAINS_2G);
	nss_chains->num_tx_chains[NSS_CHAINS_BAND_5GHZ] =
					    cfg_get(psoc, CFG_NUM_TX_CHAINS_5G);

	nss_chains->tx_nss[NSS_CHAINS_BAND_2GHZ] = cfg_get(psoc, CFG_TX_NSS_2G);
	nss_chains->tx_nss[NSS_CHAINS_BAND_5GHZ] = cfg_get(psoc, CFG_TX_NSS_5G);
	nss_chains->rx_nss[NSS_CHAINS_BAND_2GHZ] = cfg_get(psoc, CFG_RX_NSS_2G);
	nss_chains->rx_nss[NSS_CHAINS_BAND_5GHZ] = cfg_get(psoc, CFG_RX_NSS_5G);

	nss_chains->num_tx_chains_11b = cfg_get(psoc, CFG_NUM_TX_CHAINS_11b);
	nss_chains->num_tx_chains_11g = cfg_get(psoc, CFG_NUM_TX_CHAINS_11g);
	nss_chains->num_tx_chains_11a = cfg_get(psoc, CFG_NUM_TX_CHAINS_11a);

	nss_chains->disable_rx_mrc[NSS_CHAINS_BAND_2GHZ] =
					   cfg_get(psoc, CFG_DISABLE_RX_MRC_2G);
	nss_chains->disable_rx_mrc[NSS_CHAINS_BAND_5GHZ] =
					   cfg_get(psoc, CFG_DISABLE_RX_MRC_5G);
	nss_chains->disable_tx_mrc[NSS_CHAINS_BAND_2GHZ] =
					   cfg_get(psoc, CFG_DISABLE_TX_MRC_2G);
	nss_chains->disable_tx_mrc[NSS_CHAINS_BAND_5GHZ] =
					   cfg_get(psoc, CFG_DISABLE_TX_MRC_5G);
	nss_chains->enable_dynamic_nss_chains_cfg =
			cfg_get(psoc, CFG_ENABLE_DYNAMIC_NSS_CHAIN_CONFIG);
	nss_chains->restart_sap_on_dyn_nss_chains_cfg =
			cfg_get(psoc,
				CFG_RESTART_SAP_ON_DYNAMIC_NSS_CHAINS_CONFIG);
}

static void mlme_init_wep_cfg(struct wlan_mlme_wep_cfg *wep_params)
{
	wep_params->is_privacy_enabled = cfg_default(CFG_PRIVACY_ENABLED);
	wep_params->auth_type = cfg_default(CFG_AUTHENTICATION_TYPE);
	wep_params->is_shared_key_auth =
			cfg_default(CFG_SHARED_KEY_AUTH_ENABLE);
	wep_params->is_auth_open_system =
			cfg_default(CFG_OPEN_SYSTEM_AUTH_ENABLE);

	wep_params->wep_default_key_id = cfg_default(CFG_WEP_DEFAULT_KEYID);
}

#if defined(WIFI_POS_CONVERGED) && defined(WLAN_FEATURE_RTT_11AZ_SUPPORT)
static void
mlme_init_wifi_pos_11az_config(struct wlan_objmgr_psoc *psoc,
			       struct wlan_mlme_wifi_pos_cfg *wifi_pos_cfg)
{
	bool rsta_sec_ltf_enabled =
			cfg_get(psoc, CFG_RESPONDER_SECURE_LTF_SUPPORT);
	bool rsta_11az_ranging_enabled = cfg_get(psoc,
						 CFG_RESPONDER_11AZ_SUPPORT);

	wifi_pos_set_rsta_11az_ranging_cap(rsta_11az_ranging_enabled);
	wifi_pos_set_rsta_sec_ltf_cap(rsta_sec_ltf_enabled);
}
#else
static inline void
mlme_init_wifi_pos_11az_config(struct wlan_objmgr_psoc *psoc,
			       struct wlan_mlme_wifi_pos_cfg *wifi_pos_cfg)
{}
#endif

static void mlme_init_wifi_pos_cfg(struct wlan_objmgr_psoc *psoc,
				   struct wlan_mlme_wifi_pos_cfg *wifi_pos_cfg)
{
	wifi_pos_cfg->fine_time_meas_cap =
		cfg_get(psoc, CFG_FINE_TIME_MEAS_CAPABILITY);
	wifi_pos_cfg->oem_6g_support_disable =
		cfg_get(psoc, CFG_OEM_SIXG_SUPPORT_DISABLE);

	mlme_init_wifi_pos_11az_config(psoc, wifi_pos_cfg);
}

#ifdef FEATURE_WLAN_ESE
static void mlme_init_inactivity_intv(struct wlan_objmgr_psoc *psoc,
				      struct wlan_mlme_wmm_params *wmm_params)
{
	wmm_params->wmm_tspec_element.inactivity_intv =
		cfg_get(psoc, CFG_QOS_WMM_INACTIVITY_INTERVAL);
}
#else
static inline void
mlme_init_inactivity_intv(struct wlan_objmgr_psoc *psoc,
			  struct wlan_mlme_wmm_params *wmm_params)
{
}
#endif /* FEATURE_WLAN_ESE */

static void mlme_init_wmm_in_cfg(struct wlan_objmgr_psoc *psoc,
				 struct wlan_mlme_wmm_params *wmm_params)
{
	wmm_params->qos_enabled = cfg_default(CFG_QOS_ENABLED);
	wmm_params->wme_enabled = cfg_default(CFG_WME_ENABLED);
	wmm_params->max_sp_length = cfg_default(CFG_MAX_SP_LENGTH);
	wmm_params->wsm_enabled = cfg_default(CFG_WSM_ENABLED);
	wmm_params->edca_profile = cfg_default(CFG_EDCA_PROFILE);

	wmm_params->ac_vo.dir_ac_vo = cfg_get(psoc, CFG_QOS_WMM_DIR_AC_VO);
	wmm_params->ac_vo.nom_msdu_size_ac_vo =
			cfg_get(psoc, CFG_QOS_WMM_NOM_MSDU_SIZE_AC_VO);
	wmm_params->ac_vo.mean_data_rate_ac_vo =
			cfg_get(psoc, CFG_QOS_WMM_MEAN_DATA_RATE_AC_VO);
	wmm_params->ac_vo.min_phy_rate_ac_vo =
			cfg_get(psoc, CFG_QOS_WMM_MIN_PHY_RATE_AC_VO);
	wmm_params->ac_vo.sba_ac_vo = cfg_get(psoc, CFG_QOS_WMM_SBA_AC_VO);
	wmm_params->ac_vo.uapsd_vo_srv_intv =
			cfg_get(psoc, CFG_QOS_WMM_UAPSD_VO_SRV_INTV);
	wmm_params->ac_vo.uapsd_vo_sus_intv =
			cfg_get(psoc, CFG_QOS_WMM_UAPSD_VO_SUS_INTV);

	wmm_params->ac_vi.dir_ac_vi =
		cfg_get(psoc, CFG_QOS_WMM_DIR_AC_VI);
	wmm_params->ac_vi.nom_msdu_size_ac_vi =
		cfg_get(psoc, CFG_QOS_WMM_NOM_MSDU_SIZE_AC_VI);
	wmm_params->ac_vi.mean_data_rate_ac_vi =
		cfg_get(psoc, CFG_QOS_WMM_MEAN_DATA_RATE_AC_VI);
	wmm_params->ac_vi.min_phy_rate_ac_vi =
		cfg_get(psoc, CFG_QOS_WMM_MIN_PHY_RATE_AC_VI);
	wmm_params->ac_vi.sba_ac_vi =
		cfg_get(psoc, CFG_QOS_WMM_SBA_AC_VI);
	wmm_params->ac_vi.uapsd_vi_srv_intv =
		cfg_get(psoc, CFG_QOS_WMM_UAPSD_VI_SRV_INTV);
	wmm_params->ac_vi.uapsd_vi_sus_intv =
		cfg_get(psoc, CFG_QOS_WMM_UAPSD_VI_SUS_INTV);

	wmm_params->ac_be.dir_ac_be =
		cfg_get(psoc, CFG_QOS_WMM_DIR_AC_BE);
	wmm_params->ac_be.nom_msdu_size_ac_be =
		cfg_get(psoc, CFG_QOS_WMM_NOM_MSDU_SIZE_AC_BE);
	wmm_params->ac_be.mean_data_rate_ac_be =
		cfg_get(psoc, CFG_QOS_WMM_MEAN_DATA_RATE_AC_BE);
	wmm_params->ac_be.min_phy_rate_ac_be =
		cfg_get(psoc, CFG_QOS_WMM_MIN_PHY_RATE_AC_BE);
	wmm_params->ac_be.sba_ac_be =
		cfg_get(psoc, CFG_QOS_WMM_SBA_AC_BE);
	wmm_params->ac_be.uapsd_be_srv_intv =
		cfg_get(psoc, CFG_QOS_WMM_UAPSD_BE_SRV_INTV);
	wmm_params->ac_be.uapsd_be_sus_intv =
		cfg_get(psoc, CFG_QOS_WMM_UAPSD_BE_SUS_INTV);

	wmm_params->ac_bk.dir_ac_bk =
		cfg_get(psoc, CFG_QOS_WMM_DIR_AC_BK);
	wmm_params->ac_bk.nom_msdu_size_ac_bk =
		cfg_get(psoc, CFG_QOS_WMM_NOM_MSDU_SIZE_AC_BK);
	wmm_params->ac_bk.mean_data_rate_ac_bk =
		cfg_get(psoc, CFG_QOS_WMM_MEAN_DATA_RATE_AC_BK);
	wmm_params->ac_bk.min_phy_rate_ac_bk =
		cfg_get(psoc, CFG_QOS_WMM_MIN_PHY_RATE_AC_BK);
	wmm_params->ac_bk.sba_ac_bk =
		cfg_get(psoc, CFG_QOS_WMM_SBA_AC_BK);
	wmm_params->ac_bk.uapsd_bk_srv_intv =
		cfg_get(psoc, CFG_QOS_WMM_UAPSD_BK_SRV_INTV);
	wmm_params->ac_bk.uapsd_bk_sus_intv =
		cfg_get(psoc, CFG_QOS_WMM_UAPSD_BK_SUS_INTV);

	wmm_params->wmm_config.wmm_mode =
		cfg_get(psoc, CFG_QOS_WMM_MODE);
	wmm_params->wmm_config.b80211e_is_enabled =
		cfg_get(psoc, CFG_QOS_WMM_80211E_ENABLED);
	wmm_params->wmm_config.uapsd_mask =
		cfg_get(psoc, CFG_QOS_WMM_UAPSD_MASK);

	mlme_init_inactivity_intv(psoc, wmm_params);
	wmm_params->wmm_tspec_element.burst_size_def =
		cfg_get(psoc, CFG_QOS_WMM_BURST_SIZE_DEFN);
	wmm_params->wmm_tspec_element.ts_ack_policy =
		cfg_get(psoc, CFG_QOS_WMM_TS_INFO_ACK_POLICY);
	wmm_params->wmm_tspec_element.ts_acm_is_off =
		cfg_get(psoc, CFG_QOS_ADDTS_WHEN_ACM_IS_OFF);
	wmm_params->delayed_trigger_frm_int =
		cfg_get(psoc, CFG_TL_DELAYED_TRGR_FRM_INTERVAL);

}

static void mlme_init_wps_params_cfg(struct wlan_objmgr_psoc *psoc,
				     struct wlan_mlme_wps_params *wps_params)
{
	wps_params->enable_wps = cfg_default(CFG_WPS_ENABLE);
	wps_params->wps_cfg_method = cfg_default(CFG_WPS_CFG_METHOD);
	wps_params->wps_device_password_id =
				cfg_default(CFG_WPS_DEVICE_PASSWORD_ID);
	wps_params->wps_device_sub_category =
				cfg_default(CFG_WPS_DEVICE_SUB_CATEGORY);
	wps_params->wps_primary_device_category =
				cfg_default(CFG_WPS_PRIMARY_DEVICE_CATEGORY);
	wps_params->wps_primary_device_oui =
				cfg_default(CFG_WPS_PIMARY_DEVICE_OUI);
	wps_params->wps_state = cfg_default(CFG_WPS_STATE);
	wps_params->wps_version = cfg_default(CFG_WPS_VERSION);
	wps_params->wps_uuid.max_len = MLME_CFG_WPS_UUID_MAX_LEN;
	qdf_uint8_array_parse(cfg_default(CFG_WPS_UUID),
			      wps_params->wps_uuid.data,
			      MLME_CFG_WPS_UUID_MAX_LEN,
			      &wps_params->wps_uuid.len);
}

static void mlme_init_btm_cfg(struct wlan_objmgr_psoc *psoc,
			      struct wlan_mlme_btm *btm)
{
	btm->btm_offload_config = cfg_get(psoc, CFG_BTM_ENABLE);
	btm->prefer_btm_query = cfg_get(psoc, CFG_PREFER_BTM_QUERY);
	if (btm->prefer_btm_query)
		MLME_SET_BIT(btm->btm_offload_config, BTM_OFFLOAD_CONFIG_BIT_8);

	btm->abridge_flag = cfg_get(psoc, CFG_ENABLE_BTM_ABRIDGE);
#ifdef SEC_CONFIG_PSM_SYSFS
	if (btm->abridge_flag && !wlan_hdd_sec_get_psm())
#else /* SEC_CONFIG_PSM_SYSFS */
	if (btm->abridge_flag)
#endif /* !SEC_CONFIG_PSM_SYSFS */
		MLME_SET_BIT(btm->btm_offload_config, BTM_OFFLOAD_CONFIG_BIT_7);
	wlan_mlme_set_btm_abridge_flag(psoc, btm->abridge_flag);

	btm->btm_solicited_timeout = cfg_get(psoc, CFG_BTM_SOLICITED_TIMEOUT);
	btm->btm_max_attempt_cnt = cfg_get(psoc, CFG_BTM_MAX_ATTEMPT_CNT);
	btm->btm_sticky_time = cfg_get(psoc, CFG_BTM_STICKY_TIME);
	btm->rct_validity_timer = cfg_get(psoc, CFG_BTM_VALIDITY_TIMER);
	btm->disassoc_timer_threshold =
			cfg_get(psoc, CFG_BTM_DISASSOC_TIMER_THRESHOLD);
	btm->btm_query_bitmask = cfg_get(psoc, CFG_BTM_QUERY_BITMASK);
	btm->btm_trig_min_candidate_score =
			cfg_get(psoc, CFG_MIN_BTM_CANDIDATE_SCORE);
#ifdef SEC_CONFIG_PSM_SYSFS
	if (wlan_hdd_sec_get_psm()) {
		btm->abridge_flag = 0;
		printk("[WIFI] CFG_ENABLE_BTM_ABRIDGE : sec_control_psm = %u", btm->abridge_flag = 0);
	}
#endif /* SEC_CONFIG_PSM_SYSFS */
}

static void
mlme_init_roam_score_config(struct wlan_objmgr_psoc *psoc,
			    struct wlan_mlme_cfg *mlme_cfg)
{
	struct roam_trigger_score_delta *score_delta_param;
	struct roam_trigger_min_rssi *min_rssi_param;

	score_delta_param = &mlme_cfg->trig_score_delta[IDLE_ROAM_TRIGGER];
	score_delta_param->roam_score_delta =
			cfg_get(psoc, CFG_IDLE_ROAM_SCORE_DELTA);
	score_delta_param->trigger_reason = ROAM_TRIGGER_REASON_IDLE;

	score_delta_param = &mlme_cfg->trig_score_delta[BTM_ROAM_TRIGGER];
	score_delta_param->roam_score_delta =
			cfg_get(psoc, CFG_BTM_ROAM_SCORE_DELTA);
	score_delta_param->trigger_reason = ROAM_TRIGGER_REASON_BTM;

	min_rssi_param = &mlme_cfg->trig_min_rssi[DEAUTH_MIN_RSSI];
	min_rssi_param->min_rssi =
		cfg_get(psoc, CFG_DISCONNECT_ROAM_TRIGGER_MIN_RSSI);
	min_rssi_param->trigger_reason = ROAM_TRIGGER_REASON_DEAUTH;

	min_rssi_param = &mlme_cfg->trig_min_rssi[BMISS_MIN_RSSI];
	min_rssi_param->min_rssi =
		cfg_get(psoc, CFG_BMISS_ROAM_MIN_RSSI);
	min_rssi_param->trigger_reason = ROAM_TRIGGER_REASON_BMISS;

	min_rssi_param = &mlme_cfg->trig_min_rssi[MIN_RSSI_2G_TO_5G_ROAM];
	min_rssi_param->min_rssi =
		cfg_get(psoc, CFG_2G_TO_5G_ROAM_MIN_RSSI);
	min_rssi_param->trigger_reason = ROAM_TRIGGER_REASON_HIGH_RSSI;

}

#ifdef MULTI_CLIENT_LL_SUPPORT
static void
mlme_init_wlm_multi_client_ll_support(struct wlan_objmgr_psoc *psoc,
				      struct wlan_mlme_fe_wlm *wlm_config)
{
	wlm_config->multi_client_ll_support =
			cfg_get(psoc, CFG_WLM_MULTI_CLIENT_LL_SUPPORT);
}

QDF_STATUS
mlme_get_cfg_multi_client_ll_ini_support(struct wlan_objmgr_psoc *psoc,
					 bool *multi_client_ll_support)
{
	struct wlan_mlme_psoc_ext_obj *mlme_obj;

	mlme_obj = mlme_get_psoc_ext_obj(psoc);
	if (!mlme_obj)
		return QDF_STATUS_E_FAILURE;

	*multi_client_ll_support =
			mlme_obj->cfg.wlm_config.multi_client_ll_support;

	return QDF_STATUS_SUCCESS;
}
#else
static inline void
mlme_init_wlm_multi_client_ll_support(struct wlan_objmgr_psoc *psoc,
				      struct wlan_mlme_fe_wlm *wlm_config)
{
}
#endif

/**
 * mlme_init_fe_wlm_in_cfg() - Populate WLM INI in MLME cfg
 * @psoc: pointer to the psoc object
 * @wlm_config: pointer to the MLME WLM cfg
 *
 * Return: None
 */
static void mlme_init_fe_wlm_in_cfg(struct wlan_objmgr_psoc *psoc,
				    struct wlan_mlme_fe_wlm *wlm_config)
{
	uint64_t flags = 0;
	QDF_STATUS status;

	wlm_config->latency_enable = cfg_get(psoc, CFG_LATENCY_ENABLE);
	wlm_config->latency_reset = cfg_get(psoc, CFG_LATENCY_RESET);
	wlm_config->latency_level = cfg_get(psoc, CFG_LATENCY_LEVEL);
	mlme_init_wlm_multi_client_ll_support(psoc, wlm_config);

	status = qdf_uint64_parse(cfg_get(psoc, CFG_LATENCY_FLAGS_NORMAL),
				  &flags);
	if (status != QDF_STATUS_SUCCESS) {
		flags = 0;
		mlme_legacy_err("normal latency flags parsing failed");
	}

	wlm_config->latency_flags[0] = flags & 0xFFFFFFFF;
	wlm_config->latency_host_flags[0] = flags >> 32;
	mlme_legacy_debug("normal latency flags 0x%x host flags 0x%x",
			  wlm_config->latency_flags[0],
			  wlm_config->latency_host_flags[0]);

	status = qdf_uint64_parse(cfg_get(psoc, CFG_LATENCY_FLAGS_XR),
				  &flags);
	if (status != QDF_STATUS_SUCCESS) {
		flags = 0;
		mlme_legacy_err("xr latency flags parsing failed");
	}

	wlm_config->latency_flags[1] = flags & 0xFFFFFFFF;
	wlm_config->latency_host_flags[1] = flags >> 32;
	mlme_legacy_debug("xr latency flags 0x%x host flags 0x%x",
			  wlm_config->latency_flags[1],
			  wlm_config->latency_host_flags[1]);

	status = qdf_uint64_parse(cfg_get(psoc, CFG_LATENCY_FLAGS_LOW),
				  &flags);
	if (status != QDF_STATUS_SUCCESS) {
		flags = 0;
		mlme_legacy_err("low latency flags parsing failed");
	}

	wlm_config->latency_flags[2] = flags & 0xFFFFFFFF;
	wlm_config->latency_host_flags[2] = flags >> 32;
	mlme_legacy_debug("low latency flags 0x%x host flags 0x%x",
			  wlm_config->latency_flags[2],
			  wlm_config->latency_host_flags[2]);

	status = qdf_uint64_parse(cfg_get(psoc, CFG_LATENCY_FLAGS_ULTLOW),
				  &flags);
	if (status != QDF_STATUS_SUCCESS) {
		flags = 0;
		mlme_legacy_err("ultra-low latency flags parsing failed");
	}

	wlm_config->latency_flags[3] = flags & 0xFFFFFFFF;
	wlm_config->latency_host_flags[3] = flags >> 32;
	mlme_legacy_debug("ultra-low latency flags 0x%x host flags 0x%x",
			  wlm_config->latency_flags[3],
			  wlm_config->latency_host_flags[3]);
}

/**
 * mlme_init_fe_rrm_in_cfg() - Populate RRM INI in MLME cfg
 * @psoc: pointer to the psoc object
 * @rrm_config: pointer to the MLME RRM cfg
 *
 * Return: None
 */
static void mlme_init_fe_rrm_in_cfg(struct wlan_objmgr_psoc *psoc,
				    struct wlan_mlme_fe_rrm *rrm_config)
{
	qdf_size_t len;

	rrm_config->rrm_enabled = cfg_get(psoc, CFG_RRM_ENABLE);
	rrm_config->sap_rrm_enabled = cfg_get(psoc, CFG_SAP_RRM_ENABLE);
	rrm_config->rrm_rand_interval = cfg_get(psoc, CFG_RRM_MEAS_RAND_INTVL);

	qdf_uint8_array_parse(cfg_get(psoc, CFG_RM_CAPABILITY),
			      rrm_config->rm_capability,
			      sizeof(rrm_config->rm_capability), &len);

	if (len < MLME_RMENABLEDCAP_MAX_LEN) {
		mlme_legacy_debug("Incorrect RM capability, using default");
		qdf_uint8_array_parse(cfg_default(CFG_RM_CAPABILITY),
				      rrm_config->rm_capability,
				      sizeof(rrm_config->rm_capability), &len);
	}
}

static void mlme_init_powersave_params(struct wlan_objmgr_psoc *psoc,
				       struct wlan_mlme_powersave *ps_cfg)
{
	ps_cfg->is_imps_enabled = cfg_get(psoc, CFG_ENABLE_IMPS);
	ps_cfg->is_bmps_enabled = cfg_get(psoc, CFG_ENABLE_PS);
	ps_cfg->auto_bmps_timer_val = cfg_get(psoc, CFG_AUTO_BMPS_ENABLE_TIMER);
	ps_cfg->bmps_min_listen_interval = cfg_get(psoc, CFG_BMPS_MINIMUM_LI);
	ps_cfg->bmps_max_listen_interval = cfg_get(psoc, CFG_BMPS_MAXIMUM_LI);
	ps_cfg->dtim_selection_diversity =
				cfg_get(psoc, CFG_DTIM_SELECTION_DIVERSITY);
#ifdef SEC_CONFIG_PSM_SYSFS
	if (wlan_hdd_sec_get_psm()) {
		ps_cfg->is_imps_enabled = 0;
		ps_cfg->is_bmps_enabled = 0;
		printk("[WIFI] CFG_ENABLE_IMPS : sec_control_psm = %d", ps_cfg->is_imps_enabled);
		printk("[WIFI] CFG_ENABLE_PS : sec_control_psm = %d", ps_cfg->is_bmps_enabled);
	}
#endif /* SEC_CONFIG_PSM_SYSFS */
}

#if defined(CONFIG_AFC_SUPPORT) && defined(CONFIG_BAND_6GHZ)
static void mlme_init_afc_cfg(struct wlan_objmgr_psoc *psoc,
			      struct wlan_mlme_reg *reg)
{
	reg->enable_6ghz_sp_pwrmode_supp =
		cfg_get(psoc, CFG_6GHZ_SP_POWER_MODE_SUPP);
	reg->afc_disable_timer_check =
		cfg_default(CFG_AFC_TIMER_CHECK_DIS);
	reg->afc_disable_request_id_check =
		cfg_default(CFG_AFC_REQ_ID_CHECK_DIS);
	reg->is_afc_reg_noaction =
		cfg_default(CFG_AFC_REG_NO_ACTION);
}
#else
static inline void mlme_init_afc_cfg(struct wlan_objmgr_psoc *psoc,
				     struct wlan_mlme_reg *reg)
{
}
#endif

#ifdef MWS_COEX
static void mlme_init_mwc_cfg(struct wlan_objmgr_psoc *psoc,
			      struct wlan_mlme_mwc *mwc)
{
	mwc->mws_coex_4g_quick_tdm =
		cfg_get(psoc, CFG_MWS_COEX_4G_QUICK_FTDM);
	mwc->mws_coex_5g_nr_pwr_limit =
		cfg_get(psoc, CFG_MWS_COEX_5G_NR_PWR_LIMIT);
	mwc->mws_coex_pcc_channel_avoid_delay =
		cfg_get(psoc, CFG_MWS_COEX_PCC_CHANNEL_AVOID_DELAY);
	mwc->mws_coex_scc_channel_avoid_delay =
		cfg_get(psoc, CFG_MWS_COEX_SCC_CHANNEL_AVOID_DELAY);
}
#else
static void mlme_init_mwc_cfg(struct wlan_objmgr_psoc *psoc,
			      struct wlan_mlme_mwc *mwc)
{
}
#endif

#ifdef SAP_AVOID_ACS_FREQ_LIST
static void mlme_init_acs_avoid_freq_list(struct wlan_objmgr_psoc *psoc,
					  struct wlan_mlme_reg *reg)
{
	qdf_size_t avoid_acs_freq_list_num = 0;
	uint8_t i;

	qdf_uint16_array_parse(cfg_get(psoc, CFG_SAP_AVOID_ACS_FREQ_LIST),
			       reg->avoid_acs_freq_list,
			       CFG_VALID_CHANNEL_LIST_LEN,
			       &avoid_acs_freq_list_num);
	reg->avoid_acs_freq_list_num = avoid_acs_freq_list_num;

	for (i = 0; i < avoid_acs_freq_list_num; i++)
		mlme_legacy_debug("avoid_acs_freq %d",
				  reg->avoid_acs_freq_list[i]);
}
#else
static void mlme_init_acs_avoid_freq_list(struct wlan_objmgr_psoc *psoc,
					  struct wlan_mlme_reg *reg)
{
}
#endif

#ifdef FEATURE_WLAN_CH_AVOID_EXT
static void mlme_init_coex_unsafe_chan_cfg(struct wlan_objmgr_psoc *psoc,
					   struct wlan_mlme_reg *reg)
{
	reg->coex_unsafe_chan_nb_user_prefer =
		cfg_get(psoc, CFG_COEX_UNSAFE_CHAN_NB_USER_PREFER);
}

static void mlme_init_coex_unsafe_chan_reg_disable_cfg(
		struct wlan_objmgr_psoc *psoc, struct wlan_mlme_reg *reg)
{
	reg->coex_unsafe_chan_reg_disable =
		cfg_get(psoc, CFG_COEX_UNSAFE_CHAN_REG_DISABLE);
}
#else
static void mlme_init_coex_unsafe_chan_cfg(struct wlan_objmgr_psoc *psoc,
					   struct wlan_mlme_reg *reg)
{
}

static void mlme_init_coex_unsafe_chan_reg_disable_cfg(
		struct wlan_objmgr_psoc *psoc, struct wlan_mlme_reg *reg)
{
}
#endif

static void mlme_init_reg_cfg(struct wlan_objmgr_psoc *psoc,
			      struct wlan_mlme_reg *reg)
{
	reg->self_gen_frm_pwr = cfg_get(psoc, CFG_SELF_GEN_FRM_PWR);
	reg->etsi_srd_chan_in_master_mode =
			cfg_get(psoc, CFG_ETSI_SRD_CHAN_IN_MASTER_MODE);
	reg->fcc_5dot9_ghz_chan_in_master_mode =
			cfg_get(psoc, CFG_FCC_5DOT9_GHZ_CHAN_IN_MASTER_MODE);
	reg->restart_beaconing_on_ch_avoid =
			cfg_get(psoc, CFG_RESTART_BEACONING_ON_CH_AVOID);
	reg->indoor_channel_support = cfg_get(psoc, CFG_INDOOR_CHANNEL_SUPPORT);
	reg->enable_11d_in_world_mode = cfg_get(psoc,
						CFG_ENABLE_11D_IN_WORLD_MODE);
	reg->scan_11d_interval = cfg_get(psoc, CFG_SCAN_11D_INTERVAL);
	reg->enable_pending_chan_list_req = cfg_get(psoc,
					CFG_ENABLE_PENDING_CHAN_LIST_REQ);
	reg->ignore_fw_reg_offload_ind = cfg_get(
						psoc,
						CFG_IGNORE_FW_REG_OFFLOAD_IND);
	reg->retain_nol_across_regdmn_update =
		cfg_get(psoc, CFG_RETAIN_NOL_ACROSS_REG_DOMAIN);

	reg->enable_nan_on_indoor_channels =
		cfg_get(psoc, CFG_INDOOR_CHANNEL_SUPPORT_FOR_NAN);

	mlme_init_afc_cfg(psoc, reg);
	mlme_init_acs_avoid_freq_list(psoc, reg);
	mlme_init_coex_unsafe_chan_cfg(psoc, reg);
	mlme_init_coex_unsafe_chan_reg_disable_cfg(psoc, reg);
}

static void
mlme_init_dot11_mode_cfg(struct wlan_objmgr_psoc *psoc,
			 struct wlan_mlme_dot11_mode *dot11_mode)
{
	dot11_mode->dot11_mode = cfg_default(CFG_DOT11_MODE);
	dot11_mode->vdev_type_dot11_mode = cfg_get(psoc, CFG_VDEV_DOT11_MODE);
}

/**
 * mlme_iot_parse_aggr_info - parse aggr related items in ini
 * @psoc: PSOC pointer
 * @iot: IOT related CFG items
 *
 * Return: None
 */
static void
mlme_iot_parse_aggr_info(struct wlan_objmgr_psoc *psoc,
			 struct wlan_mlme_iot *iot)
{
	char *aggr_info, *oui, *msdu, *mpdu, *aggr_info_temp;
	uint32_t ampdu_sz, amsdu_sz, index = 0, oui_len, cfg_str_len;
	struct wlan_iot_aggr *aggr_info_list;
	const char *cfg_str;
	int ret;

	cfg_str = cfg_get(psoc, CFG_TX_IOT_AGGR);
	if (!cfg_str)
		return;

	cfg_str_len = qdf_str_len(cfg_str);
	if (!cfg_str_len)
		return;

	aggr_info = qdf_mem_malloc(cfg_str_len + 1);
	if (!aggr_info)
		return;

	aggr_info_list = iot->aggr;
	qdf_mem_copy(aggr_info, cfg_str, cfg_str_len);
	mlme_legacy_debug("aggr_info=[%s]", aggr_info);

	aggr_info_temp = aggr_info;
	while (aggr_info_temp) {
		/* skip possible spaces before oui string */
		while (*aggr_info_temp == ' ')
			aggr_info_temp++;

		oui = strsep(&aggr_info_temp, ",");
		if (!oui) {
			mlme_legacy_err("oui error");
			goto end;
		}

		oui_len = qdf_str_len(oui) / 2;
		if (oui_len > sizeof(aggr_info_list[index].oui)) {
			mlme_legacy_err("size error");
			goto end;
		}

		amsdu_sz = 0;
		msdu = strsep(&aggr_info_temp, ",");
		if (!msdu) {
			mlme_legacy_err("msdu error");
			goto end;
		}

		ret = kstrtou32(msdu, 10, &amsdu_sz);
		if (ret || amsdu_sz > IOT_AGGR_MSDU_MAX_NUM) {
			mlme_legacy_err("invalid msdu no. %s [%u]",
					msdu, amsdu_sz);
			goto end;
		}

		ampdu_sz = 0;
		mpdu = strsep(&aggr_info_temp, ",");
		if (!mpdu) {
			mlme_legacy_err("mpdu error");
			goto end;
		}

		ret = kstrtou32(mpdu, 10, &ampdu_sz);
		if (ret || ampdu_sz > IOT_AGGR_MPDU_MAX_NUM) {
			mlme_legacy_err("invalid mpdu no. %s [%u]",
					mpdu, ampdu_sz);
			goto end;
		}

		mlme_legacy_debug("id %u oui[%s] len %u msdu %u mpdu %u",
				  index, oui, oui_len, amsdu_sz, ampdu_sz);

		ret = qdf_hex_str_to_binary(aggr_info_list[index].oui,
					    oui, oui_len);
		if (ret) {
			mlme_legacy_err("oui error: %d", ret);
			goto end;
		}

		aggr_info_list[index].amsdu_sz = amsdu_sz;
		aggr_info_list[index].ampdu_sz = ampdu_sz;
		aggr_info_list[index].oui_len = oui_len;
		index++;
		if (index >= IOT_AGGR_INFO_MAX_NUM) {
			mlme_legacy_err("exceed max num, index = %d", index);
			break;
		}
	}
	iot->aggr_num = index;

end:
	mlme_legacy_debug("configured aggr num %d", iot->aggr_num);
	qdf_mem_free(aggr_info);
}

/**
 * mlme_init_iot_cfg() - parse IOT related items in ini
 * @psoc: PSOC pointer
 * @iot: IOT related CFG items
 *
 * Return: None
 */
static void
mlme_init_iot_cfg(struct wlan_objmgr_psoc *psoc,
		  struct wlan_mlme_iot *iot)
{
	mlme_iot_parse_aggr_info(psoc, iot);
}

/**
 * mlme_init_dual_sta_config - Initialize dual sta configurations
 * @gen: Generic CFG config items
 *
 * Return: None
 */
static void
mlme_init_dual_sta_config(struct wlan_mlme_generic *gen)
{
	gen->dual_sta_policy.primary_vdev_id = WLAN_UMAC_VDEV_ID_MAX;
	gen->dual_sta_policy.concurrent_sta_policy =
				QCA_WLAN_CONCURRENT_STA_POLICY_UNBIASED;
}

#ifdef WLAN_FEATURE_MCC_QUOTA
/**
 * mlme_init_user_mcc_quota_config - Initialize mcc quota
 * @gen: Generic CFG config items
 *
 * Return: None
 */
static void
mlme_init_user_mcc_quota_config(struct wlan_mlme_generic *gen)
{
	gen->user_mcc_quota.quota = 0;
	gen->user_mcc_quota.op_mode = QDF_MAX_NO_OF_MODE;
	gen->user_mcc_quota.vdev_id = WLAN_UMAC_VDEV_ID_MAX;
}
#else
static void
mlme_init_user_mcc_quota_config(struct wlan_mlme_generic *gen)
{
}
#endif
QDF_STATUS mlme_cfg_on_psoc_enable(struct wlan_objmgr_psoc *psoc)
{
	struct wlan_mlme_psoc_ext_obj *mlme_obj;
	struct wlan_mlme_cfg *mlme_cfg;
	QDF_STATUS status = QDF_STATUS_SUCCESS;

	mlme_obj = mlme_get_psoc_ext_obj(psoc);
	if (!mlme_obj) {
		mlme_legacy_err("Failed to get MLME Obj");
		return QDF_STATUS_E_FAILURE;
	}

	mlme_cfg = &mlme_obj->cfg;
	mlme_init_generic_cfg(psoc, &mlme_cfg->gen);
	mlme_init_timeout_cfg(psoc, &mlme_cfg->timeouts);
	mlme_init_edca_params(psoc, &mlme_cfg->edca_params);
	mlme_init_ht_cap_in_cfg(psoc, &mlme_cfg->ht_caps);
	mlme_init_wmm_in_cfg(psoc, &mlme_cfg->wmm_params);
	mlme_init_mbo_cfg(psoc, &mlme_cfg->mbo_cfg);
	mlme_init_qos_cfg(psoc, &mlme_cfg->qos_mlme_params);
	mlme_init_rates_in_cfg(psoc, &mlme_cfg->rates);
	mlme_init_dfs_cfg(psoc, &mlme_cfg->dfs_cfg);
	mlme_init_passive_enable_in_cfg(psoc, mlme_cfg);
	mlme_init_sap_protection_cfg(psoc, &mlme_cfg->sap_protection_cfg);
	mlme_init_vht_cap_cfg(psoc, &mlme_cfg->vht_caps.vht_cap_info);
	mlme_init_chainmask_cfg(psoc, &mlme_cfg->chainmask_cfg);
	mlme_init_sap_cfg(psoc, &mlme_cfg->sap_cfg);
	mlme_init_nss_chains(psoc, &mlme_cfg->nss_chains_ini_cfg);
	mlme_init_twt_cfg(psoc, &mlme_cfg->twt_cfg);
	mlme_init_he_cap_in_cfg(psoc, mlme_cfg);
	mlme_init_eht_cap_in_cfg(psoc, mlme_cfg);
	mlme_init_obss_ht40_cfg(psoc, &mlme_cfg->obss_ht40);
	mlme_init_product_details_cfg(&mlme_cfg->product_details);
	mlme_init_powersave_params(psoc, &mlme_cfg->ps_params);
	mlme_init_sta_cfg(psoc, &mlme_cfg->sta);
	mlme_init_stats_cfg(psoc, &mlme_cfg->stats);
	mlme_init_lfr_cfg(psoc, &mlme_cfg->lfr);
	mlme_init_feature_flag_in_cfg(psoc, &mlme_cfg->feature_flags);
	mlme_init_roam_scoring_cfg(psoc, &mlme_cfg->roam_scoring);
	mlme_init_dot11_mode_cfg(psoc, &mlme_cfg->dot11_mode);
	mlme_init_threshold_cfg(psoc, &mlme_cfg->threshold);
	mlme_init_acs_cfg(psoc, &mlme_cfg->acs);
	mlme_init_power_cfg(psoc, &mlme_cfg->power);
	mlme_init_oce_cfg(psoc, &mlme_cfg->oce);
	mlme_init_wep_cfg(&mlme_cfg->wep_params);
	mlme_init_wifi_pos_cfg(psoc, &mlme_cfg->wifi_pos_cfg);
	mlme_init_wps_params_cfg(psoc, &mlme_cfg->wps_params);
	mlme_init_fe_wlm_in_cfg(psoc, &mlme_cfg->wlm_config);
	mlme_init_fe_rrm_in_cfg(psoc, &mlme_cfg->rrm_config);
	mlme_init_mwc_cfg(psoc, &mlme_cfg->mwc);
	mlme_init_reg_cfg(psoc, &mlme_cfg->reg);
	mlme_init_btm_cfg(psoc, &mlme_cfg->btm);
	mlme_init_roam_score_config(psoc, mlme_cfg);
	mlme_init_ratemask_cfg(psoc, &mlme_cfg->ratemask_cfg);
	mlme_init_iot_cfg(psoc, &mlme_cfg->iot);
	mlme_init_dual_sta_config(&mlme_cfg->gen);
	mlme_init_user_mcc_quota_config(&mlme_cfg->gen);

	return status;
}

struct sae_auth_retry *mlme_get_sae_auth_retry(struct wlan_objmgr_vdev *vdev)
{
	struct mlme_legacy_priv *mlme_priv;

	mlme_priv = wlan_vdev_mlme_get_ext_hdl(vdev);
	if (!mlme_priv) {
		mlme_legacy_err("vdev legacy private object is NULL");
		return NULL;
	}

	return &mlme_priv->sae_retry;
}

void mlme_free_sae_auth_retry(struct wlan_objmgr_vdev *vdev)
{
	struct mlme_legacy_priv *mlme_priv;

	mlme_priv = wlan_vdev_mlme_get_ext_hdl(vdev);
	if (!mlme_priv) {
		mlme_legacy_err("vdev legacy private object is NULL");
		return;
	}

	mlme_priv->sae_retry.sae_auth_max_retry = 0;
	if (mlme_priv->sae_retry.sae_auth.ptr)
		qdf_mem_free(mlme_priv->sae_retry.sae_auth.ptr);
	mlme_priv->sae_retry.sae_auth.ptr = NULL;
	mlme_priv->sae_retry.sae_auth.len = 0;
}

void mlme_set_self_disconnect_ies(struct wlan_objmgr_vdev *vdev,
				  struct element_info *ie)
{
	struct mlme_legacy_priv *mlme_priv;

	if (!ie || !ie->len || !ie->ptr) {
		mlme_legacy_debug("disocnnect IEs are NULL");
		return;
	}

	mlme_priv = wlan_vdev_mlme_get_ext_hdl(vdev);
	if (!mlme_priv) {
		mlme_legacy_err("vdev legacy private object is NULL");
		return;
	}

	if (mlme_priv->disconnect_info.self_discon_ies.ptr) {
		qdf_mem_free(mlme_priv->disconnect_info.self_discon_ies.ptr);
		mlme_priv->disconnect_info.self_discon_ies.len = 0;
	}

	mlme_priv->disconnect_info.self_discon_ies.ptr =
				qdf_mem_malloc(ie->len);
	if (!mlme_priv->disconnect_info.self_discon_ies.ptr)
		return;

	qdf_mem_copy(mlme_priv->disconnect_info.self_discon_ies.ptr,
		     ie->ptr, ie->len);
	mlme_priv->disconnect_info.self_discon_ies.len = ie->len;

	mlme_legacy_debug("Self disconnect IEs");
	QDF_TRACE_HEX_DUMP(QDF_MODULE_ID_MLME, QDF_TRACE_LEVEL_DEBUG,
			   mlme_priv->disconnect_info.self_discon_ies.ptr,
			   mlme_priv->disconnect_info.self_discon_ies.len);
}

void mlme_free_self_disconnect_ies(struct wlan_objmgr_vdev *vdev)
{
	struct mlme_legacy_priv *mlme_priv;

	mlme_priv = wlan_vdev_mlme_get_ext_hdl(vdev);
	if (!mlme_priv) {
		mlme_legacy_err("vdev legacy private object is NULL");
		return;
	}

	if (mlme_priv->disconnect_info.self_discon_ies.ptr) {
		qdf_mem_free(mlme_priv->disconnect_info.self_discon_ies.ptr);
		mlme_priv->disconnect_info.self_discon_ies.ptr = NULL;
		mlme_priv->disconnect_info.self_discon_ies.len = 0;
	}
}

struct element_info *mlme_get_self_disconnect_ies(struct wlan_objmgr_vdev *vdev)
{
	struct mlme_legacy_priv *mlme_priv;

	mlme_priv = wlan_vdev_mlme_get_ext_hdl(vdev);
	if (!mlme_priv) {
		mlme_legacy_err("vdev legacy private object is NULL");
		return NULL;
	}

	return &mlme_priv->disconnect_info.self_discon_ies;
}

void mlme_set_peer_disconnect_ies(struct wlan_objmgr_vdev *vdev,
				  struct element_info *ie)
{
	struct mlme_legacy_priv *mlme_priv;

	if (!ie || !ie->len || !ie->ptr) {
		mlme_legacy_debug("disocnnect IEs are NULL");
		return;
	}

	mlme_priv = wlan_vdev_mlme_get_ext_hdl(vdev);
	if (!mlme_priv) {
		mlme_legacy_err("vdev legacy private object is NULL");
		return;
	}

	if (mlme_priv->disconnect_info.peer_discon_ies.ptr) {
		qdf_mem_free(mlme_priv->disconnect_info.peer_discon_ies.ptr);
		mlme_priv->disconnect_info.peer_discon_ies.len = 0;
	}

	mlme_priv->disconnect_info.peer_discon_ies.ptr =
					qdf_mem_malloc(ie->len);
	if (!mlme_priv->disconnect_info.peer_discon_ies.ptr)
		return;

	qdf_mem_copy(mlme_priv->disconnect_info.peer_discon_ies.ptr,
		     ie->ptr, ie->len);
	mlme_priv->disconnect_info.peer_discon_ies.len = ie->len;

	mlme_legacy_debug("peer disconnect IEs");
	QDF_TRACE_HEX_DUMP(QDF_MODULE_ID_MLME, QDF_TRACE_LEVEL_DEBUG,
			   mlme_priv->disconnect_info.peer_discon_ies.ptr,
			   mlme_priv->disconnect_info.peer_discon_ies.len);
}

void mlme_free_peer_disconnect_ies(struct wlan_objmgr_vdev *vdev)
{
	struct mlme_legacy_priv *mlme_priv;

	mlme_priv = wlan_vdev_mlme_get_ext_hdl(vdev);
	if (!mlme_priv) {
		mlme_legacy_err("vdev legacy private object is NULL");
		return;
	}

	if (mlme_priv->disconnect_info.peer_discon_ies.ptr) {
		qdf_mem_free(mlme_priv->disconnect_info.peer_discon_ies.ptr);
		mlme_priv->disconnect_info.peer_discon_ies.ptr = NULL;
		mlme_priv->disconnect_info.peer_discon_ies.len = 0;
	}
}

struct element_info *mlme_get_peer_disconnect_ies(struct wlan_objmgr_vdev *vdev)
{
	struct mlme_legacy_priv *mlme_priv;

	mlme_priv = wlan_vdev_mlme_get_ext_hdl(vdev);
	if (!mlme_priv) {
		mlme_legacy_err("vdev legacy private object is NULL");
		return NULL;
	}

	return &mlme_priv->disconnect_info.peer_discon_ies;
}

void mlme_free_peer_assoc_rsp_ie(struct peer_mlme_priv_obj *peer_priv)
{
	if (!peer_priv) {
		mlme_legacy_debug("peer priv is NULL");
		return;
	}

	if (peer_priv->assoc_rsp.ptr) {
		qdf_mem_free(peer_priv->assoc_rsp.ptr);
		peer_priv->assoc_rsp.ptr = NULL;
		peer_priv->assoc_rsp.len = 0;
	}
}

void mlme_set_peer_assoc_rsp_ie(struct wlan_objmgr_psoc *psoc,
				uint8_t *peer_addr, struct element_info *ie)
{
	struct wlan_objmgr_peer *peer;
	struct peer_mlme_priv_obj *peer_priv;

	if (!ie || !ie->len || !ie->ptr || !peer_addr) {
		mlme_legacy_debug("Assoc IE is NULL");
		return;
	}

	peer = wlan_objmgr_get_peer_by_mac(psoc, peer_addr, WLAN_LEGACY_MAC_ID);
	if (!peer)
		return;

	peer_priv = wlan_objmgr_peer_get_comp_private_obj(peer,
							  WLAN_UMAC_COMP_MLME);

	if (!peer_priv)
		goto end;

	/* Free existing assoc_rsp */
	mlme_free_peer_assoc_rsp_ie(peer_priv);

	peer_priv->assoc_rsp.ptr = qdf_mem_malloc(ie->len);
	if (!peer_priv->assoc_rsp.ptr)
		goto end;

	qdf_mem_copy(peer_priv->assoc_rsp.ptr, ie->ptr, ie->len);
	peer_priv->assoc_rsp.len = ie->len;
end:
	wlan_objmgr_peer_release_ref(peer, WLAN_LEGACY_MAC_ID);
}

void mlme_set_follow_ap_edca_flag(struct wlan_objmgr_vdev *vdev, bool flag)
{
	struct mlme_legacy_priv *mlme_priv;

	mlme_priv = wlan_vdev_mlme_get_ext_hdl(vdev);
	if (!mlme_priv) {
		mlme_legacy_err("vdev legacy private object is NULL");
		return;
	}

	mlme_priv->follow_ap_edca = flag;
}

bool mlme_get_follow_ap_edca_flag(struct wlan_objmgr_vdev *vdev)
{
	struct mlme_legacy_priv *mlme_priv;

	mlme_priv = wlan_vdev_mlme_get_ext_hdl(vdev);
	if (!mlme_priv) {
		mlme_legacy_err("vdev legacy private object is NULL");
		return false;
	}

	return mlme_priv->follow_ap_edca;
}

void mlme_set_best_6g_power_type(struct wlan_objmgr_vdev *vdev,
				 enum reg_6g_ap_type best_6g_power_type)
{
	struct mlme_legacy_priv *mlme_priv;

	mlme_priv = wlan_vdev_mlme_get_ext_hdl(vdev);
	if (!mlme_priv) {
		mlme_legacy_err("vdev legacy private object is NULL");
		return;
	}

	mlme_priv->best_6g_power_type = best_6g_power_type;
}

enum reg_6g_ap_type mlme_get_best_6g_power_type(struct wlan_objmgr_vdev *vdev)
{
	struct mlme_legacy_priv *mlme_priv;

	mlme_priv = wlan_vdev_mlme_get_ext_hdl(vdev);
	if (!mlme_priv) {
		mlme_legacy_err("vdev legacy private object is NULL");
		return REG_VERY_LOW_POWER_AP;
	}

	return mlme_priv->best_6g_power_type;
}

void mlme_set_reconn_after_assoc_timeout_flag(struct wlan_objmgr_psoc *psoc,
					      uint8_t vdev_id, bool flag)
{
	struct wlan_objmgr_vdev *vdev;
	struct mlme_legacy_priv *mlme_priv;

	if (!psoc)
		return;

	vdev = wlan_objmgr_get_vdev_by_id_from_psoc(psoc, vdev_id,
						    WLAN_LEGACY_MAC_ID);
	if (!vdev)
		return;
	mlme_priv = wlan_vdev_mlme_get_ext_hdl(vdev);
	if (!mlme_priv) {
		mlme_legacy_err("vdev legacy private object is NULL");
		wlan_objmgr_vdev_release_ref(vdev, WLAN_LEGACY_MAC_ID);
		return;
	}

	mlme_priv->reconn_after_assoc_timeout = flag;
	wlan_objmgr_vdev_release_ref(vdev, WLAN_LEGACY_MAC_ID);
}

bool mlme_get_reconn_after_assoc_timeout_flag(struct wlan_objmgr_psoc *psoc,
					      uint8_t vdev_id)
{
	struct wlan_objmgr_vdev *vdev;
	struct mlme_legacy_priv *mlme_priv;
	bool reconn_after_assoc_timeout;

	if (!psoc)
		return false;

	vdev = wlan_objmgr_get_vdev_by_id_from_psoc(psoc, vdev_id,
						    WLAN_LEGACY_MAC_ID);
	if (!vdev)
		return false;
	mlme_priv = wlan_vdev_mlme_get_ext_hdl(vdev);
	if (!mlme_priv) {
		mlme_legacy_err("vdev legacy private object is NULL");
		wlan_objmgr_vdev_release_ref(vdev, WLAN_LEGACY_MAC_ID);
		return false;
	}

	reconn_after_assoc_timeout = mlme_priv->reconn_after_assoc_timeout;
	wlan_objmgr_vdev_release_ref(vdev, WLAN_LEGACY_MAC_ID);

	return reconn_after_assoc_timeout;
}

void mlme_set_peer_pmf_status(struct wlan_objmgr_peer *peer,
			      bool is_pmf_enabled)
{
	struct peer_mlme_priv_obj *peer_priv;

	peer_priv = wlan_objmgr_peer_get_comp_private_obj(peer,
							  WLAN_UMAC_COMP_MLME);
	if (!peer_priv) {
		mlme_legacy_err(" peer mlme component object is NULL");
		return;
	}
	peer_priv->is_pmf_enabled = is_pmf_enabled;
}

bool mlme_get_peer_pmf_status(struct wlan_objmgr_peer *peer)
{
	struct peer_mlme_priv_obj *peer_priv;

	peer_priv = wlan_objmgr_peer_get_comp_private_obj(peer,
							  WLAN_UMAC_COMP_MLME);
	if (!peer_priv) {
		mlme_legacy_err("peer mlme component object is NULL");
		return false;
	}

	return peer_priv->is_pmf_enabled;
}

enum QDF_OPMODE wlan_get_opmode_from_vdev_id(struct wlan_objmgr_pdev *pdev,
					     uint8_t vdev_id)
{
	struct wlan_objmgr_vdev *vdev;
	enum QDF_OPMODE opmode = QDF_MAX_NO_OF_MODE;

	if (!pdev)
		return opmode;

	vdev = wlan_objmgr_get_vdev_by_id_from_pdev(pdev, vdev_id,
						    WLAN_LEGACY_MAC_ID);
	if (!vdev)
		return opmode;

	opmode = wlan_vdev_mlme_get_opmode(vdev);
	wlan_objmgr_vdev_release_ref(vdev, WLAN_LEGACY_MAC_ID);

	return opmode;
}

QDF_STATUS wlan_mlme_get_bssid_vdev_id(struct wlan_objmgr_pdev *pdev,
				       uint8_t vdev_id,
				       struct qdf_mac_addr *bss_peer_mac)
{
	struct wlan_objmgr_vdev *vdev;
	QDF_STATUS status;

	if (!pdev)
		return QDF_STATUS_E_INVAL;

	vdev = wlan_objmgr_get_vdev_by_id_from_pdev(pdev, vdev_id,
						    WLAN_LEGACY_MAC_ID);
	if (!vdev)
		return QDF_STATUS_E_INVAL;

	status = wlan_vdev_get_bss_peer_mac(vdev, bss_peer_mac);
	wlan_objmgr_vdev_release_ref(vdev, WLAN_LEGACY_MAC_ID);

	return status;
}

qdf_freq_t wlan_get_operation_chan_freq(struct wlan_objmgr_vdev *vdev)
{
	qdf_freq_t chan_freq = 0;
	struct wlan_channel *chan;

	if (!vdev)
		return chan_freq;

	chan = wlan_vdev_get_active_channel(vdev);
	if (chan)
		chan_freq = chan->ch_freq;

	return chan_freq;
}

qdf_freq_t wlan_get_operation_chan_freq_vdev_id(struct wlan_objmgr_pdev *pdev,
						uint8_t vdev_id)
{
	qdf_freq_t chan_freq = 0;
	struct wlan_objmgr_vdev *vdev;

	if (!pdev)
		return chan_freq;

	vdev = wlan_objmgr_get_vdev_by_id_from_pdev(pdev, vdev_id,
						    WLAN_LEGACY_MAC_ID);
	if (!vdev)
		return chan_freq;
	chan_freq = wlan_get_operation_chan_freq(vdev);
	wlan_objmgr_vdev_release_ref(vdev, WLAN_LEGACY_MAC_ID);

	return chan_freq;
}

void wlan_vdev_set_dot11mode(struct wlan_mlme_cfg *mac_mlme_cfg,
			     enum QDF_OPMODE device_mode,
			     struct vdev_mlme_obj *vdev_mlme)
{
	uint8_t dot11_mode_indx;
	uint8_t *mld_addr;
	enum mlme_vdev_dot11_mode vdev_dot11_mode;
	uint32_t mac_dot11_mode =
			mac_mlme_cfg->dot11_mode.vdev_type_dot11_mode;

	switch (device_mode) {
	default:
	case QDF_STA_MODE:
		dot11_mode_indx = STA_DOT11_MODE_INDX;
		break;
	case QDF_P2P_CLIENT_MODE:
	case QDF_P2P_DEVICE_MODE:
		dot11_mode_indx = P2P_DEV_DOT11_MODE_INDX;
		break;
	case QDF_TDLS_MODE:
		dot11_mode_indx = TDLS_DOT11_MODE_INDX;
		break;
	case QDF_NAN_DISC_MODE:
		dot11_mode_indx = NAN_DISC_DOT11_MODE_INDX;
		break;
	case QDF_NDI_MODE:
		dot11_mode_indx = NDI_DOT11_MODE_INDX;
		break;
	case QDF_OCB_MODE:
		dot11_mode_indx = OCB_DOT11_MODE_INDX;
		break;
	}

	vdev_dot11_mode = QDF_GET_BITS(mac_dot11_mode, dot11_mode_indx, 4);
	if ((device_mode != QDF_NAN_DISC_MODE && device_mode != QDF_NDI_MODE) &&
	    (vdev_dot11_mode == MLME_VDEV_DOT11_MODE_AUTO ||
	     vdev_dot11_mode == MLME_VDEV_DOT11_MODE_11BE)) {
		mld_addr = wlan_vdev_mlme_get_mldaddr(vdev_mlme->vdev);
		if (qdf_is_macaddr_zero((struct qdf_mac_addr *)mld_addr)) {
			vdev_dot11_mode = MLME_VDEV_DOT11_MODE_11AX;
			vdev_mlme->proto.vdev_dot11_mode = vdev_dot11_mode;
		}
	}
	mlme_debug("vdev%d: dot11_mode %d", wlan_vdev_get_id(vdev_mlme->vdev),
		   vdev_dot11_mode);
}

bool wlan_is_open_wep_cipher(struct wlan_objmgr_pdev *pdev, uint8_t vdev_id)
{
	struct wlan_objmgr_vdev *vdev;
	int32_t ucast_cipher;
	bool is_open_wep = false;

	if (!pdev)
		return is_open_wep;

	vdev = wlan_objmgr_get_vdev_by_id_from_pdev(pdev, vdev_id,
						    WLAN_LEGACY_MAC_ID);
	if (!vdev)
		return is_open_wep;
	ucast_cipher = wlan_crypto_get_param(vdev,
					     WLAN_CRYPTO_PARAM_UCAST_CIPHER);
	if (!ucast_cipher ||
	    ((QDF_HAS_PARAM(ucast_cipher, WLAN_CRYPTO_CIPHER_NONE) ==
	      ucast_cipher)) ||
	      QDF_HAS_PARAM(ucast_cipher, WLAN_CRYPTO_CIPHER_WEP) ||
	      QDF_HAS_PARAM(ucast_cipher, WLAN_CRYPTO_CIPHER_WEP_40) ||
	      QDF_HAS_PARAM(ucast_cipher,  WLAN_CRYPTO_CIPHER_WEP_104))
		is_open_wep = true;
	wlan_objmgr_vdev_release_ref(vdev, WLAN_LEGACY_MAC_ID);

	return is_open_wep;
}

bool wlan_vdev_is_open_mode(struct wlan_objmgr_vdev *vdev)
{
	int32_t ucast_cipher;

	ucast_cipher = wlan_crypto_get_param(vdev,
					     WLAN_CRYPTO_PARAM_UCAST_CIPHER);
	if (!ucast_cipher ||
	    ((QDF_HAS_PARAM(ucast_cipher, WLAN_CRYPTO_CIPHER_NONE) ==
	      ucast_cipher)))
		return true;

	return false;
}

bool wlan_vdev_id_is_open_cipher(struct wlan_objmgr_pdev *pdev, uint8_t vdev_id)
{
	struct wlan_objmgr_vdev *vdev;
	bool is_open = false;

	if (!pdev)
		return is_open;

	vdev = wlan_objmgr_get_vdev_by_id_from_pdev(pdev, vdev_id,
						    WLAN_LEGACY_MAC_ID);
	if (!vdev)
		return is_open;
	is_open = wlan_vdev_is_open_mode(vdev);
	wlan_objmgr_vdev_release_ref(vdev, WLAN_LEGACY_MAC_ID);

	return is_open;
}

bool wlan_vdev_id_is_11n_allowed(struct wlan_objmgr_pdev *pdev, uint8_t vdev_id)
{
	struct wlan_objmgr_vdev *vdev;
	bool is_11n_allowed = true;
	int32_t ucast_cipher;

	if (!pdev)
		return is_11n_allowed;

	vdev = wlan_objmgr_get_vdev_by_id_from_pdev(pdev, vdev_id,
						    WLAN_LEGACY_MAC_ID);
	if (!vdev)
		return is_11n_allowed;
	ucast_cipher = wlan_crypto_get_param(vdev,
					     WLAN_CRYPTO_PARAM_UCAST_CIPHER);

	if (ucast_cipher == -1)
		goto err;
	if (QDF_HAS_PARAM(ucast_cipher, WLAN_CRYPTO_CIPHER_TKIP) ||
	    QDF_HAS_PARAM(ucast_cipher, WLAN_CRYPTO_CIPHER_WEP) ||
	    QDF_HAS_PARAM(ucast_cipher, WLAN_CRYPTO_CIPHER_WEP_40) ||
	    QDF_HAS_PARAM(ucast_cipher, WLAN_CRYPTO_CIPHER_WEP_104)) {
		QDF_CLEAR_PARAM(ucast_cipher, WLAN_CRYPTO_CIPHER_TKIP);
		QDF_CLEAR_PARAM(ucast_cipher, WLAN_CRYPTO_CIPHER_WEP);
		QDF_CLEAR_PARAM(ucast_cipher, WLAN_CRYPTO_CIPHER_WEP_40);
		QDF_CLEAR_PARAM(ucast_cipher, WLAN_CRYPTO_CIPHER_WEP_104);
		if (!ucast_cipher)
			is_11n_allowed = false;
	}
err:
	wlan_objmgr_vdev_release_ref(vdev, WLAN_LEGACY_MAC_ID);

	return is_11n_allowed;
}


bool wlan_is_vdev_id_up(struct wlan_objmgr_pdev *pdev, uint8_t vdev_id)
{
	struct wlan_objmgr_vdev *vdev;
	bool is_up = false;

	if (!pdev)
		return is_up;

	vdev = wlan_objmgr_get_vdev_by_id_from_pdev(pdev, vdev_id,
						    WLAN_LEGACY_MAC_ID);
	if (vdev) {
		is_up = QDF_IS_STATUS_SUCCESS(wlan_vdev_is_up(vdev));
		wlan_objmgr_vdev_release_ref(vdev, WLAN_LEGACY_MAC_ID);
	}

	return is_up;
}


QDF_STATUS
wlan_get_op_chan_freq_info_vdev_id(struct wlan_objmgr_pdev *pdev,
				   uint8_t vdev_id, qdf_freq_t *op_freq,
				   qdf_freq_t *freq_seg_0,
				   enum phy_ch_width *ch_width)
{
	struct wlan_objmgr_vdev *vdev;
	struct wlan_channel *chan;
	QDF_STATUS status = QDF_STATUS_E_INVAL;

	*op_freq = 0;
	*freq_seg_0 = 0;
	*ch_width = 0;

	if (!pdev)
		return QDF_STATUS_E_INVAL;

	vdev = wlan_objmgr_get_vdev_by_id_from_pdev(pdev, vdev_id,
						    WLAN_LEGACY_MAC_ID);
	if (!vdev)
		goto rel_ref;
	if (wlan_vdev_mlme_is_active(vdev) != QDF_STATUS_SUCCESS)
		goto rel_ref;
	chan = wlan_vdev_get_active_channel(vdev);
	if (!chan)
		goto rel_ref;

	/* If operating mode is STA / P2P-CLI then get the channel width
	 * from phymode. This is due the reason where actual operating
	 * channel width is configured as part of WMI_PEER_ASSOC_CMDID
	 * which could be downgraded while the peer associated.
	 * If there is a failure or operating mode is not STA / P2P-CLI
	 * then get channel width from wlan_channel.
	 */
	status = wlan_mlme_get_sta_ch_width(vdev, ch_width);
	if (QDF_IS_STATUS_ERROR(status))
		*ch_width = chan->ch_width;

	*op_freq = chan->ch_freq;
	*freq_seg_0 = chan->ch_cfreq1;
	status = QDF_STATUS_SUCCESS;

rel_ref:
	wlan_objmgr_vdev_release_ref(vdev, WLAN_LEGACY_MAC_ID);

	return status;
}

QDF_STATUS wlan_strip_ie(uint8_t *addn_ie, uint16_t *addn_ielen,
			 uint8_t eid, enum size_of_len_field size_of_len_field,
			 uint8_t *oui, uint8_t oui_length,
			 uint8_t *extracted_ie, uint32_t eid_max_len)
{
	uint8_t *tmp_buf = NULL;
	uint16_t tmp_len = 0;
	int left = *addn_ielen;
	uint8_t *ptr = addn_ie;
	uint8_t elem_id;
	uint16_t elem_len, ie_len, extracted_ie_len = 0;

	if (!addn_ie) {
		mlme_debug("NULL addn_ie pointer");
		return QDF_STATUS_E_INVAL;
	}
	if (!left)
		return QDF_STATUS_E_INVAL;

	tmp_buf = qdf_mem_malloc(left);
	if (!tmp_buf)
		return QDF_STATUS_E_NOMEM;

	if (extracted_ie)
		qdf_mem_zero(extracted_ie, eid_max_len + size_of_len_field + 1);

	while (left >= 2) {
		elem_id  = ptr[0];
		left -= 1;
		if (size_of_len_field == TWO_BYTE) {
			elem_len = *((uint16_t *)&ptr[1]);
			left -= 2;
		} else {
			elem_len = ptr[1];
			left -= 1;
		}
		if (elem_len > left) {
			mlme_err("Invalid IEs eid: %d elem_len: %d left: %d",
				 elem_id, elem_len, left);
			qdf_mem_free(tmp_buf);
			return QDF_STATUS_E_FAILURE;
		}

		if (eid != elem_id ||
				(oui && qdf_mem_cmp(oui,
						&ptr[size_of_len_field + 1],
						oui_length))) {
			qdf_mem_copy(tmp_buf + tmp_len, &ptr[0],
				     elem_len + size_of_len_field + 1);
			tmp_len += (elem_len + size_of_len_field + 1);
		} else {
			/*
			 * eid matched and if provided OUI also matched
			 * take oui IE and store in provided buffer.
			 */
			if (extracted_ie) {
				ie_len = elem_len + size_of_len_field + 1;
				if (ie_len <= eid_max_len - extracted_ie_len) {
					qdf_mem_copy(
					extracted_ie + extracted_ie_len,
					&ptr[0], ie_len);
					extracted_ie_len += ie_len;
				}
			}
		}
		left -= elem_len;
		ptr += (elem_len + size_of_len_field + 1);
	}
	qdf_mem_copy(addn_ie, tmp_buf, tmp_len);

	*addn_ielen = tmp_len;
	qdf_mem_free(tmp_buf);

	return QDF_STATUS_SUCCESS;
}

bool wlan_is_channel_present_in_list(qdf_freq_t *freq_lst,
				     uint32_t num_chan, qdf_freq_t chan_freq)
{
	int i = 0;

	/* Check for NULL pointer */
	if (!freq_lst || (num_chan == 0))
		return false;

	/* Look for the channel in the list */
	for (i = 0; (i < num_chan) && (i < CFG_VALID_CHANNEL_LIST_LEN); i++) {
		if (freq_lst[i] == chan_freq)
			return true;
	}

	return false;
}

bool wlan_roam_is_channel_valid(struct wlan_mlme_reg *reg, qdf_freq_t chan_freq)
{
	bool valid = false;
	uint32_t i;
	uint32_t len = reg->valid_channel_list_num;

	for (i = 0; (i < len); i++) {
		if (wlan_reg_is_dsrc_freq(
			reg->valid_channel_freq_list[i]))
			continue;

		if (chan_freq == reg->valid_channel_freq_list[i]) {
			valid = true;
			break;
		}
	}

	return valid;
}

int8_t wlan_get_cfg_max_tx_power(struct wlan_objmgr_psoc *psoc,
				 struct wlan_objmgr_pdev *pdev,
				 uint32_t ch_freq)
{
	uint32_t cfg_length = 0;
	int8_t max_tx_pwr = 0;
	struct pwr_channel_info *country_info = NULL;
	uint8_t count = 0;
	uint8_t maxChannels;
	int32_t rem_length = 0;
	struct wlan_mlme_psoc_ext_obj *mlme_obj;

	mlme_obj = mlme_get_psoc_ext_obj(psoc);
	if (!mlme_obj)
		return max_tx_pwr;

	if (WLAN_REG_IS_5GHZ_CH_FREQ(ch_freq)) {
		cfg_length = mlme_obj->cfg.power.max_tx_power_5.len;
	} else if (WLAN_REG_IS_24GHZ_CH_FREQ(ch_freq)) {
		cfg_length = mlme_obj->cfg.power.max_tx_power_24.len;

	} else if (wlan_reg_is_6ghz_chan_freq(ch_freq)) {
		return wlan_reg_get_channel_reg_power_for_freq(pdev,
							       ch_freq);
	} else {
		return max_tx_pwr;
	}

	if (!cfg_length)
		goto error;

	country_info = qdf_mem_malloc(cfg_length);
	if (!country_info)
		goto error;

	if (WLAN_REG_IS_5GHZ_CH_FREQ(ch_freq)) {
		if (cfg_length > CFG_MAX_TX_POWER_5_LEN)
			goto error;
		qdf_mem_copy(country_info,
			     mlme_obj->cfg.power.max_tx_power_5.data,
			     cfg_length);
	} else if (WLAN_REG_IS_24GHZ_CH_FREQ(ch_freq)) {
		if (cfg_length > CFG_MAX_TX_POWER_2_4_LEN)
			goto error;
		qdf_mem_copy(country_info,
			     mlme_obj->cfg.power.max_tx_power_24.data,
			     cfg_length);
	}

	/* Identify the channel and maxtxpower */
	rem_length = cfg_length;
	while (rem_length >= (sizeof(struct pwr_channel_info))) {
		maxChannels = country_info[count].num_chan;
		max_tx_pwr = country_info[count].max_tx_pwr;
		count++;
		rem_length -= (sizeof(struct pwr_channel_info));

		if (ch_freq >= country_info[count].first_freq &&
		    ch_freq < (country_info[count].first_freq + maxChannels)) {
			break;
		}
	}

error:
	if (country_info)
		qdf_mem_free(country_info);

	return max_tx_pwr;
}

#if defined(WLAN_FEATURE_HOST_ROAM) || defined(WLAN_FEATURE_ROAM_OFFLOAD)
static
const char *mlme_roam_state_to_string(enum roam_offload_state state)
{
	switch (state) {
	case WLAN_ROAM_INIT:
		return "ROAM_INIT";
	case WLAN_ROAM_DEINIT:
		return "ROAM_DEINIT";
	case WLAN_ROAM_RSO_ENABLED:
		return "ROAM_RSO_ENABLED";
	case WLAN_ROAM_RSO_STOPPED:
		return "ROAM_RSO_STOPPED";
	case WLAN_ROAMING_IN_PROG:
		return "ROAMING_IN_PROG";
	case WLAN_ROAM_SYNCH_IN_PROG:
		return "ROAM_SYNCH_IN_PROG";
	case WLAN_MLO_ROAM_SYNCH_IN_PROG:
		return "MLO_ROAM_SYNCH_IN_PROG";
	default:
		return "";
	}
}

static void
mlme_print_roaming_state(uint8_t vdev_id, enum roam_offload_state cur_state,
			 enum roam_offload_state new_state)
{
	mlme_nofl_debug("CM_RSO: vdev%d: [%s(%d)] --> [%s(%d)]",
			vdev_id, mlme_roam_state_to_string(cur_state),
			cur_state,
			mlme_roam_state_to_string(new_state), new_state);

	/* TODO: Try to print the state change requestor also */
}

bool
mlme_get_supplicant_disabled_roaming(struct wlan_objmgr_psoc *psoc,
				     uint8_t vdev_id)
{
	struct wlan_objmgr_vdev *vdev;
	struct mlme_legacy_priv *mlme_priv;
	bool value;

	vdev = wlan_objmgr_get_vdev_by_id_from_psoc(psoc, vdev_id,
						    WLAN_MLME_OBJMGR_ID);

	if (!vdev) {
		mlme_legacy_err("vdev object is NULL");
		return 0;
	}

	mlme_priv = wlan_vdev_mlme_get_ext_hdl(vdev);
	if (!mlme_priv) {
		mlme_legacy_err("vdev legacy private object is NULL");
		wlan_objmgr_vdev_release_ref(vdev, WLAN_MLME_OBJMGR_ID);
		return 0;
	}

	value = mlme_priv->mlme_roam.roam_cfg.supplicant_disabled_roaming;
	wlan_objmgr_vdev_release_ref(vdev, WLAN_MLME_OBJMGR_ID);

	return value;
}

void mlme_set_supplicant_disabled_roaming(struct wlan_objmgr_psoc *psoc,
					  uint8_t vdev_id, bool val)
{
	struct wlan_objmgr_vdev *vdev;
	struct mlme_legacy_priv *mlme_priv;

	vdev = wlan_objmgr_get_vdev_by_id_from_psoc(psoc, vdev_id,
						    WLAN_MLME_OBJMGR_ID);

	if (!vdev) {
		mlme_legacy_err("vdev object is NULL");
		return;
	}

	mlme_priv = wlan_vdev_mlme_get_ext_hdl(vdev);
	if (!mlme_priv) {
		mlme_legacy_err("vdev legacy private object is NULL");
		wlan_objmgr_vdev_release_ref(vdev, WLAN_MLME_OBJMGR_ID);
		return;
	}

	mlme_priv->mlme_roam.roam_cfg.supplicant_disabled_roaming = val;
	wlan_objmgr_vdev_release_ref(vdev, WLAN_MLME_OBJMGR_ID);
}

uint32_t
mlme_get_roam_trigger_bitmap(struct wlan_objmgr_psoc *psoc, uint8_t vdev_id)
{
	struct wlan_objmgr_vdev *vdev;
	struct mlme_legacy_priv *mlme_priv;
	uint32_t roam_bitmap;

	vdev = wlan_objmgr_get_vdev_by_id_from_psoc(psoc, vdev_id,
						    WLAN_MLME_OBJMGR_ID);

	if (!vdev) {
		mlme_legacy_err("vdev object is NULL");
		return 0;
	}

	mlme_priv = wlan_vdev_mlme_get_ext_hdl(vdev);
	if (!mlme_priv) {
		mlme_legacy_err("vdev legacy private object is NULL");
		wlan_objmgr_vdev_release_ref(vdev, WLAN_MLME_OBJMGR_ID);
		return 0;
	}

	roam_bitmap = mlme_priv->mlme_roam.roam_cfg.roam_trigger_bitmap;
	wlan_objmgr_vdev_release_ref(vdev, WLAN_MLME_OBJMGR_ID);

	return roam_bitmap;
}

void mlme_set_roam_trigger_bitmap(struct wlan_objmgr_psoc *psoc,
				  uint8_t vdev_id, uint32_t val)
{
	struct wlan_objmgr_vdev *vdev;
	struct mlme_legacy_priv *mlme_priv;

	vdev = wlan_objmgr_get_vdev_by_id_from_psoc(psoc, vdev_id,
						    WLAN_MLME_OBJMGR_ID);
	if (!vdev) {
		mlme_legacy_err("vdev object is NULL");
		return;
	}

	mlme_priv = wlan_vdev_mlme_get_ext_hdl(vdev);
	if (!mlme_priv) {
		mlme_legacy_err("vdev legacy private object is NULL");
		wlan_objmgr_vdev_release_ref(vdev, WLAN_MLME_OBJMGR_ID);
		return;
	}

	mlme_priv->mlme_roam.roam_cfg.roam_trigger_bitmap = val;
	wlan_objmgr_vdev_release_ref(vdev, WLAN_MLME_OBJMGR_ID);
}

uint8_t
mlme_get_operations_bitmap(struct wlan_objmgr_psoc *psoc, uint8_t vdev_id)
{
	struct wlan_objmgr_vdev *vdev;
	struct mlme_legacy_priv *mlme_priv;
	uint8_t bitmap;

	vdev = wlan_objmgr_get_vdev_by_id_from_psoc(psoc, vdev_id,
						    WLAN_MLME_OBJMGR_ID);

	if (!vdev) {
		mlme_legacy_err("vdev object is NULL");
		return 0xFF;
	}

	mlme_priv = wlan_vdev_mlme_get_ext_hdl(vdev);
	if (!mlme_priv) {
		mlme_legacy_err("vdev legacy private object is NULL");
		wlan_objmgr_vdev_release_ref(vdev, WLAN_MLME_OBJMGR_ID);
		return 0xFF;
	}

	bitmap = mlme_priv->mlme_roam.roam_sm.mlme_operations_bitmap;
	mlme_legacy_debug("vdev[%d] bitmap[0x%x]", vdev_id,
			  mlme_priv->mlme_roam.roam_sm.mlme_operations_bitmap);
	wlan_objmgr_vdev_release_ref(vdev, WLAN_MLME_OBJMGR_ID);

	return bitmap;
}

void
mlme_set_operations_bitmap(struct wlan_objmgr_psoc *psoc, uint8_t vdev_id,
			   enum wlan_cm_rso_control_requestor reqs, bool clear)
{
	struct wlan_objmgr_vdev *vdev;
	struct mlme_legacy_priv *mlme_priv;

	vdev = wlan_objmgr_get_vdev_by_id_from_psoc(psoc, vdev_id,
						    WLAN_MLME_OBJMGR_ID);
	if (!vdev) {
		mlme_legacy_err("vdev object is NULL");
		return;
	}

	mlme_priv = wlan_vdev_mlme_get_ext_hdl(vdev);
	if (!mlme_priv) {
		mlme_legacy_err("vdev legacy private object is NULL");
		wlan_objmgr_vdev_release_ref(vdev, WLAN_MLME_OBJMGR_ID);
		return;
	}

	if (clear)
		mlme_priv->mlme_roam.roam_sm.mlme_operations_bitmap &= ~reqs;
	else
		mlme_priv->mlme_roam.roam_sm.mlme_operations_bitmap |= reqs;

	mlme_legacy_debug("vdev[%d] bitmap[0x%x], reqs: %d, clear: %d", vdev_id,
			  mlme_priv->mlme_roam.roam_sm.mlme_operations_bitmap,
			  reqs, clear);
	wlan_objmgr_vdev_release_ref(vdev, WLAN_MLME_OBJMGR_ID);
}

void
mlme_clear_operations_bitmap(struct wlan_objmgr_psoc *psoc, uint8_t vdev_id)
{
	struct wlan_objmgr_vdev *vdev;
	struct mlme_legacy_priv *mlme_priv;

	vdev = wlan_objmgr_get_vdev_by_id_from_psoc(psoc, vdev_id,
						    WLAN_MLME_OBJMGR_ID);
	if (!vdev) {
		mlme_legacy_err("vdev object is NULL");
		return;
	}

	mlme_priv = wlan_vdev_mlme_get_ext_hdl(vdev);
	if (!mlme_priv) {
		mlme_legacy_err("vdev legacy private object is NULL");
		wlan_objmgr_vdev_release_ref(vdev, WLAN_MLME_OBJMGR_ID);
		return;
	}

	mlme_priv->mlme_roam.roam_sm.mlme_operations_bitmap = 0;
	wlan_objmgr_vdev_release_ref(vdev, WLAN_MLME_OBJMGR_ID);
}

QDF_STATUS mlme_get_cfg_wlm_level(struct wlan_objmgr_psoc *psoc,
				  uint8_t *level)
{
	struct wlan_mlme_psoc_ext_obj *mlme_obj;

	mlme_obj = mlme_get_psoc_ext_obj(psoc);
	if (!mlme_obj)
		return QDF_STATUS_E_FAILURE;

	*level = mlme_obj->cfg.wlm_config.latency_level;

	return QDF_STATUS_SUCCESS;
}

QDF_STATUS mlme_get_cfg_wlm_reset(struct wlan_objmgr_psoc *psoc,
				  bool *reset)
{
	struct wlan_mlme_psoc_ext_obj *mlme_obj;

	mlme_obj = mlme_get_psoc_ext_obj(psoc);
	if (!mlme_obj)
		return QDF_STATUS_E_FAILURE;

	*reset = mlme_obj->cfg.wlm_config.latency_reset;

	return QDF_STATUS_SUCCESS;
}

enum roam_offload_state
mlme_get_roam_state(struct wlan_objmgr_psoc *psoc, uint8_t vdev_id)
{
	struct wlan_objmgr_vdev *vdev;
	struct mlme_legacy_priv *mlme_priv;
	enum roam_offload_state roam_state;

	vdev = wlan_objmgr_get_vdev_by_id_from_psoc(psoc, vdev_id,
						    WLAN_MLME_OBJMGR_ID);

	if (!vdev)
		return WLAN_ROAM_DEINIT;

	mlme_priv = wlan_vdev_mlme_get_ext_hdl(vdev);
	if (!mlme_priv) {
		mlme_legacy_err("vdev legacy private object is NULL");
		wlan_objmgr_vdev_release_ref(vdev, WLAN_MLME_OBJMGR_ID);
		return WLAN_ROAM_DEINIT;
	}

	roam_state = mlme_priv->mlme_roam.roam_sm.state;
	wlan_objmgr_vdev_release_ref(vdev, WLAN_MLME_OBJMGR_ID);

	return roam_state;
}

void mlme_set_roam_state(struct wlan_objmgr_psoc *psoc, uint8_t vdev_id,
			 enum roam_offload_state new_state)
{
	struct wlan_objmgr_vdev *vdev;
	struct mlme_legacy_priv *mlme_priv;

	vdev = wlan_objmgr_get_vdev_by_id_from_psoc(psoc, vdev_id,
						    WLAN_MLME_OBJMGR_ID);

	if (!vdev) {
		mlme_err("vdev%d: vdev object is NULL", vdev_id);
		return;
	}

	mlme_priv = wlan_vdev_mlme_get_ext_hdl(vdev);
	if (!mlme_priv) {
		mlme_err("vdev%d: vdev legacy private object is NULL", vdev_id);
		wlan_objmgr_vdev_release_ref(vdev, WLAN_MLME_OBJMGR_ID);
		return;
	}

	mlme_print_roaming_state(vdev_id, mlme_priv->mlme_roam.roam_sm.state,
				 new_state);
	mlme_priv->mlme_roam.roam_sm.state = new_state;
	wlan_objmgr_vdev_release_ref(vdev, WLAN_MLME_OBJMGR_ID);
}

QDF_STATUS
mlme_store_fw_scan_channels(struct wlan_objmgr_psoc *psoc,
			    tSirUpdateChanList *chan_list)
{
	struct wlan_mlme_psoc_ext_obj *mlme_obj;
	struct wlan_mlme_lfr_cfg *lfr;
	uint16_t i;

	mlme_obj = mlme_get_psoc_ext_obj(psoc);
	if (!mlme_obj) {
		mlme_legacy_err("Failed to get MLME Obj");
		return QDF_STATUS_E_FAILURE;
	}

	lfr = &mlme_obj->cfg.lfr;
	qdf_mem_zero(&lfr->saved_freq_list, sizeof(lfr->saved_freq_list));
	lfr->saved_freq_list.num_channels = chan_list->numChan;
	for (i = 0; i < chan_list->numChan; i++)
		lfr->saved_freq_list.freq[i] = chan_list->chanParam[i].freq;

	mlme_legacy_debug("ROAM: save %d channels",
			  chan_list->numChan);

	return QDF_STATUS_SUCCESS;
}

QDF_STATUS mlme_get_fw_scan_channels(struct wlan_objmgr_psoc *psoc,
				     uint32_t *freq_list,
				     uint8_t *saved_num_chan)
{
	struct wlan_mlme_psoc_ext_obj *mlme_obj;
	struct wlan_mlme_lfr_cfg *lfr;
	uint16_t i;

	if (!freq_list) {
		mlme_legacy_err("ROAM: Freq list is NULL");
		*saved_num_chan = 0;
		return QDF_STATUS_E_FAILURE;
	}

	mlme_obj = mlme_get_psoc_ext_obj(psoc);
	if (!mlme_obj) {
		mlme_legacy_err("Failed to get MLME Obj");
		*saved_num_chan = 0;
		return QDF_STATUS_E_FAILURE;
	}

	lfr = &mlme_obj->cfg.lfr;
	*saved_num_chan = lfr->saved_freq_list.num_channels;

	for (i = 0; i < lfr->saved_freq_list.num_channels; i++)
		freq_list[i] = lfr->saved_freq_list.freq[i];

	return QDF_STATUS_SUCCESS;
}
#endif

QDF_STATUS wlan_mlme_get_mac_vdev_id(struct wlan_objmgr_pdev *pdev,
				     uint8_t vdev_id,
				     struct qdf_mac_addr *self_mac)
{
	struct wlan_objmgr_vdev *vdev;

	if (!pdev)
		return QDF_STATUS_E_INVAL;

	vdev = wlan_objmgr_get_vdev_by_id_from_pdev(pdev, vdev_id,
						    WLAN_LEGACY_MAC_ID);
	if (!vdev)
		return QDF_STATUS_E_INVAL;

	qdf_mem_copy(self_mac->bytes,
		     wlan_vdev_mlme_get_macaddr(vdev), QDF_MAC_ADDR_SIZE);
	wlan_objmgr_vdev_release_ref(vdev, WLAN_LEGACY_MAC_ID);

	return QDF_STATUS_SUCCESS;
}

qdf_freq_t
wlan_get_sap_user_config_freq(struct wlan_objmgr_vdev *vdev)
{
	struct mlme_legacy_priv *mlme_priv;
	enum QDF_OPMODE opmode = QDF_MAX_NO_OF_MODE;

	mlme_priv = wlan_vdev_mlme_get_ext_hdl(vdev);
	if (!mlme_priv) {
		mlme_legacy_err("vdev legacy private object is NULL");
		return 0;
	}

	opmode = wlan_vdev_mlme_get_opmode(vdev);
	if (opmode != QDF_SAP_MODE && opmode != QDF_P2P_GO_MODE) {
		mlme_debug("Cannot get user config freq for mode %d", opmode);
		return 0;
	}

	return mlme_priv->mlme_ap.user_config_sap_ch_freq;
}

QDF_STATUS
wlan_set_sap_user_config_freq(struct wlan_objmgr_vdev *vdev,
			      qdf_freq_t freq)
{
	struct mlme_legacy_priv *mlme_priv;
	enum QDF_OPMODE opmode = QDF_MAX_NO_OF_MODE;

	mlme_priv = wlan_vdev_mlme_get_ext_hdl(vdev);
	if (!mlme_priv) {
		mlme_legacy_err("vdev legacy private object is NULL");
		return QDF_STATUS_E_INVAL;
	}

	opmode = wlan_vdev_mlme_get_opmode(vdev);
	if (opmode != QDF_SAP_MODE && opmode != QDF_P2P_GO_MODE) {
		mlme_debug("Cannot set user config freq for mode %d", opmode);
		return QDF_STATUS_E_FAILURE;
	}

	mlme_priv->mlme_ap.user_config_sap_ch_freq = freq;
	return QDF_STATUS_SUCCESS;
}

#ifdef CONFIG_BAND_6GHZ
bool
wlan_get_tpc_update_required_for_sta(struct wlan_objmgr_vdev *vdev)
{
	struct mlme_legacy_priv *mlme_priv;
	enum QDF_OPMODE opmode;

	mlme_priv = wlan_vdev_mlme_get_ext_hdl(vdev);
	if (!mlme_priv) {
		mlme_legacy_err("vdev legacy private object is NULL");
		return false;
	}

	opmode = wlan_vdev_mlme_get_opmode(vdev);
	if (opmode != QDF_SAP_MODE && opmode != QDF_P2P_GO_MODE) {
		mlme_debug("Invalid opmode %d", opmode);
		return false;
	}

	return mlme_priv->mlme_ap.update_required_scc_sta_power;
}

QDF_STATUS
wlan_set_tpc_update_required_for_sta(struct wlan_objmgr_vdev *vdev, bool value)
{
	struct mlme_legacy_priv *mlme_priv;
	enum QDF_OPMODE opmode;

	mlme_priv = wlan_vdev_mlme_get_ext_hdl(vdev);
	if (!mlme_priv) {
		mlme_legacy_err("vdev legacy private object is NULL");
		return QDF_STATUS_E_INVAL;
	}

	opmode = wlan_vdev_mlme_get_opmode(vdev);
	if (opmode != QDF_SAP_MODE && opmode != QDF_P2P_GO_MODE) {
		mlme_debug("Invalid mode %d", opmode);
		QDF_ASSERT(0);
		return QDF_STATUS_E_FAILURE;
	}

	mlme_priv->mlme_ap.update_required_scc_sta_power = value;
	mlme_debug("Set change scc power as %d", value);
	return QDF_STATUS_SUCCESS;
}
#endif

QDF_STATUS wlan_mlme_get_sta_num_tx_chains(struct wlan_objmgr_psoc *psoc,
					   struct wlan_objmgr_vdev *vdev,
					   uint8_t *tx_chains)
{
	bool dynamic_nss_chains_support;
	struct wlan_mlme_nss_chains *dynamic_cfg;
	enum band_info operating_band;
	QDF_STATUS status;
	struct vdev_mlme_obj *vdev_mlme;

	status = wlan_mlme_cfg_get_dynamic_nss_chains_support
					(psoc, &dynamic_nss_chains_support);
	if (QDF_IS_STATUS_ERROR(status)) {
		mlme_err("Failed to get dynamic_nss_chains_support");
		return QDF_STATUS_E_INVAL;
	}

	vdev_mlme =
		wlan_objmgr_vdev_get_comp_private_obj(vdev,
						      WLAN_UMAC_COMP_MLME);
	if (!vdev_mlme) {
		QDF_ASSERT(0);
		return false;
	}

	if (dynamic_nss_chains_support) {
		dynamic_cfg = mlme_get_dynamic_vdev_config(vdev);
		if (!dynamic_cfg) {
			mlme_err("nss chain dynamic config NULL");
			return QDF_STATUS_E_INVAL;
		}

		operating_band = ucfg_cm_get_connected_band(vdev);
		switch (operating_band) {
		case BAND_2G:
			*tx_chains =
			dynamic_cfg->num_tx_chains[NSS_CHAINS_BAND_2GHZ];
			break;
		case BAND_5G:
			*tx_chains =
			dynamic_cfg->num_tx_chains[NSS_CHAINS_BAND_5GHZ];
			break;
		default:
			mlme_err("Band %d Not 2G or 5G", operating_band);
			return QDF_STATUS_E_INVAL;
		}
	}

	return QDF_STATUS_SUCCESS;
}

QDF_STATUS wlan_mlme_get_sta_tx_nss(struct wlan_objmgr_psoc *psoc,
				    struct wlan_objmgr_vdev *vdev,
				    uint8_t *tx_nss)
{
	uint8_t proto_generic_nss;
	bool dynamic_nss_chains_support;
	struct wlan_mlme_nss_chains *dynamic_cfg;
	enum band_info operating_band;
	QDF_STATUS status;

	status = wlan_mlme_cfg_get_dynamic_nss_chains_support
					(psoc, &dynamic_nss_chains_support);
	if (QDF_IS_STATUS_ERROR(status)) {
		mlme_err("Failed to get dynamic_nss_chains_support");
		return QDF_STATUS_E_INVAL;
	}

	proto_generic_nss = wlan_vdev_mlme_get_nss(vdev);
	if (dynamic_nss_chains_support) {
		dynamic_cfg = mlme_get_dynamic_vdev_config(vdev);
		if (!dynamic_cfg) {
			mlme_err("nss chain dynamic config NULL");
			return QDF_STATUS_E_INVAL;
		}

		operating_band = ucfg_cm_get_connected_band(vdev);
		switch (operating_band) {
		case BAND_2G:
			*tx_nss = dynamic_cfg->tx_nss[NSS_CHAINS_BAND_2GHZ];
			break;
		case BAND_5G:
			*tx_nss = dynamic_cfg->tx_nss[NSS_CHAINS_BAND_5GHZ];
			break;
		default:
			mlme_err("Band %d Not 2G or 5G", operating_band);
			return QDF_STATUS_E_INVAL;
		}

		if (*tx_nss > proto_generic_nss)
			*tx_nss = proto_generic_nss;
	} else {
		*tx_nss = proto_generic_nss;
	}

	return QDF_STATUS_SUCCESS;
}

QDF_STATUS wlan_mlme_get_sta_num_rx_chains(struct wlan_objmgr_psoc *psoc,
					   struct wlan_objmgr_vdev *vdev,
					   uint8_t *rx_chains)
{
	bool dynamic_nss_chains_support;
	struct wlan_mlme_nss_chains *dynamic_cfg;
	enum band_info operating_band;
	QDF_STATUS status;
	struct vdev_mlme_obj *vdev_mlme;

	status = wlan_mlme_cfg_get_dynamic_nss_chains_support
					(psoc, &dynamic_nss_chains_support);
	if (QDF_IS_STATUS_ERROR(status)) {
		mlme_err("Failed to get dynamic_nss_chains_support");
		return QDF_STATUS_E_INVAL;
	}
	vdev_mlme =
		wlan_objmgr_vdev_get_comp_private_obj(vdev,
						      WLAN_UMAC_COMP_MLME);
	if (!vdev_mlme) {
		QDF_ASSERT(0);
		return false;
	}

	if (dynamic_nss_chains_support) {
		dynamic_cfg = mlme_get_dynamic_vdev_config(vdev);
		if (!dynamic_cfg) {
			mlme_err("nss chain dynamic config NULL");
			return QDF_STATUS_E_INVAL;
		}

		operating_band = ucfg_cm_get_connected_band(vdev);
		switch (operating_band) {
		case BAND_2G:
			*rx_chains =
			dynamic_cfg->num_rx_chains[NSS_CHAINS_BAND_2GHZ];
			break;
		case BAND_5G:
			*rx_chains =
			dynamic_cfg->num_rx_chains[NSS_CHAINS_BAND_5GHZ];
			break;
		default:
			mlme_err("Band %d Not 2G or 5G", operating_band);
			return QDF_STATUS_E_INVAL;
		}
	}

	return QDF_STATUS_SUCCESS;
}

QDF_STATUS wlan_mlme_get_sta_rx_nss(struct wlan_objmgr_psoc *psoc,
				    struct wlan_objmgr_vdev *vdev,
				    uint8_t *rx_nss)
{
	uint8_t proto_generic_nss;
	bool dynamic_nss_chains_support;
	struct wlan_mlme_nss_chains *dynamic_cfg;
	enum band_info operating_band;
	QDF_STATUS status;

	status = wlan_mlme_cfg_get_dynamic_nss_chains_support
					(psoc, &dynamic_nss_chains_support);
	if (QDF_IS_STATUS_ERROR(status)) {
		mlme_err("Failed to get dynamic_nss_chains_support");
		return QDF_STATUS_E_INVAL;
	}

	proto_generic_nss = wlan_vdev_mlme_get_nss(vdev);
	if (dynamic_nss_chains_support) {
		dynamic_cfg = mlme_get_dynamic_vdev_config(vdev);
		if (!dynamic_cfg) {
			mlme_err("nss chain dynamic config NULL");
			return QDF_STATUS_E_INVAL;
		}

		operating_band = ucfg_cm_get_connected_band(vdev);
		switch (operating_band) {
		case BAND_2G:
			*rx_nss = dynamic_cfg->rx_nss[NSS_CHAINS_BAND_2GHZ];
			break;
		case BAND_5G:
			*rx_nss = dynamic_cfg->rx_nss[NSS_CHAINS_BAND_5GHZ];
			break;
		default:
			mlme_err("Band %d Not 2G or 5G", operating_band);
			return QDF_STATUS_E_INVAL;
		}

		if (*rx_nss > proto_generic_nss)
			*rx_nss = proto_generic_nss;
	} else {
		*rx_nss = proto_generic_nss;
	}

	return QDF_STATUS_SUCCESS;
}

#ifdef WLAN_FEATURE_ROAM_OFFLOAD
QDF_STATUS
wmi_extract_peer_oper_mode_event(wmi_unified_t wmi_handle,
				 uint8_t *event,
				 uint32_t len,
				 struct peer_oper_mode_event *data)
{
	if (wmi_handle->ops->extract_peer_oper_mode_event)
		return wmi_handle->ops->extract_peer_oper_mode_event(wmi_handle,
								     event,
								     len, data);
	return QDF_STATUS_E_FAILURE;
}

int mlme_peer_oper_mode_change_event_handler(ol_scn_t scn,
					      uint8_t *event,
					      uint32_t len)
{
	struct wlan_objmgr_psoc *psoc;
	struct wmi_unified *wmi_handle;
	struct peer_oper_mode_event data = {0};
	struct wlan_mlme_rx_ops *mlme_rx_ops;
	QDF_STATUS qdf_status;

	psoc = target_if_get_psoc_from_scn_hdl(scn);
	if (!psoc) {
		target_if_err("psoc is null");
		return -EINVAL;
	}

	wmi_handle = get_wmi_unified_hdl_from_psoc(psoc);
	if (!wmi_handle) {
		mlme_err("wmi_handle is null");
		return -EINVAL;
	}

	qdf_status = wmi_extract_peer_oper_mode_event(wmi_handle, event,
						      len, &data);
	if (QDF_IS_STATUS_ERROR(qdf_status)) {
		mlme_err("parsing of event failed, %d", qdf_status);
		return -EINVAL;
	}

	mlme_rx_ops = mlme_get_rx_ops(psoc);
	if (!mlme_rx_ops || !mlme_rx_ops->peer_oper_mode_eventid) {
		mlme_err("No valid roam rx ops");
		return -EINVAL;
	}

	qdf_status = mlme_rx_ops->peer_oper_mode_eventid(psoc, &data);
	if (QDF_IS_STATUS_ERROR(qdf_status)) {
		mlme_err("peer_oper_mode_change_event Failed");
		return -EINVAL;
	}

	return QDF_STATUS_SUCCESS;
}

QDF_STATUS wlan_mlme_register_common_events(struct wlan_objmgr_psoc *psoc)
{
	QDF_STATUS ret;
	wmi_unified_t handle = get_wmi_unified_hdl_from_psoc(psoc);

	if (!handle) {
		mlme_err("handle is NULL");
		return QDF_STATUS_E_FAILURE;
	}

	/* Register for peer operating mode change devent */
	ret = wmi_unified_register_event_handler(handle,
				wmi_peer_oper_mode_change_event_id,
				mlme_peer_oper_mode_change_event_handler,
				WMI_RX_SERIALIZER_CTX);
	if (QDF_IS_STATUS_ERROR(ret)) {
		mlme_err("wmi event(%u) registration failed, ret: %d",
			      wmi_peer_oper_mode_change_event_id, ret);
		return QDF_STATUS_E_FAILURE;
	}
	return QDF_STATUS_SUCCESS;
}
#endif

QDF_STATUS
wlan_mlme_send_csa_event_status_ind_cmd(struct wlan_objmgr_vdev *vdev,
					uint8_t csa_status)
{
	struct wlan_objmgr_psoc *psoc;
	struct  wlan_mlme_tx_ops *tx_ops;
	mlme_psoc_ext_t *mlme_priv;

	psoc = wlan_vdev_get_psoc(vdev);
	if (!psoc) {
		mlme_err("vdev_id %d psoc object is NULL",
			 wlan_vdev_get_id(vdev));
		return QDF_STATUS_E_FAILURE;
	}

	mlme_priv = wlan_psoc_mlme_get_ext_hdl(psoc);
	if (!mlme_priv)
		return QDF_STATUS_E_FAILURE;

	tx_ops = &mlme_priv->mlme_tx_ops;

	if (!tx_ops || !tx_ops->send_csa_event_status_ind) {
		mlme_err("CSA no op defined");
		return QDF_STATUS_E_FAILURE;
	}

	return tx_ops->send_csa_event_status_ind(vdev, csa_status);
}

