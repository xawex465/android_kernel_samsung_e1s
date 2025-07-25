/*
 * Copyright (c) 2018-2021 The Linux Foundation. All rights reserved.
 * Copyright (c) 2022-2024 Qualcomm Innovation Center, Inc. All rights reserved.
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
 * DOC: define UCFG APIs exposed by the mlme component
 */

#include "cfg_ucfg_api.h"
#include "cfg_mlme_sta.h"
#include "wlan_mlme_main.h"
#include "wlan_mlme_api.h"
#include "wlan_mlme_ucfg_api.h"
#include "wlan_objmgr_pdev_obj.h"
#include "wlan_mlme_vdev_mgr_interface.h"
#include <include/wlan_pdev_mlme.h>
#include "wlan_pdev_mlme_api.h"
#include "wlan_vdev_mgr_tgt_if_tx_api.h"
#include "wlan_policy_mgr_public_struct.h"
#include "spatial_reuse_api.h"

QDF_STATUS ucfg_mlme_global_init(void)
{
	mlme_register_mlme_ext_ops();

	return QDF_STATUS_SUCCESS;
}

QDF_STATUS ucfg_mlme_global_deinit(void)
{
	return QDF_STATUS_SUCCESS;
}

QDF_STATUS ucfg_mlme_init(void)
{
	QDF_STATUS status;

	status = wlan_objmgr_register_peer_create_handler(
			WLAN_UMAC_COMP_MLME,
			mlme_peer_object_created_notification,
			NULL);
	if (QDF_IS_STATUS_ERROR(status)) {
		mlme_legacy_err("peer create register notification failed");
		return QDF_STATUS_E_FAILURE;
	}

	status = wlan_objmgr_register_peer_destroy_handler(
			WLAN_UMAC_COMP_MLME,
			mlme_peer_object_destroyed_notification,
			NULL);
	if (QDF_IS_STATUS_ERROR(status)) {
		mlme_legacy_err("peer destroy register notification failed");
		return QDF_STATUS_E_FAILURE;
	}

	mlme_register_mlo_ext_ops();
	return status;
}

QDF_STATUS ucfg_mlme_deinit(void)
{
	QDF_STATUS status;

	mlme_unregister_mlo_ext_ops();
	status = wlan_objmgr_unregister_peer_destroy_handler(
			WLAN_UMAC_COMP_MLME,
			mlme_peer_object_destroyed_notification,
			NULL);
	if (QDF_IS_STATUS_ERROR(status))
		mlme_legacy_err("unable to unregister peer destroy handle");

	status = wlan_objmgr_unregister_peer_create_handler(
			WLAN_UMAC_COMP_MLME,
			mlme_peer_object_created_notification,
			NULL);
	if (QDF_IS_STATUS_ERROR(status))
		mlme_legacy_err("unable to unregister peer create handle");

	return status;
}

QDF_STATUS ucfg_mlme_psoc_open(struct wlan_objmgr_psoc *psoc)
{
	QDF_STATUS status;

	status = mlme_cfg_on_psoc_enable(psoc);
	if (!QDF_IS_STATUS_SUCCESS(status))
		mlme_legacy_err("Failed to initialize MLME CFG");

	return status;
}

void ucfg_mlme_psoc_close(struct wlan_objmgr_psoc *psoc)
{
	/* Clear the MLME CFG Structure */
}

QDF_STATUS ucfg_mlme_pdev_open(struct wlan_objmgr_pdev *pdev)
{
	struct pdev_mlme_obj *pdev_mlme;

	pdev_mlme = wlan_pdev_mlme_get_cmpt_obj(pdev);
	if (!pdev_mlme) {
		mlme_legacy_err(" PDEV MLME is NULL");
		return QDF_STATUS_E_FAILURE;
	}
	pdev_mlme->mlme_register_ops = mlme_register_vdev_mgr_ops;

	return QDF_STATUS_SUCCESS;
}

QDF_STATUS ucfg_mlme_pdev_close(struct wlan_objmgr_pdev *pdev)
{
	return QDF_STATUS_SUCCESS;
}

void ucfg_mlme_set_ml_link_control_mode(struct wlan_objmgr_psoc *psoc,
					uint8_t vdev_id, uint8_t value)
{
	wlan_mlme_set_ml_link_control_mode(psoc, vdev_id, value);
}

void ucfg_mlme_set_bt_profile_con(struct wlan_objmgr_psoc *psoc,
				  bool bt_profile_con)
{
	wlan_mlme_set_bt_profile_con(psoc, bt_profile_con);
}

uint8_t ucfg_mlme_get_ml_link_control_mode(struct wlan_objmgr_psoc *psoc,
					   uint8_t vdev_id)
{
	return wlan_mlme_get_ml_link_control_mode(psoc, vdev_id);
}


/**
 * ucfg_mlme_convert_power_cfg_chan_to_freq() - converts channel numbers to
 * frequencies and copies the triplets to power_freq_data array
 * @pdev: pointer to pdev object
 * @max_length: Max length of the power chan data array
 * @length: length of the data present in power_chan_data array
 * @power_chan_data: Power data array from which channel numbers needs to be
 * converted to frequencies
 * @power_freq_data: Power data array in which the power data needs to be copied
 * after conversion of channel numbers to frequencies
 *
 * power_data is received in the form of (first_channel_number,
 * number_of_channels, max_tx_power) triplet, convert the channel numbers from
 * the power_chan_data array to frequencies and copy the triplets
 * (first_frequency, number_of_channels, max_tx_power) values to
 * the power_freq_data array
 *
 * Return: Number of bytes filled in power_freq_data
 */

static uint32_t ucfg_mlme_convert_power_cfg_chan_to_freq(
						struct wlan_objmgr_pdev *pdev,
						uint32_t max_length,
						qdf_size_t length,
						uint8_t *power_chan_data,
						uint8_t *power_freq_data)
{
	uint32_t count = 0, rem_length = length, copied_length = 0, i = 0;
	struct pwr_channel_info *pwr_cfg_data;

	pwr_cfg_data = qdf_mem_malloc(max_length);
	if (!pwr_cfg_data)
		return 0;

	mlme_legacy_debug("max_length %d length %zu", max_length, length);
	while ((rem_length >= 3) &&
	       (copied_length <= (max_length - (sizeof(struct pwr_channel_info))))) {
		pwr_cfg_data[i].first_freq = wlan_reg_legacy_chan_to_freq(
						pdev,
						power_chan_data[count++]);
		pwr_cfg_data[i].num_chan = power_chan_data[count++];
		pwr_cfg_data[i].max_tx_pwr = power_chan_data[count++];
		copied_length += sizeof(struct pwr_channel_info);
		rem_length -= 3;
		mlme_legacy_debug("First freq %d num channels %d max tx power %d",
				  pwr_cfg_data[i].first_freq,
				  pwr_cfg_data[i].num_chan,
				  pwr_cfg_data[i].max_tx_pwr);
		i++;
	}

	qdf_mem_zero(power_freq_data, max_length);
	qdf_mem_copy(power_freq_data, pwr_cfg_data, copied_length);
	qdf_mem_free(pwr_cfg_data);
	return copied_length;
}

void ucfg_mlme_cfg_chan_to_freq(struct wlan_objmgr_pdev *pdev)
{
	struct wlan_objmgr_psoc *psoc = wlan_pdev_get_psoc(pdev);
	struct wlan_mlme_psoc_ext_obj *mlme_obj;
	struct wlan_mlme_cfg *mlme_cfg;
	uint32_t converted_data_len = 0;

	mlme_obj = mlme_get_psoc_ext_obj(psoc);
	if (!mlme_obj)
		return;

	mlme_cfg = &mlme_obj->cfg;

	mlme_cfg->power.max_tx_power_24.max_len = CFG_MAX_TX_POWER_2_4_LEN;
	converted_data_len = ucfg_mlme_convert_power_cfg_chan_to_freq(
				pdev,
				mlme_cfg->power.max_tx_power_24_chan.max_len,
				mlme_cfg->power.max_tx_power_24_chan.len,
				mlme_cfg->power.max_tx_power_24_chan.data,
				mlme_cfg->power.max_tx_power_24.data);
	if (!converted_data_len) {
		mlme_legacy_err("mlme cfg power 2_4 data chan number to freq failed");
		return;
	}

	mlme_cfg->power.max_tx_power_24.len = converted_data_len;

	mlme_cfg->power.max_tx_power_5.max_len = CFG_MAX_TX_POWER_5_LEN;
	converted_data_len = ucfg_mlme_convert_power_cfg_chan_to_freq(
				pdev,
				mlme_cfg->power.max_tx_power_5_chan.max_len,
				mlme_cfg->power.max_tx_power_5_chan.len,
				mlme_cfg->power.max_tx_power_5_chan.data,
				mlme_cfg->power.max_tx_power_5.data);
	if (!converted_data_len) {
		mlme_legacy_err("mlme cfg power 5 data chan number to freq failed");
		return;
	}
	mlme_cfg->power.max_tx_power_5.len = converted_data_len;
}

QDF_STATUS
ucfg_mlme_get_sta_keep_alive_period(struct wlan_objmgr_psoc *psoc,
				    uint32_t *val)
{
	return wlan_mlme_get_sta_keep_alive_period(psoc, val);
}

QDF_STATUS
ucfg_mlme_get_dfs_master_capability(struct wlan_objmgr_psoc *psoc,
				    bool *val)
{
	struct wlan_mlme_psoc_ext_obj *mlme_obj;

	mlme_obj = mlme_get_psoc_ext_obj(psoc);
	if (!mlme_obj) {
		*val = cfg_default(CFG_ENABLE_DFS_MASTER_CAPABILITY);
		return QDF_STATUS_E_INVAL;
	}

	*val = mlme_obj->cfg.dfs_cfg.dfs_master_capable;

	return QDF_STATUS_SUCCESS;
}

QDF_STATUS
ucfg_mlme_get_oem_6g_supported(struct wlan_objmgr_psoc *psoc,
			       bool *oem_6g_disable)
{
	struct wlan_mlme_psoc_ext_obj *mlme_obj;

	mlme_obj = mlme_get_psoc_ext_obj(psoc);
	if (!mlme_obj) {
		*oem_6g_disable =
			cfg_default(CFG_OEM_SIXG_SUPPORT_DISABLE);
		return QDF_STATUS_E_INVAL;
	}

	*oem_6g_disable = mlme_obj->cfg.wifi_pos_cfg.oem_6g_support_disable;

	return QDF_STATUS_SUCCESS;
}

QDF_STATUS
ucfg_mlme_get_fine_time_meas_cap(struct wlan_objmgr_psoc *psoc,
				 uint32_t *fine_time_meas_cap)
{
	struct wlan_mlme_psoc_ext_obj *mlme_obj;

	mlme_obj = mlme_get_psoc_ext_obj(psoc);
	if (!mlme_obj) {
		*fine_time_meas_cap =
			cfg_default(CFG_FINE_TIME_MEAS_CAPABILITY);
		return QDF_STATUS_E_INVAL;
	}

	*fine_time_meas_cap = mlme_obj->cfg.wifi_pos_cfg.fine_time_meas_cap;

	return QDF_STATUS_SUCCESS;
}

QDF_STATUS
ucfg_mlme_set_fine_time_meas_cap(struct wlan_objmgr_psoc *psoc,
				 uint32_t fine_time_meas_cap)
{
	struct wlan_mlme_psoc_ext_obj *mlme_obj;

	mlme_obj = mlme_get_psoc_ext_obj(psoc);
	if (!mlme_obj)
		return QDF_STATUS_E_INVAL;

	mlme_obj->cfg.wifi_pos_cfg.fine_time_meas_cap = fine_time_meas_cap;

	return QDF_STATUS_SUCCESS;
}

static QDF_STATUS
ucfg_mlme_set_vdev_traffic_type(struct wlan_objmgr_psoc *psoc,
				struct wlan_objmgr_vdev *vdev, bool set,
				uint8_t bit_mask)
{
	struct mlme_legacy_priv *mlme_priv;
	struct vdev_mlme_obj *vdev_mlme;
	struct vdev_set_params param = {0};
	enum QDF_OPMODE mode;
	QDF_STATUS status;
	uint8_t vdev_id = wlan_vdev_get_id(vdev);
	uint8_t prev_traffic_type;

	mode = wlan_vdev_mlme_get_opmode(vdev);
	if (mode != QDF_SAP_MODE && mode != QDF_P2P_CLIENT_MODE &&
	    mode != QDF_P2P_GO_MODE) {
		mlme_legacy_debug("vdev %d: not supported for opmode %d",
				  vdev_id, mode);
		return QDF_STATUS_E_NOSUPPORT;
	}

	vdev_mlme = wlan_vdev_mlme_get_cmpt_obj(vdev);
	if (!vdev_mlme) {
		mlme_legacy_err("vdev %d: bit_mask 0x%x, set %d, vdev mlme is null",
				vdev_id, bit_mask, set);
		return QDF_STATUS_E_FAILURE;
	}
	mlme_priv = wlan_vdev_mlme_get_ext_hdl(vdev);
	if (!mlme_priv) {
		mlme_legacy_err("vdev %d: bit_mask 0x%x, set %d, vmlme_priv is null",
				vdev_id, bit_mask, set);
		return QDF_STATUS_E_FAILURE;
	}
	prev_traffic_type = mlme_priv->vdev_traffic_type;
	if (set)
		mlme_priv->vdev_traffic_type |= bit_mask;
	else
		mlme_priv->vdev_traffic_type &= ~bit_mask;

	if (prev_traffic_type == mlme_priv->vdev_traffic_type) {
		mlme_legacy_debug("vdev %d: No change in value 0x%x, set %d mask 0x%x",
				  vdev_id, mlme_priv->vdev_traffic_type, set,
				  bit_mask);
		return QDF_STATUS_SUCCESS;
	}
	mlme_legacy_debug("vdev %d: vdev_traffic_type 0x%x (set %d with bit_mask 0x%x)",
			  vdev_id, mlme_priv->vdev_traffic_type, set, bit_mask);
	param.param_id = wmi_vdev_param_set_traffic_config;
	param.vdev_id = vdev_id;
	param.param_value = mlme_priv->vdev_traffic_type;
	status = tgt_vdev_mgr_set_param_send(vdev_mlme, &param);
	policy_mgr_handle_ml_sta_link_on_traffic_type_change(psoc, vdev);

	return status;
}

QDF_STATUS ucfg_mlme_connected_chan_stats_request(struct wlan_objmgr_psoc *psoc,
						  uint8_t vdev_id)
{
	return mlme_connected_chan_stats_request(psoc, vdev_id);
}

bool
ucfg_mlme_is_chwidth_with_notify_supported(struct wlan_objmgr_psoc *psoc)
{
	return wlan_psoc_nif_fw_ext2_cap_get(psoc,
				WLAN_VDEV_PARAM_CHWIDTH_WITH_NOTIFY_SUPPORT);
}

QDF_STATUS ucfg_mlme_update_bss_rate_flags(struct wlan_objmgr_psoc *psoc,
					   uint8_t vdev_id,
					   enum phy_ch_width ch_width,
					   uint8_t eht_present,
					   uint8_t he_present,
					   uint8_t vht_present,
					   uint8_t ht_present)
{
	return wlan_mlme_update_bss_rate_flags(psoc, vdev_id, ch_width,
					       eht_present, he_present,
					       vht_present, ht_present);
}

QDF_STATUS
ucfg_mlme_send_ch_width_update_with_notify(struct wlan_objmgr_psoc *psoc,
					   struct wlan_objmgr_vdev *link_vdev,
					   enum phy_ch_width ch_width,
					   uint8_t link_vdev_id)
{
	QDF_STATUS status = QDF_STATUS_E_FAILURE;

	status = wlan_mlme_send_ch_width_update_with_notify(psoc, link_vdev,
							    link_vdev_id,
							    ch_width);

	return status;
}

QDF_STATUS
ucfg_mlme_set_vdev_wifi_std(struct wlan_objmgr_psoc *psoc, uint8_t vdev_id,
			    WMI_HOST_WIFI_STANDARD wifi_std)
{
	struct wlan_objmgr_vdev *vdev;
	struct mlme_legacy_priv *mlme_priv;

	vdev = wlan_objmgr_get_vdev_by_id_from_psoc(psoc, vdev_id,
						    WLAN_MLME_OBJMGR_ID);
	if (!vdev) {
		mlme_legacy_err("vdev %d: vdev not found",
				vdev_id);
		return QDF_STATUS_E_FAILURE;
	}

	mlme_priv = wlan_vdev_mlme_get_ext_hdl(vdev);
	if (!mlme_priv) {
		mlme_legacy_err("vdev %d: vmlme_priv is null", vdev_id);
		wlan_objmgr_vdev_release_ref(vdev, WLAN_MLME_OBJMGR_ID);
		return QDF_STATUS_E_FAILURE;
	}

	mlme_priv->wifi_std = wifi_std;
	mlme_priv->is_user_std_set = true;

	if (wifi_std < WMI_HOST_WIFI_STANDARD_7)
		wlan_vdev_mlme_set_user_dis_eht_flag(vdev, true);
	else
		wlan_vdev_mlme_set_user_dis_eht_flag(vdev, false);

	wlan_objmgr_vdev_release_ref(vdev, WLAN_MLME_OBJMGR_ID);

	return QDF_STATUS_SUCCESS;
}

QDF_STATUS
ucfg_mlme_set_vdev_traffic_low_latency(struct wlan_objmgr_psoc *psoc,
				       uint8_t vdev_id, bool set)
{
	struct wlan_objmgr_vdev *vdev;
	QDF_STATUS status;

	vdev = wlan_objmgr_get_vdev_by_id_from_psoc(psoc, vdev_id,
						    WLAN_MLME_OBJMGR_ID);
	if (!vdev) {
		mlme_legacy_err("vdev %d: vdev not found",
				vdev_id);
		return QDF_STATUS_E_FAILURE;
	}
	status = ucfg_mlme_set_vdev_traffic_type(psoc, vdev, set,
						 PM_VDEV_TRAFFIC_LOW_LATENCY);
	wlan_objmgr_vdev_release_ref(vdev, WLAN_MLME_OBJMGR_ID);

	return status;
}

QDF_STATUS
ucfg_mlme_set_vdev_traffic_high_throughput(struct wlan_objmgr_psoc *psoc,
					   uint8_t vdev_id, bool set)
{
	struct wlan_objmgr_vdev *vdev;
	QDF_STATUS status;

	vdev = wlan_objmgr_get_vdev_by_id_from_psoc(psoc, vdev_id,
						    WLAN_MLME_OBJMGR_ID);
	if (!vdev) {
		mlme_legacy_err("vdev %d: vdev not found",
				vdev_id);
		return QDF_STATUS_E_FAILURE;
	}
	status = ucfg_mlme_set_vdev_traffic_type(psoc, vdev, set,
						 PM_VDEV_TRAFFIC_HIGH_TPUT);
	wlan_objmgr_vdev_release_ref(vdev, WLAN_MLME_OBJMGR_ID);

	return status;
}

QDF_STATUS
ucfg_mlme_get_dfs_disable_channel_switch(struct wlan_objmgr_psoc *psoc,
					 bool *dfs_disable_channel_switch)
{
	struct wlan_mlme_psoc_ext_obj *mlme_obj;

	mlme_obj = mlme_get_psoc_ext_obj(psoc);
	if (!mlme_obj) {
		*dfs_disable_channel_switch =
			cfg_default(CFG_DISABLE_DFS_CH_SWITCH);
		return QDF_STATUS_E_INVAL;
	}

	*dfs_disable_channel_switch =
		mlme_obj->cfg.dfs_cfg.dfs_disable_channel_switch;

	return QDF_STATUS_SUCCESS;
}

QDF_STATUS
ucfg_mlme_set_dfs_disable_channel_switch(struct wlan_objmgr_psoc *psoc,
					 bool dfs_disable_channel_switch)
{
	struct wlan_mlme_psoc_ext_obj *mlme_obj;

	mlme_obj = mlme_get_psoc_ext_obj(psoc);
	if (!mlme_obj) {
		return QDF_STATUS_E_INVAL;
	}

	mlme_obj->cfg.dfs_cfg.dfs_disable_channel_switch =
		dfs_disable_channel_switch;

	return QDF_STATUS_SUCCESS;
}

QDF_STATUS
ucfg_mlme_get_dfs_ignore_cac(struct wlan_objmgr_psoc *psoc,
			     bool *dfs_ignore_cac)
{
	struct wlan_mlme_psoc_ext_obj *mlme_obj;

	mlme_obj = mlme_get_psoc_ext_obj(psoc);
	if (!mlme_obj) {
		*dfs_ignore_cac = cfg_default(CFG_IGNORE_CAC);
		return QDF_STATUS_E_INVAL;
	}

	*dfs_ignore_cac = mlme_obj->cfg.dfs_cfg.dfs_ignore_cac;

	return QDF_STATUS_SUCCESS;
}

QDF_STATUS
ucfg_mlme_set_dfs_ignore_cac(struct wlan_objmgr_psoc *psoc,
			     bool dfs_ignore_cac)
{
	struct wlan_mlme_psoc_ext_obj *mlme_obj;

	mlme_obj = mlme_get_psoc_ext_obj(psoc);
	if (!mlme_obj)
		return QDF_STATUS_E_INVAL;

	mlme_obj->cfg.dfs_cfg.dfs_ignore_cac = dfs_ignore_cac;

	return QDF_STATUS_SUCCESS;
}

QDF_STATUS
ucfg_mlme_get_sap_tx_leakage_threshold(struct wlan_objmgr_psoc *psoc,
				       uint32_t *sap_tx_leakage_threshold)
{
	struct wlan_mlme_psoc_ext_obj *mlme_obj;

	mlme_obj = mlme_get_psoc_ext_obj(psoc);
	if (!mlme_obj) {
		*sap_tx_leakage_threshold =
			cfg_default(CFG_SAP_TX_LEAKAGE_THRESHOLD);
		return QDF_STATUS_E_INVAL;
	}

	*sap_tx_leakage_threshold =
		mlme_obj->cfg.dfs_cfg.sap_tx_leakage_threshold;

	return QDF_STATUS_SUCCESS;
}

QDF_STATUS
ucfg_mlme_set_sap_tx_leakage_threshold(struct wlan_objmgr_psoc *psoc,
				       uint32_t sap_tx_leakage_threshold)
{
	struct wlan_mlme_psoc_ext_obj *mlme_obj;

	mlme_obj = mlme_get_psoc_ext_obj(psoc);
	if (!mlme_obj)
		return QDF_STATUS_E_INVAL;

	mlme_obj->cfg.dfs_cfg.sap_tx_leakage_threshold =
		sap_tx_leakage_threshold;

	return QDF_STATUS_SUCCESS;
}

QDF_STATUS
ucfg_mlme_get_dfs_pri_multiplier(struct wlan_objmgr_psoc *psoc,
				 uint32_t *dfs_pri_multiplier)
{
	struct wlan_mlme_psoc_ext_obj *mlme_obj;

	mlme_obj = mlme_get_psoc_ext_obj(psoc);
	if (!mlme_obj) {
		*dfs_pri_multiplier =
			cfg_default(CFG_DFS_RADAR_PRI_MULTIPLIER);
		return QDF_STATUS_E_INVAL;
	}

	*dfs_pri_multiplier =
		mlme_obj->cfg.dfs_cfg.dfs_pri_multiplier;

	return QDF_STATUS_SUCCESS;
}

QDF_STATUS
ucfg_mlme_set_dfs_pri_multiplier(struct wlan_objmgr_psoc *psoc,
				 uint32_t dfs_pri_multiplier)
{
	struct wlan_mlme_psoc_ext_obj *mlme_obj;

	mlme_obj = mlme_get_psoc_ext_obj(psoc);
	if (!mlme_obj)
		return QDF_STATUS_E_INVAL;

	mlme_obj->cfg.dfs_cfg.dfs_pri_multiplier =
		dfs_pri_multiplier;

	return QDF_STATUS_SUCCESS;
}

QDF_STATUS
ucfg_mlme_get_dfs_filter_offload(struct wlan_objmgr_psoc *psoc,
				 bool *dfs_filter_offload)
{
	struct wlan_mlme_psoc_ext_obj *mlme_obj;

	mlme_obj = mlme_get_psoc_ext_obj(psoc);
	if (!mlme_obj) {
		*dfs_filter_offload =
			cfg_default(CFG_ENABLE_DFS_PHYERR_FILTEROFFLOAD);
		return QDF_STATUS_E_INVAL;
	}

	*dfs_filter_offload = mlme_obj->cfg.dfs_cfg.dfs_filter_offload;

	return QDF_STATUS_SUCCESS;
}

QDF_STATUS
ucfg_mlme_set_dfs_filter_offload(struct wlan_objmgr_psoc *psoc,
				 bool dfs_filter_offload)
{
	struct wlan_mlme_psoc_ext_obj *mlme_obj;

	mlme_obj = mlme_get_psoc_ext_obj(psoc);
	if (!mlme_obj)
		return QDF_STATUS_E_INVAL;

	mlme_obj->cfg.dfs_cfg.dfs_filter_offload = dfs_filter_offload;

	return QDF_STATUS_SUCCESS;
}

QDF_STATUS
ucfg_mlme_get_pmkid_modes(struct wlan_objmgr_psoc *psoc,
			  uint32_t *val)
{
	struct wlan_mlme_psoc_ext_obj *mlme_obj;

	mlme_obj = mlme_get_psoc_ext_obj(psoc);
	if (!mlme_obj) {
		*val = cfg_default(CFG_PMKID_MODES);
		return QDF_STATUS_E_INVAL;
	}

	*val = mlme_obj->cfg.sta.pmkid_modes;

	return QDF_STATUS_SUCCESS;
}

QDF_STATUS
ucfg_mlme_set_pmkid_modes(struct wlan_objmgr_psoc *psoc,
			  uint32_t val)
{
	struct wlan_mlme_psoc_ext_obj *mlme_obj;

	mlme_obj = mlme_get_psoc_ext_obj(psoc);
	if (!mlme_obj)
		return QDF_STATUS_E_INVAL;

	mlme_obj->cfg.sta.pmkid_modes = val;

	return QDF_STATUS_SUCCESS;
}

QDF_STATUS
ucfg_mlme_get_dot11p_mode(struct wlan_objmgr_psoc *psoc,
			  enum dot11p_mode *out_mode)
{
	struct wlan_mlme_psoc_ext_obj *mlme_obj;

	mlme_obj = mlme_get_psoc_ext_obj(psoc);
	if (!mlme_obj) {
		*out_mode = cfg_default(CFG_DOT11P_MODE);
		return QDF_STATUS_E_INVAL;
	}

	*out_mode = mlme_obj->cfg.sta.dot11p_mode;

	return QDF_STATUS_SUCCESS;
}

QDF_STATUS
ucfg_mlme_get_go_cts2self_for_sta(struct wlan_objmgr_psoc *psoc,
				  bool *val)
{
	struct wlan_mlme_psoc_ext_obj *mlme_obj;

	mlme_obj = mlme_get_psoc_ext_obj(psoc);
	if (!mlme_obj) {
		*val = cfg_default(CFG_ENABLE_GO_CTS2SELF_FOR_STA);
		return QDF_STATUS_E_INVAL;
	}

	*val = mlme_obj->cfg.sta.enable_go_cts2self_for_sta;

	return QDF_STATUS_SUCCESS;
}

QDF_STATUS
ucfg_mlme_get_qcn_ie_support(struct wlan_objmgr_psoc *psoc,
			     bool *val)
{
	struct wlan_mlme_psoc_ext_obj *mlme_obj;

	mlme_obj = mlme_get_psoc_ext_obj(psoc);
	if (!mlme_obj) {
		*val = cfg_default(CFG_QCN_IE_SUPPORT);
		return QDF_STATUS_E_INVAL;
	}

	*val = mlme_obj->cfg.sta.qcn_ie_support;

	return QDF_STATUS_SUCCESS;
}

QDF_STATUS
ucfg_mlme_get_tgt_gtx_usr_cfg(struct wlan_objmgr_psoc *psoc,
			      uint32_t *val)
{
	struct wlan_mlme_psoc_ext_obj *mlme_obj;

	mlme_obj = mlme_get_psoc_ext_obj(psoc);
	if (!mlme_obj) {
		*val = cfg_default(CFG_TGT_GTX_USR_CFG);
		return QDF_STATUS_E_INVAL;
	}

	*val = mlme_obj->cfg.sta.tgt_gtx_usr_cfg;

	return QDF_STATUS_SUCCESS;
}

QDF_STATUS
ucfg_mlme_is_override_ht20_40_24g(struct wlan_objmgr_psoc *psoc, bool *val)
{
	struct wlan_mlme_psoc_ext_obj *mlme_obj;

	mlme_obj = mlme_get_psoc_ext_obj(psoc);
	if (!mlme_obj) {
		*val = cfg_default(CFG_OBSS_HT40_OVERRIDE_HT40_20_24GHZ);
		return QDF_STATUS_E_INVAL;
	}
	*val = mlme_obj->cfg.obss_ht40.is_override_ht20_40_24g;

	return QDF_STATUS_SUCCESS;
}

#ifdef WLAN_FEATURE_ROAM_OFFLOAD
QDF_STATUS
ucfg_mlme_get_roam_disable_config(struct wlan_objmgr_psoc *psoc,
				  uint32_t *val)
{
	struct wlan_mlme_psoc_ext_obj *mlme_obj;

	mlme_obj = mlme_get_psoc_ext_obj(psoc);
	if (!mlme_obj) {
		*val = cfg_default(CFG_STA_DISABLE_ROAM);
		return QDF_STATUS_E_INVAL;
	}

	*val = mlme_obj->cfg.lfr.sta_roam_disable;

	return QDF_STATUS_SUCCESS;
}

QDF_STATUS
ucfg_mlme_get_roaming_offload(struct wlan_objmgr_psoc *psoc,
			      bool *val)
{
	return wlan_mlme_get_roaming_offload(psoc, val);
}

QDF_STATUS
ucfg_mlme_set_roaming_offload(struct wlan_objmgr_psoc *psoc,
			      bool val)
{
	struct wlan_mlme_psoc_ext_obj *mlme_obj;

	mlme_obj = mlme_get_psoc_ext_obj(psoc);
	if (!mlme_obj)
		return QDF_STATUS_E_INVAL;

	mlme_obj->cfg.lfr.lfr3_roaming_offload = val;

	return QDF_STATUS_SUCCESS;
}
#endif

QDF_STATUS
ucfg_mlme_is_mawc_enabled(struct wlan_objmgr_psoc *psoc, bool *val)
{
	struct wlan_mlme_psoc_ext_obj *mlme_obj;

	mlme_obj = mlme_get_psoc_ext_obj(psoc);
	if (!mlme_obj) {
		*val = cfg_default(CFG_LFR_MAWC_FEATURE_ENABLED);
		return QDF_STATUS_E_INVAL;
	}
	*val = mlme_obj->cfg.lfr.mawc_enabled;

	return QDF_STATUS_SUCCESS;
}

QDF_STATUS
ucfg_mlme_set_mawc_enabled(struct wlan_objmgr_psoc *psoc, bool val)
{
	struct wlan_mlme_psoc_ext_obj *mlme_obj;

	mlme_obj = mlme_get_psoc_ext_obj(psoc);
	if (!mlme_obj)
		return QDF_STATUS_E_INVAL;

	mlme_obj->cfg.lfr.mawc_enabled = val;

	return QDF_STATUS_SUCCESS;
}

QDF_STATUS
ucfg_mlme_is_fast_transition_enabled(struct wlan_objmgr_psoc *psoc,
				     bool *val)
{
	struct wlan_mlme_psoc_ext_obj *mlme_obj;

	mlme_obj = mlme_get_psoc_ext_obj(psoc);
	if (!mlme_obj) {
		*val = cfg_default(CFG_LFR_FAST_TRANSITION_ENABLED);
		return QDF_STATUS_E_INVAL;
	}

	*val = mlme_obj->cfg.lfr.fast_transition_enabled;

	return QDF_STATUS_SUCCESS;
}

QDF_STATUS
ucfg_mlme_set_fast_transition_enabled(struct wlan_objmgr_psoc *psoc,
				      bool val)
{
	struct wlan_mlme_psoc_ext_obj *mlme_obj;

	mlme_obj = mlme_get_psoc_ext_obj(psoc);
	if (!mlme_obj)
		return QDF_STATUS_E_INVAL;

	mlme_obj->cfg.lfr.fast_transition_enabled = val;

	return QDF_STATUS_SUCCESS;
}

#ifdef WLAN_ADAPTIVE_11R
QDF_STATUS
ucfg_mlme_set_tgt_adaptive_11r_cap(struct wlan_objmgr_psoc *psoc,
				   bool val)
{
	struct wlan_mlme_psoc_ext_obj *mlme_obj;

	mlme_obj = mlme_get_psoc_ext_obj(psoc);
	if (!mlme_obj)
		return QDF_STATUS_E_INVAL;

	mlme_obj->cfg.lfr.tgt_adaptive_11r_cap = val;

	return QDF_STATUS_SUCCESS;
}

QDF_STATUS
ucfg_mlme_get_adaptive11r_enabled(struct wlan_objmgr_psoc *psoc, bool *val)
{
	struct wlan_mlme_psoc_ext_obj *mlme_obj;

	mlme_obj = mlme_get_psoc_ext_obj(psoc);
	if (!mlme_obj) {
		*val = cfg_default(CFG_ADAPTIVE_11R);
		return QDF_STATUS_E_INVAL;
	}

	*val = mlme_obj->cfg.lfr.enable_adaptive_11r;

	return QDF_STATUS_SUCCESS;
}
#endif

QDF_STATUS
ucfg_mlme_is_roam_scan_offload_enabled(struct wlan_objmgr_psoc *psoc,
				       bool *val)
{
	struct wlan_mlme_psoc_ext_obj *mlme_obj;

	mlme_obj = mlme_get_psoc_ext_obj(psoc);
	if (!mlme_obj) {
		*val = cfg_default(CFG_LFR_ROAM_SCAN_OFFLOAD_ENABLED);
		return QDF_STATUS_E_INVAL;
	}

	*val = mlme_obj->cfg.lfr.roam_scan_offload_enabled;

	return QDF_STATUS_SUCCESS;
}

QDF_STATUS
ucfg_mlme_set_roam_scan_offload_enabled(struct wlan_objmgr_psoc *psoc,
					bool val)
{
	struct wlan_mlme_psoc_ext_obj *mlme_obj;

	mlme_obj = mlme_get_psoc_ext_obj(psoc);
	if (!mlme_obj)
		return QDF_STATUS_E_INVAL;

	mlme_obj->cfg.lfr.roam_scan_offload_enabled = val;

	return QDF_STATUS_SUCCESS;
}

QDF_STATUS
ucfg_mlme_get_neighbor_scan_max_chan_time(struct wlan_objmgr_psoc *psoc,
					  uint16_t *val)
{
	struct wlan_mlme_psoc_ext_obj *mlme_obj;

	mlme_obj = mlme_get_psoc_ext_obj(psoc);
	if (!mlme_obj) {
		*val = cfg_default(CFG_LFR_NEIGHBOR_SCAN_MAX_CHAN_TIME);
		return QDF_STATUS_E_INVAL;
	}

	*val = mlme_obj->cfg.lfr.neighbor_scan_max_chan_time;

	return QDF_STATUS_SUCCESS;
}

QDF_STATUS
ucfg_mlme_get_neighbor_scan_min_chan_time(struct wlan_objmgr_psoc *psoc,
					  uint16_t *val)
{
	struct wlan_mlme_psoc_ext_obj *mlme_obj;

	mlme_obj = mlme_get_psoc_ext_obj(psoc);
	if (!mlme_obj) {
		*val = cfg_default(CFG_LFR_NEIGHBOR_SCAN_MIN_CHAN_TIME);
		return QDF_STATUS_E_INVAL;
	}

	*val = mlme_obj->cfg.lfr.neighbor_scan_min_chan_time;

	return QDF_STATUS_SUCCESS;
}

QDF_STATUS
ucfg_mlme_get_delay_before_vdev_stop(struct wlan_objmgr_psoc *psoc,
				     uint8_t *val)
{
	struct wlan_mlme_psoc_ext_obj *mlme_obj;

	mlme_obj = mlme_get_psoc_ext_obj(psoc);
	if (!mlme_obj) {
		*val = cfg_default(CFG_LFR_DELAY_BEFORE_VDEV_STOP);
		return QDF_STATUS_E_INVAL;
	}

	*val = mlme_obj->cfg.lfr.delay_before_vdev_stop;

	return QDF_STATUS_SUCCESS;
}

QDF_STATUS
ucfg_mlme_get_roam_bmiss_final_bcnt(struct wlan_objmgr_psoc *psoc,
				    uint8_t *val)
{
	return wlan_mlme_get_roam_bmiss_final_bcnt(psoc, val);
}

bool
ucfg_mlme_validate_roam_bmiss_final_bcnt(uint32_t bmiss_final_bcnt)
{
	bool is_valid = true;
	uint32_t min, max;

	if (!cfg_in_range(CFG_LFR_ROAM_BMISS_FINAL_BCNT,
			  bmiss_final_bcnt)) {
		min = (cfg_min(CFG_LFR_ROAM_BMISS_FINAL_BCNT));
		max = (cfg_max(CFG_LFR_ROAM_BMISS_FINAL_BCNT));
		mlme_legacy_err("bmiss final bcnt %d is out of range "
				"(Min: %d Max: %d)",
				bmiss_final_bcnt, min, max);
		is_valid = false;
	}

	return is_valid;
}

bool ucfg_mlme_get_dual_sta_roaming_enabled(struct wlan_objmgr_psoc *psoc)
{
	return wlan_mlme_get_dual_sta_roaming_enabled(psoc);
}

QDF_STATUS
ucfg_mlme_get_roam_bmiss_first_bcnt(struct wlan_objmgr_psoc *psoc,
				    uint8_t *val)
{
	return wlan_mlme_get_roam_bmiss_first_bcnt(psoc, val);
}

QDF_STATUS
ucfg_mlme_is_lfr_enabled(struct wlan_objmgr_psoc *psoc, bool *val)
{
	struct wlan_mlme_psoc_ext_obj *mlme_obj;

	mlme_obj = mlme_get_psoc_ext_obj(psoc);
	if (!mlme_obj) {
		*val = cfg_default(CFG_LFR_FEATURE_ENABLED);
		return QDF_STATUS_E_INVAL;
	}

	*val = mlme_obj->cfg.lfr.lfr_enabled;

	return QDF_STATUS_SUCCESS;
}

QDF_STATUS
ucfg_mlme_set_lfr_enabled(struct wlan_objmgr_psoc *psoc, bool val)
{
	struct wlan_mlme_psoc_ext_obj *mlme_obj;

	mlme_obj = mlme_get_psoc_ext_obj(psoc);
	if (!mlme_obj)
		return QDF_STATUS_E_INVAL;

	mlme_obj->cfg.lfr.lfr_enabled = val;

	return QDF_STATUS_SUCCESS;
}

QDF_STATUS
ucfg_mlme_is_roam_prefer_5ghz(struct wlan_objmgr_psoc *psoc, bool *val)
{
	struct wlan_mlme_psoc_ext_obj *mlme_obj;

	mlme_obj = mlme_get_psoc_ext_obj(psoc);
	if (!mlme_obj) {
		*val = cfg_default(CFG_LFR_ROAM_PREFER_5GHZ);
		return QDF_STATUS_E_INVAL;
	}

	*val = mlme_obj->cfg.lfr.roam_prefer_5ghz;

	return QDF_STATUS_SUCCESS;
}

bool ucfg_mlme_is_roam_intra_band(struct wlan_objmgr_psoc *psoc)
{
	struct wlan_mlme_psoc_ext_obj *mlme_obj;

	mlme_obj = mlme_get_psoc_ext_obj(psoc);
	if (!mlme_obj)
		return true;

	return mlme_obj->cfg.lfr.roam_intra_band;
}

QDF_STATUS
ucfg_mlme_set_roam_intra_band(struct wlan_objmgr_psoc *psoc, bool val)
{
	struct wlan_mlme_psoc_ext_obj *mlme_obj;

	mlme_obj = mlme_get_psoc_ext_obj(psoc);
	if (!mlme_obj)
		return QDF_STATUS_E_INVAL;

	mlme_obj->cfg.lfr.roam_intra_band = val;

	return QDF_STATUS_SUCCESS;
}

QDF_STATUS
ucfg_mlme_get_home_away_time(struct wlan_objmgr_psoc *psoc, uint16_t *val)
{
	struct wlan_mlme_psoc_ext_obj *mlme_obj;

	mlme_obj = mlme_get_psoc_ext_obj(psoc);
	if (!mlme_obj) {
		*val = cfg_default(CFG_LFR_ROAM_SCAN_HOME_AWAY_TIME);
		return QDF_STATUS_E_INVAL;
	}

	*val = mlme_obj->cfg.lfr.roam_scan_home_away_time;

	return QDF_STATUS_SUCCESS;
}

QDF_STATUS
ucfg_mlme_set_fast_roam_in_concurrency_enabled(struct wlan_objmgr_psoc *psoc,
					       bool val)
{
	struct wlan_mlme_psoc_ext_obj *mlme_obj;

	mlme_obj = mlme_get_psoc_ext_obj(psoc);
	if (!mlme_obj)
		return QDF_STATUS_E_INVAL;

	mlme_obj->cfg.lfr.enable_fast_roam_in_concurrency = val;

	return QDF_STATUS_SUCCESS;
}

#ifdef MULTI_CLIENT_LL_SUPPORT
bool ucfg_mlme_get_wlm_multi_client_ll_caps(struct wlan_objmgr_psoc *psoc)
{
	return wlan_mlme_get_wlm_multi_client_ll_caps(psoc);
}

QDF_STATUS
ucfg_mlme_cfg_get_multi_client_ll_ini_support(struct wlan_objmgr_psoc *psoc,
					      bool *multi_client_ll_support)
{
	return mlme_get_cfg_multi_client_ll_ini_support(psoc,
						multi_client_ll_support);
}
#endif

#ifdef WLAN_VENDOR_HANDOFF_CONTROL
bool ucfg_mlme_get_vendor_handoff_control_caps(struct wlan_objmgr_psoc *psoc)
{
	return wlan_mlme_get_vendor_handoff_control_caps(psoc);
}
#endif

#ifdef FEATURE_WLAN_ESE
QDF_STATUS
ucfg_mlme_is_ese_enabled(struct wlan_objmgr_psoc *psoc, bool *val)
{
	struct wlan_mlme_psoc_ext_obj *mlme_obj;

	mlme_obj = mlme_get_psoc_ext_obj(psoc);
	if (!mlme_obj) {
		*val = cfg_default(CFG_LFR_ESE_FEATURE_ENABLED);
		return QDF_STATUS_E_INVAL;
	}

	*val = mlme_obj->cfg.lfr.ese_enabled;

	return QDF_STATUS_SUCCESS;
}
#endif /* FEATURE_WLAN_ESE */

QDF_STATUS
ucfg_mlme_get_supported_mcs_set(struct wlan_objmgr_psoc *psoc,
				uint8_t *buf, qdf_size_t *len)
{
	struct wlan_mlme_psoc_ext_obj *mlme_obj;

	mlme_obj = mlme_get_psoc_ext_obj(psoc);
	if (!mlme_obj)
		return QDF_STATUS_E_INVAL;

	return wlan_mlme_get_cfg_str(buf,
				     &mlme_obj->cfg.rates.supported_mcs_set,
				     len);
}

QDF_STATUS
ucfg_mlme_set_supported_mcs_set(struct wlan_objmgr_psoc *psoc,
				uint8_t *buf, qdf_size_t len)
{
	struct wlan_mlme_psoc_ext_obj *mlme_obj;

	mlme_obj = mlme_get_psoc_ext_obj(psoc);
	if (!mlme_obj)
		return QDF_STATUS_E_INVAL;

	return wlan_mlme_set_cfg_str(buf,
				     &mlme_obj->cfg.rates.supported_mcs_set,
				     len);
}

QDF_STATUS
ucfg_mlme_get_current_mcs_set(struct wlan_objmgr_psoc *psoc,
			      uint8_t *buf, qdf_size_t *len)
{
	struct wlan_mlme_psoc_ext_obj *mlme_obj;

	mlme_obj = mlme_get_psoc_ext_obj(psoc);
	if (!mlme_obj)
		return QDF_STATUS_E_INVAL;

	return wlan_mlme_get_cfg_str(buf,
				     &mlme_obj->cfg.rates.current_mcs_set,
				     len);
}

QDF_STATUS
ucfg_mlme_get_wmi_wq_watchdog_timeout(struct wlan_objmgr_psoc *psoc,
				      uint32_t *wmi_wq_watchdog_timeout)
{
	struct wlan_mlme_psoc_ext_obj *mlme_obj;

	mlme_obj = mlme_get_psoc_ext_obj(psoc);
	if (!mlme_obj) {
		*wmi_wq_watchdog_timeout = cfg_default(CFG_WMI_WQ_WATCHDOG);
		return QDF_STATUS_E_INVAL;
	}

	*wmi_wq_watchdog_timeout =
		mlme_obj->cfg.timeouts.wmi_wq_watchdog_timeout;

	return QDF_STATUS_SUCCESS;
}

QDF_STATUS
ucfg_mlme_set_wmi_wq_watchdog_timeout(struct wlan_objmgr_psoc *psoc,
				      uint32_t wmi_wq_watchdog_timeout)
{
	struct wlan_mlme_psoc_ext_obj *mlme_obj;

	mlme_obj = mlme_get_psoc_ext_obj(psoc);
	if (!mlme_obj)
		return QDF_STATUS_E_INVAL;

	if (!cfg_in_range(CFG_WMI_WQ_WATCHDOG, wmi_wq_watchdog_timeout)) {
		mlme_legacy_err("wmi watchdog bite timeout is invalid %d",
				wmi_wq_watchdog_timeout);
		return QDF_STATUS_E_INVAL;
	}

	mlme_obj->cfg.timeouts.wmi_wq_watchdog_timeout =
		wmi_wq_watchdog_timeout;

	return QDF_STATUS_SUCCESS;
}

QDF_STATUS
ucfg_mlme_stats_get_periodic_display_time(struct wlan_objmgr_psoc *psoc,
					  uint32_t *periodic_display_time)
{
	return wlan_mlme_stats_get_periodic_display_time(psoc,
							 periodic_display_time);
}

QDF_STATUS
ucfg_mlme_stats_get_cfg_values(struct wlan_objmgr_psoc *psoc,
			       int *link_speed_rssi_high,
			       int *link_speed_rssi_mid,
			       int *link_speed_rssi_low,
			       uint32_t *link_speed_rssi_report)
{
	struct wlan_mlme_psoc_ext_obj *mlme_obj;

	mlme_obj = mlme_get_psoc_ext_obj(psoc);
	if (!mlme_obj) {
		*link_speed_rssi_high =
			cfg_default(CFG_LINK_SPEED_RSSI_HIGH);
		*link_speed_rssi_mid =
			cfg_default(CFG_LINK_SPEED_RSSI_MID);
		*link_speed_rssi_low =
			cfg_default(CFG_LINK_SPEED_RSSI_LOW);
		*link_speed_rssi_report =
			cfg_default(CFG_REPORT_MAX_LINK_SPEED);
		return QDF_STATUS_E_INVAL;
	}

	*link_speed_rssi_high =
		mlme_obj->cfg.stats.stats_link_speed_rssi_high;
	*link_speed_rssi_mid =
		mlme_obj->cfg.stats.stats_link_speed_rssi_med;
	*link_speed_rssi_low =
		mlme_obj->cfg.stats.stats_link_speed_rssi_low;
	*link_speed_rssi_report =
		mlme_obj->cfg.stats.stats_report_max_link_speed_rssi;

	return QDF_STATUS_SUCCESS;
}

bool ucfg_mlme_stats_is_link_speed_report_actual(struct wlan_objmgr_psoc *psoc)
{
	struct wlan_mlme_psoc_ext_obj *mlme_obj;
	int report_link_speed = 0;

	mlme_obj = mlme_get_psoc_ext_obj(psoc);
	if (!mlme_obj)
		report_link_speed = cfg_default(CFG_REPORT_MAX_LINK_SPEED);
	else
		report_link_speed =
			mlme_obj->cfg.stats.stats_report_max_link_speed_rssi;

	return (report_link_speed == CFG_STATS_LINK_SPEED_REPORT_ACTUAL);
}

bool ucfg_mlme_stats_is_link_speed_report_max(struct wlan_objmgr_psoc *psoc)
{
	struct wlan_mlme_psoc_ext_obj *mlme_obj;
	int report_link_speed = 0;

	mlme_obj = mlme_get_psoc_ext_obj(psoc);
	if (!mlme_obj)
		report_link_speed = cfg_default(CFG_REPORT_MAX_LINK_SPEED);
	else
		report_link_speed =
			mlme_obj->cfg.stats.stats_report_max_link_speed_rssi;

	return (report_link_speed == CFG_STATS_LINK_SPEED_REPORT_MAX);
}

bool
ucfg_mlme_stats_is_link_speed_report_max_scaled(struct wlan_objmgr_psoc *psoc)
{
	struct wlan_mlme_psoc_ext_obj *mlme_obj;
	int report_link_speed = 0;

	mlme_obj = mlme_get_psoc_ext_obj(psoc);
	if (!mlme_obj)
		report_link_speed = cfg_default(CFG_REPORT_MAX_LINK_SPEED);
	else
		report_link_speed =
			mlme_obj->cfg.stats.stats_report_max_link_speed_rssi;

	return (report_link_speed == CFG_STATS_LINK_SPEED_REPORT_MAX_SCALED);
}

QDF_STATUS
ucfg_mlme_get_sta_keepalive_method(struct wlan_objmgr_psoc *psoc,
				   enum station_keepalive_method *val)
{
	struct wlan_mlme_psoc_ext_obj *mlme_obj;

	mlme_obj = mlme_get_psoc_ext_obj(psoc);
	if (!mlme_obj)
		return QDF_STATUS_E_INVAL;

	*val = mlme_obj->cfg.sta.sta_keepalive_method;
	return QDF_STATUS_SUCCESS;
}

QDF_STATUS
ucfg_mlme_get_enable_deauth_to_disassoc_map(struct wlan_objmgr_psoc *psoc,
					    bool *value)
{
	struct wlan_mlme_psoc_ext_obj *mlme_obj;

	mlme_obj = mlme_get_psoc_ext_obj(psoc);
	if (!mlme_obj)
		return QDF_STATUS_E_INVAL;

	*value = mlme_obj->cfg.gen.enable_deauth_to_disassoc_map;
	return QDF_STATUS_SUCCESS;
}


QDF_STATUS
ucfg_mlme_get_ap_random_bssid_enable(struct wlan_objmgr_psoc *psoc,
				     bool *value)
{
	struct wlan_mlme_psoc_ext_obj *mlme_obj;

	mlme_obj = mlme_get_psoc_ext_obj(psoc);
	if (!mlme_obj)
		return QDF_STATUS_E_INVAL;

	*value = mlme_obj->cfg.sap_cfg.ap_random_bssid_enable;
	return QDF_STATUS_SUCCESS;
}

QDF_STATUS
ucfg_mlme_get_latency_enable(struct wlan_objmgr_psoc *psoc, bool *value)
{
	struct wlan_mlme_psoc_ext_obj *mlme_obj;

	mlme_obj = mlme_get_psoc_ext_obj(psoc);
	if (!mlme_obj) {
		mlme_legacy_err("mlme obj null");
		return QDF_STATUS_E_INVAL;
	}

	*value = mlme_obj->cfg.wlm_config.latency_enable;
	return QDF_STATUS_SUCCESS;
}

QDF_STATUS
ucfg_mlme_get_latency_level(struct wlan_objmgr_psoc *psoc, uint8_t *value)
{
	struct wlan_mlme_psoc_ext_obj *mlme_obj;

	mlme_obj = mlme_get_psoc_ext_obj(psoc);
	if (!mlme_obj) {
		mlme_legacy_err("mlme obj null");
		return QDF_STATUS_E_INVAL;
	}

	*value = mlme_obj->cfg.wlm_config.latency_level;
	return QDF_STATUS_SUCCESS;
}

QDF_STATUS
ucfg_mlme_get_latency_host_flags(struct wlan_objmgr_psoc *psoc,
				 uint8_t latency_level, uint32_t *value)
{
	struct wlan_mlme_psoc_ext_obj *mlme_obj;

	mlme_obj = mlme_get_psoc_ext_obj(psoc);
	if (!mlme_obj) {
		mlme_legacy_err("mlme obj null");
		return QDF_STATUS_E_INVAL;
	}

	*value = mlme_obj->cfg.wlm_config.latency_host_flags[latency_level];
	return QDF_STATUS_SUCCESS;
}

#ifdef MWS_COEX
QDF_STATUS
ucfg_mlme_get_mws_coex_4g_quick_tdm(struct wlan_objmgr_psoc *psoc,
				    uint32_t *val)
{
	struct wlan_mlme_psoc_ext_obj *mlme_obj;

	mlme_obj = mlme_get_psoc_ext_obj(psoc);
	if (!mlme_obj) {
		*val = cfg_default(CFG_MWS_COEX_4G_QUICK_FTDM);
		mlme_legacy_err("mlme obj null");
		return QDF_STATUS_E_INVAL;
	}

	*val = mlme_obj->cfg.mwc.mws_coex_4g_quick_tdm;

	return QDF_STATUS_SUCCESS;
}

QDF_STATUS
ucfg_mlme_get_mws_coex_5g_nr_pwr_limit(struct wlan_objmgr_psoc *psoc,
				       uint32_t *val)
{
	struct wlan_mlme_psoc_ext_obj *mlme_obj;

	mlme_obj = mlme_get_psoc_ext_obj(psoc);
	if (!mlme_obj) {
		*val = cfg_default(CFG_MWS_COEX_5G_NR_PWR_LIMIT);
		mlme_legacy_err("mlme obj null");
		return QDF_STATUS_E_INVAL;
	}

	*val = mlme_obj->cfg.mwc.mws_coex_5g_nr_pwr_limit;

	return QDF_STATUS_SUCCESS;
}

QDF_STATUS
ucfg_mlme_get_mws_coex_pcc_channel_avoid_delay(struct wlan_objmgr_psoc *psoc,
					       uint32_t *val)
{
	struct wlan_mlme_psoc_ext_obj *mlme_obj;

	mlme_obj = mlme_get_psoc_ext_obj(psoc);
	if (!mlme_obj) {
		*val = cfg_default(CFG_MWS_COEX_PCC_CHANNEL_AVOID_DELAY);
		mlme_legacy_err("mlme obj null");
		return QDF_STATUS_SUCCESS;
	}

	*val = mlme_obj->cfg.mwc.mws_coex_pcc_channel_avoid_delay;

	return QDF_STATUS_SUCCESS;
}

QDF_STATUS
ucfg_mlme_get_mws_coex_scc_channel_avoid_delay(struct wlan_objmgr_psoc *psoc,
					       uint32_t *val)
{
	struct wlan_mlme_psoc_ext_obj *mlme_obj;

	mlme_obj = mlme_get_psoc_ext_obj(psoc);
	if (!mlme_obj) {
		*val = cfg_default(CFG_MWS_COEX_SCC_CHANNEL_AVOID_DELAY);
		mlme_legacy_err("mlme obj null");
		return QDF_STATUS_SUCCESS;
	}

	*val = mlme_obj->cfg.mwc.mws_coex_scc_channel_avoid_delay;

	return QDF_STATUS_SUCCESS;
}
#endif

QDF_STATUS
ucfg_mlme_get_etsi_srd_chan_in_master_mode(struct wlan_objmgr_psoc *psoc,
					   uint8_t *value)
{
	struct wlan_mlme_psoc_ext_obj *mlme_obj;

	mlme_obj = mlme_get_psoc_ext_obj(psoc);
	if (!mlme_obj) {
		*value = cfg_default(CFG_ETSI_SRD_CHAN_IN_MASTER_MODE);
		mlme_legacy_err("Failed to get MLME Obj");
		return QDF_STATUS_E_INVAL;
	}

	*value = mlme_obj->cfg.reg.etsi_srd_chan_in_master_mode;

	return QDF_STATUS_SUCCESS;
}

QDF_STATUS
ucfg_mlme_get_5dot9_ghz_chan_in_master_mode(struct wlan_objmgr_psoc *psoc,
					    bool *value)
{
	struct wlan_mlme_psoc_ext_obj *mlme_obj;

	mlme_obj = mlme_get_psoc_ext_obj(psoc);
	if (!mlme_obj) {
		*value = cfg_default(CFG_FCC_5DOT9_GHZ_CHAN_IN_MASTER_MODE);
		mlme_legacy_err("Failed to get MLME Obj");
		return QDF_STATUS_E_INVAL;
	}

	*value = mlme_obj->cfg.reg.fcc_5dot9_ghz_chan_in_master_mode;

	return QDF_STATUS_SUCCESS;
}

QDF_STATUS
ucfg_mlme_get_srd_master_mode_for_vdev(struct wlan_objmgr_psoc *psoc,
				       enum QDF_OPMODE vdev_opmode,
				       bool *value)
{
	return wlan_mlme_get_srd_master_mode_for_vdev(psoc, vdev_opmode, value);
}

#ifdef SAP_AVOID_ACS_FREQ_LIST
QDF_STATUS
ucfg_mlme_get_acs_avoid_freq_list(struct wlan_objmgr_psoc *psoc,
				  uint16_t *freq_list, uint8_t *freq_list_num)
{
	struct wlan_mlme_psoc_ext_obj *mlme_obj;
	qdf_size_t avoid_acs_freq_list_num;

	mlme_obj = mlme_get_psoc_ext_obj(psoc);
	if (!mlme_obj) {
		qdf_uint16_array_parse(
				cfg_default(CFG_SAP_AVOID_ACS_FREQ_LIST),
				freq_list, CFG_VALID_CHANNEL_LIST_LEN,
				&avoid_acs_freq_list_num);
		*freq_list_num = avoid_acs_freq_list_num;

		mlme_legacy_err("Failed to get MLME Obj");
		return QDF_STATUS_E_INVAL;
	}

	*freq_list_num = mlme_obj->cfg.reg.avoid_acs_freq_list_num;
	qdf_mem_copy(freq_list, mlme_obj->cfg.reg.avoid_acs_freq_list,
		     *freq_list_num * sizeof(uint16_t));

	return QDF_STATUS_SUCCESS;
}
#endif

QDF_STATUS
ucfg_mlme_get_11d_in_world_mode(struct wlan_objmgr_psoc *psoc,
				bool *value)
{
	struct wlan_mlme_psoc_ext_obj *mlme_obj;

	mlme_obj = mlme_get_psoc_ext_obj(psoc);
	if (!mlme_obj) {
		*value = cfg_default(CFG_ENABLE_11D_IN_WORLD_MODE);
		mlme_legacy_err("Failed to get MLME Obj");
		return QDF_STATUS_E_INVAL;
	}

	*value = mlme_obj->cfg.reg.enable_11d_in_world_mode;

	return QDF_STATUS_SUCCESS;
}

QDF_STATUS
ucfg_mlme_get_restart_beaconing_on_ch_avoid(struct wlan_objmgr_psoc *psoc,
					    uint32_t *value)
{
	struct wlan_mlme_psoc_ext_obj *mlme_obj;

	mlme_obj = mlme_get_psoc_ext_obj(psoc);
	if (!mlme_obj) {
		*value = cfg_default(CFG_RESTART_BEACONING_ON_CH_AVOID);
		mlme_legacy_err("Failed to get MLME Obj");
		return QDF_STATUS_E_INVAL;
	}

	*value = mlme_obj->cfg.reg.restart_beaconing_on_ch_avoid;

	return QDF_STATUS_SUCCESS;
}

QDF_STATUS
ucfg_mlme_get_indoor_channel_support(struct wlan_objmgr_psoc *psoc,
				     bool *value)
{
	struct wlan_mlme_psoc_ext_obj *mlme_obj;

	mlme_obj = mlme_get_psoc_ext_obj(psoc);
	if (!mlme_obj) {
		*value = cfg_default(CFG_INDOOR_CHANNEL_SUPPORT);
		mlme_legacy_err("Failed to get MLME Obj");
		return QDF_STATUS_E_INVAL;
	}

	*value = mlme_obj->cfg.reg.indoor_channel_support;

	return QDF_STATUS_SUCCESS;
}

QDF_STATUS
ucfg_mlme_get_scan_11d_interval(struct wlan_objmgr_psoc *psoc,
				uint32_t *value)
{
	struct wlan_mlme_psoc_ext_obj *mlme_obj;

	mlme_obj = mlme_get_psoc_ext_obj(psoc);
	if (!mlme_obj) {
		*value = cfg_default(CFG_SCAN_11D_INTERVAL);
		mlme_legacy_err("Failed to get MLME Obj");
		return QDF_STATUS_E_INVAL;
	}

	*value = mlme_obj->cfg.reg.scan_11d_interval;
	return QDF_STATUS_SUCCESS;
}

QDF_STATUS
ucfg_mlme_get_nol_across_regdmn(struct wlan_objmgr_psoc *psoc, bool *value)
{
	struct wlan_mlme_psoc_ext_obj *mlme_obj;

	mlme_obj = mlme_get_psoc_ext_obj(psoc);
	if (!mlme_obj) {
		*value = cfg_default(CFG_RETAIN_NOL_ACROSS_REG_DOMAIN);
		mlme_legacy_err("Failed to get MLME Obj");
		return QDF_STATUS_E_INVAL;
	}

	*value = mlme_obj->cfg.reg.retain_nol_across_regdmn_update;
	return QDF_STATUS_SUCCESS;
}

#ifdef FEATURE_LFR_SUBNET_DETECTION
QDF_STATUS
ucfg_mlme_is_subnet_detection_enabled(struct wlan_objmgr_psoc *psoc, bool *val)
{
	struct wlan_mlme_psoc_ext_obj *mlme_obj;

	mlme_obj = mlme_get_psoc_ext_obj(psoc);
	if (!mlme_obj) {
		*val = cfg_default(CFG_LFR3_ENABLE_SUBNET_DETECTION);
		return QDF_STATUS_E_INVAL;
	}
	*val = mlme_obj->cfg.lfr.enable_lfr_subnet_detection;

	return QDF_STATUS_SUCCESS;
}
#endif

QDF_STATUS
ucfg_mlme_set_current_tx_power_level(struct wlan_objmgr_psoc *psoc,
				     uint8_t value)
{
	struct wlan_mlme_psoc_ext_obj *mlme_obj;

	mlme_obj = mlme_get_psoc_ext_obj(psoc);
	if (!mlme_obj)
		return QDF_STATUS_E_INVAL;

	mlme_obj->cfg.power.current_tx_power_level = value;

	return QDF_STATUS_SUCCESS;
}

QDF_STATUS
ucfg_mlme_get_current_tx_power_level(struct wlan_objmgr_psoc *psoc,
				     uint8_t *value)
{
	struct wlan_mlme_psoc_ext_obj *mlme_obj;

	mlme_obj = mlme_get_psoc_ext_obj(psoc);
	if (!mlme_obj) {
		*value = cfg_default(CFG_CURRENT_TX_POWER_LEVEL);
		return QDF_STATUS_E_INVAL;
	}

	*value = mlme_obj->cfg.power.current_tx_power_level;

	return QDF_STATUS_SUCCESS;
}

QDF_STATUS
ucfg_mlme_set_obss_detection_offload_enabled(struct wlan_objmgr_psoc *psoc,
					     uint8_t value)
{
	struct wlan_mlme_psoc_ext_obj *mlme_obj;

	mlme_obj = mlme_get_psoc_ext_obj(psoc);
	if (!mlme_obj)
		return QDF_STATUS_E_INVAL;

	mlme_obj->cfg.obss_ht40.obss_detection_offload_enabled = value;

	return QDF_STATUS_SUCCESS;
}

QDF_STATUS
ucfg_mlme_set_bss_color_collision_det_sta(struct wlan_objmgr_psoc *psoc,
					  bool value)
{
	struct wlan_mlme_psoc_ext_obj *mlme_obj;

	mlme_obj = mlme_get_psoc_ext_obj(psoc);
	if (!mlme_obj)
		return QDF_STATUS_E_INVAL;

	mlme_obj->cfg.obss_ht40.bss_color_collision_det_sta = value;

	return QDF_STATUS_SUCCESS;
}

QDF_STATUS
ucfg_mlme_set_bss_color_collision_det_support(struct wlan_objmgr_psoc *psoc,
					      bool val)
{
	struct wlan_mlme_psoc_ext_obj *mlme_obj;

	mlme_obj = mlme_get_psoc_ext_obj(psoc);
	if (!mlme_obj)
		return QDF_STATUS_E_INVAL;

	mlme_obj->cfg.obss_ht40.bss_color_collision_det_tgt_support = val;

	return QDF_STATUS_SUCCESS;
}

QDF_STATUS
ucfg_mlme_get_bss_color_collision_det_support(struct wlan_objmgr_psoc *psoc,
					      bool *val)
{
	struct wlan_mlme_psoc_ext_obj *mlme_obj;

	mlme_obj = mlme_get_psoc_ext_obj(psoc);
	if (!mlme_obj)
		return QDF_STATUS_E_INVAL;

	*val = mlme_obj->cfg.obss_ht40.bss_color_collision_det_tgt_support;

	return QDF_STATUS_SUCCESS;
}

QDF_STATUS
ucfg_mlme_set_obss_color_collision_offload_enabled(
		struct wlan_objmgr_psoc *psoc, uint8_t value)
{
	struct wlan_mlme_psoc_ext_obj *mlme_obj;

	mlme_obj = mlme_get_psoc_ext_obj(psoc);
	if (!mlme_obj)
		return QDF_STATUS_E_INVAL;

	mlme_obj->cfg.obss_ht40.obss_color_collision_offload_enabled = value;

	return QDF_STATUS_SUCCESS;
}

QDF_STATUS ucfg_mlme_set_restricted_80p80_bw_supp(struct wlan_objmgr_psoc *psoc,
						  bool restricted_80p80_supp)
{
	struct wlan_mlme_psoc_ext_obj *mlme_obj;

	mlme_obj = mlme_get_psoc_ext_obj(psoc);
	if (!mlme_obj)
		return QDF_STATUS_E_INVAL;

	mlme_obj->cfg.vht_caps.vht_cap_info.restricted_80p80_bw_supp =
					restricted_80p80_supp;

	return QDF_STATUS_SUCCESS;
}

bool ucfg_mlme_get_restricted_80p80_bw_supp(struct wlan_objmgr_psoc *psoc)
{
	struct wlan_mlme_psoc_ext_obj *mlme_obj;

	mlme_obj = mlme_get_psoc_ext_obj(psoc);

	if (!mlme_obj)
		return true;

	return mlme_obj->cfg.vht_caps.vht_cap_info.restricted_80p80_bw_supp;
}

QDF_STATUS
ucfg_mlme_get_channel_bonding_24ghz(struct wlan_objmgr_psoc *psoc,
				    uint32_t *val)
{
	struct wlan_mlme_psoc_ext_obj *mlme_obj;

	mlme_obj = mlme_get_psoc_ext_obj(psoc);
	if (!mlme_obj) {
		*val = cfg_default(CFG_CHANNEL_BONDING_MODE_24GHZ);
		return QDF_STATUS_E_INVAL;
	}
	*val = mlme_obj->cfg.feature_flags.channel_bonding_mode_24ghz;

	return QDF_STATUS_SUCCESS;
}

QDF_STATUS
ucfg_mlme_set_channel_bonding_24ghz(struct wlan_objmgr_psoc *psoc,
				    uint32_t value)
{
	struct wlan_mlme_psoc_ext_obj *mlme_obj;

	mlme_obj = mlme_get_psoc_ext_obj(psoc);
	if (!mlme_obj)
		return QDF_STATUS_E_INVAL;

	mlme_obj->cfg.feature_flags.channel_bonding_mode_24ghz = value;

	return QDF_STATUS_SUCCESS;
}

QDF_STATUS
ucfg_mlme_get_channel_bonding_5ghz(struct wlan_objmgr_psoc *psoc,
				   uint32_t *value)
{
	return wlan_mlme_get_channel_bonding_5ghz(psoc, value);
}

QDF_STATUS
ucfg_mlme_set_channel_bonding_5ghz(struct wlan_objmgr_psoc *psoc,
				   uint32_t value)
{
	struct wlan_mlme_psoc_ext_obj *mlme_obj;

	mlme_obj = mlme_get_psoc_ext_obj(psoc);
	if (!mlme_obj)
		return QDF_STATUS_E_INVAL;

	mlme_obj->cfg.feature_flags.channel_bonding_mode_5ghz = value;

	return QDF_STATUS_SUCCESS;
}

bool ucfg_mlme_validate_full_roam_scan_period(uint32_t full_roam_scan_period)
{
	bool is_valid = true;
	uint32_t min, max;

	if (!cfg_in_range(CFG_LFR_FULL_ROAM_SCAN_REFRESH_PERIOD,
			  full_roam_scan_period)) {
		min = (cfg_min(CFG_LFR_FULL_ROAM_SCAN_REFRESH_PERIOD));
		max = (cfg_max(CFG_LFR_FULL_ROAM_SCAN_REFRESH_PERIOD));
		mlme_legacy_err("Full roam scan period value %d is out of range (Min: %d Max: %d)",
				full_roam_scan_period, min, max);
		is_valid = false;
	}

	return is_valid;
}

bool ucfg_mlme_validate_scan_period(struct wlan_objmgr_psoc *psoc,
				    uint32_t roam_scan_period)
{
	bool is_valid = true, val = false;

	if (!cfg_in_range(CFG_LFR_EMPTY_SCAN_REFRESH_PERIOD,
			  roam_scan_period)) {
		ucfg_mlme_get_connection_roaming_ini_present(psoc, &val);
		if (val)
			mlme_legacy_err("Roam scan period value %d msec is out of range (Min: %d msec Max: %d msec)",
					roam_scan_period,
					cfg_min(CFG_ROAM_SCAN_FIRST_TIMER) * 1000,
					cfg_max(CFG_ROAM_SCAN_FIRST_TIMER) * 1000);
		else
			mlme_legacy_err("Roam scan period value %d msec is out of range (Min: %d msec Max: %d msec)",
					roam_scan_period,
					cfg_min(CFG_LFR_EMPTY_SCAN_REFRESH_PERIOD),
					cfg_max(CFG_LFR_EMPTY_SCAN_REFRESH_PERIOD));
		is_valid = false;
	}

	return is_valid;
}

#ifdef FEATURE_WLAN_CH_AVOID_EXT
bool ucfg_mlme_get_coex_unsafe_chan_nb_user_prefer(
		struct wlan_objmgr_psoc *psoc)
{
	return wlan_mlme_get_coex_unsafe_chan_nb_user_prefer_for_sap(psoc);
}

bool ucfg_mlme_get_coex_unsafe_chan_nb_user_prefer_for_sap(
		struct wlan_objmgr_psoc *psoc)
{
	return wlan_mlme_get_coex_unsafe_chan_nb_user_prefer_for_sap(psoc);
}

bool ucfg_mlme_get_coex_unsafe_chan_reg_disable(
		struct wlan_objmgr_psoc *psoc)
{
	struct wlan_mlme_psoc_ext_obj *mlme_obj;

	mlme_obj = mlme_get_psoc_ext_obj(psoc);
	if (!mlme_obj) {
		mlme_legacy_err("Failed to get MLME Obj");
		return cfg_default(CFG_COEX_UNSAFE_CHAN_REG_DISABLE);
	}
	return mlme_obj->cfg.reg.coex_unsafe_chan_reg_disable;
}
#endif

#if defined(CONFIG_AFC_SUPPORT) && defined(CONFIG_BAND_6GHZ)
QDF_STATUS
ucfg_mlme_get_enable_6ghz_sp_mode_support(struct wlan_objmgr_psoc *psoc,
					  bool *value)
{
	struct wlan_mlme_psoc_ext_obj *mlme_obj;

	mlme_obj = mlme_get_psoc_ext_obj(psoc);
	if (!mlme_obj)
		return QDF_STATUS_E_INVAL;

	*value = mlme_obj->cfg.reg.enable_6ghz_sp_pwrmode_supp;

	return QDF_STATUS_SUCCESS;
}

QDF_STATUS
ucfg_mlme_get_afc_disable_timer_check(struct wlan_objmgr_psoc *psoc,
				      bool *value)
{
	struct wlan_mlme_psoc_ext_obj *mlme_obj;

	mlme_obj = mlme_get_psoc_ext_obj(psoc);
	if (!mlme_obj)
		return QDF_STATUS_E_INVAL;

	*value = mlme_obj->cfg.reg.afc_disable_timer_check;

	return QDF_STATUS_SUCCESS;
}

QDF_STATUS
ucfg_mlme_get_afc_disable_request_id_check(struct wlan_objmgr_psoc *psoc,
					   bool *value)
{
	struct wlan_mlme_psoc_ext_obj *mlme_obj;

	mlme_obj = mlme_get_psoc_ext_obj(psoc);
	if (!mlme_obj)
		return QDF_STATUS_E_INVAL;

	*value = mlme_obj->cfg.reg.afc_disable_request_id_check;

	return QDF_STATUS_SUCCESS;
}

QDF_STATUS
ucfg_mlme_get_afc_reg_noaction(struct wlan_objmgr_psoc *psoc, bool *value)
{
	struct wlan_mlme_psoc_ext_obj *mlme_obj;

	mlme_obj = mlme_get_psoc_ext_obj(psoc);
	if (!mlme_obj)
		return QDF_STATUS_E_INVAL;

	*value = mlme_obj->cfg.reg.is_afc_reg_noaction;

	return QDF_STATUS_SUCCESS;
}
#endif

#ifdef CONNECTION_ROAMING_CFG
QDF_STATUS
ucfg_mlme_set_connection_roaming_ini_present(struct wlan_objmgr_psoc *psoc,
					     bool value)
{
	struct wlan_mlme_psoc_ext_obj *mlme_obj;

	mlme_obj = mlme_get_psoc_ext_obj(psoc);
	if (!mlme_obj)
		return QDF_STATUS_E_INVAL;

	mlme_obj->cfg.connection_roaming_ini_flag = value;

	return QDF_STATUS_SUCCESS;
}

QDF_STATUS
ucfg_mlme_get_connection_roaming_ini_present(struct wlan_objmgr_psoc *psoc,
					     bool *value)
{
	struct wlan_mlme_psoc_ext_obj *mlme_obj;

	mlme_obj = mlme_get_psoc_ext_obj(psoc);

	if (!mlme_obj)
		return QDF_STATUS_E_INVAL;

	*value = mlme_obj->cfg.connection_roaming_ini_flag;

	return QDF_STATUS_SUCCESS;
}
#endif

enum wlan_phymode
ucfg_mlme_get_vdev_phy_mode(struct wlan_objmgr_psoc *psoc, uint8_t vdev_id)
{
	struct wlan_objmgr_vdev *vdev;
	struct vdev_mlme_obj *mlme_obj;
	enum wlan_phymode phymode;

	vdev = wlan_objmgr_get_vdev_by_id_from_psoc(psoc, vdev_id,
						    WLAN_MLME_OBJMGR_ID);
	if (!vdev) {
		mlme_err("get vdev failed for vdev_id: %d", vdev_id);
		return WLAN_PHYMODE_AUTO;
	}

	mlme_obj = wlan_vdev_mlme_get_cmpt_obj(vdev);
	if (!mlme_obj) {
		mlme_err("failed to get mlme_obj vdev_id: %d", vdev_id);
		phymode = WLAN_PHYMODE_AUTO;
		goto done;
	}
	phymode = mlme_obj->mgmt.generic.phy_mode;

done:
	wlan_objmgr_vdev_release_ref(vdev, WLAN_MLME_OBJMGR_ID);

	return phymode;
}

QDF_STATUS
ucfg_mlme_get_valid_channels(struct wlan_objmgr_psoc *psoc,
			     uint32_t *ch_freq_list, uint32_t *list_len)
{
	struct wlan_mlme_psoc_ext_obj *mlme_obj;
	uint32_t num_valid_chan;
	uint8_t i;

	mlme_obj = mlme_get_psoc_ext_obj(psoc);
	if (!mlme_obj) {
		*list_len = 0;
		mlme_legacy_err("Failed to get MLME Obj");
		return QDF_STATUS_E_FAILURE;
	}

	num_valid_chan =  mlme_obj->cfg.reg.valid_channel_list_num;
	if (num_valid_chan > *list_len) {
		mlme_err("list len size %d less than expected %d", *list_len,
			 num_valid_chan);
		num_valid_chan = *list_len;
	}
	*list_len = num_valid_chan;
	for (i = 0; i < *list_len; i++)
		ch_freq_list[i] = mlme_obj->cfg.reg.valid_channel_freq_list[i];

	return QDF_STATUS_SUCCESS;
}

QDF_STATUS
ucfg_mlme_get_dfs_discard_mode(struct wlan_objmgr_psoc *psoc,
			       uint8_t *val)
{
	struct wlan_mlme_psoc_ext_obj *mlme_obj;

	mlme_obj = mlme_get_psoc_ext_obj(psoc);
	if (!mlme_obj) {
		*val = cfg_default(CFG_DISCARD_DFS_CHANNEL_FOR_MODE);
		return QDF_STATUS_E_INVAL;
	}

	*val = mlme_obj->cfg.dfs_cfg.dfs_discard_mode;

	return QDF_STATUS_SUCCESS;
}

QDF_STATUS
ucfg_mlme_get_passive_discard_mode(struct wlan_objmgr_psoc *psoc,
				   uint8_t *val)
{
	struct wlan_mlme_psoc_ext_obj *mlme_obj;

	mlme_obj = mlme_get_psoc_ext_obj(psoc);
	if (!mlme_obj) {
		*val = cfg_default(CFG_DISCARD_PASSIVE_CHANNEL_FOR_MODE);
		return QDF_STATUS_E_INVAL;
	}

	*val = mlme_obj->cfg.passive_chan_discard_mode;

	return QDF_STATUS_SUCCESS;
}

