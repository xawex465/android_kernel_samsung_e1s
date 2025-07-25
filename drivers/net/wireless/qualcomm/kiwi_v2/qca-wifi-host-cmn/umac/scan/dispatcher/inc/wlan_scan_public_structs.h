/*
 * Copyright (c) 2017-2021 The Linux Foundation. All rights reserved.
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

/*
 * DOC: contains scan structure definitions
 */

#ifndef _WLAN_SCAN_STRUCTS_H_
#define _WLAN_SCAN_STRUCTS_H_
#include <wlan_cmn.h>
#include <qdf_time.h>
#include <qdf_list.h>
#include <qdf_atomic.h>
#include <wlan_cmn_ieee80211.h>
#include <wlan_mgmt_txrx_utils_api.h>
#include <reg_services_public_struct.h>
#ifdef WLAN_FEATURE_11BE_MLO
#include "wlan_mlo_mgr_public_structs.h"
#endif

typedef uint16_t wlan_scan_requester;
typedef uint32_t wlan_scan_id;

#define WLAN_SCAN_MAX_HINT_S_SSID        10
#define WLAN_SCAN_MAX_HINT_BSSID         10
/*
 * For N(4 LINK) link MLO, Max RNR BSS will be given:
 * 16(N_6G_LINKS) + N - (N_6G_LINKS) - 1(SELF_LINK) = 16*2 + N-2-1 = 33
 */
#define MAX_RNR_BSS                      33
#define WLAN_SCAN_MAX_NUM_SSID          16
#define WLAN_SCAN_MAX_NUM_BSSID         4

#define SCM_CANCEL_SCAN_WAIT_TIME 50
#define SCM_CANCEL_SCAN_WAIT_ITERATION 600

#define INVAL_SCAN_ID        0xFFFFFFFF
#define CANCEL_HOST_SCAN_ID  0xFFFFFFFE
#define INVAL_VDEV_ID        0xFFFFFFFF
#define INVAL_PDEV_ID        0xFFFFFFFF

#define USER_SCAN_REQUESTOR_ID  0xA0000
#define PREAUTH_REQUESTOR_ID    0xC0000

#define BURST_SCAN_MAX_NUM_OFFCHANNELS 3
#define P2P_SCAN_MAX_BURST_DURATION 180
/* Increase dwell time for P2P search in ms */
#define P2P_SEARCH_DWELL_TIME_INC 20

#define PROBE_REQ_BITMAP_LEN 8
#define MAX_PROBE_REQ_OUIS 16

#define TBTT_INFO_COUNT 16

/*
 * IE Field nomenclature
 * @MBSSID_INDICATOR_POS: Position of MaxBSSID indicator inside MBSSID tag
 * @MIN_IE_LEN: 2bytes, which includes Tag Number and Tag length field
 * @TAG_LEN_POS: Position of tag length field in MBSSID tag
 * @VALID_ELEM_LEAST_LEN: Minimum fields required after tag length to call
 * a MBSSID tag valid. (MaxBSSID Indicator + subelement ID + Subelement length
 * atleast 1 byte of payload from subelement)
 * @SUBELEMENT_START_POS: Starting position of 1st subelement in MBSSID tag
 * @MAX_SUBELEM_LEN: Maximum length of a subelement
 * @PAYLOAD_START_POS: Payload start position of a non tx bssid profile
 * @FIXED_LENGTH: Length which includes header, timestamp, interval and
 * capability
 * @CAP_INFO_POS: Position of capability information in a non tx bssid profile
 * @CAP_INFO_LEN: Length of capability information
 * @SUBELEM_DATA_POS_FROM_MBSSID: Position of first byte of subelement payload
 * from MBSSID Tag
 * @ID_POS: Position of subelement ID in a non tx BSSID profile
 * @NONTX_BSSID_CAP_TAG_LEN_POS: Position of tag length field of nontx bssid
 * capability tag from starting of nontx bssid profile
 * @VALID_BSS_PROF_LEAST_LEN: At least one tag should present to call it a valid
 * non tx bssid profile and that is nothing but nontx bssid capability tag which
 * is of 4 bytes
 * @SPLIT_PROF_DATA_LEAST_LEN: Least possible length of second part of a split
 * profile, which includes at least one tag, which may have tag number + tag
 * length + atleast 1 byte of datai
 * @BSS_INDEX_POS: Position of BSSID index field in Multiple BSSID index tag
 * @MIN_VENDOR_TAG_LEN: Minimum length of a vendor specific tag
 * @OUI_LEN: OUI + OUI Type
 * @ELEM_ID_EXTN_POS: Position of element ID extension in an extension element
 * @ELEM_ID_LIST_LEN_POS: Position of length field in list of element IDs
 * @ELEM_ID_LIST_POS: Position to the start of element ID list
 */
#define MBSSID_INDICATOR_POS 2
#define MIN_IE_LEN 2
#define TAG_LEN_POS 1
#define VALID_ELEM_LEAST_LEN 4
#define SUBELEMENT_START_POS 3
#define MAX_SUBELEM_LEN 252
#define PAYLOAD_START_POS 2
#define FIXED_LENGTH 36
#define CAP_INFO_POS 4
#define CAP_INFO_LEN 2
#define SUBELEM_DATA_POS_FROM_MBSSID 5
#define ID_POS 0
#define NONTX_BSSID_CAP_TAG_LEN_POS 3
#define VALID_BSS_PROF_LEAST_LEN 4
#define SPLIT_PROF_DATA_LEAST_LEN 3
#define BSS_INDEX_POS 2
#define MIN_VENDOR_TAG_LEN 7
#define OUI_LEN 4
#define ELEM_ID_EXTN_POS 2
#define ELEM_ID_LIST_LEN_POS 3
#define ELEM_ID_LIST_POS 4

/* Active dwell time in low span scan mode(NL80211_SCAN_FLAG_LOW_SPAN)
 * in msec
 */
#define LOW_SPAN_ACTIVE_DWELL_TIME 40
/* passive dwell time in low span scan mode (NL80211_SCAN_FLAG_LOW_SPAN)
 * in msec
 */
#define LOW_SPAN_PASSIVE_DWELL_TIME 110

/* Min & Max offset from TBTT, after which Scan can start */
#define SCAN_START_OFFSET_MIN 26 /* msec */
#define SCAN_START_OFFSET_MAX 90 /* msec */

/* forward declaration */
struct wlan_objmgr_vdev;
struct wlan_objmgr_pdev;
struct wlan_objmgr_psoc;

/**
 * struct channel_info - BSS channel information
 * @chan_freq: channel frequency
 * @cfreq0: channel frequency index0
 * @cfreq1: channel frequency index1
 * @puncture_bitmap: puncture bitmap advertised in beacon
 * @priv: channel private information
 */
struct channel_info {
	uint32_t chan_freq;
	uint32_t cfreq0;
	uint32_t cfreq1;
#ifdef WLAN_FEATURE_11BE
	uint16_t puncture_bitmap;
#endif
	void *priv;
};

/**
 * struct ie_list - pointers to various IEs
 * @tim:        pointer to tim ie
 * @country:    pointer to country ie
 * @ssid:       pointer to ssid ie
 * @rates:      pointer to supported rates ie
 * @xrates:     pointer to extended supported rate ie
 * @ds_param:   pointer to ds params
 * @csa:        pointer to csa ie
 * @xcsa:       pointer to extended csa ie
 * @mcst:       pointer to maximum channel switch time ie
 * @wpa:        pointer to wpa ie
 * @wcn:        pointer to wcn ie
 * @rsn:        pointer to rsn ie
 * @wps:        pointer to wps ie
 * @wmeinfo:    pointer to wmeinfo ie
 * @wmeparam:   pointer to wmeparam ie
 * @quiet:      pointer to quiet ie
 * @htcap:      pointer to htcap ie
 * @htinfo:     pointer to htinfo ie
 * @athcaps:    pointer to athcaps ie
 * @athextcaps: pointer to extended athcaps ie
 * @sfa:        pointer to sfa ie
 * @vendor:     pointer to vendor ie
 * @qbssload:   pointer to qbssload ie
 * @wapi:       pointer to wapi ie
 * @p2p:        pointer to p2p ie
 * @alt_wcn:    pointer to alternate wcn ie
 * @extcaps:    pointer to extended caps ie
 * @ibssdfs:    pointer to ibssdfs ie
 * @sonadv:     pointer to wifi son ie
 * @vhtcap:     pointer to vhtcap ie
 * @vhtop:      pointer to vhtop ie
 * @opmode:     pointer to opmode ie
 * @tpe:        array of pointers to transmit power envelope ie
 * @cswrp:      pointer to channel switch announcement wrapper ie
 * @widebw:     pointer to wide band channel switch sub ie
 * @txpwrenvlp: pointer to tx power envelop sub ie
 * @hecap:      pointer to hecap ie
 * @hecap_6g:   pointer to he 6ghz cap ie
 * @srp: pointer to spatial reuse parameter sub extended ie
 * @fils_indication: pointer to FILS indication ie
 * @esp: pointer to ESP indication ie
 * @mbo_oce: pointer to mbo/oce indication ie
 * @rnrie: reduced neighbor report IE
 * @adaptive_11r: pointer to adaptive 11r IE
 * @single_pmk: Pointer to sae single pmk IE
 * @rsnxe: Pointer to rsnxe IE
 * @ehtcap: pointer to ehtcap ie
 * @ehtop: pointer to eht op ie
 * @bw_ind: pointer to bandwidth indication element sub ie
 * @multi_link_bv: pointer to multi link basic variant IE
 * @multi_link_rv: pointer to multi link reconfig IE
 * @t2lm: array of pointers to t2lm op ie
 * @bwnss_map: pointer to NSS map IE
 * @secchanoff: pointer to secondary chan IE
 * @mdie: pointer to md IE
 * @heop: pointer to HE op IE
 * @muedca: pointer to muedca IE
 * @extender: pointer to extended IE
 * @qcn: pointer to QCN IE
 */
struct ie_list {
	uint8_t *tim;
	uint8_t *country;
	uint8_t *ssid;
	uint8_t *rates;
	uint8_t *xrates;
	uint8_t *ds_param;
	uint8_t *csa;
	uint8_t *xcsa;
	uint8_t *mcst;
	uint8_t *wpa;
	uint8_t *wcn;
	uint8_t *rsn;
	uint8_t *wps;
	uint8_t *wmeinfo;
	uint8_t *wmeparam;
	uint8_t *quiet;
	uint8_t *htcap;
	uint8_t *htinfo;
	uint8_t *athcaps;
	uint8_t *athextcaps;
	uint8_t *sfa;
	uint8_t *vendor;
	uint8_t *qbssload;
	uint8_t *wapi;
	uint8_t *p2p;
	uint8_t *alt_wcn;
	uint8_t *extcaps;
	uint8_t *ibssdfs;
	uint8_t *sonadv;
	uint8_t *vhtcap;
	uint8_t *vhtop;
	uint8_t *opmode;
	uint8_t *tpe[WLAN_MAX_NUM_TPE_IE];
	uint8_t *cswrp;
	uint8_t *widebw;
	uint8_t *txpwrenvlp;
	uint8_t *bwnss_map;
	uint8_t *secchanoff;
	uint8_t *mdie;
	uint8_t *hecap;
	uint8_t *hecap_6g;
	uint8_t *heop;
	uint8_t *srp;
	uint8_t *fils_indication;
	uint8_t *esp;
	uint8_t *mbo_oce;
	uint8_t *muedca;
	uint8_t *rnrie;
	uint8_t *extender;
	uint8_t *adaptive_11r;
	uint8_t *single_pmk;
	uint8_t *rsnxe;
#ifdef WLAN_FEATURE_11BE
	uint8_t *ehtcap;
	uint8_t *ehtop;
	uint8_t *bw_ind;
#endif
#ifdef WLAN_FEATURE_11BE_MLO
	uint8_t *multi_link_bv;
	uint8_t *multi_link_rv;
	uint8_t *t2lm[WLAN_MAX_T2LM_IE];
#endif
	uint8_t *qcn;

/*
 * For any new IEs in this structure, add handling in
 * util_scan_copy_beacon_data API.
 */
};

enum scan_entry_connection_state {
	SCAN_ENTRY_CON_STATE_NONE,
	SCAN_ENTRY_CON_STATE_AUTH,
	SCAN_ENTRY_CON_STATE_ASSOC
};

/**
 * struct mlme_info - mlme specific info
 * temporarily maintained in scan cache for backward compatibility.
 * must be removed as part of umac convergence.
 * @bad_ap_time: time when this ap was marked bad
 * @status: status
 * @rank: rank
 * @utility: utility
 * @assoc_state: association state
 * @chanload: channel load
 */
struct mlme_info {
	qdf_time_t bad_ap_time;
	uint32_t status;
	uint32_t rank;
	uint32_t utility;
	uint32_t assoc_state;
	uint32_t chanload;
};

/**
 * struct bss_info - information required to uniquely define a bss
 * @freq: freq of operating primary channel
 * @ssid: ssid of bss
 * @bssid: bssid of bss
 */
struct bss_info {
	uint32_t freq;
	struct wlan_ssid ssid;
	struct qdf_mac_addr bssid;
};

#define SCAN_NODE_ACTIVE_COOKIE 0x1248F842
/**
 * struct scan_cache_node - Scan cache entry node
 * @node: node pointers
 * @ref_cnt: ref count if in use
 * @cookie: cookie to check if entry is logically active
 * @entry: scan entry pointer
 */
struct scan_cache_node {
	qdf_list_node_t node;
	qdf_atomic_t ref_cnt;
	uint32_t cookie;
	struct scan_cache_entry *entry;
};

/**
 * struct security_info - Scan cache security info
 * @authmodeset: auth mode
 * @key_mgmt: key management
 * @ucastcipherset: unicast cipher set
 * @mcastcipherset: multicast cipher set
 * @mgmtcipherset: mgmt cipher set
 * @rsn_caps: rsn caps of scan entry
 */
struct security_info {
	uint32_t authmodeset;
	uint32_t key_mgmt;
	uint32_t ucastcipherset;
	uint32_t mcastcipherset;
	uint32_t mgmtcipherset;
	uint16_t rsn_caps;
};

/**
 * struct scan_mbssid_info - Scan mbssid information
 * @profile_num: profile number
 * @profile_count: total profile count
 * @trans_bssid: TX BSSID address
 * @non_trans_bssid: non TX BSSID address
 * @split_profile: Indicates if next MBSSID tag has the other part
 *                 of the non tx profile
 * @prof_residue: Set prof_residue to true, if the first non TX
 *                     profile of the subsequent MBSSID IE does not contain
 *                     nontx BSSID Capability as the 1st tag of the payload
 *                     of nontx profile
 * @split_prof_continue: Indicates if we are evaluating the fragmented part
 *                      present in the subsequent MBSSID tag
 * @skip_bssid_copy: For the 2nd fragmented part of the split profile
 *                  skip copying bssid if BSSID index is already found
 *                  in the previous part of split profile
 */
struct scan_mbssid_info {
	uint8_t profile_num;
	uint8_t profile_count;
	uint8_t trans_bssid[QDF_MAC_ADDR_SIZE];
	uint8_t non_trans_bssid[QDF_MAC_ADDR_SIZE];
	bool split_profile;
	bool prof_residue;
	bool split_prof_continue;
	bool skip_bssid_copy;
};

/**
 * enum nontx_profile_reasoncode - Reason codes based on which the decision
 * needs to be taken whether to continue with the on going nontx profile or
 * move to the next one
 * @VALID_NONTX_PROF: Continue with the on-going profile
 * @INVALID_SPLIT_PROF: Invalid data seen in the split profile
 * @INVALID_NONTX_PROF: Invalid data in a non split profile
 */
enum nontx_profile_reasoncode {
	VALID_NONTX_PROF = 0,
	INVALID_SPLIT_PROF = 0x1,
	INVALID_NONTX_PROF = 0x2
};

/**
 * struct non_inheritance_ie - Non inheritance tag information
 * @list_len: Length of element ID list
 * @extn_len: Length of element ID extension list
 * @non_inherit: Flag to indicate if any noninheritance tag present
 *              in the non tx BSSID profile
 * @non_inh_ie_found: Flag to indicate if the noninheritance tag found
 *                   from non tx BSSID profile present in the tx profile
 *                   so that the copy of that IE can be skipped.
 */
struct non_inheritance_ie {
	uint8_t list_len;
	uint8_t extn_len;
	bool non_inherit;
	bool non_inh_ie_found;
};

#define TBTT_BSS_PARAM_MBSSID_BIT      0x04
#define TBTT_BSS_PARAM_TRANS_BSSID_BIT 0x08
#define TBTT_BSS_PARAM_MBSSID_TX_MASK  (TBTT_BSS_PARAM_MBSSID_BIT |\
					TBTT_BSS_PARAM_TRANS_BSSID_BIT)
#define TBTT_BSS_PARAM_MBSSID_NONTX_MASK TBTT_BSS_PARAM_MBSSID_BIT
/**
 * struct rnr_bss_info - Reduced Neighbor Report BSS information
 * @neighbor_ap_tbtt_offset: Neighbor AP TBTT offset
 * @channel_number: channel number
 * @operating_class: operting class
 * @bssid: BSS MAC address
 * @short_ssid: short ssid
 * @bss_params: BSS parameters
 * @psd_20mhz: 20MHz power spectral density
 * @mld_info_valid: valid MLD info
 * @mld_info: MLD information
 */
struct rnr_bss_info {
	uint8_t neighbor_ap_tbtt_offset;
	uint32_t channel_number;
	uint32_t operating_class;
	struct qdf_mac_addr bssid;
	uint32_t short_ssid;
	uint8_t bss_params;
	uint8_t psd_20mhz;
#ifdef WLAN_FEATURE_11BE_MLO
	bool mld_info_valid;
	struct rnr_mld_info mld_info;
#endif
};

/**
 * struct neighbor_ap_info_field - Neighbor information field
 * @tbtt_header: TBTT information header
 * @operting_class: operating class
 * @channel_number: channel number
 */
struct neighbor_ap_info_field {
	struct tbtt_information_header tbtt_header;
	uint8_t operting_class;
	uint8_t channel_number;
};

/**
 * enum tbtt_information_field - TBTT information field
 * @TBTT_NEIGHBOR_AP_OFFSET_ONLY: TBTT information field type
 * @TBTT_NEIGHBOR_AP_BSS_PARAM: neighbor AP and bss param
 * @TBTT_NEIGHBOR_AP_SHORTSSID: neighbor AP and Short ssid
 * @TBTT_NEIGHBOR_AP_S_SSID_BSS_PARAM: neighbor AP, short ssid and bss param
 * @TBTT_NEIGHBOR_AP_BSSID: neighbor AP and bssid
 * @TBTT_NEIGHBOR_AP_BSSID_BSS_PARAM: neighbor AP, bssid and bss param
 * @TBTT_NEIGHBOR_AP_BSSID_BSS_PARAM_20MHZ_PSD: neighbor AP, bssid and bss
 * param and 20MHz PSD
 * @TBTT_NEIGHBOR_AP_BSSSID_S_SSID: neighbor AP, bssid and short ssid
 * @TBTT_NEIGHBOR_AP_BSSID_S_SSID_BSS_PARAM: neighbor AP, bssid, short ssid
 * and bss params
 * @TBTT_NEIGHBOR_AP_BSSID_S_SSID_BSS_PARAM_20MHZ_PSD: neighbor AP, bssid,
 * short ssid, bss params and 20MHz PSD
 * bssid, short ssid, bss params, 20MHz PSD and MLD param
 * @TBTT_NEIGHBOR_AP_BSSID_S_SSID_BSS_PARAM_20MHZ_PSD_MLD_PARAM:
 * @TBTT_NEIGHBOR_AP_PARAM_AFTER_LAST: This is to calculate the max supported
 * param length and maintain it in TBTT_NEIGHBOR_AP_PARAM_MAX
 * @TBTT_NEIGHBOR_AP_PARAM_MAX: This is to track the max supported param length
 */
enum tbtt_information_field {
	TBTT_NEIGHBOR_AP_OFFSET_ONLY = 1,
	TBTT_NEIGHBOR_AP_BSS_PARAM = 2,
	TBTT_NEIGHBOR_AP_SHORTSSID = 5,
	TBTT_NEIGHBOR_AP_S_SSID_BSS_PARAM = 6,
	TBTT_NEIGHBOR_AP_BSSID = 7,
	TBTT_NEIGHBOR_AP_BSSID_BSS_PARAM = 8,
	TBTT_NEIGHBOR_AP_BSSID_BSS_PARAM_20MHZ_PSD = 9,
	TBTT_NEIGHBOR_AP_BSSSID_S_SSID = 11,
	TBTT_NEIGHBOR_AP_BSSID_S_SSID_BSS_PARAM = 12,
	TBTT_NEIGHBOR_AP_BSSID_S_SSID_BSS_PARAM_20MHZ_PSD = 13,
	TBTT_NEIGHBOR_AP_BSSID_S_SSID_BSS_PARAM_20MHZ_PSD_MLD_PARAM = 16,

	/* keep last */
	TBTT_NEIGHBOR_AP_PARAM_AFTER_LAST,
	TBTT_NEIGHBOR_AP_PARAM_MAX = TBTT_NEIGHBOR_AP_PARAM_AFTER_LAST - 1,
};

/**
 * struct reduced_neighbor_report - Reduced Neighbor Report
 * @count: number of RNR info
 * @bss_info: RNR BSS Information
 */
struct reduced_neighbor_report {
	uint8_t count;
	struct rnr_bss_info bss_info[MAX_RNR_BSS];
};

#define SCAN_SECURITY_TYPE_WEP 0x01
#define SCAN_SECURITY_TYPE_WPA 0x02
#define SCAN_SECURITY_TYPE_WAPI 0x04
#define SCAN_SECURITY_TYPE_RSN 0x08

#ifdef WLAN_FEATURE_11BE_MLO
#define MLD_MAX_LINKS 4

/**
 * struct partner_link_info: Partner link information of an ML
 * @link_addr: BSSID of the link
 * @freq: center frequency in MHz
 * @cfreq2: center frequency of the secondary channel in MHz
 * @link_id: Link id advertised by the AP
 * @csa_ie: Pointer to CSA IE
 * @ecsa_ie: Pointer to eCSA IE
 * @max_cst_ie: Pointer to Max Channel Switch Time IE
 * @is_valid_link: The partner link can be used if true
 * @is_scan_entry_not_found: If set to true, the partner link scan entry is
 * not present in scan DB (currently using for non-TxMBSSID MLO AP)
 * @op_class: Operating class
 */
struct partner_link_info {
	struct qdf_mac_addr link_addr;
	uint16_t freq;
	uint16_t cfreq2;
	uint8_t link_id;
	const uint8_t *csa_ie;
	const uint8_t *ecsa_ie;
	const uint8_t *max_cst_ie;
	bool is_valid_link;
	bool is_scan_entry_not_found;
	uint8_t op_class;
};

/**
 * struct ml_info: Multi link formation of a 11be beacon
 * @mld_mac_addr: MLD mac address
 * @num_links: Number of links supported by ML AP
 * @self_link_id: Link id of the scan entry
 * @link_info: Array containing partner links information
 * @ml_bss_score: Multi link BSS score
 * @link_score: MLO link score
 */
struct ml_info {
	struct qdf_mac_addr mld_mac_addr;
	uint8_t num_links;
	uint8_t self_link_id;
	struct partner_link_info link_info[MLD_MAX_LINKS - 1];
	uint16_t ml_bss_score;
	uint16_t link_score;
};

/**
 * enum number_of_partner_link: Enumeration for number of partner links
 * @NO_LINK:    Default value
 * @ONE_LINK:   Single Link
 * @TWO_LINK:   2 Links
 * @THREE_LINK: 3 Links
 */
enum number_of_partner_link {
	NO_LINK,
	ONE_LINK,
	TWO_LINK,
	THREE_LINK,
};
#endif

/**
 * struct scan_cache_entry: structure containing scan entry
 * @frm_subtype: updated from beacon/probe
 * @bssid: bssid
 * @mac_addr: mac address
 * @ssid: ssid
 * @is_hidden_ssid: is AP having hidden ssid.
 * @security_type: security supported
 * @seq_num: sequence number
 * @phy_mode: Phy mode of the AP
 * @avg_rssi: Average RSSI of the AP
 * @rssi_raw: The rssi of the last beacon/probe received
 * @snr: The snr of the last beacon/probe received
 * @avg_snr: Average SNR of the AP
 * @bcn_int: Beacon interval of the AP
 * @cap_info: Capability of the AP
 * @tsf_info: TSF info
 * @erp: erp info
 * @dtim_period: dtime period
 * @air_time_fraction: Air time fraction from ESP param
 * @qbss_chan_load: Qbss channel load
 * @nss: supported NSS information
 * @is_p2p: is P2P entry
 * @adaptive_11r_ap: flag to check if AP supports adaptive 11r
 * @scan_entry_time: boottime in microsec when last beacon/probe is received
 * @rssi_timestamp: boottime in microsec when RSSI was updated
 * @hidden_ssid_timestamp: boottime in microsec when hidden
 *                         ssid was received
 * @mbssid_info: Multi bssid information
 * @rnr: Reduced neighbor report information
 * @channel: channel info on which AP is present
 * @channel_mismatch: if channel received in metadata
 *                    doesn't match the one in beacon
 * @mlme_info: Mlme info, this will be updated by MLME for the scan entry
 * @tsf_delta: TSF delta
 * @bss_score: bss score calculated on basis of RSSI/caps etc.
 * @neg_sec_info: negotiated security info
 * @per_chain_rssi: per chain RSSI value received.
 * @boottime_ns: boottime in ns.
 * @rrm_parent_tsf: RRM parent tsf
 * @alt_wcn_ie: alternate WCN IE
 * @ie_list: IE list pointers
 * @raw_frame: contain raw frame and the length of the raw frame
 * @pdev_id: pdev id
 * @ml_info: Multi link information
 * @mlo_max_recom_simult_links: Max recommended simultaneous link
 * @non_intersected_phymode: Non intersected phy mode of the AP
 */
struct scan_cache_entry {
	uint8_t frm_subtype;
	struct qdf_mac_addr bssid;
	struct qdf_mac_addr mac_addr;
	struct wlan_ssid ssid;
	bool is_hidden_ssid;
	uint8_t security_type;
	uint16_t seq_num;
	enum wlan_phymode phy_mode;
	int32_t avg_rssi;
	int8_t rssi_raw;
	uint8_t snr;
	uint32_t avg_snr;
	uint16_t bcn_int;
	union wlan_capability cap_info;
	union {
		uint8_t data[8];
		uint64_t tsf;
	} tsf_info;
	uint8_t erp;
	uint8_t dtim_period;
	uint8_t air_time_fraction;
	uint8_t qbss_chan_load;
	uint8_t nss;
	bool is_p2p;
	bool adaptive_11r_ap;
	qdf_time_t scan_entry_time;
	qdf_time_t rssi_timestamp;
	qdf_time_t hidden_ssid_timestamp;
	struct scan_mbssid_info mbssid_info;
	struct reduced_neighbor_report rnr;
	struct channel_info channel;
	bool channel_mismatch;
	struct mlme_info mlme_info;
	uint32_t tsf_delta;
	uint32_t bss_score;
	struct security_info neg_sec_info;
	uint8_t per_chain_rssi[WLAN_MGMT_TXRX_HOST_MAX_ANTENNA];
	uint64_t boottime_ns;
	uint32_t rrm_parent_tsf;
	struct element_info alt_wcn_ie;
	struct ie_list ie_list;
	struct element_info raw_frame;
	/*
	 * This is added temporarily for 6GHz channel to freq conversion
	 * to get pdev wherever it requores to convert frequency to
	 * channel as regulatory apis requires pdev as argument
	 */
	uint8_t pdev_id;
#ifdef WLAN_FEATURE_11BE_MLO
	struct ml_info ml_info;
	uint8_t mlo_max_recom_simult_links;
#endif
	enum wlan_phymode non_intersected_phymode;
};

#define MAX_FAVORED_BSSID 16
#define MAX_ALLOWED_SSID_LIST 4

#define WLAN_SCAN_FILTER_NUM_SSID 5
#define WLAN_SCAN_FILTER_NUM_BSSID 5

#define REALM_HASH_LEN 2
#define CACHE_IDENTIFIER_LEN 2
#define HESSID_LEN 6

#ifdef WLAN_FEATURE_FILS_SK
/**
 * struct fils_filter_info: FILS info present in scan filter
 * @realm_check: whether realm check is required
 * @fils_realm: realm hash value
 * @security_type: type of security supported
 */
struct fils_filter_info {
	bool realm_check;
	uint8_t fils_realm[REALM_HASH_LEN];
	uint8_t security_type;
};
#endif

/*
 * struct filter_arg: Opaque pointer for the filter arguments
 */
struct filter_arg;
typedef struct filter_arg *bss_filter_arg_t;

/**
 * enum dot11_mode_filter - Filter APs according to dot11mode
 * @ALLOW_ALL: ignore check
 * @ALLOW_11N_ONLY: allow only 11n AP
 * @ALLOW_11AC_ONLY: allow only 11ac AP
 * @ALLOW_11AX_ONLY: allow only 11ax AP
 * @ALLOW_11BE_ONLY: allow only 11be AP
 */
enum dot11_mode_filter {
	ALLOW_ALL,
	ALLOW_11N_ONLY,
	ALLOW_11AC_ONLY,
	ALLOW_11AX_ONLY,
	ALLOW_11BE_ONLY,
};

/**
 * struct scan_filter: scan filter
 * @enable_adaptive_11r:    flag to check if adaptive 11r ini is enabled
 * @rrm_measurement_filter: For measurement reports.if set, only SSID, BSSID
 *                          and channel is considered for filtering.
 * @ignore_pmf_cap: Ignore pmf capability match
 * @ignore_auth_enc_type: Ignore enc type if
 *                        this is set (For WPS/OSEN connection)
 * @ignore_nol_chan: Ignore entry with channel in the NOL list
 * @ignore_6ghz_channel: ignore 6Ghz channels
 * @age_threshold: If set return entry which are newer than the age_threshold
 * @num_of_bssid: number of bssid passed
 * @num_of_ssid: number of ssid
 * @num_of_channels: number of  channels
 * @bss_type: bss type IBSS or BSS or ANY
 * @pmf_cap: Pmf capability
 * @dot11mode: Filter APs based upon dot11mode
 * @rssi_threshold: AP having RSSI greater than
 *                  rssi threasholed (ignored if set 0)
 * @mobility_domain: Mobility domain for 11r
 * @authmodeset: auth mode
 * @key_mgmt: key management
 * @ucastcipherset: unicast cipher set
 * @mcastcipherset: multicast cipher set
 * @mgmtcipherset: mgmt cipher set
 * @fils_scan_filter: FILS info
 * @bssid_hint: Mac address of bssid_hint
 * @bssid_list: bssid list
 * @ssid_list: ssid list
 * @chan_freq_list: channel frequency list, frequency unit: MHz
 * @match_security_func: Function pointer to custom security filter
 * @match_security_func_arg: Function argument to custom security filter
 * @ccx_validate_bss: Function pointer to custom bssid filter
 * @ccx_validate_bss_arg: Function argument to custom bssid filter
 * @band_bitmap: Allowed band bit map, BIT0: 2G, BIT1: 5G, BIT2: 6G
 */
struct scan_filter {
	uint8_t enable_adaptive_11r:1,
		rrm_measurement_filter:1,
		ignore_pmf_cap:1,
		ignore_auth_enc_type:1,
		ignore_nol_chan:1,
		ignore_6ghz_channel:1;
	qdf_time_t age_threshold;
	uint8_t num_of_bssid;
	uint8_t num_of_ssid;
	uint16_t num_of_channels;
	enum wlan_bss_type bss_type;
	enum wlan_pmf_cap pmf_cap;
	enum dot11_mode_filter dot11mode;
	uint8_t rssi_threshold;
	uint32_t mobility_domain;
	uint32_t authmodeset;
	uint32_t key_mgmt;
	uint32_t ucastcipherset;
	uint32_t mcastcipherset;
	uint32_t mgmtcipherset;
#ifdef WLAN_FEATURE_FILS_SK
	struct fils_filter_info fils_scan_filter;
#endif
	struct qdf_mac_addr bssid_hint;
	/* Variable params list */
	struct qdf_mac_addr bssid_list[WLAN_SCAN_FILTER_NUM_BSSID];
	struct wlan_ssid ssid_list[WLAN_SCAN_FILTER_NUM_SSID];
	qdf_freq_t chan_freq_list[NUM_CHANNELS];
	bool (*match_security_func)(void *, struct scan_cache_entry *);
	bss_filter_arg_t match_security_func_arg;
	bool (*ccx_validate_bss)(void *, struct scan_cache_entry *, int);
	bss_filter_arg_t ccx_validate_bss_arg;
#ifdef WLAN_FEATURE_11BE_MLO
	uint32_t band_bitmap;
#endif
};

/**
 * enum scan_disable_reason - scan enable/disable reason
 * @REASON_SUSPEND: reason is suspend
 * @REASON_SYSTEM_DOWN: reason is system going down
 * @REASON_USER_SPACE: reason is user space initiated
 * @REASON_VDEV_DOWN: reason is vdev going down
 */
enum scan_disable_reason {
	REASON_SUSPEND  = 0x1,
	REASON_SYSTEM_DOWN = 0x2,
	REASON_USER_SPACE = 0x4,
	REASON_VDEV_DOWN = 0x8,
};

/**
 * enum scan_priority - scan priority definitions
 * @SCAN_PRIORITY_VERY_LOW: very low priority
 * @SCAN_PRIORITY_LOW: low scan priority
 * @SCAN_PRIORITY_MEDIUM: medium priority
 * @SCAN_PRIORITY_HIGH: high priority
 * @SCAN_PRIORITY_VERY_HIGH: very high priority
 * @SCAN_PRIORITY_COUNT: number of priorities supported
 */
enum scan_priority {
	SCAN_PRIORITY_VERY_LOW,
	SCAN_PRIORITY_LOW,
	SCAN_PRIORITY_MEDIUM,
	SCAN_PRIORITY_HIGH,
	SCAN_PRIORITY_VERY_HIGH,
	SCAN_PRIORITY_COUNT,
};

/**
 * enum scan_phy_mode - phymode used for scan
 * @SCAN_PHY_MODE_11A: 11a mode
 * @SCAN_PHY_MODE_11G: 11g mode
 * @SCAN_PHY_MODE_11B: 11b mode
 * @SCAN_PHY_MODE_11GONLY: 11g only mode
 * @SCAN_PHY_MODE_11NA_HT20: 11na ht20 mode
 * @SCAN_PHY_MODE_11NG_HT20: 11ng ht20 mode
 * @SCAN_PHY_MODE_11NA_HT40: 11na ht40 mode
 * @SCAN_PHY_MODE_11NG_HT40: 11ng ht40 mode
 * @SCAN_PHY_MODE_11AC_VHT20: 11ac vht20 mode
 * @SCAN_PHY_MODE_11AC_VHT40: 11ac vht40 mode
 * @SCAN_PHY_MODE_11AC_VHT80: 11ac vht80 mode
 * @SCAN_PHY_MODE_11AC_VHT20_2G: 2GHz 11ac vht20 mode
 * @SCAN_PHY_MODE_11AC_VHT40_2G: 2GHz 11ac vht40 mode
 * @SCAN_PHY_MODE_11AC_VHT80_2G: 2GHz 11ac vht80 mode
 * @SCAN_PHY_MODE_11AC_VHT80_80: 11ac vht 80+80 mode
 * @SCAN_PHY_MODE_11AC_VHT160: 11ac vht160 mode
 * @SCAN_PHY_MODE_11AX_HE20: 11ax he20 mode
 * @SCAN_PHY_MODE_11AX_HE40: 11ax he40 mode
 * @SCAN_PHY_MODE_11AX_HE80: 11ax he80 mode
 * @SCAN_PHY_MODE_11AX_HE80_80: 11ax he80+80 mode
 * @SCAN_PHY_MODE_11AX_HE160: 11ax he160 mode
 * @SCAN_PHY_MODE_11AX_HE20_2G: 2GHz 11ax he20 mode
 * @SCAN_PHY_MODE_11AX_HE40_2G: 2GHz 11ax he40 mode
 * @SCAN_PHY_MODE_11AX_HE80_2G: 2GHz 11ax he80 mode
 * @SCAN_PHY_MODE_11BE_EHT20: 11be EHT 20 mode
 * @SCAN_PHY_MODE_11BE_EHT40: 11be EHT 40 mode
 * @SCAN_PHY_MODE_11BE_EHT80: 11be EHT 80 mode
 * @SCAN_PHY_MODE_11BE_EHT80_80: 11be EHT 80+80 mode
 * @SCAN_PHY_MODE_11BE_EHT160: 11be EHT 160 mode
 * @SCAN_PHY_MODE_11BE_EHT160_160: 11be EHT 160+160 mode
 * @SCAN_PHY_MODE_11BE_EHT320: 11be EHT 320 mode
 * @SCAN_PHY_MODE_11BE_EHT20_2G: 2GHz 11be EHT 20 mode
 * @SCAN_PHY_MODE_11BE_EHT40_2G: 2GHz 11be EHT 40 mode
 * @SCAN_PHY_MODE_11BE_EHT80_2G: 2GHz 11be EHT 80 mode
 * @SCAN_PHY_MODE_UNKNOWN: unknown phy mode
 * @SCAN_PHY_MODE_MAX: max valid phymode
 */
enum scan_phy_mode {
	SCAN_PHY_MODE_11A = 0,
	SCAN_PHY_MODE_11G = 1,
	SCAN_PHY_MODE_11B = 2,
	SCAN_PHY_MODE_11GONLY = 3,
	SCAN_PHY_MODE_11NA_HT20 = 4,
	SCAN_PHY_MODE_11NG_HT20 = 5,
	SCAN_PHY_MODE_11NA_HT40 = 6,
	SCAN_PHY_MODE_11NG_HT40 = 7,
	SCAN_PHY_MODE_11AC_VHT20 = 8,
	SCAN_PHY_MODE_11AC_VHT40 = 9,
	SCAN_PHY_MODE_11AC_VHT80 = 10,
	SCAN_PHY_MODE_11AC_VHT20_2G = 11,
	SCAN_PHY_MODE_11AC_VHT40_2G = 12,
	SCAN_PHY_MODE_11AC_VHT80_2G = 13,
	SCAN_PHY_MODE_11AC_VHT80_80 = 14,
	SCAN_PHY_MODE_11AC_VHT160 = 15,
	SCAN_PHY_MODE_11AX_HE20 = 16,
	SCAN_PHY_MODE_11AX_HE40 = 17,
	SCAN_PHY_MODE_11AX_HE80 = 18,
	SCAN_PHY_MODE_11AX_HE80_80 = 19,
	SCAN_PHY_MODE_11AX_HE160 = 20,
	SCAN_PHY_MODE_11AX_HE20_2G = 21,
	SCAN_PHY_MODE_11AX_HE40_2G = 22,
	SCAN_PHY_MODE_11AX_HE80_2G = 23,
#ifdef WLAN_FEATURE_11BE
	SCAN_PHY_MODE_11BE_EHT20 = 24,
	SCAN_PHY_MODE_11BE_EHT40 = 25,
	SCAN_PHY_MODE_11BE_EHT80 = 26,
	SCAN_PHY_MODE_11BE_EHT80_80 = 27,
	SCAN_PHY_MODE_11BE_EHT160 = 28,
	SCAN_PHY_MODE_11BE_EHT160_160 = 29,
	SCAN_PHY_MODE_11BE_EHT320 = 30,
	SCAN_PHY_MODE_11BE_EHT20_2G = 31,
	SCAN_PHY_MODE_11BE_EHT40_2G = 32,
	SCAN_PHY_MODE_11BE_EHT80_2G = 33,
#endif
	SCAN_PHY_MODE_UNKNOWN = 34,
	SCAN_PHY_MODE_MAX = 34
};

/**
 * enum scan_dwelltime_adaptive_mode: dwelltime_mode
 * @SCAN_DWELL_MODE_DEFAULT: Use firmware default mode
 * @SCAN_DWELL_MODE_CONSERVATIVE: Conservative adaptive mode
 * @SCAN_DWELL_MODE_MODERATE: Moderate adaptive mode
 * @SCAN_DWELL_MODE_AGGRESSIVE: Aggressive adaptive mode
 * @SCAN_DWELL_MODE_STATIC: static adaptive mode
 */
enum scan_dwelltime_adaptive_mode {
	SCAN_DWELL_MODE_DEFAULT = 0,
	SCAN_DWELL_MODE_CONSERVATIVE = 1,
	SCAN_DWELL_MODE_MODERATE = 2,
	SCAN_DWELL_MODE_AGGRESSIVE = 3,
	SCAN_DWELL_MODE_STATIC = 4
};

/**
 * struct scan_random_attr - holds scan randomization attrs
 * @randomize: set to true for scan randomization
 * @mac_addr: mac addr to be randomized
 * @mac_mask: used to represent bits in mac_addr for randomization
 */
struct scan_random_attr {
	bool randomize;
	uint8_t mac_addr[QDF_MAC_ADDR_SIZE];
	uint8_t mac_mask[QDF_MAC_ADDR_SIZE];
};

/**
 * struct probe_req_allowlist_attr - holds probe req ie allowlist attrs
 * @allow_list: enable/disable allowlist
 * @ie_bitmap: bitmap of IEs to be enabled
 * @num_vendor_oui: number of vendor OUIs
 * @voui: vendor oui buffer
 */
struct probe_req_allowlist_attr {
	bool allow_list;
	uint32_t ie_bitmap[PROBE_REQ_BITMAP_LEN];
	uint32_t num_vendor_oui;
	uint32_t voui[MAX_PROBE_REQ_OUIS];
};

/**
 * enum scan_flags: scan flags
 * @FLAG_SCAN_ONLY_IF_RNR_FOUND: Set this flag for a 6g channel to scan it only
 *  if an RNR IE is found with that channel while scanning 2g/5g bands.
 */
enum scan_flags {
	FLAG_SCAN_ONLY_IF_RNR_FOUND = 0x1,
};

/**
 * struct chan_info - channel information
 * @freq: frequency to scan
 * @phymode: phymode in which @frequency should be scanned
 * @flags: Flags to define channel property as defined @enum scan_flags.
 *  Firmware can use this info for different operations, e.g.: scan
 */
struct chan_info {
	qdf_freq_t freq;
	enum scan_phy_mode phymode;
	enum scan_flags flags;
};

struct chan_list_info {
	qdf_freq_t freq;
	uint32_t last_scan_time;
};

struct chan_list_scan_info {
	uint8_t num_chan;
	struct chan_list_info ch_scan_info[NUM_CHANNELS];
};

/**
 * struct chan_list - list of frequencies to be scanned
 *  and their phymode
 * @num_chan: number of channels to scan
 * @chan: channel parameters used for this scan
 */
struct chan_list {
	uint8_t num_chan;
	struct chan_info chan[NUM_CHANNELS];
};

/**
 * struct hint_short_ssid - short SSID hint
 *  and their phymode
 * @freq_flags: freq unit: MHz (upper 16bits)
 *              flags (lower 16bits)
 * @short_ssid: short SSID
 */
struct hint_short_ssid {
	uint32_t freq_flags;
	uint32_t short_ssid;
};

/**
 * struct hint_bssid - BSSID hint
 *  and their phymode
 * @freq_flags: freq unit: MHz (upper 16bits)
 *              flags (lower 16bits)
 * @bssid: BSSID
 */
struct hint_bssid {
	uint32_t freq_flags;
	struct qdf_mac_addr bssid;
};

/**
 * enum scan_request_type: scan type
 * @SCAN_TYPE_DEFAULT: Def scan
 * @SCAN_TYPE_P2P_SEARCH: P2P Search
 * @SCAN_TYPE_P2P_LISTEN: P2P listed
 * @SCAN_TYPE_RRM: RRM scan request
 * @SCAN_TYPE_SCAN_FOR_CONNECT : Scan for connect
 */
enum scan_request_type {
	SCAN_TYPE_DEFAULT = 0,
	SCAN_TYPE_P2P_SEARCH = 1,
	SCAN_TYPE_P2P_LISTEN = 2,
	SCAN_TYPE_RRM = 3,
	SCAN_TYPE_SCAN_FOR_CONNECT = 4
};

/**
 * struct scan_req_params - start scan request parameter
 * @scan_id: scan id
 * @scan_req_id: scan requester id
 * @vdev_id: vdev id where scan was originated
 * @pdev_id: pdev id of parent pdev
 * @scan_priority: scan priority
 * @scan_type: scan request type
 * @scan_ev_started: notify scan started event
 * @scan_ev_completed: notify scan completed event
 * @scan_ev_bss_chan: notify bss chan event
 * @scan_ev_foreign_chan: notify foreign chan event
 * @scan_ev_dequeued: notify scan request dequeued event
 * @scan_ev_preempted: notify scan preempted event
 * @scan_ev_start_failed: notify scan start failed event
 * @scan_ev_restarted: notify scan restarted event
 * @scan_ev_foreign_chn_exit: notify foreign chan exit event
 * @scan_ev_invalid: notify invalid scan request event
 * @scan_ev_gpio_timeout: notify gpio timeout event
 * @scan_ev_suspended: notify scan suspend event
 * @scan_ev_resumed: notify scan resumed event
 * @scan_events: variable to read and set scan_ev_* flags in one shot
 *               can be used to dump all scan_ev_* flags for debug
 * @dwell_time_active: active dwell time
 * @dwell_time_active_2g: active dwell time for 2G channels, if it's not zero
 * @dwell_time_passive: passive dwell time
 * @min_dwell_time_6g: 6Ghz min dwell time
 * @dwell_time_active_6g: 6Ghz active dwell time
 * @dwell_time_passive_6g: 6Ghz passive dwell time
 * @min_rest_time: min rest time
 * @max_rest_time: max rest time
 * @repeat_probe_time: repeat probe time
 * @probe_spacing_time: probe spacing time
 * @idle_time: idle time
 * @max_scan_time: max scan time
 * @probe_delay: probe delay
 * @scan_offset_time: Support split scanning on the
 *                    same channel for CBS feature.
 * @scan_f_passive: passively scan all channels including active channels
 * @scan_f_bcast_probe: add wild card ssid prbreq even if ssid_list is specified
 * @scan_f_cck_rates: add cck rates to rates/xrates ie in prb req
 * @scan_f_ofdm_rates: add ofdm rates to rates/xrates ie in prb req
 * @scan_f_chan_stat_evnt: enable indication of chan load and noise floor
 * @scan_f_filter_prb_req: filter Probe request frames
 * @scan_f_bypass_dfs_chn: when set, do not scan DFS channels
 * @scan_f_continue_on_err:continue scan even if few certain errors have occurred
 * @scan_f_offchan_mgmt_tx: allow mgmt transmission during off channel scan
 * @scan_f_offchan_data_tx: allow data transmission during off channel scan
 * @scan_f_promisc_mode: scan with promiscuous mode
 * @scan_f_capture_phy_err: enable capture ppdu with phy errors
 * @scan_f_strict_passive_pch: do passive scan on passive channels
 * @scan_f_half_rate: enable HALF (10MHz) rate support
 * @scan_f_quarter_rate: set Quarter (5MHz) rate support
 * @scan_f_force_active_dfs_chn: allow to send probe req on DFS channel
 * @scan_f_add_tpc_ie_in_probe: add TPC ie in probe req frame
 * @scan_f_add_ds_ie_in_probe: add DS ie in probe req frame
 * @scan_f_add_spoofed_mac_in_probe: use random mac address for TA in probe
 * @scan_f_add_rand_seq_in_probe: use random sequence number in probe
 * @scan_f_en_ie_allowlist_in_probe: enable ie allowlist in probe
 * @scan_f_forced: force scan even in presence of data traffic
 * @scan_f_2ghz: scan 2.4 GHz channels
 * @scan_f_5ghz: scan 5 GHz channels
 * @scan_f_wide_band: scan in 40 MHz or higher bandwidth
 * @scan_f_pause_home_channel: To pause home channel in FW when scan channel is
 * same as home channel
 * @scan_f_report_cca_busy_for_each_20mhz: Allow FW to report CCA busy for each
 * possible 20Mhz subbands of the wideband scan channel
 * @scan_flags: variable to read and set scan_f_* flags in one shot
 *              can be used to dump all scan_f_* flags for debug
 * @scan_policy_high_accuracy:
 * @scan_policy_low_span:
 * @scan_policy_low_power:
 * @scan_policy_colocated_6ghz:
 * @scan_policy_type: variable to read and set all scan_policy_* flags
 * @adaptive_dwell_time_mode:
 * @burst_duration: burst duration
 * @num_bssid: no of bssid
 * @num_ssids: no of ssid
 * @n_probes: no of probe
 * @chan_list: channel list
 * @ssid: ssid list
 * @bssid_list: Lisst of bssid to scan
 * @scan_random: scan randomization params
 * @ie_allowlist: probe req IE allowlist attrs
 * @extraie: list of optional/vendor specific ie's to be added in probe requests
 * @htcap: htcap ie
 * @vhtcap: vhtcap ie
 * @scan_ctrl_flags_ext: scan control flag extended
 * @num_hint_s_ssid: number of short SSID hints
 * @num_hint_bssid: number of BSSID hints
 * @hint_s_ssid: short SSID hints
 * @hint_bssid: BSSID hints
 * @mld_id: MLD ID of the requested BSS within ML probe request
 */
struct scan_req_params {
	uint32_t scan_id;
	uint32_t scan_req_id;
	uint32_t vdev_id;
	uint32_t pdev_id;
	enum scan_priority scan_priority;
	enum scan_request_type scan_type;
	union {
		struct {
			uint32_t scan_ev_started:1,
				 scan_ev_completed:1,
				 scan_ev_bss_chan:1,
				 scan_ev_foreign_chan:1,
				 scan_ev_dequeued:1,
				 scan_ev_preempted:1,
				 scan_ev_start_failed:1,
				 scan_ev_restarted:1,
				 scan_ev_foreign_chn_exit:1,
				 scan_ev_invalid:1,
				 scan_ev_gpio_timeout:1,
				 scan_ev_suspended:1,
				 scan_ev_resumed:1;
		};
		uint32_t scan_events;
	};
	uint32_t dwell_time_active;
	uint32_t dwell_time_active_2g;
	uint32_t dwell_time_passive;
	uint32_t min_dwell_time_6g;
	uint32_t dwell_time_active_6g;
	uint32_t dwell_time_passive_6g;
	uint32_t min_rest_time;
	uint32_t max_rest_time;
	uint32_t repeat_probe_time;
	uint32_t probe_spacing_time;
	uint32_t idle_time;
	uint32_t max_scan_time;
	uint32_t probe_delay;
	uint32_t scan_offset_time;
	union {
		struct {
			uint32_t scan_f_passive:1,
				 scan_f_bcast_probe:1,
				 scan_f_cck_rates:1,
				 scan_f_ofdm_rates:1,
				 scan_f_chan_stat_evnt:1,
				 scan_f_filter_prb_req:1,
				 scan_f_bypass_dfs_chn:1,
				 scan_f_continue_on_err:1,
				 scan_f_offchan_mgmt_tx:1,
				 scan_f_offchan_data_tx:1,
				 scan_f_promisc_mode:1,
				 scan_f_capture_phy_err:1,
				 scan_f_strict_passive_pch:1,
				 scan_f_half_rate:1,
				 scan_f_quarter_rate:1,
				 scan_f_force_active_dfs_chn:1,
				 scan_f_add_tpc_ie_in_probe:1,
				 scan_f_add_ds_ie_in_probe:1,
				 scan_f_add_spoofed_mac_in_probe:1,
				 scan_f_add_rand_seq_in_probe:1,
				 scan_f_en_ie_allowlist_in_probe:1,
				 scan_f_forced:1,
				 scan_f_2ghz:1,
				 scan_f_5ghz:1,
				 scan_f_wide_band:1,
				 scan_f_pause_home_channel:1,
				 scan_f_report_cca_busy_for_each_20mhz:1;
		};
		uint32_t scan_flags;
	};
	union {
		struct {
			uint32_t scan_policy_high_accuracy:1,
				 scan_policy_low_span:1,
				 scan_policy_low_power:1,
				 scan_policy_colocated_6ghz:1;
		};
		uint32_t scan_policy_type;
	};

	enum scan_dwelltime_adaptive_mode adaptive_dwell_time_mode;
	uint32_t burst_duration;
	uint32_t num_bssid;
	uint32_t num_ssids;
	uint32_t n_probes;
	struct chan_list chan_list;
	struct wlan_ssid ssid[WLAN_SCAN_MAX_NUM_SSID];
	struct qdf_mac_addr bssid_list[WLAN_SCAN_MAX_NUM_BSSID];
	struct scan_random_attr scan_random;
	struct probe_req_allowlist_attr ie_allowlist;
	struct element_info extraie;
	struct element_info htcap;
	struct element_info vhtcap;
	uint32_t scan_ctrl_flags_ext;
	uint32_t num_hint_s_ssid;
	uint32_t num_hint_bssid;
	struct hint_short_ssid hint_s_ssid[WLAN_SCAN_MAX_HINT_S_SSID];
	struct hint_bssid hint_bssid[WLAN_SCAN_MAX_HINT_BSSID];
	uint8_t mld_id;
};

/**
 * struct scan_start_request - scan request config
 * @vdev: vdev
 * @scan_req: common scan start request parameters
 */
struct scan_start_request {
	struct wlan_objmgr_vdev *vdev;
	struct scan_req_params scan_req;
};

/**
 * enum scan_cancel_req_type - type specifiers for cancel scan request
 * @WLAN_SCAN_CANCEL_SINGLE: cancel particular scan specified by scan_id
 * @WLAN_SCAN_CANCEL_VDEV_ALL: cancel all scans running on a particular vdevid
 * @WLAN_SCAN_CANCEL_PDEV_ALL: cancel all scans running on parent pdev of vdevid
 * @WLAN_SCAN_CANCEL_HOST_VDEV_ALL: Cancel all host triggered scans alone on
 * vdev
 */
enum scan_cancel_req_type {
	WLAN_SCAN_CANCEL_SINGLE = 1,
	WLAN_SCAN_CANCEL_VDEV_ALL,
	WLAN_SCAN_CANCEL_PDEV_ALL,
	WLAN_SCAN_CANCEL_HOST_VDEV_ALL,
};

/**
 * struct scan_cancel_param - stop scan cmd parameter
 * @requester: scan requester
 * @scan_id: scan id
 * @req_type: scan request type
 * @vdev_id: vdev id
 * @pdev_id: pdev id of parent pdev
 */
struct scan_cancel_param {
	uint32_t requester;
	uint32_t scan_id;
	enum scan_cancel_req_type req_type;
	uint32_t vdev_id;
	uint32_t pdev_id;
};

/**
 * struct scan_cancel_request - stop scan cmd
 * @vdev: vdev object
 * @wait_tgt_cancel: wait for target to cancel scan
 * @cancel_req: stop scan cmd parameter
 */
struct scan_cancel_request {
	/* Extra parameters consumed by scan module or serialization */
	struct wlan_objmgr_vdev *vdev;
	bool wait_tgt_cancel;
	/* Actual scan cancel request parameters */
	struct scan_cancel_param cancel_req;
};

/**
 * enum scan_event_type - scan event types
 * @SCAN_EVENT_TYPE_STARTED: scan started
 * @SCAN_EVENT_TYPE_COMPLETED: scan completed
 * @SCAN_EVENT_TYPE_BSS_CHANNEL: HW came back to home channel
 * @SCAN_EVENT_TYPE_FOREIGN_CHANNEL: HW moved to foreign channel
 * @SCAN_EVENT_TYPE_DEQUEUED: scan request dequeued
 * @SCAN_EVENT_TYPE_PREEMPTED: scan got preempted
 * @SCAN_EVENT_TYPE_START_FAILED: couldn't start scan
 * @SCAN_EVENT_TYPE_RESTARTED: scan restarted
 * @SCAN_EVENT_TYPE_FOREIGN_CHANNEL_EXIT: HW exited foreign channel
 * @SCAN_EVENT_TYPE_SUSPENDED: scan got suspended
 * @SCAN_EVENT_TYPE_RESUMED: scan resumed
 * @SCAN_EVENT_TYPE_NLO_COMPLETE: NLO completed
 * @SCAN_EVENT_TYPE_NLO_MATCH: NLO match event
 * @SCAN_EVENT_TYPE_INVALID: invalid request
 * @SCAN_EVENT_TYPE_GPIO_TIMEOUT: gpio timeout
 * @SCAN_EVENT_TYPE_RADIO_MEASUREMENT_START: radio measurement start
 * @SCAN_EVENT_TYPE_RADIO_MEASUREMENT_END: radio measurement end
 * @SCAN_EVENT_TYPE_BSSID_MATCH: bssid match found
 * @SCAN_EVENT_TYPE_FOREIGN_CHANNEL_GET_NF: foreign channel noise floor
 * @SCAN_EVENT_TYPE_MAX: marker for invalid event
 */
enum scan_event_type {
	SCAN_EVENT_TYPE_STARTED,
	SCAN_EVENT_TYPE_COMPLETED,
	SCAN_EVENT_TYPE_BSS_CHANNEL,
	SCAN_EVENT_TYPE_FOREIGN_CHANNEL,
	SCAN_EVENT_TYPE_DEQUEUED,
	SCAN_EVENT_TYPE_PREEMPTED,
	SCAN_EVENT_TYPE_START_FAILED,
	SCAN_EVENT_TYPE_RESTARTED,
	SCAN_EVENT_TYPE_FOREIGN_CHANNEL_EXIT,
	SCAN_EVENT_TYPE_SUSPENDED,
	SCAN_EVENT_TYPE_RESUMED,
	SCAN_EVENT_TYPE_NLO_COMPLETE,
	SCAN_EVENT_TYPE_NLO_MATCH,
	SCAN_EVENT_TYPE_INVALID,
	SCAN_EVENT_TYPE_GPIO_TIMEOUT,
	SCAN_EVENT_TYPE_RADIO_MEASUREMENT_START,
	SCAN_EVENT_TYPE_RADIO_MEASUREMENT_END,
	SCAN_EVENT_TYPE_BSSID_MATCH,
	SCAN_EVENT_TYPE_FOREIGN_CHANNEL_GET_NF,
	SCAN_EVENT_TYPE_MAX,
};

/**
 * enum scan_completion_reason - scan completion reason
 * @SCAN_REASON_NONE: un specified reason
 * @SCAN_REASON_COMPLETED: scan successfully completed
 * @SCAN_REASON_CANCELLED: scan got cancelled
 * @SCAN_REASON_PREEMPTED: scan got preempted
 * @SCAN_REASON_TIMEDOUT: couldn't complete within specified time
 * @SCAN_REASON_INTERNAL_FAILURE: cancelled because of some failure
 * @SCAN_REASON_SUSPENDED: scan suspended
 * @SCAN_REASON_RUN_FAILED: run failed
 * @SCAN_REASON_TERMINATION_FUNCTION: termination function
 * @SCAN_REASON_MAX_OFFCHAN_RETRIES: max retries exceeded threshold
 * @SCAN_REASON_DFS_VIOLATION: Scan start failure due to DFS violation.
 * @SCAN_REASON_MAX: invalid completion reason marker
 */
enum scan_completion_reason {
	SCAN_REASON_NONE,
	SCAN_REASON_COMPLETED,
	SCAN_REASON_CANCELLED,
	SCAN_REASON_PREEMPTED,
	SCAN_REASON_TIMEDOUT,
	SCAN_REASON_INTERNAL_FAILURE,
	SCAN_REASON_SUSPENDED,
	SCAN_REASON_RUN_FAILED,
	SCAN_REASON_TERMINATION_FUNCTION,
	SCAN_REASON_MAX_OFFCHAN_RETRIES,
	SCAN_REASON_DFS_VIOLATION,
	SCAN_REASON_MAX,
};

/**
 * struct scan_event - scan event definition
 * @vdev_id: vdev where scan was run
 * @type: type of scan event
 * @reason: completion reason
 * @chan_freq: channel centre frequency
 * @requester: requester id
 * @scan_id: scan id
 * @timestamp: timestamp in microsec recorded by target for the scan event
 * @scan_start_req: scan request object used to start this scan
 */
struct scan_event {
	uint32_t vdev_id;
	enum scan_event_type type;
	enum scan_completion_reason reason;
	uint32_t chan_freq;
	uint32_t requester;
	uint32_t scan_id;
	uint32_t timestamp;
	struct scan_start_request *scan_start_req;
};

/**
 * struct scan_event_info - scan event information
 * @vdev: vdev object
 * @event: scan event
 */
struct scan_event_info {
	struct wlan_objmgr_vdev *vdev;
	struct scan_event event;
};

/**
 * enum scm_scan_status - scan status
 * @SCAN_NOT_IN_PROGRESS: Neither active nor pending scan in progress
 * @SCAN_IS_ACTIVE: scan request is present only in active list
 * @SCAN_IS_PENDING: scan request is present only in pending list
 * @SCAN_IS_ACTIVE_AND_PENDING: scan request is present in active
 *                               and pending both lists
 */
enum scm_scan_status {
	SCAN_NOT_IN_PROGRESS = 0, /* Must be 0 */
	SCAN_IS_ACTIVE,
	SCAN_IS_PENDING,
	SCAN_IS_ACTIVE_AND_PENDING,
};

/**
 * typedef scan_event_handler() - function prototype of scan event handlers
 * @vdev: vdev object
 * @event: scan event
 * @arg: argument
 *
 * PROTO TYPE, scan event handler call back function prototype
 *
 * Return: void
 */
typedef void (*scan_event_handler) (struct wlan_objmgr_vdev *vdev,
	struct scan_event *event, void *arg);

/**
 * enum scan_cb_type - update beacon cb type
 * @SCAN_CB_TYPE_INFORM_BCN: Callback to indicate beacon to OS
 * @SCAN_CB_TYPE_UPDATE_BCN: Callback to indicate beacon
 * @SCAN_CB_TYPE_UNLINK_BSS: cb to unlink bss entry
 *                    to MLME and update MLME info
 *
 */
enum scan_cb_type {
	SCAN_CB_TYPE_INFORM_BCN,
	SCAN_CB_TYPE_UPDATE_BCN,
	SCAN_CB_TYPE_UNLINK_BSS,
};

/* Set PNO */
#define SCAN_PNO_MAX_PLAN_REQUEST   2
#define SCAN_PNO_MAX_NETW_CHANNELS_EX  (NUM_CHANNELS)
#define SCAN_PNO_MAX_SUPP_NETWORKS  16
#define SCAN_PNO_DEF_SLOW_SCAN_MULTIPLIER 6
#define SCAN_PNO_DEF_SCAN_TIMER_REPEAT 20
#define SCAN_PNO_MATCH_WAKE_LOCK_TIMEOUT         (5 * 1000)     /* in msec */
#define SCAN_MAX_IE_LENGTH 255
#ifdef CONFIG_SLUB_DEBUG_ON
#define SCAN_PNO_SCAN_COMPLETE_WAKE_LOCK_TIMEOUT (2 * 1000)     /* in msec */
#else
#define SCAN_PNO_SCAN_COMPLETE_WAKE_LOCK_TIMEOUT (1 * 1000)     /* in msec */
#endif /* CONFIG_SLUB_DEBUG_ON */

/**
 * enum ssid_bc_type - SSID broadcast type
 * @SSID_BC_TYPE_UNKNOWN: Broadcast unknown
 * @SSID_BC_TYPE_NORMAL: Broadcast normal
 * @SSID_BC_TYPE_HIDDEN: Broadcast hidden
 */
enum ssid_bc_type {
	SSID_BC_TYPE_UNKNOWN = 0,
	SSID_BC_TYPE_NORMAL = 1,
	SSID_BC_TYPE_HIDDEN = 2,
};

/**
 * struct pno_nw_type - pno nw type
 * @ssid: ssid
 * @authentication: authentication type
 * @encryption: encryption type
 * @bc_new_type: broadcast nw type
 * @pno_chan_list: pno channel list info
 * @rssi_thresh: rssi threshold
 */
struct pno_nw_type {
	struct wlan_ssid ssid;
	uint32_t authentication;
	uint32_t encryption;
	uint32_t bc_new_type;
	struct chan_list pno_chan_list;
	int32_t rssi_thresh;
};

/**
 * struct cpno_band_rssi_pref - BSS preference based on band and RSSI
 * @band: band preference
 * @rssi: RSSI preference
 */
struct cpno_band_rssi_pref {
	int8_t band;
	int8_t rssi;
};

/**
 * struct nlo_mawc_params - Motion Aided Wireless Connectivity based
 *                          Network List Offload configuration
 * @vdev_id: VDEV ID on which the configuration needs to be applied
 * @enable: flag to enable or disable
 * @exp_backoff_ratio: ratio of exponential backoff
 * @init_scan_interval: initial scan interval(msec)
 * @max_scan_interval:  max scan interval(msec)
 */
struct nlo_mawc_params {
	uint8_t vdev_id;
	bool enable;
	uint32_t exp_backoff_ratio;
	uint32_t init_scan_interval;
	uint32_t max_scan_interval;
};

/**
 * struct pno_scan_req_params - PNO Scan request structure
 * @vdev: vdev object
 * @networks_cnt: Number of networks
 * @do_passive_scan: Flag to request passive scan to fw
 * @vdev_id: vdev id
 * @fast_scan_period: Fast Scan period
 * @slow_scan_period: Slow scan period
 * @delay_start_time: delay in seconds to use before starting the first scan
 * @fast_scan_max_cycles: Fast scan max cycles
 * @scan_backoff_multiplier: multiply fast scan period by this after max cycles
 * @pno_channel_prediction: PNO channel prediction feature status
 * @active_dwell_time: active dwell time
 * @passive_dwell_time: passive dwell time
 * @top_k_num_of_channels: top K number of channels are used for tanimoto
 * distance calculation.
 * @stationary_thresh: threshold value to determine that the STA is stationary.
 * @adaptive_dwell_mode: adaptive dwelltime mode for pno scan
 * @channel_prediction_full_scan: periodic timer upon which a full scan needs
 * to be triggered.
 * @networks_list: Preferred network list
 * @scan_random: scan randomization params
 * @ie_allowlist: probe req IE allowlist attrs
 * @relative_rssi_set: Flag to check whether realtive_rssi is set or not
 * @relative_rssi: Relative rssi threshold, used for connected pno
 * @band_rssi_pref: Band and RSSI preference that can be given to one BSS
 *     over the other BSS
 *
 * E.g.
 *	{ fast_scan_period=120, fast_scan_max_cycles=2,
 *	  slow_scan_period=1800, scan_backoff_multiplier=2 }
 *	Result: 120s x2, 240s x2, 480s x2, 960s x2, 1800s xN
 * @mawc_params: Configuration parameters for NLO MAWC.
 * @scan_policy_colocated_6ghz: colocated_6ghz flag is set in pno scan req
 */
struct pno_scan_req_params {
	struct wlan_objmgr_vdev *vdev;
	uint32_t networks_cnt;
	bool     do_passive_scan;
	uint32_t vdev_id;
	uint32_t fast_scan_period;
	uint32_t slow_scan_period;
	uint32_t delay_start_time;
	uint32_t fast_scan_max_cycles;
	uint8_t scan_backoff_multiplier;
	uint32_t active_dwell_time;
	uint32_t passive_dwell_time;
	uint32_t pno_channel_prediction;
	uint32_t top_k_num_of_channels;
	uint32_t stationary_thresh;
	enum scan_dwelltime_adaptive_mode adaptive_dwell_mode;
	uint32_t channel_prediction_full_scan;
	struct pno_nw_type networks_list[SCAN_PNO_MAX_SUPP_NETWORKS];
	struct scan_random_attr scan_random;
	struct probe_req_allowlist_attr ie_allowlist;
	bool relative_rssi_set;
	int8_t relative_rssi;
	struct cpno_band_rssi_pref band_rssi_pref;
	struct nlo_mawc_params mawc_params;
	bool scan_policy_colocated_6ghz;
};

/**
 * struct scan_user_cfg - user configuration required for for scan
 * @ie_allowlist: probe req IE allowlist attrs
 * @sta_miracast_mcc_rest_time: sta miracast mcc rest time
 */
struct scan_user_cfg {
	struct probe_req_allowlist_attr ie_allowlist;
	uint32_t sta_miracast_mcc_rest_time;
};

/**
 * typedef update_mbssid_bcn_prb_rsp() - cb to inform mbssid beacon or prob resp
 * @frame: the pointer of frame data
 * @frame_len: the length of frame data
 * @frm_subtype: frame type
 * @bssid: the pointer of bssid
 *
 * Return: QDF_STATUS
 */
typedef QDF_STATUS (*update_mbssid_bcn_prb_rsp)(uint8_t *frame,
						uint32_t frame_len,
						uint8_t frm_subtype,
						char *bssid);

/**
 * typedef update_beacon_cb() - cb to inform/update beacon
 * @pdev: pdev pointer
 * @scan_entry:  scan entry to inform/update
 *
 * Return: void
 */
typedef void (*update_beacon_cb) (struct wlan_objmgr_pdev *pdev,
	struct scan_cache_entry *scan_entry);

/**
 * typedef scan_iterator_func() - function prototype of scan iterator function
 * @arg: extra argument
 * @scan_entry: scan entry object
 *
 * PROTO TYPE, scan iterator function prototype
 *
 * Return: QDF_STATUS
 */
typedef QDF_STATUS (*scan_iterator_func) (void *arg,
	struct scan_cache_entry *scan_entry);

/**
 * enum scan_config - scan configuration definitions
 * @SCAN_CFG_DISABLE_SCAN_COMMAND_TIMEOUT: disable scan command timeout
 * @SCAN_CFG_DROP_BCN_ON_CHANNEL_MISMATCH: config to drop beacon/probe
 *  response frames if received channel and IE channels do not match
 */
enum scan_config {
	SCAN_CFG_DISABLE_SCAN_COMMAND_TIMEOUT,
	SCAN_CFG_DROP_BCN_ON_CHANNEL_MISMATCH,
};

/**
 * enum ext_cap_bit_field - Extended capabilities bit field
 * @BSS_2040_COEX_MGMT_SUPPORT: 20/40 BSS Coexistence Management Support field
 * @OBSS_NARROW_BW_RU_IN_ULOFDMA_TOLERENT_SUPPORT: OBSS Narrow  Bandwidth RU
 *     in UL OFDMA  Tolerance Support
 */
enum ext_cap_bit_field {
	BSS_2040_COEX_MGMT_SUPPORT = 0,
	OBSS_NARROW_BW_RU_IN_ULOFDMA_TOLERENT_SUPPORT = 79,
};

/**
 * struct scan_rnr_info - RNR information
 * @timestamp: time stamp of beacon/probe
 * @short_ssid: Short SSID
 * @bssid: BSSID
 * @bss_params: bss params present in RNR IE
 */
struct scan_rnr_info {
	qdf_time_t timestamp;
	uint32_t short_ssid;
	struct qdf_mac_addr bssid;
	uint8_t bss_params;
};

/**
 * struct scan_rnr_node - Scan RNR entry node
 * @node: node pointers
 * @entry: scan RNR entry pointer
 */
struct scan_rnr_node {
	qdf_list_node_t node;
	struct scan_rnr_info entry;
};

/**
 * struct meta_rnr_channel - Channel information for scan priority algorithm
 * @chan_freq: channel frequency
 * @bss_beacon_probe_count: Beacon and probe request count
 * @saved_profile_count: Saved profile count
 * @beacon_probe_last_time_found: Timestamp of beacon/probe observed
 * @rnr_list: RNR list to store RNR IE information
 */
struct meta_rnr_channel {
	uint32_t chan_freq;
	uint32_t bss_beacon_probe_count;
	uint32_t saved_profile_count;
	qdf_time_t beacon_probe_last_time_found;
	qdf_list_t rnr_list;
};

#define RNR_UPDATE_SCAN_CNT_THRESHOLD 2
/**
 * struct channel_list_db - Database for channel information
 * @channel: channel meta information
 * @scan_count: scan count since the db was updated
 */
struct channel_list_db {
	struct meta_rnr_channel channel[NUM_6GHZ_CHANNELS];
	uint8_t scan_count;
};

/**
 * struct rnr_chan_weight - RNR channel weightage
 * @chan_freq: channel frequency
 * @weight: weightage of the channel
 * @phymode: phymode in which @frequency should be scanned
 * @flags: Flags to define channel property as defined @enum scan_flags.
 *  Firmware can use this info for different operations, e.g.: scan
 */
struct rnr_chan_weight {
	uint32_t chan_freq;
	uint32_t weight;
	enum scan_phy_mode phymode;
	enum scan_flags flags;
};

/**
 * enum trim_channel_list - which channel list need trim
 * @TRIM_CHANNEL_LIST_NONE: no channel need trim
 * @TRIM_CHANNEL_LIST_5G: 5G channel need trim
 * @TRIM_CHANNEL_LIST_24G: 2.4G channel need trim
 */
enum trim_channel_list {
	TRIM_CHANNEL_LIST_NONE,
	TRIM_CHANNEL_LIST_5G,
	TRIM_CHANNEL_LIST_24G,
};

#ifdef FEATURE_SET
/**
 * struct wlan_scan_features - Scan feature set structure
 * @pno_in_unassoc_state: is pno supported in unassoc state
 * @pno_in_assoc_state: is pno supported in assoc state
 */
struct wlan_scan_features {
	bool pno_in_unassoc_state;
	bool pno_in_assoc_state;
};
#endif
#endif
