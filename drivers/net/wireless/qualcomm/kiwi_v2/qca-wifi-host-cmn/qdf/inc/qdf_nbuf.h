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
 * DOC: qdf_nbuf_public network buffer API
 * This file defines the network buffer abstraction.
 */

#ifndef _QDF_NBUF_H
#define _QDF_NBUF_H

#include <qdf_util.h>
#include <qdf_types.h>
#include <qdf_lock.h>
#include <i_qdf_trace.h>
#include <i_qdf_nbuf.h>
#include <qdf_net_types.h>

#define IPA_NBUF_OWNER_ID			0xaa55aa55
#define QDF_NBUF_PKT_TRAC_TYPE_DNS		0x01
#define QDF_NBUF_PKT_TRAC_TYPE_EAPOL		0x02
#define QDF_NBUF_PKT_TRAC_TYPE_DHCP		0x04
#define QDF_NBUF_PKT_TRAC_TYPE_MGMT_ACTION	0x08
#define QDF_NBUF_PKT_TRAC_TYPE_ARP		0x10
#define QDF_NBUF_PKT_TRAC_TYPE_ICMP		0x20
#define QDF_NBUF_PKT_TRAC_TYPE_ICMPv6		0x40
#define QDF_HL_CREDIT_TRACKING			0x80

#define QDF_NBUF_PKT_TRAC_MAX_STRING		12
#define QDF_NBUF_PKT_TRAC_PROTO_STRING		4
#define QDF_NBUF_PKT_ERROR			1

#define QDF_NBUF_TRAC_IPV4_OFFSET		14
#define QDF_NBUF_TRAC_IPV4_HEADER_MASK		0xF
#define QDF_NBUF_TRAC_IPV4_HEADER_SIZE		20
#define QDF_NBUF_TRAC_DHCP_SRV_PORT		67
#define QDF_NBUF_TRAC_DHCP_CLI_PORT		68
#define QDF_NBUF_TRAC_ETH_TYPE_OFFSET		12
#define QDF_NBUF_TRAC_VLAN_ETH_TYPE_OFFSET	16
#define QDF_NBUF_TRAC_DOUBLE_VLAN_ETH_TYPE_OFFSET	20
#define QDF_NBUF_TRAC_EAPOL_ETH_TYPE		0x888E
#define QDF_NBUF_TRAC_WAPI_ETH_TYPE		0x88b4
#define QDF_NBUF_TRAC_ARP_ETH_TYPE		0x0806
#define QDF_NBUF_PKT_IPV4_DSCP_MASK     0xFC
#define QDF_NBUF_PKT_IPV4_DSCP_SHIFT  0x02
#define QDF_NBUF_TRAC_TDLS_ETH_TYPE		0x890D
#define QDF_NBUF_TRAC_IPV4_ETH_TYPE     0x0800
#define QDF_NBUF_TRAC_IPV6_ETH_TYPE     0x86dd
#define QDF_NBUF_DEST_MAC_OFFSET		0
#define QDF_NBUF_SRC_MAC_OFFSET			6
#define QDF_NBUF_TRAC_IPV4_TOS_OFFSET		15
#define QDF_NBUF_TRAC_IPV4_PROTO_TYPE_OFFSET  23
#define QDF_NBUF_TRAC_VLAN_IPV4_PROTO_TYPE_OFFSET  27
#define QDF_NBUF_TRAC_IPV4_DEST_ADDR_OFFSET   30
#define QDF_NBUF_TRAC_IPV4_SRC_ADDR_OFFSET    26
#define QDF_NBUF_TRAC_IPV6_PROTO_TYPE_OFFSET  20
#define QDF_NBUF_TRAC_VLAN_IPV6_PROTO_TYPE_OFFSET  24
#define QDF_NBUF_TRAC_IPV4_ADDR_MCAST_MASK    0xE0000000
#define QDF_NBUF_TRAC_IPV4_ADDR_BCAST_MASK    0xF0000000
#define QDF_NBUF_TRAC_IPV6_DEST_ADDR_OFFSET   38
#define QDF_NBUF_TRAC_IPV6_DEST_ADDR          0xFF00
#define QDF_NBUF_TRAC_IPV6_OFFSET		14
#define QDF_NBUF_TRAC_VLAN_IPV6_OFFSET		18
#define QDF_NBUF_TRAC_IPV6_HEADER_SIZE   40
#define QDF_NBUF_TRAC_ICMP_TYPE         1
#define QDF_NBUF_TRAC_IGMP_TYPE         2
#define QDF_NBUF_TRAC_TCP_TYPE          6
#define QDF_NBUF_TRAC_TCP_FLAGS_OFFSET       (47 - 34)
#define QDF_NBUF_TRAC_TCP_ACK_OFFSET         (42 - 34)
#define QDF_NBUF_TRAC_TCP_HEADER_LEN_OFFSET  (46 - 34)
#define QDF_NBUF_TRAC_TCP_ACK_MASK           0x10
#define QDF_NBUF_TRAC_TCP_SPORT_OFFSET       (34 - 34)
#define QDF_NBUF_TRAC_TCP_DPORT_OFFSET       (36 - 34)
#define QDF_NBUF_TRAC_UDP_TYPE          17
#define QDF_NBUF_TRAC_ICMPV6_TYPE       0x3a
#define QDF_NBUF_TRAC_HOPOPTS_TYPE      0
#define QDF_NBUF_TRAC_DHCP6_SRV_PORT		547
#define QDF_NBUF_TRAC_DHCP6_CLI_PORT		546
#define QDF_NBUF_TRAC_MDNS_SRC_N_DST_PORT	5353
#define QDF_NBUF_TRAC_IP_OFFSET		14
#define QDF_NBUF_TRAC_VLAN_IP_OFFSET		18
#define QDF_NBUF_TRAC_DOUBLE_VLAN_IP_OFFSET	22
/* One dword for IPv4 header size unit */
#define QDF_NBUF_IPV4_HDR_SIZE_UNIT	4
#define QDF_NBUF_TRAC_IPV4_TOTAL_LEN_OFFSET 16
#define QDF_NBUF_TRAC_IPV6_PAYLOAD_LEN_OFFSET 18

/* EAPOL Related MASK */
#define EAPOL_PACKET_TYPE_OFFSET		15
#define EAPOL_KEY_INFO_OFFSET			19
#define EAPOL_PKT_LEN_OFFSET			16
#define EAPOL_KEY_LEN_OFFSET			21
#define EAPOL_KEY_DATA_LENGTH_OFFSET		111
#define EAPOL_WPA_KEY_NONCE_OFFSET		31

#define EAPOL_PACKET_TYPE_EAP                   0
#define EAPOL_PACKET_TYPE_START                 1
#define EAPOL_PACKET_TYPE_LOGOFF                2
#define EAPOL_PACKET_TYPE_KEY                   3
#define EAPOL_PACKET_TYPE_ASF			4

#define EAPOL_KEY_TYPE_MASK			0x0800
#define EAPOL_KEY_ENCRYPTED_MASK		0x0010

/* EAP Related Mask */

#define EAP_CODE_OFFSET				18
#define EAP_LENGTH_OFFSET			20
#define EAP_TYPE_OFFSET				22
#define QDF_EAP_REQUEST				1
#define QDF_EAP_RESPONSE			2
#define QDF_EAP_SUCCESS				3
#define QDF_EAP_FAILURE				4
#define QDF_EAP_INITIATE			5
#define QDF_EAP_FINISH				6

#define EAP_PACKET_TYPE_ID 0x01
#define EAP_PACKET_TYPE_EXP 0xFE

#define EAP_EXP_TYPE_WSC_START 0x01
#define EAP_EXP_TYPE_M1 0x04
#define EAP_EXP_TYPE_M2 0x05
#define EAP_EXP_TYPE_M3 0x07
#define EAP_EXP_TYPE_M4 0x08
#define EAP_EXP_TYPE_M5 0x09
#define EAP_EXP_TYPE_M6 0x0A
#define EAP_EXP_TYPE_M7 0x0B
#define EAP_EXP_TYPE_M8 0x0C
#define EAP_EXP_TYPE_WSC_DONE 0x0F

#define EAP_EXP_MSG_OPCODE_OFFSET 0x1E
#define EAP_EXP_MSG_TYPE_OFFSET 0x29

enum wsc_op_code {
	WSC_UPNP = 0, /* No OP Code in UPnP transport */
	WSC_START = 0x01,
	WSC_ACK = 0x02,
	WSC_NACK = 0x03,
	WSC_MSG = 0x04,
	WSC_DONE = 0x05,
	WSC_FRAG_ACK = 0x06
};

/* ARP Related MASK */
#define QDF_NBUF_PKT_ARP_OPCODE_OFFSET	20
#define QDF_NBUF_PKT_ARPOP_REQ		1
#define QDF_NBUF_PKT_ARPOP_REPLY	2
#define QDF_NBUF_PKT_ARP_SRC_IP_OFFSET	28
#define QDF_NBUF_PKT_ARP_TGT_IP_OFFSET	38

/* ICMPv4 Related MASK */
#define QDF_NBUF_PKT_ICMPv4_OPCODE_OFFSET	34
#define QDF_NBUF_PKT_ICMPv4OP_REQ		0x08
#define QDF_NBUF_PKT_ICMPv4OP_REPLY		0x00
#define QDF_NBUF_PKT_ICMPv4_SRC_IP_OFFSET	26
#define QDF_NBUF_PKT_ICMPv4_TGT_IP_OFFSET	30
#define QDF_NBUF_PKT_ICMPV4_REDIRECT		0x05

/* TCP Related MASK */
#define QDF_NBUF_PKT_TCP_OPCODE_OFFSET		47
#define QDF_NBUF_PKT_TCPOP_SYN			0x02
#define QDF_NBUF_PKT_TCPOP_SYN_ACK		0x12
#define QDF_NBUF_PKT_TCPOP_ACK			0x10
#define QDF_NBUF_PKT_TCP_SRC_PORT_OFFSET	34
#define QDF_NBUF_PKT_TCP_DST_PORT_OFFSET	36
#define QDF_NBUF_PKT_IPV4_TCP_HDR_LEN_OFFSET 46
#define QDF_NBUF_PKT_IPV4_TCP_OPCODE_OFFSET 47
#define QDF_NBUF_PKT_IPV6_TCP_HDR_LEN_OFFSET 66
#define QDF_NBUF_PKT_IPV6_TCP_OPCODE_OFFSET 67
#define QDF_NBUF_PKT_TCP_HDR_LEN_MASK 0xF0
#define QDF_NBUF_PKT_TCP_HDR_LEN_LSB 4
#define QDF_NBUF_PKT_TCP_HDR_LEN_UNIT 4
#define QDF_NBUF_PKT_TCP_ACK_MAX_LEN 100

/* DNS Related MASK */
#define QDF_NBUF_PKT_DNS_OVER_UDP_OPCODE_OFFSET	44
#define QDF_NBUF_PKT_DNSOP_BITMAP		0xF800
#define QDF_NBUF_PKT_DNSOP_STANDARD_QUERY	0x0000
#define QDF_NBUF_PKT_DNSOP_STANDARD_RESPONSE	0x8000
#define QDF_NBUF_PKT_DNS_SRC_PORT_OFFSET	34
#define QDF_NBUF_PKT_DNS_DST_PORT_OFFSET	36
#define QDF_NBUF_PKT_DNS_NAME_OVER_UDP_OFFSET	54
#define QDF_NBUF_PKT_DNS_STANDARD_PORT		53

/* Tracked Packet types */
#define QDF_NBUF_TX_PKT_INVALID              0
#define QDF_NBUF_TX_PKT_DATA_TRACK           1
#define QDF_NBUF_TX_PKT_MGMT_TRACK           2
#define QDF_NBUF_RX_PKT_DATA_TRACK           3

/* Different Packet states */
#define QDF_NBUF_TX_PKT_HDD                  1
#define QDF_NBUF_TX_PKT_TXRX_ENQUEUE         2
#define QDF_NBUF_TX_PKT_TXRX_DEQUEUE         3
#define QDF_NBUF_TX_PKT_TXRX                 4
#define QDF_NBUF_TX_PKT_HTT                  5
#define QDF_NBUF_TX_PKT_HTC                  6
#define QDF_NBUF_TX_PKT_HIF                  7
#define QDF_NBUF_TX_PKT_CE                   8
#define QDF_NBUF_TX_PKT_FREE                 9
#define QDF_NBUF_TX_PKT_LI_DP                10
#define QDF_NBUF_TX_PKT_DP                   11
#define QDF_NBUF_TX_PKT_STATE_MAX            12

/* nbuf allocations only come from one domain */
#define QDF_DEBUG_NBUF_DOMAIN		     0

/* qdf_nbuf allocate and map max retry threshold when failed */
#define QDF_NBUF_ALLOC_MAP_RETRY_THRESHOLD      20

/* Enable flag to print TSO specific prints in datapath */
#ifdef TSO_DEBUG_LOG_ENABLE
#define TSO_DEBUG(fmt, args ...) \
	QDF_TRACE(QDF_MODULE_ID_DP, QDF_TRACE_LEVEL_NONE, \
		fmt, ## args)
#else
#define TSO_DEBUG(fmt, args ...)
#endif

#define IEEE80211_AMPDU_FLAG    0x01

#ifdef GET_MSDU_AGGREGATION
#define IEEE80211_AMSDU_FLAG    0x02
#endif

#define MAX_CHAIN 8
#define QDF_MON_STATUS_MPDU_FCS_BMAP_NWORDS 8

#define EHT_USER_INFO_LEN 4

/**
 * typedef qdf_nbuf_queue_t - Platform independent packet queue abstraction
 */
typedef __qdf_nbuf_queue_t qdf_nbuf_queue_t;

/*
 * This is the length for radiotap, combined length
 * (Mandatory part struct ieee80211_radiotap_header + RADIOTAP_HEADER_LEN)
 * cannot be more than available headroom_sz.
 * increase this when we add more radiotap elements.
 * Number after '+' indicates maximum possible increase due to alignment
 */
#define RADIOTAP_TX_FLAGS_LEN (2 + 1)
#define RADIOTAP_VHT_FLAGS_LEN (12 + 1)
#define RADIOTAP_HE_FLAGS_LEN (12 + 1)
#define RADIOTAP_HE_MU_FLAGS_LEN (8 + 1)
#define RADIOTAP_HE_MU_OTHER_FLAGS_LEN (18 + 1)
#define RADIOTAP_U_SIG_FLAGS_LEN (12 + 3)
#define RADIOTAP_EHT_FLAGS_LEN (32 + 3)
#define RADIOTAP_FIXED_HEADER_LEN 17
#define RADIOTAP_HT_FLAGS_LEN 3
#define RADIOTAP_AMPDU_STATUS_LEN (8 + 3)
#define RADIOTAP_VENDOR_NS_LEN \
	(sizeof(struct qdf_radiotap_vendor_ns_ath) + 1)
/* This is Radio Tap Header Extension Length.
 * 4 Bytes for Extended it_present bit map +
 * 4 bytes padding for alignment
 */
#define RADIOTAP_HEADER_EXT_LEN (2 * sizeof(uint32_t))
#define RADIOTAP_HEADER_EXT2_LEN \
	(sizeof(struct qdf_radiotap_ext2))
#define RADIOTAP_HEADER_LEN (RADIOTAP_BASE_HEADER_LEN + \
				RADIOTAP_FIXED_HEADER_LEN + \
				RADIOTAP_TX_FLAGS_LEN + \
				RADIOTAP_HT_FLAGS_LEN + \
				RADIOTAP_VHT_FLAGS_LEN + \
				RADIOTAP_AMPDU_STATUS_LEN + \
				RADIOTAP_HE_FLAGS_LEN + \
				RADIOTAP_HE_MU_FLAGS_LEN + \
				RADIOTAP_HE_MU_OTHER_FLAGS_LEN + \
				RADIOTAP_VENDOR_NS_LEN + \
				RADIOTAP_HEADER_EXT_LEN + \
				RADIOTAP_HEADER_EXT2_LEN + \
				RADIOTAP_U_SIG_FLAGS_LEN + \
				RADIOTAP_EHT_FLAGS_LEN)

/**
 * struct mon_rx_status - This will have monitor mode rx_status extracted from
 * htt_rx_desc used later to update radiotap information.
 * @tsft: Time Synchronization Function timer
 * @ppdu_timestamp: Timestamp in the PPDU_START TLV
 * @chan_freq: Capture channel frequency
 * @chan_num: Capture channel number
 * @chan_flags: Bitmap of Channel flags, IEEE80211_CHAN_TURBO,
 *              IEEE80211_CHAN_CCK...
 * @ht_flags: HT flags, only present for HT frames.
 * @vht_flags: VHT flags, only present for VHT frames.
 * @vht_flag_values1-5: Contains corresponding data for flags field
 * @he_flags: HE (11ax) flags, only present in HE frames
 * @he_mu_flags: HE-MU (11ax) flags, only present in HE frames
 * @he_mu_other_flags: HE-MU-OTHER (11ax) flags, only present in HE frames
 * @usig_flags: USIG flags, only present in 802.11BE and subsequent protocol
 * @eht_flags: EHT (11be) flags, only present in EHT frames
 * @nr_ant: Number of Antennas used for streaming
 * @mcs: MCS index of Rx frame
 * @nss: Number of spatial streams
 * @bw: bandwidth of rx frame
 * @is_stbc: Is STBC enabled
 * @sgi: Rx frame short guard interval
 * @he_re: HE range extension
 * @ldpc: ldpc enabled
 * @beamformed: Is frame beamformed.
 * @dcm: dcm
 * @preamble_type: Preamble type in radio header
 * @tid: QoS traffic tid number
 * @rs_fcs_err: FCS error flag
 * @cck_flag: Flag to indicate CCK modulation
 * @ofdm_flag: Flag to indicate OFDM modulation
 * @ulofdma_flag: Flag to indicate UL OFDMA PPDU
 * @monitor_direct_used: monitor direct mode
 * @data_sequence_control_info_valid: field to indicate validity of seq control
 * @rxpcu_filter_pass: Flag which indicates whether RX packets are received in
 *						BSS mode(not in promisc mode)
 * @add_rtap_ext: add radio tap extension
 * @frame_control_info_valid: field indicates if fc value is valid
 * @add_rtap_ext2: add radiotap extension2
 * @reception_type: PPDU reception type
 * @ltf_size: ltf size
 * @tx_status: packet tx status
 * @mu_dl_ul: MU down or up link, 0 downlink, 1 uplink
 * @rx_antenna: rx antenna
 * @vht_flag_values6: VHT flag value6
 * @he_mu_other_flags: HE MU other flag
 * @he_sig_b_common: HE (11ax) sig B common field
 * @he_sig_b_common_known: HE (11ax) sig B common known field
 * @l_sig_a_info: L_SIG_A value coming in Rx descriptor
 * @l_sig_b_info: L_SIG_B value coming in Rx descriptor
 * @num_eht_user_info_valid: Number of valid EHT user info
 * @rate: Rate in terms 500Kbps
 * @rtap_flags: Bit map of available fields in the radiotap
 * @ant_signal_db: Rx packet RSSI
 * @ht_mcs: MCS index for HT RX frames
 * @tcp_msdu_count: TCP MSDU Count
 * @udp_msdu_count: UDP MSDU Count
 * @other_msdu_count: Other MSDU Count
 * @vht_flag_values1: VHT flag value 1
 * @vht_flag_values2: VHT flag value 2
 * @vht_flag_values3: VHT flag value 3
 * @vht_flag_values4: VHT flag value 4
 * @vht_flag_values5: VHT flag value 5
 * @he_sig_b_common_RU: HE (11ax) common RU assignment index
 * @rssi_comb: Combined RSSI
 * @rssi: 8 bits RSSI per 20 MHz per chain
 * @duration: 802.11 Duration
 * @frame_control: frame control field
 * @ast_index: AST table hash index
 * @rs_flags: Flags to indicate AMPDU or AMSDU aggregation
 * @he_per_user_1: HE per user info1
 * @he_per_user_2: HE per user info2
 * @he_per_user_position: HE per user position info
 * @he_per_user_known: HE per user known info
 * @he_flags1: HE flags
 * @he_flags2: HE flags
 * @he_RU: HE RU assignment index
 * @he_data1: HE property of received frame
 * @he_data2: HE property of received frame
 * @he_data3: HE property of received frame
 * @he_data4: HE property of received frame
 * @he_data5: HE property of received frame
 * @he_data6: HE property of received frame
 * @ppdu_len: PPDU length
 * @prev_ppdu_id: ppdu_id in previously received message
 * @ppdu_id: Id of the PLCP protocol data unit
 *
 * The following variables are not coming from the TLVs.
 * These variables are placeholders for passing information to update_radiotap
 * function.
 * @device_id: Device ID coming from sub-system (PCI, AHB etc..)
 * @chan_noise_floor: Channel Noise Floor for the pdev
 * @first_data_seq_ctrl: Sequence ctrl field of first data frame
 * @rssi_chain: Rssi chain per nss per bw
 * @tx_retry_cnt: tx retry count
 * @start_seq: starting sequence number
 * @ba_bitmap: 256 bit block ack bitmap
 * @mpdu_retry_cnt: Rx mpdu retry count
 * @punctured_pattern: punctured pattern (0 means the band is punctured)
 * @usig_common: U-SIG property of received frame
 * @usig_value: U-SIG property of received frame
 * @usig_mask: U-SIG property of received frame
 * @eht_known: EHT property of received frame
 * @eht_data: EHT property of received frame
 * @eht_user_info: EHT USER property of received frame
 * @phyrx_abort: phy aborted undecoded frame indication
 * @phyrx_abort_reason: abort reason in phyrx_abort_request_info
 * @vht_crc: vht crc
 * @vht_no_txop_ps: TXOP power save mode
 * @he_crc: he crc
 * @l_sig_length: L SIG A length
 * @l_sig_a_parity: L SIG A parity
 * @l_sig_a_pkt_type: L SIG A info pkt type
 * @l_sig_a_implicit_sounding: L SIG A info captured implicit sounding
 * @ht_length: num of bytes in PSDU
 * @smoothing: Indicate smoothing
 * @not_sounding: Indicate sounding
 * @aggregation: Indicate A-MPDU format
 * @ht_stbc: Indicate stbc
 * @ht_crc: ht crc
 * @rx_user_status: pointer to mon_rx_user_status, when set update
 * @rssi_offset: This offset value will use for RSSI db to dbm conversion
 * @rssi_dbm_conv_support: Rssi dbm conversion support param
 * radiotap header will use userinfo from this structure.
 */
struct mon_rx_status {
	uint64_t tsft;
	uint32_t ppdu_timestamp;
	qdf_freq_t chan_freq;
	uint16_t chan_num;
	uint16_t chan_flags;
	uint32_t ht_flags : 1,
		 vht_flags : 1,
		 he_flags : 1,
		 he_mu_flags : 1,
		 usig_flags : 1,
		 eht_flags : 1,
		 nr_ant : 3,
		 mcs : 4,
		 nss : 3,
		 bw : 4,
		 is_stbc : 1,
		 sgi : 2,
		 he_re : 1,
		 ldpc : 1,
		 beamformed : 1,
		 dcm : 1,
		 preamble_type : 4;
	uint32_t tid : 5,
		 rs_fcs_err : 1,
		 cck_flag : 1,
		 ofdm_flag : 1,
		 ulofdma_flag : 1,
		 monitor_direct_used : 1,
		 data_sequence_control_info_valid : 1,
		 rxpcu_filter_pass : 1,
		 add_rtap_ext : 1,
		 frame_control_info_valid : 1,
		 add_rtap_ext2 : 1,
		 reception_type : 4,
		 ltf_size : 2,
		 tx_status : 4,
		 mu_dl_ul : 1;
	uint32_t rx_antenna : 24;
	uint16_t vht_flag_values6;
	uint16_t he_mu_other_flags;
	uint16_t he_sig_b_common;
	uint16_t he_sig_b_common_known;
	uint32_t l_sig_a_info;
	uint32_t l_sig_b_info;
	uint8_t  num_eht_user_info_valid;
	uint8_t  rate;
	uint8_t  rtap_flags;
	uint8_t  ant_signal_db;
	uint8_t  ht_mcs;
	uint16_t  tcp_msdu_count;
	uint16_t  udp_msdu_count;
	uint16_t  other_msdu_count;
	uint8_t  vht_flag_values1;
	uint8_t  vht_flag_values2;
	uint8_t  vht_flag_values3[4];
	uint8_t  vht_flag_values4;
	uint8_t  vht_flag_values5;
	uint8_t  he_sig_b_common_RU[4];
	int8_t   rssi_comb;
	int8_t rssi[MAX_CHAIN];
	uint16_t duration;
	uint16_t frame_control;
	uint16_t ast_index;
	uint8_t      rs_flags;
	/* New HE radiotap fields */
	uint16_t he_per_user_1;
	uint16_t he_per_user_2;
	uint8_t he_per_user_position;
	uint8_t he_per_user_known;
	uint16_t he_flags1;
	uint16_t he_flags2;
	uint8_t he_RU[8];
	uint16_t he_data1;
	uint16_t he_data2;
	uint16_t he_data3;
	uint16_t he_data4;
	uint16_t he_data5;
	uint16_t he_data6;
	uint32_t ppdu_len;
	uint16_t prev_ppdu_id;
	uint16_t ppdu_id;
	uint16_t device_id;
	int16_t chan_noise_floor;
	uint16_t first_data_seq_ctrl;
	int8_t rssi_chain[8][8];
	uint8_t  tx_retry_cnt;
	uint16_t start_seq;
	uint32_t ba_bitmap[8];
	uint16_t mpdu_retry_cnt;
#ifdef WLAN_FEATURE_11BE
	uint16_t punctured_pattern;
#endif
	uint32_t usig_common;
	uint32_t usig_value;
	uint32_t usig_mask;
	uint32_t eht_known;
	uint32_t eht_data[6];
	uint32_t eht_user_info[EHT_USER_INFO_LEN];
#ifdef QCA_UNDECODED_METADATA_SUPPORT
	uint32_t phyrx_abort:1,
		 phyrx_abort_reason:8,
		 vht_crc:8,
		 vht_no_txop_ps:1,
		 he_crc:4;
	uint32_t l_sig_length:12,
		 l_sig_a_parity:1,
		 l_sig_a_pkt_type:4,
		 l_sig_a_implicit_sounding:1;
	uint32_t ht_length:16,
		 smoothing:1,
		 not_sounding:1,
		 aggregation:1,
		 ht_stbc:2,
		 ht_crc:8;
#endif
	struct mon_rx_user_status *rx_user_status;
	int32_t rssi_offset;
	bool rssi_dbm_conv_support;
};

/**
 * struct mon_rx_user_status - This will have monitor mode per user rx_status
 * extracted from hardware TLV.
 * @mcs: MCS index of Rx frame
 * @nss: Number of spatial streams
 * @mu_ul_info_valid: MU UL info below is valid
 * @ofdma_ru_start_index: OFDMA RU start index
 * @ofdma_ru_width: OFDMA total RU width
 * @ofdma_ru_size: OFDMA RU size index
 * @is_ampdu: AMPDU flag
 * @mu_ul_user_v0_word0: MU UL user info word 0
 * @mu_ul_user_v0_word1: MU UL user info word 1
 * @ast_index: AST table hash index
 * @sw_peer_id: software peer id
 * @tid: QoS traffic tid number
 * @preamble_type: Preamble type in radio header
 * @ht_flags: HT flags, only present for HT frames.
 * @vht_flags: VHT flags, only present for VHT frames.
 * @he_flags: HE (11ax) flags, only present in HE frames
 * @frame_control_info_valid: field indicates if fc value is valid
 * @frame_control: frame control field
 * @data_sequence_control_info_valid: field to indicate validity of seq control
 * @ba_bitmap_sz: blockack bitmap size
 * @filter_category: mpdu filter category
 * @tcp_msdu_count: tcp protocol msdu count
 * @udp_msdu_count: udp protocol msdu count
 * @other_msdu_count: other protocol msdu count
 * @first_data_seq_ctrl: Sequence ctrl field of first data frame
 * @duration: 802.11 Duration
 * @vht_flag_values2: Contains corresponding data for flags field
 * @vht_flag_values3: Contains corresponding data for flags field
 * @vht_flag_values4: Contains corresponding data for flags field
 * @vht_flag_values5: Contains corresponding data for flags field
 * @vht_flag_values6: Contains corresponding data for flags field
 * @he_flags1: HE flags
 * @he_flags2: HE flags
 * @he_RU: HE RU assignment index
 * @he_data1: HE property of received frame
 * @he_data2: HE property of received frame
 * @he_data3: HE property of received frame
 * @he_data4: HE property of received frame
 * @he_data5: HE property of received frame
 * @he_data6: HE property of received frame
 * @he_per_user_1: HE per user info1
 * @he_per_user_2: HE per user info2
 * @he_per_user_position: HE per user position info
 * @he_per_user_known: HE per user known info
 * @rtap_flags: Bit map of available fields in the radiotap
 * @rs_flags: Flags to indicate AMPDU or AMSDU aggregation
 * @mpdu_cnt_fcs_ok: mpdu count received with fcs ok
 * @mpdu_cnt_fcs_err: mpdu count received with fcs ok bitmap
 * @mpdu_fcs_ok_bitmap: mpdu with fcs ok bitmap
 * @mpdu_ok_byte_count: mpdu byte count with fcs ok
 * @mpdu_err_byte_count: mpdu byte count with fcs err
 * @retry_mpdu: mpdu retry count
 * @start_seq: starting sequence number
 * @ba_control: Block ack control
 * @ba_bitmap: 256 bit block ack bitmap
 * @aid: Association ID
 * @mpdu_q: user mpdu_queue used for monitor
 */
struct mon_rx_user_status {
	uint32_t mcs:4,
		 nss:3,
		 mu_ul_info_valid:1,
		 ofdma_ru_start_index:7,
		 ofdma_ru_width:7,
		 ofdma_ru_size:8,
		 is_ampdu:1;
	uint32_t mu_ul_user_v0_word0;
	uint32_t mu_ul_user_v0_word1;
	uint32_t ast_index : 16,
		 sw_peer_id : 16;
	uint32_t tid : 4,
		 preamble_type : 4,
		 ht_flags : 1,
		 vht_flags : 1,
		 he_flags : 1,
		 frame_control_info_valid : 1,
		 frame_control : 16,
		 data_sequence_control_info_valid : 1,
		 ba_bitmap_sz : 2,
		 filter_category : 2;
	uint16_t tcp_msdu_count;
	uint16_t udp_msdu_count;
	uint16_t other_msdu_count;
	uint16_t first_data_seq_ctrl;
	uint16_t duration;
	uint8_t  vht_flag_values2;
	uint8_t  vht_flag_values3[4];
	uint8_t  vht_flag_values4;
	uint8_t  vht_flag_values5;
	uint16_t vht_flag_values6;
	uint16_t he_flags1;
	uint16_t he_flags2;
	uint8_t he_RU[8];
	uint16_t he_data1;
	uint16_t he_data2;
	uint16_t he_data3;
	uint16_t he_data4;
	uint16_t he_data5;
	uint16_t he_data6;
	uint8_t he_per_user_1;
	uint8_t he_per_user_2;
	uint8_t he_per_user_position;
	uint8_t he_per_user_known;
	uint8_t rtap_flags;
	uint8_t rs_flags;
	uint16_t mpdu_cnt_fcs_ok;
	uint8_t mpdu_cnt_fcs_err;
	uint32_t mpdu_fcs_ok_bitmap[QDF_MON_STATUS_MPDU_FCS_BMAP_NWORDS];
	uint32_t mpdu_ok_byte_count;
	uint32_t mpdu_err_byte_count;
	uint16_t retry_mpdu;
	uint16_t start_seq;
	uint16_t ba_control;
	uint32_t ba_bitmap[8];
	uint16_t aid;
	qdf_nbuf_queue_t mpdu_q;
};

/**
 * struct qdf_radiotap_vendor_ns - Vendor Namespace header as per
 * Radiotap spec: https://www.radiotap.org/fields/Vendor%20Namespace.html
 * @oui: Vendor OUI
 * @selector: sub_namespace selector
 * @skip_length: How many bytes of Vendor Namespace data that follows
 */
struct qdf_radiotap_vendor_ns {
	uint8_t oui[3];
	uint8_t selector;
	uint16_t skip_length;
} __attribute__((__packed__));

/**
 * struct qdf_radiotap_vendor_ns_ath - Combined QTI Vendor NS
 * including the Radiotap specified Vendor Namespace header and
 * QTI specific Vendor Namespace data
 * @hdr: radiotap vendor namespace header
 * @lsig: L_SIG_A (or L_SIG)
 * @device_id: Device Identification
 * @lsig_b: L_SIG_B
 * @ppdu_start_timestamp: Timestamp from RX_PPDU_START TLV
 */
struct qdf_radiotap_vendor_ns_ath {
	struct qdf_radiotap_vendor_ns hdr;
	/* QTI specific data follows */
	uint32_t lsig;
	uint32_t device_id;
	uint32_t lsig_b;
	uint32_t ppdu_start_timestamp;
} __attribute__((__packed__));

/**
 * struct qdf_radiotap_ext2 - radiotap ext2 fields
 * @ppdu_id: ppdu_id of current msdu
 * @prev_ppdu_id: ppdu_id of previous msdu
 * @tid: tid number of previous msdu
 * @reserved: reserved bits
 * @start_seq: start sequence of previous msdu
 * @ba_bitmap: block ack bitmap of previous msdu
 */
struct qdf_radiotap_ext2 {
	uint32_t ppdu_id;
	uint32_t prev_ppdu_id;
	uint16_t tid:8,
		 reserved:8;
	uint16_t start_seq;
	uint32_t ba_bitmap[8];
} __attribute__((__packed__));

#define QDF_MEM_FUNC_NAME_SIZE 48

/* Masks for HE SIG known fields in mon_rx_status structure */
#define QDF_MON_STATUS_HE_SIG_B_COMMON_KNOWN_RU0	0x00000001
#define QDF_MON_STATUS_HE_SIG_B_COMMON_KNOWN_RU1	0x00000002
#define QDF_MON_STATUS_HE_SIG_B_COMMON_KNOWN_RU2	0x00000004
#define QDF_MON_STATUS_HE_SIG_B_COMMON_KNOWN_RU3	0x00000008
#define QDF_MON_STATUS_HE_SIG_B_USER_KNOWN_SIG_B_ALL   0x00fe0000
#define QDF_MON_STATUS_HE_SIG_A1_HE_FORMAT_SU		0x00000000
#define QDF_MON_STATUS_HE_SIG_A1_HE_FORMAT_EXT_SU	0x40000000
#define QDF_MON_STATUS_HE_SIG_A1_HE_FORMAT_TRIG		0xc0000000

/* DHCP Related Mask */
#define QDF_DHCP_OPTION53			(0x35)
#define QDF_DHCP_OPTION53_LENGTH		(1)
#define QDF_DHCP_OPTION53_OFFSET		(0x11A)
#define QDF_DHCP_OPTION53_LENGTH_OFFSET	(0x11B)
#define QDF_DHCP_OPTION53_STATUS_OFFSET	(0x11C)
#define DHCP_PKT_LEN_OFFSET           16
#define DHCP_TRANSACTION_ID_OFFSET    46
#define QDF_DHCP_DISCOVER			(1)
#define QDF_DHCP_OFFER				(2)
#define QDF_DHCP_REQUEST			(3)
#define QDF_DHCP_DECLINE			(4)
#define QDF_DHCP_ACK				(5)
#define QDF_DHCP_NAK				(6)
#define QDF_DHCP_RELEASE			(7)
#define QDF_DHCP_INFORM				(8)

/* ARP Related Mask */
#define ARP_SUB_TYPE_OFFSET  20
#define ARP_REQUEST			(1)
#define ARP_RESPONSE		(2)

/* IPV4 header fields offset values */
#define IPV4_PKT_LEN_OFFSET           16
#define IPV4_TCP_SEQ_NUM_OFFSET       38
#define IPV4_SRC_ADDR_OFFSET          26
#define IPV4_DST_ADDR_OFFSET          30
#define IPV4_SRC_PORT_OFFSET          34
#define IPV4_DST_PORT_OFFSET          36

/* IPV4 ICMP Related Mask */
#define ICMP_ID_OFFSET                38
#define ICMP_SEQ_NUM_OFFSET           40
#define ICMP_SUBTYPE_OFFSET           34
#define ICMP_REQUEST                  0x08
#define ICMP_RESPONSE                 0x00

#define IPV6_ADDR_STR "%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:"\
			"%02x%02x:%02x%02x"

/* IPV6 header fields offset values */
#define IPV6_PKT_LEN_OFFSET           18
#define IPV6_TCP_SEQ_NUM_OFFSET       58
#define IPV6_SRC_ADDR_OFFSET          22
#define IPV6_DST_ADDR_OFFSET          38
#define IPV6_SRC_PORT_OFFSET          54
#define IPV6_DST_PORT_OFFSET          56

/* IPV6 ICMPV6 Related Mask */
#define ICMPV6_REDIRECT               137
#define ICMPV6_SEQ_NUM_OFFSET         60
#define ICMPV6_SUBTYPE_OFFSET         54
#define ICMPV6_REQUEST                0x80
#define ICMPV6_RESPONSE               0x81
#define ICMPV6_RS                     0x85
#define ICMPV6_RA                     0x86
#define ICMPV6_NS                     0x87
#define ICMPV6_NA                     0x88

#define QDF_NBUF_IPA_CHECK_MASK		0x80000000

/* HE Radiotap data1 Mask */
#define QDF_MON_STATUS_HE_SU_FORMAT_TYPE 0x0000
#define QDF_MON_STATUS_HE_EXT_SU_FORMAT_TYPE 0x0001
#define QDF_MON_STATUS_HE_MU_FORMAT_TYPE 0x0002
#define QDF_MON_STATUS_HE_TRIG_FORMAT_TYPE 0x0003


#define QDF_MON_STATUS_HE_BEAM_CHANGE_KNOWN 0x0008
#define QDF_MON_STATUS_HE_DL_UL_KNOWN 0x0010
#define QDF_MON_STATUS_HE_MCS_KNOWN 0x0020
#define QDF_MON_STATUS_HE_DCM_KNOWN 0x0040
#define QDF_MON_STATUS_HE_CODING_KNOWN 0x0080
#define QDF_MON_STATUS_HE_LDPC_EXTRA_SYMBOL_KNOWN 0x0100
#define QDF_MON_STATUS_HE_STBC_KNOWN 0x0200
#define QDF_MON_STATUS_HE_SPATIAL_REUSE_1_KNOWN 0x0400
#define QDF_MON_STATUS_HE_SPATIAL_REUSE_2_KNOWN 0x0800
#define QDF_MON_STATUS_HE_SPATIAL_REUSE_3_KNOWN 0x1000
#define QDF_MON_STATUS_HE_SPATIAL_REUSE_4_KNOWN 0x2000
#define QDF_MON_STATUS_HE_DATA_BW_RU_KNOWN 0x4000
#define QDF_MON_STATUS_HE_DOPPLER_KNOWN 0x8000
#define QDF_MON_STATUS_HE_BSS_COLOR_KNOWN 0x0004

/* HE Radiotap data2 Mask */
#define QDF_MON_STATUS_HE_GI_KNOWN 0x0002
#define QDF_MON_STATUS_TXBF_KNOWN 0x0010
#define QDF_MON_STATUS_PE_DISAMBIGUITY_KNOWN 0x0020
#define QDF_MON_STATUS_TXOP_KNOWN 0x0040
#define QDF_MON_STATUS_LTF_SYMBOLS_KNOWN 0x0004
#define QDF_MON_STATUS_PRE_FEC_PADDING_KNOWN 0x0008
#define QDF_MON_STATUS_MIDABLE_PERIODICITY_KNOWN 0x0080
#define QDF_MON_STATUS_RU_ALLOCATION_OFFSET_KNOWN 0x4000
#define QDF_MON_STATUS_RU_ALLOCATION_SHIFT 8

/* HE radiotap data3 shift values */
#define QDF_MON_STATUS_BEAM_CHANGE_SHIFT 6
#define QDF_MON_STATUS_DL_UL_SHIFT 7
#define QDF_MON_STATUS_TRANSMIT_MCS_SHIFT 8
#define QDF_MON_STATUS_DCM_SHIFT 12
#define QDF_MON_STATUS_CODING_SHIFT 13
#define QDF_MON_STATUS_LDPC_EXTRA_SYMBOL_SHIFT 14
#define QDF_MON_STATUS_STBC_SHIFT 15

/* HE radiotap data4 shift values */
#define QDF_MON_STATUS_STA_ID_SHIFT 4

/* HE radiotap data5 */
#define QDF_MON_STATUS_GI_SHIFT 4
#define QDF_MON_STATUS_HE_LTF_SIZE_SHIFT 6
#define QDF_MON_STATUS_HE_LTF_SYM_SHIFT 8
#define QDF_MON_STATUS_TXBF_SHIFT 14
#define QDF_MON_STATUS_PE_DISAMBIGUITY_SHIFT 15
#define QDF_MON_STATUS_PRE_FEC_PAD_SHIFT 12

/* HE radiotap data6 */
#define QDF_MON_STATUS_HE_DATA_6_NSS_SHIFT 0
#define QDF_MON_STATUS_DOPPLER_SHIFT 4
#define QDF_MON_STATUS_TXOP_SHIFT 8

/* HE radiotap HE-MU flags1 */
#define QDF_MON_STATUS_SIG_B_MCS_SHIFT 0x0000
#define QDF_MON_STATUS_SIG_B_MCS_KNOWN 0x0010
#define QDF_MON_STATUS_SIG_B_DCM_SHIFT 5
#define QDF_MON_STATUS_SIG_B_DCM_KNOWN 0x0040
#define QDF_MON_STATUS_CHANNEL_2_CENTER_26_RU_KNOWN 0x0080
#define QDF_MON_STATUS_CHANNEL_1_RU_KNOWN 0x0100
#define QDF_MON_STATUS_CHANNEL_2_RU_KNOWN 0x0200
#define QDF_MON_STATUS_CHANNEL_1_CENTER_26_RU_KNOWN 0x1000
#define QDF_MON_STATUS_CHANNEL_1_CENTER_26_RU_VALUE 0x2000
#define QDF_MON_STATUS_CHANNEL_1_CENTER_26_RU_SHIFT 13
#define QDF_MON_STATUS_SIG_B_SYM_NUM_KNOWN 0x8000
#define QDF_MON_STATUS_RU_0_KNOWN 0x0100
#define QDF_MON_STATUS_RU_1_KNOWN 0x0200
#define QDF_MON_STATUS_RU_2_KNOWN 0x0400
#define QDF_MON_STATUS_RU_3_KNOWN 0x0800
#define QDF_MON_STATUS_DCM_FLAG_1_SHIFT 5
#define QDF_MON_STATUS_SPATIAL_REUSE_MU_KNOWN 0x0100
#define QDF_MON_STATUS_SIG_B_COMPRESSION_FLAG_1_KNOWN 0x4000
#define QDF_MON_STATUS_SIG_B_SYMBOL_USER_KNOWN 0x8000

/* HE radiotap HE-MU flags2 */
#define QDF_MON_STATUS_SIG_A_BANDWIDTH_KNOWN 0x0004
#define QDF_MON_STATUS_SIG_A_BANDWIDTH_SHIFT 0
#define QDF_MON_STATUS_SIG_B_COMPRESSION_FLAG_2_SHIFT 3
#define QDF_MON_STATUS_BW_KNOWN 0x0004
#define QDF_MON_STATUS_NUM_SIG_B_SYMBOLS_SHIFT 4
#define QDF_MON_STATUS_SIG_B_COMPRESSION_FLAG_2_KNOWN 0x0100
#define QDF_MON_STATUS_NUM_SIG_B_FLAG_2_SHIFT 9
#define QDF_MON_STATUS_SIG_A_PUNC_BANDWIDTH_KNOWN 0x0400
#define QDF_MON_STATUS_SIG_A_PUNC_BANDWIDTH_SHIFT 8
#define QDF_MON_STATUS_CHANNEL_2_CENTER_26_RU_VALUE 0x0800
#define QDF_MON_STATUS_CHANNEL_2_CENTER_26_RU_SHIFT 11
#define QDF_MON_STATUS_LTF_FLAG_2_SYMBOLS_SHIFT 12
#define QDF_MON_STATUS_LTF_KNOWN 0x8000

/* HE radiotap per_user_1 */
#define QDF_MON_STATUS_STA_SPATIAL_SHIFT 11
#define QDF_MON_STATUS_TXBF_SHIFT 14
#define QDF_MON_STATUS_RESERVED_SET_TO_1_SHIFT 19
#define QDF_MON_STATUS_STA_CODING_SHIFT 20

/* HE radiotap per_user_2 */
#define QDF_MON_STATUS_STA_MCS_SHIFT 4
#define QDF_MON_STATUS_STA_DCM_SHIFT 5

/* HE radiotap per user known */
#define QDF_MON_STATUS_USER_FIELD_POSITION_KNOWN 0x01
#define QDF_MON_STATUS_STA_ID_PER_USER_KNOWN 0x02
#define QDF_MON_STATUS_STA_NSTS_KNOWN 0x04
#define QDF_MON_STATUS_STA_TX_BF_KNOWN 0x08
#define QDF_MON_STATUS_STA_SPATIAL_CONFIG_KNOWN 0x10
#define QDF_MON_STATUS_STA_MCS_KNOWN 0x20
#define QDF_MON_STATUS_STA_DCM_KNOWN 0x40
#define QDF_MON_STATUS_STA_CODING_KNOWN 0x80

/* U-SIG Common Mask */
#define QDF_MON_STATUS_USIG_PHY_VERSION_KNOWN		0x00000001
#define QDF_MON_STATUS_USIG_BW_KNOWN			0x00000002
#define QDF_MON_STATUS_USIG_UL_DL_KNOWN			0x00000004
#define QDF_MON_STATUS_USIG_BSS_COLOR_KNOWN		0x00000008
#define QDF_MON_STATUS_USIG_TXOP_KNOWN			0x00000010

#define QDF_MON_STATUS_USIG_PHY_VERSION_SHIFT		12
#define QDF_MON_STATUS_USIG_BW_SHIFT			15
#define QDF_MON_STATUS_USIG_UL_DL_SHIFT			18
#define QDF_MON_STATUS_USIG_BSS_COLOR_SHIFT		19
#define QDF_MON_STATUS_USIG_TXOP_SHIFT			25

/* U-SIG MU/TB Value */
#define QDF_MON_STATUS_USIG_DISREGARD_SHIFT			0
#define QDF_MON_STATUS_USIG_PPDU_TYPE_N_COMP_MODE_SHIFT		6
#define QDF_MON_STATUS_USIG_VALIDATE_SHIFT			8

#define QDF_MON_STATUS_USIG_MU_VALIDATE1_SHIFT			5
#define QDF_MON_STATUS_USIG_MU_PUNCTURE_CH_INFO_SHIFT		9
#define QDF_MON_STATUS_USIG_MU_VALIDATE2_SHIFT			14
#define QDF_MON_STATUS_USIG_MU_EHT_SIG_MCS_SHIFT		15
#define QDF_MON_STATUS_USIG_MU_NUM_EHT_SIG_SYM_SHIFT		17

#define QDF_MON_STATUS_USIG_TB_SPATIAL_REUSE_1_SHIFT		9
#define QDF_MON_STATUS_USIG_TB_SPATIAL_REUSE_2_SHIFT		13
#define QDF_MON_STATUS_USIG_TB_DISREGARD1_SHIFT			17

#define QDF_MON_STATUS_USIG_CRC_SHIFT				22
#define QDF_MON_STATUS_USIG_TAIL_SHIFT				26

/* U-SIG MU/TB Mask */
#define QDF_MON_STATUS_USIG_DISREGARD_KNOWN			0x00000001
#define QDF_MON_STATUS_USIG_PPDU_TYPE_N_COMP_MODE_KNOWN		0x00000004
#define QDF_MON_STATUS_USIG_VALIDATE_KNOWN			0x00000008

#define QDF_MON_STATUS_USIG_MU_VALIDATE1_KNOWN			0x00000002
#define QDF_MON_STATUS_USIG_MU_PUNCTURE_CH_INFO_KNOWN		0x00000010
#define QDF_MON_STATUS_USIG_MU_VALIDATE2_KNOWN			0x00000020
#define QDF_MON_STATUS_USIG_MU_EHT_SIG_MCS_KNOWN		0x00000040
#define QDF_MON_STATUS_USIG_MU_NUM_EHT_SIG_SYM_KNOWN		0x00000080

#define QDF_MON_STATUS_USIG_TB_SPATIAL_REUSE_1_KNOWN		0x00000010
#define QDF_MON_STATUS_USIG_TB_SPATIAL_REUSE_2_KNOWN		0x00000020
#define QDF_MON_STATUS_USIG_TB_DISREGARD1_KNOWN			0x00000040

#define QDF_MON_STATUS_USIG_CRC_KNOWN				0x00000100
#define QDF_MON_STATUS_USIG_TAIL_KNOWN				0x00000200

/* EHT known Mask */
#define QDF_MON_STATUS_EHT_CONTENT_CH_INDEX_KNOWN		0x00000001
#define QDF_MON_STATUS_EHT_SPATIAL_REUSE_KNOWN			0x00000002
#define QDF_MON_STATUS_EHT_GUARD_INTERVAL_KNOWN			0x00000004
#define QDF_MON_STATUS_EHT_LTF_KNOWN				0x00000008
#define QDF_MON_STATUS_EHT_EHT_LTF_KNOWN			0x00000010
#define QDF_MON_STATUS_EHT_LDPC_EXTRA_SYMBOL_SEG_KNOWN		0x00000020
#define QDF_MON_STATUS_EHT_PRE_FEC_PADDING_FACTOR_KNOWN		0x00000040
#define QDF_MON_STATUS_EHT_PE_DISAMBIGUITY_KNOWN		0x00000080
#define QDF_MON_STATUS_EHT_DISREARD_KNOWN			0x00000100
#define QDF_MON_STATUS_EHT_CRC1_KNOWN				0x00002000
#define QDF_MON_STATUS_EHT_TAIL1_KNOWN				0x00004000
#define QDF_MON_STATUS_EHT_CRC2_KNOWN				0x00008000
#define QDF_MON_STATUS_EHT_TAIL2_KNOWN				0x00010000
#define QDF_MON_STATUS_EHT_RU_MRU_SIZE_KNOWN			0x00400000
#define QDF_MON_STATUS_EHT_RU_MRU_INDEX_KNOWN			0x00800000
#define QDF_MON_STATUS_EHT_TB_RU_ALLOCATION_KNOWN		0x01000000

#define QDF_MON_STATUS_EHT_NUM_NON_OFDMA_USERS_KNOWN		0x00080000
#define QDF_MON_STATUS_EHT_USER_ENC_BLOCK_CRC_KNOWN		0x00100000
#define QDF_MON_STATUS_EHT_USER_ENC_BLOCK_TAIL_KNOWN		0x00200000

#define QDF_MON_STATUS_EHT_NDP_DISREGARD_KNOWN			0x00000200
#define QDF_MON_STATUS_EHT_NDP_NSS_KNOWN			0x00020000
#define QDF_MON_STATUS_EHT_NDP_BEAMFORMED_KNOWN			0x00040000

#define QDF_MON_STATUS_EHT_NUM_KNOWN_RU_ALLOCATIONS_SHIFT	10

/* EHT data0 Mask/SHIFT */
#define QDF_MON_STATUS_EHT_CONTENT_CH_INDEX_SHIFT		0
#define QDF_MON_STATUS_EHT_SPATIAL_REUSE_SHIFT			3
#define QDF_MON_STATUS_EHT_GI_SHIFT				7
#define QDF_MON_STATUS_EHT_LTF_SHIFT				9
#define QDF_MON_STATUS_EHT_EHT_LTF_SHIFT			11
#define QDF_MON_STATUS_EHT_LDPC_EXTRA_SYMBOL_SEG_SHIFT		14
#define QDF_MON_STATUS_EHT_PRE_FEC_PADDING_FACTOR_SHIFT		15
#define QDF_MON_STATUS_EHT_PE_DISAMBIGUITY_SHIFT		17
#define QDF_MON_STATUS_EHT_NDP_DISREGARD_SHIFT			18
#define QDF_MON_STATUS_EHT_DISREGARD_SHIFT			18
#define QDF_MON_STATUS_EHT_CRC1_SHIFT				22
#define QDF_MON_STATUS_EHT_TAIL1_SHIFT				26

/* EHT data1 Mask/SHIFT */
#define QDF_MON_STATUS_EHT_RU_MRU_SIZE_SHIFT			0
#define QDF_MON_STATUS_EHT_RU_MRU_INDEX_SHIFT			5
#define QDF_MON_STATUS_EHT_RU_ALLOCATION1_1_SHIFT		13
#define QDF_MON_STATUS_EHT_RU_ALLOCATION1_2_SHIFT		22

/* EHT data2 Mask/SHIFT */
#define QDF_MON_STATUS_EHT_RU_ALLOCATION2_1_SHIFT		0
#define QDF_MON_STATUS_EHT_RU_ALLOCATION2_2_SHIFT		9
#define QDF_MON_STATUS_EHT_RU_ALLOCATION2_3_SHIFT		18

/* EHT data3 Mask/SHIFT */
#define QDF_MON_STATUS_EHT_RU_ALLOCATION2_4_SHIFT		0
#define QDF_MON_STATUS_EHT_RU_ALLOCATION2_5_SHIFT		9
#define QDF_MON_STATUS_EHT_RU_ALLOCATION2_6_SHIFT		18

/* EHT data4 Mask/SHIFT */
#define QDF_MON_STATUS_EHT_CRC2_SHIFT				0
#define QDF_MON_STATUS_EHT_TAIL2_SHIFT				4
#define QDF_MON_STATUS_EHT_NDP_NSS_SHIFT			12
#define QDF_MON_STATUS_EHT_NDP_BEAMFORMED_SHIFT			16
#define QDF_MON_STATUS_EHT_NUM_NON_OFDMA_USERS_SHIFT		17
#define QDF_MON_STATUS_EHT_USER_ENC_BLOCK_CRC_SHIFT		20
#define QDF_MON_STATUS_EHT_USER_ENC_BLOCK_TAIL_SHIFT		24

/* EHT data5 Mask/SHIFT */
#define QDF_MON_STATUS_EHT_TB_RU_PS160_SHIFT			0
#define QDF_MON_STATUS_EHT_TB_RU_PS80_SHIFT			1
#define QDF_MON_STATUS_EHT_TB_RU_B7_B1_SHIFT			2

/* EHT user info Mask/SHIFT */
#define QDF_MON_STATUS_EHT_USER_STA_ID_KNOWN			0x00000001
#define QDF_MON_STATUS_EHT_USER_MCS_KNOWN			0x00000002
#define QDF_MON_STATUS_EHT_USER_CODING_KNOWN			0x00000004
#define QDF_MON_STATUS_EHT_USER_RESERVED_KNOWN			0x00000008
#define QDF_MON_STATUS_EHT_USER_NSS_KNOWN			0x00000010
#define QDF_MON_STATUS_EHT_USER_BEAMFORMING_KNOWN		0x00000020
#define QDF_MON_STATUS_EHT_USER_SPATIAL_CONFIG_KNOWN		0x00000040

#define QDF_MON_STATUS_EHT_USER_DATA_FOR_THIS_USER_SHIFT	7
#define QDF_MON_STATUS_EHT_USER_STA_ID_SHIFT			8
#define QDF_MON_STATUS_EHT_USER_CODING_SHIFT			19
#define QDF_MON_STATUS_EHT_USER_MCS_SHIFT			20
#define QDF_MON_STATUS_EHT_USER_NSS_SHIFT			24
#define QDF_MON_STATUS_EHT_USER_RESERVED_SHIFT			28
#define QDF_MON_STATUS_EHT_USER_BEAMFORMING_SHIFT		29
#define QDF_MON_STATUS_EHT_USER_SPATIAL_CONFIG_SHIFT		24

/**
 * enum qdf_proto_type - protocol type
 * @QDF_PROTO_TYPE_DHCP: DHCP
 * @QDF_PROTO_TYPE_EAPOL: EAPOL
 * @QDF_PROTO_TYPE_ARP: ARP
 * @QDF_PROTO_TYPE_MGMT: MGMT
 * @QDF_PROTO_TYPE_ICMP: ICMP
 * @QDF_PROTO_TYPE_ICMPv6: ICMPv6
 * @QDF_PROTO_TYPE_EVENT: EVENT
 * @QDF_PROTO_TYPE_DNS: DNS
 * @QDF_PROTO_TYPE_MAX: Max enumeration
 */
enum qdf_proto_type {
	QDF_PROTO_TYPE_DHCP,
	QDF_PROTO_TYPE_EAPOL,
	QDF_PROTO_TYPE_ARP,
	QDF_PROTO_TYPE_MGMT,
	QDF_PROTO_TYPE_ICMP,
	QDF_PROTO_TYPE_ICMPv6,
	QDF_PROTO_TYPE_EVENT,
	QDF_PROTO_TYPE_DNS,
	QDF_PROTO_TYPE_MAX
};

/**
 * enum qdf_reception_type - reception type used by lithium phy TLV
 * @QDF_RECEPTION_TYPE_ULOFMDA: UL OFDMA
 * @QDF_RECEPTION_TYPE_ULMIMO: UL MIMO
 * @QDF_RECEPTION_TYPE_FRAMELESS: Frame less
 * @QDF_RECEPTION_TYPE_OTHER: All the other types
 */
enum qdf_reception_type {
	QDF_RECEPTION_TYPE_ULOFMDA,
	QDF_RECEPTION_TYPE_ULMIMO,
	QDF_RECEPTION_TYPE_OTHER,
	QDF_RECEPTION_TYPE_FRAMELESS
};

/**
 * enum cb_ftype - Frame type information in skb cb
 * @CB_FTYPE_INVALID: Invalid
 * @CB_FTYPE_MCAST2UCAST: Multicast to Unicast converted packet
 * @CB_FTYPE_TSO: TCP Segmentation Offload
 * @CB_FTYPE_TSO_SG: TSO Scatter Gather
 * @CB_FTYPE_SG: Scatter Gather
 * @CB_FTYPE_INTRABSS_FWD: Intra BSS forwarding
 * @CB_FTYPE_RX_INFO: Rx information
 * @CB_FTYPE_MESH_RX_INFO: Mesh Rx information
 * @CB_FTYPE_MESH_TX_INFO: Mesh Tx information
 * @CB_FTYPE_DMS: Directed Multicast Service
 * @CB_FTYPE_SAWF: SAWF information
 * @CB_FTYPE_MLO_MCAST: MLO MCAST enable information
 */
enum cb_ftype {
	CB_FTYPE_INVALID = 0,
	CB_FTYPE_MCAST2UCAST = 1,
	CB_FTYPE_TSO = 2,
	CB_FTYPE_TSO_SG = 3,
	CB_FTYPE_SG = 4,
	CB_FTYPE_INTRABSS_FWD = 5,
	CB_FTYPE_RX_INFO = 6,
	CB_FTYPE_MESH_RX_INFO = 7,
	CB_FTYPE_MESH_TX_INFO = 8,
	CB_FTYPE_DMS = 9,
	CB_FTYPE_SAWF = 10,
	CB_FTYPE_MLO_MCAST = 11,
};

/**
 * typedef qdf_nbuf_t - Platform independent packet abstraction
 */
typedef __qdf_nbuf_t qdf_nbuf_t;

/**
 * typedef qdf_nbuf_shared_info_t - Platform independent shared info
 */
typedef __qdf_nbuf_shared_info_t qdf_nbuf_shared_info_t;

/**
 * struct qdf_nbuf_track_t - Network buffer track structure
 *
 * @p_next: Pointer to next
 * @net_buf: Pointer to network buffer
 * @func_name: Function name
 * @line_num: Line number
 * @size: Size
 * @map_func_name: nbuf mapping function name
 * @map_line_num: mapping function line number
 * @unmap_func_name: nbuf unmapping function name
 * @unmap_line_num: mapping function line number
 * @is_nbuf_mapped: indicate mapped/unmapped nbuf
 * @time: mapping function timestamp
 * @smmu_map_line_num: smmu mapping line number
 * @smmu_unmap_line_num: smmu unmapping line number
 * @smmu_map_func_name: smmu mapping function name
 * @smmu_unmap_func_name: smmu unmapping function name
 * @is_nbuf_smmu_mapped: nbuf is smmu mapped
 * @smmu_map_iova_addr: nbuf smmu map virtual address
 * @smmu_map_pa_addr: nbuf smmu map physical address
 * @smmu_unmap_iova_addr: nbuf smmu unmap virtual address
 * @smmu_unmap_pa_addr: nbuf smmu unmap physical address
 */
struct qdf_nbuf_track_t {
	struct qdf_nbuf_track_t *p_next;
	qdf_nbuf_t net_buf;
	char func_name[QDF_MEM_FUNC_NAME_SIZE];
	uint32_t line_num;
	size_t size;
	char map_func_name[QDF_MEM_FUNC_NAME_SIZE];
	uint32_t map_line_num;
	char unmap_func_name[QDF_MEM_FUNC_NAME_SIZE];
	uint32_t unmap_line_num;
	bool is_nbuf_mapped;
	qdf_time_t time;
#ifdef NBUF_SMMU_MAP_UNMAP_DEBUG
	uint32_t smmu_map_line_num;
	uint32_t smmu_unmap_line_num;
	char smmu_map_func_name[QDF_MEM_FUNC_NAME_SIZE];
	char smmu_unmap_func_name[QDF_MEM_FUNC_NAME_SIZE];
	bool is_nbuf_smmu_mapped;
	unsigned long smmu_map_iova_addr;
	unsigned long smmu_map_pa_addr;
	unsigned long smmu_unmap_iova_addr;
	unsigned long smmu_unmap_pa_addr;
#endif
};

typedef struct qdf_nbuf_track_t QDF_NBUF_TRACK;

/**
 * typedef qdf_nbuf_queue_head_t - Platform independent nbuf queue head
 */
typedef __qdf_nbuf_queue_head_t qdf_nbuf_queue_head_t;

/**
 * typedef qdf_dma_map_cb_t() - Dma map callback prototype
 * @arg: callback context
 * @buf: netbuf
 * @dmap: DMA map
 */
typedef void (*qdf_dma_map_cb_t)(void *arg, qdf_nbuf_t buf,
				 qdf_dma_map_t dmap);

/* BUS/DMA mapping routines */

static inline QDF_STATUS
qdf_nbuf_dmamap_create(qdf_device_t osdev, qdf_dma_map_t *dmap)
{
	return __qdf_nbuf_dmamap_create(osdev, dmap);
}

static inline void
qdf_nbuf_dmamap_destroy(qdf_device_t osdev, qdf_dma_map_t dmap)
{
	__qdf_nbuf_dmamap_destroy(osdev, dmap);
}

static inline void
qdf_nbuf_dmamap_set_cb(qdf_dma_map_t dmap, qdf_dma_map_cb_t cb, void *arg)
{
	__qdf_nbuf_dmamap_set_cb(dmap, cb, arg);
}

static inline void
qdf_nbuf_set_send_complete_flag(qdf_nbuf_t buf, bool flag)
{
	__qdf_nbuf_set_send_complete_flag(buf, flag);
}

#define QDF_NBUF_QUEUE_WALK_SAFE(queue, var, tvar)	\
		__qdf_nbuf_queue_walk_safe(queue, var, tvar)

#ifdef NBUF_MAP_UNMAP_DEBUG
/**
 * qdf_nbuf_map_check_for_leaks() - check for nbuf map leaks
 *
 * Check for net buffers that have been mapped, but never unmapped.
 *
 * Returns: None
 */
void qdf_nbuf_map_check_for_leaks(void);

QDF_STATUS qdf_nbuf_map_debug(qdf_device_t osdev,
			      qdf_nbuf_t buf,
			      qdf_dma_dir_t dir,
			      const char *func,
			      uint32_t line);

#define qdf_nbuf_map(osdev, buf, dir) \
	qdf_nbuf_map_debug(osdev, buf, dir, __func__, __LINE__)

void qdf_nbuf_unmap_debug(qdf_device_t osdev,
			  qdf_nbuf_t buf,
			  qdf_dma_dir_t dir,
			  const char *func,
			  uint32_t line);

#define qdf_nbuf_unmap(osdev, buf, dir) \
	qdf_nbuf_unmap_debug(osdev, buf, dir, __func__, __LINE__)

QDF_STATUS qdf_nbuf_map_single_debug(qdf_device_t osdev,
				     qdf_nbuf_t buf,
				     qdf_dma_dir_t dir,
				     const char *func,
				     uint32_t line);

#define qdf_nbuf_map_single(osdev, buf, dir) \
	qdf_nbuf_map_single_debug(osdev, buf, dir, __func__, __LINE__)

void qdf_nbuf_unmap_single_debug(qdf_device_t osdev,
				 qdf_nbuf_t buf,
				 qdf_dma_dir_t dir,
				 const char *func,
				 uint32_t line);

#define qdf_nbuf_unmap_single(osdev, buf, dir) \
	qdf_nbuf_unmap_single_debug(osdev, buf, dir, __func__, __LINE__)

QDF_STATUS qdf_nbuf_map_nbytes_debug(qdf_device_t osdev,
				     qdf_nbuf_t buf,
				     qdf_dma_dir_t dir,
				     int nbytes,
				     const char *func,
				     uint32_t line);

#define qdf_nbuf_map_nbytes(osdev, buf, dir, nbytes) \
	qdf_nbuf_map_nbytes_debug(osdev, buf, dir, nbytes, __func__, __LINE__)

void qdf_nbuf_unmap_nbytes_debug(qdf_device_t osdev,
				 qdf_nbuf_t buf,
				 qdf_dma_dir_t dir,
				 int nbytes,
				 const char *func,
				 uint32_t line);

#define qdf_nbuf_unmap_nbytes(osdev, buf, dir, nbytes) \
	qdf_nbuf_unmap_nbytes_debug(osdev, buf, dir, nbytes, __func__, __LINE__)

QDF_STATUS qdf_nbuf_map_nbytes_single_debug(qdf_device_t osdev,
					    qdf_nbuf_t buf,
					    qdf_dma_dir_t dir,
					    int nbytes,
					    const char *func,
					    uint32_t line);

#define qdf_nbuf_map_nbytes_single(osdev, buf, dir, nbytes) \
	qdf_nbuf_map_nbytes_single_debug(osdev, buf, dir, nbytes, \
					 __func__, __LINE__)

void qdf_nbuf_unmap_nbytes_single_debug(qdf_device_t osdev,
					qdf_nbuf_t buf,
					qdf_dma_dir_t dir,
					int nbytes,
					const char *func,
					uint32_t line);

#define qdf_nbuf_unmap_nbytes_single(osdev, buf, dir, nbytes) \
	qdf_nbuf_unmap_nbytes_single_debug(osdev, buf, dir, nbytes, \
					   __func__, __LINE__)

void qdf_nbuf_unmap_nbytes_single_paddr_debug(qdf_device_t osdev,
					      qdf_nbuf_t buf,
					      qdf_dma_addr_t phy_addr,
					      qdf_dma_dir_t dir, int nbytes,
					      const char *func, uint32_t line);

#define qdf_nbuf_unmap_nbytes_single_paddr(osdev, buf, phy_addr, dir, nbytes) \
	qdf_nbuf_unmap_nbytes_single_paddr_debug(osdev, buf, phy_addr, \
						 dir, nbytes, __func__, \
						 __LINE__)
#else /* NBUF_MAP_UNMAP_DEBUG */

static inline void qdf_nbuf_map_check_for_leaks(void) {}

static inline QDF_STATUS
qdf_nbuf_map(qdf_device_t osdev, qdf_nbuf_t buf, qdf_dma_dir_t dir)
{
	return __qdf_nbuf_map(osdev, buf, dir);
}

static inline void
qdf_nbuf_unmap(qdf_device_t osdev, qdf_nbuf_t buf, qdf_dma_dir_t dir)
{
	__qdf_nbuf_unmap(osdev, buf, dir);
}

static inline QDF_STATUS
qdf_nbuf_map_single(qdf_device_t osdev, qdf_nbuf_t buf, qdf_dma_dir_t dir)
{
	return __qdf_nbuf_map_single(osdev, buf, dir);
}

static inline void
qdf_nbuf_unmap_single(qdf_device_t osdev, qdf_nbuf_t buf, qdf_dma_dir_t dir)
{
	__qdf_nbuf_unmap_single(osdev, buf, dir);
}

static inline QDF_STATUS
qdf_nbuf_map_nbytes(qdf_device_t osdev, qdf_nbuf_t buf,
		qdf_dma_dir_t dir, int nbytes)
{
	return __qdf_nbuf_map_nbytes(osdev, buf, dir, nbytes);
}

static inline void
qdf_nbuf_unmap_nbytes(qdf_device_t osdev,
	qdf_nbuf_t buf, qdf_dma_dir_t dir, int nbytes)
{
	__qdf_nbuf_unmap_nbytes(osdev, buf, dir, nbytes);
}

static inline QDF_STATUS
qdf_nbuf_map_nbytes_single(
	qdf_device_t osdev, qdf_nbuf_t buf, qdf_dma_dir_t dir, int nbytes)
{
	return __qdf_nbuf_map_nbytes_single(osdev, buf, dir, nbytes);
}

static inline void
qdf_nbuf_unmap_nbytes_single(
	qdf_device_t osdev, qdf_nbuf_t buf, qdf_dma_dir_t dir, int nbytes)
{
	return __qdf_nbuf_unmap_nbytes_single(osdev, buf, dir, nbytes);
}

static inline void
qdf_nbuf_unmap_nbytes_single_paddr(qdf_device_t osdev, qdf_nbuf_t buf,
				   qdf_dma_addr_t phy_addr, qdf_dma_dir_t dir,
				   int nbytes)
{
	__qdf_record_nbuf_nbytes(__qdf_nbuf_get_end_offset(buf), dir, false);
	__qdf_mem_unmap_nbytes_single(osdev, phy_addr, dir, nbytes);
}
#endif /* NBUF_MAP_UNMAP_DEBUG */

/**
 * qdf_nbuf_queue_head_dequeue() - dequeue nbuf from the head of queue
 * @nbuf_queue_head: pointer to nbuf queue head
 *
 * Return: pointer to network buffer dequeued
 */
static inline
qdf_nbuf_t qdf_nbuf_queue_head_dequeue(qdf_nbuf_queue_head_t *nbuf_queue_head)
{
	return __qdf_nbuf_queue_head_dequeue(nbuf_queue_head);
}

/**
 * qdf_nbuf_queue_head_qlen() - length of the queue
 * @nbuf_queue_head: pointer to nbuf queue head
 *
 * Return: length of queue (number of nbufs) pointed by qdf_nbuf_queue_head_t
 */
static inline
uint32_t qdf_nbuf_queue_head_qlen(qdf_nbuf_queue_head_t *nbuf_queue_head)
{
	return __qdf_nbuf_queue_head_qlen(nbuf_queue_head);
}

/**
 * qdf_nbuf_queue_head_enqueue_tail() - enqueue nbuf into queue tail
 * @nbuf_queue_head: pointer to nbuf queue head
 * @nbuf: nbuf to be enqueued
 *
 * Return: None
 */
static inline
void qdf_nbuf_queue_head_enqueue_tail(qdf_nbuf_queue_head_t *nbuf_queue_head,
				      qdf_nbuf_t nbuf)
{
	return __qdf_nbuf_queue_head_enqueue_tail(nbuf_queue_head, nbuf);
}

/**
 * qdf_nbuf_queue_head_init() - initialize qdf_nbuf_queue_head_t
 * @nbuf_queue_head: pointer to nbuf queue head to be initialized
 *
 * Return: None
 */
static inline
void qdf_nbuf_queue_head_init(qdf_nbuf_queue_head_t *nbuf_queue_head)
{
	return __qdf_nbuf_queue_head_init(nbuf_queue_head);
}

/**
 * qdf_nbuf_queue_head_purge() - purge qdf_nbuf_queue_head_t
 * @nbuf_queue_head: pointer to nbuf queue head to be purged
 *
 * Return: None
 */
static inline
void qdf_nbuf_queue_head_purge(qdf_nbuf_queue_head_t *nbuf_queue_head)
{
	return __qdf_nbuf_queue_head_purge(nbuf_queue_head);
}

/**
 * qdf_nbuf_queue_empty() - dequeue nbuf from the head of queue
 * @nbuf_queue_head: pointer to nbuf queue head
 *
 * Return: true if queue is empty else false
 */
static inline
int qdf_nbuf_queue_empty(qdf_nbuf_queue_head_t *nbuf_queue_head)
{
	return __qdf_nbuf_queue_empty(nbuf_queue_head);
}

/**
 * qdf_nbuf_queue_head_lock() - Acquire the nbuf_queue_head lock
 * @head: nbuf_queue_head of the nbuf_list for which lock is to be acquired
 *
 * Return: void
 */
static inline void qdf_nbuf_queue_head_lock(qdf_nbuf_queue_head_t *head)
{
	__qdf_nbuf_queue_head_lock(head);
}

/**
 * qdf_nbuf_queue_head_unlock() - Release the nbuf queue lock
 * @head: nbuf_queue_head of the nbuf_list for which lock is to be release
 *
 * Return: void
 */
static inline void qdf_nbuf_queue_head_unlock(qdf_nbuf_queue_head_t *head)
{
	__qdf_nbuf_queue_head_unlock(head);
}

static inline void
qdf_nbuf_sync_for_cpu(qdf_device_t osdev, qdf_nbuf_t buf, qdf_dma_dir_t dir)
{
	__qdf_nbuf_sync_for_cpu(osdev, buf, dir);
}

/**
 * qdf_nbuf_dma_inv_range() - Invalidate the specified virtual address range
 * @buf_start: start address
 * @buf_end: end address
 *
 * Return: none
 */
static inline void
qdf_nbuf_dma_inv_range(const void *buf_start, const void *buf_end)
{
	__qdf_nbuf_dma_inv_range(buf_start, buf_end);
}

/**
 * qdf_nbuf_dma_inv_range_no_dsb() - barrierless Invalidate the specified
 *				     virtual address range
 * @buf_start: start address
 * @buf_end: end address
 *
 * Return: none
 */
static inline void
qdf_nbuf_dma_inv_range_no_dsb(const void *buf_start, const void *buf_end)
{
	__qdf_nbuf_dma_inv_range_no_dsb(buf_start, buf_end);
}

/**
 * qdf_nbuf_dma_clean_range_no_dsb() - barrierless clean the specified
 *				       virtual address range
 * @buf_start: start address
 * @buf_end: end address
 *
 * Return: none
 */
static inline void
qdf_nbuf_dma_clean_range_no_dsb(const void *buf_start, const void *buf_end)
{
	__qdf_nbuf_dma_clean_range_no_dsb(buf_start, buf_end);
}

static inline void
qdf_dsb(void)
{
	__qdf_dsb();
}

static inline int qdf_nbuf_get_num_frags(qdf_nbuf_t buf)
{
	return __qdf_nbuf_get_num_frags(buf);
}

/**
 * qdf_nbuf_dma_clean_range() - Clean the specified virtual address range
 * @buf_start: start address
 * @buf_end: end address
 *
 * Return: none
 */
static inline void
qdf_nbuf_dma_clean_range(const void *buf_start, const void *buf_end)
{
	__qdf_nbuf_dma_clean_range(buf_start, buf_end);
}

/**
 * qdf_nbuf_get_frag_len() - get fragment length
 * @buf: Network buffer
 * @frag_num: Fragment number
 *
 * Return: Fragment length
 */
static inline int qdf_nbuf_get_frag_len(qdf_nbuf_t buf, int frag_num)
{
	QDF_BUG(!(frag_num >= QDF_NBUF_CB_TX_MAX_EXTRA_FRAGS));
	return __qdf_nbuf_get_frag_len(buf, frag_num);
}

/**
 * qdf_nbuf_get_frag_vaddr() - get fragment virtual address
 * @buf: Network buffer
 * @frag_num: Fragment number
 *
 * Return: Fragment virtual address
 */
static inline unsigned char *qdf_nbuf_get_frag_vaddr(qdf_nbuf_t buf,
			int frag_num)
{
	QDF_BUG(!(frag_num >= QDF_NBUF_CB_TX_MAX_EXTRA_FRAGS));
	return __qdf_nbuf_get_frag_vaddr(buf, frag_num);
}

/**
 * qdf_nbuf_get_frag_vaddr_always() - get fragment virtual address
 * @buf: Network buffer
 *
 * Return: Fragment virtual address
 */
static inline unsigned char *
qdf_nbuf_get_frag_vaddr_always(qdf_nbuf_t buf)
{
	return __qdf_nbuf_get_frag_vaddr_always(buf);
}

/**
 * qdf_nbuf_get_frag_paddr() - get physical address for skb linear buffer
 *                              or skb fragment, based on frag_num passed
 * @buf: Network buffer
 * @frag_num: Fragment number
 *
 * Return: Fragment physical address
 */
static inline qdf_dma_addr_t qdf_nbuf_get_frag_paddr(qdf_nbuf_t buf,
			unsigned int frag_num)
{
	QDF_BUG(!(frag_num >= QDF_NBUF_CB_TX_MAX_EXTRA_FRAGS));
	return __qdf_nbuf_get_frag_paddr(buf, frag_num);
}

/**
 * qdf_nbuf_get_tx_frag_paddr() - get physical address for skb fragments only
 * @buf: Network buffer
 *
 * Return: Fragment physical address
 * Usage guideline: Use “qdf_nbuf_frag_map()” to dma map the specific
 *                  skb fragment , followed by “qdf_nbuf_get_tx_frag_paddr”
 */
static inline qdf_dma_addr_t qdf_nbuf_get_tx_frag_paddr(qdf_nbuf_t buf)
{
	return __qdf_nbuf_get_tx_frag_paddr(buf);
}

/**
 * qdf_nbuf_get_frag_is_wordstream() - is fragment wordstream
 * @buf: Network buffer
 * @frag_num: Fragment number
 *
 * Return: Fragment wordstream or not
 */
static inline int qdf_nbuf_get_frag_is_wordstream(qdf_nbuf_t buf, int frag_num)
{
	QDF_BUG(!(frag_num >= QDF_NBUF_CB_TX_MAX_EXTRA_FRAGS));
	return __qdf_nbuf_get_frag_is_wordstream(buf, frag_num);
}

/**
 * qdf_nbuf_set_frag_is_wordstream() - set fragment wordstream
 * @buf: Network buffer
 * @frag_num: Fragment number
 * @is_wordstream: Wordstream
 *
 * Return: none
 */
static inline void
qdf_nbuf_set_frag_is_wordstream(qdf_nbuf_t buf,
		 int frag_num, int is_wordstream)
{
	QDF_BUG(!(frag_num >= QDF_NBUF_CB_TX_MAX_EXTRA_FRAGS));
	__qdf_nbuf_set_frag_is_wordstream(buf, frag_num, is_wordstream);
}

static inline void
qdf_nbuf_set_vdev_ctx(qdf_nbuf_t buf, uint8_t vdev_id)
{
	__qdf_nbuf_set_vdev_ctx(buf, vdev_id);
}

static inline void
qdf_nbuf_set_tx_ftype(qdf_nbuf_t buf, enum cb_ftype type)
{
	__qdf_nbuf_set_tx_ftype(buf, type);
}

static inline void
qdf_nbuf_set_rx_ftype(qdf_nbuf_t buf, enum cb_ftype type)
{
	__qdf_nbuf_set_rx_ftype(buf, type);
}

#if defined(CONFIG_NBUF_AP_PLATFORM)
static inline void qdf_nbuf_set_vdev_xmit_type(qdf_nbuf_t buf, uint8_t type)
{
	__qdf_nbuf_set_vdev_xmit_type(buf, type);
}

static inline uint8_t qdf_nbuf_get_vdev_xmit_type(qdf_nbuf_t buf)
{
	return __qdf_nbuf_get_vdev_xmit_type(buf);
}
#else
static inline void qdf_nbuf_set_vdev_xmit_type(qdf_nbuf_t buf, uint8_t type)
{
}

static inline uint8_t qdf_nbuf_get_vdev_xmit_type(qdf_nbuf_t buf)
{
	return 0;
}
#endif

static inline uint8_t
qdf_nbuf_get_vdev_ctx(qdf_nbuf_t buf)
{
	return  __qdf_nbuf_get_vdev_ctx(buf);
}

static inline enum cb_ftype qdf_nbuf_get_tx_ftype(qdf_nbuf_t buf)
{
	return  __qdf_nbuf_get_tx_ftype(buf);
}

static inline enum cb_ftype qdf_nbuf_get_rx_ftype(qdf_nbuf_t buf)
{
	return  __qdf_nbuf_get_rx_ftype(buf);
}


static inline qdf_dma_addr_t
qdf_nbuf_mapped_paddr_get(qdf_nbuf_t buf)
{
	return __qdf_nbuf_mapped_paddr_get(buf);
}

static inline void
qdf_nbuf_mapped_paddr_set(qdf_nbuf_t buf, qdf_dma_addr_t paddr)
{
	__qdf_nbuf_mapped_paddr_set(buf, paddr);
}

static inline void
qdf_nbuf_frag_push_head(qdf_nbuf_t buf,
			int frag_len, unsigned char *frag_vaddr,
			qdf_dma_addr_t frag_paddr)
{
	__qdf_nbuf_frag_push_head(buf, frag_len, frag_vaddr, frag_paddr);
}

#define qdf_nbuf_num_frags_init(_nbuf) __qdf_nbuf_num_frags_init((_nbuf))

/**
 * qdf_nbuf_set_rx_chfrag_start() - set msdu start bit
 * @buf: Network buffer
 * @val: 0/1
 *
 * Return: void
 */
static inline void
qdf_nbuf_set_rx_chfrag_start(qdf_nbuf_t buf, uint8_t val)
{
	__qdf_nbuf_set_rx_chfrag_start(buf, val);
}

/**
 * qdf_nbuf_is_rx_chfrag_start() - get msdu start bit
 * @buf: Network buffer
 *
 * Return: integer value - 0/1
 */
static inline int qdf_nbuf_is_rx_chfrag_start(qdf_nbuf_t buf)
{
	return __qdf_nbuf_is_rx_chfrag_start(buf);
}

/**
 * qdf_nbuf_set_rx_chfrag_cont() - set msdu continuation bit
 * @buf: Network buffer
 * @val: 0/1
 *
 * Return: void
 */
static inline void
qdf_nbuf_set_rx_chfrag_cont(qdf_nbuf_t buf, uint8_t val)
{
	__qdf_nbuf_set_rx_chfrag_cont(buf, val);
}

/**
 * qdf_nbuf_is_rx_chfrag_cont() - get msdu continuation bit
 * @buf: Network buffer
 *
 * Return: integer value - 0/1
 */
static inline int qdf_nbuf_is_rx_chfrag_cont(qdf_nbuf_t buf)
{
	return __qdf_nbuf_is_rx_chfrag_cont(buf);
}

/**
 * qdf_nbuf_set_rx_chfrag_end() - set msdu end bit
 * @buf: Network buffer
 * @val: 0/1
 *
 * Return: void
 */
static inline void qdf_nbuf_set_rx_chfrag_end(qdf_nbuf_t buf, uint8_t val)
{
	__qdf_nbuf_set_rx_chfrag_end(buf, val);
}

/**
 * qdf_nbuf_is_rx_chfrag_end() - set msdu end bit
 * @buf: Network buffer
 *
 * Return: integer value - 0/1
 */
static inline int qdf_nbuf_is_rx_chfrag_end(qdf_nbuf_t buf)
{
	return __qdf_nbuf_is_rx_chfrag_end(buf);
}

/**
 * qdf_nbuf_set_da_mcbc() - set da is mcbc
 * @buf: Network buffer
 * @val: 0/1
 *
 * Return: void
 */
static inline void
qdf_nbuf_set_da_mcbc(qdf_nbuf_t buf, uint8_t val)
{
	__qdf_nbuf_set_da_mcbc(buf, val);
}

/**
 * qdf_nbuf_is_da_mcbc() - get da is mcbc bit
 * @buf: Network buffer
 *
 * Return: integer value - 0/1
 */
static inline int qdf_nbuf_is_da_mcbc(qdf_nbuf_t buf)
{
	return __qdf_nbuf_is_da_mcbc(buf);
}

/**
 * qdf_nbuf_set_da_valid() - set  da valid bit
 * @buf: Network buffer
 * @val: 0/1
 *
 * Return: void
 */
static inline void qdf_nbuf_set_da_valid(qdf_nbuf_t buf, uint8_t val)
{
	__qdf_nbuf_set_da_valid(buf, val);
}

/**
 * qdf_nbuf_is_da_valid() - get da valid bit
 * @buf: Network buffer
 *
 * Return: integer value - 0/1
 */
static inline int qdf_nbuf_is_da_valid(qdf_nbuf_t buf)
{
	return __qdf_nbuf_is_da_valid(buf);
}

/**
 * qdf_nbuf_set_sa_valid() - set  sa valid bit
 * @buf: Network buffer
 * @val: 0/1
 *
 * Return: void
 */
static inline void qdf_nbuf_set_sa_valid(qdf_nbuf_t buf, uint8_t val)
{
	__qdf_nbuf_set_sa_valid(buf, val);
}

/**
 * qdf_nbuf_is_sa_valid() - get da valid bit
 * @buf: Network buffer
 *
 * Return: integer value - 0/1
 */
static inline int qdf_nbuf_is_sa_valid(qdf_nbuf_t buf)
{
	return __qdf_nbuf_is_sa_valid(buf);
}

/**
 * qdf_nbuf_set_rx_retry_flag() - set rx retry flag bit
 * @buf: Network buffer
 * @val: 0/1
 *
 * Return: void
 */
static inline void qdf_nbuf_set_rx_retry_flag(qdf_nbuf_t buf, uint8_t val)
{
	__qdf_nbuf_set_rx_retry_flag(buf, val);
}

/**
 * qdf_nbuf_is_rx_retry_flag() - get rx retry flag bit
 * @buf: Network buffer
 *
 * Return: integer value - 0/1
 */
static inline int qdf_nbuf_is_rx_retry_flag(qdf_nbuf_t buf)
{
	return __qdf_nbuf_is_rx_retry_flag(buf);
}

/**
 * qdf_nbuf_set_raw_frame() - set  raw_frame bit
 * @buf: Network buffer
 * @val: 0/1
 *
 * Return: void
 */
static inline void qdf_nbuf_set_raw_frame(qdf_nbuf_t buf, uint8_t val)
{
	__qdf_nbuf_set_raw_frame(buf, val);
}

/**
 * qdf_nbuf_is_raw_frame() -  get raw_frame bit
 * @buf: Network buffer
 *
 * Return: integer value - 0/1
 */
static inline int qdf_nbuf_is_raw_frame(qdf_nbuf_t buf)
{
	return __qdf_nbuf_is_raw_frame(buf);
}

/**
 * qdf_nbuf_is_fr_ds_set() - get from DS bit
 * @buf: Network buffer
 *
 * Return: integer value - 0/1
 */
static inline int qdf_nbuf_is_fr_ds_set(qdf_nbuf_t buf)
{
	return __qdf_nbuf_is_fr_ds_set(buf);
}

/**
 * qdf_nbuf_is_to_ds_set() - get to DS bit
 * @buf: Network buffer
 *
 * Return: integer value - 0/1
 */
static inline int qdf_nbuf_is_to_ds_set(qdf_nbuf_t buf)
{
	return __qdf_nbuf_is_to_ds_set(buf);
}

/**
 * qdf_nbuf_set_tid_val() - set  tid_val
 * @buf: Network buffer
 * @val: 4 bits tid value
 */
static inline void qdf_nbuf_set_tid_val(qdf_nbuf_t buf, uint8_t val)
{
	__qdf_nbuf_set_tid_val(buf, val);
}

/**
 * qdf_nbuf_get_tid_val() - get  tid_val
 * @buf: Network buffer
 *
 * Return: integer value[4 bits tid value]
 */
static inline uint8_t qdf_nbuf_get_tid_val(qdf_nbuf_t buf)
{
	return __qdf_nbuf_get_tid_val(buf);
}

/**
 * qdf_nbuf_set_is_frag() - set  frag list bit
 * @buf: Network buffer
 * @val: 0/1
 *
 * Return: void
 */
static inline void qdf_nbuf_set_is_frag(qdf_nbuf_t buf, uint8_t val)
{
	__qdf_nbuf_set_is_frag(buf, val);
}

/**
 * qdf_nbuf_is_frag() - get da frag list bit
 * @buf: Network buffer
 *
 * Return: integer value - 0/1
 */
static inline int qdf_nbuf_is_frag(qdf_nbuf_t buf)
{
	return __qdf_nbuf_is_frag(buf);
}

/**
 * qdf_nbuf_set_tx_chfrag_start() - set msdu start bit
 * @buf: Network buffer
 * @val: 0/1
 *
 * Return: void
 */
static inline void
qdf_nbuf_set_tx_chfrag_start(qdf_nbuf_t buf, uint8_t val)
{
	__qdf_nbuf_set_tx_chfrag_start(buf, val);
}

/**
 * qdf_nbuf_is_tx_chfrag_start() - get msdu start bit
 * @buf: Network buffer
 *
 * Return: integer value - 0/1
 */
static inline int qdf_nbuf_is_tx_chfrag_start(qdf_nbuf_t buf)
{
	return __qdf_nbuf_is_tx_chfrag_start(buf);
}

/**
 * qdf_nbuf_set_tx_chfrag_cont() - set msdu continuation bit
 * @buf: Network buffer
 * @val: 0/1
 *
 * Return: void
 */
static inline void
qdf_nbuf_set_tx_chfrag_cont(qdf_nbuf_t buf, uint8_t val)
{
	__qdf_nbuf_set_tx_chfrag_cont(buf, val);
}

/**
 * qdf_nbuf_is_tx_chfrag_cont() - get msdu continuation bit
 * @buf: Network buffer
 *
 * Return: integer value - 0/1
 */
static inline int qdf_nbuf_is_tx_chfrag_cont(qdf_nbuf_t buf)
{
	return __qdf_nbuf_is_tx_chfrag_cont(buf);
}

/**
 * qdf_nbuf_set_tx_chfrag_end() - set msdu end bit
 * @buf: Network buffer
 * @val: 0/1
 *
 * Return: void
 */
static inline void qdf_nbuf_set_tx_chfrag_end(qdf_nbuf_t buf, uint8_t val)
{
	__qdf_nbuf_set_tx_chfrag_end(buf, val);
}

/**
 * qdf_nbuf_is_tx_chfrag_end() - set msdu end bit
 * @buf: Network buffer
 *
 * Return: integer value - 0/1
 */
static inline int qdf_nbuf_is_tx_chfrag_end(qdf_nbuf_t buf)
{
	return __qdf_nbuf_is_tx_chfrag_end(buf);
}

static inline void
qdf_nbuf_dma_map_info(qdf_dma_map_t bmap, qdf_dmamap_info_t *sg)
{
	__qdf_nbuf_dma_map_info(bmap, sg);
}

/**
 * qdf_nbuf_is_tso() - is the network buffer a jumbo packet?
 * @nbuf: Network buffer
 *
 * Return: 1 - this is a jumbo packet 0 - not a jumbo packet
 */
static inline uint8_t qdf_nbuf_is_tso(qdf_nbuf_t nbuf)
{
	return __qdf_nbuf_is_tso(nbuf);
}

/**
 * qdf_nbuf_get_users() - function to get the number of users referencing this
 * network buffer
 *
 * @nbuf:   network buffer
 *
 * Return: number of user references to nbuf.
 */
static inline int qdf_nbuf_get_users(qdf_nbuf_t nbuf)
{
	return __qdf_nbuf_get_users(nbuf);
}

/**
 * qdf_nbuf_next() - get the next packet in the linked list
 * @buf: Network buffer
 *
 * This function can be used when nbufs are directly linked into a list,
 * rather than using a separate network buffer queue object.
 *
 * Return: next network buffer in the linked list
 */
static inline qdf_nbuf_t qdf_nbuf_next(qdf_nbuf_t buf)
{
	return __qdf_nbuf_next(buf);
}

#ifdef IPA_OFFLOAD
/**
 * qdf_nbuf_smmu_map_debug() - map smmu buffer
 * @nbuf: network buffer
 * @hdl: ipa handle
 * @num_buffers: number of buffers
 * @info: memory info
 * @func: function name
 * @line: line number
 *
 * Return: QDF_STATUS
 */
QDF_STATUS qdf_nbuf_smmu_map_debug(qdf_nbuf_t nbuf,
				   uint8_t hdl,
				   uint8_t num_buffers,
				   qdf_mem_info_t *info,
				   const char *func,
				   uint32_t line);

/**
 * qdf_nbuf_smmu_unmap_debug() - unmap smmu buffer
 * @nbuf: network buffer
 * @hdl: ipa handle
 * @num_buffers: number of buffers
 * @info: memory info
 * @func: function name
 * @line: line number
 *
 * Return: QDF_STATUS
 */
QDF_STATUS qdf_nbuf_smmu_unmap_debug(qdf_nbuf_t nbuf,
				     uint8_t hdl,
				     uint8_t num_buffers,
				     qdf_mem_info_t *info,
				     const char *func,
				     uint32_t line);

#endif /* IPA_OFFLOAD */

#ifdef NBUF_MEMORY_DEBUG

#define QDF_NET_BUF_TRACK_MAX_SIZE    (1024)

enum qdf_nbuf_event_type {
	QDF_NBUF_ALLOC,
	QDF_NBUF_ALLOC_CLONE,
	QDF_NBUF_ALLOC_COPY,
	QDF_NBUF_ALLOC_FAILURE,
	QDF_NBUF_FREE,
	QDF_NBUF_MAP,
	QDF_NBUF_UNMAP,
	QDF_NBUF_ALLOC_COPY_EXPAND,
	QDF_NBUF_SMMU_MAP,
	QDF_NBUF_SMMU_UNMAP,
};

/**
 * qdf_net_buf_debug_init() - initialize network buffer debug functionality
 *
 * QDF network buffer debug feature tracks all SKBs allocated by WLAN driver
 * in a hash table and when driver is unloaded it reports about leaked SKBs.
 * WLAN driver module whose allocated SKB is freed by network stack are
 * suppose to call qdf_net_buf_debug_release_skb() such that the SKB is not
 * reported as memory leak.
 *
 * Return: none
 */
void qdf_net_buf_debug_init(void);

/**
 * qdf_net_buf_debug_exit() - exit network buffer debug functionality
 *
 * Exit network buffer tracking debug functionality and log SKB memory leaks
 * As part of exiting the functionality, free the leaked memory and
 * cleanup the tracking buffers.
 *
 * Return: none
 */
void qdf_net_buf_debug_exit(void);

void qdf_net_buf_debug_clean(void);
void qdf_nbuf_history_add(qdf_nbuf_t nbuf, const char *func, uint32_t line,
			  enum qdf_nbuf_event_type type);

/**
 * qdf_net_buf_debug_add_node() - store skb in debug hash table
 * @net_buf: network buffer
 * @size: buffer size
 * @func_name: function name that requests for mapping the nbuf
 * @line_num: function line number
 *
 * Return: none
 */
void qdf_net_buf_debug_add_node(qdf_nbuf_t net_buf, size_t size,
				const char *func_name, uint32_t line_num);

/**
 * qdf_net_buf_debug_update_node() - update nbuf in debug hash table
 * @net_buf: network buffer
 * @func_name: function name that requests for mapping the nbuf
 * @line_num: function line number
 *
 * Return: none
 */
void qdf_net_buf_debug_update_node(qdf_nbuf_t net_buf, const char *func_name,
				   uint32_t line_num);

/**
 * qdf_net_buf_debug_delete_node() - remove skb from debug hash table
 * @net_buf: network buffer
 *
 * Return: none
 */
void qdf_net_buf_debug_delete_node(qdf_nbuf_t net_buf);

/**
 * qdf_net_buf_debug_update_map_node() - update nbuf in debug
 * hash table with the mapping function info
 * @net_buf: network buffer
 * @func_name: function name that requests for mapping the nbuf
 * @line_num: function line number
 *
 * Return: none
 */
void qdf_net_buf_debug_update_map_node(qdf_nbuf_t net_buf,
				       const char *func_name,
				       uint32_t line_num);

#ifdef NBUF_SMMU_MAP_UNMAP_DEBUG
/**
 * qdf_nbuf_map_check_for_smmu_leaks() - check for nbuf smmu map leaks
 *
 * Check for net buffers that have been smmu mapped, but never smmu unmapped.
 *
 * Returns: None
 */
void qdf_nbuf_map_check_for_smmu_leaks(void);

/**
 * qdf_net_buf_debug_update_smmu_map_node() - update nbuf in debug
 * hash table with the mapping function info
 * @nbuf: network buffer
 * @iova: Virtual address of buffer
 * @pa: Physical address of buffer
 * @func: function name that requests for mapping the nbuf
 * @line: function line number
 *
 * Return: none
 */
void qdf_net_buf_debug_update_smmu_map_node(qdf_nbuf_t nbuf,
					    unsigned long iova,
					    unsigned long pa,
					    const char *func,
					    uint32_t line);

/**
 * qdf_net_buf_debug_update_smmu_unmap_node() - update nbuf in debug
 * hash table with the unmapping function info
 * @nbuf: network buffer
 * @iova: Virtual address of buffer
 * @pa: Physical address of buffer
 * @func: function name that requests for unmapping the nbuf
 * @line: function line number
 *
 * Return: none
 */
void qdf_net_buf_debug_update_smmu_unmap_node(qdf_nbuf_t nbuf,
					      unsigned long iova,
					      unsigned long pa,
					      const char *func,
					      uint32_t line);
#endif /* NBUF_SMMU_MAP_UNMAP_DEBUG */

/**
 * qdf_net_buf_debug_update_unmap_node() - update nbuf in debug
 * hash table with the unmap function info
 * @net_buf:   network buffer
 * @func_name: function name that requests for unmapping the nbuf
 * @line_num: function line number
 *
 * Return: none
 */
void qdf_net_buf_debug_update_unmap_node(qdf_nbuf_t net_buf,
					 const char *func_name,
					 uint32_t line_num);

/**
 * qdf_net_buf_debug_acquire_skb() - acquire skb to avoid memory leak
 * @net_buf: Network buf holding head segment (single)
 * @func_name: pointer to function name
 * @line_num: line number
 *
 * WLAN driver module's SKB which are allocated by network stack are
 * suppose to call this API before freeing it such that the SKB
 * is not reported as memory leak.
 *
 * Return: none
 */
void qdf_net_buf_debug_acquire_skb(qdf_nbuf_t net_buf,
				   const char *func_name,
				   uint32_t line_num);

/**
 * qdf_net_buf_debug_release_skb() - release skb to avoid memory leak
 * @net_buf: Network buf holding head segment (single)
 *
 * WLAN driver module whose allocated SKB is freed by network stack are
 * suppose to call this API before returning SKB to network stack such
 * that the SKB is not reported as memory leak.
 *
 * Return: none
 */
void qdf_net_buf_debug_release_skb(qdf_nbuf_t net_buf);

/* nbuf allocation routines */

#define qdf_nbuf_alloc_simple(d, s, r, a, p) \
	__qdf_nbuf_alloc_simple(d, s, __func__, __LINE__)

#define qdf_nbuf_alloc(d, s, r, a, p) \
	qdf_nbuf_alloc_debug(d, s, r, a, p, __func__, __LINE__)

qdf_nbuf_t qdf_nbuf_alloc_debug(qdf_device_t osdev, qdf_size_t size,
				int reserve, int align, int prio,
				const char *func, uint32_t line);

#define qdf_nbuf_frag_alloc(d, s, r, a, p) \
	qdf_nbuf_frag_alloc_debug(d, s, r, a, p, __func__, __LINE__)

qdf_nbuf_t qdf_nbuf_frag_alloc_debug(qdf_device_t osdev, qdf_size_t size,
				     int reserve, int align, int prio,
				     const char *func, uint32_t line);

/**
 * qdf_nbuf_alloc_no_recycler() - Allocates skb
 * @size: Size to be allocated for skb
 * @reserve: Reserved headroom size
 * @align: Align
 *
 * This API allocates skb of required size and aligns if needed and reserves
 * some space in the front. This skb allocation is not from skb recycler pool.
 *
 * Return: Allocated nbuf pointer
 */
#define qdf_nbuf_alloc_no_recycler(size, reserve, align) \
	qdf_nbuf_alloc_no_recycler_debug(size, reserve, align, __func__, __LINE__)

/**
 * qdf_nbuf_alloc_no_recycler_debug() - Allocates skb
 * @size: Size to be allocated for skb
 * @reserve: Reserved headroom size
 * @align: Align
 * @func: Function name of the call site
 * @line: Line number of the callsite
 *
 * This API allocates skb of required size and aligns if needed and reserves
 * some space in the front. This skb allocation is not from skb recycler pool.
 *
 * Return: Allocated nbuf pointer
 */
qdf_nbuf_t qdf_nbuf_alloc_no_recycler_debug(size_t size, int reserve, int align,
					    const char *func, uint32_t line);
#define qdf_nbuf_free(d) \
	qdf_nbuf_free_debug(d, __func__, __LINE__)

void qdf_nbuf_free_debug(qdf_nbuf_t nbuf, const char *func, uint32_t line);

#define qdf_nbuf_free_simple(d) \
	qdf_nbuf_free_debug_simple(d, __func__, __LINE__)

void qdf_nbuf_free_debug_simple(qdf_nbuf_t nbuf, const char *func,
				uint32_t line);

#define qdf_nbuf_clone(buf)     \
	qdf_nbuf_clone_debug(buf, __func__, __LINE__)

/**
 * qdf_nbuf_clone_debug() - clone the nbuf (copy is readonly)
 * @buf: nbuf to clone from
 * @func: name of the calling function
 * @line: line number of the callsite
 *
 * This function clones the nbuf and creates a memory tracking
 * node corresponding to that cloned skbuff structure.
 *
 * Return: cloned buffer
 */
qdf_nbuf_t qdf_nbuf_clone_debug(qdf_nbuf_t buf, const char *func,
				uint32_t line);

#define qdf_nbuf_copy(buf)     \
	qdf_nbuf_copy_debug(buf, __func__, __LINE__)

/**
 * qdf_nbuf_copy_debug() - returns a private copy of the buf
 * @buf: nbuf to copy from
 * @func: name of the calling function
 * @line: line number of the callsite
 *
 * This API returns a private copy of the buf, the buf returned is completely
 * modifiable by callers. It also creates a memory tracking node corresponding
 * to that new skbuff structure.
 *
 * Return: copied buffer
 */
qdf_nbuf_t qdf_nbuf_copy_debug(qdf_nbuf_t buf, const char *func, uint32_t line);

#define qdf_nbuf_copy_expand(buf, headroom, tailroom)     \
	qdf_nbuf_copy_expand_debug(buf, headroom, tailroom, __func__, __LINE__)

/**
 * qdf_nbuf_copy_expand_debug() - copy and expand nbuf
 * @buf: Network buf instance
 * @headroom: Additional headroom to be added
 * @tailroom: Additional tailroom to be added
 * @func: name of the calling function
 * @line: line number of the callsite
 *
 * Return: New nbuf that is a copy of buf, with additional head and tailroom
 *	or NULL if there is no memory
 */
qdf_nbuf_t
qdf_nbuf_copy_expand_debug(qdf_nbuf_t buf, int headroom, int tailroom,
			   const char *func, uint32_t line);

/**
 * qdf_nbuf_unshare() - make a copy of the shared nbuf
 * @buf: Network buf instance
 *
 * Return: New nbuf which is a copy of the received nbuf if it is cloned,
 *      else, return the original nbuf
 */
#define qdf_nbuf_unshare(buf) \
	qdf_nbuf_unshare_debug(buf, __func__, __LINE__)

qdf_nbuf_t
qdf_nbuf_unshare_debug(qdf_nbuf_t buf, const char *func_name,
		       uint32_t line_num);

/**
 * qdf_nbuf_dev_kfree_list() - Free nbuf list using kfree
 * @buf: Pointer to network buffer head
 *
 * This function is called to free the nbuf list on failure cases
 *
 * Return: None
 */
#define qdf_nbuf_dev_kfree_list(buf) \
	qdf_nbuf_dev_kfree_list_debug(buf, __func__, __LINE__)

void
qdf_nbuf_dev_kfree_list_debug(qdf_nbuf_queue_head_t *nbuf_queue_head,
			      const char *func_name,
			      uint32_t line_num);

#define qdf_nbuf_page_frag_alloc(d, s, r, a, p) \
	qdf_nbuf_page_frag_alloc_debug(d, s, r, a, p, __func__, __LINE__)

qdf_nbuf_t
qdf_nbuf_page_frag_alloc_debug(qdf_device_t osdev, qdf_size_t size, int reserve,
			       int align, qdf_frag_cache_t *pf_cache,
			       const char *func, uint32_t line);

/**
 * qdf_nbuf_ssr_register_region() - Register nbuf history with SSR dump
 *
 * Return: None
 */
void qdf_nbuf_ssr_register_region(void);

/**
 * qdf_nbuf_ssr_unregister_region() - Unregister nbuf history with SSR dump
 *
 * Return: None
 */

void qdf_nbuf_ssr_unregister_region(void);

#else /* NBUF_MEMORY_DEBUG */

static inline
void qdf_nbuf_ssr_register_region(void)
{
}

static inline
void qdf_nbuf_ssr_unregister_region(void)
{
}

static inline void qdf_net_buf_debug_init(void) {}
static inline void qdf_net_buf_debug_exit(void) {}

static inline void qdf_net_buf_debug_acquire_skb(qdf_nbuf_t net_buf,
						 const char *func_name,
						 uint32_t line_num)
{
}

static inline void qdf_net_buf_debug_release_skb(qdf_nbuf_t net_buf)
{
}

static inline void
qdf_net_buf_debug_update_node(qdf_nbuf_t net_buf, const char *func_name,
			      uint32_t line_num)
{
}

static inline void
qdf_net_buf_debug_update_map_node(qdf_nbuf_t net_buf,
				  const char *func_name,
				  uint32_t line_num)
{
}

static inline void
qdf_net_buf_debug_update_unmap_node(qdf_nbuf_t net_buf,
				    const char *func_name,
				    uint32_t line_num)
{
}
/* Nbuf allocation routines */

#define qdf_nbuf_alloc_simple(osdev, size, reserve, align, prio) \
	qdf_nbuf_alloc_fl(osdev, size, reserve, align, prio, \
			  __func__, __LINE__)

#define qdf_nbuf_alloc(osdev, size, reserve, align, prio) \
	qdf_nbuf_alloc_fl(osdev, size, reserve, align, prio, \
			  __func__, __LINE__)

#define qdf_nbuf_alloc_no_recycler(size, reserve, align) \
	qdf_nbuf_alloc_no_recycler_fl(size, reserve, align, __func__, __LINE__)

static inline qdf_nbuf_t
qdf_nbuf_alloc_fl(qdf_device_t osdev, qdf_size_t size, int reserve, int align,
		  int prio, const char *func, uint32_t line)
{
	return __qdf_nbuf_alloc(osdev, size, reserve, align, prio, func, line);
}

#define qdf_nbuf_frag_alloc(osdev, size, reserve, align, prio) \
	qdf_nbuf_frag_alloc_fl(osdev, size, reserve, align, prio, \
			  __func__, __LINE__)

static inline qdf_nbuf_t
qdf_nbuf_frag_alloc_fl(qdf_device_t osdev, qdf_size_t size, int reserve,
		       int align, int prio, const char *func, uint32_t line)
{
	return __qdf_nbuf_frag_alloc(osdev, size, reserve, align, prio,
				     func, line);
}

/**
 * qdf_nbuf_alloc_no_recycler_fl() - Allocate SKB
 * @size: Size to be allocated for skb
 * @reserve: Reserved headroom size
 * @align: Align
 * @func: Function name of the call site
 * @line: Line number of the callsite
 *
 * This API allocates skb of required size and aligns if needed and reserves
 * some space in the front. This skb allocation is not from skb recycler pool.
 *
 * Return: Allocated nbuf pointer
 */
static inline qdf_nbuf_t
qdf_nbuf_alloc_no_recycler_fl(size_t size, int reserve, int align,
			      const char *func, uint32_t line)
{
	return __qdf_nbuf_alloc_no_recycler(size, reserve, align, func, line);
}

#define qdf_nbuf_free_simple(d) qdf_nbuf_free(d)

static inline void qdf_nbuf_free(qdf_nbuf_t buf)
{
	if (qdf_likely(buf))
		__qdf_nbuf_free(buf);
}

/**
 * qdf_nbuf_clone() - clone the nbuf (copy is readonly)
 * @buf: Pointer to network buffer
 *
 * This function clones the nbuf and returns new sk_buff
 * structure.
 *
 * Return: cloned skb
 */
static inline qdf_nbuf_t qdf_nbuf_clone(qdf_nbuf_t buf)
{
	return __qdf_nbuf_clone(buf);
}

/**
 * qdf_nbuf_copy() - returns a private copy of the buf
 * @buf: Pointer to network buffer
 *
 * This API returns a private copy of the buf, the buf returned is completely
 *  modifiable by callers
 *
 * Return: skb or NULL
 */
static inline qdf_nbuf_t qdf_nbuf_copy(qdf_nbuf_t buf)
{
	return __qdf_nbuf_copy(buf);
}

/**
 * qdf_nbuf_copy_expand() - copy and expand nbuf
 * @buf: Network buf instance
 * @headroom: Additional headroom to be added
 * @tailroom: Additional tailroom to be added
 *
 * Return: New nbuf that is a copy of buf, with additional head and tailroom
 *	or NULL if there is no memory
 */
static inline qdf_nbuf_t qdf_nbuf_copy_expand(qdf_nbuf_t buf, int headroom,
					      int tailroom)
{
	return __qdf_nbuf_copy_expand(buf, headroom, tailroom);
}

static inline qdf_nbuf_t qdf_nbuf_unshare(qdf_nbuf_t buf)
{
	return __qdf_nbuf_unshare(buf);
}

/**
 * qdf_nbuf_dev_kfree_list() - Free nbuf list using kfree
 * @nbuf_queue_head: Pointer to buffer list head
 *
 * This function is called to free the nbuf list on failure cases
 *
 * Return: None
 */
static inline void
qdf_nbuf_dev_kfree_list(qdf_nbuf_queue_head_t *nbuf_queue_head)
{
	__qdf_nbuf_dev_kfree_list(nbuf_queue_head);
}

#define qdf_nbuf_page_frag_alloc(osdev, size, reserve, align, pf_cache) \
	qdf_nbuf_page_frag_alloc_fl(osdev, size, reserve, align, pf_cache, \
			  __func__, __LINE__)

static inline qdf_nbuf_t
qdf_nbuf_page_frag_alloc_fl(qdf_device_t osdev, qdf_size_t size, int reserve,
			    int align, qdf_frag_cache_t *pf_cache,
			    const char *func, uint32_t line)
{
	return __qdf_nbuf_page_frag_alloc(osdev, size, reserve, align, pf_cache,
					  func, line);
}
#endif /* NBUF_MEMORY_DEBUG */

#if defined(QCA_DP_NBUF_FAST_PPEDS)
#define qdf_nbuf_alloc_ppe_ds(d, s, r, a, p) \
	__qdf_nbuf_alloc_ppe_ds(d, s, __func__, __LINE__)
#endif /* QCA_DP_NBUF_FAST_PPEDS */

/**
 * qdf_nbuf_dev_queue_head() - Queue a buffer at the list head
 * @nbuf_queue_head: Pointer to buffer list head
 * @buf: Pointer to network buffer head
 *
 * This function is called to queue a buffer at the list head
 *
 * Return: None
 */
static inline void
qdf_nbuf_dev_queue_head(qdf_nbuf_queue_head_t *nbuf_queue_head,
			qdf_nbuf_t buf)
{
	__qdf_nbuf_dev_queue_head(nbuf_queue_head, buf);
}

/**
 * qdf_nbuf_kfree() - Free nbuf using kfree
 * @buf: Pointer to network buffer
 *
 * This function is called to free the skb on failure cases
 *
 * Return: None
 */
static inline void qdf_nbuf_kfree(qdf_nbuf_t buf)
{
	__qdf_nbuf_kfree(buf);
}

/**
 * qdf_nbuf_dev_kfree() - Free nbuf using dev based os call
 * @buf: Pointer to network buffer
 *
 * This function is called to free the skb on failure cases
 *
 * Return: None
 */
static inline void qdf_nbuf_dev_kfree(qdf_nbuf_t buf)
{
	__qdf_nbuf_dev_kfree(buf);
}

/**
 * qdf_nbuf_copy_expand_fraglist() - copy and expand nbuf and
 * get reference of the fraglist.
 * @buf: Network buf instance
 * @headroom: Additional headroom to be added
 * @tailroom: Additional tailroom to be added
 *
 * Return: New nbuf that is a copy of buf, with additional head and tailroom
 *	or NULL if there is no memory
 */
static inline qdf_nbuf_t
qdf_nbuf_copy_expand_fraglist(qdf_nbuf_t buf, int headroom,
			      int tailroom)
{
	buf = qdf_nbuf_copy_expand(buf, headroom, tailroom);

	/* get fraglist reference */
	if (buf)
		__qdf_nbuf_get_ref_fraglist(buf);

	return buf;
}

#ifdef WLAN_FEATURE_FASTPATH
/**
 * qdf_nbuf_init_fast() - before put buf into pool,turn it to init state
 * @nbuf: buf instance
 *
 * Return: data pointer of this buf where new data has to be
 *         put, or NULL if there is not enough room in this buf.
 */
void qdf_nbuf_init_fast(qdf_nbuf_t nbuf);
#endif /* WLAN_FEATURE_FASTPATH */

/**
 * qdf_nbuf_list_free() - free a list of nbufs
 * @buf_list: A list of nbufs to be freed
 *
 * Return: none
 */
static inline void qdf_nbuf_list_free(qdf_nbuf_t buf_list)
{
	while (buf_list) {
		qdf_nbuf_t next = qdf_nbuf_next(buf_list);
		qdf_nbuf_free(buf_list);
		buf_list = next;
	}
}

static inline void qdf_nbuf_tx_free(qdf_nbuf_t buf_list, int tx_err)
{
	qdf_nbuf_list_free(buf_list);
}

static inline void qdf_nbuf_ref(qdf_nbuf_t buf)
{
	__qdf_nbuf_ref(buf);
}

static inline int qdf_nbuf_shared(qdf_nbuf_t buf)
{
	return __qdf_nbuf_shared(buf);
}

static inline QDF_STATUS qdf_nbuf_cat(qdf_nbuf_t dst, qdf_nbuf_t src)
{
	return __qdf_nbuf_cat(dst, src);
}

/**
 * qdf_nbuf_copy_bits() - return the length of the copy bits for skb
 * @nbuf: netbuf
 * @offset: offset
 * @len: Length
 * @to: To
 *
 * Return: int32_t
 */
static inline int32_t
qdf_nbuf_copy_bits(qdf_nbuf_t nbuf, uint32_t offset, uint32_t len, void *to)
{
	return __qdf_nbuf_copy_bits(nbuf, offset, len, to);
}


/* nbuf manipulation routines */

/**
 * qdf_nbuf_head() - return the address of an nbuf's buffer
 * @buf: netbuf
 *
 * Return: head address
 */
static inline uint8_t *qdf_nbuf_head(qdf_nbuf_t buf)
{
	return __qdf_nbuf_head(buf);
}

/**
 * qdf_nbuf_data() - Return the address of the start of data within an nbuf
 * @buf: Network buffer
 *
 * Return: Data address
 */
static inline uint8_t *qdf_nbuf_data(qdf_nbuf_t buf)
{
	return __qdf_nbuf_data(buf);
}

/**
 * qdf_nbuf_data_addr() - Return the address of skb->data
 * @buf: Network buffer
 *
 * Return: Data address
 */
static inline uint8_t *qdf_nbuf_data_addr(qdf_nbuf_t buf)
{
	return __qdf_nbuf_data_addr(buf);
}

/**
 * qdf_nbuf_headroom() - amount of headroom int the current nbuf
 * @buf: Network buffer
 *
 * Return: Amount of head room
 */
static inline uint32_t qdf_nbuf_headroom(qdf_nbuf_t buf)
{
	return __qdf_nbuf_headroom(buf);
}

/**
 * qdf_nbuf_tailroom() - amount of tail space available
 * @buf: Network buffer
 *
 * Return: amount of tail room
 */
static inline uint32_t qdf_nbuf_tailroom(qdf_nbuf_t buf)
{
	return __qdf_nbuf_tailroom(buf);
}

/**
 * qdf_nbuf_push_head() - push data in the front
 * @buf: Network buf instance
 * @size: Size to be pushed
 *
 * Return: New data pointer of this buf after data has been pushed,
 *	or NULL if there is not enough room in this buf.
 */
static inline uint8_t *qdf_nbuf_push_head(qdf_nbuf_t buf, qdf_size_t size)
{
	return __qdf_nbuf_push_head(buf, size);
}

/**
 * qdf_nbuf_put_tail() - puts data in the end
 * @buf: Network buf instance
 * @size: Size to be pushed
 *
 * Return: Data pointer of this buf where new data has to be
 *	put, or NULL if there is not enough room in this buf.
 */
static inline uint8_t *qdf_nbuf_put_tail(qdf_nbuf_t buf, qdf_size_t size)
{
	return __qdf_nbuf_put_tail(buf, size);
}

/**
 * qdf_nbuf_pull_head() - pull data out from the front
 * @buf: Network buf instance
 * @size: Size to be popped
 *
 * Return: New data pointer of this buf after data has been popped,
 *	or NULL if there is not sufficient data to pull.
 */
static inline uint8_t *qdf_nbuf_pull_head(qdf_nbuf_t buf, qdf_size_t size)
{
	return __qdf_nbuf_pull_head(buf, size);
}

/**
 * qdf_nbuf_trim_tail() - trim data out from the end
 * @buf: Network buf instance
 * @size: Size to be popped
 *
 * Return: none
 */
static inline void qdf_nbuf_trim_tail(qdf_nbuf_t buf, qdf_size_t size)
{
	__qdf_nbuf_trim_tail(buf, size);
}

/**
 * qdf_nbuf_len() - get the length of the buf
 * @buf: Network buf instance
 *
 * Return: total length of this buf.
 */
static inline qdf_size_t qdf_nbuf_len(qdf_nbuf_t buf)
{
	return __qdf_nbuf_len(buf);
}

/**
 * qdf_nbuf_set_pktlen() - set the length of the buf
 * @buf: Network buf instance
 * @len: Size to be set
 *
 * Return: none
 */
static inline void qdf_nbuf_set_pktlen(qdf_nbuf_t buf, uint32_t len)
{
	__qdf_nbuf_set_pktlen(buf, len);
}

/**
 * qdf_nbuf_reserve() - trim data out from the end
 * @buf: Network buf instance
 * @size: Size to be popped
 *
 * Return: none
 */
static inline void qdf_nbuf_reserve(qdf_nbuf_t buf, qdf_size_t size)
{
	__qdf_nbuf_reserve(buf, size);
}

/**
 * qdf_nbuf_set_data_pointer() - set data pointer
 * @buf: Network buf instance
 * @data: data pointer
 *
 * Return: none
 */
static inline void qdf_nbuf_set_data_pointer(qdf_nbuf_t buf, uint8_t *data)
{
	__qdf_nbuf_set_data_pointer(buf, data);
}

/**
 * qdf_nbuf_set_len() - set data length
 * @buf: Network buf instance
 * @len: data length
 * Return: none
 */
static inline void qdf_nbuf_set_len(qdf_nbuf_t buf, uint32_t len)
{
	__qdf_nbuf_set_len(buf, len);
}

/**
 * qdf_nbuf_set_tail_pointer() - set data tail pointer
 * @buf: Network buf instance
 * @len: length of data
 *
 * Return: none
 */
static inline void qdf_nbuf_set_tail_pointer(qdf_nbuf_t buf, int len)
{
	__qdf_nbuf_set_tail_pointer(buf, len);
}

/**
 * qdf_nbuf_unlink_no_lock() - unlink a nbuf from nbuf list
 * @buf: Network buf instance
 * @list: list to use
 *
 * This is a lockless version, driver must acquire locks if it
 * needs to synchronize
 *
 * Return: none
 */
static inline void
qdf_nbuf_unlink_no_lock(qdf_nbuf_t buf, qdf_nbuf_queue_head_t *list)
{
	__qdf_nbuf_unlink_no_lock(buf, list);
}

/**
 * qdf_nbuf_reset() - reset the buffer data and pointer
 * @buf: Network buf instance
 * @reserve: reserve
 * @align: align
 *
 * Return: none
 */
static inline void qdf_nbuf_reset(qdf_nbuf_t buf, int reserve, int align)
{
	__qdf_nbuf_reset(buf, reserve, align);
}

/**
 * qdf_nbuf_is_dev_scratch_supported() - dev_scratch support for network buffer
 *                                       in kernel
 *
 * Return: true if dev_scratch is supported
 *         false if dev_scratch is not supported
 */
static inline bool qdf_nbuf_is_dev_scratch_supported(void)
{
	return __qdf_nbuf_is_dev_scratch_supported();
}

/**
 * qdf_nbuf_get_dev_scratch() - get dev_scratch of network buffer
 * @buf: Pointer to network buffer
 *
 * Return: dev_scratch if dev_scratch supported
 *         0 if dev_scratch not supported
 */
static inline unsigned long qdf_nbuf_get_dev_scratch(qdf_nbuf_t buf)
{
	return __qdf_nbuf_get_dev_scratch(buf);
}

/**
 * qdf_nbuf_set_dev_scratch() - set dev_scratch of network buffer
 * @buf: Pointer to network buffer
 * @value: value to be set in dev_scratch of network buffer
 *
 * Return: void
 */
static inline void qdf_nbuf_set_dev_scratch(qdf_nbuf_t buf, unsigned long value)
{
	__qdf_nbuf_set_dev_scratch(buf, value);
}

/**
 * qdf_nbuf_set_dev() - set dev in network buffer
 * @nbuf: Pointer to network buffer
 * @dev: netdev to be set in network buffer
 *
 * Return: void
 */
static inline
void qdf_nbuf_set_dev(qdf_nbuf_t nbuf, qdf_netdev_t dev)
{
	__qdf_nbuf_set_dev(nbuf, dev);
}

/**
 * qdf_nbuf_get_dev_mtu() - get dev mtu in n/w buffer
 * @nbuf: Pointer to network buffer
 *
 * Return: dev mtu value in nbuf
 */
static inline
unsigned int qdf_nbuf_get_dev_mtu(qdf_nbuf_t nbuf)
{
	return __qdf_nbuf_get_dev_mtu(nbuf);
}

/**
 * qdf_nbuf_set_protocol_eth_tye_trans() - set protocol using eth trans os API
 * @nbuf: Pointer to network buffer
 *
 * Return: None
 */
static inline
void qdf_nbuf_set_protocol_eth_tye_trans(qdf_nbuf_t nbuf)
{
	__qdf_nbuf_set_protocol_eth_type_trans(nbuf);
}

/**
 * qdf_nbuf_peek_header() - return the data pointer & length of the header
 * @buf: Network nbuf
 * @addr: Data pointer
 * @len: Length of the data
 *
 * Return: none
 */
static inline void
qdf_nbuf_peek_header(qdf_nbuf_t buf, uint8_t **addr, uint32_t *len)
{
	__qdf_nbuf_peek_header(buf, addr, len);
}

/* nbuf queue routines */

/**
 * qdf_nbuf_queue_init() - initialize buf queue
 * @head: Network buf queue head
 *
 * Return: none
 */
static inline void qdf_nbuf_queue_init(qdf_nbuf_queue_t *head)
{
	__qdf_nbuf_queue_init(head);
}

/**
 * qdf_nbuf_queue_add() - append a nbuf to the tail of the buf queue
 * @head: Network buf queue head
 * @buf: Network buf
 *
 * Return: none
 */
static inline void qdf_nbuf_queue_add(qdf_nbuf_queue_t *head, qdf_nbuf_t buf)
{
	__qdf_nbuf_queue_add(head, buf);
}

/**
 * qdf_nbuf_queue_insert_head() - insert nbuf at the head of queue
 * @head: Network buf queue head
 * @buf: Network buf
 *
 * Return: none
 */
static inline void
qdf_nbuf_queue_insert_head(qdf_nbuf_queue_t *head, qdf_nbuf_t buf)
{
	__qdf_nbuf_queue_insert_head(head, buf);
}

/**
 * qdf_nbuf_queue_remove_last() - remove last nbuf from queue
 * @head: Network buf queue head
 *
 * Return: none
 */
static inline qdf_nbuf_t qdf_nbuf_queue_remove_last(qdf_nbuf_queue_t *head)
{
	return __qdf_nbuf_queue_remove_last(head);
}

/**
 * qdf_nbuf_queue_remove() - retrieve a buf from the head of the buf queue
 * @head: Network buf queue head
 *
 * Return: The head buf in the buf queue.
 */
static inline qdf_nbuf_t qdf_nbuf_queue_remove(qdf_nbuf_queue_t *head)
{
	return __qdf_nbuf_queue_remove(head);
}

/**
 * qdf_nbuf_queue_len() - get the length of the queue
 * @head: Network buf queue head
 *
 * Return: length of the queue
 */
static inline uint32_t qdf_nbuf_queue_len(qdf_nbuf_queue_t *head)
{
	return __qdf_nbuf_queue_len(head);
}

/**
 * qdf_nbuf_queue_next() - get the next guy/packet of the given buffer
 * @buf: Network buffer
 *
 * Return: next buffer/packet
 */
static inline qdf_nbuf_t qdf_nbuf_queue_next(qdf_nbuf_t buf)
{
	return __qdf_nbuf_queue_next(buf);
}

/**
 * qdf_nbuf_is_queue_empty() - check if the buf queue is empty
 * @nbq: Network buf queue handle
 *
 * Return: true  if queue is empty
 *	   false if queue is not empty
 */
static inline bool qdf_nbuf_is_queue_empty(qdf_nbuf_queue_t *nbq)
{
	return __qdf_nbuf_is_queue_empty(nbq);
}

static inline qdf_nbuf_queue_t *
qdf_nbuf_queue_append(qdf_nbuf_queue_t *dest, qdf_nbuf_queue_t *src)
{
	return __qdf_nbuf_queue_append(dest, src);
}

static inline void
qdf_nbuf_queue_free(qdf_nbuf_queue_t *head)
{
	qdf_nbuf_t  buf = NULL;

	while ((buf = qdf_nbuf_queue_remove(head)) != NULL)
		qdf_nbuf_free(buf);
}

static inline qdf_nbuf_t
qdf_nbuf_queue_first(qdf_nbuf_queue_t *head)
{
	return __qdf_nbuf_queue_first(head);
}

static inline qdf_nbuf_t
qdf_nbuf_queue_last(qdf_nbuf_queue_t *head)
{
	return __qdf_nbuf_queue_last(head);
}

/**
 * qdf_nbuf_get_protocol() - return the protocol value of the skb
 * @skb: Pointer to network buffer
 *
 * Return: skb protocol
 */
static inline uint16_t qdf_nbuf_get_protocol(struct sk_buff *skb)
{
	return __qdf_nbuf_get_protocol(skb);
}

/**
 * qdf_nbuf_get_ip_summed() - return the ip checksum value of the skb
 * @skb: Pointer to network buffer
 *
 * Return: skb ip_summed
 */
static inline uint8_t qdf_nbuf_get_ip_summed(struct sk_buff *skb)
{
	return __qdf_nbuf_get_ip_summed(skb);
}

/**
 * qdf_nbuf_set_ip_summed() - sets the ip_summed value of the skb
 * @skb: Pointer to network buffer
 * @ip_summed: ip checksum
 *
 * Return: none
 */
static inline void qdf_nbuf_set_ip_summed(struct sk_buff *skb,
	uint8_t ip_summed)
{
	__qdf_nbuf_set_ip_summed(skb, ip_summed);
}

/**
 * qdf_nbuf_set_next() - add a packet to a linked list
 * @this_buf: Predecessor buffer
 * @next_buf: Successor buffer
 *
 * This function can be used to directly link nbufs, rather than using
 * a separate network buffer queue object.
 *
 * Return: none
 */
static inline void qdf_nbuf_set_next(qdf_nbuf_t this_buf, qdf_nbuf_t next_buf)
{
	__qdf_nbuf_set_next(this_buf, next_buf);
}

/* nbuf extension routines */

/**
 * qdf_nbuf_set_next_ext() - link extension of this packet contained in a new
 *			nbuf
 * @this_buf: predecessor buffer
 * @next_buf: successor buffer
 *
 * This function is used to link up many nbufs containing a single logical
 * packet - not a collection of packets. Do not use for linking the first
 * extension to the head
 *
 * Return: none
 */
static inline void
qdf_nbuf_set_next_ext(qdf_nbuf_t this_buf, qdf_nbuf_t next_buf)
{
	__qdf_nbuf_set_next_ext(this_buf, next_buf);
}

/**
 * qdf_nbuf_next_ext() - get the next packet extension in the linked list
 * @buf: Network buffer
 *
 * Return: Next network buffer in the linked list
 */
static inline qdf_nbuf_t qdf_nbuf_next_ext(qdf_nbuf_t buf)
{
	return __qdf_nbuf_next_ext(buf);
}

/**
 * qdf_nbuf_append_ext_list() - link list of packet extensions to the head
 *				segment
 * @head_buf: Network buf holding head segment (single)
 * @ext_list: Network buf list holding linked extensions to the head
 * @ext_len: Total length of all buffers in the extension list
 *
 * This function is used to link up a list of packet extensions (seg1, 2,
 * ...) to the nbuf holding the head segment (seg0)
 *
 * Return: none
 */
static inline void
qdf_nbuf_append_ext_list(qdf_nbuf_t head_buf, qdf_nbuf_t ext_list,
			qdf_size_t ext_len)
{
	__qdf_nbuf_append_ext_list(head_buf, ext_list, ext_len);
}

/**
 * qdf_nbuf_get_ext_list() - Get the link to extended nbuf list.
 * @head_buf: Network buf holding head segment (single)
 *
 * This ext_list is populated when we have Jumbo packet, for example in case of
 * monitor mode amsdu packet reception, and are stiched using frags_list.
 *
 * Return: Network buf list holding linked extensions from head buf.
 */
static inline qdf_nbuf_t qdf_nbuf_get_ext_list(qdf_nbuf_t head_buf)
{
	return (qdf_nbuf_t)__qdf_nbuf_get_ext_list(head_buf);
}

/**
 * qdf_nbuf_get_shinfo() - gets the shared info of head buf
 * @head_buf: Network buffer
 *
 * Return: shared info of head buf
 */
static inline qdf_nbuf_shared_info_t qdf_nbuf_get_shinfo(qdf_nbuf_t head_buf)
{
	return (qdf_nbuf_shared_info_t)__qdf_nbuf_get_shinfo(head_buf);
}

/**
 * qdf_nbuf_get_tx_cksum() - gets the tx checksum offload demand
 * @buf: Network buffer
 *
 * Return: qdf_nbuf_tx_cksum_t checksum offload demand for the frame
 */
static inline qdf_nbuf_tx_cksum_t qdf_nbuf_get_tx_cksum(qdf_nbuf_t buf)
{
	return __qdf_nbuf_get_tx_cksum(buf);
}

/**
 * qdf_nbuf_set_rx_cksum() - drivers that support hw checksumming use this to
 *			indicate checksum info to the stack.
 * @buf: Network buffer
 * @cksum: Checksum
 *
 * Return: none
 */
static inline void
qdf_nbuf_set_rx_cksum(qdf_nbuf_t buf, qdf_nbuf_rx_cksum_t *cksum)
{
	__qdf_nbuf_set_rx_cksum(buf, cksum);
}

/**
 * qdf_nbuf_get_tid() - this function extracts the TID value from nbuf
 * @buf: Network buffer
 *
 * Return: TID value
 */
static inline uint8_t qdf_nbuf_get_tid(qdf_nbuf_t buf)
{
	return __qdf_nbuf_get_tid(buf);
}

/**
 * qdf_nbuf_set_tid() - this function sets the TID value in nbuf
 * @buf: Network buffer
 * @tid: TID value
 *
 * Return: none
 */
static inline void qdf_nbuf_set_tid(qdf_nbuf_t buf, uint8_t tid)
{
	__qdf_nbuf_set_tid(buf, tid);
}

/**
 * qdf_nbuf_get_exemption_type() - this function extracts the exemption type
 *				from nbuf
 * @buf: Network buffer
 *
 * Return: Exemption type
 */
static inline uint8_t qdf_nbuf_get_exemption_type(qdf_nbuf_t buf)
{
	return __qdf_nbuf_get_exemption_type(buf);
}

/**
 * qdf_nbuf_set_protocol() - this function peeks data into the buffer at given
 *			offset
 * @buf: Network buffer
 * @proto: Protocol
 *
 * Return: none
 */
static inline void qdf_nbuf_set_protocol(qdf_nbuf_t buf, uint16_t proto)
{
	__qdf_nbuf_set_protocol(buf, proto);
}

/**
 * qdf_nbuf_trace_get_proto_type() - this function return packet proto type
 * @buf: Network buffer
 *
 * Return: Packet protocol type
 */
static inline uint8_t qdf_nbuf_trace_get_proto_type(qdf_nbuf_t buf)
{
	return __qdf_nbuf_trace_get_proto_type(buf);
}

/**
 * qdf_nbuf_reg_trace_cb() - this function registers protocol trace callback
 * @cb_func_ptr: Callback pointer
 *
 * Return: none
 */
static inline void qdf_nbuf_reg_trace_cb(qdf_nbuf_trace_update_t cb_func_ptr)
{
	__qdf_nbuf_reg_trace_cb(cb_func_ptr);
}


/**
 * qdf_nbuf_set_tx_parallel_dnload_frm() - set tx parallel download
 * @buf: Network buffer
 * @candi: Candidate of parallel download frame
 *
 * This function stores a flag specifying this TX frame is suitable for
 * downloading though a 2nd TX data pipe that is used for short frames for
 * protocols that can accept out-of-order delivery.
 *
 * Return: none
 */
static inline void
qdf_nbuf_set_tx_parallel_dnload_frm(qdf_nbuf_t buf, uint8_t candi)
{
	__qdf_nbuf_set_tx_htt2_frm(buf, candi);
}

/**
 * qdf_nbuf_get_tx_parallel_dnload_frm() - get tx parallel download
 * @buf: Network buffer
 *
 * This function return whether this TX frame is allow to download though a 2nd
 * TX data pipe or not.
 *
 * Return: none
 */
static inline uint8_t qdf_nbuf_get_tx_parallel_dnload_frm(qdf_nbuf_t buf)
{
	return __qdf_nbuf_get_tx_htt2_frm(buf);
}

/**
 * qdf_nbuf_get_dhcp_subtype() - get the subtype
 *              of DHCP packet.
 * @buf: Pointer to DHCP packet buffer
 *
 * This func. returns the subtype of DHCP packet.
 *
 * Return: subtype of the DHCP packet.
 */
static inline enum qdf_proto_subtype
qdf_nbuf_get_dhcp_subtype(qdf_nbuf_t buf)
{
	return __qdf_nbuf_data_get_dhcp_subtype(qdf_nbuf_data(buf));
}

/**
 * qdf_nbuf_data_get_dhcp_subtype() - get the subtype
 *              of DHCP packet.
 * @data: Pointer to DHCP packet data buffer
 *
 * This func. returns the subtype of DHCP packet.
 *
 * Return: subtype of the DHCP packet.
 */
static inline enum qdf_proto_subtype
qdf_nbuf_data_get_dhcp_subtype(uint8_t *data)
{
	return __qdf_nbuf_data_get_dhcp_subtype(data);
}

/**
 * qdf_nbuf_get_eapol_subtype() - get the subtype
 *            of EAPOL packet.
 * @buf: Pointer to EAPOL packet buffer
 *
 * This func. returns the subtype of EAPOL packet.
 *
 * Return: subtype of the EAPOL packet.
 */
static inline enum qdf_proto_subtype
qdf_nbuf_get_eapol_subtype(qdf_nbuf_t buf)
{
	return __qdf_nbuf_data_get_eapol_subtype(qdf_nbuf_data(buf));
}

/**
 * qdf_nbuf_data_get_eapol_subtype() - get the subtype
 *            of EAPOL packet.
 * @data: Pointer to EAPOL packet data buffer
 *
 * This func. returns the subtype of EAPOL packet.
 *
 * Return: subtype of the EAPOL packet.
 */
static inline enum qdf_proto_subtype
qdf_nbuf_data_get_eapol_subtype(uint8_t *data)
{
	return __qdf_nbuf_data_get_eapol_subtype(data);
}

/**
 * qdf_nbuf_get_arp_subtype() - get the subtype
 *            of ARP packet.
 * @buf: Pointer to ARP packet buffer
 *
 * This func. returns the subtype of ARP packet.
 *
 * Return: subtype of the ARP packet.
 */
static inline enum qdf_proto_subtype
qdf_nbuf_get_arp_subtype(qdf_nbuf_t buf)
{
	return __qdf_nbuf_data_get_arp_subtype(qdf_nbuf_data(buf));
}

/**
 * qdf_nbuf_data_get_arp_subtype() - get the subtype
 *            of ARP packet.
 * @data: Pointer to ARP packet data buffer
 *
 * This func. returns the subtype of ARP packet.
 *
 * Return: subtype of the ARP packet.
 */
static inline enum qdf_proto_subtype
qdf_nbuf_data_get_arp_subtype(uint8_t *data)
{
	return __qdf_nbuf_data_get_arp_subtype(data);
}

/**
 * qdf_nbuf_get_icmp_subtype() - get the subtype
 *            of IPV4 ICMP packet.
 * @buf: Pointer to IPV4 ICMP packet buffer
 *
 * This func. returns the subtype of ICMP packet.
 *
 * Return: subtype of the ICMP packet.
 */
static inline enum qdf_proto_subtype
qdf_nbuf_get_icmp_subtype(qdf_nbuf_t buf)
{
	return __qdf_nbuf_data_get_icmp_subtype(qdf_nbuf_data(buf));
}

/**
 * qdf_nbuf_data_get_icmp_subtype() - get the subtype
 *            of IPV4 ICMP packet.
 * @data: Pointer to IPV4 ICMP packet data buffer
 *
 * This func. returns the subtype of ICMP packet.
 *
 * Return: subtype of the ICMP packet.
 */
static inline enum qdf_proto_subtype
qdf_nbuf_data_get_icmp_subtype(uint8_t *data)
{
	return __qdf_nbuf_data_get_icmp_subtype(data);
}

/**
 * qdf_nbuf_get_icmpv6_subtype() - get the subtype
 *            of IPV6 ICMPV6 packet.
 * @buf: Pointer to IPV6 ICMPV6 packet buffer
 *
 * This func. returns the subtype of ICMPV6 packet.
 *
 * Return: subtype of the ICMPV6 packet.
 */
static inline enum qdf_proto_subtype
qdf_nbuf_get_icmpv6_subtype(qdf_nbuf_t buf)
{
	return __qdf_nbuf_data_get_icmpv6_subtype(qdf_nbuf_data(buf));
}

/**
 * qdf_nbuf_data_get_icmpv6_subtype() - get the subtype
 *            of IPV6 ICMPV6 packet.
 * @data: Pointer to IPV6 ICMPV6 packet data buffer
 *
 * This func. returns the subtype of ICMPV6 packet.
 *
 * Return: subtype of the ICMPV6 packet.
 */
static inline enum qdf_proto_subtype
qdf_nbuf_data_get_icmpv6_subtype(uint8_t *data)
{
	return __qdf_nbuf_data_get_icmpv6_subtype(data);
}

/**
 * qdf_nbuf_is_ipv4_last_fragment() - Check if IPV4 packet is last fragment
 * @nbuf: Network buffer
 *
 * This function check if IPV4 packet is last fragment or not.
 * Caller has to call this function for ipv4 packets only.
 *
 * Return: True if ipv4 packet is last fragment otherwise false
 */
static inline bool
qdf_nbuf_is_ipv4_last_fragment(qdf_nbuf_t nbuf)
{
	return __qdf_nbuf_is_ipv4_last_fragment(nbuf);
}

/**
 * qdf_nbuf_data_set_ipv4_tos() - set the TOS field of IPV4 packet.
 *
 * @data: Pointer to IPV4 packet data buffer
 * @tos: TOS value to be set in IPV4 packet
 *
 * This func. set the TOS field of IPV4 packet.
 *
 * Return: None
 */
static inline void
qdf_nbuf_data_set_ipv4_tos(uint8_t *data, uint8_t tos)
{
	__qdf_nbuf_data_set_ipv4_tos(data, tos);
}

/**
 * qdf_nbuf_data_get_ipv4_tos() - get the TOS field of IPV4 packet.
 *
 * @data: Pointer to IPV4 packet data buffer
 *
 * This func. returns the TOS field of IPV4 packet.
 *
 * Return: TOS of IPV4 packet.
 */
static inline uint8_t
qdf_nbuf_data_get_ipv4_tos(uint8_t *data)
{
	return __qdf_nbuf_data_get_ipv4_tos(data);
}

/**
 * qdf_nbuf_data_get_ipv4_proto() - get the proto type
 *            of IPV4 packet.
 * @data: Pointer to IPV4 packet data buffer
 *
 * This func. returns the proto type of IPV4 packet.
 *
 * Return: proto type of IPV4 packet.
 */
static inline uint8_t
qdf_nbuf_data_get_ipv4_proto(uint8_t *data)
{
	return __qdf_nbuf_data_get_ipv4_proto(data);
}

/**
 * qdf_nbuf_data_set_ipv6_tc() - set the TC field
 *                               of IPV6 packet.
 * @data: Pointer to IPV6 packet data buffer
 * @tc: Value to IPV6 packet TC field
 *
 * This func. set the TC field of IPV6 packet.
 *
 * Return: None
 */
static inline void
qdf_nbuf_data_set_ipv6_tc(uint8_t *data, uint8_t tc)
{
	__qdf_nbuf_data_set_ipv6_tc(data, tc);
}

/**
 * qdf_nbuf_data_get_ipv6_tc() - get the TC field
 *                               of IPV6 packet.
 * @data: Pointer to IPV6 packet data buffer
 *
 * This func. returns the TC field of IPV6 packet.
 *
 * Return: Traffic classification field of IPV6 packet.
 */
static inline uint8_t
qdf_nbuf_data_get_ipv6_tc(uint8_t *data)
{
	return __qdf_nbuf_data_get_ipv6_tc(data);
}

/**
 * qdf_nbuf_data_get_ipv6_proto() - get the proto type
 *            of IPV6 packet.
 * @data: Pointer to IPV6 packet data buffer
 *
 * This func. returns the proto type of IPV6 packet.
 *
 * Return: proto type of IPV6 packet.
 */
static inline uint8_t
qdf_nbuf_data_get_ipv6_proto(uint8_t *data)
{
	return __qdf_nbuf_data_get_ipv6_proto(data);
}

/**
 * qdf_nbuf_is_ipv4_pkt() - check if packet is a ipv4 packet or not
 * @buf:  buffer
 *
 * This api is for Tx packets.
 *
 * Return: true if packet is ipv4 packet
 */
static inline
bool qdf_nbuf_is_ipv4_pkt(qdf_nbuf_t buf)
{
	return __qdf_nbuf_data_is_ipv4_pkt(qdf_nbuf_data(buf));
}

/**
 * qdf_nbuf_data_is_ipv4_pkt() - check if packet is a ipv4 packet or not
 * @data:  data
 *
 * This api is for Tx packets.
 *
 * Return: true if packet is ipv4 packet
 */
static inline
bool qdf_nbuf_data_is_ipv4_pkt(uint8_t *data)
{
	return __qdf_nbuf_data_is_ipv4_pkt(data);
}

/**
 * qdf_nbuf_is_ipv4_dhcp_pkt() - check if packet is a dhcp packet or not
 * @buf:  buffer
 *
 * This api is for ipv4 packet.
 *
 * Return: true if packet is DHCP packet
 */
static inline
bool qdf_nbuf_is_ipv4_dhcp_pkt(qdf_nbuf_t buf)
{
	return __qdf_nbuf_data_is_ipv4_dhcp_pkt(qdf_nbuf_data(buf));
}

/**
 * qdf_nbuf_data_is_ipv4_dhcp_pkt() - check if it is DHCP packet.
 * @data: Pointer to DHCP packet data buffer
 *
 * This func. checks whether it is a DHCP packet or not.
 *
 * Return: true if it is a DHCP packet
 *         false if not
 */
static inline
bool qdf_nbuf_data_is_ipv4_dhcp_pkt(uint8_t *data)
{
	return __qdf_nbuf_data_is_ipv4_dhcp_pkt(data);
}

/**
 * qdf_nbuf_is_ipv6_mdns_pkt() - check if it is MDNS packet.
 * @buf: Pointer to packet data buffer
 *
 * This func. checks whether it is a MDNS packet or not.
 *
 * Return: true if it is a MDNS packet, false if not
 */
static inline
bool qdf_nbuf_is_ipv6_mdns_pkt(qdf_nbuf_t buf)
{
	return __qdf_nbuf_data_is_ipv6_mdns_pkt(qdf_nbuf_data(buf));
}

/**
 * qdf_nbuf_is_ipv6_dhcp_pkt() - check if it is DHCP packet.
 * @buf: Pointer to DHCP packet data buffer
 *
 * This func. checks whether it is a DHCP packet or not.
 *
 * Return: true if it is a DHCP packet
 *         false if not
 */
static inline
bool qdf_nbuf_is_ipv6_dhcp_pkt(qdf_nbuf_t buf)
{
	return __qdf_nbuf_data_is_ipv6_dhcp_pkt(qdf_nbuf_data(buf));
}

/**
 * qdf_nbuf_is_ipv4_eapol_pkt() - check if packet is a eapol packet or not
 * @buf:  buffer
 *
 * This api is for ipv4 packet.
 *
 * Return: true if packet is EAPOL packet
 */
static inline
bool qdf_nbuf_is_ipv4_eapol_pkt(qdf_nbuf_t buf)
{
	return __qdf_nbuf_data_is_ipv4_eapol_pkt(qdf_nbuf_data(buf));
}

/**
 * qdf_nbuf_data_is_ipv4_eapol_pkt() - check if it is EAPOL packet.
 * @data: Pointer to EAPOL packet data buffer
 *
 * This func. checks whether it is a EAPOL packet or not.
 *
 * Return: true if it is a EAPOL packet
 *         false if not
 */
static inline
bool qdf_nbuf_data_is_ipv4_eapol_pkt(uint8_t *data)
{
	return __qdf_nbuf_data_is_ipv4_eapol_pkt(data);
}

/**
 * qdf_nbuf_is_ipv4_wapi_pkt() - check if packet is a wapi packet or not
 * @buf:  buffer
 *
 * This api is for ipv4 packet.
 *
 * Return: true if packet is WAPI packet
 */
static inline
bool qdf_nbuf_is_ipv4_wapi_pkt(qdf_nbuf_t buf)
{
	return __qdf_nbuf_is_ipv4_wapi_pkt(buf);
}

/**
 * qdf_nbuf_is_ipv4_igmp_pkt() - check if packet is a igmp packet or not
 * @buf:  buffer
 *
 * This api is for ipv4 packet.
 *
 * Return: true if packet is igmp packet
 */
static inline
bool qdf_nbuf_is_ipv4_igmp_pkt(qdf_nbuf_t buf)
{
	return __qdf_nbuf_data_is_ipv4_igmp_pkt(qdf_nbuf_data(buf));
}

/**
 * qdf_nbuf_is_ipv6_igmp_pkt() - check if packet is a igmp packet or not
 * @buf:  buffer
 *
 * This api is for ipv6 packet.
 *
 * Return: true if packet is igmp packet
 */
static inline
bool qdf_nbuf_is_ipv6_igmp_pkt(qdf_nbuf_t buf)
{
	return __qdf_nbuf_data_is_ipv6_igmp_pkt(qdf_nbuf_data(buf));
}

/**
 * qdf_nbuf_is_ipv4_igmp_leave_pkt() - check if it is a igmp leave packet or not
 * @buf:  buffer
 *
 * This api is for ipv4 packet.
 *
 * Return: true if packet is igmp packet
 */
static inline
bool qdf_nbuf_is_ipv4_igmp_leave_pkt(qdf_nbuf_t buf)
{
	return __qdf_nbuf_is_ipv4_igmp_leave_pkt(buf);
}

/**
 * qdf_nbuf_is_ipv6_igmp_leave_pkt() - check if it is a igmp leave packet or not
 * @buf:  buffer
 *
 * This api is for ipv6 packet.
 *
 * Return: true if packet is igmp packet
 */
static inline
bool qdf_nbuf_is_ipv6_igmp_leave_pkt(qdf_nbuf_t buf)
{
	return __qdf_nbuf_is_ipv6_igmp_leave_pkt(buf);
}

/**
 * qdf_nbuf_is_ipv4_tdls_pkt() - check if packet is a tdls packet or not
 * @buf:  buffer
 *
 * This api is for ipv4 packet.
 *
 * Return: true if packet is TDLS packet
 */
static inline
bool qdf_nbuf_is_ipv4_tdls_pkt(qdf_nbuf_t buf)
{
	return __qdf_nbuf_is_ipv4_tdls_pkt(buf);
}

/**
 * qdf_nbuf_is_ipv4_arp_pkt() - check if packet is a arp packet or not
 * @buf:  buffer
 *
 * This api is for ipv4 packet.
 *
 * Return: true if packet is ARP packet
 */
static inline
bool qdf_nbuf_is_ipv4_arp_pkt(qdf_nbuf_t buf)
{
	return __qdf_nbuf_data_is_ipv4_arp_pkt(qdf_nbuf_data(buf));
}

/**
 * qdf_nbuf_data_is_ipv4_arp_pkt() - check if it is ARP packet.
 * @data: Pointer to ARP packet data buffer
 *
 * This func. checks whether it is a ARP packet or not.
 *
 * Return: TRUE if it is a ARP packet
 *         FALSE if not
 */
static inline
bool qdf_nbuf_data_is_ipv4_arp_pkt(uint8_t *data)
{
	return __qdf_nbuf_data_is_ipv4_arp_pkt(data);
}

/**
 * qdf_nbuf_data_is_arp_req() - check if ARP packet is request.
 * @buf:  buffer
 *
 * This func. checks whether it is a ARP request or not.
 *
 * Return: true if it is a ARP request or FALSE if not
 */
static inline
bool qdf_nbuf_data_is_arp_req(qdf_nbuf_t buf)
{
	return __qdf_nbuf_data_is_arp_req(qdf_nbuf_data(buf));
}

/**
 * qdf_nbuf_data_is_arp_rsp() - check if ARP packet is response.
 * @buf:  buffer
 *
 * This func. checks whether it is a ARP response or not.
 *
 * Return: true if it is a ARP response or FALSE if not
 */
static inline
bool qdf_nbuf_data_is_arp_rsp(qdf_nbuf_t buf)
{
	return __qdf_nbuf_data_is_arp_rsp(qdf_nbuf_data(buf));
}

/**
 * qdf_nbuf_get_arp_src_ip() - get ARP packet source IP gateway.
 * @buf:  buffer
 *
 * Return: ARP packet source IP value.
 */
static inline
uint32_t qdf_nbuf_get_arp_src_ip(qdf_nbuf_t buf)
{
	return __qdf_nbuf_get_arp_src_ip(qdf_nbuf_data(buf));
}

/**
 * qdf_nbuf_get_arp_tgt_ip() - get ARP packet target IP gateway.
 * @buf:  buffer
 *
 * Return: ARP packet target IP value.
 */
static inline
uint32_t qdf_nbuf_get_arp_tgt_ip(qdf_nbuf_t buf)
{
	return __qdf_nbuf_get_arp_tgt_ip(qdf_nbuf_data(buf));
}

/**
 * qdf_nbuf_get_dns_domain_name() - get dns domain name of required length
 * @buf: buffer
 * @len: length to copy
 *
 * Return: dns domain name
 */
static inline
uint8_t *qdf_nbuf_get_dns_domain_name(qdf_nbuf_t buf, uint32_t len)
{
	return __qdf_nbuf_get_dns_domain_name(qdf_nbuf_data(buf), len);
}

/**
 * qdf_nbuf_data_is_dns_query() - check if skb data is a dns query
 * @buf: buffer
 *
 * Return: true if packet is dns query packet.
 *	   false otherwise.
 */
static inline
bool qdf_nbuf_data_is_dns_query(qdf_nbuf_t buf)
{
	return __qdf_nbuf_data_is_dns_query(qdf_nbuf_data(buf));
}

/**
 * qdf_nbuf_data_is_dns_response() - check if skb data is a dns response
 * @buf:  buffer
 *
 * Return: true if packet is dns response packet.
 *	   false otherwise.
 */
static inline
bool qdf_nbuf_data_is_dns_response(qdf_nbuf_t buf)
{
	return __qdf_nbuf_data_is_dns_response(qdf_nbuf_data(buf));
}

/**
 * qdf_nbuf_data_is_tcp_fin() - check if skb data is a tcp fin
 * @buf:  buffer
 *
 * Return: true if packet is tcp fin packet.
 *	   false otherwise.
 */
static inline
bool qdf_nbuf_data_is_tcp_fin(qdf_nbuf_t buf)
{
	return __qdf_nbuf_data_is_tcp_fin(qdf_nbuf_data(buf));
}

/**
 * qdf_nbuf_data_is_tcp_fin_ack() - check if skb data is a tcp fin ack
 * @buf:  buffer
 *
 * Return: true if packet is tcp fin ack packet.
 *	   false otherwise.
 */
static inline
bool qdf_nbuf_data_is_tcp_fin_ack(qdf_nbuf_t buf)
{
	return __qdf_nbuf_data_is_tcp_fin_ack(qdf_nbuf_data(buf));
}

/**
 * qdf_nbuf_data_is_tcp_syn() - check if skb data is a tcp syn
 * @buf:  buffer
 *
 * Return: true if packet is tcp syn packet.
 *	   false otherwise.
 */
static inline
bool qdf_nbuf_data_is_tcp_syn(qdf_nbuf_t buf)
{
	return __qdf_nbuf_data_is_tcp_syn(qdf_nbuf_data(buf));
}

/**
 * qdf_nbuf_data_is_tcp_syn_ack() - check if skb data is a tcp syn ack
 * @buf:  buffer
 *
 * Return: true if packet is tcp syn ack packet.
 *	   false otherwise.
 */
static inline
bool qdf_nbuf_data_is_tcp_syn_ack(qdf_nbuf_t buf)
{
	return __qdf_nbuf_data_is_tcp_syn_ack(qdf_nbuf_data(buf));
}

/**
 * qdf_nbuf_data_is_tcp_rst() - check if skb data is a tcp rst
 * @buf:  buffer
 *
 * Return: true if packet is tcp rst packet.
 *	   false otherwise.
 */
static inline
bool qdf_nbuf_data_is_tcp_rst(qdf_nbuf_t buf)
{
	return __qdf_nbuf_data_is_tcp_rst(qdf_nbuf_data(buf));
}

/**
 * qdf_nbuf_data_is_tcp_ack() - check if skb data is a tcp ack
 * @buf:  buffer
 *
 * Return: true if packet is tcp ack packet.
 *	   false otherwise.
 */
static inline
bool qdf_nbuf_data_is_tcp_ack(qdf_nbuf_t buf)
{
	return __qdf_nbuf_data_is_tcp_ack(qdf_nbuf_data(buf));
}

/**
 * qdf_nbuf_data_get_tcp_src_port() - get tcp src port
 * @buf:  buffer
 *
 * Return: tcp source port value.
 */
static inline
uint16_t qdf_nbuf_data_get_tcp_src_port(qdf_nbuf_t buf)
{
	return __qdf_nbuf_data_get_tcp_src_port(qdf_nbuf_data(buf));
}

/**
 * qdf_nbuf_data_get_tcp_dst_port() - get tcp dst port
 * @buf:  buffer
 *
 * Return: tcp destination port value.
 */
static inline
uint16_t qdf_nbuf_data_get_tcp_dst_port(qdf_nbuf_t buf)
{
	return __qdf_nbuf_data_get_tcp_dst_port(qdf_nbuf_data(buf));
}

/**
 * qdf_nbuf_data_is_icmpv4_req() - check if ICMPv4 packet is request.
 * @buf:  buffer
 *
 * This func. checks whether it is a ICMPv4 request or not.
 *
 * Return: true if it is a ICMPv4 request or fALSE if not
 */
static inline
bool qdf_nbuf_data_is_icmpv4_req(qdf_nbuf_t buf)
{
	return __qdf_nbuf_data_is_icmpv4_req(qdf_nbuf_data(buf));
}

/**
 * qdf_nbuf_data_is_icmpv4_rsp() - check if ICMPv4 packet is res
 * @buf:  buffer
 *
 * Return: true if packet is icmpv4 response
 *	   false otherwise.
 */
static inline
bool qdf_nbuf_data_is_icmpv4_rsp(qdf_nbuf_t buf)
{
	return __qdf_nbuf_data_is_icmpv4_rsp(qdf_nbuf_data(buf));
}

static inline
bool qdf_nbuf_is_icmpv4_redirect(qdf_nbuf_t buf)
{
	return __qdf_nbuf_data_is_icmpv4_redirect(qdf_nbuf_data(buf));
}

/**
 * qdf_nbuf_get_icmpv4_src_ip() - get icmpv4 src IP
 * @buf:  buffer
 *
 * Return: icmpv4 packet source IP value.
 */
static inline
uint32_t qdf_nbuf_get_icmpv4_src_ip(qdf_nbuf_t buf)
{
	return __qdf_nbuf_get_icmpv4_src_ip(qdf_nbuf_data(buf));
}

/**
 * qdf_nbuf_get_icmpv4_tgt_ip() - get icmpv4 target IP
 * @buf:  buffer
 *
 * Return: icmpv4 packet target IP value.
 */
static inline
uint32_t qdf_nbuf_get_icmpv4_tgt_ip(qdf_nbuf_t buf)
{
	return __qdf_nbuf_get_icmpv4_tgt_ip(qdf_nbuf_data(buf));
}

/**
 * qdf_nbuf_is_ipv6_pkt() - check if it is IPV6 packet.
 * @buf: Pointer to IPV6 packet buffer
 *
 * This func. checks whether it is a IPV6 packet or not.
 *
 * Return: TRUE if it is a IPV6 packet
 *         FALSE if not
 */
static inline
bool qdf_nbuf_is_ipv6_pkt(qdf_nbuf_t buf)
{
	return __qdf_nbuf_data_is_ipv6_pkt(qdf_nbuf_data(buf));
}

static inline
bool qdf_nbuf_is_icmpv6_redirect(qdf_nbuf_t buf)
{
	return __qdf_nbuf_data_is_icmpv6_redirect(qdf_nbuf_data(buf));
}
/**
 * qdf_nbuf_data_is_ipv6_pkt() - check if it is IPV6 packet.
 * @data: Pointer to IPV6 packet data buffer
 *
 * This func. checks whether it is a IPV6 packet or not.
 *
 * Return: TRUE if it is a IPV6 packet
 *         FALSE if not
 */
static inline
bool qdf_nbuf_data_is_ipv6_pkt(uint8_t *data)
{
	return __qdf_nbuf_data_is_ipv6_pkt(data);
}

/**
 * qdf_nbuf_data_is_ipv4_mcast_pkt() - check if it is IPV4 multicast packet.
 * @data: Pointer to IPV4 packet data buffer
 *
 * This func. checks whether it is a IPV4 multicast packet or not.
 *
 * Return: TRUE if it is a IPV4 multicast packet
 *         FALSE if not
 */
static inline
bool qdf_nbuf_data_is_ipv4_mcast_pkt(uint8_t *data)
{
	return __qdf_nbuf_data_is_ipv4_mcast_pkt(data);
}

/**
 * qdf_nbuf_data_is_ipv6_mcast_pkt() - check if it is IPV6 multicast packet.
 * @data: Pointer to IPV6 packet data buffer
 *
 * This func. checks whether it is a IPV6 multicast packet or not.
 *
 * Return: TRUE if it is a IPV6 multicast packet
 *         FALSE if not
 */
static inline
bool qdf_nbuf_data_is_ipv6_mcast_pkt(uint8_t *data)
{
	return __qdf_nbuf_data_is_ipv6_mcast_pkt(data);
}

/**
 * qdf_nbuf_is_icmp_pkt() - check if it is IPV4 ICMP packet.
 * @buf: Pointer to IPV4 ICMP packet buffer
 *
 * This func. checks whether it is a ICMP packet or not.
 *
 * Return: TRUE if it is a ICMP packet
 *         FALSE if not
 */
static inline
bool qdf_nbuf_is_icmp_pkt(qdf_nbuf_t buf)
{
	return __qdf_nbuf_data_is_icmp_pkt(qdf_nbuf_data(buf));
}

/**
 * qdf_nbuf_data_is_icmp_pkt() - check if it is IPV4 ICMP packet.
 * @data: Pointer to IPV4 ICMP packet data buffer
 *
 * This func. checks whether it is a ICMP packet or not.
 *
 * Return: TRUE if it is a ICMP packet
 *         FALSE if not
 */
static inline
bool qdf_nbuf_data_is_icmp_pkt(uint8_t *data)
{
	return __qdf_nbuf_data_is_icmp_pkt(data);
}

/**
 * qdf_nbuf_is_icmpv6_pkt() - check if it is IPV6 ICMPV6 packet.
 * @buf: Pointer to IPV6 ICMPV6 packet buffer
 *
 * This func. checks whether it is a ICMPV6 packet or not.
 *
 * Return: TRUE if it is a ICMPV6 packet
 *         FALSE if not
 */
static inline
bool qdf_nbuf_is_icmpv6_pkt(qdf_nbuf_t buf)
{
	return __qdf_nbuf_data_is_icmpv6_pkt(qdf_nbuf_data(buf));
}

/**
 * qdf_nbuf_data_is_icmpv6_pkt() - check if it is IPV6 ICMPV6 packet.
 * @data: Pointer to IPV6 ICMPV6 packet data buffer
 *
 * This func. checks whether it is a ICMPV6 packet or not.
 *
 * Return: TRUE if it is a ICMPV6 packet
 *         FALSE if not
 */
static inline
bool qdf_nbuf_data_is_icmpv6_pkt(uint8_t *data)
{
	return __qdf_nbuf_data_is_icmpv6_pkt(data);
}

/**
 * qdf_nbuf_is_ipv4_udp_pkt() - check if it is IPV4 UDP packet.
 * @buf: Pointer to IPV4 UDP packet buffer
 *
 * This func. checks whether it is a IPV4 UDP packet or not.
 *
 * Return: TRUE if it is a IPV4 UDP packet
 *         FALSE if not
 */
static inline
bool qdf_nbuf_is_ipv4_udp_pkt(qdf_nbuf_t buf)
{
	return __qdf_nbuf_data_is_ipv4_udp_pkt(qdf_nbuf_data(buf));
}

/**
 * qdf_nbuf_data_is_ipv4_udp_pkt() - check if it is IPV4 UDP packet.
 * @data: Pointer to IPV4 UDP packet data buffer
 *
 * This func. checks whether it is a IPV4 UDP packet or not.
 *
 * Return: TRUE if it is a IPV4 UDP packet
 *         FALSE if not
 */
static inline
bool qdf_nbuf_data_is_ipv4_udp_pkt(uint8_t *data)
{
	return __qdf_nbuf_data_is_ipv4_udp_pkt(data);
}

/**
 * qdf_nbuf_is_ipv4_tcp_pkt() - check if it is IPV4 TCP packet.
 * @buf: Pointer to IPV4 TCP packet buffer
 *
 * This func. checks whether it is a IPV4 TCP packet or not.
 *
 * Return: TRUE if it is a IPV4 TCP packet
 *         FALSE if not
 */
static inline
bool qdf_nbuf_is_ipv4_tcp_pkt(qdf_nbuf_t buf)
{
	return __qdf_nbuf_data_is_ipv4_tcp_pkt(qdf_nbuf_data(buf));
}

/**
 * qdf_nbuf_data_is_ipv4_tcp_pkt() - check if it is IPV4 TCP packet.
 * @data: Pointer to IPV4 TCP packet data buffer
 *
 * This func. checks whether it is a IPV4 TCP packet or not.
 *
 * Return: TRUE if it is a IPV4 TCP packet
 *         FALSE if not
 */
static inline
bool qdf_nbuf_data_is_ipv4_tcp_pkt(uint8_t *data)
{
	return __qdf_nbuf_data_is_ipv4_tcp_pkt(data);
}

/**
 * qdf_nbuf_is_ipv6_udp_pkt() - check if it is IPV6 UDP packet.
 * @buf: Pointer to IPV6 UDP packet buffer
 *
 * This func. checks whether it is a IPV6 UDP packet or not.
 *
 * Return: TRUE if it is a IPV6 UDP packet
 *         FALSE if not
 */
static inline
bool qdf_nbuf_is_ipv6_udp_pkt(qdf_nbuf_t buf)
{
	return __qdf_nbuf_data_is_ipv6_udp_pkt(qdf_nbuf_data(buf));
}

/**
 * qdf_nbuf_data_is_ipv6_udp_pkt() - check if it is IPV6 UDP packet.
 * @data: Pointer to IPV6 UDP packet data buffer
 *
 * This func. checks whether it is a IPV6 UDP packet or not.
 *
 * Return: TRUE if it is a IPV6 UDP packet
 *         FALSE if not
 */
static inline
bool qdf_nbuf_data_is_ipv6_udp_pkt(uint8_t *data)
{
	return __qdf_nbuf_data_is_ipv6_udp_pkt(data);
}

/**
 * qdf_nbuf_is_ipv6_tcp_pkt() - check if it is IPV6 TCP packet.
 * @buf: Pointer to IPV6 TCP packet buffer
 *
 * This func. checks whether it is a IPV6 TCP packet or not.
 *
 * Return: TRUE if it is a IPV6 TCP packet
 *         FALSE if not
 */
static inline
bool qdf_nbuf_is_ipv6_tcp_pkt(qdf_nbuf_t buf)
{
	return __qdf_nbuf_data_is_ipv6_tcp_pkt(qdf_nbuf_data(buf));
}

/**
 * qdf_nbuf_data_is_ipv6_tcp_pkt() - check if it is IPV6 TCP packet.
 * @data: Pointer to IPV6 TCP packet data buffer
 *
 * This func. checks whether it is a IPV6 TCP packet or not.
 *
 * Return: TRUE if it is a IPV6 TCP packet
 *         FALSE if not
 */
static inline
bool qdf_nbuf_data_is_ipv6_tcp_pkt(uint8_t *data)
{
	return __qdf_nbuf_data_is_ipv6_tcp_pkt(data);
}

/**
 * qdf_nbuf_is_bcast_pkt() - check if it is broadcast packet.
 * @buf: Network buffer
 *
 * This func. checks whether packet is broadcast or not.
 *
 * Return: TRUE if it is broadcast packet
 *         FALSE if not
 */
static inline
bool qdf_nbuf_is_bcast_pkt(qdf_nbuf_t buf)
{
	return __qdf_nbuf_is_bcast_pkt(buf);
}

/**
 * qdf_nbuf_pkt_type_is_mcast() - check if skb pkt type is mcast
 * @buf: Network buffer
 *
 * Return: TRUE if skb pkt type is mcast
 *         FALSE if not
 */
static inline
bool qdf_nbuf_pkt_type_is_mcast(qdf_nbuf_t buf)
{
	return __qdf_nbuf_pkt_type_is_mcast(buf);
}

/**
 * qdf_nbuf_pkt_type_is_bcast() - check if skb pkt type is bcast
 * @buf: Network buffer
 *
 * Return: TRUE if skb pkt type is mcast
 *         FALSE if not
 */
static inline
bool qdf_nbuf_pkt_type_is_bcast(qdf_nbuf_t buf)
{
	return __qdf_nbuf_pkt_type_is_bcast(buf);
}

/**
 * qdf_nbuf_is_mcast_replay() - check if it is multicast replay packet.
 * @buf: Network buffer
 *
 * This func. checks whether packet is multicast replay packet or not.
 *
 * Return: TRUE if it is multicast packet
 *         FALSE if not
 */
static inline
bool qdf_nbuf_is_mcast_replay(qdf_nbuf_t buf)
{
	return __qdf_nbuf_is_mcast_replay(buf);
}

#ifdef DP_TX_PACKET_INSPECT_FOR_ILP
/* Reuse bit24~31 in skb->priority for packet type */
#define QDF_NBUF_PRIORITY_PKT_TYPE_MASK 0xFF000000
#define QDF_NBUF_PRIORITY_PKT_TYPE_LSB 24
/* TCP ACK */
#define QDF_NBUF_PRIORITY_PKT_TCP_ACK 0x1

#define QDF_NBUF_GET_PRIORITY_PKT_TYPE(_pri) \
	(((_pri) & QDF_NBUF_PRIORITY_PKT_TYPE_MASK) >> \
	 QDF_NBUF_PRIORITY_PKT_TYPE_LSB)

#define QDF_NBUF_PRIORITY_PKT_TYPE(_pkt_type) \
	(((_pkt_type) << QDF_NBUF_PRIORITY_PKT_TYPE_LSB) & \
	 QDF_NBUF_PRIORITY_PKT_TYPE_MASK)

/**
 * qdf_nbuf_get_priority_pkt_type() - Get packet type from priority
 * @nbuf: pointer to network buffer
 *
 * Return: packet type
 */
static inline
uint8_t qdf_nbuf_get_priority_pkt_type(qdf_nbuf_t nbuf)
{
	return QDF_NBUF_GET_PRIORITY_PKT_TYPE(nbuf->priority);
}

/**
 * qdf_nbuf_set_priority_pkt_type() - Set packet type to priority
 * @nbuf: pointer to network buffer
 * @pkt_type: packet type to be set
 *
 * Return: none
 */
static inline
void qdf_nbuf_set_priority_pkt_type(qdf_nbuf_t nbuf, uint8_t pkt_type)
{
	nbuf->priority |= QDF_NBUF_PRIORITY_PKT_TYPE(pkt_type);
}

/**
 * qdf_nbuf_remove_priority_pkt_type() - Remove the packet type bits
 *					 from priority
 * @nbuf: pointer to network buffer
 *
 * Return: none
 */
static inline
void qdf_nbuf_remove_priority_pkt_type(qdf_nbuf_t nbuf)
{
	nbuf->priority &= ~QDF_NBUF_PRIORITY_PKT_TYPE_MASK;
}
#endif

/**
 * qdf_nbuf_is_ipv4_v6_pure_tcp_ack() - check if it is pure tcp ack
 *					without data payload
 * @buf: Network buffer
 *
 * Check whether the packet is pure TCP ack without data payload.
 *
 * Return : true if TCP ack, else return false
 */
static inline
bool qdf_nbuf_is_ipv4_v6_pure_tcp_ack(qdf_nbuf_t buf)
{
	return __qdf_nbuf_is_ipv4_v6_pure_tcp_ack(buf);
}

/**
 * qdf_nbuf_is_arp_local() - check if it is local or no local arp
 * @buf: Network buffer
 *
 * This func. checks whether packet is local or no local arp.
 *
 * Return: TRUE if it is broadcast packet
 *         FALSE if not
 */
static inline
bool qdf_nbuf_is_arp_local(qdf_nbuf_t buf)
{
	return __qdf_nbuf_is_arp_local(buf);
}

/**
 * qdf_nbuf_reset_num_frags() - decrement the number of fragments
 * @buf: Network buffer
 *
 * Return: Number of fragments
 */
static inline void qdf_nbuf_reset_num_frags(qdf_nbuf_t buf)
{
	__qdf_nbuf_reset_num_frags(buf);
}

/**
 * qdf_dmaaddr_to_32s - return high and low parts of dma_addr
 * @dmaaddr: DMA address
 * @lo: low 32-bits of @dmaaddr
 * @hi: high 32-bits of @dmaaddr
 *
 * Returns the high and low 32-bits of the DMA addr in the provided ptrs
 *
 * Return: N/A
 */
static inline void qdf_dmaaddr_to_32s(qdf_dma_addr_t dmaaddr,
				      uint32_t *lo, uint32_t *hi)
{
	return __qdf_dmaaddr_to_32s(dmaaddr, lo, hi);
}

/**
 * qdf_nbuf_get_tso_info() - function to divide a jumbo TSO
 *                           network buffer into segments
 * @osdev: qdf device handle
 * @nbuf:   network buffer to be segmented
 * @tso_info:  This is the output. The information about the
 *             TSO segments will be populated within this.
 *
 * This function fragments a TCP jumbo packet into smaller
 * segments to be transmitted by the driver. It chains the TSO
 * segments created into a list.
 *
 * Return: number of TSO segments
 */
static inline uint32_t qdf_nbuf_get_tso_info(qdf_device_t osdev,
		 qdf_nbuf_t nbuf, struct qdf_tso_info_t *tso_info)
{
	return __qdf_nbuf_get_tso_info(osdev, nbuf, tso_info);
}

/**
 * qdf_nbuf_unmap_tso_segment() - function to dma unmap TSO segment element
 *
 * @osdev: qdf device handle
 * @tso_seg: TSO segment element to be unmapped
 * @is_last_seg: whether this is last tso seg or not
 *
 * Return: none
 */
static inline void qdf_nbuf_unmap_tso_segment(qdf_device_t osdev,
			  struct qdf_tso_seg_elem_t *tso_seg,
			  bool is_last_seg)
{
	return __qdf_nbuf_unmap_tso_segment(osdev, tso_seg, is_last_seg);
}

/**
 * qdf_nbuf_get_tcp_payload_len() - function to return the tso payload len
 * @nbuf: network buffer
 *
 * Return: size of the tso packet
 */
static inline size_t qdf_nbuf_get_tcp_payload_len(qdf_nbuf_t nbuf)
{
	return __qdf_nbuf_get_tcp_payload_len(nbuf);
}

/**
 * qdf_nbuf_get_tso_num_seg() - function to calculate the number
 * of TCP segments within the TSO jumbo packet
 * @nbuf:   TSO jumbo network buffer to be segmented
 *
 * This function calculates the number of TCP segments that the
 * network buffer can be divided into.
 *
 * Return: number of TCP segments
 */
static inline uint32_t qdf_nbuf_get_tso_num_seg(qdf_nbuf_t nbuf)
{
	return __qdf_nbuf_get_tso_num_seg(nbuf);
}

/**
 * qdf_nbuf_get_gso_segs() - Return the number of gso segments in nbuf
 * @nbuf: Network buffer
 *
 * Return: number of gso segments in nbuf
 */
static inline uint16_t qdf_nbuf_get_gso_segs(qdf_nbuf_t nbuf)
{
	return __qdf_nbuf_get_gso_segs(nbuf);
}

/**
 * qdf_nbuf_set_gso_segs() - set the number of gso segments in nbuf
 * @nbuf: Network buffer
 * @val: val to be set
 *
 * Return: None
 */
static inline void qdf_nbuf_set_gso_segs(qdf_nbuf_t nbuf, uint16_t val)
{
	__qdf_nbuf_set_gso_segs(nbuf, val);
}

/**
 * qdf_nbuf_set_gso_type_udp_l4() - set the gso type to GSO UDP L4
 * @nbuf: Network buffer
 *
 * Return: None
 */
static inline void qdf_nbuf_set_gso_type_udp_l4(qdf_nbuf_t nbuf)
{
	__qdf_nbuf_set_gso_type_udp_l4(nbuf);
}

/**
 * qdf_nbuf_set_ip_summed_partial() - set the ip summed to CHECKSUM_PARTIAL
 * @nbuf: Network buffer
 *
 * Return: None
 */
static inline void qdf_nbuf_set_ip_summed_partial(qdf_nbuf_t nbuf)
{
	__qdf_nbuf_set_ip_summed_partial(nbuf);
}

/**
 * qdf_nbuf_get_gso_size() - Return the number of gso size in nbuf
 * @nbuf: Network buffer
 *
 * Return: number of gso segments in nbuf
 */
static inline unsigned int qdf_nbuf_get_gso_size(qdf_nbuf_t nbuf)
{
	return __qdf_nbuf_get_gso_size(nbuf);
}

/**
 * qdf_nbuf_set_gso_size() - Set the gso size in nbuf
 * @nbuf: Pointer to network buffer
 * @val: number of gso segments in nbuf
 *
 * Return: None
 */
static inline void  qdf_nbuf_set_gso_size(qdf_nbuf_t nbuf, unsigned int val)
{
	__qdf_nbuf_set_gso_size(nbuf, val);
}

/**
 * qdf_nbuf_inc_users() - function to increment the number of
 *                        users referencing this network buffer
 * @nbuf:   network buffer
 *
 * This function increments the number of users referencing this
 * network buffer
 *
 * Return: the network buffer
 */
static inline qdf_nbuf_t qdf_nbuf_inc_users(qdf_nbuf_t nbuf)
{
	return __qdf_nbuf_inc_users(nbuf);
}

/**
 * qdf_nbuf_data_attr_get() - Get data_attr field from cvg_nbuf_cb
 * @buf: Network buffer (skb on linux)
 *
 * This function returns the values of data_attr field
 * in struct cvg_nbuf_cb{}, to which skb->cb is typecast.
 * This value is actually the value programmed in CE descriptor.
 *
 * Return: Value of data_attr
 */
static inline uint32_t qdf_nbuf_data_attr_get(qdf_nbuf_t buf)
{
	return __qdf_nbuf_data_attr_get(buf);
}

/**
 * qdf_nbuf_data_attr_set() - Sets data_attr field in cvg_nbuf_cb
 * @buf: Network buffer (skb on linux)
 * @data_attr: Value to be stored cvg_nbuf_cb->data_attr
 *
 * This function stores the value to be programmed in CE
 * descriptor as part skb->cb which is typecast to struct cvg_nbuf_cb{}
 *
 * Return: void
 */
static inline
void qdf_nbuf_data_attr_set(qdf_nbuf_t buf, uint32_t data_attr)
{
	__qdf_nbuf_data_attr_set(buf, data_attr);
}

/**
 * qdf_nbuf_tx_info_get() - Parse skb and get Tx metadata
 * @nbuf:		Network buffer
 * @pkt_type:		Pkt type (from enum htt_pkt_type)
 * @pkt_subtype:	Bit 4 of this field in HTT descriptor
 *			needs to be set in case of CE classification support
 *			Is set by this macro.
 * @hw_classify:	This is a flag which is set to indicate
 *			CE classification is enabled.
 *			Do not set this bit for VLAN packets
 *			OR for mcast / bcast frames.
 *
 * This function parses the payload to figure out relevant
 * Tx meta-data e.g. whether to enable tx_classify bit
 * in CE.
 *
 * Return:     void
 */
#define qdf_nbuf_tx_info_get(nbuf, pkt_type, pkt_subtype, hw_classify)	\
		__qdf_nbuf_tx_info_get(nbuf, pkt_type,			\
				       pkt_subtype, hw_classify)

/**
 * qdf_nbuf_set_state() - Updates the packet state
 * @nbuf:            network buffer
 * @current_state :  layer at which the packet currently is
 *
 * This function updates the packet state to the layer at which the packet
 * currently is
 *
 * Return: none
 */
void qdf_nbuf_set_state(qdf_nbuf_t nbuf, uint8_t current_state);

/**
 * qdf_nbuf_tx_desc_count_display() - Displays the packet counter
 *
 * Return: none
 */
void qdf_nbuf_tx_desc_count_display(void);

/**
 * qdf_nbuf_tx_desc_count_clear() - Clears packet counter for both data, mgmt
 *
 * Return: none
 */
void qdf_nbuf_tx_desc_count_clear(void);

static inline qdf_nbuf_t
qdf_nbuf_realloc_headroom(qdf_nbuf_t buf, uint32_t headroom)
{
	return __qdf_nbuf_realloc_headroom(buf, headroom);
}

static inline qdf_nbuf_t
qdf_nbuf_realloc_tailroom(qdf_nbuf_t buf, uint32_t tailroom)
{
	return __qdf_nbuf_realloc_tailroom(buf, tailroom);
}

static inline qdf_nbuf_t
qdf_nbuf_expand(qdf_nbuf_t buf, uint32_t headroom, uint32_t tailroom)
{
	return __qdf_nbuf_expand(buf, headroom, tailroom);
}

static inline int
qdf_nbuf_linearize(qdf_nbuf_t buf)
{
	return __qdf_nbuf_linearize(buf);
}

static inline bool
qdf_nbuf_is_cloned(qdf_nbuf_t buf)
{
	return __qdf_nbuf_is_cloned(buf);
}

static inline void
qdf_nbuf_frag_info(qdf_nbuf_t buf, qdf_sglist_t *sg)
{
	__qdf_nbuf_frag_info(buf, sg);
}

static inline qdf_nbuf_tx_cksum_t
qdf_nbuf_tx_cksum_info(qdf_nbuf_t buf, uint8_t **hdr_off, uint8_t **where)
{
	return __qdf_nbuf_tx_cksum_info(buf, hdr_off, where);
}

static inline void qdf_nbuf_reset_ctxt(__qdf_nbuf_t nbuf)
{
	__qdf_nbuf_reset_ctxt(nbuf);
}

static inline void qdf_nbuf_init(qdf_nbuf_t buf)
{
	__qdf_nbuf_init(buf);
}

static inline void *qdf_nbuf_network_header(qdf_nbuf_t buf)
{
	return __qdf_nbuf_network_header(buf);
}

static inline void *qdf_nbuf_transport_header(qdf_nbuf_t buf)
{
	return __qdf_nbuf_transport_header(buf);
}

static inline qdf_size_t qdf_nbuf_tcp_tso_size(qdf_nbuf_t buf)
{
	return __qdf_nbuf_tcp_tso_size(buf);
}

static inline void *qdf_nbuf_get_cb(qdf_nbuf_t nbuf)
{
	return __qdf_nbuf_get_cb(nbuf);
}

static inline uint32_t qdf_nbuf_get_nr_frags(qdf_nbuf_t nbuf)
{
	return __qdf_nbuf_get_nr_frags(nbuf);
}

static inline uint32_t qdf_nbuf_get_nr_frags_in_fraglist(qdf_nbuf_t nbuf)
{
	return __qdf_nbuf_get_nr_frags_in_fraglist(nbuf);
}

static inline qdf_size_t qdf_nbuf_headlen(qdf_nbuf_t buf)
{
	return __qdf_nbuf_headlen(buf);
}

static inline QDF_STATUS qdf_nbuf_frag_map(qdf_device_t osdev,
	qdf_nbuf_t buf, int offset,
	qdf_dma_dir_t dir, int cur_frag)
{
	return __qdf_nbuf_frag_map(osdev, buf, offset, dir, cur_frag);
}

static inline bool qdf_nbuf_tso_tcp_v4(qdf_nbuf_t buf)
{
	return __qdf_nbuf_tso_tcp_v4(buf);
}

static inline bool qdf_nbuf_tso_tcp_v6(qdf_nbuf_t buf)
{
	return __qdf_nbuf_tso_tcp_v6(buf);
}

static inline uint32_t qdf_nbuf_tcp_seq(qdf_nbuf_t buf)
{
	return __qdf_nbuf_tcp_seq(buf);
}

static inline qdf_size_t qdf_nbuf_l2l3l4_hdr_len(qdf_nbuf_t buf)
{
	return __qdf_nbuf_l2l3l4_hdr_len(buf);
}

/**
 * qdf_nbuf_get_tcp_hdr_len() - return TCP header length of the skb
 * @nbuf: sk buff
 *
 * Return: size of TCP header length
 */
static inline size_t qdf_nbuf_get_tcp_hdr_len(qdf_nbuf_t nbuf)
{
	return __qdf_nbuf_get_tcp_hdr_len(nbuf);
}

static inline bool qdf_nbuf_is_nonlinear(qdf_nbuf_t buf)
{
	return __qdf_nbuf_is_nonlinear(buf);
}

static inline uint32_t
qdf_nbuf_get_frag_size(qdf_nbuf_t buf, uint32_t frag_num)
{
	return __qdf_nbuf_get_frag_size(buf, frag_num);
}

static inline uint32_t qdf_nbuf_get_priority(qdf_nbuf_t buf)
{
	return __qdf_nbuf_get_priority(buf);
}

static inline void qdf_nbuf_set_priority(qdf_nbuf_t buf, uint32_t p)
{
	__qdf_nbuf_set_priority(buf, p);
}

static inline void qdf_nbuf_record_rx_queue(qdf_nbuf_t buf, uint32_t queue_id)
{
	__qdf_nbuf_record_rx_queue(buf, queue_id);
}

static inline uint16_t
qdf_nbuf_get_queue_mapping(qdf_nbuf_t buf)
{
	return __qdf_nbuf_get_queue_mapping(buf);
}

static inline void
qdf_nbuf_set_queue_mapping(qdf_nbuf_t buf, uint16_t val)
{
	__qdf_nbuf_set_queue_mapping(buf, val);
}

static inline char *
qdf_nbuf_get_priv_ptr(qdf_nbuf_t buf)
{
	return __qdf_nbuf_get_priv_ptr(buf);
}

/**
 * qdf_nbuf_has_fraglist() - check if nbuf has attached frag list
 * @nbuf: Pointer to nbuf
 *
 * Return: bool
 */
static inline bool
qdf_nbuf_has_fraglist(qdf_nbuf_t nbuf)
{
	return __qdf_nbuf_has_fraglist(nbuf);
}

/**
 * qdf_nbuf_get_last_frag_list_nbuf() - Fetch pointer to last nbuf in frag list
 * @nbuf: Pointer to nbuf
 *
 * Return: Pointer to last nbuf in frag list if parent nbuf has extended frag
 *         list or else return NULL
 */
static inline qdf_nbuf_t
qdf_nbuf_get_last_frag_list_nbuf(qdf_nbuf_t nbuf)
{
	return __qdf_nbuf_get_last_frag_list_nbuf(nbuf);
}

/**
 * qdf_nbuf_update_radiotap() - update radiotap at head of nbuf.
 * @rx_status: rx_status containing required info to update radiotap
 * @nbuf: Pointer to nbuf
 * @headroom_sz: Available headroom size
 *
 * Return: radiotap length.
 */
unsigned int qdf_nbuf_update_radiotap(struct mon_rx_status *rx_status,
				      qdf_nbuf_t nbuf, uint32_t headroom_sz);

/**
 * qdf_nbuf_mark_wakeup_frame() - mark wakeup frame.
 * @buf: Pointer to nbuf
 *
 * Return: None
 */
static inline void
qdf_nbuf_mark_wakeup_frame(qdf_nbuf_t buf)
{
	 __qdf_nbuf_mark_wakeup_frame(buf);
}

/**
 * qdf_nbuf_reg_free_cb - Registers nbuf free callback
 * @cb_func_ptr: Callback pointer
 *
 * This function registers nbuf free callback
 *
 * Return: void
 */
static inline void
qdf_nbuf_reg_free_cb(qdf_nbuf_free_t cb_func_ptr)
{
	 __qdf_nbuf_reg_free_cb(cb_func_ptr);
}

/**
 * qdf_nbuf_count_get() - get global nbuf gauge
 *
 * Return: global nbuf gauge
 */
static inline int qdf_nbuf_count_get(void)
{
	return __qdf_nbuf_count_get();
}

/**
 * qdf_nbuf_count_inc() - increment nbuf global count
 *
 * @buf: sk buff
 *
 * Return: void
 */
static inline void qdf_nbuf_count_inc(qdf_nbuf_t buf)
{
	return __qdf_nbuf_count_inc(buf);
}

/**
 * qdf_nbuf_count_dec() - decrement nbuf global count
 *
 * @buf: sk buff
 *
 * Return: void
 */
static inline void qdf_nbuf_count_dec(qdf_nbuf_t buf)
{
	return __qdf_nbuf_count_dec(buf);
}

/**
 * qdf_nbuf_mod_init() - Initialization routine for qdf_nbuf
 *
 * Return void
 */
static inline void qdf_nbuf_mod_init(void)
{
	return __qdf_nbuf_mod_init();
}

/**
 * qdf_nbuf_mod_exit() - Unintialization routine for qdf_nbuf
 *
 * Return void
 */
static inline void qdf_nbuf_mod_exit(void)
{
	return __qdf_nbuf_mod_exit();
}

/**
 * qdf_nbuf_orphan() - orphan a nbuf
 * @buf: Pointer to network buffer
 *
 * If a buffer currently has an owner then we call the
 * owner's destructor function
 *
 * Return: void
 */
static inline void qdf_nbuf_orphan(qdf_nbuf_t buf)
{
	return __qdf_nbuf_orphan(buf);
}

/**
 * qdf_nbuf_get_frag_size_by_idx() - Get size of nbuf frag at index idx
 * @nbuf: qdf_nbuf_t
 * @idx: Frag index for which frag size is requested
 *
 * Return: Frag size
 */
static inline unsigned int qdf_nbuf_get_frag_size_by_idx(qdf_nbuf_t nbuf,
							 uint8_t idx)
{
	return __qdf_nbuf_get_frag_size_by_idx(nbuf, idx);
}

/**
 * qdf_nbuf_get_frag_addr() - Get nbuf frag address at index idx
 * @nbuf: qdf_nbuf_t
 * @idx: Frag index for which frag address is requested
 *
 * Return: Frag address
 */
static inline qdf_frag_t qdf_nbuf_get_frag_addr(qdf_nbuf_t nbuf, uint8_t idx)
{
	return __qdf_nbuf_get_frag_addr(nbuf, idx);
}

/**
 * qdf_nbuf_trim_add_frag_size() - Increase/Decrease frag_size by size
 * @nbuf: qdf_nbuf_t
 * @idx: Frag index
 * @size: Size by which frag_size needs to be increased/decreased
 *        +Ve means increase, -Ve means decrease
 * @truesize: truesize
 */
static inline void qdf_nbuf_trim_add_frag_size(qdf_nbuf_t nbuf, uint8_t idx,
					       int size, unsigned int truesize)
{
	__qdf_nbuf_trim_add_frag_size(nbuf, idx, size, truesize);
}

/**
 * qdf_nbuf_set_mark() - Set nbuf mark
 * @nbuf: qdf_nbuf_t
 * @mark: Value to set mark
 *
 * Return: none
 */
static inline void qdf_nbuf_set_mark(qdf_nbuf_t nbuf, uint32_t mark)
{
	__qdf_nbuf_set_mark(nbuf, mark);
}

/**
 * qdf_nbuf_get_mark() - Get nbuf mark
 * @nbuf: qdf_nbuf_t
 *
 * Return: mark value
 */
static inline uint32_t qdf_nbuf_get_mark(qdf_nbuf_t nbuf)
{
	return __qdf_nbuf_get_mark(nbuf);
}

/**
 * qdf_nbuf_get_data_len() - Return the size of the nbuf from
 * data pointer to end pointer
 * @nbuf: qdf_nbuf_t
 *
 * Return: size of network buffer from data pointer to end
 * pointer
 */
static inline qdf_size_t qdf_nbuf_get_data_len(qdf_nbuf_t nbuf)
{
	return __qdf_nbuf_get_data_len(nbuf);
}

/**
 * qdf_nbuf_set_data_len() - Return the data_len of the nbuf
 * @nbuf: qdf_nbuf_t
 * @len: data_len to be set
 *
 * Return: set data_len value
 */
static inline qdf_size_t qdf_nbuf_set_data_len(qdf_nbuf_t nbuf, uint32_t len)
{
	return __qdf_nbuf_set_data_len(nbuf, len);
}

/**
 * qdf_nbuf_get_only_data_len() - Return the data_len of the nbuf
 * @nbuf: qdf_nbuf_t
 *
 * Return: data_len value
 */
static inline qdf_size_t qdf_nbuf_get_only_data_len(qdf_nbuf_t nbuf)
{
	return __qdf_nbuf_get_only_data_len(nbuf);
}

/**
 * qdf_nbuf_set_hash() - set the hash of the buf
 * @buf: Network buf instance
 * @len: len to be set
 *
 * Return: none
 */
static inline void qdf_nbuf_set_hash(qdf_nbuf_t buf, uint32_t len)
{
	__qdf_nbuf_set_hash(buf, len);
}

/**
 * qdf_nbuf_set_sw_hash() - set the sw hash of the buf
 * @buf: Network buf instance
 * @len: len to be set
 *
 * Return: none
 */
static inline void qdf_nbuf_set_sw_hash(qdf_nbuf_t buf, uint32_t len)
{
	__qdf_nbuf_set_sw_hash(buf, len);
}

/**
 * qdf_nbuf_set_csum_start() - set the csum start of the buf
 * @buf: Network buf instance
 * @len: len to be set
 *
 * Return: none
 */
static inline void qdf_nbuf_set_csum_start(qdf_nbuf_t buf, uint16_t len)
{
	__qdf_nbuf_set_csum_start(buf, len);
}

/**
 * qdf_nbuf_set_csum_offset() - set the csum offset of the buf
 * @buf: Network buf instance
 * @len: len to be set
 *
 * Return: none
 */
static inline void qdf_nbuf_set_csum_offset(qdf_nbuf_t buf, uint16_t len)
{
	__qdf_nbuf_set_csum_offset(buf, len);
}

/**
 * qdf_nbuf_get_end_offset() - Return the size of the nbuf from
 * head pointer to end pointer
 * @nbuf: qdf_nbuf_t
 *
 * Return: size of network buffer from head pointer to end
 * pointer
 */
static inline qdf_size_t qdf_nbuf_get_end_offset(qdf_nbuf_t nbuf)
{
	return __qdf_nbuf_get_end_offset(nbuf);
}

/**
 * qdf_nbuf_get_truesize() - Return the true size of the nbuf
 * including the header and variable data area
 * @nbuf: qdf_nbuf_t
 *
 * Return: size of network buffer
 */
static inline qdf_size_t qdf_nbuf_get_truesize(qdf_nbuf_t nbuf)
{
	return __qdf_nbuf_get_truesize(nbuf);
}

/**
 * qdf_nbuf_get_allocsize() - Return the actual size of the skb->head
 * excluding the header and variable data area
 * @nbuf: qdf_nbuf_t
 *
 * Return: actual allocated size of network buffer
 */
static inline qdf_size_t qdf_nbuf_get_allocsize(qdf_nbuf_t nbuf)
{
	return __qdf_nbuf_get_allocsize(nbuf);
}

#ifdef NBUF_FRAG_MEMORY_DEBUG

#define qdf_nbuf_move_frag_page_offset(f, i, o) \
	qdf_nbuf_move_frag_page_offset_debug(f, i, o, __func__, __LINE__)

/**
 * qdf_nbuf_move_frag_page_offset_debug() - Move frag page_offset by size
 *          and adjust length by size.
 * @nbuf: qdf_nbuf_t
 * @idx: Frag index
 * @offset: Frag page offset should be moved by offset.
 *      +Ve - Move offset forward.
 *      -Ve - Move offset backward.
 * @func: Caller function name
 * @line: Caller function line no.
 *
 * Return: QDF_STATUS
 */
QDF_STATUS qdf_nbuf_move_frag_page_offset_debug(qdf_nbuf_t nbuf, uint8_t idx,
						int offset, const char *func,
						uint32_t line);

#define qdf_nbuf_remove_frag(n, i, t) \
	qdf_nbuf_remove_frag_debug(n, i, t, __func__, __LINE__)

/**
 * qdf_nbuf_remove_frag_debug - Remove frag from nbuf
 * @nbuf: nbuf where frag will be removed
 * @idx: frag index
 * @truesize: truesize of frag
 * @func: Caller function name
 * @line:  Caller function line no.
 *
 * Return: QDF_STATUS
 *
 */
QDF_STATUS
qdf_nbuf_remove_frag_debug(qdf_nbuf_t nbuf,
			   uint16_t idx,
			   uint16_t truesize,
			   const char *func,
			   uint32_t line);

#define qdf_nbuf_add_rx_frag(f, b, o, l, s, r) \
	qdf_nbuf_add_rx_frag_debug(f, b, o, l, s, r, __func__, __LINE__)

/**
 * qdf_nbuf_add_rx_frag_debug() - Add frag to nbuf at index frag_idx
 * @buf: Frag pointer needs to be added in nbuf
 * @nbuf: qdf_nbuf_t where frag will be added
 * @offset: Offset in frag to be added to nbuf_frags
 * @frag_len: Frag length
 * @truesize: truesize
 * @take_frag_ref: Whether to take ref for frag or not
 *      This bool must be set as per below comdition:
 *      1. False: If this frag is being added in any nbuf
 *              for the first time after allocation
 *      2. True: If frag is already attached part of any
 *              nbuf
 * @func: Caller function name
 * @line: Caller function line no.
 *
 * Return: none
 */
void qdf_nbuf_add_rx_frag_debug(qdf_frag_t buf, qdf_nbuf_t nbuf,
				int offset, int frag_len,
				unsigned int truesize, bool take_frag_ref,
				const char *func, uint32_t line);


/**
 * qdf_net_buf_debug_acquire_frag() - Add frag nodes to frag debug tracker
 *	when nbuf is received from network stack
 * @buf: qdf_nbuf_t
 * @func: Caller function name
 * @line: Caller function line no.
 *
 * Return: none
 */
void qdf_net_buf_debug_acquire_frag(qdf_nbuf_t buf, const char *func,
				    uint32_t line);

/**
 * qdf_net_buf_debug_release_frag() - Update frag nodes in frag debug tracker
 *	when nbuf is sent to network stack
 * @buf: qdf_nbuf_t
 * @func: Caller function name
 * @line: Caller function line no.
 *
 * Return: none
 */
void qdf_net_buf_debug_release_frag(qdf_nbuf_t buf, const char *func,
				    uint32_t line);

/**
 * qdf_nbuf_frag_count_inc() - Increment global frag counter
 * @buf: qdf_nbuf_t
 *
 * Return: none
 */
void qdf_nbuf_frag_count_inc(qdf_nbuf_t buf);

/**
 * qdf_nbuf_frag_count_dec() - Decrement global frag counter
 * @buf: qdf_nbuf_t
 *
 * Return: none
 */
void qdf_nbuf_frag_count_dec(qdf_nbuf_t buf);

#else /* NBUF_FRAG_MEMORY_DEBUG */

/**
 * qdf_nbuf_move_frag_page_offset() - Move frag page_offset by size
 *          and adjust length by size.
 * @nbuf: qdf_nbuf_t
 * @idx: Frag index
 * @offset: Frag page offset should be moved by offset.
 *      +Ve - Move offset forward.
 *      -Ve - Move offset backward.
 */
static inline QDF_STATUS qdf_nbuf_move_frag_page_offset(qdf_nbuf_t nbuf,
							uint8_t idx,
							int offset)
{
	return __qdf_nbuf_move_frag_page_offset(nbuf, idx, offset);
}

/**
 * qdf_nbuf_remove_frag() - Remove frag from nbuf
 *
 * @nbuf: nbuf pointer
 * @idx: idx at which frag need to be removed
 * @truesize: truesize of frag
 *
 * Return: void
 */
static inline void qdf_nbuf_remove_frag(qdf_nbuf_t nbuf,
					uint16_t idx,
					uint16_t truesize)
{
	return __qdf_nbuf_remove_frag(nbuf, idx, truesize);
}

/**
 * qdf_nbuf_add_rx_frag() - Add frag to nbuf at index frag_idx
 * @buf: Frag pointer needs to be added in nbuf frag
 * @nbuf: qdf_nbuf_t where frag will be added
 * @offset: Offset in frag to be added to nbuf_frags
 * @frag_len: Frag length
 * @truesize: truesize
 * @take_frag_ref: Whether to take ref for frag or not
 *      This bool must be set as per below comdition:
 *      1. False: If this frag is being added in any nbuf
 *              for the first time after allocation
 *      2. True: If frag is already attached part of any
 *              nbuf
 *
 * qdf_nbuf_add_rx_frag takes ref_count based on boolean flag take_frag_ref
 */
static inline void qdf_nbuf_add_rx_frag(qdf_frag_t buf, qdf_nbuf_t nbuf,
					int offset, int frag_len,
					unsigned int truesize,
					bool take_frag_ref)
{
	__qdf_nbuf_add_rx_frag(buf, nbuf, offset,
			       frag_len, truesize, take_frag_ref);
}

static inline void qdf_net_buf_debug_acquire_frag(qdf_nbuf_t buf,
						  const char *func,
						  uint32_t line)
{
}

static inline void qdf_net_buf_debug_release_frag(qdf_nbuf_t buf,
						  const char *func,
						  uint32_t line)
{
}

static inline void qdf_nbuf_frag_count_inc(qdf_nbuf_t buf)
{
}

static inline void qdf_nbuf_frag_count_dec(qdf_nbuf_t buf)
{
}

#endif /* NBUF_FRAG_MEMORY_DEBUG */

#define qdf_nbuf_add_frag(dev, f, n, o, f_l, t_sz, f_r, sz) \
	qdf_nbuf_add_frag_debug(dev, f, n, o, f_l, t_sz,	\
				f_r, sz, __func__, __LINE__)

/**
 * qdf_nbuf_add_frag_debug() - Add frag to nbuf
 * @osdev: Device handle
 * @buf: Frag pointer needs to be added in nbuf frag
 * @nbuf: qdf_nbuf_t where frag will be added
 * @offset: Offset in frag to be added to nbuf_frags
 * @frag_len: Frag length
 * @truesize: truesize
 * @take_frag_ref: Whether to take ref for frag or not
 *      This bool must be set as per below comdition:
 *      1. False: If this frag is being added in any nbuf
 *              for the first time after allocation
 *      2. True: If frag is already attached part of any
 *              nbuf
 * @minsize: Minimum size to allocate
 * @func: Caller function name
 * @line: Caller function line no.
 *
 * if number of frag exceed maximum frag array. A new nbuf is allocated
 * with minimum headroom and frag it added to that nbuf.
 * new nbuf is added as frag_list to the master nbuf.
 *
 * Return: QDF_STATUS
 */
QDF_STATUS
qdf_nbuf_add_frag_debug(qdf_device_t osdev, qdf_frag_t buf,
			qdf_nbuf_t nbuf, int offset,
			int frag_len, unsigned int truesize,
			bool take_frag_ref, unsigned int minsize,
			const char *func, uint32_t line);

#ifdef MEMORY_DEBUG
/**
 * qdf_nbuf_acquire_track_lock - acquire the nbuf spinlock at the
 * specified index
 * @index: index to get the lock
 * @irq_flag: lock flag for using nbuf lock
 *
 * Return: none
 */
void qdf_nbuf_acquire_track_lock(uint32_t index,
				 unsigned long irq_flag);

/**
 * qdf_nbuf_release_track_lock - release the nbuf spinlock at the
 * specified index
 * @index: index of the lock to be released
 * @irq_flag: lock flag for using nbuf lock
 *
 * Return: none
 */
void qdf_nbuf_release_track_lock(uint32_t index,
				 unsigned long irq_flag);

/**
 * qdf_nbuf_get_track_tbl - get the QDF_NBUF_TRACK entry from the track
 * table at the specified index
 * @index: index to get the table entry
 *
 * Return: the QDF_NBUF_TRACK entry at the specified index in the table
 */
QDF_NBUF_TRACK *qdf_nbuf_get_track_tbl(uint32_t index);
#endif /* MEMORY_DEBUG */

#ifdef CONFIG_WLAN_SYSFS_MEM_STATS
/**
 * qdf_record_nbuf_nbytes() - add or subtract the size of the nbuf
 * from the total skb mem and DP tx/rx skb mem
 * @nbytes: number of bytes
 * @dir: direction
 * @is_mapped: is mapped or unmapped memory
 *
 * Return: none
 */
void qdf_record_nbuf_nbytes(
	uint32_t nbytes, qdf_dma_dir_t dir, bool is_mapped);

#else /* CONFIG_WLAN_SYSFS_MEM_STATS */
static inline void qdf_record_nbuf_nbytes(
	int nbytes, qdf_dma_dir_t dir, bool is_mapped)
{
}
#endif /* CONFIG_WLAN_SYSFS_MEM_STATS */

#ifdef ENHANCED_OS_ABSTRACTION
/**
 * qdf_nbuf_set_timestamp() - set the timestamp for frame
 * @buf: pointer to network buffer
 *
 * Return: none
 */
void qdf_nbuf_set_timestamp(qdf_nbuf_t buf);

/**
 * qdf_nbuf_get_timestamp() - get the timestamp for frame
 * @buf: pointer to network buffer
 *
 * Return: timestamp stored in skb in ms
 */
uint64_t qdf_nbuf_get_timestamp(qdf_nbuf_t buf);

/**
 * qdf_nbuf_get_timestamp_us() - get the timestamp for frame
 * @buf: pointer to network buffer
 *
 * Return: timestamp stored in nbuf in us
 */
uint64_t qdf_nbuf_get_timestamp_us(qdf_nbuf_t buf);

/**
 * qdf_nbuf_get_timedelta_ms() - get time difference in ms
 * @buf: pointer to network buffer
 *
 * Return: time difference ms
 */
uint64_t qdf_nbuf_get_timedelta_ms(qdf_nbuf_t buf);

/**
 * qdf_nbuf_get_timedelta_us() - get time difference in micro seconds
 * @buf: pointer to network buffer
 *
 * Return: time difference in micro seconds
 */
uint64_t qdf_nbuf_get_timedelta_us(qdf_nbuf_t buf);

/**
 * qdf_nbuf_net_timedelta() - get time delta
 * @t: time as qdf_ktime_t object
 *
 * Return: time delta as ktime_t object
 */
qdf_ktime_t qdf_nbuf_net_timedelta(qdf_ktime_t t);
#else
static inline void
qdf_nbuf_set_timestamp(struct sk_buff *skb)
{
	__qdf_nbuf_set_timestamp(skb);
}

static inline uint64_t
qdf_nbuf_get_timestamp(struct sk_buff *skb)
{
	return __qdf_nbuf_get_timestamp(skb);
}

static inline uint64_t
qdf_nbuf_get_timestamp_us(qdf_nbuf_t buf)
{
	return __qdf_nbuf_get_timestamp_us(buf);
}

static inline uint64_t
qdf_nbuf_get_timedelta_ms(struct sk_buff *skb)
{
	return __qdf_nbuf_get_timedelta_ms(skb);
}

static inline uint64_t
qdf_nbuf_get_timedelta_us(struct sk_buff *skb)
{
	return __qdf_nbuf_get_timedelta_us(skb);
}

static inline qdf_ktime_t qdf_nbuf_net_timedelta(qdf_ktime_t t)
{
	return __qdf_nbuf_net_timedelta(t);
}
#endif /* ENHANCED_OS_ABSTRACTION */

#ifdef NBUF_MEMORY_DEBUG
/**
 * qdf_set_smmu_fault_state() - Set smmu fault state
 * @smmu_fault_state: state of the wlan smmu
 *
 * Return: void
 */
void qdf_set_smmu_fault_state(bool smmu_fault_state);
#else
static inline void qdf_set_smmu_fault_state(bool smmu_fault_state)
{
}
#endif

#ifdef CONFIG_NBUF_AP_PLATFORM
#include <i_qdf_nbuf_api_w.h>
#else
#include <i_qdf_nbuf_api_m.h>
#endif

/**
 * qdf_nbuf_stop_replenish_timer - Stop alloc fail replenish timer
 *
 * This function stops the alloc fail replenish timer.
 *
 * Return: void
 */
void qdf_nbuf_stop_replenish_timer(void);

/**
 * qdf_get_nbuf_valid_frag() - Get nbuf to store frag
 * @nbuf: qdf_nbuf_t master nbuf
 *
 * Return: qdf_nbuf_t
 */
qdf_nbuf_t qdf_get_nbuf_valid_frag(qdf_nbuf_t nbuf);

/**
 * qdf_nbuf_fast_xmit() - Check if packet has fast_xmit support
 * @nbuf: qdf_nbuf_t master nbuf
 *
 * This function checks if skb has fast_xmit or not.
 *
 * Return: True if skb support fast_xmit otherwise false
 */
bool qdf_nbuf_fast_xmit(qdf_nbuf_t nbuf);

/**
 * qdf_nbuf_set_fast_xmit() - Set fast_xmit in SKB
 * @nbuf: qdf_nbuf_t master nbuf
 * @value: value to set in fast_xmit
 *
 * This function set fast_xmit in SKB if it exist.
 *
 * Return: void
 */
void qdf_nbuf_set_fast_xmit(qdf_nbuf_t nbuf, int value);

#endif /* _QDF_NBUF_H */
