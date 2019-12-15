/*******************************************************************************
 * BAREFOOT NETWORKS CONFIDENTIAL & PROPRIETARY
 *
 * Copyright (c) 2015-2019 Barefoot Networks, Inc.

 * All Rights Reserved.
 *
 * NOTICE: All information contained herein is, and remains the property of
 * Barefoot Networks, Inc. and its suppliers, if any. The intellectual and
 * technical concepts contained herein are proprietary to Barefoot Networks,
 * Inc.
 * and its suppliers and may be covered by U.S. and Foreign Patents, patents in
 * process, and are protected by trade secret or copyright law.
 * Dissemination of this information or reproduction of this material is
 * strictly forbidden unless prior written permission is obtained from
 * Barefoot Networks, Inc.
 *
 * No warranty, explicit or implicit is provided, unless granted under a
 * written agreement with Barefoot Networks, Inc.
 *
 ******************************************************************************/

// List of all supported #define directives.

// #define ACL_REDIRECT_ENABLE
// #define BRIDGE_PORT_ENABLE
#define COPP_ENABLE
#if __TARGET_TOFINO__ == 1
#define DTEL_ENABLE
#define DTEL_QUEUE_REPORT_ENABLE
#define DTEL_DROP_REPORT_ENABLE
#define DTEL_FLOW_REPORT_ENABLE
#define DTEL_ACL_ENABLE
#endif
// #define EGRESS_IP_ACL_ENABLE
#define EGRESS_PORT_MIRROR_ENABLE
#define ERSPAN_ENABLE
#define ERSPAN_TYPE2_ENABLE
#define INGRESS_ACL_POLICER_ENABLE
#define INGRESS_PORT_MIRROR_ENABLE
// #define IPINIP_ENABLE
#define IPV6_ENABLE
#define IPV6_TUNNEL_ENABLE
#define L4_PORT_LOU_ENABLE
// #define MAC_PACKET_CLASSIFICATION
#define MIRROR_ENABLE
#define INGRESS_MIRROR_ACL_ENABLE
#define NON_SHARED_INGRESS_MIRROR_ACL
// #define MLAG_ENABLE
#define MULTICAST_ENABLE
#define PACKET_LENGTH_ADJUSTMENT
// #define PBR_ENABLE
// #define PTP_ENABLE
// #define QINQ_ENABLE
// #define QINQ_RIF_ENABLE
#define QOS_ENABLE
// #define QOS_ACL_ENABLE
#define RACL_ENABLE
#define STORM_CONTROL_ENABLE
//#define STP_ENABLE
// #define TCP_FLAGS_LOU_ENABLE
//#define TUNNEL_ENABLE
// #define UNICAST_SELF_FORWARDING_CHECK
#define VXLAN_ENABLE
// #define WRED_ENABLE
