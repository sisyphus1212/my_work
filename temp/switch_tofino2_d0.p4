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

#include <core.p4>
#include <t2na.p4>

//-----------------------------------------------------------------------------
// Features.
//-----------------------------------------------------------------------------
#define ACL_REDIRECT_ENABLE
#define COPP_ENABLE
#define ECN_ACL_ENABLE
#define EGRESS_PORT_MIRROR_ENABLE
#define EGRESS_MIRROR_ACL_ENABLE
#define ERSPAN_ENABLE
#define ERSPAN_TYPE2_ENABLE
#define INGRESS_ACL_POLICER_ENABLE
#define INGRESS_PORT_MIRROR_ENABLE
#define IPINIP_ENABLE
#define IPV6_ENABLE
#define L4_PORT_LOU_ENABLE
#define MIRROR_ENABLE
#define INGRESS_MIRROR_ACL_ENABLE
#define QOS_ENABLE
#define TUNNEL_ENABLE
#define IPV6_TUNNEL_ENABLE
#define VXLAN_ENABLE
#define WRED_ENABLE

//-----------------------------------------------------------------------------
// Table sizes.
//-----------------------------------------------------------------------------

// 4K L2 vlans
const bit<32> VLAN_TABLE_SIZE = 4096;
const bit<32> BD_FLOOD_TABLE_SIZE = VLAN_TABLE_SIZE * 4;

// 1K (port, vlan) <--> BD
const bit<32> PORT_VLAN_TABLE_SIZE = 1024;

// 4K (port, vlan[0], vlan[1]) <--> BD
const bit<32> DOUBLE_TAG_TABLE_SIZE = 4096;

// 1K VRF
#define switch_vrf_width 14

// 5K BDs
const bit<32> BD_TABLE_SIZE = 5120;

// 16K MACs
const bit<32> MAC_TABLE_SIZE = 4096;

// Tunnels
#define switch_tunnel_index_width 18
const bit<32> TUNNEL_IPV4_REWRITE_SIZE = 262144;
const bit<32> TUNNEL_IPV6_REWRITE_SIZE = 98304;
const bit<32> NUM_TUNNELS = TUNNEL_IPV4_REWRITE_SIZE + TUNNEL_IPV6_REWRITE_SIZE;
const bit<32> OUTER_ECMP_GROUP_TABLE_SIZE = 1024;
const bit<32> OUTER_ECMP_SELECT_TABLE_SIZE = 16384;

// IP Hosts/Routes
const bit<32> IPV4_HOST_TABLE_SIZE = NUM_TUNNELS;
const bit<32> IPV4_LPM_TABLE_SIZE = 2048;
const bit<32> IPV6_HOST_TABLE_SIZE = 8192;
const bit<32> IPV6_LPM_TABLE_SIZE = 10240;

// ECMP/Nexthop
const bit<32> ECMP_GROUP_TABLE_SIZE = 1024;
const bit<32> ECMP_SELECT_TABLE_SIZE = 16384;
#define switch_nexthop_width 19
const bit<32> NEXTHOP_TABLE_SIZE = NUM_TUNNELS;

// Ingress ACLs
const bit<32> INGRESS_IPV4_ACL_TABLE_SIZE = 1024;
const bit<32> INGRESS_IPV6_ACL_TABLE_SIZE = 512;

#include "headers.p4"
#include "types.p4"
#include "util.p4"

#include "l3.p4"
#include "nexthop.p4"
#include "parde.p4"
#include "port.p4"
#include "validation.p4"
#include "rewrite.p4"
#include "multicast.p4"
#include "qos.p4"
#include "meter.p4"
#include "wred.p4"
#include "tunnel.p4"
#include "acl.p4"

control SwitchIngress(
        inout switch_header_t hdr,
        inout switch_ingress_metadata_t ig_md,
        in ingress_intrinsic_metadata_t ig_intr_md,
        in ingress_intrinsic_metadata_from_parser_t ig_intr_from_prsr,
        inout ingress_intrinsic_metadata_for_deparser_t ig_intr_md_for_dprsr,
        inout ingress_intrinsic_metadata_for_tm_t ig_intr_md_for_tm) {
    IngressPortMapping(PORT_VLAN_TABLE_SIZE, BD_TABLE_SIZE) ingress_port_mapping;
    PktValidation() pkt_validation;
    SMAC(MAC_TABLE_SIZE) smac;
    DMAC(MAC_TABLE_SIZE) dmac;
    IngressBd(BD_TABLE_SIZE) bd_stats;
    IngressUnicast(dmac,
                   IPV4_HOST_TABLE_SIZE,
                   IPV4_LPM_TABLE_SIZE,
                   IPV6_HOST_TABLE_SIZE,
                   IPV6_LPM_TABLE_SIZE) unicast;
    IngressAcl(INGRESS_IPV4_ACL_TABLE_SIZE, INGRESS_IPV6_ACL_TABLE_SIZE, 0, false) acl;
    IngressTunnel() tunnel;
    MirrorAcl(stats_enable=true) mirror_acl;
    ECNAcl() ecn_acl;
    PFCWd(512) pfc_wd;
    IngressQoS() qos;
    Nexthop(NEXTHOP_TABLE_SIZE, ECMP_GROUP_TABLE_SIZE, ECMP_SELECT_TABLE_SIZE) nexthop;
    OuterFib(
        NUM_TUNNELS, OUTER_ECMP_GROUP_TABLE_SIZE, OUTER_ECMP_SELECT_TABLE_SIZE) outer_fib;
    LAG() lag;
    MulticastFlooding(BD_FLOOD_TABLE_SIZE) flood;
    IngressSystemAcl() system_acl;

    apply {
        pkt_validation.apply(
            hdr, ig_md.flags, ig_md.lkp, ig_intr_md_for_tm, ig_md.drop_reason);
        ingress_port_mapping.apply(hdr, ig_md, ig_intr_md_for_tm, ig_intr_md_for_dprsr);

        tunnel.apply(hdr, ig_md, ig_md.lkp);
        smac.apply(ig_md.lkp.mac_src_addr, ig_md, ig_intr_md_for_dprsr.digest_type);
        bd_stats.apply(ig_md.bd, ig_md.lkp.pkt_type);
        if (ig_md.lkp.pkt_type == SWITCH_PKT_TYPE_UNICAST) {
            // Unicast packets.
            unicast.apply(ig_md.lkp, ig_md);
        } else if (ig_md.lkp.pkt_type == SWITCH_PKT_TYPE_MULTICAST &&
                ig_md.lkp.ip_type != SWITCH_IP_TYPE_NONE) {
            // IP multicast packets.
        } else {
            // Broadcast packets.
            dmac.apply(ig_md.lkp.mac_dst_addr, ig_md);
        }

        acl.apply(ig_md.lkp, ig_md);
        mirror_acl.apply(ig_md.lkp, ig_md);
        if (ig_md.lkp.ip_type == SWITCH_IP_TYPE_NONE) {
            compute_non_ip_hash(ig_md.lkp, ig_md.hash);
        } else {
            compute_ip_hash(ig_md.lkp, ig_md.hash);
        }

        nexthop.apply(ig_md.lkp, ig_md, ig_md.hash[15:0]);
        qos.apply(hdr, ig_md.lkp, ig_md);
        outer_fib.apply(ig_md, ig_md.hash[31:16]);
        if (ig_md.egress_ifindex == SWITCH_IFINDEX_FLOOD) {
            flood.apply(ig_md);
        } else {
            lag.apply(ig_md, ig_md.hash[31:16], ig_intr_md_for_tm.ucast_egress_port);
        }

        ecn_acl.apply(ig_md, ig_md.lkp, ig_intr_md_for_tm.packet_color);
        pfc_wd.apply(ig_md.port, ig_md.qos.qid, ig_md.flags.pfc_wd_drop);

        system_acl.apply(
            ig_md, ig_intr_md_for_tm, ig_intr_md_for_dprsr);

        // Only add bridged metadata if we are NOT bypassing egress pipeline.
        if (ig_intr_md_for_tm.bypass_egress == 1w0) {
            add_bridged_md(hdr.bridged_md, ig_md);
        }

        set_ig_intr_md(ig_md, ig_intr_md_for_dprsr, ig_intr_md_for_tm);
    }
}

control SwitchEgress(
        inout switch_header_t hdr,
        inout switch_egress_metadata_t eg_md,
        in egress_intrinsic_metadata_t eg_intr_md,
        in egress_intrinsic_metadata_from_parser_t eg_intr_from_prsr,
        inout egress_intrinsic_metadata_for_deparser_t eg_intr_md_for_dprsr,
        inout egress_intrinsic_metadata_for_output_port_t eg_intr_md_for_oport) {
    EgressPortMapping() egress_port_mapping;
    EgressQoS() qos;
    EgressMirrorAcl() mirror_acl;
    EgressSystemAcl() system_acl;
    PFCWd(512) pfc_wd;
    Rewrite(NEXTHOP_TABLE_SIZE, BD_TABLE_SIZE) rewrite;
    MirrorRewrite() mirror_rewrite;
    VlanXlate(VLAN_TABLE_SIZE, PORT_VLAN_TABLE_SIZE) vlan_xlate;
    VlanDecap() vlan_decap;
    TunnelDecap(mode=switch_tunnel_mode_t.PIPE) tunnel_decap;
    TunnelEncap(mode=switch_tunnel_mode_t.PIPE) tunnel_encap;
    TunnelRewrite(TUNNEL_IPV4_REWRITE_SIZE, TUNNEL_IPV6_REWRITE_SIZE, 1024) tunnel_rewrite;

    MTU() mtu;
    WRED() wred;
    MulticastReplication() multicast_replication;

    apply {
        // Packet is mirrored.
        eg_intr_md_for_dprsr.drop_ctl = 0;
        mirror_rewrite.apply(hdr, eg_md);
        egress_port_mapping.apply(hdr, eg_md, eg_intr_md_for_dprsr, eg_intr_md.egress_port);
        vlan_decap.apply(hdr, eg_md);
        tunnel_decap.apply(hdr, eg_md);
        rewrite.apply(hdr, eg_md);
        qos.apply(hdr, eg_intr_md.egress_port, eg_md);
        wred.apply(hdr, eg_md, eg_intr_md, eg_md.flags.wred_drop);
        mirror_acl.apply(hdr, eg_md.lkp, eg_md);
        tunnel_encap.apply(hdr, eg_md);
        tunnel_rewrite.apply(hdr, eg_md);
        mtu.apply(hdr, eg_md, eg_md.checks.mtu);
        vlan_xlate.apply(hdr, eg_md);
        pfc_wd.apply(eg_intr_md.egress_port, eg_md.qos.qid, eg_md.flags.pfc_wd_drop);
        system_acl.apply(hdr, eg_md, eg_intr_md, eg_intr_md_for_dprsr);

        set_eg_intr_md(eg_md, eg_intr_md_for_dprsr, eg_intr_md_for_oport);
    }
}

Pipeline(SwitchIngressParser(),
        SwitchIngress(),
        SwitchIngressDeparser(),
        SwitchEgressParser(),
        SwitchEgress(),
        SwitchEgressDeparser()) pipe;

Switch(pipe) main;
