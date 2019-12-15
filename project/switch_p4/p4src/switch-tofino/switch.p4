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

#if defined(A0_PROFILE)
#include "switch_tofino_a0.p4"
#elif defined(B0_PROFILE)
#include "switch_tofino_b0.p4"
#elif defined(L0_PROFILE)
#include "switch_profile_l0.p4"
#else /* Default profile */

#include <core.p4>
#if __TARGET_TOFINO__ == 2
#include <t2na.p4>
#else
#include <tna.p4>
#endif

#include "features.p4"
#include "headers.p4"
#include "types.p4"

const bit<32> PORT_TABLE_SIZE = 288 * 2;

// 4K L2 vlans
const bit<32> VLAN_TABLE_SIZE = 4096;
const bit<32> BD_FLOOD_TABLE_SIZE = VLAN_TABLE_SIZE * 4;

// 1K (port, vlan) <--> BD
const bit<32> PORT_VLAN_TABLE_SIZE = 1024;

// 4K (port, vlan[0], vlan[1]) <--> BD
const bit<32> DOUBLE_TAG_TABLE_SIZE = 4096;

// 5K BDs
const bit<32> BD_TABLE_SIZE = 5120;

// 16K MACs
const bit<32> MAC_TABLE_SIZE = 16384;

// IP Hosts/Routes
const bit<32> IPV4_LPM_TABLE_SIZE = 16384;
const bit<32> IPV6_LPM_TABLE_SIZE = 1024; // 8192;
const bit<32> IPV4_HOST_TABLE_SIZE = 16384;  // 32768
const bit<32> IPV6_HOST_TABLE_SIZE = 8192; // 16384;
// Multicast
const bit<32> IPV4_MULTICAST_STAR_G_TABLE_SIZE = 2048;
const bit<32> IPV4_MULTICAST_S_G_TABLE_SIZE = 4096;
const bit<32> IPV6_MULTICAST_STAR_G_TABLE_SIZE = 512;
const bit<32> IPV6_MULTICAST_S_G_TABLE_SIZE = 512;
const bit<32> RID_TABLE_SIZE = 4096;

// Tunnels - 4K IPv4 + 1K IPv6
const bit<32> DEST_TUNNEL_TABLE_SIZE = 512;
const bit<32> IPV4_SRC_TUNNEL_TABLE_SIZE = 4096;
const bit<32> IPV6_SRC_TUNNEL_TABLE_SIZE = 1024;
const bit<32> VNI_MAPPING_TABLE_SIZE = 4096;
const bit<32> TUNNEL_SRC_REWRITE_TABLE_SIZE = 512;
const bit<32> TUNNEL_DST_REWRITE_TABLE_SIZE = 4096;
const bit<32> TUNNEL_SMAC_REWRITE_TABLE_SIZE = 512;
const bit<32> TUNNEL_DMAC_REWRITE_TABLE_SIZE = 4096;
const bit<32> TUNNEL_REWRITE_TABLE_SIZE = 512;

// ECMP/Nexthop
const bit<32> ECMP_GROUP_TABLE_SIZE = 1024;
const bit<32> OUTER_ECMP_GROUP_TABLE_SIZE = 1024;
const bit<32> ECMP_SELECT_TABLE_SIZE = 16384;
const bit<32> OUTER_ECMP_SELECT_TABLE_SIZE = 1638;
const bit<32> NEXTHOP_TABLE_SIZE = 16384; // 32768
const bit<32> NUM_TUNNELS = 4096;

// Ingress ACLs
const bit<32> INGRESS_MAC_ACL_TABLE_SIZE = 512;
const bit<32> INGRESS_IPV4_ACL_TABLE_SIZE = 512;
const bit<32> INGRESS_IPV6_ACL_TABLE_SIZE = 512;
const bit<32> INGRESS_MIRROR_ACL_TABLE_SIZE = 512;
const bit<32> INGRESS_MAC_QOS_ACL_TABLE_SIZE = 512;
const bit<32> INGRESS_IPV4_QOS_ACL_TABLE_SIZE = 512;
const bit<32> INGRESS_IPV6_QOS_ACL_TABLE_SIZE = 512;

const bit<32> INGRESS_L4_PORT_LOU_TABLE_SIZE = switch_l4_port_label_width / 2;

const bit<32> IPV4_RACL_TABLE_SIZE = 512;
const bit<32> IPV6_RACL_TABLE_SIZE = 512;

// Egress ACL
const bit<32> EGRESS_MAC_ACL_TABLE_SIZE = 512;
const bit<32> EGRESS_IPV4_ACL_TABLE_SIZE = 512;
const bit<32> EGRESS_IPV6_ACL_TABLE_SIZE = 512;

// WRED
const bit<32> WRED_SIZE = 1 << switch_wred_index_width;

// COPP
const bit<32> COPP_METER_SIZE = 1 << switch_copp_meter_id_width;
const bit<32> COPP_DROP_TABLE_SIZE = 1 << (switch_copp_meter_id_width + 1);

// QoS
const bit<32> DSCP_TO_TC_TABLE_SIZE = 1024;
const bit<32> PCP_TO_TC_TABLE_SIZE = 1024;
const bit<32> QUEUE_TABLE_SIZE = 1024;
const bit<32> EGRESS_QOS_MAP_TABLE_SIZE = 1024;

// Policer
const bit<32> INGRESS_POLICER_TABLE_SIZE = 1 << switch_policer_meter_index_width;

// Storm Control
const bit<32> STORM_CONTROL_TABLE_SIZE = 512;

// System ACL
const bit<32> INGRESS_SYSTEM_ACL_TABLE_SIZE = 512;
const bit<32> EGRESS_SYSTEM_ACL_TABLE_SIZE = 512;
const bit<32> DROP_STATS_TABLE_SIZE = 1 << switch_drop_reason_width;

const bit<32> L3_MTU_TABLE_SIZE = 1024;

#if __TARGET_TOFINO__ == 1
#include "util.p4"
#else
#include "../switch-tofino2/util.p4"
#endif

#include "l3.p4"
#include "nexthop.p4"
#include "parde.p4"
#include "port.p4"
#include "validation.p4"
#include "rewrite.p4"
#include "tunnel.p4"
#include "multicast.p4"
#include "qos.p4"
#include "meter.p4"
#include "wred.p4"
#include "dtel.p4"
#include "acl.p4"

@pa_no_overlay("ingress", "hdr.bridged_md.__pad_3")

control SwitchIngress(
        inout switch_header_t hdr,
        inout switch_ingress_metadata_t ig_md,
        in ingress_intrinsic_metadata_t ig_intr_md,
        in ingress_intrinsic_metadata_from_parser_t ig_intr_from_prsr,
        inout ingress_intrinsic_metadata_for_deparser_t ig_intr_md_for_dprsr,
        inout ingress_intrinsic_metadata_for_tm_t ig_intr_md_for_tm) {

    IngressPortMapping(PORT_VLAN_TABLE_SIZE,
                       BD_TABLE_SIZE,
                       DOUBLE_TAG_TABLE_SIZE) ingress_port_mapping;
    PktValidation() pkt_validation;
    IngressSTP() stp;
    SMAC(MAC_TABLE_SIZE) smac;
    DMAC(MAC_TABLE_SIZE) dmac;
    //IngressTunnel(IPV4_SRC_TUNNEL_TABLE_SIZE) tunnel;
    IngressBd(BD_TABLE_SIZE) bd_stats;
    IngressMulticast(IPV4_MULTICAST_S_G_TABLE_SIZE,
                     IPV4_MULTICAST_STAR_G_TABLE_SIZE,
                     IPV6_MULTICAST_S_G_TABLE_SIZE,
                     IPV6_MULTICAST_STAR_G_TABLE_SIZE) multicast;
    IngressUnicast(dmac,
                   IPV4_HOST_TABLE_SIZE,
                   IPV4_LPM_TABLE_SIZE,
                   IPV6_HOST_TABLE_SIZE,
                   IPV6_LPM_TABLE_SIZE) unicast;
   
    InnerPktValidation()inner_pkt_validation;
    IngressAcl(INGRESS_IPV4_ACL_TABLE_SIZE,
               INGRESS_IPV6_ACL_TABLE_SIZE,
               INGRESS_MAC_ACL_TABLE_SIZE,
               true /* mac_acl */) acl;
    MirrorAcl(stats_enable=true) mirror_acl;
    RouterAcl(IPV4_RACL_TABLE_SIZE, IPV6_RACL_TABLE_SIZE, true) racl;

    IngressDtel() dtel;
    IngressQoS() qos;
    StormControl(STORM_CONTROL_TABLE_SIZE) storm_control;
    Nexthop(NEXTHOP_TABLE_SIZE, ECMP_GROUP_TABLE_SIZE, ECMP_SELECT_TABLE_SIZE) nexthop;
    OuterFib(
        NUM_TUNNELS, OUTER_ECMP_GROUP_TABLE_SIZE, OUTER_ECMP_SELECT_TABLE_SIZE) outer_fib;
    LAG() lag;
    MulticastFlooding(BD_FLOOD_TABLE_SIZE) flood;
    IngressSystemAcl() system_acl;

    apply {
        ig_intr_md_for_dprsr.drop_ctl = 0;
        ig_md.multicast.id = 0;
        ig_md.flags.racl_deny = false;
#ifdef MULTICAST_ENABLE
        ig_md.flags.flood_to_multicast_routers = false;
#endif

        pkt_validation.apply(hdr, ig_md.flags, ig_md.lkp, ig_intr_md_for_tm, ig_md.drop_reason);

        ingress_port_mapping.apply(hdr, ig_md, ig_intr_md_for_tm, ig_intr_md_for_dprsr);
        stp.apply(ig_md, ig_md.stp);

        
        smac.apply(ig_md.lkp.mac_src_addr, ig_md, ig_intr_md_for_dprsr.digest_type);
        bd_stats.apply(ig_md.bd, ig_md.lkp.pkt_type);
        
        //tunnel.apply(hdr, ig_md, ig_md.lkp);

        if (ig_md.lkp.tunnel_flag == true){
            inner_pkt_validation.apply(hdr, ig_md.lkp, ig_md.flags, ig_md.drop_reason);
        }

        acl.apply(ig_md.lkp, ig_md);
        mirror_acl.apply(ig_md.lkp, ig_md);
        if (ig_md.lkp.pkt_type == SWITCH_PKT_TYPE_UNICAST) {
            // Unicast packets.
            unicast.apply(ig_md.lkp, ig_md);
        } else if (ig_md.lkp.pkt_type == SWITCH_PKT_TYPE_MULTICAST &&
                ig_md.lkp.ip_type != SWITCH_IP_TYPE_NONE) {
            // IP multicast packets.
            multicast.apply(ig_md.lkp, ig_md);
        } else {
            // Non-IP multicast and broadcast packets.
            dmac.apply(ig_md.lkp.mac_dst_addr, ig_md);
        }

        racl.apply(ig_md.lkp, ig_md);
        if (ig_md.lkp.ip_type == SWITCH_IP_TYPE_NONE)
            compute_non_ip_hash(ig_md.lkp, ig_md.hash);
        else
            compute_ip_hash(ig_md.lkp, ig_md.hash);

        nexthop.apply(ig_md.lkp, ig_md, ig_md.hash[15:0]);
        qos.apply(hdr, ig_md.lkp, ig_md);
        storm_control.apply(ig_md, ig_md.lkp.pkt_type, ig_md.flags.storm_control_drop);
        outer_fib.apply(ig_md, ig_md.hash[31:16]);

        if (ig_md.egress_ifindex == SWITCH_IFINDEX_FLOOD) {
            flood.apply(ig_md);
        } else {
            lag.apply(ig_md, ig_md.hash[31:16], ig_intr_md_for_tm.ucast_egress_port);
        }

        system_acl.apply(ig_md, ig_intr_md_for_tm, ig_intr_md_for_dprsr);
        dtel.apply(
            hdr, ig_md.lkp, ig_md, ig_md.hash[15:0], ig_intr_md_for_dprsr, ig_intr_md_for_tm);

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
        in egress_intrinsic_metadata_from_parser_t eg_intr_md_from_prsr,
        inout egress_intrinsic_metadata_for_deparser_t eg_intr_md_for_dprsr,
        inout egress_intrinsic_metadata_for_output_port_t eg_intr_md_for_oport) {
    EgressPortMapping(PORT_TABLE_SIZE) egress_port_mapping;
    EgressSTP() stp;
    EgressAcl() acl;
    EgressQoS(EGRESS_QOS_MAP_TABLE_SIZE) qos;
    EgressSystemAcl() system_acl;
    Rewrite(NEXTHOP_TABLE_SIZE, BD_TABLE_SIZE) rewrite;
    EgressDtel() dtel;
    MirrorRewrite() mirror_rewrite;
    VlanXlate(VLAN_TABLE_SIZE, PORT_VLAN_TABLE_SIZE) vlan_xlate;
    VlanDecap() vlan_decap;
    TunnelDecap(switch_tunnel_mode_t.PIPE) tunnel_decap;
    TunnelEncap(switch_tunnel_mode_t.PIPE) tunnel_encap;
    TunnelRewrite() tunnel_rewrite;

    MTU() mtu;
    WRED() wred;
    MulticastReplication(RID_TABLE_SIZE) multicast_replication;

    apply {
        eg_intr_md_for_dprsr.drop_ctl = 0;
        eg_md.timestamp = eg_intr_md_from_prsr.global_tstamp[31:0];
        egress_port_mapping.apply(hdr, eg_md, eg_intr_md_for_dprsr, eg_intr_md.egress_port);
        mirror_rewrite.apply(hdr, eg_md);
        multicast_replication.apply(eg_intr_md.egress_rid, eg_intr_md.egress_port, eg_md);
        stp.apply(eg_md, eg_intr_md.egress_port, eg_md.checks.stp);
        vlan_decap.apply(hdr, eg_md);
        tunnel_decap.apply(hdr, eg_md);
        qos.apply(hdr, eg_intr_md.egress_port, eg_md);
        wred.apply(hdr, eg_md, eg_intr_md, eg_md.flags.wred_drop);

        rewrite.apply(hdr, eg_md);
        acl.apply(hdr, eg_md.lkp, eg_md);
        tunnel_encap.apply(hdr, eg_md);
        tunnel_rewrite.apply(hdr, eg_md);
        mtu.apply(hdr, eg_md, eg_md.checks.mtu);
        vlan_xlate.apply(hdr, eg_md);

        dtel.apply(hdr, eg_md, eg_intr_md, eg_md.dtel.hash, eg_intr_md_for_dprsr);
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

#endif /* Default profile */
