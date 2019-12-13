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
#if __TARGET_TOFINO__ == 2
#include <t2na.p4>
#else
#include <tna.p4>
#endif

//-----------------------------------------------------------------------------
// Features.
//-----------------------------------------------------------------------------
#define ACL_REDIRECT_ENABLE
#define COPP_ENABLE
#define EGRESS_IP_ACL_ENABLE
#define EGRESS_PORT_MIRROR_ENABLE
#define ERSPAN_ENABLE
#define ERSPAN_TYPE2_ENABLE
#define INGRESS_ACL_POLICER_ENABLE
#define INGRESS_PORT_MIRROR_ENABLE
#define IPV6_ENABLE
#define L4_PORT_LOU_ENABLE
#define MIRROR_ENABLE
#define MIRROR_ACL_ENABLE
#define QOS_ENABLE
#define STORM_CONTROL_ENABLE
#define UNICAST_SELF_FORWARDING_CHECK
#define WRED_ENABLE
#define PACKET_LENGTH_ADJUSTMENT

//-----------------------------------------------------------------------------
// Table sizes.
//-----------------------------------------------------------------------------
// 4K L2 vlans
const bit<32> VLAN_TABLE_SIZE = 4096;
const bit<32> BD_FLOOD_TABLE_SIZE = VLAN_TABLE_SIZE * 4;

// 1K (port, vlan) <--> BD
const bit<32> PORT_VLAN_TABLE_SIZE = 1024;

// 5K BDs
const bit<32> BD_TABLE_SIZE = 5120;

// 16K MACs
const bit<32> MAC_TABLE_SIZE = 16384;

// IP Hosts/Routes
const bit<32> IPV4_HOST_TABLE_SIZE = 65536;
const bit<32> IPV4_LPM_TABLE_SIZE = 32768;
const bit<32> IPV6_HOST_TABLE_SIZE = 16384;
const bit<32> IPV6_LPM_TABLE_SIZE = 16384;

// ECMP/Nexthop
const bit<32> ECMP_GROUP_TABLE_SIZE = 1024;
const bit<32> ECMP_SELECT_TABLE_SIZE = 16384;
const bit<32> NEXTHOP_TABLE_SIZE = 65536;

// Ingress ACLs
const bit<32> INGRESS_MAC_ACL_TABLE_SIZE = 512;
const bit<32> INGRESS_IPV4_ACL_TABLE_SIZE = 1024;
const bit<32> INGRESS_IPV6_ACL_TABLE_SIZE = 512;

const bit<32> EGRESS_IPV6_ACL_TABLE_SIZE = 512;
const bit<32> EGRESS_MAC_ACL_TABLE_SIZE = 512;
const bit<32> EGRESS_IPV4_ACL_TABLE_SIZE = 512;

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
    IngressAcl(
        INGRESS_IPV4_ACL_TABLE_SIZE, INGRESS_IPV6_ACL_TABLE_SIZE, INGRESS_MAC_ACL_TABLE_SIZE) acl;
    MirrorAcl(stats_enable=true) mirror_acl;
    ECNAcl() ecn_acl;
    IngressQoS() qos;
    StormControl() storm_control;
    Nexthop(NEXTHOP_TABLE_SIZE, ECMP_GROUP_TABLE_SIZE, ECMP_SELECT_TABLE_SIZE) nexthop;
    LAG() lag;
    MulticastFlooding(BD_FLOOD_TABLE_SIZE) flood;
    IngressSystemAcl() system_acl;

   action vip_hit(switch_port_t port) {
        // Send the packet to the other pipe and bypass rest of the lookups.
        //TODO(msharif): Load balance across all the ports in the other pipelines using the flow
        // hash.
        ig_intr_md_for_tm.ucast_egress_port = port;
        ig_md.egress_port_lag_index = 0;
        ig_md.egress_ifindex = 0;
        ig_md.bypass = SWITCH_INGRESS_BYPASS_ALL;
    }

    table vip {
        key = {
            hdr.ipv4.dst_addr : exact;
            ig_md.lkp.l4_dst_port   : exact;
            ig_md.lkp.ip_proto : exact;
        }

        actions = {
            NoAction;
            vip_hit;
        }

        const default_action = NoAction;
    }

    apply {
        ig_intr_md_for_dprsr.drop_ctl = 0;
        ig_md.multicast.id = 0;
        ig_md.flags.racl_deny = false;
#ifdef MULTICAST_ENABLE
        ig_md.flags.flood_to_multicast_routers = false;
#endif

        pkt_validation.apply(
            hdr, ig_md.flags, ig_md.lkp, ig_intr_md_for_tm, ig_md.drop_reason);
        ingress_port_mapping.apply(hdr, ig_md, ig_intr_md_for_tm, ig_intr_md_for_dprsr);
        smac.apply(ig_md.lkp.mac_src_addr, ig_md, ig_intr_md_for_dprsr.digest_type);
        bd_stats.apply(ig_md.bd, ig_md.lkp.pkt_type);

        if (ig_md.lkp.pkt_type == SWITCH_PKT_TYPE_UNICAST) {
            // Unicast packets.
            unicast.apply(ig_md.lkp, ig_md);
            vip.apply();
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
        storm_control.apply(ig_md, ig_md.lkp.pkt_type, ig_md.flags.storm_control_drop);

        if (ig_md.egress_ifindex == SWITCH_IFINDEX_FLOOD) {
            flood.apply(ig_md);
        } else {
            lag.apply(ig_md, ig_md.hash[31:16], ig_intr_md_for_tm.ucast_egress_port);
        }

        ecn_acl.apply(ig_md, ig_md.lkp, ig_intr_md_for_tm.packet_color);
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
    EgressAcl(
        EGRESS_IPV4_ACL_TABLE_SIZE, EGRESS_IPV6_ACL_TABLE_SIZE, EGRESS_MAC_ACL_TABLE_SIZE) acl;
    EgressQoS() qos;
    EgressSystemAcl() system_acl;
    Rewrite(NEXTHOP_TABLE_SIZE, BD_TABLE_SIZE) rewrite;
    MirrorRewrite() mirror_rewrite;
    VlanXlate(VLAN_TABLE_SIZE, PORT_VLAN_TABLE_SIZE) vlan_xlate;
    VlanDecap() vlan_decap;
    MTU() mtu;
    WRED() wred;
    MulticastReplication() multicast_replication;

    apply {
        eg_intr_md_for_dprsr.drop_ctl = 0;
        egress_port_mapping.apply(hdr, eg_md, eg_intr_md_for_dprsr, eg_intr_md.egress_port);
        multicast_replication.apply(
            eg_intr_md.egress_rid, eg_intr_md.egress_port, eg_md);

        mirror_rewrite.apply(hdr, eg_md);
        vlan_decap.apply(hdr, eg_md);
        qos.apply(hdr, eg_intr_md.egress_port, eg_md);
        wred.apply(hdr, eg_md, eg_intr_md, eg_md.flags.wred_drop);

        rewrite.apply(hdr, eg_md);
        acl.apply(hdr, eg_md.lkp, eg_md);
        mtu.apply(hdr, eg_md, eg_md.checks.mtu);
        vlan_xlate.apply(hdr, eg_md);

        system_acl.apply(hdr, eg_md, eg_intr_md, eg_intr_md_for_dprsr);

        set_eg_intr_md(eg_md, eg_intr_md_for_dprsr, eg_intr_md_for_oport);
    }
}

control L4LB(inout switch_header_t hdr,
             inout switch_ingress_metadata_t ig_md)(
             switch_uint32_t conn_table_size,
             switch_uint32_t vip_table_size,
             switch_uint32_t dip_pool_table_size) {
// Base on
// R Miao, H Zeng, C Kim, J Lee, M Yu, "SilkRoad: Making Stateful Layer-4 Load Balancing Fast and
// Cheap Using Switching ASICs", SIGCOMM'17
//
// Notable missing features:
// - Learning
// - Transit table

    bit<6> pool_version;

    bit<16> digest;
    Hash<bit<16>>(HashAlgorithm_t.CRC16) digest_hash;

    Hash<bit<32>>(HashAlgorithm_t.CRC32) selector_hash;
    ActionSelector(1024, selector_hash, SelectorMode_t.FAIR) dip_selector;

    action set_pool_version(bit<6> version) {
        pool_version = version;
    }

    @pragma proxy_hash_width 16
    //TODO(msharif): This table (or part of it) can be moved to switch pipeline to reduce latency.
    table conn {
        key = {
            hdr.ipv4.src_addr : exact;
            hdr.ipv4.dst_addr : exact;
            hdr.ipv4.protocol : exact;
            ig_md.lkp.l4_src_port : exact;
            ig_md.lkp.l4_dst_port : exact;
        }

        actions = {
            NoAction;
            set_pool_version;
        }

        const default_action = NoAction;
        size = conn_table_size;
        idle_timeout = true;
    }

    table vip {
        key = {
            hdr.ipv4.dst_addr : exact @name("vip");
            ig_md.lkp.l4_dst_port : exact;
            ig_md.lkp.ip_proto : exact;
        }

        actions = {
            NoAction;
            set_pool_version;
        }

        const default_action = NoAction;
    }

    action set_dip(ipv4_addr_t dip, bit<16> dst_port) {
        hdr.ipv4.dst_addr = dip;
        ig_md.lkp.l4_dst_port = dst_port;
    }

    table dip_pool {
        key = {
            pool_version : exact;
            hdr.ipv4.dst_addr : exact @name("vip");
            ig_md.lkp.l4_dst_port : exact;
            hdr.ipv4.src_addr : selector;
            ig_md.lkp.l4_src_port : selector;
        }

        actions = {
            NoAction;
            set_dip;
        }

        size = dip_pool_table_size;
        implementation = dip_selector;
    }

    apply {
        if (!conn.apply().hit) {
            vip.apply();

            if (pool_version != 0) {
                // Generate digest.
            }
        }

        dip_pool.apply();

        if (hdr.tcp.isValid()) {
            hdr.tcp.dst_port = ig_md.lkp.l4_dst_port;
        } else if (hdr.udp.isValid()) {
            hdr.udp.dst_port = ig_md.lkp.l4_dst_port;
        }
    }
}

control L4LBIngress(
        inout switch_header_t hdr,
        inout switch_ingress_metadata_t ig_md,
        in ingress_intrinsic_metadata_t ig_intr_md,
        in ingress_intrinsic_metadata_from_parser_t ig_intr_from_prsr,
        inout ingress_intrinsic_metadata_for_deparser_t ig_intr_md_for_dprsr,
        inout ingress_intrinsic_metadata_for_tm_t ig_intr_md_for_tm) {

    action fib_hit(mac_addr_t dmac, switch_port_t port) {
        hdr.ethernet.dst_addr = dmac;
        ig_intr_md_for_tm.ucast_egress_port = port;
        ig_intr_md_for_tm.bypass_egress = 1w1;
        ig_intr_md_for_dprsr.drop_ctl = 0x0;
    }

    action fib_miss() {
        ig_intr_md_for_dprsr.drop_ctl = 0x1;
    }

    table fib {
        key = { hdr.ipv4.dst_addr : exact; }
        actions = {
            fib_hit;
            fib_miss;
        }

        const default_action = fib_miss;
    }

    apply {
        fib.apply();
    }
}

control L4LBEgress(
        inout switch_header_t hdr,
        inout switch_ingress_metadata_t eg_md,
        in egress_intrinsic_metadata_t eg_intr_md,
        in egress_intrinsic_metadata_from_parser_t eg_intr_from_prsr,
        inout egress_intrinsic_metadata_for_deparser_t eg_intr_md_for_dprsr,
        inout egress_intrinsic_metadata_for_output_port_t eg_intr_md_for_oport) {

    L4LB(conn_table_size=1 << 18,
         vip_table_size=16384,
         dip_pool_table_size=16384) l4lb;

    apply {
        l4lb.apply(hdr, eg_md);
    }
}


//-----------------------------------------------------------------------------
// Parser
//-----------------------------------------------------------------------------
parser PacketParser(packet_in pkt, inout switch_header_t hdr) {
    state start {
        pkt.extract(hdr.ethernet);
        transition select(hdr.ethernet.ether_type) {
            ETHERTYPE_IPV4 : parse_ipv4;
            default : accept;
        }
    }

    state parse_ipv4 {
        pkt.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            IP_PROTOCOLS_TCP : parse_tcp;
            IP_PROTOCOLS_UDP : parse_udp;
            default : accept;
        }
    }

    state parse_vlan {
        pkt.extract(hdr.vlan_tag.next);
        transition select(hdr.vlan_tag.last.ether_type) {
            ETHERTYPE_IPV4 : parse_ipv4;
            ETHERTYPE_VLAN : parse_vlan;
            default : accept;
        }
    }

    state parse_udp {
        pkt.extract(hdr.udp);
        transition accept;
    }

    state parse_tcp {
        pkt.extract(hdr.tcp);
        transition accept;
    }
}

parser L4LBIngressParser(packet_in pkt,
                        out switch_header_t hdr,
                        out switch_ingress_metadata_t ig_md,
                        out ingress_intrinsic_metadata_t ig_intr_md) {

    PacketParser() packet_parser;
    state start {
        pkt.extract(ig_intr_md);
        pkt.advance(PORT_METADATA_SIZE);
        packet_parser.apply(pkt, hdr);
        transition accept;
    }
}

parser L4LBEgressParser(packet_in pkt,
                        out switch_header_t hdr,
                        out switch_ingress_metadata_t eg_md,
                        out egress_intrinsic_metadata_t eg_intr_md) {

    PacketParser() packet_parser;
    state start {
        pkt.extract(eg_intr_md);
        transition parse_bridged_metadata;
    }

    state parse_bridged_metadata {
        pkt.extract(hdr.bridged_md);
        eg_md.lkp.l4_src_port = hdr.bridged_md.acl.l4_src_port;
        eg_md.lkp.l4_dst_port = hdr.bridged_md.acl.l4_dst_port;
        packet_parser.apply(pkt, hdr);
        transition accept;
    }
}

//-----------------------------------------------------------------------------
// Deparser
//-----------------------------------------------------------------------------
control L4LBIngressDeparser(
    packet_out pkt,
    inout switch_header_t hdr,
    in switch_ingress_metadata_t ig_md,
    in ingress_intrinsic_metadata_for_deparser_t ig_intr_md_for_dprsr) {

    apply {
        pkt.emit(hdr.ethernet);
        pkt.emit(hdr.vlan_tag);
        pkt.emit(hdr.ipv4);
        pkt.emit(hdr.udp);
        pkt.emit(hdr.tcp);
    }
}

control L4LBEgressDeparser(
        packet_out pkt,
        inout switch_header_t hdr,
        in switch_ingress_metadata_t eg_md,
        in egress_intrinsic_metadata_for_deparser_t eg_intr_md_for_dprsr) {

    apply {
        pkt.emit(hdr.ethernet);
        pkt.emit(hdr.vlan_tag);
        pkt.emit(hdr.ipv4);
        pkt.emit(hdr.udp);
        pkt.emit(hdr.tcp);
    }
}

Pipeline(L4LBIngressParser(),
         L4LBIngress(),
         L4LBIngressDeparser(),
         L4LBEgressParser(),
         L4LBEgress(),
         L4LBEgressDeparser()) lb;


Pipeline(SwitchIngressParser(),
         SwitchIngress(),
         SwitchIngressDeparser(),
         SwitchEgressParser(),
         SwitchEgress(),
         SwitchEgressDeparser()) pipe;

Switch(pipe, lb) main;
