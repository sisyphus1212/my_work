/*******************************************************************************
 * BAREFOOT NETWORKS CONFIDENTIAL & PROPRIETARY
 *
 * Copyright (c) 2015-2019 Barefoot Networks, Inc.
 *
 * NOTICE: All information contained herein is, and remains the property of
 * Barefoot Networks, Inc. and its suppliers, if any. The intellectual and
 * technical concepts contained herein are proprietary to Barefoot Networks,
 * Inc.
 * and its suppliers and may be coverep by U.S. and Foreign Patents, patents in
 * process, and are protected by trade secret or copyright law.
 * Dissemination of this information or reproduction of this material is
 * strictly forbidden unless prior written permission is obtained from
 * Barefoot Networks, Inc.
 *
 * No warranty, explicit or implicit is provided, unless granted under a
 * written agreement with Barefoot Networks, Inc.
 *
 ******************************************************************************/

#include "headers.p4"
#include "types.p4"

//-----------------------------------------------------------------------------
// Segment routing extension header parser
//-----------------------------------------------------------------------------
parser SRHParser(packet_in pkt, inout switch_header_t hdr) {
    state start {
#ifdef SRV6_ENABLE
        transition parse_srh;
#else
        transition accept;
#endif
    }

    state parse_srh {
        //TODO(msharif) : implement SRH parser.
        transition accept;
    }
}



//=============================================================================
// Ingress parser
//=============================================================================
parser SwitchIngressParser(
        packet_in pkt,
        out switch_header_t hdr,
        out switch_ingress_metadata_t ig_md,
        out ingress_intrinsic_metadata_t ig_intr_md) {
    Checksum() ipv4_checksum;
    Checksum() inner_ipv4_checksum;
    value_set<bit<16>>(1) udp_port_vxlan;
    value_set<switch_cpu_port_value_set_t>(1) cpu_port;

    state start {
        pkt.extract(ig_intr_md);
        ig_md.port = ig_intr_md.ingress_port;
        ig_md.timestamp = ig_intr_md.ingress_mac_tstamp;
        // Check for resubmit flag if packet is resubmitted.
        // transition select(ig_intr_md.resubmit_flag) {
        //    1 : parse_resubmit;
        //    0 : parse_port_metadata;
        // }
        transition parse_port_metadata;
    }

    state parse_resubmit {
        // Parse resubmitted packet here.
        transition accept;
    }

    state parse_port_metadata {
        // Parse port metadata produced by ibuf
        switch_port_metadata_t port_md = port_metadata_unpack<switch_port_metadata_t>(pkt);
        ig_md.port_lag_index = port_md.port_lag_index;
        ig_md.port_lag_label = port_md.port_lag_label;
        ig_md.ifindex = port_md.ifindex;
        transition parse_packet;
    }

    state parse_packet {
        transition parse_ethernet;
    }

    state parse_ethernet {
        pkt.extract(hdr.ethernet);
        transition select(hdr.ethernet.ether_type, ig_intr_md.ingress_port) {
            (ETHERTYPE_IPV4, _) : parse_ipv4;
            (ETHERTYPE_ARP, _) : parse_arp;
            (ETHERTYPE_IPV6, _) : parse_ipv6;
            (ETHERTYPE_VLAN, _) : parse_vlan;
            (ETHERTYPE_QINQ, _) : parse_vlan;
            (ETHERTYPE_FCOE, _) : parse_fcoe;
            cpu_port  : parse_cpu;
            default : accept;
        }
    }

    state parse_cpu {
        pkt.extract(hdr.fabric);
        pkt.extract(hdr.cpu);
        ig_md.bypass = hdr.cpu.reason_code;
        ig_md.flags.capture_ts = (bool) hdr.cpu.capture_ts;
        transition select(hdr.cpu.ether_type) {
            ETHERTYPE_IPV4 : parse_ipv4;
            ETHERTYPE_IPV6 : parse_ipv6;
            ETHERTYPE_VLAN : parse_vlan;
            ETHERTYPE_QINQ : parse_vlan;
            default : accept;
        }
    }

    state parse_ipv4 {
        pkt.extract(hdr.ipv4);
        ipv4_checksum.add(hdr.ipv4);
        transition select(hdr.ipv4.ihl) {
            5 : parse_ipv4_no_options;
            6 : parse_ipv4_options;
            default : accept;
        }
    }

    state parse_ipv4_options {
        // Only a single 32-bit option (e.g. router alert) is supported.
        pkt.extract(hdr.ipv4_option);
        ipv4_checksum.add(hdr.ipv4_option);
        transition parse_ipv4_no_options;
    }

    state parse_ipv4_no_options {
        ig_md.flags.ipv4_checksum_err = ipv4_checksum.verify();
        transition select(hdr.ipv4.protocol, hdr.ipv4.frag_offset) {
            (IP_PROTOCOLS_ICMP, 0) : parse_icmp;
            (IP_PROTOCOLS_IGMP, 0) : parse_igmp;
            (IP_PROTOCOLS_TCP, 0) : parse_tcp;
            (IP_PROTOCOLS_UDP, 0) : parse_udp;
            (IP_PROTOCOLS_IPV4, 0) : parse_ipinip;
            (IP_PROTOCOLS_IPV6, 0) : parse_ipv6inip;
            // Do NOT parse the next header if IP packet is fragmented.
            default : accept;
        }
    }

    state parse_arp {
        pkt.extract(hdr.arp);
        transition accept;
    }

    state parse_vlan {
        pkt.extract(hdr.vlan_tag.next);
        transition select(hdr.vlan_tag.last.ether_type) {
            ETHERTYPE_ARP : parse_arp;
            ETHERTYPE_IPV4 : parse_ipv4;
            ETHERTYPE_VLAN : parse_vlan;
            ETHERTYPE_IPV6 : parse_ipv6;
            default : accept;
        }
    }

    state parse_ipv6 {
#ifdef IPV6_ENABLE
        pkt.extract(hdr.ipv6);
        transition select(hdr.ipv6.next_hdr) {
            IP_PROTOCOLS_ICMPV6 : parse_icmp;
            IP_PROTOCOLS_TCP : parse_tcp;
            IP_PROTOCOLS_UDP : parse_udp;
            IP_PROTOCOLS_IPV4 : parse_ipinip;
            IP_PROTOCOLS_IPV6 : parse_ipv6inip;
            default : accept;
        }
#else
        transition accept;
#endif
    }

    state parse_udp {
        pkt.extract(hdr.udp);
        transition select(hdr.udp.dst_port) {
            udp_port_vxlan : parse_vxlan;
            UDP_PORT_ROCEV2 : parse_rocev2;
	        default : accept;
	    }
    }

    state parse_tcp {
        pkt.extract(hdr.tcp);
        transition accept;
    }

    state parse_icmp {
        pkt.extract(hdr.icmp);
        transition accept;
    }

    state parse_igmp {
        pkt.extract(hdr.igmp);
        transition accept;
    }

    state parse_rocev2 {
#ifdef ROCEV2_ACL_ENABLE
        pkt.extract(hdr.rocev2_bth);
#else
        transition accept;
#endif
    }

    state parse_fcoe {
#ifdef FCOE_ACL_ENABLE
        pkt.extract(hdr.fcoe_fc);
#else
        transition accept;
#endif
    }

    state parse_vxlan {
#ifdef VXLAN_ENABLE
        pkt.extract(hdr.vxlan);
        ig_md.tunnel.type = SWITCH_TUNNEL_TYPE_VXLAN;
        ig_md.tunnel.id = hdr.vxlan.vni;
        transition parse_inner_ethernet;
#else
        transition accept;
#endif
    }

    state parse_ipinip {
#ifdef IPINIP_ENABLE
        ig_md.tunnel.type = SWITCH_TUNNEL_TYPE_IPINIP;
        transition parse_inner_ipv4;
#else
        transition accept;
#endif
    }

    state parse_ipv6inip {
#if defined(IPINIP_ENABLE) && defined(IPV6_TUNNEL_ENABLE)
        ig_md.tunnel.type = SWITCH_TUNNEL_TYPE_IPINIP;
        transition parse_inner_ipv6;
#else
        transition accept;
#endif
    }

    state parse_inner_ethernet {
        pkt.extract(hdr.inner_ethernet);
        transition select(hdr.inner_ethernet.ether_type) {
            ETHERTYPE_IPV4 : parse_inner_ipv4;
            ETHERTYPE_IPV6 : parse_inner_ipv6;
            default : accept;
        }
    }

    state parse_inner_ipv4 {
        pkt.extract(hdr.inner_ipv4);
        inner_ipv4_checksum.add(hdr.inner_ipv4);
        ig_md.flags.inner_ipv4_checksum_err = inner_ipv4_checksum.verify();
        transition select(hdr.inner_ipv4.protocol) {
            IP_PROTOCOLS_ICMP : parse_inner_icmp;
            IP_PROTOCOLS_TCP : parse_inner_tcp;
            IP_PROTOCOLS_UDP : parse_inner_udp;
            default : accept;
        }
    }

    state parse_inner_ipv6 {
#ifdef IPV6_TUNNEL_ENABLE
        pkt.extract(hdr.inner_ipv6);
        transition select(hdr.inner_ipv6.next_hdr) {
            IP_PROTOCOLS_ICMPV6 : parse_inner_icmp;
            IP_PROTOCOLS_TCP : parse_inner_tcp;
            IP_PROTOCOLS_UDP : parse_inner_udp;
            default : accept;
        }
#else
        transition accept;
#endif
    }

    state parse_inner_udp {
        pkt.extract(hdr.inner_udp);
        transition accept;
    }

    state parse_inner_tcp {
        pkt.extract(hdr.inner_tcp);
        transition accept;
    }

    state parse_inner_icmp {
        pkt.extract(hdr.inner_icmp);
        transition accept;
    }

}

//----------------------------------------------------------------------------
// Egress parser
//----------------------------------------------------------------------------
parser SwitchEgressParser(
        packet_in pkt,
        out switch_header_t hdr,
        out switch_egress_metadata_t eg_md,
        out egress_intrinsic_metadata_t eg_intr_md) {

    value_set<bit<16>>(1) udp_port_vxlan;
    value_set<switch_cpu_port_value_set_t>(1) cpu_port;

    @critical
    state start {
        pkt.extract(eg_intr_md);
        eg_md.pkt_length = eg_intr_md.pkt_length;
        eg_md.port = eg_intr_md.egress_port;
        eg_md.qos.qdepth = eg_intr_md.enq_qdepth;

#ifdef MIRROR_ENABLE
        switch_port_mirror_metadata_h mirror_md = pkt.lookahead<switch_port_mirror_metadata_h>();
        transition select(eg_intr_md.deflection_flag, mirror_md.src, mirror_md.type) {
            (1, _, _) : parse_deflected_pkt;
            (_, SWITCH_PKT_SRC_BRIDGED, _) : parse_bridged_pkt;
            (_, _, SWITCH_MIRROR_TYPE_PORT) : parse_port_mirrored_metadata;
            (_, SWITCH_PKT_SRC_CLONED_EGRESS, SWITCH_MIRROR_TYPE_CPU) : parse_cpu_mirrored_metadata;
            (_, _, SWITCH_MIRROR_TYPE_DTEL_DROP) : parse_dtel_drop_metadata;
            (_, _, SWITCH_MIRROR_TYPE_DTEL_SWITCH_LOCAL) : parse_dtel_switch_local_metadata;
        }
#else
        transition parse_bridged_pkt;
#endif
    }

    state parse_bridged_pkt {
        pkt.extract(hdr.bridged_md);
        eg_md.pkt_src = SWITCH_PKT_SRC_BRIDGED;
        eg_md.ingress_port = hdr.bridged_md.base.ingress_port;
        eg_md.ingress_ifindex = hdr.bridged_md.base.ingress_ifindex;
        eg_md.bd = hdr.bridged_md.base.ingress_bd;
        eg_md.nexthop = hdr.bridged_md.base.nexthop;
        eg_md.cpu_reason = hdr.bridged_md.base.cpu_reason;
        eg_md.flags.routed = hdr.bridged_md.base.routed;
        eg_md.flags.peer_link = hdr.bridged_md.base.peer_link;
//      eg_md.flags.capture_ts = hdr.bridged_md.base.capture_ts;
        eg_md.pkt_type = hdr.bridged_md.base.pkt_type;
        eg_md.ingress_timestamp = hdr.bridged_md.base.timestamp;
        eg_md.qos.tc = hdr.bridged_md.base.tc;
        eg_md.qos.qid = hdr.bridged_md.base.qid;
        eg_md.qos.color = hdr.bridged_md.base.color;

#if defined(EGRESS_IP_ACL_ENABLE) || defined(EGRESS_MIRROR_ACL_ENABLE)
        eg_md.l4_port_label = hdr.bridged_md.acl.l4_port_label;
        eg_md.lkp.l4_src_port = hdr.bridged_md.acl.l4_src_port;
        eg_md.lkp.l4_dst_port = hdr.bridged_md.acl.l4_dst_port;
        eg_md.lkp.tcp_flags = hdr.bridged_md.acl.tcp_flags;
#endif
#ifdef TUNNEL_ENABLE
        eg_md.outer_nexthop = hdr.bridged_md.tunnel.outer_nexthop;
        eg_md.tunnel.index = hdr.bridged_md.tunnel.index;
        eg_md.tunnel.hash = hdr.bridged_md.tunnel.hash;
        eg_md.vrf = hdr.bridged_md.tunnel.vrf;
        eg_md.tunnel.terminate = hdr.bridged_md.tunnel.terminate;
#endif
#ifdef DTEL_ENABLE
        eg_md.dtel.report_type = hdr.bridged_md.dtel.report_type;
        eg_md.dtel.hash = hdr.bridged_md.dtel.hash;
        eg_md.dtel.session_id = hdr.bridged_md.dtel.session_id;
#endif

        transition parse_ethernet;
    }

    state parse_deflected_pkt {
#ifdef DTEL_ENABLE
        pkt.extract(hdr.bridged_md);
        eg_md.pkt_src = SWITCH_PKT_SRC_DEFLECTED;
        eg_md.dtel.report_type = hdr.bridged_md.dtel.report_type;
        eg_md.dtel.hash = hdr.bridged_md.dtel.hash;
        // Initialize eg_md.dtel.session_id to prevent it from being marked @pa_no_init.
        eg_md.dtel.session_id = 0;
        eg_md.mirror.session_id = hdr.bridged_md.dtel.session_id;
        eg_md.ingress_timestamp = hdr.bridged_md.base.timestamp;
        eg_md.qos.qid = hdr.bridged_md.base.qid;
        hdr.dtel_drop_report = {
            0,
            hdr.bridged_md.base.ingress_port,
            0,
            hdr.bridged_md.dtel.egress_port,
            0,
            hdr.bridged_md.base.qid,
            SWITCH_DROP_REASON_TRAFFIC_MANAGER,
            0};
        transition accept;
#endif
    }

    state parse_port_mirrored_metadata {
        switch_port_mirror_metadata_h port_md;
        pkt.extract(port_md);
        pkt.extract(hdr.ethernet);
        eg_md.pkt_src = port_md.src;
        eg_md.mirror.session_id = port_md.session_id;
        eg_md.ingress_timestamp = port_md.timestamp;
        eg_md.bypass = ~SWITCH_EGRESS_BYPASS_MTU;
#ifdef PACKET_LENGTH_ADJUSTMENT
        eg_md.mirror.type = port_md.type;
#endif
#ifdef DTEL_ENABLE
        // Initialize eg_md.dtel.session_id to prevent it from being marked @pa_no_init.
        eg_md.dtel.session_id = 0;
#endif
        transition accept;
    }

    state parse_cpu_mirrored_metadata {
        switch_cpu_mirror_metadata_h cpu_md;
        pkt.extract(cpu_md);
        pkt.extract(hdr.ethernet);
        eg_md.pkt_src = cpu_md.src;
        eg_md.bypass = ~SWITCH_EGRESS_BYPASS_MTU;
        eg_md.bd = cpu_md.bd;
        // eg_md.ingress_port = cpu_md.md.port;
        // eg_md.ingress_ifindex = cpu_md.md.ifindex;
        eg_md.cpu_reason = cpu_md.reason_code;
#ifdef PACKET_LENGTH_ADJUSTMENT
        eg_md.mirror.type = cpu_md.type;
#endif
#ifdef DTEL_ENABLE
        // Initialize eg_md.dtel.session_id to prevent it from being marked @pa_no_init.
        eg_md.dtel.session_id = 0;
#endif
        transition accept;
    }

    state parse_dtel_drop_metadata {
#ifdef DTEL_ENABLE
        switch_dtel_drop_mirror_metadata_h dtel_md;
        pkt.extract(dtel_md);
        eg_md.pkt_src = dtel_md.src;
        eg_md.mirror.type = dtel_md.type;
        eg_md.dtel.report_type = dtel_md.report_type;
        eg_md.dtel.hash = dtel_md.hash;
        // Initialize eg_md.dtel.session_id to prevent it from being marked @pa_no_init.
        eg_md.dtel.session_id = 0;
        eg_md.mirror.session_id = dtel_md.session_id;
        eg_md.ingress_timestamp = dtel_md.timestamp;
        hdr.dtel_drop_report = {
            0,
            dtel_md.ingress_port,
            0,
            SWITCH_PORT_INVALID,
            0,
            dtel_md.qid,
            dtel_md.drop_reason,
            0};
        transition accept;
#else
        transition reject;
#endif
    }

    state parse_dtel_switch_local_metadata {
#ifdef DTEL_ENABLE
        switch_dtel_switch_local_mirror_metadata_h dtel_md;
        pkt.extract(dtel_md);
        eg_md.pkt_src = dtel_md.src;
        eg_md.mirror.type = dtel_md.type;
        eg_md.dtel.report_type = dtel_md.report_type;
        eg_md.dtel.hash = dtel_md.hash;
        // Initialize eg_md.dtel.session_id to prevent it from being marked @pa_no_init.
        eg_md.dtel.session_id = 0;
        eg_md.mirror.session_id = dtel_md.session_id;
        eg_md.ingress_timestamp = dtel_md.timestamp;
        hdr.dtel_switch_local_report = {
            0,
            dtel_md.ingress_port,
            0,
            dtel_md.egress_port,
            0,
            dtel_md.qid,
            0,
            dtel_md.qdepth,
            dtel_md.egress_timestamp};
        transition accept;
#else
        transition reject;
#endif
    }


    state parse_packet {
        transition parse_ethernet;
    }

    state parse_ethernet {
        pkt.extract(hdr.ethernet);
        transition select(hdr.ethernet.ether_type, eg_intr_md.egress_port) {
            cpu_port : parse_cpu;
            (ETHERTYPE_IPV4, _) : parse_ipv4;
            (ETHERTYPE_IPV6, _) : parse_ipv6;
            (ETHERTYPE_VLAN, _) : parse_vlan;
            (ETHERTYPE_QINQ, _) : parse_vlan;
            default : accept;
        }
    }

    state parse_cpu {
        eg_md.bypass = SWITCH_EGRESS_BYPASS_ALL;
        transition accept;
    }

    state parse_ipv4 {
        pkt.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol, hdr.ipv4.ihl, hdr.ipv4.frag_offset) {
#ifdef TUNNEL_ENABLE
            (IP_PROTOCOLS_UDP, 5, 0) : parse_udp;
#ifdef IPINIP_ENABLE
            (IP_PROTOCOLS_IPV4, 5, 0) : parse_inner_ipv4;
            (IP_PROTOCOLS_IPV6, 5, 0) : parse_inner_ipv6;
#endif
#endif
            (_, 6, _) : parse_ipv4_options;
            default : accept;
        }
    }

    state parse_ipv4_options {
        pkt.extract(hdr.ipv4_option);
        transition select(hdr.ipv4.protocol, hdr.ipv4.frag_offset) {
#ifdef TUNNEL_ENABLE
            (IP_PROTOCOLS_UDP, 0) : parse_udp;
#ifdef IPINIP_ENABLE
            (IP_PROTOCOLS_IPV4, 0) : parse_inner_ipv4;
            (IP_PROTOCOLS_IPV6, 0) : parse_inner_ipv6;
#endif
#endif
            default : accept;
        }
    }

    state parse_vlan {
        pkt.extract(hdr.vlan_tag.next);
        transition select(hdr.vlan_tag.last.ether_type) {
            ETHERTYPE_IPV4 : parse_ipv4;
            ETHERTYPE_VLAN : parse_vlan;
            ETHERTYPE_IPV6 : parse_ipv6;
            default : accept;
        }
    }

    state parse_ipv6 {
#ifdef IPV6_ENABLE
        pkt.extract(hdr.ipv6);
        transition select(hdr.ipv6.next_hdr) {
#ifdef IPV6_TUNNEL_ENABLE
            // IP_PROTOCOLS_TCP : parse_tcp;
            IP_PROTOCOLS_UDP : parse_udp;
#ifdef IPINIP_ENABLE
            IP_PROTOCOLS_IPV4 : parse_inner_ipv4;
            IP_PROTOCOLS_IPV6 : parse_inner_ipv6;
#endif /* IPINIP_ENABLE */
#endif /* IPV6_TUNNEL_ENABLE */
            default : accept;
        }
#else
        transition accept;
#endif /* IPV6_ENABLE */
    }

    state parse_udp {
        pkt.extract(hdr.udp);
        transition select(hdr.udp.dst_port) {
          udp_port_vxlan : parse_vxlan;
	        default : accept;
	    }
    }

    state parse_tcp {
        pkt.extract(hdr.tcp);
        transition accept;
    }

    state parse_vxlan {
#ifdef VXLAN_ENABLE
        pkt.extract(hdr.vxlan);
        transition parse_inner_ethernet;
#else
        transition accept;
#endif
    }

    state parse_inner_ethernet {
        pkt.extract(hdr.inner_ethernet);
        transition select(hdr.inner_ethernet.ether_type) {
            ETHERTYPE_IPV4 : parse_inner_ipv4;
            ETHERTYPE_IPV6 : parse_inner_ipv6;
            default : accept;
        }
    }

    state parse_inner_ipv4 {
        pkt.extract(hdr.inner_ipv4);
        transition select(hdr.inner_ipv4.protocol) {
            // IP_PROTOCOLS_TCP : parse_inner_tcp;
            IP_PROTOCOLS_UDP : parse_inner_udp;
            default : accept;
        }
    }

    state parse_inner_ipv6 {
#ifdef IPV6_TUNNEL_ENABLE
        pkt.extract(hdr.inner_ipv6);
        transition select(hdr.inner_ipv6.next_hdr) {
            // IP_PROTOCOLS_TCP : parse_inner_tcp;
            IP_PROTOCOLS_UDP : parse_inner_udp;
            default : accept;
        }
#else
        transition accept;
#endif
    }

    state parse_inner_udp {
        pkt.extract(hdr.inner_udp);
        transition accept;
    }

    state parse_inner_tcp {
        pkt.extract(hdr.inner_tcp);
        transition accept;
    }

    state parse_inner_icmp {
        pkt.extract(hdr.inner_icmp);
        transition accept;
    }
}


//----------------------------------------------------------------------------
// Mirror packet deparser
//-----------------------------------------------------------------------------
control IngressMirror(
    inout switch_header_t hdr,
    in switch_ingress_metadata_t ig_md,
    in ingress_intrinsic_metadata_for_deparser_t ig_intr_md_for_dprsr) {
// Ingress deparser create a copy of the original ingress packet and prepend the prepend the mirror
// header.
    Mirror() mirror;

    apply {
#ifdef MIRROR_ENABLE
        if (ig_intr_md_for_dprsr.mirror_type == SWITCH_MIRROR_TYPE_PORT) {
            mirror.emit<switch_port_mirror_metadata_h>(
                ig_md.mirror.session_id,
                {ig_md.mirror.src,
                 ig_md.mirror.type,
                 ig_md.timestamp,
#if __TARGET_TOFINO__ == 1
                 0,
#endif
                 ig_md.mirror.session_id});

        } else if (ig_intr_md_for_dprsr.mirror_type == SWITCH_MIRROR_TYPE_DTEL_DROP) {
#ifdef DTEL_ENABLE
            mirror.emit<switch_dtel_drop_mirror_metadata_h>(ig_md.dtel.session_id, {
                ig_md.mirror.src,
                ig_md.mirror.type,
                ig_md.timestamp,
#if __TARGET_TOFINO__ == 1
                 0,
#endif
                ig_md.dtel.session_id,
                ig_md.hash,
                0,
                ig_md.dtel.report_type,
                0,
                ig_md.port,
                0,
                ig_md.egress_port,
                0,
                ig_md.qos.qid,
                ig_md.drop_reason
            });

#endif /* DTEL_ENABLE */
        }
#endif /* MIRROR_ENABLE */
    }
}

control EgressMirror(
    inout switch_header_t hdr,
    in switch_egress_metadata_t eg_md,
    in egress_intrinsic_metadata_for_deparser_t eg_intr_md_for_dprsr) {
// Egress deparser first construct the output packet and then prepend the mirror header.
    Mirror() mirror;

    apply {
#ifdef MIRROR_ENABLE
        if (eg_intr_md_for_dprsr.mirror_type == SWITCH_MIRROR_TYPE_PORT) {
            mirror.emit<switch_port_mirror_metadata_h>(eg_md.mirror.session_id, {
                eg_md.mirror.src,
                eg_md.mirror.type,
                eg_md.ingress_timestamp,
#if __TARGET_TOFINO__ == 1
                0,
#endif
                eg_md.mirror.session_id});
        } else if (eg_intr_md_for_dprsr.mirror_type == SWITCH_MIRROR_TYPE_CPU) {
            mirror.emit<switch_cpu_mirror_metadata_h>(eg_md.mirror.session_id, {
                eg_md.mirror.src,
                eg_md.mirror.type,
                0,
                eg_md.ingress_port,
                eg_md.bd,
                eg_md.ingress_ifindex,
                eg_md.cpu_reason});
        } else if (eg_intr_md_for_dprsr.mirror_type == SWITCH_MIRROR_TYPE_DTEL_SWITCH_LOCAL) {
#ifdef DTEL_ENABLE
            mirror.emit<switch_dtel_switch_local_mirror_metadata_h>(eg_md.dtel.session_id, {
                eg_md.mirror.src, eg_md.mirror.type,
                eg_md.ingress_timestamp,
#if __TARGET_TOFINO__ == 1
                0,
#endif
                eg_md.dtel.session_id,
                eg_md.dtel.hash,
                0,
                eg_md.dtel.report_type,
                0,
                eg_md.ingress_port,
                0,
                eg_md.port,
                0,
                eg_md.qos.qid,
                0,
                eg_md.qos.qdepth,
                eg_md.timestamp[31:0]
            });
#endif /* DTEL_ENABLE */
        }
#endif /* MIRROR_ENABLE */
    }
}

//-----------------------------------------------------------------------------
// Ingress Deparser
//-----------------------------------------------------------------------------
control SwitchIngressDeparser(
    packet_out pkt,
    inout switch_header_t hdr,
    in switch_ingress_metadata_t ig_md,
    in ingress_intrinsic_metadata_for_deparser_t ig_intr_md_for_dprsr) {

    IngressMirror() mirror;
    Digest<switch_learning_digest_t>() digest;

    apply {
        mirror.apply(hdr, ig_md, ig_intr_md_for_dprsr);

        if (ig_intr_md_for_dprsr.digest_type == SWITCH_DIGEST_TYPE_MAC_LEARNING) {
            digest.pack({ig_md.bd, ig_md.ifindex, ig_md.lkp.mac_src_addr});
        }

        pkt.emit(hdr.bridged_md); // Ingress only.
        pkt.emit(hdr.ethernet);
        pkt.emit(hdr.vlan_tag);
        pkt.emit(hdr.arp); // Ingress only.
        pkt.emit(hdr.ipv4);
        pkt.emit(hdr.ipv4_option);
        pkt.emit(hdr.ipv6);
        pkt.emit(hdr.udp);
        pkt.emit(hdr.tcp); // Ingress only.
        pkt.emit(hdr.icmp); // Ingress only.
        pkt.emit(hdr.igmp); // Ingress only.
        pkt.emit(hdr.rocev2_bth); // Ingress only.
        pkt.emit(hdr.vxlan);
        pkt.emit(hdr.inner_ethernet);
        pkt.emit(hdr.inner_ipv4);
        pkt.emit(hdr.inner_ipv6);
        pkt.emit(hdr.inner_udp);
        pkt.emit(hdr.inner_tcp);
        pkt.emit(hdr.inner_icmp);
    }
}


//-----------------------------------------------------------------------------
// Egress Deparser
//-----------------------------------------------------------------------------
control SwitchEgressDeparser(
        packet_out pkt,
        inout switch_header_t hdr,
        in switch_egress_metadata_t eg_md,
        in egress_intrinsic_metadata_for_deparser_t eg_intr_md_for_dprsr) {

    EgressMirror() mirror;
    Checksum() ipv4_checksum;
    Checksum() inner_ipv4_checksum;

    apply {
        mirror.apply(hdr, eg_md, eg_intr_md_for_dprsr);

        if (hdr.ipv4_option.isValid()) {
            hdr.ipv4.hdr_checksum = ipv4_checksum.update({
                hdr.ipv4.version,
                hdr.ipv4.ihl,
                hdr.ipv4.diffserv,
                hdr.ipv4.total_len,
                hdr.ipv4.identification,
                hdr.ipv4.flags,
                hdr.ipv4.frag_offset,
                hdr.ipv4.ttl,
                hdr.ipv4.protocol,
                hdr.ipv4.src_addr,
                hdr.ipv4.dst_addr,
                hdr.ipv4_option.type,
                hdr.ipv4_option.length,
                hdr.ipv4_option.value});
        } else if (hdr.ipv4.isValid()) {
            hdr.ipv4.hdr_checksum = ipv4_checksum.update({
                hdr.ipv4.version,
                hdr.ipv4.ihl,
                hdr.ipv4.diffserv,
                hdr.ipv4.total_len,
                hdr.ipv4.identification,
                hdr.ipv4.flags,
                hdr.ipv4.frag_offset,
                hdr.ipv4.ttl,
                hdr.ipv4.protocol,
                hdr.ipv4.src_addr,
                hdr.ipv4.dst_addr});
        }

#ifdef TUNNEL_ENABLE
        hdr.inner_ipv4.hdr_checksum = inner_ipv4_checksum.update({
            hdr.inner_ipv4.version,
            hdr.inner_ipv4.ihl,
            hdr.inner_ipv4.diffserv,
            hdr.inner_ipv4.total_len,
            hdr.inner_ipv4.identification,
            hdr.inner_ipv4.flags,
            hdr.inner_ipv4.frag_offset,
            hdr.inner_ipv4.ttl,
            hdr.inner_ipv4.protocol,
            hdr.inner_ipv4.src_addr,
            hdr.inner_ipv4.dst_addr});
#endif

        pkt.emit(hdr.ethernet);
        pkt.emit(hdr.fabric); // Egress only.
        pkt.emit(hdr.cpu); // Egress only.
        pkt.emit(hdr.timestamp); // Egress only.
        pkt.emit(hdr.vlan_tag);
        pkt.emit(hdr.ipv4);
        pkt.emit(hdr.ipv6);
        pkt.emit(hdr.udp);
        pkt.emit(hdr.dtel); // Egress only.
        pkt.emit(hdr.dtel_switch_local_report); // Egress only.
        pkt.emit(hdr.dtel_drop_report); // Egress only.
        pkt.emit(hdr.vxlan);
        pkt.emit(hdr.gre); // Egress only.
        pkt.emit(hdr.erspan_type2); // Egress only.
        pkt.emit(hdr.erspan_type3); // Egress only.
        pkt.emit(hdr.erspan_platform); // Egress only.
        pkt.emit(hdr.inner_ethernet);
        pkt.emit(hdr.inner_ipv4);
        pkt.emit(hdr.inner_ipv6);
        pkt.emit(hdr.inner_udp);
    }
}
