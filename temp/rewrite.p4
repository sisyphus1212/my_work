
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

#ifndef _P4_REWRITE_
#define  _P4_REWRITE_

#include "l2.p4"

//-----------------------------------------------------------------------------
// @param hdr : Parsed headers. For mirrored packet only Ethernet header is parsed.
// @param eg_md : Egress metadata fields.
// @param table_size : Number of mirror sessions.
//
// @flags PACKET_LENGTH_ADJUSTMENT : For mirrored packet, the length of the mirrored
// metadata fields is also accounted in the packet length. This flags enables the
// calculation of the packet length excluding the mirrored metadata fields.
//-----------------------------------------------------------------------------
control MirrorRewrite(inout switch_header_t hdr,
                      inout switch_egress_metadata_t eg_md)(
                      switch_uint32_t table_size=1024) {
    bit<16> length;

    action add_ethernet_header(in mac_addr_t src_addr,
                               in mac_addr_t dst_addr,
                               in bit<16> ether_type) {
        hdr.ethernet.setValid();
        hdr.ethernet.ether_type = ether_type;
        hdr.ethernet.src_addr = src_addr;
        hdr.ethernet.dst_addr = dst_addr;
    }

    action add_vlan_tag(vlan_id_t vid, bit<3> pcp, bit<16> ether_type) {
        hdr.vlan_tag[0].setValid();
        hdr.vlan_tag[0].pcp = pcp;
        // hdr.vlan_tag[0].cfi = 0;
        hdr.vlan_tag[0].vid = vid;
        hdr.vlan_tag[0].ether_type = ether_type;
    }

    action add_ipv4_header(in bit<8> diffserv,
                           in bit<8> ttl,
                           in bit<8> protocol,
                           in ipv4_addr_t src_addr,
                           in ipv4_addr_t dst_addr) {
        hdr.ipv4.setValid();
        hdr.ipv4.version = 4w4;
        hdr.ipv4.ihl = 4w5;
        hdr.ipv4.diffserv = diffserv;
        // hdr.ipv4.total_len = 0;
        hdr.ipv4.identification = 0;
        hdr.ipv4.flags = 0;
        hdr.ipv4.frag_offset = 0;
        hdr.ipv4.ttl = ttl;
        hdr.ipv4.protocol = protocol;
        hdr.ipv4.src_addr = src_addr;
        hdr.ipv4.dst_addr = dst_addr;
    }

    action add_gre_header(in bit<16> proto) {
        hdr.gre.setValid();
        // hdr.gre.C = 0;
        // hdr.gre.K = 0;
        // hdr.gre.S = 0;
        // hdr.gre.s = 0;
        // hdr.gre.recurse = 0;
        hdr.gre.flags = 0;
        hdr.gre.version = 0;
        hdr.gre.proto = proto;
    }

    action add_erspan_type2(bit<10> session_id) {
        //TODO(msharif): Support for GRE sequence number.
        hdr.erspan_type2.setValid();
        hdr.erspan_type2.version = 4w0x1;
        hdr.erspan_type2.vlan = 0;
        hdr.erspan_type2.cos_en_t = 0;
        hdr.erspan_type2.session_id = session_id;
    }

    action add_erspan_type3(bit<10> session_id, bit<32> timestamp, bool opt_sub_header) {
        hdr.erspan_type3.setValid();
        hdr.erspan_type3.version = 4w0x2;
        hdr.erspan_type3.vlan = 0;
        hdr.erspan_type3.cos_bso_t = 0;
        hdr.erspan_type3.session_id = session_id;
        hdr.erspan_type3.timestamp = timestamp;
        hdr.erspan_type3.sgt = 0;
        hdr.erspan_type3.p = 0;
        hdr.erspan_type3.ft = 0; // Ethernet frame
        hdr.erspan_type3.hw_id = 0;
        //TODO(msharif): Set direction flag if EGRESS_PORT_MIRRORING is enabled.
        hdr.erspan_type3.d = 0;
        hdr.erspan_type3.gra = 0b10;
        if (opt_sub_header) {
            hdr.erspan_type3.o = 1;
            hdr.erspan_platform.setValid();
            hdr.erspan_platform.id = 0;
            hdr.erspan_platform.info = 0;
        } else {
            hdr.erspan_type3.o = 0;
        }
    }

    action rewrite_(switch_qid_t qid) {
        eg_md.qos.qid = qid;
    }

    action rewrite_rspan(switch_qid_t qid, bit<3> pcp, vlan_id_t vid) {
#ifdef RSPAN_ENABLE
        eg_md.qos.qid = qid;
        add_vlan_tag(vid, pcp, hdr.ethernet.ether_type);
        hdr.ethernet.ether_type = ETHERTYPE_VLAN;
#endif
    }

    action rewrite_erspan_type2(
            switch_qid_t qid,
            mac_addr_t smac, mac_addr_t dmac,
            ipv4_addr_t sip, ipv4_addr_t dip, bit<8> tos, bit<8> ttl) {
        //TODO(msharif): Support for GRE sequence number.
#ifdef ERSPAN_TYPE2_ENABLE
        eg_md.qos.qid = qid;
        add_erspan_type2((bit<10>)eg_md.mirror.session_id);
        add_gre_header(GRE_PROTOCOLS_ERSPAN_TYPE_2);

        // Total length = packet length + 32
        //   IPv4 (20) + GRE (4) + Erspan (8)
        add_ipv4_header(tos, ttl, IP_PROTOCOLS_GRE, sip, dip);
#ifdef PACKET_LENGTH_ADJUSTMENT
        hdr.ipv4.total_len = eg_md.pkt_length + 16w32;
#else
        hdr.ipv4.total_len = eg_md.pkt_length + 16w18;
#endif

        hdr.inner_ethernet = hdr.ethernet;
        add_ethernet_header(smac, dmac, ETHERTYPE_IPV4);
#endif
    }

    action rewrite_erspan_type2_with_vlan(
            switch_qid_t qid,
            bit<16> ether_type, mac_addr_t smac, mac_addr_t dmac,
            bit<3> pcp, vlan_id_t vid,
            ipv4_addr_t sip, ipv4_addr_t dip, bit<8> tos, bit<8> ttl) {
#ifdef ERSPAN_TYPE2_ENABLE
        eg_md.qos.qid = qid;
        add_erspan_type2((bit<10>) eg_md.mirror.session_id);
        add_gre_header(GRE_PROTOCOLS_ERSPAN_TYPE_2);

        // Total length = packet length + 32
        //   IPv4 (20) + GRE (4) + Erspan (8)
        add_ipv4_header(tos, ttl, IP_PROTOCOLS_GRE, sip, dip);
#ifdef PACKET_LENGTH_ADJUSTMENT
        hdr.ipv4.total_len = eg_md.pkt_length + 16w32;
#else
        hdr.ipv4.total_len = eg_md.pkt_length + 16w18;
#endif
        hdr.inner_ethernet = hdr.ethernet;
        add_ethernet_header(smac, dmac, ether_type);
        add_vlan_tag(vid, pcp, ETHERTYPE_IPV4);
#endif
    }

    action rewrite_erspan_type3(
            switch_qid_t qid,
            mac_addr_t smac, mac_addr_t dmac,
            ipv4_addr_t sip, ipv4_addr_t dip, bit<8> tos, bit<8> ttl) {
#ifdef ERSPAN_ENABLE
        eg_md.qos.qid = qid;
        add_erspan_type3((bit<10>)eg_md.mirror.session_id, (bit<32>)eg_md.ingress_timestamp, false);
        add_gre_header(GRE_PROTOCOLS_ERSPAN_TYPE_3);

        // Total length = packet length + 36
        //   IPv4 (20) + GRE (4) + Erspan (12)
        add_ipv4_header(tos, ttl, IP_PROTOCOLS_GRE, sip, dip);
#ifdef PACKET_LENGTH_ADJUSTMENT
        hdr.ipv4.total_len = eg_md.pkt_length + 16w36;
#else
        hdr.ipv4.total_len = eg_md.pkt_length + 16w22;
#endif

        hdr.inner_ethernet = hdr.ethernet;
        add_ethernet_header(smac, dmac, ETHERTYPE_IPV4);
#endif /* ERSPAN_ENABLE */
    }

    action rewrite_erspan_type3_with_vlan(
            switch_qid_t qid,
            bit<16> ether_type, mac_addr_t smac, mac_addr_t dmac,
            bit<3> pcp, vlan_id_t vid,
            ipv4_addr_t sip, ipv4_addr_t dip, bit<8> tos, bit<8> ttl) {
#ifdef ERSPAN_ENABLE
        eg_md.qos.qid = qid;
        add_erspan_type3((bit<10>)eg_md.mirror.session_id, (bit<32>)eg_md.ingress_timestamp, false);
        add_gre_header(GRE_PROTOCOLS_ERSPAN_TYPE_3);

        // Total length = packet length + 36
        //   IPv4 (20) + GRE (4) + Erspan (12)
        add_ipv4_header(tos, ttl, IP_PROTOCOLS_GRE, sip, dip);
#ifdef PACKET_LENGTH_ADJUSTMENT
        hdr.ipv4.total_len = eg_md.pkt_length + 16w36;
#else
        hdr.ipv4.total_len = eg_md.pkt_length + 16w22;
#endif
        hdr.inner_ethernet = hdr.ethernet;
        add_ethernet_header(smac, dmac, ether_type);
        add_vlan_tag(vid, pcp, ETHERTYPE_IPV4);
#endif /* ERSPAN_ENABLE */
    }

    action rewrite_erspan_type3_platform_specific(
            switch_qid_t qid,
            mac_addr_t smac, mac_addr_t dmac,
            ipv4_addr_t sip, ipv4_addr_t dip, bit<8> tos, bit<8> ttl) {
#ifdef ERSPAN_ENABLE
        eg_md.qos.qid = qid;
        add_erspan_type3((bit<10>)eg_md.mirror.session_id, (bit<32>)eg_md.ingress_timestamp, true);
        add_gre_header(GRE_PROTOCOLS_ERSPAN_TYPE_3);

        // Total length = packet length + 44
        //   IPv4 (20) + GRE (4) + Erspan (12) + Platform Specific (8)
        add_ipv4_header(tos, ttl, IP_PROTOCOLS_GRE, sip, dip);
#ifdef PACKET_LENGTH_ADJUSTMENT
        hdr.ipv4.total_len = eg_md.pkt_length + 16w44;
#else
        hdr.ipv4.total_len = eg_md.pkt_length + 16w30;
#endif

        hdr.inner_ethernet = hdr.ethernet;
        add_ethernet_header(smac, dmac, ETHERTYPE_IPV4);
#endif /* ERSPAN_ENABLE */
    }

    action rewrite_erspan_type3_platform_specific_with_vlan(
            switch_qid_t qid,
            bit<16> ether_type, mac_addr_t smac, mac_addr_t dmac,
            bit<3> pcp, vlan_id_t vid,
            ipv4_addr_t sip, ipv4_addr_t dip, bit<8> tos, bit<8> ttl) {
#ifdef ERSPAN_ENABLE
        eg_md.qos.qid = qid;

        add_erspan_type3((bit<10>)eg_md.mirror.session_id, (bit<32>)eg_md.ingress_timestamp, true);
        add_gre_header(GRE_PROTOCOLS_ERSPAN_TYPE_3);

        // Total length = packet length + 44
        //   IPv4 (20) + GRE (4) + Erspan (12) + Platform Specific (8)
        add_ipv4_header(tos, ttl, IP_PROTOCOLS_GRE, sip, dip);
#ifdef PACKET_LENGTH_ADJUSTMENT
        hdr.ipv4.total_len = eg_md.pkt_length + 16w44;
#else
        hdr.ipv4.total_len = eg_md.pkt_length + 16w30;
#endif

        hdr.inner_ethernet = hdr.ethernet;
        add_ethernet_header(smac, dmac, ether_type);
        add_vlan_tag(vid, pcp, ETHERTYPE_IPV4);
#endif /* ERSPAN_ENABLE */
    }

    action rewrite_dtel_report(
            mac_addr_t smac, mac_addr_t dmac,
            ipv4_addr_t sip, ipv4_addr_t dip, bit<8> tos, bit<8> ttl,
            bit<16> udp_dst_port) {
#ifdef DTEL_ENABLE
        // Dtel report header is added later in the pipeline.
        hdr.udp.setValid();
        hdr.udp.dst_port = udp_dst_port;
        hdr.udp.checksum = 0;

        // Total length = packet length + 40
        //   IPv4 (20) + UDP (8) + DTel switch local/drop report.
        add_ipv4_header(tos, ttl, IP_PROTOCOLS_UDP, sip, dip);
#ifdef PACKET_LENGTH_ADJUSTMENT
        hdr.ipv4.total_len = eg_md.pkt_length + 16w40;
        hdr.udp.length = eg_md.pkt_length + 16w20;
#else
#error "Packet length adjustment is required for DTel"
#endif
        hdr.ipv4.flags = 2;

        add_ethernet_header(smac, dmac, ETHERTYPE_IPV4);
#endif /* DTEL_ENABLE */
    }

    action rewrite_dtel_report_with_entropy(
            mac_addr_t smac, mac_addr_t dmac,
            ipv4_addr_t sip, ipv4_addr_t dip, bit<8> tos, bit<8> ttl,
            bit<16> udp_dst_port) {
#ifdef DTEL_ENABLE
        rewrite_dtel_report(smac, dmac, sip, dip, tos, ttl, udp_dst_port);
        hdr.udp.src_port = eg_md.dtel.hash[15:0];
#endif /* DTEL_ENABLE */
    }

    action rewrite_dtel_report_without_entropy(
            mac_addr_t smac, mac_addr_t dmac,
            ipv4_addr_t sip, ipv4_addr_t dip, bit<8> tos, bit<8> ttl,
            bit<16> udp_dst_port, bit<16> udp_src_port) {
#ifdef DTEL_ENABLE
        rewrite_dtel_report(smac, dmac, sip, dip, tos, ttl, udp_dst_port);
        hdr.udp.src_port = udp_src_port;
#endif /* DTEL_ENABLE */
    }

    table rewrite {
        key = { eg_md.mirror.session_id : exact; }
        actions = {
            NoAction;
            rewrite_;
            rewrite_rspan;
            rewrite_erspan_type2;
            rewrite_erspan_type3;
            rewrite_erspan_type3_platform_specific;
            rewrite_erspan_type2_with_vlan;
            rewrite_erspan_type3_with_vlan;
            rewrite_erspan_type3_platform_specific_with_vlan;
            rewrite_dtel_report_with_entropy;
            rewrite_dtel_report_without_entropy;
        }

        const default_action = NoAction;
        size = table_size;
    }


    action adjust_length(bit<16> length_offset) {
        eg_md.pkt_length = eg_md.pkt_length + length_offset;
        eg_md.mirror.type = SWITCH_MIRROR_TYPE_INVALID;
    }

    table pkt_length {
        key = { eg_md.mirror.type : exact; }
        actions = { adjust_length; }
        const entries = {
            SWITCH_MIRROR_TYPE_PORT : adjust_length(-14); // switch_port_mirror_metadata_h + 4 bytes of CRC
            SWITCH_MIRROR_TYPE_CPU : adjust_length(-14);
#if __TARGET_TOFINO__ == 1
            SWITCH_MIRROR_TYPE_DTEL_DROP : adjust_length(-13);
            SWITCH_MIRROR_TYPE_DTEL_SWITCH_LOCAL : adjust_length(-15);
#else
            SWITCH_MIRROR_TYPE_DTEL_DROP : adjust_length(-12);
            SWITCH_MIRROR_TYPE_DTEL_SWITCH_LOCAL : adjust_length(-14);
#endif
        }
    }

    apply {
#if defined(MIRROR_ENABLE)
        if (eg_md.pkt_src != SWITCH_PKT_SRC_BRIDGED) {
#ifdef PACKET_LENGTH_ADJUSTMENT
            pkt_length.apply();
#endif
            rewrite.apply();
        }
#endif /* MIRROR_ENABLE */
    }
}

control Rewrite(inout switch_header_t hdr,
                inout switch_egress_metadata_t eg_md)(
                switch_uint32_t nexthop_table_size,
                switch_uint32_t bd_table_size) {
    EgressBd(bd_table_size) egress_bd;
    switch_smac_index_t smac_index;

    action rewrite_l2_with_tunnel(switch_tunnel_type_t type) {
#ifdef TUNNEL_ENABLE
        eg_md.flags.routed = false;
        eg_md.tunnel.type = type;
#endif
    }

    action rewrite_l3(switch_bd_t bd, mac_addr_t dmac) {
        eg_md.flags.routed = true;
        hdr.ethernet.dst_addr = dmac;
        eg_md.bd = bd;
    }

    action rewrite_l3_with_tunnel_id(
            mac_addr_t dmac, switch_tunnel_type_t type, switch_tunnel_id_t id) {
#ifdef TUNNEL_ENABLE
        eg_md.flags.routed = true;
        hdr.ethernet.dst_addr = dmac;
        eg_md.bd = SWITCH_BD_DEFAULT_VRF;
        eg_md.tunnel.type = type;
        eg_md.tunnel.id = id;
#endif
    }

    action rewrite_l3_with_tunnel_bd(mac_addr_t dmac, switch_tunnel_type_t type, switch_bd_t bd) {
#ifdef TUNNEL_ENABLE
        eg_md.flags.routed = true;
        hdr.ethernet.dst_addr = dmac;
        eg_md.bd = bd;
        eg_md.tunnel.type = type;
#endif
    }

    action rewrite_l3_with_tunnel(mac_addr_t dmac, switch_tunnel_type_t type) {
#ifdef TUNNEL_ENABLE
        eg_md.flags.routed = true;
        hdr.ethernet.dst_addr = dmac;
        eg_md.tunnel.type = type;
        eg_md.bd = (switch_bd_t) eg_md.vrf;
#endif
    }

    table nexthop_rewrite {
        key = { eg_md.nexthop : exact; }
        actions = {
            NoAction;
            rewrite_l2_with_tunnel;
            rewrite_l3;
            rewrite_l3_with_tunnel;
            rewrite_l3_with_tunnel_bd;
            rewrite_l3_with_tunnel_id;
        }

        const default_action = NoAction;
        size = nexthop_table_size;
    }

    action rewrite_smac(mac_addr_t smac) {
        hdr.ethernet.src_addr = smac;
    }

    table smac_rewrite {
        key = { smac_index : exact; }
        actions = {
            NoAction;
            rewrite_smac;
        }

        const default_action = NoAction;
    }

    // RFC 1112
    action rewrite_ipv4_multicast() {
        //XXX might be possible on Tofino as dst_addr[23] is 0.
        //hdr.ethernet.dst_addr[22:0] = hdr.ipv4.dst_addr[22:0];
        //hdr.ethernet.dst_addr[47:24] = 0x01005E;
    }

    // RFC 2464
    action rewrite_ipv6_multicast() {
        //hdr.ethernet.dst_addr[31:0] = hdr.ipv6.dst_addr[31:0];
        //hdr.ethernet.dst_addr[47:32] = 16w0x3333;
    }

    table multicast_rewrite {
        key = {
            hdr.ipv4.isValid() : exact;
            hdr.ipv4.dst_addr[31:28] : ternary;
            //hdr.ipv6.isValid() : exact;
            //hdr.ipv6.dst_addr[127:96] : ternary;
        }

        actions = {
            NoAction;
            rewrite_ipv4_multicast;
            rewrite_ipv6_multicast;
        }

        const default_action = NoAction;
    }


    action rewrite_ipv4() {
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    action rewrite_ipv6() {
#ifdef IPV6_ENABLE
        hdr.ipv6.hop_limit = hdr.ipv6.hop_limit - 1;
#endif
    }

    table ip_rewrite {
        key = {
            hdr.ipv4.isValid() : exact;
            hdr.ipv6.isValid() : exact;
        }

        actions = {
            rewrite_ipv4;
            rewrite_ipv6;
        }

        const entries = {
            (true, false) : rewrite_ipv4();
            (false, true) : rewrite_ipv6();
        }
    }

    apply {
        smac_index = 0;

        // Should not rewrite packets redirected to CPU.
        if (!EGRESS_BYPASS(REWRITE)) {
            nexthop_rewrite.apply();
        }

        egress_bd.apply(hdr, eg_md.bd, eg_md.pkt_type, eg_md.pkt_src,
            eg_md.bd_label, smac_index, eg_md.checks.mtu);

        if (!EGRESS_BYPASS(REWRITE) && eg_md.flags.routed) {
            ip_rewrite.apply();
            smac_rewrite.apply();
        }
    }
}

#endif /* _P4_REWRITE_ */
