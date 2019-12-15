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

#ifndef _P4_ACL_
#define _P4_ACL_

//-----------------------------------------------------------------------------
// Common Ingress ACL actions.
//-----------------------------------------------------------------------------
action ingress_acl_deny(inout switch_ingress_metadata_t ig_md,
                        inout switch_stats_index_t index,
                        switch_stats_index_t stats_index) {
    index = stats_index;
    ig_md.flags.acl_deny = true;
}

action ingress_acl_permit(inout switch_ingress_metadata_t ig_md,
                          inout switch_stats_index_t index,
                          switch_stats_index_t stats_index) {
    index = stats_index;
    ig_md.flags.acl_deny = false;
}

action ingress_acl_redirect(inout switch_ingress_metadata_t ig_md,
                            inout switch_stats_index_t index,
                            inout switch_nexthop_t nexthop,
                            switch_nexthop_t nexthop_index,
                            switch_stats_index_t stats_index) {
    index = stats_index;
    ig_md.flags.acl_deny = false;
#ifdef ACL_REDIRECT_OPT
    ig_md.acl_nexthop = nexthop_index;
    ig_md.acl_redirect = true;
#endif
}

action ingress_acl_mirror(inout switch_ingress_metadata_t ig_md,
                          inout switch_stats_index_t index,
                          switch_stats_index_t stats_index,
                          switch_mirror_session_t session_id) {
#ifdef INGRESS_MIRROR_ACL_ENABLE
    index = stats_index;
    ig_md.mirror.type = SWITCH_MIRROR_TYPE_PORT;
    ig_md.mirror.src = SWITCH_PKT_SRC_CLONED_INGRESS;
    ig_md.mirror.session_id = session_id;
#endif
}

//-----------------------------------------------------------------------------
// Common Egress ACL actions.
//-----------------------------------------------------------------------------
action egress_acl_deny(inout switch_egress_metadata_t eg_md,
                        inout switch_stats_index_t index,
                        switch_stats_index_t stats_index) {
    index = stats_index;
    eg_md.flags.acl_deny = true;
}

action egress_acl_permit(inout switch_egress_metadata_t eg_md,
                         inout switch_stats_index_t index,
                         switch_stats_index_t stats_index) {
    index = stats_index;
    eg_md.flags.acl_deny = false;
}

action egress_acl_mirror(inout switch_egress_metadata_t eg_md,
                         inout switch_stats_index_t index,
                         switch_stats_index_t stats_index,
                         switch_mirror_session_t session_id) {
#ifdef EGRESS_MIRROR_ACL_ENABLE
    index = stats_index;
    eg_md.mirror.type = SWITCH_MIRROR_TYPE_PORT;
    eg_md.mirror.src = SWITCH_PKT_SRC_CLONED_EGRESS;
    eg_md.mirror.session_id = session_id;
#endif
}

//-----------------------------------------------------------------------------
// Common ACL match keys.
//-----------------------------------------------------------------------------
#define INGRESS_MAC_ACL_KEY              \
    lkp.mac_src_addr : ternary;          \
    lkp.mac_dst_addr : ternary;          \
    lkp.mac_type : ternary;

#define INGRESS_VXLAN_ACL_KEY
    lkp.vni : exact;

#define INGRESS_IPV4_ACL_KEY             \
    lkp.ip_src_addr[31:0] : ternary;     \
    lkp.ip_dst_addr[31:0] : ternary;     \
    lkp.ip_proto : ternary;              \
    lkp.ip_tos : ternary;                \
    lkp.l4_src_port : ternary;           \
    lkp.l4_dst_port : ternary;           \
    lkp.ip_ttl : ternary;                \
    lkp.ip_frag : ternary;               \
    lkp.tcp_flags : ternary;

#define INGRESS_IPV6_ACL_KEY             \
    lkp.ip_src_addr : ternary;           \
    lkp.ip_dst_addr : ternary;           \
    lkp.ip_proto : ternary;              \
    lkp.ip_tos : ternary;                \
    lkp.l4_src_port : ternary;           \
    lkp.l4_dst_port : ternary;           \
    lkp.ip_ttl : ternary;                \
    lkp.tcp_flags : ternary;

#define INGRESS_IP_ACL_KEY               \
    lkp.mac_type : ternary;              \
    lkp.ip_src_addr : ternary;           \
    lkp.ip_dst_addr : ternary;           \
    lkp.ip_proto : ternary;              \
    lkp.ip_tos : ternary;                \
    lkp.l4_src_port : ternary;           \
    lkp.l4_dst_port : ternary;           \
    lkp.ip_ttl : ternary;                \
    lkp.tcp_flags : ternary;

#define EGRESS_IPV4_ACL_KEY              \
    hdr.ipv4.src_addr : ternary;         \
    hdr.ipv4.dst_addr : ternary;         \
    hdr.ipv4.protocol : ternary;         \
    hdr.ipv4.diffserv : ternary;         \
    lkp.tcp_flags : ternary;             \
    lkp.l4_src_port : ternary;           \
    lkp.l4_dst_port : ternary;

#define EGRESS_IPV6_ACL_KEY              \
    hdr.ipv6.src_addr : ternary;         \
    hdr.ipv6.dst_addr : ternary;         \
    hdr.ipv6.next_hdr : ternary;         \
    hdr.ipv6.traffic_class : ternary;    \
    lkp.tcp_flags : ternary;             \
    lkp.l4_src_port : ternary;           \
    lkp.l4_dst_port : ternary;

//-----------------------------------------------------------------------------
// IP ACL
//-----------------------------------------------------------------------------
control IngressIpAcl(
        in switch_lookup_fields_t lkp,
        inout switch_ingress_metadata_t ig_md,
        out switch_stats_index_t index,
        out switch_nexthop_t nexthop)(
        switch_uint32_t table_size=512) {

    table acl {
        key = {
            INGRESS_IP_ACL_KEY
            ig_md.port_lag_label : ternary;
            ig_md.bd_label : ternary;
            ig_md.l4_port_label : ternary;
        }

        actions = {
            NoAction;
            ingress_acl_deny(ig_md, index);
            ingress_acl_permit(ig_md, index);
            ingress_acl_redirect(ig_md, index, nexthop);
        }

        const default_action = NoAction;
        size = table_size;
    }

    apply {
        acl.apply();
    }
}

//-----------------------------------------------------------------------------
// IPv4 ACL
//-----------------------------------------------------------------------------
control IngressIpv4Acl(
        in switch_lookup_fields_t lkp,
        inout switch_ingress_metadata_t ig_md,
        out switch_stats_index_t index,
        out switch_nexthop_t nexthop)(
        switch_uint32_t table_size=512) {

    table acl {
        key = {
            INGRESS_IPV4_ACL_KEY
            lkp.mac_type : ternary;
            ig_md.port_lag_label : ternary;
            ig_md.bd_label : ternary;
            ig_md.l4_port_label : ternary;
        }

        actions = {
            NoAction;
            ingress_acl_deny(ig_md, index);
            ingress_acl_permit(ig_md, index);
            ingress_acl_redirect(ig_md, index, nexthop);
        }

        const default_action = NoAction;
        size = table_size;
    }

    apply {
        acl.apply();
    }
}

//-----------------------------------------------------------------------------
// IPv6 ACL
//-----------------------------------------------------------------------------
control IngressIpv6Acl(
        in switch_lookup_fields_t lkp,
        inout switch_ingress_metadata_t ig_md,
        out switch_stats_index_t index,
        out switch_nexthop_t nexthop)(
        switch_uint32_t table_size=512) {
    table acl {
        key = {
            INGRESS_IPV6_ACL_KEY
            ig_md.port_lag_label : ternary;
            ig_md.bd_label : ternary;
            ig_md.l4_port_label : ternary;
        }

        actions = {
            NoAction;
            ingress_acl_deny(ig_md, index);
            ingress_acl_permit(ig_md, index);
            ingress_acl_redirect(ig_md, index, nexthop);
        }

        const default_action = NoAction;
        size = table_size;
    }

    apply {
        acl.apply();
    }
}

//-----------------------------------------------------------------------------
// MAC ACL
//-----------------------------------------------------------------------------
control IngressMacAcl(
        in switch_lookup_fields_t lkp,
        inout switch_ingress_metadata_t ig_md,
        out switch_stats_index_t index,
        out switch_nexthop_t nexthop)(
        switch_uint32_t table_size=512) {

    table acl {
        key = {
            INGRESS_MAC_ACL_KEY
            ig_md.port_lag_label : ternary;
            ig_md.bd_label : ternary;
        }

        actions = {
            NoAction;
            ingress_acl_deny(ig_md, index);
            ingress_acl_permit(ig_md, index);
            ingress_acl_redirect(ig_md, index, nexthop);
        }

        const default_action = NoAction;
        size = table_size;
    }

    apply {
        acl.apply();
    }
}

// ----------------------------------------------------------------------------
// Comparison/Logical operation unit (LOU)
// LOU can perform logical operationis such AND and OR on tcp flags as well as comparison
// operations such as LT, GT, EQ, and NE for src/dst UDP/TCP ports.
//
// @param src_port : UDP/TCP source port.
// @param dst_port : UDP/TCP destination port.
// @param flags : TCP flags.
// @param port_label : A bit-map for L4 src/dst port ranges. Each bit is corresponding to a single
// range for src or dst port.
// @param table_size : Total number of supported ranges for src/dst ports.
// ----------------------------------------------------------------------------
control LOU(in bit<16> src_port,
            in bit<16> dst_port,
            inout bit<8> tcp_flags,
            out switch_l4_port_label_t port_label) {

    const switch_uint32_t table_size = switch_l4_port_label_width / 2;

    //TODO(msharif): Change this to bitwise OR so we can allocate bits to src/dst ports at runtime.
    action set_src_port_label(bit<8> label) {
        port_label[7:0] = label;
    }

    action set_dst_port_label(bit<8> label) {
        port_label[15:8] = label;
    }

    @entries_with_ranges(table_size)
    // @ignore_table_dependency("SwitchIngress.acl.lou.l4_src_port")
    table l4_dst_port {
        key = {
            dst_port : range;
        }

        actions = {
            NoAction;
            set_dst_port_label;
        }

        const default_action = NoAction;
        size = table_size;
    }

    @entries_with_ranges(table_size)
    table l4_src_port {
        key = {
            src_port : range;
        }

        actions = {
            NoAction;
            set_src_port_label;
        }

        const default_action = NoAction;
        size = table_size;
    }

    action set_tcp_flags(bit<8> flags) {
        tcp_flags = flags;
    }

    table tcp {
        key = { tcp_flags : exact; }
        actions = {
            NoAction;
            set_tcp_flags;
        }

        size = 256;
    }

    apply {
#ifdef L4_PORT_LOU_ENABLE
        l4_src_port.apply();
        l4_dst_port.apply();
#endif

#ifdef TCP_FLAGS_LOU_ENABLE
        tcp.apply();
#endif
    }
}

// ----------------------------------------------------------------------------
// Ingress Access Control List (ACL)
//
// @param lkp : Lookup fields used for lookups.
// @param ig_md : Ingress metadata.
// @param mac_acl_enable : Add a ACL slice for L2 traffic. If mac_acl_enable is false, IPv4 ACL is
// applied to IPv4 and non-IP traffic.
// @param mac_packet_class_enable : Controls whether MAC ACL applies to all traffic entering the
// interface, including IP traffic, or to non-IP traffic only.
// ----------------------------------------------------------------------------
control IngressAcl(
        inout switch_lookup_fields_t lkp,
        inout switch_ingress_metadata_t ig_md)(
#if defined(INGRESS_SHARED_IP_ACL_ENABLE)
        switch_uint32_t ip_table_size=512,
#else
        switch_uint32_t ipv4_table_size=512,
        switch_uint32_t ipv6_table_size=512,
#endif /* INGRESS_SHARED_IP_ACL_ENABLE */
        switch_uint32_t mac_table_size=512,
        bool mac_acl_enable=false,
        bool mac_packet_class_enable=false) {

#if defined(INGRESS_SHARED_IP_ACL_ENABLE)
    IngressIpAcl(ip_table_size) ip_acl;
#else
    IngressIpv4Acl(ipv4_table_size) ipv4_acl;
    IngressIpv6Acl(ipv6_table_size) ipv6_acl;
#endif /* INGRESS_SHARED_IP_ACL_ENABLE */
    IngressMacAcl(mac_table_size) mac_acl;
    LOU() lou;

#if defined(INGRESS_SHARED_IP_ACL_ENABLE)
    Counter<bit<16>, switch_stats_index_t>(
        ip_table_size + mac_table_size, CounterType_t.PACKETS_AND_BYTES) stats;
#else
    Counter<bit<16>, switch_stats_index_t>(
        ipv4_table_size + ipv6_table_size + mac_table_size, CounterType_t.PACKETS_AND_BYTES) stats;
#endif /* INGRESS_SHARED_IP_ACL_ENABLE */

    switch_stats_index_t stats_index;
    switch_nexthop_t nexthop;

    apply {
        ig_md.flags.acl_deny = false;
        stats_index = 0;
        nexthop = 0;

        lou.apply(lkp.l4_src_port, lkp.l4_dst_port, lkp.tcp_flags, ig_md.l4_port_label);

        if (mac_acl_enable && !INGRESS_BYPASS(ACL)) {
            if (lkp.ip_type == SWITCH_IP_TYPE_NONE || \
                    (mac_packet_class_enable && ig_md.flags.mac_pkt_class)) {
                mac_acl.apply(lkp, ig_md, stats_index, nexthop);
            }
        }

#if defined(INGRESS_SHARED_IP_ACL_ENABLE)
        if (!INGRESS_BYPASS(ACL)) {
            if (lkp.ip_type != SWITCH_IP_TYPE_NONE) {
                ip_acl.apply(lkp, ig_md, stats_index, nexthop);
            }
        }
#else
        if (!INGRESS_BYPASS(ACL) && (!mac_packet_class_enable || !ig_md.flags.mac_pkt_class)) {
            if (lkp.ip_type == SWITCH_IP_TYPE_IPV6) {
                ipv6_acl.apply(lkp, ig_md, stats_index, nexthop);
            } else if (!mac_acl_enable || lkp.ip_type == SWITCH_IP_TYPE_IPV4) {
                ipv4_acl.apply(lkp, ig_md, stats_index, nexthop);
            }
        }
#endif /* INGRESS_SHARED_IP_ACL_ENABLE */

#if defined(ACL_REDIRECT_ENABLE) && !defined(ACL_REDIRECT_OPT)
        if (nexthop != 0)
            ig_md.nexthop = nexthop;
#endif

        stats.count(stats_index);
    }
}
//-----------------------------------------------------------------------------
// Common RACL actions.
//-----------------------------------------------------------------------------
action racl_deny(inout switch_ingress_metadata_t ig_md,
                 inout switch_stats_index_t index,
                 switch_stats_index_t stats_index) {
    index = stats_index;
    ig_md.flags.racl_deny = true;
}

action racl_permit(inout switch_ingress_metadata_t ig_md,
                   inout switch_stats_index_t index,
                   switch_stats_index_t stats_index) {
    index = stats_index;
    ig_md.flags.racl_deny = false;
}

action racl_redirect(inout switch_stats_index_t index,
                     inout switch_nexthop_t nexthop,
                     switch_stats_index_t stats_index,
                     switch_nexthop_t nexthop_index) {
    index = stats_index;
    nexthop = nexthop_index;
}

//-----------------------------------------------------------------------------
// IPv4 RACL
//-----------------------------------------------------------------------------
control Ipv4Racl(
        in switch_lookup_fields_t lkp,
        inout switch_ingress_metadata_t ig_md,
        out switch_stats_index_t index,
        out switch_nexthop_t nexthop)(
        switch_uint32_t table_size=512) {

    table acl {
        key = {
            INGRESS_IPV4_ACL_KEY
            ig_md.port_lag_label : ternary;
            ig_md.bd_label : ternary;
            ig_md.l4_port_label : ternary;
        }

        actions = {
            NoAction;
            racl_deny(ig_md, index);
            racl_permit(ig_md, index);
            racl_redirect(index, nexthop);
        }

        const default_action = NoAction;
        size = table_size;
    }

    apply {
        acl.apply();
    }
}


//-----------------------------------------------------------------------------
// IPv6 RACL
//-----------------------------------------------------------------------------
control Ipv6Racl(
        in switch_lookup_fields_t lkp,
        inout switch_ingress_metadata_t ig_md,
        out switch_stats_index_t index,
        out switch_nexthop_t nexthop)(
        switch_uint32_t table_size=512) {

    table acl {
        key = {
            INGRESS_IPV6_ACL_KEY
            ig_md.port_lag_label : ternary;
            ig_md.bd_label : ternary;
            ig_md.l4_port_label : ternary;
        }

        actions = {
            NoAction;
            racl_deny(ig_md, index);
            racl_permit(ig_md, index);
            racl_redirect(index, nexthop);
        }

        const default_action = NoAction;
        size = table_size;
    }

    apply {
        acl.apply();
    }
}

// ----------------------------------------------------------------------------
// Router Access Control List (Router-ACL)
// @param lkp : Lookup fields used for ACL.
// @param ig_md : Ingress metadata fields.
//
// @flags PBR_ENABLE : Enable policy-based routing. PBR dictates a policy that
// determines where the packets are forwarded. Policies can be based IP address,
// port numbers and etc.
// ----------------------------------------------------------------------------
control RouterAcl(in switch_lookup_fields_t lkp,
                  inout switch_ingress_metadata_t ig_md)(
                  switch_uint32_t ipv4_table_size=512,
                  switch_uint32_t ipv6_table_size=512,
                  bool stats_enable=false) {

    switch_stats_index_t stats_index;
    switch_nexthop_t nexthop;

    Counter<bit<16>, switch_stats_index_t>(
        ipv4_table_size + ipv6_table_size, CounterType_t.PACKETS_AND_BYTES) stats;

    Ipv4Racl(ipv4_table_size) ipv4_racl;
    Ipv6Racl(ipv6_table_size) ipv6_racl;

    apply {
#ifdef RACL_ENABLE
        stats_index = 0;

        if (!INGRESS_BYPASS(ACL)) {
            if (lkp.ip_type == SWITCH_IP_TYPE_IPV4) {
                ipv4_racl.apply(lkp, ig_md, stats_index, nexthop);
            } else if (lkp.ip_type == SWITCH_IP_TYPE_IPV6) {
#ifdef IPV6_ENABLE
                ipv6_racl.apply(lkp, ig_md, stats_index, nexthop);
#endif
            }
        }

#ifdef PBR_ENABLE
        if (nexthop != 0 && ig_md.flags.routed)
            ig_md.nexthop = nexthop;
#endif /* PBR_ENABLE */

        if (stats_enable && ig_md.flags.routed)
            stats.count(stats_index);
#endif /* RACL_ENABLE */
    }
}

// ----------------------------------------------------------------------------
// IPv4 Ingress Mirror ACL.
// @param lkp : Lookup fields used for ACL.
// @param ig_md : Ingress metadata fields.
// @param index : ACL stats index.
// @param table_size
// ----------------------------------------------------------------------------
control Ipv4MirrorAcl(
        in switch_lookup_fields_t lkp,
        inout switch_ingress_metadata_t ig_md,
        out switch_stats_index_t index)(
        switch_uint32_t table_size=512) {

    table acl {
        key = {
            INGRESS_IPV4_ACL_KEY
            lkp.mac_type : ternary;
            ig_md.port_lag_label : ternary;
            ig_md.l4_port_label : ternary;
        }

        actions = {
            NoAction;
            ingress_acl_mirror(ig_md, index);
        }

        size = table_size;
    }

    apply {
        acl.apply();
    }
}

// ----------------------------------------------------------------------------
// IPv6 Ingress Mirror ACL.
// @param lkp : Lookup fields used for ACL.
// @param ig_md : Ingress metadata fields.
// @param index : ACL stats index.
// @param table_size
// ----------------------------------------------------------------------------
control Ipv6MirrorAcl(
        in switch_lookup_fields_t lkp,
        inout switch_ingress_metadata_t ig_md,
        out switch_stats_index_t index)(
        switch_uint32_t table_size=512) {

    table acl {
        key = {
            INGRESS_IPV6_ACL_KEY
            ig_md.port_lag_label : ternary;
            ig_md.l4_port_label : ternary;
        }

        actions = {
            NoAction;
            ingress_acl_mirror(ig_md, index);
        }

        size = table_size;
    }

    apply {
        acl.apply();
    }
}

// ----------------------------------------------------------------------------
// Unified IPv4/v6 Ingress Mirror ACL.
// @param lkp : Lookup fields used for ACL.
// @param ig_md : Ingress metadata fields.
// @param index : ACL stats index.
// @param table_size
// ----------------------------------------------------------------------------
control IpMirrorAcl(
        in switch_lookup_fields_t lkp,
        inout switch_ingress_metadata_t ig_md,
        out switch_stats_index_t index)(
        switch_uint32_t table_size=512) {

    table acl {
        key = {
            INGRESS_IP_ACL_KEY
            ig_md.port_lag_label : ternary;
            ig_md.l4_port_label : ternary;
        }

        actions = {
            NoAction;
            ingress_acl_mirror(ig_md, index);
        }

        size = table_size;
    }

    apply {
        acl.apply();
    }
}

// ----------------------------------------------------------------------------
// Mirror Access Control List (ACL)
//
// @param lkp : Lookup fields used for lookups.
// @param ig_md : Ingress metadata.
// @param ipv4_table_size : Dedicated IPv4 ACL table size.
// @param ipv6_table_size : Dedicated IPv6 ACL table size.
// @param stats_enable : Enable a shared stats table for IPv4/6 tables.
// ----------------------------------------------------------------------------
control MirrorAcl(
        inout switch_lookup_fields_t lkp,
        inout switch_ingress_metadata_t ig_md)(
        switch_uint32_t ipv4_table_size=512,
        switch_uint32_t ipv6_table_size=512,
        bool stats_enable=false) {

    Ipv4MirrorAcl(ipv4_table_size) ipv4;
    Ipv6MirrorAcl(ipv6_table_size) ipv6;
    IpMirrorAcl(ipv6_table_size) ip;

    Counter<bit<16>, switch_stats_index_t>(
        ipv4_table_size + ipv6_table_size, CounterType_t.PACKETS_AND_BYTES) stats;
    switch_stats_index_t stats_index;

    apply {
#ifdef INGRESS_MIRROR_ACL_ENABLE
        stats_index = 0;

        if (!INGRESS_BYPASS(ACL)) {
#ifdef NON_SHARED_INGRESS_MIRROR_ACL
            if (lkp.ip_type == SWITCH_IP_TYPE_IPV4) {
                ipv4.apply(lkp, ig_md, stats_index);
            } else if (lkp.ip_type == SWITCH_IP_TYPE_IPV6) {
#ifdef IPV6_ENABLE
                ipv6.apply(lkp, ig_md, stats_index);
#endif
            }
#else
            ip.apply(lkp, ig_md, stats_index);
#endif
        }

        if (stats_enable)
            stats.count(stats_index);
#endif /* INGRESS_MIRROR_ACL_ENABLE */
    }
}

// ----------------------------------------------------------------------------
// IPv4 Egress Mirror ACL.
//
// @param hdr : Parsed headers.
// @param lkp : Lookup fields used for ACL.
// @param eg_md : Egress metadata fields.
// @param index : ACL stats index.
// @param table_size
// ----------------------------------------------------------------------------
control Ipv4EgressMirrorAcl(
        in switch_header_t hdr,
        in switch_lookup_fields_t lkp,
        inout switch_egress_metadata_t eg_md,
        out switch_stats_index_t index)(
        switch_uint32_t table_size=512) {

    table acl {
        key = {
            EGRESS_IPV4_ACL_KEY
            hdr.ethernet.ether_type : ternary;
            eg_md.port_lag_label : ternary;
            eg_md.l4_port_label : ternary;
        }

        actions = {
            NoAction;
            egress_acl_mirror(eg_md, index);
        }

        size = table_size;
    }

    apply {
        acl.apply();
    }
}

// ----------------------------------------------------------------------------
// IPv6 Egress Mirror ACL.
//
// @param hdr : Parsed headers.
// @param lkp : Lookup fields used for ACL.
// @param eg_md : Egress metadata fields.
// @param index : ACL stats index.
// @param table_size
// ----------------------------------------------------------------------------
control Ipv6EgressMirrorAcl(
        in switch_header_t hdr,
        in switch_lookup_fields_t lkp,
        inout switch_egress_metadata_t eg_md,
        out switch_stats_index_t index)(
        switch_uint32_t table_size=512) {

    table acl {
        key = {
            EGRESS_IPV6_ACL_KEY
            eg_md.port_lag_label : ternary;
            eg_md.l4_port_label : ternary;
        }

        actions = {
            NoAction;
            egress_acl_mirror(eg_md, index);
        }

        size = table_size;
    }

    apply {
        acl.apply();
    }
}

// ----------------------------------------------------------------------------
// Mirror Access Control List (ACL)
//
// @param hdr : Parsed headers.
// @param lkp : Lookup fields used for lookups.
// @param eg_md : Egress metadata fields.
// @param ipv4_table_size : Dedicated IPv4 ACL table size.
// @param ipv6_table_size : Dedicated IPv6 ACL table size.
// @param stats_enable : Enable a shared stats table for IPv4/6 tables.
// ----------------------------------------------------------------------------
control EgressMirrorAcl(
        in switch_header_t hdr,
        inout switch_lookup_fields_t lkp,
        inout switch_egress_metadata_t eg_md)(
        switch_uint32_t ipv4_table_size=512,
        switch_uint32_t ipv6_table_size=512,
        bool stats_enable=false) {
    Ipv4EgressMirrorAcl(ipv4_table_size) ipv4;
    Ipv6EgressMirrorAcl(ipv6_table_size) ipv6;

    Counter<bit<16>, switch_stats_index_t>(
        ipv4_table_size + ipv6_table_size, CounterType_t.PACKETS_AND_BYTES) stats;
    switch_stats_index_t stats_index;

    apply {
#ifdef EGRESS_MIRROR_ACL_ENABLE
        if (!EGRESS_BYPASS(ACL)) {
            if (hdr.ipv4.isValid()) {
                ipv4.apply(hdr, lkp, eg_md, stats_index);
            } else if (hdr.ipv6.isValid()) {
#ifdef IPV6_ENABLE
                ipv6.apply(hdr, lkp, eg_md, stats_index);
#endif
            }
        }

        if (stats_enable)
            stats.count(stats_index);
#endif /* EGRESS_MIRROR_ACL_ENABLE */
    }
}



//-----------------------------------------------------------------------------
// System ACL
//
// @flag COPP_ENABLE
// @flag
//-----------------------------------------------------------------------------
control IngressSystemAcl(
        inout switch_ingress_metadata_t ig_md,
        inout ingress_intrinsic_metadata_for_tm_t ig_intr_md_for_tm,
        inout ingress_intrinsic_metadata_for_deparser_t ig_intr_md_for_dprsr)(
        switch_uint32_t table_size=512) {

    const switch_uint32_t drop_stats_table_size = 8192;

    DirectCounter<bit<32>>(CounterType_t.PACKETS) stats;

    Meter<bit<8>>(1 << switch_copp_meter_id_width, MeterType_t.PACKETS) copp_meter;
    DirectCounter<bit<32>>(CounterType_t.PACKETS) copp_stats;

    switch_copp_meter_id_t copp_meter_id;

    action drop(switch_drop_reason_t drop_reason, bool disable_learning) {
        ig_intr_md_for_dprsr.drop_ctl = 0x1;
        ig_intr_md_for_dprsr.digest_type =
            disable_learning ? SWITCH_DIGEST_TYPE_INVALID : ig_intr_md_for_dprsr.digest_type;
        ig_md.drop_reason = drop_reason;
    }

    action copy_to_cpu(switch_cpu_reason_t reason_code,
                       switch_qid_t qid,
                       switch_copp_meter_id_t meter_id,
                       bool disable_learning) {
        ig_md.qos.qid = qid;
        // ig_md.qos.icos = icos;
        ig_intr_md_for_tm.copy_to_cpu = 1w1;
        ig_intr_md_for_dprsr.digest_type =
            disable_learning ? SWITCH_DIGEST_TYPE_INVALID : ig_intr_md_for_dprsr.digest_type;
#ifdef COPP_ENABLE
        ig_intr_md_for_tm.packet_color = (bit<2>) copp_meter.execute(meter_id);
        copp_meter_id = meter_id;
#endif
        ig_md.cpu_reason = reason_code;
    }

    action redirect_to_cpu(switch_cpu_reason_t reason_code,
                           switch_qid_t qid,
                           switch_copp_meter_id_t meter_id,
                           bool disable_learning) {
        ig_intr_md_for_dprsr.drop_ctl = 0b1;
        copy_to_cpu(reason_code, qid, meter_id, disable_learning);
    }

    table system_acl {
        key = {
            ig_md.port_lag_label : ternary;
            ig_md.bd_label : ternary;
            ig_md.ifindex : ternary;

            // Lookup fields
            ig_md.lkp.pkt_type : ternary;
            ig_md.lkp.mac_type : ternary;
            ig_md.lkp.mac_dst_addr : ternary;
            ig_md.lkp.ip_type : ternary;
            ig_md.lkp.ip_ttl : ternary;
            ig_md.lkp.ip_proto : ternary;
            ig_md.lkp.ip_frag : ternary;
            ig_md.lkp.ip_dst_addr : ternary;
            ig_md.lkp.l4_src_port : ternary;
            ig_md.lkp.l4_dst_port : ternary;
            ig_md.lkp.arp_opcode : ternary;

            // Flags
            ig_md.flags.port_vlan_miss : ternary;
            ig_md.flags.acl_deny : ternary;
            ig_md.flags.racl_deny : ternary;
            ig_md.flags.rmac_hit : ternary;
            ig_md.flags.dmac_miss : ternary;
            ig_md.flags.myip : ternary;
            ig_md.flags.glean : ternary;
            ig_md.flags.routed : ternary;
#ifdef INGRESS_ACL_POLICER_ENABLE
            ig_md.qos.acl_policer_color : ternary;
#endif
#ifdef STORM_CONTROL_ENABLE
            ig_md.qos.storm_control_color : ternary;
#endif
            ig_md.flags.link_local : ternary;

#ifdef INGRESS_PORT_METER_ENABLE
            ig_md.flags.port_policer_drop : ternary;
#endif

#ifdef UNICAST_SELF_FORWARDING_CHECK
            ig_md.checks.same_bd : ternary;
            ig_md.checks.same_if : ternary;
#endif

#ifdef STP_ENABLE
            ig_md.stp.state_ : ternary;
#endif
#ifdef PFC_ENABLE
            ig_md.flags.pfc_wd_drop : ternary;
#endif
            ig_md.ipv4.unicast_enable : ternary;
            ig_md.ipv6.unicast_enable : ternary;

#ifdef MULTICAST_ENABLE
            ig_md.checks.mrpf : ternary;
            ig_md.ipv4.multicast_enable : ternary;
            ig_md.ipv4.multicast_snooping : ternary;
            ig_md.ipv6.multicast_enable : ternary;
            ig_md.ipv6.multicast_snooping : ternary;
#endif
            ig_md.drop_reason : ternary;
        }

        actions = {
            NoAction;
            drop;
            copy_to_cpu;
            redirect_to_cpu;
        }

        const default_action = NoAction;
        size = table_size;
    }

    action copp_drop() {
        ig_intr_md_for_tm.copy_to_cpu = 1w0;
        copp_stats.count();
    }

    action copp_permit() {
        copp_stats.count();
    }

    table copp {
        key = {
            ig_intr_md_for_tm.packet_color : ternary;
            copp_meter_id : ternary;
        }

        actions = {
            copp_permit;
            copp_drop;
        }

        const default_action = copp_permit;
        size = (1 << switch_copp_meter_id_width + 1);
        counters = copp_stats;
    }

    action count() { stats.count(); }

    table drop_stats {
        key = {
            ig_md.drop_reason : exact @name("drop_reason");
            ig_md.port : exact @name("port");
        }

        actions = {
            @defaultonly NoAction;
            count;
        }

        const default_action = NoAction;
        counters = stats;
        size = drop_stats_table_size;
    }

    apply {
        ig_intr_md_for_tm.copy_to_cpu = 1w0;
        copp_meter_id = 0;

        if (!INGRESS_BYPASS(SYSTEM_ACL))
            system_acl.apply();

#ifdef COPP_ENABLE
        copp.apply();
#endif
        drop_stats.apply();
    }
}

//-----------------------------------------------------------------------------
// MAC ACL
//-----------------------------------------------------------------------------
control EgressMacAcl(in switch_header_t hdr,
                     inout switch_egress_metadata_t eg_md,
                     out switch_stats_index_t index)(
                     switch_uint32_t table_size=512) {
    table acl {
        key = {
            eg_md.port_lag_label : ternary;
            eg_md.bd_label : ternary;
            hdr.ethernet.src_addr : ternary;
            hdr.ethernet.dst_addr : ternary;
            hdr.ethernet.ether_type : ternary;
        }

        actions = {
            NoAction;
            egress_acl_deny(eg_md, index);
            egress_acl_permit(eg_md, index);
        }

        const default_action = NoAction;
        size = table_size;
    }

    apply {
        acl.apply();
    }
}

//-----------------------------------------------------------------------------
// IPv4 ACL
//-----------------------------------------------------------------------------
control EgressIpv4Acl(in switch_header_t hdr,
                      in switch_lookup_fields_t lkp,
                      inout switch_egress_metadata_t eg_md,
                      out switch_stats_index_t index)(
                      switch_uint32_t table_size=512) {
    table acl {
        key = {
            EGRESS_IPV4_ACL_KEY
            hdr.ethernet.ether_type : ternary;
            eg_md.port_lag_label : ternary;
            eg_md.bd_label : ternary;
            eg_md.l4_port_label : ternary;
        }

        actions = {
            NoAction;
            egress_acl_deny(eg_md, index);
            egress_acl_permit(eg_md, index);
        }

        const default_action = NoAction;
        size = table_size;
    }

    apply {
        acl.apply();
    }
}

//-----------------------------------------------------------------------------
// IPv6 ACL
//-----------------------------------------------------------------------------
control EgressIpv6Acl(in switch_header_t hdr,
                      in switch_lookup_fields_t lkp,
                      inout switch_egress_metadata_t eg_md,
                      out switch_stats_index_t index)(
                      switch_uint32_t table_size=512) {
    table acl {
        key = {
            EGRESS_IPV6_ACL_KEY
            eg_md.port_lag_label : ternary;
            eg_md.bd_label : ternary;
            eg_md.l4_port_label : ternary;
        }

        actions = {
            NoAction;
            egress_acl_deny(eg_md, index);
            egress_acl_permit(eg_md, index);
        }

        const default_action = NoAction;
        size = table_size;
    }

    apply {
        acl.apply();
    }
}

control EgressAcl(in switch_header_t hdr,
                  in switch_lookup_fields_t lkp,
                  inout switch_egress_metadata_t eg_md)(
                  switch_uint32_t ipv4_table_size=512,
                  switch_uint32_t ipv6_table_size=512,
                  switch_uint32_t mac_table_size=512,
                  bool mac_acl_enable=false) {
    EgressIpv4Acl(ipv4_table_size) egress_ipv4_acl;
    EgressIpv6Acl(ipv6_table_size) egress_ipv6_acl;
    EgressMacAcl(mac_table_size) egress_mac_acl;

    Counter<bit<16>, switch_stats_index_t>(
        ipv4_table_size + ipv6_table_size + mac_table_size, CounterType_t.PACKETS_AND_BYTES) stats;

    switch_stats_index_t stats_index;

    apply {
        eg_md.flags.acl_deny = false;
#ifdef EGRESS_IP_ACL_ENABLE
        stats_index = 0;

        if (mac_acl_enable && !EGRESS_BYPASS(ACL)) {
            egress_mac_acl.apply(hdr, eg_md, stats_index);
        }
        if (!EGRESS_BYPASS(ACL)) {
            if (hdr.ipv6.isValid()) {
                egress_ipv6_acl.apply(hdr, lkp, eg_md, stats_index);
            } else if (!mac_acl_enable || hdr.ipv4.isValid()) {
                egress_ipv4_acl.apply(hdr, lkp, eg_md, stats_index);
            }
        }

        stats.count(stats_index);
#endif /* EGRESS_IP_ACL_ENABLE */
    }
}

control EgressSystemAcl(
        inout switch_header_t hdr,
        inout switch_egress_metadata_t eg_md,
        in egress_intrinsic_metadata_t eg_intr_md,
        out egress_intrinsic_metadata_for_deparser_t eg_intr_md_for_dprsr)(
        switch_uint32_t table_size=512) {

    const switch_uint32_t drop_stats_table_size = 8192;
    DirectCounter<bit<32>>(CounterType_t.PACKETS) stats;

    action drop(switch_drop_reason_t reason_code) {
        eg_md.drop_reason = reason_code;
        eg_intr_md_for_dprsr.drop_ctl = 0x1;
    }

    action copy_to_cpu(switch_cpu_reason_t reason_code) {
        eg_md.cpu_reason = reason_code;
        eg_intr_md_for_dprsr.mirror_type = SWITCH_MIRROR_TYPE_CPU;
        eg_md.mirror.type = SWITCH_MIRROR_TYPE_CPU;
        eg_md.mirror.session_id = SWITCH_MIRROR_SESSION_CPU;
        eg_md.mirror.src = SWITCH_PKT_SRC_CLONED_EGRESS;
    }

    action redirect_to_cpu(switch_cpu_reason_t reason_code) {
        copy_to_cpu(reason_code);
        eg_intr_md_for_dprsr.drop_ctl = 0x1;
    }

    action insert_timestamp() {
#ifdef PTP_ENABLE
        hdr.timestamp.setValid();
        hdr.timestamp.timestamp = eg_md.ingress_timestamp;
#endif
    }

    table system_acl {
        key = {
            eg_intr_md.egress_port : ternary;
            eg_md.flags.acl_deny : ternary;

#ifdef MLAG_ENABLE
            eg_md.flags.mlag_member : ternary;
            eg_md.flags.peer_link : ternary;
#endif
            eg_md.checks.mtu : ternary;

#ifdef STP_ENABLE
            eg_md.checks.stp : ternary;
#endif
#ifdef WRED_ENABLE
            eg_md.flags.wred_drop : ternary;
#endif
#ifdef PFC_ENABLE
            eg_md.flags.pfc_wd_drop : ternary;
#endif
            //TODO add more
        }

        actions = {
            NoAction;
            drop;
            copy_to_cpu;
            redirect_to_cpu;
            insert_timestamp;
        }

        const default_action = NoAction;
        size = table_size;
    }

    action count() { stats.count(); }

    table drop_stats {
        key = {
            eg_md.drop_reason : exact @name("drop_reason");
            eg_intr_md.egress_port : exact @name("port");
        }

        actions = {
            @defaultonly NoAction;
            count;
        }

        const default_action = NoAction;
        counters = stats;
        size = drop_stats_table_size;
    }


    apply {
        eg_md.drop_reason = 0;

        if (!EGRESS_BYPASS(SYSTEM_ACL))
            system_acl.apply();
        drop_stats.apply();
    }
}

#endif /* _P4_ACL_ */
