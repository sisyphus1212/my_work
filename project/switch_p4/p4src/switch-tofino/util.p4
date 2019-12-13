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

#include "types.p4"

// Flow hash calculation.
Hash<bit<32>>(HashAlgorithm_t.CRC32) ip_hash;
Hash<bit<32>>(HashAlgorithm_t.CRC32) non_ip_hash;

action compute_ip_hash(in switch_lookup_fields_t lkp, out bit<32> hash) {
    hash = ip_hash.get({lkp.ip_src_addr,
                        lkp.ip_dst_addr,
                        lkp.ip_proto,
                        lkp.l4_dst_port,
                        lkp.l4_src_port});
}

action compute_non_ip_hash(in switch_lookup_fields_t lkp, out bit<32> hash) {
    hash = non_ip_hash.get({lkp.mac_type, lkp.mac_src_addr, lkp.mac_dst_addr});
}

// Bridged metadata fields for Egress pipeline.
action add_bridged_md(
        inout switch_bridged_metadata_h bridged_md, in switch_ingress_metadata_t ig_md) {
    bridged_md.setValid();
    bridged_md.src = SWITCH_PKT_SRC_BRIDGED;
    bridged_md.base = {
        ig_md.port, ig_md.ifindex, ig_md.bd, ig_md.nexthop, ig_md.lkp.pkt_type,
        ig_md.flags.routed, ig_md.flags.peer_link, ig_md.cpu_reason,
        ig_md.timestamp, ig_md.qos.tc, ig_md.qos.qid, ig_md.qos.color};

#if defined(EGRESS_IP_ACL_ENABLE) || defined(EGRESS_MIRROR_ACL_ENABLE)
    bridged_md.acl = {ig_md.lkp.l4_src_port,
                      ig_md.lkp.l4_dst_port,
                      ig_md.lkp.tcp_flags,
                      ig_md.l4_port_label};
#endif

#ifdef TUNNEL_ENABLE
    bridged_md.tunnel = {ig_md.tunnel.index,
                         ig_md.outer_nexthop,
                         ig_md.hash[15:0],
                         ig_md.vrf,
                         ig_md.tunnel.terminate};
#endif

#ifdef DTEL_ENABLE
    bridged_md.dtel = {ig_md.dtel.report_type,
                       ig_md.dtel.session_id,
                       ig_md.hash,
                       ig_md.egress_port};
#endif
}

action set_ig_intr_md(in switch_ingress_metadata_t ig_md,
                      inout ingress_intrinsic_metadata_for_deparser_t ig_intr_md_for_dprsr,
                      inout ingress_intrinsic_metadata_for_tm_t ig_intr_md_for_tm) {
    ig_intr_md_for_tm.mcast_grp_b = ig_md.multicast.id;
// Set PRE hash values
//  ig_intr_md_for_tm.level1_mcast_hash = ig_md.hash[12:0];
    ig_intr_md_for_tm.level2_mcast_hash = ig_md.hash[28:16];
//    ig_intr_md_for_dprsr.mirror_type = (bit<3>) ig_md.mirror.type;
#ifdef QOS_ENABLE
    ig_intr_md_for_tm.qid = ig_md.qos.qid;
    ig_intr_md_for_tm.ingress_cos = ig_md.qos.icos;
#endif
}

action set_eg_intr_md(in switch_egress_metadata_t eg_md,
                      inout egress_intrinsic_metadata_for_deparser_t eg_intr_md_for_dprsr,
                      inout egress_intrinsic_metadata_for_output_port_t eg_intr_md_for_oport) {
#ifdef PTP_ENABLE
    eg_intr_md_for_oport.capture_tstamp_on_tx = eg_md.flags.capture_ts;
#endif
    eg_intr_md_for_dprsr.mirror_type = (bit<3>) eg_md.mirror.type;
}
