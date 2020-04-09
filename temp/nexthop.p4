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

// ----------------------------------------------------------------------------
// Nexthop/ECMP resolution
//
// @param lkp : Lookup fields used for hash calculation.
// @param ig_md : Ingress metadata fields
// @param hash : Hash value used for ECMP selection.
// @param nexthop_table_size : Number of nexthops.
// @param ecmp_table_size : Number of ECMP groups.
// @param ecmp_selction_table_size : Maximum number of ECMP members.
//
// ----------------------------------------------------------------------------
control Nexthop(inout switch_lookup_fields_t lkp,
                inout switch_ingress_metadata_t ig_md,
                in bit<16> hash)(
                switch_uint32_t nexthop_table_size,
                switch_uint32_t ecmp_table_size,
                switch_uint32_t ecmp_selection_table_size) {

    Hash<switch_uint16_t>(HashAlgorithm_t.IDENTITY) selector_hash;
    ActionSelector(
        ecmp_selection_table_size, selector_hash, SelectorMode_t.FAIR) ecmp_selector;

    action set_nexthop_properties(switch_ifindex_t ifindex,
                                  switch_port_lag_index_t port_lag_index,
                                  switch_bd_t bd) {
        ig_md.egress_ifindex = ifindex;
        ig_md.egress_port_lag_index = port_lag_index;
        ig_md.checks.same_if = ig_md.ifindex ^ ifindex;
        ig_md.checks.same_bd = ig_md.bd ^ bd;
    }

    action set_nexthop_properties_post_routed_flood(switch_bd_t bd, switch_mgid_t mgid) {
        ig_md.egress_ifindex = 0;
        ig_md.egress_port_lag_index = 0;
        ig_md.checks.same_bd = ig_md.bd ^ bd;
        ig_md.multicast.id = mgid;
    }

    action set_nexthop_properties_glean() {
        ig_md.flags.glean = true;
        ig_md.checks.same_bd = 0xffff;
    }

    action set_nexthop_properties_drop() {
        ig_md.drop_reason = SWITCH_DROP_REASON_NEXTHOP;
    }

    action set_ecmp_properties(switch_ifindex_t ifindex,
                               switch_port_lag_index_t port_lag_index,
                               switch_bd_t bd,
                               switch_nexthop_t nexthop_index) {
        ig_md.nexthop = nexthop_index;
        set_nexthop_properties(ifindex, port_lag_index, bd);
    }

    action set_ecmp_properties_post_routed_flood(
            switch_bd_t bd,
            switch_mgid_t mgid,
            switch_nexthop_t nexthop_index) {
        ig_md.nexthop = nexthop_index;
        set_nexthop_properties_post_routed_flood(bd, mgid);
    }

    action set_ecmp_properties_glean(switch_nexthop_t nexthop_index) {
        ig_md.nexthop = nexthop_index;
        set_nexthop_properties_glean();
    }

    action set_tunnel_properties(switch_bd_t bd, switch_tunnel_index_t tunnel_index) {
        // TODO(msharif) : Disable cut-through for non-ip packets.
        ig_md.tunnel.index = tunnel_index;
        ig_md.egress_ifindex = 0;
        ig_md.checks.same_bd = ig_md.bd ^ bd;
    }

    table ecmp {
        key = {
            ig_md.nexthop : exact;
#ifdef ACL_REDIRECT_OPT
            ig_md.acl_nexthop : exact;
            ig_md.acl_redirect : exact;
#endif            
            hash : selector;
        }

        actions = {
            NoAction;
            set_ecmp_properties;
            set_ecmp_properties_glean;
            set_ecmp_properties_post_routed_flood;
            set_tunnel_properties;
        }

        const default_action = NoAction;
        size = ecmp_table_size;
        implementation = ecmp_selector;
    }

    table nexthop {
        key = {
            ig_md.nexthop : exact;
#ifdef ACL_REDIRECT_OPT
            ig_md.acl_nexthop : exact;
            ig_md.acl_redirect : exact;
#endif            
        }

        actions = {
            NoAction;
            set_nexthop_properties;
            set_nexthop_properties_drop;
            set_nexthop_properties_glean;
            set_nexthop_properties_post_routed_flood;
            set_tunnel_properties;
        }

        const default_action = NoAction;
        size = nexthop_table_size;
    }

    apply {
        ig_md.checks.same_bd = 0;
        ig_md.flags.glean = false;

        switch(nexthop.apply().action_run) {
            NoAction : { ecmp.apply(); }
            default : {}
        }
    }
}

control OuterFib(inout switch_ingress_metadata_t ig_md,
                     in bit<16> hash)(
                     switch_uint32_t fib_table_size,
                     switch_uint32_t ecmp_table_size,
                     switch_uint32_t ecmp_selection_table_size) {
    Hash<switch_uint16_t>(HashAlgorithm_t.IDENTITY) selector_hash;
    ActionSelector(ecmp_selection_table_size, selector_hash, SelectorMode_t.FAIR) ecmp_selector;

    action set_nexthop_properties(switch_ifindex_t ifindex,
                                  switch_port_lag_index_t port_lag_index,
                                  switch_outer_nexthop_t nexthop_index) {
        ig_md.outer_nexthop = nexthop_index;
        ig_md.egress_ifindex = ifindex;
        ig_md.egress_port_lag_index = port_lag_index;
    }

    table fib {
        key = {
            ig_md.tunnel.index : exact;
            hash : selector;
        }

        actions = {
            NoAction;
            set_nexthop_properties;
        }

        const default_action = NoAction;
        implementation = ecmp_selector;
        size = fib_table_size;
    }

    apply {
#ifdef TUNNEL_ENABLE
        fib.apply();
#endif
    }
}
