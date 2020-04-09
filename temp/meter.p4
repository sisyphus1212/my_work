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

#ifndef _P4_METER_
#define _P4_METER_

#include "acl.p4"

//-------------------------------------------------------------------------------------------------
// Ingress Policer
//
// Monitors the data rate for a particular class of service and drops the traffic
// when the rate exceeds a user-defined thresholds.
//
// @param ig_md : Ingress metadata fields.
// @param qos_md : QoS related metadata fields.
// @param flag : Indicating whether the packet should get dropped or not.
// @param table_size : Size of the ingress policer table.
//-------------------------------------------------------------------------------------------------
control IngressPolicer(in switch_ingress_metadata_t ig_md,
                       inout switch_qos_metadata_t qos_md,
                       out bool flag)(
                       switch_uint32_t table_size=1024) {
    DirectCounter<bit<32>>(CounterType_t.PACKETS_AND_BYTES) stats;
    DirectMeter(MeterType_t.BYTES) meter;

    // Requires 3 entries per meter index for unicast/broadcast/multicast packets.
    action meter_deny() {
        stats.count();
        flag = true;
        qos_md.color = qos_md.acl_policer_color;
    }

    action meter_permit() {
        stats.count();
    }

    table meter_action {
        key = {
            qos_md.acl_policer_color : exact;
            qos_md.meter_index : exact;
        }

        actions = {
            meter_permit;
            meter_deny;
        }

        const default_action = meter_permit;
        size = 3 * table_size;
        counters = stats;
    }

    action set_color() {
        qos_md.acl_policer_color = (bit<2>) meter.execute();
    }

    table meter_index {
        key = {
            qos_md.meter_index: exact;
        }

        actions = {
            @defaultonly NoAction;
            set_color;
        }

        const default_action = NoAction;
        size = table_size;
        meters = meter;
    }

    apply {
#if defined(INGRESS_ACL_POLICER_ENABLE)
        flag = false;

        if (!INGRESS_BYPASS(POLICER))
            meter_index.apply();

        if (!INGRESS_BYPASS(POLICER))
            meter_action.apply();
#endif
    }
}

//-------------------------------------------------------------------------------------------------
// Storm Control
//
// Monitors incoming traffic and prevents the excessive traffic on a particular interface by
// dropping the traffic. Each port has a single storm control levels for all types of traffic
// (broadcast, multicast, and unicast).
//
// @param ig_md : Ingress metadata fields
// @param pkt_type : One of Unicast, Multicast, or Broadcast packet types.
// @param flag : Indicating whether the packet should get dropped or not.
// @param table_size : Size of the storm control table.
//-------------------------------------------------------------------------------------------------
control StormControl(inout switch_ingress_metadata_t ig_md,
                     in switch_pkt_type_t pkt_type,
                     out bool flag)(
                     switch_uint32_t table_size=512) {
    DirectCounter<bit<32>>(CounterType_t.PACKETS) storm_control_stats;
    Meter<bit<16>>(table_size, MeterType_t.BYTES) meter;

    action count() {
        storm_control_stats.count();
    }

    action drop_and_count() {
        storm_control_stats.count();
        flag = true;
    }

    table stats {
        key = {
            ig_md.qos.storm_control_color: exact;
            pkt_type : ternary;
            ig_md.port: exact;
            ig_md.flags.dmac_miss : ternary;
        }

        actions = {
            @defaultonly NoAction;
            count;
            drop_and_count;
        }

        const default_action = NoAction;
        size = table_size;
        counters = storm_control_stats;
    }

    action set_meter(bit<16> index) {
        ig_md.qos.storm_control_color = (bit<2>) meter.execute(index);
    }

    table storm_control {
        key =  {
            ig_md.port : exact;
            pkt_type : ternary;
            ig_md.flags.dmac_miss : ternary;
        }

        actions = {
            @defaultonly NoAction;
            set_meter;
        }

        const default_action = NoAction;
        size = table_size;
    }

    apply {
        ig_md.qos.storm_control_color = 0;
#ifdef STORM_CONTROL_ENABLE
        flag = false;

        if (!INGRESS_BYPASS(STORM_CONTROL))
            storm_control.apply();

        if (!INGRESS_BYPASS(STORM_CONTROL))
            stats.apply();
#endif
    }
}

//-------------------------------------------------------------------------------------------------
// Port Policer
//
// Monitors traffic on a port and prevents the excessive traffic on a particular port by
// dropping the traffic.
//
// @param port : Ingress/Egress Port
// @param flag : Indicating whether the packet should get dropped or not.
// @param table_size : Size of the policer table.
//-------------------------------------------------------------------------------------------------

control PortPolicer(in switch_port_t port,
                     out bool flag)(
                     switch_uint32_t table_size=288) {
    DirectCounter<bit<32>>(CounterType_t.BYTES) stats;
    Meter<bit<9>>(table_size, MeterType_t.BYTES) meter;
    switch_pkt_color_t color;

    action permit_and_count() {
        stats.count();
        flag = false;
    }

    action drop_and_count() {
        stats.count();
        flag = true;
    }

    table meter_action {
        key = {
            color: exact;
            port: exact;
        }

        actions = {
            @defaultonly NoAction;
            permit_and_count;
            drop_and_count;
        }

        const default_action = NoAction;
        size = table_size*2;
        counters = stats;
    }

    action set_meter(bit<9> index) {
        color = (bit<2>) meter.execute(index);
    }

    table meter_index {
        key =  {
            port : exact;
        }

        actions = {
            @defaultonly NoAction;
            set_meter;
        }

        const default_action = NoAction;
        size = table_size;
    }

    apply {
            meter_index.apply();
            meter_action.apply();
    }
}

control PortPolicer2(in switch_port_t port,
                     out bool flag)(
                     switch_uint32_t table_size=288) {
    DirectCounter<bit<32>>(CounterType_t.BYTES) stats;
    Meter<bit<9>>(table_size, MeterType_t.BYTES) meter;
    switch_pkt_color_t color;

    action permit_and_count() {
        stats.count();
        flag = false;
    }

    action drop_and_count() {
        stats.count();
        flag = true;
    }

    table meter_action {
        key = {
            color: exact;
            port: exact;
        }

        actions = {
            @defaultonly NoAction;
            permit_and_count;
            drop_and_count;
        }

        const default_action = NoAction;
        size = table_size*2;
        counters = stats;
    }

    action set_meter(bit<9> index) {
        color = (bit<2>) meter.execute(index);
    }

    table meter_index {
        key =  {
            port : exact;
        }

        actions = {
            @defaultonly NoAction;
            set_meter;
        }

        const default_action = NoAction;
        size = table_size;
    }

    apply {
            meter_index.apply();
            meter_action.apply();
    }
}

#endif /* _P4_METER_ */
