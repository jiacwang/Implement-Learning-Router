#!/usr/bin/env python2
#
# Copyright 2017-present Open Networking Foundation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
import argparse
import json
import os
import sys
import time
import threading

sys.path.append("utils")
import bmv2
import helper
from convert import *

from p4.v1 import p4runtime_pb2

# Helper function to add entries to the Ethernet table.
# The router cares about frames that match the local MAC or the broadcast MAC.
# Nothing else.
def AddEthernetEntries(sw, helper, local_mac, ingress_port):
    table_entry = helper.buildTableEntry(
            table_name = "cis553Ingress.tiHandleEthernet",
            match_fields = { "hdr.ethernet.dstAddr": local_mac,
                             "standard_metadata.ingress_port" :  ingress_port},
            action_name = "cis553Ingress.aiForMe")
    sw.WriteTableEntry(table_entry);

    table_entry = helper.buildTableEntry(
            table_name = "cis553Ingress.tiHandleEthernet",
            match_fields = { "hdr.ethernet.dstAddr": "ff:ff:ff:ff:ff:ff",
                             "standard_metadata.ingress_port" :  ingress_port},
            action_name = "cis553Ingress.aiForMe")
    sw.WriteTableEntry(table_entry);

# Helper function to add an LPM entry to the IPv4 forwarding table.
# prefix_len = 32 indicates that the address must match the full string
def AddRoutingEntry(sw, helper, ip, mac_sa, mac_da, egress_port, prefix_len = 32):
    table_entry = helper.buildTableEntry(
            table_name = "cis553Ingress.tiIpv4Lpm",
            match_fields = { "hdr.ipv4.dstAddr": [ ip, prefix_len ] },
            action_name = "cis553Ingress.aiForward",
            action_params = { "mac_sa": mac_sa,
                              "mac_da": mac_da,
                              "egress_port": egress_port } )
    sw.WriteTableEntry(table_entry);


# Helper function to add an entry to the ARP response table.
# oper = 1 checks that it is a request
def AddARPResponse(sw, helper, target_pa, mac_sa, oper = 1):
    table_entry = helper.buildTableEntry(
            table_name = "cis553Ingress.tiArpResponse",
            match_fields = { "hdr.arp.oper": oper,
                             "hdr.arp.targetPA" : target_pa },
            action_name = "cis553Ingress.aiArpResponse",
            action_params = { "mac_sa": mac_sa } )
    sw.WriteTableEntry(table_entry);


def ProgramSwitch(sw, id, p4info_helper):
    mac_h1_to_s1 = "00:00:00:00:01:01"
    mac_h2_to_s2 = "00:00:00:00:02:02"
    mac_h3_to_s3 = "00:00:00:00:03:03"

    mac_s1_to_h1 = "00:00:00:01:01:00"
    mac_s1_to_s2 = "00:00:00:01:02:00"
    mac_s1_to_s3 = "00:00:00:01:03:00"

    mac_s2_to_s1 = "00:00:00:02:02:00"
    mac_s2_to_h2 = "00:00:00:02:01:00"
    mac_s2_to_s3 = "00:00:00:02:03:00"

    mac_s3_to_s1 = "00:00:00:03:02:00"
    mac_s3_to_s2 = "00:00:00:03:03:00"
    mac_s3_to_h3 = "00:00:00:03:01:00"

    if id == 1:
        AddEthernetEntries(sw, p4info_helper, mac_s1_to_h1, 1);
        AddEthernetEntries(sw, p4info_helper, mac_s1_to_s2, 2);
        AddEthernetEntries(sw, p4info_helper, mac_s1_to_s3, 3);
        AddRoutingEntry(sw, p4info_helper,
                    "10.0.1.1", mac_s1_to_h1, mac_h1_to_s1, 1);
        AddRoutingEntry(sw, p4info_helper,
                    "10.0.2.2", mac_s1_to_s2, mac_s2_to_s1, 2);
        AddRoutingEntry(sw, p4info_helper,
                    "10.0.3.3", mac_s1_to_s3, mac_s3_to_s1, 3);
        AddARPResponse(sw, p4info_helper, "10.0.1.100", mac_s1_to_h1);
    
    elif id == 2:
        AddEthernetEntries(sw, p4info_helper, mac_s2_to_h2, 1);
        AddEthernetEntries(sw, p4info_helper, mac_s2_to_s1, 2);
        AddEthernetEntries(sw, p4info_helper, mac_s2_to_s3, 3);
        AddRoutingEntry(sw, p4info_helper,
                    "10.0.1.1", mac_s2_to_s1, mac_s1_to_s2, 2);
        AddRoutingEntry(sw, p4info_helper,
                    "10.0.2.2", mac_s2_to_h2, mac_h2_to_s2, 1);
        AddRoutingEntry(sw, p4info_helper,
                    "10.0.3.3", mac_s2_to_s3, mac_s3_to_s2, 3);
        AddARPResponse(sw, p4info_helper, "10.0.2.100", mac_s2_to_h2);

    elif id == 3:
        AddEthernetEntries(sw, p4info_helper, mac_s3_to_h3, 1);
        AddEthernetEntries(sw, p4info_helper, mac_s3_to_s1, 2);
        AddEthernetEntries(sw, p4info_helper, mac_s3_to_s2, 3);
        AddRoutingEntry(sw, p4info_helper,
                    "10.0.1.1", mac_s3_to_s1, mac_s1_to_s3, 2);
        AddRoutingEntry(sw, p4info_helper,
                    "10.0.2.2", mac_s3_to_s2, mac_s2_to_s3, 3);
        AddRoutingEntry(sw, p4info_helper,
                    "10.0.3.3", mac_s3_to_h3, mac_h3_to_s3, 1);
        AddARPResponse(sw, p4info_helper, "10.0.3.100", mac_s3_to_h3);

    #while True:
        # This control plane is 100% static! We don't need to loop.


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='CIS553 P4Runtime Controller')

    parser.add_argument("-b", '--bmv2-json',
                        help="path to BMv2 switch description (json)",
                        type=str, action="store", default="build/basic.json")
    parser.add_argument("-c", '--p4info-file',
                        help="path to P4Runtime protobuf description (text)",
                        type=str, action="store", default="build/basic.p4info")

    args = parser.parse_args()

    if not os.path.exists(args.p4info_file):
        parser.error("File %s does not exist!" % args.p4info_file)
    if not os.path.exists(args.bmv2_json):
        parser.error("File %s does not exist!" % args.bmv2_json)
    p4info_helper = helper.P4InfoHelper(args.p4info_file)


    threads = []

    print "Connecting to P4Runtime server on s1..."
    sw1 = bmv2.Bmv2SwitchConnection('s1', "127.0.0.1:50051", 0)
    sw1.MasterArbitrationUpdate()
    sw1.SetForwardingPipelineConfig(p4info = p4info_helper.p4info,
                                    bmv2_json_file_path = args.bmv2_json)
    t = threading.Thread(target=ProgramSwitch, args=(sw1, 1, p4info_helper))
    t.start()
    threads.append(t)

    print "Connecting to P4Runtime server on s2..."
    sw2 = bmv2.Bmv2SwitchConnection('s2', "127.0.0.1:50052", 1)
    sw2.MasterArbitrationUpdate()
    sw2.SetForwardingPipelineConfig(p4info = p4info_helper.p4info,
                                    bmv2_json_file_path = args.bmv2_json)
    t = threading.Thread(target=ProgramSwitch, args=(sw2, 2, p4info_helper))
    t.start()
    threads.append(t)

    print "Connecting to P4Runtime server on s3..."
    sw3 = bmv2.Bmv2SwitchConnection('s3', "127.0.0.1:50053", 2)
    sw3.MasterArbitrationUpdate()
    sw3.SetForwardingPipelineConfig(p4info = p4info_helper.p4info,
                                    bmv2_json_file_path = args.bmv2_json)
    t = threading.Thread(target=ProgramSwitch, args=(sw3, 3, p4info_helper))
    t.start()
    threads.append(t)

    for t in threads:
        t.join()
