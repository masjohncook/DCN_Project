# Copyright (C) 2011 Nippon Telegraph and Telephone Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.lib.packet import vlan

#Initiating VLAN configuration
port_vlan = {4:{1:[30], 2:[20], 3:[30,20]},
             5:{1:[10], 2:[30], 3:[10,30]},
             7:{1:[30], 2:[20], 3:[20,30]},
             8:{1:[20], 2:[10], 3:[10.20]},
             11:{1:[20], 2:[10], 3:[10,20]},
             12:{1:[30], 2:[20], 3:[20,30]},
             14:{1:[10], 2:[30], 3:[10,30]},
             15:{1:[10], 2:[20], 3:[10,20]}
             }

access = {4:[1, 2],
          5:[1, 2],
          7:[1, 2],
          8:[1, 2],
          11:[1, 2],
          12:[1, 2],
          14:[1, 2],
          15:[1, 2]}

trunk = {5:[1, 2, 3],
         6:[1, 2, 3],
         10:[1, 2, 3],
         13:[1, 2, 3],
         9:[1, 2, 3],
         2:[1, 2, 3],
         1:[1, 2]
         }



class SimpleSwitch13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch13, self).__init__(*args, **kwargs)
        self.mac_to_port = {}

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # install table-miss flow entry
        #
        # We specify NO BUFFER to max_len of the output action due to
        # OVS bug. At this moment, if we specify a lesser number, e.g.,
        # 128, OVS will send Packet-In with invalid buffer_id and
        # truncated packet data. In that case, we cannot output packets
        # correctly.  The bug has been fixed in OVS v2.1.0.
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst)
        datapath.send_msg(mod)

    def vlan_membership(self, dpid, in_port, src_vlan):
        B =[]
        self.access_ports = []
        self.trunk_ports = []

        if src_vlan == "NULL":
            return

        for item in port_vlan[dpid]:
            vlans = port_vlan[dpid][item]
            if src_vlan in vlans and item != in_port:
                B.append(item)
        for port in B:
            if port in access[dpid]:
                self.access_ports.append(port)
            else:
                self.trunk_ports.append(port)

    def getActionsArrayTrunk(self, out_port_access, out_port_trunk, parser):
        actions = []

        for port in out_port_trunk:
            actions.append(parser.OFPActionOutput(port))

        actions.append(parser.OFPActionPopVlan())

        for port in out_port_access:
            actions.append(parser.OFPActionOutput(port))

        return actions

    def getActionArrayAccess(self, out_port_access, out_port_trunk, src_vlan, parser):
        actions = []

        for port in out_port_access:
            actions.append(parser.OFPActionOutput(port))

        actions.append(parser.OFPActionPushVlan(33024))
        actions.append(parser.OFPActionSetField(vlan_vid=src_vlan))

        for port in out_port_trunk:
            actions.append(parser.OFPActionOutput(port))

        return actions

    def getActionsNormalUntagged(self, dpid, in_port, parser):
        actions = []

        for port in port_vlan[dpid]:
            if port_vlan[dpid][port][0] == " " and port != in_port:
                actions.append(parser.OFPActionOutput(port))

        if dpid in trunk:
            for port in trunk[dpid]:
                if port != in_port:
                    actions.append(parser.OFPActionOutput(port))

        return  actions

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        # If you hit this you might want to increase
        # the "miss_send_length" of your switch
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated: only %s of %s bytes",
                              ev.msg.msg_len, ev.msg.total_len)
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        dpid = datapath.id

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        vlan_header = pkt.get_protocols(vlan.vlan)

        if eth.ethertype == ether_types.ETH_TYPE_8021Q:
            vlan_header_present = 1
            src_vlan = vlan_header[0].vid
        elif dpid not in port_vlan:
            vlan_header_present = 0
            in_port_type = "NORMAL SWITCH"
            src_vlan = "NULL"
        else:
            vlan_header_present = 0
            src_vlan = port_vlan[dpid][in_port][0]


        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return
        dst = eth.dst
        src = eth.src

        #dpid = format(datapath.id, "d").zfill(16)
        self.mac_to_port.setdefault(dpid, {})

        self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port

        self.vlan_membership(dpid, in_port, src_vlan)

        if dst in self.mac_to_port[dpid]:
            out_port_unknown = 0
            out_port = self.mac_to_port[dpid][dst]
            if src_vlan != "NULL":
                if out_port in access[dpid]:
                    out_port_type = "ACCESS"
                else:
                    out_port_type = "TRUNK"
            else:
                out_port_type = "NORMAL"
        else:
            out_port_unknown = 1
            out_port_access = self.access_ports
            out_port_trunk = self.trunk_ports

            #out_port = ofproto.OFPP_FLOOD

        # actions = [parser.OFPActionOutput(out_port)]

        if out_port_unknown != 1:
            if vlan_header_present and out_port_type == "ACCESS":
                match = parser.OFPMatch(in_port=in_port, eth_dst=dst, vlan_vid=(0x1000 | src_vlan))
                actions = [parser.OFPActionPopVlan(),
                           parser.OFPActionOutput(out_port)]
            elif vlan_header_present and out_port_type == "TRUNK":
                match = parser.OFPMatch(in_port=in_port, eth_dst=dst, vlan_vid=(0x1000 | src_vlan))
                actions = [parser.OFPActionOutput(out_port)]
            elif vlan_header_present != 1 and out_port_type == "TRUNK":
                match = parser.OFPMatch(in_port=in_port, eth_dst=dst)
                actions = [parser.OFPActionPushVlan(33024),
                           parser.OFPActionSetField(vlan_vid=src_vlan),
                           parser.OFPActionOutput(out_port)]
            else:
                match = parser.OFPMatch(in_port=in_port, eth_dst=dst)
                actions = [parser.OFPActionOutput(out_port)]


            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self.add_flow(datapath, 1, match, actions, msg.buffer_id)
                return
            else:
                self.add_flow(datapath, 1, match, actions)

        else:
            if vlan_header_present:
                actions = self.getActionsArrayTrunk(out_port_access, out_port_trunk, parser)
            elif vlan_header_present == 0 and src_vlan != "NULL":
                actions = self.getActionArrayAccess(out_port_access, out_port_trunk, src_vlan, parser)
            elif in_port_type == "NORMAL UNTAGGED":
                actions = self. getActionsNormalUntagged(dpid, in_port, parser)
            else:
                actions = [parser.OFPActionOutput(ofproto.OFPP_FLOOD)]

        # install a flow to avoid packet_in next time
        # if out_port != ofproto.OFPP_FLOOD:
        #     match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
        #     # verify if we have a valid buffer_id, if yes avoid to send both
        #     # flow_mod & packet_out
        #     if msg.buffer_id != ofproto.OFP_NO_BUFFER:
        #         self.add_flow(datapath, 1, match, actions, msg.buffer_id)
        #         return
        #     else:
        #         self.add_flow(datapath, 1, match, actions)
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)