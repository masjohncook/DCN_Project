from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.lib.packet import vlan

# port_vlan[dpid][port]=vlan_id
port_vlan = {4: {1: 10, 2: 20},
             5: {1: 30, 2: 10},
             7: {1: 20, 2: 30},
             8: {1: 10, 2: 20},
             11: {1: 30, 2: 10},
             12: {1: 20, 2: 30},
             14: {1: 10, 2: 20},
             15: {1: 30, 2: 10},
             }


# access= {11:[1,2], 12:[1,2], 14:[1,2], 15:[1,2], 5:[1,2], 4:[1,2], 7:[1,2], 8:[1,2]}
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
        # Building the Flow Entry
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    # Helper Method for Adding Flow Entries
    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Constructing the Instructions
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        # Constructing the Flow Mod
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst)
        # Sending the Flow Mod
        datapath.send_msg(mod)

    # Packet-In Handler and Packet Dissection
    #   main logic in the controller application
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        # If you hit this you might want to increase
        # the "miss_send_length" of your switch
        # Sanity Checking for Message Length
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated: only %s of %s bytes",
                              ev.msg.msg_len, ev.msg.total_len)
        # Pulling Important Data
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            # Link Layer Discovery Protocol (LLDP)
            return
        # Learning the Source MAC
        dst = eth.dst
        src = eth.src

        # Learning the MAC Address and Associated Port
        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        # self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port

        # MAC-to-Port Lookup and Packet Destination
        # Destination Lookup
        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        # If packet is tagged,then this will have non-null value
        vlan_header = pkt.get_protocols(vlan.vlan)
        src_vlan = None

        # Checking for VLAN Tagged Packet
        if eth.ethertype == ether_types.ETH_TYPE_8021Q:
            src_vlan = vlan_header[0].vid
            vlan_num = src_vlan
            # Check if the switch is on the bottom layer
            if dpid in port_vlan:
                # Check if the destination host is in the same vlan group
                if out_port == ofproto.OFPP_FLOOD:
                    actions = [parser.OFPActionPopVlan()]
                    for port_id in port_vlan[dpid]:
                        if vlan_num == port_vlan[dpid][port_id]:
                            self.logger.info("FLOOD: dpid=%d, in_port=%d, vlan_num=%d, port_id=%d", dpid, in_port,
                                             vlan_num, port_id)
                            # match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src,vlan_vid=(src_vlan))
                            actions.append(parser.OFPActionOutput(port_id))

                elif out_port in port_vlan[dpid] and port_vlan[dpid][out_port] != vlan_num:
                    # Drop the packet
                    self.logger.info("DROP: dpid=%d, in_port=%d, vlan_num=%d, out_port=%d", dpid, in_port, vlan_num,
                                     out_port)
                    actions = []
                    match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)

                else:
                    # STRIP VLAN TAG and SEND TO OUTPUT PORT
                    self.logger.info("StripVLAN: dpid=%d, in_port=%d, vlan_num=%d, out_port=%d", dpid, in_port,
                                     vlan_num, out_port)
                    actions = [parser.OFPActionPopVlan(), parser.OFPActionOutput(out_port)]
                    match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src, vlan_vid=(0x1000 | vlan_num))

            else:
                actions = [parser.OFPActionOutput(out_port)]
                match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
        else:
            # Check VLAN ID for packets comes directly from hosts (lowest layer switches)
            src_vlan = None
            if dpid in port_vlan and in_port in port_vlan[dpid]:
                vlan_num = port_vlan[dpid][in_port]
                src_vlan = 0x1000 | vlan_num
                self.logger.info("Tagged: dpid=%d, in_port=%d, vlan_num=%d", dpid, in_port, vlan_num)
                actions = [parser.OFPActionPushVlan(33024), parser.OFPActionSetField(vlan_vid=src_vlan),
                           parser.OFPActionOutput(out_port)]
                match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
            else:
                actions = [parser.OFPActionOutput(out_port)]
                match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)

        # Adding a Flow Entry for a Learned Destination
        # install a flow to avoid packet_in next time
        # Adding a Flow Entryu  ry
        if out_port != ofproto.OFPP_FLOOD:
            # match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src, vlan_vid=(0x1000 | src_vlan))
            #     # verify if we have a valid buffer_id, if yes avoid to send both
            #     # flow_mod & packet_out
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self.add_flow(datapath, 1, match, actions, msg.buffer_id)
                return
            else:
                self.add_flow(datapath, 1, match, actions)

        # Forwarding the Packet Sent to the Controller
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)