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
from ryu.ofproto import ofproto_v1_0
from ryu.ofproto import inet
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types


#class SimpleSwitch13(app_manager.RyuApp):
class SimpleSwitch13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    #OFP_VERSIONS = [ofproto_v1_0.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        #super(SimpleSwitch13, self).__init__(*args, **kwargs)
        super(SimpleSwitch13, self).__init__(*args, **kwargs)
        #path from switch 1 to internet router in DPID:port
        self.path1 = {1: 3, 4: 2, 5: 2}
        self.path2 = {1: 2, 2: 2, 3: 2, 4: 3, 5: 2}
        #path back
        self.path1r = {1: 1, 4: 1, 5: 1}
        self.path2r = {1: 1, 2: 1, 3: 1, 4: 2, 5: 1}
        self.switch1 = 22095312170516
        self.switch2 = 22095312165570
        self.switch3 = 22095312170183
        self.switch4 = 122196462433
        self.switch5 = 122196467835
        self.path1_s1 = 1
        self.path1_s4 = 1

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
        #actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
        #                                  ofproto.OFPCML_NO_BUFFER)]
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER)]
        self.add_flow(datapath, 0, match, actions)
        dpid = datapath.id
        if (dpid == self.switch2) | (dpid == self.switch3):
            match = parser.OFPMatch(in_port=1)
            actions = [parser.OFPActionOutput(port=2)]
            self.add_flow(datapath, 2, match, actions)
            match = parser.OFPMatch(in_port=2)
            actions = [parser.OFPActionOutput(port=1)]
            self.add_flow(datapath, 2, match, actions)
        elif dpid == self.switch5:
            #port 1 = 17, port 2=18
            match = parser.OFPMatch(in_port=17)
            actions = [parser.OFPActionOutput(port=18)]
            self.add_flow(datapath, 2, match, actions)
            match = parser.OFPMatch(in_port=18)
            actions = [parser.OFPActionOutput(port=17)]
            self.add_flow(datapath, 2, match, actions)
        elif dpid == self.switch1:
            #DHCP Rewrite
            match =  parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,  # Match IPv4 packets (0x0800)
                     ip_proto=17,        # Match UDP packets (17)
                     udp_src=68)                        # Match source port 68 (client)
            actions = [parser.OFPActionSetField(eth_dst='00:19:2f:d6:03:f1'), parser.OFPActionOutput(port=2)]
            self.add_flow(datapath, 4, match, actions)
            actions = [parser.OFPActionOutput(port=2)]
            match = parser.OFPMatch(in_port=1)
            self.add_flow(datapath, 2, match, actions)
            actions = [parser.OFPActionOutput(port=3)]
            match = parser.OFPMatch(in_port=1)
            self.add_flow(datapath, 3, match, actions)
            match = parser.OFPMatch(in_port=3)
            actions = [parser.OFPActionOutput(port=1)]
            self.add_flow(datapath, 3, match, actions)
            match = parser.OFPMatch(in_port=2)
            actions = [parser.OFPActionOutput(port=1)]
            self.add_flow(datapath, 2, match, actions)
        elif dpid == self.switch4:
            #17 is port 1, 18 port 2, 19 port 3
            actions = [parser.OFPActionOutput(port=17)]
            match = parser.OFPMatch(in_port=19)
            self.add_flow(datapath, 3, match, actions)
            match = parser.OFPMatch(in_port=18)
            actions = [parser.OFPActionOutput(port=19)]
            self.add_flow(datapath, 2, match, actions)
            match = parser.OFPMatch(in_port=19)
            actions = [parser.OFPActionOutput(port=18)]
            self.add_flow(datapath, 2, match, actions)
            match = parser.OFPMatch(in_port=17)
            actions = [parser.OFPActionOutput(port=19)]
            self.add_flow(datapath, 3, match, actions)

               

    #def add_flow(self, datapath, priority, match, actions, buffer_id=None):
    #    ofproto = datapath.ofproto
    #    parser = datapath.ofproto_parser
    #
    #    inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
    #                                         actions)]
    #    if buffer_id:
    #        mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
    #                                priority=priority, match=match,
    #                                instructions=inst)
    #    else:
    #        mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
    #                                match=match, instructions=inst)
    #    datapath.send_msg(mod)

    def add_flow(self, datapath, priority, match, actions):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        mod = datapath.ofproto_parser.OFPFlowMod(
            datapath=datapath, match=match, cookie=0,
            command=ofproto.OFPFC_ADD, idle_timeout=0, hard_timeout=0,
            priority=priority,
            #flags=ofproto.OFPFF_SEND_FLOW_REM, actions=actions)
            instructions=inst)
        datapath.send_msg(mod)


    def mod_flow(self, datapath, priority, match, actions):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        mod = datapath.ofproto_parser.OFPFlowMod(
            datapath=datapath, match=match,
            command=ofproto.OFPFC_MODIFY,
            priority=priority,
            table_id=0,
            cookie=0x0,
            #flags=ofproto.OFPFF_SEND_FLOW_REM, actions=actions)
            instructions=inst)
        datapath.send_msg(mod)
    
    def del_flow(self, datapath, priority, match, actions):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        mod = datapath.ofproto_parser.OFPFlowMod(
            datapath=datapath, match=match,
            command=ofproto.OFPFC_DELETE,
            priority=priority,
            table_id=0,
            cookie=0x0,
            out_port=ofproto.OFPP_ANY,
            out_group=ofproto.OFPP_ANY,
            #flags=ofproto.OFPFF_SEND_FLOW_REM, actions=actions)
            instructions=inst)
        datapath.send_msg(mod)



#set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
   # def _packet_in_handler(self, ev):
        # If you hit this you might want to increase
        # the "miss_send_length" of your switch
    #    if ev.msg.msg_len < ev.msg.total_len:
        #    self.logger.debug("packet truncated: only %s of %s bytes",
        #                      ev.msg.msg_len, ev.msg.total_len)
     #   msg = ev.msg
      #  datapath = msg.datapath
       # ofproto = datapath.ofproto
       # parser = datapath.ofproto_parser
       # in_port = msg.match['in_port']

       # pkt = packet.Packet(msg.data)
       # eth = pkt.get_protocols(ethernet.ethernet)[0]

       # if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
       #     return
       # dst = eth.dst
       # src = eth.src

       # dpid = datapath.id
        #self.mac_to_port.setdefault(dpid, {})

        #self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)

        # learn a mac address to avoid FLOOD next time.
        #self.mac_to_port[dpid][src] = in_port

        #if dst in self.mac_to_port[dpid]:
        #    out_port = self.mac_to_port[dpid][dst]
        #else:
        #    out_port = ofproto.OFPP_FLOOD

        #actions = [parser.OFPActionOutput(out_port)]

        # install a flow to avoid packet_in next time
        #if out_port != ofproto.OFPP_FLOOD:
        #    match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
            # verify if we have a valid buffer_id, if yes avoid to send both
            # flow_mod & packet_out
        #    if msg.buffer_id != ofproto.OFP_NO_BUFFER:
        #        self.add_flow(datapath, 1, match, actions, msg.buffer_id)
        #        return
        #    else:
        #        self.add_flow(datapath, 1, match, actions)
        #data = None
        #if msg.buffer_id == ofproto.OFP_NO_BUFFER:
        #    data = msg.data

        #out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
        #                          in_port=in_port, actions=actions, data=data)
        #datapath.send_msg(out)'''
    
    @set_ev_cls(ofp_event.EventOFPPortStatus, MAIN_DISPATCHER)
    def port_status_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        dpid = datapath.id
        ofproto = datapath.ofproto
        portnum = msg.desc.port_no
        parser = datapath.ofproto_parser

        if msg.reason == ofproto.OFPPR_ADD:
            reason = "ADD"
            #link up
            #priorities go back to normal
            if dpid == self.switch1 & portnum == 3:
                match = parser.OFPMatch(in_port=3)
                actions = [parser.OFPActionOutput(port=1)]
                self.mod_flow(datapath, 2, match, actions)
                self.logger.info("setting port 3 flows to priority 2")
            elif dpid == self.switch4 & portnum == 17:
                #17 is port 1, 18 port 2, 19 port 3
                actions = [parser.OFPActionOutput(port=17)]
                match = parser.OFPMatch(in_port=19)
                self.mod_flow(datapath, 2, match, actions)
                match = parser.OFPMatch(in_port=17)
                actions = [parser.OFPActionOutput(port=19)]
                self.mod_flow(datapath, 2, match, actions)
                self.logger.info("setting port 17 flows to priority 2")
        elif msg.reason == ofproto.OFPPR_DELETE:
            reason = "DELETE"
            #link down
            if dpid == self.switch1 & portnum == 3:
                match = parser.OFPMatch(in_port=3)
                actions = [parser.OFPActionOutput(port=1)]
                self.mod_flow(datapath, 0, match, actions)
                self.logger.info("setting flow for port 3 on dpid 1 to priority 0")
            elif dpid == self.switch4 & portnum == 17:
                #17 is port 1, 18 port 2, 19 port 3
                actions = [parser.OFPActionOutput(port=17)]
                match = parser.OFPMatch(in_port=19)
                self.mod_flow(datapath, 0, match, actions)
                match = parser.OFPMatch(in_port=17)
                actions = [parser.OFPActionOutput(port=19)]
                self.mod_flow(datapath, 0, match, actions)
                self.logger.info("setting port 1 flows on dpid 4 to priority 0")
        elif msg.reason == ofproto.OFPPR_MODIFY:
            reason = "MODIFY"
            self.logger.info("got MODIFY message for %s on %s", dpid, portnum)
            if (dpid == self.switch1) & (portnum == 3):
                if self.path1_s1 == 1:
                    match = parser.OFPMatch(in_port=1)
                    actions = [parser.OFPActionOutput(port=3)]
                    self.del_flow(datapath, 3, match, actions)
                    self.add_flow(datapath, 1, match, actions)
                    self.logger.info("setting flow for port 3 on dpid 1 to priority 1")
                    self.path1_s1 = 0
                elif self.path1_s1 == 0:
                    match = parser.OFPMatch(in_port=1)
                    actions = [parser.OFPActionOutput(port=3)]
                    self.del_flow(datapath, 1, match, actions)
                    self.add_flow(datapath, 3, match, actions)
                    self.logger.info("setting flow for port 3 on dpid 1 to priority 3")
                    self.path1_s1 = 1
            elif (dpid == self.switch4) & (portnum == 17):
                if self.path1_s4 == 1:
                    actions = [parser.OFPActionOutput(port=17)]
                    match = parser.OFPMatch(in_port=19)
                    self.del_flow(datapath, 3, match, actions)
                    self.add_flow(datapath, 1, match, actions)
                    match = parser.OFPMatch(in_port=17)
                    actions = [parser.OFPActionOutput(port=19)]
                    self.del_flow(datapath, 3, match, actions)
                    self.add_flow(datapath, 1, match, actions)
                    self.logger.info("setting port 1 flows on dpid 4 to priority 1")
                    self.path1_s4 = 0
                elif self.path1_s4 == 0:
                    actions = [parser.OFPActionOutput(port=17)]
                    match = parser.OFPMatch(in_port=19)
                    self.del_flow(datapath, 1, match, actions)
                    self.add_flow(datapath, 3, match, actions)
                    match = parser.OFPMatch(in_port=17)
                    actions = [parser.OFPActionOutput(port=19)]
                    self.del_flow(datapath, 1, match, actions)
                    self.add_flow(datapath, 3, match, actions)
                    self.logger.info("setting port 1 flows on dpid 4 to priority 3")
                    self.path1_s4 = 1
        else:
            reason = "unknown"
        
        self.logger.info('OFPortStatus received: reason: %s, desc: %s', reason, msg.desc)
    
    #@set_ev_cls(ofp_event.EventOFPStateChange, MAIN_DISPATCHER)
    #def state_change_handler(self, ev):
    #    return
