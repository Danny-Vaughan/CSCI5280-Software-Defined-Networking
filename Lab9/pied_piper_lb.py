from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ipv4, arp, ether_types


class RoundRobinLB(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(RoundRobinLB, self).__init__(*args, **kwargs)

        # Backend pool (3 servers)
        self.backends = [
            {"ip": "10.0.0.1", "mac": "00:00:00:00:00:01", "port": 1},
            {"ip": "10.0.0.2", "mac": "00:00:00:00:00:02", "port": 2},
            {"ip": "10.0.0.3", "mac": "00:00:00:00:00:03", "port": 3},
        ]

        # Virtual IP and MAC (VIP)
        self.virtual_ip = "10.0.0.100"
        self.virtual_mac = "00:00:00:00:ff:ff"

        # Per-client rotation
        # self.client_rr = { "10.0.0.4": 0, "10.0.0.5": 2, ... }
        self.client_rr = {}

        # Dynamic client table: { "10.0.0.4": {"mac": "...", "port": 4}, ... }
        self.clients = {}

    # Table-miss flow
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        dp = ev.msg.datapath
        parser = dp.ofproto_parser
        ofproto = dp.ofproto
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(dp, 0, match, actions)
        self.logger.info("Table-miss flow installed on switch %s", dp.id)

    # Add flow helper
    def add_flow(self, dp, priority, match, actions, idle_timeout=0, hard_timeout=0):
        parser = dp.ofproto_parser
        ofproto = dp.ofproto
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=dp, priority=priority,
                                match=match, instructions=inst,
                                idle_timeout=idle_timeout,
                                hard_timeout=hard_timeout)
        dp.send_msg(mod)

    # Packet-in handler
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        dp = msg.datapath
        parser = dp.ofproto_parser
        ofproto = dp.ofproto
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        # Handle ARP
        arp_pkt = pkt.get_protocol(arp.arp)
        if arp_pkt and arp_pkt.opcode == arp.ARP_REQUEST:
            # learn client
            self.clients[arp_pkt.src_ip] = {"mac": eth.src, "port": in_port}

            # Client asking for VIP
            if arp_pkt.dst_ip == self.virtual_ip:
                self.logger.info("Replying to ARP for VIP %s from client %s (port %s)",
                                 self.virtual_ip, arp_pkt.src_ip, in_port)
                self._send_arp_reply(dp, eth.src, arp_pkt.src_ip, in_port,
                                     self.virtual_mac, self.virtual_ip)
                return

            # Backend asking for client
            if arp_pkt.dst_ip in self.clients:
                c = self.clients[arp_pkt.dst_ip]
                self.logger.info("Replying to ARP for client %s from backend %s (port %s)",
                                 arp_pkt.dst_ip, arp_pkt.src_ip, in_port)
                self._send_arp_reply(dp, eth.src, arp_pkt.src_ip, in_port,
                                     c["mac"], arp_pkt.dst_ip)
                return


        # Handle IPv4
        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        if not ip_pkt:
            return

        # learn new client
        if ip_pkt.src not in self.clients and in_port >= 4:
            self.clients[ip_pkt.src] = {"mac": eth.src, "port": in_port}
            self.logger.info("Learned new client %s at port %s", ip_pkt.src, in_port)


        # Client → VIP
        if ip_pkt.dst == self.virtual_ip:
            # get or initialize client rotation index
            idx = self.client_rr.get(ip_pkt.src, 0)
            backend = self.backends[idx]
            # update client-specific index
            self.client_rr[ip_pkt.src] = (idx + 1) % len(self.backends)

            self.logger.info("Client %s -> VIP %s -> backend %s (port %s) [rr=%s]",
                             ip_pkt.src, self.virtual_ip,
                             backend["ip"], backend["port"], self.client_rr[ip_pkt.src])

            actions = [
                parser.OFPActionSetField(ipv4_dst=backend["ip"]),
                parser.OFPActionSetField(eth_dst=backend["mac"]),
                parser.OFPActionSetField(eth_src=self.virtual_mac),
                parser.OFPActionOutput(backend["port"]),
            ]
            match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,
                                    ipv4_dst=self.virtual_ip,
                                    ipv4_src=ip_pkt.src)
            self.add_flow(dp, 10, match, actions, idle_timeout=30)

            out = parser.OFPPacketOut(datapath=dp,
                                      buffer_id=ofproto.OFP_NO_BUFFER,
                                      in_port=in_port,
                                      actions=actions,
                                      data=msg.data)
            dp.send_msg(out)
            return

        
        # Backend → Client
        backend_ips = [b["ip"] for b in self.backends]
        if ip_pkt.src in backend_ips and ip_pkt.dst in self.clients:
            c = self.clients[ip_pkt.dst]
            actions = [
                parser.OFPActionSetField(ipv4_src=self.virtual_ip),
                parser.OFPActionSetField(eth_src=self.virtual_mac),
                parser.OFPActionSetField(eth_dst=c["mac"]),
                parser.OFPActionOutput(c["port"]),
            ]
            match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,
                                    ipv4_src=ip_pkt.src,
                                    ipv4_dst=ip_pkt.dst)
            self.add_flow(dp, 10, match, actions, idle_timeout=30)

            out = parser.OFPPacketOut(datapath=dp,
                                      buffer_id=ofproto.OFP_NO_BUFFER,
                                      in_port=in_port,
                                      actions=actions,
                                      data=msg.data)
            dp.send_msg(out)
            return


    # Send ARP reply helper
    def _send_arp_reply(self, dp, dst_mac, dst_ip, out_port,
                        src_mac, src_ip):
        parser = dp.ofproto_parser
        ofproto = dp.ofproto

        e = ethernet.ethernet(ethertype=ether_types.ETH_TYPE_ARP,
                              dst=dst_mac, src=src_mac)
        a = arp.arp(opcode=arp.ARP_REPLY,
                    src_mac=src_mac, src_ip=src_ip,
                    dst_mac=dst_mac, dst_ip=dst_ip)

        pkt = packet.Packet()
        pkt.add_protocol(e)
        pkt.add_protocol(a)
        pkt.serialize()

        actions = [parser.OFPActionOutput(out_port)]
        out = parser.OFPPacketOut(datapath=dp,
                                  buffer_id=ofproto.OFP_NO_BUFFER,
                                  in_port=ofproto.OFPP_CONTROLLER,
                                  actions=actions,
                                  data=pkt.data)
        dp.send_msg(out)
        self.logger.info("Sent ARP reply: %s is-at %s -> %s (%s) via port %s",
                         src_ip, src_mac, dst_ip, dst_mac, out_port)
