from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ipv4, arp, tcp, ether_types


class L4StatefulLB(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(L4StatefulLB, self).__init__(*args, **kwargs)

        # Backends: each supports one or more TCP service ports
        self.backends = [
            {"ip": "10.0.0.1", "mac": "00:00:00:00:00:01", "port": 1, "services": [8080]},
            {"ip": "10.0.0.2", "mac": "00:00:00:00:00:02", "port": 2, "services": [8080, 8181]},
            {"ip": "10.0.0.3", "mac": "00:00:00:00:00:03", "port": 3, "services": [8181]},
        ]

        self.virtual_ip = "10.0.0.100"
        self.virtual_mac = "00:00:00:00:ff:ff"

        # State: { client_ip: { service_port: backend_dict } }
        self.state = {}

        # Clients: { client_ip: { mac, port } }
        self.clients = {}

        # RR index per service
        self.next_backend = {8080: 0, 8181: 0}

    # Table-miss flow
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        dp = ev.msg.datapath
        parser = dp.ofproto_parser
        ofproto = dp.ofproto

        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self._add_flow(dp, 0, match, actions)
        self.logger.info("Table-miss installed on switch %s", dp.id)

    def _add_flow(self, dp, priority, match, actions, idle_timeout=0, hard_timeout=0):
        parser = dp.ofproto_parser
        ofproto = dp.ofproto
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=dp, priority=priority,
                                match=match, instructions=inst,
                                idle_timeout=idle_timeout,
                                hard_timeout=hard_timeout)
        dp.send_msg(mod)

    # Packet-in
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

        # ARP handling
        arp_pkt = pkt.get_protocol(arp.arp)
        if arp_pkt and arp_pkt.opcode == arp.ARP_REQUEST:
            self.clients[arp_pkt.src_ip] = {"mac": eth.src, "port": in_port}
            if arp_pkt.dst_ip == self.virtual_ip:
                self._send_arp_reply(dp, eth.src, arp_pkt.src_ip, in_port,
                                     self.virtual_mac, self.virtual_ip)
                self.logger.info("ARP reply for VIP to %s", arp_pkt.src_ip)
                return
            if arp_pkt.dst_ip in self.clients:
                c = self.clients[arp_pkt.dst_ip]
                self._send_arp_reply(dp, eth.src, arp_pkt.src_ip, in_port,
                                     c["mac"], arp_pkt.dst_ip)
                return

        # IPv4
        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        if not ip_pkt:
            return

        if ip_pkt.src not in self.clients and in_port >= 4:
            self.clients[ip_pkt.src] = {"mac": eth.src, "port": in_port}

        # --- TCP ---
        tcp_pkt = pkt.get_protocol(tcp.tcp)
        if not tcp_pkt:
            return

        # Detect FIN or RST from either side and clear state
        if tcp_pkt.bits & (tcp.TCP_FIN | tcp.TCP_RST):
            self._clear_session_state(ip_pkt.src, ip_pkt.dst, tcp_pkt)
            return

        # Client -> VIP
        if ip_pkt.dst == self.virtual_ip:
            service_port = tcp_pkt.dst_port
            backend = self._select_backend(ip_pkt.src, service_port)
            if not backend:
                self.logger.warning("No backend supports service port %s", service_port)
                return

            actions = [
                parser.OFPActionSetField(ipv4_dst=backend["ip"]),
                parser.OFPActionSetField(eth_dst=backend["mac"]),
                parser.OFPActionSetField(eth_src=self.virtual_mac),
                parser.OFPActionOutput(backend["port"]),
            ]
            match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,
                                    ip_proto=6,
                                    ipv4_src=ip_pkt.src,
                                    ipv4_dst=self.virtual_ip,
                                    tcp_dst=service_port)
            self._add_flow(dp, 20, match, actions, idle_timeout=60)

            out = parser.OFPPacketOut(datapath=dp,
                                      buffer_id=ofproto.OFP_NO_BUFFER,
                                      in_port=in_port,
                                      actions=actions,
                                      data=msg.data)
            dp.send_msg(out)
            return

        # Backend -> Client
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
                                    ip_proto=6,
                                    ipv4_src=ip_pkt.src,
                                    ipv4_dst=ip_pkt.dst)
            self._add_flow(dp, 20, match, actions, idle_timeout=60)

            out = parser.OFPPacketOut(datapath=dp,
                                      buffer_id=ofproto.OFP_NO_BUFFER,
                                      in_port=in_port,
                                      actions=actions,
                                      data=msg.data)
            dp.send_msg(out)
            return

    # Backend selection
    def _select_backend(self, client_ip, service_port):
        # Return cached mapping if exists
        if client_ip in self.state and service_port in self.state[client_ip]:
            return self.state[client_ip][service_port]

        # Filter eligible servers
        eligible = [b for b in self.backends if service_port in b["services"]]
        if not eligible:
            return None

        # Round robin selection
        idx = self.next_backend.get(service_port, 0)
        backend = eligible[idx % len(eligible)]
        self.next_backend[service_port] = (idx + 1) % len(eligible)

        # Record new mapping
        if client_ip not in self.state:
            self.state[client_ip] = {}
        self.state[client_ip][service_port] = backend

        self.logger.info("New mapping: %s:%s -> %s", client_ip, service_port, backend["ip"])
        return backend

    # State cleanup
    def _clear_session_state(self, src_ip, dst_ip, tcp_pkt):
        """
        When TCP FIN or RST is seen from either side, remove that session state.
        """
        service_port = tcp_pkt.dst_port if dst_ip == self.virtual_ip else tcp_pkt.src_port

        # Remove state if known
        if src_ip in self.state and service_port in self.state[src_ip]:
            backend = self.state[src_ip].pop(service_port)
            self.logger.info("Session ended: %s:%s (backend %s)", src_ip, service_port, backend["ip"])
            if not self.state[src_ip]:
                del self.state[src_ip]
        elif dst_ip in self.state and service_port in self.state[dst_ip]:
            backend = self.state[dst_ip].pop(service_port)
            self.logger.info("Session ended (reverse): %s:%s (backend %s)", dst_ip, service_port, backend["ip"])
            if not self.state[dst_ip]:
                del self.state[dst_ip]

    # ARP reply helper
    def _send_arp_reply(self, dp, dst_mac, dst_ip, out_port, src_mac, src_ip):
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
