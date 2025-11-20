#!/usr/bin/env python3

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ipv4, udp
import requests, socket
from scapy.all import DNS, DNSQR, DNSRR, Ether, IP, UDP, sr1

CHECKER_URL = "http://127.0.0.1:8181/check/"
REAL_DNS = "1.1.1.1"
BLOCK_IP = "10.10.10.1"


class DNSFirewall(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(DNSFirewall, self).__init__(*args, **kwargs)
        self.domain_cache = {}

    # ---------------- DEFAULT RULES -----------------
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        dp = ev.msg.datapath
        parser = dp.ofproto_parser
        ofp = dp.ofproto

        # Send UDP/53 to controller
        match = parser.OFPMatch(eth_type=0x0800, ip_proto=17, udp_dst=53)
        actions = [parser.OFPActionOutput(ofp.OFPP_CONTROLLER,
                                          ofp.OFPCML_NO_BUFFER)]
        inst = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]

        dp.send_msg(parser.OFPFlowMod(
            datapath=dp, priority=100, match=match,
            instructions=inst
        ))

        self.logger.info("Installed DNS → controller rule")

    # ---------------- PACKET IN -----------------

    def dns_responder(self, pkt, ip):
    # Check if the packet is a DNS query and has no answers yet
        if (DNS in pkt and pkt[DNS].opcode == 0 and pkt[DNS].ancount == 0):
            spoofed_response = Ether(dst=pkt[Ether].src, src=pkt[Ether].dst)/IP(dst=pkt[IP].src, src=pkt[IP].dst)/ \
                           UDP(dport=pkt[UDP].sport, sport=53)/ \
                           DNS(id=pkt[DNS].id, qr=1, aa=1, rd=1, ra=1,
                               qd=pkt[DNS].qd,
                               an=DNSRR(rrname=pkt[DNSQR].qname, ttl=10, rdata=ip))

            return spoofed_response
        return None


    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):

        msg = ev.msg
        dp = msg.datapath
        ofp = dp.ofproto
        parser = dp.ofproto_parser

        raw = msg.data
        pkt = packet.Packet(raw)
        ether_pkt = Ether(raw)
        eth = pkt.get_protocol(ethernet.ethernet)
        ip = pkt.get_protocol(ipv4.ipv4)
        udp_pkt = pkt.get_protocol(udp.udp)

        if not (ip and udp_pkt and udp_pkt.dst_port == 53):
            return

        try:
            sc = ether_pkt[DNS]
            if not sc.qd.qname.decode('utf-8'):
                return  # not a query
            qname =  sc.qd.qname.decode('utf-8').rstrip('.')
        except Exception as e:
            self.logger.error("Scapy failed DNS parse: %s", e)
            return

        self.logger.info(f"DNS Query Intercepted via Scapy: {qname}")

        # ---------------- SITE CHECKER -----------------
        if qname not in self.domain_cache:
            try:
                r = requests.get(CHECKER_URL + qname)
                result = r.json().get("result", "unknown")
            except:
                result = "unknown"
            self.domain_cache[qname] = result

        result = self.domain_cache[qname]
        self.logger.info(f"DNS classifier: {qname} → {result}")

        # ---------------- DECISION -----------------
        if result == "bad":
            self.logger.info(f"Sending FAKE reply for: {qname}")
            payload = self.dns_responder(ether_pkt, BLOCK_IP)
            self.send_dns_reply(dp, payload)
            return

        # Otherwise forward to real DNS
        real_ip = self.query_real_dns(sc)
        if real_ip:
            self.logger.info(f"Real DNS: {qname} → {real_ip}")
            payload = self.dns_responder(ether_pkt, real_ip)
            self.send_dns_reply(dp, payload)
        else:
            self.logger.warning(f"Real DNS lookup failed for {qname}")

    # ---------------- REAL DNS FORWARD -----------------
    def query_real_dns(self, scapy_query):
        #try:
        ip_address = socket.gethostbyname(scapy_query.qd.qname.decode('utf-8').rstrip('.'))
        return ip_address

    
    # ---------------- DNS REPLY (FAKE or REAL) -----------------
    def send_dns_reply(self, dp, payload):
        parser = dp.ofproto_parser
        ofp = dp.ofproto
        payload_bytes=bytes(payload)
        actions = [parser.OFPActionOutput(1)]

        out = parser.OFPPacketOut(
            datapath=dp,
            buffer_id=ofp.OFP_NO_BUFFER,
            in_port=ofp.OFPP_CONTROLLER,
            actions=actions,
            data=payload_bytes
        )
        dp.send_msg(out)
