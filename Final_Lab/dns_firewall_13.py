#!/usr/bin/env python3
"""
Ryu SDN app: DNS Firewall with site-checker and fake reply injection
Author: Danny Vaughan (CSCI SDN Lab)

Behavior:
- Intercepts DNS queries from any host.
- For each domain:
    * Query local Flask checker (http://127.0.0.1:8080/check/<domain>)
    * If "bad"  -> Send fake DNS reply mapping to 10.0.0.254 ("blocked site")
    * If "good" -> Forward DNS query to 8.8.8.8, return real reply.
    * If "unknown" -> Forward to 8.8.8.8 and allow.
"""

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ipv4, udp, dns
import requests, socket

CHECKER_URL = "http://127.0.0.1:8080/check/"  # Flask checker
REAL_DNS = "8.8.8.8"                           # real resolver
BLOCK_IP = "10.0.0.254"                        # your "blocked site" page

class DNSFirewall(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(DNSFirewall, self).__init__(*args, **kwargs)
        self.domain_cache = {}

    # -------------------- Default Rules --------------------
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        dp = ev.msg.datapath
        parser = dp.ofproto_parser
        ofp = dp.ofproto

        # DNS packets → controller
        match = parser.OFPMatch(eth_type=0x0800, ip_proto=17, udp_dst=53)
        actions = [parser.OFPActionOutput(ofp.OFPP_CONTROLLER, ofp.OFPCML_NO_BUFFER)]
        inst = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]
        dp.send_msg(parser.OFPFlowMod(datapath=dp, priority=100, match=match, instructions=inst))

        self.logger.info("Default rule installed: send UDP/53 to controller")

    # -------------------- Packet Handling --------------------
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        dp = msg.datapath
        pkt = packet.Packet(msg.data)
        eth_pkt = pkt.get_protocol(ethernet.ethernet)
        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        udp_pkt = pkt.get_protocol(udp.udp)
        dns_pkt = pkt.get_protocol(dns.dns)

        if not dns_pkt or dns_pkt.qr != 0:
            return  # Only process DNS queries

        qname = dns_pkt.qd.name.lower() if dns_pkt.qd else None
        if not qname:
            return

        in_port = msg.match["in_port"]
        self.logger.info(f"DNS Query intercepted: {qname}")

        # -------------------- Site Checker --------------------
        result = self.domain_cache.get(qname)
        if not result:
            try:
                r = requests.get(CHECKER_URL + qname)
                result = r.json().get("result", "unknown")
                self.domain_cache[qname] = result
            except Exception as e:
                self.logger.error(f"Checker request failed: {e}")
                result = "unknown"

        self.logger.info(f"Domain {qname} classified as {result}")

        # -------------------- Decision --------------------
        if result == "bad":
            self.logger.info(f"Sending fake reply for blocked domain: {qname}")
            self.send_fake_dns_reply(dp, in_port, eth_pkt.src, eth_pkt.dst,
                                     ip_pkt.dst, ip_pkt.src, dns_pkt, BLOCK_IP)
            return

        # Otherwise query real DNS and forward result
        real_ip = self.query_real_dns(pkt)
        if real_ip:
            self.logger.info(f"{qname} resolved via 8.8.8.8 → {real_ip}")
            self.send_real_dns_reply(dp, in_port, eth_pkt.src, eth_pkt.dst,
                                     ip_pkt.dst, ip_pkt.src, dns_pkt, real_ip)
        else:
            self.logger.warning(f"Could not resolve {qname} via 8.8.8.8")

    # -------------------- DNS Forwarding --------------------
    def query_real_dns(self, pkt):
        """Send real DNS query to 8.8.8.8 and parse reply."""
        try:
            raw_dns = pkt.protocols[-1].to_bytes()
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(3)
            sock.sendto(raw_dns, (REAL_DNS, 53))
            data, _ = sock.recvfrom(4096)
            sock.close()

            p = packet.Packet(data)
            dns_reply = p.get_protocol(dns.dns)
            if dns_reply and dns_reply.an:
                for ans in dns_reply.an:
                    if ans.type == dns.DNS_A:
                        return ans.rdata
        except Exception as e:
            self.logger.error(f"DNS forward error: {e}")
        return None

    # -------------------- Fake DNS Reply --------------------
    def send_fake_dns_reply(self, dp, in_port, eth_src, eth_dst, ip_src, ip_dst, dns_query, blocked_ip):
        parser = dp.ofproto_parser
        ofp = dp.ofproto

        answer = dns.dns.answer(
            name=dns_query.qd.name,
            type=dns.DNS_A,
            cls=1,
            ttl=60,
            rdlen=4,
            rdata=blocked_ip
        )

        dns_reply = dns.dns(
            id=dns_query.id,
            qr=1, aa=1, rd=1, ra=1,
            qd=dns_query.qd,
            an=[answer]
        )

        udp_reply = udp.udp(src_port=53, dst_port=udp.udp.SRC_PORT)
        ip_reply = ipv4.ipv4(proto=17, src=ip_src, dst=ip_dst)
        eth_reply = ethernet.ethernet(dst=eth_src, src=eth_dst, ethertype=0x0800)

        pkt_out = packet.Packet()
        pkt_out.add_protocol(eth_reply)
        pkt_out.add_protocol(ip_reply)
        pkt_out.add_protocol(udp_reply)
        pkt_out.add_protocol(dns_reply)
        pkt_out.serialize()

        actions = [parser.OFPActionOutput(in_port)]
        out = parser.OFPPacketOut(datapath=dp, buffer_id=ofp.OFP_NO_BUFFER,
                                  in_port=ofp.OFPP_CONTROLLER,
                                  actions=actions, data=pkt_out.data)
        dp.send_msg(out)

    # -------------------- Real DNS Reply Forward --------------------
    def send_real_dns_reply(self, dp, in_port, eth_src, eth_dst, ip_src, ip_dst, dns_query, real_ip):
        parser = dp.ofproto_parser
        ofp = dp.ofproto

        answer = dns.dns.answer(
            name=dns_query.qd.name,
            type=dns.DNS_A,
            cls=1,
            ttl=300,
            rdlen=4,
            rdata=real_ip
        )

        dns_reply = dns.dns(
            id=dns_query.id,
            qr=1, aa=1, rd=1, ra=1,
            qd=dns_query.qd,
            an=[answer]
        )

        udp_reply = udp.udp(src_port=53, dst_port=udp.udp.SRC_PORT)
        ip_reply = ipv4.ipv4(proto=17, src=ip_src, dst=ip_dst)
        eth_reply = ethernet.ethernet(dst=eth_src, src=eth_dst, ethertype=0x0800)

        pkt_out = packet.Packet()
        pkt_out.add_protocol(eth_reply)
        pkt_out.add_protocol(ip_reply)
        pkt_out.add_protocol(udp_reply)
        pkt_out.add_protocol(dns_reply)
        pkt_out.serialize()

        actions = [parser.OFPActionOutput(in_port)]
        out = parser.OFPPacketOut(datapath=dp, buffer_id=ofp.OFP_NO_BUFFER,
                                  in_port=ofp.OFPP_CONTROLLER,
                                  actions=actions, data=pkt_out.data)
        dp.send_msg(out)
