#!/usr/bin/env python3
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_0
from ryu.lib.packet import packet, ethernet, ipv4, udp, dns
import socket, requests

CHECKER_URL = "http://127.0.0.1:8080/check/"
REAL_DNS = "8.8.8.8"
BLOCK_IP = "10.0.0.254"

class DNSFirewall10(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_0.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(DNSFirewall10, self).__init__(*args, **kwargs)
        self.cache = {}

    # install base rule
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features(self, ev):
        dp = ev.msg.datapath
        ofp, parser = dp.ofproto, dp.ofproto_parser
        match = parser.OFPMatch(dl_type=0x0800, nw_proto=17, tp_dst=53)
        actions = [parser.OFPActionOutput(ofp.OFPP_CONTROLLER, ofp.OFPCML_NO_BUFFER)]
        dp.send_msg(parser.OFPFlowMod(datapath=dp, match=match, actions=actions))
        self.logger.info("OF1.0: capture UDP/53 → controller")

    # handle packets
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def pkt_in(self, ev):
        msg, dp = ev.msg, ev.msg.datapath
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        ip = pkt.get_protocol(ipv4.ipv4)
        udp_pkt = pkt.get_protocol(udp.udp)
        dns_pkt = pkt.get_protocol(dns.dns)
        if not dns_pkt or dns_pkt.qr != 0:
            return

        qname = dns_pkt.qd.name.lower()
        self.logger.info(f"DNS query for {qname}")

        # check site classification
        status = self.cache.get(qname)
        if not status:
            try:
                r = requests.get(CHECKER_URL + qname)
                status = r.json().get("result", "unknown")
                self.cache[qname] = status
            except Exception as e:
                status = "unknown"

        if status == "bad":
            self.logger.info(f"BAD site {qname}, sending fake reply")
            self.fake_reply(dp, msg.in_port, eth, ip, dns_pkt)
        else:
            ipaddr = self.query_real_dns(pkt)
            if ipaddr:
                self.real_reply(dp, msg.in_port, eth, ip, dns_pkt, ipaddr)

    # forward to 8.8.8.8
    def query_real_dns(self, pkt):
        try:
            raw = pkt.protocols[-1].to_bytes()
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(3)
            s.sendto(raw, (REAL_DNS, 53))
            data, _ = s.recvfrom(2048)
            s.close()
            p = packet.Packet(data)
            d = p.get_protocol(dns.dns)
            if d and d.an:
                for a in d.an:
                    if a.type == dns.DNS_A:
                        return a.rdata
        except Exception as e:
            self.logger.error(f"DNS forward error: {e}")
        return None

    # fake DNS reply
    def fake_reply(self, dp, in_port, eth, ip, dns_q):
        self.logger.debug("Injecting fake DNS reply")
        ofp, parser = dp.ofproto, dp.ofproto_parser
        ans = dns.dns.answer(name=dns_q.qd.name, type=dns.DNS_A, cls=1, ttl=60, rdlen=4, rdata=BLOCK_IP)
        dns_r = dns.dns(id=dns_q.id, qr=1, aa=1, rd=1, ra=1, qd=dns_q.qd, an=[ans])
        udp_r = udp.udp(src_port=53, dst_port=udp.udp.SRC_PORT)
        ip_r = ipv4.ipv4(proto=17, src=ip.dst, dst=ip.src)
        eth_r = ethernet.ethernet(dst=eth.src, src=eth.dst, ethertype=0x0800)
        p = packet.Packet()
        p.add_protocol(eth_r); p.add_protocol(ip_r); p.add_protocol(udp_r); p.add_protocol(dns_r)
        p.serialize()
        actions = [parser.OFPActionOutput(in_port)]
        dp.send_msg(parser.OFPPacketOut(datapath=dp, buffer_id=ofp.OFP_NO_BUFFER,
                                        in_port=ofp.OFPP_CONTROLLER,
                                        actions=actions, data=p.data))

    # real DNS reply to host
    def real_reply(self, dp, in_port, eth, ip, dns_q, ipaddr):
        ofp, parser = dp.ofproto, dp.ofproto_parser
        ans = dns.dns.answer(name=dns_q.qd.name, type=dns.DNS_A, cls=1, ttl=300, rdlen=4, rdata=ipaddr)
        dns_r = dns.dns(id=dns_q.id, qr=1, aa=1, rd=1, ra=1, qd=dns_q.qd, an=[ans])
        udp_r = udp.udp(src_port=53, dst_port=udp.udp.SRC_PORT)
        ip_r = ipv4.ipv4(proto=17, src=ip.dst, dst=ip.src)
        eth_r = ethernet.ethernet(dst=eth.src, src=eth.dst, ethertype=0x0800)
        p = packet.Packet()
        p.add_protocol(eth_r); p.add_protocol(ip_r); p.add_protocol(udp_r); p.add_protocol(dns_r)
        p.serialize()
        actions = [parser.OFPActionOutput(in_port)]
        dp.send_msg(parser.OFPPacketOut(datapath=dp, buffer_id=ofp.OFP_NO_BUFFER,
                                        in_port=ofp.OFPP_CONTROLLER,
                                        actions=actions, data=p.data))
