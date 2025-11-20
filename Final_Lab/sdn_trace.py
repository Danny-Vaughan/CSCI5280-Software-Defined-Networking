#!/usr/bin/env python3

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import (MAIN_DISPATCHER, CONFIG_DISPATCHER, DEAD_DISPATCHER, set_ev_cls)
from ryu.ofproto import ofproto_v1_3, ofproto_v1_3_parser
from ryu.lib.packet import packet, ethernet, ipv4, icmp
from ryu.controller import dpset
from ryu.app.wsgi import ControllerBase, WSGIApplication, route

TRACE_INSTANCE = "trace_api"


class IcmpPathTracer(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    _CONTEXTS = {
        'wsgi': WSGIApplication,
        'dpset': dpset.DPSet,
    }

    def __init__(self, *args, **kwargs):
        super(IcmpPathTracer, self).__init__(*args, **kwargs)

        wsgi = kwargs['wsgi']
        self.dpset = kwargs['dpset']

        # Track all datapaths
        self.datapaths = {}

        # For tracing
        self.trace = []
        self.pending = {}
        self.seen_hops = set()
        self.finished = False
        self.tracing = False

        # Track which switches have ICMP punt rules
        self.icmp_flows_installed = set()

        self.MAX_HOPS = 64

        wsgi.register(TraceAPI, {TRACE_INSTANCE: self})
        self.logger.info("ICMP Path Tracer initialized (on-demand mode).")

    # ----------------------------------------------------------------------
    # Datapath register / unregister
    # ----------------------------------------------------------------------
    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        dp = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            self.datapaths[dp.id] = dp
            self.logger.info("Datapath %016x registered", dp.id)
        elif ev.state == DEAD_DISPATCHER:
            if dp.id in self.datapaths:
                self.logger.info("Datapath %016x unregistered", dp.id)
                del self.datapaths[dp.id]

    # ----------------------------------------------------------------------
    # SwitchFeatures: install ONLY the table-miss rule
    # ----------------------------------------------------------------------
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        dp = ev.msg.datapath
        ofp = dp.ofproto
        parser = dp.ofproto_parser

        # Table-miss rule sends unknown packets to controller
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofp.OFPP_CONTROLLER,
                                          ofp.OFPCML_NO_BUFFER)]
        inst = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]

        mod = parser.OFPFlowMod(
            datapath=dp,
            priority=0,
            match=match,
            instructions=inst
        )
        dp.send_msg(mod)
        self.logger.info("Installed table-miss rule on %016x", dp.id)

    # ----------------------------------------------------------------------
    # Install ICMP punt flows when trace starts
    # ----------------------------------------------------------------------
    def install_icmp_flows(self):
        for dpid, dp in self.datapaths.items():
            ofp = dp.ofproto
            parser = dp.ofproto_parser

            match_icmp = parser.OFPMatch(eth_type=0x0800, ip_proto=1)
            actions = [parser.OFPActionOutput(ofp.OFPP_CONTROLLER,
                                              ofp.OFPCML_NO_BUFFER)]
            inst = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]
            mod = parser.OFPFlowMod(
                datapath=dp,
                priority=200,
                match=match_icmp,
                instructions=inst
            )
            dp.send_msg(mod)
            self.icmp_flows_installed.add(dpid)
            self.logger.info("Installed ICMP punt rule on %016x", dpid)

    # ----------------------------------------------------------------------
    # Remove ICMP punt flows
    # ----------------------------------------------------------------------
    def _remove_icmp_flows_all(self):
        self.logger.info("Removing ICMP punt flows from all switches...")
        for dpid, dp in self.datapaths.items():
            ofp = dp.ofproto
            parser = dp.ofproto_parser

            match = parser.OFPMatch(eth_type=0x0800, ip_proto=1)
            mod = parser.OFPFlowMod(
                datapath=dp,
                command=ofp.OFPFC_DELETE,
                out_port=ofp.OFPP_ANY,
                out_group=ofp.OFPG_ANY,
                match=match,
                instructions=[]
            )
            dp.send_msg(mod)
            self.logger.info("Removed ICMP punt rule from %016x", dpid)

    # ----------------------------------------------------------------------
    # PacketIn handler
    # ----------------------------------------------------------------------
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):

        # Only process PacketIns when tracing is enabled
        if not self.tracing or self.finished:
            return

        msg = ev.msg
        dp = msg.datapath
        in_port = msg.match.get('in_port')

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        if eth is None:
            return

        if eth.ethertype != 0x0800:
            return

        ip = pkt.get_protocol(ipv4.ipv4)
        if ip is None or ip.proto != 1:
            return

        icmp_pkt = pkt.get_protocol(icmp.icmp)
        if icmp_pkt is None or icmp_pkt.type != icmp.ICMP_ECHO_REQUEST:
            return

        src_ip = ip.src
        dst_ip = ip.dst

        self.logger.info("ICMP Echo Request: %s -> %s dp=%016x in_port=%s",
                         src_ip, dst_ip, dp.id, in_port)

        # Save context for FlowStatsReply
        self.pending[dp.id] = {
            'msg': msg,
            'in_port': in_port,
            'src_ip': src_ip,
            'dst_ip': dst_ip
        }

        # Request flow table for this switch
        parser = dp.ofproto_parser
        req = parser.OFPFlowStatsRequest(dp)
        dp.send_msg(req)

    # ----------------------------------------------------------------------
    # FlowStatsReply handler with specificity logic
    # ----------------------------------------------------------------------
    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def flow_stats_reply_handler(self, ev):

        if not self.tracing or self.finished:
            return

        dp = ev.msg.datapath
        ofp = dp.ofproto
        parser = dp.ofproto_parser

        ctx = self.pending.pop(dp.id, None)
        if ctx is None:
            return

        in_port = ctx['in_port']
        msg = ctx['msg']
        body = ev.msg.body

        best_flow = None
        best_priority = -1
        best_spec = -1
        best_out_port = None

        for stat in body:
            # Must match the correct ingress port
            if stat.match.get('in_port') != in_port:
                continue

            # Look for a forwarding action (skip controller/local)
            out_port = None
            for inst in stat.instructions:
                if isinstance(inst, ofproto_v1_3_parser.OFPInstructionActions):
                    for a in inst.actions:
                        if isinstance(a, ofproto_v1_3_parser.OFPActionOutput):
                            if a.port in (ofp.OFPP_CONTROLLER, ofp.OFPP_LOCAL):
                                continue
                            out_port = a.port
                            break
                if out_port is not None:
                    break

            if out_port is None:
                continue

            # Compute specificity score safely
            m = stat.match
            cand_spec = 0

            # eth_type specificity
            eth_type = m.get('eth_type')
            if eth_type is not None:
                cand_spec += 10
                if eth_type == 0x0800:  # IPv4
                    cand_spec += 10

            # ip_proto specificity
            ip_proto = m.get('ip_proto')
            if ip_proto is not None:
                cand_spec += 10
                if ip_proto == 1:       # ICMP
                    cand_spec += 20

            # Extra fields beyond basic in_port/eth_type/ip_proto
            extra = 0
            try:
                # Arista EOS + Ryu: OFPMatch supports .items()
                for k, v in m.items():
                    if k not in ('in_port', 'eth_type', 'ip_proto'):
                        extra += 1
            except Exception:
                # If match type is weird, just ignore extras
                pass

            cand_spec += 5 * extra

            # Decide if this candidate is better
            if (best_flow is None or
                stat.priority > best_priority or
                (stat.priority == best_priority and cand_spec > best_spec)):
                best_flow = stat
                best_priority = stat.priority
                best_spec = cand_spec
                best_out_port = out_port

        if best_flow is None or best_out_port is None:
            self.logger.info(
                "No suitable forwarding flow for dp=%016x in_port=%s - ending trace",
                dp.id, in_port
            )
            self._finish_trace()
            return

        hop = (dp.id, in_port, best_out_port)
        self.logger.info("Hop: dp=%016x in_port=%s -> out_port=%s (prio=%d spec=%d)",
                         dp.id, in_port, best_out_port, best_priority, best_spec)

        # Loop detection
        if hop in self.seen_hops:
            self.logger.info("Loop detected — finishing trace.")
            self.trace.append({'dpid': dp.id,
                               'in_port': in_port,
                               'out_port': best_out_port})
            self._finish_trace()
            return

        self.seen_hops.add(hop)
        self.trace.append({'dpid': dp.id,
                           'in_port': in_port,
                           'out_port': best_out_port})

        if len(self.trace) >= self.MAX_HOPS:
            self.logger.info("Reached MAX_HOPS=%d — finishing trace.", self.MAX_HOPS)
            self._finish_trace()
            return

        # PacketOut to next hop
        data = msg.data if msg.buffer_id == ofp.OFP_NO_BUFFER else None
        actions = [parser.OFPActionOutput(best_out_port)]
        out = parser.OFPPacketOut(
            datapath=dp,
            buffer_id=msg.buffer_id,
            in_port=in_port,
            actions=actions,
            data=data
        )
        dp.send_msg(out)

    # ----------------------------------------------------------------------
    # Trace finishing
    # ----------------------------------------------------------------------
    def _finish_trace(self):
        if self.finished:
            return

        self.finished = True
        self.logger.info("===== TRACE COMPLETE =====")
        self._print_trace_summary()
        self.logger.info("Use POST /trace/stop to clean up flows.")

    def _print_trace_summary(self):
        if not self.trace:
            self.logger.info("Trace empty.")
            return

        for i, hop in enumerate(self.trace, 1):
            self.logger.info(
                "Hop %d: dpid=%016x in_port=%s out_port=%s",
                i, hop['dpid'], hop['in_port'], hop['out_port']
            )


# ==========================================================================
# REST API for on-demand tracing
# ==========================================================================
class TraceAPI(ControllerBase):

    def __init__(self, req, link, data, **config):
        super(TraceAPI, self).__init__(req, link, data, **config)
        self.tracer = data[TRACE_INSTANCE]

    @route('starttrace', '/trace/start', methods=['POST'])
    def start_trace(self, req, **kwargs):
        t = self.tracer
        t.logger.info("Trace started manually.")

        # Reset state
        t.trace = []
        t.pending = {}
        t.seen_hops = set()
        t.finished = False
        t.tracing = True

        t.install_icmp_flows()

        return "Trace started\n"

    @route('stoptrace', '/trace/stop', methods=['POST'])
    def stop_trace(self, req, **kwargs):
        t = self.tracer
        t.logger.info("Trace stopped manually.")

        t.tracing = False
        t._remove_icmp_flows_all()

        return "Trace stopped, flows removed\n"
