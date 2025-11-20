#!/usr/bin/env python3
import requests

class SimpleTracer:
    def __init__(self, controller="127.0.0.1", port=8080):
        self.base = f"http://{controller}:{port}"

    def flows(self, dpid):
        r = requests.get(f"{self.base}/stats/flow/{dpid}")
        return r.json().get(str(dpid), [])

    def links(self):
        return requests.get(f"{self.base}/v1.0/topology/links").json()

    # Build adjacency: adj[switch][port] = (next_switch, next_port)
    def adjacency(self):
        adj = {}
        for l in self.links():
            s = l["src"]
            d = l["dst"]
            s_dpid, s_port = s["dpid"], s["port_no"]
            d_dpid, d_port = d["dpid"], d["port_no"]

            adj.setdefault(s_dpid, {})[s_port] = (d_dpid, d_port)
            adj.setdefault(d_dpid, {})[d_port] = (s_dpid, s_port)
        return adj

    # Match decision logic that parses the flows in the switches flow table and finds dst_ip
    # If no dst_ip it will try to find a flow that matches all ip traffic
    # If no flow for all IP traffic it will make one last effort to match any output port that is not controller or the ingress port
    def find_output(self, flows, dst_ip, in_port):
        best_exact = None
        best_ipv4 = None
        best_fallback = None

        for f in flows:
            match = f.get("match", {})

            # Extract output port from action/instruction
            out_port = None

            for inst in f.get("instructions", []):
                if inst["type"] == "APPLY_ACTIONS":
                    for act in inst["actions"]:
                        if act["type"] == "OUTPUT":
                            out_port = act["port"]
                            break

            if not out_port:
                continue

            # 1. Exact match on ipv4_dst (unlikely, but it tries)
            if match.get("ipv4_dst") == dst_ip:
                best_exact = out_port

            # 2. Trying to find a match eth_type = IPv4 (0x0800) (most likely scenario)
            if match.get("eth_type") == 2048:  # 0x0800
                best_ipv4 = out_port

            # 3. Fallback: first out port that is not controller or ingress port
            if out_port not in (in_port, "CONTROLLER", 0xfffffffd, 4294967293):
                if best_fallback is None:
                    best_fallback = out_port

        return best_exact or best_ipv4 or best_fallback

    # Path trace logic
    def trace(self, start_dpid, start_port, dst_ip):
        adj = self.adjacency()
        path = []

        current = int(start_dpid)
        in_port = int(start_port)

        while True:
            fs = self.flows(current)

            out_port = self.find_output(fs, dst_ip, in_port)

            hop = {
                "dpid": current,
                "in_port": in_port,
                "out_port": out_port
            }
            path.append(hop)

            if out_port is None:
                hop["note"] = "No usable flow/action found"
                break

            # If this port doesn’t connect to another switch we are finished
            if current not in adj or out_port not in adj[current]:
                hop["note"] = "Reached host or non-switch port"
                break

            # Move to next hop
            next_sw, next_in = adj[current][out_port]
            current = next_sw
            in_port = next_in

        return path
