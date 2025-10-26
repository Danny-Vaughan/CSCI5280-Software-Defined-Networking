#!/usr/bin/env python3
import requests
from requests.auth import HTTPBasicAuth

controller_ip = "10.224.78.63"
authentication = HTTPBasicAuth("onos", "rocks")
rest_url = f"http://{controller_ip}:8181/onos/v1"
json_headers = {"Accept": "application/json"}

# We only care about the edge switches:
devices = {
    "OvS1": "of:0000000000000001",
    "OvS5": "of:0000000000000005",
}

def of_to_name(ofid: str) -> str:
    if ofid.startswith("of:00000000000000"):
        try:
            return f"OvS{int(ofid[-2:], 16)}"
        except Exception:
            return ofid
    return ofid

def get_json(url):
    r = requests.get(url, auth=authentication, headers=json_headers)
    r.raise_for_status()
    return r.json()

def get_links_map():
    # Return map {(device,port) → neighbor_device} for inter-switch links
    links = get_json(f"{rest_url}/links").get("links", [])
    link_map = {}
    for l in links:
        sdev, sport = l["src"]["device"], l["src"]["port"]
        ddev, dport = l["dst"]["device"], l["dst"]["port"]
        link_map[(sdev, sport)] = ddev
        link_map[(ddev, dport)] = sdev
    return link_map

def flow_output_port(flow):
    for inst in flow.get("treatment", {}).get("instructions", []):
        if inst.get("type") == "OUTPUT":
            return inst.get("port")
    return None

def is_ipv4(flow):
    for c in flow.get("selector", {}).get("criteria", []):
        if c.get("type") == "ETH_TYPE" and c.get("ethType") in ("0x0800", "0x800"):
            return True
    return False

def is_http(flow):
    # Return True if the flow matches TCP src or dst port 80 or 8080
    for c in flow.get("selector", {}).get("criteria", []):
        if c.get("type") in ("TCP_DST", "TCP_SRC") and str(c.get("tcpPort")) in ("80", "8080"):
            return True
    return False

def summarize_network_outbound(device_id, links_map):
    flows = get_json(f"{rest_url}/flows/{device_id}").get("flows", [])
    http_next, ip_next = None, None

    for f in flows:
        if not is_ipv4(f):
            continue
        outp = flow_output_port(f)
        if not outp or outp == "CONTROLLER":
            continue

        # Only consider links that lead to another switch
        nxt = links_map.get((device_id, str(outp)))
        if not nxt:
            continue  # skip host/gw ports

        nxt_name = of_to_name(nxt)
        if is_http(f):
            http_next = nxt_name
        else:
            ip_next = nxt_name

    return ip_next, http_next

def main():
    links_map = get_links_map()
    print()
    for name, ofid in devices.items():
        ip_next, http_next = summarize_network_outbound(ofid, links_map)
        print(f"{name}:")
        print(f"   IP traffic outbound -> {ip_next or '(no network flow found)'}")
        print(f"   HTTP traffic outbound -> {http_next or '(no network flow found)'}")
        print()

if __name__ == "__main__":
    main()

