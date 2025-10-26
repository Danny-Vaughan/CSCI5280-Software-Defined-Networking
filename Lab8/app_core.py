#!/usr/bin/env python3

import requests
from requests.auth import HTTPBasicAuth


controller_ip = "10.224.78.63"
controller_port = 8181
auth_creds = HTTPBasicAuth("onos", "rocks")
rest_url = f"http://{controller_ip}:{controller_port}/onos/v1"
headers_global = {"Content-Type": "application/json"}


devices = {
    "OvS1": "of:0000000000000001",
    "OvS2": "of:0000000000000002",
    "OvS3": "of:0000000000000003",
    "OvS4": "of:0000000000000004",
    "OvS5": "of:0000000000000005",
    "OvS6": "of:0000000000000006",
    "OvS7": "of:0000000000000007",
    "OvS8": "of:0000000000000008",
}

host_ip_address = "10.0.0.1"
server_ip = "10.0.0.2"
host_ipv6_address = "1::1"
server_ipv6_address = "2::2"
http_port = 8080


def push_static_flows(device, selector, treatment, priority=100, comment=""):
    body = {
        "priority": priority,
        "timeout": 0,
        "isPermanent": True,
        "deviceId": devices[device],
        "treatment": {"instructions": [{"type": "OUTPUT", "port": str(treatment)}]},
        "selector": {"criteria": selector},
    }
    r = requests.post(
        f"{rest_url}/flows/{devices[device]}",
        json=body,
        headers=headers_global,
        auth=auth_creds,
        timeout=5,
    )
    if r.status_code not in (200, 201):
        print(f"Failed to push flow to {device}: {r.status_code} {r.text}")
    else:
        print(f"Flow pushed to {device} ({comment})")


def remove_flows():
    for name, did in devices.items():
        # Get flows for that device
        res = requests.get(f"{rest_url}/flows/{did}", auth=auth_creds, timeout=5)
        if res.status_code != 200:
            print(f"Could not fetch flows for {name}: {res.status_code}")
            continue

        flows = res.json().get("flows", [])
        for f in flows:
            fid = f["id"]
            del_url = f"{rest_url}/flows/{did}/{fid}"
            r = requests.delete(del_url, auth=auth_creds, timeout=5)
            if r.status_code == 204:
                print(f"Deleted flow")
            else:
                print(f"Could not delete flow {fid} on {name}: {r.status_code}")


def initial_setup():

    print("Installing baseline static connectivity + ARP handling")
    gw1_port = "5"
    gw5_port = "5"
    gw1_mac = "52:3c:97:f6:96:4d"
    gw5_mac = "ae:a6:56:4c:34:86"

    gw1_sel_mac = [{"type": "ETH_TYPE", "ethType": "0x0800"}, {"type": "ETH_DST", "mac": gw1_mac}]
    gw1_sel_port = [{"type": "ETH_TYPE", "ethType": "0x0800"}, {"type": "ETH_DST", "mac": gw1_port}]
    gw5_sel_mac = [{"type": "ETH_TYPE", "ethType": "0x0800"}, {"type": "ETH_DST", "mac": gw5_mac}]
    gw5_sel_port = [{"type": "ETH_TYPE", "ethType": "0x0800"}, {"type": "ETH_DST", "mac": gw5_port}]
    
    push_static_flows("OvS1", gw1_sel_mac, 5, priority=500, comment="H1 to gw1")
    push_static_flows("OvS1", gw1_sel_port, 3, priority=200, comment="gw1 to core")
    push_static_flows("OvS5", gw5_sel_mac, 5, priority=500, comment="Server to gw5")
    push_static_flows("OvS5", gw5_sel_port, 4, priority=200, comment="gw5 to Server")
    push_static_flows("OvS5", gw5_sel_port, 2, priority=200, comment="gw5 to core")
    
    arp_sel = [{"type": "ETH_TYPE", "ethType": "0x0806"}]
    for device in devices:
        push_static_flows(device, arp_sel, "CONTROLLER", priority=40000, comment=f"ARP to controller")

    # Basic IPv4 forwarding between static links (for simplicity use wildcard IPv4)
    ipv4_sel = [{"type": "ETH_TYPE", "ethType": "0x0800"}]

    # Simple “port-to-port” connectivity
    link_ports = {
        "OvS2": [(1, 2), (2, 1)],
        "OvS3": [(1, 2), (2, 1)],
        "OvS4": [(1, 2), (2, 1)],
        "OvS6": [(1, 2), (2, 1)],
        "OvS7": [(1, 2), (2, 1)],
        "OvS8": [(1, 2), (2, 1)],
    }
    for sw, tuples in link_ports.items():
        for inport, outport in tuples:
            push_static_flows(sw, ipv4_sel + [{"type": "IN_PORT", "port": str(inport)}], outport,
                              comment=f"default fwd {inport}->{outport}")

    # IPv6 default forwarding
    ipv6_sel = [{"type": "ETH_TYPE", "ethType": "0x86DD"}]
    for sw, tuples in link_ports.items():
        for inport, outport in tuples:
            push_static_flows(sw, ipv6_sel + [{"type": "IN_PORT", "port": str(inport)}], outport,
                              comment=f"IPv6 fwd {inport}->{outport}")

    print("Initial setup complete.")


def default_path():
    print("Setting default path (all traffic via OvS6–OvS7–OvS5)")
    remove_flows()
    initial_setup()

    # 1 -> 6 -> 7 -> 5
    server_match = [{"type": "ETH_TYPE", "ethType": "0x0800"}, {"type": "IPV4_DST", "ip": "1.1.1.1/32"}]
    host_match = [{"type": "ETH_TYPE", "ethType": "0x0800"}, {"type": "IPV4_DST", "ip": "10.0.0.1/32"}]   
    # OvS1
    push_static_flows("OvS1", server_match, 3, comment="to OvS6 (default path)")
    # OvS5 (to Server)
    push_static_flows("OvS5", server_match, 4, comment="to Server")
    # reverse for replies
    push_static_flows("OvS5", host_match, 2, comment="reply to OvS7")
    push_static_flows("OvS1", host_match, 1, comment="to host")

    # IPv6 (proof)
    ipv6_sel = [{"type": "ETH_TYPE", "ethType": "0x86DD"}]
    push_static_flows("OvS1", ipv6_sel, 3, comment="IPv6 fwd to OvS6")
    push_static_flows("OvS5", ipv6_sel, 4, comment="IPv6 fwd to Server")
    print("Default path installed.")


def shortest_path():

    print("Setting shortest path (HTTP via OvS8, others default path)")
    remove_flows()
    initial_setup()

    # All traffic default
    default_path()
    http_sel_source = [
        {"type": "ETH_TYPE", "ethType": "0x0800"},
        {"type": "IP_PROTO", "protocol": 6},
        {"type": "TCP_SRC", "tcpPort": http_port},
    ]
    http_sel_dest = [
        {"type": "ETH_TYPE", "ethType": "0x0800"},
        {"type": "IP_PROTO", "protocol": 6},
        {"type": "TCP_DST", "tcpPort": http_port},
    ]
    push_static_flows("OvS1", http_sel_dest, 4, priority=200, comment="HTTP via OvS8")
    push_static_flows("OvS5", http_sel_source, 3, priority=200, comment="HTTP return")
    print("Shortest-path flows installed.")


def longest_path():
    print("Setting longest path (HTTP via OvS2–OvS3–OvS4–OvS5)")
    remove_flows()
    initial_setup()
    default_path()

    http_sel_source = [
        {"type": "ETH_TYPE", "ethType": "0x0800"},
        {"type": "IP_PROTO", "protocol": 6},
        {"type": "TCP_SRC", "tcpPort": http_port},
    ]
    http_sel_dest = [
        {"type": "ETH_TYPE", "ethType": "0x0800"},
        {"type": "IP_PROTO", "protocol": 6},
        {"type": "TCP_DST", "tcpPort": http_port},
    ]
    # Path 1–2–3–4–5
    push_static_flows("OvS1", http_sel_dest, 2, priority=200, comment="HTTP via OvS2")
    push_static_flows("OvS5", http_sel_source, 1, priority=200, comment="HTTP return")
    print("[+] Longest-path (HTTP) flows installed.")


def main():
    remove_flows()

if __name__ == "__main__":
    main()
