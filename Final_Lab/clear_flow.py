#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import requests

BASE = "http://127.0.0.1:8080"

def main():
    # 1. 先拿到当前所有 switch 的 DPID 列表
    r = requests.get(f"{BASE}/stats/switches")
    r.raise_for_status()
    dpids = r.json()
    print("Switches:", dpids)

    # 2. 对每个 DPID 调用 clear flow
    for dpid in dpids:
        print(f">>> Clearing flows on dpid={dpid}")
        url = f"{BASE}/stats/flowentry/clear/{dpid}"
        resp = requests.delete(url)
        print("    status:", resp.status_code, resp.text)

if __name__ == "__main__":
    main()
