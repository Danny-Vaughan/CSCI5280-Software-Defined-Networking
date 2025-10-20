#!/usr/bin/env python3

import requests
from requests.auth import HTTPBasicAuth

controller_ip = '10.224.78.63'
port = 8080
#user = 'admin'
#password = 'admin'

def get_switches():
    url = f'http://{controller_ip}:{port}/wm/core/switch/00:00:00:00:00:00:00:01/port/json'
    print(url)
    resp = requests.get(url)
    return resp.json()

def main():
    switches = get_switches()
    print(switches)

if __name__ == "__main__":
    main()
