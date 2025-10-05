#!/usr/bin/env python3

import re
import time
from netmiko import ConnectHandler
import paramiko

# Device info
device_info = {
    "R1": {"host": "192.168.122.2", "username": "admin", "password": "admin", "device_type": "cisco_ios"},
    "R2": {"host": "192.168.200.2", "username": "admin", "password": "admin", "device_type": "cisco_ios"},
    "R4": {"host": "172.16.100.1", "username": "admin", "password": "admin", "device_type": "cisco_ios"},
    "controller_vm": {"host": "10.20.30.2", "username": "sdn", "password": "sdn123", "interface": "enp0s8"},
    "mininet_fallback_ip": "192.168.122.80",
    "mininet_vm": {"username": "mininet", "password": "mininet"},
}


def netmiko_connect(device):
    return ConnectHandler(**device)


def discover_mininet_ip():
    # Discover the Mininet VM IP via cli commands
    device = device_info["R1"]
    print(f"Connecting to R1 ({device['host']}) to find Mininet VM IP")
    try:
        conn = netmiko_connect(device)
    except Exception as e:
        print(f"Netmiko connection to R1 failed: {e}")
        return device_info['mininet_fallback_ip']

    # Try show ip dhcp binding
    try:
        out = conn.send_command("show ip dhcp binding", use_textfsm=False)
        ip_list = re.findall(r"(\d+\.\d+\.\d+\.\d+)\s+(\S+)\s+(\S+)\s+(\S+)", out)
        for ips in ip_list:
            ip = ips[0]
            if ip:
                print(f"Found DHCP binding with IP {ip}")
                conn.disconnect()
                return ip
    except Exception:
        pass

    # Try to look at 'show arp' to see if the Mininet VM mac address is in the ARP table
    try:
        out = conn.send_command("show ip arp", use_textfsm=False)
        m = re.findall(r"(\d+\.\d+\.\d+\.\d+)\s+\d+\s+(\S+)\s+\S+\s+\S+", out)
        for ip, mac in m:
            if mac.startswith("08"):
                print(f"Found ARP entry {ip} -> {mac}")
                conn.disconnect()
                return ip
    except Exception:
        pass

    print("Could not discover Mininet IP from R1 outputs, using fallback")
    conn.disconnect()
    return device_info['mininet_fallback_ip']


def paramiko_send_command(host, username, password, command, timeout=10):
    # Send a command via SSH using Paramiko
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(hostname=host, username=username, password=password, timeout=timeout)
    if command.strip().startswith("sudo"):
        command = f"echo {password} | sudo -S {command[5:]}"
    stdin, stdout, stderr = client.exec_command(command, timeout=timeout)
    output = stdout.read().decode()
    err = stderr.read().decode()
    if err:
        print(err)
    client.close()
    return output


def config(man_ip, config):
    # Configure a router via Netmiko
    login = {
        "device_type": "cisco_ios",
        "host": man_ip,
        "username": "admin",
        "password": "admin"
    }
    with ConnectHandler(**login) as net_connect:
        net_connect.enable()
        net_connect.send_config_set(config)
        print(f"{man_ip} configured")


def wait_for_bridge(mininet_ip, mn_cfg, switch="s1", timeout=30):
    # Wait until the switch appears in Mininet (basically wait for Mininet to initialize)
    for _ in range(timeout):
        out = paramiko_send_command(mininet_ip, mn_cfg['username'], mn_cfg['password'], "sudo ovs-vsctl list-br")
        if switch in out:
            print(f"{switch} exists")
            return True
        time.sleep(1)
    print(f"{switch} never appeared")
    return False


def verify_openflow(mininet_ip, mn_cfg):
    # Verify OpenFlow connectivity
    print("Verifying OpenFlow connectivity...")
    show1 = paramiko_send_command(mininet_ip, mn_cfg['username'], mn_cfg['password'], "sudo ovs-vsctl show")
    show2 = paramiko_send_command(mininet_ip, mn_cfg['username'], mn_cfg['password'], "sudo ovs-vsctl get-controller s1")
    show3 = paramiko_send_command(mininet_ip, mn_cfg['username'], mn_cfg['password'], "sudo ovs-ofctl -O OpenFlow13 show s1")
    print(show1)
    print(show2)
    print(show3)

def run_pingall(mininet_ip, mn_cfg):
    # Run pingall in the existing Mininet screen session
    print("Running pingall in Mininet session...")

    # Send pingall command into screen
    cmd = 'sudo screen -S mininet -X stuff "pingall\n"'
    paramiko_send_command(mininet_ip, mn_cfg['username'], mn_cfg['password'], cmd)
    time.sleep(8)

    # Read and print the screen content
    dump_cmd = 'sudo screen -S mininet -X hardcopy /tmp/mininet_dump.txt'
    paramiko_send_command(mininet_ip, mn_cfg['username'], mn_cfg['password'], dump_cmd)
    output = paramiko_send_command(mininet_ip, mn_cfg['username'], mn_cfg['password'], 'cat /tmp/mininet_dump.txt')
    print(output)


def main():
    # Discover Mininet IP
    mininet_ip = discover_mininet_ip()
    print(f"Using Mininet IP: {mininet_ip}")
    mn_cfg = device_info['mininet_vm']

    # Start Mininet in a detached screen
    print("Starting Mininet")
    cmd = "sudo screen -dmS mininet sudo mn --switch ovs,protocols=OpenFlow13"
    paramiko_send_command(mininet_ip, mn_cfg['username'], mn_cfg['password'], cmd)

    # Wait for s1 to come up
    if not wait_for_bridge(mininet_ip, mn_cfg):
        print("Exiting: s1 not found")
        return

    # Set controller for s1
    print("Setting controller for s1")
    paramiko_send_command(mininet_ip, mn_cfg['username'], mn_cfg['password'], "sudo ovs-vsctl set-controller s1 tcp:10.20.30.2:6653")
    # Verify that controller is connected
    ctrl_out = paramiko_send_command(mininet_ip, mn_cfg['username'], mn_cfg['password'], "sudo ovs-vsctl get-controller s1")
    if "tcp:10.20.30.2:6653" in ctrl_out:
        print(f"Controller 10.20.30.2:6653 connected")
    else:
        print("Controller connection failed")

    # Configure routers
    routers = [
        {'name': 'R1', "ip": "192.168.122.2", "config": ["ip route 10.20.30.0 255.255.255.0 192.168.200.2", "ip route 172.16.100.0 255.255.255.0 192.168.200.2"]},
        {'name': 'R2', "ip": "192.168.200.2", "config": ["ip route 10.20.30.0 255.255.255.0 172.16.100.1", "ip route 192.168.122.0 255.255.255.0 192.168.200.1"]},
        {'name': 'R4', "ip": "172.16.100.1", "config": ["ip route 192.168.122.0 255.255.255.0 172.16.100.2"]}
    ]
    for router in routers:
        config(router['ip'], router['config'])
        print(f"Configured {router['name']} at {router['ip']}")

    # Verify OpenFlow connectivity
    time.sleep(4)
    verify_openflow(mininet_ip, mn_cfg)

    # Run pingall in Mininet session
    run_pingall(mininet_ip, mn_cfg)


if __name__ == "__main__":
    main()

