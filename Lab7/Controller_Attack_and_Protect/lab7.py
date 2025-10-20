#!/usr/bin/env python3

import re
import time
import paramiko
import packet_in


# Device info
device_info = {
    "controller_vm": {"host": "10.224.78.63", "username": "sdn", "password": "sdn123"},
    "mininet_vm": {"host": "10.224.79.89", "username": "mininet", "password": "sdn123"}
}


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


def main():
    mn_cfg = device_info['mininet_vm']
    mininet_ip = mn_cfg['host']
    # Wait for s1 to come up
    if not wait_for_bridge(mininet_ip, mn_cfg):
        print("Exiting: s1 not found")
        return

    ctrl_out = paramiko_send_command(mininet_ip, mn_cfg['username'], mn_cfg['password'], "sudo ovs-vsctl get-controller s1")
    if "tcp:10" in ctrl_out:
        print(f"Controller found")
        parts = ctrl_out.split(":")
        ip = parts[2]
        port = int(parts[3])
        print(f"ip is {ip}")
        print(f"port is {port}")
        packet_in.send_packet_in(ip, port)
    else:
        print("Controller not found")


if __name__ == "__main__":
    main()

