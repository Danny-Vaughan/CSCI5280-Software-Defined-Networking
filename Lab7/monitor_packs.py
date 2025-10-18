#!/usr/bin/env python3
import subprocess
from collections import defaultdict

limit = 100

# Dictionary to keep track of counts
packet_in_counts = defaultdict(int)
blocked_ips = set()

def add_firewall_rule(ip):

    print(f"Limit reached: {ip} -> Blocking with iptables")
    try:
        subprocess.run(
            ["sudo", "iptables", "-I", "INPUT", "-s", ip, "-j", "DROP"],
            check=True,
        )
        blocked_ips.add(ip)
        print(f"Successfully blocked {ip}")
    except subprocess.CalledProcessError as e:
        print(f"Failed to add iptables rule for {ip}: {e}")

def process_packet(src_ip):

    if src_ip in blocked_ips:
        return

    packet_in_counts[src_ip] += 1
    count = packet_in_counts[src_ip]

    print(f"{src_ip}: {count} packet_ins")

    if count >= limit:
        add_firewall_rule(src_ip)

def monitor_packet_ins():

    cmd = ["sudo", "tcpdump", "-l", "-n", "tcp port 6653"]
    process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
    print("Monitoring PACKET_IN traffic on TCP 6653")

    try:
        for line in process.stdout:
            parts = line.split()
            if len(parts) < 3:
                continue

            src_parts = parts[2].split(".")
            if len(src_parts) < 5:
                continue
            src_ip = ".".join(src_parts[:-1])

            process_packet(src_ip)
    except KeyboardInterrupt:
        print("\nStopping monitor")
        process.terminate()

if __name__ == "__main__":
    monitor_packet_ins()
