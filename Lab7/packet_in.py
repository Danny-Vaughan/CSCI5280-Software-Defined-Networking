#!/usr/bin/env python3
from scapy.all import Ether, IP, UDP, raw
import socket, struct, time

def build_packet_in(controller_ip="10.224.78.63", controller_port=6653, source_ip="10.224.79.89", dst_ip="10.0.0.1", ofp_version=0x04, ofpt_packet_in=10):

    # Build inner Ethernet/IP/UDP packet
    pkt = Ether(dst="ff:ff:ff:ff:ff:ff", src="00:11:22:33:44:55") / IP(src=source_ip, dst=dst_ip) / UDP(sport=1234, dport=80)
    data = raw(pkt)

    # OpenFlow 1.3 PACKET_IN
    buf_id = struct.pack("!I", 0xffffffff)
    tot_len = struct.pack("!H", len(data))
    reason = b"\x00"
    table = b"\x00"
    cookie = struct.pack("!Q", 0)
    match_hdr = struct.pack("!HH", 1, 4) + b"\x00"*4  # minimal ofp_match padded to 8 bytes
    payload = buf_id + tot_len + reason + table + cookie + match_hdr + data
    of_hdr = struct.pack("!BBHI", ofp_version, ofpt_packet_in, 8 + len(payload), 1)
    msg = of_hdr + payload
    return msg

def send_packet_in():
    # Send it
    controller_ip = "10.224.78.63"
    controller_port = 6653
    s = socket.socket()
    s.connect((controller_ip, controller_port))
    for i in range(10):
        msg = build_packet_in()
        s.sendall(msg)
        
    s.close()

    print("Sending PACKET_INs to controller", controller_ip, "on port", controller_port)

def main():
    send_packet_in()

if __name__ == "__main__":
    main()
