#!/usr/bin/env python3
import subprocess
import pyshark
import json
import time, os

interface = 'any'
port = '6653'
pcap_file = 'openflow.pcap'
output_file = 'connected.txt'
cap_count = '500'


def get_pcap():
	print('Starting packet capture')
	tcpdump_command = ['sudo', 'tcpdump', '-i', interface, 'tcp', 'port', port, '-w', pcap_file, '-c', cap_count]
	subprocess.run(tcpdump_command)
	print('Capture done and saved to file: {}'.format(pcap_file))

def find_connections():
	print('Parsing file now')
	cap = pyshark.FileCapture(pcap_file, display_filter="openflow_v4")
	switch_connections = {}

	for packet in cap:
		if 'openflow_v4' in packet:
			of_layer = packet.openflow_v4
			try:
				if hasattr(of_layer, "type") and int(of_layer.type) == 6:
					print("Openflow 1.3 feature reply found")
					switch_ip = packet.ip.src
					dpid_hex = of_layer.get_field_value("openflow_v4.switch_features.datapath_id")
					if dpid_hex:
						dpid = dpid_hex.replace("0x", "").zfill(16).lower()
					else:
						dpid = "unknown"
					switch_connections[dpid] = {
						"ip": switch_ip,
						"status": "connected"
					}
					print("A switch has connected, DPID: {}, IP: {}".format(dpid, switch_ip))
			except AttributeError:
				continue
	with open(output_file, "w") as file:
		json.dump(switch_connections, file, indent=4)
	print("Connected switches saved to {}".format(output_file))

get_pcap()
time.sleep(15)
find_connections()
