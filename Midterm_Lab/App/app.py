#!/usr/bin/env python3
from flask import Flask, render_template, jsonify
import requests
import time

app = Flask(__name__)

# Controller connection info
CONTROLLER_IP = "10.20.30.2"
CONTROLLER_PORT = 8181
USERNAME = "onos"
PASSWORD = "rocks"

# Local data buffers
packet_in_counts = []
timestamps = []


def get_packet_in_count():
    url = f"http://{CONTROLLER_IP}:{CONTROLLER_PORT}/onos/v1/statistics/ports"
    try:
        resp = requests.get(url, auth=(USERNAME, PASSWORD), timeout=3)
        resp.raise_for_status()
        data = resp.json()
        count = 0
        for device in data.get("statistics", []):
            for port in device.get("ports", []):
                count += port.get("packetsReceived", 0)

        return count
    except Exception as e:
        print(f"[!] Failed to fetch packet_in count: {e}")
        return 0


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/data')
def data():
    count = get_packet_in_count()
    packet_in_counts.append(count)
    timestamps.append(time.strftime("%H:%M:%S"))

    # Keep only last 20 samples
    if len(packet_in_counts) > 20:
        packet_in_counts.pop(0)
        timestamps.pop(0)

    return jsonify({
        "labels": timestamps,
        "values": packet_in_counts
    })


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)

