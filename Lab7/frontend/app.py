#!/usr/bin/env python3

from flask import Flask, render_template, request, redirect, url_for, flash
import requests

app = Flask(__name__)
app.secret_key = "supersecret"

# Floodlight controller info
controller_ip = "10.224.78.63"
port = 8080


@app.route('/')
def index():
    return render_template('index.html')


# -------------------- Static Routing --------------------
@app.route('/static_routing', methods=['GET', 'POST'])
def static_routing():
    if request.method == 'POST':
        flow = {}
        # Collect only non-empty fields
        for field in [
            "switch", "name", "priority", "in_port", "eth_type",
            "ipv4_src", "ipv4_dst", "arp_spa", "arp_tpa", "idle_timeout", "hard_timeout"
        ]:
            value = request.form.get(field)
            if value:
                if field == "priority":
                    try:
                        value = int(value)
                    except ValueError:
                        pass
                flow[field] = value

        flow["active"] = "true"

        # Add action if provided
        action = request.form.get("action")
        if action:
            flow["actions"] = f"output={action}"

        url = f"http://{controller_ip}:{port}/wm/staticflowentrypusher/json"
        resp = requests.post(url, json=flow)

        if resp.status_code == 200:
            flash("✅ Flow added successfully!", "success")
        else:
            flash(f"❌ Error adding flow: {resp.text}", "danger")

        return redirect(url_for("static_routing"))

    return render_template("static_routing.html")


# -------------------- Firewall --------------------
@app.route('/firewall', methods=['GET', 'POST'])
def firewall():
    if request.method == 'POST':
        # Get user input
        src_ip = request.form.get('src_ip', '')
        dst_ip = request.form.get('dest_ip', '')
        eth_type = request.form.get('eth_type', '0x800')
        l4_proto = request.form.get('l4_proto', '')
        in_port = request.form.get('in_port', '')
        priority = int(request.form.get('priority', '100'))

        # First, push a default drop rule to all switches
        switches_url = f'http://{controller_ip}:{port}/wm/core/controller/switches/json'
        switches = requests.get(switches_url).json()

        for sw in switches:
            drop_rule = {
                "switch": sw["switchDPID"],
                "name": f"default_drop_{sw['switchDPID']}",
                "priority": 1,
                "active": "true",
                "actions": ""
            }
            requests.post(f'http://{controller_ip}:{port}/wm/staticflowentrypusher/json', json=drop_rule)

        # Now push the specific allow rule from user input
        allow_rule = {
            "switch": request.form['dpid'],
            "name": f"allow_{src_ip}_{dst_ip}",
            "priority": priority,
            "in_port": in_port,
            "eth_type": eth_type,
            "ipv4_src": src_ip,
            "ipv4_dst": dst_ip,
            "ip_proto": l4_proto,
            "active": "true",
            "actions": f"output={request.form['action']}"
        }
        resp = requests.post(f'http://{controller_ip}:{port}/wm/staticflowentrypusher/json', json=allow_rule)

        if resp.status_code == 200:
            flash('Firewall rule added successfully! Default drop applied to all switches.', 'success')
        else:
            flash(f'Error: {resp.text}', 'danger')

        return redirect(url_for('firewall'))

    return render_template('firewall.html')



if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)

