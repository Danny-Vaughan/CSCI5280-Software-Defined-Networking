#!/usr/bin/env python3
"""
Flask-based API for DNS Firewall.
Run on controller (localhost:8080).
Keeps track of blacklisted domains for dynamic blocking.

Usage:
    python3 site_checker_api.py
Then from a browser or curl:
    curl http://127.0.0.1:8080/check/openai.com
    curl -X POST http://127.0.0.1:8080/blacklist -H "Content-Type: application/json" -d '{"domain": "facebook.com"}'
"""

from flask import Flask, request, jsonify
from threading import Lock
import os, json

app = Flask(__name__)
shunned_sites = "site_blacklist.json"
lock = Lock()

# ----------------------------------------------------------
# Gets the blacklist at start, if it doesn't exist it inits an empty list
# ----------------------------------------------------------
if os.path.exists(shunned_sites):
    with open(shunned_sites, "r") as f:
        data = json.load(f)
        BLACKLIST = set(data.get("blacklist", []))
else:
    BLACKLIST = set()

# ----------------------------------------------------------
# Takes the blacklist in memory after an operation is performed and dumps to the file for saving
# ----------------------------------------------------------
def save_state():
    with lock:
        with open(shunned_sites, "w") as f:
            json.dump({"blacklist": sorted(list(BLACKLIST))}, f, indent=2)

# ----------------------------------------------------------
# Routes for check, adding and removing domains from the blacklist
# ----------------------------------------------------------

@app.route("/check/<domain>", methods=["GET"])
def check_site(domain):
    domain = domain.lower().strip()
    if domain in BLACKLIST:
        result = "bad"
    else:
        result = "good"
    return jsonify({"domain": domain, "result": result})


@app.route("/blacklist", methods=["POST"])
def add_blacklist():
    data = request.get_json(force=True)
    domain = data.get("domain", "").lower().strip()
    if not domain:
        return jsonify({"error": "missing domain"}), 400
    BLACKLIST.add(domain)
    save_state()
    return jsonify({"message": f"{domain} added to blacklist", "blacklist": sorted(list(BLACKLIST))})


@app.route("/whitelist", methods=["POST"])
def remove_blacklist():
    data = request.get_json(force=True)
    domain = data.get("domain", "").lower().strip()
    if not domain:
        return jsonify({"error": "missing domain"}), 400
    if domain in BLACKLIST:
        BLACKLIST.remove(domain)
        save_state()
        return jsonify({"message": f"{domain} removed from blacklist"})
    else:
        return jsonify({"message": f"{domain} not found"}), 404


@app.route("/list", methods=["GET"])
def list_blacklist():
    return jsonify({"blacklist": sorted(list(BLACKLIST))})


@app.route("/")
def index():
    return (
        "<h2>Site Checker API</h2>"
        "<p>Use /check/&lt;domain&gt;, /blacklist (POST JSON), /whitelist (POST JSON), /list</p>"
    )


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
