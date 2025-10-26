#!/usr/bin/env python3

from flask import Flask, render_template, redirect, url_for, flash
import app_core

app = Flask(__name__)
app.secret_key = "secret-key-for-lab"


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/default", methods=["POST"])
def default():
    app_core.default_path()
    flash("Default path activated.", "success")
    return redirect(url_for("index"))


@app.route("/shortest", methods=["POST"])
def shortest():
    app_core.shortest_path()
    flash("Shortest path (HTTP via OvS8) activated.", "success")
    return redirect(url_for("index"))


@app.route("/longest", methods=["POST"])
def longest():
    app_core.longest_path()
    flash("Longest path (HTTP via OvS2–OvS3–OvS4) activated.", "success")
    return redirect(url_for("index"))


@app.route("/bestdelay", methods=["POST"])
def bestdelay():
    delay_test.choose_best_delay()
    flash("Best-delay path activated", "success")
    return redirect(url_for("index"))


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
