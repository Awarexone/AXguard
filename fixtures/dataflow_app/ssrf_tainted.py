"""Dataflow fixture: Flask-style tainted URL → requests.get (SSRF-shaped)."""

from __future__ import annotations

import requests
from flask import Flask, request

app = Flask(__name__)


@app.route("/fetch", methods=["GET"])
def fetch_url():
    url = request.args.get("url")
    # Tainted URL reaches network sink (diagnostic path for SSRF-shaped flow).
    return requests.get(url, timeout=5).text
