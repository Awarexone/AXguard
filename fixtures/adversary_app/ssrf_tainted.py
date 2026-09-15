"""True-positive SSRF: must survive adversary as CONFIRMED or LIKELY."""

from __future__ import annotations

import requests
from flask import Flask, request

app = Flask(__name__)


@app.route("/fetch", methods=["GET"])
def fetch_url():
    url = request.args.get("url")
    # expected: CONFIRMED or LIKELY after adversary
    return requests.get(url, timeout=5).text
