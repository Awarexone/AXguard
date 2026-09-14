"""True-positive SSRF: request url → requests.get(url) — expect VERIFIED or LIKELY."""

from __future__ import annotations

import requests
from flask import Flask, request

app = Flask(__name__)


@app.route("/fetch", methods=["GET"])
def fetch_url():
    url = request.args.get("url")
    # expected.json: VERIFIED or LIKELY
    return requests.get(url, timeout=5).text
