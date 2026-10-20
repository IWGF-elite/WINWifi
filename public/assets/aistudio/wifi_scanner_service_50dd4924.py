"""
WinWiFi Local Scanner Service
------------------------------
Runs netsh wlan show networks mode=bssid on an interval, parses the
output, and exposes it as JSON over a local HTTP server so a web app
(running in the browser, e.g. your WinWiFi Security Auditor UI) can
poll it for real, live Wi-Fi scan data.

Requirements:
    pip install flask flask-cors

Run:
    python wifi_scanner_service.py

Then in your web app, fetch:
    GET http://127.0.0.1:5055/api/networks

Note: Windows signal % is converted to an approximate dBm value using
the standard formula dBm = (signal% / 2) - 100, which is what most
Wi-Fi tools use for display purposes. It's an approximation, not a
true radio reading, but it is the same approximation nearly every
consumer Wi-Fi tool uses, so it's a reasonable value to show.
"""

import re
import subprocess
import threading
import time
from datetime import datetime, timezone

from flask import Flask, jsonify
from flask_cors import CORS

app = Flask(__name__)
CORS(app)  # allow the web app (different origin/port) to fetch this

# Shared state, updated by the background scan thread
_latest_scan = {
    "networks": [],
    "last_updated": None,
    "error": None,
}
_lock = threading.Lock()

SCAN_INTERVAL_SECONDS = 4


def signal_percent_to_dbm(percent: int) -> int:
    """Approximate dBm from the Windows signal percentage."""
    return int((percent / 2) - 100)


def radio_type_to_band(channel: int) -> str:
    if channel is None:
        return "unknown"
    if channel <= 14:
        return "2.4 GHz"
    if 36 <= channel <= 177:
        return "5 GHz"
    return "6 GHz"


def parse_netsh_output(raw: str):
    """
    Parses the output of: netsh wlan show networks mode=bssid
    into a list of network dicts.
    """
    networks = []
    current = None

    # Split into per-SSID blocks
    ssid_blocks = re.split(r"\r?\n(?=SSID \d+ : )", raw)

    for block in ssid_blocks:
        ssid_match = re.search(r"SSID \d+ : (.*)", block)
        if not ssid_match:
            continue

        ssid = ssid_match.group(1).strip()
        auth_match = re.search(r"Authentication\s*:\s*(.*)", block)
        enc_match = re.search(r"Encryption\s*:\s*(.*)", block)
        bssid_match = re.search(r"BSSID \d+\s*:\s*([0-9a-fA-F:]+)", block)
        signal_match = re.search(r"Signal\s*:\s*(\d+)%", block)
        radio_match = re.search(r"Radio type\s*:\s*(.*)", block)
        channel_match = re.search(r"Channel\s*:\s*(\d+)", block)

        channel = int(channel_match.group(1)) if channel_match else None
        signal_pct = int(signal_match.group(1)) if signal_match else None

        networks.append({
            "ssid": ssid if ssid else "(hidden network)",
            "bssid": bssid_match.group(1) if bssid_match else None,
            "authentication": auth_match.group(1).strip() if auth_match else None,
            "encryption": enc_match.group(1).strip() if enc_match else None,
            "radio_type": radio_match.group(1).strip() if radio_match else None,
            "channel": channel,
            "band": radio_type_to_band(channel),
            "signal_percent": signal_pct,
            "signal_dbm": signal_percent_to_dbm(signal_pct) if signal_pct is not None else None,
        })

    return networks


def run_scan_loop():
    while True:
        try:
            result = subprocess.run(
                ["netsh", "wlan", "show", "networks", "mode=bssid"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            parsed = parse_netsh_output(result.stdout)
            with _lock:
                _latest_scan["networks"] = parsed
                _latest_scan["last_updated"] = datetime.now(timezone.utc).isoformat()
                _latest_scan["error"] = None
        except Exception as e:
            with _lock:
                _latest_scan["error"] = str(e)

        time.sleep(SCAN_INTERVAL_SECONDS)


@app.route("/api/networks", methods=["GET"])
def get_networks():
    with _lock:
        return jsonify(dict(_latest_scan))


@app.route("/api/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "scanning": True})


if __name__ == "__main__":
    scan_thread = threading.Thread(target=run_scan_loop, daemon=True)
    scan_thread.start()
    print("WinWiFi local scanner running at http://127.0.0.1:5055/api/networks")
    app.run(host="127.0.0.1", port=5055)
