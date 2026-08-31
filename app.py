"""
5G-PacketSense v2 — Unified Network Analysis Platform.

Slim application entry point. Creates the Flask app, registers
blueprints, initializes SocketIO, and starts the server.
"""

import logging
import sys
from pathlib import Path

from flask import Flask
from flask_socketio import SocketIO
from flask_cors import CORS

import config
from routes.api import api, _load_parquet
from routes.ws import register_ws_handlers
from routes.agent import agent_bp
from services.capture import set_socketio
from services.vpn import load_vpn_ip_lists
from services.threat_intel import load_threat_databases

# ── App creation ──────────────────────────────────────────────────

app = Flask(__name__, static_folder="static")
app.config["SECRET_KEY"] = "packetsense-v2-secret-key"
CORS(app)
socketio = SocketIO(app, cors_allowed_origins="*", async_mode="threading")

# Suppress Werkzeug request logs
logging.getLogger("werkzeug").setLevel(logging.ERROR)

# No-cache headers
@app.after_request
def add_header(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    return response

# Register blueprints & WebSocket handlers
app.register_blueprint(api)
app.register_blueprint(agent_bp)
register_ws_handlers(socketio)
set_socketio(socketio, app)

# ── Main ──────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("=" * 70)
    print("5G-PacketSense v2 - Unified Network Analysis Platform")
    print("=" * 70)
    print("\nFeatures:")
    print("  [+] PCAP file analysis with DuckDB")
    print("  [+] Live packet capture with real-time visualization")
    print("  [+] Multi-signal VPN detection with confidence scoring")
    print("  [+] Multi-factor risk scoring engine")
    print("  [+] Interactive geolocation mapping")
    print("  [+] Switch monitoring mode")
    print("  [+] Behavioural traffic analysis")
    print("  [+] AbuseIPDB + vpnapi.io + ipinfo.io integration")
    print("  [+] PacketSense AI Agent (qwen/qwen3-8b via OpenRouter)")
    print("\nStarting server on http://localhost:5000")

    # Load VPN databases (offline — reads local cache only)
    print("\n[VPN-DB] Loading local VPN detection databases...")
    try:
        load_vpn_ip_lists()
    except Exception as e:
        print(f"[VPN-DB] Warning: {e}")

    # Load threat intelligence databases
    print("\n[THREAT-INTEL] Loading offline threat intelligence...")
    try:
        load_threat_databases()
    except Exception as e:
        print(f"[THREAT-INTEL] Warning: {e}")

    # Load AbuseIPDB offline blacklist
    print("\n[ABUSEIPDB] Loading offline blacklist...")
    try:
        from services.abuseipdb import load_offline_blacklist, get_status
        load_offline_blacklist()
        status = get_status()
        if config.ABUSEIPDB_ENABLED:
            print(f"[ABUSEIPDB] API enabled (limit: {config.ABUSEIPDB_DAILY_LIMIT}/day)")
        else:
            print("[ABUSEIPDB] API not configured — using offline blacklist only")
    except Exception as e:
        print(f"[ABUSEIPDB] Warning: {e}")

    print("\nIMPORTANT for live capture:")
    print("  Windows: Run as Administrator")
    print("  Linux/Mac: Use sudo python app.py")
    print("=" * 70 + "\n")

    # Auto-load parquet if provided via CLI
    if len(sys.argv) >= 2:
        pq = sys.argv[1]
        if Path(pq).exists():
            _load_parquet(pq)
        else:
            print(f"[WARN] File not found: {pq}")

    socketio.run(app, debug=True, host="0.0.0.0", port=5000, allow_unsafe_werkzeug=True)
