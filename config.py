"""
5G-PacketSense v2 — Centralized configuration and shared state.

All mutable runtime state (caches, stats, device tracking) lives here
so every module imports from one place instead of juggling globals.
"""

import os
import threading
from collections import defaultdict, deque
from pathlib import Path
from dotenv import load_dotenv

load_dotenv()

# ── Paths ─────────────────────────────────────────────────────────
BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
THREAT_INTEL_DIR = DATA_DIR / "threat_intel"

# ── Capture settings ──────────────────────────────────────────────
CAPTURE_MODE = "local"  # "local" or "switch"
CAPTURE_INTERFACE = None  # None → all interfaces
CAPTURE_SUBNET = None  # For switch mode
CAPTURE_SNAPLEN = 128    # Increased from 96 — captures full IP+TCP/UDP headers + payload prefix
MAX_HISTORY = 5000       # 16GB RAM machine — keep 5× more packet history

# ── Performance mode ──────────────────────────────────────────────
# When True, per-packet processing skips heavy offline database lookups:
#   - FireHOL / IPsum / Blocklist.de threat intel scan
#   - AbuseIPDB per-packet blacklist check
#   - Threat intel correlation inside VPN detection
#   - Behavioural analysis engine (beaconing, exfil, tunnel)
# Only kept: MMDB geo, keyword/ASN VPN detection, X4BNet/Tor IP ranges, protocol heuristics.
# Enable this on low-spec hardware or high-traffic interfaces.
FAST_MODE = True  # Toggle False to re-enable full analysis pipeline


# ── Offline user location (used in switch mode when no internet) ─
USER_LAT = float(os.getenv("USER_LAT", "0"))
USER_LON = float(os.getenv("USER_LON", "0"))
USER_CITY = os.getenv("USER_CITY", "")
USER_COUNTRY = os.getenv("USER_COUNTRY", "")

# ── LLM ───────────────────────────────────────────────────────────
LLM_PROVIDER = os.getenv("LLM_PROVIDER", "ollama").lower()
OPENROUTER_API_KEY = os.getenv("OPENROUTER_API_KEY", "")

# Ollama (local or SSH-tunnelled remote instance)
OLLAMA_URL = os.getenv("OLLAMA_URL", "http://localhost:11434/v1")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "qwen2.5:7b")
OLLAMA_TIMEOUT = int(os.getenv("OLLAMA_TIMEOUT", "60"))  # seconds

# ── DuckDB Column Mapping ────────────────────────────────────────
COLS = {
    "time": '"timestamp"',
    "len": '"length"',
    "proto": '"protocol"',
    "src": '"src_ip"',
    "dst": '"dst_ip"',
    "ttl": '"ttl"',
    "number": '"frame_no"',
    "tcp_src": '"src_port"',
    "tcp_dst": '"dst_port"',
    "udp_src": '"src_port"',
    "udp_dst": '"dst_port"',
}

# ── Cache size limits (memory management for 16GB machine) ─────
# Caches are evicted when they exceed these sizes (oldest entries removed)
GEOIP_CACHE_MAX    = 50_000   # ~50 bytes/entry × 50k = ~2.5 MB
VPN_CACHE_MAX      = 25_000   # key + result dict
VPN_API_CACHE_MAX  = 10_000   # per-IP merged API result
IPAPI_CACHE_MAX    = 10_000
IPINFO_CACHE_MAX   = 10_000
VPNAPI_CACHE_MAX   = 10_000
ABUSEIPDB_CACHE_MAX = 5_000

# ── DuckDB settings optimized for 16GB RAM ───────────────────────
DUCKDB_MEMORY_LIMIT = "8GB"   # Give DuckDB half the machine RAM
DUCKDB_THREADS      = 4       # Parallel query threads

# ── Shared mutable state ─────────────────────────────────────────
# GeoIP
GEOIP_CACHE: dict = {}
user_public_location: dict | None = None

# VPN detection
VPN_CACHE: dict = {}
vpn_ips: set = set()
VPN_IP_RANGES_V4: list = []
VPN_IP_RANGES_LOADED = False

# Threat intelligence
THREAT_INTEL_LOADED = False
THREAT_INTEL_SOURCES: dict = {}

# AbuseIPDB (optional online enrichment)
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "")
ABUSEIPDB_ENABLED = bool(ABUSEIPDB_API_KEY)
ABUSEIPDB_CACHE: dict = {}
ABUSEIPDB_DAILY_COUNT = 0
ABUSEIPDB_DAILY_LIMIT = 950  # Stay under 1000 free tier limit

# vpnapi.io (optional — 1,000 lookups/day on free tier)
VPNAPI_IO_KEY = os.getenv("VPNAPI_IO_KEY", "")
VPNAPI_IO_ENABLED = bool(VPNAPI_IO_KEY)
VPNAPI_IO_CACHE: dict = {}
VPNAPI_IO_DAILY_COUNT = 0
VPNAPI_IO_DAILY_LIMIT = 950

# ipinfo.io (optional token — 50k/month free without token)
IPINFO_TOKEN = os.getenv("IPINFO_TOKEN", "")
IPINFO_CACHE: dict = {}
IPINFO_DAILY_COUNT = 0
IPINFO_DAILY_LIMIT = 48000  # Conservative limit for free tier

# ip-api.com (free, no key — 45 req/min)
IPAPI_CACHE: dict = {}
IPAPI_MINUTE_COUNT = 0
IPAPI_MINUTE_RESET = 0.0  # Unix timestamp of current minute window
IPAPI_MINUTE_LIMIT = 40   # Conservative limit (actual limit: 45/min)

# Shared VPN API enrichment cache (keyed by IP, stores merged result)
VPN_API_CACHE: dict = {}

# DuckDB
conn = None
parquet_path = None

# LLM client (lazy init)
llm_client = None

# Live capture
capture_running = False
SWITCH_MONITOR_RUNNING = False
packet_history = deque(maxlen=MAX_HISTORY)  # 5000 packets in-memory ring buffer
captured_packets: list = []
capture_session_name: str | None = None

live_stats = {
    "total_packets": 0,
    "tcp_packets": 0,
    "udp_packets": 0,
    "unique_ips": set(),
    "unique_src_ips": set(),
    "unique_dst_ips": set(),
    "connections": {},
    "start_time": None,
    "total_bytes": 0,
    "protocols": defaultdict(int),
    "ports": defaultdict(int),
    "top_talkers": defaultdict(int),
    "vpn_ips": set(),
    "vpn_details": {},
}

# Switch monitoring
switch_devices: dict = {}
switch_vpn_alerts: list = []
switch_device_lock = threading.Lock()

# Behavioural analysis (analyzer instance created by capture.py)
behaviour_analyzer = None


def evict_cache_if_needed(cache: dict, max_size: int, name: str = "") -> int:
    """Evict the oldest 20% of entries when cache exceeds max_size.

    Uses insertion-order (Python 3.7+ dict) — oldest keys are first.
    Returns the number of evicted entries.
    """
    if len(cache) <= max_size:
        return 0
    # Evict enough to get back to 80% of max
    evict_count = len(cache) - int(max_size * 0.8)
    keys_to_remove = list(cache.keys())[:evict_count]
    for k in keys_to_remove:
        del cache[k]
    if name:
        print(f"[CACHE] Evicted {evict_count} entries from {name} (limit: {max_size})")
    return evict_count


def reset_live_stats():
    """Reset all live capture counters."""
    live_stats.update(
        {
            "total_packets": 0,
            "tcp_packets": 0,
            "udp_packets": 0,
            "unique_ips": set(),
            "unique_src_ips": set(),
            "unique_dst_ips": set(),
            "connections": {},
            "start_time": None,
            "total_bytes": 0,
            "protocols": defaultdict(int),
            "ports": defaultdict(int),
            "top_talkers": defaultdict(int),
            "vpn_ips": set(),
            "vpn_details": {},
        }
    )
