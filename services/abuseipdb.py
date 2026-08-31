"""
services/abuseipdb.py — Optional AbuseIPDB integration.

Provides two modes of operation:
  1. Offline: Checks IPs against a pre-downloaded AbuseIPDB public blacklist
     (stored in data/threat_intel/abuseipdb_blacklist.txt)
  2. Online:  If ABUSEIPDB_API_KEY is set in .env, queries the AbuseIPDB API
     for real-time abuse confidence scores and VPN/proxy flags.

The API is rate-limited to 950 calls/day (free tier = 1,000/day).
All results are cached for 24 hours to minimize API calls.

This module is OPTIONAL. The rest of the system works 100% offline without it.
"""

import ipaddress
import time
from pathlib import Path
from typing import Optional

import config

# ── Offline blacklist (pre-downloaded IPs with 100% abuse confidence) ──

_offline_blacklist: set[int] = set()
_offline_loaded = False


def load_offline_blacklist():
    """Load AbuseIPDB public blacklist from local file.
    File should be at data/threat_intel/abuseipdb_blacklist.txt
    (one IP per line, downloaded by scripts/update_threat_intel.py).
    """
    global _offline_blacklist, _offline_loaded
    bl_path = config.THREAT_INTEL_DIR / "abuseipdb_blacklist.txt"
    if not bl_path.exists():
        _offline_loaded = True
        return

    count = 0
    try:
        for line in bl_path.read_text(errors="replace").splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            try:
                _offline_blacklist.add(int(ipaddress.ip_address(line)))
                count += 1
            except ValueError:
                pass
    except Exception as e:
        print(f"[ABUSEIPDB] Error loading offline blacklist: {e}")

    _offline_loaded = True
    if count:
        print(f"[ABUSEIPDB] Loaded offline blacklist: {count} IPs")


def check_offline_blacklist(ip_str: str) -> bool:
    """Check if IP is in the pre-downloaded AbuseIPDB blacklist."""
    if not _offline_loaded:
        load_offline_blacklist()
    try:
        return int(ipaddress.ip_address(ip_str)) in _offline_blacklist
    except ValueError:
        return False


# ── Online API (optional, requires ABUSEIPDB_API_KEY) ────────────


def _api_available() -> bool:
    """Check if the AbuseIPDB API is configured and within rate limits."""
    return (
        config.ABUSEIPDB_ENABLED
        and config.ABUSEIPDB_DAILY_COUNT < config.ABUSEIPDB_DAILY_LIMIT
    )


def check_ip_abuseipdb(ip_str: str) -> dict:
    """Query AbuseIPDB for an IP's abuse score and VPN/proxy status.

    Returns a dict with:
      - available: bool — whether we got a result
      - abuse_confidence: int (0-100) — crowd-sourced abuse confidence
      - is_vpn: bool — AbuseIPDB's VPN/proxy flag
      - is_tor: bool — Tor exit node flag
      - usage_type: str — e.g. "Data Center/Web Hosting/Transit", "Fixed Line ISP"
      - total_reports: int — number of abuse reports
      - categories: list[int] — AbuseIPDB category codes
      - isp: str — ISP name from AbuseIPDB
      - domain: str — domain associated with IP
      - in_offline_blacklist: bool — whether IP is in the offline blacklist

    If API is not available or IP is private, returns {available: False}.
    Results are cached for 24 hours.
    """
    # Always check offline blacklist
    in_blacklist = check_offline_blacklist(ip_str)

    # Skip private IPs
    try:
        ip_obj = ipaddress.ip_address(ip_str)
        if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local:
            return _empty_result(in_blacklist=in_blacklist)
    except ValueError:
        return _empty_result()

    # Check cache (24h TTL)
    if ip_str in config.ABUSEIPDB_CACHE:
        cached = config.ABUSEIPDB_CACHE[ip_str]
        if time.time() - cached.get("_cached_at", 0) < 86400:  # 24 hours
            cached["in_offline_blacklist"] = in_blacklist
            return cached

    # If API not available, return offline-only result
    if not _api_available():
        result = _empty_result(in_blacklist=in_blacklist)
        if in_blacklist:
            result["abuse_confidence"] = 100
            result["available"] = True
        return result

    # Query the API
    try:
        import requests

        config.ABUSEIPDB_DAILY_COUNT += 1
        resp = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={
                "Key": config.ABUSEIPDB_API_KEY,
                "Accept": "application/json",
            },
            params={"ipAddress": ip_str, "maxAgeInDays": 90, "verbose": ""},
            timeout=5,
        )

        if resp.status_code == 200:
            data = resp.json().get("data", {})
            result = {
                "available": True,
                "abuse_confidence": data.get("abuseConfidenceScore", 0),
                "is_vpn": data.get("isVpn", False) or data.get("isProxy", False),
                "is_tor": data.get("isTor", False),
                "usage_type": data.get("usageType", ""),
                "total_reports": data.get("totalReports", 0),
                "categories": data.get("categories", []),
                "isp": data.get("isp", ""),
                "domain": data.get("domain", ""),
                "in_offline_blacklist": in_blacklist,
                "_cached_at": time.time(),
            }
            config.ABUSEIPDB_CACHE[ip_str] = result
            return result

        elif resp.status_code == 429:
            # Rate limited — disable for rest of session
            print("[ABUSEIPDB] Rate limited! Disabling API for this session.")
            config.ABUSEIPDB_DAILY_COUNT = config.ABUSEIPDB_DAILY_LIMIT
            return _empty_result(in_blacklist=in_blacklist)

        else:
            return _empty_result(in_blacklist=in_blacklist)

    except ImportError:
        print("[ABUSEIPDB] 'requests' library not installed — API disabled")
        config.ABUSEIPDB_ENABLED = False
        return _empty_result(in_blacklist=in_blacklist)
    except Exception:
        return _empty_result(in_blacklist=in_blacklist)


def _empty_result(in_blacklist: bool = False) -> dict:
    """Return an empty AbuseIPDB result."""
    return {
        "available": False,
        "abuse_confidence": 0,
        "is_vpn": False,
        "is_tor": False,
        "usage_type": "",
        "total_reports": 0,
        "categories": [],
        "isp": "",
        "domain": "",
        "in_offline_blacklist": in_blacklist,
    }


def get_status() -> dict:
    """Return AbuseIPDB integration status for admin/debug."""
    return {
        "api_enabled": config.ABUSEIPDB_ENABLED,
        "api_calls_today": config.ABUSEIPDB_DAILY_COUNT,
        "api_limit": config.ABUSEIPDB_DAILY_LIMIT,
        "cached_ips": len(config.ABUSEIPDB_CACHE),
        "offline_blacklist_size": len(_offline_blacklist),
        "offline_loaded": _offline_loaded,
    }
