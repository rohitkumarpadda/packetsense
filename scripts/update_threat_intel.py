"""
scripts/update_threat_intel.py — Pre-deployment threat intelligence downloader.

Run this script BEFORE deploying in offline/switch-mode to fetch all
threat intelligence databases while internet is still available.

Usage:
    python scripts/update_threat_intel.py

Downloads:
    - FireHOL Level 1-3 blocklists (malicious IPs/networks)
    - IPsum aggregated threat feed (IPs from 30+ sources)
    - Blocklist.de attack-source lists (SSH, mail, apache, FTP)
    - X4BNet VPN IP ranges
    - Tor exit node list
"""

import os
import sys
import time
from pathlib import Path

import requests

# Resolve project root (one level up from scripts/)
PROJECT_ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = PROJECT_ROOT / "data"
THREAT_INTEL_DIR = DATA_DIR / "threat_intel"
VPN_LISTS_DIR = DATA_DIR / "vpn_lists"

# ── Download sources ──────────────────────────────────────────────

FIREHOL_SOURCES = {
    "firehol_level1": "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset",
    "firehol_level2": "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level2.netset",
    "firehol_level3": "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level3.netset",
    "firehol_abusers_1d": "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_abusers_1d.netset",
    "dshield": "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/dshield.netset",
    "spamhaus_drop": "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/spamhaus_drop.netset",
    "spamhaus_edrop": "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/spamhaus_edrop.netset",
}

IPSUM_SOURCE = {
    "ipsum": "https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt",
}

BLOCKLIST_DE_SOURCES = {
    "blocklist_de_ssh": "https://lists.blocklist.de/lists/ssh.txt",
    "blocklist_de_mail": "https://lists.blocklist.de/lists/mail.txt",
    "blocklist_de_apache": "https://lists.blocklist.de/lists/apache.txt",
    "blocklist_de_bruteforce": "https://lists.blocklist.de/lists/bruteforcelogin.txt",
}

VPN_SOURCES = {
    "x4bnet_ipv4": "https://raw.githubusercontent.com/X4BNet/lists_vpn/main/output/vpn/ipv4.txt",
    "tor_exit_nodes": "https://www.dan.me.uk/torlist/?exit",
}

# AbuseIPDB public blacklist (no API key needed)
# This is a curated list of IPs with 100% abuse confidence.
ABUSEIPDB_SOURCES = {
    "abuseipdb_blacklist": "https://raw.githubusercontent.com/borestad/blocklist-abuseipdb/main/abuseipdb-s100-all.ipv4",
}


def _download_file(url: str, dest: Path, name: str, timeout: int = 30) -> bool:
    """Download a file from URL to dest. Returns True on success."""
    try:
        print(f"  Downloading {name}...", end=" ", flush=True)
        resp = requests.get(url, timeout=timeout)
        if resp.status_code == 200:
            content = resp.text.strip()
            lines = [l for l in content.splitlines() if l.strip() and not l.startswith("#")]
            dest.write_text(content)
            print(f"OK ({len(lines)} entries)")
            return True
        else:
            print(f"FAILED (HTTP {resp.status_code})")
            return False
    except requests.exceptions.Timeout:
        print("FAILED (timeout)")
        return False
    except Exception as e:
        print(f"FAILED ({e})")
        return False


def download_all():
    """Download all threat intelligence databases."""
    THREAT_INTEL_DIR.mkdir(parents=True, exist_ok=True)
    VPN_LISTS_DIR.mkdir(parents=True, exist_ok=True)

    results = {"success": 0, "failed": 0, "skipped": 0}
    start = time.time()

    # ── FireHOL blocklists ────────────────────────────────────────
    print("\n[1/5] FireHOL Blocklists")
    print("=" * 50)
    for name, url in FIREHOL_SOURCES.items():
        dest = THREAT_INTEL_DIR / f"{name}.netset"
        if _download_file(url, dest, name):
            results["success"] += 1
        else:
            results["failed"] += 1

    # ── IPsum aggregated feed ─────────────────────────────────────
    print("\n[2/5] IPsum Aggregated Threat Feed")
    print("=" * 50)
    for name, url in IPSUM_SOURCE.items():
        dest = THREAT_INTEL_DIR / f"{name}.txt"
        if _download_file(url, dest, name):
            results["success"] += 1
        else:
            results["failed"] += 1

    # ── Blocklist.de ──────────────────────────────────────────────
    print("\n[3/5] Blocklist.de Attack Source Lists")
    print("=" * 50)
    for name, url in BLOCKLIST_DE_SOURCES.items():
        dest = THREAT_INTEL_DIR / f"{name}.txt"
        if _download_file(url, dest, name):
            results["success"] += 1
        else:
            results["failed"] += 1

    # ── VPN IP lists ──────────────────────────────────────────────
    print("\n[4/5] VPN / Proxy / Tor IP Lists")
    print("=" * 50)
    for name, url in VPN_SOURCES.items():
        dest = VPN_LISTS_DIR / f"{name}.txt"
        if _download_file(url, dest, name):
            results["success"] += 1
        else:
            results["failed"] += 1

    # ── AbuseIPDB public blacklist ─────────────────────────────────
    print("\n[5/5] AbuseIPDB Public Blacklist (no API key needed)")
    print("=" * 50)
    for name, url in ABUSEIPDB_SOURCES.items():
        dest = THREAT_INTEL_DIR / f"{name}.txt"
        if _download_file(url, dest, name):
            results["success"] += 1
        else:
            results["failed"] += 1

    # ── Summary ───────────────────────────────────────────────────
    elapsed = time.time() - start
    print("\n" + "=" * 50)
    print("DOWNLOAD SUMMARY")
    print("=" * 50)
    print(f"  Successful:  {results['success']}")
    print(f"  Failed:      {results['failed']}")
    print(f"  Time:        {elapsed:.1f}s")
    print(f"  Location:    {THREAT_INTEL_DIR}")

    # Check for MMDB databases
    print("\n[INFO] Checking MMDB databases...")
    mmdb_files = {
        "GeoLite2-City.mmdb": DATA_DIR / "GeoLite2-City.mmdb",
        "GeoLite2-ASN.mmdb": DATA_DIR / "GeoLite2-ASN.mmdb",
        "GeoLite2-Country.mmdb": DATA_DIR / "GeoLite2-Country.mmdb",
    }
    for name, path in mmdb_files.items():
        if path.exists():
            size_mb = path.stat().st_size / (1024 * 1024)
            print(f"  ✓ {name} ({size_mb:.1f} MB)")
        else:
            print(f"  ✗ {name} — MISSING (download from maxmind.com)")

    # Check for DB-IP
    dbip_path = THREAT_INTEL_DIR / "dbip-asn-lite.mmdb"
    if dbip_path.exists():
        size_mb = dbip_path.stat().st_size / (1024 * 1024)
        print(f"  ✓ dbip-asn-lite.mmdb ({size_mb:.1f} MB)")
    else:
        print(f"  ✗ dbip-asn-lite.mmdb — MISSING (download from db-ip.com/db/lite.php)")

    if results["failed"] > 0:
        print(f"\n[WARN] {results['failed']} downloads failed. Re-run when internet is available.")
        return False

    print("\n[OK] All threat intelligence databases are ready for offline use.")
    return True


if __name__ == "__main__":
    print("5G-PacketSense v2 — Threat Intelligence Database Updater")
    print("This script downloads all databases needed for offline operation.\n")

    success = download_all()
    sys.exit(0 if success else 1)
