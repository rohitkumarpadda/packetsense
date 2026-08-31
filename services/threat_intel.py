"""
services/threat_intel.py — Offline IP reputation & threat intelligence engine.

Loads pre-downloaded blocklists from data/threat_intel/ into memory and
provides O(log n) IP lookups against:
  - FireHOL Level 1-3 blocklists
  - IPsum aggregated feed (IPs from 30+ sources)
  - Blocklist.de attack-source lists
"""

import bisect
import ipaddress
import time
from pathlib import Path
from typing import Optional

import config

_threat_networks: list[tuple[int, int, str]] = []
_threat_network_starts: list[int] = []
_threat_single_ips: set[int] = set()
_threat_ip_sources: dict[int, set[str]] = {}
_ipsum_scores: dict[int, int] = {}
_loaded = False
_load_stats: dict[str, int] = {}


def _parse_netset_file(filepath: Path) -> list:
    networks = []
    if not filepath.exists():
        return networks
    try:
        for line in filepath.read_text(errors="replace").splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            try:
                networks.append(ipaddress.ip_network(line, strict=False))
            except ValueError:
                pass
    except Exception as e:
        print(f"[THREAT-INTEL] Parse error {filepath.name}: {e}")
    return networks


def _parse_ipsum_file(filepath: Path, threshold: int = 3) -> dict[int, int]:
    result = {}
    if not filepath.exists():
        return result
    try:
        for line in filepath.read_text(errors="replace").splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split("\t")
            if len(parts) >= 2:
                try:
                    ip_int = int(ipaddress.ip_address(parts[0].strip()))
                    score = int(parts[1].strip())
                    if score >= threshold:
                        result[ip_int] = score
                except (ValueError, IndexError):
                    pass
    except Exception as e:
        print(f"[THREAT-INTEL] Parse error {filepath.name}: {e}")
    return result


def _parse_plain_ip_list(filepath: Path) -> list:
    entries = []
    if not filepath.exists():
        return entries
    try:
        for line in filepath.read_text(errors="replace").splitlines():
            line = line.strip()
            if not line or line.startswith("#") or line.startswith(";"):
                continue
            try:
                entries.append(ipaddress.ip_address(line))
            except ValueError:
                try:
                    entries.append(ipaddress.ip_network(line, strict=False))
                except ValueError:
                    pass
    except Exception as e:
        print(f"[THREAT-INTEL] Parse error {filepath.name}: {e}")
    return entries


def load_threat_databases():
    global _threat_networks, _threat_network_starts, _threat_single_ips
    global _threat_ip_sources, _ipsum_scores, _loaded, _load_stats

    start_time = time.time()
    threat_dir = config.THREAT_INTEL_DIR
    _load_stats = {}

    if not threat_dir.exists():
        print("[THREAT-INTEL] No threat_intel dir. Run scripts/update_threat_intel.py")
        _loaded = True
        config.THREAT_INTEL_LOADED = True
        return

    networks_raw = []

    firehol_files = {
        "firehol_level1": "firehol_level1.netset",
        "firehol_level2": "firehol_level2.netset",
        "firehol_level3": "firehol_level3.netset",
        "firehol_abusers_1d": "firehol_abusers_1d.netset",
        "dshield": "dshield.netset",
        "spamhaus_drop": "spamhaus_drop.netset",
        "spamhaus_edrop": "spamhaus_edrop.netset",
    }
    for source_name, filename in firehol_files.items():
        nets = _parse_netset_file(threat_dir / filename)
        _load_stats[source_name] = len(nets)
        for net in nets:
            networks_raw.append((net, source_name))
        if nets:
            print(f"[THREAT-INTEL] Loaded {source_name}: {len(nets)} networks")

    blocklist_files = {
        "blocklist_de_ssh": "blocklist_de_ssh.txt",
        "blocklist_de_mail": "blocklist_de_mail.txt",
        "blocklist_de_apache": "blocklist_de_apache.txt",
        "blocklist_de_bruteforce": "blocklist_de_bruteforce.txt",
    }
    for source_name, filename in blocklist_files.items():
        entries = _parse_plain_ip_list(threat_dir / filename)
        count = 0
        for entry in entries:
            if isinstance(entry, (ipaddress.IPv4Address, ipaddress.IPv6Address)):
                ip_int = int(entry)
                _threat_single_ips.add(ip_int)
                _threat_ip_sources.setdefault(ip_int, set()).add(source_name)
                count += 1
            else:
                networks_raw.append((entry, source_name))
                count += 1
        _load_stats[source_name] = count
        if count:
            print(f"[THREAT-INTEL] Loaded {source_name}: {count} entries")

    ipsum_file = threat_dir / "ipsum.txt"
    _ipsum_scores = _parse_ipsum_file(ipsum_file, threshold=3)
    _load_stats["ipsum"] = len(_ipsum_scores)
    if _ipsum_scores:
        _threat_single_ips.update(_ipsum_scores.keys())
        for ip_int in _ipsum_scores:
            _threat_ip_sources.setdefault(ip_int, set()).add("ipsum")
        print(f"[THREAT-INTEL] Loaded ipsum: {len(_ipsum_scores)} high-confidence IPs")

    # AbuseIPDB offline blacklist (IPs with 100% abuse confidence)
    abuseipdb_file = threat_dir / "abuseipdb_blacklist.txt"
    abuseipdb_entries = _parse_plain_ip_list(abuseipdb_file)
    abuseipdb_count = 0
    for entry in abuseipdb_entries:
        if isinstance(entry, (ipaddress.IPv4Address, ipaddress.IPv6Address)):
            ip_int = int(entry)
            _threat_single_ips.add(ip_int)
            _threat_ip_sources.setdefault(ip_int, set()).add("abuseipdb")
            abuseipdb_count += 1
        else:
            networks_raw.append((entry, "abuseipdb"))
            abuseipdb_count += 1
    _load_stats["abuseipdb"] = abuseipdb_count
    if abuseipdb_count:
        print(f"[THREAT-INTEL] Loaded abuseipdb: {abuseipdb_count} blacklisted IPs")

    indexed = []
    for net, source in networks_raw:
        indexed.append((int(net.network_address), int(net.broadcast_address), source))
    indexed.sort(key=lambda x: x[0])
    _threat_networks = indexed
    _threat_network_starts = [n[0] for n in indexed]

    elapsed = time.time() - start_time
    print(f"[THREAT-INTEL] Total: {len(_threat_networks)} nets + {len(_threat_single_ips)} IPs ({elapsed:.2f}s)")
    _loaded = True
    config.THREAT_INTEL_LOADED = True
    config.THREAT_INTEL_SOURCES = _load_stats.copy()


CATEGORY_MAP = {
    "firehol_level1": "malware", "firehol_level2": "attacks",
    "firehol_level3": "reputation", "firehol_abusers_1d": "abuse",
    "dshield": "scanning", "spamhaus_drop": "hijacked",
    "spamhaus_edrop": "hijacked", "blocklist_de_ssh": "brute_force",
    "blocklist_de_mail": "spam", "blocklist_de_apache": "web_attacks",
    "blocklist_de_bruteforce": "brute_force", "ipsum": "multi_source_threat",
    "abuseipdb": "crowd_sourced_abuse",
}


def check_ip_reputation(ip_str: str) -> dict:
    if not _loaded:
        return _safe_result()
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return _safe_result()
    if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast:
        return _safe_result()

    ip_int = int(ip)
    sources: set[str] = set()

    if ip_int in _threat_single_ips and ip_int in _threat_ip_sources:
        sources.update(_threat_ip_sources[ip_int])

    idx = bisect.bisect_right(_threat_network_starts, ip_int) - 1
    for i in range(max(0, idx - 5), min(len(_threat_networks), idx + 20)):
        s, e, src = _threat_networks[i]
        if s > ip_int:
            break
        if s <= ip_int <= e:
            sources.add(src)

    ipsum_score = _ipsum_scores.get(ip_int)
    if not sources and ipsum_score is None:
        return _safe_result()

    categories = sorted({CATEGORY_MAP.get(s, "unknown") for s in sources})
    threat_level = _compute_threat_level(sources, ipsum_score)
    details = []
    if sources:
        details.append(f"Found in: {', '.join(sorted(sources))}")
    if ipsum_score:
        details.append(f"IPsum score: {ipsum_score}")

    return {
        "is_malicious": True, "threat_level": threat_level,
        "sources": sorted(sources), "categories": categories,
        "ipsum_score": ipsum_score, "details": "; ".join(details),
    }


def _compute_threat_level(sources: set[str], ipsum_score: Optional[int]) -> str:
    score = 0
    if "firehol_level1" in sources:
        score += 40
    if "spamhaus_drop" in sources or "spamhaus_edrop" in sources:
        score += 40
    if "firehol_level2" in sources:
        score += 25
    if "dshield" in sources:
        score += 20
    if "firehol_level3" in sources:
        score += 10
    if "firehol_abusers_1d" in sources:
        score += 30
    score += sum(15 for s in sources if s.startswith("blocklist_de_"))
    if "abuseipdb" in sources:
        score += 35  # 100% abuse confidence = very strong signal
    if ipsum_score is not None:
        score += min(ipsum_score * 5, 40)
    if score >= 60:
        return "critical"
    if score >= 40:
        return "high"
    if score >= 20:
        return "medium"
    if score > 0:
        return "low"
    return "none"


def _safe_result() -> dict:
    return {
        "is_malicious": False, "threat_level": "none",
        "sources": [], "categories": [],
        "ipsum_score": None, "details": "",
    }


def get_load_stats() -> dict:
    return {
        "loaded": _loaded, "sources": _load_stats.copy(),
        "total_networks": len(_threat_networks),
        "total_single_ips": len(_threat_single_ips),
        "ipsum_entries": len(_ipsum_scores),
    }
