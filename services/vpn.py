"""
services/vpn.py — Multi-signal VPN detection engine with confidence scoring.

Detection layers (all signals are accumulated, NOT short-circuited):
  1. Cache lookup
  2. ISP/Org keyword matching (with CDN whitelist to avoid false positives)
  3. Known VPN ASN database
  4. Dual-ASN cross-validation (GeoLite2 vs DB-IP agreement)
  5. X4BNet / Tor IP range lists (pre-downloaded)
  6. AbuseIPDB enrichment (optional online, with offline blacklist)
  7. Offline threat intelligence (FireHOL, IPsum, Blocklist.de)
  8. External API enrichment: vpnapi.io, ipinfo.io, ip-api.com

Each layer contributes a confidence score. Final classification:
  0-15   → not_vpn
  16-35  → vpn_suspect
  36-60  → vpn_likely
  61-100 → vpn_confirmed
"""

import ipaddress
import time
from pathlib import Path
from typing import Optional

import config

# ── Confidence weights for each detection signal ─────────────────
#
# Tier 1 — Near-certain (standalone confirmation → vpn_confirmed ≥ 61):
#   X4BNet, Tor lists, vpnapi.io, ipinfo.io Tor → score alone crosses threshold
# Tier 2 — High (61-84, vpn_confirmed with single strong signal):
#   Known VPN ASN, ipinfo.io VPN, ip-api.com proxy
# Tier 3 — Likely (36-60, vpn_likely — corroboration needed):
#   ISP/Org keyword, DB-IP keyword, dual ASN agreement
# Tier 4 — Suspect (16-35):
#   Protocol heuristics, AbuseIPDB flags
# Tier 5 — Insufficient (<16):
#   Weak corroborating signals

CONFIDENCE_WEIGHTS = {
    # ── Tier 1: Near-certain IP list signals ─────────────────────────────────
    "x4bnet_vpn":              85,  # IP in X4BNet curated VPN list (standalone confirmation)
    "x4bnet_corroborated":     90,  # X4BNet match + ISP keyword agreement (near-certain)
    "tor_exit_node":           90,  # Confirmed Tor exit node (was: 50)

    # ── Tier 1: Purpose-built VPN detection API signals ──────────────────────
    "vpnapi_tor_flag":         90,  # vpnapi.io confirms Tor (was: 55)
    "vpnapi_vpn_flag":         75,  # vpnapi.io confirms VPN/proxy/relay (was: 45)
    "vpnapi_proxy_flag":       65,  # vpnapi.io proxy-only flag (was: 40)
    "ipinfo_tor_flag":         80,  # ipinfo.io privacy.tor confirmed (was: 45)

    # ── Tier 2: High-confidence signals ──────────────────────────────────────
    "asn_database":            65,  # ASN exclusively owned by VPN provider (was: 40)
    "ipinfo_vpn_flag":         60,  # ipinfo.io privacy.vpn/proxy confirmed (was: 40)
    "ipapi_proxy_flag":        50,  # ip-api.com proxy=true flag (was: 35)
    "ipinfo_relay_flag":       40,  # ipinfo.io privacy.relay (was: 25)

    # ── API consensus bonuses — independent APIs agreeing raises certainty ────
    "api_consensus_2":         20,  # 2 out of 3 established APIs independently confirm VPN
    "api_consensus_3":         35,  # All 3 established APIs agree — near-certain

    # ── Tier 3: Likely signals (need corroboration) ───────────────────────────
    "keyword_match":           35,  # ISP/Org name matched VPN provider keyword
    "dual_asn_agreement":      15,  # Both GeoLite2 and DB-IP agree on VPN org
    "dbip_vpn_keyword":        20,  # DB-IP org name matches VPN provider (GeoLite2 didn't)

    # ── Tier 4: Suspect signals ───────────────────────────────────────────────
    "protocol_strong":         20,  # Non-ambiguous VPN port (WireGuard, IPSec)
    "protocol_weak":           10,  # Ambiguous port (OpenVPN alt, etc.)
    "abuseipdb_vpn_flag":      20,  # AbuseIPDB explicitly marks as VPN/proxy
    "abuseipdb_tor_flag":      25,  # AbuseIPDB marks as Tor
    "abuseipdb_blacklist":     10,  # In AbuseIPDB offline blacklist
    "threat_intel_vpn_corr":   10,  # Threat intel + VPN IP range correlation

    # ── Tier 5: Legacy/fallback (kept for backward compat, low weight) ────────
    "ip_range_corroborated":   45,  # Legacy: non-X4BNet list + ISP confirms
    "ip_range_uncorroborated": 15,  # Legacy: non-X4BNet list, ISP doesn't match

    # ── Relay-only signal — VERY LOW (not a VPN exit node, just a CDN/hosting env) ──
    # vpnapi.io 'is_relay=True' without 'is_vpn=True': the IP hosts relays (cloud infra).
    # This CANNOT alone cross the is_vpn threshold (36). Only adds minor suspicion.
    "vpnapi_relay_only":        5,
}


# ── Layer 1: ISP / Org keyword matching ──────────────────────────

VPN_PROVIDERS = {
    "NordVPN": ["nordvpn", "nord vpn", "tesonet", "tefincom"],
    "ExpressVPN": ["expressvpn", "express vpn", "express networks"],
    "ProtonVPN": ["protonvpn", "proton vpn", "proton ag", "proton technologies"],
    "Surfshark": ["surfshark"],
    "Private Internet Access": [
        "private internet access",
        "london trust media",
        "kape technologies",
    ],
    "CyberGhost": ["cyberghost", "cg server"],
    "IPVanish": ["ipvanish", "mudhook marketing", "stackpath"],
    "Mullvad": ["mullvad", "aeza group", "31173 services"],
    "TunnelBear": ["tunnelbear"],
    "Windscribe": ["windscribe"],
    "VyprVPN": ["vyprvpn", "golden frog"],
    "HideMyAss": ["hidemyass", "hma", "privax"],
    "TorGuard": ["torguard"],
    "Perfect Privacy": ["perfect privacy", "perfect-privacy"],
    "AirVPN": ["airvpn"],
    "IVPN": ["ivpn"],
    "VPN.ac": ["vpn.ac", "netlabs"],
    "ZenMate": ["zenmate"],
    "Atlas VPN": ["atlas vpn", "atlasvpn"],
    "Hotspot Shield": ["hotspot shield", "anchorfree", "pango", "aura"],
    "PrivateVPN": ["privatevpn"],
    "StrongVPN": ["strongvpn", "reliablehosting"],
    "VPN Unlimited": ["vpn unlimited", "keepsolid"],
    "PureVPN": ["purevpn", "gaditek"],
    "Astrill": ["astrill"],
    "hide.me": ["hide.me", "eventnet", "ehostserver"],
    "Mozilla VPN": ["mozilla vpn"],
    "Kaspersky VPN": ["kaspersky"],
    "Norton VPN": ["norton", "symantec"],
    "Psiphon": ["psiphon"],
    "Lantern": ["lantern"],
    "Opera VPN": ["opera vpn", "surfeasy"],
    "1.1.1.1 WARP": ["cloudflare warp", "warp+", "warp plus"],
    "iCloud Private Relay": ["apple private relay", "aaplrelay"],
}

# ── Major CDN/cloud infrastructure ASNs to NEVER flag as VPN ───────────
# These serve legitimate traffic for the vast majority of the internet.
# vpnapi.io correctly marks many of these as "relay" (they do host relays)
# but that is NOT the same as a VPN exit node.

CDN_WHITELIST_ASNS = {
    # Cloudflare
    "AS13335", "AS209242", "AS132892", "AS395747", "AS133877",
    # Google / Google Cloud
    "AS15169", "AS396982", "AS19527", "AS36040", "AS43515",
    "AS22859", "AS24429", "AS36385", "AS36384", "AS139190",
    # Microsoft / Azure / Office 365
    "AS8075", "AS8068", "AS8069", "AS8070", "AS8071",
    "AS8072", "AS8073", "AS8078", "AS3598",  "AS6182",
    "AS6194", "AS12222", "AS8067", "AS32475", "AS36375",
    # Amazon / AWS
    "AS16509", "AS14618", "AS7224", "AS38895", "AS16604",
    # Akamai
    "AS20940", "AS16625", "AS18717", "AS23454", "AS31108",
    # Fastly
    "AS54113", "AS394536",
    # Meta / Facebook
    "AS32934", "AS63293", "AS54115",
    # Apple
    "AS714",  "AS6185",
    # Netflix
    "AS2906", "AS40027",
    # GitHub / Microsoft
    "AS36459",
    # Twitch / Amazon
    "AS46489",
    # Comcast / ISPs (never VPN ASNs)
    "AS7922",  "AS7015",
    # AT&T
    "AS7018",  "AS20057",
    # Verizon
    "AS701",  "AS702",
}

# ISP/org name fragments for cloud & infrastructure providers.
# Used as a SECONDARY check when the ASN is not in the list above.
# Only MAJOR providers whose IPs are overwhelmingly legitimate traffic.
_CLOUD_ISP_KEYWORDS: frozenset = frozenset([
    "microsoft", "amazon.com", "google llc", "cloudflare",
    "fastly", "akamai", "apple inc", "meta platforms",
    "facebook", "netflix", "twitch", "github",
    "at&t", "comcast", "verizon", "deutsche telekom",
    "orange s.a", "vodafone", "bt group", "ntt ",
])

# ── Layer 2: Known VPN ASN numbers ───────────────────────────────

VPN_ASN_DATABASE = {
    # Only ASNs exclusively owned/operated by VPN providers.
    # Hosting providers (M247, Datacamp, Vultr, etc.) are NOT included
    # because they serve both VPN and legitimate traffic — without an
    # API to verify, flagging all their traffic causes false positives.
    "AS212238": "NordVPN",
    "AS394711": "NordVPN",
    "AS210565": "NordVPN",
    "AS18450": "ExpressVPN",
    "AS209103": "ProtonVPN",
    "AS51852": "ProtonVPN",
    "AS198093": "Mullvad",
    "AS31173": "Mullvad",
    "AS26496": "Private Internet Access",
    "AS44592": "CyberGhost",
    "AS33438": "IPVanish",
    "AS55286": "IPVanish",
    "AS399532": "TorGuard",
    "AS25379": "Windscribe",
    "AS36351": "VyprVPN",
    "AS198605": "HideMyAss",
    "AS205467": "AirVPN",
    "AS398789": "IVPN",
}

# ── VPN protocol port signatures ─────────────────────────────────

VPN_PROTOCOL_PORTS = {
    443: "HTTPS/SSL VPN",
    1194: "OpenVPN",
    1195: "OpenVPN (alt)",
    500: "IKE (IPSec)",
    4500: "IPSec NAT-T",
    1701: "L2TP",
    1723: "PPTP",
    51820: "WireGuard",
    51821: "WireGuard (alt)",
    4443: "OpenVPN (alt)",
    8443: "OpenVPN (alt)",
    41194: "Mullvad OpenVPN",
    53: "DNS/VPN tunnel",
}

# Ports that are strong VPN indicators (not shared with common services)
STRONG_VPN_PORTS = {1194, 1195, 1701, 1723, 51820, 51821, 41194, 4500}


# ── IP list loader (offline only) ────────────────────────────────

# Each entry: (ip_network, source_name)
_VPN_IP_ENTRIES: list[tuple] = []  # populated by load_vpn_ip_lists


def load_vpn_ip_lists():
    """Load VPN IP ranges from pre-downloaded local files.
    No download attempts are made — files must exist from a prior
    run of scripts/update_threat_intel.py.
    """
    global _VPN_IP_ENTRIES
    vpn_dir = config.DATA_DIR / "vpn_lists"
    vpn_dir.mkdir(parents=True, exist_ok=True)
    entries: list[tuple] = []

    _load_from_cache(vpn_dir, "x4bnet_ipv4", entries, source_label="X4BNet VPN IP List", single_ips=False)
    _load_from_cache(vpn_dir, "tor_exit_nodes", entries, source_label="Tor Exit Node List", single_ips=True)

    _VPN_IP_ENTRIES = entries
    config.VPN_IP_RANGES_V4 = [e[0] for e in entries]
    config.VPN_IP_RANGES_LOADED = True
    print(f"[VPN-DB] Total networks loaded: {len(config.VPN_IP_RANGES_V4)}")


def _load_from_cache(
    vpn_dir: Path, name: str, out: list, source_label: str = "", single_ips: bool = False
):
    """Load IP ranges from a cached local file."""
    cache_file = vpn_dir / f"{name}.txt"
    if not cache_file.exists():
        print(f"[VPN-DB] {name}.txt not found — run scripts/update_threat_intel.py")
        return

    label = source_label or name
    age_hours = (time.time() - cache_file.stat().st_mtime) / 3600
    count = 0
    try:
        for line in cache_file.read_text().strip().splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            try:
                cidr = f"{line}/32" if single_ips and "/" not in line else line
                out.append((ipaddress.ip_network(cidr, strict=False), label))
                count += 1
            except ValueError:
                pass
    except Exception as e:
        print(f"[VPN-DB] Parse error for {name}: {e}")
        return

    print(f"[VPN-DB] Loaded {name}: {count} entries (age: {int(age_hours)}h)")


def check_ip_in_vpn_ranges(ip_str: str) -> tuple[bool, str]:
    """Check if IP falls within any downloaded VPN CIDR range.
    Returns (matched: bool, source_label: str).
    """
    if not config.VPN_IP_RANGES_LOADED or not _VPN_IP_ENTRIES:
        return False, ""
    try:
        ip = ipaddress.ip_address(ip_str)
        for net, label in _VPN_IP_ENTRIES:
            if ip in net:
                return True, label
    except ValueError:
        pass
    return False, ""


# ── Classification thresholds ────────────────────────────────────

def _classify_confidence(confidence: int) -> str:
    """Map a confidence score (0-100) to a classification label."""
    if confidence >= 61:
        return "vpn_confirmed"
    if confidence >= 36:
        return "vpn_likely"
    if confidence >= 16:
        return "vpn_suspect"
    return "not_vpn"


# ── Helpers ──────────────────────────────────────────────────────

def _extract_asn_number(asn: str) -> str:
    """Extract the AS#### token from strings like 'AS13335 Cloudflare, Inc.'."""
    return asn.split()[0] if asn else ""


def _is_cdn_whitelisted(asn: str, isp: str = "") -> bool:
    """Return True if this IP belongs to a major CDN or cloud infrastructure.

    Two-tier check:
      1. ASN number exact match against CDN_WHITELIST_ASNS
      2. ISP/org name substring match against _CLOUD_ISP_KEYWORDS
         (catches IPs that GeoLite2 assigns to an unlisted Microsoft/AWS ASN)
    """
    if _extract_asn_number(asn) in CDN_WHITELIST_ASNS:
        return True
    # Secondary: check ISP/org name for known cloud provider names
    if isp:
        isp_lower = isp.lower()
        if any(kw in isp_lower for kw in _CLOUD_ISP_KEYWORDS):
            return True
    return False


def _check_vpn_keywords(text: str) -> tuple[Optional[str], Optional[str]]:
    """Check text against all VPN provider keywords.
    Returns (provider_name, matched_keyword) or (None, None).
    """
    text_lower = text.lower()
    for vpn_name, keywords in VPN_PROVIDERS.items():
        for kw in keywords:
            if kw in text_lower:
                return vpn_name, kw
    return None, None


# ── Main detection function ──────────────────────────────────────


def detect_vpn(ip: str, isp: str, asn: str, asn_data: dict = None) -> dict:
    """Multi-signal VPN detection with confidence scoring.

    All detection layers are evaluated and their confidence signals are
    accumulated. The result includes:
      - is_vpn: bool (True if confidence >= 36)
      - confidence: int (0-100)
      - classification: str (not_vpn, vpn_suspect, vpn_likely, vpn_confirmed)
      - provider: str or None
      - method: str (primary detection method)
      - method_detail: str (human-readable explanation)
      - signals: list[dict] (each contributing signal)

    Args:
        ip: IP address string
        isp: ISP/org name from primary ASN database
        asn: ASN string (e.g. "AS12345 Company Name")
        asn_data: Optional cross-validation dict from geo._lookup_asn()
    """
    cache_key = f"{ip}_{isp}_{asn}"
    if cache_key in config.VPN_CACHE:
        return config.VPN_CACHE[cache_key]

    signals: list[dict] = []
    confidence = 0
    detected_provider = None
    primary_method = None
    primary_detail = None

    # ── CDN / infrastructure whitelist check ────────────────────
    # Pass BOTH ASN and ISP so the secondary ISP-keyword check fires for
    # Microsoft/AWS/Google IPs that GeoLite2 assigns to unlisted ASNs.
    is_cdn = _is_cdn_whitelisted(asn, isp)

    # ── Signal 1: ISP/Org keyword matching ───────────────────
    if not is_cdn:
        provider, matched_kw = _check_vpn_keywords(f"{isp} {asn}")
        if provider:
            weight = CONFIDENCE_WEIGHTS["keyword_match"]
            confidence += weight
            detected_provider = provider
            primary_method = "keyword"
            primary_detail = f"ISP/Org keyword '{matched_kw}' matched VPN provider '{provider}'"
            signals.append({
                "type": "keyword_match",
                "weight": weight,
                "detail": primary_detail,
                "provider": provider,
            })

    # ── Signal 2: Known VPN ASN database ─────────────────────
    if asn and asn not in ("Unknown", "N/A") and not is_cdn:
        asn_number = _extract_asn_number(asn)
        if asn_number in VPN_ASN_DATABASE:
            vpn_name = VPN_ASN_DATABASE[asn_number]
            weight = CONFIDENCE_WEIGHTS["asn_database"]
            confidence += weight
            detected_provider = detected_provider or vpn_name
            detail = f"{asn_number} matched known VPN ASN -> {vpn_name}"
            if not primary_method:
                primary_method = "asn_database"
                primary_detail = detail
            signals.append({
                "type": "asn_database",
                "weight": weight,
                "detail": detail,
                "provider": vpn_name,
            })

    # ── Signal 3: Dual-ASN cross-validation (DB-IP) ──────────
    if asn_data and not is_cdn:
        dbip_info = asn_data.get("dbip")
        if dbip_info:
            db_isp = dbip_info.get("isp", "")
            db_provider, db_kw = _check_vpn_keywords(f"{db_isp} {dbip_info.get('asn', '')}")

            if db_provider:
                if detected_provider:
                    # Both GeoLite2 + DB-IP agree → cross-validation bonus
                    weight = CONFIDENCE_WEIGHTS["dual_asn_agreement"]
                    confidence += weight
                    detail = f"DB-IP also identifies '{db_provider}' (cross-validated with GeoLite2)"
                    signals.append({
                        "type": "dual_asn_agreement",
                        "weight": weight,
                        "detail": detail,
                        "provider": db_provider,
                    })
                else:
                    # Only DB-IP found VPN keywords
                    weight = CONFIDENCE_WEIGHTS["dbip_vpn_keyword"]
                    confidence += weight
                    detected_provider = db_provider
                    detail = f"DB-IP org '{db_isp}' matched VPN provider '{db_provider}'"
                    if not primary_method:
                        primary_method = "dbip_keyword"
                        primary_detail = detail
                    signals.append({
                        "type": "dbip_vpn_keyword",
                        "weight": weight,
                        "detail": detail,
                        "provider": db_provider,
                    })

            # Check DB-IP ASN number against VPN ASN database
            db_asn_num = dbip_info.get("asn_number")
            if db_asn_num:
                db_asn_str = f"AS{db_asn_num}"
                if db_asn_str in VPN_ASN_DATABASE and db_asn_str != _extract_asn_number(asn):
                    vpn_name = VPN_ASN_DATABASE[db_asn_str]
                    weight = CONFIDENCE_WEIGHTS["asn_database"]
                    confidence += weight
                    detected_provider = detected_provider or vpn_name
                    detail = f"DB-IP ASN {db_asn_str} matched VPN ASN -> {vpn_name}"
                    signals.append({
                        "type": "dbip_asn_database",
                        "weight": weight,
                        "detail": detail,
                        "provider": vpn_name,
                    })

    # ── Signal 4: IP range lists (pre-downloaded) ────────────
    # X4BNet is a maintained, curated VPN IP database — a match alone is
    # near-certain confirmation regardless of ISP keyword corroboration.
    # Tor exit nodes are also near-certain by definition.
    # Other/unknown list sources fall back to legacy corroborated/uncorroborated logic.
    ip_matched, source_label = check_ip_in_vpn_ranges(ip)
    if ip_matched:
        is_tor = "tor" in source_label.lower()
        is_x4bnet = "x4bnet" in source_label.lower()

        if is_tor:
            weight = CONFIDENCE_WEIGHTS["tor_exit_node"]   # 90 pts — near-certain
            confidence += weight
            detected_provider = detected_provider or "Tor"
            detail = f"Confirmed Tor exit node (source: {source_label})"
            if not primary_method:
                primary_method = "tor_exit_node"
                primary_detail = detail
            signals.append({
                "type": "tor_exit_node",
                "weight": weight,
                "detail": detail,
                "provider": "Tor",
            })

        elif is_x4bnet:
            # X4BNet is a curated, maintained VPN IP range list.
            # A match is standalone confirmation — ISP corroboration raises it further.
            corroborated_provider, _ = _check_vpn_keywords(isp or "")
            if corroborated_provider:
                weight = CONFIDENCE_WEIGHTS["x4bnet_corroborated"]  # 90 pts
                sig_type = "x4bnet_corroborated"
                detail = f"IP in X4BNet VPN database + ISP '{isp}' confirms {corroborated_provider} (near-certain)"
                detected_provider = detected_provider or corroborated_provider
            else:
                weight = CONFIDENCE_WEIGHTS["x4bnet_vpn"]  # 85 pts — still vpn_confirmed
                sig_type = "x4bnet_vpn"
                detail = f"IP in X4BNet curated VPN database (source: {source_label})"
            confidence += weight
            if not primary_method:
                primary_method = "x4bnet"
                primary_detail = detail
            signals.append({
                "type": sig_type,
                "weight": weight,
                "detail": detail,
                "provider": detected_provider,
            })

        else:
            # Legacy path for any other list source (non-X4BNet, non-Tor)
            corroborated_provider, _ = _check_vpn_keywords(isp or "")
            if corroborated_provider:
                weight = CONFIDENCE_WEIGHTS["ip_range_corroborated"]
                confidence += weight
                detected_provider = detected_provider or corroborated_provider
                detail = f"IP in '{source_label}' + ISP '{isp}' confirms {corroborated_provider}"
                if not primary_method:
                    primary_method = "ip_database"
                    primary_detail = detail
                signals.append({
                    "type": "ip_range_corroborated",
                    "weight": weight,
                    "detail": detail,
                    "provider": corroborated_provider,
                })
            else:
                weight = CONFIDENCE_WEIGHTS["ip_range_uncorroborated"]
                confidence += weight
                detail = f"IP found in '{source_label}' but ISP '{isp}' is not a known VPN provider"
                signals.append({
                    "type": "ip_range_uncorroborated",
                    "weight": weight,
                    "detail": detail,
                })

    # ── Signal 5: AbuseIPDB enrichment (skipped in FAST_MODE) ──
    if not config.FAST_MODE and not ip.startswith(("10.", "172.", "192.168.", "127.")):
        try:
            from services.abuseipdb import check_ip_abuseipdb
            abuse_result = check_ip_abuseipdb(ip)

            if abuse_result.get("in_offline_blacklist"):
                weight = CONFIDENCE_WEIGHTS["abuseipdb_blacklist"]
                confidence += weight
                signals.append({
                    "type": "abuseipdb_blacklist",
                    "weight": weight,
                    "detail": "IP found in AbuseIPDB offline blacklist (100% abuse confidence)",
                })

            if abuse_result.get("available"):
                if abuse_result.get("is_tor"):
                    weight = CONFIDENCE_WEIGHTS["abuseipdb_tor_flag"]
                    confidence += weight
                    detected_provider = detected_provider or "Tor"
                    signals.append({
                        "type": "abuseipdb_tor_flag",
                        "weight": weight,
                        "detail": f"AbuseIPDB flags as Tor node (abuse confidence: {abuse_result.get('abuse_confidence', 0)}%)",
                        "provider": "Tor",
                    })
                elif abuse_result.get("is_vpn"):
                    weight = CONFIDENCE_WEIGHTS["abuseipdb_vpn_flag"]
                    confidence += weight
                    signals.append({
                        "type": "abuseipdb_vpn_flag",
                        "weight": weight,
                        "detail": f"AbuseIPDB flags as VPN/proxy (abuse confidence: {abuse_result.get('abuse_confidence', 0)}%, ISP: {abuse_result.get('isp', 'N/A')})",
                    })
        except ImportError:
            pass

    # ── Signal 6: Offline threat intelligence correlation (skipped in FAST_MODE) ──
    if not config.FAST_MODE and not ip.startswith(("10.", "172.", "192.168.", "127.")):
        try:
            from services.threat_intel import check_ip_reputation
            rep = check_ip_reputation(ip)
            if rep.get("is_malicious") and ip_matched and rep.get("threat_level") in ("high", "critical"):
                weight = CONFIDENCE_WEIGHTS["threat_intel_vpn_corr"]
                confidence += weight
                sources = ", ".join(rep.get("sources", []))
                signals.append({
                    "type": "threat_intel_vpn_corr",
                    "weight": weight,
                    "detail": f"Threat intel corroborates VPN range match (sources: {sources})",
                })
        except ImportError:
            pass

    # ── Signal 7: External API enrichment (SKIPPED for CDN/cloud infrastructure) ──
    # Key principle: vpnapi.io marks cloud provider IPs (Microsoft Azure, AWS,
    # Google Cloud, Cloudflare, Fastly) as "relay" because they DO host relay
    # services. This is NOT the same as a VPN exit node. The CDN whitelist gate
    # below prevents these false positives.
    #
    # Relay-only (`is_relay=True`, `is_vpn=False`, `is_proxy=False`) gets a very
    # small weight because it just means "this IP is in a hosting/CDN network" —
    # not that the specific IP is a VPN server.
    if not is_cdn and not ip.startswith(("10.", "172.", "192.168.", "127.")):
        try:
            from services.vpn_api import query_all_vpn_apis
            api_result = query_all_vpn_apis(ip)

            if api_result.get("available"):
                api_positive_votes = 0

                for sig in api_result.get("signals", []):
                    source = sig.get("source", "")
                    sig_flagged = False

                    if "vpnapi.io" in source:
                        if sig.get("is_tor"):
                            weight = CONFIDENCE_WEIGHTS["vpnapi_tor_flag"]
                            confidence += weight
                            detected_provider = detected_provider or "Tor"
                            signals.append({
                                "type": "vpnapi_tor_flag",
                                "weight": weight,
                                "detail": "vpnapi.io confirms Tor exit node",
                                "provider": "Tor",
                                "api": "vpnapi.io",
                            })
                            sig_flagged = True
                        elif sig.get("is_vpn"):
                            # Confirmed VPN exit node — high weight
                            weight = CONFIDENCE_WEIGHTS["vpnapi_vpn_flag"]
                            confidence += weight
                            provider_hint = sig.get("provider")
                            detected_provider = detected_provider or provider_hint
                            signals.append({
                                "type": "vpnapi_vpn_flag",
                                "weight": weight,
                                "detail": f"vpnapi.io confirms VPN exit node — provider: {provider_hint or 'unknown'}",
                                "provider": provider_hint,
                                "api": "vpnapi.io",
                            })
                            sig_flagged = True
                        elif sig.get("is_proxy") and not sig.get("is_relay"):
                            # Proxy (not just relay) — medium weight
                            weight = CONFIDENCE_WEIGHTS["vpnapi_proxy_flag"]
                            confidence += weight
                            provider_hint = sig.get("provider")
                            detected_provider = detected_provider or provider_hint
                            signals.append({
                                "type": "vpnapi_proxy_flag",
                                "weight": weight,
                                "detail": f"vpnapi.io confirms proxy — provider: {provider_hint or 'unknown'}",
                                "provider": provider_hint,
                                "api": "vpnapi.io",
                            })
                            sig_flagged = True
                        elif sig.get("is_relay") and not sig.get("is_vpn") and not sig.get("is_proxy"):
                            # Relay-only — VERY LOW weight: this just means CDN/hosting env.
                            # Needs at least 3 other non-API signals to reach is_vpn threshold.
                            weight = CONFIDENCE_WEIGHTS.get("vpnapi_relay_only", 5)
                            confidence += weight
                            signals.append({
                                "type": "vpnapi_relay_only",
                                "weight": weight,
                                "detail": "vpnapi.io: relay-only flag (hosting/CDN environment — low confidence)",
                                "api": "vpnapi.io",
                            })
                            # relay-only does NOT count as a positive vote

                    elif "ipinfo.io" in source:
                        if sig.get("is_tor"):
                            weight = CONFIDENCE_WEIGHTS["ipinfo_tor_flag"]
                            confidence += weight
                            detected_provider = detected_provider or "Tor"
                            signals.append({
                                "type": "ipinfo_tor_flag",
                                "weight": weight,
                                "detail": "ipinfo.io confirms Tor exit node",
                                "provider": "Tor",
                                "api": "ipinfo.io",
                            })
                            sig_flagged = True
                        elif sig.get("is_vpn") or sig.get("is_proxy"):
                            weight = CONFIDENCE_WEIGHTS["ipinfo_vpn_flag"]
                            confidence += weight
                            provider_hint = sig.get("provider")
                            detected_provider = detected_provider or provider_hint
                            signals.append({
                                "type": "ipinfo_vpn_flag",
                                "weight": weight,
                                "detail": f"ipinfo.io confirms VPN/proxy — provider: {provider_hint or 'unknown'}",
                                "provider": provider_hint,
                                "api": "ipinfo.io",
                            })
                            sig_flagged = True
                        elif sig.get("is_relay") and not sig.get("is_vpn") and not sig.get("is_proxy"):
                            # iCloud Private Relay / CDN relay — low but non-zero weight
                            weight = CONFIDENCE_WEIGHTS["ipinfo_relay_flag"]
                            confidence += weight
                            signals.append({
                                "type": "ipinfo_relay_flag",
                                "weight": weight,
                                "detail": "ipinfo.io: privacy relay flag (e.g. iCloud Private Relay)",
                                "api": "ipinfo.io",
                            })
                            sig_flagged = True

                    elif "ip-api.com" in source:
                        if sig.get("is_proxy"):
                            weight = CONFIDENCE_WEIGHTS["ipapi_proxy_flag"]
                            confidence += weight
                            provider_hint = sig.get("provider")
                            detected_provider = detected_provider or provider_hint
                            signals.append({
                                "type": "ipapi_proxy_flag",
                                "weight": weight,
                                "detail": f"ip-api.com proxy=true — org: {provider_hint or 'unknown'}",
                                "api": "ip-api.com",
                            })
                            sig_flagged = True

                    if sig_flagged:
                        api_positive_votes += 1

                # ── API consensus bonus ───────────────────────────────
                if api_positive_votes >= 3:
                    weight = CONFIDENCE_WEIGHTS["api_consensus_3"]
                    confidence += weight
                    signals.append({
                        "type": "api_consensus_3",
                        "weight": weight,
                        "detail": "All 3 established APIs (vpnapi.io + ipinfo.io + ip-api.com) independently confirm VPN/proxy — very high confidence",
                        "api": "consensus",
                    })
                    if not primary_method:
                        primary_method = "api_consensus_3"
                        primary_detail = signals[-1]["detail"]
                elif api_positive_votes == 2:
                    weight = CONFIDENCE_WEIGHTS["api_consensus_2"]
                    confidence += weight
                    signals.append({
                        "type": "api_consensus_2",
                        "weight": weight,
                        "detail": "2 out of 3 established APIs independently confirm VPN/proxy (strong evidence)",
                        "api": "consensus",
                    })

                # Set primary method from highest-weight API signal if not yet set
                if not primary_method and signals:
                    api_signals = [s for s in signals if s["type"].startswith(("vpnapi_", "ipinfo_", "ipapi_", "api_consensus"))]
                    if api_signals:
                        best = max(api_signals, key=lambda s: s["weight"])
                        primary_method = best["type"]
                        primary_detail = best["detail"]

        except ImportError:
            pass



    # ── Build final result ───────────────────────────────────
    confidence = min(confidence, 100)
    classification = _classify_confidence(confidence)
    is_vpn = classification in ("vpn_likely", "vpn_confirmed")

    # Use the highest-weight signal as primary if none was set
    if not primary_method and signals:
        best_signal = max(signals, key=lambda s: s["weight"])
        primary_method = best_signal["type"]
        primary_detail = best_signal["detail"]

    result = {
        "is_vpn": is_vpn,
        "confidence": confidence,
        "classification": classification,
        "provider": detected_provider,
        "method": primary_method,
        "method_detail": primary_detail or "",
        "signals": signals,
    }

    # Preserve backward-compat fields for suspect IPs
    if ip_matched and not is_vpn and confidence > 0:
        result["vpn_suspect"] = True
        result["suspect_source"] = source_label
        uncorr_signals = [s for s in signals if s["type"] == "ip_range_uncorroborated"]
        if uncorr_signals:
            result["suspect_detail"] = uncorr_signals[0]["detail"]

    # Cache with automatic eviction to prevent unbounded memory growth
    config.evict_cache_if_needed(config.VPN_CACHE, config.VPN_CACHE_MAX, "VPN_CACHE")
    config.VPN_CACHE[cache_key] = result
    return result


def detect_vpn_protocol_heuristic(packet, src_port, dst_port, protocol):
    """DPI-lite: detect VPN by port/protocol heuristics."""
    from scapy.all import IP

    hints = []

    for port in (src_port, dst_port):
        if port in VPN_PROTOCOL_PORTS:
            if port not in (443, 53):
                hints.append({
                    "port": port,
                    "protocol_hint": VPN_PROTOCOL_PORTS[port],
                    "strength": "strong" if port in STRONG_VPN_PORTS else "weak",
                })
            elif port == 53 and protocol == "TCP" and len(packet) > 200:
                hints.append({"port": port, "protocol_hint": "DNS Tunnel (suspicious)", "strength": "weak"})

    if protocol == "UDP" and 51820 <= dst_port <= 51830:
        hints.append({"port": dst_port, "protocol_hint": "WireGuard", "strength": "strong"})

    if IP in packet and packet[IP].proto == 50:
        hints.append({"port": 0, "protocol_hint": "IPSec ESP", "strength": "strong"})

    if protocol == "UDP" and dst_port in (500, 4500):
        hints.append({"port": dst_port, "protocol_hint": VPN_PROTOCOL_PORTS[dst_port], "strength": "strong"})

    if 1194 in (dst_port, src_port):
        hints.append({"port": 1194, "protocol_hint": "OpenVPN", "strength": "strong"})

    return hints
