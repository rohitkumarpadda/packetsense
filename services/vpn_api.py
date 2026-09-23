"""
services/vpn_api.py — Unified external VPN/proxy API enrichment layer.

Integrates three online APIs to supplement offline VPN detection:

  1. vpnapi.io       — Requires VPNAPI_IO_KEY in .env (free: 1,000/day)
                       Returns: vpn, proxy, tor, relay, anonymizer flags
  2. ipinfo.io       — Optional IPINFO_TOKEN in .env (free without key: 50k/mo)
                       Returns: privacy.vpn, privacy.proxy, privacy.tor, privacy.relay
  3. ip-api.com      — No key required (free: 45 req/min)
                       Returns: proxy flag, hosting flag, ISP/org

Design principles:
  - All APIs fail gracefully → {available: False} without raising
  - Per-API caches with 24h TTL to minimize API calls
  - Per-API rate-limit tracking (daily for keyed APIs, per-minute for ip-api.com)
  - Private/loopback IPs are skipped immediately
  - Short request timeouts (4 s) to avoid blocking packet processing
"""

import ipaddress
import time
from typing import Optional

import config

# ── Shared private-IP guard ─────────────────────────────────────────


def _is_non_routable(ip_str: str) -> bool:
    """Return True for private, loopback, link-local, and multicast IPs."""
    try:
        ip = ipaddress.ip_address(ip_str)
        return ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast
    except ValueError:
        return True


_NEGATIVE_TTL = 300   # Cache negative (failed) results for 5 minutes
_POSITIVE_TTL = 86400 # Cache positive (successful) results for 24 hours


def _get_cached(cache: dict, ip: str) -> Optional[dict]:
    """Return a cached result if it is still within its TTL.

    Positive results (available=True)  → 24 h TTL
    Negative results (available=False) → 5 min TTL (retry after a while)
    """
    entry = cache.get(ip)
    if not entry:
        return None
    age = time.time() - entry.get("_cached_at", 0)
    ttl = _POSITIVE_TTL if entry.get("available") else _NEGATIVE_TTL
    if age < ttl:
        return entry
    # Expired — remove stale entry
    cache.pop(ip, None)
    return None


def _store_cached(cache: dict, ip: str, result: dict) -> dict:
    """Store a result in cache with the current timestamp."""
    result["_cached_at"] = time.time()
    cache[ip] = result
    return result


# ── Normalised result schema ────────────────────────────────────────


def _empty(source: str) -> dict:
    return {
        "available": False,
        "is_vpn": False,
        "is_proxy": False,
        "is_tor": False,
        "is_relay": False,
        "provider": None,
        "source": source,
    }


# ── 1. vpnapi.io ────────────────────────────────────────────────────


def query_vpnapi_io(ip: str) -> dict:
    """Query vpnapi.io for VPN/proxy/Tor/relay status.

    Requires VPNAPI_IO_KEY in .env.
    Free tier: 1,000 lookups/day.
    Returns a normalised dict (see _empty()).
    """
    source = "vpnapi.io"

    if _is_non_routable(ip):
        return _empty(source)

    cached = _get_cached(config.VPNAPI_IO_CACHE, ip)
    if cached:
        return cached

    if not config.VPNAPI_IO_ENABLED:
        return _empty(source)

    if config.VPNAPI_IO_DAILY_COUNT >= config.VPNAPI_IO_DAILY_LIMIT:
        return _empty(source)

    try:
        import requests

        config.VPNAPI_IO_DAILY_COUNT += 1
        resp = requests.get(
            f"https://vpnapi.io/api/{ip}",
            params={"key": config.VPNAPI_IO_KEY},
            timeout=4,
        )

        if resp.status_code == 200:
            data = resp.json()
            security = data.get("security", {})
            network = data.get("network", {})
            result = {
                "available": True,
                "is_vpn": bool(security.get("vpn")),
                "is_proxy": bool(security.get("proxy")),
                "is_tor": bool(security.get("tor")),
                "is_relay": bool(security.get("relay")),
                "provider": network.get("autonomous_system_organization") or None,
                "source": source,
            }
            config.evict_cache_if_needed(config.VPNAPI_IO_CACHE, config.VPNAPI_CACHE_MAX, "VPNAPI_IO_CACHE")
            return _store_cached(config.VPNAPI_IO_CACHE, ip, result)

        if resp.status_code == 429:
            print(f"[VPN-API] vpnapi.io rate limited — disabling for this session")
            config.VPNAPI_IO_DAILY_COUNT = config.VPNAPI_IO_DAILY_LIMIT

        if resp.status_code == 403:
            print(f"[VPN-API] vpnapi.io invalid key — disabling")
            config.VPNAPI_IO_ENABLED = False

    except Exception as exc:
        print(f"[VPN-API] vpnapi.io error for {ip}: {exc}")

    # Cache the empty result with a short TTL so we don't retry on every packet
    empty = _empty(source)
    _store_cached(config.VPNAPI_IO_CACHE, ip, empty)
    return empty


# ── 2. ipinfo.io ────────────────────────────────────────────────────


def query_ipinfo(ip: str) -> dict:
    """Query ipinfo.io for VPN/proxy/Tor/relay status.

    Works without a token (50k/month free). Set IPINFO_TOKEN for higher limits.
    Returns a normalised dict (see _empty()).
    """
    source = "ipinfo.io"

    if _is_non_routable(ip):
        return _empty(source)

    cached = _get_cached(config.IPINFO_CACHE, ip)
    if cached:
        return cached

    if config.IPINFO_DAILY_COUNT >= config.IPINFO_DAILY_LIMIT:
        return _empty(source)

    try:
        import requests

        headers = {"Accept": "application/json"}
        if config.IPINFO_TOKEN:
            headers["Authorization"] = f"Bearer {config.IPINFO_TOKEN}"

        config.IPINFO_DAILY_COUNT += 1
        resp = requests.get(
            f"https://ipinfo.io/{ip}/json",
            headers=headers,
            timeout=4,
        )

        if resp.status_code == 200:
            data = resp.json()
            privacy = data.get("privacy", {})
            org = data.get("org", "") or ""
            result = {
                "available": True,
                "is_vpn": bool(privacy.get("vpn")),
                "is_proxy": bool(privacy.get("proxy")),
                "is_tor": bool(privacy.get("tor")),
                "is_relay": bool(privacy.get("relay")),
                "provider": org.split(" ", 1)[1] if " " in org else org or None,
                "source": source,
            }
            config.evict_cache_if_needed(config.IPINFO_CACHE, config.IPINFO_CACHE_MAX, "IPINFO_CACHE")
            return _store_cached(config.IPINFO_CACHE, ip, result)

        if resp.status_code == 429:
            print(f"[VPN-API] ipinfo.io rate limited — pausing")
            config.IPINFO_DAILY_COUNT = config.IPINFO_DAILY_LIMIT

    except Exception as exc:
        print(f"[VPN-API] ipinfo.io error for {ip}: {exc}")

    # Cache the empty result so we don’t retry on the next packet
    empty = _empty(source)
    config.evict_cache_if_needed(config.IPINFO_CACHE, config.IPINFO_CACHE_MAX, "IPINFO_CACHE")
    _store_cached(config.IPINFO_CACHE, ip, empty)
    return empty


# ── 3. ip-api.com ───────────────────────────────────────────────────


def query_ip_api(ip: str) -> dict:
    """Query ip-api.com for proxy/hosting status.

    No API key required. Free: 45 requests/minute.
    Returns a normalised dict (see _empty()).
    """
    source = "ip-api.com"

    if _is_non_routable(ip):
        return _empty(source)

    cached = _get_cached(config.IPAPI_CACHE, ip)
    if cached:
        return cached

    # Per-minute rate limiting
    now = time.time()
    if now - config.IPAPI_MINUTE_RESET >= 60:
        # New minute window
        config.IPAPI_MINUTE_COUNT = 0
        config.IPAPI_MINUTE_RESET = now

    if config.IPAPI_MINUTE_COUNT >= config.IPAPI_MINUTE_LIMIT:
        return _empty(source)

    try:
        import requests

        config.IPAPI_MINUTE_COUNT += 1
        resp = requests.get(
            f"http://ip-api.com/json/{ip}",
            params={"fields": "status,proxy,hosting,isp,org,query"},
            timeout=4,
        )

        if resp.status_code == 200:
            data = resp.json()
            if data.get("status") == "success":
                is_proxy = bool(data.get("proxy"))
                is_hosting = bool(data.get("hosting"))
                result = {
                    "available": True,
                    "is_vpn": is_proxy,       # ip-api "proxy" covers VPN/proxy/Tor
                    "is_proxy": is_proxy,
                    "is_tor": False,           # ip-api doesn't distinguish Tor separately
                    "is_relay": is_hosting,   # "hosting" = likely relay/datacenter
                    "provider": data.get("org") or data.get("isp") or None,
                    "source": source,
                }
                config.evict_cache_if_needed(config.IPAPI_CACHE, config.IPAPI_CACHE_MAX, "IPAPI_CACHE")
                return _store_cached(config.IPAPI_CACHE, ip, result)

        if resp.status_code == 429:
            print(f"[VPN-API] ip-api.com rate limited — waiting for next minute")
            config.IPAPI_MINUTE_COUNT = config.IPAPI_MINUTE_LIMIT

    except Exception as exc:
        print(f"[VPN-API] ip-api.com error for {ip}: {exc}")

    # Cache the empty result so we don’t retry on the next packet for this IP
    empty = _empty(source)
    config.evict_cache_if_needed(config.IPAPI_CACHE, config.IPAPI_CACHE_MAX, "IPAPI_CACHE")
    _store_cached(config.IPAPI_CACHE, ip, empty)
    return empty


# ── Aggregated query (all three APIs) ──────────────────────────────


def query_all_vpn_apis(ip: str) -> dict:
    """Query all configured external VPN APIs and return merged signals.

    Returns:
        {
          "available": bool,            — True if at least one API responded
          "is_vpn": bool,
          "is_proxy": bool,
          "is_tor": bool,
          "is_relay": bool,
          "provider": str | None,
          "signals": list[dict],        — one entry per API that responded
          "api_count": int,             — number of APIs that responded
          "vpn_vote_count": int,        — how many APIs flagged as VPN/proxy/Tor
          "consensus_vpn": bool,        — True if >= 2 APIs flag as VPN/proxy
          "consensus_tor": bool,        — True if >= 2 APIs flag as Tor
          "confidence_tier": str,       — "none"|"single"|"dual"|"triple"
        }
    """
    # Fast path: check merged cache
    cached = _get_cached(config.VPN_API_CACHE, ip)
    if cached:
        return cached

    results = [
        query_vpnapi_io(ip),
        query_ipinfo(ip),
        query_ip_api(ip),
    ]

    available_results = [r for r in results if r.get("available")]

    # Count agreement across APIs
    vpn_votes   = sum(1 for r in available_results if r.get("is_vpn"))
    proxy_votes = sum(1 for r in available_results if r.get("is_proxy"))
    tor_votes   = sum(1 for r in available_results if r.get("is_tor"))
    relay_votes = sum(1 for r in available_results if r.get("is_relay"))
    # Total positive votes (an API counts once even if it flags multiple categories)
    positive_votes = sum(
        1 for r in available_results
        if r.get("is_vpn") or r.get("is_proxy") or r.get("is_tor") or r.get("is_relay")
    )

    confidence_tier = "none"
    if positive_votes >= 3:
        confidence_tier = "triple"
    elif positive_votes == 2:
        confidence_tier = "dual"
    elif positive_votes == 1:
        confidence_tier = "single"

    merged = {
        "available": bool(available_results),
        "is_vpn":  any(r["is_vpn"]  for r in available_results),
        "is_proxy": any(r["is_proxy"] for r in available_results),
        "is_tor":  any(r["is_tor"]  for r in available_results),
        "is_relay": any(r["is_relay"] for r in available_results),
        "provider": next(
            (r["provider"] for r in available_results if r.get("provider")), None
        ),
        "signals": [
            {k: v for k, v in r.items() if k != "_cached_at"}
            for r in available_results
        ],
        # Consensus metadata — used by vpn.py for elevated scoring
        "api_count":       len(available_results),
        "vpn_vote_count":  vpn_votes,
        "proxy_vote_count": proxy_votes,
        "tor_vote_count":  tor_votes,
        "relay_vote_count": relay_votes,
        "positive_vote_count": positive_votes,
        "consensus_vpn":  vpn_votes >= 2 or proxy_votes >= 2,
        "consensus_tor":  tor_votes >= 2,
        "confidence_tier": confidence_tier,
    }

    # Evict cache if needed to prevent unbounded growth
    config.evict_cache_if_needed(config.VPN_API_CACHE, config.VPN_API_CACHE_MAX, "VPN_API_CACHE")
    _store_cached(config.VPN_API_CACHE, ip, merged)
    return merged


def get_status() -> dict:
    """Return status of all external VPN APIs for admin/debug."""
    return {
        "vpnapi_io": {
            "enabled": config.VPNAPI_IO_ENABLED,
            "calls_today": config.VPNAPI_IO_DAILY_COUNT,
            "limit": config.VPNAPI_IO_DAILY_LIMIT,
            "cached_ips": len(config.VPNAPI_IO_CACHE),
            "cache_max": config.VPNAPI_CACHE_MAX,
        },
        "ipinfo": {
            "token_set": bool(config.IPINFO_TOKEN),
            "calls_today": config.IPINFO_DAILY_COUNT,
            "limit": config.IPINFO_DAILY_LIMIT,
            "cached_ips": len(config.IPINFO_CACHE),
            "cache_max": config.IPINFO_CACHE_MAX,
        },
        "ip_api": {
            "calls_this_minute": config.IPAPI_MINUTE_COUNT,
            "limit_per_minute": config.IPAPI_MINUTE_LIMIT,
            "cached_ips": len(config.IPAPI_CACHE),
            "cache_max": config.IPAPI_CACHE_MAX,
        },
        "merged_cache": {
            "cached_ips": len(config.VPN_API_CACHE),
            "cache_max": config.VPN_API_CACHE_MAX,
        },
        "consensus_scoring": "enabled",
        "api_weight_profile": "elevated (vpnapi.io=45/55, ipinfo.io=40/45, ip-api.com=35)",
    }
