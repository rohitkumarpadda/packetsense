"""
services/geo.py — Fully offline GeoIP + ASN resolution.

Uses ONLY local MMDB databases:
  - GeoLite2-City.mmdb   → lat, lon, city, country
  - GeoLite2-ASN.mmdb    → ASN number, ISP/org name
  - GeoLite2-Country.mmdb → country fallback
  - dbip-asn-lite.mmdb   → secondary ASN source (DB-IP)

NO external API calls are made. This module works 100% offline.
"""

import ipaddress
import random
import socket
from pathlib import Path

import maxminddb

import config
from services.vpn import detect_vpn

# ── MMDB readers (initialized once) ──────────────────────────────

_city_reader = None
_asn_reader = None
_country_reader = None
_dbip_asn_reader = None


def _init_readers():
    """Open all available MMDB databases."""
    global _city_reader, _asn_reader, _country_reader, _dbip_asn_reader

    data = config.DATA_DIR
    ti = config.THREAT_INTEL_DIR

    # GeoLite2-City
    city_path = data / "GeoLite2-City.mmdb"
    if city_path.exists():
        try:
            _city_reader = maxminddb.open_database(str(city_path))
            print(f"[GEO] Loaded GeoLite2-City ({city_path.stat().st_size // (1024*1024)} MB)")
        except Exception as e:
            print(f"[GEO] Error loading GeoLite2-City: {e}")
    else:
        # Try bundled maxminddb-geolite2 package as fallback
        try:
            from maxminddb_geolite2 import open_database
            _city_reader = open_database()
            print("[GEO] Loaded GeoLite2-City (from maxminddb-geolite2 package)")
        except Exception:
            print("[WARN] GeoLite2-City.mmdb not found in data/")

    # GeoLite2-ASN
    asn_path = data / "GeoLite2-ASN.mmdb"
    if asn_path.exists():
        try:
            _asn_reader = maxminddb.open_database(str(asn_path))
            print(f"[GEO] Loaded GeoLite2-ASN ({asn_path.stat().st_size // (1024*1024)} MB)")
        except Exception as e:
            print(f"[GEO] Error loading GeoLite2-ASN: {e}")

    # GeoLite2-Country (fallback)
    country_path = data / "GeoLite2-Country.mmdb"
    if country_path.exists():
        try:
            _country_reader = maxminddb.open_database(str(country_path))
            print(f"[GEO] Loaded GeoLite2-Country ({country_path.stat().st_size // (1024*1024)} MB)")
        except Exception as e:
            print(f"[GEO] Error loading GeoLite2-Country: {e}")

    # DB-IP ASN Lite (secondary ASN source)
    dbip_path = ti / "dbip-asn-lite.mmdb"
    if dbip_path.exists():
        try:
            _dbip_asn_reader = maxminddb.open_database(str(dbip_path))
            print(f"[GEO] Loaded DB-IP ASN Lite ({dbip_path.stat().st_size // (1024*1024)} MB)")
        except Exception as e:
            print(f"[GEO] Error loading DB-IP ASN Lite: {e}")


# Initialize on module import
_init_readers()


# ── Helpers ───────────────────────────────────────────────────────


def is_private_ip(ip: str) -> bool:
    """Return True for RFC-1918, loopback, multicast, and link-local addresses."""
    if ":" in ip:
        return ip.startswith("fe80:") or ip.startswith("fc") or ip == "::1"
    try:
        parts = ip.split(".")
        if len(parts) != 4:
            return True
        first = int(parts[0])
        return (
            first in (10, 127, 0)
            or (first == 172 and 16 <= int(parts[1]) <= 31)
            or (first == 192 and int(parts[1]) == 168)
            or first >= 224
        )
    except Exception:
        return True


def get_local_ip_addresses() -> list[str]:
    """Return a list of this machine's non-loopback IPv4 addresses."""
    local_ips: list[str] = []
    try:
        hostname = socket.gethostname()
        for info in socket.getaddrinfo(hostname, None):
            ip = info[4][0]
            if ":" not in ip and not ip.startswith("127.") and ip not in local_ips:
                local_ips.append(ip)
    except Exception:
        pass

    if not local_ips:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ips.append(s.getsockname()[0])
            s.close()
        except Exception:
            pass
    return local_ips


def get_user_public_location() -> dict:
    """Get user's location for map display — fully offline.

    Priority:
      1. Cached result
      2. .env config (USER_LAT, USER_LON, ...)
      3. GeoLite2 lookup on machine's default gateway IP
      4. Hard-coded fallback
    """
    if config.user_public_location:
        return config.user_public_location

    # Try .env configured location
    if config.USER_LAT and config.USER_LON:
        config.user_public_location = {
            "ip": "Configured",
            "country": config.USER_COUNTRY or "Unknown",
            "city": config.USER_CITY or "Unknown",
            "lat": config.USER_LAT,
            "lon": config.USER_LON,
            "isp": "Configured",
            "asn": "N/A",
            "is_vpn": False,
            "vpn_provider": None,
        }
        print(f"[GEO] Using configured location: {config.USER_CITY}, {config.USER_COUNTRY}")
        return config.user_public_location

    # Try to resolve machine's default interface IP via GeoLite2
    local_ips = get_local_ip_addresses()
    for lip in local_ips:
        if not is_private_ip(lip):
            loc = _lookup_mmdb(lip)
            if loc and loc.get("lat"):
                config.user_public_location = {
                    "ip": lip,
                    "country": loc.get("country", "Unknown"),
                    "city": loc.get("city", "Unknown"),
                    "lat": loc["lat"],
                    "lon": loc["lon"],
                    "isp": loc.get("isp", "Unknown"),
                    "asn": loc.get("asn", "N/A"),
                    "is_vpn": False,
                    "vpn_provider": None,
                }
                print(f"[GEO] Resolved location from local IP: {loc.get('city')}, {loc.get('country')}")
                return config.user_public_location

    # Fallback
    config.user_public_location = {
        "ip": "Local", "country": "Local Network", "city": "Your Location",
        "lat": 20, "lon": 0, "isp": "Local", "asn": "N/A",
        "is_vpn": False, "vpn_provider": None,
    }
    print("[GEO] Using default fallback location")
    return config.user_public_location


# ── MMDB lookup ───────────────────────────────────────────────────


def _lookup_asn(ip: str) -> dict:
    """Lookup ISP and ASN from ALL available MMDB databases.
    Returns a dict with cross-validation data:
      {
        "isp": str,         # Best ISP name (GeoLite2 preferred)
        "asn": str,         # Best ASN string
        "geolite2": {...},  # GeoLite2 result (or None)
        "dbip": {...},      # DB-IP result (or None)
        "dual_source": bool,  # True if both databases returned data
        "asn_agreement": bool,  # True if both databases report same ASN number
        "org_agreement": bool,  # True if org names overlap (fuzzy)
      }
    """
    result = {
        "isp": "Unknown", "asn": "Unknown",
        "geolite2": None, "dbip": None,
        "dual_source": False, "asn_agreement": False, "org_agreement": False,
    }

    gl_isp = gl_asn = gl_num = None
    db_isp = db_asn = db_num = None

    # GeoLite2-ASN
    if _asn_reader:
        try:
            data = _asn_reader.get(ip)
            if data:
                gl_num = data.get("autonomous_system_number", "")
                gl_org = data.get("autonomous_system_organization", "Unknown")
                gl_isp = gl_org
                gl_asn = f"AS{gl_num} {gl_org}" if gl_num else gl_org
                result["geolite2"] = {"isp": gl_isp, "asn": gl_asn, "asn_number": gl_num}
                result["isp"] = gl_isp
                result["asn"] = gl_asn
        except Exception:
            pass

    # DB-IP ASN Lite
    if _dbip_asn_reader:
        try:
            data = _dbip_asn_reader.get(ip)
            if data:
                db_num = data.get("autonomous_system_number", "")
                db_org = data.get("autonomous_system_organization", "Unknown")
                db_isp = db_org
                db_asn = f"AS{db_num} {db_org}" if db_num else db_org
                result["dbip"] = {"isp": db_isp, "asn": db_asn, "asn_number": db_num}
                # Only use DB-IP values if GeoLite2 didn't return anything
                if result["isp"] == "Unknown":
                    result["isp"] = db_isp
                    result["asn"] = db_asn
        except Exception:
            pass

    # Cross-validation
    if result["geolite2"] and result["dbip"]:
        result["dual_source"] = True
        # ASN number agreement
        if gl_num and db_num and str(gl_num) == str(db_num):
            result["asn_agreement"] = True
        # Org name fuzzy agreement (either name contains the other)
        if gl_isp and db_isp:
            gl_lower = gl_isp.lower()
            db_lower = db_isp.lower()
            result["org_agreement"] = (
                gl_lower in db_lower or db_lower in gl_lower
                or gl_lower == db_lower
            )

    return result


def _lookup_mmdb(ip: str) -> dict | None:
    """Full MMDB lookup: City + ASN. Returns location dict or None."""
    lat, lon = 0, 0
    country, city = "Unknown", "Unknown"

    # City database
    if _city_reader:
        try:
            response = _city_reader.get(ip)
            if response and "location" in response:
                lat = response["location"].get("latitude", 0)
                lon = response["location"].get("longitude", 0)
                country = (response.get("country", {})
                          .get("names", {}).get("en", "Unknown"))
                city = (response.get("city", {})
                       .get("names", {}).get("en", "Unknown"))
        except Exception:
            pass

    # If no city data, try country database
    if not lat and not lon and _country_reader:
        try:
            response = _country_reader.get(ip)
            if response:
                country = (response.get("country", {})
                          .get("names", {}).get("en", "Unknown"))
                # Use country centroid as fallback coordinates
                loc = response.get("location", {})
                lat = loc.get("latitude", 0)
                lon = loc.get("longitude", 0)
        except Exception:
            pass

    if not lat and not lon:
        return None

    asn_data = _lookup_asn(ip)

    return {
        "lat": lat, "lon": lon,
        "country": country, "city": city,
        "isp": asn_data["isp"], "asn": asn_data["asn"],
        "asn_data": asn_data,  # Full cross-validation data for VPN detection
    }


# ── Main resolver ─────────────────────────────────────────────────


def resolve_ip(ip: str) -> dict | None:
    """
    Unified IP → location resolver. Fully offline — uses ONLY local MMDB databases.
    Handles private IPs, GeoLite2, DB-IP, and VPN detection.
    Returns None when no location can be determined.
    """
    # Cache hit
    if ip in config.GEOIP_CACHE:
        return config.GEOIP_CACHE[ip].copy()

    # Evict oldest entries if cache is over its limit
    config.evict_cache_if_needed(config.GEOIP_CACHE, config.GEOIP_CACHE_MAX, "GEOIP_CACHE")

    # Private IP → user's approx location with jitter
    if is_private_ip(ip):
        fallback = get_user_public_location()
        if fallback and fallback.get("lat"):
            loc = {
                "ip": ip,
                "lat": fallback["lat"] + random.uniform(-0.5, 0.5),
                "lon": fallback["lon"] + random.uniform(-0.5, 0.5),
                "country": fallback["country"],
                "city": "Local Network",
                "isp": "Private Network",
                "asn": "N/A",
                "is_private": True,
                "is_vpn": False,
                "vpn_provider": None,
            }
            config.GEOIP_CACHE[ip] = loc
            return loc
        return None

    # Full MMDB lookup (City + ASN)
    mmdb_data = _lookup_mmdb(ip)
    if mmdb_data and (mmdb_data["lat"] or mmdb_data["lon"]):
        isp = mmdb_data.get("isp", "Unknown")
        asn = mmdb_data.get("asn", "Unknown")
        asn_data = mmdb_data.get("asn_data")

        # VPN detection (fully offline, with cross-validation data)
        vpn_info = detect_vpn(ip, isp, asn, asn_data=asn_data)

        loc = {
            "ip": ip,
            "lat": mmdb_data["lat"],
            "lon": mmdb_data["lon"],
            "country": mmdb_data.get("country", "Unknown"),
            "city": mmdb_data.get("city", "Unknown"),
            "isp": isp,
            "asn": asn,
            "is_private": False,
            "is_vpn": vpn_info["is_vpn"],
            "vpn_provider": vpn_info.get("provider"),
            "vpn_method": vpn_info.get("method"),
            "vpn_method_detail": vpn_info.get("method_detail", ""),
            "vpn_confidence": vpn_info.get("confidence", 0),
            "vpn_classification": vpn_info.get("classification", "not_vpn"),
            "vpn_signals": vpn_info.get("signals", []),
        }
        config.GEOIP_CACHE[ip] = loc
        if vpn_info["is_vpn"]:
            config.vpn_ips.add(ip)
        return loc

    # ASN-only resolution (no coordinates, but still useful for VPN detection)
    asn_data = _lookup_asn(ip)
    if asn_data["isp"] != "Unknown" or asn_data["asn"] != "Unknown":
        vpn_info = detect_vpn(ip, asn_data["isp"], asn_data["asn"], asn_data=asn_data)
        # Return minimal data without coordinates
        loc = {
            "ip": ip,
            "lat": 0, "lon": 0,
            "country": "Unknown", "city": "Unknown",
            "isp": asn_data["isp"], "asn": asn_data["asn"],
            "is_private": False,
            "is_vpn": vpn_info["is_vpn"],
            "vpn_provider": vpn_info.get("provider"),
            "vpn_method": vpn_info.get("method"),
            "vpn_method_detail": vpn_info.get("method_detail", ""),
            "vpn_confidence": vpn_info.get("confidence", 0),
            "vpn_classification": vpn_info.get("classification", "not_vpn"),
            "vpn_signals": vpn_info.get("signals", []),
        }
        config.GEOIP_CACHE[ip] = loc
        if vpn_info["is_vpn"]:
            config.vpn_ips.add(ip)
        return loc

    return None

