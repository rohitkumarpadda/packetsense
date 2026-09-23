"""
routes/api.py — REST API blueprint.

All /api/* endpoints consolidated into a single Flask Blueprint.
"""

import platform
import threading
import time
from datetime import datetime
from pathlib import Path

import duckdb
from flask import Blueprint, jsonify, request, send_from_directory

import config
from services.geo import resolve_ip, get_local_ip_addresses, get_user_public_location
from services.vpn import load_vpn_ip_lists, VPN_PROVIDERS, VPN_ASN_DATABASE
from services.capture import (
    start_unified_capture,
    save_captured_packets,
    sanitize_device,
)
from services.threat_intel import (
    check_ip_reputation,
    get_load_stats as get_threat_intel_stats,
    load_threat_databases,
)

api = Blueprint("api", __name__)


# ── Static ────────────────────────────────────────────────────────


@api.route("/")
def index():
    return send_from_directory("static", "index.html")


# ── Mode / Info ───────────────────────────────────────────────────


@api.route("/api/mode")
def get_mode():
    return jsonify(
        {
            "has_parquet": config.conn is not None,
            "live_capture": config.capture_running,
            "parquet_path": config.parquet_path,
        }
    )


@api.route("/api/local_ips")
def get_local_ips():
    return jsonify({"local_ips": get_local_ip_addresses()})


# ── Network Interfaces ────────────────────────────────────────────


@api.route("/api/interfaces")
def get_interfaces():
    result = []
    try:
        if platform.system() == "Windows":
            from scapy.arch.windows import get_windows_if_list
            from scapy.all import conf

            ifaces = get_windows_if_list()
            skip = [
                "WFP",
                "Filter",
                "Pseudo",
                "Tunneling",
                "6to4",
                "SSTP",
                "IKEv2",
                "L2TP",
                "PPTP",
                "PPPOE",
                "WAN Miniport",
                "QoS Packet Scheduler",
                "Npcap Packet Driver",
                "Kernel Debug",
                "Wi-Fi Direct",
                "Bluetooth",
                "Microsoft IP-HTTPS",
                "Teredo",
            ]
            
            for iface in ifaces:
                name = iface.get("name", "")
                desc = iface.get("description", "")
                guid = iface.get("guid", "")
                ips = iface.get("ips", [])
                if any(s.lower() in f"{name} {desc}".lower() for s in skip):
                    continue
                ipv4s = [ip for ip in ips if "." in ip and not ip.startswith("169.254")]
                combined = f"{name} {desc}".lower()
                is_eth = any(
                    kw in combined
                    for kw in ["ethernet", "realtek", "intel i2", "broadcom", "gigabit"]
                )
                is_wifi = any(
                    kw in combined
                    for kw in ["wi-fi", "wifi", "wireless", "wlan", "killer"]
                )
                if not ipv4s and not is_eth and not is_wifi:
                    continue
                
                # Use GUID as the interface identifier (compatible with scapy.conf.ifaces and sniff())
                result.append(
                    {
                        "name": guid,  # GUID for sniff() - this is what conf.ifaces expects
                        "friendly_name": name,
                        "description": desc,
                        "ips": ips,
                        "ipv4": ipv4s,
                        "is_ethernet": is_eth,
                        "is_wifi": is_wifi,
                    }
                )
        else:
            from scapy.all import get_if_list
            import socket

            for iface_name in get_if_list():
                if iface_name.startswith(
                    ("lo", "docker", "br-", "veth", "virbr", "vmnet")
                ):
                    continue
                is_eth = any(
                    kw in iface_name.lower() for kw in ["eth", "en", "enp", "ens"]
                )
                is_wifi = any(kw in iface_name.lower() for kw in ["wl", "wlan", "wifi"])
                ipv4s = []
                try:
                    import fcntl, struct

                    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    ip_addr = socket.inet_ntoa(
                        fcntl.ioctl(
                            s.fileno(),
                            0x8915,
                            struct.pack("256s", iface_name[:15].encode("utf-8")),
                        )[20:24]
                    )
                    if not ip_addr.startswith("169.254"):
                        ipv4s.append(ip_addr)
                except Exception:
                    pass
                result.append(
                    {
                        "name": iface_name,
                        "description": iface_name,
                        "ips": ipv4s,
                        "ipv4": ipv4s,
                        "is_ethernet": is_eth,
                        "is_wifi": is_wifi,
                    }
                )

        result.sort(
            key=lambda x: (not x["is_ethernet"], not x.get("is_wifi", False), x["name"])
        )
        return jsonify({"interfaces": result})
    except Exception as e:
        try:
            from scapy.all import get_if_list

            return jsonify(
                {
                    "interfaces": [
                        {
                            "name": i,
                            "description": i,
                            "ips": [],
                            "ipv4": [],
                            "is_ethernet": False,
                            "is_wifi": False,
                        }
                        for i in get_if_list()
                    ]
                }
            )
        except Exception:
            return jsonify({"error": str(e)}), 500


# ── Capture Control ───────────────────────────────────────────────


@api.route("/api/capture/start", methods=["POST", "GET"])
def start_capture_route():
    if config.capture_running:
        return jsonify(
            {"status": "already_running", "message": "Capture already active"}
        )

    data = request.json or {}
    capture_mode = data.get("mode", "local")
    interface = data.get("interface") or None
    
    config.CAPTURE_MODE = capture_mode
    config.CAPTURE_INTERFACE = interface
    config.CAPTURE_SUBNET = data.get("subnet", "172.16.0.0/16")

    config.GEOIP_CACHE.clear()
    config.VPN_CACHE.clear()
    config.vpn_ips.clear()
    config.reset_live_stats()
    config.packet_history.clear()

    t = threading.Thread(target=start_unified_capture, daemon=True)
    t.start()

    return jsonify(
        {
            "status": "started",
            "message": f"Capture started in {config.CAPTURE_MODE} mode on {config.CAPTURE_INTERFACE or 'all interfaces'}",
            "mode": config.CAPTURE_MODE,
        }
    )


@api.route("/api/capture/stop")
def stop_capture_route():
    config.capture_running = False
    config.SWITCH_MONITOR_RUNNING = False
    time.sleep(0.5)

    res = {"status": "stopped", "message": "Capture stopped"}

    if config.CAPTURE_MODE == "switch":
        device_count = len(config.switch_devices)
        vpn_count = sum(
            1 for d in config.switch_devices.values() if d.get("vpn_detected")
        )
        res.update(
            {
                "devices_seen": device_count,
                "vpn_devices_detected": vpn_count,
                "total_alerts": len(config.switch_vpn_alerts),
            }
        )
    else:
        res.update(save_captured_packets())

    return jsonify(res)


# ── PCAP Flows & Stats ───────────────────────────────────────────


@api.route("/api/flows")
def get_flows():
    if not config.conn:
        return jsonify({"error": "No PCAP loaded. Use /api/load_parquet first."}), 400

    C = config.COLS
    limit = int(request.args.get("limit", 100))
    protocol = request.args.get("protocol")
    min_pkts = int(request.args.get("min_packets", 1))

    sql = f"""
        SELECT {C['src']} as src_ip, {C['dst']} as dst_ip,
               COUNT(*) as packet_count,
               COALESCE(SUM(TRY_CAST({C['len']} AS INTEGER)), 0) as total_bytes,
               COALESCE(AVG(TRY_CAST({C['len']} AS INTEGER)), 0) as avg_size
        FROM packets
        WHERE {C['src']} IS NOT NULL AND {C['dst']} IS NOT NULL
    """
    if protocol:
        sql += f" AND {C['proto']} LIKE '%{protocol}%'"
    sql += f" GROUP BY src_ip, dst_ip HAVING COUNT(*) >= {min_pkts}"
    sql += f" ORDER BY packet_count DESC LIMIT {limit}"

    def _safe_geo(geo: dict, ip: str) -> dict:
        """Return only the fields the map frontend needs — no vpn_signals list,
        no asn_data dict, no non-serialisable objects."""
        return {
            "ip":                 ip,
            "lat":                geo.get("lat") or 0,
            "lon":                geo.get("lon") or 0,
            "city":               geo.get("city") or "Unknown",
            "country":            geo.get("country") or "Unknown",
            "isp":                geo.get("isp") or "",
            "asn":                geo.get("asn") or "",
            "is_private":         bool(geo.get("is_private")),
            "is_vpn":             bool(geo.get("is_vpn")),
            "vpn_provider":       geo.get("vpn_provider"),
            "vpn_method":         geo.get("vpn_method"),
            "vpn_method_detail":  geo.get("vpn_method_detail") or "",
            "vpn_confidence":     geo.get("vpn_confidence") or 0,
            "vpn_classification": geo.get("vpn_classification") or "not_vpn",
        }

    try:
        rows = config.conn.execute(sql).fetchall()
        flows, skipped = [], 0
        for src_ip, dst_ip, pkt_count, total_bytes, avg_size in rows:
            src_geo = resolve_ip(src_ip)
            dst_geo = resolve_ip(dst_ip)
            if not src_geo or not dst_geo:
                skipped += 1
                continue

            # Skip flows where BOTH endpoints lack usable coordinates.
            # ASN-only-resolved IPs get lat=0, lon=0 (null island, off Africa)
            # which are invisible to users not looking at that location.
            src_has_coords = bool(src_geo.get("lat") or src_geo.get("lon"))
            dst_has_coords = bool(dst_geo.get("lat") or dst_geo.get("lon"))
            if not src_has_coords and not dst_has_coords:
                skipped += 1
                continue

            flows.append(
                {
                    "src":   _safe_geo(src_geo, src_ip),
                    "dst":   _safe_geo(dst_geo, dst_ip),
                    "stats": {
                        "packet_count":    int(pkt_count),
                        "total_bytes":     int(total_bytes or 0),
                        "avg_packet_size": float(avg_size or 0),
                    },
                }
            )
        return jsonify({"flows": flows, "total": len(flows), "skipped": skipped})
    except Exception as e:
        import traceback; traceback.print_exc()
        return jsonify({"error": str(e)}), 500


@api.route("/api/stats")
def get_stats():
    if not config.conn:
        return jsonify({"error": "No PCAP loaded"}), 400
    C = config.COLS
    try:
        total = config.conn.execute("SELECT COUNT(*) FROM packets").fetchone()[0] or 0
        u_src = config.conn.execute(
            f"SELECT COALESCE(COUNT(DISTINCT {C['src']}), 0) FROM packets"
        ).fetchone()[0]
        u_dst = config.conn.execute(
            f"SELECT COALESCE(COUNT(DISTINCT {C['dst']}), 0) FROM packets"
        ).fetchone()[0]

        protos = config.conn.execute(
            f"""
            SELECT {C['proto']}, COUNT(*) as c FROM packets
            WHERE {C['proto']} IS NOT NULL GROUP BY 1 ORDER BY 2 DESC LIMIT 10
        """
        ).fetchall()

        top_talkers = config.conn.execute(
            f"""
            SELECT ip, SUM(packets) as tp, SUM(bytes) as tb FROM (
                SELECT {C['src']} as ip, COUNT(*) as packets,
                       COALESCE(SUM(TRY_CAST({C['len']} AS INTEGER)), 0) as bytes
                FROM packets WHERE {C['src']} IS NOT NULL GROUP BY {C['src']}
                UNION ALL
                SELECT {C['dst']} as ip, COUNT(*) as packets,
                       COALESCE(SUM(TRY_CAST({C['len']} AS INTEGER)), 0) as bytes
                FROM packets WHERE {C['dst']} IS NOT NULL GROUP BY {C['dst']}
            ) GROUP BY ip ORDER BY tb DESC LIMIT 10
        """
        ).fetchall()

        top_dst_ports = config.conn.execute(
            """
            SELECT "dst_port", COUNT(*) as c FROM packets
            WHERE "dst_port" IS NOT NULL GROUP BY "dst_port" ORDER BY c DESC LIMIT 5
        """
        ).fetchall()

        total_bytes = config.conn.execute(
            f"SELECT COALESCE(SUM(TRY_CAST({C['len']} AS INTEGER)), 0) FROM packets"
        ).fetchone()[0]
        avg_pkt = config.conn.execute(
            f"SELECT COALESCE(AVG(TRY_CAST({C['len']} AS INTEGER)), 0) FROM packets"
        ).fetchone()[0]
        time_range = config.conn.execute(
            f"SELECT MIN({C['time']}), MAX({C['time']}) FROM packets"
        ).fetchone()
        duration = (
            (time_range[1] - time_range[0]) if time_range[0] and time_range[1] else 0
        )
        pkt_rate = total / duration if duration > 0 else 0

        # VPN & unknown location scan
        all_ips = config.conn.execute(
            f"""
            SELECT DISTINCT ip FROM (
                SELECT {C['src']} as ip FROM packets WHERE {C['src']} IS NOT NULL
                UNION
                SELECT {C['dst']} as ip FROM packets WHERE {C['dst']} IS NOT NULL
            )
        """
        ).fetchall()
        unknown_locs, vpn_count, vpn_details = 0, 0, []
        for (ip,) in all_ips:
            geo = resolve_ip(ip)
            if geo is None:
                unknown_locs += 1
            elif geo.get("is_vpn"):
                vpn_count += 1
                # Field names must match what addVpnEntry() in the frontend expects:
                #   loc.vpn_provider, loc.vpn_method, loc.vpn_method_detail,
                #   loc.ip, loc.city, loc.country, loc.isp, loc.asn
                vpn_details.append(
                    {
                        "ip":               ip,
                        "vpn_provider":     geo.get("vpn_provider") or "Unknown",
                        "vpn_method":       geo.get("vpn_method") or "keyword",
                        "vpn_method_detail": geo.get("vpn_method_detail", ""),
                        "vpn_confidence":   geo.get("vpn_confidence", 0),
                        "vpn_classification": geo.get("vpn_classification", "vpn_confirmed"),
                        "isp":     geo.get("isp", "Unknown"),
                        "asn":     geo.get("asn", ""),
                        "country": geo.get("country", "Unknown"),
                        "city":    geo.get("city", "Unknown"),
                        "lat":     geo.get("lat", 0),
                        "lon":     geo.get("lon", 0),
                    }
                )

        return jsonify(
            {
                "total_packets": total,
                "unique_src_ips": u_src,
                "unique_dst_ips": u_dst,
                "protocols": [{"name": p[0], "count": p[1]} for p in protos],
                "top_talkers": [
                    {"ip": t[0], "packets": int(t[1]), "bytes": int(t[2])}
                    for t in top_talkers
                ],
                "top_dst_ports": [
                    {"port": int(p[0]), "count": int(p[1])} for p in top_dst_ports
                ],
                "total_bytes": int(total_bytes),
                "avg_packet_size": float(avg_pkt),
                "duration": float(duration),
                "packet_rate": float(pkt_rate),
                "unknown_locations": unknown_locs,
                "vpn_ips_count": vpn_count,
                "vpn_details": vpn_details[:10],
            }
        )
    except Exception as e:
        import traceback

        traceback.print_exc()
        return jsonify({"error": str(e)}), 500


@api.route("/api/time_range")
def get_time_range():
    if not config.conn:
        return jsonify({"error": "No PCAP loaded"}), 400
    try:
        C = config.COLS
        r = config.conn.execute(
            f"SELECT MIN({C['time']}), MAX({C['time']}) FROM packets WHERE {C['time']} IS NOT NULL"
        ).fetchone()
        mn, mx = r[0], r[1]
        if mn is None:
            return jsonify({"min": 0, "max": 0})
        return jsonify(
            {
                "min": float(mn) if isinstance(mn, str) else mn,
                "max": float(mx) if isinstance(mx, str) else mx,
            }
        )
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@api.route("/api/flow_details")
def get_flow_details():
    if not config.conn:
        return jsonify({"error": "No PCAP loaded"}), 400
    C = config.COLS
    src, dst = request.args.get("src"), request.args.get("dst")
    limit = int(request.args.get("limit", 50))
    try:
        rows = config.conn.execute(
            f"""
            SELECT {C['number']}, {C['time']}, {C['len']}, {C['proto']}
            FROM packets WHERE {C['src']} = '{src}' AND {C['dst']} = '{dst}'
            ORDER BY {C['time']} LIMIT {limit}
        """
        ).fetchall()
        return jsonify(
            {
                "packets": [
                    {
                        "number": r[0],
                        "time": float(r[1]) if isinstance(r[1], str) else r[1],
                        "length": r[2],
                        "protocols": r[3],
                    }
                    for r in rows
                ]
            }
        )
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ── Live Stats ────────────────────────────────────────────────────


@api.route("/api/live/stats")
def get_live_stats():
    s = config.live_stats
    uptime = time.time() - s["start_time"] if s["start_time"] else 0
    bw = s["total_bytes"] / uptime if uptime > 0 else 0
    return jsonify(
        {
            "total_packets": s["total_packets"],
            "tcp_packets": s["tcp_packets"],
            "udp_packets": s["udp_packets"],
            "unique_ips": len(s["unique_ips"]),
            "unique_src_ips": len(s["unique_src_ips"]),
            "unique_dst_ips": len(s["unique_dst_ips"]),
            "active_connections": len(s["connections"]),
            "capture_running": config.capture_running,
            "uptime": uptime,
            "total_bytes": s["total_bytes"],
            "bandwidth_bps": bw,
            "protocols": dict(s["protocols"]),
            "top_talkers": [
                {"ip": ip, "bytes": b}
                for ip, b in sorted(
                    s["top_talkers"].items(), key=lambda x: x[1], reverse=True
                )[:5]
            ],
            "top_ports": [
                {"port": p, "count": c}
                for p, c in sorted(
                    s["ports"].items(), key=lambda x: x[1], reverse=True
                )[:5]
            ],
            "captured_packets_count": len(config.captured_packets),
            "session_name": config.capture_session_name,
            "vpn_ips_count": len(s["vpn_ips"]),
            "vpn_details": list(s["vpn_details"].values())[:10],
        }
    )


@api.route("/api/live/history")
def get_live_history():
    return jsonify(list(config.packet_history))


@api.route("/api/live/save")
def save_live():
    result = save_captured_packets()
    if result.get("saved"):
        return jsonify({"status": "success", **result})
    return jsonify({"error": result.get("error", "Save failed")}), 400


# ── Switch Monitoring ─────────────────────────────────────────────


@api.route("/api/switch/status")
def get_switch_status():
    devs = config.switch_devices
    return jsonify(
        {
            "monitoring": config.SWITCH_MONITOR_RUNNING,
            "devices_count": len(devs),
            "vpn_devices_count": sum(1 for d in devs.values() if d.get("vpn_detected")),
            "total_packets": sum(d["total_packets"] for d in devs.values()),
            "total_bytes": sum(d["total_bytes"] for d in devs.values()),
            "alert_count": len(config.switch_vpn_alerts),
        }
    )


@api.route("/api/switch/devices")
def get_switch_devices():
    sort_by = request.args.get("sort", "last_seen")
    vpn_only = request.args.get("vpn_only", "false").lower() == "true"
    with config.switch_device_lock:
        devices = [
            sanitize_device(ip, dev)
            for ip, dev in config.switch_devices.items()
            if not vpn_only or dev.get("vpn_detected")
        ]
    key_map = {
        "bytes": "total_bytes",
        "vpn": "vpn_packet_count",
        "packets": "total_packets",
    }
    devices.sort(
        key=lambda d: d.get(key_map.get(sort_by, "last_seen"), 0), reverse=True
    )
    return jsonify(
        {
            "devices": devices,
            "total": len(devices),
            "monitoring": config.SWITCH_MONITOR_RUNNING,
        }
    )


@api.route("/api/switch/vpn_alerts")
def get_switch_vpn_alerts():
    limit = int(request.args.get("limit", 50))
    severity = request.args.get("severity")
    alerts = config.switch_vpn_alerts.copy()
    if severity:
        alerts = [a for a in alerts if a.get("severity") == severity]
    alerts = list(reversed(alerts[-limit:]))
    unique_devs = set(a["device_ip"] for a in config.switch_vpn_alerts)
    unique_srvs = set(a["vpn_server_ip"] for a in config.switch_vpn_alerts)
    providers = {}
    for a in config.switch_vpn_alerts:
        p = a.get("provider", "Unknown")
        providers[p] = providers.get(p, 0) + 1
    return jsonify(
        {
            "alerts": alerts,
            "total_alerts": len(config.switch_vpn_alerts),
            "unique_vpn_devices": len(unique_devs),
            "unique_vpn_servers": len(unique_srvs),
            "provider_summary": providers,
            "monitoring": config.SWITCH_MONITOR_RUNNING,
        }
    )


@api.route("/api/switch/reset")
def reset_switch_data():
    config.SWITCH_MONITOR_RUNNING = False
    with config.switch_device_lock:
        old_d, old_a = len(config.switch_devices), len(config.switch_vpn_alerts)
        config.switch_devices = {}
        config.switch_vpn_alerts = []
    return jsonify(
        {"status": "reset", "cleared_devices": old_d, "cleared_alerts": old_a}
    )


@api.route("/api/switch/device/<device_ip>")
def get_switch_device_detail(device_ip):
    with config.switch_device_lock:
        if device_ip not in config.switch_devices:
            return jsonify({"error": f"Device {device_ip} not found"}), 404
        dev = config.switch_devices[device_ip]
        detail = sanitize_device(device_ip, dev)
        ext_sorted = sorted(
            dev["external_ips"].items(), key=lambda x: x[1]["bytes"], reverse=True
        )[:20]
        detail["top_external_ips"] = [{"ip": ip, **info} for ip, info in ext_sorted]
        detail["alerts"] = [
            a for a in config.switch_vpn_alerts if a["device_ip"] == device_ip
        ][-20:]
    return jsonify(detail)


# ── VPN DB ────────────────────────────────────────────────────────


@api.route("/api/vpn/status")
def get_vpn_db_status():
    vpn_dir = config.DATA_DIR / "vpn_lists"
    sources = {}
    for name in ["x4bnet_ipv4", "tor_exit_nodes"]:
        f = vpn_dir / f"{name}.txt"
        if f.exists():
            sources[name] = {
                "loaded": True,
                "entries": len(f.read_text().strip().splitlines()),
                "age_hours": round((time.time() - f.stat().st_mtime) / 3600, 1),
            }
        else:
            sources[name] = {"loaded": False, "entries": 0}

    ti_stats = get_threat_intel_stats()

    return jsonify(
        {
            "ip_ranges_loaded": len(config.VPN_IP_RANGES_V4),
            "asn_entries": len(VPN_ASN_DATABASE),
            "keyword_providers": len(VPN_PROVIDERS),
            "cached_lookups": len(config.VPN_CACHE),
            "vpn_ips_detected": len(config.vpn_ips),
            "offline_mode": True,
            "threat_intel_loaded": config.THREAT_INTEL_LOADED,
            "threat_intel_sources": ti_stats.get("sources", {}),
            "behavioural_analysis_active": config.behaviour_analyzer is not None,
            "sources": sources,
        }
    )


@api.route("/api/vpn/refresh", methods=["POST"])
def refresh_vpn_db():
    """Reload VPN IP lists and threat intel from local files."""
    try:
        config.VPN_CACHE.clear()
        load_vpn_ip_lists()
        load_threat_databases()
        return jsonify(
            {
                "status": "success",
                "ip_ranges_loaded": len(config.VPN_IP_RANGES_V4),
                "threat_intel_loaded": config.THREAT_INTEL_LOADED,
            }
        )
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@api.route("/api/vpn/clear_cache", methods=["POST"])
def clear_vpn_cache():
    """Flush all VPN detection caches so IPs are re-evaluated on next access.

    Use this after a configuration change (e.g. whitelist expansion) to clear
    stale false-positive results without restarting the server.
    """
    cleared = {
        "VPN_CACHE":      len(config.VPN_CACHE),
        "GEOIP_CACHE":    len(config.GEOIP_CACHE),
        "VPN_API_CACHE":  len(config.VPN_API_CACHE),
        "VPNAPI_IO_CACHE": len(config.VPNAPI_IO_CACHE),
        "IPINFO_CACHE":   len(config.IPINFO_CACHE),
        "IPAPI_CACHE":    len(config.IPAPI_CACHE),
    }
    config.VPN_CACHE.clear()
    config.GEOIP_CACHE.clear()
    config.VPN_API_CACHE.clear()
    config.VPNAPI_IO_CACHE.clear()
    config.IPINFO_CACHE.clear()
    config.IPAPI_CACHE.clear()
    config.vpn_ips.clear()
    # Reset live stats VPN tracking too
    config.live_stats["vpn_ips"].clear()
    config.live_stats["vpn_details"].clear()
    print("[VPN] All detection caches cleared")
    return jsonify({"status": "cleared", "entries_removed": cleared})


# ── Threat Intelligence ───────────────────────────────────────────


@api.route("/api/threat_intel/status")
def get_threat_intel_status():
    stats = get_threat_intel_stats()
    return jsonify(stats)


@api.route("/api/threat_intel/check/<ip>")
def check_threat_intel(ip):
    result = check_ip_reputation(ip)
    return jsonify(result)


# ── Behavioural Analysis ────────────────────────────────────────


@api.route("/api/behaviour/device/<device_ip>")
def get_device_behaviour(device_ip):
    if not config.behaviour_analyzer:
        return jsonify({"error": "Behavioural analysis not active"}), 400
    analysis = config.behaviour_analyzer.analyze_device(device_ip)
    return jsonify(analysis)


@api.route("/api/behaviour/summary")
def get_behaviour_summary():
    if not config.behaviour_analyzer:
        return jsonify({"error": "Behavioural analysis not active"}), 400
    summary = config.behaviour_analyzer.get_summary()
    return jsonify(summary)


# ── File Loading ──────────────────────────────────────────────────


def _load_parquet(path: str):
    config.parquet_path = path
    conn = duckdb.connect(":memory:")
    # Configure DuckDB for the host machine's available memory (16GB)
    try:
        conn.execute(f"SET memory_limit='{config.DUCKDB_MEMORY_LIMIT}'")
        conn.execute(f"SET threads={config.DUCKDB_THREADS}")
        conn.execute("SET enable_progress_bar=false")
    except Exception as e:
        print(f"[DuckDB] Config warning: {e}")
    config.conn = conn
    config.conn.execute(f"CREATE TABLE packets AS SELECT * FROM read_parquet('{path}')")
    try:
        count = config.conn.execute("SELECT COUNT(*) FROM packets").fetchone()[0]
        print(f"[OK] Loaded {path} (Rows: {count}, DuckDB memory: {config.DUCKDB_MEMORY_LIMIT})")
    except Exception:
        print(f"[OK] Loaded {path}")


@api.route("/api/load_parquet", methods=["POST"])
def load_parquet_route():
    path = (request.json or {}).get("path")
    if not path:
        return jsonify({"error": "No path provided"}), 400
    if not Path(path).exists():
        return jsonify({"error": f"File not found: {path}"}), 404
    try:
        _load_parquet(path)
        return jsonify({"status": "success", "path": path})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@api.route("/api/upload_pcap", methods=["POST"])
def upload_pcap():
    if "file" not in request.files:
        return jsonify({"error": "No file provided"}), 400
    file = request.files["file"]
    if file.filename == "":
        return jsonify({"error": "No file selected"}), 400
    if not file.filename.endswith((".pcap", ".pcapng")):
        return jsonify({"error": "File must be .pcap or .pcapng"}), 400

    try:
        pcap_dir = config.DATA_DIR / "pcap"
        parquet_dir = config.DATA_DIR / "parquet"
        pcap_dir.mkdir(parents=True, exist_ok=True)
        parquet_dir.mkdir(parents=True, exist_ok=True)

        stem = Path(file.filename).stem
        # Check for existing parquet from live capture
        existing = parquet_dir / f"{stem}.parquet"
        if existing.exists():
            _load_parquet(str(existing))
            count = config.conn.execute("SELECT COUNT(*) FROM packets").fetchone()[0]
            return jsonify(
                {
                    "status": "success",
                    "message": f"Loaded existing capture ({count} packets)",
                    "parquet_path": str(existing),
                    "packet_count": count,
                    "reused": True,
                }
            )

        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        pcap_path = pcap_dir / f"{stem}_{ts}.pcap"
        parquet_path = parquet_dir / f"{stem}_{ts}.parquet"
        file.save(str(pcap_path))

        from src.parsers.scapy_parser import parse_pcap_with_scapy
        from src.transformers.json_to_parquet import write_parquet_streaming

        packets = parse_pcap_with_scapy(str(pcap_path))
        if not packets:
            return jsonify({"error": "No packets found in PCAP file"}), 400
        write_parquet_streaming(packets, str(parquet_path))
        _load_parquet(str(parquet_path))

        return jsonify(
            {
                "status": "success",
                "message": f"Loaded {len(packets)} packets",
                "parquet_path": str(parquet_path),
                "packet_count": len(packets),
                "reused": False,
            }
        )
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@api.route("/api/live/load_saved")
def load_saved_capture():
    try:
        pcap_dir = config.DATA_DIR / "pcap"
        parquet_dir = config.DATA_DIR / "parquet"
        pcap_dir.mkdir(parents=True, exist_ok=True)
        parquet_dir.mkdir(parents=True, exist_ok=True)

        pcap_files = list(pcap_dir.glob("*.pcap"))
        if not pcap_files:
            return jsonify({"error": "No saved captures found"}), 404

        latest = max(pcap_files, key=lambda p: p.stat().st_mtime)
        pq_file = parquet_dir / f"{latest.stem}.parquet"

        if not pq_file.exists():
            from src.parsers.scapy_parser import parse_pcap_with_scapy
            from src.transformers.json_to_parquet import write_parquet_streaming

            pkts = parse_pcap_with_scapy(str(latest))
            if not pkts:
                return jsonify({"error": "No packets parsed"}), 500
            write_parquet_streaming(pkts, str(pq_file))

        config.capture_running = False
        time.sleep(0.5)
        _load_parquet(str(pq_file))
        return jsonify(
            {
                "status": "success",
                "message": f"Loaded {latest.name}",
                "pcap_file": str(latest),
                "parquet_file": str(pq_file),
            }
        )
    except Exception as e:
        import traceback

        traceback.print_exc()
        return jsonify({"error": str(e)}), 500
