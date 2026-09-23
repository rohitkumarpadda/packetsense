"""
routes/agent.py — PacketSense AI Agent Blueprint.

Agentic chatbot backed by Ollama (primary) with OpenRouter as fallback.
Supports multi-step ReAct-style reasoning: the agent can chain up to
MAX_AGENT_STEPS tool calls per user message, feeding each result back
to the LLM for the next action decision.

Intent classification:
  Before any tool is called, the LLM decides whether the user wants
  conversational interaction or a tool-driven answer. This allows
  natural greetings, "what is this app?", etc. to receive fluent prose
  instead of a list of commands.

Tools available:

  Core data tools:
  - get_stats              → Packet capture statistics
  - get_vpn               → All detected VPN IPs
  - get_top_talkers       → Top IPs by traffic volume
  - check_ip              → Full VPN + threat intel for a specific IP
  - get_flows             → Active network flows

  Analysis tools:
  - analyze_traffic       → Protocol distribution, port analysis, timing anomalies
  - get_threat_summary    → Comprehensive threat intel overview
  - get_vpn_signals       → Detailed VPN signal breakdown for a specific IP
  - scan_anomalies        → Proactive anomaly scan (VPN+threat correlation)
  - get_bandwidth_analysis → Bandwidth by protocol, top consumers

  Behaviour tools:
  - get_behaviour_summary → Beaconing, exfiltration, VPN-tunnel scoring (all devices)
  - get_device_behaviour  → Deep behavioural analysis for a specific device IP

  Device / session tools:
  - get_session_info      → Current session mode, uptime, loaded file, data size
  - get_capture_devices   → List available network interfaces for capture
  - get_switch_devices    → Switch-mode device inventory
  - get_switch_vpn_alerts → Switch-mode VPN alert log

  Enrichment tools:
  - check_abuse_ip        → AbuseIPDB abuse score + VPN/Tor flag for a specific IP
  - get_geo_ip            → Full geographic resolution for any IP

  Map tools:
  - inject_packet         → Plot custom src→dst packet on the map

  Utility tools:
  - explain_packet        → Plain-English explanation of packet fields
  - export_report         → Generate a JSON session summary report
  - general_answer        → Direct factual answer or conversational reply

Fallback: regex-intent matcher handles common questions when LLM unavailable.
"""

import json
import re
import time
from datetime import datetime

from flask import Blueprint, jsonify, request

import config
from services.geo import resolve_ip
from services.threat_intel import check_ip_reputation
from services.vpn import detect_vpn

agent_bp = Blueprint("agent", __name__)

# ── Model configuration ─────────────────────────────────────────────

# Ollama is tried first (SSH-tunnelled from remote laptop).
# OpenRouter free slugs are used as fallback.
OLLAMA_MODEL_NAME = getattr(config, "OLLAMA_MODEL", "qwen2.5:7b")
OLLAMA_URL = getattr(config, "OLLAMA_URL", "http://localhost:11434/v1")
OLLAMA_TIMEOUT = getattr(config, "OLLAMA_TIMEOUT", 60)

OPENROUTER_MODELS = [
    "nvidia/nemotron-3.5-lightning:free",
    "minimax/minimax-m3:free",
    "google/gemma-4-31b-it:free",
    "openrouter/free",
]

AGENT_MAX_TOKENS = 1024
AGENT_TEMPERATURE = 0.3
MAX_AGENT_STEPS = 4  # Increased from 3 to allow deeper chains

# Runtime state: which provider/model is actually active
_active_provider = "unknown"
_active_model = "unknown"
_ollama_available = None   # None=unchecked, True/False after first probe

# ── System prompt ────────────────────────────────────────────────────

SYSTEM_PROMPT = """You are PacketSense AI, an expert agentic network analyst embedded in the 5G-PacketSense v2 dashboard.

5G-PacketSense v2 is a real-time network monitoring and analysis platform that captures live packets, analyses PCAP files, detects VPNs, maps traffic geographically, scores threats, analyses behaviour (beaconing, exfiltration, tunnels), and monitors switch-connected devices.

You operate in a multi-step ReAct loop. For EVERY response, output ONLY a JSON object — no prose outside it:
{
  "mode": "tool" | "chat",
  "tool": "<tool_name>",           // only when mode=tool
  "params": { ... },               // only when mode=tool
  "answer": "<markdown prose>",    // only when mode=chat (direct conversational reply)
  "brief_plan": "<one sentence>",
  "needs_followup": false
}

Mode selection rules:
- "chat" → use for: greetings, "hello", "what is this app?", "what can you do?", general networking Q&A that doesn't need live data, follow-up clarifications, thanks.
- "tool" → use for: any question that requires live capture data, IP lookups, VPN info, threat intel, behaviour analysis, device lists, bandwidth stats, etc.

When mode="chat": write a warm, helpful, markdown-formatted reply in "answer". Do NOT call any tool.
When mode="tool": pick the best tool and set "answer" to "".

Available tools:

CORE DATA:
- get_stats              (params: {}) — Capture statistics (total pkts, bytes, protocols, VPN count, top talkers)
- get_vpn               (params: {}) — All VPN IPs with provider, confidence, classification
- get_top_talkers       (params: {}) — Top IPs by traffic volume
- check_ip              (params: {"ip": "<IP>"}) — Full geo + VPN + threat intel for one IP
- get_flows             (params: {"limit": <int, default 5>}) — Network flows (src→dst pairs)

ANALYSIS:
- analyze_traffic        (params: {}) — Protocol distribution, port patterns, packet-size analysis, timing
- get_threat_summary     (params: {}) — Threat intel overview: severity counts, top threat IPs, categories
- get_vpn_signals        (params: {"ip": "<IP>"}) — Full VPN signal breakdown (all confidence weights) for one IP
- scan_anomalies         (params: {}) — Proactive scan: suspicious patterns, high-risk IPs, anomalies
- get_bandwidth_analysis (params: {}) — Bandwidth by protocol/port, peak rate, top consumers

BEHAVIOUR:
- get_behaviour_summary  (params: {}) — All-device behavioural overview: beaconing, exfil, VPN-tunnel scores
- get_device_behaviour   (params: {"ip": "<IP>"}) — Deep behavioural profile for one device

SESSION / DEVICES:
- get_session_info       (params: {}) — Current mode, uptime, session name, loaded file, data size
- get_capture_devices    (params: {}) — Available network interfaces (for capture selection)
- get_switch_devices     (params: {}) — Switch-monitoring device inventory (MAC, IP, VPN status)
- get_switch_vpn_alerts  (params: {}) — Switch-mode VPN alert log

ENRICHMENT:
- check_abuse_ip         (params: {"ip": "<IP>"}) — AbuseIPDB score, VPN/Tor flag, total reports
- get_geo_ip             (params: {"ip": "<IP>"}) — Full geographic resolution for any IP

MAP:
- inject_packet          (params: {"src_ip": "<IP>", "dst_ip": "<IP>", "protocol": "TCP|UDP|ICMP"}) — Plot packet on map

UTILITY:
- explain_packet         (params: {"fields": "<raw fields text>"}) — Decode packet fields in plain English
- export_report          (params: {}) — Generate a JSON session summary report
- general_answer         (params: {"answer": "<text>"}) — Direct factual answer (no live data needed)

Decision rules:
- Set needs_followup=true ONLY when you need one more tool call to complete analysis.
- For IP-specific requests: check_ip first, optionally follow with check_abuse_ip or get_vpn_signals.
- For security overview: get_threat_summary → scan_anomalies (chained).
- For suspicious device: get_device_behaviour → check_ip on that device's top destination.
- For "show on map" / inject: use inject_packet.
- Keep brief_plan to ONE sentence.
"""

# ── Tool executor functions ───────────────────────────────────────────


def _get_stats() -> dict:
    """Fetch stats from live capture or PCAP."""
    try:
        if config.capture_running:
            s = config.live_stats
            uptime = time.time() - s["start_time"] if s["start_time"] else 0
            bw = (s["total_bytes"] / uptime) if uptime > 0 else 0.0
            return {
                "mode": "live",
                "total_packets": s["total_packets"],
                "tcp_packets": s["tcp_packets"],
                "udp_packets": s["udp_packets"],
                "unique_ips": len(s["unique_ips"]),
                "total_bytes": s["total_bytes"],
                "bandwidth_bps": round(bw, 1),
                "vpn_ips_count": len(s["vpn_ips"]),
                "uptime_seconds": round(uptime, 1),
                "top_talkers": [
                    {"ip": ip, "bytes": b}
                    for ip, b in sorted(
                        s["top_talkers"].items(), key=lambda x: x[1], reverse=True
                    )[:5]
                ],
            }
        elif config.conn:
            C = config.COLS
            total = config.conn.execute("SELECT COUNT(*) FROM packets").fetchone()[0]
            total_bytes = config.conn.execute(
                f"SELECT COALESCE(SUM(TRY_CAST({C['len']} AS INTEGER)), 0) FROM packets"
            ).fetchone()[0]
            vpn_count = sum(
                1 for v in config.GEOIP_CACHE.values() if v.get("is_vpn")
            )
            protos = config.conn.execute(
                f"SELECT {C['proto']}, COUNT(*) FROM packets WHERE {C['proto']} IS NOT NULL GROUP BY 1 ORDER BY 2 DESC LIMIT 5"
            ).fetchall()
            top_talkers = config.conn.execute(
                f"""SELECT ip, SUM(bytes) as tb FROM (
                    SELECT {C['src']} as ip, COALESCE(SUM(TRY_CAST({C['len']} AS INTEGER)),0) as bytes FROM packets WHERE {C['src']} IS NOT NULL GROUP BY 1
                    UNION ALL
                    SELECT {C['dst']} as ip, COALESCE(SUM(TRY_CAST({C['len']} AS INTEGER)),0) as bytes FROM packets WHERE {C['dst']} IS NOT NULL GROUP BY 1
                ) GROUP BY ip ORDER BY tb DESC LIMIT 5"""
            ).fetchall()
            return {
                "mode": "pcap",
                "total_packets": total,
                "total_bytes": int(total_bytes),
                "vpn_ips_count": vpn_count,
                "protocols": [{"name": p[0], "count": p[1]} for p in protos],
                "top_talkers": [{"ip": t[0], "bytes": int(t[1])} for t in top_talkers],
            }
        else:
            return {"error": "No data loaded. Start a live capture or upload a PCAP file."}
    except Exception as e:
        return {"error": str(e)}


def _get_vpn() -> dict:
    """Return all detected VPN IPs."""
    vpn_list = []
    if config.live_stats.get("vpn_details"):
        for ip, detail in config.live_stats["vpn_details"].items():
            vpn_list.append({
                "ip": ip,
                "provider": detail.get("provider", "Unknown"),
                "confidence": detail.get("vpn_confidence", 0),
                "classification": detail.get("vpn_classification", "unknown"),
                "method": detail.get("vpn_method", "unknown"),
            })
    for ip, geo in config.GEOIP_CACHE.items():
        if geo.get("is_vpn") and ip not in {v["ip"] for v in vpn_list}:
            vpn_list.append({
                "ip": ip,
                "provider": geo.get("vpn_provider", "Unknown"),
                "confidence": geo.get("vpn_confidence", 0),
                "classification": geo.get("vpn_classification", "unknown"),
                "method": geo.get("vpn_method", "unknown"),
            })
    return {
        "vpn_count": len(vpn_list),
        "vpn_ips": vpn_list[:20],
        "asn_database_entries": len(config.VPN_CACHE),
    }


def _get_top_talkers() -> dict:
    """Return top IPs by traffic."""
    try:
        if config.capture_running:
            s = config.live_stats
            return {
                "mode": "live",
                "top_talkers": [
                    {"ip": ip, "bytes": b}
                    for ip, b in sorted(
                        s["top_talkers"].items(), key=lambda x: x[1], reverse=True
                    )[:10]
                ],
            }
        elif config.conn:
            C = config.COLS
            rows = config.conn.execute(
                f"""SELECT ip, SUM(tb) as total FROM (
                    SELECT {C['src']} as ip, COALESCE(SUM(TRY_CAST({C['len']} AS INTEGER)),0) as tb FROM packets WHERE {C['src']} IS NOT NULL GROUP BY 1
                    UNION ALL
                    SELECT {C['dst']} as ip, COALESCE(SUM(TRY_CAST({C['len']} AS INTEGER)),0) as tb FROM packets WHERE {C['dst']} IS NOT NULL GROUP BY 1
                ) GROUP BY ip ORDER BY total DESC LIMIT 10"""
            ).fetchall()
            return {"mode": "pcap", "top_talkers": [{"ip": r[0], "bytes": int(r[1])} for r in rows]}
        return {"error": "No data available"}
    except Exception as e:
        return {"error": str(e)}


def _check_ip(ip: str) -> dict:
    """Full VPN + threat intel check on a single IP."""
    try:
        geo = resolve_ip(ip)
        threat = check_ip_reputation(ip)
        return {
            "ip": ip,
            "geo": {
                "city": geo.get("city", "Unknown") if geo else "Unknown",
                "country": geo.get("country", "Unknown") if geo else "Unknown",
                "isp": geo.get("isp", "Unknown") if geo else "Unknown",
                "asn": geo.get("asn", "Unknown") if geo else "Unknown",
                "lat": geo.get("lat") if geo else None,
                "lon": geo.get("lon") if geo else None,
            } if geo else None,
            "vpn": {
                "is_vpn": geo.get("is_vpn", False) if geo else False,
                "provider": geo.get("vpn_provider") if geo else None,
                "confidence": geo.get("vpn_confidence", 0) if geo else 0,
                "classification": geo.get("vpn_classification", "not_vpn") if geo else "not_vpn",
            },
            "threat": {
                "is_malicious": threat.get("is_malicious", False),
                "threat_level": threat.get("threat_level", "none"),
                "sources": threat.get("sources", []),
                "categories": threat.get("categories", []),
            },
        }
    except Exception as e:
        return {"error": str(e)}


def _get_flows(limit: int = 5) -> dict:
    """Get top network flows."""
    try:
        if not config.conn:
            if config.capture_running:
                conns = config.live_stats.get("connections", {})
                return {
                    "mode": "live",
                    "active_connections": len(conns),
                    "top_flows": list(conns.values())[:limit],
                }
            return {"error": "No data available"}

        C = config.COLS
        rows = config.conn.execute(
            f"""SELECT {C['src']} as src, {C['dst']} as dst,
                COUNT(*) as packets,
                COALESCE(SUM(TRY_CAST({C['len']} AS INTEGER)),0) as bytes
                FROM packets
                WHERE {C['src']} IS NOT NULL AND {C['dst']} IS NOT NULL
                GROUP BY src, dst ORDER BY packets DESC LIMIT {int(limit)}"""
        ).fetchall()
        return {
            "mode": "pcap",
            "flows": [{"src": r[0], "dst": r[1], "packets": r[2], "bytes": int(r[3])} for r in rows],
        }
    except Exception as e:
        return {"error": str(e)}


def _inject_packet(src_ip: str, dst_ip: str, protocol: str = "TCP") -> dict:
    """Resolve both IPs geographically and return map-ready data."""
    try:
        src_geo = resolve_ip(src_ip)
        dst_geo = resolve_ip(dst_ip)

        if not src_geo:
            return {"error": f"Cannot resolve source IP: {src_ip}"}
        if not dst_geo:
            return {"error": f"Cannot resolve destination IP: {dst_ip}"}

        return {
            "injected": True,
            "protocol": protocol.upper(),
            "src": {
                "ip": src_ip,
                "lat": src_geo["lat"],
                "lon": src_geo["lon"],
                "city": src_geo.get("city", "Unknown"),
                "country": src_geo.get("country", "Unknown"),
                "isp": src_geo.get("isp", ""),
                "is_vpn": src_geo.get("is_vpn", False),
                "vpn_provider": src_geo.get("vpn_provider"),
            },
            "dst": {
                "ip": dst_ip,
                "lat": dst_geo["lat"],
                "lon": dst_geo["lon"],
                "city": dst_geo.get("city", "Unknown"),
                "country": dst_geo.get("country", "Unknown"),
                "isp": dst_geo.get("isp", ""),
                "is_vpn": dst_geo.get("is_vpn", False),
                "vpn_provider": dst_geo.get("vpn_provider"),
            },
        }
    except Exception as e:
        return {"error": str(e)}


def _explain_packet(fields: str) -> dict:
    """Return structured explanation of raw packet fields."""
    explanation_parts = []
    fields_lower = fields.lower()

    if "tcp" in fields_lower:
        explanation_parts.append("**Protocol**: TCP (Transmission Control Protocol) — reliable, connection-oriented transport.")
    elif "udp" in fields_lower:
        explanation_parts.append("**Protocol**: UDP (User Datagram Protocol) — fast, connectionless, no delivery guarantee.")
    elif "icmp" in fields_lower:
        explanation_parts.append("**Protocol**: ICMP — control/error messages (e.g., ping).")

    port_match = re.findall(r'\b(\d{2,5})\b', fields)
    port_hints = {
        "443": "HTTPS (encrypted web)", "80": "HTTP (web)", "53": "DNS",
        "22": "SSH", "25": "SMTP (email)", "3389": "RDP (remote desktop)",
        "51820": "WireGuard VPN", "1194": "OpenVPN", "500": "IKE/IPSec",
        "4500": "IPSec NAT-T", "8080": "HTTP alt", "21": "FTP",
    }
    for port in port_match:
        if port in port_hints:
            explanation_parts.append(f"**Port {port}**: {port_hints[port]}")

    ttl_match = re.search(r'ttl[=:\s]+(\d+)', fields_lower)
    if ttl_match:
        ttl = int(ttl_match.group(1))
        os_hint = "Linux/Unix" if ttl <= 64 else "Windows" if ttl <= 128 else "Network device"
        explanation_parts.append(f"**TTL={ttl}**: Likely originated from a **{os_hint}** system.")

    len_match = re.search(r'len[gth]*[=:\s]+(\d+)', fields_lower)
    if len_match:
        length = int(len_match.group(1))
        size_desc = "tiny (likely control/ACK)" if length < 100 else "medium (mixed data)" if length < 1000 else "large (bulk data transfer)"
        explanation_parts.append(f"**Packet size {length}B**: {size_desc}.")

    if not explanation_parts:
        return {"explanation": "Paste packet fields like: `src=1.2.3.4 dst=5.6.7.8 ttl=64 len=200 proto=TCP port=443`. I'll decode them for you."}

    return {"explanation": "\n\n".join(explanation_parts)}


def _analyze_traffic() -> dict:
    """Analyze protocol distribution, port patterns, and packet sizes."""
    try:
        if config.conn:
            C = config.COLS
            protos = config.conn.execute(
                f"SELECT {C['proto']}, COUNT(*) as c FROM packets WHERE {C['proto']} IS NOT NULL GROUP BY 1 ORDER BY 2 DESC LIMIT 10"
            ).fetchall()
            ports = config.conn.execute(
                'SELECT "dst_port", COUNT(*) as c FROM packets WHERE "dst_port" IS NOT NULL GROUP BY 1 ORDER BY 2 DESC LIMIT 10'
            ).fetchall()
            sizes = config.conn.execute(
                f"""
                SELECT
                    CASE
                        WHEN TRY_CAST({C['len']} AS INTEGER) < 64   THEN 'tiny (<64B)'
                        WHEN TRY_CAST({C['len']} AS INTEGER) < 256  THEN 'small (64-255B)'
                        WHEN TRY_CAST({C['len']} AS INTEGER) < 1024 THEN 'medium (256-1023B)'
                        ELSE 'large (>=1024B)'
                    END as bucket,
                    COUNT(*) as c
                FROM packets GROUP BY 1 ORDER BY 2 DESC
                """
            ).fetchall()
            total = config.conn.execute("SELECT COUNT(*) FROM packets").fetchone()[0]
            u_src = config.conn.execute(f"SELECT COUNT(DISTINCT {C['src']}) FROM packets").fetchone()[0]
            u_dst = config.conn.execute(f"SELECT COUNT(DISTINCT {C['dst']}) FROM packets").fetchone()[0]

            VPN_PROTO_PORTS = {1194: "OpenVPN", 51820: "WireGuard", 500: "IKE/IPSec", 4500: "IPSec NAT-T", 1723: "PPTP", 1701: "L2TP"}
            vpn_port_hits = []
            for port_row in ports:
                if port_row[0] in VPN_PROTO_PORTS:
                    vpn_port_hits.append({"port": port_row[0], "name": VPN_PROTO_PORTS[port_row[0]], "count": port_row[1]})

            return {
                "mode": "pcap",
                "total_packets": total,
                "unique_src_ips": u_src,
                "unique_dst_ips": u_dst,
                "protocols": [{"name": p[0], "count": p[1]} for p in protos],
                "top_dst_ports": [{"port": p[0], "count": p[1]} for p in ports],
                "packet_size_distribution": [{"bucket": s[0], "count": s[1]} for s in sizes],
                "vpn_protocol_ports_detected": vpn_port_hits,
            }
        elif config.capture_running:
            s = config.live_stats
            protos = sorted(s["protocols"].items(), key=lambda x: x[1], reverse=True)[:8]
            ports = sorted(s["ports"].items(), key=lambda x: x[1], reverse=True)[:10]
            return {
                "mode": "live",
                "total_packets": s["total_packets"],
                "unique_ips": len(s["unique_ips"]),
                "protocols": [{"name": p[0], "count": p[1]} for p in protos],
                "top_ports": [{"port": p[0], "count": p[1]} for p in ports],
            }
        return {"error": "No data available. Load a PCAP or start live capture."}
    except Exception as e:
        return {"error": str(e)}


def _get_threat_summary() -> dict:
    """Summarize threat intel findings across all IPs in the current session."""
    try:
        from services.threat_intel import check_ip_reputation, get_load_stats
        stats = get_load_stats()
        if not stats.get("loaded"):
            return {"error": "Threat intel databases not loaded. Run scripts/update_threat_intel.py"}

        all_ips: list[str] = []
        if config.conn:
            C = config.COLS
            rows = config.conn.execute(
                f"SELECT DISTINCT ip FROM (SELECT {C['src']} as ip FROM packets WHERE {C['src']} IS NOT NULL UNION SELECT {C['dst']} as ip FROM packets WHERE {C['dst']} IS NOT NULL)"
            ).fetchall()
            all_ips = [r[0] for r in rows if r[0]]
        elif config.capture_running:
            all_ips = list(config.live_stats.get("unique_ips", set()))

        threat_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "none": 0}
        top_threats = []
        category_counts: dict = {}

        for ip in all_ips[:2000]:
            rep = check_ip_reputation(ip)
            level = rep.get("threat_level", "none")
            threat_counts[level] = threat_counts.get(level, 0) + 1
            if rep.get("is_malicious"):
                for cat in rep.get("categories", []):
                    category_counts[cat] = category_counts.get(cat, 0) + 1
                if len(top_threats) < 15:
                    top_threats.append({
                        "ip": ip,
                        "level": level,
                        "sources": rep.get("sources", []),
                        "categories": rep.get("categories", []),
                        "ipsum_score": rep.get("ipsum_score"),
                    })

        top_threats.sort(key=lambda x: ["critical", "high", "medium", "low"].index(x["level"]) if x["level"] in ["critical", "high", "medium", "low"] else 99)
        total_scanned = len(all_ips)
        total_malicious = sum(v for k, v in threat_counts.items() if k != "none")

        return {
            "total_ips_scanned": total_scanned,
            "total_malicious": total_malicious,
            "threat_breakdown": threat_counts,
            "top_categories": sorted(category_counts.items(), key=lambda x: x[1], reverse=True)[:8],
            "top_threat_ips": top_threats[:10],
            "intel_sources": stats.get("sources", {}),
        }
    except Exception as e:
        return {"error": str(e)}


def _get_vpn_signals(ip: str) -> dict:
    """Return full VPN signal breakdown for a specific IP."""
    if not ip:
        return {"error": "No IP provided"}
    try:
        geo = resolve_ip(ip)
        if not geo:
            return {"error": f"Cannot resolve IP: {ip}"}

        vpn_signals = geo.get("vpn_signals", [])
        if not vpn_signals:
            from services.vpn import detect_vpn
            vpn_info = detect_vpn(ip, geo.get("isp", ""), geo.get("asn", ""))
            vpn_signals = vpn_info.get("signals", [])
        else:
            vpn_info = {
                "is_vpn": geo.get("is_vpn", False),
                "confidence": geo.get("vpn_confidence", 0),
                "classification": geo.get("vpn_classification", "not_vpn"),
                "provider": geo.get("vpn_provider"),
                "method": geo.get("vpn_method"),
            }

        from services.vpn_api import get_status as vpn_api_status
        api_status = vpn_api_status()

        return {
            "ip": ip,
            "is_vpn": vpn_info.get("is_vpn", False),
            "confidence": vpn_info.get("confidence", 0),
            "classification": vpn_info.get("classification", "not_vpn"),
            "provider": vpn_info.get("provider"),
            "primary_method": vpn_info.get("method"),
            "signal_count": len(vpn_signals),
            "total_weight": sum(s.get("weight", 0) for s in vpn_signals),
            "signals": vpn_signals,
            "api_sources_queried": {
                "vpnapi_io": api_status.get("vpnapi_io", {}).get("enabled", False),
                "ipinfo_io": True,
                "ip_api_com": True,
            },
        }
    except Exception as e:
        return {"error": str(e)}


def _scan_anomalies() -> dict:
    """Proactively scan traffic for suspicious patterns and high-risk indicators."""
    try:
        from services.threat_intel import check_ip_reputation

        anomalies = []
        summary = {"vpn_confirmed": 0, "vpn_likely": 0, "threat_critical": 0, "threat_high": 0,
                   "suspicious_ports": 0, "beaconing": 0}

        all_ips: list[str] = []
        if config.conn:
            C = config.COLS
            rows = config.conn.execute(
                f"SELECT DISTINCT ip FROM (SELECT {C['src']} as ip FROM packets WHERE {C['src']} IS NOT NULL UNION SELECT {C['dst']} as ip FROM packets WHERE {C['dst']} IS NOT NULL)"
            ).fetchall()
            all_ips = [r[0] for r in rows if r[0]]
        elif config.capture_running:
            all_ips = list(config.live_stats.get("unique_ips", set()))

        SUSPICIOUS_PORTS = {4444, 5555, 6666, 6667, 31337, 12345, 9050, 9150}
        for ip in all_ips[:500]:
            geo = config.GEOIP_CACHE.get(ip, {})
            threat = check_ip_reputation(ip)
            reasons = []

            vpn_class = geo.get("vpn_classification", "not_vpn")
            if vpn_class == "vpn_confirmed":
                summary["vpn_confirmed"] += 1
                reasons.append(f"VPN confirmed (confidence {geo.get('vpn_confidence', 0)}%, provider: {geo.get('vpn_provider', '?')})")
            elif vpn_class == "vpn_likely":
                summary["vpn_likely"] += 1
                reasons.append(f"VPN likely (confidence {geo.get('vpn_confidence', 0)}%)")

            t_level = threat.get("threat_level", "none")
            if t_level == "critical":
                summary["threat_critical"] += 1
                reasons.append(f"CRITICAL threat (sources: {', '.join(threat.get('sources', [])[:3])})")
            elif t_level == "high":
                summary["threat_high"] += 1
                reasons.append(f"HIGH threat (categories: {', '.join(threat.get('categories', [])[:3])})")

            if reasons:
                risk_score = 0
                if vpn_class == "vpn_confirmed": risk_score += 30
                elif vpn_class == "vpn_likely": risk_score += 20
                if t_level == "critical": risk_score += 50
                elif t_level == "high": risk_score += 35
                if vpn_class != "not_vpn" and t_level in ("critical", "high"):
                    risk_score += 20
                anomalies.append({
                    "ip": ip,
                    "risk_score": min(risk_score, 100),
                    "reasons": reasons,
                    "country": geo.get("country", "?"),
                    "isp": geo.get("isp", "?"),
                })

        if config.conn:
            try:
                port_rows = config.conn.execute(
                    'SELECT "dst_port", COUNT(*) FROM packets WHERE "dst_port" IS NOT NULL GROUP BY 1'
                ).fetchall()
                for port, cnt in port_rows:
                    if port in SUSPICIOUS_PORTS:
                        summary["suspicious_ports"] += cnt
                        anomalies.append({
                            "type": "suspicious_port",
                            "port": port,
                            "count": cnt,
                            "risk_score": 70,
                            "reasons": [f"Port {port} is commonly used by backdoors/Tor/attack tools"],
                        })
            except Exception:
                pass

        anomalies.sort(key=lambda x: x.get("risk_score", 0), reverse=True)
        top_risk_ips = [a["ip"] for a in anomalies if "ip" in a][:3]

        return {
            "anomalies_found": len(anomalies),
            "summary": summary,
            "top_anomalies": anomalies[:10],
            "recommendation": (
                f"High-risk IPs to investigate: {', '.join(top_risk_ips)}" if top_risk_ips
                else "No high-risk indicators found in scanned traffic."
            ),
            "ips_scanned": len(all_ips),
        }
    except Exception as e:
        return {"error": str(e)}


def _get_bandwidth_analysis() -> dict:
    """Detailed bandwidth breakdown by protocol, port, and time."""
    try:
        if config.conn:
            C = config.COLS
            total_bytes = config.conn.execute(
                f"SELECT COALESCE(SUM(TRY_CAST({C['len']} AS INTEGER)), 0) FROM packets"
            ).fetchone()[0]
            total_pkts = config.conn.execute("SELECT COUNT(*) FROM packets").fetchone()[0]
            avg_pkt_size = total_bytes / total_pkts if total_pkts > 0 else 0

            proto_bytes = config.conn.execute(
                f"""SELECT {C['proto']}, COUNT(*) as pkts,
                    COALESCE(SUM(TRY_CAST({C['len']} AS INTEGER)),0) as bytes
                    FROM packets WHERE {C['proto']} IS NOT NULL
                    GROUP BY 1 ORDER BY 3 DESC LIMIT 8"""
            ).fetchall()

            port_bytes = config.conn.execute(
                f"""SELECT "dst_port", COUNT(*) as pkts,
                    COALESCE(SUM(TRY_CAST({C['len']} AS INTEGER)),0) as bytes
                    FROM packets WHERE "dst_port" IS NOT NULL
                    GROUP BY 1 ORDER BY 3 DESC LIMIT 10"""
            ).fetchall()

            time_range = config.conn.execute(
                f"SELECT MIN({C['time']}), MAX({C['time']}) FROM packets"
            ).fetchone()
            duration = (time_range[1] - time_range[0]) if (time_range[0] and time_range[1]) else 0
            avg_bps = (total_bytes * 8 / duration) if duration > 0 else 0

            return {
                "mode": "pcap",
                "total_bytes": int(total_bytes),
                "total_packets": int(total_pkts),
                "avg_packet_size_bytes": round(avg_pkt_size, 1),
                "capture_duration_seconds": round(duration, 2),
                "avg_throughput_bps": round(avg_bps, 0),
                "by_protocol": [{"protocol": r[0], "packets": r[1], "bytes": int(r[2])} for r in proto_bytes],
                "by_dst_port": [{"port": r[0], "packets": r[1], "bytes": int(r[2])} for r in port_bytes],
            }
        elif config.capture_running:
            s = config.live_stats
            uptime = time.time() - s["start_time"] if s["start_time"] else 0
            bps = (s["total_bytes"] * 8 / uptime) if uptime > 0 else 0
            return {
                "mode": "live",
                "total_bytes": s["total_bytes"],
                "total_packets": s["total_packets"],
                "uptime_seconds": round(uptime, 1),
                "avg_throughput_bps": round(bps, 0),
                "top_talkers_bytes": [
                    {"ip": ip, "bytes": b}
                    for ip, b in sorted(s["top_talkers"].items(), key=lambda x: x[1], reverse=True)[:10]
                ],
            }
        return {"error": "No data available."}
    except Exception as e:
        return {"error": str(e)}


# ── New tool: Behaviour analysis ──────────────────────────────────────

def _get_behaviour_summary() -> dict:
    """All-device behavioural overview: beaconing, exfil, VPN-tunnel scores."""
    analyzer = config.behaviour_analyzer
    if not analyzer:
        return {"error": "Behaviour analyzer not active. Start a live capture to enable behavioural analysis."}
    try:
        summary = analyzer.get_summary()
        return {
            "total_devices_tracked": summary.get("total_devices", 0),
            "suspicious_devices": summary.get("suspicious_devices", 0),
            "top_suspicious": [
                {
                    "ip": d["device_ip"],
                    "composite_anomaly_score": d["scores"]["composite_anomaly"],
                    "vpn_tunnel_score": d["scores"]["vpn_tunnel"],
                    "beaconing_score": d["scores"]["beaconing"],
                    "exfil_score": d["scores"]["data_exfiltration"],
                    "classifications": d["classifications"],
                    "total_bytes": d["total_bytes"],
                    "flow_count": d["flow_count"],
                }
                for d in summary.get("suspicious", [])[:10]
            ],
        }
    except Exception as e:
        return {"error": str(e)}


def _get_device_behaviour(ip: str) -> dict:
    """Deep behavioural profile for a specific device IP."""
    if not ip:
        return {"error": "No IP provided"}
    analyzer = config.behaviour_analyzer
    if not analyzer:
        return {"error": "Behaviour analyzer not active. Start a live capture to enable."}
    try:
        analysis = analyzer.analyze_device(ip)
        return analysis
    except Exception as e:
        return {"error": str(e)}


# ── New tool: Session info ────────────────────────────────────────────

def _get_session_info() -> dict:
    """Current session mode, uptime, loaded file, and data summary."""
    now = time.time()
    info: dict = {
        "timestamp": datetime.now().isoformat(),
        "mode": "idle",
        "pcap_loaded": False,
        "live_capture_active": False,
        "switch_monitor_active": False,
    }

    if config.capture_running:
        info["mode"] = "live_capture"
        info["live_capture_active"] = True
        s = config.live_stats
        uptime = now - s["start_time"] if s["start_time"] else 0
        info["uptime_seconds"] = round(uptime, 1)
        info["uptime_human"] = _fmt_duration(uptime)
        info["session_name"] = config.capture_session_name or "unnamed"
        info["packets_captured"] = s["total_packets"]
        info["bytes_captured"] = s["total_bytes"]
        info["unique_ips"] = len(s["unique_ips"])
        info["vpn_ips_detected"] = len(s["vpn_ips"])

    if config.SWITCH_MONITOR_RUNNING:
        info["switch_monitor_active"] = True
        info["switch_devices_count"] = len(config.switch_devices)

    if config.conn:
        info["pcap_loaded"] = True
        if info["mode"] == "idle":
            info["mode"] = "pcap_analysis"
        info["parquet_path"] = str(config.parquet_path) if config.parquet_path else "unknown"
        try:
            total = config.conn.execute("SELECT COUNT(*) FROM packets").fetchone()[0]
            info["pcap_total_packets"] = total
        except Exception:
            pass

    info["geoip_cache_size"] = len(config.GEOIP_CACHE)
    info["vpn_cache_size"] = len(config.VPN_CACHE)
    info["fast_mode"] = config.FAST_MODE
    info["abuseipdb_api_enabled"] = config.ABUSEIPDB_ENABLED
    info["abuseipdb_calls_today"] = config.ABUSEIPDB_DAILY_COUNT

    return info


def _fmt_duration(seconds: float) -> str:
    """Format seconds as human-readable duration."""
    s = int(seconds)
    if s < 60:
        return f"{s}s"
    if s < 3600:
        return f"{s // 60}m {s % 60}s"
    return f"{s // 3600}h {(s % 3600) // 60}m"


# ── New tool: Capture devices ─────────────────────────────────────────

def _get_capture_devices() -> dict:
    """List available network interfaces for capture."""
    try:
        import platform
        ifaces = []
        if platform.system() == "Windows":
            try:
                from scapy.arch.windows import get_windows_if_list
                raw = get_windows_if_list()
                skip = ["WFP", "Filter", "Pseudo", "Tunneling", "6to4", "SSTP", "IKEv2", "L2TP"]
                for iface in raw:
                    name = iface.get("name", "")
                    desc = iface.get("description", "")
                    if any(s.lower() in desc.lower() for s in skip):
                        continue
                    ifaces.append({
                        "name": name,
                        "description": desc,
                        "ips": iface.get("ips", []),
                        "mac": iface.get("mac", ""),
                    })
            except Exception as e:
                return {"error": f"Could not list interfaces: {e}"}
        else:
            try:
                from scapy.all import get_if_list
                for iface in get_if_list():
                    ifaces.append({"name": iface, "description": iface})
            except Exception as e:
                return {"error": f"Could not list interfaces: {e}"}
        return {
            "interface_count": len(ifaces),
            "interfaces": ifaces[:20],
            "current_interface": config.CAPTURE_INTERFACE or "all",
            "capture_mode": config.CAPTURE_MODE,
        }
    except Exception as e:
        return {"error": str(e)}


# ── New tool: Switch devices ──────────────────────────────────────────

def _get_switch_devices() -> dict:
    """Switch-monitoring device inventory."""
    if not config.SWITCH_MONITOR_RUNNING and not config.switch_devices:
        return {"error": "Switch monitor is not active. Start capture in switch mode to see devices."}
    try:
        devices = []
        with config.switch_device_lock:
            for mac, dev in config.switch_devices.items():
                devices.append({
                    "mac": mac,
                    "ip": dev.get("ip", "?"),
                    "hostname": dev.get("hostname", ""),
                    "vendor": dev.get("vendor", ""),
                    "vpn_detected": dev.get("vpn_detected", False),
                    "vpn_provider": dev.get("vpn_provider", ""),
                    "last_seen": dev.get("last_seen", ""),
                    "packets": dev.get("packets", 0),
                    "bytes": dev.get("bytes", 0),
                })
        devices.sort(key=lambda d: d["packets"], reverse=True)
        return {
            "total_devices": len(devices),
            "vpn_devices": sum(1 for d in devices if d["vpn_detected"]),
            "devices": devices[:25],
        }
    except Exception as e:
        return {"error": str(e)}


def _get_switch_vpn_alerts() -> dict:
    """Switch-mode VPN alert log."""
    alerts = config.switch_vpn_alerts
    if not alerts:
        return {"alert_count": 0, "alerts": [], "message": "No switch VPN alerts recorded."}
    return {
        "alert_count": len(alerts),
        "alerts": alerts[-20:],  # Most recent 20
    }


# ── New tool: AbuseIPDB check ─────────────────────────────────────────

def _check_abuse_ip(ip: str) -> dict:
    """AbuseIPDB abuse score, VPN/Tor flag, total reports for a specific IP."""
    if not ip:
        return {"error": "No IP provided"}
    try:
        from services.abuseipdb import check_ip_abuseipdb
        result = check_ip_abuseipdb(ip)
        result["ip"] = ip
        return result
    except Exception as e:
        return {"error": str(e)}


# ── New tool: Full geo resolution ────────────────────────────────────

def _get_geo_ip(ip: str) -> dict:
    """Full geographic resolution for any IP address."""
    if not ip:
        return {"error": "No IP provided"}
    try:
        geo = resolve_ip(ip)
        if not geo:
            return {"error": f"Could not resolve IP: {ip}"}
        return {
            "ip": ip,
            "city": geo.get("city", "Unknown"),
            "region": geo.get("region", ""),
            "country": geo.get("country", "Unknown"),
            "country_code": geo.get("country_code", ""),
            "continent": geo.get("continent", ""),
            "lat": geo.get("lat"),
            "lon": geo.get("lon"),
            "isp": geo.get("isp", "Unknown"),
            "org": geo.get("org", ""),
            "asn": geo.get("asn", "Unknown"),
            "is_vpn": geo.get("is_vpn", False),
            "vpn_provider": geo.get("vpn_provider"),
            "vpn_confidence": geo.get("vpn_confidence", 0),
            "vpn_classification": geo.get("vpn_classification", "not_vpn"),
        }
    except Exception as e:
        return {"error": str(e)}


# ── New tool: Export session report ──────────────────────────────────

def _export_report() -> dict:
    """Generate a JSON session summary report for the current session."""
    report: dict = {
        "generated_at": datetime.now().isoformat(),
        "session_info": _get_session_info(),
    }

    # Stats
    stats = _get_stats()
    if not stats.get("error"):
        report["stats"] = stats

    # VPN summary
    vpn = _get_vpn()
    report["vpn_summary"] = {
        "total_vpn_ips": vpn.get("vpn_count", 0),
        "top_vpn_ips": vpn.get("vpn_ips", [])[:5],
    }

    # Top talkers
    talkers = _get_top_talkers()
    if not talkers.get("error"):
        report["top_talkers"] = talkers.get("top_talkers", [])[:5]

    # Threat summary (fast — skip full scan)
    try:
        from services.threat_intel import get_load_stats
        intel_stats = get_load_stats()
        report["threat_intel_status"] = {
            "loaded": intel_stats.get("loaded", False),
            "sources": intel_stats.get("sources", {}),
        }
    except Exception:
        pass

    # Behaviour summary (if active)
    if config.behaviour_analyzer:
        try:
            beh = _get_behaviour_summary()
            if not beh.get("error"):
                report["behaviour_summary"] = beh
        except Exception:
            pass

    report["export_note"] = "This report is a point-in-time snapshot. Use the dashboard for real-time monitoring."
    return report


# ── Tool dispatch table ───────────────────────────────────────────────

TOOLS = {
    # Core
    "get_stats":              lambda p: _get_stats(),
    "get_vpn":                lambda p: _get_vpn(),
    "get_top_talkers":        lambda p: _get_top_talkers(),
    "check_ip":               lambda p: _check_ip(p.get("ip", "")),
    "get_flows":              lambda p: _get_flows(p.get("limit", 5)),
    # Analysis
    "analyze_traffic":        lambda p: _analyze_traffic(),
    "get_threat_summary":     lambda p: _get_threat_summary(),
    "get_vpn_signals":        lambda p: _get_vpn_signals(p.get("ip", "")),
    "scan_anomalies":         lambda p: _scan_anomalies(),
    "get_bandwidth_analysis": lambda p: _get_bandwidth_analysis(),
    # Behaviour
    "get_behaviour_summary":  lambda p: _get_behaviour_summary(),
    "get_device_behaviour":   lambda p: _get_device_behaviour(p.get("ip", "")),
    # Session / devices
    "get_session_info":       lambda p: _get_session_info(),
    "get_capture_devices":    lambda p: _get_capture_devices(),
    "get_switch_devices":     lambda p: _get_switch_devices(),
    "get_switch_vpn_alerts":  lambda p: _get_switch_vpn_alerts(),
    # Enrichment
    "check_abuse_ip":         lambda p: _check_abuse_ip(p.get("ip", "")),
    "get_geo_ip":             lambda p: _get_geo_ip(p.get("ip", "")),
    # Map
    "inject_packet":          lambda p: _inject_packet(p.get("src_ip", ""), p.get("dst_ip", ""), p.get("protocol", "TCP")),
    # Utility
    "explain_packet":         lambda p: _explain_packet(p.get("fields", "")),
    "export_report":          lambda p: _export_report(),
    "general_answer":         lambda p: {"answer": p.get("answer", "")},
}

# ── Regex fallback (no LLM) ───────────────────────────────────────────

def _regex_intent(message: str) -> dict:
    """Rule-based intent matching when LLM is unavailable."""
    msg = message.lower().strip()

    ip_match = re.search(r'\b(\d{1,3}(?:\.\d{1,3}){3})\b', message)
    ips = re.findall(r'\b(\d{1,3}(?:\.\d{1,3}){3})\b', message)

    if len(ips) >= 2 and any(k in msg for k in ["inject", "plot", "show on map", "send", "map"]):
        proto = "UDP" if "udp" in msg else "ICMP" if "icmp" in msg else "TCP"
        return {"mode": "tool", "tool": "inject_packet", "params": {"src_ip": ips[0], "dst_ip": ips[1], "protocol": proto}, "brief_plan": f"Plotting {ips[0]} → {ips[1]} ({proto}) on map"}

    if ip_match and any(k in msg for k in ["abuse", "abuseipdb", "reports", "reported"]):
        return {"mode": "tool", "tool": "check_abuse_ip", "params": {"ip": ip_match.group(1)}, "brief_plan": f"Checking AbuseIPDB score for {ip_match.group(1)}"}

    if ip_match and any(k in msg for k in ["behav", "beaconing", "exfil", "tunnel", "device analysis"]):
        return {"mode": "tool", "tool": "get_device_behaviour", "params": {"ip": ip_match.group(1)}, "brief_plan": f"Analysing behaviour for device {ip_match.group(1)}"}

    if ip_match and any(k in msg for k in ["geo", "location", "where is", "country", "city", "isp"]):
        return {"mode": "tool", "tool": "get_geo_ip", "params": {"ip": ip_match.group(1)}, "brief_plan": f"Resolving geo for {ip_match.group(1)}"}

    if ip_match and any(k in msg for k in ["check", "look up", "is", "what", "who", "vpn", "threat", "reputation"]):
        return {"mode": "tool", "tool": "check_ip", "params": {"ip": ip_match.group(1)}, "brief_plan": f"Checking IP {ip_match.group(1)}"}

    if any(k in msg for k in ["vpn signal", "vpn detail", "vpn breakdown", "vpn weight", "why vpn"]):
        if ip_match:
            return {"mode": "tool", "tool": "get_vpn_signals", "params": {"ip": ip_match.group(1)}, "brief_plan": f"Getting VPN signal breakdown for {ip_match.group(1)}"}

    if any(k in msg for k in ["behaviour", "behavior", "beaconing", "exfil", "all devices"]):
        return {"mode": "tool", "tool": "get_behaviour_summary", "params": {}, "brief_plan": "Getting behavioural analysis summary for all tracked devices"}

    if any(k in msg for k in ["session", "uptime", "loaded", "current mode", "session info", "what mode", "what's loaded"]):
        return {"mode": "tool", "tool": "get_session_info", "params": {}, "brief_plan": "Fetching current session info"}

    if any(k in msg for k in ["interface", "capture device", "network card", "adapter"]):
        return {"mode": "tool", "tool": "get_capture_devices", "params": {}, "brief_plan": "Listing available network interfaces"}

    if any(k in msg for k in ["switch device", "switch monitor", "connected device", "lan device"]):
        return {"mode": "tool", "tool": "get_switch_devices", "params": {}, "brief_plan": "Getting switch-mode device inventory"}

    if any(k in msg for k in ["switch alert", "vpn alert", "switch vpn"]):
        return {"mode": "tool", "tool": "get_switch_vpn_alerts", "params": {}, "brief_plan": "Getting switch VPN alert log"}

    if any(k in msg for k in ["export", "report", "summary report", "download report"]):
        return {"mode": "tool", "tool": "export_report", "params": {}, "brief_plan": "Generating session summary report"}

    if any(k in msg for k in ["vpn", "proxy", "tor", "detected"]):
        return {"mode": "tool", "tool": "get_vpn", "params": {}, "brief_plan": "Fetching VPN detections"}

    if any(k in msg for k in ["anomal", "suspicious", "threat scan", "risk scan", "proactive", "scan"]):
        return {"mode": "tool", "tool": "scan_anomalies", "params": {}, "brief_plan": "Scanning for traffic anomalies and high-risk IPs"}

    if any(k in msg for k in ["threat summary", "threat overview", "malicious", "threat intel"]):
        return {"mode": "tool", "tool": "get_threat_summary", "params": {}, "brief_plan": "Getting threat intelligence summary"}

    if any(k in msg for k in ["bandwidth analysis", "throughput", "data rate", "bytes by proto"]):
        return {"mode": "tool", "tool": "get_bandwidth_analysis", "params": {}, "brief_plan": "Analyzing bandwidth by protocol and port"}

    if any(k in msg for k in ["analyze traffic", "traffic analysis", "protocol distribution", "port analysis"]):
        return {"mode": "tool", "tool": "analyze_traffic", "params": {}, "brief_plan": "Analyzing traffic patterns and protocol distribution"}

    if any(k in msg for k in ["top talker", "busiest", "most traffic", "top ip"]):
        return {"mode": "tool", "tool": "get_top_talkers", "params": {}, "brief_plan": "Getting top talkers"}

    if any(k in msg for k in ["flow", "connection", "src", "dst"]):
        return {"mode": "tool", "tool": "get_flows", "params": {"limit": 5}, "brief_plan": "Getting network flows"}

    if any(k in msg for k in ["bandwidth", "bytes", "throughput"]):
        return {"mode": "tool", "tool": "get_bandwidth_analysis", "params": {}, "brief_plan": "Analyzing bandwidth utilization"}

    if any(k in msg for k in ["stat", "packet", "total", "count", "how many", "rate"]):
        return {"mode": "tool", "tool": "get_stats", "params": {}, "brief_plan": "Fetching capture statistics"}

    if any(k in msg for k in ["explain", "decode", "parse", "field"]):
        return {"mode": "tool", "tool": "explain_packet", "params": {"fields": message}, "brief_plan": "Explaining packet fields"}

    # Conversational fallback
    if any(k in msg for k in ["hello", "hi", "hey", "what is", "what are", "what can", "who are", "help", "about"]):
        return {
            "mode": "chat",
            "tool": "general_answer",
            "params": {},
            "answer": (
                " Hi! I'm **PacketSense AI** — your intelligent network analyst.\n\n"
                "I'm embedded in **5G-PacketSense v2**, a platform for real-time packet capture, "
                "PCAP analysis, VPN detection, threat intelligence, and network behaviour analysis.\n\n"
                "Here's what I can do for you:\n"
                "- [DATA] **Traffic analysis** — protocols, ports, packet sizes\n"
                "- [VPN] **VPN detection** — confidence scores, provider identification\n"
                "- [THREAT] **Threat intelligence** — FireHOL, IPsum, AbuseIPDB\n"
                "- [AI] **Behaviour analysis** — beaconing, exfiltration, tunnel detection\n"
                "- [RADIO] **Bandwidth analysis** — by protocol, port, and IP\n"
                "- [PC] **Device monitoring** — switch-mode device inventory\n"
                "- [MAP] **Map injection** — plot any src→dst packet on the geo-map\n"
                "- [SCAN] **IP investigation** — geo, ISP, VPN signals, abuse scores\n\n"
                "Just ask me anything or use the quick-action chips below! 🚀"
            ),
            "brief_plan": "Greeting response",
        }

    return {
        "mode": "tool",
        "tool": "general_answer",
        "params": {"answer": "I can help with: stats, VPN detections, traffic & bandwidth analysis, threat intelligence, anomaly scanning, behaviour analysis, device monitoring, IP reputation, flows, and map injection.\n\nTry: **'Scan for anomalies'**, **'Analyse traffic'**, **'Behaviour summary'**, **'Threat summary'**, **'Check IP 8.8.8.8'**, or **'Inject 1.2.3.4 → 8.8.8.8'**."},
        "brief_plan": "General guidance",
    }


# ── LLM caller — Ollama primary, OpenRouter fallback ─────────────────

def _probe_ollama() -> bool:
    """Quick health check to see if Ollama is reachable."""
    global _ollama_available
    try:
        import urllib.request
        base = OLLAMA_URL.replace("/v1", "")
        req = urllib.request.Request(f"{base}/api/tags", method="GET")
        with urllib.request.urlopen(req, timeout=3) as resp:
            _ollama_available = resp.status == 200
    except Exception:
        _ollama_available = False
    return _ollama_available


def _call_ollama(messages: list) -> str | None:
    """Call local/tunnelled Ollama. Returns raw response text or None."""
    global _active_provider, _active_model
    try:
        import openai
        client = openai.OpenAI(api_key="ollama", base_url=OLLAMA_URL, timeout=OLLAMA_TIMEOUT)
        resp = client.chat.completions.create(
            model=OLLAMA_MODEL_NAME,
            messages=messages,
            max_tokens=AGENT_MAX_TOKENS,
            temperature=AGENT_TEMPERATURE,
        )
        _active_provider = "ollama"
        _active_model = OLLAMA_MODEL_NAME
        return resp.choices[0].message.content
    except Exception as e:
        print(f"[AGENT] Ollama call failed: {e}")
        return None


def _call_openrouter(messages: list) -> str | None:
    """Call OpenRouter as fallback. Returns raw response text or None."""
    global _active_provider, _active_model
    api_key = getattr(config, "OPENROUTER_API_KEY", "")
    if not api_key:
        return None
    try:
        import openai
        client = openai.OpenAI(api_key=api_key, base_url="https://openrouter.ai/api/v1")
        for model_name in OPENROUTER_MODELS:
            try:
                resp = client.chat.completions.create(
                    model=model_name,
                    messages=messages,
                    max_tokens=AGENT_MAX_TOKENS,
                    temperature=AGENT_TEMPERATURE,
                    extra_headers={
                        "HTTP-Referer": "http://localhost:5000",
                        "X-Title": "5G-PacketSense Agent",
                    },
                )
                _active_provider = "openrouter"
                _active_model = model_name
                return resp.choices[0].message.content
            except Exception as e:
                print(f"[AGENT] OpenRouter model {model_name} failed: {e}")
        return None
    except Exception as e:
        print(f"[AGENT] OpenRouter client setup failed: {e}")
        return None


def _call_llm(messages: list) -> str | None:
    """Try Ollama first, fall back to OpenRouter, return None if both fail."""
    global _ollama_available
    # Probe Ollama if not yet checked
    if _ollama_available is None:
        _probe_ollama()

    if _ollama_available:
        result = _call_ollama(messages)
        if result is not None:
            return result
        # Ollama failed mid-session; mark unavailable, fallback
        _ollama_available = False
        print("[AGENT] Ollama unreachable, switching to OpenRouter fallback.")

    return _call_openrouter(messages)


# ── Conversational LLM call (free-form prose, no JSON required) ───────

def _call_llm_chat(messages: list) -> str | None:
    """Call LLM in plain conversational mode (no tool JSON needed)."""
    # Use a simpler system prompt for pure chat
    chat_messages = [
        {
            "role": "system",
            "content": (
                "You are PacketSense AI, a friendly and expert network security assistant "
                "embedded in the 5G-PacketSense v2 dashboard — a real-time network monitoring, "
                "VPN detection, threat intelligence, and behavioural analysis platform. "
                "Reply in markdown. Be concise, warm, and informative. "
                "If the user asks what the app does, explain it clearly."
            )
        }
    ] + [m for m in messages if m["role"] != "system"]

    return _call_llm(chat_messages)


# ── Response formatter ─────────────────────────────────────────────────

def _format_tool_result(tool: str, result: dict, brief_plan: str) -> str:
    """Turn raw tool result dict into a human-readable markdown string."""
    if result.get("error"):
        return f"[!] {result['error']}"

    if tool == "get_stats":
        mode = result.get("mode", "unknown")
        r = result
        lines = [f"**[DATA] Capture Statistics** ({'Live' if mode == 'live' else 'PCAP'} mode)\n"]
        if r.get("total_packets") is not None:
            lines.append(f"- **Total packets**: {r['total_packets']:,}")
        if r.get("total_bytes") is not None:
            lines.append(f"- **Total data**: {_fmt_bytes(r['total_bytes'])}")
        if r.get("unique_ips") is not None:
            lines.append(f"- **Unique IPs**: {r['unique_ips']}")
        if r.get("bandwidth_bps") is not None:
            lines.append(f"- **Bandwidth**: {_fmt_bytes(r['bandwidth_bps'])}/s")
        if r.get("vpn_ips_count"):
            lines.append(f"- **VPN IPs detected**: {r['vpn_ips_count']} [VPN]")
        if r.get("uptime_seconds"):
            lines.append(f"- **Capture uptime**: {_fmt_duration(r['uptime_seconds'])}")
        if r.get("top_talkers"):
            lines.append("\n**Top Talkers:**")
            for t in r["top_talkers"][:5]:
                lines.append(f"  - `{t['ip']}` — {_fmt_bytes(t['bytes'])}")
        if r.get("protocols"):
            lines.append("\n**Protocols:**")
            for p in r["protocols"][:5]:
                lines.append(f"  - {p['name']}: {p['count']:,} packets")
        return "\n".join(lines)

    elif tool == "get_vpn":
        count = result.get("vpn_count", 0)
        if count == 0:
            return "[OK] **No VPN IPs detected** in the current capture."
        lines = [f"[VPN] **{count} VPN IP(s) detected:**\n"]
        for v in result.get("vpn_ips", [])[:10]:
            provider = v.get("provider") or "Unknown provider"
            conf = v.get("confidence", 0)
            cls = v.get("classification", "")
            lines.append(f"- `{v['ip']}` — **{provider}** ({cls}, confidence: {conf}%)")
        return "\n".join(lines)

    elif tool == "get_top_talkers":
        talkers = result.get("top_talkers", [])
        if not talkers:
            return "No traffic data available yet."
        lines = ["**[NET] Top Talkers by Traffic:**\n"]
        for i, t in enumerate(talkers[:10], 1):
            lines.append(f"{i}. `{t['ip']}` — {_fmt_bytes(t['bytes'])}")
        return "\n".join(lines)

    elif tool == "check_ip":
        ip = result.get("ip", "")
        geo = result.get("geo") or {}
        vpn = result.get("vpn", {})
        threat = result.get("threat", {})
        lines = [f"**[SCAN] IP Analysis: `{ip}`**\n"]
        if geo:
            lines.append(f"- **Location**: {geo.get('city', '?')}, {geo.get('country', '?')}")
            lines.append(f"- **ISP**: {geo.get('isp', 'Unknown')}")
            lines.append(f"- **ASN**: {geo.get('asn', 'Unknown')}")
        is_vpn = vpn.get("is_vpn", False)
        lines.append(f"- **VPN**: {'[VPN] YES — ' + (vpn.get('provider') or 'Unknown provider') if is_vpn else '[OK] Not a VPN'}")
        if is_vpn:
            lines.append(f"  Confidence: {vpn.get('confidence', 0)}% ({vpn.get('classification', '')})")
        is_threat = threat.get("is_malicious", False)
        lines.append(f"- **Threat**: {'[!] ' + threat.get('threat_level', 'low').upper() + ' — ' + ', '.join(threat.get('categories', [])) if is_threat else '[OK] Clean'}")
        if threat.get("sources"):
            lines.append(f"  Sources: {', '.join(threat['sources'])}")
        return "\n".join(lines)

    elif tool == "get_flows":
        flows = result.get("flows", [])
        conns = result.get("active_connections")
        if conns is not None:
            return f"**Active connections**: {conns} live"
        if not flows:
            return "No flows found."
        lines = ["**[FLOW] Top Network Flows:**\n"]
        for f in flows[:5]:
            lines.append(f"- `{f['src']}` → `{f['dst']}` — {f['packets']:,} pkts, {_fmt_bytes(f['bytes'])}")
        return "\n".join(lines)

    elif tool == "inject_packet":
        src = result.get("src", {})
        dst = result.get("dst", {})
        proto = result.get("protocol", "TCP")
        vpn_warn = ""
        if src.get("is_vpn") or dst.get("is_vpn"):
            vpn_warn = "\n\n[VPN] **VPN detected** on this path!"
        return (
            f"**[MAP] Custom Packet Injected on Map**\n\n"
            f"- **Source**: `{src.get('ip')}` — {src.get('city')}, {src.get('country')} ({src.get('isp', '')})\n"
            f"- **Destination**: `{dst.get('ip')}` — {dst.get('city')}, {dst.get('country')} ({dst.get('isp', '')})\n"
            f"- **Protocol**: {proto}"
            f"{vpn_warn}"
        )

    elif tool == "explain_packet":
        return result.get("explanation", "No explanation available.")

    elif tool == "general_answer":
        return result.get("answer", "")

    elif tool == "analyze_traffic":
        r = result
        mode = r.get("mode", "")
        lines = [f"**[DATA] Traffic Analysis** ({'Live' if mode == 'live' else 'PCAP'} mode)\n"]
        if r.get("total_packets") is not None:
            lines.append(f"- **Total packets**: {r['total_packets']:,}")
        if r.get("unique_src_ips"):
            lines.append(f"- **Unique source IPs**: {r['unique_src_ips']:,}")
        if r.get("unique_dst_ips"):
            lines.append(f"- **Unique destination IPs**: {r['unique_dst_ips']:,}")
        if r.get("protocols"):
            lines.append("\n**Protocol Distribution:**")
            for p in r["protocols"][:6]:
                lines.append(f"  - `{p['name']}`: {p['count']:,} packets")
        if r.get("top_dst_ports") or r.get("top_ports"):
            ports = r.get("top_dst_ports") or r.get("top_ports", [])
            lines.append("\n**Top Destination Ports:**")
            for p in ports[:6]:
                lines.append(f"  - Port `{p['port']}`: {p['count']:,} packets")
        if r.get("packet_size_distribution"):
            lines.append("\n**Packet Size Distribution:**")
            for s in r["packet_size_distribution"]:
                lines.append(f"  - {s['bucket']}: {s['count']:,}")
        if r.get("vpn_protocol_ports_detected"):
            lines.append("\n**[!] VPN Protocol Ports Detected:**")
            for v in r["vpn_protocol_ports_detected"]:
                lines.append(f"  - Port `{v['port']}` ({v['name']}): {v['count']:,} packets")
        return "\n".join(lines)

    elif tool == "get_threat_summary":
        r = result
        total = r.get("total_ips_scanned", 0)
        malicious = r.get("total_malicious", 0)
        breakdown = r.get("threat_breakdown", {})
        lines = ["**[THREAT] Threat Intelligence Summary**\n"]
        lines.append(f"- **IPs scanned**: {total:,}")
        lines.append(f"- **Malicious IPs found**: {malicious:,} ({round(100 * malicious / total, 1) if total else 0}%)")
        if breakdown:
            lines.append("\n**Severity Breakdown:**")
            for level in ("critical", "high", "medium", "low"):
                cnt = breakdown.get(level, 0)
                if cnt:
                    icons = {"critical": "[CRIT]", "high": "[HIGH]", "medium": "[MED]", "low": "[LOW]"}
                    lines.append(f"  - {icons.get(level, '')} **{level.upper()}**: {cnt}")
        if r.get("top_categories"):
            lines.append("\n**Top Threat Categories:**")
            for cat, cnt in r["top_categories"][:5]:
                lines.append(f"  - `{cat}`: {cnt} IPs")
        if r.get("top_threat_ips"):
            lines.append("\n**Highest-Risk IPs:**")
            for t in r["top_threat_ips"][:5]:
                lines.append(f"  - `{t['ip']}` — {t['level'].upper()}: {', '.join(t.get('categories', []))[:60]}")
        return "\n".join(lines)

    elif tool == "get_vpn_signals":
        r = result
        ip = r.get("ip", "?")
        is_vpn = r.get("is_vpn", False)
        conf = r.get("confidence", 0)
        cls = r.get("classification", "not_vpn")
        provider = r.get("provider", "Unknown")
        lines = [f"**[SCAN] VPN Signal Breakdown: `{ip}`**\n"]
        lines.append(f"- **Result**: {'[VPN] VPN DETECTED' if is_vpn else '[OK] Not a VPN'}")
        lines.append(f"- **Confidence**: {conf}% ({cls})")
        if provider and is_vpn:
            lines.append(f"- **Provider**: {provider}")
        lines.append(f"- **Total signals**: {r.get('signal_count', 0)}, combined weight: {r.get('total_weight', 0)}")
        signals = r.get("signals", [])
        if signals:
            lines.append("\n**Signal contributions** (weight = confidence points added):")
            for sig in sorted(signals, key=lambda s: s.get("weight", 0), reverse=True):
                api_tag = f" [{sig.get('api', '')}]" if sig.get("api") else ""
                lines.append(f"  - `{sig['type']}`{api_tag} +{sig['weight']}pts: {sig.get('detail', '')[:80]}")
        else:
            lines.append("\nNo VPN signals detected — IP appears clean.")
        return "\n".join(lines)

    elif tool == "scan_anomalies":
        r = result
        found = r.get("anomalies_found", 0)
        scanned = r.get("ips_scanned", 0)
        summary = r.get("summary", {})
        lines = [f"**[SEARCH] Anomaly Scan Results** ({scanned} IPs scanned)\n"]
        if found == 0:
            lines.append("[OK] No anomalies detected in scanned traffic.")
        else:
            lines.append(f"**{found} anomal{'y' if found == 1 else 'ies'} found:**\n")
            if summary.get("vpn_confirmed"):
                lines.append(f"  - [VPN] VPN confirmed: {summary['vpn_confirmed']} IP(s)")
            if summary.get("vpn_likely"):
                lines.append(f"  - [VPN] VPN likely: {summary['vpn_likely']} IP(s)")
            if summary.get("threat_critical"):
                lines.append(f"  - [CRIT] Critical threats: {summary['threat_critical']} IP(s)")
            if summary.get("threat_high"):
                lines.append(f"  - [HIGH] High threats: {summary['threat_high']} IP(s)")
            if summary.get("suspicious_ports"):
                lines.append(f"  - [!] Suspicious port traffic: {summary['suspicious_ports']} packets")
            lines.append("")
            for a in r.get("top_anomalies", [])[:6]:
                if "ip" in a:
                    risk = a.get("risk_score", 0)
                    reasons = "; ".join(a.get("reasons", []))[:100]
                    lines.append(f"  **`{a['ip']}`** (risk: {risk}/100) — {reasons}")
                elif "type" in a:
                    lines.append(f"  **{a['type'].replace('_', ' ').title()}**: {'; '.join(a.get('reasons', []))}")
        rec = r.get("recommendation", "")
        if rec:
            lines.append(f"\n**Recommendation**: {rec}")
        return "\n".join(lines)

    elif tool == "get_bandwidth_analysis":
        r = result
        mode = r.get("mode", "")
        lines = [f"**[BW] Bandwidth Analysis** ({'Live' if mode == 'live' else 'PCAP'} mode)\n"]
        if r.get("total_bytes") is not None:
            lines.append(f"- **Total data**: {_fmt_bytes(r['total_bytes'])}")
        if r.get("total_packets"):
            lines.append(f"- **Total packets**: {r['total_packets']:,}")
        if r.get("avg_packet_size_bytes"):
            lines.append(f"- **Avg packet size**: {r['avg_packet_size_bytes']} B")
        if r.get("capture_duration_seconds"):
            lines.append(f"- **Duration**: {r['capture_duration_seconds']}s")
        if r.get("avg_throughput_bps"):
            bps = r["avg_throughput_bps"]
            lines.append(f"- **Avg throughput**: {_fmt_bytes(bps / 8)}/s ({_fmt_bytes(bps)} bps)")
        if r.get("by_protocol"):
            lines.append("\n**Bytes by Protocol:**")
            total_b = r.get("total_bytes", 1) or 1
            for p in r["by_protocol"][:6]:
                pct = round(100 * p["bytes"] / total_b, 1)
                lines.append(f"  - `{p['protocol']}`: {_fmt_bytes(p['bytes'])} ({pct}%)")
        if r.get("by_dst_port"):
            lines.append("\n**Top Ports by Traffic:**")
            for p in r["by_dst_port"][:5]:
                lines.append(f"  - Port `{p['port']}`: {_fmt_bytes(p['bytes'])} ({p['packets']:,} pkts)")
        if r.get("top_talkers_bytes"):
            lines.append("\n**Top Consumers:**")
            for t in r["top_talkers_bytes"][:5]:
                lines.append(f"  - `{t['ip']}`: {_fmt_bytes(t['bytes'])}")
        return "\n".join(lines)

    elif tool == "get_behaviour_summary":
        r = result
        total = r.get("total_devices_tracked", 0)
        suspicious = r.get("suspicious_devices", 0)
        lines = [f"**[AI] Behavioural Analysis Summary** ({total} devices tracked)\n"]
        if suspicious == 0:
            lines.append("[OK] No suspicious behaviour detected across tracked devices.")
        else:
            lines.append(f"[!] **{suspicious} device(s) flagged as suspicious:**\n")
            for d in r.get("top_suspicious", [])[:8]:
                score = d.get("composite_anomaly_score", 0)
                cls = ", ".join(d.get("classifications", []))
                lines.append(f"- **`{d['ip']}`** (anomaly score: {score}/100)")
                lines.append(f"  - Classifications: `{cls}`")
                if d.get("vpn_tunnel_score", 0) >= 40:
                    lines.append(f"  - [VPN] VPN tunnel score: {d['vpn_tunnel_score']}")
                if d.get("beaconing_score", 0) >= 40:
                    lines.append(f"  - [RADIO] Beaconing score: {d['beaconing_score']}")
                if d.get("exfil_score", 0) >= 40:
                    lines.append(f"  - [EXPORT] Exfiltration score: {d['exfil_score']}")
        return "\n".join(lines)

    elif tool == "get_device_behaviour":
        r = result
        ip = r.get("device_ip", "?")
        if r.get("classifications") == ["insufficient_data"]:
            return f"[!] Not enough data yet for `{ip}`. Need at least 10 packets from this device."
        scores = r.get("scores", {})
        cls = r.get("classifications", [])
        lines = [f"**[AI] Device Behaviour: `{ip}`**\n"]
        lines.append(f"- **Packets**: {r.get('total_packets', 0):,} | **Bytes**: {_fmt_bytes(r.get('total_bytes', 0))}")
        lines.append(f"- **Flows**: {r.get('flow_count', 0)} | **Unique destinations**: {r.get('unique_destinations', 0)}")
        duration = r.get("duration", 0)
        if duration:
            lines.append(f"- **Session duration**: {_fmt_duration(duration)}")
        lines.append(f"\n**Anomaly Scores:**")
        lines.append(f"  - [VPN] VPN tunnel: **{scores.get('vpn_tunnel', 0)}/100**")
        lines.append(f"  - [RADIO] Beaconing: **{scores.get('beaconing', 0)}/100**")
        lines.append(f"  - [EXPORT] Data exfiltration: **{scores.get('data_exfiltration', 0)}/100**")
        lines.append(f"  - [SEARCH] Composite anomaly: **{scores.get('composite_anomaly', 0)}/100**")
        lines.append(f"\n**Classification**: `{'`, `'.join(cls)}`")
        top_flows = r.get("top_flows", [])
        if top_flows:
            lines.append("\n**Top Flows:**")
            for f in top_flows[:4]:
                lines.append(f"  - → `{f['dst_ip']}:{f['dst_port']}` ({f['protocol']}) — {_fmt_bytes(f['bytes'])}, {f['packets']} pkts")
        return "\n".join(lines)

    elif tool == "get_session_info":
        r = result
        mode_labels = {
            "idle": "[MED] Idle — no data loaded",
            "live_capture": "[LOW] Live Capture",
            "pcap_analysis": "🔵 PCAP Analysis",
        }
        mode_str = mode_labels.get(r.get("mode", "idle"), r.get("mode", "idle"))
        lines = [f"**[INFO] Session Info**\n"]
        lines.append(f"- **Mode**: {mode_str}")
        if r.get("session_name"):
            lines.append(f"- **Session**: {r['session_name']}")
        if r.get("uptime_human"):
            lines.append(f"- **Uptime**: {r['uptime_human']}")
        if r.get("packets_captured") is not None:
            lines.append(f"- **Packets captured**: {r['packets_captured']:,}")
        if r.get("bytes_captured") is not None:
            lines.append(f"- **Bytes captured**: {_fmt_bytes(r['bytes_captured'])}")
        if r.get("parquet_path"):
            lines.append(f"- **Loaded file**: `{r['parquet_path']}`")
        if r.get("pcap_total_packets") is not None:
            lines.append(f"- **PCAP packets**: {r['pcap_total_packets']:,}")
        if r.get("switch_monitor_active"):
            lines.append(f"- **Switch monitor**: [LOW] active ({r.get('switch_devices_count', 0)} devices)")
        lines.append(f"\n**Cache Stats:**")
        lines.append(f"  - GeoIP cache: {r.get('geoip_cache_size', 0):,} IPs")
        lines.append(f"  - VPN cache: {r.get('vpn_cache_size', 0):,} entries")
        lines.append(f"  - AbuseIPDB: {'[OK] enabled' if r.get('abuseipdb_api_enabled') else '[!] offline only'} ({r.get('abuseipdb_calls_today', 0)} calls today)")
        return "\n".join(lines)

    elif tool == "get_capture_devices":
        r = result
        count = r.get("interface_count", 0)
        current = r.get("current_interface", "all")
        lines = [f"**[PC] Network Interfaces** ({count} available)\n"]
        lines.append(f"- **Current interface**: `{current}` (mode: {r.get('capture_mode', '?')})\n")
        for iface in r.get("interfaces", [])[:10]:
            ips = ", ".join(iface.get("ips", [])[:2])
            ip_str = f" — `{ips}`" if ips else ""
            lines.append(f"- `{iface['name']}` — {iface.get('description', '')}{ip_str}")
        return "\n".join(lines)

    elif tool == "get_switch_devices":
        r = result
        total = r.get("total_devices", 0)
        vpn_count = r.get("vpn_devices", 0)
        lines = [f"**[PLUG] Switch Devices** ({total} detected, {vpn_count} with VPN)\n"]
        for d in r.get("devices", [])[:10]:
            vpn_flag = f" [VPN] **{d['vpn_provider']}**" if d.get("vpn_detected") else ""
            lines.append(f"- `{d['mac']}` → `{d.get('ip', '?')}` {d.get('vendor', '')}{vpn_flag}")
            lines.append(f"  {d['packets']:,} pkts, {_fmt_bytes(d['bytes'])}")
        return "\n".join(lines)

    elif tool == "get_switch_vpn_alerts":
        r = result
        if r.get("alert_count", 0) == 0:
            return "[OK] No switch VPN alerts recorded in this session."
        lines = [f"**[!] Switch VPN Alerts** ({r['alert_count']} total)\n"]
        for alert in r.get("alerts", [])[-10:]:
            lines.append(f"- {json.dumps(alert, default=str)[:120]}")
        return "\n".join(lines)

    elif tool == "check_abuse_ip":
        r = result
        ip = r.get("ip", "?")
        if not r.get("available") and not r.get("in_offline_blacklist"):
            return f"ℹ️ No AbuseIPDB data available for `{ip}` (API not configured or IP is private)."
        lines = [f"**[ALERT] AbuseIPDB: `{ip}`**\n"]
        score = r.get("abuse_confidence", 0)
        risk = "[CRIT] HIGH" if score >= 75 else "[HIGH] MEDIUM" if score >= 25 else "[LOW] LOW"
        lines.append(f"- **Abuse confidence**: {score}% ({risk})")
        if r.get("is_vpn"):
            lines.append("- **VPN/Proxy**: [VPN] Yes (flagged by AbuseIPDB)")
        if r.get("is_tor"):
            lines.append("- **Tor exit node**: [!] Yes")
        if r.get("total_reports"):
            lines.append(f"- **Total abuse reports**: {r['total_reports']:,}")
        if r.get("usage_type"):
            lines.append(f"- **Usage type**: {r['usage_type']}")
        if r.get("isp"):
            lines.append(f"- **ISP**: {r['isp']}")
        if r.get("in_offline_blacklist"):
            lines.append("- **Offline blacklist**: [!] IP in AbuseIPDB public blacklist")
        return "\n".join(lines)

    elif tool == "get_geo_ip":
        r = result
        ip = r.get("ip", "?")
        lines = [f"**[GEO] Geo Resolution: `{ip}`**\n"]
        loc_parts = [p for p in [r.get("city"), r.get("region"), r.get("country")] if p and p != "Unknown"]
        lines.append(f"- **Location**: {', '.join(loc_parts) or 'Unknown'}")
        if r.get("lat") and r.get("lon"):
            lines.append(f"- **Coordinates**: {r['lat']:.4f}, {r['lon']:.4f}")
        if r.get("isp") and r["isp"] != "Unknown":
            lines.append(f"- **ISP**: {r['isp']}")
        if r.get("org"):
            lines.append(f"- **Org**: {r['org']}")
        if r.get("asn") and r["asn"] != "Unknown":
            lines.append(f"- **ASN**: {r['asn']}")
        is_vpn = r.get("is_vpn", False)
        if is_vpn:
            vpn_conf = r.get('vpn_confidence', 0)
            vpn_prov = r.get('vpn_provider') or 'Unknown'
            lines.append(f"- **VPN**: [VPN] {vpn_prov} ({vpn_conf}%)")
        else:
            lines.append("- **VPN**: [OK] Not a VPN")

        return "\n".join(lines)

    elif tool == "export_report":
        r = result
        lines = ["**[EXPORT] Session Report Generated**\n"]
        lines.append(f"- **Generated at**: {r.get('generated_at', '?')}")
        si = r.get("session_info", {})
        lines.append(f"- **Mode**: {si.get('mode', '?')}")
        if si.get("packets_captured") is not None:
            lines.append(f"- **Packets**: {si['packets_captured']:,}")
        if si.get("pcap_total_packets") is not None:
            lines.append(f"- **PCAP packets**: {si['pcap_total_packets']:,}")
        vpn_sum = r.get("vpn_summary", {})
        if vpn_sum.get("total_vpn_ips") is not None:
            lines.append(f"- **VPN IPs**: {vpn_sum['total_vpn_ips']}")
        lines.append(f"\n[OK] Full report data is available in the API response JSON (`tool_result`).")
        return "\n".join(lines)

    return json.dumps(result, indent=2)[:800]


def _fmt_bytes(b: float) -> str:
    if b >= 1073741824:
        return f"{b / 1073741824:.2f} GB"
    if b >= 1048576:
        return f"{b / 1048576:.2f} MB"
    if b >= 1024:
        return f"{b / 1024:.1f} KB"
    return f"{round(b)} B"


# ── Main chat endpoint ────────────────────────────────────────────────

def _parse_llm_json(llm_response: str) -> dict | None:
    """Parse JSON tool/chat decision from LLM response, handling markdown fences."""
    try:
        clean = re.sub(r"```(?:json)?\s*", "", llm_response).strip().rstrip("`").strip()
        json_match = re.search(r"\{.*\}", clean, re.DOTALL)
        if json_match:
            return json.loads(json_match.group())
    except (json.JSONDecodeError, AttributeError):
        pass
    return None


@agent_bp.route("/api/agent/chat", methods=["POST"])
def chat():
    """Main agent endpoint with multi-step ReAct-style agentic loop.

    Supports both conversational and tool-driven responses via intent
    classification. Ollama is tried first; OpenRouter is the fallback.

    Request body:
        { "message": str, "history": [{"role": "user"|"assistant", "content": str}] }

    Response:
        {
          "reply": str,             — formatted response text (markdown)
          "tool_used": str,         — primary tool called
          "tools_chain": list[str], — all tools called in order (multi-step)
          "map_action": dict|null,  — non-null for inject_packet
          "tool_result": dict,      — final tool output
          "steps": int,             — how many steps were executed
          "model": str,             — model name used
          "provider": str,          — "ollama" | "openrouter" | "regex-fallback"
          "mode": str,              — "chat" | "tool"
        }
    """
    body = request.get_json(silent=True) or {}
    user_message = (body.get("message") or "").strip()
    history = body.get("history", [])

    if not user_message:
        return jsonify({"error": "Empty message"}), 400

    # Build initial LLM message list
    llm_messages = [{"role": "system", "content": SYSTEM_PROMPT}]
    for h in history[-8:]:  # last 4 turns (increased from 3)
        if h.get("role") in ("user", "assistant") and h.get("content"):
            llm_messages.append({"role": h["role"], "content": h["content"]})
    llm_messages.append({"role": "user", "content": user_message})

    # ── Try LLM for intent classification ────────────────────────────
    all_reply_parts: list[str] = []
    tools_chain: list[str] = []
    map_action = None
    last_tool_result: dict = {}
    model_used = "regex-fallback"
    provider_used = "regex-fallback"
    first_brief_plan = ""
    response_mode = "tool"

    llm_response = _call_llm(llm_messages)
    tool_decision = None

    if llm_response:
        model_used = _active_model
        provider_used = _active_provider
        tool_decision = _parse_llm_json(llm_response)

    # ── Conversational mode (mode="chat") ─────────────────────────────
    if tool_decision and tool_decision.get("mode") == "chat":
        response_mode = "chat"
        answer = tool_decision.get("answer", "").strip()

        # If the LLM gave an answer directly, use it
        if answer:
            reply_text = answer
        else:
            # Ask the LLM again in plain chat mode
            chat_reply = _call_llm_chat(llm_messages)
            reply_text = chat_reply if chat_reply else "I'm here to help! Ask me anything about your network traffic."

        first_brief_plan = tool_decision.get("brief_plan", "Conversational reply")
        return jsonify({
            "reply": reply_text,
            "tool_used": "general_answer",
            "tools_chain": ["general_answer"],
            "brief_plan": first_brief_plan,
            "map_action": None,
            "tool_result": {"answer": reply_text},
            "steps": 0,
            "model": model_used,
            "provider": provider_used,
            "mode": "chat",
        })

    # ── Tool mode (mode="tool") — ReAct agentic loop ──────────────────
    for step in range(MAX_AGENT_STEPS):
        if step == 0:
            # Already fetched at the top; use existing tool_decision or regex
            if not tool_decision:
                tool_decision = _regex_intent(user_message)
                model_used = "regex-fallback"
                provider_used = "regex-fallback"
        else:
            # Fetch next LLM decision
            llm_response = _call_llm(llm_messages)
            tool_decision = None
            if llm_response:
                model_used = _active_model
                provider_used = _active_provider
                tool_decision = _parse_llm_json(llm_response)
            if not tool_decision:
                break

        # Handle chat mode within loop (shouldn't happen, but be safe)
        if tool_decision.get("mode") == "chat":
            answer = tool_decision.get("answer", "")
            if answer:
                all_reply_parts.append(answer)
            break

        tool_name = tool_decision.get("tool", "general_answer")
        params = tool_decision.get("params", {})
        brief_plan = tool_decision.get("brief_plan", "")
        needs_followup = bool(tool_decision.get("needs_followup", False))

        if step == 0:
            first_brief_plan = brief_plan

        # Execute the tool
        tool_fn = TOOLS.get(tool_name, TOOLS["general_answer"])
        try:
            tool_result = tool_fn(params)
        except Exception as e:
            tool_result = {"error": str(e)}

        last_tool_result = tool_result
        tools_chain.append(tool_name)

        # Format this step's reply
        step_reply = _format_tool_result(tool_name, tool_result, brief_plan)
        if step > 0 and step_reply:
            step_reply = f"\n\n---\n** Follow-up ({tool_name.replace('_', ' ')}):** {brief_plan}\n\n{step_reply}"
        all_reply_parts.append(step_reply)

        # Map action (only from inject_packet)
        if tool_name == "inject_packet" and tool_result.get("injected"):
            map_action = {
                "type": "inject_packet",
                "src": tool_result["src"],
                "dst": tool_result["dst"],
                "protocol": tool_result.get("protocol", "TCP"),
            }

        if not needs_followup or tool_name == "general_answer":
            break

        # Feed result back to LLM for next step
        result_summary = json.dumps(tool_result, default=str)[:1200]
        llm_messages.append({
            "role": "assistant",
            "content": json.dumps(tool_decision),
        })
        llm_messages.append({
            "role": "user",
            "content": f"Tool result from {tool_name}:\n{result_summary}\n\nContinue analysis. Set needs_followup=false when done.",
        })

    reply_text = "".join(all_reply_parts)

    return jsonify({
        "reply": reply_text,
        "tool_used": tools_chain[0] if tools_chain else "general_answer",
        "tools_chain": tools_chain,
        "brief_plan": first_brief_plan,
        "map_action": map_action,
        "tool_result": last_tool_result,
        "steps": len(tools_chain),
        "model": model_used,
        "provider": provider_used,
        "mode": response_mode,
    })


@agent_bp.route("/api/agent/status")
def agent_status():
    """Return agent configuration, Ollama connectivity, and availability."""
    global _ollama_available

    # Re-probe Ollama on every status call so UI gets fresh data
    ollama_reachable = _probe_ollama()

    has_openrouter = bool(getattr(config, "OPENROUTER_API_KEY", ""))
    available = ollama_reachable or has_openrouter

    if ollama_reachable:
        active_provider = "ollama"
        active_model = OLLAMA_MODEL_NAME
    elif has_openrouter:
        active_provider = "openrouter"
        active_model = OPENROUTER_MODELS[0]
    else:
        active_provider = "regex-fallback"
        active_model = "regex-fallback"

    return jsonify({
        "model": active_model,
        "provider": active_provider,
        "available": available,
        "ollama": {
            "reachable": ollama_reachable,
            "url": OLLAMA_URL,
            "model": OLLAMA_MODEL_NAME,
            "timeout": OLLAMA_TIMEOUT,
        },
        "openrouter": {
            "configured": has_openrouter,
            "fallback_models": OPENROUTER_MODELS[:3],
        },
        "fallback": "regex-intent",
        "max_steps": MAX_AGENT_STEPS,
        "agentic_mode": "ReAct (multi-step tool chaining) + Conversational",
        "tools": list(TOOLS.keys()),
        "tool_count": len(TOOLS),
        "capabilities": [
            "Live & PCAP statistics",
            "VPN detection with full signal breakdown",
            "Top talkers analysis",
            "IP reputation & threat intel",
            "Network flow inspection",
            "Traffic pattern & protocol analysis",
            "Threat intelligence summary",
            "Proactive anomaly scanning",
            "Bandwidth utilization analysis",
            "Behavioural analysis (beaconing, exfil, tunnel)",
            "Device behaviour profiling",
            "Session info & capture devices",
            "Switch device inventory & VPN alerts",
            "AbuseIPDB per-IP enrichment",
            "Full geo IP resolution",
            "Session report export",
            "Custom packet map injection",
            "Packet field explanation",
            "Natural language conversation",
            "Multi-step ReAct reasoning",
        ],
    })
