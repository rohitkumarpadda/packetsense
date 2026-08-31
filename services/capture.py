"""
services/capture.py — Unified packet capture engine.

Handles both local-machine and switch-monitoring modes through a single
start_unified_capture() entry point.  Per-packet callbacks feed data to
the SocketIO emitter for real-time frontend updates.
"""

import ipaddress
import random
import time
from datetime import datetime
from pathlib import Path

from scapy.all import sniff, IP, TCP, UDP, wrpcap

import config
from services.geo import resolve_ip, is_private_ip, get_user_public_location
from services.vpn import detect_vpn_protocol_heuristic
from services.behaviour import BehaviourAnalyzer
from services.threat_intel import check_ip_reputation

# Reference to SocketIO — injected by app.py at startup
socketio = None
app = None  # Flask app instance for context

# ── Emission throttle (batch packets every 500ms) ────────────────
_emit_buffer = []
_emit_timer = None
_EMIT_INTERVAL = 0.5  # seconds


def _flush_emit_buffer():
    """Flush buffered packets to SocketIO as a batch."""
    global _emit_buffer, _emit_timer
    if not socketio or not _emit_buffer:
        _emit_timer = None
        return
    batch = _emit_buffer[:]
    batch_len = len(batch)
    _emit_buffer = []
    _emit_timer = None
    
    # Emit each packet individually with proper app context
    try:
        if app:
            with app.app_context():
                for pkt_data in batch:
                    socketio.emit(pkt_data["event"], pkt_data["data"], broadcast=True)
                print(f"[SocketIO] Emitted {batch_len} packets to frontend")
        else:
            print("[WARN] Flask app context not available, attempting emit anyway")
            for pkt_data in batch:
                socketio.emit(pkt_data["event"], pkt_data["data"], broadcast=True)
            print(f"[SocketIO] Emitted {batch_len} packets to frontend (no context)")
    except Exception as e:
        print(f"[ERROR] Failed to emit {batch_len} packets: {e}")
        import traceback
        print(traceback.format_exc())


def _throttled_emit(event, data):
    """Queue a packet for throttled emission."""
    global _emit_timer
    _emit_buffer.append({"event": event, "data": data})
    if _emit_timer is None:
        import threading
        _emit_timer = threading.Timer(_EMIT_INTERVAL, _flush_emit_buffer)
        _emit_timer.daemon = True
        _emit_timer.start()


def set_socketio(sio, flask_app=None):
    """Called once by app.py to inject the SocketIO instance and Flask app."""
    global socketio, app
    socketio = sio
    app = flask_app


# ── Risk score computation ────────────────────────────────────────

# Risk factor weights — each factor contributes points toward the 0-100 score
RISK_FACTORS = {
    # VPN-related (scaled by confidence)
    "vpn_confirmed":        25,  # High-confidence VPN (confidence >= 61)
    "vpn_likely":           15,  # Medium-confidence VPN (36-60)
    "vpn_suspect":           5,  # Low-confidence (16-35)

    # VPN protocol heuristics
    "vpn_protocol_strong":  10,  # WireGuard, IPSec, OpenVPN detected
    "vpn_protocol_weak":     5,  # Ambiguous VPN port hint

    # Threat intelligence (from FireHOL, IPsum, Blocklist.de)
    "threat_critical":      50,  # FireHOL L1, Spamhaus DROP → malware C&C, hijacked ranges
    "threat_high":          35,  # FireHOL L2, dshield, multiple blocklist.de → known attackers
    "threat_medium":        20,  # FireHOL L3, single blocklist.de → reputation risk
    "threat_low":           10,  # Low-severity threat match

    # Cross-correlation bonuses (combined signals = worse than either alone)
    "vpn_plus_threat_crit": 20,  # VPN traffic to C&C/malware server
    "vpn_plus_threat_high": 10,  # VPN traffic to known attacker

    # Behavioural analysis
    "behaviour_tunnel":     15,  # Behavioural engine detects tunnel patterns
    "behaviour_beaconing":  20,  # C2-like beaconing pattern
    "behaviour_exfil":      25,  # Data exfiltration pattern

    # Suspicious ports
    "suspicious_port":      15,  # Known backdoor/attack ports
    "dark_web_port":        20,  # Tor hidden service ports

    # AbuseIPDB (when available)
    "abuseipdb_critical":   30,  # Abuse confidence > 75%
    "abuseipdb_high":       20,  # Abuse confidence 50-75%
    "abuseipdb_medium":     10,  # Abuse confidence 25-50%
}

# Ports commonly associated with backdoors and attack tools
SUSPICIOUS_PORTS = {4444, 5555, 6666, 6667, 31337, 12345, 65535, 1337}
DARK_WEB_PORTS = {9050, 9051, 9150}  # Tor SOCKS proxy


def compute_risk_score(vpn_detected, threat_info, vpn_explanation, dst_port,
                       behaviour_scores=None, abuseipdb_info=None,
                       vpn_confidence=0, vpn_classification="not_vpn"):
    """Compute a 0-100 risk score using multi-factor weighted scoring.

    Args:
        vpn_detected: bool — is this packet VPN traffic?
        threat_info: dict — from threat_intel.check_ip_reputation()
        vpn_explanation: dict — VPN detection details
        dst_port: int — destination port
        behaviour_scores: dict — from BehaviourAnalyzer.analyze_device()
        abuseipdb_info: dict — from abuseipdb.check_ip_abuseipdb()
        vpn_confidence: int — VPN confidence score (0-100)
        vpn_classification: str — VPN classification label

    Returns:
        {
            "score": int (0-100),
            "risk_level": str (critical/high/medium/low/none),
            "reasons": list[str],
            "breakdown": list[dict],  # Each contributing factor
            "primary_concern": str,   # Single biggest factor
        }
    """
    score = 0
    reasons = []
    breakdown = []

    # ── VPN factor (scaled by classification) ────────────────
    if vpn_classification == "vpn_confirmed":
        pts = RISK_FACTORS["vpn_confirmed"]
        score += pts
        reasons.append(f"Confirmed VPN traffic (confidence: {vpn_confidence}%)")
        breakdown.append({"factor": "vpn_confirmed", "points": pts,
                          "detail": f"VPN confirmed with {vpn_confidence}% confidence"})
    elif vpn_classification == "vpn_likely":
        pts = RISK_FACTORS["vpn_likely"]
        score += pts
        reasons.append(f"Likely VPN traffic (confidence: {vpn_confidence}%)")
        breakdown.append({"factor": "vpn_likely", "points": pts,
                          "detail": f"VPN likely with {vpn_confidence}% confidence"})
    elif vpn_classification == "vpn_suspect":
        pts = RISK_FACTORS["vpn_suspect"]
        score += pts
        reasons.append(f"Suspected VPN traffic (confidence: {vpn_confidence}%)")
        breakdown.append({"factor": "vpn_suspect", "points": pts,
                          "detail": f"VPN suspected with {vpn_confidence}% confidence"})

    # ── VPN protocol heuristic factor ────────────────────────
    if vpn_explanation and vpn_explanation.get("protocol_hints"):
        hints = vpn_explanation["protocol_hints"]
        has_strong = any(h.get("strength") == "strong" for h in hints)
        if has_strong:
            pts = RISK_FACTORS["vpn_protocol_strong"]
            score += pts
            hint_names = [h["protocol_hint"] for h in hints if h.get("strength") == "strong"]
            reasons.append(f"VPN protocol: {', '.join(hint_names)}")
            breakdown.append({"factor": "vpn_protocol_strong", "points": pts,
                              "detail": f"Strong VPN protocol signature: {', '.join(hint_names)}"})
        else:
            pts = RISK_FACTORS["vpn_protocol_weak"]
            score += pts
            breakdown.append({"factor": "vpn_protocol_weak", "points": pts,
                              "detail": "Weak VPN protocol hint detected"})

    # ── Threat intelligence factor (FireHOL, IPsum, Blocklist.de) ──
    threat_level = "none"
    if threat_info and threat_info.get("is_malicious"):
        threat_level = threat_info.get("threat_level", "low")
        sources = threat_info.get("sources", [])
        sources_str = ", ".join(sources) if sources else "unknown"

        if threat_level == "critical":
            pts = RISK_FACTORS["threat_critical"]
            score += pts
            reasons.append(f"Critical threat: {sources_str}")
            breakdown.append({"factor": "threat_critical", "points": pts,
                              "detail": f"Critical threat match in: {sources_str}"})
        elif threat_level == "high":
            pts = RISK_FACTORS["threat_high"]
            score += pts
            reasons.append(f"High threat: {sources_str}")
            breakdown.append({"factor": "threat_high", "points": pts,
                              "detail": f"High threat match in: {sources_str}"})
        elif threat_level == "medium":
            pts = RISK_FACTORS["threat_medium"]
            score += pts
            reasons.append(f"Medium threat: {sources_str}")
            breakdown.append({"factor": "threat_medium", "points": pts,
                              "detail": f"Medium threat match in: {sources_str}"})
        else:
            pts = RISK_FACTORS["threat_low"]
            score += pts
            reasons.append(f"Low threat: {sources_str}")
            breakdown.append({"factor": "threat_low", "points": pts,
                              "detail": f"Low threat match in: {sources_str}"})

        # ── Cross-correlation bonus: VPN + threat intel ──────
        if vpn_detected and threat_level == "critical":
            pts = RISK_FACTORS["vpn_plus_threat_crit"]
            score += pts
            reasons.append("VPN routing through malicious infrastructure")
            breakdown.append({"factor": "vpn_plus_threat_crit", "points": pts,
                              "detail": "VPN + critical threat = possible malicious VPN tunnel"})
        elif vpn_detected and threat_level == "high":
            pts = RISK_FACTORS["vpn_plus_threat_high"]
            score += pts
            breakdown.append({"factor": "vpn_plus_threat_high", "points": pts,
                              "detail": "VPN + high threat = elevated risk"})

    # ── Behavioural analysis factor ──────────────────────────
    if behaviour_scores:
        vpn_tunnel_score = behaviour_scores.get("vpn_tunnel", 0)
        beacon_score = behaviour_scores.get("beaconing", 0)
        exfil_score = behaviour_scores.get("data_exfiltration", 0)

        if vpn_tunnel_score >= 50:
            pts = RISK_FACTORS["behaviour_tunnel"]
            score += pts
            reasons.append(f"Behavioural tunnel pattern (score: {vpn_tunnel_score})")
            breakdown.append({"factor": "behaviour_tunnel", "points": pts,
                              "detail": f"Traffic patterns consistent with VPN tunnel (score: {vpn_tunnel_score})"})
        if beacon_score >= 50:
            pts = RISK_FACTORS["behaviour_beaconing"]
            score += pts
            reasons.append(f"C2-like beaconing detected (score: {beacon_score})")
            breakdown.append({"factor": "behaviour_beaconing", "points": pts,
                              "detail": f"Regular-interval connections suggest C2 beaconing (score: {beacon_score})"})
        if exfil_score >= 50:
            pts = RISK_FACTORS["behaviour_exfil"]
            score += pts
            reasons.append(f"Data exfiltration pattern (score: {exfil_score})")
            breakdown.append({"factor": "behaviour_exfil", "points": pts,
                              "detail": f"Large sustained data transfer pattern (score: {exfil_score})"})

    # ── AbuseIPDB factor ─────────────────────────────────────
    if abuseipdb_info and abuseipdb_info.get("available"):
        abuse_conf = abuseipdb_info.get("abuse_confidence", 0)
        if abuse_conf > 75:
            pts = RISK_FACTORS["abuseipdb_critical"]
            score += pts
            reasons.append(f"AbuseIPDB: {abuse_conf}% abuse confidence ({abuseipdb_info.get('total_reports', 0)} reports)")
            breakdown.append({"factor": "abuseipdb_critical", "points": pts,
                              "detail": f"AbuseIPDB abuse confidence {abuse_conf}% from {abuseipdb_info.get('total_reports', 0)} reports"})
        elif abuse_conf > 50:
            pts = RISK_FACTORS["abuseipdb_high"]
            score += pts
            reasons.append(f"AbuseIPDB: {abuse_conf}% abuse confidence")
            breakdown.append({"factor": "abuseipdb_high", "points": pts,
                              "detail": f"AbuseIPDB abuse confidence {abuse_conf}%"})
        elif abuse_conf > 25:
            pts = RISK_FACTORS["abuseipdb_medium"]
            score += pts
            breakdown.append({"factor": "abuseipdb_medium", "points": pts,
                              "detail": f"AbuseIPDB abuse confidence {abuse_conf}%"})
    elif abuseipdb_info and abuseipdb_info.get("in_offline_blacklist"):
        pts = RISK_FACTORS["abuseipdb_critical"]
        score += pts
        reasons.append("IP in AbuseIPDB offline blacklist")
        breakdown.append({"factor": "abuseipdb_blacklist", "points": pts,
                          "detail": "Found in AbuseIPDB public blacklist (100% confidence)"})

    # ── Suspicious port factor ───────────────────────────────
    if dst_port in SUSPICIOUS_PORTS:
        pts = RISK_FACTORS["suspicious_port"]
        score += pts
        reasons.append(f"Suspicious port {dst_port}")
        breakdown.append({"factor": "suspicious_port", "points": pts,
                          "detail": f"Port {dst_port} is commonly used by backdoors/attack tools"})
    elif dst_port in DARK_WEB_PORTS:
        pts = RISK_FACTORS["dark_web_port"]
        score += pts
        reasons.append(f"Tor proxy port {dst_port}")
        breakdown.append({"factor": "dark_web_port", "points": pts,
                          "detail": f"Port {dst_port} is a Tor SOCKS proxy port"})

    # ── Final score and classification ───────────────────────
    final_score = min(score, 100)

    if final_score >= 70:
        risk_level = "critical"
    elif final_score >= 45:
        risk_level = "high"
    elif final_score >= 25:
        risk_level = "medium"
    elif final_score > 0:
        risk_level = "low"
    else:
        risk_level = "none"

    # Primary concern = highest-weight contributing factor
    primary_concern = ""
    if breakdown:
        top = max(breakdown, key=lambda b: b["points"])
        primary_concern = top["detail"]

    return {
        "score": final_score,
        "risk_level": risk_level,
        "reasons": reasons,
        "breakdown": breakdown,
        "primary_concern": primary_concern,
    }



def _build_vpn_explanation(ip, loc, vpn_hints=None):
    """Build a detailed explanation dict for why an IP is classified as VPN."""
    if not loc or not loc.get("is_vpn"):
        return None

    method = loc.get("vpn_method", "unknown")
    method_detail = loc.get("vpn_method_detail", "")

    explanation = {
        "ip": ip,
        "provider": loc.get("vpn_provider", "Unknown"),
        "method": method,
        "isp": loc.get("isp", "Unknown"),
        "asn": loc.get("asn", "Unknown"),
        "country": loc.get("country", "Unknown"),
        "city": loc.get("city", "Unknown"),
        "protocol_hints": vpn_hints or [],
        "method_label": method_detail if method_detail else _method_label(method),
        "method_detail": method_detail,
    }
    return explanation


def _method_label(method):
    """Human-readable fallback label for VPN detection method."""
    labels = {
        "keyword": "ISP/Org name matched known VPN provider keywords",
        "asn_database": "ASN number matched known VPN infrastructure",
        "ip_database": "IP found in pre-downloaded VPN IP range database",
        "threat_intel": "IP flagged by offline threat intelligence feeds",
    }
    return labels.get(method, f"Detected via: {method}")


# ── Local capture callback ────────────────────────────────────────


def packet_callback(packet):
    """Process a captured packet in local mode."""
    config.captured_packets.append(packet)

    if config.live_stats["total_packets"] == 0:
        print("[SUCCESS] First packet captured!")

    if IP not in packet:
        return

    src_ip = packet[IP].src
    dst_ip = packet[IP].dst
    protocol = "TCP" if TCP in packet else "UDP" if UDP in packet else "OTHER"
    pkt_size = len(packet)
    now = time.time()

    stats = config.live_stats
    stats["total_packets"] += 1
    stats["total_bytes"] += pkt_size
    stats["unique_ips"].update((src_ip, dst_ip))
    stats["unique_src_ips"].add(src_ip)
    stats["unique_dst_ips"].add(dst_ip)
    stats["protocols"][protocol] += 1
    stats["top_talkers"][src_ip] += pkt_size

    if protocol == "TCP":
        stats["tcp_packets"] += 1
        src_port, dst_port = packet[TCP].sport, packet[TCP].dport
        flags, seq, ack = str(packet[TCP].flags), packet[TCP].seq, packet[TCP].ack
        stats["ports"][dst_port] += 1
    elif protocol == "UDP":
        stats["udp_packets"] += 1
        src_port, dst_port = packet[UDP].sport, packet[UDP].dport
        flags = seq = ack = None
        stats["ports"][dst_port] += 1
    else:
        return

    conn_key = f"{src_ip}:{src_port}->{dst_ip}:{dst_port}"
    stats["connections"][conn_key] = stats["connections"].get(conn_key, 0) + 1

    src_loc = resolve_ip(src_ip)
    dst_loc = resolve_ip(dst_ip)
    if not (src_loc and dst_loc):
        return

    vpn_detected = _track_vpn(src_ip, dst_ip, src_loc, dst_loc)
    vpn_hints = detect_vpn_protocol_heuristic(packet, src_port, dst_port, protocol)

    # Build VPN explanation
    vpn_explanation = None
    vpn_confidence = 0
    vpn_classification = "not_vpn"
    if src_loc.get("is_vpn"):
        vpn_explanation = _build_vpn_explanation(src_ip, src_loc, vpn_hints)
        vpn_confidence = src_loc.get("vpn_confidence", 0)
        vpn_classification = src_loc.get("vpn_classification", "not_vpn")
    elif dst_loc.get("is_vpn"):
        vpn_explanation = _build_vpn_explanation(dst_ip, dst_loc, vpn_hints)
        vpn_confidence = dst_loc.get("vpn_confidence", 0)
        vpn_classification = dst_loc.get("vpn_classification", "not_vpn")
    elif vpn_hints:
        vpn_explanation = {"ip": dst_ip, "provider": vpn_hints[0]["protocol_hint"],
                          "method": f"port_{vpn_hints[0]['port']}",
                          "method_label": f"VPN protocol detected on port {vpn_hints[0]['port']}",
                          "protocol_hints": vpn_hints}
        # Check if dst_loc has suspect VPN classification
        vpn_confidence = dst_loc.get("vpn_confidence", 0) if dst_loc else 0
        vpn_classification = dst_loc.get("vpn_classification", "not_vpn") if dst_loc else "not_vpn"

    # Threat intelligence check
    threat_info = None
    for ip in (src_ip, dst_ip):
        if not is_private_ip(ip):
            threat_info = check_ip_reputation(ip)
            if threat_info and threat_info.get("is_malicious"):
                break

    # AbuseIPDB enrichment (optional online, always tries offline blacklist)
    abuseipdb_info = None
    try:
        from services.abuseipdb import check_ip_abuseipdb
        for ip in (dst_ip, src_ip):
            if not is_private_ip(ip):
                abuseipdb_info = check_ip_abuseipdb(ip)
                if abuseipdb_info and (abuseipdb_info.get("available") or abuseipdb_info.get("in_offline_blacklist")):
                    break
    except ImportError:
        pass

    # Behavioural analysis scores for risk computation
    behaviour_scores = None
    if config.behaviour_analyzer and not is_private_ip(src_ip):
        analysis = config.behaviour_analyzer.analyze_device(src_ip)
        if analysis and analysis.get("scores", {}).get("composite_anomaly", 0) > 0:
            behaviour_scores = analysis["scores"]

    # Feed behavioural analysis engine
    if config.behaviour_analyzer and not is_private_ip(dst_ip):
        config.behaviour_analyzer.record_packet(
            src_ip, dst_ip, dst_port, protocol, pkt_size, now
        )

    # Risk score (multi-factor weighted)
    risk = compute_risk_score(
        vpn_detected, threat_info, vpn_explanation, dst_port,
        behaviour_scores=behaviour_scores,
        abuseipdb_info=abuseipdb_info,
        vpn_confidence=vpn_confidence,
        vpn_classification=vpn_classification,
    )

    pkt_data = {
        "timestamp": now,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": src_port,
        "dst_port": dst_port,
        "protocol": protocol,
        "src_location": src_loc,
        "dst_location": dst_loc,
        "size": pkt_size,
        "flags": flags,
        "seq": seq,
        "ack": ack,
        "ttl": packet[IP].ttl,
        "id": packet[IP].id,
        "vpn_detected": vpn_detected,
        "vpn_confidence": vpn_confidence,
        "vpn_classification": vpn_classification,
        "risk_score": risk["score"],
        "risk_level": risk["risk_level"],
        "risk_reasons": risk["reasons"],
        "risk_breakdown": risk["breakdown"],
        "risk_primary_concern": risk["primary_concern"],
        "vpn_explanation": vpn_explanation,
        "threat_info": {
            "is_malicious": threat_info.get("is_malicious", False),
            "threat_level": threat_info.get("threat_level", "none"),
            "sources": threat_info.get("sources", []),
        } if threat_info and threat_info.get("is_malicious") else None,
    }
    config.packet_history.append(pkt_data)
    if socketio:
        _throttled_emit("new_packet", pkt_data)
        if stats["total_packets"] <= 3 or stats["total_packets"] % 100 == 0:
            print(f"[EMIT] Queued packet #{stats['total_packets']} for emission (buffer size: {len(_emit_buffer)})")
    else:
        print("[WARN] SocketIO not initialized - packets not being emitted to frontend")


# ── Switch monitoring callback ────────────────────────────────────


def switch_packet_callback(packet):
    """Process a packet captured from a switch mirror port."""
    if IP not in packet:
        return

    src_ip, dst_ip = packet[IP].src, packet[IP].dst
    protocol = "TCP" if TCP in packet else "UDP" if UDP in packet else "OTHER"
    pkt_size = len(packet)
    now = time.time()

    if protocol == "TCP" and TCP in packet:
        src_port, dst_port = packet[TCP].sport, packet[TCP].dport
    elif protocol == "UDP" and UDP in packet:
        src_port, dst_port = packet[UDP].sport, packet[UDP].dport
    else:
        src_port = dst_port = 0

    src_internal = _is_internal_ip(src_ip)
    dst_internal = _is_internal_ip(dst_ip)
    if not src_internal and not dst_internal:
        return

    if src_internal:
        internal_ip, external_ip, direction = src_ip, dst_ip, "outbound"
    else:
        internal_ip, external_ip, direction = dst_ip, src_ip, "inbound"

    # Internal-to-internal: just track activity
    if _is_internal_ip(external_ip):
        with config.switch_device_lock:
            dev = config.switch_devices.setdefault(
                internal_ip, _new_device_entry(internal_ip, now)
            )
            dev["last_seen"] = now
            dev["total_packets"] += 1
            dev["total_bytes"] += pkt_size
            dev["internal_traffic_bytes"] += pkt_size
        return

    # Track device
    with config.switch_device_lock:
        dev = config.switch_devices.setdefault(
            internal_ip, _new_device_entry(internal_ip, now)
        )
        dev["last_seen"] = now
        dev["total_packets"] += 1
        dev["total_bytes"] += pkt_size
        dev["protocols"][protocol] = dev["protocols"].get(protocol, 0) + 1
        ext = dev["external_ips"].setdefault(
            external_ip, {"packets": 0, "bytes": 0, "first_seen": now}
        )
        ext["packets"] += 1
        ext["bytes"] += pkt_size

    # VPN detection
    vpn_hints = detect_vpn_protocol_heuristic(packet, src_port, dst_port, protocol)
    vpn_by_ip = False
    vpn_provider = vpn_method = None
    vpn_confidence = 0
    vpn_classification = "not_vpn"
    threat_info = None

    if not is_private_ip(external_ip):
        ext_loc = resolve_ip(external_ip)
        if ext_loc and ext_loc.get("is_vpn"):
            vpn_by_ip = True
            vpn_provider = ext_loc.get("vpn_provider", "Unknown VPN")
            vpn_method = ext_loc.get("vpn_method", "ip_lookup")
            vpn_confidence = ext_loc.get("vpn_confidence", 0)
            vpn_classification = ext_loc.get("vpn_classification", "not_vpn")

        # Offline threat intelligence check
        threat_info = check_ip_reputation(external_ip)

    is_vpn_traffic = vpn_by_ip or len(vpn_hints) > 0

    if is_vpn_traffic:
        _record_switch_vpn(
            internal_ip,
            external_ip,
            dst_port,
            protocol,
            pkt_size,
            now,
            vpn_by_ip,
            vpn_provider,
            vpn_method,
            vpn_hints,
            direction,
        )

    # Build VPN explanation for switch mode
    vpn_explanation = None
    if vpn_by_ip and not is_private_ip(external_ip):
        ext_loc = config.GEOIP_CACHE.get(external_ip)
        vpn_explanation = _build_vpn_explanation(external_ip, ext_loc, vpn_hints)
    elif vpn_hints:
        vpn_explanation = {"ip": external_ip, "provider": vpn_hints[0]["protocol_hint"],
                          "method": f"port_{vpn_hints[0]['port']}",
                          "method_label": f"VPN protocol detected on port {vpn_hints[0]['port']}",
                          "protocol_hints": vpn_hints}

    # AbuseIPDB enrichment (optional)
    abuseipdb_info = None
    if not is_private_ip(external_ip):
        try:
            from services.abuseipdb import check_ip_abuseipdb
            abuseipdb_info = check_ip_abuseipdb(external_ip)
        except ImportError:
            pass

    # Behavioural analysis scores for risk computation
    behaviour_scores = None
    if config.behaviour_analyzer and direction == "outbound":
        analysis = config.behaviour_analyzer.analyze_device(internal_ip)
        if analysis and analysis.get("scores", {}).get("composite_anomaly", 0) > 0:
            behaviour_scores = analysis["scores"]

    # Risk score (multi-factor weighted)
    risk = compute_risk_score(
        is_vpn_traffic, threat_info, vpn_explanation, dst_port,
        behaviour_scores=behaviour_scores,
        abuseipdb_info=abuseipdb_info,
        vpn_confidence=vpn_confidence,
        vpn_classification=vpn_classification,
    )

    # Feed behavioural analysis engine
    if config.behaviour_analyzer and direction == "outbound":
        config.behaviour_analyzer.record_packet(
            internal_ip, external_ip, dst_port, protocol, pkt_size, now
        )
        # Emit behavioural alert if anomaly score is high (every 100 packets)
        with config.switch_device_lock:
            dev_pkts = config.switch_devices.get(internal_ip, {}).get("total_packets", 0)
        if dev_pkts > 0 and dev_pkts % 100 == 0:
            analysis = config.behaviour_analyzer.analyze_device(internal_ip)
            if analysis["scores"]["composite_anomaly"] > 40 and socketio:
                socketio.emit("behaviour_alert", analysis)

    # Emit live packet for map
    if not is_private_ip(external_ip):
        _emit_switch_packet(
            packet,
            internal_ip,
            external_ip,
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            protocol,
            pkt_size,
            now,
            direction,
            is_vpn_traffic,
            threat_info,
            risk,
            vpn_explanation,
            vpn_confidence=vpn_confidence,
            vpn_classification=vpn_classification,
        )

    # Periodic device update
    with config.switch_device_lock:
        dev = config.switch_devices[internal_ip]
        if dev["total_packets"] % 50 == 0 and socketio:
            socketio.emit("switch_device_update", sanitize_device(internal_ip, dev))


# ── Unified capture starter ──────────────────────────────────────


def start_unified_capture():
    """Start packet capture in the configured mode. Runs until capture_running is False."""
    import platform
    from scapy.all import conf
    
    config.capture_running = True
    config.SWITCH_MONITOR_RUNNING = True
    config.live_stats["start_time"] = time.time()
    config.switch_devices = {}
    config.switch_vpn_alerts = []
    config.captured_packets = []
    config.capture_session_name = (
        f"live_capture_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    )

    # Initialize behavioural analysis engine
    config.behaviour_analyzer = BehaviourAnalyzer()

    # Resolve interface on Windows: GUID string → interface object
    capture_iface = config.CAPTURE_INTERFACE
    if platform.system() == "Windows" and capture_iface:
        if capture_iface in conf.ifaces:
            capture_iface = conf.ifaces[capture_iface]
            print(f"[INFO] Resolved interface {config.CAPTURE_INTERFACE} → {capture_iface.name}")
        else:
            print(f"[WARN] Interface {capture_iface} not found in conf.ifaces, passing as-is")

    print(
        f"[INFO] Starting capture — mode: {config.CAPTURE_MODE.upper()}, interface: {config.CAPTURE_INTERFACE or 'ALL'}"
    )
    get_user_public_location()

    callback = (
        switch_packet_callback if config.CAPTURE_MODE == "switch" else packet_callback
    )

    try:
        try:
            sniff(
                iface=capture_iface,
                prn=callback,
                filter="ip and (tcp or udp)",
                store=False,
                snaplen=config.CAPTURE_SNAPLEN,
                stop_filter=lambda x: not config.capture_running,
            )
        except TypeError:
            print("[WARN] snaplen not supported, capturing full packets")
            sniff(
                iface=config.CAPTURE_INTERFACE,
                prn=callback,
                filter="ip and (tcp or udp)",
                store=False,
                stop_filter=lambda x: not config.capture_running,
            )
    except PermissionError:
        print("[ERROR] Permission denied! Run as Administrator/root")
        config.capture_running = False
    except OSError as e:
        if "Npcap" in str(e) or "permission" in str(e).lower():
            print("[ERROR] Npcap/WinPcap not installed or not accessible. Install Npcap: https://nmap.org/npcap/")
        else:
            print(f"[ERROR] OS error during capture: {e}")
        config.capture_running = False
    except Exception as e:
        import traceback
        print(f"[ERROR] Capture error: {e}")
        print(f"[DEBUG] Traceback:\n{traceback.format_exc()}")
        config.capture_running = False


def save_captured_packets() -> dict:
    """Save captured packets to PCAP and convert to Parquet. Returns status dict."""
    if not config.captured_packets:
        return {"saved": False, "error": "No packets captured"}

    try:
        pcap_dir = config.DATA_DIR / "pcap"
        parquet_dir = config.DATA_DIR / "parquet"
        pcap_dir.mkdir(parents=True, exist_ok=True)
        parquet_dir.mkdir(parents=True, exist_ok=True)

        pcap_path = pcap_dir / f"{config.capture_session_name}.pcap"
        wrpcap(str(pcap_path), config.captured_packets)

        from src.parsers.scapy_parser import parse_pcap_with_scapy
        from src.transformers.json_to_parquet import write_parquet_streaming

        packets = parse_pcap_with_scapy(str(pcap_path))
        if packets:
            parquet_path = parquet_dir / f"{config.capture_session_name}.parquet"
            write_parquet_streaming(packets, str(parquet_path))
            return {
                "saved": True,
                "pcap_file": str(pcap_path),
                "parquet_file": str(parquet_path),
                "packet_count": len(config.captured_packets),
            }
        return {
            "saved": True,
            "pcap_file": str(pcap_path),
            "packet_count": len(config.captured_packets),
        }
    except Exception as e:
        return {"saved": False, "error": str(e)}


# ── Helpers ───────────────────────────────────────────────────────


def _is_internal_ip(ip_str: str) -> bool:
    if not config.CAPTURE_SUBNET:
        return is_private_ip(ip_str)
    try:
        return ipaddress.ip_address(ip_str) in ipaddress.ip_network(
            config.CAPTURE_SUBNET, strict=False
        )
    except ValueError:
        return False


def _new_device_entry(ip: str, now: float) -> dict:
    return {
        "ip": ip,
        "first_seen": now,
        "last_seen": now,
        "total_packets": 0,
        "total_bytes": 0,
        "internal_traffic_bytes": 0,
        "protocols": {},
        "external_ips": {},
        "vpn_detected": False,
        "vpn_packet_count": 0,
        "vpn_bytes": 0,
        "vpn_connections": {},
    }


def _track_vpn(src_ip, dst_ip, src_loc, dst_loc) -> bool:
    """Track VPN IPs from live capture and update stats."""
    vpn_detected = False
    stats = config.live_stats

    for ip, loc, direction, peer_ip in [
        (src_ip, src_loc, "source", dst_ip),
        (dst_ip, dst_loc, "destination", src_ip),
    ]:
        if loc.get("is_vpn"):
            vpn_detected = True
            stats["vpn_ips"].add(ip)
            config.vpn_ips.add(ip)
            if ip not in stats["vpn_details"]:
                stats["vpn_details"][ip] = {
                    "ip": ip,
                    "provider": loc.get("vpn_provider", "Unknown"),
                    "isp": loc.get("isp", "Unknown"),
                    "country": loc.get("country", "Unknown"),
                    "city": loc.get("city", "Unknown"),
                    "direction": direction,
                    "peer_ip": peer_ip,
                    "method": loc.get("vpn_method", "keyword"),
                }
    return vpn_detected


def _record_switch_vpn(
    internal_ip,
    external_ip,
    dst_port,
    protocol,
    pkt_size,
    now,
    vpn_by_ip,
    vpn_provider,
    vpn_method,
    vpn_hints,
    direction,
):
    with config.switch_device_lock:
        dev = config.switch_devices[internal_ip]
        dev["vpn_detected"] = True
        dev["vpn_packet_count"] = dev.get("vpn_packet_count", 0) + 1
        dev["vpn_bytes"] = dev.get("vpn_bytes", 0) + pkt_size

        if vpn_by_ip and vpn_provider:
            provider, method = vpn_provider, vpn_method
        elif vpn_hints:
            provider = vpn_hints[0]["protocol_hint"]
            method = f"port_{vpn_hints[0]['port']}"
        else:
            provider, method = "Unknown VPN", "heuristic"

        conn_key = f"{external_ip}:{dst_port}"
        if "vpn_connections" not in dev:
            dev["vpn_connections"] = {}
        if conn_key not in dev["vpn_connections"]:
            dev["vpn_connections"][conn_key] = {
                "external_ip": external_ip,
                "port": dst_port,
                "provider": provider,
                "method": method,
                "first_seen": now,
                "last_seen": now,
                "packets": 0,
                "bytes": 0,
            }
            alert = {
                "id": len(config.switch_vpn_alerts) + 1,
                "timestamp": now,
                "timestamp_str": datetime.fromtimestamp(now).strftime(
                    "%Y-%m-%d %H:%M:%S"
                ),
                "device_ip": internal_ip,
                "vpn_server_ip": external_ip,
                "port": dst_port,
                "protocol": protocol,
                "provider": provider,
                "method": method,
                "direction": direction,
                "severity": "HIGH" if vpn_by_ip else "MEDIUM",
            }
            config.switch_vpn_alerts.append(alert)
            if len(config.switch_vpn_alerts) > 500:
                config.switch_vpn_alerts = config.switch_vpn_alerts[-500:]
            if socketio:
                socketio.emit("switch_vpn_alert", alert)

        vc = dev["vpn_connections"][conn_key]
        vc["last_seen"] = now
        vc["packets"] += 1
        vc["bytes"] += pkt_size


def _emit_switch_packet(
    packet,
    internal_ip,
    external_ip,
    src_ip,
    dst_ip,
    src_port,
    dst_port,
    protocol,
    pkt_size,
    now,
    direction,
    is_vpn,
    threat_info=None,
    risk=None,
    vpn_explanation=None,
    vpn_confidence=0,
    vpn_classification="not_vpn",
):
    ext_loc = config.GEOIP_CACHE.get(external_ip)
    if not (ext_loc and ext_loc.get("lat")):
        return
    user_loc = get_user_public_location()
    if not user_loc:
        return

    int_loc = {
        "lat": user_loc["lat"] + random.uniform(-0.3, 0.3),
        "lon": user_loc["lon"] + random.uniform(-0.3, 0.3),
        "ip": internal_ip,
        "city": user_loc.get("city", ""),
        "country": user_loc.get("country", ""),
        "isp": "Internal",
        "is_vpn": False,
    }
    ext_loc_data = {
        "lat": ext_loc["lat"],
        "lon": ext_loc["lon"],
        "ip": external_ip,
        "city": ext_loc.get("city", ""),
        "country": ext_loc.get("country", ""),
        "isp": ext_loc.get("isp", ""),
        "is_vpn": ext_loc.get("is_vpn", False),
        "vpn_provider": ext_loc.get("vpn_provider"),
    }
    src_loc_data = int_loc if direction == "outbound" else ext_loc_data
    dst_loc_data = ext_loc_data if direction == "outbound" else int_loc

    pkt_data = {
        "timestamp": now,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": src_port,
        "dst_port": dst_port,
        "protocol": protocol,
        "src_location": src_loc_data,
        "dst_location": dst_loc_data,
        "size": pkt_size,
        "flags": str(packet[TCP].flags) if TCP in packet else None,
        "seq": packet[TCP].seq if TCP in packet else None,
        "ack": packet[TCP].ack if TCP in packet else None,
        "ttl": packet[IP].ttl,
        "id": packet[IP].id,
        "vpn_detected": is_vpn,
        "vpn_confidence": vpn_confidence,
        "vpn_classification": vpn_classification,
        "device_ip": internal_ip,
        "direction": direction,
        "risk_score": risk["score"] if risk else 0,
        "risk_level": risk["risk_level"] if risk else "none",
        "risk_reasons": risk["reasons"] if risk else [],
        "risk_breakdown": risk["breakdown"] if risk else [],
        "risk_primary_concern": risk["primary_concern"] if risk else "",
        "vpn_explanation": vpn_explanation,
        "threat_info": {
            "is_malicious": threat_info.get("is_malicious", False),
            "threat_level": threat_info.get("threat_level", "none"),
            "sources": threat_info.get("sources", []),
        } if threat_info and threat_info.get("is_malicious") else None,
    }
    if socketio:
        _throttled_emit("switch_new_packet", pkt_data)


def sanitize_device(ip: str, dev: dict) -> dict:
    """Create a JSON-safe summary of a switch device."""
    vpn_conns = []
    for conn_info in dev.get("vpn_connections", {}).values():
        geo = config.GEOIP_CACHE.get(conn_info["external_ip"])
        vpn_conns.append(
            {
                "external_ip": conn_info["external_ip"],
                "port": conn_info["port"],
                "provider": conn_info["provider"],
                "method": conn_info["method"],
                "packets": conn_info["packets"],
                "bytes": conn_info["bytes"],
                "first_seen": conn_info["first_seen"],
                "last_seen": conn_info["last_seen"],
                "geo": (
                    {
                        "lat": geo["lat"],
                        "lon": geo["lon"],
                        "city": geo.get("city", ""),
                        "country": geo.get("country", ""),
                        "isp": geo.get("isp", ""),
                    }
                    if geo and geo.get("lat")
                    else None
                ),
            }
        )

    ext_geo_samples = []
    for ext_ip, info in list(dev.get("external_ips", {}).items())[:30]:
        geo = config.GEOIP_CACHE.get(ext_ip)
        if geo and geo.get("lat"):
            ext_geo_samples.append(
                {
                    "ip": ext_ip,
                    "lat": geo["lat"],
                    "lon": geo["lon"],
                    "city": geo.get("city", ""),
                    "country": geo.get("country", ""),
                    "isp": geo.get("isp", ""),
                    "is_vpn": geo.get("is_vpn", False),
                    "vpn_provider": geo.get("vpn_provider"),
                    "packets": info["packets"],
                    "bytes": info["bytes"],
                }
            )

    return {
        "ip": ip,
        "first_seen": dev["first_seen"],
        "last_seen": dev["last_seen"],
        "total_packets": dev["total_packets"],
        "total_bytes": dev["total_bytes"],
        "internal_traffic_bytes": dev.get("internal_traffic_bytes", 0),
        "protocols": dev["protocols"],
        "external_ip_count": len(dev["external_ips"]),
        "vpn_detected": dev["vpn_detected"],
        "vpn_packet_count": dev.get("vpn_packet_count", 0),
        "vpn_bytes": dev.get("vpn_bytes", 0),
        "vpn_connections": vpn_conns,
        "ext_geo": ext_geo_samples,
    }
