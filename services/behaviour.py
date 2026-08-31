"""
services/behaviour.py — Offline traffic behavioural analysis engine.

Detects VPN tunnels, beaconing, data exfiltration, and anomalous traffic
patterns by analysing per-device flow statistics. No network calls are made.

Detection methods:
  - Packet size distribution analysis (VPN MTU clamping)
  - Connection duration patterns (long-lived tunnels)
  - Port diversity scoring (tunnel = low diversity)
  - Beaconing detection (regular-interval C2-like connections)
  - Protocol ratio anomalies (unusual UDP:TCP ratios)
  - Bytes-per-flow analysis (bulk data exfiltration)
"""

import math
import time
from collections import defaultdict
from dataclasses import dataclass, field

import config


@dataclass
class FlowStats:
    """Per-flow (src→dst:port) statistics accumulator."""
    packets: int = 0
    total_bytes: int = 0
    first_seen: float = 0.0
    last_seen: float = 0.0
    packet_sizes: list = field(default_factory=list)
    inter_arrival_times: list = field(default_factory=list)
    _last_packet_time: float = 0.0

    MAX_SAMPLES: int = 200  # cap stored samples to bound memory

    def record_packet(self, size: int, timestamp: float):
        self.packets += 1
        self.total_bytes += size
        if self.first_seen == 0:
            self.first_seen = timestamp
        self.last_seen = timestamp
        if len(self.packet_sizes) < self.MAX_SAMPLES:
            self.packet_sizes.append(size)
        if self._last_packet_time > 0 and len(self.inter_arrival_times) < self.MAX_SAMPLES:
            iat = timestamp - self._last_packet_time
            if iat > 0:
                self.inter_arrival_times.append(iat)
        self._last_packet_time = timestamp

    @property
    def duration(self) -> float:
        return max(self.last_seen - self.first_seen, 0.001)

    @property
    def avg_packet_size(self) -> float:
        return self.total_bytes / max(self.packets, 1)

    @property
    def bytes_per_second(self) -> float:
        return self.total_bytes / self.duration


class DeviceProfile:
    """Aggregated behavioural profile for a single internal device."""

    def __init__(self, device_ip: str):
        self.device_ip = device_ip
        self.flows: dict[str, FlowStats] = {}  # key: "dst_ip:dst_port:proto"
        self.dst_ips: set[str] = set()
        self.dst_ports: defaultdict[int, int] = defaultdict(int)
        self.protocols: defaultdict[str, int] = defaultdict(int)
        self.total_packets: int = 0
        self.total_bytes: int = 0
        self.first_seen: float = 0.0
        self.last_seen: float = 0.0

    def record_packet(
        self, dst_ip: str, dst_port: int, protocol: str,
        size: int, timestamp: float
    ):
        self.total_packets += 1
        self.total_bytes += size
        if self.first_seen == 0:
            self.first_seen = timestamp
        self.last_seen = timestamp

        self.dst_ips.add(dst_ip)
        self.dst_ports[dst_port] += 1
        self.protocols[protocol] += 1

        flow_key = f"{dst_ip}:{dst_port}:{protocol}"
        if flow_key not in self.flows:
            self.flows[flow_key] = FlowStats()
        self.flows[flow_key].record_packet(size, timestamp)


class BehaviourAnalyzer:
    """Main behavioural analysis engine. Maintains per-device profiles
    and computes anomaly scores on demand.
    """

    def __init__(self):
        self.profiles: dict[str, DeviceProfile] = {}

    def record_packet(
        self, src_ip: str, dst_ip: str, dst_port: int,
        protocol: str, size: int, timestamp: float
    ):
        """Record a packet for behavioural profiling."""
        if src_ip not in self.profiles:
            self.profiles[src_ip] = DeviceProfile(src_ip)
        self.profiles[src_ip].record_packet(
            dst_ip, dst_port, protocol, size, timestamp
        )

    def analyze_device(self, device_ip: str) -> dict:
        """Compute full behavioural analysis for a device."""
        profile = self.profiles.get(device_ip)
        if not profile or profile.total_packets < 10:
            return self._empty_analysis(device_ip)

        vpn_score = self._vpn_tunnel_score(profile)
        beacon_score = self._beaconing_score(profile)
        exfil_score = self._exfiltration_score(profile)
        anomaly_score = self._composite_anomaly_score(
            vpn_score, beacon_score, exfil_score
        )

        return {
            "device_ip": device_ip,
            "total_packets": profile.total_packets,
            "total_bytes": profile.total_bytes,
            "unique_destinations": len(profile.dst_ips),
            "unique_ports": len(profile.dst_ports),
            "flow_count": len(profile.flows),
            "duration": profile.last_seen - profile.first_seen,
            "scores": {
                "vpn_tunnel": round(vpn_score, 1),
                "beaconing": round(beacon_score, 1),
                "data_exfiltration": round(exfil_score, 1),
                "composite_anomaly": round(anomaly_score, 1),
            },
            "classifications": self._classify(
                vpn_score, beacon_score, exfil_score
            ),
            "top_flows": self._top_flows(profile),
        }

    def get_summary(self) -> dict:
        """Get overall summary of all tracked devices."""
        suspicious = []
        for ip, profile in self.profiles.items():
            if profile.total_packets < 10:
                continue
            analysis = self.analyze_device(ip)
            if analysis["scores"]["composite_anomaly"] > 40:
                suspicious.append(analysis)
        suspicious.sort(
            key=lambda a: a["scores"]["composite_anomaly"], reverse=True
        )
        return {
            "total_devices": len(self.profiles),
            "suspicious_devices": len(suspicious),
            "suspicious": suspicious[:20],
        }

    def _vpn_tunnel_score(self, profile: DeviceProfile) -> float:
        """Score 0-100 indicating likelihood of VPN tunnel usage."""
        score = 0.0

        # Check for dominant single-destination flows (tunnel indicator)
        if profile.flows:
            top_flow = max(
                profile.flows.values(), key=lambda f: f.total_bytes
            )
            flow_ratio = top_flow.total_bytes / max(profile.total_bytes, 1)
            if flow_ratio > 0.8:
                score += 25  # >80% traffic to one flow = likely tunnel
            elif flow_ratio > 0.6:
                score += 15

            # Long-lived connection
            if top_flow.duration > 300:  # >5 min
                score += 15
            if top_flow.duration > 1800:  # >30 min
                score += 10

            # Packet size distribution (VPN = bimodal, MTU-clamped)
            if len(top_flow.packet_sizes) >= 10:
                sizes = top_flow.packet_sizes
                avg = sum(sizes) / len(sizes)
                std = _std_dev(sizes)
                # VPN tunnels show high avg sizes (close to MTU)
                if avg > 800:
                    score += 10
                # Low variance = consistent encryption overhead
                if 0 < std < 100 and avg > 500:
                    score += 10
                # Check for MTU clamping (many packets near 1400-1500)
                mtu_count = sum(1 for s in sizes if 1300 <= s <= 1500)
                if mtu_count / len(sizes) > 0.3:
                    score += 15

        # Low port diversity with high traffic = tunnel
        if len(profile.dst_ports) <= 3 and profile.total_bytes > 100000:
            score += 10

        # Protocol ratio: mostly UDP with large volume = WireGuard/OpenVPN-UDP
        udp_pct = profile.protocols.get("UDP", 0) / max(profile.total_packets, 1)
        if udp_pct > 0.9 and profile.total_bytes > 50000:
            score += 10

        return min(score, 100)

    def _beaconing_score(self, profile: DeviceProfile) -> float:
        """Score 0-100 for C2-like beaconing behaviour."""
        score = 0.0

        for flow in profile.flows.values():
            if len(flow.inter_arrival_times) < 5:
                continue
            iats = flow.inter_arrival_times
            avg_iat = sum(iats) / len(iats)
            std_iat = _std_dev(iats)

            if avg_iat > 0:
                # Coefficient of variation: low = regular intervals = beaconing
                cv = std_iat / avg_iat
                if cv < 0.1 and flow.packets > 20:
                    score = max(score, 80)  # very regular
                elif cv < 0.2 and flow.packets > 10:
                    score = max(score, 60)
                elif cv < 0.3 and flow.packets > 10:
                    score = max(score, 40)

        return min(score, 100)

    def _exfiltration_score(self, profile: DeviceProfile) -> float:
        """Score 0-100 for potential data exfiltration."""
        score = 0.0

        for flow in profile.flows.values():
            # Large sustained outbound transfer
            if flow.total_bytes > 10_000_000 and flow.duration > 60:
                score = max(score, 60)
            elif flow.total_bytes > 1_000_000 and flow.duration > 30:
                score = max(score, 40)

            # High bytes-per-second sustained transfer
            bps = flow.bytes_per_second
            if bps > 500_000 and flow.duration > 30:
                score = max(score, 50)

        # Few destinations but very high total volume
        if len(profile.dst_ips) <= 3 and profile.total_bytes > 50_000_000:
            score += 20

        return min(score, 100)

    def _composite_anomaly_score(
        self, vpn: float, beacon: float, exfil: float
    ) -> float:
        """Weighted composite of all behavioural scores."""
        return min(vpn * 0.4 + beacon * 0.3 + exfil * 0.3, 100)

    def _classify(
        self, vpn: float, beacon: float, exfil: float
    ) -> list[str]:
        """Return list of classification labels that exceed thresholds."""
        labels = []
        if vpn >= 60:
            labels.append("vpn_tunnel_likely")
        elif vpn >= 40:
            labels.append("vpn_tunnel_possible")
        if beacon >= 60:
            labels.append("beaconing_detected")
        elif beacon >= 40:
            labels.append("beaconing_possible")
        if exfil >= 60:
            labels.append("data_exfiltration_likely")
        elif exfil >= 40:
            labels.append("data_exfiltration_possible")
        if not labels:
            labels.append("normal")
        return labels

    def _top_flows(self, profile: DeviceProfile, n: int = 5) -> list[dict]:
        """Return top N flows by byte volume."""
        sorted_flows = sorted(
            profile.flows.items(),
            key=lambda kv: kv[1].total_bytes,
            reverse=True,
        )[:n]
        result = []
        for key, flow in sorted_flows:
            parts = key.split(":")
            result.append({
                "dst_ip": parts[0] if len(parts) >= 1 else "?",
                "dst_port": int(parts[1]) if len(parts) >= 2 else 0,
                "protocol": parts[2] if len(parts) >= 3 else "?",
                "packets": flow.packets,
                "bytes": flow.total_bytes,
                "duration": round(flow.duration, 1),
                "avg_packet_size": round(flow.avg_packet_size, 1),
            })
        return result

    def _empty_analysis(self, device_ip: str) -> dict:
        return {
            "device_ip": device_ip,
            "total_packets": 0, "total_bytes": 0,
            "unique_destinations": 0, "unique_ports": 0,
            "flow_count": 0, "duration": 0,
            "scores": {
                "vpn_tunnel": 0, "beaconing": 0,
                "data_exfiltration": 0, "composite_anomaly": 0,
            },
            "classifications": ["insufficient_data"],
            "top_flows": [],
        }


def _std_dev(values: list) -> float:
    """Compute population standard deviation."""
    if len(values) < 2:
        return 0.0
    mean = sum(values) / len(values)
    variance = sum((x - mean) ** 2 for x in values) / len(values)
    return math.sqrt(variance)
