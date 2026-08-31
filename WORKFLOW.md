# 5G-PacketSense v2 — System Workflow & Architecture

This document explains how data flows through the system, how each analysis engine works, and how the AI agent reasons about your network traffic.

---

## Table of Contents

1. [High-Level Architecture](#1-high-level-architecture)
2. [Data Flow: Live Capture](#2-data-flow-live-capture)
3. [Data Flow: PCAP Analysis](#3-data-flow-pcap-analysis)
4. [VPN Detection Engine](#4-vpn-detection-engine)
5. [Risk Scoring Engine](#5-risk-scoring-engine)
6. [Threat Intelligence Engine](#6-threat-intelligence-engine)
7. [Behavioural Analysis Engine](#7-behavioural-analysis-engine)
8. [Geolocation Pipeline](#8-geolocation-pipeline)
9. [AI Agent (PacketSense AI)](#9-ai-agent-packetsense-ai)
10. [Frontend & Real-Time Updates](#10-frontend--real-time-updates)

---

## 1. High-Level Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│                        Browser (port 5000)                       │
│  Leaflet Map · Stats Panel · AI Chat · PCAP Upload · Controls    │
└────────────────────────┬──────────────────────────────┬─────────┘
                         │ HTTP REST                     │ WebSocket
                         ▼                               ▼
┌──────────────────────────────────────────────────────────────────┐
│                     Flask + Flask-SocketIO                       │
│  routes/api.py  ──  routes/agent.py  ──  routes/ws.py           │
└──────┬──────────────────────────────────────────────────────────┘
       │
       ├── services/capture.py      ← Scapy packet sniffer
       ├── services/geo.py          ← MMDB GeoIP/ASN lookup
       ├── services/vpn.py          ← Multi-layer VPN detector
       ├── services/vpn_api.py      ← External API enrichment
       ├── services/behaviour.py    ← Behavioural pattern engine
       ├── services/threat_intel.py ← FireHOL/IPsum/Blocklist.de
       ├── services/abuseipdb.py    ← AbuseIPDB integration
       │
       ├── config.py                ← Shared runtime state & caches
       │
       └── data/                    ← Offline databases
           ├── GeoLite2-*.mmdb
           ├── dbip-asn-lite.mmdb
           ├── threat_intel/
           └── vpn_lists/
```

---

## 2. Data Flow: Live Capture

```
Network Interface (NIC)
        │
        │  Scapy sniff()
        ▼
services/capture.py — per-packet callback
        │
        ├─► Extract: src_ip, dst_ip, protocol, ports, length, TTL
        │
        ├─► services/geo.py
        │       └─► MMDB lookup → lat, lon, city, country, ASN, org
        │
        ├─► services/vpn.py
        │       └─► Signals 1–6: keyword / ASN / IP ranges / Tor
        │               └─► Signal 7: vpnapi.io + ipinfo.io + ip-api.com
        │                       (24h per-IP cache — HTTP only on first new IP)
        │
        ├─► services/threat_intel.py        ← SKIPPED in FAST_MODE
        │       └─► Binary-search blocklist → is_malicious, threat_level
        │
        ├─► services/abuseipdb.py           ← SKIPPED in FAST_MODE
        │       └─► Abuse confidence score (online API or offline blacklist)
        │
        ├─► services/behaviour.py           ← SKIPPED in FAST_MODE
        │       └─► Per-device flow stats → tunnel / beaconing / exfil signals
        │
        ├─► compute_risk_score()
        │       └─► Weighted multi-factor → 0–100 risk score + breakdown
        │
        ├─► config.live_stats (in-memory ring buffer, 5000 packets)
        │
        └─► SocketIO emit (throttled, 500ms batches)
                └─► Frontend: map marker + stats update
```

**Emission throttle**: Packets are buffered for 500ms and emitted as a single batch to avoid overwhelming the WebSocket connection on high-traffic interfaces.

---

## 2a. FAST_MODE — Performance Switch

Controlled by `FAST_MODE` in `config.py` (default: `True`). Designed for live capture on modest hardware.

| Signal / Engine | `FAST_MODE = True` | `FAST_MODE = False` |
|---|---|---|
| MMDB GeoIP/ASN | ✅ | ✅ |
| VPN keyword + ASN matching | ✅ | ✅ |
| X4BNet + Tor IP range lists | ✅ | ✅ |
| Protocol heuristics | ✅ | ✅ |
| vpnapi.io + ipinfo.io + ip-api.com | ✅ (24h cache) | ✅ (24h cache) |
| API consensus bonus scoring | ✅ | ✅ |
| FireHOL / IPsum / Blocklist.de scan | ❌ skipped | ✅ |
| AbuseIPDB per-packet blacklist | ❌ skipped | ✅ |
| Threat intel VPN correlation | ❌ skipped | ✅ |
| Behavioural analysis (beaconing/exfil) | ❌ skipped | ✅ |

> **Why all 3 online APIs still run in FAST_MODE**: each API caches results for 24 hours per IP. On a typical capture you'll see 20–50 unique external IPs, so at most 150 total HTTP calls ever — every repeat packet to a known IP is a free dictionary lookup.


---

## 3. Data Flow: PCAP Analysis

```
User uploads .pcap / .pcapng
        │
        ▼
src/parsers/scapy_parser.py
        │  Reads with Scapy, extracts all fields
        ▼
pandas DataFrame → PyArrow → Parquet (Snappy compressed)
        │
        ▼
DuckDB in-memory database (config.conn)
        │  SQL analytics on parquet — up to 8 GB RAM
        │
        ├─► /api/stats     → counts, protocol distribution
        ├─► /api/map_data  → IPs enriched through same geo/vpn/threat pipeline
        ├─► /api/query     → natural-language → SQL (via AI agent or regex)
        └─► /api/agent/*   → AI agent tools can query this DuckDB instance
```

PCAP mode uses the same analysis pipeline as live capture — every IP in the file is still run through geolocation, VPN detection, and threat intelligence.

---

## 4. VPN Detection Engine

`services/vpn.py` accumulates evidence across **7 independent signals**. All signals that apply are summed; nothing short-circuits. The final confidence score is capped at 100.

```
IP address
    │
    ├── Signal 0: Cache lookup (skip re-analysis for known IPs)
    │
    ├── Signal 1: ISP/Org keyword matching
    │       30+ VPN providers (NordVPN, ExpressVPN, Mullvad, Proton…)
    │       CDN whitelist prevents false positives on Cloudflare, Akamai
    │       Weight: 35 pts
    │
    ├── Signal 2: Known VPN ASN database
    │       Curated list of ASNs exclusively operated by VPN providers
    │       Weight: 40 pts
    │
    ├── Signal 3: Dual-ASN cross-validation
    │       Compare GeoLite2-ASN vs DB-IP — agreement on VPN org adds weight
    │       Weight: 15–20 pts
    │
    ├── Signal 4: IP range lists (pre-downloaded)
    │       X4BNet: ~1M IPv4 ranges, corroborated by ISP: 45 pts / uncorroborated: 15 pts
    │       Tor exit nodes: 50 pts
    │
    ├── Signal 5: AbuseIPDB flags          ← FULL MODE only
    │       VPN/proxy flag: 20 pts · Tor flag: 25 pts · offline blacklist: 20 pts
    │
    ├── Signal 6: Threat intel correlation ← FULL MODE only
    │       IP in VPN range + in FireHOL/IPsum → corroborating weight: 20 pts
    │
    └── Signal 7: External API consensus   ← ALWAYS (24h per-IP cache)
            vpnapi.io:  VPN/proxy flag: 40–55 pts · Tor flag: 55 pts
            ipinfo.io:  VPN flag: 40 pts · relay: 25 pts · Tor: 45 pts
            ip-api.com: proxy flag: 35 pts
            Consensus bonus — 2 APIs agree: +20 pts · all 3 agree: +35 pts
```

### Classification thresholds

| Score | Label | Meaning |
|---|---|---|
| 0–15 | `not_vpn` | Clean — no meaningful signals |
| 16–35 | `vpn_suspect` | Weak signals, monitor |
| 36–60 | `vpn_likely` | Strong evidence of VPN |
| 61–100 | `vpn_confirmed` | Near-certain VPN/proxy/Tor |

---

## 5. Risk Scoring Engine

`services/capture.py → compute_risk_score()` produces a **0–100 risk score** per packet/IP by combining all available signals:

```
Risk score = Σ(weighted factors, capped at 100)

VPN factors:
  vpn_confirmed      +25     vpn_likely         +15     vpn_suspect        +5
  vpn_protocol_strong +10    vpn_protocol_weak  +5

Threat Intel factors:
  threat_critical    +50     threat_high        +35
  threat_medium      +20     threat_low         +10

Cross-correlation:
  vpn + critical threat  +20   (VPN tunneling to C&C/malware host)
  vpn + high threat      +10

Behavioural:
  exfil pattern      +25     beaconing          +20     tunnel             +15

Ports:
  dark_web_ports     +20     suspicious_ports   +15

AbuseIPDB (when configured):
  abuse > 75%        +30     abuse 50–75%       +20     abuse 25–50%       +10
```

### Risk levels

| Score | Level | Dashboard colour |
|---|---|---|
| 75–100 | Critical | Red |
| 50–74 | High | Orange |
| 25–49 | Medium | Yellow |
| 1–24 | Low | Blue |
| 0 | None | Grey |

---

## 6. Threat Intelligence Engine

`services/threat_intel.py` loads blocklists into memory at startup and uses **binary search (O log n)** for fast IP lookups.

### Data sources (downloaded by `scripts/update_threat_intel.py`)

| Source | Type | Content |
|---|---|---|
| FireHOL Level 1 | CIDR ranges | Malware C&C, hijacked IP blocks |
| FireHOL Level 2 | CIDR ranges | Known attackers, spammers |
| FireHOL Level 3 | CIDR ranges | Reputation-risk IPs |
| Spamhaus DROP/EDROP | CIDR ranges | Stolen/hijacked address space |
| DShield | CIDR ranges | Top 20 attacking netblocks |
| IPsum | Single IPs | Aggregated from 30+ threat feeds |
| Blocklist.de SSH | Single IPs | Active SSH brute-force sources |
| Blocklist.de Mail | Single IPs | Mail server attackers |
| Blocklist.de Apache | Single IPs | Web server attackers |
| AbuseIPDB blacklist | Single IPs | 100% confidence abuse IPs |

### Threat levels

IPs matched in Level 1 sources or multiple Level 2 sources → **critical**  
Level 2 sources → **high**  
Level 3 / single Blocklist.de → **medium**  
Anything else → **low**

---

## 7. Behavioural Analysis Engine

`services/behaviour.py` — fully offline, runs per-device across all observed flows.

### Detection methods

**VPN tunnel fingerprinting**
- Packets consistently near MTU size (1400–1480 bytes for WireGuard, 1438 for OpenVPN)
- Low port diversity on the device (tunnels route all traffic through one port)
- Long-lived connections with consistent inter-packet timing

**Beaconing detection**
- Regular inter-arrival times suggest automated C2 check-ins
- Low variance in packet sizing
- Fires after 10+ packets to avoid false positives

**Data exfiltration**
- Abnormally high bytes-per-flow ratio
- Sustained high bytes/second to a single destination
- Combined with non-standard ports or VPN signals

### Signals fed into risk scoring

Each behavioural flag adds to the risk score (`+15` tunnel, `+20` beaconing, `+25` exfil) and is surfaced in the AI agent's `scan_anomalies` tool.

---

## 8. Geolocation Pipeline

`services/geo.py` — **100% offline**, no external API calls.

```
IP address
    │
    ├── Private IP check (RFC1918/link-local/loopback) → skip
    │
    ├── GeoLite2-City.mmdb
    │       → latitude, longitude, city, country, ISO code
    │
    ├── GeoLite2-ASN.mmdb
    │       → ASN number, organization name
    │
    ├── DB-IP ASN (dbip-asn-lite.mmdb)
    │       → Secondary org name for dual-ASN VPN validation
    │
    └── VPN detection with geo context
            → is_vpn, vpn_provider, confidence, classification
```

Results are cached in `config.GEOIP_CACHE` (LRU eviction at 50,000 entries, ~2.5 MB).

For **switch mode** or when the user's own public IP can't be determined, `USER_LAT`/`USER_LON` from `.env` are used to centre the map.

---

## 9. AI Agent (PacketSense AI)

`routes/agent.py` — a multi-step **ReAct** (Reason + Act) agent backed by OpenRouter free models.

### Model cascade

The agent tries models in order, falling back to the next if one fails or returns an error. NVIDIA and MiniMax models are tried first to avoid Google AI Studio shared-pool rate limits:

```
nvidia/nemotron-3.5-lightning:free    ← Primary (NVIDIA pool, 1M ctx, rarely rate-limited)
    → minimax/minimax-m3:free         ← Separate MiniMax pool, 1M ctx
        → nvidia/nemotron-3-super-120b-a12b:free
            → google/gemma-4-31b-it:free    ← Google (secondary — shared pool 429s)
                → google/gemma-4-26b-a4b-it:free
                    → openrouter/free       ← Auto-picks any available free model
                        → regex-fallback    ← No LLM needed
```

### ReAct loop

Each user message triggers up to `MAX_AGENT_STEPS = 3` LLM calls:

```
User message
    │
    ▼
LLM call → JSON response:
{
  "tool": "scan_anomalies",
  "params": {},
  "brief_plan": "Scan all traffic for suspicious patterns",
  "needs_followup": true       ← chain to next step
}
    │
    ▼
Execute tool → get result
    │
    ▼ (if needs_followup)
LLM call with result → next tool...
    │
    ▼ (needs_followup: false)
Final answer rendered to user
```

### Available tools

**Core data tools**
- `get_stats` — packet counts, bytes, protocol distribution, VPN count
- `get_vpn` — all VPN IPs with provider name and confidence
- `get_top_talkers` — top IPs by traffic volume
- `check_ip` — full geo + VPN + threat analysis for one IP
- `get_flows` — active src→dst network flows

**Analysis tools**
- `analyze_traffic` — protocol mix, port patterns, packet size distribution
- `get_threat_summary` — threat overview: severity counts, top threat IPs
- `get_vpn_signals` — full signal breakdown for one IP (all 8 layers)
- `scan_anomalies` — proactive scan: high-risk IPs, VPN+threat correlation
- `get_bandwidth_analysis` — bandwidth by protocol/port, top consumers

**Map tools**
- `inject_packet` — plot a custom src→dst packet on the live map

**Utility tools**
- `explain_packet` — decode raw packet fields into plain English
- `general_answer` — direct factual answer, no live data needed

### Regex fallback

When no LLM is available, common questions are matched by keyword patterns and answered using live data directly — the agent never crashes the dashboard.

---

## 10. Frontend & Real-Time Updates

`static/index.html` — a single-page application, no build step required.

### Real-time path

```
SocketIO event: "new_packet"
    │
    ▼
addMarker(pkt) — place coloured dot on Leaflet map
    │
    ├── Green  → normal traffic
    ├── Yellow → VPN suspect / low risk
    ├── Orange → VPN confirmed / medium-high risk
    └── Red    → critical threat / Tor / exfil
```

### Double-buffer cycle system

The map uses a **2-minute cycle** to prevent marker accumulation on long captures:
- All markers for the current 2-minute window land on a `displayLayerGroup`
- At cycle end, the layer is cleared and a fresh cycle starts
- This keeps the map readable without losing live situational awareness

### Map tiles

Uses **Stadia Maps** `alidade_smooth_dark` — a free, dark-themed tile layer with no API key required.

### Key UI sections

| Panel | Purpose |
|---|---|
| Map | Live packet geolocation, VPN/threat markers |
| Stats bar | Total packets, unique IPs, VPN count, bandwidth |
| Top Talkers | Most active IPs by byte volume |
| VPN panel | All detected VPN IPs with confidence + provider |
| Threat panel | High-risk IPs from blocklists |
| AI Agent | Natural-language chat with 12 live-data tools |
| PCAP upload | Drop zone for offline analysis |
| Query | Natural-language → SQL → results table |
