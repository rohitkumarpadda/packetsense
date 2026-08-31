# 5G-PacketSense v2

> **Real-time network packet analysis with AI-powered threat detection, VPN identification, and live geolocation mapping.**

A self-hosted, browser-based network analysis platform built for 5G/LTE environments. Supports live packet capture from any interface, offline PCAP file analysis, and an agentic AI assistant that can answer questions about your traffic in plain English.

---

## Features at a Glance

| Category | Capability |
|---|---|
| **Capture** | Live NIC capture · PCAP file upload · Switch monitoring mode |
| **Analysis** | DuckDB-powered SQL analytics · Protocol breakdown · Bandwidth analysis |
| **VPN Detection** | 8-layer confidence scoring · 30+ known VPN providers · Tor exit nodes |
| **Threat Intel** | FireHOL L1-L3 · IPsum · Blocklist.de · AbuseIPDB · Spamhaus DROP |
| **Geolocation** | Fully offline GeoLite2 · DB-IP ASN · Interactive Leaflet map |
| **Behavioural** | Beaconing detection · Tunnel fingerprinting · Exfiltration patterns |
| **Risk Scoring** | Multi-factor 0–100 score per IP/packet (VPN + threat + behaviour) |
| **AI Agent** | 12-tool ReAct agent via OpenRouter free models |
| **APIs** | vpnapi.io · ipinfo.io · ip-api.com (24h per-IP cache, always active) |
| **Performance** | `FAST_MODE` in `config.py` — skip heavy offline DBs, keep online APIs |

---

## Quick Start

### 1. Clone & install dependencies

```bash
git clone https://github.com/your-user/5G-PacketSense-v2.git
cd 5G-PacketSense-v2
python -m venv .venv

# Windows
.venv\Scripts\activate

# Linux / macOS
source .venv/bin/activate

pip install -r requirements.txt
```

### 2. Install Npcap / libpcap (required for live capture)

- **Windows** → Install [Npcap](https://npcap.com/) (check "WinPcap API-compatible mode")
- **Linux** → `sudo apt install libpcap-dev`
- **macOS** → `brew install libpcap`

### 3. Configure environment

```bash
cp .env.example .env
# Edit .env with your API keys (see Configuration section below)
```

### 4. Download offline databases

```bash
# Download GeoLite2 MMDB databases into data/
# (GeoLite2-City.mmdb, GeoLite2-ASN.mmdb, GeoLite2-Country.mmdb)
# Free signup at https://dev.maxmind.com/geoip/geolite2-free-geolocation-data

# Download threat intelligence & VPN blocklists
python scripts/update_threat_intel.py
```

### 5. Run the server

```bash
# Windows — must be run as Administrator for live capture
python app.py

# Linux / macOS
sudo python app.py
```

Open **http://localhost:5000** in your browser.

---

## Configuration

All configuration is done through `.env`. Copy `.env.example` and fill in what you need:

```ini
# ── AI Agent (choose one or leave all blank for regex-fallback mode) ──
OPENROUTER_API_KEY=sk-or-v1-...     # Recommended — free models available

# ── Optional enrichment APIs ─────────────────────────────────────────
VPNAPI_IO_KEY=...                   # 1,000 lookups/day free — best VPN detection
ABUSEIPDB_API_KEY=...               # 1,000 lookups/day free
IPINFO_TOKEN=...                    # 50,000/month free without token

# ── Your location (for map centering) ────────────────────────────────
USER_LAT=28.6139
USER_LON=77.2090
USER_CITY=Delhi
USER_COUNTRY=India
```

> The three VPN enrichment APIs (vpnapi.io, ipinfo.io, ip-api.com) always run — results are **cached for 24 hours per IP** so each unique IP only makes 1 real HTTP call per day. The system also works fully offline using local MMDB databases and pre-downloaded blocklists.

### Performance tuning

Open `config.py` and set:

```python
FAST_MODE = True   # (default) Skip heavy offline DB scans — best for live capture
FAST_MODE = False  # Full pipeline — use for PCAP deep analysis, no real-time pressure
```

| `FAST_MODE` | Skipped | Always runs |
|---|---|---|
| `True` | FireHOL/IPsum/Blocklist.de · AbuseIPDB per-packet · Behavioural analysis | MMDB geo · VPN keyword/ASN · X4BNet/Tor IP lists · **All 3 online APIs** |
| `False` | Nothing | Full pipeline |

---

## Offline Databases (required)

Place these files in the `data/` directory:

| File | Source | Purpose |
|---|---|---|
| `GeoLite2-City.mmdb` | MaxMind (free signup) | IP → lat/lon, city, country |
| `GeoLite2-ASN.mmdb` | MaxMind (free signup) | IP → ASN, ISP/org name |
| `GeoLite2-Country.mmdb` | MaxMind (free signup) | Country-level fallback |
| `dbip-asn-lite.mmdb` | DB-IP (free download) | Secondary ASN for dual-ASN validation |

Run `python scripts/update_threat_intel.py` once to download:
- FireHOL Level 1–3 blocklists
- IPsum aggregated feed (30+ sources)
- Blocklist.de (SSH, mail, apache, bruteforce)
- X4BNet VPN IP ranges
- Tor exit node list
- AbuseIPDB public blacklist

---

## Usage Modes

### Live Capture

1. Click **Start Capture** in the dashboard
2. Select a network interface
3. Packets appear on the map in real time — VPN and threat-flagged IPs are highlighted

### PCAP Analysis

1. Click **Upload PCAP** and select a `.pcap` or `.pcapng` file
2. The file is parsed with Scapy/PyShark and loaded into DuckDB
3. Use the **Query** tab or **AI Agent** to analyse the data

### Switch Monitoring Mode

Designed for 5G/LTE base station environments where the monitoring device sniffs traffic from an upstream switch port. Set `CAPTURE_MODE=switch` in `config.py` and point it at the right interface.

---

## Project Structure

```
5G-PacketSense-v2/
├── app.py                  # Flask entry point — wires everything together
├── config.py               # Centralized settings & shared runtime state
├── requirements.txt
├── .env.example
│
├── routes/
│   ├── api.py              # All REST /api/* endpoints
│   ├── agent.py            # AI agent blueprint (ReAct loop + 12 tools)
│   └── ws.py               # WebSocket event handlers (SocketIO)
│
├── services/
│   ├── capture.py          # Packet capture engine (local + switch modes)
│   ├── geo.py              # Offline GeoIP/ASN resolution (MMDB)
│   ├── vpn.py              # 8-layer VPN detection with confidence scoring
│   ├── vpn_api.py          # External VPN API enrichment (vpnapi.io, ipinfo.io, ip-api.com)
│   ├── behaviour.py        # Behavioural analysis (beaconing, tunnels, exfil)
│   ├── threat_intel.py     # Offline IP reputation engine (FireHOL, IPsum, etc.)
│   └── abuseipdb.py        # AbuseIPDB integration (online + offline blacklist)
│
├── src/
│   ├── agents/
│   │   └── llm_client.py   # LLM client (OpenRouter / Ollama / Anthropic / OpenAI)
│   ├── parsers/
│   │   └── scapy_parser.py # PCAP → structured dict parser
│   ├── query/
│   │   └── sql_executor.py # DuckDB query execution
│   └── transformers/       # Data transformation utilities
│
├── scripts/
│   └── update_threat_intel.py  # Pre-deployment database downloader
│
├── static/
│   └── index.html          # Single-page frontend (Leaflet + vanilla JS)
│
└── data/                   # Runtime databases (not committed to git)
    ├── GeoLite2-City.mmdb
    ├── GeoLite2-ASN.mmdb
    ├── GeoLite2-Country.mmdb
    ├── dbip-asn-lite.mmdb
    ├── threat_intel/       # FireHOL, IPsum, Blocklist.de files
    └── vpn_lists/          # X4BNet VPN ranges, Tor exit nodes
```

---

## Tech Stack

| Layer | Technology |
|---|---|
| Backend | Python 3.11+, Flask, Flask-SocketIO |
| Packet capture | Scapy, PyShark |
| Analytics engine | DuckDB (in-process SQL, up to 8 GB RAM) |
| Geolocation | maxminddb, GeoLite2, DB-IP MMDB |
| Frontend | Vanilla JS, Leaflet.js, Stadia Maps tiles |
| AI Agent | OpenRouter (free models) via OpenAI-compatible API |
| Data format | Parquet (PyArrow, Snappy compression) |

---

## Requirements

- Python **3.11+**
- **Windows**: Npcap installed, run as **Administrator**
- **Linux/macOS**: `libpcap`, run with `sudo`
- ~500 MB disk for offline databases
- 2 GB RAM minimum (8 GB+ recommended for large PCAPs)

---

## See Also

- [`WORKFLOW.md`](./WORKFLOW.md) — detailed data flow, VPN scoring, risk model, and AI agent internals
- [`.env.example`](./.env.example) — annotated configuration reference
- [OpenRouter free models](https://openrouter.ai/models?supported_parameters=free) — for AI agent model selection
