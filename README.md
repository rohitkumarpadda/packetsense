# VPN-PacketSense v2

VPN-PacketSense v2 is a self-hosted network observability, packet analysis, and security detection platform. It provides real-time packet capture, switch port monitoring, offline PCAP forensics with DuckDB SQL analytics, hybrid VPN and proxy detection, threat intelligence correlation, behavioral anomaly heuristics, and an embedded ReAct AI assistant driven primarily by Ollama running the phi4-mini model.

---

## Table of Contents

- [System Architecture](#system-architecture)
- [Directory and File Structure](#directory-and-file-structure)
- [Primary AI Assistant (Ollama & phi4-mini)](#primary-ai-assistant-ollama--phi4-mini)
  - [Model Specification & Rationale](#model-specification--rationale)
  - [SSH-Tunnelled Remote Deployment](#ssh-tunnelled-remote-deployment)
  - [Runtime Optimizations for phi4-mini](#runtime-optimizations-for-phi4-mini)
  - [Fallback Cascade](#fallback-cascade)
- [Hybrid Geolocation and VPN Detection](#hybrid-geolocation-and-vpn-detection)
  - [Geolocation Resolution](#geolocation-resolution)
  - [8-Layer VPN Detection Engine](#8-layer-vpn-detection-engine)
  - [External Enrichment APIs](#external-enrichment-apis)
- [Risk Scoring Model](#risk-scoring-model)
  - [Factor Weight Distribution](#factor-weight-distribution)
  - [Severity Thresholds](#severity-thresholds)
- [Threat Intelligence and Behavioral Engines](#threat-intelligence-and-behavioral-engines)
  - [Threat Intelligence Feeds](#threat-intelligence-feeds)
  - [Behavioral Analytics](#behavioral-analytics)
- [Operational Modes](#operational-modes)
  - [Live NIC Capture](#live-nic-capture)
  - [Switch Mirror (SPAN) Monitoring](#switch-mirror-span-monitoring)
  - [PCAP/PCAPNG Forensics with DuckDB](#pcappcapng-forensics-with-duckdb)
- [Installation and Setup](#installation-and-setup)
  - [Prerequisites](#prerequisites)
  - [Environment Configuration](#environment-configuration)
  - [Offline Databases and Threat Intel Download](#offline-databases-and-threat-intel-download)
  - [Running the Application](#running-the-application)
- [Configuration and Performance Tuning](#configuration-and-performance-tuning)
  - [Performance Mode (FAST_MODE)](#performance-mode-fast_mode)
  - [Cache and Memory Bounds](#cache-and-memory-bounds)
- [REST API Reference](#rest-api-reference)
- [WebSocket Telemetry](#websocket-telemetry)
- [AI Agent Tools](#ai-agent-tools)
- [Test Suite](#test-suite)
- [Troubleshooting](#troubleshooting)
- [License](#license)

---

## System Architecture

```
+-----------------------------------------------------------------------------------+
|                            Web Interface (Port 5000)                              |
|   Leaflet Map  |  Live Telemetry  |  Top Talkers  |  Switch Table  |  AI Chat     |
+-----------------------------------------+-----------------------------------------+
                                          |
                        +-----------------+-----------------+
                        | REST Requests                     | WebSocket Push
                        v                                   v
+-----------------------------------------------------------------------------------+
|                         Flask Application Core (app.py)                           |
|   routes/api.py (REST)      routes/agent.py (AI Agent)      routes/ws.py (Socket) |
+--------------------+-----------------------------+--------------------+-----------+
                     |                             |                    |
     +---------------+---------------+             |                    |
     v                               v             v                    v
+-------------------------+ +---------------------+ +-------------------------------+
|  Capture Engine         | |  Primary AI Engine  | |  Analytics Engine             |
|  services/capture.py    | |  Ollama (phi4-mini) | |  DuckDB SQL + Parquet         |
|  Scapy Sniffer Thread   | |  Local or Tunnelled | |  src/parsers/scapy_parser.py  |
|  Local & Switch Modes   | |  Fallback: OR/Regex | |  src/query/sql_executor.py    |
+------------+------------+ +----------+----------+ +---------------+---------------+
             |                         |                            |
             +-------------------------+----------------------------+
                                       |
                                       v
+-----------------------------------------------------------------------------------+
|                        Enrichment & Detection Pipeline                            |
|                                                                                   |
|  Offline Core:                                                                    |
|  - services/geo.py          MaxMind GeoLite2 & DB-IP ASN MMDB readers             |
|  - services/vpn.py          Keywords, ASNs, Dual-ASN cross-check, IP ranges, Tor  |
|  - services/threat_intel.py Binary-search matching (FireHOL, IPsum, Blocklist.de) |
|  - services/behaviour.py    MTU fingerprinting, C2 beaconing, exfiltration        |
|                                                                                   |
|  Online Enrichment Layer (24h per-IP cache):                                      |
|  - services/vpn_api.py      vpnapi.io, ipinfo.io, ip-api.com (consensus scoring) |
|  - services/abuseipdb.py    AbuseIPDB reputation API + offline 100% blacklist     |
+--------------------------------------+--------------------------------------------+
                                       |
                                       v
+-----------------------------------------------------------------------------------+
|                          Storage and State Management                             |
|  - config.py                Central runtime state, circular buffers, LRU caches   |
|  - data/parquet/            Converted Parquet captures (Snappy-compressed)        |
|  - data/pcap/               Raw captured PCAP storage                             |
|  - data/threat_intel/       Local blocklists and MMDB files                       |
|  - data/vpn_lists/          Pre-downloaded X4BNet VPN subnets and Tor exit nodes  |
+-----------------------------------------------------------------------------------+
```

---

## Directory and File Structure

```
VPN-PacketSense-v2/
|-- app.py                      # Flask entry point and SocketIO initialization
|-- config.py                   # Centralized configuration, cache limits, and shared state
|-- requirements.txt            # Python runtime dependencies
|-- .env.example                # Template environment file
|-- WORKFLOW.md                 # Detailed architectural and mathematical workflow document
|-- README.md                   # Primary system documentation
|
|-- routes/
|   |-- __init__.py
|   |-- api.py                  # Consolidated REST API endpoints (/api/*)
|   |-- agent.py                # ReAct AI Agent loop and tool dispatcher
|   `-- ws.py                   # WebSocket connection event handlers
|
|-- services/
|   |-- __init__.py
|   |-- capture.py              # Packet sniffing engine and risk score calculator
|   |-- geo.py                  # Geolocation resolver (MMDB and fallback coordination)
|   |-- vpn.py                  # Multi-layer VPN detection engine
|   |-- vpn_api.py              # External VPN API enrichment (vpnapi.io, ipinfo, ip-api)
|   |-- threat_intel.py         # Binary-search threat intelligence engine
|   |-- abuseipdb.py            # AbuseIPDB API client and offline blacklist checker
|   `-- behaviour.py            # Heuristic behavioral analysis (tunnels, beaconing, exfil)
|
|-- src/
|   |-- __init__.py
|   |-- agents/
|   |   |-- __init__.py
|   |   `-- llm_client.py       # SQL query translation via LLM
|   |-- parsers/
|   |   |-- __init__.py
|   |   `-- scapy_parser.py     # PCAP/PCAPNG to Parquet converter
|   |-- query/
|   |   |-- __init__.py
|   |   `-- sql_executor.py     # DuckDB in-memory SQL execution engine
|   |-- transformers/
|   |   |-- __init__.py
|   |   `-- json_to_parquet.py  # JSON to Parquet serialization helper
|   `-- utils/
|       |-- __init__.py
|       `-- logger.py           # Logging utility
|
|-- scripts/
|   `-- update_threat_intel.py  # Updater script for threat feeds and VPN blocklists
|
|-- static/
|   `-- index.html              # Cyber-themed frontend (Leaflet.js + Vanilla JS)
|
|-- tests/
|   |-- __init__.py
|   |-- test_api_routes.py      # Comprehensive 75-test REST API suite
|   |-- test_config.py          # Configuration and cache eviction unit tests
|   |-- test_offline_databases.py # MMDB and blocklist file validation tests
|   |-- test_v1_vs_v2.py        # Parity tests between v1 and v2 engines
|   `-- test_vpn_risk.py        # VPN detection and risk scoring test suite
|
`-- data/                       # Local data directory (runtime generated / downloaded)
    |-- parquet/                # Ingested Parquet files for DuckDB querying
    |-- pcap/                   # Stored PCAP captures
    |-- threat_intel/           # FireHOL, IPsum, Blocklist.de feeds, and secondary MMDBs
    `-- vpn_lists/              # X4BNet VPN IP ranges and Tor exit node lists
```

---

## Primary AI Assistant (Ollama & phi4-mini)

The embedded AI analyst in `routes/agent.py` uses a multi-step ReAct (Reason + Act) loop to answer questions about live traffic, query DuckDB datasets, inspect IP reputations, and trigger map interactions.

### Model Specification & Rationale

The primary model powering the agent is **`phi4-mini`** (Microsoft's 3.8B parameter model) running locally on **Ollama**.

Key characteristics of this design:
- **Local & Private**: No packet payloads, IPs, or network metadata are sent to cloud LLMs during normal operation.
- **Compact & High Efficiency**: The 3.8B architecture delivers strong reasoning and JSON structured-output compliance while running comfortably on consumer hardware or low-VRAM GPUs.
- **Configured Defaults**:
  - `LLM_PROVIDER=ollama`
  - `OLLAMA_MODEL=phi4-mini`
  - `OLLAMA_URL=http://localhost:11434/v1`
  - `OLLAMA_TIMEOUT=120`

### SSH-Tunnelled Remote Deployment

To preserve CPU and memory on the sniffing machine during intensive live packet capture, Ollama can be offloaded to a separate secondary laptop or GPU workstation over an SSH tunnel:

1. **On the remote laptop / GPU host**:
   ```bash
   ollama serve
   ollama pull phi4-mini
   ```

2. **On the capture machine**:
   ```bash
   ssh -N -L 11434:localhost:11434 <user>@<remote-ip>
   ```

3. **In `.env` on the capture machine**:
   ```ini
   OLLAMA_URL=http://localhost:11434/v1
   OLLAMA_MODEL=phi4-mini
   OLLAMA_TIMEOUT=120
   ```
   The backend connects through `localhost:11434` transparently to the remote Ollama daemon.

### Runtime Optimizations for phi4-mini

To keep response times fast and prevent multi-turn latency compounding on a 3.8B model:
1. **`MAX_AGENT_STEPS = 2`**: Because smaller models tend to flag `needs_followup=true` too eagerly, the agent loop is capped at 2 steps maximum to prevent unnecessary multi-roundtrip stalls.
2. **`AGENT_MAX_TOKENS = 256`**: The agent outputs structured JSON action objects. Capping generation at 256 tokens eliminates bloated text output and reduces latency.
3. **`AGENT_TEMPERATURE = 0.3`**: Low temperature ensures deterministic tool selection and adherence to JSON schemas.
4. **Compressed System Prompt**: Tool signatures use compact one-line notations to minimize prompt token overhead.
5. **Probe Caching (`OLLAMA_PROBE_TTL = 30`)**: Ollama availability is probed once and cached for 30 seconds rather than blocking each chat request with health checks.

### Fallback Cascade

If Ollama with `phi4-mini` is offline, unreachable, or times out:
1. **OpenRouter Cloud Fallback**: Automatically activates if `OPENROUTER_API_KEY` is present in `.env`. Cascades through available free models:
   - `nvidia/nemotron-3.5-lightning:free`
   - `minimax/minimax-m3:free`
   - `google/gemma-4-31b-it:free`
   - `openrouter/free`
2. **Offline Deterministic Fallback**: If neither Ollama nor OpenRouter is reachable, the internal regex matcher processes common operational intents (`get_stats`, `get_vpn`, `check_ip`, `scan_anomalies`), ensuring the assistant never crashes the dashboard.

---

## Hybrid Geolocation and VPN Detection

VPN-PacketSense v2 utilizes a hybrid architecture that pairs deterministic offline databases with online enrichment APIs to maximize accuracy without overwhelming network bandwidth.

### Geolocation Resolution

Handled by `services/geo.py`:
1. **Private IP Filtering**: RFC1918 (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16), loopback, link-local, and multicast addresses are isolated. When displayed on the map, private IPs anchor to the user's configured location (`USER_LAT`, `USER_LON` in `.env`) with spatial jitter to distinguish individual endpoints.
2. **Offline MMDB Databases**:
   - `GeoLite2-City.mmdb`: Resolves latitude, longitude, city, and country.
   - `GeoLite2-Country.mmdb`: Country centroid fallback if city data is missing.
   - `GeoLite2-ASN.mmdb`: Resolves the autonomous system number and primary organization string.
   - `dbip-asn-lite.mmdb`: Secondary ASN source for dual-source organization validation.
3. **API Geolocation Enrichment**: When online APIs (`ip-api.com`, `vpnapi.io`, `ipinfo.io`) run during VPN evaluation, their returned geographical coordinates and ISP metadata cross-verify or supplement local MMDB coordinates.

### 8-Layer VPN Detection Engine

Implemented in `services/vpn.py`, the engine evaluates 8 independent layers. Signals accumulate points into a composite confidence score (0 to 100):

| Layer | Type | Mechanism | Weight Contribution |
|---|---|---|---|
| **Layer 1** | Cache | `config.VPN_CACHE` memory lookup | Instant return (bypasses re-computation) |
| **Layer 2** | Offline Keywords | Matches ISP/Org name against 30+ VPN providers (NordVPN, ExpressVPN, Mullvad, ProtonVPN, Surfshark, CyberGhost, PIA, etc.) with CDN whitelist safeguards | +35 pts |
| **Layer 3** | Offline ASN | Matches ASNs owned exclusively by VPN providers | +65 pts |
| **Layer 4** | Offline Dual-ASN | GeoLite2-ASN vs DB-IP ASN cross-validation agreement | +15 to +20 pts |
| **Layer 5** | Offline IP Ranges | Pre-compiled X4BNet VPN lists (~1M ranges) and Tor exit nodes | +85 to +90 pts |
| **Layer 6** | Threat Intel | Corroborates IP presence in both VPN ranges and threat feeds | +10 pts |
| **Layer 7** | AbuseIPDB | VPN, proxy, or Tor flags reported by AbuseIPDB | +20 to +25 pts |
| **Layer 8** | Online APIs | Consolidated flags from `vpnapi.io`, `ipinfo.io`, and `ip-api.com` | Up to +90 pts + consensus bonuses |

#### Classification Tiers
- **`not_vpn` (0–15)**: Clean connection, standard consumer/enterprise ISP.
- **`vpn_suspect` (16–35)**: Weak heuristics or protocol-only indicators.
- **`vpn_likely` (36–60)**: Corroborated signals across multiple layers.
- **`vpn_confirmed` (61–100)**: Verified VPN provider, active Tor exit node, or API consensus.

### External Enrichment APIs

Implemented in `services/vpn_api.py` and `services/abuseipdb.py`. To prevent rate-limiting and performance bottlenecks during live packet processing, all API responses are cached in memory for **24 hours per IP**:

1. **`vpnapi.io`** (Requires `VPNAPI_IO_KEY` in `.env`, 1,000 lookups/day free):
   - Returns explicit boolean flags: `vpn`, `proxy`, `tor`, `relay`.
   - Tor flag adds +90 pts, VPN flag adds +75 pts, Proxy flag adds +65 pts.
2. **`ipinfo.io`** (Optional `IPINFO_TOKEN` in `.env`, 50,000 lookups/month free):
   - Returns privacy parameters: `vpn`, `proxy`, `tor`, `relay`.
   - Tor flag adds +80 pts, VPN flag adds +60 pts, Relay flag adds +40 pts.
3. **`ip-api.com`** (Free, no key required, 45 requests/minute):
   - Returns `proxy` and `hosting` indicators along with organization metadata.
   - Proxy flag adds +50 pts.
4. **`AbuseIPDB`** (Requires `ABUSEIPDB_API_KEY` in `.env`, 1,000 lookups/day free):
   - Queries abuse confidence score (0–100%) and report counts.
   - Provides an offline 100% abuse blacklist fallback when internet is unavailable.
5. **Multi-API Consensus Bonuses**:
   - If 2 APIs independently confirm VPN/proxy: **+20 pts bonus** (`api_consensus_2`).
   - If all 3 APIs independently agree: **+35 pts bonus** (`api_consensus_3`).

---

## Risk Scoring Model

Every packet and external IP is evaluated by `compute_risk_score()` in `services/capture.py`. Scores range from 0 to 100.

### Factor Weight Distribution

The final score is calculated as:
$$\text{Score} = \min\left(100, \sum \text{Active Risk Factors}\right)$$

```
VPN Signals:
  vpn_confirmed                           +25
  vpn_likely                              +15
  vpn_suspect                             +5
  vpn_protocol_strong (WireGuard, IPSec)  +10
  vpn_protocol_weak (Ambiguous VPN port)  +5

Threat Intelligence (FireHOL, IPsum, Blocklist.de):
  threat_critical (FireHOL L1, Spamhaus)  +50
  threat_high (FireHOL L2, DShield)       +35
  threat_medium (FireHOL L3)              +20
  threat_low                              +10

Cross-Correlation:
  vpn_plus_threat_crit (VPN to C2/Malware) +20
  vpn_plus_threat_high                    +10

Behavioral Analytics:
  behaviour_exfil (Exfil score >= 50)     +25
  behaviour_beaconing (Beacon >= 50)      +20
  behaviour_tunnel (Tunnel >= 50)         +15

Suspicious Destination Ports:
  dark_web_port (Tor SOCKS: 9050, 9051)   +20
  suspicious_port (4444, 5555, 31337, etc) +15

AbuseIPDB Reputation:
  abuseipdb_critical (Confidence > 75%)   +30
  abuseipdb_high (Confidence 50-75%)      +20
  abuseipdb_medium (Confidence 25-50%)    +10
  abuseipdb_blacklist (Offline list hit)  +30
```

### Severity Thresholds

The score maps to risk classifications:

| Score Range | Severity Label | Visual Indication | Operational Significance |
|---|---|---|---|
| **>= 70** | **critical** | Red Marker | Immediate threat: Active C2, Tor exit, or malware host. |
| **>= 45** | **high** | Orange Marker | High concern: Confirmed VPN or known attacker infrastructure. |
| **>= 25** | **medium** | Yellow Marker | Suspicious: Unverified anomaly, suspect VPN, or port alert. |
| **> 0** | **low** | Blue Marker | Informational: Weak signal or minor reputation flag. |
| **== 0** | **none** | Grey / Green | Normal: Clean network communication. |

---

## Threat Intelligence and Behavioral Engines

### Threat Intelligence Feeds

Loaded and queried via `services/threat_intel.py`. Threat databases are held in sorted memory lists, allowing binary searches in $O(\log n)$ time:
- **FireHOL Level 1**: Malware command-and-control, cybercrime IPs, and hijacked netblocks.
- **FireHOL Level 2 & 3**: Known malicious hosts, attack sources, and spammers.
- **Spamhaus DROP / EDROP**: Don't Route Or Peer hijacked IP blocks.
- **DShield**: Top attacking subnets reported across distributed firewalls.
- **IPsum**: Multi-source feed aggregating scores from 30+ security feeds.
- **Blocklist.de**: Specialized feeds for active SSH, Mail, Apache, and FTP brute-force sources.

### Behavioral Analytics

Implemented in `services/behaviour.py`, this engine maintains rolling connection statistics for each internal endpoint:
- **Tunnel Fingerprinting**: Identifies packets clustered around tunnel MTUs (1400–1480 bytes for WireGuard, 1438 for OpenVPN), low port diversity, and persistent session durations.
- **C2 Beaconing Detection**: Identifies automated check-in routines by tracking regular packet inter-arrival intervals and low variation in packet size across windows of 10+ packets.
- **Data Exfiltration**: Detects anomalous outbound byte volumes and sustained high-speed uploads to external destinations.

---

## Operational Modes

### Live NIC Capture
1. Select an active hardware network adapter from the dashboard interface dropdown.
2. Click **Start Capture**.
3. Packets are captured via Scapy, analyzed across the enrichment pipeline, and pushed to the browser in 500ms batches via WebSockets.
4. Leaflet plots packet paths with animated arcs, updating bandwidth gauges, protocol charts, and active threat counters.
5. Click **Stop Capture** or **Save Packets** to serialize the session to a `.pcap` file in `data/pcap/`.

### Switch Mirror (SPAN) Monitoring
Set `CAPTURE_MODE = "switch"` in `config.py`:
- Captures traffic mirrored from an enterprise core switch, network tap, or 5G user plane gateway.
- Maps internal devices on the subnet (`/api/switch/devices`).
- Dispatches immediate alerts (`switch_vpn_alert`) if an internal device initiates an unauthorized VPN tunnel or data exfiltration spike.

### PCAP/PCAPNG Forensics with DuckDB
1. Open the **PCAP Analysis** tab in the dashboard.
2. Upload a `.pcap` or `.pcapng` file.
3. `src/parsers/scapy_parser.py` parses the file and outputs a Snappy-compressed Parquet file to `data/parquet/`.
4. DuckDB initializes an in-memory SQL catalog over the dataset:
   - Query traffic using standard SQL via the Query tab.
   - Investigate protocols, conversational flows, and packet distributions.

---

## Installation and Setup

### Prerequisites

- **Python**: Version 3.11 or higher.
- **Capture Drivers**:
  - **Windows**: Install [Npcap](https://npcap.com/). Check **"Install Npcap in WinPcap API-compatible Mode"** during setup. Terminal must be run as **Administrator**.
  - **Linux**: Install `libpcap-dev` (`sudo apt-get install libpcap-dev`). Terminal must run with `sudo`.
  - **macOS**: Install `libpcap` (`brew install libpcap`). Terminal must run with `sudo`.
- **Local Ollama** (Recommended): Download and install [Ollama](https://ollama.ai/). Run `ollama pull phi4-mini`.

### Environment Configuration

Clone the repository and prepare the virtual environment:

```bash
git clone https://github.com/your-user/VPN-PacketSense-v2.git
cd VPN-PacketSense-v2

# Create virtual environment
python -m venv .venv

# Activate on Windows (PowerShell)
.venv\Scripts\Activate.ps1

# Activate on Linux / macOS
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

Create your `.env` file:
```bash
cp .env.example .env
```

Configure `.env`:
```ini
# Primary LLM Provider (Ollama with phi4-mini)
LLM_PROVIDER=ollama
OLLAMA_URL=http://localhost:11434/v1
OLLAMA_MODEL=phi4-mini
OLLAMA_TIMEOUT=120

# Optional Cloud LLM Fallback (OpenRouter)
OPENROUTER_API_KEY=

# Optional Online Enrichment APIs
VPNAPI_IO_KEY=
ABUSEIPDB_API_KEY=
IPINFO_TOKEN=

# Static Anchor Coordinates (Used in Switch Mode / RFC1918 Private Mapping)
USER_LAT=25.4279
USER_LON=81.7710
USER_CITY=Prayagraj
USER_COUNTRY=India
```

### Offline Databases and Threat Intel Download

Download threat feeds, IPsum lists, X4BNet VPN ranges, and Tor exit nodes:
```bash
python scripts/update_threat_intel.py
```

Place the required MMDB files in the `data/` directory:
- `GeoLite2-City.mmdb` (MaxMind free account)
- `GeoLite2-ASN.mmdb` (MaxMind free account)
- `GeoLite2-Country.mmdb` (MaxMind free account)
- `dbip-asn-lite.mmdb` (DB-IP free download)

### Running the Application

```bash
# Windows (PowerShell as Administrator)
python app.py

# Linux / macOS
sudo python app.py
```

Open `http://localhost:5000` in your web browser.

---

## Configuration and Performance Tuning

### Performance Mode (FAST_MODE)

In `config.py`, toggle `FAST_MODE` depending on your interface throughput:

```python
FAST_MODE = True   # Default: Skips CPU-heavy threat DB scans for real-time live sniffing
FAST_MODE = False  # Full pipeline: Runs every packet through threat feeds and behavioral scans
```

| Engine Feature | FAST_MODE = True | FAST_MODE = False |
|---|:---:|:---:|
| MaxMind GeoIP and ASN Resolution | Enabled | Enabled |
| Provider Keywords and VPN ASN Checks | Enabled | Enabled |
| X4BNet and Tor Range Validation | Enabled | Enabled |
| Online VPN APIs (Cached 24h per IP) | Enabled | Enabled |
| FireHOL and IPsum Threat Scanning | Skipped | Enabled |
| AbuseIPDB Per-Packet Check | Skipped | Enabled |
| Behavioral Engine (Beaconing/Exfil) | Skipped | Enabled |

### Cache and Memory Bounds

`config.py` enforces memory boundaries:
- `DUCKDB_MEMORY_LIMIT`: `"8GB"`
- `DUCKDB_THREADS`: `4` parallel threads
- `MAX_HISTORY`: `5000` packets in circular ring buffer
- `GEOIP_CACHE_MAX`: `50,000` entries (~2.5 MB)
- `VPN_CACHE_MAX`: `25,000` entries
- `VPN_API_CACHE_MAX`: `10,000` entries
- Eviction Strategy: When a cache exceeds its maximum bound, `evict_cache_if_needed()` removes the oldest 20% of entries using insertion-order eviction.

---

## REST API Reference

| Endpoint | Method | Description |
|---|---|---|
| `/` | GET | Serves dashboard UI (`static/index.html`). |
| `/api/mode` | GET | Current engine mode (`has_parquet`, `live_capture`, `parquet_path`). |
| `/api/interfaces` | GET | List available hardware network interfaces. |
| `/api/local_ips` | GET | List non-loopback host IP addresses. |
| `/api/capture/start` | POST | Starts live packet capture (`{"interface": "...", "mode": "local\|switch"}`). |
| `/api/capture/stop` | GET | Stops the active packet capture thread. |
| `/api/live/stats` | GET | Real-time session telemetry (packet counts, bandwidth, protocols). |
| `/api/live/history` | GET | Recent packet circular buffer. |
| `/api/live/save` | GET | Saves in-memory captured packets to a PCAP file in `data/pcap/`. |
| `/api/live/load_saved` | GET | Loads previously saved capture files. |
| `/api/stats` | GET | Dataset statistics from active DuckDB database. |
| `/api/flows` | GET | Returns directional network flows. |
| `/api/time_range` | GET | Minimum and maximum timestamps of loaded data. |
| `/api/flow_details` | GET | Packet details for a specific source and destination pair. |
| `/api/vpn/status` | GET | VPN engine status, database records, and cache metrics. |
| `/api/vpn/refresh` | POST | Reloads VPN ASN definitions and IP range lists. |
| `/api/vpn/clear_cache` | POST | Flushes the in-memory VPN decision cache. |
| `/api/threat_intel/status` | GET | Status of loaded FireHOL, IPsum, and Blocklist.de feeds. |
| `/api/threat_intel/check/<ip>` | GET | Performs on-demand threat verification for an IP. |
| `/api/behaviour/summary` | GET | Active beaconing, tunnel, and exfiltration alerts. |
| `/api/behaviour/device/<ip>` | GET | Behavioral profiling metrics for a specific internal host. |
| `/api/switch/status` | GET | Switch monitoring state and host metrics. |
| `/api/switch/devices` | GET | Monitored endpoints on the switched network. |
| `/api/switch/vpn_alerts` | GET | Historical VPN detection alerts for switch devices. |
| `/api/switch/reset` | GET | Resets tracked switch monitoring records. |
| `/api/switch/device/<ip>` | GET | Metadata for a specific switch-monitored host. |
| `/api/upload_pcap` | POST | Uploads and processes `.pcap` / `.pcapng` files into Parquet. |
| `/api/load_parquet` | POST | Attaches an existing Parquet capture to DuckDB. |
| `/api/agent/chat` | POST | Queries the ReAct AI Agent (`{"message": "..."}`). |
| `/api/agent/status` | GET | Reports active LLM provider, current model, and availability. |

---

## WebSocket Telemetry

The application exposes real-time bidirectional communication via Flask-SocketIO:

| Event Name | Direction | Description |
|---|:---:|---|
| `connect` | Client -> Server | Client initiates WebSocket handshake. |
| `connection_response` | Server -> Client | Confirms successful socket initialization. |
| `new_packet` | Server -> Client | Batched packet telemetry (coordinates, protocol, risk score). |
| `stats_update` | Server -> Client | 1-second rolling telemetry (pps, bandwidth bps, unique IPs). |
| `switch_device_update` | Server -> Client | Emitted when an internal host's state changes in switch mode. |
| `switch_vpn_alert` | Server -> Client | Dispatched when a switch host initiates a VPN connection. |
| `behaviour_alert` | Server -> Client | Broadcast when beaconing or exfiltration patterns exceed threshold. |

---

## AI Agent Tools

The embedded ReAct agent in `routes/agent.py` can invoke 22 distinct tools during reasoning:

| Tool Name | Parameters | Purpose |
|---|---|---|
| `get_stats` | None | Total packets, bytes, protocol distributions, and VPN count. |
| `get_vpn` | None | Lists detected VPN IPs with provider name and confidence rating. |
| `get_top_talkers` | None | Returns top 5 IP addresses by transmitted byte volume. |
| `get_flows` | `{"limit": 5}` | Lists dominant source-to-destination network flows. |
| `check_ip` | `{"ip": "..."}` | Audits an IP across GeoIP, ASN, VPN scoring, and threat feeds. |
| `get_vpn_signals` | `{"ip": "..."}` | Returns full 8-layer score breakdown for an IP. |
| `check_abuse_ip` | `{"ip": "..."}` | Queries AbuseIPDB reputation scores and malicious flags. |
| `get_geo_ip` | `{"ip": "..."}` | Returns geographic coordinates, city, country, and ASN. |
| `analyze_traffic` | None | Evaluates protocol balance, port activity, and frame size profiles. |
| `get_threat_summary` | None | Summarizes active threats grouped by severity tier. |
| `scan_anomalies` | None | Scans session for high-risk IPs and correlated threats. |
| `get_bandwidth_analysis` | None | Bandwidth breakdown by protocol and destination port. |
| `get_behaviour_summary` | None | Summarizes active C2 beaconing and data exfiltration detections. |
| `get_device_behaviour` | `{"ip": "..."}` | Deep-dive behavioral analysis for a specific internal device. |
| `get_session_info` | None | Returns capture mode, active interface, and database status. |
| `get_capture_devices` | None | Lists active internal devices observed during live capture. |
| `get_switch_devices` | None | Lists all tracked endpoints in switch monitoring mode. |
| `get_switch_vpn_alerts` | None | Historical VPN alert logs recorded during switch monitoring. |
| `inject_packet` | `{"src_ip":"", "dst_ip":"", "protocol":"TCP"}` | Plots a simulated packet transmission arc on the live map. |
| `explain_packet` | `{"fields": "..."}` | Explains raw packet headers and flags in plain English. |
| `export_report` | None | Generates an executive security assessment summary. |
| `general_answer` | `{"answer": "..."}` | Delivers direct factual answers without running tool executions. |

---

## Test Suite

The project includes an automated test suite verifying REST API routes, parameter handling, error conditions, and empty-state fallbacks.

Run the test suite:
```bash
python -m unittest tests/test_api_routes.py
```

All 75 test cases execute against the Flask test client without requiring live hardware capture interfaces.

---

## Troubleshooting

### 1. Packet Capture Fails or Returns Permission Denied
- **Windows**: Confirm Npcap is installed with **WinPcap API-compatible mode** checked. You must open PowerShell or Command Prompt with **Run as Administrator**.
- **Linux/macOS**: Packet capture requires raw socket privileges. Start the application with `sudo python app.py`.

### 2. Ollama Connection Error or phi4-mini Latency
- If running Ollama on a remote laptop via SSH tunnel:
  ```bash
  ssh -N -L 11434:localhost:11434 <user>@<remote-ip>
  ```
- Verify that `phi4-mini` is pulled and available:
  ```bash
  ollama list
  ```
- Ensure `OLLAMA_TIMEOUT=120` in `.env` to accommodate CPU or low-VRAM inferences.

### 3. Geolocation Shows Coordinate (0, 0)
- Verify that `GeoLite2-City.mmdb` and `GeoLite2-ASN.mmdb` are present in the `data/` directory.
- Note that private IP ranges (RFC1918) will display on your configured anchor coordinates (`USER_LAT`, `USER_LON`) rather than external coordinates.

### 4. High CPU Utilization on High-Throughput Interfaces
- Ensure `FAST_MODE = True` in `config.py`. This disables computationally intensive threat database iterations and behavioral scans on per-packet hot paths while maintaining MMDB geolocation and cached VPN lookups.

---

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for full details.
