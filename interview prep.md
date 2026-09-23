# 5G-PacketSense v2 - Interview Preparation

## 1. One-minute project explanation

**5G-PacketSense v2 is a self-hosted network observability and security-analysis platform for 5G/LTE-style traffic environments.** It can capture packets from a local network interface, monitor traffic from an upstream switch, or analyze an uploaded PCAP file. It enriches traffic with offline geolocation, ASN information, VPN/Tor detection, threat intelligence, behavioural signals, and a combined risk score. The results are exposed through a Flask API and displayed in a browser dashboard with a live Leaflet map, statistics, alerts, and an AI assistant.

The main design goal was to combine **real-time visibility**, **offline-first analysis**, and **natural-language investigation** in one lightweight application. The core security decisions do not depend on an LLM: deterministic analyzers produce the facts, and the AI agent is an optional interface for asking questions about those facts.

A concise architecture summary is:

```text
Network interface / PCAP
          |
          v
 Scapy capture or parser
          |
          v
 Structured packet record
          |
          +--> GeoIP and ASN enrichment
          +--> VPN/Tor multi-signal detection
          +--> Threat-intelligence lookup
          +--> Behavioural analysis
          +--> Weighted risk score
          |
          +--> In-memory state / Parquet / DuckDB
          |
          +--> Flask REST API
          +--> Socket.IO real-time events
          +--> AI agent tools
          |
          v
 Browser dashboard and analyst answers
```

## 2. The problem it solves

Traditional packet capture tools are powerful but often require the analyst to combine several separate tools and manually correlate their output. This project provides one workflow for:

- seeing traffic and packet locations on a live map;
- identifying likely VPN, proxy, relay, or Tor endpoints;
- checking whether an IP appears in several threat feeds;
- detecting suspicious behaviour such as beaconing, tunnelling, or possible exfiltration;
- querying PCAP data with SQL or natural language;
- retaining an offline analysis path when API keys or internet access are unavailable.

The project is especially useful in a 5G/LTE monitoring context because traffic may be observed at a local interface or at a switch mirror/SPAN port. The platform focuses on IP-level traffic analysis and enrichment; it is not intended to replace a specialized 5G control-plane decoder.

## 3. End-to-end startup workflow

1. The user installs Python dependencies from `requirements.txt` and, for live capture, installs Npcap on Windows or libpcap on Linux/macOS.
2. `app.py` creates the Flask application, enables CORS, creates a Flask-SocketIO instance, and registers the API and AI-agent blueprints.
3. The capture service receives the Socket.IO instance so background capture threads can emit events to the browser.
4. At startup, local VPN lists and threat-intelligence databases are loaded into memory. The optional AbuseIPDB offline blacklist is also loaded.
5. GeoIP readers are initialized from local MMDB files when `services/geo.py` is imported.
6. Optional credentials are read from `.env`: OpenRouter/LLM credentials, VPN API credentials, AbuseIPDB credentials, and an optional configured user location.
7. The server starts on port `5000`. The frontend at `static/index.html` calls the REST endpoints and opens a Socket.IO connection.
8. The user chooses either live capture, switch monitoring, or PCAP analysis.

The application can also receive a PCAP/Parquet path as a command-line argument and auto-load it during startup.

## 4. Live-capture workflow

### Step 1: Select a capture source

The browser requests `/api/interfaces`. On Windows, the application uses Scapy's Windows interface listing and returns a Scapy-compatible GUID. It filters virtual or unsuitable adapters and labels likely Ethernet and Wi-Fi interfaces. On Unix-like systems it uses Scapy's interface list and excludes common loopback/container interfaces.

The user starts capture through `/api/capture/start`. The route stores the selected mode, interface, and subnet in centralized configuration, clears old caches and statistics, and starts `start_unified_capture()` in a daemon thread so the Flask request thread remains responsive.

### Step 2: Capture packets

`services/capture.py` uses Scapy's `sniff()` function. The packet callback extracts fields such as:

- source and destination IP;
- protocol;
- source and destination ports;
- packet length;
- TTL and frame-related metadata where available.

The same capture engine supports local mode and switch-monitoring mode. Switch mode is designed for traffic arriving from a mirrored upstream port, with a configured subnet and device tracking.

### Step 3: Enrich each packet

For external IPs, the packet is enriched using the following pipeline:

1. **Private-address filtering** prevents meaningless external GeoIP and reputation lookups for RFC1918, loopback, link-local, and multicast addresses.
2. **GeoIP lookup** uses local MaxMind GeoLite2 MMDB files for latitude, longitude, city, and country.
3. **ASN lookup** uses GeoLite2 ASN and optionally DB-IP ASN Lite. The second source helps cross-check the organization and ASN.
4. **VPN detection** combines organization keywords, known VPN ASNs, IP range lists, Tor exit-node lists, protocol-port hints, optional AbuseIPDB data, threat-intelligence correlation, and optional external VPN APIs.
5. **Threat intelligence** checks local FireHOL, Spamhaus, DShield, IPsum, Blocklist.de, and AbuseIPDB-derived data.
6. **Behavioural analysis** tracks per-device flow patterns and can identify possible tunnels, regular beaconing, or unusual high-volume flows.
7. **Risk scoring** combines the independent signals into a score from 0 to 100 with a severity label and human-readable reasons.

Results are cached by IP. This matters because a capture can contain thousands of packets but far fewer unique endpoints.

### Step 4: Store state and update the UI

Live counters and device state are kept in `config.py`, which acts as the shared runtime state module. A bounded `deque` retains recent packet history, and cache eviction limits memory growth.

Packets are queued for Socket.IO emission and flushed in batches at approximately 500 ms intervals. This reduces WebSocket overhead and prevents one event per packet from overwhelming the browser during busy captures.

The frontend receives packet events and updates:

- Leaflet map markers;
- packet and byte counters;
- protocol and bandwidth statistics;
- top talkers;
- VPN details;
- threat alerts;
- behavioural indicators.

The map uses a two-minute marker cycle so long-running captures remain readable instead of accumulating unlimited markers.

### Step 5: Stop or save

The user can stop capture through the API. Captured packets can be saved for later analysis, allowing a live session to become a reproducible PCAP-based investigation.

## 5. PCAP-analysis workflow

1. The user uploads a `.pcap` or `.pcapng` file through the dashboard.
2. `src/parsers/scapy_parser.py` reads the file with Scapy's `rdpcap()`.
3. Each packet is converted into a normalized dictionary containing frame number, timestamp, IPs, ports, protocol, length, a readable summary, and a protocol stack.
4. The records are converted to a DataFrame and written to Parquet using PyArrow and Snappy compression.
5. DuckDB loads the Parquet data into an in-memory `packets` table.
6. API endpoints query that table for counts, protocol distributions, top talkers, flows, and bandwidth data.
7. IPs discovered in the PCAP can go through the same GeoIP, VPN, and threat-enrichment pipeline used by live traffic.
8. The user can issue SQL queries directly or ask the AI agent to select an analysis tool.

This separation is useful: Scapy handles packet decoding, Parquet provides a compact columnar interchange format, and DuckDB provides fast local SQL analytics without deploying a separate database server.

## 6. VPN and Tor detection design

The detector is deliberately multi-signal instead of trusting one heuristic. A single organization name or port can produce false positives, so evidence is accumulated and classified:

| Confidence | Classification | Interpretation |
|---|---|---|
| 0-15 | `not_vpn` | No meaningful VPN evidence |
| 16-35 | `vpn_suspect` | Weak or isolated evidence |
| 36-60 | `vpn_likely` | Several signals or strong evidence |
| 61-100 | `vpn_confirmed` | High-confidence VPN/proxy/Tor evidence |

Signals include:

- ISP and organization keyword matching for known providers;
- a curated database of VPN-provider ASNs;
- GeoLite2 and DB-IP cross-validation;
- cached X4BNet VPN ranges;
- Tor exit-node IPs;
- VPN protocol and port hints such as WireGuard, OpenVPN, or IPSec;
- optional AbuseIPDB flags and offline blacklist membership;
- correlation with local threat intelligence;
- optional vpnapi.io, ipinfo.io, and ip-api.com enrichment.

The detector also has a CDN whitelist for infrastructure such as Cloudflare, Google, Microsoft, Amazon, and Akamai. This reduces false positives because large CDNs can look like hosting or proxy infrastructure.

A good interview explanation is: **the score is evidence aggregation, not proof of user intent**. A VPN may be legitimate, and a non-VPN IP may still be malicious.

## 7. Threat-intelligence design

Threat feeds are downloaded separately by `scripts/update_threat_intel.py` and then used locally. Sources include FireHOL levels, Spamhaus DROP/EDROP, DShield, IPsum, Blocklist.de, and an AbuseIPDB-derived blacklist.

At startup, CIDR networks are parsed and sorted. IP lookups use binary-search indexing over network start addresses rather than scanning every network sequentially. Individual IP feeds are held in sets for fast membership checks. This gives the hot path predictable lookup performance.

The result includes whether an IP is malicious, the threat level, matching sources, categories, and any IPsum score. Multiple source matches can raise the severity because independent corroboration is stronger than a single feed hit.

The feeds are not treated as ground truth. They are reputation signals with freshness, coverage, and false-positive limitations.

## 8. Risk scoring design

`compute_risk_score()` produces a score capped at 100, a severity level, reasons, a factor breakdown, and a primary concern. Example factors include:

- confirmed/likely/suspected VPN evidence;
- strong or weak VPN protocol hints;
- critical, high, medium, or low threat intelligence matches;
- VPN plus threat correlation;
- tunnel, beaconing, or exfiltration behaviour;
- suspicious or Tor-related ports;
- AbuseIPDB confidence bands.

The important design choice is explainability. The UI and AI agent can say not only that traffic is high risk, but **which signals contributed to the score**. This is more useful to an analyst than an opaque binary alert.

The score is a prioritization mechanism, not a machine-learning probability. The weights are manually chosen domain heuristics and should be calibrated against labeled traffic in a production system.

## 9. Behavioural analysis

The behavioural engine tracks traffic over time instead of judging a packet in isolation. It looks for patterns such as:

- tunnel-like traffic near common MTU sizes with low port diversity;
- regular packet timing and similar packet sizes, which can indicate beaconing;
- sustained high-volume transfers to one destination, which may indicate exfiltration.

Behavioural indicators are combined with static evidence such as VPN status, threat feeds, and suspicious ports. This reduces the risk of treating one unusual packet as a complete incident.

In performance-sensitive live environments, heavy analysis can be disabled with `FAST_MODE`; the current code sets `FAST_MODE = False`, so the full pipeline is the present default. For high-volume monitoring, enabling fast mode is a tradeoff between lower per-packet cost and fewer deep signals.

## 10. AI agent workflow

The AI layer is implemented in `routes/agent.py` as a tool-using ReAct-style agent:

1. The user asks a natural-language question in the dashboard.
2. The agent sends the question and available tool descriptions to an OpenAI-compatible LLM endpoint, commonly through OpenRouter.
3. The model must return a JSON action containing a tool name, parameters, a short plan, and whether another step is needed.
4. The backend executes the selected tool against live state, DuckDB, or deterministic analysis services.
5. The result is sent back to the model for up to three tool steps.
6. The final answer is shown to the user.

Available tools include `get_stats`, `get_vpn`, `get_top_talkers`, `check_ip`, `get_flows`, `analyze_traffic`, `get_threat_summary`, `get_vpn_signals`, `scan_anomalies`, `get_bandwidth_analysis`, `inject_packet`, `explain_packet`, and `general_answer`.

The model does not directly read arbitrary files or run arbitrary SQL without the application controlling the tool boundary. This keeps the agent grounded in application data and makes the operations easier to audit.

There is a model cascade and a regex-intent fallback. If the LLM is unavailable, common questions still receive answers from live data. This is an important reliability decision: the dashboard should not become unusable just because an optional AI service is rate-limited or unconfigured.

## 11. Technology choices and why they fit

### Python

Python has a mature networking and security ecosystem. Scapy makes packet capture and protocol-layer inspection practical, while pandas, PyArrow, DuckDB, and the GeoIP libraries support the analysis pipeline without requiring a large distributed system.

### Flask

Flask is lightweight and well suited to a local analyst tool. Blueprints separate API routes from agent routes, and the application remains easy to run with one command.

### Flask-SocketIO

REST is appropriate for commands and query results, but live packet visualization needs server-to-browser push. Socket.IO provides an event-driven channel with a simpler browser integration than polling.

### Scapy

Scapy supports both live sniffing and PCAP decoding in Python. Using the same library for both paths reduces differences between live and offline behaviour.

### Parquet and PyArrow

Parquet is columnar, compressed, and portable. It is a good intermediate format for packet metadata because analytical queries often need only a few columns, such as timestamps, protocol, IP, and length.

### DuckDB

DuckDB is an embedded analytical database. It gives the project SQL, grouping, aggregation, and columnar execution without a separate database server or network dependency. In-memory DuckDB also makes local PCAP investigation quick to start.

### MMDB / GeoLite2 / DB-IP

Local MaxMind-compatible databases make geolocation and ASN enrichment fast and available offline. A secondary ASN source provides a way to validate provider information rather than trusting one database.

### Vanilla JavaScript and Leaflet

The frontend is a single-page static HTML application with no frontend build step. This lowers deployment complexity for a self-hosted tool. Leaflet provides a mature map abstraction, while Socket.IO updates the map and panels in real time.

### Local files plus optional APIs

Offline threat lists and MMDB files provide a baseline that works without credentials. Optional services add freshness and independent corroboration, but results are cached for 24 hours and rate limits are tracked to control cost and API pressure.

### Centralized runtime state

`config.py` contains shared settings, caches, counters, and capture state. For a single-process local application this is simple and practical. In a multi-worker production deployment, this would need to move to a proper shared store such as Redis or a database.

## 12. Reliability, performance, and security decisions

- **Bounded history:** a ring buffer prevents unlimited live packet history from consuming memory.
- **Cache limits and eviction:** repeated IPs do not repeatedly trigger expensive database or network lookups.
- **API quotas:** optional services have daily/minute counters and conservative limits.
- **Batching:** Socket.IO events are throttled into short batches.
- **Offline fallback:** the essential pipeline continues without external APIs or an LLM.
- **Input handling:** private and invalid IPs are filtered before external enrichment.
- **Explainability:** risk scores include contributing factors and reasons.
- **Threaded capture:** the sniffer runs separately from Flask request handling.
- **Graceful empty states:** API tests cover idle capture, missing PCAP state, static serving, interface discovery, and error responses.

## 13. Honest limitations and improvements

These are good answers if an interviewer asks what you would improve:

1. **Single-process shared state:** the current dictionaries and counters are process-local. For production scale, use a message broker or shared state store and separate capture from web workers.
2. **Capture privileges:** live capture needs Administrator privileges on Windows and elevated permissions on Unix-like systems. A production deployment could isolate capture in a least-privilege service.
3. **Heuristic scoring:** VPN and risk weights are expert heuristics, not trained probabilities. The next step would be labeled evaluation, calibration, and per-environment tuning.
4. **Threat-feed freshness:** local feeds need scheduled updates and source-health monitoring.
5. **External API dependency:** optional APIs can fail or be rate-limited. The cache and offline path help, but the UI should display freshness and confidence explicitly.
6. **PCAP memory usage:** `rdpcap()` loads the capture into memory. A streaming parser would be better for very large PCAPs.
7. **LLM output validation:** the agent expects structured JSON. Production hardening should use strict schema validation, retries, tool allow-lists, timeouts, and prompt-injection protections.
8. **Deployment security:** CORS is permissive and the example secret key is development-oriented. A deployed version should restrict origins, use a real secret from the environment, add authentication, and protect sensitive endpoints.
9. **5G specificity:** the current system analyzes IP traffic and metadata. It could be extended with 5G protocol parsers for GTP-U, NGAP, PFCP, and subscriber/session-aware correlation.
10. **Documentation drift:** some older documentation describes a different `FAST_MODE` default and older model names. In an interview, describe the current code as the source of truth.

## 14. Likely interview questions and answers

### Q1. Give me the architecture in one minute.

The browser talks to a Flask backend through REST and Socket.IO. The backend captures or parses packets, normalizes them, enriches external IPs with local GeoIP/ASN data, evaluates VPN and threat signals, computes an explainable risk score, stores live state or Parquet/DuckDB data, and exposes deterministic analysis tools to an optional AI agent. The frontend renders maps, statistics, alerts, and chat responses.

### Q2. Why did you use both REST and WebSockets?

REST fits request-response operations such as starting capture, loading a PCAP, retrieving stats, and checking one IP. Live packet updates are server-initiated and frequent, so Socket.IO avoids polling and provides a better real-time experience.

### Q3. Why DuckDB instead of PostgreSQL?

The main workload is local analytical querying over PCAP data, not multi-user transactional updates. DuckDB provides SQL, aggregation, and columnar execution in-process with no database server to install or operate. PostgreSQL would become more appropriate for centralized multi-user deployments and durable shared state.

### Q4. Why Parquet between Scapy and DuckDB?

Scapy produces packet objects, while analytics work better on typed tabular data. Parquet gives a compressed, columnar, reusable representation. DuckDB can query it efficiently and the file can be retained as an analysis artifact.

### Q5. Why not call an online geolocation API for every packet?

That would be slow, rate-limited, privacy-sensitive, and unreliable during an incident. Local MMDB lookup is fast and offline. The application only uses optional external APIs for additional VPN or abuse corroboration, with per-IP caching and quota controls.

### Q6. How do you reduce VPN false positives?

I do not classify based on one port or one keyword. I combine independent signals, use a confidence score, cross-check ASN sources, corroborate IP ranges with provider information, and whitelist major CDN infrastructure. The output distinguishes suspect, likely, and confirmed rather than pretending the result is absolute.

### Q7. What is the difference between VPN detection and risk scoring?

VPN detection answers, “How much evidence is there that this endpoint uses VPN/proxy/Tor infrastructure?” Risk scoring answers, “How concerning is this traffic overall?” A VPN may add risk points, but threat-feed matches, behavioural anomalies, suspicious ports, and cross-signal correlations contribute separately.

### Q8. Why is an LLM useful here if the security logic is deterministic?

The LLM is an analyst interface, not the detection authority. It maps questions such as “show suspicious external IPs” to controlled tools, combines tool results, and explains findings in natural language. The underlying facts still come from code, databases, and explicit scoring logic.

### Q9. What happens if the LLM is unavailable?

The dashboard and deterministic analysis continue to work. The agent has a regex-based fallback for common intents, and the core capture, GeoIP, VPN, threat, and risk services do not require the LLM.

### Q10. How is the AI agent prevented from making arbitrary changes?

The model returns a structured tool request, and the backend chooses from an explicit allow-list of tools with defined parameters. Tools read application state or perform specific controlled actions. A production version should add strict JSON-schema validation, authentication, audit logging, and stronger prompt-injection defenses.

### Q11. How does the system perform under high traffic?

It caches by IP, bounds history, evicts oversized caches, indexes threat networks for fast lookup, and batches Socket.IO emissions. There is also a fast mode that skips heavier per-packet work. The current implementation is best understood as a single-host analysis tool; horizontal scaling would require moving state and capture coordination outside the process.

### Q12. How would you test it?

I would test route contracts with Flask's test client, unit-test VPN classifications and score boundaries, test threat-intel lookups against known fixtures, parse small representative PCAPs, test cache expiration and rate limits, and use an integration test to verify capture-to-Socket.IO event flow. I would also add property tests for malformed packets and invalid IP addresses.

### Q13. What was a difficult engineering tradeoff?

The main tradeoff was depth versus real-time responsiveness. More threat feeds, behavioural analysis, and API enrichment improve detection but increase per-packet cost. Caching, batching, bounded state, and `FAST_MODE` let the operator choose between a lighter live view and a deeper offline investigation.

### Q14. What would you improve first?

I would first add authentication and restrictive CORS, move capture and shared state behind a more production-ready service boundary, stream large PCAPs instead of loading them all with `rdpcap()`, and add evaluation data for calibrating the risk weights.

### Q15. Is this a machine-learning intrusion detection system?

No. The current detection pipeline is primarily deterministic and heuristic: curated lists, database lookups, protocol hints, temporal rules, and weighted scoring. The LLM adds natural-language interaction and tool orchestration, but it is not used as the source of the security score.

### Q16. What does “5G” mean in this project?

It describes the intended monitoring environment, including 5G/LTE networks and switch-mirrored traffic. The current implementation operates mainly on IP-level packet metadata and enrichment. It does not yet decode every 5G signaling protocol, so specialized GTP, NGAP, or PFCP analysis would be a natural extension.

## 15. Suggested live demo narrative

1. Start the application and explain that local databases are loaded before serving traffic.
2. Open the dashboard and show interface discovery.
3. Start a small live capture and point out the Socket.IO connection and live counters.
4. Select one external endpoint and explain the GeoIP, ASN, VPN, threat, and risk fields.
5. Show that a VPN result contains individual signals and a confidence classification.
6. Upload a small PCAP and explain the Scapy -> normalized records -> Parquet -> DuckDB path.
7. Run a protocol or top-talker query.
8. Ask the AI agent for a threat summary and explain that it is calling controlled tools.
9. Mention the offline fallback and the performance controls.
10. Close with limitations and the production improvements you would make.

## 16. Strong closing statement

“PacketSense is designed as an explainable network-analysis workflow. It brings packet capture, local enrichment, multi-signal VPN and threat detection, behavioural analysis, SQL analytics, real-time visualization, and an optional natural-language agent into one tool. The important design principle is that the AI improves investigation ergonomics, while the security evidence remains grounded in deterministic, inspectable data.”

## 17. Files to remember before the interview

- [app.py](app.py): application startup, blueprint registration, Socket.IO, database loading.
- [config.py](config.py): settings, caches, counters, and shared runtime state.
- [routes/api.py](routes/api.py): REST endpoints for capture, PCAP loading, stats, and enrichment.
- [routes/agent.py](routes/agent.py): ReAct-style AI agent and controlled analysis tools.
- [services/capture.py](services/capture.py): Scapy capture, event batching, and risk scoring.
- [services/vpn.py](services/vpn.py): multi-signal VPN/Tor detector.
- [services/threat_intel.py](services/threat_intel.py): local feed loading and indexed reputation lookups.
- [services/geo.py](services/geo.py): offline GeoIP and ASN resolution.
- [services/behaviour.py](services/behaviour.py): tunnel, beaconing, and exfiltration signals.
- [src/parsers/scapy_parser.py](src/parsers/scapy_parser.py): PCAP-to-structured-record conversion.
- [src/query/sql_executor.py](src/query/sql_executor.py): DuckDB-backed SQL analytics.
- [static/index.html](static/index.html): single-page dashboard.
- [tests/](tests/): route, offline database, VPN-risk, and regression coverage.
