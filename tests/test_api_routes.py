"""
tests/test_api_routes.py — Comprehensive REST API endpoint tests for 5G-PacketSense v2.

Tests all Blueprint routes registered via routes.api, using Flask's built-in
test client.  Tests are designed to run without live capture or loaded PCAP
data, exercising both success paths and graceful error / empty-state responses.

Actual endpoint mapping (corrected from earlier spec):
  GET  /                          → index (serves static/index.html)
  GET  /api/mode                  → {has_parquet, live_capture, parquet_path}
  GET  /api/local_ips             → {local_ips: [...]}
  GET  /api/interfaces            → {interfaces: [...]}
  GET  /api/capture/stop          → stop capture (GET, not POST)
  GET  /api/live/save             → save captured packets
  GET  /api/stats                 → requires conn (400 without it)
  GET  /api/live/stats            → live stats structure
  GET  /api/live/history          → packet history list
  GET  /api/switch/status         → switch monitoring status
  GET  /api/switch/devices        → devices list
  GET  /api/switch/vpn_alerts     → VPN alerts list
  GET  /api/switch/reset          → reset switch data
  GET  /api/vpn/status            → VPN DB status
  GET  /api/threat_intel/status   → threat intel status
  GET  /api/threat_intel/check/<ip> → IP reputation
  GET  /api/behaviour/device/<ip> → device behaviour (400 without analyzer)
  GET  /api/behaviour/summary     → behaviour summary (400 without analyzer)
  POST /api/load_parquet          → load parquet file
  POST /api/upload_pcap           → upload PCAP file
"""

import io
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

# ── Project root on sys.path ────────────────────────────────────────────────
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import config
from app import app as flask_app


# ── Shared client factory ────────────────────────────────────────────────────

def _make_client():
    """Return a Flask test client with TESTING mode enabled."""
    flask_app.config["TESTING"] = True
    flask_app.config["WTF_CSRF_ENABLED"] = False
    return flask_app.test_client()


# ── Helper: reset shared mutable state ──────────────────────────────────────

def _reset_state():
    """Restore config to a known idle state between tests."""
    config.conn = None
    config.capture_running = False
    config.parquet_path = None
    config.SWITCH_MONITOR_RUNNING = False
    config.switch_devices = {}
    config.switch_vpn_alerts = []
    config.behaviour_analyzer = None
    config.reset_live_stats()
    config.captured_packets.clear()
    config.packet_history.clear()


# ════════════════════════════════════════════════════════════════════════════
# 1 — Static / core informational endpoints
# ════════════════════════════════════════════════════════════════════════════

class TestStaticEndpoints(unittest.TestCase):
    """Tests for the root HTML endpoint and core /api/mode, /api/local_ips,
    /api/interfaces routes."""

    @classmethod
    def setUpClass(cls):
        cls.client = _make_client()

    # ── GET / ────────────────────────────────────────────────────────────────

    def test_root_returns_200(self):
        """GET / must serve static/index.html with HTTP 200."""
        resp = self.client.get("/")
        self.assertEqual(
            resp.status_code, 200,
            "Root endpoint must return HTTP 200"
        )

    def test_root_content_type_is_html(self):
        """GET / content-type must indicate text/html."""
        resp = self.client.get("/")
        ct = resp.content_type.lower()
        self.assertIn("html", ct,
                      f"Expected HTML content-type, got: {ct!r}")

    def test_root_response_not_empty(self):
        """GET / body must contain actual content."""
        resp = self.client.get("/")
        self.assertGreater(len(resp.data), 0,
                           "Root response body must not be empty")

    # ── GET /api/mode ─────────────────────────────────────────────────────────

    def test_get_mode_returns_200(self):
        """GET /api/mode must return HTTP 200."""
        resp = self.client.get("/api/mode")
        self.assertEqual(resp.status_code, 200)

    def test_get_mode_returns_json(self):
        """GET /api/mode must return a parseable JSON body."""
        resp = self.client.get("/api/mode")
        data = resp.get_json()
        self.assertIsNotNone(data, "Response must be valid JSON")

    def test_get_mode_has_required_keys(self):
        """GET /api/mode JSON must contain has_parquet, live_capture,
        parquet_path."""
        resp = self.client.get("/api/mode")
        data = resp.get_json()
        for key in ("has_parquet", "live_capture", "parquet_path"):
            self.assertIn(key, data,
                          f"Mode response must contain '{key}'")

    def test_get_mode_no_capture_idle(self):
        """GET /api/mode with no capture active must report live_capture=False."""
        original = config.capture_running
        try:
            config.capture_running = False
            resp = self.client.get("/api/mode")
            data = resp.get_json()
            self.assertFalse(data["live_capture"],
                             "live_capture must be False when idle")
        finally:
            config.capture_running = original

    def test_get_mode_no_pcap_loaded(self):
        """GET /api/mode with no PCAP must report has_parquet=False."""
        original = config.conn
        try:
            config.conn = None
            resp = self.client.get("/api/mode")
            data = resp.get_json()
            self.assertFalse(data["has_parquet"],
                             "has_parquet must be False when conn is None")
        finally:
            config.conn = original

    # ── GET /api/local_ips ────────────────────────────────────────────────────

    def test_get_local_ips_returns_200(self):
        """GET /api/local_ips must return HTTP 200."""
        resp = self.client.get("/api/local_ips")
        self.assertEqual(resp.status_code, 200)

    def test_get_local_ips_returns_local_ips_key(self):
        """GET /api/local_ips JSON must contain a 'local_ips' list (not 'ips')."""
        resp = self.client.get("/api/local_ips")
        data = resp.get_json()
        self.assertIsNotNone(data)
        self.assertIn("local_ips", data,
                      "Response must use 'local_ips' key (not 'ips')")
        self.assertIsInstance(data["local_ips"], list,
                              "'local_ips' must be a list")

    # ── GET /api/interfaces ───────────────────────────────────────────────────

    def test_get_interfaces_returns_200(self):
        """GET /api/interfaces must return HTTP 200."""
        resp = self.client.get("/api/interfaces")
        self.assertEqual(resp.status_code, 200)

    def test_get_interfaces_has_interfaces_list(self):
        """GET /api/interfaces JSON must contain an 'interfaces' list."""
        resp = self.client.get("/api/interfaces")
        data = resp.get_json()
        self.assertIsNotNone(data)
        self.assertIn("interfaces", data,
                      "Response must contain 'interfaces'")
        self.assertIsInstance(data["interfaces"], list,
                              "'interfaces' must be a list")

    def test_get_interfaces_entries_have_name_key(self):
        """Each interface entry in GET /api/interfaces must have a 'name' key."""
        resp = self.client.get("/api/interfaces")
        data = resp.get_json()
        for iface in data.get("interfaces", []):
            self.assertIn("name", iface,
                          "Each interface entry must have a 'name' key")


# ════════════════════════════════════════════════════════════════════════════
# 2 — Capture control endpoints
# ════════════════════════════════════════════════════════════════════════════

class TestCaptureEndpoints(unittest.TestCase):
    """Tests for capture stop (GET /api/capture/stop) and live save
    (GET /api/live/save)."""

    @classmethod
    def setUpClass(cls):
        cls.client = _make_client()

    def setUp(self):
        _reset_state()

    def test_stop_capture_returns_200(self):
        """GET /api/capture/stop with no active capture must return HTTP 200."""
        resp = self.client.get("/api/capture/stop")
        self.assertEqual(resp.status_code, 200,
                         "Stop capture must always return 200")

    def test_stop_capture_returns_status_key(self):
        """GET /api/capture/stop JSON must include a 'status' key."""
        resp = self.client.get("/api/capture/stop")
        data = resp.get_json()
        self.assertIsNotNone(data, "Response must be valid JSON")
        self.assertIn("status", data,
                      "Stop response must include 'status'")

    def test_stop_capture_status_is_stopped(self):
        """GET /api/capture/stop sets status='stopped'."""
        resp = self.client.get("/api/capture/stop")
        data = resp.get_json()
        self.assertEqual(data.get("status"), "stopped",
                         "Status must be 'stopped' after stopping")

    def test_save_live_no_data_returns_error(self):
        """GET /api/live/save with no packets captured returns 400 or error JSON."""
        config.capture_running = False
        config.captured_packets.clear()

        resp = self.client.get("/api/live/save")
        data = resp.get_json()
        self.assertIsNotNone(data, "Response must be valid JSON")
        # Endpoint returns 400 with error when nothing to save
        self.assertTrue(
            resp.status_code == 400 or "error" in data,
            f"Expected 400 or error JSON, got {resp.status_code}: {data}"
        )


# ════════════════════════════════════════════════════════════════════════════
# 3 — Stats and live monitoring endpoints
# ════════════════════════════════════════════════════════════════════════════

class TestStatsEndpoints(unittest.TestCase):
    """Tests for GET /api/stats, /api/live/stats, /api/live/history."""

    @classmethod
    def setUpClass(cls):
        cls.client = _make_client()

    def setUp(self):
        _reset_state()

    def tearDown(self):
        # Close any DuckDB connection opened during the test
        if config.conn:
            try:
                config.conn.close()
            except Exception:
                pass
        config.conn = None
        config.parquet_path = None

    # ── GET /api/stats ────────────────────────────────────────────────────────

    def test_get_stats_without_pcap_returns_400(self):
        """GET /api/stats with no PCAP loaded must return HTTP 400."""
        resp = self.client.get("/api/stats")
        self.assertEqual(resp.status_code, 400,
                         "Stats must 400 when no PCAP is loaded")

    def test_get_stats_without_pcap_error_json(self):
        """GET /api/stats with no PCAP loaded must include 'error' in JSON."""
        resp = self.client.get("/api/stats")
        data = resp.get_json()
        self.assertIsNotNone(data)
        self.assertIn("error", data,
                      "Stats error response must include 'error' key")

    # ── GET /api/live/stats ───────────────────────────────────────────────────

    def test_get_live_stats_returns_200(self):
        """GET /api/live/stats must always return HTTP 200."""
        resp = self.client.get("/api/live/stats")
        self.assertEqual(resp.status_code, 200)

    def test_get_live_stats_has_packet_keys(self):
        """GET /api/live/stats must include total_packets, tcp_packets,
        udp_packets, unique_ips, total_bytes, bandwidth_bps, capture_running."""
        resp = self.client.get("/api/live/stats")
        data = resp.get_json()
        self.assertIsNotNone(data, "Live stats response must be valid JSON")
        expected_keys = [
            "total_packets", "tcp_packets", "udp_packets",
            "unique_ips", "total_bytes", "bandwidth_bps", "capture_running",
        ]
        for key in expected_keys:
            self.assertIn(key, data,
                          f"Live stats must contain '{key}'")

    def test_get_live_stats_zero_when_idle(self):
        """GET /api/live/stats with no capture active reports zero packets/bytes."""
        config.reset_live_stats()
        resp = self.client.get("/api/live/stats")
        data = resp.get_json()
        self.assertEqual(data["total_packets"], 0,
                         "No capture — total_packets must be 0")
        self.assertEqual(data["total_bytes"], 0,
                         "No capture — total_bytes must be 0")

    def test_get_live_stats_capture_running_false_when_idle(self):
        """GET /api/live/stats reports capture_running=False when idle."""
        resp = self.client.get("/api/live/stats")
        data = resp.get_json()
        self.assertFalse(data["capture_running"],
                         "capture_running must be False when idle")

    def test_get_live_stats_has_top_talkers_list(self):
        """GET /api/live/stats response must include 'top_talkers' list."""
        resp = self.client.get("/api/live/stats")
        data = resp.get_json()
        self.assertIn("top_talkers", data,
                      "Live stats must include 'top_talkers'")
        self.assertIsInstance(data["top_talkers"], list,
                              "'top_talkers' must be a list")

    def test_get_live_stats_has_vpn_ips_count(self):
        """GET /api/live/stats response must include 'vpn_ips_count' key."""
        resp = self.client.get("/api/live/stats")
        data = resp.get_json()
        self.assertIn("vpn_ips_count", data,
                      "Live stats must include 'vpn_ips_count'")

    # ── GET /api/live/history ─────────────────────────────────────────────────

    def test_get_live_history_returns_200(self):
        """GET /api/live/history must always return HTTP 200."""
        resp = self.client.get("/api/live/history")
        self.assertEqual(resp.status_code, 200)

    def test_get_live_history_returns_list(self):
        """GET /api/live/history body must be a JSON list."""
        resp = self.client.get("/api/live/history")
        data = resp.get_json()
        self.assertIsInstance(data, list,
                              "Live history response must be a JSON list")

    def test_get_live_history_empty_when_idle(self):
        """GET /api/live/history returns empty list when no packets captured."""
        config.packet_history.clear()
        resp = self.client.get("/api/live/history")
        data = resp.get_json()
        self.assertEqual(data, [],
                         "No packets — history must be an empty list")


# ════════════════════════════════════════════════════════════════════════════
# 4 — VPN detection database status
# ════════════════════════════════════════════════════════════════════════════

class TestVPNDBEndpoints(unittest.TestCase):
    """Tests for GET /api/vpn/status (VPN detection DB status)."""

    @classmethod
    def setUpClass(cls):
        cls.client = _make_client()

    def test_vpn_db_status_returns_200(self):
        """GET /api/vpn/status must return HTTP 200."""
        resp = self.client.get("/api/vpn/status")
        self.assertEqual(resp.status_code, 200)

    def test_vpn_db_status_has_required_keys(self):
        """GET /api/vpn/status must include ip_ranges_loaded, asn_entries,
        keyword_providers, cached_lookups, offline_mode, sources."""
        resp = self.client.get("/api/vpn/status")
        data = resp.get_json()
        self.assertIsNotNone(data, "VPN status must be valid JSON")
        for key in (
            "ip_ranges_loaded", "asn_entries", "keyword_providers",
            "cached_lookups", "offline_mode", "sources",
        ):
            self.assertIn(key, data,
                          f"VPN status must contain '{key}'")

    def test_vpn_db_status_offline_mode_true(self):
        """GET /api/vpn/status must always report offline_mode=True."""
        resp = self.client.get("/api/vpn/status")
        data = resp.get_json()
        self.assertTrue(data.get("offline_mode"),
                        "System operates offline — offline_mode must be True")

    def test_vpn_db_status_sources_is_dict(self):
        """GET /api/vpn/status 'sources' field must be a dict."""
        resp = self.client.get("/api/vpn/status")
        data = resp.get_json()
        self.assertIsInstance(data.get("sources"), dict,
                              "'sources' must be a dict")

    def test_vpn_db_status_asn_entries_non_negative(self):
        """GET /api/vpn/status 'asn_entries' must be a non-negative integer."""
        resp = self.client.get("/api/vpn/status")
        data = resp.get_json()
        self.assertGreaterEqual(data["asn_entries"], 0,
                                "'asn_entries' must be >= 0")

    def test_vpn_db_status_threat_intel_loaded_is_bool(self):
        """GET /api/vpn/status 'threat_intel_loaded' must be a boolean."""
        resp = self.client.get("/api/vpn/status")
        data = resp.get_json()
        self.assertIsInstance(data.get("threat_intel_loaded"), bool,
                              "'threat_intel_loaded' must be a boolean")


# ════════════════════════════════════════════════════════════════════════════
# 5 — Threat intelligence endpoints
# ════════════════════════════════════════════════════════════════════════════

class TestThreatIntelEndpoints(unittest.TestCase):
    """Tests for GET /api/threat_intel/status and
    GET /api/threat_intel/check/<ip>."""

    @classmethod
    def setUpClass(cls):
        cls.client = _make_client()

    # ── GET /api/threat_intel/status ──────────────────────────────────────────

    def test_threat_intel_status_returns_200(self):
        """GET /api/threat_intel/status must return HTTP 200."""
        resp = self.client.get("/api/threat_intel/status")
        self.assertEqual(resp.status_code, 200)

    def test_threat_intel_status_has_loaded_key(self):
        """GET /api/threat_intel/status must include 'loaded' boolean."""
        resp = self.client.get("/api/threat_intel/status")
        data = resp.get_json()
        self.assertIsNotNone(data)
        self.assertIn("loaded", data,
                      "Threat intel status must include 'loaded'")
        self.assertIsInstance(data["loaded"], bool,
                              "'loaded' must be a boolean")

    def test_threat_intel_status_has_sources_key(self):
        """GET /api/threat_intel/status must include 'sources' dict."""
        resp = self.client.get("/api/threat_intel/status")
        data = resp.get_json()
        self.assertIn("sources", data,
                      "Threat intel status must include 'sources'")
        self.assertIsInstance(data["sources"], dict,
                              "'sources' must be a dict")

    # ── GET /api/threat_intel/check/<ip> ─────────────────────────────────────

    def test_threat_intel_check_valid_ip_returns_200(self):
        """GET /api/threat_intel/check/8.8.8.8 must return HTTP 200."""
        resp = self.client.get("/api/threat_intel/check/8.8.8.8")
        self.assertEqual(resp.status_code, 200)

    def test_threat_intel_check_has_is_malicious(self):
        """GET /api/threat_intel/check/8.8.8.8 must include 'is_malicious'."""
        resp = self.client.get("/api/threat_intel/check/8.8.8.8")
        data = resp.get_json()
        self.assertIsNotNone(data, "IP check must return JSON")
        self.assertIn("is_malicious", data,
                      "IP check must include 'is_malicious'")

    def test_threat_intel_check_private_ip_not_malicious(self):
        """Private IPs (192.168.x.x) must never be flagged as malicious."""
        resp = self.client.get("/api/threat_intel/check/192.168.1.1")
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertFalse(data.get("is_malicious"),
                         "192.168.1.1 (private) must not be malicious")

    def test_threat_intel_check_loopback_not_malicious(self):
        """Loopback 127.0.0.1 must never be flagged as malicious."""
        resp = self.client.get("/api/threat_intel/check/127.0.0.1")
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertFalse(data.get("is_malicious"),
                         "127.0.0.1 (loopback) must not be malicious")

    def test_threat_intel_check_has_threat_level(self):
        """GET /api/threat_intel/check/<ip> must include 'threat_level'."""
        resp = self.client.get("/api/threat_intel/check/8.8.8.8")
        data = resp.get_json()
        self.assertIn("threat_level", data,
                      "IP check must include 'threat_level'")


# ════════════════════════════════════════════════════════════════════════════
# 6 — Switch monitoring endpoints
# ════════════════════════════════════════════════════════════════════════════

class TestSwitchEndpoints(unittest.TestCase):
    """Tests for GET /api/switch/status, /api/switch/devices,
    /api/switch/vpn_alerts, and /api/switch/reset."""

    @classmethod
    def setUpClass(cls):
        cls.client = _make_client()

    def setUp(self):
        """Reset switch state to idle before each test."""
        config.SWITCH_MONITOR_RUNNING = False
        config.switch_devices = {}
        config.switch_vpn_alerts = []

    # ── GET /api/switch/status ────────────────────────────────────────────────

    def test_switch_status_returns_200(self):
        """GET /api/switch/status must return HTTP 200."""
        resp = self.client.get("/api/switch/status")
        self.assertEqual(resp.status_code, 200)

    def test_switch_status_has_monitoring_bool(self):
        """GET /api/switch/status must include 'monitoring' boolean."""
        resp = self.client.get("/api/switch/status")
        data = resp.get_json()
        self.assertIsNotNone(data)
        self.assertIn("monitoring", data,
                      "Switch status must include 'monitoring'")
        self.assertIsInstance(data["monitoring"], bool,
                              "'monitoring' must be a boolean")

    def test_switch_status_idle(self):
        """GET /api/switch/status with no active monitoring reports
        monitoring=False."""
        resp = self.client.get("/api/switch/status")
        data = resp.get_json()
        self.assertFalse(data["monitoring"],
                         "No monitoring active — 'monitoring' must be False")

    def test_switch_status_has_device_counts(self):
        """GET /api/switch/status must include devices_count and
        vpn_devices_count."""
        resp = self.client.get("/api/switch/status")
        data = resp.get_json()
        self.assertIn("devices_count", data)
        self.assertIn("vpn_devices_count", data)

    # ── GET /api/switch/devices ───────────────────────────────────────────────

    def test_switch_devices_returns_200(self):
        """GET /api/switch/devices must return HTTP 200."""
        resp = self.client.get("/api/switch/devices")
        self.assertEqual(resp.status_code, 200)

    def test_switch_devices_has_devices_list(self):
        """GET /api/switch/devices must return a 'devices' list."""
        resp = self.client.get("/api/switch/devices")
        data = resp.get_json()
        self.assertIsNotNone(data)
        self.assertIn("devices", data,
                      "Response must include 'devices'")
        self.assertIsInstance(data["devices"], list,
                              "'devices' must be a list")

    def test_switch_devices_empty_when_idle(self):
        """GET /api/switch/devices with no monitoring returns empty list."""
        resp = self.client.get("/api/switch/devices")
        data = resp.get_json()
        self.assertEqual(data["devices"], [],
                         "No monitoring — device list must be empty")

    def test_switch_devices_has_total_key(self):
        """GET /api/switch/devices must include 'total' count."""
        resp = self.client.get("/api/switch/devices")
        data = resp.get_json()
        self.assertIn("total", data,
                      "Response must include 'total'")

    # ── GET /api/switch/vpn_alerts ────────────────────────────────────────────

    def test_switch_vpn_alerts_returns_200(self):
        """GET /api/switch/vpn_alerts must return HTTP 200."""
        resp = self.client.get("/api/switch/vpn_alerts")
        self.assertEqual(resp.status_code, 200)

    def test_switch_vpn_alerts_has_alerts_list(self):
        """GET /api/switch/vpn_alerts must return an 'alerts' list."""
        resp = self.client.get("/api/switch/vpn_alerts")
        data = resp.get_json()
        self.assertIsNotNone(data)
        self.assertIn("alerts", data,
                      "Response must include 'alerts'")
        self.assertIsInstance(data["alerts"], list,
                              "'alerts' must be a list")

    def test_switch_vpn_alerts_empty_when_idle(self):
        """GET /api/switch/vpn_alerts with no alerts returns empty list."""
        resp = self.client.get("/api/switch/vpn_alerts")
        data = resp.get_json()
        self.assertEqual(data["alerts"], [],
                         "No alerts — alerts list must be empty")

    def test_switch_vpn_alerts_has_total_alerts(self):
        """GET /api/switch/vpn_alerts must include 'total_alerts' count."""
        resp = self.client.get("/api/switch/vpn_alerts")
        data = resp.get_json()
        self.assertIn("total_alerts", data,
                      "Response must include 'total_alerts'")

    # ── GET /api/switch/reset ─────────────────────────────────────────────────

    def test_switch_reset_returns_200(self):
        """GET /api/switch/reset must return HTTP 200."""
        resp = self.client.get("/api/switch/reset")
        self.assertEqual(resp.status_code, 200)

    def test_switch_reset_status_is_reset(self):
        """GET /api/switch/reset must return status='reset'."""
        resp = self.client.get("/api/switch/reset")
        data = resp.get_json()
        self.assertEqual(data.get("status"), "reset",
                         "Reset response must include status='reset'")

    def test_switch_reset_clears_devices_and_alerts(self):
        """GET /api/switch/reset clears populated devices and alerts."""
        # Populate fake switch state
        config.switch_devices = {
            "192.168.1.10": {"total_packets": 100, "total_bytes": 5000},
            "192.168.1.11": {"total_packets": 50,  "total_bytes": 2500},
        }
        config.switch_vpn_alerts = [
            {
                "device_ip": "192.168.1.10",
                "vpn_server_ip": "1.1.1.1",
                "provider": "TestVPN",
                "severity": "high",
            }
        ]

        resp = self.client.get("/api/switch/reset")
        data = resp.get_json()
        self.assertEqual(data.get("cleared_devices"), 2,
                         "Should report 2 cleared devices")
        self.assertEqual(data.get("cleared_alerts"), 1,
                         "Should report 1 cleared alert")
        # State should now be empty
        self.assertEqual(len(config.switch_devices), 0)
        self.assertEqual(len(config.switch_vpn_alerts), 0)


# ════════════════════════════════════════════════════════════════════════════
# 7 — PCAP upload (bad-request paths)
# ════════════════════════════════════════════════════════════════════════════

class TestPCAPUploadEndpoints(unittest.TestCase):
    """Tests for POST /api/upload_pcap — bad request paths only (no real
    scapy parsing is exercised here)."""

    @classmethod
    def setUpClass(cls):
        cls.client = _make_client()

    def test_upload_no_file_field_returns_400(self):
        """POST /api/upload_pcap with no file field must return HTTP 400."""
        resp = self.client.post("/api/upload_pcap", data={})
        self.assertEqual(resp.status_code, 400,
                         "Missing file field must return 400")

    def test_upload_no_file_includes_error(self):
        """POST /api/upload_pcap with no file includes 'error' in JSON."""
        resp = self.client.post("/api/upload_pcap", data={})
        data = resp.get_json()
        self.assertIsNotNone(data)
        self.assertIn("error", data,
                      "Missing file response must include 'error'")

    def test_upload_wrong_extension_txt_returns_400(self):
        """POST /api/upload_pcap with .txt file must return HTTP 400."""
        fake_file = (io.BytesIO(b"fake content"), "capture.txt")
        resp = self.client.post(
            "/api/upload_pcap",
            data={"file": fake_file},
            content_type="multipart/form-data",
        )
        self.assertEqual(resp.status_code, 400,
                         "Wrong extension (.txt) must return 400")

    def test_upload_wrong_extension_csv_returns_400(self):
        """POST /api/upload_pcap with .csv file must return HTTP 400."""
        fake_file = (io.BytesIO(b"a,b,c\n1,2,3"), "data.csv")
        resp = self.client.post(
            "/api/upload_pcap",
            data={"file": fake_file},
            content_type="multipart/form-data",
        )
        self.assertEqual(resp.status_code, 400,
                         "Wrong extension (.csv) must return 400")

    def test_upload_wrong_extension_includes_error(self):
        """POST /api/upload_pcap with wrong extension includes 'error' in JSON."""
        fake_file = (io.BytesIO(b"fake"), "capture.json")
        resp = self.client.post(
            "/api/upload_pcap",
            data={"file": fake_file},
            content_type="multipart/form-data",
        )
        data = resp.get_json()
        self.assertIsNotNone(data)
        self.assertIn("error", data,
                      "Wrong-extension response must include 'error'")

    def test_upload_empty_filename_returns_error(self):
        """POST /api/upload_pcap with blank filename returns 400 or 500."""
        fake_file = (io.BytesIO(b""), "")
        resp = self.client.post(
            "/api/upload_pcap",
            data={"file": fake_file},
            content_type="multipart/form-data",
        )
        self.assertIn(resp.status_code, [400, 500],
                      "Empty filename must return 400 or 500")


# ════════════════════════════════════════════════════════════════════════════
# 8 — Parquet loading (POST /api/load_parquet)
# ════════════════════════════════════════════════════════════════════════════

class TestParquetLoading(unittest.TestCase):
    """Tests for POST /api/load_parquet — missing-file error path and a
    success path using a real temporary parquet file."""

    @classmethod
    def setUpClass(cls):
        cls.client = _make_client()

    def setUp(self):
        config.conn = None
        config.parquet_path = None

    def tearDown(self):
        if config.conn:
            try:
                config.conn.close()
            except Exception:
                pass
        config.conn = None
        config.parquet_path = None

    def test_load_parquet_no_path_returns_400(self):
        """POST /api/load_parquet with no 'path' field must return HTTP 400."""
        resp = self.client.post("/api/load_parquet", json={})
        self.assertEqual(resp.status_code, 400,
                         "Missing path must return 400")

    def test_load_parquet_no_path_has_error(self):
        """POST /api/load_parquet with no path includes 'error' in JSON."""
        resp = self.client.post("/api/load_parquet", json={})
        data = resp.get_json()
        self.assertIn("error", data,
                      "Missing path response must include 'error'")

    def test_load_parquet_missing_file_returns_404(self):
        """POST /api/load_parquet with non-existent path must return 404."""
        resp = self.client.post(
            "/api/load_parquet",
            json={"path": "/nonexistent/totally/fake/file.parquet"},
        )
        self.assertEqual(resp.status_code, 404,
                         "Non-existent parquet path must return 404")

    def test_load_parquet_missing_file_has_error(self):
        """POST /api/load_parquet with missing file includes 'error' in JSON."""
        resp = self.client.post(
            "/api/load_parquet",
            json={"path": "/nonexistent/totally/fake/file.parquet"},
        )
        data = resp.get_json()
        self.assertIsNotNone(data)
        self.assertIn("error", data,
                      "Missing file response must include 'error'")

    def test_load_parquet_valid_file_returns_success(self):
        """POST /api/load_parquet with a valid minimal parquet returns success."""
        try:
            import pandas as pd
        except ImportError:
            self.skipTest("pandas not installed — skipping parquet round-trip test")

        with tempfile.NamedTemporaryFile(suffix=".parquet", delete=False) as f:
            tmp_path = f.name

        try:
            # Create a minimal parquet matching the packets schema
            df = pd.DataFrame(
                {
                    "frame_no":  [1, 2, 3],
                    "timestamp": [1700000000.0, 1700000001.0, 1700000002.0],
                    "src_ip":    ["192.168.1.1", "192.168.1.2", "8.8.8.8"],
                    "dst_ip":    ["8.8.8.8",     "8.8.4.4",     "192.168.1.1"],
                    "protocol":  ["TCP",          "UDP",         "TCP"],
                    "length":    [100,            200,           150],
                    "ttl":       [64,             128,           64],
                    "src_port":  [12345,          53,            443],
                    "dst_port":  [80,             12345,         12345],
                }
            )
            df.to_parquet(tmp_path, index=False)

            resp = self.client.post(
                "/api/load_parquet",
                json={"path": tmp_path},
            )
            data = resp.get_json()
            self.assertEqual(
                resp.status_code, 200,
                f"Valid parquet should return 200; got {resp.status_code}: {data}",
            )
            self.assertEqual(
                data.get("status"), "success",
                f"Expected status='success', got: {data}",
            )
        finally:
            Path(tmp_path).unlink(missing_ok=True)

    def test_load_parquet_sets_config_conn(self):
        """POST /api/load_parquet with valid file sets config.conn to non-None."""
        try:
            import pandas as pd
        except ImportError:
            self.skipTest("pandas not installed")

        with tempfile.NamedTemporaryFile(suffix=".parquet", delete=False) as f:
            tmp_path = f.name

        try:
            pd.DataFrame({"frame_no": [1], "timestamp": [1.0],
                          "src_ip": ["1.1.1.1"], "dst_ip": ["2.2.2.2"],
                          "protocol": ["TCP"], "length": [60],
                          "ttl": [64], "src_port": [1234], "dst_port": [80]}
                         ).to_parquet(tmp_path, index=False)

            self.client.post("/api/load_parquet", json={"path": tmp_path})
            self.assertIsNotNone(config.conn,
                                 "Successful load must set config.conn")
        finally:
            Path(tmp_path).unlink(missing_ok=True)


# ════════════════════════════════════════════════════════════════════════════
# 9 — Behavioural analysis endpoints
# ════════════════════════════════════════════════════════════════════════════

class TestBehaviourEndpoints(unittest.TestCase):
    """Tests for GET /api/behaviour/device/<ip> and GET /api/behaviour/summary."""

    @classmethod
    def setUpClass(cls):
        cls.client = _make_client()

    def setUp(self):
        """Ensure behaviour_analyzer is None before each test."""
        config.behaviour_analyzer = None

    def tearDown(self):
        config.behaviour_analyzer = None

    # ── No analyzer active ────────────────────────────────────────────────────

    def test_device_behaviour_no_analyzer_returns_400(self):
        """GET /api/behaviour/device/<ip> without analyzer must return 400."""
        resp = self.client.get("/api/behaviour/device/192.168.1.1")
        self.assertEqual(resp.status_code, 400,
                         "No analyzer — must return 400")

    def test_device_behaviour_no_analyzer_has_error(self):
        """GET /api/behaviour/device/<ip> without analyzer includes 'error'."""
        resp = self.client.get("/api/behaviour/device/192.168.1.1")
        data = resp.get_json()
        self.assertIsNotNone(data)
        self.assertIn("error", data,
                      "No-analyzer response must include 'error'")

    def test_behaviour_summary_no_analyzer_returns_400(self):
        """GET /api/behaviour/summary without analyzer must return 400."""
        resp = self.client.get("/api/behaviour/summary")
        self.assertEqual(resp.status_code, 400,
                         "No analyzer — must return 400")

    def test_behaviour_summary_no_analyzer_has_error(self):
        """GET /api/behaviour/summary without analyzer includes 'error'."""
        resp = self.client.get("/api/behaviour/summary")
        data = resp.get_json()
        self.assertIsNotNone(data)
        self.assertIn("error", data,
                      "No-analyzer response must include 'error'")

    # ── With a mock analyzer ──────────────────────────────────────────────────

    def test_device_behaviour_with_mock_analyzer(self):
        """GET /api/behaviour/device/<ip> with mock analyzer returns 200."""
        mock_analyzer = MagicMock()
        mock_analyzer.analyze_device.return_value = {
            "device": "192.168.1.50",
            "packets_analyzed": 200,
            "anomaly_score": 0.05,
        }
        config.behaviour_analyzer = mock_analyzer

        resp = self.client.get("/api/behaviour/device/192.168.1.50")
        self.assertEqual(resp.status_code, 200,
                         "Mock analyzer present — should return 200")
        data = resp.get_json()
        self.assertIsNotNone(data, "Response must be valid JSON")
        mock_analyzer.analyze_device.assert_called_once_with("192.168.1.50")

    def test_behaviour_summary_with_mock_analyzer(self):
        """GET /api/behaviour/summary with mock analyzer returns 200."""
        mock_analyzer = MagicMock()
        mock_analyzer.get_summary.return_value = {
            "total_devices": 5,
            "anomalous_devices": 1,
            "top_anomalous": [],
        }
        config.behaviour_analyzer = mock_analyzer

        resp = self.client.get("/api/behaviour/summary")
        self.assertEqual(resp.status_code, 200,
                         "Mock analyzer present — should return 200")
        data = resp.get_json()
        self.assertIsNotNone(data, "Response must be valid JSON")
        mock_analyzer.get_summary.assert_called_once()


if __name__ == "__main__":
    unittest.main(verbosity=2)
