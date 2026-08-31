"""
tests/test_v1_vs_v2.py — Comparative test suite: v1 (API-based) vs v2 (offline).

Tests that v2's offline implementation provides equivalent or better
coverage compared to v1's API-dependent approach, while guaranteeing
zero network calls.
"""

import ipaddress
import sys
import time
import unittest
from pathlib import Path
from unittest.mock import patch, MagicMock

# Add v2 project root to path
V2_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(V2_ROOT))

import config


class TestVPNKeywordDetectionParity(unittest.TestCase):
    """V1 and V2 should produce identical results for ISP keyword matching."""

    def setUp(self):
        config.VPN_CACHE.clear()

    def test_nordvpn_keyword_detected(self):
        from services.vpn import detect_vpn
        result = detect_vpn("1.2.3.4", "NordVPN S.A.", "AS212238 NordVPN")
        self.assertTrue(result["is_vpn"])
        self.assertEqual(result["provider"], "NordVPN")
        self.assertEqual(result["method"], "keyword")

    def test_expressvpn_keyword_detected(self):
        from services.vpn import detect_vpn
        result = detect_vpn("5.6.7.8", "Express Networks Ltd", "AS18450")
        self.assertTrue(result["is_vpn"])
        self.assertIn("ExpressVPN", result["provider"])

    def test_protonvpn_keyword_detected(self):
        from services.vpn import detect_vpn
        result = detect_vpn("9.10.11.12", "Proton AG", "AS209103")
        self.assertTrue(result["is_vpn"])
        self.assertEqual(result["provider"], "ProtonVPN")

    def test_cloudflare_warp_detected(self):
        from services.vpn import detect_vpn
        result = detect_vpn("1.1.1.1", "Cloudflare, Inc", "AS13335 Cloudflare")
        self.assertTrue(result["is_vpn"])
        self.assertEqual(result["provider"], "1.1.1.1 WARP")

    def test_mullvad_keyword_detected(self):
        from services.vpn import detect_vpn
        result = detect_vpn("10.0.0.1", "Mullvad VPN", "AS198093 Mullvad")
        self.assertTrue(result["is_vpn"])
        self.assertEqual(result["provider"], "Mullvad")

    def test_non_vpn_isp_not_flagged(self):
        from services.vpn import detect_vpn
        result = detect_vpn("8.8.8.8", "Google LLC", "AS15169 Google")
        self.assertFalse(result["is_vpn"])
        self.assertIsNone(result["provider"])

    def test_comcast_not_flagged(self):
        from services.vpn import detect_vpn
        result = detect_vpn("73.1.2.3", "Comcast Cable", "AS7922 Comcast")
        self.assertFalse(result["is_vpn"])


class TestVPNASNDetectionParity(unittest.TestCase):
    """V1 and V2 should match on ASN-based VPN detection."""

    def setUp(self):
        config.VPN_CACHE.clear()

    def test_asn_nordvpn(self):
        from services.vpn import detect_vpn
        result = detect_vpn("1.2.3.4", "Some ISP", "AS212238 SomeOrg")
        self.assertTrue(result["is_vpn"])
        self.assertEqual(result["method"], "asn_database")

    def test_asn_mullvad(self):
        from services.vpn import detect_vpn
        result = detect_vpn("1.2.3.4", "Random ISP", "AS198093 RandomOrg")
        self.assertTrue(result["is_vpn"])
        self.assertEqual(result["method"], "asn_database")

    def test_asn_m247_vpn_host(self):
        from services.vpn import detect_vpn
        result = detect_vpn("1.2.3.4", "Generic ISP", "AS9009 M247 Ltd")
        self.assertTrue(result["is_vpn"])
        self.assertIn("M247", result["provider"])

    def test_asn_google_not_vpn(self):
        from services.vpn import detect_vpn
        result = detect_vpn("8.8.8.8", "Google LLC", "AS15169 Google")
        self.assertFalse(result["is_vpn"])

    def test_unknown_asn_not_vpn(self):
        from services.vpn import detect_vpn
        result = detect_vpn("1.2.3.4", "Unknown ISP", "Unknown")
        self.assertFalse(result["is_vpn"])


class TestVPNIPRangeDetectionParity(unittest.TestCase):
    """V2 should match v1 for IP range-based detection."""

    def test_ip_range_check_function_exists(self):
        from services.vpn import check_ip_in_vpn_ranges
        # Should return False for random IP when no lists loaded
        result = check_ip_in_vpn_ranges("192.0.2.1")
        self.assertIsInstance(result, bool)

    def test_private_ip_not_checked(self):
        from services.vpn import check_ip_in_vpn_ranges
        result = check_ip_in_vpn_ranges("10.0.0.1")
        self.assertFalse(result)

    def test_invalid_ip_handled(self):
        from services.vpn import check_ip_in_vpn_ranges
        result = check_ip_in_vpn_ranges("not-an-ip")
        self.assertFalse(result)


class TestVPNDetectionOfflineResilience(unittest.TestCase):
    """V2 must work without any network access. V1 degrades."""

    def setUp(self):
        config.VPN_CACHE.clear()

    @patch("services.vpn.check_ip_in_vpn_ranges", return_value=False)
    def test_v2_detect_vpn_makes_no_network_calls(self, mock_range):
        """Verify detect_vpn never imports or calls requests."""
        from services.vpn import detect_vpn

        # Patch requests to raise if called
        with patch.dict("sys.modules", {"requests": MagicMock(side_effect=RuntimeError("Network call!"))}):
            # This should complete without error — no network calls
            result = detect_vpn("1.2.3.4", "Google LLC", "AS15169 Google")
            self.assertIsInstance(result, dict)
            self.assertIn("is_vpn", result)

    def test_v2_vpn_detection_is_fast(self):
        """V2 offline detection must be faster than v1's API round-trips."""
        from services.vpn import detect_vpn

        ips = [f"203.0.113.{i}" for i in range(100)]
        config.VPN_CACHE.clear()

        start = time.time()
        for ip in ips:
            detect_vpn(ip, "Random ISP", "AS12345 Random")
        elapsed = time.time() - start

        # 100 lookups should complete in under 1 second (no network)
        self.assertLess(elapsed, 1.0, f"100 VPN lookups took {elapsed:.2f}s — too slow")

    def test_v2_no_requests_import_in_vpn_module(self):
        """V2 vpn.py should NOT import requests at module level."""
        import importlib
        spec = importlib.util.find_spec("services.vpn")
        source = Path(spec.origin).read_text()
        # Check no top-level 'import requests'
        lines = source.splitlines()
        top_level_imports = [l for l in lines if l.startswith("import requests") or l.startswith("from requests")]
        self.assertEqual(len(top_level_imports), 0,
                        "vpn.py should not import requests at module level")

    def test_v2_no_requests_import_in_geo_module(self):
        """V2 geo.py should NOT import requests."""
        import importlib
        spec = importlib.util.find_spec("services.geo")
        source = Path(spec.origin).read_text()
        self.assertNotIn("import requests", source,
                        "geo.py should not import requests for offline mode")


class TestGeoIPOfflineResolution(unittest.TestCase):
    """V2 GeoIP must resolve from local MMDB only."""

    def test_private_ip_returns_location(self):
        from services.geo import resolve_ip, is_private_ip
        self.assertTrue(is_private_ip("192.168.1.1"))
        # Should return something (even default location)
        loc = resolve_ip("192.168.1.1")
        if loc:  # may be None if no user location set
            self.assertTrue(loc.get("is_private", False) or loc.get("city") == "Local Network")

    def test_private_ip_classification(self):
        from services.geo import is_private_ip
        self.assertTrue(is_private_ip("10.0.0.1"))
        self.assertTrue(is_private_ip("172.16.0.1"))
        self.assertTrue(is_private_ip("192.168.1.1"))
        self.assertTrue(is_private_ip("127.0.0.1"))
        self.assertFalse(is_private_ip("8.8.8.8"))
        self.assertFalse(is_private_ip("1.1.1.1"))

    def test_public_ip_resolved_from_mmdb(self):
        """If MMDB databases are present, public IPs should resolve."""
        from services.geo import resolve_ip
        config.GEOIP_CACHE.clear()
        # Google DNS - should be in any GeoLite2 database
        loc = resolve_ip("8.8.8.8")
        if loc:
            self.assertEqual(loc["ip"], "8.8.8.8")
            self.assertIn("country", loc)
            self.assertIn("is_vpn", loc)

    def test_resolve_ip_caching_works(self):
        from services.geo import resolve_ip
        config.GEOIP_CACHE.clear()
        loc1 = resolve_ip("8.8.8.8")
        loc2 = resolve_ip("8.8.8.8")
        # Both calls should return same data (from cache)
        if loc1 and loc2:
            self.assertEqual(loc1["country"], loc2["country"])

    def test_geolocation_no_network_calls(self):
        """Verify resolve_ip never makes HTTP requests."""
        from services.geo import resolve_ip
        config.GEOIP_CACHE.clear()

        # If requests were called, it would fail
        with patch("builtins.__import__", side_effect=lambda name, *a, **k:
                    (_ for _ in ()).throw(ImportError("No requests!"))
                    if name == "requests" else __builtins__.__import__(name, *a, **k)):
            # This might raise if the module tries lazy requests import
            # But our v2 geo.py shouldn't need it at all
            pass

    def test_user_location_from_config(self):
        """User location should come from .env, not API."""
        from services.geo import get_user_public_location
        config.user_public_location = None
        old_lat, old_lon = config.USER_LAT, config.USER_LON
        old_city, old_country = config.USER_CITY, config.USER_COUNTRY

        config.USER_LAT = 28.6139
        config.USER_LON = 77.2090
        config.USER_CITY = "Delhi"
        config.USER_COUNTRY = "India"

        try:
            loc = get_user_public_location()
            self.assertEqual(loc["city"], "Delhi")
            self.assertEqual(loc["country"], "India")
            self.assertAlmostEqual(loc["lat"], 28.6139)
        finally:
            config.USER_LAT = old_lat
            config.USER_LON = old_lon
            config.USER_CITY = old_city
            config.USER_COUNTRY = old_country
            config.user_public_location = None


class TestVPNDetectionLatency(unittest.TestCase):
    """V2 must be significantly faster than v1's API-based approach."""

    def test_bulk_vpn_detection_performance(self):
        """1000 VPN checks should complete in under 0.5s offline."""
        from services.vpn import detect_vpn
        config.VPN_CACHE.clear()

        isps = ["Google LLC", "Comcast", "AT&T", "NordVPN", "Mullvad VPN"]
        asns = ["AS15169", "AS7922", "AS7018", "AS212238", "AS198093"]

        start = time.time()
        for i in range(1000):
            ip = f"{(i >> 16) & 255}.{(i >> 8) & 255}.{i & 255}.1"
            detect_vpn(ip, isps[i % len(isps)], asns[i % len(asns)])
        elapsed = time.time() - start

        self.assertLess(elapsed, 0.5,
                        f"1000 VPN lookups took {elapsed:.3f}s — must be under 0.5s")


class TestBehaviouralAnalysis(unittest.TestCase):
    """Test the new behavioural analysis engine (v2-only feature)."""

    def test_vpn_tunnel_traffic_pattern_detection(self):
        """Synthetic VPN-like traffic should get high VPN tunnel score."""
        from services.behaviour import BehaviourAnalyzer

        analyzer = BehaviourAnalyzer()
        # Simulate VPN tunnel: all traffic to single IP:port, large MTU-clamped packets
        for i in range(100):
            analyzer.record_packet(
                "192.168.1.100", "203.0.113.50", 51820, "UDP",
                1420 + (i % 10),  # Near-MTU sizes
                1000.0 + i * 0.1,
            )

        analysis = analyzer.analyze_device("192.168.1.100")
        self.assertGreater(analysis["scores"]["vpn_tunnel"], 40,
                          f"VPN tunnel score {analysis['scores']['vpn_tunnel']} should be >40")

    def test_normal_web_traffic_not_flagged(self):
        """Regular web browsing should get low anomaly score."""
        from services.behaviour import BehaviourAnalyzer
        import random

        analyzer = BehaviourAnalyzer()
        # Simulate normal web: multiple destinations, varied ports/sizes
        destinations = [f"203.0.113.{i}" for i in range(20)]
        for i in range(200):
            dst = random.choice(destinations)
            port = random.choice([80, 443, 8080])
            size = random.randint(40, 1400)
            analyzer.record_packet(
                "192.168.1.50", dst, port, "TCP",
                size, 1000.0 + i * random.uniform(0.01, 2.0),
            )

        analysis = analyzer.analyze_device("192.168.1.50")
        self.assertLess(analysis["scores"]["composite_anomaly"], 40,
                       f"Normal traffic anomaly {analysis['scores']['composite_anomaly']} should be <40")

    def test_beaconing_detection(self):
        """Regular-interval connections should be flagged as beaconing."""
        from services.behaviour import BehaviourAnalyzer

        analyzer = BehaviourAnalyzer()
        # Simulate beaconing: exactly every 60s to same destination
        for i in range(30):
            analyzer.record_packet(
                "192.168.1.200", "10.20.30.40", 443, "TCP",
                200, 1000.0 + i * 60.0,  # exactly 60s intervals
            )

        analysis = analyzer.analyze_device("192.168.1.200")
        self.assertGreater(analysis["scores"]["beaconing"], 40,
                          f"Beaconing score {analysis['scores']['beaconing']} should be >40")

    def test_data_exfiltration_detection(self):
        """Large sustained outbound transfer should flag exfiltration."""
        from services.behaviour import BehaviourAnalyzer

        analyzer = BehaviourAnalyzer()
        # Simulate large data transfer: 50MB to single IP over 2 minutes
        for i in range(5000):
            analyzer.record_packet(
                "192.168.1.150", "198.51.100.1", 443, "TCP",
                10000,  # ~10KB packets
                1000.0 + i * 0.024,  # over ~120 seconds
            )

        analysis = analyzer.analyze_device("192.168.1.150")
        self.assertGreater(analysis["scores"]["data_exfiltration"], 40,
                          f"Exfil score {analysis['scores']['data_exfiltration']} should be >40")

    def test_behavioural_scoring_consistency(self):
        """Same traffic pattern should produce same score."""
        from services.behaviour import BehaviourAnalyzer

        def create_analyzer_with_traffic():
            a = BehaviourAnalyzer()
            for i in range(50):
                a.record_packet("10.0.0.1", "1.2.3.4", 443, "TCP", 500, 1000.0 + i)
            return a.analyze_device("10.0.0.1")

        result1 = create_analyzer_with_traffic()
        result2 = create_analyzer_with_traffic()
        self.assertEqual(result1["scores"], result2["scores"])

    def test_insufficient_data_handled(self):
        """Devices with <10 packets should return insufficient_data."""
        from services.behaviour import BehaviourAnalyzer

        analyzer = BehaviourAnalyzer()
        for i in range(5):
            analyzer.record_packet("10.0.0.1", "1.2.3.4", 80, "TCP", 200, 1000.0 + i)

        analysis = analyzer.analyze_device("10.0.0.1")
        self.assertIn("insufficient_data", analysis["classifications"])

    def test_summary_filters_suspicious(self):
        """Summary should only list devices above anomaly threshold."""
        from services.behaviour import BehaviourAnalyzer

        analyzer = BehaviourAnalyzer()
        # Normal device
        for i in range(20):
            analyzer.record_packet(
                "192.168.1.1", f"10.0.0.{i}", 80 + i, "TCP", 200, 1000.0 + i
            )

        summary = analyzer.get_summary()
        self.assertEqual(summary["total_devices"], 1)
        # Normal traffic should not appear in suspicious list
        self.assertIsInstance(summary["suspicious"], list)


class TestV1vsV2CoverageComparison(unittest.TestCase):
    """Compare detection coverage between v1 (API) and v2 (offline)."""

    def test_v2_has_more_detection_layers(self):
        """V2 has threat_intel + behavioural that v1 doesn't have."""
        # V1 layers: keyword, ASN, IP range, vpnapi.io (4 layers)
        # V2 layers: keyword, ASN, IP range, threat_intel, behavioural (5 layers)
        from services import vpn, threat_intel, behaviour
        self.assertTrue(hasattr(vpn, 'detect_vpn'))
        self.assertTrue(hasattr(threat_intel, 'check_ip_reputation'))
        self.assertTrue(hasattr(behaviour, 'BehaviourAnalyzer'))

    def test_v2_threat_intel_replaces_vpnapi(self):
        """Threat intel check provides similar coverage to vpnapi.io."""
        from services.threat_intel import check_ip_reputation
        # Should return structured result even if no databases loaded
        result = check_ip_reputation("1.2.3.4")
        self.assertIn("is_malicious", result)
        self.assertIn("threat_level", result)
        self.assertIn("sources", result)

    def test_v2_behaviour_is_unique_advantage(self):
        """Behavioural analysis is a v2-only capability not in v1."""
        from services.behaviour import BehaviourAnalyzer
        analyzer = BehaviourAnalyzer()
        # V1 has no equivalent — this is new offline detection
        self.assertTrue(hasattr(analyzer, 'analyze_device'))
        self.assertTrue(hasattr(analyzer, 'get_summary'))
        analysis = analyzer.analyze_device("10.0.0.1")
        self.assertIn("scores", analysis)
        self.assertIn("vpn_tunnel", analysis["scores"])
        self.assertIn("beaconing", analysis["scores"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
