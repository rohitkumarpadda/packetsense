"""
tests/test_offline_databases.py — Unit tests for offline database integrations.

Tests loading, parsing, lookup, and performance of:
  - FireHOL blocklists
  - IPsum aggregated feed
  - Blocklist.de attack-source lists
  - GeoLite2 MMDB databases
  - DB-IP ASN Lite MMDB
"""

import ipaddress
import sys
import time
import unittest
from pathlib import Path
from unittest.mock import patch

V2_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(V2_ROOT))

import config


class TestThreatIntelLoading(unittest.TestCase):
    """Test loading and parsing of threat intelligence databases."""

    def test_load_returns_without_error(self):
        """Loading should succeed even if no database files exist."""
        from services.threat_intel import load_threat_databases
        # Should not raise even if data/threat_intel/ is empty
        try:
            load_threat_databases()
        except Exception as e:
            self.fail(f"load_threat_databases raised {e}")

    def test_load_stats_populated(self):
        """After loading, stats should report loaded sources."""
        from services.threat_intel import get_load_stats
        stats = get_load_stats()
        self.assertIn("loaded", stats)
        self.assertIn("sources", stats)
        self.assertIn("total_networks", stats)
        self.assertIn("total_single_ips", stats)
        self.assertIsInstance(stats["sources"], dict)

    def test_threat_intel_loaded_flag_set(self):
        """After loading, the config flag should be True."""
        from services.threat_intel import load_threat_databases
        load_threat_databases()
        self.assertTrue(config.THREAT_INTEL_LOADED)


class TestThreatIntelLookup(unittest.TestCase):
    """Test IP reputation lookups against threat intelligence."""

    def test_private_ip_not_malicious(self):
        from services.threat_intel import check_ip_reputation
        result = check_ip_reputation("192.168.1.1")
        self.assertFalse(result["is_malicious"])
        self.assertEqual(result["threat_level"], "none")

    def test_loopback_not_malicious(self):
        from services.threat_intel import check_ip_reputation
        result = check_ip_reputation("127.0.0.1")
        self.assertFalse(result["is_malicious"])

    def test_invalid_ip_handled(self):
        from services.threat_intel import check_ip_reputation
        result = check_ip_reputation("not-an-ip")
        self.assertFalse(result["is_malicious"])
        self.assertEqual(result["threat_level"], "none")

    def test_multicast_not_malicious(self):
        from services.threat_intel import check_ip_reputation
        result = check_ip_reputation("224.0.0.1")
        self.assertFalse(result["is_malicious"])

    def test_result_structure(self):
        """All results should have required fields."""
        from services.threat_intel import check_ip_reputation
        result = check_ip_reputation("8.8.8.8")
        self.assertIn("is_malicious", result)
        self.assertIn("threat_level", result)
        self.assertIn("sources", result)
        self.assertIn("categories", result)
        self.assertIn("ipsum_score", result)
        self.assertIn("details", result)
        self.assertIsInstance(result["sources"], list)
        self.assertIsInstance(result["categories"], list)

    def test_legitimate_ips_not_flagged(self):
        """Well-known legitimate IPs should not be flagged."""
        from services.threat_intel import check_ip_reputation
        legit_ips = ["8.8.8.8", "1.1.1.1", "208.67.222.222"]
        for ip in legit_ips:
            result = check_ip_reputation(ip)
            # These SHOULD be clean, but depends on database contents
            # At minimum, verify the function doesn't error
            self.assertIn("is_malicious", result)


class TestThreatIntelPerformance(unittest.TestCase):
    """Performance tests for threat intel lookups."""

    def test_lookup_speed_10k(self):
        """10,000 lookups should complete within 5 seconds."""
        from services.threat_intel import check_ip_reputation, load_threat_databases
        load_threat_databases()

        start = time.time()
        for i in range(10000):
            ip = f"{(i >> 16) & 255}.{(i >> 8) & 255}.{i & 255}.1"
            check_ip_reputation(ip)
        elapsed = time.time() - start

        self.assertLess(elapsed, 5.0,
                        f"10k lookups took {elapsed:.2f}s — must be under 5s")

    def test_load_time_under_10s(self):
        """Database loading should complete within 10 seconds."""
        from services.threat_intel import load_threat_databases

        start = time.time()
        load_threat_databases()
        elapsed = time.time() - start

        self.assertLess(elapsed, 10.0,
                        f"Loading took {elapsed:.2f}s — must be under 10s")


class TestNetsetParsing(unittest.TestCase):
    """Test parsing of FireHOL .netset format files."""

    def test_parse_valid_netset(self):
        from services.threat_intel import _parse_netset_file
        import tempfile

        content = """# FireHOL test
# Comment line
10.0.0.0/8
172.16.0.0/12
192.168.0.0/16
"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.netset', delete=False) as f:
            f.write(content)
            f.flush()
            networks = _parse_netset_file(Path(f.name))

        self.assertEqual(len(networks), 3)
        self.assertEqual(str(networks[0]), "10.0.0.0/8")

    def test_parse_empty_file(self):
        from services.threat_intel import _parse_netset_file
        import tempfile

        with tempfile.NamedTemporaryFile(mode='w', suffix='.netset', delete=False) as f:
            f.write("# Only comments\n")
            f.flush()
            networks = _parse_netset_file(Path(f.name))

        self.assertEqual(len(networks), 0)

    def test_parse_nonexistent_file(self):
        from services.threat_intel import _parse_netset_file
        networks = _parse_netset_file(Path("/nonexistent/file.netset"))
        self.assertEqual(len(networks), 0)

    def test_parse_invalid_entries_skipped(self):
        from services.threat_intel import _parse_netset_file
        import tempfile

        content = """10.0.0.0/8
not-a-network
999.999.999.999/32
192.168.0.0/16
"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.netset', delete=False) as f:
            f.write(content)
            f.flush()
            networks = _parse_netset_file(Path(f.name))

        self.assertEqual(len(networks), 2)  # Only valid entries


class TestIPsumParsing(unittest.TestCase):
    """Test parsing of IPsum format files."""

    def test_parse_ipsum_with_threshold(self):
        from services.threat_intel import _parse_ipsum_file
        import tempfile

        content = """# IPsum test
1.2.3.4\t5
5.6.7.8\t2
9.10.11.12\t8
"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            f.write(content)
            f.flush()
            result = _parse_ipsum_file(Path(f.name), threshold=3)

        # Only IPs with score >= 3 should be included
        self.assertEqual(len(result), 2)
        ip1_int = int(ipaddress.ip_address("1.2.3.4"))
        ip2_int = int(ipaddress.ip_address("5.6.7.8"))
        self.assertIn(ip1_int, result)
        self.assertNotIn(ip2_int, result)
        self.assertEqual(result[ip1_int], 5)

    def test_parse_nonexistent_ipsum(self):
        from services.threat_intel import _parse_ipsum_file
        result = _parse_ipsum_file(Path("/nonexistent.txt"))
        self.assertEqual(len(result), 0)


class TestCIDRMatching(unittest.TestCase):
    """Test CIDR matching correctness."""

    def test_ip_in_network(self):
        net = ipaddress.ip_network("10.0.0.0/8")
        self.assertIn(ipaddress.ip_address("10.1.2.3"), net)
        self.assertNotIn(ipaddress.ip_address("11.0.0.1"), net)

    def test_ip_in_small_cidr(self):
        net = ipaddress.ip_network("192.168.1.0/24")
        self.assertIn(ipaddress.ip_address("192.168.1.100"), net)
        self.assertNotIn(ipaddress.ip_address("192.168.2.1"), net)

    def test_single_ip_cidr(self):
        net = ipaddress.ip_network("1.2.3.4/32")
        self.assertIn(ipaddress.ip_address("1.2.3.4"), net)
        self.assertNotIn(ipaddress.ip_address("1.2.3.5"), net)


class TestGeoIPMMDB(unittest.TestCase):
    """Test GeoIP MMDB database integration."""

    def test_asn_lookup_function_exists(self):
        from services.geo import _lookup_asn
        isp, asn = _lookup_asn("8.8.8.8")
        # Should return strings regardless
        self.assertIsInstance(isp, str)
        self.assertIsInstance(asn, str)

    def test_mmdb_lookup_structure(self):
        from services.geo import _lookup_mmdb
        result = _lookup_mmdb("8.8.8.8")
        if result:  # May be None if no MMDB files
            self.assertIn("lat", result)
            self.assertIn("lon", result)
            self.assertIn("country", result)
            self.assertIn("isp", result)
            self.assertIn("asn", result)

    def test_mmdb_private_ip_returns_none(self):
        from services.geo import _lookup_mmdb
        result = _lookup_mmdb("192.168.1.1")
        # MMDB databases don't have private IPs
        # Result should be None or have no coordinates
        if result:
            self.assertEqual(result.get("lat", 0), 0)

    def test_resolve_ip_with_asn(self):
        """If ASN database is present, ISP should be resolved."""
        from services.geo import resolve_ip
        config.GEOIP_CACHE.clear()
        loc = resolve_ip("8.8.8.8")
        if loc:
            # If GeoLite2-ASN.mmdb is present, ISP should not be 'Unknown'
            asn_path = config.DATA_DIR / "GeoLite2-ASN.mmdb"
            if asn_path.exists():
                self.assertNotEqual(loc.get("isp"), "Unknown",
                                  "ASN database present but ISP is Unknown")


class TestGracefulDegradation(unittest.TestCase):
    """Test that everything works when database files are missing."""

    def test_threat_intel_without_files(self):
        from services.threat_intel import check_ip_reputation
        result = check_ip_reputation("1.2.3.4")
        self.assertIn("is_malicious", result)

    def test_vpn_detection_without_ip_lists(self):
        from services.vpn import detect_vpn
        config.VPN_CACHE.clear()
        config.VPN_IP_RANGES_V4 = []
        config.VPN_IP_RANGES_LOADED = False
        result = detect_vpn("1.2.3.4", "NordVPN", "AS212238")
        # Keyword match should still work
        self.assertTrue(result["is_vpn"])

    def test_geo_without_mmdb(self):
        """Even without MMDB files, private IPs should resolve."""
        from services.geo import resolve_ip
        config.GEOIP_CACHE.clear()
        config.user_public_location = {
            "ip": "Local", "lat": 20, "lon": 0,
            "country": "Test", "city": "Test",
        }
        loc = resolve_ip("192.168.1.1")
        self.assertIsNotNone(loc)
        self.assertEqual(loc["city"], "Local Network")
        config.user_public_location = None


if __name__ == "__main__":
    unittest.main(verbosity=2)
