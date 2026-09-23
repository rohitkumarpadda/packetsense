"""
tests/test_config.py — Unit tests for config module (memory optimization features).

Tests the new cache eviction system, memory limits, and configuration values
optimized for 16GB RAM machines.
"""

import sys
import unittest
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import config


class TestCacheEviction(unittest.TestCase):
    """Test the cache eviction mechanism for memory management."""

    def test_evict_under_limit_no_action(self):
        """When cache is under limit, no entries should be evicted."""
        cache = {f"key_{i}": f"value_{i}" for i in range(100)}
        evicted = config.evict_cache_if_needed(cache, max_size=500, name="test")
        self.assertEqual(evicted, 0, "No eviction should occur when under limit")
        self.assertEqual(len(cache), 100, "Cache size should remain unchanged")

    def test_evict_over_limit_removes_oldest_20_percent(self):
        """When over limit, oldest 20% of entries should be evicted."""
        # Python 3.7+ dicts maintain insertion order
        cache = {f"key_{i}": f"value_{i}" for i in range(1000)}
        initial_size = len(cache)
        evicted = config.evict_cache_if_needed(cache, max_size=500, name="test")
        
        # Should evict enough to get to 80% of max (400 entries)
        # Eviction count = 1000 - 400 = 600
        self.assertEqual(evicted, 600, f"Should evict 600 entries, got {evicted}")
        self.assertEqual(len(cache), 400, f"Cache should be 400 after eviction")
        
        # Verify oldest entries were removed (key_0 through key_599 should be gone)
        self.assertNotIn("key_0", cache, "Oldest entry should be removed")
        self.assertNotIn("key_100", cache, "Old entry should be removed")
        self.assertIn("key_600", cache, "Newer entry should remain")
        self.assertIn("key_999", cache, "Newest entry should remain")

    def test_evict_empty_cache_safe(self):
        """Empty cache should be handled safely."""
        cache = {}
        evicted = config.evict_cache_if_needed(cache, max_size=100, name="test")
        self.assertEqual(evicted, 0, "No eviction on empty cache")
        self.assertEqual(len(cache), 0, "Cache should remain empty")

    def test_evict_returns_correct_count(self):
        """Eviction should return the number of entries removed."""
        cache = {f"key_{i}": f"value_{i}" for i in range(250)}
        evicted = config.evict_cache_if_needed(cache, max_size=100, name="test")
        
        # Should evict to get to 80 entries (250 - 80 = 170)
        self.assertEqual(evicted, 170, f"Should return count of 170, got {evicted}")

    def test_evict_large_cache_performance(self):
        """Eviction of large cache (10k entries) should be fast."""
        import time
        cache = {f"key_{i}": {"data": f"value_{i}" * 10} for i in range(10000)}
        
        start = time.time()
        evicted = config.evict_cache_if_needed(cache, max_size=5000, name="large_test")
        elapsed = time.time() - start
        
        self.assertLess(elapsed, 1.0, f"Eviction took {elapsed:.3f}s, should be < 1s")
        self.assertEqual(evicted, 6000, "Should evict 6000 entries (10k - 4k)")
        self.assertEqual(len(cache), 4000, "Should leave 4000 entries (80% of 5k)")

    def test_evict_at_exact_limit(self):
        """When cache is exactly at limit, no eviction occurs."""
        cache = {f"key_{i}": f"value_{i}" for i in range(100)}
        evicted = config.evict_cache_if_needed(cache, max_size=100, name="test")
        self.assertEqual(evicted, 0, "No eviction when exactly at limit")
        self.assertEqual(len(cache), 100)


class TestMemorySettings(unittest.TestCase):
    """Test memory optimization configuration values."""

    def test_max_history_increased(self):
        """MAX_HISTORY should be 5000 for 16GB RAM machines."""
        self.assertEqual(config.MAX_