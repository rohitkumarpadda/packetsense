"""Quick smoke test for the enhanced VPN detection and risk scoring."""
import sys
sys.path.insert(0, '.')

import config
print("config OK")
print(f"  AbuseIPDB enabled: {config.ABUSEIPDB_ENABLED}")

from services.vpn import detect_vpn, CONFIDENCE_WEIGHTS
print(f"vpn.py OK - {len(CONFIDENCE_WEIGHTS)} signal types")

from services.abuseipdb import check_ip_abuseipdb, get_status
status = get_status()
print(f"abuseipdb.py OK - offline blacklist: {status['offline_blacklist_size']} IPs")

from services.threat_intel import CATEGORY_MAP
has_abuse = "abuseipdb" in CATEGORY_MAP
print(f"threat_intel.py OK - {len(CATEGORY_MAP)} categories (abuseipdb: {has_abuse})")

from services.capture import compute_risk_score, RISK_FACTORS
print(f"capture.py risk scoring OK - {len(RISK_FACTORS)} risk factors")

print("\n=== VPN Detection Tests ===")

# Test 1: Google DNS - should NOT be VPN
r = detect_vpn('8.8.8.8', 'Google LLC', 'AS15169 Google LLC')
print(f"8.8.8.8 (Google DNS): is_vpn={r['is_vpn']}, confidence={r['confidence']}, classification={r['classification']}")
assert not r['is_vpn'], "FAIL: Google DNS flagged as VPN!"

# Test 2: Cloudflare - CDN whitelisted, should NOT be VPN
config.VPN_CACHE = {}  # Clear cache
r2 = detect_vpn('1.1.1.1', 'Cloudflare Inc', 'AS13335 Cloudflare, Inc.')
print(f"1.1.1.1 (Cloudflare): is_vpn={r2['is_vpn']}, confidence={r2['confidence']}, classification={r2['classification']}")
assert not r2['is_vpn'], "FAIL: Cloudflare flagged as VPN!"

# Test 3: NordVPN ASN - should be VPN with high confidence
config.VPN_CACHE = {}
r3 = detect_vpn('10.0.0.1', 'NordVPN', 'AS212238 NordVPN')
print(f"NordVPN test: is_vpn={r3['is_vpn']}, confidence={r3['confidence']}, classification={r3['classification']}, signals={len(r3['signals'])}")
assert r3['is_vpn'], "FAIL: NordVPN not detected!"
assert r3['confidence'] >= 61, f"FAIL: NordVPN confidence too low: {r3['confidence']}"
print(f"  Signals:")
for sig in r3['signals']:
    print(f"    [{sig['type']}] +{sig['weight']}pts: {sig['detail']}")

# Test 4: ProtonVPN keyword only
config.VPN_CACHE = {}
r4 = detect_vpn('10.0.0.2', 'Proton AG', 'AS99999 Proton AG')
print(f"ProtonVPN keyword: is_vpn={r4['is_vpn']}, confidence={r4['confidence']}, classification={r4['classification']}")
assert r4['confidence'] >= 16, "FAIL: ProtonVPN keyword should have some confidence"

# Test 5: Risk scoring
print("\n=== Risk Scoring Tests ===")
risk = compute_risk_score(
    vpn_detected=True,
    threat_info={"is_malicious": True, "threat_level": "critical", "sources": ["firehol_level1"]},
    vpn_explanation={"protocol_hints": [{"protocol_hint": "WireGuard", "strength": "strong"}]},
    dst_port=51820,
    vpn_confidence=75,
    vpn_classification="vpn_confirmed",
)
print(f"VPN + Critical threat + WireGuard port:")
print(f"  Score: {risk['score']}, Level: {risk['risk_level']}")
print(f"  Reasons: {risk['reasons']}")
print(f"  Primary concern: {risk['primary_concern']}")
print(f"  Breakdown:")
for b in risk['breakdown']:
    print(f"    [{b['factor']}] +{b['points']}pts: {b['detail']}")
assert risk['score'] >= 70, f"FAIL: Combined VPN+threat should be critical, got {risk['score']}"
assert risk['risk_level'] == 'critical', f"FAIL: Should be critical, got {risk['risk_level']}"

# Test 6: Clean traffic - no risk
risk_clean = compute_risk_score(
    vpn_detected=False,
    threat_info=None,
    vpn_explanation=None,
    dst_port=443,
)
print(f"\nClean HTTPS traffic: score={risk_clean['score']}, level={risk_clean['risk_level']}")
assert risk_clean['score'] == 0, "FAIL: Clean traffic should have 0 risk"

print("\n" + "=" * 50)
print("ALL TESTS PASSED!")
print("=" * 50)
