"""Tests for the anomaly checks. Run with:  python3 -m unittest discover tests -v"""

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import anomalies as an  # noqa: E402


def hop(ttl, ip, rtt=10.0, country=None, city=None, lat=None, lon=None):
    data = {"ttl": ttl, "ip": ip, "rtt_ms": rtt if ip else None}
    if country:
        data.update({"country": country, "city": city or country, "lat": lat, "lon": lon})
    return data


# A normal-looking route: home router, provider, then two public hops in the UK.
CLEAN_ROUTE = [
    hop(1, "192.168.1.1", 2),
    hop(2, "100.64.0.1", 8),
    hop(3, "81.2.69.142", 12, "United Kingdom", "London", 51.5, -0.12),
    hop(4, "81.2.69.160", 15, "United Kingdom", "Manchester", 53.48, -2.24),
]


class HelperTests(unittest.TestCase):
    def test_distance_london_to_new_york(self):
        km = an.distance_km(51.5074, -0.1278, 40.7128, -74.0060)
        self.assertAlmostEqual(km, 5570, delta=30)

    def test_public_and_private_addresses(self):
        self.assertTrue(an.is_public("8.8.8.8"))
        self.assertFalse(an.is_public("192.168.1.1"))
        self.assertFalse(an.is_public("100.64.0.1"))      # carrier-grade NAT range
        self.assertFalse(an.is_public("not-an-ip"))


class CheckTests(unittest.TestCase):
    def test_clean_route_has_no_findings(self):
        self.assertEqual(an.detect_anomalies(CLEAN_ROUTE), [])

    def test_latency_spike(self):
        route = [hop(1, "81.2.69.142", 10), hop(2, "81.2.69.160", 180)]
        findings = an.check_latency_spikes(route)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["ttl"], 2)

    def test_small_latency_rise_is_ignored(self):
        route = [hop(1, "81.2.69.142", 10), hop(2, "81.2.69.160", 60)]
        self.assertEqual(an.check_latency_spikes(route), [])

    def test_latency_spike_skips_silent_hops(self):
        route = [hop(1, "81.2.69.142", 10), hop(2, None), hop(3, "81.2.69.160", 200)]
        self.assertEqual(an.check_latency_spikes(route)[0]["ttl"], 3)

    def test_routing_loop(self):
        route = [hop(1, "81.2.69.142"), hop(2, "81.2.69.160"), hop(3, "81.2.69.142")]
        findings = an.check_routing_loops(route)
        self.assertEqual([f["ttl"] for f in findings], [3])

    def test_same_ip_twice_in_a_row_is_not_a_loop(self):
        route = [hop(1, "81.2.69.142"), hop(2, "81.2.69.142")]
        self.assertEqual(an.check_routing_loops(route), [])

    def test_private_address_in_the_middle(self):
        route = [hop(1, "192.168.1.1"), hop(2, "81.2.69.142"), hop(3, "10.20.30.40"), hop(4, "8.8.8.8")]
        findings = an.check_private_mid_path(route)
        self.assertEqual([f["ttl"] for f in findings], [3])

    def test_private_addresses_at_the_start_are_normal(self):
        route = [hop(1, "192.168.1.1"), hop(2, "10.0.0.1"), hop(3, "8.8.8.8")]
        self.assertEqual(an.check_private_mid_path(route), [])

    def test_country_revisit(self):
        route = [
            hop(1, "81.2.69.142", country="United Kingdom"),
            hop(2, "5.6.7.8", country="France"),
            hop(3, "81.2.69.160", country="United Kingdom"),
        ]
        findings = an.check_country_revisits(route)
        self.assertEqual([f["ttl"] for f in findings], [3])

    def test_staying_in_one_country_is_fine(self):
        self.assertEqual(an.check_country_revisits(CLEAN_ROUTE), [])

    def test_long_jump(self):
        route = [
            hop(1, "81.2.69.142", country="United Kingdom", city="London", lat=51.5, lon=-0.12),
            hop(2, "8.8.8.8", country="United States", city="New York", lat=40.71, lon=-74.0),
        ]
        findings = an.check_long_jumps(route)
        self.assertEqual(len(findings), 1)
        self.assertIn("London", findings[0]["detail"])

    def test_silent_gap(self):
        route = [hop(1, "81.2.69.142"), hop(2, None), hop(3, None), hop(4, None), hop(5, "8.8.8.8")]
        findings = an.check_silent_gaps(route)
        self.assertEqual(findings[0]["ttl"], 2)

    def test_two_silent_hops_are_ignored(self):
        route = [hop(1, "81.2.69.142"), hop(2, None), hop(3, None), hop(4, "8.8.8.8")]
        self.assertEqual(an.check_silent_gaps(route), [])

    def test_silent_gap_at_the_end_of_the_route(self):
        route = [hop(1, "81.2.69.142"), hop(2, None), hop(3, None), hop(4, None)]
        self.assertEqual(len(an.check_silent_gaps(route)), 1)

    def test_findings_are_sorted_by_hop(self):
        route = [
            hop(1, "81.2.69.142", 10, "United Kingdom", "London", 51.5, -0.12),
            hop(2, "8.8.8.8", 200, "United States", "New York", 40.71, -74.0),
            hop(3, "81.2.69.142", 210, "United Kingdom", "London", 51.5, -0.12),
        ]
        ttls = [f["ttl"] for f in an.detect_anomalies(route)]
        self.assertEqual(ttls, sorted(ttls))
        self.assertGreaterEqual(len(ttls), 3)


if __name__ == "__main__":
    unittest.main()
