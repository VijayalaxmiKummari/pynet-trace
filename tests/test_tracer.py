"""Tests for the tracer. No packets are sent and no website is contacted."""

import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import tracer  # noqa: E402


class FakeReply:
    def __init__(self, src, icmp_type):
        self.src = src
        self.type = icmp_type


def fake_sender(replies):
    """Return a send function that answers each TTL from a prepared list."""
    def send(target_host, ttl):
        return replies[ttl - 1] if ttl <= len(replies) else None
    return send


class TraceRouteTests(unittest.TestCase):
    def test_records_each_hop_and_stops_at_destination(self):
        send = fake_sender([
            FakeReply("192.168.1.1", 11),
            None,                                   # this hop times out
            FakeReply("8.8.8.8", 0),                # destination answers
            FakeReply("9.9.9.9", 11),               # must never be reached
        ])
        hops = tracer.trace_route("example.com", max_hops=10, send=send)

        self.assertEqual([h["ip"] for h in hops], ["192.168.1.1", None, "8.8.8.8"])
        self.assertEqual([h["ttl"] for h in hops], [1, 2, 3])
        self.assertIsNone(hops[1]["rtt_ms"])
        self.assertGreaterEqual(hops[0]["rtt_ms"], 0)

    def test_respects_max_hops(self):
        send = fake_sender([FakeReply("10.0.0.%d" % i, 11) for i in range(1, 50)])
        self.assertEqual(len(tracer.trace_route("example.com", max_hops=5, send=send)), 5)


class GeolocateTests(unittest.TestCase):
    def test_adds_location_when_lookup_succeeds(self):
        answer = mock.Mock()
        answer.json.return_value = {"status": "success", "lat": 51.5, "lon": -0.12,
                                    "city": "London", "country": "United Kingdom", "isp": "Example ISP"}
        with mock.patch.object(tracer.requests, "get", return_value=answer) as get:
            hops = tracer.geolocate_ips([{"ttl": 1, "ip": "81.2.69.142", "rtt_ms": 12.0}])

        self.assertEqual(hops[0]["city"], "London")
        self.assertEqual(hops[0]["rtt_ms"], 12.0)
        self.assertIn("81.2.69.142", get.call_args[0][0])

    def test_keeps_hop_when_lookup_fails(self):
        answer = mock.Mock()
        answer.json.return_value = {"status": "fail", "message": "private range"}
        with mock.patch.object(tracer.requests, "get", return_value=answer):
            hops = tracer.geolocate_ips([{"ttl": 1, "ip": "192.168.1.1", "rtt_ms": 2.0}])

        self.assertEqual(len(hops), 1)
        self.assertNotIn("lat", hops[0])

    def test_survives_a_network_error(self):
        with mock.patch.object(tracer.requests, "get", side_effect=tracer.requests.ConnectionError):
            hops = tracer.geolocate_ips([{"ttl": 1, "ip": "8.8.8.8", "rtt_ms": 9.0}])
        self.assertEqual(hops[0]["ip"], "8.8.8.8")

    def test_silent_hops_are_not_looked_up(self):
        with mock.patch.object(tracer.requests, "get") as get:
            tracer.geolocate_ips([{"ttl": 1, "ip": None, "rtt_ms": None}])
        get.assert_not_called()


if __name__ == "__main__":
    unittest.main()
