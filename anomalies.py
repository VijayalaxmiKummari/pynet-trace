"""
anomalies.py - checks that flag unusual behaviour in a traced route.

Every function here works on plain Python data (a list of hop dictionaries),
so the checks can be tested without sending a single packet.

A hop looks like this:

    {"ttl": 4, "ip": "203.0.113.9", "rtt_ms": 18.2,
     "lat": 51.5, "lon": -0.12, "city": "London", "country": "United Kingdom"}

"ip" and "rtt_ms" are None when the hop did not answer. The location fields
are only present when the IP could be geolocated.
"""

import ipaddress
import math

# Thresholds (change these to make the checks stricter or looser)
LATENCY_SPIKE_MS = 100     # jump in round-trip time between two answering hops
LONG_JUMP_KM = 5000        # distance between two consecutive located hops
SILENT_GAP_HOPS = 3        # consecutive hops that did not answer


def distance_km(lat1, lon1, lat2, lon2):
    """Great-circle distance between two points on Earth (haversine formula)."""
    radius = 6371.0
    p1, p2 = math.radians(lat1), math.radians(lat2)
    d_lat = p2 - p1
    d_lon = math.radians(lon2 - lon1)
    a = math.sin(d_lat / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(d_lon / 2) ** 2
    return 2 * radius * math.asin(math.sqrt(a))


# Address ranges reserved for examples and documentation (RFC 5737, RFC 3849).
# Nobody owns them, so the demo route and the tests use them to stand in for
# public addresses. They are counted as public for that reason.
DOCUMENTATION_RANGES = [ipaddress.ip_network(n) for n in (
    "192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32")]


def is_public(ip):
    """True for an address that is routable on the public internet."""
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return False
    if any(address in network for network in DOCUMENTATION_RANGES):
        return True
    return address.is_global


def _finding(kind, severity, ttl, detail):
    return {"type": kind, "severity": severity, "ttl": ttl, "detail": detail}


def check_latency_spikes(hops, threshold_ms=LATENCY_SPIKE_MS):
    """Flag a hop whose latency jumps sharply compared with the hop before it."""
    findings = []
    previous = None
    for hop in hops:
        if hop.get("rtt_ms") is None:
            continue
        if previous is not None:
            jump = hop["rtt_ms"] - previous["rtt_ms"]
            if jump > threshold_ms:
                findings.append(_finding(
                    "latency_spike", "info", hop["ttl"],
                    "Latency rose by {:.0f} ms between hop {} and hop {} ({} -> {}).".format(
                        jump, previous["ttl"], hop["ttl"], previous["ip"], hop["ip"])))
        previous = hop
    return findings


def check_routing_loops(hops):
    """Flag an IP that shows up again after the route has moved on to another IP."""
    findings = []
    last_seen = {}          # ip -> ttl where it was last seen
    previous_ip = None
    for hop in hops:
        ip = hop.get("ip")
        if ip is None:
            continue
        if ip in last_seen and previous_ip != ip:
            findings.append(_finding(
                "routing_loop", "warning", hop["ttl"],
                "{} appears at hop {} and again at hop {}, which suggests a routing loop.".format(
                    ip, last_seen[ip], hop["ttl"])))
        last_seen[ip] = hop["ttl"]
        previous_ip = ip
    return findings


def check_private_mid_path(hops):
    """Flag a private or reserved address that appears after the route reached the public internet.

    Private addresses are normal for the first hops (your own router and your
    provider's internal network). Seeing one later in the path is unusual.
    """
    findings = []
    seen_public = False
    for hop in hops:
        ip = hop.get("ip")
        if ip is None:
            continue
        if is_public(ip):
            seen_public = True
        elif seen_public:
            findings.append(_finding(
                "private_mid_path", "warning", hop["ttl"],
                "Non-public address {} appears at hop {} after the route had reached the public internet.".format(
                    ip, hop["ttl"])))
    return findings


def check_country_revisits(hops):
    """Flag a route that leaves a country and later comes back to it (a detour)."""
    findings = []
    visited = []            # countries in the order the route passed through them
    for hop in hops:
        country = hop.get("country")
        if not country:
            continue
        if visited and visited[-1] == country:
            continue
        if country in visited:
            findings.append(_finding(
                "country_revisit", "warning", hop["ttl"],
                "Route returns to {} at hop {} after passing through {}.".format(
                    country, hop["ttl"], visited[-1])))
        visited.append(country)
    return findings


def check_long_jumps(hops, threshold_km=LONG_JUMP_KM):
    """Flag two consecutive located hops that are very far apart."""
    findings = []
    previous = None
    for hop in hops:
        if hop.get("lat") is None or hop.get("lon") is None:
            continue
        if previous is not None:
            km = distance_km(previous["lat"], previous["lon"], hop["lat"], hop["lon"])
            if km > threshold_km:
                findings.append(_finding(
                    "long_jump", "info", hop["ttl"],
                    "Hop {} is about {:,.0f} km from hop {} ({} -> {}).".format(
                        hop["ttl"], km, previous["ttl"],
                        previous.get("city", "?"), hop.get("city", "?"))))
        previous = hop
    return findings


def check_silent_gaps(hops, threshold=SILENT_GAP_HOPS):
    """Flag a run of hops that did not answer."""
    findings = []
    run_start, run_length = None, 0
    for hop in hops + [{"ttl": None, "ip": "end"}]:      # sentinel closes the last run
        if hop.get("ip") is None:
            if run_length == 0:
                run_start = hop["ttl"]
            run_length += 1
        else:
            if run_length >= threshold:
                findings.append(_finding(
                    "silent_gap", "info", run_start,
                    "{} hops in a row did not answer, starting at hop {}.".format(run_length, run_start)))
            run_length = 0
    return findings


def detect_anomalies(hops):
    """Run every check and return all findings, ordered by hop number."""
    findings = []
    for check in (check_latency_spikes, check_routing_loops, check_private_mid_path,
                  check_country_revisits, check_long_jumps, check_silent_gaps):
        findings.extend(check(hops))
    return sorted(findings, key=lambda f: f["ttl"])
