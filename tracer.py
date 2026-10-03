"""
PyNet-Trace - trace the route to a host, measure latency at each hop,
look up where each hop is, flag unusual routing, and draw it on a map.

Usage:
    sudo python3 tracer.py google.com
    sudo python3 tracer.py google.com --max-hops 25 --output my_map.html
    python3 tracer.py --demo          (sample route, no sudo or network needed)
"""

import argparse
import os
import time

import requests

from anomalies import detect_anomalies

GEO_API = "http://ip-api.com/json/{}"

# A made-up route used by --demo. It lets you see the anomaly checks and the map
# without root access or a network connection. The addresses are documentation
# ranges and private ranges, so they do not belong to anyone.
DEMO_ROUTE = [
    {"ttl": 1, "ip": "192.168.1.1", "rtt_ms": 2.1},
    {"ttl": 2, "ip": "100.64.0.1", "rtt_ms": 9.4},
    {"ttl": 3, "ip": "198.51.100.10", "rtt_ms": 12.8, "lat": 51.51, "lon": -0.13,
     "city": "London", "country": "United Kingdom", "isp": "Example Broadband"},
    {"ttl": 4, "ip": "198.51.100.44", "rtt_ms": 21.5, "lat": 48.86, "lon": 2.35,
     "city": "Paris", "country": "France", "isp": "Example Transit"},
    {"ttl": 5, "ip": "198.51.100.71", "rtt_ms": 29.0, "lat": 53.48, "lon": -2.24,
     "city": "Manchester", "country": "United Kingdom", "isp": "Example Transit"},
    {"ttl": 6, "ip": "10.44.0.9", "rtt_ms": 31.2},
    {"ttl": 7, "ip": "203.0.113.20", "rtt_ms": 168.3, "lat": 40.71, "lon": -74.01,
     "city": "New York", "country": "United States", "isp": "Example Backbone"},
    {"ttl": 8, "ip": "203.0.113.80", "rtt_ms": 171.9, "lat": 39.04, "lon": -77.49,
     "city": "Ashburn", "country": "United States", "isp": "Example Hosting"},
]


def send_probe(target_host, ttl):
    """Send one ICMP echo request with the given TTL and return the reply (or None)."""
    from scapy.all import IP, ICMP, sr1          # imported here so tests do not need Scapy

    # Build IP packet with the chosen TTL and an ICMP echo request
    packet = IP(dst=target_host, ttl=ttl) / ICMP()
    return sr1(packet, verbose=0, timeout=2)


def trace_route(target_host, max_hops=20, send=send_probe):
    """Send ICMP packets with a rising TTL and record who answers and how fast.

    Returns one dictionary per hop: {"ttl", "ip", "rtt_ms"}.
    "ip" and "rtt_ms" are None when the hop did not answer in time.

    'send' is the function that sends one probe and returns the reply. Tests
    pass in a fake one, so they run without Scapy, root access or a network.
    """
    print(f"[*] Starting route trace for {target_host} (Max Hops: {max_hops})...\n")
    hops = []

    for ttl in range(1, max_hops + 1):
        started = time.perf_counter()
        reply = send(target_host, ttl)
        rtt_ms = round((time.perf_counter() - started) * 1000, 1)

        if reply is None:
            print(f"Hop {ttl}: * Request Timed Out")
            hops.append({"ttl": ttl, "ip": None, "rtt_ms": None})
        elif reply.type == 11:  # Time Exceeded (Hop reached)
            print(f"Hop {ttl}: {reply.src}  ({rtt_ms} ms)")
            hops.append({"ttl": ttl, "ip": reply.src, "rtt_ms": rtt_ms})
        elif reply.type == 0:   # Echo Reply (Destination reached)
            print(f"Hop {ttl}: {reply.src}  ({rtt_ms} ms) [Destination Reached!]")
            hops.append({"ttl": ttl, "ip": reply.src, "rtt_ms": rtt_ms})
            break

    return hops


def geolocate_ips(hops):
    """Add city, country, ISP and coordinates to every hop that can be located.

    Hops that did not answer, and private addresses the API cannot place,
    are returned unchanged.
    """
    print("\n[*] Fetching Geolocation Data for network hops...")
    located = []

    for hop in hops:
        hop = dict(hop)
        ip = hop.get("ip")
        if ip:
            try:
                # Query free IP geolocation API
                res = requests.get(GEO_API.format(ip), timeout=5).json()
                if res.get("status") == "success":
                    hop.update({
                        "lat": res.get("lat"),
                        "lon": res.get("lon"),
                        "city": res.get("city", "Unknown"),
                        "country": res.get("country", "Unknown"),
                        "isp": res.get("isp", "Unknown"),
                    })
                    print(f"  └─ {ip} -> {hop['city']}, {hop['country']} ({hop['isp']})")
            except (requests.RequestException, ValueError):
                pass                                   # leave this hop without a location
        located.append(hop)

    return located


def generate_map(hops, anomalies=None, output_file="route_map.html"):
    """Plot the located hops on an interactive map. Flagged hops are drawn in red."""
    import folium                                      # imported here so tests do not need Folium

    locations = [h for h in hops if h.get("lat") is not None and h.get("lon") is not None]
    if not locations:
        print("[!] No geolocation data available to plot on map.")
        return None

    notes = {}
    for finding in anomalies or []:
        notes.setdefault(finding["ttl"], []).append(finding["detail"])

    # Center map on the first valid hop location
    start_loc = [locations[0]["lat"], locations[0]["lon"]]
    route_map = folium.Map(location=start_loc, zoom_start=3, tiles="CartoDB dark_matter")

    coordinates = []
    for hop in locations:
        coord = [hop["lat"], hop["lon"]]
        coordinates.append(coord)
        flagged = hop["ttl"] in notes
        colour = "#FF4D4D" if flagged else "#00FF7F"

        # Add marker for each hop
        popup_text = (f"<b>Hop:</b> {hop['ttl']}<br><b>IP:</b> {hop['ip']}<br>"
                      f"<b>Latency:</b> {hop['rtt_ms']} ms<br>"
                      f"<b>Location:</b> {hop['city']}, {hop['country']}<br><b>ISP:</b> {hop['isp']}")
        if flagged:
            popup_text += "<br><b>Flagged:</b> " + "<br>".join(notes[hop["ttl"]])
        folium.CircleMarker(
            location=coord,
            radius=8 if flagged else 6,
            popup=folium.Popup(popup_text, max_width=320),
            color=colour,
            fill=True,
            fill_color=colour,
        ).add_to(route_map)

    # Draw line connecting hops
    folium.PolyLine(coordinates, color="#00BFFF", weight=2.5, opacity=0.8).add_to(route_map)

    route_map.save(output_file)
    print(f"\n[✓] Interactive map successfully saved to: {os.path.abspath(output_file)}")
    return output_file


def print_anomalies(anomalies):
    print("\n[*] Anomaly checks...")
    if not anomalies:
        print("  └─ Nothing unusual found on this route.")
        return
    for finding in anomalies:
        print(f"  └─ [{finding['severity'].upper()}] hop {finding['ttl']}: {finding['detail']}")


def main():
    parser = argparse.ArgumentParser(description="Trace a network route and plot it on a map.")
    parser.add_argument("target", nargs="?", help="domain or IP to trace, e.g. google.com")
    parser.add_argument("--max-hops", type=int, default=20, help="stop after this many hops (default 20)")
    parser.add_argument("--output", default="route_map.html", help="name of the map file to write")
    parser.add_argument("--demo", action="store_true",
                        help="use a built-in sample route (no sudo or network needed)")
    args = parser.parse_args()

    if args.demo:
        print("[*] Demo mode: using a built-in sample route. No packets are sent.\n")
        hops = DEMO_ROUTE
        for hop in hops:
            print(f"Hop {hop['ttl']}: {hop['ip']}  ({hop['rtt_ms']} ms)")
    else:
        target = args.target or input("Enter target domain or IP (e.g., google.com): ").strip()
        if not target:
            return
        hops = trace_route(target, max_hops=args.max_hops)
        hops = geolocate_ips(hops)

    anomalies = detect_anomalies(hops)
    print_anomalies(anomalies)
    generate_map(hops, anomalies, output_file=args.output)


if __name__ == "__main__":
    main()
