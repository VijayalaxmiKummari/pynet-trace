import os
import requests
import folium
from scapy.all import IP, ICMP, sr1

def trace_route(target_host, max_hops=20):
    print(f"[*] Starting route trace for {target_host} (Max Hops: {max_hops})...\n")
    hops = []

    for ttl in range(1, max_hops + 1):
        # Build IP packet with increasing TTL and ICMP echo request
        packet = IP(dst=target_host, ttl=ttl) / ICMP()
        reply = sr1(packet, verbose=0, timeout=2)

        if reply is None:
            print(f"Hop {ttl}: * Request Timed Out")
        elif reply.type == 11:  # Time Exceeded (Hop reached)
            print(f"Hop {ttl}: {reply.src}")
            hops.append(reply.src)
        elif reply.type == 0:   # Echo Reply (Destination reached)
            print(f"Hop {ttl}: {reply.src} [Destination Reached!]")
            hops.append(reply.src)
            break

    return hops

def geolocate_ips(ip_list):
    print("\n[*] Fetching Geolocation Data for network hops...")
    locations = []
    
    for ip in ip_list:
        try:
            # Query free IP geolocation API
            res = requests.get(f"http://ip-api.com/json/{ip}").json()
            if res.get("status") == "success":
                lat = res.get("lat")
                lon = res.get("lon")
                city = res.get("city", "Unknown")
                country = res.get("country", "Unknown")
                isp = res.get("isp", "Unknown")
                locations.append({"ip": ip, "lat": lat, "lon": lon, "city": city, "country": country, "isp": isp})
                print(f"  └─ {ip} -> {city}, {country} ({isp})")
        except Exception as e:
            continue

    return locations

def generate_map(locations, output_file="route_map.html"):
    if not locations:
        print("[!] No geolocation data available to plot on map.")
        return

    # Center map on the first valid hop location
    start_loc = [locations[0]["lat"], locations[0]["lon"]]
    route_map = folium.Map(location=start_loc, zoom_start=3, tiles="CartoDB dark_matter")

    coordinates = []
    for hop in locations:
        coord = [hop["lat"], hop["lon"]]
        coordinates.append(coord)
        
        # Add marker for each hop
        popup_text = f"<b>IP:</b> {hop['ip']}<br><b>Location:</b> {hop['city']}, {hop['country']}<br><b>ISP:</b> {hop['isp']}"
        folium.CircleMarker(
            location=coord,
            radius=6,
            popup=popup_text,
            color="#00FF7F",
            fill=True,
            fill_color="#00FF7F"
        ).add_to(route_map)

    # Draw line connecting hops
    folium.PolyLine(coordinates, color="#00BFFF", weight=2.5, opacity=0.8).add_to(route_map)

    route_map.save(output_file)
    print(f"\n[✓] Interactive map successfully saved to: {os.path.abspath(output_file)}")

if __name__ == "__main__":
    target = input("Enter target domain or IP (e.g., google.com): ").strip()
    if target:
        ip_hops = trace_route(target)
        geo_data = geolocate_ips(ip_hops)
        generate_map(geo_data)