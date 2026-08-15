# 🌐 PyNet-Trace — Visual IP & Network Path Tracer

A Python-based networking utility that traces the route of ICMP packets to a target destination, extracts hop IP addresses, retrieves geolocation metadata via REST APIs, and renders an interactive HTML map visualizing the global packet journey.

## 🛠️ Tech Stack
- **Language:** Python 3
- **Networking Library:** Scapy (Layer 3/4 packet crafting & ICMP manipulation)
- **Geolocation API:** ip-api.com
- **Visualization:** Folium / Leaflet.js

## 🚀 How to Run

### 1. Install dependencies
\`\`\`bash
python3 -m pip install requests folium scapy
\`\`\`

### 2. Run the tracer
> **Note:** Scapy requires elevated administrative privileges to craft raw ICMP packets on macOS/Linux.

\`\`\`bash
sudo python3 tracer.py
\`\`\`

3. Enter a target domain (e.g., `google.com`) when prompted.
4. Open the generated `route_map.html` in your browser to view the interactive network path map!
5.