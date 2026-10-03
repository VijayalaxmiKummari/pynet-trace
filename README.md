# 🌐 PyNet-Trace — Visual IP & Network Path Tracer

A Python networking tool that traces the route packets take to a destination, measures the latency at every hop, looks up where each hop is, flags unusual routing, and draws the whole journey on an interactive map.

## ✨ What it does

1. **Traces the route** — sends ICMP packets with a rising TTL (the same idea as `traceroute`) and records which router answers at each hop.
2. **Measures latency** — times every reply in milliseconds.
3. **Finds the location** — looks up the city, country and ISP of each hop.
4. **Checks for anomalies** — flags unexpected routing paths and unusual hops (see below).
5. **Draws the map** — plots the route on an interactive HTML map. Flagged hops are shown in red.

## 🔎 Anomaly checks

| Check | What it flags | Why it matters |
|---|---|---|
| Latency spike | Latency rises by more than 100 ms between two hops | Congestion, a long-distance link or a detour |
| Routing loop | The same IP appears again after the route moved on | Misconfigured routing; packets going in circles |
| Private address mid-path | A private or reserved IP appears after the route reached the public internet | Unusual; can point to tunnelling or a misconfiguration |
| Country revisit | The route leaves a country and later returns to it | An inefficient or unexpected detour |
| Long jump | Two consecutive hops are more than 5,000 km apart | Shows where the route crosses an ocean or continent |
| Silent gap | Three or more hops in a row do not answer | Routers that drop ICMP, or filtering on the path |

These are indicators, not proof that something is wrong. Many routes cross oceans and many routers ignore ICMP. The thresholds are at the top of `anomalies.py` and can be changed.

## 🛠️ Tech Stack
- **Language:** Python 3
- **Networking Library:** Scapy (Layer 3/4 packet crafting & ICMP manipulation)
- **Geolocation API:** ip-api.com
- **Visualization:** Folium / Leaflet.js
- **Testing:** unittest (standard library)

## 📁 Project layout

```
pynet-trace/
├── tracer.py              trace, geolocate, map and command line
├── anomalies.py           the anomaly checks
├── requirements.txt       libraries to install
└── tests/
    ├── test_anomalies.py  tests for every anomaly check
    └── test_tracer.py     tests for tracing and geolocation (no network used)
```

## 🚀 How to Run

### 1. Install dependencies
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### 2. Try the demo (no sudo, no network)
```bash
python3 tracer.py --demo
```
This uses a built-in sample route so you can see the anomaly checks and the map straight away.

### 3. Trace a real route
> **Note:** Scapy requires elevated administrative privileges to craft raw ICMP packets on macOS/Linux.

```bash
sudo .venv/bin/python3 tracer.py google.com
```

Options:

| Option | Meaning |
|---|---|
| `--max-hops 25` | stop after this many hops (default 20) |
| `--output my_map.html` | name of the map file |
| `--demo` | use the built-in sample route |

If you leave out the target, the tool asks for one.

### 4. Open the map
Open the generated `route_map.html` in your browser. Click a marker to see the hop number, IP, latency, location and ISP. Red markers are hops that were flagged.

## 🖥️ Example output

```
Hop 3: 198.51.100.10  (12.8 ms)
Hop 4: 198.51.100.44  (21.5 ms)
Hop 5: 198.51.100.71  (29.0 ms)
Hop 7: 203.0.113.20  (168.3 ms)

[*] Anomaly checks...
  └─ [WARNING] hop 5: Route returns to United Kingdom at hop 5 after passing through France.
  └─ [INFO] hop 7: Latency rose by 137 ms between hop 6 and hop 7 (10.44.0.9 -> 203.0.113.20).
  └─ [INFO] hop 7: Hop 7 is about 5,370 km from hop 5 (Manchester -> New York).
```

## ✅ Running the tests

```bash
python3 -m unittest discover tests -v
```

The tests use fake replies and a mocked geolocation service, so they need no root access and send no packets.

## ⚠️ Limitations
- Latency is one measurement per hop, so a single slow reply can trigger a spike. Run the trace again to confirm.
- IP geolocation is approximate. It places an IP where its owner registered it, which is not always where the router sits.
- Hops with private addresses cannot be geolocated, so they do not appear on the map.
- The free ip-api.com service allows about 45 lookups a minute.

## 📌 Responsible use
Only trace hosts you are allowed to test. A trace sends a small number of ordinary ICMP packets, the same as the standard `traceroute` command.
