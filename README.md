# Network Traffic Analyzer — upgraded

## What this version does

- Public live dashboard: throughput, packets/sec, active devices, top talkers, protocols, and live anomaly alerts.
- Account-only pages: History, Devices, Anomalies, Analytics, and Network Map.
- History ranges: 1m, 5m, 10m, 1h, 24h, 7d.
- Device drill-down from the Devices table.
- Persistent anomaly log.
- Route observations collected by the local agent using the operating system traceroute/tracert command.
- Hop details with RTT and timeout indicators.
- Route history and bottleneck/timeout/latency-spike summaries.
- Best-effort IP geolocation/organization enrichment for public hops.
- Route tracing is isolated from packet flushing so a route measurement failure cannot stop packet collection.

## Deployment

The deployed service should use `backend` as its root directory.

Build:

```bash
pip install -r requirements.txt
```

Start:

```bash
uvicorn main:app --host 0.0.0.0 --port $PORT
```

Set these environment variables on the host:

- `INGEST_TOKEN` — shared secret used only by the local capture agent.
- `DATABASE_URL` — PostgreSQL connection string for persistent data.
- `SESSION_SECRET` — long random secret for login sessions.

The backend serves `backend/static/index.html`, so `frontend/index.html` is the editable source copy and `backend/static/index.html` is the deployment copy.

## Local agent

Install:

```bash
pip install -r agent/requirements.txt
```

Start against Railway:

```bash
python agent/capture_agent.py --backend wss://YOUR-APP/ws/ingest --token YOUR_INGEST_TOKEN
```

Windows users may need to run the terminal as Administrator and have Npcap installed for packet capture.

## Route-map behavior

The map is an observed route visualization, not a guarantee of the exact physical path taken by every packet. Routers may not answer traceroute probes. Timeouts and latency spikes are recorded as observations.
