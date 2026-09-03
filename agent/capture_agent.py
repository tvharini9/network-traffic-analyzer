"""Local packet capture agent with safe, optional traceroute collection."""
import argparse
import asyncio
import ipaddress
import json
import platform
import re
import socket
import sys
import subprocess
import threading
import time
import os
import sys
import os
import os
from collections import Counter, deque

import websockets
from scapy.all import IP, TCP, UDP, sniff

batch = deque()
destinations = Counter()
lock = threading.Lock()

PROTO_NAMES = {1: "ICMP", 6: "TCP", 17: "UDP"}


def classify_packet(packet):
    if IP not in packet:
        return
    ip = packet[IP]
    sport = dport = None
    if TCP in packet:
        sport, dport = int(packet[TCP].sport), int(packet[TCP].dport)
    elif UDP in packet:
        sport, dport = int(packet[UDP].sport), int(packet[UDP].dport)

    record = {
        "ts": time.time(),
        "src": ip.src,
        "dst": ip.dst,
        "sport": sport,
        "dport": dport,
        "proto": PROTO_NAMES.get(int(ip.proto), f"OTHER({int(ip.proto)})"),
        "length": len(packet),
    }

    with lock:
        batch.append(record)
        destinations[ip.dst] += 1


def on_packet(packet):
    try:
        classify_packet(packet)
    except Exception as exc:
        print(f"[agent] packet error: {exc}")


def sniff_thread(iface):
    print(f"[agent] starting capture on interface: {iface or 'default'}")
    try:
        sniff(iface=iface, prn=on_packet, store=False)
    except Exception as exc:
        print(f"[agent] capture error: {exc}")


def pop_batch():
    with lock:
        data = list(batch)
        batch.clear()
    return data


def top_destinations(limit=3):
    with lock:
        candidates = destinations.most_common()
    out = []
    for ip, _ in candidates:
        try:
            if ipaddress.ip_address(ip).is_global and ip not in out:
                out.append(ip)
        except ValueError:
            pass
        if len(out) >= limit:
            break
    return out


def parse_rtt_ms(text):
    m = re.search(r"(?:<|=)\s*(\d+)\s*ms", text, re.I)
    if m:
        return float(m.group(1))
    m = re.search(r"(\d+(?:\.\d+)?)\s*ms", text, re.I)
    return float(m.group(1)) if m else None


def parse_ip(text):
    matches = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text)
    for value in matches:
        try:
            ipaddress.ip_address(value)
            return value
        except ValueError:
            continue
    return None


def run_traceroute(target):
    """Best-effort system traceroute; a failure returns None."""
    try:
        if platform.system().lower().startswith("win"):
            cmd = ["tracert", "-d", "-h", "20", "-w", "1000", target]
        else:
            cmd = ["traceroute", "-n", "-m", "20", "-w", "1", target]

        completed = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=45,
            errors="ignore",
        )
    except Exception as exc:
        print(f"[agent] traceroute failed for {target}: {exc}")
        return None

    lines = completed.stdout.splitlines()
    hops = []
    events = []

    for line in lines:
        if not re.search(r"\s\d+\s", line):
            continue

        number_match = re.search(r"^\s*(\d+)\s+", line)
        if not number_match:
            continue
        hop_number = int(number_match.group(1))

        timeout = "*" in line
        hop_ip = parse_ip(line)
        rtt = parse_rtt_ms(line)

        hostname = None
        if hop_ip:
            try:
                hostname = socket.gethostbyaddr(hop_ip)[0]
            except Exception:
                hostname = None

        hops.append({
            "hop": hop_number,
            "ip": hop_ip,
            "hostname": hostname,
            "timeout": timeout and not hop_ip,
            "rtt_ms": rtt,
        })

        if timeout and not hop_ip:
            events.append({
                "ts": time.time(),
                "target": target,
                "hop_number": hop_number,
                "ip": None,
                "event_type": "timeout",
                "rtt_ms": None,
                "details": "Traceroute hop did not respond",
            })
        elif rtt is not None and rtt > 150:
            events.append({
                "ts": time.time(),
                "target": target,
                "hop_number": hop_number,
                "ip": hop_ip,
                "event_type": "latency_spike",
                "rtt_ms": rtt,
                "details": "RTT exceeded 150 ms",
            })

    if not hops:
        return None

    valid = [h["rtt_ms"] for h in hops if h.get("rtt_ms") is not None]
    return {
        "target": target,
        "ts": time.time(),
        "hops": hops,
        "total_rtt_ms": max(valid) if valid else None,
        "events": events,
    }


async def flush_loop(ws, device_id):
    sent = 0
    while True:
        await asyncio.sleep(1)
        payload = pop_batch()
        if not payload:
            continue
        await ws.send(json.dumps({"type": "packet_batch", "device_id": device_id, "packets": payload}))
        sent += len(payload)
        print(f"[agent] sent {len(payload)} packets (total sent: {sent})")


async def route_loop(ws, device_id):
    """Optional route task. Any error is isolated from packet flushing."""
    while True:
        await asyncio.sleep(30)
        try:
            routes = []
            for target in top_destinations(3):
                try:
                    route = await asyncio.to_thread(run_traceroute, target)
                except Exception as exc:
                    print(f"[agent] route measurement failed for {target}: {exc}")
                    route = None
                if route:
                    routes.append(route)
            if routes:
                await ws.send(json.dumps({"type": "route_batch", "device_id": device_id, "routes": routes}))
                print(f"[agent] sent {len(routes)} route observations")
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            print(f"[agent] route loop error: {exc}")


async def main(iface, backend_url, token, device_id):
    threading.Thread(target=sniff_thread, args=(iface,), daemon=True).start()
    full_url = f"{backend_url}?token={token}"

    while True:
        try:
            print(f"[agent] connecting to backend at {backend_url}")
            async with websockets.connect(full_url, ping_interval=20, ping_timeout=20) as ws:
                print("[agent] connected. streaming traffic...")
                packet_task = asyncio.create_task(flush_loop(ws, device_id))
                route_task = asyncio.create_task(route_loop(ws, device_id))
                done, pending = await asyncio.wait(
                    {packet_task, route_task},
                    return_when=asyncio.FIRST_EXCEPTION,
                )

                for task in done:
                    exc = task.exception()
                    if exc:
                        if task is packet_task:
                            raise exc
                        print(f"[agent] optional route task stopped: {exc}")

                # Keep packet capture alive even if route task ended.
                if route_task in done:
                    route_task = asyncio.create_task(route_loop(ws, device_id))
                await packet_task

        except asyncio.CancelledError:
            raise
        except Exception as exc:
            print(f"[agent] connection/stream error: {exc}")
            print("[agent] retrying in 3 seconds...")
            await asyncio.sleep(3)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Network Traffic Analyzer capture agent")
    parser.add_argument("--iface", default=None, help="Network interface to sniff")
    parser.add_argument("--backend", default=None, help="Backend WebSocket URL")
    parser.add_argument("--token", default=None, help="Backend ingest token")
    parser.add_argument("--device-id", default=platform.node(), help="Unique identifier for this device")
    args = parser.parse_args()

    if getattr(sys, "frozen", False):
        config_path = os.path.join(os.path.dirname(sys.executable), "agent_config.json")
    else:
        config_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "agent_config.json")

    if os.path.exists(config_path):
        with open(config_path, "r", encoding="utf-8-sig") as f:
            config = json.load(f)

        args.backend = args.backend or config.get("backend")
        args.token = args.token or config.get("token")
        args.device_id = args.device_id or config.get("device_id")

    if not args.backend or not args.token:
        raise RuntimeError("Agent configuration is missing.")

    args.device_id = args.device_id or platform.node()

    try:
        asyncio.run(main(args.iface, args.backend, args.token, args.device_id))
    except KeyboardInterrupt:
        print("\n[agent] stopped")









