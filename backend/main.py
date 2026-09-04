import asyncio
import hashlib
import ipaddress
import json
import os
import secrets
import time
from collections import defaultdict, deque
from pathlib import Path

import httpx
from fastapi import FastAPI, Form, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles

import database
from auth import SESSION_COOKIE, create_session, get_user_id, hash_password, verify_password

app = FastAPI(title="Network Traffic Analyzer")
INGEST_TOKEN = os.environ.get("INGEST_TOKEN", "dev-token-change-me")
WINDOW_SECONDS = 60
BROADCAST_INTERVAL = 1.0
ANOMALY_MULTIPLIER = 4
STATIC_DIR = Path(__file__).resolve().parent / "static"

GEO_CACHE: dict[str, dict] = {}


class RollingStats:
    def __init__(self, window_seconds: int = WINDOW_SECONDS):
        self.window_seconds = window_seconds
        self.packets = deque()
        self.per_ip_history = defaultdict(lambda: deque(maxlen=30))
        self.lock = asyncio.Lock()

    def add_batch(self, packets: list[dict]) -> None:
        received = time.time()
        for packet in packets:
            if not isinstance(packet, dict):
                continue
            if "length" not in packet or "src" not in packet:
                continue
            try:
                packet = dict(packet)
                packet["length"] = int(packet["length"])
                packet["capture_ts"] = float(packet.get("ts", received))
                packet["ts"] = received
                self.packets.append(packet)
            except (TypeError, ValueError):
                continue
        self._evict_old(received)

    def _evict_old(self, now: float) -> None:
        cutoff = now - self.window_seconds
        while self.packets and self.packets[0].get("ts", 0) < cutoff:
            self.packets.popleft()

    def snapshot(self) -> dict:
        now = time.time()
        self._evict_old(now)
        last = [p for p in self.packets if p.get("ts", 0) >= now - 1.2]

        total_bps = sum(max(0, int(p.get("length", 0))) for p in last)
        total_pps = len(last)
        bytes_by_ip = defaultdict(int)
        packets_by_ip = defaultdict(int)
        proto_counts = defaultdict(int)

        for packet in last:
            src = packet.get("src", "unknown")
            bytes_by_ip[src] += max(0, int(packet.get("length", 0)))
            packets_by_ip[src] += 1
            proto_counts[packet.get("proto", "OTHER")] += 1

        alerts: list[dict] = []
        for ip, current_bytes in bytes_by_ip.items():
            hist = self.per_ip_history[ip]
            if len(hist) >= 5:
                avg = sum(hist) / len(hist)
                if avg > 0 and current_bytes > avg * ANOMALY_MULTIPLIER:
                    multiplier = current_bytes / avg
                    alerts.append({
                        "ts": now,
                        "ip": ip,
                        "current_bytes": current_bytes,
                        "baseline_bytes": round(avg),
                        "multiplier": round(multiplier, 2),
                        "message": f"{ip} is sending {multiplier:.1f}Ã— its usual traffic",
                    })
            hist.append(current_bytes)

        return {
            "type": "stats",
            "ts": now,
            "total_bps": total_bps,
            "total_pps": total_pps,
            "active_devices": len(bytes_by_ip),
            "top_talkers": [
                {"ip": ip, "bytes": b}
                for ip, b in sorted(bytes_by_ip.items(), key=lambda x: x[1], reverse=True)[:10]
            ],
            "protocol_breakdown": dict(proto_counts),
            "alerts": alerts,
            "device_samples": [
                {"ip": ip, "bytes": b, "packets": packets_by_ip[ip]}
                for ip, b in bytes_by_ip.items()
            ],
        }


stats = RollingStats()
stats_by_device: dict[str, RollingStats] = {}
device_user_ids: dict[str, int] = {}


class DashboardManager:
    def __init__(self):
        self.clients: dict[WebSocket, int | None] = {}

    async def connect(self, websocket: WebSocket, user_id: int | None) -> None:
        await websocket.accept()
        self.clients[websocket] = user_id

    def disconnect(self, websocket: WebSocket) -> None:
        self.clients.pop(websocket, None)

    async def broadcast(self, message: dict, user_id: int | None) -> None:
        dead = []

        for websocket, client_user_id in list(self.clients.items()):
            if client_user_id != user_id:
                continue

            try:
                await websocket.send_json(message)
            except Exception:
                dead.append(websocket)

        for websocket in dead:
            self.disconnect(websocket)
dashboard_manager = DashboardManager()


def require_user(request: Request) -> int | None:
    return get_user_id(request.cookies.get(SESSION_COOKIE))


def auth_error(message: str, status: int = 401) -> JSONResponse:
    return JSONResponse({"error": message}, status_code=status)


def public_ip(value: str | None) -> bool:
    try:
        return ipaddress.ip_address(value or "").is_global
    except ValueError:
        return False


@app.get("/health")
async def health():
    return {
        "status": "ok",
        "message": "Network Traffic Analyzer backend running",
        "clients": len(dashboard_manager.clients),
        "window_packets": len(stats.packets),
    }

@app.post("/devices/register")
async def register_device(
    request: Request,
    device_id: str = Form(...),
    device_name: str = Form(""),
):
    user_id = require_user(request)
    if not user_id:
        return auth_error("Login required")

    device_id = device_id.strip()
    device_name = device_name.strip()

    if not device_id:
        return auth_error("Device ID is required.", 400)

    raw_token = secrets.token_urlsafe(32)
    token_hash = hashlib.sha256(raw_token.encode("utf-8")).hexdigest()

    device = await asyncio.to_thread(
        database.register_device,
        user_id,
        device_id,
        device_name or device_id,
        token_hash,
    )

    return {
        "message": "Device registered",
        "device": device,
        "token": raw_token,
    }

@app.post("/signup")
async def signup(request: Request, username: str = Form(...), password: str = Form(...)):
    username = username.strip()
    if not 3 <= len(username) <= 64:
        return auth_error("Username must be 3â€“64 characters.", 400)
    if len(password) < 8:
        return auth_error("Password must be at least 8 characters.", 400)
    try:
        user = await asyncio.to_thread(database.create_user, username, hash_password(password))
    except ValueError as exc:
        return auth_error(str(exc), 409)
    response = JSONResponse({"message": "Account created", "username": user["username"]})
    response.set_cookie(
        SESSION_COOKIE,
        create_session(user["id"]),
        max_age=7 * 24 * 60 * 60,
        httponly=True,
        samesite="lax",
        secure=request.url.scheme == "https",
    )
    return response


@app.post("/login")
async def login(request: Request, username: str = Form(...), password: str = Form(...)):
    user = await asyncio.to_thread(database.get_user_by_username, username.strip())
    if not user or not verify_password(password, user["password_hash"]):
        return auth_error("Invalid username or password")
    response = JSONResponse({"message": "Login successful", "username": user["username"]})
    response.set_cookie(
        SESSION_COOKIE,
        create_session(user["id"]),
        max_age=7 * 24 * 60 * 60,
        httponly=True,
        samesite="lax",
        secure=request.url.scheme == "https",
    )
    return response
@app.get("/devices")
async def list_devices(request: Request):
    user_id = require_user(request)
    if not user_id:
        return auth_error("Login required")

    return await asyncio.to_thread(
        database.get_devices_for_user,
        user_id,
    )

@app.post("/logout")
async def logout():
    response = JSONResponse({"message": "Logged out"})
    response.delete_cookie(SESSION_COOKIE)
    return response


@app.get("/me")
async def me(request: Request):
    user_id = require_user(request)
    if not user_id:
        return {"authenticated": False}
    user = await asyncio.to_thread(database.get_user, user_id)
    return {"authenticated": True, "user": user} if user else {"authenticated": False}


@app.get("/history")
async def history(request: Request, minutes: int = 60):
    if not require_user(request):
        return auth_error("Login required")
    return await asyncio.to_thread(database.get_history, max(1, min(minutes, 10080)))


@app.get("/api/analytics")
async def analytics(request: Request, minutes: int = 1440):
    if not require_user(request):
        return auth_error("Login required")
    return await asyncio.to_thread(database.get_analytics, max(1, min(minutes, 10080)))


@app.get("/api/anomalies")
async def anomalies(request: Request, minutes: int = 10080):
    if not require_user(request):
        return auth_error("Login required")
    return await asyncio.to_thread(database.get_anomalies, max(1, min(minutes, 10080)))


@app.get("/api/devices")
async def devices(request: Request, minutes: int = 60):
    if not require_user(request):
        return auth_error("Login required")
    return await asyncio.to_thread(database.get_devices, max(1, min(minutes, 10080)))


@app.get("/api/devices/{ip:path}")
async def device_history(request: Request, ip: str, minutes: int = 1440):
    if not require_user(request):
        return auth_error("Login required")
    return await asyncio.to_thread(database.get_device_history, ip, max(1, min(minutes, 10080)))


@app.get("/api/routes")
async def routes(request: Request):
    if not require_user(request):
        return auth_error("Login required")
    return await asyncio.to_thread(database.get_latest_routes)


@app.get("/api/routes/{target:path}")
async def route_history(request: Request, target: str):
    if not require_user(request):
        return auth_error("Login required")
    return await asyncio.to_thread(database.get_route_history, target)


@app.get("/api/bottlenecks")
async def bottlenecks(request: Request):
    if not require_user(request):
        return auth_error("Login required")
    return await asyncio.to_thread(database.get_bottlenecks)


async def enrich_route(route: dict) -> dict:
    hops = route.get("hops", [])
    public_targets = [h.get("ip") for h in hops if public_ip(h.get("ip"))]
    if not public_targets:
        return route

    async with httpx.AsyncClient(timeout=4) as client:
        for hop in hops:
            ip = hop.get("ip")
            if not public_ip(ip):
                continue
            if ip in GEO_CACHE:
                hop.update(GEO_CACHE[ip])
                continue
            try:
                response = await client.get(f"https://ipwho.is/{ip}")
                data = response.json()
                if data.get("success"):
                    geo = {
                        "country": data.get("country"),
                        "city": data.get("city"),
                        "location": ", ".join(x for x in [data.get("city"), data.get("country")] if x),
                        "organization": (data.get("connection") or {}).get("org"),
                        "latitude": data.get("latitude"),
                        "longitude": data.get("longitude"),
                    }
                    GEO_CACHE[ip] = geo
                    hop.update(geo)
            except Exception:
                continue
    return route


@app.websocket("/ws/ingest")
async def ws_ingest(websocket: WebSocket, token: str = ""):
    device = None

    if token:
        token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
        device = await asyncio.to_thread(
            database.get_device_by_token,
            token_hash,
        )

    if device is None and token != INGEST_TOKEN:
        await websocket.close(code=4401)
        print("[backend] rejected agent connection: bad token")
        return

    await websocket.accept()

    if device:
        print(
            f"[backend] device connected: "
            f"{device['device_id']} (user {device['user_id']})"
        )
    else:
        print("[backend] legacy agent connected")

    try:
        while True:
            message = json.loads(await websocket.receive_text())
            kind = message.get("type")

            if kind == "packet_batch":
                if device:
                    device_id = device["device_id"]
                    user_id = device["user_id"]
                else:
                    device_id = message.get("device_id") or "legacy"
                    user_id = None

                packet_list = message.get("packets", [])

                for packet in packet_list:
                    if isinstance(packet, dict):
                        packet["device_id"] = device_id

                if device:
                    if device_id not in stats_by_device:
                        stats_by_device[device_id] = RollingStats()

                    device_user_ids[device_id] = user_id
                    stats_by_device[device_id].add_batch(packet_list)
                else:
                    stats.add_batch(packet_list)

            elif kind == "route_batch":
                for route in message.get("routes", []):
                    enriched = await enrich_route(route)

                    await asyncio.to_thread(
                        database.save_route_observation,
                        enriched.get("target", ""),
                        enriched.get("hops", []),
                        enriched.get("total_rtt_ms"),
                    )

                    await asyncio.to_thread(
                        database.save_route_events,
                        enriched.get("events", []),
                    )

    except WebSocketDisconnect:
        print("[backend] agent disconnected")
    except Exception as exc:
        print(f"[backend] ingest error: {exc}")

@app.websocket("/ws/dashboard")
async def ws_dashboard(websocket: WebSocket):
    user_id = get_user_id(websocket.cookies.get(SESSION_COOKIE))
    await dashboard_manager.connect(websocket, user_id)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        dashboard_manager.disconnect(websocket)

async def broadcast_loop():
    while True:
        await asyncio.sleep(BROADCAST_INTERVAL)

        if stats_by_device:
            for device_id, device_stats in list(stats_by_device.items()):
                snapshot = device_stats.snapshot()
                snapshot["device_id"] = device_id
                user_id = device_user_ids.get(device_id)

                # Send live data first. Database failures must not stop the dashboard.
                if user_id is not None and dashboard_manager.clients:
                    await dashboard_manager.broadcast(snapshot, user_id)

                # Save history separately. A DB failure must not kill this loop.
                try:
                    await asyncio.to_thread(database.save_snapshot, snapshot)

                    if snapshot.get("alerts"):
                        await asyncio.to_thread(
                            database.save_anomalies,
                            snapshot["alerts"],
                        )

                except Exception as exc:
                    print(f"[backend] persistence error: {exc}")

        elif stats.packets:
            snapshot = stats.snapshot()

            if dashboard_manager.clients:
                await dashboard_manager.broadcast(snapshot, None)

            try:
                await asyncio.to_thread(database.save_snapshot, snapshot)

                if snapshot.get("alerts"):
                    await asyncio.to_thread(
                        database.save_anomalies,
                        snapshot["alerts"],
                    )

            except Exception as exc:
                print(f"[backend] persistence error: {exc}")

@app.on_event("startup")
async def startup():
    database.init_db()
    await asyncio.to_thread(database.prune_old, 7)
    asyncio.create_task(broadcast_loop())


if not STATIC_DIR.exists():
    STATIC_DIR.mkdir(parents=True, exist_ok=True)

app.mount("/", StaticFiles(directory=str(STATIC_DIR), html=True), name="frontend")






