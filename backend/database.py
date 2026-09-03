import json
import os
import time
from typing import Any

from sqlalchemy import Column, Float, Integer, String, Text, create_engine, text
from sqlalchemy.orm import declarative_base, sessionmaker

DATABASE_URL = os.environ.get("DATABASE_URL", "sqlite:///traffic.db")
if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False} if "sqlite" in DATABASE_URL else {},
)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)
Base = declarative_base()


class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, autoincrement=True)
    username = Column(String(64), unique=True, index=True, nullable=False)
    password_hash = Column(String(255), nullable=False)
    created_at = Column(Float, default=time.time, nullable=False)

class Device(Base):
    __tablename__ = "devices"

    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(Integer, index=True, nullable=False)
    device_id = Column(String(255), index=True, nullable=False)
    device_name = Column(String(255), nullable=True)
    token_hash = Column(String(255), nullable=False, unique=True, index=True)
    created_at = Column(Float, default=time.time, nullable=False)
    last_seen = Column(Float, default=time.time, nullable=False)

class Snapshot(Base):
    __tablename__ = "snapshots"
    id = Column(Integer, primary_key=True, autoincrement=True)
    ts = Column(Float, index=True, nullable=False)
    total_bps = Column(Integer, nullable=False)
    total_pps = Column(Integer, nullable=False)
    active_devices = Column(Integer, nullable=False)
    top_talkers_json = Column(Text, nullable=False)
    protocol_breakdown_json = Column(Text, nullable=False)


class DeviceSample(Base):
    __tablename__ = "device_samples"
    id = Column(Integer, primary_key=True, autoincrement=True)
    ts = Column(Float, index=True, nullable=False)
    ip = Column(String(64), index=True, nullable=False)
    bytes = Column(Integer, nullable=False)
    packets = Column(Integer, nullable=False)


class Anomaly(Base):
    __tablename__ = "anomalies"
    id = Column(Integer, primary_key=True, autoincrement=True)
    ts = Column(Float, index=True, nullable=False)
    ip = Column(String(64), index=True, nullable=False)
    current_bytes = Column(Integer, nullable=False)
    baseline_bytes = Column(Integer, nullable=False)
    multiplier = Column(Float, nullable=False)
    message = Column(Text, nullable=False)


class RouteObservation(Base):
    __tablename__ = "route_observations"
    id = Column(Integer, primary_key=True, autoincrement=True)
    ts = Column(Float, index=True, nullable=False)
    target = Column(String(255), index=True, nullable=False)
    total_hops = Column(Integer, nullable=False)
    total_rtt_ms = Column(Float, nullable=True)
    hops_json = Column(Text, nullable=False)


class HopStat(Base):
    __tablename__ = "hop_stats"
    id = Column(Integer, primary_key=True, autoincrement=True)
    ip = Column(String(64), index=True, nullable=False)
    hostname = Column(String(255), nullable=True)
    location = Column(String(255), nullable=True)
    organization = Column(String(255), nullable=True)
    country = Column(String(128), nullable=True)
    city = Column(String(128), nullable=True)
    observations = Column(Integer, default=0, nullable=False)
    timeouts = Column(Integer, default=0, nullable=False)
    total_rtt_ms = Column(Float, default=0.0, nullable=False)
    max_rtt_ms = Column(Float, default=0.0, nullable=False)
    last_seen = Column(Float, index=True, nullable=False)
    latitude = Column(Float, nullable=True)
    longitude = Column(Float, nullable=True)


class RouteEvent(Base):
    __tablename__ = "route_events"
    id = Column(Integer, primary_key=True, autoincrement=True)
    ts = Column(Float, index=True, nullable=False)
    target = Column(String(255), index=True, nullable=False)
    hop_number = Column(Integer, nullable=False)
    ip = Column(String(64), nullable=True)
    event_type = Column(String(32), nullable=False)  # timeout, loss, latency_spike, route_change
    rtt_ms = Column(Float, nullable=True)
    details = Column(Text, nullable=True)


def init_db() -> None:
    Base.metadata.create_all(engine)


def get_user(user_id: int) -> dict[str, Any] | None:
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.id == user_id).first()
        return {"id": user.id, "username": user.username} if user else None
    finally:
        db.close()


def get_user_by_username(username: str) -> dict[str, Any] | None:
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.username == username).first()
        if not user:
            return None
        return {"id": user.id, "username": user.username, "password_hash": user.password_hash}
    finally:
        db.close()


def create_user(username: str, password_hash: str) -> dict[str, Any]:
    db = SessionLocal()
    try:
        if db.query(User).filter(User.username == username).first():
            raise ValueError("Username already exists")
        user = User(username=username, password_hash=password_hash)
        db.add(user)
        db.commit()
        db.refresh(user)
        return {"id": user.id, "username": user.username}
    finally:
        db.close()

def register_device(
    user_id: int,
    device_id: str,
    device_name: str | None = None,
    token_hash: str | None = None,
) -> dict[str, Any]:
    db = SessionLocal()
    try:
        device = (
            db.query(Device)
            .filter(
                Device.user_id == user_id,
                Device.device_id == device_id,
            )
            .first()
        )

        now = time.time()

        if device:
            device.last_seen = now
            if device_name:
                device.device_name = device_name
        else:
            device = Device(
                user_id=user_id,
                device_id=device_id,
                device_name=device_name or device_id,
                token_hash=token_hash,
                created_at=now,
                last_seen=now,
            )
            db.add(device)

        db.commit()
        db.refresh(device)

        return {
            "id": device.id,
            "user_id": device.user_id,
            "device_id": device.device_id,
            "device_name": device.device_name,
            "last_seen": device.last_seen,
        }
    finally:
        db.close()


def get_device(
    user_id: int,
    device_id: str,
) -> dict[str, Any] | None:
    db = SessionLocal()
    try:
        device = (
            db.query(Device)
            .filter(
                Device.user_id == user_id,
                Device.device_id == device_id,
            )
            .first()
        )

        if not device:
            return None

        return {
            "id": device.id,
            "user_id": device.user_id,
            "device_id": device.device_id,
            "device_name": device.device_name,
            "last_seen": device.last_seen,
        }
    finally:
        db.close()


def save_snapshot(snapshot: dict[str, Any]) -> None:
    db = SessionLocal()
    try:
        db.add(
            Snapshot(
                ts=snapshot["ts"],
                total_bps=int(snapshot["total_bps"]),
                total_pps=int(snapshot["total_pps"]),
                active_devices=int(snapshot["active_devices"]),
                top_talkers_json=json.dumps(snapshot.get("top_talkers", [])),
                protocol_breakdown_json=json.dumps(snapshot.get("protocol_breakdown", {})),
            )
        )
        for sample in snapshot.get("device_samples", []):
            db.add(DeviceSample(
                ts=snapshot["ts"],
                ip=sample["ip"],
                bytes=int(sample["bytes"]),
                packets=int(sample["packets"]),
            ))
        db.commit()
    finally:
        db.close()


def get_history(minutes: int = 60) -> list[dict[str, Any]]:
    cutoff = time.time() - max(1, minutes) * 60
    db = SessionLocal()
    try:
        rows = db.query(Snapshot).filter(Snapshot.ts >= cutoff).order_by(Snapshot.ts.asc()).all()
        return [
            {
                "ts": r.ts,
                "total_bps": r.total_bps,
                "total_pps": r.total_pps,
                "active_devices": r.active_devices,
                "top_talkers": json.loads(r.top_talkers_json),
                "protocol_breakdown": json.loads(r.protocol_breakdown_json),
            }
            for r in rows
        ]
    finally:
        db.close()


def get_devices(minutes: int = 60, limit: int = 100) -> list[dict[str, Any]]:
    cutoff = time.time() - max(1, minutes) * 60
    db = SessionLocal()
    try:
        rows = db.query(DeviceSample).filter(DeviceSample.ts >= cutoff).all()
        agg: dict[str, dict[str, Any]] = {}
        for r in rows:
            item = agg.setdefault(r.ip, {"ip": r.ip, "bytes": 0, "packets": 0, "samples": 0, "peak_bps": 0, "last_seen": r.ts})
            item["bytes"] += r.bytes
            item["packets"] += r.packets
            item["samples"] += 1
            item["peak_bps"] = max(item["peak_bps"], r.bytes)
            item["last_seen"] = max(item["last_seen"], r.ts)
        out = list(agg.values())
        for item in out:
            item["avg_bps"] = round(item["bytes"] / max(item["samples"], 1))
        out.sort(key=lambda x: x["bytes"], reverse=True)
        return out[:limit]
    finally:
        db.close()


def get_device_history(ip: str, minutes: int = 60) -> list[dict[str, Any]]:
    cutoff = time.time() - max(1, minutes) * 60
    db = SessionLocal()
    try:
        rows = db.query(DeviceSample).filter(DeviceSample.ip == ip, DeviceSample.ts >= cutoff).order_by(DeviceSample.ts.asc()).all()
        return [{"ts": r.ts, "bytes": r.bytes, "packets": r.packets} for r in rows]
    finally:
        db.close()


def save_anomalies(alerts: list[dict[str, Any]]) -> None:
    if not alerts:
        return
    db = SessionLocal()
    try:
        for alert in alerts:
            db.add(
                Anomaly(
                    ts=alert["ts"],
                    ip=alert["ip"],
                    current_bytes=int(alert["current_bytes"]),
                    baseline_bytes=int(alert["baseline_bytes"]),
                    multiplier=float(alert["multiplier"]),
                    message=alert["message"],
                )
            )
        db.commit()
    finally:
        db.close()


def get_anomalies(minutes: int = 1440, limit: int = 200) -> list[dict[str, Any]]:
    cutoff = time.time() - max(1, minutes) * 60
    db = SessionLocal()
    try:
        rows = (
            db.query(Anomaly)
            .filter(Anomaly.ts >= cutoff)
            .order_by(Anomaly.ts.desc())
            .limit(limit)
            .all()
        )
        return [
            {
                "id": r.id,
                "ts": r.ts,
                "ip": r.ip,
                "current_bytes": r.current_bytes,
                "baseline_bytes": r.baseline_bytes,
                "multiplier": r.multiplier,
                "message": r.message,
            }
            for r in rows
        ]
    finally:
        db.close()


def save_route_observation(target: str, hops: list[dict[str, Any]], total_rtt_ms: float | None) -> None:
    now = time.time()
    db = SessionLocal()
    try:
        db.add(
            RouteObservation(
                ts=now,
                target=target,
                total_hops=len(hops),
                total_rtt_ms=total_rtt_ms,
                hops_json=json.dumps(hops),
            )
        )

        for hop in hops:
            ip = hop.get("ip") or f"timeout-{target}-{hop.get('hop', 0)}"
            stat = db.query(HopStat).filter(HopStat.ip == ip).first()
            if not stat:
                stat = HopStat(ip=ip, last_seen=now)
                db.add(stat)
                db.flush()

            stat.hostname = hop.get("hostname") or stat.hostname
            stat.location = hop.get("location") or stat.location
            stat.organization = hop.get("organization") or stat.organization
            stat.country = hop.get("country") or stat.country
            stat.city = hop.get("city") or stat.city
            stat.latitude = hop.get("latitude") if hop.get("latitude") is not None else stat.latitude
            stat.longitude = hop.get("longitude") if hop.get("longitude") is not None else stat.longitude
            stat.observations += 1
            stat.last_seen = now

            if hop.get("timeout"):
                stat.timeouts += 1
            else:
                rtt = hop.get("rtt_ms")
                if rtt is not None:
                    stat.total_rtt_ms += float(rtt)
                    stat.max_rtt_ms = max(stat.max_rtt_ms, float(rtt))

        db.commit()
    finally:
        db.close()


def save_route_events(events: list[dict[str, Any]]) -> None:
    if not events:
        return
    db = SessionLocal()
    try:
        for e in events:
            db.add(
                RouteEvent(
                    ts=e["ts"],
                    target=e["target"],
                    hop_number=int(e["hop_number"]),
                    ip=e.get("ip"),
                    event_type=e["event_type"],
                    rtt_ms=e.get("rtt_ms"),
                    details=e.get("details"),
                )
            )
        db.commit()
    finally:
        db.close()


def get_latest_routes(limit: int = 50) -> list[dict[str, Any]]:
    db = SessionLocal()
    try:
        rows = db.query(RouteObservation).order_by(RouteObservation.ts.desc()).limit(limit).all()
        return [
            {
                "id": r.id,
                "ts": r.ts,
                "target": r.target,
                "total_hops": r.total_hops,
                "total_rtt_ms": r.total_rtt_ms,
                "hops": json.loads(r.hops_json),
            }
            for r in rows
        ]
    finally:
        db.close()


def get_route_history(target: str, limit: int = 100) -> list[dict[str, Any]]:
    db = SessionLocal()
    try:
        rows = (
            db.query(RouteObservation)
            .filter(RouteObservation.target == target)
            .order_by(RouteObservation.ts.desc())
            .limit(limit)
            .all()
        )
        return [
            {"id": r.id, "ts": r.ts, "target": r.target, "total_hops": r.total_hops, "total_rtt_ms": r.total_rtt_ms, "hops": json.loads(r.hops_json)}
            for r in rows
        ]
    finally:
        db.close()


def get_bottlenecks(limit: int = 100) -> list[dict[str, Any]]:
    db = SessionLocal()
    try:
        rows = db.query(HopStat).order_by(HopStat.timeouts.desc(), HopStat.max_rtt_ms.desc()).limit(limit).all()
        events = db.query(RouteEvent).filter(RouteEvent.event_type.in_(["timeout", "loss", "latency_spike"])).all()
        event_counts: dict[tuple[str, int], int] = {}
        for e in events:
            key = (e.ip or "unknown", e.hop_number)
            event_counts[key] = event_counts.get(key, 0) + 1

        out = []
        for r in rows:
            avg = (r.total_rtt_ms / r.observations) if r.observations > 0 else None
            matching = sum(v for (ip, _hop), v in event_counts.items() if ip == r.ip)
            out.append(
                {
                    "ip": r.ip,
                    "hostname": r.hostname,
                    "location": r.location,
                    "organization": r.organization,
                    "country": r.country,
                    "city": r.city,
                    "latitude": r.latitude,
                    "longitude": r.longitude,
                    "observations": r.observations,
                    "timeouts": r.timeouts,
                    "event_count": matching,
                    "avg_rtt_ms": avg,
                    "max_rtt_ms": r.max_rtt_ms,
                    "last_seen": r.last_seen,
                }
            )
        return out
    finally:
        db.close()


def get_analytics(minutes: int = 1440) -> dict[str, Any]:
    rows = get_history(minutes)
    if not rows:
        return {"samples": 0, "average_bps": 0, "peak_bps": 0, "total_bytes": 0, "average_pps": 0, "peak_pps": 0}
    bps = [r["total_bps"] for r in rows]
    pps = [r["total_pps"] for r in rows]
    return {
        "samples": len(rows),
        "average_bps": round(sum(bps) / len(bps)),
        "peak_bps": max(bps),
        "total_bytes": sum(bps),
        "average_pps": round(sum(pps) / len(pps)),
        "peak_pps": max(pps),
    }


def prune_old(days: int = 7) -> None:
    cutoff = time.time() - days * 86400
    db = SessionLocal()
    try:
        for table in (Snapshot, DeviceSample, Anomaly, RouteObservation, RouteEvent):
            db.query(table).filter(table.ts < cutoff).delete(synchronize_session=False)
        db.commit()
        if "sqlite" in DATABASE_URL:
            with engine.connect() as conn:
                conn.execute(text("VACUUM"))
    finally:
        db.close()

def get_devices_for_user(user_id: int) -> list[dict[str, Any]]:
    db = SessionLocal()
    try:
        devices = (
            db.query(Device)
            .filter(Device.user_id == user_id)
            .order_by(Device.created_at.desc())
            .all()
        )

        return [
            {
                "id": device.id,
                "device_id": device.device_id,
                "device_name": device.device_name,
                "created_at": device.created_at,
                "last_seen": device.last_seen,
            }
            for device in devices
        ]
    finally:
        db.close()



