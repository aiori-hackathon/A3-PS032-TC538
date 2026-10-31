"""Opt-in RIPE RIS Live monitor with bounded in-memory event history.

The default subscription is scoped to the exact PATHWATCH_LIVE_PREFIX
to avoid subscribing to the global firehose. Live validation uses the
locally available VRP set; the API reports its source and timestamp explicitly.
"""
from __future__ import annotations


import json
import ipaddress
import os
import threading
import time
from collections import deque
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from src.rpki_validator import VRP, validate_prefix_origin
from src.vrp_cache import vrp_cache

ROOT = Path(__file__).resolve().parents[1]
PROCESSED = ROOT / "data" / "processed"
RAW = ROOT / "data" / "raw"
RIS_URL = "wss://ris-live.ripe.net/v1/ws/?client=rpki-pathwatch-a3-ps032"
DEFAULT_PREFIX = os.getenv("PATHWATCH_LIVE_PREFIX", "193.0.0.0/21")
MAX_EVENTS = 1000


def load_local_vrps() -> tuple[list[VRP], str | None, str | None]:
    """Load the most relevant locally available ROAs and disclose provenance."""
    candidates = [
        PROCESSED / "rpki_bgp_correlation.json",
        RAW / "rpki_current_193.0.0.0_21_3333.json",
    ]
    rows: list[dict[str, Any]] = []
    source = None
    source_time = None

    # The current RIPE Stat response has the most explicit source timestamp.
    current_path = candidates[1]
    try:
        current = json.loads(current_path.read_text(encoding="utf-8"))
        payload = current.get("data", {})
        raw_roas = payload.get("validating_roas", [])
        if isinstance(raw_roas, list) and raw_roas:
            rows = [
                {
                    "prefix": row.get("prefix"),
                    "origin": row.get("origin"),
                    "max_length": row.get("max_length"),
                }
                for row in raw_roas
                if isinstance(row, dict) and row.get("prefix") and row.get("origin") is not None
            ]
            source = str(current_path.relative_to(ROOT))
            source_time = current.get("time")
    except (OSError, json.JSONDecodeError, TypeError):
        pass

    if not rows:
        try:
            corr = json.loads(candidates[0].read_text(encoding="utf-8"))
            raw_vrps = corr.get("vrp_summary", [])
            if isinstance(raw_vrps, list):
                rows = [
                    {
                        "prefix": row.get("prefix"),
                        "origin": row.get("origin_asn", row.get("asn")),
                        "max_length": row.get("max_length"),
                    }
                    for row in raw_vrps
                    if isinstance(row, dict) and row.get("prefix") and row.get("origin_asn", row.get("asn")) is not None
                ]
                source = str(candidates[0].relative_to(ROOT))
                source_time = (corr.get("metadata") or {}).get("generated_at_utc")
        except (OSError, json.JSONDecodeError, TypeError):
            pass

    vrps: list[VRP] = []
    for row in rows:
        try:
            vrps.append(VRP.from_dict(row, snapshot_id=source or "local-vrp-data"))
        except (ValueError, TypeError, KeyError):
            continue
    return vrps, source, source_time


def normalize_ris_message(message: dict[str, Any], vrps: list[VRP], received_at: datetime | None = None) -> list[dict[str, Any]]:
    """Convert a RIS Live UPDATE into one row per announced/withdrawn prefix."""
    if not isinstance(message, dict) or message.get("type") != "ris_message":
        return []
    data = message.get("data")
    if not isinstance(data, dict) or data.get("type") != "UPDATE":
        return []

    stamp = received_at or datetime.now(timezone.utc)
    event_ts = data.get("timestamp")
    try:
        observed_time = datetime.fromtimestamp(float(event_ts), tz=timezone.utc).isoformat()
    except (TypeError, ValueError, OSError, OverflowError):
        observed_time = None

    path = data.get("path") if isinstance(data.get("path"), list) else None
    base = {
        "source": "RIPE RIS Live",
        "observed_at_utc": observed_time,
        "received_at_utc": stamp.isoformat(),
        "peer": data.get("peer"),
        "peer_asn": data.get("peer_asn"),
        "collector": data.get("host"),
        "message_id": data.get("id"),
        "as_path": path,
    }
    rows: list[dict[str, Any]] = []

    for announcement in data.get("announcements", []) or []:
        if not isinstance(announcement, dict):
            continue
        for prefix in announcement.get("prefixes", []) or []:
            if not isinstance(prefix, str):
                continue
            try:
                if not ipaddress.ip_network(prefix, strict=False).subnet_of(
                    ipaddress.ip_network(DEFAULT_PREFIX, strict=False)
                ):
                    continue
            except ValueError:
                continue
            result = validate_prefix_origin(prefix, path, "A", vrps, reference_time=stamp)
            rows.append({**base, "prefix": prefix, "event_type": "A", **result})

    for prefix in data.get("withdrawals", []) or []:
        if not isinstance(prefix, str):
            continue
        try:
            if not ipaddress.ip_network(prefix, strict=False).subnet_of(
                ipaddress.ip_network(DEFAULT_PREFIX, strict=False)
            ):
                continue
        except ValueError:
            continue
        result = validate_prefix_origin(prefix, path, "W", vrps, reference_time=stamp)
        rows.append({**base, "prefix": prefix, "event_type": "W", **result})

    return rows


class RISLiveMonitor:
    def __init__(self, max_events: int = MAX_EVENTS):
        self._lock = threading.RLock()
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None
        self._ws = None
        self._events: deque[dict[str, Any]] = deque(maxlen=max_events)
        self._status: dict[str, Any] = {
            "state": "stopped",
            "connected": False,
            "started_at_utc": None,
            "last_message_at_utc": None,
            "last_error": None,
            "received_messages": 0,
            "subscription_acknowledgements": 0,
            "bgp_updates_received": 0,
            "filtered_events": 0,
            "processed_events": 0,
            "subscription_prefix": DEFAULT_PREFIX,
            "subscription_scope": "Prefix subscription including more-specific routes",
            "source": "RIPE RIS Live WebSocket",
        }

    def status(self) -> dict[str, Any]:
        with self._lock:
            return {**self._status, "buffered_events": len(self._events), "max_events": self._events.maxlen}

    def events(self, limit: int = 100) -> list[dict[str, Any]]:
        limit = max(1, min(int(limit), self._events.maxlen or MAX_EVENTS))
        with self._lock:
            return list(self._events)[:limit]

    def start(self) -> dict[str, Any]:
        with self._lock:
            if self._thread and self._thread.is_alive():
                return self.status()
            self._stop_event.clear()
            self._status.update({
                "state": "connecting", "connected": False,
                "started_at_utc": datetime.now(timezone.utc).isoformat(),
                "last_error": None,
                "received_messages": 0,
                "subscription_acknowledgements": 0,
                "bgp_updates_received": 0,
                "filtered_events": 0,
                "processed_events": 0,
                "subscription_prefix": DEFAULT_PREFIX,
                "subscription_scope": "Prefix subscription including more-specific routes",
            })
            self._thread = threading.Thread(target=self._run, name="pathwatch-ris-live", daemon=True)
            self._thread.start()
            return self.status()

    def stop(self) -> dict[str, Any]:
        self._stop_event.set()
        with self._lock:
            ws = self._ws
            self._status["state"] = "stopping" if self._thread and self._thread.is_alive() else "stopped"
            self._status["connected"] = False
        if ws is not None:
            try:
                ws.close()
            except Exception:
                pass
        return self.status()

    def _run(self) -> None:
        try:
            import websocket
        except ImportError:
            with self._lock:
                self._status.update(state="error", last_error="Install websocket-client to enable live monitoring.")
            return

        retry_delay = 1
        while not self._stop_event.is_set():
            try:
                ws = websocket.create_connection(RIS_URL, timeout=15, enable_multithread=True)
                ws.settimeout(60)
                with self._lock:
                    self._ws = ws
                    self._status.update(state="connected", connected=True, last_error=None)
                subscription = {
                    "type": "ris_subscribe",
                    "data": {
                        "type": "UPDATE",
                        "prefix": DEFAULT_PREFIX,
                        "moreSpecific": True,
                        "lessSpecific": False,
                        "socketOptions": {"acknowledge": True},
                    },
                }
                ws.send(json.dumps(subscription))
                retry_delay = 1
                while not self._stop_event.is_set():
                    try:
                        raw = ws.recv()
                    except websocket.WebSocketTimeoutException:
                        continue
                    if not raw:
                        continue
                    try:
                        payload = json.loads(raw)
                    except json.JSONDecodeError:
                        continue

                    now = datetime.now(timezone.utc)
                    print("[RIS DEBUG]", json.dumps(payload)[:2000], flush=True)

                    with self._lock:
                        self._status["last_message_at_utc"] = now.isoformat()
                        self._status["received_messages"] += 1

                    if isinstance(payload, dict) and payload.get("type") == "ping":
                        ws.send(json.dumps({"type": "pong", "data": None}))
                        continue

                    if isinstance(payload, dict) and payload.get("type") == "ris_subscribe_ok":
                        with self._lock:
                            self._status["subscription_acknowledgements"] += 1
                        continue

                    if isinstance(payload, dict) and payload.get("type") == "ris_error":
                        with self._lock:
                            self._status["last_error"] = (payload.get("data") or {}).get("message", "RIS Live error")
                        continue

                    if isinstance(payload, dict) and payload.get("type") == "ris_message":
                        data = payload.get("data") or {}
                        if data.get("type") != "UPDATE":
                            continue

                        announcements = data.get("announcements", []) or []
                        withdrawals = data.get("withdrawals", []) or []
                        candidate_count = sum(
                            isinstance(prefix, str)
                            for announcement in announcements
                            if isinstance(announcement, dict)
                            for prefix in (announcement.get("prefixes", []) or [])
                        ) + sum(isinstance(prefix, str) for prefix in withdrawals)

                        with self._lock:
                            self._status["bgp_updates_received"] += 1

                        vrps = vrp_cache.get_vrps()
                        rows = normalize_ris_message(payload, vrps, received_at=now)

                        with self._lock:
                            self._status["filtered_events"] += max(0, candidate_count - len(rows))
                            for row in reversed(rows):
                                self._events.appendleft(row)
                            self._status["processed_events"] += len(rows)
            except Exception as exc:
                if self._stop_event.is_set():
                    break
                with self._lock:
                    self._status.update(state="reconnecting", connected=False, last_error=f"{type(exc).__name__}: {exc}")
            finally:
                with self._lock:
                    ws = self._ws
                    self._ws = None
                    self._status["connected"] = False
                if ws is not None:
                    try:
                        ws.close()
                    except Exception:
                        pass
            if not self._stop_event.wait(retry_delay):
                retry_delay = min(retry_delay * 2, 30)

        with self._lock:
            self._status.update(state="stopped", connected=False)


monitor = RISLiveMonitor()
