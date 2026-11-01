"""Shared, refreshable cache of relevant RPKI VRPs from RIPE Routinator."""

from __future__ import annotations

import ipaddress
import json
import os
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import requests

from src.rpki_validator import VRP


ROOT = Path(__file__).resolve().parents[1]
RAW = ROOT / "data" / "raw"
CACHE_FILE = RAW / "rpki_live_vrps.json"

VRP_EXPORT_URL = "https://rpki-validator.ripe.net/api/export.json"
DEFAULT_PREFIX = os.getenv("PATHWATCH_LIVE_PREFIX", "193.0.0.0/21")
REFRESH_INTERVAL_SECONDS = int(os.getenv("PATHWATCH_VRP_REFRESH_SECONDS", "3600"))
REQUEST_TIMEOUT_SECONDS = 90
MAX_RESPONSE_BYTES = 250 * 1024 * 1024


class VRPCache:
    """Thread-safe cache with periodic refresh and last-known-good fallback."""

    def __init__(
        self,
        target_prefix: str = DEFAULT_PREFIX,
        cache_file: Path = CACHE_FILE,
        refresh_interval: int = REFRESH_INTERVAL_SECONDS,
    ):
        self.target = ipaddress.ip_network(target_prefix, strict=False)
        self.cache_file = Path(cache_file)
        self.refresh_interval = max(60, int(refresh_interval))

        self._lock = threading.RLock()
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None
        self._vrps: list[VRP] = []

        self._status: dict[str, Any] = {
            "validation_data_source": None,
            "validation_data_timestamp": None,
            "validation_retrieved_at_utc": None,
            "validation_vrp_count": 0,
            "validation_data_age_seconds": None,
            "validation_data_fresh": False,
            "validation_refresh_status": "not_started",
            "validation_last_refresh_error": None,
            "validation_refresh_interval_seconds": self.refresh_interval,
        }

        self._load_cached_snapshot()

    def seed_if_empty(
        self,
        vrps: list[VRP],
        source: str | None,
        source_time: str | None,
    ) -> None:
        """Use existing local VRPs until the first successful feed refresh."""
        with self._lock:
            if self._vrps or not vrps:
                return

            self._vrps = list(vrps)
            self._status.update({
                "validation_data_source": source,
                "validation_data_timestamp": source_time,
                "validation_retrieved_at_utc": None,
                "validation_vrp_count": len(vrps),
                "validation_data_fresh": False,
                "validation_refresh_status": "using_fallback",
            })

    def get_vrps(self) -> list[VRP]:
        """Return a stable copy of the current VRP set."""
        with self._lock:
            return list(self._vrps)

    def status(self) -> dict[str, Any]:
        """Return cache provenance and freshness information."""
        with self._lock:
            result = dict(self._status)

        retrieved = result.get("validation_retrieved_at_utc")
        if retrieved:
            try:
                stamp = datetime.fromisoformat(retrieved)
                age = max(0, int((datetime.now(timezone.utc) - stamp).total_seconds()))
                result["validation_data_age_seconds"] = age
                result["validation_data_fresh"] = age <= self.refresh_interval * 2
            except (TypeError, ValueError):
                pass

        return result

    def _is_relevant(self, raw_prefix: str) -> bool:
        try:
            network = ipaddress.ip_network(raw_prefix, strict=False)
        except (TypeError, ValueError):
            return False

        return (
            network.version == self.target.version
            and network.overlaps(self.target)
        )

    def _parse_export(self, payload: Any) -> tuple[list[VRP], str]:
        if not isinstance(payload, dict):
            raise ValueError("Routinator response is not a JSON object")

        metadata = payload.get("metadata")
        rows = payload.get("roas")

        if not isinstance(metadata, dict):
            raise ValueError("Routinator response has no metadata object")

        if not isinstance(rows, list) or not rows:
            raise ValueError("Routinator response has no non-empty ROA list")

        generated = metadata.get("generatedTime")
        if not isinstance(generated, str) or not generated:
            raise ValueError("Routinator response has no generatedTime timestamp")

        parsed: list[VRP] = []
        for row in rows:
            if not isinstance(row, dict):
                continue

            raw_prefix = row.get("prefix")
            if not isinstance(raw_prefix, str) or not self._is_relevant(raw_prefix):
                continue

            try:
                parsed.append(
                    VRP.from_dict(
                        {
                            "asn": row.get("asn"),
                            "prefix": raw_prefix,
                            "maxLength": row.get("maxLength"),
                        },
                        snapshot_id="RIPE Routinator export",
                    )
                )
            except (ValueError, TypeError, KeyError):
                continue

        if not parsed:
            raise ValueError(
                f"Export contained no usable VRPs overlapping {self.target}"
            )

        return parsed, generated

    def _persist(self, vrps: list[VRP], generated: str, retrieved: str) -> None:
        self.cache_file.parent.mkdir(parents=True, exist_ok=True)

        document = {
            "source": VRP_EXPORT_URL,
            "target_prefix": str(self.target),
            "generated_time": generated,
            "retrieved_at_utc": retrieved,
            "vrp_count": len(vrps),
            "roas": [
                {
                    "asn": f"AS{vrp.asn}",
                    "prefix": str(vrp.prefix),
                    "maxLength": vrp.max_length,
                }
                for vrp in vrps
            ],
        }

        temporary = self.cache_file.with_suffix(
            self.cache_file.suffix + ".tmp"
        )

        try:
            with temporary.open("w", encoding="utf-8") as handle:
                json.dump(document, handle, separators=(",", ":"))
                handle.flush()
                os.fsync(handle.fileno())

            os.replace(temporary, self.cache_file)
        finally:
            if temporary.exists():
                temporary.unlink()

    def _source_label(self) -> str:
        try:
            return str(self.cache_file.relative_to(ROOT))
        except ValueError:
            return str(self.cache_file)

    def _load_cached_snapshot(self) -> None:
        try:
            document = json.loads(self.cache_file.read_text(encoding="utf-8"))
            if document.get("target_prefix") != str(self.target):
                return

            rows = document.get("roas")
            if not isinstance(rows, list) or not rows:
                return

            parsed = []
            for row in rows:
                if not isinstance(row, dict):
                    continue
                try:
                    parsed.append(
                        VRP.from_dict(row, snapshot_id="RIPE Routinator cached snapshot")
                    )
                except (ValueError, TypeError, KeyError):
                    continue

            if not parsed:
                return

            with self._lock:
                self._vrps = parsed
                self._status.update({
                    "validation_data_source": self._source_label(),
                    "validation_data_timestamp": document.get("generated_time"),
                    "validation_retrieved_at_utc": document.get("retrieved_at_utc"),
                    "validation_vrp_count": len(parsed),
                    "validation_refresh_status": "cached",
                })

        except (OSError, json.JSONDecodeError, TypeError, ValueError):
            return

    def refresh_once(self) -> int:
        """Fetch and validate a complete export; preserve cache on failure."""
        with self._lock:
            self._status["validation_refresh_status"] = "refreshing"
            self._status["validation_last_refresh_error"] = None

        try:
            response = requests.get(
                VRP_EXPORT_URL,
                timeout=REQUEST_TIMEOUT_SECONDS,
                headers={"Accept": "application/json"},
                stream=True,
            )
            response.raise_for_status()

            chunks: list[bytes] = []
            total = 0
            for chunk in response.iter_content(chunk_size=1024 * 1024):
                if not chunk:
                    continue
                total += len(chunk)
                if total > MAX_RESPONSE_BYTES:
                    raise ValueError("Routinator export exceeded the response size limit")
                chunks.append(chunk)

            payload = json.loads(b"".join(chunks))
            parsed, generated = self._parse_export(payload)
            retrieved = datetime.now(timezone.utc).isoformat()

            # Persist before publishing the new in-memory snapshot.
            self._persist(parsed, generated, retrieved)

            with self._lock:
                self._vrps = parsed
                self._status.update({
                    "validation_data_source": self._source_label(),
                    "validation_data_timestamp": generated,
                    "validation_retrieved_at_utc": retrieved,
                    "validation_vrp_count": len(parsed),
                    "validation_refresh_status": "success",
                    "validation_last_refresh_error": None,
                })

            return len(parsed)

        except Exception as exc:
            with self._lock:
                self._status["validation_refresh_status"] = "failed"
                self._status["validation_last_refresh_error"] = (
                    f"{type(exc).__name__}: {exc}"
                )
            raise

    def start(self, refresh_immediately: bool = True) -> None:
        """Start one background refresh worker; safe to call repeatedly."""
        with self._lock:
            if self._thread and self._thread.is_alive():
                return

            self._stop_event.clear()
            self._thread = threading.Thread(
                target=self._run,
                args=(refresh_immediately,),
                name="pathwatch-vrp-refresh",
                daemon=True,
            )
            self._thread.start()

    def stop(self) -> None:
        self._stop_event.set()

    def _run(self, refresh_immediately: bool) -> None:
        if not refresh_immediately:
            if self._stop_event.wait(self.refresh_interval):
                return

        while not self._stop_event.is_set():
            try:
                self.refresh_once()
            except Exception:
                pass

            if self._stop_event.wait(self.refresh_interval):
                break


vrp_cache = VRPCache()
