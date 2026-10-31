"""Data layer for PathWatch backend: dataset loading, dynamic snapshot discovery,
and shared event filtering and CSV serialization.
"""

from __future__ import annotations

import csv
import datetime
import io
import json
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

ROOT = Path(__file__).resolve().parents[1]
PROCESSED_DIR = ROOT / "data" / "processed"
RAW_DIR = ROOT / "data" / "raw"


def safe_load_json(path: Path) -> Any:
    """Safely load JSON without leaking internal paths or throwing raw errors."""
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def discover_snapshot_comparisons() -> list[dict[str, Any]]:
    """Dynamically discover comparison JSON files without hardcoded filenames."""
    if not PROCESSED_DIR.exists():
        return []
    comparison_files = sorted(PROCESSED_DIR.glob("comparison_*.json"))
    snapshots = []
    for f in comparison_files:
        data = safe_load_json(f)
        if isinstance(data, dict):
            snapshots.append(data)
    return snapshots


def load_dataset() -> dict[str, Any]:
    """Load existing processed study outputs without modifying historical data."""
    corr_path = PROCESSED_DIR / "rpki_bgp_correlation.json"
    corr_data = safe_load_json(corr_path) or {}
    summary_data = safe_load_json(PROCESSED_DIR / "bgp_updates_summary.json") or {}
    analysis_data = safe_load_json(PROCESSED_DIR / "route_event_analysis.json") or {}
    rpki_history = safe_load_json(PROCESSED_DIR / "rpki_history_summary.json") or {}

    snapshots = discover_snapshot_comparisons()
    raw_events = corr_data.get("events") or []
    # Accept both the frontend bundle's unified correlation schema and the
    # standalone historical-correlator schema (rpki_state_counts, rpki_snapshot).
    events = []
    for index, raw_event in enumerate(raw_events, start=1):
        if not isinstance(raw_event, dict):
            continue

        event = dict(raw_event)

        # Stable identifier for API pagination and frontend rendering.
        event.setdefault("id", f"event-{index:04d}")

        # Withdrawals have no origin AS and therefore no assigned
        # RPKI validation state. Normalize this in memory only.
        if (
            str(event.get("event_type") or "").upper() == "W"
            and event.get("rpki_state") is None
        ):
            event["rpki_state"] = "Unassigned"

        # Preserve compatibility with the historical snapshot schema.
        if not event.get("snapshot_used"):
            event["snapshot_used"] = (
                event.get("rpki_snapshot")
                or event.get("rpki_snapshot_time")
            )

        events.append(event)

    summary = corr_data.get("summary")
    if not isinstance(summary, dict):
        summary = dict(summary_data)
    else:
        summary = dict(summary)
    state_counts = corr_data.get("rpki_state_counts") or corr_data.get("state_counts")
    if isinstance(state_counts, dict):
        summary["rpki_state_counts"] = state_counts
    if corr_data.get("event_count") is not None:
        summary["events_parsed"] = corr_data.get("event_count")
    if isinstance(corr_data.get("event_type_counts"), dict):
        summary["event_type_counts"] = corr_data["event_type_counts"]

    vrp_summary = corr_data.get("vrp_summary")
    if not isinstance(vrp_summary, list):
        vrp_summary = []
    if not vrp_summary:
        history_snapshots = rpki_history.get("snapshots", [])
        if history_snapshots:
            latest = history_snapshots[-1]
            for row in latest.get("matching_exact_prefix_vrps", []) or []:
                if isinstance(row, dict):
                    vrp_summary.append({
                        "origin_asn": row.get("asn"),
                        "prefix": row.get("prefix"),
                        "max_length": row.get("max_length"),
                        "snapshot": latest.get("snapshot_file"),
                    })

    # AS path length distribution from summary or computed from events
    dist = summary_data.get("path_length_distribution")
    if not dist:
        dist = {}
        for e in events:
            p = e.get("as_path")
            if isinstance(p, list) and len(p) > 0:
                l_str = str(len(p))
                dist[l_str] = dist.get(l_str, 0) + 1

    dist_int = {str(k): int(v) for k, v in sorted(dist.items(), key=lambda x: int(x[0]))}
    npath = sum(dist_int.values())
    weighted = sum(int(k) * v for k, v in dist_int.items())

    return {
        "metadata": corr_data.get("metadata", {}),
        "summary": summary,
        "events": events,
        "snapshots": snapshots,
        "sequences": analysis_data.get("sequences", []),
        "observed_path_change_count": analysis_data.get("observed_path_change_count", 0),
        "announcement_after_withdrawal_count": analysis_data.get("announcement_after_withdrawal_count", 0),
        "path_length_distribution": dist_int,
        "path_stats": {
            "min": min(map(int, dist_int.keys())) if dist_int else None,
            "max": max(map(int, dist_int.keys())) if dist_int else None,
            "average": round(weighted / npath, 2) if npath else None,
            "count": npath,
        },
        "study_window": {
            "start": summary_data.get("query_starttime"),
            "end_exclusive": summary_data.get("query_endtime"),
            "first_event": summary_data.get("first_event_timestamp"),
            "last_event": summary_data.get("last_event_timestamp"),
        },
        "vrp_summary": vrp_summary,
        "rpki_history_summary": rpki_history,
        "sensitivity_analysis": corr_data.get("sensitivity_analysis", {}),
        "limitations": corr_data.get("limitations", analysis_data.get("limitations", [])),
    }


def parse_timestamp_filter(val: str | None) -> datetime.datetime | None:
    if not val:
        return None
    try:
        clean = val.replace("Z", "+00:00")
        dt = datetime.datetime.fromisoformat(clean)
        return dt if dt.tzinfo else dt.replace(tzinfo=datetime.timezone.utc)
    except ValueError:
        raise ValueError(f"Invalid timestamp format: '{val}'. Expected ISO 8601 (e.g., 2024-12-21T12:00:00Z).")


def parse_event_filter_args(args_mapping: Any) -> dict[str, Any]:
    """Parse and convert query parameters for event filtering from request.args.

    Raises ValueError if page or page_size are invalid integers.
    """
    page_raw = args_mapping.get("page", 1)
    page_size_raw = args_mapping.get("page_size", 50)
    try:
        page = int(page_raw)
        page_size = int(page_size_raw)
    except (ValueError, TypeError):
        raise ValueError("page and page_size must be integers")

    return {
        "q": args_mapping.get("q"),
        "event_type": args_mapping.get("event_type"),
        "rpki_state": args_mapping.get("rpki_state"),
        "start": args_mapping.get("start"),
        "end": args_mapping.get("end"),
        "sort": args_mapping.get("sort", "timestamp_desc"),
        "page": page,
        "page_size": page_size,
    }


def filter_events(
    events: list[dict[str, Any]],
    q: str | None = None,
    event_type: str | None = None,
    rpki_state: str | None = None,
    start: str | None = None,
    end: str | None = None,
    sort: str = "timestamp_desc",
    page: int = 1,
    page_size: int = 50,
) -> dict[str, Any]:
    """Shared pure filtering, sorting, and pagination function for table API and CSV export.

    Validates all parameters strictly and raises ValueError on bad inputs.
    """
    # 1. Parameter Validation
    if page < 1:
        raise ValueError("page must be an integer >= 1")
    if page_size < 1 or page_size > 1000:
        raise ValueError("page_size must be between 1 and 1000")

    allowed_sorts = {
        "timestamp_desc", "timestamp_asc",
        "path_length_desc", "path_length_asc",
        "source_asc", "source_desc",
        "origin_asc", "origin_desc",
    }
    if sort not in allowed_sorts:
        raise ValueError(f"Invalid sort parameter '{sort}'. Allowed: {sorted(allowed_sorts)}")

    start_dt = parse_timestamp_filter(start)
    end_dt = parse_timestamp_filter(end)
    if start_dt and end_dt and start_dt > end_dt:
        raise ValueError(f"start timestamp ({start}) cannot be later than end timestamp ({end})")

    # Normalize filters
    q_clean = q.strip().lower() if q else None
    type_filter = event_type.strip().upper() if event_type and event_type.strip().lower() != "all" else None
    state_filter = rpki_state.strip().lower() if rpki_state and rpki_state.strip().lower() != "all" else None

    allowed_types = {"A", "W", "P"}
    if type_filter and type_filter not in allowed_types:
        raise ValueError(f"Invalid event_type '{event_type}'. Allowed: A, W, P, all")

    allowed_states = {"valid", "invalid", "notfound", "unassigned"}
    if state_filter and state_filter not in allowed_states:
        raise ValueError(f"Invalid rpki_state '{rpki_state}'. Allowed: Valid, Invalid, NotFound, Unassigned, all")

    filtered: list[dict[str, Any]] = []

    for e in events:
        # Event type filter
        e_type = str(e.get("event_type") or "").upper()
        if type_filter and e_type != type_filter:
            continue

        # RPKI state filter
        e_state = str(e.get("rpki_state") or "").lower()
        if state_filter and e_state != state_filter:
            continue

        # Time range filter
        ts_str = e.get("timestamp") or e.get("timestamp_utc")
        if (start_dt or end_dt) and ts_str:
            try:
                e_dt = datetime.datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
                if not e_dt.tzinfo:
                    e_dt = e_dt.replace(tzinfo=datetime.timezone.utc)
                if start_dt and e_dt < start_dt:
                    continue
                if end_dt and e_dt > end_dt:
                    continue
            except ValueError:
                pass

        # Text search q
        if q_clean:
            match_parts = [
                str(e.get("prefix") or ""),
                str(e.get("source_id") or ""),
                str(e.get("origin_as") or ""),
                str(e.get("timestamp") or ""),
                str(e.get("rpki_state") or ""),
                str(e.get("snapshot_used") or ""),
            ]
            path = e.get("as_path")
            if isinstance(path, list):
                match_parts.extend(map(str, path))

            combined_search_text = " ".join(match_parts).lower()
            if q_clean not in combined_search_text:
                continue

        filtered.append(e)

    # 2. Sorting
    def sort_key(row: dict[str, Any]):
        if sort in ("timestamp_desc", "timestamp_asc"):
            return row.get("timestamp") or ""
        elif sort in ("path_length_desc", "path_length_asc"):
            p = row.get("as_path")
            return len(p) if isinstance(p, list) else -1
        elif sort in ("source_asc", "source_desc"):
            return str(row.get("source_id") or "")
        elif sort in ("origin_asc", "origin_desc"):
            orig = row.get("origin_as")
            return orig if isinstance(orig, int) else -1
        return ""

    reverse_sort = sort.endswith("_desc")
    filtered.sort(key=sort_key, reverse=reverse_sort)

    total_filtered = len(filtered)
    total_pages = max(1, (total_filtered + page_size - 1) // page_size)

    # 3. Pagination
    start_idx = (page - 1) * page_size
    end_idx = start_idx + page_size
    page_items = filtered[start_idx:end_idx]

    return {
        "items": page_items,
        "all_filtered": filtered,
        "total_filtered": total_filtered,
        "total_unfiltered": len(events),
        "page": page,
        "page_size": page_size,
        "total_pages": total_pages,
        "has_next": page < total_pages,
        "has_prev": page > 1,
    }


def sanitize_csv_cell(val: Any) -> str:
    """Neutralize formula injection by quoting values starting with =, +, -, @."""
    if val is None:
        return ""
    s = str(val).strip()
    if s and s[0] in ("=", "+", "-", "@"):
        return f"'{s}"
    return s


def format_as_path_str(path: Any) -> str:
    if isinstance(path, list) and path:
        return " → ".join(map(str, path))
    return "—"


def export_events_csv(filtered_events: list[dict[str, Any]]) -> str:
    """Export filtered events as CSV string adhering to required schema and formula escaping.

    Columns:
    timestamp_utc, event_type, prefix, source_id, as_path, origin_as,
    rpki_state, snapshot_used, snapshot_gap, data_quality_note
    """
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        "timestamp_utc",
        "event_type",
        "prefix",
        "source_id",
        "as_path",
        "origin_as",
        "rpki_state",
        "snapshot_used",
        "snapshot_gap",
        "data_quality_note",
    ])

    for e in filtered_events:
        path_str = format_as_path_str(e.get("as_path"))
        origin_str = str(e.get("origin_as")) if e.get("origin_as") is not None else "—"
        writer.writerow([
            sanitize_csv_cell(e.get("timestamp_utc") or e.get("timestamp")),
            sanitize_csv_cell(e.get("event_type")),
            sanitize_csv_cell(e.get("prefix")),
            sanitize_csv_cell(e.get("source_id")),
            sanitize_csv_cell(path_str),
            sanitize_csv_cell(origin_str),
            sanitize_csv_cell(e.get("rpki_state")),
            sanitize_csv_cell(e.get("snapshot_used")),
            sanitize_csv_cell(e.get("snapshot_gap")),
            sanitize_csv_cell(e.get("data_quality_note")),
        ])

    return output.getvalue()
