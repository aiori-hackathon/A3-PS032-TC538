
import json
from datetime import datetime
from pathlib import Path

from src.rpki_history import (
    load_vrps,
    snapshot_time_from_filename,
    validate_origin,
)

ROOT = Path(__file__).resolve().parents[1]
SNAPSHOT_DIR = ROOT / "data" / "raw" / "rpki_history"
EVENTS_FILE = ROOT / "data" / "processed" / "bgp_updates_normalized.json"
OUTPUT_FILE = ROOT / "data" / "processed" / "rpki_bgp_correlation.json"


def parse_timestamp(value):
    return datetime.fromisoformat(value)


def select_snapshot(event_time, snapshots):
    """Return the latest snapshot dated at or before event_time."""
    eligible = [
        snapshot
        for snapshot in snapshots
        if snapshot["timestamp"] <= event_time
    ]
    return eligible[-1] if eligible else None


def correlate_event(event, snapshots):
    """Correlate one BGP event with the latest eligible RPKI snapshot."""
    event_time = parse_timestamp(event["timestamp"])
    prefix = event.get("prefix")
    event_type = event.get("event_type")
    path = event.get("as_path")

    result = {
        "timestamp": event["timestamp"],
        "event_type": event_type,
        "prefix": prefix,
        "source_id": event.get("source_id"),
        "as_path": path,
        "data_source": event.get("data_source"),
        "synthetic": event.get("synthetic", False),
        "origin_as": None,
        "rpki_state": None,
        "rpki_snapshot": None,
        "rpki_snapshot_time": None,
        "rpki_state_basis": "daily_snapshot",
        "rpki_time_gap_seconds": None,
        "status_note": None,
    }

    if event_type == "W":
        result["status_note"] = (
            "Withdrawal has no origin AS in this event; "
            "validation state is not assigned."
        )
        return result

    if not isinstance(path, list) or not path:
        result["status_note"] = "Announcement has no usable AS path."
        return result

    if not prefix:
        result["status_note"] = "Announcement has no usable prefix."
        return result

    snapshot = select_snapshot(event_time, snapshots)
    if snapshot is None:
        result["status_note"] = (
            "No snapshot exists at or before this event timestamp."
        )
        return result

    origin_as = path[-1]
    result["origin_as"] = origin_as
    result["rpki_state"] = validate_origin(
        prefix, origin_as, snapshot["vrps"]
    )
    result["rpki_snapshot"] = snapshot["file"]
    result["rpki_snapshot_time"] = snapshot["timestamp"].isoformat()
    result["rpki_time_gap_seconds"] = int(
        (event_time - snapshot["timestamp"]).total_seconds()
    )
    result["status_note"] = (
        "State inferred from the latest available daily snapshot; "
        "not a continuous historical observation."
    )
    return result


def main():
    snapshots = []

    for path in sorted(SNAPSHOT_DIR.glob("roas_2024-12-*.csv.xz")):
        snapshot_time = snapshot_time_from_filename(path)
        snapshots.append({
            "timestamp": snapshot_time,
            "file": path.name,
            "vrps": load_vrps(path, at_time=snapshot_time),
        })

    if not snapshots:
        raise RuntimeError(f"No RPKI snapshots found in {SNAPSHOT_DIR}")

    events = json.loads(EVENTS_FILE.read_text(encoding="utf-8"))
    results = [
        correlate_event(event, snapshots)
        for event in events
    ]

    state_counts = {}
    event_counts = {}

    for result in results:
        state = result["rpki_state"] or "Unassigned"
        state_counts[state] = state_counts.get(state, 0) + 1

        kind = result["event_type"] or "Unknown"
        event_counts[kind] = event_counts.get(kind, 0) + 1

    output = {
        "data_source": (
            "RIPE Stat BGP updates + RIPE NCC RPKI archive snapshots"
        ),
        "prefix_scope": sorted({
            result["prefix"]
            for result in results
            if result["prefix"]
        }),
        "event_count": len(results),
        "event_type_counts": event_counts,
        "rpki_state_counts": state_counts,
        "correlation_method": (
            "For announcements, use the latest daily RPKI snapshot at or "
            "before the BGP event timestamp and validate the last AS in its path."
        ),
        "limitations": [
            "Daily snapshots do not establish the exact RPKI state at every event time.",
            "Snapshot filename dates are used as timestamps; their precise temporal semantics must be verified.",
            "Withdrawals are not assigned an origin AS or validation state.",
            "BGP events are observations from the queried data source, not a complete global view.",
            "Temporal correlation does not establish RPKI causation.",
        ],
        "events": results,
    }

    OUTPUT_FILE.write_text(
        json.dumps(output, indent=2) + "\n",
        encoding="utf-8",
    )

    print(f"Saved: {OUTPUT_FILE.relative_to(ROOT)}")
    print(f"Events correlated: {len(results)}")
    print(f"Event types: {event_counts}")
    print(f"RPKI state counts: {state_counts}")


if __name__ == "__main__":
    main()
