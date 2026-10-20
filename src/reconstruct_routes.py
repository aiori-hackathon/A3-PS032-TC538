"""Reconstruct observed route-event sequences from real BGP updates."""

import json
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
INPUT = ROOT / "data" / "processed" / "bgp_updates_normalized.json"
OUT = ROOT / "data" / "processed" / "route_event_analysis.json"


def parse_time(value):
    if not value:
        return None
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def main():
    if not INPUT.exists():
        raise SystemExit(
            "Normalized events not found. Run src/analyze_updates.py first."
        )

    rows = json.loads(INPUT.read_text(encoding="utf-8"))
    rows.sort(key=lambda row: row.get("timestamp") or "")

    counts = Counter()
    events_by_source = defaultdict(list)
    sequences = []
    current_path = {}
    previous_event = {}

    for row in rows:
        event_type = row.get("event_type", "UNKNOWN")
        source = row.get("source_id")
        prefix = row.get("prefix")
        timestamp = row.get("timestamp")
        path = row.get("as_path")

        counts[event_type] += 1

        if not source or not prefix:
            continue

        key = (prefix, source)
        event = {
            "timestamp": timestamp,
            "event_type": event_type,
            "prefix": prefix,
            "source_id": source,
            "as_path": path,
        }
        events_by_source[f"{prefix}|{source}"].append(event)


        if event_type == "A":
            valid_path = (
                isinstance(path, list)
                and all(
                    isinstance(asn, int)
                    and not isinstance(asn, bool)
                    and asn > 0
                    for asn in path
                )
            )

            if valid_path:
                old_path = current_path.get(key)

                if old_path is not None and old_path != path:
                    sequences.append({
                        "sequence_type": "announced_path_changed",
                        "timestamp": timestamp,
                        "prefix": prefix,
                        "source_id": source,
                        "previous_path": old_path,
                        "new_path": path,
                    })

                current_path[key] = path
            else:
                # Do not retain stale route state after an announcement
                # whose AS path is missing or malformed.
                current_path.pop(key, None)

                sequences.append({
                    "sequence_type": "announcement_invalid_path",
                    "timestamp": timestamp,
                    "prefix": prefix,
                    "source_id": source,
                    "as_path": path,
                    "reason": (
                        "missing_or_non_list_path"
                        if not isinstance(path, list)
                        else "invalid_asn_entries"
                    ),
                })

            previous_event[key] = event

        elif event_type == "W":
            had_tracked_route = key in current_path
            last_path = current_path.pop(key, None)
            prior = previous_event.get(key)

            sequences.append({
                "sequence_type": "withdrawal_observed",
                "withdrawal_classification": (
                    "withdrawal_with_tracked_route"
                    if had_tracked_route
                    else "withdrawal_without_tracked_route"
                ),
                "timestamp": timestamp,
                "prefix": prefix,
                "source_id": source,
                "last_known_path": last_path,
                "previous_event_timestamp": (
                    prior.get("timestamp") if prior else None
                ),
                "previous_event_type": (
                    prior.get("event_type") if prior else None
                ),
            })

            previous_event[key] = event

        else:
            sequences.append({
                "sequence_type": "unclassified_event",
                "timestamp": timestamp,
                "prefix": prefix,
                "source_id": source,
                "event_type": event_type,
            })
            previous_event[key] = event

    # Identify announcements following a withdrawal for the same
    # prefix/source. This is a sequence, not proof of causal relation.
    reannouncements = []
    last_withdrawal = {}

    for row in rows:
        key = (row.get("prefix"), row.get("source_id"))
        event_type = row.get("event_type")

        if event_type == "W":
            last_withdrawal[key] = row.get("timestamp")
        elif event_type == "A" and key in last_withdrawal:
            reannouncements.append({
                "sequence_type": "announcement_after_withdrawal",
                "prefix": row.get("prefix"),
                "source_id": row.get("source_id"),
                "withdrawal_timestamp": last_withdrawal[key],
                "announcement_timestamp": row.get("timestamp"),
                "announced_path": row.get("as_path"),
            })
            del last_withdrawal[key]

    summary = {
        "data_source": "ripe_stat_bgp_updates",
        "input_event_count": len(rows),
        "event_type_counts": dict(counts),
        "source_prefix_pairs": len(events_by_source),
        "observed_withdrawal_count": counts.get("W", 0),
        "observed_path_change_count": sum(
            item["sequence_type"] == "announced_path_changed"
            for item in sequences
        ),
        "announcement_after_withdrawal_count": len(reannouncements),
        "announcement_after_withdrawal": reannouncements,
        "sequences": sequences,
        "synthetic_data_used": False,
        "limitations": [
            "Only events returned by the queried API are represented.",
            "A withdrawal has no path in the observed sample; last-known paths "
            "are reconstructed from earlier announcements in this dataset.",
            "A later announcement does not prove the withdrawal was caused "
            "by an RPKI state change.",
            "The analysis does not infer historical RPKI validation status."
        ]
    }

    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(
        json.dumps(summary, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )

    print("Route-event reconstruction complete")
    print("-" * 45)
    print(f"Input events:                     {len(rows)}")
    print(f"Event counts:                     {dict(counts)}")
    print(f"Prefix/source pairs:              {len(events_by_source)}")
    print(f"Observed path changes:            "
          f"{summary['observed_path_change_count']}")
    print(f"Announcements after withdrawals:  {len(reannouncements)}")
    print(f"Output:                           {OUT}")

    if reannouncements:
        print("\nFirst announcement-after-withdrawal sequence:")
        print(json.dumps(reannouncements[0], indent=2))


if __name__ == "__main__":
    main()
