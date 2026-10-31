"""Timestamp association policy and sensitivity evaluation for BGP events and snapshots.

Policy specification:
- A daily snapshot (e.g., from roas_YYYY-MM-DD.csv.xz or periodic route dump) is treated
  as a discrete sample taken at an unknown time within its UTC date.
- Because the exact publication/processing timestamp within that day is generally
  undeterminable from the date label alone, an event occurring on the same UTC date
  as a snapshot has an *ambiguous* temporal relationship with that snapshot (the event
  could have preceded or followed the snapshot by up to 24 hours).
- An event is formally bracketed by:
  * S_before: the latest snapshot strictly dated before the event's UTC date.
  * S_after:  the earliest snapshot dated on or after the event's UTC date.
- When an event occurs on the same UTC date as a snapshot:
  * snapshot_used: the same-day snapshot is selected as the primary reference sample.
  * snapshot_gap: reported as a bounded range ("-24h to +24h (same-day ambiguous)").
  * flag_bracketing_disagreement: True if S_before and S_after yield differing
    validation states or route reachability for the target prefix.
"""

from __future__ import annotations

import datetime
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple


@dataclass(frozen=True)
class SnapshotMetadata:
    snapshot_id: str
    date: datetime.date
    timestamp_utc: datetime.datetime | None = None
    vrp_count: int = 0
    raw_filename: str = ""
    notes: str = ""


def parse_utc_timestamp(val: str | datetime.datetime) -> datetime.datetime:
    """Parse an ISO 8601 or common timestamp string to a UTC datetime."""
    if isinstance(val, datetime.datetime):
        if val.tzinfo is None:
            return val.replace(tzinfo=datetime.timezone.utc)
        return val.astimezone(datetime.timezone.utc)

    clean = val.replace("Z", "+00:00")
    dt = datetime.datetime.fromisoformat(clean)
    if dt.tzinfo is None:
        return dt.replace(tzinfo=datetime.timezone.utc)
    return dt.astimezone(datetime.timezone.utc)


def associate_event_snapshot(
    event_timestamp: str | datetime.datetime,
    snapshots: list[SnapshotMetadata],
    policy: str = "bracketing",
    validator_fn: Callable[[SnapshotMetadata], str] | None = None,
) -> dict[str, Any]:
    """Associate a BGP event with bracketing snapshots and evaluate temporal ambiguity.

    Parameters:
    - event_timestamp: ISO 8601 timestamp string or datetime
    - snapshots: list of SnapshotMetadata objects
    - policy: 'bracketing' (default), 'strict_before', 'strict_after', 'nearest'
    - validator_fn: optional callable taking a SnapshotMetadata and returning
      its validation state string (e.g. 'Valid') to check for bracketing disagreement.
    """
    event_dt = parse_utc_timestamp(event_timestamp)
    event_date = event_dt.date()

    if not snapshots:
        return {
            "snapshot_used": None,
            "before_snapshot": None,
            "after_snapshot": None,
            "snapshot_gap": None,
            "gap_hours_min": None,
            "gap_hours_max": None,
            "is_ambiguous": False,
            "flag_bracketing_disagreement": False,
            "policy": policy,
            "reason": "No snapshots available in dataset",
        }

    sorted_snaps = sorted(snapshots, key=lambda s: s.date)

    before_snaps = [s for s in sorted_snaps if s.date < event_date]
    after_snaps = [s for s in sorted_snaps if s.date >= event_date]

    s_before = before_snaps[-1] if before_snaps else None
    s_after = after_snaps[0] if after_snaps else None

    # Check for same-day snapshot
    same_day_snaps = [s for s in sorted_snaps if s.date == event_date]
    is_same_day = len(same_day_snaps) > 0

    # Compute bracketing disagreement if validator supplied
    disagreement = False
    if validator_fn and s_before and s_after:
        state_before = validator_fn(s_before)
        state_after = validator_fn(s_after)
        disagreement = (state_before != state_after)

    # Policy resolution
    if policy == "strict_before":
        chosen = s_before
        ambiguous = False
        if chosen:
            gap_days = (event_date - chosen.date).days
            gap_str = f"+{gap_days}d ({gap_days * 24}h after snapshot)"
            gap_min = float(gap_days * 24)
            gap_max = float((gap_days + 1) * 24)
        else:
            gap_str = "no prior snapshot"
            gap_min = None
            gap_max = None

    elif policy == "strict_after":
        chosen = s_after
        ambiguous = False
        if chosen:
            gap_days = (chosen.date - event_date).days
            gap_str = f"-{gap_days}d ({gap_days * 24}h before snapshot)"
            gap_min = float(-gap_days * 24)
            gap_max = float(-(gap_days - 1) * 24)
        else:
            gap_str = "no subsequent snapshot"
            gap_min = None
            gap_max = None

    elif policy == "nearest":
        # Nearest calendar date
        chosen = min(sorted_snaps, key=lambda s: abs((s.date - event_date).days))
        ambiguous = (chosen.date == event_date)
        gap_days = (event_date - chosen.date).days
        if gap_days == 0:
            gap_str = "same-day (0d, ambiguous within 24h)"
            gap_min = -24.0
            gap_max = 24.0
        else:
            gap_str = f"{gap_days:+d}d"
            gap_min = float(gap_days * 24 - 12)
            gap_max = float(gap_days * 24 + 12)

    else:  # 'bracketing' (primary policy)
        if is_same_day:
            chosen = same_day_snaps[0]
            ambiguous = True
            gap_str = "[-24h, +24h] same-day ambiguous"
            gap_min = -24.0
            gap_max = 24.0
        elif s_before:
            chosen = s_before
            ambiguous = False
            gap_days = (event_date - s_before.date).days
            gap_str = f"+{gap_days}d (+{gap_days * 24}h)"
            gap_min = float(gap_days * 24)
            gap_max = float((gap_days + 1) * 24)
        else:
            chosen = s_after
            ambiguous = False
            gap_days = (s_after.date - event_date).days if s_after else 0
            gap_str = f"-{gap_days}d (-{gap_days * 24}h)"
            gap_min = float(-gap_days * 24)
            gap_max = float(-(gap_days - 1) * 24)

    return {
        "snapshot_used": chosen.snapshot_id if chosen else None,
        "before_snapshot": s_before.snapshot_id if s_before else None,
        "after_snapshot": s_after.snapshot_id if s_after else None,
        "snapshot_gap": gap_str,
        "gap_hours_min": gap_min,
        "gap_hours_max": gap_max,
        "is_ambiguous": ambiguous,
        "flag_bracketing_disagreement": disagreement,
        "policy": policy,
        "event_date_utc": event_date.isoformat(),
    }


def run_policy_sensitivity_check(
    events: list[dict[str, Any]],
    snapshots: list[SnapshotMetadata],
    eval_state_fn: Callable[[dict[str, Any], str | None], str],
) -> dict[str, Any]:
    """Evaluate whether any event's RPKI state changes under alternative policies.

    Policies tested:
    - bracketing (same-day ambiguous)
    - strict_before (only prior snapshot)
    - strict_after (only next/same-day snapshot)
    - nearest (closest calendar day)

    eval_state_fn: takes (event_dict, snapshot_id) and returns state ('Valid', etc.)
    """
    policies = ["bracketing", "strict_before", "strict_after", "nearest"]
    results_by_policy: dict[str, dict[str, int]] = {p: {} for p in policies}
    discrepancy_count = 0
    discrepant_event_ids: list[str] = []

    for idx, event in enumerate(events):
        ts = event.get("timestamp", "")
        event_id = event.get("id", str(idx))
        states = {}

        for p in policies:
            assoc = associate_event_snapshot(ts, snapshots, policy=p)
            snap_id = assoc["snapshot_used"]
            state = eval_state_fn(event, snap_id)
            states[p] = state
            results_by_policy[p][state] = results_by_policy[p].get(state, 0) + 1

        # Check if state differed across any of the policies
        unique_states = set(states.values())
        if len(unique_states) > 1:
            discrepancy_count += 1
            discrepant_event_ids.append(event_id)

    return {
        "total_events_evaluated": len(events),
        "discrepancy_count": discrepancy_count,
        "sensitivity_percentage": round((discrepancy_count / len(events) * 100), 3) if events else 0.0,
        "policies_tested": policies,
        "state_distributions": results_by_policy,
        "is_sensitive": discrepancy_count > 0,
        "conclusion": (
            "No event RPKI validation states change across alternative timestamp policies."
            if discrepancy_count == 0
            else f"{discrepancy_count} events exhibit state changes depending on timestamp policy."
        ),
    }
