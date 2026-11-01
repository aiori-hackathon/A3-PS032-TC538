"""Unit tests for timestamp association policy, bracketing, and sensitivity evaluation."""

import datetime
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import pytest
from src.timestamp_policy import (
    SnapshotMetadata,
    associate_event_snapshot,
    parse_utc_timestamp,
    run_policy_sensitivity_check,
)


@pytest.fixture
def sample_snapshots():
    return [
        SnapshotMetadata(
            snapshot_id="snap_20241220",
            date=datetime.date(2024, 12, 20),
            timestamp_utc=datetime.datetime(2024, 12, 20, 12, 0, tzinfo=datetime.timezone.utc),
            vrp_count=1,
        ),
        SnapshotMetadata(
            snapshot_id="snap_20241221",
            date=datetime.date(2024, 12, 21),
            timestamp_utc=datetime.datetime(2024, 12, 21, 12, 0, tzinfo=datetime.timezone.utc),
            vrp_count=1,
        ),
        SnapshotMetadata(
            snapshot_id="snap_20241222",
            date=datetime.date(2024, 12, 22),
            timestamp_utc=datetime.datetime(2024, 12, 22, 12, 0, tzinfo=datetime.timezone.utc),
            vrp_count=1,
        ),
    ]


def test_same_day_snapshot_is_ambiguous(sample_snapshots):
    # Event on 2024-12-21 at 03:00 UTC, snapshot on 2024-12-21
    res = associate_event_snapshot("2024-12-21T03:00:00Z", sample_snapshots, policy="bracketing")
    assert res["is_ambiguous"] is True
    assert res["snapshot_used"] == "snap_20241221"
    assert "same-day ambiguous" in res["snapshot_gap"]
    assert res["before_snapshot"] == "snap_20241220"
    assert res["after_snapshot"] == "snap_20241221"


def test_event_between_dates_without_same_day():
    snaps = [
        SnapshotMetadata(snapshot_id="s1", date=datetime.date(2024, 12, 18)),
        SnapshotMetadata(snapshot_id="s2", date=datetime.date(2024, 12, 24)),
    ]
    res = associate_event_snapshot("2024-12-20T10:00:00Z", snaps, policy="bracketing")
    assert res["is_ambiguous"] is False
    assert res["before_snapshot"] == "s1"
    assert res["after_snapshot"] == "s2"
    assert res["snapshot_used"] == "s1"


def test_event_before_all_snapshots(sample_snapshots):
    res = associate_event_snapshot("2024-12-15T12:00:00Z", sample_snapshots, policy="bracketing")
    assert res["before_snapshot"] is None
    assert res["after_snapshot"] == "snap_20241220"
    assert res["snapshot_used"] == "snap_20241220"


def test_event_after_all_snapshots(sample_snapshots):
    res = associate_event_snapshot("2024-12-25T12:00:00Z", sample_snapshots, policy="bracketing")
    assert res["before_snapshot"] == "snap_20241222"
    assert res["after_snapshot"] is None
    assert res["snapshot_used"] == "snap_20241222"


def test_flag_bracketing_disagreement():
    snaps = [
        SnapshotMetadata(snapshot_id="s_valid", date=datetime.date(2024, 12, 20)),
        SnapshotMetadata(snapshot_id="s_invalid", date=datetime.date(2024, 12, 22)),
    ]
    # Validator returns 'Valid' for s_valid and 'Invalid' for s_invalid
    def validator(s: SnapshotMetadata) -> str:
        return "Valid" if s.snapshot_id == "s_valid" else "Invalid"

    res = associate_event_snapshot(
        "2024-12-21T00:00:00Z",
        snaps,
        policy="bracketing",
        validator_fn=validator,
    )
    assert res["flag_bracketing_disagreement"] is True


def test_sensitivity_analysis_consistency():
    events = [
        {"timestamp": "2024-12-20T05:00:00Z", "id": "1"},
        {"timestamp": "2024-12-21T08:00:00Z", "id": "2"},
        {"timestamp": "2024-12-22T20:00:00Z", "id": "3"},
    ]
    snaps = [
        SnapshotMetadata(snapshot_id="s1", date=datetime.date(2024, 12, 20)),
        SnapshotMetadata(snapshot_id="s2", date=datetime.date(2024, 12, 21)),
        SnapshotMetadata(snapshot_id="s3", date=datetime.date(2024, 12, 22)),
    ]

    # Constant state across all snapshots (like our 193.0.0.0/21 dataset)
    def constant_eval(ev, snap_id):
        return "Valid"

    res = run_policy_sensitivity_check(events, snaps, constant_eval)
    assert res["discrepancy_count"] == 0
    assert res["is_sensitive"] is False
    assert res["sensitivity_percentage"] == 0.0
