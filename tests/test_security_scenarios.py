"""Unit tests for the 10 cybersecurity research scenarios.

All scenarios use synthetic test fixtures and run through the SAME
validate_prefix_origin() function in src.rpki_validator.
"""

import datetime
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import pytest
from src.rpki_validator import VRP, validate_prefix_origin
from src.timestamp_policy import parse_utc_timestamp

FIXTURE_PATH = ROOT / "tests" / "fixtures" / "scenarios" / "synthetic_test_scenarios.json"


@pytest.fixture
def scenarios_data():
    raw = json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))
    assert raw["synthetic"] is True
    return raw["scenarios"]


def _make_vrps(raw_vrps, snapshot_id="test"):
    return [VRP.from_dict(v, snapshot_id=snapshot_id) for v in raw_vrps]


def test_scenario_01_legitimate_valid(scenarios_data):
    s = scenarios_data[0]
    vrps = _make_vrps(s["vrps"])
    res = validate_prefix_origin(s["prefix"], s["as_path"], s["event_type"], vrps)
    assert res["rpki_state"] == s["expected_state"]
    assert res["origin_as"] == s["expected_origin_as"]


def test_scenario_02_wrong_origin_hijack(scenarios_data):
    s = scenarios_data[1]
    vrps = _make_vrps(s["vrps"])
    res = validate_prefix_origin(s["prefix"], s["as_path"], s["event_type"], vrps)
    assert res["rpki_state"] == s["expected_state"]
    assert res["invalid_subreason"] == s["expected_subreason"]
    assert res["origin_as"] == s["expected_origin_as"]


def test_scenario_03_more_specific_exceeding_max_length(scenarios_data):
    s = scenarios_data[2]
    vrps = _make_vrps(s["vrps"])
    res = validate_prefix_origin(s["prefix"], s["as_path"], s["event_type"], vrps)
    assert res["rpki_state"] == s["expected_state"]
    assert res["invalid_subreason"] == s["expected_subreason"]
    assert res["origin_as"] == s["expected_origin_as"]


def test_scenario_04_no_covering_roa(scenarios_data):
    s = scenarios_data[3]
    vrps = _make_vrps(s["vrps"])
    res = validate_prefix_origin(s["prefix"], s["as_path"], s["event_type"], vrps)
    assert res["rpki_state"] == s["expected_state"]
    assert res["origin_as"] == s["expected_origin_as"]


def test_scenario_05_roa_expired(scenarios_data):
    s = scenarios_data[4]
    vrps = _make_vrps(s["vrps"])
    ref_time = parse_utc_timestamp(s["reference_time"])
    res = validate_prefix_origin(s["prefix"], s["as_path"], s["event_type"], vrps, reference_time=ref_time)
    assert res["rpki_state"] == s["expected_state"]
    assert res["origin_as"] == s["expected_origin_as"]
    assert res["inactive_vrps_count"] == 1


def test_scenario_06_roa_removed_across_snapshots(scenarios_data):
    s = scenarios_data[5]
    vrps_snap1 = _make_vrps(s["snapshot_1_vrps"], "snap1")
    vrps_snap2 = _make_vrps(s["snapshot_2_vrps"], "snap2")

    res1 = validate_prefix_origin(s["prefix"], s["as_path"], s["event_type"], vrps_snap1)
    res2 = validate_prefix_origin(s["prefix"], s["as_path"], s["event_type"], vrps_snap2)

    assert res1["rpki_state"] == s["expected_state_snap1"]
    assert res2["rpki_state"] == s["expected_state_snap2"]


def test_scenario_07_roa_tightened_across_snapshots(scenarios_data):
    s = scenarios_data[6]
    vrps_snap1 = _make_vrps(s["snapshot_1_vrps"], "snap1")
    vrps_snap2 = _make_vrps(s["snapshot_2_vrps"], "snap2")

    res1 = validate_prefix_origin(s["prefix"], s["as_path"], s["event_type"], vrps_snap1)
    res2 = validate_prefix_origin(s["prefix"], s["as_path"], s["event_type"], vrps_snap2)

    assert res1["rpki_state"] == s["expected_state_snap1"]
    assert res2["rpki_state"] == s["expected_state_snap2"]
    assert res2["invalid_subreason"] == "MaxLengthExceeded"


def test_scenario_08_forged_origin_path_manipulation(scenarios_data):
    s = scenarios_data[7]
    vrps = _make_vrps(s["vrps"])
    res = validate_prefix_origin(s["prefix"], s["as_path"], s["event_type"], vrps)
    # ROV blind spot: still Valid because terminal hop matches AS3333
    assert res["rpki_state"] == s["expected_state"]
    assert res["origin_as"] == s["expected_origin_as"]


def test_scenario_09_withdrawal_event(scenarios_data):
    s = scenarios_data[8]
    vrps = _make_vrps(s["vrps"])
    res = validate_prefix_origin(s["prefix"], s["as_path"], s["event_type"], vrps)
    assert res["rpki_state"] == s["expected_state"]
    assert res["origin_as"] is None


def test_scenario_10_malformed_as_path(scenarios_data):
    s = scenarios_data[9]
    vrps = _make_vrps(s["vrps"])
    res = validate_prefix_origin(s["prefix"], s["as_path"], s["event_type"], vrps)
    assert res["rpki_state"] == s["expected_state"]
    assert res["origin_as"] is None
