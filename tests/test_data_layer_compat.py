import json

from src import data_layer


def test_load_dataset_supports_daily_snapshot_correlation_schema(tmp_path, monkeypatch):
    monkeypatch.setattr(data_layer, "PROCESSED_DIR", tmp_path)
    (tmp_path / "rpki_bgp_correlation.json").write_text(json.dumps({
        "data_source": "RIPE Stat + RIPE NCC daily snapshots",
        "event_count": 2,
        "event_type_counts": {"A": 1, "W": 1},
        "rpki_state_counts": {"Valid": 1, "Unassigned": 1},
        "events": [
            {"timestamp": "2024-12-20T01:00:00", "event_type": "A", "prefix": "193.0.0.0/21", "origin_as": 3333, "rpki_state": "Valid", "rpki_snapshot": "roas_2024-12-20.csv.xz", "as_path": [64500, 3333]},
            {"timestamp": "2024-12-20T02:00:00", "event_type": "W", "prefix": "193.0.0.0/21", "origin_as": None, "rpki_state": None, "rpki_snapshot": None, "as_path": None},
        ],
        "limitations": ["Daily snapshots are not continuous observations."],
    }), encoding="utf-8")
    (tmp_path / "bgp_updates_summary.json").write_text(json.dumps({
        "unique_prefixes": ["193.0.0.0/21"], "events_parsed": 2,
        "event_type_counts": {"A": 1, "W": 1}, "events_with_path": 1,
        "unique_source_ids": 1,
    }), encoding="utf-8")
    (tmp_path / "route_event_analysis.json").write_text("{}", encoding="utf-8")
    (tmp_path / "rpki_history_summary.json").write_text(json.dumps({
        "snapshots": [{
            "snapshot_file": "roas_2024-12-20.csv.xz",
            "snapshot_time": "2024-12-20 00:00:00",
            "target_prefix": "193.0.0.0/21",
            "observed_origin_as": 3333,
            "validation_state": "Valid",
            "matching_exact_prefix_vrps": [{"prefix": "193.0.0.0/21", "asn": 3333, "max_length": 21}],
        }]
    }), encoding="utf-8")

    result = data_layer.load_dataset()
    assert result["summary"]["rpki_state_counts"] == {"Valid": 1, "Unassigned": 1}
    assert result["summary"]["events_parsed"] == 2
    assert result["events"][0]["snapshot_used"] == "roas_2024-12-20.csv.xz"
    assert result["vrp_summary"][0]["origin_asn"] == 3333
    assert result["rpki_history_summary"]["snapshots"][0]["validation_state"] == "Valid"
