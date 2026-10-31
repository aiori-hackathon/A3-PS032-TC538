"""Unit and integration tests for PathWatch Flask backend API endpoints."""

import csv
import io
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import pytest
from app import app
from src.data_layer import filter_events, sanitize_csv_cell


@pytest.fixture
def client():
    app.config["TESTING"] = True
    with app.test_client() as client:
        yield client


def test_index_serves_html(client):
    res = client.get("/")
    assert res.status_code == 200
    assert "PathWatch" in res.get_data(as_text=True)
    assert "text/html" in res.headers["Content-Type"]


def test_health_endpoint(client):
    res = client.get("/api/health")
    assert res.status_code == 200
    data = res.get_json()
    assert data["status"] == "ok"
    assert data["data_directory_exists"] is True
    assert data["processed_files"] > 0
    assert data.get("events_count") == 266


def test_dashboard_endpoint_default(client):
    res = client.get("/api/dashboard")
    assert res.status_code == 200
    data = res.get_json()

    assert "summary" in data
    assert "events" in data
    assert "timeline_events" in data
    assert "path_length_distribution" in data
    assert "snapshots" in data
    assert "rpki_status" in data
    assert "pagination" in data
    assert data["synthetic_data_used"] is False

    summary = data["summary"]
    assert summary["events"] == 266
    assert summary["announcements"] == 262
    assert summary["withdrawals"] == 4
    assert summary["missing_evidence_count"] == 4
    assert summary["prefix"] == "193.0.0.0/21"
    assert summary["rpki_state_counts"]["Valid"] == 262
    assert summary["rpki_state_counts"]["Unassigned"] == 4

    rpki = data["rpki_status"]
    assert rpki["exact_prefix_authorized"] is True
    assert rpki["origin_asn"] == 3333
    assert rpki["max_length"] == 21


def test_dashboard_filtering_by_event_type(client):
    # Withdrawals only
    res_w = client.get("/api/dashboard?event_type=W")
    assert res_w.status_code == 200
    data_w = res_w.get_json()
    assert data_w["pagination"]["total_filtered"] == 4
    for e in data_w["events"]:
        assert e["event_type"] == "W"
        assert e["rpki_state"] == "Unassigned"
        assert e["origin_as"] is None

    # Announcements only
    res_a = client.get("/api/dashboard?event_type=A")
    assert res_a.status_code == 200
    data_a = res_a.get_json()
    assert data_a["pagination"]["total_filtered"] == 262
    for e in data_a["events"]:
        assert e["event_type"] == "A"


def test_dashboard_filtering_by_rpki_state(client):
    res = client.get("/api/dashboard?rpki_state=Unassigned")
    assert res.status_code == 200
    data = res.get_json()
    assert data["pagination"]["total_filtered"] == 4

    res_valid = client.get("/api/dashboard?rpki_state=Valid")
    assert res_valid.status_code == 200
    assert res_valid.get_json()["pagination"]["total_filtered"] == 262


def test_dashboard_search_filter(client):
    res = client.get("/api/dashboard?q=3333")
    assert res.status_code == 200
    data = res.get_json()
    assert data["pagination"]["total_filtered"] > 0


def test_dashboard_pagination(client):
    res_p1 = client.get("/api/dashboard?page=1&page_size=10")
    assert res_p1.status_code == 200
    d1 = res_p1.get_json()
    assert len(d1["events"]) == 10
    assert d1["pagination"]["page"] == 1
    assert d1["pagination"]["has_next"] is True
    assert d1["pagination"]["has_prev"] is False

    res_p2 = client.get("/api/dashboard?page=2&page_size=10")
    assert res_p2.status_code == 200
    d2 = res_p2.get_json()
    assert len(d2["events"]) == 10
    assert d2["pagination"]["page"] == 2
    assert d2["pagination"]["has_prev"] is True

    # Ensure pages contain distinct items
    assert d1["events"][0]["id"] != d2["events"][0]["id"]


def test_dashboard_bad_parameters_return_400(client):
    # Invalid page
    res = client.get("/api/dashboard?page=-1")
    assert res.status_code == 400
    assert "error" in res.get_json()

    # Invalid page_size
    res2 = client.get("/api/dashboard?page_size=99999")
    assert res2.status_code == 400

    # Invalid event_type
    res3 = client.get("/api/dashboard?event_type=INVALID_TYPE")
    assert res3.status_code == 400

    # Invalid sort
    res4 = client.get("/api/dashboard?sort=fake_sort")
    assert res4.status_code == 400

    # Invalid timestamp
    res5 = client.get("/api/dashboard?start=not_a_time")
    assert res5.status_code == 400


def test_events_csv_export_matches_filtered_table(client):
    # Filter withdrawals
    csv_res = client.get("/api/events.csv?event_type=W")
    assert csv_res.status_code == 200
    assert "text/csv" in csv_res.headers["Content-Type"]

    csv_text = csv_res.get_data(as_text=True)
    reader = list(csv.reader(io.StringIO(csv_text)))
    header = reader[0]
    rows = reader[1:]

    expected_cols = [
        "timestamp_utc", "event_type", "prefix", "source_id", "as_path",
        "origin_as", "rpki_state", "snapshot_used", "snapshot_gap", "data_quality_note"
    ]
    assert header == expected_cols
    assert len(rows) == 4

    # Every row in withdrawals CSV should have event_type W and origin_as '—'
    for r in rows:
        assert r[1] == "W"
        assert r[5] == "—"
        assert r[6] == "Unassigned"


def test_csv_formula_injection_escaping():
    assert sanitize_csv_cell("=1+1") == "'=1+1"
    assert sanitize_csv_cell("+cmd") == "'+cmd"
    assert sanitize_csv_cell("-123") == "'-123"
    assert sanitize_csv_cell("@SUM(A1:A10)") == "'@SUM(A1:A10)"
    assert sanitize_csv_cell("normal_text") == "normal_text"
    assert sanitize_csv_cell(None) == ""


def test_events_endpoint_valid_and_pagination(client):
    res = client.get("/api/events?page=1&page_size=20&sort=timestamp_asc")
    assert res.status_code == 200
    data = res.get_json()
    assert "events" in data
    assert "pagination" in data
    assert "filters_applied" in data

    assert len(data["events"]) == 20
    assert data["pagination"]["total_filtered"] == 266
    assert data["pagination"]["page"] == 1
    assert data["pagination"]["page_size"] == 20
    assert data["pagination"]["has_next"] is True
    assert data["pagination"]["has_prev"] is False
    assert data["filters_applied"]["sort"] == "timestamp_asc"


def test_events_endpoint_bad_parameters_return_400(client):
    # Bad page
    assert client.get("/api/events?page=-1").status_code == 400
    assert client.get("/api/events?page=not_an_int").status_code == 400

    # Bad page_size
    assert client.get("/api/events?page_size=0").status_code == 400
    assert client.get("/api/events?page_size=5000").status_code == 400

    # Bad event_type
    assert client.get("/api/events?event_type=XYZ").status_code == 400

    # Bad rpki_state
    assert client.get("/api/events?rpki_state=UnknownState").status_code == 400

    # Bad start / end
    assert client.get("/api/events?start=invalid-date").status_code == 400
    assert client.get("/api/events?start=2024-12-23T00:00:00Z&end=2024-12-20T00:00:00Z").status_code == 400

    # Bad sort
    assert client.get("/api/events?sort=unsupported_sort").status_code == 400


def test_csv_row_count_matches_events_pagination_total_filtered(client):
    filter_combos = [
        "",
        "?event_type=W",
        "?event_type=A",
        "?rpki_state=Valid",
        "?rpki_state=Unassigned",
        "?q=3333",
        "?q=193.0.0.0/21&event_type=A",
        "?start=2024-12-21T00:00:00Z&end=2024-12-22T00:00:00Z",
    ]
    for combo in filter_combos:
        events_res = client.get(f"/api/events{combo}")
        assert events_res.status_code == 200
        total_filtered = events_res.get_json()["pagination"]["total_filtered"]

        csv_res = client.get(f"/api/events.csv{combo}")
        assert csv_res.status_code == 200
        csv_text = csv_res.get_data(as_text=True)
        reader = list(csv.reader(io.StringIO(csv_text)))
        rows = reader[1:]  # Skip header
        assert len(rows) == total_filtered, f"Mismatch for combo {combo}: CSV had {len(rows)}, pagination had {total_filtered}"


def test_json_405_method_not_allowed(client):
    res = client.post("/api/dashboard", json={"test": "data"})
    assert res.status_code == 405
    data = res.get_json()
    assert data["error"] == "Method Not Allowed"
    assert data["status_code"] == 405



def test_live_status_endpoint_is_opt_in(client):
    res = client.get("/api/live/status")
    assert res.status_code == 200
    data = res.get_json()
    assert data["state"] == "stopped"
    assert data["connected"] is False
    assert data["subscription_prefix"] == "193.0.0.0/21"
    assert "validation_data_note" in data


def test_live_events_endpoint_returns_bounded_buffer(client):
    res = client.get("/api/live/events?limit=10")
    assert res.status_code == 200
    data = res.get_json()
    assert data["events"] == []
    assert data["status"]["buffered_events"] == 0


def test_live_events_rejects_invalid_limit(client):
    assert client.get("/api/live/events?limit=1001").status_code == 400
    assert client.get("/api/live/events?limit=nope").status_code == 400
