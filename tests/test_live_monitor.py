from datetime import datetime, timezone

from src.live_monitor import RISLiveMonitor, normalize_ris_message
from src.rpki_validator import VRP


def test_normalize_announcement_includes_more_specific_routes():
    vrps = [VRP.from_dict({"prefix": "193.0.0.0/21", "origin": 3333, "max_length": 24})]
    message = {
        "type": "ris_message",
        "data": {
            "type": "UPDATE",
            "timestamp": 1792120617.63,
            "peer": "192.0.2.1",
            "peer_asn": "64500",
            "host": "rrc21",
            "id": "test-message-1",
            "path": [64500, 3333],
            "announcements": [{"next_hop": "192.0.2.1", "prefixes": ["193.0.0.0/21", "193.0.4.0/24"]}],
            "withdrawals": [],
        },
    }
    rows = normalize_ris_message(message, vrps, datetime(2026, 10, 29, tzinfo=timezone.utc))
    assert len(rows) == 2
    assert rows[0]["rpki_state"] == "Valid"
    assert rows[0]["origin_as"] == 3333
    assert rows[0]["event_type"] == "A"
    assert rows[0]["prefix"] == "193.0.0.0/21"
    assert rows[1]["prefix"] == "193.0.4.0/24"
    assert rows[1]["rpki_state"] == "Valid"


def test_withdrawal_is_unassigned_and_has_no_origin():
    message = {
        "type": "ris_message",
        "data": {
            "type": "UPDATE",
            "timestamp": 1792120617.63,
            "path": [64500, 3333],
            "announcements": [],
            "withdrawals": ["193.0.0.0/21"],
        },
    }
    rows = normalize_ris_message(message, [], datetime(2026, 10, 29, tzinfo=timezone.utc))
    assert len(rows) == 1
    assert rows[0]["event_type"] == "W"
    assert rows[0]["rpki_state"] == "Unassigned"
    assert rows[0]["origin_as"] is None


def test_ignores_non_update_ris_messages():
    assert normalize_ris_message({"type": "ris_message", "data": {"type": "KEEPALIVE"}}, []) == []


def test_monitor_buffer_is_bounded_and_status_is_copy():
    monitor = RISLiveMonitor(max_events=2)
    monitor._events.extend([{"n": 1}, {"n": 2}, {"n": 3}])
    assert monitor.events(10) == [{"n": 2}, {"n": 3}]
    status = monitor.status()
    status["state"] = "fake"
    assert monitor.status()["state"] == "stopped"
