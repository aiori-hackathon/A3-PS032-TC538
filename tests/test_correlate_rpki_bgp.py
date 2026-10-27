
import unittest
from datetime import datetime

from src.correlate_rpki_bgp import (
    correlate_event,
    parse_timestamp,
    select_snapshot,
)


class TestCorrelationHelpers(unittest.TestCase):
    def setUp(self):
        self.snapshots = [
            {
                "timestamp": datetime(2024, 12, 20),
                "file": "roas_2024-12-20.csv.xz",
                "vrps": [],
            },
            {
                "timestamp": datetime(2024, 12, 21),
                "file": "roas_2024-12-21.csv.xz",
                "vrps": [],
            },
        ]

    def test_parse_timestamp(self):
        result = parse_timestamp("2024-12-20T00:00:30")
        self.assertEqual(result, datetime(2024, 12, 20, 0, 0, 30))

    def test_parse_timestamp_preserves_timezone_if_present(self):
        result = parse_timestamp("2024-12-20T00:00:30+00:00")
        self.assertIsNotNone(result.tzinfo)

    def test_selects_latest_snapshot_at_or_before_event(self):
        result = select_snapshot(
            datetime(2024, 12, 21, 12),
            self.snapshots,
        )
        self.assertEqual(result["file"], "roas_2024-12-21.csv.xz")

    def test_does_not_select_future_snapshot(self):
        result = select_snapshot(
            datetime(2024, 12, 19, 12),
            self.snapshots,
        )
        self.assertIsNone(result)

    def test_selects_snapshot_at_exact_timestamp(self):
        result = select_snapshot(
            datetime(2024, 12, 21),
            self.snapshots,
        )
        self.assertEqual(result["file"], "roas_2024-12-21.csv.xz")

    def test_withdrawal_has_no_assigned_validation_state(self):
        event = {
            "timestamp": "2024-12-21T12:00:00",
            "event_type": "W",
            "prefix": "193.0.0.0/21",
            "as_path": None,
        }
        result = correlate_event(event, self.snapshots)

        self.assertIsNone(result["origin_as"])
        self.assertIsNone(result["rpki_state"])
        self.assertIn("Withdrawal", result["status_note"])

    def test_announcement_without_path_is_unassigned(self):
        event = {
            "timestamp": "2024-12-21T12:00:00",
            "event_type": "A",
            "prefix": "193.0.0.0/21",
            "as_path": [],
        }
        result = correlate_event(event, self.snapshots)

        self.assertIsNone(result["rpki_state"])
        self.assertIn("no usable AS path", result["status_note"])

    def test_announcement_without_eligible_snapshot_is_unassigned(self):
        event = {
            "timestamp": "2024-12-19T12:00:00",
            "event_type": "A",
            "prefix": "193.0.0.0/21",
            "as_path": [140984, 3333],
        }
        result = correlate_event(event, self.snapshots)

        self.assertIsNone(result["rpki_state"])
        self.assertIsNone(result["rpki_snapshot"])
        self.assertIn("No snapshot", result["status_note"])


if __name__ == "__main__":
    unittest.main()
