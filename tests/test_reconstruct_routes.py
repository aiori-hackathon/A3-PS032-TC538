
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from contextlib import redirect_stdout
from io import StringIO

from src import reconstruct_routes


class TestReconstructRoutes(unittest.TestCase):

    def test_malformed_path_clears_stale_route(self):
        events = [
            {
                "timestamp": "2024-12-20T00:00:00",
                "event_type": "A",
                "prefix": "193.0.0.0/21",
                "source_id": "collector-1",
                "as_path": [64500, 3333],
            },
            {
                "timestamp": "2024-12-20T00:01:00",
                "event_type": "A",
                "prefix": "193.0.0.0/21",
                "source_id": "collector-1",
                "as_path": [64500, "3333"],
            },
            {
                "timestamp": "2024-12-20T00:02:00",
                "event_type": "W",
                "prefix": "193.0.0.0/21",
                "source_id": "collector-1",
                "as_path": None,
            },
        ]

        result = self.run_reconstruction(events)

        invalid_events = [
            item for item in result["sequences"]
            if item["sequence_type"] == "announcement_invalid_path"
        ]
        withdrawals = [
            item for item in result["sequences"]
            if item["sequence_type"] == "withdrawal_observed"
        ]

        self.assertEqual(len(invalid_events), 1)
        self.assertEqual(
            invalid_events[0]["reason"],
            "invalid_asn_entries",
        )
        self.assertEqual(len(withdrawals), 1)
        self.assertEqual(
            withdrawals[0]["withdrawal_classification"],
            "withdrawal_without_tracked_route",
        )
        self.assertIsNone(withdrawals[0]["last_known_path"])

    def run_reconstruction(self, events):
        with tempfile.TemporaryDirectory() as temp_dir:
            temp = Path(temp_dir)
            input_path = temp / "events.json"
            output_path = temp / "analysis.json"

            input_path.write_text(
                json.dumps(events),
                encoding="utf-8",
            )

            with (
                patch.object(reconstruct_routes, "INPUT", input_path),
                patch.object(reconstruct_routes, "OUT", output_path),
                redirect_stdout(StringIO()),
            ):
                reconstruct_routes.main()

            return json.loads(output_path.read_text(encoding="utf-8"))

    def test_announcement_after_withdrawal(self):
        events = [
            {
                "timestamp": "2024-12-20T00:00:30",
                "event_type": "W",
                "prefix": "193.0.0.0/21",
                "source_id": "collector-1",
                "as_path": None,
            },
            {
                "timestamp": "2024-12-20T00:01:27",
                "event_type": "A",
                "prefix": "193.0.0.0/21",
                "source_id": "collector-1",
                "as_path": [140984, 3333],
            },
        ]

        result = self.run_reconstruction(events)

        self.assertEqual(
            result["announcement_after_withdrawal_count"], 1
        )
        sequence = result["announcement_after_withdrawal"][0]
        self.assertEqual(sequence["withdrawal_timestamp"],
                         "2024-12-20T00:00:30")
        self.assertEqual(sequence["announcement_timestamp"],
                         "2024-12-20T00:01:27")
        self.assertEqual(sequence["announced_path"], [140984, 3333])
        self.assertFalse(result["synthetic_data_used"])

    def test_announced_path_change(self):
        events = [
            {
                "timestamp": "2024-12-20T00:00:00",
                "event_type": "A",
                "prefix": "193.0.0.0/21",
                "source_id": "collector-1",
                "as_path": [140984, 3333],
            },
            {
                "timestamp": "2024-12-20T00:01:00",
                "event_type": "A",
                "prefix": "193.0.0.0/21",
                "source_id": "collector-1",
                "as_path": [64500, 3333],
            },
        ]

        result = self.run_reconstruction(events)

        self.assertEqual(result["observed_path_change_count"], 1)
        changes = [
            item for item in result["sequences"]
            if item["sequence_type"] == "announced_path_changed"
        ]
        self.assertEqual(changes[0]["previous_path"], [140984, 3333])
        self.assertEqual(changes[0]["new_path"], [64500, 3333])

    def test_empty_events(self):
        result = self.run_reconstruction([])

        self.assertEqual(result["input_event_count"], 0)
        self.assertEqual(result["observed_path_change_count"], 0)
        self.assertEqual(result["announcement_after_withdrawal_count"], 0)


    def test_withdrawal_classification(self):
        events = [
            {
                "timestamp": "2024-12-20T00:00:00",
                "event_type": "A",
                "prefix": "193.0.0.0/21",
                "source_id": "collector-1",
                "as_path": [64500, 3333],
            },
            {
                "timestamp": "2024-12-20T00:01:00",
                "event_type": "W",
                "prefix": "193.0.0.0/21",
                "source_id": "collector-1",
                "as_path": None,
            },
            {
                "timestamp": "2024-12-20T00:02:00",
                "event_type": "W",
                "prefix": "193.0.0.0/21",
                "source_id": "collector-2",
                "as_path": None,
            },
        ]

        result = self.run_reconstruction(events)
        withdrawals = [
            item for item in result["sequences"]
            if item["sequence_type"] == "withdrawal_observed"
        ]

        self.assertEqual(len(withdrawals), 2)
        self.assertEqual(
            withdrawals[0]["withdrawal_classification"],
            "withdrawal_with_tracked_route",
        )
        self.assertEqual(
            withdrawals[0]["last_known_path"],
            [64500, 3333],
        )
        self.assertEqual(
            withdrawals[1]["withdrawal_classification"],
            "withdrawal_without_tracked_route",
        )


    def test_repeated_withdrawal_without_intervening_announcement(self):
        events = [
            {
                "timestamp": "2024-12-20T00:00:00",
                "event_type": "A",
                "prefix": "193.0.0.0/21",
                "source_id": "collector-1",
                "as_path": [64500, 3333],
            },
            {
                "timestamp": "2024-12-20T00:01:00",
                "event_type": "W",
                "prefix": "193.0.0.0/21",
                "source_id": "collector-1",
                "as_path": None,
            },
            {
                "timestamp": "2024-12-20T00:02:00",
                "event_type": "W",
                "prefix": "193.0.0.0/21",
                "source_id": "collector-1",
                "as_path": None,
            },
        ]

        result = self.run_reconstruction(events)
        withdrawals = [
            item for item in result["sequences"]
            if item["sequence_type"] == "withdrawal_observed"
        ]

        self.assertEqual(len(withdrawals), 2)
        self.assertEqual(
            withdrawals[0]["withdrawal_classification"],
            "withdrawal_with_tracked_route",
        )
        self.assertEqual(
            withdrawals[1]["withdrawal_classification"],
            "withdrawal_without_tracked_route",
        )
        self.assertEqual(
            withdrawals[1]["last_known_path"],
            None,
        )


    def test_missing_path_does_not_preserve_stale_route(self):
        events = [
            {
                "timestamp": "2024-12-20T00:00:00",
                "event_type": "A",
                "prefix": "193.0.0.0/21",
                "source_id": "collector-1",
                "as_path": [64500, 3333],
            },
            {
                "timestamp": "2024-12-20T00:01:00",
                "event_type": "A",
                "prefix": "193.0.0.0/21",
                "source_id": "collector-1",
                "as_path": None,
            },
            {
                "timestamp": "2024-12-20T00:02:00",
                "event_type": "W",
                "prefix": "193.0.0.0/21",
                "source_id": "collector-1",
                "as_path": None,
            },
        ]

        result = self.run_reconstruction(events)
        withdrawals = [
            item for item in result["sequences"]
            if item["sequence_type"] == "withdrawal_observed"
        ]

        self.assertEqual(len(withdrawals), 1)
        self.assertEqual(
            withdrawals[0]["withdrawal_classification"],
            "withdrawal_without_tracked_route",
        )
        self.assertIsNone(withdrawals[0]["last_known_path"])


if __name__ == "__main__":
    unittest.main()
