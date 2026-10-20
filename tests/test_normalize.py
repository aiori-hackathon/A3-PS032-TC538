import json
import tempfile
import unittest
from pathlib import Path

from src.normalize import normalize_bgp_file


class TestNormalizeBGPFile(unittest.TestCase):
    def normalize_payload(self, payload):
        with tempfile.TemporaryDirectory() as temp_dir:
            input_path = Path(temp_dir) / "snapshot.json"
            input_path.write_text(
                json.dumps(payload),
                encoding="utf-8",
            )
            return normalize_bgp_file(input_path)

    def test_normalizes_valid_route(self):
        payload = {
            "data": {
                "timestamp": "2024-12-20T12:00:00",
                "bgp_state": [
                    {
                        "target_prefix": "193.0.0.0/21",
                        "source_id": "collector-1",
                        "path": [64500, 3333],
                    }
                ],
            }
        }

        routes = self.normalize_payload(payload)

        self.assertEqual(len(routes), 1)
        self.assertEqual(routes[0]["timestamp"], "2024-12-20T12:00:00")
        self.assertEqual(routes[0]["prefix"], "193.0.0.0/21")
        self.assertEqual(routes[0]["source_id"], "collector-1")
        self.assertEqual(routes[0]["as_path"], [64500, 3333])
        self.assertEqual(routes[0]["origin_as"], 3333)
        self.assertEqual(routes[0]["as_path_length"], 2)
        self.assertIsNone(routes[0]["rpki_status"])
        self.assertFalse(routes[0]["synthetic"])

    def test_empty_bgp_state_returns_no_routes(self):
        routes = self.normalize_payload({"data": {"bgp_state": []}})
        self.assertEqual(routes, [])

    def test_missing_bgp_state_returns_no_routes(self):
        routes = self.normalize_payload({"data": {}})
        self.assertEqual(routes, [])

    def test_empty_as_path_has_no_origin(self):
        payload = {
            "data": {
                "bgp_state": [
                    {
                        "target_prefix": "193.0.0.0/21",
                        "source_id": "collector-1",
                        "path": [],
                    }
                ]
            }
        }

        routes = self.normalize_payload(payload)

        self.assertIsNone(routes[0]["origin_as"])
        self.assertEqual(routes[0]["as_path_length"], 0)

    def test_snapshot_discovery_excludes_update_files(self):
        from unittest.mock import patch

        from src import normalize

        fake_files = [
            Path("bgp_snapshot.json"),
            Path("bgp_updates_events.json"),
            Path("bgp_another_snapshot.json"),
        ]

        with patch.object(normalize, "RAW_DIR") as mock_raw_dir:
            mock_raw_dir.glob.return_value = fake_files

            result = normalize.find_snapshot_files()

        self.assertEqual(
            [path.name for path in result],
            ["bgp_another_snapshot.json", "bgp_snapshot.json"],
        )

if __name__ == "__main__":
    unittest.main()