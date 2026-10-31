import json
from pathlib import Path

import pytest

from src.vrp_cache import VRPCache


@pytest.fixture
def export_payload():
    return {
        "metadata": {"generatedTime": "2026-10-31T16:42:41Z"},
        "roas": [
            {"asn": "AS3333", "prefix": "193.0.0.0/16", "maxLength": 24},
            {"asn": "AS3333", "prefix": "193.0.0.0/21", "maxLength": 21},
            {"asn": "AS3333", "prefix": "193.0.4.0/24", "maxLength": 24},
            {"asn": "AS15169", "prefix": "8.8.8.0/24", "maxLength": 24},
        ],
    }


def test_export_filters_covering_exact_and_more_specific_roas(tmp_path, export_payload):
    cache = VRPCache(cache_file=tmp_path / "vrps.json")

    vrps, generated = cache._parse_export(export_payload)

    assert generated == "2026-10-31T16:42:41Z"
    assert {str(vrp.prefix) for vrp in vrps} == {
        "193.0.0.0/16",
        "193.0.0.0/21",
        "193.0.4.0/24",
    }


def test_rejects_export_without_usable_relevant_roas(tmp_path):
    cache = VRPCache(cache_file=tmp_path / "vrps.json")

    payload = {
        "metadata": {"generatedTime": "2026-10-31T16:42:41Z"},
        "roas": [
            {"asn": "AS15169", "prefix": "8.8.8.0/24", "maxLength": 24}
        ],
    }

    with pytest.raises(ValueError):
        cache._parse_export(payload)


def test_snapshot_persists_and_reloads(tmp_path, export_payload):
    path = tmp_path / "vrps.json"
    cache = VRPCache(cache_file=path)

    vrps, generated = cache._parse_export(export_payload)
    cache._persist(vrps, generated, "2026-10-31T17:00:00+00:00")

    restored = VRPCache(cache_file=path)

    assert len(restored.get_vrps()) == 3
    assert restored.status()["validation_refresh_status"] == "cached"


def test_failed_refresh_preserves_last_known_good_snapshot(
    tmp_path, export_payload, monkeypatch
):
    path = tmp_path / "vrps.json"
    cache = VRPCache(cache_file=path)

    vrps, generated = cache._parse_export(export_payload)
    cache._persist(vrps, generated, "2026-10-31T17:00:00+00:00")

    restored = VRPCache(cache_file=path)

    def fail_request(*args, **kwargs):
        raise RuntimeError("Simulated RIPE outage")

    monkeypatch.setattr("src.vrp_cache.requests.get", fail_request)

    with pytest.raises(RuntimeError):
        restored.refresh_once()

    assert len(restored.get_vrps()) == 3
    assert path.exists()
    assert restored.status()["validation_refresh_status"] == "failed"
    assert "Simulated RIPE outage" in restored.status()["validation_last_refresh_error"]


def test_successful_refresh_updates_cache_and_snapshot(
    tmp_path, export_payload, monkeypatch
):
    path = tmp_path / "vrps.json"
    cache = VRPCache(cache_file=path)

    class FakeResponse:
        def raise_for_status(self):
            pass

        def iter_content(self, chunk_size):
            yield json.dumps(export_payload).encode("utf-8")

    def fake_request(*args, **kwargs):
        return FakeResponse()

    monkeypatch.setattr("src.vrp_cache.requests.get", fake_request)

    count = cache.refresh_once()

    assert count == 3
    assert len(cache.get_vrps()) == 3
    assert path.exists()
    assert cache.status()["validation_refresh_status"] == "success"
    assert cache.status()["validation_data_source"] == str(path)
