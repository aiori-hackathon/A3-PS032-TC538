"""Normalize historical RIPE Stat BGP-state JSON into route records."""

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RAW_DIR = ROOT / "data" / "raw"
PROCESSED_DIR = ROOT / "data" / "processed"


def find_snapshot_files() -> list[Path]:
    """Return BGP snapshot files, excluding BGP update-event files."""
    return sorted(
        path
        for path in RAW_DIR.glob("bgp_*.json")
        if not path.name.startswith("bgp_updates_")
    )


def normalize_bgp_file(input_path: Path) -> list[dict]:
    """Convert a RIPE Stat BGP-state response into normalized route records."""
    payload = json.loads(input_path.read_text(encoding="utf-8"))
    data = payload.get("data", {})

    timestamp = data.get("timestamp")
    records = data.get("bgp_state", [])

    normalized = []

    for route in records:
        path = route.get("path") or []

        normalized.append({
            "timestamp": timestamp,
            "prefix": route.get("target_prefix"),
            "source_id": route.get("source_id"),
            "as_path": path,
            "origin_as": path[-1] if path else None,
            "as_path_length": len(path),
            "rpki_status": None,
            "data_source": "ripe_stat_bgp_state",
            "synthetic": False,
        })

    return normalized


def main() -> None:
    PROCESSED_DIR.mkdir(parents=True, exist_ok=True)

    input_files = find_snapshot_files()

    if not input_files:
        raise SystemExit(
            "No BGP snapshot JSON files found in data/raw/. "
            "Run src/ingest.py first."
        )

    total = 0

    for input_path in input_files:
        records = normalize_bgp_file(input_path)

        output_path = PROCESSED_DIR / f"{input_path.stem}_routes.json"
        output_path.write_text(
            json.dumps(records, indent=2),
            encoding="utf-8",
        )

        total += len(records)
        print(f"{input_path.name}: {len(records)} routes")
        print(f"  -> {output_path.relative_to(ROOT)}")

    print(f"\nNormalization complete: {total} route records.")
    print("RPKI status remains unknown until time-aligned data is available.")
    print("All records originate from real API responses; none are synthetic.")


if __name__ == "__main__":
    main()
