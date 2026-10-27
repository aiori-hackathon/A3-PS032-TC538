import csv
import ipaddress
import lzma
from datetime import datetime
from pathlib import Path


VALID = "Valid"
INVALID = "Invalid"
NOT_FOUND = "NotFound"


def _parse_datetime(value):
    """Parse the timestamp format used by the historical ROA CSV files."""
    return datetime.fromisoformat(value.strip())


def load_vrps(snapshot_path, at_time=None):
    """Load VRPs from a compressed ROA CSV snapshot.

    If at_time is supplied, discard records outside their Not Before/Not After
    validity interval. Times must use the same timezone convention as the CSV.
    """
    vrps = []
    snapshot_path = Path(snapshot_path)

    with lzma.open(snapshot_path, "rt", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)

        required = {"ASN", "IP Prefix", "Max Length", "Not Before", "Not After"}
        if not reader.fieldnames or not required.issubset(reader.fieldnames):
            raise ValueError(
                f"Unexpected ROA CSV schema in {snapshot_path}: "
                f"{reader.fieldnames}"
            )

        for row in reader:
            try:
                prefix = ipaddress.ip_network(row["IP Prefix"].strip(), strict=False)
                max_length = int(row["Max Length"])
                asn_text = row["ASN"].strip().upper()
                if not asn_text.startswith("AS"):
                    continue
                asn = int(asn_text[2:])
                not_before = _parse_datetime(row["Not Before"])
                not_after = _parse_datetime(row["Not After"])
            except (ValueError, TypeError, KeyError):
                continue

            if not prefix.prefixlen <= max_length <= prefix.max_prefixlen:
                continue

            if at_time is not None and not (
                not_before <= at_time <= not_after
            ):
                continue

            vrps.append({
                "prefix": prefix,
                "asn": asn,
                "max_length": max_length,
                "not_before": not_before,
                "not_after": not_after,
            })

    return vrps


def validate_origin(prefix, origin_asn, vrps):
    """Return Valid, Invalid, or NotFound for a prefix/origin-AS pair."""
    announced_prefix = ipaddress.ip_network(prefix, strict=False)
    origin_asn = int(origin_asn)

    covering = [
        vrp for vrp in vrps
        if vrp["prefix"].version == announced_prefix.version
        and announced_prefix.subnet_of(vrp["prefix"])
    ]

    if not covering:
        return NOT_FOUND

    for vrp in covering:
        if (
            vrp["asn"] == origin_asn
            and announced_prefix.prefixlen <= vrp["max_length"]
        ):
            return VALID

    return INVALID


def snapshot_time_from_filename(snapshot_path):
    """Read YYYY-MM-DD from filenames like roas_2024-12-20.csv.xz."""
    name = Path(snapshot_path).name
    date_text = name.removeprefix("roas_").removesuffix(".csv.xz")
    return datetime.strptime(date_text, "%Y-%m-%d")
