"""Unit tests for RFC 6811 / RFC 9582 BGP Prefix Origin Validation."""

import datetime
import ipaddress
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import pytest
from src.rpki_validator import VRP, extract_origin_as, validate_prefix_origin


def test_extract_origin_as_valid():
    assert extract_origin_as([174, 3333]) == (3333, None)
    assert extract_origin_as(["AS174", "AS3333"]) == (3333, None)
    assert extract_origin_as([64512]) == (64512, None)


def test_extract_origin_as_empty_and_none():
    assert extract_origin_as([]) == (None, "Empty AS_PATH (0 hops)")
    assert extract_origin_as(None) == (None, "Path is None")


def test_extract_origin_as_set():
    origin, note = extract_origin_as([174, {3333, 4444}])
    assert origin is None
    assert "AS_SET" in note

    origin2, note2 = extract_origin_as([174, "{3333,4444}"])
    assert origin2 is None
    assert "AS_SET" in note2


def test_extract_origin_as_malformed():
    origin, note = extract_origin_as([174, "not_an_asn"])
    assert origin is None
    assert "Malformed" in note


def test_rfc6811_valid_exact_match():
    vrps = [VRP(asn=3333, prefix=ipaddress.ip_network("193.0.0.0/21"), max_length=21)]
    res = validate_prefix_origin("193.0.0.0/21", [174, 3333], "A", vrps)
    assert res["rpki_state"] == "Valid"
    assert res["origin_as"] == 3333
    assert res["matching_vrps_count"] == 1


def test_rfc6811_valid_more_specific_within_max_length():
    vrps = [VRP(asn=3333, prefix=ipaddress.ip_network("193.0.0.0/20"), max_length=24)]
    res = validate_prefix_origin("193.0.0.0/21", [174, 3333], "A", vrps)
    assert res["rpki_state"] == "Valid"
    assert res["origin_as"] == 3333


def test_rfc6811_invalid_wrong_origin():
    vrps = [VRP(asn=3333, prefix=ipaddress.ip_network("193.0.0.0/21"), max_length=21)]
    res = validate_prefix_origin("193.0.0.0/21", [174, 9999], "A", vrps)
    assert res["rpki_state"] == "Invalid"
    assert res["origin_as"] == 9999
    assert res["invalid_subreason"] == "WrongOrigin"
    assert res["matching_vrps_count"] == 0
    assert res["covering_vrps_count"] == 1


def test_rfc6811_invalid_max_length_exceeded():
    vrps = [VRP(asn=3333, prefix=ipaddress.ip_network("193.0.0.0/21"), max_length=21)]
    # Announcement of a /22 when max_length is 21
    res = validate_prefix_origin("193.0.0.0/22", [174, 3333], "A", vrps)
    assert res["rpki_state"] == "Invalid"
    assert res["invalid_subreason"] == "MaxLengthExceeded"


def test_rfc6811_invalid_wrong_origin_and_max_length():
    vrps = [VRP(asn=3333, prefix=ipaddress.ip_network("193.0.0.0/21"), max_length=21)]
    res = validate_prefix_origin("193.0.0.0/22", [174, 8888], "A", vrps)
    assert res["rpki_state"] == "Invalid"
    assert res["invalid_subreason"] == "WrongOriginAndMaxLengthExceeded"


def test_rfc6811_not_found_no_covering_vrp():
    vrps = [VRP(asn=3333, prefix=ipaddress.ip_network("193.0.0.0/21"), max_length=21)]
    res = validate_prefix_origin("8.8.8.0/24", [174, 15169], "A", vrps)
    assert res["rpki_state"] == "NotFound"
    assert res["covering_vrps_count"] == 0


def test_rfc6811_ipv6_support():
    vrps = [VRP(asn=3333, prefix=ipaddress.ip_network("2001:7fb::/32"), max_length=48)]
    res_valid = validate_prefix_origin("2001:7fb::/32", [3333], "A", vrps)
    assert res_valid["rpki_state"] == "Valid"

    res_invalid = validate_prefix_origin("2001:7fb::/32", [9999], "A", vrps)
    assert res_invalid["rpki_state"] == "Invalid"

    res_notfound = validate_prefix_origin("2001:db8::/32", [3333], "A", vrps)
    assert res_notfound["rpki_state"] == "NotFound"


def test_rfc6811_temporal_validity_active():
    t0 = datetime.datetime(2024, 1, 1, tzinfo=datetime.timezone.utc)
    t1 = datetime.datetime(2024, 12, 21, 12, 0, tzinfo=datetime.timezone.utc)
    t2 = datetime.datetime(2025, 1, 1, tzinfo=datetime.timezone.utc)

    vrps = [VRP(asn=3333, prefix=ipaddress.ip_network("193.0.0.0/21"), max_length=21, not_before=t0, not_after=t2)]
    res = validate_prefix_origin("193.0.0.0/21", [3333], "A", vrps, reference_time=t1)
    assert res["rpki_state"] == "Valid"


def test_rfc6811_temporal_validity_expired():
    t0 = datetime.datetime(2024, 1, 1, tzinfo=datetime.timezone.utc)
    t_exp = datetime.datetime(2024, 6, 1, tzinfo=datetime.timezone.utc)
    t_event = datetime.datetime(2024, 12, 21, tzinfo=datetime.timezone.utc)

    vrps = [VRP(asn=3333, prefix=ipaddress.ip_network("193.0.0.0/21"), max_length=21, not_before=t0, not_after=t_exp)]
    res = validate_prefix_origin("193.0.0.0/21", [3333], "A", vrps, reference_time=t_event)
    # Expired VRP is inactive, so no active covering ROA -> NotFound
    assert res["rpki_state"] == "NotFound"
    assert res["inactive_vrps_count"] == 1


def test_rfc6811_temporal_validity_not_yet_valid():
    t_future = datetime.datetime(2025, 1, 1, tzinfo=datetime.timezone.utc)
    t_event = datetime.datetime(2024, 12, 21, tzinfo=datetime.timezone.utc)

    vrps = [VRP(asn=3333, prefix=ipaddress.ip_network("193.0.0.0/21"), max_length=21, not_before=t_future)]
    res = validate_prefix_origin("193.0.0.0/21", [3333], "A", vrps, reference_time=t_event)
    assert res["rpki_state"] == "NotFound"
    assert res["inactive_vrps_count"] == 1


def test_withdrawal_is_unassigned_with_no_origin():
    vrps = [VRP(asn=3333, prefix=ipaddress.ip_network("193.0.0.0/21"), max_length=21)]
    # Even if path was somehow passed, withdrawal must NEVER have an origin AS
    res = validate_prefix_origin("193.0.0.0/21", [3333], "W", vrps)
    assert res["rpki_state"] == "Unassigned"
    assert res["origin_as"] is None
    assert "Withdrawal" in res["reason"]


def test_malformed_path_is_unassigned():
    vrps = [VRP(asn=3333, prefix=ipaddress.ip_network("193.0.0.0/21"), max_length=21)]
    res = validate_prefix_origin("193.0.0.0/21", [], "A", vrps)
    assert res["rpki_state"] == "Unassigned"
    assert res["origin_as"] is None
