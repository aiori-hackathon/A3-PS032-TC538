import unittest
from datetime import datetime
from ipaddress import ip_network

from src.rpki_history import (
    VALID,
    INVALID,
    NOT_FOUND,
    validate_origin,
)


def vrp(prefix, asn, max_length):
    return {
        "prefix": ip_network(prefix),
        "asn": asn,
        "max_length": max_length,
        "not_before": datetime(2024, 1, 1),
        "not_after": datetime(2025, 12, 31),
    }


class TestValidateOrigin(unittest.TestCase):
    def setUp(self):
        self.vrps = [
            vrp("193.0.0.0/21", 3333, 21),
        ]

    def test_exact_authorized_prefix_is_valid(self):
        self.assertEqual(
            validate_origin("193.0.0.0/21", 3333, self.vrps),
            VALID,
        )

    def test_wrong_origin_is_invalid(self):
        self.assertEqual(
            validate_origin("193.0.0.0/21", 64500, self.vrps),
            INVALID,
        )

    def test_more_specific_beyond_max_length_is_invalid(self):
        self.assertEqual(
            validate_origin("193.0.0.0/22", 3333, self.vrps),
            INVALID,
        )

    def test_no_covering_vrp_is_not_found(self):
        self.assertEqual(
            validate_origin("198.51.100.0/24", 3333, self.vrps),
            NOT_FOUND,
        )

    def test_authorized_more_specific_is_valid_when_max_length_allows_it(self):
        vrps = [vrp("193.0.0.0/21", 3333, 24)]
        self.assertEqual(
            validate_origin("193.0.0.0/22", 3333, vrps),
            VALID,
        )

    def test_any_matching_covering_vrp_makes_route_valid(self):
        vrps = [
            vrp("193.0.0.0/21", 64500, 24),
            vrp("193.0.0.0/21", 3333, 21),
        ]
        self.assertEqual(
            validate_origin("193.0.0.0/21", 3333, vrps),
            VALID,
        )


if __name__ == "__main__":
    unittest.main()
