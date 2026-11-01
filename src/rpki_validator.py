"""RFC 6811 / RFC 9582 BGP Prefix Origin Validation (ROV) implementation.

Audited requirements:
- Validated ROA Payload (VRP) structure with IPv4/IPv6, origin ASN, maxLength,
  and optional Not Before / Not After temporal validity with timezone support.
- Covering VRP evaluation: a VRP covers a route prefix if the route prefix is
  contained within (or equal to) the VRP prefix.
- Tri-state RFC 6811 validation for announcements with determined origin:
  * Valid: at least one covering VRP matches origin ASN and prefix length <= maxLength.
  * Invalid: covering VRP(s) exist, but none match both origin ASN and maxLength.
    (distinguishes wrong-origin, maxLength exceeded, or both).
  * NotFound: no covering VRP exists for the route prefix.
- Withdrawals:
  * Origin validation does not apply to withdrawals.
  * State: 'Unassigned', origin AS: None.
  * Never infer origin AS from a withdrawal.
- Malformed, empty, or AS_SET paths:
  * State: 'Unassigned', origin AS: None.
"""

from __future__ import annotations

import datetime
import ipaddress
from dataclasses import dataclass, field
from typing import Any, List, Optional, Tuple, Union


@dataclass(frozen=True)
class VRP:
    asn: int
    prefix: ipaddress.IPv4Network | ipaddress.IPv6Network
    max_length: int
    not_before: datetime.datetime | None = None
    not_after: datetime.datetime | None = None
    source_snapshot: str = ""

    @classmethod
    def from_dict(cls, data: dict[str, Any], snapshot_id: str = "") -> VRP:
        raw_prefix = data["prefix"]
        net = ipaddress.ip_network(raw_prefix, strict=False)
        asn_val = int(str(data.get("origin") or data.get("asn")).replace("AS", "").replace("as", "").strip())
        ml = int(data.get("max_length") or data.get("maxLength") or net.prefixlen)

        nb = data.get("not_before")
        na = data.get("not_after")

        def _parse_dt(val: Any) -> datetime.datetime | None:
            if not val:
                return None
            if isinstance(val, datetime.datetime):
                return val if val.tzinfo else val.replace(tzinfo=datetime.timezone.utc)
            clean = str(val).replace("Z", "+00:00")
            dt = datetime.datetime.fromisoformat(clean)
            return dt if dt.tzinfo else dt.replace(tzinfo=datetime.timezone.utc)

        return cls(
            asn=asn_val,
            prefix=net,
            max_length=ml,
            not_before=_parse_dt(nb),
            not_after=_parse_dt(na),
            source_snapshot=snapshot_id,
        )

    def is_active_at(self, reference_time: datetime.datetime | None) -> bool:
        """Check if VRP is active at the reference UTC time.
        If dates are absent, VRP is assumed active.
        """
        if reference_time is None:
            return True
        ref = reference_time if reference_time.tzinfo else reference_time.replace(tzinfo=datetime.timezone.utc)
        if self.not_before and ref < self.not_before:
            return False
        if self.not_after and ref > self.not_after:
            return False
        return True


def extract_origin_as(as_path: Any) -> tuple[int | None, str | None]:
    """Extract origin AS from an AS_PATH attribute.

    Returns (origin_as, note).
    - If path is empty, malformed, or terminates in an AS_SET: returns (None, note).
    - If valid AS_SEQUENCE ending in a valid integer ASN: returns (origin_as, None).
    """
    if as_path is None:
        return None, "Path is None"

    if not isinstance(as_path, (list, tuple)):
        return None, f"Malformed AS_PATH type: {type(as_path).__name__}"

    if len(as_path) == 0:
        return None, "Empty AS_PATH (0 hops)"

    origin_hop = as_path[-1]

    # Check for AS_SET (set, list, or string representation with braces)
    if isinstance(origin_hop, (set, list, tuple)):
        return None, f"Origin hop is an AS_SET {origin_hop}; origin ASN cannot be determined"

    if isinstance(origin_hop, str):
        hop_str = origin_hop.strip()
        if hop_str.startswith("{") and hop_str.endswith("}"):
            return None, f"Origin hop is an AS_SET string '{origin_hop}'; origin ASN cannot be determined"
        try:
            val = int(hop_str.replace("AS", "").replace("as", ""))
            if val < 0 or val > 4294967295:
                return None, f"Origin ASN out of range: {val}"
            return val, None
        except ValueError:
            return None, f"Malformed origin hop string: '{origin_hop}'"

    if isinstance(origin_hop, int):
        if origin_hop < 0 or origin_hop > 4294967295:
            return None, f"Origin ASN out of 32-bit range: {origin_hop}"
        return origin_hop, None

    return None, f"Unrecognized hop type: {type(origin_hop).__name__}"


def validate_prefix_origin(
    prefix_str: str,
    as_path: Any,
    event_type: str,
    vrps: list[VRP],
    reference_time: datetime.datetime | None = None,
) -> dict[str, Any]:
    """Perform RFC 6811 BGP Prefix Origin Validation.

    Returns a comprehensive structured result dict:
    - rpki_state: 'Valid' | 'Invalid' | 'NotFound' | 'Unassigned'
    - origin_as: int | None
    - reason: human-readable explanation
    - invalid_subreason: 'WrongOrigin' | 'MaxLengthExceeded' | 'WrongOriginAndMaxLengthExceeded' | None
    - covering_vrps_count: int
    - matching_vrps_count: int
    - inactive_vrps_count: int
    """
    ev_type = str(event_type or "").upper().strip()

    # Rule 1: Withdrawals
    if ev_type == "W":
        return {
            "rpki_state": "Unassigned",
            "origin_as": None,
            "reason": "Withdrawal message does not carry origin AS; RPKI origin validation unassigned per RFC 6811",
            "invalid_subreason": None,
            "covering_vrps_count": 0,
            "matching_vrps_count": 0,
            "inactive_vrps_count": 0,
        }

    # Rule 2: Origin AS extraction
    origin_as, path_note = extract_origin_as(as_path)
    if origin_as is None:
        return {
            "rpki_state": "Unassigned",
            "origin_as": None,
            "reason": f"AS path cannot yield origin AS: {path_note}",
            "invalid_subreason": None,
            "covering_vrps_count": 0,
            "matching_vrps_count": 0,
            "inactive_vrps_count": 0,
        }

    # Parse route prefix
    try:
        route_net = ipaddress.ip_network(prefix_str, strict=False)
    except Exception as exc:
        return {
            "rpki_state": "Unassigned",
            "origin_as": origin_as,
            "reason": f"Malformed IP prefix '{prefix_str}': {exc}",
            "invalid_subreason": None,
            "covering_vrps_count": 0,
            "matching_vrps_count": 0,
            "inactive_vrps_count": 0,
        }

    # Temporal and family filtering
    active_vrps: list[VRP] = []
    inactive_vrps: list[VRP] = []

    for v in vrps:
        if v.prefix.version != route_net.version:
            continue
        if v.is_active_at(reference_time):
            active_vrps.append(v)
        else:
            inactive_vrps.append(v)

    # Find covering VRPs: route_net is a subnet of or equal to v.prefix
    covering: list[VRP] = [
        v for v in active_vrps
        if route_net.subnet_of(v.prefix)
    ]

    # RFC 6811: If no covering VRP exists -> NotFound
    if not covering:
        # Check if there are inactive covering VRPs for context
        inactive_covering = [v for v in inactive_vrps if route_net.subnet_of(v.prefix)]
        reason = "No active covering ROA exists for this prefix."
        if inactive_covering:
            reason += f" ({len(inactive_covering)} covering ROA(s) exist but are inactive/expired at reference time)."
        return {
            "rpki_state": "NotFound",
            "origin_as": origin_as,
            "reason": reason,
            "invalid_subreason": None,
            "covering_vrps_count": 0,
            "matching_vrps_count": 0,
            "inactive_vrps_count": len(inactive_covering),
        }

    # Covering VRPs exist: check for matches
    matching: list[VRP] = []
    asn_matches: list[VRP] = []
    length_matches: list[VRP] = []

    for v in covering:
        asn_ok = (v.asn == origin_as)
        len_ok = (route_net.prefixlen <= v.max_length)
        if asn_ok:
            asn_matches.append(v)
        if len_ok:
            length_matches.append(v)
        if asn_ok and len_ok:
            matching.append(v)

    if matching:
        return {
            "rpki_state": "Valid",
            "origin_as": origin_as,
            "reason": f"Covering ROA matches origin AS{origin_as} and prefix length /{route_net.prefixlen} <= maxLength {matching[0].max_length}",
            "invalid_subreason": None,
            "covering_vrps_count": len(covering),
            "matching_vrps_count": len(matching),
            "inactive_vrps_count": 0,
        }

    # Invalid: covering ROAs exist but none match both
    if asn_matches and not length_matches:
        subreason = "MaxLengthExceeded"
        reason = f"Covering ROA matches origin AS{origin_as} but route prefix /{route_net.prefixlen} exceeds allowed maxLength (max allowed: {max(v.max_length for v in asn_matches)})"
    elif not asn_matches and length_matches:
        subreason = "WrongOrigin"
        allowed_asns = sorted({v.asn for v in covering})
        reason = f"Origin AS{origin_as} not authorized by covering ROA (authorized ASN(s): {allowed_asns})"
    else:
        subreason = "WrongOriginAndMaxLengthExceeded"
        allowed_asns = sorted({v.asn for v in covering})
        reason = f"Origin AS{origin_as} unauthorized and prefix length /{route_net.prefixlen} exceeds allowed maxLength"

    return {
        "rpki_state": "Invalid",
        "origin_as": origin_as,
        "reason": reason,
        "invalid_subreason": subreason,
        "covering_vrps_count": len(covering),
        "matching_vrps_count": 0,
        "inactive_vrps_count": 0,
    }
