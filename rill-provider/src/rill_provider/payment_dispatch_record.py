"""The persisted dispatch-record format and its original-payer binding.

A record is committed atomically when the one-shot grant is consumed, before
any external effect. It is custody history, never permission to replay.
Version 1 records name the LND identity that prepared the exact request and
the full configured network, so a later negative tracking result can be
attributed to that payer. Older, partial, or malformed records yield no
payer: they remain witness-only and never gain authority from configuration.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from rill_core.wire.canonical import canonicalize, parse_json_strict
from rill_core.wire.types import NetworkIdentity

from rill_provider._lnd_proto.routerrpc import router_pb2

DISPATCH_RECORD_VERSION = 1
MAX_RECORD_BYTES = 256 * 1024
_NODE_KEY = re.compile(r"0[23][0-9a-f]{64}")
_HEX = re.compile(r"(?:[0-9a-f]{2})+")


@dataclass(frozen=True, slots=True)
class PaymentAuthority:
    """The LND identity and configured network bound to one dispatch."""

    node_pubkey: str
    network: NetworkIdentity

    def __post_init__(self) -> None:
        """Refuse any identity that is not a compressed secp256k1 key."""
        if type(self.node_pubkey) is not str or _NODE_KEY.fullmatch(self.node_pubkey) is None:
            raise ValueError("LND identity must be a compressed public key")
        if not isinstance(self.network, NetworkIdentity):
            raise TypeError("payer network identity required")


def encode_dispatch(request: bytes, payer: PaymentAuthority) -> bytes:
    """Return the canonical, self-describing version 1 dispatch record."""
    return canonicalize(
        {
            "version": DISPATCH_RECORD_VERSION,
            "method": "SendToRouteV2",
            "request_hex": request.hex(),
            "payer": {
                "node_pubkey": payer.node_pubkey,
                "network": payer.network.model_dump(mode="json"),
            },
        }
    )


def bound_payer(
    record: bytes | None, *, payment_hash: str, network: NetworkIdentity
) -> PaymentAuthority | None:
    """Return the bound payer only for a complete, consistent version 1 record.

    Absent, legacy (unversioned or relative-send), malformed, non-canonical,
    other-network, or other-hash records return None. None proves nothing
    about the payment; callers must treat it as unknown provenance.
    """
    try:
        return _parse(record, payment_hash=payment_hash, network=network)
    except Exception:  # noqa: BLE001 - malformed custody is unknown provenance, never authority
        return None


def _parse(record: object, *, payment_hash: str, network: NetworkIdentity) -> PaymentAuthority:
    """Parse one record completely or raise; the caller maps any failure to None."""
    if type(record) is not bytes or not 0 < len(record) <= MAX_RECORD_BYTES:
        raise ValueError("record size")
    document = parse_json_strict(record, max_bytes=MAX_RECORD_BYTES)
    if canonicalize(document) != record or not isinstance(document, dict):
        raise ValueError("record encoding")
    payer = document.get("payer")
    request_hex = document.get("request_hex")
    if (
        set(document) != {"version", "method", "request_hex", "payer"}
        or type(document["version"]) is not int
        or document["version"] != DISPATCH_RECORD_VERSION
        or document["method"] != "SendToRouteV2"
        or type(request_hex) is not str
        or _HEX.fullmatch(request_hex) is None
        or not isinstance(payer, dict)
        or set(payer) != {"node_pubkey", "network"}
        or type(payer["node_pubkey"]) is not str
    ):
        raise ValueError("record fields")
    raw = bytes.fromhex(request_hex)
    request = router_pb2.SendToRouteRequest.FromString(raw)
    bound_network = NetworkIdentity.model_validate_json(canonicalize(payer["network"]), strict=True)
    if (
        request.SerializeToString() != raw
        or request.payment_hash.hex() != payment_hash
        or bound_network != network
    ):
        raise ValueError("record binding")
    return PaymentAuthority(payer["node_pubkey"], bound_network)
