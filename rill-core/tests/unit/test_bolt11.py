"""BOLT 11 reading and admission agree with the browser decoder's shared vectors.

Offline: a pinned authenticator stands in for libsecp256k1, so every parsing,
routing, and admission rule is checked here; signature validity itself is the
native contract test's job (tests/adapter_contracts/test_bolt11_native.py).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from rill_core.errors import ValidationError
from rill_core.wire.bolt11 import (
    InvoiceRejectedError,
    decode_bolt11,
    invoice_binding,
    require_wire_agreement,
)
from rill_core.wire.types import NetworkIdentity

DOCS = Path(__file__).parents[3] / "rill-docs"
VECTORS = json.loads((DOCS / "vectors/bolt11/cases-v1.json").read_text())
NETWORK_FILES = {
    "mainnet": "mainnet",
    "testnet4": "testnet4",
    "signet": "signet",
    "regtest": "regtest-rillswap-e2e-v1",
}
SIGNATURE_INVALID = "Invoice refused: signature invalid"


def network(name: str) -> NetworkIdentity:
    return NetworkIdentity.model_validate_json(
        (DOCS / "networks" / f"{NETWORK_FILES[name]}.json").read_bytes()
    )


class PinnedAuthenticator:
    """Returns the expected payee and records which path the decoder chose."""

    def __init__(self, payee: str | None) -> None:
        self.payee = payee
        self.calls: list[tuple[str, bytes, bytes, Any]] = []

    def ecdsa_recover(self, message: bytes, signature: bytes, recovery_id: int) -> bytes:
        self.calls.append(("recover", message, signature, recovery_id))
        if self.payee is None:
            raise RuntimeError("native refusal")
        return bytes.fromhex(self.payee)

    def ecdsa_verify(self, public_key: bytes, message: bytes, signature: bytes) -> None:
        self.calls.append(("verify", message, signature, public_key))
        if self.payee is None:
            raise RuntimeError("native refusal")


def decoded_fields(invoice: str, crypto: PinnedAuthenticator) -> dict[str, Any]:
    value = decode_bolt11(invoice, crypto=crypto)
    return {
        "currency": value.currency,
        "amount_msat": None if value.amount_msat is None else str(value.amount_msat),
        "timestamp": value.timestamp,
        "payment_hash": value.payment_hash,
        "payment_secret": value.payment_secret,
        "payee": value.payee,
        "expiry_seconds": value.expiry_seconds,
        "min_final_cltv_delta": value.min_final_cltv_delta,
        "features": sorted(value.features),
        "blinded_paths": value.blinded_paths,
    }


CASES = [pytest.param(case, id=case["name"]) for case in VECTORS["cases"]]


@pytest.mark.parametrize("case", CASES)
def test_reader_and_admission_match_the_shared_vectors(case: dict[str, Any]) -> None:
    expected = case["decoded"]
    if expected.get("error") == SIGNATURE_INVALID:
        pytest.skip("signature validity needs libsecp256k1 (native contract test)")
    crypto = PinnedAuthenticator(expected.get("payee", "02" + "11" * 32))
    if "error" in expected:
        with pytest.raises(InvoiceRejectedError) as refused:
            decode_bolt11(case["invoice"], crypto=crypto)
        assert str(refused.value) == expected["error"]
    else:
        assert decoded_fields(case["invoice"], crypto) == expected
    for name, binding in case["bindings"].items():
        if "error" in binding:
            with pytest.raises(InvoiceRejectedError) as refused:
                invoice_binding(case["invoice"], network(name), crypto=crypto)
            assert str(refused.value) == binding["error"]
        else:
            admitted = invoice_binding(case["invoice"], network(name), crypto=crypto)
            assert admitted.model_dump(mode="json") == binding


def _case(name: str) -> dict[str, Any]:
    (case,) = (item for item in VECTORS["cases"] if item["name"] == name)
    return case


def test_an_explicit_payee_is_verified_and_never_recovered() -> None:
    case = _case("explicit payee with a low-S signature")
    crypto = PinnedAuthenticator(case["decoded"]["payee"])
    decode_bolt11(case["invoice"], crypto=crypto)
    ((kind, digest, signature, key),) = crypto.calls
    assert (kind, key.hex()) == ("verify", case["decoded"]["payee"])
    assert (len(digest), len(signature)) == (32, 64)


def test_without_a_payee_the_recovery_id_selects_the_key() -> None:
    plain, flipped = _case("regtest hold invoice"), _case("other recovery parity")
    ids = []
    for case in (plain, flipped):
        crypto = PinnedAuthenticator(case["decoded"]["payee"])
        decode_bolt11(case["invoice"], crypto=crypto)
        ((kind, _, _, recovery_id),) = crypto.calls
        assert kind == "recover"
        ids.append(recovery_id)
    assert ids[0] ^ ids[1] == 1


def test_every_native_refusal_and_a_large_recovery_id_are_one_rejection() -> None:
    for name in ("regtest hold invoice", "explicit payee with a low-S signature"):
        with pytest.raises(InvoiceRejectedError, match="signature invalid"):
            decode_bolt11(_case(name)["invoice"], crypto=PinnedAuthenticator(None))
    crypto = PinnedAuthenticator("02" + "11" * 32)
    with pytest.raises(InvoiceRejectedError, match="signature invalid"):
        decode_bolt11(_case("recovery id 4")["invoice"], crypto=crypto)
    assert crypto.calls == []


def test_admission_refuses_networks_outside_execution_policy() -> None:
    testnet3 = NetworkIdentity.model_validate_json((DOCS / "networks/testnet3.json").read_bytes())
    case = _case("testnet hold invoice")
    with pytest.raises(ValidationError, match="unsupported Bitcoin network identity"):
        invoice_binding(case["invoice"], testnet3, crypto=PinnedAuthenticator(None))


def test_rejections_are_validation_errors_and_inputs_must_be_strings() -> None:
    assert issubclass(InvoiceRejectedError, ValidationError)
    with pytest.raises(InvoiceRejectedError, match="length unsupported"):
        decode_bolt11("", crypto=PinnedAuthenticator(None))
    with pytest.raises(InvoiceRejectedError, match="length unsupported"):
        decode_bolt11(1234, crypto=PinnedAuthenticator(None))  # type: ignore[arg-type]


def _reported(name: str, **changes: Any) -> dict[str, Any]:  # noqa: ANN401
    """What an authenticating node (LND) reports for a vector, plus changes."""
    decoded = _case(name)["decoded"]
    facts = {
        "payment_hash": decoded["payment_hash"],
        "payment_secret": decoded["payment_secret"],
        "amount_msat": int(decoded["amount_msat"]),
        "payee": decoded["payee"],
        "timestamp": decoded["timestamp"],
        "expiry_seconds": decoded["expiry_seconds"],
        "min_final_cltv_delta": decoded["min_final_cltv_delta"],
        "features": frozenset(decoded["features"]),
        "blinded_paths": decoded["blinded_paths"],
    }
    return facts | changes


def test_wire_agreement_accepts_only_the_facts_the_bytes_carry() -> None:
    invoice = _case("regtest hold invoice")["invoice"]
    require_wire_agreement(invoice, **_reported("regtest hold invoice"))
    # Without an explicit n field the payee is the node's recovered key.
    require_wire_agreement(invoice, **_reported("regtest hold invoice", payee="02" + "11" * 32))
    for change in (
        {"payment_hash": "00" * 32},
        {"payment_secret": "00" * 32},
        {"amount_msat": 50_001_000},
        {"timestamp": 1_700_000_001},
        {"expiry_seconds": 3600},
        {"min_final_cltv_delta": 18},
        {"features": frozenset({8, 14})},
        {"blinded_paths": True},
    ):
        with pytest.raises(InvoiceRejectedError, match="decoders disagree"):
            require_wire_agreement(invoice, **_reported("regtest hold invoice", **change))


def test_wire_agreement_binds_an_explicit_payee() -> None:
    name = "explicit payee with a low-S signature"
    require_wire_agreement(_case(name)["invoice"], **_reported(name))
    with pytest.raises(InvoiceRejectedError, match="decoders disagree"):
        require_wire_agreement(_case(name)["invoice"], **_reported(name, payee="02" + "11" * 32))


def test_without_a_final_cltv_field_a_node_may_assume_only_a_larger_delta() -> None:
    name = "default expiry and final CLTV"
    invoice = _case(name)["invoice"]
    assert _case(name)["decoded"]["min_final_cltv_delta"] == 18  # BOLT 11 default
    for assumed in (18, 24, 144):  # LND v0.21 assumes 24
        require_wire_agreement(invoice, **_reported(name, min_final_cltv_delta=assumed))
    with pytest.raises(InvoiceRejectedError, match="decoders disagree"):
        require_wire_agreement(invoice, **_reported(name, min_final_cltv_delta=17))
    # The expiry default is not direction-safe: a longer one is refused.
    with pytest.raises(InvoiceRejectedError, match="decoders disagree"):
        require_wire_agreement(invoice, **_reported(name, expiry_seconds=3601))
    # An explicit c field is exact in both directions.
    explicit = "regtest hold invoice"
    delta = _case(explicit)["decoded"]["min_final_cltv_delta"]
    for wrong in (delta - 1, delta + 1):
        with pytest.raises(InvoiceRejectedError, match="decoders disagree"):
            require_wire_agreement(
                _case(explicit)["invoice"], **_reported(explicit, min_final_cltv_delta=wrong)
            )


@pytest.mark.parametrize(
    "name",
    [
        "two payment hashes",
        "duplicate payment secret",
        "duplicate expiry",
        "duplicate final CLTV",
        "duplicate explicit payee",
        "payment hash of 51 words",
        "payment secret of 53 words",
    ],
)
def test_wire_agreement_refuses_fields_a_first_wins_node_would_pick(name: str) -> None:
    # LND keeps the first occurrence (older LND also a second payment hash),
    # so it reports the ordinary invoice's facts; the reader refuses anyway.
    with pytest.raises(InvoiceRejectedError):
        require_wire_agreement(_case(name)["invoice"], **_reported("regtest hold invoice"))


def test_a_repeated_feature_field_stays_last_wins_but_cannot_disagree_with_a_node() -> None:
    name = "repeated feature field, last wins"
    invoice = _case(name)["invoice"]
    assert _case(name)["decoded"]["features"] == [8, 14, 17]  # the published v1 vector
    with pytest.raises(InvoiceRejectedError, match="decoders disagree"):
        # LND keeps the first 9 field: 8, 14 and the unknown even bit 100.
        require_wire_agreement(invoice, **_reported(name, features=frozenset({8, 14, 100})))
    require_wire_agreement(invoice, **_reported(name))


def _joined(separator: str) -> str:
    first = _case("regtest hold invoice")["invoice"]
    second = _case("explicit payee with a low-S signature")["invoice"]
    return first + separator + second


@pytest.mark.parametrize(
    "invoice",
    [
        _joined(""),
        _joined(" "),
        _joined(","),
        _joined("\n"),
        "lightning:" + _case("regtest hold invoice")["invoice"],
        _case("regtest hold invoice")["invoice"] + " ",
        " " + _case("regtest hold invoice")["invoice"],
        _case("regtest hold invoice")["invoice"] + "q",
    ],
    ids=["concatenated", "space", "comma", "newline", "uri", "trailing", "leading", "extra"],
)
def test_batched_or_wrapped_invoices_are_one_rejection_before_any_signature(invoice: str) -> None:
    crypto = PinnedAuthenticator(_case("regtest hold invoice")["decoded"]["payee"])
    with pytest.raises(InvoiceRejectedError):
        decode_bolt11(invoice, crypto=crypto)
    with pytest.raises(InvoiceRejectedError):
        require_wire_agreement(invoice, **_reported("regtest hold invoice"))
    for name in NETWORK_FILES:
        with pytest.raises(InvoiceRejectedError):
            invoice_binding(invoice, network(name), crypto=crypto)
    assert crypto.calls == []
