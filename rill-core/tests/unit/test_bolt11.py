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
from rill_core.wire.bolt11 import InvoiceRejectedError, decode_bolt11, invoice_binding
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
