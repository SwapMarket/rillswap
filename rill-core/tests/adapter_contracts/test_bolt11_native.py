"""Opt-in: rill-core's BOLT 11 decoder with libsecp256k1 equals the browser decoder."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import TYPE_CHECKING, Any

import pytest

from rill_core.wire.bolt11 import (
    EcdsaAuthenticator,
    InvoiceRejectedError,
    decode_bolt11,
    invoice_binding,
)
from rill_core.wire.types import NetworkIdentity

if TYPE_CHECKING:
    from collections.abc import Callable

DOCS = Path(__file__).parents[3] / "rill-docs"
VECTORS = json.loads((DOCS / "vectors/bolt11/cases-v1.json").read_text())
NETWORK_FILES = {
    "mainnet": "mainnet",
    "testnet4": "testnet4",
    "signet": "signet",
    "regtest": "regtest-rillswap-e2e-v1",
}


@pytest.mark.native_crypto
@pytest.mark.skipif(
    os.environ.get("RILLSWAP_RUN_NATIVE_CRYPTO") != "1",
    reason="set RILLSWAP_RUN_NATIVE_CRYPTO=1 to run pinned native interoperability",
)
def test_every_shared_bolt11_vector_with_native_crypto() -> None:
    from rill_crypto import Context  # noqa: PLC0415

    networks = {
        name: NetworkIdentity.model_validate_json((DOCS / "networks" / f"{file}.json").read_bytes())
        for name, file in NETWORK_FILES.items()
    }
    with Context() as crypto:
        for case in VECTORS["cases"]:
            decoded = _outcome(lambda case=case: _decoded(case["invoice"], crypto))
            assert decoded == case["decoded"], case["name"]
            for name, binding in case["bindings"].items():
                admitted = _outcome(
                    lambda case=case, name=name: invoice_binding(
                        case["invoice"], networks[name], crypto=crypto
                    ).model_dump(mode="json")
                )
                assert admitted == binding, (case["name"], name)


def _outcome(run: Callable[[], dict[str, Any]]) -> dict[str, Any]:
    try:
        return run()
    except InvoiceRejectedError as error:
        return {"error": str(error)}


def _decoded(invoice: str, crypto: EcdsaAuthenticator) -> dict[str, Any]:
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
