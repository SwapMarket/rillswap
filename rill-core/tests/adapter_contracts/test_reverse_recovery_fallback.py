"""Native private reverse fallback evidence never becomes disclosure authority."""

from __future__ import annotations

import copy
import json
import os
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

from rill_core.errors import ValidationError
from rill_core.recovery import (
    construct_selected_recovery_claim,
    inspect_recovery_plaintext,
    inspect_recovery_recorded_claim_txid,
    inspect_recovery_successor,
)
from rill_core.recovery.inspection import REVERSE_FALLBACK_EXTENSION
from rill_core.settlement import (
    FundingOutput,
    UnilateralAuthorization,
    build_unilateral_spend,
    finalize_unilateral_spend,
    validate_unilateral_spend,
)
from rill_core.wire.canonical import canonicalize
from rill_core.wire.hashes import funding_binding_hash
from rill_core.wire.messages import ContractTerms, FundingBinding
from rill_core.wire.types import NetworkIdentity

if TYPE_CHECKING:
    from collections.abc import Iterator

    from rill_crypto import Context

pytestmark = [
    pytest.mark.native_crypto,
    pytest.mark.skipif(
        os.environ.get("RILLSWAP_RUN_NATIVE_CRYPTO") != "1",
        reason="set RILLSWAP_RUN_NATIVE_CRYPTO=1 for native reverse fallback verification",
    ),
]
FIXTURES = Path(__file__).parents[1] / "fixtures" / "recovery-v1"


class PreparedFallback:
    def __init__(self, crypto: Context) -> None:
        self.crypto = crypto
        self.prior = json.loads((FIXTURES / "initial-ln-to-btc-no-prepayment-v1.json").read_bytes())
        self.prior["extensions"]["test/opaque"] = {"retain": [1, "exact"]}
        self.network = NetworkIdentity.model_validate(self.prior["network_identity"])
        self.terms = ContractTerms.model_validate_json(canonicalize(self.prior["contract_terms"]))
        self.binding = FundingBinding(
            contract_hash=self.prior["contract_hash"],
            funding_attempt_id="cc" * 32,
            binding_revision=0,
            funder_role="provider",
            lineage_anchor_txid="dd" * 32,
            lineage_anchor_vout=1,
            funding_txid="aa" * 32,
            contract_vout=0,
            contract_value_sat=self.terms.economics.contract_amount_sat,
            contract_script_pubkey=self.prior["taproot_contract"]["script_pubkey"],
            replaces_txid=None,
            created_at=self.prior["updated_at"],
        )
        self.append(self.prior, self.binding)
        funding = FundingOutput(
            bytes.fromhex(self.binding.funding_txid),
            self.binding.contract_vout,
            int(self.binding.contract_value_sat),
            bytes.fromhex(self.binding.contract_script_pubkey),
        )
        self.authorization = UnilateralAuthorization.from_terms(
            self.terms, funding, "claim", keys=crypto
        )
        self.plan = build_unilateral_spend(
            self.authorization,
            fee_sat=200,
            claim_preimage=bytes.fromhex(self.prior["monotonic_knowledge"]["preimage"]),
        )
        self.signature = crypto.schnorr_sign(
            bytes.fromhex(self.prior["user_secret"]["contract_secret_key"]),
            self.plan.signature_hash,
            b"\x55" * 32,
        )
        self.raw = finalize_unilateral_spend(
            self.plan, self.signature, verifier=crypto
        ).raw_transaction
        self.next = copy.deepcopy(self.prior)
        self.next["extensions"][REVERSE_FALLBACK_EXTENSION] = {
            "version": 1,
            "funding_binding_hash": funding_binding_hash(self.binding).hex(),
            "transaction": self.raw.hex(),
        }

    def append(self, document: dict, binding: FundingBinding) -> None:
        document["funding_history"].append(
            {
                "binding": binding.model_dump(mode="json"),
                "funder_session_signature": self.crypto.schnorr_sign(
                    (9).to_bytes(32, "big"), funding_binding_hash(binding), b"\x31" * 32
                ).hex(),
            }
        )

    def inspect(self, document: dict) -> object:
        return inspect_recovery_plaintext(canonicalize(document), self.network, crypto=self.crypto)

    def successor(self, previous: dict, candidate: dict) -> object:
        return inspect_recovery_successor(
            canonicalize(previous), canonicalize(candidate), self.network, crypto=self.crypto
        )


@pytest.fixture
def fallback() -> Iterator[PreparedFallback]:
    from rill_crypto import Context  # noqa: PLC0415 - opt-in native dependency

    with Context(library_path=os.environ["RILL_CRYPTO_LIBRARY"]) as crypto:
        yield PreparedFallback(crypto)


@pytest.mark.parametrize("issued", [False, True])
def test_private_preparation_preserves_both_issuance_flags_and_independent_recovery(
    fallback: PreparedFallback,
    *,
    issued: bool,
) -> None:
    fallback.prior["monotonic_knowledge"]["dangerous_signature_issued"] = issued
    fallback.next["monotonic_knowledge"]["dangerous_signature_issued"] = issued
    old = fallback.inspect(fallback.prior)
    new = fallback.successor(fallback.prior, fallback.next)
    assert old == new  # Prepared evidence adds no redacted authority assertion.
    assert canonicalize(fallback.prior["user_secret"]) == canonicalize(fallback.next["user_secret"])
    assert fallback.prior["extensions"]["test/opaque"] == fallback.next["extensions"]["test/opaque"]
    assert fallback.next["monotonic_knowledge"]["dangerous_signature_issued"] is issued
    assert fallback.prior["monotonic_knowledge"]["preimage"] in fallback.raw.hex()


@pytest.mark.parametrize(
    "case",
    [
        "signature",
        "preimage",
        "outpoint",
        "destination",
        "control block",
        "fee",
        "wrong key",
        "binding hash",
        "empty history",
        "duplicate binding",
        "forward role",
        "odd hex",
        "upper hex",
        "partial",
        "version",
        "boolean version",
        "extra field",
    ],
)
def test_invalid_reverse_fallback_is_refused_with_native_verification_and_redacted_errors(  # noqa: PLR0912 - distinct adversarial mutations of one signed record
    fallback: PreparedFallback,
    case: str,
) -> None:
    document = copy.deepcopy(fallback.next)
    marker = document["extensions"][REVERSE_FALLBACK_EXTENSION]
    raw = bytearray(fallback.raw)
    if case in {"signature", "preimage", "control block"}:
        needle = {
            "signature": fallback.signature,
            "preimage": bytes.fromhex(fallback.prior["monotonic_knowledge"]["preimage"]),
            "control block": bytes.fromhex(
                fallback.prior["taproot_contract"]["claim_control_block"]
            ),
        }[case]
        raw[raw.index(needle)] ^= 1
        marker["transaction"] = raw.hex()
    elif case == "outpoint":
        raw[6] ^= 1
        marker["transaction"] = raw.hex()
    elif case == "destination":
        needle = bytes.fromhex(fallback.terms.client_destination_script)
        raw[raw.index(needle) + len(needle) - 1] ^= 1
        marker["transaction"] = raw.hex()
    elif case == "fee":
        value = int(fallback.binding.contract_value_sat) - 200
        start = raw.index(value.to_bytes(8, "little"))
        raw[start : start + 8] = (
            int(fallback.binding.contract_value_sat) - int(fallback.terms.max_claim_fee_sat) - 1
        ).to_bytes(8, "little")
        marker["transaction"] = raw.hex()
    elif case == "wrong key":
        wrong_signature = fallback.crypto.schnorr_sign(
            (9).to_bytes(32, "big"), fallback.plan.signature_hash, b"\x55" * 32
        )
        marker["transaction"] = fallback.raw.replace(fallback.signature, wrong_signature).hex()
    elif case == "binding hash":
        marker["funding_binding_hash"] = "bb" * 32
    elif case == "empty history":
        document["funding_history"] = []
    elif case == "duplicate binding":
        document["funding_history"] *= 2
    elif case == "forward role":
        document = json.loads((FIXTURES / "initial-btc-to-ln-v1.json").read_bytes())
        document["extensions"][REVERSE_FALLBACK_EXTENSION] = marker
    elif case == "odd hex":
        marker["transaction"] = marker["transaction"][:-1]
    elif case == "upper hex":
        marker["transaction"] = marker["transaction"].upper()
    elif case == "partial":
        del marker["transaction"]
    elif case == "version":
        marker["version"] = 2
    elif case == "boolean version":
        marker["version"] = True
    else:
        marker["unknown"] = 1
    with pytest.raises(ValidationError, match="invalid or unsupported recovery plaintext") as error:
        fallback.inspect(document)
    assert error.value.__context__ is None
    assert fallback.prior["monotonic_knowledge"]["preimage"] not in str(error.value)
    assert fallback.prior["user_secret"]["contract_secret_key"] not in str(error.value)


@pytest.mark.parametrize(
    "change", ["remove", "replace", "opaque", "issuance knowledge", "funding at insertion"]
)
def test_fallback_successors_are_append_once_and_preserve_prior_state(
    fallback: PreparedFallback,
    change: str,
) -> None:
    previous, candidate = copy.deepcopy(fallback.next), copy.deepcopy(fallback.next)
    if change == "remove":
        del candidate["extensions"][REVERSE_FALLBACK_EXTENSION]
    elif change == "replace":
        plan = build_unilateral_spend(
            fallback.authorization,
            fee_sat=201,
            claim_preimage=bytes.fromhex(fallback.prior["monotonic_knowledge"]["preimage"]),
        )
        signature = fallback.crypto.schnorr_sign(
            bytes.fromhex(fallback.prior["user_secret"]["contract_secret_key"]),
            plan.signature_hash,
            b"\x66" * 32,
        )
        candidate["extensions"][REVERSE_FALLBACK_EXTENSION]["transaction"] = (
            finalize_unilateral_spend(
                plan, signature, verifier=fallback.crypto
            ).raw_transaction.hex()
        )
        fallback.inspect(candidate)  # Both records individually valid, but replacement is not.
    elif change == "opaque":
        candidate["extensions"]["test/opaque"] = "changed"
    elif change == "issuance knowledge":
        previous = fallback.prior
        candidate["monotonic_knowledge"]["dangerous_signature_issued"] = True
    else:
        previous = copy.deepcopy(fallback.prior)
        previous["funding_history"] = []
    with pytest.raises(ValidationError, match="nonmonotonic recovery successor"):
        fallback.successor(previous, candidate)


def test_historical_fallback_survives_later_binding_but_cannot_be_inserted_for_it(
    fallback: PreparedFallback,
) -> None:
    candidate = copy.deepcopy(fallback.next)
    later = fallback.binding.model_copy(
        update={
            "binding_revision": 1,
            "funding_txid": "bb" * 32,
            "replaces_txid": fallback.binding.funding_txid,
            "created_at": fallback.binding.created_at + 1,
        }
    )
    fallback.append(candidate, later)
    candidate["updated_at"] += (
        100_000_000  # Inspection must not infer expiry/reorg/payment authority.
    )
    assert fallback.successor(fallback.next, candidate).recorded_binding_count == 2
    predecessor = copy.deepcopy(candidate)
    del predecessor["extensions"][REVERSE_FALLBACK_EXTENSION]
    fallback.inspect(predecessor)
    fallback.inspect(candidate)
    with pytest.raises(ValidationError, match="nonmonotonic recovery successor"):
        fallback.successor(predecessor, candidate)
    # A retained historical fixed-fee transaction must never become the sole
    # recovery path. Reconstruct using the preserved key for the replacement.
    replacement_funding = FundingOutput(
        bytes.fromhex(later.funding_txid),
        later.contract_vout,
        int(later.contract_value_sat),
        bytes.fromhex(later.contract_script_pubkey),
    )
    rebuilt = construct_selected_recovery_claim(
        canonicalize(candidate),
        fallback.network,
        funding_attempt_id=later.funding_attempt_id,
        binding_revision=later.binding_revision,
        live_funding=replacement_funding,
        sampled_tip_height=100,
        sampled_confirmations=2,
        fee_sat=201,
        auxiliary_random=b"\x77" * 32,
        crypto=fallback.crypto,
    )
    replacement_authorization = UnilateralAuthorization.from_terms(
        fallback.terms,
        replacement_funding,
        "claim",
        keys=fallback.crypto,
    )
    validated = validate_unilateral_spend(
        rebuilt, replacement_authorization, verifier=fallback.crypto
    )
    assert validated.fee_sat == 201
    assert validated.raw_transaction == rebuilt != fallback.raw
    assert candidate["extensions"][REVERSE_FALLBACK_EXTENSION]["transaction"] == fallback.raw.hex()


def test_duplicate_keys_in_fallback_are_not_accepted(fallback: PreparedFallback) -> None:
    canonical = canonicalize(fallback.next)
    raw = canonical.replace(b'"version":1', b'"version":1,"version":1')
    assert raw != canonical
    with pytest.raises(ValidationError, match="invalid or unsupported recovery plaintext"):
        inspect_recovery_plaintext(raw, fallback.network, crypto=fallback.crypto)


def test_recorded_claim_txid_is_named_only_for_its_own_binding(
    fallback: PreparedFallback,
) -> None:
    def recorded(document: dict, revision: int) -> str | None:
        return inspect_recovery_recorded_claim_txid(
            canonicalize(document),
            fallback.network,
            funding_attempt_id="cc" * 32,
            binding_revision=revision,
            crypto=fallback.crypto,
        )

    expected = validate_unilateral_spend(
        fallback.raw, fallback.authorization, verifier=fallback.crypto
    ).txid
    assert recorded(fallback.next, 0) == expected
    assert recorded(fallback.prior, 0) is None  # nothing prepared
    later = fallback.binding.model_copy(
        update={
            "binding_revision": 1,
            "funding_txid": "bb" * 32,
            "replaces_txid": fallback.binding.funding_txid,
            "created_at": fallback.binding.created_at + 1,
        }
    )
    fallback.append(fallback.next, later)
    assert recorded(fallback.next, 1) is None  # prepared for another binding
    assert recorded(fallback.next, 0) == expected
    with pytest.raises(
        ValidationError, match="invalid or unavailable recovery funding context"
    ) as error:
        recorded(fallback.next, 2)  # no such binding
    assert error.value.__context__ is None
