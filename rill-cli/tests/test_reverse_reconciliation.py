"""Actual native claim correspondence with synthetic read transports/custody.

No historical vector is rewritten. These separately signed test-time packages
prove native composition, not actual LND/Core inclusion or key custody.
"""

from __future__ import annotations

import hashlib
import json
import os
import time
from dataclasses import replace
from importlib import import_module
from typing import TYPE_CHECKING, Any
from unittest.mock import Mock

import pytest
from pyrage import x25519
from rill_core.recovery.inspection import inspect_recovery_selected_funding_context
from rill_core.settlement import (
    FundingOutput,
    UnilateralAuthorization,
    build_cooperative_claim,
    build_unilateral_spend,
    finalize_cooperative_claim,
    finalize_unilateral_spend,
    reconstruct_taproot_contract,
)
from rill_core.wire.canonical import canonicalize
from rill_core.wire.hashes import (
    client_acceptance_hash,
    contract_hash,
    funding_binding_hash,
    provider_terms_hash,
)
from rill_core.wire.messages import ClientAcceptance, ContractTerms, FundingBinding, ProviderTerms
from rill_crypto import Context
from rill_provider.core_tx_bytes import CoreHistoricalTransaction, CoreSourceSnapshot
from rill_provider.lnd_treasury_observation import (
    LndCompletedPayment,
    LndTipClaim,
    LndTreasuryContext,
)

from rill_cli import reverse_reconciliation as module
from rill_cli.age_container import (
    X25519Credentials,
    encrypt_verified_plaintext,
    verify_export_ciphertext,
)
from rill_cli.conversion_journal import ConversionReceipt, PreparedConversion
from rill_cli.wallet_rpc import HistoricalWalletOutput

if TYPE_CHECKING:
    from collections.abc import Iterator
    from pathlib import Path

NATIVE = pytest.mark.skipif(
    os.environ.get("RILLSWAP_RUN_NATIVE_CRYPTO") != "1",
    reason="explicit native receipt conformance opt-in",
)
TIP_HASH, FUND_HASH, CLAIM_HASH = "a" * 64, "b" * 64, "c" * 64


class Case:
    def __init__(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, crypto: Context) -> None:  # noqa: PLR0915 - explicit newly signed native package and original journal checkpoint
        scaffolding = import_module("test_reverse_conversion")
        self.harness = scaffolding.Harness(tmp_path, monkeypatch)
        self.crypto = crypto
        self.now = float(scaffolding.NOW)
        monkeypatch.setattr(time, "time", lambda: self.now)
        monkeypatch.setattr(time, "monotonic", lambda: 100.0)
        authority = self.harness.authority
        identity = x25519.Identity.generate()
        self.credentials = X25519Credentials(str(identity.to_public()), str(identity))
        initial = json.loads(json.dumps(scaffolding.PACKAGE))
        initial["contract_terms"]["client_destination_script"] = authority.treasury_script
        terms = ContractTerms.model_validate_json(canonicalize(initial["contract_terms"]))
        initial["contract_hash"] = contract_hash(terms).hex()
        context = initial["verification_context"]
        init, accept = context["handshake_init"], context["handshake_accept"]
        provider = ProviderTerms(
            contract_hash=initial["contract_hash"],
            contract_terms=terms,
            handshake_hash=context["handshake_hash"],
        )
        client = ClientAcceptance(
            contract_hash=initial["contract_hash"],
            handshake_hash=context["handshake_hash"],
            session_id=init["session_id"],
            client_session_xonly_key=init["client_session_xonly_key"],
            provider_session_xonly_key=accept["provider_session_xonly_key"],
        )
        context["provider_terms_signature"] = crypto.schnorr_sign(
            (1).to_bytes(32, "big"), provider_terms_hash(provider), b"\x55" * 32
        ).hex()
        context["client_acceptance_signature"] = crypto.schnorr_sign(
            (8).to_bytes(32, "big"), client_acceptance_hash(client), b"\x56" * 32
        ).hex()
        self.initial = canonicalize(initial)
        self.terms = terms
        contract = reconstruct_taproot_contract(terms, keys=crypto)
        amount = int(terms.economics.contract_amount_sat)
        # Actual bounded serialization includes the explicitly declared anchor,
        # not the historical vector's synthetic funding txid.
        self.funding_raw = (
            b"\x02\x00\x00\x00\x01"
            + b"\xee" * 32
            + b"\x00" * 5
            + b"\xff" * 4
            + b"\x01"
            + amount.to_bytes(8, "little")
            + bytes([len(contract.script_pubkey)])
            + contract.script_pubkey
            + b"\x00" * 4
        )
        funding_txid = (
            hashlib.sha256(hashlib.sha256(self.funding_raw).digest()).digest()[::-1].hex()
        )
        self.binding = FundingBinding(
            contract_hash=initial["contract_hash"],
            funding_attempt_id="f" * 64,
            binding_revision=0,
            funder_role="provider",
            lineage_anchor_txid="ee" * 32,
            lineage_anchor_vout=0,
            funding_txid=funding_txid,
            contract_vout=0,
            contract_value_sat=str(amount),
            contract_script_pubkey=contract.script_pubkey.hex(),
            replaces_txid=None,
            created_at=int(self.now),
        )
        candidate = json.loads(self.initial)
        candidate["funding_history"] = [
            {
                "binding": self.binding.model_dump(mode="json"),
                "funder_session_signature": crypto.schnorr_sign(
                    (9).to_bytes(32, "big"), funding_binding_hash(self.binding), b"\x57" * 32
                ).hex(),
            }
        ]
        self.candidate = canonicalize(candidate)
        inspect_recovery_selected_funding_context(
            self.candidate,
            authority.network,
            funding_attempt_id=self.binding.funding_attempt_id,
            binding_revision=0,
            crypto=crypto,
        )
        self.candidate_path = tmp_path / "explicit-funded.age"
        self.candidate_path.write_bytes(
            encrypt_verified_plaintext(
                self.candidate, authority.network, credentials=self.credentials, crypto=crypto
            )
        )
        self.candidate_path.chmod(0o600)
        self.prepared = PreparedConversion(
            contract_hash=initial["contract_hash"],
            payment_hash=terms.invoice_binding.payment_hash,
            invoice_sha256=terms.invoice_binding.bolt11_sha256,
            invoice_amount_msat=int(terms.invoice_binding.amount_msat),
            routing_fee_ceiling_msat=1000000,
            minimum_net_output_sat=amount - int(terms.max_claim_fee_sat),
        )
        right = self.harness.journal.invoke(self.harness.reservation)
        ciphertext = encrypt_verified_plaintext(
            self.initial, authority.network, credentials=self.credentials, crypto=crypto
        )
        self.initial_path = self.harness.journal.checkpoint(
            right,
            self.prepared,
            ciphertext,
            verify_from_disk=lambda stored: verify_export_ciphertext(
                stored,
                self.initial,
                authority.network,
                credentials=self.credentials,
                crypto=crypto,
            ),
        )
        self.harness.journal.dispatch(right, self.prepared.payment_hash)
        self.authorization = UnilateralAuthorization.from_terms(
            terms,
            FundingOutput(bytes.fromhex(funding_txid), 0, amount, contract.script_pubkey),
            "claim",
            keys=crypto,
        )
        self.contract = contract
        self.core = Mock()
        self.wallet = Mock()
        self.payer = Mock()
        self.complete = Mock(side_effect=AssertionError("collector must never complete"))
        monkeypatch.setattr(self.harness.journal, "complete", self.complete)
        self.calls: list[tuple[str, object]] = []
        self.hashes = {970: FUND_HASH, 990: CLAIM_HASH, 1000: TIP_HASH}
        self.final_tip = (1000, TIP_HASH)
        self.after_source: Any = None
        self.core.observe_source.side_effect = self.source
        self.core.observe_block_transaction.side_effect = self.transaction
        self.wallet.observe_historical_wallet_output.side_effect = self.history
        self.context = LndTreasuryContext(
            authority.network,
            authority.source_node,
            "regtest",
            LndTipClaim(1000, TIP_HASH),
            LndTipClaim(1000, TIP_HASH),
        )
        self.payment = LndCompletedPayment(
            self.context, self.prepared.payment_hash, self.prepared.invoice_amount_msat, 1000
        )
        self.payer.observe_completed_payment.side_effect = lambda *_args, **_kwargs: self.payment

        def core_factory(**kwargs: Any) -> Mock:  # noqa: ANN401 - explicit concrete constructor correspondence
            assert kwargs == {
                "port": self.harness.config.core_port,
                "cookie_path": self.harness.config.core_cookie_path,
                "network": authority.network,
            }
            return self.core

        def wallet_factory(**kwargs: Any) -> Mock:  # noqa: ANN401 - explicit named wallet correspondence
            assert kwargs["network"] == authority.network
            assert kwargs["wallet"] == self.harness.config.core_wallet
            return self.wallet

        def payer_factory(**kwargs: Any) -> Mock:  # noqa: ANN401 - source/TLS/read credential pin
            assert kwargs["expected_node_pubkey"] == authority.source_node
            assert kwargs["network"] == authority.network
            assert kwargs["read_macaroon_path"] == self.harness.config.lnd_read_macaroon_path
            return self.payer

        monkeypatch.setattr(module, "CoreTransactionReader", core_factory)
        monkeypatch.setattr(module, "WalletRpc", wallet_factory)
        monkeypatch.setattr(module, "LndTreasuryObserver", payer_factory)
        self.set_path("unilateral")
        self.custody = module.DestinationCustody(
            network=authority.network,
            script=authority.treasury_script,
            core_wallet=self.harness.config.core_wallet,
            destination_keys_controlled=True,
        )
        self.job = self.harness.journal.status(self.harness.request.operation_id)

    def set_path(self, path: str) -> None:
        if path == "unilateral":
            plan = build_unilateral_spend(
                self.authorization, fee_sat=200, claim_preimage=b"\x52" * 32
            )
            signature = self.crypto.schnorr_sign(
                (10).to_bytes(32, "big"), plan.signature_hash, b"\x61" * 32
            )
            claim = finalize_unilateral_spend(plan, signature, verifier=self.crypto)
        else:
            cooperative_plan = build_cooperative_claim(self.authorization, fee_sat=200)
            session = {
                "user_public_key": bytes.fromhex(self.terms.client_contract_compressed_key),
                "provider_public_key": bytes.fromhex(self.terms.provider_contract_compressed_key),
                "tap_tweak": self.contract.tap_tweak,
                "message": cooperative_plan.signature_hash,
            }
            user_attempt, user_nonce = self.crypto.musig_begin(
                secret_key=(10).to_bytes(32, "big"), cooperation_id=b"\x62" * 32, **session
            )
            provider_attempt, provider_nonce = self.crypto.musig_begin(
                secret_key=(11).to_bytes(32, "big"), cooperation_id=b"\x62" * 32, **session
            )
            with user_attempt, provider_attempt:
                user_partial = user_attempt.partial_sign_once(provider_nonce)
                provider_partial = provider_attempt.partial_sign_once(user_nonce)
                signature = self.crypto.musig_aggregate(
                    user_partial_signature=user_partial,
                    provider_partial_signature=provider_partial,
                    user_public_nonce=user_nonce,
                    provider_public_nonce=provider_nonce,
                    **session,
                )
            cooperative_claim = finalize_cooperative_claim(
                cooperative_plan, signature, verifier=self.crypto
            )
        self.path = path
        self.claim = claim if path == "unilateral" else cooperative_claim
        self.signature = signature

    def transaction(
        self, txid: str, *, block_height: int, block_hash: str, deadline_seconds: float
    ) -> CoreHistoricalTransaction:
        assert 0 < deadline_seconds <= 10
        self.calls.append(("bytes", txid))
        raw = self.funding_raw if txid == self.binding.funding_txid else self.claim.raw_transaction
        return CoreHistoricalTransaction(
            self.harness.authority.network,
            raw,
            txid,
            block_height,
            block_hash,
            1000,
            TIP_HASH,
            1000,
            TIP_HASH,
            1000 - block_height + 1,
            self.now,
            self.now,
        )

    def history(
        self, txid: str, script: bytes, *, deadline_seconds: float
    ) -> HistoricalWalletOutput:
        assert txid == self.claim.txid
        assert script.hex() == self.harness.authority.treasury_script
        assert 0 < deadline_seconds <= 10
        return HistoricalWalletOutput(
            self.harness.authority.network,
            txid,
            0,
            int(self.terms.economics.contract_amount_sat) - self.claim.fee_sat,
            script,
            11,
            990,
            CLAIM_HASH,
            self.now,
            self.now,
        )

    def source(self, height: int, *, deadline_seconds: float) -> CoreSourceSnapshot:
        assert 0 < deadline_seconds <= 10
        self.calls.append(("source", height))
        if self.after_source is not None:
            self.after_source()
        return CoreSourceSnapshot(
            self.harness.authority.network,
            "regtest",
            self.harness.authority.network.genesis_hash,
            None,
            self.final_tip[0],
            self.final_tip[1],
            height,
            self.hashes[height],
        )

    def collect(self, **changes: Any) -> ConversionReceipt:  # noqa: ANN401 - explicit runtime parameter fault matrix
        arguments = {
            "config": self.harness.config,
            "credentials": self.credentials,
            "crypto": self.crypto,
            "funding_recovery_path": self.candidate_path,
            "funding_attempt_id": self.binding.funding_attempt_id,
            "binding_revision": 0,
            "funding_block": module.BlockHint(height=970, block_hash=FUND_HASH),
            "claim_txid": self.claim.txid,
            "claim_path": self.path,
            "custody": self.custody,
        } | changes
        return module.collect_conversion_receipt(
            self.harness.journal, self.harness.request.operation_id, **arguments
        )


@pytest.fixture
def case(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Case]:
    with Context(library_path=os.environ["RILL_CRYPTO_LIBRARY"]) as crypto:
        yield Case(tmp_path, monkeypatch, crypto)


def refused(case: Case, **changes: Any) -> None:  # noqa: ANN401 - explicit malformed input matrix
    with pytest.raises(module.ReverseReconciliationError) as failure:
        case.collect(**changes)
    assert str(failure.value) == "historical conversion receipt unavailable"
    assert failure.value.__cause__ is None
    assert failure.value.__context__ is None
    case.complete.assert_not_called()


@pytest.mark.native_crypto
@NATIVE
@pytest.mark.parametrize("path", ["unilateral", "cooperative"])
def test_actual_native_original_funding_and_claim_receipt_never_completes(
    case: Case, path: str
) -> None:
    case.set_path(path)
    result = case.collect()
    assert result.payment_hash == case.prepared.payment_hash
    assert result.invoice_sha256 == case.prepared.invoice_sha256
    assert result.amount_msat == case.prepared.invoice_amount_msat
    assert result.routing_fee_msat == 1000
    assert result.destination_txid == case.claim.txid
    assert result.destination_vout == 0
    assert result.destination_value_sat == 100300
    assert result.confirmation_blocks == 11
    assert {value for kind, value in case.calls if kind == "source"} == {970, 990, 1000}
    assert case.harness.journal.status(case.harness.request.operation_id) == case.job
    case.complete.assert_not_called()


@pytest.mark.native_crypto
@NATIVE
def test_expired_original_approval_and_invoice_do_not_grant_retry_or_forbid_history(
    case: Case,
) -> None:
    case.now += 10000
    assert case.collect().destination_txid == case.claim.txid
    case.complete.assert_not_called()


@pytest.mark.native_crypto
@NATIVE
@pytest.mark.parametrize(
    "fault",
    [
        "unrelated_deposit",
        "funding_bytes",
        "claim_signature",
        "recovery_anchor",
        "private_mode",
        "missing_candidate",
        "source_hash",
        "source_node",
        "source_fee",
        "prepared_hash",
        "prepared_invoice",
        "prepared_net",
        "history_script",
        "insufficient_depth",
        "funding_after_claim",
        "candidate_secret_error",
        "clock_rollback",
        "final_source_fork",
        "final_claim_fork",
        "tip_movement",
        "generation_changed",
        "late",
        "wrong_custody",
        "wrong_path",
    ],
)
def test_native_composition_refuses_unrelated_private_or_contradictory_evidence(  # noqa: PLR0912, PLR0915 - explicit independent financial fault matrix
    case: Case, monkeypatch: pytest.MonkeyPatch, fault: str
) -> None:
    changes: dict[str, Any] = {}
    if fault == "unrelated_deposit":
        # Native-valid claim to the same script/value, but a different prevout.
        # All raw-byte identifiers/history correspond; only selected authority
        # rejects this genuinely unrelated receipt.
        case.authorization = UnilateralAuthorization.from_terms(
            case.terms,
            FundingOutput(
                bytes.fromhex("ee" * 32),
                0,
                int(case.terms.economics.contract_amount_sat),
                case.contract.script_pubkey,
            ),
            "claim",
            keys=case.crypto,
        )
        case.set_path("unilateral")
    elif fault == "funding_bytes":
        case.funding_raw = case.funding_raw[:-4] + b"\x01\x00\x00\x00"
    elif fault == "claim_signature":
        original = case.transaction
        signature_offset = case.claim.raw_transaction.index(case.signature)
        mutated = bytearray(case.claim.raw_transaction)
        mutated[signature_offset] ^= 1
        case.core.observe_block_transaction.side_effect = lambda txid, **kwargs: (
            replace(
                original(txid, **kwargs),
                raw_transaction=bytes(mutated),
            )
            if txid == case.claim.txid
            else original(txid, **kwargs)
        )
    elif fault == "recovery_anchor":
        case.initial_path.write_bytes(b"SECRET_CANARY")
    elif fault == "private_mode":
        case.candidate_path.chmod(0o644)
    elif fault == "missing_candidate":
        case.candidate_path.unlink()
    elif fault == "source_hash":
        case.payment = replace(case.payment, payment_hash="f" * 64)
    elif fault == "source_node":
        case.payment = replace(
            case.payment, context=replace(case.context, observed_node_pubkey="02" + "f" * 64)
        )
    elif fault == "source_fee":
        case.payment = replace(case.payment, routing_fee_msat=1000001)
    elif fault in {"prepared_hash", "prepared_invoice", "prepared_net"}:
        changes_by_fault: dict[str, dict[str, object]] = {
            "prepared_hash": {"contract_hash": "f" * 64},
            "prepared_invoice": {"invoice_sha256": "f" * 64},
            "prepared_net": {"minimum_net_output_sat": 1},
        }
        updates = changes_by_fault[fault]
        modified = case.job.model_copy(
            update={"prepared": case.prepared.model_copy(update=updates)}
        )
        monkeypatch.setattr(case.harness.journal, "status", lambda _operation: modified)
    elif fault == "history_script":
        original_history = case.history
        case.wallet.observe_historical_wallet_output.side_effect = lambda *args, **kwargs: replace(
            original_history(*args, **kwargs), script_pubkey=bytes.fromhex("5120" + "f" * 64)
        )
    elif fault == "insufficient_depth":
        original_history = case.history
        case.wallet.observe_historical_wallet_output.side_effect = lambda *args, **kwargs: replace(
            original_history(*args, **kwargs), confirmations=0
        )
    elif fault == "funding_after_claim":
        changes["funding_block"] = module.BlockHint(height=991, block_hash=FUND_HASH)
    elif fault == "candidate_secret_error":
        case.candidate_path.write_bytes(b"SECRET_CANARY")
    elif fault == "clock_rollback":
        case.after_source = lambda: setattr(case, "now", case.now - 1)
    elif fault == "final_source_fork":
        case.hashes[1000] = "e" * 64
    elif fault == "final_claim_fork":
        case.hashes[990] = "e" * 64
    elif fault == "tip_movement":

        def move() -> None:
            if len([item for item in case.calls if item[0] == "source"]) > 1:
                case.final_tip = (1001, "e" * 64)

        case.after_source = move
    elif fault == "generation_changed":
        query = case.harness.journal.begin_capacity_query()
        monkeypatch.setattr(
            case.harness.journal,
            "begin_capacity_query",
            Mock(
                side_effect=[query, query.model_copy(update={"generation": query.generation + 1})]
            ),
        )
    elif fault == "late":
        case.after_source = lambda: monkeypatch.setattr(time, "monotonic", lambda: 130.0)
    elif fault == "wrong_custody":
        changes["custody"] = case.custody.model_copy(update={"core_wallet": "public-only"})
    else:
        changes["claim_path"] = "refund"
    refused(case, **changes)


@pytest.mark.parametrize("assertion", [False, 1, "true", None])
def test_destination_custody_assertions_never_coerce_wallet_recognition(assertion: object) -> None:
    scaffolding = import_module("test_reverse_conversion")
    with pytest.raises(ValueError, match="independently established destination keys required"):
        module.DestinationCustody(
            network=scaffolding.TERMS.network_identity,
            script="5120" + "a" * 64,
            core_wallet="merchant",
            destination_keys_controlled=assertion,  # type: ignore[arg-type]
        )


@pytest.mark.parametrize("budget", [0, True, 31, float("nan"), float("inf"), 10**1000])
def test_invalid_total_budget_never_queries_journal_or_observes(budget: float) -> None:
    journal = Mock()
    with pytest.raises(module.ReverseReconciliationError):
        module.collect_conversion_receipt(
            journal,
            "conversion_wrong01",
            config=Mock(),
            credentials=Mock(),
            crypto=Mock(),
            funding_recovery_path=Mock(),
            funding_attempt_id="f" * 64,
            binding_revision=0,
            funding_block=Mock(),
            claim_txid="f" * 64,
            claim_path="cooperative",
            custody=Mock(),
            deadline_seconds=budget,
        )
    journal.begin_capacity_query.assert_not_called()
