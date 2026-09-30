"""Actual forward funding and native owner, with feature negotiation stubbed."""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import threading
from dataclasses import replace
from typing import TYPE_CHECKING
from unittest.mock import AsyncMock, Mock

import pytest
from rill_core.settlement import FundingBindingTransactionMatch, reconstruct_taproot_contract
from rill_core.settlement.unilateral import (
    FundingOutput,
    UnilateralAuthorization,
    build_cooperative_claim,
)
from rill_core.wire.canonical import canonicalize
from rill_core.wire.hashes import provider_terms_hash
from rill_core.wire.messages import (
    ContractTerms,
    Envelope,
    HandshakeAccept,
    HandshakeInit,
    ProviderTerms,
)
from rill_core.wire.quotes import TermsOfferPayload
from rill_crypto import Context
from rill_provider.core_tx_bytes import CooperativeClaimOutpoint, CooperativeFeePolicy
from test_cooperative_client_attempt import Harness
from test_cooperative_reservation_publication import LIBRARY, _credentials, _snapshots
from test_live_swap import FakeWallet

from rill_cli import live_swap, swap_command
from rill_cli.live_swap import (
    SwapError,
    SwapLimits,
    SwapOutcome,
    _drain_cooperative_workers,
    _Session,
    run_swap,
)
from rill_cli.publication import RecoveryPublicationUncertainError
from rill_cli.wallet_rpc import CooperativeClaimEvidence

if TYPE_CHECKING:
    from pathlib import Path

INVOICE = "lnbcrt500u1pclientexample"


class Forward(Harness):
    """Reuse the exact native signing producer, not its prepublished snapshots.

    Discovery/handshake are stubbed. Funding, signed acceptance/binding,
    recovery encryption/readback, FIFO, and the client owner remain real.
    """

    def __init__(self, crypto: Context, path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        self.crypto, self.path = crypto, path
        initial, _, _, reserved = _snapshots(crypto)
        self.initial = initial
        self.funded = initial
        terms = ContractTerms.model_validate_json(canonicalize(initial["contract_terms"]))
        self.terms = terms.model_copy(
            update={
                "invoice_binding": terms.invoice_binding.model_copy(
                    update={
                        "bolt11_sha256": hashlib.sha256(INVOICE.encode()).hexdigest(),
                    }
                )
            }
        )
        context = initial["verification_context"]
        self.init = HandshakeInit.model_validate_json(canonicalize(context["handshake_init"]))
        self.accept = HandshakeAccept.model_validate_json(canonicalize(context["handshake_accept"]))
        self.offer_terms = ProviderTerms(
            contract_hash=live_swap.contract_hash(self.terms).hex(),
            contract_terms=self.terms,
            handshake_hash=context["handshake_hash"],
        )
        self.offer = TermsOfferPayload(
            terms=self.offer_terms,
            provider_terms_signature=crypto.schnorr_sign(
                (1).to_bytes(32, "big"), provider_terms_hash(self.offer_terms), b"\x55" * 32
            ).hex(),
        )
        self.credentials = _credentials()
        self.output = path / "forward.age"
        self.events = []
        self.sent = []
        self.documents: list[bytes] = []
        self.session = _Session(Mock(), crypto, self.terms.network_identity, timeout=1)
        self.session.secret = (2).to_bytes(32, "big")
        self.session.key = crypto.public_key(self.session.secret)[1:].hex()
        self.session.session_id = self.init.session_id
        self.session.provider_key = self.accept.provider_session_xonly_key
        self.session._provider_next = 1  # noqa: SLF001 - fixture begins after handshake
        self.proposal_template = Envelope.model_validate_json(
            canonicalize(
                reserved["extensions"][live_swap.COOPERATIVE_RESERVATION_EXTENSION]["proposal"]
            )
        )
        wallet = FakeWallet()
        self.wallet = Mock(wraps=wallet, observe_cooperative_claim_evidence=Mock())
        self.wallet.tip_height.return_value = self.terms.refund_lock_height - 100
        self.wallet.new_destination_script.return_value = bytes.fromhex(
            self.terms.client_destination_script
        )
        self.wallet.observe_cooperative_claim_evidence.side_effect = lambda *_args, **_kwargs: (
            self.sample
        )
        self.loop = asyncio.get_running_loop()
        self.wallet.broadcast.side_effect = lambda raw: (
            self.loop.call_soon_threadsafe(self.start),
            wallet.broadcast(raw),
        )[1]
        self.broadcasts = wallet.broadcasts

        async def handshake(_session: _Session, *_args: object) -> tuple:
            assert _session is self.session
            return (
                self.init,
                self.accept,
                context["provider_identity_signature"],
                context["handshake_hash"],
            )

        async def reply(_request: Envelope, kind: str) -> Envelope:
            return self.proposal_template.model_copy(
                update={
                    "message_type": kind,
                    "payload": self.offer.model_dump(mode="json") if kind == "terms_offer" else {},
                }
            )

        async def send(message: Envelope, recipient: str) -> None:
            if message.message_type == "action_result":
                await Harness.send(self, message, recipient)

        self.session.send = send
        self.session.reply_to = reply
        monkeypatch.setattr(live_swap, "_Session", lambda *_args, **_kwargs: self.session)
        monkeypatch.setattr(live_swap, "_handshake", handshake)
        monkeypatch.setattr(live_swap, "discover", AsyncMock())
        monkeypatch.setattr(live_swap, "_check_offer", lambda *_args, **_kwargs: self.terms)
        scalars = iter((4, 6))
        monkeypatch.setattr(
            live_swap,
            "_scalar",
            lambda _crypto: (
                (value := next(scalars)).to_bytes(32, "big"),
                crypto.public_key(value.to_bytes(32, "big")),
            ),
        )
        monkeypatch.setattr(live_swap.time, "time", lambda: initial["updated_at"])
        monkeypatch.setattr(
            live_swap,
            "_wait_for_payment",
            AsyncMock(side_effect=AssertionError("no second settlement consumer")),
        )

    def write(self, candidate: bytes, previous: bytes | None) -> None:
        self.documents.append(candidate)
        swap_command._write_recovery_snapshot(  # noqa: SLF001 - actual create-only encrypted publication
            self.output,
            candidate,
            previous,
            self.terms.network_identity,
            credentials=self.credentials,
            crypto=self.crypto,
        )
        record = json.loads(candidate)
        if record["funding_history"] and not record["monotonic_knowledge"]["preimage_known"]:
            self.funded = record
            self.prepare(record)

    def prepare(self, record: dict) -> None:
        binding = record["funding_history"][-1]["binding"]
        funding = FundingOutput(
            bytes.fromhex(binding["funding_txid"]),
            binding["contract_vout"],
            int(binding["contract_value_sat"]),
            bytes.fromhex(binding["contract_script_pubkey"]),
        )
        self.plan = build_cooperative_claim(
            UnilateralAuthorization.from_terms(self.terms, funding, "claim", keys=self.crypto),
            fee_sat=300,
        )
        artifacts = reconstruct_taproot_contract(self.terms, keys=self.crypto)
        self.provider_attempt, nonce = self.crypto.musig_begin(
            secret_key=(5).to_bytes(32, "big"),
            user_public_key=bytes.fromhex(self.terms.client_contract_compressed_key),
            provider_public_key=bytes.fromhex(self.terms.provider_contract_compressed_key),
            tap_tweak=artifacts.tap_tweak,
            message=self.plan.signature_hash,
            cooperation_id=b"\xbb" * 32,
        )
        payload = {
            **self.proposal_template.payload,
            "unsigned_transaction": self.plan.base_transaction.hex(),
            "public_nonce": nonce.hex(),
        }
        self.proposal = self.sign(
            self.proposal_template.model_copy(
                update={"sequence": 2, "contract_hash": record["contract_hash"], "payload": payload}
            )
        )
        self.ready = self.sign(
            self.proposal.model_copy(
                update={
                    "sequence": 1,
                    "message_id": "cc" * 32,
                    "payload": {
                        "action": "cooperative_claim_ready",
                        "challenge": "dd" * 32,
                        "payment_preimage": payload["payment_preimage"],
                        "deadline_at": payload["deadline_at"],
                        "deadline_height": payload["deadline_height"],
                    },
                }
            )
        )
        self.public = {
            "user_public_key": bytes.fromhex(self.terms.client_contract_compressed_key),
            "provider_public_key": bytes.fromhex(self.terms.provider_contract_compressed_key),
            "tap_tweak": artifacts.tap_tweak,
            "message": self.plan.signature_hash,
            "provider_public_nonce": nonce,
        }
        tip = self.terms.refund_lock_height - 50
        self.wallet.tip_height.return_value = tip
        output = CooperativeClaimOutpoint(
            self.terms.network_identity,
            FundingBindingTransactionMatch(
                binding["funding_txid"],
                binding["contract_vout"],
                binding["lineage_anchor_txid"],
                binding["lineage_anchor_vout"],
            ),
            binding["funding_txid"],
            binding["contract_vout"],
            int(binding["contract_value_sat"]),
            bytes.fromhex(binding["contract_script_pubkey"]),
            "aa" * 32,
            tip,
            self.terms.funding_confirmations,
            tip - self.terms.funding_confirmations + 1,
            "bb" * 32,
        )
        self.sample = CooperativeClaimEvidence(
            output,
            CooperativeFeePolicy(
                self.terms.network_identity,
                "aa" * 32,
                tip,
                self.terms.timing_policy.claim_confirmation_blocks,
                100,
                1000,
                1000,
                self.terms.timing_policy.claim_confirmation_blocks,
            ),
        )

    async def run(
        self, writer: object = None, *, settle_timeout: float = 60
    ) -> live_swap.SwapOutcome:
        return await run_swap(
            Mock(),
            identity=self.terms.provider_identity_key,
            network=self.terms.network_identity,
            invoice=INVOICE,
            decode_invoice=lambda _invoice: self.terms.invoice_binding,
            wallet=self.wallet,
            write_recovery=writer or self.write,
            limits=SwapLimits(max_success_fee_sat=5000),
            crypto=self.crypto,
            settle_timeout=settle_timeout,
            report=self.events.append,
        )


NATIVE = pytest.mark.skipif(
    LIBRARY is None, reason="set RILL_CRYPTO_LIBRARY for native forward owner"
)


@pytest.mark.native_crypto
@NATIVE
@pytest.mark.parametrize("failure", ["none", "paid uncertain", "reservation uncertain", "evidence"])
def test_featured_forward_dispatch_uses_actual_owner_once(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, failure: str
) -> None:
    async def exercise(crypto: Context) -> None:
        fixture = Forward(crypto, tmp_path, monkeypatch)

        def write(candidate: bytes, previous: bytes | None) -> None:
            fixture.write(candidate, previous)
            record = json.loads(candidate)
            paid = record["monotonic_knowledge"]["preimage_known"]
            reserved = live_swap.COOPERATIVE_RESERVATION_EXTENSION in record["extensions"]
            if (failure == "paid uncertain" and paid and not reserved) or (
                failure == "reservation uncertain" and reserved
            ):
                raise RecoveryPublicationUncertainError("sensitive publication details")

        if failure == "evidence":
            fixture.wallet.observe_cooperative_claim_evidence.side_effect = OSError("unavailable")
        try:
            if failure == "paid uncertain":
                with pytest.raises(SwapError, match=r"payment verified.*do not retry payment"):
                    await fixture.run(write)
            else:
                result = await fixture.run(write)
                assert result.payment_preimage == "42" * 32
                assert result.cooperation == ("verified" if failure == "none" else "abandoned")
                assert (result.cooperative_claim_txid is not None) == (failure == "none")
                if failure != "none":
                    assert any("not canceled at the provider" in event for event in fixture.events)
            assert len(fixture.broadcasts) == 1
            assert sum(
                json.loads(document)["monotonic_knowledge"]["preimage_known"]
                for document in fixture.documents
            ) == (2 if failure in {"none", "reservation uncertain"} else 1)
            assert (tmp_path / "forward.age.paid").exists()
        finally:
            if hasattr(fixture, "provider_attempt"):
                fixture.provider_attempt.close()

    with Context(library_path=LIBRARY) as crypto:
        asyncio.run(exercise(crypto))


@pytest.mark.parametrize("value", [0, -1, True, 1.5, 5001])
def test_invalid_absolute_claim_floor_fails_before_any_forward_effect(value: object) -> None:
    async def exercise() -> None:
        decoder = Mock(side_effect=AssertionError("no invoice decode"))
        with pytest.raises(SwapError, match="claim fee floor"):
            await run_swap(
                Mock(),
                identity="",
                network=Mock(),
                invoice="",
                decode_invoice=decoder,
                wallet=Mock(),
                write_recovery=Mock(),
                limits=SwapLimits(max_success_fee_sat=1, claim_fee_floor_sat=value),
                crypto=Mock(),
            )
        decoder.assert_not_called()

    asyncio.run(exercise())


@pytest.mark.parametrize("value", [0, -1, 5001])
def test_cli_floor_validation_precedes_native_and_relay_setup(
    monkeypatch: pytest.MonkeyPatch,
    value: int,
) -> None:
    parser = argparse.ArgumentParser()
    swap_command.add_parser(parser.add_subparsers(dest="category"))
    args = parser.parse_args(
        [
            "swap",
            "btc-to-ln",
            "--network",
            "unused",
            "--crypto-library",
            "unused",
            "--relay",
            "ws://unused",
            "--provider",
            "00" * 32,
            "--max-success-fee-sat",
            "1",
            "--core-port",
            "1",
            "--core-cookie",
            "unused",
            "--lnd-port",
            "2",
            "--lnd-tls-cert",
            "unused",
            "--recipient",
            "unused",
            "--identity",
            "unused",
            "--recovery-output",
            "unused",
            "--invoice",
            INVOICE,
            "--wallet",
            "unused",
            "--lnd-macaroon",
            "unused",
            "--claim-fee-floor-sat",
            str(value),
        ]
    )
    relay, crypto = (
        Mock(side_effect=AssertionError("no relay")),
        Mock(side_effect=AssertionError("no native")),
    )
    monkeypatch.setattr(swap_command, "RelayConnection", relay)
    monkeypatch.setattr(swap_command, "Context", crypto)
    with pytest.raises(SwapError, match="claim fee floor"):
        swap_command.run(args, Mock(), "unused")
    relay.assert_not_called()
    crypto.assert_not_called()


def test_forward_report_preserves_old_text_and_distinguishes_cooperation() -> None:
    outcome = SwapOutcome("session", "contract", "funding", "preimage", 1)
    assert (
        swap_command._forward_report(outcome)  # noqa: SLF001 - observable report contract
        == "Paid. preimage preimage (funding funding, contract contract)"
    )
    verified = swap_command._forward_report(  # noqa: SLF001 - observable report contract
        replace(outcome, cooperation="verified", cooperative_claim_txid="claim")
    )
    assert "Cooperative completion verified (claim)" in verified
    assert "not a chain confirmation" in verified
    abandoned = swap_command._forward_report(replace(outcome, cooperation="abandoned"))  # noqa: SLF001
    assert "not canceled at the provider" in abandoned
    assert "do not retry payment or signing" in abandoned


@pytest.mark.parametrize("exceptional", [False, True])
def test_repeated_cancellation_cannot_close_context_before_worker_cleanup(
    *, exceptional: bool
) -> None:
    async def exercise() -> None:
        entered, release = asyncio.Event(), asyncio.Event()
        done: list[bool] = []

        async def drain() -> None:
            entered.set()
            await release.wait()
            done.append(True)

        owner = Mock(wait_for_workers=drain)

        async def lifetime() -> None:
            try:
                if exceptional:
                    raise asyncio.CancelledError
            finally:
                await _drain_cooperative_workers(owner)

        running = asyncio.create_task(lifetime())
        await entered.wait()
        for _ in range(3):
            running.cancel()
            await asyncio.sleep(0)
            assert not running.done()
        release.set()
        with pytest.raises(asyncio.CancelledError):
            await running
        assert done == [True]

    asyncio.run(exercise())


@pytest.mark.native_crypto
@NATIVE
@pytest.mark.parametrize("normal_cleanup", [False, True])
def test_actual_forward_writer_drains_before_repeated_cancellation_escapes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    normal_cleanup: bool,
) -> None:
    async def exercise(crypto: Context) -> None:
        fixture = Forward(crypto, tmp_path, monkeypatch)
        entered, release = threading.Event(), threading.Event()

        def blocked_writer(candidate: bytes, previous: bytes | None) -> None:
            if json.loads(candidate)["monotonic_knowledge"]["preimage_known"]:
                entered.set()
                assert release.wait(timeout=3)
            fixture.write(candidate, previous)

        running = asyncio.create_task(
            fixture.run(blocked_writer, settle_timeout=0.05 if normal_cleanup else 60)
        )
        try:
            assert await asyncio.to_thread(entered.wait, 1)
            if normal_cleanup:
                await asyncio.sleep(
                    0.1
                )  # run returned a bounded known-paid result; cleanup still owns the writer
            for _ in range(3):
                running.cancel()
                await asyncio.sleep(0)
                assert not running.done()
            assert fixture.sent == []
            release.set()
            with pytest.raises(asyncio.CancelledError):
                await running
            assert (tmp_path / "forward.age.paid").exists()
            assert not (tmp_path / "forward.age.cooperating").exists()
            assert fixture.sent == []
            # Context is still valid through actual encrypted writer readback.
            assert (
                crypto.public_key((4).to_bytes(32, "big")).hex()
                == fixture.terms.client_contract_compressed_key
            )
        finally:
            release.set()
            await asyncio.gather(running, return_exceptions=True)
            fixture.provider_attempt.close()

    with Context(library_path=LIBRARY) as crypto:
        asyncio.run(exercise(crypto))


@pytest.mark.native_crypto
@NATIVE
def test_expiry_after_learning_without_a_candidate_is_not_confirmed_paid_storage(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def exercise(crypto: Context) -> None:
        fixture = Forward(crypto, tmp_path, monkeypatch)
        clock = live_swap._CooperativeClaimAttempt._clock  # noqa: SLF001 - exact learned-knowledge failure boundary

        def expired_clock(owner: live_swap._CooperativeClaimAttempt) -> tuple[int, float]:
            if owner.preimage is not None:
                raise SwapError("cooperative attempt expired")
            return clock(owner)

        monkeypatch.setattr(live_swap._CooperativeClaimAttempt, "_clock", expired_clock)  # noqa: SLF001
        try:
            with pytest.raises(SwapError, match=r"payment verified.*do not retry payment"):
                await fixture.run()
            assert len(fixture.documents) == 2
            assert not (tmp_path / "forward.age.paid").exists()
            assert fixture.sent == []
        finally:
            fixture.provider_attempt.close()

    with Context(library_path=LIBRARY) as crypto:
        asyncio.run(exercise(crypto))
