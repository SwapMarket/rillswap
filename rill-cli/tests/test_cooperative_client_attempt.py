"""Dormant native client owner: paid publication, burn, one partial, completion."""

from __future__ import annotations

import asyncio
import json
import threading
from dataclasses import replace
from typing import TYPE_CHECKING
from unittest.mock import AsyncMock, Mock

import pytest
from rill_core.recovery import COOPERATIVE_RESERVATION_EXTENSION
from rill_core.settlement import FundingBindingTransactionMatch, reconstruct_taproot_contract
from rill_core.settlement.unilateral import (
    FundingOutput,
    UnilateralAuthorization,
    verify_cooperative_claim_proposal,
)
from rill_core.wire.canonical import canonicalize
from rill_core.wire.hashes import unsigned_envelope_hash
from rill_core.wire.messages import ContractTerms, Envelope, HandshakeAccept, HandshakeInit
from rill_crypto import Context
from rill_crypto.binding import MusigAttempt
from rill_provider.core_tx_bytes import CooperativeClaimOutpoint, CooperativeFeePolicy
from test_cooperative_reservation_publication import LIBRARY, _credentials, _snapshots

from rill_cli.age_container import verify_export_ciphertext
from rill_cli.live_swap import SwapError, _CooperativeClaimAttempt, _Session, _wait_for_payment
from rill_cli.publication import RecoveryPublicationUncertainError
from rill_cli.swap_command import _write_recovery_snapshot
from rill_cli.wallet_rpc import CooperativeClaimEvidence

if TYPE_CHECKING:
    from pathlib import Path

pytestmark = [
    pytest.mark.native_crypto,
    pytest.mark.skipif(LIBRARY is None, reason="set RILL_CRYPTO_LIBRARY for native client attempt"),
]


class Harness:
    """Genuinely signed static fixture, not a negotiated production handshake."""

    def __init__(self, crypto: Context, path: Path, *, dangerous: bool = False) -> None:
        self.crypto, self.path = crypto, path
        self.initial, self.funded, _, reserved = _snapshots(crypto)
        for document in (self.initial, self.funded):
            document["monotonic_knowledge"]["dangerous_signature_issued"] = dangerous
        self.terms = ContractTerms.model_validate_json(canonicalize(self.funded["contract_terms"]))
        context = self.funded["verification_context"]
        self.init = HandshakeInit.model_validate_json(canonicalize(context["handshake_init"]))
        self.accept = HandshakeAccept.model_validate_json(canonicalize(context["handshake_accept"]))
        self.credentials = _credentials()
        self.output = path / "swap.age"
        self.offset = 0.0
        self.wall_offset = 0
        self.origin = asyncio.get_running_loop().time()
        self.events: list[str] = []
        self.sent: list[Envelope] = []
        self.session = _Session(Mock(), crypto, self.terms.network_identity, timeout=1)
        self.session.secret = (2).to_bytes(32, "big")
        self.session.key = crypto.public_key(self.session.secret)[1:].hex()
        self.session.session_id = self.init.session_id
        self.session.provider_key = self.accept.provider_session_xonly_key
        self.session._provider_next = 1  # noqa: SLF001 - fixture starts after authenticated handshake
        self.proposal = Envelope.model_validate_json(
            canonicalize(reserved["extensions"][COOPERATIVE_RESERVATION_EXTENSION]["proposal"])
        )
        binding = self.funded["funding_history"][0]["binding"]
        funding = FundingOutput(
            bytes.fromhex(binding["funding_txid"]),
            binding["contract_vout"],
            int(binding["contract_value_sat"]),
            bytes.fromhex(binding["contract_script_pubkey"]),
        )
        self.plan = verify_cooperative_claim_proposal(
            bytes.fromhex(self.proposal.payload["unsigned_transaction"]),
            UnilateralAuthorization.from_terms(self.terms, funding, "claim", keys=crypto),
        )
        artifacts = reconstruct_taproot_contract(self.terms, keys=crypto)
        self.provider_attempt, provider_nonce = crypto.musig_begin(
            secret_key=(5).to_bytes(32, "big"),
            user_public_key=bytes.fromhex(self.terms.client_contract_compressed_key),
            provider_public_key=bytes.fromhex(self.terms.provider_contract_compressed_key),
            tap_tweak=artifacts.tap_tweak,
            message=self.plan.signature_hash,
            cooperation_id=bytes.fromhex(self.proposal.payload["cooperation_id"]),
        )
        self.proposal = self.sign(
            self.proposal.model_copy(
                update={
                    "sequence": 2,
                    "payload": {
                        **self.proposal.payload,
                        "public_nonce": provider_nonce.hex(),
                    },
                }
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
                        "payment_preimage": self.proposal.payload["payment_preimage"],
                        "deadline_at": self.proposal.payload["deadline_at"],
                        "deadline_height": self.proposal.payload["deadline_height"],
                    },
                }
            )
        )
        self.public = {
            "user_public_key": bytes.fromhex(self.terms.client_contract_compressed_key),
            "provider_public_key": bytes.fromhex(self.terms.provider_contract_compressed_key),
            "tap_tweak": artifacts.tap_tweak,
            "message": self.plan.signature_hash,
            "provider_public_nonce": provider_nonce,
        }
        tip = self.terms.refund_lock_height - 50
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
        policy = CooperativeFeePolicy(
            self.terms.network_identity,
            "aa" * 32,
            tip,
            self.terms.timing_policy.claim_confirmation_blocks,
            100,
            1000,
            1000,
            self.terms.timing_policy.claim_confirmation_blocks,
        )
        self.sample = CooperativeClaimEvidence(output, policy)
        self.wallet = Mock()
        self.wallet.observe_cooperative_claim_evidence.side_effect = self.observe
        self.wallet.tip_height.return_value = tip
        self.write(canonicalize(self.initial), None)
        self.write(canonicalize(self.funded), canonicalize(self.initial))
        self.events.clear()
        self.session.send = self.send
        self.owner = _CooperativeClaimAttempt(
            self.session,
            terms=self.terms,
            init=self.init,
            accept=self.accept,
            funded_recovery=canonicalize(self.funded),
            contract_secret=bytes.fromhex(self.funded["user_secret"]["contract_secret_key"]),
            wallet=self.wallet,
            write_recovery=self.write,
            settlement_deadline=self.monotonic() + 60,
            configured_fee_floor_sat=300,
            wall_clock=self.wall,
            monotonic_clock=self.monotonic,
        )

    def sign(self, message: Envelope) -> Envelope:
        return message.model_copy(
            update={
                "signature": self.crypto.schnorr_sign(
                    (3).to_bytes(32, "big"),
                    unsigned_envelope_hash(message),
                    b"\x77" * 32,
                ).hex()
            }
        )

    def wall(self) -> int:
        return self.funded["updated_at"] + self.wall_offset

    def monotonic(self) -> float:
        return asyncio.get_running_loop().time() + self.offset

    def write(self, candidate: bytes, previous: bytes | None) -> None:
        self.events.append("write")
        _write_recovery_snapshot(
            self.output,
            candidate,
            previous,
            self.terms.network_identity,
            credentials=self.credentials,
            crypto=self.crypto,
        )

    def observe(self, *_args: object, **_kwargs: object) -> CooperativeClaimEvidence:
        self.events.append("sample")
        return self.sample

    def enqueue(self, message: Envelope) -> None:
        # Native authentication precedes the existing FIFO sequence admission.
        self.crypto.schnorr_verify(
            bytes.fromhex(message.sender_session_key),
            unsigned_envelope_hash(message),
            bytes.fromhex(message.signature or ""),
        )
        admitted = self.session._order_provider(message)  # noqa: SLF001 - admission fixture
        if admitted is not None:
            self.session._buffer_inbox(admitted)  # noqa: SLF001 - original FIFO, no synthetic direct handler calls

    async def send(self, message: Envelope, _recipient: str) -> None:
        self.sent.append(message)
        self.events.append("send " + str(message.payload["action"]))
        if message.payload.get("status") == "signed":
            public = {
                **self.public,
                "user_public_nonce": bytes.fromhex(message.payload["public_nonce"]),
            }
            self.crypto.musig_partial_verify(
                **public,
                signer_index=0,
                partial_signature=bytes.fromhex(message.payload["partial_signature"]),
            )
            partial = self.provider_attempt.partial_sign_once(public["user_public_nonce"])
            self.provider_attempt.close()
            self.enqueue(
                self.sign(
                    self.proposal.model_copy(
                        update={
                            "sequence": self.proposal.sequence + 1,
                            "message_id": "ee" * 32,
                            "payload": {
                                "action": "cooperative_claim_complete",
                                "cooperation_id": message.payload["cooperation_id"],
                                "partial_signature": partial.hex(),
                            },
                        }
                    )
                )
            )

    def start(self) -> None:
        self.enqueue(self.ready)
        self.enqueue(self.proposal)


@pytest.mark.parametrize("dangerous", [False, True])
def test_native_original_session_attempt_burns_before_nonce_and_completes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    dangerous: bool,
) -> None:
    async def exercise(crypto: Context) -> None:
        harness = Harness(crypto, tmp_path, dangerous=dangerous)
        begin = crypto.musig_begin

        def guarded_begin(**kwargs: bytes) -> tuple:
            assert (tmp_path / "swap.age.paid").exists()
            assert (tmp_path / "swap.age.cooperating").exists()
            harness.events.append("client nonce")
            return begin(**kwargs)

        monkeypatch.setattr(crypto, "musig_begin", guarded_begin)
        harness.start()
        try:
            result = await harness.owner.run()
            assert result.claim is not None
            assert result.claim.signature_hash == harness.plan.signature_hash
            assert result.preimage == harness.proposal.payload["payment_preimage"]
            assert result.pending_recovery is None
            assert (
                json.loads(result.recovery)["monotonic_knowledge"]["dangerous_signature_issued"]
                is dangerous
            )
            assert harness.events[:6] == [
                "write",
                "sample",
                "send cooperative_claim_ready",
                "sample",
                "write",
                "sample",
            ]
            assert harness.events.count("client nonce") == 1
            assert [message.payload.get("status") for message in harness.sent] == [
                "ready",
                "signed",
                "verified",
            ]
            with pytest.raises(SwapError, match="cannot resume"):
                await harness.owner.run()
        finally:
            harness.provider_attempt.close()
            await harness.owner.wait_for_workers()

    with Context(library_path=LIBRARY) as crypto:
        asyncio.run(exercise(crypto))


@pytest.mark.parametrize(
    "failure",
    [
        "paid publication",
        "reservation collision",
        "reservation uncertainty",
        "post-write evidence",
        "fee",
        "height",
    ],
)
def test_failure_never_allocates_a_client_nonce_or_retries_payment(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    failure: str,
) -> None:
    async def exercise(crypto: Context) -> None:
        harness = Harness(crypto, tmp_path)
        begin = Mock(side_effect=AssertionError("client nonce forbidden"))
        monkeypatch.setattr(crypto, "musig_begin", begin)
        original_write = harness.write

        def write(candidate: bytes, previous: bytes | None) -> None:
            record = json.loads(candidate)
            reservation = COOPERATIVE_RESERVATION_EXTENSION in record["extensions"]
            if failure == "paid publication" and not reservation:
                raise OSError("sensitive backend details")
            if failure == "reservation uncertainty" and reservation:
                original_write(candidate, previous)
                raise RecoveryPublicationUncertainError("sensitive backend details")
            original_write(candidate, previous)
            if failure == "post-write evidence" and reservation:
                harness.wallet.observe_cooperative_claim_evidence.side_effect = OSError(
                    "unavailable"
                )

        harness.owner.write_recovery = write
        if failure == "reservation collision":
            (tmp_path / "swap.age.cooperating").write_bytes(b"existing immutable file")
        elif failure == "fee":
            harness.sample = replace(
                harness.sample,
                fee_policy=replace(harness.sample.fee_policy, estimate_sat_kvb=100000),
            )
        elif failure == "height":
            harness.sample = replace(
                harness.sample,
                outpoint=replace(harness.sample.outpoint, tip_height=harness.owner.height_deadline),
                fee_policy=replace(
                    harness.sample.fee_policy, tip_height=harness.owner.height_deadline
                ),
            )
        harness.start()
        try:
            result = await harness.owner.run()
            assert result.preimage == harness.proposal.payload["payment_preimage"]
            assert result.claim is None
            assert harness.owner.stage == "abandoned"
            begin.assert_not_called()
            assert all(message.payload.get("status") == "ready" for message in harness.sent)
            if failure in {"paid publication", "reservation collision", "reservation uncertainty"}:
                assert result.pending_recovery is not None
            with pytest.raises(SwapError, match="cannot resume"):
                await harness.owner.run()
        finally:
            harness.provider_attempt.close()
            await harness.owner.wait_for_workers()

    with Context(library_path=LIBRARY) as crypto:
        asyncio.run(exercise(crypto))


def test_payment_before_readiness_is_durable_and_does_not_end_the_attempt(tmp_path: Path) -> None:
    async def exercise(crypto: Context) -> None:
        harness = Harness(crypto, tmp_path)
        payment = harness.sign(
            harness.ready.model_copy(
                update={
                    "sequence": 1,
                    "message_id": "ab" * 32,
                    "message_type": "observation",
                    "required_features": (),
                    "payload": {
                        "kind": "payment_settled",
                        "payment_preimage": harness.proposal.payload["payment_preimage"],
                    },
                }
            )
        )
        harness.ready = harness.sign(harness.ready.model_copy(update={"sequence": 2}))
        harness.proposal = harness.sign(harness.proposal.model_copy(update={"sequence": 3}))
        harness.enqueue(payment)
        harness.start()
        try:
            result = await harness.owner.run()
            assert result.claim is not None
            assert harness.events.count("write") == 2
        finally:
            harness.provider_attempt.close()
            await harness.owner.wait_for_workers()

    with Context(library_path=LIBRARY) as crypto:
        asyncio.run(exercise(crypto))


@pytest.mark.parametrize("publication", ["paid", "reservation"])
def test_canceled_publication_stays_owned_and_late_success_never_resumes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    publication: str,
) -> None:
    async def exercise(crypto: Context) -> None:
        harness = Harness(crypto, tmp_path)
        entered, release = threading.Event(), threading.Event()
        original_write = harness.write

        def blocked_write(candidate: bytes, previous: bytes | None) -> None:
            reserved = COOPERATIVE_RESERVATION_EXTENSION in json.loads(candidate)["extensions"]
            if reserved == (publication == "reservation"):
                entered.set()
                assert release.wait(timeout=3)
            original_write(candidate, previous)

        harness.owner.write_recovery = blocked_write
        begin = Mock(side_effect=AssertionError("client nonce forbidden"))
        monkeypatch.setattr(crypto, "musig_begin", begin)
        harness.start()
        running = asyncio.create_task(harness.owner.run())
        try:
            assert await asyncio.to_thread(entered.wait, 1)
            assert len(harness.owner.workers) == 1
            with pytest.raises(SwapError, match="stream already owned"):
                await _wait_for_payment(
                    harness.session,
                    harness.terms,
                    deadline=harness.monotonic() + 1,
                    refund_hint="funded",
                )
            running.cancel()
            with pytest.raises(asyncio.CancelledError):
                await running
            assert harness.owner.stage == "abandoned"
            assert len(harness.owner.workers) == 1
            assert harness.owner.pending_recovery is not None
            with pytest.raises(SwapError, match="cannot resume"):
                await harness.owner.run()
            release.set()
            await harness.owner.wait_for_workers()
            assert harness.owner.workers == set()
            assert harness.owner.stage == "abandoned"
            begin.assert_not_called()
            suffix = ".cooperating" if publication == "reservation" else ".paid"
            verify_export_ciphertext(
                (tmp_path / ("swap.age" + suffix)).read_bytes(),
                harness.owner.pending_recovery,
                harness.terms.network_identity,
                credentials=harness.credentials,
                crypto=crypto,
            )
            assert all(message.payload.get("status") == "ready" for message in harness.sent)
        finally:
            release.set()
            if not running.done():
                running.cancel()
            await asyncio.gather(running, return_exceptions=True)
            harness.provider_attempt.close()
            await harness.owner.wait_for_workers()

    with Context(library_path=LIBRARY) as crypto:
        asyncio.run(exercise(crypto))


@pytest.mark.parametrize(
    "boundary",
    [
        "paid write",
        "reservation write",
        "nonce",
        "partial",
        "queued completion",
        "completion verification",
    ],
)
def test_deadline_crossing_closes_custody_and_never_publishes_later_effects(  # noqa: PLR0915 - native effect-boundary matrix
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    boundary: str,
) -> None:
    async def exercise(crypto: Context) -> None:  # noqa: PLR0915 - retained custody across each boundary
        harness = Harness(crypto, tmp_path)
        nonce_calls: list[object] = []
        partial_calls: list[object] = []
        original_write, begin = harness.write, crypto.musig_begin
        partial_sign = MusigAttempt.partial_sign_once
        verify = crypto.musig_partial_verify
        send = harness.send

        def expire() -> None:
            harness.wall_offset = 20  # equality with the original advertised deadline

        def write(candidate: bytes, previous: bytes | None) -> None:
            original_write(candidate, previous)
            reserved = COOPERATIVE_RESERVATION_EXTENSION in json.loads(candidate)["extensions"]
            if boundary == ("reservation write" if reserved else "paid write"):
                expire()

        def nonce(**kwargs: bytes) -> tuple:
            handle, public = begin(**kwargs)
            nonce_calls.append(handle)
            if boundary == "nonce":
                expire()
            return handle, public

        def partial(handle: MusigAttempt, public_nonce: bytes) -> bytes:
            result = partial_sign(handle, public_nonce)
            partial_calls.append(handle)
            if boundary == "partial":
                expire()
            return result

        def partial_verify(**kwargs: object) -> None:
            verify(**kwargs)
            if boundary == "completion verification" and kwargs["signer_index"] == 1:
                expire()

        async def send_with_expiry(message: Envelope, recipient: str) -> None:
            await send(message, recipient)
            if boundary == "queued completion" and message.payload.get("status") == "signed":
                expire()

        harness.owner.write_recovery = write
        harness.session.send = send_with_expiry
        monkeypatch.setattr(crypto, "musig_begin", nonce)
        monkeypatch.setattr(MusigAttempt, "partial_sign_once", partial)
        monkeypatch.setattr(crypto, "musig_partial_verify", partial_verify)
        harness.start()
        try:
            result = await harness.owner.run()
            assert result.claim is None
            assert result.preimage == harness.proposal.payload["payment_preimage"]
            assert harness.owner.stage == "abandoned"
            assert len(nonce_calls) <= 1
            assert all(message.payload.get("status") != "verified" for message in harness.sent)
            if boundary in {"paid write", "reservation write"}:
                assert nonce_calls == []
            elif nonce_calls:
                with pytest.raises(RuntimeError, match="closed"):
                    nonce_calls[0].partial_sign_once(harness.public["provider_public_nonce"])
            if boundary == "nonce":
                assert partial_calls == []
            if boundary == "queued completion":
                assert len(harness.session.inbox) == 1
        finally:
            harness.provider_attempt.close()
            await harness.owner.wait_for_workers()

    with Context(library_path=LIBRARY) as crypto:
        asyncio.run(exercise(crypto))


@pytest.mark.parametrize(
    "change",
    [
        "deadline",
        "height",
        "preimage",
        "transaction",
        "nonce",
        "completion id",
        "completion partial",
    ],
)
def test_signed_changed_context_cannot_reopen_or_complete_the_attempt(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    change: str,
) -> None:
    async def exercise(crypto: Context) -> None:
        harness = Harness(crypto, tmp_path)
        payload = dict(harness.proposal.payload)
        if change == "deadline":
            payload["deadline_at"] += 1
        elif change == "height":
            payload["deadline_height"] += 1
        elif change == "preimage":
            payload["payment_preimage"] = "00" * 32
        elif change == "transaction":
            payload["unsigned_transaction"] = "01" + payload["unsigned_transaction"][2:]
        elif change == "nonce":
            payload["public_nonce"] = "00" * 66
        harness.proposal = harness.sign(harness.proposal.model_copy(update={"payload": payload}))
        original_enqueue = harness.enqueue

        def enqueue(message: Envelope) -> None:
            if message.payload.get("action") == "cooperative_claim_complete":
                altered = dict(message.payload)
                if change == "completion id":
                    altered["cooperation_id"] = "ff" * 32
                elif change == "completion partial":
                    altered["partial_signature"] = "00" * 32
                message = harness.sign(message.model_copy(update={"payload": altered}))
            original_enqueue(message)

        harness.enqueue = enqueue
        begin = Mock(wraps=crypto.musig_begin)
        monkeypatch.setattr(crypto, "musig_begin", begin)
        harness.start()
        try:
            result = await harness.owner.run()
            assert result.claim is None
            assert harness.owner.stage == "abandoned"
            assert all(message.payload.get("status") != "verified" for message in harness.sent)
            assert begin.call_count == (1 if change.startswith("completion") else 0)
            with pytest.raises(SwapError, match="cannot resume"):
                await harness.owner.run()
        finally:
            harness.provider_attempt.close()
            await harness.owner.wait_for_workers()

    with Context(library_path=LIBRARY) as crypto:
        asyncio.run(exercise(crypto))


@pytest.mark.parametrize("change", ["expired", "future", "height", "expiry after hash"])
def test_unusable_readiness_preserves_verified_knowledge_without_signing_authority(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    change: str,
) -> None:
    async def exercise(crypto: Context) -> None:
        harness = Harness(crypto, tmp_path)
        payload = dict(harness.ready.payload)
        if change == "expired":
            payload["deadline_at"] = harness.wall()
        elif change == "future":
            payload["deadline_at"] = harness.wall() + 31
        elif change == "height":
            payload["deadline_height"] = harness.owner.height_deadline + 1
        else:
            mono = harness.monotonic
            harness.owner.monotonic_clock = lambda: (
                harness.owner.deadline if harness.owner.preimage is not None else mono()
            )
        harness.ready = harness.sign(harness.ready.model_copy(update={"payload": payload}))
        begin = Mock(side_effect=AssertionError("nonce forbidden"))
        monkeypatch.setattr(crypto, "musig_begin", begin)
        harness.enqueue(harness.ready)
        try:
            result = await harness.owner.run()
            assert result.preimage == harness.proposal.payload["payment_preimage"]
            assert result.claim is None
            assert harness.sent == []
            begin.assert_not_called()
            harness.wallet.observe_cooperative_claim_evidence.assert_not_called()
            assert (tmp_path / "swap.age.paid").exists() == (change != "expiry after hash")
            assert not (tmp_path / "swap.age.cooperating").exists()
        finally:
            harness.provider_attempt.close()
            await harness.owner.wait_for_workers()

    with Context(library_path=LIBRARY) as crypto:
        asyncio.run(exercise(crypto))


@pytest.mark.parametrize("status", ["ready", "signed", "verified"])
@pytest.mark.parametrize("failure", ["uncertain", "blocked"])
def test_failed_or_blocked_send_never_reopens_nonce_custody(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    status: str,
    failure: str,
) -> None:
    async def exercise(crypto: Context) -> None:
        harness = Harness(crypto, tmp_path)
        original_send = harness.send
        entered = asyncio.Event()
        begin = Mock(wraps=crypto.musig_begin)
        monkeypatch.setattr(crypto, "musig_begin", begin)

        async def failed_send(message: Envelope, recipient: str) -> None:
            if message.payload.get("status") == status:
                harness.sent.append(message)  # possibly disclosed before failure
                entered.set()
                if failure == "blocked":
                    await asyncio.Future()
                raise OSError("sensitive transport details")
            await original_send(message, recipient)

        harness.session.send = failed_send
        if failure == "blocked":
            harness.owner.deadline = (
                harness.monotonic() + 1
            )  # shorten, never renew the fixed lifetime
        harness.start()
        running = asyncio.create_task(harness.owner.run())
        try:
            if failure == "blocked":
                await asyncio.wait_for(entered.wait(), timeout=1)
                result = await asyncio.wait_for(asyncio.shield(running), timeout=1.5)
                assert result.claim is None
                assert result.preimage == harness.proposal.payload["payment_preimage"]
            else:
                result = await running
                assert result.claim is None
                assert result.preimage == harness.proposal.payload["payment_preimage"]
            assert harness.owner.stage == "abandoned"
            assert begin.call_count == (0 if status == "ready" else 1)
            assert sum(message.payload.get("status") == status for message in harness.sent) == 1
            with pytest.raises(SwapError, match="cannot resume"):
                await harness.owner.run()
        finally:
            running.cancel()
            await asyncio.gather(running, return_exceptions=True)
            harness.provider_attempt.close()
            await harness.owner.wait_for_workers()

    with Context(library_path=LIBRARY) as crypto:
        asyncio.run(exercise(crypto))


def test_hung_core_sample_is_single_flight_and_late_result_is_discarded(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def exercise(crypto: Context) -> None:
        harness = Harness(crypto, tmp_path)
        entered, release = threading.Event(), threading.Event()

        def blocked_sample(*_args: object, **_kwargs: object) -> CooperativeClaimEvidence:
            entered.set()
            assert release.wait(timeout=3)
            return harness.sample

        harness.wallet.observe_cooperative_claim_evidence.side_effect = blocked_sample
        begin = Mock(side_effect=AssertionError("nonce forbidden"))
        monkeypatch.setattr(crypto, "musig_begin", begin)
        harness.start()
        running = asyncio.create_task(harness.owner.run())
        try:
            assert await asyncio.to_thread(entered.wait, 1)
            result = await asyncio.wait_for(asyncio.shield(running), timeout=1.5)
            assert result.claim is None
            assert harness.owner.stage == "abandoned"
            assert len(harness.owner.workers) == 1
            harness.wallet.observe_cooperative_claim_evidence.assert_called_once()
            assert harness.sent == []
            release.set()
            await harness.owner.wait_for_workers()
            begin.assert_not_called()
            assert harness.owner.stage == "abandoned"
            assert harness.owner.workers == set()
        finally:
            release.set()
            running.cancel()
            await asyncio.gather(running, return_exceptions=True)
            harness.provider_attempt.close()
            await harness.owner.wait_for_workers()

    with Context(library_path=LIBRARY) as crypto:
        asyncio.run(exercise(crypto))


def test_another_owner_cannot_renew_the_original_session(tmp_path: Path) -> None:
    async def exercise(crypto: Context) -> None:
        harness = Harness(crypto, tmp_path)
        try:
            with pytest.raises(SwapError, match="already reserved"):
                _CooperativeClaimAttempt(
                    harness.session,
                    terms=harness.terms,
                    init=harness.init,
                    accept=harness.accept,
                    funded_recovery=canonicalize(harness.funded),
                    contract_secret=bytes.fromhex(
                        harness.funded["user_secret"]["contract_secret_key"]
                    ),
                    wallet=harness.wallet,
                    write_recovery=harness.write,
                    settlement_deadline=harness.monotonic() + 60,
                    configured_fee_floor_sat=300,
                )
        finally:
            harness.provider_attempt.close()

    with Context(library_path=LIBRARY) as crypto:
        asyncio.run(exercise(crypto))


@pytest.mark.parametrize("consumed", [False, True])
def test_native_partial_failure_closes_the_handle_without_result_or_retry(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    consumed: bool,
) -> None:
    async def exercise(crypto: Context) -> None:
        harness = Harness(crypto, tmp_path)
        partial = MusigAttempt.partial_sign_once
        handles: list[MusigAttempt] = []

        def failed_partial(handle: MusigAttempt, nonce: bytes) -> bytes:
            handles.append(handle)
            if consumed:
                partial(handle, nonce)
            raise OSError("test-only native failure")

        monkeypatch.setattr(MusigAttempt, "partial_sign_once", failed_partial)
        harness.start()
        try:
            result = await harness.owner.run()
            assert result.claim is None
            assert len(handles) == 1
            assert harness.owner.stage == "abandoned"
            assert [message.payload["status"] for message in harness.sent] == ["ready"]
            assert (tmp_path / "swap.age.cooperating").exists()
            with pytest.raises(RuntimeError, match="closed"):
                partial(handles[0], harness.public["provider_public_nonce"])
            with pytest.raises(SwapError, match="cannot resume"):
                await harness.owner.run()
        finally:
            harness.provider_attempt.close()
            await harness.owner.wait_for_workers()

    with Context(library_path=LIBRARY) as crypto:
        asyncio.run(exercise(crypto))


@pytest.mark.parametrize("which", ["ready", "proposal"])
def test_new_signed_duplicate_cannot_produce_a_second_partial(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    which: str,
) -> None:
    async def exercise(crypto: Context) -> None:
        harness = Harness(crypto, tmp_path)
        nonce = Mock(wraps=crypto.musig_begin)
        monkeypatch.setattr(crypto, "musig_begin", nonce)

        async def send_without_completion(message: Envelope, _recipient: str) -> None:
            harness.sent.append(message)

        harness.session.send = send_without_completion
        harness.start()
        duplicate = harness.ready if which == "ready" else harness.proposal
        harness.enqueue(
            harness.sign(duplicate.model_copy(update={"message_id": "ff" * 32, "sequence": 3}))
        )
        try:
            result = await harness.owner.run()
            assert result.claim is None
            assert nonce.call_count == 1
            assert sum(message.payload.get("status") == "signed" for message in harness.sent) == 1
            assert harness.owner.stage == "abandoned"
        finally:
            harness.provider_attempt.close()
            await harness.owner.wait_for_workers()

    with Context(library_path=LIBRARY) as crypto:
        asyncio.run(exercise(crypto))


@pytest.mark.parametrize(
    "change", ["estimate target", "estimate rate", "relay floor", "confirmations"]
)
def test_typed_evidence_alone_does_not_grant_partial_authority(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    change: str,
) -> None:
    async def exercise(crypto: Context) -> None:
        harness = Harness(crypto, tmp_path)
        sample = harness.sample
        if change == "estimate target":
            sample = replace(
                sample,
                fee_policy=replace(
                    sample.fee_policy, estimate_blocks=sample.fee_policy.confirmation_blocks + 1
                ),
            )
        elif change == "estimate rate":
            sample = replace(sample, fee_policy=replace(sample.fee_policy, estimate_sat_kvb=True))
        elif change == "relay floor":
            sample = replace(sample, fee_policy=replace(sample.fee_policy, min_relay_sat_kvb=-1))
        else:
            sample = replace(sample, outpoint=replace(sample.outpoint, confirmations=True))
        harness.sample = sample
        begin = Mock(side_effect=AssertionError("nonce forbidden"))
        monkeypatch.setattr(crypto, "musig_begin", begin)
        harness.start()
        try:
            result = await harness.owner.run()
            assert result.claim is None
            assert harness.owner.stage == "abandoned"
            begin.assert_not_called()
            assert harness.sent == []
        finally:
            harness.provider_attempt.close()
            await harness.owner.wait_for_workers()

    with Context(library_path=LIBRARY) as crypto:
        asyncio.run(exercise(crypto))


def test_real_transport_retransmits_identical_events_without_another_partial(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def exercise(crypto: Context) -> None:
        harness = Harness(crypto, tmp_path)
        publish = AsyncMock(side_effect=[False, False, True, False, False, False])
        harness.session.connection.publish = publish

        async def actual_send(message: Envelope, recipient: str) -> None:
            await _Session.send(harness.session, message, recipient)

        harness.session.send = actual_send
        begin = Mock(wraps=crypto.musig_begin)
        monkeypatch.setattr(crypto, "musig_begin", begin)
        harness.start()
        try:
            result = await harness.owner.run()
            assert result.claim is None
            assert harness.owner.stage == "abandoned"
            assert begin.call_count == 1
            assert publish.await_count == 6
            events = [call.args[0] for call in publish.await_args_list]
            assert events[0] == events[1] == events[2]
            assert events[3] == events[4] == events[5]
            assert events[0] != events[3]
            assert harness.session.sequence == 2  # ready and partial, not six signed replies
        finally:
            harness.provider_attempt.close()
            await harness.owner.wait_for_workers()

    with Context(library_path=LIBRARY) as crypto:
        asyncio.run(exercise(crypto))


@pytest.mark.parametrize("snapshot", ["funded", "paid", "reserved"])
def test_restored_snapshots_cannot_supply_the_original_session_capability(
    tmp_path: Path, snapshot: str
) -> None:
    async def exercise(crypto: Context) -> None:
        harness = Harness(crypto, tmp_path)
        _, funded, paid, reserved = _snapshots(crypto)
        document = {"funded": funded, "paid": paid, "reserved": reserved}[snapshot]
        restarted = _Session(Mock(), crypto, harness.terms.network_identity, timeout=1)
        restarted.session_id = harness.init.session_id
        restarted.provider_key = harness.accept.provider_session_xonly_key
        try:
            with pytest.raises(SwapError, match="original live funded session"):
                _CooperativeClaimAttempt(
                    restarted,
                    terms=harness.terms,
                    init=harness.init,
                    accept=harness.accept,
                    funded_recovery=canonicalize(document),
                    contract_secret=bytes.fromhex(document["user_secret"]["contract_secret_key"]),
                    wallet=harness.wallet,
                    write_recovery=harness.write,
                    settlement_deadline=harness.monotonic() + 60,
                    configured_fee_floor_sat=300,
                )
            harness.wallet.observe_cooperative_claim_evidence.assert_not_called()
            assert not (tmp_path / "swap.age.paid").exists()
            assert not (tmp_path / "swap.age.cooperating").exists()
        finally:
            harness.provider_attempt.close()

    with Context(library_path=LIBRARY) as crypto:
        asyncio.run(exercise(crypto))


def test_payment_before_readiness_has_one_nonrenewing_local_budget(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def exercise(crypto: Context) -> None:
        harness = Harness(crypto, tmp_path)
        payment = harness.sign(
            harness.ready.model_copy(
                update={
                    "sequence": 1,
                    "message_id": "ab" * 32,
                    "message_type": "observation",
                    "required_features": (),
                    "payload": {
                        "kind": "payment_settled",
                        "payment_preimage": harness.proposal.payload["payment_preimage"],
                    },
                }
            )
        )
        harness.ready = harness.sign(
            harness.ready.model_copy(
                update={
                    "sequence": 2,
                    "payload": {
                        **harness.ready.payload,
                        "deadline_at": harness.wall() + 59,
                    },
                }
            )
        )
        harness.proposal = harness.sign(
            harness.proposal.model_copy(
                update={
                    "sequence": 3,
                    "payload": {
                        **harness.proposal.payload,
                        "deadline_at": harness.wall() + 59,
                    },
                }
            )
        )
        write = harness.write

        def advance_after_paid(candidate: bytes, previous: bytes | None) -> None:
            write(candidate, previous)
            harness.wall_offset, harness.offset = 29, 29.0

        async def due_after_echo(message: Envelope, _recipient: str) -> None:
            harness.sent.append(message)
            assert harness.owner.wall_deadline == harness.funded["updated_at"] + 30
            harness.wall_offset, harness.offset = 30, 30.0

        harness.owner.write_recovery = advance_after_paid
        harness.session.send = due_after_echo
        nonce = Mock(side_effect=AssertionError("no renewed nonce authority"))
        monkeypatch.setattr(crypto, "musig_begin", nonce)
        harness.enqueue(payment)
        harness.start()
        try:
            result = await harness.owner.run()
            assert result.claim is None
            assert result.preimage == harness.proposal.payload["payment_preimage"]
            assert [message.payload["status"] for message in harness.sent] == ["ready"]
            assert len(harness.session.inbox) == 1
            nonce.assert_not_called()
        finally:
            harness.provider_attempt.close()
            await harness.owner.wait_for_workers()

    with Context(library_path=LIBRARY) as crypto:
        asyncio.run(exercise(crypto))
