"""Native proposal reservation, not live settlement or production activation.

The acceptance guard is explicitly bypassed only to prepare the future reverse
population. Reservation independently authenticates all retained signatures.
Synthetic funding bytes are structurally valid, not chain-confirmed or paid.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
from dataclasses import dataclass, replace
from typing import TYPE_CHECKING, Any
from unittest.mock import Mock

import pytest
import test_reverse_negotiation_origin as origins
from rill_core.settlement import (
    FundingOutput,
    UnilateralAuthorization,
    build_cooperative_claim,
    reconstruct_taproot_contract,
)
from rill_core.wire.canonical import canonicalize
from rill_core.wire.hashes import handshake_accept_hash, unsigned_envelope_hash
from rill_core.wire.messages import Envelope, FundingBinding, HandshakeAccept
from rill_core.wire.quotes import TermsOfferPayload
from test_handshake_reverse_gate import CommitThenFail
from test_reverse_cooperation_window import Clock

from rill_provider.live_session_store import (
    LiveSessionStoreError,
    SessionBlockedError,
    StaleOwnerError,
)

if TYPE_CHECKING:
    from collections.abc import Iterator
    from pathlib import Path

    from rill_crypto import Context

    from rill_provider.live_session_store import LiveSessionStore, ReverseProposalAdmission
    from rill_provider.reverse_operations import ReverseOperation

pytestmark = [
    pytest.mark.native_crypto,
    pytest.mark.skipif(
        os.environ.get("RILLSWAP_RUN_NATIVE_CRYPTO") != "1",
        reason="set RILLSWAP_RUN_NATIVE_CRYPTO=1 for native reverse reservation",
    ),
]
# ruff: noqa: SLF001, ANN401 - intentional component seams, native test adapter


class NativeVerifier:
    def __init__(self, crypto: Context) -> None:
        self.crypto = crypto

    def permit_confirm(self, document: dict[str, Any]) -> None:
        envelope = Envelope.model_validate_json(canonicalize(document), strict=True)
        document["signature"] = self.crypto.schnorr_sign(
            (8).to_bytes(32, "big"),
            unsigned_envelope_hash(envelope),
            b"\x55" * 32,
        ).hex()

    def schnorr_verify(self, key: bytes, digest: bytes, signature: bytes) -> None:
        self.crypto.schnorr_verify(key, digest, signature)


class NativeSigner:
    def __init__(self, harness: origins.OriginHarness) -> None:
        self.verifier = harness.crypto

    def schnorr_sign(self, scalar: bytes, digest: bytes, aux: bytes) -> bytes:
        return self.verifier.crypto.schnorr_sign(scalar, digest, aux)

    def schnorr_verify(self, key: bytes, digest: bytes, signature: bytes) -> None:
        self.verifier.schnorr_verify(key, digest, signature)


@dataclass
class ReservationCase:
    origin: origins.OriginHarness
    store: LiveSessionStore
    document: bytes
    clock: Clock

    def admit(
        self, operation: ReverseOperation, document: bytes | None = None
    ) -> ReverseProposalAdmission:
        return self.store._admit_reverse_cooperative_proposal(
            self.document if document is None else document,
            operation=operation,
            wall_clock=self.clock.utc,
            monotonic_clock=self.clock.steady,
        )

    def signed(
        self,
        *,
        message: str | None = None,
        cooperation: str | None = None,
        transaction: str | None = None,
        deadline: int | None = None,
    ) -> bytes:
        document = json.loads(self.document)
        if message is not None:
            document["message_id"] = message
        if cooperation is not None:
            document["payload"]["cooperation_id"] = cooperation
        if transaction is not None:
            document["payload"]["unsigned_transaction"] = transaction
        if deadline is not None:
            document["payload"]["deadline_at"] = deadline
        self.origin.crypto.permit_confirm(document)
        return canonicalize(document)


@pytest.fixture
def reserved(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[ReservationCase]:
    from rill_crypto import Context  # noqa: PLC0415 - explicit native opt-in

    with Context(library_path=os.environ["RILL_CRYPTO_LIBRARY"]) as crypto:
        origin = origins.OriginHarness(tmp_path, monkeypatch)
        origin.crypto = NativeVerifier(crypto)
        monkeypatch.setattr(origins, "Signer", NativeSigner)
        monkeypatch.setattr(origins, "OriginSigner", NativeSigner)
        accepted = HandshakeAccept.model_validate_json(
            canonicalize(origin.source["verification_context"]["handshake_accept"]), strict=True
        )
        origin.envelopes[1]["payload"]["provider_identity_signature"] = crypto.schnorr_sign(
            (1).to_bytes(32, "big"),
            handshake_accept_hash(accepted),
            b"\x55" * 32,
        ).hex()
        origin.crypto.permit_confirm(origin.envelopes[2])
        origin.init, origin.accept, origin.confirm = map(canonicalize, origin.envelopes)
        with origin.acquire_at(origin.path, crypto=origin.crypto, public_keys=crypto) as store:
            origins._handshake(store, origin)
            service, request, digest = origins._isolated_provenance_acceptance(origin, store)
            assert asyncio.run(service._answer(request, (), 1_700_000_000)) == "request-answered"
            assert store._has_original_reverse_negotiation(origin.session_id, digest)
            offer = next(
                Envelope.model_validate_json(entry.canonical_bytes, strict=True)
                for entry in store.pending_outbox()
                if b'"message_type":"terms_offer"' in entry.canonical_bytes
            )
            terms = TermsOfferPayload.model_validate_json(
                canonicalize(offer.payload), strict=True
            ).terms.contract_terms
            script = reconstruct_taproot_contract(terms, keys=crypto).script_pubkey
            value = int(terms.economics.contract_amount_sat)
            raw = (
                b"\x02\x00\x00\x00\x01"
                + b"\x41" * 32
                + b"\x01\x00\x00\x00\x00"
                + b"\xff" * 4
                + b"\x01"
                + value.to_bytes(8, "little")
                + bytes([len(script)])
                + script
                + b"\x00" * 4
            )
            txid = hashlib.sha256(hashlib.sha256(raw).digest()).digest()[::-1].hex()
            binding = FundingBinding(
                created_at=1_700_000_000,
                contract_hash=digest,
                funder_role="provider",
                funding_attempt_id="cc" * 32,
                lineage_anchor_txid="41" * 32,
                lineage_anchor_vout=1,
                binding_revision=0,
                replaces_txid=None,
                funding_txid=txid,
                contract_vout=0,
                contract_value_sat=str(value),
                contract_script_pubkey=script.hex(),
            )
            signer = NativeSigner(origin)
            store.advance_reverse_swap(
                origin.session_id,
                from_state="ACCEPTED",
                to_state="LN_HELD",
                signer=signer,
                now=1_700_000_000,
            )
            store.advance_reverse_swap(
                origin.session_id,
                from_state="LN_HELD",
                to_state="FUNDING_SENT",
                signer=signer,
                now=1_700_000_000,
                funding=(binding, raw),
            )
            authorization = UnilateralAuthorization.from_terms(
                terms, FundingOutput(bytes.fromhex(txid), 0, value, script), "claim", keys=crypto
            )
            plan = build_cooperative_claim(authorization, fee_sat=300)
            document = json.loads(request)
            document.update(
                message_type="action_request",
                sequence=4,
                message_id="ee" * 32,
                in_reply_to=None,
                payload={
                    "action": "cooperative_claim_propose",
                    "cooperation_id": "ff" * 32,
                    "unsigned_transaction": plan.base_transaction.hex(),
                    "public_nonce": (
                        crypto.public_key((7).to_bytes(32, "big"))
                        + crypto.public_key((8).to_bytes(32, "big"))
                    ).hex(),
                    "payment_preimage": "52" * 32,
                    "deadline_at": 1_700_000_030,
                    "deadline_height": terms.refund_lock_height
                    - terms.timing_policy.claim_confirmation_blocks,
                },
            )
            origin.crypto.permit_confirm(document)
            yield ReservationCase(origin, store, canonicalize(document), Clock(1_700_000_000, 100))


def test_native_reservation_is_atomic_receipt_only_with_no_economic_or_nonce_effects(
    reserved: ReservationCase,
) -> None:
    async def exercise() -> None:
        store = reserved.store
        before = store._connection.execute("SELECT next_provider_seq FROM sessions").fetchone()
        outbox = store.pending_outbox()
        swap = store._connection.execute("SELECT state,preimage FROM swaps").fetchone()
        async with store.reverse_operations.operation() as operation:
            receipt = reserved.admit(operation)
            assert not receipt.replay
            assert reserved.admit(operation).replay
        assert store.pending_outbox() == outbox
        assert (
            store._connection.execute("SELECT next_provider_seq FROM sessions").fetchone() == before
        )
        assert store._connection.execute("SELECT state,preimage FROM swaps").fetchone() == swap
        row = store._connection.execute(
            "SELECT binding,state,local_nonce,peer_nonce FROM cooperation_attempts"
        ).fetchone()
        binding = json.loads(row[0])
        assert binding["version"] == 2
        assert binding["kind"] == "reverse-proposal-reservation"
        assert binding["proposal_message_id"] == receipt.message_id
        assert binding["funding_message_id"]
        assert row[1:] == ("BURNED", None, None)
        assert not store._cooperation_handles
        assert store._connection.execute("SELECT next_client_seq FROM sessions").fetchone() == (5,)

    asyncio.run(exercise())


@pytest.mark.parametrize("failure", ["invalid plan", "expired", "slow validation"])
def test_post_anchor_failure_rolls_back_but_corrected_or_new_id_cannot_reanchor(
    reserved: ReservationCase, monkeypatch: pytest.MonkeyPatch, failure: str
) -> None:
    async def exercise() -> None:
        initial = reserved.document
        if failure == "invalid plan":
            initial = reserved.signed(transaction="00" * 60)
        elif failure == "expired":
            reserved.clock.advance(30)
        else:
            from rill_provider import live_session_store as module  # noqa: PLC0415

            verify = module.verify_cooperative_claim_proposal

            def slow(*args: Any) -> Any:
                result = verify(*args)
                reserved.clock.advance(30)
                return result

            monkeypatch.setattr(module, "verify_cooperative_claim_proposal", slow)
        async with reserved.store.reverse_operations.operation() as operation:
            with pytest.raises(LiveSessionStoreError):
                reserved.admit(operation, initial)
            assert reserved.store._connection.execute(
                "SELECT count(*) FROM cooperation_attempts"
            ).fetchone() == (0,)
            assert reserved.store._connection.execute(
                "SELECT next_client_seq FROM sessions"
            ).fetchone() == (4,)
            corrected = reserved.signed(
                message="ab" * 32, cooperation="bc" * 32, deadline=1_700_001_000
            )
            with pytest.raises(LiveSessionStoreError, match="unavailable"):
                reserved.admit(operation, corrected)
        attempt = reserved.store._reverse_proposals[reserved.origin.session_id]
        assert attempt.window is None or not attempt.window.time_allowed()

    asyncio.run(exercise())


def test_authenticated_conflict_durably_blocks_and_abandons(reserved: ReservationCase) -> None:
    async def exercise() -> None:
        async with reserved.store.reverse_operations.operation() as operation:
            reserved.admit(operation)
            conflict = reserved.signed(message="ab" * 32)
            with pytest.raises(SessionBlockedError):
                reserved.admit(operation, conflict)
        assert reserved.store._connection.execute("SELECT blocked FROM sessions").fetchone() == (1,)
        assert reserved.store._connection.execute(
            "SELECT state FROM cooperation_attempts"
        ).fetchone() == ("ABANDONED",)
        assert not reserved.store._reverse_proposals[
            reserved.origin.session_id
        ].window.time_allowed()

    asyncio.run(exercise())


def test_restart_replay_is_receipt_only_and_never_reconstructs_window(
    reserved: ReservationCase,
) -> None:
    async def exercise() -> None:
        async with reserved.store.reverse_operations.operation() as operation:
            reserved.admit(operation)
        reserved.store.close()
        with reserved.origin.acquire_at(
            reserved.origin.path,
            crypto=reserved.origin.crypto,
            public_keys=reserved.origin.crypto.crypto,
        ) as fresh:
            async with fresh.reverse_operations.operation() as operation:
                replay = json.loads(reserved.signed())
                replay["signature"] = reserved.origin.crypto.crypto.schnorr_sign(
                    (8).to_bytes(32, "big"),
                    unsigned_envelope_hash(
                        Envelope.model_validate_json(canonicalize(replay), strict=True)
                    ),
                    b"\x66" * 32,
                ).hex()
                assert replay["signature"] != json.loads(reserved.document)["signature"]
                receipt = fresh._admit_reverse_cooperative_proposal(
                    canonicalize(replay), operation=operation
                )
                assert receipt.replay
            assert not fresh._reverse_proposals
            assert not fresh._reverse_negotiations
            assert not fresh._cooperation_handles
            assert fresh._connection.execute(
                "SELECT state FROM cooperation_attempts"
            ).fetchone() == ("ABANDONED",)

    asyncio.run(exercise())


def test_uncertain_commit_preserves_burn_and_inbox_but_never_live_authority(
    reserved: ReservationCase,
) -> None:
    async def exercise() -> None:
        async with reserved.store.reverse_operations.operation() as operation:
            proxy = CommitThenFail(reserved.store._connection)
            proxy.armed = True
            reserved.store._connection = proxy
            with pytest.raises(StaleOwnerError, match="uncertain"):
                reserved.admit(operation)
            assert not reserved.store._reverse_proposals
        with reserved.origin.acquire_at(
            reserved.origin.path,
            crypto=reserved.origin.crypto,
            public_keys=reserved.origin.crypto.crypto,
        ) as fresh:
            assert fresh._connection.execute(
                "SELECT count(*) FROM cooperation_attempts"
            ).fetchone() == (1,)
            async with fresh.reverse_operations.operation() as operation:
                assert fresh._admit_reverse_cooperative_proposal(
                    reserved.document, operation=operation
                ).replay
            assert not fresh._reverse_proposals

    asyncio.run(exercise())


def test_child_and_stale_tokens_cannot_reserve(reserved: ReservationCase) -> None:
    async def exercise() -> None:
        async with reserved.store.reverse_operations.operation() as operation:

            async def child() -> None:
                reserved.admit(operation)

            with pytest.raises(LiveSessionStoreError, match="another task"):
                await asyncio.create_task(child())
        with pytest.raises(LiveSessionStoreError, match="not active"):
            reserved.admit(operation)
        assert reserved.store._connection.execute(
            "SELECT count(*) FROM cooperation_attempts"
        ).fetchone() == (0,)

    asyncio.run(exercise())


@pytest.mark.parametrize("failure", ["signature", "preimage", "sequence", "negotiation", "sender"])
def test_unauthenticated_or_context_invalid_input_creates_no_attempt(
    reserved: ReservationCase,
    failure: str,
) -> None:
    async def exercise() -> None:
        document = json.loads(reserved.document)
        if failure == "preimage":
            document["payload"]["payment_preimage"] = "00" * 32
        elif failure == "sequence":
            document["sequence"] = 6
        elif failure == "negotiation":
            reserved.store._reverse_negotiations.clear()
        elif failure == "sender":
            document["sender_session_key"] = reserved.origin.source["verification_context"][
                "provider_session_xonly_key"
            ]
        reserved.origin.crypto.permit_confirm(document)
        if failure == "signature":
            document["signature"] = "00" * 64
        async with reserved.store.reverse_operations.operation() as operation:
            with pytest.raises(LiveSessionStoreError):
                reserved.admit(operation, canonicalize(document))
        assert not reserved.store._reverse_proposals
        assert reserved.store._connection.execute(
            "SELECT count(*) FROM cooperation_attempts"
        ).fetchone() == (0,)
        assert reserved.store._connection.execute(
            "SELECT next_client_seq FROM sessions"
        ).fetchone() == (4,)

    asyncio.run(exercise())


@pytest.mark.parametrize(
    "failure", ["missing", "raw", "outpoint", "binding signature", "revision", "ambiguous"]
)
def test_invalid_owned_funding_association_rolls_back_and_stops_attempt(
    reserved: ReservationCase,
    failure: str,
) -> None:
    store = reserved.store
    message_id, document = next(
        (entry.message_id, json.loads(entry.canonical_bytes))
        for entry in store.pending_outbox()
        if b'"message_type":"funding_binding"' in entry.canonical_bytes
    )
    if failure == "missing":
        store._connection.execute("DELETE FROM outbox WHERE message_id=?", (message_id,))
    elif failure == "outpoint":
        store._connection.execute("UPDATE swaps SET funding_vout=1")
    else:
        if failure == "raw":
            document["payload"]["funding_transaction"] = "00" * 60
            store._connection.execute("UPDATE swaps SET funding_tx=?", (bytes(60),))
        elif failure == "binding signature":
            document["payload"]["funding_binding_signature"] = "00" * 64
        elif failure == "revision":
            document["payload"]["binding"]["binding_revision"] = 1
            document["payload"]["binding"]["replaces_txid"] = "aa" * 32
        elif failure == "ambiguous":
            document["message_id"] = "de" * 32
            document["sequence"] += 1
        envelope = Envelope.model_validate_json(canonicalize(document), strict=True)
        document["signature"] = reserved.origin.crypto.crypto.schnorr_sign(
            (9).to_bytes(32, "big"),
            unsigned_envelope_hash(envelope),
            b"\x44" * 32,
        ).hex()
        if failure == "ambiguous":
            store._connection.execute(
                "INSERT INTO outbox VALUES (?,?,?,?,?,?,'PENDING')",
                (
                    document["message_id"],
                    document["session_id"],
                    document["sequence"],
                    document["in_reply_to"],
                    canonicalize(document),
                    100,
                ),
            )
        else:
            store._connection.execute(
                "UPDATE outbox SET canonical_bytes=? WHERE message_id=?",
                (canonicalize(document), message_id),
            )

    async def exercise() -> None:
        async with store.reverse_operations.operation() as operation:
            with pytest.raises(LiveSessionStoreError):
                reserved.admit(operation)
        assert store._connection.execute(
            "SELECT count(*) FROM cooperation_attempts"
        ).fetchone() == (0,)
        assert store._connection.execute("SELECT next_client_seq FROM sessions").fetchone() == (4,)
        assert not store._reverse_proposals[reserved.origin.session_id].window.time_allowed()

    asyncio.run(exercise())


def test_forward_native_allocation_rejects_reverse_reservation_variant(
    reserved: ReservationCase,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def exercise() -> None:
        async with reserved.store.reverse_operations.operation() as operation:
            receipt = reserved.admit(operation)
        crypto = reserved.origin.crypto.crypto
        reserved.store._crypto = crypto
        never_allocate = Mock(side_effect=AssertionError("reservation must never allocate"))
        monkeypatch.setattr(crypto, "musig_begin", never_allocate)
        with pytest.raises(LiveSessionStoreError):
            reserved.store._begin_and_commit_cooperative_proposal(
                receipt.session_id,
                bytes.fromhex(receipt.cooperation_id),
                now=1_700_000_000,
            )
        never_allocate.assert_not_called()
        assert not reserved.store._cooperation_handles
        assert reserved.store._connection.execute(
            "SELECT local_nonce,peer_nonce FROM cooperation_attempts"
        ).fetchone() == (None, None)

    asyncio.run(exercise())


def test_another_store_gate_token_does_not_authorize_reservation(
    reserved: ReservationCase,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from test_live_session_store import Harness  # noqa: PLC0415

    other_path = tmp_path / "other"
    other_path.mkdir()
    other = Harness(other_path, monkeypatch)
    other.provision()

    async def exercise() -> None:
        with other.acquire() as owner:
            async with owner.reverse_operations.operation() as operation:
                with pytest.raises(LiveSessionStoreError, match="not active"):
                    reserved.admit(operation)
        assert not reserved.store._reverse_proposals

    asyncio.run(exercise())


@pytest.mark.parametrize("state", ["BURNED", "ABANDONED"])
def test_permanent_attempt_row_prevents_changed_id_retry_even_without_window_cache(
    reserved: ReservationCase,
    state: str,
) -> None:
    async def exercise() -> None:
        async with reserved.store.reverse_operations.operation() as operation:
            reserved.admit(operation)
            # Deliberate fault injection proves the permanent SQL predicate is
            # independent of the process-local cache and active-state index.
            reserved.store._reverse_proposals.clear()
            reserved.store._connection.execute("UPDATE cooperation_attempts SET state=?", (state,))
            following = json.loads(reserved.signed(message="ab" * 32, cooperation="bc" * 32))
            following["sequence"] = 5
            reserved.origin.crypto.permit_confirm(following)
            with pytest.raises(LiveSessionStoreError, match="unavailable"):
                reserved.admit(operation, canonicalize(following))
        assert reserved.store._connection.execute(
            "SELECT count(*) FROM cooperation_attempts"
        ).fetchone() == (1,)
        assert reserved.store._connection.execute(
            "SELECT next_client_seq FROM sessions"
        ).fetchone() == (5,)

    asyncio.run(exercise())


@pytest.mark.parametrize("version", [1, 2])
def test_version_discriminator_alone_blocks_otherwise_allocatable_forward_attempt(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    version: int,
) -> None:
    """Synthetic forward history, real native allocation in the version-1 control."""
    from rill_core.wire.hashes import COOPERATIVE_CLAIM_FEATURE  # noqa: PLC0415
    from rill_crypto import Context  # noqa: PLC0415
    from test_cooperation_burn import Harness, _featured_paid_swap  # noqa: PLC0415

    from rill_provider import live_session_store as module  # noqa: PLC0415

    harness = Harness(tmp_path, monkeypatch)
    harness.policy = replace(harness.policy, features=frozenset({COOPERATIVE_CLAIM_FEATURE}))
    harness.provision()
    with (
        Context(library_path=os.environ["RILL_CRYPTO_LIBRARY"]) as crypto,
        harness.acquire() as store,
    ):
        session, plan, _ = _featured_paid_swap(harness, store)
        store._public_keys = crypto
        store._crypto = crypto
        monkeypatch.setattr(module, "_new_session_scalar", lambda: (5).to_bytes(32, "big"))
        with store._write() as connection:
            store._contract_key(connection, session)
        cooperation_id = b"\xc1" * 32
        store._burn_cooperative_claim(
            session, cooperation_id, plan, now=1000, deadline_at=1020, deadline_height=1100
        )
        binding = json.loads(
            store._connection.execute("SELECT binding FROM cooperation_attempts").fetchone()[0]
        )
        binding["version"] = version  # No state, role, key, transaction, or signature changes.
        store._connection.execute(
            "UPDATE cooperation_attempts SET binding=?", (canonicalize(binding),)
        )
        if version == 1:
            assert store._begin_and_commit_cooperative_proposal(session, cooperation_id, now=1001)
            assert store._cooperation_handles
            assert store._connection.execute(
                "SELECT state FROM cooperation_attempts"
            ).fetchone() == ("NONCE_READY",)
        else:
            never_allocate = Mock(side_effect=AssertionError("unknown version must never allocate"))
            monkeypatch.setattr(crypto, "musig_begin", never_allocate)
            with pytest.raises(LiveSessionStoreError):
                store._begin_and_commit_cooperative_proposal(session, cooperation_id, now=1001)
            never_allocate.assert_not_called()
            assert not store._cooperation_handles


@pytest.mark.parametrize("failure", ["payload", "noncanonical"])
def test_rejected_secret_input_does_not_retain_local_parser_exception_chain(
    reserved: ReservationCase,
    failure: str,
) -> None:
    async def exercise() -> None:
        document = json.loads(reserved.document)
        secret = document["payload"]["payment_preimage"]
        if failure == "payload":
            document["payload"]["payment_preimage"] = secret + "invalid"
        reserved.origin.crypto.permit_confirm(document)
        raw = canonicalize(document)
        if failure == "noncanonical":
            raw += b"\n"
        async with reserved.store.reverse_operations.operation() as operation:
            with pytest.raises(LiveSessionStoreError) as observed:
                reserved.admit(operation, raw)
        assert secret not in str(observed.value)
        assert observed.value.__context__ is None
        assert observed.value.__cause__ is None
        assert not reserved.store._reverse_proposals

    asyncio.run(exercise())
