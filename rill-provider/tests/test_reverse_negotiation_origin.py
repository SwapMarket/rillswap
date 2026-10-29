"""Preparatory owner-local provenance, not production reverse acceptance readiness."""

from __future__ import annotations

import asyncio
import copy
import hashlib
import multiprocessing
from dataclasses import replace
from pathlib import Path
from typing import TYPE_CHECKING
from unittest.mock import AsyncMock, Mock

import pytest
import test_live_session_store as fixtures
from rill_core.wire.canonical import canonicalize
from rill_core.wire.hashes import (
    COOPERATIVE_CLAIM_FEATURE,
    EPOCH_SESSION_FEATURE,
    client_acceptance_hash,
    contract_hash,
    handshake_hash,
    handshake_init_hash,
    provider_terms_hash,
)
from rill_core.wire.messages import (
    ClientAcceptance,
    Envelope,
    HandshakeAccept,
    HandshakeInit,
    ProviderTerms,
)
from rill_core.wire.quotes import TermsOfferPayload
from test_handshake_hold_invoice import POLICY
from test_handshake_reverse_gate import CommitThenFail
from test_payment_reconciliation import Signer
from test_reverse_quote_policy import HOLD, REVERSE_FIRM

from rill_provider.handshake_service import HandshakeService
from rill_provider.live_session_store import (
    AcceptSwap,
    Answer,
    LiveSessionStoreError,
    SessionBlockedError,
    SessionExpiredError,
    StaleOwnerError,
)
from rill_provider.quote_policy import FirmSigner
from rill_provider.settlement_policy import answer_client_request

if TYPE_CHECKING:
    from rill_provider.live_session_store import LiveSessionStore

# These tests deliberately inspect the private provenance and transaction seams.
# ruff: noqa: SLF001


class OriginSigner(Signer):
    def schnorr_verify(self, key: bytes, digest: bytes, signature: bytes) -> None:
        self.harness.crypto.schnorr_verify(key, digest, signature)


class OriginHarness(fixtures.Harness):
    def __init__(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, *, featured: bool = True
    ) -> None:
        monkeypatch.setattr(
            fixtures,
            "FIXTURE",
            Path(fixtures.__file__).parent / "fixtures/initial-ln-to-btc-no-prepayment-v1.json",
        )
        super().__init__(tmp_path, monkeypatch)
        features = [COOPERATIVE_CLAIM_FEATURE] if featured else []
        bound = sorted({*features, EPOCH_SESSION_FEATURE})  # every session is epoch-bound
        self.policy = replace(self.policy, profile="ln-to-btc/v1", features=frozenset(bound))
        self.scalar = (9).to_bytes(32, "big")
        context = self.source["verification_context"]
        context["handshake_init"]["required_features"] = bound
        context["handshake_accept"]["required_features"] = bound
        initiation = HandshakeInit.model_validate_json(
            canonicalize(context["handshake_init"]), strict=True
        )
        context["handshake_accept"]["handshake_init_hash"] = handshake_init_hash(initiation).hex()
        acceptance = HandshakeAccept.model_validate_json(
            canonicalize(context["handshake_accept"]), strict=True
        )
        context["handshake_hash"] = handshake_hash(initiation, acceptance).hex()
        self.envelopes[2]["payload"]["handshake_hash"] = context["handshake_hash"]
        for envelope in self.envelopes:
            envelope["required_features"] = features
        # This is an explicit cryptographic test double. Real store admission,
        # transcript/sequence checks, custody, COMMIT, and rollback remain live.
        self.crypto = fixtures.PinnedCrypto(self.source, self.envelopes)
        self.init, self.accept, self.confirm = map(canonicalize, self.envelopes)
        self.session_id = initiation.session_id
        self.monkeypatch = monkeypatch
        self.featured = featured
        self.provision()

    def service(self, store: LiveSessionStore) -> HandshakeService:
        signer, hold = OriginSigner(self), Mock()
        invoice = "lnbcrt1007u1hold"
        hold.add.return_value = invoice
        binding = HOLD.model_copy(
            update={
                "bolt11_sha256": hashlib.sha256(invoice.encode()).hexdigest(),
                "expires_at": 1_700_003_600,
            }
        )
        service = HandshakeService(
            store,
            Mock(),
            signer,
            replace(POLICY, network=self.network),
            clock=lambda: 1_700_000_000,
            invoice_decoder=lambda _invoice: binding,
            hold_invoices=hold,
        )
        firm = FirmSigner(
            network=self.network,
            provider_identity_key=self.identity,
            provider_destination_script=POLICY.provider_destination_script,
            sign=lambda terms: signer.schnorr_sign(
                (1).to_bytes(32, "big"), provider_terms_hash(terms), b"\0" * 32
            ).hex(),
        )
        self.monkeypatch.setattr(service, "_firm_signer", lambda: firm)
        self.monkeypatch.setattr(service, "_send_pending", AsyncMock(return_value=None))

        def featured_reply(*args: object) -> Answer:
            reply = answer_client_request(*args)
            if not self.featured or reply.message_type != "terms_offer":
                return reply
            # This fixture signs the negotiated contract directly to
            # isolate store provenance from the quote policy.
            offer = TermsOfferPayload.model_validate_json(canonicalize(reply.payload), strict=True)
            terms = offer.terms.contract_terms.model_copy(
                update={"required_features": (COOPERATIVE_CLAIM_FEATURE,)}
            )
            provider = ProviderTerms(
                contract_hash=contract_hash(terms).hex(),
                contract_terms=terms,
                handshake_hash=offer.terms.handshake_hash,
            )
            offer = offer.model_copy(
                update={
                    "terms": provider,
                    "provider_terms_signature": signer.schnorr_sign(
                        (1).to_bytes(32, "big"), provider_terms_hash(provider), b"\0" * 32
                    ).hex(),
                }
            )
            return replace(
                reply, payload=offer.model_dump(mode="json"), contract_hash=provider.contract_hash
            )

        self.monkeypatch.setattr(
            "rill_provider.handshake_service.answer_client_request", featured_reply
        )
        service._state.tip = 850
        return service

    def acceptance(self, store: LiveSessionStore) -> tuple[HandshakeService, bytes, str]:
        service = self.service(store)
        request = copy.deepcopy(self.envelopes[2])
        request.update(
            message_type="quote_request",
            sequence=2,
            message_id="66" * 32,
            in_reply_to=None,
            payload=REVERSE_FIRM | {"extensions": {}},
            signature="55" * 64,
        )
        self.crypto.permit_confirm(request)
        assert (
            asyncio.run(service._answer(canonicalize(request), (), 1_700_000_000))
            == "request-answered"
        )
        response = next(
            Envelope.model_validate_json(entry.canonical_bytes, strict=True)
            for entry in store.pending_outbox()
            if b'"message_type":"terms_offer"' in entry.canonical_bytes
        )
        offer = TermsOfferPayload.model_validate_json(canonicalize(response.payload), strict=True)
        acceptance = ClientAcceptance(
            contract_hash=offer.terms.contract_hash,
            handshake_hash=offer.terms.handshake_hash,
            session_id=self.session_id,
            client_session_xonly_key=request["sender_session_key"],
            provider_session_xonly_key=response.sender_session_key,
        )
        request.update(
            message_type="terms_accept",
            sequence=3,
            message_id="67" * 32,
            in_reply_to=response.message_id,
            contract_hash=offer.terms.contract_hash,
            payload={
                "acceptance": acceptance.model_dump(mode="json"),
                "client_acceptance_signature": Signer(self)
                .schnorr_sign(
                    (8).to_bytes(32, "big"), client_acceptance_hash(acceptance), b"\0" * 32
                )
                .hex(),
            },
        )
        self.crypto.permit_confirm(request)
        return service, canonicalize(request), offer.terms.contract_hash


@pytest.fixture
def origin(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> OriginHarness:
    return OriginHarness(tmp_path, monkeypatch)


def _handshake(store: LiveSessionStore, origin: OriginHarness) -> None:
    store.reserve(origin.initiation)
    store.commit_accept(origin.accept)
    store.admit_confirm(origin.confirm)


def _isolated_provenance_acceptance(
    origin: OriginHarness,
    store: LiveSessionStore,
) -> tuple[HandshakeService, bytes, str]:
    """Opt into bookkeeping only on this store, without enabling acceptance.

    The omitted production guard also authenticates contract bindings and
    signatures. These component tests assume that guard succeeds, not that a
    future reverse implementation is equivalent or ready for signing.
    """
    original = store._admit_claim_arbitration

    def isolated(
        connection: object, request: Envelope, reply: Answer, replied: object, now: int
    ) -> None:
        if request.profile_id != "ln-to-btc/v1":
            original(connection, request, reply, replied, now)
            return
        assert request.message_type == "terms_accept"
        assert reply.message_type == "ack"
        assert isinstance(reply.effect, AcceptSwap)
        assert reply.effect.contract_hash == request.contract_hash
        # No SQL, provenance, or native signing mutation occurs in this stub.

    origin.monkeypatch.setattr(store, "_admit_claim_arbitration", isolated)
    return origin.acceptance(store)


def test_successful_same_owner_negotiation_and_replays_never_refresh_origin(
    origin: OriginHarness,
) -> None:
    with origin.acquire() as store:
        _handshake(store, origin)
        service, document, digest = _isolated_provenance_acceptance(origin, store)
        assert not store._has_original_reverse_negotiation(origin.session_id, digest)
        assert asyncio.run(service._answer(document, (), 1_700_000_000)) == "request-answered"
        assert store._has_original_reverse_negotiation(origin.session_id, digest)
        original = store._reverse_negotiations[origin.session_id]
        store.commit_accept(origin.accept)
        store.admit_confirm(origin.confirm)
        assert asyncio.run(service._answer(document, (), 1_700_000_000)) == "request-replay"
        assert store._reverse_negotiations[origin.session_id] is original
        assert store._has_original_reverse_negotiation(origin.session_id, digest)
        assert not store._has_original_reverse_negotiation(origin.session_id, "ff" * 32)
    with origin.acquire() as fresh:
        assert not fresh._has_original_reverse_negotiation(origin.session_id, digest)
        assert not fresh._reverse_negotiations


@pytest.mark.parametrize("stage", ["accept", "confirm", "terms"])
def test_restart_never_reconstructs_origin_from_accept_confirm_or_accepted_swap(
    origin: OriginHarness, stage: str
) -> None:
    with origin.acquire() as store:
        store.reserve(origin.initiation)
        store.commit_accept(origin.accept)
        if stage != "accept":
            store.admit_confirm(origin.confirm)
        if stage == "terms":
            service, document, digest = _isolated_provenance_acceptance(origin, store)
            asyncio.run(service._answer(document, (), 1_700_000_000))
            assert store._has_original_reverse_negotiation(origin.session_id, digest)
    with origin.acquire() as fresh:
        fresh.commit_accept(origin.accept)  # Replay cannot seed origin.
        fresh.admit_confirm(origin.confirm)
        if stage == "terms":
            service = origin.service(fresh)
            assert asyncio.run(service._answer(document, (), 1_700_000_000)) == "request-replay"
        else:
            service, document, digest = _isolated_provenance_acceptance(origin, fresh)
            assert asyncio.run(service._answer(document, (), 1_700_000_000)) == "request-answered"
        assert not fresh._has_original_reverse_negotiation(origin.session_id, digest)
        assert not fresh._reverse_negotiations


@pytest.mark.parametrize("stage", ["accept", "terms"])
def test_successful_commit_reported_failed_never_creates_or_retains_origin(
    origin: OriginHarness, stage: str
) -> None:
    with origin.acquire() as store:
        store.reserve(origin.initiation)
        if stage == "terms":
            store.commit_accept(origin.accept)
            store.admit_confirm(origin.confirm)
            service, document, _digest = _isolated_provenance_acceptance(origin, store)
        proxy = CommitThenFail(store._connection)
        proxy.armed = stage == "accept"
        store._connection = proxy  # type: ignore[assignment]
        if stage == "terms":
            original_answer = store.answer_request

            def admit(*args: object, **kwargs: object) -> object:
                proxy.armed = True
                return original_answer(*args, **kwargs)

            origin.monkeypatch.setattr(store, "answer_request", admit)

        def fail() -> None:
            if stage == "accept":
                store.commit_accept(origin.accept)
            else:
                asyncio.run(service._answer(document, (), 1_700_000_000))

        with pytest.raises(StaleOwnerError, match="uncertain"):
            fail()
        assert not store._reverse_negotiations
    with origin.acquire() as fresh:
        fresh.commit_accept(origin.accept)  # The actual committed accept is a replay.
        assert not fresh._reverse_negotiations
        if stage == "terms":
            assert fresh._connection.execute("SELECT count(*) FROM swaps").fetchone() == (1,)
            assert not fresh._has_original_reverse_negotiation(origin.session_id, _digest)


def test_close_while_pinned_fences_origin_immediately(origin: OriginHarness) -> None:
    with origin.acquire() as store:
        _handshake(store, origin)
        service, document, digest = _isolated_provenance_acceptance(origin, store)
        asyncio.run(service._answer(document, (), 1_700_000_000))
        assert store._has_original_reverse_negotiation(origin.session_id, digest)
        with store.retain_owner():
            store.close()
            assert not store._has_original_reverse_negotiation(origin.session_id, digest)
            assert not store._reverse_negotiations


def test_signed_conflict_invalidates_consumption_of_retained_origin(origin: OriginHarness) -> None:
    with origin.acquire() as store:
        _handshake(store, origin)
        service, document, digest = _isolated_provenance_acceptance(origin, store)
        asyncio.run(service._answer(document, (), 1_700_000_000))
        conflict = Envelope.model_validate_json(document, strict=True).model_copy(
            update={"message_id": "68" * 32}
        )
        origin.crypto.permit_confirm(conflict.model_dump(mode="json"))
        with pytest.raises(SessionBlockedError):
            asyncio.run(
                service._answer(canonicalize(conflict.model_dump(mode="json")), (), 1_700_000_000)
            )
        assert not store._has_original_reverse_negotiation(origin.session_id, digest)


def test_nonfeatured_reverse_negotiation_has_no_cooperative_origin(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    origin = OriginHarness(tmp_path, monkeypatch, featured=False)
    with origin.acquire() as store:
        _handshake(store, origin)
        service, document, digest = origin.acceptance(store)
        asyncio.run(service._answer(document, (), 1_700_000_000))
        assert not store._has_original_reverse_negotiation(origin.session_id, digest)
        assert not store._reverse_negotiations


def test_production_featured_reverse_acceptance_is_authenticated_without_claim_arbitration(
    origin: OriginHarness,
) -> None:
    with origin.acquire() as store:
        _handshake(store, origin)
        service, document, digest = origin.acceptance(store)  # Deliberately no isolated seam.
        asyncio.run(service._answer(document, (), 1_700_000_000))
        assert store._connection.execute("SELECT count(*) FROM swaps").fetchone() == (1,)
        assert any(
            b'"message_type":"ack"' in entry.canonical_bytes for entry in store.pending_outbox()
        )
        assert store._has_original_reverse_negotiation(origin.session_id, digest)
        # The client claims LN to BTC swaps: no provider claim is arbitrated.
        assert store._connection.execute("SELECT count(*) FROM claim_arbitration").fetchone() == (
            0,
        )
        assert not store.admitted_featured_claim(origin.session_id, digest)


def test_fresh_accept_without_confirmation_cannot_create_final_origin(
    origin: OriginHarness,
) -> None:
    with origin.acquire() as store:
        store.reserve(origin.initiation)
        store.commit_accept(origin.accept)
        with pytest.raises(LiveSessionStoreError, match="confirmed session"):
            origin.acceptance(store)
        assert store._reverse_negotiations[origin.session_id].contract_hash is None


def _inherited_origin(store: LiveSessionStore, session_id: str, digest: str, queue: object) -> None:
    queue.put(store._has_original_reverse_negotiation(session_id, digest))
    store.close()
    queue.put(bool(store._reverse_negotiations))


def test_fork_cannot_consume_or_clear_parents_origin(origin: OriginHarness) -> None:
    with origin.acquire() as store:
        _handshake(store, origin)
        service, document, digest = _isolated_provenance_acceptance(origin, store)
        asyncio.run(service._answer(document, (), 1_700_000_000))
        context = multiprocessing.get_context("fork")
        queue = context.Queue()
        child = context.Process(
            target=_inherited_origin, args=(store, origin.session_id, digest, queue)
        )
        child.start()
        child.join(30)
        assert child.exitcode == 0
        assert queue.get(timeout=5) is False
        assert queue.get(timeout=5) is False
        assert store._has_original_reverse_negotiation(origin.session_id, digest)


def test_idle_expiry_removes_preliminary_origin_after_commit_without_reconstruction(
    origin: OriginHarness,
) -> None:
    with origin.acquire() as store:
        _handshake(store, origin)
        assert origin.session_id in store._reverse_negotiations
        active_at = store._connection.execute(
            "SELECT active_at FROM sessions WHERE session_id=?",
            (origin.session_id,),
        ).fetchone()[0]
        assert store.expire_idle(now=active_at + 101, idle_timeout=100) == 1
        assert origin.session_id not in store._reverse_negotiations
        assert not store._has_original_reverse_negotiation(origin.session_id, "ff" * 32)
        with pytest.raises(SessionExpiredError):
            store.reserve(origin.initiation)
        assert not store._reverse_negotiations
