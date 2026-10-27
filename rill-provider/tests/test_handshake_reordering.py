"""A session's first request may reach the provider before its confirm.

Clients send the confirm and their first request back to back. Relays replay
stored gift wraps ordered by their randomized ``created_at``, so after a
(re)subscription the request can arrive first. It is held, not refused, and
answered once the confirm is admitted.
"""

from __future__ import annotations

import asyncio
import copy
import json
import os
from typing import TYPE_CHECKING, Any

import pytest
from pyrage import x25519  # type: ignore[import-untyped]
from rill_core.wire.hashes import unsigned_envelope_hash
from rill_core.wire.messages import Envelope
from test_handshake_service import (
    CLIENT_SECRET,
    NATIVE,
    _Identity,
    _Relay,
    _signed_confirm,
    _signed_quote_request,
)
from test_live_session_store import Harness, _bytes

from rill_provider import handshake_service
from rill_provider.handshake_service import HandshakeService, ServicePolicy

if TYPE_CHECKING:
    from pathlib import Path

    from rill_crypto import Context


@pytest.fixture
def harness(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Harness:
    return Harness(tmp_path, monkeypatch)


def _policy(harness: Harness, **changed: Any) -> ServicePolicy:  # noqa: ANN401
    arguments: dict[str, Any] = {
        "network": harness.network,
        "profiles": ("btc-to-ln/v1",),
        "amount_bands": ((1000, 100_000),),
        "base_fee_sat": 50,
        "proportional_millionths": 1000,
        "slot": "regtest-main",
        "relay_urls": ("ws://fake/",),
    }
    return ServicePolicy(**(arguments | changed))


def _event(number: int) -> bytes:
    return json.dumps({"id": f"{number:064x}"}).encode()


def test_store_reports_only_unblocked_sessions_awaiting_their_confirm(harness: Harness) -> None:
    harness.provision()
    session_id = json.loads(harness.init)["session_id"]
    with harness.acquire() as store:
        assert store.session_awaiting_confirm(session_id) is False  # unknown
        store.reserve(harness.init, now=1000)
        store.commit_accept(harness.accept)
        assert store.session_awaiting_confirm(session_id) is True
        store._connection.execute(  # noqa: SLF001 - fixture-only conflict evidence
            "UPDATE sessions SET blocked=1 WHERE session_id=?", (session_id,)
        )
        assert store.session_awaiting_confirm(session_id) is False
        store._connection.execute(  # noqa: SLF001
            "UPDATE sessions SET blocked=0 WHERE session_id=?", (session_id,)
        )
        store.admit_confirm(harness.confirm)
        assert store.session_awaiting_confirm(session_id) is False


def test_held_frames_are_bounded_per_session_and_overall(harness: Harness) -> None:
    harness.provision()
    with harness.acquire() as store:
        service = HandshakeService(store, _Identity(), object(), _policy(harness))  # type: ignore[arg-type]
        state = service._state  # noqa: SLF001
        for number in (1, 2, 1, 3):  # the repeat is held once
            state.seen[f"{number:064x}"] = None
            service._defer("aa" * 32, _event(number), 1000)  # noqa: SLF001
        # Two per session, oldest dropped; a dropped frame is no longer "seen",
        # so a relay replay can deliver it again.
        assert [held[1] for held in state.deferred] == [f"{2:064x}", f"{3:064x}"]
        assert not state.seen
        limit = handshake_service.MAX_DEFERRED_EVENTS
        for number in range(10, 10 + limit):
            service._defer(f"{number:064x}", _event(number), 1001)  # noqa: SLF001
        assert len(state.deferred) == limit
        assert state.deferred[0][1] == f"{4 + 6:064x}"  # the two oldest made room
        assert state.deferred[-1][1] == f"{9 + limit:064x}"


def test_held_frames_expire_with_the_handshake_timeout(harness: Harness) -> None:
    harness.provision()
    clock = [10_000.0]
    policy = _policy(harness, handshake_timeout=100)
    with harness.acquire() as store:
        service = HandshakeService(store, _Identity(), object(), policy, clock=lambda: clock[0])  # type: ignore[arg-type]
        service._defer("aa" * 32, _event(1), 10_000)  # noqa: SLF001
        relay = _Relay(accept=True)
        clock[0] += 99
        asyncio.run(service.tick([relay]))
        assert len(service._state.deferred) == 1  # noqa: SLF001
        clock[0] += 1
        asyncio.run(service.tick([relay]))
        assert service._state.deferred == []  # noqa: SLF001


class _OrderedRelay(_Relay):
    def __init__(self) -> None:
        super().__init__(accept=True)
        self.log: list[str] = []

    async def publish(self, event: bytes) -> bool:
        self.log.append("publish")
        return await super().publish(event)

    async def subscribe(self, filters: list[dict[str, Any]]) -> None:
        self.log.append("subscribe")
        await super().subscribe(filters)


@pytest.mark.native_crypto
@NATIVE
def test_request_before_confirm_is_answered_once_the_confirm_arrives(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from rill_crypto import Context  # noqa: PLC0415

    from rill_provider._nip59_receive import _decode_gift_wrap_candidate  # noqa: PLC0415
    from rill_provider._nip59_send import _wrap_envelope  # noqa: PLC0415
    from rill_provider.provider_identity import ProviderIdentity  # noqa: PLC0415

    harness = Harness(tmp_path, monkeypatch)
    harness.provision()
    unlock = x25519.Identity.generate()

    async def scenario(crypto: Context) -> None:
        with monkeypatch.context() as patch:
            patch.setattr(
                "rill_provider.provider_identity.secrets.token_bytes",
                lambda _n: (1).to_bytes(32, "big"),
            )
            ProviderIdentity.provision(
                tmp_path / "id.age", recipient=str(unlock.to_public()), crypto=crypto
            )
        signer = ProviderIdentity.load(
            tmp_path / "id.age",
            custody_identity=str(unlock),
            expected_xonly_public_key=harness.identity,
            crypto=crypto,
        )
        client_key = crypto.public_key(CLIENT_SECRET)[1:].hex()

        def wrap(envelope: dict[str, Any] | bytes, recipient: str) -> bytes:
            body = envelope if isinstance(envelope, bytes) else _bytes(envelope)
            return _wrap_envelope(
                body,
                sender_session_secret=CLIENT_SECRET,
                recipient_xonly_key=recipient,
                crypto=crypto,
            )

        def opened(event: bytes) -> Envelope:
            return _decode_gift_wrap_candidate(
                event,
                recipient_mailbox_secret=CLIENT_SECRET,
                expected_recipient_xonly_key=client_key,
                expected_network=harness.network,
                expected_profile_id="btc-to-ln/v1",
                crypto=crypto,
            ).envelope

        with harness.acquire_at(harness.path, crypto=crypto, public_keys=crypto) as store:
            service = HandshakeService(
                store, signer, crypto, _policy(harness), chain_tip=lambda: 500
            )
            relay = _OrderedRelay()
            await service.tick([relay])
            announcement = json.loads(relay.published[-1])
            (epoch,) = json.loads(announcement["content"])["advertisement"][
                "epoch_inbox_xonly_keys"
            ]
            before = len(relay.log)
            assert await service.handle(wrap(harness.init, epoch), [relay]) == "init-accepted"
            # The new mailbox is subscribed before the accept is published.
            assert relay.log[before:] == ["subscribe", "publish"]
            accept = opened(relay.published[-1])
            assert accept.message_type == "handshake_accept"
            confirm = _signed_confirm(harness, accept, crypto)
            request = _signed_quote_request(harness, crypto)
            mailbox = accept.sender_session_key

            published = len(relay.published)
            early = wrap(request, mailbox)
            assert await service.handle(early, [relay]) == "deferred"
            assert len(relay.published) == published  # no answer before the confirm

            # A malformed confirm is not held: it is refused like any request.
            forged = copy.deepcopy(confirm)
            forged["payload"]["handshake_hash"] = "00" * 32
            forged["signature"] = None
            digest = unsigned_envelope_hash(Envelope.model_validate_json(json.dumps(forged)))
            forged["signature"] = crypto.schnorr_sign(CLIENT_SECRET, digest, b"\x68" * 32).hex()
            assert await service.handle(wrap(forged, mailbox), [relay]) == "refused"
            assert len(service._state.deferred) == 1  # noqa: SLF001

            assert await service.handle(wrap(confirm, mailbox), [relay]) == "confirm-admitted"
            offer = opened(relay.published[-1])
            assert (offer.message_type, offer.in_reply_to) == ("quote_offer", request["message_id"])
            assert service._state.deferred == []  # noqa: SLF001
            # Later relay copies are deduplicated or answered from the record.
            assert await service.handle(early, [relay]) == "duplicate"
            assert await service.handle(wrap(request, mailbox), [relay]) == "request-replay"

    with Context(library_path=os.environ["RILL_CRYPTO_LIBRARY"]) as crypto:
        asyncio.run(scenario(crypto))
