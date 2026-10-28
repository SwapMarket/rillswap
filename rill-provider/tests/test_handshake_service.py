"""Full provider handshake over a relay: announce, init, accept, confirm."""

from __future__ import annotations

import asyncio
import copy
import hashlib
import json
import logging
import os
from dataclasses import replace
from types import SimpleNamespace
from typing import TYPE_CHECKING, Any
from unittest.mock import Mock

import pytest
from fake_relay import FakeRelay
from pyrage import x25519  # type: ignore[import-untyped]
from rill_core.wire.hashes import handshake_hash, unsigned_envelope_hash
from rill_core.wire.messages import Envelope, HandshakeAccept, HandshakeInit
from rill_core.wire.quotes import QuoteOffer
from test_live_session_store import Harness, _bytes

from rill_provider.handshake_service import (
    HandshakeService,
    ServiceHealth,
    ServicePolicy,
    _disposition_level,
)
from rill_provider.live_session_store import (
    LiveSessionStore,
    LiveSessionStoreError,
    SessionExpiredError,
    StaleOwnerError,
)
from rill_provider.quote_policy import ClaimFeeRate
from rill_provider.relay_client import RelayConnection

if TYPE_CHECKING:
    from pathlib import Path

    from rill_crypto import Context

NATIVE = pytest.mark.skipif(
    os.environ.get("RILLSWAP_RUN_NATIVE_CRYPTO") != "1",
    reason="set RILLSWAP_RUN_NATIVE_CRYPTO=1 with pinned native library",
)
CLIENT_SECRET = (2).to_bytes(32, "big")  # Fixture-only public scalar of the client key.


def test_policy_refuses_schedules_that_strand_epochs() -> None:
    with pytest.raises(ValueError, match="schedule"):
        ServicePolicy(
            network=None,  # type: ignore[arg-type]
            profiles=("btc-to-ln/v1",),
            amount_bands=((1000, 2000),),
            base_fee_sat=1,
            proportional_millionths=1,
            slot="s",
            relay_urls=("ws://r/",),
            announcement_lifetime=10,
            announcement_refresh=10,
        )


def _signed_confirm(harness: Harness, accept: Envelope, crypto: Context) -> dict[str, Any]:
    selection = HandshakeAccept.model_validate_json(json.dumps(accept.payload["accept"]))
    init = HandshakeInit.model_validate_json(json.dumps(harness.envelopes[0]["payload"]))
    confirm = copy.deepcopy(harness.envelopes[2])
    confirm["in_reply_to"] = accept.message_id
    confirm["payload"]["provider_session_xonly_key"] = accept.sender_session_key
    confirm["payload"]["handshake_hash"] = handshake_hash(init, selection).hex()
    confirm["signature"] = None
    unsigned = unsigned_envelope_hash(Envelope.model_validate_json(json.dumps(confirm)))
    confirm["signature"] = crypto.schnorr_sign(CLIENT_SECRET, unsigned, b"\x66" * 32).hex()
    return confirm


def _signed_quote_request(harness: Harness, crypto: Context) -> dict[str, Any]:
    request = copy.deepcopy(harness.envelopes[2])
    request.update(
        message_id="21" * 32,
        sequence=2,
        in_reply_to=None,
        message_type="quote_request",
        payload={
            "kind": "btc-to-ln",
            "mode": "indicative",
            "lightning_principal_sat": "50000",
            "extensions": {},
        },
        signature=None,
    )
    unsigned = unsigned_envelope_hash(Envelope.model_validate_json(json.dumps(request)))
    request["signature"] = crypto.schnorr_sign(CLIENT_SECRET, unsigned, b"\x67" * 32).hex()
    return request


async def _next(connection: RelayConnection, predicate: object) -> bytes:
    async for event in connection.events():
        if predicate(json.loads(event)):  # type: ignore[operator]
            return event
    raise AssertionError("relay closed")


@pytest.mark.native_crypto
@NATIVE
def test_native_handshake_through_relay_and_service(  # noqa: PLR0915 - one end-to-end story
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
        relay = FakeRelay()
        url = await relay.start()
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
        policy = ServicePolicy(
            network=harness.network,
            profiles=("btc-to-ln/v1",),
            amount_bands=((1000, 100_000),),
            base_fee_sat=50,
            proportional_millionths=1000,
            slot="regtest-main",
            relay_urls=(url,),
        )
        stop = asyncio.Event()
        client_key = crypto.public_key(CLIENT_SECRET)[1:].hex()
        try:
            with harness.acquire_at(harness.path, crypto=crypto, public_keys=crypto) as store:
                service = HandshakeService(store, signer, crypto, policy, chain_tip=lambda: 500)
                runner = asyncio.create_task(service.run(stop, tick_seconds=0.2))
                async with RelayConnection(url) as client:
                    await client.subscribe(
                        [{"kinds": [39417]}, {"kinds": [1059], "#p": [client_key]}]
                    )
                    announcement = json.loads(
                        await asyncio.wait_for(_next(client, lambda e: e["kind"] == 39417), 10)
                    )
                    advertisement = json.loads(announcement["content"])["advertisement"]
                    (epoch,) = advertisement["epoch_inbox_xonly_keys"]
                    assert advertisement["transport_endpoints"] == [url]
                    assert service.health().relays_connected == 1  # the relays down alert
                    await relay.inject(
                        _wrap_envelope(
                            harness.init,
                            sender_session_secret=CLIENT_SECRET,
                            recipient_xonly_key=epoch,
                            crypto=crypto,
                        )
                    )
                    wrap = await asyncio.wait_for(_next(client, lambda e: e["kind"] == 1059), 10)
                    accept = _decode_gift_wrap_candidate(
                        wrap,
                        recipient_mailbox_secret=CLIENT_SECRET,
                        expected_recipient_xonly_key=client_key,
                        expected_network=harness.network,
                        expected_profile_id="btc-to-ln/v1",
                        crypto=crypto,
                    ).envelope
                    confirm = _signed_confirm(harness, accept, crypto)
                    await relay.inject(
                        _wrap_envelope(
                            _bytes(confirm),
                            sender_session_secret=CLIENT_SECRET,
                            recipient_xonly_key=accept.sender_session_key,
                            crypto=crypto,
                        )
                    )
                    for _ in range(100):
                        if not store.pending_outbox():
                            break
                        await asyncio.sleep(0.05)
                    assert store.pending_outbox() == ()
                    assert store.awaiting_confirm_mailboxes() == ()
                    request = _signed_quote_request(harness, crypto)
                    await relay.inject(
                        _wrap_envelope(
                            _bytes(request),
                            sender_session_secret=CLIENT_SECRET,
                            recipient_xonly_key=accept.sender_session_key,
                            crypto=crypto,
                        )
                    )
                    wrap = await asyncio.wait_for(_next(client, lambda e: e["kind"] == 1059), 10)
                    offer = _decode_gift_wrap_candidate(
                        wrap,
                        recipient_mailbox_secret=CLIENT_SECRET,
                        expected_recipient_xonly_key=client_key,
                        expected_network=harness.network,
                        expected_profile_id="btc-to-ln/v1",
                        crypto=crypto,
                    ).envelope
                    assert (offer.message_type, offer.sequence) == ("quote_offer", 1)
                    assert offer.in_reply_to == request["message_id"]
                    crypto.schnorr_verify(
                        bytes.fromhex(accept.sender_session_key),
                        unsigned_envelope_hash(offer),
                        bytes.fromhex(offer.signature or ""),
                    )
                    quote = QuoteOffer.model_validate_json(json.dumps(offer.payload))
                    assert quote.economics.contract_amount_sat == "50100"  # L + base 50 + 1000 ppm
                    assert quote.reference_height == 500
                stop.set()
                await asyncio.wait_for(runner, 10)
        finally:
            await relay.stop()

    with Context(library_path=os.environ["RILL_CRYPTO_LIBRARY"]) as crypto:
        asyncio.run(scenario(crypto))


def test_untrusted_events_are_refused_or_deduplicated_without_effects(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    harness = Harness(tmp_path, monkeypatch)
    harness.provision()
    policy = ServicePolicy(
        network=harness.network,
        profiles=("btc-to-ln/v1",),
        amount_bands=((1000, 2000),),
        base_fee_sat=1,
        proportional_millionths=1,
        slot="s",
        relay_urls=("ws://r/",),
    )
    event = json.dumps({"id": "ee" * 32, "tags": [["p", "ff" * 32]]}).encode()
    with harness.acquire() as store:
        service = HandshakeService(store, object(), object(), policy)  # type: ignore[arg-type]
        assert asyncio.run(service.handle(event, [])) == "refused"
        assert asyncio.run(service.handle(event, [])) == "duplicate"
        assert asyncio.run(service.handle(b"not json", [])) == "duplicate"
        assert store.pending_outbox() == ()
        assert store.awaiting_confirm_mailboxes() == ()


class _Relay:
    def __init__(self, *, accept: bool) -> None:
        self.url = "ws://fake/"
        self.accept = accept
        self.published: list[bytes] = []
        self.filters: list[dict[str, Any]] = []

    async def publish(self, event: bytes) -> bool:
        self.published.append(event)
        return self.accept

    async def subscribe(self, filters: list[dict[str, Any]]) -> None:
        self.filters = filters


class _Identity:
    def __init__(self) -> None:
        self.built = 0

    def build_announcement(self, terms: Any) -> bytes:  # noqa: ANN401
        self.built += 1
        return json.dumps({"n": self.built, "created_at": terms.created_at}).encode()


def test_announcements_are_durably_ordered_cached_and_sessions_expire(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    harness = Harness(tmp_path, monkeypatch)
    harness.provision()
    policy = ServicePolicy(
        network=harness.network,
        profiles=("btc-to-ln/v1",),
        amount_bands=((1000, 2000),),
        base_fee_sat=1,
        proportional_millionths=1,
        slot="s",
        relay_urls=("ws://fake/",),
        handshake_timeout=100,
    )
    clock = [10_000.0]
    identity = _Identity()
    with harness.acquire() as store:
        store.reserve(harness.init, now=9_000)
        service = HandshakeService(store, identity, object(), policy, clock=lambda: clock[0])  # type: ignore[arg-type]
        down = _Relay(accept=False)
        asyncio.run(service.tick([down]))
        with pytest.raises(SessionExpiredError):  # recorded answer, never a new accept
            store.reserve(harness.init)
        clock[0] += 1
        asyncio.run(service.tick([down]))
        assert identity.built == 1
        assert down.published[0] == down.published[1]  # exact retransmission
        up = _Relay(accept=True)
        asyncio.run(service.tick([up]))
        asyncio.run(service.tick([up]))
        assert len(up.published) == 1
        clock[0] += policy.epoch_period  # rotation: old key no longer advertised
        asyncio.run(service.tick([up]))
        receiving = store.receiving_epochs(now=int(clock[0]))
        assert len(receiving) == 2
        assert up.filters[0]["#p"] == sorted(receiving)  # still listening on the old key
        rotated, published = clock[0], len(up.published)
    with harness.acquire() as store:  # restart with the clock rolled back
        clock[0] = rotated - 1
        restarted = HandshakeService(store, identity, object(), policy, clock=lambda: clock[0])  # type: ignore[arg-type]
        with pytest.raises(LiveSessionStoreError, match="clock is behind"):
            asyncio.run(restarted.tick([up]))
        clock[0] = rotated  # same second as the durable revision
        built = identity.built
        asyncio.run(restarted.tick([up]))
        assert identity.built == built
        assert len(up.published) == published


class _BandsIdentity(_Identity):
    def __init__(self) -> None:
        super().__init__()
        self.bands: list[tuple[tuple[int, int], ...]] = []

    def build_announcement(self, terms: Any) -> bytes:  # noqa: ANN401
        self.bands.append(terms.amount_bands)
        return super().build_announcement(terms)


def _liquidity_service(
    store: LiveSessionStore,
    harness: Harness,
    liquidity: list[int | Exception],
    clock: list[float],
) -> tuple[HandshakeService, _BandsIdentity]:
    policy = ServicePolicy(
        network=harness.network,
        profiles=("btc-to-ln/v1",),
        amount_bands=((1000, 2_000_000),),
        base_fee_sat=1,
        proportional_millionths=1,
        slot="s",
        relay_urls=("ws://fake/",),
        liquidity_margin_percent=(10, 10),
    )

    def read() -> int:
        value = liquidity[0]
        if isinstance(value, Exception):
            raise value
        return value

    identity = _BandsIdentity()
    service = HandshakeService(
        store,
        identity,  # type: ignore[arg-type]
        object(),  # type: ignore[arg-type]
        policy,
        clock=lambda: clock[0],
        liquidity=read,
    )
    return service, identity


def _admitted_bands(
    service: HandshakeService, store: LiveSessionStore, monkeypatch: pytest.MonkeyPatch
) -> tuple[tuple[int, int], ...]:
    """Run quote admission and return the bands the quote rules were given."""
    seen: list[Any] = []

    def answer(*args: Any) -> Any:  # noqa: ANN401 - (request, prior, context, terms, signer)
        seen.append(args[3])
        return SimpleNamespace(message_type="error", payload={"code": "amount_out_of_range"})

    def answer_request(_store: object, _document: bytes, *, responder: Any, **_: object) -> Any:  # noqa: ANN401
        return responder(None, (), SimpleNamespace(economic_capacity_available=True))

    monkeypatch.setattr("rill_provider.handshake_service.answer_client_request", answer)
    monkeypatch.setattr(type(store), "answer_request", answer_request)
    document = json.dumps({"message_type": "quote_request", "payload": {}}).encode()
    asyncio.run(service._prepare_answer(document, 10_000, operation=None))  # noqa: SLF001
    (terms,) = seen
    return terms.amount_bands  # type: ignore[no-any-return]


def test_announced_and_admitted_amounts_follow_liquidity(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    harness = Harness(tmp_path, monkeypatch)
    harness.provision()
    clock, liquidity = [10_000.0], [1_000_000]
    relay = _Relay(accept=True)
    with harness.acquire() as store:
        service, identity = _liquidity_service(store, harness, liquidity, clock)
        assert _admitted_bands(service, store, monkeypatch) == ((1000, 2_000_000),)
        asyncio.run(service.tick([relay]))
        assert identity.bands == [((1000, 900_000),)]  # 10 % below liquidity
        assert _admitted_bands(service, store, monkeypatch) == ((1000, 900_000),)
        liquidity[0] = 850_000  # a drop waits for the scheduled refresh
        clock[0] += 60
        asyncio.run(service.tick([relay]))
        assert len(identity.bands) == 1
        assert _admitted_bands(service, store, monkeypatch) == ((1000, 900_000),)
        clock[0] += service._policy.announcement_refresh  # noqa: SLF001
        asyncio.run(service.tick([relay]))
        assert identity.bands[-1] == ((1000, 765_000),)
        assert _admitted_bands(service, store, monkeypatch) == ((1000, 765_000),)
        liquidity[0] = 1_000_000  # refilled: the cap rises at the next refresh
        clock[0] += service._policy.announcement_refresh  # noqa: SLF001
        asyncio.run(service.tick([relay]))
        assert identity.bands[-1] == ((1000, 900_000),)
        liquidity[0] = 5_000_000  # covers every band even 10 % below
        clock[0] += service._policy.announcement_refresh  # noqa: SLF001
        asyncio.run(service.tick([relay]))
        assert identity.bands[-1] == ((1000, 2_000_000),)
        assert _admitted_bands(service, store, monkeypatch) == ((1000, 2_000_000),)


def test_a_failing_liquidity_source_keeps_the_last_cap_and_never_raises_it(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    harness = Harness(tmp_path, monkeypatch)
    harness.provision()
    clock, liquidity = [10_000.0], [OSError("LND down")]
    relay = _Relay(accept=True)
    refresh = 30 * 60
    with harness.acquire() as store:
        service, identity = _liquidity_service(store, harness, liquidity, clock)
        asyncio.run(service.tick([relay]))
        assert identity.bands == [((1000, 2_000_000),)]  # never read: configured bands
        liquidity[0] = 1_000_000
        clock[0] += refresh
        asyncio.run(service.tick([relay]))
        liquidity[0] = OSError("LND down")
        for _ in range(2):
            clock[0] += refresh
            asyncio.run(service.tick([relay]))
        assert (
            identity.bands == [((1000, 2_000_000),), ((1000, 900_000),)] + [((1000, 900_000),)] * 2
        )
        assert _admitted_bands(service, store, monkeypatch) == ((1000, 900_000),)
    warnings = [r.message for r in caplog.records if "liquidity unavailable" in r.message]
    assert len(warnings) == 2  # once per failure streak


def test_liquidity_below_every_band_stops_announcing_and_admitting(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    harness = Harness(tmp_path, monkeypatch)
    harness.provision()
    clock, liquidity = [10_000.0], [1_000_000]
    relay = _Relay(accept=True)
    refresh = 30 * 60
    with harness.acquire() as store:
        service, identity = _liquidity_service(store, harness, liquidity, clock)
        asyncio.run(service.tick([relay]))
        assert service.health().announcing
        liquidity[0] = 1000  # 10 % below is under the smallest band
        clock[0] += refresh
        asyncio.run(service.tick([relay]))
        assert len(identity.bands) == 1  # nothing built or recorded
        assert _admitted_bands(service, store, monkeypatch) == ()
        assert not service.health().announcing  # what the low liquidity alert watches
        service._state.republish = True  # noqa: SLF001 - a relay reconnects
        clock[0] += 60
        asyncio.run(service.tick([relay]))
        assert len(relay.published) == 1  # the old, larger offer is not resent
        liquidity[0] = 100_000
        clock[0] += refresh
        asyncio.run(service.tick([relay]))
        assert identity.bands[-1] == ((1000, 90_000),)
        assert len(relay.published) == 2
        assert _admitted_bands(service, store, monkeypatch) == ((1000, 90_000),)
        assert service.health().announcing


def test_relay_queue_loss_forces_one_replay_req_and_failed_req_retries(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Loss on an otherwise-live socket must not silently strand a wrapper."""

    class CountingRelay(_Relay):
        def __init__(self) -> None:
            super().__init__(accept=True)
            self.dropped_events = 0
            self.subscriptions = 0
            self.fail_next = False

        async def subscribe(self, filters: list[dict[str, Any]]) -> None:
            self.subscriptions += 1
            if self.fail_next:
                self.fail_next = False
                raise OSError("test-only relay send failure")
            await super().subscribe(filters)

    harness = Harness(tmp_path, monkeypatch)
    harness.provision()
    policy = ServicePolicy(
        network=harness.network,
        profiles=("btc-to-ln/v1",),
        amount_bands=((1000, 2000),),
        base_fee_sat=1,
        proportional_millionths=1,
        slot="s",
        relay_urls=("ws://fake/",),
    )
    relay = CountingRelay()
    healthy = CountingRelay()
    with harness.acquire() as store:
        service = HandshakeService(store, _Identity(), object(), policy, clock=lambda: 10_000)  # type: ignore[arg-type]
        asyncio.run(service.tick([relay, healthy]))
        assert relay.subscriptions == 1
        assert healthy.subscriptions == 1
        asyncio.run(service.tick([relay, healthy]))
        assert relay.subscriptions == 1
        relay.dropped_events += 1
        asyncio.run(service.tick([relay, healthy]))
        assert relay.subscriptions == 2
        assert healthy.subscriptions == 1  # one faulty relay does not replay all others
        asyncio.run(service.tick([relay, healthy]))
        assert relay.subscriptions == 2
        relay.dropped_events += 1
        relay.fail_next = True
        asyncio.run(service.tick([relay, healthy]))
        assert relay.subscriptions == 3
        assert healthy.subscriptions == 1
        asyncio.run(service.tick([relay, healthy]))
        assert relay.subscriptions == 4
        assert healthy.subscriptions == 2  # retry after failed REQ repairs all filters
        asyncio.run(service.tick([relay, healthy]))
        assert relay.subscriptions == 4


def test_ownership_loss_is_never_swallowed_as_a_refusal() -> None:
    class Fenced:
        def open_mailbox_frame(self, *_args: object, **_kwargs: object) -> bytes:
            raise StaleOwnerError("fenced")

    policy = ServicePolicy(
        network=None,  # type: ignore[arg-type]
        profiles=("btc-to-ln/v1",),
        amount_bands=((1000, 2000),),
        base_fee_sat=1,
        proportional_millionths=1,
        slot="s",
        relay_urls=("ws://r/",),
    )
    service = HandshakeService(Fenced(), object(), object(), policy)  # type: ignore[arg-type]
    event = json.dumps({"id": "ab" * 32}).encode()
    with pytest.raises(StaleOwnerError):
        asyncio.run(service.handle(event, []))


def test_result_transport_admits_without_creating_an_answer() -> None:
    """Ingress routes to the authenticated store, not request-response logic."""

    class CooperativeStore:
        def __init__(self) -> None:
            self.document = b'{"message_type":"action_result"}'
            self.replay = False
            self.error: LiveSessionStoreError | None = None
            self.admitted: list[tuple[bytes, int]] = []
            self.answered: list[bytes] = []

        def open_mailbox_frame(self, *_args: object, **_kwargs: object) -> bytes:
            return self.document

        def _admit_cooperative_result(self, document: bytes, *, now: int) -> SimpleNamespace:
            self.admitted.append((document, now))
            if self.error is not None:
                raise self.error
            return SimpleNamespace(replay=self.replay)

        def answer_request(self, document: bytes, **_kwargs: object) -> None:
            self.answered.append(document)
            raise LiveSessionStoreError("not a client request")

    policy = ServicePolicy(
        network=None,  # type: ignore[arg-type]
        profiles=("btc-to-ln/v1",),
        amount_bands=((1000, 2000),),
        base_fee_sat=1,
        proportional_millionths=1,
        slot="s",
        relay_urls=("ws://r/",),
    )
    store = CooperativeStore()
    service = HandshakeService(store, object(), object(), policy, clock=lambda: 123)  # type: ignore[arg-type]
    relay = _Relay(accept=True)

    def handle_event(index: int) -> str:
        return asyncio.run(service.handle(json.dumps({"id": f"{index:064x}"}).encode(), [relay]))

    assert handle_event(1) == "result-admitted"
    store.replay = True
    assert handle_event(2) == "result-replay"
    store.error = LiveSessionStoreError("invalid cooperative result")
    assert handle_event(3) == "refused"
    assert store.admitted == [(store.document, 123)] * 3
    assert store.answered == []
    assert relay.published == []
    store.document = b'{"message_type":"action_request"}'
    assert handle_event(4) == "refused"
    assert store.answered == [store.document]
    assert relay.published == []


@pytest.mark.native_crypto
@NATIVE
@pytest.mark.parametrize(("label", "sequence"), [("handshake_confirm", 2), ("quote_request", 1)])
def test_native_sequence_reuse_conflicts_whatever_the_label(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, label: str, sequence: int
) -> None:
    from rill_crypto import Context  # noqa: PLC0415

    from rill_provider._nip59_send import _wrap_envelope  # noqa: PLC0415

    harness = Harness(tmp_path, monkeypatch)
    harness.provision()
    policy = ServicePolicy(
        network=harness.network,
        profiles=("btc-to-ln/v1",),
        amount_bands=((1000, 100_000),),
        base_fee_sat=50,
        proportional_millionths=1000,
        slot="s",
        relay_urls=("ws://r/",),
    )
    tips: list[int] = []

    def chain_tip() -> int:
        tips.append(500)
        return 500

    with (
        Context(library_path=os.environ["RILL_CRYPTO_LIBRARY"]) as crypto,
        harness.acquire_at(harness.path, crypto=crypto, public_keys=crypto) as store,
    ):
        store.reserve(harness.init)
        store.commit_accept(harness.accept)
        store.admit_confirm(harness.confirm)
        mailbox = harness.envelopes[1]["sender_session_key"]
        service = HandshakeService(store, object(), crypto, policy, chain_tip=chain_tip)  # type: ignore[arg-type]
        asyncio.run(service._refresh_tip())  # noqa: SLF001 - the per-tick step alone

        def deliver(envelope: dict[str, Any]) -> str:
            wrap = _wrap_envelope(
                _bytes(envelope),
                sender_session_secret=CLIENT_SECRET,
                recipient_xonly_key=mailbox,
                crypto=crypto,
            )
            return asyncio.run(service.handle(wrap, []))

        request = _signed_quote_request(harness, crypto)
        assert deliver(request) == "request-answered"
        assert deliver(request) == "request-replay"
        reuse = copy.deepcopy(request)
        reuse.update(message_id="23" * 32, sequence=sequence, message_type=label, signature=None)
        unsigned = unsigned_envelope_hash(Envelope.model_validate_json(json.dumps(reuse)))
        reuse["signature"] = crypto.schnorr_sign(CLIENT_SECRET, unsigned, b"\x68" * 32).hex()
        invalid = dict(reuse, signature="00" * 64)
        assert deliver(invalid) == "refused"  # no unauthenticated sequence-conflict denial
        assert deliver(request) == "request-replay"
        assert deliver(reuse) == "blocked"
        assert deliver(request) == "blocked"
        assert store.session_mailboxes() == ()
        assert tips == [500]  # requests never trigger chain RPC


@pytest.mark.native_crypto
@NATIVE
@pytest.mark.parametrize("funding_depth", [2, 0])
def test_native_firm_request_gets_signed_terms_and_reserves_the_hash(  # noqa: PLR0915
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, funding_depth: int
) -> None:
    from rill_core.settlement.taproot import reconstruct_taproot_contract  # noqa: PLC0415
    from rill_core.settlement.unilateral import (  # noqa: PLC0415
        FundingOutput,
        UnilateralAuthorization,
        validate_unilateral_spend,
    )
    from rill_core.wire.hashes import (  # noqa: PLC0415
        client_acceptance_hash,
        funding_binding_hash,
        provider_terms_hash,
    )
    from rill_core.wire.messages import ClientAcceptance, FundingBinding  # noqa: PLC0415
    from rill_core.wire.quotes import (  # noqa: PLC0415
        FirmQuoteRequest,
        TermsOfferPayload,
        check_terms_offer,
        parse_quote_request,
    )
    from rill_crypto import Context  # noqa: PLC0415
    from test_quote_policy import BINDING, CONTRACT, FIRM, FIRM_SCHEDULE  # noqa: PLC0415

    from rill_provider._nip59_send import _wrap_envelope  # noqa: PLC0415
    from rill_provider.lnd_payment_send import PaymentOutcome, PreparedPayment  # noqa: PLC0415
    from rill_provider.payment_dispatch_record import PaymentAuthority  # noqa: PLC0415
    from rill_provider.provider_identity import ProviderIdentity  # noqa: PLC0415
    from rill_provider.settlement_engine import SettlementEngine  # noqa: PLC0415

    harness = Harness(tmp_path, monkeypatch)
    harness.provision()
    unlock = x25519.Identity.generate()
    policy = ServicePolicy(
        network=harness.network,
        profiles=("btc-to-ln/v1",),
        amount_bands=((1000, 100_000),),
        base_fee_sat=50,
        proportional_millionths=1000,
        slot="s",
        relay_urls=("ws://r/",),
        provider_destination_script=CONTRACT["provider_destination_script"],
        quote=replace(FIRM_SCHEDULE, funding_confirmations=funding_depth),
    )
    decoded: list[str] = []

    exact = BINDING.model_copy(  # the engine re-checks the invoice string it pays
        update={"bolt11_sha256": hashlib.sha256(FIRM["invoice"].encode()).hexdigest()}
    )

    def decoder(invoice: str) -> Any:  # noqa: ANN401
        decoded.append(invoice)
        return exact

    with (
        Context(library_path=os.environ["RILL_CRYPTO_LIBRARY"]) as crypto,
        harness.acquire_at(harness.path, crypto=crypto, public_keys=crypto) as store,
    ):
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
        store.reserve(harness.init)
        store.commit_accept(harness.accept)
        store.admit_confirm(harness.confirm)
        mailbox = harness.envelopes[1]["sender_session_key"]
        service = HandshakeService(
            store,
            signer,
            crypto,
            policy,
            clock=lambda: BINDING.created_at,
            chain_tip=lambda: 850,
            invoice_decoder=decoder,
        )
        asyncio.run(service._refresh_tip())  # noqa: SLF001 - the per-tick step alone

        def deliver(envelope: dict[str, Any]) -> str:
            wrap = _wrap_envelope(
                _bytes(envelope),
                sender_session_secret=CLIENT_SECRET,
                recipient_xonly_key=mailbox,
                crypto=crypto,
            )
            return asyncio.run(service.handle(wrap, []))

        request = _signed_quote_request(harness, crypto)
        request.update(payload=FIRM | {"extensions": {}}, signature=None)
        for identifier in ("21", "22", "23"):
            invalid = dict(request, message_type="error", message_id=identifier * 32)
            unsigned = unsigned_envelope_hash(Envelope.model_validate_json(json.dumps(invalid)))
            invalid["signature"] = crypto.schnorr_sign(CLIENT_SECRET, unsigned, b"\x69" * 32).hex()
            assert deliver(invalid) == "refused"
            assert decoded == []
        unsigned = unsigned_envelope_hash(Envelope.model_validate_json(json.dumps(request)))
        request["signature"] = crypto.schnorr_sign(CLIENT_SECRET, unsigned, b"\x69" * 32).hex()
        assert deliver(request) == "request-answered"
        assert deliver(request) == "request-replay"
        assert decoded == [FIRM["invoice"]]  # replays never reach the backend
        (pending,) = store.pending_outbox()
        response = Envelope.model_validate_json(pending.canonical_bytes)
        assert response.message_type == "terms_offer", response.payload
        offer = TermsOfferPayload.model_validate_json(json.dumps(response.payload))
        assert response.contract_hash == offer.terms.contract_hash  # RS-003 envelope binding
        parsed = parse_quote_request(json.dumps(FIRM | {"extensions": {}}).encode())
        assert isinstance(parsed, FirmQuoteRequest)
        check_terms_offer(
            parsed,
            offer,
            handshake_hash=harness.envelopes[2]["payload"]["handshake_hash"],
            invoice_binding=exact,
        )
        crypto.schnorr_verify(
            bytes.fromhex(harness.identity),
            provider_terms_hash(offer.terms),
            bytes.fromhex(offer.provider_terms_signature),
        )

        def signed(envelope: dict[str, Any], aux: int) -> dict[str, Any]:
            envelope["signature"] = None
            digest = unsigned_envelope_hash(Envelope.model_validate_json(json.dumps(envelope)))
            envelope["signature"] = crypto.schnorr_sign(
                CLIENT_SECRET, digest, bytes([aux]) * 32
            ).hex()
            return envelope

        acceptance = ClientAcceptance(
            contract_hash=offer.terms.contract_hash,
            handshake_hash=offer.terms.handshake_hash,
            session_id=response.session_id,
            client_session_xonly_key=request["sender_session_key"],
            provider_session_xonly_key=response.sender_session_key,
        )
        accept = copy.deepcopy(request)
        accept.update(
            message_id="22" * 32,
            sequence=3,
            in_reply_to=response.message_id,
            contract_hash=offer.terms.contract_hash,
            message_type="terms_accept",
            payload={
                "acceptance": acceptance.model_dump(mode="json"),
                "client_acceptance_signature": crypto.schnorr_sign(
                    CLIENT_SECRET, client_acceptance_hash(acceptance), b"\x70" * 32
                ).hex(),
            },
        )
        bad = copy.deepcopy(accept)
        bad["payload"]["client_acceptance_signature"] = "11" * 64
        assert deliver(signed(bad, 0x71)) == "request-answered"  # refused, stream advances
        assert store.pending_outbox()[-1].canonical_bytes.count(b"request_unacceptable") == 1
        accept["message_id"], accept["sequence"] = "23" * 32, 4
        assert deliver(signed(accept, 0x72)) == "request-answered"
        ack = Envelope.model_validate_json(store.pending_outbox()[-1].canonical_bytes)
        assert (ack.message_type, ack.contract_hash) == ("ack", offer.terms.contract_hash)

        terms = offer.terms.contract_terms
        script = reconstruct_taproot_contract(terms, keys=crypto).script_pubkey
        value = int(terms.economics.contract_amount_sat)
        raw = (
            (2).to_bytes(4, "little")
            + b"\x01"
            + bytes.fromhex("41" * 32)
            + b"\x00\x00\x00\x00\x00\xff\xff\xff\xff\x01"
            + value.to_bytes(8, "little")
            + bytes([len(script)])
            + script
            + b"\x00\x00\x00\x00"
        )
        binding = FundingBinding(
            contract_hash=offer.terms.contract_hash,
            funding_attempt_id="31" * 32,
            binding_revision=0,
            funder_role="client",
            lineage_anchor_txid="41" * 32,
            lineage_anchor_vout=0,
            funding_txid=hashlib.sha256(hashlib.sha256(raw).digest()).digest()[::-1].hex(),
            contract_vout=0,
            contract_value_sat=str(value),
            contract_script_pubkey=script.hex(),
            replaces_txid=None,
            created_at=BINDING.created_at,
        )
        funding = copy.deepcopy(accept)
        funding.update(
            message_id="24" * 32,
            sequence=5,
            in_reply_to=None,
            message_type="funding_binding",
            payload={
                "binding": binding.model_dump(mode="json"),
                "funding_binding_signature": crypto.schnorr_sign(
                    CLIENT_SECRET, funding_binding_hash(binding), b"\x73" * 32
                ).hex(),
                "funding_transaction": raw.hex(),
            },
        )
        assert deliver(signed(funding, 0x74)) == "request-answered"
        ack = Envelope.model_validate_json(store.pending_outbox()[-1].canonical_bytes)
        assert ack.message_type == "ack", ack.payload
        swap = store._connection.execute(  # noqa: SLF001 - durable swap state
            "SELECT state, contract_hash FROM swaps"
        ).fetchall()
        assert swap == [("FUNDING_SEEN", offer.terms.contract_hash)]

        preimage = "42" * 32  # sha256 is the fixture payment hash
        chain = SimpleNamespace(depth=1, claim_depth=0, broadcasts=[])
        chain.tip_height = lambda: 850
        chain.observe_candidate_outpoint = lambda _b, _t, *, keys: SimpleNamespace(  # noqa: ARG005
            chain_only_confirmations=chain.depth, tip_height=850
        )
        mempool_samples: list[int] = []
        # Zero-confirmation terms pay on the output being unspent in the mempool.
        chain.observe_mempool_outpoint = lambda _b, t, *, keys: (  # noqa: ARG005
            mempool_samples.append(t.funding_confirmations)
            or SimpleNamespace(confirmations=0, tip_height=850)
        )
        chain.broadcast = lambda raw, txid: chain.broadcasts.append((raw, txid)) or txid
        chain.confirmations = lambda _txid: chain.claim_depth
        chain.outpoint_unspent = lambda _txid, _vout: True
        chain.fee_rate_sat_vb = lambda _target: None
        sent: list[dict[str, Any]] = []

        def track(_payment_hash: str) -> PaymentOutcome:
            return PaymentOutcome("SUCCEEDED", preimage) if sent else PaymentOutcome("UNKNOWN")

        prepared: list[dict[str, Any]] = []

        def prepare(bolt11: str, **bounds: Any) -> PreparedPayment:  # noqa: ANN401
            prepared.append({"invoice": bolt11, **bounds})
            return PreparedPayment(
                b"route",
                BINDING.payment_hash,
                BINDING.expires_at,
                994,
                BINDING.min_final_cltv_delta,
                PaymentAuthority("03" + "ab" * 32, terms.network_identity),
            )

        def send(payment: PreparedPayment) -> PaymentOutcome:
            assert payment.request == b"route"
            sent.append(prepared.pop())
            return PaymentOutcome("SUCCEEDED", preimage, fee_msat=1500)

        lightning = SimpleNamespace(track=track, prepare=prepare, send=send)
        engine = SettlementEngine(store, chain, lightning, crypto)
        later = BINDING.created_at + 10
        assert terms.funding_confirmations == funding_depth  # signed as configured
        if funding_depth:
            assert asyncio.run(engine.tick(later)) == {}  # one confirmation is not enough
            chain.depth = 2
        else:
            chain.depth = 0  # unconfirmed: only the mempool sample may authorize payment
        progressed = asyncio.run(engine.tick(later))
        # Both payment gates (FUNDING_SEEN and the PAYING re-check) sampled the mempool.
        assert mempool_samples == ([] if funding_depth else [0, 0])
        (session_id,) = progressed
        assert progressed == {session_id: "CLAIMING"}, (progressed, sent)
        assert store.settlement_work()[0].state == "CLAIMING"
        assert sent == [
            {
                "invoice": FIRM["invoice"],
                "invoice_binding": terms.invoice_binding,
                "fee_limit_sat": int(terms.economics.success_fee_sat),
                "max_expiry_height": 994,
            }
        ]
        ((raw_claim, claim_txid),) = chain.broadcasts
        observations = [
            Envelope.model_validate_json(entry.canonical_bytes)
            for entry in store.pending_outbox()
            if b'"observation"' in entry.canonical_bytes
        ]
        assert [item.payload for item in observations] == [
            {"kind": "payment_settled", "payment_preimage": preimage},
            {"kind": "claim_broadcast", "claim_txid": claim_txid},
        ]
        for item in observations:
            assert (item.in_reply_to, item.contract_hash) == (None, offer.terms.contract_hash)
            crypto.schnorr_verify(
                bytes.fromhex(response.sender_session_key),
                unsigned_envelope_hash(item),
                bytes.fromhex(item.signature or ""),
            )
        claim = UnilateralAuthorization.from_terms(
            terms,
            FundingOutput(bytes.fromhex(binding.funding_txid), 0, value, script),
            "claim",
            keys=crypto,
        )
        assert validate_unilateral_spend(raw_claim, claim, verifier=crypto).txid == claim_txid
        chain.claim_depth = 3
        assert asyncio.run(engine.tick(later)) == {session_id: "CLAIMED"}
        assert store.settlement_work() == ()
        assert len(sent) == 1  # never paid twice
        # Durable accounting of the whole swap, each row from its own transition.
        (claim_fee,) = store._connection.execute(  # noqa: SLF001 - the attempt that confirmed
            "SELECT fee_sat FROM claim_attempts WHERE txid=?", (claim_txid,)
        ).fetchone()
        principal = int(terms.economics.lightning_principal_sat)
        assert [(e.kind, e.amount, e.unit) for e in store.ledger_session(session_id)] == [
            ("offered", principal, "sat"),
            ("accepted", principal, "sat"),
            ("routing_fee", 1500, "msat"),
            ("completed", int(terms.economics.success_fee_sat), "sat"),
            ("claim_fee", claim_fee, "sat"),
        ]
        assert claim_fee > 0

        # An accepted contract is never idle-expired; its hash stays reserved.
        assert store.expire_idle(now=BINDING.created_at + 10**6, idle_timeout=1) == 0
        reserved = store._connection.execute(  # noqa: SLF001 - durable history
            "SELECT payment_hash FROM payment_hashes"
        ).fetchall()
        assert reserved == [(BINDING.payment_hash,)]


@pytest.mark.parametrize(
    ("disposition", "level"),
    [
        ("duplicate", "DEBUG"),
        ("insufficient-work", "DEBUG"),
        ("unavailable", "DEBUG"),
        ("deferred", "DEBUG"),
        ("request-replay", "DEBUG"),
        ("init-replay", "DEBUG"),
        ("request-answered", "INFO"),
        ("init-accepted", "INFO"),
        ("confirm-admitted", "INFO"),
        ("refused", "INFO"),
    ],
)
def test_routine_relay_dispositions_log_at_debug(disposition: str, level: str) -> None:
    """Relay history replays after every resubscribe must not flood INFO."""
    assert logging.getLevelName(_disposition_level(disposition)) == level


def test_health_reports_only_configured_quote_inputs_as_unavailable() -> None:
    policy = Mock(amount_bands=((1000, 100_000),))
    tip, fee = Mock(side_effect=OSError("Core down")), Mock(side_effect=OSError("Core down"))
    service = HandshakeService(Mock(), Mock(), Mock(), policy, chain_tip=tip, claim_fee=fee)
    assert service.health() == ServiceHealth(
        relays_connected=0, announcing=True, tip_available=False, claim_fee_available=False
    )  # before the first tick nothing is proven

    async def refresh() -> None:
        await service._refresh_tip()  # noqa: SLF001 - the per-tick snapshots
        await service._refresh_claim_fee()  # noqa: SLF001

    asyncio.run(refresh())
    assert (service.health().tip_available, service.health().claim_fee_available) == (False, False)
    tip.side_effect, tip.return_value = None, 850
    fee.side_effect, fee.return_value = None, ClaimFeeRate(rate_sat_kvb=2000, floor_sat_kvb=1000)
    asyncio.run(refresh())
    assert (service.health().tip_available, service.health().claim_fee_available) == (True, True)
    unconfigured = HandshakeService(Mock(), Mock(), Mock(), policy)
    assert unconfigured.health().tip_available
    assert unconfigured.health().claim_fee_available
