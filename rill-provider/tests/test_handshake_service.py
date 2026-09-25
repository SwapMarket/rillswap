"""Full provider handshake over a relay: announce, init, accept, confirm."""

from __future__ import annotations

import asyncio
import copy
import json
import os
from typing import TYPE_CHECKING, Any

import pytest
from fake_relay import FakeRelay
from pyrage import x25519  # type: ignore[import-untyped]
from rill_core.wire.hashes import handshake_hash, unsigned_envelope_hash
from rill_core.wire.messages import Envelope, HandshakeAccept, HandshakeInit
from rill_core.wire.quotes import QuoteOffer
from test_live_session_store import Harness, _bytes

from rill_provider.handshake_service import HandshakeService, ServicePolicy
from rill_provider.live_session_store import (
    LiveSessionStoreError,
    SessionExpiredError,
    StaleOwnerError,
)
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
        assert deliver(reuse) == "blocked"
        assert deliver(request) == "blocked"
        assert store.session_mailboxes() == ()
        assert tips == [500]  # requests never trigger chain RPC


@pytest.mark.native_crypto
@NATIVE
def test_native_firm_request_gets_signed_terms_and_reserves_the_hash(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from rill_core.wire.hashes import provider_terms_hash  # noqa: PLC0415
    from rill_core.wire.quotes import (  # noqa: PLC0415
        FirmQuoteRequest,
        TermsOfferPayload,
        check_terms_offer,
        parse_quote_request,
    )
    from rill_crypto import Context  # noqa: PLC0415
    from test_quote_policy import BINDING, CONTRACT, FIRM, FIRM_SCHEDULE  # noqa: PLC0415

    from rill_provider._nip59_send import _wrap_envelope  # noqa: PLC0415
    from rill_provider.provider_identity import ProviderIdentity  # noqa: PLC0415

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
        quote=FIRM_SCHEDULE,
    )
    decoded: list[str] = []

    def decoder(invoice: str) -> Any:  # noqa: ANN401
        decoded.append(invoice)
        return BINDING

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
        unsigned = unsigned_envelope_hash(Envelope.model_validate_json(json.dumps(request)))
        request["signature"] = crypto.schnorr_sign(CLIENT_SECRET, unsigned, b"\x69" * 32).hex()
        assert deliver(request) == "request-answered"
        assert deliver(request) == "request-replay"
        assert decoded == [FIRM["invoice"]]  # replays never reach the backend
        (pending,) = store.pending_outbox()
        response = Envelope.model_validate_json(pending.canonical_bytes)
        assert response.message_type == "terms_offer", response.payload
        offer = TermsOfferPayload.model_validate_json(json.dumps(response.payload))
        parsed = parse_quote_request(json.dumps(FIRM | {"extensions": {}}).encode())
        assert isinstance(parsed, FirmQuoteRequest)
        check_terms_offer(
            parsed,
            offer,
            handshake_hash=harness.envelopes[2]["payload"]["handshake_hash"],
            invoice_binding=BINDING,
        )
        crypto.schnorr_verify(
            bytes.fromhex(harness.identity),
            provider_terms_hash(offer.terms),
            bytes.fromhex(offer.provider_terms_signature),
        )
        assert store.expire_idle(now=BINDING.created_at + 10**6, idle_timeout=1) == 1
        reserved = store._connection.execute(  # noqa: SLF001 - durable history survives expiry
            "SELECT payment_hash FROM payment_hashes"
        ).fetchall()
        assert reserved == [(BINDING.payment_hash,)]
