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
from test_live_session_store import Harness, _bytes

from rill_provider.handshake_service import HandshakeService, ServicePolicy
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


async def _next(connection: RelayConnection, predicate: object) -> bytes:
    async for event in connection.events():
        if predicate(json.loads(event)):  # type: ignore[operator]
            return event
    raise AssertionError("relay closed")


@pytest.mark.native_crypto
@NATIVE
def test_native_handshake_through_relay_and_service(
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
                service = HandshakeService(store, signer, crypto, policy)
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
