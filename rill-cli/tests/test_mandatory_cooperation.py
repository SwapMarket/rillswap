"""Cooperative MuSig2 claims are negotiated for every new swap, in both directions."""

from __future__ import annotations

import asyncio
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, Mock

import pytest
from rill_core.wire.hashes import (
    COOPERATIVE_CLAIM_FEATURE,
    EPOCH_SESSION_FEATURE,
    handshake_init_hash,
)
from rill_core.wire.messages import HandshakeAccept, HandshakeInit
from test_live_swap import NETWORK

from rill_cli import live_reverse_swap, live_swap
from rill_cli.live_swap import SwapError

# x-only keys of G, 2G, 3G and 4G: valid points with no secret needed here.
IDENTITY = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
PROVIDER_SESSION = "c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5"
CLIENT_SESSION = "f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9"
EPOCH = "e493dbf1c10d80f3581e4904930b1404cc6c13900ee0758474fa94abe8c4cd13"


def _session() -> Mock:
    session = Mock(
        network=NETWORK,
        profile="btc-to-ln/v1",
        session_id="55" * 32,
        key=CLIENT_SESSION,
        listen=AsyncMock(),
        send=AsyncMock(),
    )
    session.envelope.return_value = SimpleNamespace(message_id="66" * 32)
    return session


def _accept(init: HandshakeInit, features: tuple[str, ...]) -> HandshakeAccept:
    return HandshakeAccept(
        handshake_init_hash=handshake_init_hash(init).hex(),
        protocol=init.protocol,
        wire_version=init.wire_version,
        profile_id=init.profile_id,
        network_identity=init.network_identity,
        session_id=init.session_id,
        client_challenge=init.client_challenge,
        provider_challenge="77" * 32,
        client_session_xonly_key=init.client_session_xonly_key,
        provider_session_xonly_key=PROVIDER_SESSION,
        provider_identity_xonly_key=IDENTITY,
        selected_encryption_suite=init.requested_encryption_suites[0],
        selected_capabilities=init.requested_capabilities,
        transport_endpoints=("wss://relay.example",),
        required_features=features,
        extensions={},
    )


def _run_handshake(advertisement: dict[str, Any], echo: tuple[str, ...] | None) -> HandshakeInit:
    """Drive ``_handshake`` against a provider that echoes ``echo`` (None: init's)."""
    session = _session()
    seen: list[HandshakeInit] = []
    session.expect_accept.side_effect = lambda _request, init, _identity: seen.append(init)

    async def reply_to(_request: object, _kind: str) -> SimpleNamespace:
        (init,) = seen
        accept = _accept(init, init.required_features if echo is None else echo)
        return SimpleNamespace(
            payload={
                "accept": accept.model_dump(mode="json"),
                "provider_identity_signature": "88" * 64,
            },
            sender_session_key=PROVIDER_SESSION,
            message_id="99" * 32,
        )

    session.reply_to = reply_to
    asyncio.run(live_swap._handshake(session, advertisement, IDENTITY))  # noqa: SLF001
    (init,) = seen
    return init


def test_init_always_requests_cooperative_claims() -> None:
    init = _run_handshake({"epoch_inbox_xonly_keys": [EPOCH]}, echo=None)
    assert init.required_features == (COOPERATIVE_CLAIM_FEATURE,)


def test_epoch_bound_init_requests_both_features_sorted() -> None:
    advertisement = {
        "epoch_inbox_xonly_keys": [EPOCH],
        "extensions": {live_swap.HANDSHAKE_FEATURES_EXTENSION: [EPOCH_SESSION_FEATURE]},
    }
    init = _run_handshake(advertisement, echo=None)
    assert init.required_features == (COOPERATIVE_CLAIM_FEATURE, EPOCH_SESSION_FEATURE)


def test_accept_without_cooperative_claims_is_refused_before_terms() -> None:
    with pytest.raises(ValueError, match="cooperative claim must be jointly negotiated"):
        _run_handshake({"epoch_inbox_xonly_keys": [EPOCH]}, echo=())


@pytest.mark.parametrize("module", [live_swap, live_reverse_swap], ids=["btc-to-ln", "ln-to-btc"])
def test_terms_without_cooperative_claims_are_refused(
    module: Any,  # noqa: ANN401 - either direction's module
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    terms = SimpleNamespace(
        provider_identity_key=IDENTITY,
        network_identity=NETWORK,
        terms_expiry=2_000,
        required_features=(),
    )
    offer = SimpleNamespace(
        terms=SimpleNamespace(contract_terms=terms, contract_hash="aa" * 32),
        provider_terms_signature="bb" * 64,
    )
    for name in ("check_terms_offer", "check_reverse_terms_offer"):
        monkeypatch.setattr(module, name, Mock(), raising=False)
    monkeypatch.setattr(module, "provider_terms_hash", Mock(return_value=b""))
    monkeypatch.setattr(module, "contract_hash", Mock(return_value=bytes.fromhex("aa" * 32)))
    arguments = {
        "envelope": SimpleNamespace(contract_hash="aa" * 32),
        "transcript": "cc" * 32,
        "identity": IDENTITY,
        "network": NETWORK,
        "crypto": Mock(),
        "now": 1_000,
        ("invoice" if module is live_swap else "hold"): Mock(),
    }
    with pytest.raises(SwapError, match="terms offer does not commit to cooperative claims"):
        module._check_offer(offer, Mock(), **arguments)  # noqa: SLF001
    terms.required_features = (COOPERATIVE_CLAIM_FEATURE,)
    assert module._check_offer(offer, Mock(), **arguments) is terms  # noqa: SLF001
