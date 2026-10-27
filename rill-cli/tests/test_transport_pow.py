"""RS-006 transport proof of work: the CLI declares and mines what a provider requires."""

from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, Mock

import pytest
from rill_core.wire.hashes import EPOCH_SESSION_EXTENSION, EPOCH_SESSION_FEATURE
from rill_core.wire.messages import HandshakeInit
from rill_provider import _transport_pow as transport_pow
from test_mandatory_cooperation import EPOCH, IDENTITY, PROVIDER_SESSION, _accept, _session

from rill_cli import live_swap

KEY = transport_pow.TRANSPORT_POW_EXTENSION
EPOCH_REQUIREMENT = {live_swap.HANDSHAKE_FEATURES_EXTENSION: [EPOCH_SESSION_FEATURE]}
FIXTURE = (
    Path(__file__).parents[2] / "rill-provider" / "tests" / "fixtures" / "initial-btc-to-ln-v1.json"
)


def test_announced_work_is_read_only_from_a_well_formed_requirement() -> None:
    assert live_swap._transport_work({}) == 0  # noqa: SLF001
    assert live_swap._transport_work({"extensions": EPOCH_REQUIREMENT}) == 0  # noqa: SLF001
    assert live_swap._transport_work({"extensions": {KEY: {"bits": 16}}}) == 16  # noqa: SLF001
    both = {"extensions": {**EPOCH_REQUIREMENT, KEY: {"bits": 20}}}
    assert live_swap._transport_work(both) == 20  # noqa: SLF001
    assert live_swap._requires_epoch_binding(both)  # noqa: SLF001
    assert not live_swap._requires_epoch_binding({"extensions": {KEY: {"bits": 16}}})  # noqa: SLF001


@pytest.mark.parametrize(
    "value", [{"bits": 0}, {"bits": 21}, {"bits": "16"}, {"bits": 16, "more": 1}, 16, None]
)
def test_malformed_or_excessive_work_is_refused_not_ignored(value: object) -> None:
    with pytest.raises(live_swap.SwapError, match="transport work"):
        live_swap._transport_work({"extensions": {KEY: value}})  # noqa: SLF001


@pytest.mark.parametrize(
    ("extensions", "bits"),
    [({}, 0), ({KEY: {"bits": 12}}, 12), ({**EPOCH_REQUIREMENT, KEY: {"bits": 8}}, 8)],
    ids=["none", "work", "epoch-and-work"],
)
def test_handshake_declares_the_work_it_mines_on_every_send(
    extensions: dict[str, Any], bits: int
) -> None:
    session = _session()
    seen: list[HandshakeInit] = []
    mined: list[int] = []
    session.expect_accept.side_effect = lambda _request, init, _identity: seen.append(init)

    async def send(_request: object, _recipient: str) -> None:
        mined.append(session.work_bits)

    async def reply_to(_request: object, _kind: str) -> SimpleNamespace:
        (init,) = seen
        accept = _accept(init, init.required_features)
        return SimpleNamespace(
            payload={
                "accept": accept.model_dump(mode="json"),
                "provider_identity_signature": "88" * 64,
            },
            sender_session_key=PROVIDER_SESSION,
            message_id="99" * 32,
        )

    session.send, session.reply_to = send, reply_to
    advertisement = {"epoch_inbox_xonly_keys": [EPOCH], "extensions": extensions}
    asyncio.run(live_swap._handshake(session, advertisement, IDENTITY))  # noqa: SLF001
    (init,) = seen
    assert init.extensions.get(KEY) == ({"bits": bits} if bits else None)
    assert (EPOCH_SESSION_EXTENSION in init.extensions) == (
        EPOCH_REQUIREMENT.keys() <= extensions.keys()
    )
    assert mined
    assert set(mined) == {bits}  # the init and everything after it


@pytest.mark.native_crypto
@pytest.mark.skipif(
    os.environ.get("RILLSWAP_RUN_NATIVE_CRYPTO") != "1" or "RILL_CRYPTO_LIBRARY" not in os.environ,
    reason="set RILLSWAP_RUN_NATIVE_CRYPTO=1 and RILL_CRYPTO_LIBRARY",
)
def test_session_send_mines_the_outer_event() -> None:
    from rill_crypto import Context  # noqa: PLC0415 - opt-in native test

    context = json.loads(FIXTURE.read_text())["verification_context"]
    init = HandshakeInit.model_validate_json(json.dumps(context["handshake_init"]), strict=True)
    with Context(library_path=os.environ["RILL_CRYPTO_LIBRARY"]) as crypto:
        session = live_swap._Session(Mock(), crypto, init.network_identity, timeout=1)  # noqa: SLF001
        session.connection.publish = AsyncMock(return_value=True)
        request = session.envelope("handshake_init", init.model_dump(mode="json"), signed=False)
        for bits in (0, 10):
            session.work_bits = bits
            asyncio.run(session.send(request, EPOCH))
            event = session.connection.publish.await_args.args[0]
            assert transport_pow.outer_work(event) == (EPOCH, bits)
            assert len(json.loads(event)["tags"]) == (2 if bits else 1)
