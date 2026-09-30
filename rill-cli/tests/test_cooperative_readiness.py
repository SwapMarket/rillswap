"""A readiness echo binds to the original session, not recovery custody."""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

import pytest
from rill_core.wire.hashes import (
    COOPERATIVE_CLAIM_FEATURE,
    EPOCH_SESSION_FEATURE,
    contract_hash,
    handshake_init_hash,
    unsigned_envelope_hash,
)
from rill_core.wire.messages import ContractTerms, Envelope, HandshakeAccept, HandshakeInit

from rill_cli.live_swap import (
    SwapError,
    _answer_cooperative_readiness,
    _Session,
    _validate_cooperative_readiness,
)

FIXTURE = (
    Path(__file__).parents[2] / "rill-core/tests/fixtures/recovery-v1/initial-btc-to-ln-v1.json"
)
PREIMAGE = "11" * 32
PROVIDER_SIGNATURE = "77" * 64


def test_untrusted_accept_does_not_bind_a_provider_or_poison_replay(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from rill_cli import live_swap  # noqa: PLC0415 - patch only this process's transport decoder

    context = json.loads(FIXTURE.read_text())["verification_context"]
    init = HandshakeInit.model_validate_json(json.dumps(context["handshake_init"]), strict=True)
    accept = HandshakeAccept.model_validate_json(
        json.dumps(context["handshake_accept"]), strict=True
    )
    crypto = Mock(public_key=lambda _secret: bytes.fromhex("02" + "11" * 32))

    def verify(_key: bytes, _digest: bytes, signature: bytes) -> None:
        if signature != bytes.fromhex(PROVIDER_SIGNATURE):
            raise ValueError("not signed by provider identity")

    crypto.schnorr_verify.side_effect = verify
    session = _Session(Mock(), crypto, init.network_identity, timeout=1)
    session.session_id = init.session_id
    session.key = init.client_session_xonly_key
    request = session.envelope("handshake_init", init.model_dump(mode="json"), signed=False)
    session.expect_accept(request, init, accept.provider_identity_xonly_key)
    correct = request.model_copy(
        update={
            "message_type": "handshake_accept",
            "message_id": "aa" * 32,
            "sender_session_key": accept.provider_session_xonly_key,
            "sequence": 0,
            "in_reply_to": request.message_id,
            "payload": {
                "accept": accept.model_dump(mode="json"),
                "provider_identity_signature": PROVIDER_SIGNATURE,
            },
        }
    )
    frames = {
        b"wrong-signature": correct.model_copy(
            update={"payload": correct.payload | {"provider_identity_signature": "00" * 64}}
        ),
        b"wrong-reply": correct.model_copy(update={"in_reply_to": "ff" * 32}),
        b"wrong-sequence": correct.model_copy(update={"sequence": 1}),
        b"wrong-key": correct.model_copy(
            update={"sender_session_key": init.client_session_xonly_key}
        ),
        b"extra-payload": correct.model_copy(update={"payload": correct.payload | {"x": 1}}),
        b"unknown-feature": correct.model_copy(
            update={"required_features": ("unknown-feature/v1",)}
        ),
        b"pre-accept": correct.model_copy(
            update={"message_type": "observation", "signature": PROVIDER_SIGNATURE}
        ),
        b"provider-one": correct.model_copy(
            update={
                "message_type": "observation",
                "sequence": 1,
                "message_id": "f1" * 32,
                "signature": PROVIDER_SIGNATURE,
            }
        ),
        b"correct": correct,
    }
    monkeypatch.setattr(
        live_swap,
        "_decode_gift_wrap_candidate",
        lambda raw, **_kwargs: SimpleNamespace(
            envelope=frames[raw], seal_author_xonly_key=frames[raw].sender_session_key
        ),
    )
    for raw in tuple(frames)[:-2]:
        assert session._admit(raw) is None  # noqa: SLF001 - signed envelope ingress boundary
        assert session.provider_key is None
        assert not session.seen
    frames[b"supported-outer"] = correct.model_copy(
        update={
            "required_features": (EPOCH_SESSION_FEATURE,),
            "extensions": {"example.invalid/optional": {"enabled": True}},
        }
    )
    assert session._admit(b"supported-outer") == frames[b"supported-outer"]  # noqa: SLF001
    assert session.provider_key == accept.provider_session_xonly_key
    assert session.seen == {correct.message_id}
    assert session._provider_next == 1  # noqa: SLF001 - accept establishes sequence one
    assert session._admit(b"correct") is None  # noqa: SLF001 - exact message ID replay
    assert session._admit(b"wrong-reply") is None  # noqa: SLF001 - no second accept
    assert session._provider_next == 1  # noqa: SLF001 - replay cannot reset the stream
    assert session.seen == {correct.message_id}
    assert session._admit(b"provider-one") == frames[b"provider-one"]  # noqa: SLF001
    assert session._provider_next == 2  # noqa: SLF001
    assert session._admit(b"correct") is None  # noqa: SLF001 - stale unsigned replay
    assert session._provider_next == 2  # noqa: SLF001 - no reopened sequence zero


def _context() -> tuple[ContractTerms, HandshakeInit, HandshakeAccept]:
    original = json.loads(FIXTURE.read_text())
    context = original["verification_context"]
    init_data = context["handshake_init"] | {"required_features": [COOPERATIVE_CLAIM_FEATURE]}
    init = HandshakeInit.model_validate_json(json.dumps(init_data), strict=True)
    accept_data = context["handshake_accept"] | {
        "required_features": [COOPERATIVE_CLAIM_FEATURE],
        "handshake_init_hash": handshake_init_hash(init).hex(),
    }
    accept = HandshakeAccept.model_validate_json(json.dumps(accept_data), strict=True)
    invoice = original["contract_terms"]["invoice_binding"]
    invoice["payment_hash"] = hashlib.sha256(bytes.fromhex(PREIMAGE)).hexdigest()
    original["contract_terms"]["required_features"] = [COOPERATIVE_CLAIM_FEATURE]
    terms = ContractTerms.model_validate_json(json.dumps(original["contract_terms"]), strict=True)
    return terms, init, accept


def _request(terms: ContractTerms, init: HandshakeInit, accept: HandshakeAccept) -> Envelope:
    return Envelope.model_validate_json(
        json.dumps(
            {
                "protocol": "rillswap",
                "wire_version": "1",
                "profile_id": terms.profile_id,
                "network_identity": terms.network_identity.model_dump(mode="json"),
                "session_id": init.session_id,
                "message_id": "aa" * 32,
                "sender_session_key": accept.provider_session_xonly_key,
                "sequence": 5,
                "in_reply_to": None,
                "contract_hash": contract_hash(terms).hex(),
                "message_type": "action_request",
                "payload": {
                    "action": "cooperative_claim_ready",
                    "challenge": "cc" * 32,
                    "payment_preimage": PREIMAGE,
                    "deadline_at": 1020,
                    "deadline_height": 1094,
                },
                "required_features": [COOPERATIVE_CLAIM_FEATURE],
                "extensions": {},
                "signature": PROVIDER_SIGNATURE,
            }
        ),
        strict=True,
    )


@pytest.mark.parametrize(
    ("variation", "change"),
    [
        ("wrong request key", {"sender_session_key": "ff" * 32}),
        ("unsigned request", {"signature": None}),
        ("wrong signed feature", {"required_features": ()}),
        ("wrong contract", {"contract_hash": "ff" * 32}),
        ("old request", {"payload": {"deadline_at": 999}}),
        ("far future", {"payload": {"deadline_at": 1031}}),
        ("unsafe height", {"payload": {"deadline_height": 1090}}),
        ("refund margin", {"payload": {"deadline_height": 1095}}),
        ("wrong preimage", {"payload": {"payment_preimage": "22" * 32}}),
    ],
)
def test_readiness_refuses_unbound_requests(variation: str, change: dict[str, object]) -> None:  # noqa: ARG001
    async def scenario() -> None:
        terms, init, accept = _context()
        crypto = Mock(public_key=lambda _secret: bytes.fromhex("02" + "11" * 32))

        def verify(_key: bytes, _digest: bytes, signature: bytes) -> None:
            if signature != bytes.fromhex(PROVIDER_SIGNATURE):
                raise ValueError("invalid signature")

        crypto.schnorr_verify.side_effect = verify
        crypto.schnorr_sign.return_value = b"\x33" * 64
        session = _Session(Mock(), crypto, terms.network_identity, timeout=1)
        session.session_id = init.session_id
        session.key = init.client_session_xonly_key
        session.provider_key = accept.provider_session_xonly_key
        session.send = AsyncMock()  # type: ignore[method-assign]
        request = _request(terms, init, accept)
        if "payload" in change:
            request = request.model_copy(
                update={
                    "payload": request.payload | change["payload"],  # type: ignore[operator]
                }
            )
        else:
            request = request.model_copy(update=change)
        with pytest.raises(SwapError, match=r"readiness|provider session"):
            await _answer_cooperative_readiness(
                session,
                request,
                terms=terms,
                init=init,
                accept=accept,
                provider_key=accept.provider_session_xonly_key,
                observed_preimage=None,
                now=1000,
                tip_height=1090,
            )
        session.send.assert_not_awaited()

    asyncio.run(scenario())


@pytest.mark.native_crypto
@pytest.mark.skipif(
    os.environ.get("RILLSWAP_RUN_NATIVE_CRYPTO") != "1" or "RILL_CRYPTO_LIBRARY" not in os.environ,
    reason="set RILLSWAP_RUN_NATIVE_CRYPTO=1 and RILL_CRYPTO_LIBRARY",
)
def test_native_readiness_authentication_rejects_tampered_signed_request() -> None:
    from rill_crypto import Context  # noqa: PLC0415 - opt-in native crypto

    async def scenario(crypto: Context) -> None:
        terms, init, accepted = _context()
        provider_secret = (5).to_bytes(32, "big")
        provider_key = crypto.public_key(provider_secret)[1:].hex()
        accept = accepted.model_copy(update={"provider_session_xonly_key": provider_key})
        session = _Session(Mock(), crypto, terms.network_identity, timeout=1)
        session.session_id = init.session_id
        session.secret = (4).to_bytes(32, "big")
        session.key = init.client_session_xonly_key
        session.provider_key = provider_key
        session.send = AsyncMock()  # type: ignore[method-assign]
        unsigned = _request(terms, init, accept).model_copy(update={"signature": None})
        signature = crypto.schnorr_sign(
            provider_secret, unsigned_envelope_hash(unsigned), b"\x01" * 32
        )
        request = unsigned.model_copy(update={"signature": signature.hex()})
        assert (
            await _answer_cooperative_readiness(
                session,
                request,
                terms=terms,
                init=init,
                accept=accept,
                provider_key=provider_key,
                observed_preimage=None,
                now=1000,
                tip_height=1090,
            )
            == PREIMAGE
        )
        assert session.send.await_count == 1
        forged = request.model_copy(update={"payload": request.payload | {"challenge": "bb" * 32}})
        with pytest.raises(SwapError, match="readiness refused"):
            await _answer_cooperative_readiness(
                session,
                forged,
                terms=terms,
                init=init,
                accept=accept,
                provider_key=provider_key,
                observed_preimage=None,
                now=1000,
                tip_height=1090,
            )
        assert session.send.await_count == 1

    with Context(library_path=os.environ["RILL_CRYPTO_LIBRARY"]) as crypto:
        asyncio.run(scenario(crypto))


def test_readiness_echo_has_exact_request_and_feature_without_recovery_changes() -> None:
    async def scenario() -> None:
        terms, init, accept = _context()
        crypto = Mock(public_key=lambda _secret: bytes.fromhex("02" + "11" * 32))
        crypto.schnorr_sign.return_value = b"\x33" * 64
        session = _Session(Mock(), crypto, terms.network_identity, timeout=1)
        session.session_id = init.session_id
        session.key = init.client_session_xonly_key
        session.provider_key = accept.provider_session_xonly_key
        session.sequence = 3
        session.send = AsyncMock()  # type: ignore[method-assign]
        request = _request(terms, init, accept)
        assert (
            await _answer_cooperative_readiness(
                session,
                request,
                terms=terms,
                init=init,
                accept=accept,
                provider_key=accept.provider_session_xonly_key,
                observed_preimage=PREIMAGE,
                now=1000,
                tip_height=1090,
            )
            == PREIMAGE
        )
        reply, recipient = session.send.await_args.args
        assert recipient == accept.provider_session_xonly_key
        assert reply.sequence == 3
        assert session.sequence == 4
        assert reply.in_reply_to == request.message_id
        assert reply.contract_hash == contract_hash(terms).hex()
        assert reply.required_features == (COOPERATIVE_CLAIM_FEATURE,)
        assert reply.payload == {
            "action": "cooperative_claim_ready",
            "challenge": "cc" * 32,
            "status": "ready",
        }
        with pytest.raises(SwapError, match="readiness"):
            await _answer_cooperative_readiness(
                session,
                request,
                terms=terms,
                init=init,
                accept=accept,
                provider_key=accept.provider_session_xonly_key,
                observed_preimage="22" * 32,
                now=1000,
                tip_height=1090,
            )
        assert session.send.await_count == 1

    asyncio.run(scenario())


def test_readiness_validation_learns_preimage_without_any_protocol_effect() -> None:
    terms, init, accept = _context()
    crypto = Mock(public_key=lambda _secret: bytes.fromhex("02" + "11" * 32))
    session = _Session(Mock(), crypto, terms.network_identity, timeout=1)
    session.session_id = init.session_id
    session.key = init.client_session_xonly_key
    session.provider_key = accept.provider_session_xonly_key
    session.sequence = 3
    session.send = AsyncMock()
    request = _request(terms, init, accept)
    validated = _validate_cooperative_readiness(
        session,
        request,
        terms=terms,
        init=init,
        accept=accept,
        provider_key=accept.provider_session_xonly_key,
        observed_preimage=None,
        now=1000,
        tip_height=1090,
    )
    assert validated.payment_preimage == PREIMAGE
    assert validated.challenge == "cc" * 32
    assert session.sequence == 3
    session.send.assert_not_called()
    crypto.schnorr_sign.assert_not_called()


@pytest.mark.parametrize("expiry", ["wall", "height"])
def test_readiness_echo_rechecks_deadlines_after_validation(expiry: str) -> None:
    async def scenario() -> None:
        terms, init, accept = _context()
        crypto = Mock(public_key=lambda _secret: bytes.fromhex("02" + "11" * 32))
        session = _Session(Mock(), crypto, terms.network_identity, timeout=1)
        session.session_id = init.session_id
        session.key = init.client_session_xonly_key
        session.provider_key = accept.provider_session_xonly_key
        session.sequence = 3
        session.send = AsyncMock()
        request = _request(terms, init, accept)
        validated = _validate_cooperative_readiness(
            session,
            request,
            terms=terms,
            init=init,
            accept=accept,
            provider_key=accept.provider_session_xonly_key,
            observed_preimage=None,
            now=1000,
            tip_height=1090,
        )
        with pytest.raises(SwapError, match="readiness refused"):
            await _answer_cooperative_readiness(
                session,
                request,
                terms=terms,
                init=init,
                accept=accept,
                provider_key=accept.provider_session_xonly_key,
                observed_preimage=validated.payment_preimage,
                now=1020 if expiry == "wall" else 1001,
                tip_height=1094 if expiry == "height" else 1090,
            )
        assert session.sequence == 3
        session.send.assert_not_called()
        crypto.schnorr_sign.assert_not_called()

    asyncio.run(scenario())
