"""Cooperative MuSig2 claims are mandatory for new business, never for history."""

from __future__ import annotations

import copy
import json
import os
from dataclasses import replace
from typing import TYPE_CHECKING, Any

import pytest
from pydantic import ValidationError
from pyrage import x25519
from rill_core.wire.canonical import canonicalize, parse_model_json
from rill_core.wire.hashes import (
    COOPERATIVE_CLAIM_FEATURE,
    EPOCH_SESSION_FEATURE,
    unsigned_envelope_hash,
)
from rill_core.wire.messages import Envelope
from rill_core.wire.quotes import TermsOfferPayload
from test_live_session_store import POLICY, Harness, _bytes
from test_live_session_store import harness as harness  # noqa: PLC0414 - fixture
from test_quote_policy import CONTRACT, FIRM, FIRM_TERMS, HANDSHAKE, _envelope, _with

from rill_provider import live_session_store as live
from rill_provider.evm_quote_policy import EVM_PROFILES
from rill_provider.live_session_store import LiveSessionStoreError, RequestContext
from rill_provider.operator_config import HandshakeSelection, OperatorConfig
from rill_provider.quote_policy import answer_quote

if TYPE_CHECKING:
    from pathlib import Path

COOPERATIVE = replace(POLICY, features=POLICY.features | {COOPERATIVE_CLAIM_FEATURE})
CLIENT_SECRET = (2).to_bytes(32, "big")  # Fixture-only public scalar of the client key.

# ruff: noqa: SLF001 - store metadata and fixture policy seams


def _featured_init(harness: Harness) -> live.EpochInitiation:
    envelope = copy.deepcopy(harness.envelopes[0])
    envelope["required_features"] = [COOPERATIVE_CLAIM_FEATURE]
    envelope["payload"]["required_features"] = [COOPERATIVE_CLAIM_FEATURE, EPOCH_SESSION_FEATURE]
    return harness.received(_bytes(envelope))


def _stored_policy(store: live.LiveSessionStore) -> dict[str, Any]:
    (policy,) = store._connection.execute("SELECT policy_jcs FROM meta").fetchone()
    return json.loads(policy)


@pytest.mark.parametrize(
    ("profile", "features"),
    [
        ("btc-to-ln/v1", {COOPERATIVE_CLAIM_FEATURE, EPOCH_SESSION_FEATURE}),
        ("ln-to-btc/v1", {COOPERATIVE_CLAIM_FEATURE, EPOCH_SESSION_FEATURE}),
        *((evm, {EPOCH_SESSION_FEATURE}) for evm in sorted(EVM_PROFILES)),
    ],
)
def test_operator_policy_features_are_intrinsic(profile: str, features: set[str]) -> None:
    selection = HandshakeSelection(
        profile=profile,
        encryption_suites=("noise-xk-secp256k1-chachapoly-sha256/v1",),
        capabilities=("core/v1",),
    )
    config = OperatorConfig.model_construct(handshake=selection)
    assert config.handshake_policy().features == features


def test_operator_cannot_configure_features() -> None:
    with pytest.raises(ValidationError, match="features"):
        HandshakeSelection.model_validate(
            {
                "profile": "btc-to-ln/v1",
                "features": [COOPERATIVE_CLAIM_FEATURE],
                "encryption_suites": ["noise-xk-secp256k1-chachapoly-sha256/v1"],
                "capabilities": ["core/v1"],
            }
        )


def test_new_unfeatured_initiation_is_refused_before_any_reservation(harness: Harness) -> None:
    harness.policy = COOPERATIVE
    harness.provision()
    with harness.acquire() as store:
        with pytest.raises(LiveSessionStoreError, match="requires cooperative claims"):
            store.reserve(harness.initiation)
        assert store._connection.execute("SELECT count(*) FROM sessions").fetchone() == (0,)
        reserved = store.reserve(_featured_init(harness))
        assert store.reserve(_featured_init(harness)) == reserved


def test_store_policy_never_changes_in_place(harness: Harness) -> None:
    harness.provision()  # without cooperation
    harness.policy = COOPERATIVE
    with pytest.raises(LiveSessionStoreError, match="policy mismatch"):
        harness.acquire()  # no upgrade
    harness.path = harness.path.with_name("cooperative.sqlite")
    harness.provision()
    with harness.acquire() as store:
        assert _stored_policy(store)["features"] == [
            COOPERATIVE_CLAIM_FEATURE,
            EPOCH_SESSION_FEATURE,
        ]
    for changed in (POLICY, replace(COOPERATIVE, capabilities=frozenset({"core/v1"}))):
        harness.policy = changed
        with pytest.raises(LiveSessionStoreError, match="policy mismatch"):
            harness.acquire()  # no silent downgrade or selection change


def test_terms_features_follow_the_negotiated_transcript() -> None:
    def offer(*, cooperative: bool) -> tuple[str, ...]:
        context = RequestContext(
            handshake_hash=HANDSHAKE,
            provider_contract_key=CONTRACT["provider_contract_compressed_key"],
            is_payment_hash_reserved=lambda _digest: False,
            cooperative=cooperative,
        )
        answer = answer_quote(_envelope(FIRM), (), context, _with(FIRM_TERMS))
        payload = parse_model_json(TermsOfferPayload, canonicalize(answer.payload))
        return payload.terms.contract_terms.required_features

    assert offer(cooperative=True) == (COOPERATIVE_CLAIM_FEATURE,)
    assert offer(cooperative=False) == ()


@pytest.mark.native_crypto
@pytest.mark.skipif(
    os.environ.get("RILLSWAP_RUN_NATIVE_CRYPTO") != "1",
    reason="set RILLSWAP_RUN_NATIVE_CRYPTO=1 with pinned native library",
)
def test_native_accept_commits_cooperation(
    harness: Harness, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    from rill_crypto import Context  # noqa: PLC0415

    from rill_provider.provider_identity import ProviderIdentity  # noqa: PLC0415

    harness.policy = COOPERATIVE
    harness.provision()
    unlock = x25519.Identity.generate()
    with (
        Context(library_path=os.environ["RILL_CRYPTO_LIBRARY"]) as crypto,
    ):
        with monkeypatch.context() as patch:  # fixture identity scalar 1
            patch.setattr(
                "rill_provider.provider_identity.secrets.token_bytes",
                lambda _n: (1).to_bytes(32, "big"),
            )
            xonly = ProviderIdentity.provision(
                tmp_path / "id.age", recipient=str(unlock.to_public()), crypto=crypto
            )
        signer = ProviderIdentity.load(
            tmp_path / "id.age",
            custody_identity=str(unlock),
            expected_xonly_public_key=xonly,
            crypto=crypto,
        )
        with harness.acquire_at(harness.path, crypto=crypto, public_keys=crypto) as store:
            reserved = store.reserve(_featured_init(harness))
            committed = store.create_accept(
                reserved.session_id, identity=signer, transport_endpoints=("wss://r/",)
            )
            accept = Envelope.model_validate_json(committed.canonical_bytes, strict=True)
            assert accept.payload["accept"]["required_features"] == [
                COOPERATIVE_CLAIM_FEATURE,
                EPOCH_SESSION_FEATURE,
            ]
            confirm = copy.deepcopy(harness.envelopes[2])
            confirm["in_reply_to"] = committed.message_id
            confirm["payload"]["handshake_hash"] = committed.transcript_digest
            confirm["signature"] = None
            digest = unsigned_envelope_hash(Envelope.model_validate_json(json.dumps(confirm)))
            confirm["signature"] = crypto.schnorr_sign(CLIENT_SECRET, digest, b"\x55" * 32).hex()
            store.admit_confirm(_bytes(confirm))
            request = copy.deepcopy(harness.envelopes[2])
            request.update(
                message_type="quote_request",
                message_id="21" * 32,
                sequence=2,
                in_reply_to=None,
                payload={"kind": "btc-to-ln", "mode": "indicative"},
                required_features=[COOPERATIVE_CLAIM_FEATURE],
                signature=None,
            )
            digest = unsigned_envelope_hash(Envelope.model_validate_json(json.dumps(request)))
            request["signature"] = crypto.schnorr_sign(CLIENT_SECRET, digest, b"\x56" * 32).hex()
            seen: list[RequestContext] = []

            def responder(_request: object, _prior: object, context: RequestContext) -> live.Answer:
                seen.append(context)
                return live.Answer("error", {"code": "unsupported_request", "message": "x"})

            store.answer_request(_bytes(request), responder=responder, signer=crypto, now=1000)
            assert [context.cooperative for context in seen] == [True]
