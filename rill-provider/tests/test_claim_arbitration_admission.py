"""Featured acceptance is an affirmative, authenticated arbitration marker."""

from __future__ import annotations

import copy
import json
import os
from dataclasses import replace
from typing import TYPE_CHECKING, Any

import pytest
from rill_core.wire.canonical import canonicalize
from rill_core.wire.hashes import (
    COOPERATIVE_CLAIM_FEATURE,
    client_acceptance_hash,
    contract_hash,
    handshake_accept_hash,
    handshake_hash,
    handshake_init_hash,
    provider_terms_hash,
    unsigned_envelope_hash,
)
from rill_core.wire.messages import (
    ClientAcceptance,
    ContractTerms,
    Envelope,
    HandshakeAccept,
    HandshakeInit,
    ProviderTerms,
)
from test_live_session_store import Harness

from rill_provider import live_session_store as live

if TYPE_CHECKING:
    from pathlib import Path

    from rill_crypto import Context


NATIVE = pytest.mark.skipif(
    os.environ.get("RILLSWAP_RUN_NATIVE_CRYPTO") != "1",
    reason="set RILLSWAP_RUN_NATIVE_CRYPTO=1 with pinned native library",
)
CLIENT_SECRET = (2).to_bytes(32, "big")  # Fixture-only public deterministic scalars.
IDENTITY_SECRET = (1).to_bytes(32, "big")


def _signed(envelope: dict[str, Any], crypto: Context, salt: int) -> bytes:
    unsigned = dict(envelope, signature=None)
    digest = unsigned_envelope_hash(Envelope.model_validate_json(json.dumps(unsigned)))
    unsigned["signature"] = crypto.schnorr_sign(CLIENT_SECRET, digest, bytes([salt]) * 32).hex()
    return canonicalize(unsigned)


def _featured_handshake(
    harness: Harness, crypto: Context, *, featured: bool = True
) -> tuple[bytes, bytes, bytes, str]:
    init_envelope, accept_envelope, confirm_envelope = copy.deepcopy(harness.envelopes)
    features = [COOPERATIVE_CLAIM_FEATURE] if featured else []
    init_envelope["required_features"] = features
    init_envelope["payload"]["required_features"] = features
    initiation = HandshakeInit.model_validate_json(json.dumps(init_envelope["payload"]))
    accept_envelope["required_features"] = features
    accept_envelope["payload"]["accept"]["required_features"] = features
    accept_envelope["payload"]["accept"]["handshake_init_hash"] = handshake_init_hash(
        initiation
    ).hex()
    acceptance = HandshakeAccept.model_validate_json(
        json.dumps(accept_envelope["payload"]["accept"])
    )
    accept_envelope["payload"]["provider_identity_signature"] = crypto.schnorr_sign(
        IDENTITY_SECRET, handshake_accept_hash(acceptance), b"\x34" * 32
    ).hex()
    transcript = handshake_hash(initiation, acceptance).hex()
    confirm_envelope["payload"]["handshake_hash"] = transcript
    return (
        canonicalize(init_envelope),
        canonicalize(accept_envelope),
        _signed(confirm_envelope, crypto, 0x35),
        transcript,
    )


def _signed_request(  # noqa: PLR0913 - explicit signed fixture envelope fields
    harness: Harness,
    crypto: Context,
    *,
    sequence: int,
    message_id: str,
    message_type: str,
    contract: str | None,
    in_reply_to: str | None,
    payload: dict[str, Any],
    featured: bool = True,
) -> bytes:
    envelope = copy.deepcopy(harness.envelopes[2])
    envelope.update(
        message_id=message_id,
        sequence=sequence,
        in_reply_to=in_reply_to,
        message_type=message_type,
        contract_hash=contract,
        payload=payload,
        required_features=[COOPERATIVE_CLAIM_FEATURE] if featured else [],
    )
    return _signed(envelope, crypto, sequence)


@pytest.mark.native_crypto
@NATIVE
@pytest.mark.parametrize(
    "variant",
    [
        "valid",
        "legacy",
        "no_terms_feature",
        "no_handshake_feature",
        "bad_offer_signature",
        "bad_client_signature",
        "wrong_answer_contract",
        "error_answer",
        "signer_failure",
        "wrong_client_contract",
        "expired",
    ],
)
def test_featured_new_acceptance_admits_once_and_replays_without_second_effect(  # noqa: PLR0915 - one variant matrix
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, variant: str
) -> None:
    from rill_crypto import Context  # noqa: PLC0415 - opt-in native dependency

    harness = Harness(tmp_path, monkeypatch)
    harness.policy = replace(harness.policy, features=frozenset({COOPERATIVE_CLAIM_FEATURE}))
    harness.provision()
    with (
        Context(library_path=os.environ["RILL_CRYPTO_LIBRARY"]) as crypto,
        harness.acquire_at(harness.path, crypto=crypto, public_keys=crypto) as store,
    ):
        init, accept, confirm, transcript = _featured_handshake(
            harness, crypto, featured=variant not in ("no_handshake_feature", "legacy")
        )
        policy = store._policy  # noqa: SLF001
        if variant in ("no_handshake_feature", "legacy"):
            # Unfeatured sessions and their quotes exist only from before
            # cooperation was mandatory; acceptance runs under today's policy.
            store._policy = replace(policy, features=frozenset())  # noqa: SLF001
        session = store.reserve(init).session_id
        if variant == "no_handshake_feature":
            store._policy = policy  # noqa: SLF001
        store.commit_accept(accept)
        store.admit_confirm(confirm)
        source = copy.deepcopy(harness.source["contract_terms"])
        source["required_features"] = (
            [] if variant in ("no_terms_feature", "legacy") else [COOPERATIVE_CLAIM_FEATURE]
        )
        terms = ContractTerms.model_validate_json(json.dumps(source))
        digest = contract_hash(terms).hex()
        provider_terms = ProviderTerms(
            contract_hash=digest, contract_terms=terms, handshake_hash=transcript
        )
        payload = {
            "terms": provider_terms.model_dump(mode="json"),
            "provider_terms_signature": crypto.schnorr_sign(
                IDENTITY_SECRET, provider_terms_hash(provider_terms), b"\x36" * 32
            ).hex(),
        }
        if variant == "bad_offer_signature":
            payload["provider_terms_signature"] = "11" * 64
        quote = _signed_request(
            harness,
            crypto,
            sequence=2,
            message_id="21" * 32,
            message_type="quote_request",
            contract=None,
            in_reply_to=None,
            payload={"kind": "btc-to-ln", "mode": "indicative"},
            featured=variant != "legacy",
        )
        if variant == "no_handshake_feature":
            # A historical unfeatured session cannot obtain new (cooperative) terms.
            with pytest.raises(live.LiveSessionStoreError, match="request not admissible"):
                store.answer_request(quote, responder=pytest.fail, signer=crypto, now=1000)
            assert not store.pending_outbox()
            return
        offer_answer = store.answer_request(
            quote,
            responder=lambda *_: live.Answer(
                "terms_offer",
                payload,
                payment_hash=terms.invoice_binding.payment_hash,
                contract_hash=digest,
            ),
            signer=crypto,
            now=1000,
        )
        store._policy = policy  # noqa: SLF001
        offer = Envelope.model_validate_json(store.pending_outbox()[-1].canonical_bytes)
        assert offer.message_id == offer_answer.response_message_id
        client_acceptance = ClientAcceptance(
            contract_hash=digest,
            handshake_hash=transcript,
            session_id=session,
            client_session_xonly_key=harness.envelopes[0]["sender_session_key"],
            provider_session_xonly_key=offer.sender_session_key,
        )
        if variant == "wrong_client_contract":
            client_acceptance = client_acceptance.model_copy(update={"contract_hash": "ff" * 32})
        signature = crypto.schnorr_sign(
            CLIENT_SECRET, client_acceptance_hash(client_acceptance), b"\x37" * 32
        ).hex()
        if variant == "bad_client_signature":
            signature = "11" * 64
        document = _signed_request(
            harness,
            crypto,
            sequence=3,
            message_id="22" * 32,
            message_type="terms_accept",
            contract=digest,
            in_reply_to=offer.message_id,
            payload={
                "acceptance": client_acceptance.model_dump(mode="json"),
                "client_acceptance_signature": signature,
            },
            featured=variant != "legacy",
        )

        def answer() -> live.RequestAnswer:
            class BrokenSigner:
                def schnorr_sign(self, *_args: object) -> bytes:
                    return b"\x00" * 64

            response_contract = "ff" * 32 if variant == "wrong_answer_contract" else digest
            return store.answer_request(
                document,
                responder=lambda *_: live.Answer(
                    "error" if variant == "error_answer" else "ack",
                    {"acknowledged_message_id": "22" * 32},
                    contract_hash=response_contract,
                    effect=live.AcceptSwap(digest),
                ),
                signer=BrokenSigner() if variant == "signer_failure" else crypto,  # type: ignore[arg-type]
                now=1700001801 if variant == "expired" else 1001,
            )

        if variant not in ("valid", "legacy"):
            with pytest.raises(live.LiveSessionStoreError):
                answer()
            assert store._connection.execute(  # noqa: SLF001 - no half-admitted state
                "SELECT count(*) FROM swaps"
            ).fetchone() == (0,)
            assert store._connection.execute(  # noqa: SLF001
                "SELECT count(*) FROM claim_arbitration"
            ).fetchone() == (0,)
            assert store._connection.execute(  # noqa: SLF001
                "SELECT phase,next_client_seq FROM sessions WHERE session_id=?",
                (session,),
            ).fetchone() == ("CONFIRMED", 3)
            assert len(store.pending_outbox()) == 1  # no ack exposed
            return
        accepted = answer()
        assert not accepted.replay
        assert store._connection.execute(  # noqa: SLF001 - atomic admission evidence
            "SELECT contract_hash,version,state,deadline_at,fallback_raw "
            "FROM claim_arbitration WHERE session_id=?",
            (session,),
        ).fetchone() == ((digest, 1, "ADMITTED", None, None) if variant == "valid" else None)
        replay = store.answer_request(
            document,
            responder=lambda *_: pytest.fail("replay invoked responder"),
            signer=crypto,
        )
        assert replay.replay
        assert replay.response_message_id == accepted.response_message_id
        assert store._connection.execute(  # noqa: SLF001
            "SELECT count(*) FROM claim_arbitration"
        ).fetchone() == (int(variant == "valid"),)
    with harness.acquire() as restarted:
        assert restarted._connection.execute(  # noqa: SLF001
            "SELECT state FROM claim_arbitration WHERE session_id=?", (session,)
        ).fetchone() == (("ADMITTED",) if variant == "valid" else None)
