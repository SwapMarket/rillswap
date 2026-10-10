"""Explicit unfeatured reverse business, without loosening forward or signing authority."""

from __future__ import annotations

import asyncio
import copy
import json
import os
from dataclasses import replace
from typing import TYPE_CHECKING, Any

import pytest
from pyrage import x25519
from rill_core.wire.canonical import canonicalize, parse_model_json
from rill_core.wire.hashes import (
    COOPERATIVE_CLAIM_FEATURE,
    EPOCH_SESSION_FEATURE,
    client_acceptance_hash,
    unsigned_envelope_hash,
)
from rill_core.wire.messages import ClientAcceptance, Envelope
from rill_core.wire.quotes import TermsOfferPayload
from test_live_session_store import POLICY, _bytes
from test_live_session_store import harness as harness  # noqa: PLC0414 - shared fixture
from test_reverse_quote_policy import HOLD, REVERSE_FIRM, TERMS

from rill_provider import live_session_store as live
from rill_provider.live_session_store import LiveSessionStoreError
from rill_provider.settlement_policy import answer_client_request

if TYPE_CHECKING:
    from test_live_session_store import Harness

    from rill_provider.live_session_store import Answer, RequestContext

# ruff: noqa: SLF001 - exact admission records and absence of cooperative provenance


def reverse_init(harness: Harness, features: tuple[str, ...] = ()) -> None:
    harness.policy = replace(
        POLICY, profile="ln-to-btc/v1", features=frozenset({COOPERATIVE_CLAIM_FEATURE})
    )
    for envelope in harness.envelopes:
        envelope["profile_id"] = "ln-to-btc/v1"
        envelope["required_features"] = list(features)
    harness.envelopes[0]["payload"]["profile_id"] = "ln-to-btc/v1"
    harness.envelopes[0]["payload"]["required_features"] = list(features)
    harness.init = _bytes(harness.envelopes[0])


def test_reverse_unfeatured_reservation_keeps_advertised_policy_unchanged(harness: Harness) -> None:
    reverse_init(harness)
    harness.provision()
    with harness.acquire() as store:
        reserved = store.reserve(harness.init)
        assert store.reserve(harness.init) == reserved
        assert json.loads(store._connection.execute("SELECT policy_jcs FROM meta").fetchone()[0])[
            "features"
        ] == [COOPERATIVE_CLAIM_FEATURE]
        assert store._reverse_negotiations == {}


def test_unilateral_reverse_does_not_waive_epoch_admission(harness: Harness) -> None:
    reverse_init(harness)
    harness.policy = replace(
        harness.policy, features=frozenset({COOPERATIVE_CLAIM_FEATURE, EPOCH_SESSION_FEATURE})
    )
    harness.provision()
    with harness.acquire() as store:
        with pytest.raises(LiveSessionStoreError, match="epoch-bound"):
            store.reserve(harness.init)
        assert store._connection.execute("SELECT count(*) FROM sessions").fetchone() == (0,)


@pytest.mark.native_crypto
@pytest.mark.skipif(
    os.environ.get("RILLSWAP_RUN_NATIVE_CRYPTO") != "1", reason="needs pinned native crypto"
)
@pytest.mark.parametrize("cooperative", [False, True])
def test_fresh_reverse_negotiation_accepts_matching_terms_without_node_or_funds(  # noqa: PLR0915 - one authenticated admission story
    harness: Harness, monkeypatch: pytest.MonkeyPatch, *, cooperative: bool
) -> None:
    from rill_crypto import Context  # noqa: PLC0415

    from rill_provider.provider_identity import ProviderIdentity  # noqa: PLC0415

    features = (COOPERATIVE_CLAIM_FEATURE,) if cooperative else ()
    reverse_init(harness, features)
    harness.provision()
    unlock = x25519.Identity.generate()
    with Context(library_path=os.environ["RILL_CRYPTO_LIBRARY"]) as crypto:
        with monkeypatch.context() as patch:
            patch.setattr(
                "rill_provider.provider_identity.secrets.token_bytes",
                lambda _n: (1).to_bytes(32, "big"),
            )
            key = ProviderIdentity.provision(
                harness.path.parent / "id.age", recipient=str(unlock.to_public()), crypto=crypto
            )
        identity = ProviderIdentity.load(
            harness.path.parent / "id.age",
            custody_identity=str(unlock),
            expected_xonly_public_key=key,
            crypto=crypto,
        )
        with harness.acquire_at(harness.path, crypto=crypto, public_keys=crypto) as store:
            reservation = store.reserve(harness.init)
            accepted = store.create_accept(
                reservation.session_id,
                identity=identity,
                transport_endpoints=("wss://relay.test/",),
            )
            assert json.loads(accepted.canonical_bytes)["payload"]["accept"][
                "required_features"
            ] == list(features)
            confirm = copy.deepcopy(harness.envelopes[2])
            confirm["in_reply_to"] = accepted.message_id
            confirm["payload"]["handshake_hash"] = accepted.transcript_digest
            # Provider keys are freshly built rather than inherited fixture keys.
            confirm["payload"]["provider_session_xonly_key"] = reservation.provider_session_key

            def client_sign(envelope: dict[str, Any]) -> bytes:
                envelope["signature"] = None
                envelope["signature"] = crypto.schnorr_sign(
                    (2).to_bytes(32, "big"),
                    unsigned_envelope_hash(
                        Envelope.model_validate_json(_bytes(envelope), strict=True)
                    ),
                    b"\x55" * 32,
                ).hex()
                return _bytes(envelope)

            store.admit_confirm(client_sign(confirm))
            schedule = replace(
                TERMS,
                firm=replace(TERMS.firm, sign=identity.sign_provider_terms),
                hold=("lnbcrt1007u1hold", HOLD),
            )

            def responder(
                request: Envelope, prior: tuple[Envelope, ...], context: RequestContext
            ) -> Answer:
                return answer_client_request(request, prior, context, schedule, crypto)

            request = copy.deepcopy(confirm)
            request.update(
                message_type="quote_request",
                sequence=2,
                message_id="66" * 32,
                in_reply_to=None,
                contract_hash=None,
                payload=copy.deepcopy(REVERSE_FIRM) | {"extensions": {}},
            )
            store.answer_request(
                client_sign(request), responder=responder, signer=crypto, now=TERMS.now
            )
            response = next(
                Envelope.model_validate_json(item.canonical_bytes, strict=True)
                for item in store.pending_outbox()
                if b'"message_type":"terms_offer"' in item.canonical_bytes
            )
            offer = parse_model_json(TermsOfferPayload, canonicalize(response.payload))
            assert offer.terms.contract_terms.required_features == features
            assert response.payload["hold_invoice"] == "lnbcrt1007u1hold"
            acceptance = ClientAcceptance(
                contract_hash=offer.terms.contract_hash,
                handshake_hash=accepted.transcript_digest,
                session_id=reservation.session_id,
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
                    "client_acceptance_signature": crypto.schnorr_sign(
                        (2).to_bytes(32, "big"), client_acceptance_hash(acceptance), b"\x55" * 32
                    ).hex(),
                },
            )
            answer = store.answer_request(
                client_sign(request), responder=responder, signer=crypto, now=TERMS.now
            )
            swap = live._swap(store._connection, reservation.session_id)
            assert swap is not None
            assert swap.state == "ACCEPTED"
            assert any(
                item.message_id == answer.response_message_id
                and b'"message_type":"ack"' in item.canonical_bytes
                for item in store.pending_outbox()
            )
            assert (
                store._has_original_reverse_negotiation(
                    reservation.session_id, offer.terms.contract_hash
                )
                is cooperative
            )
            if not cooperative:
                # Submit a signed action to the actual proposal admission entry,
                # not merely a passive provenance-map assertion.
                proposal = copy.deepcopy(request)
                terms = offer.terms.contract_terms
                destination = bytes.fromhex(terms.client_destination_script)
                unsigned = (
                    bytes.fromhex("0200000001")
                    + b"\x11" * 32
                    + bytes.fromhex("0000000000fdffffff01")
                    + (int(terms.economics.contract_amount_sat) - 100).to_bytes(8, "little")
                    + bytes([len(destination)])
                    + destination
                    + b"\0" * 4
                )
                proposal.update(
                    message_type="action_request",
                    sequence=4,
                    message_id="68" * 32,
                    in_reply_to=None,
                    payload={
                        "action": "cooperative_claim_propose",
                        "cooperation_id": "69" * 32,
                        "payment_preimage": "11" * 32,
                        "public_nonce": (
                            crypto.public_key((7).to_bytes(32, "big"))
                            + crypto.public_key((8).to_bytes(32, "big"))
                        ).hex(),
                        "unsigned_transaction": unsigned.hex(),
                        "deadline_at": TERMS.now + 20,
                        "deadline_height": 900,
                    },
                )
                document = client_sign(proposal)
                tables = [
                    name
                    for (name,) in store._connection.execute(
                        "SELECT name FROM sqlite_master WHERE type='table' "
                        "AND name LIKE '%cooperat%'"
                    )
                ]
                assert tables
                assert all(name.isidentifier() for name in tables)

                def rows() -> dict[str, list[tuple[object, ...]]]:
                    return {
                        name: store._connection.execute(f'SELECT * FROM "{name}"').fetchall()  # noqa: S608 - validated SQLite schema identifiers
                        for name in tables
                    }

                before = rows()
                economic_calls = []

                def forbidden(*_args: object, **_kwargs: object) -> bytes:
                    economic_calls.append(True)
                    raise AssertionError("unfeatured cooperation cannot allocate or sign")

                async def refuse() -> None:
                    async with store.reverse_operations.operation() as operation:
                        with pytest.raises(
                            LiveSessionStoreError, match="reverse proposal unavailable"
                        ):
                            store._admit_reverse_cooperative_proposal(
                                document, operation=operation, wall_clock=lambda: float(TERMS.now)
                            )

                with monkeypatch.context() as patch:
                    patch.setattr(type(crypto), "schnorr_sign", forbidden)
                    patch.setattr(type(crypto), "musig_begin", forbidden)
                    asyncio.run(refuse())
                assert economic_calls == []
                assert rows() == before
                assert store._reverse_negotiations == {}
                assert store._reverse_proposals == {}
