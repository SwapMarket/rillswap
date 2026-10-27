"""Reverse completion verifies archived public data without renewing cooperation."""

from __future__ import annotations

import asyncio
import json
from typing import TYPE_CHECKING
from unittest.mock import Mock

import pytest
from rill_core.settlement import (
    FundingOutput,
    UnilateralAuthorization,
    build_cooperative_claim,
    reconstruct_taproot_contract,
)
from rill_core.wire.canonical import canonicalize
from rill_core.wire.cooperative_messages import CooperativeClaimVerified
from rill_core.wire.hashes import unsigned_envelope_hash
from rill_core.wire.messages import Envelope
from rill_core.wire.quotes import TermsOfferPayload
from test_reverse_paid_preflight import _backends
from test_reverse_proposal_debt import pytestmark as pytestmark  # noqa: PLC0414
from test_reverse_proposal_reservation import reserved as reserved  # noqa: PLC0414
from test_reverse_signed_replay import _complete

from rill_provider.live_session_store import LiveSessionStoreError, SessionBlockedError
from rill_provider.reverse_settlement import ReverseSettlement

if TYPE_CHECKING:
    from test_reverse_proposal_reservation import ReservationCase

    from rill_provider.live_session_store import RequestAnswer

# ruff: noqa: SLF001 - exact archive/transaction and nonce-custody regression seams


async def _completion(case: ReservationCase) -> bytes:
    """Use real client/provider nonces and partial signatures for the accepted swap."""
    store, crypto = case.store, case.origin.crypto.crypto
    offer, txid, vout = store._connection.execute(
        "SELECT terms_offer,funding_txid,funding_vout FROM swaps"
    ).fetchone()
    offered = Envelope.model_validate_json(offer, strict=True)
    terms = TermsOfferPayload.model_validate_json(
        canonicalize(offered.payload), strict=True
    ).terms.contract_terms
    contract = reconstruct_taproot_contract(terms, keys=crypto)
    authorization = UnilateralAuthorization.from_terms(
        terms,
        FundingOutput(
            bytes.fromhex(txid),
            vout,
            int(terms.economics.contract_amount_sat),
            contract.script_pubkey,
        ),
        "claim",
        keys=crypto,
    )
    plan = build_cooperative_claim(authorization, fee_sat=300)
    proposal = json.loads(case.document)
    secret = (4).to_bytes(
        32, "big"
    )  # Public fixture client contract key, not the source's older key.
    assert crypto.public_key(secret).hex() == terms.client_contract_compressed_key
    attempt, nonce = crypto.musig_begin(
        secret_key=secret,
        user_public_key=bytes.fromhex(terms.client_contract_compressed_key),
        provider_public_key=bytes.fromhex(terms.provider_contract_compressed_key),
        tap_tweak=contract.tap_tweak,
        message=plan.signature_hash,
        cooperation_id=bytes.fromhex(proposal["payload"]["cooperation_id"]),
    )
    try:
        proposal["payload"]["public_nonce"] = nonce.hex()
        case.origin.crypto.permit_confirm(proposal)
        case.document = canonicalize(proposal)
        signed = Envelope.model_validate_json(await _complete(case), strict=True)
        partial = attempt.partial_sign_once(bytes.fromhex(signed.payload["public_nonce"]))
    finally:
        attempt.close()
    proposal.update(
        message_id="ab" * 32,
        sequence=store._connection.execute("SELECT next_client_seq FROM sessions").fetchone()[0],
        payload={
            "action": "cooperative_claim_complete",
            "cooperation_id": proposal["payload"]["cooperation_id"],
            "partial_signature": partial.hex(),
        },
    )
    case.origin.crypto.permit_confirm(proposal)
    return canonicalize(proposal)


async def _admit(case: ReservationCase, document: bytes) -> RequestAnswer:
    chain, hold = _backends(case)
    engine = ReverseSettlement(case.store, chain, hold, case.origin.crypto.crypto)
    result = await engine.verify_cooperative_completion(document, 1_700_000_100)
    assert chain.method_calls == []
    assert hold.method_calls == []
    return result


@pytest.mark.parametrize("restart", [False, True])
def test_public_completion_verifies_after_expiry_or_restart_without_financial_effects(
    reserved: ReservationCase, monkeypatch: pytest.MonkeyPatch, *, restart: bool
) -> None:
    async def exercise() -> None:
        document = await _completion(reserved)
        reserved.clock.advance(60)
        forbidden = Mock(side_effect=AssertionError("verification must not allocate a nonce"))
        monkeypatch.setattr(reserved.origin.crypto.crypto, "musig_begin", forbidden)

        async def check() -> None:
            store = reserved.store
            before = store._connection.execute("SELECT * FROM swaps").fetchall()
            attempts = store._connection.execute("SELECT * FROM cooperation_attempts").fetchall()
            sequences = store._connection.execute(
                "SELECT revision,next_client_seq,next_provider_seq FROM sessions"
            ).fetchone()
            result = await _admit(reserved, document)
            assert not result.replay
            encoded = store._connection.execute(
                "SELECT canonical_bytes FROM outbox WHERE message_id=?",
                (result.response_message_id,),
            ).fetchone()[0]
            reply = Envelope.model_validate_json(encoded, strict=True)
            payload = CooperativeClaimVerified.model_validate_json(
                canonicalize(reply.payload), strict=True
            )
            assert payload.status == "verified"
            assert reply.in_reply_to == result.request_message_id
            reserved.origin.crypto.crypto.schnorr_verify(
                bytes.fromhex(reply.sender_session_key),
                unsigned_envelope_hash(reply),
                bytes.fromhex(reply.signature),
            )
            assert store._connection.execute("SELECT * FROM swaps").fetchall() == before
            assert (
                store._connection.execute("SELECT * FROM cooperation_attempts").fetchall()
                == attempts
            )
            assert store._connection.execute(
                "SELECT revision,next_client_seq,next_provider_seq FROM sessions"
            ).fetchone() == tuple(value + 1 for value in sequences)
            repeated = json.loads(document)
            repeated["signature"] = reserved.origin.crypto.crypto.schnorr_sign(
                (8).to_bytes(32, "big"),
                unsigned_envelope_hash(Envelope.model_validate_json(document, strict=True)),
                b"\x66" * 32,
            ).hex()
            replay = await _admit(reserved, canonicalize(repeated))
            assert replay.replay
            assert replay.response_message_id == result.response_message_id

        if restart:
            reserved.store.close()
            with reserved.origin.acquire_at(
                reserved.origin.path,
                crypto=reserved.origin.crypto,
                public_keys=reserved.origin.crypto.crypto,
            ) as fresh:
                reserved.store = fresh
                await check()
        else:
            await check()
        forbidden.assert_not_called()

    asyncio.run(exercise())


def test_invalid_partial_is_not_admitted_and_distinct_second_completion_does_not_block(
    reserved: ReservationCase,
) -> None:
    async def exercise() -> None:
        document = await _completion(reserved)
        invalid = json.loads(document)
        invalid["payload"]["partial_signature"] = "00" * 32
        reserved.origin.crypto.permit_confirm(invalid)
        inbox = reserved.store._connection.execute("SELECT * FROM inbox").fetchall()
        with pytest.raises(LiveSessionStoreError, match="completion refused"):
            await _admit(reserved, canonicalize(invalid))
        assert reserved.store._connection.execute("SELECT * FROM inbox").fetchall() == inbox
        await _admit(reserved, document)
        second = json.loads(document)
        second.update(message_id="ac" * 32, sequence=second["sequence"] + 1)
        reserved.origin.crypto.permit_confirm(second)
        with pytest.raises(LiveSessionStoreError, match="completion refused"):
            await _admit(reserved, canonicalize(second))
        assert reserved.store._connection.execute("SELECT blocked FROM sessions").fetchone() == (0,)

    asyncio.run(exercise())


def test_completion_sequence_conflict_blocks_the_session(reserved: ReservationCase) -> None:
    async def exercise() -> None:
        document = await _completion(reserved)
        await _admit(reserved, document)
        changed = json.loads(document)
        changed["message_id"] = "ad" * 32
        reserved.origin.crypto.permit_confirm(changed)
        with pytest.raises(SessionBlockedError):
            await _admit(reserved, canonicalize(changed))
        assert reserved.store._connection.execute("SELECT blocked FROM sessions").fetchone() == (1,)

    asyncio.run(exercise())


@pytest.mark.parametrize("state", ["absent", "BURNED", "ABANDONED"])
def test_missing_or_unfinished_contribution_cannot_be_completed(
    reserved: ReservationCase, state: str
) -> None:
    async def exercise() -> None:
        document = await _completion(reserved)
        if state == "absent":
            reserved.store._connection.execute("DELETE FROM cooperation_attempts")
        else:
            reserved.store._connection.execute(
                "UPDATE cooperation_attempts SET state=?,local_nonce=NULL,peer_nonce=NULL,"
                "partial_signature=NULL,nonce_response_id=NULL,partial_response_id=NULL",
                (state,),
            )
        inbox = reserved.store._connection.execute("SELECT * FROM inbox").fetchall()
        with pytest.raises(LiveSessionStoreError, match="completion refused"):
            await _admit(reserved, document)
        assert reserved.store._connection.execute("SELECT * FROM inbox").fetchall() == inbox

    asyncio.run(exercise())
