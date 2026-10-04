"""The LN to BTC claimant spends by key path, or falls back to its durable script path."""

from __future__ import annotations

import asyncio
import json
from time import time as wall_clock
from typing import TYPE_CHECKING

import pytest
from rill_core.recovery import REVERSE_DISCLOSURE_EXTENSION
from rill_core.settlement import (
    FundingOutput,
    UnilateralAuthorization,
    reconstruct_taproot_contract,
    verify_cooperative_claim_proposal,
)
from rill_core.wire.hashes import COOPERATIVE_CLAIM_FEATURE
from rill_crypto import Context
from test_live_reverse_swap import _segwit_claim
from test_recovery_cli import NATIVE_LIBRARY, NATIVE_ONLY
from test_reverse_fallback_publication import _featured
from test_reverse_sdk_lifetime import NativeSdk

from rill_cli import live_reverse_swap as reverse
from rill_cli.live_swap import _Session

if TYPE_CHECKING:
    from pathlib import Path

    from rill_core.wire.messages import Envelope

PROVIDER_CONTRACT = (11).to_bytes(32, "big")
PROVIDER_SESSION = (9).to_bytes(32, "big")
KEY_PATH_SIGNATURE = 64
LIFETIME = 120  # long enough for the cooperative wait plus its unilateral reserve


def _provider(fixture: NativeSdk) -> _Session:
    session = _Session(
        fixture.session.connection,
        fixture.crypto,
        fixture.terms.network_identity,
        timeout=1,
        profile="ln-to-btc/v1",
    )
    session.secret = PROVIDER_SESSION
    session.key = fixture.crypto.public_key(PROVIDER_SESSION)[1:].hex()
    assert session.key == fixture.accept.provider_session_xonly_key
    session.session_id = fixture.session.session_id
    return session


def _proposal(fixture: NativeSdk) -> Envelope:
    (proposal,) = (
        call.args[0]
        for call in fixture.session.send.call_args_list
        if call.args[0].message_type == "action_request"
    )
    return proposal


def _reply(fixture: NativeSdk, mode: str) -> Envelope:
    """Answer the sent proposal as an honest (or faulty) provider would."""
    crypto = fixture.crypto
    proposal = _proposal(fixture)
    payload = proposal.payload
    terms = fixture.terms
    if mode == "declined":
        body: dict[str, object] = {
            "action": "cooperative_claim_propose",
            "cooperation_id": payload["cooperation_id"],
            "status": "declined",
        }
    else:
        funding = FundingOutput(
            bytes.fromhex(fixture.binding.funding_txid),
            fixture.binding.contract_vout,
            int(terms.economics.contract_amount_sat),
            bytes.fromhex(fixture.binding.contract_script_pubkey),
        )
        authorization = UnilateralAuthorization.from_terms(terms, funding, "claim", keys=crypto)
        plan = verify_cooperative_claim_proposal(
            bytes.fromhex(payload["unsigned_transaction"]), authorization
        )
        attempt, nonce = crypto.musig_begin(
            secret_key=PROVIDER_CONTRACT,
            user_public_key=bytes.fromhex(terms.client_contract_compressed_key),
            provider_public_key=bytes.fromhex(terms.provider_contract_compressed_key),
            tap_tweak=reconstruct_taproot_contract(terms, keys=crypto).tap_tweak,
            message=plan.signature_hash,
            cooperation_id=bytes.fromhex(payload["cooperation_id"]),
        )
        try:
            partial = attempt.partial_sign_once(bytes.fromhex(payload["public_nonce"]))
        finally:
            attempt.close()
        if mode == "bad partial":
            partial = bytes(32 * [1])
        body = {
            "action": "cooperative_claim_propose",
            "cooperation_id": payload["cooperation_id"],
            "status": "signed",
            "public_nonce": nonce.hex(),
            "partial_signature": partial.hex(),
        }
    return _provider(fixture).envelope(
        "action_result",
        body,
        in_reply_to=None if mode == "unrelated" else proposal.message_id,
        contract=proposal.contract_hash,
        required_features=(COOPERATIVE_CLAIM_FEATURE,),
    )


def _run(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, mode: str
) -> tuple[NativeSdk, reverse.ReverseSwapOutcome]:
    async def exercise(crypto: Context) -> tuple[NativeSdk, reverse.ReverseSwapOutcome]:
        fixture = NativeSdk(crypto, tmp_path, monkeypatch)
        _featured(fixture, monkeypatch)
        # Snapshots are stamped by the real wall clock; keep the claimant on it.
        monkeypatch.setattr(reverse.time, "time", wall_clock)

        async def receive(wanted: object, *, timeout: float | None = None) -> Envelope:  # noqa: ASYNC109
            assert timeout == reverse.REVERSE_PROPOSAL_SECONDS + reverse.REVERSE_REPLY_GRACE_SECONDS
            # The proposal is sent only after its disclosure snapshot is acknowledged.
            assert REVERSE_DISCLOSURE_EXTENSION in json.loads(fixture.documents[-1])["extensions"]
            fixture.reports.append("test: reply awaited after acknowledged disclosure")
            if mode == "timeout":
                raise TimeoutError
            reply = _reply(fixture, mode)
            assert callable(wanted)
            if not wanted(reply):
                raise TimeoutError
            return reply

        fixture.session.receive = receive  # type: ignore[method-assign]
        if mode == "relay":

            async def send(envelope: Envelope, _recipient: str) -> None:
                if envelope.message_type == "action_request":
                    raise ConnectionError("relay closed")

            fixture.session.send.side_effect = send

        def write(candidate: bytes, previous: bytes | None) -> bytes:
            fixture.write(candidate, previous)
            return candidate

        return fixture, await fixture.run(write, settle_timeout=LIFETIME)

    with Context(library_path=NATIVE_LIBRARY) as crypto:
        return asyncio.run(exercise(crypto))


@NATIVE_ONLY
@pytest.mark.native_crypto
def test_signed_reply_is_verified_aggregated_and_broadcast_as_a_key_path_spend(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fixture, outcome = _run(tmp_path, monkeypatch, "signed")
    (raw,) = fixture.broadcasts
    txid, witness = _segwit_claim(raw)
    assert outcome.claim_txid == txid
    # A single 64-byte BIP340 signature: no script, preimage, or control block.
    assert [len(item) for item in witness] == [KEY_PATH_SIGNATURE]
    assert fixture.preimage not in raw
    proposal = _proposal(fixture)
    assert proposal.payload["payment_preimage"] == fixture.preimage.hex()
    assert proposal.payload["deadline_height"] == (
        fixture.terms.refund_lock_height - fixture.terms.timing_policy.claim_confirmation_blocks
    )
    assert not any("unilaterally" in line for line in fixture.reports)
    assert "test: reply awaited after acknowledged disclosure" in fixture.reports
    assert any(line.startswith("cooperative claim ") for line in fixture.reports)


@NATIVE_ONLY
@pytest.mark.native_crypto
@pytest.mark.parametrize("mode", ["timeout", "declined", "bad partial", "unrelated", "relay"])
def test_any_cooperative_failure_claims_with_the_durable_script_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, mode: str
) -> None:
    fixture, outcome = _run(tmp_path, monkeypatch, mode)
    (raw,) = fixture.broadcasts
    txid, witness = _segwit_claim(raw)
    assert outcome.claim_txid == txid
    # Script path: signature, preimage, leaf script, control block.
    assert fixture.preimage in witness
    assert len(witness) > 1
    expected = {
        "timeout": "no cooperative signature in time",
        "declined": "provider declined cooperation",
        "bad partial": "provider cooperative signature invalid",
        "unrelated": "no cooperative signature in time",
        "relay": "no cooperative signature in time",
    }[mode]
    assert any(line.startswith(expected) for line in fixture.reports), fixture.reports
    awaited = "test: reply awaited after acknowledged disclosure" in fixture.reports
    assert awaited is (mode != "relay")


@NATIVE_ONLY
@pytest.mark.native_crypto
def test_tip_past_cooperative_deadline_never_discloses(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    async def exercise(crypto: Context) -> None:
        fixture = NativeSdk(crypto, tmp_path, monkeypatch)
        _featured(fixture, monkeypatch)
        fixture.wallet.tip_height.return_value = (
            fixture.terms.refund_lock_height - fixture.terms.timing_policy.claim_confirmation_blocks
        )

        def write(candidate: bytes, previous: bytes | None) -> bytes:
            fixture.write(candidate, previous)
            return candidate

        await fixture.run(write, settle_timeout=LIFETIME)
        assert "cooperative claim window unavailable; claiming unilaterally" in fixture.reports
        assert all(
            call.args[0].message_type != "action_request"
            for call in fixture.session.send.call_args_list
        )
        assert all(
            REVERSE_DISCLOSURE_EXTENSION not in json.loads(document)["extensions"]
            for document in fixture.documents
        )

    with Context(library_path=NATIVE_LIBRARY) as crypto:
        asyncio.run(exercise(crypto))


@NATIVE_ONLY
@pytest.mark.native_crypto
def test_short_settlement_lifetime_never_discloses(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A wait that could exhaust the lifetime would risk the unilateral claim."""

    async def exercise(crypto: Context) -> None:
        fixture = NativeSdk(crypto, tmp_path, monkeypatch)
        _featured(fixture, monkeypatch)

        def write(candidate: bytes, previous: bytes | None) -> bytes:
            fixture.write(candidate, previous)
            return candidate

        needed = (
            reverse.REVERSE_PROPOSAL_SECONDS
            + reverse.REVERSE_REPLY_GRACE_SECONDS
            + reverse.REVERSE_UNILATERAL_RESERVE_SECONDS
        )
        await fixture.run(write, settle_timeout=needed - 1)
        assert "cooperative claim window unavailable; claiming unilaterally" in fixture.reports
        assert all(
            call.args[0].message_type != "action_request"
            for call in fixture.session.send.call_args_list
        )
        (raw,) = fixture.broadcasts
        assert fixture.preimage in _segwit_claim(raw)[1]

    with Context(library_path=NATIVE_LIBRARY) as crypto:
        asyncio.run(exercise(crypto))


def test_client_window_stays_inside_the_provider_cap() -> None:
    assert reverse.REVERSE_PROPOSAL_SECONDS + reverse.REVERSE_REPLY_GRACE_SECONDS < 30
