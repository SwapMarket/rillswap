"""Burn-only store boundary; these fixtures do not simulate live peer admission."""

from __future__ import annotations

import copy
import hashlib
import json
import os
import select
import signal
import sqlite3
from dataclasses import replace
from typing import TYPE_CHECKING, Any

import pyrage
import pytest
from rill_core.settlement import (
    CooperativeClaimPlan,
    FundingOutput,
    UnilateralAuthorization,
    build_cooperative_claim,
)
from rill_core.wire.canonical import canonicalize, parse_json_strict
from rill_core.wire.hashes import (
    COOPERATIVE_CLAIM_FEATURE,
    contract_hash,
    handshake_hash,
    handshake_init_hash,
)
from rill_core.wire.messages import ContractTerms, Envelope, HandshakeAccept, HandshakeInit
from test_live_session_store import Harness, PurePublicKeys
from test_payment_dispatch_store import _insert_funded_swap
from test_settlement_engine import BINDING

from rill_provider import live_session_store as live

if TYPE_CHECKING:
    from pathlib import Path


class PinnedContractKeys(PurePublicKeys):
    """Fixture-only reference outputs; not a production curve implementation."""

    def __init__(self, terms: ContractTerms, artifacts: dict[str, str | int]) -> None:
        self.terms, self.artifacts = terms, artifacts

    def musig_internal_key(self, user: bytes, provider: bytes) -> tuple[bytes, int]:
        assert user.hex() == self.terms.client_contract_compressed_key
        assert provider.hex() == self.terms.provider_contract_compressed_key
        return bytes.fromhex(str(self.artifacts["internal_xonly_key"])), int(
            self.artifacts["internal_key_parity"]
        )

    def musig_output_key(self, user: bytes, provider: bytes, tweak: bytes) -> tuple[bytes, int]:
        assert user.hex() == self.terms.client_contract_compressed_key
        assert provider.hex() == self.terms.provider_contract_compressed_key
        assert tweak.hex() == self.artifacts["tap_tweak"]
        return bytes.fromhex(str(self.artifacts["output_xonly_key"])), int(
            self.artifacts["output_key_parity"]
        )


class FixtureEnvelopeSigner:
    """Allows only its own exact test signature; not actual BIP340 signing."""

    def __init__(self, harness: Harness, keys: PurePublicKeys) -> None:
        self.crypto, self.keys = harness.crypto, keys

    def schnorr_sign(self, secret_key: bytes, message: bytes, auxiliary_random: bytes) -> bytes:
        assert len(auxiliary_random) == 32
        signature = b"\x77" * 64
        self.crypto.permitted.add((self.keys.public_key(secret_key)[1:], message, signature))
        return signature


def _assert_fork_refuses_parent_nonce(store: live.LiveSessionStore, session: str) -> None:
    """A child cannot allocate or close a parent's live store-owned handle."""
    read_fd, write_fd = os.pipe()
    try:
        child = os.fork()
        if child == 0:
            os.close(read_fd)
            try:
                with pytest.raises(live.StaleOwnerError, match="inherited across fork"):
                    store._begin_and_commit_cooperative_proposal(  # noqa: SLF001
                        session, b"\xff" * 32, now=1002
                    )
                store.close()  # inherited descriptor copy only, not native handles
                os.write(write_fd, b"refused")
            except Exception:  # noqa: BLE001 - report every child failure to parent
                os.write(write_fd, b"failed")
            finally:
                os._exit(0)  # child must never run inherited pytest teardown
        os.close(write_fd)
        readable, _, _ = select.select([read_fd], [], [], 2)
        if not readable:
            os.kill(child, signal.SIGKILL)
            os.waitpid(child, 0)
            pytest.fail("fork child blocked on inherited provider or native ownership")
        result = os.read(read_fd, 32)
        _, status = os.waitpid(child, 0)
        assert result == b"refused"
        assert os.WIFEXITED(status)
    finally:
        os.close(read_fd)


def _featured_paid_swap(
    harness: Harness, store: live.LiveSessionStore, *, with_feature: bool = True
) -> tuple[str, CooperativeClaimPlan, FundingOutput]:
    """Construct a retained state boundary, not an authenticated peer transcript.

    The actual provider cannot issue featured terms yet. Acceptance and
    signature checks need a later live feature-negotiation test. This synthetic
    fixture isolates the store's *independent* persisted-fact checks.
    """
    session = _insert_funded_swap(store, harness, "PAID")
    source = copy.deepcopy(harness.source)
    context = source["verification_context"]
    features = [COOPERATIVE_CLAIM_FEATURE] if with_feature else []
    context["handshake_init"]["required_features"] = features
    init = HandshakeInit.model_validate_json(json.dumps(context["handshake_init"]), strict=True)
    context["handshake_accept"]["required_features"] = features
    context["handshake_accept"]["handshake_init_hash"] = handshake_init_hash(init).hex()
    accept = HandshakeAccept.model_validate_json(
        json.dumps(context["handshake_accept"]), strict=True
    )
    transcript = handshake_hash(init, accept).hex()
    source["contract_terms"]["required_features"] = features
    terms = ContractTerms.model_validate_json(json.dumps(source["contract_terms"]), strict=True)
    digest = contract_hash(terms).hex()
    init_envelope = copy.deepcopy(harness.envelopes[0])
    init_envelope["payload"] = init.model_dump(mode="json")
    init_envelope["required_features"] = features
    accept_envelope = copy.deepcopy(harness.envelopes[1])
    accept_envelope["payload"]["accept"] = accept.model_dump(mode="json")
    accept_envelope["required_features"] = features
    offer = copy.deepcopy(harness.envelopes[1])
    offer.update(
        message_type="terms_offer",
        contract_hash=digest,
        payload={
            "terms": {
                "contract_hash": digest,
                "contract_terms": terms.model_dump(mode="json"),
                "handshake_hash": transcript,
            },
            "provider_terms_signature": context["provider_terms_signature"],
        },
    )
    accepted = copy.deepcopy(harness.envelopes[2])
    accepted.update(
        message_type="terms_accept",
        contract_hash=digest,
        payload={
            "acceptance": {
                "contract_hash": digest,
                "handshake_hash": transcript,
                "session_id": session,
                "client_session_xonly_key": init.client_session_xonly_key,
                "provider_session_xonly_key": accept.provider_session_xonly_key,
            },
            "client_acceptance_signature": context["client_acceptance_signature"],
        },
    )
    signed_binding = BINDING.model_copy(update={"contract_hash": digest})
    funding_envelope = copy.deepcopy(harness.envelopes[2])
    funding_envelope.update(
        message_type="funding_binding",
        contract_hash=digest,
        payload={
            "binding": signed_binding.model_dump(mode="json"),
            "funding_binding_signature": "00" * 64,
            "funding_transaction": "00" * 100,
        },
    )
    preimage = b"\x42" * 32
    assert hashlib.sha256(preimage).hexdigest() == terms.invoice_binding.payment_hash
    connection = store._connection  # noqa: SLF001 - synthetic persisted-state fixture only
    (challenge, provider_key) = connection.execute(
        "SELECT provider_challenge,provider_session_key FROM sessions WHERE session_id=?",
        (session,),
    ).fetchone()
    sealed = pyrage.encrypt(
        store._key_record(  # noqa: SLF001 - rebuild fixture custody for the changed init digest
            session, handshake_init_hash(init).hex(), challenge, harness.scalar, provider_key
        ),
        [harness.custody.to_public()],
    )
    connection.execute(
        "UPDATE sessions SET init_bytes=?,accept_bytes=?,transcript_digest=?,"
        "session_secret_age=? WHERE session_id=?",
        (canonicalize(init_envelope), canonicalize(accept_envelope), transcript, sealed, session),
    )
    connection.execute(
        "UPDATE swaps SET contract_hash=?,terms_offer=?,terms_accept=?,funding_binding=?,"
        "preimage=? WHERE session_id=?",
        (
            digest,
            canonicalize(offer),
            canonicalize(accepted),
            canonicalize(funding_envelope),
            preimage.hex(),
            session,
        ),
    )
    store._public_keys = PinnedContractKeys(terms, source["taproot_contract"])  # noqa: SLF001
    funding = FundingOutput(
        bytes.fromhex(signed_binding.funding_txid),
        signed_binding.contract_vout,
        int(signed_binding.contract_value_sat),
        bytes.fromhex(signed_binding.contract_script_pubkey),
    )
    authorization = UnilateralAuthorization.from_terms(
        terms,
        funding,
        "claim",
        keys=store._public_keys,  # noqa: SLF001
    )
    return session, build_cooperative_claim(authorization, fee_sat=300), funding


def test_burn_is_durable_and_never_reissued_after_abandonment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    harness = Harness(tmp_path, monkeypatch)
    harness.policy = replace(harness.policy, features=frozenset({COOPERATIVE_CLAIM_FEATURE}))
    harness.provision()
    with harness.acquire() as store:
        session, plan, _ = _featured_paid_swap(harness, store)
        store._burn_cooperative_claim(  # noqa: SLF001 - internal durable admission boundary
            session, b"\x11" * 32, plan, now=1000, deadline_at=1020, deadline_height=1100
        )
        original = store._connection.execute(  # noqa: SLF001
            "SELECT state,binding,owner_generation FROM cooperation_attempts"
        ).fetchone()
        assert original[0] == "BURNED"
        binding = parse_json_strict(original[1])
        assert binding["unsigned_transaction"] == plan.base_transaction.hex()
        assert binding["signature_hash"] == plan.signature_hash.hex()
        assert (
            binding["contract_hash"]
            == store._connection.execute(  # noqa: SLF001
                "SELECT contract_hash FROM swaps WHERE session_id=?", (session,)
            ).fetchone()[0]
        )
        assert original[2] == store.generation
        for candidate in (b"\x11" * 32, b"\x12" * 32):
            with pytest.raises(live.LiveSessionStoreError, match="unavailable"):
                store._burn_cooperative_claim(  # noqa: SLF001
                    session,
                    candidate,
                    plan,
                    now=1000,
                    deadline_at=1020,
                    deadline_height=1100,
                )
    with harness.acquire() as store:
        assert store._connection.execute(  # noqa: SLF001
            "SELECT cooperation_id,state,binding FROM cooperation_attempts"
        ).fetchone() == (b"\x11" * 32, "ABANDONED", original[1])
        with pytest.raises(live.LiveSessionStoreError, match="unavailable"):
            store._burn_cooperative_claim(  # noqa: SLF001
                session,
                b"\x13" * 32,
                plan,
                now=1000,
                deadline_at=1020,
                deadline_height=1100,
            )


def test_burn_refuses_wrong_transaction_funding_or_deadline_without_an_attempt(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    harness = Harness(tmp_path, monkeypatch)
    harness.policy = replace(harness.policy, features=frozenset({COOPERATIVE_CLAIM_FEATURE}))
    harness.provision()
    with harness.acquire() as store:
        session, plan, funding = _featured_paid_swap(harness, store)
        wrong_outpoint = replace(funding, txid=b"\xff" * 32)
        (offer,) = store._connection.execute(  # noqa: SLF001 - synthetic retained terms
            "SELECT terms_offer FROM swaps WHERE session_id=?", (session,)
        ).fetchone()
        wrong_plan = build_cooperative_claim(
            UnilateralAuthorization.from_terms(
                live._offer_terms(offer),  # noqa: SLF001
                wrong_outpoint,
                "claim",
                keys=store._public_keys,  # noqa: SLF001
            ),
            fee_sat=300,
        )
        for attempt, deadline in (
            (replace(plan, signature_hash=b"\xff" * 32), 1020),
            (wrong_plan, 1020),
            (plan, 1031),
        ):
            with pytest.raises(live.LiveSessionStoreError):
                store._burn_cooperative_claim(  # noqa: SLF001
                    session,
                    b"\x21" * 32,
                    attempt,
                    now=1000,
                    deadline_at=deadline,
                    deadline_height=1100,
                )
        assert store._connection.execute(  # noqa: SLF001
            "SELECT count(*) FROM cooperation_attempts"
        ).fetchone() == (0,)


@pytest.mark.parametrize("preimage", [None, "GG" * 32, "43" * 32, b"\x42" * 32])
def test_burn_refuses_missing_malformed_and_wrong_hash_preimage(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, preimage: str | bytes | None
) -> None:
    harness = Harness(tmp_path, monkeypatch)
    harness.policy = replace(harness.policy, features=frozenset({COOPERATIVE_CLAIM_FEATURE}))
    harness.provision()
    with harness.acquire() as store:
        session, plan, _ = _featured_paid_swap(harness, store)
        store._connection.execute(  # noqa: SLF001 - mutate retained-state fixture only
            "UPDATE swaps SET preimage=? WHERE session_id=?", (preimage, session)
        )
        with pytest.raises(live.LiveSessionStoreError, match="authority unavailable"):
            store._burn_cooperative_claim(  # noqa: SLF001
                session,
                b"\x31" * 32,
                plan,
                now=1000,
                deadline_at=1020,
                deadline_height=1100,
            )
        assert store._connection.execute(  # noqa: SLF001
            "SELECT count(*) FROM cooperation_attempts"
        ).fetchone() == (0,)


def test_legacy_swap_never_gains_nonce_authority_from_empty_v12_table(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    harness = Harness(tmp_path, monkeypatch)
    harness.provision()
    with harness.acquire() as store:
        # Deliberately no supported or jointly signed cooperative feature.
        session = _insert_funded_swap(store, harness, "PAID")
        terms = ContractTerms.model_validate_json(json.dumps(harness.source["contract_terms"]))
        keys = PinnedContractKeys(terms, harness.source["taproot_contract"])
        funding = FundingOutput(
            bytes.fromhex(BINDING.funding_txid),
            BINDING.contract_vout,
            int(BINDING.contract_value_sat),
            bytes.fromhex(BINDING.contract_script_pubkey),
        )
        plan = build_cooperative_claim(
            UnilateralAuthorization.from_terms(terms, funding, "claim", keys=keys), fee_sat=300
        )
        with pytest.raises(live.LiveSessionStoreError, match="unavailable"):
            store._burn_cooperative_claim(  # noqa: SLF001
                session,
                b"\x31" * 32,
                plan,
                now=1000,
                deadline_at=1020,
                deadline_height=1100,
            )
        assert store._connection.execute(  # noqa: SLF001
            "SELECT count(*) FROM cooperation_attempts"
        ).fetchone() == (0,)


def test_supported_cooperation_cannot_upgrade_an_accepted_legacy_contract(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    harness = Harness(tmp_path, monkeypatch)
    harness.policy = replace(harness.policy, features=frozenset({COOPERATIVE_CLAIM_FEATURE}))
    harness.provision()
    with harness.acquire() as store:
        session, plan, _ = _featured_paid_swap(harness, store, with_feature=False)
        with pytest.raises(live.LiveSessionStoreError, match="authority unavailable"):
            store._burn_cooperative_claim(  # noqa: SLF001
                session,
                b"\x32" * 32,
                plan,
                now=1000,
                deadline_at=1020,
                deadline_height=1100,
            )
        assert store._connection.execute(  # noqa: SLF001
            "SELECT count(*) FROM cooperation_attempts"
        ).fetchone() == (0,)


def test_public_nonce_and_signed_proposal_commit_before_outbox_replay(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    harness = Harness(tmp_path, monkeypatch)
    harness.policy = replace(harness.policy, features=frozenset({COOPERATIVE_CLAIM_FEATURE}))
    harness.provision()
    nonce = b"\x02" * 66  # structural test only; native integration validates the curve
    with harness.acquire() as store:
        session, plan, _ = _featured_paid_swap(harness, store)
        store._burn_cooperative_claim(  # noqa: SLF001
            session,
            b"\x51" * 32,
            plan,
            now=1000,
            deadline_at=1020,
            deadline_height=1100,
        )

        def validate_nonce(value: bytes) -> None:
            if value != nonce:
                raise ValueError("unexpected test nonce")

        monkeypatch.setattr(
            harness.crypto, "musig_public_nonce_validate", validate_nonce, raising=False
        )
        signer = FixtureEnvelopeSigner(harness, store._public_keys)  # noqa: SLF001
        message_id = store._commit_cooperative_proposal_nonce(  # noqa: SLF001
            session, b"\x51" * 32, nonce, signer=signer, now=1001
        )
        (state, saved_nonce, response_id) = store._connection.execute(  # noqa: SLF001
            "SELECT state,local_nonce,nonce_response_id FROM cooperation_attempts"
        ).fetchone()
        assert (state, saved_nonce, response_id) == ("NONCE_READY", nonce, message_id)
        pending = store.pending_outbox()
        assert len(pending) == 1
        assert pending[0].message_id == message_id
        envelope = Envelope.model_validate_json(pending[0].canonical_bytes, strict=True)
        assert envelope.message_type == "action_request"
        assert envelope.required_features == (COOPERATIVE_CLAIM_FEATURE,)
        assert envelope.payload["unsigned_transaction"] == plan.base_transaction.hex()
        assert envelope.payload["public_nonce"] == nonce.hex()
        assert envelope.payload["payment_preimage"] == "42" * 32
        with pytest.raises(live.LiveSessionStoreError, match="unavailable"):
            store._commit_cooperative_proposal_nonce(  # noqa: SLF001
                session, b"\x51" * 32, nonce, signer=signer, now=1002
            )
    with harness.acquire() as store:
        assert store._connection.execute(  # noqa: SLF001
            "SELECT state,local_nonce,nonce_response_id FROM cooperation_attempts"
        ).fetchone() == ("ABANDONED", nonce, message_id)
        # Replaying already committed public bytes never recreates a secret
        # handle or re-signs a changed message after the owner is gone.
        assert store.pending_outbox()[0].canonical_bytes == pending[0].canonical_bytes
        with pytest.raises(live.LiveSessionStoreError, match="unavailable"):
            store._commit_cooperative_proposal_nonce(  # noqa: SLF001
                session, b"\x51" * 32, nonce, signer=signer, now=1002
            )
        with pytest.raises(live.LiveSessionStoreError, match="unavailable"):
            store._burn_cooperative_claim(  # noqa: SLF001
                session,
                b"\x52" * 32,
                plan,
                now=1002,
                deadline_at=1019,
                deadline_height=1100,
            )
        # Do not cancel the already sequenced proposal. A later fallback
        # observation must have a contiguous sequence and remain deliverable.
        with store._write() as connection:  # noqa: SLF001 - outbox sequence boundary
            observation_id = store._record_observation(  # noqa: SLF001
                connection,
                session,
                {"event": "fallback"},
                FixtureEnvelopeSigner(harness, PurePublicKeys()),
                1003,
            )
        messages = store.pending_outbox()
        assert [entry.message_id for entry in messages] == [message_id, observation_id]
        assert [
            Envelope.model_validate_json(entry.canonical_bytes).sequence for entry in messages
        ] == [0, 1]


def test_failed_proposal_signing_rolls_back_nonce_and_outbox_together(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    harness = Harness(tmp_path, monkeypatch)
    harness.policy = replace(harness.policy, features=frozenset({COOPERATIVE_CLAIM_FEATURE}))
    harness.provision()
    with harness.acquire() as store:
        session, plan, _ = _featured_paid_swap(harness, store)
        store._burn_cooperative_claim(  # noqa: SLF001
            session,
            b"\x61" * 32,
            plan,
            now=1000,
            deadline_at=1020,
            deadline_height=1100,
        )
        monkeypatch.setattr(
            harness.crypto, "musig_public_nonce_validate", lambda _nonce: None, raising=False
        )

        class FailingSigner:
            def schnorr_sign(
                self, _secret_key: bytes, _message: bytes, _auxiliary_random: bytes
            ) -> bytes:
                raise OSError("fixture signing interrupted")

        with pytest.raises(live.LiveSessionStoreError, match="commit refused"):
            store._commit_cooperative_proposal_nonce(  # noqa: SLF001
                session,
                b"\x61" * 32,
                b"\x02" * 66,
                signer=FailingSigner(),
                now=1001,
            )
        assert store._connection.execute(  # noqa: SLF001
            "SELECT state,local_nonce,nonce_response_id FROM cooperation_attempts"
        ).fetchone() == ("BURNED", None, None)
        assert store.pending_outbox() == ()
        before_sequence = store._connection.execute(  # noqa: SLF001
            "SELECT next_provider_seq FROM sessions WHERE session_id=?", (session,)
        ).fetchone()

        original_record = store._record_observation  # noqa: SLF001

        def interrupted_record(*args: object, **kwargs: object) -> str:
            original_record(*args, **kwargs)  # type: ignore[arg-type]
            raise OSError("interrupted after outbox insertion")

        monkeypatch.setattr(store, "_record_observation", interrupted_record)
        with pytest.raises(live.LiveSessionStoreError, match="commit refused"):
            store._commit_cooperative_proposal_nonce(  # noqa: SLF001
                session,
                b"\x61" * 32,
                b"\x02" * 66,
                signer=FixtureEnvelopeSigner(harness, store._public_keys),  # noqa: SLF001
                now=1001,
            )
        assert (
            store._connection.execute(  # noqa: SLF001
                "SELECT next_provider_seq FROM sessions WHERE session_id=?", (session,)
            ).fetchone()
            == before_sequence
        )
        assert store._connection.execute(  # noqa: SLF001
            "SELECT state,local_nonce,nonce_response_id FROM cooperation_attempts"
        ).fetchone() == ("BURNED", None, None)
        assert store.pending_outbox() == ()
    with harness.acquire() as store:
        assert store._connection.execute(  # noqa: SLF001
            "SELECT state FROM cooperation_attempts"
        ).fetchone() == ("ABANDONED",)


@pytest.mark.parametrize("changed", ["preimage", "funding", "time"])
def test_committed_burn_cannot_publish_against_changed_facts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, changed: str
) -> None:
    harness = Harness(tmp_path, monkeypatch)
    harness.policy = replace(harness.policy, features=frozenset({COOPERATIVE_CLAIM_FEATURE}))
    harness.provision()
    with harness.acquire() as store:
        session, plan, _ = _featured_paid_swap(harness, store)
        store._burn_cooperative_claim(  # noqa: SLF001
            session,
            b"\x71" * 32,
            plan,
            now=1000,
            deadline_at=1020,
            deadline_height=1100,
        )
        if changed == "preimage":
            store._connection.execute(  # noqa: SLF001 - simulate inconsistent retained evidence
                "UPDATE swaps SET preimage=? WHERE session_id=?", ("41" * 32, session)
            )
        elif changed == "funding":
            store._connection.execute(  # noqa: SLF001
                "UPDATE swaps SET funding_binding=NULL WHERE session_id=?", (session,)
            )
        monkeypatch.setattr(
            harness.crypto, "musig_public_nonce_validate", lambda _nonce: None, raising=False
        )
        with pytest.raises(live.LiveSessionStoreError, match=r"unavailable|binding changed"):
            store._commit_cooperative_proposal_nonce(  # noqa: SLF001
                session,
                b"\x71" * 32,
                b"\x02" * 66,
                signer=FixtureEnvelopeSigner(harness, store._public_keys),  # noqa: SLF001
                now=999 if changed == "time" else 1001,
            )
        assert store._connection.execute(  # noqa: SLF001
            "SELECT state,local_nonce,nonce_response_id FROM cooperation_attempts"
        ).fetchone() == ("BURNED", None, None)
        assert store.pending_outbox() == ()


@pytest.mark.native_crypto
@pytest.mark.skipif(
    os.environ.get("RILLSWAP_RUN_NATIVE_CRYPTO") != "1",
    reason="set RILLSWAP_RUN_NATIVE_CRYPTO=1 with pinned native library",
)
def test_pinned_native_provider_nonce_and_signed_proposal_bytes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Native compatibility only; test-held scalar is not provider custody."""
    from rill_crypto import Context  # noqa: PLC0415 - opt-in native dependency

    harness = Harness(tmp_path, monkeypatch)
    harness.policy = replace(harness.policy, features=frozenset({COOPERATIVE_CLAIM_FEATURE}))
    harness.provision()
    with (
        Context(library_path=os.environ["RILL_CRYPTO_LIBRARY"]) as crypto,
        harness.acquire() as store,
    ):
        session, plan, _ = _featured_paid_swap(harness, store)
        store._public_keys = crypto  # noqa: SLF001 - compare native to pinned artifacts
        store._crypto = crypto  # noqa: SLF001 - BIP340 verifies native signed envelope
        cooperation_id = b"\x91" * 32
        store._burn_cooperative_claim(  # noqa: SLF001
            session,
            cooperation_id,
            plan,
            now=1000,
            deadline_at=1020,
            deadline_height=1100,
        )
        terms = live._offer_terms(  # noqa: SLF001 - fixture signed terms
            store._connection.execute(  # noqa: SLF001
                "SELECT terms_offer FROM swaps WHERE session_id=?", (session,)
            ).fetchone()[0]
        )
        attempt, nonce = crypto.musig_begin(
            secret_key=(5).to_bytes(32, "big"),  # fixture scalar, not production custody
            user_public_key=bytes.fromhex(terms.client_contract_compressed_key),
            provider_public_key=bytes.fromhex(terms.provider_contract_compressed_key),
            tap_tweak=bytes.fromhex(harness.source["taproot_contract"]["tap_tweak"]),
            message=plan.signature_hash,
            cooperation_id=cooperation_id,
        )
        with attempt:
            message_id = store._commit_cooperative_proposal_nonce(  # noqa: SLF001
                session, cooperation_id, nonce, signer=crypto, now=1001
            )
        entry = next(item for item in store.pending_outbox() if item.message_id == message_id)
        envelope = Envelope.model_validate_json(entry.canonical_bytes, strict=True)
        assert envelope.payload["public_nonce"] == nonce.hex()
        crypto.schnorr_verify(
            bytes.fromhex(envelope.sender_session_key),
            live.unsigned_envelope_hash(envelope),
            bytes.fromhex(envelope.signature or ""),
        )


@pytest.mark.native_crypto
@pytest.mark.skipif(
    os.environ.get("RILLSWAP_RUN_NATIVE_CRYPTO") != "1",
    reason="set RILLSWAP_RUN_NATIVE_CRYPTO=1 with pinned native library",
)
@pytest.mark.parametrize("failure_stage", ["none", "begin", "sign", "funding"])
def test_store_owned_native_nonce_never_exports_scalar_or_reallocates(  # noqa: PLR0915 - one native custody lifecycle per failure stage
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, failure_stage: str
) -> None:
    """Synthetic retained terms, real age-sealed provider key and native nonce."""
    from rill_crypto import Context  # noqa: PLC0415 - opt-in native dependency

    harness = Harness(tmp_path, monkeypatch)
    harness.policy = replace(harness.policy, features=frozenset({COOPERATIVE_CLAIM_FEATURE}))
    harness.provision()
    with (
        Context(library_path=os.environ["RILL_CRYPTO_LIBRARY"]) as crypto,
        harness.acquire() as store,
    ):
        session, plan, _ = _featured_paid_swap(harness, store)
        store._public_keys = crypto  # noqa: SLF001 - use real native key operations
        store._crypto = crypto  # noqa: SLF001 - native envelope and nonce checks
        monkeypatch.setattr(live, "_new_session_scalar", lambda: (5).to_bytes(32, "big"))
        with store._write() as connection:  # noqa: SLF001 - materialize matching key custody
            compressed = store._contract_key(connection, session)  # noqa: SLF001
        assert compressed == harness.source["contract_terms"]["provider_contract_compressed_key"]
        cooperation_id = b"\xa1" * 32
        store._burn_cooperative_claim(  # noqa: SLF001
            session,
            cooperation_id,
            plan,
            now=1000,
            deadline_at=1020,
            deadline_height=1100,
        )
        if failure_stage == "begin":

            def fail_begin(**_inputs: object) -> None:
                raise OSError("test-only native begin interruption")

            monkeypatch.setattr(crypto, "musig_begin", fail_begin)
        elif failure_stage == "sign":

            def fail_signing(_secret: bytes, _digest: bytes, _aux: bytes) -> bytes:
                raise OSError("test-only signer interruption")

            monkeypatch.setattr(crypto, "schnorr_sign", fail_signing)
        elif failure_stage == "funding":
            commit = store._commit_cooperative_proposal_nonce  # noqa: SLF001

            def replace_funding_before_commit(*args: object, **kwargs: object) -> str:
                store._connection.execute(  # noqa: SLF001 - synthetic between-phases race
                    "UPDATE swaps SET funding_binding=NULL WHERE session_id=?", (session,)
                )
                return commit(*args, **kwargs)  # type: ignore[arg-type]

            monkeypatch.setattr(
                store, "_commit_cooperative_proposal_nonce", replace_funding_before_commit
            )
        if failure_stage != "none":
            with pytest.raises(
                live.LiveSessionStoreError,
                match=r"native proposal refused|commit refused|unavailable",
            ):
                store._begin_and_commit_cooperative_proposal(  # noqa: SLF001
                    session, cooperation_id, now=1001
                )
            assert store._connection.execute(  # noqa: SLF001
                "SELECT state,local_nonce FROM cooperation_attempts"
            ).fetchone() == ("BURNED", None)
            assert store.pending_outbox() == ()
            assert crypto._active_attempts == 0  # noqa: SLF001 - native handle disposed
        else:
            message_id = store._begin_and_commit_cooperative_proposal(  # noqa: SLF001
                session, cooperation_id, now=1001
            )
            assert crypto._active_attempts == 1  # noqa: SLF001 - retained until store closes
            (state, nonce, recorded_id) = store._connection.execute(  # noqa: SLF001
                "SELECT state,local_nonce,nonce_response_id FROM cooperation_attempts"
            ).fetchone()
            assert state == "NONCE_READY"
            assert recorded_id == message_id
            crypto.musig_public_nonce_validate(nonce)
            envelope = Envelope.model_validate_json(store.pending_outbox()[0].canonical_bytes)
            assert envelope.payload["public_nonce"] == nonce.hex()
            if hasattr(os, "fork"):
                _assert_fork_refuses_parent_nonce(store, session)
                assert crypto._active_attempts == 1  # noqa: SLF001 - parent retains custody
        with pytest.raises(live.LiveSessionStoreError, match="already attempted"):
            store._begin_and_commit_cooperative_proposal(  # noqa: SLF001
                session, cooperation_id, now=1002
            )
        assert cooperation_id in store._allocated_cooperation_ids  # noqa: SLF001
    assert crypto._active_attempts == 0  # noqa: SLF001 - store close disposed native handle
    with harness.acquire() as store:
        assert store._connection.execute(  # noqa: SLF001
            "SELECT state FROM cooperation_attempts"
        ).fetchone() == ("ABANDONED",)


@pytest.mark.native_crypto
@pytest.mark.skipif(
    os.environ.get("RILLSWAP_RUN_NATIVE_CRYPTO") != "1",
    reason="set RILLSWAP_RUN_NATIVE_CRYPTO=1 with pinned native library",
)
@pytest.mark.parametrize("commit_reached_disk", [False, True])
def test_uncertain_nonce_proposal_commit_releases_native_custody(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, *, commit_reached_disk: bool
) -> None:
    """Either SQLite outcome abandons the handle and never reopens allocation."""
    from rill_crypto import Context  # noqa: PLC0415 - opt-in native dependency

    harness = Harness(tmp_path, monkeypatch)
    harness.policy = replace(harness.policy, features=frozenset({COOPERATIVE_CLAIM_FEATURE}))
    harness.provision()
    with (
        Context(library_path=os.environ["RILL_CRYPTO_LIBRARY"]) as crypto,
        harness.acquire() as store,
    ):
        session, plan, _ = _featured_paid_swap(harness, store)
        store._public_keys = crypto  # noqa: SLF001
        store._crypto = crypto  # noqa: SLF001
        monkeypatch.setattr(live, "_new_session_scalar", lambda: (5).to_bytes(32, "big"))
        with store._write() as connection:  # noqa: SLF001
            store._contract_key(connection, session)  # noqa: SLF001
        cooperation_id = b"\xb1" * 32
        store._burn_cooperative_claim(  # noqa: SLF001
            session,
            cooperation_id,
            plan,
            now=1000,
            deadline_at=1020,
            deadline_height=1100,
        )

        class UncertainCommit:
            def __init__(self, delegate: sqlite3.Connection) -> None:
                self.delegate = delegate
                self.fired = False

            def __getattr__(self, name: str) -> Any:  # noqa: ANN401 - SQLite proxy fixture
                return getattr(self.delegate, name)

            def execute(self, statement: str, *values: object) -> sqlite3.Cursor:
                if (
                    statement == "COMMIT"
                    and not self.fired
                    and self.delegate.execute(
                        "SELECT state FROM cooperation_attempts WHERE cooperation_id=?",
                        (cooperation_id,),
                    ).fetchone()
                    == ("NONCE_READY",)
                ):
                    self.fired = True
                    if commit_reached_disk:
                        self.delegate.execute(statement)
                    raise sqlite3.OperationalError("unknown commit outcome")
                return self.delegate.execute(statement, *values)

        proxy = UncertainCommit(store._connection)  # noqa: SLF001
        store._connection = proxy  # type: ignore[assignment]  # noqa: SLF001 - fault injection
        with pytest.raises(live.StaleOwnerError, match="commit outcome uncertain"):
            store._begin_and_commit_cooperative_proposal(  # noqa: SLF001
                session, cooperation_id, now=1001
            )
        assert proxy.fired
        assert crypto._active_attempts == 0  # noqa: SLF001 - closed despite unknown SQL result
        assert cooperation_id in store._allocated_cooperation_ids  # noqa: SLF001
        with pytest.raises(live.StaleOwnerError, match="closed"):
            store._begin_and_commit_cooperative_proposal(  # noqa: SLF001
                session, b"\xb2" * 32, now=1002
            )
    with harness.acquire() as reopened:
        assert reopened._connection.execute(  # noqa: SLF001
            "SELECT state FROM cooperation_attempts"
        ).fetchone() == ("ABANDONED",)
        assert len(reopened.pending_outbox()) == int(commit_reached_disk)


@pytest.mark.native_crypto
@pytest.mark.skipif(
    os.environ.get("RILLSWAP_RUN_NATIVE_CRYPTO") != "1",
    reason="set RILLSWAP_RUN_NATIVE_CRYPTO=1 with pinned native library",
)
@pytest.mark.parametrize(
    "result_status",
    [
        "signed",
        "signed_clean",
        "declined",
        "invalid_partial",
        "wrong_reply",
        "wrong_contract",
        "missing_feature",
        "expired",
        "invalid_nonce",
        "wrong_stage",
    ],
)
def test_authenticated_cooperative_reply_is_durable_without_granting_signature(  # noqa: PLR0915 - three outcomes share one real native transcript
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, result_status: str
) -> None:
    """Synthetic admission history, real native action signature and peer partial."""
    from rill_crypto import Context  # noqa: PLC0415 - opt-in native dependency

    harness = Harness(tmp_path, monkeypatch)
    harness.policy = replace(harness.policy, features=frozenset({COOPERATIVE_CLAIM_FEATURE}))
    harness.provision()
    with (
        Context(library_path=os.environ["RILL_CRYPTO_LIBRARY"]) as crypto,
        harness.acquire() as store,
    ):
        session, plan, _ = _featured_paid_swap(harness, store)
        store._public_keys = crypto  # noqa: SLF001
        store._crypto = crypto  # noqa: SLF001
        store._connection.execute(  # noqa: SLF001 - synthetic confirmed client sequence
            "UPDATE sessions SET next_client_seq=2 WHERE session_id=?", (session,)
        )
        monkeypatch.setattr(live, "_new_session_scalar", lambda: (5).to_bytes(32, "big"))
        with store._write() as connection:  # noqa: SLF001
            store._contract_key(connection, session)  # noqa: SLF001
        cooperation_id = b"\xc1" * 32
        store._burn_cooperative_claim(  # noqa: SLF001
            session,
            cooperation_id,
            plan,
            now=1000,
            deadline_at=1020,
            deadline_height=1100,
        )
        proposal_id = store._begin_and_commit_cooperative_proposal(  # noqa: SLF001
            session, cooperation_id, now=1001
        )
        proposal = Envelope.model_validate_json(store.pending_outbox()[0].canonical_bytes)
        assert proposal.message_id == proposal_id
        provider_nonce = bytes.fromhex(str(proposal.payload["public_nonce"]))
        terms = live._offer_terms(  # noqa: SLF001
            store._connection.execute(  # noqa: SLF001
                "SELECT terms_offer FROM swaps WHERE session_id=?", (session,)
            ).fetchone()[0]
        )
        user_attempt, user_nonce = crypto.musig_begin(
            secret_key=(4).to_bytes(32, "big"),
            user_public_key=bytes.fromhex(terms.client_contract_compressed_key),
            provider_public_key=bytes.fromhex(terms.provider_contract_compressed_key),
            tap_tweak=bytes.fromhex(harness.source["taproot_contract"]["tap_tweak"]),
            message=plan.signature_hash,
            cooperation_id=cooperation_id,
        )
        with user_attempt:
            user_partial = user_attempt.partial_sign_once(provider_nonce)
        payload: dict[str, object] = {
            "action": "cooperative_claim_propose",
            "cooperation_id": cooperation_id.hex(),
            "status": "declined" if result_status == "declined" else "signed",
        }
        if result_status != "declined":
            payload["public_nonce"] = (
                "00" * 66 if result_status == "invalid_nonce" else user_nonce.hex()
            )
            payload["partial_signature"] = (
                "ff" * 32 if result_status == "invalid_partial" else user_partial.hex()
            )
        if result_status == "wrong_stage":
            payload = {
                "action": "cooperative_claim_complete",
                "cooperation_id": cooperation_id.hex(),
                "status": "verified",
            }
        unsigned = proposal.model_copy(
            update={
                "message_id": "d1" * 32,
                "sender_session_key": harness.source["verification_context"]["handshake_init"][
                    "client_session_xonly_key"
                ],
                "sequence": 2,
                "in_reply_to": proposal_id,
                "message_type": "action_result",
                "payload": payload,
                "signature": None,
            }
        )
        if result_status == "wrong_reply":
            unsigned = unsigned.model_copy(update={"in_reply_to": "ee" * 32})
        elif result_status == "wrong_contract":
            unsigned = unsigned.model_copy(update={"contract_hash": "ee" * 32})
        elif result_status == "missing_feature":
            unsigned = unsigned.model_copy(update={"required_features": ()})
        signed = unsigned.model_copy(
            update={
                "signature": crypto.schnorr_sign(
                    (2).to_bytes(32, "big"), live.unsigned_envelope_hash(unsigned), b"\x11" * 32
                ).hex()
            }
        )
        document = canonicalize(signed.model_dump(mode="json"))
        if result_status not in ("signed", "signed_clean", "declined"):
            with pytest.raises(
                live.LiveSessionStoreError,
                match=r"result refused|status unsupported|no longer current",
            ):
                store._admit_cooperative_result(  # noqa: SLF001
                    document, now=1020 if result_status == "expired" else 1002
                )
            assert store._connection.execute(  # noqa: SLF001
                "SELECT state FROM cooperation_attempts"
            ).fetchone() == ("NONCE_READY",)
            assert store._connection.execute(  # noqa: SLF001
                "SELECT count(*) FROM inbox"
            ).fetchone() == (0,)
            assert store._connection.execute(  # noqa: SLF001
                "SELECT next_client_seq FROM sessions WHERE session_id=?", (session,)
            ).fetchone() == (2,)
            assert crypto._active_attempts == 1  # noqa: SLF001 - provider still owns attempt
        else:
            receipt = store._admit_cooperative_result(document, now=1002)  # noqa: SLF001
            expected_status = "signed" if result_status == "signed_clean" else result_status
            assert receipt.status == expected_status
            assert not receipt.replay
            state = "SIGNING" if result_status in ("signed", "signed_clean") else "ABANDONED"
            assert store._connection.execute(  # noqa: SLF001
                "SELECT state FROM cooperation_attempts"
            ).fetchone() == (state,)
            assert store._connection.execute(  # noqa: SLF001
                "SELECT next_client_seq FROM sessions WHERE session_id=?", (session,)
            ).fetchone() == (3,)
            replay = store._admit_cooperative_result(document, now=1030)  # noqa: SLF001
            assert replay.replay
            assert replay.status == expected_status
            fresh_signature = crypto.schnorr_sign(
                (2).to_bytes(32, "big"), live.unsigned_envelope_hash(unsigned), b"\x22" * 32
            ).hex()
            assert fresh_signature != signed.signature
            same_unsigned = signed.model_copy(update={"signature": fresh_signature})
            fresh_replay = store._admit_cooperative_result(  # noqa: SLF001
                canonicalize(same_unsigned.model_dump(mode="json")), now=1031
            )
            assert fresh_replay.replay
            assert crypto._active_attempts == int(state == "SIGNING")  # noqa: SLF001
            with pytest.raises(live.LiveSessionStoreError, match="request not admissible"):
                store.answer_request(
                    document, responder=lambda *_args: None, signer=crypto, now=1002
                )
            if result_status == "signed_clean":
                invalid_signature = unsigned.model_copy(
                    update={"message_id": "d3" * 32, "signature": "00" * 64}
                )
                with pytest.raises(live.LiveSessionStoreError, match="result refused"):
                    store._admit_cooperative_result(  # noqa: SLF001
                        canonicalize(invalid_signature.model_dump(mode="json")), now=1003
                    )
                assert store._connection.execute(  # noqa: SLF001
                    "SELECT blocked,next_client_seq FROM sessions WHERE session_id=?", (session,)
                ).fetchone() == (0, 3)
                assert store._connection.execute(  # noqa: SLF001
                    "SELECT state FROM cooperation_attempts"
                ).fetchone() == ("SIGNING",)
                assert crypto._active_attempts == 1  # noqa: SLF001 - invalid auth preserves handle
            if result_status == "signed":
                conflicting = unsigned.model_copy(update={"message_id": "d2" * 32})
                conflicting = conflicting.model_copy(
                    update={
                        "signature": crypto.schnorr_sign(
                            (2).to_bytes(32, "big"),
                            live.unsigned_envelope_hash(conflicting),
                            b"\x33" * 32,
                        ).hex()
                    }
                )
                with pytest.raises(live.SessionBlockedError, match="conflicting signed"):
                    store._admit_cooperative_result(  # noqa: SLF001
                        canonicalize(conflicting.model_dump(mode="json")), now=1003
                    )
                assert store._connection.execute(  # noqa: SLF001
                    "SELECT blocked FROM sessions WHERE session_id=?", (session,)
                ).fetchone() == (1,)
                assert store._connection.execute(  # noqa: SLF001
                    "SELECT state FROM cooperation_attempts"
                ).fetchone() == ("ABANDONED",)
                assert crypto._active_attempts == 0  # noqa: SLF001 - conflict destroyed handle
                # Blocking further risk cannot block the already-paid script claim.
                claim_signature = store.sign_with_contract_key(session, b"\x19" * 32, crypto)
                crypto.schnorr_verify(
                    bytes.fromhex(terms.provider_contract_compressed_key)[1:],
                    b"\x19" * 32,
                    claim_signature,
                )
        assert store.pending_outbox()[0].canonical_bytes == canonicalize(
            proposal.model_dump(mode="json")
        )
    if result_status in ("signed", "signed_clean", "declined"):
        with (
            Context(library_path=os.environ["RILL_CRYPTO_LIBRARY"]) as verifier,
            harness.acquire_at(harness.path, crypto=verifier, public_keys=verifier) as restarted,
        ):
            assert restarted._connection.execute(  # noqa: SLF001
                "SELECT state FROM cooperation_attempts"
            ).fetchone() == ("ABANDONED",)
            recovered = restarted._admit_cooperative_result(document, now=2000)  # noqa: SLF001
            assert recovered.replay
            assert recovered.status == expected_status


@pytest.mark.native_crypto
@pytest.mark.skipif(
    os.environ.get("RILLSWAP_RUN_NATIVE_CRYPTO") != "1",
    reason="set RILLSWAP_RUN_NATIVE_CRYPTO=1 with pinned native library",
)
@pytest.mark.parametrize(
    "outcome",
    [
        "complete",
        "stale",
        "spent",
        "low_fee",
        "rollback",
        "wrong_network",
        "wrong_funding",
        "low_confirmations",
        "refund_height",
        "expired",
        "invalid_peer",
        "changed_plan",
        "non_native",
        "commit_not_written",
        "commit_written",
    ],
)
def test_native_provider_partial_requires_fresh_facts_and_durable_completion(  # noqa: PLR0912, PLR0915 - one real native custody lifecycle per outcome
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, outcome: str
) -> None:
    """Trusted observations are synthetic; signing and durable custody are real."""
    from rill_crypto import Context  # noqa: PLC0415 - opt-in native dependency

    harness = Harness(tmp_path, monkeypatch)
    harness.policy = replace(harness.policy, features=frozenset({COOPERATIVE_CLAIM_FEATURE}))
    harness.provision()
    with (
        Context(library_path=os.environ["RILL_CRYPTO_LIBRARY"]) as crypto,
        harness.acquire() as store,
    ):
        session, plan, funding = _featured_paid_swap(harness, store)
        store._public_keys = crypto  # noqa: SLF001 - real native crypto in isolated fixture
        store._crypto = crypto  # noqa: SLF001
        store._connection.execute(  # noqa: SLF001 - synthetic confirmed client sequence
            "UPDATE sessions SET next_client_seq=2 WHERE session_id=?", (session,)
        )
        monkeypatch.setattr(live, "_new_session_scalar", lambda: (5).to_bytes(32, "big"))
        with store._write() as connection:  # noqa: SLF001
            store._contract_key(connection, session)  # noqa: SLF001
        cooperation_id = b"\xe1" * 32
        store._burn_cooperative_claim(  # noqa: SLF001
            session,
            cooperation_id,
            plan,
            now=1000,
            deadline_at=1020,
            deadline_height=1100,
        )
        proposal_id = store._begin_and_commit_cooperative_proposal(  # noqa: SLF001
            session, cooperation_id, now=1001
        )
        proposal = Envelope.model_validate_json(store.pending_outbox()[0].canonical_bytes)
        assert proposal.message_id == proposal_id
        provider_nonce = bytes.fromhex(str(proposal.payload["public_nonce"]))
        terms = live._offer_terms(  # noqa: SLF001
            store._connection.execute(  # noqa: SLF001
                "SELECT terms_offer FROM swaps WHERE session_id=?", (session,)
            ).fetchone()[0]
        )
        user_attempt, user_nonce = crypto.musig_begin(
            secret_key=(4).to_bytes(32, "big"),
            user_public_key=bytes.fromhex(terms.client_contract_compressed_key),
            provider_public_key=bytes.fromhex(terms.provider_contract_compressed_key),
            tap_tweak=bytes.fromhex(harness.source["taproot_contract"]["tap_tweak"]),
            message=plan.signature_hash,
            cooperation_id=cooperation_id,
        )
        with user_attempt:
            user_partial = user_attempt.partial_sign_once(provider_nonce)
        unsigned = proposal.model_copy(
            update={
                "message_id": "e2" * 32,
                "sender_session_key": harness.source["verification_context"]["handshake_init"][
                    "client_session_xonly_key"
                ],
                "sequence": 2,
                "in_reply_to": proposal_id,
                "message_type": "action_result",
                "payload": {
                    "action": "cooperative_claim_propose",
                    "cooperation_id": cooperation_id.hex(),
                    "status": "signed",
                    "public_nonce": user_nonce.hex(),
                    "partial_signature": user_partial.hex(),
                },
                "signature": None,
            }
        )
        signed = unsigned.model_copy(
            update={
                "signature": crypto.schnorr_sign(
                    (2).to_bytes(32, "big"), live.unsigned_envelope_hash(unsigned), b"\x19" * 32
                ).hex(),
            }
        )
        document = canonicalize(signed.model_dump(mode="json"))
        assert store._admit_cooperative_result(document, now=1002).status == "signed"  # noqa: SLF001
        observation = live.CooperativeClaimObservation(
            network=harness.network,
            funding_txid=funding.txid.hex(),
            funding_vout=funding.output_index,
            funding_value_sat=funding.value_sat,
            funding_script_pubkey=funding.script_pubkey,
            tip_height=1090,
            tip_hash="19" * 32,
            confirmations=terms.funding_confirmations,
            sampled_at=1003,
            mempool_unspent=True,
            fee_floor_sat=0,
        )
        if outcome == "stale":
            observation = replace(observation, sampled_at=995)
        elif outcome == "spent":
            observation = replace(observation, mempool_unspent=False)
        elif outcome == "low_fee":
            observation = replace(observation, fee_floor_sat=plan.fee_sat + 1)
        elif outcome == "wrong_network":
            observation = replace(
                observation,
                network=observation.network.model_copy(update={"genesis_hash": "ff" * 32}),
            )
        elif outcome == "wrong_funding":
            observation = replace(observation, funding_txid="ff" * 32)
        elif outcome == "low_confirmations":
            observation = replace(observation, confirmations=terms.funding_confirmations - 1)
        elif outcome == "refund_height":
            observation = replace(observation, tip_height=terms.refund_lock_height)
        elif outcome == "changed_plan":
            stored = store._connection.execute(  # noqa: SLF001 - synthetic persisted corruption
                "SELECT binding FROM cooperation_attempts"
            ).fetchone()[0]
            corrupted = parse_json_strict(stored)
            assert isinstance(corrupted, dict)
            corrupted["signature_hash"] = "ff" * 32
            store._connection.execute(  # noqa: SLF001
                "UPDATE cooperation_attempts SET binding=?", (canonicalize(corrupted),)
            )
        elif outcome == "invalid_peer":
            store._connection.execute(  # noqa: SLF001 - corrupted retained inbox
                "UPDATE inbox SET canonical_bytes=?", (b"corrupted signed result",)
            )
        elif outcome == "non_native":
            store._crypto = harness.crypto  # noqa: SLF001 - refuse non-native signer
        if outcome == "rollback":
            real_record = store._record_observation  # noqa: SLF001

            def fail_after_insertion(*args: object, **kwargs: object) -> str:
                real_record(*args, **kwargs)  # type: ignore[arg-type]
                raise OSError("test-only failure after signing and outbox insert")

            monkeypatch.setattr(store, "_record_observation", fail_after_insertion)
        if outcome in ("commit_not_written", "commit_written"):

            class UncertainCompletion:
                def __init__(self, delegate: sqlite3.Connection) -> None:
                    self.delegate = delegate
                    self.fired = False

                def __getattr__(self, name: str) -> Any:  # noqa: ANN401 - SQLite proxy fixture
                    return getattr(self.delegate, name)

                def execute(self, statement: str, *values: object) -> sqlite3.Cursor:
                    if (
                        statement == "COMMIT"
                        and not self.fired
                        and self.delegate.execute(
                            "SELECT state FROM cooperation_attempts WHERE cooperation_id=?",
                            (cooperation_id,),
                        ).fetchone()
                        == ("COMPLETE",)
                    ):
                        self.fired = True
                        if outcome == "commit_written":
                            self.delegate.execute(statement)
                        raise sqlite3.OperationalError("unknown completion commit outcome")
                    return self.delegate.execute(statement, *values)

            proxy = UncertainCompletion(store._connection)  # noqa: SLF001
            store._connection = proxy  # type: ignore[assignment]  # noqa: SLF001
            with pytest.raises(live.StaleOwnerError, match="commit outcome uncertain"):
                store._commit_cooperative_claim_partial(  # noqa: SLF001
                    session, cooperation_id, observation, now=1003
                )
            assert proxy.fired
            assert crypto._active_attempts == 0  # noqa: SLF001 - no second native signing
            with pytest.raises(live.StaleOwnerError, match="closed"):
                store._commit_cooperative_claim_partial(  # noqa: SLF001
                    session, cooperation_id, observation, now=1004
                )
        elif outcome != "complete":
            with pytest.raises(live.LiveSessionStoreError):
                store._commit_cooperative_claim_partial(  # noqa: SLF001
                    session,
                    cooperation_id,
                    observation,
                    now=1020 if outcome == "expired" else 1003,
                )
            assert store._connection.execute(  # noqa: SLF001
                "SELECT count(*) FROM outbox WHERE session_id=?", (session,)
            ).fetchone() == (1,)
            expected = "ABANDONED" if outcome == "rollback" else "SIGNING"
            assert store._connection.execute(  # noqa: SLF001
                "SELECT state FROM cooperation_attempts"
            ).fetchone() == (expected,)
            assert crypto._active_attempts == int(expected == "SIGNING")  # noqa: SLF001
        else:
            complete_id = store._commit_cooperative_claim_partial(  # noqa: SLF001
                session, cooperation_id, observation, now=1003
            )
            assert store._connection.execute(  # noqa: SLF001
                "SELECT state,partial_response_id FROM cooperation_attempts"
            ).fetchone() == ("COMPLETE", complete_id)
            assert crypto._active_attempts == 0  # noqa: SLF001 - one-shot native handle consumed
            queued = store.pending_outbox()
            assert [entry.message_id for entry in queued] == [proposal_id, complete_id]
            completion = Envelope.model_validate_json(queued[1].canonical_bytes)
            assert completion.message_type == "action_request"
            assert completion.in_reply_to is None
            assert completion.required_features == (COOPERATIVE_CLAIM_FEATURE,)
            partial = bytes.fromhex(str(completion.payload["partial_signature"]))
            signature = crypto.musig_aggregate(
                user_public_key=bytes.fromhex(terms.client_contract_compressed_key),
                provider_public_key=bytes.fromhex(terms.provider_contract_compressed_key),
                tap_tweak=bytes.fromhex(harness.source["taproot_contract"]["tap_tweak"]),
                message=plan.signature_hash,
                user_public_nonce=user_nonce,
                provider_public_nonce=provider_nonce,
                user_partial_signature=user_partial,
                provider_partial_signature=partial,
            )
            live.finalize_cooperative_claim(plan, signature, verifier=crypto)
            with pytest.raises(live.LiveSessionStoreError):
                store._commit_cooperative_claim_partial(  # noqa: SLF001
                    session, cooperation_id, observation, now=1004
                )
        if outcome not in ("non_native", "commit_not_written", "commit_written"):
            assert store._admit_cooperative_result(document, now=1050).replay  # noqa: SLF001
    with (
        Context(library_path=os.environ["RILL_CRYPTO_LIBRARY"]) as verifier,
        harness.acquire() as restarted,
    ):
        expected_after_restart = (
            "COMPLETE" if outcome in ("complete", "commit_written") else "ABANDONED"
        )
        assert restarted._connection.execute(  # noqa: SLF001
            "SELECT state FROM cooperation_attempts"
        ).fetchone() == (expected_after_restart,)
        if outcome in ("commit_not_written", "commit_written"):
            assert len(restarted.pending_outbox()) == (2 if outcome == "commit_written" else 1)
        restarted._crypto = verifier  # noqa: SLF001 - independently recover script signing
        restarted._public_keys = verifier  # noqa: SLF001
        claim_digest = b"\x19" * 32
        claim_signature = restarted.sign_with_contract_key(session, claim_digest, verifier)
        verifier.schnorr_verify(
            bytes.fromhex(terms.provider_contract_compressed_key)[1:],
            claim_digest,
            claim_signature,
        )


def _completed_cooperation(
    harness: Harness,
    store: live.LiveSessionStore,
    crypto: Any,  # noqa: ANN401 - opt-in native Context
    monkeypatch: pytest.MonkeyPatch,
    *,
    complete: bool,
) -> tuple[str, bytes, str, str | None]:
    """Run one real native forward cooperation to COMPLETE (or stop at SIGNING)."""
    session, plan, funding = _featured_paid_swap(harness, store)
    store._public_keys = crypto  # noqa: SLF001
    store._crypto = crypto  # noqa: SLF001
    store._connection.execute(  # noqa: SLF001 - synthetic confirmed client sequence
        "UPDATE sessions SET next_client_seq=2 WHERE session_id=?", (session,)
    )
    monkeypatch.setattr(live, "_new_session_scalar", lambda: (5).to_bytes(32, "big"))
    with store._write() as connection:  # noqa: SLF001
        store._contract_key(connection, session)  # noqa: SLF001
    cooperation_id = b"\xf1" * 32
    store._burn_cooperative_claim(  # noqa: SLF001
        session, cooperation_id, plan, now=1000, deadline_at=1020, deadline_height=1100
    )
    proposal_id = store._begin_and_commit_cooperative_proposal(  # noqa: SLF001
        session, cooperation_id, now=1001
    )
    proposal = Envelope.model_validate_json(store.pending_outbox()[0].canonical_bytes)
    terms = live._offer_terms(  # noqa: SLF001
        store._connection.execute(  # noqa: SLF001
            "SELECT terms_offer FROM swaps WHERE session_id=?", (session,)
        ).fetchone()[0]
    )
    user_attempt, user_nonce = crypto.musig_begin(
        secret_key=(4).to_bytes(32, "big"),
        user_public_key=bytes.fromhex(terms.client_contract_compressed_key),
        provider_public_key=bytes.fromhex(terms.provider_contract_compressed_key),
        tap_tweak=bytes.fromhex(harness.source["taproot_contract"]["tap_tweak"]),
        message=plan.signature_hash,
        cooperation_id=cooperation_id,
    )
    with user_attempt:
        user_partial = user_attempt.partial_sign_once(
            bytes.fromhex(proposal.payload["public_nonce"])
        )
    signed = _client_result(
        crypto,
        harness,
        proposal,
        message_id="e2" * 32,
        sequence=2,
        in_reply_to=proposal_id,
        payload={
            "action": "cooperative_claim_propose",
            "cooperation_id": cooperation_id.hex(),
            "status": "signed",
            "public_nonce": user_nonce.hex(),
            "partial_signature": user_partial.hex(),
        },
    )
    assert store._admit_cooperative_result(signed, now=1002).status == "signed"  # noqa: SLF001
    if not complete:
        return session, cooperation_id, proposal_id, None
    observation = live.CooperativeClaimObservation(
        network=harness.network,
        funding_txid=funding.txid.hex(),
        funding_vout=funding.output_index,
        funding_value_sat=funding.value_sat,
        funding_script_pubkey=funding.script_pubkey,
        tip_height=1090,
        tip_hash="19" * 32,
        confirmations=terms.funding_confirmations,
        sampled_at=1003,
        mempool_unspent=True,
        fee_floor_sat=0,
    )
    complete_id = store._commit_cooperative_claim_partial(  # noqa: SLF001
        session, cooperation_id, observation, now=1003
    )
    return session, cooperation_id, proposal_id, complete_id


def _client_result(  # noqa: PLR0913 - one synthetic signed client envelope
    crypto: Any,  # noqa: ANN401 - opt-in native Context
    harness: Harness,
    template: Envelope,
    *,
    message_id: str,
    sequence: int,
    in_reply_to: str | None,
    payload: dict[str, object],
    secret: int = 2,
    aux: bytes = b"\x11" * 32,
    **changed: object,
) -> bytes:
    unsigned = template.model_copy(
        update={
            "message_id": message_id,
            "sender_session_key": harness.source["verification_context"]["handshake_init"][
                "client_session_xonly_key"
            ],
            "sequence": sequence,
            "in_reply_to": in_reply_to,
            "message_type": "action_result",
            "payload": payload,
            "signature": None,
            **changed,
        }
    )
    signature = crypto.schnorr_sign(
        secret.to_bytes(32, "big"), live.unsigned_envelope_hash(unsigned), aux
    )
    return canonicalize(
        unsigned.model_copy(update={"signature": signature.hex()}).model_dump(mode="json")
    )


def _receipt_state(store: live.LiveSessionStore, session: str) -> tuple[object, ...]:
    connection = store._connection  # noqa: SLF001 - read-only state snapshot
    return (
        connection.execute("SELECT count(*) FROM inbox").fetchone(),
        connection.execute(
            "SELECT next_client_seq,blocked FROM sessions WHERE session_id=?", (session,)
        ).fetchone(),
        connection.execute(
            "SELECT state,partial_response_id,partial_signature FROM cooperation_attempts"
        ).fetchall(),
        connection.execute(
            "SELECT state,claim_txid,claim_tx FROM swaps WHERE session_id=?", (session,)
        ).fetchone(),
        connection.execute("SELECT * FROM claim_arbitration").fetchall(),
        connection.execute("SELECT message_id,delivery_state FROM outbox ORDER BY seq").fetchall(),
    )


@pytest.mark.native_crypto
@pytest.mark.skipif(
    os.environ.get("RILLSWAP_RUN_NATIVE_CRYPTO") != "1",
    reason="set RILLSWAP_RUN_NATIVE_CRYPTO=1 with pinned native library",
)
@pytest.mark.parametrize(
    "case",
    [
        "fresh",
        "late_after_restart",
        "answers_proposal",
        "unknown_request",
        "unknown_attempt",
        "wrong_contract",
        "extra_field",
        "out_of_sequence",
        "wrong_signer",
        "signing_stage",
    ],
)
def test_verified_completion_receipt_is_admitted_without_authority(  # noqa: PLR0915 - one native lifecycle per case
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, case: str
) -> None:
    """RS-002's client receipt answers the provider's completion and grants nothing.

    It consumes the client's next sequence (the client already counted it), late
    or after a restart. Anything else, including a receipt for a proposal or a
    not yet complete attempt, is refused without consuming sequence.
    """
    from rill_crypto import Context  # noqa: PLC0415 - opt-in native dependency

    harness = Harness(tmp_path, monkeypatch)
    harness.policy = replace(harness.policy, features=frozenset({COOPERATIVE_CLAIM_FEATURE}))
    harness.provision()
    with (
        Context(library_path=os.environ["RILL_CRYPTO_LIBRARY"]) as crypto,
        harness.acquire() as store,
    ):
        session, cooperation_id, proposal_id, complete_id = _completed_cooperation(
            harness, store, crypto, monkeypatch, complete=case != "signing_stage"
        )
        template = Envelope.model_validate_json(store.pending_outbox()[0].canonical_bytes)
        payload: dict[str, object] = {
            "action": "cooperative_claim_complete",
            "cooperation_id": cooperation_id.hex(),
            "status": "verified",
        }
        changed: dict[str, object] = {}
        reply_to = proposal_id if case in ("answers_proposal", "signing_stage") else complete_id
        sequence, secret = 3, 2
        if case == "unknown_request":
            reply_to = "ee" * 32
        elif case == "unknown_attempt":
            payload["cooperation_id"] = "ee" * 32
        elif case == "wrong_contract":
            changed["contract_hash"] = "ee" * 32
        elif case == "extra_field":
            payload["claim_txid"] = "ee" * 32
        elif case == "out_of_sequence":
            sequence = 4
        elif case == "wrong_signer":
            secret = 3
        receipt = _client_result(
            crypto,
            harness,
            template,
            message_id="f1" * 32,
            sequence=sequence,
            in_reply_to=reply_to,
            payload=payload,
            secret=secret,
            **changed,
        )
        before = _receipt_state(store, session)
        assert before[1] == (3, 0)
        if case not in ("fresh", "late_after_restart"):
            with pytest.raises(
                live.LiveSessionStoreError,
                match=r"result refused|status unsupported|no longer current|out of sequence",
            ):
                store._admit_cooperative_result(receipt, now=1004)  # noqa: SLF001
            assert _receipt_state(store, session) == before
            return
        if case == "fresh":
            admitted = store._admit_cooperative_result(receipt, now=1004)  # noqa: SLF001
            assert (admitted.status, admitted.replay) == ("verified", False)
            after = _receipt_state(store, session)
            assert after[0] == (before[0][0] + 1,)  # type: ignore[index]
            assert after[1] == (4, 0)
            # No signing, settlement, broadcast, arbitration or reply follows a receipt.
            assert after[2:] == before[2:]
            assert after[2] == [("COMPLETE", complete_id, after[2][0][2])]  # type: ignore[index]
            assert crypto._active_attempts == 0  # noqa: SLF001
            # The same receipt again, even re-signed, is a replay that changes nothing.
            replay = store._admit_cooperative_result(receipt, now=1100)  # noqa: SLF001
            assert (replay.status, replay.replay) == ("verified", True)
            resigned = _client_result(
                crypto,
                harness,
                template,
                message_id="f1" * 32,
                sequence=3,
                in_reply_to=complete_id,
                payload=payload,
                aux=b"\x22" * 32,
            )
            assert resigned != receipt
            assert store._admit_cooperative_result(resigned, now=1101).replay  # noqa: SLF001
            assert _receipt_state(store, session) == after
            # A second distinct receipt is harmless and keeps the sequence in step.
            second = _client_result(
                crypto,
                harness,
                template,
                message_id="f2" * 32,
                sequence=4,
                in_reply_to=complete_id,
                payload=payload,
            )
            again = store._admit_cooperative_result(second, now=1102)  # noqa: SLF001
            assert (again.status, again.replay) == ("verified", False)
            assert _receipt_state(store, session)[1] == (5, 0)
            assert _receipt_state(store, session)[2:] == before[2:]
    with (
        Context(library_path=os.environ["RILL_CRYPTO_LIBRARY"]) as verifier,
        harness.acquire_at(harness.path, crypto=verifier, public_keys=verifier) as restarted,
    ):
        # Past the attempt's deadline, under a new owner generation, without a native handle.
        result = restarted._admit_cooperative_result(receipt, now=5000)  # noqa: SLF001
        assert result.status == "verified"
        assert result.replay is (case == "fresh")
        assert restarted._connection.execute(  # noqa: SLF001
            "SELECT next_client_seq FROM sessions WHERE session_id=?", (session,)
        ).fetchone() == ((5,) if case == "fresh" else (4,))
        assert restarted._connection.execute(  # noqa: SLF001
            "SELECT state,partial_response_id FROM cooperation_attempts"
        ).fetchone() == ("COMPLETE", complete_id)
