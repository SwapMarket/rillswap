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
