"""Burn-only store boundary; these fixtures do not simulate live peer admission."""

from __future__ import annotations

import copy
import hashlib
import json
import os
from dataclasses import replace
from typing import TYPE_CHECKING

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
