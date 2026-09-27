"""Burn-only store boundary; these fixtures do not simulate live peer admission."""

from __future__ import annotations

import copy
import hashlib
import json
from dataclasses import replace
from typing import TYPE_CHECKING

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
from rill_core.wire.messages import ContractTerms, HandshakeAccept, HandshakeInit
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
    connection.execute(
        "UPDATE sessions SET init_bytes=?,accept_bytes=?,transcript_digest=? WHERE session_id=?",
        (canonicalize(init_envelope), canonicalize(accept_envelope), transcript, session),
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
