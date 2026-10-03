"""Historical repayment routing authenticates features, never signing eligibility."""

from __future__ import annotations

import asyncio
import copy
import inspect
import json
import os
import textwrap
from typing import TYPE_CHECKING

import pytest
from rill_core.wire.canonical import canonicalize
from rill_core.wire.hashes import (
    EPOCH_SESSION_FEATURE,
    client_acceptance_hash,
    handshake_accept_hash,
    handshake_hash,
    handshake_init_hash,
    provider_terms_hash,
    unsigned_envelope_hash,
)
from rill_core.wire.messages import (
    ClientAcceptance,
    Envelope,
    HandshakeAccept,
    HandshakeInit,
    ProviderTerms,
)
from test_live_session_store import Harness
from test_reverse_proposal_reservation import reserved as reserved  # noqa: PLC0414 - pytest fixture
from test_reverse_settlement_intent import _funded
from test_reverse_swap_store import PREIMAGE

from rill_provider import live_session_store as live

if TYPE_CHECKING:
    from pathlib import Path

    from test_reverse_proposal_reservation import ReservationCase

# ruff: noqa: SLF001 - authoritative-store archive/corruption test seams


@pytest.mark.parametrize("epoch", [False, True])
def test_exact_known_legacy_features_preserve_opaque_acceptance_repayment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, *, epoch: bool
) -> None:
    harness = Harness(tmp_path, monkeypatch)
    harness.provision()
    with harness.acquire() as store:
        session = _funded(store, harness)
        store.record_reverse_settlement_preimage(
            session, from_state="FUNDED", preimage=PREIMAGE, now=2001
        )
        if epoch:
            init, accept = store._connection.execute(
                "SELECT init_bytes,accept_bytes FROM sessions"
            ).fetchone()
            initiation, acceptance = json.loads(init), json.loads(accept)
            initiation["payload"]["required_features"] = [EPOCH_SESSION_FEATURE]
            acceptance["payload"]["accept"]["required_features"] = [EPOCH_SESSION_FEATURE]
            store._connection.execute(
                "UPDATE sessions SET init_bytes=?,accept_bytes=?",
                (canonicalize(initiation), canonicalize(acceptance)),
            )
        before = store._connection.execute("SELECT * FROM swaps").fetchall()
        assert store._connection.execute("SELECT terms_accept FROM swaps").fetchone() == (
            b"accepted",
        )
        assert store._reverse_repayment_binding(session) is None
        assert store._connection.execute("SELECT * FROM swaps").fetchall() == before


@pytest.mark.parametrize(
    "fault",
    [
        "inner init missing",
        "inner accept missing",
        "terms missing",
        "outer init missing",
        "outer accept missing",
        "outer offer missing",
        "mixed epoch",
        "unknown inner",
        "cooperative outer",
        "unknown outer",
        "accept archive missing",
    ],
)
def test_missing_mixed_or_unknown_commitments_never_infer_legacy(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fault: str
) -> None:
    harness = Harness(tmp_path, monkeypatch)
    harness.provision()
    with harness.acquire() as store:
        session = _funded(store, harness)
        store.record_reverse_settlement_preimage(
            session, from_state="FUNDED", preimage=PREIMAGE, now=2001
        )
        init, accept = store._connection.execute(
            "SELECT init_bytes,accept_bytes FROM sessions"
        ).fetchone()
        offered = store._connection.execute("SELECT terms_offer FROM swaps").fetchone()[0]
        initiation, acceptance, offer = json.loads(init), json.loads(accept), json.loads(offered)
        if fault == "inner init missing":
            del initiation["payload"]["required_features"]
        elif fault == "inner accept missing":
            del acceptance["payload"]["accept"]["required_features"]
        elif fault == "terms missing":
            del offer["payload"]["terms"]["contract_terms"]["required_features"]
        elif fault == "outer init missing":
            del initiation["required_features"]
        elif fault == "outer accept missing":
            del acceptance["required_features"]
        elif fault == "outer offer missing":
            del offer["required_features"]
        elif fault == "mixed epoch":
            initiation["payload"]["required_features"] = [EPOCH_SESSION_FEATURE]
        elif fault == "unknown inner":
            initiation["payload"]["required_features"] = ["unknown/v1"]
            acceptance["payload"]["accept"]["required_features"] = ["unknown/v1"]
        elif fault == "cooperative outer":
            offer["required_features"] = ["cooperative-claim/v1"]
        elif fault == "unknown outer":
            offer["required_features"] = ["unknown/v1"]
        store._connection.execute(
            "UPDATE sessions SET init_bytes=?,accept_bytes=?",
            (canonicalize(initiation), canonicalize(acceptance)),
        )
        store._connection.execute("UPDATE swaps SET terms_offer=?", (canonicalize(offer),))
        if fault == "accept archive missing":
            store._connection.execute("UPDATE sessions SET accept_bytes=NULL")
        before = store._connection.execute("SELECT * FROM swaps").fetchall()
        with pytest.raises(live.LiveSessionStoreError, match="repayment context refused"):
            store._reverse_repayment_binding(session)
        assert store._connection.execute("SELECT * FROM swaps").fetchall() == before


@pytest.mark.native_crypto
@pytest.mark.skipif(
    os.environ.get("RILLSWAP_RUN_NATIVE_CRYPTO") != "1",
    reason="native archived signature validation",
)
def test_featured_original_binding_survives_restart_without_any_proposal_or_window(
    reserved: ReservationCase,
) -> None:
    async def exercise() -> None:
        store = reserved.store
        # No reservation, proposal window, debt, or native participant is created.
        assert not store._reverse_proposals
        binding = store._reverse_repayment_binding(reserved.origin.session_id)
        assert binding is not None
        assert not store._cooperation_handles
        store.close()
        with reserved.origin.acquire_at(
            reserved.origin.path,
            crypto=reserved.origin.crypto,
            public_keys=reserved.origin.crypto.crypto,
        ) as fresh:
            assert fresh._reverse_repayment_binding(reserved.origin.session_id) == binding
            assert not fresh._reverse_negotiations
            assert not fresh._reverse_proposals
            assert not fresh._cooperation_handles

    asyncio.run(exercise())


@pytest.mark.native_crypto
@pytest.mark.skipif(
    os.environ.get("RILLSWAP_RUN_NATIVE_CRYPTO") != "1",
    reason="native archived signature validation",
)
@pytest.mark.parametrize(
    "signature", ["terms_offer", "terms_accept", "provider terms", "client acceptance"]
)
def test_featured_corrupt_archived_signature_refuses_without_downgrade(
    reserved: ReservationCase, signature: str
) -> None:
    store = reserved.store
    column = "terms_offer" if signature in ("terms_offer", "provider terms") else "terms_accept"
    document = json.loads(store._connection.execute(f"SELECT {column} FROM swaps").fetchone()[0])  # noqa: S608
    if signature in ("terms_offer", "terms_accept"):
        document["signature"] = "01" * 64
    else:
        field = (
            "provider_terms_signature"
            if signature == "provider terms"
            else "client_acceptance_signature"
        )
        document["payload"][field] = "01" * 64
        envelope = Envelope.model_validate_json(canonicalize(document), strict=True)
        document["signature"] = reserved.origin.crypto.crypto.schnorr_sign(
            (9 if column == "terms_offer" else 8).to_bytes(32, "big"),
            unsigned_envelope_hash(envelope),
            b"\x55" * 32,
        ).hex()
    store._connection.execute(f"UPDATE swaps SET {column}=?", (canonicalize(document),))  # noqa: S608
    before = store._connection.execute("SELECT * FROM swaps").fetchall()
    with pytest.raises(live.LiveSessionStoreError, match="repayment context refused"):
        store._reverse_repayment_binding(reserved.origin.session_id)
    assert store._connection.execute("SELECT * FROM swaps").fetchall() == before


@pytest.mark.native_crypto
@pytest.mark.skipif(
    os.environ.get("RILLSWAP_RUN_NATIVE_CRYPTO") != "1", reason="native archive anchors"
)
@pytest.mark.parametrize("anchor", ["session_id", "profile_id", "network_identity"])
def test_signed_internally_consistent_transcript_cannot_cross_external_agreement_anchors(
    reserved: ReservationCase, monkeypatch: pytest.MonkeyPatch, anchor: str
) -> None:
    store = reserved.store
    original_binding = store._reverse_repayment_binding(reserved.origin.session_id)
    init, accept = store._connection.execute(
        "SELECT init_bytes,accept_bytes FROM sessions"
    ).fetchone()
    offer, accepted = store._connection.execute(
        "SELECT terms_offer,terms_accept FROM swaps"
    ).fetchone()
    init_doc, accept_doc = json.loads(init), json.loads(accept)
    offer_doc, accepted_doc = json.loads(offer), json.loads(accepted)
    changed = "ab" * 32 if anchor == "session_id" else "btc-to-ln/v1"
    if anchor == "network_identity":
        changed = {**init_doc["payload"][anchor], "deployment_namespace": "wrong-retained-v1"}
    init_doc["payload"][anchor] = changed
    accept_doc["payload"]["accept"][anchor] = copy.deepcopy(changed)
    initiation = HandshakeInit.model_validate_json(canonicalize(init_doc["payload"]), strict=True)
    accept_doc["payload"]["accept"]["handshake_init_hash"] = handshake_init_hash(initiation).hex()
    acceptance = HandshakeAccept.model_validate_json(
        canonicalize(accept_doc["payload"]["accept"]), strict=True
    )
    acceptance.validate_against(initiation, supported_features=store._policy.features)
    crypto = reserved.origin.crypto.crypto

    def sign(scalar: int, digest: bytes) -> str:
        return crypto.schnorr_sign(scalar.to_bytes(32, "big"), digest, b"\x55" * 32).hex()

    accept_doc["payload"]["provider_identity_signature"] = sign(
        1, handshake_accept_hash(acceptance)
    )
    transcript = handshake_hash(initiation, acceptance).hex()
    offer_doc["payload"]["terms"]["handshake_hash"] = transcript
    offered = ProviderTerms.model_validate_json(
        canonicalize(offer_doc["payload"]["terms"]), strict=True
    )
    offer_doc["payload"]["provider_terms_signature"] = sign(1, provider_terms_hash(offered))
    accepted_doc["payload"]["acceptance"]["handshake_hash"] = transcript
    agreement = ClientAcceptance.model_validate_json(
        canonicalize(accepted_doc["payload"]["acceptance"]), strict=True
    )
    accepted_doc["payload"]["client_acceptance_signature"] = sign(
        8, client_acceptance_hash(agreement)
    )
    for document, scalar in ((offer_doc, 9), (accepted_doc, 8)):
        envelope = Envelope.model_validate_json(canonicalize(document), strict=True)
        document["signature"] = sign(scalar, unsigned_envelope_hash(envelope))
    store._connection.execute(
        "UPDATE sessions SET init_bytes=?,accept_bytes=?,transcript_digest=?",
        (canonicalize(init_doc), canonicalize(accept_doc), transcript),
    )
    store._connection.execute(
        "UPDATE swaps SET terms_offer=?,terms_accept=?",
        (canonicalize(offer_doc), canonicalize(accepted_doc)),
    )
    before = store._connection.execute("SELECT * FROM swaps").fetchall()
    with pytest.raises(live.LiveSessionStoreError, match="repayment context refused"):
        store._reverse_repayment_binding(reserved.origin.session_id)
    # Test-only negative control omits exactly the three new relationships.
    # It still executes every other check and genuine signature verification.
    source = textwrap.dedent(
        inspect.getsource(live.LiveSessionStore._authenticated_reverse_agreement)
    )
    for check in (
        "or initiation.session_id != session_id",
        "or initiation.profile_id != terms.profile_id",
        "or initiation.network_identity != terms.network_identity",
    ):
        assert source.count(check) == 1
        source = "\n".join(line for line in source.splitlines() if check not in line)
    namespace = dict(live.__dict__)
    exec(compile(source, "<agreement-anchor-control>", "exec"), namespace)  # noqa: S102 - local test-only source control
    with monkeypatch.context() as patch:
        patch.setattr(
            live.LiveSessionStore,
            "_authenticated_reverse_agreement",
            namespace["_authenticated_reverse_agreement"],
        )
        assert store._reverse_repayment_binding(reserved.origin.session_id) == original_binding
    assert store._connection.execute("SELECT * FROM swaps").fetchall() == before
    assert not store._reverse_proposals
