"""A signed readiness probe is not persisted cooperation authority."""

from __future__ import annotations

from dataclasses import replace
from typing import TYPE_CHECKING

import pytest
from rill_core.wire.canonical import canonicalize
from rill_core.wire.cooperative_messages import (
    CooperativeClaimReadyRequest,
    parse_cooperative_payload,
)
from rill_core.wire.hashes import COOPERATIVE_CLAIM_FEATURE, unsigned_envelope_hash
from rill_core.wire.messages import Envelope
from test_cooperation_burn import FixtureEnvelopeSigner, _featured_paid_swap
from test_live_session_store import Harness

from rill_provider.live_session_store import LiveSessionStoreError, SessionBlockedError

if TYPE_CHECKING:
    from pathlib import Path


def test_probe_requires_admission_and_is_abandoned_after_owner_restart(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    harness = Harness(tmp_path, monkeypatch)
    harness.policy = replace(harness.policy, features=frozenset({COOPERATIVE_CLAIM_FEATURE}))
    harness.provision()
    with harness.acquire() as store:
        session, _, _ = _featured_paid_swap(harness, store)
        signer = FixtureEnvelopeSigner(harness, store._public_keys)  # noqa: SLF001
        kwargs = {
            "signer": signer,
            "started_at": 1000,
            "now": 1001,
            "deadline_at": 1020,
            "deadline_height": 1094,
        }
        with pytest.raises(LiveSessionStoreError, match="not admitted"):
            store.issue_cooperative_readiness(session, **kwargs)
        (digest,) = store._connection.execute(  # noqa: SLF001
            "SELECT contract_hash FROM swaps WHERE session_id=?", (session,)
        ).fetchone()
        with store._connection as connection:  # noqa: SLF001 - synthetic admitted transcript
            connection.execute(
                "INSERT INTO claim_arbitration (session_id,contract_hash,version,state) "
                "VALUES (?, ?, 1, 'ADMITTED')",
                (session, digest),
            )
        assert store.cooperative_height_cutoff(session, digest) == 1094
        assert store.cooperative_height_cutoff(session, "ff" * 32) is None
        for invalid in ({"deadline_at": 1031}, {"now": 1020}, {"deadline_height": 0}):
            with pytest.raises(LiveSessionStoreError, match="deadline unavailable"):
                store.issue_cooperative_readiness(session, **(kwargs | invalid))
        with pytest.raises(LiveSessionStoreError, match="authority unavailable"):
            store.issue_cooperative_readiness(session, **(kwargs | {"deadline_height": 1095}))
        assert store.pending_outbox() == ()
        probe = store.issue_cooperative_readiness(session, **kwargs)
        assert (probe.session_id, probe.contract_hash, probe.owner_generation) == (
            session,
            digest,
            store.generation,
        )
        assert probe.challenge != "00" * 32
        pending = store.pending_outbox()
        assert len(pending) == 1
        envelope = Envelope.model_validate_json(pending[0].canonical_bytes, strict=True)
        assert envelope.message_id == probe.request_id
        assert envelope.contract_hash == digest
        assert envelope.required_features == (COOPERATIVE_CLAIM_FEATURE,)
        payload = parse_cooperative_payload("action_request", canonicalize(envelope.payload))
        assert isinstance(payload, CooperativeClaimReadyRequest)
        assert payload.challenge == probe.challenge
        assert (payload.deadline_at, payload.deadline_height) == (1020, 1094)
        assert not store.pending_sendable(probe.request_id, now=1002, tip_height=1090)
        assert store.pending_sendable(probe.request_id, now=1002, tip_height=1090, readiness=probe)
        assert not store.pending_sendable(
            probe.request_id, now=1020, tip_height=1090, readiness=probe
        )
        assert not store.pending_sendable(
            probe.request_id, now=1002, tip_height=1094, readiness=probe
        )
        assert store._connection.execute(  # noqa: SLF001
            "SELECT state FROM claim_arbitration WHERE session_id=?", (session,)
        ).fetchone() == ("ADMITTED",)
        assert store._connection.execute(  # noqa: SLF001
            "SELECT count(*) FROM cooperation_attempts WHERE session_id=?", (session,)
        ).fetchone() == (0,)
        with store._connection as connection:  # noqa: SLF001 - previous-release pending backlog
            connection.executemany(
                "INSERT INTO outbox VALUES (?,?,?,NULL,?,?,'PENDING')",
                [
                    ("a1" * 32, session, 100, b"malformed ordinary entry", 100),
                    (
                        "a2" * 32,
                        session,
                        101,
                        b'{"message_type":"observation","payload":{"action":"ordinary"}}',
                        101,
                    ),
                ],
            )
    with harness.acquire() as restarted:
        with pytest.raises(LiveSessionStoreError, match="owner unavailable"):
            restarted.retire_cooperative_readiness(probe)
        assert {entry.message_id for entry in restarted.pending_outbox()} == {
            "a1" * 32,
            "a2" * 32,
        }
        assert restarted._connection.execute(  # noqa: SLF001
            "SELECT delivery_state FROM outbox WHERE message_id=?", (probe.request_id,)
        ).fetchone() == ("RECONCILED",)
        assert restarted._connection.execute(  # noqa: SLF001
            "SELECT state FROM claim_arbitration WHERE session_id=?", (session,)
        ).fetchone() == ("ADMITTED",)
        assert restarted.immediate_claim_allowed(session)


def test_signed_readiness_echo_is_authenticated_and_never_prepares_a_claim(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    harness = Harness(tmp_path, monkeypatch)
    harness.policy = replace(harness.policy, features=frozenset({COOPERATIVE_CLAIM_FEATURE}))
    harness.provision()
    with harness.acquire() as store:
        session, _, _ = _featured_paid_swap(harness, store)
        with store._connection as connection:  # noqa: SLF001 - synthetic authenticated admission
            (digest,) = connection.execute(
                "SELECT contract_hash FROM swaps WHERE session_id=?", (session,)
            ).fetchone()
            connection.execute(
                "INSERT INTO claim_arbitration (session_id,contract_hash,version,state) "
                "VALUES (?, ?, 1, 'ADMITTED')",
                (session, digest),
            )
            connection.execute(
                "UPDATE sessions SET next_client_seq=2 WHERE session_id=?", (session,)
            )
        signer = FixtureEnvelopeSigner(harness, store._public_keys)  # noqa: SLF001
        probe = store.issue_cooperative_readiness(
            session,
            signer=signer,
            started_at=1000,
            now=1000,
            deadline_at=1020,
            deadline_height=1094,
        )
        request = Envelope.model_validate_json(
            store.pending_outbox()[0].canonical_bytes, strict=True
        )
        client_key = harness.source["verification_context"]["handshake_init"][
            "client_session_xonly_key"
        ]

        def signed_result(*, message_id: str = "d1" * 32, **updates: object) -> bytes:
            bare = request.model_copy(
                update={
                    "message_type": "action_result",
                    "message_id": message_id,
                    "sender_session_key": client_key,
                    "sequence": 2,
                    "in_reply_to": probe.request_id,
                    "payload": {
                        "action": "cooperative_claim_ready",
                        "challenge": probe.challenge,
                        "status": "ready",
                    },
                    "signature": None,
                    **updates,
                }
            )
            signature = b"\x81" * 64
            harness.crypto.permitted.add(
                (bytes.fromhex(client_key), unsigned_envelope_hash(bare), signature)
            )
            return canonicalize(
                bare.model_copy(update={"signature": signature.hex()}).model_dump(mode="json")
            )

        for document, kwargs in (
            (signed_result(message_id="d2" * 32, in_reply_to="ff" * 32), {}),
            (
                signed_result(
                    message_id="d3" * 32,
                    payload={
                        "action": "cooperative_claim_ready",
                        "challenge": "ee" * 32,
                        "status": "ready",
                    },
                ),
                {},
            ),
            (signed_result(message_id="d4" * 32), {"now": 1020}),
            (signed_result(message_id="d5" * 32), {"tip_height": 1100}),
            (signed_result(message_id="d7" * 32, sender_session_key="ff" * 32), {}),
            (signed_result(message_id="d8" * 32, required_features=()), {}),
            (
                canonicalize(
                    Envelope.model_validate_json(signed_result(message_id="d9" * 32))
                    .model_copy(update={"signature": "00" * 64})
                    .model_dump(mode="json")
                ),
                {},
            ),
        ):
            with pytest.raises(LiveSessionStoreError):
                store.admit_cooperative_readiness(
                    document,
                    probe,
                    now=kwargs.get("now", 1002),
                    tip_height=kwargs.get("tip_height", 1090),
                )
        assert store._connection.execute(  # noqa: SLF001
            "SELECT count(*) FROM inbox WHERE session_id=?", (session,)
        ).fetchone() == (0,)
        reply = signed_result()
        with pytest.raises(LiveSessionStoreError, match="token unavailable"):
            store._admit_cooperative_result(reply, now=1002)  # noqa: SLF001 - old API cannot admit readiness
        assert store._connection.execute(  # noqa: SLF001
            "SELECT count(*) FROM inbox WHERE session_id=?", (session,)
        ).fetchone() == (0,)
        admitted = store.admit_cooperative_readiness(reply, probe, now=1002, tip_height=1090)
        assert admitted.status == "ready"
        assert not admitted.replay
        assert store.pending_outbox() == ()
        replay = store.admit_cooperative_readiness(reply, probe, now=1003, tip_height=1090)
        assert replay.replay
        with pytest.raises(LiveSessionStoreError, match="request missing"):
            store.admit_cooperative_readiness(
                signed_result(message_id="da" * 32, sequence=3),
                probe,
                now=1003,
                tip_height=1090,
            )
        assert store._connection.execute(  # noqa: SLF001
            "SELECT state FROM claim_arbitration WHERE session_id=?", (session,)
        ).fetchone() == ("ADMITTED",)
        assert store._connection.execute(  # noqa: SLF001
            "SELECT count(*) FROM cooperation_attempts WHERE session_id=?", (session,)
        ).fetchone() == (0,)
        with pytest.raises(SessionBlockedError, match="conflicting signed"):
            store.admit_cooperative_readiness(
                signed_result(message_id="d6" * 32), probe, now=1003, tip_height=1090
            )
        assert store._connection.execute(  # noqa: SLF001
            "SELECT blocked FROM sessions WHERE session_id=?", (session,)
        ).fetchone() == (1,)
    with (
        harness.acquire() as restarted,
        pytest.raises(LiveSessionStoreError, match="token unavailable"),
    ):
        restarted.admit_cooperative_readiness(reply, probe, now=1004, tip_height=1090)
