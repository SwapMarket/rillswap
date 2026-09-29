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
from rill_core.wire.hashes import COOPERATIVE_CLAIM_FEATURE
from rill_core.wire.messages import Envelope
from test_cooperation_burn import FixtureEnvelopeSigner, _featured_paid_swap
from test_live_session_store import Harness

from rill_provider.live_session_store import LiveSessionStoreError

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
            "deadline_height": 1100,
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
        for invalid in ({"deadline_at": 1031}, {"now": 1020}, {"deadline_height": 0}):
            with pytest.raises(LiveSessionStoreError, match="deadline unavailable"):
                store.issue_cooperative_readiness(session, **(kwargs | invalid))
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
        assert (payload.deadline_at, payload.deadline_height) == (1020, 1100)
        assert not store.pending_sendable(probe.request_id, now=1002, tip_height=1090)
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
