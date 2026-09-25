"""RS-006 NIP-59 sender is the exact inverse of the receive decoder."""

from __future__ import annotations

import json
import os
import time
from pathlib import Path
from typing import Any

import pytest
from rill_core.wire.canonical import canonicalize
from rill_core.wire.messages import Envelope
from rill_core.wire.types import NetworkIdentity

from rill_provider import _nip59_receive as receive
from rill_provider import _nip59_send as send

FIXTURE = Path(__file__).parent / "fixtures" / "initial-btc-to-ln-v1.json"
SENDER = (3).to_bytes(32, "big")  # Fixture-only public scalar of the fixture session key.
RECIPIENT = (7).to_bytes(32, "big")  # Synthetic test mailbox, never deployed.


def _accept() -> tuple[bytes, NetworkIdentity]:
    source = json.loads(FIXTURE.read_text())
    context = source["verification_context"]
    accepted = context["handshake_accept"]
    envelope: dict[str, Any] = {
        "protocol": "rillswap",
        "wire_version": "1",
        "profile_id": source["profile_id"],
        "network_identity": source["network_identity"],
        "session_id": context["handshake_init"]["session_id"],
        "contract_hash": None,
        "required_features": [],
        "extensions": {},
        "message_type": "handshake_accept",
        "message_id": "14" * 32,
        "sender_session_key": accepted["provider_session_xonly_key"],
        "sequence": 0,
        "in_reply_to": "12" * 32,
        "payload": {
            "accept": accepted,
            "provider_identity_signature": context["provider_identity_signature"],
        },
        "signature": None,
    }
    return canonicalize(envelope), NetworkIdentity.model_validate(source["network_identity"])


def test_non_canonical_or_unbounded_envelope_is_refused_before_crypto() -> None:
    document, _ = _accept()
    for bad in (document + b" ", b"", json.dumps(json.loads(document), indent=1).encode()):
        with pytest.raises((send.Nip59WrapRefusedError, ValueError)):
            send._wrap_envelope(  # noqa: SLF001
                bad,
                sender_session_secret=SENDER,
                recipient_xonly_key="aa" * 32,
                crypto=object(),  # type: ignore[arg-type]
            )


@pytest.mark.native_crypto
@pytest.mark.skipif(
    not os.environ.get("RILL_CRYPTO_LIBRARY"), reason="requires pinned native crypto"
)
def test_wrap_round_trips_through_receive_with_fresh_randomness() -> None:
    from rill_crypto import Context  # noqa: PLC0415 - opt-in native test

    document, network = _accept()
    with Context(library_path=os.environ["RILL_CRYPTO_LIBRARY"]) as crypto:
        recipient = crypto.public_key(RECIPIENT)[1:].hex()
        wraps = [
            send._wrap_envelope(  # noqa: SLF001
                document,
                sender_session_secret=SENDER,
                recipient_xonly_key=recipient,
                crypto=crypto,
            )
            for _ in range(2)
        ]
        candidates = [
            receive._decode_gift_wrap_candidate(  # noqa: SLF001
                wrap,
                recipient_mailbox_secret=RECIPIENT,
                expected_recipient_xonly_key=recipient,
                expected_network=network,
                expected_profile_id="btc-to-ln/v1",
                crypto=crypto,
            )
            for wrap in wraps
        ]
        expected = Envelope.model_validate_json(document)
        assert [c.envelope for c in candidates] == [expected, expected]
        assert candidates[0].seal_author_xonly_key == expected.sender_session_key
        assert candidates[0].outer_event_id != candidates[1].outer_event_id
        outers = [json.loads(wrap) for wrap in wraps]
        assert outers[0]["pubkey"] != outers[1]["pubkey"]
        now = int(time.time())
        for outer in outers:
            assert outer["kind"] == receive.OUTER_KIND
            assert outer["tags"] == [["p", recipient]]
            assert now - send.TIMESTAMP_JITTER_SECONDS <= outer["created_at"] <= now
            assert outer["pubkey"] not in (recipient, expected.sender_session_key)
        with pytest.raises(send.Nip59WrapRefusedError):
            send._wrap_envelope(  # noqa: SLF001 - sender secret must own the envelope
                document,
                sender_session_secret=RECIPIENT,
                recipient_xonly_key=crypto.public_key(SENDER)[1:].hex(),
                crypto=crypto,
            )
