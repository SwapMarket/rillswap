"""A signed historical handshake is static evidence, not a live session."""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

import pytest

from rill_core.errors import ValidationError
from rill_core.wire import verify_static_handshake_accept, verify_static_handshake_transcript
from rill_core.wire.hashes import handshake_accept_hash, unsigned_envelope_hash
from rill_core.wire.messages import Envelope, HandshakeAccept
from rill_core.wire.types import NetworkIdentity

FIXTURE = Path(__file__).parents[1] / "fixtures" / "recovery-v1" / "initial-btc-to-ln-v1.json"
CLIENT_CONFIRM_SIGNATURE = (
    "d8a7339977e4673e215e61339386e8208b0c6d1ecbe01621e985fe3d6c1399"
    "384f7b321a32c9ddf5363cb484e78561b3fb6aa65e686a076fcf95c7263a13c3bb"
)
TRANSCRIPT_DIGEST = bytes.fromhex(
    "5fbb869c7f2df70b939d7c370478c06f5819f287351c1d19b4921fe95aa156c8"
)


def _data() -> tuple[dict[str, Any], list[dict[str, Any]]]:
    source = json.loads(FIXTURE.read_text())
    context = source["verification_context"]
    init, accept = context["handshake_init"], context["handshake_accept"]
    shared = {
        "protocol": "rillswap",
        "wire_version": "1",
        "profile_id": init["profile_id"],
        "network_identity": init["network_identity"],
        "session_id": init["session_id"],
        "contract_hash": None,
        "required_features": [],
        "extensions": {},
    }
    envelopes = [
        {
            **shared,
            "message_type": "handshake_init",
            "message_id": "12" * 32,
            "sender_session_key": init["client_session_xonly_key"],
            "sequence": 0,
            "in_reply_to": None,
            "payload": init,
            "signature": None,
        },
        {
            **shared,
            "message_type": "handshake_accept",
            "message_id": "14" * 32,
            "sender_session_key": accept["provider_session_xonly_key"],
            "sequence": 0,
            "in_reply_to": "12" * 32,
            "payload": {
                "accept": accept,
                "provider_identity_signature": context["provider_identity_signature"],
            },
            "signature": None,
        },
        {
            **shared,
            "message_type": "handshake_confirm",
            "message_id": "13" * 32,
            "sender_session_key": init["client_session_xonly_key"],
            "sequence": 1,
            "in_reply_to": "14" * 32,
            "payload": {
                "handshake_hash": context["handshake_hash"],
                "session_id": init["session_id"],
                "client_session_xonly_key": init["client_session_xonly_key"],
                "provider_session_xonly_key": accept["provider_session_xonly_key"],
            },
            "signature": CLIENT_CONFIRM_SIGNATURE,
        },
    ]
    return source, envelopes


class PinnedCrypto:
    def __init__(self, source: dict[str, Any], envelopes: list[dict[str, Any]]) -> None:
        context = source["verification_context"]
        selected = HandshakeAccept.model_validate_json(json.dumps(context["handshake_accept"]))
        confirm = Envelope.model_validate_json(json.dumps(envelopes[2]))
        self.permitted = {
            (
                bytes.fromhex(selected.provider_identity_xonly_key),
                handshake_accept_hash(selected),
                bytes.fromhex(context["provider_identity_signature"]),
            ),
            (
                bytes.fromhex(context["client_session_xonly_key"]),
                unsigned_envelope_hash(confirm),
                bytes.fromhex(confirm.signature or ""),
            ),
        }
        self.calls: list[tuple[bytes, bytes, bytes]] = []

    def schnorr_verify(self, key: bytes, digest: bytes, signature: bytes) -> None:
        self.calls.append((key, digest, signature))
        if (key, digest, signature) not in self.permitted:
            raise ValueError("upstream secret must not escape")


def _verify(
    source: dict[str, Any], envelopes: list[dict[str, Any]], crypto: PinnedCrypto, **changed: object
) -> bytes:
    init = source["verification_context"]["handshake_init"]
    expected: dict[str, Any] = {
        "expected_provider_identity": init["expected_provider_identity_xonly_key"],
        "expected_profile": "btc-to-ln/v1",
        "expected_network": NetworkIdentity.model_validate_json(
            json.dumps(init["network_identity"])
        ),
        "supported_features": frozenset(),
        "supported_encryption_suites": frozenset({"noise-xk-secp256k1-chachapoly-sha256/v1"}),
        "supported_capabilities": frozenset({"core/v1", "recovery/v1"}),
        "crypto": crypto,
    }
    expected.update(changed)
    return verify_static_handshake_transcript(
        *(json.dumps(envelope).encode() for envelope in envelopes), **expected
    )


def test_pinned_static_transcript_accepts_historical_replay_without_admission() -> None:
    source, envelopes = _data()
    crypto = PinnedCrypto(source, envelopes)
    assert unsigned_envelope_hash(Envelope.model_validate_json(json.dumps(envelopes[2]))) == (
        bytes.fromhex("eef562447f6afa99cc8e9c949c72b37613488e1b061a01207fa51bca349eb20b")
    )
    assert _verify(source, envelopes, crypto) == TRANSCRIPT_DIGEST
    assert _verify(source, envelopes, crypto) == TRANSCRIPT_DIGEST
    assert len(crypto.calls) == 4


def test_cross_sender_id_collision_and_unsigned_wrapper_mutation_are_not_authentication() -> None:
    source, envelopes = _data()
    crypto = PinnedCrypto(source, envelopes)
    envelopes[0]["message_id"] = envelopes[1]["message_id"]
    envelopes[1]["in_reply_to"] = envelopes[0]["message_id"]
    assert _verify(source, envelopes, crypto) == TRANSCRIPT_DIGEST
    # Init/accept wrappers are unsigned: a different linked ID changes neither signature.
    envelopes[0]["message_id"] = "15" * 32
    envelopes[1]["in_reply_to"] = "15" * 32
    assert _verify(source, envelopes, crypto) == TRANSCRIPT_DIGEST


@pytest.mark.parametrize(
    "change",
    [
        "init-sequence",
        "init-sender",
        "init-signature",
        "init-outer-network",
        "accept-reply",
        "accept-sender",
        "accept-signature",
        "provider-signature",
        "confirm-reply",
        "confirm-sequence",
        "confirm-sender",
        "confirm-signature",
        "confirm-hash",
        "confirm-client-key",
        "confirm-session",
        "duplicate-id",
        "unknown-envelope-feature",
        "unknown-inner-feature",
        "unoffered-suite",
        "unsupported-suite",
        "unsupported-capability",
        "wrong-trusted-identity",
        "wrong-trusted-profile",
        "wrong-trusted-network",
        "bad-inner-payload",
    ],
)
def test_bad_static_transcript_never_grants_context(  # noqa: PLR0912, PLR0915 - adversarial cases
    change: str,
) -> None:
    source, original = _data()
    envelopes = copy.deepcopy(original)
    expected: dict[str, object] = {}
    if change == "init-sequence":
        envelopes[0]["sequence"] = 1
    elif change == "init-sender":
        envelopes[0]["sender_session_key"] = envelopes[1]["sender_session_key"]
    elif change == "init-signature":
        envelopes[0]["signature"] = CLIENT_CONFIRM_SIGNATURE
    elif change == "init-outer-network":
        envelopes[0]["network_identity"]["deployment_namespace"] = "another"
    elif change == "accept-reply":
        envelopes[1]["in_reply_to"] = "01" * 32
    elif change == "accept-sender":
        envelopes[1]["sender_session_key"] = envelopes[0]["sender_session_key"]
    elif change == "accept-signature":
        envelopes[1]["signature"] = CLIENT_CONFIRM_SIGNATURE
    elif change == "provider-signature":
        envelopes[1]["payload"]["provider_identity_signature"] = "00" * 64
    elif change == "confirm-reply":
        envelopes[2]["in_reply_to"] = "01" * 32
    elif change == "confirm-sequence":
        envelopes[2]["sequence"] = 0
    elif change == "confirm-sender":
        envelopes[2]["sender_session_key"] = envelopes[1]["sender_session_key"]
    elif change == "confirm-signature":
        envelopes[2]["signature"] = "00" * 64
    elif change == "confirm-hash":
        envelopes[2]["payload"]["handshake_hash"] = "00" * 32
    elif change == "confirm-client-key":
        envelopes[2]["payload"]["client_session_xonly_key"] = envelopes[1]["sender_session_key"]
    elif change == "confirm-session":
        envelopes[2]["payload"]["session_id"] = "30" * 32
    elif change == "duplicate-id":
        envelopes[2]["message_id"] = envelopes[0]["message_id"]
    elif change == "unknown-envelope-feature":
        envelopes[0]["required_features"] = ["org.test/unknown"]
    elif change == "unknown-inner-feature":
        envelopes[1]["payload"]["accept"]["required_features"] = ["org.test/unknown"]
    elif change == "unoffered-suite":
        envelopes[1]["payload"]["accept"]["selected_encryption_suite"] = "other/v1"
    elif change == "unsupported-suite":
        expected["supported_encryption_suites"] = frozenset()
    elif change == "unsupported-capability":
        expected["supported_capabilities"] = frozenset({"core/v1"})
    elif change == "wrong-trusted-identity":
        expected["expected_provider_identity"] = envelopes[1]["sender_session_key"]
    elif change == "wrong-trusted-profile":
        expected["expected_profile"] = "ln-to-btc/v1"
    elif change == "wrong-trusted-network":
        different = copy.deepcopy(envelopes[0]["network_identity"])
        different["deployment_namespace"] = "other"
        expected["expected_network"] = NetworkIdentity.model_validate_json(json.dumps(different))
    else:
        envelopes[1]["payload"]["extra"] = "unregistered"
    with pytest.raises(ValidationError, match="invalid static handshake transcript") as error:
        _verify(source, envelopes, PinnedCrypto(source, original), **expected)
    assert error.value.__cause__ is None
    assert error.value.__context__ is None


def test_boolean_verifier_and_noncanonical_duplicate_key_are_rejected() -> None:
    source, envelopes = _data()
    crypto = PinnedCrypto(source, envelopes)
    crypto.schnorr_verify = lambda *_args: False  # type: ignore[method-assign]
    with pytest.raises(ValidationError, match="invalid static handshake transcript"):
        _verify(source, envelopes, crypto)
    init = json.dumps(envelopes[0]).encode()
    duplicated = init.replace(
        b'"protocol": "rillswap"', b'"protocol": "rillswap", "protocol": "rillswap"', 1
    )
    with pytest.raises(ValidationError, match="invalid static handshake transcript"):
        verify_static_handshake_transcript(
            duplicated,
            json.dumps(envelopes[1]).encode(),
            json.dumps(envelopes[2]).encode(),
            expected_provider_identity=source["verification_context"]["handshake_init"][
                "expected_provider_identity_xonly_key"
            ],
            expected_profile="btc-to-ln/v1",
            expected_network=NetworkIdentity.model_validate_json(
                json.dumps(source["network_identity"])
            ),
            supported_features=frozenset(),
            supported_encryption_suites=frozenset({"noise-xk-secp256k1-chachapoly-sha256/v1"}),
            supported_capabilities=frozenset({"core/v1", "recovery/v1"}),
            crypto=crypto,
        )


def test_static_accept_pair_returns_transcript_digest_only_for_signed_accept() -> None:
    source, envelopes = _data()
    crypto = PinnedCrypto(source, envelopes)
    init = source["verification_context"]["handshake_init"]
    expected: dict[str, Any] = {
        "expected_provider_identity": init["expected_provider_identity_xonly_key"],
        "expected_profile": "btc-to-ln/v1",
        "expected_network": NetworkIdentity.model_validate_json(
            json.dumps(init["network_identity"])
        ),
        "supported_features": frozenset(),
        "supported_encryption_suites": frozenset({"noise-xk-secp256k1-chachapoly-sha256/v1"}),
        "supported_capabilities": frozenset({"core/v1", "recovery/v1"}),
        "crypto": crypto,
    }
    pair = [json.dumps(envelope).encode() for envelope in envelopes[:2]]
    assert verify_static_handshake_accept(*pair, **expected) == TRANSCRIPT_DIGEST
    assert len(crypto.calls) == 1
    tampered = copy.deepcopy(envelopes[1])
    tampered["payload"]["provider_identity_signature"] = "00" * 64
    with pytest.raises(ValidationError, match=r"\Ainvalid static handshake accept\Z") as caught:
        verify_static_handshake_accept(pair[0], json.dumps(tampered).encode(), **expected)
    assert caught.value.__cause__ is None
    with pytest.raises(ValidationError, match=r"\Ainvalid static handshake accept\Z"):
        verify_static_handshake_accept(pair[1], pair[0], **expected)
    with pytest.raises(ValidationError, match=r"\Ainvalid static handshake accept\Z"):
        verify_static_handshake_accept(*pair, **{**expected, "expected_profile": "ln-to-btc/v1"})
