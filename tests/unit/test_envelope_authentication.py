"""Static authentication never grants transcript or financial authority."""

from __future__ import annotations

import copy
import json
from typing import Any

import pytest

from rill_core.errors import ValidationError
from rill_core.wire import verify_static_signed_envelope
from rill_core.wire.hashes import unsigned_envelope_hash
from rill_core.wire.messages import Envelope
from rill_core.wire.types import NetworkIdentity

CLIENT = "c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5"
PROVIDER = "f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9"
SIGNATURE = "ab" * 64


def _envelope() -> dict[str, Any]:
    return {
        "protocol": "rillswap",
        "wire_version": "1",
        "profile_id": "btc-to-ln/v1",
        "network_identity": {
            "family": "bitcoin",
            "name": "regtest",
            "genesis_hash": "01" * 32,
            "signet_challenge": None,
            "consensus_profile": "bitcoin-core-v30.0-regtest-default",
            "deployment_namespace": "rill-test",
        },
        "session_id": "11" * 32,
        "message_id": "22" * 32,
        "sender_session_key": CLIENT,
        "sequence": 2,
        "in_reply_to": None,
        "contract_hash": None,
        "message_type": "observation",
        "payload": {"height": 100},
        "required_features": [],
        "extensions": {},
        "signature": SIGNATURE,
    }


def _encoded(value: dict[str, Any]) -> bytes:
    return json.dumps(value).encode()


class PinnedVerifier:
    def __init__(self, value: dict[str, Any]) -> None:
        self.digest = unsigned_envelope_hash(Envelope.model_validate_json(_encoded(value)))
        self.calls: list[tuple[bytes, bytes, bytes]] = []

    def schnorr_verify(self, public_key: bytes, message: bytes, signature: bytes) -> None:
        self.calls.append((public_key, message, signature))
        if (public_key, message, signature) != (
            bytes.fromhex(CLIENT),
            self.digest,
            bytes.fromhex(SIGNATURE),
        ):
            raise ValueError("secret-bearing adapter failure")


def _verify(
    document: bytes,
    crypto: PinnedVerifier,
    **changes: object,
) -> bytes:
    data = _envelope()
    expectations: dict[str, Any] = {
        "expected_session_id": data["session_id"],
        "expected_profile": data["profile_id"],
        "expected_network": NetworkIdentity.model_validate(data["network_identity"]),
        "expected_sender_key": CLIENT,
        "supported_features": frozenset(),
        "crypto": crypto,
    }
    expectations.update(changes)
    return verify_static_signed_envelope(document, **expectations)


def test_unsigned_digest_verified_against_expected_key_but_grants_no_authority() -> None:
    value = _envelope()
    crypto = PinnedVerifier(value)
    assert _verify(_encoded(value), crypto) == crypto.digest
    assert crypto.calls == [(bytes.fromhex(CLIENT), crypto.digest, bytes.fromhex(SIGNATURE))]
    # No state or effect capability is returned. The caller still owns role and replay checks.


@pytest.mark.parametrize(
    "mutation",
    [
        "signature",
        "payload",
        "session_id",
        "profile_id",
        "network_identity",
        "sender_session_key",
        "unsupported_feature",
        "null_signature",
        "init",
        "accept",
        "invalid_sequence",
    ],
)
def test_context_and_signature_mismatch_fail_closed(mutation: str) -> None:
    value = _envelope()
    crypto = PinnedVerifier(value)
    if mutation == "signature":
        value["signature"] = "ff" * 64
    elif mutation == "payload":
        value["payload"]["height"] = 101
    elif mutation == "session_id":
        value["session_id"] = "33" * 32
    elif mutation == "profile_id":
        value["profile_id"] = "ln-to-btc/v1"
    elif mutation == "network_identity":
        value["network_identity"]["deployment_namespace"] = "other"
    elif mutation == "sender_session_key":
        value["sender_session_key"] = PROVIDER
    elif mutation == "unsupported_feature":
        value["required_features"] = ["org.test/unknown"]
    elif mutation == "null_signature":
        value["signature"] = None
    elif mutation in {"init", "accept"}:
        value["message_type"] = "handshake_" + mutation
    else:
        value["sequence"] = True
    with pytest.raises(ValidationError, match="invalid static signed envelope") as error:
        _verify(_encoded(value), crypto)
    assert error.value.__cause__ is None
    assert error.value.__context__ is None


@pytest.mark.parametrize("expectation", ["session", "profile", "network", "sender", "features"])
def test_independently_supplied_expectations_are_validated(expectation: str) -> None:
    value = _envelope()
    crypto = PinnedVerifier(value)
    changes: dict[str, Any] = {}
    if expectation == "session":
        changes["expected_session_id"] = "not-a-session"
    elif expectation == "profile":
        changes["expected_profile"] = "unregistered/v1"
    elif expectation == "network":
        invalid = copy.deepcopy(value["network_identity"])
        invalid["genesis_hash"] = "not-a-hash"
        changes["expected_network"] = NetworkIdentity.model_construct(**invalid)
    elif expectation == "sender":
        changes["expected_sender_key"] = "not-a-key"
    else:
        changes["supported_features"] = frozenset({"BAD FEATURE"})
    with pytest.raises(ValidationError, match="invalid static signed envelope"):
        _verify(_encoded(value), crypto, **changes)


def test_understood_feature_requires_signature_over_that_feature() -> None:
    value = _envelope()
    value["required_features"] = ["org.test/known"]
    crypto = PinnedVerifier(value)
    assert _verify(_encoded(value), crypto, supported_features=frozenset({"org.test/known"})) == (
        crypto.digest
    )


@pytest.mark.parametrize("document", [b"\xff", b'{"sequence":1,"sequence":2}', b"[]"])
def test_invalid_bytes_never_reach_signature_verification(document: bytes) -> None:
    crypto = PinnedVerifier(_envelope())
    with pytest.raises(ValidationError, match="invalid static signed envelope"):
        _verify(document, crypto)
    assert crypto.calls == []


def test_crypto_returning_false_and_leaky_crypto_error_are_both_redacted() -> None:
    value = _envelope()

    class InvalidVerifier:
        def schnorr_verify(self, *_args: bytes) -> bool:
            return False

    with pytest.raises(ValidationError, match="invalid static signed envelope"):
        _verify(_encoded(value), InvalidVerifier())  # type: ignore[arg-type]
    value["signature"] = "ff" * 64
    with pytest.raises(ValidationError, match="invalid static signed envelope") as error:
        _verify(_encoded(value), PinnedVerifier(_envelope()))
    assert "secret-bearing" not in repr(error.value)
    assert error.value.__cause__ is None
    assert error.value.__context__ is None
