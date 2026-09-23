"""Read-only provider/core/native transcript integration without admission."""

from __future__ import annotations

import copy
import json
import os
from pathlib import Path
from typing import Any, Self

import pytest
from rill_core.errors import ValidationError
from rill_core.wire.types import NetworkIdentity

from rill_provider import handshake_diagnostic as diagnostic

FIXTURE = Path(__file__).parent / "fixtures" / "initial-btc-to-ln-v1.json"
CONFIRM_SIGNATURE = (
    "d8a7339977e4673e215e61339386e8208b0c6d1ecbe01621e985fe3d6c1399"
    "384f7b321a32c9ddf5363cb484e78561b3fb6aa65e686a076fcf95c7263a13c3bb"
)


def _transcript() -> tuple[dict[str, Any], list[dict[str, Any]]]:
    source = json.loads(FIXTURE.read_text())
    context = source["verification_context"]
    init, accepted = context["handshake_init"], context["handshake_accept"]
    shared = {
        "protocol": "rillswap",
        "wire_version": "1",
        "profile_id": source["profile_id"],
        "network_identity": source["network_identity"],
        "session_id": init["session_id"],
        "contract_hash": None,
        "required_features": [],
        "extensions": {},
    }
    return source, [
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
            "sender_session_key": accepted["provider_session_xonly_key"],
            "sequence": 0,
            "in_reply_to": "12" * 32,
            "payload": {
                "accept": accepted,
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
                "provider_session_xonly_key": accepted["provider_session_xonly_key"],
            },
            "signature": CONFIRM_SIGNATURE,
        },
    ]


def _check(
    source: dict[str, Any], envelopes: list[dict[str, Any]], library: Path, **changes: object
) -> bytes:
    configured: dict[str, Any] = {
        "expected_provider_identity": source["verification_context"]["handshake_init"][
            "expected_provider_identity_xonly_key"
        ],
        "expected_profile": source["profile_id"],
        "expected_network": NetworkIdentity.model_validate_json(
            json.dumps(source["network_identity"])
        ),
        "supported_features": frozenset(),
        "supported_encryption_suites": frozenset({"noise-xk-secp256k1-chachapoly-sha256/v1"}),
        "supported_capabilities": frozenset({"core/v1", "recovery/v1"}),
        "native_library_path": library,
    }
    configured.update(changes)
    return diagnostic.verify_handshake_diagnostic(
        *(json.dumps(envelope).encode() for envelope in envelopes), **configured
    )


def test_explicit_native_context_is_closed_on_success_and_validation_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source, envelopes = _transcript()
    library = tmp_path / "operator-selected-native.so"
    seen: list[str] = []

    class FakeContext:
        def __init__(self, *, library_path: Path) -> None:
            assert library_path == library
            seen.append("open")

        def __enter__(self) -> Self:
            return self

        def __exit__(self, *_args: object) -> None:
            seen.append("close")

        def schnorr_verify(self, _public: bytes, _digest: bytes, _signature: bytes) -> None:
            seen.append("verify")

    monkeypatch.setattr(diagnostic, "Context", FakeContext)
    assert _check(source, envelopes, library) == bytes.fromhex(
        source["verification_context"]["handshake_hash"]
    )
    invalid = copy.deepcopy(envelopes)
    invalid[2]["payload"]["session_id"] = "20" * 32
    with pytest.raises(ValidationError, match="invalid static handshake transcript"):
        _check(source, invalid, library)
    assert seen == ["open", "verify", "verify", "close", "open", "verify", "close"]


def test_unavailable_library_and_non_absolute_path_do_not_echo_configuration(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source, envelopes = _transcript()

    def fail(*, library_path: Path) -> None:
        raise RuntimeError("private-native-path-" + str(library_path))

    monkeypatch.setattr(diagnostic, "Context", fail)
    for path in (tmp_path / "missing.so", Path("relative.so")):
        with pytest.raises(diagnostic.HandshakeDiagnosticUnavailableError) as error:
            _check(source, envelopes, path)
        assert str(error.value) == "native handshake diagnostic unavailable"
        assert error.value.__cause__ is None
        assert error.value.__context__ is None


@pytest.mark.native_crypto
@pytest.mark.skipif(
    os.environ.get("RILLSWAP_RUN_NATIVE_CRYPTO") != "1",
    reason="set RILLSWAP_RUN_NATIVE_CRYPTO=1 with pinned RILL_CRYPTO_LIBRARY",
)
def test_real_native_handshake_is_only_a_historical_diagnostic() -> None:
    source, envelopes = _transcript()
    library = Path(os.environ["RILL_CRYPTO_LIBRARY"])
    digest = bytes.fromhex(source["verification_context"]["handshake_hash"])
    assert _check(source, envelopes, library) == digest
    assert _check(source, envelopes, library) == digest  # Historical replay still verifies.
    for change in (
        "provider-signature",
        "client-signature",
        "wrong-identity",
        "wrong-network",
        "wrong-profile",
        "unsupported-suite",
    ):
        changed = copy.deepcopy(envelopes)
        kwargs: dict[str, object] = {}
        if change == "provider-signature":
            changed[1]["payload"]["provider_identity_signature"] = "00" * 64
        elif change == "client-signature":
            changed[2]["signature"] = "00" * 64
        elif change == "wrong-identity":
            kwargs["expected_provider_identity"] = changed[1]["payload"]["accept"][
                "provider_session_xonly_key"
            ]
        elif change == "wrong-network":
            different = copy.deepcopy(source["network_identity"])
            different["deployment_namespace"] = "other"
            kwargs["expected_network"] = NetworkIdentity.model_validate_json(json.dumps(different))
        elif change == "wrong-profile":
            kwargs["expected_profile"] = "ln-to-btc/v1"
        else:
            kwargs["supported_encryption_suites"] = frozenset()
        with pytest.raises(ValidationError, match="invalid static handshake transcript"):
            _check(source, changed, library, **kwargs)
