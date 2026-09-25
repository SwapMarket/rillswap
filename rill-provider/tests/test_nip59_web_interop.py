"""Opt-in, disposable web-to-provider NIP-59 proof, not live receipt or admission."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path
from typing import Any

import pytest
from rill_core.wire.canonical import canonicalize
from rill_core.wire.envelope_authentication import verify_static_signed_envelope
from rill_core.wire.messages import Envelope

from rill_provider import _nip59_receive as receiver

ROOT = Path(__file__).parents[2]
DOCS_FIXTURE = ROOT / "rill-docs/vectors/authentication/cases-v1.json"
WEB_SCRIPT = ROOT / "rill-web/scripts/emit-nip59-test-wrap.ts"
RECIPIENT_SECRET = b"\x03" * 32  # Disposable synthetic mailbox only, never deployed.


def _required_sources() -> tuple[str, Path]:
    library = os.environ.get("RILL_CRYPTO_LIBRARY")
    bun = shutil.which("bun")
    # Explicit opt-in fails closed when a sibling, dependency, or native
    # capability is absent. The default provider suite is standalone.
    assert library is not None, "native crypto library required"
    assert Path(library).is_file(), "native crypto library file required"
    assert bun is not None, "Bun required for web interop"
    assert DOCS_FIXTURE.is_file(), "docs fixture required"
    assert WEB_SCRIPT.is_file(), "web emitter required"
    assert (ROOT / "rill-web/node_modules/nostr-tools").is_dir(), (
        "nostr-tools installation required"
    )
    return bun, Path(library)


def _web_wrap(
    *,
    bun: str,
    case: dict[str, Any],
    recipient_xonly: str,
) -> bytes:
    content = canonicalize(case["confirm_envelope"]["object"])
    request = {
        "canonical_envelope": content.decode("utf-8"),
        "sender_secret_hex": case["confirm_envelope"]["signer_secret_key"],
        "recipient_xonly_key": recipient_xonly,
    }
    result = subprocess.run(  # noqa: S603 - local test script, no shell
        [bun, str(WEB_SCRIPT)],
        cwd=ROOT / "rill-web",
        input=json.dumps(request).encode(),
        capture_output=True,
        timeout=30,
        check=False,
    )
    assert result.returncode == 0, "independent test producer failed"
    assert 0 < len(result.stdout) <= 128 * 1024
    return result.stdout


@pytest.mark.web_nip59_interop
@pytest.mark.skipif(
    os.environ.get("RILLSWAP_RUN_WEB_NIP59") != "1",
    reason="explicit local web/native opt-in required",
)
@pytest.mark.parametrize(
    ("case_index", "profile_id"),
    [(0, "btc-to-ln/v1"), (1, "ln-to-btc/v1")],
)
def test_web_produced_wrap_native_provider_consumes_signed_rs001(
    case_index: int,
    profile_id: str,
) -> None:
    from rill_crypto import Context  # noqa: PLC0415 - native opt-in boundary

    bun, library = _required_sources()
    fixture = json.loads(DOCS_FIXTURE.read_bytes())
    case: dict[str, Any] = fixture["valid"][case_index]
    canonical_envelope = canonicalize(case["confirm_envelope"]["object"])
    signed = Envelope.model_validate_json(canonical_envelope, strict=True)
    assert case["profile_id"] == signed.profile_id == profile_id
    assert signed.network_identity.name == "regtest"
    with Context(library_path=library) as crypto:
        # Independently confirm that this is a genuine fixture-signed RS-001
        # frame; the producer only accepts bytes and never signs the envelope.
        digest = verify_static_signed_envelope(
            canonical_envelope,
            expected_session_id=signed.session_id,
            expected_profile=signed.profile_id,
            expected_network=signed.network_identity,
            expected_sender_key=signed.sender_session_key,
            supported_features=frozenset(),
            crypto=crypto,
        )
        assert digest.hex() == case["confirm_envelope"]["tagged_hash"]
        mailbox_xonly = crypto.public_key(RECIPIENT_SECRET)[1:].hex()
        first = _web_wrap(bun=bun, case=case, recipient_xonly=mailbox_xonly)
        second = _web_wrap(bun=bun, case=case, recipient_xonly=mailbox_xonly)
        decoded = []
        for outer in (first, second):
            candidate = receiver._decode_gift_wrap_candidate(  # noqa: SLF001 - no admission
                outer,
                recipient_mailbox_secret=RECIPIENT_SECRET,
                expected_recipient_xonly_key=mailbox_xonly,
                expected_network=signed.network_identity,
                expected_profile_id=signed.profile_id,
                crypto=crypto,
            )
            assert candidate.envelope == signed
            assert candidate.seal_author_xonly_key == signed.sender_session_key
            decoded.append(candidate)
        assert decoded[0].outer_event_id != decoded[1].outer_event_id
        assert decoded[0].envelope.message_id == decoded[1].envelope.message_id
        # Decoding the same bytes twice also succeeds: replay disposition is
        # deliberately NOT a property of this receive primitive.
        again = receiver._decode_gift_wrap_candidate(  # noqa: SLF001
            first,
            recipient_mailbox_secret=RECIPIENT_SECRET,
            expected_recipient_xonly_key=mailbox_xonly,
            expected_network=signed.network_identity,
            expected_profile_id=signed.profile_id,
            crypto=crypto,
        )
        assert again.outer_event_id == decoded[0].outer_event_id
