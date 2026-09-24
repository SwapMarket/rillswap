"""Synthetic, disposable NIP-59 frames are candidates, never swap admission."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
from pathlib import Path
from typing import TYPE_CHECKING, Any

import pytest
from Cryptodome.Cipher import ChaCha20
from rill_core.wire.canonical import canonicalize
from rill_core.wire.types import NetworkIdentity

from rill_provider import _nip59_receive as receive

if TYPE_CHECKING:
    from rill_crypto import Context

FIXTURE = Path(__file__).parent / "fixtures/initial-btc-to-ln-v1.json"
RECIPIENT = b"\x03" * 32  # Synthetic key for test-only mailbox, never funded or deployed.
SENDER = b"\x02" * 32
WRAPPER = b"\x04" * 32
NONCE = b"\x08" * 32  # Test vector only; production must use fresh CSPRNG nonces.


def _encrypt(content: str, secret: bytes, peer_xonly_key: str, crypto: Context) -> str:
    from rill_provider import _nip44_v2 as codec  # noqa: PLC0415 - test-only construction

    shared = crypto.nip44_shared_x(secret, bytes.fromhex(peer_xonly_key))
    conversation = hmac.digest(b"nip44-v2", shared, "sha256")
    key, chacha_nonce, hmac_key = codec._message_keys(conversation, NONCE)  # noqa: SLF001
    plaintext = content.encode()
    padded = (
        len(plaintext).to_bytes(2, "big")
        + plaintext
        + bytes(codec._padded_length(len(plaintext)) - len(plaintext))  # noqa: SLF001
    )
    ciphertext = ChaCha20.new(key=key, nonce=chacha_nonce).encrypt(padded)
    mac = hmac.digest(hmac_key, NONCE + ciphertext, "sha256")
    return base64.b64encode(b"\x02" + NONCE + ciphertext + mac).decode()


def _signed(
    kind: int,
    tags: list[list[str]],
    content: str,
    secret: bytes,
    crypto: Context,
) -> dict[str, Any]:
    public = crypto.public_key(secret)[1:].hex()
    event: dict[str, Any] = {
        "pubkey": public,
        "created_at": 1703021488,
        "kind": kind,
        "tags": tags,
        "content": content,
    }
    event["id"] = hashlib.sha256(
        json.dumps(
            [0, public, event["created_at"], kind, tags, content],
            ensure_ascii=False,
            separators=(",", ":"),
        ).encode()
    ).hexdigest()
    event["sig"] = crypto.schnorr_sign(secret, bytes.fromhex(event["id"]), b"\x07" * 32).hex()
    return event


def _frame(  # noqa: PLR0912, PLR0915 - layered negative fixture generator
    crypto: Context,
    *,
    mutation: str = "",
) -> tuple[bytes, NetworkIdentity, str, str]:
    fixture = json.loads(FIXTURE.read_bytes())
    network = NetworkIdentity.model_validate_json(json.dumps(fixture["network_identity"]))
    recipient_pub = crypto.public_key(RECIPIENT)[1:].hex()
    sender_pub = crypto.public_key(SENDER)[1:].hex()
    init = dict(fixture["verification_context"]["handshake_init"])
    init["client_session_xonly_key"] = sender_pub
    envelope = {
        "protocol": "rillswap",
        "wire_version": "1",
        "profile_id": fixture["profile_id"],
        "network_identity": fixture["network_identity"],
        "session_id": init["session_id"],
        "message_id": "12" * 32,
        "sender_session_key": sender_pub,
        "sequence": 0,
        "in_reply_to": None,
        "contract_hash": None,
        "message_type": "handshake_init",
        "payload": init,
        "required_features": [],
        "extensions": {},
        "signature": None,
    }
    if mutation == "envelope-wrong-sender":
        envelope["sender_session_key"] = "aa" * 32
    if mutation == "rumor-wrong-author":
        envelope["sender_session_key"] = "bb" * 32
    if mutation == "wrong-envelope-version":
        envelope["wire_version"] = "2"
    content = canonicalize(envelope).decode()
    if mutation == "noncanonical-envelope":
        content = json.dumps(envelope, indent=2)
    tags = [["rillswap", "nostr-experimental-1"]]
    if mutation == "rumor-wrong-tag":
        tags = [["rillswap", "unknown-version"]]
    rumor_pub = "bb" * 32 if mutation == "rumor-wrong-author" else sender_pub
    rumor = {
        "pubkey": rumor_pub,
        "created_at": 1703021488,
        "kind": 21417,
        "tags": tags,
        "content": content,
    }
    rumor["id"] = hashlib.sha256(
        json.dumps(
            [0, rumor_pub, rumor["created_at"], rumor["kind"], tags, content],
            ensure_ascii=False,
            separators=(",", ":"),
        ).encode()
    ).hexdigest()
    if mutation == "rumor-bad-id":
        rumor["id"] = "00" * 32
    if mutation == "rumor-sig-null":
        rumor["sig"] = None
    if mutation == "rumor-extra-field":
        rumor["extra"] = True
    rumor_text = json.dumps(rumor, ensure_ascii=False, separators=(",", ":"))
    seal_content = _encrypt(rumor_text, SENDER, recipient_pub, crypto)
    seal = _signed(13, [], seal_content, SENDER, crypto)
    if mutation == "seal-wrong-kind":
        seal = _signed(12, [], seal_content, SENDER, crypto)
    if mutation == "seal-nonempty-tags":
        seal = _signed(13, [["p", recipient_pub]], seal_content, SENDER, crypto)
    if mutation == "seal-bad-signature":
        seal["sig"] = "00" * 64
    wrap_content = _encrypt(json.dumps(seal, separators=(",", ":")), WRAPPER, recipient_pub, crypto)
    outer_tags = [["p", recipient_pub]]
    if mutation == "wrong-recipient-tag":
        outer_tags = [["p", "ff" * 32]]
    if mutation == "duplicate-recipient-tag":
        outer_tags.append(["p", recipient_pub])
    outer_kind = 21059 if mutation == "ephemeral-wrap" else 1059
    outer = _signed(outer_kind, outer_tags, wrap_content, WRAPPER, crypto)
    if mutation == "outer-bad-signature":
        outer["sig"] = "00" * 64
    if mutation == "outer-bad-id":
        outer["id"] = "00" * 32
    if mutation == "outer-bad-mac":
        changed = bytearray(base64.b64decode(wrap_content))
        changed[-1] ^= 1
        outer = _signed(1059, outer_tags, base64.b64encode(changed).decode(), WRAPPER, crypto)
    return json.dumps(outer, separators=(",", ":")).encode(), network, recipient_pub, sender_pub


@pytest.mark.native_crypto
@pytest.mark.skipif(
    not os.environ.get("RILL_CRYPTO_LIBRARY"), reason="requires pinned native crypto"
)
def test_private_regtest_nip59_receive_is_not_admission() -> None:
    from rill_crypto import Context  # noqa: PLC0415 - opt-in native test

    with Context(library_path=os.environ["RILL_CRYPTO_LIBRARY"]) as crypto:
        outer, network, recipient, sender = _frame(crypto)
        candidate = receive._decode_gift_wrap_candidate(  # noqa: SLF001
            outer,
            recipient_mailbox_secret=RECIPIENT,
            expected_recipient_xonly_key=recipient,
            expected_network=network,
            expected_profile_id="btc-to-ln/v1",
            crypto=crypto,
        )
        assert candidate.seal_author_xonly_key == sender
        assert candidate.envelope.sender_session_key == sender
        assert candidate.envelope.message_type == "handshake_init"
        assert candidate.envelope.signature is None
        assert candidate.rumor_id != candidate.outer_event_id


@pytest.mark.native_crypto
@pytest.mark.skipif(
    not os.environ.get("RILL_CRYPTO_LIBRARY"), reason="requires pinned native crypto"
)
@pytest.mark.parametrize(
    "mutation",
    [
        "outer-bad-signature",
        "outer-bad-id",
        "wrong-recipient-tag",
        "duplicate-recipient-tag",
        "ephemeral-wrap",
        "outer-bad-mac",
        "seal-bad-signature",
        "seal-wrong-kind",
        "seal-nonempty-tags",
        "rumor-bad-id",
        "rumor-sig-null",
        "rumor-extra-field",
        "rumor-wrong-tag",
        "rumor-wrong-author",
        "envelope-wrong-sender",
        "wrong-envelope-version",
        "noncanonical-envelope",
        "wrong-network",
        "wrong-profile",
        "wrong-mailbox-secret",
    ],
)
def test_nip59_layered_rejection_never_admits_candidate(mutation: str) -> None:
    from rill_crypto import Context  # noqa: PLC0415 - opt-in native test

    with Context(library_path=os.environ["RILL_CRYPTO_LIBRARY"]) as crypto:
        outer, network, recipient, _sender = _frame(crypto, mutation=mutation)
        expected_network = (
            network.model_copy(update={"deployment_namespace": "other-regtest"})
            if mutation == "wrong-network"
            else network
        )
        expected_profile = "ln-to-btc/v1" if mutation == "wrong-profile" else "btc-to-ln/v1"
        secret = b"\x05" * 32 if mutation == "wrong-mailbox-secret" else RECIPIENT
        with pytest.raises(receive.Nip59ReceiveRefusedError) as failure:
            receive._decode_gift_wrap_candidate(  # noqa: SLF001
                outer,
                recipient_mailbox_secret=secret,
                expected_recipient_xonly_key=recipient,
                expected_network=expected_network,
                expected_profile_id=expected_profile,
                crypto=crypto,
            )
        assert failure.value.__cause__ is None
        assert failure.value.__context__ is None
        assert str(failure.value) == "NIP-59 frame candidate refused"


def test_invalid_outer_event_is_refused_without_decrypting(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class NoNative:
        def schnorr_verify(self, *_args: object) -> None:
            pytest.fail("invalid outer ID must fail before native verification")

    def no_decrypt(*_args: object, **_kwargs: object) -> None:
        pytest.fail("outer signature and routing must be verified first")

    from rill_provider import _nip44_v2 as codec  # noqa: PLC0415 - ordering seam

    monkeypatch.setattr(codec, "_decrypt_payload", no_decrypt)
    with pytest.raises(receive.Nip59ReceiveRefusedError):
        receive._decode_gift_wrap_candidate(  # noqa: SLF001 - malformed before ECDH
            b"{",
            recipient_mailbox_secret=RECIPIENT,
            expected_recipient_xonly_key="11" * 32,
            expected_network=NetworkIdentity.model_validate_json(
                json.dumps(json.loads(FIXTURE.read_bytes())["network_identity"])
            ),
            expected_profile_id="btc-to-ln/v1",
            crypto=NoNative(),  # type: ignore[arg-type]
        )


@pytest.mark.native_crypto
@pytest.mark.skipif(
    not os.environ.get("RILL_CRYPTO_LIBRARY"), reason="requires pinned native crypto"
)
@pytest.mark.parametrize(
    ("mutation", "decrypt_calls"),
    [
        ("outer-bad-signature", 0),
        ("wrong-recipient-tag", 0),
        ("seal-bad-signature", 1),
        ("seal-wrong-kind", 1),
        ("seal-nonempty-tags", 1),
    ],
)
def test_each_signature_and_routing_check_precedes_its_decryption(
    monkeypatch: pytest.MonkeyPatch,
    mutation: str,
    decrypt_calls: int,
) -> None:
    from rill_crypto import Context  # noqa: PLC0415 - opt-in native test

    from rill_provider import _nip44_v2 as codec  # noqa: PLC0415 - ordering seam

    with Context(library_path=os.environ["RILL_CRYPTO_LIBRARY"]) as crypto:
        outer, network, recipient, _sender = _frame(crypto, mutation=mutation)
        calls: list[str] = []
        original = codec._decrypt_payload  # noqa: SLF001 - observe ordering

        def count_decrypt(
            payload: str,
            *,
            recipient_secret: bytes,
            sender_public_key: bytes,
            crypto: Context,
        ) -> str:
            calls.append(payload)
            return original(
                payload,
                recipient_secret=recipient_secret,
                sender_public_key=sender_public_key,
                crypto=crypto,
            )

        monkeypatch.setattr(codec, "_decrypt_payload", count_decrypt)
        with pytest.raises(receive.Nip59ReceiveRefusedError):
            receive._decode_gift_wrap_candidate(  # noqa: SLF001 - ordering invariant
                outer,
                recipient_mailbox_secret=RECIPIENT,
                expected_recipient_xonly_key=recipient,
                expected_network=network,
                expected_profile_id="btc-to-ln/v1",
                crypto=crypto,
            )
        assert len(calls) == decrypt_calls


@pytest.mark.native_crypto
@pytest.mark.skipif(
    not os.environ.get("RILL_CRYPTO_LIBRARY"), reason="requires pinned native crypto"
)
@pytest.mark.parametrize("missing", ["verifier", "ecdh"])
def test_missing_native_capability_is_sanitized_configuration_failure(missing: str) -> None:
    from rill_crypto import Context  # noqa: PLC0415 - opt-in native test

    with Context(library_path=os.environ["RILL_CRYPTO_LIBRARY"]) as crypto:
        outer, network, recipient, _sender = _frame(crypto)

        class PartialBinding:
            def __getattr__(self, name: str) -> object:
                if name == ("schnorr_verify" if missing == "verifier" else "nip44_shared_x"):
                    raise AttributeError(name)
                return getattr(crypto, name)

        with pytest.raises(receive.Nip59CapabilityUnavailableError) as failure:
            receive._decode_gift_wrap_candidate(  # noqa: SLF001 - capability boundary
                outer,
                recipient_mailbox_secret=RECIPIENT,
                expected_recipient_xonly_key=recipient,
                expected_network=network,
                expected_profile_id="btc-to-ln/v1",
                crypto=PartialBinding(),  # type: ignore[arg-type]
            )
        assert failure.value.__cause__ is None
        assert failure.value.__context__ is None
        assert str(failure.value) == "NIP-59 native capability unavailable"
        frames = []
        traceback = failure.value.__traceback__
        while traceback is not None:
            if traceback.tb_frame.f_code.co_filename == receive.__file__:
                frames.append(traceback.tb_frame)
            traceback = traceback.tb_next
        assert len(frames) == 1
        assert "recipient_mailbox_secret" not in frames[0].f_locals
