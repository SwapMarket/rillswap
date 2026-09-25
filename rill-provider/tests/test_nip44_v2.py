"""Internal NIP-44 decoder interoperability, not a transport acceptance test."""

from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import json
import os
from pathlib import Path
from typing import Any

import pytest
from Cryptodome.Cipher import ChaCha20

from rill_provider import _nip44_v2 as codec

FIXTURE = Path(__file__).parent / "fixtures/nip44-v2-curated.json"
CURATED_SHA256 = "7820c4d2cbe021f8ca5cd92adb12a5a8308b73dccf1dc41ee38942167a8eaddd"
SOURCE_SHA256 = "269ed0f69e4c192512cc779e78c555090cebc7c785b609e338a62afc3ce25040"


def _fixture() -> dict[str, Any]:
    content = FIXTURE.read_bytes()
    assert hashlib.sha256(content).hexdigest() == CURATED_SHA256
    fixture: dict[str, Any] = json.loads(content)
    assert fixture["source_sha256"] == SOURCE_SHA256
    assert fixture["source"].endswith("/nip44.vectors.json")
    return fixture


def _decode_with_key(payload: str, conversation_key: bytes) -> str:
    nonce, ciphertext, mac = codec._decode(payload)  # noqa: SLF001 - internal vector seam
    return codec._decrypt_with_conversation_key(  # noqa: SLF001 - internal vector seam
        nonce,
        ciphertext,
        mac,
        conversation_key,
    )


def test_official_nip44_message_keys_and_valid_payload_without_native() -> None:
    fixture = _fixture()
    keys = fixture["valid_message_keys_0"]
    derived = codec._message_keys(  # noqa: SLF001 - pinned upstream intermediate vectors
        bytes.fromhex(keys["conversation_key"]),
        bytes.fromhex(keys["nonce"]),
    )
    assert tuple(part.hex() for part in derived) == (
        keys["chacha_key"],
        keys["chacha_nonce"],
        keys["hmac_key"],
    )
    sample = fixture["valid_encrypt_decrypt_0"]
    assert (
        _decode_with_key(sample["payload"], bytes.fromhex(sample["conversation_key"]))
        == (sample["plaintext"])
    )
    assert codec._decode(sample["payload"])[0].hex() == sample["nonce"]  # noqa: SLF001


def test_all_official_invalid_nip44_decrypt_vectors() -> None:
    rows = _fixture()["invalid_decrypt"]
    assert len(rows) == 12
    for row in rows:
        expected = (
            codec.Nip44UnsupportedVersionError
            if row["note"].startswith("unknown encryption version")
            else codec.Nip44InvalidPayloadError
        )
        with pytest.raises(expected):
            _decode_with_key(row["payload"], bytes.fromhex(row["conversation_key"]))


def test_reject_noncanonical_and_oversized_base64_before_cryptography() -> None:
    sample = _fixture()["valid_encrypt_decrypt_0"]
    payload = sample["payload"]
    bad = [
        "",
        payload + " ",
        payload + "\n",
        "é" + payload,
        payload[:-1],
        payload[:-1] + "@",
        payload + "A" * codec.MAX_ENCODED_PAYLOAD,
    ]
    decoded = bytearray(base64.b64decode(payload))
    # The final base64 character can have different unused pad bits for a
    # one-byte tail; reject aliases even if they decode to the same bytes.
    canonical = base64.b64encode(b"\x02" * 100).decode()
    assert canonical.endswith("==")
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    previous = alphabet.index(canonical[-3])
    alias = canonical[:-3] + alphabet[previous + 1] + "=="
    assert base64.b64decode(alias) == base64.b64decode(canonical)
    bad.append(alias)

    class NoCrypto:
        def nip44_shared_x(self, *_args: object) -> bytes:
            pytest.fail("invalid encoding must be refused before ECDH")

    for item in bad:
        with pytest.raises(codec.Nip44InvalidPayloadError, match="payload refused"):
            codec._decrypt_payload(  # noqa: SLF001 - internal vector seam
                item,
                recipient_secret=b"\x01" * 32,
                sender_public_key=b"\x02" * 32,
                crypto=NoCrypto(),  # type: ignore[arg-type]
            )
    for item in ("#" + payload, base64.b64encode(b"\x00" + decoded[1:]).decode()):
        with pytest.raises(codec.Nip44UnsupportedVersionError, match="unsupported"):
            codec._decrypt_payload(  # noqa: SLF001 - version rejected before ECDH
                item,
                recipient_secret=b"\x01" * 32,
                sender_public_key=b"\x02" * 32,
                crypto=NoCrypto(),  # type: ignore[arg-type]
            )


def test_mac_failure_does_not_invoke_chacha(monkeypatch: pytest.MonkeyPatch) -> None:
    sample = _fixture()["valid_encrypt_decrypt_0"]
    decoded = bytearray(base64.b64decode(sample["payload"]))
    decoded[-1] ^= 1

    def forbid_decrypt(**_kwargs: object) -> None:
        pytest.fail("ChaCha20 must not receive unauthenticated ciphertext")

    monkeypatch.setattr(codec.ChaCha20, "new", forbid_decrypt)
    with pytest.raises(codec.Nip44InvalidPayloadError):
        _decode_with_key(
            base64.b64encode(decoded).decode(), bytes.fromhex(sample["conversation_key"])
        )


@pytest.mark.parametrize(
    ("length", "expected"),
    [
        (1, 32),
        (32, 32),
        (33, 64),
        (256, 256),
        (257, 320),
        (65535, 65536),
        (65536, 65536),
        (65537, 81920),
    ],
)
def test_padding_boundaries_and_extended_length(length: int, expected: int) -> None:
    assert codec._padded_length(length) == expected  # noqa: SLF001 - independent NIP-44 buckets
    prefix = (
        (b"\x00\x00" + length.to_bytes(4, "big"))
        if length >= 65536
        else (length.to_bytes(2, "big"))
    )
    padded = prefix + b"a" * length + bytes(codec._padded_length(length) - length)  # noqa: SLF001
    assert codec._unpad(padded) == "a" * length  # noqa: SLF001
    with pytest.raises(codec.Nip44InvalidPayloadError):
        codec._unpad(padded[:-1])  # noqa: SLF001
    if codec._padded_length(length) > length:  # noqa: SLF001 - has zero suffix to corrupt
        with pytest.raises(codec.Nip44InvalidPayloadError):
            codec._unpad(padded[:-1] + b"\x01")  # noqa: SLF001


def _authenticated_payload(content: bytes, *, conversation_key: bytes, nonce: bytes) -> str:
    keys = codec._message_keys(conversation_key, nonce)  # noqa: SLF001 - synthetic cases only
    prefix = (
        b"\x00\x00" + len(content).to_bytes(4, "big")
        if len(content) >= 65536
        else len(content).to_bytes(2, "big")
    )
    padding = bytes(codec._padded_length(len(content)) - len(content))  # noqa: SLF001
    ciphertext = ChaCha20.new(key=keys[0], nonce=keys[1]).encrypt(prefix + content + padding)
    mac = hmac.digest(keys[2], nonce + ciphertext, "sha256")
    return base64.b64encode(b"\x02" + nonce + ciphertext + mac).decode()


def test_official_extended_payload_hashes_and_utf8_validation() -> None:
    # Published payload hashes in NIP-44's independent extended-prefix table.
    key = bytes.fromhex("c41c775356fd92eadc63ff5a0dc1da211b268cbea22316767095b2871ea1412d")
    nonce = bytes.fromhex("00" * 31 + "01")
    published = (
        (65535, "6d8c2810d1e870fbaa1f0a0937126cca837a15f9260e27060c331d70a3c0bc84"),
        (65536, "b7b4edb36ba92e267d322d56d9aebc22e7fa96ff52e3c12adc07f07a43cbc616"),
        (65537, "eeb7c7c5373894ea2c1547cfd3ccb15d5a0b2d619da852e5c79df792dcc9e435"),
    )
    for length, expected_sha256 in published:
        payload = _authenticated_payload(b"a" * length, conversation_key=key, nonce=nonce)
        assert hashlib.sha256(payload.encode()).hexdigest() == expected_sha256
        assert _decode_with_key(payload, key) == "a" * length
    unicode_text = "recipient 🍕"
    payload = _authenticated_payload(unicode_text.encode(), conversation_key=key, nonce=nonce)
    assert _decode_with_key(payload, key) == unicode_text
    invalid = _authenticated_payload(b"\xff", conversation_key=key, nonce=nonce)
    with pytest.raises(codec.Nip44InvalidPayloadError):
        _decode_with_key(invalid, key)


def test_large_nip44_payload_limited_before_decrypt() -> None:
    sample = _fixture()["valid_encrypt_decrypt_0"]
    with pytest.raises(codec.Nip44InvalidPayloadError):
        codec._decode(sample["payload"] * 1000)  # noqa: SLF001


def test_missing_native_capability_is_distinct_from_invalid_ciphertext() -> None:
    sample = _fixture()["valid_encrypt_decrypt_0"]
    root = b"\x1a" * 32

    class PreviousNative:
        def nip44_shared_x(self, *_args: object) -> bytes:
            raise RuntimeError("library lacks optional NIP-44 ECDH " + root.hex())

    with pytest.raises(codec.Nip44UnavailableError, match="ECDH unavailable") as failure:
        codec._decrypt_payload(  # noqa: SLF001 - internal capability seam
            sample["payload"],
            recipient_secret=root,
            sender_public_key=b"\x02" * 32,
            crypto=PreviousNative(),  # type: ignore[arg-type]
        )
    assert failure.value.__cause__ is None
    assert failure.value.__context__ is None
    traceback = failure.value.__traceback__
    frames = []
    while traceback is not None:
        if traceback.tb_frame.f_code.co_filename == codec.__file__:
            frames.append(traceback.tb_frame)
        traceback = traceback.tb_next
    assert len(frames) == 1
    assert "recipient_secret" not in frames[0].f_locals
    assert root.hex() not in repr(failure.value) + repr(frames[0].f_locals)


@pytest.mark.parametrize(
    "interruption",
    [KeyboardInterrupt, SystemExit, asyncio.CancelledError, GeneratorExit],
)
def test_native_interruption_has_no_secret_decoder_frames(
    interruption: type[BaseException],
) -> None:
    sample = _fixture()["valid_encrypt_decrypt_0"]
    root = b"\x1a" * 32

    class InterruptedNative:
        def nip44_shared_x(self, *_args: object) -> bytes:
            raise interruption("private scalar " + root.hex())

    with pytest.raises(interruption, match="decoding interrupted") as failure:
        codec._decrypt_payload(  # noqa: SLF001 - interrupt hygiene
            sample["payload"],
            recipient_secret=root,
            sender_public_key=b"\x02" * 32,
            crypto=InterruptedNative(),  # type: ignore[arg-type]
        )
    assert failure.value.__context__ is None
    assert failure.value.__cause__ is None
    traceback = failure.value.__traceback__
    frames = []
    while traceback is not None:
        if traceback.tb_frame.f_code.co_filename == codec.__file__:
            frames.append(traceback.tb_frame)
        traceback = traceback.tb_next
    assert len(frames) == 1
    assert root.hex() not in repr(failure.value) + repr(frames[0].f_locals)
    assert "recipient_secret" not in frames[0].f_locals


@pytest.mark.native_crypto
@pytest.mark.skipif(
    not os.environ.get("RILL_CRYPTO_LIBRARY"), reason="requires pinned native library"
)
def test_official_nip44_full_decrypt_with_native_shared_x() -> None:
    from rill_crypto import Context  # noqa: PLC0415 - opt-in native boundary

    sample = _fixture()["valid_encrypt_decrypt_0"]
    with Context(library_path=os.environ["RILL_CRYPTO_LIBRARY"]) as crypto:
        sender_key = crypto.public_key(bytes.fromhex(sample["sec2"]))[1:]
        assert (
            codec._decrypt_payload(  # noqa: SLF001 - internal native interoperability
                sample["payload"],
                recipient_secret=bytes.fromhex(sample["sec1"]),
                sender_public_key=sender_key,
                crypto=crypto,
            )
            == sample["plaintext"]
        )
        shared = crypto.nip44_shared_x(bytes.fromhex(sample["sec1"]), sender_key)
        assert hmac.digest(b"nip44-v2", shared, "sha256").hex() == sample["conversation_key"]


def test_official_nip44_encrypt_vector_and_round_trip_without_native() -> None:
    vector = _fixture()["valid_encrypt_decrypt_0"]
    key = bytes.fromhex(vector["conversation_key"])
    nonce = bytes.fromhex(vector["nonce"])
    payload = codec._encrypt_with_conversation_key(  # noqa: SLF001 - internal vector seam
        vector["plaintext"], key, nonce
    )
    assert payload == vector["payload"]
    for text in ("a", "x" * 32, "y" * 33, "é" * 5000, "z" * 70_000):
        encoded = codec._encrypt_with_conversation_key(text, key, nonce)  # noqa: SLF001
        assert _decode_with_key(encoded, key) == text
    with pytest.raises(codec.Nip44InvalidPayloadError):
        codec._encrypt_with_conversation_key("", key, nonce)  # noqa: SLF001
    with pytest.raises(codec.Nip44InvalidPayloadError):
        codec._encrypt_with_conversation_key("q" * 200_000, key, nonce)  # noqa: SLF001
