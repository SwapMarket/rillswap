"""Signed NIP-01 event verification does not establish NIP-59/app admission."""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
from typing import Any

import pytest

from rill_provider import _nip01_event as nip01

PUBLISHED_RUMOR = {
    "created_at": 1691518405,
    "content": "Are you going to the party tonight?",
    "tags": [],
    "kind": 1,
    "pubkey": "611df01bfcf85c26ae65453b772d8f1dfd25c264621c0277e1fc1518686faef9",
    "id": "9dd003c6d3b73b74a85a9ab099469ce251653a7af76f523671ab828acd2a0ef9",
}


def _event(
    *,
    content: str = "",
    tags: list[list[str]] | None = None,
    kind: int = 1059,
) -> dict[str, Any]:
    item = {
        "pubkey": PUBLISHED_RUMOR["pubkey"],
        "created_at": 1703021488,
        "kind": kind,
        "tags": [] if tags is None else tags,
        "content": content,
        "id": "00" * 32,
        "sig": "00" * 64,
    }
    item["id"] = hashlib.sha256(
        json.dumps(
            [0, item["pubkey"], item["created_at"], kind, item["tags"], content],
            ensure_ascii=False,
            separators=(",", ":"),
        ).encode()
    ).hexdigest()
    return item


def _bytes(item: dict[str, Any], *, sort_keys: bool = False) -> bytes:
    return json.dumps(item, ensure_ascii=False, separators=(",", ":"), sort_keys=sort_keys).encode()


def _recompute_id(item: dict[str, Any]) -> None:
    item["id"] = hashlib.sha256(
        json.dumps(
            [0, item["pubkey"], item["created_at"], item["kind"], item["tags"], item["content"]],
            ensure_ascii=False,
            separators=(",", ":"),
        ).encode()
    ).hexdigest()


def test_nip59_published_rumor_id_is_independent_serialization_control() -> None:
    # NIP-59 published rumor ID, not a self-generated expected hash.
    signed_shape = {**PUBLISHED_RUMOR, "sig": "00" * 64}
    parsed = nip01._parse(_bytes(signed_shape))  # noqa: SLF001 - ID-only control
    assert parsed.id == "9dd003c6d3b73b74a85a9ab099469ce251653a7af76f523671ab828acd2a0ef9"
    assert parsed.sig == "00" * 64  # Parsing an ID does NOT establish a signature.


def test_reordered_json_members_escapes_unicode_and_tag_order_bind_id() -> None:
    item = _event(
        content='line\nquote "\\" / 🍕',
        tags=[["p", "ab"], ["x", "é", "one"]],
    )
    parsed = nip01._parse(_bytes(item, sort_keys=True))  # noqa: SLF001
    assert parsed.tags == (("p", "ab"), ("x", "é", "one"))
    assert parsed.content == item["content"]
    # Equivalent JSON string escapes represent the same parsed strings.
    escaped = _bytes(item).decode().replace("🍕", r"\ud83c\udf55")
    assert nip01._parse(escaped.encode()).id == item["id"]  # noqa: SLF001
    changed = {**item, "tags": list(reversed(item["tags"]))}
    with pytest.raises(nip01.Nip01InvalidEventError):
        nip01._parse(_bytes(changed))  # noqa: SLF001


@pytest.mark.parametrize(
    "mutation",
    [
        "duplicate",
        "extra",
        "missing",
        "bad-id",
        "bad-pubkey",
        "bad-sig",
        "bool-time",
        "float-time",
        "negative-time",
        "too-large-time",
        "bool-kind",
        "float-kind",
        "too-large-kind",
        "object-tags",
        "empty-tag",
        "numeric-tag",
        "long-tag",
        "many-tags",
        "invalid-utf8",
        "lone-surrogate",
        "nested",
    ],
)
def test_malformed_or_noncanonical_event_is_rejected_before_native_crypto(  # noqa: PLR0912 - malformed-field matrix
    mutation: str,
) -> None:
    item = _event()
    if mutation == "duplicate":
        raw = _bytes(item)[:-1] + b',"id":"' + item["id"].encode() + b'"}'
    elif mutation == "invalid-utf8":
        raw = _bytes(item)[:-1] + b"\xff}"
    elif mutation == "lone-surrogate":
        raw = _bytes(item).replace(b'"content":""', b'"content":"\\ud800"')
    else:
        if mutation == "extra":
            item["unexpected"] = "ignored?"
        elif mutation == "missing":
            del item["sig"]
        elif mutation == "bad-id":
            item["id"] = "aa" * 32
        elif mutation == "bad-pubkey":
            item["pubkey"] = "AA" * 32
        elif mutation == "bad-sig":
            item["sig"] = "ff"
        elif mutation in {"bool-time", "float-time", "negative-time", "too-large-time"}:
            item["created_at"] = {
                "bool-time": True,
                "float-time": 3.0,
                "negative-time": -1,
                "too-large-time": 1 << 53,
            }[mutation]
        elif mutation in {"bool-kind", "float-kind", "too-large-kind"}:
            item["kind"] = {"bool-kind": False, "float-kind": 1.0, "too-large-kind": 65536}[
                mutation
            ]
        elif mutation == "object-tags":
            item["tags"] = {}
        elif mutation == "empty-tag":
            item["tags"] = [[]]
        elif mutation == "numeric-tag":
            item["tags"] = [["p", 1]]
        elif mutation == "long-tag":
            item["tags"] = [["p", *(["a"] * 16)]]
        elif mutation == "many-tags":
            item["tags"] = [["p"]] * 257
        else:
            item["tags"] = [[[["p"]]]]
        if mutation not in {"bad-id", "bad-pubkey", "bad-sig", "missing", "extra"}:
            _recompute_id(item)
        raw = _bytes(item)

    class MustNotVerify:
        def schnorr_verify(self, *_args: object) -> None:
            pytest.fail("malformed event must not invoke signature verification")

    with pytest.raises(nip01.Nip01InvalidEventError, match="refused"):
        nip01._verify_signed_event(raw, verifier=MustNotVerify())  # type: ignore[arg-type]  # noqa: SLF001


def test_invalid_event_traceback_does_not_retain_library_raw_input() -> None:
    raw = _bytes({**_event(), "id": "aa" * 32})

    class UnusedVerifier:
        pass

    with pytest.raises(nip01.Nip01InvalidEventError) as failure:
        nip01._verify_signed_event(  # noqa: SLF001 - diagnostic hygiene
            raw,
            verifier=UnusedVerifier(),  # type: ignore[arg-type]
        )
    assert failure.value.__cause__ is None
    assert failure.value.__context__ is None
    frames = []
    traceback = failure.value.__traceback__
    while traceback is not None:
        if traceback.tb_frame.f_code.co_filename == nip01.__file__:
            frames.append(traceback.tb_frame)
        traceback = traceback.tb_next
    assert len(frames) == 1
    assert "raw" not in frames[0].f_locals


def test_transport_size_cap_allows_boundary_without_using_application_parser() -> None:
    item = _event()
    fixed = len(_bytes(item))
    item = _event(content="z" * (nip01.MAX_EVENT_BYTES - fixed))
    raw = _bytes(item)
    assert len(raw) == nip01.MAX_EVENT_BYTES
    parsed = nip01._parse(raw)  # noqa: SLF001 - 128KiB signed-event parser cap
    assert len(parsed.content) > 16 * 1024

    class MustNotVerify:
        def schnorr_verify(self, *_args: object) -> None:
            pytest.fail("oversized event must not invoke cryptography")

    with pytest.raises(nip01.Nip01InvalidEventError):
        nip01._verify_signed_event(raw + b" ", verifier=MustNotVerify())  # type: ignore[arg-type]  # noqa: SLF001


@pytest.mark.parametrize("interruption", [KeyboardInterrupt, SystemExit, asyncio.CancelledError])
def test_signature_verifier_interruption_is_sanitized(interruption: type[BaseException]) -> None:
    item = _event(content="encrypted relay content")

    class Interrupted:
        def schnorr_verify(self, *_args: object) -> None:
            raise interruption("private native trace")

    with pytest.raises(interruption, match="verification interrupted") as failure:
        nip01._verify_signed_event(_bytes(item), verifier=Interrupted())  # type: ignore[arg-type]  # noqa: SLF001
    assert failure.value.__cause__ is None
    assert failure.value.__context__ is None
    frames = []
    traceback = failure.value.__traceback__
    while traceback is not None:
        if traceback.tb_frame.f_code.co_filename == nip01.__file__:
            frames.append(traceback.tb_frame)
        traceback = traceback.tb_next
    assert len(frames) == 1


@pytest.mark.native_crypto
@pytest.mark.skipif(
    not os.environ.get("RILL_CRYPTO_LIBRARY"), reason="requires pinned native library"
)
def test_native_nip01_signature_accepts_only_exact_signed_id() -> None:
    from rill_crypto import Context  # noqa: PLC0415 - opt-in native boundary

    with Context(library_path=os.environ["RILL_CRYPTO_LIBRARY"]) as crypto:
        secret = bytes.fromhex("01" * 32)
        public = crypto.public_key(secret)[1:].hex()
        item = _event(content="signed wrap")
        item["pubkey"] = public
        item["id"] = hashlib.sha256(
            json.dumps(
                [0, public, item["created_at"], item["kind"], item["tags"], item["content"]],
                separators=(",", ":"),
                ensure_ascii=False,
            ).encode()
        ).hexdigest()
        item["sig"] = crypto.schnorr_sign(secret, bytes.fromhex(item["id"]), b"\x00" * 32).hex()
        parsed = nip01._verify_signed_event(_bytes(item), verifier=crypto)  # noqa: SLF001
        assert parsed.id == item["id"]
        assert parsed.pubkey == public
        changed = {**item, "sig": "00" * 64}
        with pytest.raises(nip01.Nip01InvalidEventError):
            nip01._verify_signed_event(_bytes(changed), verifier=crypto)  # noqa: SLF001


def test_absent_verifier_is_distinct_from_invalid_signature() -> None:
    class PreviousBinding:
        pass

    with pytest.raises(nip01.Nip01VerifierUnavailableError) as failure:
        nip01._verify_signed_event(  # noqa: SLF001 - capability test
            _bytes(_event()),
            verifier=PreviousBinding(),  # type: ignore[arg-type]
        )
    assert failure.value.__cause__ is None
    assert failure.value.__context__ is None
