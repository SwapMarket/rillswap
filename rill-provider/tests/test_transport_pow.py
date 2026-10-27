"""RS-006 transport proof of work (NIP-13) on provider-bound gift wraps."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from rill_provider import _nip01_event as nip01
from rill_provider import _transport_pow as transport_pow

PUBKEY = "11" * 32
RECIPIENT = "22" * 32
CONTENT = "QUJD" * 500  # base64-shaped, like a NIP-44 payload
VECTOR = Path(__file__).parents[2] / "rill-docs/vectors/wire/nostr-transport-pow-v1.json"


def _event(tags: list[list[str]], *, kind: int = 1059, created_at: int = 1_700_000_000) -> bytes:
    """An outer event with a correct ID; the signature is never checked here."""
    event_id = nip01._event_id(PUBKEY, created_at, kind, tags, CONTENT)  # noqa: SLF001
    document = {
        "id": event_id,
        "pubkey": PUBKEY,
        "created_at": created_at,
        "kind": kind,
        "tags": tags,
        "content": CONTENT,
        "sig": "33" * 64,
    }
    return json.dumps(document, separators=(",", ":")).encode()


def test_leading_zero_bits_counts_from_the_most_significant_bit() -> None:
    assert transport_pow.leading_zero_bits("ff" * 32) == 0
    assert transport_pow.leading_zero_bits("0000f" + "0" * 59) == 16
    assert transport_pow.leading_zero_bits("001" + "0" * 61) == 11
    assert transport_pow.leading_zero_bits("00" * 32) == 256


def test_mined_tags_keep_the_fields_and_prove_exactly_the_committed_target() -> None:
    tags = transport_pow.mine(PUBKEY, 1_700_000_000, 1059, [["p", RECIPIENT]], CONTENT, bits=12)
    assert tags[0] == ["p", RECIPIENT]
    assert tags[1][0] == "nonce"
    assert tags[1][2] == "12"
    assert transport_pow.outer_work(_event(tags)) == (RECIPIENT, 12)


def test_work_is_capped_by_the_committed_target_and_needs_one_nonce_tag() -> None:
    tags = transport_pow.mine(PUBKEY, 1_700_000_000, 1059, [["p", RECIPIENT]], CONTENT, bits=12)
    event_id = nip01._event_id(PUBKEY, 1_700_000_000, 1059, tags, CONTENT)  # noqa: SLF001
    counter = tags[1][1]
    assert transport_pow.committed_work(event_id, [["p", RECIPIENT], ["nonce", counter, "8"]]) <= 8
    for nonces in (
        [],
        [["nonce", counter]],
        [["nonce", counter, "12"], ["nonce", counter, "12"]],
        [["nonce", counter, "012"]],
        [["nonce", counter, "twelve"]],
        [["nonce", counter, "12", "extra"]],
    ):
        assert transport_pow.committed_work(event_id, [["p", RECIPIENT], *nonces]) == 0


def test_outer_work_recomputes_the_id_and_refuses_non_wraps() -> None:
    tags = transport_pow.mine(PUBKEY, 1_700_000_000, 1059, [["p", RECIPIENT]], CONTENT, bits=10)
    forged = json.loads(_event([["p", RECIPIENT], ["nonce", "0", "10"]]))
    forged["id"] = "00" * 32  # a claimed ID proves nothing
    assert transport_pow.outer_work(json.dumps(forged).encode()) is None
    assert transport_pow.outer_work(_event(tags, kind=1)) is None
    assert transport_pow.outer_work(_event([tags[1]])) is None  # no recipient
    assert transport_pow.outer_work(_event([["p", RECIPIENT], ["p", PUBKEY], tags[1]])) is None
    assert transport_pow.outer_work(b"not json") is None
    assert transport_pow.outer_work(_event([["p", RECIPIENT]])) == (RECIPIENT, 0)


def test_mining_refuses_targets_outside_the_supported_range() -> None:
    for bits in (0, -1, transport_pow.MAX_WORK_BITS + 1, True):
        with pytest.raises(transport_pow.TransportWorkError):
            transport_pow.mine(PUBKEY, 1, 1059, [["p", RECIPIENT]], CONTENT, bits=bits)


def test_shared_vector_agrees_with_the_docs_reference() -> None:
    vector = json.loads(VECTOR.read_text())
    required = vector["required_bits"]
    assert transport_pow.requirement(vector["announcement_extensions"]) == required
    assert transport_pow.requirement(vector["init_extensions"]) == required
    for case in vector["cases"]:
        found = transport_pow.outer_work(json.dumps(case["event"]).encode())
        proven = case["proven_work"]
        assert found == (None if proven is None else (vector["recipient_xonly_key"], proven))
        assert (found is not None and found[1] >= required) == case["accepted"], case["name"]


def test_requirement_is_absent_or_exactly_bits_in_range() -> None:
    key = transport_pow.TRANSPORT_POW_EXTENSION
    assert transport_pow.requirement({}) is None
    assert transport_pow.requirement({"other/key": 1}) is None
    assert transport_pow.requirement({key: {"bits": 16}}) == 16
    assert transport_pow.requirement({key: {"bits": transport_pow.MAX_WORK_BITS}}) == 20
    for value in (
        {"bits": 0},
        {"bits": transport_pow.MAX_WORK_BITS + 1},
        {"bits": "16"},
        {"bits": True},
        {"bits": 16, "extra": 1},
        {},
        16,
        None,
    ):
        with pytest.raises(transport_pow.TransportWorkError):
            transport_pow.requirement({key: value})
