"""RS-006 transport proof of work: which work each provider recipient requires."""

from __future__ import annotations

import asyncio
import json
from typing import TYPE_CHECKING
from unittest.mock import Mock

import pytest
from rill_core.wire.canonical import canonicalize
from test_cli import _config
from test_live_session_store import Harness
from test_payment_dispatch_store import _insert_funded_swap

from rill_provider import _nip01_event as nip01
from rill_provider import _transport_pow as transport_pow
from rill_provider.handshake_service import HandshakeService, ServicePolicy
from rill_provider.live_session_store import EpochInitiation, LiveSessionStoreError, MailboxWork
from rill_provider.operator_config import OperatorConfigError, load_config

if TYPE_CHECKING:
    from pathlib import Path

EPOCH = "e1" * 32
LEGACY = "a1" * 32  # admitted before any declaration, swap unfinished
FINISHED = "a2" * 32  # admitted before any declaration, swap terminal
DECLARED = "a3" * 32  # init declared 12 bits
UNKNOWN = "a4" * 32
WRAPPER = "11" * 32
CONTENT = "QUJD" * 100
KEY = transport_pow.TRANSPORT_POW_EXTENSION


def _policy(bits: int) -> ServicePolicy:
    return ServicePolicy(
        network=None,  # type: ignore[arg-type]
        profiles=("btc-to-ln/v1",),
        amount_bands=((1000, 2000),),
        base_fee_sat=1,
        proportional_millionths=1,
        slot="s",
        relay_urls=("ws://r/",),
        transport_pow_bits=bits,
    )


def _service(bits: int, mailboxes: tuple[MailboxWork, ...] = ()) -> tuple[HandshakeService, Mock]:
    store = Mock(generation=1)
    store.receiving_epochs.return_value = (EPOCH,)
    store.mailbox_work.return_value = mailboxes
    service = HandshakeService(store, Mock(), Mock(), _policy(bits), clock=lambda: 1000)
    service._filters()  # noqa: SLF001 - the subscription refresh builds the work table
    return service, store


def _wrap(recipient: str, bits: int = 0) -> bytes:
    """A kind-1059 event with a correct ID; nothing here checks its signature."""
    tags = [["p", recipient]]
    if bits:
        tags = transport_pow.mine(WRAPPER, 1_700_000_000, 1059, tags, CONTENT, bits=bits)
    event_id = nip01._event_id(WRAPPER, 1_700_000_000, 1059, tags, CONTENT)  # noqa: SLF001
    document = {
        "id": event_id,
        "pubkey": WRAPPER,
        "created_at": 1_700_000_000,
        "kind": 1059,
        "tags": tags,
        "content": CONTENT,
        "sig": "33" * 64,
    }
    return json.dumps(document, separators=(",", ":")).encode()


def _init(extensions: object) -> bytes:
    return json.dumps({"payload": {"extensions": extensions}}).encode()


MAILBOXES = (
    MailboxWork(LEGACY, None, finished=False),
    MailboxWork(FINISHED, None, finished=True),
    MailboxWork(DECLARED, 12, finished=False),
)


def test_disabled_work_leaves_every_event_unchanged() -> None:
    service, _store = _service(0, (MailboxWork(LEGACY, None, finished=True),))
    assert service._has_work(b"not json")  # noqa: SLF001
    assert service._has_work(_wrap(EPOCH))  # noqa: SLF001
    assert service._has_work(_wrap(LEGACY))  # noqa: SLF001


def test_required_work_applies_per_recipient() -> None:
    service, store = _service(8, MAILBOXES)
    filters = service._filters()  # noqa: SLF001
    assert filters[0]["#p"] == sorted({EPOCH, LEGACY, FINISHED, DECLARED})
    store.session_mailboxes.assert_not_called()  # one query defines the subscribed set
    has_work = service._has_work  # noqa: SLF001
    assert not has_work(_wrap(EPOCH))
    assert not has_work(_wrap(EPOCH, 7))  # the committed target caps a lucky hash
    assert has_work(_wrap(EPOCH, 8))
    assert has_work(_wrap(LEGACY))  # enabling work never strands an unfinished swap
    assert not has_work(_wrap(FINISHED))
    assert has_work(_wrap(FINISHED, 8))
    assert not has_work(_wrap(DECLARED, 8))
    assert has_work(_wrap(DECLARED, 12))
    assert not has_work(_wrap(UNKNOWN))  # e.g. a session admitted since the last refresh
    assert has_work(_wrap(UNKNOWN, 8))
    assert not has_work(b"not json")


def test_lowered_requirement_still_holds_sessions_to_their_declaration() -> None:
    service, _store = _service(0, MAILBOXES)
    has_work = service._has_work  # noqa: SLF001
    assert has_work(_wrap(EPOCH))
    assert has_work(_wrap(LEGACY))
    assert has_work(_wrap(FINISHED))
    assert not has_work(_wrap(DECLARED))
    assert has_work(_wrap(DECLARED, 12))


def test_insufficient_work_is_dropped_before_dedup_and_any_decryption() -> None:
    async def scenario() -> None:
        service, store = _service(8)
        event = _wrap(EPOCH)
        assert await service.handle(event, []) == "insufficient-work"
        assert await service.handle(event, []) == "insufficient-work"  # never marked seen
        store.open_mailbox_frame.assert_not_called()
        store.open_epoch_frame.assert_not_called()

    asyncio.run(scenario())


def test_admission_needs_a_well_formed_declaration_meeting_the_requirement() -> None:
    declares = {
        bits: _service(bits)[0]._declares_work  # noqa: SLF001
        for bits in (0, 8)
    }
    assert declares[0](_init({}))
    assert declares[0](_init({KEY: {"bits": 4}}))
    assert declares[8](_init({KEY: {"bits": 8}}))
    assert declares[8](_init({KEY: {"bits": 12}}))
    assert not declares[8](_init({}))  # an older client cannot promise work
    assert not declares[8](_init({KEY: {"bits": 4}}))
    for malformed in (
        _init({KEY: {"bits": 0}}),
        _init({KEY: {"bits": transport_pow.MAX_WORK_BITS + 1}}),
        _init({KEY: "8"}),
        _init([]),
        b"{}",
        b"not json",
    ):
        for check in declares.values():
            assert not check(malformed)  # refused even while no work is required


def test_epoch_init_without_the_declaration_is_refused_before_reservation() -> None:
    async def scenario(declared: dict[str, object]) -> tuple[str, Mock]:
        service, store = _service(8)
        store.open_mailbox_frame.side_effect = LiveSessionStoreError("not a session mailbox")
        store.open_epoch_frame.return_value = EpochInitiation(_init(declared), EPOCH)
        store.reserve.return_value = Mock(revision=1)
        return await service.handle(_wrap(EPOCH, 8), []), store

    disposition, store = asyncio.run(scenario({}))
    assert disposition == "refused"
    store.reserve.assert_not_called()
    disposition, store = asyncio.run(scenario({KEY: {"bits": 8}}))
    assert disposition == "init-replay"  # reached reservation
    store.reserve.assert_called_once()


def test_store_reports_each_mailbox_with_its_declared_work(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    harness = Harness(tmp_path, monkeypatch)
    harness.provision()
    with harness.acquire() as store:
        store.reserve(harness.initiation)
        assert store.mailbox_work() == ()  # no committed accept: nothing to receive yet
        store.commit_accept(harness.accept)
        key = harness.envelopes[1]["sender_session_key"]
        assert store.mailbox_work() == (MailboxWork(key, None, finished=False),)
        assert store.session_mailboxes() == (key,)
        declared = json.loads(harness.init)
        for extension, bits in (({"bits": 12}, 12), ({"bits": 99}, None), ("12", None)):
            declared["payload"]["extensions"] = {KEY: extension}
            # Database fixture for the read path: an unreadable declaration
            # (only an older store could hold one) never adds a requirement.
            store._connection.execute(  # noqa: SLF001
                "UPDATE sessions SET init_bytes=?", (canonicalize(declared),)
            )
            assert store.mailbox_work() == (MailboxWork(key, bits, finished=False),)


@pytest.mark.parametrize(
    ("state", "finished"),
    [
        ("ACCEPTED", False),
        ("PAYING", False),
        ("CLAIMING", False),
        ("LN_HELD", False),
        ("REFUNDING", False),
        ("FAILED", True),
        ("CLAIMED", True),
        ("LOST", True),
        ("SETTLED", True),
        ("REFUNDED", True),
        ("ABORTED", True),
    ],
)
def test_only_terminal_swaps_count_as_finished(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, state: str, *, finished: bool
) -> None:
    harness = Harness(tmp_path, monkeypatch)
    harness.provision()
    with harness.acquire() as store:
        session_id = _insert_funded_swap(store, harness, state)
        (key,) = store._connection.execute(  # noqa: SLF001
            "SELECT provider_session_key FROM sessions WHERE session_id=?", (session_id,)
        ).fetchone()
        assert store.mailbox_work() == (MailboxWork(key, None, finished=finished),)


def test_operator_config_bounds_the_requirement(tmp_path: Path) -> None:
    assert load_config(_config(tmp_path)).service_policy().transport_pow_bits == 0
    config = load_config(_config(tmp_path, transport_pow_bits=16))
    assert config.service_policy().transport_pow_bits == 16
    for bad in (-1, transport_pow.MAX_WORK_BITS + 1):
        with pytest.raises(OperatorConfigError, match="config refused"):
            load_config(_config(tmp_path, transport_pow_bits=bad))
