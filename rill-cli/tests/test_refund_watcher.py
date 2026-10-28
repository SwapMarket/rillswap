"""The refund watcher escalates fees, records before sending, and never steals."""

from __future__ import annotations

from dataclasses import dataclass, field
from itertools import pairwise
from types import SimpleNamespace
from typing import TYPE_CHECKING

import pytest

from rill_cli import refund_watcher
from rill_cli.refund_watcher import (
    MAX_ATTEMPTS,
    ChainView,
    RefundAttempt,
    RefundWatcher,
    RefundWatchError,
    load_attempts,
    refund_fee_target,
)

if TYPE_CHECKING:
    from pathlib import Path

VSIZE = 120
LOCK = 1_000


def _attempt(n: int, fee: int, height: int | None = None) -> RefundAttempt:
    return RefundAttempt(n, f"{n:064x}", b"raw%d" % n, fee, VSIZE, height)


def _target(latest: RefundAttempt | None, tip: int) -> int | None:
    return refund_fee_target(
        initial=500,
        maximum=5_000,
        start_height=LOCK + 1,
        escalate_blocks=10,
        tip=tip,
        latest=latest,
    )


def test_schedule_starts_at_initial_and_reaches_the_maximum_without_stranding() -> None:
    assert _target(None, LOCK + 1) == 500
    latest, fees = _attempt(0, 500, LOCK + 1), []
    for tip in range(LOCK + 2, LOCK + 20):
        fee = _target(latest, tip)
        if fee is not None:
            fees.append(fee)
            latest = _attempt(latest.attempt + 1, fee, tip)
    assert fees[-1] == 5_000  # the last replacement is the signed maximum
    assert all(b - a >= VSIZE for a, b in pairwise(fees))
    assert fees[0] == 500 + 4_500 * 1 // 10


def test_a_bump_waits_for_a_new_block_and_the_relay_increment() -> None:
    assert _target(_attempt(0, 500, LOCK + 5), LOCK + 5) is None
    assert _target(_attempt(0, 4_950, LOCK + 5), LOCK + 30) is None  # cannot beat by vsize
    assert _target(_attempt(MAX_ATTEMPTS - 1, 500, LOCK + 5), LOCK + 30) is None


@dataclass
class _World:
    invoice: str | None = "OPEN"
    view: ChainView | None = field(
        default_factory=lambda: ChainView(LOCK + 1, unspent_on_chain=True)
    )
    depths: dict[str, int] = field(default_factory=dict)
    submitted: list[str] = field(default_factory=list)
    accept: bool = True
    recorded_before_send: list[int] = field(default_factory=list)


def _watcher(
    tmp_path: Path, world: _World, monkeypatch: pytest.MonkeyPatch, *, chain_only: bool = False
) -> RefundWatcher:
    monkeypatch.setattr(
        refund_watcher,
        "validate_unilateral_spend",
        lambda raw, _a, verifier: SimpleNamespace(  # noqa: ARG005
            txid=raw[3:].decode().rjust(64, "0"), fee_sat=int(raw[3:]), vsize=VSIZE
        ),
    )

    def sign(fee: int, _tip: int) -> tuple[bytes, str, int, int]:
        return (b"fee%d" % fee, str(fee).rjust(64, "0"), fee, VSIZE)

    def submit(_raw: bytes, txid: str) -> bool:
        world.recorded_before_send.append(len(list(tmp_path.glob("refund-*.json"))))
        world.submitted.append(txid)
        return world.accept

    return RefundWatcher(
        attempts=[],
        intent_dir=tmp_path,
        funding_txid="51" * 32,
        contract_vout=0,
        refund_lock_height=LOCK,
        initial_fee_sat=500,
        max_fee_sat=5_000,
        escalate_blocks=10,
        chain=lambda: world.view,
        invoice_state=None if chain_only else (lambda: world.invoice),
        sign=sign,
        submit=submit,
        confirmations=world.depths.get,
        authorization=None,  # type: ignore[arg-type]
        verifier=None,  # type: ignore[arg-type]
        poll_seconds=0,
        sleep=lambda _s: None,
    )


def test_a_settled_invoice_is_never_refunded(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    world = _World(invoice="SETTLED")
    outcome = _watcher(tmp_path, world, monkeypatch).run(max_polls=3)
    assert outcome is not None
    assert outcome["outcome"] == "invoice_settled"
    assert world.submitted == []


def test_missing_invoice_or_chain_evidence_only_waits(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    for world in (
        _World(invoice=None),
        _World(view=None),
        _World(view=ChainView(LOCK, unspent_on_chain=True)),
    ):
        assert _watcher(tmp_path, world, monkeypatch).run(max_polls=2) is None
        assert world.submitted == []


def test_unknown_outpoint_still_detects_our_confirmed_refund(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    world = _World()
    watcher = _watcher(tmp_path, world, monkeypatch)
    watcher.step()
    world.view = None  # Core gettxout null or an unavailable sample
    world.depths[watcher.attempts[0].txid] = 2
    outcome = watcher.step()
    assert outcome is not None
    assert (outcome["outcome"], outcome["confirmations"]) == ("refund_confirmed", 2)


def test_each_attempt_is_recorded_before_its_send_and_reloads(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    world = _World()
    watcher = _watcher(tmp_path, world, monkeypatch)
    assert watcher.step() is None
    world.view = ChainView(LOCK + 4, unspent_on_chain=True)
    assert watcher.step() is None
    assert [a.fee_sat for a in watcher.attempts] == [500, 500 + 4_500 * 3 // 10]
    assert world.recorded_before_send == [1, 2]
    reloaded = load_attempts(tmp_path, None, verifier=None)  # type: ignore[arg-type]
    assert reloaded == watcher.attempts
    (tmp_path / "refund-00-x.json").write_bytes(b'{"kind":"other"}')
    with pytest.raises(RefundWatchError):
        load_attempts(tmp_path, None, verifier=None)  # type: ignore[arg-type]


def test_a_spent_output_ends_with_our_confirmed_refund_or_someone_elses_spend(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    world = _World()
    watcher = _watcher(tmp_path, world, monkeypatch)
    watcher.step()
    world.view = ChainView(LOCK + 2, unspent_on_chain=False)
    outcome = watcher.step()
    assert outcome is not None
    assert outcome["outcome"] == "outpoint_spent_elsewhere"
    world.depths[watcher.attempts[0].txid] = 1
    outcome = watcher.step()
    assert outcome is not None
    assert (outcome["outcome"], outcome["confirmations"]) == ("refund_confirmed", 1)


@pytest.mark.parametrize("depth", [0, -1, -6])
def test_an_unconfirmed_or_conflicted_refund_is_not_reported_confirmed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, depth: int
) -> None:
    world = _World()
    watcher = _watcher(tmp_path, world, monkeypatch)
    watcher.step()
    world.view = ChainView(LOCK + 2, unspent_on_chain=False)
    world.depths[watcher.attempts[0].txid] = depth  # Core reports conflicts as negative
    outcome = watcher.step()
    assert outcome is not None
    assert outcome["outcome"] == "outpoint_spent_elsewhere"


def test_rejected_replacement_is_kept_and_rebroadcast(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    world = _World(accept=False)
    watcher = _watcher(tmp_path, world, monkeypatch)
    watcher.step()
    watcher.step()  # same block: no bump, rebroadcast the recorded attempt
    assert len(watcher.attempts) == 1
    assert world.submitted == [watcher.attempts[0].txid] * 2


def test_cli_registers_watch_refund_with_lnd_evidence() -> None:
    from rill_cli.main import _parser  # noqa: PLC0415

    with pytest.raises(SystemExit):  # the invoices:read macaroon is mandatory
        _parser().parse_args(
            ["recover", "watch-refund", "--network", "n", "--crypto-library", "l",
             "--funding-attempt-id", "a", "--binding-revision", "0", "--rpc-cookie", "c",
             "--rpc-port", "1", "--identity", "i", "--intent-dir", "d",
             "--initial-fee-sat", "1", "--max-fee-sat", "2", "f"]
        )  # fmt: skip


def test_chain_only_refunds_past_the_lock_without_any_invoice_evidence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    world = _World(invoice=None, view=ChainView(LOCK, unspent_on_chain=True))
    watcher = _watcher(tmp_path, world, monkeypatch, chain_only=True)
    assert watcher.step() is None  # at the lock height: still the provider's window
    assert world.submitted == []
    world.view = ChainView(LOCK + 1, unspent_on_chain=True)
    assert watcher.step() is None
    assert len(world.submitted) == 1
    world.view = ChainView(LOCK + 2, unspent_on_chain=False)
    world.depths[watcher.attempts[0].txid] = 1
    outcome = watcher.step()
    assert outcome is not None
    assert outcome["outcome"] == "refund_confirmed"
    assert outcome["invoice_check"] == "skipped-chain-only"


def test_chain_only_still_stops_when_the_provider_claimed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    world = _World(view=ChainView(LOCK + 1, unspent_on_chain=False))
    outcome = _watcher(tmp_path, world, monkeypatch, chain_only=True).step()
    assert outcome is not None
    assert outcome["outcome"] == "outpoint_spent_elsewhere"
    assert world.submitted == []


def test_lnd_checked_outcomes_say_so(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    outcome = _watcher(tmp_path, _World(invoice="SETTLED"), monkeypatch).step()
    assert outcome is not None
    assert outcome["invoice_check"] == "lnd"


def test_cli_chain_only_is_explicit_and_excludes_lnd() -> None:
    from rill_cli.main import _parser  # noqa: PLC0415

    base = ["recover", "watch-refund", "--network", "n", "--crypto-library", "l",
            "--funding-attempt-id", "a", "--binding-revision", "0", "--rpc-cookie", "c",
            "--rpc-port", "1", "--identity", "i", "--intent-dir", "d",
            "--initial-fee-sat", "1", "--max-fee-sat", "2"]  # fmt: skip
    args = _parser().parse_args([*base, "--chain-only", "f"])
    assert args.chain_only is True
    assert args.lnd_port is None
    with pytest.raises(SystemExit):
        _parser().parse_args([*base, "--chain-only", "--lnd-port", "1", "f"])
