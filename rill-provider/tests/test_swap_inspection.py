"""Offline operator inspection must be bounded, secret-free, and non-authorizing."""

from __future__ import annotations

import json
import os
import sqlite3
from dataclasses import asdict
from typing import TYPE_CHECKING

import pytest
from test_cli import _config
from test_live_session_store import Harness
from test_payment_dispatch_store import _hash, _insert_funded_swap

from rill_provider import cli
from rill_provider import live_session_store as live

if TYPE_CHECKING:
    from pathlib import Path


@pytest.fixture
def harness(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Harness:
    result = Harness(tmp_path, monkeypatch)
    result.provision()
    return result


@pytest.mark.parametrize("dispatch", [None, "UNSENT", "SUBMITTED"])
def test_inspection_never_exposes_secrets_or_changes_financial_state(
    harness: Harness, dispatch: str | None
) -> None:
    secret = "private invoice, preimage, or dispatch route"  # noqa: S105 - disclosure sentinel
    with harness.acquire() as store:
        session = _insert_funded_swap(store, harness, "PAYING")
        connection = store._connection  # noqa: SLF001
        connection.execute(
            "UPDATE swaps SET preimage=?, claim_tx=?, claim_txid=? WHERE session_id=?",
            (secret, secret.encode(), "ab" * 32, session),
        )
        if dispatch is not None:
            connection.execute(
                "INSERT INTO payment_dispatch VALUES (?, ?, ?, ?)",
                (session, _hash(harness), dispatch, secret.encode()),
            )
        before = [
            connection.execute(f"SELECT * FROM {table}").fetchall()  # noqa: S608
            for table in ("swaps", "sessions", "payment_dispatch")
        ]
        page = store.inspect_swaps(session_id=session)
        assert page.next_after is None
        (item,) = page.swaps
        assert item.session_id == session
        assert item.session_present
        assert item.blocked is False
        assert item.dispatch_state == (dispatch or "UNKNOWN")
        assert item.dispatch_recorded == (dispatch is not None)
        assert item.preimage_recorded
        assert item.claim_recorded
        assert item.funding_binding_recorded
        assert item.claim_txid == "ab" * 32
        assert secret not in json.dumps(asdict(page))
        assert [
            connection.execute(f"SELECT * FROM {table}").fetchall()  # noqa: S608
            for table in ("swaps", "sessions", "payment_dispatch")
        ] == before


def test_pagination_is_stable_and_does_not_hide_missing_session_rows(harness: Harness) -> None:
    with harness.acquire() as store:
        session = _insert_funded_swap(store, harness, "PAYING")
        connection = store._connection  # noqa: SLF001
        expected = [session]
        for index in range(1, 6):
            sid = f"{index:064x}"
            expected.append(sid)
            connection.execute(
                "INSERT INTO swaps SELECT ?, ?, terms_offer, terms_accept, state, "
                "funding_binding, preimage, claim_txid, claim_tx, updated_at, NULL "
                "FROM swaps WHERE session_id=?",
                (sid, f"{index + 100:064x}", session),
            )
        after = None
        found = []
        for _ in range(3):
            page = store.inspect_swaps(after=after, limit=2)
            assert len(page.swaps) == 2
            found.extend(item.session_id for item in page.swaps)
            after = page.next_after
        assert after is None
        assert found == sorted(expected)
        (missing_session,) = store.inspect_swaps(session_id=f"{1:064x}").swaps
        assert not missing_session.session_present
        assert missing_session.blocked is None
        assert missing_session.dispatch_state == "UNKNOWN"
        assert store.inspect_swaps(after=max(expected)).swaps == ()
        assert store.inspect_swaps(session_id="ff" * 32).swaps == ()


@pytest.mark.parametrize(
    "bounds",
    [
        {"limit": 0},
        {"limit": 1001},
        {"limit": True},
        {"after": "secret input"},
        {"session_id": "secret input"},
        {"session_id": "aa" * 32, "after": "bb" * 32},
    ],
)
def test_invalid_inspection_bounds_are_refused_without_echoing_input(
    harness: Harness, bounds: dict
) -> None:
    with harness.acquire() as store, pytest.raises(live.LiveSessionStoreError) as error:
        store.inspect_swaps(**bounds)
    assert str(error.value) == "swap inspection bounds unsupported"


def test_corrupted_output_identifiers_fail_closed_without_disclosure(harness: Harness) -> None:
    with harness.acquire() as store:
        _insert_funded_swap(store, harness, "PAYING")
        store._connection.execute("UPDATE swaps SET claim_txid='private material'")  # noqa: SLF001
        with pytest.raises(live.LiveSessionStoreError, match="state unsupported") as error:
            store.inspect_swaps()
        assert "private material" not in str(error.value)


@pytest.mark.native_crypto
@pytest.mark.skipif(
    os.environ.get("RILLSWAP_RUN_NATIVE_CRYPTO") != "1",
    reason="set RILLSWAP_RUN_NATIVE_CRYPTO=1 with pinned native library",
)
def test_offline_cli_never_starts_backends_or_exposes_sensitive_payloads(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    config = _config(tmp_path)
    assert cli.main(["provision-store", "--config", str(config)]) == 0
    database = tmp_path / "store/live.sqlite"
    secret = "do not expose retained financial payloads"  # noqa: S105 - disclosure sentinel
    with sqlite3.connect(database) as connection:
        connection.execute(
            "INSERT INTO swaps VALUES (?, ?, ?, ?, 'PAYING', NULL, ?, NULL, NULL, 1, NULL)",
            ("11" * 32, "22" * 32, secret.encode(), secret.encode(), secret),
        )

    def forbidden(*_args: object, **_kwargs: object) -> None:
        pytest.fail("inspection must not load signing identity or construct network backends")

    for name in ("_serve", "_settlement", "_chain_tip", "_invoice_decoder"):
        monkeypatch.setattr(cli, name, forbidden)
    monkeypatch.setattr(cli.ProviderIdentity, "load", forbidden)
    assert cli.main(["inspect-swaps", "--config", str(config), "--limit", "1"]) == 0
    output = capsys.readouterr()
    assert secret not in output.out + output.err
    report = json.loads(output.out)
    assert report["action_authority"] == "none"
    assert report["format"] == "rillswap/provider-swap-inspection/v1"
    assert report["next_after"] is None
    assert report["swaps"][0]["dispatch_state"] == "UNKNOWN"
    assert report["swaps"][0]["session_present"] is False
    assert report["swaps"][0]["preimage_recorded"] is True
    assert cli.main(["inspect-swaps", "--config", str(config), "--limit", "0"]) == cli.REFUSED
    capsys.readouterr()
    with sqlite3.connect(database) as connection:
        connection.execute("PRAGMA user_version=6")
    assert cli.main(["inspect-swaps", "--config", str(config)]) == cli.REFUSED
    with sqlite3.connect(database) as connection:
        assert connection.execute("PRAGMA user_version").fetchone() == (6,)
