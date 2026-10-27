"""Exact deployed formats upgrade losslessly, never by discarding retained evidence."""

from __future__ import annotations

import shutil
import sqlite3
from typing import TYPE_CHECKING

import pytest
from pyrage import x25519
from test_claim_escalation import _claiming
from test_live_session_store import Harness, without_v12_cooperation, without_v15_evm_swaps

from rill_provider import live_session_store as live

if TYPE_CHECKING:
    from pathlib import Path

# Verbatim deployed table definitions from da3df28 and d92c758^ respectively.
# These independent fixtures must not be generated from the normalizer's constants.
HASH_ONLY_EVM = (
    "CREATE TABLE evm_swaps (session_id TEXT PRIMARY KEY NOT NULL, "
    "lock_tx_hash TEXT, lock_log_index INTEGER CHECK (lock_log_index >= 0), "
    "lock_block INTEGER CHECK (lock_block >= 0), provider_tx_hash TEXT, "
    "claim_tx_hash TEXT, refund_tx_hash TEXT, "
    "CHECK ((lock_tx_hash IS NULL) = (lock_log_index IS NULL) AND "
    "(lock_tx_hash IS NULL) = (lock_block IS NULL)))"
)
HEIGHT_ONLY_SWAPS = (
    "CREATE TABLE swaps (session_id TEXT PRIMARY KEY, contract_hash TEXT NOT NULL UNIQUE, "
    "terms_offer BLOB NOT NULL, terms_accept BLOB NOT NULL, state TEXT NOT NULL CHECK "
    "(state IN ('ACCEPTED', 'FUNDING_SEEN', 'PAYING', 'PAID', 'FAILED', 'CLAIMING', "
    "'CLAIMED', 'LOST')), funding_binding BLOB, preimage TEXT, claim_txid TEXT, claim_tx BLOB, "
    "updated_at INTEGER NOT NULL, outpoint_spent_height INTEGER "
    "CHECK (outpoint_spent_height > 0))"
)
HISTORICAL_SWAP_COLUMNS = (
    "session_id,contract_hash,terms_offer,terms_accept,state,funding_binding,preimage,"
    "claim_txid,claim_tx,updated_at,outpoint_spent_height"
)


@pytest.fixture
def harness(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Harness:
    result = Harness(tmp_path, monkeypatch)
    result.provision()
    return result


def _historical(path: Path, variant: str) -> None:
    with sqlite3.connect(path) as connection:
        version = 15
        if variant == "v14":
            without_v15_evm_swaps(connection)
            version = 14
        elif variant == "hash-only":
            connection.execute("DROP TABLE evm_swaps")
            connection.execute(HASH_ONLY_EVM)
            connection.execute(
                "INSERT INTO evm_swaps VALUES ('retained-lock',?,3,100,NULL,NULL,NULL)",
                ("ab" * 32,),
            )
        elif variant == "height-only":
            without_v12_cooperation(connection)
            connection.execute("ALTER TABLE swaps RENAME TO temporary_swaps")
            connection.execute(HEIGHT_ONLY_SWAPS)
            connection.execute(
                f"INSERT INTO swaps ({HISTORICAL_SWAP_COLUMNS}) "  # noqa: S608 - fixed columns
                f"SELECT {HISTORICAL_SWAP_COLUMNS} FROM temporary_swaps"
            )
            connection.execute("DROP TABLE temporary_swaps")
            version = 10
        connection.execute("UPDATE meta SET schema_version=?", (version,))
        connection.execute(f"PRAGMA user_version={version}")


def _snapshot(path: Path) -> tuple[str, ...]:
    with sqlite3.connect(path) as connection:
        version = connection.execute("PRAGMA user_version").fetchone()[0]
        return (f"PRAGMA user_version={version}", *connection.iterdump())


@pytest.mark.parametrize("variant", ["v14", "v15", "hash-only", "height-only"])
def test_populated_historical_store_preserves_claim_and_reservation_across_restarts(
    harness: Harness, variant: str
) -> None:
    with harness.acquire() as store:
        session = _claiming(store, harness)
    _historical(harness.path, variant)
    with sqlite3.connect(harness.path) as connection:
        original = connection.execute(
            f"SELECT {HISTORICAL_SWAP_COLUMNS} FROM swaps WHERE session_id=?",  # noqa: S608
            (session,),
        ).fetchone()
        reservations = connection.execute("SELECT * FROM economic_reservations").fetchall()
        outbox = connection.execute("SELECT * FROM outbox").fetchall()
    for _ in range(2):
        with harness.acquire() as store:
            connection = store._connection  # noqa: SLF001 - durable acquisition acceptance
            assert connection.execute("PRAGMA user_version").fetchone() == (16,)
            assert connection.execute("SELECT schema_version FROM meta").fetchone() == (16,)
            assert (
                connection.execute(
                    f"SELECT {HISTORICAL_SWAP_COLUMNS} FROM swaps WHERE session_id=?",  # noqa: S608
                    (session,),
                ).fetchone()
                == original
            )
            assert (
                connection.execute("SELECT * FROM economic_reservations").fetchall() == reservations
            )
            assert connection.execute("SELECT * FROM outbox").fetchall() == outbox
            assert not store.commit_payment_dispatch(
                session,
                harness.source["contract_terms"]["invoice_binding"]["payment_hash"],
                b"request",
            )
            if variant == "hash-only":
                assert connection.execute("SELECT * FROM evm_swaps").fetchall() == [
                    ("retained-lock", "ab" * 32, 3, 100, None, None, None, None, None, None)
                ]


@pytest.mark.parametrize("variant", ["hash-only", "height-only"])
@pytest.mark.parametrize("phase", ["normalization", "markers"])
def test_interrupted_normalization_rolls_back_schema_rows_and_both_markers(
    harness: Harness, monkeypatch: pytest.MonkeyPatch, variant: str, phase: str
) -> None:
    with harness.acquire() as store:
        _claiming(store, harness)
    _historical(harness.path, variant)
    before = _snapshot(harness.path)
    normalize = live._normalize_historical_schema  # noqa: SLF001 - interrupt after real conversion

    def interrupt(connection: sqlite3.Connection, recognized: str) -> None:
        normalize(connection, recognized)  # type: ignore[arg-type]
        raise OSError("injected interruption")

    def interrupt_after_markers(connection: sqlite3.Connection) -> int:
        assert connection.execute("PRAGMA user_version").fetchone() == (16,)
        assert connection.execute("SELECT schema_version FROM meta").fetchone() == (16,)
        raise OSError("interrupted after version markers")

    with monkeypatch.context() as patch:
        if phase == "normalization":
            patch.setattr(live, "_normalize_historical_schema", interrupt)
        else:
            patch.setattr(live, "_epoch_watermark", interrupt_after_markers)
        with pytest.raises(live.LiveSessionStoreError, match="store unavailable"):
            harness.acquire()
    assert _snapshot(harness.path) == before
    with harness.acquire():
        pass


@pytest.mark.parametrize("column", ["provider_tx_hash", "claim_tx_hash", "refund_tx_hash"])
def test_each_unrepresentable_historical_hash_refuses_unchanged(
    harness: Harness, column: str
) -> None:
    _historical(harness.path, "hash-only")
    with sqlite3.connect(harness.path) as connection:
        connection.execute(f"UPDATE evm_swaps SET {column}=?", ("cd" * 32,))  # noqa: S608
    before = _snapshot(harness.path)
    with pytest.raises(live.LiveSessionStoreError, match="transaction-hash evidence"):
        harness.acquire()
    assert _snapshot(harness.path) == before


def test_retained_spent_height_refuses_unchanged(harness: Harness) -> None:
    with harness.acquire() as store:
        _claiming(store, harness)
    _historical(harness.path, "height-only")
    with sqlite3.connect(harness.path) as connection:
        connection.execute("UPDATE swaps SET outpoint_spent_height=100")
    before = _snapshot(harness.path)
    with pytest.raises(live.LiveSessionStoreError, match="spent-height evidence"):
        harness.acquire()
    assert _snapshot(harness.path) == before


def test_canonical_v15_preserves_all_evm_transaction_bytes(harness: Harness) -> None:
    with sqlite3.connect(harness.path) as connection:
        connection.execute(
            "INSERT INTO evm_swaps VALUES ('funded',?,2,100,?,?,?,?,?,?)",
            ("aa" * 32, "bb" * 32, b"funding", "cc" * 32, b"claim", "dd" * 32, b"refund"),
        )
        original = connection.execute("SELECT * FROM evm_swaps").fetchall()
    _historical(harness.path, "v15")
    with harness.acquire() as store:
        assert store._connection.execute("SELECT * FROM evm_swaps").fetchall() == original  # noqa: SLF001


@pytest.mark.parametrize("variant", ["v14", "hash-only", "height-only"])
@pytest.mark.parametrize("fault", ["custody", "copied-file"])
def test_historical_normalization_requires_original_files_and_custody(
    harness: Harness, variant: str, fault: str
) -> None:
    _historical(harness.path, variant)
    path = harness.path
    if fault == "copied-file":
        path = harness.path.with_name("copied.sqlite")
        shutil.copyfile(harness.path, path)
        shutil.copyfile(str(harness.path) + live.LOCK_SUFFIX, str(path) + live.LOCK_SUFFIX)
    before = _snapshot(path)
    changed = {"custody_identity": str(x25519.Identity.generate())} if fault == "custody" else {}
    with pytest.raises(live.LiveSessionStoreError, match=r"custody identity|authoritative copy"):
        harness.acquire_at(path, **changed)
    assert _snapshot(path) == before


@pytest.mark.parametrize("fault", ["extra-object", "changed-constraint", "markers"])
def test_near_match_is_not_a_historical_upgrade_marker(harness: Harness, fault: str) -> None:
    _historical(harness.path, "hash-only")
    with sqlite3.connect(harness.path) as connection:
        if fault == "extra-object":
            connection.execute("CREATE TABLE unrecognized (id INTEGER)")
        elif fault == "changed-constraint":
            connection.execute("DROP TABLE evm_swaps")
            connection.execute(HASH_ONLY_EVM.replace("lock_block >= 0", "lock_block >= -1"))
        else:
            connection.execute("UPDATE meta SET schema_version=14")
    before = _snapshot(harness.path)
    with pytest.raises(
        live.LiveSessionStoreError, match=r"schema incompatible|namespace or policy"
    ):
        harness.acquire()
    assert _snapshot(harness.path) == before
