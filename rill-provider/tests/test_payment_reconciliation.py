"""Operator tracking retains witnesses, never infers permission from missing state."""

from __future__ import annotations

import copy
import json
from contextlib import nullcontext
from dataclasses import asdict
from typing import TYPE_CHECKING
from unittest.mock import Mock

import pytest
from rill_core.wire.canonical import canonicalize
from rill_core.wire.messages import Envelope
from test_cli import _config
from test_live_session_store import Harness, PurePublicKeys
from test_payment_dispatch_store import _hash, _insert_funded_swap
from test_quote_policy import FIRM

from rill_provider import cli
from rill_provider import live_session_store as live
from rill_provider.lnd_payment_observation import LndUnavailableError
from rill_provider.lnd_payment_send import PaymentOutcome
from rill_provider.payment_reconciliation import reconcile_payment

if TYPE_CHECKING:
    from pathlib import Path

PREIMAGE = "42" * 32


@pytest.fixture
def harness(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Harness:
    result = Harness(tmp_path, monkeypatch)
    result.provision()
    return result


def _paying(store: live.LiveSessionStore, harness: Harness, dispatch: str | None) -> str:
    session = _insert_funded_swap(store, harness, "FUNDING_SEEN")
    request = copy.deepcopy(harness.envelopes[2])
    request.update(message_type="quote_request", sequence=2, payload=FIRM | {"extensions": {}})
    # Database-boundary fixture, preserving the real retained envelope and grant paths.
    store._connection.execute(  # noqa: SLF001
        "INSERT INTO inbox VALUES (?, ?, ?, ?, ?, ?, ?)",
        (
            session,
            request["sender_session_key"],
            request["message_id"],
            2,
            "00" * 32,
            canonicalize(request),
            0,
        ),
    )
    store.advance_swap(
        session, from_state="FUNDING_SEEN", to_state="PAYING", signer=Mock(), now=1001
    )
    if dispatch is None:
        store._connection.execute("DELETE FROM payment_dispatch")  # noqa: SLF001
    elif dispatch == "SUBMITTED":
        assert store.commit_payment_dispatch(session, _hash(harness), b"private committed route")
    assert store.settlement_work(session_id=session)[0].payment_dispatch == (dispatch or "UNKNOWN")
    return session


class Signer:
    def __init__(self, harness: Harness) -> None:
        self.harness = harness

    def schnorr_sign(self, scalar: bytes, digest: bytes, _aux: bytes) -> bytes:
        signature = bytes([119]) * 64
        key = PurePublicKeys().public_key(scalar)[1:]
        self.harness.crypto.permitted.add((key, digest, signature))
        return signature


def _tracker(outcome: PaymentOutcome) -> Mock:
    tracker = Mock(spec=["track"])
    tracker.track.return_value = outcome
    return tracker


def _financial_rows(store: live.LiveSessionStore) -> list:
    return [
        store._connection.execute(f"SELECT * FROM {table}").fetchall()  # noqa: SLF001, S608
        for table in ("swaps", "sessions", "payment_dispatch", "outbox", "payment_hashes")
    ]


@pytest.mark.parametrize("configured", [False, True])
def test_cli_refuses_missing_backend_or_store_ownership_before_network_construction(
    harness: Harness,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    *,
    configured: bool,
) -> None:
    settings = (
        {"lnd": {"port": 10009, "tls_certificate": "tls.cert", "macaroon": "read.macaroon"}}
        if configured
        else {}
    )
    config = _config(tmp_path, harness.custody, **settings)
    monkeypatch.setattr(cli, "_context", lambda _library: nullcontext(Signer(harness)))
    acquisition = Mock(side_effect=live.LiveSessionStoreError("store already owned"))
    constructor = Mock(side_effect=AssertionError("no network backend may be constructed"))
    monkeypatch.setattr(live.LiveSessionStore, "acquire", acquisition)
    monkeypatch.setattr(cli, "RegtestLndPaymentSender", constructor)
    assert (
        cli.main(["reconcile-payment", "--config", str(config), "--session-id", "00" * 32])
        == cli.REFUSED
    )
    constructor.assert_not_called()
    assert acquisition.call_count == int(configured)
    output = capsys.readouterr()
    assert not output.out
    assert output.err.startswith("rill-provider: ")


@pytest.mark.parametrize("status", ["SUCCEEDED", "FAILED", "UNKNOWN"])
def test_cli_uses_read_credentials_only_and_reports_no_secrets(
    harness: Harness,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    status: str,
) -> None:
    config = _config(
        tmp_path,
        harness.custody,
        lnd={
            "port": 10009,
            "tls_certificate": "tls.cert",
            "macaroon": "read.macaroon",
            "payment_macaroon": "never-read.macaroon",
        },
    )
    tracker = _tracker(PaymentOutcome(status, PREIMAGE if status == "SUCCEEDED" else None))
    constructor = Mock(return_value=tracker)
    monkeypatch.setattr(cli, "RegtestLndPaymentSender", constructor)
    monkeypatch.setattr(cli, "_context", lambda _library: nullcontext(Signer(harness)))
    for name in (
        "RegtestCoreTransactionReader",
        "RegtestLndInvoiceDecoder",
        "SettlementEngine",
        "HandshakeService",
        "_serve",
    ):
        monkeypatch.setattr(cli, name, Mock(side_effect=AssertionError("forbidden backend")))
    with harness.acquire() as store:
        session = _paying(store, harness, "SUBMITTED")
        monkeypatch.setattr(
            live.LiveSessionStore, "acquire", lambda *_args, **_kwargs: nullcontext(store)
        )
        assert (
            cli.main(["reconcile-payment", "--config", str(config), "--session-id", session]) == 0
        )
        output = capsys.readouterr()
        assert not output.err
        assert PREIMAGE not in output.out
        assert _hash(harness) not in output.out
        assert json.loads(output.out) == {
            "format": "rillswap/provider-payment-reconciliation/v1",
            "session_id": session,
            "payment_status": status,
            "swap_state": "PAID" if status == "SUCCEEDED" else "PAYING",
            "state_changed": status == "SUCCEEDED",
        }
        assert constructor.call_args.kwargs["macaroon_path"] == tmp_path / "read.macaroon"
        tracker.track.assert_called_once_with(_hash(harness))


@pytest.mark.parametrize(
    "failure",
    [
        LndUnavailableError("LND payment call failed; outcome unknown"),
        ValueError("private endpoint or credential failure"),
    ],
)
def test_cli_backend_failures_are_redacted_and_do_not_mutate_payments(
    harness: Harness,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    failure: Exception,
) -> None:
    config = _config(
        tmp_path,
        harness.custody,
        lnd={
            "port": 10009,
            "tls_certificate": "tls.cert",
            "macaroon": "read.macaroon",
        },
    )
    monkeypatch.setattr(cli, "_context", lambda _library: nullcontext(Signer(harness)))
    tracker = _tracker(PaymentOutcome("UNKNOWN"))
    tracker.track.side_effect = failure
    constructor = Mock(return_value=tracker)
    if isinstance(failure, ValueError):
        constructor.side_effect = failure
    monkeypatch.setattr(cli, "RegtestLndPaymentSender", constructor)
    with harness.acquire() as store:
        session = _paying(store, harness, "SUBMITTED")
        before = _financial_rows(store)
        monkeypatch.setattr(
            live.LiveSessionStore, "acquire", lambda *_args, **_kwargs: nullcontext(store)
        )
        assert (
            cli.main(["reconcile-payment", "--config", str(config), "--session-id", session])
            == cli.REFUSED
        )
        output = capsys.readouterr()
        assert not output.out
        assert output.err.startswith("rill-provider: ")
        assert "private" not in output.err
        assert _financial_rows(store) == before


@pytest.mark.parametrize("dispatch", [None, "UNSENT", "SUBMITTED"])
@pytest.mark.parametrize("status", ["UNKNOWN", "IN_FLIGHT", "FAILED"])
def test_non_witness_outcomes_preserve_all_authority_across_restart(
    harness: Harness, dispatch: str | None, status: str
) -> None:
    tracker = _tracker(PaymentOutcome(status))
    with harness.acquire() as store:
        session = _paying(store, harness, dispatch)
        before = _financial_rows(store)
        result = reconcile_payment(store, tracker, Signer(harness), session_id=session, now=1002)
        assert result.payment_status == status
        assert result.swap_state == "PAYING"
        assert not result.state_changed
        assert _financial_rows(store) == before
    with harness.acquire() as store:
        assert _financial_rows(store) == before
    tracker.track.assert_called_once_with(_hash(harness))


@pytest.mark.parametrize(
    "outcome",
    [
        PaymentOutcome("SUCCEEDED"),
        PaymentOutcome("SUCCEEDED", "43" * 32),
        PaymentOutcome("SUCCEEDED", "sensitive invalid preimage"),
        PaymentOutcome("SUCCEEDED", "AB" * 32),
        PaymentOutcome("FAILED", PREIMAGE),
        PaymentOutcome("UNKNOWN", PREIMAGE),
        PaymentOutcome("IN_FLIGHT", PREIMAGE),
        PaymentOutcome("unexpected"),
    ],
)
def test_malformed_outcome_never_changes_state_or_echoes_preimage(
    harness: Harness, outcome: PaymentOutcome
) -> None:
    with harness.acquire() as store:
        session = _paying(store, harness, "SUBMITTED")
        before = _financial_rows(store)
        with pytest.raises(live.LiveSessionStoreError, match="outcome unsupported") as error:
            reconcile_payment(
                store, _tracker(outcome), Signer(harness), session_id=session, now=1002
            )
        assert outcome.preimage is None or outcome.preimage not in str(error.value)
        assert _financial_rows(store) == before


def test_tracking_error_and_signing_failure_preserve_the_transaction(harness: Harness) -> None:
    with harness.acquire() as store:
        session = _paying(store, harness, "SUBMITTED")
        before = _financial_rows(store)
        tracker = _tracker(PaymentOutcome("SUCCEEDED", PREIMAGE))
        tracker.track.side_effect = LndUnavailableError("LND payment call failed; outcome unknown")
        with pytest.raises(LndUnavailableError):
            reconcile_payment(store, tracker, Signer(harness), session_id=session, now=1002)
        assert _financial_rows(store) == before
        tracker.track.side_effect = None
        signer = Mock()
        signer.schnorr_sign.side_effect = ValueError("private signing failure")
        with pytest.raises(live.LiveSessionStoreError, match="swap transition refused"):
            reconcile_payment(store, tracker, signer, session_id=session, now=1002)
        assert _financial_rows(store) == before


def test_stale_transition_does_not_commit_a_second_observation(harness: Harness) -> None:
    with harness.acquire() as store:
        session = _paying(store, harness, "SUBMITTED")
        tracker = _tracker(PaymentOutcome("SUCCEEDED", PREIMAGE))

        def track(_payment_hash: str) -> PaymentOutcome:
            store.advance_swap(
                session, from_state="PAYING", to_state="FAILED", signer=Mock(), now=1002
            )
            return PaymentOutcome("SUCCEEDED", PREIMAGE)

        tracker.track.side_effect = track
        with pytest.raises(live.StaleSwapError):
            reconcile_payment(store, tracker, Signer(harness), session_id=session, now=1003)
        assert not store.pending_outbox()
        assert store._connection.execute("SELECT state, preimage FROM swaps").fetchone() == (  # noqa: SLF001
            "FAILED",
            None,
        )


def test_invalid_retained_terms_are_redacted_before_tracking(harness: Harness) -> None:
    with harness.acquire() as store:
        session = _paying(store, harness, "SUBMITTED")
        store._connection.execute(  # noqa: SLF001
            "UPDATE swaps SET terms_offer=?", (b"private damaged invoice terms",)
        )
        before = _financial_rows(store)
        tracker = _tracker(PaymentOutcome("UNKNOWN"))
        with pytest.raises(live.LiveSessionStoreError, match="terms unavailable") as error:
            reconcile_payment(store, tracker, Signer(harness), session_id=session, now=1002)
        assert "private" not in str(error.value)
        tracker.track.assert_not_called()
        assert _financial_rows(store) == before


@pytest.mark.parametrize("session", ["00" * 32, "private invalid ID"])
def test_nonexistent_or_invalid_session_never_tracks(harness: Harness, session: str) -> None:
    with harness.acquire() as store:
        _paying(store, harness, "SUBMITTED")
        before = _financial_rows(store)
        tracker = _tracker(PaymentOutcome("SUCCEEDED", PREIMAGE))
        with pytest.raises(live.LiveSessionStoreError) as error:
            reconcile_payment(store, tracker, Signer(harness), session_id=session, now=1002)
        assert session not in str(error.value)
        tracker.track.assert_not_called()
        assert _financial_rows(store) == before


@pytest.mark.parametrize("dispatch", [None, "UNSENT", "SUBMITTED"])
@pytest.mark.parametrize("blocked", [False, True])
def test_verified_witness_is_atomic_durable_and_never_creates_dispatch_authority(
    harness: Harness, dispatch: str | None, *, blocked: bool
) -> None:
    tracker = _tracker(PaymentOutcome("SUCCEEDED", PREIMAGE))
    with harness.acquire() as store:
        session = _paying(store, harness, dispatch)
        connection = store._connection  # noqa: SLF001
        connection.execute("UPDATE sessions SET blocked=?", (int(blocked),))
        before_dispatch = connection.execute("SELECT * FROM payment_dispatch").fetchall()
        before_hashes = connection.execute("SELECT * FROM payment_hashes").fetchall()
        result = reconcile_payment(store, tracker, Signer(harness), session_id=session, now=1002)
        assert result.swap_state == "PAID"
        assert result.state_changed
        assert PREIMAGE not in json.dumps(asdict(result))
        assert _hash(harness) not in json.dumps(asdict(result))
        assert connection.execute("SELECT state, preimage FROM swaps").fetchall() == [
            ("PAID", PREIMAGE)
        ]
        (message,) = store.pending_outbox()
        envelope = Envelope.model_validate_json(message.canonical_bytes)
        assert envelope.payload == {"kind": "payment_settled", "payment_preimage": PREIMAGE}
        assert connection.execute("SELECT * FROM payment_dispatch").fetchall() == before_dispatch
        assert connection.execute("SELECT * FROM payment_hashes").fetchall() == before_hashes
        assert not store.commit_payment_dispatch(session, _hash(harness), b"forbidden retry")
    with harness.acquire() as store:
        assert store.settlement_work(session_id=session)[0].preimage == PREIMAGE
        assert store.pending_outbox() == (message,)
        with pytest.raises(live.LiveSessionStoreError, match="PAYING"):
            reconcile_payment(store, tracker, Signer(harness), session_id=session, now=1003)
    tracker.track.assert_called_once_with(_hash(harness))
