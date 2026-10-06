"""A narrow sync refusal applies only before bound invoice submission."""

from __future__ import annotations

from contextlib import contextmanager
from typing import TYPE_CHECKING

import pytest
from test_lnd_bound_invoice import _bound
from test_lnd_bound_settlement import PREIMAGE, _settler

from rill_provider import lnd_hold_invoice as hold
from rill_provider._lnd_proto import lightning_pb2
from rill_provider.lnd_payment_observation import LndNotSyncedError

if TYPE_CHECKING:
    from collections.abc import Callable, Iterator
    from pathlib import Path

# ruff: noqa: SLF001 - the trusted adapter's deliberately private no-dispatch signal


@pytest.mark.parametrize("position", [0, 2])
def test_bound_sync_refusal_at_either_info_precedes_every_settlement_dispatch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, position: int
) -> None:
    case = _settler(tmp_path, monkeypatch)
    info = case.responses[position]
    assert isinstance(info, lightning_pb2.GetInfoResponse)
    info.synced_to_chain = False
    with pytest.raises(hold._BoundInvoiceSyncBeforeSubmissionError):
        case.client.settle_bound_invoice(case.expected, PREIMAGE)
    assert len(case.channel.calls) == position + 1
    assert all(method != hold.SETTLE_METHOD for method, _ in case.channel.calls)
    assert case.channel.closed


@pytest.mark.parametrize("position", [0, 2])
@pytest.mark.parametrize("observer", ["observe_bound_invoice", "observe_bound_settled_invoice"])
def test_ordinary_invoice_observation_never_emits_the_bound_submission_signal(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, position: int, observer: str
) -> None:
    case = _bound(tmp_path, monkeypatch)
    info = case.responses[position]
    assert isinstance(info, lightning_pb2.GetInfoResponse)
    info.synced_to_chain = False
    with pytest.raises(LndNotSyncedError) as caught:
        getattr(case.client, observer)(case.expected)
    assert type(caught.value) is LndNotSyncedError
    assert len(case.channel.calls) == position + 1
    assert case.channel.closed


def test_a_sync_exception_after_submission_is_never_translated_into_no_dispatch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    case = _settler(tmp_path, monkeypatch)
    submitted: list[str] = []
    original_factory = case.channel.unary_unary

    def observed_factory(method: str, **kwargs: object) -> Callable[..., object]:
        original_call = original_factory(method, **kwargs)

        def observed_call(*args: object, **call_kwargs: object) -> object:
            if method == hold.SETTLE_METHOD:
                submitted.append(method)
            return original_call(*args, **call_kwargs)

        return observed_call

    monkeypatch.setattr(case.channel, "unary_unary", observed_factory)

    def fail_after_submission() -> None:
        raise LndNotSyncedError("unknown outcome after invocation dispatch")

    case.responses[3] = fail_after_submission
    with pytest.raises(LndNotSyncedError) as caught:
        case.client.settle_bound_invoice(case.expected, PREIMAGE)
    assert type(caught.value) is LndNotSyncedError
    # The fixture records successful RPCs only, so count entry into its actual
    # settlement callable even when its simulated response raises.
    assert submitted == [hold.SETTLE_METHOD]
    assert case.channel.closed


@pytest.mark.parametrize("failure", ["setup", "context_exit"])
def test_connection_sync_errors_never_inherit_the_observation_only_signal(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, failure: str
) -> None:
    case = _settler(tmp_path, monkeypatch)
    original = hold.LndHoldInvoices._connect

    @contextmanager
    def connection(client: hold.LndHoldInvoices) -> Iterator[object]:
        if failure == "setup":
            raise LndNotSyncedError("connection setup failure")
        with original(client) as calls:
            yield calls
        raise LndNotSyncedError("connection exit failure")

    monkeypatch.setattr(hold.LndHoldInvoices, "_connect", connection)
    with pytest.raises(LndNotSyncedError) as caught:
        case.client.settle_bound_invoice(case.expected, PREIMAGE)
    assert type(caught.value) is LndNotSyncedError
    assert [method for method, _ in case.channel.calls].count(hold.SETTLE_METHOD) == (
        0 if failure == "setup" else 1
    )
