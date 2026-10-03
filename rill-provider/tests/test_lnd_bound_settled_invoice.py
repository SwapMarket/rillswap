"""Positive bound SETTLED knowledge never dispatches or grants signing authority."""

from __future__ import annotations

from typing import TYPE_CHECKING
from unittest.mock import Mock

import pytest
from test_lnd_bound_invoice import HASH, _bound

from rill_provider import lnd_hold_invoice as hold
from rill_provider._lnd_proto import lightning_pb2
from rill_provider.lnd_payment_observation import LndProtocolError, LndUnavailableError

if TYPE_CHECKING:
    from pathlib import Path

# ruff: noqa: SLF001 - actual transport setup and credential seams


@pytest.mark.parametrize("state", ["OPEN", "ACCEPTED", "CANCELED", "SETTLED"])
@pytest.mark.parametrize("paid", [-1, 0, 999, 1000, 1001])
def test_sufficient_paid_settled_state_is_required_without_financial_dispatch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    state: str,
    paid: int,
) -> None:
    case = _bound(tmp_path, monkeypatch)
    invoice = case.responses[1]
    invoice.state = getattr(lightning_pb2.Invoice, state)
    invoice.amt_paid_msat = paid
    if state == "SETTLED" and paid >= 1000:
        result = case.client.observe_bound_settled_invoice(case.expected)
        assert result.payment_hash == HASH
        assert result.status.state == "SETTLED"
    else:
        with pytest.raises(LndProtocolError, match="not sufficiently settled"):
            case.client.observe_bound_settled_invoice(case.expected)
    assert [method for method, _ in case.channel.calls] == [
        hold.INFO_METHOD,
        hold.LOOKUP_METHOD,
        hold.INFO_METHOD,
    ]
    assert case.channel.closed


@pytest.mark.parametrize("fault", ["original hash", "final identity"])
def test_new_entry_point_cannot_skip_original_correspondence_or_final_identity(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    fault: str,
) -> None:
    case = _bound(tmp_path, monkeypatch)
    case.responses[1].state = lightning_pb2.Invoice.SETTLED
    case.responses[1].amt_paid_msat = 1000
    if fault == "original hash":
        case.responses[1].r_hash = b"\x01" * 32
    else:
        case.responses[2].identity_pubkey = "03" + "11" * 32
    with pytest.raises(LndProtocolError):
        case.client.observe_bound_settled_invoice(case.expected)
    assert len(case.channel.calls) == (2 if fault == "original hash" else 3)
    assert case.channel.closed


@pytest.mark.parametrize("fault", ["untyped", "due", "predicate"])
def test_strong_observation_refuses_before_credentials(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    fault: str,
) -> None:
    case = _bound(tmp_path, monkeypatch)
    monkeypatch.setattr(hold.time, "monotonic", lambda: 100.0)
    credentials = Mock(side_effect=AssertionError("credential access forbidden"))
    monkeypatch.setattr(hold, "_read_file", credentials)
    with pytest.raises((LndProtocolError, LndUnavailableError)):
        case.client.observe_bound_settled_invoice(
            object() if fault == "untyped" else case.expected,
            deadline=100.0 if fault == "due" else None,
            submission_allowed=(lambda: False) if fault == "predicate" else None,
        )
    credentials.assert_not_called()
    assert case.channel.calls == []


@pytest.mark.parametrize("position", [0, 1, 2])
def test_original_predicate_reaches_every_read_dispatch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    position: int,
) -> None:
    case = _bound(tmp_path, monkeypatch)
    case.responses[1].state = lightning_pb2.Invoice.SETTLED
    case.responses[1].amt_paid_msat = 1000
    enabled = True
    setup_count = 0
    original = case.channel.unary_unary

    def setup(method: str, **kwargs: object) -> object:
        nonlocal enabled, setup_count
        rpc = original(method, **kwargs)
        if setup_count == position:
            enabled = False
        setup_count += 1
        return rpc

    monkeypatch.setattr(case.channel, "unary_unary", setup)
    with pytest.raises(LndUnavailableError):
        case.client.observe_bound_settled_invoice(case.expected, submission_allowed=lambda: enabled)
    assert len(case.channel.calls) == position
    assert case.channel.closed


def test_strong_observation_charges_setup_against_fixed_batch_budget(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    case = _bound(tmp_path, monkeypatch)
    case.responses[1].state = lightning_pb2.Invoice.SETTLED
    case.responses[1].amt_paid_msat = 1000
    clock = {"mono": 100.0}
    monkeypatch.setattr(hold.time, "monotonic", lambda: clock["mono"])
    connect = case.client._connect
    original = case.channel.unary_unary

    def delayed_connect() -> object:
        clock["mono"] += 1.0
        return connect()

    def setup(method: str, **kwargs: object) -> object:
        clock["mono"] += 1.0
        return original(method, **kwargs)

    monkeypatch.setattr(case.client, "_connect", delayed_connect)
    monkeypatch.setattr(case.channel, "unary_unary", setup)
    allowed = Mock(return_value=True)
    case.client.observe_bound_settled_invoice(
        case.expected, deadline=105.0, submission_allowed=allowed
    )
    assert case.budgets == [3.0, 2.0, 1.0]
    assert allowed.call_count == 4


@pytest.mark.parametrize("paid", [999, 1000])
@pytest.mark.parametrize("position", [0, 1, 2])
def test_late_final_positive_or_insufficient_knowledge_is_not_reclassified_by_revocation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    paid: int,
    position: int,
) -> None:
    case = _bound(tmp_path, monkeypatch)
    case.responses[1].state = lightning_pb2.Invoice.SETTLED
    case.responses[1].amt_paid_msat = paid
    clock = {"mono": 100.0}
    enabled = True
    monkeypatch.setattr(hold.time, "monotonic", lambda: clock["mono"])
    original = case.responses[position]

    def late() -> object:
        nonlocal enabled
        enabled = False
        clock["mono"] = 200.0
        return original

    case.responses[position] = late
    if position != 2:
        with pytest.raises(LndUnavailableError):
            case.client.observe_bound_settled_invoice(
                case.expected, deadline=110.0, submission_allowed=lambda: enabled
            )
    elif paid == 1000:
        assert (
            case.client.observe_bound_settled_invoice(
                case.expected, deadline=110.0, submission_allowed=lambda: enabled
            ).payment_hash
            == HASH
        )
    else:
        with pytest.raises(LndProtocolError, match="not sufficiently settled"):
            case.client.observe_bound_settled_invoice(
                case.expected, deadline=110.0, submission_allowed=lambda: enabled
            )
    assert len(case.channel.calls) == position + 1
    assert case.channel.closed
