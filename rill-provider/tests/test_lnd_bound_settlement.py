"""No secret dispatch before original-invoice correspondence and caller guards."""

from __future__ import annotations

import hashlib
from typing import TYPE_CHECKING
from unittest.mock import Mock

import pytest
from test_lnd_bound_invoice import _bound

from rill_provider import lnd_hold_invoice as hold
from rill_provider._lnd_proto import lightning_pb2
from rill_provider._lnd_proto.invoicesrpc import invoices_pb2
from rill_provider.lnd_payment_observation import LndProtocolError, LndUnavailableError

if TYPE_CHECKING:
    from pathlib import Path

    from test_lnd_bound_invoice import BoundCase

PREIMAGE = "cd" * 32


def _settler(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> BoundCase:
    case = _bound(tmp_path, monkeypatch)
    digest = hashlib.sha256(bytes.fromhex(PREIMAGE)).hexdigest()
    case.expected = case.expected.model_copy(update={"payment_hash": digest})
    case.responses[1].r_hash = bytes.fromhex(digest)
    case.responses.append(invoices_pb2.SettleInvoiceResp())
    return case


def test_accepted_original_invoice_dispatches_once_on_one_snapshot(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    case = _settler(tmp_path, monkeypatch)
    monkeypatch.setattr(hold.time, "monotonic", lambda: 100.0)
    allowed = Mock(return_value=True)
    assert (
        case.client.settle_bound_invoice(
            case.expected, PREIMAGE, deadline=105.0, submission_allowed=allowed
        )
        is None
    )
    assert [method for method, _ in case.channel.calls] == [
        hold.INFO_METHOD,
        hold.LOOKUP_METHOD,
        hold.INFO_METHOD,
        hold.SETTLE_METHOD,
    ]
    assert case.channel.calls[-1][1] == invoices_pb2.SettleInvoiceMsg(
        preimage=bytes.fromhex(PREIMAGE)
    )
    assert case.budgets == [5.0] * 4
    assert allowed.call_count == 5
    assert case.channel.closed


@pytest.mark.parametrize(
    "preimage", [True, "cd", "CD" * 32, "zz" * 32, "ef" * 32, "cd " * 21 + " "]
)
def test_invalid_preimage_refuses_before_credentials(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, preimage: object
) -> None:
    case = _settler(tmp_path, monkeypatch)
    credentials = Mock(side_effect=AssertionError("no credential access"))
    monkeypatch.setattr(hold, "_read_file", credentials)
    with pytest.raises(LndProtocolError, match="preimage unsupported"):
        case.client.settle_bound_invoice(case.expected, preimage)
    credentials.assert_not_called()
    assert case.channel.calls == []


@pytest.mark.parametrize(
    "deadline",
    [100.0, True, float("nan"), float("inf"), 10**1000],
    ids=["due", "bool", "nan", "infinite", "huge"],
)
def test_bound_settlement_invalid_budget_refuses_before_credentials(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, deadline: object
) -> None:
    case = _settler(tmp_path, monkeypatch)
    monkeypatch.setattr(hold.time, "monotonic", lambda: 100.0)
    credentials = Mock(side_effect=AssertionError("no credential access"))
    monkeypatch.setattr(hold, "_read_file", credentials)
    with pytest.raises(LndUnavailableError):
        case.client.settle_bound_invoice(case.expected, PREIMAGE, deadline=deadline)
    credentials.assert_not_called()
    assert case.channel.calls == []


@pytest.mark.parametrize("answer", [False, 1, "raises"])
def test_bound_settlement_requires_affirmative_permission_before_credentials(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, answer: object
) -> None:
    case = _settler(tmp_path, monkeypatch)
    allowed = Mock(return_value=answer)
    if answer == "raises":
        allowed.side_effect = RuntimeError("private permission details")
    credentials = Mock(side_effect=AssertionError("no credential access"))
    monkeypatch.setattr(hold, "_read_file", credentials)
    with pytest.raises(LndUnavailableError, match="authority unavailable") as error:
        case.client.settle_bound_invoice(case.expected, PREIMAGE, submission_allowed=allowed)
    assert "private" not in str(error.value)
    credentials.assert_not_called()
    assert case.channel.calls == []


@pytest.mark.parametrize(
    "fault",
    [
        "first identity",
        "last identity",
        "network",
        "hash",
        "bill",
        "amount",
        "creation",
        "expiry",
        "cltv",
        "tip drift",
    ],
)
def test_original_correspondence_mismatch_never_dispatches_preimage(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fault: str
) -> None:
    case = _settler(tmp_path, monkeypatch)
    invoice = case.responses[1]
    if fault == "first identity":
        case.responses[0].identity_pubkey = "03" + "33" * 32
    elif fault == "last identity":
        case.responses[2].identity_pubkey = "03" + "33" * 32
    elif fault == "network":
        case.responses[2].chains[0].network = "testnet"
    elif fault == "hash":
        invoice.r_hash = b"\x00" * 32
    elif fault == "bill":
        invoice.payment_request += "changed"
    elif fault == "amount":
        invoice.value_msat += 1000
    elif fault == "creation":
        invoice.creation_date += 1
    elif fault == "expiry":
        invoice.expiry += 1
    elif fault == "cltv":
        invoice.cltv_expiry += 1
    else:
        case.responses[2].block_hash = "ab" * 32
    with pytest.raises(LndProtocolError):
        case.client.settle_bound_invoice(case.expected, PREIMAGE)
    assert all(method != hold.SETTLE_METHOD for method, _ in case.channel.calls)
    assert case.channel.closed


@pytest.mark.parametrize("held", [500, 1000, 2000])
@pytest.mark.parametrize("multipart", [False, True])
def test_accepted_total_must_be_exact_without_restricting_valid_multipart(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, held: int, *, multipart: bool
) -> None:
    case = _settler(tmp_path, monkeypatch)
    invoice = case.responses[1]
    invoice.ClearField("htlcs")
    amounts = [held // 2, held - held // 2] if multipart else [held]
    for amount in amounts:
        invoice.htlcs.add(amt_msat=amount, expiry_height=160, state=lightning_pb2.ACCEPTED)
    if held == 1000:
        assert case.client.settle_bound_invoice(case.expected, PREIMAGE) is None
    else:
        with pytest.raises(LndProtocolError, match="not accepted as agreed"):
            case.client.settle_bound_invoice(case.expected, PREIMAGE)
    assert sum(method == hold.SETTLE_METHOD for method, _ in case.channel.calls) == int(
        held == 1000
    )


@pytest.mark.parametrize("state", [lightning_pb2.Invoice.OPEN, lightning_pb2.Invoice.CANCELED])
def test_open_or_canceled_original_invoice_does_not_receive_a_preimage(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, state: int
) -> None:
    case = _settler(tmp_path, monkeypatch)
    case.responses[1].state = state
    with pytest.raises(LndProtocolError, match="not accepted as agreed"):
        case.client.settle_bound_invoice(case.expected, PREIMAGE)
    assert all(method != hold.SETTLE_METHOD for method, _ in case.channel.calls)


@pytest.mark.parametrize("paid", [500, 1000, 2000])
def test_paid_original_invoice_is_no_dispatch_success_only_for_sufficient_amount(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, paid: int
) -> None:
    case = _settler(tmp_path, monkeypatch)
    invoice = case.responses[1]
    invoice.state = lightning_pb2.Invoice.SETTLED
    invoice.amt_paid_msat = paid
    invoice.ClearField("htlcs")
    if paid >= 1000:
        assert case.client.settle_bound_invoice(case.expected, PREIMAGE) is None
    else:
        with pytest.raises(LndProtocolError, match="paid amount inconsistent"):
            case.client.settle_bound_invoice(case.expected, PREIMAGE)
    assert all(method != hold.SETTLE_METHOD for method, _ in case.channel.calls)
    assert case.channel.closed


@pytest.mark.parametrize("position", [0, 1, 2, 3])
@pytest.mark.parametrize("failure", ["expiry", "revocation", "predicate expiry"])
def test_every_unary_setup_including_secret_dispatch_is_fenced(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, position: int, failure: str
) -> None:
    case = _settler(tmp_path, monkeypatch)
    clock = {"mono": 100.0}
    enabled = True
    count = 0
    monkeypatch.setattr(hold.time, "monotonic", lambda: clock["mono"])
    original = case.channel.unary_unary

    def setup(method: str, **kwargs: object) -> object:
        nonlocal count, enabled
        rpc = original(method, **kwargs)
        if count == position:
            if failure == "expiry":
                clock["mono"] = 110.0
            elif failure == "revocation":
                enabled = False
        count += 1
        return rpc

    def allowed() -> bool:
        if count - 1 == position and failure == "predicate expiry":
            clock["mono"] = 110.0
        return enabled

    monkeypatch.setattr(case.channel, "unary_unary", setup)
    with pytest.raises(LndUnavailableError):
        case.client.settle_bound_invoice(
            case.expected, PREIMAGE, deadline=110.0, submission_allowed=allowed
        )
    assert len(case.channel.calls) == position
    assert all(method != hold.SETTLE_METHOD for method, _ in case.channel.calls)
    assert case.channel.closed


@pytest.mark.parametrize("failure", ["expiry", "revocation"])
def test_credential_preparation_cannot_extend_dispatch_authority(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, failure: str
) -> None:
    case = _settler(tmp_path, monkeypatch)
    clock = {"mono": 100.0}
    enabled = True
    monkeypatch.setattr(hold.time, "monotonic", lambda: clock["mono"])
    original = hold._read_file  # noqa: SLF001 - credential preparation boundary

    def read(*args: object, **kwargs: object) -> bytes:
        nonlocal enabled
        value = original(*args, **kwargs)
        if kwargs.get("private"):
            if failure == "expiry":
                clock["mono"] = 110.0
            else:
                enabled = False
        return value

    monkeypatch.setattr(hold, "_read_file", read)
    with pytest.raises(LndUnavailableError):
        case.client.settle_bound_invoice(
            case.expected, PREIMAGE, deadline=110.0, submission_allowed=lambda: enabled
        )
    assert case.channel.calls == []
    assert case.channel.closed


@pytest.mark.parametrize("deadline", [None, 700.0])
def test_bound_settlement_always_caps_preconnect_setup_at_ten_seconds(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, deadline: float | None
) -> None:
    case = _settler(tmp_path, monkeypatch)
    clock = {"mono": 100.0}
    monkeypatch.setattr(hold.time, "monotonic", lambda: clock["mono"])
    original = hold._read_file  # noqa: SLF001 - setup must consume the default local budget

    def read(*args: object, **kwargs: object) -> bytes:
        value = original(*args, **kwargs)
        if kwargs.get("private"):
            clock["mono"] = 111.0
        return value

    monkeypatch.setattr(hold, "_read_file", read)
    with pytest.raises(LndUnavailableError):
        case.client.settle_bound_invoice(case.expected, PREIMAGE, deadline=deadline)
    assert case.channel.calls == []
    assert case.channel.closed


@pytest.mark.parametrize("outcome", ["success", "unknown"])
@pytest.mark.parametrize("boundary", ["expiry", "revocation"])
def test_started_settlement_retains_outcome_without_retry_or_post_auth_check(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, outcome: str, boundary: str
) -> None:
    case = _settler(tmp_path, monkeypatch)
    clock = {"mono": 100.0}
    enabled = True
    monkeypatch.setattr(hold.time, "monotonic", lambda: clock["mono"])

    def result() -> object:
        nonlocal enabled
        if boundary == "expiry":
            clock["mono"] = 200.0
        else:
            enabled = False
        return (
            RuntimeError("private invoice details")
            if outcome == "unknown"
            else invoices_pb2.SettleInvoiceResp()
        )

    case.responses[3] = result
    if outcome == "success":
        assert (
            case.client.settle_bound_invoice(
                case.expected, PREIMAGE, deadline=110.0, submission_allowed=lambda: enabled
            )
            is None
        )
    else:
        with pytest.raises(LndUnavailableError, match="outcome unknown") as error:
            case.client.settle_bound_invoice(
                case.expected, PREIMAGE, deadline=110.0, submission_allowed=lambda: enabled
            )
        assert "private" not in str(error.value)
    assert [method for method, _ in case.channel.calls] == [
        hold.INFO_METHOD,
        hold.LOOKUP_METHOD,
        hold.INFO_METHOD,
        hold.SETTLE_METHOD,
    ]
    assert case.channel.closed
