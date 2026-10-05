"""Real signatures with synthetic RPCs, not funded service interoperability."""

from __future__ import annotations

import json
import time
from dataclasses import replace
from typing import TYPE_CHECKING, Any

import pytest
from Cryptodome.Signature import eddsa
from rill_provider.core_tx_bytes import CoreSourceSnapshot
from rill_provider.lnd_hold_invoice import BoundHoldInvoiceObservation, HoldInvoiceStatus
from test_merchant_credit import ProofCase, encode, proof

from rill_cli import merchant_source as module
from rill_cli.merchant_credit import (
    AcquisitionInterval,
    extract_merchant_invoice_candidate,
    verify_merchant_credit,
)
from rill_cli.merchant_https import MerchantReadBatch

if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path


def loopback_proof() -> ProofCase:
    original = proof()
    origin = "https://127.0.0.1:12345"
    key = eddsa.import_private_key(bytes([9]) * 32)
    signer = eddsa.new(key, "rfc8032")
    public = key.public_key().export_key(format="raw").hex()
    acceptance = json.loads(original.acceptance)
    event = acceptance["event"]
    event["merchantOrigin"] = origin
    message = encode(
        [
            "rillswap-payment-event/1",
            event["version"],
            event["id"],
            origin,
            event["type"],
            event["intentId"],
            event["attemptId"],
            event["paymentHash"],
            event["amountMsat"],
            event["acceptedAt"],
        ]
    )
    acceptance["publicKey"], acceptance["signature"] = public, signer.sign(message).hex()
    view = json.loads(original.view.document)
    view["attempt"]["terms"]["merchantOrigin"] = origin
    interval = AcquisitionInterval(started_at=original.now, completed_at=original.now)
    return replace(
        original,
        pin=original.pin.model_copy(update={"merchant_origin": origin, "event_public_key": public}),
        acceptance=encode(acceptance),
        view=original.view.model_copy(
            update={"origin": origin, "document": encode(view), "acquisition": interval}
        ),
        source=original.source.model_copy(update={"acquisition": interval}),
        core=original.core.model_copy(update={"acquisition": interval}),
    )


class Transport:
    def __init__(self, case: ProofCase) -> None:
        self.case = case
        self.batch = MerchantReadBatch(
            case.view, b"[" + case.acceptance + b"]", case.view.acquisition
        )
        self.calls: list[str] = []
        self.configs: dict[str, dict[str, Any]] = {}
        self.clock = [100.0]
        self.failure: str | None = None
        self.late: str | None = None
        self.state = "SETTLED"
        self.source_node = case.pin.source_node

    def step(self, phase: str) -> None:
        self.calls.append(phase)
        if phase == self.late:
            self.clock[0] += 11
        if phase == self.failure:
            raise RuntimeError("SECRET_CANARY")

    def install(self, monkeypatch: pytest.MonkeyPatch) -> None:
        owner = self

        class Https:
            def __init__(self, *_args: object) -> None:
                owner.configs["https"] = {}

            def read(
                self, _intent: str, _token: str, *, deadline_seconds: float
            ) -> MerchantReadBatch:
                assert 0 < deadline_seconds <= 10
                owner.step("https")
                return owner.batch

        class Decoder:
            def __init__(self, **kwargs: Any) -> None:  # noqa: ANN401 - record concrete client constructor arguments
                owner.configs["decoder"] = kwargs

            def decode(self, invoice: str, *, deadline_seconds: float) -> object:
                assert invoice == json.loads(owner.case.view.document)["attempt"]["invoice"]
                assert 0 < deadline_seconds <= 10
                owner.step("decode")
                return owner.case.invoice

        class Receiver:
            def __init__(self, **kwargs: Any) -> None:  # noqa: ANN401 - record concrete client constructor arguments
                owner.configs["receiver"] = kwargs

            def observe_bound_settled_invoice(
                self, invoice: object, *, deadline: float
            ) -> BoundHoldInvoiceObservation:
                assert invoice == owner.case.invoice
                assert deadline == 110
                owner.step("settled")
                source = owner.case.source
                return BoundHoldInvoiceObservation(
                    source.payment_hash,
                    source.invoice_sha256,
                    owner.source_node,
                    source.network,
                    HoldInvoiceStatus(owner.state, ()),  # type: ignore[arg-type]
                    source.last_lnd_height,
                    source.last_lnd_block_hash,
                )

        class Core:
            def __init__(self, **kwargs: Any) -> None:  # noqa: ANN401 - record concrete client constructor arguments
                owner.configs["core"] = kwargs

            def observe_source(self, height: int, *, deadline_seconds: float) -> CoreSourceSnapshot:
                assert 0 < deadline_seconds <= 10
                assert height == owner.case.source.last_lnd_height
                owner.step("core")
                core = owner.case.core
                return CoreSourceSnapshot(
                    core.configured_network,
                    "regtest",
                    core.genesis_hash,
                    core.signet_challenge,
                    core.tip_height,
                    "b" * 64,
                    core.source_height,
                    core.source_block_hash,
                )

        for name, implementation in (
            ("MerchantHttpsReader", Https),
            ("LndInvoiceDecoder", Decoder),
            ("LndHoldInvoices", Receiver),
            ("CoreTransactionReader", Core),
        ):
            monkeypatch.setattr(module, name, implementation)
        monkeypatch.setattr(time, "monotonic", lambda: owner.clock[0])
        monkeypatch.setattr(time, "time", lambda: owner.case.now)


@pytest.fixture
def transport(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> tuple[module.MerchantCreditCollector, Transport]:
    case = loopback_proof()
    backend = Transport(case)
    backend.install(monkeypatch)
    config = module.MerchantSourceConfig(
        "a" * 64,
        tmp_path / "merchant.cert",
        10009,
        tmp_path / "lnd.cert",
        tmp_path / "source.macaroon",
        18443,
        tmp_path / "core.cookie",
    )
    return module.MerchantCreditCollector(case.authority, case.pin, config), backend


def refused(action: Callable[[], object]) -> None:
    with pytest.raises(module.MerchantSourceError) as failure:
        action()
    assert failure.value.__cause__ is None
    assert failure.value.__context__ is None
    assert "SECRET_CANARY" not in str(failure.value)


def test_concrete_sequence_verifies_real_signature_without_inventory_import(
    transport: tuple[module.MerchantCreditCollector, Transport],
) -> None:
    collector, backend = transport
    assert not backend.calls
    credit = collector.acquire(backend.case.view.intent_id, "synthetic_status_capability_0001")
    assert credit == backend.case.verify()
    assert backend.calls == ["https", "decode", "settled", "core"]
    assert backend.configs["decoder"] == backend.configs["receiver"]
    assert credit.model_dump() == {
        "payment_hash": backend.case.invoice.payment_hash,
        "invoice_sha256": backend.case.invoice.bolt11_sha256,
        "amount_msat": int(backend.case.invoice.amount_msat),
    }


@pytest.mark.parametrize("phase", ["https", "decode", "settled", "core"])
def test_failure_or_late_result_never_releases_credit(
    transport: tuple[module.MerchantCreditCollector, Transport], phase: str
) -> None:
    collector, backend = transport
    backend.failure = phase
    refused(
        lambda: collector.acquire(backend.case.view.intent_id, "synthetic_status_capability_0001")
    )
    backend.calls.clear()
    backend.failure = None
    backend.late = phase
    refused(
        lambda: collector.acquire(backend.case.view.intent_id, "synthetic_status_capability_0001")
    )
    assert backend.calls[-1] == phase


@pytest.mark.parametrize(
    "fault",
    [
        "waiting",
        "no_event",
        "duplicate_event",
        "foreign_attempt",
        "uppercase_invoice",
        "oversized_invoice",
        "bad_signature",
        "earlier_interval",
    ],
)
def test_bad_documents_do_not_establish_credit(
    transport: tuple[module.MerchantCreditCollector, Transport], fault: str
) -> None:
    collector, backend = transport
    view, events = (
        json.loads(backend.batch.view.document),
        json.loads(backend.batch.events_document),
    )
    if fault == "waiting":
        view["status"], view["attempt"] = "waiting", None
    elif fault == "no_event":
        events = []
    elif fault == "duplicate_event":
        events *= 2
    elif fault == "foreign_attempt":
        events[0]["event"]["attemptId"] = "another_attempt_01"
    elif fault == "uppercase_invoice":
        view["attempt"]["invoice"] = "LNBCRT1FAKE"
    elif fault == "oversized_invoice":
        view["attempt"]["invoice"] = "lnbcrt1" + "a" * 2048
    elif fault == "bad_signature":
        events[0]["signature"] = "a" * 128
    observed = backend.batch.view.model_copy(update={"document": encode(view)})
    if fault == "earlier_interval":
        observed = observed.model_copy(
            update={
                "acquisition": AcquisitionInterval(
                    started_at=backend.case.now - 1, completed_at=backend.case.now
                )
            }
        )
    backend.batch = MerchantReadBatch(observed, encode(events), observed.acquisition)
    refused(
        lambda: collector.acquire(backend.case.view.intent_id, "synthetic_status_capability_0001")
    )
    assert backend.calls == (
        ["https", "decode", "settled", "core"] if fault == "bad_signature" else ["https"]
    )


def test_wrong_authority_refuses_before_client_construction(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    case = loopback_proof()
    backend = Transport(case)
    backend.install(monkeypatch)
    config = module.MerchantSourceConfig(
        "a" * 64,
        tmp_path / "ca",
        10009,
        tmp_path / "tls",
        tmp_path / "mac",
        18443,
        tmp_path / "cookie",
    )
    wrong = case.authority.model_copy(update={"source_node": "03" + case.pin.source_node[2:]})
    refused(lambda: module.MerchantCreditCollector(wrong, case.pin, config))
    assert not backend.calls
    assert not backend.configs


def test_final_verifier_expiry_discards_already_computed_credit(
    transport: tuple[module.MerchantCreditCollector, Transport], monkeypatch: pytest.MonkeyPatch
) -> None:
    collector, backend = transport
    verify = verify_merchant_credit

    def slow(*args: Any, **kwargs: Any) -> object:  # noqa: ANN401 - instrument final pure verification
        result = verify(*args, **kwargs)
        backend.clock[0] += 11
        return result

    monkeypatch.setattr(module, "verify_merchant_credit", slow)
    refused(
        lambda: collector.acquire(backend.case.view.intent_id, "synthetic_status_capability_0001")
    )


@pytest.mark.parametrize("state", ["OPEN", "ACCEPTED", "CANCELED"])
def test_even_fabricated_nonsettled_return_refuses_credit(
    transport: tuple[module.MerchantCreditCollector, Transport], state: str
) -> None:
    collector, backend = transport
    backend.state = state
    refused(
        lambda: collector.acquire(backend.case.view.intent_id, "synthetic_status_capability_0001")
    )


def test_duplicate_safe_structural_parser_does_not_authenticate_signature() -> None:
    case = loopback_proof()
    event = json.loads(case.acceptance)
    event["signature"] = "a" * 128
    candidate = extract_merchant_invoice_candidate(case.view, encode([event]))
    assert candidate.invoice == json.loads(case.view.document)["attempt"]["invoice"]
    assert candidate.acceptance


def test_wrong_receiver_refuses_before_independent_core_read(
    transport: tuple[module.MerchantCreditCollector, Transport],
) -> None:
    collector, backend = transport
    backend.source_node = "03" + backend.case.pin.source_node[2:]
    refused(
        lambda: collector.acquire(backend.case.view.intent_id, "synthetic_status_capability_0001")
    )
    assert backend.calls == ["https", "decode", "settled"]


@pytest.mark.parametrize("field", ["genesis_hash", "source_block_hash", "source_height"])
def test_wrong_core_correspondence_never_establishes_credit(
    transport: tuple[module.MerchantCreditCollector, Transport],
    field: str,
) -> None:
    collector, backend = transport
    value = 999 if field == "source_height" else "d" * 64
    backend.case = replace(backend.case, core=backend.case.core.model_copy(update={field: value}))
    refused(
        lambda: collector.acquire(backend.case.view.intent_id, "synthetic_status_capability_0001")
    )


def test_earlier_events_interval_cannot_be_refreshed_to_view_completion(
    transport: tuple[module.MerchantCreditCollector, Transport],
) -> None:
    collector, backend = transport
    earlier = AcquisitionInterval(started_at=backend.case.now - 1, completed_at=backend.case.now)
    backend.batch = replace(backend.batch, events_acquisition=earlier)
    refused(
        lambda: collector.acquire(backend.case.view.intent_id, "synthetic_status_capability_0001")
    )
    assert backend.calls == ["https"]


@pytest.mark.parametrize("duration", [True, 0, -1, 11, 10**400, float("nan"), float("inf")])
def test_bad_lifetime_performs_no_reads(
    transport: tuple[module.MerchantCreditCollector, Transport],
    duration: float,
) -> None:
    collector, backend = transport
    refused(
        lambda: collector.acquire(
            "merchant_intent_01", "synthetic_status_capability_0001", deadline_seconds=duration
        )
    )
    assert not backend.calls


@pytest.mark.parametrize(
    "events", [b'[{"algorithm":"Ed25519","algorithm":"Ed25519"}]', b"[1.0]", b"[]" + b" " * 16384]
)
def test_duplicate_float_or_oversized_events_are_not_decoded(
    transport: tuple[module.MerchantCreditCollector, Transport],
    events: bytes,
) -> None:
    collector, backend = transport
    backend.batch = replace(backend.batch, events_document=events)
    refused(
        lambda: collector.acquire(backend.case.view.intent_id, "synthetic_status_capability_0001")
    )
    assert backend.calls == ["https"]


def test_final_clock_rollback_cannot_shorten_completed_https_acquisitions(
    transport: tuple[module.MerchantCreditCollector, Transport],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    collector, backend = transport
    start = backend.case.now
    # Historical signed acceptance stays valid, so the interval enclosure
    # regression, not event acceptedAt freshness, must refuse this credit.
    assert json.loads(backend.case.acceptance)["event"]["acceptedAt"] < start
    completed = AcquisitionInterval(started_at=start, completed_at=start + 5)
    backend.batch = replace(
        backend.batch,
        view=backend.batch.view.model_copy(update={"acquisition": completed}),
        events_acquisition=completed,
    )
    wall = iter((start, start + 5, start + 5, start + 3))
    monkeypatch.setattr(time, "time", lambda: next(wall))
    refused(
        lambda: collector.acquire(backend.case.view.intent_id, "synthetic_status_capability_0001")
    )
    assert backend.calls == ["https", "decode", "settled", "core"]
    assert backend.clock == [100.0]
