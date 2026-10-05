"""Real cross-language signatures, mocked authenticated RPC/HTTP observations."""

from __future__ import annotations

import hashlib
import json
import traceback
from dataclasses import dataclass, replace
from pathlib import Path

import pytest
from Cryptodome.Signature import eddsa
from pydantic import ValidationError
from rill_core.wire.messages import InvoiceBinding
from rill_core.wire.types import NetworkIdentity
from rill_provider.lnd_hold_invoice import BoundHoldInvoiceObservation, HoldInvoiceStatus, HoldState

from rill_cli.conversion_journal import SourceAuthority, SourceCredit
from rill_cli.merchant_credit import (
    AcquisitionInterval,
    CoreSourceObservation,
    MerchantCreditError,
    MerchantSourcePin,
    MerchantViewObservation,
    SourceReceiptObservation,
    verify_merchant_credit,
)

FIXTURE = json.loads((Path(__file__).parent / "fixtures/merchant_acceptance.json").read_bytes())
NODE = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
NETWORK = NetworkIdentity(
    family="bitcoin",
    name="regtest",
    genesis_hash="0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206",
    signet_challenge=None,
    consensus_profile="bitcoin-regtest/1",
    deployment_namespace="merchant-credit-fixture",
)
ORIGIN = "https://merchant.invalid"
INTERVAL = AcquisitionInterval(started_at=1760000005, completed_at=1760000009)


def encode(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode()


@dataclass(frozen=True)
class ProofCase:
    authority: SourceAuthority
    pin: MerchantSourcePin
    acceptance: bytes
    view: MerchantViewObservation
    invoice: InvoiceBinding
    source: SourceReceiptObservation
    core: CoreSourceObservation
    now: int = 1760000010

    def verify(self) -> SourceCredit:
        return verify_merchant_credit(
            self.authority,
            self.pin,
            self.acceptance,
            self.view,
            self.invoice,
            self.source,
            self.core,
            now=self.now,
        )


def proof() -> ProofCase:
    pin = MerchantSourcePin(
        merchant_origin=ORIGIN,
        event_public_key=FIXTURE["envelope"]["publicKey"],
        source_node=NODE,
        network=NETWORK,
    )
    authority = SourceAuthority(
        source_node=NODE,
        network=NETWORK,
        source_epoch="b" * 64,
        exclusive_wallet=True,
        commitments_known=True,
        fixed_reserve_msat=1_000_000,
        treasury_script="5120" + NODE[2:],
        provider_identity=NODE[2:],
    )
    # The invoice decoder projection is a fixture, not a cryptographically valid
    # BOLT11 or an actual ordinary-invoice/backend interoperability assertion.
    literal_invoice = "lnbcrt1publicfixture"
    invoice = InvoiceBinding(
        bolt11_sha256=hashlib.sha256(literal_invoice.encode()).hexdigest(),
        payment_hash="c" * 64,
        amount_msat="50000000",
        payee_compressed_pubkey=NODE,
        created_at=1759999900,
        expires_at=1760001000,
        min_final_cltv_delta=40,
    )
    view = {
        "version": "checkout-view/1",
        "id": "merchant_intent_01",
        "status": "paid",
        "attempt": {
            "terms": {
                "version": "checkout/0.1",
                "policyVersion": "native-lightning/1",
                "merchantOrigin": ORIGIN,
                "intentId": "merchant_intent_01",
                "attemptId": "merchant_attempt_01",
                "network": "regtest",
                "amountMsat": "50000000",
                "paymentHash": "c" * 64,
                "receiver": NODE,
                "expiresAt": 1760000900,
                "buyerExtraMsat": "0",
            },
            "invoice": literal_invoice,
        },
    }
    bound = BoundHoldInvoiceObservation(
        payment_hash=invoice.payment_hash,
        bolt11_sha256=invoice.bolt11_sha256,
        node_pubkey=NODE,
        network=NETWORK,
        status=HoldInvoiceStatus("SETTLED", ()),
        last_lnd_height=1000,
        last_lnd_block_hash="a" * 64,
    )
    return ProofCase(
        authority,
        pin,
        encode(FIXTURE["envelope"]),
        MerchantViewObservation(
            origin=ORIGIN,
            intent_id="merchant_intent_01",
            acquisition=INTERVAL,
            document=encode(view),
        ),
        invoice,
        SourceReceiptObservation.from_bound(bound, INTERVAL),
        CoreSourceObservation(
            acquisition=INTERVAL,
            configured_network=NETWORK,
            genesis_hash=NETWORK.genesis_hash,
            signet_challenge=None,
            tip_height=1001,
            source_height=1000,
            source_block_hash="a" * 64,
        ),
    )


def test_literal_typescript_signature_yields_only_canonical_agreed_credit() -> None:
    case = proof()
    credit = case.verify()
    assert credit.model_dump() == {
        "payment_hash": "c" * 64,
        "invoice_sha256": case.invoice.bolt11_sha256,
        "amount_msat": 50_000_000,
    }
    public_key = eddsa.import_public_key(bytes.fromhex(FIXTURE["envelope"]["publicKey"]))
    eddsa.new(public_key, "rfc8032").verify(
        bytes.fromhex(FIXTURE["messageHex"]), bytes.fromhex(FIXTURE["envelope"]["signature"])
    )
    assert "preimage" not in credit.model_dump_json()
    assert "invoice" not in credit.model_dump()  # raw invoice is not retained


def test_historical_accepted_invoice_expiry_does_not_invalidate_provenance() -> None:
    case = proof()
    later = AcquisitionInterval(started_at=1900000005, completed_at=1900000009)
    case = replace(
        case,
        now=1900000010,
        view=case.view.model_copy(update={"acquisition": later}),
        source=case.source.model_copy(update={"acquisition": later}),
        core=case.core.model_copy(update={"acquisition": later}),
    )
    assert case.verify().amount_msat == 50_000_000


def test_two_operator_pinned_origins_cannot_create_different_source_credit() -> None:
    original = proof()
    alias = "https://alias.invalid"
    envelope, paid = json.loads(original.acceptance), json.loads(original.view.document)
    envelope["event"]["merchantOrigin"] = alias
    paid["attempt"]["terms"]["merchantOrigin"] = alias
    message = bytes.fromhex(FIXTURE["messageHex"]).replace(ORIGIN.encode(), alias.encode())
    key = eddsa.import_private_key(bytes.fromhex(FIXTURE["publicTestSeed"]))
    envelope["signature"] = eddsa.new(key, "rfc8032").sign(message).hex()
    alternate = replace(
        original,
        acceptance=encode(envelope),
        pin=original.pin.model_copy(update={"merchant_origin": alias}),
        view=original.view.model_copy(update={"origin": alias, "document": encode(paid)}),
    )
    assert alternate.verify() == original.verify()


@pytest.mark.parametrize(
    "kind",
    [
        "wrong_key",
        "self_signed_key",
        "signature_mutation",
        "wrong_domain",
        "extra_envelope",
        "duplicate_key",
        "oversized",
        "non_json",
        "float_time",
        "bool_time",
        "negative_time",
        "future_time",
        "numeric_id",
        "numeric_amount",
        "noncanonical_amount",
        "fractional_satoshi",
        "too_large_amount",
        "extra_event",
        "unknown_version",
        "foreign_intent",
        "foreign_origin",
        "foreign_attempt",
        "foreign_hash",
    ],
)
def test_strict_signed_event_mutations_never_import_credit(kind: str) -> None:
    case = proof()
    envelope = json.loads(case.acceptance)
    event = envelope["event"]
    if kind == "wrong_key":
        case = replace(case, pin=case.pin.model_copy(update={"event_public_key": "1" * 64}))
    elif kind == "self_signed_key":
        key = eddsa.import_private_key(bytes.fromhex("04" * 32))
        envelope["publicKey"] = key.public_key().export_key(format="raw").hex()
        envelope["signature"] = (
            eddsa.new(key, "rfc8032").sign(bytes.fromhex(FIXTURE["messageHex"])).hex()
        )
    elif kind == "signature_mutation":
        envelope["signature"] = "0" * 128
    elif kind == "wrong_domain":
        message = bytes.fromhex(FIXTURE["messageHex"]).replace(
            b"rillswap-payment-event/1", b"foreign-payment-event/1"
        )
        envelope["signature"] = (
            eddsa.new(eddsa.import_private_key(bytes.fromhex(FIXTURE["publicTestSeed"])), "rfc8032")
            .sign(message)
            .hex()
        )
    elif kind == "extra_envelope":
        envelope["statusToken"] = "SECRET_CANARY"
    elif kind == "duplicate_key":
        case = replace(
            case, acceptance=case.acceptance.replace(b"{", b'{"algorithm":"foreign",', 1)
        )
    elif kind == "oversized":
        case = replace(case, acceptance=b" " * 16385)
    elif kind == "non_json":
        case = replace(case, acceptance=b"SECRET_CANARY")
    else:
        updates = {
            "float_time": {"acceptedAt": 1760000000.0},
            "bool_time": {"acceptedAt": True},
            "negative_time": {"acceptedAt": -1},
            "future_time": {"acceptedAt": 1900000000},
            "numeric_id": {"id": 1234567890123456},
            "numeric_amount": {"amountMsat": 50000000},
            "noncanonical_amount": {"amountMsat": "050000000"},
            "fractional_satoshi": {"amountMsat": "1"},
            "too_large_amount": {"amountMsat": "2100000000000001000"},
            "extra_event": {"secret": "SECRET_CANARY"},
            "unknown_version": {"version": "checkout-event/2"},
            "foreign_intent": {"intentId": "another_intent_01"},
            "foreign_origin": {"merchantOrigin": "https://foreign.invalid"},
            "foreign_attempt": {"attemptId": "another_attempt_01"},
            "foreign_hash": {"paymentHash": "d" * 64},
        }
        event.update(updates[kind])
    if kind not in {"duplicate_key", "oversized", "non_json"}:
        case = replace(case, acceptance=encode(envelope))
    with pytest.raises(MerchantCreditError, match="merchant source proof refused") as refused:
        case.verify()
    assert "SECRET_CANARY" not in "".join(traceback.format_exception(refused.value))


@pytest.mark.parametrize(
    "kind",
    [
        "not_paid",
        "no_attempt",
        "other_intent",
        "foreign_receiver",
        "foreign_network",
        "other_hash",
        "other_attempt",
        "other_origin",
        "other_amount",
        "wrong_policy",
        "extra_terms",
        "extra_view",
        "duplicate_key",
        "uppercase_invoice",
        "other_invoice",
        "excess_term_expiry",
        "bool_expiry",
        "negative_extra",
        "oversized",
    ],
)
def test_current_paid_view_must_correspond_to_signed_event_and_decoded_invoice(kind: str) -> None:
    case = proof()
    paid = json.loads(case.view.document)
    terms = paid["attempt"]["terms"]
    if kind == "not_paid":
        paid["status"] = "reconciliation"
    elif kind == "no_attempt":
        paid["attempt"] = None
    elif kind == "other_intent":
        paid["id"] = "another_intent_01"
    elif kind == "extra_view":
        paid["statusToken"] = "SECRET_CANARY"
    elif kind in {"uppercase_invoice", "other_invoice"}:
        paid["attempt"]["invoice"] = (
            paid["attempt"]["invoice"].upper()
            if kind == "uppercase_invoice"
            else "lnbcrt1foreigninvoice"
        )
    elif kind == "duplicate_key":
        case = replace(
            case,
            view=case.view.model_copy(
                update={"document": case.view.document.replace(b"{", b'{"status":"waiting",', 1)}
            ),
        )
    elif kind == "oversized":
        case = replace(case, view=case.view.model_copy(update={"document": b" " * 16385}))
    else:
        updates = {
            "foreign_receiver": {"receiver": "03" + NODE[2:]},
            "foreign_network": {"network": "mainnet"},
            "other_hash": {"paymentHash": "d" * 64},
            "other_attempt": {"attemptId": "another_attempt_01"},
            "other_origin": {"merchantOrigin": "https://foreign.invalid"},
            "other_amount": {"amountMsat": "49000000"},
            "wrong_policy": {"policyVersion": "unverified/1"},
            "extra_terms": {"preimage": "SECRET_CANARY"},
            "excess_term_expiry": {"expiresAt": 1760001001},
            "bool_expiry": {"expiresAt": True},
            "negative_extra": {"buyerExtraMsat": "-1"},
        }
        terms.update(updates[kind])
    if kind not in {"duplicate_key", "oversized"}:
        case = replace(case, view=case.view.model_copy(update={"document": encode(paid)}))
    with pytest.raises(MerchantCreditError, match="merchant source proof refused") as refused:
        case.verify()
    assert "SECRET_CANARY" not in "".join(traceback.format_exception(refused.value))


@pytest.mark.parametrize(
    "kind",
    [
        "journal_network",
        "journal_source",
        "source_node",
        "source_network",
        "source_hash",
        "source_digest",
        "core_network",
        "core_genesis",
        "core_challenge",
        "core_tip_behind",
        "core_other_height",
        "core_other_hash",
        "view_other_origin",
        "view_other_endpoint",
        "invoice_payee",
        "invoice_hash",
        "invoice_digest",
        "invoice_amount",
        "invoice_future_created",
        "invoice_too_short_expiry",
    ],
)
def test_source_journal_lnd_core_and_transport_pins_must_all_match(kind: str) -> None:
    case = proof()
    wrong_network = NETWORK.model_copy(update={"deployment_namespace": "foreign-fixture"})
    updates = {
        "journal_network": ("authority", {"network": wrong_network}),
        "journal_source": ("authority", {"source_node": "03" + NODE[2:]}),
        "source_node": ("source", {"source_node": "03" + NODE[2:]}),
        "source_network": ("source", {"network": wrong_network}),
        "source_hash": ("source", {"payment_hash": "d" * 64}),
        "source_digest": ("source", {"invoice_sha256": "d" * 64}),
        "core_network": ("core", {"configured_network": wrong_network}),
        "core_genesis": ("core", {"genesis_hash": "b" * 64}),
        "core_challenge": ("core", {"signet_challenge": "00"}),
        "core_tip_behind": ("core", {"tip_height": 999}),
        "core_other_height": ("core", {"source_height": 1001}),
        "core_other_hash": ("core", {"source_block_hash": "b" * 64}),
        "view_other_origin": ("view", {"origin": "https://foreign.invalid"}),
        "view_other_endpoint": ("view", {"intent_id": "another_intent_01"}),
        "invoice_payee": ("invoice", {"payee_compressed_pubkey": "03" + NODE[2:]}),
        "invoice_hash": ("invoice", {"payment_hash": "d" * 64}),
        "invoice_digest": ("invoice", {"bolt11_sha256": "d" * 64}),
        "invoice_amount": ("invoice", {"amount_msat": "49000000"}),
        "invoice_future_created": ("invoice", {"created_at": 1760000011}),
        "invoice_too_short_expiry": ("invoice", {"expires_at": 1760000899}),
    }
    field, changes = updates[kind]
    case = replace(case, **{field: getattr(case, field).model_copy(update=changes)})
    with pytest.raises(MerchantCreditError, match="merchant source proof refused"):
        case.verify()


@pytest.mark.parametrize("field", ["view", "source", "core"])
@pytest.mark.parametrize(
    "interval",
    [
        AcquisitionInterval(started_at=1759999900, completed_at=1759999901),
        AcquisitionInterval(started_at=1760000011, completed_at=1760000012),
        AcquisitionInterval(started_at=1759999999, completed_at=1760000009),
    ],
)
def test_entire_acquisition_must_be_fresh_not_just_recent_completion(
    field: str, interval: AcquisitionInterval
) -> None:
    case = proof()
    case = replace(
        case, **{field: getattr(case, field).model_copy(update={"acquisition": interval})}
    )
    with pytest.raises(MerchantCreditError, match="merchant source proof refused"):
        case.verify()


@pytest.mark.parametrize("value", [True, 1760000010.0, -1, 9_007_199_254_740_992])
def test_reference_clock_is_strict_and_safe(value: object) -> None:
    with pytest.raises(MerchantCreditError, match="merchant source proof refused"):
        replace(proof(), now=value).verify()  # type: ignore[arg-type]


@pytest.mark.parametrize("origin", FIXTURE["origins"])
def test_shared_whatwg_origin_edge_vectors(origin: dict[str, object]) -> None:
    values = proof().pin.model_dump() | {"merchant_origin": origin["value"]}
    if origin["valid"]:
        assert MerchantSourcePin.model_validate(values).merchant_origin == origin["value"]
    else:
        with pytest.raises(ValidationError):
            MerchantSourcePin.model_validate(values)


@pytest.mark.parametrize("state", ["OPEN", "ACCEPTED", "CANCELED"])
def test_projection_requires_the_successful_bound_settlement_state(state: HoldState) -> None:
    bound = BoundHoldInvoiceObservation(
        payment_hash="c" * 64,
        bolt11_sha256="d" * 64,
        node_pubkey=NODE,
        network=NETWORK,
        status=HoldInvoiceStatus(state, ()),
        last_lnd_height=1000,
        last_lnd_block_hash="a" * 64,
    )
    with pytest.raises(MerchantCreditError, match="bound merchant settlement required"):
        SourceReceiptObservation.from_bound(bound, INTERVAL)


@pytest.mark.parametrize(
    ("start", "end"), [(1760000010, 1760000009), (1759999900, 1760000009), (True, 1760000009)]
)
def test_acquisition_intervals_are_strict_ordered_and_bounded(start: object, end: object) -> None:
    with pytest.raises(ValidationError):
        AcquisitionInterval.model_validate({"started_at": start, "completed_at": end})
