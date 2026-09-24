"""Pinned invoice protobuf messages, not invoice creation or permission to act."""

from __future__ import annotations

import hashlib
import importlib.util
from pathlib import Path

from rill_provider._lnd_proto import lightning_pb2
from rill_provider._lnd_proto.invoicesrpc import invoices_pb2

UPSTREAM_SHA256 = "1724f72aa2ed070c8978f5e8a40bc828a2859bbf5a56274ffa1577a65f3f05e7"
PROTO = Path(__file__).resolve().parents[1] / "proto/lnd-v0.21.0-beta/invoicesrpc/invoices.proto"


def test_invoice_source_pin_and_rpc_descriptors_are_not_callables() -> None:
    assert hashlib.sha256(PROTO.read_bytes()).hexdigest() == UPSTREAM_SHA256
    service = invoices_pb2.DESCRIPTOR.services_by_name["Invoices"]
    assert service.methods_by_name["AddHoldInvoice"].input_type.name == "AddHoldInvoiceRequest"
    assert service.methods_by_name["LookupInvoiceV2"].output_type.full_name == "lnrpc.Invoice"
    assert service.methods_by_name["CancelInvoice"].input_type.name == "CancelInvoiceMsg"
    assert service.methods_by_name["SettleInvoice"].input_type.name == "SettleInvoiceMsg"
    grpc_stub = "rill_provider._lnd_proto.invoicesrpc.invoices_pb2_grpc"
    assert importlib.util.find_spec(grpc_stub) is None


def test_exact_invoice_messages_round_trip_through_pinned_protobuf() -> None:
    selected_hash = bytes(range(32))
    lookup = invoices_pb2.LookupInvoiceMsg(payment_hash=selected_hash)
    assert lookup.WhichOneof("invoice_ref") == "payment_hash"
    assert invoices_pb2.LookupInvoiceMsg.FromString(lookup.SerializeToString()) == lookup
    hold = invoices_pb2.AddHoldInvoiceRequest(hash=selected_hash, value_msat=1000)
    assert invoices_pb2.AddHoldInvoiceRequest.FromString(hold.SerializeToString()) == hold
    reply = lightning_pb2.Invoice(
        r_hash=selected_hash,
        state=lightning_pb2.Invoice.ACCEPTED,
    )
    assert lightning_pb2.Invoice.FromString(reply.SerializeToString()) == reply
    assert reply.state != lightning_pb2.Invoice.SETTLED
