"""One bounded, read-only LND invoice snapshot, never authority to fund BTC.

The pinned LND LookupInvoice API requires invoices:read. A successful response
does not reserve an accepted HTLC, establish remaining expiry margin, or prove
that a restored local journal has not missed an earlier financial action.
"""

from __future__ import annotations

from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Literal

import grpc
from rill_core.wire.types import NetworkIdentity

from rill_provider._lnd_proto import lightning_pb2
from rill_provider.lnd_payment_observation import (
    DEFAULT_DEADLINE_SECONDS,
    MAX_CERT_BYTES,
    MAX_DEADLINE_SECONDS,
    MAX_MACAROON_BYTES,
    MAX_MESSAGE_BYTES,
    MAX_PORT,
    LndAuthError,
    LndObservationError,
    LndProtocolError,
    LndUnavailableError,
    _read_file,
)

if TYPE_CHECKING:
    import os

LOOKUP_METHOD = "/lnrpc.Lightning/LookupInvoice"
MAX_HTLCS = 64
HASH_BYTES = 32
type InvoiceState = Literal["OPEN", "SETTLED", "CANCELED", "ACCEPTED"]
type HtlcState = Literal["ACCEPTED", "SETTLED", "CANCELED"]
INVOICE_STATES: dict[int, InvoiceState] = {
    0: "OPEN",
    1: "SETTLED",
    2: "CANCELED",
    3: "ACCEPTED",
}
HTLC_STATES: dict[int, HtlcState] = {
    0: "ACCEPTED",
    1: "SETTLED",
    2: "CANCELED",
}


@dataclass(frozen=True, slots=True)
class InvoiceHtlcSnapshot:
    """One reported incoming part, including historical settled/canceled parts."""

    channel_id: int
    htlc_index: int
    state: HtlcState
    amount_msat: int
    accepted_height: int
    expiry_height: int
    mpp_total_msat: int


@dataclass(frozen=True, slots=True)
class InvoiceSnapshot:
    """Backend-reported record; not a current, safely collectible hold."""

    payment_hash: str
    state: InvoiceState
    value_sat: int
    value_msat: int
    amount_paid_msat: int
    creation_time: int
    invoice_expiry_seconds: int
    final_cltv_delta: int
    htlcs: tuple[InvoiceHtlcSnapshot, ...]


def _snapshot(invoice: lightning_pb2.Invoice, selected_hash: bytes) -> InvoiceSnapshot:
    if not isinstance(invoice, lightning_pb2.Invoice) or invoice.r_hash != selected_hash:
        raise LndProtocolError("LND invoice differs from requested payment hash")
    state = INVOICE_STATES.get(invoice.state)
    if state is None or len(invoice.htlcs) > MAX_HTLCS:
        raise LndProtocolError("LND invoice state or HTLC count unsupported")
    if invoice.is_amp or invoice.amp_invoice_state or invoice.is_keysend or invoice.is_blinded:
        raise LndProtocolError("LND invoice has unsupported payment mode")
    seen: set[tuple[int, int]] = set()
    parts: list[InvoiceHtlcSnapshot] = []
    for htlc in invoice.htlcs:
        part_state = HTLC_STATES.get(htlc.state)
        identifier = (htlc.chan_id, htlc.htlc_index)
        if (
            identifier in seen
            or part_state is None
            or htlc.HasField("amp")
            or htlc.custom_channel_data
        ):
            raise LndProtocolError("LND invoice HTLC identity or state unsupported")
        seen.add(identifier)
        parts.append(
            InvoiceHtlcSnapshot(
                htlc.chan_id,
                htlc.htlc_index,
                part_state,
                htlc.amt_msat,
                htlc.accept_height,
                htlc.expiry_height,
                htlc.mpp_total_amt_msat,
            )
        )
    return InvoiceSnapshot(
        selected_hash.hex(),
        state,
        invoice.value,
        invoice.value_msat,
        invoice.amt_paid_msat,
        invoice.creation_date,
        invoice.expiry,
        invoice.cltv_expiry,
        tuple(parts),
    )


class RegtestLndInvoiceObserver:
    """Explicit invoices:read diagnostic, separate from info/offchain credentials."""

    def __init__(
        self,
        *,
        host: str,
        port: int,
        tls_certificate_path: str | os.PathLike[str],
        invoice_macaroon_path: str | os.PathLike[str],
        network: NetworkIdentity,
    ) -> None:
        """Configure only; no credential read, network dial, or state change."""
        if host not in ("127.0.0.1", "::1") or type(port) is not int or not 1 <= port <= MAX_PORT:
            raise ValueError("LND endpoint must be a numeric loopback host and port")
        if not isinstance(network, NetworkIdentity) or network.name != "regtest":
            raise ValueError("LND invoice diagnostic requires explicit regtest network identity")
        self._target = f"[{host}]:{port}" if host == "::1" else f"{host}:{port}"
        self._certificate = Path(tls_certificate_path)
        self._macaroon = Path(invoice_macaroon_path)

    def lookup(
        self, payment_hash: bytes, *, deadline_seconds: float = DEFAULT_DEADLINE_SECONDS
    ) -> InvoiceSnapshot:
        """Read one invoice by hash, retaining all bounded HTLC history."""
        if type(payment_hash) is not bytes or len(payment_hash) != HASH_BYTES:
            raise ValueError("invoice payment hash must be exactly 32 bytes")
        if (
            type(deadline_seconds) not in (float, int)
            or not 0 < deadline_seconds <= MAX_DEADLINE_SECONDS
        ):
            raise ValueError("LND invoice deadline must be within (0, 30] seconds")
        certificate = _read_file(self._certificate, MAX_CERT_BYTES, private=False)
        macaroon = _read_file(self._macaroon, MAX_MACAROON_BYTES, private=True)
        channel: grpc.Channel | None = None
        failure: LndObservationError | None = None
        try:
            channel = grpc.secure_channel(
                self._target,
                grpc.ssl_channel_credentials(root_certificates=certificate),
                options=(
                    ("grpc.max_receive_message_length", MAX_MESSAGE_BYTES),
                    ("grpc.max_send_message_length", 1024),
                    ("grpc.enable_retries", 0),
                ),
            )
            rpc = channel.unary_unary(
                LOOKUP_METHOD,
                request_serializer=lightning_pb2.PaymentHash.SerializeToString,
                response_deserializer=lightning_pb2.Invoice.FromString,
            )
            invoice = rpc(
                lightning_pb2.PaymentHash(r_hash=payment_hash),
                timeout=deadline_seconds,
                metadata=(("macaroon", macaroon.hex()),),
                wait_for_ready=False,
            )
            return _snapshot(invoice, payment_hash)
        except grpc.RpcError as error:
            try:
                denied = error.code() in (
                    grpc.StatusCode.UNAUTHENTICATED,
                    grpc.StatusCode.PERMISSION_DENIED,
                )
            except Exception:  # noqa: BLE001 - upstream error may be malformed
                denied = False
            failure = (
                LndAuthError("LND rejected read-only invoice credentials")
                if denied
                else LndUnavailableError("LND invoice lookup unavailable; no absence claim")
            )
        except LndObservationError:
            raise
        except Exception:  # noqa: BLE001 - never retain invoice or credential-bearing errors
            failure = LndUnavailableError("LND invoice lookup unavailable; no absence claim")
        finally:
            if channel is not None:
                with suppress(Exception):
                    channel.close()
        if failure is None:
            raise LndUnavailableError("LND invoice lookup unavailable; no absence claim")
        raise failure
