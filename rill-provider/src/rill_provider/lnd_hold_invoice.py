"""Loopback LND hold invoices for LN to BTC swaps (RS-004).

The provider opens a hold invoice for the client's ``payment_hash``, watches
it until every HTLC is ``ACCEPTED``, funds the contract, and settles the
invoice only once it holds the verified preimage. Cancelation happens only
before funding or after a confirmed refund; the caller owns those rules.
Errors never carry invoice, preimage, or credential material.
"""

from __future__ import annotations

import math
import time
from contextlib import contextmanager, suppress
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Literal

import grpc
from rill_core.errors import ValidationError
from rill_core.networks import backend_names

from rill_provider._lnd_proto import lightning_pb2
from rill_provider._lnd_proto.invoicesrpc import invoices_pb2
from rill_provider.lnd_payment_observation import (
    MAX_CERT_BYTES,
    MAX_MACAROON_BYTES,
    MAX_MESSAGE_BYTES,
    MAX_PORT,
    LndObservationError,
    LndProtocolError,
    LndUnavailableError,
    _read_file,
)
from rill_provider.lnd_payment_send import _Calls, _check_submission_authority

if TYPE_CHECKING:
    import os
    from collections.abc import Callable, Iterator

    from rill_core.wire.types import NetworkIdentity

ADD_METHOD = "/invoicesrpc.Invoices/AddHoldInvoice"
LOOKUP_METHOD = "/invoicesrpc.Invoices/LookupInvoiceV2"
SETTLE_METHOD = "/invoicesrpc.Invoices/SettleInvoice"
CANCEL_METHOD = "/invoicesrpc.Invoices/CancelInvoice"
DEADLINE_SECONDS = 10.0
HASH_BYTES = 32
MAX_CLTV_DELTA = 2016
MAX_EXPIRY_SECONDS = 7 * 24 * 3600
MAX_MSAT = 21_000_000 * 100_000_000 * 1000

HoldState = Literal["OPEN", "ACCEPTED", "SETTLED", "CANCELED"]
_STATES: dict[int, HoldState] = {
    lightning_pb2.Invoice.OPEN: "OPEN",
    lightning_pb2.Invoice.ACCEPTED: "ACCEPTED",
    lightning_pb2.Invoice.SETTLED: "SETTLED",
    lightning_pb2.Invoice.CANCELED: "CANCELED",
}


@dataclass(frozen=True, slots=True)
class HeldHtlc:
    """One accepted incoming HTLC part."""

    amount_msat: int
    expiry_height: int


@dataclass(frozen=True, slots=True)
class HoldInvoiceStatus:
    """What LND reports for one hold invoice; ``htlcs`` are the ACCEPTED parts only."""

    state: HoldState
    htlcs: tuple[HeldHtlc, ...]

    @property
    def held_msat(self) -> int:
        """Total currently held by accepted parts."""
        return sum(part.amount_msat for part in self.htlcs)

    @property
    def earliest_expiry_height(self) -> int | None:
        """The earliest accepted part expiry (RS-004 ``E_in``), if any."""
        return min((part.expiry_height for part in self.htlcs), default=None)


class LndHoldInvoices:
    """Loopback hold invoice management with a dedicated invoices macaroon."""

    def __init__(
        self,
        *,
        host: str,
        port: int,
        tls_certificate_path: str | os.PathLike[str],
        macaroon_path: str | os.PathLike[str],
        network: NetworkIdentity,
    ) -> None:
        """Configure only; no credential read or network dial."""
        if host not in ("127.0.0.1", "::1") or type(port) is not int or not 1 <= port <= MAX_PORT:
            raise ValueError("LND endpoint must be a numeric loopback host and port")
        try:
            backend_names(network)
        except ValidationError:
            raise ValueError("LND hold invoices require a supported network identity") from None
        self._target = f"[{host}]:{port}" if host == "::1" else f"{host}:{port}"
        self._certificate = Path(tls_certificate_path)
        self._macaroon = Path(macaroon_path)

    def add(
        self,
        payment_hash: str,
        *,
        value_msat: int,
        expiry_seconds: int,
        cltv_expiry_delta: int,
    ) -> str:
        """Open a hold invoice for ``payment_hash`` and return its BOLT11 string."""
        digest = _hash_bytes(payment_hash)
        if not (
            type(value_msat) is int
            and 0 < value_msat <= MAX_MSAT
            and value_msat % 1000 == 0
            and type(expiry_seconds) is int
            and 0 < expiry_seconds <= MAX_EXPIRY_SECONDS
            and type(cltv_expiry_delta) is int
            and 0 < cltv_expiry_delta <= MAX_CLTV_DELTA
        ):
            raise ValueError("hold invoice parameters unsupported")
        request = invoices_pb2.AddHoldInvoiceRequest(
            hash=digest,
            value_msat=value_msat,
            expiry=expiry_seconds,
            cltv_expiry=cltv_expiry_delta,
        )
        with self._connect() as calls:
            response = calls.unary(
                request=request,
                method=ADD_METHOD,
                response_type=invoices_pb2.AddHoldInvoiceResp,
                deadline=_deadline(),
            )
        bolt11 = getattr(response, "payment_request", None)
        if type(bolt11) is not str or not bolt11:
            raise LndProtocolError("LND returned no hold invoice")
        return bolt11

    def lookup(self, payment_hash: str) -> HoldInvoiceStatus:
        """Return the invoice state and its currently accepted HTLC parts."""
        request = invoices_pb2.LookupInvoiceMsg(payment_hash=_hash_bytes(payment_hash))
        with self._connect() as calls:
            invoice = calls.unary(
                request=request,
                method=LOOKUP_METHOD,
                response_type=lightning_pb2.Invoice,
                deadline=_deadline(),
            )
        state = _STATES.get(int(invoice.state))
        if state is None:
            raise LndProtocolError("LND reported an unknown invoice state")
        parts = []
        for htlc in invoice.htlcs:
            if int(htlc.state) != lightning_pb2.ACCEPTED:
                continue
            amount, expiry = int(htlc.amt_msat), int(htlc.expiry_height)
            if amount <= 0 or expiry <= 0:
                raise LndProtocolError("LND reported an invalid accepted HTLC")
            parts.append(HeldHtlc(amount_msat=amount, expiry_height=expiry))
        return HoldInvoiceStatus(state=state, htlcs=tuple(parts))

    def settle(
        self,
        preimage: str,
        *,
        deadline: float | None = None,
        submission_allowed: Callable[[], bool] | None = None,
    ) -> None:
        """Settle the hold invoice whose hash is SHA256 of ``preimage``.

        Optional guards cap dispatch with an absolute monotonic deadline and
        a repeatable, nonconsuming predicate that must return exactly True.
        Guarded calls charge setup against a fixed ten-second budget. They
        grant no financial authority and cannot terminate an in-flight RPC
        or atomically exclude concurrent revocation. Late results retain
        their meaning, without retrying or renewing caller authority.
        Omitted guards preserve the existing post-connect call budget.
        """
        request = invoices_pb2.SettleInvoiceMsg(preimage=_hash_bytes(preimage))
        if deadline is None and submission_allowed is None:
            with self._connect() as calls:
                calls.unary(
                    request=request,
                    method=SETTLE_METHOD,
                    response_type=invoices_pb2.SettleInvoiceResp,
                    deadline=_deadline(),
                )
            return
        if deadline is not None:
            try:
                valid = type(deadline) in (int, float) and math.isfinite(deadline)
            except OverflowError:
                valid = False
            if not valid:
                raise LndUnavailableError("LND settlement submission authority invalid")
        call_deadline = _deadline()
        if deadline is not None:
            call_deadline = min(call_deadline, deadline)
        _check_submission_authority(call_deadline, submission_allowed)
        with self._connect() as calls:
            calls.unary(
                request=request,
                method=SETTLE_METHOD,
                response_type=invoices_pb2.SettleInvoiceResp,
                deadline=call_deadline,
                submission_allowed=submission_allowed,
            )

    def cancel(self, payment_hash: str) -> None:
        """Cancel the hold invoice; accepted HTLCs are failed back."""
        request = invoices_pb2.CancelInvoiceMsg(payment_hash=_hash_bytes(payment_hash))
        with self._connect() as calls:
            calls.unary(
                request=request,
                method=CANCEL_METHOD,
                response_type=invoices_pb2.CancelInvoiceResp,
                deadline=_deadline(),
            )

    @contextmanager
    def _connect(self) -> Iterator[_Calls]:
        certificate = _read_file(self._certificate, MAX_CERT_BYTES, private=False)
        macaroon = _read_file(self._macaroon, MAX_MACAROON_BYTES, private=True)
        channel: grpc.Channel | None = None
        try:
            try:
                channel = grpc.secure_channel(
                    self._target,
                    grpc.ssl_channel_credentials(root_certificates=certificate),
                    options=(
                        ("grpc.max_receive_message_length", MAX_MESSAGE_BYTES),
                        ("grpc.max_send_message_length", MAX_MESSAGE_BYTES),
                        ("grpc.enable_retries", 0),
                    ),
                )
            except Exception:  # noqa: BLE001 - never echo credential details
                raise LndUnavailableError("LND hold invoice call failed") from None
            yield _Calls(channel, macaroon)
        finally:
            if channel is not None:
                with suppress(Exception):
                    channel.close()


def _hash_bytes(value: str) -> bytes:
    if type(value) is not str or len(value) != 2 * HASH_BYTES:
        raise ValueError("expected 32 bytes of hex")
    try:
        return bytes.fromhex(value)
    except ValueError:
        raise ValueError("expected 32 bytes of hex") from None


def _deadline() -> float:
    return time.monotonic() + DEADLINE_SECONDS


__all__ = [
    "HeldHtlc",
    "HoldInvoiceStatus",
    "LndHoldInvoices",
    "LndObservationError",
]
