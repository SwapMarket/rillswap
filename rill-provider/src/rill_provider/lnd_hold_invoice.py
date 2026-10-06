"""Loopback LND hold invoices for LN to BTC swaps (RS-004).

The provider opens a hold invoice for the client's ``payment_hash``, watches
it until every HTLC is ``ACCEPTED``, funds the contract, and settles the
invoice only once it holds the verified preimage. Cancelation happens only
before funding or after a confirmed refund; the caller owns those rules.
Errors never carry invoice, preimage, or credential material.
"""

from __future__ import annotations

import hashlib
import math
import time
from contextlib import contextmanager, suppress
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Literal

import grpc
from rill_core.errors import ValidationError
from rill_core.networks import backend_names, invoice_matches_network
from rill_core.wire.messages import InvoiceBinding

from rill_provider._lnd_proto import lightning_pb2
from rill_provider._lnd_proto.invoicesrpc import invoices_pb2
from rill_provider.lnd_payment_observation import (
    MAX_CERT_BYTES,
    MAX_MACAROON_BYTES,
    MAX_MESSAGE_BYTES,
    MAX_PORT,
    LndNotSyncedError,
    LndObservationError,
    LndProtocolError,
    LndUnavailableError,
    _info_snapshot,
    _read_file,
)
from rill_provider.lnd_payment_send import INFO_METHOD, _Calls, _check_submission_authority

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


class _BoundInvoiceSyncBeforeSubmissionError(LndNotSyncedError):
    """Report bound settlement sync refusal before this invocation's dispatch.

    This is a trusted adapter contract, not proof about earlier or concurrent
    submissions, invoice payment, custody, or permission to repeat settlement.
    """


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


@dataclass(frozen=True, slots=True)
class BoundHoldInvoiceObservation:
    """Non-atomic Own-LND assertions, never financial or signing authority."""

    payment_hash: str
    bolt11_sha256: str
    node_pubkey: str
    network: NetworkIdentity
    status: HoldInvoiceStatus
    last_lnd_height: int
    last_lnd_block_hash: str


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
            names = backend_names(network)
        except ValidationError:
            raise ValueError("LND hold invoices require a supported network identity") from None
        self._target = f"[{host}]:{port}" if host == "::1" else f"{host}:{port}"
        self._network = network
        self._lnd_network = names.lnd_network
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
        return _invoice_status(invoice)

    def observe_bound_invoice(
        self,
        expected: InvoiceBinding,
        *,
        deadline: float | None = None,
        submission_allowed: Callable[[], bool] | None = None,
    ) -> BoundHoldInvoiceObservation:
        """Observe an original invoice between two same-channel identity checks.

        The caller supplies a previously signature-validated invoice binding
        from authenticated original terms, and must measure the full observation
        interval and independently assess freshness and economic eligibility.
        A typed binding alone proves no provenance. The configured invoices
        credential also needs info:read; there is no credential fallback.

        These three separate RPCs attest neither atomic invoice state, exclusive
        custody, original process identity, nor genesis or signet challenge.
        The last reported tip is not necessarily current or an ancestor of
        subsequent tips. Observed rollback or same-height reorganization refuses
        the batch. Late final responses retain knowledge, not renewed authority.
        No settlement, retry, nonce, or store mutation occurs.
        """
        if not isinstance(expected, InvoiceBinding):
            raise LndProtocolError("LND original invoice binding unsupported")
        call_deadline = _bounded_deadline(deadline)
        _check_submission_authority(call_deadline, submission_allowed)
        with self._connect() as calls:
            observation, _ = self._observe_bound_invoice_on_calls(
                calls, expected, call_deadline, submission_allowed
            )
        return observation

    def _observe_bound_invoice_on_calls(
        self,
        calls: _Calls,
        expected: InvoiceBinding,
        deadline: float,
        submission_allowed: Callable[[], bool] | None,
    ) -> tuple[BoundHoldInvoiceObservation, lightning_pb2.Invoice]:
        """Keep original correspondence checks on the caller's credential/channel snapshot."""
        key = bytes.fromhex(expected.payee_compressed_pubkey)
        first_info = calls.unary(
            INFO_METHOD,
            lightning_pb2.GetInfoRequest(),
            lightning_pb2.GetInfoResponse,
            deadline,
            submission_allowed=submission_allowed,
        )
        first_height, first_hash = _bound_tip(first_info, key, self._lnd_network)
        invoice = calls.unary(
            LOOKUP_METHOD,
            invoices_pb2.LookupInvoiceMsg(payment_hash=bytes.fromhex(expected.payment_hash)),
            lightning_pb2.Invoice,
            deadline,
            submission_allowed=submission_allowed,
        )
        _check_bound_invoice(invoice, expected, self._network)
        status = _invoice_status(invoice)
        last_info = calls.unary(
            INFO_METHOD,
            lightning_pb2.GetInfoRequest(),
            lightning_pb2.GetInfoResponse,
            deadline,
            submission_allowed=submission_allowed,
        )
        last_height, last_hash = _bound_tip(last_info, key, self._lnd_network)
        if last_height < first_height or (last_height == first_height and last_hash != first_hash):
            raise LndProtocolError("LND invoice observation tip changed inconsistently")
        observation = BoundHoldInvoiceObservation(
            expected.payment_hash,
            expected.bolt11_sha256,
            expected.payee_compressed_pubkey,
            self._network,
            status,
            last_height,
            last_hash,
        )
        return observation, invoice

    def observe_bound_settled_invoice(
        self,
        expected: InvoiceBinding,
        *,
        deadline: float | None = None,
        submission_allowed: Callable[[], bool] | None = None,
    ) -> BoundHoldInvoiceObservation:
        """Require sufficiently paid original-invoice knowledge from this invocation.

        The trusted runtime must collect this actual call, not substitute an
        ordinary observation of the same type. Successful return requires a
        bound SETTLED invoice with paid amount at least the original amount.
        As with observe_bound_invoice, the caller supplies authenticated original
        terms and synchronized original LND. A dedicated observer can use exact
        URI permissions for GetInfo and LookupInvoiceV2. Pinned LND maps the
        latter to invoices:write, so info:read plus invoices:read is insufficient.
        Three reads use one channel and a fixed setup-inclusive transport budget;
        no settlement, fallback, retry, or nonce allocation occurs.

        Late final knowledge retains its meaning, not freshness or signing
        authority. The caller must independently recheck its original window,
        complete acquisition interval, chain, fees, and custody before effects.
        This is neither atomic state nor transferable acquisition provenance.
        """
        if not isinstance(expected, InvoiceBinding):
            raise LndProtocolError("LND original invoice binding unsupported")
        call_deadline = _bounded_deadline(deadline)
        _check_submission_authority(call_deadline, submission_allowed)
        with self._connect() as calls:
            observation, invoice = self._observe_bound_invoice_on_calls(
                calls, expected, call_deadline, submission_allowed
            )
        if invoice.state != lightning_pb2.Invoice.SETTLED or (
            invoice.amt_paid_msat < int(expected.amount_msat)
        ):
            raise LndProtocolError("LND original invoice is not sufficiently settled")
        return observation

    def settle_bound_invoice(
        self,
        expected: InvoiceBinding,
        preimage: str,
        *,
        deadline: float | None = None,
        submission_allowed: Callable[[], bool] | None = None,
    ) -> None:
        """Dispatch once after checking the original invoice on this channel.

        The trusted caller must already have authenticated the original binding
        and durably admitted settlement debt. These checks grant no financial
        or signing authority. The configured credential also needs info:read.
        A channel can reconnect; this is trusted-service correspondence, not
        proof of one physical connection, original process, or exclusive custody.

        None means the RPC succeeded or a sufficiently paid original invoice
        was observed. It is not current signing eligibility or post-RPC payment
        reconciliation. Late success retains its meaning; any failure after
        dispatch may be ambiguous and never authorizes a retry or fallback.
        """
        if not isinstance(expected, InvoiceBinding):
            raise LndProtocolError("LND original invoice binding unsupported")
        try:
            secret = _hash_bytes(preimage)
            matches = (
                len(secret) == HASH_BYTES
                and secret.hex() == preimage
                and hashlib.sha256(secret).hexdigest() == expected.payment_hash
            )
        except ValueError:
            matches = False
        if not matches:
            raise LndProtocolError("LND bound settlement preimage unsupported")
        call_deadline = _bounded_deadline(deadline)
        _check_submission_authority(call_deadline, submission_allowed)
        with self._connect() as calls:
            try:
                observation, invoice = self._observe_bound_invoice_on_calls(
                    calls, expected, call_deadline, submission_allowed
                )
            except LndNotSyncedError:
                # Only these read-only observations precede the dispatch below.
                # Never translate setup, dispatch, or context-exit failures.
                raise _BoundInvoiceSyncBeforeSubmissionError(
                    "LND invoice observation requires a synchronized tip"
                ) from None
            amount = int(expected.amount_msat)
            if observation.status.state == "SETTLED":
                if invoice.amt_paid_msat < amount:
                    raise LndProtocolError("LND settled invoice paid amount inconsistent")
                return
            if observation.status.state != "ACCEPTED" or observation.status.held_msat != amount:
                raise LndProtocolError("LND bound settlement hold is not accepted as agreed")
            calls.unary(
                SETTLE_METHOD,
                invoices_pb2.SettleInvoiceMsg(preimage=secret),
                invoices_pb2.SettleInvoiceResp,
                call_deadline,
                submission_allowed=submission_allowed,
            )

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
        call_deadline = _bounded_deadline(deadline)
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


def _invoice_status(invoice: lightning_pb2.Invoice) -> HoldInvoiceStatus:
    """Preserve the ordinary lookup's state and accepted-part interpretation."""
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


def _bound_tip(info: lightning_pb2.GetInfoResponse, key: bytes, network: str) -> tuple[int, str]:
    snapshot = _info_snapshot(info, key, network)
    if not snapshot.synced_to_chain:
        raise LndNotSyncedError("LND invoice observation requires a synchronized tip")
    if snapshot.block_height <= 0:
        raise LndProtocolError("LND invoice observation requires a synchronized tip")
    try:
        valid_hash = _hash_bytes(info.block_hash).hex() == info.block_hash
    except ValueError:
        valid_hash = False
    if not valid_hash:
        raise LndProtocolError("LND invoice observation block hash unsupported")
    return snapshot.block_height, info.block_hash


def _check_bound_invoice(
    invoice: lightning_pb2.Invoice, expected: InvoiceBinding, network: NetworkIdentity
) -> None:
    if not isinstance(invoice, lightning_pb2.Invoice):
        raise LndProtocolError("LND invoice observation response unsupported")
    try:
        digest = hashlib.sha256(invoice.payment_request.encode("ascii")).hexdigest()
    except UnicodeEncodeError:
        raise LndProtocolError("LND invoice observation encoding unsupported") from None
    if not (
        invoice.r_hash == bytes.fromhex(expected.payment_hash)
        and digest == expected.bolt11_sha256
        and invoice_matches_network(invoice.payment_request, network)
        and invoice.value_msat == int(expected.amount_msat)
        and invoice.creation_date == expected.created_at
        and invoice.expiry > 0
        and invoice.creation_date + invoice.expiry == expected.expires_at
        and invoice.cltv_expiry == expected.min_final_cltv_delta
    ):
        raise LndProtocolError("LND invoice observation differs from original binding")


def _bounded_deadline(deadline: float | None) -> float:
    """Validate and freeze the shared guarded hold-call budget before setup."""
    if deadline is not None:
        try:
            valid = type(deadline) in (int, float) and math.isfinite(deadline)
        except OverflowError:
            valid = False
        if not valid:
            raise LndUnavailableError("LND settlement submission authority invalid")
    local = _deadline()
    return local if deadline is None else min(local, deadline)


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
    "BoundHoldInvoiceObservation",
    "HeldHtlc",
    "HoldInvoiceStatus",
    "LndHoldInvoices",
    "LndObservationError",
]
