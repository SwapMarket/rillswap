"""Pay and track one BTC to LN invoice with the provider's local LND.

The caller must durably consume a one-shot dispatch grant before ``send``.
Tracking an unknown hash is not sufficient authorization to send again after
an ambiguous submission. Preparation is read-only; submission sends the exact
prepared route once, with an absolute first-hop expiry bounded by the contract.
"""

from __future__ import annotations

import hashlib
import math
import time
from contextlib import contextmanager, suppress
from dataclasses import dataclass, replace
from pathlib import Path
from typing import TYPE_CHECKING, Any, Literal

import grpc
from rill_core.errors import ValidationError
from rill_core.networks import backend_names, invoice_matches_network

from rill_provider._lnd_proto import lightning_pb2
from rill_provider._lnd_proto.routerrpc import router_pb2
from rill_provider.lnd_invoice_decode import DECODE_METHOD, MAX_INVOICE_CHARS, binding_from_payreq
from rill_provider.lnd_payment_observation import (
    MAX_CERT_BYTES,
    MAX_MACAROON_BYTES,
    MAX_MESSAGE_BYTES,
    MAX_PORT,
    LndAuthError,
    LndNotSyncedError,
    LndObservationError,
    LndProtocolError,
    LndUnavailableError,
    _read_file,
)
from rill_provider.payment_dispatch_record import PaymentAuthority, encode_dispatch

if TYPE_CHECKING:
    import os
    from collections.abc import Callable, Iterator

    from rill_core.wire.messages import InvoiceBinding
    from rill_core.wire.types import NetworkIdentity

SEND_METHOD = "/routerrpc.Router/SendToRouteV2"
QUERY_METHOD = "/lnrpc.Lightning/QueryRoutes"
INFO_METHOD = "/lnrpc.Lightning/GetInfo"
TRACK_METHOD = "/routerrpc.Router/TrackPaymentV2"
LIST_CHANNELS_METHOD = "/lnrpc.Lightning/ListChannels"
LIQUIDITY_DEADLINE_SECONDS = 10.0
MAX_UPDATES = 64
HASH_BYTES = 32
# lnrpc.Payment.PaymentStatus
_SUCCEEDED, _FAILED = 2, 3
FINAL_CLTV_PADDING = 3
MAX_ROUTE_HOPS = 20
PREPARE_DEADLINE_SECONDS = 20.0
MAX_BLOCK_HEIGHT = 499_999_999

type Status = Literal["SUCCEEDED", "FAILED", "IN_FLIGHT", "UNKNOWN"]


@dataclass(frozen=True, slots=True)
class PaymentOutcome:
    """``UNKNOWN`` means tracking found no record, not proof of no prior send."""

    status: Status
    preimage: str | None = None
    # Node that attested this outcome on the same channel, when bound: only a
    # FAILED from the dispatch's own payer is terminal for that dispatch.
    payer: str | None = None


@dataclass(frozen=True, slots=True)
class PreparedPayment:
    """Immutable dispatch bytes from prepare(), not permission to send them.

    The store must commit ``dispatch_record`` before send(). A committed request is
    never automatically resubmitted, even if tracking cannot find the payment.
    """

    request: bytes
    payment_hash: str
    expires_at: int
    max_expiry_height: int
    min_final_cltv_delta: int
    payer: PaymentAuthority

    @property
    def dispatch_record(self) -> bytes:
        """Versioned custody record naming the LND identity that prepared it."""
        return encode_dispatch(self.request, self.payer)


def _check_route(
    route: lightning_pb2.Route,
    invoice: InvoiceBinding,
    fee_limit_sat: int,
    max_expiry_height: int,
    tip: int,
) -> None:
    amount = int(invoice.amount_msat)
    if not (
        0 < len(route.hops) <= MAX_ROUTE_HOPS
        and tip < route.total_time_lock <= max_expiry_height
        and 0 <= route.total_fees_msat <= fee_limit_sat * 1000
        and route.total_amt_msat == amount + route.total_fees_msat
        and route.first_hop_amount_msat in (0, route.total_amt_msat)
        and not route.custom_channel_data
    ):
        raise LndProtocolError("LND route exceeds payment bounds")
    final = route.hops[-1]
    if not (
        final.pub_key == invoice.payee_compressed_pubkey
        and final.amt_to_forward_msat == amount
        and final.fee_msat == 0
        and final.expiry >= tip + invoice.min_final_cltv_delta
    ):
        raise LndProtocolError("LND route does not match the invoice")
    previous_expiry = route.total_time_lock
    for hop in route.hops:
        if not (
            tip < hop.expiry <= previous_expiry
            and hop.amt_to_forward_msat >= amount
            and 0 <= hop.fee_msat <= route.total_fees_msat
        ) or (
            hop.HasField("amp_record")
            or hop.HasField("mpp_record")
            or hop.custom_records
            or hop.metadata
            or hop.blinding_point
            or hop.encrypted_data
            or hop.total_amt_msat
        ):
            raise LndProtocolError("LND route contains unsupported hop data")
        previous_expiry = hop.expiry


def _outcome(
    stream: Iterator[lightning_pb2.Payment], payment_hash: str, *, current: bool = False
) -> PaymentOutcome:
    last: PaymentOutcome = PaymentOutcome("IN_FLIGHT")
    for count, payment in enumerate(stream, start=1):
        if not isinstance(payment, lightning_pb2.Payment) or payment.payment_hash != payment_hash:
            raise LndProtocolError("LND reported another payment")
        if payment.status == _SUCCEEDED:
            preimage = payment.payment_preimage
            if (
                len(preimage) != 2 * HASH_BYTES
                or hashlib.sha256(bytes.fromhex(preimage)).hexdigest() != payment_hash
            ):
                raise LndProtocolError("LND preimage does not match the payment hash")
            return PaymentOutcome("SUCCEEDED", preimage)
        if payment.status == _FAILED:
            return PaymentOutcome("FAILED")
        if current or count >= MAX_UPDATES:
            break
    return last


class LndPaymentSender:
    """Loopback explicit-route submission and payment tracking on one network."""

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
            raise ValueError("LND payments require a supported network identity") from None
        self._lnd_network = names.lnd_network
        self._target = f"[{host}]:{port}" if host == "::1" else f"{host}:{port}"
        self._certificate = Path(tls_certificate_path)
        self._macaroon = Path(macaroon_path)
        self._network = network

    def prepare(
        self,
        bolt11: str,
        *,
        invoice_binding: InvoiceBinding,
        fee_limit_sat: int,
        max_expiry_height: int,
        deadline_seconds: float = PREPARE_DEADLINE_SECONDS,
    ) -> PreparedPayment:
        """Decode and query one route without making any payment attempt.

        ``deadline_seconds`` bounds every RPC of this call together, so a
        caller with a shared budget (route readiness) can enforce it here
        rather than abandoning a thread that keeps querying.
        """
        if not (
            type(fee_limit_sat) is int
            and 0 <= fee_limit_sat < 2**63 // 1000
            and type(max_expiry_height) is int
            and 0 < max_expiry_height <= MAX_BLOCK_HEIGHT
            and type(bolt11) is str
            and 0 < len(bolt11) <= MAX_INVOICE_CHARS
            and invoice_matches_network(bolt11, self._network)
        ):
            raise ValueError("payment bounds unsupported")
        if not (
            type(deadline_seconds) in (int, float)
            and 0 < deadline_seconds <= PREPARE_DEADLINE_SECONDS
        ):
            raise ValueError("payment bounds unsupported")
        deadline = time.monotonic() + deadline_seconds
        with self._connect() as calls:
            payreq = calls.unary(
                DECODE_METHOD,
                lightning_pb2.PayReqString(pay_req=bolt11),
                lightning_pb2.PayReq,
                deadline,
            )
            if binding_from_payreq(bolt11, payreq) != invoice_binding:
                raise LndProtocolError("decoded invoice differs from signed binding")
            tip, payer = self._attest(calls, deadline, expected=None)
            limit = max_expiry_height - tip
            if (
                time.time() >= invoice_binding.expires_at
                or limit <= invoice_binding.min_final_cltv_delta
            ):
                raise LndProtocolError("payment authorization expired")
            response = self._query(calls, payreq, fee_limit_sat, limit, deadline)
        return self._plan(
            response,
            payreq,
            invoice_binding,
            fee_limit_sat,
            max_expiry_height,
            tip,
            payer,
            deadline,
        )

    def largest_channel_send_sat(self) -> int:
        """Return the most one open channel could send now: local balance less its reserve.

        Payments take one route (no multi-part), so this bounds one payment
        before routing fees. Inactive channels count: a peer reconnecting must
        not look like spent liquidity, and route checks gate each payment.
        Indicative only; it authorizes nothing.
        """
        deadline = time.monotonic() + LIQUIDITY_DEADLINE_SECONDS
        with self._connect() as calls:
            response: lightning_pb2.ListChannelsResponse = calls.unary(
                LIST_CHANNELS_METHOD,
                lightning_pb2.ListChannelsRequest(),
                lightning_pb2.ListChannelsResponse,
                deadline,
            )
        sendable = (
            int(channel.local_balance) - int(channel.local_constraints.chan_reserve_sat)
            for channel in response.channels
        )
        return max([0, *sendable])

    @staticmethod
    def _query(
        calls: _Calls,
        payreq: lightning_pb2.PayReq,
        fee_limit_sat: int,
        limit: int,
        deadline: float,
    ) -> lightning_pb2.QueryRoutesResponse:
        return calls.unary(  # type: ignore[no-any-return]
            QUERY_METHOD,
            lightning_pb2.QueryRoutesRequest(
                pub_key=payreq.destination,
                amt_msat=payreq.num_msat,
                final_cltv_delta=payreq.cltv_expiry + FINAL_CLTV_PADDING,
                fee_limit=lightning_pb2.FeeLimit(fixed_msat=fee_limit_sat * 1000),
                cltv_limit=limit,
                route_hints=payreq.route_hints,
                dest_features=list(payreq.features),
            ),
            lightning_pb2.QueryRoutesResponse,
            deadline,
        )

    @staticmethod
    def _plan(  # noqa: PLR0913, PLR0917 - one prepared plan's explicit parts
        response: lightning_pb2.QueryRoutesResponse,
        payreq: lightning_pb2.PayReq,
        invoice_binding: InvoiceBinding,
        fee_limit_sat: int,
        max_expiry_height: int,
        tip: int,
        payer: PaymentAuthority,
        deadline: float,
    ) -> PreparedPayment:
        if len(response.routes) != 1:
            raise LndProtocolError("LND did not return one supported route")
        route = response.routes[0]
        _check_route(route, invoice_binding, fee_limit_sat, max_expiry_height, tip)
        for hop in route.hops:
            hop.tlv_payload = True
        route.hops[-1].mpp_record.CopyFrom(
            lightning_pb2.MPPRecord(
                payment_addr=payreq.payment_addr,
                total_amt_msat=payreq.num_msat,
            )
        )
        request = router_pb2.SendToRouteRequest(
            payment_hash=bytes.fromhex(invoice_binding.payment_hash),
            route=route,
            skip_temp_err=False,
        )
        if time.time() >= invoice_binding.expires_at or time.monotonic() >= deadline:
            raise LndUnavailableError("payment preparation deadline elapsed")
        return PreparedPayment(
            request.SerializeToString(),
            invoice_binding.payment_hash,
            invoice_binding.expires_at,
            max_expiry_height,
            invoice_binding.min_final_cltv_delta,
            payer,
        )

    def send(
        self,
        payment: PreparedPayment,
        *,
        deadline: float | None = None,
        submission_allowed: Callable[[], bool] | None = None,
    ) -> PaymentOutcome:
        """Submit the in-memory plan from prepare() once, after its store commit.

        This is not a restored-request API. Immutable prepared bytes preserve
        the amount/fee/destination checks; only time-dependent bounds are
        refreshed here. Ambiguous outcomes require tracking, never replay.
        ``LndNotSyncedError`` from this method proves pre-submission refusal;
        a sync failure while reconciling a submitted attempt is unavailable
        evidence, not permission to submit again.

        An optional absolute monotonic deadline caps the normal call budget.
        The nonconsuming predicate must return exactly True at every check.
        These fence submission authorization, not physical completion of an
        RPC already started. Late results do not renew caller authority.
        """
        if deadline is not None and (
            type(deadline) not in (int, float) or not math.isfinite(deadline)
        ):
            raise LndUnavailableError("LND payment submission authority invalid")
        deadline = (
            min(time.monotonic() + 60, deadline) if deadline is not None else time.monotonic() + 60
        )
        _check_submission_authority(deadline, submission_allowed)
        request = router_pb2.SendToRouteRequest.FromString(payment.request)
        # Attest the bound payer on the channel that carries the submission.
        with self._connect() as calls:
            tip, _ = self._attest(calls, deadline, expected=payment.payer)
            _check_submission_authority(deadline, submission_allowed)
            if not (
                request.payment_hash.hex() == payment.payment_hash
                and not request.skip_temp_err
                and 0 < len(request.route.hops) <= MAX_ROUTE_HOPS
                and tip < request.route.total_time_lock <= payment.max_expiry_height
                and all(tip < hop.expiry <= payment.max_expiry_height for hop in request.route.hops)
                and payment.min_final_cltv_delta > 0
                and request.route.hops[-1].expiry >= tip + payment.min_final_cltv_delta
                and time.time() < payment.expires_at
            ):
                raise LndProtocolError("prepared payment is expired or inconsistent")
            attempt = calls.unary(
                SEND_METHOD,
                request,
                lightning_pb2.HTLCAttempt,
                deadline,
                expires_at=payment.expires_at,
                submission_allowed=submission_allowed,
            )
        if attempt.status == lightning_pb2.HTLCAttempt.SUCCEEDED:
            if (
                len(attempt.preimage) != HASH_BYTES
                or hashlib.sha256(attempt.preimage).hexdigest() != payment.payment_hash
            ):
                raise LndProtocolError("LND preimage does not match the payment hash")
            return PaymentOutcome("SUCCEEDED", attempt.preimage.hex())
        # An attempt failure alone need not prove the whole payment failed.
        # Reconcile the payment-level record; never authorize another shard.
        if attempt.status == lightning_pb2.HTLCAttempt.FAILED:
            try:
                return self.track(payment.payment_hash, payer=payment.payer)
            except LndNotSyncedError:
                raise LndUnavailableError(
                    "LND payment reconciliation unavailable after submission; outcome unknown"
                ) from None
        return PaymentOutcome("IN_FLIGHT")

    def _attest(
        self, calls: _Calls, deadline: float, *, expected: PaymentAuthority | None
    ) -> tuple[int, PaymentAuthority]:
        """GetInfo on this channel: synced tip on our network and the payer identity.

        A mismatch with a bound dispatch's payer refuses the call rather than
        letting another node's history speak for the original payment.
        """
        info = calls.unary(
            INFO_METHOD, lightning_pb2.GetInfoRequest(), lightning_pb2.GetInfoResponse, deadline
        )
        if not (
            len(info.chains) == 1
            and info.chains[0].chain == "bitcoin"
            and info.chains[0].network == self._lnd_network
            and 0 < info.block_height <= MAX_BLOCK_HEIGHT
        ):
            raise LndProtocolError("LND chain is not the synchronized configured network")
        if not info.synced_to_chain:  # transient: LND catches up after each new block
            raise LndNotSyncedError("LND chain is not the synchronized configured network")
        try:
            payer = PaymentAuthority(info.identity_pubkey, self._network)
        except (TypeError, ValueError):
            raise LndProtocolError("LND identity unsupported") from None
        if expected is not None and payer != expected:
            raise LndProtocolError("LND payer differs from the bound dispatch")
        return int(info.block_height), payer

    @contextmanager
    def _connect(self) -> Iterator[_Calls]:
        """One credential snapshot and channel for a bound sequence of calls."""
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
                raise LndUnavailableError("LND payment call failed; outcome unknown") from None
            yield _Calls(channel, macaroon)
        finally:
            if channel is not None:
                with suppress(Exception):
                    channel.close()

    def track(
        self,
        payment_hash: str,
        *,
        payer: PaymentAuthority | None = None,
        current: bool = False,
    ) -> PaymentOutcome:
        """Return current status (``UNKNOWN`` if LND reports no payment record).

        Without ``payer`` this reports whatever the configured node knows. With
        a bound payer, GetInfo on the same channel must match it first, so a
        negative result is attributable to the original payer. By default an
        in-flight payment is waited on briefly for a final state; ``current``
        returns LND's first update instead, so a held payment reads
        ``IN_FLIGHT`` at once.
        """
        request = router_pb2.TrackPaymentRequest(
            payment_hash=bytes.fromhex(payment_hash), no_inflight_updates=not current
        )
        if len(payment_hash) != 2 * HASH_BYTES:
            raise ValueError("payment hash must be 32 bytes of hex")
        deadline = time.monotonic() + 10
        with self._connect() as calls:
            if payer is not None:
                self._attest(calls, deadline, expected=payer)
            outcome = calls.track(
                request, payment_hash, min(5.0, deadline - time.monotonic()), current=current
            )
        if payer is None:
            return outcome
        return replace(outcome, payer=payer.node_pubkey)


def _check_submission_authority(
    deadline: float, submission_allowed: Callable[[], bool] | None
) -> None:
    """Fence both sides of a caller predicate, including a delayed callback."""
    if time.monotonic() >= deadline:
        raise LndUnavailableError("LND payment submission deadline elapsed")
    if submission_allowed is not None:
        try:
            allowed = submission_allowed() is True
        except Exception:  # noqa: BLE001 - caller details may contain secrets
            allowed = False
        if not allowed:
            raise LndUnavailableError("LND payment submission authority unavailable")
    if time.monotonic() >= deadline:
        raise LndUnavailableError("LND payment submission deadline elapsed")


class _Calls:
    """Calls over one channel and credential snapshot, with redacted errors."""

    def __init__(self, channel: grpc.Channel, macaroon: bytes) -> None:
        self._channel = channel
        self._metadata = (("macaroon", macaroon.hex()),)

    def unary(  # noqa: PLR0913 - explicit RPC bounds and optional submission guard
        self,
        method: str,
        request: Any,  # noqa: ANN401 - pinned protobuf request
        response_type: Any,  # noqa: ANN401 - pinned protobuf response class
        deadline: float,
        *,
        expires_at: int | None = None,
        submission_allowed: Callable[[], bool] | None = None,
    ) -> Any:  # noqa: ANN401 - pinned protobuf response class
        failure: LndObservationError | None = None
        try:
            rpc = self._channel.unary_unary(
                method,
                request_serializer=type(request).SerializeToString,
                response_deserializer=response_type.FromString,
            )
            if submission_allowed is not None:
                _check_submission_authority(deadline, submission_allowed)
            remaining = deadline - time.monotonic()
            if expires_at is not None:
                remaining = min(remaining, expires_at - time.time())
            if remaining <= 0:
                raise LndUnavailableError("LND payment deadline elapsed")  # noqa: TRY301
            return rpc(request, timeout=remaining, metadata=self._metadata, wait_for_ready=False)
        except grpc.RpcError as error:
            failure = _rpc_failure(error)
        except LndObservationError:
            raise
        except Exception:  # noqa: BLE001 - never echo invoice, route, or credential details
            failure = LndUnavailableError("LND payment call failed; outcome unknown")
        raise failure

    def track(
        self,
        request: router_pb2.TrackPaymentRequest,
        payment_hash: str,
        timeout: float,
        *,
        current: bool = False,
    ) -> PaymentOutcome:
        if timeout <= 0:
            raise LndUnavailableError("LND payment deadline elapsed")
        try:
            rpc = self._channel.unary_stream(
                TRACK_METHOD,
                request_serializer=router_pb2.TrackPaymentRequest.SerializeToString,
                response_deserializer=lightning_pb2.Payment.FromString,
            )
            stream = rpc(request, timeout=timeout, metadata=self._metadata, wait_for_ready=False)
            return _outcome(stream, payment_hash, current=current)
        except grpc.RpcError as error:
            if _code(error) == grpc.StatusCode.NOT_FOUND:
                return PaymentOutcome("UNKNOWN")
            raise _rpc_failure(error) from None
        except LndObservationError:
            raise
        except Exception:  # noqa: BLE001 - never retain invoice or credential-bearing errors
            raise LndUnavailableError("LND payment call failed; outcome unknown") from None


def _code(error: grpc.RpcError) -> grpc.StatusCode:
    try:
        return error.code()
    except Exception:  # noqa: BLE001 - upstream error may be malformed
        return grpc.StatusCode.UNAVAILABLE


def _rpc_failure(error: grpc.RpcError) -> LndObservationError:
    if _code(error) in (grpc.StatusCode.UNAUTHENTICATED, grpc.StatusCode.PERMISSION_DENIED):
        return LndAuthError("LND rejected payment credentials")
    return LndUnavailableError("LND payment call failed; outcome unknown")
