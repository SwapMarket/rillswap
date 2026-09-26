"""Pay and track one BTC to LN invoice with the provider's regtest LND.

The caller must durably consume a one-shot dispatch grant before ``send``.
Tracking an unknown hash is not sufficient authorization to send again after
an ambiguous submission. Preparation is read-only; submission sends the exact
prepared route once, with an absolute first-hop expiry bounded by the contract.
"""

from __future__ import annotations

import hashlib
import time
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any, Literal

import grpc
from rill_core.wire.canonical import canonicalize
from rill_core.wire.types import NetworkIdentity

from rill_provider._lnd_proto import lightning_pb2
from rill_provider._lnd_proto.routerrpc import router_pb2
from rill_provider.lnd_invoice_decode import DECODE_METHOD, MAX_INVOICE_CHARS, binding_from_payreq
from rill_provider.lnd_payment_observation import (
    MAX_CERT_BYTES,
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
    from collections.abc import Callable, Iterator

    from rill_core.wire.messages import InvoiceBinding

SEND_METHOD = "/routerrpc.Router/SendToRouteV2"
QUERY_METHOD = "/lnrpc.Lightning/QueryRoutes"
INFO_METHOD = "/lnrpc.Lightning/GetInfo"
TRACK_METHOD = "/routerrpc.Router/TrackPaymentV2"
MAX_UPDATES = 64
HASH_BYTES = 32
# lnrpc.Payment.PaymentStatus
_SUCCEEDED, _FAILED = 2, 3
FINAL_CLTV_PADDING = 3
MAX_ROUTE_HOPS = 20
MAX_BLOCK_HEIGHT = 499_999_999

type Status = Literal["SUCCEEDED", "FAILED", "IN_FLIGHT", "UNKNOWN"]


@dataclass(frozen=True, slots=True)
class PaymentOutcome:
    """``UNKNOWN`` means tracking found no record, not proof of no prior send."""

    status: Status
    preimage: str | None = None


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

    @property
    def dispatch_record(self) -> bytes:
        """Self-describing custody record, distinct from older relative sends."""
        return canonicalize({"method": "SendToRouteV2", "request_hex": self.request.hex()})


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


def _outcome(stream: Iterator[lightning_pb2.Payment], payment_hash: str) -> PaymentOutcome:
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
        if count >= MAX_UPDATES:
            break
    return last


class RegtestLndPaymentSender:
    """Loopback, regtest-only explicit-route submission and payment tracking."""

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
        if not isinstance(network, NetworkIdentity) or network.name != "regtest":
            raise ValueError("LND payments require explicit regtest network identity")
        self._target = f"[{host}]:{port}" if host == "::1" else f"{host}:{port}"
        self._certificate = Path(tls_certificate_path)
        self._macaroon = Path(macaroon_path)

    def prepare(
        self,
        bolt11: str,
        *,
        invoice_binding: InvoiceBinding,
        fee_limit_sat: int,
        max_expiry_height: int,
    ) -> PreparedPayment:
        """Decode and query one route without making any payment attempt."""
        if not (
            type(fee_limit_sat) is int
            and 0 <= fee_limit_sat < 2**63 // 1000
            and type(max_expiry_height) is int
            and 0 < max_expiry_height <= MAX_BLOCK_HEIGHT
            and type(bolt11) is str
            and 0 < len(bolt11) <= MAX_INVOICE_CHARS
            and bolt11.startswith("lnbcrt")
        ):
            raise ValueError("payment bounds unsupported")
        deadline = time.monotonic() + 20
        payreq = self._unary(
            DECODE_METHOD,
            lightning_pb2.PayReqString(pay_req=bolt11),
            lightning_pb2.PayReq,
            deadline,
        )
        if binding_from_payreq(bolt11, payreq) != invoice_binding:
            raise LndProtocolError("decoded invoice differs from signed binding")
        tip = self._tip(deadline)
        limit = max_expiry_height - tip
        if (
            time.time() >= invoice_binding.expires_at
            or limit <= invoice_binding.min_final_cltv_delta
        ):
            raise LndProtocolError("payment authorization expired")
        response = self._unary(
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
        )

    def send(self, payment: PreparedPayment) -> PaymentOutcome:
        """Submit the in-memory plan from prepare() once, after its store commit.

        This is not a restored-request API. Immutable prepared bytes preserve
        the amount/fee/destination checks; only time-dependent bounds are
        refreshed here. Ambiguous outcomes require tracking, never replay.
        """
        request = router_pb2.SendToRouteRequest.FromString(payment.request)
        deadline = time.monotonic() + 60
        tip = self._tip(deadline)
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
        attempt = self._unary(
            SEND_METHOD,
            request,
            lightning_pb2.HTLCAttempt,
            deadline,
            expires_at=payment.expires_at,
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
            return self.track(payment.payment_hash)
        return PaymentOutcome("IN_FLIGHT")

    def _tip(self, deadline: float) -> int:
        info = self._unary(
            INFO_METHOD, lightning_pb2.GetInfoRequest(), lightning_pb2.GetInfoResponse, deadline
        )
        if not (
            info.synced_to_chain
            and len(info.chains) == 1
            and info.chains[0].chain == "bitcoin"
            and info.chains[0].network == "regtest"
            and 0 < info.block_height <= MAX_BLOCK_HEIGHT
        ):
            raise LndProtocolError("LND chain is not synchronized regtest")
        return int(info.block_height)

    def _unary(
        self,
        method: str,
        request: Any,  # noqa: ANN401 - pinned protobuf request
        response_type: Any,  # noqa: ANN401 - pinned protobuf response class
        deadline: float,
        *,
        expires_at: int | None = None,
    ) -> Any:  # noqa: ANN401 - pinned protobuf response class
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
                    ("grpc.max_send_message_length", MAX_MESSAGE_BYTES),
                    ("grpc.enable_retries", 0),
                ),
            )
            rpc = channel.unary_unary(
                method,
                request_serializer=type(request).SerializeToString,
                response_deserializer=response_type.FromString,
            )
            remaining = deadline - time.monotonic()
            if expires_at is not None:
                remaining = min(remaining, expires_at - time.time())
            if remaining <= 0:
                raise LndUnavailableError("LND payment deadline elapsed")  # noqa: TRY301
            return rpc(
                request,
                timeout=remaining,
                metadata=(("macaroon", macaroon.hex()),),
                wait_for_ready=False,
            )
        except grpc.RpcError as error:
            try:
                code = error.code()
            except Exception:  # noqa: BLE001 - upstream error may be malformed
                code = grpc.StatusCode.UNAVAILABLE
            if code in (grpc.StatusCode.UNAUTHENTICATED, grpc.StatusCode.PERMISSION_DENIED):
                failure = LndAuthError("LND rejected payment credentials")
            else:
                failure = LndUnavailableError("LND payment call failed; outcome unknown")
        except LndObservationError:
            raise
        except Exception:  # noqa: BLE001 - never echo invoice, route, or credential details
            failure = LndUnavailableError("LND payment call failed; outcome unknown")
        finally:
            if channel is not None:
                with suppress(Exception):
                    channel.close()
        raise failure if failure is not None else LndUnavailableError("LND payment failed")

    def track(self, payment_hash: str) -> PaymentOutcome:
        """Return current status (``UNKNOWN`` if LND reports no payment record)."""
        request = router_pb2.TrackPaymentRequest(
            payment_hash=bytes.fromhex(payment_hash), no_inflight_updates=True
        )
        return self._stream(
            TRACK_METHOD,
            request,
            router_pb2.TrackPaymentRequest.SerializeToString,
            payment_hash,
            5,
        )

    def _stream(
        self,
        method: str,
        request: Any,  # noqa: ANN401 - pinned router tracking request
        serializer: Callable[[Any], bytes],
        payment_hash: str,
        deadline: float,
    ) -> PaymentOutcome:
        if len(payment_hash) != 2 * HASH_BYTES:
            raise ValueError("payment hash must be 32 bytes of hex")
        certificate = _read_file(self._certificate, MAX_CERT_BYTES, private=False)
        macaroon = _read_file(self._macaroon, MAX_MACAROON_BYTES, private=True)
        channel: grpc.Channel | None = None
        failure: LndObservationError | PaymentOutcome | None = None
        try:
            channel = grpc.secure_channel(
                self._target,
                grpc.ssl_channel_credentials(root_certificates=certificate),
                options=(
                    ("grpc.max_receive_message_length", MAX_MESSAGE_BYTES),
                    ("grpc.max_send_message_length", 8192),
                    ("grpc.enable_retries", 0),
                ),
            )
            rpc = channel.unary_stream(
                method,
                request_serializer=serializer,
                response_deserializer=lightning_pb2.Payment.FromString,
            )
            stream = rpc(
                request,
                timeout=deadline,
                metadata=(("macaroon", macaroon.hex()),),
                wait_for_ready=False,
            )
            return _outcome(stream, payment_hash)
        except grpc.RpcError as error:
            try:
                code = error.code()
            except Exception:  # noqa: BLE001 - upstream error may be malformed
                code = grpc.StatusCode.UNAVAILABLE
            if code in (grpc.StatusCode.UNAUTHENTICATED, grpc.StatusCode.PERMISSION_DENIED):
                failure = LndAuthError("LND rejected payment credentials")
            elif method == TRACK_METHOD and code == grpc.StatusCode.NOT_FOUND:
                failure = PaymentOutcome("UNKNOWN")
            else:
                failure = LndUnavailableError("LND payment call failed; outcome unknown")
        except LndObservationError:
            raise
        except Exception:  # noqa: BLE001 - never retain invoice or credential-bearing errors
            failure = LndUnavailableError("LND payment call failed; outcome unknown")
        finally:
            if channel is not None:
                with suppress(Exception):
                    channel.close()
        if isinstance(failure, PaymentOutcome):
            return failure
        raise failure if failure is not None else LndUnavailableError("LND payment failed")
