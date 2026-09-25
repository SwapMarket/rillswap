"""Pay and track one BTC to LN invoice with the provider's regtest LND.

The caller must durably record the payment intent (swap state ``PAYING``)
before ``send``. LND refuses a second payment for a hash that is in flight or
succeeded, and ``track`` is always tried first after a restart, so one intent
never becomes two payments. ``cltv_limit`` bounds the absolute HTLC expiry
by the signed ``max_outgoing_htlc_expiry_height`` (RS-003).
"""

from __future__ import annotations

import hashlib
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any, Literal

import grpc
from rill_core.wire.types import NetworkIdentity

from rill_provider._lnd_proto import lightning_pb2
from rill_provider._lnd_proto.routerrpc import router_pb2
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

SEND_METHOD = "/routerrpc.Router/SendPaymentV2"
TRACK_METHOD = "/routerrpc.Router/TrackPaymentV2"
MAX_UPDATES = 64
HASH_BYTES = 32
# lnrpc.Payment.PaymentStatus
_SUCCEEDED, _FAILED = 2, 3

type Status = Literal["SUCCEEDED", "FAILED", "IN_FLIGHT", "UNKNOWN"]


@dataclass(frozen=True, slots=True)
class PaymentOutcome:
    """``UNKNOWN`` means LND has no payment for the hash (never sent)."""

    status: Status
    preimage: str | None = None


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
    """Loopback, regtest-only ``SendPaymentV2``/``TrackPaymentV2``."""

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

    def send(
        self,
        bolt11: str,
        *,
        payment_hash: str,
        fee_limit_sat: int,
        cltv_limit: int,
        timeout_seconds: int = 60,
    ) -> PaymentOutcome:
        """Submit one payment and wait (bounded) for its result.

        A deadline or dropped stream returns ``IN_FLIGHT``: LND keeps paying,
        and the next call should ``track``.
        """
        if not (fee_limit_sat >= 0 and cltv_limit > 0 and 0 < timeout_seconds <= 600):  # noqa: PLR2004
            raise ValueError("payment bounds unsupported")
        request = router_pb2.SendPaymentRequest(
            payment_request=bolt11,
            timeout_seconds=timeout_seconds,
            fee_limit_sat=fee_limit_sat,
            cltv_limit=cltv_limit,
            no_inflight_updates=True,
        )
        return self._stream(
            SEND_METHOD,
            request,
            router_pb2.SendPaymentRequest.SerializeToString,
            payment_hash,
            timeout_seconds + 5,
        )

    def track(self, payment_hash: str) -> PaymentOutcome:
        """Return the current status of a payment by hash (``UNKNOWN`` if never sent)."""
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
        request: Any,  # noqa: ANN401 - one of two router request messages
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
            elif method == SEND_METHOD and code == grpc.StatusCode.DEADLINE_EXCEEDED:
                failure = PaymentOutcome("IN_FLIGHT")  # LND keeps the payment going
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
