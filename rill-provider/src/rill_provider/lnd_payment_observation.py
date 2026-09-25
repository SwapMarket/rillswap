"""Explicit, bounded, read-only LND v0.21.0-beta outgoing payment observation.

Payment and HTLC attempt statuses have different meanings. No journal writes,
retries, payments, invoices, reconciliation, or permission to act follow from
this diagnostic. Missing history is never proof a payment was not attempted.
"""

from __future__ import annotations

import os
import stat
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Literal

import grpc
from rill_core.wire.types import NetworkIdentity

from rill_provider._lnd_proto import lightning_pb2
from rill_provider._lnd_proto.routerrpc import router_pb2

if TYPE_CHECKING:
    from collections.abc import Iterator

TRACK_METHOD = "/routerrpc.Router/TrackPaymentV2"
INFO_METHOD = "/lnrpc.Lightning/GetInfo"
MAX_CERT_BYTES = 64 * 1024
MAX_MACAROON_BYTES = 4096
MAX_MESSAGE_BYTES = 256 * 1024
MAX_UPDATES = 16
MAX_ATTEMPTS = 32
DEFAULT_DEADLINE_SECONDS = 10.0
MAX_DEADLINE_SECONDS = 30.0
PAYMENT_HASH_BYTES = 32
MAX_PORT = 65535
MAX_HEIGHT = 0xFFFFFFFF
COMPRESSED_KEY_BYTES = 33

type PaymentStatus = Literal["INITIATED", "IN_FLIGHT", "SUCCEEDED", "FAILED"]
type AttemptStatus = Literal["IN_FLIGHT", "SUCCEEDED", "FAILED"]
type Completion = Literal["terminal", "update-limit"]

PAYMENT_STATUSES: dict[int, PaymentStatus] = {
    4: "INITIATED",
    1: "IN_FLIGHT",
    2: "SUCCEEDED",
    3: "FAILED",
}
ATTEMPT_STATUSES: dict[int, AttemptStatus] = {
    0: "IN_FLIGHT",
    1: "SUCCEEDED",
    2: "FAILED",
}


@dataclass(frozen=True, slots=True)
class HtlcAttemptSnapshot:
    """One LND HTLC attempt ID and its own status, not a Rill attempt ID."""

    lnd_attempt_id: int
    status: AttemptStatus


@dataclass(frozen=True, slots=True)
class PaymentSnapshot:
    """Payment-level status and separately reported HTLC attempts."""

    payment_hash: str
    status: PaymentStatus
    htlc_attempts: tuple[HtlcAttemptSnapshot, ...]


@dataclass(frozen=True, slots=True)
class TrackResult:
    """Finite diagnostic result; not backend action or durable evidence."""

    completion: Completion
    snapshots: tuple[PaymentSnapshot, ...]


@dataclass(frozen=True, slots=True)
class LndInfoSnapshot:
    """One TLS-authenticated endpoint's claims, not Rill network attestation."""

    node_pubkey: str
    block_height: int
    synced_to_chain: bool
    synced_to_graph: bool


class LndObservationError(ValueError):
    """Requested LND evidence was not established, never proof of absence."""


class LndAuthError(LndObservationError):
    """Configured credential or authenticated endpoint was unusable."""


class LndUnavailableError(LndObservationError):
    """LND did not provide a complete diagnostic stream within its bound."""


class LndProtocolError(LndObservationError):
    """LND response did not match the requested payment or supported schema."""


def _read_file(path: Path, limit: int, *, private: bool) -> bytes:
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, "rb", closefd=True) as stream:
            metadata = os.fstat(stream.fileno())
            usable = stat.S_ISREG(metadata.st_mode) and not (private and metadata.st_mode & 0o077)
            contents = stream.read(limit + 1) if usable else b""
    except (OSError, ValueError):
        pass
    else:
        if usable and 0 < len(contents) <= limit:
            return contents
    # Raise outside the original handler: `from None` would hide, not remove,
    # a secret-bearing upstream exception's __context__.
    raise LndAuthError("LND credential file unavailable or invalid")


def _snapshot(payment: lightning_pb2.Payment, expected_hash: str) -> PaymentSnapshot:
    if not isinstance(payment, lightning_pb2.Payment) or payment.payment_hash != expected_hash:
        raise LndProtocolError("LND returned another or malformed payment hash")
    payment_status = PAYMENT_STATUSES.get(payment.status)
    if payment_status is None or len(payment.htlcs) > MAX_ATTEMPTS:
        raise LndProtocolError("LND payment status or HTLC count unsupported")
    attempts: list[HtlcAttemptSnapshot] = []
    seen: set[int] = set()
    for htlc in payment.htlcs:
        status = ATTEMPT_STATUSES.get(htlc.status)
        if htlc.attempt_id <= 0 or htlc.attempt_id in seen or status is None:
            raise LndProtocolError("LND HTLC attempt status or identifier unsupported")
        seen.add(htlc.attempt_id)
        attempts.append(HtlcAttemptSnapshot(htlc.attempt_id, status))
    return PaymentSnapshot(expected_hash, payment_status, tuple(attempts))


def _collect(stream: Iterator[lightning_pb2.Payment], expected_hash: str) -> TrackResult:
    snapshots: list[PaymentSnapshot] = []
    for payment in stream:
        snapshot = _snapshot(payment, expected_hash)
        snapshots.append(snapshot)
        if snapshot.status in ("SUCCEEDED", "FAILED"):
            return TrackResult("terminal", tuple(snapshots))
        if len(snapshots) >= MAX_UPDATES:
            return TrackResult("update-limit", tuple(snapshots))
    raise LndUnavailableError("LND track stream ended without terminal evidence")


def _info_snapshot(info: lightning_pb2.GetInfoResponse, expected_key: bytes) -> LndInfoSnapshot:
    if not isinstance(info, lightning_pb2.GetInfoResponse):
        raise LndProtocolError("LND info response is malformed")
    try:
        reported_key = bytes.fromhex(info.identity_pubkey)
    except ValueError:
        reported_key = b""
    if reported_key != expected_key or info.identity_pubkey != expected_key.hex():
        raise LndProtocolError("LND node identity differs from configured identity")
    if (
        len(info.chains) != 1
        or info.chains[0].chain != "bitcoin"
        or info.chains[0].network != "regtest"
        or type(info.block_height) is not int
        or not 0 <= info.block_height <= MAX_HEIGHT
        or type(info.synced_to_chain) is not bool
        or type(info.synced_to_graph) is not bool
    ):
        raise LndProtocolError("LND reported unsupported chain or sync information")
    return LndInfoSnapshot(
        expected_key.hex(), info.block_height, info.synced_to_chain, info.synced_to_graph
    )


class RegtestLndInfoObserver:
    """Separate info:read, operator-invoked GetInfo diagnostic; never admission."""

    def __init__(  # noqa: PLR0913 - explicit endpoint, trust root, credential and pin
        self,
        *,
        host: str,
        port: int,
        tls_certificate_path: str | os.PathLike[str],
        info_macaroon_path: str | os.PathLike[str],
        network: NetworkIdentity,
        expected_node_pubkey: str,
    ) -> None:
        """Validate public configuration without reading files or dialing."""
        if host not in ("127.0.0.1", "::1") or type(port) is not int or not 1 <= port <= MAX_PORT:
            raise ValueError("LND endpoint must be a numeric loopback host and port")
        if not isinstance(network, NetworkIdentity) or network.name != "regtest":
            raise ValueError("LND diagnostic requires explicit regtest network identity")
        if (
            type(expected_node_pubkey) is not str
            or len(expected_node_pubkey) != COMPRESSED_KEY_BYTES * 2
        ):
            raise ValueError("expected LND node key must be compressed lowercase hex")
        try:
            key = bytes.fromhex(expected_node_pubkey)
        except ValueError:
            key = b""
        if (
            len(key) != COMPRESSED_KEY_BYTES
            or key[0] not in (2, 3)
            or key.hex() != expected_node_pubkey
        ):
            raise ValueError("expected LND node key must be compressed lowercase hex")
        self._target = f"[{host}]:{port}" if host == "::1" else f"{host}:{port}"
        self._certificate = Path(tls_certificate_path)
        self._macaroon = Path(info_macaroon_path)
        self._expected_key = key

    def get_info(self, *, deadline_seconds: float = DEFAULT_DEADLINE_SECONDS) -> LndInfoSnapshot:
        """Return bounded endpoint claims; no network, journal, or payment authority."""
        if (
            type(deadline_seconds) not in (float, int)
            or not 0 < deadline_seconds <= MAX_DEADLINE_SECONDS
        ):
            raise ValueError("LND observation deadline must be within (0, 30] seconds")
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
                INFO_METHOD,
                request_serializer=lightning_pb2.GetInfoRequest.SerializeToString,
                response_deserializer=lightning_pb2.GetInfoResponse.FromString,
            )
            info = rpc(
                lightning_pb2.GetInfoRequest(),
                timeout=deadline_seconds,
                metadata=(("macaroon", macaroon.hex()),),
                wait_for_ready=False,
            )
            return _info_snapshot(info, self._expected_key)
        except grpc.RpcError as error:
            try:
                denied = error.code() in (
                    grpc.StatusCode.UNAUTHENTICATED,
                    grpc.StatusCode.PERMISSION_DENIED,
                )
            except Exception:  # noqa: BLE001 - malformed upstream error
                denied = False
            failure = (
                LndAuthError("LND rejected read-only information credentials")
                if denied
                else LndUnavailableError("LND information unavailable; no readiness claim")
            )
        except LndObservationError:
            raise
        except Exception:  # noqa: BLE001 - never retain credential-bearing upstream errors
            failure = LndUnavailableError("LND information unavailable; no readiness claim")
        finally:
            if channel is not None:
                with suppress(Exception):
                    channel.close()
        if failure is None:
            raise LndUnavailableError("LND information unavailable; no readiness claim")
        raise failure


class RegtestLndPaymentObserver:
    """Operator-invoked TLS diagnostic only; construction does no I/O.

    TLS authenticates a configured endpoint, not the complete network
    identity or actual journal intent. The caller must separately check node
    identity, network, and durable payment-intent correlation before acting.
    """

    def __init__(
        self,
        *,
        host: str,
        port: int,
        tls_certificate_path: str | os.PathLike[str],
        read_macaroon_path: str | os.PathLike[str],
        network: NetworkIdentity,
    ) -> None:
        """Configure one explicit regtest observer without reading files or dialing LND."""
        if host not in ("127.0.0.1", "::1") or type(port) is not int or not 1 <= port <= MAX_PORT:
            raise ValueError("LND endpoint must be a numeric loopback host and port")
        if not isinstance(network, NetworkIdentity) or network.name != "regtest":
            raise ValueError("LND diagnostic requires explicit regtest network identity")
        self._target = f"[{host}]:{port}" if host == "::1" else f"{host}:{port}"
        self._certificate = Path(tls_certificate_path)
        self._macaroon = Path(read_macaroon_path)

    def track(
        self, payment_hash: bytes, *, deadline_seconds: float = DEFAULT_DEADLINE_SECONDS
    ) -> TrackResult:
        """Receive at most 16 updates by hash with a total RPC deadline.

        The preflight does not read secrets or open the network. A gRPC
        deadline cancels tracking, not the underlying outgoing payment.
        """
        if not isinstance(payment_hash, bytes) or len(payment_hash) != PAYMENT_HASH_BYTES:
            raise ValueError("payment hash must be exactly 32 bytes")
        if (
            type(deadline_seconds) not in (float, int)
            or not 0 < deadline_seconds <= MAX_DEADLINE_SECONDS
        ):
            raise ValueError("LND observation deadline must be within (0, 30] seconds")
        certificate = _read_file(self._certificate, MAX_CERT_BYTES, private=False)
        macaroon = _read_file(self._macaroon, MAX_MACAROON_BYTES, private=True)
        channel: grpc.Channel | None = None
        stream: Iterator[lightning_pb2.Payment] | None = None
        failure: LndObservationError | None = None
        try:
            credentials = grpc.ssl_channel_credentials(root_certificates=certificate)
            channel = grpc.secure_channel(
                self._target,
                credentials,
                options=(
                    ("grpc.max_receive_message_length", MAX_MESSAGE_BYTES),
                    ("grpc.max_send_message_length", 1024),
                    ("grpc.enable_retries", 0),
                ),
            )
            rpc = channel.unary_stream(
                TRACK_METHOD,
                request_serializer=router_pb2.TrackPaymentRequest.SerializeToString,
                response_deserializer=lightning_pb2.Payment.FromString,
            )
            stream = rpc(
                router_pb2.TrackPaymentRequest(
                    payment_hash=payment_hash, no_inflight_updates=False
                ),
                timeout=deadline_seconds,
                metadata=(("macaroon", macaroon.hex()),),
                wait_for_ready=False,
            )
            return _collect(stream, payment_hash.hex())
        except grpc.RpcError as error:
            try:
                authorization_failure = error.code() in (
                    grpc.StatusCode.UNAUTHENTICATED,
                    grpc.StatusCode.PERMISSION_DENIED,
                )
            except Exception:  # noqa: BLE001 - upstream error may be malformed
                authorization_failure = False
            failure = (
                LndAuthError("LND rejected read-only observation credentials")
                if authorization_failure
                else LndUnavailableError("LND tracking unavailable; no absence claim")
            )
        except LndObservationError:
            raise
        except Exception:  # noqa: BLE001 - never expose upstream data or credential errors
            failure = LndUnavailableError("LND tracking unavailable; no absence claim")
        finally:
            if stream is not None:
                with suppress(Exception):  # Cleanup must not replace a sanitized observation error.
                    cancellation = getattr(stream, "cancel", None)
                    if callable(cancellation):
                        cancellation()
            if channel is not None:
                with suppress(Exception):
                    channel.close()
        if failure is None:
            raise LndUnavailableError("LND tracking unavailable; no absence claim")
        raise failure
