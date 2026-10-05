"""Read-only LND accounting claims, never bandwidth or payment authority.

Named read RPCs do not establish that supplied credentials lack write authority.
Configured TLS roots are trust anchors, not necessarily exact leaf pins. GetInfo
bracketing establishes endpoint correspondence, not an atomic snapshot or full
genesis/challenge/profile/namespace attestation, even at an unchanged block tip.
No journal adapter, positive spendability budget, or background task is provided.
"""

from __future__ import annotations

import math
import re
import time
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

import grpc
from pydantic import TypeAdapter
from rill_core.domain.amounts import MAX_MILLISATS, MAX_SATS
from rill_core.networks import backend_names
from rill_core.wire.types import CompressedKey

from rill_provider._lnd_proto import lightning_pb2
from rill_provider._lnd_proto.routerrpc import router_pb2
from rill_provider.lnd_payment_observation import _info_snapshot, _read_file, _snapshot

if TYPE_CHECKING:
    from rill_core.wire.types import NetworkIdentity

_MAX_PORT = 65535
_MAX_CHANNELS = 256
_MAX_HTLCS_PER_CHANNEL = 483
_MAX_TOTAL_HTLCS = 4096
_MAX_UPDATES = 16
_MAX_HOPS = 20
_MAX_MESSAGE_BYTES = 256 * 1024
_MAX_CERT_BYTES = 64 * 1024
_MAX_MACAROON_BYTES = 4096
_MAX_DEADLINE_SECONDS = 30
_HASH = re.compile(r"^[0-9a-f]{64}$")
_KEY: TypeAdapter[str] = TypeAdapter(CompressedKey)
_DEFAULT_ACCOUNTABILITY_RECORD = 106823
type _Metadata = tuple[tuple[str, str], ...]
_KNOWN_COMMITMENTS = {
    lightning_pb2.LEGACY,
    lightning_pb2.STATIC_REMOTE_KEY,
    lightning_pb2.ANCHORS,
    lightning_pb2.SCRIPT_ENFORCED_LEASE,
    lightning_pb2.TAPROOT,
    lightning_pb2.SIMPLE_TAPROOT_FINAL,
    lightning_pb2.SIMPLE_TAPROOT,
}


class LndTreasuryObservationError(ValueError):
    """Evidence unavailable, never proof of absent funds or permission to retry."""


@dataclass(frozen=True, slots=True)
class LndTipClaim:
    """Endpoint's synchronized tip claim, not independent chain attestation."""

    height: int
    block_hash: str


@dataclass(frozen=True, slots=True)
class LndTreasuryContext:
    """Separate configuration from observed claims and non-atomic read interval."""

    configured_network: NetworkIdentity
    observed_node_pubkey: str
    observed_network_label: str
    before_tip: LndTipClaim
    after_tip: LndTipClaim


@dataclass(frozen=True, slots=True)
class LndChannelAccounting:
    """Supported subtotals only, never available liquidity or refundable capacity.

    Amounts read from satoshi fields are floored individually. Local commitment
    balances already deduct commitment fees, anchors and committed outgoing
    principal. A zero floor can represent a positive sub-satoshi HTLC, not proof
    of a zero-value payment. Pending incoming value is NOT added. Missing constraints/custom
    channels make coverage incomplete, not affirmative zero-wallet eligibility.
    """

    context: LndTreasuryContext
    channel_count: int
    classified_channel_count: int
    coverage_complete: bool
    classified_local_commitment_floor_msat: int
    active_classified_local_commitment_floor_msat: int
    classified_local_reserve_msat: int
    classified_pending_incoming_floor_msat: int
    classified_pending_outgoing_floor_msat: int


@dataclass(frozen=True, slots=True)
class LndCompletedPayment:
    """Exact successful source value/settled route fees, with no preimage or route."""

    context: LndTreasuryContext
    payment_hash: str
    amount_msat: int
    routing_fee_msat: int


def _bounded(value: int, maximum: int, *, positive: bool = False) -> int:
    if type(value) is not int or not int(positive) <= value <= maximum:
        raise LndTreasuryObservationError("LND accounting quantity invalid")
    return value


def _remaining(deadline: float) -> float:
    remaining = deadline - time.monotonic()
    if not math.isfinite(remaining) or remaining <= 0:
        raise LndTreasuryObservationError("LND treasury observation expired")
    return remaining


def _deadline(duration: float) -> float:
    if (
        type(duration) not in (float, int)
        or not 0 < duration <= _MAX_DEADLINE_SECONDS
        or not math.isfinite(duration)
    ):
        raise LndTreasuryObservationError("LND treasury observation deadline invalid")
    return time.monotonic() + duration


def _channel_totals(response: lightning_pb2.ListChannelsResponse) -> tuple[int, ...]:
    if (
        not isinstance(response, lightning_pb2.ListChannelsResponse)
        or len(response.channels) > _MAX_CHANNELS
    ):
        raise LndTreasuryObservationError("LND channel accounting unsupported")
    classified = local = active_local = reserve = incoming = outgoing = htlc_count = 0
    for channel in response.channels:
        balance = _bounded(channel.local_balance, MAX_SATS) * 1000
        if len(channel.pending_htlcs) > _MAX_HTLCS_PER_CHANNEL:
            raise LndTreasuryObservationError("LND channel HTLC count unsupported")
        htlc_count += len(channel.pending_htlcs)
        if htlc_count > _MAX_TOTAL_HTLCS:
            raise LndTreasuryObservationError("LND aggregate HTLC count unsupported")
        channel_incoming = channel_outgoing = 0
        for htlc in channel.pending_htlcs:
            quantity = _bounded(htlc.amount, MAX_SATS) * 1000
            if htlc.incoming:
                channel_incoming += quantity
            else:
                channel_outgoing += quantity
        complete_constraints = channel.HasField("local_constraints") and channel.HasField(
            "remote_constraints"
        )
        for field in ("local_constraints", "remote_constraints"):
            if channel.HasField(field):
                constraints = getattr(channel, field)
                _bounded(constraints.chan_reserve_sat, MAX_SATS)
                _bounded(constraints.max_pending_amt_msat, MAX_MILLISATS)
                _bounded(constraints.min_htlc_msat, MAX_MILLISATS)
                _bounded(constraints.max_accepted_htlcs, _MAX_HTLCS_PER_CHANNEL)
        if (
            not complete_constraints
            or channel.custom_channel_data
            or channel.commitment_type not in _KNOWN_COMMITMENTS
        ):
            continue
        classified += 1
        local += balance
        active_local += balance if channel.active else 0
        reserve += channel.local_constraints.chan_reserve_sat * 1000
        incoming += channel_incoming
        outgoing += channel_outgoing
    return tuple(
        _bounded(value, MAX_MILLISATS)
        for value in (
            len(response.channels),
            classified,
            local,
            active_local,
            reserve,
            incoming,
            outgoing,
        )
    )


def _payment_totals(
    payment: lightning_pb2.Payment, expected_hash: str, expected_amount_msat: int
) -> tuple[int, int]:
    if payment.status != lightning_pb2.Payment.SUCCEEDED:
        raise LndTreasuryObservationError("LND payment is not successful")
    amount = _bounded(payment.value_msat, MAX_MILLISATS, positive=True)
    fees = _bounded(payment.fee_msat, MAX_MILLISATS)
    if payment.payment_hash != expected_hash or amount != expected_amount_msat:
        raise LndTreasuryObservationError("LND payment binding differs")
    records = payment.first_hop_custom_records
    # v0.21.0-beta adds this metadata to ordinary BTC creation records. This
    # allowlist does not attest actual attempt wire records; the positive
    # first-hop amount below is the decisive source-debit correspondence.
    if records and not (
        len(records) == 1 and records.get(_DEFAULT_ACCOUNTABILITY_RECORD) == b"\x00"
    ):
        raise LndTreasuryObservationError("LND custom payment accounting unsupported")
    recipients = settled_fees = successes = 0
    for attempt in payment.htlcs:
        if attempt.status == lightning_pb2.HTLCAttempt.FAILED:
            continue
        if attempt.status != lightning_pb2.HTLCAttempt.SUCCEEDED or not attempt.HasField("route"):
            raise LndTreasuryObservationError("LND payment attempt not terminal")
        route = attempt.route
        total = _bounded(route.total_amt_msat, MAX_MILLISATS, positive=True)
        fee = _bounded(route.total_fees_msat, MAX_MILLISATS)
        if route.custom_channel_data or route.first_hop_amount_msat != total:
            raise LndTreasuryObservationError("LND custom settled route unsupported")
        if not 0 < len(route.hops) <= _MAX_HOPS:
            raise LndTreasuryObservationError("LND settled route unsupported")
        recipient = _bounded(route.hops[-1].amt_to_forward_msat, MAX_MILLISATS, positive=True)
        if total - fee != recipient:
            raise LndTreasuryObservationError("LND settled route amounts differ")
        recipients += recipient
        settled_fees += fee
        successes += 1
    if not successes or recipients != amount or settled_fees != fees:
        raise LndTreasuryObservationError("LND successful payment quantities differ")
    _bounded(amount + fees, MAX_MILLISATS)
    return amount, fees


class LndTreasuryObserver:
    """Inert until called, one configured TLS source per bounded read batch."""

    def __init__(  # noqa: PLR0913 - explicit source/TLS/credential configuration
        self,
        *,
        host: str,
        port: int,
        tls_certificate_path: str | Path,
        read_macaroon_path: str | Path,
        network: NetworkIdentity,
        expected_node_pubkey: str,
    ) -> None:
        """Require operator-provided info/offchain-read credentials and source pin."""
        if host not in ("127.0.0.1", "::1") or type(port) is not int or not 1 <= port <= _MAX_PORT:
            raise LndTreasuryObservationError("LND treasury endpoint must be numeric loopback")
        names = key = None
        try:
            names = backend_names(network)
            key = bytes.fromhex(_KEY.validate_python(expected_node_pubkey, strict=True))
        except (ValueError, TypeError):
            pass
        if names is None or key is None:
            raise LndTreasuryObservationError("LND treasury source configuration invalid")
        self._network_label = names.lnd_network
        self._key = key
        self._network = network
        self._target = f"[{host}]:{port}" if host == "::1" else f"{host}:{port}"
        self._certificate = Path(tls_certificate_path)
        self._macaroon = Path(read_macaroon_path)

    def _connect(self, deadline: float) -> tuple[grpc.Channel, _Metadata]:
        certificate = _read_file(self._certificate, _MAX_CERT_BYTES, private=False)
        _remaining(deadline)
        macaroon = _read_file(self._macaroon, _MAX_MACAROON_BYTES, private=True)
        _remaining(deadline)
        channel = grpc.secure_channel(
            self._target,
            grpc.ssl_channel_credentials(root_certificates=certificate),
            options=(
                ("grpc.max_receive_message_length", _MAX_MESSAGE_BYTES),
                ("grpc.max_send_message_length", 1024),
                ("grpc.enable_retries", 0),
            ),
        )
        return channel, (("macaroon", macaroon.hex()),)

    def _info(self, channel: grpc.Channel, metadata: _Metadata, deadline: float) -> LndTipClaim:
        rpc = channel.unary_unary(
            "/lnrpc.Lightning/GetInfo",
            request_serializer=lightning_pb2.GetInfoRequest.SerializeToString,
            response_deserializer=lightning_pb2.GetInfoResponse.FromString,
        )
        info = rpc(
            lightning_pb2.GetInfoRequest(),
            timeout=_remaining(deadline),
            metadata=metadata,
            wait_for_ready=False,
        )
        _remaining(deadline)
        snapshot = _info_snapshot(info, self._key, self._network_label)
        if (
            not snapshot.synced_to_chain
            or snapshot.block_height <= 0
            or not _HASH.fullmatch(info.block_hash)
        ):
            raise LndTreasuryObservationError("LND synchronized tip unavailable")
        return LndTipClaim(snapshot.block_height, info.block_hash)

    def _context(self, before: LndTipClaim, after: LndTipClaim) -> LndTreasuryContext:
        if after.height < before.height or (
            after.height == before.height and after.block_hash != before.block_hash
        ):
            raise LndTreasuryObservationError("LND tip correspondence changed")
        return LndTreasuryContext(
            self._network, self._key.hex(), self._network_label, before, after
        )

    def observe_accounting(self, *, deadline_seconds: float = 10) -> LndChannelAccounting:
        """Read classified commitment subtotals, with no available-budget field."""
        deadline = _deadline(deadline_seconds)
        channel: grpc.Channel | None = None
        result = None
        failed = False
        try:
            channel, metadata = self._connect(deadline)
            before = self._info(channel, metadata, deadline)
            rpc = channel.unary_unary(
                "/lnrpc.Lightning/ListChannels",
                request_serializer=lightning_pb2.ListChannelsRequest.SerializeToString,
                response_deserializer=lightning_pb2.ListChannelsResponse.FromString,
            )
            response = rpc(
                lightning_pb2.ListChannelsRequest(),
                timeout=_remaining(deadline),
                metadata=metadata,
                wait_for_ready=False,
            )
            _remaining(deadline)
            count, classified, local, active_local, reserve, incoming, outgoing = _channel_totals(
                response
            )
            after = self._info(channel, metadata, deadline)
            result = LndChannelAccounting(
                self._context(before, after),
                count,
                classified,
                classified == count,
                local,
                active_local,
                reserve,
                incoming,
                outgoing,
            )
        except Exception:  # noqa: BLE001 - discard secret-bearing upstream errors
            failed = True
        finally:
            if channel is not None:
                try:
                    channel.close()
                except Exception:  # noqa: BLE001 - discard cleanup errors too
                    failed = True
        # Check after owned cleanup. Raise outside all upstream handlers so even
        # __context__, not only formatted tracebacks, excludes their secrets.
        if failed or result is None:
            raise LndTreasuryObservationError("LND treasury accounting unavailable")
        _remaining(deadline)
        return result

    def observe_completed_payment(
        self, payment_hash: str, expected_amount_msat: int, *, deadline_seconds: float = 10
    ) -> LndCompletedPayment:
        """Read exact payment-level success, never replay or funding permission."""
        if type(payment_hash) is not str or not _HASH.fullmatch(payment_hash):
            raise LndTreasuryObservationError("LND payment hash invalid")
        _bounded(expected_amount_msat, MAX_MILLISATS, positive=True)
        deadline = _deadline(deadline_seconds)
        channel: grpc.Channel | None = None
        stream = None
        result = None
        failed = False
        try:
            channel, metadata = self._connect(deadline)
            before = self._info(channel, metadata, deadline)
            rpc = channel.unary_stream(
                "/routerrpc.Router/TrackPaymentV2",
                request_serializer=router_pb2.TrackPaymentRequest.SerializeToString,
                response_deserializer=lightning_pb2.Payment.FromString,
            )
            stream = rpc(
                router_pb2.TrackPaymentRequest(
                    payment_hash=bytes.fromhex(payment_hash), no_inflight_updates=False
                ),
                timeout=_remaining(deadline),
                metadata=metadata,
                wait_for_ready=False,
            )
            totals = None
            for index, payment in enumerate(stream):
                _remaining(deadline)
                snapshot = _snapshot(payment, payment_hash)
                if snapshot.status == "SUCCEEDED":
                    totals = _payment_totals(payment, payment_hash, expected_amount_msat)
                    break
                if snapshot.status not in {"IN_FLIGHT", "INITIATED"} or index + 1 >= _MAX_UPDATES:
                    raise LndTreasuryObservationError("LND successful payment unavailable")  # noqa: TRY301 - detach upstream contexts at boundary
            stream.cancel()
            stream = None
            _remaining(deadline)
            if totals is None:
                raise LndTreasuryObservationError("LND successful payment unavailable")  # noqa: TRY301 - detach upstream contexts at boundary
            after = self._info(channel, metadata, deadline)
            result = LndCompletedPayment(self._context(before, after), payment_hash, *totals)
        except Exception:  # noqa: BLE001 - never project raw Payment or exceptions
            failed = True
        finally:
            if stream is not None:
                try:
                    stream.cancel()
                except Exception:  # noqa: BLE001 - cleanup cannot leak upstream errors
                    failed = True
            if channel is not None:
                try:
                    channel.close()
                except Exception:  # noqa: BLE001 - cleanup cannot leak upstream errors
                    failed = True
        if failed or result is None:
            raise LndTreasuryObservationError("LND completed payment unavailable")
        _remaining(deadline)
        return result
