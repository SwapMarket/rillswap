"""Concrete explicit merchant/source acquisition, provenance ONLY.

No acquisition callbacks or caller-supplied observation DTOs substitute for RPCs.
This prevents accidental substitution, not malicious same-process Python code.
No credit import, allocation, refund promise, swap or payment is performed.
Existing installations perform no work automatically. This synchronous regtest
diagnostic has an acceptance deadline, not a hard execution or dispatch deadline.
Credential/setup work in the existing decoder can delay dispatch beyond that
deadline; all late results are refused. Never run on a shared server event loop.
Core trusts an operator-owned loopback host/listener, not cryptographic server
identity; configured namespace/profile and custody are not daemon attestations.
"""

from __future__ import annotations

import math
import time
from dataclasses import dataclass
from typing import TYPE_CHECKING

from rill_provider.core_tx_bytes import CoreTransactionReader
from rill_provider.lnd_hold_invoice import LndHoldInvoices
from rill_provider.lnd_invoice_decode import LndInvoiceDecoder

from rill_cli.conversion_journal import SourceAuthority, SourceCredit
from rill_cli.merchant_credit import (
    AcquisitionInterval,
    CoreSourceObservation,
    MerchantSourcePin,
    SourceReceiptObservation,
    extract_merchant_invoice_candidate,
    verify_merchant_credit,
)
from rill_cli.merchant_https import MerchantHttpsReader

if TYPE_CHECKING:
    from pathlib import Path

_MAX_SECONDS = 10


class MerchantSourceError(ValueError):
    """No acquired credit provenance; no private exception chain or retry authority."""


@dataclass(frozen=True, slots=True)
class MerchantSourceConfig:
    """Explicit operator trust inputs, never credentials learned from observations.

    Supply a dedicated LND macaroon with ONLY exact URI GetInfo, LookupInvoiceV2
    and DecodePayReq permissions. Configuration/files/ancestors require trusted
    operator control. Credential permissions are not inferred from RPC success.
    """

    merchant_leaf_der_sha256: str
    merchant_ca_path: Path
    lnd_port: int
    lnd_tls_root_path: Path
    lnd_macaroon_path: Path
    core_port: int
    core_cookie_path: Path


def _remaining(deadline: float) -> float:
    remaining = deadline - time.monotonic()
    if not math.isfinite(remaining) or remaining <= 0:
        raise MerchantSourceError("merchant source acquisition expired")
    return remaining


class MerchantCreditCollector:
    """One concrete regtest acquisition sequence with inert construction."""

    def __init__(
        self, authority: SourceAuthority, pin: MerchantSourcePin, config: MerchantSourceConfig
    ) -> None:
        """Validate one affirmative trust relationship without credential reads or RPCs."""
        valid = False
        try:
            authority = SourceAuthority.model_validate(authority.model_dump(), strict=True)
            pin = MerchantSourcePin.model_validate(pin.model_dump(), strict=True)
            if authority.source_node != pin.source_node or authority.network != pin.network:
                raise ValueError  # noqa: TRY301 - reject wrong destination authority before any reads
            self._https = MerchantHttpsReader(
                pin, config.merchant_leaf_der_sha256, config.merchant_ca_path
            )
            self._decoder = LndInvoiceDecoder(
                host="127.0.0.1",
                port=config.lnd_port,
                tls_certificate_path=config.lnd_tls_root_path,
                macaroon_path=config.lnd_macaroon_path,
                network=pin.network,
            )
            self._receiver = LndHoldInvoices(
                host="127.0.0.1",
                port=config.lnd_port,
                tls_certificate_path=config.lnd_tls_root_path,
                macaroon_path=config.lnd_macaroon_path,
                network=pin.network,
            )
            self._core = CoreTransactionReader(
                port=config.core_port, cookie_path=config.core_cookie_path, network=pin.network
            )
            self._authority, self._pin = authority, pin
            valid = True
        except Exception:  # noqa: BLE001, S110 - detach configuration validation details
            pass
        if not valid:
            raise MerchantSourceError("explicit merchant source trust configuration required")

    def acquire(
        self, intent_id: str, status_token: str, *, deadline_seconds: float = 10
    ) -> SourceCredit:
        """Collect actual reads and verify provenance, never import or spend credit."""
        if (
            type(deadline_seconds) not in (int, float)
            or not 0 < deadline_seconds <= _MAX_SECONDS
            or not math.isfinite(deadline_seconds)
        ):
            raise MerchantSourceError("merchant source acquisition lifetime invalid")
        deadline, started = time.monotonic() + deadline_seconds, int(time.time())
        credit = None
        try:
            batch = self._https.read(intent_id, status_token, deadline_seconds=_remaining(deadline))
            _remaining(deadline)
            if any(
                interval.started_at < started or interval.completed_at > int(time.time())
                for interval in (batch.view.acquisition, batch.events_acquisition)
            ):
                raise ValueError  # noqa: TRY301 - cannot relabel an earlier or future acquisition
            candidate = extract_merchant_invoice_candidate(batch.view, batch.events_document)
            invoice = self._decoder.decode(candidate.invoice, deadline_seconds=_remaining(deadline))
            _remaining(deadline)
            bound = self._receiver.observe_bound_settled_invoice(invoice, deadline=deadline)
            _remaining(deadline)
            if bound.node_pubkey != self._pin.source_node or bound.network != self._pin.network:
                raise ValueError  # noqa: TRY301 - wrong source cannot establish correspondence
            snapshot = self._core.observe_source(
                bound.last_lnd_height, deadline_seconds=_remaining(deadline)
            )
            _remaining(deadline)
            completed = int(time.time())
            if completed < max(
                batch.view.acquisition.completed_at, batch.events_acquisition.completed_at
            ):
                raise ValueError  # noqa: TRY301 - rollback cannot shorten already acquired evidence
            interval = AcquisitionInterval(started_at=started, completed_at=completed)
            # Conservatively include setup and every preceding acquisition in
            # each observation's interval, never refresh only completion times.
            view = batch.view.model_copy(update={"acquisition": interval})
            source = SourceReceiptObservation.from_bound(bound, interval)
            core = CoreSourceObservation(
                acquisition=interval,
                configured_network=snapshot.configured_network,
                genesis_hash=snapshot.genesis_hash,
                signet_challenge=snapshot.signet_challenge,
                tip_height=snapshot.tip_height,
                source_height=snapshot.source_height,
                source_block_hash=snapshot.source_block_hash,
            )
            credit = verify_merchant_credit(
                self._authority,
                self._pin,
                candidate.acceptance,
                view,
                invoice,
                source,
                core,
                now=completed,
            )
            _remaining(deadline)
        except Exception:  # noqa: BLE001 - discard rather than retain secret-bearing acquisition errors
            credit = None
        if credit is None:
            raise MerchantSourceError("merchant source provenance acquisition unavailable")
        _remaining(deadline)
        return credit
