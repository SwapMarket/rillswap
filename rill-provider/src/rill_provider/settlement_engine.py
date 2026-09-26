"""Move funded BTC to LN swaps to settlement (RS-003), one tick at a time.

Every consequential step is recorded before its external effect:

- ``FUNDING_SEEN``: the exact bound output must have ``funding_confirmations``
  on our own node, and the signed ``max_outgoing_htlc_expiry_height`` must
  still leave the invoice's final CLTV. Then ``PAYING`` is recorded (or
  ``FAILED`` with a ``payment_failed`` observation).
- ``PAYING``: ``track`` first, so a restart never sends twice; ``send`` only
  when LND has no payment for the hash. The ``cltv_limit`` bounds the
  absolute expiry by the signed height. Success records ``PAID`` with the
  verified preimage and a ``payment_settled`` observation atomically.
- ``PAID``: build and sign the unilateral claim (claim leaf, preimage,
  sealed contract key), record its exact bytes as ``CLAIMING`` with a
  ``claim_broadcast`` observation, then broadcast.
- ``CLAIMING``: rebroadcast until ``settlement_confirmations``, then
  ``CLAIMED``.

A blocked (conflicting) session never starts a payment: that is new
financial risk. Claiming only reduces risk and proceeds regardless.
Store calls stay on the event-loop thread; RPCs run in worker threads.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
from dataclasses import dataclass, replace
from typing import TYPE_CHECKING, Protocol

from rill_core.settlement.unilateral import (
    FundingOutput,
    UnilateralAuthorization,
    build_unilateral_spend,
    finalize_unilateral_spend,
)
from rill_core.wire.canonical import canonicalize, parse_model_json
from rill_core.wire.messages import Envelope
from rill_core.wire.settlement_messages import FundingBindingPayload

from rill_provider.live_session_store import StaleSwapError
from rill_provider.settlement_policy import SettlementCrypto, offered_terms

if TYPE_CHECKING:
    from rill_core.settlement.taproot import TaprootKeyOperations
    from rill_core.wire.messages import ContractTerms, FundingBinding

    from rill_provider.core_tx_bytes import CandidateFundingOutpoint
    from rill_provider.live_session_store import LiveSessionStore, SettlementItem
    from rill_provider.lnd_payment_send import PaymentOutcome

LOG = logging.getLogger(__name__)


class ChainBackend(Protocol):
    """The provider's own Bitcoin Core (``RegtestCoreTransactionReader``)."""

    def tip_height(self) -> int:
        """Return the validated tip height."""
        ...

    def observe_candidate_outpoint(
        self, binding: FundingBinding, terms: ContractTerms, *, keys: TaprootKeyOperations
    ) -> CandidateFundingOutpoint:
        """Return the exact bound output's confirmations or raise."""
        ...

    def broadcast(self, raw: bytes, txid: str) -> str:
        """Submit exact bytes idempotently."""
        ...

    def confirmations(self, txid: str) -> int:
        """Return best-chain confirmations (0 in mempool) or raise."""
        ...


class LightningBackend(Protocol):
    """The provider's own LND (``RegtestLndPaymentSender``)."""

    def track(self, payment_hash: str) -> PaymentOutcome:
        """Return the payment status by hash."""
        ...

    def send(
        self, bolt11: str, *, payment_hash: str, fee_limit_sat: int, cltv_limit: int
    ) -> PaymentOutcome:
        """Pay once, bounded."""
        ...


class EngineCrypto(SettlementCrypto, Protocol):
    """Verification, key operations, and BIP340 signing (``rill_crypto.Context``)."""

    def schnorr_sign(self, secret_key: bytes, message: bytes, auxiliary_random: bytes) -> bytes:
        """Sign a 32-byte digest."""
        ...


@dataclass(frozen=True, slots=True)
class EngineSettings:
    """Operator limits for settlement."""

    claim_fee_sat: int = 1_000
    max_routing_fee_sat: int = 1_000


class SettlementEngine:
    """Drive every funded swap forward; safe to call repeatedly."""

    def __init__(
        self,
        store: LiveSessionStore,
        chain: ChainBackend,
        lightning: LightningBackend,
        crypto: EngineCrypto,
        settings: EngineSettings | None = None,
    ) -> None:
        """Bind already-configured backends; no I/O."""
        self._store = store
        self._chain = chain
        self._lightning = lightning
        self._crypto = crypto
        self._settings = settings or EngineSettings()

    async def tick(self, now: int) -> dict[str, str]:
        """Advance each swap at most through its available steps; return new states."""
        results: dict[str, str] = {}
        for item in self._store.settlement_work():
            try:
                state = await self._advance(item, now)
            except StaleSwapError:
                continue
            except Exception:  # noqa: BLE001 - one swap's backend trouble never stops others
                LOG.warning("settlement step deferred for one swap", exc_info=False)
                continue
            if state != item.state:
                results[item.session_id] = state
        return results

    def _move(self, item: SettlementItem, to_state: str, now: int, **fields: object) -> str:
        self._store.advance_swap(
            item.session_id,
            from_state=item.state,
            to_state=to_state,
            signer=self._crypto,
            now=now,
            **fields,  # type: ignore[arg-type]
        )
        return to_state

    async def _advance(self, item: SettlementItem, now: int) -> str:  # noqa: PLR0911 - one step per state
        terms = offered_terms(Envelope.model_validate_json(item.terms_offer, strict=True))
        funding = Envelope.model_validate_json(item.funding_binding, strict=True)
        binding = parse_model_json(FundingBindingPayload, canonicalize(funding.payload)).binding
        invoice = terms.invoice_binding
        timing = terms.timing_policy.model_dump()
        expiry_height = int(timing["max_outgoing_htlc_expiry_height"])
        if item.state == "FUNDING_SEEN":
            if item.blocked:
                return item.state
            seen = await asyncio.to_thread(
                self._chain.observe_candidate_outpoint, binding, terms, keys=self._crypto
            )
            if seen.chain_only_confirmations < terms.funding_confirmations:
                return item.state
            if (
                seen.tip_height + invoice.min_final_cltv_delta >= expiry_height
                or now >= invoice.expires_at
            ):
                return self._move(item, "FAILED", now, observation={"kind": "payment_failed"})
            self._move(item, "PAYING", now)
            return await self._advance(_with_state(item, "PAYING"), now)
        if item.state == "PAYING":
            outcome = await self._pay(item, terms, binding, expiry_height, now)
            if outcome is None:
                return self._move(item, "FAILED", now, observation={"kind": "payment_failed"})
            if outcome.status == "FAILED":
                return self._move(item, "FAILED", now, observation={"kind": "payment_failed"})
            if outcome.status != "SUCCEEDED" or outcome.preimage is None:
                return item.state
            self._move(
                item,
                "PAID",
                now,
                preimage=outcome.preimage,
                observation={"kind": "payment_settled", "payment_preimage": outcome.preimage},
            )
            return await self._advance(_with_state(item, "PAID", preimage=outcome.preimage), now)
        if item.state == "PAID" and item.preimage is not None:
            raw, txid = self._claim(item, terms, binding)
            self._move(
                item,
                "CLAIMING",
                now,
                claim_tx=raw,
                claim_txid=txid,
                observation={"kind": "claim_broadcast", "claim_txid": txid},
            )
            return await self._advance(
                _with_state(item, "CLAIMING", claim_tx=raw, claim_txid=txid), now
            )
        if item.state == "CLAIMING" and item.claim_tx is not None and item.claim_txid is not None:
            txid = item.claim_txid
            try:
                await asyncio.to_thread(self._chain.broadcast, item.claim_tx, txid)
            except Exception:  # noqa: BLE001 - e.g. already in mempool; confirmations decide
                LOG.info("claim rebroadcast not accepted; checking confirmations")
            depth = await asyncio.to_thread(self._chain.confirmations, txid)
            if depth >= terms.settlement_confirmations:
                return self._move(item, "CLAIMED", now)
        return item.state

    async def _pay(
        self,
        item: SettlementItem,
        terms: ContractTerms,
        binding: FundingBinding,
        expiry_height: int,
        now: int,
    ) -> PaymentOutcome | None:
        """Return the payment outcome, or None when it must never be sent."""
        invoice = terms.invoice_binding
        outcome = await asyncio.to_thread(self._lightning.track, invoice.payment_hash)
        if outcome.status != "UNKNOWN":
            return outcome
        # PAYING is a durable intent, not durable chain evidence. After an
        # interrupted attempt, reconcile LND first, but never start a new
        # payment against a stale confirmation or newly blocked session.
        if item.blocked:
            return outcome
        seen = await asyncio.to_thread(
            self._chain.observe_candidate_outpoint, binding, terms, keys=self._crypto
        )
        if seen.chain_only_confirmations < terms.funding_confirmations:
            return outcome
        if now >= invoice.expires_at or (
            hashlib.sha256(item.invoice.encode("ascii")).hexdigest() != invoice.bolt11_sha256
        ):
            return None
        tip = await asyncio.to_thread(self._chain.tip_height)
        cltv_limit = expiry_height - tip
        if cltv_limit <= invoice.min_final_cltv_delta:
            return None
        fee_limit = min(self._settings.max_routing_fee_sat, int(terms.economics.success_fee_sat))
        return await asyncio.to_thread(
            lambda: self._lightning.send(
                item.invoice,
                payment_hash=invoice.payment_hash,
                fee_limit_sat=fee_limit,
                cltv_limit=cltv_limit,
            )
        )

    def _claim(
        self, item: SettlementItem, terms: ContractTerms, binding: FundingBinding
    ) -> tuple[bytes, str]:
        funding = FundingOutput(
            txid=bytes.fromhex(binding.funding_txid),
            output_index=binding.contract_vout,
            value_sat=int(binding.contract_value_sat),
            script_pubkey=bytes.fromhex(binding.contract_script_pubkey),
        )
        authorization = UnilateralAuthorization.from_terms(
            terms, funding, "claim", keys=self._crypto
        )
        fee = min(self._settings.claim_fee_sat, int(terms.max_claim_fee_sat))
        plan = build_unilateral_spend(
            authorization, fee_sat=fee, claim_preimage=bytes.fromhex(item.preimage or "")
        )
        signature = self._store.sign_with_contract_key(
            item.session_id, plan.signature_hash, self._crypto
        )
        spend = finalize_unilateral_spend(plan, signature, verifier=self._crypto)
        return spend.raw_transaction, spend.txid


def _with_state(item: SettlementItem, state: str, **changes: object) -> SettlementItem:
    return replace(item, state=state, **changes)  # type: ignore[arg-type]
