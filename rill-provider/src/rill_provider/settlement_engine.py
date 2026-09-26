"""Move funded BTC to LN swaps to settlement (RS-003), one tick at a time.

Every consequential step is recorded before its external effect:

- ``FUNDING_SEEN``: the exact bound output must have ``funding_confirmations``
  on our own node, and the signed ``max_outgoing_htlc_expiry_height`` must
  still leave the invoice's final CLTV. Then ``PAYING`` is recorded (or
  ``FAILED`` with a ``payment_failed`` observation).
- ``PAYING``: reconcile first. An affirmative ``UNSENT`` grant plus fresh
  funding permits read-only route preparation. Commit the exact request and
  consume the grant before sending once. The route's absolute expiry cannot
  exceed the signed height. Success records ``PAID`` with the verified
  preimage and a ``payment_settled`` observation atomically.
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
from rill_provider.lnd_invoice_decode import InvoiceRejectedError
from rill_provider.lnd_payment_observation import LndUnavailableError
from rill_provider.settlement_policy import SettlementCrypto, offered_terms

if TYPE_CHECKING:
    from rill_core.settlement.taproot import TaprootKeyOperations
    from rill_core.wire.messages import ContractTerms, FundingBinding, InvoiceBinding

    from rill_provider.core_tx_bytes import CandidateFundingOutpoint
    from rill_provider.live_session_store import LiveSessionStore, SettlementItem
    from rill_provider.lnd_payment_send import PaymentOutcome, PreparedPayment
    from rill_provider.payment_dispatch_record import PaymentAuthority

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


CLAIM_PAGE = 16  # historical claims checked per tick


class LightningBackend(Protocol):
    """The provider's own LND (``RegtestLndPaymentSender``)."""

    def track(self, payment_hash: str, *, payer: PaymentAuthority | None = None) -> PaymentOutcome:
        """Return the payment status by hash, attesting ``payer`` when bound."""
        ...

    def prepare(
        self,
        bolt11: str,
        *,
        invoice_binding: InvoiceBinding,
        fee_limit_sat: int,
        max_expiry_height: int,
    ) -> PreparedPayment:
        """Prepare exact, absolute-bounded dispatch bytes without paying."""
        ...

    def send(self, payment: PreparedPayment) -> PaymentOutcome:
        """Submit the exact committed request once."""
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
        self._claim_cursor = ""  # fair paging of the historical claim sweep

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
        for session_id in await self._close_unfunded(now):
            results[session_id] = "FAILED"
        await self._release_claims()
        return results

    async def _close_unfunded(self, now: int) -> list[str]:
        """Fail accepted, never-funded swaps once the provider can no longer pay.

        Mirrors the FUNDING_SEEN deadline guard. The transition is terminal
        and the store releases the swap's never-dispatched reservation in the
        same transaction. A late funding binding is then refused; the client
        keeps its unilateral refund. A concurrent binding wins as a stale swap.
        """
        closed: list[str] = []
        unfunded = self._store.unfunded_swaps()
        if not unfunded:
            return closed
        try:
            tip = await asyncio.to_thread(self._chain.tip_height)
        except Exception:  # noqa: BLE001 - no fresh tip, no height-based closure
            tip = None
        for session_id, offer in unfunded:
            try:
                terms = offered_terms(Envelope.model_validate_json(offer, strict=True))
                invoice = terms.invoice_binding
                expiry = int(terms.timing_policy.model_dump()["max_outgoing_htlc_expiry_height"])
                if now < invoice.expires_at and (
                    tip is None or tip + invoice.min_final_cltv_delta < expiry
                ):
                    continue
                self._store.advance_swap(
                    session_id,
                    from_state="ACCEPTED",
                    to_state="FAILED",
                    signer=self._crypto,
                    now=now,
                    observation={"kind": "payment_failed"},
                )
            except StaleSwapError:
                continue
            except Exception:  # noqa: BLE001 - one swap's trouble never stops others
                LOG.warning("unfunded swap closure deferred", exc_info=False)
                continue
            closed.append(session_id)
        return closed

    async def _release_claims(self) -> None:
        """Release historical claimed reservations on fresh claim-depth evidence.

        One bounded page per tick; the cursor wraps after a short page, so rows
        that never confirm (or keep failing) cannot starve later claims.
        """
        page = self._store.unreleased_claims(after=self._claim_cursor, limit=CLAIM_PAGE)
        self._claim_cursor = page[-1][0] if len(page) == CLAIM_PAGE else ""
        for session_id, txid, _required in page:
            try:
                depth = await asyncio.to_thread(self._chain.confirmations, txid)
                self._store.release_claim(session_id, txid, confirmations=depth)
            except Exception:  # noqa: BLE001 - retried next tick; nothing is released
                LOG.warning("claim reservation release deferred", exc_info=False)

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
            return await self._advance(_with_state(item, "PAYING", payment_dispatch="UNSENT"), now)
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

    async def _pay(  # noqa: PLR0911 - explicit exposure guards before the sole send
        self,
        item: SettlementItem,
        terms: ContractTerms,
        binding: FundingBinding,
        expiry_height: int,
        now: int,
    ) -> PaymentOutcome | None:
        """Return the payment outcome, or None when it must never be sent."""
        invoice = terms.invoice_binding
        payer = item.payment_payer
        if payer is None:
            outcome = await asyncio.to_thread(self._lightning.track, invoice.payment_hash)
        else:
            # Same-channel GetInfo must match the dispatch's recorded payer.
            outcome = await asyncio.to_thread(
                lambda: self._lightning.track(invoice.payment_hash, payer=payer)
            )
        if outcome.status == "FAILED" and payer is None:
            # Absent, legacy, or malformed provenance: the configured node is
            # not bound to the historical payer, so its failed record cannot
            # terminate tracking of another node's attempt. send() reports
            # FAILED only after affirmative failure of the sole newly
            # authorized attempt, re-tracked against that attempt's payer.
            raise LndUnavailableError("tracked failure lacks bound payer authority")
        if outcome.status != "UNKNOWN":
            return outcome
        # PAYING is a durable intent, not durable chain evidence. After an
        # interrupted attempt, reconcile LND first, but never start a new
        # payment against a stale confirmation or newly blocked session.
        if item.blocked or item.payment_dispatch != "UNSENT":
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
        if expiry_height - tip <= invoice.min_final_cltv_delta:
            return None
        fee_limit = min(self._settings.max_routing_fee_sat, int(terms.economics.success_fee_sat))
        try:
            payment = await asyncio.to_thread(
                lambda: self._lightning.prepare(
                    item.invoice,
                    invoice_binding=invoice,
                    fee_limit_sat=fee_limit,
                    max_expiry_height=expiry_height,
                )
            )
        except InvoiceRejectedError:
            # An older accepted invoice can be outside the supported routing
            # subset. No dispatch grant has been consumed or request sent.
            return None
        if not self._store.commit_payment_dispatch(
            item.session_id, invoice.payment_hash, payment.dispatch_record
        ):
            return outcome
        return await asyncio.to_thread(self._lightning.send, payment)

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
