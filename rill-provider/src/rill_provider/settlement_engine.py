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
import time
from dataclasses import dataclass, replace
from typing import TYPE_CHECKING, Protocol

from rill_core.settlement.unilateral import (
    FundingOutput,
    UnilateralAuthorization,
    ValidatedUnilateralSpend,
    build_unilateral_spend,
    finalize_unilateral_spend,
    max_spendable_fee,
    validate_unilateral_spend,
)
from rill_core.wire.canonical import canonicalize, parse_model_json
from rill_core.wire.messages import Envelope
from rill_core.wire.settlement_messages import FundingBindingPayload

from rill_provider.core_tx_bytes import CoreTransactionUnknownError
from rill_provider.live_session_store import MAX_CLAIM_ATTEMPTS, StaleSwapError
from rill_provider.lnd_invoice_decode import InvoiceRejectedError
from rill_provider.lnd_payment_observation import LndNotSyncedError, LndUnavailableError
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
    """The provider's own Bitcoin Core (``CoreTransactionReader``)."""

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
CLAIM_URGENCY_BLOCKS = 6  # claim at the signed maximum fee this far before refund
INCREMENTAL_RELAY_SAT_VB = 1  # BIP125 rule 4 at Core's default incremental relay fee
READINESS_BUDGET_SECONDS = 10.0  # one shared bound for the whole offer preflight
READINESS_SYNC_DELAY = 1.0


class LightningBackend(Protocol):
    """The provider's own LND (``LndPaymentSender``)."""

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
        deadline_seconds: float = 20.0,
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

    def _fee_limit(self, success_fee_sat: int) -> int:
        """Routing fees may use at most the success fee and the operator cap."""
        return min(self._settings.max_routing_fee_sat, success_fee_sat)

    def route_ready(
        self,
        invoice: str,
        *,
        invoice_binding: InvoiceBinding,
        success_fee_sat: int,
        max_expiry_height: int,
    ) -> None:
        """Raise unless LND can route this invoice within the payment's own bounds now.

        Blocking readiness evidence for a firm offer: the node is synced on this
        network and one route exists with the fee limit and absolute expiry the
        payment would use. LND checks first-hop local balance when routing, so
        this also shows outbound liquidity at this moment (not a reservation).
        The prepared route is discarded; nothing is recorded or dispatched.
        LND reports itself unsynchronized for a moment after every block, so
        that one condition is retried briefly instead of refusing the offer.
        """
        deadline = time.monotonic() + READINESS_BUDGET_SECONDS
        while True:
            remaining = deadline - time.monotonic()
            try:
                self._lightning.prepare(
                    invoice,
                    invoice_binding=invoice_binding,
                    fee_limit_sat=self._fee_limit(success_fee_sat),
                    max_expiry_height=max_expiry_height,
                    deadline_seconds=max(0.1, remaining),
                )
            except LndNotSyncedError:
                if remaining <= READINESS_SYNC_DELAY:
                    raise
                time.sleep(READINESS_SYNC_DELAY)
            else:
                return

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
                # Attributed to the dispatch's own payer, so the reservation
                # can be released; the store checks the attribution itself.
                return self._move(
                    item,
                    "FAILED",
                    now,
                    failed_by_payer=outcome.payer,
                    observation={"kind": "payment_failed"},
                )
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
            tip = await asyncio.to_thread(self._chain.tip_height)
            ceiling = max_spendable_fee(self._authorization(terms, binding))
            spend = self._claim(item, terms, binding, min(self._settings.claim_fee_sat, ceiling))
            self._move(
                item,
                "CLAIMING",
                now,
                claim_tx=spend.raw_transaction,
                claim_txid=spend.txid,
                claim_fee_sat=spend.fee_sat,
                claim_height=tip,
                observation={"kind": "claim_broadcast", "claim_txid": spend.txid},
            )
            return await self._advance(
                _with_state(
                    item, "CLAIMING", claim_tx=spend.raw_transaction, claim_txid=spend.txid
                ),
                now,
            )
        if item.state == "CLAIMING":
            return await self._claiming(item, terms, binding, now)
        return item.state

    async def _claiming(  # noqa: PLR0911, PLR0912 - one ordered escalation step
        self, item: SettlementItem, terms: ContractTerms, binding: FundingBinding, now: int
    ) -> str:
        """Confirm any recorded claim, else rebroadcast and bump the fee on schedule.

        Every attempt is recorded before it is broadcast, and every attempt is
        checked because any of them may confirm. A transport or index failure is
        not evidence, so it ends the step without bumping.
        """
        attempts = self._store.claim_attempts(item.session_id)
        if not attempts:
            LOG.error("claiming swap has no recorded claim; operator attention required")
            return item.state
        tip = await asyncio.to_thread(self._chain.tip_height)
        authorization = self._authorization(terms, binding)
        sizes: dict[int, int] = {}
        for attempt in attempts:
            try:
                checked = validate_unilateral_spend(
                    attempt.raw, authorization, verifier=self._crypto
                )
            except Exception:  # noqa: BLE001 - isolate this swap, never broadcast it
                LOG.error("recorded claim failed validation; operator attention required")  # noqa: TRY400 - no details
                return item.state
            if checked.txid != attempt.txid:
                LOG.error("recorded claim ID mismatch; operator attention required")
                return item.state
            sizes[attempt.attempt] = checked.vsize
            if attempt.fee_sat is None or attempt.first_seen_height is None:
                self._store.observe_claim_attempt(
                    item.session_id, attempt.attempt, fee_sat=checked.fee_sat, height=tip
                )
        attempts = self._store.claim_attempts(item.session_id)
        latest = attempts[-1]
        try:  # harmless if an older attempt is mined: Core rejects the conflict
            await asyncio.to_thread(self._chain.broadcast, latest.raw, latest.txid)
        except Exception:  # noqa: BLE001 - e.g. replacement policy; the next bump retries
            LOG.info("claim broadcast not accepted; checking confirmations")
        for attempt in reversed(attempts):
            try:
                depth = await asyncio.to_thread(self._chain.confirmations, attempt.txid)
            except CoreTransactionUnknownError:
                continue  # never broadcast, evicted, or replaced
            if depth >= terms.settlement_confirmations:
                return self._move(
                    item, "CLAIMED", now, claim_tx=attempt.raw, claim_txid=attempt.txid
                )
            if depth >= 1:
                return item.state  # mined; wait for depth, never replace
        fee = claim_fee_target(
            initial=attempts[0].fee_sat,
            maximum=max_spendable_fee(authorization),
            anchor=attempts[0].first_seen_height,
            deadline=terms.refund_lock_height,
            tip=tip,
            latest_fee=latest.fee_sat,
            latest_height=latest.first_seen_height,
            vsize=sizes[latest.attempt],
            attempts=len(attempts),
        )
        if fee is None:
            return item.state
        try:
            spend = self._claim(item, terms, binding, fee)
        except Exception:  # noqa: BLE001 - e.g. dust bound; keep the recorded attempts
            LOG.warning("claim fee bump could not be built")
            return item.state
        self._store.record_claim_attempt(
            item.session_id,
            attempt=latest.attempt + 1,
            txid=spend.txid,
            raw=spend.raw_transaction,
            fee_sat=spend.fee_sat,
            height=tip,
        )
        try:
            await asyncio.to_thread(self._chain.broadcast, spend.raw_transaction, spend.txid)
        except Exception:  # noqa: BLE001 - recorded; rebroadcast next tick
            LOG.info("claim replacement not accepted yet")
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
        fee_limit = self._fee_limit(int(terms.economics.success_fee_sat))
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

    def _authorization(
        self, terms: ContractTerms, binding: FundingBinding
    ) -> UnilateralAuthorization:
        funding = FundingOutput(
            txid=bytes.fromhex(binding.funding_txid),
            output_index=binding.contract_vout,
            value_sat=int(binding.contract_value_sat),
            script_pubkey=bytes.fromhex(binding.contract_script_pubkey),
        )
        return UnilateralAuthorization.from_terms(terms, funding, "claim", keys=self._crypto)

    def _claim(
        self, item: SettlementItem, terms: ContractTerms, binding: FundingBinding, fee: int
    ) -> ValidatedUnilateralSpend:
        authorization = self._authorization(terms, binding)
        plan = build_unilateral_spend(
            authorization, fee_sat=fee, claim_preimage=bytes.fromhex(item.preimage or "")
        )
        signature = self._store.sign_with_contract_key(
            item.session_id, plan.signature_hash, self._crypto
        )
        return finalize_unilateral_spend(plan, signature, verifier=self._crypto)


def claim_fee_target(  # noqa: PLR0913 - explicit schedule inputs
    *,
    initial: int | None,
    maximum: int,
    anchor: int | None,
    deadline: int,
    tip: int,
    latest_fee: int | None,
    latest_height: int | None,
    vsize: int,
    attempts: int,
) -> int | None:
    """Return the next claim fee, or ``None`` when no replacement is due.

    The fee rises linearly from the first attempt's fee at its immutable
    first-seen height to ``maximum`` at ``deadline - CLAIM_URGENCY_BLOCKS``
    (the client can refund after ``deadline``), and is ``maximum`` from then
    on. A replacement needs a new block since the latest attempt (except at
    urgency) and must beat the latest fee by the BIP125 incremental relay fee.
    The last attempt of the budget is reserved for ``maximum``, and a target
    that would leave less than one increment of headroom below ``maximum``
    becomes ``maximum`` so the final replacement is always reachable. Unknown
    fees or heights never trigger a bump.
    """
    if (
        initial is None
        or anchor is None
        or latest_fee is None
        or latest_height is None
        or attempts >= MAX_CLAIM_ATTEMPTS
    ):
        return None
    urgent = deadline - CLAIM_URGENCY_BLOCKS
    if tip >= urgent:
        target = maximum
    elif tip <= latest_height or attempts == MAX_CLAIM_ATTEMPTS - 1:
        return None  # wait for a block; the final slot is kept for the maximum
    else:
        span = max(1, urgent - anchor)
        target = initial + (maximum - initial) * max(0, tip - anchor) // span
    increment = vsize * INCREMENTAL_RELAY_SAT_VB
    target = min(target, maximum)
    if maximum - target < increment:
        target = maximum  # never strand the final replacement below the maximum
    if target < latest_fee + increment:
        return None
    return target


def _with_state(item: SettlementItem, state: str, **changes: object) -> SettlementItem:
    return replace(item, state=state, **changes)  # type: ignore[arg-type]
