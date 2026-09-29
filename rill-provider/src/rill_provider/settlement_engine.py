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
import math
import time
from dataclasses import dataclass, replace
from typing import TYPE_CHECKING, Protocol

from rill_core.settlement.unilateral import (
    FundingOutput,
    UnilateralAuthorization,
    ValidatedCooperativeClaim,
    ValidatedUnilateralSpend,
    build_unilateral_spend,
    finalize_unilateral_spend,
    max_spendable_fee,
    validate_cooperative_claim,
    validate_unilateral_spend,
)
from rill_core.wire.canonical import canonicalize, parse_model_json
from rill_core.wire.hashes import COOPERATIVE_CLAIM_FEATURE, contract_hash
from rill_core.wire.messages import Envelope
from rill_core.wire.settlement_messages import FundingBindingPayload

from rill_provider.core_tx_bytes import CoreTransactionUnknownError
from rill_provider.live_session_store import (
    MAX_CLAIM_ATTEMPTS,
    CooperativeWinner,
    LiveSessionStoreError,
    PreparedFallback,
    ReadinessChallenge,
    RecordedUnilateralClaim,
    StaleOwnerError,
    StaleSwapError,
)
from rill_provider.lnd_invoice_decode import InvoiceRejectedError
from rill_provider.lnd_payment_observation import LndNotSyncedError, LndUnavailableError
from rill_provider.reverse_settlement import HoldInvoiceBackend, ReverseSettlement
from rill_provider.settlement_policy import SettlementCrypto, offered_terms

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable

    from rill_core.settlement.taproot import TaprootKeyOperations
    from rill_core.wire.messages import ContractTerms, FundingBinding, InvoiceBinding

    from rill_provider.core_tx_bytes import CandidateFundingOutpoint, FundedOutput, SpendScan
    from rill_provider.live_session_store import ClaimAttempt, LiveSessionStore, SettlementItem
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

    def outpoint_unspent(self, txid: str, vout: int) -> bool:
        """Whether the output is unspent on the confirmed chain (mempool ignored)."""
        ...

    def block_hash(self, height: int) -> str:
        """Return the active-chain block hash at ``height`` or raise."""
        ...

    def fund_output(
        self, script_pubkey: bytes, value_sat: int, *, max_fee_sat: int
    ) -> FundedOutput:
        """Sign (never broadcast) a wallet payment to the script at index 0 (RS-004)."""

    def find_spender(self, txid: str, vout: int, *, from_height: int, to_height: int) -> SpendScan:
        """Look for the transaction spending the outpoint (RS-004)."""

    def fee_rate_sat_vb(self, target_blocks: int) -> float | None:
        """Return a conservative feerate estimate, or ``None`` when the node has none."""
        ...


CLAIM_PAGE = 16  # historical claims checked per tick
CLAIM_URGENCY_BLOCKS = 6  # claim at the signed maximum fee this far before refund
CLAIM_ESTIMATE_TARGET = 6  # confirmation target asked of Core for the first claim fee
INCREMENTAL_RELAY_SAT_VB = 1  # BIP125 rule 4 at Core's default incremental relay fee
READINESS_BUDGET_SECONDS = 10.0  # one shared bound for the whole offer preflight
READINESS_SYNC_DELAY = 1.0
COOPERATIVE_PROBE_SECONDS = 30


@dataclass(frozen=True, slots=True)
class ClaimProbeWindow:
    """Owner-process-only pre-echo claim deferral, never restartable authority."""

    session_id: str
    contract_hash: str
    owner_generation: int
    started_at: int
    deadline_at: int
    started_monotonic: float
    abandoned: bool = False


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

    def __init__(  # noqa: PLR0913 - explicit injected backends
        self,
        store: LiveSessionStore,
        chain: ChainBackend,
        lightning: LightningBackend,
        crypto: EngineCrypto,
        settings: EngineSettings | None = None,
        *,
        hold_invoices: HoldInvoiceBackend | None = None,
    ) -> None:
        """Bind already-configured backends; no I/O.

        ``hold_invoices`` enables the LN to BTC lifecycle (RS-004); without
        it, swaps of that profile are left untouched.
        """
        self._store = store
        self._chain = chain
        self._lightning = lightning
        self._crypto = crypto
        self._settings = settings or EngineSettings()
        self._reverse = (
            None
            if hold_invoices is None
            else ReverseSettlement(
                store,
                chain,
                hold_invoices,
                crypto,
                refund_fee_floor_sat=self._settings.claim_fee_sat,
            )
        )
        self._claim_cursor = ""  # fair paging of the historical claim sweep
        self._new_exposure_allowed = True
        self._new_featured_sessions: dict[str, tuple[str, int]] = {}
        self._claim_probes: dict[str, ClaimProbeWindow] = {}

    def register_new_featured_session(self, session_id: str, contract: str) -> bool:
        """Remember one current-process original session, not a stored ADMITTED row.

        Caller must have authenticated both a new acceptance and first funding
        binding under this owner. Relayed replay or restart never recreates it.
        """
        if not self._new_exposure_allowed or not self._store.admitted_featured_claim(
            session_id, contract
        ):
            return False
        if session_id in self._new_featured_sessions or session_id in self._claim_probes:
            return False
        self._new_featured_sessions[session_id] = (contract, self._store.generation)
        return True

    def probe_window(self, session_id: str) -> ClaimProbeWindow | None:
        """Return only the live gate held by this owner (never from SQLite)."""
        window = self._claim_probes.get(session_id)
        if window is None or window.owner_generation != self._store.generation:
            return None
        return window

    def expired_probe_windows(self) -> tuple[ClaimProbeWindow, ...]:
        """List gates requiring independent unilateral recovery."""
        now = time.monotonic()
        return tuple(
            window
            for window in self._claim_probes.values()
            if window.owner_generation == self._store.generation
            and (window.abandoned or now >= window.started_monotonic + COOPERATIVE_PROBE_SECONDS)
        )

    def abandon_probe(self, session_id: str) -> None:
        """Irreversibly stop deferral after failed tip, echo or preparation."""
        window = self.probe_window(session_id)
        if window is not None:
            self._claim_probes[session_id] = replace(window, abandoned=True)

    def _activate_probe(self, session_id: str, terms: ContractTerms) -> bool:
        eligible = self._new_featured_sessions.pop(session_id, None)
        if eligible != (contract_hash(terms).hex(), self._store.generation):
            return False
        if not self._new_exposure_allowed or not self._store.admitted_featured_claim(
            session_id, eligible[0]
        ):
            return False
        started_at = int(time.time())
        self._claim_probes[session_id] = ClaimProbeWindow(
            session_id,
            eligible[0],
            self._store.generation,
            started_at,
            started_at + COOPERATIVE_PROBE_SECONDS,
            time.monotonic(),
        )
        return True

    async def recover_expired_probe(self, window: ClaimProbeWindow, now: int) -> None:
        """Durably select a floor-fee claim without Core or Lightning RPC waits."""
        current = self.probe_window(window.session_id)
        if current != window or window not in self.expired_probe_windows():
            return
        items = self._store.settlement_work(session_id=window.session_id)
        if len(items) != 1:
            return
        item = items[0]
        if item.state != "PAID":
            self._claim_probes.pop(window.session_id, None)
            return  # a selected claim or terminal swap owns recovery now
        if item.preimage is None:
            return  # inconsistent PAID state must not invent a preimage
        if not self._store.immediate_claim_allowed(window.session_id):
            self._claim_probes.pop(window.session_id, None)
            return  # prepared or selected arbitration owns the fallback
        terms = offered_terms(Envelope.model_validate_json(item.terms_offer, strict=True))
        if terms.profile_id != "btc-to-ln/v1" or contract_hash(terms).hex() != window.contract_hash:
            raise LiveSessionStoreError("due probe contract changed")
        if item.funding_binding is None:
            raise LiveSessionStoreError("due probe funding missing")
        funding = Envelope.model_validate_json(item.funding_binding, strict=True)
        binding = parse_model_json(FundingBindingPayload, canonicalize(funding.payload)).binding
        if (
            funding.contract_hash != window.contract_hash
            or binding.contract_hash != window.contract_hash
            or hashlib.sha256(bytes.fromhex(item.preimage)).hexdigest()
            != terms.invoice_binding.payment_hash
        ):
            raise LiveSessionStoreError("due probe binding changed")
        spend = await self._initial_claim(item, terms, binding, use_estimate=False)
        self._move(
            item,
            "CLAIMING",
            now,
            claim_tx=spend.raw_transaction,
            claim_txid=spend.txid,
            claim_fee_sat=spend.fee_sat,
            claim_height=None,
            observation={"kind": "claim_broadcast", "claim_txid": spend.txid},
        )
        self._claim_probes.pop(window.session_id, None)

    async def prepare_cooperative_window(
        self,
        challenge: ReadinessChallenge,
        *,
        sample_tip: Callable[[], Awaitable[int | None]],
        now: Callable[[], int],
    ) -> None:
        """Commit a verified fallback using the original paid probe's deadlines.

        Sign locally before the last fresh-tip check. No cooperative nonce is
        exposed here; the store's ADMITTED-to-WAITING transaction is the only
        authority for a subsequent signing attempt.
        """
        window = self.probe_window(challenge.session_id)
        if (
            window is None
            or window.abandoned
            or challenge.contract_hash != window.contract_hash
            or challenge.owner_generation != window.owner_generation
            or challenge.started_at != window.started_at
            or challenge.deadline_at != window.deadline_at
            or time.monotonic() >= window.started_monotonic + COOPERATIVE_PROBE_SECONDS
            or now() >= window.deadline_at
        ):
            raise LiveSessionStoreError("original claim probe unavailable")
        items = self._store.settlement_work(session_id=challenge.session_id)
        if len(items) != 1:
            raise LiveSessionStoreError("paid claim unavailable")
        item = items[0]
        if item.state != "PAID" or item.preimage is None:
            raise LiveSessionStoreError("paid claim unavailable")
        terms = offered_terms(Envelope.model_validate_json(item.terms_offer, strict=True))
        if (
            terms.profile_id != "btc-to-ln/v1"
            or contract_hash(terms).hex() != window.contract_hash
            or challenge.deadline_height
            != terms.refund_lock_height - terms.timing_policy.claim_confirmation_blocks
            or item.funding_binding is None
        ):
            raise LiveSessionStoreError("cooperative fallback terms changed")
        funding = Envelope.model_validate_json(item.funding_binding, strict=True)
        binding = parse_model_json(FundingBindingPayload, canonicalize(funding.payload)).binding
        if (
            funding.contract_hash != window.contract_hash
            or binding.contract_hash != window.contract_hash
            or hashlib.sha256(bytes.fromhex(item.preimage)).hexdigest()
            != terms.invoice_binding.payment_hash
        ):
            raise LiveSessionStoreError("cooperative fallback binding changed")
        spend = await self._initial_claim(item, terms, binding, use_estimate=False)
        tip = await sample_tip()
        committed_at = now()
        if (
            tip is None
            or type(tip) is not int
            or tip >= challenge.deadline_height
            or committed_at >= window.deadline_at
            or time.monotonic() >= window.started_monotonic + COOPERATIVE_PROBE_SECONDS
            or self.probe_window(challenge.session_id) != window
            or not self._new_exposure_allowed
        ):
            raise LiveSessionStoreError("cooperative fallback deadline unavailable")
        self._store.prepare_claim_window(
            challenge.session_id,
            fallback_raw=spend.raw_transaction,
            fallback_txid=spend.txid,
            fallback_fee_sat=spend.fee_sat,
            started_at=window.started_at,
            now=committed_at,
            deadline_at=window.deadline_at,
            deadline_height=challenge.deadline_height,
        )
        self._claim_probes.pop(challenge.session_id, None)

    def disable_new_exposure(self) -> None:
        """Latch off new BTC-to-LN sends after deadline supervision fails."""
        self._new_exposure_allowed = False

    def _fee_limit(self, success_fee_sat: int) -> int:
        """Routing fees may use at most the success fee and the operator cap."""
        return min(self._settings.max_routing_fee_sat, success_fee_sat)

    def select_due_fallbacks(
        self, now: int, *, closed_only: bool = False
    ) -> tuple[PreparedFallback, ...]:
        """Validate exact stored claims and select before any network submission.

        This synchronous operation does not wait for Core, LN, or relays. A
        restarted owner may select only a previous generation's CLOSED bundle;
        a live deadline may select only its own expired WAITING bundle.
        """
        selected: list[PreparedFallback] = []
        for candidate in self._store.prepared_fallbacks(closed_only=closed_only):
            if candidate.state == "WAITING" and now < candidate.deadline_at:
                continue  # height-based expiry requires fresh chain evidence elsewhere
            try:
                self._validate_prepared_fallback(candidate)
            except Exception:  # noqa: BLE001 - bad bundle stays blocked for operator review
                LOG.warning(
                    "prepared fallback refused for %s; operator attention required",
                    candidate.session_id[:16],
                )  # do not log the signed transaction, preimage, or parser details
                continue
            try:
                self._store.select_prepared_fallback(
                    candidate, signer=self._crypto, now=now, height=None
                )
            except StaleSwapError:
                continue  # re-read the new durable state on the next pass
            # Store failure (including StaleOwnerError) cannot be deferred:
            # do not begin serving with a possibly unselected paid swap.
            selected.append(candidate)
        return tuple(selected)

    def _validate_prepared_fallback(self, candidate: PreparedFallback) -> None:
        terms = offered_terms(Envelope.model_validate_json(candidate.terms_offer, strict=True))
        funding = Envelope.model_validate_json(candidate.funding_binding, strict=True)
        binding = parse_model_json(FundingBindingPayload, canonicalize(funding.payload)).binding
        if (
            terms.profile_id != "btc-to-ln/v1"
            or contract_hash(terms).hex() != candidate.contract_hash
            or binding.contract_hash != candidate.contract_hash
            or funding.contract_hash != candidate.contract_hash
            or hashlib.sha256(bytes.fromhex(candidate.preimage)).hexdigest()
            != terms.invoice_binding.payment_hash
        ):
            raise LiveSessionStoreError("prepared claim binding mismatch")
        verified = validate_unilateral_spend(
            candidate.raw, self._authorization(terms, binding), verifier=self._crypto
        )
        if (
            verified.raw_transaction != candidate.raw
            or verified.txid != candidate.txid
            or verified.fee_sat != candidate.fee_sat
        ):
            raise LiveSessionStoreError("prepared claim validation mismatch")

    def recorded_fallbacks(self) -> tuple[PreparedFallback, ...]:
        """Read durable selected work for the independent submission lane."""
        return self._store.recorded_fallbacks()

    def recorded_unilateral_claims(self) -> tuple[RecordedUnilateralClaim, ...]:
        """Rediscover selected script-path claims, including old ADMITTED rows."""
        return self._store.recorded_unilateral_claims()

    def _validate_recorded_unilateral(self, claim: RecordedUnilateralClaim) -> None:
        terms = offered_terms(Envelope.model_validate_json(claim.terms_offer, strict=True))
        funding = Envelope.model_validate_json(claim.funding_binding, strict=True)
        binding = parse_model_json(FundingBindingPayload, canonicalize(funding.payload)).binding
        if (
            terms.profile_id != "btc-to-ln/v1"
            or terms.network_identity != self._store.network_identity
            or contract_hash(terms).hex() != claim.contract_hash
            or funding.contract_hash != claim.contract_hash
            or binding.contract_hash != claim.contract_hash
            or hashlib.sha256(bytes.fromhex(claim.preimage)).hexdigest()
            != terms.invoice_binding.payment_hash
        ):
            raise LiveSessionStoreError("recorded unilateral binding mismatch")
        verified = validate_unilateral_spend(
            claim.raw, self._authorization(terms, binding), verifier=self._crypto
        )
        if (
            verified.raw_transaction != claim.raw
            or verified.txid != claim.txid
            or (claim.fee_sat is not None and verified.fee_sat != claim.fee_sat)
        ):
            raise LiveSessionStoreError("recorded unilateral spend mismatch")

    async def broadcast_recorded_unilateral(self, claim: RecordedUnilateralClaim) -> None:
        """Broadcast only the still-selected, validated durable script-path bytes."""
        try:
            current = self._store.recorded_unilateral_claims(session_id=claim.session_id)
            if current != (claim,):
                return
            self._validate_recorded_unilateral(claim)
        except StaleOwnerError:
            raise
        except Exception:  # noqa: BLE001 - corrupted or stale custody must not be submitted
            LOG.warning("recorded unilateral claim invalid for %s", claim.session_id[:16])
            return
        try:
            await asyncio.to_thread(self._chain.broadcast, claim.raw, claim.txid)
        except Exception:  # noqa: BLE001 - CLAIMING remains durable and discoverable
            LOG.warning("selected unilateral claim not accepted yet for %s", claim.session_id[:16])

    def recover_cooperative_winners(self, now: int) -> tuple[CooperativeWinner, ...]:
        """Promote affirmative old PAID winners before accepting new work."""
        promoted: list[CooperativeWinner] = []
        for winner in self._store.cooperative_winners():
            if winner.state != "PAID":
                continue
            try:
                validated = self._validate_cooperative_winner(winner)
            except Exception:  # noqa: BLE001 - invalid persisted bytes cannot be dispatched
                LOG.warning(
                    "cooperative winner invalid for %s; operator attention required",
                    winner.session_id[:16],
                )
                continue
            try:
                self._store.promote_cooperative_winner(
                    winner, fee_sat=validated.fee_sat, signer=self._crypto, now=now
                )
            except StaleSwapError:
                continue
            promoted.append(winner)
        return tuple(promoted)

    def recorded_cooperative_winners(self) -> tuple[CooperativeWinner, ...]:
        """Return selected key-path claims for independent broadcast retries."""
        return tuple(w for w in self._store.cooperative_winners() if w.state == "CLAIMING")

    def _validate_cooperative_winner(self, winner: CooperativeWinner) -> ValidatedCooperativeClaim:
        terms = offered_terms(Envelope.model_validate_json(winner.terms_offer, strict=True))
        funding = Envelope.model_validate_json(winner.funding_binding, strict=True)
        binding = parse_model_json(FundingBindingPayload, canonicalize(funding.payload)).binding
        if (
            terms.profile_id != "btc-to-ln/v1"
            or terms.network_identity != self._store.network_identity
            or contract_hash(terms).hex() != winner.contract_hash
            or funding.contract_hash != winner.contract_hash
            or binding.contract_hash != winner.contract_hash
            or hashlib.sha256(bytes.fromhex(winner.preimage)).hexdigest()
            != terms.invoice_binding.payment_hash
        ):
            raise LiveSessionStoreError("cooperative winner binding mismatch")
        verified = validate_cooperative_claim(
            winner.raw, self._authorization(terms, binding), verifier=self._crypto
        )
        if verified.raw_transaction != winner.raw or verified.txid != winner.txid:
            raise LiveSessionStoreError("cooperative winner validation mismatch")
        return verified

    async def broadcast_cooperative_winner(self, winner: CooperativeWinner) -> None:
        """Submit only the validated, recorded exact key-path winner."""
        try:
            verified = self._validate_cooperative_winner(winner)
            selected = self._store.selected_cooperative_claim(winner.session_id)
        except StaleOwnerError:
            raise
        except Exception:  # noqa: BLE001 - never publish inconsistent custody
            LOG.warning("recorded cooperative claim invalid for %s", winner.session_id[:16])
            return
        if (
            selected is None
            or selected.raw != winner.raw
            or selected.txid != winner.txid
            or selected.fee_sat != verified.fee_sat
        ):
            LOG.warning("recorded cooperative claim differs for %s", winner.session_id[:16])
            return
        try:
            await asyncio.to_thread(self._chain.broadcast, winner.raw, winner.txid)
        except Exception:  # noqa: BLE001 - durable CLAIMING remains retryable
            LOG.warning(
                "selected cooperative claim not accepted yet for %s", winner.session_id[:16]
            )

    async def broadcast_selected_fallback(self, candidate: PreparedFallback) -> None:
        """Submit an already recorded attempt outside the deadline selector."""
        try:
            self._validate_prepared_fallback(candidate)
        except Exception:  # noqa: BLE001 - persisted bytes must not be trusted on restart
            LOG.warning("recorded fallback failed validation for %s", candidate.session_id[:16])
            return
        try:
            await asyncio.to_thread(self._chain.broadcast, candidate.raw, candidate.txid)
        except Exception:  # noqa: BLE001 - durable CLAIMING is retried by the normal sweep
            LOG.warning("selected fallback not accepted yet for %s", candidate.session_id[:16])

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
            except StaleOwnerError:
                raise  # a fenced/uncertain store cannot defer economic work
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
        await self._release_expired()
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
                if terms.profile_id != "btc-to-ln/v1":
                    continue  # LN to BTC: the provider funds; ReverseSettlement decides
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
            except StaleOwnerError:
                raise
            except Exception:  # noqa: BLE001 - one swap's trouble never stops others
                LOG.warning("unfunded swap closure deferred", exc_info=False)
                continue
            closed.append(session_id)
        return closed

    async def _release_expired(self) -> None:
        """Release terminal swaps' reservations once every exposure window closed."""
        try:
            if not self._store.expirable_exposure_pending():
                return
            tip = await asyncio.to_thread(self._chain.tip_height)
            released = self._store.release_expired_exposure(tip)
        except StaleOwnerError:
            raise
        except Exception:  # noqa: BLE001 - retried next tick; nothing is released
            LOG.warning("exposure release deferred", exc_info=False)
            return
        if released:
            LOG.info("released %d reservations whose exposure windows closed", released)

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
            except StaleOwnerError:
                raise
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

    async def _advance(  # noqa: PLR0911, PLR0912 - one ordered lifecycle per state
        self, item: SettlementItem, now: int
    ) -> str:
        terms = offered_terms(Envelope.model_validate_json(item.terms_offer, strict=True))
        if terms.profile_id == "ln-to-btc/v1":
            return item.state if self._reverse is None else await self._reverse.advance(item, now)
        if item.funding_binding is None:
            return item.state  # ACCEPTED: awaiting the client's funding binding
        funding = Envelope.model_validate_json(item.funding_binding, strict=True)
        binding = parse_model_json(FundingBindingPayload, canonicalize(funding.payload)).binding
        invoice = terms.invoice_binding
        timing = terms.timing_policy.model_dump()
        expiry_height = int(timing["max_outgoing_htlc_expiry_height"])
        if item.state == "FUNDING_SEEN":
            if item.blocked or not self._new_exposure_allowed:
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
            if self._activate_probe(item.session_id, terms):
                return "PAID"  # explicit new original session; echo handled outside this tick
            return await self._advance(_with_state(item, "PAID", preimage=outcome.preimage), now)
        if item.state == "PAID" and item.preimage is not None:
            probe = self.probe_window(item.session_id)
            if (
                probe is not None
                and not probe.abandoned
                and (time.monotonic() < probe.started_monotonic + COOPERATIVE_PROBE_SECONDS)
            ):
                return item.state
            if not self._store.immediate_claim_allowed(item.session_id):
                return item.state  # selection/recovery owns every prepared window
            tip = await asyncio.to_thread(self._chain.tip_height)
            spend = await self._initial_claim(item, terms, binding)
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
            self._claim_probes.pop(item.session_id, None)
            return await self._advance(
                _with_state(
                    item, "CLAIMING", claim_tx=spend.raw_transaction, claim_txid=spend.txid
                ),
                now,
            )
        if item.state == "CLAIMING":
            return await self._claiming(item, terms, binding, now)
        return item.state

    async def _claiming(  # noqa: PLR0911, PLR0912, PLR0915 - one ordered escalation step
        self, item: SettlementItem, terms: ContractTerms, binding: FundingBinding, now: int
    ) -> str:
        """Confirm any recorded claim, else rebroadcast and bump the fee on schedule.

        Every attempt is recorded before it is broadcast, and every attempt is
        checked because any of them may confirm. A transport or index failure is
        not evidence, so it ends the step without bumping.
        """
        if COOPERATIVE_CLAIM_FEATURE in terms.required_features:
            cooperative = self._store.selected_cooperative_claim(item.session_id)
            if cooperative is not None:
                return await self._claiming_cooperative(item, terms, binding, cooperative, now)
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
                if item.outpoint_spent_height is not None:
                    self._store.observe_outpoint_spent(item.session_id, None)
                return item.state  # mined; wait for depth, never replace
        # No recorded attempt is mined. If the contract output is gone from the
        # confirmed chain anyway, the client's refund spent it: the claim is
        # lost once that spend has held for refund_resolution_confirmations.
        unspent = await asyncio.to_thread(
            self._chain.outpoint_unspent, binding.funding_txid, binding.contract_vout
        )
        if not unspent:
            return await self._maybe_lost(item, terms, binding, tip, now)
        if item.outpoint_spent_height is not None:
            self._store.observe_outpoint_spent(item.session_id, None)  # reorged back
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
        except StaleOwnerError:
            raise
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

    async def _claiming_cooperative(
        self,
        item: SettlementItem,
        terms: ContractTerms,
        binding: FundingBinding,
        selected: ClaimAttempt,
        now: int,
    ) -> str:
        """Rebroadcast the exact selected key-path spend; never unilaterally replace it."""
        try:
            verified = validate_cooperative_claim(
                selected.raw, self._authorization(terms, binding), verifier=self._crypto
            )
        except Exception:  # noqa: BLE001 - bad stored claim cannot be broadcast
            LOG.warning("cooperative claim validation refused; operator attention required")
            return item.state
        if (
            verified.txid != selected.txid
            or verified.fee_sat != selected.fee_sat
            or item.claim_tx != selected.raw
            or item.claim_txid != selected.txid
        ):
            LOG.error("cooperative claim state differs; operator attention required")
            return item.state
        try:
            await asyncio.to_thread(self._chain.broadcast, selected.raw, selected.txid)
        except Exception:  # noqa: BLE001 - recorded attempt is retried on the next tick
            LOG.info("cooperative claim not accepted yet")
        try:
            depth = await asyncio.to_thread(self._chain.confirmations, selected.txid)
        except CoreTransactionUnknownError:
            depth = 0
        if depth >= terms.settlement_confirmations:
            return self._move(item, "CLAIMED", now, claim_tx=selected.raw, claim_txid=selected.txid)
        if depth >= 1:
            if item.outpoint_spent_height is not None:
                self._store.observe_outpoint_spent(item.session_id, None)
            return item.state
        tip = await asyncio.to_thread(self._chain.tip_height)
        unspent = await asyncio.to_thread(
            self._chain.outpoint_unspent, binding.funding_txid, binding.contract_vout
        )
        if not unspent:
            return await self._maybe_lost(item, terms, binding, tip, now)
        if item.outpoint_spent_height is not None:
            self._store.observe_outpoint_spent(item.session_id, None)
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
        if item.blocked or item.payment_dispatch != "UNSENT" or not self._new_exposure_allowed:
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
        if not self._new_exposure_allowed or not self._store.commit_payment_dispatch(
            item.session_id, invoice.payment_hash, payment.dispatch_record
        ):
            return outcome
        return await asyncio.to_thread(self._lightning.send, payment)

    async def _maybe_lost(
        self,
        item: SettlementItem,
        terms: ContractTerms,
        binding: FundingBinding,
        tip: int,
        now: int,
    ) -> str:
        """Close a claim as LOST only on anchored, still-active-chain evidence.

        A missing output is not proof of a refund: the funding itself may be
        reorged out. So the funding must be confirmed on the active chain at
        the signed depth and the refund must be possible (tip past the lock
        height). The first sighting is anchored to the tip block hash; the
        anchor must still be on the active chain when the wait ends, otherwise
        the spend may have been reorged and the wait restarts.
        """
        try:
            funding_depth = await asyncio.to_thread(self._chain.confirmations, binding.funding_txid)
        except CoreTransactionUnknownError:
            funding_depth = 0
        if funding_depth < terms.funding_confirmations or tip <= terms.refund_lock_height:
            LOG.warning("contract output missing while funding is unconfirmed; waiting")
            if item.outpoint_spent_height is not None:
                self._store.observe_outpoint_spent(item.session_id, None)
            return item.state
        if item.outpoint_spent_height is None or item.outpoint_spent_block is None:
            LOG.error("contract output spent by another transaction; claim may be lost")
            anchor = await asyncio.to_thread(self._chain.block_hash, tip)
            self._store.observe_outpoint_spent(item.session_id, tip, anchor)
            return item.state
        seen_height = item.outpoint_spent_height
        active = await asyncio.to_thread(self._chain.block_hash, seen_height)
        if tip < seen_height or active != item.outpoint_spent_block:
            LOG.warning("lost-claim anchor left the active chain; restarting the wait")
            self._store.observe_outpoint_spent(item.session_id, None)
            return item.state
        if tip - seen_height + 1 >= terms.refund_resolution_confirmations:
            LOG.error("claim lost: the refund resolved; operator attention required")
            return self._move(item, "LOST", now)
        return item.state

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

    async def _initial_claim(
        self,
        item: SettlementItem,
        terms: ContractTerms,
        binding: FundingBinding,
        *,
        use_estimate: bool = True,
    ) -> ValidatedUnilateralSpend:
        """Build attempt 0 at the node's feerate estimate, never below the configured floor.

        ``claim_fee_sat`` is the floor and the fallback when Core has no
        estimate; the ceiling is the signed cap or the dust floor. Escalation
        takes over from whatever this chooses.
        """
        ceiling = max_spendable_fee(self._authorization(terms, binding))
        floor = min(self._settings.claim_fee_sat, ceiling)
        spend = self._claim(item, terms, binding, floor)
        if not use_estimate:
            return spend  # deadline recovery never waits for fee advice
        try:
            rate = await asyncio.to_thread(self._chain.fee_rate_sat_vb, CLAIM_ESTIMATE_TARGET)
        except Exception:  # noqa: BLE001 - advice only; never defer a timelocked spend for it
            LOG.warning("fee estimate unavailable; signing at the floor fee")
            rate = None
        if rate is None:
            return spend
        wanted = min(ceiling, max(floor, math.ceil(rate * spend.vsize)))
        return spend if wanted == floor else self._claim(item, terms, binding, wanted)

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
