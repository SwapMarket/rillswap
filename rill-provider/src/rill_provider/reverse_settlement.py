"""Provider lifecycle for LN to BTC swaps (RS-004 "Funding and settlement").

The provider is the funder and refund party; the client claims. Every step
takes the conservative branch: nothing is funded until every accepted HTLC
is checked, nothing is settled without the preimage of the payment hash,
the hold is canceled only after the refund has its signed depth, and every
signed transaction is recorded before it is broadcast.
"""

from __future__ import annotations

import hashlib
import logging
import math
import secrets
from functools import partial
from typing import TYPE_CHECKING, ParamSpec, Protocol, TypeVar

from rill_core.settlement import (
    FundingOutput,
    UnilateralAuthorization,
    ValidatedUnilateralSpend,
    build_unilateral_spend,
    finalize_unilateral_spend,
    max_spendable_fee,
    reconstruct_taproot_contract,
)
from rill_core.wire.hashes import contract_hash
from rill_core.wire.messages import Envelope, FundingBinding

from rill_provider.live_session_store import LiveSessionStoreError, StaleSwapError
from rill_provider.lnd_payment_observation import LndObservationError
from rill_provider.settlement_policy import offered_terms

if TYPE_CHECKING:
    from collections.abc import Callable

    from rill_core.wire.messages import ContractTerms

    from rill_provider.core_tx_bytes import FundedOutput, SpendScan
    from rill_provider.live_session_store import LiveSessionStore, SettlementItem
    from rill_provider.lnd_hold_invoice import HoldInvoiceStatus
    from rill_provider.reverse_operations import ReverseOperation
    from rill_provider.settlement_engine import EngineCrypto

LOG = logging.getLogger(__name__)
REFUND_ESTIMATE_TARGET = 6
PREIMAGE_BYTES = 32
_P = ParamSpec("_P")
_T = TypeVar("_T")


class HoldInvoiceBackend(Protocol):
    """The hold invoice calls the lifecycle needs (``LndHoldInvoices``)."""

    def lookup(self, payment_hash: str) -> HoldInvoiceStatus:
        """Return the invoice state and accepted parts."""

    def settle(self, preimage: str) -> None:
        """Settle with the verified preimage."""

    def cancel(self, payment_hash: str) -> None:
        """Cancel; accepted parts are failed back."""


class ReverseChainBackend(Protocol):
    """The chain calls the lifecycle needs (``CoreTransactionReader``)."""

    def tip_height(self) -> int:
        """Active chain height."""

    def fund_output(
        self, script_pubkey: bytes, value_sat: int, *, max_fee_sat: int
    ) -> FundedOutput:
        """Sign, never broadcast, a wallet payment to the script at index 0."""

    def broadcast(self, raw: bytes, txid: str) -> str:
        """Submit exact bytes; idempotent."""

    def confirmations(self, txid: str) -> int:
        """Return the confirmed depth, 0 in the mempool."""

    def find_spender(self, txid: str, vout: int, *, from_height: int, to_height: int) -> SpendScan:
        """Look for the transaction spending the outpoint."""

    def fee_rate_sat_vb(self, target_blocks: int) -> float | None:
        """Fee estimate, advice only."""


class ReverseSettlement:
    """Advance fresh state inside the acquired owner's reverse execution gate."""

    def __init__(
        self,
        store: LiveSessionStore,
        chain: ReverseChainBackend,
        hold_invoices: HoldInvoiceBackend,
        crypto: EngineCrypto,
        *,
        refund_fee_floor_sat: int = 1_000,
    ) -> None:
        """Bind already-configured backends; no I/O."""
        self._store = store
        self._chain = chain
        self._hold = hold_invoices
        self._crypto = crypto
        self._refund_fee_floor_sat = refund_fee_floor_sat
        self._operation: ReverseOperation | None = None

    async def advance(self, item: SettlementItem, now: int) -> str:
        """Reload after serialization, never execute a queued stale snapshot."""
        async with self._store.reverse_operations.operation() as operation:
            work = self._store.settlement_work(session_id=item.session_id)
            if len(work) != 1:
                raise StaleSwapError("reverse swap no longer available for settlement")
            self._operation = operation
            try:
                return await self._step(work[0], now)
            finally:
                self._operation = None

    def _check_operation(self) -> ReverseOperation:
        if self._operation is None:
            raise LiveSessionStoreError("reverse settlement step not active")
        self._operation.check()
        return self._operation

    async def _worker(self, function: Callable[_P, _T], *args: _P.args, **kwargs: _P.kwargs) -> _T:
        return await self._check_operation().worker(partial(function, *args, **kwargs))

    async def _step(self, item: SettlementItem, now: int) -> str:
        if item.preimage is not None and item.state not in {"FUNDED", "REFUNDING", "SETTLED"}:
            raise LiveSessionStoreError("reverse settlement intent in an unexpected state")
        terms = offered_terms(Envelope.model_validate_json(item.terms_offer, strict=True))
        if terms.profile_id != "ln-to-btc/v1":
            raise LiveSessionStoreError("reverse settlement requires LN to BTC terms")
        if item.state == "ACCEPTED":
            return await self._accepted(item, terms, now)
        if item.state == "LN_HELD":
            return await self._held(item, terms, now)
        if item.state == "FUNDING_SENT":
            return await self._funding_sent(item, terms, now)
        if item.state in ("FUNDED", "REFUNDING"):
            return await self._funded(item, terms, now)
        return item.state

    def _move(self, item: SettlementItem, to_state: str, now: int, **fields: object) -> str:
        self._check_operation()
        self._store.advance_reverse_swap(
            item.session_id,
            from_state=item.state,
            to_state=to_state,
            signer=self._crypto,
            now=now,
            **fields,  # type: ignore[arg-type]
        )
        return to_state

    async def _abort(self, item: SettlementItem, terms: ContractTerms, now: int, why: str) -> str:
        """Cancel the hold (nothing was funded) and close the swap."""
        await self._worker(self._hold.cancel, terms.invoice_binding.payment_hash)
        LOG.info("LN to BTC swap aborted before funding: %s", why)
        return self._move(item, "ABORTED", now, observation={"kind": "swap_aborted", "reason": why})

    def _funding_window_open(self, terms: ContractTerms, tip: int) -> bool:
        timing = terms.timing_policy.model_dump()
        needed = (
            terms.funding_confirmations
            + int(timing["client_response_blocks"])
            + int(timing["claim_confirmation_blocks"])
        )
        return tip + needed < terms.refund_lock_height

    def _held_as_agreed(self, terms: ContractTerms, status: HoldInvoiceStatus) -> str | None:
        """Return why the accepted hold does not satisfy the terms, or None."""
        economics = terms.economics.model_dump()
        timing = terms.timing_policy.model_dump()
        if status.state != "ACCEPTED":
            return f"hold invoice is {status.state}"
        if status.held_msat != int(economics["hold_invoice_sat"]) * 1000:
            return "held amount differs from H"
        earliest = status.earliest_expiry_height
        first_refund_block = terms.refund_lock_height + 1
        if earliest is None or (
            first_refund_block + int(timing["refund_and_ln_resolution_blocks"]) >= earliest
        ):
            return "incoming HTLC expires too soon"
        return None

    async def _accepted(self, item: SettlementItem, terms: ContractTerms, now: int) -> str:
        """Wait for the hold; move to LN_HELD once every accepted part checks out."""
        status = await self._worker(self._hold.lookup, terms.invoice_binding.payment_hash)
        if status.state == "OPEN":
            if now >= terms.invoice_binding.expires_at:
                return await self._abort(item, terms, now, "hold invoice expired unpaid")
            return item.state
        if status.state == "CANCELED":
            return self._move(
                item,
                "ABORTED",
                now,
                observation={"kind": "swap_aborted", "reason": "hold canceled"},
            )
        problem = self._held_as_agreed(terms, status)
        if problem is not None:
            return await self._abort(item, terms, now, problem)
        tip = await self._worker(self._chain.tip_height)
        if not self._funding_window_open(terms, tip):
            return await self._abort(item, terms, now, "funding window closed")
        return self._move(item, "LN_HELD", now, observation={"kind": "hold_accepted"})

    async def _held(self, item: SettlementItem, terms: ContractTerms, now: int) -> str:
        """Fund the contract: re-check the hold and the window, sign, record, broadcast."""
        status = await self._worker(self._hold.lookup, terms.invoice_binding.payment_hash)
        problem = self._held_as_agreed(terms, status)
        if problem is not None:
            return await self._abort(item, terms, now, problem)
        tip = await self._worker(self._chain.tip_height)
        if not self._funding_window_open(terms, tip):
            return await self._abort(item, terms, now, "funding window closed")
        script = reconstruct_taproot_contract(terms, keys=self._crypto).script_pubkey
        value = int(terms.economics.model_dump()["contract_amount_sat"])
        funded = await self._worker(
            self._chain.fund_output,
            script,
            value,
            max_fee_sat=int(terms.max_funding_fee_sat),
        )
        binding = FundingBinding(
            contract_hash=contract_hash(terms).hex(),
            funding_attempt_id=secrets.token_hex(32),
            binding_revision=0,
            funder_role="provider",
            lineage_anchor_txid=funded.anchor_txid,
            lineage_anchor_vout=funded.anchor_vout,
            funding_txid=funded.txid,
            contract_vout=funded.vout,
            contract_value_sat=str(value),
            contract_script_pubkey=script.hex(),
            replaces_txid=None,
            created_at=now,
        )
        # The grant (and the signed funding_binding for the client) is durable
        # before any broadcast; FUNDING_SENT rebroadcasts.
        state = self._move(item, "FUNDING_SENT", now, funding=(binding, funded.raw))
        await self._worker(self._chain.broadcast, funded.raw, funded.txid)
        return state

    async def _funding_sent(self, item: SettlementItem, terms: ContractTerms, now: int) -> str:
        """Keep the funding broadcast; move to FUNDED at the signed depth."""
        txid, raw = _funding(item)
        await self._worker(self._chain.broadcast, raw, txid)
        depth = await self._worker(self._chain.confirmations, txid)
        if depth < terms.funding_confirmations:
            return item.state
        tip = await self._worker(self._chain.tip_height)
        state = self._move(item, "FUNDED", now)
        # Scan for a claim from the inclusion block on.
        self._store.record_spend_scan(item.session_id, max(1, tip - depth))
        return state

    async def _funded(self, item: SettlementItem, terms: ContractTerms, now: int) -> str:
        """Settle on a claim revealing the preimage; otherwise refund after the lock."""
        if item.preimage is not None:
            # Affirmatively recorded intent survives vanished witnesses and
            # Core outages. No chain scan or refund may supersede this debt.
            return await self._settle_claim(item, terms, now, item.preimage)
        txid, _raw = _funding(item)
        vout = int(item.funding_vout or 0)
        tip = await self._worker(self._chain.tip_height)
        start = (item.spend_scan_height or max(1, tip - 1)) + 1
        scan = await self._worker(
            self._chain.find_spender, txid, vout, from_height=start, to_height=tip
        )
        payment_hash = terms.invoice_binding.payment_hash
        if scan.spender is not None:
            preimage = _preimage_in(scan.spender.witness, payment_hash)
            if preimage is not None:
                return await self._settle_claim(item, terms, now, preimage)
            # Our own refund, or an unknown spend: only our refund is expected here.
            if scan.spender.txid != item.refund_txid:
                LOG.warning("contract spent by an unexpected transaction; not settling")
                return item.state
        if scan.scanned_to > (item.spend_scan_height or 0):
            self._store.record_spend_scan(item.session_id, scan.scanned_to)
        if item.state == "REFUNDING":
            return await self._refunding(item, terms, now)
        if tip < terms.refund_lock_height:
            return item.state
        spend = await self._refund(item, terms)
        state = self._move(
            item,
            "REFUNDING",
            now,
            refund=(spend.txid, spend.raw_transaction),
            observation={"kind": "refund_broadcast", "refund_txid": spend.txid},
        )
        await self._worker(self._chain.broadcast, spend.raw_transaction, spend.txid)
        return state

    async def _refunding(self, item: SettlementItem, terms: ContractTerms, now: int) -> str:
        """Keep the refund broadcast; cancel the hold only at the signed depth."""
        if item.refund_txid is None or item.refund_tx is None:
            raise RuntimeError("REFUNDING swap without its refund")
        await self._worker(self._chain.broadcast, item.refund_tx, item.refund_txid)
        depth = await self._worker(self._chain.confirmations, item.refund_txid)
        if depth < terms.refund_resolution_confirmations:
            return item.state
        await self._worker(self._hold.cancel, terms.invoice_binding.payment_hash)
        return self._move(
            item,
            "REFUNDED",
            now,
            refund_confirmations=depth,
            observation={"kind": "refund_confirmed", "refund_txid": item.refund_txid},
        )

    async def _settle_claim(
        self, item: SettlementItem, terms: ContractTerms, now: int, preimage: str
    ) -> str:
        self._check_operation()
        self._store.record_reverse_settlement_preimage(
            item.session_id, from_state=item.state, preimage=preimage, now=now
        )
        await self._settle(preimage, terms.invoice_binding.payment_hash)
        return self._move(
            item, "SETTLED", now, preimage=preimage, observation={"kind": "hold_settled"}
        )

    async def _settle(self, preimage: str, payment_hash: str) -> None:
        """Settle the hold; tolerate an earlier settlement of the same invoice."""
        try:
            await self._worker(self._hold.settle, preimage)
        except LndObservationError:
            status = await self._worker(self._hold.lookup, payment_hash)
            if status.state != "SETTLED":
                raise

    async def _refund(self, item: SettlementItem, terms: ContractTerms) -> ValidatedUnilateralSpend:
        self._check_operation()
        txid, _raw = _funding(item)
        funding = FundingOutput(
            txid=bytes.fromhex(txid),
            output_index=int(item.funding_vout or 0),
            value_sat=int(terms.economics.model_dump()["contract_amount_sat"]),
            script_pubkey=reconstruct_taproot_contract(terms, keys=self._crypto).script_pubkey,
        )
        authorization = UnilateralAuthorization.from_terms(
            terms, funding, "refund", keys=self._crypto
        )
        ceiling = max_spendable_fee(authorization)
        floor = min(self._refund_fee_floor_sat, ceiling)
        spend = self._sign_refund(item, authorization, floor)
        try:
            rate = await self._worker(self._chain.fee_rate_sat_vb, REFUND_ESTIMATE_TARGET)
        except Exception:  # noqa: BLE001 - advice only; never defer a timelocked spend for it
            LOG.warning("fee estimate unavailable; signing at the floor fee")
            rate = None
        if rate is None:
            return spend
        wanted = min(ceiling, max(floor, math.ceil(rate * spend.vsize)))
        return spend if wanted == floor else self._sign_refund(item, authorization, wanted)

    def _sign_refund(
        self, item: SettlementItem, authorization: UnilateralAuthorization, fee: int
    ) -> ValidatedUnilateralSpend:
        self._check_operation()
        plan = build_unilateral_spend(authorization, fee_sat=fee)
        signature = self._store.sign_with_contract_key(
            item.session_id, plan.signature_hash, self._crypto
        )
        return finalize_unilateral_spend(plan, signature, verifier=self._crypto)


def _funding(item: SettlementItem) -> tuple[str, bytes]:
    if item.funding_txid is None or item.funding_tx is None:
        raise RuntimeError("funded swap without its funding")
    return item.funding_txid, item.funding_tx


def _preimage_in(witness: tuple[bytes, ...], payment_hash: str) -> str | None:
    """Return the 32-byte witness element hashing to ``payment_hash``, if any."""
    for element in witness:
        if len(element) == PREIMAGE_BYTES and hashlib.sha256(element).hexdigest() == payment_hash:
            return element.hex()
    return None
