"""LN to BTC swap client over Nostr relays (RS-001, RS-004, RS-005).

One swap, one fresh session: discover and verify the provider announcement,
handshake, request firm terms for a payout the client chose (the client
picks the preimage), verify the terms and the hold invoice, write the
encrypted recovery file (with the preimage), accept, pay the hold invoice
from the local LND, wait for the provider's signed ``funding_binding``,
verify it, write the funded recovery snapshot, wait for the signed depth,
then claim the contract to the client's destination revealing the preimage.

Nothing of the client's is at risk before the hold is paid; after that the
Lightning funds stay held until the claim reveals the preimage or the
provider's refund resolves the hold. If this process dies after paying, the
funded recovery snapshot plus ``rill recover watch-claim`` finish the claim,
with the same fee escalation.
"""

from __future__ import annotations

import asyncio
import contextvars
import hashlib
import math
import secrets
import threading
import time
from dataclasses import dataclass
from typing import TYPE_CHECKING, Literal, Protocol, TypeVar

from rill_core.recovery import REVERSE_FALLBACK_EXTENSION, inspect_recovery_successor
from rill_core.settlement import (
    FundingOutput,
    UnilateralAuthorization,
    build_unilateral_spend,
    check_funding_binding_transaction,
    finalize_unilateral_spend,
    max_spendable_fee,
    reconstruct_taproot_contract,
)
from rill_core.wire.canonical import canonicalize, parse_json_strict, parse_model_json
from rill_core.wire.hashes import (
    COOPERATIVE_CLAIM_FEATURE,
    client_acceptance_hash,
    contract_hash,
    funding_binding_hash,
    provider_terms_hash,
)
from rill_core.wire.messages import ClientAcceptance
from rill_core.wire.quotes import TermsOfferPayload
from rill_core.wire.reverse_quotes import (
    ReverseFirmQuoteRequest,
    ReverseQuoteLimits,
    check_reverse_terms_offer,
)
from rill_core.wire.settlement_messages import FundingBindingPayload, parse_observation
from rill_provider.lnd_payment_observation import LndObservationError

from rill_cli.claim_watcher import ClaimWatcher
from rill_cli.live_swap import (
    SwapError,
    _handshake,
    _recovery_document,
    _scalar,
    _Session,
    discover,
)
from rill_cli.refund_watcher import ChainView

if TYPE_CHECKING:
    from collections.abc import Callable
    from types import TracebackType
    from typing import Any, Self

    from rill_core.wire.messages import ContractTerms, Envelope, FundingBinding, InvoiceBinding
    from rill_core.wire.types import NetworkIdentity
    from rill_crypto import Context
    from rill_provider.relay_client import RelayConnection

    from rill_cli.hold_payment import HoldStatus
    from rill_cli.wallet_rpc import ConfirmedOutput

PROFILE: Literal["ln-to-btc/v1"] = "ln-to-btc/v1"
POLL_SECONDS = 5.0
_T = TypeVar("_T")
_UNRESOLVED = (
    "reverse swap status unresolved; preserve all recovery files, check `lncli listpayments`, "
    "and do not retry payment; if funded, use `rill recover watch-claim` before the refund lock"
)


class _ReverseLifetime:
    """Own actual workers across startup and one nonrenewing payment lifetime.

    Startup work may precede the anchor, but payment and claim authorization
    require start(). Cancellation stops future effects, never the owned tasks.
    Cleanup waits outside the budget so SDK callers cannot close crypto early.
    """

    def __init__(self, duration: float) -> None:
        if not math.isfinite(duration) or duration <= 0:
            raise SwapError("settlement timeout must be finite and positive")
        self._duration = duration
        self._deadline: float | None = None
        self._stopped = threading.Event()
        self._workers: set[asyncio.Future[Any]] = (
            set()
        )  # Heterogeneous results, consumed only for drainage.

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(
        self,
        _kind: type[BaseException] | None,
        error: BaseException | None,
        _traceback: TracebackType | None,
    ) -> None:
        self._stopped.set()

        # Neither executor bridges nor this gather are Tasks. Loop-wide Task
        # cancellation must not mark an actual running thread as completed.
        draining = asyncio.gather(*self._workers, return_exceptions=True)
        canceled = isinstance(error, asyncio.CancelledError)
        while not draining.done():
            try:
                await asyncio.shield(draining)
            except asyncio.CancelledError:
                canceled = True
        draining.result()
        self._workers.clear()
        if canceled:
            raise asyncio.CancelledError

    def start(self) -> None:
        """Anchor immediately before scheduling the exact invoice submission."""
        if self._deadline is not None or self._stopped.is_set():
            raise SwapError("reverse lifetime start refused")
        self._deadline = time.monotonic() + self._duration

    @property
    def deadline(self) -> float:
        if self._deadline is None:
            raise SwapError("reverse payment lifetime not started")
        return self._deadline

    def allowed(self) -> bool:
        """Expose only local, thread-safe payment/signing permission."""
        return (
            self._deadline is not None
            and not self._stopped.is_set()
            and time.monotonic() < self._deadline
        )

    def check(self) -> None:
        if not self.allowed():
            raise TimeoutError

    def _check_work(self) -> None:
        if self._stopped.is_set() or (
            self._deadline is not None and time.monotonic() >= self._deadline
        ):
            raise TimeoutError

    async def worker(self, function: Callable[[], _T]) -> _T:
        """Shield execution, reject late authority, retain uncertain work to drain."""
        self._check_work()

        def execute() -> _T:
            self._check_work()  # Executor queueing cannot reserve authority.
            return function()

        context = contextvars.copy_context()
        task = asyncio.get_running_loop().run_in_executor(None, context.run, execute)
        self._workers.add(task)
        try:
            if self._deadline is None:
                result = await asyncio.shield(task)
            else:
                async with asyncio.timeout(max(0, self._deadline - time.monotonic())):
                    result = await asyncio.shield(task)
            self._check_work()
            return result  # noqa: TRY300 - a late-result refusal must stop future work
        except (TimeoutError, asyncio.CancelledError):
            self._stopped.set()
            raise
        finally:
            if task.done():
                if not task.cancelled():
                    task.exception()  # Consume an uncertain late failure before releasing custody.
                self._workers.discard(task)


class ClaimWallet(Protocol):
    """The user's own Core node and wallet (``WalletRpc``)."""

    def tip_height(self) -> int:
        """Return the best height."""
        ...

    def new_destination_script(self) -> bytes:
        """Return a fresh payout scriptPubKey."""
        ...

    def confirmed_output(self, txid: str, vout: int) -> ConfirmedOutput | None:
        """Return the outpoint as Core sees it, or None when unknown or spent."""
        ...

    def unspent_on_chain(self, txid: str, vout: int) -> bool:
        """Whether the output is unspent in the active chain (mempool ignored)."""
        ...

    def wallet_confirmations(self, txid: str) -> int | None:
        """Depth of a wallet transaction, ``None`` when unknown."""
        ...

    def broadcast(
        self,
        raw: bytes,
        *,
        deadline: float | None = None,
        effect_allowed: Callable[[], bool] | None = None,
    ) -> str:
        """Submit exact bytes; return Core's txid."""
        ...


class HoldPayer(Protocol):
    """The user's own LND (``LndHoldPayer``)."""

    def pay(  # noqa: PLR0913 - exact invoice bounds and original lifetime
        self,
        bolt11: str,
        *,
        invoice_binding: InvoiceBinding,
        min_final_expiry_height: int,
        max_expiry_height: int,
        fee_limit_sat: int,
        deadline: float | None = None,
        submission_allowed: Callable[[], bool] | None = None,
    ) -> HoldStatus:
        """Submit the hold payment once."""
        ...


@dataclass(frozen=True, slots=True)
class ReverseSwapLimits:
    """The user's ceilings for the firm offer and the payment."""

    max_success_fee_sat: int
    min_claim_fee_reserve_sat: int
    max_claim_fee_sat: int
    min_refund_delay_blocks: int  # blocks the provider must wait before refunding
    max_incoming_htlc_delay_blocks: int  # how long the LN funds may stay held
    max_routing_fee_sat: int
    claim_fee_rate_sat_vb: int


@dataclass(frozen=True, slots=True)
class ReverseSwapOutcome:
    """A claimed swap: the claim transaction pays the client's destination."""

    session_id: str
    contract_hash: str
    funding_txid: str
    claim_txid: str
    payout_sat: int


def _check_offer(  # noqa: PLR0913 - every binding checked explicitly
    offer: TermsOfferPayload,
    request: ReverseFirmQuoteRequest,
    *,
    envelope: Envelope,
    transcript: str,
    hold: InvoiceBinding,
    identity: str,
    network: NetworkIdentity,
    crypto: Context,
    now: int,
) -> ContractTerms:
    check_reverse_terms_offer(request, offer, handshake_hash=transcript, invoice_binding=hold)
    terms = offer.terms.contract_terms
    crypto.schnorr_verify(
        bytes.fromhex(identity),
        provider_terms_hash(offer.terms),
        bytes.fromhex(offer.provider_terms_signature),
    )
    if not (
        contract_hash(terms).hex() == offer.terms.contract_hash == envelope.contract_hash
        and terms.provider_identity_key == identity
        and terms.network_identity == network
        and now < terms.terms_expiry
    ):
        raise SwapError("terms offer is not bound to this provider, network, or time")
    return terms


def _check_funding(  # noqa: PLR0913 - every binding checked explicitly
    envelope: Envelope,
    *,
    terms: ContractTerms,
    contract: str,
    provider_key: str,
    script: bytes,
    crypto: Context,
) -> tuple[FundingBinding, str, bytes]:
    """Return the provider's binding, its signature, and the exact transaction bytes."""
    payload = parse_model_json(FundingBindingPayload, canonicalize(envelope.payload))
    binding = payload.binding
    crypto.schnorr_verify(
        bytes.fromhex(provider_key),
        funding_binding_hash(binding),
        bytes.fromhex(payload.funding_binding_signature),
    )
    if not (
        binding.contract_hash == contract == envelope.contract_hash
        and binding.funder_role == "provider"
        and binding.binding_revision == 0
        and binding.replaces_txid is None
        and binding.contract_script_pubkey == script.hex()
        and binding.contract_value_sat == terms.economics.contract_amount_sat
    ):
        raise SwapError("provider's funding binding does not fund these terms")
    raw = bytes.fromhex(payload.funding_transaction)
    match = check_funding_binding_transaction(raw, binding, terms, keys=crypto)
    if (match.funding_txid, match.contract_vout) != (binding.funding_txid, binding.contract_vout):
        raise SwapError("provider's funding transaction differs from its binding")
    return binding, payload.funding_binding_signature, raw


async def _await_funding(  # noqa: PLR0912, PLR0913 - one FIFO and its explicit waiting bounds
    session: _Session,
    *,
    contract: str,
    timeout: float,  # noqa: ASYNC109
    terms: ContractTerms,
    provider_key: str,
    script: bytes,
    crypto: Context,
    absolute_deadline: float | None = None,
) -> tuple[FundingBinding, str, bytes]:
    """Own the original FIFO until funding under one nonrenewing wait budget.

    Never skip an earlier action or foreign context to a later binding. Reverse
    cooperation is not available here; no readiness or signing is attempted.
    """
    if not math.isfinite(timeout) or timeout <= 0:
        raise SwapError("funding timeout must be finite and positive")
    deadline = time.monotonic() + timeout
    if absolute_deadline is not None:
        if type(absolute_deadline) not in (int, float) or not math.isfinite(absolute_deadline):
            raise SwapError("funding deadline must be finite")
        deadline = min(deadline, absolute_deadline)
    timeout_error = (
        "provider funding not observed in time; check `lncli listpayments`; "
        "the held payment fails back when the provider cancels the hold; do not retry payment"
    )
    context_hint = "funding status unresolved; check `lncli listpayments`; do not retry payment"
    async with session.settlement_stream():
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise SwapError(timeout_error)
            try:
                message = await session.receive_next(timeout=remaining)
            except TimeoutError:
                raise SwapError(timeout_error) from None
            except SwapError:
                raise SwapError("provider session stopped; " + context_hint) from None
            if time.monotonic() >= deadline:
                raise SwapError(timeout_error)
            if message.in_reply_to is not None or message.contract_hash != contract:
                raise SwapError("unexpected provider funding context; " + context_hint)
            if message.message_type == "funding_binding":
                checked = _check_funding(
                    message,
                    terms=terms,
                    contract=contract,
                    provider_key=provider_key,
                    script=script,
                    crypto=crypto,
                )
                if time.monotonic() >= deadline:
                    raise SwapError(timeout_error)
                return checked
            if message.message_type != "observation":
                raise SwapError("unexpected provider funding message; " + context_hint)
            try:
                seen = parse_observation(canonicalize(message.payload))
            except ValueError:
                raise SwapError("invalid provider funding observation; " + context_hint) from None
            if seen.kind == "swap_aborted":
                raise SwapError(
                    f"provider reported an abort before funding ({seen.reason}); " + context_hint
                )


async def _await_depth(  # noqa: PLR0913 - explicit waiting bounds
    wallet: ClaimWallet,
    *,
    binding: FundingBinding,
    script: bytes,
    value: int,
    depth: int,
    lock_height: int,
    lifetime: _ReverseLifetime,
    report: Callable[[str], None],
) -> None:
    """Poll Core until the contract output has ``depth`` confirmations."""
    while True:
        lifetime.check()
        seen = await lifetime.worker(
            lambda: wallet.confirmed_output(binding.funding_txid, binding.contract_vout)
        )
        tip = await lifetime.worker(wallet.tip_height)
        lifetime.check()
        if tip >= lock_height:
            raise SwapError("the refund lock passed before funding was usable; " + _UNRESOLVED)
        if seen is not None:
            if (seen.script_pubkey, seen.value_sat) != (script, value):
                raise SwapError("Core shows another output at the provider's funding outpoint")
            if seen.confirmations >= depth:
                return
        report(
            f"funding {binding.funding_txid} at depth "
            f"{0 if seen is None else seen.confirmations}/{depth}"
        )
        await asyncio.sleep(min(POLL_SECONDS, max(0, lifetime.deadline - time.monotonic())))


def _claim_signer(  # noqa: PLR0913 - explicit signing inputs
    terms: ContractTerms,
    binding: FundingBinding,
    *,
    script: bytes,
    contract_secret: bytes,
    preimage: bytes,
    crypto: Context,
    check_authority: Callable[[], None] | None = None,
) -> tuple[Callable[[int, int], tuple[bytes, str, int, int]], int]:
    """Return ``sign(fee, tip) -> (raw, txid, fee, vsize)`` and the fee ceiling."""
    funding = FundingOutput(
        txid=bytes.fromhex(binding.funding_txid),
        output_index=binding.contract_vout,
        value_sat=int(terms.economics.contract_amount_sat),
        script_pubkey=script,
    )
    if check_authority is not None:
        check_authority()
    authorization = UnilateralAuthorization.from_terms(terms, funding, "claim", keys=crypto)

    def sign(fee: int, _tip: int) -> tuple[bytes, str, int, int]:
        if check_authority is not None:
            check_authority()
        plan = build_unilateral_spend(authorization, fee_sat=fee, claim_preimage=preimage)
        if check_authority is not None:
            check_authority()
        signature = bytes(
            crypto.schnorr_sign(contract_secret, plan.signature_hash, secrets.token_bytes(32))
        )
        spend = finalize_unilateral_spend(plan, signature, verifier=crypto)
        if check_authority is not None:
            check_authority()
        return spend.raw_transaction, spend.txid, spend.fee_sat, spend.vsize

    return sign, max_spendable_fee(authorization)


def _chain_view(wallet: ClaimWallet, binding: FundingBinding) -> ChainView | None:
    try:
        tip = wallet.tip_height()
        return ChainView(tip, wallet.unspent_on_chain(binding.funding_txid, binding.contract_vout))
    except Exception:  # noqa: BLE001 - a failed sample is no evidence; wait
        return None


def _submit(wallet: ClaimWallet, raw: bytes, txid: str, lifetime: _ReverseLifetime) -> bool:
    lifetime.check()  # Expired authority is not an ordinary retryable RPC failure.
    try:
        result = wallet.broadcast(raw, deadline=lifetime.deadline, effect_allowed=lifetime.allowed)
    except TimeoutError:
        raise
    except Exception:  # noqa: BLE001 - e.g. a replacement below the mempool's; retried
        lifetime.check()  # WalletRpc reports authority refusal as WalletRpcError.
        return False
    lifetime.check()
    return result == txid


async def _publish_reverse_fallback(  # noqa: PLR0913 - exact retained predecessor and private claim
    lifetime: _ReverseLifetime,
    *,
    funded_document: bytes,
    binding: FundingBinding,
    transaction: bytes,
    session: _Session,
    write_recovery: Callable[[bytes, bytes | None], bytes | None],
) -> bytes:
    """Require the trusted writer's exact acknowledgment, never infer disclosure authority.

    The CLI returns bytes only after durable encrypted publication and readback.
    Matching bytes detect accidental no-ops, not a lying storage adapter. A late
    or uncertain write may leave a valid sibling, but cannot reopen cooperation.
    """
    lifetime.check()

    def prepare() -> bytes:
        lifetime.check()
        record = parse_json_strict(funded_document)
        if not isinstance(record, dict):
            raise SwapError("reverse fallback predecessor unavailable")
        extensions = record.get("extensions")
        if not isinstance(extensions, dict):
            raise SwapError("reverse fallback predecessor unavailable")
        if REVERSE_FALLBACK_EXTENSION in extensions:
            raise SwapError("reverse fallback already prepared; restart cannot resume cooperation")
        extensions[REVERSE_FALLBACK_EXTENSION] = {
            "version": 1,
            "funding_binding_hash": funding_binding_hash(binding).hex(),
            "transaction": transaction.hex(),
        }
        candidate = canonicalize(record)
        inspect_recovery_successor(
            funded_document, candidate, session.network, crypto=session.crypto
        )
        lifetime.check()
        return candidate

    try:
        candidate = await lifetime.worker(prepare)
        acknowledged = await lifetime.worker(lambda: write_recovery(candidate, funded_document))
    except (TimeoutError, asyncio.CancelledError):
        raise
    except Exception:  # noqa: BLE001 - publication errors may contain encrypted/plaintext secrets
        raise SwapError("reverse fallback publication uncertain; " + _UNRESOLVED) from None
    lifetime.check()
    if type(acknowledged) is not bytes or acknowledged != candidate:
        raise SwapError("reverse fallback publication not acknowledged; " + _UNRESOLVED)
    return candidate


async def run_reverse_swap(  # noqa: PLR0913, PLR0915 - one ordered swap story
    connection: RelayConnection,
    *,
    identity: str,
    network: NetworkIdentity,
    payout_sat: int,
    decode_invoice: Callable[[str], InvoiceBinding],
    payer: HoldPayer,
    wallet: ClaimWallet,
    write_recovery: Callable[[bytes, bytes | None], bytes | None],
    limits: ReverseSwapLimits,
    crypto: Context,
    timeout: float = 60.0,  # noqa: ASYNC109
    settle_timeout: float = 1800.0,
    report: Callable[[str], None] = lambda _line: None,
) -> ReverseSwapOutcome:
    """Run one LN to BTC swap; see the module docstring for the order."""
    if not math.isfinite(settle_timeout) or settle_timeout <= 0:
        raise SwapError("settlement timeout must be finite and positive")
    now = int(time.time())
    preimage = secrets.token_bytes(32)
    payment_hash = hashlib.sha256(preimage).hexdigest()
    advertisement = await discover(
        connection, identity=identity, network=network, crypto=crypto, now=now, profile=PROFILE
    )
    session = _Session(connection, crypto, network, timeout=timeout, profile=PROFILE)
    init, accept, accept_signature, transcript = await _handshake(session, advertisement, identity)
    report(f"session {session.session_id[:16]} confirmed")
    provider_key = session.provider_key or ""

    contract_secret, contract_public = _scalar(crypto)
    _, recovery_public = _scalar(crypto)  # authorization key; its secret is not needed
    try:
        async with _ReverseLifetime(settle_timeout) as lifetime:
            tip = await lifetime.worker(wallet.tip_height)
            destination = await lifetime.worker(wallet.new_destination_script)
            request_model = ReverseFirmQuoteRequest(
                kind="ln-to-btc",
                mode="firm",
                nominal_payout_sat=str(payout_sat),
                payment_hash=payment_hash,
                client_contract_compressed_key=contract_public.hex(),
                recovery_authorization_xonly_key=recovery_public[1:].hex(),
                client_destination_script=destination.hex(),
                limits=ReverseQuoteLimits(
                    max_success_fee_sat=str(limits.max_success_fee_sat),
                    min_claim_fee_reserve_sat=str(limits.min_claim_fee_reserve_sat),
                    max_claim_fee_sat=str(limits.max_claim_fee_sat),
                    min_refund_lock_height=tip + limits.min_refund_delay_blocks,
                    max_incoming_htlc_expiry_height=tip + limits.max_incoming_htlc_delay_blocks,
                ),
                extensions={},
            )
            request = session.envelope("quote_request", request_model.model_dump(mode="json"))
            await session.send(request, provider_key)
            answer = await session.reply_to(request, "terms_offer")
            offer = parse_model_json(TermsOfferPayload, canonicalize(answer.payload))
            if offer.hold_invoice is None:
                raise SwapError("terms offer carries no hold invoice")
            hold = decode_invoice(offer.hold_invoice)
            if hold.bolt11_sha256 != hashlib.sha256(offer.hold_invoice.encode("ascii")).hexdigest():
                raise SwapError("invoice decoder returned another invoice")
            terms = _check_offer(
                offer,
                request_model,
                envelope=answer,
                transcript=transcript,
                hold=hold,
                identity=identity,
                network=network,
                crypto=crypto,
                now=int(time.time()),
            )
            economics = terms.economics
            contract = offer.terms.contract_hash
            min_incoming = int(terms.timing_policy.model_dump()["min_incoming_htlc_expiry_height"])
            report(
                f"terms: pay {int(hold.amount_msat) // 1000} sat on Lightning for "
                f"{economics.contract_amount_sat} sat on chain; provider refunds after block "
                f"{terms.refund_lock_height}"
            )
            acceptance = ClientAcceptance(
                contract_hash=contract,
                handshake_hash=transcript,
                session_id=session.session_id,
                client_session_xonly_key=session.key,
                provider_session_xonly_key=provider_key,
            )
            acceptance_signature = bytes(
                crypto.schnorr_sign(
                    session.secret,
                    client_acceptance_hash(acceptance),
                    secrets.token_bytes(32),
                )
            ).hex()
            record = {
                "session": session,
                "init": init,
                "accept": accept,
                "accept_signature": accept_signature,
                "offer": offer,
                "acceptance_signature": acceptance_signature,
                "contract_secret": contract_secret,
                "birthday": tip,
                "created_at": int(time.time()),
                "preimage": preimage,
            }
            document = _recovery_document(**record)  # type: ignore[arg-type]
            await lifetime.worker(lambda: write_recovery(document, None))
            report("recovery file written (terms and preimage, nothing paid yet)")
            accepted = session.envelope(
                "terms_accept",
                {
                    "acceptance": acceptance.model_dump(mode="json"),
                    "client_acceptance_signature": acceptance_signature,
                },
                in_reply_to=answer.message_id,
                contract=contract,
            )
            await session.send(accepted, provider_key)
            await session.reply_to(accepted, "ack")

            lifetime.start()  # Includes queueing and uncertain submission, never renewed.
            try:
                status = await lifetime.worker(
                    lambda: payer.pay(
                        offer.hold_invoice or "",
                        invoice_binding=hold,
                        min_final_expiry_height=min_incoming,
                        max_expiry_height=request_model.limits.max_incoming_htlc_expiry_height,
                        fee_limit_sat=limits.max_routing_fee_sat,
                        deadline=lifetime.deadline,
                        submission_allowed=lifetime.allowed,
                    )
                )
            except LndObservationError:
                raise SwapError("hold payment outcome unknown; " + _UNRESOLVED) from None
            if status == "FAILED":
                raise SwapError("the hold invoice could not be paid; nothing is at risk")
            if status not in {"IN_FLIGHT", "SUCCEEDED"}:
                raise SwapError("hold payment outcome unknown; " + _UNRESOLVED)
            report(f"hold payment observed ({status}); waiting for the provider's funding")

            lifetime.check()
            script = reconstruct_taproot_contract(terms, keys=crypto).script_pubkey
            lifetime.check()
            binding, binding_signature, _raw = await _await_funding(
                session,
                contract=contract,
                timeout=settle_timeout,
                terms=terms,
                provider_key=provider_key,
                script=script,
                crypto=crypto,
                absolute_deadline=lifetime.deadline,
            )
            successor = _recovery_document(
                **record,  # type: ignore[arg-type]
                funding=((binding, binding_signature),),
            )
            await lifetime.worker(lambda: write_recovery(successor, document))
            report(
                f"funded recovery snapshot written (funding {binding.funding_txid}, "
                f"attempt {binding.funding_attempt_id} revision 0)"
            )
            value = int(economics.contract_amount_sat)
            await _await_depth(
                wallet,
                binding=binding,
                script=script,
                value=value,
                depth=terms.funding_confirmations,
                lock_height=terms.refund_lock_height,
                lifetime=lifetime,
                report=report,
            )
            sign, ceiling = _claim_signer(
                terms,
                binding,
                script=script,
                contract_secret=contract_secret,
                preimage=preimage,
                crypto=crypto,
                check_authority=lifetime.check,
            )
            probe_vsize = (await lifetime.worker(lambda: sign(min(ceiling, 1), 0)))[3]
            initial_fee = max(
                1, min(ceiling, math.ceil(limits.claim_fee_rate_sat_vb * probe_vsize))
            )
            if COOPERATIVE_CLAIM_FEATURE in terms.required_features:
                prepared_claim = await lifetime.worker(lambda: sign(initial_fee, 0))
                await _publish_reverse_fallback(
                    lifetime,
                    funded_document=successor,
                    binding=binding,
                    transaction=prepared_claim[0],
                    session=session,
                    write_recovery=write_recovery,
                )
                report("private signed fallback snapshot acknowledged; cooperation remains gated")
                # Do not turn a negotiated privacy commitment into an implicit
                # script-path claim while the cooperative consumer is unfinished.
                raise SwapError(
                    "reverse cooperative settlement is not yet available; " + _UNRESOLVED
                )

            watcher = ClaimWatcher(
                initial_fee_sat=initial_fee,
                max_fee_sat=max(1, ceiling),
                deadline_height=terms.refund_lock_height
                - terms.timing_policy.claim_confirmation_blocks,
                chain=lambda: _chain_view(wallet, binding),
                confirmations=wallet.wallet_confirmations,
                sign=sign,
                submit=lambda raw, txid: _submit(wallet, raw, txid, lifetime),
                report=report,
                poll_seconds=POLL_SECONDS,
                deadline=lifetime.deadline,
                effect_allowed=lifetime.allowed,
            )
            outcome, claim_txid = await lifetime.worker(watcher.run)
            if outcome == "claim_window_passed":
                raise SwapError("the claim window closed; " + _UNRESOLVED)
            if outcome != "claim_confirmed" or claim_txid is None:
                raise SwapError("the contract was spent by another transaction; " + _UNRESOLVED)
            report(f"claim {claim_txid} confirmed; the provider settles the hold from its witness")
            return ReverseSwapOutcome(
                session.session_id, contract, binding.funding_txid, claim_txid, value
            )
    except TimeoutError:
        raise SwapError("original reverse settlement lifetime expired; " + _UNRESOLVED) from None
