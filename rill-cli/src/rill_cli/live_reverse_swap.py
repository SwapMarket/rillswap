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
recovery file plus ``rill recover prepare-claim`` / ``broadcast-claim``
finish the claim from the funded snapshot.
"""

from __future__ import annotations

import asyncio
import hashlib
import math
import secrets
import time
from dataclasses import dataclass
from typing import TYPE_CHECKING, Literal, Protocol

from rill_core.settlement import (
    FundingOutput,
    UnilateralAuthorization,
    build_unilateral_spend,
    check_funding_binding_transaction,
    finalize_unilateral_spend,
    max_spendable_fee,
    reconstruct_taproot_contract,
)
from rill_core.wire.canonical import canonicalize, parse_model_json
from rill_core.wire.hashes import (
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

from rill_cli.live_swap import (
    SwapError,
    _handshake,
    _recovery_document,
    _scalar,
    _Session,
    discover,
)

if TYPE_CHECKING:
    from collections.abc import Callable

    from rill_core.wire.messages import ContractTerms, Envelope, FundingBinding, InvoiceBinding
    from rill_core.wire.types import NetworkIdentity
    from rill_crypto import Context
    from rill_provider.relay_client import RelayConnection

    from rill_cli.hold_payment import HoldStatus
    from rill_cli.wallet_rpc import ConfirmedOutput

PROFILE: Literal["ln-to-btc/v1"] = "ln-to-btc/v1"
POLL_SECONDS = 5.0


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

    def broadcast(self, raw: bytes) -> str:
        """Submit exact bytes; return Core's txid."""
        ...


class HoldPayer(Protocol):
    """The user's own LND (``LndHoldPayer``)."""

    def pay(
        self,
        bolt11: str,
        *,
        invoice_binding: InvoiceBinding,
        min_final_expiry_height: int,
        max_expiry_height: int,
        fee_limit_sat: int,
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


async def _await_funding(  # noqa: PLR0913 - explicit waiting bounds
    session: _Session,
    *,
    contract: str,
    timeout: float,  # noqa: ASYNC109
    terms: ContractTerms,
    provider_key: str,
    script: bytes,
    crypto: Context,
) -> tuple[FundingBinding, str, bytes]:
    """Wait for the signed funding_binding; a swap_aborted notice ends the swap."""
    deadline = time.monotonic() + timeout
    while True:
        try:
            message = await session.receive(
                lambda item: (
                    item.message_type in ("funding_binding", "observation")
                    and item.in_reply_to is None
                    and item.contract_hash == contract
                ),
                timeout=max(0.1, deadline - time.monotonic()),
            )
        except TimeoutError:
            raise SwapError(
                "provider did not fund in time; the held payment fails back when the "
                "provider cancels the hold, check `lncli listpayments`"
            ) from None
        if message.message_type == "funding_binding":
            return _check_funding(
                message,
                terms=terms,
                contract=contract,
                provider_key=provider_key,
                script=script,
                crypto=crypto,
            )
        seen = parse_observation(canonicalize(message.payload))
        if seen.kind == "swap_aborted":
            raise SwapError(f"provider aborted before funding ({seen.reason}); nothing is at risk")


async def _await_depth(  # noqa: PLR0913 - explicit waiting bounds
    wallet: ClaimWallet,
    *,
    binding: FundingBinding,
    script: bytes,
    value: int,
    depth: int,
    lock_height: int,
    timeout: float,  # noqa: ASYNC109
    report: Callable[[str], None],
) -> None:
    """Poll Core until the contract output has ``depth`` confirmations."""
    deadline = time.monotonic() + timeout
    while True:
        seen = await asyncio.to_thread(
            wallet.confirmed_output, binding.funding_txid, binding.contract_vout
        )
        if seen is not None:
            if (seen.script_pubkey, seen.value_sat) != (script, value):
                raise SwapError("Core shows another output at the provider's funding outpoint")
            if seen.confirmations >= depth:
                return
        tip = await asyncio.to_thread(wallet.tip_height)
        if tip >= lock_height:
            raise SwapError(
                "the refund lock passed before the funding was usable; claim with "
                "`rill recover prepare-claim` only if the output is still unspent"
            )
        if time.monotonic() >= deadline:
            raise SwapError(
                "funding did not confirm in time; finish with `rill recover prepare-claim` "
                "and `broadcast-claim` on the funded recovery file"
            )
        report(
            f"funding {binding.funding_txid} at depth "
            f"{0 if seen is None else seen.confirmations}/{depth}"
        )
        await asyncio.sleep(POLL_SECONDS)


def _claim(  # noqa: PLR0913 - explicit signing inputs
    terms: ContractTerms,
    binding: FundingBinding,
    *,
    script: bytes,
    contract_secret: bytes,
    preimage: bytes,
    fee_rate_sat_vb: int,
    crypto: Context,
) -> tuple[bytes, str]:
    """Build, sign, and validate the claim; return its bytes and txid."""
    funding = FundingOutput(
        txid=bytes.fromhex(binding.funding_txid),
        output_index=binding.contract_vout,
        value_sat=int(terms.economics.contract_amount_sat),
        script_pubkey=script,
    )
    authorization = UnilateralAuthorization.from_terms(terms, funding, "claim", keys=crypto)
    ceiling = max_spendable_fee(authorization)

    def sign(fee: int) -> tuple[bytes, str, int]:
        plan = build_unilateral_spend(authorization, fee_sat=fee, claim_preimage=preimage)
        signature = bytes(
            crypto.schnorr_sign(contract_secret, plan.signature_hash, secrets.token_bytes(32))
        )
        spend = finalize_unilateral_spend(plan, signature, verifier=crypto)
        return spend.raw_transaction, spend.txid, spend.vsize

    raw, txid, vsize = sign(min(ceiling, 1))
    wanted = min(ceiling, math.ceil(fee_rate_sat_vb * vsize))
    if wanted != min(ceiling, 1):
        raw, txid, _ = sign(wanted)
    return raw, txid


async def run_reverse_swap(  # noqa: PLR0913, PLR0915 - one ordered swap story
    connection: RelayConnection,
    *,
    identity: str,
    network: NetworkIdentity,
    payout_sat: int,
    decode_invoice: Callable[[str], InvoiceBinding],
    payer: HoldPayer,
    wallet: ClaimWallet,
    write_recovery: Callable[[bytes, bytes | None], None],
    limits: ReverseSwapLimits,
    crypto: Context,
    timeout: float = 60.0,  # noqa: ASYNC109
    settle_timeout: float = 1800.0,
    report: Callable[[str], None] = lambda _line: None,
) -> ReverseSwapOutcome:
    """Run one LN to BTC swap; see the module docstring for the order."""
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
    tip = await asyncio.to_thread(wallet.tip_height)
    destination = await asyncio.to_thread(wallet.new_destination_script)
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
    timing = terms.timing_policy.model_dump()
    min_incoming = int(timing["min_incoming_htlc_expiry_height"])
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
            session.secret, client_acceptance_hash(acceptance), secrets.token_bytes(32)
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
    await asyncio.to_thread(write_recovery, document, None)
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

    try:
        status = await asyncio.to_thread(
            lambda: payer.pay(
                offer.hold_invoice or "",
                invoice_binding=hold,
                min_final_expiry_height=min_incoming,
                max_expiry_height=request_model.limits.max_incoming_htlc_expiry_height,
                fee_limit_sat=limits.max_routing_fee_sat,
            )
        )
    except LndObservationError as error:
        raise SwapError(
            f"hold invoice payment not submitted ({error}); nothing is at risk"
        ) from None
    if status == "FAILED":
        raise SwapError("the hold invoice could not be paid; nothing is at risk")
    report(f"hold invoice paid ({status}); waiting for the provider's funding")

    script = reconstruct_taproot_contract(terms, keys=crypto).script_pubkey
    binding, binding_signature, _raw = await _await_funding(
        session,
        contract=contract,
        timeout=settle_timeout,
        terms=terms,
        provider_key=provider_key,
        script=script,
        crypto=crypto,
    )
    successor = _recovery_document(
        **record,  # type: ignore[arg-type]
        funding=((binding, binding_signature),),
    )
    await asyncio.to_thread(write_recovery, successor, document)
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
        timeout=settle_timeout,
        report=report,
    )
    raw_claim, claim_txid = _claim(
        terms,
        binding,
        script=script,
        contract_secret=contract_secret,
        preimage=preimage,
        fee_rate_sat_vb=limits.claim_fee_rate_sat_vb,
        crypto=crypto,
    )
    broadcast = await asyncio.to_thread(wallet.broadcast, raw_claim)
    if broadcast != claim_txid:
        raise SwapError("Core broadcast another transaction; check the wallet")
    report(f"claim broadcast {claim_txid}; the provider settles the hold from its witness")
    return ReverseSwapOutcome(session.session_id, contract, binding.funding_txid, claim_txid, value)
