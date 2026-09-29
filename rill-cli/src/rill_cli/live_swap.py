"""Regtest BTC to LN swap client over Nostr relays (RS-001, RS-003, RS-005).

One swap, one fresh session: discover and verify the provider announcement,
handshake, request firm terms for the user's invoice, verify them, write the
encrypted recovery file, accept, fund from the local Core wallet, write the
funded recovery snapshot, bind the funding, broadcast, then wait for the
provider's ``payment_settled`` observation and check the preimage.

Every irreversible step is preceded by a durable recovery record: the terms
recovery file exists before acceptance, and the snapshot with the signed
binding exists before the funding transaction is broadcast. If the provider
never pays, the user refunds after ``refund_lock_height`` with
``rill recover watch-refund`` (or ``sign-refund``/``broadcast-refund``).
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import math
import secrets
import time
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Literal, Protocol

from rill_core.domain.chain import MAX_EXACT_JSON_INTEGER
from rill_core.settlement import (
    FundingPlan,
    authorize_funding_transaction,
    reconstruct_taproot_contract,
)
from rill_core.wire.canonical import canonicalize, parse_model_json
from rill_core.wire.cooperative_messages import (
    CooperativeClaimReadyRequest,
    check_cooperative_action_context,
)
from rill_core.wire.hashes import (
    COOPERATIVE_CLAIM_FEATURE,
    EPOCH_SESSION_EXTENSION,
    EPOCH_SESSION_FEATURE,
    HANDSHAKE_FEATURES_EXTENSION,
    client_acceptance_hash,
    contract_hash,
    epoch_bound_session_id,
    funding_binding_hash,
    handshake_accept_hash,
    handshake_hash,
    provider_terms_hash,
    tagged_hash,
    unsigned_envelope_hash,
)
from rill_core.wire.messages import (
    ClientAcceptance,
    Envelope,
    FundingBinding,
    HandshakeAccept,
    HandshakeAcceptPayload,
    HandshakeInit,
)
from rill_core.wire.quotes import (
    FirmQuoteRequest,
    QuoteLimits,
    TermsOfferPayload,
    check_terms_offer,
)
from rill_core.wire.settlement_messages import PaymentSettled, parse_observation
from rill_provider import _nip01_event as nip01
from rill_provider._nip59_receive import _decode_gift_wrap_candidate
from rill_provider._nip59_send import _wrap_envelope
from rill_provider.provider_identity import ADVERTISEMENT_TAG, ANNOUNCEMENT_KIND

if TYPE_CHECKING:
    from collections.abc import Callable

    from rill_core.wire.messages import ContractTerms, InvoiceBinding
    from rill_core.wire.types import NetworkIdentity
    from rill_crypto import Context
    from rill_provider.relay_client import RelayConnection

    from rill_cli.wallet_rpc import WalletFunding

PROFILE: Literal["btc-to-ln/v1"] = "btc-to-ln/v1"
type ProfileId = Literal["btc-to-ln/v1", "ln-to-btc/v1"]
ENCRYPTION_SUITES = ("noise-xk-secp256k1-chachapoly-sha256/v1",)
CAPABILITIES = ("core/v1", "recovery/v1")
NIP59_BACKDATE_SECONDS = 2 * 24 * 60 * 60
MAX_PROVIDER_SEQUENCE_WINDOW = 16
MAX_PROVIDER_PENDING_BYTES = 256 * 1024
MAX_PROVIDER_MESSAGES = 4096
MAX_PROVIDER_INBOX_MESSAGES = 64
MAX_PROVIDER_INBOX_BYTES = 256 * 1024
GIFT_WRAP_KIND = 1059
MAX_DISCOVERY_EVENTS = 256


class SwapError(RuntimeError):
    """The swap stopped; the message says whether funds were committed."""


class Wallet(Protocol):
    """The user's own Core wallet (``WalletRpc``)."""

    def tip_height(self) -> int:
        """Return the best height."""
        ...

    def new_destination_script(self) -> bytes:
        """Return a fresh refund destination scriptPubKey."""
        ...

    def fund(self, script_pubkey: bytes, amount_sat: int, *, fee_rate_sat_vb: int) -> WalletFunding:
        """Return a signed, unbroadcast funding transaction."""
        ...

    def broadcast(self, raw: bytes) -> str:
        """Submit exact bytes."""
        ...


@dataclass(frozen=True, slots=True)
class SwapLimits:
    """The user's ceilings for the firm offer."""

    max_success_fee_sat: int
    max_funding_fee_sat: int = 5_000
    max_claim_fee_sat: int = 5_000
    max_refund_fee_sat: int = 5_000
    max_refund_delay_blocks: int = 288
    funding_fee_rate_sat_vb: int = 2


@dataclass(frozen=True, slots=True)
class SwapOutcome:
    """A settled swap: the preimage proves the invoice was paid."""

    session_id: str
    contract_hash: str
    funding_txid: str
    payment_preimage: str
    refund_lock_height: int


def _scalar(crypto: Context) -> tuple[bytes, bytes]:
    """Return a fresh valid secret scalar and its compressed public key."""
    while True:
        secret = secrets.token_bytes(32)
        try:
            return secret, bytes(crypto.public_key(secret))
        except Exception:  # noqa: BLE001, S112 - out of range, draw again
            continue


def verify_announcement(  # noqa: PLR0913 - explicit trust inputs
    raw: bytes,
    *,
    identity: str,
    network: NetworkIdentity,
    crypto: Context,
    now: int,
    profile: ProfileId = PROFILE,
) -> dict[str, Any]:
    """Return the advertisement of a valid, unexpired announcement or raise."""
    event = nip01._verify_signed_event(raw, verifier=crypto)  # noqa: SLF001
    if event.pubkey != identity or event.kind != ANNOUNCEMENT_KIND:
        raise SwapError("announcement from another key or kind")
    wrapper = json.loads(event.content)
    advertisement = wrapper["advertisement"]
    if type(advertisement.get("revision")) is not int or not (
        0 <= advertisement["revision"] <= MAX_EXACT_JSON_INTEGER
    ):
        raise SwapError("announcement does not offer an exact bounded revision")
    crypto.schnorr_verify(
        bytes.fromhex(identity),
        tagged_hash(ADVERTISEMENT_TAG, canonicalize(advertisement)),
        bytes.fromhex(wrapper["signature"]),
    )
    if (
        advertisement["provider_identity_xonly_key"] != identity
        or network.model_dump(mode="json") not in advertisement["network_identities"]
        or profile not in advertisement["profiles"]
        or not advertisement["created_at"] <= now < advertisement["expires_at"]
        or not advertisement["epoch_inbox_xonly_keys"]
    ):
        raise SwapError("announcement does not offer this swap now")
    _requires_epoch_binding(advertisement)
    return dict(advertisement)


def _requires_epoch_binding(advertisement: dict[str, Any]) -> bool:
    """Interpret only an explicit, signed requirement; malformed is not legacy."""
    extensions = advertisement.get("extensions", {})
    if not isinstance(extensions, dict):
        raise SwapError("announcement extensions unsupported")
    if not extensions:
        return False
    if set(extensions) != {HANDSHAKE_FEATURES_EXTENSION} or extensions[
        HANDSHAKE_FEATURES_EXTENSION
    ] != [EPOCH_SESSION_FEATURE]:
        raise SwapError("announcement handshake requirements unsupported")
    return True


async def discover(  # noqa: PLR0913 - explicit trust inputs
    connection: RelayConnection,
    *,
    identity: str,
    network: NetworkIdentity,
    crypto: Context,
    now: int,
    timeout: float = 10.0,  # noqa: ASYNC109
    profile: ProfileId = PROFILE,
) -> dict[str, Any]:
    """Select the highest valid revision observed during a bounded relay query.

    A relay can withhold announcements; this is not a proof of global freshness.
    Refuse equivocation or a truncated flood rather than accepting the first ad.
    """
    await connection.subscribe([{"kinds": [ANNOUNCEMENT_KIND], "authors": [identity]}])
    best: dict[str, Any] | None = None
    seen = 0
    try:
        async with asyncio.timeout(timeout):
            async for raw in connection.events():
                seen += 1
                if seen > MAX_DISCOVERY_EVENTS:
                    raise SwapError(
                        "provider discovery event limit exceeded; nothing was committed"
                    )
                try:
                    found = verify_announcement(
                        raw,
                        identity=identity,
                        network=network,
                        crypto=crypto,
                        now=now,
                        profile=profile,
                    )
                except Exception:  # noqa: BLE001, S112 - ignore invalid events
                    continue
                if best is not None and found["revision"] == best["revision"] and found != best:
                    raise SwapError("provider announced conflicting data at the same revision")
                if best is None or found["revision"] > best["revision"]:
                    best = found
    except TimeoutError:
        pass
    if best is None:
        raise SwapError("no valid provider announcement found; nothing was committed")
    return best


class _Session:
    """One client session's keys, sequence, and authenticated inbox."""

    def __init__(
        self,
        connection: RelayConnection,
        crypto: Context,
        network: NetworkIdentity,
        *,
        timeout: float,
        profile: ProfileId = PROFILE,
    ) -> None:
        self.connection = connection
        self.crypto = crypto
        self.network = network
        self.timeout = timeout
        self.profile = profile
        self.secret, public = _scalar(crypto)
        self.key = public[1:].hex()
        self.session_id = secrets.token_hex(32)
        self.sequence = 0
        self.provider_key: str | None = None
        self._expected_accept: tuple[Envelope, HandshakeInit, str] | None = None
        self.seen: set[str] = set()
        self.inbox: list[Envelope] = []
        self._inbox_bytes = 0
        self._provider_next = 0
        self._provider_by_id: dict[str, bytes] = {}
        self._provider_by_sequence: dict[int, tuple[str, bytes]] = {}
        self._provider_pending: dict[int, tuple[Envelope, int]] = {}
        self._provider_pending_bytes = 0

    def envelope(  # noqa: PLR0913 - explicit per-envelope negotiated features
        self,
        message_type: str,
        payload: dict[str, Any],
        *,
        in_reply_to: str | None = None,
        contract: str | None = None,
        signed: bool = True,
        required_features: tuple[str, ...] = (),
    ) -> Envelope:
        unsigned = Envelope.model_validate_json(
            canonicalize(
                {
                    "protocol": "rillswap",
                    "wire_version": "1",
                    "profile_id": self.profile,
                    "network_identity": self.network.model_dump(mode="json"),
                    "session_id": self.session_id,
                    "message_id": secrets.token_hex(32),
                    "sender_session_key": self.key,
                    "sequence": self.sequence,
                    "in_reply_to": in_reply_to,
                    "contract_hash": contract,
                    "message_type": message_type,
                    "payload": payload,
                    "required_features": list(required_features),
                    "extensions": {},
                    "signature": None,
                }
            ),
            strict=True,
        )
        self.sequence += 1
        if not signed:
            return unsigned
        signature = self.crypto.schnorr_sign(
            self.secret, unsigned_envelope_hash(unsigned), secrets.token_bytes(32)
        )
        return unsigned.model_copy(update={"signature": bytes(signature).hex()})

    async def send(self, envelope: Envelope, recipient: str) -> None:
        event = _wrap_envelope(
            canonicalize(envelope.model_dump(mode="json")),
            sender_session_secret=self.secret,
            recipient_xonly_key=recipient,
            crypto=self.crypto,
        )
        for _ in range(3):
            if await self.connection.publish(event):
                return
        raise SwapError(f"relay did not accept {envelope.message_type}")

    async def listen(self) -> None:
        await self.connection.subscribe(
            [
                {
                    "kinds": [GIFT_WRAP_KIND],
                    "#p": [self.key],
                    "since": int(time.time()) - NIP59_BACKDATE_SECONDS,
                }
            ]
        )

    def expect_accept(self, request: Envelope, initiation: HandshakeInit, identity: str) -> None:
        """Do not bind an unsigned accept until its identity signature verifies."""
        if self.provider_key is not None or self._expected_accept is not None:
            raise SwapError("handshake already started")
        self._expected_accept = (request, initiation, identity)

    def _authenticate_initial_accept(self, envelope: Envelope) -> bool:
        """Bind only the identity-authenticated provider session key."""
        if envelope.message_type != "handshake_accept" or self._expected_accept is None:
            return False
        request, initiation, identity = self._expected_accept
        try:
            if (
                envelope.sequence != 0
                or envelope.signature is not None
                or envelope.in_reply_to != request.message_id
                or envelope.contract_hash is not None
                or set(envelope.required_features) - {EPOCH_SESSION_FEATURE}
            ):
                return False
            payload = parse_model_json(HandshakeAcceptPayload, canonicalize(envelope.payload))
            accepted = payload.accept
            accepted.validate_against(
                initiation, supported_features=frozenset({EPOCH_SESSION_FEATURE})
            )
            if accepted.provider_session_xonly_key != envelope.sender_session_key:
                return False
            self.crypto.schnorr_verify(
                bytes.fromhex(identity),
                handshake_accept_hash(accepted),
                bytes.fromhex(payload.provider_identity_signature),
            )
        except Exception:  # noqa: BLE001 - invalid accept cannot establish a provider
            return False
        self.provider_key = envelope.sender_session_key
        self._expected_accept = None
        return True

    def _admit(self, raw: bytes) -> Envelope | None:
        try:
            frame = _decode_gift_wrap_candidate(
                raw,
                recipient_mailbox_secret=self.secret,
                expected_recipient_xonly_key=self.key,
                expected_network=self.network,
                expected_profile_id=self.profile,
                crypto=self.crypto,
            )
        except Exception:  # noqa: BLE001 - not for us or malformed
            return None
        envelope = frame.envelope
        if (
            envelope.session_id != self.session_id
            or frame.seal_author_xonly_key != envelope.sender_session_key
            or (self.provider_key is not None and envelope.sender_session_key != self.provider_key)
        ):
            return None
        if self.provider_key is None:
            if not self._authenticate_initial_accept(envelope):
                return None
        else:
            if envelope.message_type == "handshake_accept":
                return None  # only the first identity-authenticated accept binds the session
            try:
                self.crypto.schnorr_verify(
                    bytes.fromhex(envelope.sender_session_key),
                    unsigned_envelope_hash(envelope),
                    bytes.fromhex(envelope.signature or ""),
                )
            except Exception:  # noqa: BLE001 - unsigned or forged
                return None
        return self._order_provider(envelope)

    def _order_provider(self, envelope: Envelope) -> Envelope | None:
        """Admit authenticated provider bytes only across a contiguous stream."""
        if envelope.message_type == "handshake_accept":
            self.seen.add(envelope.message_id)
            self._provider_by_id[envelope.message_id] = unsigned_envelope_hash(envelope)
            self._provider_by_sequence[0] = (
                envelope.message_id,
                self._provider_by_id[envelope.message_id],
            )
            self._provider_next = 1
            return envelope
        digest = unsigned_envelope_hash(envelope)
        existing_id = self._provider_by_id.get(envelope.message_id)
        existing_sequence = self._provider_by_sequence.get(envelope.sequence)
        if (existing_id is not None and existing_id != digest) or (
            existing_sequence is not None and existing_sequence != (envelope.message_id, digest)
        ):
            raise SwapError("provider signed a conflicting sequence or message ID")
        if existing_id is not None:
            return None  # exact replay cannot repeat a client effect
        if (
            envelope.sequence < self._provider_next
            or envelope.sequence > self._provider_next + MAX_PROVIDER_SEQUENCE_WINDOW
            or len(self._provider_by_id) >= MAX_PROVIDER_MESSAGES
        ):
            raise SwapError("provider sequence outside the bounded live window")
        size = len(canonicalize(envelope.model_dump(mode="json")))
        if envelope.sequence != self._provider_next and (
            len(self._provider_pending) >= MAX_PROVIDER_SEQUENCE_WINDOW
            or self._provider_pending_bytes + size > MAX_PROVIDER_PENDING_BYTES
        ):
            raise SwapError("provider future-message buffer exhausted")
        self.seen.add(envelope.message_id)
        self._provider_by_id[envelope.message_id] = digest
        self._provider_by_sequence[envelope.sequence] = (envelope.message_id, digest)
        if envelope.sequence != self._provider_next:
            self._provider_pending[envelope.sequence] = (envelope, size)
            self._provider_pending_bytes += size
            return None
        self._provider_next += 1
        while pending := self._provider_pending.pop(self._provider_next, None):
            ready, buffered_size = pending
            self._provider_pending_bytes -= buffered_size
            self._buffer_inbox(ready)
            self._provider_next += 1
        return envelope

    def _buffer_inbox(self, envelope: Envelope) -> None:
        """Keep selectively deferred messages within a small process budget."""
        size = len(canonicalize(envelope.model_dump(mode="json")))
        if (
            len(self.inbox) >= MAX_PROVIDER_INBOX_MESSAGES
            or self._inbox_bytes + size > MAX_PROVIDER_INBOX_BYTES
        ):
            raise SwapError("provider live inbox exhausted")
        self.inbox.append(envelope)
        self.inbox.sort(key=lambda item: item.sequence)
        self._inbox_bytes += size

    def _pop_inbox(self, index: int) -> Envelope:
        envelope = self.inbox.pop(index)
        self._inbox_bytes -= len(canonicalize(envelope.model_dump(mode="json")))
        return envelope

    async def receive(
        self,
        wanted: Callable[[Envelope], bool],
        *,
        timeout: float | None = None,  # noqa: ASYNC109
    ) -> Envelope:
        for index, envelope in enumerate(self.inbox):
            if wanted(envelope):
                return self._pop_inbox(index)
        duration = self.timeout if timeout is None else timeout
        loop = asyncio.get_running_loop()
        deadline = loop.time() + duration
        try:
            async with asyncio.timeout(duration):
                async for raw in self.connection.events():
                    # Already-queued invalid/replayed frames need not suspend,
                    # so the timeout callback alone cannot bound this loop.
                    if loop.time() >= deadline:
                        break
                    admitted = self._admit(raw)
                    if admitted is None:
                        continue
                    if wanted(admitted):
                        return admitted
                    self._buffer_inbox(admitted)
                    for index, ready in enumerate(self.inbox):
                        if wanted(ready):
                            return self._pop_inbox(index)
        except TimeoutError:
            pass
        raise TimeoutError

    async def receive_next(self, *, timeout: float | None = None) -> Envelope:  # noqa: ASYNC109
        """Take the first admitted provider message, never skipping an earlier one."""
        return await self.receive(lambda _item: True, timeout=timeout)

    async def reply_to(self, request: Envelope, expected: str) -> Envelope:
        try:
            answer = await self.receive(lambda item: item.in_reply_to == request.message_id)
        except TimeoutError:
            raise SwapError(f"no answer to {request.message_type}") from None
        if answer.message_type == "error":
            raise SwapError(
                f"provider refused {request.message_type}: {answer.payload.get('code')}"
            )
        if answer.message_type != expected:
            raise SwapError(f"unexpected answer {answer.message_type}")
        return answer


async def _wait_for_payment(
    session: _Session,
    terms: ContractTerms,
    *,
    deadline: float,
    refund_hint: str,
) -> str:
    """Dispatch the original provider stream in order under one fixed lifetime.

    Cooperation is not negotiated by the current client. Never skip an action
    request to a later payment observation, and never echo readiness before
    a complete signing/completion handler is available.
    """
    loop = asyncio.get_running_loop()
    expected_contract = contract_hash(terms).hex()
    timeout_error = "provider settlement not observed in time; " + refund_hint
    while True:
        remaining = deadline - loop.time()
        if remaining <= 0:
            raise SwapError(timeout_error)
        try:
            message = await session.receive_next(timeout=remaining)
        except TimeoutError:
            raise SwapError(timeout_error) from None
        except SwapError as error:
            raise SwapError(f"provider session stopped: {error}; " + refund_hint) from None
        if loop.time() >= deadline:
            raise SwapError(timeout_error)
        if message.contract_hash != expected_contract or message.in_reply_to is not None:
            raise SwapError("unexpected provider settlement context; " + refund_hint)
        if message.message_type == "action_request":
            raise SwapError("cooperation unavailable; payment status unresolved; " + refund_hint)
        if message.message_type != "observation":
            raise SwapError("unexpected provider settlement message; " + refund_hint)
        try:
            seen = parse_observation(canonicalize(message.payload))
        except ValueError:
            raise SwapError("invalid provider settlement observation; " + refund_hint) from None
        if isinstance(seen, PaymentSettled):
            preimage = seen.payment_preimage
            if hashlib.sha256(bytes.fromhex(preimage)).hexdigest() != (
                terms.invoice_binding.payment_hash
            ):
                raise SwapError("provider sent a wrong preimage; " + refund_hint)
            return preimage
        if seen.kind == "payment_failed":
            raise SwapError("provider reports the payment failed; " + refund_hint)


async def _answer_cooperative_readiness(  # noqa: PLR0913 - all independent bindings are explicit
    session: _Session,
    request: Envelope,
    *,
    terms: ContractTerms,
    init: HandshakeInit,
    accept: HandshakeAccept,
    provider_key: str,
    observed_preimage: str | None,
    now: int,
    tip_height: int,
) -> str:
    """Answer one authenticated original-session readiness request, no nonce.

    This helper does not establish receive ordering or consent to a proposal.
    Its caller must admit the request from the original relay session exactly
    once, not from a recovery file, and retain the swap's bounded lifetime.
    """
    if (
        request.sender_session_key != provider_key
        or session.provider_key != provider_key
        or session.session_id != init.session_id
        or request.message_type != "action_request"
    ):
        raise SwapError("readiness is not from this provider session")
    try:
        session.crypto.schnorr_verify(
            bytes.fromhex(provider_key),
            unsigned_envelope_hash(request),
            bytes.fromhex(request.signature or ""),
        )
        payload = check_cooperative_action_context(request, terms, init, accept)
    except Exception:  # noqa: BLE001 - a signed but invalid request grants no effect
        raise SwapError("cooperative readiness refused") from None
    if not isinstance(payload, CooperativeClaimReadyRequest) or (
        type(now) is not int
        or type(tip_height) is not int
        or now < 0
        or tip_height < 0
        or not now < payload.deadline_at <= now + 30
        or not tip_height
        < payload.deadline_height
        <= (terms.refund_lock_height - terms.timing_policy.claim_confirmation_blocks)
        or hashlib.sha256(bytes.fromhex(payload.payment_preimage)).hexdigest()
        != terms.invoice_binding.payment_hash
        or (observed_preimage is not None and payload.payment_preimage != observed_preimage)
    ):
        raise SwapError("cooperative readiness refused")
    reply = session.envelope(
        "action_result",
        {
            "action": "cooperative_claim_ready",
            "challenge": payload.challenge,
            "status": "ready",
        },
        in_reply_to=request.message_id,
        contract=contract_hash(terms).hex(),
        required_features=(COOPERATIVE_CLAIM_FEATURE,),
    )
    await session.send(reply, provider_key)
    return payload.payment_preimage


def _recovery_document(  # noqa: PLR0913 - one record's explicit parts
    *,
    session: _Session,
    init: HandshakeInit,
    accept: HandshakeAccept,
    accept_signature: str,
    offer: TermsOfferPayload,
    acceptance_signature: str,
    contract_secret: bytes,
    birthday: int,
    created_at: int,
    funding: tuple[tuple[FundingBinding, str], ...] = (),
    preimage: bytes | None = None,
) -> bytes:
    terms = offer.terms.contract_terms
    artifacts = reconstruct_taproot_contract(terms, keys=session.crypto)
    return canonicalize(
        {
            "format": "rillswap-recovery",
            "format_version": "1-pre.1",
            "specification_version": "0.1.0-pre.1",
            "created_at": created_at,
            "updated_at": int(time.time()) if funding else created_at,
            "network_identity": session.network.model_dump(mode="json"),
            "profile_id": session.profile,
            "contract_hash": offer.terms.contract_hash,
            "contract_terms": terms.model_dump(mode="json"),
            "verification_context": {
                "handshake_init": init.model_dump(mode="json"),
                "handshake_accept": accept.model_dump(mode="json"),
                "provider_identity_signature": accept_signature,
                "handshake_hash": offer.terms.handshake_hash,
                "client_session_xonly_key": session.key,
                "provider_session_xonly_key": accept.provider_session_xonly_key,
                "expected_provider_identity_source": {
                    "kind": "manual",
                    "advertisement_digest": None,
                },
                "provider_terms_signature": offer.provider_terms_signature,
                "client_acceptance_signature": acceptance_signature,
            },
            "taproot_contract": {
                "internal_xonly_key": artifacts.internal_key.hex(),
                "internal_key_parity": artifacts.internal_parity,
                "claim_script": artifacts.claim_script.hex(),
                "refund_script": artifacts.refund_script.hex(),
                "claim_leaf_hash": artifacts.claim_leaf_hash.hex(),
                "refund_leaf_hash": artifacts.refund_leaf_hash.hex(),
                "merkle_root": artifacts.merkle_root.hex(),
                "tap_tweak": artifacts.tap_tweak.hex(),
                "output_xonly_key": artifacts.output_key.hex(),
                "output_key_parity": artifacts.output_parity,
                "script_pubkey": artifacts.script_pubkey.hex(),
                "claim_control_block": artifacts.claim_control_block.hex(),
                "refund_control_block": artifacts.refund_control_block.hex(),
            },
            "user_secret": {
                "kind": "raw-secp256k1-v1",
                "contract_secret_key": contract_secret.hex(),
            },
            "funding_history": [
                {"binding": binding.model_dump(mode="json"), "funder_session_signature": sig}
                for binding, sig in funding
            ],
            "chain_scan_birthday_height": birthday,
            "fee_policy": {
                "max_claim_fee_sat": terms.max_claim_fee_sat,
                "max_refund_fee_sat": terms.max_refund_fee_sat,
            },
            "recovery_authorization_xonly_key": terms.recovery_authorization_xonly_key,
            "monotonic_knowledge": {
                "preimage_known": preimage is not None,
                "preimage": None if preimage is None else preimage.hex(),
                "dangerous_signature_issued": False,
            },
            "extensions": {},
        }
    )


async def _handshake(
    session: _Session, advertisement: dict[str, Any], identity: str
) -> tuple[HandshakeInit, HandshakeAccept, str, str]:
    """Return init, accept, identity signature, and handshake hash."""
    epoch = advertisement["epoch_inbox_xonly_keys"][0]
    epoch_bound = _requires_epoch_binding(advertisement)
    if epoch_bound:
        session.session_id = epoch_bound_session_id(
            session.network, identity, epoch, session.key
        ).hex()
    init = HandshakeInit(
        protocol="rillswap",
        wire_version="1",
        profile_id=session.profile,
        network_identity=session.network,
        session_id=session.session_id,
        client_challenge=secrets.token_hex(32),
        client_session_xonly_key=session.key,
        expected_provider_identity_xonly_key=identity,
        requested_encryption_suites=ENCRYPTION_SUITES,
        requested_capabilities=CAPABILITIES,
        required_features=(EPOCH_SESSION_FEATURE,) if epoch_bound else (),
        extensions={EPOCH_SESSION_EXTENSION: {"epoch_inbox_xonly_key": epoch}}
        if epoch_bound
        else {},
    )
    request = session.envelope("handshake_init", init.model_dump(mode="json"), signed=False)
    session.expect_accept(request, init, identity)
    await session.listen()
    await session.send(request, epoch)
    answer = await session.reply_to(request, "handshake_accept")
    accept = parse_model_json(HandshakeAccept, canonicalize(answer.payload["accept"]))
    signature = str(answer.payload["provider_identity_signature"])
    accept.validate_against(init, supported_features=frozenset({EPOCH_SESSION_FEATURE}))
    session.crypto.schnorr_verify(
        bytes.fromhex(identity), handshake_accept_hash(accept), bytes.fromhex(signature)
    )
    if accept.provider_session_xonly_key != answer.sender_session_key:
        raise SwapError("handshake accept names another provider session key")
    session.provider_key = answer.sender_session_key
    transcript = handshake_hash(init, accept).hex()
    confirm = session.envelope(
        "handshake_confirm",
        {
            "handshake_hash": transcript,
            "session_id": session.session_id,
            "client_session_xonly_key": session.key,
            "provider_session_xonly_key": session.provider_key,
        },
        in_reply_to=answer.message_id,
    )
    await session.send(confirm, session.provider_key)
    return init, accept, signature, transcript


def _check_offer(  # noqa: PLR0913 - every binding checked explicitly
    offer: TermsOfferPayload,
    request: FirmQuoteRequest,
    *,
    envelope: Envelope,
    transcript: str,
    invoice: InvoiceBinding,
    identity: str,
    network: NetworkIdentity,
    crypto: Context,
    now: int,
) -> ContractTerms:
    check_terms_offer(request, offer, handshake_hash=transcript, invoice_binding=invoice)
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


async def run_swap(  # noqa: PLR0913, PLR0915 - one ordered swap story
    connection: RelayConnection,
    *,
    identity: str,
    network: NetworkIdentity,
    invoice: str,
    decode_invoice: Callable[[str], InvoiceBinding],
    wallet: Wallet,
    write_recovery: Callable[[bytes, bytes | None], None],
    limits: SwapLimits,
    crypto: Context,
    timeout: float = 60.0,  # noqa: ASYNC109
    settle_timeout: float = 600.0,
    report: Callable[[str], None] = lambda _line: None,
) -> SwapOutcome:
    """Run one BTC to LN swap; see the module docstring for the order."""
    if not math.isfinite(settle_timeout) or settle_timeout <= 0:
        raise SwapError("settlement timeout must be finite and positive")
    now = int(time.time())
    binding_invoice = decode_invoice(invoice)
    if binding_invoice.bolt11_sha256 != hashlib.sha256(invoice.encode("ascii")).hexdigest():
        raise SwapError("invoice decoder returned another invoice")
    principal = int(binding_invoice.amount_msat) // 1000
    advertisement = await discover(
        connection, identity=identity, network=network, crypto=crypto, now=now
    )
    session = _Session(connection, crypto, network, timeout=timeout)
    init, accept, accept_signature, transcript = await _handshake(session, advertisement, identity)
    report(f"session {session.session_id[:16]} confirmed")
    provider_key = session.provider_key or ""

    contract_secret, contract_public = _scalar(crypto)
    _, recovery_public = _scalar(crypto)  # authorization key; its secret is not needed
    tip = await asyncio.to_thread(wallet.tip_height)
    destination = await asyncio.to_thread(wallet.new_destination_script)
    request_model = FirmQuoteRequest(
        kind="btc-to-ln",
        mode="firm",
        lightning_principal_sat=str(principal),
        invoice=invoice,
        client_contract_compressed_key=contract_public.hex(),
        recovery_authorization_xonly_key=recovery_public[1:].hex(),
        client_destination_script=destination.hex(),
        limits=QuoteLimits(
            max_success_fee_sat=str(limits.max_success_fee_sat),
            max_funding_fee_sat=str(limits.max_funding_fee_sat),
            max_claim_fee_sat=str(limits.max_claim_fee_sat),
            max_refund_fee_sat=str(limits.max_refund_fee_sat),
            max_refund_lock_height=tip + limits.max_refund_delay_blocks,
        ),
        extensions={},
    )
    request = session.envelope("quote_request", request_model.model_dump(mode="json"))
    await session.send(request, provider_key)
    answer = await session.reply_to(request, "terms_offer")
    offer = parse_model_json(TermsOfferPayload, canonicalize(answer.payload))
    terms = _check_offer(
        offer,
        request_model,
        envelope=answer,
        transcript=transcript,
        invoice=binding_invoice,
        identity=identity,
        network=network,
        crypto=crypto,
        now=int(time.time()),
    )
    economics = terms.economics
    report(
        f"terms: fund {economics.contract_amount_sat} sat, refund after block "
        f"{terms.refund_lock_height}"
    )

    acceptance = ClientAcceptance(
        contract_hash=offer.terms.contract_hash,
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
    }
    document = _recovery_document(**record)  # type: ignore[arg-type]
    await asyncio.to_thread(write_recovery, document, None)
    report("recovery file written (terms, no funding yet)")
    accepted = session.envelope(
        "terms_accept",
        {
            "acceptance": acceptance.model_dump(mode="json"),
            "client_acceptance_signature": acceptance_signature,
        },
        in_reply_to=answer.message_id,
        contract=offer.terms.contract_hash,
    )
    await session.send(accepted, provider_key)
    await session.reply_to(accepted, "ack")

    script = reconstruct_taproot_contract(terms, keys=crypto).script_pubkey
    amount = int(economics.contract_amount_sat)
    funded = await asyncio.to_thread(
        lambda: wallet.fund(script, amount, fee_rate_sat_vb=limits.funding_fee_rate_sat_vb)
    )
    plan = FundingPlan(
        approved_inputs=funded.inputs,
        lineage_anchor=funded.inputs[0],
        approved_noncontract_outputs=funded.other_outputs,
    )
    authorized = authorize_funding_transaction(funded.raw_transaction, terms, plan, keys=crypto)
    attempt_id = secrets.token_hex(32)
    binding = FundingBinding(
        contract_hash=offer.terms.contract_hash,
        funding_attempt_id=attempt_id,
        binding_revision=0,
        funder_role="client",
        lineage_anchor_txid=funded.inputs[0].txid.hex(),
        lineage_anchor_vout=funded.inputs[0].output_index,
        funding_txid=authorized.txid,
        contract_vout=authorized.contract_vout,
        contract_value_sat=str(authorized.contract_value_sat),
        contract_script_pubkey=script.hex(),
        replaces_txid=None,
        created_at=int(time.time()),
    )
    binding_signature = bytes(
        crypto.schnorr_sign(session.secret, funding_binding_hash(binding), secrets.token_bytes(32))
    ).hex()
    successor = _recovery_document(
        **record,  # type: ignore[arg-type]
        funding=((binding, binding_signature),),
    )
    await asyncio.to_thread(write_recovery, successor, document)
    report(
        f"funded recovery snapshot written (funding {authorized.txid}, "
        f"attempt {attempt_id} revision 0)"
    )
    bound = session.envelope(
        "funding_binding",
        {
            "binding": binding.model_dump(mode="json"),
            "funding_binding_signature": binding_signature,
            "funding_transaction": funded.raw_transaction.hex(),
        },
        contract=offer.terms.contract_hash,
    )
    await session.send(bound, provider_key)
    await session.reply_to(bound, "ack")
    txid = await asyncio.to_thread(wallet.broadcast, funded.raw_transaction)
    if txid != authorized.txid:
        raise SwapError("Core broadcast another transaction; check the wallet")
    settlement_deadline = asyncio.get_running_loop().time() + settle_timeout
    report(f"funding broadcast {txid}; waiting for the provider to pay")

    refund_hint = (
        "funds are committed; check invoice status; "
        f"refund after block {terms.refund_lock_height} with "
        f"`rill recover watch-refund --funding-attempt-id {attempt_id} --binding-revision 0` "
        "on the funded recovery file"
    )
    preimage = await _wait_for_payment(
        session,
        terms,
        deadline=settlement_deadline,
        refund_hint=refund_hint,
    )
    paid_recovery = _recovery_document(
        **record,  # type: ignore[arg-type]
        funding=((binding, binding_signature),),
        preimage=bytes.fromhex(preimage),
    )
    try:
        await asyncio.to_thread(write_recovery, paid_recovery, successor)
    except Exception:  # noqa: BLE001 - do not misreport known payment as unpaid
        raise SwapError(
            "payment verified but paid recovery snapshot "
            "publication could not be confirmed; "
            "preserve all recovery files and inspect any .paid snapshot; "
            "do not retry payment"
        ) from None
    report("paid recovery snapshot written (verified payment preimage retained)")
    return SwapOutcome(
        session.session_id,
        offer.terms.contract_hash,
        txid,
        preimage,
        terms.refund_lock_height,
    )
