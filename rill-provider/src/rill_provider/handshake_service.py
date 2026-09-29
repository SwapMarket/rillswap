"""Provider handshake service: relays <-> authoritative live session store.

Order of effects is fixed by the store: an accept is committed before any
wrap of it exists, and confirms are admitted only through the store. This
module adds scheduling, routing, and retries, never authority. A confirmed
session grants no quote, funding, or payment action (none is wired).
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from collections import OrderedDict
from dataclasses import dataclass, field, replace
from typing import TYPE_CHECKING, Any, Protocol

from rill_core.wire.canonical import canonicalize
from rill_core.wire.messages import InvoiceBinding
from rill_core.wire.quotes import parse_quote_request
from rill_core.wire.reverse_quotes import ReverseFirmQuoteRequest

from rill_provider.live_session_store import (
    FIRST_REQUEST_SEQUENCE,
    Answer,
    LiveSessionStoreError,
    SessionBlockedError,
    SessionExpiredError,
    StaleOwnerError,
)
from rill_provider.lnd_invoice_decode import InvoiceRejectedError
from rill_provider.lnd_payment_observation import LndObservationError
from rill_provider.provider_identity import AnnouncementTerms
from rill_provider.quote_policy import (
    FirmSigner,
    HoldOutcome,
    InvoiceOutcome,
    QuoteSchedule,
    QuoteTerms,
    hold_invoice_msat,
    success_fee,
)
from rill_provider.relay_client import RelayConnection, RelayError
from rill_provider.settlement_policy import answer_client_request

if TYPE_CHECKING:
    from collections.abc import Callable, Sequence

    from rill_core.wire.messages import Envelope
    from rill_core.wire.types import NetworkIdentity, ProfileId
    from rill_crypto import Context

    from rill_provider.live_session_store import LiveSessionStore, RequestContext
    from rill_provider.lnd_hold_invoice import LndHoldInvoices
    from rill_provider.provider_identity import ProviderIdentity
    from rill_provider.settlement_engine import SettlementEngine

LOG = logging.getLogger(__name__)
NIP59_BACKDATE_SECONDS = 2 * 24 * 60 * 60
MAX_SEEN_EVENTS = 4096
_RELAY_CONNECTED = b""  # in-band wake: tick now and re-announce


class Relay(Protocol):
    """What the service needs from one relay connection."""

    url: str

    async def publish(self, event: bytes) -> bool:
        """Return True only on an explicit relay OK."""
        ...

    async def subscribe(self, filters: list[dict[str, Any]]) -> None:
        """Replace this connection's subscription."""
        ...


@dataclass(frozen=True, slots=True)
class ServicePolicy:
    """Operator-chosen public terms and schedules."""

    network: NetworkIdentity
    profiles: tuple[str, ...]
    amount_bands: tuple[tuple[int, int], ...]
    base_fee_sat: int
    proportional_millionths: int
    slot: str
    relay_urls: tuple[str, ...]
    epoch_period: int = 24 * 60 * 60
    announcement_lifetime: int = 60 * 60
    announcement_refresh: int = 30 * 60
    outbox_retry: int = 60
    handshake_timeout: int = 10 * 60
    max_sends_per_tick: int = 16
    quote: QuoteSchedule = field(default_factory=QuoteSchedule)
    provider_destination_script: str | None = None  # required for firm offers
    profile: ProfileId = "btc-to-ln/v1"  # the one negotiated profile this service serves
    relay_proxy: str | None = None  # checked loopback CONNECT proxy, or direct

    def __post_init__(self) -> None:
        """Refuse schedules that would leave advertised epochs undecodable."""
        if not (
            self.relay_urls
            and 0 < self.announcement_refresh < self.announcement_lifetime
            and self.epoch_period > 0
            and self.outbox_retry > 0
            and self.handshake_timeout > 0
            and self.max_sends_per_tick > 0
        ):
            raise ValueError("service schedule unsupported")


@dataclass(slots=True)
class _State:
    subscribed: tuple[str, ...] = ()
    retry_subscription: bool = False
    relay_drops: dict[int, tuple[Relay, int]] = field(default_factory=dict)
    announced_keys: tuple[str, ...] = ()
    announced_at: int = 0
    announcement: bytes | None = None  # exact bytes, retransmitted unchanged
    announcement_expires: int = 0
    republish: bool = False
    attempts: dict[str, int] = field(default_factory=dict)
    seen: OrderedDict[str, None] = field(default_factory=OrderedDict)
    tip: int | None = None  # per-tick snapshot; requests never trigger RPC


class HandshakeService:
    """Single-owner orchestration; the caller owns the store and relays."""

    def __init__(  # noqa: PLR0913 - explicit injected resources
        self,
        store: LiveSessionStore,
        identity: ProviderIdentity,
        transport: Context,
        policy: ServicePolicy,
        *,
        clock: Callable[[], float] = time.time,
        chain_tip: Callable[[], int] | None = None,
        invoice_decoder: Callable[[str], InvoiceBinding] | None = None,
        settlement: SettlementEngine | None = None,
        hold_invoices: LndHoldInvoices | None = None,
    ) -> None:
        """Bind already-acquired, already-verified resources.

        ``chain_tip`` (blocking; run off the event loop once per tick, never
        per request) supplies an indicative quote's reference height. Without
        it, or when it fails, quotes are answered ``capacity_unavailable``.
        ``invoice_decoder`` (blocking, e.g. LND ``DecodePayReq``) plus a
        ``provider_destination_script`` enable firm offers. ``settlement``
        moves funded swaps to payment and claim once per tick.
        """
        self._store = store
        self._identity = identity
        self._transport = transport
        self._policy = policy
        self._clock = clock
        self._chain_tip = chain_tip
        self._invoice_decoder = invoice_decoder
        self._settlement = settlement
        self._hold_invoices = hold_invoices
        self._state = _State()

    def _now(self) -> int:
        return int(self._clock())

    async def _publish(self, event: bytes, relays: Sequence[Relay]) -> bool:
        results = await asyncio.gather(
            *(relay.publish(event) for relay in relays), return_exceptions=True
        )
        return any(result is True for result in results)

    def _filters(self) -> list[dict[str, Any]]:
        # Every still-decodable epoch, not only advertised ones: clients may
        # hold an older, still-valid announcement.
        epochs = self._store.receiving_epochs(now=self._now())
        keys = sorted({*epochs, *self._store.session_mailboxes()})
        return [
            {
                "kinds": [1059],
                "#p": keys,
                "since": self._now() - NIP59_BACKDATE_SECONDS - self._policy.outbox_retry,
            }
        ]

    async def subscribe(self, relay: Relay) -> None:
        """Install the current filter on one (re)connected relay."""
        await relay.subscribe(self._filters())

    async def tick(self, relays: Sequence[Relay]) -> None:
        """Rotate epochs, refresh the announcement, resubscribe, retry the outbox."""
        policy, state, now = self._policy, self._state, self._now()
        epochs = self._store.rotate_epochs(
            now=now,
            period=policy.epoch_period,
            retention=2 * policy.announcement_lifetime,
            advertise_for=2 * policy.announcement_lifetime - 1,
        )
        self._store.expire_idle(now=now, idle_timeout=policy.handshake_timeout)
        await self._refresh_tip()
        if epochs != state.announced_keys or now >= state.announced_at + (
            policy.announcement_refresh
        ):
            await self._announce(epochs, now)
        if state.republish and state.announcement and now < state.announcement_expires:
            state.republish = not await self._publish(state.announcement, relays)
            if state.republish:
                LOG.warning("announcement not accepted by any relay; will retry")
        await self._resubscribe(relays)
        if self._settlement is not None:
            for session_id, moved in (await self._settlement.tick(now)).items():
                LOG.info("swap %s moved to %s", session_id[:16], moved)
        due = sorted(  # least recently attempted first (never attempted = 0)
            (
                entry.message_id
                for entry in self._store.pending_outbox()
                if now >= state.attempts.get(entry.message_id, 0) + policy.outbox_retry
            ),
            key=lambda message_id: state.attempts.get(message_id, 0),
        )[: policy.max_sends_per_tick]  # bounded work per tick; the rest wait
        results = await asyncio.gather(
            *(self._send_pending(message_id, relays) for message_id in due),
            return_exceptions=True,
        )
        for result in results:
            if isinstance(result, StaleOwnerError):
                raise result
        for message_id in list(state.attempts):
            if message_id not in {entry.message_id for entry in self._store.pending_outbox()}:
                del state.attempts[message_id]

    async def _refresh_tip(self) -> None:
        if self._chain_tip is None:
            return
        try:
            self._state.tip = await asyncio.to_thread(self._chain_tip)
        except Exception:  # noqa: BLE001 - an unavailable tip only disables quotes
            self._state.tip = None
            LOG.warning("chain tip unavailable; quotes answered capacity_unavailable")

    async def _announce(self, epochs: tuple[str, ...], now: int) -> None:
        policy, state = self._policy, self._state
        try:
            self._store.record_announcement(now)  # durable ordering before publication
        except StaleOwnerError:
            raise
        except LiveSessionStoreError:
            LOG.warning("announcement skipped: revision would not increase")
            return
        state.announcement = self._identity.build_announcement(
            AnnouncementTerms(
                network=policy.network,
                profiles=policy.profiles,
                amount_bands=policy.amount_bands,
                base_fee_sat=policy.base_fee_sat,
                proportional_millionths=policy.proportional_millionths,
                transport_endpoints=policy.relay_urls,
                epoch_inbox_xonly_keys=epochs,
                slot=policy.slot,
                created_at=now,
                expires_at=now + policy.announcement_lifetime,
                epoch_bound_sessions=self._store.requires_epoch_bound_sessions,
            )
        )
        state.announced_keys, state.announced_at = epochs, now
        state.announcement_expires = now + policy.announcement_lifetime
        state.republish = True

    async def _resubscribe(self, relays: Sequence[Relay]) -> None:
        wanted = tuple(self._filters()[0]["#p"])
        # A full per-relay ingress queue drops a wrapper without closing its
        # socket. Re-REQ the same filter to replay relay history; inbox/outbox
        # admission is idempotent. Snapshot counters before REQ so another drop
        # during publication triggers another bounded retry on the next tick.
        observed: dict[int, tuple[Relay, int]] = {}
        for relay in relays:
            count = getattr(relay, "dropped_events", 0)
            observed[id(relay)] = (relay, count if type(count) is int and count >= 0 else 0)
        lost = []
        for relay in relays:
            previous = self._state.relay_drops.get(id(relay))
            seen = previous[1] if previous is not None and previous[0] is relay else 0
            if observed[id(relay)][1] > seen:
                lost.append(relay)
        if lost:
            LOG.warning("relay inbound queue overflow; replay subscription requested")
        refresh_all = wanted != self._state.subscribed or self._state.retry_subscription
        if refresh_all or lost:
            targets = relays if refresh_all else lost
            results = await asyncio.gather(
                *(self.subscribe(relay) for relay in targets), return_exceptions=True
            )
            if any(isinstance(result, BaseException) for result in results):
                self._state.retry_subscription = True  # retry even if the filter is empty
                return
            self._state.subscribed = wanted
            self._state.retry_subscription = False
        self._state.relay_drops = observed  # prune disconnected connection IDs

    async def _send_pending(self, message_id: str, relays: Sequence[Relay]) -> None:
        self._state.attempts[message_id] = self._now()
        wrap = self._store.wrap_pending(message_id, transport=self._transport)
        if not await self._publish(wrap, relays):
            LOG.warning("outbox wrap not accepted by any relay; will retry")

    def _first_sight(self, event: bytes) -> bool:
        try:
            event_id = json.loads(event)["id"]
        except (ValueError, KeyError, TypeError):
            return False
        seen = self._state.seen
        if type(event_id) is not str or event_id in seen:
            return False
        seen[event_id] = None
        if len(seen) > MAX_SEEN_EVENTS:
            seen.popitem(last=False)
        return True

    async def handle(self, event: bytes, relays: Sequence[Relay]) -> str:  # noqa: PLR0911, PLR0912 - one disposition per outcome
        """Route one untrusted relay event; return a content-free disposition."""
        if not self._first_sight(event):
            return "duplicate"
        store = self._store
        try:
            try:
                document = store.open_mailbox_frame(event, transport=self._transport)
            except StaleOwnerError:
                raise
            except LiveSessionStoreError:
                document = None
            now = self._now()
            if document is not None:
                message_type = json.loads(document).get("message_type")
                if message_type == "handshake_confirm":
                    try:
                        admitted = store.admit_confirm(document, now=now)
                    except (StaleOwnerError, SessionBlockedError, SessionExpiredError):
                        raise
                    except LiveSessionStoreError:
                        # Not a valid confirm: classify it like any signed message,
                        # so reusing an admitted sequence is still a conflict.
                        return await self._answer(document, relays, now)
                    await self._resubscribe(relays)
                    return "confirm-replay" if admitted.replay else "confirm-admitted"
                if message_type == "action_result":
                    result = store._admit_cooperative_result(document, now=now)  # noqa: SLF001 - store-owned admission; no signer or reply
                    return "result-replay" if result.replay else "result-admitted"
                return await self._answer(document, relays, now)
            init = store.open_epoch_frame(event, now=now, transport=self._transport)
            reserved = store.reserve(init, now=now)
            if reserved.revision != 0:
                return "init-replay"  # outbox retries own any re-send
            committed = store.create_accept(
                reserved.session_id,
                identity=self._identity,
                transport_endpoints=self._policy.relay_urls,
            )
            await self._send_pending(committed.message_id, relays)
            await self._resubscribe(relays)
        except StaleOwnerError:
            raise  # ownership lost: never keep acting on this store
        except SessionBlockedError:
            return "blocked"
        except SessionExpiredError:
            return "expired"
        except LiveSessionStoreError:
            return "refused"
        return "init-accepted"

    def _firm_signer(self) -> FirmSigner | None:
        script = self._policy.provider_destination_script
        if self._invoice_decoder is None or script is None:
            return None
        return FirmSigner(
            network=self._policy.network,
            provider_identity_key=self._identity.xonly_public_key,
            provider_destination_script=script,
            sign=self._identity.sign_provider_terms,
        )

    async def _decode_invoice(self, document: bytes) -> InvoiceOutcome:
        """Decode a firm request's invoice, only for a new first request."""
        envelope = json.loads(document)
        payload = envelope.get("payload")
        if (
            self._invoice_decoder is None
            or envelope.get("sequence") != FIRST_REQUEST_SEQUENCE
            or not isinstance(payload, dict)
            or payload.get("mode") != "firm"
            or not isinstance(payload.get("invoice"), str)
            or self._store.classify_request(document) != "new"
        ):
            return None
        try:
            return await asyncio.to_thread(self._invoice_decoder, payload["invoice"])
        except InvoiceRejectedError:
            return "rejected"
        except Exception:  # noqa: BLE001 - an unavailable backend only defers firm quotes
            LOG.warning("invoice decoding unavailable; firm quote answered capacity_unavailable")
            return "unavailable"

    async def _open_hold(self, document: bytes, terms: QuoteTerms) -> HoldOutcome:
        """Open the hold invoice for a new LN to BTC firm request (RS-004).

        Runs before the store transaction, like invoice decoding. The invoice
        is for exactly ``H`` at this payout with the schedule's final CLTV, so
        the offer can bind its decoding; ``_answer`` cancels it again when the
        answer is not a terms offer. An unavailable backend only defers.
        """
        envelope = json.loads(document)
        payload = envelope.get("payload")
        if (
            self._hold_invoices is None
            or self._invoice_decoder is None
            or terms.firm is None
            or terms.profile != "ln-to-btc/v1"
            or envelope.get("sequence") != FIRST_REQUEST_SEQUENCE
            or not isinstance(payload, dict)
            or payload.get("mode") != "firm"
            or self._store.classify_request(document) != "new"
        ):
            return None
        try:
            request = parse_quote_request(canonicalize(payload))
        except ValueError:
            return None  # the quote rules answer request_unacceptable
        if not isinstance(request, ReverseFirmQuoteRequest):
            return None
        payout = int(request.nominal_payout_sat)
        if (
            not any(low <= payout <= high for low, high in terms.amount_bands)
            or self._store.payment_hash_reserved(request.payment_hash)
            or not self._store.firm_capacity_available()
        ):
            return None  # refused without opening anything
        hold_invoices, decoder, schedule = (
            self._hold_invoices,
            self._invoice_decoder,
            terms.schedule,
        )
        try:
            bolt11 = await asyncio.to_thread(
                lambda: hold_invoices.add(
                    request.payment_hash,
                    value_msat=hold_invoice_msat(terms, payout),
                    expiry_seconds=schedule.hold_invoice_lifetime,
                    cltv_expiry_delta=schedule.incoming_htlc_expiry_delta_blocks,
                )
            )
            binding = await asyncio.to_thread(decoder, bolt11)
        except Exception as error:  # noqa: BLE001 - an unavailable backend only defers
            LOG.warning(
                "hold invoice unavailable (%s); firm quote answered capacity_unavailable",
                type(error).__name__,
            )
            return "unavailable"
        return (bolt11, binding)

    async def _cancel_hold(self, hold: HoldOutcome) -> None:
        if not isinstance(hold, tuple) or self._hold_invoices is None:
            return
        hold_invoices, payment_hash = self._hold_invoices, hold[1].payment_hash
        try:
            await asyncio.to_thread(lambda: hold_invoices.cancel(payment_hash))
        except Exception as error:  # noqa: BLE001 - the invoice expires on its own
            LOG.warning("unused hold invoice not canceled (%s)", type(error).__name__)

    async def _route_ready(  # noqa: PLR0911 - one closed rule per branch
        self, document: bytes, terms: QuoteTerms
    ) -> QuoteTerms:
        """Offer firm terms only when settlement could pay this invoice now."""
        binding, tip, settlement = terms.invoice, terms.tip_height, self._settlement
        if (
            terms.firm is None
            or not isinstance(binding, InvoiceBinding)
            or settlement is None
            or tip is None
        ):
            return terms
        principal = int(binding.amount_msat) // 1000
        if not any(low <= principal <= high for low, high in terms.amount_bands):
            return terms  # the quote rules refuse this without asking for a route
        if not self._store.firm_capacity_available():
            return terms  # already full: the quote rules refuse without a route query
        try:
            await asyncio.to_thread(
                lambda: settlement.route_ready(
                    json.loads(document)["payload"]["invoice"],
                    invoice_binding=binding,
                    success_fee_sat=success_fee(terms, principal),
                    max_expiry_height=tip + terms.schedule.outgoing_cltv_budget_blocks,
                )
            )
        except InvoiceRejectedError:
            return replace(terms, invoice="rejected")
        except LndObservationError as error:  # fixed, non-secret adapter messages
            LOG.warning(
                "no payable route now (%s); firm quote answered capacity_unavailable", error
            )
            return replace(terms, invoice="unavailable")
        except Exception as error:  # noqa: BLE001 - any readiness failure only defers
            LOG.warning(
                "route readiness failed (%s); firm quote answered capacity_unavailable",
                type(error).__name__,
            )
            return replace(terms, invoice="unavailable")
        return terms

    async def _answer(self, document: bytes, relays: Sequence[Relay], now: int) -> str:
        policy = self._policy
        invoice = await self._decode_invoice(document)
        terms = QuoteTerms(
            amount_bands=policy.amount_bands,
            base_fee_sat=policy.base_fee_sat,
            proportional_millionths=policy.proportional_millionths,
            schedule=policy.quote,
            tip_height=self._state.tip,
            now=now,
            firm=self._firm_signer(),
            invoice=invoice,
            profile=policy.profile,
        )
        terms = await self._route_ready(document, terms)
        terms = replace(terms, hold=await self._open_hold(document, terms))
        sent: list[str] = []

        def responder(
            request: Envelope, prior: tuple[Envelope, ...], context: RequestContext
        ) -> Answer:
            answer = answer_client_request(request, prior, context, terms, self._transport)
            sent.append(answer.message_type)
            return answer

        try:
            answer = self._store.answer_request(
                document, responder=responder, signer=self._transport, now=now
            )
        except BaseException:
            await self._cancel_hold(terms.hold)
            raise
        if sent != ["terms_offer"]:  # refused, or a replay: this invoice binds nothing
            await self._cancel_hold(terms.hold)
        # A replay re-sends the recorded answer (RS-001 stable replay).
        await self._send_pending(answer.response_message_id, relays)
        return "request-replay" if answer.replay else "request-answered"

    async def run(self, stop: asyncio.Event, *, tick_seconds: float = 15.0) -> None:
        """Serve until ``stop`` is set, reconnecting relays with backoff."""
        connected: dict[str, RelayConnection] = {}
        inbound: asyncio.Queue[bytes] = asyncio.Queue(1024)

        async def maintain(url: str) -> None:
            delay = 1.0
            while not stop.is_set():
                try:
                    async with RelayConnection(url, proxy=self._policy.relay_proxy) as connection:
                        connected[url] = connection
                        delay = 1.0
                        await self.subscribe(connection)
                        await inbound.put(_RELAY_CONNECTED)
                        async for event in connection.events():
                            await inbound.put(event)
                except RelayError:
                    LOG.warning("relay unavailable: %s", url)
                except Exception:  # noqa: BLE001 - a hostile relay must not end reconnection
                    LOG.warning("relay connection failed: %s", url)
                finally:
                    connected.pop(url, None)
                await asyncio.sleep(delay)
                delay = min(delay * 2, 60.0)

        tasks = [asyncio.create_task(maintain(url)) for url in self._policy.relay_urls]
        try:
            while not stop.is_set():
                try:
                    await self.tick(list(connected.values()))
                except StaleOwnerError:
                    raise  # ownership lost: stop, never act on a fenced store
                except LiveSessionStoreError as error:
                    LOG.warning("tick refused: %s", error)  # e.g. clock behind; keep serving
                deadline = time.monotonic() + tick_seconds
                while not stop.is_set() and (remaining := deadline - time.monotonic()) > 0:
                    event = await _next_or_stop(inbound, stop, remaining)
                    if event is None:
                        break
                    if event == _RELAY_CONNECTED:
                        self._state.republish = True  # a new relay lacks our announcement
                        break
                    disposition = await self.handle(event, list(connected.values()))
                    LOG.info("relay event: %s", disposition)
        finally:
            for task in tasks:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)


async def _next_or_stop(
    queue: asyncio.Queue[bytes], stop: asyncio.Event, wait_seconds: float
) -> bytes | None:
    """Return the next item, or None on stop/timeout; never leak waiter tasks."""
    getter = asyncio.ensure_future(queue.get())
    stopper = asyncio.ensure_future(stop.wait())
    try:
        await asyncio.wait(
            {getter, stopper}, timeout=wait_seconds, return_when=asyncio.FIRST_COMPLETED
        )
    finally:
        for waiter in (getter, stopper):
            if not waiter.done():
                waiter.cancel()
        await asyncio.gather(getter, stopper, return_exceptions=True)
    if getter.cancelled() or getter.exception() is not None:
        return None
    return getter.result()
