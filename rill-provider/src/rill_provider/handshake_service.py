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
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Protocol

from rill_provider.live_session_store import (
    LiveSessionStoreError,
    SessionBlockedError,
    SessionExpiredError,
    StaleOwnerError,
)
from rill_provider.provider_identity import AnnouncementTerms
from rill_provider.relay_client import RelayConnection, RelayError

if TYPE_CHECKING:
    from collections.abc import Callable, Sequence

    from rill_core.wire.types import NetworkIdentity
    from rill_crypto import Context

    from rill_provider.live_session_store import LiveSessionStore
    from rill_provider.provider_identity import ProviderIdentity

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
    announced_keys: tuple[str, ...] = ()
    announced_at: int = 0
    announcement: bytes | None = None  # exact bytes, retransmitted unchanged
    announcement_expires: int = 0
    republish: bool = False
    attempts: dict[str, int] = field(default_factory=dict)
    seen: OrderedDict[str, None] = field(default_factory=OrderedDict)


class HandshakeService:
    """Single-owner orchestration; the caller owns the store and relays."""

    def __init__(
        self,
        store: LiveSessionStore,
        identity: ProviderIdentity,
        transport: Context,
        policy: ServicePolicy,
        *,
        clock: Callable[[], float] = time.time,
    ) -> None:
        """Bind already-acquired, already-verified resources."""
        self._store = store
        self._identity = identity
        self._transport = transport
        self._policy = policy
        self._clock = clock
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
        keys = sorted({*epochs, *self._store.awaiting_confirm_mailboxes()})
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
        if epochs != state.announced_keys or now >= state.announced_at + (
            policy.announcement_refresh
        ):
            await self._announce(epochs, now)
        if state.republish and state.announcement and now < state.announcement_expires:
            state.republish = not await self._publish(state.announcement, relays)
            if state.republish:
                LOG.warning("announcement not accepted by any relay; will retry")
        await self._resubscribe(relays)
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
            )
        )
        state.announced_keys, state.announced_at = epochs, now
        state.announcement_expires = now + policy.announcement_lifetime
        state.republish = True

    async def _resubscribe(self, relays: Sequence[Relay]) -> None:
        wanted = tuple(self._filters()[0]["#p"])
        if wanted != self._state.subscribed:
            await asyncio.gather(
                *(self.subscribe(relay) for relay in relays), return_exceptions=True
            )
            self._state.subscribed = wanted

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

    async def handle(self, event: bytes, relays: Sequence[Relay]) -> str:  # noqa: PLR0911 - one disposition per outcome
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
                admitted = store.admit_confirm(document, now=now)
                await self._resubscribe(relays)
                return "confirm-replay" if admitted.replay else "confirm-admitted"
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

    async def run(self, stop: asyncio.Event, *, tick_seconds: float = 15.0) -> None:
        """Serve until ``stop`` is set, reconnecting relays with backoff."""
        connected: dict[str, RelayConnection] = {}
        inbound: asyncio.Queue[bytes] = asyncio.Queue(1024)

        async def maintain(url: str) -> None:
            delay = 1.0
            while not stop.is_set():
                try:
                    async with RelayConnection(url) as connection:
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
