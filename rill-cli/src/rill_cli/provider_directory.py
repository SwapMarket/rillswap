"""Permissionless, read-only provider directory from signed Nostr announcements.

Anyone can publish a kind-39417 announcement; this lists every one that
verifies (NIP-01 and RS-001 application signatures, the complete selected
network, the btc-to-ln profile, and an unexpired window). A listing is
discovery evidence only: it proves neither liquidity, solvency, nor honesty.
Selecting a provider remains an explicit ``--provider`` choice at swap time,
and every swap stays enforceable on-chain regardless of who is chosen.
"""

from __future__ import annotations

import asyncio
import json
import time
from typing import TYPE_CHECKING, Any

from rill_provider.provider_identity import ANNOUNCEMENT_KIND

from rill_cli.live_swap import verify_announcement

if TYPE_CHECKING:
    import argparse

    from rill_core.wire.types import NetworkIdentity
    from rill_crypto import Context
    from rill_provider.relay_client import RelayConnection

# Per relay. A flood ends only that relay's query, so the listing size is
# bounded by relays times this cap. There is no provider cap: truncating by any
# sortable key would let a Sybil grind identities to push others out.
MAX_DIRECTORY_EVENTS = 4096
HEX32_LENGTH = 64


def _pubkey(raw: bytes) -> str | None:
    try:
        event = json.loads(raw)
    except ValueError:
        return None
    key = event.get("pubkey") if isinstance(event, dict) else None
    if type(key) is not str or len(key) != HEX32_LENGTH:
        return None
    return key


async def _query(
    connection: RelayConnection,
    *,
    network: NetworkIdentity,
    crypto: Context,
    now: int,
    timeout: float,  # noqa: ASYNC109
) -> dict[str, list[dict[str, Any]]]:
    """Return verified advertisements per identity seen on one relay."""
    found: dict[str, list[dict[str, Any]]] = {}
    await connection.subscribe([{"kinds": [ANNOUNCEMENT_KIND], "limit": MAX_DIRECTORY_EVENTS}])
    seen = 0
    try:
        async with asyncio.timeout(timeout):
            async for raw in connection.events():
                seen += 1
                if seen > MAX_DIRECTORY_EVENTS:
                    break
                identity = _pubkey(raw)
                if identity is None:
                    continue
                try:
                    advertisement = verify_announcement(
                        raw, identity=identity, network=network, crypto=crypto, now=now
                    )
                except Exception:  # noqa: BLE001, S112 - invalid events are ignored
                    continue
                found.setdefault(identity, []).append(advertisement)
    except TimeoutError:
        pass
    return found


def merge(per_relay: list[dict[str, list[dict[str, Any]]]]) -> list[dict[str, Any]]:
    """Keep each identity's highest revision across relays; drop equivocators.

    Two different signed advertisements at one revision are equivocation by
    that provider. It is excluded (and reported) rather than guessed at, and
    it never prevents other providers from being listed.
    """
    candidates: dict[str, list[dict[str, Any]]] = {}
    relays: dict[str, set[int]] = {}
    for index, found in enumerate(per_relay):
        for identity, advertisements in found.items():
            candidates.setdefault(identity, []).extend(advertisements)
            relays.setdefault(identity, set()).add(index)
    listing: list[dict[str, Any]] = []
    for identity in sorted(candidates):
        advertisements = candidates[identity]
        top = max(ad["revision"] for ad in advertisements)
        latest = [ad for ad in advertisements if ad["revision"] == top]
        conflict = any(ad != latest[0] for ad in latest)
        entry: dict[str, Any] = {
            "provider_identity_xonly_key": identity,
            "relays_seen": len(relays[identity]),
            "status": "equivocating" if conflict else "listed",
        }
        if not conflict:
            ad = latest[0]
            entry["advertisement"] = ad
        listing.append(entry)
    return listing


def add_parser(categories: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    """Register ``providers list``."""
    providers = categories.add_parser("providers", help="permissionless provider directory")
    commands = providers.add_subparsers(dest="command", required=True)
    command = commands.add_parser("list", help="list verified announcements (read-only)")
    command.add_argument("--network", required=True, help="complete trusted network JSON file")
    command.add_argument("--crypto-library", required=True, help="verified native library path")
    command.add_argument(
        "--relay", required=True, action="append", help="Nostr relay URL; repeat for more"
    )
    command.add_argument("--timeout", type=float, default=10.0, help="per-relay query seconds")


def run(args: argparse.Namespace, network: NetworkIdentity) -> str:
    """Query every relay and return the JSON listing; never moves funds."""
    from rill_crypto import Context  # noqa: PLC0415 - native library only when used
    from rill_provider.relay_client import RelayConnection  # noqa: PLC0415

    async def query(url: str, crypto: Context) -> dict[str, list[dict[str, Any]]]:
        async with RelayConnection(url) as connection:
            return await _query(
                connection,
                network=network,
                crypto=crypto,
                now=int(time.time()),
                timeout=args.timeout,
            )

    async def everywhere(crypto: Context) -> list[dict[str, Any]]:
        results = await asyncio.gather(
            *(query(url, crypto) for url in dict.fromkeys(args.relay)), return_exceptions=True
        )
        answered = [result for result in results if isinstance(result, dict)]
        if not answered:
            raise RelayQueryError("no relay answered")
        return merge(answered)

    with Context(library_path=args.crypto_library) as crypto:
        listing = asyncio.run(everywhere(crypto))
    return json.dumps(
        {"format": "rillswap/provider-directory/v1", "providers": listing}, sort_keys=True
    )


class RelayQueryError(RuntimeError):
    """No relay could be queried; an empty listing would be misleading."""
