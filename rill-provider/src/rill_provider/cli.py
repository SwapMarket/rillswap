"""``rill-provider`` operator entrypoint: provision identity/store, then serve.

Provisioning is explicit and never overwrites. ``serve`` takes lifetime
ownership of the store and runs the handshake service until SIGINT/SIGTERM.
Errors are printed as one redacted line; exit status 2 means refused.
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import signal
import sys
from pathlib import Path
from typing import TYPE_CHECKING

from rill_provider.core_tx_bytes import RegtestCoreTransactionReader
from rill_provider.handshake_service import HandshakeService
from rill_provider.live_session_store import LiveSessionStore, LiveSessionStoreError
from rill_provider.lnd_invoice_decode import RegtestLndInvoiceDecoder
from rill_provider.lnd_payment_send import RegtestLndPaymentSender
from rill_provider.operator_config import (
    OperatorConfig,
    OperatorConfigError,
    load_config,
    read_custody_identity,
)
from rill_provider.provider_identity import ProviderIdentity, ProviderIdentityError
from rill_provider.settlement_engine import SettlementEngine

if TYPE_CHECKING:
    from collections.abc import Callable, Sequence

    from rill_core.wire.messages import InvoiceBinding
    from rill_crypto import Context

REFUSED = 2


def _context(library: Path) -> Context:
    from rill_crypto import Context  # noqa: PLC0415 - native library loads only when needed

    return Context(library_path=str(library))


def _provision_identity(args: argparse.Namespace) -> int:
    with _context(args.native_crypto_library) as crypto:
        xonly = ProviderIdentity.provision(args.out, recipient=args.recipient, crypto=crypto)
    print(xonly)  # noqa: T201 - the public key is the command's output
    return 0


def _provision_store(config: OperatorConfig) -> int:
    LiveSessionStore.provision(
        config.store_path,
        config.network,
        config.provider_identity_xonly,
        config.handshake_policy(),
        config.authority_declaration(),
        custody_recipient=config.custody_recipient,
    )
    return 0


def _chain_tip(config: OperatorConfig) -> Callable[[], int] | None:
    core = config.bitcoin_core
    if core is None:
        return None
    try:
        reader = RegtestCoreTransactionReader(
            port=core.port, cookie_path=core.cookie_file, network=config.network
        )
    except ValueError:
        raise OperatorConfigError("bitcoin_core requires a regtest network") from None
    return reader.tip_height


def _settlement(
    config: OperatorConfig, store: LiveSessionStore, crypto: Context
) -> SettlementEngine | None:
    lnd, core = config.lnd, config.bitcoin_core
    if lnd is None or core is None or lnd.payment_macaroon is None:
        return None
    try:
        chain = RegtestCoreTransactionReader(
            port=core.port, cookie_path=core.cookie_file, network=config.network
        )
        lightning = RegtestLndPaymentSender(
            host="127.0.0.1",
            port=lnd.port,
            tls_certificate_path=lnd.tls_certificate,
            macaroon_path=lnd.payment_macaroon,
            network=config.network,
        )
    except ValueError:
        raise OperatorConfigError("settlement requires a regtest network") from None
    return SettlementEngine(store, chain, lightning, crypto)


def _invoice_decoder(config: OperatorConfig) -> Callable[[str], InvoiceBinding] | None:
    lnd = config.lnd
    if lnd is None:
        return None
    try:
        decoder = RegtestLndInvoiceDecoder(
            host="127.0.0.1",
            port=lnd.port,
            tls_certificate_path=lnd.tls_certificate,
            macaroon_path=lnd.macaroon,
            network=config.network,
        )
    except ValueError:
        raise OperatorConfigError("lnd requires a regtest network") from None
    return decoder.decode


async def _serve(config: OperatorConfig, crypto: Context, custody: str) -> None:
    identity = ProviderIdentity.load(
        config.identity_file,
        custody_identity=custody,
        expected_xonly_public_key=config.provider_identity_xonly,
        crypto=crypto,
    )
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for signum in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(signum, stop.set)
    with LiveSessionStore.acquire(
        config.store_path,
        config.network,
        config.provider_identity_xonly,
        config.handshake_policy(),
        crypto=crypto,
        custody_identity=custody,
        public_keys=crypto,
        max_sessions=config.max_sessions,
        max_tombstones=config.max_tombstones,
        new_sessions_per_minute=config.new_sessions_per_minute,
    ) as store:
        service = HandshakeService(
            store,
            identity,
            crypto,
            config.service_policy(),
            chain_tip=_chain_tip(config),
            invoice_decoder=_invoice_decoder(config),
            settlement=_settlement(config, store, crypto),
        )
        await service.run(stop)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="rill-provider", description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    identity = commands.add_parser("provision-identity", help="create a new identity file")
    identity.add_argument("--out", type=Path, required=True)
    identity.add_argument("--recipient", required=True, help="age X25519 recipient")
    identity.add_argument("--native-crypto-library", type=Path, required=True)
    for name, text in (
        ("provision-store", "create a new empty live session store"),
        ("serve", "run the handshake service until SIGINT/SIGTERM"),
    ):
        command = commands.add_parser(name, help=text)
        command.add_argument("--config", type=Path, required=True)
    parser.add_argument("--log-level", default="INFO", choices=("DEBUG", "INFO", "WARNING"))
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Run one operator command; return the process exit status."""
    args = _parser().parse_args(argv)
    logging.basicConfig(level=args.log_level, format="%(levelname)s %(name)s: %(message)s")
    try:
        if args.command == "provision-identity":
            return _provision_identity(args)
        config = load_config(args.config)
        if args.command == "provision-store":
            return _provision_store(config)
        custody = read_custody_identity(config.custody_identity_file)
        with _context(config.native_crypto_library) as crypto:
            asyncio.run(_serve(config, crypto, custody))
    except (OperatorConfigError, LiveSessionStoreError, ProviderIdentityError) as error:
        print(f"rill-provider: {error}", file=sys.stderr)  # noqa: T201
        return REFUSED
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
