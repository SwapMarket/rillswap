"""``rill swap btc-to-ln``: one live swap through a provider."""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path
from typing import TYPE_CHECKING

from rill_core.recovery import inspect_recovery_successor
from rill_crypto import Context
from rill_provider.lnd_invoice_decode import LndInvoiceDecoder
from rill_provider.relay_client import RelayConnection

from rill_cli.age_container import (
    X25519Credentials,
    encrypt_verified_plaintext,
    verify_export_ciphertext,
)
from rill_cli.live_swap import SwapLimits, run_swap
from rill_cli.publication import publish_new_ciphertext
from rill_cli.wallet_rpc import WalletRpc

if TYPE_CHECKING:
    import argparse

    from rill_core.recovery import OfflineRecoveryInspection
    from rill_core.wire.types import NetworkIdentity


def add_parser(categories: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    """Register ``swap btc-to-ln``."""
    swap = categories.add_parser("swap", help="live swaps (moves real funds)")
    kinds = swap.add_subparsers(dest="command", required=True)
    command = kinds.add_parser("btc-to-ln", help="pay a Lightning invoice with on-chain BTC")
    command.add_argument("--network", required=True, help="complete trusted network JSON file")
    command.add_argument("--crypto-library", required=True, help="verified native library path")
    command.add_argument("--relay", required=True, help="Nostr relay URL (ws:// or wss://)")
    command.add_argument("--provider", required=True, help="provider identity x-only key (hex)")
    command.add_argument("--invoice", required=True, help="BOLT11 invoice to be paid")
    command.add_argument("--max-success-fee-sat", required=True, type=int)
    command.add_argument("--max-funding-fee-sat", type=int, default=5_000)
    command.add_argument("--max-claim-fee-sat", type=int, default=5_000)
    command.add_argument("--max-refund-fee-sat", type=int, default=5_000)
    command.add_argument("--max-refund-delay-blocks", type=int, default=288)
    command.add_argument("--fee-rate", type=int, default=2, help="funding sat/vB")
    command.add_argument("--core-port", required=True, type=int, help="loopback Core RPC port")
    command.add_argument("--core-cookie", required=True, help="Core .cookie file")
    command.add_argument("--wallet", required=True, help="Core wallet that funds the swap")
    command.add_argument("--lnd-port", required=True, type=int, help="loopback LND gRPC port")
    command.add_argument("--lnd-tls-cert", required=True, help="LND tls.cert")
    command.add_argument("--lnd-macaroon", required=True, help="invoice-decoding macaroon")
    command.add_argument("--recipient", required=True, help="X25519 age recipient")
    command.add_argument("--identity", required=True, help="matching private age identity file")
    command.add_argument(
        "--recovery-output",
        required=True,
        help="create-only recovery file; the funded snapshot adds '.funded'",
    )
    command.add_argument("--timeout", type=float, default=60.0, help="per-answer seconds")
    command.add_argument("--settle-timeout", type=float, default=3600.0)


def _report(line: str) -> None:
    sys.stderr.write(line + "\n")


def _funded_path(path: Path) -> Path:
    return path.with_name(path.name + ".funded")


def run(args: argparse.Namespace, network: NetworkIdentity, identity: str) -> str:
    """Run the swap; return the final report line."""
    output = Path(args.recovery_output)
    credentials = X25519Credentials(args.recipient, identity)
    with Context(library_path=args.crypto_library) as crypto:

        def write_recovery(document: bytes, previous: bytes | None) -> None:
            ciphertext = encrypt_verified_plaintext(
                document, network, credentials=credentials, crypto=crypto
            )

            def readback(stored: bytes) -> OfflineRecoveryInspection:
                report = verify_export_ciphertext(
                    stored, document, network, credentials=credentials, crypto=crypto
                )
                if previous is None:
                    return report
                return inspect_recovery_successor(previous, document, network, crypto=crypto)

            target = output if previous is None else _funded_path(output)
            publish_new_ciphertext(str(target), ciphertext, verify_from_disk=readback)

        decoder = LndInvoiceDecoder(
            host="127.0.0.1",
            port=args.lnd_port,
            tls_certificate_path=args.lnd_tls_cert,
            macaroon_path=args.lnd_macaroon,
            network=network,
        )
        wallet = WalletRpc(
            port=args.core_port, cookie_path=args.core_cookie, wallet=args.wallet, network=network
        )
        limits = SwapLimits(
            max_success_fee_sat=args.max_success_fee_sat,
            max_funding_fee_sat=args.max_funding_fee_sat,
            max_claim_fee_sat=args.max_claim_fee_sat,
            max_refund_fee_sat=args.max_refund_fee_sat,
            max_refund_delay_blocks=args.max_refund_delay_blocks,
            funding_fee_rate_sat_vb=args.fee_rate,
        )

        async def swap() -> str:
            async with RelayConnection(args.relay) as connection:
                outcome = await run_swap(
                    connection,
                    identity=args.provider,
                    network=network,
                    invoice=args.invoice,
                    decode_invoice=decoder.decode,
                    wallet=wallet,
                    write_recovery=write_recovery,
                    limits=limits,
                    crypto=crypto,
                    timeout=args.timeout,
                    settle_timeout=args.settle_timeout,
                    report=_report,
                )
            return (
                f"Paid. preimage {outcome.payment_preimage} "
                f"(funding {outcome.funding_txid}, contract {outcome.contract_hash})"
            )

        return asyncio.run(swap())
