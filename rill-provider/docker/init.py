#!/usr/bin/env python3
"""Create provider files for the Docker Compose deployment.

``core-credential`` writes the provider's ``__cookie__`` Core credential and
prints the matching ``bitcoin.conf`` lines. ``maker`` creates one profile's
custody key, encrypted identity, optional EVM signer and ``provider.json``,
plus its empty store directory. Nothing is ever overwritten: existing files
or directories refuse the command, so an interrupted attempt needs operator
review instead of silent replacement.
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import re
import secrets
import subprocess
import sys
from pathlib import Path
from typing import Any

ROOT = Path("/rill")
NATIVE_LIBRARY = "/opt/rill/native/librill_crypto.so"
PROVIDER = "/opt/venv/bin/rill-provider"
NETWORKS = Path("/opt/rill/networks")
# Loopback ports inside each maker container; compose.yaml forwards them.
CORE_PORT = 8332
LND_PORT = 10009
RELAY_PROXY = "http://127.0.0.1:9080"
SIGNET_FEE_ESTIMATE_CEILING_SAT_VB = 2
CREDENTIALS = "/rill/credentials"
# The relays the web app queries by default (rill-web/src/swap/publicRelays.ts):
# all serve gift wraps without AUTH, keep announcements and accept Tor exits.
# The onion relays are reached through the relay proxy (Tor).
DEFAULT_RELAYS = (
    "wss://relay.primal.net",
    "wss://relay.snort.social",
    "wss://nostr.oxtr.dev",
    "wss://relay.ditto.pub",
    "wss://nostr.bitcoiner.social",
    "wss://nostr.azzamo.net",
    "wss://relay.angor.io",
    "wss://nostr.stakey.net",
    "ws://oxtrdevav64z64yb7x6rjg4ntzqjhedm5b5zjqulugknhzr46ny2qbad.onion",
    "ws://gnostr2jnapk72mnagq3cuykfon73temzp77hcbncn4silgt77boruid.onion",
)
PROFILES = ("btc-to-ln", "ln-to-btc", "erc20-to-ln", "ln-to-erc20")
BITCOIN_PROFILES = ("btc-to-ln", "ln-to-btc")
SCRIPT = re.compile(r"^(0014[0-9a-f]{40}|5120[0-9a-f]{64})$")  # P2WPKH or P2TR
REFUSED = 2
SECP256K1_ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141


class RefusedError(Exception):
    """The command would overwrite existing state or lacks a required input."""


def _write_new(path: Path, text: str, mode: int = 0o600) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    with os.fdopen(descriptor, "w") as handle:
        handle.write(text)


def rpcauth(user: str, password: str, salt: str) -> str:
    """Return Core's ``-rpcauth`` value (share/rpcauth/rpcauth.py)."""
    digest = hmac.new(salt.encode(), password.encode(), hashlib.sha256).hexdigest()
    return f"{user}:{salt}${digest}"


def core_credential(out: Path, methods: tuple[str, ...]) -> str:
    """Write a new ``__cookie__`` credential; return the bitcoin.conf lines."""
    if out.exists():
        raise RefusedError(f"{out} already exists")
    password = secrets.token_urlsafe(32)
    _write_new(out, f"__cookie__:{password}\n")
    return "\n".join(
        (
            "# Add to bitcoin.conf (in the network's section, for example [signet]),",
            "# then restart Core.",
            f"rpcauth={rpcauth('__cookie__', password, secrets.token_hex(16))}",
            "# Optional: limit __cookie__ logins to the provider's methods. Skip this if",
            "# anything else logs in with Core's own .cookie file (bitcoin-cli does).",
            f"rpcwhitelist=__cookie__:{','.join(methods)}",
            "# Keeps users without an rpcwhitelist unrestricted, as before. Leave it",
            "# out if every RPC user already has a whitelist.",
            "rpcwhitelistdefault=0",
        )
    )


def _lnd(profile: str) -> dict[str, Any]:
    lnd: dict[str, Any] = {
        "port": LND_PORT,
        "tls_certificate": f"{CREDENTIALS}/tls.cert",
        "macaroon": f"{CREDENTIALS}/read.macaroon",
    }
    if profile in ("btc-to-ln", "ln-to-btc", "erc20-to-ln"):
        lnd["payment_macaroon"] = f"{CREDENTIALS}/payment.macaroon"
    if profile in ("ln-to-btc", "ln-to-erc20"):
        lnd["invoices_macaroon"] = f"{CREDENTIALS}/invoices.macaroon"
    return lnd


def _evm_template() -> dict[str, Any]:
    # Each REPLACE string and zero fails validation, so the provider refuses
    # the config until the operator fills in chain, contracts, rate and timing.
    return {
        "rpc_url": "REPLACE with the EVM JSON-RPC URL (https://...)",
        "chain_id": 0,
        "name": "REPLACE with the chain name, like sepolia",
        "htlc_contract": "REPLACE with the verified ERC20Swap v6 address",
        "block_seconds": 12,
        "signer_key_file": "evm-signer.key",
        "tokens": [
            {
                "token_contract": "REPLACE with the token address",
                "token_symbol": "USDT",
                "token_decimals": 6,
                "rate_token_base_per_btc": 0,
            }
        ],
        "forward_timelock_delay_blocks": 0,
        "reverse_timelock_delay_blocks": 0,
        "learn_and_claim_seconds": 0,
        "refund_and_ln_resolution_seconds": 0,
    }


def maker_config(  # noqa: PLR0913 - one flat operator choice per argument
    *,
    profile: str,
    network: dict[str, Any],
    xonly: str,
    recipient: str,
    destination_script: str | None,
    core_wallet: str | None,
    relays: tuple[str, ...],
    affirm_store_authority: bool,
) -> dict[str, Any]:
    """Return a complete provider.json for one profile."""
    bitcoin = profile in BITCOIN_PROFILES
    if bitcoin and (destination_script is None or not SCRIPT.match(destination_script)):
        detail = "--destination-script (P2WPKH or P2TR scriptPubKey hex)"
        raise RefusedError(f"{profile} needs {detail}")
    if profile == "ln-to-btc" and core_wallet is None:
        raise RefusedError("ln-to-btc needs --core-wallet, the Core wallet that funds swaps")
    core: dict[str, Any] = {"port": CORE_PORT, "cookie_file": f"{CREDENTIALS}/core.cookie"}
    if core_wallet is not None:
        core["wallet"] = core_wallet
    if network["name"] == "signet":
        # Signet's few high-fee transactions skew estimatesmartfee past the signed caps.
        core["max_fee_estimate_sat_vb"] = SIGNET_FEE_ESTIMATE_CEILING_SAT_VB
    config: dict[str, Any] = {
        "network": network,
        "provider_identity_xonly": xonly,
        "identity_file": "provider-identity.age",
        "store_path": "/rill/store/live.sqlite",
        "custody_recipient": recipient,
        "custody_identity_file": "custody.key",
        "native_crypto_library": NATIVE_LIBRARY,
        "bitcoin_core": core,
        "lnd": _lnd(profile),
    }
    if bitcoin:
        config["provider_destination_script"] = destination_script
    else:
        config["evm"] = _evm_template()
    config |= {
        "authority": {
            "volume_label": f"rill-{network['name']}-{profile}",
            "outside_restore_domain": affirm_store_authority,
            "single_host": affirm_store_authority,
        },
        "handshake": {
            "profile": f"{profile}/v1",
            "features": ["cooperative-claim/v1"] if bitcoin else [],
            "encryption_suites": ["noise-xk-secp256k1-chachapoly-sha256/v1"],
            "capabilities": ["core/v1", "recovery/v1"],
        },
        "terms": {
            "profiles": [f"{profile}/v1"],
            "amount_bands": [[10_000, 1_000_000]],
            "base_fee_sat": 100,
            "proportional_millionths": 2_000,
            "slot": f"{network['name']}-{profile}",
        },
        "relay_urls": list(relays),
        "relay_proxy": RELAY_PROXY,
    }
    return config


def provision_identity(out: Path, recipient: str) -> str:
    """Create the encrypted provider identity; return its x-only public key."""
    result = subprocess.run(  # noqa: S603 - fixed executable, no shell
        [
            PROVIDER,
            "provision-identity",
            "--out",
            str(out),
            "--recipient",
            recipient,
            "--native-crypto-library",
            NATIVE_LIBRARY,
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


def new_evm_signer() -> tuple[str, str]:
    """Return a fresh secp256k1 key as hex and its Ethereum address."""
    from eth_account import Account  # noqa: PLC0415 - only ERC20 profiles need web3

    while not 0 < int(key := secrets.token_hex(32), 16) < SECP256K1_ORDER:
        pass
    return key, Account.from_key(key).address


def _refuse_existing(path: Path) -> None:
    if path.exists() and (not path.is_dir() or any(path.iterdir())):
        raise RefusedError(f"{path} already exists; review it, nothing was changed")


def init_maker(
    root: Path,
    args: argparse.Namespace,
    provision: Any = provision_identity,  # noqa: ANN401 - injectable for tests
) -> list[str]:
    """Create one maker's files under root; return lines to show the operator."""
    from pyrage import x25519  # type: ignore[import-untyped]  # noqa: PLC0415

    home = root / "makers" / args.profile
    store = root / "stores" / args.profile
    _refuse_existing(home)
    _refuse_existing(store)
    network = json.loads((NETWORKS / f"{args.network}.json").read_text())
    # Validate every operator input before creating anything.
    maker_config(
        profile=args.profile,
        network=network,
        xonly="0" * 64,
        recipient="",
        destination_script=args.destination_script,
        core_wallet=args.core_wallet,
        relays=tuple(args.relay or DEFAULT_RELAYS),
        affirm_store_authority=args.affirm_store_authority,
    )
    home.mkdir(mode=0o700, exist_ok=True)
    store.mkdir(mode=0o700, exist_ok=True)
    custody = x25519.Identity.generate()
    recipient = str(custody.to_public())
    _write_new(home / "custody.key", f"{custody}\n")
    xonly = provision(home / "provider-identity.age", recipient)
    lines = [f"provider identity: {xonly}"]
    if args.profile not in BITCOIN_PROFILES:
        key, address = new_evm_signer()
        _write_new(home / "evm-signer.key", f"{key}\n")
        lines.append(f"EVM signer address (fund it with gas): {address}")
    config = maker_config(
        profile=args.profile,
        network=network,
        xonly=xonly,
        recipient=recipient,
        destination_script=args.destination_script,
        core_wallet=args.core_wallet,
        relays=tuple(args.relay or DEFAULT_RELAYS),
        affirm_store_authority=args.affirm_store_authority,
    )
    _write_new(home / "provider.json", json.dumps(config, indent=2) + "\n")
    return [
        *lines,
        f"created {home} (back it up: it holds the custody key)",
        f"created {store} (never back up or restore it)",
    ]


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="rill-provider-init", description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    credential = commands.add_parser("core-credential", help="create the Core credential")
    credential.add_argument("--out", type=Path, default=Path(CREDENTIALS) / "core.cookie")
    maker = commands.add_parser("maker", help="create one maker's keys and config")
    maker.add_argument("--profile", required=True, choices=PROFILES)
    maker.add_argument("--network", required=True, choices=("mainnet", "signet", "testnet4"))
    maker.add_argument("--destination-script", help="provider P2WPKH or P2TR scriptPubKey hex")
    maker.add_argument("--core-wallet", help="Core wallet that funds ln-to-btc swaps")
    maker.add_argument("--relay", action="append", help="relay URL (repeat); web defaults")
    maker.add_argument(
        "--affirm-store-authority",
        action="store_true",
        help="affirm the store is outside every backup/restore domain and used by one host",
    )
    maker.add_argument("--root", type=Path, default=ROOT, help=argparse.SUPPRESS)
    return parser


def main(argv: list[str] | None = None) -> int:
    """Run one setup command; return the process exit status."""
    args = _parser().parse_args(argv)
    try:
        if args.command == "core-credential":
            from rill_provider.core_tx_bytes import CORE_RPC_METHODS  # noqa: PLC0415

            output = [core_credential(args.out, CORE_RPC_METHODS)]
        else:
            output = init_maker(args.root, args)
    except RefusedError as error:
        print(f"rill-provider-init: {error}", file=sys.stderr)  # noqa: T201
        return REFUSED
    print("\n".join(output))  # noqa: T201 - the command's report
    return 0


if __name__ == "__main__":
    sys.exit(main())
