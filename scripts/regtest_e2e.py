"""Real-backend regtest BTC to LN swap: Core, two LNDs, a relay, provider, client.

Run from the repository root with the rill-cli environment (it has every
package installed), after building the native library:

    rill-cli/.venv/bin/python scripts/regtest_e2e.py \
        --crypto-library rill-provider/tmp/native/librill_crypto.so

It creates disposable containers on a private Docker network, labeled
``org.rillswap.e2e=<run>``. Everything is removed afterwards unless
``--keep``. Nothing touches other containers or host wallets. It exits
non-zero unless the user's invoice is SETTLED and the provider's claim reaches
``CLAIMED``.
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import hashlib
import hmac
import json
import os
import secrets
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Any

from pyrage import x25519

ROOT = Path(__file__).resolve().parents[1]
CORE_IMAGE = "sha256:49b55ea5c949a9ceff50786ee678d53f2728a4daa40a8139e3ee20243d24f281"
LND_IMAGE = "sha256:60fca3f409cf3d500db1d15c9965678a4b5a60758ff30863d52b02529c18be8b"
NETWORK_FIXTURE = (
    ROOT / "rill-provider" / "tests" / "fixtures" / "initial-btc-to-ln-v1.json"
)
RPC_USER, RPC_PASSWORD = "lnd", "disposable-regtest-only"
CLI = ROOT / "rill-cli" / ".venv" / "bin"


def log(line: str) -> None:
    sys.stderr.write(f"[e2e {time.strftime('%H:%M:%S')}] {line}\n")


def docker(*args: str, timeout: int = 120, check: bool = True) -> str:
    done = subprocess.run(  # noqa: S603 - fixed docker executable, own containers only
        ["docker", *args],  # noqa: S607
        text=True,
        capture_output=True,
        timeout=timeout,
        check=False,
    )
    if check and done.returncode:
        raise RuntimeError(f"docker {args[0]} failed: {done.stderr.strip()[-400:]}")
    return done.stdout.strip()


class Stack:
    def __init__(self, work: Path) -> None:
        self.run_id = secrets.token_hex(4)
        self.work = work
        self.net = f"rill-e2e-{self.run_id}"
        self.core = f"rill-e2e-core-{self.run_id}"
        self.lnd = {
            role: f"rill-e2e-lnd-{role}-{self.run_id}" for role in ("provider", "user")
        }
        self.label = f"org.rillswap.e2e={self.run_id}"

    def cli(self, *args: str, wallet: str | None = None) -> str:
        extra = [f"-rpcwallet={wallet}"] if wallet else []
        return docker(
            "exec",
            "--user",
            "bitcoin",
            self.core,
            "bitcoin-cli",
            "-regtest",
            f"-rpcuser={RPC_USER}",
            f"-rpcpassword={RPC_PASSWORD}",
            *extra,
            *args,
        )

    def lncli(self, role: str, *args: str) -> Any:  # noqa: ANN401
        output = docker("exec", self.lnd[role], "lncli", "--network=regtest", *args)
        return json.loads(output) if output.startswith(("{", "[")) else output

    def host_port(self, container: str, port: int) -> int:
        return int(
            docker("port", container, str(port)).splitlines()[0].rsplit(":", 1)[1]
        )

    def copy_out(self, container: str, path: str, name: str, *, private: bool) -> Path:
        data = base64.b64decode(docker("exec", container, "base64", "-w0", path))
        target = self.work / name
        target.write_bytes(data)
        target.chmod(0o600 if private else 0o644)
        return target

    def start(self) -> None:
        docker("network", "create", "--label", self.label, self.net)
        salt = secrets.token_hex(16)
        digest = hmac.new(
            salt.encode(), RPC_PASSWORD.encode(), hashlib.sha256
        ).hexdigest()
        docker(
            "run",
            "--detach",
            "--name",
            self.core,
            "--label",
            self.label,
            "--network",
            self.net,
            "--publish",
            "127.0.0.1::18443",
            CORE_IMAGE,
            "-regtest=1",
            "-server=1",
            "-txindex=1",
            "-listen=0",
            "-dnsseed=0",
            f"-rpcauth={RPC_USER}:{salt}${digest}",
            "-rpcbind=0.0.0.0",
            "-rpcallowip=0.0.0.0/0",
            "-fallbackfee=0.0002",
            "-printtoconsole=1",
        )
        for _ in range(100):
            if docker(
                "exec",
                "--user",
                "bitcoin",
                self.core,
                "bitcoin-cli",
                "-regtest",
                f"-rpcuser={RPC_USER}",
                f"-rpcpassword={RPC_PASSWORD}",
                "getblockcount",
                check=False,
            ).isdigit():
                break
            time.sleep(0.3)
        for role, name in self.lnd.items():
            docker(
                "run",
                "--detach",
                "--name",
                name,
                "--label",
                self.label,
                "--network",
                self.net,
                "--publish",
                "127.0.0.1::10009",
                LND_IMAGE,
                "--bitcoin.active",
                "--bitcoin.regtest",
                "--bitcoin.node=bitcoind",
                f"--bitcoind.rpchost={self.core}:18443",
                f"--bitcoind.rpcuser={RPC_USER}",
                f"--bitcoind.rpcpass={RPC_PASSWORD}",
                "--bitcoind.rpcpolling",
                "--rpclisten=0.0.0.0:10009",
                "--listen=0.0.0.0:9735",
                "--tlsextraip=127.0.0.1",
                f"--tlsextradomain={name}",
                "--noseedbackup",
                "--nobootstrap",
                f"--alias={role}",
                "--trickledelay=50",
            )

    def wait_active(self) -> None:
        for name in self.lnd.values():
            for _ in range(200):
                state = docker(
                    "exec", name, "lncli", "--network=regtest", "state", check=False
                )
                if '"SERVER_ACTIVE"' in state:
                    break
                time.sleep(0.3)
            else:
                tail = docker("logs", "--tail", "15", name, check=False, timeout=10)
                raise RuntimeError(f"{name} did not become active: {tail}")

    def stop(self) -> None:
        names = docker(
            "ps", "-aq", "--filter", f"label={self.label}", check=False
        ).split()
        if names:
            docker("rm", "-f", *names, check=False)
        docker("network", "rm", self.net, check=False)


def mine(stack: Stack, blocks: int, address: str) -> None:
    stack.cli("generatetoaddress", str(blocks), address)


def wait_synced(stack: Stack) -> None:
    height = int(stack.cli("getblockcount"))
    for role in stack.lnd:
        for _ in range(200):
            info = stack.lncli(role, "getinfo")
            if info["synced_to_chain"] and info["block_height"] == height:
                break
            time.sleep(0.3)
        else:
            raise RuntimeError(f"{role} LND did not sync")


def start_relay() -> tuple[str, threading.Event]:
    sys.path.insert(0, str(ROOT / "rill-provider" / "tests"))
    from fake_relay import FakeRelay  # noqa: PLC0415 - dev relay double

    ready: dict[str, str] = {}
    started, stop = threading.Event(), threading.Event()

    def serve() -> None:
        async def main() -> None:
            relay = FakeRelay()
            ready["url"] = await relay.start()
            started.set()
            while not stop.is_set():
                await asyncio.sleep(0.2)
            await relay.stop()

        asyncio.run(main())

    threading.Thread(target=serve, daemon=True).start()
    started.wait(10)
    return ready["url"], stop


def private(path: Path, text: str) -> Path:
    path.write_text(text)
    path.chmod(0o600)
    return path


def provider_config(
    stack: Stack, args: argparse.Namespace, relay: str, xonly: str
) -> Path:
    work = stack.work
    network = json.loads(NETWORK_FIXTURE.read_text())["network_identity"]
    (work / "network.json").write_text(json.dumps(network))
    ports = {role: stack.host_port(name, 10009) for role, name in stack.lnd.items()}
    stack.copy_out(
        stack.lnd["provider"], "/root/.lnd/tls.cert", "provider-tls.cert", private=False
    )
    stack.copy_out(
        stack.lnd["provider"],
        "/root/.lnd/data/chain/bitcoin/regtest/admin.macaroon",
        "provider-admin.macaroon",
        private=True,
    )
    stack.copy_out(
        stack.core,
        "/home/bitcoin/.bitcoin/regtest/.cookie",
        "core.cookie",
        private=True,
    )
    destination = stack.cli(
        "getaddressinfo",
        stack.cli("getnewaddress", "", "bech32m", wallet="miner"),
        wallet="miner",
    )
    config = {
        "network": network,
        "provider_identity_xonly": xonly,
        "identity_file": "provider-identity.age",
        "store_path": "provider-store/live.sqlite",
        "custody_recipient": args.custody_recipient,
        "custody_identity_file": "custody.key",
        "native_crypto_library": str(Path(args.crypto_library).resolve()),
        "bitcoin_core": {
            "port": stack.host_port(stack.core, 18443),
            "cookie_file": "core.cookie",
        },
        "lnd": {
            "port": ports["provider"],
            "tls_certificate": "provider-tls.cert",
            "macaroon": "provider-admin.macaroon",
            "payment_macaroon": "provider-admin.macaroon",
        },
        "provider_destination_script": json.loads(destination)["scriptPubKey"],
        "authority": {
            "volume_label": "e2e",
            "outside_restore_domain": True,
            "single_host": True,
        },
        "handshake": {
            "profile": "btc-to-ln/v1",
            "encryption_suites": ["noise-xk-secp256k1-chachapoly-sha256/v1"],
            "capabilities": ["core/v1", "recovery/v1"],
        },
        "terms": {
            "profiles": ["btc-to-ln/v1"],
            "amount_bands": [[1000, 1_000_000]],
            "base_fee_sat": 50,
            "proportional_millionths": 1000,
            "slot": "e2e",
        },
        "relay_urls": [relay],
    }
    (work / "provider-store").mkdir(mode=0o700)
    path = work / "provider.json"
    path.write_text(json.dumps(config, indent=1))
    return path


def main() -> int:  # noqa: PLR0915 - one ordered scenario
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--crypto-library", required=True)
    parser.add_argument(
        "--keep", action="store_true", help="keep containers for inspection"
    )
    parser.add_argument("--timeout", type=int, default=600, help="whole swap seconds")
    args = parser.parse_args()
    work = ROOT / "tmp" / f"e2e-{time.strftime('%Y%m%dT%H%M%S')}"
    work.mkdir(parents=True, mode=0o700)
    stack = Stack(work)
    stop_mining = threading.Event()
    provider: subprocess.Popen[bytes] | None = None
    relay_stop: threading.Event | None = None
    try:
        log(f"starting containers (run {stack.run_id}, work {work})")
        stack.start()
        stack.cli("createwallet", "miner")
        stack.cli("createwallet", "user")
        miner = stack.cli("getnewaddress", wallet="miner")
        mine(stack, 101, miner)
        stack.wait_active()
        for role in stack.lnd:
            address = stack.lncli(role, "newaddress", "p2tr")["address"]
            stack.cli("sendtoaddress", address, "1", wallet="miner")
        stack.cli(
            "sendtoaddress",
            stack.cli("getnewaddress", wallet="user"),
            "1",
            wallet="miner",
        )
        mine(stack, 6, miner)
        wait_synced(stack)
        user_pubkey = stack.lncli("user", "getinfo")["identity_pubkey"]
        stack.lncli("provider", "connect", f"{user_pubkey}@{stack.lnd['user']}:9735")
        stack.lncli(
            "provider",
            "openchannel",
            "--node_key",
            user_pubkey,
            "--local_amt",
            "1000000",
        )
        mine(stack, 6, miner)
        for _ in range(200):
            if stack.lncli("provider", "listchannels")["channels"]:
                break
            time.sleep(0.3)
        else:
            raise RuntimeError("channel did not open")
        log("channel open provider -> user")

        relay, relay_stop = start_relay()
        log(f"relay {relay}")
        custody = x25519.Identity.generate()
        private(work / "custody.key", str(custody) + "\n")
        args.custody_recipient = str(custody.to_public())
        xonly = subprocess.run(  # noqa: S603 - our own console script
            [
                str(CLI / "rill-provider"),
                "provision-identity",
                "--out",
                str(work / "provider-identity.age"),
                "--recipient",
                args.custody_recipient,
                "--native-crypto-library",
                args.crypto_library,
            ],
            capture_output=True,
            text=True,
            check=True,
        ).stdout.strip()
        config = provider_config(stack, args, relay, xonly)
        subprocess.run(
            [str(CLI / "rill-provider"), "provision-store", "--config", str(config)],
            check=True,
        )  # noqa: S603
        provider_log = (work / "provider.log").open("wb")
        provider = subprocess.Popen(  # noqa: S603
            [str(CLI / "rill-provider"), "serve", "--config", str(config)],
            stdout=provider_log,
            stderr=subprocess.STDOUT,
        )
        time.sleep(3)
        if provider.poll() is not None:
            raise RuntimeError("provider exited; see provider.log")
        log(f"provider {xonly[:16]} serving")

        invoice = stack.lncli(
            "user", "addinvoice", "--amt", "50000", "--memo", "rill-e2e"
        )
        bolt11, payment_hash = invoice["payment_request"], invoice["r_hash"]
        stack.copy_out(
            stack.lnd["user"], "/root/.lnd/tls.cert", "user-tls.cert", private=False
        )
        stack.copy_out(
            stack.lnd["user"],
            "/root/.lnd/data/chain/bitcoin/regtest/admin.macaroon",
            "user-admin.macaroon",
            private=True,
        )
        user_age = x25519.Identity.generate()
        private(work / "user-age.key", str(user_age) + "\n")

        def keep_mining() -> None:
            while not stop_mining.wait(3):
                try:
                    mine(stack, 1, miner)
                except Exception:  # noqa: BLE001 - best effort block production
                    return

        threading.Thread(target=keep_mining, daemon=True).start()
        log("running rill swap btc-to-ln")
        swap = subprocess.run(  # noqa: S603
            [
                str(CLI / "rill"),
                "swap",
                "btc-to-ln",
                "--network",
                str(work / "network.json"),
                "--crypto-library",
                args.crypto_library,
                "--relay",
                relay,
                "--provider",
                xonly,
                "--invoice",
                bolt11,
                "--max-success-fee-sat",
                "2000",
                "--core-port",
                str(stack.host_port(stack.core, 18443)),
                "--core-cookie",
                str(work / "core.cookie"),
                "--wallet",
                "user",
                "--lnd-port",
                str(stack.host_port(stack.lnd["user"], 10009)),
                "--lnd-tls-cert",
                str(work / "user-tls.cert"),
                "--lnd-macaroon",
                str(work / "user-admin.macaroon"),
                "--recipient",
                str(user_age.to_public()),
                "--identity",
                str(work / "user-age.key"),
                "--recovery-output",
                str(work / "user-recovery.age"),
                "--settle-timeout",
                str(args.timeout),
            ],
            capture_output=True,
            text=True,
            timeout=args.timeout + 120,
            check=False,
        )
        sys.stderr.write(swap.stderr)
        log(f"client exit {swap.returncode}: {swap.stdout.strip()}")
        state = stack.lncli("user", "lookupinvoice", payment_hash)["state"]
        log(f"user invoice {state}")
        deadline = time.monotonic() + 180
        claimed = False
        while time.monotonic() < deadline and not claimed:
            claimed = b"moved to CLAIMED" in (work / "provider.log").read_bytes()
            time.sleep(2)
        log(f"provider claim {'CLAIMED' if claimed else 'NOT confirmed'}")
        ok = swap.returncode == 0 and state == "SETTLED" and claimed
        log("PASS" if ok else f"FAIL (logs in {work})")
        return 0 if ok else 1
    finally:
        stop_mining.set()
        if provider is not None:
            provider.terminate()
            try:
                provider.wait(10)
            except subprocess.TimeoutExpired:
                provider.kill()
        if relay_stop is not None:
            relay_stop.set()
        if args.keep:
            log(f"kept containers labeled {stack.label}")
        else:
            stack.stop()


if __name__ == "__main__":
    os.umask(0o077)
    raise SystemExit(main())
