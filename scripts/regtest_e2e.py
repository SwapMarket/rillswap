"""Real-backend regtest BTC to LN swap: Core, two LNDs, a relay, provider, client.

Run from the repository root with the rill-cli environment (it has every
package installed), after building the native library:

    rill-cli/.venv/bin/python scripts/regtest_e2e.py \
        --crypto-library rill-provider/tmp/native/librill_crypto.so

It creates disposable containers on a private Docker network, labeled
``org.rillswap.e2e=<run>``. Everything is removed afterwards unless
``--keep``. Nothing touches other containers or host wallets. It exits
non-zero unless the user's invoice is SETTLED, the provider's claim reaches
``CLAIMED``, and the sole LND attempt matches the committed absolute-bounded route.
Use ``--reconcile-after-settle`` to inject a provider crash after LND succeeds,
recover the witness with an offchain:read macaroon, and resume the normal claim.
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
import sqlite3
import subprocess
import sys
import threading
import time
from contextlib import ExitStack
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

# Subprocess-only fault injection. Exit after the real external success but
# before the engine can persist PAID. No recovery hook enters production code.
CRASH_AFTER_SETTLE = """
import os
import sys
from pathlib import Path
from rill_provider.cli import main
from rill_provider.lnd_payment_send import RegtestLndPaymentSender
original = RegtestLndPaymentSender.send
def send(self, *args, **kwargs):
    outcome = original(self, *args, **kwargs)
    if outcome.status == 'SUCCEEDED':
        Path(sys.argv[2]).write_text('settled before local commit')
        os._exit(73)
    return outcome
RegtestLndPaymentSender.send = send
raise SystemExit(main(['serve', '--config', sys.argv[1]]))
"""


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
            "features": ["epoch-bound-session/v1"] if args.epoch_bound else [],
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


def wait_chain_ready(
    stack: Stack, stop: threading.Event, *, timeout: float = 60
) -> bool:
    """Give both polling backends time to process this exact tip before mining.

    GetInfo's height alone is not readiness: its wallet, graph, and blockbeat
    consumers must all catch up. Only this harness mines its disposable chain.
    """
    tip = stack.cli("getbestblockhash").strip()
    deadline = time.monotonic() + timeout
    while not stop.is_set():
        infos = [stack.lncli(role, "getinfo") for role in ("provider", "user")]
        if all(info["synced_to_chain"] and info["block_hash"] == tip for info in infos):
            return True
        if time.monotonic() >= deadline:
            raise RuntimeError(
                "disposable LND nodes did not synchronize to the mined tip"
            )
        stop.wait(0.25)
    return False


def check_absolute_payment(stack: Stack, work: Path) -> None:
    """Compare the real LND attempt against signed terms and dispatch custody."""
    from rill_provider._lnd_proto.routerrpc import router_pb2  # noqa: PLC0415

    with sqlite3.connect(
        (work / "provider-store/live.sqlite").as_uri() + "?mode=ro", uri=True
    ) as connection:
        (row,) = connection.execute(
            "SELECT p.payment_hash, p.state, p.request, s.terms_offer, h.init_bytes "
            "FROM payment_dispatch p JOIN swaps s ON s.session_id=p.session_id "
            "JOIN sessions h ON h.session_id=p.session_id"
        ).fetchall()
        admissions = connection.execute(
            "SELECT COUNT(*) FROM epoch_admissions"
        ).fetchone()[0]
        reservations = connection.execute(
            "SELECT payment_hash, state, release_evidence FROM economic_reservations"
        ).fetchall()
    payment_hash, state, record_bytes, offer_bytes, init_bytes = row
    # The confirmed claim released the swap's economic reservation with evidence.
    ((reserved_hash, reservation, evidence),) = reservations
    assert (reserved_hash, reservation) == (payment_hash, "RELEASED")
    assert json.loads(evidence)["reason"] == "claim-confirmed"
    record = json.loads(record_bytes)
    terms = json.loads(offer_bytes)["payload"]["terms"]["contract_terms"]
    required_features = json.loads((work / "provider.json").read_text())["handshake"][
        "features"
    ]
    assert json.loads(init_bytes)["payload"]["required_features"] == required_features
    assert admissions == (1 if required_features else 0)
    assert state == "SUBMITTED" and record["method"] == "SendToRouteV2"
    assert record["version"] == 1
    assert (
        record["payer"]["node_pubkey"]
        == stack.lncli("provider", "getinfo")["identity_pubkey"]
    )
    assert record["payer"]["network"] == json.loads((work / "network.json").read_text())
    request = router_pb2.SendToRouteRequest.FromString(
        bytes.fromhex(record["request_hex"])
    )
    (payment,) = stack.lncli("provider", "listpayments", "--include_incomplete")[
        "payments"
    ]
    (attempt,) = payment["htlcs"]
    assert payment["payment_hash"] == payment_hash == request.payment_hash.hex()
    assert payment["status"] == attempt["status"] == "SUCCEEDED"
    expiry = int(attempt["route"]["total_time_lock"])
    assert expiry == request.route.total_time_lock
    assert expiry <= terms["timing_policy"]["max_outgoing_htlc_expiry_height"]
    assert (
        int(attempt["route"]["total_fees_msat"])
        <= int(terms["economics"]["success_fee_sat"]) * 1000
    )
    log("one LND attempt verified against committed route and signed absolute expiry")


def reconcile_after_crash(stack: Stack, config: Path, payment_hash: str) -> None:
    """Exercise the real command with offchain:read and verify retained custody."""
    work = stack.work
    assert stack.lncli("user", "lookupinvoice", payment_hash)["state"] == "SETTLED"
    with sqlite3.connect(
        (work / "provider-store/live.sqlite").as_uri() + "?mode=ro", uri=True
    ) as connection:
        (session, state, dispatch, request) = connection.execute(
            "SELECT s.session_id, s.state, p.state, p.request FROM swaps s "
            "JOIN payment_dispatch p ON p.session_id=s.session_id"
        ).fetchone()
    assert state == "PAYING" and dispatch == "SUBMITTED"
    stack.lncli(
        "provider",
        "bakemacaroon",
        "--save_to",
        "/root/reconcile-read.macaroon",
        "offchain:read",
    )
    read_macaroon = stack.copy_out(
        stack.lnd["provider"],
        "/root/reconcile-read.macaroon",
        "reconcile-read.macaroon",
        private=True,
    )
    document = json.loads(config.read_text())
    document["lnd"]["macaroon"] = str(read_macaroon)
    document["lnd"].pop("payment_macaroon")
    reconciliation_config = private(work / "reconcile.json", json.dumps(document))
    result = subprocess.run(
        [
            str(CLI / "rill-provider"),
            "reconcile-payment",
            "--config",
            str(reconciliation_config),
            "--session-id",
            session,
        ],
        capture_output=True,
        text=True,
        check=True,
        timeout=30,
    )
    assert not result.stderr
    assert json.loads(result.stdout) == {
        "format": "rillswap/provider-payment-reconciliation/v1",
        "session_id": session,
        "payment_status": "SUCCEEDED",
        "swap_state": "PAID",
        "state_changed": True,
    }
    with sqlite3.connect(
        (work / "provider-store/live.sqlite").as_uri() + "?mode=ro", uri=True
    ) as connection:
        assert connection.execute("SELECT state FROM swaps").fetchone() == ("PAID",)
        assert connection.execute(
            "SELECT state, request FROM payment_dispatch"
        ).fetchone() == (dispatch, request)
    log("crash-recovered witness using offchain:read only; dispatch bytes unchanged")


def main() -> int:  # noqa: PLR0915 - one ordered scenario
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--crypto-library", required=True)
    parser.add_argument(
        "--epoch-bound",
        action="store_true",
        help="exercise negotiated epoch-bound admission",
    )
    parser.add_argument(
        "--keep", action="store_true", help="keep containers for inspection"
    )
    parser.add_argument("--timeout", type=int, default=600, help="whole swap seconds")
    parser.add_argument(
        "--reconcile-after-settle",
        action="store_true",
        help="crash after LND settles, reconcile with read credentials, then resume",
    )
    args = parser.parse_args()
    work = ROOT / "tmp" / f"e2e-{time.strftime('%Y%m%dT%H%M%S')}"
    work.mkdir(parents=True, mode=0o700)
    stack = Stack(work)
    stop_mining = threading.Event()
    provider: subprocess.Popen[bytes] | None = None
    client: subprocess.Popen[bytes] | None = None
    files = ExitStack()
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
        provider_log = files.enter_context((work / "provider.log").open("wb"))
        provider_command = [
            str(CLI / "rill-provider"),
            "serve",
            "--config",
            str(config),
        ]
        marker = work / "settled-before-commit"
        initial_command = (
            [str(CLI / "python"), "-c", CRASH_AFTER_SETTLE, str(config), str(marker)]
            if args.reconcile_after_settle
            else provider_command
        )
        provider = subprocess.Popen(  # noqa: S603
            initial_command,
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
            while not stop_mining.is_set():
                try:
                    if not wait_chain_ready(stack, stop_mining) or stop_mining.wait(3):
                        return
                    mine(stack, 1, miner)
                except Exception:  # noqa: BLE001 - best effort block production
                    log(
                        "disposable mining stopped: node readiness or mining unavailable"
                    )
                    return

        threading.Thread(target=keep_mining, daemon=True).start()
        log("running rill swap btc-to-ln")
        client_stdout = files.enter_context((work / "client.stdout").open("wb"))
        client_stderr = files.enter_context((work / "client.stderr").open("wb"))
        client = subprocess.Popen(  # noqa: S603
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
            stdout=client_stdout,
            stderr=client_stderr,
        )
        if args.reconcile_after_settle:
            if provider.wait(timeout=args.timeout) != 73 or not marker.exists():
                raise RuntimeError(
                    "provider did not reach the deterministic settled crash"
                )
            reconcile_after_crash(stack, config, payment_hash)
            provider = subprocess.Popen(
                provider_command, stdout=provider_log, stderr=subprocess.STDOUT
            )
        client.wait(timeout=args.timeout + 120)
        swap = subprocess.CompletedProcess(
            client.args,
            client.returncode,
            (work / "client.stdout").read_text(),
            (work / "client.stderr").read_text(),
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
        if ok:
            check_absolute_payment(stack, work)
        log("PASS" if ok else f"FAIL (logs in {work})")
        return 0 if ok else 1
    finally:
        stop_mining.set()
        if client is not None and client.poll() is None:
            client.kill()
            client.wait(10)
        if provider is not None:
            provider.terminate()
            try:
                provider.wait(10)
            except subprocess.TimeoutExpired:
                provider.kill()
                provider.wait(10)
        files.close()
        if relay_stop is not None:
            relay_stop.set()
        if args.keep:
            log(f"kept containers labeled {stack.label}")
        else:
            stack.stop()


if __name__ == "__main__":
    os.umask(0o077)
    raise SystemExit(main())
