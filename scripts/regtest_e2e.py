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
``--ln-to-btc`` runs RS-004 instead: the user opens the channel, pays the
provider's hold invoice, and claims the contract the provider funds from its
Core wallet; it passes once the provider's swap is ``SETTLED``, its hold
invoice settled, the user's payment succeeded, and the confirmed claim pays
the user at least the requested payout.
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import hashlib
import hmac
import http.client
import json
import os
import re
import secrets
import selectors
import shutil
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
CORE_IMAGE = "sha256:ca69e5a5e316cdde3334b277caff687dd07b8c322f208063aa29a976132fca34"
LND_IMAGE = "sha256:ca3477292ae8805d4d49d99c70f492c56bd001f2f464c482cd58de9443f56930"
NETWORK_FIXTURE = (
    ROOT / "rill-provider" / "tests" / "fixtures" / "initial-btc-to-ln-v1.json"
)
RPC_USER, RPC_PASSWORD = "lnd", "disposable-regtest-only"
CLI = ROOT / "rill-cli" / ".venv" / "bin"
MERCHANT_BUN = ROOT / "tmp/toolchains/bun-v1.3.11/bun"

# Subprocess-only fault injection. Exit after the real external success but
# before the engine can persist PAID. No recovery hook enters production code.
CRASH_AFTER_SETTLE = """
import os
import sys
from pathlib import Path
from rill_provider.cli import main
from rill_provider.lnd_payment_send import LndPaymentSender
original = LndPaymentSender.send
def send(self, *args, **kwargs):
    outcome = original(self, *args, **kwargs)
    if outcome.status == 'SUCCEEDED':
        Path(sys.argv[2]).write_text('settled before local commit')
        os._exit(73)
    return outcome
LndPaymentSender.send = send
raise SystemExit(main(['serve', '--config', sys.argv[1]]))
"""

# Subprocess-only fault injection: the provider's sender reports the sole
# authorized attempt as FAILED by its own payer without sending it, so the
# swap fails after dispatch and the client must refund on chain.
NEVER_PAY = """
import sys
from rill_provider.cli import main
from rill_provider.lnd_payment_send import LndPaymentSender, PaymentOutcome
def send(self, payment):
    return PaymentOutcome('FAILED', payer=payment.payer.node_pubkey)
LndPaymentSender.send = send
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
        self.merchant_mode = False
        self.created_containers: list[str] = []
        self.created_network: str | None = None
        self.anonymous_volumes: set[str] = set()

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

    def start(self, *, merchant_mode: bool = False) -> None:
        self.merchant_mode = merchant_mode
        network_id = docker("network", "create", "--label", self.label, self.net)
        if merchant_mode:
            if not re.fullmatch(r"[0-9a-f]{64}", network_id):
                raise RuntimeError("new network ownership unresolved")
            self.created_network = network_id
        salt = secrets.token_hex(16)
        digest = hmac.new(
            salt.encode(), RPC_PASSWORD.encode(), hashlib.sha256
        ).hexdigest()
        core_id = docker(
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
        if merchant_mode:
            self._record_container(core_id, "/home/bitcoin/.bitcoin")
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
            rest_args = (
                ("--publish", "127.0.0.1::8080")
                if merchant_mode and role == "user"
                else ()
            )
            lnd_id = docker(
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
                *rest_args,
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
                *(("--restlisten=0.0.0.0:8080",) if rest_args else ()),
            )
            if merchant_mode:
                self._record_container(lnd_id, "/root/.lnd")

    def _record_container(self, container_id: str, destination: str) -> None:
        if not re.fullmatch(r"[0-9a-f]{64}", container_id):
            raise RuntimeError("new container ownership unresolved")
        self.created_containers.append(container_id)
        actual = json.loads(docker("inspect", container_id))[0]
        if actual["Config"]["Labels"].get("org.rillswap.e2e") != self.run_id:
            raise RuntimeError("new container label mismatch")
        expected_image = (
            CORE_IMAGE if destination == "/home/bitcoin/.bitcoin" else LND_IMAGE
        )
        host = actual["HostConfig"]
        if (
            actual["Image"] != expected_image
            or host["NetworkMode"] != self.net
            or host.get("Binds")
            or host.get("VolumesFrom")
        ):
            raise RuntimeError("new container configuration mismatch")
        if any(
            binding["HostIp"] != "127.0.0.1"
            for bindings in host["PortBindings"].values()
            for binding in bindings
        ):
            raise RuntimeError("non-loopback diagnostic publication refused")
        mounts = actual["Mounts"]
        if (
            len(mounts) != 1
            or mounts[0]["Type"] != "volume"
            or mounts[0]["Destination"] != destination
        ):
            raise RuntimeError("unexpected disposable container mount")
        volume = mounts[0]["Name"]
        if (
            not re.fullmatch(r"[0-9a-f]{64}", volume)
            or volume in self.anonymous_volumes
        ):
            raise RuntimeError("anonymous volume ownership unresolved")
        # Fixed docker run has no volume/bind/inheritance arguments; this mount
        # was created from the reviewed pinned image's sole VOLUME declaration.
        self.anonymous_volumes.add(volume)

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
        if self.merchant_mode:
            unresolved = False
            for container_id in reversed(self.created_containers):
                try:
                    if not docker_resource_present("container", container_id):
                        continue
                    record = json.loads(docker("inspect", container_id))[0]
                    if (
                        record["Config"]["Labels"].get("org.rillswap.e2e")
                        != self.run_id
                    ):
                        raise RuntimeError("owned container identity unresolved")
                    if any(
                        mount["Type"] != "volume"
                        or mount["Name"] not in self.anonymous_volumes
                        for mount in record["Mounts"]
                    ):
                        # A rejected/unrecorded mount never authorizes volume deletion.
                        docker("rm", "-f", container_id)
                    else:
                        docker("rm", "-f", "--volumes", container_id)
                except Exception:  # noqa: BLE001 - attempt every owned cleanup, never publish private errors
                    unresolved = True
            if self.created_network:
                try:
                    if docker_resource_present("network", self.created_network):
                        label = docker(
                            "network",
                            "inspect",
                            self.created_network,
                            "--format",
                            '{{index .Labels "org.rillswap.e2e"}}',
                        )
                        if label != self.run_id:
                            raise RuntimeError("owned network identity unresolved")
                        docker("network", "rm", self.created_network)
                except Exception:  # noqa: BLE001
                    unresolved = True
            if unresolved:
                raise RuntimeError("owned diagnostic cleanup identity unresolved")
            return
        names = docker(
            "ps", "-aq", "--filter", f"label={self.label}", check=False
        ).split()
        if names:
            docker("rm", "-f", *names, check=False)
        docker("network", "rm", self.net, check=False)


def docker_resource_present(kind: str, resource_id: str) -> bool:
    """Only a successful daemon query can prove a captured resource absent."""
    ids = docker(
        kind,
        "ls",
        *(("--all",) if kind == "container" else ()),
        "--quiet",
        "--no-trunc",
        "--filter",
        f"id={resource_id}",
    ).split()
    if ids and ids != [resource_id]:
        raise RuntimeError("owned resource query unresolved")
    return bool(ids)


class MerchantDiagnostic:
    """Trusted happy-path test process, independently observed merchant receipt."""

    def __init__(self, work: Path, bun: Path) -> None:
        self.work = work / "merchant"
        self.work.mkdir(mode=0o700)
        self.bun = bun
        self.child: subprocess.Popen[bytes] | None = None
        self.port = 0
        self.admin = secrets.token_urlsafe(32)
        self.public_key = ""
        self.checkout: dict[str, Any] | None = None
        self.status_token = ""
        self.restarted = False
        self.crash_armed = False
        self.receipt_recovered = False
        self.receipt_loss_baseline: (
            tuple[
                dict[str, tuple[int, int, str]],
                dict[str, list[tuple[Any, ...]]],
                tuple[int, int],
            ]
            | None
        ) = None

    def start(self, stack: Stack, *, crash_after_settled: bool = False) -> None:
        from Cryptodome.Signature import eddsa  # noqa: PLC0415 - diagnostic only

        if self.child is not None or any(self.work.iterdir()):
            raise RuntimeError("merchant initialization already attempted")
        config: dict[str, str] = {
            "origin": "https://merchant.invalid",
            "receiver": stack.lncli("user", "getinfo")["identity_pubkey"],
            "endpoint": f"https://127.0.0.1:{stack.host_port(stack.lnd['user'], 8080)}/",
            "ledgerPath": str(self.work / "merchant.sqlite"),
        }
        for field, name in (
            ("issuanceKeyPath", "issuance.key"),
            ("statusKeyPath", "status.key"),
            ("eventKeyPath", "event.key"),
        ):
            key = secrets.token_bytes(32)
            target = self.work / name
            target.write_bytes(key)
            target.chmod(0o600)
            config[field] = str(target)
            if field == "eventKeyPath":
                self.public_key = (
                    eddsa.import_private_key(key)
                    .public_key()
                    .export_key(format="raw")
                    .hex()
                )
        config["adminTokenPath"] = str(private(self.work / "admin.token", self.admin))
        stack.lncli(
            "user",
            "bakemacaroon",
            "--save_to",
            "/root/merchant.macaroon",
            "info:read",
            "invoices:read",
            "invoices:write",
        )
        config["macaroonPath"] = str(
            stack.copy_out(
                stack.lnd["user"],
                "/root/merchant.macaroon",
                "merchant/invoice.macaroon",
                private=True,
            )
        )
        config["certificatePath"] = str(
            stack.copy_out(
                stack.lnd["user"],
                "/root/.lnd/tls.cert",
                "merchant/tls.cert",
                private=True,
            )
        )
        config_path = private(self.work / "config.json", json.dumps(config))
        bundle = self.work / "service.js"
        built = subprocess.run(
            [
                str(self.bun),
                "build",
                "scripts/regtest-merchant.ts",
                "--target",
                "bun",
                "--outfile",
                str(bundle),
            ],
            cwd=ROOT / "rill-payments",
            capture_output=True,
            timeout=30,
            check=False,
        )  # noqa: S603
        if built.returncode:
            raise RuntimeError("merchant diagnostic build refused")
        env = {**os.environ, "RILLSWAP_REGTEST_MERCHANT": "1"}
        provisioned = subprocess.run(
            [str(self.bun), str(bundle), "provision", str(config_path)],
            env=env,
            capture_output=True,
            timeout=20,
            check=False,
        )  # noqa: S603
        if provisioned.returncode or json.loads(provisioned.stdout) != {
            "provisioned": True
        }:
            raise RuntimeError("explicit merchant provisioning refused")
        self.crash_armed = crash_after_settled
        self._launch_merchant(initial_fault=crash_after_settled)

    def _serve_existing(self) -> None:
        # Reopening cannot arm a fault or infer permission from missing state.
        self._launch_merchant()

    def _launch_merchant(self, *, initial_fault: bool = False) -> None:
        if self.child is not None and self.child.poll() is None:
            raise RuntimeError("original merchant child remains live")
        self.port = 0
        self.child = subprocess.Popen(
            [
                str(self.bun),
                str(self.work / "service.js"),
                "serve",
                str(self.work / "config.json"),
                *(("crash-after-settled",) if initial_fault else ()),
            ],
            env={**os.environ, "RILLSWAP_REGTEST_MERCHANT": "1"},
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        )  # noqa: S603
        assert self.child.stdout is not None
        with selectors.DefaultSelector() as selector:
            selector.register(self.child.stdout, selectors.EVENT_READ)
            buffer = bytearray()
            deadline = time.monotonic() + 20
            while b"\n" not in buffer:
                remaining = deadline - time.monotonic()
                if remaining <= 0 or not selector.select(timeout=remaining):
                    raise RuntimeError("merchant readiness timed out")
                chunk = os.read(self.child.stdout.fileno(), 4096)
                if not chunk or len(buffer) + len(chunk) > 8192:
                    raise RuntimeError("merchant readiness refused")
                buffer.extend(chunk)
        ready = json.loads(buffer.split(b"\n", 1)[0])
        if (
            set(ready) != {"ready", "port", "publicKey"}
            or ready["ready"] is not True
            or type(ready["port"]) is not int
            or not 0 < ready["port"] < 65536
            or ready["publicKey"] != self.public_key
        ):
            raise RuntimeError("merchant readiness identity mismatch")
        self.port = ready["port"]

    def _immutable_inputs(self) -> dict[str, tuple[int, int, str]]:
        snapshots = {}
        for name in (
            "config.json",
            "issuance.key",
            "status.key",
            "event.key",
            "admin.token",
            "invoice.macaroon",
            "tls.cert",
            "service.js",
        ):
            path = self.work / name
            stat = path.lstat()
            if (
                not path.is_file()
                or path.is_symlink()
                or stat.st_nlink != 1
                or (name != "service.js" and stat.st_mode & 0o077)
            ):
                raise RuntimeError("merchant restart input refused")
            snapshots[name] = (
                stat.st_dev,
                stat.st_ino,
                hashlib.sha256(path.read_bytes()).hexdigest(),
            )
        return snapshots

    def _waiting_state(self) -> dict[str, list[tuple[Any, ...]]]:
        if self.checkout is None or not self.status_token:
            raise RuntimeError("merchant checkout baseline missing")
        route = "/v1/intents/" + self.checkout["id"]
        if (
            self.request(route, status=True) != self.checkout
            or self.request(route + "/events", status=True) != []
        ):
            raise RuntimeError("merchant waiting checkout changed")
        return self._unaccepted_state()

    def _unaccepted_state(self) -> dict[str, list[tuple[Any, ...]]]:
        if self.checkout is None:
            raise RuntimeError("merchant checkout baseline missing")
        # Read the logical SQLite view, including WAL, with database creation disabled.
        with sqlite3.connect(
            (self.work / "merchant.sqlite").as_uri() + "?mode=ro", uri=True
        ) as db:
            state = {
                table: db.execute(f"SELECT * FROM {table} ORDER BY 1").fetchall()
                for table in (
                    "metadata",
                    "intents",
                    "idempotency",
                    "attempts",
                    "receipts",
                    "outbox",
                )
            }  # noqa: S608 - fixed table names only
            terms = self.checkout["attempt"]["terms"]
            if db.execute("SELECT id, amount_msat, status FROM intents").fetchall() != [
                (terms["intentId"], terms["amountMsat"], "waiting")
            ]:
                raise RuntimeError("merchant intent continuity refused")
            if db.execute(
                "SELECT id, intent_id, state, invoice, payment_hash FROM attempts"
            ).fetchall() != [
                (
                    terms["attemptId"],
                    terms["intentId"],
                    "ready",
                    self.checkout["attempt"]["invoice"],
                    terms["paymentHash"],
                )
            ]:
                raise RuntimeError("merchant attempt continuity refused")
            if state["receipts"] or state["outbox"]:
                raise RuntimeError("merchant accepted before payer dispatch")
        return state

    def _store_identity(self) -> tuple[int, int]:
        store = self.work / "merchant.sqlite"
        stat = store.lstat()
        if (
            not store.is_file()
            or store.is_symlink()
            or stat.st_nlink != 1
            or stat.st_mode & 0o077
        ):
            raise RuntimeError("merchant store continuity refused")
        return stat.st_dev, stat.st_ino

    def prepare_receipt_loss(self) -> None:
        if (
            not self.crash_armed
            or self.receipt_loss_baseline is not None
            or self.child is None
            or self.child.poll() is not None
        ):
            raise RuntimeError("merchant receipt fault baseline refused")
        if os.path.lexists(self.work / "settled-receipt-fault.json"):
            raise RuntimeError("merchant receipt fault evidence already exists")
        self.receipt_loss_baseline = (
            self._immutable_inputs(),
            self._waiting_state(),
            self._store_identity(),
        )

    def recover_receipt_loss(self, *, timeout: int = 30) -> None:
        if (
            not self.crash_armed
            or self.receipt_recovered
            or self.receipt_loss_baseline is None
            or self.child is None
            or self.checkout is None
        ):
            raise RuntimeError("merchant receipt recovery baseline refused")
        if self.child.wait(timeout=timeout) != 74:
            raise RuntimeError("merchant settled-observation exit refused")
        if self.child.stdout:
            self.child.stdout.close()
        marker = self.work / "settled-receipt-fault.json"
        stat = marker.lstat()
        if (
            not marker.is_file()
            or marker.is_symlink()
            or stat.st_nlink != 1
            or stat.st_mode & 0o077
            or stat.st_size > 4096
        ):
            raise RuntimeError("merchant receipt fault evidence refused")
        evidence = json.loads(marker.read_text())
        terms = self.checkout["attempt"]["terms"]
        if (
            not isinstance(evidence, dict)
            or set(evidence)
            != {
                "version",
                "receiver",
                "network",
                "paymentHash",
                "invoiceAmountMsat",
                "paidMsat",
                "state",
                "settledAt",
            }
            or evidence["version"] != "regtest-settled-receipt-loss/1"
            or evidence["state"] != "SETTLED"
            or any(
                evidence[name] != terms[name]
                for name in ("receiver", "network", "paymentHash")
            )
            or evidence["invoiceAmountMsat"] != terms["amountMsat"]
            or not isinstance(evidence["paidMsat"], str)
            or not re.fullmatch(r"[1-9][0-9]{0,18}", evidence["paidMsat"])
            or int(evidence["paidMsat"]) < int(terms["amountMsat"])
            or type(evidence["settledAt"]) is not int
            or not 0 < evidence["settledAt"] <= int(time.time())
        ):
            raise RuntimeError("merchant receipt fault binding refused")
        inputs, baseline, identity = self.receipt_loss_baseline
        if (
            self._immutable_inputs() != inputs
            or self._store_identity() != identity
            or self._unaccepted_state() != baseline
        ):
            raise RuntimeError("merchant preacceptance crash state changed")
        self._serve_existing()
        if self._immutable_inputs() != inputs or self._store_identity() != identity:
            raise RuntimeError("merchant reopened inputs changed")
        # The ordinary observer can accept immediately. Never feed it the marker
        # or require that the intent is still waiting after readiness.
        self.receipt_recovered = True

    def restart_after_issue(self) -> None:
        """Explicit graceful restart, never provision, rebuild, issue or fund again."""
        if (
            self.restarted
            or self.child is None
            or self.child.poll() is not None
            or self.checkout is None
        ):
            raise RuntimeError("merchant restart baseline refused")
        inputs, baseline = self._immutable_inputs(), self._waiting_state()
        identity = self._store_identity()
        self.stop()
        if self.child.poll() != 0:
            raise RuntimeError("original merchant did not close cleanly")
        if self._store_identity() != identity or self._immutable_inputs() != inputs:
            raise RuntimeError("merchant restart files changed")
        self._serve_existing()
        # Inode continuity alone says nothing about logical contents or WAL state.
        if self._immutable_inputs() != inputs or self._waiting_state() != baseline:
            raise RuntimeError("merchant reopened state changed")
        self.restarted = True

    def request(
        self,
        path: str,
        *,
        body: dict[str, Any] | None = None,
        key: str | None = None,
        status: bool = False,
    ) -> dict[str, Any] | list[Any]:
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        headers = {
            "Authorization": "Bearer " + (self.status_token if status else self.admin)
        }
        if body is not None:
            headers["Content-Type"] = "application/json"
        if key:
            headers["Idempotency-Key"] = key
        try:
            connection.request(
                "POST" if body is not None else "GET",
                path,
                body=None if body is None else json.dumps(body),
                headers=headers,
            )
            response = connection.getresponse()
            data = response.read(32769)
            if response.status not in (200, 201, 202) or len(data) > 32768:
                raise RuntimeError("merchant diagnostic request refused")
            return json.loads(data)
        finally:
            connection.close()

    def issue(self) -> dict[str, Any]:
        created = self.request(
            "/v1/intents",
            body={
                "orderRef": "regtest-rillswap-order",
                "amountMsat": "50000000",
                "expiresAt": int(time.time()) + 7200,
            },
            key="regtest_merchant_intent_01",
        )
        assert isinstance(created, dict)
        self.status_token = created["statusToken"]
        checkout = self.request(
            "/v1/intents/" + created["id"] + "/attempts",
            body={},
            key="regtest_merchant_attempt_01",
        )
        if (
            not isinstance(checkout, dict)
            or checkout["status"] != "waiting"
            or not checkout.get("attempt")
        ):
            raise RuntimeError("merchant invoice unresolved")
        self.checkout = checkout
        return checkout

    def observe_paid(self, timeout: int = 60) -> bool:
        from Cryptodome.Signature import eddsa  # noqa: PLC0415 - diagnostic only

        assert self.checkout is not None
        route = "/v1/intents/" + self.checkout["id"]
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            status = self.request(route, status=True)
            if isinstance(status, dict) and status["status"] == "paid":
                break
            time.sleep(0.2)
        else:
            return False
        if status["attempt"] != self.checkout["attempt"]:
            return False
        events = self.request(route + "/events", status=True)
        if not isinstance(events, list) or len(events) != 1:
            return False
        envelope = events[0]
        if (
            set(envelope) != {"algorithm", "publicKey", "event", "signature"}
            or envelope["algorithm"] != "Ed25519"
            or envelope["publicKey"] != self.public_key
        ):
            return False
        event, terms = envelope["event"], self.checkout["attempt"]["terms"]
        if (
            set(event)
            != {
                "version",
                "id",
                "merchantOrigin",
                "type",
                "intentId",
                "attemptId",
                "paymentHash",
                "amountMsat",
                "acceptedAt",
            }
            or event["version"] != "checkout-event/1"
            or event["type"] != "payment.accepted"
            or any(
                event[name] != terms[name]
                for name in (
                    "merchantOrigin",
                    "intentId",
                    "attemptId",
                    "paymentHash",
                    "amountMsat",
                )
            )
        ):
            return False
        message = [
            "rillswap-payment-event/1",
            event["version"],
            event["id"],
            event["merchantOrigin"],
            event["type"],
            event["intentId"],
            event["attemptId"],
            event["paymentHash"],
            event["amountMsat"],
            event["acceptedAt"],
        ]
        try:
            eddsa.new(
                eddsa.import_public_key(bytes.fromhex(self.public_key)), "rfc8032"
            ).verify(
                json.dumps(message, separators=(",", ":")).encode(),
                bytes.fromhex(envelope["signature"]),
            )
        except (ValueError, TypeError):
            return False
        return self.request(route + "/events", status=True) == events

    def stop(self) -> None:
        if self.child is None:
            return
        if self.child.poll() is None:
            self.child.terminate()
            try:
                self.child.wait(timeout=12)
            except subprocess.TimeoutExpired:
                self.child.kill()
                self.child.wait(timeout=5)
        if self.child.stdout:
            self.child.stdout.close()


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
    profile = "ln-to-btc/v1" if args.ln_to_btc else "btc-to-ln/v1"
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
        # A disposable regtest node: the admin macaroon stands in for each
        # narrower credential, which production operators bake separately.
        "provider_destination_script": json.loads(destination)["scriptPubKey"],
        "authority": {
            "volume_label": "e2e",
            "outside_restore_domain": True,
            "single_host": True,
        },
        "handshake": {
            "profile": profile,
            "encryption_suites": ["noise-xk-secp256k1-chachapoly-sha256/v1"],
            "capabilities": ["core/v1", "recovery/v1"],
        },
        "terms": {
            "profiles": [profile],
            "amount_bands": [[1000, 1_000_000]],
            "base_fee_sat": 50,
            "proportional_millionths": 1000,
            "slot": "e2e",
        },
        "relay_urls": [relay],
    }
    if args.ln_to_btc:
        config["bitcoin_core"]["wallet"] = "provider"
        config["lnd"]["invoices_macaroon"] = "provider-admin.macaroon"
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
    # Cooperative claims and epoch binding are both mandatory; features are sorted.
    required_features = ["cooperative-claim/v1", "epoch-bound-session/v1"]
    assert json.loads(init_bytes)["payload"]["required_features"] == required_features
    assert "cooperative-claim/v1" in terms["required_features"]
    assert admissions == 1
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


def provider_claim(work: Path) -> tuple[str, str]:
    """The provider's recorded claim txid and preimage for the only swap."""
    with sqlite3.connect(
        (work / "provider-store/live.sqlite").as_uri() + "?mode=ro", uri=True
    ) as connection:
        ((claim_txid, preimage),) = connection.execute(
            "SELECT claim_txid, preimage FROM swaps"
        ).fetchall()
    return claim_txid, preimage


def check_claim_witness(
    stack: Stack, claim_txid: str, preimage: str, *, key_path: bool | None
) -> bool:
    """Prove the confirmed claim's spending path from its witness.

    A cooperative key-path claim carries one 64-byte signature and never the
    preimage; the unilateral script path reveals it. ``None`` accepts either
    (a crash-recovered provider loses its original cooperation window).
    """
    tx = json.loads(stack.cli("getrawtransaction", claim_txid, "true"))
    (contract_input,) = tx["vin"]
    witness = contract_input["txinwitness"]
    cooperative = len(witness) == 1 and len(witness[0]) == 128
    if cooperative:
        assert preimage not in "".join(witness), "key-path claim leaked the preimage"
    else:
        assert len(witness) == 4 and witness[1] == preimage, witness
    log(f"claim {claim_txid[:16]} spent the {'key' if cooperative else 'script'} path")
    return key_path is None or cooperative == key_path


def refund_after_unpaid(  # noqa: PLR0913 - explicit scenario inputs
    stack: Stack,
    args: argparse.Namespace,
    work: Path,
    swap: subprocess.CompletedProcess[str],
    config: Path,
    miner: str,
    invoice_state: str,
    stop_mining: threading.Event,
    recovery: Path,
) -> bool:
    """The provider failed after dispatch; the client refunds with fee escalation.

    Takes over block production: the background miner waits for both LND
    nodes per block and gives up after a minute, which a bulk mine past the
    lock height would trip.
    """
    if swap.returncode == 0 or invoice_state == "SETTLED":
        log("swap unexpectedly succeeded")
        return False
    attempt = re.search(r"attempt ([0-9a-f]{64}) revision (\d+)", swap.stderr)
    lock = re.search(r"refund after block (\d+)", swap.stderr)
    if attempt is None or lock is None:
        log("client did not report its funding attempt or refund lock height")
        return False
    deadline = time.monotonic() + 120
    while b"moved to FAILED" not in (work / "provider.log").read_bytes():
        if time.monotonic() > deadline:
            log("provider never recorded the failed payment")
            return False
        time.sleep(2)
    store = sqlite3.connect(
        f"file:{work / 'provider-store' / 'live.sqlite'}?mode=ro", uri=True
    )
    with store:
        reservations = store.execute(
            "SELECT state, release_evidence FROM economic_reservations"
        ).fetchall()
    store.close()
    log(f"provider reservations after failure: {reservations}")
    if not (
        len(reservations) == 1
        and reservations[0][0] == "RELEASED"
        and b'"reason":"failed-after-dispatch"' in reservations[0][1]
    ):
        log("the payer-attested failure did not release the reservation")
        return False
    lock_height = int(lock.group(1))
    stop_mining.set()
    time.sleep(4)  # let the background miner finish its current block
    height = int(stack.cli("getblockcount"))
    if height <= lock_height:
        mine(stack, lock_height + 1 - height, miner)
        wait_synced(stack)
    log(f"past refund lock height {lock_height}; running rill recover watch-refund")
    watch_stdout = (work / "watch.stdout").open("wb")
    watch_stderr = (work / "watch.stderr").open("wb")
    watch = subprocess.Popen(  # noqa: S603
        [
            str(CLI / "rill"),
            "recover",
            "watch-refund",
            "--network",
            str(work / "network.json"),
            "--crypto-library",
            args.crypto_library,
            "--funding-attempt-id",
            attempt.group(1),
            "--binding-revision",
            attempt.group(2),
            "--rpc-cookie",
            str(work / "core.cookie"),
            "--rpc-port",
            str(stack.host_port(stack.core, 18443)),
            "--identity",
            str(work / "user-age.key"),
            # A web payer usually pays someone else's invoice: refund from
            # chain state alone. The CLI run checks its own LND's invoice.
            *(
                ["--chain-only"]
                if args.web
                else [
                    "--lnd-port",
                    str(stack.host_port(stack.lnd["user"], 10009)),
                    "--lnd-tls-cert",
                    str(work / "user-tls.cert"),
                    "--lnd-invoice-macaroon",
                    str(work / "user-admin.macaroon"),
                ]
            ),
            "--intent-dir",
            str(work),
            "--initial-fee-sat",
            "300",
            "--max-fee-sat",
            "3000",
            "--escalate-blocks",
            "3",
            "--poll-seconds",
            "2",
            str(recovery),
        ],
        stdout=watch_stdout,
        stderr=watch_stderr,
    )
    deadline = time.monotonic() + 300
    while watch.poll() is None:  # one block per poll interval so bumps are exercised
        if time.monotonic() > deadline:
            watch.kill()
            log("watch-refund did not finish; see watch.stderr")
            return False
        time.sleep(3)
        mine(stack, 1, miner)
    watch_stdout.close()
    watch_stderr.close()
    sys.stderr.write((work / "watch.stderr").read_text())
    stdout = (work / "watch.stdout").read_text()
    log(f"watch-refund exit {watch.returncode}: {stdout.strip()}")
    if watch.returncode != 0:
        return False
    outcome = json.loads(stdout)
    expected_check = "skipped-chain-only" if args.web else "lnd"
    if outcome.get("invoice_check") != expected_check:
        log(
            f"watch-refund invoice check {outcome.get('invoice_check')} != {expected_check}"
        )
        return False
    if outcome["outcome"] != "refund_confirmed" or not outcome["attempts"]:
        return False
    refund = json.loads(stack.cli("getrawtransaction", outcome["refund_txid"], "true"))
    log(f"refund {outcome['refund_txid'][:16]} confirmations {refund['confirmations']}")
    return int(refund["confirmations"]) >= 1


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


def ln_to_btc(  # noqa: PLR0913 - explicit scenario inputs
    stack: Stack,
    args: argparse.Namespace,
    work: Path,
    relay: str,
    xonly: str,
    user_age: x25519.Identity,
    files: ExitStack,
) -> bool:
    """RS-004: the user pays the hold invoice, claims on chain, the provider settles."""
    payout = 50_000
    log("running rill swap ln-to-btc")
    stdout = files.enter_context((work / "client.stdout").open("wb"))
    stderr = files.enter_context((work / "client.stderr").open("wb"))
    command = [
        str(CLI / "rill"),
        "swap",
        "ln-to-btc",
        "--network",
        str(work / "network.json"),
        "--crypto-library",
        args.crypto_library,
        "--relay",
        relay,
        "--provider",
        xonly,
        "--payout-sat",
        str(payout),
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
    ]
    client = subprocess.Popen(command, stdout=stdout, stderr=stderr)  # noqa: S603
    try:
        code = client.wait(timeout=args.timeout + 120)
    finally:
        if client.poll() is None:
            client.kill()
            client.wait(10)
    out = (work / "client.stdout").read_text()
    sys.stderr.write((work / "client.stderr").read_text())
    log(f"client exit {code}: {out.strip()}")
    claim = re.search(r"claim ([0-9a-f]{64})", out)
    if code != 0 or claim is None:
        return False
    deadline = time.monotonic() + 180
    state = None
    while time.monotonic() < deadline and state != "SETTLED":
        with sqlite3.connect(
            (work / "provider-store/live.sqlite").as_uri() + "?mode=ro", uri=True
        ) as connection:
            (state,) = connection.execute("SELECT state FROM swaps").fetchone()
        time.sleep(2)
    log(f"provider swap {state}")
    if state != "SETTLED":
        return False
    check_ln_to_btc(stack, work, claim.group(1), payout)
    _, preimage = provider_claim(work)
    return check_claim_witness(stack, claim.group(1), preimage, key_path=True)


def check_ln_to_btc(stack: Stack, work: Path, claim_txid: str, payout: int) -> None:
    """The hold settled once, the payment succeeded, and the claim paid the user."""
    with sqlite3.connect(
        (work / "provider-store/live.sqlite").as_uri() + "?mode=ro", uri=True
    ) as connection:
        ((payment_hash, reservation),) = connection.execute(
            "SELECT payment_hash, state FROM economic_reservations"
        ).fetchall()
    assert reservation == "RELEASED"
    hold = stack.lncli("provider", "lookupinvoice", payment_hash)
    assert hold["state"] == "SETTLED"
    (payment,) = stack.lncli("user", "listpayments", "--include_incomplete")["payments"]
    assert payment["payment_hash"] == payment_hash
    assert payment["status"] == "SUCCEEDED"
    deadline = time.monotonic() + 120  # the provider may settle from the mempool
    while (
        json.loads(stack.cli("gettransaction", claim_txid, wallet="user"))[
            "confirmations"
        ]
        < 1
    ):
        assert time.monotonic() < deadline, "the claim did not confirm"
        time.sleep(2)
    received = stack.cli("gettransaction", claim_txid, wallet="user")
    credited = sum(
        round(float(entry["amount"]) * 100_000_000)
        for entry in json.loads(received)["details"]
        if entry["category"] == "receive"
    )
    assert credited >= payout, (credited, payout)  # the claim fee came from the reserve
    log(f"user received {credited} sat on chain; hold {payment_hash[:16]} settled")


def web_client_command(  # noqa: PLR0913 - one explicit command line
    stack: Stack,
    args: argparse.Namespace,
    work: Path,
    relay: str,
    provider: str,
    bolt11: str,
    user_age: x25519.Identity,
) -> list[str]:
    """The rill-web runSwap driver with Core's user wallet as the user's wallet."""
    bun = (
        str(MERCHANT_BUN)
        if getattr(args, "merchant_checkout", False)
        else shutil.which("bun")
    )
    if bun is None:
        raise RuntimeError("--web needs bun on PATH")
    command = [
        bun,
        "run",
        str(ROOT / "rill-web" / "scripts" / "web-swap-e2e.ts"),
        "--relay",
        relay,
        "--provider",
        provider,
        "--network",
        str(work / "network.json"),
        "--invoice",
        bolt11,
        "--core-port",
        str(stack.host_port(stack.core, 18443)),
        "--core-cookie",
        str(work / "core.cookie"),
        "--wallet",
        "user",
        "--recipient",
        str(user_age.to_public()),
        "--out",
        str(work),
        "--settle-timeout",
        str(args.timeout),
    ]
    if getattr(args, "merchant_checkout", False):
        command.extend(["--merchant-checkout", str(work / "merchant/checkout.json")])
    return command


def inspect_web_recovery(args: argparse.Namespace, work: Path) -> bool:
    """rill-cli must accept every browser-written recovery file offline."""
    for stage in ("terms", "funded", "paid"):
        inspected = subprocess.run(  # noqa: S603 - our own console script
            [
                str(CLI / "rill"),
                "recover",
                "inspect",
                "--network",
                str(work / "network.json"),
                "--crypto-library",
                args.crypto_library,
                "--identity",
                str(work / "user-age.key"),
                str(work / f"web-recovery-{stage}.age"),
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        log(f"rill recover inspect ({stage}) exit {inspected.returncode}")
        if inspected.returncode != 0:
            if not getattr(args, "merchant_checkout", False):
                sys.stderr.write(inspected.stderr)
            return False
    return True


def merchant_progress(
    result: subprocess.CompletedProcess[str],
) -> dict[str, str] | None:
    """Validate the entire new-mode public output before the parent reports it."""
    if result.returncode != 0 or result.stderr.strip() or len(result.stdout) > 8192:
        return None
    try:
        value = json.loads(result.stdout)
        if set(value) != {"state", "swapId", "fundingTxid", "recoveryRef"}:
            return None
        if (
            value["state"] != "awaiting_merchant_receipt"
            or value["recoveryRef"] != "web-recovery-paid.age"
        ):
            return None
        if not all(
            isinstance(value[name], str) and re.fullmatch(r"[0-9a-f]{64}", value[name])
            for name in ("swapId", "fundingTxid")
        ):
            return None
    except (ValueError, TypeError, KeyError):
        return None
    return value


def check_merchant_swap_identity(
    work: Path, checkout: dict[str, Any], progress: dict[str, str]
) -> None:
    terms = checkout["attempt"]["terms"]
    checkpoint = json.loads((work / "merchant-checkpoint.json").read_text())
    assert checkpoint["stage"] == "observing" and checkpoint["terms"] == terms
    assert checkpoint["invoice"] == checkout["attempt"]["invoice"]
    assert checkpoint["route"]["swapId"] == progress["swapId"]
    assert checkpoint["route"]["fundingTxid"] == progress["fundingTxid"]
    with sqlite3.connect(
        (work / "provider-store/live.sqlite").as_uri() + "?mode=ro", uri=True
    ) as db:
        ((session, binding),) = db.execute(
            "SELECT session_id, funding_binding FROM swaps"
        ).fetchall()
        assert session == progress["swapId"]
        assert (
            json.loads(binding)["payload"]["binding"]["funding_txid"]
            == progress["fundingTxid"]
        )
        assert db.execute(
            "SELECT session_id, payment_hash FROM payment_dispatch"
        ).fetchall() == [(session, terms["paymentHash"])]
    with sqlite3.connect(
        (work / "merchant/merchant.sqlite").as_uri() + "?mode=ro", uri=True
    ) as db:
        assert db.execute("SELECT id, status FROM intents").fetchall() == [
            (terms["intentId"], "paid")
        ]
        assert db.execute(
            "SELECT id, intent_id, state, invoice, payment_hash FROM attempts"
        ).fetchall() == [
            (
                terms["attemptId"],
                terms["intentId"],
                "ready",
                checkout["attempt"]["invoice"],
                terms["paymentHash"],
            )
        ]
        assert db.execute(
            "SELECT payment_hash, attempt_id FROM receipts"
        ).fetchall() == [(terms["paymentHash"], terms["attemptId"])]
    log(
        "original merchant attempt, single swap dispatch and funding reference verified"
    )


def stop_diagnostic_child(child: subprocess.Popen[bytes] | None) -> None:
    if child is None or child.poll() is not None:
        return
    child.terminate()
    try:
        child.wait(timeout=10)
    except subprocess.TimeoutExpired:
        child.kill()
        child.wait(timeout=5)


def cleanup_merchant_run(  # noqa: PLR0913 - owns the disposable diagnostic's entire teardown
    *,
    stack: Stack,
    stop_mining: threading.Event,
    client: subprocess.Popen[bytes] | None,
    provider: subprocess.Popen[bytes] | None,
    merchant: MerchantDiagnostic | None,
    files: ExitStack,
    relay_stop: threading.Event | None,
    keep: bool,
) -> bool:
    failed = False
    actions = [
        stop_mining.set,
        lambda: stop_diagnostic_child(client),
        lambda: stop_diagnostic_child(provider),
    ]
    if merchant is not None:
        actions.append(merchant.stop)
    actions.append(files.close)
    if relay_stop is not None:
        actions.append(relay_stop.set)
    if not keep:
        actions.append(stack.stop)
    for action in actions:
        try:
            action()
        except Exception:  # noqa: BLE001 - one failure must not skip the other owned resources
            failed = True
    if keep:
        log(f"kept containers labeled {stack.label}")
    if failed:
        log("merchant diagnostic cleanup refused")
    return not failed


def main() -> int:  # noqa: PLR0915 - one ordered scenario
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--crypto-library", required=True)
    parser.add_argument(
        "--keep", action="store_true", help="keep containers for inspection"
    )
    parser.add_argument("--timeout", type=int, default=600, help="whole swap seconds")
    parser.add_argument(
        "--unpaid-refund",
        action="store_true",
        help="the provider fails after dispatch; the client refunds with watch-refund",
    )
    parser.add_argument(
        "--reconcile-after-settle",
        action="store_true",
        help="crash after LND settles, reconcile with read credentials, then resume",
    )
    parser.add_argument(
        "--ln-to-btc",
        action="store_true",
        help="RS-004: pay the provider's hold invoice and claim its on-chain funding",
    )
    parser.add_argument(
        "--web",
        action="store_true",
        help="run the BTC to LN swap with the rill-web browser client (bun)",
    )
    parser.add_argument(
        "--merchant-checkout",
        action="store_true",
        help="explicit disposable web-to-merchant happy-path diagnostic",
    )
    parser.add_argument(
        "--merchant-restart-after-issue",
        action="store_true",
        help="explicit merchant-only graceful restart before payer dispatch",
    )
    parser.add_argument(
        "--merchant-crash-after-settled",
        action="store_true",
        help="explicit settled-observation loss before merchant receipt allocation",
    )
    args = parser.parse_args()
    if args.merchant_crash_after_settled and (
        not args.merchant_checkout or not args.web or args.merchant_restart_after_issue
    ):
        parser.error(
            "--merchant-crash-after-settled requires --web --merchant-checkout without prepayment restart"
        )
    if args.merchant_restart_after_issue and (
        not args.merchant_checkout or not args.web
    ):
        parser.error(
            "--merchant-restart-after-issue requires --web --merchant-checkout"
        )
    if args.merchant_checkout and (
        not args.web
        or args.ln_to_btc
        or args.unpaid_refund
        or args.reconcile_after_settle
    ):
        parser.error("--merchant-checkout requires --web and the happy-path scenario")
    if args.ln_to_btc and (args.unpaid_refund or args.reconcile_after_settle):
        parser.error("--ln-to-btc runs its own scenario")
    if args.web and (args.ln_to_btc or args.reconcile_after_settle):
        parser.error("--web runs the BTC to LN scenario, optionally --unpaid-refund")
    merchant_bun = MERCHANT_BUN
    if args.merchant_checkout:
        try:
            verified = (
                hashlib.sha256(merchant_bun.read_bytes()).hexdigest()
                == "6d5bb405b1d037a2a466b92757de7e47e4369930fa94bd42f8ff44ba49de6c57"
            )
        except OSError:
            verified = False
        if not verified:
            parser.error("verified Bun merchant toolchain required")
    work = ROOT / "tmp" / f"e2e-{time.strftime('%Y%m%dT%H%M%S')}"
    work.mkdir(parents=True, mode=0o700)
    stack = Stack(work)
    stop_mining = threading.Event()
    provider: subprocess.Popen[bytes] | None = None
    client: subprocess.Popen[bytes] | None = None
    merchant: MerchantDiagnostic | None = None
    files = ExitStack()
    relay_stop: threading.Event | None = None
    try:
        log(f"starting containers (run {stack.run_id}, work {work})")
        if args.merchant_checkout:
            stack.start(merchant_mode=True)
        else:
            stack.start()
        stack.cli("createwallet", "miner")
        stack.cli("createwallet", "user")
        if args.ln_to_btc:
            stack.cli("createwallet", "provider")  # funds RS-004 contracts
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
        if args.ln_to_btc:
            stack.cli(
                "sendtoaddress",
                stack.cli("getnewaddress", wallet="provider"),
                "1",
                wallet="miner",
            )
        mine(stack, 6, miner)
        wait_synced(stack)
        # The payer of the swap's Lightning leg opens the channel: the provider
        # for BTC to LN, the user for LN to BTC.
        payer, payee = ("user", "provider") if args.ln_to_btc else ("provider", "user")
        payee_pubkey = stack.lncli(payee, "getinfo")["identity_pubkey"]
        stack.lncli(payer, "connect", f"{payee_pubkey}@{stack.lnd[payee]}:9735")
        stack.lncli(
            payer,
            "openchannel",
            "--node_key",
            payee_pubkey,
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
        log(f"channel open {payer} -> {payee}")

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
        initial_command = provider_command
        if args.reconcile_after_settle:
            initial_command = [
                str(CLI / "python"),
                "-c",
                CRASH_AFTER_SETTLE,
                str(config),
                str(marker),
            ]
        elif args.unpaid_refund:
            initial_command = [str(CLI / "python"), "-c", NEVER_PAY, str(config)]
        provider = subprocess.Popen(  # noqa: S603
            initial_command,
            stdout=provider_log,
            stderr=subprocess.STDOUT,
        )
        time.sleep(3)
        if provider.poll() is not None:
            raise RuntimeError("provider exited; see provider.log")
        log(f"provider {xonly[:16]} serving")

        stack.copy_out(
            stack.lnd["user"], "/root/.lnd/tls.cert", "user-tls.cert", private=False
        )
        if not args.merchant_checkout:
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
        if args.ln_to_btc:
            ok = ln_to_btc(stack, args, work, relay, xonly, user_age, files)
            log("PASS" if ok else f"FAIL (logs in {work})")
            return 0 if ok else 1
        if args.merchant_checkout:
            merchant = MerchantDiagnostic(work, merchant_bun)
            if args.merchant_crash_after_settled:
                merchant.start(stack, crash_after_settled=True)
            else:
                merchant.start(stack)
            checkout = merchant.issue()
            if args.merchant_crash_after_settled:
                merchant.prepare_receipt_loss()
            if args.merchant_restart_after_issue:
                merchant.restart_after_issue()
                log(
                    "original waiting merchant checkout reopened after graceful restart"
                )
            bolt11 = checkout["attempt"]["invoice"]
            payment_hash = checkout["attempt"]["terms"]["paymentHash"]
            private(work / "merchant/checkout.json", json.dumps(checkout))
        else:
            invoice = stack.lncli(
                "user", "addinvoice", "--amt", "50000", "--memo", "rill-e2e"
            )
            bolt11, payment_hash = invoice["payment_request"], invoice["r_hash"]
        log("running " + ("the rill-web client" if args.web else "rill swap btc-to-ln"))
        client_stdout = files.enter_context((work / "client.stdout").open("wb"))
        client_stderr = files.enter_context((work / "client.stderr").open("wb"))
        client = subprocess.Popen(  # noqa: S603
            web_client_command(stack, args, work, relay, xonly, bolt11, user_age)
            if args.web
            else [
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
        if args.merchant_checkout:
            progress = merchant_progress(swap)
            log(
                f"merchant client exit {swap.returncode}, public progress {'valid' if progress else 'refused'}"
            )
            if progress is not None and args.merchant_crash_after_settled:
                merchant.recover_receipt_loss()
                log(
                    "settled observation lost before allocation; original merchant state reopened"
                )
        else:
            sys.stderr.write(swap.stderr)
            log(f"client exit {swap.returncode}: {swap.stdout.strip()}")
        state = stack.lncli("user", "lookupinvoice", payment_hash)["state"]
        log(f"user invoice {state}")
        if args.unpaid_refund:
            ok = refund_after_unpaid(
                stack,
                args,
                work,
                swap,
                config,
                miner,
                state,
                stop_mining,
                work
                / (
                    "web-recovery-funded.age"
                    if args.web
                    else "user-recovery.age.funded"
                ),
            )
            log("PASS" if ok else f"FAIL (logs in {work})")
            return 0 if ok else 1
        deadline = time.monotonic() + 180
        claimed = False
        while time.monotonic() < deadline and not claimed:
            claimed = b"moved to CLAIMED" in (work / "provider.log").read_bytes()
            time.sleep(2)
        log(f"provider claim {'CLAIMED' if claimed else 'NOT confirmed'}")
        ok = swap.returncode == 0 and state == "SETTLED" and claimed
        if ok:
            check_absolute_payment(stack, work)
            claim_txid, preimage = provider_claim(work)
            ok = check_claim_witness(
                stack,
                claim_txid,
                preimage,
                key_path=None if args.reconcile_after_settle else True,
            )
        if ok and args.web:
            ok = inspect_web_recovery(args, work)
        if ok and merchant is not None:
            ok = progress is not None and merchant.observe_paid()
            if ok and (
                args.merchant_restart_after_issue or args.merchant_crash_after_settled
            ):
                check_merchant_swap_identity(work, merchant.checkout, progress)
            if ok and args.merchant_crash_after_settled:
                (invoice,) = stack.lncli("user", "listinvoices")["invoices"]
                original_hash = invoice["r_hash"]
                if not re.fullmatch(r"[0-9a-f]{64}", original_hash):
                    original_hash = base64.b64decode(original_hash, validate=True).hex()
                assert (
                    original_hash
                    == merchant.checkout["attempt"]["terms"]["paymentHash"]
                )
                assert (
                    invoice["payment_request"]
                    == merchant.checkout["attempt"]["invoice"]
                    and invoice["state"] == "SETTLED"
                )
                log("merchant LND inventory contains only the original settled invoice")
            log(f"independent merchant acceptance {'verified' if ok else 'refused'}")
        log("PASS" if ok else f"FAIL (logs in {work})")
        result = 0 if ok else 1
        if not args.merchant_checkout:
            return result
    except Exception:  # noqa: BLE001 - new diagnostic never republishes secret-bearing failures
        if not args.merchant_checkout:
            raise
        log("merchant checkout diagnostic refused")
        result = 1
    finally:
        if args.merchant_checkout:
            if not cleanup_merchant_run(
                stack=stack,
                stop_mining=stop_mining,
                client=client,
                provider=provider,
                merchant=merchant,
                files=files,
                relay_stop=relay_stop,
                keep=args.keep,
            ):
                result = 1
        else:
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
    return result


if __name__ == "__main__":
    os.umask(0o077)
    raise SystemExit(main())
