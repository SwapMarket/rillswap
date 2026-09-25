"""Two opt-in, isolated pinned LND regtest empty-wallet diagnostics.

The original NOT_FOUND/permission diagnostic mines no blocks and creates no
invoices. Its separate OPEN/CANCELED invoice counterpart mines one unspendable
OP_RETURN block and creates one unfunded hold, with no channel or payment.
The third test funds a private channel between two disposable nodes, with no
invoice or payment. All keep credentials in container tmpfs, never host wallets.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import shutil
import subprocess
import time
from decimal import Decimal
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

if TYPE_CHECKING:
    from collections.abc import Sequence

CORE_IMAGE = (
    "docker.io/bitcoin/bitcoin@"
    "sha256:49b55ea5c949a9ceff50786ee678d53f2728a4daa40a8139e3ee20243d24f281"
)
LND_IMAGE = (
    "lightninglabs/lnd@sha256:60fca3f409cf3d500db1d15c9965678a4b5a60758ff30863d52b02529c18be8b"
)
PYTHON_IMAGE = "python@sha256:ce40764625a4ff50df3548277632e7f96c4e77fe75fa848aae9885476e7df5a4"
GENESIS = "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206"
WALLET_PROTO_SHA256 = "2b1810df963e3b50858f9306207a1edf97ff5588ce6dd9afad5ca5e677d5dea6"
STATE_PROTO_SHA256 = "e7c9e1083804c5510874a4e549e3a26864e91892c830921e82d555e469f97242"
ROOT = Path(__file__).parents[1]
CORE = ROOT.parent / "rill-core"
DOCKER = shutil.which("docker")


def _docker(*args: str, timeout: int = 60, check: bool = True) -> str:
    assert DOCKER is not None
    completed = subprocess.run(  # noqa: S603 - fixed Docker executable, isolated test containers
        [DOCKER, *args],
        text=True,
        capture_output=True,
        timeout=timeout,
        check=False,
    )
    if check and completed.returncode:
        # Never echo stderr/stdout from wallet-init or private macaroon operations.
        phases = re.findall(r"^PHASE: ([a-z_]+)$", completed.stderr, re.MULTILINE)
        error_types = re.findall(r"\b([_A-Za-z]+Error):", completed.stderr)
        grpc_codes = re.findall(r"StatusCode\.([A-Z_]+)", completed.stderr)
        diagnostics = re.findall(
            r"^DIAGNOSTIC: (peer_not_ready|insufficient_funds|"
            r"unconfirmed_funds|fee_rejected|payment_failed_[0-9]|"
            r"stream_ended|hash_mismatch|graph_missing|policy_missing|"
            r"route_unavailable|other)$",
            completed.stderr,
            re.MULTILINE,
        )
        phase = phases[-1] if phases else "unidentified"
        category = error_types[-1] if error_types else "unidentified"
        grpc_code = grpc_codes[-1] if grpc_codes else "none"
        diagnostic = diagnostics[-1] if diagnostics else "none"
        raise AssertionError(
            f"disposable LND failed in {phase} "
            f"({category}, grpc={grpc_code}, diagnostic={diagnostic})"
        )
    return completed.stdout.strip() if completed.returncode == 0 else ""


def _core_cli(container: str, *args: str, timeout: int = 5) -> str:
    return _docker(
        "exec",
        "--user",
        "bitcoin:bitcoin",
        container,
        "bitcoin-cli",
        "-regtest",
        "-datadir=/home/bitcoin/.bitcoin",
        "-rpcuser=rill-disposable",
        "-rpcpassword=disposable-regtest-only",
        *args,
        timeout=timeout,
    )


def _wait_for_core(container: str) -> None:
    for _ in range(80):
        try:
            if _core_cli(container, "getblockhash", "0") == GENESIS:
                assert json.loads(_core_cli(container, "getblockchaininfo"))["chain"] == "regtest"
                return
        except AssertionError:
            time.sleep(0.2)
    raise AssertionError("disposable Core failed bounded genesis/readiness check")


def _wait_for_public_certificate(container: str, destination: Path) -> None:
    for _ in range(120):
        # Docker cp cannot see files in the container's tmpfs. Read only the
        # public certificate over Docker exec; the wallet/key remain there.
        pem = _docker("exec", container, "cat", "/root/.lnd/tls.cert", timeout=5, check=False)
        if pem.startswith("-----BEGIN CERTIFICATE-----"):
            fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            with os.fdopen(fd, "wb") as output:
                output.write(pem.encode("ascii") + b"\n")
            return
        time.sleep(0.2)
    raise AssertionError("disposable LND did not generate a TLS certificate")


def _wallet_messages(destination: Path) -> None:
    proto = ROOT / "tests/fixtures/lnd-v0.21.0-beta/walletunlocker.proto"
    if hashlib.sha256(proto.read_bytes()).hexdigest() != WALLET_PROTO_SHA256:
        raise AssertionError("test-only LND wallet bootstrap proto differs from pinned tag")
    destination.mkdir(mode=0o700)
    subprocess.run(  # noqa: S603 - fixed interpreter and pinned local proto file
        [
            str(ROOT / ".venv/bin/python"),
            "-m",
            "grpc_tools.protoc",
            "-I",
            str(ROOT / "proto/lnd-v0.21.0-beta"),
            "-I",
            str(proto.parent),
            f"--python_out={destination}",
            str(proto),
        ],
        capture_output=True,
        check=True,
        timeout=15,
    )
    generated = destination / "walletunlocker_pb2.py"
    content = generated.read_text()
    original = "import lightning_pb2 as lightning__pb2"
    if content.count(original) != 1:
        raise AssertionError("test bootstrap protobuf import changed")
    generated.write_text(
        content.replace(
            original, "from rill_provider._lnd_proto import lightning_pb2 as lightning__pb2"
        )
    )


def _state_messages(destination: Path) -> None:
    """Generate pinned, test-only LND server-readiness messages."""
    proto = ROOT / "tests/fixtures/lnd-v0.21.0-beta/stateservice.proto"
    if hashlib.sha256(proto.read_bytes()).hexdigest() != STATE_PROTO_SHA256:
        raise AssertionError("test-only LND state protobuf differs from pinned tag")
    subprocess.run(  # noqa: S603 - fixed interpreter and pinned local proto file
        [
            str(ROOT / ".venv/bin/python"),
            "-m",
            "grpc_tools.protoc",
            "-I",
            str(proto.parent),
            f"--python_out={destination}",
            str(proto),
        ],
        capture_output=True,
        check=True,
        timeout=15,
    )


def _cleanup_containers(names: tuple[str, ...], run_id: str, cert: Path) -> None:
    """Remove only verified owned containers, attempt every cleanup step."""
    assert DOCKER is not None
    failures: list[str] = []
    for name in names:
        try:
            inspected = subprocess.run(  # noqa: S603 - fixed Docker and explicit test container
                [
                    DOCKER,
                    "inspect",
                    name,
                    "--format",
                    '{{index .Config.Labels "org.rillswap.test-run"}}',
                ],
                text=True,
                capture_output=True,
                timeout=5,
                check=False,
            )
            if inspected.returncode != 0:
                # A failed inspect might mean "not created", or Docker might
                # be unavailable. Confirm absence; never delete on uncertainty.
                listed = subprocess.run(  # noqa: S603 - bounded, exact-name container query
                    [
                        DOCKER,
                        "container",
                        "ls",
                        "--all",
                        "--filter",
                        f"name=^/{name}$",
                        "--format",
                        "{{.ID}}",
                    ],
                    text=True,
                    capture_output=True,
                    timeout=5,
                    check=False,
                )
                if listed.returncode != 0 or listed.stdout.strip():
                    failures.append(f"{name}: inspection unavailable")
                continue
            if inspected.stdout.strip() != run_id:
                failures.append(f"{name}: owner mismatch")
                continue
            removed = subprocess.run(  # noqa: S603 - owner label verified immediately above
                [DOCKER, "rm", "--force", "--volumes", name],
                text=True,
                capture_output=True,
                timeout=30,
                check=False,
            )
            if removed.returncode != 0:
                failures.append(f"{name}: removal failed")
        except (OSError, subprocess.TimeoutExpired):
            failures.append(f"{name}: Docker cleanup timed out or failed")
    try:
        cert.unlink(missing_ok=True)
    except OSError:
        failures.append("public TLS certificate cleanup failed")
    if failures:
        raise AssertionError("disposable LND cleanup incomplete: " + "; ".join(failures))


@pytest.mark.parametrize(
    "scenario",
    [
        (("core",), "none", ("core",), False),
        (("core", "lnd"), "none", ("lnd", "core"), False),
        (("core", "lnd", "sidecar"), "inspection-timeout", ("lnd", "core"), True),
        (("core", "lnd", "sidecar"), "removal-timeout", ("lnd", "core"), True),
        (("core", "lnd", "sidecar"), "owner-mismatch", ("lnd", "core"), True),
        (("core", "lnd"), "inspection-uncertain", ("core",), True),
    ],
)
def test_cleanup_only_removes_verified_owned_containers_and_continues(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    scenario: tuple[tuple[str, ...], str, tuple[str, ...], bool],
) -> None:
    owned, problem, expected_removed, expect_failure = scenario
    monkeypatch.setattr(__import__(__name__), "DOCKER", "docker")
    cert = tmp_path / "tls.cert"
    cert.write_bytes(b"public synthetic certificate")
    removed: list[str] = []
    inspected: list[str] = []

    def fake_run(
        command: Sequence[str],
        **_kwargs: object,
    ) -> subprocess.CompletedProcess[str]:
        action = command[1]
        if action == "inspect":
            name = command[2]
            inspected.append(name)
            if problem == "inspection-timeout" and name == "sidecar":
                raise subprocess.TimeoutExpired(command, 5)
            if problem == "inspection-uncertain" and name == "lnd":
                return subprocess.CompletedProcess(command, 1, "", "daemon error")
            if name not in owned:
                return subprocess.CompletedProcess(command, 1, "", "no such container")
            owner = "someone-else" if problem == "owner-mismatch" and name == "sidecar" else "run"
            return subprocess.CompletedProcess(command, 0, owner + "\n", "")
        if action == "container":
            name = command[5].removeprefix("name=^/").removesuffix("$")
            exists = name in owned
            return subprocess.CompletedProcess(command, 0, "container-id\n" if exists else "", "")
        assert action == "rm"
        name = command[-1]
        if problem == "removal-timeout" and name == "sidecar":
            raise subprocess.TimeoutExpired(command, 30)
        removed.append(name)
        return subprocess.CompletedProcess(command, 0, name, "")

    monkeypatch.setattr(subprocess, "run", fake_run)
    if expect_failure:
        with pytest.raises(AssertionError, match="cleanup incomplete"):
            _cleanup_containers(("sidecar", "lnd", "core"), "run", cert)
    else:
        _cleanup_containers(("sidecar", "lnd", "core"), "run", cert)
    assert tuple(removed) == expected_removed
    assert inspected == ["sidecar", "lnd", "core"]
    assert not cert.exists()


BOOTSTRAP = """
import json, os, secrets, sys, time
from pathlib import Path
import grpc
from rill_core.wire.types import NetworkIdentity
from rill_provider._lnd_proto import lightning_pb2
from rill_provider._lnd_proto.invoicesrpc import invoices_pb2
from rill_provider._lnd_proto.routerrpc import router_pb2
from rill_provider.lnd_invoice_observation import RegtestLndInvoiceObserver
from rill_provider.lnd_payment_observation import (
    RegtestLndInfoObserver, RegtestLndPaymentObserver, LndUnavailableError,
)
import walletunlocker_pb2 as unlock

print('PHASE: certificate', file=sys.stderr)
cert = Path('/work/public/tls.cert').read_bytes()
creds = grpc.ssl_channel_credentials(root_certificates=cert)
def unary(channel, path, request_type, response_type):
    return channel.unary_unary(path, request_serializer=request_type.SerializeToString,
                               response_deserializer=response_type.FromString)
def metadata(mac):
    return (('macaroon', mac.hex()),)
channel = grpc.secure_channel('127.0.0.1:10009', creds)
print('PHASE: seed', file=sys.stderr)
gen = unary(channel, '/lnrpc.WalletUnlocker/GenSeed', unlock.GenSeedRequest, unlock.GenSeedResponse)
seed = gen(unlock.GenSeedRequest(), timeout=10)
assert len(seed.cipher_seed_mnemonic) == 24
init = unary(channel, '/lnrpc.WalletUnlocker/InitWallet',
             unlock.InitWalletRequest, unlock.InitWalletResponse)
print('PHASE: wallet_init', file=sys.stderr)
initialized = init(unlock.InitWalletRequest(wallet_password=secrets.token_bytes(24),
                   cipher_seed_mnemonic=seed.cipher_seed_mnemonic, recovery_window=0,
                   stateless_init=True), timeout=20)
admin = initialized.admin_macaroon
assert admin and len(admin) < 4096
channel.close()
channel = grpc.secure_channel('127.0.0.1:10009', creds)
info = unary(channel, '/lnrpc.Lightning/GetInfo',
             lightning_pb2.GetInfoRequest, lightning_pb2.GetInfoResponse)
balance = unary(channel, '/lnrpc.Lightning/WalletBalance', lightning_pb2.WalletBalanceRequest,
                lightning_pb2.WalletBalanceResponse)
last_error = None
print('PHASE: readiness', file=sys.stderr)
for _ in range(80):
    try:
        identity = info(lightning_pb2.GetInfoRequest(), metadata=metadata(admin), timeout=1)
        break
    except grpc.RpcError:
        time.sleep(0.2)
else:
    raise AssertionError('pinned LND did not become ready without mining')
assert len(identity.chains) == 1
assert identity.chains[0].chain == 'bitcoin' and identity.chains[0].network == 'regtest'
assert identity.block_height == 0
wallet = balance(lightning_pb2.WalletBalanceRequest(), metadata=metadata(admin), timeout=3)
print('PHASE: bake', file=sys.stderr)
assert wallet.total_balance == wallet.confirmed_balance == wallet.unconfirmed_balance == 0
bake = unary(channel, '/lnrpc.Lightning/BakeMacaroon', lightning_pb2.BakeMacaroonRequest,
             lightning_pb2.BakeMacaroonResponse)
baked = bake(lightning_pb2.BakeMacaroonRequest(
    permissions=[lightning_pb2.MacaroonPermission(entity='offchain', action='read')],
    root_key_id=0, allow_external_permissions=False), metadata=metadata(admin), timeout=3)
restricted = bytes.fromhex(baked.macaroon)
assert 0 < len(restricted) <= 4096
info_baked = bake(lightning_pb2.BakeMacaroonRequest(
    permissions=[lightning_pb2.MacaroonPermission(entity='info', action='read')],
    root_key_id=0, allow_external_permissions=False), metadata=metadata(admin), timeout=3)
info_restricted = bytes.fromhex(info_baked.macaroon)
assert 0 < len(info_restricted) <= 4096
invoice_baked = bake(lightning_pb2.BakeMacaroonRequest(
    permissions=[lightning_pb2.MacaroonPermission(entity='invoices', action='read')],
    root_key_id=0, allow_external_permissions=False), metadata=metadata(admin), timeout=3)
invoice_restricted = bytes.fromhex(invoice_baked.macaroon)
assert 0 < len(invoice_restricted) <= 4096
admin = b''
print('PHASE: restricted_info', file=sys.stderr)
try:
    info(lightning_pb2.GetInfoRequest(), metadata=metadata(restricted), timeout=3)
except grpc.RpcError as error:
    # Pinned LND returns UNKNOWN with a plain permission-denied error for a
    # well-formed macaroon lacking info:read (not UNAUTHENTICATED).
    assert error.code() == grpc.StatusCode.UNKNOWN
    assert 'permission denied' in (error.details() or '').lower()
else:
    raise AssertionError('restricted macaroon unexpectedly permits info:read')
raw_track = channel.unary_stream('/routerrpc.Router/TrackPaymentV2',
    request_serializer=router_pb2.TrackPaymentRequest.SerializeToString,
    response_deserializer=lightning_pb2.Payment.FromString)
payment_hash = bytes.fromhex('00' * 31 + '01')
print('PHASE: invoices_only', file=sys.stderr)
lookup = unary(channel, '/lnrpc.Lightning/LookupInvoice',
    lightning_pb2.PaymentHash, lightning_pb2.Invoice)
try:
    lookup(lightning_pb2.PaymentHash(r_hash=payment_hash),
        metadata=metadata(invoice_restricted), timeout=3)
except grpc.RpcError as error:
    assert error.code() == grpc.StatusCode.NOT_FOUND
else:
    raise AssertionError('missing invoice must not be reported as observed')
add_hold = unary(channel, '/invoicesrpc.Invoices/AddHoldInvoice',
    invoices_pb2.AddHoldInvoiceRequest, invoices_pb2.AddHoldInvoiceResp)
try:
    add_hold(invoices_pb2.AddHoldInvoiceRequest(hash=payment_hash, value_msat=1000),
        metadata=metadata(invoice_restricted), timeout=3)
except grpc.RpcError as error:
    assert error.code() == grpc.StatusCode.UNKNOWN
    assert 'permission denied' in (error.details() or '').lower()
else:
    raise AssertionError('invoices:read must not create a hold invoice')
invoice_private = Path('/tmp/rill-invoice-only.macaroon')
fd = os.open(invoice_private, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
with os.fdopen(fd, 'wb') as output:
    output.write(invoice_restricted)
selected_network = NetworkIdentity.model_validate(json.loads(
    Path('/work/provider/tests/fixtures/initial-btc-to-ln-v1.json').read_text()
)['contract_terms']['network_identity'])
invoice_observer = RegtestLndInvoiceObserver(host='127.0.0.1', port=10009,
    tls_certificate_path='/work/public/tls.cert', invoice_macaroon_path=invoice_private,
    network=selected_network)
try:
    invoice_observer.lookup(payment_hash, deadline_seconds=3)
except LndUnavailableError as error:
    assert str(error) == 'LND invoice lookup unavailable; no absence claim'
    assert error.__context__ is None and error.__cause__ is None
else:
    raise AssertionError('missing invoice never provides usable hold evidence')
invoice_private.unlink()
print('PHASE: info_only', file=sys.stderr)
reported = info(lightning_pb2.GetInfoRequest(), metadata=metadata(info_restricted), timeout=3)
assert reported.identity_pubkey == identity.identity_pubkey
try:
    next(iter(raw_track(router_pb2.TrackPaymentRequest(payment_hash=payment_hash),
        metadata=metadata(info_restricted), timeout=3)))
except grpc.RpcError as error:
    assert error.code() == grpc.StatusCode.UNKNOWN
    assert 'permission denied' in (error.details() or '').lower()
else:
    raise AssertionError('info:read must not authorize payment tracking')
info_private = Path('/tmp/rill-info-only.macaroon')
fd = os.open(info_private, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
with os.fdopen(fd, 'wb') as output:
    output.write(info_restricted)
info_observer = RegtestLndInfoObserver(host='127.0.0.1', port=10009,
    tls_certificate_path='/work/public/tls.cert', info_macaroon_path=info_private,
    network=NetworkIdentity.model_validate(json.loads(
        Path('/work/provider/tests/fixtures/initial-btc-to-ln-v1.json').read_text()
    )['contract_terms']['network_identity']), expected_node_pubkey=identity.identity_pubkey)
snapshot = info_observer.get_info(deadline_seconds=3)
assert snapshot.node_pubkey == identity.identity_pubkey
assert snapshot.block_height == 0
assert isinstance(snapshot.synced_to_chain, bool) and isinstance(snapshot.synced_to_graph, bool)
info_private.unlink()
print('PHASE: raw_track', file=sys.stderr)
try:
    next(iter(raw_track(router_pb2.TrackPaymentRequest(payment_hash=payment_hash),
        metadata=metadata(restricted), timeout=3)))
except grpc.RpcError as error:
    assert error.code() == grpc.StatusCode.NOT_FOUND
else:
    raise AssertionError('pinned LND absent-hash RPC was not NOT_FOUND')
private = Path('/tmp/rill-observer.macaroon')
fd = os.open(private, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
with os.fdopen(fd, 'wb') as output:
    output.write(restricted)
network = NetworkIdentity.model_validate(json.loads(
    Path('/work/provider/tests/fixtures/initial-btc-to-ln-v1.json').read_text()
)['contract_terms']['network_identity'])
observer = RegtestLndPaymentObserver(host='127.0.0.1', port=10009,
    tls_certificate_path='/work/public/tls.cert', read_macaroon_path=private, network=network)
try:
    print('PHASE: observer_track', file=sys.stderr)
    observer.track(payment_hash, deadline_seconds=3)
except LndUnavailableError as error:
    assert str(error) == 'LND tracking unavailable; no absence claim'
    assert error.__cause__ is None and error.__context__ is None
else:
    raise AssertionError('unknown payment must never be a successful observation')
malformed = b'not-an-authorized-macaroon'
print('PHASE: malformed_raw', file=sys.stderr)
try:
    next(iter(raw_track(router_pb2.TrackPaymentRequest(payment_hash=payment_hash),
        metadata=metadata(malformed), timeout=3)))
except grpc.RpcError as error:
    assert error.code() == grpc.StatusCode.UNKNOWN
else:
    raise AssertionError('malformed macaroon must not reach payment tracking')
private.write_bytes(malformed)
print('PHASE: invalid_macaroon', file=sys.stderr)
# Pinned LND reports malformed-macaroon errors as gRPC UNKNOWN. The observer
# leaves that failure unclassified: no payment evidence or upstream error echo.
try:
    observer.track(payment_hash, deadline_seconds=3)
except LndUnavailableError as error:
    assert str(error) == 'LND tracking unavailable; no absence claim'
    assert error.__cause__ is None and error.__context__ is None
else:
    raise AssertionError('invalid-macaroon observation must fail without absence evidence')
private.unlink()
channel.close()
print('Pinned LND read-only NOT_FOUND and restricted macaroon checks passed')
"""


@pytest.mark.lnd
@pytest.mark.skipif(
    os.environ.get("RILLSWAP_RUN_LND") != "1",
    reason="set RILLSWAP_RUN_LND=1 for pinned disposable LND",
)
def test_pinned_lnd_restricted_read_diagnostic(tmp_path: Path) -> None:
    assert DOCKER is not None
    base = tmp_path / "public"
    base.mkdir(mode=0o700)
    generated = tmp_path / "generated"
    _wallet_messages(generated)
    run_id = secrets.token_hex(16)
    label = f"org.rillswap.test-run={run_id}"
    core = f"rillswap-lnd-core-{secrets.token_hex(6)}"
    lnd = f"rillswap-lnd-read-{secrets.token_hex(6)}"
    sidecar = f"rillswap-lnd-client-{secrets.token_hex(6)}"
    cert = base / "tls.cert"
    try:
        _docker(
            "run",
            "--detach",
            "--name",
            core,
            "--label",
            label,
            "--platform",
            "linux/amd64",
            "--network",
            "none",
            "--tmpfs",
            "/home/bitcoin/.bitcoin:rw,uid=101,gid=101,mode=0700",
            CORE_IMAGE,
            "-regtest=1",
            "-server=1",
            "-listen=0",
            "-discover=0",
            "-dnsseed=0",
            "-rpcuser=rill-disposable",
            "-rpcpassword=disposable-regtest-only",
            "-rpcbind=127.0.0.1",
            "-rpcallowip=127.0.0.1",
            "-zmqpubrawblock=tcp://127.0.0.1:28332",
            "-zmqpubrawtx=tcp://127.0.0.1:28333",
            "-printtoconsole=1",
        )
        _wait_for_core(core)
        _docker(
            "run",
            "--detach",
            "--name",
            lnd,
            "--label",
            label,
            "--platform",
            "linux/amd64",
            "--network",
            f"container:{core}",
            "--tmpfs",
            "/root/.lnd:rw,mode=0700",
            LND_IMAGE,
            "--bitcoin.active",
            "--bitcoin.regtest",
            "--bitcoin.node=bitcoind",
            "--bitcoind.rpchost=127.0.0.1:18443",
            "--bitcoind.rpcuser=rill-disposable",
            "--bitcoind.rpcpass=disposable-regtest-only",
            "--bitcoind.zmqpubrawblock=tcp://127.0.0.1:28332",
            "--bitcoind.zmqpubrawtx=tcp://127.0.0.1:28333",
            "--rpclisten=127.0.0.1:10009",
            "--nolisten",
            "--nobootstrap",
        )
        for container, path in ((core, "/home/bitcoin/.bitcoin"), (lnd, "/root/.lnd")):
            tmpfs = json.loads(
                _docker("inspect", container, "--format", "{{json .HostConfig.Tmpfs}}")
            )
            assert path in tmpfs
            mounts = json.loads(_docker("inspect", container, "--format", "{{json .Mounts}}"))
            assert all(entry["Type"] != "volume" for entry in mounts)
        _wait_for_public_certificate(lnd, cert)
        result = _docker(
            "run",
            "--rm",
            "--name",
            sidecar,
            "--label",
            label,
            "--platform",
            "linux/amd64",
            "--network",
            f"container:{core}",
            "--tmpfs",
            "/tmp:rw,mode=0700,noexec,nosuid,nodev",  # noqa: S108 - isolated container tmpfs
            "--mount",
            f"type=bind,src={ROOT},dst=/work/provider,readonly",
            "--mount",
            f"type=bind,src={CORE},dst=/work/core,readonly",
            "--mount",
            f"type=bind,src={base},dst=/work/public,readonly",
            "--mount",
            f"type=bind,src={generated},dst=/work/generated,readonly",
            "--env",
            "PYTHONPATH=/work/provider/.venv/lib/python3.14/site-packages:"
            "/work/provider/src:/work/core/packages/core/src:/work/generated",
            PYTHON_IMAGE,
            "python",
            "-c",
            BOOTSTRAP,
            timeout=100,
        )
        assert result == "Pinned LND read-only NOT_FOUND and restricted macaroon checks passed"
    finally:
        _cleanup_containers((sidecar, lnd, core), run_id, cert)


# Separate from the empty-wallet/no-invoice diagnostic above. A GetInfo reply
# can precede invoice-registry startup; this script waits for SERVER_ACTIVE
# before its one create attempt. It never retries an ambiguous create result.
OPEN_INVOICE = """
import json, os, secrets, sys, time
from pathlib import Path
import grpc
from rill_core.wire.types import NetworkIdentity
from rill_provider._lnd_proto import lightning_pb2
from rill_provider._lnd_proto.invoicesrpc import invoices_pb2
from rill_provider.lnd_invoice_observation import RegtestLndInvoiceObserver
import walletunlocker_pb2 as unlock
import stateservice_pb2 as state

cert = Path('/work/public/tls.cert').read_bytes()
def unary(channel, method, request, response):
    return channel.unary_unary(method, request_serializer=request.SerializeToString,
                               response_deserializer=response.FromString)
def metadata(mac):
    return (('macaroon', mac.hex()),)
channel = grpc.secure_channel('127.0.0.1:10009',
    grpc.ssl_channel_credentials(root_certificates=cert))
print('PHASE: open_seed', file=sys.stderr)
seed = unary(channel, '/lnrpc.WalletUnlocker/GenSeed',
    unlock.GenSeedRequest, unlock.GenSeedResponse)(unlock.GenSeedRequest(), timeout=10)
admin = unary(channel, '/lnrpc.WalletUnlocker/InitWallet',
    unlock.InitWalletRequest, unlock.InitWalletResponse)(unlock.InitWalletRequest(
    wallet_password=secrets.token_bytes(24), cipher_seed_mnemonic=seed.cipher_seed_mnemonic,
    recovery_window=0, stateless_init=True), timeout=20).admin_macaroon
assert admin
channel.close()
channel = grpc.secure_channel('127.0.0.1:10009',
    grpc.ssl_channel_credentials(root_certificates=cert))
info = unary(channel, '/lnrpc.Lightning/GetInfo',
    lightning_pb2.GetInfoRequest, lightning_pb2.GetInfoResponse)
readiness = unary(channel, '/lnrpc.State/GetState',
    state.GetStateRequest, state.GetStateResponse)
print('PHASE: open_ready', file=sys.stderr)
for _ in range(100):
    try:
        status = readiness(state.GetStateRequest(), metadata=metadata(admin), timeout=1)
        if status.state == state.SERVER_ACTIVE:
            break
    except grpc.RpcError:
        pass
    time.sleep(0.2)
else:
    raise AssertionError('LND invoice registry readiness not established')
reported = info(lightning_pb2.GetInfoRequest(), metadata=metadata(admin), timeout=3)
assert len(reported.chains) == 1
assert reported.chains[0].chain == 'bitcoin' and reported.chains[0].network == 'regtest'
assert reported.block_height == 1
assert reported.synced_to_chain
print('PHASE: open_bake', file=sys.stderr)
bake = unary(channel, '/lnrpc.Lightning/BakeMacaroon',
    lightning_pb2.BakeMacaroonRequest, lightning_pb2.BakeMacaroonResponse)
read = bytes.fromhex(bake(lightning_pb2.BakeMacaroonRequest(
    permissions=[lightning_pb2.MacaroonPermission(entity='invoices', action='read')],
    root_key_id=0, allow_external_permissions=False),
    metadata=metadata(admin), timeout=3).macaroon)
assert 0 < len(read) <= 4096
private = Path('/tmp/rill-positive-invoice.macaroon')
fd = os.open(private, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
with os.fdopen(fd, 'wb') as output:
    output.write(read)
network = NetworkIdentity.model_validate(json.loads(
    Path('/work/provider/tests/fixtures/initial-btc-to-ln-v1.json').read_text()
)['contract_terms']['network_identity'])
observer = RegtestLndInvoiceObserver(host='127.0.0.1', port=10009,
    tls_certificate_path='/work/public/tls.cert', invoice_macaroon_path=private,
    network=network)
selected = secrets.token_bytes(32)
print('PHASE: open_add_once', file=sys.stderr)
add = unary(channel, '/invoicesrpc.Invoices/AddHoldInvoice',
    invoices_pb2.AddHoldInvoiceRequest, invoices_pb2.AddHoldInvoiceResp)
result = add(invoices_pb2.AddHoldInvoiceRequest(hash=selected, value_msat=1000),
    metadata=metadata(admin), timeout=20)
assert result.payment_request
cancel = unary(channel, '/invoicesrpc.Invoices/CancelInvoice',
    invoices_pb2.CancelInvoiceMsg, invoices_pb2.CancelInvoiceResp)
try:
    print('PHASE: open_read', file=sys.stderr)
    opened = observer.lookup(selected, deadline_seconds=5)
    assert opened.payment_hash == selected.hex()
    assert opened.state == 'OPEN' and opened.htlcs == ()
    assert opened.value_msat == 1000 and opened.amount_paid_msat == 0
finally:
    print('PHASE: open_cancel', file=sys.stderr)
    cancel(invoices_pb2.CancelInvoiceMsg(payment_hash=selected),
        metadata=metadata(admin), timeout=5)
closed = observer.lookup(selected, deadline_seconds=5)
assert closed.state == 'CANCELED' and closed.htlcs == ()
assert closed.payment_hash == selected.hex()
private.unlink()
channel.close()
print('Pinned LND unfunded invoice OPEN and CANCELED observations passed')
"""


@pytest.mark.lnd
@pytest.mark.skipif(
    os.environ.get("RILLSWAP_RUN_LND") != "1",
    reason="set RILLSWAP_RUN_LND=1 for pinned disposable LND",
)
def test_pinned_lnd_unfunded_invoice_observation(tmp_path: Path) -> None:
    """Real OPEN/CANCELED serialization with no funding, channel, or HTLC."""
    assert DOCKER is not None
    public = tmp_path / "public"
    public.mkdir(mode=0o700)
    generated = tmp_path / "generated"
    _wallet_messages(generated)
    _state_messages(generated)
    run_id = secrets.token_hex(16)
    label = f"org.rillswap.test-run={run_id}"
    core = f"rillswap-invoice-core-{secrets.token_hex(6)}"
    lnd = f"rillswap-invoice-lnd-{secrets.token_hex(6)}"
    sidecar = f"rillswap-invoice-client-{secrets.token_hex(6)}"
    cert = public / "tls.cert"
    try:
        _docker(
            "run",
            "--detach",
            "--name",
            core,
            "--label",
            label,
            "--platform",
            "linux/amd64",
            "--network",
            "none",
            "--tmpfs",
            "/home/bitcoin/.bitcoin:rw,uid=101,gid=101,mode=0700",
            CORE_IMAGE,
            "-regtest=1",
            "-server=1",
            "-listen=0",
            "-discover=0",
            "-dnsseed=0",
            "-rpcuser=rill-disposable",
            "-rpcpassword=disposable-regtest-only",
            "-rpcbind=127.0.0.1",
            "-rpcallowip=127.0.0.1",
            "-zmqpubrawblock=tcp://127.0.0.1:28332",
            "-zmqpubrawtx=tcp://127.0.0.1:28333",
            "-printtoconsole=1",
        )
        _wait_for_core(core)
        before = json.loads(_core_cli(core, "getblockchaininfo"))
        assert before["chain"] == "regtest"
        assert before["blocks"] == before["headers"] == 0
        mined = json.loads(_core_cli(core, "generatetodescriptor", "1", "raw(6a)"))
        assert len(mined) == 1
        after = json.loads(_core_cli(core, "getblockchaininfo"))
        assert after["chain"] == "regtest"
        assert after["blocks"] == after["headers"] == 1
        assert after["initialblockdownload"] is False
        tip = json.loads(_core_cli(core, "getblockheader", mined[0]))
        assert tip["height"] == 1
        assert abs(time.time() - tip["time"]) < 60
        _docker(
            "run",
            "--detach",
            "--name",
            lnd,
            "--label",
            label,
            "--platform",
            "linux/amd64",
            "--network",
            f"container:{core}",
            "--tmpfs",
            "/root/.lnd:rw,mode=0700",
            LND_IMAGE,
            "--bitcoin.active",
            "--bitcoin.regtest",
            "--bitcoin.node=bitcoind",
            "--bitcoind.rpchost=127.0.0.1:18443",
            "--bitcoind.rpcuser=rill-disposable",
            "--bitcoind.rpcpass=disposable-regtest-only",
            "--bitcoind.zmqpubrawblock=tcp://127.0.0.1:28332",
            "--bitcoind.zmqpubrawtx=tcp://127.0.0.1:28333",
            "--rpclisten=127.0.0.1:10009",
            "--nolisten",
            "--nobootstrap",
        )
        for container, path in ((core, "/home/bitcoin/.bitcoin"), (lnd, "/root/.lnd")):
            tmpfs = json.loads(
                _docker("inspect", container, "--format", "{{json .HostConfig.Tmpfs}}")
            )
            assert path in tmpfs
            mounts = json.loads(_docker("inspect", container, "--format", "{{json .Mounts}}"))
            assert all(entry["Type"] != "volume" for entry in mounts)
        _wait_for_public_certificate(lnd, cert)
        result = _docker(
            "run",
            "--rm",
            "--name",
            sidecar,
            "--label",
            label,
            "--platform",
            "linux/amd64",
            "--network",
            f"container:{core}",
            "--tmpfs",
            "/tmp:rw,mode=0700,noexec,nosuid,nodev",  # noqa: S108 - test tmpfs
            "--mount",
            f"type=bind,src={ROOT},dst=/work/provider,readonly",
            "--mount",
            f"type=bind,src={CORE},dst=/work/core,readonly",
            "--mount",
            f"type=bind,src={public},dst=/work/public,readonly",
            "--mount",
            f"type=bind,src={generated},dst=/work/generated,readonly",
            "--env",
            "PYTHONPATH=/work/provider/.venv/lib/python3.14/site-packages:"
            "/work/provider/src:/work/core/packages/core/src:/work/generated",
            PYTHON_IMAGE,
            "python",
            "-c",
            OPEN_INVOICE,
            timeout=105,
        )
        assert result == "Pinned LND unfunded invoice OPEN and CANCELED observations passed"
    finally:
        _cleanup_containers((sidecar, lnd, core), run_id, cert)


# Shared test-only channel fixture. Each scenario gets fresh isolated wallets;
# no mutation is retried after an ambiguous response.
CHANNEL_SETUP = """
import hashlib, json, os, secrets, sys, tempfile, time
from decimal import Decimal
from pathlib import Path
import grpc
import httpx
from rill_core.wire.types import NetworkIdentity
from rill_provider._lnd_proto import lightning_pb2 as ln
from rill_provider._lnd_proto.invoicesrpc import invoices_pb2 as inv
from rill_provider._lnd_proto.routerrpc import router_pb2 as router
from rill_provider.lnd_invoice_observation import RegtestLndInvoiceObserver
from rill_provider.lnd_payment_observation import LndProtocolError, RegtestLndPaymentObserver
import walletunlocker_pb2 as unlock
import stateservice_pb2 as state

def unary(channel, path, request, response):
    return channel.unary_unary(path, request_serializer=request.SerializeToString,
                               response_deserializer=response.FromString)
def metadata(secret):
    return (('macaroon', secret.hex()),)
def dial(cert, port):
    return grpc.secure_channel('127.0.0.1:' + str(port),
        grpc.ssl_channel_credentials(root_certificates=cert))
def ready(channel, secret):
    rpc = unary(channel, '/lnrpc.State/GetState', state.GetStateRequest, state.GetStateResponse)
    for _ in range(100):
        try:
            status = rpc(state.GetStateRequest(), metadata=metadata(secret), timeout=1)
            if status.state == state.SERVER_ACTIVE:
                return
        except grpc.RpcError:
            pass
        time.sleep(0.2)
    raise AssertionError('pinned LND did not reach SERVER_ACTIVE')
def call(channel, secret, name, req, resp, value, *, timeout=5):
    return unary(channel, '/lnrpc.Lightning/' + name, req, resp)(
        value, metadata=metadata(secret), timeout=timeout)

nodes = {}
print('PHASE: channel_wallets', file=sys.stderr)
for label, port in (('a', 10009), ('b', 10010)):
    cert = Path('/work/public/' + label + '.cert').read_bytes()
    channel = dial(cert, port)
    seed = unary(channel, '/lnrpc.WalletUnlocker/GenSeed',
        unlock.GenSeedRequest, unlock.GenSeedResponse)(unlock.GenSeedRequest(), timeout=10)
    initiated = unary(channel, '/lnrpc.WalletUnlocker/InitWallet',
        unlock.InitWalletRequest, unlock.InitWalletResponse)(unlock.InitWalletRequest(
        wallet_password=secrets.token_bytes(24), cipher_seed_mnemonic=seed.cipher_seed_mnemonic,
        recovery_window=0, stateless_init=True), timeout=20)
    assert initiated.admin_macaroon
    channel.close()
    channel = dial(cert, port)
    ready(channel, initiated.admin_macaroon)
    info = call(channel, initiated.admin_macaroon, 'GetInfo',
        ln.GetInfoRequest, ln.GetInfoResponse, ln.GetInfoRequest())
    assert len(info.chains) == 1
    assert info.chains[0].chain == 'bitcoin' and info.chains[0].network == 'regtest'
    assert info.block_height == 101 and info.synced_to_chain
    nodes[label] = (channel, initiated.admin_macaroon, info.identity_pubkey)
assert nodes['a'][2] != nodes['b'][2]
a, a_secret, a_key = nodes['a']
b, b_secret, b_key = nodes['b']

print('PHASE: channel_receive', file=sys.stderr)
address = call(a, a_secret, 'NewAddress', ln.NewAddressRequest, ln.NewAddressResponse,
    ln.NewAddressRequest(type=ln.WITNESS_PUBKEY_HASH)).address
assert address.startswith('bcrt1')
with httpx.Client(base_url='http://127.0.0.1:18443',
    auth=httpx.BasicAuth('rill-disposable', 'disposable-regtest-only'),
    timeout=httpx.Timeout(30, connect=3), trust_env=False, follow_redirects=False) as core:
    def rpc(method, params, *, wallet=None):
        path = '/wallet/' + wallet if wallet else '/'
        response = core.post(path,
            json={'jsonrpc':'1.0','id':'test','method':method,'params':params})
        response.raise_for_status()
        body = response.json(parse_float=Decimal)
        assert body['error'] is None
        return body['result']
    print('PHASE: channel_fund_once', file=sys.stderr)
    mining_address = rpc('getnewaddress', ['', 'bech32m'], wallet='fund')
    rpc('sendtoaddress', [address, 0.02], wallet='fund')
    blocks = rpc('generatetoaddress', [1, mining_address], wallet='fund')
    assert len(blocks) == 1
    print('PHASE: channel_wallet_balance', file=sys.stderr)
    for _ in range(100):
        info = call(a, a_secret, 'GetInfo', ln.GetInfoRequest, ln.GetInfoResponse,
            ln.GetInfoRequest())
        balance = call(a, a_secret, 'WalletBalance', ln.WalletBalanceRequest,
            ln.WalletBalanceResponse, ln.WalletBalanceRequest())
        if (info.block_height == 102 and info.synced_to_chain
                and balance.confirmed_balance >= 2000000):
            break
        time.sleep(0.2)
    else:
        raise AssertionError('fresh wallet deposit not confirmed')
    print('PHASE: channel_connect_once', file=sys.stderr)
    call(a, a_secret, 'ConnectPeer', ln.ConnectPeerRequest, ln.ConnectPeerResponse,
        ln.ConnectPeerRequest(addr=ln.LightningAddress(pubkey=b_key, host='127.0.0.1:9736'),
                              perm=False, timeout=10), timeout=12)
    for _ in range(100):
        peers_a = call(a, a_secret, 'ListPeers', ln.ListPeersRequest, ln.ListPeersResponse,
            ln.ListPeersRequest())
        peers_b = call(b, b_secret, 'ListPeers', ln.ListPeersRequest, ln.ListPeersResponse,
            ln.ListPeersRequest())
        if (any(peer.pub_key == b_key for peer in peers_a.peers)
                and any(peer.pub_key == a_key for peer in peers_b.peers)):
            break
        time.sleep(0.2)
    else:
        raise AssertionError('two-node peer connection not independently visible')
    print('PHASE: channel_open_once', file=sys.stderr)
    try:
        point = call(a, a_secret, 'OpenChannelSync', ln.OpenChannelRequest, ln.ChannelPoint,
            ln.OpenChannelRequest(node_pubkey=bytes.fromhex(b_key), local_funding_amount=1000000,
                push_sat=0, private=True, min_confs=1, sat_per_vbyte=2), timeout=30)
    except grpc.RpcError as error:
        detail = (error.details() or '').lower()
        if 'peer' in detail and ('not' in detail or 'connect' in detail):
            category = 'peer_not_ready'
        elif 'insufficient' in detail or 'not enough' in detail:
            category = 'insufficient_funds'
        elif 'unconfirmed' in detail or 'confirmations' in detail:
            category = 'unconfirmed_funds'
        elif 'fee' in detail:
            category = 'fee_rejected'
        else:
            category = 'other'
        print('DIAGNOSTIC: ' + category, file=sys.stderr)
        raise RuntimeError('one-shot channel open response uncertain') from None
    txid = point.funding_txid_str if point.WhichOneof('funding_txid') == 'funding_txid_str' \
        else point.funding_txid_bytes[::-1].hex()
    assert len(txid) == 64
    assert len(rpc('generatetoaddress', [1, mining_address], wallet='fund')) == 1
    print('PHASE: channel_active', file=sys.stderr)
    for _ in range(150):
        views = []
        for channel, secret, peer in ((a, a_secret, b_key), (b, b_secret, a_key)):
            reported = call(channel, secret, 'ListChannels', ln.ListChannelsRequest,
                ln.ListChannelsResponse, ln.ListChannelsRequest(active_only=True))
            views.append([x for x in reported.channels if x.remote_pubkey == peer and x.active])
        if all(len(view) == 1 for view in views):
            break
        time.sleep(0.2)
    else:
        raise AssertionError('confirmed channel not active on both LND nodes')
    assert all(view[0].capacity == 1000000 for view in views)
    assert all(view[0].channel_point == txid + ':' + str(point.output_index) for view in views)
    assert all(view[0].private for view in views)
    assert views[0][0].local_balance > 0
    assert views[1][0].remote_balance > 0
    output = rpc('gettxout', [txid, point.output_index, False])
    assert output is not None and output['confirmations'] >= 1
    assert output['value'] == Decimal('0.01000000')
    script = output['scriptPubKey']['hex']
    assert len(script) == 68 and script.startswith('0020')
"""

CHANNEL_BOOTSTRAP = (
    CHANNEL_SETUP
    + """
    print(json.dumps({'funding_txid': txid, 'vout': point.output_index,
        'capacity_sat': views[0][0].capacity, 'confirmations': output['confirmations']}))
"""
)


HELD_HTLC_PAYMENT = (
    CHANNEL_SETUP
    + """
# Test-only SendPaymentV2 creates the incoming evidence; it is not a
# production pay_with_deadline implementation or funding permission.
assert views[0][0].chan_id == views[1][0].chan_id != 0
channel_id = views[0][0].chan_id
amount_msat = 1_000_000
print('PHASE: hold_route_preflight', file=sys.stderr)
preflight = 'route_unavailable'
for _ in range(100):
    try:
        edge = call(a, a_secret, 'GetChanInfo', ln.ChanInfoRequest, ln.ChannelEdge,
            ln.ChanInfoRequest(chan_id=channel_id), timeout=2)
        if edge.channel_id != channel_id:
            preflight = 'graph_missing'
        else:
            policy = edge.node1_policy if edge.node1_pub == a_key else edge.node2_policy
            if edge.node1_pub != a_key and edge.node2_pub != a_key:
                preflight = 'graph_missing'
            elif not policy or policy.disabled:
                preflight = 'policy_missing'
            else:
                available = call(a, a_secret, 'QueryRoutes',
                    ln.QueryRoutesRequest, ln.QueryRoutesResponse,
                    ln.QueryRoutesRequest(pub_key=b_key, amt_msat=amount_msat,
                        final_cltv_delta=80, outgoing_chan_ids=[channel_id],
                        fee_limit=ln.FeeLimit(fixed_msat=0), use_mission_control=False),
                    timeout=2)
                if (available.routes and len(available.routes[0].hops) == 1
                        and available.routes[0].hops[0].chan_id == channel_id
                        and available.routes[0].total_amt_msat == amount_msat):
                    break
    except grpc.RpcError:
        pass
    time.sleep(0.2)
else:
    print('DIAGNOSTIC: ' + preflight, file=sys.stderr)
    raise AssertionError('exact read-only channel route not available')
network = NetworkIdentity.model_validate(json.loads(
    Path('/work/provider/tests/fixtures/initial-btc-to-ln-v1.json').read_text()
)['contract_terms']['network_identity'])
def bake_read(channel, secret, entity):
    request = ln.BakeMacaroonRequest(
        permissions=[ln.MacaroonPermission(entity=entity, action='read')],
        root_key_id=0, allow_external_permissions=False)
    value = call(channel, secret, 'BakeMacaroon',
        ln.BakeMacaroonRequest, ln.BakeMacaroonResponse, request).macaroon
    assert 0 < len(value) <= 8192
    return bytes.fromhex(value)
def private_file(parent, name, contents):
    file = Path(parent) / name
    fd = os.open(file, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as target:
        target.write(contents)
    return file
def observe_invoice(observer, selected_hash, expected_state):
    for _ in range(100):
        result = observer.lookup(selected_hash, deadline_seconds=3)
        if result.state == expected_state:
            return result
        time.sleep(0.2)
    raise AssertionError('held-invoice state not observed within bound')
def decode_tlv_stream(data):
    # Test-local strict BOLT BigSize TLV decoder; diagnostic evidence only.
    def bigsize(offset):
        assert offset < len(data), 'truncated BigSize'
        first = data[offset]
        width = {0xfd: 2, 0xfe: 4, 0xff: 8}.get(first, 0)
        if not width:
            return first, offset + 1
        end = offset + 1 + width
        assert end <= len(data), 'truncated BigSize'
        value = int.from_bytes(data[offset + 1:end], 'big')
        assert value >= {2: 0xfd, 4: 0x10000, 8: 0x100000000}[width], 'noncanonical BigSize'
        return value, end
    records, offset, previous = {}, 0, -1
    while offset < len(data):
        record_type, offset = bigsize(offset)
        length, offset = bigsize(offset)
        assert record_type > previous, 'TLV types not strictly increasing'
        assert offset + length <= len(data), 'truncated TLV value'
        records[record_type] = bytes(data[offset:offset + length])
        previous, offset = record_type, offset + length
    return records
def next_status(stream, selected_hash, expected):
    for _ in range(16):
        try:
            value = next(stream)
        except StopIteration:
            print('DIAGNOSTIC: stream_ended', file=sys.stderr)
            raise AssertionError('payment stream ended without expected status') from None
        if value.payment_hash != selected_hash.hex():
            print('DIAGNOSTIC: hash_mismatch', file=sys.stderr)
            raise AssertionError('payment hash mismatch')
        if value.status == expected and value.htlcs:
            return value
        if value.status == ln.Payment.FAILED:
            reason = int(value.failure_reason)
            print('DIAGNOSTIC: payment_failed_' + str(reason if 0 <= reason <= 9 else 9),
                  file=sys.stderr)
            raise AssertionError('outgoing test payment failed before held observation')
        assert value.status in (ln.Payment.INITIATED, ln.Payment.IN_FLIGHT)
        assert len(value.htlcs) <= 1
    raise AssertionError('payment stream did not reach expected status with attempt')
def one_attempt(payment, expected, peer, selected_channel, amount):
    assert len(payment.htlcs) == 1
    attempt = payment.htlcs[0]
    assert attempt.attempt_id > 0 and attempt.status == expected
    assert len(attempt.route.hops) == 1
    hop = attempt.route.hops[0]
    assert hop.pub_key == peer and hop.chan_id == selected_channel
    assert hop.amt_to_forward_msat == amount
    assert attempt.route.total_amt_msat == amount
    assert attempt.route.total_fees_msat == 0
    mpp = hop.mpp_record.total_amt_msat if hop.HasField('mpp_record') else 0
    return attempt.route.total_time_lock, hop.expiry, mpp

with tempfile.TemporaryDirectory(prefix='rill-hold-reads-', dir='/tmp') as credentials:
    invoice_file = private_file(credentials, 'invoice.macaroon', bake_read(b, b_secret, 'invoices'))
    payment_file = private_file(credentials, 'payment.macaroon', bake_read(a, a_secret, 'offchain'))
    invoice_observer = RegtestLndInvoiceObserver(host='127.0.0.1', port=10010,
        tls_certificate_path='/work/public/b.cert', invoice_macaroon_path=invoice_file,
        network=network)
    payment_observer = RegtestLndPaymentObserver(host='127.0.0.1', port=10009,
        tls_certificate_path='/work/public/a.cert', read_macaroon_path=payment_file,
        network=network)
    raw_lookup = unary(b, '/lnrpc.Lightning/LookupInvoice', ln.PaymentHash, ln.Invoice)
    def observe_raw(selected_hash, expected):
        for _ in range(100):
            value = raw_lookup(ln.PaymentHash(r_hash=selected_hash),
                metadata=metadata(invoice_file.read_bytes()), timeout=3)
            assert value.r_hash == selected_hash
            if value.state == expected:
                return value
            time.sleep(0.2)
        raise AssertionError('raw pinned LND invoice state not observed')
    preimage = secrets.token_bytes(32)
    selected_hash = hashlib.sha256(preimage).digest()
    del preimage  # no settlement call and no preimage ever sent
    print('PHASE: hold_create_once', file=sys.stderr)
    created = unary(b, '/invoicesrpc.Invoices/AddHoldInvoice',
        inv.AddHoldInvoiceRequest, inv.AddHoldInvoiceResp)(
        inv.AddHoldInvoiceRequest(hash=selected_hash, value_msat=amount_msat,
                                  expiry=3600, cltv_expiry=80),
        metadata=metadata(b_secret), timeout=15)
    assert created.payment_request
    cancel_started = False
    def cancel_once():
        global cancel_started
        assert not cancel_started
        cancel_started = True
        unary(b, '/invoicesrpc.Invoices/CancelInvoice',
            inv.CancelInvoiceMsg, inv.CancelInvoiceResp)(
            inv.CancelInvoiceMsg(payment_hash=selected_hash),
            metadata=metadata(b_secret), timeout=5)
    try:
        opened = invoice_observer.lookup(selected_hash, deadline_seconds=3)
        assert opened.state == 'OPEN' and opened.htlcs == ()
        assert opened.value_msat == amount_msat and opened.payment_hash == selected_hash.hex()
        print('PHASE: hold_send_once', file=sys.stderr)
        send = a.unary_stream('/routerrpc.Router/SendPaymentV2',
            request_serializer=router.SendPaymentRequest.SerializeToString,
            response_deserializer=ln.Payment.FromString)
        sending = send(router.SendPaymentRequest(payment_request=created.payment_request,
            max_parts=1, outgoing_chan_ids=[channel_id], no_inflight_updates=False,
            fee_limit_msat=0, timeout_seconds=30),
            metadata=metadata(a_secret), timeout=90)
        print('PHASE: hold_stream_open', file=sys.stderr)
        live = next_status(iter(sending), selected_hash, ln.Payment.IN_FLIGHT)
        print('PHASE: hold_payment_live', file=sys.stderr)
        route_expiry, hop_expiry, mpp_total = one_attempt(
            live, ln.HTLCAttempt.IN_FLIGHT, b_key, channel_id, amount_msat)
        print('PHASE: hold_route_checked', file=sys.stderr)
        tracked = a.unary_stream('/routerrpc.Router/TrackPaymentV2',
            request_serializer=router.TrackPaymentRequest.SerializeToString,
            response_deserializer=ln.Payment.FromString)(
            router.TrackPaymentRequest(payment_hash=selected_hash, no_inflight_updates=False),
            metadata=metadata(payment_file.read_bytes()), timeout=60)
        print('PHASE: hold_track_open', file=sys.stderr)
        tracked_live = next_status(iter(tracked), selected_hash, ln.Payment.IN_FLIGHT)
        print('PHASE: hold_tracked_live', file=sys.stderr)
        assert tracked_live.htlcs[0].attempt_id == live.htlcs[0].attempt_id
        assert one_attempt(tracked_live, ln.HTLCAttempt.IN_FLIGHT,
                           b_key, channel_id, amount_msat) == (route_expiry, hop_expiry, mpp_total)
        print('PHASE: hold_accepted', file=sys.stderr)
        accepted = observe_raw(selected_hash, ln.Invoice.ACCEPTED)
        assert accepted.value_msat == accepted.amt_paid_msat == amount_msat
        assert len(accepted.htlcs) == 1
        part = accepted.htlcs[0]
        assert part.state == ln.InvoiceHTLCState.ACCEPTED and part.amt_msat == amount_msat
        assert part.chan_id == channel_id and part.htlc_index >= 0
        assert part.mpp_total_amt_msat == mpp_total
        assert mpp_total in (0, amount_msat)  # absent TLV or exact single-part total
        assert part.accept_height >= 102
        assert part.expiry_height == hop_expiry == route_expiry
        assert part.custom_channel_data  # pinned LND serializes ordinary custom records here
        decoded_custom = decode_tlv_stream(part.custom_channel_data)
        reported_custom = {key: bytes(value) for key, value in part.custom_records.items()}
        custom_matches = decoded_custom == reported_custom
        custom_shape = sorted([key, len(value)] for key, value in decoded_custom.items())
        print('DIAGNOSTIC: custom_channel_data types/lengths ' + json.dumps(custom_shape)
              + ' reported ' + json.dumps(sorted(
                  [key, len(value)] for key, value in reported_custom.items())),
              file=sys.stderr)
        try:
            invoice_observer.lookup(selected_hash, deadline_seconds=3)
        except LndProtocolError as error:
            assert str(error) == 'LND invoice HTLC identity or state unsupported'
        else:
            raise AssertionError('provider observer must refuse unsupported custom data')
        info = call(b, b_secret, 'GetInfo', ln.GetInfoRequest, ln.GetInfoResponse,
            ln.GetInfoRequest())
        assert info.block_height == 103
        assert part.expiry_height - info.block_height >= 80
        print('PHASE: hold_cancel_once', file=sys.stderr)
        cancel_once()
        print('PHASE: hold_cancel_acknowledged', file=sys.stderr)
        failed = next_status(iter(sending), selected_hash, ln.Payment.FAILED)
        print('PHASE: hold_payment_failed', file=sys.stderr)
        assert failed.htlcs[0].attempt_id == live.htlcs[0].attempt_id
        one_attempt(failed, ln.HTLCAttempt.FAILED, b_key, channel_id, amount_msat)
        print('PHASE: hold_attempt_failed', file=sys.stderr)
        observed = payment_observer.track(selected_hash, deadline_seconds=20)
        print('PHASE: hold_payment_observed', file=sys.stderr)
        assert observed.completion == 'terminal'
        print('PHASE: hold_terminal', file=sys.stderr)
        assert observed.snapshots[-1].status == 'FAILED'
        history = observed.snapshots[-1].htlc_attempts
        assert len(history) <= 1  # pinned LND may prune failed attempts by default
        if history:
            assert history[0].status == 'FAILED'
            assert history[0].lnd_attempt_id == failed.htlcs[0].attempt_id
        rejected = observe_raw(selected_hash, ln.Invoice.CANCELED)
        print('PHASE: hold_canceled_observed', file=sys.stderr)
        assert len(rejected.htlcs) == 1
        assert rejected.htlcs[0].state == ln.InvoiceHTLCState.CANCELED
        assert (rejected.htlcs[0].chan_id, rejected.htlcs[0].htlc_index,
                rejected.htlcs[0].amt_msat, rejected.htlcs[0].expiry_height) == (
                part.chan_id, part.htlc_index, part.amt_msat, part.expiry_height)
        print(json.dumps({'funding_txid': txid, 'vout': point.output_index,
            'capacity_sat': views[0][0].capacity, 'confirmations': output['confirmations'],
            'backend_hold_observed': True, 'observer_refused_custom': True,
            'payment_failed': True, 'history_returned': bool(history),
            'custom_data_matches_records': custom_matches,
            'custom_record_shape': custom_shape}))
    finally:
        if not cancel_started:
            try:
                cancel_once()
            except grpc.RpcError:
                pass  # unknown cancellation outcome, never retry
"""
)


def _run_two_node_sidecar(  # noqa: PLR0915 - isolated test infrastructure
    tmp_path: Path,
    program: str,
    *,
    prefix: str,
    deadline: int,
) -> dict[str, object]:
    """Use fresh owned Core/LND containers for one bounded sidecar scenario."""
    assert DOCKER is not None
    public = tmp_path / "public"
    public.mkdir(mode=0o700)
    generated = tmp_path / "generated"
    _wallet_messages(generated)
    _state_messages(generated)
    run_id = secrets.token_hex(16)
    label = f"org.rillswap.test-run={run_id}"
    core = f"rillswap-{prefix}-core-{secrets.token_hex(6)}"
    a = f"rillswap-{prefix}-lnd-a-{secrets.token_hex(6)}"
    b = f"rillswap-{prefix}-lnd-b-{secrets.token_hex(6)}"
    sidecar = f"rillswap-{prefix}-client-{secrets.token_hex(6)}"
    cert_a, cert_b = public / "a.cert", public / "b.cert"
    try:
        _docker(
            "run",
            "--detach",
            "--name",
            core,
            "--label",
            label,
            "--platform",
            "linux/amd64",
            "--network",
            "none",
            "--tmpfs",
            "/home/bitcoin/.bitcoin:rw,uid=101,gid=101,mode=0700",
            CORE_IMAGE,
            "-regtest=1",
            "-server=1",
            "-listen=0",
            "-discover=0",
            "-dnsseed=0",
            "-fallbackfee=0.00001000",
            "-rpcuser=rill-disposable",
            "-rpcpassword=disposable-regtest-only",
            "-rpcbind=127.0.0.1",
            "-rpcallowip=127.0.0.1",
            "-zmqpubrawblock=tcp://127.0.0.1:28332",
            "-zmqpubrawtx=tcp://127.0.0.1:28333",
            "-printtoconsole=1",
        )
        _wait_for_core(core)
        created = json.loads(_core_cli(core, "createwallet", "fund"))
        assert created["name"] == "fund"
        address = _core_cli(core, "-rpcwallet=fund", "getnewaddress", "", "bech32m")
        blocks = json.loads(
            _core_cli(
                core,
                "-rpcwallet=fund",
                "generatetoaddress",
                "101",
                address,
                timeout=180,
            )
        )
        assert len(blocks) == 101
        view = json.loads(_core_cli(core, "getblockchaininfo"))
        assert view["chain"] == "regtest"
        assert view["blocks"] == view["headers"] == 101
        assert view["initialblockdownload"] is False
        tip = json.loads(_core_cli(core, "getblockheader", blocks[-1]))
        assert tip["height"] == 101
        assert abs(time.time() - tip["time"]) < 60
        for name, port, peer_port in ((a, 10009, 9735), (b, 10010, 9736)):
            _docker(
                "run",
                "--detach",
                "--name",
                name,
                "--label",
                label,
                "--platform",
                "linux/amd64",
                "--network",
                f"container:{core}",
                "--tmpfs",
                "/root/.lnd:rw,mode=0700",
                LND_IMAGE,
                "--bitcoin.active",
                "--bitcoin.regtest",
                "--bitcoin.node=bitcoind",
                "--bitcoin.defaultchanconfs=1",
                "--bitcoind.rpchost=127.0.0.1:18443",
                "--bitcoind.rpcuser=rill-disposable",
                "--bitcoind.rpcpass=disposable-regtest-only",
                "--bitcoind.zmqpubrawblock=tcp://127.0.0.1:28332",
                "--bitcoind.zmqpubrawtx=tcp://127.0.0.1:28333",
                f"--rpclisten=127.0.0.1:{port}",
                f"--listen=127.0.0.1:{peer_port}",
                "--norest",
                "--nobootstrap",
            )
        for container, path in (
            (core, "/home/bitcoin/.bitcoin"),
            (a, "/root/.lnd"),
            (b, "/root/.lnd"),
        ):
            tmpfs = json.loads(
                _docker("inspect", container, "--format", "{{json .HostConfig.Tmpfs}}")
            )
            assert path in tmpfs
            mounts = json.loads(_docker("inspect", container, "--format", "{{json .Mounts}}"))
            assert all(entry["Type"] != "volume" for entry in mounts)
        _wait_for_public_certificate(a, cert_a)
        _wait_for_public_certificate(b, cert_b)
        result = _docker(
            "run",
            "--rm",
            "--name",
            sidecar,
            "--label",
            label,
            "--platform",
            "linux/amd64",
            "--network",
            f"container:{core}",
            "--tmpfs",
            "/tmp:rw,mode=0700,noexec,nosuid,nodev",  # noqa: S108 - test tmpfs
            "--mount",
            f"type=bind,src={ROOT},dst=/work/provider,readonly",
            "--mount",
            f"type=bind,src={CORE},dst=/work/core,readonly",
            "--mount",
            f"type=bind,src={public},dst=/work/public,readonly",
            "--mount",
            f"type=bind,src={generated},dst=/work/generated,readonly",
            "--env",
            "PYTHONPATH=/work/provider/.venv/lib/python3.14/site-packages:"
            "/work/provider/src:/work/core/packages/core/src:/work/generated",
            PYTHON_IMAGE,
            "python",
            "-c",
            program,
            timeout=deadline,
        )
        evidence = json.loads(result)
        assert evidence["capacity_sat"] == 1_000_000
        assert len(evidence["funding_txid"]) == 64
        assert type(evidence["vout"]) is int
        output = json.loads(
            _core_cli(
                core,
                "gettxout",
                evidence["funding_txid"],
                str(evidence["vout"]),
                "false",
            ),
            parse_float=Decimal,
        )
        assert output["confirmations"] >= 1
        assert output["value"] == Decimal("0.01000000")
        return evidence
    finally:
        try:
            _cleanup_containers((sidecar, b, a, core), run_id, cert_a)
        finally:
            cert_b.unlink(missing_ok=True)


@pytest.mark.lnd
@pytest.mark.skipif(
    os.environ.get("RILLSWAP_RUN_LND") != "1",
    reason="set RILLSWAP_RUN_LND=1 for pinned disposable LND",
)
def test_pinned_two_node_funded_channel_bootstrap(tmp_path: Path) -> None:
    """Fund one disposable private channel, not an LN payment or swap."""
    _run_two_node_sidecar(tmp_path, CHANNEL_BOOTSTRAP, prefix="channel", deadline=210)


@pytest.mark.lnd
@pytest.mark.skipif(
    os.environ.get("RILLSWAP_RUN_LND") != "1",
    reason="set RILLSWAP_RUN_LND=1 for pinned disposable LND",
)
def test_pinned_single_part_hold_accepted_then_canceled(tmp_path: Path) -> None:
    """Observe backend HTLC lifecycle and adapter refusal, never fund BTC."""
    evidence = _run_two_node_sidecar(tmp_path, HELD_HTLC_PAYMENT, prefix="hold", deadline=270)
    assert evidence["backend_hold_observed"] is True
    assert evidence["observer_refused_custom"] is True
    assert evidence["payment_failed"] is True
    # Characterization only: the ordinary hold's custom_channel_data is the
    # canonical TLV encoding of custom_records. The production observer still
    # refuses it (asserted above); this does not authorize accepting it.
    assert evidence["custom_data_matches_records"] is True
    shape = evidence["custom_record_shape"]
    assert shape
    assert all(key >= 65536 and length <= 1024 for key, length in shape)
