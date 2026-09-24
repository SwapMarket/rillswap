"""Opt-in pinned LND regtest NOT_FOUND check with a disposable empty wallet.

No mining, funding, channels, invoices, payments, or host wallet mounts. The
fresh wallet is initialized in memory only to make the read-only RPC available.
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
        phase = phases[-1] if phases else "unidentified"
        category = error_types[-1] if error_types else "unidentified"
        grpc_code = grpc_codes[-1] if grpc_codes else "none"
        raise AssertionError(f"disposable LND failed in {phase} ({category}, grpc={grpc_code})")
    return completed.stdout.strip() if completed.returncode == 0 else ""


def _core_cli(container: str, *args: str) -> str:
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
        timeout=5,
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
from rill_provider._lnd_proto.routerrpc import router_pb2
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
