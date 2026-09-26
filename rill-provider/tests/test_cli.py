"""Operator config, credential file, provisioning, and a native serve run."""

from __future__ import annotations

import asyncio
import json
import os
import signal
import sqlite3
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest
from fake_relay import FakeRelay
from pyrage import x25519  # type: ignore[import-untyped]

from rill_provider import cli
from rill_provider.cli import REFUSED, main
from rill_provider.operator_config import (
    OperatorConfigError,
    load_config,
    read_custody_identity,
)

FIXTURE = Path(__file__).parent / "fixtures" / "initial-btc-to-ln-v1.json"


def _network() -> dict[str, Any]:
    network: dict[str, Any] = json.loads(FIXTURE.read_text())["network_identity"]
    return network


def _config(
    tmp_path: Path,
    unlock: x25519.Identity | None = None,
    **overrides: Any,  # noqa: ANN401 - arbitrary JSON config fields
) -> Path:
    unlock = unlock or x25519.Identity.generate()
    custody = tmp_path / "custody.key"
    custody.write_text(f"# created for tests\n{unlock}\n")
    custody.chmod(0o600)
    document = {
        "network": _network(),
        "provider_identity_xonly": "79be667ef9dcbbac55a06295ce870b07"
        "029bfcdb2dce28d959f2815b16f81798",
        "identity_file": "id.age",
        "store_path": "store/live.sqlite",
        "custody_recipient": str(unlock.to_public()),
        "custody_identity_file": "custody.key",
        "native_crypto_library": os.environ.get("RILL_CRYPTO_LIBRARY", "missing.so"),
        "authority": {
            "volume_label": "test-volume",
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
            "amount_bands": [[1000, 100000]],
            "base_fee_sat": 50,
            "proportional_millionths": 1000,
            "slot": "regtest-main",
        },
        "relay_urls": ["ws://127.0.0.1:9/"],
    } | overrides
    (tmp_path / "store").mkdir(exist_ok=True)
    path = tmp_path / "provider.json"
    path.write_text(json.dumps(document))
    return path


def test_config_resolves_relative_paths_and_refuses_unknown_fields(tmp_path: Path) -> None:
    config = load_config(_config(tmp_path))
    assert config.store_path == tmp_path / "store" / "live.sqlite"
    assert config.custody_identity_file == tmp_path / "custody.key"
    assert config.service_policy().relay_urls == ("ws://127.0.0.1:9/",)
    with pytest.raises(OperatorConfigError, match="config refused"):
        load_config(_config(tmp_path, surprise=1))
    with pytest.raises(OperatorConfigError, match="config refused"):
        load_config(_config(tmp_path, relay_urls=[]))


def test_custody_identity_file_must_be_private_single_identity(tmp_path: Path) -> None:
    key = str(x25519.Identity.generate())
    path = tmp_path / "custody.key"
    path.write_text(f"# comment\n{key}\n")
    path.chmod(0o600)
    assert read_custody_identity(path) == key
    path.chmod(0o640)
    with pytest.raises(OperatorConfigError, match="0600"):
        read_custody_identity(path)
    path.chmod(0o600)
    link = tmp_path / "link.key"
    link.symlink_to(path)
    with pytest.raises(OperatorConfigError, match="unavailable"):
        read_custody_identity(link)
    path.write_text(f"{key}\n{key}\n")
    with pytest.raises(OperatorConfigError, match="exactly one"):
        read_custody_identity(path)


def test_provision_store_is_explicit_and_never_overwrites(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    config = _config(tmp_path)
    assert main(["provision-store", "--config", str(config)]) == 0
    before = (tmp_path / "store" / "live.sqlite").read_bytes()
    assert main(["provision-store", "--config", str(config)]) == REFUSED
    assert (tmp_path / "store" / "live.sqlite").read_bytes() == before
    assert capsys.readouterr().err.startswith("rill-provider: ")
    (tmp_path / "custody.key").chmod(0o644)
    assert main(["serve", "--config", str(config)]) == REFUSED


@pytest.mark.native_crypto
@pytest.mark.skipif(
    os.environ.get("RILLSWAP_RUN_NATIVE_CRYPTO") != "1",
    reason="set RILLSWAP_RUN_NATIVE_CRYPTO=1 with pinned native library",
)
def test_explicit_migration_does_not_start_the_service(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config = _config(tmp_path)
    assert main(["provision-store", "--config", str(config)]) == 0
    database = tmp_path / "store" / "live.sqlite"
    with sqlite3.connect(database) as connection:
        connection.execute("DROP TABLE payment_dispatch")
        connection.execute("UPDATE meta SET schema_version=5")
        connection.execute("PRAGMA user_version=5")

    async def refuse_service(*_args: object) -> None:
        pytest.fail("migration must not run the network service")

    monkeypatch.setattr(cli, "_serve", refuse_service)
    assert main(["migrate-store", "--config", str(config)]) == 0
    assert main(["migrate-store", "--config", str(config)]) == 0
    with sqlite3.connect(database) as connection:
        assert connection.execute("PRAGMA user_version").fetchone() == (6,)
        assert connection.execute("SELECT * FROM payment_dispatch").fetchall() == []


@pytest.mark.native_crypto
@pytest.mark.skipif(
    os.environ.get("RILLSWAP_RUN_NATIVE_CRYPTO") != "1",
    reason="set RILLSWAP_RUN_NATIVE_CRYPTO=1 with pinned native library",
)
def test_native_serve_announces_and_stops_on_sigterm(tmp_path: Path) -> None:
    unlock = x25519.Identity.generate()
    config_path = _config(tmp_path, unlock)
    recipient = str(unlock.to_public())
    library = os.environ["RILL_CRYPTO_LIBRARY"]
    created = subprocess.run(  # noqa: S603 - fixed argv
        [
            sys.executable,
            "-m",
            "rill_provider.cli",
            "provision-identity",
            "--out",
            str(tmp_path / "id.age"),
            "--recipient",
            recipient,
            "--native-crypto-library",
            library,
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    xonly = created.stdout.strip()

    async def scenario() -> None:
        relay = FakeRelay()
        url = await relay.start()
        _config(tmp_path, unlock, provider_identity_xonly=xonly, relay_urls=[url])
        try:
            assert main(["provision-store", "--config", str(config_path)]) == 0
            process = await asyncio.create_subprocess_exec(
                sys.executable,
                "-m",
                "rill_provider.cli",
                "serve",
                "--config",
                str(config_path),
                stderr=asyncio.subprocess.PIPE,
            )
            for _ in range(200):
                if any(event["kind"] == 39417 for event in relay.events):
                    break
                await asyncio.sleep(0.05)
            announcements = [e for e in relay.events if e["kind"] == 39417]
            if not announcements:
                process.kill()
                _, stderr = await process.communicate()
                pytest.fail(f"no announcement: {stderr.decode()[-2000:]}")
            announcement = announcements[0]
            assert announcement["pubkey"] == xonly
            process.send_signal(signal.SIGTERM)
            assert await asyncio.wait_for(process.wait(), 20) == 0
        finally:
            await relay.stop()

    asyncio.run(scenario())


def test_bitcoin_core_cookie_resolves_and_quote_settings_reach_the_service(
    tmp_path: Path,
) -> None:
    config = load_config(
        _config(
            tmp_path,
            bitcoin_core={"port": 18443, "cookie_file": "core.cookie"},
            quote={"lifetime": 30},
        )
    )
    assert config.bitcoin_core is not None
    assert config.bitcoin_core.cookie_file == tmp_path / "core.cookie"
    assert config.service_policy().quote.lifetime == 30
    assert config.service_policy().quote.funding_confirmations == 2
    with pytest.raises(OperatorConfigError):
        load_config(_config(tmp_path, quote={"lifetime": 0}))
    with pytest.raises(OperatorConfigError):  # not a representable wire integer
        load_config(_config(tmp_path, quote={"funding_confirmations": 2**53}))


def test_lnd_paths_resolve_and_destination_script_is_checked(tmp_path: Path) -> None:
    script = "0014" + "31" * 20
    config = load_config(
        _config(
            tmp_path,
            lnd={"port": 10009, "tls_certificate": "tls.cert", "macaroon": "read.macaroon"},
            provider_destination_script=script,
        )
    )
    assert config.lnd is not None
    assert config.lnd.macaroon == tmp_path / "read.macaroon"
    assert config.service_policy().provider_destination_script == script
    with pytest.raises(OperatorConfigError):
        load_config(_config(tmp_path, provider_destination_script="76a914" + "00" * 20))
