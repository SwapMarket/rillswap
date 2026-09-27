"""Pinned Bitcoin Core independently validates a real MuSig key-path claim.

This test runs only on explicit opt-in; no developer's existing Core node or
wallet is touched. The disposable regtest instance proves consensus accepts
our BIP341 digest, which a self-sign/self-verify test cannot establish.
"""

from __future__ import annotations

import json
import os
import secrets
import shutil
import subprocess
import time
from decimal import Decimal
from pathlib import Path
from typing import Any

import pytest

from rill_core.settlement import (
    FundingOutput,
    UnilateralAuthorization,
    build_cooperative_claim,
    finalize_cooperative_claim,
)
from rill_core.wire.messages import ContractTerms

IMAGE = (
    "docker.io/bitcoin/bitcoin@"
    "sha256:49b55ea5c949a9ceff50786ee678d53f2728a4daa40a8139e3ee20243d24f281"
)
FIXTURE = Path(__file__).parents[1] / "fixtures" / "settlement-v1" / "taproot-cases-v1.json"
SATOSHIS_PER_BTC = Decimal(100_000_000)


def _docker(*args: str, timeout: int = 60) -> str:
    executable = shutil.which("docker")
    if executable is None:
        raise RuntimeError("opt-in Core consensus test requires Docker")
    result = subprocess.run(  # noqa: S603 - pinned disposable Core
        [executable, *args], capture_output=True, text=True, timeout=timeout, check=True
    )
    return result.stdout.strip()


def _rpc(
    name: str,
    password: str,
    method: str,
    *params: object,
    wallet: str | None = None,
    timeout: int = 60,
) -> Any:  # noqa: ANN401 - Bitcoin Core returns JSON primitives
    arguments = [
        "exec",
        name,
        "bitcoin-cli",
        "-regtest",
        "-rpcuser=rillswap",
        f"-rpcpassword={password}",
    ]
    if wallet is not None:
        arguments.append(f"-rpcwallet={wallet}")
    arguments.append(method)
    arguments.extend(
        json.dumps(value) if isinstance(value, (list, dict, bool)) else str(value)
        for value in params
    )
    result = _docker(*arguments, timeout=timeout)
    try:
        return json.loads(result, parse_float=Decimal)
    except json.JSONDecodeError:
        return result  # bitcoin-cli writes plain addresses, txids and hashes


def _p2tr_address(script: bytes) -> str:
    """BIP350 regtest encoding for the fixture's 32-byte v1 witness program."""
    assert len(script) == 34
    assert script[:2] == b"\x51\x20"
    alphabet = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
    generators = (0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3)
    values = [1]
    bits = 0
    accumulated = 0
    for byte in script[2:]:
        accumulated = (accumulated << 8) | byte
        bits += 8
        while bits >= 5:
            bits -= 5
            values.append((accumulated >> bits) & 31)
    if bits:
        values.append((accumulated << (5 - bits)) & 31)
    hrp = "bcrt"
    checksum = 1
    for value in [
        *[ord(char) >> 5 for char in hrp],
        0,
        *[ord(char) & 31 for char in hrp],
        *values,
        *([0] * 6),
    ]:
        top = checksum >> 25
        checksum = ((checksum & 0x1FFFFFF) << 5) ^ value
        for index, generator in enumerate(generators):
            if (top >> index) & 1:
                checksum ^= generator
    checksum ^= 0x2BC830A3
    return (
        hrp
        + "1"
        + "".join(
            alphabet[value]
            for value in values + [(checksum >> (5 * (5 - index))) & 31 for index in range(6)]
        )
    )


@pytest.mark.native_crypto
@pytest.mark.bitcoin_core
@pytest.mark.skipif(
    os.environ.get("RILLSWAP_RUN_BITCOIN_CORE") != "1"
    or os.environ.get("RILLSWAP_RUN_NATIVE_CRYPTO") != "1",
    reason="set both RILLSWAP_RUN_BITCOIN_CORE and RILLSWAP_RUN_NATIVE_CRYPTO to 1",
)
def test_core_accepts_only_exact_tweaked_musig_key_path_claim() -> None:  # noqa: PLR0915 - full consensus scenario
    from rill_crypto import Context  # noqa: PLC0415 - opt-in native adapter

    name = f"rillswap-coop-{secrets.token_hex(6)}"
    password = secrets.token_urlsafe(32)
    try:
        _docker(
            "run",
            "--detach",
            "--name",
            name,
            "--platform",
            "linux/amd64",
            IMAGE,
            "-regtest=1",
            "-server=1",
            "-listen=0",
            "-discover=0",
            "-dnsseed=0",
            "-rpcuser=rillswap",
            f"-rpcpassword={password}",
            "-fallbackfee=0.00001000",
            timeout=180,
        )
        deadline = time.monotonic() + 60
        while True:
            try:
                assert _rpc(name, password, "getblockchaininfo")["chain"] == "regtest"
                break
            except (subprocess.CalledProcessError, AssertionError):
                if time.monotonic() >= deadline:
                    raise
                time.sleep(1)
        assert _rpc(name, password, "getnetworkinfo")["version"] == 300000
        _rpc(name, password, "createwallet", "fund")
        miner = _rpc(name, password, "getnewaddress", "", "bech32m", wallet="fund")
        _rpc(name, password, "generatetoaddress", 101, miner, wallet="fund", timeout=180)

        case = json.loads(FIXTURE.read_text())["valid"][0]
        terms = ContractTerms.model_validate_json(json.dumps(case["contract_terms"]))
        script = bytes.fromhex(case["artifacts"]["script_pubkey"])
        amount = int(terms.economics.contract_amount_sat)
        address = _p2tr_address(script)
        txid = _rpc(
            name,
            password,
            "sendtoaddress",
            address,
            f"{Decimal(amount) / SATOSHIS_PER_BTC:.8f}",
            wallet="fund",
        )
        (block_hash,) = _rpc(name, password, "generatetoaddress", 1, miner, wallet="fund")
        funded = _rpc(name, password, "getrawtransaction", txid, 1, block_hash)
        outputs = [
            output
            for output in funded["vout"]
            if output["scriptPubKey"]["hex"] == script.hex()
            and int(output["value"] * SATOSHIS_PER_BTC) == amount
        ]
        assert len(outputs) == 1
        funding = FundingOutput(bytes.fromhex(txid), int(outputs[0]["n"]), amount, script)

        with Context(library_path=os.environ["RILL_CRYPTO_LIBRARY"]) as crypto:
            auth = UnilateralAuthorization.from_terms(terms, funding, "claim", keys=crypto)
            plan = build_cooperative_claim(auth, fee_sat=300)
            keys = {
                "user_public_key": bytes.fromhex(terms.client_contract_compressed_key),
                "provider_public_key": bytes.fromhex(terms.provider_contract_compressed_key),
                "tap_tweak": bytes.fromhex(case["artifacts"]["tap_tweak"]),
                "message": plan.signature_hash,
            }
            cooperation_id = secrets.token_bytes(32)
            user, user_nonce = crypto.musig_begin(
                secret_key=bytes.fromhex(case["fixture_keys"]["client_contract_secret_key"]),
                cooperation_id=cooperation_id,
                **keys,
            )
            provider, provider_nonce = crypto.musig_begin(
                secret_key=bytes.fromhex(case["fixture_keys"]["provider_contract_secret_key"]),
                cooperation_id=cooperation_id,
                **keys,
            )
            with user, provider:
                user_partial = user.partial_sign_once(provider_nonce)
                provider_partial = provider.partial_sign_once(user_nonce)
                signature = crypto.musig_aggregate(
                    user_public_nonce=user_nonce,
                    provider_public_nonce=provider_nonce,
                    user_partial_signature=user_partial,
                    provider_partial_signature=provider_partial,
                    **keys,
                )
            claim = finalize_cooperative_claim(plan, signature, verifier=crypto)
        raw = claim.raw_transaction.hex()
        corrupted = bytearray(claim.raw_transaction)
        corrupted[-5] ^= 1  # Last BIP340 signature byte, before nLockTime.
        (bad,) = _rpc(name, password, "testmempoolaccept", [corrupted.hex()])
        assert bad["allowed"] is False
        (good,) = _rpc(name, password, "testmempoolaccept", [raw])
        assert good["allowed"] is True, good
        assert _rpc(name, password, "sendrawtransaction", raw) == claim.txid
        (confirming,) = _rpc(name, password, "generatetoaddress", 1, miner, wallet="fund")
        assert claim.txid in _rpc(name, password, "getblock", confirming, 1)["tx"]
    finally:
        executable = shutil.which("docker")
        if executable is not None:
            subprocess.run(  # noqa: S603 - disposable container named by this test
                [executable, "rm", "--force", "--volumes", name],
                capture_output=True,
                text=True,
                check=False,
                timeout=60,
            )
