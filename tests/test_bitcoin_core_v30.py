from __future__ import annotations

import hashlib
import json
import os
import secrets
import subprocess
import time
from dataclasses import dataclass
from decimal import Decimal
from pathlib import Path
from typing import Any

import pytest

from tests.settlement_support import build_spend, spend_is_authorized
from tests.test_schemas import load_json
from tests.vendor.bitcoin_core_v30_reference import OutPoint, TxOutput

ROOT = Path(__file__).parents[1]
TAPROOT_PATH = ROOT / "vectors" / "taproot" / "cases-v1.json"
IMAGE = (
    "docker.io/bitcoin/bitcoin@"
    "sha256:49b55ea5c949a9ceff50786ee678d53f2728a4daa40a8139e3ee20243d24f281"
)
REFUND_HEIGHT = 1100
SATOSHIS_PER_BTC = Decimal(100_000_000)


def _run_docker(*arguments: str, timeout: int = 60) -> str:
    result = subprocess.run(
        ("docker", *arguments),
        check=True,
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    return result.stdout.strip()


def _docker_logs(container_name: str) -> str:
    result = subprocess.run(
        ("docker", "logs", container_name),
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )
    return "\n".join(part for part in (result.stdout, result.stderr) if part).strip()


def _remove_container(container_name: str) -> None:
    result = subprocess.run(
        ("docker", "rm", "--force", "--volumes", container_name),
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )
    if result.returncode == 0:
        return
    detail = "\n".join(part for part in (result.stdout, result.stderr) if part).strip()
    if "No such container" in detail:
        return
    raise RuntimeError(f"failed to remove Bitcoin Core container: {detail}")


class RpcClient:
    def __init__(self, container_name: str, username: str, password: str) -> None:
        self._container_name = container_name
        self._username = username
        self._password = password

    def call(self, method: str, *params: Any, wallet: str | None = None) -> Any:
        arguments = [
            "docker",
            "exec",
            self._container_name,
            "bitcoin-cli",
            "-regtest",
            f"-rpcuser={self._username}",
            f"-rpcpassword={self._password}",
        ]
        if wallet is not None:
            arguments.append(f"-rpcwallet={wallet}")
        arguments.append(method)
        arguments.extend(_rpc_argument(param) for param in params)
        result = subprocess.run(
            arguments,
            check=False,
            capture_output=True,
            text=True,
            timeout=30,
        )
        if result.returncode != 0:
            detail = "\n".join(
                part for part in (result.stdout, result.stderr) if part
            ).strip()
            raise RuntimeError(f"Bitcoin Core RPC {method} failed: {detail}")
        output = result.stdout.strip()
        try:
            return json.loads(output, parse_float=Decimal)
        except json.JSONDecodeError:
            return output


def _rpc_argument(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (list, dict)) or value is None:
        return json.dumps(value)
    return str(value)


def _wait_for_rpc(client: RpcClient, container_name: str) -> None:
    deadline = time.monotonic() + 60
    last_error: Exception | None = None
    while time.monotonic() < deadline:
        try:
            client.call("getblockchaininfo")
            return
        except (OSError, RuntimeError) as error:
            last_error = error
            running = _run_docker(
                "inspect",
                "--format",
                "{{.State.Running}}",
                container_name,
            )
            if running != "true":
                logs = _docker_logs(container_name)
                raise RuntimeError(f"Bitcoin Core container exited:\n{logs}") from error
            time.sleep(0.25)
    logs = _docker_logs(container_name)
    raise TimeoutError(f"Bitcoin Core RPC did not start: {last_error}\n{logs}")


def _bech32_polymod(values: list[int]) -> int:
    generators = (0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3)
    checksum = 1
    for value in values:
        top = checksum >> 25
        checksum = (checksum & 0x1FFFFFF) << 5 ^ value
        for index, generator in enumerate(generators):
            if (top >> index) & 1:
                checksum ^= generator
    return checksum


def _bech32_hrp_expand(hrp: str) -> list[int]:
    return (
        [ord(character) >> 5 for character in hrp]
        + [0]
        + [ord(character) & 31 for character in hrp]
    )


def _convert_bits(data: bytes, from_bits: int, to_bits: int) -> list[int]:
    accumulator = 0
    bit_count = 0
    result: list[int] = []
    maximum = (1 << to_bits) - 1
    for value in data:
        accumulator = (accumulator << from_bits) | value
        bit_count += from_bits
        while bit_count >= to_bits:
            bit_count -= to_bits
            result.append((accumulator >> bit_count) & maximum)
    if bit_count:
        result.append((accumulator << (to_bits - bit_count)) & maximum)
    return result


def _p2tr_regtest_address(script_pubkey: bytes) -> str:
    if len(script_pubkey) != 34 or script_pubkey[:2] != b"\x51\x20":
        raise ValueError("expected a P2TR scriptPubKey")
    hrp = "bcrt"
    values = [1, *_convert_bits(script_pubkey[2:], 8, 5)]
    polymod = _bech32_polymod(_bech32_hrp_expand(hrp) + values + [0] * 6) ^ 0x2BC830A3
    checksum = [(polymod >> (5 * (5 - index))) & 31 for index in range(6)]
    alphabet = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
    return hrp + "1" + "".join(alphabet[value] for value in values + checksum)


def _btc_amount(satoshis: int) -> str:
    return f"{Decimal(satoshis) / SATOSHIS_PER_BTC:.8f}"


def _height(rpc: RpcClient) -> int:
    return int(rpc.call("getblockcount"))


def _mine_to(rpc: RpcClient, wallet: str, address: str, height: int) -> list[str]:
    count = height - _height(rpc)
    if count < 0:
        raise AssertionError(f"chain height {_height(rpc)} is already above {height}")
    if count == 0:
        return []
    return rpc.call("generatetoaddress", count, address, wallet=wallet)


def _mempool_result(rpc: RpcClient, raw_transaction: str) -> dict[str, Any]:
    results = rpc.call("testmempoolaccept", [raw_transaction], Decimal("0"))
    assert len(results) == 1
    return results[0]


@dataclass(frozen=True)
class FundedOutput:
    outpoint: OutPoint
    output: TxOutput


def _fund_output(
    rpc: RpcClient,
    wallet: str,
    taproot_case: dict[str, Any],
) -> str:
    amount = int(taproot_case["contract_terms"]["economics"]["contract_amount_sat"])
    script_pubkey = bytes.fromhex(taproot_case["artifacts"]["script_pubkey"])
    return rpc.call(
        "sendtoaddress",
        _p2tr_regtest_address(script_pubkey),
        _btc_amount(amount),
        wallet=wallet,
    )


def _locate_funded_output(
    rpc: RpcClient,
    txid: str,
    block_hash: str,
    taproot_case: dict[str, Any],
) -> FundedOutput:
    transaction = rpc.call("getrawtransaction", txid, True, block_hash)
    expected_script = taproot_case["artifacts"]["script_pubkey"]
    expected_value = int(
        taproot_case["contract_terms"]["economics"]["contract_amount_sat"],
    )
    matches = [
        output
        for output in transaction["vout"]
        if output["scriptPubKey"]["hex"] == expected_script
        and int(output["value"] * SATOSHIS_PER_BTC) == expected_value
    ]
    assert len(matches) == 1
    match = matches[0]
    funded = FundedOutput(
        OutPoint(bytes.fromhex(txid), int(match["n"])),
        TxOutput(expected_value, bytes.fromhex(expected_script)),
    )
    unspent = rpc.call("gettxout", txid, int(match["n"]), False)
    assert unspent is not None
    assert int(unspent["value"] * SATOSHIS_PER_BTC) == expected_value
    assert unspent["scriptPubKey"]["hex"] == expected_script
    return funded


def _dynamic_spend(
    taproot_case: dict[str, Any],
    path: str,
    funded: FundedOutput,
    label: str,
    *,
    preimage: bytes | None = None,
):
    fee = int(taproot_case["contract_terms"][f"max_{path}_fee_sat"])
    spend = build_spend(
        taproot_case,
        path,
        outpoint=funded.outpoint,
        spent_output=funded.output,
        fee_sat=fee,
        auxiliary_random=hashlib.sha256(label.encode()).digest(),
        preimage=preimage,
    )
    if preimage is None:
        assert spend_is_authorized(
            spend,
            taproot_case,
            path,
            expected_outpoint=funded.outpoint,
            expected_spent_output=funded.output,
        )
    return spend


def _raw(spend) -> str:
    return spend.transaction.serialize_with_witness(spend.witnesses).hex()


@pytest.mark.bitcoin_core
@pytest.mark.skipif(
    os.environ.get("RILLSWAP_RUN_BITCOIN_CORE") != "1",
    reason="set RILLSWAP_RUN_BITCOIN_CORE=1 to run the pinned Core test",
)
def test_unilateral_spends_execute_at_refund_height_boundaries() -> None:
    container_name = f"rillswap-core-v30-{secrets.token_hex(6)}"
    username = "rillswap"
    password = secrets.token_urlsafe(32)
    failure: BaseException | None = None
    try:
        _run_docker(
            "run",
            "--detach",
            "--name",
            container_name,
            "--platform",
            "linux/amd64",
            IMAGE,
            "-regtest=1",
            "-server=1",
            "-listen=0",
            "-discover=0",
            "-dnsseed=0",
            f"-rpcuser={username}",
            f"-rpcpassword={password}",
            "-fallbackfee=0.00001000",
            "-printtoconsole=1",
            timeout=180,
        )
        configured_image = _run_docker(
            "inspect",
            "--format",
            "{{.Config.Image}}",
            container_name,
        )
        assert configured_image == IMAGE
        platform = _run_docker(
            "inspect",
            "--format",
            "{{.Os}}/{{.Architecture}}",
            IMAGE,
        )
        assert platform == "linux/amd64"
        rpc = RpcClient(container_name, username, password)
        _wait_for_rpc(rpc, container_name)
        chain_info = rpc.call("getblockchaininfo")
        network_info = rpc.call("getnetworkinfo")
        assert chain_info["chain"] == "regtest"
        assert network_info["version"] == 300000
        assert network_info["subversion"] == "/Satoshi:30.0.0/"

        wallet = "fund"
        rpc.call("createwallet", wallet)
        mining_address = rpc.call("getnewaddress", "", "bech32m", wallet=wallet)
        _mine_to(rpc, wallet, mining_address, 101)

        taproot_cases = load_json(TAPROOT_PATH)["valid"]
        assert all(
            case["contract_terms"]["refund_lock_height"] == REFUND_HEIGHT
            for case in taproot_cases
        )
        funding_txids: dict[str, dict[str, str]] = {}
        for taproot_case in taproot_cases:
            funding_txids[taproot_case["id"]] = {
                purpose: _fund_output(rpc, wallet, taproot_case)
                for purpose in ("refund_at_t", "refund_at_t_plus_one", "claim_late")
            }
        funding_block_hash = _mine_to(rpc, wallet, mining_address, 102)[0]

        funded: dict[str, dict[str, FundedOutput]] = {}
        for taproot_case in taproot_cases:
            funded[taproot_case["id"]] = {
                purpose: _locate_funded_output(
                    rpc,
                    txid,
                    funding_block_hash,
                    taproot_case,
                )
                for purpose, txid in funding_txids[taproot_case["id"]].items()
            }

        _mine_to(rpc, wallet, mining_address, REFUND_HEIGHT - 1)
        assert _height(rpc) == REFUND_HEIGHT - 1
        first_refunds = []
        for taproot_case in taproot_cases:
            spend = _dynamic_spend(
                taproot_case,
                "refund",
                funded[taproot_case["id"]]["refund_at_t"],
                f"RillSwap/Core-v30/{taproot_case['id']}/refund-at-t",
            )
            first_refunds.append(spend)
            result = _mempool_result(rpc, _raw(spend))
            assert result["allowed"] is False
            assert result.get("reject-reason") or result.get("reject-details")

        block_t = _mine_to(rpc, wallet, mining_address, REFUND_HEIGHT)[0]
        assert rpc.call("getblockheader", block_t)["height"] == REFUND_HEIGHT
        for taproot_case, spend in zip(taproot_cases, first_refunds, strict=True):
            funding = funded[taproot_case["id"]]["refund_at_t"]
            assert (
                rpc.call(
                    "gettxout",
                    funding.outpoint.txid.hex(),
                    funding.outpoint.index,
                    False,
                )
                is not None
            )
            assert _mempool_result(rpc, _raw(spend))["allowed"] is True

        first_refund_txids = [
            rpc.call("sendrawtransaction", _raw(spend), Decimal("0"))
            for spend in first_refunds
        ]
        block_t_plus_one = _mine_to(
            rpc,
            wallet,
            mining_address,
            REFUND_HEIGHT + 1,
        )[0]
        block = rpc.call("getblock", block_t_plus_one, 1)
        assert block["height"] == REFUND_HEIGHT + 1
        assert set(first_refund_txids).issubset(block["tx"])

        later_valid_spends = []
        for taproot_case in taproot_cases:
            case_funding = funded[taproot_case["id"]]
            refund = _dynamic_spend(
                taproot_case,
                "refund",
                case_funding["refund_at_t_plus_one"],
                f"RillSwap/Core-v30/{taproot_case['id']}/refund-at-t-plus-one",
            )
            claim = _dynamic_spend(
                taproot_case,
                "claim",
                case_funding["claim_late"],
                f"RillSwap/Core-v30/{taproot_case['id']}/claim-late",
            )
            assert _mempool_result(rpc, _raw(refund))["allowed"] is True
            assert _mempool_result(rpc, _raw(claim))["allowed"] is True

            for suffix, bad_preimage in (
                ("wrong-hash", b"\x00" * 32),
                ("short", b"\x42" * 31),
                ("long", b"\x42" * 33),
            ):
                invalid_claim = _dynamic_spend(
                    taproot_case,
                    "claim",
                    case_funding["claim_late"],
                    f"RillSwap/Core-v30/{taproot_case['id']}/invalid-{suffix}",
                    preimage=bad_preimage,
                )
                result = _mempool_result(rpc, _raw(invalid_claim))
                assert result["allowed"] is False
                assert result.get("reject-reason") or result.get("reject-details")
            later_valid_spends.extend((refund, claim))

        later_txids = [
            rpc.call("sendrawtransaction", _raw(spend), Decimal("0"))
            for spend in later_valid_spends
        ]
        final_block_hash = _mine_to(
            rpc,
            wallet,
            mining_address,
            REFUND_HEIGHT + 2,
        )[0]
        final_block = rpc.call("getblock", final_block_hash, 1)
        assert final_block["height"] == REFUND_HEIGHT + 2
        assert set(later_txids).issubset(final_block["tx"])
    except BaseException as error:
        failure = error
    finally:
        try:
            _remove_container(container_name)
        except BaseException as cleanup_error:
            if failure is not None:
                raise cleanup_error from failure
            raise
    if failure is not None:
        raise failure.with_traceback(failure.__traceback__)


def test_container_cleanup_is_attempted_when_start_times_out(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[str, ...]] = []

    def fake_run(arguments: tuple[str, ...], **_kwargs: Any):
        calls.append(arguments)
        if arguments[1] == "run":
            raise subprocess.TimeoutExpired(arguments, 180)
        if arguments[1:4] == ("rm", "--force", "--volumes"):
            return subprocess.CompletedProcess(
                arguments,
                1,
                stdout="",
                stderr="Error response from daemon: No such container",
            )
        raise AssertionError(f"unexpected subprocess call: {arguments}")

    monkeypatch.setattr(subprocess, "run", fake_run)
    with pytest.raises(subprocess.TimeoutExpired):
        test_unilateral_spends_execute_at_refund_height_boundaries()
    assert any(call[1:4] == ("rm", "--force", "--volumes") for call in calls)
