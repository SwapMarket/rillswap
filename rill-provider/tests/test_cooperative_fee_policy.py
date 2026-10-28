"""Strict read-only signing fee evidence is distinct from optional fallback advice."""

from __future__ import annotations

import json
from decimal import Decimal, localcontext
from typing import TYPE_CHECKING, Any

import httpx
import pytest
from test_core_tx_bytes import _cookie, _server
from test_network_adapters import _network

from rill_provider.core_tx_bytes import (
    CooperativeFeePolicy,
    CoreProtocolError,
    CoreReadError,
    CoreTransactionReader,
    CoreUnavailableError,
    _fee_rate_sat_kvb,
)

if TYPE_CHECKING:
    from pathlib import Path


@pytest.mark.parametrize(
    "network_name", ["signet", "testnet4", "mainnet", "regtest-rillswap-e2e-v1"]
)
@pytest.mark.parametrize(
    "case",
    [
        "valid",
        "zero floors",
        "unavailable",
        "explicit fixed",
        "missing floor",
        "fractional floor",
        "zero estimate",
        "target expansion",
        "bool blocks",
        "missing blocks",
        "missing estimate",
        "empty errors",
        "null errors",
        "conflicting errors",
        "changed tip",
        "wrong genesis",
    ],
)
def test_strict_fee_sampling_never_infers_an_exemption(  # noqa: PLR0915 - one strict evidence lifecycle
    tmp_path: Path,
    network_name: str,
    case: str,
) -> None:
    network = _network(network_name)

    def reply(payload: dict[str, Any]) -> tuple[int, bytes]:  # noqa: PLR0912 - explicit malformed response cases
        mempool = {"minrelaytxfee": 0.000001, "mempoolminfee": 0.00001}
        estimate: dict[str, Any] = {"feerate": 0.00003, "blocks": 6}
        info = {
            "chain": "main" if network.name == "mainnet" else network.name,
            "blocks": 105,
            "bestblockhash": "aa" * 32,
            "initialblockdownload": False,
            "signet_challenge": network.signet_challenge,
        }
        if case == "zero floors":
            mempool.update(minrelaytxfee=0, mempoolminfee=0)
        elif case in {"unavailable", "explicit fixed"}:
            estimate = {"errors": ["Insufficient data or no feerate found"], "blocks": 0}
        elif case == "missing floor":
            del mempool["mempoolminfee"]
        elif case == "fractional floor":
            mempool["mempoolminfee"] = 0.000010001
        elif case == "zero estimate":
            estimate["feerate"] = 0
        elif case == "target expansion":
            estimate["blocks"] = 7
        elif case == "bool blocks":
            estimate["blocks"] = True
        elif case == "missing blocks":
            del estimate["blocks"]
        elif case == "missing estimate":
            del estimate["feerate"]
        elif case == "empty errors":
            estimate = {"errors": [], "blocks": 6}
        elif case == "null errors":
            estimate["errors"] = None
        elif case == "conflicting errors":
            estimate["errors"] = ["Unavailable"]
        elif case == "changed tip" and payload["id"] == 5:
            info["bestblockhash"] = "bb" * 32
        genesis = "ff" * 32 if case == "wrong genesis" else network.genesis_hash
        result = {
            "getblockchaininfo": info,
            "getblockhash": genesis,
            "getmempoolinfo": mempool,
            "estimatesmartfee": estimate,
        }[payload["method"]]
        return 200, json.dumps({"jsonrpc": "2.0", "id": payload["id"], "result": result}).encode()

    requests: list[dict[str, Any]] = []
    with _server(reply, requests) as port:
        reader = CoreTransactionReader(port=port, cookie_path=_cookie(tmp_path), network=network)
        fixed = case == "explicit fixed"
        if fixed and network.name != "regtest":
            with pytest.raises(ValueError, match="explicit regtest"):
                reader.observe_cooperative_fee_policy(6, allow_regtest_fixed_fee=True)
            assert requests == []
        elif case in {"valid", "zero floors"} or fixed:
            sample = reader.observe_cooperative_fee_policy(6, allow_regtest_fixed_fee=fixed)
            assert sample.network_identity == network
            assert sample.tip_hash == "aa" * 32
            assert sample.tip_height == 105
            assert sample.confirmation_blocks == 6
            assert sample.estimate_sat_kvb == (None if fixed else 3000)
            assert sample.fee_floor_sat(vsize=128, configured_floor_sat=300) == (
                300 if fixed else 384
            )
            assert [request["method"] for request in requests] == [
                "getblockchaininfo",
                "getblockhash",
                "getmempoolinfo",
                "estimatesmartfee",
                "getblockchaininfo",
            ]
            assert requests[3]["params"] == [6, "CONSERVATIVE"]
        else:
            with pytest.raises((CoreProtocolError, CoreUnavailableError)):
                reader.observe_cooperative_fee_policy(6)


@pytest.mark.parametrize(
    "value",
    [
        True,
        None,
        "0.00001",
        0.00001,
        Decimal("NaN"),
        Decimal("Infinity"),
        Decimal("-0.00001"),
        Decimal(1),
        Decimal("0.000000001"),
        Decimal("0.0000100000000000000000000000000000001"),
        Decimal("1e-1000000"),
    ],
)
def test_fee_rates_are_exact_whole_satoshis_not_floats(value: object) -> None:
    with pytest.raises(CoreProtocolError):
        _fee_rate_sat_kvb(value)


def test_fee_rate_conversion_does_not_use_ambient_decimal_precision() -> None:
    with localcontext() as context:
        context.prec = 2
        assert _fee_rate_sat_kvb(Decimal("0.00001234")) == 1234
        assert _fee_rate_sat_kvb(0) == 0


@pytest.mark.parametrize(
    ("rate", "vsize", "expected"), [(3, 333, 1), (3, 334, 2), (1000, 128, 128)]
)
def test_fee_floor_rounds_up_exactly(rate: int, vsize: int, expected: int) -> None:
    policy = CooperativeFeePolicy(_network("signet"), "aa" * 32, 105, 6, 0, 0, rate, 6)
    assert policy.fee_floor_sat(vsize=vsize, configured_floor_sat=1) == expected
    assert policy.fee_floor_sat(vsize=vsize, configured_floor_sat=300) == 300


@pytest.mark.parametrize(
    ("relay", "mempool", "expected"), [(100, 100, 10), (10_000, 100, 990), (100, 10_000, 990)]
)
def test_a_claim_paying_the_signed_reserve_only_has_to_relay(
    relay: int, mempool: int, expected: int
) -> None:
    # 99 vB claim: the estimate of 10 sat/vB would demand 990 sats otherwise.
    policy = CooperativeFeePolicy(_network("signet"), "aa" * 32, 105, 6, relay, mempool, 10_000, 2)
    assert policy.fee_floor_sat(vsize=99, configured_floor_sat=1) == 990
    assert (
        policy.fee_floor_sat(vsize=99, configured_floor_sat=1, pays_signed_reserve=True) == expected
    )
    assert policy.fee_floor_sat(vsize=99, configured_floor_sat=999, pays_signed_reserve=True) == 999


@pytest.mark.parametrize("flag", [1, None, "yes"])
def test_fee_floor_rejects_a_non_boolean_reserve_flag(flag: object) -> None:
    policy = CooperativeFeePolicy(_network("signet"), "aa" * 32, 105, 6, 0, 0, 1000, 6)
    with pytest.raises(ValueError, match="fee inputs invalid"):
        policy.fee_floor_sat(vsize=99, configured_floor_sat=1, pays_signed_reserve=flag)  # type: ignore[arg-type]


@pytest.mark.parametrize("vsize", [True, 0, -1, 1.5])
def test_fee_floor_rejects_invalid_vsize(vsize: object) -> None:
    policy = CooperativeFeePolicy(_network("signet"), "aa" * 32, 105, 6, 0, 0, 1000, 6)
    with pytest.raises(ValueError, match="fee inputs invalid"):
        policy.fee_floor_sat(vsize=vsize, configured_floor_sat=300)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "case",
    [
        "missing floor",
        "bad floor",
        "missing estimate",
        "null errors",
        "empty errors",
        "conflicting errors",
        "wrong target",
        "rpc failure",
        "http failure",
    ],
)
def test_explicit_regtest_exemption_never_masks_bad_evidence(tmp_path: Path, case: str) -> None:
    network = _network("regtest-rillswap-e2e-v1")

    def reply(payload: dict[str, Any]) -> tuple[int, bytes]:
        mempool = {"minrelaytxfee": 0, "mempoolminfee": 0.00001}
        estimate: dict[str, Any] = {"errors": ["Insufficient data"], "blocks": 0}
        if case == "missing floor":
            del mempool["mempoolminfee"]
        elif case == "bad floor":
            mempool["mempoolminfee"] = True
        elif case == "missing estimate":
            estimate = {"blocks": 0}
        elif case == "null errors":
            estimate["errors"] = None
        elif case == "empty errors":
            estimate["errors"] = []
        elif case == "conflicting errors":
            estimate["feerate"] = 0.00003
        elif case == "wrong target":
            estimate = {"feerate": 0.00003, "blocks": 7}
        if payload["method"] == "estimatesmartfee":
            if case == "http failure":
                return 503, b"Unavailable"
            if case == "rpc failure":
                return 200, json.dumps(
                    {
                        "jsonrpc": "2.0",
                        "id": payload["id"],
                        "error": {
                            "code": -28,
                            "message": "test-only unavailable",
                        },
                    }
                ).encode()
        result = {
            "getblockchaininfo": {
                "chain": "regtest",
                "blocks": 105,
                "bestblockhash": "aa" * 32,
                "initialblockdownload": False,
            },
            "getblockhash": network.genesis_hash,
            "getmempoolinfo": mempool,
            "estimatesmartfee": estimate,
        }[payload["method"]]
        return 200, json.dumps({"jsonrpc": "2.0", "id": payload["id"], "result": result}).encode()

    requests: list[dict[str, Any]] = []
    with _server(reply, requests) as port:
        reader = CoreTransactionReader(port=port, cookie_path=_cookie(tmp_path), network=network)
        with pytest.raises(CoreReadError):
            reader.observe_cooperative_fee_policy(6, allow_regtest_fixed_fee=True)


@pytest.mark.parametrize(
    ("target", "flag"),
    [
        (True, False),
        (0, False),
        (1009, False),
        (6.0, False),
        (6, 1),
        (6, None),
    ],
)
def test_invalid_fee_policy_arguments_fail_before_cookie_or_rpc(
    tmp_path: Path,
    target: object,
    flag: object,
) -> None:
    reader = CoreTransactionReader(
        port=18443,
        cookie_path=tmp_path / "absent",
        network=_network("regtest-rillswap-e2e-v1"),
    )
    with pytest.raises(ValueError, match=r"estimate target|explicit regtest"):
        reader.observe_cooperative_fee_policy(target, allow_regtest_fixed_fee=flag)  # type: ignore[arg-type]


def test_explicit_fixed_policy_never_converts_transport_failure_to_evidence(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    reader = CoreTransactionReader(
        port=18443,
        cookie_path=_cookie(tmp_path),
        network=_network("regtest-rillswap-e2e-v1"),
    )

    def failed_rpc(*_args: object, **_kwargs: object) -> None:
        raise httpx.ReadTimeout("test-only failure")

    monkeypatch.setattr(reader, "_rpc", failed_rpc)
    with pytest.raises(CoreUnavailableError, match="transport unavailable"):
        reader.observe_cooperative_fee_policy(6, allow_regtest_fixed_fee=True)
