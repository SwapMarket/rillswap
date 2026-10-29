"""Shared Core wallets reserve distinct coins before signing any funding."""

from __future__ import annotations

import threading
from concurrent.futures import ThreadPoolExecutor
from decimal import Decimal
from typing import TYPE_CHECKING, Any
from unittest.mock import Mock

import httpx
import pytest
from test_wallet_rpc import CONTRACT, NETWORK

from rill_cli.wallet_rpc import WalletRpc, WalletRpcError, _CoinUnavailableError

if TYPE_CHECKING:
    from pathlib import Path


def _wallet(tmp_path: Path) -> WalletRpc:
    cookie = tmp_path / "cookie"
    cookie.write_text("__cookie__:secret")
    cookie.chmod(0o600)
    return WalletRpc(port=1234, cookie_path=cookie, wallet="shared", network=NETWORK)


def _coins() -> list[dict[str, Any]]:
    return [
        {
            "txid": f"{index:064x}",
            "vout": 0,
            "scriptPubKey": "0014" + "44" * 20,
            "amount": Decimal("0.001"),
            "safe": True,
            "spendable": True,
            "solvable": True,
            "confirmations": 2,
        }
        for index in (1, 2)
    ]


def test_two_wallet_clients_reserve_different_coins_from_same_snapshot(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    wallets = [_wallet(tmp_path), _wallet(tmp_path)]
    snapshot = threading.Barrier(2)
    gate = threading.Lock()
    locked = set()
    persistent = set()

    def call(method: str, *params: Any) -> Any:  # noqa: ANN401 - Core JSON fake
        if method == "listunspent":
            snapshot.wait(timeout=5)
            return _coins()
        assert method == "lockunspent"
        assert params[0] is False
        txid = params[1][0]["txid"]
        with gate:
            if len(params) == 2:
                if txid in locked:
                    raise _CoinUnavailableError("Core coin reservation refused")
                locked.add(txid)
            else:
                assert params[2] is True
                assert txid in locked
                persistent.add(txid)
        return True

    for wallet in wallets:
        monkeypatch.setattr(wallet, "_call", call)
    with ThreadPoolExecutor(max_workers=2) as pool:
        coins = list(pool.map(lambda wallet: wallet._reserve_coin(50_000), wallets))  # noqa: SLF001
    assert len({coin.txid for coin in coins}) == 2
    assert locked == persistent == {coin["txid"] for coin in _coins()}


@pytest.mark.parametrize("status", [200, 500])
@pytest.mark.parametrize(("code", "exception"), [(-8, _CoinUnavailableError), (-1, WalletRpcError)])
def test_only_explicit_core_coin_refusal_is_retryable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    status: int,
    code: int,
    exception: type[WalletRpcError],
) -> None:
    wallet = _wallet(tmp_path)
    monkeypatch.setattr(wallet, "_verify_network", lambda: 100)
    monkeypatch.setattr(
        httpx,
        "post",
        lambda *_args, **_kwargs: httpx.Response(
            status,
            json={"result": None, "error": {"code": code, "message": "private detail"}, "id": 1},
        ),
    )
    with pytest.raises(exception) as result:
        wallet._call("lockunspent", False, [{"txid": "01" * 32, "vout": 0}])  # noqa: SLF001, FBT003
    assert type(result.value) is exception
    assert "private detail" not in str(result.value)


@pytest.mark.parametrize("failure", [_CoinUnavailableError, WalletRpcError])
def test_reservation_failure_never_signs_or_retries_uncertain_errors(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, failure: type[WalletRpcError]
) -> None:
    wallet = _wallet(tmp_path)
    calls = []

    def call(method: str, *params: Any) -> Any:  # noqa: ANN401 - Core JSON fake
        calls.append((method, params))
        if method == "listunspent":
            return _coins()
        assert method == "lockunspent"
        raise failure("unavailable")

    monkeypatch.setattr(wallet, "_call", call)
    with pytest.raises(WalletRpcError):
        wallet.fund(bytes.fromhex(CONTRACT), 50_000, fee_rate_sat_vb=2)
    assert [method for method, _ in calls] == ["listunspent"] + ["lockunspent"] * (
        2 if failure is _CoinUnavailableError else 1
    )


@pytest.mark.parametrize("phase", ["persist", "decode", "sign", "finalize", "success"])
def test_only_definitely_unsigned_reservations_can_be_released(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, phase: str
) -> None:
    wallet = _wallet(tmp_path)
    outpoint = [{"txid": _coins()[0]["txid"], "vout": 0}]
    calls = []

    def call(method: str, *params: Any, **_kwargs: Any) -> Any:  # noqa: ANN401, PLR0911 - Core JSON fake
        calls.append((method, params))
        if method == "listunspent":
            return _coins()
        if method == "lockunspent":
            if phase == "persist" and params == (False, outpoint, True):
                raise WalletRpcError("persistence uncertain")
            return True
        if method == "decodescript":
            if phase == "decode":
                raise WalletRpcError("decode failed")
            return {"address": "bcrt1pcontract"}
        if method == "walletcreatefundedpsbt":
            return {"psbt": "unsigned"}
        if method == "decodepsbt":
            return {
                "tx": {"vin": outpoint, "vout": [{"value": 0, "scriptPubKey": {"hex": CONTRACT}}]},
                "inputs": [
                    {
                        "witness_utxo": {
                            "amount": Decimal("0.001"),
                            "scriptPubKey": {"hex": _coins()[0]["scriptPubKey"]},
                        }
                    }
                ],
                "fee": Decimal("0.000003"),
            }
        if method == "walletprocesspsbt":
            if phase == "sign":
                raise WalletRpcError("signing outcome uncertain")
            return {"psbt": "signed"}
        assert method == "finalizepsbt"
        if phase == "finalize":
            raise WalletRpcError("finalization failed")
        return {"complete": True, "hex": "0200"}

    monkeypatch.setattr(wallet, "_call", call)
    if phase == "success":
        wallet.fund(bytes.fromhex(CONTRACT), 50_000, fee_rate_sat_vb=2)
    else:
        with pytest.raises(WalletRpcError):
            wallet.fund(bytes.fromhex(CONTRACT), 50_000, fee_rate_sat_vb=2)
    unlocks = [params for method, params in calls if method == "lockunspent" and params[0] is True]
    assert unlocks == ([(True, outpoint)] if phase in ("persist", "decode") else [])


def test_unlock_failure_does_not_mask_original_unsigned_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    wallet = _wallet(tmp_path)
    monkeypatch.setattr(
        wallet, "_reserve_coin", Mock(return_value=Mock(txid=b"\x01" * 32, output_index=0))
    )
    monkeypatch.setattr(
        wallet, "_call", Mock(side_effect=[WalletRpcError("original"), WalletRpcError("cleanup")])
    )
    with pytest.raises(WalletRpcError, match="original"):
        wallet.fund(bytes.fromhex(CONTRACT), 50_000, fee_rate_sat_vb=2)
