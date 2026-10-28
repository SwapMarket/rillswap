"""Operator ceiling on Core fee estimates (skewed signet estimators).

The ceiling lowers only Core's estimate, never replaces a missing one. Set,
the funding rate and advisory claim/refund rates are capped, and the node's
relay and mempool floors and every strict cooperative check still apply.
"""

from __future__ import annotations

import asyncio
import json
from types import SimpleNamespace
from typing import TYPE_CHECKING, Any
from unittest.mock import Mock

import pytest
from pydantic import ValidationError
from test_core_tx_bytes import _context, _cookie, _rpc_reply, _server
from test_core_wallet_funding import ADDRESS, SCRIPT, _by_method, _funding_replies
from test_network_adapters import _network

from rill_provider import cli
from rill_provider.core_tx_bytes import (
    CoreProtocolError,
    CoreTransactionReader,
    CoreUnavailableError,
)
from rill_provider.operator_config import BitcoinCore

if TYPE_CHECKING:
    from pathlib import Path

SKEWED = {"feerate": 0.00231893, "blocks": 6}  # 231.893 sat/vB, as seen on signet


@pytest.mark.parametrize(
    ("estimate", "rate"),
    [
        (SKEWED, "2.000"),
        ({"feerate": 0.00001234, "blocks": 2}, "1.234"),  # below the ceiling: Core's own
    ],
)
def test_capped_funding_pays_the_lower_of_the_estimate_and_the_ceiling(
    tmp_path: Path, estimate: dict[str, Any], rate: str
) -> None:
    _, _, network = _context()
    requests: list[dict[str, Any]] = []
    replies = _funding_replies(estimatesmartfee=estimate)
    with _server(_by_method(replies), requests) as port:
        reader = CoreTransactionReader(
            port=port,
            cookie_path=_cookie(tmp_path),
            network=network,
            wallet="rill",
            max_fee_estimate_sat_vb=2,
        )
        funded = reader.fund_output(SCRIPT, 100_500, max_fee_sat=400)
    assert funded.fee_sat == 300
    estimate_request = next(r for r in requests if r["method"] == "estimatesmartfee")
    assert estimate_request["params"] == [2, "ECONOMICAL"]
    create = next(r for r in requests if r["method"] == "walletcreatefundedpsbt")
    assert create["params"][1] == [{ADDRESS: "0.00100500"}]
    assert create["params"][3] == {
        "changePosition": 1,
        "lockUnspents": True,
        "replaceable": False,
        "fee_rate": rate,
        "add_inputs": False,
    }


@pytest.mark.parametrize(
    "estimate",
    [
        {"errors": ["Insufficient data or no feerate found"], "blocks": 0},
        {"code": -32601, "message": "Method not found"},  # an RPC error
    ],
)
def test_missing_estimate_never_selects_the_ceiling(
    tmp_path: Path, estimate: dict[str, Any]
) -> None:
    # Before, funding paid the ceiling whenever Core could not estimate.
    network = _network("signet")
    replies = _funding_replies()

    def respond(payload: dict[str, Any]) -> tuple[int, bytes]:
        if payload["method"] == "estimatesmartfee" and "code" in estimate:
            body = {"jsonrpc": "2.0", "id": payload["id"], "error": estimate}
            return 200, json.dumps(body).encode()
        if payload["method"] == "estimatesmartfee":
            replies["estimatesmartfee"] = estimate
        return _by_method(replies)(payload)

    requests: list[dict[str, Any]] = []
    with _server(respond, requests) as port:
        reader = CoreTransactionReader(
            port=port, cookie_path=_cookie(tmp_path), network=network, max_fee_estimate_sat_vb=3
        )
        with pytest.raises(CoreUnavailableError, match="estimate unavailable"):
            reader.fund_output(SCRIPT, 100_500, max_fee_sat=400)
    assert [r["method"] for r in requests] == ["getmempoolinfo", "estimatesmartfee"]


def test_node_minimums_still_bind_a_capped_estimate(tmp_path: Path) -> None:
    _, _, network = _context()
    requests: list[dict[str, Any]] = []
    replies = _funding_replies(
        estimatesmartfee=SKEWED,
        getmempoolinfo={"minrelaytxfee": 0.000001, "mempoolminfee": 0.00003},
    )
    with _server(_by_method(replies), requests) as port:
        reader = CoreTransactionReader(
            port=port, cookie_path=_cookie(tmp_path), network=network, max_fee_estimate_sat_vb=2
        )
        reader.fund_output(SCRIPT, 100_500, max_fee_sat=400)
    create = next(r for r in requests if r["method"] == "walletcreatefundedpsbt")
    assert create["params"][3]["fee_rate"] == "3.000"


def test_capped_funding_still_refuses_a_fee_above_the_signed_maximum(tmp_path: Path) -> None:
    _, _, network = _context()
    replies = _funding_replies(
        estimatesmartfee=SKEWED,
        walletcreatefundedpsbt={"psbt": "x", "fee": 0.00000401},
    )
    with _server(_by_method(replies), []) as port:
        reader = CoreTransactionReader(
            port=port, cookie_path=_cookie(tmp_path), network=network, max_fee_estimate_sat_vb=2
        )
        with pytest.raises(CoreProtocolError, match="fee exceeds"):
            reader.fund_output(SCRIPT, 100_500, max_fee_sat=400)


@pytest.mark.parametrize(("ceiling", "expected"), [(None, 231.893), (2, 2.0), (500, 231.893)])
def test_advisory_estimates_are_capped(
    tmp_path: Path, ceiling: int | None, expected: float
) -> None:
    _, _, network = _context()
    with _server(_rpc_reply(SKEWED), []) as port:
        reader = CoreTransactionReader(
            port=port,
            cookie_path=_cookie(tmp_path),
            network=network,
            max_fee_estimate_sat_vb=ceiling,
        )
        rate = reader.fee_rate_sat_vb(6)
    assert rate is not None
    assert abs(rate - expected) < 1e-9


def _policy_reply(network_name: str, estimate: dict[str, Any], mempool_min: float) -> Any:  # noqa: ANN401
    network = _network(network_name)

    def reply(payload: dict[str, Any]) -> tuple[int, bytes]:
        info = {
            "chain": network.name,
            "blocks": 105,
            "bestblockhash": "aa" * 32,
            "initialblockdownload": False,
            "signet_challenge": network.signet_challenge,
        }
        result = {
            "getblockchaininfo": info,
            "getblockhash": network.genesis_hash,
            "getmempoolinfo": {"minrelaytxfee": 0.000001, "mempoolminfee": mempool_min},
            "estimatesmartfee": estimate,
        }[payload["method"]]
        return 200, json.dumps({"jsonrpc": "2.0", "id": payload["id"], "result": result}).encode()

    return network, reply


@pytest.mark.parametrize(
    ("ceiling", "mempool_min", "estimate_kvb", "floor"),
    [
        (None, 0.000001, 231_893, 25_741),  # today's behavior: cooperation unaffordable
        (2, 0.000001, 2_000, 1_000),  # the claim's 1,000-sat floor now covers it
        (2, 0.0001, 2_000, 1_110),  # a full mempool's minimum still binds
    ],
)
def test_cooperative_evidence_caps_only_the_estimate(
    tmp_path: Path, ceiling: int | None, mempool_min: float, estimate_kvb: int, floor: int
) -> None:
    network, reply = _policy_reply("signet", SKEWED, mempool_min)
    with _server(reply, []) as port:
        reader = CoreTransactionReader(
            port=port,
            cookie_path=_cookie(tmp_path),
            network=network,
            max_fee_estimate_sat_vb=ceiling,
        )
        policy = reader.observe_cooperative_fee_policy(6)
    assert policy.estimate_sat_kvb == estimate_kvb
    assert policy.estimate_blocks == 6
    assert policy.fee_floor_sat(vsize=111, configured_floor_sat=1_000) == floor


def test_cooperative_evidence_checks_are_unchanged_under_a_ceiling(tmp_path: Path) -> None:
    network, reply = _policy_reply("signet", {"feerate": 0.00231893, "blocks": 7}, 0.000001)
    with _server(reply, []) as port:
        reader = CoreTransactionReader(
            port=port, cookie_path=_cookie(tmp_path), network=network, max_fee_estimate_sat_vb=2
        )
        with pytest.raises(CoreProtocolError, match="confirmation budget"):
            reader.observe_cooperative_fee_policy(6)


@pytest.mark.parametrize("ceiling", [0, -1, 10_001, True, 1.5, "2"])
def test_ceiling_must_be_a_positive_whole_rate(tmp_path: Path, ceiling: object) -> None:
    _, _, network = _context()
    with pytest.raises(ValueError, match="ceiling"):
        CoreTransactionReader(
            port=1,
            cookie_path=tmp_path / "c",
            network=network,
            max_fee_estimate_sat_vb=ceiling,  # type: ignore[arg-type]
        )
    with pytest.raises(ValidationError, match="max_fee_estimate_sat_vb"):
        _bitcoin_core(max_fee_estimate_sat_vb=ceiling)


def _bitcoin_core(**fields: object) -> BitcoinCore:
    return BitcoinCore.model_validate_json(
        json.dumps({"port": 8332, "cookie_file": "/rill/credentials/core.cookie", **fields})
    )


@pytest.mark.parametrize("ceiling", [None, 2])
def test_operator_ceiling_reaches_the_settlement_reader(
    tmp_path: Path, ceiling: int | None
) -> None:
    _, _, network = _context()
    config = SimpleNamespace(
        network=network,
        handshake=SimpleNamespace(profile="ln-to-btc/v1"),
        bitcoin_core=SimpleNamespace(
            port=18443,
            cookie_file=tmp_path / "cookie",
            wallet="w",
            max_fee_estimate_sat_vb=ceiling,
        ),
        lnd=SimpleNamespace(
            port=10009,
            tls_certificate=tmp_path / "tls.cert",
            payment_macaroon=tmp_path / "payment.macaroon",
            invoices_macaroon=tmp_path / "invoices.macaroon",
        ),
    )
    engine = cli._settlement(config, Mock(network_identity=network), Mock())  # type: ignore[arg-type]  # noqa: SLF001
    assert engine is not None
    reader = engine._chain  # noqa: SLF001
    assert isinstance(reader, CoreTransactionReader)
    assert reader._max_fee_estimate_sat_vb == ceiling  # noqa: SLF001


def test_operator_ceiling_is_optional() -> None:
    assert _bitcoin_core().max_fee_estimate_sat_vb is None
    assert _bitcoin_core(max_fee_estimate_sat_vb=2).max_fee_estimate_sat_vb == 2


@pytest.mark.parametrize(
    ("network", "ceiling", "warned"),
    [("mainnet", 2, True), ("mainnet", None, False), ("signet", 2, False)],
)
def test_serve_warns_about_a_ceiling_only_on_mainnet(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
    network: str,
    ceiling: int | None,
    warned: bool,  # noqa: FBT001
) -> None:
    # A warning, never a refusal: existing mainnet configs keep starting.
    monkeypatch.setattr(cli, "require_supported_network", Mock())
    config = SimpleNamespace(
        network=SimpleNamespace(name=network),
        provider_destination_script="00",
        lnd=None,  # stops serving right after the warning
        bitcoin_core=SimpleNamespace(max_fee_estimate_sat_vb=ceiling),
    )
    with caplog.at_level("WARNING", logger=cli.__name__), pytest.raises(cli.OperatorConfigError):
        asyncio.run(cli._serve(config, Mock(), "unused"))  # type: ignore[arg-type]  # noqa: SLF001
    warnings = [r.getMessage() for r in caplog.records if r.levelname == "WARNING"]
    assert any("caps Core's mainnet fee estimates at 2 sat/vB" in w for w in warnings) is warned
