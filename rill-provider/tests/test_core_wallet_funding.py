"""Provider-side Core wallet funding and claim spend detection (RS-004)."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

import pytest
from test_core_tx_bytes import _context, _cookie, _server

from rill_provider.core_tx_bytes import (
    MAX_SPEND_SCAN_BLOCKS,
    CoreProtocolError,
    CoreTransactionReader,
    SpendObservation,
)

if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path

SCRIPT = bytes.fromhex("5120" + "11" * 32)
ADDRESS = "bcrt1pexample"
FUNDING_TXID = "aa" * 32
SPENDER = "bb" * 32
PREIMAGE = "52" * 32


def _by_method(
    replies: dict[str, Any],
) -> Callable[[dict[str, Any]], tuple[int, bytes]]:
    def respond(payload: dict[str, Any]) -> tuple[int, bytes]:
        reply = replies[payload["method"]]
        result = reply(payload["params"]) if callable(reply) else reply
        return 200, json.dumps({"jsonrpc": "2.0", "id": payload["id"], "result": result}).encode()

    return respond


def _funding_replies(**changes: Any) -> dict[str, Any]:  # noqa: ANN401
    decoded = {
        "txid": FUNDING_TXID,
        "vout": [
            {"value": 0.00100500, "scriptPubKey": {"hex": SCRIPT.hex()}},
            {"value": 0.5, "scriptPubKey": {"hex": "0014" + "22" * 20}},
        ],
    }
    replies: dict[str, Any] = {
        "decodescript": {"address": ADDRESS},
        "walletcreatefundedpsbt": {"psbt": "cHNidP8B", "fee": 0.00000300, "changepos": 1},
        "walletprocesspsbt": {"psbt": "cHNidP8C", "complete": True},
        "finalizepsbt": {"hex": "0200", "complete": True},
        "decoderawtransaction": decoded,
    }
    replies.update(changes)
    return replies


def test_fund_output_signs_exactly_the_requested_payment_at_index_zero(tmp_path: Path) -> None:
    _, _, network = _context()
    requests: list[dict[str, Any]] = []
    with _server(_by_method(_funding_replies()), requests) as port:
        reader = CoreTransactionReader(
            port=port, cookie_path=_cookie(tmp_path), network=network, wallet="rill"
        )
        funded = reader.fund_output(SCRIPT, 100_500, max_fee_sat=400)
    assert (funded.txid, funded.vout, funded.raw, funded.fee_sat) == (
        FUNDING_TXID,
        0,
        b"\x02\x00",
        300,
    )
    methods = [(r["method"], r["path"]) for r in requests]
    assert methods == [
        ("decodescript", "/"),
        ("walletcreatefundedpsbt", "/wallet/rill"),
        ("walletprocesspsbt", "/wallet/rill"),
        ("finalizepsbt", "/"),
        ("decoderawtransaction", "/"),
    ]
    create = requests[1]["params"]
    assert create[0] == [] and create[1] == [{ADDRESS: "0.00100500"}]  # noqa: PT018
    assert create[3] == {
        "changePosition": 1,
        "lockUnspents": True,
        "replaceable": False,
        "conf_target": 6,
        "estimate_mode": "economical",
    }
    assert requests[2]["params"] == ["cHNidP8B", True]
    assert not any(r["method"] == "sendrawtransaction" for r in requests)


@pytest.mark.parametrize(
    ("changes", "reason"),
    [
        ({"walletcreatefundedpsbt": {"psbt": "x", "fee": 0.00000401}}, "fee exceeds"),
        ({"decodescript": {}}, "no address"),
        ({"finalizepsbt": {"hex": "0200", "complete": False}}, "every funding input"),
        (
            {
                "decoderawtransaction": {
                    "txid": FUNDING_TXID,
                    "vout": [{"value": 0.00100400, "scriptPubKey": {"hex": SCRIPT.hex()}}],
                }
            },
            "different funding",
        ),
        (
            {
                "decoderawtransaction": {
                    "txid": FUNDING_TXID,
                    "vout": [{"value": 0.00100500, "scriptPubKey": {"hex": "0014" + "33" * 20}}],
                }
            },
            "different funding",
        ),
    ],
)
def test_fund_output_refuses_anything_but_the_exact_payment(
    tmp_path: Path, changes: dict[str, Any], reason: str
) -> None:
    _, _, network = _context()
    with _server(_by_method(_funding_replies(**changes)), []) as port:
        reader = CoreTransactionReader(port=port, cookie_path=_cookie(tmp_path), network=network)
        with pytest.raises(CoreProtocolError, match=reason):
            reader.fund_output(SCRIPT, 100_500, max_fee_sat=400)
    with pytest.raises(ValueError, match="wallet name"):
        CoreTransactionReader(
            port=1, cookie_path=tmp_path / "c", network=network, wallet="../other"
        )
    with pytest.raises(ValueError, match="unsupported"):
        reader.fund_output(SCRIPT, 0, max_fee_sat=400)


def _spend(txid: str = FUNDING_TXID, vout: int = 0) -> dict[str, Any]:
    return {
        "txid": SPENDER,
        "vin": [
            {"txid": "cc" * 32, "vout": 3, "txinwitness": ["ee"]},
            {
                "txid": txid,
                "vout": vout,
                "txinwitness": ["dd" * 64, PREIMAGE, "51", "c0" + "00" * 32],
            },
        ],
    }


def test_find_spender_prefers_the_mempool(tmp_path: Path) -> None:
    _, _, network = _context()
    requests: list[dict[str, Any]] = []
    replies = {
        "gettxspendingprevout": [{"txid": FUNDING_TXID, "vout": 0, "spendingtxid": SPENDER}],
        "getrawtransaction": _spend(),
    }
    with _server(_by_method(replies), requests) as port:
        reader = CoreTransactionReader(port=port, cookie_path=_cookie(tmp_path), network=network)
        scan = reader.find_spender(FUNDING_TXID, 0, from_height=1010, to_height=1020)
    assert scan.spender == SpendObservation(
        SPENDER,
        (
            bytes.fromhex("dd" * 64),
            bytes.fromhex(PREIMAGE),
            b"\x51",
            bytes.fromhex("c0" + "00" * 32),
        ),
        None,
    )
    assert scan.scanned_to == 1009  # nothing was scanned: resume from from_height
    assert requests[0]["params"] == [[{"txid": FUNDING_TXID, "vout": 0}]]
    assert requests[1]["params"] == [SPENDER, True]


def test_find_spender_scans_blocks_in_bounded_batches(tmp_path: Path) -> None:
    _, _, network = _context()
    requests: list[dict[str, Any]] = []
    spend_height = 1010 + MAX_SPEND_SCAN_BLOCKS + 2

    def block(params: list[Any]) -> dict[str, Any]:
        height = int(params[0][:4])
        return {"tx": [_spend()] if height == spend_height else [_spend("ff" * 32)]}

    replies = {
        "gettxspendingprevout": [{"txid": FUNDING_TXID, "vout": 0}],
        "getblockhash": lambda params: f"{params[0]:04d}" + "0" * 60,
        "getblock": block,
    }
    with _server(_by_method(replies), requests) as port:
        reader = CoreTransactionReader(port=port, cookie_path=_cookie(tmp_path), network=network)
        first = reader.find_spender(FUNDING_TXID, 0, from_height=1010, to_height=1100)
        assert first.spender is None
        assert first.scanned_to == 1010 + MAX_SPEND_SCAN_BLOCKS - 1
        second = reader.find_spender(
            FUNDING_TXID, 0, from_height=first.scanned_to + 1, to_height=1100
        )
    assert second.spender is not None
    assert (second.spender.txid, second.spender.height) == (SPENDER, spend_height)
    assert second.spender.witness[1] == bytes.fromhex(PREIMAGE)
    assert second.scanned_to == spend_height
    blocks = [r["params"][1] for r in requests if r["method"] == "getblock"]
    assert blocks == [2] * (MAX_SPEND_SCAN_BLOCKS + 3)
    with _server(
        _by_method({"gettxspendingprevout": [{"txid": FUNDING_TXID, "vout": 0}]}), []
    ) as port:
        reader = CoreTransactionReader(port=port, cookie_path=_cookie(tmp_path), network=network)
        empty = reader.find_spender(FUNDING_TXID, 0, from_height=1010, to_height=1009)
        assert (empty.spender, empty.scanned_to) == (None, 1009)


def test_find_spender_refuses_malformed_witnesses(tmp_path: Path) -> None:
    _, _, network = _context()
    bad = _spend()
    bad["vin"][1]["txinwitness"] = ["zz"]
    replies = {
        "gettxspendingprevout": [{"txid": FUNDING_TXID, "vout": 0, "spendingtxid": SPENDER}],
        "getrawtransaction": bad,
    }
    with _server(_by_method(replies), []) as port:
        reader = CoreTransactionReader(port=port, cookie_path=_cookie(tmp_path), network=network)
        with pytest.raises(CoreProtocolError, match="witness"):
            reader.find_spender(FUNDING_TXID, 0, from_height=1010, to_height=1020)
