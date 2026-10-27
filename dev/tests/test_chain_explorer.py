"""The local explorer renders observations, never signing or wallet authority."""

from __future__ import annotations

from decimal import Decimal

import pytest
import test_chain_api as chain_tests

api = chain_tests.api
server = chain_tests.server
request = chain_tests.request


@pytest.fixture
def transaction_reader(monkeypatch):
    reader = api.ChainReader()
    txid, block, tip = "c" * 64, "b" * 64, "a" * 64
    transaction = {
        "txid": txid,
        "hex": "00" * 60,
        "blockhash": block,
        "confirmations": 2,
        "vsize": 142,
        "vin": [{"txid": "d" * 64, "vout": 1}],
        "vout": [
            {
                "n": 0,
                "value": Decimal("0.00100150"),
                "scriptPubKey": {"hex": "5120" + "e" * 64, "address": "bcrt1ptest-address"},
            },
            {"n": 1, "value": Decimal("0.99899850"), "scriptPubKey": {"hex": "0014" + "f" * 40}},
        ],
    }
    info = {"chain": "regtest", "blocks": 2, "bestblockhash": tip}
    calls = []

    def call(method, params, *, deadline=None):
        calls.append((method, params))
        if method == "getblockchaininfo":
            return info
        if method == "getblockhash":
            return {0: api.GENESIS, 1: block, 2: tip}[params[0]]
        if method == "getrawtransaction":
            if params[0] != txid:
                raise api.ChainUnavailable("private upstream error")
            return transaction
        if method == "getblockheader":
            return {"hash": block, "height": 1, "confirmations": 2, "time": 1700000000}
        raise api.ChainUnavailable()

    monkeypatch.setattr(reader, "_call", call)
    return reader, transaction, info, calls


def test_explorer_summary_status_and_read_only_headers(server, transaction_reader):
    reader, tx, _info, calls = transaction_reader
    server.reader = reader
    status, headers, body = request(server, path=f"/tx/{tx['txid']}")
    assert status == 200
    assert headers["Content-Type"] == "text/html; charset=utf-8"
    assert headers["Cache-Control"] == "no-store"
    assert "default-src 'none'" in headers["Content-Security-Policy"]
    assert b"2 confirmation(s), block 1" in body
    assert b"0.00100150 BTC" in body
    assert b"Total outputs (including change): 1.00000000 BTC" in body
    assert b"Size: 142 vB" in body
    assert b"Refresh status" in body
    assert len(calls) == 6
    assert sum(method == "getrawtransaction" for method, _ in calls) == 1


@pytest.mark.parametrize("stale", [False, True])
def test_explorer_never_labels_stale_or_unknown_inclusion_confirmed(transaction_reader, stale):
    reader, tx, _info, _calls = transaction_reader
    if stale:
        tx["confirmations"] = 0
    else:
        del tx["confirmations"], tx["blockhash"]
    html = reader.observe(f"/tx/{tx['txid']}")
    assert "Not confirmed on the active chain" in html
    assert "in mempool" not in html


def test_explorer_escapes_backend_labels_and_supports_coinbase(transaction_reader):
    reader, tx, _info, _calls = transaction_reader
    tx["vout"][0]["scriptPubKey"]["address"] = '<script>alert("x")</script>'
    tx["vin"] = [{"coinbase": "00"}]
    html = reader.observe(f"/tx/{tx['txid']}")
    assert "<script>" not in html
    assert "&lt;script&gt;" in html
    assert "<li>Coinbase</li>" in html


def test_explorer_unavailable_does_not_invent_a_confirmation_state(server, transaction_reader):
    reader, _tx, _info, _calls = transaction_reader
    server.reader = reader
    status, _headers, body = request(server, path=f"/tx/{'f' * 64}")
    assert status == 503
    assert b"private upstream error" not in body
    assert b"unconfirmed" not in body


@pytest.mark.parametrize(
    "path",
    [
        "/tx/" + "A" * 64,
        "/tx/" + "a" * 63,
        "/tx/" + "a" * 64 + "?x=1",
        "/tx/%2f",
        "/api/address/bcrt1bad%2f/txs",
        "/api/address/bcrt1badaddr/txs?x=1",
    ],
)
def test_new_routes_reject_malformed_targets_before_core(server, path):
    assert request(server, path=path)[0] == 404
    assert server.reader.calls == []


@pytest.mark.parametrize(
    "variation",
    ["amount precision", "amount float", "huge output list", "Boolean vsize", "wrong index"],
)
def test_explorer_rejects_malformed_transaction_details(transaction_reader, variation):
    reader, tx, _info, _calls = transaction_reader
    if variation == "amount precision":
        tx["vout"][0]["value"] = Decimal("0.000000001")
    elif variation == "amount float":
        tx["vout"][0]["value"] = 0.00100150
    elif variation == "huge output list":
        tx["vout"] *= 501
    elif variation == "Boolean vsize":
        tx["vsize"] = True
    else:
        tx["vout"][0]["n"] = True
    with pytest.raises(api.ChainUnavailable):
        reader.observe(f"/tx/{tx['txid']}")


def test_explorer_bounds_rendered_output_rows(transaction_reader):
    reader, tx, _info, _calls = transaction_reader
    tx["vout"] = [{"n": n, "value": 0, "scriptPubKey": {"hex": ""}} for n in range(101)]
    html = reader.observe(f"/tx/{tx['txid']}")
    assert "Showing the first 100 inputs and outputs" in html
    assert html.count("<tr>") == 101
