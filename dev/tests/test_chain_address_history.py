"""Full active regtest history is explicit and bounded, never a persistent index."""

from __future__ import annotations

import json
import time
from decimal import Decimal

import pytest
import test_chain_api as chain_tests
import test_chain_explorer as explorer_tests

api = chain_tests.api
transaction_reader = explorer_tests.transaction_reader
ADDRESS = "bcrt1ptest-address"
PATH = "/api/address/bcrt1testaddress/txs"


@pytest.fixture
def history_reader(monkeypatch, transaction_reader):
    reader, tx, info, calls = transaction_reader
    events = [
        {
            "type": "receive",
            "txid": tx["txid"],
            "vout": 0,
            "amount": Decimal("0.00100150"),
            "output_spk": tx["vout"][0]["scriptPubKey"],
            "height": 1,
            "blockhash": "b" * 64,
        }
    ]
    original = reader._call
    batches = []

    def call(method, params, *, deadline=None):
        if method == "getdescriptoractivity":
            calls.append((method, params))
            assert params == [["b" * 64, "a" * 64], ["addr(bcrt1testaddress)"], True]
            return {"activity": events}
        return original(method, params, deadline=deadline)

    def hashes(start, stop, deadline):
        batches.append((start, stop))
        return ["b" * 64, "a" * 64]

    monkeypatch.setattr(reader, "_call", call)
    monkeypatch.setattr(reader, "_block_hashes", hashes)
    return reader, tx, info, calls, events, batches


def test_address_history_finds_exact_confirmed_and_spent_receives(history_reader):
    reader, tx, _info, calls, events, batches = history_reader
    # An output having been spent does not erase the original receive.
    events.append({"type": "spend", "prevout_txid": tx["txid"], "prevout_vout": 0})
    result = json.loads(reader.observe(PATH))
    assert len(result) == 1
    assert result[0]["txid"] == tx["txid"]
    assert result[0]["vout"][0] == {
        "scriptpubkey": tx["vout"][0]["scriptPubKey"]["hex"],
        "value": 100150,
    }
    assert result[0]["status"]["confirmed"] is True
    assert batches == [(1, 2)]
    assert {method for method, _ in calls} <= api.RPC_METHODS


def test_multiple_receive_events_for_one_transaction_are_deduplicated(history_reader):
    reader, tx, _info, _calls, events, _batches = history_reader
    tx["vout"][1]["scriptPubKey"] = tx["vout"][0]["scriptPubKey"]
    events.append({**events[0], "vout": 1, "amount": tx["vout"][1]["value"]})
    assert len(json.loads(reader.observe(PATH))) == 1


def test_mempool_receive_is_not_confirmed(history_reader):
    reader, tx, _info, _calls, events, _batches = history_reader
    del tx["blockhash"], tx["confirmations"], events[0]["blockhash"], events[0]["height"]
    assert json.loads(reader.observe(PATH))[0]["status"] == {"confirmed": False}


@pytest.mark.parametrize("event_confirmed", [False, True])
def test_event_and_hydrated_inclusion_must_agree(history_reader, event_confirmed):
    reader, tx, _info, _calls, events, _batches = history_reader
    if event_confirmed:
        tx["confirmations"] = 0
    else:
        del events[0]["blockhash"], events[0]["height"]
    with pytest.raises(api.ChainUnavailable):
        reader.observe(PATH)


def test_history_enumerates_every_active_block_and_mempool_once(monkeypatch):
    reader = api.ChainReader()
    tip = f"{513:064x}"
    batches, scans = [], []

    def post(payload, _limit, timeout=3, deadline=None):
        assert 0 < deadline - time.monotonic() <= api.ACTIVITY_SECONDS
        heights = [item["params"][0] for item in payload]
        batches.append(heights)
        return [{"id": height, "result": f"{height:064x}"} for height in heights]

    def call(method, params, *, deadline=None):
        if method == "getblockchaininfo":
            return {"chain": "regtest", "blocks": 513, "bestblockhash": tip}
        if method == "getblockhash":
            assert params == [0]
            return api.GENESIS
        assert method == "getdescriptoractivity"
        scans.append(params)
        return {"activity": []}

    monkeypatch.setattr(reader, "_post", post)
    monkeypatch.setattr(reader, "_call", call)
    assert json.loads(reader.observe(PATH)) == []
    assert [height for batch in batches for height in batch] == list(range(1, 514))
    assert [len(batch) for batch in batches] == [256, 256, 1]
    assert [scan[2] for scan in scans] == [False, False, True]
    assert all(scan[1] == ["addr(bcrt1testaddress)"] for scan in scans)


def test_event_bound_applies_across_batches(monkeypatch):
    reader = api.ChainReader()
    monkeypatch.setattr(reader, "_block_hashes", lambda *_args: ["a" * 64] * 256)
    scans = []

    def call(method, params, *, deadline=None):
        assert method == "getdescriptoractivity"
        scans.append(params)
        return {"activity": [{"type": "spend"}] * 400}

    monkeypatch.setattr(reader, "_call", call)
    with pytest.raises(api.ChainUnavailable):
        reader.address_history("bcrt1testaddress", 768, "a" * 64)
    assert len(scans) == 3


def test_oversized_transaction_history_never_returns_partial_results(history_reader):
    reader, _tx, _info, calls, events, _batches = history_reader
    event = events.pop()
    events.extend({**event, "txid": f"{n:064x}"} for n in range(101))
    with pytest.raises(api.ChainUnavailable):
        reader.observe(PATH)
    assert not any(method == "getrawtransaction" for method, _ in calls)


@pytest.mark.parametrize(
    "variation",
    ["script", "amount", "event block", "event height", "Boolean height", "missing output"],
)
def test_inconsistent_activity_is_unavailable_not_an_empty_history(history_reader, variation):
    reader, _tx, _info, _calls, events, _batches = history_reader
    if variation == "script":
        events[0]["output_spk"] = {"hex": "5120" + "f" * 64}
    elif variation == "amount":
        events[0]["amount"] = Decimal("0.00100151")
    elif variation == "event block":
        events[0]["blockhash"] = "f" * 64
    elif variation == "event height":
        events[0]["height"] = 3
    elif variation == "Boolean height":
        events[0]["height"] = True
    else:
        events[0]["vout"] = 10
    with pytest.raises(api.ChainUnavailable):
        reader.observe(PATH)


def test_address_scan_rechecks_tip_and_has_no_startup_work(monkeypatch, history_reader):
    reader, _tx, info, calls, _events, _batches = history_reader
    assert calls == []
    original = reader._call

    def changed(method, params, **kwargs):
        value = original(method, params, **kwargs)
        if method == "getblockchaininfo" and len(calls) > 2:
            return {**info, "bestblockhash": "f" * 64}
        return value

    monkeypatch.setattr(reader, "_call", changed)
    with pytest.raises(api.ChainUnavailable):
        reader.observe(PATH)


def test_concurrent_or_oversized_scans_refuse_without_activity_work(history_reader):
    reader, _tx, info, calls, _events, batches = history_reader
    reader._activity_lock.acquire()
    try:
        with pytest.raises(api.ChainUnavailable):
            reader.observe(PATH)
    finally:
        reader._activity_lock.release()
    info["blocks"] = api.MAX_ADDRESS_BLOCKS + 1
    with pytest.raises(api.ChainUnavailable):
        reader.observe(PATH)
    assert batches == []
    assert not any(method == "getdescriptoractivity" for method, _ in calls)


def test_failed_core_activity_query_never_becomes_empty_history(monkeypatch, history_reader):
    reader, *_rest = history_reader
    original = reader._call

    def failed(method, params, **kwargs):
        if method == "getdescriptoractivity":
            raise api.ChainUnavailable()
        return original(method, params, **kwargs)

    monkeypatch.setattr(reader, "_call", failed)
    with pytest.raises(api.ChainUnavailable):
        reader.observe(PATH)


def test_rpc_batch_is_fixed_bounded_and_correlated(monkeypatch):
    reader = api.ChainReader()
    sent = []

    def post(payload, limit, timeout=3, deadline=None):
        sent.append(payload)
        assert limit == 128 * 1024
        return [
            {"id": item["id"], "result": f"{item['id']:064x}", "error": None}
            for item in reversed(payload)
        ]

    monkeypatch.setattr(reader, "_post", post)
    assert reader._block_hashes(1, 2, time.monotonic() + 1) == [f"{1:064x}", f"{2:064x}"]
    assert sent == [
        [{"jsonrpc": "2.0", "id": n, "method": "getblockhash", "params": [n]} for n in (1, 2)]
    ]
    for start, stop in [(0, 1), (1, 257), (2, 1)]:
        with pytest.raises(api.ChainUnavailable):
            reader._block_hashes(start, stop, time.monotonic() + 1)


@pytest.mark.parametrize(
    "result",
    [[{"id": 1, "result": "a" * 64}] * 2, [{"id": True, "result": "a" * 64}], [], {"result": []}],
)
def test_rpc_batch_refuses_partial_duplicate_and_malformed_replies(monkeypatch, result):
    reader = api.ChainReader()
    monkeypatch.setattr(reader, "_post", lambda *_args, **_kwargs: result)
    with pytest.raises(api.ChainUnavailable):
        reader._block_hashes(1, 2, time.monotonic() + 1)


def test_expired_query_and_unwhitelisted_rpc_never_open_a_connection(monkeypatch):
    reader = api.ChainReader()
    monkeypatch.setattr(
        reader.opener, "open", lambda *_args, **_kwargs: pytest.fail("unexpected RPC")
    )
    with pytest.raises(api.ChainUnavailable):
        reader._post([], 100, deadline=time.monotonic() - 1)
    with pytest.raises(api.ChainUnavailable):
        reader._call("sendrawtransaction", ["00"])
    assert {
        "getblockhash",
        "getblockchaininfo",
        "getrawtransaction",
        "getblockheader",
        "gettxout",
        "getdescriptoractivity",
    } == api.RPC_METHODS
