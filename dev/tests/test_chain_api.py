"""Narrow HTTP and RPC boundary tests for disposable regtest observations."""

from __future__ import annotations

import importlib.util
import json
import socket
import threading
from decimal import Decimal
from http.client import HTTPConnection
from pathlib import Path

import pytest

SPEC = importlib.util.spec_from_file_location(
    "chain_api", Path(__file__).parents[1] / "chain_api.py"
)
assert SPEC and SPEC.loader
api = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(api)


@pytest.fixture
def server():
    class Reader:
        def __init__(self):
            self.calls = []
            self.fail = False

        def observe(self, path):
            self.calls.append(path)
            if self.fail:
                raise api.ChainUnavailable("backend secrets must not leak")
            return "100"

    with api.ChainServer(("127.0.0.1", 0), Reader(), 9091, 9273) as instance:
        thread = threading.Thread(target=instance.serve_forever, daemon=True)
        thread.start()
        yield instance
        instance.shutdown()
        thread.join()


def request(server, method="GET", path="/api/blocks/tip/height", headers=None, body=None):
    connection = HTTPConnection(*server.server_address, timeout=2)
    connection.request(
        method, path, body=body, headers={"Host": "127.0.0.1:9091", **(headers or {})}
    )
    response = connection.getresponse()
    result = response.status, dict(response.getheaders()), response.read()
    connection.close()
    return result


def test_allowed_cors_and_local_probes(server):
    for path in [
        "/api/block-height/0",
        "/api/blocks/tip/height",
        "/api/blocks/tip/hash",
        "/api/v1/fees/recommended",
        "/api/block-height/100",
        f"/api/tx/{'a' * 64}/hex",
        f"/api/tx/{'a' * 64}/status",
        f"/api/tx/{'a' * 64}/outspend/0",
    ]:
        status, headers, body = request(
            server, path=path, headers={"Origin": "http://127.0.0.1:9273"}
        )
        assert status == 200 and body == b"100"
        assert headers["Access-Control-Allow-Origin"] == "http://127.0.0.1:9273"
        assert headers["Cache-Control"] == "no-store"
        assert "Access-Control-Allow-Credentials" not in headers
    assert request(server)[0] == 200


@pytest.mark.parametrize(
    "origin",
    ["null", "https://evil.example", "http://127.0.0.1:5273", "http://localhost:9273.evil"],
)
def test_hostile_origins_never_reach_core(server, origin):
    assert request(server, headers={"Origin": origin})[0] == 403
    assert server.reader.calls == []


@pytest.mark.parametrize("host", ["evil.example:9091", "127.0.0.1:8091", "localhost:9091.evil"])
def test_hostile_hosts_never_reach_core(server, host):
    assert request(server, headers={"Host": host})[0] == 403
    assert server.reader.calls == []


@pytest.mark.parametrize(
    "header",
    ["Origin: http://127.0.0.1:9273\r\nOrigin: http://127.0.0.1:9273", "Host: 127.0.0.1:9091"],
)
def test_duplicate_host_and_origin_headers_are_refused(server, header):
    with socket.create_connection(server.server_address, timeout=2) as connection:
        connection.sendall(
            (
                f"GET /api/blocks/tip/hash HTTP/1.1\r\nHost: 127.0.0.1:9091\r\n{header}\r\n\r\n"
            ).encode()
        )
        assert b"403" in connection.recv(4096).split(b"\r\n")[0]
    assert server.reader.calls == []


@pytest.mark.parametrize(
    "path",
    [
        "/",
        "/api/blocks/tip/hash?x=1",
        "/api/tx",
        "/wallet/test",
        "/api/block-height/01",
        "/api/block-height/500000000",
        "/api/block-height/" + "1" * 1000,
        f"/api/tx/{'A' * 64}/hex",
        f"/api/tx/{'a' * 63}/hex",
        f"/api/tx/{'a' * 64}/hex?x=1",
        f"/api/tx/{'a' * 64}/outspend/01",
        f"/api/tx/{'a' * 64}/outspend/4294967296",
        f"/api/tx/{'a' * 64}/outspend/" + "1" * 1000,
        f"/api/tx/{'a' * 64}%2fhex",
        "/api/block-height/%30",
        "/api/tx/../../wallet/test",
        "/api/v1/fees/recommended/",
        "/api/v1/fees/recommended?x=1",
        "/api/v1/fees/precise",
    ],
)
def test_routes_are_exact_and_read_only(server, path):
    assert request(server, path=path)[0] == 404
    assert server.reader.calls == []


@pytest.mark.parametrize("method", ["POST", "PUT", "PATCH", "DELETE", "OPTIONS"])
def test_unsupported_methods_never_reach_core(server, method):
    assert request(server, method=method)[0] == 405
    assert server.reader.calls == []


@pytest.mark.parametrize(
    "headers", [{"Content-Length": "0"}, {"Content-Length": "1"}, {"Transfer-Encoding": "chunked"}]
)
def test_request_bodies_are_refused(server, headers):
    assert request(server, headers=headers)[0] == 400
    assert server.reader.calls == []


def test_backend_failure_is_sanitized(server):
    server.reader.fail = True
    status, headers, body = request(server, headers={"Origin": "http://localhost:9273"})
    assert status == 503 and body == b"Regtest chain observation unavailable"
    assert headers["Access-Control-Allow-Origin"] == "http://localhost:9273"


def test_reader_checks_network_genesis_and_tip_each_time(monkeypatch):
    reader = api.ChainReader()
    info = {"chain": "regtest", "blocks": 100, "bestblockhash": "a" * 64}
    calls = []

    def call(method, params):
        calls.append((method, params))
        return info if method == "getblockchaininfo" else api.GENESIS

    monkeypatch.setattr(reader, "_call", call)
    assert reader.observe("/api/blocks/tip/height") == "100"
    assert calls == [("getblockchaininfo", []), ("getblockhash", [0])]
    for invalid in [
        {**info, "chain": "main"},
        {**info, "blocks": True},
        {**info, "blocks": -1},
        {**info, "bestblockhash": "bad"},
    ]:
        monkeypatch.setattr(
            reader,
            "_call",
            lambda method, params, invalid=invalid: (
                invalid if method == "getblockchaininfo" else api.GENESIS
            ),
        )
        with pytest.raises(api.ChainUnavailable):
            reader.observe("/api/blocks/tip/hash")
    monkeypatch.setattr(
        reader, "_call", lambda method, params: info if method == "getblockchaininfo" else "f" * 64
    )
    with pytest.raises(api.ChainUnavailable):
        reader.observe("/api/block-height/0")


def test_rpc_response_bounds_timeout_and_redirects(monkeypatch):
    reader = api.ChainReader()

    class Response:
        status = 200

        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def read(self, limit):
            assert limit == 16385
            return b"x" * limit

    def oversized(request, timeout):
        assert request.full_url == api.CORE_URL and timeout == 3
        return Response()

    monkeypatch.setattr(reader.opener, "open", oversized)
    with pytest.raises(api.ChainUnavailable):
        reader.observe("/api/blocks/tip/hash")
    monkeypatch.setattr(
        reader.opener, "open", lambda *args, **kwargs: (_ for _ in ()).throw(TimeoutError())
    )
    with pytest.raises(api.ChainUnavailable):
        reader.observe("/api/blocks/tip/hash")
    with pytest.raises(api.ChainUnavailable):
        api.NoRedirect().redirect_request(None, None, 302, "redirect", None, "http://evil")
    proxies = [handler for handler in reader.opener.handlers if hasattr(handler, "proxies")]
    assert all(handler.proxies == {} for handler in proxies)


@pytest.fixture
def reader_samples(monkeypatch):
    reader = api.ChainReader()
    txid, block, tip = "b" * 64, "c" * 64, "a" * 64
    output = {
        "bestblock": tip,
        "confirmations": 2,
        "value": Decimal("0.00100000"),
        "scriptPubKey": {"hex": "5120" + "d" * 64},
        "coinbase": False,
    }
    samples = {
        ("getblockchaininfo", ()): {"chain": "regtest", "blocks": 100, "bestblockhash": tip},
        ("getblockhash", (0,)): api.GENESIS,
        ("getblockhash", (99,)): block,
        ("getblockhash", (100,)): tip,
        ("getrawtransaction", (txid, False)): "00" * 60,
        ("getrawtransaction", (txid, True)): {
            "txid": txid,
            "hex": "00" * 60,
            "blockhash": block,
            "confirmations": 2,
        },
        ("getblockheader", (block, True)): {
            "hash": block,
            "height": 99,
            "confirmations": 2,
            "time": 1700000000,
        },
        ("gettxout", (txid, 0, False)): output,
        ("gettxout", (txid, 0, True)): {**output, "scriptPubKey": dict(output["scriptPubKey"])},
    }
    calls = []

    def call(method, params):
        key = method, tuple(params)
        calls.append(key)
        if key not in samples:
            raise api.ChainUnavailable()
        return samples[key]

    monkeypatch.setattr(reader, "_call", call)
    return reader, samples, calls, txid


def test_transaction_routes_project_only_chain_observations(reader_samples):
    reader, samples, calls, txid = reader_samples
    assert reader.observe(f"/api/tx/{txid}/hex") == "00" * 60
    assert json.loads(reader.observe(f"/api/tx/{txid}/status")) == {
        "confirmed": True,
        "block_height": 99,
        "block_hash": "c" * 64,
        "block_time": 1700000000,
    }
    assert json.loads(reader.observe(f"/api/tx/{txid}/outspend/0")) == {"spent": False}
    assert reader.observe("/api/block-height/99") == "c" * 64
    assert all(method in api.RPC_METHODS for method, _ in calls)
    assert ("gettxout", (txid, 0, False)) in calls and ("gettxout", (txid, 0, True)) in calls


def test_regtest_fees_are_fixed_after_the_network_check(reader_samples):
    reader, samples, calls, _txid = reader_samples
    fees = json.loads(reader.observe("/api/v1/fees/recommended"))
    assert fees == {
        "fastestFee": 1,
        "halfHourFee": 1,
        "hourFee": 1,
        "economyFee": 1,
        "minimumFee": 1,
    }
    assert calls == [("getblockchaininfo", ()), ("getblockhash", (0,))]  # no fee RPC
    samples[("getblockhash", (0,))] = "f" * 64
    with pytest.raises(api.ChainUnavailable):
        reader.observe("/api/v1/fees/recommended")


def test_unconfirmed_and_stale_transaction_status(reader_samples):
    reader, samples, _, txid = reader_samples
    samples["getrawtransaction", (txid, True)] = {"txid": txid, "hex": "00" * 60}
    assert json.loads(reader.observe(f"/api/tx/{txid}/status")) == {"confirmed": False}
    samples["getrawtransaction", (txid, True)] = {
        "txid": txid,
        "hex": "00" * 60,
        "blockhash": "c" * 64,
        "confirmations": 0,
    }
    assert json.loads(reader.observe(f"/api/tx/{txid}/status")) == {"confirmed": False}


@pytest.mark.parametrize("value", [None, "00" * 59, "00" * 60 + "0", "AA" * 60, "00" * 100001])
def test_raw_transaction_bounds_and_spelling(reader_samples, value):
    reader, samples, _, txid = reader_samples
    samples["getrawtransaction", (txid, False)] = value
    with pytest.raises(api.ChainUnavailable):
        reader.observe(f"/api/tx/{txid}/hex")


def test_raw_transaction_limit_is_inclusive(reader_samples):
    reader, samples, _, txid = reader_samples
    samples["getrawtransaction", (txid, False)] = "00" * 100000
    assert len(reader.observe(f"/api/tx/{txid}/hex")) == 200000


@pytest.mark.parametrize(
    "changes",
    [
        {"txid": "f" * 64},
        {"hex": "bad"},
        {"confirmations": True},
        {"confirmations": -1},
        {"confirmations": 3},
        {"blockhash": "bad"},
        {"blockhash": None},
    ],
)
def test_invalid_transaction_status_is_unknown(reader_samples, changes):
    reader, samples, _, txid = reader_samples
    samples["getrawtransaction", (txid, True)].update(changes)
    with pytest.raises(api.ChainUnavailable):
        reader.observe(f"/api/tx/{txid}/status")


@pytest.mark.parametrize(
    "changes",
    [
        {"height": True},
        {"height": 101},
        {"confirmations": -1},
        {"confirmations": 3},
        {"hash": "e" * 64},
        {"time": -1},
    ],
)
def test_invalid_or_reorganized_inclusion_is_unknown(reader_samples, changes):
    reader, samples, _, txid = reader_samples
    samples["getblockheader", ("c" * 64, True)].update(changes)
    with pytest.raises(api.ChainUnavailable):
        reader.observe(f"/api/tx/{txid}/status")


@pytest.mark.parametrize("height", [99, 100])
def test_changed_inclusion_or_tip_hash_is_unknown(reader_samples, height):
    reader, samples, _, txid = reader_samples
    samples["getblockhash", (height,)] = "e" * 64
    with pytest.raises(api.ChainUnavailable):
        reader.observe(f"/api/tx/{txid}/status")


@pytest.mark.parametrize(
    "chain,mempool", [(None, None), (None, {"confirmations": 0}), ("valid", None)]
)
def test_null_nonexistent_unconfirmed_or_spent_samples_never_prove_unspent(
    reader_samples, chain, mempool
):
    reader, samples, _, txid = reader_samples
    if chain != "valid":
        samples["gettxout", (txid, 0, False)] = chain
    samples["gettxout", (txid, 0, True)] = mempool
    with pytest.raises(api.ChainUnavailable):
        reader.observe(f"/api/tx/{txid}/outspend/0")


@pytest.mark.parametrize(
    "changes",
    [
        {"bestblock": "e" * 64},
        {"confirmations": 0},
        {"confirmations": True},
        {"confirmations": 3},
        {"value": Decimal("0.00100001")},
        {"scriptPubKey": {"hex": "5120" + "e" * 64}},
        {"coinbase": True},
    ],
)
def test_changed_tip_or_output_between_utxo_reads_is_unknown(reader_samples, changes):
    reader, samples, _, txid = reader_samples
    samples["gettxout", (txid, 0, True)].update(changes)
    with pytest.raises(api.ChainUnavailable):
        reader.observe(f"/api/tx/{txid}/outspend/0")


@pytest.mark.parametrize(
    "changes",
    [
        {"value": True},
        {"value": 0.001},
        {"value": "0.00100000"},
        {"value": Decimal("NaN")},
        {"value": Decimal("Infinity")},
        {"value": Decimal("-1")},
        {"value": Decimal("21000001")},
        {"value": Decimal("0.000000001")},
        {"value": Decimal("1.0000000000000000000000000000000000001")},
        {"value": Decimal("1e-1000000")},
        {"scriptPubKey": {}},
        {"scriptPubKey": {"hex": "0"}},
        {"scriptPubKey": {"hex": "AA"}},
        {"coinbase": 0},
    ],
)
def test_malformed_or_inexact_utxo_data_is_unknown(reader_samples, changes):
    reader, samples, _, txid = reader_samples
    samples["gettxout", (txid, 0, False)].update(changes)
    with pytest.raises(api.ChainUnavailable):
        reader.observe(f"/api/tx/{txid}/outspend/0")


def test_invalid_route_never_calls_reader_rpc(reader_samples):
    reader, _, calls, txid = reader_samples
    for path in [
        "/api/block-height/01",
        "/api/block-height/500000000",
        f"/api/tx/{txid}/outspend/4294967296",
    ]:
        with pytest.raises(api.ChainUnavailable):
            reader.observe(path)
    assert calls == []


@pytest.mark.parametrize(
    "method,limit", [("getblockchaininfo", 16384), ("getrawtransaction", 4 * 1024 * 1024)]
)
def test_rpc_limits_are_method_specific(monkeypatch, method, limit):
    reader = api.ChainReader()

    class Response:
        status = 200
        body = b"x" * (limit + 1)

        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def read(self, length):
            assert length == limit + 1
            return self.body

    response = Response()
    monkeypatch.setattr(reader.opener, "open", lambda *args, **kwargs: response)
    with pytest.raises(api.ChainUnavailable):
        reader._call(method, [])
    # Valid JSON padded to the exact cap is accepted, not silently truncated.
    valid = b'{"id":1,"result":"ok","error":null}'
    response.body = valid + b" " * (limit - len(valid))
    assert reader._call(method, []) == "ok"


def test_rpc_decimal_decode_and_invalid_envelope(monkeypatch):
    reader = api.ChainReader()

    class Response:
        status = 200
        body = b'{"id":1,"result":{"value":0.00000001},"error":null}'

        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def read(self, limit):
            return self.body

    response = Response()
    monkeypatch.setattr(reader.opener, "open", lambda *args, **kwargs: response)
    assert reader._call("gettxout", ["a" * 64, 0, True])["value"] == Decimal("0.00000001")
    for invalid in [
        b'{"id":true,"result":null}',
        b'{"id":1,"result":NaN}',
        b'{"id":1,"result":Infinity}',
    ]:
        response.body = invalid
        with pytest.raises(api.ChainUnavailable):
            reader._call("gettxout", [])
    with pytest.raises(api.ChainUnavailable):
        reader._call("sendrawtransaction", ["00"])
