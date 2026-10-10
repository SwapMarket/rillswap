"""Explicit POST admission and fixed two-method regtest RPC boundary."""

from __future__ import annotations

import importlib.util
import json
import socket
import sys
import threading
from http.client import HTTPConnection
from pathlib import Path
from unittest.mock import patch

import pytest


def load(name):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).parents[1] / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


chain = load("chain_api")
with patch.dict(sys.modules, {"chain_api": chain}):
    api = load("broadcast_api")

TX = "00" * 60
TXID = "a" * 64


@pytest.fixture
def server():
    class Broadcaster:
        def __init__(self):
            self.calls = []

        def submit(self, body):
            self.calls.append(body)
            return TXID

    with api.BroadcastServer(("127.0.0.1", 0), Broadcaster(), 9092, 9273) as instance:
        thread = threading.Thread(target=instance.serve_forever, daemon=True)
        thread.start()
        yield instance
        instance.shutdown()
        thread.join()


def request(server, body=TX, headers=None, path="/api/tx", method="POST"):
    connection = HTTPConnection(*server.server_address, timeout=2)
    connection.request(
        method,
        path,
        body=body,
        headers={
            "Host": "127.0.0.1:9092",
            "Origin": "http://127.0.0.1:9273",
            "Content-Type": "text/plain",
            **(headers or {}),
        },
    )
    response = connection.getresponse()
    result = response.status, dict(response.getheaders()), response.read()
    connection.close()
    return result


def test_valid_request_submits_once_and_returns_only_txid(server):
    status, headers, body = request(server)
    assert status == 200 and body.decode() == TXID
    assert server.broadcaster.calls == [TX]
    assert headers["Access-Control-Allow-Origin"] == "http://127.0.0.1:9273"
    assert headers["Cache-Control"] == "no-store"


@pytest.mark.parametrize(
    "headers",
    [
        {"Origin": "null"},
        {"Origin": "https://evil.example"},
        {"Host": "localhost:8092"},
        {"Content-Type": "application/json"},
        {"Content-Length": "00120"},
        {"Content-Length": "200001"},
        {"Transfer-Encoding": "chunked"},
    ],
)
def test_bad_headers_make_zero_backend_calls(server, headers):
    assert request(server, headers=headers)[0] in {400, 403}
    assert server.broadcaster.calls == []


@pytest.mark.parametrize("body", ["00", TX + " ", "A" * 120, "0" * 121, "z" * 120, "00" * 100001])
def test_bad_bodies_make_zero_backend_calls(server, body):
    assert request(server, body=body)[0] == 400
    assert server.broadcaster.calls == []


def test_absent_or_duplicate_origin_host_length_are_refused_before_body(server):
    for headers in [
        "Host: 127.0.0.1:9092\r\n",  # No Origin.
        "Host: 127.0.0.1:9092\r\nOrigin: http://127.0.0.1:9273\r\nOrigin: http://127.0.0.1:9273\r\n",
        "Host: 127.0.0.1:9092\r\nHost: localhost:9092\r\nOrigin: http://127.0.0.1:9273\r\n",
        "Host: 127.0.0.1:9092\r\nOrigin: http://127.0.0.1:9273\r\nContent-Length: 120\r\n",
    ]:
        with socket.create_connection(server.server_address, timeout=2) as connection:
            connection.sendall(
                (
                    "POST /api/tx HTTP/1.1\r\n"
                    + headers
                    + "Content-Length: 120\r\nContent-Type: text/plain\r\n\r\n"
                ).encode()
            )
            response = connection.recv(4096)
            assert b" 400 " in response or b" 403 " in response
    assert server.broadcaster.calls == []


@pytest.mark.parametrize("path", ["/api/tx?x=1", "/api/tx/", "/api/sendrawtransaction"])
def test_no_arbitrary_route(server, path):
    assert request(server, path=path)[0] == 404
    assert server.broadcaster.calls == []


@pytest.mark.parametrize(
    "preflight",
    [
        None,
        [],
        [{"allowed": False}],
        [{"allowed": 1, "txid": TXID}],
        [{"allowed": True, "txid": "bad"}],
        [{"allowed": True, "txid": TXID}] * 2,
    ],
)
def test_preflight_failure_never_sends(monkeypatch, preflight):
    broadcaster = api.Broadcaster()
    monkeypatch.setattr(broadcaster.reader, "observe", lambda _: chain.GENESIS)
    calls = []
    monkeypatch.setattr(
        broadcaster, "_call", lambda method, params: calls.append((method, params)) or preflight
    )
    with pytest.raises(api.BroadcastUnavailable):
        broadcaster.submit(TX)
    assert calls == [("testmempoolaccept", [[TX], 0.1])]


def test_valid_flow_uses_fixed_fee_and_burn_bounds_once(monkeypatch):
    broadcaster = api.Broadcaster()
    monkeypatch.setattr(broadcaster.reader, "observe", lambda _: chain.GENESIS)
    calls = []

    def call(method, params):
        calls.append((method, params))
        return [{"allowed": True, "txid": TXID}] if method == "testmempoolaccept" else TXID

    monkeypatch.setattr(broadcaster, "_call", call)
    assert broadcaster.submit(TX) == TXID
    assert calls == [("testmempoolaccept", [[TX], 0.1]), ("sendrawtransaction", [TX, 0.1, 0])]


def test_wrong_network_or_mismatched_submission_is_unavailable_without_retry(monkeypatch):
    broadcaster = api.Broadcaster()
    calls = []
    monkeypatch.setattr(
        broadcaster.reader, "observe", lambda _: (_ for _ in ()).throw(chain.ChainUnavailable())
    )
    monkeypatch.setattr(broadcaster, "_call", lambda method, params: calls.append(method))
    with pytest.raises(api.BroadcastUnavailable):
        broadcaster.submit(TX)
    assert calls == []
    monkeypatch.setattr(broadcaster.reader, "observe", lambda _: chain.GENESIS)
    monkeypatch.setattr(
        broadcaster,
        "_call",
        lambda method, params: (
            calls.append(method)
            or ([{"allowed": True, "txid": TXID}] if method == "testmempoolaccept" else "b" * 64)
        ),
    )
    with pytest.raises(api.BroadcastUnavailable):
        broadcaster.submit(TX)
    assert calls == ["testmempoolaccept", "sendrawtransaction"]


def test_rpc_allowlist_and_response_bound(monkeypatch):
    broadcaster = api.Broadcaster()
    with pytest.raises(api.BroadcastUnavailable):
        broadcaster._call("getblockchaininfo", [])

    class Response:
        status = 200
        body = json.dumps({"id": 1, "result": TXID, "error": None}).encode()

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return None

        def read(self, limit):
            return self.body[:limit]

    response = Response()
    monkeypatch.setattr(broadcaster.opener, "open", lambda *args, **kwargs: response)
    assert broadcaster._call("sendrawtransaction", [TX, 0.1, 0]) == TXID
    for invalid in [
        b"a" * 16385,
        b'{"id":true,"result":"' + TXID.encode() + b'"}',
        b'{"id":1,"error":{"message":"secret"}}',
        b'{"id":1,"id":1,"result":null}',
        b'{"id":1,"result":NaN}',
        b'{"id":1,"result":Infinity}',
        b'{"id":1,"error":false}',
    ]:
        response.body = invalid
        with pytest.raises(api.BroadcastUnavailable):
            broadcaster._call("sendrawtransaction", [TX, 0.1, 0])


def test_lost_response_after_send_never_retries(monkeypatch):
    broadcaster = api.Broadcaster()
    monkeypatch.setattr(broadcaster.reader, "observe", lambda _: chain.GENESIS)
    calls = []

    def call(method, params):
        calls.append((method, params))
        if method == "testmempoolaccept":
            return [{"allowed": True, "txid": TXID}]
        raise api.BroadcastUnavailable("synthetic response loss")

    monkeypatch.setattr(broadcaster, "_call", call)
    with pytest.raises(api.BroadcastUnavailable):
        broadcaster.submit(TX)
    assert calls == [("testmempoolaccept", [[TX], 0.1]), ("sendrawtransaction", [TX, 0.1, 0])]
