"""Narrow HTTP and RPC boundary tests for disposable regtest observations."""

from __future__ import annotations

import importlib.util
import socket
import threading
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
    for path in api.ROUTES:
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
    "path", ["/", "/api/blocks/tip/hash?x=1", "/api/tx", "/wallet/test", "/api/block-height/1"]
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
