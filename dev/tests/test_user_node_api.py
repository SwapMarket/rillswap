"""Regtest-only transport admission, fixed operations, and incremental stream forwarding."""

from __future__ import annotations

import importlib.util
import json
import ssl
import subprocess
import sys
import threading
from http.client import HTTPConnection, HTTPSConnection
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
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
    api = load("user_node_api")
KEY = "02" + "11" * 32
NETWORK = {
    "family": "bitcoin",
    "name": "regtest",
    "genesis_hash": chain.GENESIS,
    "deployment_namespace": "rillswap-e2e-v1",
}


@pytest.fixture
def server():
    class Node:
        macaroon = "00aa"
        calls = []
        fail = False

        def attest(self):
            self.calls.append("attest")
            if self.fail:
                raise api.NodeUnavailable()

        def configuration(self):
            self.attest()
            return json.dumps(
                {"macaroon": self.macaroon, "network_identity": NETWORK, "node_identity": KEY}
            ).encode()

        def open(self, method, path, body):
            self.calls.append((method, path, body))

            class Connection:
                def close(self):
                    pass

            class Response:
                status = 200
                frame = b'{"result":{"status":"IN_FLIGHT"}}\n'

                def read1(self, limit):
                    result, self.frame = self.frame, b""
                    return result

            return Connection(), Response()

    with api.UserNodeServer(("127.0.0.1", 0), Node(), 9093, 9273) as instance:
        thread = threading.Thread(target=instance.serve_forever, daemon=True)
        thread.start()
        yield instance
        instance.shutdown()
        thread.join()


def request(server, path="/configuration", method="GET", body=None, headers=None):
    connection = HTTPConnection(*server.server_address, timeout=2)
    connection.request(
        method,
        path,
        body=body,
        headers={"Host": "127.0.0.1:9093", "Origin": "http://127.0.0.1:9273", **(headers or {})},
    )
    response = connection.getresponse()
    result = response.status, dict(response.getheaders()), response.read()
    connection.close()
    return result


def test_configuration_requires_explicit_request_and_only_exports_restricted_configuration(server):
    assert server.node.calls == []
    status, headers, body = request(server)
    assert status == 200 and json.loads(body)["macaroon"] == "00aa"
    assert headers["Cache-Control"] == "no-store"
    assert server.node.calls == ["attest"]


@pytest.mark.parametrize(
    "headers",
    [
        {"Origin": "null"},
        {"Origin": "https://evil.example"},
        {"Host": "evil.example"},
        {"Origin": ""},
    ],
)
def test_wrong_origins_and_hosts_make_zero_backend_calls(server, headers):
    assert request(server, headers=headers)[0] == 403
    assert server.node.calls == []


@pytest.mark.parametrize(
    "method,path",
    [
        ("GET", "/v1/balance/channels"),
        ("POST", "/v2/router/send"),
        ("GET", "/configuration?x=1"),
        ("GET", "/v1/getinfo/"),
        ("GET", "/v1/getinfo?host=evil"),
        ("GET", "/v1/payreq/%2fadmin"),
        ("POST", "/v1/macaroon"),
        ("GET", "/v2/router/track/abc?no_inflight_updates=false"),
    ],
)
def test_arbitrary_upstream_operation_is_not_forwarded(server, method, path):
    assert request(server, method=method, path=path)[0] == 404
    assert server.node.calls == []


def test_rpc_requires_exact_memory_credential_before_attestation(server):
    for headers in [{}, {"Grpc-Metadata-macaroon": "wrong"}]:
        assert request(server, path="/v1/getinfo", headers=headers)[0] == 403
    assert server.node.calls == []
    assert request(server, path="/v1/getinfo", headers={"Grpc-Metadata-macaroon": "00aa"})[0] == 200
    assert server.node.calls == ["attest", ("GET", "/v1/getinfo", None)]


@pytest.mark.parametrize(
    "body",
    [
        b"{}",
        b'{"a":1,"a":2}',
        b'{"value":NaN}',
        b'"string"',
        b'{"payment_hash":"AA==","route":{},"skip_temp_err":false}',
    ],
)
def test_invalid_payment_body_never_connects(server, body):
    result = request(
        server,
        path="/v2/router/route/send",
        method="POST",
        body=body,
        headers={"Grpc-Metadata-macaroon": "00aa", "Content-Type": "application/json"},
    )
    # Invalid framing/schema may close the connection without exposing backend details.
    assert result[0] in {400, 503}
    assert server.node.calls == []


def test_cors_preflight_accepts_only_exact_operations_and_auth_headers(server):
    assert (
        request(
            server,
            method="OPTIONS",
            path="/v2/router/route/send",
            headers={
                "Access-Control-Request-Method": "POST",
                "Access-Control-Request-Headers": "content-type,grpc-metadata-macaroon",
            },
        )[0]
        == 204
    )
    assert (
        request(
            server,
            method="OPTIONS",
            path="/v1/getinfo",
            headers={
                "Access-Control-Request-Method": "GET",
                "Access-Control-Request-Headers": "authorization",
            },
        )[0]
        == 403
    )
    assert server.node.calls == []


def test_wrong_network_or_identity_refuses_configuration(server):
    server.node.fail = True
    assert request(server)[0] == 503


def test_tracking_frame_is_forwarded_before_upstream_stream_completes(server):
    release = threading.Event()
    original = server.node.open

    def open_stream(method, path, body):
        connection, response = original(method, path, body)
        original_read = response.read1

        def read(limit):
            if not response.frame:
                release.wait(3)
            return original_read(limit)

        response.read1 = read
        return connection, response

    server.node.open = open_stream
    connection = HTTPConnection(*server.server_address, timeout=1)
    try:
        connection.request(
            "GET",
            "/v2/router/track/" + "A" * 43 + "=?no_inflight_updates=false",
            headers={
                "Host": "127.0.0.1:9093",
                "Origin": "http://127.0.0.1:9273",
                "Grpc-Metadata-macaroon": "00aa",
            },
        )
        response = connection.getresponse()
        assert response.status == 200
        assert b'"IN_FLIGHT"' in response.readline()
        assert not release.is_set()
    finally:
        release.set()
        connection.close()


def test_existing_partial_or_unsupported_credential_directory_is_never_repaired(tmp_path):
    with pytest.raises(FileNotFoundError):
        api.UserNode(tmp_path)
    config = {
        "node_identity": KEY,
        "network_identity": {**NETWORK, "name": "mainnet"},
        "permissions": sorted(api.METHODS),
    }
    (tmp_path / "configuration.json").write_text(json.dumps(config))
    with pytest.raises(api.NodeUnavailable):
        api.UserNode(tmp_path)
    assert json.loads((tmp_path / "configuration.json").read_text()) == config


def test_attestation_and_upstream_tls_fail_closed_without_exporting_payloads(monkeypatch):
    node = object.__new__(api.UserNode)
    node.config = {"node_identity": KEY}

    class Connection:
        def close(self):
            pass

    class Response:
        status = 200
        body = b""

        def read(self, limit):
            return self.body

    response = Response()
    monkeypatch.setattr(node, "open", lambda *args: (Connection(), response))
    for info in [
        {"identity_pubkey": KEY, "chains": [{"chain": "bitcoin", "network": "mainnet"}]},
        {
            "identity_pubkey": "02" + "22" * 32,
            "chains": [{"chain": "bitcoin", "network": "regtest"}],
        },
    ]:
        response.body = json.dumps(info).encode()
        with pytest.raises(api.NodeUnavailable):
            node.attest()
    response.body = json.dumps(
        {"identity_pubkey": KEY, "chains": [{"chain": "bitcoin", "network": "regtest"}]}
    ).encode()
    node.attest()


def test_bootstrap_creates_only_restricted_credentials_and_never_replaces_existing_state(
    tmp_path, monkeypatch
):
    devtool = load("devtool")
    network = NETWORK
    monkeypatch.setattr(devtool, "network_identity", lambda: network)
    state = tmp_path / "state"
    (state / "lnd/user").mkdir(parents=True)
    (state / "lnd/user/tls.cert").write_bytes(b"public-cert-fixture")
    monkeypatch.setattr(devtool, "STATE", state)
    calls = []

    class Lnd:
        def __init__(self, name):
            assert name == "user"

        def info(self):
            return {"identity_pubkey": KEY, "chains": [{"chain": "bitcoin", "network": "regtest"}]}

        def post(self, path, body):
            calls.append((path, body))
            return {"macaroon": "00aa"}

    monkeypatch.setattr(devtool, "Lnd", Lnd)
    directory = tmp_path / "credentials"
    directory.mkdir()
    with patch.dict(sys.modules, {"user_node_api": api}):
        devtool.provision_browser_node(directory)
        assert calls == [
            (
                "/v1/macaroon",
                {
                    "permissions": [
                        {"entity": "uri", "action": method} for method in sorted(api.METHODS)
                    ]
                },
            )
        ]
        before = {path.name: path.read_bytes() for path in directory.iterdir()}
        devtool.provision_browser_node(directory)
        assert len(calls) == 1
        assert before == {path.name: path.read_bytes() for path in directory.iterdir()}
        (directory / "browser.macaroon").unlink()
        with pytest.raises(SystemExit, match="Partial"):
            devtool.provision_browser_node(directory)
        assert len(calls) == 1
        (directory / "browser.macaroon").write_bytes(b"fixture")
        config = json.loads((directory / "configuration.json").read_text())
        config["permissions"] = ["/lnrpc.Lightning/GetInfo"]
        (directory / "configuration.json").write_text(json.dumps(config))
        with pytest.raises(SystemExit, match="Unsupported"):
            devtool.provision_browser_node(directory)
        assert len(calls) == 1
        assert (
            json.loads((directory / "configuration.json").read_text())["network_identity"]
            == network
        )


def test_bootstrap_records_intent_before_baking_and_preserves_interrupted_state(
    tmp_path, monkeypatch
):
    devtool = load("devtool")
    monkeypatch.setattr(devtool, "network_identity", lambda: NETWORK)

    class Lnd:
        def __init__(self, name):
            pass

        def info(self):
            return {"identity_pubkey": KEY, "chains": [{"chain": "bitcoin", "network": "regtest"}]}

        def post(self, path, body):
            raise OSError("interrupted credential creation")

    monkeypatch.setattr(devtool, "Lnd", Lnd)
    with patch.dict(sys.modules, {"user_node_api": api}):
        with pytest.raises(OSError):
            devtool.provision_browser_node(tmp_path)
        assert {path.name for path in tmp_path.iterdir()} == {"configuration.json"}
        with pytest.raises(SystemExit, match="Partial"):
            devtool.provision_browser_node(tmp_path)


@pytest.mark.parametrize("failure", [None, "untrusted", "hostname"])
def test_real_tls_validation_precedes_credential_export(tmp_path, monkeypatch, failure):
    def certificate(name, san):
        key, cert = tmp_path / f"{name}.key", tmp_path / f"{name}.crt"
        subprocess.run(
            [
                "openssl",
                "req",
                "-x509",
                "-nodes",
                "-newkey",
                "rsa:2048",
                "-days",
                "1",
                "-subj",
                "/CN=localhost",
                "-addext",
                "subjectAltName=" + san,
                "-keyout",
                str(key),
                "-out",
                str(cert),
            ],
            check=True,
            capture_output=True,
            timeout=15,
        )
        return key, cert

    key, cert = certificate(
        "server", "DNS:wrong.example" if failure == "hostname" else "DNS:localhost,IP:127.0.0.1"
    )
    ca = certificate("other", "DNS:localhost,IP:127.0.0.1")[1] if failure == "untrusted" else cert
    directory = tmp_path / "credentials"
    directory.mkdir()
    (directory / "configuration.json").write_text(
        json.dumps(
            {"node_identity": KEY, "network_identity": NETWORK, "permissions": sorted(api.METHODS)}
        )
    )
    (directory / "browser.macaroon").write_bytes(b"test-only-restricted-token")
    (directory / "tls.cert").write_bytes(ca.read_bytes())
    calls = []

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            calls.append(self.path)
            body = json.dumps(
                {"identity_pubkey": KEY, "chains": [{"chain": "bitcoin", "network": "regtest"}]}
            ).encode()
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            pass

    with ThreadingHTTPServer(("127.0.0.1", 0), Handler) as server:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert, key)
        server.socket = context.wrap_socket(server.socket, server_side=True)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:

            def connection(host, port, *, context, timeout):
                assert host == "lnd-user" and port == 8080
                assert context.verify_mode == ssl.CERT_REQUIRED and context.check_hostname
                return HTTPSConnection(
                    "127.0.0.1", server.server_port, context=context, timeout=timeout
                )

            monkeypatch.setattr(api, "HTTPSConnection", connection)
            node = api.UserNode(directory)
            if failure:
                with pytest.raises(api.NodeUnavailable):
                    node.configuration()
                assert calls == []
            else:
                assert json.loads(node.configuration())["node_identity"] == KEY
                assert calls == ["/v1/getinfo"]
        finally:
            server.shutdown()
            thread.join()
