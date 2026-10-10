"""Fixed five-method, verified-TLS LND transport for disposable regtest browsers."""

from __future__ import annotations

import base64
import hmac
import json
import os
import re
import ssl
from http.client import HTTPException, HTTPSConnection
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from chain_api import GENESIS, loopback_port

DIRECTORY = Path("/browser-node")
MAX_BODY = 128 * 1024
METHODS = frozenset(
    {
        "/lnrpc.Lightning/DecodePayReq",
        "/lnrpc.Lightning/GetInfo",
        "/lnrpc.Lightning/QueryRoutes",
        "/routerrpc.Router/SendToRouteV2",
        "/routerrpc.Router/TrackPaymentV2",
    }
)
KEY = re.compile(r"0[23][0-9a-f]{64}\Z")


class NodeUnavailable(Exception):
    """Diagnostics never contain credentials or payment data."""


def strict_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate field")
        result[key] = value
    return result


def reject_constant(value):
    raise ValueError("Nonfinite JSON")


def parse(body: bytes):
    if not body or len(body) > MAX_BODY:
        raise NodeUnavailable()
    try:
        value = json.loads(
            body.decode("utf-8"), object_pairs_hook=strict_object, parse_constant=reject_constant
        )
        if not isinstance(value, dict):
            raise NodeUnavailable()
        return value
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise NodeUnavailable() from exc


def route(method: str, path: str) -> str | None:
    if method == "GET" and path in {"/configuration", "/v1/getinfo"}:
        return path
    if method == "GET" and re.fullmatch(r"/v1/payreq/[a-z0-9]{20,2048}", path):
        return path
    if method == "POST" and re.fullmatch(
        r"/v1/graph/routes/0[23][0-9a-f]{64}/[1-9][0-9]{0,15}", path
    ):
        return path
    if method == "POST" and path == "/v2/router/route/send":
        return path
    if method == "GET" and re.fullmatch(
        r"/v2/router/track/[A-Za-z0-9_-]{43}=?\?no_inflight_updates=false", path
    ):
        encoded = path.split("/")[-1].split("?")[0]
        try:
            if len(base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4))) == 32:
                return path
        except ValueError:
            pass
    return None


def check_body(path: str, body: bytes) -> None:
    value = parse(body)
    if path == "/v2/router/route/send":
        if (
            set(value) != {"payment_hash", "route", "skip_temp_err"}
            or value["skip_temp_err"] is not False
        ):
            raise NodeUnavailable()
        try:
            if (
                not isinstance(value["payment_hash"], str)
                or len(base64.b64decode(value["payment_hash"], validate=True)) != 32
            ):
                raise NodeUnavailable()
        except ValueError as exc:
            raise NodeUnavailable() from exc
        route_value = value["route"]
        if (
            not isinstance(route_value, dict)
            or not isinstance(route_value.get("hops"), list)
            or not 1 <= len(route_value["hops"]) <= 20
        ):
            raise NodeUnavailable()
    else:
        if set(value) != {
            "final_cltv_delta",
            "fee_limit",
            "cltv_limit",
            "route_hints",
            "dest_features",
        }:
            raise NodeUnavailable()
        if (
            not isinstance(value["route_hints"], list)
            or len(value["route_hints"]) > 20
            or not isinstance(value["dest_features"], list)
        ):
            raise NodeUnavailable()


class UserNode:
    def __init__(self, directory: Path = DIRECTORY) -> None:
        # Local validation only; never connect during construction or server startup.
        config = parse((directory / "configuration.json").read_bytes())
        network = config.get("network_identity")
        if (
            set(config) != {"node_identity", "network_identity", "permissions"}
            or not isinstance(config["node_identity"], str)
            or not KEY.fullmatch(config["node_identity"])
            or not isinstance(network, dict)
            or network.get("name") != "regtest"
            or network.get("family") != "bitcoin"
            or network.get("genesis_hash") != GENESIS
            or network.get("deployment_namespace") != "rillswap-e2e-v1"
            or config["permissions"] != sorted(METHODS)
        ):
            raise NodeUnavailable()
        macaroon = (directory / "browser.macaroon").read_bytes()
        if not 1 <= len(macaroon) <= 4096:
            raise NodeUnavailable()
        self.macaroon = macaroon.hex()
        self.config = config
        self.context = ssl.create_default_context(cafile=str(directory / "tls.cert"))

    def open(self, method: str, path: str, body: bytes | None = None):
        if route(method, path) != path or path == "/configuration":
            raise NodeUnavailable()
        connection = HTTPSConnection("lnd-user", 8080, context=self.context, timeout=65)
        try:
            connection.request(
                method,
                path,
                body=body,
                headers={
                    "Grpc-Metadata-macaroon": self.macaroon,
                    **({"Content-Type": "application/json"} if body is not None else {}),
                },
            )
            response = connection.getresponse()
            return connection, response
        except (OSError, HTTPException) as exc:
            connection.close()
            raise NodeUnavailable() from exc

    def attest(self) -> None:
        connection, response = self.open("GET", "/v1/getinfo")
        try:
            if response.status != 200:
                raise NodeUnavailable()
            info = parse(response.read(MAX_BODY + 1))
            if info.get("identity_pubkey") != self.config["node_identity"] or info.get(
                "chains"
            ) != [{"chain": "bitcoin", "network": "regtest"}]:
                raise NodeUnavailable()
        finally:
            connection.close()

    def configuration(self) -> bytes:
        self.attest()
        return json.dumps(
            {
                "node_identity": self.config["node_identity"],
                "network_identity": self.config["network_identity"],
                "macaroon": self.macaroon,
            }
        ).encode()


class UserNodeServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, address, node: UserNode, host_port: int, web_port: int):
        super().__init__(address, UserNodeHandler)
        self.node = node
        self.hosts = {f"127.0.0.1:{host_port}", f"localhost:{host_port}"}
        self.origins = {f"http://127.0.0.1:{web_port}", f"http://localhost:{web_port}"}


class UserNodeHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def setup(self):
        super().setup()
        self.connection.settimeout(5)

    def reply(
        self,
        status: int,
        body: bytes = b"Node action unavailable; never retry an unknown payment",
        origin=None,
    ):
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.headers_out(origin)
        self.end_headers()
        self.wfile.write(body)

    def headers_out(self, origin):
        self.send_header("Cache-Control", "no-store")
        self.send_header("Connection", "close")
        self.send_header("X-Content-Type-Options", "nosniff")
        if origin:
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Vary", "Origin")
        self.close_connection = True

    def admitted_origin(self):
        hosts, origins = self.headers.get_all("Host", []), self.headers.get_all("Origin", [])
        if (
            len(hosts) != 1
            or hosts[0] not in self.server.hosts
            or len(origins) != 1
            or origins[0] not in self.server.origins
        ):
            self.reply(403)
            return None
        return origins[0]

    def handle_action(self):
        origin = self.admitted_origin()
        if not origin:
            return
        path = route(self.command, self.path)
        if path is None:
            self.reply(404, origin=origin)
            return
        lengths = self.headers.get_all("Content-Length", [])
        if self.headers.get_all("Transfer-Encoding") or (self.command == "GET" and lengths):
            self.reply(400, origin=origin)
            return
        if path == "/configuration":
            if self.headers.get_all("Grpc-Metadata-macaroon"):
                self.reply(400, origin=origin)
                return
            try:
                self.reply(200, self.server.node.configuration(), origin)
            except (OSError, HTTPException, NodeUnavailable):
                self.reply(503, origin=origin)
            return
        credentials = self.headers.get_all("Grpc-Metadata-macaroon", [])
        if len(credentials) != 1 or not hmac.compare_digest(
            credentials[0], self.server.node.macaroon
        ):
            self.reply(403, origin=origin)
            return
        body = None
        response_started = False
        try:
            if self.command == "POST":
                if (
                    len(lengths) != 1
                    or not re.fullmatch(r"[1-9][0-9]{0,5}", lengths[0])
                    or int(lengths[0]) > MAX_BODY
                    or self.headers.get_all("Content-Type", []) != ["application/json"]
                ):
                    self.reply(400, origin=origin)
                    return
                body = self.rfile.read(int(lengths[0]))
                if len(body) != int(lengths[0]):
                    raise NodeUnavailable()
                try:
                    check_body(path, body)
                except NodeUnavailable:
                    self.reply(400, origin=origin)
                    return
            self.server.node.attest()
            connection, response = self.server.node.open(self.command, path, body)
            try:
                if response.status != 200:
                    self.reply(503, origin=origin)
                    return
                self.send_response(200)
                response_started = True
                self.send_header("Content-Type", "application/json")
                self.headers_out(origin)
                self.end_headers()
                # Forward streamed frames immediately; never buffer a held payment to completion.
                total = 0
                while True:
                    chunk = response.read1(16384)
                    if not chunk:
                        break
                    total += len(chunk)
                    if total > 1024 * 1024:
                        break
                    self.wfile.write(chunk)
                    self.wfile.flush()
            finally:
                connection.close()
        except (OSError, HTTPException, NodeUnavailable):
            # A POST might already have dispatched. No retry or second upstream request.
            if not response_started:
                self.reply(503, origin=origin)
            self.close_connection = True

    do_GET = do_POST = handle_action

    def do_OPTIONS(self):
        origin = self.admitted_origin()
        if not origin:
            return
        method = self.headers.get_all("Access-Control-Request-Method", [])
        headers = self.headers.get_all("Access-Control-Request-Headers", [])
        if (
            len(method) != 1
            or route(method[0], self.path) is None
            or self.headers.get_all("Content-Length")
            or self.headers.get_all("Transfer-Encoding")
            or len(headers) > 1
            or (
                headers
                and not set(headers[0].lower().replace(" ", "").split(","))
                <= {"grpc-metadata-macaroon", "content-type"}
            )
        ):
            self.reply(403, origin=origin)
            return
        self.send_response(204)
        self.send_header("Access-Control-Allow-Methods", "GET, POST")
        self.send_header("Access-Control-Allow-Headers", "Grpc-Metadata-macaroon, Content-Type")
        self.send_header("Content-Length", "0")
        self.headers_out(origin)
        self.end_headers()

    def unsupported(self):
        self.reply(405)

    do_PUT = do_PATCH = do_DELETE = do_HEAD = unsupported

    def log_message(self, format, *args):
        pass


def main():
    node = UserNode()
    with UserNodeServer(
        ("0.0.0.0", 8093),
        node,
        loopback_port(os.environ.get("RILL_DEV_NODE_PORT", "8093")),
        loopback_port(os.environ.get("RILL_DEV_WEB_PORT", "5273")),
    ) as server:
        server.serve_forever()


if __name__ == "__main__":
    main()
