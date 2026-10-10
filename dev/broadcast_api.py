"""Explicit loopback regtest transaction submission. No keys, wallet RPC, or retries."""

from __future__ import annotations

import base64
import json
import os
import re
from http.client import HTTPException
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.error import HTTPError
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener

from chain_api import CORE_URL, HEX32, ChainReader, ChainUnavailable, loopback_port

CORE_AUTH = ("rill-broadcast", "rill-dev-broadcast-regtest")  # Disposable regtest only.
MAX_BODY = 200_000


def json_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate response field")
        result[key] = value
    return result


def reject_constant(value):
    raise ValueError("Nonfinite response")


class BroadcastUnavailable(Exception):
    """No backend response or submitted bytes are exposed in diagnostics."""


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise BroadcastUnavailable()


class Broadcaster:
    def __init__(self) -> None:
        self.opener = build_opener(ProxyHandler({}), NoRedirect())
        self.reader = ChainReader()

    def _call(self, method: str, params: list[Any]) -> Any:
        if method not in {"testmempoolaccept", "sendrawtransaction"}:
            raise BroadcastUnavailable()
        auth = base64.b64encode(":".join(CORE_AUTH).encode()).decode()
        request = Request(
            CORE_URL,
            data=json.dumps(
                {"jsonrpc": "2.0", "id": 1, "method": method, "params": params}
            ).encode(),
            headers={"Authorization": f"Basic {auth}", "Content-Type": "application/json"},
            method="POST",
        )
        try:
            with self.opener.open(request, timeout=3) as response:
                if response.status != 200:
                    raise BroadcastUnavailable()
                body = response.read(16385)
                if len(body) > 16384:
                    raise BroadcastUnavailable()
            result = json.loads(body, object_pairs_hook=json_object, parse_constant=reject_constant)
            if (
                not isinstance(result, dict)
                or type(result.get("id")) is not int
                or result["id"] != 1
                or result.get("error") is not None
            ):
                raise BroadcastUnavailable()
            return result["result"]
        except (OSError, HTTPError, HTTPException, ValueError, KeyError) as exc:
            raise BroadcastUnavailable() from exc

    def submit(self, transaction_hex: str) -> str:
        if not re.fullmatch(r"(?:[0-9a-f]{2}){60,100000}", transaction_hex):
            raise BroadcastUnavailable()
        try:
            self.reader.observe("/api/block-height/0")  # Wrong backend never permits submission.
            preflight = self._call("testmempoolaccept", [[transaction_hex], 0.1])
            if not isinstance(preflight, list) or len(preflight) != 1:
                raise BroadcastUnavailable()
            result = preflight[0]
            if (
                not isinstance(result, dict)
                or result.get("allowed") is not True
                or not isinstance(result.get("txid"), str)
                or not HEX32.fullmatch(result["txid"])
            ):
                raise BroadcastUnavailable()
            txid = self._call("sendrawtransaction", [transaction_hex, 0.1, 0])
            if txid != result["txid"]:
                raise BroadcastUnavailable()
            return txid
        except ChainUnavailable as exc:
            raise BroadcastUnavailable() from exc


class BroadcastServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, address, broadcaster: Broadcaster, host_port: int, web_port: int) -> None:
        super().__init__(address, BroadcastHandler)
        self.broadcaster = broadcaster
        self.hosts = {f"127.0.0.1:{host_port}", f"localhost:{host_port}"}
        self.origins = {f"http://127.0.0.1:{web_port}", f"http://localhost:{web_port}"}


class BroadcastHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def setup(self) -> None:
        super().setup()
        self.connection.settimeout(3)

    def reply(self, status: int, text: str, origin: str | None = None) -> None:
        body = text.encode("ascii")
        self.send_response(status)
        self.send_header("Content-Type", "text/plain; charset=us-ascii")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Connection", "close")
        if origin:
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Vary", "Origin")
        self.end_headers()
        self.wfile.write(body)
        self.close_connection = True

    def do_POST(self) -> None:
        hosts, origins = self.headers.get_all("Host", []), self.headers.get_all("Origin", [])
        if len(hosts) != 1 or hosts[0] not in self.server.hosts:
            self.reply(403, "Approved local host required")
            return
        if len(origins) != 1 or origins[0] not in self.server.origins:
            self.reply(403, "Approved local origin required")
            return
        origin = origins[0]
        if self.path != "/api/tx":
            self.reply(404, "Unknown submission route", origin)
            return
        lengths = self.headers.get_all("Content-Length", [])
        if (
            self.headers.get_all("Transfer-Encoding")
            or len(lengths) != 1
            or not re.fullmatch(r"[1-9][0-9]{0,5}", lengths[0])
            or not 120 <= int(lengths[0]) <= MAX_BODY
            or self.headers.get_all("Content-Type", []) != ["text/plain"]
        ):
            self.reply(400, "Canonical bounded transaction body required", origin)
            return
        try:
            body = self.rfile.read(int(lengths[0]))
            if len(body) != int(lengths[0]):
                raise BroadcastUnavailable()
            transaction_hex = body.decode("ascii")
            if not re.fullmatch(r"(?:[0-9a-f]{2}){60,100000}", transaction_hex):
                self.reply(400, "Canonical transaction hex required", origin)
                return
            txid = self.server.broadcaster.submit(transaction_hex)
            self.reply(200, txid, origin)
        except (OSError, UnicodeError, BroadcastUnavailable):
            # Even an error can follow a submitted transaction. The browser keeps UNKNOWN.
            self.reply(503, "Submission outcome unavailable; do not automatically retry", origin)

    def unsupported(self) -> None:
        self.reply(405, "Only explicit transaction POST is accepted")

    do_GET = do_PUT = do_DELETE = do_PATCH = do_OPTIONS = do_HEAD = unsupported

    def log_message(self, format: str, *args: Any) -> None:
        pass


def main() -> None:
    broadcaster = Broadcaster()
    broadcaster.reader.observe("/api/block-height/0")
    host_port = loopback_port(os.environ.get("RILL_DEV_BROADCAST_PORT", "8092"))
    web_port = loopback_port(os.environ.get("RILL_DEV_WEB_PORT", "5273"))
    with BroadcastServer(("0.0.0.0", 8092), broadcaster, host_port, web_port) as server:
        server.serve_forever()


if __name__ == "__main__":
    main()
