"""Read-only, loopback-published regtest tip observations. No wallet or swap state."""

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

CORE_URL = "http://bitcoind:18443"
CORE_AUTH = ("rill-chain", "rill-dev-chain-regtest")  # Public disposable regtest credentials.
GENESIS = "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206"
ROUTES = frozenset({"/api/block-height/0", "/api/blocks/tip/height", "/api/blocks/tip/hash"})
HEX32 = re.compile(r"[0-9a-f]{64}\Z")


class ChainUnavailable(Exception):
    """Upstream errors deliberately carry no backend response to HTTP clients."""


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ChainUnavailable()


class ChainReader:
    def __init__(self) -> None:
        self.opener = build_opener(ProxyHandler({}), NoRedirect())

    def _call(self, method: str, params: list[Any]) -> Any:
        if method not in {"getblockhash", "getblockchaininfo"}:
            raise ChainUnavailable()
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
                    raise ChainUnavailable()
                body = response.read(16385)
                if len(body) > 16384:
                    raise ChainUnavailable()
            result = json.loads(body)
            if not isinstance(result, dict) or result.get("id") != 1 or result.get("error"):
                raise ChainUnavailable()
            return result["result"]
        except (OSError, HTTPError, HTTPException, ValueError, KeyError) as exc:
            raise ChainUnavailable() from exc

    def observe(self, path: str) -> str:
        if path not in ROUTES:
            raise ChainUnavailable()
        info = self._call("getblockchaininfo", [])
        genesis = self._call("getblockhash", [0])
        if not isinstance(info, dict) or info.get("chain") != "regtest" or genesis != GENESIS:
            raise ChainUnavailable()
        height, tip_hash = info.get("blocks"), info.get("bestblockhash")
        if (
            type(height) is not int
            or not 0 <= height < 500_000_000
            or not isinstance(tip_hash, str)
            or not HEX32.fullmatch(tip_hash)
        ):
            raise ChainUnavailable()
        return {
            "/api/block-height/0": GENESIS,
            "/api/blocks/tip/height": str(height),
            "/api/blocks/tip/hash": tip_hash,
        }[path]


def loopback_port(value: str) -> int:
    if not value.isascii() or not value.isdigit() or not 1 <= int(value) <= 65535:
        raise ValueError("Invalid local port")
    return int(value)


class ChainServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(
        self, address: tuple[str, int], reader: ChainReader, host_port: int, web_port: int
    ):
        self.reader = reader
        self.hosts = frozenset({f"127.0.0.1:{host_port}", f"localhost:{host_port}"})
        self.origins = frozenset({f"http://127.0.0.1:{web_port}", f"http://localhost:{web_port}"})
        super().__init__(address, ChainHandler)


class ChainHandler(BaseHTTPRequestHandler):
    server: ChainServer

    def setup(self) -> None:
        super().setup()
        self.connection.settimeout(5)

    def reply(self, code: int, text: str, origin: str | None = None) -> None:
        body = text.encode("ascii")
        self.send_response(code)
        self.send_header("Content-Type", "text/plain; charset=ascii")
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

    def do_GET(self) -> None:
        hosts, origins = self.headers.get_all("Host", []), self.headers.get_all("Origin", [])
        if len(hosts) != 1 or hosts[0] not in self.server.hosts:
            self.reply(403, "Local host required")
            return
        if len(origins) > 1 or (origins and origins[0] not in self.server.origins):
            self.reply(403, "Local origin required")
            return
        if self.headers.get_all("Transfer-Encoding") or self.headers.get_all("Content-Length"):
            self.reply(400, "Request bodies are not accepted")
            return
        if self.path not in ROUTES:
            self.reply(404, "Unknown chain route")
            return
        origin = origins[0] if origins else None
        try:
            value = self.server.reader.observe(self.path)
            self.reply(200, value, origin)
        except ChainUnavailable:
            self.reply(503, "Regtest chain observation unavailable", origin)

    def unsupported(self) -> None:
        self.reply(405, "Only read-only GET requests are accepted")

    do_POST = do_PUT = do_DELETE = do_PATCH = do_OPTIONS = do_HEAD = unsupported

    def log_message(self, format: str, *args: Any) -> None:
        # No untrusted request targets or backend details in logs.
        pass


def main() -> None:
    host_port = loopback_port(os.environ.get("RILL_DEV_CHAIN_PORT", "8091"))
    web_port = loopback_port(os.environ.get("RILL_DEV_WEB_PORT", "5273"))
    reader = ChainReader()
    reader.observe("/api/block-height/0")  # Wrong networks never begin serving.
    with ChainServer(("0.0.0.0", 8091), reader, host_port, web_port) as server:
        server.serve_forever()


if __name__ == "__main__":
    main()
