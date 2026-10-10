"""Read-only, loopback-published regtest chain observations. No wallet or swap state."""

from __future__ import annotations

import base64
import json
import os
import re
from decimal import Decimal, InvalidOperation
from http.client import HTTPException
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.error import HTTPError
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener

CORE_URL = "http://bitcoind:18443"
CORE_AUTH = ("rill-chain", "rill-dev-chain-regtest")  # Public disposable regtest credentials.
GENESIS = "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206"
HEX32 = re.compile(r"[0-9a-f]{64}\Z")
BLOCK_ROUTE = re.compile(r"/api/block-height/(0|[1-9][0-9]{0,8})\Z")
TRANSACTION_ROUTE = re.compile(r"/api/tx/([0-9a-f]{64})/(hex|status)\Z")
OUTSPEND_ROUTE = re.compile(r"/api/tx/([0-9a-f]{64})/outspend/(0|[1-9][0-9]{0,9})\Z")
MAX_RAW_TRANSACTION_BYTES = 100_000
MAX_TRANSACTION_RPC_BYTES = 4 * 1024 * 1024
RPC_METHODS = frozenset(
    {"getblockhash", "getblockchaininfo", "getrawtransaction", "getblockheader", "gettxout"}
)


def route(path: str) -> tuple[str, tuple[str, ...]] | None:
    """Validate all path parameters before a request can reach Core."""
    if path == "/api/blocks/tip/height":
        return "tip-height", ()
    if path == "/api/blocks/tip/hash":
        return "tip-hash", ()
    if (match := BLOCK_ROUTE.fullmatch(path)) and int(match[1]) < 500_000_000:
        return "block-height", (match[1],)
    if match := TRANSACTION_ROUTE.fullmatch(path):
        return match[2], (match[1],)
    if (match := OUTSPEND_ROUTE.fullmatch(path)) and int(match[2]) <= 0xFFFFFFFF:
        return "outspend", (match[1], match[2])
    return None


def reject_constant(value: str) -> None:
    raise ValueError("Nonfinite JSON is not accepted")


def raw_hex(value: Any) -> str:
    if not isinstance(value, str) or not re.fullmatch(
        rf"(?:[0-9a-f]{{2}}){{60,{MAX_RAW_TRANSACTION_BYTES}}}", value
    ):
        raise ChainUnavailable()
    return value


def integer(value: Any, low: int, high: int) -> bool:
    return type(value) is int and low <= value <= high


def output_sample(value: Any, tip_hash: str, tip_height: int) -> tuple[int, str, int, bool]:
    """Require an affirmative, confirmed Core UTXO observation on this tip."""
    if not isinstance(value, dict) or value.get("bestblock") != tip_hash:
        raise ChainUnavailable()
    confirmations = value.get("confirmations")
    if not integer(confirmations, 1, tip_height + 1) or type(value.get("coinbase")) is not bool:
        raise ChainUnavailable()
    amount = value.get("value")
    if type(amount) is int:
        amount = Decimal(amount)
    if not isinstance(amount, Decimal) or not amount.is_finite() or not 0 <= amount <= 21_000_000:
        raise ChainUnavailable()
    # Equality with an eight-place quantization checks exactness without first
    # rounding through float or multiplying arbitrarily precise JSON decimals.
    try:
        quantized = amount.quantize(Decimal("0.00000001"))
        if amount != quantized:
            raise ChainUnavailable()
        satoshis = int(quantized * 100_000_000)
    except InvalidOperation as exc:
        raise ChainUnavailable() from exc
    script = value.get("scriptPubKey")
    if not isinstance(script, dict) or not isinstance(script.get("hex"), str):
        raise ChainUnavailable()
    if not re.fullmatch(r"(?:[0-9a-f]{2}){0,10000}", script["hex"]):
        raise ChainUnavailable()
    return satoshis, script["hex"], confirmations, value["coinbase"]


class ChainUnavailable(Exception):
    """Upstream errors deliberately carry no backend response to HTTP clients."""


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ChainUnavailable()


class ChainReader:
    def __init__(self) -> None:
        self.opener = build_opener(ProxyHandler({}), NoRedirect())

    def _call(self, method: str, params: list[Any]) -> Any:
        if method not in RPC_METHODS:
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
                limit = MAX_TRANSACTION_RPC_BYTES if method == "getrawtransaction" else 16384
                body = response.read(limit + 1)
                if len(body) > limit:
                    raise ChainUnavailable()
            result = json.loads(body, parse_float=Decimal, parse_constant=reject_constant)
            if (
                not isinstance(result, dict)
                or type(result.get("id")) is not int
                or result["id"] != 1
                or result.get("error")
            ):
                raise ChainUnavailable()
            return result["result"]
        except (OSError, HTTPError, HTTPException, ValueError, KeyError) as exc:
            raise ChainUnavailable() from exc

    def observe(self, path: str) -> str:
        parsed = route(path)
        if parsed is None:
            raise ChainUnavailable()
        kind, params = parsed
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
        if kind == "tip-height":
            return str(height)
        if kind == "tip-hash":
            return tip_hash
        if kind == "block-height":
            selected_height = int(params[0])
            if selected_height > height:
                raise ChainUnavailable()
            value = (
                genesis if selected_height == 0 else self._call("getblockhash", [selected_height])
            )
            if not isinstance(value, str) or not HEX32.fullmatch(value):
                raise ChainUnavailable()
            return value
        txid = params[0]
        if kind == "hex":
            return raw_hex(self._call("getrawtransaction", [txid, False]))
        if kind == "status":
            return json.dumps(self.transaction_status(txid, height, tip_hash))
        chain = self._call("gettxout", [txid, int(params[1]), False])
        confirmed = output_sample(
            chain, tip_hash, height
        )  # Null is UNKNOWN, never spentness proof.
        mempool = self._call("gettxout", [txid, int(params[1]), True])
        if mempool is None:
            # A mempool spend OR a concurrent reorg may cause this. Do not turn
            # an ambiguous sequential sample into durable spent/settled evidence.
            raise ChainUnavailable()
        if output_sample(mempool, tip_hash, height) != confirmed:
            raise ChainUnavailable()
        return json.dumps({"spent": False})

    def transaction_status(self, txid: str, tip_height: int, tip_hash: str) -> dict[str, Any]:
        transaction = self._call("getrawtransaction", [txid, True])
        if not isinstance(transaction, dict) or transaction.get("txid") != txid:
            raise ChainUnavailable()
        raw_hex(transaction.get("hex"))
        if "blockhash" not in transaction:
            # Pinned Core v30 omits confirmations for mempool transactions.
            if "confirmations" in transaction:
                raise ChainUnavailable()
            return {"confirmed": False}
        block = transaction["blockhash"]
        confirmations = transaction.get("confirmations")
        if (
            not isinstance(block, str)
            or not HEX32.fullmatch(block)
            or not integer(confirmations, 0, tip_height + 1)
        ):
            raise ChainUnavailable()
        if confirmations == 0:
            return {"confirmed": False}  # A transaction retained in a stale block.
        header = self._call("getblockheader", [block, True])
        if not isinstance(header, dict) or header.get("hash") != block:
            raise ChainUnavailable()
        height, block_time = header.get("height"), header.get("time")
        if (
            not integer(height, 0, tip_height)
            or not integer(block_time, 0, 9_007_199_254_740_991)
            or not integer(header.get("confirmations"), 1, tip_height + 1)
            or confirmations != tip_height - height + 1
            or header["confirmations"] != confirmations
            or self._call("getblockhash", [height]) != block
            or self._call("getblockhash", [tip_height]) != tip_hash
        ):
            raise ChainUnavailable()
        # These sequential reads confirm observed inclusion, not an atomic or
        # independently proven canonical chain. The browser must repeat them.
        return {
            "confirmed": True,
            "block_height": height,
            "block_hash": block,
            "block_time": block_time,
        }


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

    def reply(
        self, code: int, text: str, origin: str | None = None, *, json_body: bool = False
    ) -> None:
        body = text.encode("ascii")
        self.send_response(code)
        self.send_header(
            "Content-Type", "application/json" if json_body else "text/plain; charset=ascii"
        )
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
        parsed = route(self.path)
        if parsed is None:
            self.reply(404, "Unknown chain route")
            return
        origin = origins[0] if origins else None
        try:
            value = self.server.reader.observe(self.path)
            self.reply(200, value, origin, json_body=parsed[0] in {"status", "outspend"})
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
