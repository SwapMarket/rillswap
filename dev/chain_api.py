"""Read-only, loopback-published regtest chain observations. No wallet or swap state."""

from __future__ import annotations

import base64
import json
import os
import re
import threading
import time
from decimal import Decimal, InvalidOperation
from html import escape
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
EXPLORER_ROUTE = re.compile(r"/tx/([0-9a-f]{64})\Z")
ADDRESS_ROUTE = re.compile(r"/api/address/(bcrt1[0-9a-z]{8,90})/txs\Z")
# Regtest has no fee market: mempool's recommended-fees shape at a fixed 1 sat/vB,
# at or above Core's default relay minimum, so no fee RPC needs whitelisting.
REGTEST_FEES = json.dumps(
    {"fastestFee": 1, "halfHourFee": 1, "hourFee": 1, "economyFee": 1, "minimumFee": 1}
)
MAX_RAW_TRANSACTION_BYTES = 100_000
MAX_TRANSACTION_RPC_BYTES = 4 * 1024 * 1024
MAX_ADDRESS_BLOCKS = 1_000_000
MAX_ADDRESS_TRANSACTIONS = 100
ACTIVITY_BATCH_BLOCKS = 256
ACTIVITY_SECONDS = 12
RPC_METHODS = frozenset(
    {
        "getblockhash",
        "getblockchaininfo",
        "getrawtransaction",
        "getblockheader",
        "gettxout",
        "getdescriptoractivity",
    }
)


def route(path: str) -> tuple[str, tuple[str, ...]] | None:
    """Validate all path parameters before a request can reach Core."""
    if path == "/api/blocks/tip/height":
        return "tip-height", ()
    if path == "/api/blocks/tip/hash":
        return "tip-hash", ()
    if path == "/api/v1/fees/recommended":
        return "fees", ()
    if (match := BLOCK_ROUTE.fullmatch(path)) and int(match[1]) < 500_000_000:
        return "block-height", (match[1],)
    if match := TRANSACTION_ROUTE.fullmatch(path):
        return match[2], (match[1],)
    if (match := OUTSPEND_ROUTE.fullmatch(path)) and int(match[2]) <= 0xFFFFFFFF:
        return "outspend", (match[1], match[2])
    if match := EXPLORER_ROUTE.fullmatch(path):
        return "explorer", (match[1],)
    if match := ADDRESS_ROUTE.fullmatch(path):
        return "address", (match[1],)
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


def satoshis(amount: Any) -> int:
    """Validate exact Core JSON amounts without rounding through binary floats."""
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
        return int(quantized * 100_000_000)
    except InvalidOperation as exc:
        raise ChainUnavailable() from exc


def output_sample(value: Any, tip_hash: str, tip_height: int) -> tuple[int, str, int, bool]:
    """Require an affirmative, confirmed Core UTXO observation on this tip."""
    if not isinstance(value, dict) or value.get("bestblock") != tip_hash:
        raise ChainUnavailable()
    confirmations = value.get("confirmations")
    if not integer(confirmations, 1, tip_height + 1) or type(value.get("coinbase")) is not bool:
        raise ChainUnavailable()
    amount = satoshis(value.get("value"))
    script = value.get("scriptPubKey")
    if not isinstance(script, dict) or not isinstance(script.get("hex"), str):
        raise ChainUnavailable()
    if not re.fullmatch(r"(?:[0-9a-f]{2}){0,10000}", script["hex"]):
        raise ChainUnavailable()
    return amount, script["hex"], confirmations, value["coinbase"]


class ChainUnavailable(Exception):
    """Upstream errors deliberately carry no backend response to HTTP clients."""


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ChainUnavailable()


class ChainReader:
    def __init__(self) -> None:
        self.opener = build_opener(ProxyHandler({}), NoRedirect())
        self._activity_lock = threading.Lock()

    def _post(
        self, payload: Any, limit: int, timeout: float = 3, deadline: float | None = None
    ) -> Any:
        if deadline is not None:
            timeout = min(timeout, deadline - time.monotonic())
        if timeout <= 0:
            raise ChainUnavailable()
        auth = base64.b64encode(":".join(CORE_AUTH).encode()).decode()
        request = Request(
            CORE_URL,
            data=json.dumps(payload).encode(),
            headers={"Authorization": f"Basic {auth}", "Content-Type": "application/json"},
            method="POST",
        )
        try:
            with self.opener.open(request, timeout=timeout) as response:
                if response.status != 200:
                    raise ChainUnavailable()
                body = response.read(limit + 1)
                if len(body) > limit:
                    raise ChainUnavailable()
            if deadline is not None and time.monotonic() >= deadline:
                raise ChainUnavailable()
            return json.loads(body, parse_float=Decimal, parse_constant=reject_constant)
        except (OSError, HTTPError, HTTPException, ValueError, KeyError) as exc:
            raise ChainUnavailable() from exc

    def _call(self, method: str, params: list[Any], *, deadline: float | None = None) -> Any:
        if method not in RPC_METHODS:
            raise ChainUnavailable()
        large = method in {"getrawtransaction", "getdescriptoractivity"}
        result = self._post(
            {"jsonrpc": "2.0", "id": 1, "method": method, "params": params},
            MAX_TRANSACTION_RPC_BYTES if large else 16384,
            8 if method == "getdescriptoractivity" else 3,
            deadline,
        )
        if (
            not isinstance(result, dict)
            or type(result.get("id")) is not int
            or result["id"] != 1
            or result.get("error")
            or "result" not in result
        ):
            raise ChainUnavailable()
        return result["result"]

    def _block_hashes(self, start: int, stop: int, deadline: float) -> list[str]:
        """A fixed read-only batch, never an arbitrary RPC proxy."""
        if not 1 <= start <= stop or stop - start >= ACTIVITY_BATCH_BLOCKS:
            raise ChainUnavailable()
        result = self._post(
            [
                {"jsonrpc": "2.0", "id": height, "method": "getblockhash", "params": [height]}
                for height in range(start, stop + 1)
            ],
            128 * 1024,
            deadline=deadline,
        )
        if not isinstance(result, list) or len(result) != stop - start + 1:
            raise ChainUnavailable()
        hashes = {}
        for item in result:
            if (
                not isinstance(item, dict)
                or not integer(item.get("id"), start, stop)
                or item.get("error")
                or item["id"] in hashes
                or not isinstance(item.get("result"), str)
                or not HEX32.fullmatch(item["result"])
            ):
                raise ChainUnavailable()
            hashes[item["id"]] = item["result"]
        return [hashes[height] for height in range(start, stop + 1)]

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
        if kind == "fees":
            return REGTEST_FEES
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
        if kind == "address":
            if not self._activity_lock.acquire(blocking=False):
                raise ChainUnavailable()
            try:
                return json.dumps(self.address_history(txid, height, tip_hash))
            finally:
                self._activity_lock.release()
        if kind == "explorer":
            transaction = self._call("getrawtransaction", [txid, True])
            if not isinstance(transaction, dict):
                raise ChainUnavailable()
            status = self.transaction_status(txid, height, tip_hash, transaction=transaction)
            return transaction_page(transaction, status, height)
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

    def transaction_status(
        self,
        txid: str,
        tip_height: int,
        tip_hash: str,
        transaction: Any = None,
        deadline: float | None = None,
    ) -> dict[str, Any]:
        call = (
            self._call
            if deadline is None
            else lambda method, params: self._call(method, params, deadline=deadline)
        )
        if transaction is None:
            transaction = call("getrawtransaction", [txid, True])
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
        header = call("getblockheader", [block, True])
        if not isinstance(header, dict) or header.get("hash") != block:
            raise ChainUnavailable()
        height, block_time = header.get("height"), header.get("time")
        if (
            not integer(height, 0, tip_height)
            or not integer(block_time, 0, 9_007_199_254_740_991)
            or not integer(header.get("confirmations"), 1, tip_height + 1)
            or confirmations != tip_height - height + 1
            or header["confirmations"] != confirmations
            or call("getblockhash", [height]) != block
            or call("getblockhash", [tip_height]) != tip_hash
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

    def address_history(self, address: str, tip_height: int, tip_hash: str) -> list[dict[str, Any]]:
        """Explicit, bounded regtest reads only. No index, cache, wallet, or startup scan.

        Scan all active blocks, not a recent window that could hide a duplicate
        deposit. Oversized histories, timeouts and reorgs are unavailable, never
        evidence of an empty address. Core validates the addr() descriptor.
        """
        if tip_height > MAX_ADDRESS_BLOCKS:
            raise ChainUnavailable()
        deadline = time.monotonic() + ACTIVITY_SECONDS
        receives = {}
        event_count = 0
        address_script = None
        for start in range(1, max(2, tip_height + 1), ACTIVITY_BATCH_BLOCKS):
            stop = min(tip_height, start + ACTIVITY_BATCH_BLOCKS - 1)
            hashes = self._block_hashes(start, stop, deadline) if tip_height else []
            result = self._call(
                "getdescriptoractivity",
                [hashes, [f"addr({address})"], stop == tip_height],
                deadline=deadline,
            )
            if (
                not isinstance(result, dict)
                or not isinstance(result.get("activity"), list)
                or len(result["activity"]) > 1000
            ):
                raise ChainUnavailable()
            event_count += len(result["activity"])
            if event_count > 1000:
                raise ChainUnavailable()
            for event in result["activity"]:
                if not isinstance(event, dict) or event.get("type") not in {"receive", "spend"}:
                    raise ChainUnavailable()
                if event["type"] == "spend":
                    continue
                txid, vout = event.get("txid"), event.get("vout")
                script = event.get("output_spk")
                if (
                    not isinstance(txid, str)
                    or not HEX32.fullmatch(txid)
                    or not integer(vout, 0, 10000)
                    or not isinstance(script, dict)
                    or not isinstance(script.get("hex"), str)
                    or not re.fullmatch(r"(?:[0-9a-f]{2}){1,10000}", script["hex"])
                ):
                    raise ChainUnavailable()
                if ("blockhash" in event or "height" in event) and (
                    not integer(event.get("height"), start, stop)
                    or event.get("blockhash") != hashes[event["height"] - start]
                ):
                    raise ChainUnavailable()
                if address_script is not None and script["hex"] != address_script:
                    raise ChainUnavailable()
                address_script = script["hex"]
                receives.setdefault(txid, []).append(
                    (
                        vout,
                        script["hex"],
                        satoshis(event.get("amount")),
                        event.get("blockhash"),
                        event.get("height"),
                    )
                )
                if len(receives) > MAX_ADDRESS_TRANSACTIONS:
                    raise ChainUnavailable()
        items = []
        for txid, expected in receives.items():
            transaction = self._call("getrawtransaction", [txid, True], deadline=deadline)
            outputs = transaction_outputs(transaction)
            if any(
                vout >= len(outputs)
                or outputs[vout]["scriptpubkey"] != script
                or outputs[vout]["value"] != amount
                for vout, script, amount, _block, _height in expected
            ):
                raise ChainUnavailable()
            status = self.transaction_status(txid, tip_height, tip_hash, transaction, deadline)
            if any(
                status["confirmed"] != (block is not None)
                or (
                    block is not None
                    and (status.get("block_hash"), status.get("block_height")) != (block, height)
                )
                for _vout, _script, _amount, block, height in expected
            ):
                raise ChainUnavailable()
            items.append(
                {
                    "txid": txid,
                    "vout": outputs,
                    "status": status,
                }
            )
        info = self._call("getblockchaininfo", [], deadline=deadline)
        if (
            not isinstance(info, dict)
            or info.get("chain") != "regtest"
            or info.get("blocks") != tip_height
            or info.get("bestblockhash") != tip_hash
        ):
            raise ChainUnavailable()
        return items


def transaction_outputs(transaction: Any) -> list[dict[str, Any]]:
    if (
        not isinstance(transaction, dict)
        or not isinstance(transaction.get("vout"), list)
        or not 1 <= len(transaction["vout"]) <= 1000
    ):
        raise ChainUnavailable()
    outputs = []
    for index, output in enumerate(transaction["vout"]):
        if (
            not isinstance(output, dict)
            or output.get("n") != index
            or type(output.get("n")) is not int
        ):
            raise ChainUnavailable()
        script = output.get("scriptPubKey")
        if (
            not isinstance(script, dict)
            or not isinstance(script.get("hex"), str)
            or not re.fullmatch(r"(?:[0-9a-f]{2}){0,10000}", script["hex"])
        ):
            raise ChainUnavailable()
        outputs.append({"scriptpubkey": script["hex"], "value": satoshis(output.get("value"))})
    return outputs


def transaction_page(transaction: dict[str, Any], status: dict[str, Any], tip_height: int) -> str:
    outputs = transaction_outputs(transaction)
    inputs = transaction.get("vin")
    if not isinstance(inputs, list) or not 1 <= len(inputs) <= 1000:
        raise ChainUnavailable()
    txid = transaction["txid"]
    if not isinstance(txid, str) or not HEX32.fullmatch(txid):
        raise ChainUnavailable()
    confirmations = tip_height - status["block_height"] + 1 if status["confirmed"] else 0
    heading = (
        f"{confirmations} confirmation(s), block {status['block_height']}"
        if confirmations
        else "Not confirmed on the active chain"
    )
    total = sum(output["value"] for output in outputs)
    if total > 2_100_000_000_000_000:
        raise ChainUnavailable()
    rows = []
    for index, output in enumerate(outputs[:100]):
        script = transaction["vout"][index]["scriptPubKey"]
        label = script.get("address", output["scriptpubkey"])
        if not isinstance(label, str) or len(label) > 20000:
            raise ChainUnavailable()
        amount = output["value"]
        rows.append(
            f"<tr><td>{index}</td><td>{amount // 100_000_000}.{amount % 100_000_000:08d} BTC</td>"
            f"<td>{escape(label)}</td></tr>"
        )
    references = []
    for item in inputs[:100]:
        if not isinstance(item, dict):
            raise ChainUnavailable()
        if "coinbase" in item:
            references.append("<li>Coinbase</li>")
        elif (
            isinstance(item.get("txid"), str)
            and HEX32.fullmatch(item["txid"])
            and integer(item.get("vout"), 0, 0xFFFFFFFF)
        ):
            references.append(
                f'<li><a href="/tx/{item["txid"]}">{item["txid"]}</a>:{item["vout"]}</li>'
            )
        else:
            raise ChainUnavailable()
    size = transaction.get("vsize")
    if not integer(size, 1, MAX_RAW_TRANSACTION_BYTES):
        raise ChainUnavailable()
    more = (
        "<p>Showing the first 100 inputs and outputs.</p>"
        if max(len(inputs), len(outputs)) > 100
        else ""
    )
    return (
        '<!doctype html><html lang="en"><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width">'
        f"<title>Regtest transaction {txid}</title>"
        "<style>body{font:16px system-ui;margin:2rem;overflow-wrap:anywhere}"
        "td{padding:.4rem}table{border-collapse:collapse}a{color:#245ea8}</style>"
        f"<h1>Regtest transaction</h1><p>{txid}</p><h2>{heading}</h2>"
        f'<p><a href="/tx/{txid}">Refresh status</a></p>'
        "<p>Total outputs (including change): "
        f"{total // 100_000_000}.{total % 100_000_000:08d} BTC. "
        f"Size: {size} vB.</p>"
        f"<h2>Inputs ({len(inputs)})</h2><ul>{''.join(references)}</ul>"
        f"<h2>Outputs ({len(outputs)})</h2><table><tr><th>Output</th><th>Value</th>"
        f"<th>Address or script</th></tr>{''.join(rows)}</table>{more}</html>"
    )


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
        self,
        code: int,
        text: str,
        origin: str | None = None,
        *,
        json_body: bool = False,
        html_body: bool = False,
    ) -> None:
        body = text.encode("utf-8" if html_body else "ascii")
        self.send_response(code)
        self.send_header(
            "Content-Type",
            "text/html; charset=utf-8"
            if html_body
            else "application/json"
            if json_body
            else "text/plain; charset=ascii",
        )
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Connection", "close")
        if html_body:
            self.send_header(
                "Content-Security-Policy",
                "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; "
                "form-action 'none'; frame-ancestors 'none'",
            )
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
            self.reply(
                200,
                value,
                origin,
                json_body=parsed[0] in {"status", "outspend", "address", "fees"},
                html_body=parsed[0] == "explorer",
            )
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
