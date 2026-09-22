"""Explicit read-only regtest Core RPC transaction-byte checks.

No wallet, ledger, mempool, chain-confirmation, funding, or payment action.
The operator supplies the full network identity; Core attests only chain label
and genesis, NOT the deployment namespace or consensus policy identifier.
"""

from __future__ import annotations

import json
import os
import stat
from pathlib import Path
from typing import TYPE_CHECKING, Any

import httpx
from rill_core.settlement import FundingBindingTransactionMatch, check_funding_binding_transaction
from rill_core.wire.messages import FundingBinding
from rill_core.wire.types import NetworkIdentity

if TYPE_CHECKING:
    from rill_core.settlement import TaprootKeyOperations
    from rill_core.wire.messages import ContractTerms

MAX_COOKIE_BYTES = 512
MAX_RESPONSE_BYTES = 256 * 1024
MAX_TRANSACTION_HEX_BYTES = 200_000
MAX_PORT = 65535
HTTP_OK = 200
CONNECT_SECONDS = 2.0
READ_SECONDS = 5.0


class CoreReadError(Exception):
    """No usable static transaction bytes were established; never absence proof."""


class CoreAuthError(CoreReadError):
    """RPC authentication failed or a protected cookie was not readable."""


class CoreProtocolError(CoreReadError):
    """Core RPC response or network preflight was malformed or inconsistent."""


class CoreUnavailableError(CoreReadError):
    """The requested transaction or node was unavailable, not known absent."""


def _unique_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _cookie(path: Path) -> tuple[str, str]:
    try:
        result = _read_cookie(path)
    except (OSError, ValueError, UnicodeError):
        raise CoreAuthError("Core cookie unavailable; no transaction check performed") from None
    return result


def _read_cookie(path: Path) -> tuple[str, str]:
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb", closefd=True) as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077:
            raise ValueError("cookie must be a private regular file")
        value = stream.read(MAX_COOKIE_BYTES + 1)
    if len(value) > MAX_COOKIE_BYTES or not value:
        raise ValueError("cookie exceeds size limit")
    text = value.removesuffix(b"\n").decode("ascii")
    username, password = text.split(":", 1)
    if username != "__cookie__" or not password or any(char in text for char in "\r\n\x00"):
        raise ValueError("unsupported cookie contents")
    return username, password


class RegtestCoreTransactionReader:
    """Fetch static bytes from explicitly configured local Bitcoin Core v30.

    A matching result does not authenticate the funder's binding signature,
    wallet prevouts or terms, nor imply current mempool/chain/UTXO status.
    Construction makes no RPC call and does not open or migrate any ledger.
    """

    def __init__(
        self,
        *,
        port: int,
        cookie_path: str | os.PathLike[str],
        network: NetworkIdentity,
        host: str = "127.0.0.1",
    ) -> None:
        """Configure a numeric loopback endpoint without connecting to it."""
        if host not in ("127.0.0.1", "::1") or type(port) is not int or not 1 <= port <= MAX_PORT:
            raise ValueError("Core RPC must be a numeric loopback host and valid port")
        if not isinstance(network, NetworkIdentity) or network.name != "regtest":
            raise ValueError("only explicit complete regtest network identity is supported")
        self._url = f"http://[{host}]:{port}/" if host == "::1" else f"http://{host}:{port}/"
        self._cookie_path = Path(cookie_path)
        self._network = network

    def fetch_binding_byte_match(
        self,
        binding: FundingBinding,
        terms: ContractTerms,
        *,
        keys: TaprootKeyOperations,
    ) -> FundingBindingTransactionMatch:
        """Explicitly read bytes and run only the core static matcher.

        Synchronous operator-invoked regtest diagnostic, not a service or
        watcher. Inactivity timeouts are NOT a total-duration bound: a
        configured listener that trickles incomplete HTTP can block this call
        indefinitely. Never use it to enforce funding/payment deadlines.
        """
        if not isinstance(terms.network_identity, NetworkIdentity) or (
            terms.network_identity != self._network
        ):
            raise ValueError("binding terms and configured full network identity differ")
        if not isinstance(binding, FundingBinding):
            raise TypeError("a parsed binding is required")
        username, password = _cookie(self._cookie_path)
        try:
            with httpx.Client(
                base_url=self._url,
                auth=httpx.BasicAuth(username, password),
                trust_env=False,
                follow_redirects=False,
                timeout=httpx.Timeout(READ_SECONDS, connect=CONNECT_SECONDS),
            ) as client:
                info = self._rpc(client, "getblockchaininfo", [], 1)
                if not isinstance(info, dict) or info.get("chain") != "regtest":
                    raise CoreProtocolError("Core network label differs from configured regtest")
                genesis = self._rpc(client, "getblockhash", [0], 2)
                if genesis != self._network.genesis_hash:
                    raise CoreProtocolError("Core genesis differs from configured regtest")
                raw_hex = self._rpc(client, "getrawtransaction", [binding.funding_txid, False], 3)
        except httpx.HTTPError:
            raise CoreUnavailableError("Core RPC transport unavailable") from None
        if (
            not isinstance(raw_hex, str)
            or len(raw_hex) > MAX_TRANSACTION_HEX_BYTES
            or (len(raw_hex) % 2 or any(char not in "0123456789abcdef" for char in raw_hex))
        ):
            raise CoreProtocolError("Core transaction response is not bounded lowercase hex")
        # Static mismatch remains an explicit core ValidationError, not an
        # assertion of missing/invalid live funding or a reason to retry.
        return check_funding_binding_transaction(bytes.fromhex(raw_hex), binding, terms, keys=keys)

    def _rpc(
        self,
        client: httpx.Client,
        method: str,
        params: list[object],
        request_id: int,
    ) -> Any:  # noqa: ANN401
        if method not in ("getblockchaininfo", "getblockhash", "getrawtransaction"):
            raise CoreProtocolError("unsupported read-only Core RPC method")
        try:
            with client.stream(
                "POST",
                "/",
                headers={"Accept-Encoding": "identity"},
                json={"jsonrpc": "2.0", "id": request_id, "method": method, "params": params},
                timeout=httpx.Timeout(READ_SECONDS, connect=CONNECT_SECONDS),
            ) as response:
                if response.status_code in (401, 403):
                    raise CoreAuthError("Core RPC authentication rejected")
                if response.status_code != HTTP_OK:
                    raise CoreUnavailableError(
                        "Core RPC failed without usable transaction evidence"
                    )
                if response.headers.get("content-encoding", "identity") != "identity":
                    raise CoreProtocolError("compressed Core RPC responses are unsupported")
                chunks = bytearray()
                for part in response.iter_raw():
                    if len(chunks) + len(part) > MAX_RESPONSE_BYTES:
                        raise CoreProtocolError("Core RPC response exceeded resource limit")
                    chunks.extend(part)
            envelope = json.loads(
                chunks,
                object_pairs_hook=_unique_pairs,
                parse_constant=lambda _value: (_ for _ in ()).throw(ValueError("non-JSON number")),
            )
        except (ValueError, UnicodeError):
            raise CoreProtocolError("Core RPC response is not strict JSON") from None
        except httpx.HTTPError:
            raise CoreUnavailableError("Core RPC transport unavailable") from None
        if (
            not isinstance(envelope, dict)
            or envelope.get("jsonrpc") != "2.0"
            or type(envelope.get("id")) is not int
            or envelope["id"] != request_id
            or ("result" in envelope) == ("error" in envelope)
        ):
            raise CoreProtocolError("Core RPC response envelope is inconsistent")
        if "error" in envelope:
            error = envelope["error"]
            if (
                not isinstance(error, dict)
                or type(error.get("code")) is not int
                or not isinstance(error.get("message"), str)
            ):
                raise CoreProtocolError("Core RPC error envelope is malformed")
            raise CoreUnavailableError("Core RPC result unavailable; no absence claim")
        return envelope["result"]
