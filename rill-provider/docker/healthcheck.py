#!/usr/bin/env python3
"""Non-mutating container health probes for the provider image.

``rill-provider-healthcheck provider --config PATH`` checks every backend the
provider config names through the same loopback ports the provider uses: an
authenticated Core ``getblockchaininfo`` on the configured chain, a verified
TLS handshake with LND, an HTTP reply from the relay proxy and, for ERC20
profiles, the EVM RPC chain id. ``rill-provider-healthcheck tor`` requires a
fully bootstrapped Tor client. Failures print one line without credentials
and exit 1.
"""

from __future__ import annotations

import argparse
import base64
import json
import socket
import ssl
import sys
import urllib.request
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

TIMEOUT_SECONDS = 5
TOR_CONTROL = ("127.0.0.1", 9051)
TOR_COOKIE = Path("/var/lib/rill-tor/control_auth_cookie")
CORE_CHAIN = {"mainnet": "main"}  # Core's chain name when it differs from RillSwap's
RELAY_PROXY_PROBE = b"CONNECT 127.0.0.1:1 HTTP/1.1\r\nHost: 127.0.0.1:1\r\n\r\n"
DRAIN_LIMIT_BYTES = 64 * 1024


class UnhealthyError(Exception):
    """A probe failed; the message must not contain secrets."""


def _post_json(url: str, body: dict[str, Any], headers: dict[str, str]) -> dict[str, Any]:
    request = urllib.request.Request(  # noqa: S310 - loopback or operator-configured URL
        url,
        data=json.dumps(body).encode(),
        headers={"Content-Type": "application/json", **headers},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=TIMEOUT_SECONDS) as response:  # noqa: S310
            reply = json.load(response)
    except OSError as error:
        raise UnhealthyError(f"{type(error).__name__} from {urlsplit(url).netloc}") from None
    if not isinstance(reply, dict):
        raise UnhealthyError(f"non-object JSON-RPC reply from {urlsplit(url).netloc}")
    return reply


def check_core(core: dict[str, Any], base: Path, network: str) -> None:
    """Require an authenticated Core reply for the configured chain."""
    cookie = (base / core["cookie_file"]).read_text().strip()
    auth = base64.b64encode(cookie.encode()).decode()
    reply = _post_json(
        f"http://127.0.0.1:{core['port']}/",
        {"jsonrpc": "2.0", "id": 0, "method": "getblockchaininfo", "params": []},
        {"Authorization": f"Basic {auth}"},
    )
    chain = (reply.get("result") or {}).get("chain")
    if chain != CORE_CHAIN.get(network, network):
        raise UnhealthyError(f"Core reports chain {chain!r}, config expects {network!r}")


def _drain(connection: socket.socket) -> None:
    """Half-close and read to EOF before closing.

    Closing with unread data (a TLS session ticket, the rest of an HTTP reply)
    sends a TCP reset, which the loopback forwarder logs as an error on every
    probe. The probe already has its answer, so failures here are ignored.
    """
    try:
        connection.shutdown(socket.SHUT_WR)
        received = 0
        while received < DRAIN_LIMIT_BYTES and (chunk := connection.recv(4096)):
            received += len(chunk)
    except OSError:
        pass


def check_lnd(lnd: dict[str, Any], base: Path) -> None:
    """Require a TLS handshake with LND verified by the configured certificate."""
    context = ssl.create_default_context(cafile=str(base / lnd["tls_certificate"]))
    context.set_alpn_protocols(["h2"])
    try:
        with (
            socket.create_connection(("127.0.0.1", lnd["port"]), TIMEOUT_SECONDS) as raw,
            context.wrap_socket(raw, server_hostname="127.0.0.1") as tls,
        ):
            _drain(tls)
    except OSError as error:
        raise UnhealthyError(f"LND TLS handshake failed: {type(error).__name__}") from None


def check_relay_proxy(url: str) -> None:
    """Require an HTTP reply from the relay proxy, not just a local listener.

    The loopback port is a forwarder that accepts even when its target is
    wrong or down, so the probe asks the far end to tunnel to a private
    address. Tor refuses that locally ("403 Forbidden (private address)")
    without building a circuit, so the check needs no outside network.
    """
    parts = urlsplit(url)
    try:
        with socket.create_connection((parts.hostname, parts.port), TIMEOUT_SECONDS) as proxy:
            proxy.sendall(RELAY_PROXY_PROBE)
            reply = b""
            while b"\r\n\r\n" not in reply and len(reply) < DRAIN_LIMIT_BYTES:
                if not (chunk := proxy.recv(1024)):
                    break
                reply += chunk
            _drain(proxy)
    except OSError as error:
        detail = f"relay proxy {parts.netloc} failed: {type(error).__name__}"
        raise UnhealthyError(detail) from None
    if not reply.startswith(b"HTTP/1."):
        raise UnhealthyError(f"relay proxy {parts.netloc} gave no HTTP reply")


def check_evm(evm: dict[str, Any]) -> None:
    """Require the EVM RPC to report the configured chain id."""
    reply = _post_json(
        evm["rpc_url"], {"jsonrpc": "2.0", "id": 0, "method": "eth_chainId", "params": []}, {}
    )
    if reply.get("result") != hex(evm["chain_id"]):
        raise UnhealthyError("EVM RPC reports a different chain id")


def check_provider(config_path: Path) -> None:
    """Check every backend the provider config names."""
    config = json.loads(config_path.read_text())
    base = config_path.parent
    if config.get("bitcoin_core"):
        check_core(config["bitcoin_core"], base, config["network"]["name"])
    if config.get("lnd"):
        check_lnd(config["lnd"], base)
    if config.get("relay_proxy"):
        check_relay_proxy(config["relay_proxy"])
    if config.get("evm"):
        check_evm(config["evm"])


def check_tor() -> None:
    """Require a fully bootstrapped Tor client."""
    cookie = TOR_COOKIE.read_bytes().hex()
    with socket.create_connection(TOR_CONTROL, TIMEOUT_SECONDS) as control:
        control.sendall(
            f"AUTHENTICATE {cookie}\r\nGETINFO status/bootstrap-phase\r\nQUIT\r\n".encode()
        )
        reply = b""
        while chunk := control.recv(4096):
            reply += chunk
    if b"PROGRESS=100" not in reply:
        raise UnhealthyError("Tor has not finished bootstrapping")


def main() -> int:
    """Run one probe; return 0 when healthy and 1 otherwise."""
    parser = argparse.ArgumentParser(prog="rill-provider-healthcheck", description=__doc__)
    probes = parser.add_subparsers(dest="probe", required=True)
    provider = probes.add_parser("provider", help="check the backends of one provider config")
    provider.add_argument("--config", type=Path, required=True)
    probes.add_parser("tor", help="check that the Tor client has bootstrapped")
    args = parser.parse_args()
    try:
        if args.probe == "tor":
            check_tor()
        else:
            check_provider(args.config)
    except (UnhealthyError, OSError, KeyError, TypeError, ValueError) as error:
        detail = error if isinstance(error, UnhealthyError) else type(error).__name__
        print(f"unhealthy: {detail}", file=sys.stderr)  # noqa: T201 - the probe's report
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
