"""HTTP CONNECT requests to Tor's ``HTTPTunnelPort``, each on its own circuit.

Tor resolves the CONNECT target itself, so the target name never reaches a
local resolver. Every tunnel carries a fresh random ``X-Tor-Stream-Isolation``
value: under Tor's default ``IsolateSOCKSAuth`` (Tor 0.3.2.1-alpha and later)
streams with different values never share a circuit, so no exit can link two
of the provider's connections by their circuit. No torrc change is needed;
only an explicit ``NoIsolateSOCKSAuth`` on the port turns this off.

This module is standard library only, because the notification worker
imports it in a child process that loads nothing but Apprise.
"""

from __future__ import annotations

import re
import secrets

ISOLATION_HEADER = "X-Tor-Stream-Isolation"
MAX_TUNNEL_REPLY = 8 * 1024  # status line plus Tor's few headers
_TARGET_HOST = re.compile(r"[A-Za-z0-9.\-_:]+")
_ESTABLISHED = re.compile(rb"HTTP/1\.[01] 200[ \r]")


def isolation_key() -> str:
    """Return a fresh value that gives one tunnel a circuit of its own."""
    return secrets.token_hex(16)


def connect_request(host: str, port: int, isolation: str) -> bytes:
    """Return the CONNECT request for ``host:port`` on the ``isolation`` circuit.

    IPv6 literals are bracketed. A host or port that could not be a CONNECT
    target (for example one holding whitespace) is refused, so a hostile name
    can never inject a header line.
    """
    if not _TARGET_HOST.fullmatch(host) or not 0 < port < 65536:  # noqa: PLR2004 - port range
        raise ValueError("invalid tunnel target")
    if not re.fullmatch(r"[0-9a-f]{32}", isolation):
        raise ValueError("invalid isolation key")
    target = f"[{host}]:{port}" if ":" in host else f"{host}:{port}"
    return (
        f"CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n{ISOLATION_HEADER}: {isolation}\r\n\r\n"
    ).encode("ascii")


def tunnel_established(reply: bytes) -> bool:
    """Whether the proxy's complete reply head accepts the tunnel."""
    return _ESTABLISHED.match(reply) is not None
