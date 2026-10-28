"""CONNECT requests for Tor's HTTPTunnelPort carry a per-tunnel isolation key."""

from __future__ import annotations

import pytest

from rill_provider.tor_tunnel import connect_request, isolation_key, tunnel_established

KEY = "0123456789abcdef" * 2


def test_requests_name_the_target_and_its_circuit() -> None:
    assert connect_request("relay.example", 443, KEY) == (
        b"CONNECT relay.example:443 HTTP/1.1\r\nHost: relay.example:443\r\n"
        b"X-Tor-Stream-Isolation: " + KEY.encode() + b"\r\n\r\n"
    )
    assert connect_request("2001:db8::1", 8080, KEY).startswith(
        b"CONNECT [2001:db8::1]:8080 HTTP/1.1\r\nHost: [2001:db8::1]:8080\r\n"
    )


@pytest.mark.parametrize(
    ("host", "port"),
    [
        ("relay.example\r\nX-Injected: 1", 443),
        ("relay example", 443),
        ("", 443),
        ("relay.example", 0),
        ("relay.example", 65536),
    ],
)
def test_targets_that_could_inject_or_misroute_are_refused(host: str, port: int) -> None:
    with pytest.raises(ValueError, match="invalid tunnel target"):
        connect_request(host, port, KEY)


def test_isolation_keys_are_fresh_and_well_formed() -> None:
    keys = {isolation_key() for _ in range(64)}
    assert len(keys) == 64  # all distinct
    for key in keys:
        connect_request("relay.example", 443, key)
    with pytest.raises(ValueError, match="invalid isolation key"):
        connect_request("relay.example", 443, "tor\r\n")


@pytest.mark.parametrize(
    ("reply", "established"),
    [
        (b"HTTP/1.0 200 OK\r\n\r\n", True),
        (b"HTTP/1.1 200 Connection established\r\nVia: tor\r\n\r\n", True),
        (b"HTTP/1.1 200\r\n\r\n", True),
        (b"HTTP/1.0 405 Method Not Allowed\r\n\r\n", False),
        (b"HTTP/1.1 2000 OK\r\n\r\n", False),
        (b"SSH-2.0-OpenSSH\r\n\r\n", False),
    ],
)
def test_only_a_200_reply_establishes_the_tunnel(reply: bytes, *, established: bool) -> None:
    assert tunnel_established(reply) is established
