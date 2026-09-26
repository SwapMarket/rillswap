"""Relay routing fails closed: public networks need a proxy, and it never leaks DNS."""

from __future__ import annotations

import asyncio
import socket
from pathlib import Path
from typing import Any

import pytest
from rill_core.wire.types import NetworkIdentity

from rill_provider.relay_client import (
    RelayConnection,
    RelayError,
    relay_proxy,
    require_relay_route,
)

NETWORKS = Path(__file__).parents[2] / "rill-docs" / "networks"
PUBLIC = ("mainnet", "signet", "testnet4")


def _network(name: str) -> NetworkIdentity:
    return NetworkIdentity.model_validate_json((NETWORKS / f"{name}.json").read_bytes())


@pytest.mark.parametrize("name", PUBLIC)
def test_public_networks_refuse_direct_relays_unless_explicit(name: str) -> None:
    with pytest.raises(RelayError, match="need a relay proxy"):
        require_relay_route(_network(name), None, allow_direct=False)
    assert require_relay_route(_network(name), None, allow_direct=True) is None
    proxy = "http://127.0.0.1:9080"
    assert require_relay_route(_network(name), proxy, allow_direct=False) == proxy


def test_regtest_may_connect_directly() -> None:
    assert (
        require_relay_route(_network("regtest-rillswap-e2e-v1"), None, allow_direct=False) is None
    )


@pytest.mark.parametrize(
    "proxy",
    [
        "socks5://127.0.0.1:9050",
        "http://10.0.0.1:9080",
        "http://tor.local:9080",
        "http://127.0.0.1",
        "http://user:pw@127.0.0.1:9080",
        "http://127.0.0.1:9080/path",
        "http://127.0.0.1:99999",
        "https://127.0.0.1:9080",
    ],
)
def test_only_loopback_http_connect_proxies_are_accepted(proxy: str) -> None:
    with pytest.raises(RelayError, match="loopback"):
        relay_proxy(proxy)
    assert relay_proxy("http://[::1]:9080") == "http://[::1]:9080"


def test_proxied_relays_must_use_tls() -> None:
    with pytest.raises(RelayError, match="wss://"):
        RelayConnection("ws://relay.example/", proxy="http://127.0.0.1:9080")
    RelayConnection("wss://relay.example/", proxy="http://127.0.0.1:9080")


def test_proxy_receives_the_host_name_and_no_local_lookup_happens(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    lookups: list[Any] = []
    original = socket.getaddrinfo

    def guarded(host: Any, *args: Any, **kwargs: Any) -> Any:  # noqa: ANN401
        lookups.append(host)
        return original(host, *args, **kwargs)

    monkeypatch.setattr(socket, "getaddrinfo", guarded)

    async def scenario() -> list[bytes]:
        requests: list[bytes] = []

        async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
            requests.append(await reader.readuntil(b"\r\n\r\n"))
            writer.write(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")
            await writer.drain()
            writer.close()

        server = await asyncio.start_server(handle, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        try:
            with pytest.raises(RelayError):
                async with RelayConnection(
                    "wss://relay.example.invalid/", proxy=f"http://127.0.0.1:{port}", open_timeout=5
                ):
                    pass
        finally:
            server.close()
            await server.wait_closed()
        return requests

    requests = asyncio.run(scenario())
    assert requests
    assert requests[0].startswith(b"CONNECT relay.example.invalid:443 HTTP/1.1\r\n")
    assert "relay.example.invalid" not in lookups


@pytest.mark.parametrize(
    ("proxy", "allow_direct", "relays", "refusal"),
    [
        (None, False, ("wss://relay.example/",), "need a relay proxy"),
        ("http://127.0.0.1:9080", False, ("ws://relay.example/",), "wss://"),
    ],
)
def test_serving_refuses_an_unsafe_relay_route_at_startup(
    proxy: str | None,
    allow_direct: bool,  # noqa: FBT001
    relays: tuple[str, ...],
    refusal: str,
) -> None:
    from types import SimpleNamespace  # noqa: PLC0415

    from rill_provider import cli  # noqa: PLC0415
    from rill_provider.operator_config import OperatorConfigError  # noqa: PLC0415

    config: Any = SimpleNamespace(
        network=_network("signet"),
        relay_proxy=proxy,
        allow_direct_relays=allow_direct,
        relay_urls=relays,
        provider_destination_script=None,
        lnd=None,
        bitcoin_core=None,
    )
    with pytest.raises(OperatorConfigError, match=refusal):
        asyncio.run(cli._serve(config, None, ""))  # type: ignore[arg-type]  # noqa: SLF001


def test_public_firm_offers_refuse_to_start_without_settlement() -> None:
    from types import SimpleNamespace  # noqa: PLC0415

    from rill_provider import cli  # noqa: PLC0415
    from rill_provider.operator_config import OperatorConfigError  # noqa: PLC0415

    config: Any = SimpleNamespace(
        network=_network("signet"),
        provider_destination_script="0014" + "11" * 20,
        lnd=SimpleNamespace(payment_macaroon=None),
        bitcoin_core=object(),
    )
    with pytest.raises(OperatorConfigError, match="payment_macaroon"):
        asyncio.run(cli._serve(config, None, ""))  # type: ignore[arg-type]  # noqa: SLF001
