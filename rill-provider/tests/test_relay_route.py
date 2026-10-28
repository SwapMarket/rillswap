"""Relay routing fails closed: public networks need a proxy, and it never leaks DNS."""

from __future__ import annotations

import asyncio
import json
import socket
from contextlib import suppress
from pathlib import Path
from typing import TYPE_CHECKING, Any
from urllib.parse import urlsplit

import pytest
from fake_relay import FakeRelay
from rill_core.wire.types import NetworkIdentity

from rill_provider.relay_client import (
    RelayConnection,
    RelayError,
    is_onion_relay,
    reachable_relays,
    relay_proxy,
    require_relay_route,
)

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable

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


ONION = "ws://gnostr2jnapk72mnagq3cuykfon73temzp77hcbncn4silgt77boruid.onion"


def test_onion_relays_are_recognized_strictly() -> None:
    assert is_onion_relay(ONION)
    assert is_onion_relay(ONION.replace("ws://", "wss://") + ":8443/path")
    for url in ("ws://short.onion", "ws://relay.example.org.onion", "wss://relay.example", "x"):
        assert not is_onion_relay(url)


def test_onion_relays_need_the_proxy_and_are_skipped_without_it() -> None:
    proxy = "http://127.0.0.1:9080"
    with pytest.raises(RelayError, match="onion relay needs the relay proxy"):
        RelayConnection(ONION)
    RelayConnection(ONION, proxy=proxy)  # plain ws:// is tunneled only to an onion
    relays = ("wss://relay.example/", ONION, "wss://other.example/")
    assert reachable_relays(relays, None) == ("wss://relay.example/", "wss://other.example/")
    assert reachable_relays(relays, proxy) == relays


def test_the_service_policy_announces_onion_relays_only_with_the_proxy() -> None:
    from rill_provider.operator_config import load_config  # noqa: PLC0415

    example = Path(__file__).parents[1] / "examples" / "provider.signet.json"
    config = load_config(example).model_copy(update={"relay_urls": ("wss://relay.example/", ONION)})
    assert config.relay_proxy is not None
    assert config.service_policy().relay_urls == ("wss://relay.example/", ONION)
    direct = config.model_copy(update={"relay_proxy": None, "allow_direct_relays": True})
    assert direct.service_policy().relay_urls == ("wss://relay.example/",)


def _tunnel_proxy(
    requests: list[bytes], target_port: int, reply: bytes
) -> Callable[[asyncio.StreamReader, asyncio.StreamWriter], Awaitable[None]]:
    """A CONNECT proxy that records each request and pipes to a local port."""

    async def pipe(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        with suppress(ConnectionError):
            while data := await reader.read(65536):
                writer.write(data)
                await writer.drain()
        writer.close()

    async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        requests.append(await reader.readuntil(b"\r\n\r\n"))
        writer.write(reply)
        await writer.drain()
        if not reply.startswith(b"HTTP/1.1 200"):
            writer.close()
            return
        upstream_reader, upstream_writer = await asyncio.open_connection("127.0.0.1", target_port)
        await asyncio.gather(pipe(reader, upstream_writer), pipe(upstream_reader, writer))

    return handle


def test_plain_ws_onion_relays_are_tunneled_through_the_proxy(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    lookups: list[Any] = []
    original = socket.getaddrinfo

    def guarded(host: Any, *args: Any, **kwargs: Any) -> Any:  # noqa: ANN401
        lookups.append(host)
        return original(host, *args, **kwargs)

    monkeypatch.setattr(socket, "getaddrinfo", guarded)

    async def scenario() -> list[bytes]:
        relay = FakeRelay()
        relay_port = urlsplit(await relay.start()).port
        assert relay_port is not None
        requests: list[bytes] = []
        established = b"HTTP/1.1 200 Connection established\r\n\r\n"
        server = await asyncio.start_server(
            _tunnel_proxy(requests, relay_port, established), "127.0.0.1", 0
        )
        proxy = f"http://127.0.0.1:{server.sockets[0].getsockname()[1]}"
        event = json.dumps({"id": "01" * 32, "kind": 1059, "tags": [], "content": "x"}).encode()
        try:
            async with RelayConnection(f"{ONION}/", proxy=proxy, open_timeout=5) as connection:
                assert await connection.publish(event)
        finally:
            server.close()
            await relay.stop()
        return requests

    requests = asyncio.run(scenario())
    host = ONION.removeprefix("ws://")
    assert requests == [f"CONNECT {host}:80 HTTP/1.1\r\nHost: {host}:80\r\n\r\n".encode()]
    assert host not in lookups


def test_a_refused_onion_tunnel_is_an_unavailable_relay() -> None:
    async def scenario() -> list[bytes]:
        requests: list[bytes] = []
        forbidden = b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n"
        server = await asyncio.start_server(_tunnel_proxy(requests, 9, forbidden), "127.0.0.1", 0)
        proxy = f"http://127.0.0.1:{server.sockets[0].getsockname()[1]}"
        try:
            with pytest.raises(RelayError, match="relay unavailable"):
                async with RelayConnection(f"{ONION}:8080/", proxy=proxy, open_timeout=5):
                    pass
        finally:
            server.close()
        return requests

    assert asyncio.run(scenario())[0].startswith(f"CONNECT {ONION[5:]}:8080 ".encode())


@pytest.mark.parametrize(
    ("proxy", "allow_direct", "relays", "refusal"),
    [
        (None, False, ("wss://relay.example/",), "need a relay proxy"),
        ("http://127.0.0.1:9080", False, ("ws://relay.example/",), "wss://"),
        (None, True, (ONION,), "onion relays need the relay proxy"),
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
        handshake=SimpleNamespace(profile="btc-to-ln/v1"),
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


def test_ln_to_btc_firm_offers_refuse_to_start_without_hold_invoices() -> None:
    from types import SimpleNamespace  # noqa: PLC0415

    from rill_provider import cli  # noqa: PLC0415
    from rill_provider.operator_config import OperatorConfigError  # noqa: PLC0415

    config: Any = SimpleNamespace(
        network=_network("signet"),
        provider_destination_script="0014" + "11" * 20,
        handshake=SimpleNamespace(profile="ln-to-btc/v1"),
        lnd=SimpleNamespace(payment_macaroon="pay.macaroon", invoices_macaroon=None),
        bitcoin_core=object(),
    )
    with pytest.raises(OperatorConfigError, match="invoices_macaroon"):
        asyncio.run(cli._serve(config, None, ""))  # type: ignore[arg-type]  # noqa: SLF001
