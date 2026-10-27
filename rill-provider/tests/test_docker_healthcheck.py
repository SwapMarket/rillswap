"""The Docker image's relay proxy health probe (docker/healthcheck.py).

The maker reaches Tor through a loopback forwarder that accepts connections
even when its target is wrong or down, so a healthy probe must see an HTTP
reply from the far end, not just a local listener.
"""

from __future__ import annotations

import importlib.util
import json
import socket
import threading
from contextlib import contextmanager
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

if TYPE_CHECKING:
    from collections.abc import Callable, Iterator
    from types import ModuleType


def _load_healthcheck() -> ModuleType:
    path = Path(__file__).parents[1] / "docker" / "healthcheck.py"
    spec = importlib.util.spec_from_file_location("rill_provider_docker_healthcheck", path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


healthcheck = _load_healthcheck()
TOR_REFUSAL = b"HTTP/1.0 403 Forbidden (private address)\r\nTor-Capabilities: \r\n\r\n"


@contextmanager
def _proxy(handle: Callable[[socket.socket], None]) -> Iterator[str]:
    """Serve one connection with ``handle``; yield the proxy URL."""
    with socket.create_server(("127.0.0.1", 0)) as server:
        port = server.getsockname()[1]

        def serve() -> None:
            connection, _ = server.accept()
            with connection:
                handle(connection)

        thread = threading.Thread(target=serve, daemon=True)
        thread.start()
        yield f"http://127.0.0.1:{port}"
        thread.join(timeout=5)


def _close(_connection: socket.socket) -> None:
    """Accept and close, like socat whose target refused the connection."""


def test_relay_proxy_accepts_the_tunnel_reply() -> None:
    received: list[bytes] = []

    def tunnel(connection: socket.socket) -> None:
        received.append(connection.recv(4096))
        connection.sendall(TOR_REFUSAL)

    with _proxy(tunnel) as url:
        healthcheck.check_relay_proxy(url)
    assert received == [healthcheck.RELAY_PROXY_PROBE]
    assert received[0].startswith(b"CONNECT 127.0.0.1:1 HTTP/1.1\r\n")


def test_relay_proxy_rejects_a_forwarder_whose_target_is_down() -> None:
    with _proxy(_close) as url, pytest.raises(healthcheck.UnhealthyError):
        healthcheck.check_relay_proxy(url)


def test_relay_proxy_rejects_a_non_http_reply() -> None:
    def other(connection: socket.socket) -> None:
        connection.recv(4096)
        connection.sendall(b"SSH-2.0-OpenSSH_9.9\r\n")

    with (
        _proxy(other) as url,
        pytest.raises(healthcheck.UnhealthyError, match="no HTTP reply"),
    ):
        healthcheck.check_relay_proxy(url)


def test_relay_proxy_rejects_a_silent_listener(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(healthcheck, "TIMEOUT_SECONDS", 0.2)
    release = threading.Event()

    def silent(connection: socket.socket) -> None:
        connection.recv(4096)
        release.wait(5)

    with _proxy(silent) as url:
        try:
            with pytest.raises(healthcheck.UnhealthyError, match="TimeoutError"):
                healthcheck.check_relay_proxy(url)
        finally:
            release.set()


def test_relay_proxy_rejects_a_closed_port() -> None:
    with socket.create_server(("127.0.0.1", 0)) as server:
        port = server.getsockname()[1]
    with pytest.raises(healthcheck.UnhealthyError, match="ConnectionRefusedError"):
        healthcheck.check_relay_proxy(f"http://127.0.0.1:{port}")


def test_provider_probe_checks_the_relay_proxy_end_to_end(tmp_path: Path) -> None:
    config = tmp_path / "provider.json"
    with _proxy(_close) as url:
        config.write_text(json.dumps({"relay_proxy": url}))
        with pytest.raises(healthcheck.UnhealthyError, match="relay proxy"):
            healthcheck.check_provider(config)
