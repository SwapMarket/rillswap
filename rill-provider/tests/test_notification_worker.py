"""The Apprise worker process: Tor routing that fails closed, its guard, supervision."""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import os
import re
import signal
import socket
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import TYPE_CHECKING

import pytest
from test_relay_route import _tunnel_proxy

from rill_provider import notification_worker
from rill_provider.notification_worker import AppriseWorker
from rill_provider.notifications import notification_sender
from rill_provider.operator_config import NotificationSettings

if TYPE_CHECKING:
    from collections.abc import AsyncIterator, Iterator

ONION = "gnostr2jnapk72mnagq3cuykfon73temzp77hcbncn4silgt77boruid.onion"
REFUSED = b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n"
ESTABLISHED = b"HTTP/1.1 200 Connection established\r\n\r\n"
SRC = str(Path(__file__).parents[1] / "src")


class _Hook(BaseHTTPRequestHandler):
    """A JSON webhook; while ``server.hold`` is clear, requests wait (a hung service)."""

    def do_POST(self) -> None:
        self.server.hold.wait(10)  # type: ignore[attr-defined]
        length = int(self.headers["Content-Length"])
        self.server.received.append((self.path, json.loads(self.rfile.read(length))))  # type: ignore[attr-defined]
        self.send_response(200)
        self.end_headers()

    def log_message(self, *_args: object) -> None:
        pass


@pytest.fixture
def hook() -> Iterator[ThreadingHTTPServer]:
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Hook)
    server.daemon_threads = True
    server.received = []  # type: ignore[attr-defined]
    server.hold = threading.Event()  # type: ignore[attr-defined]
    server.hold.set()  # type: ignore[attr-defined]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.hold.set()  # type: ignore[attr-defined]
        server.shutdown()
        server.server_close()


@contextlib.asynccontextmanager
async def _proxy(target_port: int, reply: bytes) -> AsyncIterator[tuple[str, list[bytes]]]:
    """A Tor-like CONNECT proxy piping every tunnel to one local port, or refusing."""
    requests: list[bytes] = []
    server = await asyncio.start_server(_tunnel_proxy(requests, target_port, reply), "127.0.0.1", 0)
    try:
        yield f"http://127.0.0.1:{server.sockets[0].getsockname()[1]}", requests
    finally:
        server.close()


def _urls(tmp_path: Path, *urls: str) -> Path:
    path = tmp_path / "notify.urls"
    path.write_text("".join(f"{url}\n" for url in urls))
    path.chmod(0o600)
    return path


def _isolation(request: bytes) -> str:
    found = re.search(rb"\r\nX-Tor-Stream-Isolation: ([0-9a-f]{32})\r\n", request)
    assert found is not None, request
    return found.group(1).decode()


def test_tor_mode_reaches_names_and_onions_only_through_the_proxy(
    tmp_path: Path, hook: ThreadingHTTPServer, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.INFO)
    port = hook.server_port
    urls = _urls(tmp_path, f"json://notify.example.invalid:{port}/hook/SECRET", f"json://{ONION}/o")

    async def scenario() -> tuple[bool, list[bytes]]:
        async with (
            _proxy(port, ESTABLISHED) as (proxy, requests),
            notification_sender(NotificationSettings(urls_file=urls), proxy) as sender,
        ):
            assert sender is not None
            return await sender.send("title", "body", warning=False), requests

    ok, requests = asyncio.run(scenario())
    assert ok  # neither name resolves locally: only Tor could have reached them
    assert sorted(path for path, _body in hook.received) == ["/hook/SECRET", "/o"]  # type: ignore[attr-defined]
    targets = sorted(request.split(b" ")[1] for request in requests)
    assert targets == [f"{ONION}:80".encode(), f"notify.example.invalid:{port}".encode()]
    assert len({_isolation(request) for request in requests}) == 2  # one circuit per service
    assert "notifications go through Tor (relay_proxy)" in caplog.messages
    assert not any(
        "outside Tor" in message or "unreachable" in message or "SECRET" in message
        for message in caplog.messages
    )


def test_a_refused_tunnel_never_falls_back_to_a_direct_connection(
    tmp_path: Path, hook: ThreadingHTTPServer, caplog: pytest.LogCaptureFixture
) -> None:
    """A LAN service behind Tor (Tor answers 403 for private addresses) fails visibly."""
    urls = _urls(tmp_path, f"json://127.0.0.1:{hook.server_port}/hook/SECRET")

    async def scenario() -> tuple[bool, list[bytes]]:
        async with (
            _proxy(hook.server_port, REFUSED) as (proxy, requests),
            notification_sender(NotificationSettings(urls_file=urls), proxy) as sender,
        ):
            assert sender is not None
            return await sender.send("title", "body", warning=True), requests

    ok, requests = asyncio.run(scenario())
    assert not ok
    assert requests  # it asked Tor
    assert hook.received == []  # type: ignore[attr-defined] # and never went around it
    assert any(
        message.startswith("notifications: ")
        and message.endswith(" services unreachable through Tor (LAN services need use_tor false)")
        for message in caplog.messages
    )


def test_services_that_are_not_http_fail_under_tor_without_leaking(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    smtp = socket.create_server(("127.0.0.1", 0))
    syslog = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    syslog.bind(("127.0.0.1", 0))
    smtp_port, syslog_port = smtp.getsockname()[1], syslog.getsockname()[1]
    urls = _urls(
        tmp_path,
        "mailto://ops:SECRET@example.invalid?smtp=smtp.example.invalid&to=ops@example.invalid",
        f"mailto://ops:SECRET@example.invalid:{smtp_port}?smtp=127.0.0.1&to=ops@example.invalid",
        f"rsyslog://127.0.0.1:{syslog_port}",
    )

    async def scenario() -> tuple[bool, list[bytes]]:
        async with (
            _proxy(9, REFUSED) as (proxy, requests),
            notification_sender(NotificationSettings(urls_file=urls), proxy) as sender,
        ):
            assert sender is not None
            return await sender.send("title", "body", warning=True), requests

    try:
        ok, requests = asyncio.run(scenario())
        smtp.settimeout(0.2)
        with pytest.raises(TimeoutError):
            smtp.accept()  # the SMTP server by IP was never reached
        syslog.settimeout(0.2)
        with pytest.raises(TimeoutError):
            syslog.recv(4096)  # nor the syslog server
    finally:
        smtp.close()
        syslog.close()
    assert not ok
    assert requests == []  # none of them is HTTP: Tor was not even asked
    refusals = [message for message in caplog.messages if "outside Tor refused" in message]
    assert len(refusals) == 1
    assert int(refusals[0].split()[1]) >= 3


GUARD_PROBE = """
import ctypes, json, socket, subprocess, sys, urllib.request
from rill_provider.notification_worker import _Guard
import apprise
from apprise.utils.http import HTTPPolicy, HTTPPolicySession

proxy = socket.create_server(("127.0.0.1", 0))
other = socket.create_server(("127.0.0.1", 0))
guard = _Guard(proxy.getsockname()[:2])
sys.addaudithook(guard)
results = {}

def attempt(name, action):
    try:
        action()
    except Exception:
        pass
    results[name] = guard.take()

attempt("policy session", lambda: HTTPPolicySession(HTTPPolicy()).get(
    "https://openpgpkey.example.invalid/.well-known/openpgpkey/policy", timeout=5))
attempt("urllib", lambda: urllib.request.urlopen("http://example.invalid/", timeout=5))
attempt("reverse lookup", lambda: socket.gethostbyaddr("192.0.2.1"))
attempt("other port", lambda: socket.create_connection(other.getsockname()[:2]))
attempt("datagram", lambda: socket.socket(socket.AF_INET, socket.SOCK_DGRAM).sendto(
    b"x", ("127.0.0.1", 9)))
attempt("process", lambda: subprocess.run(["true"], check=True))
attempt("native code", lambda: ctypes.CDLL(None))
attempt("proxy", lambda: socket.create_connection(proxy.getsockname()[:2]).close())
print(json.dumps(results))
"""


def test_the_guard_refuses_everything_but_the_proxy_even_outside_urllib3() -> None:
    """Apprise's own WKD session and the stdlib bypass the urllib3 tunnel; the guard does not."""
    probe = subprocess.run(  # noqa: S603 - fixed argv
        [sys.executable, "-c", GUARD_PROBE],
        capture_output=True,
        check=True,
        text=True,
        timeout=60,
        env={**os.environ, "PYTHONPATH": os.pathsep.join([SRC, os.environ.get("PYTHONPATH", "")])},
    )
    results = json.loads(probe.stdout)
    assert results.pop("proxy") == 0
    assert all(results.values()), results


def test_use_tor_off_and_proxy_variables_never_reroute(
    tmp_path: Path,
    hook: ThreadingHTTPServer,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """A LAN service is reached directly, whatever the environment says."""
    caplog.set_level(logging.INFO)
    urls = _urls(tmp_path, f"json://127.0.0.1:{hook.server_port}/hook/SECRET")
    settings = NotificationSettings(urls_file=urls, use_tor=False)

    async def scenario() -> tuple[bool, list[bytes]]:
        async with _proxy(9, REFUSED) as (proxy, requests):
            for name in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "all_proxy"):
                monkeypatch.setenv(name, proxy)
            async with notification_sender(settings, proxy) as sender:
                assert sender is not None
                return await sender.send("title", "body", warning=False), requests

    ok, requests = asyncio.run(scenario())
    assert ok
    assert requests == []
    assert [path for path, _body in hook.received] == ["/hook/SECRET"]  # type: ignore[attr-defined]
    assert "notifications go directly, not through Tor: use_tor is off" in caplog.messages


def test_without_a_relay_proxy_notifications_go_directly(
    tmp_path: Path, hook: ThreadingHTTPServer, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.INFO)
    urls = _urls(tmp_path, f"json://127.0.0.1:{hook.server_port}/hook/SECRET")

    async def scenario() -> bool:
        async with notification_sender(NotificationSettings(urls_file=urls), None) as sender:
            assert sender is not None
            return await sender.send("title", "body", warning=False)

    assert asyncio.run(scenario())
    assert "notifications go directly, not through Tor: no relay_proxy" in caplog.messages


def _child(worker: AppriseWorker) -> asyncio.subprocess.Process:
    process = worker._process  # noqa: SLF001 - the supervised child
    assert process is not None
    assert process.returncode is None
    return process


def test_a_worker_that_hangs_dies_or_is_cancelled_is_replaced(
    hook: ThreadingHTTPServer, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(notification_worker, "SEND_SECONDS", {True: 1.0, False: 1.0})
    worker = AppriseWorker([(1, f"json://127.0.0.1:{hook.server_port}/hook")], None)
    hold: threading.Event = hook.hold  # type: ignore[attr-defined]

    async def send() -> bool:
        return await worker.send("title", "body", warning=False)

    async def scenario() -> None:
        await worker.start()
        first = _child(worker)
        hold.clear()  # the service hangs: the bound kills the child
        with pytest.raises(TimeoutError):
            await send()
        assert await asyncio.wait_for(first.wait(), 5) == -signal.SIGKILL
        hold.set()
        assert await send()  # from a new child
        second = _child(worker)
        assert second is not first
        second.kill()  # an external kill between notifications
        await asyncio.wait_for(second.wait(), 5)
        assert await send()
        third = _child(worker)
        assert third is not second
        third.send_signal(signal.SIGINT)  # a terminal ^C is for the provider, not the child
        await asyncio.sleep(0.2)
        assert await send()
        assert _child(worker) is third
        hold.clear()
        sending = asyncio.create_task(send())
        await asyncio.sleep(0.3)
        sending.cancel()  # e.g. the shutdown bound: never reuse a child mid-request
        with pytest.raises(asyncio.CancelledError):
            await sending
        assert await asyncio.wait_for(third.wait(), 5) == -signal.SIGKILL
        hold.set()
        assert await send()
        last = _child(worker)
        await worker.close()
        assert last.returncode == 0  # it left on stdin EOF, not by a kill

    asyncio.run(scenario())


def test_the_worker_holds_no_environment_proxy_and_no_url_on_its_command_line(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("HTTPS_PROXY", "http://127.0.0.1:9")
    worker = AppriseWorker([(1, "json://127.0.0.1:9/hook/SECRET")], None)

    async def scenario() -> tuple[bytes, bytes]:
        await worker.start()
        pid = _child(worker).pid
        try:
            proc = Path(f"/proc/{pid}")
            return (proc / "environ").read_bytes(), (proc / "cmdline").read_bytes()
        finally:
            await worker.close()

    environ, cmdline = asyncio.run(scenario())
    assert b"HTTPS_PROXY=" not in environ
    assert b"SECRET" not in cmdline
    assert cmdline.split(b"\0")[1:3] == [b"-m", b"rill_provider.notification_worker"]
