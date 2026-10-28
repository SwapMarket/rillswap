"""Apprise delivery in a child process, through Tor or directly.

The provider never imports Apprise. ``AppriseWorker`` (the parent end) runs
``python -m rill_provider.notification_worker`` and speaks JSON lines with it:
one setup message (URL lines and the route), then one request per
notification. The child imports only the standard library and Apprise, writes
nothing but replies (its own stdout and stderr go to ``/dev/null``, so URLs in
Apprise's logs go nowhere), ignores SIGINT and exits when its stdin closes.

Tor mode fails closed. Every urllib3 connection (``requests``, which nearly
every Apprise plugin uses) becomes a CONNECT tunnel through the relay proxy,
on its own circuit (``tor_tunnel``), so Tor resolves the service name, onion
services work, and TLS is still verified against the service name. That patch
is only the route. The invariant is the audit hook installed before the first
send: in Tor mode the guard, not the patch, prevents leaks. It refuses every
connection except to the proxy, every name lookup except of the proxy literal,
datagrams, new processes and new native code, so plugins that bypass urllib3
(email, IRC, MQTT, syslog over UDP, Apprise's own WKD lookups) fail instead of
leaking. The hook is process-wide and cannot be removed, which is why this is
a separate process. Known limits: ``_posixsubprocess.fork_exec`` raises no
audit event (Apprise does not call it), and libc ``syslog()`` is local IPC
that no hook sees.

The parent kills the child whenever a request ends without its complete reply
(timeout, cancellation, exit, a malformed line), so a late reply can never be
read as the answer to the next request; the next send starts a new child.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import os
import re
import signal
import socket
import sys
import threading
import time
from typing import IO, TYPE_CHECKING, Any

from rill_provider.tor_tunnel import (
    MAX_TUNNEL_REPLY,
    connect_request,
    isolation_key,
    tunnel_established,
)

if TYPE_CHECKING:
    from collections.abc import Sequence

LOG = logging.getLogger(__name__)
MODULE = "rill_provider.notification_worker"
PROXY_VARIABLES = frozenset(
    name
    for base in ("http_proxy", "https_proxy", "all_proxy", "no_proxy")
    for name in (base, base.upper())
)
SETUP_SECONDS = 60.0  # importing Apprise and parsing every URL
SEND_SECONDS = {True: 90.0, False: 30.0}  # parent bound per notification, by Tor mode
EXIT_SECONDS = 2.0
# Child bounds, below the parent's: Apprise reports a timeout before the kill.
NOTIFY_SECONDS = {True: 80.0, False: 20.0}
TOR_SOCKET_SECONDS = 30.0  # connect and read, per service request
TUNNEL_REPLY_SECONDS = 60.0  # an onion rendezvous often takes tens of seconds
NO_APPRISE = "notifications need the apprise package: install rill-provider[notifications]"
_SETUP_ERROR = re.compile(r"notification URL refused \(line [0-9]{1,6}\)|" + re.escape(NO_APPRISE))


class WorkerError(RuntimeError):
    """The notification worker refused its setup or stopped answering."""


class AppriseWorker:
    """Deliver notifications through a supervised Apprise child process."""

    def __init__(self, urls: Sequence[tuple[int, str]], proxy: tuple[str, int] | None) -> None:
        """Prepare a worker for numbered URL lines; ``proxy`` selects Tor mode."""
        self._setup = {"urls": [list(item) for item in urls], "proxy": proxy}
        self._send_seconds = SEND_SECONDS[proxy is not None]
        self._process: asyncio.subprocess.Process | None = None
        self._lock = asyncio.Lock()
        self._reaping: set[asyncio.Task[int]] = set()

    async def start(self) -> None:
        """Start the child and have it check every URL; raise ``WorkerError`` if refused."""
        async with self._lock:
            await self._running()

    async def send(self, title: str, body: str, *, warning: bool) -> bool:
        """Deliver one notification; True when every service accepted it."""
        async with self._lock:
            process = await self._running()
            request = {"title": title, "body": body, "warning": warning}
            try:
                reply = await asyncio.wait_for(self._exchange(process, request), self._send_seconds)
                ok, refused, unreachable = reply["ok"], reply["refused"], reply["unreachable"]
                if type(ok) is not bool or type(refused) is not int or type(unreachable) is not int:
                    raise WorkerError("malformed notification worker reply")  # noqa: TRY301
            except BaseException:
                self._kill(process)  # its reply was not consumed: never reuse it
                raise
        if refused:
            LOG.warning(
                "notifications: %d connections outside Tor refused "
                "(services that are not HTTP need use_tor false)",
                refused,
            )
        if unreachable:
            LOG.warning(
                "notifications: %d services unreachable through Tor "
                "(LAN services need use_tor false)",
                unreachable,
            )
        return ok

    async def close(self) -> None:
        """Close the child's stdin, then kill it if it does not exit promptly."""
        process, self._process = self._process, None
        if process is not None and process.returncode is None:
            assert process.stdin is not None  # noqa: S101 - spawned with a pipe
            process.stdin.close()
            try:
                await asyncio.wait_for(process.wait(), EXIT_SECONDS)
            except TimeoutError:
                self._kill(process)
        if self._reaping:
            await asyncio.wait(self._reaping, timeout=EXIT_SECONDS)

    async def _running(self) -> asyncio.subprocess.Process:
        if self._process is not None and self._process.returncode is None:
            return self._process
        self._process = None
        # The provider's own interpreter and import path, without any proxy variable.
        env = {name: value for name, value in os.environ.items() if name not in PROXY_VARIABLES}
        process = await asyncio.create_subprocess_exec(
            sys.executable,
            "-m",
            MODULE,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
            env=env,
        )
        try:
            reply = await asyncio.wait_for(self._exchange(process, self._setup), SETUP_SECONDS)
            error = reply.get("error")
            if error is not None:
                # Only known messages, which never hold a URL, reach the operator.
                raise WorkerError(  # noqa: TRY301
                    error
                    if isinstance(error, str) and _SETUP_ERROR.fullmatch(error)
                    else "notification worker refused its setup"
                )
            if reply.get("ok") is not True:
                raise WorkerError("malformed notification worker reply")  # noqa: TRY301
        except BaseException:
            self._kill(process)
            raise
        self._process = process
        return process

    @staticmethod
    async def _exchange(process: asyncio.subprocess.Process, message: object) -> dict[str, Any]:
        assert process.stdin is not None  # noqa: S101 - spawned with pipes
        assert process.stdout is not None  # noqa: S101
        process.stdin.write(json.dumps(message).encode() + b"\n")
        await process.stdin.drain()
        line = await process.stdout.readline()
        if not line.endswith(b"\n"):
            raise WorkerError("notification worker exited")
        reply = json.loads(line)
        if type(reply) is not dict:
            raise WorkerError("malformed notification worker reply")
        return reply

    def _kill(self, process: asyncio.subprocess.Process) -> None:
        if self._process is process:
            self._process = None
        if process.returncode is None:
            with contextlib.suppress(ProcessLookupError):
                process.kill()
        task = asyncio.ensure_future(process.wait())  # reap it; close() waits for this
        self._reaping.add(task)
        task.add_done_callback(self._reaping.discard)


# Child process: standard library and Apprise only.


class GuardRefusalError(OSError):
    """An operation the Tor-mode guard refuses."""


_LOOKUPS = frozenset({"socket.getaddrinfo", "socket.gethostbyname", "socket.gethostbyaddr"})
_REFUSED = frozenset(
    {
        "socket.sendto",
        "subprocess.Popen",
        "os.system",
        "os.exec",
        "os.posix_spawn",
        "os.spawn",
        "os.fork",
        "os.forkpty",
        "ctypes.dlopen",
        "ctypes.dlsym",
    }
)
_GUARDED = _LOOKUPS | _REFUSED | {"socket.connect", "socket.getnameinfo", "socket.sendmsg"}


class _Tally:
    """A count shared with Apprise's delivery threads, reported once per reply."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._count = 0

    def add(self) -> None:
        """Count one more."""
        with self._lock:
            self._count += 1

    def take(self) -> int:
        """Return and reset the count."""
        with self._lock:
            count, self._count = self._count, 0
        return count


class _Guard(_Tally):
    """Audit hook: in Tor mode only the proxy may be reached or resolved."""

    def __init__(self, proxy: tuple[str, int]) -> None:
        super().__init__()  # counts refusals
        self._proxy = proxy
        self._literals = (proxy[0], proxy[0].encode())

    def __call__(self, event: str, args: tuple[Any, ...]) -> None:
        if event not in _GUARDED:
            return  # the hook sees every audit event: keep the common path cheap
        if event == "socket.connect":
            address = args[1]
            allowed = isinstance(address, tuple) and tuple(address[:2]) == self._proxy
        elif event in _LOOKUPS:
            allowed = args[0] in self._literals
        elif event == "socket.getnameinfo":
            allowed = isinstance(args[0], tuple) and args[0][:1] == self._proxy[:1]
        elif event == "socket.sendmsg":
            allowed = args[1] is None  # a connected socket, reached through connect
        else:
            allowed = False
        if not allowed:
            self.add()
            raise GuardRefusalError(f"{event} outside Tor refused")


def _tunnel_through(proxy: tuple[str, int], unreachable: _Tally) -> Any:  # noqa: ANN401
    """Return a ``urllib3.util.connection.create_connection`` that tunnels via Tor.

    A tunnel Tor refuses or never answers (a private address, a LAN name, an
    onion service that is down) counts as ``unreachable``.
    """

    def create_connection(
        address: tuple[str, int],
        timeout: object = None,
        source_address: object = None,
        socket_options: Sequence[tuple[int, int, int]] | None = None,
    ) -> socket.socket:
        del source_address  # Tor picks the route; binding locally would mean nothing
        host, port = address
        try:
            request = connect_request(host.strip("[]").rstrip("."), port, isolation_key())
        except ValueError:
            raise OSError("invalid notification service address") from None
        seconds = timeout if isinstance(timeout, int | float) else None
        sock = socket.create_connection(proxy, timeout=seconds)
        try:
            for option in socket_options or ():
                sock.setsockopt(*option)
            sock.sendall(request)
            reply = _tunnel_reply(sock)
            if not tunnel_established(reply):
                raise OSError("Tor refused the tunnel")  # noqa: TRY301
            sock.settimeout(seconds)
        except BaseException:
            sock.close()
            unreachable.add()
            raise
        return sock

    return create_connection


def _tunnel_reply(sock: socket.socket) -> bytes:
    """Read Tor's reply head one byte at a time, so no service byte is consumed."""
    deadline = time.monotonic() + TUNNEL_REPLY_SECONDS
    reply = b""
    while not reply.endswith(b"\r\n\r\n"):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("Tor tunnel timed out")
        sock.settimeout(remaining)
        byte = sock.recv(1)
        if not byte or len(reply) >= MAX_TUNNEL_REPLY:
            raise OSError("Tor closed the tunnel")
        reply += byte
    return reply


class _Delivery:
    """The child's Apprise instance, built from the setup message."""

    def __init__(self, setup: dict[str, Any]) -> None:
        proxy = setup["proxy"]
        self.proxy = None if proxy is None else (str(proxy[0]), int(proxy[1]))
        tor = self.proxy is not None
        self.unreachable = _Tally()
        try:
            import apprise  # noqa: PLC0415 - optional extra, only in this process
        except ImportError:
            raise WorkerError(NO_APPRISE) from None
        if self.proxy is not None:
            from urllib3.util import connection  # noqa: PLC0415 - Apprise's HTTP stack

            connection.create_connection = _tunnel_through(self.proxy, self.unreachable)
            # Tor needs longer than Apprise's 4 s defaults; per-URL cto and rto still win.
            apprise.URLBase.socket_connect_timeout = TOR_SOCKET_SECONDS
            apprise.URLBase.socket_read_timeout = TOR_SOCKET_SECONDS
        self._seconds = NOTIFY_SECONDS[tor]
        # Memory storage: Apprise writes nothing (the image's root is read-only).
        asset = apprise.AppriseAsset(storage_mode="memory", service_timeout=self._seconds)
        self._apprise = apprise.Apprise(asset=asset)
        self._types = (apprise.NotifyType.INFO, apprise.NotifyType.WARNING)
        self._format = apprise.NotifyFormat.TEXT
        for number, url in setup["urls"]:
            service = apprise.Apprise.instantiate(url, asset=asset)
            if service is None or not self._apprise.add(service):
                raise WorkerError(f"notification URL refused (line {int(number)})")

    def send(self, request: dict[str, Any]) -> bool:
        try:
            result = self._apprise.notify(
                request["body"],
                title=request["title"],
                notify_type=self._types[bool(request["warning"])],
                body_format=self._format,
                timeout=self._seconds,
            )
        except Exception:  # noqa: BLE001 - a failed delivery, never a crash
            return False
        return bool(result)


def _serve(requests: IO[bytes], replies: IO[str]) -> None:
    def reply(message: dict[str, Any]) -> None:
        replies.write(json.dumps(message) + "\n")
        replies.flush()

    line = requests.readline()
    if not line:
        return
    try:
        delivery = _Delivery(json.loads(line))
    except WorkerError as error:
        reply({"error": str(error)})
        return
    guard = _Tally()  # direct mode: nothing is refused
    if delivery.proxy is not None:
        guard = _Guard(delivery.proxy)  # after importing Apprise, before the first send
        sys.addaudithook(guard)
    reply({"ok": True})
    while line := requests.readline():
        ok = delivery.send(json.loads(line))
        reply({"ok": ok, "refused": guard.take(), "unreachable": delivery.unreachable.take()})


def main() -> None:
    """Serve the parent on stdin and the original stdout; exit at stdin EOF."""
    signal.signal(signal.SIGINT, signal.SIG_IGN)  # a terminal ^C is for the parent
    logging.disable(logging.CRITICAL)  # Apprise logs can echo URLs and tokens
    replies = os.fdopen(os.dup(1), "w", encoding="utf-8")
    devnull = os.open(os.devnull, os.O_WRONLY)
    os.dup2(devnull, 1)  # a stray print from a plugin cannot corrupt the replies
    os.dup2(devnull, 2)
    os.close(devnull)
    try:
        _serve(sys.stdin.buffer, replies)
    finally:
        replies.flush()
        os._exit(0)  # never wait for Apprise threads still stuck on a dead service


if __name__ == "__main__":
    main()
