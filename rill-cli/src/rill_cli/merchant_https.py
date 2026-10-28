"""Leaf-pinned loopback merchant reads, not receipt or spending authority.

This synchronous diagnostic reader enforces an ACCEPTANCE deadline, not a hard
execution limit. DNS, file work, headers or chunk framing can block past socket
timeouts. Late evidence is refused; do not run this on a shared server event
loop or claim production-grade availability. Acquisition headers cannot prove
the merchant generated fresh underlying state. No trust learning, provisioning,
redirect, reconnect, retry, source observation or credit import is performed.
"""

from __future__ import annotations

import hashlib
import http.client
import math
import os
import re
import ssl
import stat
import time
from contextlib import suppress
from dataclasses import dataclass
from typing import TYPE_CHECKING
from urllib.parse import urlsplit

from pydantic import TypeAdapter
from rill_core.wire.types import Hex32

from rill_cli.merchant_credit import AcquisitionInterval, MerchantSourcePin, MerchantViewObservation

if TYPE_CHECKING:
    from pathlib import Path

_MAX_CA_BYTES = 64 * 1024
_MAX_DOCUMENT_BYTES = 16 * 1024
_MAX_BATCH_SECONDS = 10
_READ_BYTES = 4096
_MIN_PORT = 1024
_MAX_PORT = 65535
_HTTP_OK = 200
_ID = re.compile(r"[A-Za-z0-9_-]{16,128}")
_TOKEN = re.compile(r"[A-Za-z0-9_-]{32,128}")
_HEX: TypeAdapter[str] = TypeAdapter(Hex32)


class MerchantHttpsError(ValueError):
    """Acquisition unavailable, with no token, body or upstream exception chain."""


@dataclass(frozen=True, slots=True)
class MerchantReadBatch:
    """Authenticated server statements only; unsigned view and unverified events."""

    view: MerchantViewObservation
    events_document: bytes
    events_acquisition: AcquisitionInterval


def _remaining(deadline: float) -> float:
    remaining = deadline - time.monotonic()
    if not math.isfinite(remaining) or remaining <= 0:
        raise MerchantHttpsError("merchant acquisition expired")
    return remaining


def _context(path: Path) -> ssl.SSLContext:
    # Operator must protect the path and its ancestors. These checks do not
    # establish isolation against same-UID code or hostile writable ancestors.
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_mode & 0o077
            or info.st_uid != os.getuid()
            or info.st_nlink != 1
        ):
            raise MerchantHttpsError("protected merchant trust configuration required")
        certificate = stream.read(_MAX_CA_BYTES + 1)
    if not 0 < len(certificate) <= _MAX_CA_BYTES:
        raise MerchantHttpsError("merchant trust configuration exceeds bound")
    return ssl.create_default_context(cadata=certificate.decode("ascii"))


def _headers(response: http.client.HTTPResponse) -> None:
    for name in ("Content-Type", "Content-Length", "Transfer-Encoding"):
        if len(response.headers.get_all(name, [])) > 1:
            raise MerchantHttpsError("merchant response framing ambiguous")
    transfer = response.getheader("Transfer-Encoding")
    # Initial profile requires explicit Content-Length. stdlib's chunk reader
    # accepts EOF after a zero chunk without the final trailer terminator;
    # supporting it would require a separate strict framing implementation.
    if transfer is not None:
        raise MerchantHttpsError("merchant response framing unsupported")
    content_type = response.getheader("Content-Type", "").lower().split(";", 1)[0].strip()
    if (
        response.status != _HTTP_OK
        or content_type != "application/json"
        or response.getheader("Age") is not None
        or response.getheader("Content-Encoding") is not None
    ):
        raise MerchantHttpsError("merchant response refused")
    directives = {}
    for item in response.getheader("Cache-Control", "").split(","):
        name, separator, value = item.strip().lower().partition("=")
        if name in directives or separator:
            raise MerchantHttpsError("merchant cache policy ambiguous")
        directives[name] = value
    if (
        "no-store" not in directives
        or any(directives.values())
        or not set(directives) <= {"no-store", "no-cache", "private", "must-revalidate"}
    ):
        raise MerchantHttpsError("merchant cache policy refused")
    length = response.getheader("Content-Length")
    if (
        length is None
        or not length.isascii()
        or not length.isdecimal()
        or not 0 < int(length) <= _MAX_DOCUMENT_BYTES
    ):
        raise MerchantHttpsError("merchant document exceeds bound")


class MerchantHttpsReader:
    """Explicit regtest loopback HTTPS profile, inert until a read is requested."""

    def __init__(self, pin: MerchantSourcePin, leaf_der_sha256: str, ca_path: Path) -> None:
        """Require independently retained leaf identity, never server-learned trust."""
        validated = None
        with suppress(ValueError):
            validated = MerchantSourcePin.model_validate(pin.model_dump(), strict=True)
        if validated is None:
            raise MerchantHttpsError("merchant source configuration invalid")
        parsed = urlsplit(validated.merchant_origin)
        digest = None
        with suppress(ValueError):
            digest = _HEX.validate_python(leaf_der_sha256, strict=True)
        if (
            parsed.hostname != "127.0.0.1"
            or parsed.port is None
            or not _MIN_PORT <= parsed.port <= _MAX_PORT
            or validated.network.name != "regtest"
            or digest is None
        ):
            raise MerchantHttpsError("explicit merchant loopback trust profile required")
        self._pin, self._leaf, self._ca = validated, digest, ca_path
        self._port = parsed.port

    def _get(
        self, context: ssl.SSLContext, path: str, token: str, deadline: float
    ) -> tuple[bytes, AcquisitionInterval]:
        started = int(time.time())
        connection = http.client.HTTPSConnection(
            "127.0.0.1", self._port, context=context, timeout=_remaining(deadline)
        )
        connection.auto_open = 0
        response = None
        try:
            connection.connect()
            _remaining(deadline)
            # Retain this verified socket: getresponse may detach connection.sock
            # for Connection: close while its body is still being consumed.
            verified = connection.sock
            if (
                not isinstance(verified, ssl.SSLSocket)
                or hashlib.sha256(verified.getpeercert(binary_form=True) or b"").hexdigest()
                != self._leaf
            ):
                raise MerchantHttpsError("merchant leaf identity differs")
            verified.settimeout(_remaining(deadline))
            connection.request(
                "GET",
                path,
                headers={
                    "Authorization": f"Bearer {token}",
                    "Origin": self._pin.merchant_origin,
                    "Accept": "application/json",
                    "Cache-Control": "no-store",
                    "Connection": "close",
                },
            )
            verified.settimeout(_remaining(deadline))
            response = connection.getresponse()
            _remaining(deadline)
            _headers(response)
            document = bytearray()
            while not response.isclosed():
                verified.settimeout(_remaining(deadline))
                chunk = response.read1(min(_READ_BYTES, _MAX_DOCUMENT_BYTES + 1 - len(document)))
                _remaining(deadline)
                if not chunk:
                    break
                document.extend(chunk)
                if len(document) > _MAX_DOCUMENT_BYTES:
                    raise MerchantHttpsError("merchant document exceeds bound")
            if not document or (response.length is not None and response.length != 0):
                raise MerchantHttpsError("merchant document incomplete")
        finally:
            try:
                if response is not None:
                    response.close()
            finally:
                connection.close()
        _remaining(deadline)
        return bytes(document), AcquisitionInterval(
            started_at=started, completed_at=int(time.time())
        )

    def read(
        self, intent_id: str, status_token: str, *, deadline_seconds: float = 10
    ) -> MerchantReadBatch:
        """Read exact view/events endpoints without promoting them to paid evidence."""
        if (
            type(intent_id) is not str
            or not _ID.fullmatch(intent_id)
            or type(status_token) is not str
            or not _TOKEN.fullmatch(status_token)
            or type(deadline_seconds) not in (float, int)
            or not 0 < deadline_seconds <= _MAX_BATCH_SECONDS
            or not math.isfinite(deadline_seconds)
        ):
            raise MerchantHttpsError("merchant acquisition input invalid")
        deadline, started = time.monotonic() + deadline_seconds, int(time.time())
        result = None
        try:
            context = _context(self._ca)
            _remaining(deadline)
            document, _view_interval = self._get(
                context, f"/v1/intents/{intent_id}", status_token, deadline
            )
            events, _events_interval = self._get(
                context, f"/v1/intents/{intent_id}/events", status_token, deadline
            )
            interval = AcquisitionInterval(started_at=started, completed_at=int(time.time()))
            result = MerchantReadBatch(
                MerchantViewObservation(
                    origin=self._pin.merchant_origin,
                    intent_id=intent_id,
                    acquisition=interval,
                    document=document,
                ),
                events,
                interval,
            )
        except Exception:  # noqa: BLE001, S110 - discard rather than log secret-bearing upstream errors
            pass
        if result is None:
            raise MerchantHttpsError("merchant HTTPS acquisition unavailable")
        _remaining(deadline)
        return result
