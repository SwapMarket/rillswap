"""Operator configuration for the live provider service (JSON, strict).

Secrets never live in this file. The age custody identity is read from a
separate owner-only file (``custody_identity_file``) that must sit outside
the store volume's images, or the at-rest encryption adds nothing.
"""

from __future__ import annotations

import os
import stat
from pathlib import Path  # noqa: TC003 - pydantic resolves field types at runtime

from pydantic import BaseModel, ConfigDict, Field
from rill_core.wire.types import NetworkIdentity  # noqa: TC002 - pydantic runtime type

from rill_provider.handshake_service import ServicePolicy
from rill_provider.handshake_store import HandshakePolicy
from rill_provider.live_session_store import (
    DEFAULT_MAX_SESSIONS,
    DEFAULT_MAX_TOMBSTONES,
    DEFAULT_NEW_SESSIONS_PER_MINUTE,
    AuthorityDeclaration,
)
from rill_provider.quote_policy import QuoteSchedule

MAX_CONFIG_BYTES = 64 * 1024
MAX_IDENTITY_FILE_BYTES = 4096


class OperatorConfigError(ValueError):
    """Configuration or credential file refused; details are not echoed."""


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


class HandshakeSelection(_Strict):
    """What this provider negotiates; bound into the store at provisioning."""

    profile: str
    features: tuple[str, ...] = ()
    encryption_suites: tuple[str, ...]
    capabilities: tuple[str, ...]


class Attestation(_Strict):
    """Operator attestation of the store's deployment boundary."""

    volume_label: str
    outside_restore_domain: bool
    single_host: bool


class BitcoinCore(_Strict):
    """Loopback regtest Core RPC, used only for indicative quote heights."""

    port: int = Field(ge=1, le=65535)
    cookie_file: Path


class QuoteSettings(_Strict):
    """Quote parameters beyond the public announcement terms."""

    funding_confirmations: int = Field(default=2, ge=1)
    settlement_confirmations: int = Field(default=3, ge=1)
    refund_resolution_confirmations: int = Field(default=6, ge=1)
    max_refund_delay_blocks: int = Field(default=288, ge=1)
    max_funding_fee_sat: int = Field(default=5_000, ge=0)
    max_claim_fee_sat: int = Field(default=5_000, ge=0)
    max_refund_fee_sat: int = Field(default=5_000, ge=0)
    minimum_invoice_remaining_seconds: int = Field(default=1_800, ge=1)
    lifetime: int = Field(default=60, ge=1)


class PublicTerms(_Strict):
    """RS-005 announcement terms."""

    profiles: tuple[str, ...]
    amount_bands: tuple[tuple[int, int], ...]
    base_fee_sat: int
    proportional_millionths: int
    slot: str


class OperatorConfig(_Strict):
    """One provider deployment; paths are resolved relative to the config file."""

    network: NetworkIdentity
    provider_identity_xonly: str = Field(pattern=r"^[0-9a-f]{64}$")
    identity_file: Path
    store_path: Path
    custody_recipient: str
    custody_identity_file: Path
    native_crypto_library: Path
    bitcoin_core: BitcoinCore | None = None
    quote: QuoteSettings = QuoteSettings()
    authority: Attestation
    handshake: HandshakeSelection
    terms: PublicTerms
    relay_urls: tuple[str, ...] = Field(min_length=1)
    epoch_period: int = 24 * 60 * 60
    announcement_lifetime: int = 60 * 60
    announcement_refresh: int = 30 * 60
    outbox_retry: int = 60
    handshake_timeout: int = 10 * 60
    max_sends_per_tick: int = 16
    max_sessions: int = Field(default=DEFAULT_MAX_SESSIONS, ge=1)
    max_tombstones: int = Field(default=DEFAULT_MAX_TOMBSTONES, ge=1)
    new_sessions_per_minute: int = Field(default=DEFAULT_NEW_SESSIONS_PER_MINUTE, ge=1)

    def handshake_policy(self) -> HandshakePolicy:
        """Return the store-bound negotiation policy."""
        h = self.handshake
        return HandshakePolicy(
            profile=h.profile,  # type: ignore[arg-type]
            features=frozenset(h.features),
            encryption_suites=frozenset(h.encryption_suites),
            capabilities=frozenset(h.capabilities),
        )

    def authority_declaration(self) -> AuthorityDeclaration:
        """Return the attestation recorded at provisioning."""
        return AuthorityDeclaration(**self.authority.model_dump())

    def service_policy(self) -> ServicePolicy:
        """Return the service schedules and public terms."""
        t = self.terms
        return ServicePolicy(
            network=self.network,
            profiles=t.profiles,
            amount_bands=t.amount_bands,
            base_fee_sat=t.base_fee_sat,
            proportional_millionths=t.proportional_millionths,
            slot=t.slot,
            relay_urls=self.relay_urls,
            epoch_period=self.epoch_period,
            announcement_lifetime=self.announcement_lifetime,
            announcement_refresh=self.announcement_refresh,
            outbox_retry=self.outbox_retry,
            handshake_timeout=self.handshake_timeout,
            max_sends_per_tick=self.max_sends_per_tick,
            quote=QuoteSchedule(**self.quote.model_dump()),
        )


def _resolve(base: Path, path: Path) -> Path:
    return path if path.is_absolute() else base / path


def load_config(path: Path) -> OperatorConfig:
    """Parse a strict JSON config; relative paths are relative to its directory."""
    try:
        raw = path.read_bytes()
        if len(raw) > MAX_CONFIG_BYTES:
            raise OperatorConfigError("config too large")  # noqa: TRY301
        config = OperatorConfig.model_validate_json(raw, strict=False)
    except OperatorConfigError:
        raise
    except (OSError, ValueError) as error:
        raise OperatorConfigError(f"config refused: {type(error).__name__}") from None
    base = path.parent.absolute()
    update: dict[str, object] = {
        name: _resolve(base, getattr(config, name))
        for name in (
            "identity_file",
            "store_path",
            "custody_identity_file",
            "native_crypto_library",
        )
    }
    if config.bitcoin_core is not None:
        update["bitcoin_core"] = config.bitcoin_core.model_copy(
            update={"cookie_file": _resolve(base, config.bitcoin_core.cookie_file)}
        )
    return config.model_copy(update=update)


def read_custody_identity(path: Path) -> str:
    """Read an owner-only age identity file; refuse group/other access or links."""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    except OSError:
        raise OperatorConfigError("custody identity file unavailable") from None
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077:
            raise OperatorConfigError("custody identity file must be a 0600 regular file")
        if info.st_uid != os.geteuid():
            raise OperatorConfigError("custody identity file must be owned by this user")
        data = os.read(fd, MAX_IDENTITY_FILE_BYTES + 1)
    finally:
        os.close(fd)
    if len(data) > MAX_IDENTITY_FILE_BYTES:
        raise OperatorConfigError("custody identity file too large")
    lines = [
        line.strip()
        for line in data.decode("utf-8", "replace").splitlines()
        if line.strip() and not line.startswith("#")
    ]
    if len(lines) != 1 or not lines[0].startswith("AGE-SECRET-KEY-"):
        raise OperatorConfigError("custody identity file must hold exactly one age identity")
    return lines[0]
