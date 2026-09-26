"""Operator configuration for the live provider service (JSON, strict).

Secrets never live in this file. The age custody identity is read from a
separate owner-only file (``custody_identity_file``) that must sit outside
the store volume's images, or the at-rest encryption adds nothing.
"""

from __future__ import annotations

import os
import stat
from pathlib import Path  # noqa: TC003 - pydantic resolves field types at runtime

from pydantic import BaseModel, ConfigDict, Field, field_validator
from rill_core.domain.amounts import MAX_SATS
from rill_core.wire.types import (
    NetworkIdentity,
    require_v1_destination_script,
)

from rill_provider.handshake_service import ServicePolicy
from rill_provider.handshake_store import HandshakePolicy
from rill_provider.live_session_store import (
    DEFAULT_MAX_ACTIVE_RESERVATIONS,
    DEFAULT_MAX_SESSIONS,
    DEFAULT_MAX_TOMBSTONES,
    DEFAULT_NEW_SESSIONS_PER_MINUTE,
    AuthorityDeclaration,
)
from rill_provider.quote_policy import MAX_WIRE_INTEGER, QuoteSchedule

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

    funding_confirmations: int = Field(default=2, ge=1, le=MAX_WIRE_INTEGER)
    settlement_confirmations: int = Field(default=3, ge=1, le=MAX_WIRE_INTEGER)
    refund_resolution_confirmations: int = Field(default=6, ge=1, le=MAX_WIRE_INTEGER)
    max_refund_delay_blocks: int = Field(default=288, ge=1, le=MAX_WIRE_INTEGER)
    max_funding_fee_sat: int = Field(default=5_000, ge=0, le=MAX_SATS)
    max_claim_fee_sat: int = Field(default=5_000, ge=0, le=MAX_SATS)
    max_refund_fee_sat: int = Field(default=5_000, ge=0, le=MAX_SATS)
    minimum_invoice_remaining_seconds: int = Field(default=1_800, ge=1, le=MAX_WIRE_INTEGER)
    lifetime: int = Field(default=60, ge=1, le=MAX_WIRE_INTEGER)
    outgoing_cltv_budget_blocks: int = Field(default=144, ge=1, le=MAX_WIRE_INTEGER)
    learn_and_claim_blocks: int = Field(default=72, ge=1, le=MAX_WIRE_INTEGER)
    client_response_blocks: int = Field(default=36, ge=1, le=MAX_WIRE_INTEGER)
    claim_confirmation_blocks: int = Field(default=6, ge=1, le=MAX_WIRE_INTEGER)
    terms_lifetime: int = Field(default=120, ge=1, le=MAX_WIRE_INTEGER)


class Lnd(_Strict):
    """Loopback regtest LND gRPC; a read macaroon suffices for invoice decoding."""

    port: int = Field(ge=1, le=65535)
    tls_certificate: Path
    macaroon: Path
    # offchain:read+write; when set (with bitcoin_core) funded swaps are paid and claimed.
    payment_macaroon: Path | None = None


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
    lnd: Lnd | None = None
    provider_destination_script: str | None = None  # P2WPKH/P2TR; enables firm offers
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
    # Unreleased firm offers plus accepted swaps; bounds concurrent financial exposure.
    max_active_reservations: int = Field(default=DEFAULT_MAX_ACTIVE_RESERVATIONS, ge=1)

    @field_validator("provider_destination_script")
    @classmethod
    def _destination(cls, value: str | None) -> str | None:
        if value is not None:
            require_v1_destination_script(value, field="provider_destination_script")
        return value

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
            provider_destination_script=self.provider_destination_script,
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
    if config.lnd is not None:
        update["lnd"] = config.lnd.model_copy(
            update={
                "tls_certificate": _resolve(base, config.lnd.tls_certificate),
                "macaroon": _resolve(base, config.lnd.macaroon),
                "payment_macaroon": None
                if config.lnd.payment_macaroon is None
                else _resolve(base, config.lnd.payment_macaroon),
            }
        )
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
