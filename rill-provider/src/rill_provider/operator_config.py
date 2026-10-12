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
from rill_core.wire.hashes import COOPERATIVE_CLAIM_FEATURE
from rill_core.wire.types import (
    EvmAssetIdentity,
    NetworkIdentity,
    require_v1_destination_script,
)

from rill_provider.evm_quote_policy import EVM_PROFILES, EvmSchedule
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
    # Wallet that funds LN to BTC contracts (RS-004); default wallet when absent.
    wallet: str | None = Field(default=None, pattern=r"^[A-Za-z0-9_.-]{1,64}$")


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
    # LN to BTC (RS-004) only: provider funding window and hold invoice terms.
    reverse_refund_delay_blocks: int = Field(default=144, ge=1, le=MAX_WIRE_INTEGER)
    refund_and_ln_resolution_blocks: int = Field(default=40, ge=1, le=MAX_WIRE_INTEGER)
    claim_fee_reserve_sat: int = Field(default=1_000, ge=0, le=MAX_SATS)
    hold_invoice_lifetime: int = Field(default=3_600, ge=1, le=MAX_WIRE_INTEGER)


class Lnd(_Strict):
    """Loopback regtest LND gRPC; a read macaroon suffices for invoice decoding."""

    port: int = Field(ge=1, le=65535)
    tls_certificate: Path
    macaroon: Path
    # offchain:read+write; when set (with bitcoin_core) funded swaps are paid and claimed.
    payment_macaroon: Path | None = None
    # invoices:read+write; required to serve LN to BTC (hold invoices).
    invoices_macaroon: Path | None = None


class EvmToken(_Strict):
    """One ERC20 token served on the configured chain (RS-010)."""

    token_contract: str = Field(pattern=r"^0x[0-9a-f]{40}$")
    token_symbol: str = Field(min_length=1, max_length=16)
    token_decimals: int = Field(ge=0, le=36)
    # Fixed operator price until a rate source exists: token base units per BTC.
    rate_token_base_per_btc: int = Field(ge=1)


class EvmSettings(_Strict):
    """One EVM chain with one verified Boltz ERC20Swap v6 deployment (RS-010)."""

    rpc_url: str = Field(pattern=r"^https?://")
    chain_id: int = Field(ge=1)
    name: str = Field(min_length=1, max_length=32)
    htlc_contract: str = Field(pattern=r"^0x[0-9a-f]{40}$")
    block_seconds: int = Field(ge=1, le=3600)
    deployment_namespace: str | None = None
    signer_key_file: Path  # owner-only file holding one hex secp256k1 private key
    tokens: tuple[EvmToken, ...] = Field(min_length=1, max_length=16)
    funding_confirmations: int = Field(default=1, ge=1)
    settlement_confirmations: int = Field(default=1, ge=1)
    forward_timelock_delay_blocks: int = Field(ge=2)
    reverse_timelock_delay_blocks: int = Field(ge=3)
    learn_and_claim_seconds: int = Field(ge=1)
    refund_and_ln_resolution_seconds: int = Field(ge=1)

    def assets(self) -> tuple[EvmAssetIdentity, ...]:
        """Return the served asset identities exactly as terms will carry them."""
        return tuple(
            EvmAssetIdentity(
                family="evm",
                chain_id=self.chain_id,
                name=self.name,
                htlc_contract=self.htlc_contract,
                htlc_version=6,
                token_contract=token.token_contract,
                token_symbol=token.token_symbol,
                token_decimals=token.token_decimals,
                block_seconds=self.block_seconds,
                deployment_namespace=self.deployment_namespace,
            )
            for token in self.tokens
        )

    def rates(self) -> dict[str, int]:
        """Return the fixed rate per token contract."""
        return {token.token_contract: token.rate_token_base_per_btc for token in self.tokens}

    def schedule(self) -> EvmSchedule:
        """Return the EVM-side quote schedule."""
        return EvmSchedule(
            funding_confirmations=self.funding_confirmations,
            settlement_confirmations=self.settlement_confirmations,
            forward_timelock_delay_blocks=self.forward_timelock_delay_blocks,
            reverse_timelock_delay_blocks=self.reverse_timelock_delay_blocks,
            learn_and_claim_seconds=self.learn_and_claim_seconds,
            refund_and_ln_resolution_seconds=self.refund_and_ln_resolution_seconds,
        )


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
    evm: EvmSettings | None = None  # required for the RS-010 ERC20 profiles
    quote: QuoteSettings = QuoteSettings()
    authority: Attestation
    handshake: HandshakeSelection
    terms: PublicTerms
    relay_urls: tuple[str, ...] = Field(min_length=1)
    # Loopback Tor HTTPTunnelPort (http://127.0.0.1:9080). Required on public
    # networks unless allow_direct_relays explicitly accepts IP exposure.
    relay_proxy: str | None = None
    allow_direct_relays: bool = False
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
        # Cooperative MuSig2 claims are intrinsic to the Bitcoin profiles, never
        # an operator toggle; EVM HTLC profiles have no key-path claim.
        intrinsic = set() if h.profile in EVM_PROFILES else {COOPERATIVE_CLAIM_FEATURE}
        return HandshakePolicy(
            profile=h.profile,  # type: ignore[arg-type]
            features=frozenset(h.features) | intrinsic,
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
            relay_proxy=self.relay_proxy,
            epoch_period=self.epoch_period,
            announcement_lifetime=self.announcement_lifetime,
            announcement_refresh=self.announcement_refresh,
            outbox_retry=self.outbox_retry,
            handshake_timeout=self.handshake_timeout,
            max_sends_per_tick=self.max_sends_per_tick,
            quote=QuoteSchedule(**self.quote.model_dump()),
            profile=self.handshake.profile,  # type: ignore[arg-type]
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
                "invoices_macaroon": None
                if config.lnd.invoices_macaroon is None
                else _resolve(base, config.lnd.invoices_macaroon),
            }
        )
    if config.bitcoin_core is not None:
        update["bitcoin_core"] = config.bitcoin_core.model_copy(
            update={"cookie_file": _resolve(base, config.bitcoin_core.cookie_file)}
        )
    if config.evm is not None:
        update["evm"] = config.evm.model_copy(
            update={"signer_key_file": _resolve(base, config.evm.signer_key_file)}
        )
    return config.model_copy(update=update)


def read_evm_signer_key(path: Path) -> str:
    """Read an owner-only file holding one hex EVM private key; refuse loose permissions."""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    except OSError:
        raise OperatorConfigError("EVM signer key file unavailable") from None
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077:
            raise OperatorConfigError("EVM signer key file must be a 0600 regular file")
        if info.st_uid != os.geteuid():
            raise OperatorConfigError("EVM signer key file must be owned by this user")
        data = os.read(fd, MAX_IDENTITY_FILE_BYTES + 1)
    finally:
        os.close(fd)
    key = data.decode("utf-8", "replace").strip().lower().removeprefix("0x")
    if len(key) != 64 or any(c not in "0123456789abcdef" for c in key):  # noqa: PLR2004
        raise OperatorConfigError("EVM signer key file must hold one 32-byte hex key")
    return "0x" + key


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
