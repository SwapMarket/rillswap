"""Operator configuration for the live provider service (JSON, strict).

Secrets never live in this file. The age custody identity is read from a
separate owner-only file (``custody_identity_file``) that must sit outside
the store volume's images, or the at-rest encryption adds nothing.
"""

from __future__ import annotations

import os
import stat
from pathlib import Path  # noqa: TC003 - pydantic resolves field types at runtime

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator
from rill_core.domain.amounts import MAX_SATS
from rill_core.wire.fee_policy import FEE_MODEL, BtcFeePolicy
from rill_core.wire.hashes import (
    COOPERATIVE_CLAIM_FEATURE,
    EPOCH_SESSION_FEATURE,
    FEE_POLICY_FEATURE,
)
from rill_core.wire.types import (
    EvmAddress,
    EvmAssetIdentity,
    NetworkIdentity,
    require_v1_destination_script,
)

from rill_provider._transport_pow import MAX_WORK_BITS
from rill_provider.balance_pricing import (
    DEFAULT_MIN_SERVICE_FEE_PPM,
    MIN_SERVICE_FEE_PPM_LIMIT,
    BalancePricingError,
    check_min_service_fee_ppm,
)
from rill_provider.core_tx_bytes import MAX_FEE_ESTIMATE_CEILING_SAT_VB
from rill_provider.dynamic_pricing import FeeLimits
from rill_provider.evm_quote_policy import EVM_PROFILES, EvmSchedule
from rill_provider.handshake_service import ServicePolicy
from rill_provider.handshake_store import HandshakePolicy
from rill_provider.liquidity_cap import check_margin_percent
from rill_provider.live_session_store import (
    DEFAULT_MAX_ACTIVE_RESERVATIONS,
    DEFAULT_MAX_SESSIONS,
    DEFAULT_MAX_TOMBSTONES,
    DEFAULT_NEW_SESSIONS_PER_MINUTE,
    AuthorityDeclaration,
)
from rill_provider.quote_policy import MAX_WIRE_INTEGER, QuoteSchedule
from rill_provider.relay_client import reachable_relays

MAX_CONFIG_BYTES = 64 * 1024
MAX_IDENTITY_FILE_BYTES = 4096


class OperatorConfigError(ValueError):
    """Configuration or credential file refused; details are not echoed."""


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


class HandshakeSelection(_Strict):
    """What this provider negotiates; bound into the store at provisioning."""

    profile: str
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
    # Ceiling on Core's fee estimates (sat/vB) for chains with a skewed
    # estimator, such as signet. Unset trusts Core's estimates.
    max_fee_estimate_sat_vb: int | None = Field(
        default=None, ge=1, le=MAX_FEE_ESTIMATE_CEILING_SAT_VB
    )


class QuoteSettings(_Strict):
    """Quote parameters beyond the public announcement terms."""

    # Blocks on the client's funding before paying (btc-to-ln; 0 pays from the
    # mempool, see README) or on the provider's lockup before the client may
    # claim (ln-to-btc, at least 1). Announced and signed into every quote.
    funding_confirmations: int = Field(default=1, ge=0, le=MAX_WIRE_INTEGER)
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
    # Unset: priced per quote from next-block fees so the claim pays exactly it.
    claim_fee_reserve_sat: int | None = Field(default=None, ge=0, le=MAX_SATS)
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
    # Forward token recipient, typically the reverse maker's funding address.
    # The transaction signer remains independent and pays only gas.
    claim_address: EvmAddress | None = None
    tokens: tuple[EvmToken, ...] = Field(min_length=1, max_length=16)
    funding_confirmations: int = Field(default=1, ge=1)
    settlement_confirmations: int = Field(default=1, ge=1)
    forward_timelock_delay_blocks: int = Field(ge=2)
    reverse_timelock_delay_blocks: int = Field(ge=3)
    learn_and_claim_seconds: int = Field(ge=1)
    refund_and_ln_resolution_seconds: int = Field(ge=1)

    @field_validator("claim_address")
    @classmethod
    def _claim_address(cls, value: str | None) -> str | None:
        if value == "0x" + "0" * 40:
            raise ValueError("evm.claim_address must not be the zero address")
        return value

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


class BitcoinNetworkFees(_Strict):
    """Explicit opt-in to offer-bound, per-request Bitcoin mining estimates."""

    max_feerate_sat_kvb: int = Field(gt=0, le=MAX_FEE_ESTIMATE_CEILING_SAT_VB * 1000)
    max_routing_fee_ppm: int = Field(ge=0, le=1_000_000)


class DynamicFees(_Strict):
    """Private balance-aware discounts below the advertised service fee, never above it.

    Swaps that repair a liquidity shortage are discounted, down to
    ``min_service_fee_ppm`` of the principal (a rebate below zero); every
    other swap pays the normal fee. Nothing here is announced.
    """

    # Soft minimum of the bitcoin_core wallet (Bitcoin profiles).
    btc_reserve_target_sat: int | None = Field(default=None, gt=0, le=MAX_SATS)
    # Soft minimum of each configured token pool, valued at 1 USD per token
    # (EVM profiles, which must serve only USD stablecoins).
    stable_reserve_target_usd: int | None = Field(default=None, gt=0, le=10**12)
    min_service_fee_ppm: int = Field(
        default=DEFAULT_MIN_SERVICE_FEE_PPM, ge=MIN_SERVICE_FEE_PPM_LIMIT, le=0
    )
    # Rebates this process may grant per 24 hours, open offers included.
    rebate_budget_sat_24h: int = Field(default=100_000, ge=0, le=MAX_SATS)


class PublicTerms(_Strict):
    """RS-005 announcement terms."""

    profiles: tuple[str, ...]
    amount_bands: tuple[tuple[int, int], ...]
    base_fee_sat: int
    proportional_millionths: int
    slot: str
    network_fees: BitcoinNetworkFees | None = None
    # Announce and admit at most the payout liquidity less a random margin in
    # this percent range (never above amount_bands), where the profile has a
    # liquidity source: LND channels to pay out, or the Core funding wallet.
    follow_liquidity: bool = True
    liquidity_margin_percent: tuple[int, int] = (10, 20)

    @field_validator("liquidity_margin_percent")
    @classmethod
    def _margin(cls, value: tuple[int, int]) -> tuple[int, int]:
        return check_margin_percent(value)


class NotificationSettings(_Strict):
    """Optional operator notifications through Apprise (``rill-provider[notifications]``).

    ``urls_file`` is an owner-only file with one Apprise URL per line (``#``
    starts a comment): URLs carry service tokens, so they never live here.
    Grace periods and the daily summary use ``alert_after_seconds`` and UTC.
    With ``use_tor`` (the default) and ``relay_proxy`` set, every service is
    reached through Tor and only HTTP services work; turn it off for services
    on the LAN, which then see this host's address.
    """

    urls_file: Path
    use_tor: bool = True
    swap_request: bool = False  # the client accepted signed terms
    swap_confirmed: bool = False  # completed: claimed or settled
    swap_failed: bool = False  # failed, refunded or aborted
    swap_lost: bool = True  # paid out without getting the funds back
    daily_summary: bool = True
    summary_balances: bool = True  # current balances and Bitcoin wallet UTXO count
    summary_time: str = Field(default="00:00", pattern=r"^([01][0-9]|2[0-3]):[0-5][0-9]$")
    low_liquidity: bool = True  # liquidity below every amount band, not announcing
    relays_down: bool = True  # no relay connected
    quotes_paused: bool = True  # chain tip or claim fee estimate unavailable
    service_start_stop: bool = False
    alert_after_seconds: int = Field(default=300, ge=60, le=24 * 60 * 60)


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
    # RS-006 transport proof of work (NIP-13 leading zero bits) on every message
    # of new sessions; 0 is off. Clients that do not support it cannot see an
    # announcement requiring it, so enable it only once they do.
    transport_pow_bits: int = Field(default=0, ge=0, le=MAX_WORK_BITS)
    notifications: NotificationSettings | None = None
    dynamic_fees: DynamicFees | None = None

    @field_validator("provider_destination_script")
    @classmethod
    def _destination(cls, value: str | None) -> str | None:
        if value is not None:
            require_v1_destination_script(value, field="provider_destination_script")
        return value

    @model_validator(mode="after")
    def _zero_conf_only_pays_lightning(self) -> OperatorConfig:
        # In ln-to-btc the client reveals the preimage on this depth, so zero
        # would let this provider double-spend its own unconfirmed lockup.
        if self.quote.funding_confirmations == 0 and self.handshake.profile != "btc-to-ln/v1":
            raise ValueError("quote.funding_confirmations 0 is only allowed for btc-to-ln/v1")
        if self.terms.network_fees is not None and (
            self.handshake.profile in EVM_PROFILES or self.bitcoin_core is None
        ):
            raise ValueError("terms.network_fees requires a Bitcoin profile and bitcoin_core")
        if (
            self.evm is not None
            and self.evm.claim_address is not None
            and self.handshake.profile != "erc20-to-ln/v1"
        ):
            raise ValueError("evm.claim_address is only allowed for erc20-to-ln/v1")
        self._check_dynamic_fees()
        return self

    def _check_dynamic_fees(self) -> None:
        fees = self.dynamic_fees
        if fees is None:
            return
        if self.terms.base_fee_sat <= 0:
            raise ValueError("dynamic_fees requires a positive terms.base_fee_sat")
        try:
            check_min_service_fee_ppm(
                fees.min_service_fee_ppm, normal_fee_ppms=(self.terms.proportional_millionths,)
            )
        except BalancePricingError as error:
            raise ValueError(f"dynamic_fees: {error}") from None
        if self.lnd is None:
            raise ValueError("dynamic_fees requires lnd to observe channel balances")
        if self.handshake.profile in EVM_PROFILES:
            if self.evm is None or fees.stable_reserve_target_usd is None:
                raise ValueError(
                    "dynamic_fees on an EVM profile requires stable_reserve_target_usd"
                )
        elif self.terms.network_fees is None or fees.btc_reserve_target_sat is None:
            # The breakdown is where clients verify the advertised ceiling.
            raise ValueError(
                "dynamic_fees on a Bitcoin profile requires terms.network_fees "
                "and btc_reserve_target_sat"
            )

    def bitcoin_fee_policy(self) -> BtcFeePolicy | None:
        """Build the announcement policy without binding coefficients to the store."""
        terms = self.terms
        fees = terms.network_fees
        if fees is None:
            return None
        return BtcFeePolicy(
            model=FEE_MODEL,
            base_sat=str(terms.base_fee_sat),
            proportional_millionths=terms.proportional_millionths,
            max_network_feerate_sat_kvb=str(fees.max_feerate_sat_kvb),
            max_routing_fee_ppm=fees.max_routing_fee_ppm,
        )

    def handshake_policy(self) -> HandshakePolicy:
        """Return the store-bound negotiation policy."""
        h = self.handshake
        # Base features are intrinsic. Opting into network pricing additionally
        # requires its enforcement feature and a separately provisioned store.
        cooperative = set() if h.profile in EVM_PROFILES else {COOPERATIVE_CLAIM_FEATURE}
        pricing = (
            {FEE_POLICY_FEATURE}
            if getattr(getattr(self, "terms", None), "network_fees", None) is not None
            else set()
        )
        return HandshakePolicy(
            profile=h.profile,  # type: ignore[arg-type]
            features=frozenset({EPOCH_SESSION_FEATURE, *cooperative, *pricing}),
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
            relay_urls=reachable_relays(self.relay_urls, self.relay_proxy),
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
            evm_assets=self.evm.assets() if self.evm is not None else (),
            evm_funding_confirmations=self.evm.funding_confirmations if self.evm else 1,
            transport_pow_bits=self.transport_pow_bits,
            follow_liquidity=t.follow_liquidity,
            liquidity_margin_percent=t.liquidity_margin_percent,
            fee_policy=self.bitcoin_fee_policy(),
            dynamic_fees=self.fee_limits(),
        )

    def fee_limits(self) -> FeeLimits | None:
        """Return the private balance-aware discount limits, if configured."""
        fees = self.dynamic_fees
        if fees is None:
            return None
        return FeeLimits(
            min_service_fee_ppm=fees.min_service_fee_ppm,
            rebate_budget_sat=fees.rebate_budget_sat_24h,
            btc_reserve_target_sat=fees.btc_reserve_target_sat,
            stable_reserve_target_usd=fees.stable_reserve_target_usd,
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
    if config.notifications is not None:
        update["notifications"] = config.notifications.model_copy(
            update={"urls_file": _resolve(base, config.notifications.urls_file)}
        )
    return config.model_copy(update=update)


def read_private_file(path: Path, label: str, *, max_bytes: int = MAX_IDENTITY_FILE_BYTES) -> bytes:
    """Read up to ``max_bytes + 1`` bytes of an owner-only regular file, never a link.

    Errors name ``label`` only, never the path or the content.
    """
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    except OSError:
        raise OperatorConfigError(f"{label} unavailable") from None
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077:
            raise OperatorConfigError(f"{label} must be a 0600 regular file")
        if info.st_uid != os.geteuid():
            raise OperatorConfigError(f"{label} must be owned by this user")
        return os.read(fd, max_bytes + 1)
    finally:
        os.close(fd)


def read_evm_signer_key(path: Path) -> str:
    """Read an owner-only file holding one hex EVM private key; refuse loose permissions."""
    data = read_private_file(path, "EVM signer key file")
    key = data.decode("utf-8", "replace").strip().lower().removeprefix("0x")
    if len(key) != 64 or any(c not in "0123456789abcdef" for c in key):  # noqa: PLR2004
        raise OperatorConfigError("EVM signer key file must hold one 32-byte hex key")
    return "0x" + key


def read_custody_identity(path: Path) -> str:
    """Read an owner-only age identity file; refuse group/other access or links."""
    data = read_private_file(path, "custody identity file")
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
