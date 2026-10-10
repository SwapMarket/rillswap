"""Version-one closed wire objects and contextual economic validation."""

from __future__ import annotations

from typing import TYPE_CHECKING, Literal

from pydantic import Field, model_validator

from rill_core.domain.amounts import MAX_SATS
from rill_core.wire.canonical import JsonValue  # noqa: TC001
from rill_core.wire.hashes import (
    COOPERATIVE_CLAIM_FEATURE,
    EPOCH_SESSION_EXTENSION,
    EPOCH_SESSION_FEATURE,
    contract_hash,
    epoch_bound_session_id,
    handshake_init_hash,
)
from rill_core.wire.types import (
    CompressedKey,
    ExactInteger,
    Hex32,
    Identifier,
    NetworkIdentity,
    Party,
    PositiveCount,
    ProfileId,
    ScriptHex,
    Signature64,
    StrictModel,
    XOnlyKey,
    require_feature_list,
    require_identifier_list,
    require_p2tr_script,
    require_v1_destination_script,
    validate_decimal_msats,
    validate_decimal_sats,
    validate_extensions,
)

MAX_PAYLOAD_MEMBERS = 128
MAX_TRANSPORT_ENDPOINTS = 16
MAX_TRANSPORT_ENDPOINT_LENGTH = 2_048
CONTRACT_PURPOSE_KEY_COUNT = 4
HANDSHAKE_ROLE_KEY_COUNT = 3

if TYPE_CHECKING:
    from collections.abc import Set as AbstractSet


class InvoiceBinding(StrictModel):
    """Decoded values and exact lowercase BOLT11 representation digest."""

    bolt11_sha256: Hex32
    payment_hash: Hex32
    amount_msat: str
    payee_compressed_pubkey: CompressedKey
    created_at: ExactInteger
    expires_at: ExactInteger
    min_final_cltv_delta: PositiveCount

    @model_validator(mode="after")
    def validate_invoice(self) -> InvoiceBinding:
        """Require positive whole-satoshi amount and increasing expiry."""
        amount = validate_decimal_msats(self.amount_msat, field="amount_msat", positive=True)
        if amount % 1_000 != 0:
            raise ValueError("version-one invoice amount must be whole satoshis")
        if self.expires_at <= self.created_at:
            raise ValueError("invoice expiry must be after creation")
        return self


class BtcToLnEconomics(StrictModel):
    """BTC to LN amount commitments."""

    kind: Literal["btc-to-ln"]
    lightning_principal_sat: str
    success_fee_sat: str
    contract_amount_sat: str

    @model_validator(mode="after")
    def validate_equation(self) -> BtcToLnEconomics:
        """Require V equals L plus S without overflow."""
        principal = validate_decimal_sats(
            self.lightning_principal_sat,
            field="lightning_principal_sat",
            positive=True,
        )
        fee = validate_decimal_sats(self.success_fee_sat, field="success_fee_sat")
        contract = validate_decimal_sats(
            self.contract_amount_sat,
            field="contract_amount_sat",
            positive=True,
        )
        if principal + fee != contract:
            raise ValueError("BTC to LN economics must satisfy V = L + S")
        return self


class LnToBtcEconomics(StrictModel):
    """LN to BTC amount commitments."""

    kind: Literal["ln-to-btc"]
    contract_amount_sat: str
    nominal_payout_sat: str
    claim_fee_reserve_sat: str
    success_fee_sat: str
    mining_prepayment_sat: str
    hold_invoice_sat: str

    @model_validator(mode="after")
    def validate_equations(self) -> LnToBtcEconomics:
        """Require V equals D plus C and H equals V plus S minus M."""
        contract = validate_decimal_sats(
            self.contract_amount_sat,
            field="contract_amount_sat",
            positive=True,
        )
        payout = validate_decimal_sats(
            self.nominal_payout_sat,
            field="nominal_payout_sat",
            positive=True,
        )
        claim_reserve = validate_decimal_sats(
            self.claim_fee_reserve_sat,
            field="claim_fee_reserve_sat",
        )
        success_fee = validate_decimal_sats(self.success_fee_sat, field="success_fee_sat")
        prepayment = validate_decimal_sats(
            self.mining_prepayment_sat,
            field="mining_prepayment_sat",
        )
        hold_invoice = validate_decimal_sats(
            self.hold_invoice_sat,
            field="hold_invoice_sat",
            positive=True,
        )
        if payout + claim_reserve != contract:
            raise ValueError("LN to BTC economics must satisfy V = D + C")
        if prepayment > success_fee:
            raise ValueError("mining prepayment cannot exceed success fee")
        if contract + success_fee > MAX_SATS:
            raise ValueError("total LN to BTC payment exceeds the monetary maximum")
        if contract + success_fee - prepayment != hold_invoice:
            raise ValueError("LN to BTC economics must satisfy H = V + S - M")
        return self


class BtcToLnTiming(StrictModel):
    """Negotiated BTC to LN block margins."""

    kind: Literal["btc-to-ln"]
    max_outgoing_htlc_expiry_height: ExactInteger
    learn_and_claim_blocks: PositiveCount
    client_response_blocks: PositiveCount
    claim_confirmation_blocks: PositiveCount


class LnToBtcTiming(StrictModel):
    """Negotiated LN to BTC block margins."""

    kind: Literal["ln-to-btc"]
    min_incoming_htlc_expiry_height: ExactInteger
    refund_and_ln_resolution_blocks: PositiveCount
    client_response_blocks: PositiveCount
    claim_confirmation_blocks: PositiveCount


class ContractTerms(StrictModel):
    """Complete immutable economic and settlement commitment."""

    protocol: Literal["rillswap"]
    contract_version: Literal["1"]
    profile_id: ProfileId
    network_identity: NetworkIdentity
    provider_identity_key: XOnlyKey
    client_contract_compressed_key: CompressedKey
    provider_contract_compressed_key: CompressedKey
    claimant: Party
    refund_party: Party
    invoice_binding: InvoiceBinding
    economics: BtcToLnEconomics | LnToBtcEconomics = Field(discriminator="kind")
    refund_lock_height: int = Field(strict=True, gt=0, lt=500_000_000)
    funding_confirmations: PositiveCount
    settlement_confirmations: PositiveCount
    refund_resolution_confirmations: PositiveCount
    max_funding_fee_sat: str
    max_claim_fee_sat: str
    max_refund_fee_sat: str
    client_destination_script: ScriptHex
    provider_destination_script: ScriptHex
    recovery_authorization_xonly_key: XOnlyKey
    terms_expiry: ExactInteger
    timing_policy: BtcToLnTiming | LnToBtcTiming = Field(discriminator="kind")
    required_features: tuple[Identifier, ...]
    extensions: dict[str, JsonValue]

    @model_validator(mode="after")
    def validate_contract(self) -> ContractTerms:
        """Enforce profile roles, amounts, key separation, scripts, and timing."""
        require_feature_list(self.required_features, field="required_features")
        validate_extensions(self.extensions)
        for field, value in (
            ("max_funding_fee_sat", self.max_funding_fee_sat),
            ("max_claim_fee_sat", self.max_claim_fee_sat),
            ("max_refund_fee_sat", self.max_refund_fee_sat),
        ):
            validate_decimal_sats(value, field=field)
        require_v1_destination_script(
            self.client_destination_script,
            field="client_destination_script",
        )
        require_v1_destination_script(
            self.provider_destination_script,
            field="provider_destination_script",
        )
        self._validate_key_separation()
        first_refund_block = self.refund_lock_height + 1
        invoice_msat = validate_decimal_msats(
            self.invoice_binding.amount_msat,
            field="amount_msat",
            positive=True,
        )
        if self.profile_id == "btc-to-ln/v1":
            self._validate_btc_to_ln(invoice_msat, first_refund_block)
        else:
            self._validate_ln_to_btc(invoice_msat, first_refund_block)
        return self

    def _validate_key_separation(self) -> None:
        purpose_keys = {
            self.provider_identity_key,
            self.client_contract_compressed_key[2:],
            self.provider_contract_compressed_key[2:],
            self.recovery_authorization_xonly_key,
        }
        if len(purpose_keys) != CONTRACT_PURPOSE_KEY_COUNT:
            raise ValueError("keys assigned to distinct purposes must be distinct")

    def _validate_btc_to_ln(self, invoice_msat: int, first_refund_block: int) -> None:
        if not isinstance(self.economics, BtcToLnEconomics) or not isinstance(
            self.timing_policy,
            BtcToLnTiming,
        ):
            raise ValueError(  # noqa: TRY004
                "BTC to LN terms contain the wrong discriminated objects",
            )
        if (self.claimant, self.refund_party) != ("provider", "client"):
            raise ValueError("BTC to LN roles are reversed")
        principal = validate_decimal_sats(
            self.economics.lightning_principal_sat,
            field="lightning_principal_sat",
            positive=True,
        )
        if invoice_msat != principal * 1_000:
            raise ValueError("invoice does not equal BTC to LN principal")
        if (
            self.timing_policy.max_outgoing_htlc_expiry_height
            + self.timing_policy.learn_and_claim_blocks
            >= first_refund_block
        ):
            raise ValueError("outgoing HTLC exposure does not fit before refund")

    def _validate_ln_to_btc(self, invoice_msat: int, first_refund_block: int) -> None:
        if not isinstance(self.economics, LnToBtcEconomics) or not isinstance(
            self.timing_policy,
            LnToBtcTiming,
        ):
            raise ValueError(  # noqa: TRY004
                "LN to BTC terms contain the wrong discriminated objects",
            )
        if (self.claimant, self.refund_party) != ("client", "provider"):
            raise ValueError("LN to BTC roles are reversed")
        hold = validate_decimal_sats(
            self.economics.hold_invoice_sat,
            field="hold_invoice_sat",
            positive=True,
        )
        if invoice_msat != hold * 1_000:
            raise ValueError("invoice does not equal LN to BTC held amount")
        if (
            first_refund_block + self.timing_policy.refund_and_ln_resolution_blocks
            >= self.timing_policy.min_incoming_htlc_expiry_height
        ):
            raise ValueError("incoming HTLC exposure does not cover refund resolution")
        if self.economics.mining_prepayment_sat != "0" and (
            "org.rillswap/mining-prepayment/v1" not in self.required_features
        ):
            raise ValueError("nonzero prepayment requires the named extension")


class ProviderTerms(StrictModel):
    """Exact provider identity-signed contract offer object."""

    contract_hash: Hex32
    contract_terms: ContractTerms
    handshake_hash: Hex32

    @model_validator(mode="after")
    def validate_contract_hash(self) -> ProviderTerms:
        """Bind the declared contract hash to the complete terms."""
        if self.contract_hash != contract_hash(self.contract_terms).hex():
            raise ValueError("contract_hash does not match contract_terms")
        return self


class ClientAcceptance(StrictModel):
    """Exact client session-key-signed terms acceptance object."""

    contract_hash: Hex32
    handshake_hash: Hex32
    session_id: Hex32
    client_session_xonly_key: XOnlyKey
    provider_session_xonly_key: XOnlyKey

    @model_validator(mode="after")
    def validate_session_keys(self) -> ClientAcceptance:
        """Reject a transcript that assigns both session roles to one key."""
        if self.client_session_xonly_key == self.provider_session_xonly_key:
            raise ValueError("client and provider session keys must be distinct")
        return self


class Envelope(StrictModel):
    """Authenticated application envelope with closed base members."""

    protocol: Literal["rillswap"]
    wire_version: Literal["1"]
    profile_id: ProfileId
    network_identity: NetworkIdentity
    session_id: Hex32
    message_id: Hex32
    sender_session_key: XOnlyKey
    sequence: ExactInteger
    in_reply_to: Hex32 | None
    contract_hash: Hex32 | None
    message_type: Literal[
        "handshake_init",
        "handshake_accept",
        "handshake_confirm",
        "quote_request",
        "quote_offer",
        "terms_offer",
        "terms_accept",
        "funding_binding",
        "observation",
        "action_request",
        "action_result",
        "ack",
        "error",
    ]
    payload: dict[str, JsonValue]
    required_features: tuple[Identifier, ...]
    extensions: dict[str, JsonValue]
    signature: Signature64 | None

    @model_validator(mode="after")
    def validate_collections(self) -> Envelope:
        """Require deterministic features and bounded namespaced extensions."""
        require_feature_list(self.required_features, field="required_features")
        if len(self.payload) > MAX_PAYLOAD_MEMBERS:
            raise ValueError("payload has too many members")
        validate_extensions(self.extensions)
        return self


class HandshakeInit(StrictModel):
    """Closed client handshake initiation payload."""

    protocol: Literal["rillswap"]
    wire_version: Literal["1"]
    profile_id: ProfileId
    network_identity: NetworkIdentity
    session_id: Hex32
    client_challenge: Hex32
    client_session_xonly_key: XOnlyKey
    expected_provider_identity_xonly_key: XOnlyKey
    requested_encryption_suites: tuple[Identifier, ...]
    requested_capabilities: tuple[Identifier, ...]
    required_features: tuple[Identifier, ...]
    extensions: dict[str, JsonValue]

    @property
    def epoch_inbox_xonly_key(self) -> str | None:
        """Return the feature-bound epoch, never infer one for legacy inits."""
        if EPOCH_SESSION_FEATURE not in self.required_features:
            return None
        binding = self.extensions.get(EPOCH_SESSION_EXTENSION)
        if not isinstance(binding, dict) or set(binding) != {"epoch_inbox_xonly_key"}:
            raise ValueError("epoch-bound session requires its exact epoch extension")
        key = binding["epoch_inbox_xonly_key"]
        if not isinstance(key, str):
            raise ValueError("epoch inbox key must be a string")  # noqa: TRY004 - Pydantic validator
        return key

    @model_validator(mode="after")
    def validate_lists(self) -> HandshakeInit:
        """Validate preference-ordered negotiation lists and canonical features."""
        for field, values in (
            ("requested_encryption_suites", self.requested_encryption_suites),
            ("requested_capabilities", self.requested_capabilities),
        ):
            require_identifier_list(values, field=field, require_nonempty=True)
        require_feature_list(self.required_features, field="required_features")
        validate_extensions(self.extensions)
        if self.session_id == self.client_challenge:
            raise ValueError("session_id and client_challenge must be independent")
        if self.client_session_xonly_key == self.expected_provider_identity_xonly_key:
            raise ValueError("client session and provider identity keys must be distinct")
        epoch = self.epoch_inbox_xonly_key
        if (
            epoch is not None
            and self.session_id
            != epoch_bound_session_id(
                self.network_identity,
                self.expected_provider_identity_xonly_key,
                epoch,
                self.client_session_xonly_key,
            ).hex()
        ):
            raise ValueError("session_id does not bind the declared provider epoch")
        return self


class HandshakeAccept(StrictModel):
    """Closed provider identity-signed handshake selection."""

    handshake_init_hash: Hex32
    protocol: Literal["rillswap"]
    wire_version: Literal["1"]
    profile_id: ProfileId
    network_identity: NetworkIdentity
    session_id: Hex32
    client_challenge: Hex32
    provider_challenge: Hex32
    client_session_xonly_key: XOnlyKey
    provider_session_xonly_key: XOnlyKey
    provider_identity_xonly_key: XOnlyKey
    selected_encryption_suite: Identifier
    selected_capabilities: tuple[Identifier, ...]
    transport_endpoints: tuple[str, ...]
    required_features: tuple[Identifier, ...]
    extensions: dict[str, JsonValue]

    @model_validator(mode="after")
    def validate_lists(self) -> HandshakeAccept:
        """Require selected lists and endpoints to be bounded and deterministic."""
        require_identifier_list(
            self.selected_capabilities,
            field="selected_capabilities",
            require_nonempty=True,
        )
        require_feature_list(self.required_features, field="required_features")
        validate_extensions(self.extensions)
        if not 1 <= len(self.transport_endpoints) <= MAX_TRANSPORT_ENDPOINTS:
            raise ValueError("transport endpoint count is outside the protocol range")
        if len(set(self.transport_endpoints)) != len(self.transport_endpoints):
            raise ValueError("transport endpoints must be unique")
        if any(
            not endpoint or len(endpoint) > MAX_TRANSPORT_ENDPOINT_LENGTH
            for endpoint in self.transport_endpoints
        ):
            raise ValueError("transport endpoint is empty or too long")
        if (
            len(
                {
                    self.client_session_xonly_key,
                    self.provider_session_xonly_key,
                    self.provider_identity_xonly_key,
                },
            )
            != HANDSHAKE_ROLE_KEY_COUNT
        ):
            raise ValueError("session and provider identity keys must be distinct")
        if self.provider_challenge in {self.session_id, self.client_challenge}:
            raise ValueError("provider_challenge must be independent")
        return self

    def validate_against(
        self,
        initiation: HandshakeInit,
        *,
        supported_features: AbstractSet[str],
    ) -> None:
        """Validate provider selections and transcript echoes against an initiation."""
        echoed_fields = (
            "protocol",
            "wire_version",
            "profile_id",
            "network_identity",
            "session_id",
            "client_challenge",
            "client_session_xonly_key",
        )
        if any(getattr(self, field) != getattr(initiation, field) for field in echoed_fields):
            raise ValueError("handshake acceptance does not echo the initiation")
        if self.handshake_init_hash != handshake_init_hash(initiation).hex():
            raise ValueError("handshake_init_hash does not match the initiation")
        if self.provider_identity_xonly_key != initiation.expected_provider_identity_xonly_key:
            raise ValueError("provider identity does not match the expected identity")
        if self.selected_encryption_suite not in initiation.requested_encryption_suites:
            raise ValueError("provider selected an encryption suite that was not requested")
        if not set(self.selected_capabilities).issubset(initiation.requested_capabilities):
            raise ValueError("provider selected a capability that was not requested")
        required = set(initiation.required_features) | set(self.required_features)
        if not required.issubset(supported_features):
            raise ValueError("handshake requires an unknown feature")
        if EPOCH_SESSION_FEATURE in required:
            if not (
                EPOCH_SESSION_FEATURE in initiation.required_features
                and EPOCH_SESSION_FEATURE in self.required_features
            ):
                raise ValueError("epoch-bound admission must be jointly negotiated")
            if self.provider_session_xonly_key == initiation.epoch_inbox_xonly_key:
                raise ValueError("provider session and epoch inbox keys must be distinct")
        if COOPERATIVE_CLAIM_FEATURE in required and not (
            COOPERATIVE_CLAIM_FEATURE in initiation.required_features
            and COOPERATIVE_CLAIM_FEATURE in self.required_features
        ):
            raise ValueError("cooperative claim must be jointly negotiated")


class HandshakeAcceptPayload(StrictModel):
    """Exact handshake-accept payload with sibling identity signature."""

    accept: HandshakeAccept
    provider_identity_signature: Signature64


def require_supported_contract_features(
    terms: ContractTerms, initiation: HandshakeInit, acceptance: HandshakeAccept
) -> None:
    """Bind supported signed contract features to both handshake commitments.

    Negotiating the cooperative feature commits a swap to attempt key-path
    claiming, but never removes independent unilateral claim/refund. New forward
    admission requires it; new reverse clients may explicitly negotiate its
    absence in both handshakes and terms. Signed historical terms retain their
    original commitment. No local metadata selects or changes this feature.
    """
    if set(terms.required_features) - {COOPERATIVE_CLAIM_FEATURE}:
        raise ValueError("unsupported contract feature")
    cooperative = COOPERATIVE_CLAIM_FEATURE in terms.required_features
    if cooperative != (
        COOPERATIVE_CLAIM_FEATURE in initiation.required_features
    ) or cooperative != (COOPERATIVE_CLAIM_FEATURE in acceptance.required_features):
        raise ValueError("cooperative contract feature is not bound to both handshakes")


class HandshakeConfirm(StrictModel):
    """Client session-key possession confirmation payload."""

    handshake_hash: Hex32
    session_id: Hex32
    client_session_xonly_key: XOnlyKey
    provider_session_xonly_key: XOnlyKey


class FundingBinding(StrictModel):
    """Authenticated exact funding outpoint and replacement lineage."""

    contract_hash: Hex32
    funding_attempt_id: Hex32
    binding_revision: ExactInteger
    funder_role: Party
    lineage_anchor_txid: Hex32
    lineage_anchor_vout: ExactInteger
    funding_txid: Hex32
    contract_vout: ExactInteger
    contract_value_sat: str
    contract_script_pubkey: ScriptHex
    replaces_txid: Hex32 | None
    created_at: ExactInteger

    @model_validator(mode="after")
    def validate_binding(self) -> FundingBinding:
        """Require positive value and coherent initial/replacement revision shape."""
        validate_decimal_sats(
            self.contract_value_sat,
            field="contract_value_sat",
            positive=True,
        )
        require_p2tr_script(
            self.contract_script_pubkey,
            field="contract_script_pubkey",
        )
        if (self.binding_revision == 0) != (self.replaces_txid is None):
            raise ValueError("only binding revision zero may omit a predecessor")
        return self
