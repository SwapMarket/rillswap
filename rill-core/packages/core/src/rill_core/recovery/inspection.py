"""Static RS-007 plaintext inspection, not recovery or historical authorization.

Only canonical UTF-8 plaintext is accepted. The returned report carries no
secrets, authenticated-provider provenance, chain evidence, durable export
proof, permission to sign, or current snapshot freshness. It must never be
used to auto-start scanning or to overwrite newer monotonic knowledge.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Annotated, Literal, Protocol

from pydantic import Field
from pydantic import ValidationError as PydanticValidationError

from rill_core.errors import CanonicalizationError, ValidationError
from rill_core.settlement.funding_authentication import (
    MAX_BINDING_HISTORY,
    SignedFundingBinding,
    _check_static_binding_history,
)
from rill_core.settlement.taproot import TaprootKeyOperations, reconstruct_taproot_contract
from rill_core.settlement.unilateral import (
    FundingOutput,
    UnilateralAuthorization,
    build_unilateral_spend,
    finalize_unilateral_spend,
)
from rill_core.wire.canonical import JsonValue, canonicalize, parse_json_strict
from rill_core.wire.hashes import (
    COOPERATIVE_CLAIM_FEATURE,
    EPOCH_SESSION_FEATURE,
    client_acceptance_hash,
    contract_hash,
    handshake_accept_hash,
    handshake_hash,
    provider_terms_hash,
)
from rill_core.wire.messages import (
    ClientAcceptance,
    ContractTerms,
    FundingBinding,
    HandshakeAccept,
    HandshakeInit,
    ProviderTerms,
    require_supported_contract_features,
)
from rill_core.wire.types import (
    ExactInteger,
    Hex32,
    NetworkIdentity,
    ScriptHex,
    Signature64,
    StrictModel,
    XOnlyKey,
    validate_decimal_sats,
    validate_extensions,
)

MAX_RECOVERY_BYTES = 128 * 1024
FUNDING_ATTEMPT_HEX_LENGTH = 64
SCHNORR_AUXILIARY_BYTES = 32
PURPOSE_KEY_COUNT = 6
type _Parity = Annotated[int, Field(strict=True, ge=0, le=1)]
UNPROVEN = (
    "provider identity provenance",
    "handshake confirmation and message order",
    "funding transactions, conflicts, UTXOs, and chain maturity",
    "export durability, age decryptability, and snapshot freshness",
)


class RecoveryCrypto(TaprootKeyOperations, Protocol):
    """Exactly the curve, signature, and public-key operations inspection needs."""

    def schnorr_verify(self, public_key: bytes, message: bytes, signature: bytes) -> None:
        """Verify a BIP340 signature or raise an exception."""
        ...

    def public_key(self, secret_key: bytes) -> bytes:
        """Return a compressed secp256k1 public key or raise an exception."""
        ...


class RecoveryRefundCrypto(RecoveryCrypto, Protocol):
    """Native one-shot signer used only inside the validated recovery boundary."""

    def schnorr_sign(self, secret_key: bytes, message: bytes, auxiliary_random: bytes) -> bytes:
        """Produce a BIP340 signature for one validated refund digest or raise."""
        ...


class _IdentitySource(StrictModel):
    kind: Literal["manual", "advertisement"]
    advertisement_digest: Hex32 | None


class _VerificationContext(StrictModel):
    handshake_init: HandshakeInit
    handshake_accept: HandshakeAccept
    provider_identity_signature: Signature64
    handshake_hash: Hex32
    client_session_xonly_key: XOnlyKey
    provider_session_xonly_key: XOnlyKey
    expected_provider_identity_source: _IdentitySource
    provider_terms_signature: Signature64
    client_acceptance_signature: Signature64


class _TaprootArtifacts(StrictModel):
    internal_xonly_key: Hex32
    internal_key_parity: _Parity
    claim_script: ScriptHex
    refund_script: ScriptHex
    claim_leaf_hash: Hex32
    refund_leaf_hash: Hex32
    merkle_root: Hex32
    tap_tweak: Hex32
    output_xonly_key: Hex32
    output_key_parity: _Parity
    script_pubkey: ScriptHex
    claim_control_block: ScriptHex
    refund_control_block: ScriptHex


class _UserSecret(StrictModel):
    kind: Literal["raw-secp256k1-v1"]
    contract_secret_key: Hex32


class _FundingRecord(StrictModel):
    binding: FundingBinding
    funder_session_signature: Signature64


class _FeePolicy(StrictModel):
    max_claim_fee_sat: str
    max_refund_fee_sat: str


class _MonotonicKnowledge(StrictModel):
    preimage_known: bool
    preimage: Hex32 | None
    dangerous_signature_issued: bool


class _RecoveryPlaintext(StrictModel):
    format: Literal["rillswap-recovery"]
    format_version: Literal["1-pre.1"]
    specification_version: Literal["0.1.0-pre.1"]
    created_at: ExactInteger
    updated_at: ExactInteger
    network_identity: NetworkIdentity
    profile_id: Literal["btc-to-ln/v1", "ln-to-btc/v1"]
    contract_hash: Hex32
    contract_terms: ContractTerms
    verification_context: _VerificationContext
    taproot_contract: _TaprootArtifacts
    user_secret: _UserSecret
    funding_history: tuple[_FundingRecord, ...] = Field(max_length=MAX_BINDING_HISTORY)
    chain_scan_birthday_height: ExactInteger
    fee_policy: _FeePolicy
    recovery_authorization_xonly_key: XOnlyKey
    monotonic_knowledge: _MonotonicKnowledge
    extensions: dict[str, JsonValue]


@dataclass(frozen=True, slots=True)
class OfflineRecoveryInspection:
    """Redacted static checks only, never evidence for any financial action."""

    network_name: str
    profile_id: str
    refund_lock_height: int
    first_refund_eligible_height: int
    recorded_binding_count: int
    unproven: tuple[str, ...] = UNPROVEN


@dataclass(frozen=True, slots=True)
class SelectedRecoveryFundingContext:
    """Signed public terms and one candidate binding, never action authority.

    Terms may contain caller-defined extensions; never log this entire value.
    Frozen models do not deep-freeze extension mappings.
    """

    terms: ContractTerms
    binding: FundingBinding


def inspect_recovery_plaintext(
    document: bytes,
    expected_network: NetworkIdentity,
    *,
    crypto: RecoveryCrypto,
) -> OfflineRecoveryInspection:
    """Inspect a fully consistent static package, without granting authority.

    All failures have sanitized errors. This does not decrypt age, establish
    provider provenance, verify funding transactions, or open a chain source.
    """
    try:
        return _parse_and_inspect(document, expected_network, crypto)
    except (CanonicalizationError, PydanticValidationError, ValueError, RuntimeError):
        # Pydantic messages and duplicate-key errors may echo secret-bearing input.
        # Exit the handler before raising so no secret-bearing __context__
        # remains reachable through the public error object.
        pass
    raise ValidationError("invalid or unsupported recovery plaintext")


def inspect_recovery_successor(
    previous: bytes,
    candidate: bytes,
    expected_network: NetworkIdentity,
    *,
    crypto: RecoveryCrypto,
) -> OfflineRecoveryInspection:
    """Validate one explicit pair of canonical offline recovery snapshots.

    This compares only to the supplied previous file. A restored prior, an
    unknown sibling, or another writer can hold more knowledge. No freshness,
    global reconciliation, chain observation, or financial authority follows.
    The secret-bearing parsed records are never returned to the caller.
    """
    try:
        prior_record, _ = _validated_record(previous, expected_network, crypto)
        next_record, result = _validated_record(candidate, expected_network, crypto)
        _require_successor(prior_record, next_record)
    except (CanonicalizationError, PydanticValidationError, ValueError, RuntimeError):
        # The private models contain keys and preimages. Do not preserve a
        # secret-bearing exception chain or echo any compared field value.
        pass
    else:
        return result
    raise ValidationError("invalid or nonmonotonic recovery successor")


def inspect_recovery_selected_funding_binding(
    document: bytes,
    expected_network: NetworkIdentity,
    *,
    funding_attempt_id: str,
    binding_revision: int,
    crypto: RecoveryCrypto,
) -> FundingBinding:
    """Project one explicitly selected, statically valid *candidate* binding.

    All records and signatures are checked before selection. This proves no
    transaction existence, unspent state, inclusion, freshness, or authority.
    A valid restored snapshot may omit later binding knowledge.
    """
    try:
        return _selected_funding_context(
            document,
            expected_network,
            funding_attempt_id,
            binding_revision,
            crypto,
        ).binding
    except Exception:  # noqa: BLE001, S110 - adapter errors can echo secret key bytes
        # Errors from signed record parsing/crypto may echo secrets. Suppress
        # exception chaining and return no partial or inferred latest history.
        pass
    raise ValidationError("invalid or unavailable recovery funding binding")


def inspect_recovery_selected_funding_context(
    document: bytes,
    expected_network: NetworkIdentity,
    *,
    funding_attempt_id: str,
    binding_revision: int,
    crypto: RecoveryCrypto,
) -> SelectedRecoveryFundingContext:
    """Project public terms with one exact binding after full static validation.

    The pair can support a future explicit chain/transaction-byte query. It
    exposes no designated recovery secret, preimage, signature, history,
    freshness, or permission to sign. Signed public terms can carry arbitrary
    extension values and should not be logged; restored files can be stale.
    """
    try:
        result = _selected_funding_context(
            document,
            expected_network,
            funding_attempt_id,
            binding_revision,
            crypto,
        )
    except Exception:  # noqa: BLE001, S110 - secret-bearing adapter errors stay private
        pass
    else:
        return result
    raise ValidationError("invalid or unavailable recovery funding context")


def _selected_funding_context(
    document: bytes,
    expected_network: NetworkIdentity,
    funding_attempt_id: str,
    binding_revision: int,
    crypto: RecoveryCrypto,
) -> SelectedRecoveryFundingContext:
    record, _ = _validated_record(document, expected_network, crypto)
    selected = _select_record_binding(record, funding_attempt_id, binding_revision)
    return SelectedRecoveryFundingContext(record.contract_terms, selected)


def _select_record_binding(
    record: _RecoveryPlaintext,
    funding_attempt_id: str,
    binding_revision: int,
) -> FundingBinding:
    _require(
        not (
            type(funding_attempt_id) is not str
            or len(funding_attempt_id) != FUNDING_ATTEMPT_HEX_LENGTH
            or any(char not in "0123456789abcdef" for char in funding_attempt_id)
            or type(binding_revision) is not int
            or binding_revision < 0
        ),
        "invalid explicit funding selector",
    )
    for item in record.funding_history:
        binding = item.binding
        if (
            binding.funding_attempt_id == funding_attempt_id
            and binding.binding_revision == binding_revision
        ):
            return binding
    raise ValidationError("explicit funding selection is not in this snapshot")


def construct_selected_recovery_refund(  # noqa: PLR0913 - all independent checks explicit
    document: bytes,
    expected_network: NetworkIdentity,
    *,
    funding_attempt_id: str,
    binding_revision: int,
    live_funding: FundingOutput,
    sampled_tip_height: int,
    fee_sat: int,
    auxiliary_random: bytes,
    crypto: RecoveryRefundCrypto,
) -> bytes:
    """Return a signed BTC-to-LN user refund for one externally checked outpoint.

    All recovery secrets remain internal. Caller-supplied chain data is NOT
    certified here: the caller must separately sample the selected Core UTXO,
    including mempool spends, and recheck before any *manual* broadcast.
    This never proves completion, absence of payment, or global lineage.
    """
    try:
        record, _ = _validated_record(document, expected_network, crypto)
        binding = _select_record_binding(record, funding_attempt_id, binding_revision)
        terms = record.contract_terms
        _require(
            terms.profile_id == "btc-to-ln/v1"
            and terms.refund_party == "client"
            and type(sampled_tip_height) is int
            and sampled_tip_height > terms.refund_lock_height
            and type(fee_sat) is int
            and type(auxiliary_random) is bytes
            and len(auxiliary_random) == SCHNORR_AUXILIARY_BYTES
            and type(live_funding) is FundingOutput
            and live_funding.txid == bytes.fromhex(binding.funding_txid)
            and live_funding.output_index == binding.contract_vout
            and live_funding.value_sat == int(binding.contract_value_sat)
            and live_funding.script_pubkey == bytes.fromhex(binding.contract_script_pubkey),
            "selected funding or refund maturity differs from signed recovery",
        )
        authorization = UnilateralAuthorization.from_terms(
            terms,
            live_funding,
            "refund",
            keys=crypto,
        )
        _require(
            authorization.signer_public_key
            == bytes.fromhex(terms.client_contract_compressed_key)[1:],
            "recovery refund does not belong to client",
        )
        plan = build_unilateral_spend(authorization, fee_sat=fee_sat)
        secret = bytes.fromhex(record.user_secret.contract_secret_key)
        signature = crypto.schnorr_sign(secret, plan.signature_hash, auxiliary_random)
        result = finalize_unilateral_spend(plan, signature, verifier=crypto).raw_transaction
    except Exception:  # noqa: BLE001, S110 - no secret, signer, or record errors escape
        pass
    else:
        return result
    raise ValidationError("recovery refund construction refused")


def construct_selected_recovery_claim(  # noqa: PLR0913 - independent policy inputs explicit
    document: bytes,
    expected_network: NetworkIdentity,
    *,
    funding_attempt_id: str,
    binding_revision: int,
    live_funding: FundingOutput,
    sampled_tip_height: int,
    sampled_confirmations: int,
    fee_sat: int,
    auxiliary_random: bytes,
    crypto: RecoveryRefundCrypto,
) -> bytes:
    """Prepare an LN-to-BTC user claim, NOT permission to disclose its preimage.

    The returned transaction bytes CONTAIN the client's preimage in the claim
    witness. Caller-supplied height/confirmations/UTXO are untrusted here and
    do not establish freshness, fee viability, durable recovery, or safety to
    expose this transaction to any external party (including a Core RPC).
    This function has no network, file, broadcast, or state side effects.
    The pre-disclosure margin is not a general prohibition on an urgent claim
    after the preimage has already become public.
    """
    try:
        record, _ = _validated_record(document, expected_network, crypto)
        binding = _select_record_binding(record, funding_attempt_id, binding_revision)
        terms = record.contract_terms
        knowledge = record.monotonic_knowledge
        _require(
            terms.profile_id == "ln-to-btc/v1"
            and terms.claimant == "client"
            and terms.timing_policy.kind == "ln-to-btc"
            and type(sampled_tip_height) is int
            and sampled_tip_height >= 0
            and type(sampled_confirmations) is int
            and sampled_confirmations >= terms.funding_confirmations
            and sampled_confirmations <= sampled_tip_height + 1
            and sampled_tip_height + terms.timing_policy.claim_confirmation_blocks
            < terms.refund_lock_height + 1
            and type(fee_sat) is int
            and type(auxiliary_random) is bytes
            and len(auxiliary_random) == SCHNORR_AUXILIARY_BYTES
            and type(live_funding) is FundingOutput
            and live_funding.txid == bytes.fromhex(binding.funding_txid)
            and live_funding.output_index == binding.contract_vout
            and live_funding.value_sat == int(binding.contract_value_sat)
            and live_funding.script_pubkey == bytes.fromhex(binding.contract_script_pubkey)
            and knowledge.preimage_known
            and knowledge.preimage is not None,
            "selected claim pre-disclosure conditions are not established",
        )
        authorization = UnilateralAuthorization.from_terms(
            terms,
            live_funding,
            "claim",
            keys=crypto,
        )
        _require(
            authorization.signer_public_key
            == bytes.fromhex(terms.client_contract_compressed_key)[1:],
            "recovery claim does not belong to client",
        )
        preimage = bytes.fromhex(knowledge.preimage or "")
        plan = build_unilateral_spend(authorization, fee_sat=fee_sat, claim_preimage=preimage)
        secret = bytes.fromhex(record.user_secret.contract_secret_key)
        signature = crypto.schnorr_sign(secret, plan.signature_hash, auxiliary_random)
        result = finalize_unilateral_spend(plan, signature, verifier=crypto).raw_transaction
    except Exception:  # noqa: BLE001, S110 - preimage, secret, and signer errors stay private
        pass
    else:
        return result
    raise ValidationError("recovery claim preparation refused")


def _parse_and_inspect(
    document: bytes, expected_network: NetworkIdentity, crypto: RecoveryCrypto
) -> OfflineRecoveryInspection:
    _, report = _validated_record(document, expected_network, crypto)
    return report


def _validated_record(
    document: bytes, expected_network: NetworkIdentity, crypto: RecoveryCrypto
) -> tuple[_RecoveryPlaintext, OfflineRecoveryInspection]:
    if not isinstance(expected_network, NetworkIdentity):
        raise ValidationError("expected network is required")
    parsed = parse_json_strict(document, max_bytes=MAX_RECOVERY_BYTES)
    if canonicalize(parsed) != document:
        raise ValidationError("recovery plaintext is not canonical UTF-8 JSON")
    record = _RecoveryPlaintext.model_validate_json(document, strict=True)
    return record, _inspect(record, expected_network, crypto)


def _require_successor(previous: _RecoveryPlaintext, candidate: _RecoveryPlaintext) -> None:
    mutable = {"updated_at", "funding_history", "chain_scan_birthday_height", "monotonic_knowledge"}
    _require(
        canonicalize(previous.model_dump(mode="json", exclude=mutable))
        == canonicalize(candidate.model_dump(mode="json", exclude=mutable)),
        "recovery contract changed",
    )
    _require(candidate.updated_at >= previous.updated_at, "recovery timestamp regressed")
    _require(
        candidate.chain_scan_birthday_height <= previous.chain_scan_birthday_height,
        "scan birthday regressed",
    )
    _require(
        candidate.funding_history[: len(previous.funding_history)] == previous.funding_history,
        "funding knowledge regressed",
    )
    earlier = previous.monotonic_knowledge
    later = candidate.monotonic_knowledge
    _require(
        not earlier.preimage_known or (later.preimage_known and earlier.preimage == later.preimage),
        "known preimage changed",
    )
    _require(
        not earlier.dangerous_signature_issued or later.dangerous_signature_issued,
        "issued signature knowledge regressed",
    )


def _require(condition: bool, message: str) -> None:  # noqa: FBT001 - internal predicate
    if not condition:
        raise ValidationError(message)


def _verify(crypto: RecoveryCrypto, key: str, digest: bytes, signature: str) -> None:
    crypto.schnorr_verify(bytes.fromhex(key), digest, bytes.fromhex(signature))


def _inspect(
    record: _RecoveryPlaintext, expected_network: NetworkIdentity, crypto: RecoveryCrypto
) -> OfflineRecoveryInspection:
    terms, context = record.contract_terms, record.verification_context
    initiation, acceptance = context.handshake_init, context.handshake_accept
    _require(record.network_identity == expected_network == terms.network_identity, "network")
    _require(
        initiation.network_identity == acceptance.network_identity == expected_network,
        "handshake network",
    )
    _require(record.profile_id == terms.profile_id == initiation.profile_id, "profile")
    require_supported_contract_features(terms, initiation, acceptance)
    acceptance.validate_against(
        initiation, supported_features=frozenset({EPOCH_SESSION_FEATURE, COOPERATIVE_CLAIM_FEATURE})
    )
    _require(context.client_session_xonly_key == initiation.client_session_xonly_key, "session")
    _require(context.provider_session_xonly_key == acceptance.provider_session_xonly_key, "session")
    _require(
        terms.provider_identity_key == initiation.expected_provider_identity_xonly_key,
        "provider identity",
    )
    _require(
        len(
            {
                initiation.client_session_xonly_key,
                acceptance.provider_session_xonly_key,
                terms.provider_identity_key,
                terms.client_contract_compressed_key[2:],
                terms.provider_contract_compressed_key[2:],
                terms.recovery_authorization_xonly_key,
            }
        )
        == PURPOSE_KEY_COUNT,
        "reused purpose key",
    )
    signed_contract_hash = contract_hash(terms).hex()
    _require(record.contract_hash == signed_contract_hash, "contract hash")
    transcript_hash = handshake_hash(initiation, acceptance).hex()
    _require(context.handshake_hash == transcript_hash, "transcript")
    provider_terms = ProviderTerms(
        contract_hash=signed_contract_hash, contract_terms=terms, handshake_hash=transcript_hash
    )
    client_acceptance = ClientAcceptance(
        contract_hash=signed_contract_hash,
        handshake_hash=transcript_hash,
        session_id=initiation.session_id,
        client_session_xonly_key=initiation.client_session_xonly_key,
        provider_session_xonly_key=acceptance.provider_session_xonly_key,
    )
    provider_key = terms.provider_identity_key
    _verify(
        crypto, provider_key, handshake_accept_hash(acceptance), context.provider_identity_signature
    )
    _verify(
        crypto, provider_key, provider_terms_hash(provider_terms), context.provider_terms_signature
    )
    _verify(
        crypto,
        initiation.client_session_xonly_key,
        client_acceptance_hash(client_acceptance),
        context.client_acceptance_signature,
    )
    _require(record.updated_at >= record.created_at, "timestamps")
    _require(record.chain_scan_birthday_height <= terms.refund_lock_height, "birthday")
    _require(
        record.recovery_authorization_xonly_key == terms.recovery_authorization_xonly_key,
        "recovery key",
    )
    for fee in (record.fee_policy.max_claim_fee_sat, record.fee_policy.max_refund_fee_sat):
        validate_decimal_sats(fee, field="recovery fee cap")
    _require(
        (record.fee_policy.max_claim_fee_sat, record.fee_policy.max_refund_fee_sat)
        == (terms.max_claim_fee_sat, terms.max_refund_fee_sat),
        "fee policy",
    )
    validate_extensions(record.extensions)
    knowledge = record.monotonic_knowledge
    _require(knowledge.preimage_known == (knowledge.preimage is not None), "preimage state")
    _require(
        terms.profile_id != "ln-to-btc/v1" or knowledge.preimage_known, "missing client preimage"
    )
    if knowledge.preimage is not None:
        _require(
            hashlib.sha256(bytes.fromhex(knowledge.preimage)).hexdigest()
            == terms.invoice_binding.payment_hash,
            "preimage hash",
        )
    _require(
        crypto.public_key(bytes.fromhex(record.user_secret.contract_secret_key)).hex()
        == terms.client_contract_compressed_key,
        "client contract key",
    )
    reconstructed = reconstruct_taproot_contract(terms, keys=crypto)
    artifacts = record.taproot_contract
    for stored, reconstructed_value in (
        (artifacts.internal_xonly_key, reconstructed.internal_key.hex()),
        (artifacts.internal_key_parity, reconstructed.internal_parity),
        (artifacts.claim_script, reconstructed.claim_script.hex()),
        (artifacts.refund_script, reconstructed.refund_script.hex()),
        (artifacts.claim_leaf_hash, reconstructed.claim_leaf_hash.hex()),
        (artifacts.refund_leaf_hash, reconstructed.refund_leaf_hash.hex()),
        (artifacts.merkle_root, reconstructed.merkle_root.hex()),
        (artifacts.tap_tweak, reconstructed.tap_tweak.hex()),
        (artifacts.output_xonly_key, reconstructed.output_key.hex()),
        (artifacts.output_key_parity, reconstructed.output_parity),
        (artifacts.script_pubkey, reconstructed.script_pubkey.hex()),
        (artifacts.claim_control_block, reconstructed.claim_control_block.hex()),
        (artifacts.refund_control_block, reconstructed.refund_control_block.hex()),
    ):
        _require(stored == reconstructed_value, "Taproot artifact")
    _check_static_history(record, crypto)
    return OfflineRecoveryInspection(
        network_name=record.network_identity.name,
        profile_id=record.profile_id,
        refund_lock_height=terms.refund_lock_height,
        first_refund_eligible_height=terms.refund_lock_height + 1,
        recorded_binding_count=len(record.funding_history),
    )


def _check_static_history(record: _RecoveryPlaintext, crypto: RecoveryCrypto) -> None:
    """Check signed binding chain only; transactions and anchor spends are unproved."""
    terms = record.contract_terms
    role = "client" if terms.profile_id == "btc-to-ln/v1" else "provider"
    session_key = (
        record.verification_context.client_session_xonly_key
        if role == "client"
        else record.verification_context.provider_session_xonly_key
    )
    _check_static_binding_history(
        tuple(
            SignedFundingBinding(item.binding, item.funder_session_signature)
            for item in record.funding_history
        ),
        terms,
        record.contract_hash,
        record.taproot_contract.script_pubkey,
        session_key,
        crypto=crypto,
    )
