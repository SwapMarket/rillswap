"""Encrypt a locally signed LN-to-BTC claim before any external preimage disclosure.

This is a static, staleable recovery artifact. Even successful readback is
never an authorization to send bytes to Core, reveal the witness, or pay.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import TYPE_CHECKING, Literal, cast

import pyrage
from pydantic import Field
from rill_core.recovery import (
    construct_selected_recovery_claim,
    inspect_recovery_selected_funding_context,
)
from rill_core.settlement import FundingOutput, UnilateralAuthorization, validate_unilateral_spend
from rill_core.wire.canonical import canonicalize, parse_model_json
from rill_core.wire.types import Hex32, NetworkIdentity, StrictModel

from rill_cli.age_container import (
    MAX_CIPHERTEXT_BYTES,
    RecoveryContainerError,
    X25519Credentials,
    _bounded_plaintext,
    _identity,
    validate_age_profile,
)

if TYPE_CHECKING:
    from rill_core.recovery.inspection import RecoveryRefundCrypto
    from rill_core.wire.messages import FundingBinding

    from rill_cli.recovery_core_observation import RecoveryOutpointCandidate

MAX_CLAIM_BYTES = 6_000  # Explicit resource cap for this one-input, one-output v1 path.


class ClaimPlanError(RecoveryContainerError):
    """An encrypted claim plan cannot be constructed or verified as selected."""


def _require(condition: bool, message: str) -> None:  # noqa: FBT001 - local predicate
    if not condition:
        raise ClaimPlanError(message)


class _ClaimPlan(StrictModel):
    kind: Literal["rillswap-opaque-claim-plan/v1"]
    network_identity: NetworkIdentity
    contract_hash: Hex32
    recovery_plaintext_sha256: Hex32
    funding_attempt_id: Hex32
    binding_revision: int = Field(strict=True, ge=0)
    signed_claim_hex: str = Field(
        min_length=2, max_length=MAX_CLAIM_BYTES * 2, pattern=r"^(?:[0-9a-f]{2})+$"
    )


@dataclass(frozen=True, slots=True)
class ClaimPlanReceipt:
    """Public metadata only, never preimage-disclosure authority."""

    funding_txid: str
    contract_vout: int
    claim_txid: str
    fee_sat: int


@dataclass(frozen=True, slots=True)
class EncryptedClaimPlan:
    """Ciphertext to publish exactly once, with only redacted public metadata."""

    ciphertext: bytes
    receipt: ClaimPlanReceipt


def _funding(binding: FundingBinding) -> FundingOutput:
    return FundingOutput(
        bytes.fromhex(binding.funding_txid),
        binding.contract_vout,
        int(binding.contract_value_sat),
        bytes.fromhex(binding.contract_script_pubkey),
    )


def _verify_plan(  # noqa: PLR0913 - all trust inputs required on readback
    plan_plaintext: bytes,
    recovery_plaintext: bytes,
    expected_network: NetworkIdentity,
    *,
    funding_attempt_id: str,
    binding_revision: int,
    crypto: RecoveryRefundCrypto,
) -> ClaimPlanReceipt:
    plan = parse_model_json(_ClaimPlan, plan_plaintext)
    if canonicalize(plan.model_dump(mode="json")) != plan_plaintext:
        raise ClaimPlanError("claim plan is not canonical")
    selected = inspect_recovery_selected_funding_context(
        recovery_plaintext,
        expected_network,
        funding_attempt_id=funding_attempt_id,
        binding_revision=binding_revision,
        crypto=crypto,
    )
    terms, binding = selected.terms, selected.binding
    if (
        terms.profile_id != "ln-to-btc/v1"
        or terms.claimant != "client"
        or plan.network_identity != expected_network
        or plan.contract_hash != binding.contract_hash
        or plan.recovery_plaintext_sha256 != hashlib.sha256(recovery_plaintext).hexdigest()
        or plan.funding_attempt_id != binding.funding_attempt_id
        or plan.binding_revision != binding.binding_revision
    ):
        raise ClaimPlanError("claim plan differs from selected recovery context")
    authorization = UnilateralAuthorization.from_terms(
        terms,
        _funding(binding),
        "claim",
        keys=crypto,
    )
    raw = bytes.fromhex(plan.signed_claim_hex)
    if raw.hex() != plan.signed_claim_hex:
        raise ClaimPlanError("claim plan transaction is not exact lowercase hex")
    checked = validate_unilateral_spend(
        raw,
        authorization,
        verifier=crypto,
    )
    return ClaimPlanReceipt(
        binding.funding_txid, binding.contract_vout, checked.txid, checked.fee_sat
    )


def verify_encrypted_claim_plan(  # noqa: PLR0913 - public readback trust inputs explicit
    plan_ciphertext: bytes,
    recovery_ciphertext: bytes,
    expected_network: NetworkIdentity,
    *,
    credentials: X25519Credentials,
    funding_attempt_id: str,
    binding_revision: int,
    crypto: RecoveryRefundCrypto,
) -> ClaimPlanReceipt:
    """Recheck a plan against the same selected snapshot, not live evidence.

    This function returns ONLY public metadata. It does not establish that the
    selected recovery snapshot or output is current, or that disclosure is safe.
    """
    try:
        result = _verify_encrypted_claim_plan(
            plan_ciphertext,
            recovery_ciphertext,
            expected_network,
            credentials=credentials,
            funding_attempt_id=funding_attempt_id,
            binding_revision=binding_revision,
            crypto=crypto,
        )
    except Exception:  # noqa: BLE001, S110 - third-party errors may contain raw witness/preimage
        pass
    else:
        return result
    raise ClaimPlanError("encrypted claim plan verification failed")


def _verify_encrypted_claim_plan(  # noqa: PLR0913 - independent readback inputs
    plan_ciphertext: bytes,
    recovery_ciphertext: bytes,
    expected_network: NetworkIdentity,
    *,
    credentials: X25519Credentials,
    funding_attempt_id: str,
    binding_revision: int,
    crypto: RecoveryRefundCrypto,
) -> ClaimPlanReceipt:
    _require(type(credentials) is X25519Credentials, "protected X25519 credentials required")
    _require(
        type(plan_ciphertext) is bytes and len(plan_ciphertext) <= MAX_CIPHERTEXT_BYTES,
        "claim plan ciphertext exceeds size limit",
    )
    recovery_plaintext = _bounded_plaintext(recovery_ciphertext, credentials)
    plan_plaintext = _bounded_plaintext(plan_ciphertext, credentials)
    return _verify_plan(
        plan_plaintext,
        recovery_plaintext,
        expected_network,
        funding_attempt_id=funding_attempt_id,
        binding_revision=binding_revision,
        crypto=crypto,
    )


def load_verified_claim_bytes_for_regtest_disclosure(  # noqa: PLR0913 - trust inputs explicit
    plan_ciphertext: bytes,
    recovery_ciphertext: bytes,
    expected_network: NetworkIdentity,
    *,
    credentials: X25519Credentials,
    funding_attempt_id: str,
    binding_revision: int,
    crypto: RecoveryRefundCrypto,
) -> tuple[bytes, ClaimPlanReceipt]:
    """Release secret-bearing bytes ONLY to the explicit experimental CLI boundary.

    Never log, publish in plaintext, pass to preflight before durable intent,
    or treat a restored plan as evidence of no earlier disclosure.
    """
    try:
        result = _load_verified_claim_bytes(
            plan_ciphertext,
            recovery_ciphertext,
            expected_network,
            credentials=credentials,
            funding_attempt_id=funding_attempt_id,
            binding_revision=binding_revision,
            crypto=crypto,
        )
    except Exception:  # noqa: BLE001, S110 - no secret-bearing helper exception escapes
        pass
    else:
        return result
    raise ClaimPlanError("encrypted claim plan unavailable for experimental disclosure")


def _load_verified_claim_bytes(  # noqa: PLR0913 - exact protected inputs explicit
    plan_ciphertext: bytes,
    recovery_ciphertext: bytes,
    expected_network: NetworkIdentity,
    *,
    credentials: X25519Credentials,
    funding_attempt_id: str,
    binding_revision: int,
    crypto: RecoveryRefundCrypto,
) -> tuple[bytes, ClaimPlanReceipt]:
    _require(type(credentials) is X25519Credentials, "protected X25519 credentials required")
    recovery_plaintext = _bounded_plaintext(recovery_ciphertext, credentials)
    plan_plaintext = _bounded_plaintext(plan_ciphertext, credentials)
    receipt = _verify_plan(
        plan_plaintext,
        recovery_plaintext,
        expected_network,
        funding_attempt_id=funding_attempt_id,
        binding_revision=binding_revision,
        crypto=crypto,
    )
    plan = parse_model_json(_ClaimPlan, plan_plaintext)
    return bytes.fromhex(plan.signed_claim_hex), receipt


def prepare_encrypted_claim_plan(  # noqa: PLR0913 - no implicit chain/selector inputs
    recovery_ciphertext: bytes,
    expected_network: NetworkIdentity,
    *,
    credentials: X25519Credentials,
    funding_attempt_id: str,
    binding_revision: int,
    candidate: RecoveryOutpointCandidate,
    fee_sat: int,
    auxiliary_random: bytes,
    crypto: RecoveryRefundCrypto,
) -> EncryptedClaimPlan:
    """Sign only inside a protected local process and return encrypted bytes.

    The caller MUST obtain the candidate from observe_claim, not from a
    restored plan. The candidate remains staleable; publication grants no
    permission to release the encrypted document or its plaintext to Core.
    """
    try:
        result = _prepare_encrypted_claim_plan(
            recovery_ciphertext,
            expected_network,
            credentials=credentials,
            funding_attempt_id=funding_attempt_id,
            binding_revision=binding_revision,
            candidate=candidate,
            fee_sat=fee_sat,
            auxiliary_random=auxiliary_random,
            crypto=crypto,
        )
    except Exception:  # noqa: BLE001, S110 - never retain secret-bearing native/pyrage errors
        pass
    else:
        return result
    raise ClaimPlanError("encrypted claim plan preparation failed")


def _prepare_encrypted_claim_plan(  # noqa: PLR0913 - secret-bearing inputs explicit
    recovery_ciphertext: bytes,
    expected_network: NetworkIdentity,
    *,
    credentials: X25519Credentials,
    funding_attempt_id: str,
    binding_revision: int,
    candidate: RecoveryOutpointCandidate,
    fee_sat: int,
    auxiliary_random: bytes,
    crypto: RecoveryRefundCrypto,
) -> EncryptedClaimPlan:
    _require(type(credentials) is X25519Credentials, "protected X25519 credentials required")
    identity, recipient = _identity(credentials)
    recovery_plaintext = _bounded_plaintext(recovery_ciphertext, credentials)
    selected = inspect_recovery_selected_funding_context(
        recovery_plaintext,
        expected_network,
        funding_attempt_id=funding_attempt_id,
        binding_revision=binding_revision,
        crypto=crypto,
    )
    terms, binding = selected.terms, selected.binding
    _require(
        not (
            terms.profile_id != "ln-to-btc/v1"
            or terms.claimant != "client"
            or candidate.network_identity != expected_network
            or candidate.static_match.funding_txid != binding.funding_txid
            or candidate.static_match.contract_vout != binding.contract_vout
            or candidate.chain_only_confirmations < terms.funding_confirmations
            or candidate.tip_height + terms.timing_policy.claim_confirmation_blocks
            >= terms.refund_lock_height + 1
        ),
        "selected claim sample is not established",
    )
    raw = construct_selected_recovery_claim(
        recovery_plaintext,
        expected_network,
        funding_attempt_id=funding_attempt_id,
        binding_revision=binding_revision,
        live_funding=_funding(binding),
        sampled_tip_height=candidate.tip_height,
        sampled_confirmations=candidate.chain_only_confirmations,
        fee_sat=fee_sat,
        auxiliary_random=auxiliary_random,
        crypto=crypto,
    )
    _require(len(raw) <= MAX_CLAIM_BYTES, "claim transaction exceeds resource limit")
    plan = _ClaimPlan(
        kind="rillswap-opaque-claim-plan/v1",
        network_identity=expected_network,
        contract_hash=binding.contract_hash,
        recovery_plaintext_sha256=hashlib.sha256(recovery_plaintext).hexdigest(),
        funding_attempt_id=binding.funding_attempt_id,
        binding_revision=binding.binding_revision,
        signed_claim_hex=raw.hex(),
    )
    plaintext = canonicalize(plan.model_dump(mode="json"))
    receipt = _verify_plan(
        plaintext,
        recovery_plaintext,
        expected_network,
        funding_attempt_id=funding_attempt_id,
        binding_revision=binding_revision,
        crypto=crypto,
    )
    ciphertext = cast("bytes", pyrage.encrypt(plaintext, [recipient]))
    validate_age_profile(ciphertext, "X25519")
    _require(
        cast("bytes", pyrage.decrypt(ciphertext, [identity])) == plaintext,
        "claim plan encryption round trip failed",
    )
    verified = verify_encrypted_claim_plan(
        ciphertext,
        recovery_ciphertext,
        expected_network,
        credentials=credentials,
        funding_attempt_id=funding_attempt_id,
        binding_revision=binding_revision,
        crypto=crypto,
    )
    _require(verified == receipt, "encrypted claim plan readback differs")
    return EncryptedClaimPlan(ciphertext, receipt)
