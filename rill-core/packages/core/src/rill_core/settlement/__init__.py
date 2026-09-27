"""Deterministic Bitcoin settlement construction and verification."""

from rill_core.settlement.funding import (
    FundingBindingTransactionMatch,
    FundingPlan,
    FundingPlanAuthorization,
    FundingPrevout,
    PlannedFundingOutput,
    authorize_funding_transaction,
    check_funding_binding_transaction,
)
from rill_core.settlement.funding_authentication import (
    FundingDeclarationCrypto,
    SignedFundingBinding,
    verify_static_signed_funding_binding_history,
)
from rill_core.settlement.taproot import (
    TaprootContract,
    TaprootKeyOperations,
    reconstruct_taproot_contract,
)
from rill_core.settlement.unilateral import (
    CooperativeClaimPlan,
    FundingOutput,
    SchnorrVerifier,
    UnilateralAuthorization,
    UnilateralPath,
    UnilateralSpendPlan,
    ValidatedCooperativeClaim,
    ValidatedUnilateralSpend,
    build_cooperative_claim,
    build_unilateral_spend,
    finalize_cooperative_claim,
    finalize_unilateral_spend,
    max_spendable_fee,
    validate_cooperative_claim,
    validate_unilateral_spend,
)

__all__ = [
    "CooperativeClaimPlan",
    "FundingBindingTransactionMatch",
    "FundingDeclarationCrypto",
    "FundingOutput",
    "FundingPlan",
    "FundingPlanAuthorization",
    "FundingPrevout",
    "PlannedFundingOutput",
    "SchnorrVerifier",
    "SignedFundingBinding",
    "TaprootContract",
    "TaprootKeyOperations",
    "UnilateralAuthorization",
    "UnilateralPath",
    "UnilateralSpendPlan",
    "ValidatedCooperativeClaim",
    "ValidatedUnilateralSpend",
    "authorize_funding_transaction",
    "build_cooperative_claim",
    "build_unilateral_spend",
    "check_funding_binding_transaction",
    "finalize_cooperative_claim",
    "finalize_unilateral_spend",
    "max_spendable_fee",
    "reconstruct_taproot_contract",
    "validate_cooperative_claim",
    "validate_unilateral_spend",
    "verify_static_signed_funding_binding_history",
]
