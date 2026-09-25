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
    FundingOutput,
    SchnorrVerifier,
    UnilateralAuthorization,
    UnilateralPath,
    UnilateralSpendPlan,
    ValidatedUnilateralSpend,
    build_unilateral_spend,
    finalize_unilateral_spend,
    validate_unilateral_spend,
)

__all__ = [
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
    "ValidatedUnilateralSpend",
    "authorize_funding_transaction",
    "build_unilateral_spend",
    "check_funding_binding_transaction",
    "finalize_unilateral_spend",
    "reconstruct_taproot_contract",
    "validate_unilateral_spend",
    "verify_static_signed_funding_binding_history",
]
