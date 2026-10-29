"""Deterministic, offer-bound Bitcoin network-fee pricing.

The charge is an estimate, not proof of the provider's transaction or routing
cost. Hosts obtain an independent feerate ceiling before building a request.
"""

from __future__ import annotations

from typing import Final, Literal

from pydantic import Field, model_validator

from rill_core.wire.canonical import JsonValue, canonicalize
from rill_core.wire.hashes import tagged_hash
from rill_core.wire.types import (
    ExactInteger,
    Hex32,
    StrictModel,
    validate_decimal_sats,
    validate_signed_sats,
)

FEE_POLICY_EXTENSION = "org.rillswap/fee-policy-v1"
FEE_MODEL: Final = "p2tr-cooperative-1in-2out/v1"
# 137 stripped bytes, marker/flag plus a 64-byte default-sighash witness:
# ceil((137 * 4 + 68) / 4) = 154 vbytes.
NETWORK_FEE_VBYTES = 154
QUOTE_LIFETIME_SECONDS = 60
MAX_ESTIMATE_AGE_SECONDS = 10
MAX_CLOCK_SKEW_SECONDS = 5
MILLION = 1_000_000


class BtcFeePolicy(StrictModel):
    """Immutable pricing coefficients committed by a signed announcement."""

    model: Literal["p2tr-cooperative-1in-2out/v1"]
    base_sat: str
    proportional_millionths: int = Field(strict=True, ge=0, le=MILLION)
    max_network_feerate_sat_kvb: str
    max_routing_fee_ppm: int = Field(strict=True, ge=0, le=MILLION)

    @model_validator(mode="after")
    def validate_amounts(self) -> BtcFeePolicy:
        """Require canonical, bounded monetary and integer feerate values."""
        validate_decimal_sats(self.base_sat, field="base_sat")
        validate_decimal_sats(
            self.max_network_feerate_sat_kvb,
            field="max_network_feerate_sat_kvb",
            positive=True,
        )
        return self

    def service_fee(self, principal_sat: int) -> int:
        """Keep the existing base-plus-proportional rounding rule."""
        return int(self.base_sat) + -(-principal_sat * self.proportional_millionths // MILLION)

    def commitment(self) -> str:
        """Bind every policy coefficient with domain-separated canonical bytes."""
        return tagged_hash(
            "RillSwap/fee-policy/v1", canonicalize(self.model_dump(mode="json"))
        ).hex()


class FeePolicyRequest(StrictModel):
    """Bind a request to the selected offer and an independently chosen ceiling."""

    offer_event_id: Hex32
    policy_hash: Hex32
    max_network_feerate_sat_kvb: str

    @model_validator(mode="after")
    def validate_rate(self) -> FeePolicyRequest:
        """Require a positive canonical integer feerate ceiling."""
        validate_decimal_sats(
            self.max_network_feerate_sat_kvb,
            field="max_network_feerate_sat_kvb",
            positive=True,
        )
        return self


class FeeBreakdown(StrictModel):
    """Signed estimate, with no provider-controlled size or fee multiplier."""

    offer_event_id: Hex32
    policy: BtcFeePolicy
    feerate_sat_kvb: str
    estimated_at: ExactInteger
    issued_at: ExactInteger
    service_fee_sat: str
    network_fee_sat: str

    @model_validator(mode="after")
    def validate_estimate(self) -> FeeBreakdown:
        """Validate independently recomputable network pricing and freshness."""
        rate = validate_decimal_sats(self.feerate_sat_kvb, field="feerate_sat_kvb", positive=True)
        validate_signed_sats(self.service_fee_sat, field="service_fee_sat")
        network_fee = validate_decimal_sats(self.network_fee_sat, field="network_fee_sat")
        if rate > int(self.policy.max_network_feerate_sat_kvb):
            raise ValueError("network feerate exceeds the advertised maximum")
        if network_fee != -(-NETWORK_FEE_VBYTES * rate // 1000):
            raise ValueError("network fee differs from the fixed transaction-size model")
        if not 0 <= self.issued_at - self.estimated_at <= MAX_ESTIMATE_AGE_SECONDS:
            raise ValueError("network fee estimate is stale or from the future")
        return self


def parse_fee_policy(extensions: dict[str, JsonValue]) -> BtcFeePolicy | None:
    """Read the known announcement extension, rejecting malformed policies."""
    if FEE_POLICY_EXTENSION not in extensions:
        return None
    return BtcFeePolicy.model_validate(extensions[FEE_POLICY_EXTENSION])


def parse_fee_request(extensions: dict[str, JsonValue]) -> FeePolicyRequest | None:
    """Read a quote request's optional policy commitment."""
    if FEE_POLICY_EXTENSION not in extensions:
        return None
    return FeePolicyRequest.model_validate(extensions[FEE_POLICY_EXTENSION])


def check_fee_breakdown(  # noqa: PLR0913 - explicit signed economics and contextual request
    extensions: dict[str, JsonValue],
    *,
    required: bool,
    principal_sat: int,
    success_fee_sat: int,
    expires_at: int,
    request_extensions: dict[str, JsonValue] | None = None,
    now: int | None = None,
) -> FeeBreakdown | None:
    """Validate economics, then optionally bind them to the original request.

    Historical/recovery validation deliberately needs neither a current clock
    nor a fresh node estimate. The request already commits the independent cap.
    """
    value = extensions.get(FEE_POLICY_EXTENSION)
    if (FEE_POLICY_EXTENSION in extensions) != required:
        raise ValueError("fee policy must be required and include a signed breakdown")
    request = None if request_extensions is None else parse_fee_request(request_extensions)
    if not required:
        if request is not None:
            raise ValueError("provider omitted the requested fee policy")
        return None
    breakdown = FeeBreakdown.model_validate(value)
    # Balance-aware providers may discount, even below zero, never surcharge.
    if int(breakdown.service_fee_sat) > breakdown.policy.service_fee(principal_sat):
        raise ValueError("service fee exceeds the advertised policy")
    if int(breakdown.service_fee_sat) + int(breakdown.network_fee_sat) != success_fee_sat:
        raise ValueError("fee breakdown does not sum to the success fee")
    if not 0 < expires_at - breakdown.issued_at <= QUOTE_LIFETIME_SECONDS:
        raise ValueError("fee quote acceptance lifetime exceeds 60 seconds")
    if now is not None and (
        breakdown.issued_at > now + MAX_CLOCK_SKEW_SECONDS or now >= expires_at
    ):
        raise ValueError("fee quote is expired or issued in the future")
    if request_extensions is not None:
        if request is None:
            raise ValueError("fee policy was not requested")
        if breakdown.offer_event_id != request.offer_event_id:
            raise ValueError("fee quote references a different announcement")
        if breakdown.policy.commitment() != request.policy_hash:
            raise ValueError("fee quote changed the advertised pricing policy")
        if int(breakdown.feerate_sat_kvb) > int(request.max_network_feerate_sat_kvb):
            raise ValueError("network feerate exceeds the client's independent ceiling")
    return breakdown
