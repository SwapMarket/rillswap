"""Strict Pydantic boundary types shared by version-one wire objects."""

from __future__ import annotations

import re
from typing import Annotated, Literal

from pydantic import (
    AfterValidator,
    BaseModel,
    ConfigDict,
    Field,
    StringConstraints,
    model_validator,
)

from rill_core.domain.amounts import MAX_MILLISATS, MAX_SATS, parse_canonical_decimal
from rill_core.errors import ValidationError
from rill_core.wire.canonical import JsonValue  # noqa: TC001

SECP256K1_FIELD_PRIME = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
MAX_EXTENSIONS = 32
MAX_FEATURES = 64
P2WPKH_SCRIPT_HEX_LENGTH = 44
P2TR_SCRIPT_HEX_LENGTH = 68


def _require_curve_x(value: str) -> str:
    x_coordinate = int(value, 16)
    if x_coordinate >= SECP256K1_FIELD_PRIME:
        raise ValueError("public key x-coordinate is outside the secp256k1 field")
    curve_y_squared = (pow(x_coordinate, 3, SECP256K1_FIELD_PRIME) + 7) % SECP256K1_FIELD_PRIME
    if pow(curve_y_squared, (SECP256K1_FIELD_PRIME - 1) // 2, SECP256K1_FIELD_PRIME) != 1:
        raise ValueError("public key x-coordinate is not on secp256k1")
    return value


def _require_compressed_curve_key(value: str) -> str:
    _require_curve_x(value[2:])
    return value


type Hex32 = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{64}$")]
type XOnlyKey = Annotated[Hex32, AfterValidator(_require_curve_x)]
type CompressedKey = Annotated[
    str,
    StringConstraints(pattern=r"^(02|03)[0-9a-f]{64}$"),
    AfterValidator(_require_compressed_curve_key),
]
type Signature64 = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{128}$")]
type ScriptHex = Annotated[
    str,
    StringConstraints(pattern=r"^([0-9a-f]{2}){1,10000}$"),
]
type Identifier = Annotated[
    str,
    StringConstraints(pattern=r"^[a-z0-9][a-z0-9._/-]{0,127}$"),
]
type ExactInteger = Annotated[int, Field(strict=True, ge=0, le=9_007_199_254_740_991)]
type PositiveCount = Annotated[int, Field(strict=True, ge=1, le=9_007_199_254_740_991)]
type ProfileId = Literal["btc-to-ln/v1", "ln-to-btc/v1"]
type Party = Literal["client", "provider"]

_EXTENSION_KEY = re.compile(r"^[a-z0-9][a-z0-9.-]{0,62}/[a-z0-9][a-z0-9._-]{0,62}$")


class StrictModel(BaseModel):
    """Base for frozen strict external values with unknown fields forbidden."""

    model_config = ConfigDict(frozen=True, strict=True, extra="forbid")


class NetworkIdentity(StrictModel):
    """Complete application-level Bitcoin network identity."""

    family: Literal["bitcoin"]
    name: Literal["mainnet", "signet", "regtest", "testnet3", "testnet4", "custom"]
    genesis_hash: Hex32
    signet_challenge: ScriptHex | None
    consensus_profile: Identifier
    deployment_namespace: Identifier | None

    @model_validator(mode="after")
    def validate_network_specific_fields(self) -> NetworkIdentity:
        """Reject label-only identities and invalid signet/regtest separation."""
        if self.name == "signet" and self.signet_challenge is None:
            raise ValueError("signet identity requires its exact challenge")
        if self.name == "regtest" and self.deployment_namespace is None:
            raise ValueError("regtest identity requires a deployment namespace")
        if self.name in {"mainnet", "testnet3", "testnet4"} and (
            self.signet_challenge is not None or self.deployment_namespace is not None
        ):
            raise ValueError("public non-signet identity cannot carry test separation fields")
        if self.name == "regtest" and self.signet_challenge is not None:
            raise ValueError("regtest identity cannot carry a signet challenge")
        return self


class Extensions(StrictModel):
    """Bounded namespaced optional extension container."""

    values: dict[str, JsonValue] = Field(default_factory=dict)

    @model_validator(mode="after")
    def validate_keys(self) -> Extensions:
        """Require bounded namespaced keys without interpreting extension values."""
        if len(self.values) > MAX_EXTENSIONS:
            raise ValueError("too many extension entries")
        if any(_EXTENSION_KEY.fullmatch(key) is None for key in self.values):
            raise ValueError("extension key is not a valid namespace/name")
        return self


def validate_decimal_sats(value: str, *, field: str, positive: bool = False) -> int:
    """Validate a canonical satoshi wire string and return its integer value."""
    parsed = parse_canonical_decimal(value, field=field, maximum=MAX_SATS)
    if positive and parsed == 0:
        raise ValidationError(f"{field} must be positive")
    return parsed


def validate_decimal_msats(value: str, *, field: str, positive: bool = False) -> int:
    """Validate a canonical millisatoshi wire string and return its integer value."""
    parsed = parse_canonical_decimal(value, field=field, maximum=MAX_MILLISATS)
    if positive and parsed == 0:
        raise ValidationError(f"{field} must be positive")
    return parsed


def require_sorted_unique(values: tuple[str, ...], *, field: str) -> None:
    """Require stable canonical list order and uniqueness."""
    if tuple(sorted(set(values))) != values:
        raise ValueError(f"{field} must be sorted and unique")


def require_identifier_list(
    values: tuple[str, ...],
    *,
    field: str,
    require_nonempty: bool = False,
) -> None:
    """Require a bounded unique negotiation list while preserving preference order."""
    if require_nonempty and not values:
        raise ValueError(f"{field} must not be empty")
    if len(values) > MAX_FEATURES:
        raise ValueError(f"{field} has too many entries")
    if len(set(values)) != len(values):
        raise ValueError(f"{field} must contain unique entries")


def require_feature_list(
    values: tuple[str, ...],
    *,
    field: str,
    require_nonempty: bool = False,
) -> None:
    """Require a bounded canonical feature or capability list."""
    require_identifier_list(
        values,
        field=field,
        require_nonempty=require_nonempty,
    )
    require_sorted_unique(values, field=field)


def validate_extensions(values: dict[str, JsonValue]) -> None:
    """Validate an extension mapping without changing its wire shape."""
    Extensions(values=values)


def require_v1_destination_script(script: str, *, field: str) -> None:
    """Accept only native P2WPKH or P2TR destination scripts in version one."""
    is_p2wpkh = len(script) == P2WPKH_SCRIPT_HEX_LENGTH and script.startswith("0014")
    is_p2tr = len(script) == P2TR_SCRIPT_HEX_LENGTH and script.startswith("5120")
    if not (is_p2wpkh or is_p2tr):
        raise ValueError(f"{field} must be a version-one P2WPKH or P2TR script")


def require_p2tr_script(script: str, *, field: str) -> None:
    """Require an exact version-one 32-byte witness-program script."""
    if len(script) != P2TR_SCRIPT_HEX_LENGTH or not script.startswith("5120"):
        raise ValueError(f"{field} must be a P2TR script")
    _require_curve_x(script[4:])
