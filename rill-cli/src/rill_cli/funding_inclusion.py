"""Encrypted historical lookup hints, never execution or financial authority."""

from __future__ import annotations

from typing import TYPE_CHECKING, Annotated, Literal

import pyrage
from pydantic import Field, model_validator
from rill_core.networks import require_supported_network
from rill_core.wire.canonical import canonicalize, parse_model_json
from rill_core.wire.messages import FundingBinding  # noqa: TC002 - evaluated Pydantic field type
from rill_core.wire.types import Hex32, NetworkIdentity, StrictModel
from rill_provider.core_tx_bytes import MAX_HISTORICAL_BLOCK_HEIGHT

from rill_cli.age_container import MAX_CIPHERTEXT_BYTES, X25519Credentials, _identity
from rill_cli.conversion_journal import OperationId, _read_private
from rill_cli.publication import publish_new_ciphertext

if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path


type Height = Annotated[int, Field(strict=True, ge=1, le=MAX_HISTORICAL_BLOCK_HEIGHT)]


class LookupBlock(StrictModel):
    """An explicit historical coordinate, not a current chain assertion."""

    height: Height
    block_hash: Hex32


class FundingInclusionHint(StrictModel):
    """Local operator metadata requiring independent original-job correlation.

    Anyone knowing the public AGE recipient can encrypt data. Encryption and
    private-file controls do not authenticate its author or establish custody,
    remaining inventory, finality or permission to resume an SDK invocation.
    """

    version: Literal["conversion-funding-inclusion/regtest/v1"]
    operation_id: OperationId
    network: NetworkIdentity
    original_recovery_sha256: Hex32
    funding_binding: FundingBinding
    funding_block: LookupBlock
    sampled_tip: LookupBlock
    confirmations: Height

    @model_validator(mode="after")
    def historical_correspondence(self) -> FundingInclusionHint:
        """Reject unsupported identities and contradictory sampled coordinates."""
        require_supported_network(self.network)
        if self.network.name != "regtest" or (
            self.confirmations != self.sampled_tip.height - self.funding_block.height + 1
        ):
            raise ValueError("original regtest inclusion coordinates required")
        return self


def publish_funding_inclusion_hint(
    path: Path,
    hint: FundingInclusionHint,
    *,
    credentials: X25519Credentials,
    publication_allowed: Callable[[], None],
) -> FundingInclusionHint:
    """Create once, verify readback, check admission before link and afterward.

    Filesystem publication/cleanup can finish beyond a deadline or after SDK
    cancellation. A late/uncertain artifact remains historical and never permits
    subsequent signing or another capture attempt. No overwrite or repair exists.
    """
    identity, recipient = _identity(credentials)
    checked = FundingInclusionHint.model_validate(
        hint.model_dump(mode="python", warnings="error"), strict=True
    )
    document = canonicalize(checked.model_dump(mode="json", warnings="error"))
    verified = parse_model_json(FundingInclusionHint, document)
    publication_allowed()
    ciphertext = pyrage.encrypt(document, [recipient])

    def readback(stored: bytes) -> FundingInclusionHint:
        plaintext = pyrage.decrypt(stored, [identity])
        selected = parse_model_json(FundingInclusionHint, plaintext)
        if plaintext != document or selected != verified:
            raise ValueError("encrypted inclusion readback differs")
        publication_allowed()
        return selected

    result = publish_new_ciphertext(path, ciphertext, verify_from_disk=readback)
    publication_allowed()
    return result


def read_funding_inclusion_hint(  # noqa: PLR0913 - independent original-job and selected-binding correlation
    path: Path,
    *,
    credentials: X25519Credentials,
    operation_id: str,
    network: NetworkIdentity,
    original_recovery_sha256: str,
    binding: FundingBinding,
) -> FundingInclusionHint:
    """Explicit private read correlated to independently supplied original facts.

    Unknown, partial, incompatible or copied mismatching files never trigger
    discovery, migration, overwrite, repair or restored execution rights. A
    matching artifact remains historical input for fresh independent validation.
    """
    result = None
    try:
        identity, _recipient = _identity(credentials)
        plaintext = pyrage.decrypt(_read_private(path, MAX_CIPHERTEXT_BYTES), [identity])
        hint = parse_model_json(FundingInclusionHint, plaintext)
        if (
            hint.operation_id == operation_id
            and hint.network == network
            and hint.original_recovery_sha256 == original_recovery_sha256
            and hint.funding_binding == binding
        ):
            result = hint
    except Exception:  # noqa: BLE001 - detach identity, ciphertext, private paths and validation data
        result = None
    if result is None:
        raise ValueError("original funding inclusion hint unavailable")
    return result
