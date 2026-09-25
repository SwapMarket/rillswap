"""Experimental regtest-only claim disclosure, NOT first-disclosure safety.

Even testmempoolaccept gives the configured RPC endpoint the preimage. This
one-path, one-invocation boundary cannot establish global no-prior-disclosure,
Lightning state, fee viability, rollback fencing, or production authority.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import TYPE_CHECKING, Literal, cast

import httpx
import pyrage
from pydantic import Field
from rill_core.wire.canonical import canonicalize, parse_model_json
from rill_core.wire.types import Hex32, NetworkIdentity, StrictModel

from rill_cli.age_container import (
    MAX_CIPHERTEXT_BYTES,
    X25519Credentials,
    _bounded_plaintext,
    _identity,
    validate_age_profile,
)
from rill_cli.claim_plan import MAX_CLAIM_BYTES, load_verified_claim_bytes_for_regtest_disclosure
from rill_cli.publication import RecoveryPublicationUncertainError, publish_new_ciphertext
from rill_cli.recovery_core_observation import CONNECT_SECONDS, READ_SECONDS, _cookie

if TYPE_CHECKING:
    from rill_core.recovery.inspection import RecoveryRefundCrypto
    from rill_core.wire.messages import ContractTerms, FundingBinding

    from rill_cli.recovery_core_observation import RegtestRecoveryCoreReader


class ClaimDisclosureRefusedError(ValueError):
    """No witness-bearing RPC was attempted by this invocation."""


class ClaimDisclosureUnknownError(Exception):
    """Preimage may have reached Core; never automatically retry or infer settlement."""


class ClaimIntentUncertainError(Exception):
    """Encrypted intent may exist without confirmed durability; do not retry."""


class _DisclosureIntent(StrictModel):
    kind: Literal["rillswap-regtest-claim-disclosure-intent/v1"]
    disclosure_may_occur: Literal[True]
    network_identity: NetworkIdentity
    recovery_plaintext_sha256: Hex32
    plan_ciphertext_sha256: Hex32
    funding_attempt_id: Hex32
    binding_revision: int = Field(strict=True, ge=0)
    selected_funding_txid: Hex32
    selected_contract_vout: int = Field(strict=True, ge=0)
    signed_claim_txid: Hex32
    signed_claim_hex: str = Field(
        min_length=2,
        max_length=MAX_CLAIM_BYTES * 2,
        pattern=r"^(?:[0-9a-f]{2})+$",
    )


@dataclass(frozen=True, slots=True)
class ClaimDisclosureReceipt:
    """Public metadata only; node acceptance is not confirmation or LN settlement."""

    claim_txid: str
    sampled_tip_hash: str
    sampled_tip_height: int


def _check(condition: bool) -> None:  # noqa: FBT001 - local predicate
    if not condition:
        raise ClaimDisclosureRefusedError("experimental claim disclosure intent refused")


def _require_rpc_result(condition: bool) -> None:  # noqa: FBT001 - local predicate
    if not condition:
        raise ClaimDisclosureUnknownError("experimental claim RPC result unknown")


def _verify_intent(
    stored: bytes,
    plaintext: bytes,
    *,
    credentials: X25519Credentials,
    expected: _DisclosureIntent,
) -> None:
    decoded = _bounded_plaintext(stored, credentials)
    _check(decoded == plaintext)
    parsed = parse_model_json(_DisclosureIntent, decoded)
    _check(parsed == expected and canonicalize(parsed.model_dump(mode="json")) == decoded)


def disclose_claim_on_regtest(  # noqa: PLR0913 - exact external and signed inputs explicit
    reader: RegtestRecoveryCoreReader,
    binding: FundingBinding,
    terms: ContractTerms,
    *,
    keys: RecoveryRefundCrypto,
    recovery_ciphertext: bytes,
    plan_ciphertext: bytes,
    network: NetworkIdentity,
    credentials: X25519Credentials,
    funding_attempt_id: str,
    binding_revision: int,
    intent_path: str,
) -> ClaimDisclosureReceipt:
    """Explicit experimental one-shot; sanitize all secret-bearing helper failures."""
    result: ClaimDisclosureReceipt | None = None
    uncertain_intent = False
    disclosure_unknown = False
    try:
        result = _disclose(
            reader,
            binding,
            terms,
            keys=keys,
            recovery_ciphertext=recovery_ciphertext,
            plan_ciphertext=plan_ciphertext,
            network=network,
            credentials=credentials,
            funding_attempt_id=funding_attempt_id,
            binding_revision=binding_revision,
            intent_path=intent_path,
        )
    except RecoveryPublicationUncertainError:
        uncertain_intent = True
    except ClaimDisclosureUnknownError:
        disclosure_unknown = True
    except KeyboardInterrupt:
        # Also conservatively classify an interruption during the encrypted
        # publication or either RPC. The previous result may be unknowable.
        disclosure_unknown = True
    except Exception:  # noqa: BLE001, S110 - never retain upstream raw witness errors
        pass
    if uncertain_intent:
        raise ClaimIntentUncertainError("encrypted claim intent publication uncertain")
    if disclosure_unknown:
        raise ClaimDisclosureUnknownError(
            "experimental claim preimage disclosure may have occurred"
        )
    if result is None:
        raise ClaimDisclosureRefusedError("experimental claim disclosure refused before RPC")
    return result


def _disclose(  # noqa: PLR0913 - one explicit side-effect sequence
    reader: RegtestRecoveryCoreReader,
    binding: FundingBinding,
    terms: ContractTerms,
    *,
    keys: RecoveryRefundCrypto,
    recovery_ciphertext: bytes,
    plan_ciphertext: bytes,
    network: NetworkIdentity,
    credentials: X25519Credentials,
    funding_attempt_id: str,
    binding_revision: int,
    intent_path: str,
) -> ClaimDisclosureReceipt:
    _check(
        network.name == "regtest"
        and terms.profile_id == "ln-to-btc/v1"
        and terms.claimant == "client"
        and type(credentials) is X25519Credentials
        and type(plan_ciphertext) is bytes
        and 0 < len(plan_ciphertext) <= MAX_CIPHERTEXT_BYTES
        # The selected binding must be the one the selectors name, on this network.
        and binding.funding_attempt_id == funding_attempt_id
        and binding.binding_revision == binding_revision
        and terms.network_identity == network
    )
    raw, receipt = load_verified_claim_bytes_for_regtest_disclosure(
        plan_ciphertext,
        recovery_ciphertext,
        network,
        credentials=credentials,
        funding_attempt_id=funding_attempt_id,
        binding_revision=binding_revision,
        crypto=keys,
    )
    _check(
        receipt.funding_txid == binding.funding_txid
        and receipt.contract_vout == binding.contract_vout
    )
    reader.observe_claim(binding, terms, keys=keys)
    recovery_plaintext = _bounded_plaintext(recovery_ciphertext, credentials)
    _, recipient = _identity(credentials)
    intent = _DisclosureIntent(
        kind="rillswap-regtest-claim-disclosure-intent/v1",
        disclosure_may_occur=True,
        network_identity=network,
        recovery_plaintext_sha256=hashlib.sha256(recovery_plaintext).hexdigest(),
        plan_ciphertext_sha256=hashlib.sha256(plan_ciphertext).hexdigest(),
        funding_attempt_id=funding_attempt_id,
        binding_revision=binding_revision,
        selected_funding_txid=binding.funding_txid,
        selected_contract_vout=binding.contract_vout,
        signed_claim_txid=receipt.claim_txid,
        signed_claim_hex=raw.hex(),
    )
    plaintext = canonicalize(intent.model_dump(mode="json"))
    ciphertext = cast("bytes", pyrage.encrypt(plaintext, [recipient]))
    validate_age_profile(ciphertext, "X25519")
    _verify_intent(ciphertext, plaintext, credentials=credentials, expected=intent)
    publish_new_ciphertext(
        intent_path,
        ciphertext,
        verify_from_disk=lambda stored: _verify_intent(
            stored,
            plaintext,
            credentials=credentials,
            expected=intent,
        ),
    )
    # No RPC receives witness bytes until the exact intent is durably installed.
    candidate = reader.observe_claim(binding, terms, keys=keys)
    username, password = _cookie(reader._cookie_path)  # noqa: SLF001 - CLI-local RPC boundary
    client = httpx.Client(
        base_url=reader._url,  # noqa: SLF001 - explicit numeric loopback endpoint
        auth=httpx.BasicAuth(username, password),
        trust_env=False,
        follow_redirects=False,
        timeout=httpx.Timeout(READ_SECONDS, connect=CONNECT_SECONDS),
    )
    try:
        with client:
            # This call itself may disclose the preimage to the configured node.
            preflight = reader._rpc(  # noqa: SLF001 - exact RPC, may disclose
                client,
                "testmempoolaccept",
                [[raw.hex()]],
                9,
                submission=True,
            )
            _require_rpc_result(
                not (
                    type(preflight) is not list
                    or len(preflight) != 1
                    or type(preflight[0]) is not dict
                    or preflight[0].get("allowed") is not True
                    or preflight[0].get("txid") != receipt.claim_txid
                )
            )
            returned = reader._rpc(  # noqa: SLF001 - one send of exact intended bytes
                client,
                "sendrawtransaction",
                [raw.hex()],
                10,
                submission=True,
            )
            _require_rpc_result(returned == receipt.claim_txid)
    except (Exception, KeyboardInterrupt):  # noqa: BLE001, S110 - sanitize operator interruption
        pass
    else:
        return ClaimDisclosureReceipt(receipt.claim_txid, candidate.tip_hash, candidate.tip_height)
    raise ClaimDisclosureUnknownError("claim preflight or submission result unknown")
