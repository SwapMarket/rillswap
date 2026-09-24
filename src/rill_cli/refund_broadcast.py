"""One explicit regtest refund submission after durable exact-byte intent.

No automatic retry, replacement, watcher, complete reconciliation, or
settlement completion claim. A response lost after submission is UNKNOWN.
"""

from __future__ import annotations

import hashlib
from typing import TYPE_CHECKING

import httpx
from rill_core.wire.canonical import JsonValue, canonicalize, parse_json_strict

from rill_cli.recovery_core_observation import (
    CONNECT_SECONDS,
    READ_SECONDS,
    RecoveryOutpointCandidate,
    _cookie,
)
from rill_cli.refund_publication import MAX_INTENT_BYTES

if TYPE_CHECKING:
    from rill_core.settlement import TaprootKeyOperations
    from rill_core.wire.messages import ContractTerms, FundingBinding

    from rill_cli.recovery_core_observation import RegtestRecoveryCoreReader

MAX_TRANSACTION_BYTES = 6_000
TXID_LENGTH = 64


class RefundPreflightError(ValueError):
    """No submission was attempted by this invocation."""


class RefundSubmissionUnknownError(Exception):
    """Submission may have happened; never auto-retry."""


def create_refund_intent(  # noqa: PLR0913 - authenticated inputs must remain explicit
    raw: bytes,
    *,
    txid: str,
    binding: FundingBinding,
    terms: ContractTerms,
    fee_sat: int,
    candidate: RecoveryOutpointCandidate,
) -> bytes:
    """Build canonical public exact-byte intent before any submission RPC."""
    if (
        type(raw) is not bytes
        or not 0 < len(raw) <= MAX_TRANSACTION_BYTES
        or type(txid) is not str
        or len(txid) != TXID_LENGTH
        or any(char not in "0123456789abcdef" for char in txid)
        or type(fee_sat) is not int
        or fee_sat < 0
        or terms.profile_id != "btc-to-ln/v1"
        or terms.refund_party != "client"
        or candidate.network_identity != terms.network_identity
        or candidate.static_match.funding_txid != binding.funding_txid
        or candidate.static_match.contract_vout != binding.contract_vout
        or candidate.tip_height <= terms.refund_lock_height
    ):
        raise RefundPreflightError("exact selected refund intent unavailable")
    intent: dict[str, JsonValue] = {
        "kind": "regtest-refund-submission-intent/v1",
        "state": "submission_may_occur",
        "network_identity": terms.network_identity.model_dump(mode="json"),
        "funding_attempt_id": binding.funding_attempt_id,
        "binding_revision": binding.binding_revision,
        "funding_txid": binding.funding_txid,
        "contract_vout": binding.contract_vout,
        "refund_txid": txid,
        "fee_sat": fee_sat,
        "signed_refund_hex": raw.hex(),
        "signed_refund_sha256": hashlib.sha256(raw).hexdigest(),
        "sampled_tip_hash": candidate.tip_hash,
        "sampled_tip_height": candidate.tip_height,
        "authority": "none (single selected outpoint, submission may be unknown)",
    }
    result = canonicalize(intent)
    if len(result) > MAX_INTENT_BYTES:
        raise RefundPreflightError("exact selected refund intent exceeds size limit")
    return result


def verify_refund_intent(stored: bytes, expected: bytes) -> bytes:
    """Verify byte-exact readback and hash; caller also verifies signed spend."""
    if type(stored) is not bytes or stored != expected or not 0 < len(stored) <= MAX_INTENT_BYTES:
        raise RefundPreflightError("durable refund intent differs from proposed send")
    parsed = parse_json_strict(stored, max_bytes=MAX_INTENT_BYTES)
    if not isinstance(parsed, dict) or canonicalize(parsed) != stored:
        raise RefundPreflightError("refund intent is not canonical")
    raw_hex = parsed.get("signed_refund_hex")
    if (
        not isinstance(raw_hex, str)
        or len(raw_hex) > 2 * MAX_TRANSACTION_BYTES
        or len(raw_hex) % 2
        or any(char not in "0123456789abcdef" for char in raw_hex)
    ):
        raise RefundPreflightError("refund intent transaction unavailable")
    raw = bytes.fromhex(raw_hex)
    if hashlib.sha256(raw).hexdigest() != parsed.get("signed_refund_sha256"):
        raise RefundPreflightError("refund intent byte digest differs")
    return raw


def _require_preflight(condition: bool) -> None:  # noqa: FBT001 - local predicate
    if not condition:
        raise RefundPreflightError("selected refund preflight refused")


def submit_prepared_refund(  # noqa: PLR0913 - exact read-only checks explicit
    reader: RegtestRecoveryCoreReader,
    binding: FundingBinding,
    terms: ContractTerms,
    *,
    keys: TaprootKeyOperations,
    raw: bytes,
    expected_txid: str,
) -> RecoveryOutpointCandidate:
    """Reobserve, preflight exact bytes, submit once; never infer confirmation."""
    send_started = False
    try:
        _require_preflight(
            type(raw) is bytes
            and 0 < len(raw) <= MAX_TRANSACTION_BYTES
            and type(expected_txid) is str
            and len(expected_txid) == TXID_LENGTH
            and all(char in "0123456789abcdef" for char in expected_txid)
        )
        candidate = reader.observe(binding, terms, keys=keys, for_refund=True)
        username, password = _cookie(reader._cookie_path)  # noqa: SLF001 - CLI-local RPC boundary
        client = httpx.Client(
            base_url=reader._url,  # noqa: SLF001 - same explicit numeric loopback endpoint
            auth=httpx.BasicAuth(username, password),
            trust_env=False,
            follow_redirects=False,
            timeout=httpx.Timeout(READ_SECONDS, connect=CONNECT_SECONDS),
        )
        with client:
            preflight = reader._rpc(  # noqa: SLF001 - exact allowed preflight
                client,
                "testmempoolaccept",
                [[raw.hex()]],
                9,
                submission=True,
            )
            _require_preflight(
                isinstance(preflight, list)
                and len(preflight) == 1
                and isinstance(preflight[0], dict)
                and preflight[0].get("allowed") is True
                and preflight[0].get("txid") == expected_txid
            )
            send_started = True
            returned = reader._rpc(  # noqa: SLF001 - the single mutating RPC
                client,
                "sendrawtransaction",
                [raw.hex()],
                10,
                submission=True,
            )
        if returned == expected_txid:
            return candidate
    except Exception:  # noqa: BLE001, S110 - only definitely pre-send failures are refused
        pass
    if send_started:
        raise RefundSubmissionUnknownError("refund submission result unknown")
    raise RefundPreflightError("refund preflight refused; no send attempted")
