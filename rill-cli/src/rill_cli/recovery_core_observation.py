"""Explicit local Core observation of one selected recovery binding.

This is not chain reconciliation, a spendable funding proof, or permission to
sign. The operator asserts complete deployment identity. Core attests only
its chain label, genesis, and signet challenge (on signet), not the configured
namespace or policy profile.
"""

from __future__ import annotations

import json
import os
import stat
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import TYPE_CHECKING, Any, Literal

import httpx
from rill_core.errors import ValidationError
from rill_core.networks import backend_names
from rill_core.settlement import FundingBindingTransactionMatch, check_funding_binding_transaction
from rill_core.wire.messages import FundingBinding

if TYPE_CHECKING:
    from rill_core.settlement import TaprootKeyOperations
    from rill_core.wire.messages import ContractTerms
    from rill_core.wire.types import NetworkIdentity

MAX_COOKIE_BYTES = 512
MAX_RESPONSE_BYTES = 256 * 1024
MAX_TRANSACTION_HEX_BYTES = 200_000
MAX_PORT = 65535
MAX_SATS = 21_000_000 * 100_000_000
SATS_PER_BTC = Decimal(100_000_000)
HASH_HEX_LENGTH = 64
HTTP_OK = 200
READ_SECONDS = 5.0
CONNECT_SECONDS = 2.0


@dataclass(frozen=True, slots=True)
class RecoveryOutpointCandidate:
    """Staleable chain-only sample, never lineage or financial authority."""

    network_identity: NetworkIdentity
    static_match: FundingBindingTransactionMatch
    tip_hash: str
    tip_height: int
    transaction_lookup_block_hash: str
    sampled_inclusion_height: int
    chain_only_confirmations: int
    refund_first_eligible_height: int


class RecoveryCoreReadError(Exception):
    """Selected-chain evidence was not established; no absence claim."""


class RecoveryCoreUnavailableError(RecoveryCoreReadError):
    """Node, transaction, or tip unavailable; not proof of no funding."""


class RecoveryCoreProtocolError(RecoveryCoreReadError):
    """Node evidence was malformed or inconsistent with selected record."""


def _hash(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == HASH_HEX_LENGTH
        and all(char in "0123456789abcdef" for char in value)
    )


def _pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for name, value in items:
        if name in result:
            raise ValueError("duplicate RPC result key")
        result[name] = value
    return result


def _require_cookie(condition: bool) -> None:  # noqa: FBT001 - internal predicate
    if not condition:
        raise ValueError("unsupported private Core cookie")


def _cookie(path: Path) -> tuple[str, str]:
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, "rb", closefd=True) as stream:
            info = os.fstat(stream.fileno())
            _require_cookie(stat.S_ISREG(info.st_mode) and not info.st_mode & 0o077)
            value = stream.read(MAX_COOKIE_BYTES + 1)
        _require_cookie(bool(value) and len(value) <= MAX_COOKIE_BYTES)
        text = value.removesuffix(b"\n").decode("ascii")
        username, password = text.split(":", 1)
        _require_cookie(
            username == "__cookie__"
            and bool(password)
            and not any(char in text for char in "\r\n\x00")
        )
    except (OSError, ValueError, UnicodeError):
        pass
    else:
        return username, password
    raise RecoveryCoreUnavailableError("private Core RPC cookie unavailable")


def _tip(value: object, chain: str) -> tuple[str, int]:
    if (
        not isinstance(value, dict)
        or value.get("chain") != chain
        or not _hash(value.get("bestblockhash"))
        or type(value.get("blocks")) is not int
        or value["blocks"] < 0
        or value.get("initialblockdownload") is not False
    ):
        raise RecoveryCoreProtocolError("Core has no usable named tip on the configured chain")
    return value["bestblockhash"], value["blocks"]


def _matches_signet_challenge(info: object, network: NetworkIdentity) -> bool:
    """Require Core's exact consensus script, not the shared signet genesis alone."""
    return network.name != "signet" or (
        isinstance(info, dict)
        and type(info.get("signet_challenge")) is str
        and info["signet_challenge"] == network.signet_challenge
    )


def _exact_sats(value: object, expected: int) -> bool:
    if (
        isinstance(value, bool)
        or not isinstance(value, (Decimal, int))
        or not 0 <= expected <= MAX_SATS
        or not Decimal(value).is_finite()
    ):
        return False
    whole, fractional = divmod(expected, int(SATS_PER_BTC))
    return value == Decimal(f"{whole}.{fractional:08d}")


def _outpoint(value: object, binding: FundingBinding, height: int) -> tuple[str, int]:
    if value is None:
        raise RecoveryCoreUnavailableError("selected outpoint unavailable; no absence proof")
    count = value.get("confirmations") if isinstance(value, dict) else None
    if (
        not isinstance(value, dict)
        or type(count) is not int
        or not 1 <= count <= height
        or not _hash(value.get("bestblock"))
        or value.get("coinbase") is not False
        or not isinstance(value.get("scriptPubKey"), dict)
        or value["scriptPubKey"].get("hex") != binding.contract_script_pubkey
        or not _exact_sats(value.get("value"), int(binding.contract_value_sat))
    ):
        raise RecoveryCoreProtocolError("selected Core outpoint differs from signed binding")
    return value["bestblock"], count


def _raw_bytes(value: object) -> bytes:
    if (
        not isinstance(value, str)
        or len(value) > MAX_TRANSACTION_HEX_BYTES
        or len(value) % 2
        or any(char not in "0123456789abcdef" for char in value)
    ):
        raise RecoveryCoreProtocolError("Core transaction bytes are not bounded lowercase hex")
    return bytes.fromhex(value)


class RecoveryCoreReader:
    """Read-only numeric-loopback RPC client, no wallet or background actions."""

    def __init__(
        self, *, port: int, cookie_path: Path, network: NetworkIdentity, host: str = "127.0.0.1"
    ) -> None:
        """Store one operator-selected loopback endpoint, without connecting."""
        if host not in ("127.0.0.1", "::1") or type(port) is not int or not 1 <= port <= MAX_PORT:
            raise ValueError("Core RPC needs numeric loopback host and valid port")
        try:
            # Observation and refunds recover funds, so no release gate applies.
            self._chain = backend_names(network).core_chain
        except ValidationError:
            raise ValueError("only a supported complete network identity is accepted") from None
        self._url = f"http://[{host}]:{port}/" if host == "::1" else f"http://{host}:{port}/"
        self._cookie_path = Path(cookie_path)
        self._network = network

    def observe(
        self,
        binding: FundingBinding,
        terms: ContractTerms,
        *,
        keys: TaprootKeyOperations,
        for_refund: bool = False,
    ) -> RecoveryOutpointCandidate:
        """Sample one exact selected binding; a successful result is staleable.

        RPC read timeouts are inactivity limits, not a total deadline against a
        trickling configured listener. Do not use this for settlement deadlines.
        """
        if type(for_refund) is not bool:
            raise RecoveryCoreProtocolError("invalid recovery observation mode")
        return self._sample(
            binding, terms, keys=keys, purpose="refund" if for_refund else "candidate"
        )

    def observe_claim(
        self,
        binding: FundingBinding,
        terms: ContractTerms,
        *,
        keys: TaprootKeyOperations,
    ) -> RecoveryOutpointCandidate:
        """Sample LN-to-BTC client claim outpoint without signing or disclosing.

        The Core result is staleable and insufficient for a preimage release.
        """
        return self._sample(binding, terms, keys=keys, purpose="claim")

    def _sample(
        self,
        binding: FundingBinding,
        terms: ContractTerms,
        *,
        keys: TaprootKeyOperations,
        purpose: Literal["candidate", "refund", "claim"],
    ) -> RecoveryOutpointCandidate:
        category: type[RecoveryCoreReadError]
        try:
            result = self._observe(binding, terms, keys=keys, purpose=purpose)
        except RecoveryCoreUnavailableError:
            category = RecoveryCoreUnavailableError
        except Exception:  # noqa: BLE001 - native and transport details can retain credentials
            category = RecoveryCoreProtocolError
        else:
            return result
        # No caught exception (including an httpx request containing Basic
        # Auth) remains reachable from this public error's context or cause.
        raise category("selected Core evidence unavailable; no absence or authority proof")

    def _observe(
        self,
        binding: FundingBinding,
        terms: ContractTerms,
        *,
        keys: TaprootKeyOperations,
        purpose: Literal["candidate", "refund", "claim"],
    ) -> RecoveryOutpointCandidate:
        if (
            not isinstance(binding, FundingBinding)
            or terms.network_identity != self._network
            or purpose not in {"candidate", "refund", "claim"}
            or (
                purpose == "claim"
                and (
                    terms.profile_id != "ln-to-btc/v1"
                    or terms.claimant != "client"
                    or terms.timing_policy.kind != "ln-to-btc"
                )
            )
        ):
            raise RecoveryCoreProtocolError(
                "selected funding context differs from configured network"
            )
        username, password = _cookie(self._cookie_path)
        try:
            with httpx.Client(
                base_url=self._url,
                auth=httpx.BasicAuth(username, password),
                trust_env=False,
                follow_redirects=False,
                timeout=httpx.Timeout(READ_SECONDS, connect=CONNECT_SECONDS),
            ) as client:
                first_info = self._rpc(client, "getblockchaininfo", [], 1)
                tip_hash, height = _tip(first_info, self._chain)
                if not _matches_signet_challenge(first_info, self._network):
                    raise RecoveryCoreProtocolError(
                        "Core signet challenge differs from configuration"
                    )
                if self._rpc(client, "getblockhash", [0], 2) != self._network.genesis_hash:
                    raise RecoveryCoreProtocolError("Core genesis differs from configured network")
                output = self._rpc(
                    client, "gettxout", [binding.funding_txid, binding.contract_vout, False], 3
                )
                outpoint_tip, confirmations = _outpoint(output, binding, height)
                inclusion_height = height - confirmations + 1
                block_hash = self._rpc(client, "getblockhash", [inclusion_height], 4)
                if not _hash(block_hash) or (inclusion_height == height and block_hash != tip_hash):
                    raise RecoveryCoreProtocolError("Core inclusion block differs from tip")
                raw = _raw_bytes(
                    self._rpc(
                        client,
                        "getrawtransaction",
                        [
                            binding.funding_txid,
                            False,
                            block_hash,
                        ],
                        5,
                    )
                )
                try:
                    match = check_funding_binding_transaction(raw, binding, terms, keys=keys)
                except Exception:  # noqa: BLE001 - no native/transaction diagnostics escape
                    raise RecoveryCoreProtocolError("selected transaction bytes differ") from None
                if purpose != "candidate":
                    if purpose == "refund" and height <= terms.refund_lock_height:
                        raise RecoveryCoreUnavailableError("refund height not yet sampled")
                    if purpose == "claim" and (
                        confirmations < terms.funding_confirmations
                        or height + terms.timing_policy.claim_confirmation_blocks
                        >= terms.refund_lock_height + 1
                    ):
                        raise RecoveryCoreUnavailableError("claim window not established")
                    # Mempool-aware gettxout excludes a confirmed output spent
                    # by a known unconfirmed transaction; this is a sample, not
                    # a future-unspent guarantee.
                    mempool_out = self._rpc(
                        client,
                        "gettxout",
                        [
                            binding.funding_txid,
                            binding.contract_vout,
                            True,
                        ],
                        8,
                    )
                    mempool_tip, mempool_confirms = _outpoint(mempool_out, binding, height)
                    if mempool_tip != tip_hash or mempool_confirms != confirmations:
                        raise RecoveryCoreUnavailableError("mempool-aware outpoint sample changed")
                last_info = self._rpc(client, "getblockchaininfo", [], 6)
                last_hash, last_height = _tip(last_info, self._chain)
                if not _matches_signet_challenge(last_info, self._network):
                    raise RecoveryCoreProtocolError(
                        "Core signet challenge differs from configuration"
                    )
                # Resample the lookup height to reject observable inconsistency.
                # Matching samples prove neither ancestry to the named tip nor
                # an atomic snapshot under repeated rapid reorganization.
                final_block = self._rpc(client, "getblockhash", [inclusion_height], 7)
        except httpx.HTTPError:
            raise RecoveryCoreUnavailableError("Core RPC transport unavailable") from None
        if (
            tip_hash != last_hash
            or height != last_height
            or outpoint_tip != tip_hash
            or final_block != block_hash
        ):
            raise RecoveryCoreUnavailableError("Core tip changed; no current outpoint proof")
        return RecoveryOutpointCandidate(
            self._network,
            match,
            tip_hash,
            height,
            block_hash,
            inclusion_height,
            confirmations,
            terms.refund_lock_height + 1,
        )

    def _rpc(
        self,
        client: httpx.Client,
        method: str,
        params: list[object],
        request_id: int,
        *,
        submission: bool = False,
    ) -> Any:  # noqa: ANN401
        permitted = (
            {"testmempoolaccept", "sendrawtransaction"}
            if submission
            else {"getblockchaininfo", "getblockhash", "gettxout", "getrawtransaction"}
        )
        if method not in permitted:
            raise RecoveryCoreProtocolError("unsupported read-only Core method")
        try:
            with client.stream(
                "POST",
                "/",
                headers={"Accept-Encoding": "identity"},
                json={"jsonrpc": "2.0", "id": request_id, "method": method, "params": params},
                timeout=httpx.Timeout(READ_SECONDS, connect=CONNECT_SECONDS),
            ) as response:
                if response.status_code in (401, 403):
                    raise RecoveryCoreUnavailableError("Core authentication rejected")
                if response.status_code != HTTP_OK:
                    raise RecoveryCoreUnavailableError(
                        "Core RPC result unavailable; no absence proof"
                    )
                if response.headers.get("content-encoding", "identity") != "identity":
                    raise RecoveryCoreProtocolError("compressed Core RPC response refused")
                chunks = bytearray()
                for part in response.iter_raw():
                    if len(chunks) + len(part) > MAX_RESPONSE_BYTES:
                        raise RecoveryCoreProtocolError("Core response exceeds resource limit")
                    chunks.extend(part)
            envelope = json.loads(
                chunks,
                object_pairs_hook=_pairs,
                parse_float=Decimal,
                parse_constant=lambda _value: (_ for _ in ()).throw(ValueError("non-JSON number")),
            )
        except (ValueError, UnicodeError, InvalidOperation):
            raise RecoveryCoreProtocolError("Core RPC response is not strict JSON") from None
        except httpx.HTTPError:
            raise RecoveryCoreUnavailableError("Core RPC transport unavailable") from None
        if (
            not isinstance(envelope, dict)
            or envelope.get("jsonrpc") != "2.0"
            or type(envelope.get("id")) is not int
            or envelope["id"] != request_id
            or ("result" in envelope) == ("error" in envelope)
        ):
            raise RecoveryCoreProtocolError("Core RPC response envelope inconsistent")
        if "error" in envelope:
            error = envelope["error"]
            if (
                not isinstance(error, dict)
                or type(error.get("code")) is not int
                or not isinstance(error.get("message"), str)
            ):
                raise RecoveryCoreProtocolError("malformed Core RPC error envelope")
            raise RecoveryCoreUnavailableError("Core RPC result unavailable; no absence proof")
        return envelope["result"]
