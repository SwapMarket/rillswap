"""In-memory RS-001 funding-binding history and reversible chain observations.

Inputs at this boundary MUST have been independently authenticated and checked
against transaction bytes and a serialized, current chain view. This module
does not verify those facts, persist events, or authorize any external action.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, replace
from typing import TYPE_CHECKING

from rill_core.errors import TransitionError, ValidationError
from rill_core.settlement.taproot import TaprootKeyOperations, reconstruct_taproot_contract
from rill_core.wire.hashes import contract_hash
from rill_core.wire.messages import ContractTerms, FundingBinding

if TYPE_CHECKING:
    from rill_core.wire.types import NetworkIdentity

MAX_UINT32 = 0xFFFFFFFF
HEX32 = re.compile(r"[0-9a-f]{64}\Z")


def _require_hash(value: str, *, field: str) -> None:
    if not isinstance(value, str) or HEX32.fullmatch(value) is None:
        raise ValidationError(f"{field} must be lowercase 32-byte hex")


@dataclass(frozen=True, slots=True)
class BestChainObservation:
    """Caller-verified current best-chain view of an accepted funding output."""

    funding_txid: str
    contract_vout: int
    block_hash: str
    block_height: int
    tip_hash: str
    tip_height: int

    def __post_init__(self) -> None:
        for field, value in (
            ("funding_txid", self.funding_txid),
            ("block_hash", self.block_hash),
            ("tip_hash", self.tip_hash),
        ):
            _require_hash(value, field=field)
        if type(self.contract_vout) is not int or not 0 <= self.contract_vout <= MAX_UINT32:
            raise ValidationError("contract_vout must be a uint32")
        if (
            type(self.block_height) is not int
            or type(self.tip_height) is not int
            or not 0 <= self.block_height <= self.tip_height
        ):
            raise ValidationError("inclusion block height must not exceed chain tip height")
        if self.block_height == self.tip_height and self.block_hash != self.tip_hash:
            raise ValidationError("inclusion block at tip height must be the chain tip")

    @property
    def depth(self) -> int:
        """Inclusion depth within the caller's verified current best chain."""
        return self.tip_height - self.block_height + 1


@dataclass(frozen=True, slots=True)
class FundingLineage:
    """Accepted binding history and at most one reversible best-chain view.

    The fields are in-memory observations, NOT evidence of verified signatures,
    actual UTXOs, durable export, or permissions. Rebuild only from independently
    verified context and current chain observations, not an untrusted dump.
    """

    contract_hash: str
    funding_attempt_id: str
    network_identity: NetworkIdentity
    funder_role: str
    contract_value_sat: str
    contract_script_pubkey: str
    bindings: tuple[FundingBinding, ...] = ()
    best_chain: BestChainObservation | None = None

    @classmethod
    def for_terms(
        cls,
        terms: ContractTerms,
        funding_attempt_id: str,
        *,
        keys: TaprootKeyOperations,
    ) -> FundingLineage:
        """Bind a new in-memory lineage to authenticated terms and an attempt ID.

        The caller must first verify the signed terms and choose the attempt ID.
        This operation does not create a funding attempt or attest export safety.
        """
        _require_hash(funding_attempt_id, field="funding_attempt_id")
        contract = reconstruct_taproot_contract(terms, keys=keys)
        return cls(
            contract_hash=contract_hash(terms).hex(),
            funding_attempt_id=funding_attempt_id,
            network_identity=terms.network_identity,
            funder_role="client" if terms.profile_id == "btc-to-ln/v1" else "provider",
            contract_value_sat=terms.economics.contract_amount_sat,
            contract_script_pubkey=contract.script_pubkey.hex(),
        )

    def append_verified_binding(self, binding: FundingBinding) -> FundingLineage:
        """Append previously authenticated and transaction-verified binding.

        The host must verify the funder's session signature, contract identity,
        actual transaction ID and output, common anchor spend and conflicts,
        and applicable chain or mempool status before calling this method.
        """
        if not isinstance(binding, FundingBinding):
            raise ValidationError("funding lineage requires a parsed binding")
        if (
            binding.contract_hash != self.contract_hash
            or binding.funding_attempt_id != self.funding_attempt_id
            or binding.funder_role != self.funder_role
            or binding.contract_value_sat != self.contract_value_sat
            or binding.contract_script_pubkey != self.contract_script_pubkey
        ):
            raise TransitionError("binding disagrees with authenticated contract and attempt")
        if binding.contract_vout > MAX_UINT32 or binding.lineage_anchor_vout > MAX_UINT32:
            raise TransitionError("binding outpoint index exceeds uint32")
        revision = binding.binding_revision
        if revision < len(self.bindings):
            if self.bindings[revision] == binding:
                return self
            raise TransitionError("conflicting binding at an accepted revision")
        if revision != len(self.bindings):
            raise TransitionError("funding binding revision skips or forks the lineage")
        if self.bindings:
            previous = self.bindings[-1]
            if (
                binding.replaces_txid != previous.funding_txid
                or binding.lineage_anchor_txid != previous.lineage_anchor_txid
                or binding.lineage_anchor_vout != previous.lineage_anchor_vout
            ):
                raise TransitionError("replacement changes predecessor or lineage anchor")
            if any(old.funding_txid == binding.funding_txid for old in self.bindings):
                raise TransitionError("replacement repeats an accepted transaction ID")
        elif binding.replaces_txid is not None:
            raise TransitionError("first funding binding must be revision zero")
        return replace(self, bindings=(*self.bindings, binding))

    def observe_verified_best_chain(
        self,
        observation: BestChainObservation,
    ) -> FundingLineage:
        """Record a current, caller-verified serialized best-chain observation.

        An existing observation must be explicitly removed before any different
        view, including one at a later tip, is installed. No accepted binding
        revision can silently displace a confirmed earlier candidate.
        """
        if not isinstance(observation, BestChainObservation):
            raise ValidationError("best-chain view requires a parsed observation")
        if not any(
            (binding.funding_txid, binding.contract_vout)
            == (observation.funding_txid, observation.contract_vout)
            for binding in self.bindings
        ):
            raise TransitionError("best-chain outpoint is not an accepted binding")
        if self.best_chain == observation:
            return self
        if self.best_chain is not None:
            raise TransitionError("remove the prior best-chain observation before replacing it")
        return replace(self, best_chain=observation)

    def require_funding_confirmations(self, terms: ContractTerms) -> BestChainObservation:
        """Check signed-term depth against this caller-verified current view.

        The host must authenticate the terms and serialize chain observation
        and action decisions. Returning this snapshot is not a durable or
        revocable authorization: an old lineage instance may outlive a reorg.
        """
        if not isinstance(terms, ContractTerms):
            raise ValidationError("funding depth requires parsed contract terms")
        if contract_hash(terms).hex() != self.contract_hash:
            raise TransitionError("funding depth terms differ from accepted contract")
        if self.best_chain is None or self.best_chain.depth < terms.funding_confirmations:
            raise TransitionError("required funding confirmations are not observed")
        return self.best_chain

    def remove_verified_best_chain(
        self,
        observation: BestChainObservation,
    ) -> FundingLineage:
        """Invalidate only the exact observation verified stale by the host.

        An old delayed removal cannot erase a later observation. The host must
        supply a fresh current-chain view after a reorg; revision order alone
        cannot restore a prior confirmation.
        """
        if self.best_chain != observation or self.best_chain is None:
            raise TransitionError("cannot remove a different or absent best-chain observation")
        return replace(self, best_chain=None)
