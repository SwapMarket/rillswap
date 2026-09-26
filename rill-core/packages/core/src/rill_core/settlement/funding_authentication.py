"""Static signed funding context checks, never live funding acceptance.

The expected identity must come from a trust source independent of the signed
handshake. Signature consistency is not proof of message delivery, order,
intent admission, transaction bytes, anchor approval, chain state, or permission
to fund, pay, sign, broadcast, or retry.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:
    from collections.abc import Callable

from rill_core.errors import ValidationError
from rill_core.settlement.taproot import TaprootKeyOperations, reconstruct_taproot_contract
from rill_core.settlement.unilateral import SchnorrVerifier
from rill_core.wire.hashes import (
    EPOCH_SESSION_FEATURE,
    client_acceptance_hash,
    contract_hash,
    funding_binding_hash,
    handshake_accept_hash,
    handshake_hash,
    provider_terms_hash,
)
from rill_core.wire.messages import (
    ClientAcceptance,
    ContractTerms,
    FundingBinding,
    HandshakeAccept,
    HandshakeInit,
    ProviderTerms,
)
from rill_core.wire.types import NetworkIdentity, Signature64, XOnlyKey

MAX_BINDING_HISTORY = 64
MAX_UINT32 = 0xFFFFFFFF
PURPOSE_KEY_COUNT = 6
SIGNATURE_HEX_LENGTH = 128


class FundingDeclarationCrypto(TaprootKeyOperations, SchnorrVerifier, Protocol):
    """Only the curve operations needed to reconstruct and check signed context."""


@dataclass(frozen=True, slots=True)
class SignedFundingBinding:
    """One signed declaration, not proof of a funded or spendable outpoint."""

    binding: FundingBinding
    funder_session_signature: Signature64


def _require(condition: bool, message: str) -> None:  # noqa: FBT001 - internal predicate
    if not condition:
        raise ValidationError(message)


def _signature(crypto: SchnorrVerifier, key: str, digest: bytes, signature: str) -> None:
    _require(
        isinstance(signature, str)
        and len(signature) == SIGNATURE_HEX_LENGTH
        and all(char in "0123456789abcdef" for char in signature),
        "invalid static signature encoding",
    )
    verify: Callable[[bytes, bytes, bytes], object] = crypto.schnorr_verify
    checked = verify(bytes.fromhex(key), digest, bytes.fromhex(signature))
    _require(checked is None, "crypto adapter must raise on invalid signatures")


def _check_static_binding_history(  # noqa: PLR0913 - signature context is explicit
    signed_bindings: tuple[SignedFundingBinding, ...],
    terms: ContractTerms,
    contract_digest: str,
    script_pubkey: str,
    funder_session_key: str,
    *,
    crypto: SchnorrVerifier,
) -> None:
    """Share the exact signed revision and predecessor invariants with recovery."""
    _require(
        isinstance(signed_bindings, tuple) and len(signed_bindings) <= MAX_BINDING_HISTORY,
        "unsupported signed funding history",
    )
    role = "client" if terms.profile_id == "btc-to-ln/v1" else "provider"
    for revision, item in enumerate(signed_bindings):
        _require(
            isinstance(item, SignedFundingBinding) and isinstance(item.binding, FundingBinding),
            "invalid signed funding record",
        )
        binding = item.binding
        _require(binding.contract_hash == contract_digest, "binding contract hash")
        _require(binding.funder_role == role, "binding funder")
        _require(binding.binding_revision == revision, "binding revision")
        _require(
            binding.contract_value_sat == terms.economics.contract_amount_sat, "binding amount"
        )
        _require(binding.contract_script_pubkey == script_pubkey, "binding script")
        _require(
            binding.contract_vout <= MAX_UINT32 and binding.lineage_anchor_vout <= MAX_UINT32,
            "binding outpoint index",
        )
        if revision:
            previous = signed_bindings[revision - 1].binding
            _require(binding.funding_attempt_id == previous.funding_attempt_id, "binding attempt")
            _require(binding.replaces_txid == previous.funding_txid, "binding predecessor")
            _require(
                (binding.lineage_anchor_txid, binding.lineage_anchor_vout)
                == (previous.lineage_anchor_txid, previous.lineage_anchor_vout),
                "binding anchor",
            )
            _require(
                all(
                    old.binding.funding_txid != binding.funding_txid
                    for old in signed_bindings[:revision]
                ),
                "binding duplicate transaction",
            )
        _signature(
            crypto, funder_session_key, funding_binding_hash(binding), item.funder_session_signature
        )


def verify_static_signed_funding_binding_history(  # noqa: PLR0913 - explicit trust inputs
    *,
    terms: ContractTerms,
    handshake_init: HandshakeInit,
    handshake_accept: HandshakeAccept,
    provider_identity_signature: Signature64,
    provider_terms_signature: Signature64,
    client_acceptance_signature: Signature64,
    signed_bindings: tuple[SignedFundingBinding, ...],
    expected_provider_identity: XOnlyKey,
    expected_network: NetworkIdentity,
    crypto: FundingDeclarationCrypto,
) -> None:
    """Verify externally anchored *static signatures* of a nonempty history.

    Success is not live admission or a security capability. The caller must
    separately establish the independent provider identity source, confirmed
    handshake/message order, acceptance-time policy, transaction inputs/bytes,
    current chain view, and durable action fences. No effects occur here.
    """
    try:
        _require(isinstance(terms, ContractTerms), "missing signed terms")
        _require(isinstance(handshake_init, HandshakeInit), "missing handshake initiation")
        _require(isinstance(handshake_accept, HandshakeAccept), "missing handshake acceptance")
        _require(isinstance(expected_network, NetworkIdentity), "missing expected network")
        _require(isinstance(expected_provider_identity, str), "missing trusted provider identity")
        _require(bool(signed_bindings), "empty funding declaration")
        _require(terms.network_identity == expected_network, "funding network differs")
        _require(
            handshake_init.network_identity
            == handshake_accept.network_identity
            == expected_network,
            "handshake network differs",
        )
        _require(
            handshake_init.profile_id == handshake_accept.profile_id == terms.profile_id,
            "handshake profile differs",
        )
        _require(not terms.required_features, "unsupported contract feature")
        handshake_accept.validate_against(
            handshake_init, supported_features=frozenset({EPOCH_SESSION_FEATURE})
        )
        _require(
            expected_provider_identity
            == terms.provider_identity_key
            == handshake_init.expected_provider_identity_xonly_key
            == handshake_accept.provider_identity_xonly_key,
            "provider identity not independently anchored",
        )
        _require(
            len(
                {
                    handshake_init.client_session_xonly_key,
                    handshake_accept.provider_session_xonly_key,
                    terms.provider_identity_key,
                    terms.client_contract_compressed_key[2:],
                    terms.provider_contract_compressed_key[2:],
                    terms.recovery_authorization_xonly_key,
                }
            )
            == PURPOSE_KEY_COUNT,
            "reused purpose key",
        )
        digest = contract_hash(terms).hex()
        transcript = handshake_hash(handshake_init, handshake_accept).hex()
        offer = ProviderTerms(contract_hash=digest, contract_terms=terms, handshake_hash=transcript)
        acceptance = ClientAcceptance(
            contract_hash=digest,
            handshake_hash=transcript,
            session_id=handshake_init.session_id,
            client_session_xonly_key=handshake_init.client_session_xonly_key,
            provider_session_xonly_key=handshake_accept.provider_session_xonly_key,
        )
        _signature(
            crypto,
            expected_provider_identity,
            handshake_accept_hash(handshake_accept),
            provider_identity_signature,
        )
        _signature(
            crypto, expected_provider_identity, provider_terms_hash(offer), provider_terms_signature
        )
        _signature(
            crypto,
            handshake_init.client_session_xonly_key,
            client_acceptance_hash(acceptance),
            client_acceptance_signature,
        )
        script_pubkey = reconstruct_taproot_contract(terms, keys=crypto).script_pubkey.hex()
        funder_session_key = (
            handshake_init.client_session_xonly_key
            if terms.profile_id == "btc-to-ln/v1"
            else handshake_accept.provider_session_xonly_key
        )
        _check_static_binding_history(
            signed_bindings, terms, digest, script_pubkey, funder_session_key, crypto=crypto
        )
    except Exception:  # noqa: BLE001, S110 - secret-bearing adapter errors must not escape
        pass
    else:
        return
    raise ValidationError("invalid static signed funding declaration")
