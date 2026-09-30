"""Historical disclosure reservations never restore live cooperation authority."""

from __future__ import annotations

import copy
import os
from typing import TYPE_CHECKING

import pytest
from test_reverse_recovery_fallback import PreparedFallback

from rill_core.errors import ValidationError
from rill_core.recovery import construct_selected_recovery_claim
from rill_core.recovery.inspection import REVERSE_DISCLOSURE_EXTENSION, REVERSE_FALLBACK_EXTENSION
from rill_core.settlement import (
    UnilateralAuthorization,
    build_cooperative_claim,
    validate_unilateral_spend,
)
from rill_core.wire.canonical import canonicalize
from rill_core.wire.cooperative_messages import COOPERATIVE_CLAIM_FEATURE
from rill_core.wire.hashes import (
    client_acceptance_hash,
    contract_hash,
    funding_binding_hash,
    handshake_accept_hash,
    handshake_hash,
    handshake_init_hash,
    provider_terms_hash,
    unsigned_envelope_hash,
)
from rill_core.wire.messages import (
    ClientAcceptance,
    ContractTerms,
    Envelope,
    HandshakeAccept,
    HandshakeInit,
    ProviderTerms,
)

if TYPE_CHECKING:
    from collections.abc import Iterator

    from rill_crypto import Context

pytestmark = [
    pytest.mark.native_crypto,
    pytest.mark.skipif(
        os.environ.get("RILLSWAP_RUN_NATIVE_CRYPTO") != "1",
        reason="set RILLSWAP_RUN_NATIVE_CRYPTO=1 for native reverse disclosure verification",
    ),
]


class ReservedDisclosure(PreparedFallback):
    def __init__(self, crypto: Context) -> None:
        super().__init__(crypto)
        # The original fallback fixture intentionally has no cooperative feature.
        # Refresh authenticated context before constructing the reservation's
        # predecessor. Claim scripts and native fallback bytes stay unchanged.
        prepared = copy.deepcopy(self.next)
        context = prepared["verification_context"]
        features = [COOPERATIVE_CLAIM_FEATURE]
        context["handshake_init"]["required_features"] = features
        context["handshake_accept"]["required_features"] = features
        init = HandshakeInit.model_validate_json(
            canonicalize(context["handshake_init"]), strict=True
        )
        context["handshake_accept"]["handshake_init_hash"] = handshake_init_hash(init).hex()
        accept = HandshakeAccept.model_validate_json(
            canonicalize(context["handshake_accept"]), strict=True
        )
        context["handshake_hash"] = handshake_hash(init, accept).hex()
        prepared["contract_terms"]["required_features"] = features
        self.terms = ContractTerms.model_validate_json(
            canonicalize(prepared["contract_terms"]), strict=True
        )
        prepared["contract_hash"] = contract_hash(self.terms).hex()
        provider = ProviderTerms(
            contract_hash=prepared["contract_hash"],
            contract_terms=self.terms,
            handshake_hash=context["handshake_hash"],
        )
        client = ClientAcceptance(
            contract_hash=prepared["contract_hash"],
            handshake_hash=context["handshake_hash"],
            session_id=init.session_id,
            client_session_xonly_key=init.client_session_xonly_key,
            provider_session_xonly_key=accept.provider_session_xonly_key,
        )
        for name, scalar, digest in (
            ("provider_identity_signature", 1, handshake_accept_hash(accept)),
            ("provider_terms_signature", 1, provider_terms_hash(provider)),
            ("client_acceptance_signature", 8, client_acceptance_hash(client)),
        ):
            context[name] = crypto.schnorr_sign(
                scalar.to_bytes(32, "big"), digest, b"\x55" * 32
            ).hex()
        self.binding = self.binding.model_copy(update={"contract_hash": prepared["contract_hash"]})
        prepared["funding_history"] = []
        self.append(prepared, self.binding)
        prepared["extensions"][REVERSE_FALLBACK_EXTENSION]["funding_binding_hash"] = (
            funding_binding_hash(self.binding).hex()
        )
        self.authorization = UnilateralAuthorization.from_terms(
            self.terms, self.authorization.funding, "claim", keys=crypto
        )
        plan = build_cooperative_claim(self.authorization, fee_sat=300)
        public_nonce = crypto.public_key((7).to_bytes(32, "big")) + crypto.public_key(
            (8).to_bytes(32, "big")
        )
        crypto.musig_public_nonce_validate(public_nonce)
        proposal = Envelope.model_validate_json(
            canonicalize(
                {
                    "protocol": "rillswap",
                    "wire_version": "1",
                    "profile_id": "ln-to-btc/v1",
                    "network_identity": prepared["network_identity"],
                    "required_features": features,
                    "extensions": {},
                    "session_id": init.session_id,
                    "message_id": "ee" * 32,
                    "sender_session_key": init.client_session_xonly_key,
                    "sequence": 3,
                    "in_reply_to": None,
                    "contract_hash": prepared["contract_hash"],
                    "message_type": "action_request",
                    "signature": None,
                    "payload": {
                        "action": "cooperative_claim_propose",
                        "cooperation_id": "ff" * 32,
                        "unsigned_transaction": plan.base_transaction.hex(),
                        "public_nonce": public_nonce.hex(),
                        "payment_preimage": prepared["monotonic_knowledge"]["preimage"],
                        "deadline_at": prepared["updated_at"] + 20,
                        "deadline_height": self.terms.refund_lock_height
                        - self.terms.timing_policy.claim_confirmation_blocks,
                    },
                }
            ),
            strict=True,
        )
        self.prior = prepared
        self.next = copy.deepcopy(prepared)
        self.next["extensions"][REVERSE_DISCLOSURE_EXTENSION] = {
            "version": 1,
            "funding_binding_hash": funding_binding_hash(self.binding).hex(),
            "proposal": self.sign(proposal).model_dump(mode="json"),
        }

    def sign(self, proposal: Envelope, scalar: int = 8) -> Envelope:
        return proposal.model_copy(
            update={
                "signature": self.crypto.schnorr_sign(
                    scalar.to_bytes(32, "big"),
                    unsigned_envelope_hash(proposal),
                    b"\x77" * 32,
                ).hex()
            }
        )


@pytest.fixture
def reservation() -> Iterator[ReservedDisclosure]:
    from rill_crypto import Context  # noqa: PLC0415 - opt-in native dependency

    with Context(library_path=os.environ["RILL_CRYPTO_LIBRARY"]) as crypto:
        yield ReservedDisclosure(crypto)


@pytest.mark.parametrize("issued", [False, True])
def test_reserved_possible_disclosure_preserves_knowledge_and_independent_recovery(
    reservation: ReservedDisclosure,
    *,
    issued: bool,
) -> None:
    reservation.prior["monotonic_knowledge"]["dangerous_signature_issued"] = issued
    reservation.next["monotonic_knowledge"]["dangerous_signature_issued"] = issued
    assert reservation.inspect(reservation.prior) == reservation.successor(
        reservation.prior, reservation.next
    )
    assert reservation.next["monotonic_knowledge"] == reservation.prior["monotonic_knowledge"]
    assert (
        reservation.next["extensions"]["test/opaque"]
        == reservation.prior["extensions"]["test/opaque"]
    )
    # The marker reserves uncertainty, not native nonce custody, live signing,
    # payment, or a different recovery path. Explicit key-based recovery survives.
    rebuilt = construct_selected_recovery_claim(
        canonicalize(reservation.next),
        reservation.network,
        funding_attempt_id=reservation.binding.funding_attempt_id,
        binding_revision=reservation.binding.binding_revision,
        live_funding=reservation.authorization.funding,
        sampled_tip_height=100,
        sampled_confirmations=2,
        fee_sat=201,
        auxiliary_random=b"\x77" * 32,
        crypto=reservation.crypto,
    )
    assert (
        validate_unilateral_spend(
            rebuilt,
            reservation.authorization,
            verifier=reservation.crypto,
        ).fee_sat
        == 201
    )


@pytest.mark.parametrize("field", ["version", "funding_binding_hash", "proposal"])
def test_partial_disclosure_is_rejected_not_ignored(
    reservation: ReservedDisclosure, field: str
) -> None:
    malformed = copy.deepcopy(reservation.next)
    del malformed["extensions"][REVERSE_DISCLOSURE_EXTENSION][field]
    with pytest.raises(ValidationError):
        reservation.inspect(malformed)


@pytest.mark.parametrize(
    "case",
    [
        "boolean version",
        "unsupported version",
        "extra",
        "binding",
        "fallback missing",
        "fallback invalid",
        "wrong signer",
        "contract signer",
        "signature",
        "preimage",
        "transaction",
        "deadline",
        "cutoff",
        "profile",
        "session",
        "contract",
        "feature",
        "nonce",
        "cooperation id",
    ],
)
def test_invalid_disclosure_evidence_never_passes_inspection(  # noqa: PLR0912 - one artifact fault per case
    reservation: ReservedDisclosure, case: str
) -> None:
    candidate = copy.deepcopy(reservation.next)
    marker = candidate["extensions"][REVERSE_DISCLOSURE_EXTENSION]
    if case == "boolean version":
        marker["version"] = True
    elif case == "unsupported version":
        marker["version"] = 2
    elif case == "extra":
        marker["signature_hash"] = "00" * 32
    elif case == "binding":
        marker["funding_binding_hash"] = "00" * 32
    elif case == "fallback missing":
        del candidate["extensions"][REVERSE_FALLBACK_EXTENSION]
    elif case == "fallback invalid":
        candidate["extensions"][REVERSE_FALLBACK_EXTENSION]["transaction"] = "00"
    else:
        proposal = marker["proposal"]
        if case in {"wrong signer", "contract signer"}:
            marker["proposal"] = reservation.sign(
                Envelope.model_validate_json(canonicalize(proposal), strict=True),
                9 if case == "wrong signer" else 10,
            ).model_dump(mode="json")
        elif case == "signature":
            proposal["signature"] = "00" * 64
        elif case == "preimage":
            proposal["payload"]["payment_preimage"] = "00" * 32
        elif case == "transaction":
            proposal["payload"]["unsigned_transaction"] = "00"
        elif case == "deadline":
            proposal["payload"]["deadline_at"] = 0
        elif case == "cutoff":
            proposal["payload"]["deadline_height"] = reservation.terms.refund_lock_height
        elif case == "profile":
            proposal["profile_id"] = "btc-to-ln/v1"
        elif case == "session":
            proposal["session_id"] = "00" * 32
        elif case == "contract":
            proposal["contract_hash"] = "00" * 32
        elif case == "feature":
            proposal["required_features"] = []
        elif case == "nonce":
            proposal["payload"]["public_nonce"] = "00" * 66
        elif case == "cooperation id":
            proposal["payload"]["cooperation_id"] = "00" * 32
        if case in {
            "preimage",
            "transaction",
            "deadline",
            "cutoff",
            "profile",
            "session",
            "contract",
            "feature",
        }:
            # Authenticate invalid semantics, so rejection cannot be explained
            # solely by a stale signature. Nonce/id mutations intentionally keep
            # their old signature to characterize frozen signed attempt bytes.
            marker["proposal"] = reservation.sign(
                Envelope.model_validate_json(canonicalize(proposal), strict=True)
            ).model_dump(mode="json")
    with pytest.raises(ValidationError):
        reservation.inspect(candidate)


@pytest.mark.parametrize(
    "change", ["remove", "replace", "knowledge", "opaque", "late", "simultaneous"]
)
def test_disclosure_successors_cannot_rewind_or_reserve_late(
    reservation: ReservedDisclosure, change: str
) -> None:
    prior, candidate = copy.deepcopy(reservation.prior), copy.deepcopy(reservation.next)
    if change in {"remove", "replace"}:
        prior = copy.deepcopy(reservation.next)
        if change == "remove":
            del candidate["extensions"][REVERSE_DISCLOSURE_EXTENSION]
        else:
            proposal = candidate["extensions"][REVERSE_DISCLOSURE_EXTENSION]["proposal"]
            proposal["message_id"] = "ab" * 32
            candidate["extensions"][REVERSE_DISCLOSURE_EXTENSION]["proposal"] = reservation.sign(
                Envelope.model_validate_json(canonicalize(proposal), strict=True)
            ).model_dump(mode="json")
            reservation.inspect(candidate)  # Independently valid, not a permitted successor.
    elif change == "knowledge":
        candidate["monotonic_knowledge"]["dangerous_signature_issued"] = True
    elif change == "opaque":
        candidate["extensions"]["test/opaque"] = {"changed": True}
    elif change == "late":
        candidate["updated_at"] = candidate["extensions"][REVERSE_DISCLOSURE_EXTENSION]["proposal"][
            "payload"
        ]["deadline_at"]
    elif change == "simultaneous":
        del prior["extensions"][REVERSE_FALLBACK_EXTENSION]
    with pytest.raises(ValidationError):
        reservation.successor(prior, candidate)


def test_historical_disclosure_survives_binding_append_but_cannot_be_inserted_for_old_output(
    reservation: ReservedDisclosure,
) -> None:
    historical = copy.deepcopy(reservation.next)
    later = reservation.binding.model_copy(
        update={
            "binding_revision": 1,
            "funding_txid": "bb" * 32,
            "replaces_txid": reservation.binding.funding_txid,
        }
    )
    reservation.append(historical, later)
    reservation.successor(reservation.next, historical)
    reservation.inspect(historical)
    missing = copy.deepcopy(historical)
    del missing["extensions"][REVERSE_DISCLOSURE_EXTENSION]
    with pytest.raises(ValidationError, match="invalid or nonmonotonic recovery successor"):
        reservation.successor(missing, historical)


def test_expired_historical_marker_remains_evidence_only(reservation: ReservedDisclosure) -> None:
    historical = copy.deepcopy(reservation.next)
    historical["updated_at"] = (
        historical["extensions"][REVERSE_DISCLOSURE_EXTENSION]["proposal"]["payload"]["deadline_at"]
        + 100
    )
    assert reservation.inspect(historical) == reservation.inspect(reservation.next)
    reservation.successor(reservation.next, historical)


@pytest.mark.parametrize("boundary", ["inspect", "successor"])
def test_disclosure_parse_failures_do_not_expose_secret_input_or_exception_context(
    reservation: ReservedDisclosure,
    boundary: str,
) -> None:
    malformed = copy.deepcopy(reservation.next)
    secret = reservation.next["monotonic_knowledge"]["preimage"]
    malformed["extensions"][REVERSE_DISCLOSURE_EXTENSION]["version"] = secret
    inspect = (
        reservation.inspect
        if boundary == "inspect"
        else lambda document: reservation.successor(reservation.prior, document)
    )
    with pytest.raises(ValidationError) as observed:
        inspect(malformed)
    expected = (
        "invalid or unsupported recovery plaintext"
        if boundary == "inspect"
        else "invalid or nonmonotonic recovery successor"
    )
    assert str(observed.value) == expected
    assert observed.value.__context__ is None
    assert observed.value.__cause__ is None
    assert secret not in str(observed.value)
    assert reservation.next["user_secret"]["contract_secret_key"] not in str(observed.value)
