"""Native authenticated reservations use a fourth encrypted create-only file."""

from __future__ import annotations

import copy
import json
import os
from typing import TYPE_CHECKING, Any

import httpx
import pytest
from pyrage import x25519
from rill_core.errors import ValidationError
from rill_core.recovery import (
    COOPERATIVE_RESERVATION_EXTENSION,
    construct_selected_recovery_refund,
    inspect_recovery_plaintext,
    inspect_recovery_successor,
)
from rill_core.settlement.unilateral import (
    FundingOutput,
    UnilateralAuthorization,
    build_cooperative_claim,
    validate_unilateral_spend,
)
from rill_core.wire.canonical import canonicalize
from rill_core.wire.hashes import (
    COOPERATIVE_CLAIM_FEATURE,
    client_acceptance_hash,
    contract_hash,
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
from rill_core.wire.types import NetworkIdentity
from rill_crypto import Context
from rill_crypto.binding import MusigAttempt
from test_recovery_cli import _fixture, _signed_binding

from rill_cli import main, publication, swap_command
from rill_cli.age_container import X25519Credentials, verify_export_ciphertext
from rill_cli.publication import RecoveryPublicationError, RecoveryPublicationUncertainError
from rill_cli.swap_command import _write_recovery_snapshot

if TYPE_CHECKING:
    from pathlib import Path

LIBRARY = os.environ.get("RILL_CRYPTO_LIBRARY")
pytestmark = [
    pytest.mark.native_crypto,
    pytest.mark.skipif(
        LIBRARY is None, reason="set RILL_CRYPTO_LIBRARY for native reservation checks"
    ),
]


def _snapshots(crypto: Context) -> tuple[dict[str, Any], ...]:
    initial, _ = _fixture("btc-to-ln")
    context = initial["verification_context"]
    feature = [COOPERATIVE_CLAIM_FEATURE]
    context["handshake_init"]["required_features"] = feature
    context["handshake_accept"]["required_features"] = feature
    init = HandshakeInit.model_validate_json(canonicalize(context["handshake_init"]), strict=True)
    context["handshake_accept"]["handshake_init_hash"] = handshake_init_hash(init).hex()
    accept = HandshakeAccept.model_validate_json(
        canonicalize(context["handshake_accept"]), strict=True
    )
    context["handshake_hash"] = handshake_hash(init, accept).hex()
    initial["contract_terms"]["required_features"] = feature
    terms = ContractTerms.model_validate_json(canonicalize(initial["contract_terms"]), strict=True)
    initial["contract_hash"] = contract_hash(terms).hex()
    provider_terms = ProviderTerms(
        contract_hash=initial["contract_hash"],
        contract_terms=terms,
        handshake_hash=context["handshake_hash"],
    )
    client_acceptance = ClientAcceptance(
        contract_hash=initial["contract_hash"],
        handshake_hash=context["handshake_hash"],
        session_id=init.session_id,
        client_session_xonly_key=init.client_session_xonly_key,
        provider_session_xonly_key=accept.provider_session_xonly_key,
    )
    assert crypto.public_key((1).to_bytes(32, "big"))[1:].hex() == terms.provider_identity_key
    assert crypto.public_key((3).to_bytes(32, "big"))[1:].hex() == accept.provider_session_xonly_key
    for name, scalar, digest in (
        ("provider_identity_signature", 1, handshake_accept_hash(accept)),
        ("provider_terms_signature", 1, provider_terms_hash(provider_terms)),
        ("client_acceptance_signature", 2, client_acceptance_hash(client_acceptance)),
    ):
        context[name] = crypto.schnorr_sign(scalar.to_bytes(32, "big"), digest, b"\x55" * 32).hex()
    funded = copy.deepcopy(initial)
    funded["funding_history"] = [_signed_binding(funded, 0, str(LIBRARY))]
    paid = copy.deepcopy(funded)
    paid["monotonic_knowledge"].update(preimage_known=True, preimage="42" * 32)
    binding = funded["funding_history"][0]["binding"]
    funding = FundingOutput(
        txid=bytes.fromhex(binding["funding_txid"]),
        output_index=binding["contract_vout"],
        value_sat=int(binding["contract_value_sat"]),
        script_pubkey=bytes.fromhex(binding["contract_script_pubkey"]),
    )
    plan = build_cooperative_claim(
        UnilateralAuthorization.from_terms(terms, funding, "claim", keys=crypto),
        fee_sat=300,
    )
    # Public fixture points only. This test never allocates a client MuSig handle.
    public_nonce = crypto.public_key((7).to_bytes(32, "big")) + crypto.public_key(
        (8).to_bytes(32, "big")
    )
    crypto.musig_public_nonce_validate(public_nonce)
    unsigned = Envelope.model_validate_json(
        canonicalize(
            {
                "protocol": "rillswap",
                "wire_version": "1",
                "profile_id": "btc-to-ln/v1",
                "network_identity": initial["network_identity"],
                "required_features": feature,
                "extensions": {},
                "session_id": init.session_id,
                "message_id": "aa" * 32,
                "sender_session_key": accept.provider_session_xonly_key,
                "sequence": 3,
                "in_reply_to": None,
                "contract_hash": initial["contract_hash"],
                "message_type": "action_request",
                "signature": None,
                "payload": {
                    "action": "cooperative_claim_propose",
                    "cooperation_id": "bb" * 32,
                    "unsigned_transaction": plan.base_transaction.hex(),
                    "public_nonce": public_nonce.hex(),
                    "payment_preimage": "42" * 32,
                    "deadline_at": initial["updated_at"] + 20,
                    "deadline_height": terms.refund_lock_height
                    - terms.timing_policy.claim_confirmation_blocks,
                },
            }
        ),
        strict=True,
    )
    proposal = unsigned.model_copy(
        update={
            "signature": crypto.schnorr_sign(
                (3).to_bytes(32, "big"),
                unsigned_envelope_hash(unsigned),
                b"\x77" * 32,
            ).hex()
        }
    )
    reserved = copy.deepcopy(paid)
    reserved["extensions"][COOPERATIVE_RESERVATION_EXTENSION] = {
        "version": 1,
        "proposal": proposal.model_dump(mode="json"),
        "signature_hash": plan.signature_hash.hex(),
    }
    return initial, funded, paid, reserved


def _credentials() -> X25519Credentials:
    identity = x25519.Identity.generate()
    return X25519Credentials(str(identity.to_public()), str(identity))


def test_native_reservation_publication_preserves_all_predecessors(tmp_path: Path) -> None:
    with Context(library_path=LIBRARY) as crypto:
        snapshots = _snapshots(crypto)
        network = NetworkIdentity.model_validate_json(
            canonicalize(snapshots[0]["network_identity"])
        )
        output, credentials = tmp_path / "swap.age", _credentials()
        previous = None
        for document, suffix in zip(
            snapshots, ("", ".funded", ".paid", ".cooperating"), strict=True
        ):
            prior_bytes = {path: path.read_bytes() for path in tmp_path.iterdir()}
            intended = canonicalize(document)
            _write_recovery_snapshot(
                output, intended, previous, network, credentials=credentials, crypto=crypto
            )
            stored = (tmp_path / ("swap.age" + suffix)).read_bytes()
            verify_export_ciphertext(
                stored, intended, network, credentials=credentials, crypto=crypto
            )
            assert {path: path.read_bytes() for path in prior_bytes} == prior_bytes
            previous = intended
        prior_bytes = {path: path.read_bytes() for path in tmp_path.iterdir()}
        paid, reserved = canonicalize(snapshots[2]), canonicalize(snapshots[3])
        with pytest.raises(RecoveryPublicationError):
            _write_recovery_snapshot(
                output, reserved, paid, network, credentials=credentials, crypto=crypto
            )
        assert {path: path.read_bytes() for path in tmp_path.iterdir()} == prior_bytes
        later = copy.deepcopy(snapshots[3])
        later["updated_at"] += 1000
        later["funding_history"].append(_signed_binding(later, 1, str(LIBRARY)))
        assert inspect_recovery_successor(reserved, canonicalize(later), network, crypto=crypto)


@pytest.mark.parametrize("failure", ["fsync", "directory fsync", "readback"])
def test_uncertain_reservation_publication_is_not_reported_as_success(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    failure: str,
) -> None:
    with Context(library_path=LIBRARY) as crypto:
        _, _, paid, reserved = _snapshots(crypto)
        network = NetworkIdentity.model_validate_json(canonicalize(paid["network_identity"]))
        output, credentials = tmp_path / "swap.age", _credentials()
        for suffix in ("", ".funded", ".paid"):
            (tmp_path / (output.name + suffix)).write_bytes(b"immutable predecessor")
        prior_bytes = {path: path.read_bytes() for path in tmp_path.iterdir()}

        def fail(*_args: object, **_kwargs: object) -> None:
            raise OSError("test-only publication uncertainty")

        if failure == "readback":
            monkeypatch.setattr(swap_command, "verify_export_ciphertext", fail)
        else:
            original_fsync = publication.os.fsync
            syncs = 0

            def fail_fsync(fd: int) -> None:
                nonlocal syncs
                syncs += 1
                if syncs == (1 if failure == "fsync" else 2):
                    fail()
                original_fsync(fd)

            monkeypatch.setattr(publication.os, "fsync", fail_fsync)
        expected_error = (
            RecoveryPublicationUncertainError
            if failure == "directory fsync"
            else RecoveryPublicationError
        )
        with pytest.raises(expected_error):
            _write_recovery_snapshot(
                output,
                canonicalize(reserved),
                canonicalize(paid),
                network,
                credentials=credentials,
                crypto=crypto,
            )
        assert {path: path.read_bytes() for path in prior_bytes} == prior_bytes
        target = tmp_path / "swap.age.cooperating"
        if failure == "directory fsync":
            assert target.exists()
            # A publication exception can coexist with valid retained ciphertext.
            verify_export_ciphertext(
                target.read_bytes(),
                canonicalize(reserved),
                network,
                credentials=credentials,
                crypto=crypto,
            )
        else:
            assert not target.exists()


def test_native_signature_tampering_cannot_create_reservation_file(tmp_path: Path) -> None:
    with Context(library_path=LIBRARY) as crypto:
        _, _, paid, reserved = _snapshots(crypto)
        network = NetworkIdentity.model_validate_json(canonicalize(paid["network_identity"]))
        reserved["extensions"][COOPERATIVE_RESERVATION_EXTENSION]["proposal"]["signature"] = (
            "33" * 64
        )
        with pytest.raises(ValidationError, match="invalid or nonmonotonic recovery successor"):
            _write_recovery_snapshot(
                tmp_path / "swap.age",
                canonicalize(reserved),
                canonicalize(paid),
                network,
                credentials=_credentials(),
                crypto=crypto,
            )
        assert list(tmp_path.iterdir()) == []
        assert inspect_recovery_plaintext(canonicalize(paid), network, crypto=crypto)


def test_stored_reservation_inspection_never_networks_or_resumes_signing(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    credentials = _credentials()
    with Context(library_path=LIBRARY) as crypto:
        _, _, paid, reserved = _snapshots(crypto)
        network = NetworkIdentity.model_validate_json(canonicalize(paid["network_identity"]))
        output = tmp_path / "swap.age"
        _write_recovery_snapshot(
            output,
            canonicalize(reserved),
            canonicalize(paid),
            network,
            credentials=credentials,
            crypto=crypto,
        )
    trusted = tmp_path / "network.json"
    trusted.write_text(json.dumps(reserved["network_identity"]))
    identity = tmp_path / "identity"
    identity.write_text(credentials.identity + "\n")
    identity.chmod(0o600)

    def forbidden(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("recovery inspection must not network or sign")

    monkeypatch.setattr(httpx, "Client", forbidden)
    monkeypatch.setattr(swap_command, "RelayConnection", forbidden)
    monkeypatch.setattr(Context, "musig_begin", forbidden)
    monkeypatch.setattr(Context, "schnorr_sign", forbidden)
    monkeypatch.setattr(MusigAttempt, "partial_sign_once", forbidden)
    assert (
        main.main(
            [
                "recover",
                "inspect",
                "--network",
                str(trusted),
                "--crypto-library",
                str(LIBRARY),
                "--identity",
                str(identity),
                str(tmp_path / "swap.age.cooperating"),
            ]
        )
        == 0
    )
    captured = capsys.readouterr()
    assert captured.err == ""
    assert reserved["user_secret"]["contract_secret_key"] not in captured.out
    assert reserved["monotonic_knowledge"]["preimage"] not in captured.out


@pytest.mark.parametrize("reserved_snapshot", [False, True])
def test_native_reservation_never_blocks_independent_unilateral_refund(
    monkeypatch: pytest.MonkeyPatch,
    *,
    reserved_snapshot: bool,
) -> None:
    with Context(library_path=LIBRARY) as crypto:
        _, _, paid, reserved = _snapshots(crypto)
        document = reserved if reserved_snapshot else paid
        terms = ContractTerms.model_validate_json(
            canonicalize(document["contract_terms"]), strict=True
        )
        binding = document["funding_history"][0]["binding"]
        funding = FundingOutput(
            txid=bytes.fromhex(binding["funding_txid"]),
            output_index=binding["contract_vout"],
            value_sat=int(binding["contract_value_sat"]),
            script_pubkey=bytes.fromhex(binding["contract_script_pubkey"]),
        )

        def forbidden(*_args: object, **_kwargs: object) -> None:
            raise AssertionError("unilateral recovery must never allocate a cooperative nonce")

        monkeypatch.setattr(crypto, "musig_begin", forbidden)
        monkeypatch.setattr(MusigAttempt, "partial_sign_once", forbidden)
        monkeypatch.setattr(httpx, "Client", forbidden)
        raw = construct_selected_recovery_refund(
            canonicalize(document),
            terms.network_identity,
            funding_attempt_id=binding["funding_attempt_id"],
            binding_revision=0,
            live_funding=funding,
            sampled_tip_height=terms.refund_lock_height + 1,
            fee_sat=300,
            auxiliary_random=b"\x33" * 32,
            crypto=crypto,
        )
        checked = validate_unilateral_spend(
            raw,
            UnilateralAuthorization.from_terms(terms, funding, "refund", keys=crypto),
            verifier=crypto,
        )
        assert checked.fee_sat == 300
        assert document["monotonic_knowledge"] == paid["monotonic_knowledge"]
