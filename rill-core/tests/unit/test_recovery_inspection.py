from __future__ import annotations

import copy
import hashlib
import json
from dataclasses import fields
from pathlib import Path
from typing import Any

import pytest

from rill_core.errors import CanonicalizationError, ValidationError
from rill_core.recovery import (
    OfflineRecoveryInspection,
    construct_selected_recovery_claim,
    construct_selected_recovery_refund,
    inspect_recovery_plaintext,
    inspect_recovery_selected_funding_binding,
    inspect_recovery_selected_funding_context,
    inspect_recovery_successor,
)
from rill_core.settlement import (
    FundingOutput,
    SignedFundingBinding,
    verify_static_signed_funding_binding_history,
)
from rill_core.wire.canonical import canonicalize, parse_json_strict
from rill_core.wire.hashes import (
    COOPERATIVE_CLAIM_FEATURE,
    client_acceptance_hash,
    contract_hash,
    funding_binding_hash,
    handshake_accept_hash,
    handshake_hash,
    handshake_init_hash,
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
from rill_core.wire.types import NetworkIdentity

FIXTURES = Path(__file__).parents[1] / "fixtures" / "recovery-v1"
TAPROOT = Path(__file__).parents[1] / "fixtures" / "settlement-v1" / "taproot-cases-v1.json"


def _source() -> dict[str, Any]:
    manifest = json.loads((FIXTURES / "manifest.json").read_text())
    contents = (FIXTURES / manifest["fixture_path"]).read_bytes()
    assert hashlib.sha256(contents).hexdigest() == manifest["sha256"]
    return json.loads(contents)


def _canonical(value: dict[str, Any]) -> bytes:
    return canonicalize(value)


def _network(value: dict[str, Any]) -> NetworkIdentity:
    return NetworkIdentity.model_validate(value["network_identity"])


class FixtureCrypto:
    """Pinned fixture signatures only, not a replacement for native verification."""

    def __init__(self, reference: dict[str, Any], taproot: dict[str, Any]) -> None:
        self.terms = ContractTerms.model_validate_json(json.dumps(reference["contract_terms"]))
        self.artifacts = taproot
        self.secret = bytes.fromhex(reference["user_secret"]["contract_secret_key"])
        self.calls: list[tuple[bytes, bytes, bytes]] = []
        self.permitted: set[tuple[bytes, bytes, bytes]] = set()
        context = reference["verification_context"]
        initiation = HandshakeInit.model_validate_json(json.dumps(context["handshake_init"]))
        acceptance = HandshakeAccept.model_validate_json(json.dumps(context["handshake_accept"]))
        signed_terms = ProviderTerms(
            contract_hash=contract_hash(self.terms).hex(),
            contract_terms=self.terms,
            handshake_hash=handshake_hash(initiation, acceptance).hex(),
        )
        acceptance_of_terms = ClientAcceptance(
            contract_hash=signed_terms.contract_hash,
            handshake_hash=signed_terms.handshake_hash,
            session_id=initiation.session_id,
            client_session_xonly_key=initiation.client_session_xonly_key,
            provider_session_xonly_key=acceptance.provider_session_xonly_key,
        )
        for key, digest, signature in (
            (
                self.terms.provider_identity_key,
                handshake_accept_hash(acceptance),
                context["provider_identity_signature"],
            ),
            (
                self.terms.provider_identity_key,
                provider_terms_hash(signed_terms),
                context["provider_terms_signature"],
            ),
            (
                initiation.client_session_xonly_key,
                client_acceptance_hash(acceptance_of_terms),
                context["client_acceptance_signature"],
            ),
        ):
            self.allow(key, digest, signature)

    def allow(self, key: str, digest: bytes, signature: str) -> None:
        self.permitted.add((bytes.fromhex(key), digest, bytes.fromhex(signature)))

    def schnorr_verify(self, public_key: bytes, message: bytes, signature: bytes) -> None:
        call = (public_key, message, signature)
        self.calls.append(call)
        if call not in self.permitted:
            raise RuntimeError("fixture signature rejected")

    def public_key(self, secret_key: bytes) -> bytes:
        if secret_key != self.secret:
            raise RuntimeError("unknown fixture secret")
        return bytes.fromhex(self.terms.client_contract_compressed_key)

    def musig_internal_key(self, client: bytes, provider: bytes) -> tuple[bytes, int]:
        assert client == bytes.fromhex(self.terms.client_contract_compressed_key)
        assert provider == bytes.fromhex(self.terms.provider_contract_compressed_key)
        return bytes.fromhex(self.artifacts["internal_key"]), self.artifacts["internal_parity"]

    def musig_output_key(
        self, client: bytes, provider: bytes, tap_tweak: bytes
    ) -> tuple[bytes, int]:
        assert client == bytes.fromhex(self.terms.client_contract_compressed_key)
        assert provider == bytes.fromhex(self.terms.provider_contract_compressed_key)
        assert tap_tweak == bytes.fromhex(self.artifacts["tap_tweak"])
        return bytes.fromhex(self.artifacts["output_key"]), self.artifacts["output_parity"]


def _crypto(reference: dict[str, Any]) -> FixtureCrypto:
    valid = json.loads(TAPROOT.read_text())["valid"]
    taproot = next(
        item["artifacts"] for item in valid if item["contract_terms"] == reference["contract_terms"]
    )
    return FixtureCrypto(reference, taproot)


def _inspect(
    document: dict[str, Any], *, reference: dict[str, Any] | None = None
) -> OfflineRecoveryInspection:
    pinned = _source() if reference is None else reference
    return inspect_recovery_plaintext(
        _canonical(document), _network(pinned), crypto=_crypto(pinned)
    )


def test_initial_recovery_inspection_is_redacted_and_not_action_authority() -> None:
    document = _source()
    report = _inspect(document)
    assert report.network_name == "regtest"
    assert report.profile_id == "btc-to-ln/v1"
    assert report.refund_lock_height == 1100
    assert report.first_refund_eligible_height == 1101
    assert report.recorded_binding_count == 0
    assert len(report.unproven) == 4
    assert {field.name for field in fields(report)} == {
        "network_name",
        "profile_id",
        "refund_lock_height",
        "first_refund_eligible_height",
        "recorded_binding_count",
        "unproven",
    }
    assert document["user_secret"]["contract_secret_key"] not in repr(report)
    assert document["verification_context"]["provider_terms_signature"] not in repr(report)


def test_plaintext_requires_canonical_bytes_and_bounded_duplicate_safe_parser() -> None:
    document = _source()
    crypto = _crypto(document)
    network = _network(document)
    pretty = (FIXTURES / "initial-btc-to-ln-v1.json").read_bytes()
    for invalid in (
        pretty,
        b"\xef\xbb\xbf" + _canonical(document),
        b'{"format":"rillswap-recovery","format":"rillswap-recovery"}',
        b'{"unexpected":"\\ud800"}',
        b"[" * 18 + b"0" + b"]" * 18,
        b" " * (128 * 1024 + 1),
        b"{}",
    ):
        with pytest.raises(
            ValidationError, match="invalid or unsupported recovery plaintext"
        ) as error:
            inspect_recovery_plaintext(invalid, network, crypto=crypto)
        assert error.value.__cause__ is None
        assert error.value.__context__ is None
    with pytest.raises(CanonicalizationError, match="protocol limit"):
        parse_json_strict(b" " * (16 * 1024 + 1))
    assert parse_json_strict(b" " * (16 * 1024 + 1) + b"0", max_bytes=32 * 1024) == 0


@pytest.mark.parametrize("field", ["format", "format_version", "specification_version"])
def test_older_unknown_or_missing_version_cannot_be_inspected(field: str) -> None:
    document = _source()
    for change in (None, "unknown"):
        changed = copy.deepcopy(document)
        if change is None:
            del changed[field]
        else:
            changed[field] = change
        with pytest.raises(ValidationError):
            _inspect(changed)


@pytest.mark.parametrize(
    ("area", "field", "value"),
    [
        ("verification_context", "provider_identity_signature", "00" * 64),
        ("verification_context", "provider_terms_signature", "00" * 64),
        ("verification_context", "client_acceptance_signature", "00" * 64),
        ("verification_context", "handshake_hash", "00" * 32),
        ("", "contract_hash", "00" * 32),
        ("", "profile_id", "ln-to-btc/v1"),
        ("", "created_at", 1700000101),
    ],
)
def test_wrong_signed_context_or_metadata_is_rejected(area: str, field: str, value: object) -> None:
    document = _source()
    if field == "created_at":
        value = document["updated_at"] + 1
    target = document[area] if area else document
    target[field] = value
    with pytest.raises(ValidationError):
        _inspect(document)


def test_inspection_never_treats_package_timestamps_as_present_day_eligibility() -> None:
    document = _source()
    assert document["contract_terms"]["terms_expiry"] < 1800000000
    assert _inspect(document).recorded_binding_count == 0
    later = copy.deepcopy(document)
    later["updated_at"] += 10_000_000
    assert _inspect(later).recorded_binding_count == 0


@pytest.mark.parametrize(
    "artifact",
    [
        "internal_xonly_key",
        "internal_key_parity",
        "claim_script",
        "refund_script",
        "claim_leaf_hash",
        "refund_leaf_hash",
        "merkle_root",
        "tap_tweak",
        "output_xonly_key",
        "output_key_parity",
        "script_pubkey",
        "claim_control_block",
        "refund_control_block",
    ],
)
def test_each_stored_taproot_artifact_must_match_reconstruction(artifact: str) -> None:
    document = _source()
    value = document["taproot_contract"][artifact]
    document["taproot_contract"][artifact] = (
        1 - value if isinstance(value, int) else "00" + value[2:]
    )
    with pytest.raises(ValidationError):
        _inspect(document)


@pytest.mark.parametrize("parity", ["internal_key_parity", "output_key_parity"])
@pytest.mark.parametrize("boolean", [False, True])
def test_json_boolean_never_counts_as_a_numeric_taproot_parity(
    parity: str,
    boolean: bool,  # noqa: FBT001 - parity input must reject booleans
) -> None:
    document = _source()
    document["taproot_contract"][parity] = boolean
    with pytest.raises(ValidationError) as error:
        _inspect(document)
    assert error.value.__cause__ is None
    assert error.value.__context__ is None


def test_secret_preimage_network_fee_and_purpose_key_checks() -> None:
    original = _source()
    mutations = (
        ("user_secret", "contract_secret_key", "02" * 32),
        ("monotonic_knowledge", "preimage_known", True),
        ("monotonic_knowledge", "preimage", "00" * 32),
        ("fee_policy", "max_claim_fee_sat", "999"),
        ("verification_context", "provider_session_xonly_key", "00" * 32),
        ("", "recovery_authorization_xonly_key", "00" * 32),
        ("", "chain_scan_birthday_height", 1200),
    )
    for area, field, value in mutations:
        changed = copy.deepcopy(original)
        target = changed[area] if area else changed
        target[field] = value
        with pytest.raises(ValidationError):
            _inspect(changed)
    changed = copy.deepcopy(original)
    changed["network_identity"]["deployment_namespace"] = "different"
    with pytest.raises(ValidationError):
        _inspect(changed)
    changed = copy.deepcopy(original)
    changed["contract_terms"]["client_contract_compressed_key"] = original["verification_context"][
        "handshake_init"
    ]["client_session_xonly_key"]
    with pytest.raises(ValidationError):
        _inspect(changed)


def _binding(document: dict[str, Any], revision: int) -> dict[str, Any]:
    return {
        "contract_hash": document["contract_hash"],
        "funding_attempt_id": "11" * 32,
        "binding_revision": revision,
        "funder_role": "client" if document["profile_id"] == "btc-to-ln/v1" else "provider",
        "lineage_anchor_txid": "33" * 32,
        "lineage_anchor_vout": 0,
        "funding_txid": f"{revision + 34:02x}" * 32,
        "contract_vout": revision + 1,
        "contract_value_sat": document["contract_terms"]["economics"]["contract_amount_sat"],
        "contract_script_pubkey": document["taproot_contract"]["script_pubkey"],
        "replaces_txid": f"{revision + 33:02x}" * 32 if revision else None,
        "created_at": 1700000200 + revision,
    }


def _add_history(document: dict[str, Any], crypto: FixtureCrypto, revisions: int) -> None:
    session = document["verification_context"][
        "client_session_xonly_key"
        if document["profile_id"] == "btc-to-ln/v1"
        else "provider_session_xonly_key"
    ]
    for revision in range(revisions):
        binding = _binding(document, revision)
        signature = f"{revision + 1:02x}" * 64
        crypto.allow(
            session, funding_binding_hash(FundingBinding.model_validate(binding)), signature
        )
        document["funding_history"].append(
            {
                "binding": binding,
                "funder_session_signature": signature,
            }
        )


def test_selected_recovery_binding_requires_full_history_and_explicit_revision() -> None:
    document = _source()
    crypto = _crypto(document)
    _add_history(document, crypto, 2)
    for revision in (0, 1):
        selected = inspect_recovery_selected_funding_binding(
            _canonical(document),
            _network(document),
            funding_attempt_id="11" * 32,
            binding_revision=revision,
            crypto=crypto,
        )
        assert selected == FundingBinding.model_validate(
            document["funding_history"][revision]["binding"]
        )
        assert selected.binding_revision == revision
        assert "user_secret" not in repr(selected)
        assert document["user_secret"]["contract_secret_key"] not in repr(selected)
        assert "funder_session_signature" not in repr(selected)
    changed = copy.deepcopy(document)
    changed["funding_history"][1]["binding"]["contract_value_sat"] = "1"
    with pytest.raises(ValidationError, match="invalid or unavailable recovery funding binding"):
        inspect_recovery_selected_funding_binding(
            _canonical(changed),
            _network(changed),
            funding_attempt_id="11" * 32,
            binding_revision=0,
            crypto=crypto,
        )


def test_selected_public_context_excludes_secrets_and_cannot_skip_bad_history() -> None:
    document = _source()
    crypto = _crypto(document)
    _add_history(document, crypto, 2)
    selected = inspect_recovery_selected_funding_context(
        _canonical(document),
        _network(document),
        funding_attempt_id="11" * 32,
        binding_revision=0,
        crypto=crypto,
    )
    assert selected.terms == ContractTerms.model_validate_json(
        json.dumps(document["contract_terms"])
    )
    assert selected.binding == FundingBinding.model_validate_json(
        json.dumps(document["funding_history"][0]["binding"])
    )
    assert {field.name for field in fields(selected)} == {"terms", "binding"}
    assert document["user_secret"]["contract_secret_key"] not in repr(selected)
    assert "monotonic_knowledge" not in repr(selected)
    assert document["funding_history"][0]["funder_session_signature"] not in repr(selected)
    corrupted = copy.deepcopy(document)
    corrupted["funding_history"][1]["binding"]["contract_value_sat"] = "1"
    with pytest.raises(ValidationError, match="invalid or unavailable recovery funding context"):
        inspect_recovery_selected_funding_context(
            _canonical(corrupted),
            _network(corrupted),
            funding_attempt_id="11" * 32,
            binding_revision=0,
            crypto=crypto,
        )


def test_refund_construction_requires_exact_selected_record_and_maturity(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    document = _source()
    crypto = _crypto(document)
    _add_history(document, crypto, 1)
    binding = FundingBinding.model_validate(document["funding_history"][0]["binding"])
    funding = FundingOutput(
        bytes.fromhex(binding.funding_txid),
        binding.contract_vout,
        int(binding.contract_value_sat),
        bytes.fromhex(binding.contract_script_pubkey),
    )
    signed: list[bytes] = []

    def sign(secret: bytes, digest: bytes, auxiliary: bytes) -> bytes:
        assert secret.hex() == document["user_secret"]["contract_secret_key"]
        assert auxiliary == b"\x55" * 32
        signed.append(digest)
        crypto.allow(
            document["contract_terms"]["client_contract_compressed_key"][2:], digest, "44" * 64
        )
        return b"\x44" * 64

    monkeypatch.setattr(crypto, "schnorr_sign", sign, raising=False)
    options: dict[str, Any] = {
        "funding_attempt_id": binding.funding_attempt_id,
        "binding_revision": 0,
        "live_funding": funding,
        "sampled_tip_height": document["contract_terms"]["refund_lock_height"] + 1,
        "fee_sat": 200,
        "auxiliary_random": b"\x55" * 32,
        "crypto": crypto,
    }

    def construct(record: dict[str, Any] = document, **changes: object) -> bytes:
        arguments = {**options, **changes}
        return construct_selected_recovery_refund(_canonical(record), _network(record), **arguments)

    raw = construct()
    assert raw.startswith(b"\x02\x00\x00\x00")
    assert len(signed) == 1
    rejected = (
        {"sampled_tip_height": document["contract_terms"]["refund_lock_height"]},
        {"binding_revision": 1},
        {"funding_attempt_id": "00" * 32},
        {
            "live_funding": FundingOutput(
                funding.txid, funding.output_index, funding.value_sat + 1, funding.script_pubkey
            )
        },
        {
            "live_funding": FundingOutput(
                b"\xee" * 32,
                funding.output_index,
                funding.value_sat,
                funding.script_pubkey,
            )
        },
        {
            "live_funding": FundingOutput(
                funding.txid,
                funding.output_index + 1,
                funding.value_sat,
                funding.script_pubkey,
            )
        },
        {
            "live_funding": FundingOutput(
                funding.txid,
                funding.output_index,
                funding.value_sat,
                b"\x51\x20" + b"\xaa" * 32,
            )
        },
        {"fee_sat": int(document["contract_terms"]["max_refund_fee_sat"]) + 1},
        {"auxiliary_random": b"\x00"},
    )
    for mismatch in rejected:
        with pytest.raises(ValidationError, match="recovery refund construction refused") as error:
            construct(**mismatch)
        assert error.value.__cause__ is None
        assert error.value.__context__ is None
    assert len(signed) == 1
    invalid = copy.deepcopy(document)
    invalid["funding_history"][0]["funder_session_signature"] = "00" * 64
    with pytest.raises(ValidationError, match="recovery refund construction refused"):
        construct(invalid)
    assert len(signed) == 1

    monkeypatch.setattr(crypto, "schnorr_sign", lambda *_args: b"\x00" * 64, raising=False)
    with pytest.raises(ValidationError, match="recovery refund construction refused") as error:
        construct()
    assert error.value.__context__ is None
    assert error.value.__cause__ is None

    def leak(secret: bytes, *_args: bytes) -> bytes:
        raise OSError("secret-bearing native failure: " + secret.hex())

    monkeypatch.setattr(crypto, "schnorr_sign", leak, raising=False)
    with pytest.raises(ValidationError, match="recovery refund construction refused") as error:
        construct()
    assert document["user_secret"]["contract_secret_key"] not in repr(error.value)
    assert error.value.__context__ is None
    assert error.value.__cause__ is None


def test_claim_preparation_is_secret_bearing_but_not_disclosure_authority(  # noqa: PLR0915 - negative matrix
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    document: dict[str, Any] = json.loads(
        (FIXTURES / "initial-ln-to-btc-no-prepayment-v1.json").read_bytes()
    )
    other = next(
        item
        for item in json.loads(TAPROOT.read_text())["valid"]
        if item["profile_id"] == "ln-to-btc/v1"
    )
    crypto = FixtureCrypto(document, other["artifacts"])
    _add_history(document, crypto, 1)
    binding = FundingBinding.model_validate(document["funding_history"][0]["binding"])
    funding = FundingOutput(
        bytes.fromhex(binding.funding_txid),
        binding.contract_vout,
        int(binding.contract_value_sat),
        bytes.fromhex(binding.contract_script_pubkey),
    )
    knowledge = document["monotonic_knowledge"]
    assert knowledge["preimage_known"] is True
    preimage = bytes.fromhex(knowledge["preimage"])
    calls: list[bytes] = []

    def sign(secret: bytes, digest: bytes, auxiliary: bytes) -> bytes:
        assert secret.hex() == document["user_secret"]["contract_secret_key"]
        assert auxiliary == b"\x55" * 32
        calls.append(digest)
        crypto.allow(
            document["contract_terms"]["client_contract_compressed_key"][2:], digest, "44" * 64
        )
        return b"\x44" * 64

    monkeypatch.setattr(crypto, "schnorr_sign", sign, raising=False)
    options: dict[str, Any] = {
        "funding_attempt_id": binding.funding_attempt_id,
        "binding_revision": binding.binding_revision,
        "live_funding": funding,
        "sampled_tip_height": 1094,
        "sampled_confirmations": 2,
        "fee_sat": 200,
        "auxiliary_random": b"\x55" * 32,
        "crypto": crypto,
    }

    def construct(record: dict[str, Any] = document, **changes: object) -> bytes:
        return construct_selected_recovery_claim(
            _canonical(record),
            _network(document),
            **{**options, **changes},
        )

    raw = construct()
    assert preimage in raw  # Witness reveals it, so never publish this result by default.
    assert len(calls) == 1
    failures = (
        {"sampled_confirmations": 1},
        {"sampled_confirmations": True},
        {"sampled_confirmations": 1096},
        {"sampled_tip_height": 1095},  # h + delta == T + 1 is insufficient.
        {"sampled_tip_height": False},
        {"sampled_tip_height": -1},
        {"funding_attempt_id": "00" * 32},
        {"binding_revision": 1},
        {
            "live_funding": FundingOutput(
                funding.txid, funding.output_index, funding.value_sat + 1, funding.script_pubkey
            )
        },
        {"fee_sat": int(document["contract_terms"]["max_claim_fee_sat"]) + 1},
        {"auxiliary_random": b"\x00"},
    )
    for mismatch in failures:
        with pytest.raises(ValidationError, match="recovery claim preparation refused") as error:
            construct(**mismatch)
        assert error.value.__cause__ is None
        assert error.value.__context__ is None
    assert len(calls) == 1
    for mutation in ("no-preimage", "wrong-preimage", "wrong-key", "wrong-history"):
        changed = copy.deepcopy(document)
        if mutation == "no-preimage":
            changed["monotonic_knowledge"].update(preimage_known=False, preimage=None)
        elif mutation == "wrong-preimage":
            changed["monotonic_knowledge"]["preimage"] = "00" * 32
        elif mutation == "wrong-key":
            changed["user_secret"]["contract_secret_key"] = "01" * 32
        else:
            changed["funding_history"][0]["funder_session_signature"] = "00" * 64
        with pytest.raises(ValidationError, match="recovery claim preparation refused"):
            construct(changed)
    assert len(calls) == 1
    monkeypatch.setattr(crypto, "schnorr_sign", lambda *_args: b"\x00" * 64, raising=False)
    with pytest.raises(ValidationError, match="recovery claim preparation refused") as error:
        construct()
    assert error.value.__context__ is None
    assert error.value.__cause__ is None

    def leak(secret: bytes, *_args: bytes) -> bytes:
        raise OSError("secret-bearing native failure: " + secret.hex())

    monkeypatch.setattr(crypto, "schnorr_sign", leak, raising=False)
    with pytest.raises(ValidationError, match="recovery claim preparation refused") as error:
        construct()
    assert document["user_secret"]["contract_secret_key"] not in repr(error.value)
    assert error.value.__context__ is None
    assert error.value.__cause__ is None


@pytest.mark.parametrize(
    "selector",
    [
        ("22" * 32, 0),
        ("11" * 32, 2),
        ("broken", 0),
        ("11" * 32, True),
        ("11" * 32, -1),
    ],
)
def test_selected_recovery_binding_never_infers_missing_or_invalid_history(
    selector: tuple[str, int],
) -> None:
    document = _source()
    crypto = _crypto(document)
    _add_history(document, crypto, 2)
    with pytest.raises(
        ValidationError, match="invalid or unavailable recovery funding binding"
    ) as error:
        inspect_recovery_selected_funding_binding(
            _canonical(document),
            _network(document),
            funding_attempt_id=selector[0],
            binding_revision=selector[1],
            crypto=crypto,
        )
    assert error.value.__cause__ is None
    assert error.value.__context__ is None


def test_selected_recovery_binding_rejects_absent_and_unsupported_history() -> None:
    document = _source()
    crypto = _crypto(document)
    with pytest.raises(ValidationError, match="invalid or unavailable recovery funding binding"):
        inspect_recovery_selected_funding_binding(
            _canonical(document),
            _network(document),
            funding_attempt_id="11" * 32,
            binding_revision=0,
            crypto=crypto,
        )
    _add_history(document, crypto, 1)
    document["format_version"] = "older"
    with pytest.raises(ValidationError, match="invalid or unavailable recovery funding binding"):
        inspect_recovery_selected_funding_binding(
            _canonical(document),
            _network(document),
            funding_attempt_id="11" * 32,
            binding_revision=0,
            crypto=crypto,
        )


def test_selected_recovery_binding_redacts_nonstandard_crypto_adapter_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    document = _source()
    crypto = _crypto(document)
    _add_history(document, crypto, 1)

    def fail(secret: bytes) -> bytes:
        raise OSError("secret-bearing adapter failure: " + secret.hex())

    monkeypatch.setattr(crypto, "public_key", fail)
    with pytest.raises(
        ValidationError, match="invalid or unavailable recovery funding binding"
    ) as error:
        inspect_recovery_selected_funding_binding(
            _canonical(document),
            _network(document),
            funding_attempt_id="11" * 32,
            binding_revision=0,
            crypto=crypto,
        )
    assert document["user_secret"]["contract_secret_key"] not in repr(error.value)
    assert error.value.__cause__ is None
    assert error.value.__context__ is None


def test_signature_checked_history_is_not_live_transaction_evidence() -> None:
    document = _source()
    crypto = _crypto(document)
    _add_history(document, crypto, 2)
    report = inspect_recovery_plaintext(_canonical(document), _network(document), crypto=crypto)
    assert report.recorded_binding_count == 2
    assert "funding transactions, conflicts, UTXOs, and chain maturity" in report.unproven
    for field, value in (
        ("funding_attempt_id", "00" * 32),
        ("binding_revision", 3),
        ("lineage_anchor_txid", "00" * 32),
        ("replaces_txid", "ff" * 32),
        ("funding_txid", document["funding_history"][0]["binding"]["funding_txid"]),
        ("contract_vout", 2**32),
    ):
        changed = copy.deepcopy(document)
        changed["funding_history"][1]["binding"][field] = value
        with pytest.raises(ValidationError):
            inspect_recovery_plaintext(_canonical(changed), _network(changed), crypto=crypto)
    overlong = copy.deepcopy(document)
    overlong["funding_history"] *= 33
    with pytest.raises(ValidationError):
        inspect_recovery_plaintext(_canonical(overlong), _network(overlong), crypto=crypto)


def test_failed_import_message_never_echoes_secret_or_signature() -> None:
    document = _source()
    secret = document["user_secret"]["contract_secret_key"]
    signature = document["verification_context"]["provider_terms_signature"]
    document["user_secret"]["unexpected"] = secret + signature
    with pytest.raises(ValidationError) as error:
        _inspect(document)
    assert secret not in str(error.value)
    assert signature not in str(error.value)
    assert error.value.__cause__ is None
    assert error.value.__context__ is None


def _ln_without_optional_feature() -> tuple[dict[str, Any], FixtureCrypto]:
    """Synthetic policy case; dummy fixture signatures are accepted by test port only."""
    document = _source()
    other = next(
        case
        for case in json.loads(TAPROOT.read_text())["valid"]
        if case["profile_id"] == "ln-to-btc/v1"
    )
    terms = copy.deepcopy(other["contract_terms"])
    terms["required_features"] = []
    terms["economics"]["mining_prepayment_sat"] = "0"
    terms["economics"]["hold_invoice_sat"] = "102000"
    terms["invoice_binding"]["amount_msat"] = "102000000"
    typed = ContractTerms.model_validate_json(json.dumps(terms))
    document["contract_terms"] = terms
    document["contract_hash"] = contract_hash(typed).hex()
    document["network_identity"] = terms["network_identity"]
    document["profile_id"] = "ln-to-btc/v1"
    document["fee_policy"] = {
        "max_claim_fee_sat": terms["max_claim_fee_sat"],
        "max_refund_fee_sat": terms["max_refund_fee_sat"],
    }
    document["recovery_authorization_xonly_key"] = terms["recovery_authorization_xonly_key"]
    document["user_secret"]["contract_secret_key"] = other["fixture_keys"][
        "client_contract_secret_key"
    ]
    mapping = {
        "internal_xonly_key": "internal_key",
        "internal_key_parity": "internal_parity",
        "output_xonly_key": "output_key",
        "output_key_parity": "output_parity",
    }
    for field in document["taproot_contract"]:
        document["taproot_contract"][field] = other["artifacts"][mapping.get(field, field)]
    document["monotonic_knowledge"] = {
        "preimage_known": True,
        "preimage": other["claim_preimage"],
        "dangerous_signature_issued": False,
    }
    context = document["verification_context"]
    context["handshake_init"]["profile_id"] = "ln-to-btc/v1"
    context["handshake_accept"]["profile_id"] = "ln-to-btc/v1"
    init = HandshakeInit.model_validate_json(json.dumps(context["handshake_init"]))
    context["handshake_accept"]["handshake_init_hash"] = handshake_init_hash(init).hex()
    accept = HandshakeAccept.model_validate_json(json.dumps(context["handshake_accept"]))
    context["handshake_hash"] = handshake_hash(init, accept).hex()
    for key in (
        "provider_identity_signature",
        "provider_terms_signature",
        "client_acceptance_signature",
    ):
        context[key] = "11" * 64
    return document, FixtureCrypto(document, other["artifacts"])


def test_ln_to_btc_requires_client_preimage_from_initial_export() -> None:
    document, crypto = _ln_without_optional_feature()
    report = inspect_recovery_plaintext(_canonical(document), _network(document), crypto=crypto)
    assert report.profile_id == "ln-to-btc/v1"
    for known, preimage in ((False, None), (True, None), (True, "00" * 32)):
        changed = copy.deepcopy(document)
        changed["monotonic_knowledge"]["preimage_known"] = known
        changed["monotonic_knowledge"]["preimage"] = preimage
        with pytest.raises(ValidationError):
            inspect_recovery_plaintext(_canonical(changed), _network(document), crypto=crypto)


def test_pinned_signed_ln_no_prepayment_object_is_accepted_only_with_preimage() -> None:
    manifest = json.loads((FIXTURES / "ln-no-prepayment-manifest.json").read_text())
    contents = (FIXTURES / manifest["fixture_path"]).read_bytes()
    assert hashlib.sha256(contents).hexdigest() == manifest["sha256"]
    document: dict[str, Any] = json.loads(contents)
    assert document["contract_terms"]["required_features"] == []
    assert document["verification_context"]["handshake_init"]["required_features"] == []
    assert document["verification_context"]["handshake_accept"]["required_features"] == []
    original_taproot = next(
        item["artifacts"]
        for item in json.loads(TAPROOT.read_text())["valid"]
        if item["profile_id"] == "ln-to-btc/v1"
    )
    crypto = FixtureCrypto(document, original_taproot)
    report = inspect_recovery_plaintext(_canonical(document), _network(document), crypto=crypto)
    assert report.profile_id == "ln-to-btc/v1"
    assert report.recorded_binding_count == 0
    assert "funding transactions, conflicts, UTXOs, and chain maturity" in report.unproven
    without_preimage = copy.deepcopy(document)
    without_preimage["monotonic_knowledge"] = {
        "preimage_known": False,
        "preimage": None,
        "dangerous_signature_issued": False,
    }
    with pytest.raises(ValidationError):
        inspect_recovery_plaintext(_canonical(without_preimage), _network(document), crypto=crypto)


def test_unknown_required_features_reject_before_crypto_signatures() -> None:
    document = _source()
    crypto = _crypto(document)
    document["contract_terms"]["required_features"] = ["example/unknown-feature/v1"]
    with pytest.raises(ValidationError):
        inspect_recovery_plaintext(_canonical(document), _network(document), crypto=crypto)
    assert crypto.calls == []


def _successor(
    previous: dict[str, Any], candidate: dict[str, Any], crypto: FixtureCrypto
) -> OfflineRecoveryInspection:
    return inspect_recovery_successor(
        _canonical(previous), _canonical(candidate), _network(previous), crypto=crypto
    )


def test_explicit_successor_preserves_signed_history_and_known_observations() -> None:
    original = _source()
    crypto = _crypto(original)
    previous = copy.deepcopy(original)
    _add_history(previous, crypto, 1)
    candidate = copy.deepcopy(previous)
    candidate["funding_history"] = []
    _add_history(candidate, crypto, 2)
    candidate["updated_at"] += 1
    candidate["chain_scan_birthday_height"] -= 1
    candidate["monotonic_knowledge"]["dangerous_signature_issued"] = True
    report = _successor(previous, candidate, crypto)
    assert report.recorded_binding_count == 2
    assert original["user_secret"]["contract_secret_key"] not in repr(report)
    # Equal timestamps and identical snapshots are allowed, but not proof of freshness.
    assert _successor(previous, previous, crypto).recorded_binding_count == 1


@pytest.mark.parametrize(
    "changed_field",
    [
        "created_at",
        "updated_at",
        "birthday",
        "history",
        "dangerous",
        "extensions",
    ],
)
def test_successor_rejects_immutable_or_monotonic_regression(changed_field: str) -> None:
    previous = _source()
    crypto = _crypto(previous)
    previous["monotonic_knowledge"]["dangerous_signature_issued"] = True
    _add_history(previous, crypto, 1)
    candidate = copy.deepcopy(previous)
    if changed_field == "created_at":
        candidate["created_at"] -= 1
    elif changed_field == "updated_at":
        candidate["updated_at"] -= 1
    elif changed_field == "birthday":
        candidate["chain_scan_birthday_height"] += 1
    elif changed_field == "history":
        candidate["funding_history"] = []
    elif changed_field == "dangerous":
        candidate["monotonic_knowledge"]["dangerous_signature_issued"] = False
    else:
        candidate["extensions"]["example.invalid/key"] = "changed"
    with pytest.raises(
        ValidationError, match="invalid or nonmonotonic recovery successor"
    ) as error:
        _successor(previous, candidate, crypto)
    assert error.value.__cause__ is None
    assert error.value.__context__ is None


@pytest.mark.parametrize(
    ("original", "changed"),
    [
        (True, 1),
        (False, 0),
        ({"nested": [True]}, {"nested": [1]}),
        ({"nested": [False]}, {"nested": [0]}),
        ("first", "second"),
    ],
)
def test_immutable_extension_json_types_are_preserved(original: object, changed: object) -> None:
    previous = _source()
    crypto = _crypto(previous)
    previous["extensions"]["example.invalid/type"] = original
    candidate = copy.deepcopy(previous)
    candidate["extensions"]["example.invalid/type"] = changed
    network = _network(previous)
    assert inspect_recovery_plaintext(_canonical(previous), network, crypto=crypto)
    assert inspect_recovery_plaintext(_canonical(candidate), network, crypto=crypto)
    assert _successor(previous, previous, crypto)
    with pytest.raises(ValidationError, match="invalid or nonmonotonic recovery successor"):
        _successor(previous, candidate, crypto)


def test_successor_rejects_missing_corrupt_and_unsupported_prior_without_mutation() -> None:
    previous = _source()
    crypto = _crypto(previous)
    candidate = copy.deepcopy(previous)
    candidate["updated_at"] += 1
    for prior in (
        b"",
        b"{",
        b"{}",
        _canonical({**previous, "format_version": "older"}),
    ):
        with pytest.raises(ValidationError, match="invalid or nonmonotonic recovery successor"):
            inspect_recovery_successor(
                prior, _canonical(candidate), _network(previous), crypto=crypto
            )
    assert _successor(previous, candidate, crypto).recorded_binding_count == 0


def test_successor_cannot_forget_initial_ln_preimage() -> None:
    manifest = json.loads((FIXTURES / "ln-no-prepayment-manifest.json").read_text())
    previous = json.loads((FIXTURES / manifest["fixture_path"]).read_text())
    other = next(
        item
        for item in json.loads(TAPROOT.read_text())["valid"]
        if item["profile_id"] == "ln-to-btc/v1"
    )
    crypto = FixtureCrypto(previous, other["artifacts"])
    candidate = copy.deepcopy(previous)
    candidate["updated_at"] += 1
    assert _successor(previous, candidate, crypto).profile_id == "ln-to-btc/v1"
    candidate["monotonic_knowledge"] = {
        "preimage_known": False,
        "preimage": None,
        "dangerous_signature_issued": False,
    }
    with pytest.raises(ValidationError):
        _successor(previous, candidate, crypto)


def test_successor_can_learn_btc_preimage_but_never_forget_it() -> None:
    previous = _source()
    crypto = _crypto(previous)
    learned = copy.deepcopy(previous)
    learned["monotonic_knowledge"].update({"preimage_known": True, "preimage": "42" * 32})
    assert _successor(previous, learned, crypto).profile_id == "btc-to-ln/v1"
    with pytest.raises(ValidationError, match="invalid or nonmonotonic recovery successor"):
        _successor(learned, previous, crypto)


def test_successor_rejects_divergent_but_independently_signed_history() -> None:
    previous = _source()
    crypto = _crypto(previous)
    _add_history(previous, crypto, 1)
    candidate = copy.deepcopy(previous)
    other = candidate["funding_history"][0]
    other["binding"]["funding_txid"] = "44" * 32
    other["funder_session_signature"] = "aa" * 64
    crypto.allow(
        candidate["verification_context"]["client_session_xonly_key"],
        funding_binding_hash(FundingBinding.model_validate(other["binding"])),
        other["funder_session_signature"],
    )
    assert (
        inspect_recovery_plaintext(
            _canonical(candidate), _network(previous), crypto=crypto
        ).recorded_binding_count
        == 1
    )
    with pytest.raises(ValidationError, match="invalid or nonmonotonic recovery successor"):
        _successor(previous, candidate, crypto)


def _signed_context(
    document: dict[str, Any],
    crypto: FixtureCrypto,
    *,
    trusted_key: str | None = None,
) -> None:
    context = document["verification_context"]
    terms = ContractTerms.model_validate_json(json.dumps(document["contract_terms"]))
    verify_static_signed_funding_binding_history(
        terms=terms,
        handshake_init=HandshakeInit.model_validate_json(json.dumps(context["handshake_init"])),
        handshake_accept=HandshakeAccept.model_validate_json(
            json.dumps(context["handshake_accept"])
        ),
        provider_identity_signature=context["provider_identity_signature"],
        provider_terms_signature=context["provider_terms_signature"],
        client_acceptance_signature=context["client_acceptance_signature"],
        signed_bindings=tuple(
            SignedFundingBinding(
                FundingBinding.model_validate_json(json.dumps(item["binding"])),
                item["funder_session_signature"],
            )
            for item in document["funding_history"]
        ),
        expected_provider_identity=trusted_key or terms.provider_identity_key,
        expected_network=_network(document),
        crypto=crypto,
    )


@pytest.mark.parametrize("profile", ["btc-to-ln", "ln-to-btc"])
def test_static_signed_context_checks_both_profiles_without_funding_authority(profile: str) -> None:
    if profile == "btc-to-ln":
        document = _source()
    else:
        manifest = json.loads((FIXTURES / "ln-no-prepayment-manifest.json").read_text())
        document = json.loads((FIXTURES / manifest["fixture_path"]).read_text())
    if profile == "btc-to-ln":
        crypto = _crypto(document)
    else:
        other = next(
            item
            for item in json.loads(TAPROOT.read_text())["valid"]
            if item["profile_id"] == "ln-to-btc/v1"
        )
        crypto = FixtureCrypto(document, other["artifacts"])
    _add_history(document, crypto, 2)
    _signed_context(document, crypto)
    assert len(crypto.calls) == 5  # Three signed context objects plus two bindings.
    assert crypto.terms.network_identity == _network(document)


@pytest.mark.parametrize("profile", ["btc-to-ln", "ln-to-btc"])
def test_jointly_signed_cooperation_does_not_block_unilateral_recovery(
    profile: str,
) -> None:
    """A cooperative-first contract still admits offline recovery for both roles."""
    if profile == "btc-to-ln":
        document = _source()
        artifacts = _crypto(document).artifacts
    else:
        document, old_crypto = _ln_without_optional_feature()
        artifacts = old_crypto.artifacts
    context = document["verification_context"]
    feature = [COOPERATIVE_CLAIM_FEATURE]
    context["handshake_init"]["required_features"] = feature
    context["handshake_accept"]["required_features"] = feature
    init = HandshakeInit.model_validate_json(json.dumps(context["handshake_init"]))
    context["handshake_accept"]["handshake_init_hash"] = handshake_init_hash(init).hex()
    accept = HandshakeAccept.model_validate_json(json.dumps(context["handshake_accept"]))
    context["handshake_hash"] = handshake_hash(init, accept).hex()
    document["contract_terms"]["required_features"] = feature
    terms = ContractTerms.model_validate_json(json.dumps(document["contract_terms"]))
    document["contract_hash"] = contract_hash(terms).hex()
    # FixtureCrypto pins the exact changed digests; no native signing is simulated.
    for name in (
        "provider_identity_signature",
        "provider_terms_signature",
        "client_acceptance_signature",
    ):
        context[name] = "11" * 64
    crypto = FixtureCrypto(document, artifacts)
    assert inspect_recovery_plaintext(_canonical(document), _network(document), crypto=crypto)
    _add_history(document, crypto, 1)
    _signed_context(document, crypto)


@pytest.mark.parametrize(
    "part",
    [
        "trusted-provider",
        "network",
        "provider-identity-signature",
        "provider-terms-signature",
        "client-acceptance-signature",
        "handshake",
        "session",
        "contract-amount",
        "script",
        "funder",
        "revision",
        "predecessor",
        "anchor",
        "duplicate-txid",
        "binding-signature",
    ],
)
def test_static_signed_context_rejects_substitution_and_lineage_forks(  # noqa: PLR0912 - explicit adversarial cases
    part: str,
) -> None:
    document = _source()
    crypto = _crypto(document)
    _add_history(document, crypto, 2)
    changed = copy.deepcopy(document)
    trusted_key = None
    if part == "trusted-provider":
        trusted_key = "ee" * 32
    elif part == "network":
        changed["network_identity"]["deployment_namespace"] = "other"
    elif part in (
        "provider-identity-signature",
        "provider-terms-signature",
        "client-acceptance-signature",
    ):
        changed["verification_context"][part.replace("-", "_")] = "aa" * 64
    elif part == "handshake":
        changed["verification_context"]["handshake_accept"]["client_challenge"] = "ff" * 32
    elif part == "session":
        changed["verification_context"]["handshake_accept"]["provider_session_xonly_key"] = (
            "ee" * 32
        )
    elif part == "contract-amount":
        changed["funding_history"][0]["binding"]["contract_value_sat"] = "1"
    elif part == "script":
        changed["funding_history"][0]["binding"]["contract_script_pubkey"] = "5120" + "ee" * 32
    elif part == "funder":
        changed["funding_history"][0]["binding"]["funder_role"] = "provider"
    elif part == "revision":
        changed["funding_history"][1]["binding"]["binding_revision"] = 2
    elif part == "predecessor":
        changed["funding_history"][1]["binding"]["replaces_txid"] = "ee" * 32
    elif part == "anchor":
        changed["funding_history"][1]["binding"]["lineage_anchor_txid"] = "ee" * 32
    elif part == "duplicate-txid":
        changed["funding_history"][1]["binding"]["funding_txid"] = changed["funding_history"][0][
            "binding"
        ]["funding_txid"]
    else:
        changed["funding_history"][1]["funder_session_signature"] = "ee" * 64
    with pytest.raises(ValidationError, match="invalid static signed funding declaration") as error:
        _signed_context(changed, crypto, trusted_key=trusted_key)
    assert error.value.__cause__ is None
    assert error.value.__context__ is None


def test_static_signed_context_requires_nonempty_history_and_never_leaks_adapter_error() -> None:
    document = _source()
    crypto = _crypto(document)
    with pytest.raises(ValidationError, match="invalid static signed funding declaration"):
        _signed_context(document, crypto)
    _add_history(document, crypto, 1)
    crypto.permitted.clear()
    with pytest.raises(ValidationError, match="invalid static signed funding declaration") as error:
        _signed_context(document, crypto)
    assert error.value.__cause__ is None
    assert error.value.__context__ is None
    assert document["user_secret"]["contract_secret_key"] not in repr(error.value)


@pytest.mark.parametrize("field", ["attempt", "predecessor", "anchor", "duplicate-txid"])
def test_static_lineage_guards_reject_even_freshly_permitted_signature(field: str) -> None:
    document = _source()
    crypto = _crypto(document)
    _add_history(document, crypto, 2)
    later = document["funding_history"][1]
    if field == "attempt":
        later["binding"]["funding_attempt_id"] = "ee" * 32
    elif field == "predecessor":
        later["binding"]["replaces_txid"] = "ee" * 32
    elif field == "anchor":
        later["binding"]["lineage_anchor_txid"] = "ee" * 32
    else:
        later["binding"]["funding_txid"] = document["funding_history"][0]["binding"]["funding_txid"]
    crypto.allow(
        document["verification_context"]["client_session_xonly_key"],
        funding_binding_hash(FundingBinding.model_validate_json(json.dumps(later["binding"]))),
        later["funder_session_signature"],
    )
    with pytest.raises(ValidationError, match="invalid static signed funding declaration"):
        _signed_context(document, crypto)


def test_static_verifier_rejects_crypto_adapter_returning_false_instead_of_raising(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    document = _source()
    crypto = _crypto(document)
    _add_history(document, crypto, 1)
    monkeypatch.setattr(crypto, "schnorr_verify", lambda *_args: False)
    with pytest.raises(ValidationError, match="invalid static signed funding declaration"):
        _signed_context(document, crypto)
