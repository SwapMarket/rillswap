"""Encrypted lookup metadata is historical, never fresh or restored authority."""

from __future__ import annotations

import json
import os
import warnings
from pathlib import Path

import pyrage
import pytest
from pydantic import ValidationError
from pyrage import x25519
from rill_core.wire.canonical import canonicalize
from rill_core.wire.messages import FundingBinding

from rill_cli import funding_inclusion as module
from rill_cli import publication
from rill_cli.age_container import X25519Credentials
from rill_cli.funding_inclusion import FundingInclusionHint, LookupBlock

SOURCE = json.loads(
    (Path(__file__).parent / "fixtures/initial-ln-to-btc-no-prepayment-v1.json").read_bytes()
)
BINDING = FundingBinding.model_validate(
    {
        "contract_hash": SOURCE["contract_hash"],
        "funding_attempt_id": "cc" * 32,
        "binding_revision": 0,
        "funder_role": "provider",
        "lineage_anchor_txid": "11" * 32,
        "lineage_anchor_vout": 0,
        "funding_txid": "22" * 32,
        "contract_vout": 0,
        "contract_value_sat": SOURCE["contract_terms"]["economics"]["contract_amount_sat"],
        "contract_script_pubkey": SOURCE["taproot_contract"]["script_pubkey"],
        "replaces_txid": None,
        "created_at": 1700000200,
    }
)
HINT = FundingInclusionHint.model_validate_json(
    canonicalize(
        {
            "version": "conversion-funding-inclusion/regtest/v1",
            "operation_id": "original-operation",
            "network": SOURCE["network_identity"],
            "original_recovery_sha256": "33" * 32,
            "funding_binding": BINDING.model_dump(mode="json"),
            "funding_block": {"height": 102, "block_hash": "44" * 32},
            "sampled_tip": {"height": 103, "block_hash": "55" * 32},
            "confirmations": 2,
        }
    )
)


@pytest.fixture
def credentials() -> X25519Credentials:
    identity = x25519.Identity.generate()
    return X25519Credentials(str(identity.to_public()), str(identity))


def read(path: Path, credentials: X25519Credentials, **kwargs: object) -> FundingInclusionHint:
    expected: dict[str, object] = {
        "operation_id": HINT.operation_id,
        "network": HINT.network,
        "original_recovery_sha256": HINT.original_recovery_sha256,
        "binding": HINT.funding_binding,
    }
    expected.update(kwargs)
    return module.read_funding_inclusion_hint(path, credentials=credentials, **expected)  # type: ignore[arg-type]


def publish(path: Path, credentials: X25519Credentials) -> FundingInclusionHint:
    return module.publish_funding_inclusion_hint(
        path, HINT, credentials=credentials, publication_allowed=lambda: None
    )


def test_private_encrypted_readback_is_correlated_history_and_never_overwrites(
    tmp_path: Path, credentials: X25519Credentials
) -> None:
    path = tmp_path / "original.funding-inclusion.age"
    assert publish(path, credentials) == HINT
    stored = path.read_bytes()
    assert b"original-operation" not in stored
    assert path.stat().st_mode & 0o777 == 0o600
    assert path.stat().st_nlink == 1
    assert read(path, credentials) == HINT
    with pytest.raises(publication.RecoveryPublicationError):
        publish(path, credentials)
    assert path.read_bytes() == stored
    assert list(tmp_path.iterdir()) == [path]


@pytest.mark.parametrize(
    "fault",
    [
        "absent",
        "partial",
        "public",
        "symlink",
        "hardlink",
        "identity",
        "operation",
        "network",
        "digest",
        "binding",
    ],
)
def test_unknown_unsafe_or_mismatched_hints_refuse_without_repair(
    tmp_path: Path, credentials: X25519Credentials, fault: str
) -> None:
    path = tmp_path / "original.funding-inclusion.age"
    publish(path, credentials)
    other = tmp_path / "other"
    expected: dict[str, object] = {}
    if fault == "absent":
        path.unlink()
    elif fault == "partial":
        path.write_bytes(b"PRIVATE_CANARY")
    elif fault == "public":
        path.chmod(0o644)
    elif fault == "symlink":
        path.rename(other)
        path.symlink_to(other)
    elif fault == "hardlink":
        os.link(path, other)
    elif fault == "identity":
        identity = x25519.Identity.generate()
        credentials = X25519Credentials(str(identity.to_public()), str(identity))
    elif fault == "operation":
        expected["operation_id"] = "another-operation"
    elif fault == "network":
        expected["network"] = HINT.network.model_copy(update={"deployment_namespace": "different"})
    elif fault == "digest":
        expected["original_recovery_sha256"] = "ff" * 32
    elif fault == "binding":
        expected["binding"] = BINDING.model_copy(update={"binding_revision": 1})
    before = {item.name: item.read_bytes() for item in tmp_path.iterdir()}
    with pytest.raises(ValueError, match=r"^original funding inclusion hint unavailable$") as error:
        read(path, credentials, **expected)
    assert error.value.__cause__ is None
    assert error.value.__context__ is None
    assert {item.name: item.read_bytes() for item in tmp_path.iterdir()} == before


@pytest.mark.parametrize(
    "fault",
    [
        "older",
        "missing_version",
        "unknown_field",
        "missing_block",
        "depth",
        "height_bool",
        "future_block",
        "profile",
        "namespace",
    ],
)
def test_strict_encrypted_version_and_coordinate_contract(
    tmp_path: Path, credentials: X25519Credentials, fault: str
) -> None:
    document = HINT.model_dump(mode="json")
    if fault == "older":
        document["version"] = "conversion-funding-inclusion/regtest/v0"
    elif fault == "missing_version":
        del document["version"]
    elif fault == "unknown_field":
        document["fresh"] = True
    elif fault == "missing_block":
        del document["funding_block"]
    elif fault == "depth":
        document["confirmations"] = 3
    elif fault == "height_bool":
        document["funding_block"]["height"] = True
    elif fault == "future_block":
        document["funding_block"]["height"] = 104
    elif fault == "profile":
        document["network"]["consensus_profile"] = "older-profile"
    elif fault == "namespace":
        document["network"]["deployment_namespace"] = "another"
    path = tmp_path / "hint.age"
    with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb") as handle:
        handle.write(
            pyrage.encrypt(
                canonicalize(document), [x25519.Recipient.from_str(credentials.recipient)]
            )
        )
    with pytest.raises(ValueError, match=r"^original funding inclusion hint unavailable$"):
        read(path, credentials)


def test_public_recipient_encryption_does_not_authenticate_the_author(
    tmp_path: Path, credentials: X25519Credentials
) -> None:
    # Demonstrate the documented limit: equality with caller-supplied trusted facts
    # is correlation only. There is no author signature in this metadata format.
    path = tmp_path / "hint.age"
    public = x25519.Recipient.from_str(credentials.recipient)
    path.write_bytes(pyrage.encrypt(canonicalize(HINT.model_dump(mode="json")), [public]))
    path.chmod(0o600)
    assert read(path, credentials) == HINT


@pytest.mark.parametrize("stage", ["initial", "before_link", "after_link"])
def test_admission_failure_never_overwrites_or_repairs_an_uncertain_artifact(
    tmp_path: Path, credentials: X25519Credentials, stage: str
) -> None:
    calls = 0
    target = {"initial": 1, "before_link": 2, "after_link": 3}[stage]

    def allowed() -> None:
        nonlocal calls
        calls += 1
        if calls == target:
            raise ValueError("PRIVATE_CANARY")

    path = tmp_path / "hint.age"
    with pytest.raises((ValueError, publication.RecoveryPublicationError)):
        module.publish_funding_inclusion_hint(
            path, HINT, credentials=credentials, publication_allowed=allowed
        )
    assert calls == target
    if stage == "after_link":
        assert read(path, credentials) == HINT
        stored = path.read_bytes()
        with pytest.raises(publication.RecoveryPublicationError):
            publish(path, credentials)
        assert path.read_bytes() == stored
    else:
        assert not path.exists()
    assert not any(item.name.startswith(".rill") for item in tmp_path.iterdir())


def test_post_link_directory_fsync_uncertainty_preserves_history_without_retry(
    tmp_path: Path, credentials: X25519Credentials, monkeypatch: pytest.MonkeyPatch
) -> None:
    original = publication.os.fsync
    calls = 0

    def fsync(descriptor: int) -> None:
        nonlocal calls
        calls += 1
        if calls == 2:
            raise OSError("PRIVATE_CANARY")
        original(descriptor)

    monkeypatch.setattr(publication.os, "fsync", fsync)
    path = tmp_path / "hint.age"
    with pytest.raises(publication.RecoveryPublicationUncertainError):
        publish(path, credentials)
    # Failure before temp unlink leaves two links. The strict reader refuses
    # this uncertain state; it does not repair or promote the surviving names.
    with pytest.raises(ValueError, match=r"^original funding inclusion hint unavailable$"):
        read(path, credentials)
    assert path.stat().st_nlink == 2
    assert len(list(tmp_path.iterdir())) == 2


def test_bypassed_metadata_serializer_warns_only_in_characterization_not_publication(
    tmp_path: Path, credentials: X25519Credentials
) -> None:
    hint = HINT.model_copy(update={"operation_id": {"PRIVATE_CANARY": True}})
    with warnings.catch_warnings(record=True) as emitted:
        warnings.simplefilter("always")
        with pytest.raises(Exception):  # noqa: B017, PT011 - serializer-specific exception is intentionally not a public policy
            module.publish_funding_inclusion_hint(
                tmp_path / "hint.age",
                hint,
                credentials=credentials,
                publication_allowed=lambda: None,
            )
    assert emitted == []
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize("count", [True, 0, -1, 2.0])
def test_strict_depth_model(count: object) -> None:
    document = HINT.model_dump(mode="json")
    document["confirmations"] = count
    with pytest.raises(ValidationError):
        FundingInclusionHint.model_validate_json(json.dumps(document))


def test_complete_old_hint_is_never_implicitly_migrated() -> None:
    assert FundingInclusionHint.model_fields["version"].is_required()
    assert LookupBlock.model_fields["height"].is_required()


@pytest.mark.parametrize("field", ["confirmations", "contract_vout"])
def test_bypassed_counters_cannot_be_normalized_by_publication(
    tmp_path: Path, credentials: X25519Credentials, field: str
) -> None:
    if field == "confirmations":
        hint = HINT.model_copy(update={"confirmations": True})
    else:
        binding = BINDING.model_copy(update={"contract_vout": True})
        hint = HINT.model_copy(update={"funding_binding": binding})
    with pytest.raises(ValidationError):
        module.publish_funding_inclusion_hint(
            tmp_path / "hint.age", hint, credentials=credentials, publication_allowed=lambda: None
        )
    assert list(tmp_path.iterdir()) == []
