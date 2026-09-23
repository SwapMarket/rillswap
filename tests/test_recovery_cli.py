from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import TYPE_CHECKING, Any

import pytest
from pyrage import x25519
from rill_core.wire.canonical import canonicalize
from rill_core.wire.hashes import funding_binding_hash
from rill_core.wire.messages import FundingBinding
from rill_crypto import Context

if TYPE_CHECKING:
    from collections.abc import Sequence

FIXTURES = Path(__file__).parent / "fixtures"
CLI = Path(sys.executable).with_name("rill")
NATIVE_LIBRARY = os.environ.get("RILL_CRYPTO_LIBRARY")
AGE_BINARY = os.environ.get("AGE_BINARY")
NATIVE_ONLY = pytest.mark.skipif(
    not NATIVE_LIBRARY,
    reason="set RILL_CRYPTO_LIBRARY to the pinned native crypto library",
)


def _fixture(direction: str) -> tuple[dict[str, Any], bytes]:
    manifest = json.loads((FIXTURES / "manifest.json").read_text())
    name, digest = (
        (manifest["btc_fixture"], manifest["btc_sha256"])
        if direction == "btc-to-ln"
        else (manifest["ln_fixture"], manifest["ln_sha256"])
    )
    source = (FIXTURES / name).read_bytes()
    assert hashlib.sha256(source).hexdigest() == digest
    package: dict[str, Any] = json.loads(source)
    return package, canonicalize(package)


def _inputs(tmp_path: Path, direction: str) -> tuple[list[str], bytes, str]:
    package, canonical = _fixture(direction)
    network = tmp_path / "trusted-network.json"
    network.write_text(json.dumps(package["network_identity"]))
    identity = x25519.Identity.generate()
    key_file = tmp_path / "secret-identity"
    key_file.write_text(str(identity) + "\n")
    key_file.chmod(0o600)
    common = [
        "--network",
        str(network),
        "--crypto-library",
        str(NATIVE_LIBRARY),
    ]
    return [*common, "--identity", str(key_file)], canonical, str(identity.to_public())


def _rill(args: Sequence[str], *, plaintext: bytes = b"") -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(  # noqa: S603 - fixed installed entrypoint, no shell
        [str(CLI), "recover", *args],
        input=plaintext,
        capture_output=True,
        timeout=20,
        check=False,
    )


def _signed_binding(package: dict[str, Any], revision: int, library: str) -> dict[str, Any]:
    role = "client" if package["profile_id"] == "btc-to-ln/v1" else "provider"
    secret_scalar = 2 if role == "client" else 9  # Public synthetic fixture-only session keys.
    binding = FundingBinding.model_validate(
        {
            "contract_hash": package["contract_hash"],
            "funding_attempt_id": "11" * 32,
            "binding_revision": revision,
            "funder_role": role,
            "lineage_anchor_txid": "33" * 32,
            "lineage_anchor_vout": 0,
            "funding_txid": f"{revision + 34:02x}" * 32,
            "contract_vout": revision + 1,
            "contract_value_sat": package["contract_terms"]["economics"]["contract_amount_sat"],
            "contract_script_pubkey": package["taproot_contract"]["script_pubkey"],
            "replaces_txid": f"{revision + 33:02x}" * 32 if revision else None,
            "created_at": 1_700_000_200 + revision,
        }
    )
    with Context(library_path=library) as crypto:
        signature = crypto.schnorr_sign(
            secret_scalar.to_bytes(32, "big"), funding_binding_hash(binding), b"\x77" * 32
        )
    return {"binding": binding.model_dump(mode="json"), "funder_session_signature": signature.hex()}


def _export_snapshot(
    common: list[str],
    recipient: str,
    destination: Path,
    package: dict[str, Any],
    *,
    previous: Path | None = None,
) -> subprocess.CompletedProcess[bytes]:
    return _rill(
        [
            "export-update" if previous is not None else "export",
            *common,
            "--recipient",
            recipient,
            "--output",
            str(destination),
            *(["--previous", str(previous)] if previous is not None else []),
        ],
        plaintext=canonicalize(package),
    )


@NATIVE_ONLY
@pytest.mark.native_crypto
@pytest.mark.parametrize("direction", ["btc-to-ln", "ln-to-btc"])
def test_real_native_age_export_and_inspect_are_redacted(tmp_path: Path, direction: str) -> None:
    common, canonical, recipient = _inputs(tmp_path, direction)
    output = tmp_path / "recovery.age"
    exported = _rill(
        [
            "export",
            *common,
            "--recipient",
            recipient,
            "--output",
            str(output),
        ],
        plaintext=canonical,
    )
    assert exported.returncode == 0, exported.stderr
    assert not exported.stderr
    assert output.read_bytes().startswith(b"age-encryption.org/v1\n")
    assert b"rillswap-recovery" not in output.read_bytes()
    assert output.stat().st_mode & 0o777 == 0o600
    assert b"No funding authority" in exported.stdout
    assert b"funding transactions, conflicts, UTXOs, and chain maturity" in exported.stdout
    inspected = _rill(["inspect", *common, str(output)])
    assert inspected.returncode == 0, inspected.stderr
    assert json.loads(inspected.stdout)["profile"] == f"{direction}/v1"
    assert json.loads(inspected.stdout)["recorded_binding_count"] == 0
    package, _ = _fixture(direction)
    secret = package["user_secret"]["contract_secret_key"].encode()
    assert secret not in inspected.stdout
    assert secret not in exported.stdout
    assert sorted(p.name for p in tmp_path.iterdir()) == [
        "recovery.age",
        "secret-identity",
        "trusted-network.json",
    ]


@NATIVE_ONLY
@pytest.mark.native_crypto
@pytest.mark.parametrize("direction", ["btc-to-ln", "ln-to-btc"])
def test_successor_export_adds_two_signed_bindings_without_replacing_prior(
    tmp_path: Path, direction: str
) -> None:
    common, _, recipient = _inputs(tmp_path, direction)
    initial, _ = _fixture(direction)
    first = tmp_path / "initial.age"
    assert _export_snapshot(common, recipient, first, initial).returncode == 0
    initial_bytes = first.read_bytes()
    candidate = json.loads(json.dumps(initial))
    candidate["updated_at"] += 1
    candidate["funding_history"].append(_signed_binding(candidate, 0, str(NATIVE_LIBRARY)))
    second = tmp_path / "binding-0.age"
    result = _export_snapshot(common, recipient, second, candidate, previous=first)
    assert result.returncode == 0, result.stderr
    assert b"relative only to supplied previous file" in result.stdout
    assert b"No funding authority" in result.stdout
    assert b'"recorded_binding_count":1' in result.stdout
    second_bytes = second.read_bytes()
    candidate["updated_at"] += 1
    candidate["funding_history"].append(_signed_binding(candidate, 1, str(NATIVE_LIBRARY)))
    candidate["chain_scan_birthday_height"] -= 1
    candidate["monotonic_knowledge"]["dangerous_signature_issued"] = True
    third = tmp_path / "binding-1.age"
    updated = _export_snapshot(common, recipient, third, candidate, previous=second)
    assert updated.returncode == 0, updated.stderr
    assert b'"recorded_binding_count":2' in updated.stdout
    assert json.loads(_rill(["inspect", *common, str(third)]).stdout)["recorded_binding_count"] == 2
    assert first.read_bytes() == initial_bytes
    assert second.read_bytes() == second_bytes
    assert third.stat().st_mode & 0o777 == 0o600
    assert initial["user_secret"]["contract_secret_key"].encode() not in updated.stdout


@NATIVE_ONLY
@pytest.mark.native_crypto
def test_successor_refuses_unknown_prior_rollback_cross_swap_and_overwrite(tmp_path: Path) -> None:
    common, _, recipient = _inputs(tmp_path, "btc-to-ln")
    initial, _ = _fixture("btc-to-ln")
    prior = tmp_path / "previous.age"
    assert _export_snapshot(common, recipient, prior, initial).returncode == 0
    candidate = json.loads(json.dumps(initial))
    candidate["updated_at"] += 1
    candidate["monotonic_knowledge"]["dangerous_signature_issued"] = True
    output = tmp_path / "new.age"
    absent = tmp_path / "absent.age"
    for bad_previous in (absent, prior.with_name("corrupt.age")):
        if bad_previous.name == "corrupt.age":
            bad_previous.write_bytes(b"not age")
        failed = _export_snapshot(common, recipient, output, candidate, previous=bad_previous)
        assert failed.returncode == 2
        assert not output.exists()
        assert failed.stdout == b""
    link = tmp_path / "prior-link.age"
    link.symlink_to(prior)
    assert _export_snapshot(common, recipient, output, candidate, previous=link).returncode == 2
    assert not output.exists()
    first = _export_snapshot(common, recipient, output, candidate, previous=prior)
    assert first.returncode == 0
    preserved = output.read_bytes()
    assert _export_snapshot(common, recipient, output, candidate, previous=prior).returncode == 2
    assert output.read_bytes() == preserved
    rollback = _export_snapshot(
        common, recipient, tmp_path / "rollback.age", initial, previous=output
    )
    assert rollback.returncode == 2
    assert not (tmp_path / "rollback.age").exists()
    foreign, _ = _fixture("ln-to-btc")
    cross_swap = _export_snapshot(
        common, recipient, tmp_path / "cross.age", foreign, previous=prior
    )
    assert cross_swap.returncode == 2
    assert not (tmp_path / "cross.age").exists()
    assert prior.exists()


@NATIVE_ONLY
@pytest.mark.native_crypto
def test_restored_old_prior_allows_only_pairwise_successor_not_global_knowledge(
    tmp_path: Path,
) -> None:
    common, _, recipient = _inputs(tmp_path, "btc-to-ln")
    initial, _ = _fixture("btc-to-ln")
    old = tmp_path / "old.age"
    assert _export_snapshot(common, recipient, old, initial).returncode == 0
    old_bytes = old.read_bytes()
    known = json.loads(json.dumps(initial))
    known["updated_at"] += 1
    known["monotonic_knowledge"]["dangerous_signature_issued"] = True
    informed = tmp_path / "informed.age"
    assert _export_snapshot(common, recipient, informed, known, previous=old).returncode == 0
    informed_bytes = informed.read_bytes()
    restored_candidate = json.loads(json.dumps(initial))
    restored_candidate["updated_at"] += 1
    less_informed = tmp_path / "less-informed.age"
    outcome = _export_snapshot(common, recipient, less_informed, restored_candidate, previous=old)
    assert outcome.returncode == 0
    assert b"relative only to supplied previous file" in outcome.stdout
    assert b"No funding authority" in outcome.stdout
    assert old.read_bytes() == old_bytes
    assert informed.read_bytes() == informed_bytes
    # If the more-informed sibling is explicitly selected, rollback is refused.
    rejected = _export_snapshot(
        common, recipient, tmp_path / "rejected.age", restored_candidate, previous=informed
    )
    assert rejected.returncode == 2
    assert not (tmp_path / "rejected.age").exists()


@NATIVE_ONLY
@pytest.mark.native_crypto
def test_invalid_export_never_overwrites_or_claims_success(tmp_path: Path) -> None:
    common, canonical, recipient = _inputs(tmp_path, "btc-to-ln")
    output = tmp_path / "recovery.age"
    output.write_bytes(b"prior age file, must be preserved")
    for plaintext in (
        canonical,
        (FIXTURES / "initial-btc-to-ln-v1.json").read_bytes(),
        b"{}",
        canonical + b" ",
        b"x" * (128 * 1024 + 1),
    ):
        failed = _rill(
            [
                "export",
                *common,
                "--recipient",
                recipient,
                "--output",
                str(output),
            ],
            plaintext=plaintext,
        )
        assert failed.returncode == 2
        assert failed.stdout == b""
        assert b"funding authority" in failed.stderr
        assert output.read_bytes() == b"prior age file, must be preserved"
        assert not list(tmp_path.glob(".rill-recovery-*.tmp"))
    wrong_network = tmp_path / "wrong-network.json"
    package, _ = _fixture("btc-to-ln")
    package["network_identity"]["deployment_namespace"] = "foreign"
    wrong_network.write_text(json.dumps(package["network_identity"]))
    absent = tmp_path / "absent.age"
    rejected = _rill(
        [
            "export",
            "--network",
            str(wrong_network),
            "--crypto-library",
            str(NATIVE_LIBRARY),
            *common[4:],
            "--recipient",
            recipient,
            "--output",
            str(absent),
        ],
        plaintext=canonical,
    )
    assert rejected.returncode == 2
    assert not absent.exists()


@NATIVE_ONLY
@pytest.mark.native_crypto
def test_wrong_identity_tampered_ciphertext_and_missing_library_fail_closed(tmp_path: Path) -> None:
    common, canonical, recipient = _inputs(tmp_path, "ln-to-btc")
    output = tmp_path / "good.age"
    assert (
        _rill(
            [
                "export",
                *common,
                "--recipient",
                recipient,
                "--output",
                str(output),
            ],
            plaintext=canonical,
        ).returncode
        == 0
    )
    other = x25519.Identity.generate()
    wrong_file = tmp_path / "wrong-key"
    wrong_file.write_text(str(other) + "\n")
    wrong_file.chmod(0o600)
    wrong_args = [*common[:-1], str(wrong_file)]
    failed = _rill(["inspect", *wrong_args, str(output)])
    assert failed.returncode == 2
    assert failed.stdout == b""
    copied = bytearray(output.read_bytes())
    copied[-1] ^= 1
    modified = tmp_path / "tampered.age"
    modified.write_bytes(copied)
    failed = _rill(["inspect", *common, str(modified)])
    assert failed.returncode == 2
    assert failed.stdout == b""
    failed = _rill(
        [
            "export",
            "--network",
            common[1],
            "--crypto-library",
            str(tmp_path / "missing.so"),
            *common[4:],
            "--recipient",
            recipient,
            "--output",
            str(tmp_path / "not-created.age"),
        ],
        plaintext=canonical,
    )
    assert failed.returncode == 2
    assert not (tmp_path / "not-created.age").exists()


@NATIVE_ONLY
@pytest.mark.native_crypto
def test_identity_file_must_be_private_and_not_a_symlink(tmp_path: Path) -> None:
    common, canonical, recipient = _inputs(tmp_path, "btc-to-ln")
    secret_path = Path(common[-1])
    secret_path.chmod(0o644)
    output = tmp_path / "never.age"
    failed = _rill(
        [
            "export",
            *common,
            "--recipient",
            recipient,
            "--output",
            str(output),
        ],
        plaintext=canonical,
    )
    assert failed.returncode == 2
    assert not output.exists()
    secret_path.chmod(0o600)
    symlink = tmp_path / "key-link"
    symlink.symlink_to(secret_path)
    failed = _rill(
        [
            "export",
            *common[:-1],
            str(symlink),
            "--recipient",
            recipient,
            "--output",
            str(output),
        ],
        plaintext=canonical,
    )
    assert failed.returncode == 2
    assert not output.exists()


@NATIVE_ONLY
@pytest.mark.age_interop
@pytest.mark.skipif(not AGE_BINARY, reason="set AGE_BINARY to the pinned Go age executable")
@pytest.mark.parametrize("direction", ["btc-to-ln", "ln-to-btc"])
def test_two_direction_independent_go_age_interoperability(tmp_path: Path, direction: str) -> None:
    common, canonical, recipient = _inputs(tmp_path, direction)
    output = tmp_path / "python.age"
    exported = _rill(
        [
            "export",
            *common,
            "--recipient",
            recipient,
            "--output",
            str(output),
        ],
        plaintext=canonical,
    )
    assert exported.returncode == 0, exported.stderr
    assert output.is_file()
    assert output.stat().st_mode & 0o777 == 0o600
    assert not list(tmp_path.glob(".rill-recovery-*.tmp"))
    decrypted = subprocess.run(  # noqa: S603 - explicitly selected pinned Go binary, no shell
        [str(AGE_BINARY), "-d", "-i", common[-1]],
        input=output.read_bytes(),
        capture_output=True,
        timeout=20,
        check=False,
    )
    assert decrypted.returncode == 0, decrypted.stderr
    assert decrypted.stdout == canonical
    encrypted = subprocess.run(  # noqa: S603 - explicitly selected pinned Go binary, no shell
        [str(AGE_BINARY), "-r", recipient],
        input=canonical,
        capture_output=True,
        timeout=20,
        check=False,
    )
    assert encrypted.returncode == 0, encrypted.stderr
    from_go = tmp_path / "go.age"
    from_go.write_bytes(encrypted.stdout)
    inspected = _rill(["inspect", *common, str(from_go)])
    assert inspected.returncode == 0, inspected.stderr
    assert json.loads(inspected.stdout)["profile"] == f"{direction}/v1"
