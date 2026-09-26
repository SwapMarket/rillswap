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
from rill_core.wire.messages import ContractTerms, FundingBinding
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


@NATIVE_ONLY
@pytest.mark.native_crypto
def test_observe_funding_checks_selected_encrypted_record_before_any_core_rpc(  # noqa: PLR0915 - ordered native recovery commands
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import pyrage  # noqa: PLC0415
    from rill_core.settlement import FundingBindingTransactionMatch  # noqa: PLC0415
    from rill_core.wire.types import NetworkIdentity  # noqa: PLC0415

    from rill_cli import main as cli_main  # noqa: PLC0415
    from rill_cli.recovery_core_observation import RecoveryOutpointCandidate  # noqa: PLC0415

    package, _ = _fixture("btc-to-ln")
    package["funding_history"].append(_signed_binding(package, 0, str(NATIVE_LIBRARY)))
    common, _, _ = _inputs(tmp_path, "btc-to-ln")
    identity = x25519.Identity.from_str(Path(common[-1]).read_text().strip())
    encrypted = tmp_path / "selected.age"
    encrypted.write_bytes(pyrage.encrypt(canonicalize(package), [identity.to_public()]))
    binding = FundingBinding.model_validate(package["funding_history"][0]["binding"])
    seen: list[tuple[str, int]] = []

    class Reader:
        def __init__(self, **_kwargs: object) -> None:
            seen.append(("connect", 0))

        def observe(
            self,
            selected: FundingBinding,
            _terms: object,
            *,
            keys: object,
            for_refund: bool = False,
        ) -> RecoveryOutpointCandidate:
            assert selected == binding
            assert isinstance(keys, Context)
            seen.append(("refund" if for_refund else "observe", selected.binding_revision))
            return RecoveryOutpointCandidate(
                NetworkIdentity.model_validate(package["network_identity"]),
                FundingBindingTransactionMatch(
                    binding.funding_txid,
                    binding.contract_vout,
                    binding.lineage_anchor_txid,
                    binding.lineage_anchor_vout,
                ),
                "ab" * 32,
                1101 if for_refund else 100,
                "bc" * 32,
                99,
                2,
                1101,
            )

    monkeypatch.setattr(cli_main, "RecoveryCoreReader", Reader)
    selected_args = [
        "observe-funding",
        *common,
        "--funding-attempt-id",
        "11" * 32,
        "--binding-revision",
        "0",
        "--rpc-cookie",
        str(tmp_path / "never-open-cookie"),
        "--rpc-port",
        "18443",
        str(encrypted),
    ]
    report = json.loads(cli_main._run(cli_main._parser().parse_args(["recover", *selected_args])))  # noqa: SLF001
    assert report["kind"] == "selected-funding-candidate-observation/v1"
    assert report["static_transaction_bytes_match"] is True
    assert report["funding_txid"] == binding.funding_txid
    assert report["authority"].startswith("none")
    assert seen == [("connect", 0), ("observe", 0)]
    seen.clear()
    tampered = json.loads(json.dumps(package))
    tampered["funding_history"][0]["funder_session_signature"] = "00" * 64
    for changes in ({"funding_history": []}, {"format_version": "older"}, tampered):
        changed = {**package, **changes}
        encrypted.write_bytes(pyrage.encrypt(canonicalize(changed), [identity.to_public()]))
        assert cli_main.main(["recover", *selected_args]) == 2
        assert seen == []
    encrypted.write_bytes(pyrage.encrypt(canonicalize(package), [identity.to_public()]))
    output = tmp_path / "refund.raw"
    signing_args = [
        "recover",
        "sign-refund",
        *selected_args[1:-1],
        "--fee-sat",
        "200",
        "--output",
        str(output),
        str(encrypted),
    ]
    report = json.loads(cli_main._run(cli_main._parser().parse_args(signing_args)))  # noqa: SLF001
    assert report["kind"] == "offline-signed-btc-to-ln-refund/v1"
    assert report["broadcast"] is False
    assert report["sampled_tip_height"] == 1101
    assert output.read_bytes().startswith(b"\x02\x00\x00\x00")
    assert output.stat().st_mode & 0o777 == 0o600
    assert seen == [("connect", 0), ("refund", 0)]
    seen.clear()
    assert cli_main.main(signing_args) == 2  # Never overwrite the signed output.
    assert seen == [("connect", 0), ("refund", 0)]
    seen.clear()
    intent = tmp_path / "broadcast-intent.json"

    def assert_persisted_then_submit(
        _reader: object,
        submitted_binding: FundingBinding,
        _terms: object,
        *,
        keys: object,
        raw: bytes,
        expected_txid: str,
    ) -> RecoveryOutpointCandidate:
        from rill_cli.refund_broadcast import verify_refund_intent  # noqa: PLC0415

        assert submitted_binding == binding
        assert isinstance(keys, Context)
        assert verify_refund_intent(intent.read_bytes(), intent.read_bytes()) == raw
        assert len(expected_txid) == 64
        seen.append(("send", 1))
        return Reader().observe(binding, _terms, keys=keys, for_refund=True)

    monkeypatch.setattr(cli_main, "submit_prepared_refund", assert_persisted_then_submit)
    broadcast_args = [
        "recover",
        "broadcast-refund",
        *selected_args[1:-1],
        "--fee-sat",
        "200",
        "--intent",
        str(intent),
        str(encrypted),
    ]
    submitted = json.loads(cli_main._run(cli_main._parser().parse_args(broadcast_args)))  # noqa: SLF001
    assert submitted["submission"] == "node_accepted"
    assert submitted["chain_observation"] == "unobserved_after_send"
    assert submitted["broadcast_attempts_this_invocation"] == 1
    assert intent.stat().st_mode & 0o777 == 0o600
    assert seen[:2] == [("connect", 0), ("refund", 0)]
    assert seen.count(("send", 1)) == 1
    seen.clear()
    assert cli_main.main(broadcast_args) == 2
    assert ("send", 1) not in seen
    from rill_cli.refund_broadcast import RefundSubmissionUnknownError  # noqa: PLC0415
    from rill_cli.refund_publication import RefundPublicationUncertainError  # noqa: PLC0415

    another_intent = tmp_path / "uncertain-publication.json"
    another_args = [
        "recover",
        "broadcast-refund",
        *selected_args[1:-1],
        "--fee-sat",
        "200",
        "--intent",
        str(another_intent),
        str(encrypted),
    ]
    original_publish = cli_main.publish_new_broadcast_intent

    def cannot_confirm_persistence(*_args: object, **_kwargs: object) -> None:
        raise RefundPublicationUncertainError("private failure")

    monkeypatch.setattr(cli_main, "publish_new_broadcast_intent", cannot_confirm_persistence)
    seen.clear()
    assert cli_main.main(another_args) == 3
    assert ("send", 1) not in seen
    monkeypatch.setattr(cli_main, "publish_new_broadcast_intent", original_publish)

    def ambiguous_submit(*_args: object, **_kwargs: object) -> None:
        assert another_intent.exists()
        seen.append(("send", 1))
        raise RefundSubmissionUnknownError("private upstream result")

    monkeypatch.setattr(cli_main, "submit_prepared_refund", ambiguous_submit)
    seen.clear()
    assert cli_main.main(another_args) == 4
    assert seen.count(("send", 1)) == 1
    assert another_intent.is_file()
    seen.clear()
    assert cli_main.main(another_args) == 2
    assert ("send", 1) not in seen


@NATIVE_ONLY
@pytest.mark.native_crypto
@pytest.mark.parametrize("command", ["sign-refund", "broadcast-refund"])
def test_sign_refund_rejects_provider_refund_profile_before_rpc(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    command: str,
) -> None:
    import pyrage  # noqa: PLC0415

    from rill_cli import main as cli_main  # noqa: PLC0415

    package, _ = _fixture("ln-to-btc")
    package["funding_history"].append(_signed_binding(package, 0, str(NATIVE_LIBRARY)))
    common, _, _ = _inputs(tmp_path, "ln-to-btc")
    identity = x25519.Identity.from_str(Path(common[-1]).read_text().strip())
    encrypted = tmp_path / "provider-refund.age"
    encrypted.write_bytes(pyrage.encrypt(canonicalize(package), [identity.to_public()]))
    output = tmp_path / "no-output.raw"

    def should_not_connect(**_kwargs: object) -> None:
        pytest.fail("wrong profile must not connect to Core")

    monkeypatch.setattr(cli_main, "RecoveryCoreReader", should_not_connect)
    assert (
        cli_main.main(
            [
                "recover",
                command,
                *common,
                "--funding-attempt-id",
                "11" * 32,
                "--binding-revision",
                "0",
                "--rpc-cookie",
                str(tmp_path / "no-cookie"),
                "--rpc-port",
                "18443",
                "--fee-sat",
                "200",
                "--output" if command == "sign-refund" else "--intent",
                str(output),
                str(encrypted),
            ]
        )
        == 2
    )
    assert not output.exists()


@NATIVE_ONLY
@pytest.mark.native_crypto
@pytest.mark.parametrize("profile", ["btc-to-ln", "ln-to-btc"])
def test_claim_observation_checks_profile_and_signed_record_before_rpc(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    profile: str,
) -> None:
    import pyrage  # noqa: PLC0415
    from rill_core.settlement import FundingBindingTransactionMatch  # noqa: PLC0415
    from rill_core.wire.types import NetworkIdentity  # noqa: PLC0415

    from rill_cli import main as cli_main  # noqa: PLC0415
    from rill_cli.recovery_core_observation import RecoveryOutpointCandidate  # noqa: PLC0415

    package, _ = _fixture(profile)
    package["funding_history"].append(_signed_binding(package, 0, str(NATIVE_LIBRARY)))
    common, _, _ = _inputs(tmp_path, profile)
    identity = x25519.Identity.from_str(Path(common[-1]).read_text().strip())
    encrypted = tmp_path / "claim-observation.age"
    encrypted.write_bytes(pyrage.encrypt(canonicalize(package), [identity.to_public()]))
    binding = FundingBinding.model_validate(package["funding_history"][0]["binding"])
    seen: list[str] = []

    class Reader:
        def __init__(self, **_kwargs: object) -> None:
            seen.append("connect")

        def observe_claim(
            self,
            selected: FundingBinding,
            _terms: object,
            *,
            keys: object,
        ) -> RecoveryOutpointCandidate:
            assert selected == binding
            assert isinstance(keys, Context)
            seen.append("claim-read-only")
            return RecoveryOutpointCandidate(
                NetworkIdentity.model_validate(package["network_identity"]),
                FundingBindingTransactionMatch(
                    binding.funding_txid,
                    binding.contract_vout,
                    binding.lineage_anchor_txid,
                    binding.lineage_anchor_vout,
                ),
                "ab" * 32,
                103,
                "bc" * 32,
                102,
                2,
                1101,
            )

    monkeypatch.setattr(cli_main, "RecoveryCoreReader", Reader)
    arguments = [
        "recover",
        "observe-claim",
        *common,
        "--funding-attempt-id",
        "11" * 32,
        "--binding-revision",
        "0",
        "--rpc-cookie",
        str(tmp_path / "never-open-cookie"),
        "--rpc-port",
        "18443",
        str(encrypted),
    ]
    if profile == "btc-to-ln":
        assert cli_main.main(arguments) == 2
        assert not seen
        wrong_profile_plan = [
            "recover",
            "prepare-claim",
            *common,
            "--funding-attempt-id",
            "11" * 32,
            "--binding-revision",
            "0",
            "--rpc-cookie",
            str(tmp_path / "never-open-cookie"),
            "--rpc-port",
            "18443",
            "--fee-sat",
            "300",
            "--output",
            str(tmp_path / "no-plan.age"),
            str(encrypted),
        ]
        assert cli_main.main(wrong_profile_plan) == 2
        assert not (tmp_path / "no-plan.age").exists()
        assert not seen
        return
    report = json.loads(cli_main._run(cli_main._parser().parse_args(arguments)))  # noqa: SLF001
    assert report["kind"] == "selected-claim-candidate-observation/v1"
    assert report["mempool_aware_unspent_sampled"] is True
    assert report["chain_only_confirmations"] == 2
    assert report["authority"].startswith("none")
    assert package["monotonic_knowledge"]["preimage"] not in json.dumps(report)
    assert package["user_secret"]["contract_secret_key"] not in json.dumps(report)
    assert seen == ["connect", "claim-read-only"]
    seen.clear()
    damaged = json.loads(json.dumps(package))
    damaged["funding_history"][0]["funder_session_signature"] = "00" * 64
    encrypted.write_bytes(pyrage.encrypt(canonicalize(damaged), [identity.to_public()]))
    assert cli_main.main(arguments) == 2
    plan_args = [
        "recover",
        "prepare-claim",
        *common,
        "--funding-attempt-id",
        "11" * 32,
        "--binding-revision",
        "0",
        "--rpc-cookie",
        str(tmp_path / "never-open-cookie"),
        "--rpc-port",
        "18443",
        "--fee-sat",
        "300",
        "--output",
        str(tmp_path / "no-plan.age"),
        str(encrypted),
    ]
    assert cli_main.main(plan_args) == 2
    assert not (tmp_path / "no-plan.age").exists()
    assert not seen
    passphrase_args = [arg for arg in plan_args if arg not in ("--identity", common[-1])]
    passphrase_args.insert(4, "--passphrase-prompt")
    assert cli_main.main(passphrase_args) == 2
    assert not seen


@NATIVE_ONLY
@pytest.mark.native_crypto
def test_prepare_claim_publishes_only_encrypted_verified_selected_transaction(  # noqa: PLR0915 - native end-to-end negative matrix
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    import pyrage  # noqa: PLC0415
    from rill_core.settlement import (  # noqa: PLC0415
        FundingBindingTransactionMatch,
        FundingOutput,
        UnilateralAuthorization,
        validate_unilateral_spend,
    )
    from rill_core.wire.types import NetworkIdentity  # noqa: PLC0415

    from rill_cli import claim_plan  # noqa: PLC0415
    from rill_cli import main as cli_main  # noqa: PLC0415
    from rill_cli.age_container import X25519Credentials  # noqa: PLC0415
    from rill_cli.claim_plan import ClaimPlanError, verify_encrypted_claim_plan  # noqa: PLC0415
    from rill_cli.recovery_core_observation import RecoveryOutpointCandidate  # noqa: PLC0415

    package, _ = _fixture("ln-to-btc")
    package["funding_history"].append(_signed_binding(package, 0, str(NATIVE_LIBRARY)))
    common, _, _ = _inputs(tmp_path, "ln-to-btc")
    identity = x25519.Identity.from_str(Path(common[-1]).read_text().strip())
    credentials = X25519Credentials(str(identity.to_public()), str(identity))
    recovery = tmp_path / "selected.age"
    recovery.write_bytes(pyrage.encrypt(canonicalize(package), [identity.to_public()]))
    binding = FundingBinding.model_validate(package["funding_history"][0]["binding"])
    network = NetworkIdentity.model_validate(package["network_identity"])
    public_sample = RecoveryOutpointCandidate(
        network,
        FundingBindingTransactionMatch(
            binding.funding_txid,
            binding.contract_vout,
            binding.lineage_anchor_txid,
            binding.lineage_anchor_vout,
        ),
        "ab" * 32,
        103,
        "bc" * 32,
        102,
        2,
        1101,
    )
    calls: list[str] = []

    class Reader:
        def __init__(self, **_kwargs: object) -> None:
            calls.append("connect")

        def observe_claim(
            self,
            selected: FundingBinding,
            _terms: object,
            *,
            keys: object,
        ) -> RecoveryOutpointCandidate:
            assert selected == binding
            assert isinstance(keys, Context)
            calls.append("claim-read-only")
            return public_sample

    monkeypatch.setattr(cli_main, "RecoveryCoreReader", Reader)
    destination = tmp_path / "private-claim.age"
    args = [
        "recover",
        "prepare-claim",
        *common,
        "--funding-attempt-id",
        "11" * 32,
        "--binding-revision",
        "0",
        "--rpc-cookie",
        str(tmp_path / "test-only-cookie"),
        "--rpc-port",
        "18443",
        "--fee-sat",
        "300",
        "--output",
        str(destination),
        str(recovery),
    ]
    assert cli_main.main(args) == 0
    captured = capsys.readouterr()
    assert captured.err == ""
    report = json.loads(captured.out)
    assert report["kind"] == "encrypted-ln-to-btc-claim-preparation/v1"
    assert report["broadcast"] is False
    assert report["preimage_external_disclosure"] is False
    assert report["authority"].startswith("none")
    assert calls == ["connect", "claim-read-only"]
    ciphertext = destination.read_bytes()
    assert ciphertext.startswith(b"age-encryption.org/v1\n")
    assert destination.stat().st_mode & 0o777 == 0o600
    preimage = package["monotonic_knowledge"]["preimage"]
    assert preimage not in captured.out
    assert preimage not in ciphertext.decode("latin1")
    plan = json.loads(pyrage.decrypt(ciphertext, [identity]))
    assert plan["kind"] == "rillswap-opaque-claim-plan/v1"
    assert plan["recovery_plaintext_sha256"] == hashlib.sha256(canonicalize(package)).hexdigest()
    assert bytes.fromhex(preimage) in bytes.fromhex(plan["signed_claim_hex"])
    if AGE_BINARY:
        decrypted = subprocess.run(  # noqa: S603 - pinned age executable, synthetic fixture
            [AGE_BINARY, "--decrypt", "--identity", common[-1]],
            input=ciphertext,
            capture_output=True,
            timeout=15,
            check=False,
        )
        assert decrypted.returncode == 0
        assert decrypted.stdout == canonicalize(plan)
        encrypted_by_go = subprocess.run(  # noqa: S603 - pinned age executable
            [AGE_BINARY, "--encrypt", "--recipient", str(identity.to_public())],
            input=canonicalize(plan),
            capture_output=True,
            timeout=15,
            check=False,
        )
        assert encrypted_by_go.returncode == 0
    with Context(library_path=str(NATIVE_LIBRARY)) as crypto:
        receipt = verify_encrypted_claim_plan(
            ciphertext,
            recovery.read_bytes(),
            network,
            credentials=credentials,
            funding_attempt_id=binding.funding_attempt_id,
            binding_revision=0,
            crypto=crypto,
        )
        funding = FundingOutput(
            bytes.fromhex(binding.funding_txid),
            binding.contract_vout,
            int(binding.contract_value_sat),
            bytes.fromhex(binding.contract_script_pubkey),
        )
        terms = ContractTerms.model_validate_json(json.dumps(package["contract_terms"]))
        authorization = UnilateralAuthorization.from_terms(terms, funding, "claim", keys=crypto)
        checked = validate_unilateral_spend(
            bytes.fromhex(plan["signed_claim_hex"]),
            authorization,
            verifier=crypto,
        )
        assert receipt.claim_txid == checked.txid == report["claim_txid"]
        assert receipt.fee_sat == checked.fee_sat == 300
        if AGE_BINARY:
            assert (
                verify_encrypted_claim_plan(
                    encrypted_by_go.stdout,
                    recovery.read_bytes(),
                    network,
                    credentials=credentials,
                    funding_attempt_id=binding.funding_attempt_id,
                    binding_revision=0,
                    crypto=crypto,
                )
                == receipt
            )
        for mutation in ("network_identity", "signed_claim_hex", "kind", "digest"):
            changed = json.loads(json.dumps(plan))
            if mutation == "network_identity":
                changed["network_identity"]["deployment_namespace"] = "other"
            elif mutation == "signed_claim_hex":
                changed["signed_claim_hex"] = "00" + changed["signed_claim_hex"][2:]
            elif mutation == "kind":
                changed["kind"] = "older-version"
            else:
                changed["recovery_plaintext_sha256"] = "00" * 32
            altered = pyrage.encrypt(canonicalize(changed), [identity.to_public()])
            with pytest.raises(ClaimPlanError) as error:
                verify_encrypted_claim_plan(
                    altered,
                    recovery.read_bytes(),
                    network,
                    credentials=credentials,
                    funding_attempt_id=binding.funding_attempt_id,
                    binding_revision=0,
                    crypto=crypto,
                )
            assert error.value.__cause__ is None
            assert error.value.__context__ is None
        other_identity = x25519.Identity.generate()
        with pytest.raises(ClaimPlanError):
            verify_encrypted_claim_plan(
                ciphertext,
                recovery.read_bytes(),
                network,
                credentials=X25519Credentials(str(other_identity.to_public()), str(other_identity)),
                funding_attempt_id=binding.funding_attempt_id,
                binding_revision=0,
                crypto=crypto,
            )
        plan_ciphertext = pyrage.encrypt(b'{"unexpected":"secret witness"}', [identity.to_public()])

        def assert_no_retained_internal_plaintext(error: ClaimPlanError) -> None:
            assert error.__context__ is None
            assert error.__cause__ is None
            frames = []
            traceback = error.__traceback__
            while traceback is not None:
                if traceback.tb_frame.f_code.co_filename == claim_plan.__file__:
                    frames.append(traceback.tb_frame)
                traceback = traceback.tb_next
            assert frames
            assert all(
                frame.f_code.co_name
                not in {
                    "_verify_encrypted_claim_plan",
                    "_prepare_encrypted_claim_plan",
                    "_verify_plan",
                }
                for frame in frames
            )
            sensitive = {"recovery_plaintext", "plan_plaintext", "raw", "plan", "plaintext"}
            assert all(not sensitive.intersection(frame.f_locals) for frame in frames)

        with pytest.raises(ClaimPlanError) as rejected_plan:
            verify_encrypted_claim_plan(
                plan_ciphertext,
                recovery.read_bytes(),
                network,
                credentials=credentials,
                funding_attempt_id=binding.funding_attempt_id,
                binding_revision=0,
                crypto=crypto,
            )
        assert_no_retained_internal_plaintext(rejected_plan.value)

        def private_failure(*_args: object, **_kwargs: object) -> None:
            raise OSError("internal preimage " + preimage)

        with monkeypatch.context() as failure:
            failure.setattr(claim_plan, "_verify_plan", private_failure)
            with pytest.raises(ClaimPlanError) as signing_failure:
                claim_plan.prepare_encrypted_claim_plan(
                    recovery.read_bytes(),
                    network,
                    credentials=credentials,
                    funding_attempt_id=binding.funding_attempt_id,
                    binding_revision=0,
                    candidate=public_sample,
                    fee_sat=300,
                    auxiliary_random=b"\x55" * 32,
                    crypto=crypto,
                )
            assert_no_retained_internal_plaintext(signing_failure.value)
            assert preimage not in repr(signing_failure.value)

        with monkeypatch.context() as failure:
            failure.setattr(claim_plan.pyrage, "encrypt", private_failure)
            with pytest.raises(ClaimPlanError) as encryption_failure:
                claim_plan.prepare_encrypted_claim_plan(
                    recovery.read_bytes(),
                    network,
                    credentials=credentials,
                    funding_attempt_id=binding.funding_attempt_id,
                    binding_revision=0,
                    candidate=public_sample,
                    fee_sat=300,
                    auxiliary_random=b"\x55" * 32,
                    crypto=crypto,
                )
            assert_no_retained_internal_plaintext(encryption_failure.value)
        original_decrypt = claim_plan.pyrage.decrypt
        decrypt_calls = 0

        def fail_plan_decrypt(*args: object, **kwargs: object) -> bytes:
            nonlocal decrypt_calls
            decrypt_calls += 1
            if decrypt_calls == 2:
                raise OSError("post-sign decryption failed with " + preimage)
            return original_decrypt(*args, **kwargs)

        with monkeypatch.context() as failure:
            failure.setattr(claim_plan.pyrage, "decrypt", fail_plan_decrypt)
            with pytest.raises(ClaimPlanError) as decryption_failure:
                claim_plan.prepare_encrypted_claim_plan(
                    recovery.read_bytes(),
                    network,
                    credentials=credentials,
                    funding_attempt_id=binding.funding_attempt_id,
                    binding_revision=0,
                    candidate=public_sample,
                    fee_sat=300,
                    auxiliary_random=b"\x55" * 32,
                    crypto=crypto,
                )
            assert decrypt_calls == 2
            assert_no_retained_internal_plaintext(decryption_failure.value)
    calls.clear()
    assert cli_main.main(args) == 2  # No overwrite or automatic preparation retry.
    assert destination.read_bytes() == ciphertext
    assert calls == ["connect", "claim-read-only"]


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
