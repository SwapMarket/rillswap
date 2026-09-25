"""Regtest-only exposure boundary: intent must precede witness-bearing RPC."""

from __future__ import annotations

import json
import os
import stat
from pathlib import Path
from typing import TYPE_CHECKING, Any, Self

import pyrage
import pytest
from pyrage import x25519
from rill_core.wire.messages import ContractTerms, FundingBinding

from rill_cli import claim_disclosure as disclosure
from rill_cli import publication
from rill_cli.age_container import X25519Credentials
from rill_cli.claim_plan import ClaimPlanReceipt
from rill_cli.publication import RecoveryPublicationUncertainError

if TYPE_CHECKING:
    from rill_core.wire.types import NetworkIdentity


def _context() -> tuple[ContractTerms, FundingBinding, NetworkIdentity]:
    source = json.loads(
        (Path(__file__).parent / "fixtures" / "initial-ln-to-btc-no-prepayment-v1.json").read_text()
    )
    terms = ContractTerms.model_validate_json(json.dumps(source["contract_terms"]))
    binding = FundingBinding.model_validate_json(
        json.dumps(
            {
                "contract_hash": source["contract_hash"],
                "funding_attempt_id": "cc" * 32,
                "binding_revision": 0,
                "funder_role": "provider",
                "lineage_anchor_txid": "dd" * 32,
                "lineage_anchor_vout": 1,
                "funding_txid": "aa" * 32,
                "contract_vout": 0,
                "contract_value_sat": terms.economics.contract_amount_sat,
                "contract_script_pubkey": source["taproot_contract"]["script_pubkey"],
                "replaces_txid": None,
                "created_at": 1700000200,
            }
        )
    )
    return terms, binding, terms.network_identity


@pytest.mark.parametrize(
    ("fault", "expected_error", "expected_methods"),
    [
        ("none", None, ["testmempoolaccept", "sendrawtransaction"]),
        ("first-observation", disclosure.ClaimDisclosureRefusedError, []),
        ("second-observation", disclosure.ClaimDisclosureRefusedError, []),
        ("intent-uncertain", disclosure.ClaimIntentUncertainError, []),
        ("fsync-uncertain", disclosure.ClaimIntentUncertainError, []),
        ("readback-failed", disclosure.ClaimDisclosureRefusedError, []),
        ("preflight-reject", disclosure.ClaimDisclosureUnknownError, ["testmempoolaccept"]),
        ("preflight-timeout", disclosure.ClaimDisclosureUnknownError, ["testmempoolaccept"]),
        ("preflight-ctrl-c", disclosure.ClaimDisclosureUnknownError, ["testmempoolaccept"]),
        (
            "send-timeout",
            disclosure.ClaimDisclosureUnknownError,
            ["testmempoolaccept", "sendrawtransaction"],
        ),
        (
            "send-ctrl-c",
            disclosure.ClaimDisclosureUnknownError,
            ["testmempoolaccept", "sendrawtransaction"],
        ),
        (
            "wrong-response",
            disclosure.ClaimDisclosureUnknownError,
            ["testmempoolaccept", "sendrawtransaction"],
        ),
    ],
)
def test_experimental_disclosure_records_encrypted_exact_bytes_before_rpc(  # noqa: PLR0915 - fault matrix
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    fault: str,
    expected_error: type[Exception] | None,
    expected_methods: list[str],
) -> None:
    intent_exists = fault not in {"first-observation", "intent-uncertain", "readback-failed"}
    terms, binding, network = _context()
    identity = x25519.Identity.generate()
    credentials = X25519Credentials(str(identity.to_public()), str(identity))
    recovery = pyrage.encrypt(b"synthetic recovery", [identity.to_public()])
    raw = bytes.fromhex("52" * 32 + "11" * 12)
    plan = b"synthetic encrypted plan"
    txid = "bb" * 32
    receipt = ClaimPlanReceipt(binding.funding_txid, binding.contract_vout, txid, 300)
    monkeypatch.setattr(
        disclosure,
        "load_verified_claim_bytes_for_regtest_disclosure",
        lambda *_a, **_kw: (raw, receipt),
    )
    methods: list[str] = []
    observations = 0

    class Reader:
        _url = "http://127.0.0.1:18443/"
        _cookie_path = tmp_path / "cookie"

        def observe_claim(self, *_args: object, **_kwargs: object) -> Any:  # noqa: ANN401
            nonlocal observations
            observations += 1
            if fault == "first-observation" or (
                fault == "second-observation" and observations == 2
            ):
                raise OSError("private witness " + raw.hex())
            return type("Sample", (), {"tip_hash": "ad" * 32, "tip_height": 103})()

        def _rpc(
            self,
            _client: object,
            method: str,
            params: list[Any],
            _request_id: int,
            *,
            submission: bool,
        ) -> Any:  # noqa: ANN401
            assert submission
            if method == "testmempoolaccept":
                assert params[0][0] == raw.hex()
            else:
                assert params[0] == raw.hex()
            intent = tmp_path / "intent.age"
            assert intent.is_file()
            stored = json.loads(pyrage.decrypt(intent.read_bytes(), [identity]))
            assert stored["disclosure_may_occur"] is True
            assert stored["signed_claim_hex"] == raw.hex()
            methods.append(method)
            if fault in ("preflight-ctrl-c", "send-ctrl-c") and (
                (method == "testmempoolaccept" and fault == "preflight-ctrl-c")
                or (method == "sendrawtransaction" and fault == "send-ctrl-c")
            ):
                raise KeyboardInterrupt("private upstream " + raw.hex())
            if fault in ("preflight-timeout", "send-timeout") and (
                (method == "testmempoolaccept" and fault == "preflight-timeout")
                or (method == "sendrawtransaction" and fault == "send-timeout")
            ):
                raise OSError("private upstream " + raw.hex())
            if method == "testmempoolaccept":
                return [{"allowed": fault != "preflight-reject", "txid": txid}]
            return txid if fault != "wrong-response" else "00" * 32

    class Client:
        def __init__(self, **_kwargs: object) -> None:
            pass

        def __enter__(self) -> Self:
            return self

        def __exit__(self, *_args: object) -> None:
            return None

    monkeypatch.setattr(disclosure.httpx, "Client", Client)
    cookie = tmp_path / "cookie"
    cookie.write_text("__cookie__:test-only-password")
    cookie.chmod(0o600)
    if fault == "intent-uncertain":

        def uncertain(*_args: object, **_kwargs: object) -> None:
            raise RecoveryPublicationUncertainError("private witness " + raw.hex())

        monkeypatch.setattr(disclosure, "publish_new_ciphertext", uncertain)
    if fault == "fsync-uncertain":
        original_fsync = os.fsync

        def fail_directory_fsync(descriptor: int) -> None:
            if stat.S_ISDIR(os.fstat(descriptor).st_mode):
                raise OSError("private witness " + raw.hex())
            original_fsync(descriptor)

        monkeypatch.setattr(publication.os, "fsync", fail_directory_fsync)
    if fault == "readback-failed":
        original_verify = disclosure._verify_intent  # noqa: SLF001 - injected failure boundary
        verifications = 0

        def fail_second_readback(*args: object, **kwargs: object) -> None:
            nonlocal verifications
            verifications += 1
            if verifications == 2:
                raise disclosure.ClaimDisclosureRefusedError("private witness " + raw.hex())
            original_verify(*args, **kwargs)

        monkeypatch.setattr(disclosure, "_verify_intent", fail_second_readback)
    args = (Reader(), binding, terms)
    kwargs = {
        "keys": object(),
        "recovery_ciphertext": recovery,
        "plan_ciphertext": plan,
        "network": network,
        "credentials": credentials,
        "funding_attempt_id": binding.funding_attempt_id,
        "binding_revision": 0,
        "intent_path": str(tmp_path / "intent.age"),
    }
    if expected_error is None:
        result = disclosure.disclose_claim_on_regtest(*args, **kwargs)  # type: ignore[arg-type]
        assert result.claim_txid == txid
    else:
        with pytest.raises(expected_error) as caught:
            disclosure.disclose_claim_on_regtest(*args, **kwargs)  # type: ignore[arg-type]
        assert caught.value.__cause__ is None
        assert caught.value.__context__ is None
        assert raw.hex() not in repr(caught.value)
        frames = []
        traceback = caught.value.__traceback__
        while traceback is not None:
            if traceback.tb_frame.f_code.co_filename == disclosure.__file__:
                frames.append(traceback.tb_frame)
            traceback = traceback.tb_next
        assert len(frames) == 1
        assert "raw" not in frames[0].f_locals
    assert methods == expected_methods
    assert (tmp_path / "intent.age").exists() is intent_exists
    if intent_exists:
        ciphertext = (tmp_path / "intent.age").read_bytes()
        assert ciphertext.startswith(b"age-encryption.org/v1\n")
        assert raw.hex().encode() not in ciphertext
        assert (tmp_path / "intent.age").stat().st_mode & 0o777 == 0o600
        with pytest.raises(disclosure.ClaimDisclosureRefusedError):
            disclosure.disclose_claim_on_regtest(*args, **kwargs)  # type: ignore[arg-type]
        assert methods == expected_methods


def test_cli_requires_explicit_acknowledgment_before_any_decryption() -> None:
    from rill_cli.main import _parser  # noqa: PLC0415 - CLI argument contract

    arguments = [
        "recover",
        "broadcast-claim",
        "--network",
        "trusted.json",
        "--crypto-library",
        "native.so",
        "--identity",
        "secret.agekey",
        "--funding-attempt-id",
        "cc" * 32,
        "--binding-revision",
        "0",
        "--rpc-cookie",
        "cookie",
        "--rpc-port",
        "18443",
        "--plan",
        "plan.age",
        "--intent",
        "intent.age",
        "recovery.age",
    ]
    with pytest.raises(SystemExit) as failure:
        _parser().parse_args(arguments)
    assert failure.value.code == 2
    parsed = _parser().parse_args(
        [
            *arguments[:-1],
            "--acknowledge-regtest-preimage-disclosure",
            arguments[-1],
        ]
    )
    assert parsed.command == "broadcast-claim"
    assert parsed.acknowledge_regtest_preimage_disclosure is True


def test_cli_reports_unknown_disclosure_without_upstream_secret(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    from rill_cli import main as cli_main  # noqa: PLC0415

    def interrupted(_args: object) -> str:
        raise disclosure.ClaimDisclosureUnknownError("private preimage " + "52" * 32)

    monkeypatch.setattr(cli_main, "_run", interrupted)
    status = cli_main.main(
        [
            "recover",
            "broadcast-claim",
            "--network",
            "trusted.json",
            "--crypto-library",
            "native.so",
            "--identity",
            "secret.agekey",
            "--funding-attempt-id",
            "cc" * 32,
            "--binding-revision",
            "0",
            "--rpc-cookie",
            "cookie",
            "--rpc-port",
            "18443",
            "--plan",
            "plan.age",
            "--intent",
            "intent.age",
            "--acknowledge-regtest-preimage-disclosure",
            "recovery.age",
        ]
    )
    assert status == 4
    result = capsys.readouterr()
    assert result.out == ""
    assert "preimage may have reached Core" in result.err
    assert "52" * 32 not in result.err


@pytest.mark.parametrize("mismatch", ["attempt", "revision", "network"])
def test_disclosure_refuses_selectors_not_bound_to_passed_binding(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, mismatch: str
) -> None:
    terms, binding, network = _context()
    identity = x25519.Identity.generate()
    credentials = X25519Credentials(str(identity.to_public()), str(identity))
    loaded: list[object] = []
    monkeypatch.setattr(
        disclosure,
        "load_verified_claim_bytes_for_regtest_disclosure",
        lambda *_a, **_kw: loaded.append(True),
    )

    class Reader:
        def observe_claim(self, *_args: object, **_kwargs: object) -> None:
            raise AssertionError("no observation before argument binding")

        def _rpc(self, *_args: object, **_kwargs: object) -> None:
            raise AssertionError("no RPC before argument binding")

    kwargs: dict[str, Any] = {
        "keys": object(),
        "recovery_ciphertext": pyrage.encrypt(b"synthetic", [identity.to_public()]),
        "plan_ciphertext": b"synthetic encrypted plan",
        "network": network,
        "credentials": credentials,
        "funding_attempt_id": binding.funding_attempt_id,
        "binding_revision": 0,
        "intent_path": str(tmp_path / "intent.age"),
    }
    if mismatch == "attempt":
        kwargs["funding_attempt_id"] = "ee" * 32
    elif mismatch == "revision":
        kwargs["binding_revision"] = 1
    else:
        kwargs["network"] = network.model_copy(update={"genesis_hash": "00" * 32})
    with pytest.raises(disclosure.ClaimDisclosureRefusedError):
        disclosure.disclose_claim_on_regtest(Reader(), binding, terms, **kwargs)  # type: ignore[arg-type]
    assert loaded == []
    assert not (tmp_path / "intent.age").exists()
