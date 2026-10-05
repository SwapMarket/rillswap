"""Only the original opted-in dispatched owner may retain historical coordinates."""

from __future__ import annotations

import asyncio
from importlib import import_module
from typing import TYPE_CHECKING
from unittest.mock import Mock

import pytest
from rill_core.wire.canonical import canonicalize
from rill_provider.core_tx_bytes import CoreHistoricalTransaction
from test_funding_inclusion import BINDING
from test_reverse_conversion import CREDENTIALS, LIMITS, Harness

from rill_cli import reverse_conversion as module
from rill_cli.funding_inclusion import read_funding_inclusion_hint

if TYPE_CHECKING:
    from pathlib import Path

HELPERS = import_module("test_reverse_conversion")


def prepared(harness: Harness, monkeypatch: pytest.MonkeyPatch) -> module._Invocation:
    owner = harness.owner()
    harness.checkpoint(owner)
    harness.pay(owner)
    # This synthetic publisher tests ownership/admission independently of native
    # signed successor validation (covered by actual SDK and funded conformance).
    successor = HELPERS.PACKAGE.copy()
    successor["funding_history"] = [
        {"binding": BINDING.model_dump(mode="json"), "funder_session_signature": "11" * 64}
    ]
    document = canonicalize(successor)
    monkeypatch.setattr(module, "_write_recovery_snapshot", lambda *_args, **_kwargs: None)
    owner.write_recovery(document, owner.previous)
    assert owner.previous == document
    owner.capture_reader = Mock()
    owner.capture_reader.observe_funding_inclusion.return_value = CoreHistoricalTransaction(
        harness.authority.network,
        b"public-placeholder",
        BINDING.funding_txid,
        102,
        "44" * 32,
        103,
        "55" * 32,
        103,
        "55" * 32,
        2,
        1000,
        1001,
    )
    return owner


def test_original_capture_uses_acknowledged_binding_terms_equality_and_initial_digest(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    harness = Harness(tmp_path, monkeypatch)
    owner = prepared(harness, monkeypatch)
    job = harness.journal.status(harness.request.operation_id)
    generation = harness.journal.begin_capacity_query().generation
    assert owner.path is not None
    assert owner.capture_reader is not None
    deadline = 105.0
    assert owner.terms is not None
    owner.capture_funding_inclusion(BINDING, owner.terms.model_copy(), deadline)
    path = owner.path.with_suffix(".funding-inclusion.age")
    hint = read_funding_inclusion_hint(
        path,
        credentials=CREDENTIALS,
        operation_id=harness.request.operation_id,
        network=harness.authority.network,
        original_recovery_sha256=job.recovery_sha256,
        binding=BINDING,
    )
    assert hint.funding_block.height == 102
    assert hint.confirmations == 2
    owner.capture_reader.observe_funding_inclusion.assert_called_once_with(
        BINDING, owner.terms, keys=owner.crypto, deadline_seconds=5.0
    )
    assert harness.journal.status(harness.request.operation_id) == job
    assert harness.journal.begin_capacity_query().generation == generation
    harness.payer.pay.assert_called_once()
    with pytest.raises(module.ReverseConversionError, match="already attempted"):
        owner.capture_funding_inclusion(BINDING, owner.terms, deadline)
    with pytest.raises(Exception, match=r"original|reservation|invocation"):
        harness.journal.invoke(harness.reservation)


@pytest.mark.parametrize(
    "fault",
    [
        "before_payment",
        "stage",
        "journal",
        "operation",
        "terms",
        "binding",
        "no_ack",
        "deadline",
        "approval",
        "initial_digest",
        "existing",
        "partial",
        "symlink",
        "hardlink",
    ],
)
def test_missing_positive_original_ownership_or_present_artifacts_refuse_before_rpc(  # noqa: PLR0912 - explicit original-owner and unsafe-artifact refusal matrix
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fault: str
) -> None:
    harness = Harness(tmp_path, monkeypatch)
    owner = prepared(harness, monkeypatch)
    assert owner.path is not None
    assert owner.terms is not None
    binding, terms, deadline = BINDING, owner.terms, 105.0
    if fault == "before_payment":
        owner.payment_attempted = False
    elif fault == "stage":
        owner.right.stage = "unknown"
    elif fault == "journal":
        owner.right.journal = Mock()
    elif fault == "operation":
        owner.right.operation_id = "different-operation"
    elif fault == "terms":
        terms = owner.terms.model_copy(update={"max_claim_fee_sat": "1"})
    elif fault == "binding":
        binding = BINDING.model_copy(update={"binding_revision": 1})
    elif fault == "no_ack":
        owner.previous = canonicalize(harness.plain)
    elif fault == "deadline":
        deadline = 100.0
    elif fault == "approval":
        harness.clock[0] = owner.approval_deadline
    elif fault == "initial_digest":
        owner.path.write_bytes(b"OTHER")
    else:
        path = owner.path.with_suffix(".funding-inclusion.age")
        if fault == "symlink":
            path.symlink_to(tmp_path / "absent")
        else:
            path.write_bytes(b"OLD_OR_PARTIAL")
            if fault == "hardlink":
                import os  # noqa: PLC0415 - boundary fault only

                os.link(path, tmp_path / "other")
    with pytest.raises(module.ReverseConversionError):
        owner.capture_funding_inclusion(binding, terms, deadline)
    assert owner.capture_reader is not None
    assert owner.terms is not None
    owner.capture_reader.observe_funding_inclusion.assert_not_called()
    assert owner.capture_attempted
    harness.payer.pay.assert_called_once()


@pytest.mark.parametrize("fault", ["unavailable", "late", "lost_ack"])
def test_capture_uncertainty_retains_dispatched_hold_no_reacquisition(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fault: str
) -> None:
    harness = Harness(tmp_path, monkeypatch)
    owner = prepared(harness, monkeypatch)
    job = harness.journal.status(harness.request.operation_id)
    query = harness.journal.begin_capacity_query()
    assert owner.capture_reader is not None
    if fault == "unavailable":
        owner.capture_reader.observe_funding_inclusion.side_effect = RuntimeError("PRIVATE_CANARY")
    elif fault == "late":
        observed = owner.capture_reader.observe_funding_inclusion.return_value

        def late(*_args: object, **_kwargs: object) -> CoreHistoricalTransaction:
            harness.clock[0] = 105.0
            return observed

        owner.capture_reader.observe_funding_inclusion.side_effect = late
    else:
        original = module.publish_funding_inclusion_hint

        def lost(*args: object, **kwargs: object) -> None:
            original(*args, **kwargs)
            raise RuntimeError("PRIVATE_CANARY")

        monkeypatch.setattr(module, "publish_funding_inclusion_hint", lost)
    with pytest.raises((RuntimeError, module.ReverseConversionError)):
        owner.capture_funding_inclusion(BINDING, owner.terms, 105.0)
    with pytest.raises(module.ReverseConversionError, match="already attempted"):
        owner.capture_funding_inclusion(BINDING, owner.terms, 105.0)
    assert harness.journal.status(harness.request.operation_id) == job
    assert harness.journal.begin_capacity_query().generation == query.generation
    harness.payer.pay.assert_called_once()
    assert owner.capture_reader.observe_funding_inclusion.call_count == 1
    assert owner.path is not None
    assert owner.path.with_suffix(".funding-inclusion.age").exists() == (fault == "lost_ack")


@pytest.mark.parametrize("opt_in", [False, True])
def test_default_sdk_keywords_unchanged_and_opt_in_adds_only_original_capture(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, *, opt_in: bool
) -> None:
    harness = Harness(tmp_path, monkeypatch)
    seen = []

    async def sdk(*_args: object, **kwargs: object) -> object:
        seen.append(kwargs)
        return HELPERS.ReverseSwapOutcome(
            "session", HELPERS.PACKAGE["contract_hash"], "e" * 64, "f" * 64, 100500
        )

    reader = Mock()
    monkeypatch.setattr(module, "run_reverse_swap", sdk)
    monkeypatch.setattr(module, "CoreTransactionReader", reader)
    asyncio.run(
        module.run_reserved_conversion(
            harness.journal,
            harness.reservation,
            Mock(),
            config=harness.config,
            limits=LIMITS,
            credentials=CREDENTIALS,
            crypto=Mock(),
            retain_funding_inclusion=opt_in,
        )
    )
    assert ("funding_inclusion_observer" in seen[0]) is opt_in
    assert reader.call_count == int(opt_in)
    if opt_in:
        reader.assert_called_once_with(
            port=harness.config.core_port,
            cookie_path=harness.config.core_cookie_path,
            network=harness.authority.network,
        )


@pytest.mark.parametrize("invalid", [1, None, "yes"])
def test_opt_in_must_be_affirmative_bool_before_consuming_right(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, invalid: object
) -> None:
    harness = Harness(tmp_path, monkeypatch)
    monkeypatch.setattr(module, "run_reverse_swap", Mock())
    with pytest.raises(module.ReverseConversionError):
        asyncio.run(
            module.run_reserved_conversion(
                harness.journal,
                harness.reservation,
                Mock(),
                config=harness.config,
                limits=LIMITS,
                credentials=CREDENTIALS,
                crypto=Mock(),
                retain_funding_inclusion=invalid,
            )
        )
    assert harness.journal.status(harness.request.operation_id).state == "reserved"


@pytest.mark.parametrize("fault", ["acquisition", "acknowledgment"])
def test_original_public_owner_boundary_detaches_capture_failure_and_never_reexecutes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fault: str
) -> None:
    harness = Harness(tmp_path, monkeypatch)
    reader = Mock()
    reader.observe_funding_inclusion.return_value = CoreHistoricalTransaction(
        harness.authority.network,
        b"public-placeholder",
        BINDING.funding_txid,
        102,
        "44" * 32,
        103,
        "55" * 32,
        103,
        "55" * 32,
        2,
        1000,
        1001,
    )
    if fault == "acquisition":
        reader.observe_funding_inclusion.side_effect = RuntimeError("PRIVATE_CANARY")
    else:
        original = module.publish_funding_inclusion_hint

        def lost(*args: object, **kwargs: object) -> None:
            original(*args, **kwargs)
            raise RuntimeError("PRIVATE_CANARY")

        monkeypatch.setattr(module, "publish_funding_inclusion_hint", lost)
    monkeypatch.setattr(module, "CoreTransactionReader", Mock(return_value=reader))
    monkeypatch.setattr(module, "_write_recovery_snapshot", lambda *_args, **_kwargs: None)
    calls = []
    stages = []

    async def sdk(*_args: object, **kwargs: object) -> object:
        calls.append(True)
        stages.append("entered")
        owner = kwargs["payer"]
        assert kwargs["wallet"].tip_height() == 900
        harness.checkpoint(owner)
        stages.append("checkpointed")
        harness.pay(owner)
        stages.append("paid")
        successor = HELPERS.PACKAGE.copy()
        successor["funding_history"] = [
            {"binding": BINDING.model_dump(mode="json"), "funder_session_signature": "11" * 64}
        ]
        owner.write_recovery(canonicalize(successor), owner.previous)
        kwargs["funding_inclusion_observer"](BINDING, owner.terms, 105.0)
        raise AssertionError("capture error must stop the original SDK")

    monkeypatch.setattr(module, "run_reverse_swap", sdk)

    def run() -> None:
        asyncio.run(
            module.run_reserved_conversion(
                harness.journal,
                harness.reservation,
                Mock(),
                config=harness.config,
                limits=LIMITS,
                credentials=CREDENTIALS,
                crypto=Mock(),
                retain_funding_inclusion=True,
            )
        )

    with pytest.raises(module.ReverseConversionError, match="unresolved") as error:
        run()
    assert error.value.__cause__ is None
    assert error.value.__context__ is None
    assert "PRIVATE_CANARY" not in str(error.value)
    job = harness.journal.status(harness.request.operation_id)
    assert job.state == "dispatched", stages
    assert job.receipt is None
    with pytest.raises(module.ReverseConversionError):
        run()
    assert calls == [True]
    reader.observe_funding_inclusion.assert_called_once()
    harness.payer.pay.assert_called_once()
    assert harness.journal.status(harness.request.operation_id) == job
