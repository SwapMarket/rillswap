"""The disposable miner must not outrun LND's polling/sync consumers."""

from __future__ import annotations

import json
import runpy
import subprocess
import sys
import threading
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

RUNNER = runpy.run_path(str(Path(__file__).resolve().parents[2] / "scripts/regtest_e2e.py"))


@pytest.mark.parametrize(
    "not_ready",
    [
        {"synced_to_chain": False, "block_hash": "tip"},
        {"synced_to_chain": True, "block_hash": "older-tip"},
    ],
)
def test_mining_barrier_requires_both_nodes_synced_to_exact_tip(not_ready: dict) -> None:
    ready = {"synced_to_chain": True, "block_hash": "tip"}
    stack = SimpleNamespace(
        cli=Mock(return_value="tip\n"),
        lncli=Mock(side_effect=[ready, not_ready, ready, ready]),
    )
    stop = Mock(spec=threading.Event)
    stop.is_set.return_value = False
    assert RUNNER["wait_chain_ready"](stack, stop)
    stack.cli.assert_called_once_with("getbestblockhash")
    assert stack.lncli.call_count == 4
    stop.wait.assert_called_once_with(0.25)


def test_mining_barrier_times_out_without_claiming_readiness() -> None:
    stack = SimpleNamespace(
        cli=Mock(return_value="tip"),
        lncli=Mock(return_value={"synced_to_chain": False, "block_hash": "tip"}),
    )
    with pytest.raises(RuntimeError, match="did not synchronize"):
        RUNNER["wait_chain_ready"](stack, threading.Event(), timeout=0)


def test_mining_barrier_obeys_cleanup_stop() -> None:
    stack = SimpleNamespace(cli=Mock(return_value="tip"), lncli=Mock())
    stop = threading.Event()
    stop.set()
    assert not RUNNER["wait_chain_ready"](stack, stop)
    stack.lncli.assert_not_called()


@pytest.mark.parametrize(
    "extra",
    [
        [],
        ["--web", "--unpaid-refund"],
        ["--web", "--ln-to-btc"],
        ["--web", "--reconcile-after-settle"],
    ],
)
def test_merchant_mode_rejects_incompatible_flags_before_resource_creation(
    monkeypatch: pytest.MonkeyPatch, extra: list[str]
) -> None:
    main = RUNNER["main"]
    constructor = Mock(side_effect=AssertionError("must not create resources"))
    monkeypatch.setitem(main.__globals__, "Stack", constructor)
    monkeypatch.setattr(
        sys, "argv", ["regtest_e2e.py", "--crypto-library", "unused", "--merchant-checkout", *extra]
    )
    with pytest.raises(SystemExit) as failure:
        main()
    assert failure.value.code == 2
    constructor.assert_not_called()


def container_record(run_id: str, network: str, mount: dict | None = None) -> dict:
    return {
        "Config": {"Labels": {"org.rillswap.e2e": run_id}},
        "Image": RUNNER["CORE_IMAGE"],
        "HostConfig": {
            "NetworkMode": network,
            "Binds": None,
            "VolumesFrom": None,
            "PortBindings": {"18443/tcp": [{"HostIp": "127.0.0.1"}]},
        },
        "Mounts": [
            mount or {"Type": "volume", "Destination": "/home/bitcoin/.bitcoin", "Name": "b" * 64}
        ],
    }


@pytest.mark.parametrize(
    "mount",
    [
        {"Type": "bind", "Destination": "/home/bitcoin/.bitcoin", "Name": "b" * 64},
        {"Type": "volume", "Destination": "/unknown", "Name": "b" * 64},
        {"Type": "volume", "Destination": "/home/bitcoin/.bitcoin", "Name": "named-wallet"},
    ],
)
def test_merchant_storage_inspection_refuses_unowned_mounts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, mount: dict
) -> None:
    stack = RUNNER["Stack"](tmp_path)
    monkeypatch.setitem(
        stack._record_container.__globals__,  # noqa: SLF001 - test the pre-funding guard directly
        "docker",
        Mock(return_value=json.dumps([container_record(stack.run_id, stack.net, mount)])),
    )
    with pytest.raises(RuntimeError):
        stack._record_container("a" * 64, "/home/bitcoin/.bitcoin")  # noqa: SLF001
    assert not stack.anonymous_volumes


def test_merchant_cleanup_uses_only_created_ids_and_verified_anonymous_volumes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    stack = RUNNER["Stack"](tmp_path)
    stack.merchant_mode = True
    record = container_record(stack.run_id, stack.net)
    calls: list[tuple[str, ...]] = []

    def docker(*args: str, **_kwargs: object) -> str:
        calls.append(args)
        if args[:2] == ("container", "ls"):
            return "a" * 64
        return json.dumps([record]) if args[0] == "inspect" else ""

    monkeypatch.setitem(stack._record_container.__globals__, "docker", docker)  # noqa: SLF001
    stack._record_container("a" * 64, "/home/bitcoin/.bitcoin")  # noqa: SLF001
    stack.stop()
    assert ("rm", "-f", "--volumes", "a" * 64) in calls
    assert not any(args[0] == "ps" for args in calls)
    calls.clear()
    record["Config"]["Labels"]["org.rillswap.e2e"] = "another-run"
    with pytest.raises(RuntimeError, match="identity unresolved"):
        stack.stop()
    assert not any(args[0] == "rm" for args in calls)


def test_default_cleanup_does_not_remove_volumes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    stack = RUNNER["Stack"](tmp_path)
    command = Mock(side_effect=["old-default-container", "", ""])
    monkeypatch.setitem(stack.stop.__globals__, "docker", command)
    stack.stop()
    assert command.call_args_list[1].args == ("rm", "-f", "old-default-container")


def test_public_merchant_progress_rejects_secret_canaries_and_malformed_results() -> None:
    valid = {
        "state": "awaiting_merchant_receipt",
        "swapId": "a" * 64,
        "fundingTxid": "b" * 64,
        "recoveryRef": "web-recovery-paid.age",
    }
    parse = RUNNER["merchant_progress"]
    assert parse(subprocess.CompletedProcess([], 0, json.dumps(valid), "")) == valid
    for body, stderr, code in [
        ({**valid, "preimage": "SECRET_CANARY"}, "", 0),
        (valid, "SECRET_CANARY", 0),
        (valid, "", 1),
        ({**valid, "swapId": "SECRET_CANARY"}, "", 0),
        ({}, "", 0),
    ]:
        assert parse(subprocess.CompletedProcess([], code, json.dumps(body), stderr)) is None


@pytest.mark.parametrize("failed_command", ["ls", "inspect", "rm", "network_rm"])
def test_merchant_cleanup_reports_failures_but_attempts_other_owned_resources(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    failed_command: str,
) -> None:
    stack = RUNNER["Stack"](tmp_path)
    stack.merchant_mode = True
    stack.created_containers = ["a" * 64, "c" * 64]
    stack.created_network = "d" * 64
    stack.anonymous_volumes = {"b" * 64}
    calls: list[tuple[str, ...]] = []

    def docker(*args: str, **kwargs: object) -> str:
        calls.append(args)
        assert kwargs.get("check", True) is True
        if (
            (
                failed_command == "ls"
                and args[:2] == ("container", "ls")
                and args[-1] == "id=" + "c" * 64
            )
            or (
                failed_command in ("inspect", "rm")
                and args[0] == failed_command
                and args[-1] == "c" * 64
            )
            or (failed_command == "network_rm" and args[:2] == ("network", "rm"))
        ):
            raise RuntimeError("SECRET_CANARY")
        if args[1] == "ls":
            return args[-1].removeprefix("id=")
        if args[:2] == ("network", "inspect"):
            return stack.run_id
        return (
            json.dumps([container_record(stack.run_id, stack.net)]) if args[0] == "inspect" else ""
        )

    monkeypatch.setitem(stack.stop.__globals__, "docker", docker)
    with pytest.raises(RuntimeError, match=r"^owned diagnostic cleanup identity unresolved$"):
        stack.stop()
    assert ("rm", "-f", "--volumes", "a" * 64) in calls
    assert ("network", "rm", "d" * 64) in calls


def test_merchant_cleanup_accepts_only_affirmative_resource_absence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    stack = RUNNER["Stack"](tmp_path)
    stack.merchant_mode = True
    stack.created_containers = ["a" * 64]
    stack.created_network = "d" * 64
    command = Mock(return_value="")
    monkeypatch.setitem(stack.stop.__globals__, "docker", command)
    stack.stop()
    assert all(
        call.args[1] == "ls" and call.kwargs.get("check", True) for call in command.call_args_list
    )


@pytest.mark.parametrize("failure", ["client", "provider", "merchant", "files", "stack"])
def test_new_mode_teardown_attempts_every_action_and_redacts_errors(
    failure: str, capsys: pytest.CaptureFixture[str]
) -> None:
    resources = {
        name: Mock()
        for name in (
            "client",
            "provider",
            "merchant",
            "files",
            "stack",
            "stop_mining",
            "relay_stop",
        )
    }
    for name in ("client", "provider"):
        resources[name].poll.return_value = None
    method = (
        "wait" if failure in ("client", "provider") else "close" if failure == "files" else "stop"
    )
    getattr(resources[failure], method).side_effect = RuntimeError("SECRET_CANARY")
    assert RUNNER["cleanup_merchant_run"](**resources, keep=False) is False
    for name in ("client", "provider"):
        resources[name].terminate.assert_called_once()
    for name in ("merchant", "stack"):
        resources[name].stop.assert_called_once()
    resources["files"].close.assert_called_once()
    resources["stop_mining"].set.assert_called_once()
    resources["relay_stop"].set.assert_called_once()
    assert capsys.readouterr().err.endswith("merchant diagnostic cleanup refused\n")


def test_keep_stops_host_children_but_preserves_containers() -> None:
    resources = {
        name: Mock()
        for name in (
            "client",
            "provider",
            "merchant",
            "files",
            "stack",
            "stop_mining",
            "relay_stop",
        )
    }
    assert RUNNER["cleanup_merchant_run"](**resources, keep=True)
    resources["merchant"].stop.assert_called_once()
    resources["stack"].stop.assert_not_called()


def test_merchant_web_driver_uses_verified_bun_not_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    command = RUNNER["web_client_command"]
    monkeypatch.setattr(
        command.__globals__["shutil"],
        "which",
        Mock(side_effect=AssertionError("PATH must not select Bun")),
    )
    stack = SimpleNamespace(host_port=lambda *_: 1234, core="core")
    args = SimpleNamespace(merchant_checkout=True, timeout=600)
    age = SimpleNamespace(to_public=lambda: "fixture-recipient")
    result = command(stack, args, tmp_path, "ws://fixture", "a" * 64, "invoice", age)
    assert result[0] == str(RUNNER["MERCHANT_BUN"])
    assert result[-2:] == ["--merchant-checkout", str(tmp_path / "merchant/checkout.json")]


@pytest.mark.parametrize(
    "fault",
    [
        None,
        "wrong_hash",
        "wrong_amount",
        "foreign_key",
        "bad_signature",
        "extra_field",
        "duplicate_event",
        "changed_delivery",
        "changed_attempt",
    ],
)
def test_independent_merchant_acceptance_requires_bound_stable_signed_receipt(
    tmp_path: Path,
    fault: str | None,
) -> None:
    from Cryptodome.Signature import eddsa  # noqa: PLC0415 - matches the funded diagnostic verifier

    merchant = RUNNER["MerchantDiagnostic"](tmp_path, Path("unused-bun"))
    seed = bytes(range(32))
    key = eddsa.import_private_key(seed)
    merchant.public_key = key.public_key().export_key(format="raw").hex()
    terms = {
        "merchantOrigin": "https://merchant.invalid",
        "intentId": "intent_fixture_001",
        "attemptId": "attempt_fixture_001",
        "paymentHash": "a" * 64,
        "amountMsat": "50000000",
    }
    merchant.checkout = {
        "id": terms["intentId"],
        "attempt": {"terms": terms, "invoice": "private-invoice-fixture"},
    }
    event = {
        "version": "checkout-event/1",
        "id": "event_fixture_001",
        "type": "payment.accepted",
        **terms,
        "acceptedAt": 1234,
    }
    if fault == "wrong_hash":
        event["paymentHash"] = "b" * 64
    if fault == "wrong_amount":
        event["amountMsat"] = "50001000"
    message = [
        "rillswap-payment-event/1",
        *(
            event[name]
            for name in (
                "version",
                "id",
                "merchantOrigin",
                "type",
                "intentId",
                "attemptId",
                "paymentHash",
                "amountMsat",
                "acceptedAt",
            )
        ),
    ]
    signature = (
        eddsa.new(key, "rfc8032").sign(json.dumps(message, separators=(",", ":")).encode()).hex()
    )
    envelope = {
        "algorithm": "Ed25519",
        "publicKey": merchant.public_key,
        "event": event,
        "signature": signature,
    }
    if fault == "foreign_key":
        envelope["publicKey"] = "b" * 64
    if fault == "bad_signature":
        envelope["signature"] = "0" * 128
    if fault == "extra_field":
        envelope["preimage"] = "SECRET_CANARY"
    events = [envelope] * (2 if fault == "duplicate_event" else 1)
    status = {"status": "paid", "attempt": merchant.checkout["attempt"]}
    if fault == "changed_attempt":
        status["attempt"] = {"invoice": "foreign-invoice"}
    merchant.request = Mock(
        side_effect=[status, events, [] if fault == "changed_delivery" else events]
    )
    assert merchant.observe_paid() is (fault is None)
