"""Two-launch test supervisor, no container restart or wallet initialization retry."""

from __future__ import annotations

import ast
import os
import secrets
import time
from importlib import import_module
from typing import TYPE_CHECKING

import pytest

from rill_provider._lnd_proto import lightning_pb2 as ln

if TYPE_CHECKING:
    from pathlib import Path

helpers = import_module("test_lnd_payment_pinned")


def test_restart_history_uses_deterministic_full_messages_without_changing_crash_snapshots() -> (
    None
):
    program = import_module("test_merchant_conversion_pinned")._program(  # noqa: SLF001 - actual generated assertions
        completion=True, restart=True
    )
    nodes = list(ast.walk(ast.parse(program)))
    restart = [
        node
        for node in nodes
        if isinstance(node, ast.FunctionDef) and node.name == "source_restart"
    ]
    final = [
        node
        for node in nodes
        if isinstance(node, ast.If) and ast.unparse(node.test) == "restart_snapshot is not None"
    ]
    assert len(restart) == len(final) == 1
    calls = [
        node
        for root in (*restart, *final)
        for node in ast.walk(root)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "SerializeToString"
        and any(keyword.arg == "deterministic" for keyword in node.keywords)
    ]
    assert len(calls) == 6
    assert all(
        any(
            keyword.arg == "deterministic"
            and isinstance(keyword.value, ast.Constant)
            and keyword.value.value is True
            for keyword in call.keywords
        )
        for call in calls
    )
    # Accepted M39 raw snapshots and comparisons remain their original contract.
    assert "assert final_payments==original_payments" in program
    assert "assert final_paid.SerializeToString()==original_payments" in program


@pytest.mark.parametrize(
    "fault", ["none", "feature", "hash", "state", "amount", "htlc_order", "htlc_value"]
)
def test_deterministic_history_preserves_all_invoice_and_payment_values(fault: str) -> None:
    left, right = ln.ListInvoiceResponse(), ln.ListInvoiceResponse()
    for response, keys in ((left, (9, 14, 17)), (right, (17, 14, 9))):
        invoice = response.invoices.add(
            r_hash=b"a" * 32, state=ln.Invoice.SETTLED, amt_paid_msat=200000000
        )
        for key in keys:
            invoice.features[key].name = str(key)
    a, b = ln.ListPaymentsResponse(), ln.ListPaymentsResponse()
    for response in (a, b):
        payment = response.payments.add(
            payment_hash="b" * 64, status=ln.Payment.SUCCEEDED, value_msat=100000000, fee_msat=1000
        )
        payment.htlcs.add(attempt_id=1, status=ln.HTLCAttempt.SUCCEEDED)
        payment.htlcs.add(attempt_id=2, status=ln.HTLCAttempt.FAILED)
    if fault == "feature":
        right.invoices[0].features[9].name = "changed"
    elif fault == "hash":
        right.invoices[0].r_hash = b"c" * 32
    elif fault == "state":
        right.invoices[0].state = ln.Invoice.CANCELED
    elif fault == "amount":
        right.invoices[0].amt_paid_msat += 1
    elif fault == "htlc_order":
        b.payments[0].htlcs.reverse()
    elif fault == "htlc_value":
        b.payments[0].htlcs[0].attempt_id = 3
    equal = left.SerializeToString(deterministic=True) == right.SerializeToString(
        deterministic=True
    ) and a.SerializeToString(deterministic=True) == b.SerializeToString(deterministic=True)
    assert equal is (fault == "none")


def test_original_launch_and_missing_restart_inputs_keep_existing_gates() -> None:
    assert helpers._lnd_runtime(supervised=False) == (helpers.LND_IMAGE,)  # noqa: SLF001 - fixture composition contract
    supervised = helpers._lnd_runtime(supervised=True)  # noqa: SLF001 - exact controlled command
    assert supervised == (
        "--entrypoint",
        "/bin/sh",
        helpers.LND_IMAGE,
        "-c",
        helpers.SOURCE_SUPERVISOR,
        "rill-source-supervisor",
    )
    assert "exec lnd" not in helpers.SOURCE_SUPERVISOR
    assert "for launch in 1 2" in helpers.SOURCE_SUPERVISOR
    assert '[ "$status" -eq 0 ] || exit' in helpers.SOURCE_SUPERVISOR
    with pytest.raises(ValueError, match="explicit bundle and TLS"):
        helpers._merchant_proof_mounts("merchant_restart", None, None)  # noqa: SLF001 - admission precedes effects
    assert "source_wallet_password = None" in helpers.CHANNEL_SETUP
    assert (
        "if label=='b' and os.environ.get('RILLSWAP_TEST_SOURCE_RESTART')=='1'"
        in helpers.CHANNEL_SETUP
    )
    assert "del wallet_password" in helpers.CHANNEL_SETUP
    compile(helpers.CHANNEL_SETUP, "<restart-setup>", "exec")


@pytest.mark.lnd
@pytest.mark.skipif(
    os.environ.get("RILLSWAP_RUN_LND") != "1",
    reason="explicit pinned shell/image conformance opt-in",
)
@pytest.mark.parametrize(
    "mode", ["graceful", "both_graceful", "failed", "terminate_child", "terminate_between"]
)
def test_pinned_supervisor_reaps_and_never_relaunches_on_failure_or_termination(
    tmp_path: Path, mode: str
) -> None:
    assert helpers.DOCKER is not None
    run_id = secrets.token_hex(16)
    name = f"rillswap-supervisor-{run_id}"
    label = f"org.rillswap.test-run={run_id}"
    literal = helpers.SOURCE_SUPERVISOR
    assert literal.count('/bin/lnd "$@"') == 1
    # Docker tmpfs can be nonexecutable. The pinned shell reads this fake child
    # without changing tmpfs protections or the supervisor's control flow.
    literal = literal.replace('/bin/lnd "$@"', '/bin/sh /tmp/owned-fake-lnd "$@"')
    if mode == "terminate_between":
        # Lengthen only the inter-launch test delay to make the signal location
        # deterministic; the original trap/wait/exit/relaunch code is unchanged.
        assert literal.count("sleep 0.2") == 1
        literal = literal.replace("sleep 0.2", "sleep 5")
    fake = """#!/bin/sh
n=$(cat /tmp/launch-count 2>/dev/null || printf 0)
n=$((n+1))
printf '%s' "$n" >/tmp/launch-count
if [ "$1" = failed ]; then exit 7; fi
if [ "$1" = terminate_child ]; then
    trap 'exit 0' TERM INT
    printf 'FAKE_READY:child\\n'
    while :; do sleep 1; done
fi
if [ "$n" -eq 1 ]; then exit 0; fi
if [ "$1" = both_graceful ]; then exit 0; fi
exit 9
"""
    program = (
        "cat > /tmp/owned-fake-lnd <<'OWNED_FAKE'\n"
        + fake
        + "OWNED_FAKE\nchmod 700 /tmp/owned-fake-lnd\n"
        + literal
    )
    try:
        helpers._docker(  # noqa: SLF001 - owned pinned image, no private artifacts
            "run",
            "--detach",
            "--name",
            name,
            "--label",
            label,
            "--network",
            "none",
            "--tmpfs",
            "/tmp:rw,mode=0700",  # noqa: S108 - independent owned container tmpfs
            "--entrypoint",
            "/bin/sh",
            helpers.LND_IMAGE,
            "-c",
            program,
            "owned-supervisor-test",
            mode,
        )
        if mode.startswith("terminate"):
            marker = "FAKE_READY:child" if mode == "terminate_child" else "RILL_SUPERVISOR:between"
            deadline = time.monotonic() + 10
            while marker not in helpers._docker("logs", name):  # noqa: SLF001 - fixed public readiness only
                assert time.monotonic() < deadline, (
                    "supervisor did not reach the owned signal boundary"
                )
                time.sleep(0.02)
            helpers._docker("kill", "--signal", "TERM", name)  # noqa: SLF001 - PID1 termination must suppress relaunch
        expected = {
            "graceful": "9",
            "both_graceful": "0",
            "failed": "7",
            "terminate_child": "143",
            "terminate_between": "143",
        }[mode]
        assert helpers._docker("wait", name, timeout=15).strip() == expected  # noqa: SLF001 - no hung child remains
        events = [
            line
            for line in helpers._docker("logs", name).splitlines()  # noqa: SLF001 - fixed outputs only
            if line.startswith("RILL_SUPERVISOR:")
        ]
        if mode in ("graceful", "both_graceful"):
            assert events == [
                "RILL_SUPERVISOR:launch_1",
                "RILL_SUPERVISOR:reap_1_0",
                "RILL_SUPERVISOR:between",
                "RILL_SUPERVISOR:launch_2",
                "RILL_SUPERVISOR:reap_2_0"
                if mode == "both_graceful"
                else "RILL_SUPERVISOR:reap_2_9",
            ]
        elif mode == "failed":
            assert events == ["RILL_SUPERVISOR:launch_1", "RILL_SUPERVISOR:reap_1_7"]
        else:
            assert events[-1] == "RILL_SUPERVISOR:terminating"
            assert "RILL_SUPERVISOR:launch_2" not in events
    finally:
        helpers._cleanup_containers((name,), run_id, tmp_path / "unused-public-cert")  # noqa: SLF001 - reuse verified ownership cleanup
