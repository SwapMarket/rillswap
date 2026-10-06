"""Actual supported accounting while one original outgoing hold remains pending.

No credit, inventory eligibility, SDK invocation or production funding is created.
The original hold fixture's send, single cancellation and cleanup remain intact.
"""

from __future__ import annotations

import ast
import os
from types import SimpleNamespace
from typing import TYPE_CHECKING

import pytest
import test_lnd_payment_pinned as fixture

if TYPE_CHECKING:
    from pathlib import Path

# Embedded owned programs are compiled and their budget checked offline.
# ruff: noqa: E501

BEFORE_SEND = r"""        print('PHASE: pending_accounting_credentials', file=sys.stderr)
        from rill_provider.lnd_treasury_observation import LndTreasuryObserver
        pending_scope=ln.BakeMacaroonRequest(permissions=[
            ln.MacaroonPermission(entity=entity,action='read')
            for entity in ('info','offchain')],root_key_id=0,allow_external_permissions=False)
        pending_encoded=call(a,a_secret,'BakeMacaroon',ln.BakeMacaroonRequest,
            ln.BakeMacaroonResponse,pending_scope).macaroon
        pending_file=private_file(credentials,'pending-accounting-read.macaroon',bytes.fromhex(pending_encoded))
        pending_secret=pending_file.read_bytes()
        def pending_read_timeout(cap=5.0):
            remaining=pending_accounting_deadline-time.monotonic()
            # This test-local elapsed bound does not reconstruct or renew the
            # server's payment authority. Invalid or expired clocks refuse reads.
            assert 0<remaining<=30.0,'original pending observation budget closed'
            return min(cap,remaining)
        print('PHASE: hold_send_once', file=sys.stderr)
"""

ACCOUNTING = r"""            print('PHASE: pending_treasury_accounting', file=sys.stderr)
            before_info=call(a,pending_secret,'GetInfo',ln.GetInfoRequest,ln.GetInfoResponse,
                ln.GetInfoRequest(),timeout=pending_read_timeout())
            before_channels=call(a,pending_secret,'ListChannels',ln.ListChannelsRequest,ln.ListChannelsResponse,
                ln.ListChannelsRequest(),timeout=pending_read_timeout())
            pending_observer=LndTreasuryObserver(host='127.0.0.1',port=10009,
                tls_certificate_path='/work/public/a.cert',read_macaroon_path=pending_file,
                network=network,expected_node_pubkey=a_key)
            accounting=pending_observer.observe_accounting(deadline_seconds=pending_read_timeout(10.0))
            after_channels=call(a,pending_secret,'ListChannels',ln.ListChannelsRequest,ln.ListChannelsResponse,
                ln.ListChannelsRequest(),timeout=pending_read_timeout())
            after_info=call(a,pending_secret,'GetInfo',ln.GetInfoRequest,ln.GetInfoResponse,
                ln.GetInfoRequest(),timeout=pending_read_timeout())
            histories=call(a,pending_secret,'ListPayments',ln.ListPaymentsRequest,ln.ListPaymentsResponse,
                ln.ListPaymentsRequest(include_incomplete=True),timeout=pending_read_timeout())
            pending_read_timeout()  # Late knowledge is not a successful bounded observation.
            assert before_info.identity_pubkey==after_info.identity_pubkey==a_key
            assert before_info.synced_to_chain and after_info.synced_to_chain
            assert (before_info.block_height,before_info.block_hash)==(after_info.block_height,after_info.block_hash)
            assert accounting.context.observed_node_pubkey==a_key
            assert accounting.context.before_tip==accounting.context.after_tip
            assert (accounting.context.before_tip.height,accounting.context.before_tip.block_hash)==(
                before_info.block_height,before_info.block_hash)
            assert len(before_channels.channels)==len(after_channels.channels)==1
            before_channel,after_channel=before_channels.channels[0],after_channels.channels[0]
            for channel in (before_channel,after_channel):
                assert channel.active and channel.chan_id==channel_id
                assert channel.HasField('local_constraints') and channel.HasField('remote_constraints')
                assert not channel.custom_channel_data
                assert len(channel.pending_htlcs)==1
                pending=channel.pending_htlcs[0]
                assert pending.incoming is False and pending.amount*1000==amount_msat
                assert pending.htlc_index==part.htlc_index and pending.expiration_height==part.expiry_height
            assert before_channel.channel_point==after_channel.channel_point
            assert before_channel.commitment_type==after_channel.commitment_type
            assert before_channel.local_balance==after_channel.local_balance
            assert before_channel.local_constraints==after_channel.local_constraints
            assert before_channel.remote_constraints==after_channel.remote_constraints
            assert accounting.coverage_complete is True
            assert accounting.channel_count==accounting.classified_channel_count==1
            # Characterize the existing adapter's separate floors against actual
            # daemon fields. Do not deduct commitment fees or outgoing principal
            # again, add incoming, or turn a positive floor into spending rights.
            assert accounting.classified_local_commitment_floor_msat==1000*before_channel.local_balance
            assert accounting.active_classified_local_commitment_floor_msat==1000*before_channel.local_balance
            assert accounting.classified_local_reserve_msat==1000*before_channel.local_constraints.chan_reserve_sat
            assert accounting.classified_pending_outgoing_floor_msat==amount_msat==1000000
            assert accounting.classified_pending_incoming_floor_msat==0
            assert accounting.classified_local_commitment_floor_msat-accounting.classified_local_reserve_msat>0
            matches=[payment for payment in histories.payments if payment.payment_hash==selected_hash.hex()]
            assert len(matches)==1 and matches[0].status==ln.Payment.IN_FLIGHT
            assert matches[0].htlcs[0].attempt_id==live.htlcs[0].attempt_id
            assert one_attempt(matches[0],ln.HTLCAttempt.IN_FLIGHT,b_key,channel_id,amount_msat)==(
                route_expiry,hop_expiry,mpp_total)
            print('PHASE: hold_cancel_once', file=sys.stderr)
"""


def _replace_once(program: str, before: str, after: str) -> str:
    assert program.count(before) == 1, "owned pending accounting boundary changed"
    return program.replace(before, after, 1)


def _program() -> str:
    program = _replace_once(
        fixture.HELD_HTLC_PAYMENT,
        "        print('PHASE: hold_send_once', file=sys.stderr)\n",
        BEFORE_SEND,
    )
    program = _replace_once(
        program,
        "        sending = send(router.SendPaymentRequest(",
        "        pending_accounting_deadline=time.monotonic()+30.0\n"
        "        sending = send(router.SendPaymentRequest(",
    )
    program = _replace_once(
        program,
        "            print('PHASE: hold_cancel_once', file=sys.stderr)\n",
        ACCOUNTING,
    )
    return _replace_once(
        program,
        "'payment_failed': True, 'history_returned': bool(history),",
        "'payment_failed': True, 'history_returned': bool(history),"
        "'pending_accounting_observed': True,'pending_outgoing_floor_msat':amount_msat,"
        "'pending_accounting_coverage_complete': accounting.coverage_complete,",
    )


def test_pending_accounting_program_preserves_send_and_single_cancel_contract() -> None:
    program = _program()
    compile(program, "<owned-pending-accounting>", "exec")
    ast.parse(program)
    assert program.count("pending_accounting_deadline=time.monotonic()+30.0") == 1
    assert program.index("pending_accounting_deadline=") < program.index("        sending = send(")
    # The shared template contains an inactive ordinary-payment branch for its
    # other scenarios. Preserve every existing request, not a false global count.
    assert program.count(
        "fee_limit_msat=0, timeout_seconds=30)"
    ) == fixture.HELD_HTLC_PAYMENT.count("fee_limit_msat=0, timeout_seconds=30)")
    assert program.count("cancel_started = True") == fixture.HELD_HTLC_PAYMENT.count(
        "cancel_started = True"
    )
    assert "assert history[0].lnd_attempt_id == failed.htlcs[0].attempt_id" in program
    assert "if not cancel_started and not settlement_observed:" in program
    assert "timeout=pending_read_timeout()" in ACCOUNTING
    assert "deadline_seconds=pending_read_timeout(10.0)" in ACCOUNTING


@pytest.mark.parametrize(("now", "expected"), [(100.0, 5.0), (127.0, 3.0), (129.75, 0.25)])
def test_new_pending_reads_use_only_the_remaining_original_budget(
    now: float, expected: float
) -> None:
    function = next(
        node
        for node in ast.walk(ast.parse(_program()))
        if isinstance(node, ast.FunctionDef) and node.name == "pending_read_timeout"
    )
    namespace = {
        "time": SimpleNamespace(monotonic=lambda: now),
        "pending_accounting_deadline": 130.0,
    }
    exec(  # noqa: S102 - only this owned template's budget function, never external code
        compile(ast.Module(body=[function], type_ignores=[]), "<pending-read-budget>", "exec"),
        namespace,
    )
    assert namespace["pending_read_timeout"]() == expected


@pytest.mark.parametrize("now", [130.0, 131.0, 99.0, float("nan"), float("inf")])
def test_closed_or_invalid_pending_budget_never_admits_an_added_read(now: float) -> None:
    function = next(
        node
        for node in ast.walk(ast.parse(_program()))
        if isinstance(node, ast.FunctionDef) and node.name == "pending_read_timeout"
    )
    namespace = {
        "time": SimpleNamespace(monotonic=lambda: now),
        "pending_accounting_deadline": 130.0,
    }
    exec(  # noqa: S102 - only this owned template's budget function, never external code
        compile(ast.Module(body=[function], type_ignores=[]), "<pending-read-budget>", "exec"),
        namespace,
    )
    with pytest.raises(AssertionError, match="original pending observation budget closed"):
        namespace["pending_read_timeout"]()


@pytest.mark.lnd
@pytest.mark.skipif(
    os.environ.get("RILLSWAP_RUN_LND") != "1",
    reason="explicit pinned disposable LND accounting opt-in",
)
def test_pinned_supported_accounting_with_one_committed_pending_outgoing_htlc(
    tmp_path: Path,
) -> None:
    evidence = fixture._run_two_node_sidecar(  # noqa: SLF001 - unchanged isolated digest-pinned setup and owned cleanup
        tmp_path,
        _program(),
        prefix="accounting-pending",
        deadline=270,
    )
    assert evidence["pending_accounting_observed"] is True
    assert evidence["pending_accounting_coverage_complete"] is True
    assert evidence["pending_outgoing_floor_msat"] == 1_000_000
    assert evidence["payment_failed"] is True
    assert evidence["backend_hold_observed"] is True
    assert evidence["observer_refused_custom"] is True
