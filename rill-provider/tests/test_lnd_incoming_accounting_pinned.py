"""Committed incoming value stays separate from a receiver's local channel floor.

This controlled zero-push channel says nothing about the node's wallet balance,
available inventory, atomic observations or permission to spend pending income.
"""

from __future__ import annotations

import ast
import os
from typing import TYPE_CHECKING

import pytest
import test_lnd_payment_pinned as fixture
import test_lnd_pending_accounting_pinned as outgoing

if TYPE_CHECKING:
    from pathlib import Path

# Embedded owned programs preserve and structurally check the original fixture.
# ruff: noqa: E501, SLF001


def _segments() -> tuple[str, str]:
    before = outgoing._replace_once(
        outgoing.BEFORE_SEND,
        "pending_encoded=call(a,a_secret,'BakeMacaroon'",
        "pending_encoded=call(b,b_secret,'BakeMacaroon'",
    )
    before = outgoing._replace_once(
        before, "'pending-accounting-read.macaroon'", "'incoming-accounting-read.macaroon'"
    )
    before = outgoing._replace_once(
        before,
        "        pending_secret=pending_file.read_bytes()\n",
        "        pending_secret=pending_file.read_bytes()\n"
        "        # Measure the explicit zero-push channel before sending. This\n"
        "        # setup-only read neither creates nor renews a payment deadline.\n"
        "        incoming_initial=call(b,pending_secret,'ListChannels',ln.ListChannelsRequest,\n"
        "            ln.ListChannelsResponse,ln.ListChannelsRequest(),timeout=5)\n"
        "        assert len(incoming_initial.channels)==1\n"
        "        assert incoming_initial.channels[0].local_balance==0\n",
    )
    accounting = outgoing._replace_once(
        outgoing.ACCOUNTING,
        "histories=call(a,pending_secret,'ListPayments'",
        "histories=call(a,payment_file.read_bytes(),'ListPayments'",
    )
    # Only receiver accounting uses B's token. Original payer payment history
    # must use A's independent offchain-read credential, never B's token on A.
    assert accounting.count("call(a,pending_secret,") == 4
    accounting = accounting.replace("call(a,pending_secret,", "call(b,pending_secret,")
    for before_text, after_text in (
        ("port=10009,", "port=10010,"),
        (
            "tls_certificate_path='/work/public/a.cert'",
            "tls_certificate_path='/work/public/b.cert'",
        ),
        ("expected_node_pubkey=a_key", "expected_node_pubkey=b_key"),
        (
            "before_info.identity_pubkey==after_info.identity_pubkey==a_key",
            "before_info.identity_pubkey==after_info.identity_pubkey==b_key",
        ),
        (
            "accounting.context.observed_node_pubkey==a_key",
            "accounting.context.observed_node_pubkey==b_key",
        ),
        ("pending.incoming is False", "pending.incoming is True"),
        (
            "accounting.classified_pending_outgoing_floor_msat==amount_msat==1000000",
            "accounting.classified_pending_outgoing_floor_msat==0",
        ),
        (
            "accounting.classified_pending_incoming_floor_msat==0",
            "accounting.classified_pending_incoming_floor_msat==amount_msat==1000000",
        ),
        (
            "accounting.classified_local_commitment_floor_msat-accounting.classified_local_reserve_msat>0",
            (
                "before_channel.local_balance==incoming_initial.channels[0].local_balance==0\n"
                "            assert before_channel.channel_point==incoming_initial.channels[0].channel_point\n"
                "            assert accounting.classified_local_commitment_floor_msat==0\n"
                "            assert accounting.active_classified_local_commitment_floor_msat==0"
            ),
        ),
    ):
        accounting = outgoing._replace_once(accounting, before_text, after_text)
    return before, accounting


def _program() -> str:
    before, accounting = _segments()
    program = outgoing._replace_once(outgoing._program(), outgoing.BEFORE_SEND, before)
    program = outgoing._replace_once(program, outgoing.ACCOUNTING, accounting)
    return outgoing._replace_once(
        program,
        "'pending_outgoing_floor_msat':amount_msat,",
        "'pending_incoming_floor_msat':amount_msat,'receiver_local_channel_floor_msat':0,",
    )


def test_incoming_program_keeps_receiver_and_payer_read_roles_separate() -> None:
    program = _program()
    compile(program, "<owned-incoming-accounting>", "exec")
    ast.parse(program)
    before, accounting = _segments()
    assert "pending_encoded=call(b,b_secret,'BakeMacaroon'" in before
    assert "histories=call(a,payment_file.read_bytes(),'ListPayments'" in accounting
    assert accounting.count("call(b,pending_secret,") == 4
    assert "expected_node_pubkey=b_key" in accounting
    assert "accounting.context.observed_node_pubkey==b_key" in accounting
    assert "pending.incoming is True" in accounting
    assert "classified_pending_incoming_floor_msat==amount_msat==1000000" in accounting
    assert "classified_local_commitment_floor_msat==0" in accounting
    assert "classified_pending_outgoing_floor_msat==0" in accounting


def test_incoming_program_preserves_original_deadline_and_single_cancel_tail() -> None:
    program = _program()
    setup_read = program.index("incoming_initial=call(")
    deadline = program.index("pending_accounting_deadline=time.monotonic()+30.0")
    send = program.index("        sending = send(")
    accounting = program.index("            print('PHASE: pending_treasury_accounting'")
    cancel = program.index("            print('PHASE: hold_cancel_once'")
    assert setup_read < deadline < send < accounting < cancel
    assert program.count(
        "fee_limit_msat=0, timeout_seconds=30)"
    ) == fixture.HELD_HTLC_PAYMENT.count("fee_limit_msat=0, timeout_seconds=30)")
    assert "deadline_seconds=pending_read_timeout(10.0)" in program
    assert "if not cancel_started and not settlement_observed:" in program
    assert "cancel_started = True" in program
    assert "assert history[0].lnd_attempt_id == failed.htlcs[0].attempt_id" in program


@pytest.mark.lnd
@pytest.mark.skipif(
    os.environ.get("RILLSWAP_RUN_LND") != "1",
    reason="explicit pinned receiver pending-accounting opt-in",
)
def test_pinned_incoming_hold_never_increases_receiver_local_channel_floor(tmp_path: Path) -> None:
    evidence = fixture._run_two_node_sidecar(
        tmp_path,
        _program(),
        prefix="accounting-incoming",
        deadline=270,
    )
    assert evidence["pending_accounting_observed"] is True
    assert evidence["pending_accounting_coverage_complete"] is True
    assert evidence["pending_incoming_floor_msat"] == 1_000_000
    assert evidence["receiver_local_channel_floor_msat"] == 0
    assert evidence["payment_failed"] is True
    assert evidence["backend_hold_observed"] is True
    assert evidence["observer_refused_custom"] is True
