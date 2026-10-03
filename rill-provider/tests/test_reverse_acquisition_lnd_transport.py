"""Real bound LND observation adapter behind the original-owner acquisition gate."""

from __future__ import annotations

import asyncio
import hashlib
import time
from contextlib import contextmanager
from typing import TYPE_CHECKING
from unittest.mock import Mock

import pytest
from rill_core.networks import backend_names
from test_lnd_hold_invoice import FakeChannel
from test_reverse_proposal_acquisition import _funded, _no_debt
from test_reverse_proposal_debt import _facts
from test_reverse_proposal_debt import (
    pytestmark as pytestmark,  # noqa: PLC0414 - native test policy
)
from test_reverse_proposal_reservation import reserved as reserved  # noqa: PLC0414 - fixture

from rill_provider import lnd_hold_invoice as lnd
from rill_provider import lnd_payment_send as send
from rill_provider._lnd_proto import lightning_pb2
from rill_provider._lnd_proto.invoicesrpc import invoices_pb2
from rill_provider.live_session_store import LiveSessionStoreError
from rill_provider.reverse_settlement import ReverseSettlement

if TYPE_CHECKING:
    from collections.abc import Callable, Iterator
    from pathlib import Path

    from test_reverse_proposal_reservation import ReservationCase

# ruff: noqa: SLF001 - real adapter/dispatch inspection and store assertions


@pytest.mark.parametrize("expiry", [None, "connection", "third dispatch"])
def test_consumer_real_adapter_preserves_original_window_predicate_and_transport_clock(  # noqa: PLR0915 - real adapter and dispatch fixture
    reserved: ReservationCase,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    expiry: str | None,
) -> None:
    _funded(reserved)
    terms, core, observed = _facts(reserved)
    binding = terms.invoice_binding
    # Synthetic but genuinely authenticated fixture invoice, not a real BOLT11.
    bolt11 = "lnbcrt1007u1hold"
    assert hashlib.sha256(bolt11.encode("ascii")).hexdigest() == binding.bolt11_sha256
    info = lightning_pb2.GetInfoResponse(
        identity_pubkey=binding.payee_compressed_pubkey,
        synced_to_chain=True,
        block_height=core.tip_height,
        block_hash=core.tip_hash,
        chains=[
            lightning_pb2.Chain(
                chain="bitcoin", network=backend_names(terms.network_identity).lnd_network
            )
        ],
    )
    invoice = lightning_pb2.Invoice(
        r_hash=bytes.fromhex(binding.payment_hash),
        payment_request=bolt11,
        value_msat=int(binding.amount_msat),
        creation_date=binding.created_at,
        expiry=binding.expires_at - binding.created_at,
        cltv_expiry=binding.min_final_cltv_delta,
        state=lightning_pb2.Invoice.ACCEPTED,
        htlcs=[
            lightning_pb2.InvoiceHTLC(
                amt_msat=part.amount_msat,
                expiry_height=part.expiry_height,
                state=lightning_pb2.ACCEPTED,
            )
            for part in observed.status.htlcs
        ],
    )
    responses = iter([info, invoice, info])
    channel = FakeChannel(None)
    checks = []
    real_check = send._check_submission_authority

    def checked(deadline: float, predicate: Callable[[], bool] | None) -> None:
        assert callable(predicate)
        real_check(deadline, predicate)
        checks.append((deadline, predicate))

    monkeypatch.setattr(send, "_check_submission_authority", checked)
    original_setup = channel.unary_unary

    def setup(method: str, **kwargs: object) -> object:
        rpc = original_setup(method, **kwargs)
        if expiry == "third dispatch" and len(channel.calls) == 2:
            reserved.clock.advance(30)

        def dispatch(request: object, **options: object) -> object:
            assert len(checks) == len(channel.calls) + 1
            assert options["wait_for_ready"] is False
            assert 0 < options["timeout"] <= lnd.DEADLINE_SECONDS
            channel.response = next(responses)
            return rpc(request, **options)

        return dispatch

    monkeypatch.setattr(channel, "unary_unary", setup)
    client = lnd.LndHoldInvoices(
        host="127.0.0.1",
        port=10009,
        tls_certificate_path=tmp_path / "unused.cert",
        macaroon_path=tmp_path / "unused.macaroon",
        network=terms.network_identity,
    )

    @contextmanager
    def connect() -> Iterator[send._Calls]:
        try:
            if expiry == "connection":
                reserved.clock.advance(30)
            yield send._Calls(channel, b"INVOICES")
        finally:
            channel.close()

    monkeypatch.setattr(client, "_connect", connect)
    chain = Mock()
    chain.observe_cooperative_claim_outpoint.return_value = core
    engine = ReverseSettlement(reserved.store, chain, client, reserved.origin.crypto.crypto)

    async def exercise() -> None:
        before = time.monotonic()
        if expiry is None:
            receipt = await engine._acquire_proposal_debt(
                reserved.document,
                1_700_000_001,
                wall_clock=reserved.clock.utc,
                monotonic_clock=reserved.clock.steady,
            )
            assert not receipt.replay
        else:
            with pytest.raises(LiveSessionStoreError, match="acquisition refused"):
                await engine._acquire_proposal_debt(
                    reserved.document,
                    1_700_000_001,
                    wall_clock=reserved.clock.utc,
                    monotonic_clock=reserved.clock.steady,
                )
            _no_debt(reserved)
        after = time.monotonic()
        assert channel.closed
        methods = [method for method, _ in channel.calls]
        if expiry == "connection":
            assert methods == []
        elif expiry == "third dispatch":
            assert methods == [lnd.INFO_METHOD, lnd.LOOKUP_METHOD]
        else:
            assert methods == [lnd.INFO_METHOD, lnd.LOOKUP_METHOD, lnd.INFO_METHOD]
            assert reserved.store._connection.execute("SELECT preimage FROM swaps").fetchone() == (
                "52" * 32,
            )
        if checks:
            assert len(checks) == len(channel.calls)
            assert len({deadline for deadline, _ in checks}) == 1
            deadline = checks[0][0]
            assert before + lnd.DEADLINE_SECONDS <= deadline <= after + lnd.DEADLINE_SECONDS
            assert deadline != 130  # The original nonrenewing window's unrelated clock origin.
            assert all(predicate is checks[0][1] for _, predicate in checks)
            assert checks[0][1]() is False
        if len(channel.calls) >= 2:
            assert channel.calls[1][1] == invoices_pb2.LookupInvoiceMsg(
                payment_hash=bytes.fromhex(binding.payment_hash)
            )
        assert not reserved.store._cooperation_handles

    asyncio.run(exercise())
