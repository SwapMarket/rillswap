"""EVM settlement lifecycles (RS-010) against the real store and fake backends."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any
from unittest.mock import Mock

import pytest
from evm_fixtures import PAYMENT_HASH, PREIMAGE, evm_terms
from test_cooperation_burn import FixtureEnvelopeSigner
from test_evm_swap_store import _accept_evm_swap

from rill_provider.evm_htlc import ClaimEvent, LockupEvent, SignedTx, TxReceipt
from rill_provider.evm_quote_policy import EvmSchedule
from rill_provider.evm_settlement import EvmSettlementEngine
from rill_provider.lnd_hold_invoice import HeldHtlc, HoldInvoiceStatus
from rill_provider.lnd_payment_send import PaymentOutcome, PreparedPayment
from rill_provider.payment_dispatch_record import PaymentAuthority

if TYPE_CHECKING:
    from pathlib import Path

    from rill_core.wire.messages import EvmContractTerms
    from test_live_session_store import Harness

    from rill_provider import live_session_store as live

pytest.importorskip("rill_crypto")
SCHEDULE = EvmSchedule(
    funding_confirmations=1,
    settlement_confirmations=1,
    forward_timelock_delay_blocks=1000,
    reverse_timelock_delay_blocks=500,
    learn_and_claim_seconds=1,
    refund_and_ln_resolution_seconds=1,
)
LOCK_TX = "ab" * 32


@pytest.fixture
def harness(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Harness:
    from test_live_session_store import Harness  # noqa: PLC0415 - heavy fixture module

    result = Harness(tmp_path, monkeypatch)
    result.provision()
    return result


@dataclass
class FakeHtlc:
    """An in-memory HTLC chain: lockups, claims, receipts, and signed sends."""

    tip: int = 10
    signer_address: str = "0x" + "bd" * 20
    lockups: list[LockupEvent] = field(default_factory=list)
    claim: ClaimEvent | None = None
    active: bool = False
    receipts: dict[str, TxReceipt] = field(default_factory=dict)
    broadcasts: list[bytes] = field(default_factory=list)
    allowance_pending: bool = False
    signed: int = 0

    def block_number(self) -> int:
        return self.tip

    def find_lockups(
        self, payment_hash: str, *, from_block: int, to_block: int
    ) -> list[LockupEvent]:
        assert payment_hash == PAYMENT_HASH
        assert 0 <= from_block <= to_block
        return list(self.lockups)

    def lock_active(self, _params: Any) -> bool:  # noqa: ANN401
        return self.active

    def find_claim(self, _payment_hash: str, **_window: int) -> ClaimEvent | None:
        return self.claim

    def receipt(self, tx_hash: str) -> TxReceipt | None:
        return self.receipts.get(tx_hash)

    def confirmations(self, tx_hash: str) -> int:
        receipt = self.receipts[tx_hash]
        return self.tip - receipt.block_number + 1

    def ensure_allowance(self, _token: str, _amount: int) -> str | None:
        return "ee" * 32 if self.allowance_pending else None

    def _sign(self) -> SignedTx:
        self.signed += 1
        return SignedTx(f"{self.signed:02x}" * 32, b"signed-%d" % self.signed)

    def prepare_lock(self, _params: Any) -> SignedTx:  # noqa: ANN401
        return self._sign()

    def prepare_claim(self, _params: Any, preimage: str) -> SignedTx:  # noqa: ANN401
        assert preimage == PREIMAGE
        return self._sign()

    def prepare_refund(self, _params: Any) -> SignedTx:  # noqa: ANN401
        return self._sign()

    def broadcast(self, raw: bytes) -> str:
        self.broadcasts.append(raw)
        return "00" * 32


def _lockup(terms: EvmContractTerms, block: int = 5) -> LockupEvent:
    from rill_provider.evm_htlc import LockParams  # noqa: PLC0415

    return LockupEvent(LOCK_TX, 3, block, LockParams.from_terms(terms))


def _lightning(terms: EvmContractTerms, outcome: PaymentOutcome) -> Mock:
    lightning = Mock()
    lightning.track.return_value = outcome
    lightning.prepare.return_value = PreparedPayment(
        b"exact request",
        terms.invoice_binding.payment_hash,
        terms.invoice_binding.expires_at,
        terms.timing_policy.model_dump()["max_outgoing_htlc_expiry_height"],
        terms.invoice_binding.min_final_cltv_delta,
        PaymentAuthority("03" + "ab" * 32, terms.network_identity),
    )
    lightning.send.return_value = PaymentOutcome("IN_FLIGHT")
    return lightning


def _engine(  # noqa: PLR0913 - explicit fakes
    store: live.LiveSessionStore,
    harness: Harness,
    htlc: FakeHtlc,
    *,
    lightning: Mock | None = None,
    hold: Mock | None = None,
    btc_tip: int = 100,
) -> EvmSettlementEngine:
    return EvmSettlementEngine(
        store,
        htlc,  # type: ignore[arg-type]
        FixtureEnvelopeSigner(harness, store._public_keys),  # noqa: SLF001
        assets=(evm_terms("erc20-to-ln/v1").evm_asset,),
        rates=dict,
        schedule=SCHEDULE,
        btc_tip=lambda: btc_tip,
        lightning=lightning,
        hold_invoices=hold,
    )


def _state(store: live.LiveSessionStore) -> str:
    (item,) = store.evm_settlement_work()
    return item.state


def _reservation(store: live.LiveSessionStore) -> str:
    return store._connection.execute(  # noqa: SLF001
        "SELECT state FROM economic_reservations WHERE payment_hash=?", (PAYMENT_HASH,)
    ).fetchone()[0]


def _forward_terms() -> EvmContractTerms:
    import hashlib  # noqa: PLC0415

    terms = evm_terms("erc20-to-ln/v1", timelock=100_000)
    binding = terms.invoice_binding.model_copy(
        update={"bolt11_sha256": hashlib.sha256(b"lnbc1fake").hexdigest()}
    )
    return terms.model_copy(update={"invoice_binding": binding})


def test_forward_swap_pays_once_after_the_lock_and_claims_with_the_preimage(
    harness: Harness,
) -> None:
    terms = _forward_terms()
    htlc = FakeHtlc()
    lightning = _lightning(terms, PaymentOutcome("UNKNOWN"))
    with harness.acquire() as store:
        session = _accept_evm_swap(store, harness, terms)
        engine = _engine(store, harness, htlc, lightning=lightning)
        assert asyncio.run(engine.tick(1500)) == {}  # no lock yet
        htlc.lockups, htlc.active = [_lockup(terms)], True
        assert asyncio.run(engine.tick(1500)) == {session: "PAYING"}
        (item,) = store.evm_settlement_work()
        assert (item.lock_tx_hash, item.lock_log_index, item.lock_block) == (LOCK_TX, 3, 5)
        assert (item.dispatch_state, _reservation(store)) == ("SUBMITTED", "DISPATCHED")
        lightning.send.assert_called_once()
        assert lightning.prepare.call_args.kwargs["fee_limit_sat"] == 5  # 5000 base units
        # In flight: nothing is re-sent on later ticks.
        assert asyncio.run(engine.tick(1600)) == {}
        lightning.send.assert_called_once()
        lightning.track.return_value = PaymentOutcome("SUCCEEDED", preimage=PREIMAGE)
        assert asyncio.run(engine.tick(1700)) == {session: "CLAIMING"}
        (item,) = store.evm_settlement_work()
        assert (item.preimage, item.claim_tx_hash, item.claim_tx) == (
            PREIMAGE,
            "01" * 32,
            b"signed-1",
        )
        assert htlc.broadcasts == [b"signed-1"]
        assert asyncio.run(engine.tick(1800)) == {}  # unmined: rebroadcast, never re-sign
        assert (htlc.broadcasts, htlc.signed) == ([b"signed-1", b"signed-1"], 1)
        htlc.receipts["01" * 32] = TxReceipt("01" * 32, 12, "success")
        htlc.tip = 12
        assert asyncio.run(engine.tick(1900)) == {session: "CLAIMED"}
        assert store.evm_settlement_work() == ()
        assert _reservation(store) == "RELEASED"


def test_forward_swap_fails_when_no_lock_appears_before_the_invoice_expires(
    harness: Harness,
) -> None:
    terms = _forward_terms()
    with harness.acquire() as store:
        session = _accept_evm_swap(store, harness, terms)
        engine = _engine(
            store, harness, FakeHtlc(), lightning=_lightning(terms, PaymentOutcome("UNKNOWN"))
        )
        assert asyncio.run(engine.tick(terms.invoice_binding.expires_at)) == {session: "FAILED"}
        assert _reservation(store) == "RELEASED"


def test_forward_claim_reverted_on_a_vanished_lock_is_lost(harness: Harness) -> None:
    terms = _forward_terms()
    htlc = FakeHtlc(lockups=[_lockup(terms)], active=True)
    lightning = _lightning(terms, PaymentOutcome("SUCCEEDED", preimage=PREIMAGE))
    with harness.acquire() as store:
        session = _accept_evm_swap(store, harness, terms)
        engine = _engine(store, harness, htlc, lightning=lightning)
        assert asyncio.run(engine.tick(1500)) == {session: "CLAIMING"}
        lightning.send.assert_not_called()  # tracked as already settled: no new dispatch
        htlc.receipts["01" * 32] = TxReceipt("01" * 32, 12, "reverted")
        htlc.active = False
        assert asyncio.run(engine.tick(1600)) == {session: "LOST"}


def _hold(state: str = "ACCEPTED", amount_msat: int = 1_100_000, expiry: int = 10_000) -> Mock:
    hold = Mock()
    parts = (HeldHtlc(amount_msat, expiry),) if state == "ACCEPTED" else ()
    hold.lookup.return_value = HoldInvoiceStatus(state, parts)  # type: ignore[arg-type]
    return hold


def test_reverse_swap_locks_once_after_the_hold_and_settles_on_the_claim_log(
    harness: Harness,
) -> None:
    terms = evm_terms("ln-to-erc20/v1")
    htlc = FakeHtlc(allowance_pending=True)
    hold = _hold("OPEN")
    with harness.acquire() as store:
        session = _accept_evm_swap(store, harness, terms)
        engine = _engine(store, harness, htlc, hold=hold)
        assert asyncio.run(engine.tick(1500)) == {}
        hold.lookup.return_value = _hold().lookup.return_value
        assert asyncio.run(engine.tick(1500)) == {session: "LN_HELD"}  # approval pending
        assert htlc.signed == 0
        htlc.allowance_pending = False
        assert asyncio.run(engine.tick(1600)) == {session: "FUNDING_SENT"}
        (item,) = store.evm_settlement_work()
        assert (item.provider_tx_hash, item.provider_tx) == ("01" * 32, b"signed-1")
        assert (_reservation(store), htlc.broadcasts) == ("DISPATCHED", [b"signed-1"])
        assert asyncio.run(engine.tick(1700)) == {}  # unmined: rebroadcast only
        assert (htlc.broadcasts, htlc.signed) == ([b"signed-1", b"signed-1"], 1)
        htlc.receipts["01" * 32] = TxReceipt("01" * 32, 11, "success")
        htlc.tip, htlc.active = 11, True
        assert asyncio.run(engine.tick(1800)) == {session: "FUNDED"}
        assert asyncio.run(engine.tick(1900)) == {}  # before the timelock, no claim yet
        htlc.claim = ClaimEvent("cc" * 32, 12, PREIMAGE)
        assert asyncio.run(engine.tick(2000)) == {session: "SETTLED"}
        hold.settle.assert_called_once_with(PREIMAGE)
        hold.cancel.assert_not_called()
        assert _reservation(store) == "RELEASED"
        assert store._connection.execute(  # noqa: SLF001
            "SELECT claim_tx_hash FROM evm_swaps WHERE session_id=?", (session,)
        ).fetchone() == ("cc" * 32,)


def test_reverse_swap_refunds_after_the_timelock_and_cancels_the_hold(harness: Harness) -> None:
    terms = evm_terms("ln-to-erc20/v1")
    htlc = FakeHtlc()
    hold = _hold()
    with harness.acquire() as store:
        session = _accept_evm_swap(store, harness, terms)
        engine = _engine(store, harness, htlc, hold=hold)
        assert asyncio.run(engine.tick(1500)) == {session: "FUNDING_SENT"}
        htlc.receipts["01" * 32] = TxReceipt("01" * 32, 11, "success")
        htlc.tip, htlc.active = 11, True
        assert asyncio.run(engine.tick(1600)) == {session: "FUNDED"}
        htlc.tip = terms.htlc_timelock_block
        assert asyncio.run(engine.tick(1700)) == {session: "REFUNDING"}
        assert htlc.broadcasts[-1] == b"signed-2"
        htlc.receipts["02" * 32] = TxReceipt("02" * 32, 501, "success")
        htlc.tip = 501
        assert asyncio.run(engine.tick(1800)) == {session: "REFUNDED"}
        hold.cancel.assert_called_once_with(PAYMENT_HASH)
        hold.settle.assert_not_called()
        assert _reservation(store) == "RELEASED"


@pytest.mark.parametrize(
    ("hold", "now", "canceled"),
    [
        (_hold("OPEN"), 4600, True),  # expired unpaid
        (_hold("CANCELED"), 1500, False),
        (_hold(amount_msat=1_000_000), 1500, True),  # held amount differs from H
        (_hold(expiry=9_000), 1500, True),  # incoming HTLC expires too soon
    ],
)
def test_reverse_swap_aborts_before_locking_when_the_hold_is_wrong(
    harness: Harness,
    hold: Mock,
    now: int,
    canceled: bool,  # noqa: FBT001
) -> None:
    terms = evm_terms("ln-to-erc20/v1")
    htlc = FakeHtlc()
    with harness.acquire() as store:
        session = _accept_evm_swap(store, harness, terms)
        engine = _engine(store, harness, htlc, hold=hold)
        assert asyncio.run(engine.tick(now)) == {session: "ABORTED"}
        assert hold.cancel.called is canceled
        assert (htlc.signed, _reservation(store)) == (0, "RELEASED")
