"""Native SDK lifetime and publication, with negotiation/funding receive stubbed.

The unchanged live reverse test covers full provider ingress and funding bytes.
Here exact signed synthetic bindings isolate deadline and worker ownership.
"""

from __future__ import annotations

import asyncio
import hashlib
import threading
import time
from typing import TYPE_CHECKING
from unittest.mock import AsyncMock, Mock

import pytest
from rill_core.settlement import reconstruct_taproot_contract
from rill_core.wire.canonical import canonicalize
from rill_core.wire.hashes import contract_hash, funding_binding_hash, provider_terms_hash
from rill_core.wire.messages import (
    ContractTerms,
    FundingBinding,
    HandshakeAccept,
    HandshakeInit,
    ProviderTerms,
)
from rill_core.wire.quotes import TermsOfferPayload
from rill_crypto import Context
from rill_provider.core_tx_bytes import NextBlockFee
from rill_provider.lnd_payment_observation import LndUnavailableError
from test_cooperative_reservation_publication import _credentials
from test_live_reverse_swap import _segwit_claim
from test_recovery_cli import NATIVE_LIBRARY, NATIVE_ONLY, _fixture

from rill_cli import live_reverse_swap as reverse
from rill_cli import live_swap, swap_command
from rill_cli.live_swap import SwapError, _Session
from rill_cli.wallet_rpc import ConfirmedOutput

if TYPE_CHECKING:
    from pathlib import Path

INVOICE = "lnbcrt1reverselifetimefixture"


class NativeSdk:
    def __init__(  # noqa: PLR0915 - one original-session native fixture
        self,
        crypto: Context,
        path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        self.crypto, self.path = crypto, path
        initial, _ = _fixture("ln-to-btc")
        context = initial["verification_context"]
        terms = ContractTerms.model_validate_json(canonicalize(initial["contract_terms"]))
        self.terms = terms.model_copy(
            update={
                "invoice_binding": terms.invoice_binding.model_copy(
                    update={
                        "bolt11_sha256": hashlib.sha256(INVOICE.encode()).hexdigest(),
                    }
                )
            }
        )
        self.preimage = bytes.fromhex(initial["monotonic_knowledge"]["preimage"])
        self.contract_secret = bytes.fromhex(initial["user_secret"]["contract_secret_key"])
        self.init = HandshakeInit.model_validate_json(canonicalize(context["handshake_init"]))
        self.accept = HandshakeAccept.model_validate_json(canonicalize(context["handshake_accept"]))
        provider_terms = ProviderTerms(
            contract_hash=contract_hash(self.terms).hex(),
            contract_terms=self.terms,
            handshake_hash=context["handshake_hash"],
        )
        self.offer = TermsOfferPayload(
            terms=provider_terms,
            hold_invoice=INVOICE,
            provider_terms_signature=crypto.schnorr_sign(
                (1).to_bytes(32, "big"), provider_terms_hash(provider_terms), b"\x55" * 32
            ).hex(),
        )
        self.offset = 0.0
        self.output = path / "reverse.age"
        self.credentials = _credentials()
        self.documents: list[bytes] = []
        self.reports: list[str] = []
        self.bounds: list[dict] = []
        self.broadcasts: list[bytes] = []
        self.claim_txid: str | None = None
        self.contract_signatures = 0
        self.sign_late = False
        self._original_sign = crypto.schnorr_sign

        def sign(secret: bytes, *args: object) -> bytes:
            signature = self._original_sign(secret, *args)
            if secret == self.contract_secret:
                self.contract_signatures += 1
                if self.sign_late:
                    self.offset += 30
            return signature

        monkeypatch.setattr(crypto, "schnorr_sign", sign)
        self.session = _Session(
            Mock(),
            crypto,
            self.terms.network_identity,
            timeout=1,
            profile="ln-to-btc/v1",
        )
        self.session.secret = (8).to_bytes(32, "big")
        self.session.key = crypto.public_key(self.session.secret)[1:].hex()
        assert self.session.key == self.init.client_session_xonly_key
        self.session.session_id = self.init.session_id
        self.session.provider_key = self.accept.provider_session_xonly_key
        self.session.send = AsyncMock()
        self.session.reply_to = AsyncMock(
            side_effect=[
                Mock(payload=self.offer.model_dump(mode="json"), message_id="55" * 32),
                Mock(),
            ]
        )
        self.artifacts = reconstruct_taproot_contract(self.terms, keys=crypto)
        self.binding = FundingBinding(
            contract_hash=provider_terms.contract_hash,
            funding_attempt_id="11" * 32,
            binding_revision=0,
            funder_role="provider",
            lineage_anchor_txid="33" * 32,
            lineage_anchor_vout=0,
            funding_txid="22" * 32,
            contract_vout=1,
            contract_value_sat=self.terms.economics.contract_amount_sat,
            contract_script_pubkey=self.artifacts.script_pubkey.hex(),
            replaces_txid=None,
            created_at=initial["updated_at"],
        )
        self.binding_signature = crypto.schnorr_sign(
            (9).to_bytes(32, "big"), funding_binding_hash(self.binding), b"\x77" * 32
        ).hex()
        self.wallet = Mock(
            tip_height=Mock(return_value=1000),
            next_block_fee=Mock(return_value=NextBlockFee(1000, 1000, 1000)),
            new_destination_script=Mock(
                return_value=bytes.fromhex(self.terms.client_destination_script)
            ),
            confirmed_output=Mock(
                return_value=ConfirmedOutput(
                    int(self.terms.economics.contract_amount_sat),
                    self.artifacts.script_pubkey,
                    self.terms.funding_confirmations,
                )
            ),
            unspent_on_chain=Mock(side_effect=lambda *_args: not self.broadcasts),
            wallet_confirmations=Mock(
                side_effect=lambda txid: 1 if txid == self.claim_txid else None
            ),
            broadcast=Mock(side_effect=self.broadcast),
        )
        self.payer = Mock(pay=Mock(side_effect=self.pay))
        self.funding = AsyncMock(
            return_value=(self.binding, self.binding_signature, b"synthetic funding receive")
        )

        monkeypatch.setattr(
            reverse, "time", Mock(time=lambda: initial["updated_at"], monotonic=self.now)
        )
        # Funded recovery and later claimant snapshots must use the same fixture clock.
        monkeypatch.setattr(live_swap, "time", reverse.time)
        monkeypatch.setattr(reverse, "POLL_SECONDS", 0.001)
        # A provider that announced no funding depth unless a test sets one.
        self.discover = AsyncMock(return_value={"profiles": ["ln-to-btc/v1"]})
        monkeypatch.setattr(reverse, "discover", self.discover)
        monkeypatch.setattr(reverse, "_Session", lambda *_args, **_kwargs: self.session)
        monkeypatch.setattr(
            reverse,
            "_handshake",
            AsyncMock(
                return_value=(
                    self.init,
                    self.accept,
                    context["provider_identity_signature"],
                    context["handshake_hash"],
                )
            ),
        )
        monkeypatch.setattr(reverse, "_check_offer", lambda *_args, **_kwargs: self.terms)
        monkeypatch.setattr(reverse, "_await_funding", self.funding)
        scalars = iter((self.contract_secret, (12).to_bytes(32, "big")))
        monkeypatch.setattr(
            reverse,
            "_scalar",
            lambda _crypto: ((secret := next(scalars)), crypto.public_key(secret)),
        )
        token_bytes = reverse.secrets.token_bytes
        draws = 0

        def draw(length: int) -> bytes:
            nonlocal draws
            draws += 1
            return self.preimage if draws == 1 else token_bytes(length)

        monkeypatch.setattr(reverse.secrets, "token_bytes", draw)

    def now(self) -> float:
        return time.monotonic() + self.offset

    def write(self, candidate: bytes, previous: bytes | None) -> None:
        swap_command._write_recovery_snapshot(  # noqa: SLF001 - real encrypted publication and native readback
            self.output,
            candidate,
            previous,
            self.terms.network_identity,
            credentials=self.credentials,
            crypto=self.crypto,
        )
        self.documents.append(candidate)

    def pay(self, _invoice: str, **bounds: object) -> str:
        assert bounds["submission_allowed"]() is True
        assert self.now() < bounds["deadline"]
        self.bounds.append(bounds)
        return "IN_FLIGHT"

    def broadcast(self, raw: bytes, **bounds: object) -> str:
        assert bounds["effect_allowed"]() is True
        assert self.now() < bounds["deadline"] == self.bounds[0]["deadline"]
        self.claim_txid, _ = _segwit_claim(raw)
        self.broadcasts.append(raw)
        return self.claim_txid

    async def run(
        self,
        writer: object = None,
        *,
        settle_timeout: float = 20,
    ) -> reverse.ReverseSwapOutcome:
        return await reverse.run_reverse_swap(
            Mock(),
            identity=self.terms.provider_identity_key,
            network=self.terms.network_identity,
            payout_sat=int(self.terms.economics.nominal_payout_sat),
            decode_invoice=lambda _invoice: self.terms.invoice_binding,
            payer=self.payer,
            wallet=self.wallet,
            write_recovery=writer or self.write,
            limits=reverse.ReverseSwapLimits(5000, 0, 5000, 1, 1000, 100, 2),
            crypto=self.crypto,
            settle_timeout=settle_timeout,
            report=self.reports.append,
        )


@NATIVE_ONLY
@pytest.mark.native_crypto
def test_native_reverse_rejects_quote_that_expires_before_acceptance(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def exercise(crypto: Context) -> None:
        fixture = NativeSdk(crypto, tmp_path, monkeypatch)

        def write(candidate: bytes, previous: bytes | None) -> None:
            fixture.write(candidate, previous)
            monkeypatch.setattr(reverse.time, "time", lambda: fixture.terms.terms_expiry)

        with pytest.raises(SwapError, match="quote expired before acceptance"):
            await fixture.run(write)
        assert len(fixture.documents) == 1
        fixture.payer.pay.assert_not_called()
        fixture.funding.assert_not_called()
        fixture.wallet.broadcast.assert_not_called()

    with Context(library_path=NATIVE_LIBRARY) as crypto:
        asyncio.run(exercise(crypto))


@NATIVE_ONLY
@pytest.mark.native_crypto
def test_native_reverse_sdk_propagates_one_original_deadline_and_keeps_paid_distinction(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def exercise(crypto: Context) -> None:
        fixture = NativeSdk(crypto, tmp_path, monkeypatch)
        result = await fixture.run()
        assert result.claim_txid == fixture.claim_txid
        assert len(fixture.bounds) == len(fixture.broadcasts) == 1
        assert (
            fixture.funding.call_args.kwargs["absolute_deadline"] == fixture.bounds[0]["deadline"]
        )
        assert (tmp_path / "reverse.age").exists()
        assert (tmp_path / "reverse.age.funded").exists()
        assert fixture.contract_signatures == 1  # the one broadcast claim
        assert any("hold payment observed (IN_FLIGHT)" in report for report in fixture.reports)
        assert not any("hold invoice paid" in report for report in fixture.reports)

    with Context(library_path=NATIVE_LIBRARY) as crypto:
        asyncio.run(exercise(crypto))


@NATIVE_ONLY
@pytest.mark.native_crypto
def test_native_reverse_sdk_reminds_an_external_wallet_once_funding_proves_the_hold(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def exercise(crypto: Context) -> None:
        fixture = NativeSdk(crypto, tmp_path, monkeypatch)
        shown = fixture.payer.pay.side_effect

        def show(invoice: str, **bounds: object) -> str:
            shown(invoice, **bounds)  # the same lifetime bounds as an LND payment
            return "SHOWN"

        fixture.payer.pay.side_effect = show
        result = await fixture.run()
        assert result.claim_txid == fixture.claim_txid
        assert not any("hold payment observed" in report for report in fixture.reports)
        waiting = fixture.reports.index(
            "waiting for your wallet's payment, then for the provider's funding"
        )
        funded = next(
            index
            for index, report in enumerate(fixture.reports)
            if report.startswith("funded recovery snapshot written")
        )
        reminder = fixture.reports[funded + 1]
        assert waiting < funded
        assert reminder.startswith("The provider funded, so it holds your payment")
        assert fixture.terms.invoice_binding.payment_hash in reminder
        assert INVOICE in reminder
        assert reminder.endswith("Do not pay again.")

    with Context(library_path=NATIVE_LIBRARY) as crypto:
        asyncio.run(exercise(crypto))


@NATIVE_ONLY
@pytest.mark.native_crypto
def test_native_reverse_terms_waiting_longer_than_announced_are_refused_before_paying(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def exercise(crypto: Context) -> None:
        fixture = NativeSdk(crypto, tmp_path, monkeypatch)
        signed = fixture.terms.funding_confirmations
        fixture.discover.return_value = {
            "profiles": ["ln-to-btc/v1"],
            "extensions": {"rillswap/funding-confirmations": {"confirmations": signed - 1}},
        }
        with pytest.raises(SwapError, match=f"more than the announced {signed - 1}"):
            await fixture.run()
        fixture.payer.pay.assert_not_called()
        assert fixture.documents == []  # nothing accepted, nothing to recover
        assert fixture.broadcasts == []

    with Context(library_path=NATIVE_LIBRARY) as crypto:
        asyncio.run(exercise(crypto))


@NATIVE_ONLY
@pytest.mark.native_crypto
def test_native_reverse_terms_are_checked_at_the_tip_after_negotiation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def exercise(crypto: Context) -> None:
        fixture = NativeSdk(crypto, tmp_path, monkeypatch)
        lock = fixture.terms.refund_lock_height
        # The request is built at 1000; 95 blocks later the signed funding,
        # response and claim margins no longer fit before the refund lock.
        fixture.wallet.tip_height.side_effect = [1000, lock - 5]
        with pytest.raises(SwapError, match="no claim window"):
            await fixture.run()
        fixture.payer.pay.assert_not_called()
        assert fixture.documents == []
        assert fixture.broadcasts == []

    with Context(library_path=NATIVE_LIBRARY) as crypto:
        asyncio.run(exercise(crypto))


@NATIVE_ONLY
@pytest.mark.native_crypto
@pytest.mark.parametrize("payment", ["before exception", "after exception", "UNKNOWN", "FAILED"])
def test_native_reverse_sdk_never_interprets_ambiguous_payment_as_unsubmitted(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    payment: str,
) -> None:
    async def exercise(crypto: Context) -> None:
        fixture = NativeSdk(crypto, tmp_path, monkeypatch)

        def pay(invoice: str, **bounds: object) -> str:
            if payment == "after exception":
                fixture.pay(invoice, **bounds)
            if "exception" in payment:
                raise LndUnavailableError("private transport information")
            return payment

        fixture.payer.pay.side_effect = pay
        with pytest.raises(SwapError) as error:
            await fixture.run()
        if payment == "FAILED":
            assert "could not be paid" in str(error.value)
        else:
            assert "outcome unknown" in str(error.value)
            assert "lncli listpayments" in str(error.value)
            assert "do not retry payment" in str(error.value)
            assert "nothing is at risk" not in str(error.value)
            assert "private transport information" not in str(error.value)
        assert len(fixture.bounds) == (1 if payment == "after exception" else 0)
        fixture.funding.assert_not_awaited()
        assert len(fixture.documents) == 1
        assert fixture.broadcasts == []
        assert fixture.contract_signatures == 0

    with Context(library_path=NATIVE_LIBRARY) as crypto:
        asyncio.run(exercise(crypto))


@NATIVE_ONLY
@pytest.mark.native_crypto
@pytest.mark.parametrize("phase", ["depth", "sign", "watcher"])
def test_native_reverse_expiry_never_renews_signing_or_assumes_broadcast(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    phase: str,
) -> None:
    async def exercise(crypto: Context) -> None:
        fixture = NativeSdk(crypto, tmp_path, monkeypatch)
        if phase == "depth":
            output = fixture.wallet.confirmed_output.return_value

            def confirmed(*_args: object) -> ConfirmedOutput:
                fixture.offset += 30
                return output

            fixture.wallet.confirmed_output.side_effect = confirmed
        elif phase == "sign":
            fixture.sign_late = True
        else:
            monkeypatch.setattr(reverse.ClaimWatcher, "run", Mock(side_effect=TimeoutError))
        with pytest.raises(
            SwapError, match="original reverse settlement lifetime expired"
        ) as error:
            await fixture.run()
        assert "do not retry payment" in str(error.value)
        assert "the claim is broadcast" not in str(error.value)
        assert "preimage stays private" not in str(error.value)
        assert (tmp_path / "reverse.age.funded").exists()
        assert fixture.broadcasts == []
        assert fixture.contract_signatures == (1 if phase == "sign" else 0)

    with Context(library_path=NATIVE_LIBRARY) as crypto:
        asyncio.run(exercise(crypto))


@NATIVE_ONLY
@pytest.mark.native_crypto
@pytest.mark.parametrize("publication", ["initial", "funded"])
def test_native_initial_writer_drains_before_sdk_cancellation_can_close_crypto(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    publication: str,
) -> None:
    async def exercise(crypto: Context) -> None:
        fixture = NativeSdk(crypto, tmp_path, monkeypatch)
        entered, release = threading.Event(), threading.Event()

        def write(candidate: bytes, previous: bytes | None) -> None:
            if (previous is None) == (publication == "initial"):
                entered.set()
                assert release.wait(3)
            fixture.write(candidate, previous)

        running = asyncio.create_task(fixture.run(write))
        try:
            assert await asyncio.to_thread(entered.wait, 1)
            for _ in range(3):
                running.cancel()
                await asyncio.sleep(0)
                assert not running.done()
            assert (
                crypto.public_key(fixture.contract_secret).hex()
                == fixture.terms.client_contract_compressed_key
            )
            release.set()
            with pytest.raises(asyncio.CancelledError):
                await running
            assert (tmp_path / "reverse.age").exists()
            assert len(fixture.documents) == (1 if publication == "initial" else 2)
            if publication == "initial":
                fixture.payer.pay.assert_not_called()
            else:
                assert (tmp_path / "reverse.age.funded").exists()
                fixture.payer.pay.assert_called_once()
            assert fixture.broadcasts == []
        finally:
            release.set()
            await asyncio.gather(running, return_exceptions=True)

    with Context(library_path=NATIVE_LIBRARY) as crypto:
        asyncio.run(exercise(crypto))


@NATIVE_ONLY
@pytest.mark.native_crypto
def test_native_startup_time_does_not_advance_the_predispatch_payment_anchor(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def exercise(crypto: Context) -> None:
        fixture = NativeSdk(crypto, tmp_path, monkeypatch)

        def write(candidate: bytes, previous: bytes | None) -> None:
            fixture.write(candidate, previous)
            if previous is None:
                fixture.offset += 30

        result = await fixture.run(write)
        assert fixture.bounds[0]["deadline"] > time.monotonic() + 30
        assert result.claim_txid == fixture.claim_txid
        assert len(fixture.broadcasts) == 1

    with Context(library_path=NATIVE_LIBRARY) as crypto:
        asyncio.run(exercise(crypto))
