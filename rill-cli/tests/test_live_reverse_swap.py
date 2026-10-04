"""The LN to BTC client against the real provider service over a relay (native crypto).

Chain, Lightning, and hold invoice backends are fakes on both sides;
everything else (Nostr wrapping, handshake, reverse firm terms, acceptance,
provider funding grant and signed funding_binding, recovery inspection,
claim signing, preimage extraction and settlement) is the real code.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import sys
import time
from dataclasses import dataclass, field
from types import SimpleNamespace
from typing import TYPE_CHECKING, Any

import pytest
from rill_core.wire.messages import InvoiceBinding
from test_live_swap import NATIVE, NETWORK, PROVIDER_TESTS, TIP, FakeWallet

from rill_cli.age_container import X25519Credentials, verify_export_ciphertext
from rill_cli.live_reverse_swap import ReverseSwapLimits, run_reverse_swap
from rill_cli.swap_command import _write_recovery_snapshot
from rill_cli.wallet_rpc import ConfirmedOutput

if TYPE_CHECKING:
    from pathlib import Path

PAYOUT = 50_000
TIP_HASH = "61" * 32  # the one block both Core and LND report at TIP


def _varint(raw: bytes, at: int) -> tuple[int, int]:
    first = raw[at]
    if first < 0xFD:
        return first, at + 1
    if first == 0xFD:
        return int.from_bytes(raw[at + 1 : at + 3], "little"), at + 3
    raise AssertionError("fake parser: large varint")


def _segwit_claim(raw: bytes) -> tuple[str, tuple[bytes, ...]]:
    """Return the txid and the first input's witness of a one-input segwit tx."""
    assert raw[4:6] == b"\x00\x01"
    at = 6
    count, at = _varint(raw, at)
    assert count == 1
    inputs_start = at
    at += 36
    script_len, at = _varint(raw, at)
    at += script_len + 4
    outputs, at = _varint(raw, at)
    for _ in range(outputs):
        at += 8
        script_len, at = _varint(raw, at)
        at += script_len
    body_end = at
    items, at = _varint(raw, at)
    witness = []
    for _ in range(items):
        size, at = _varint(raw, at)
        witness.append(raw[at : at + size])
        at += size
    stripped = raw[:4] + raw[inputs_start - 1 : body_end] + raw[at : at + 4]
    return hashlib.sha256(hashlib.sha256(stripped).digest()).digest()[::-1].hex(), tuple(witness)


@dataclass
class FakeHold:
    """Both sides' view of the one hold invoice: provider LND and client LND."""

    invoices: dict[str, dict[str, Any]] = field(default_factory=dict)
    paid: set[str] = field(default_factory=set)
    settled: list[str] = field(default_factory=list)
    canceled: list[str] = field(default_factory=list)
    payments: list[dict[str, Any]] = field(default_factory=list)

    def add(
        self, payment_hash: str, *, value_msat: int, expiry_seconds: int, cltv_expiry_delta: int
    ) -> str:
        bolt11 = f"lnbcrt1hold{payment_hash[:16]}"
        self.invoices[bolt11] = {
            "hash": payment_hash,
            "msat": value_msat,
            "expires_at": int(time.time()) + expiry_seconds,
            "cltv": cltv_expiry_delta,
        }
        return bolt11

    def decode(self, bolt11: str) -> InvoiceBinding:
        invoice = self.invoices[bolt11]
        return InvoiceBinding(
            bolt11_sha256=hashlib.sha256(bolt11.encode()).hexdigest(),
            payment_hash=invoice["hash"],
            amount_msat=str(invoice["msat"]),
            payee_compressed_pubkey="02"
            "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
            created_at=invoice["expires_at"] - 1800,
            expires_at=invoice["expires_at"],
            min_final_cltv_delta=invoice["cltv"],
        )

    def lookup(self, payment_hash: str) -> Any:  # noqa: ANN401 - provider HoldInvoiceStatus
        from rill_provider.lnd_hold_invoice import HeldHtlc, HoldInvoiceStatus  # noqa: PLC0415

        invoice = next(i for i in self.invoices.values() if i["hash"] == payment_hash)
        if payment_hash in self.settled:
            return HoldInvoiceStatus("SETTLED", ())
        if payment_hash not in self.paid:
            return HoldInvoiceStatus("OPEN", ())
        return HoldInvoiceStatus(
            "ACCEPTED", (HeldHtlc(invoice["msat"], TIP + invoice["cltv"] + 10),)
        )

    def observe_bound_invoice(self, expected: InvoiceBinding, **_options: Any) -> Any:  # noqa: ANN401
        from rill_provider.lnd_hold_invoice import BoundHoldInvoiceObservation  # noqa: PLC0415

        return BoundHoldInvoiceObservation(
            expected.payment_hash,
            expected.bolt11_sha256,
            expected.payee_compressed_pubkey,
            NETWORK,
            self.lookup(expected.payment_hash),
            TIP,
            TIP_HASH,
        )

    observe_bound_settled_invoice = observe_bound_invoice

    def settle_bound_invoice(
        self,
        expected: InvoiceBinding,
        preimage: str,
        **_options: Any,  # noqa: ANN401 - provider settle options
    ) -> None:
        assert hashlib.sha256(bytes.fromhex(preimage)).hexdigest() == expected.payment_hash
        self.settle(preimage)

    def settle(self, preimage: str) -> None:
        self.settled.append(hashlib.sha256(bytes.fromhex(preimage)).hexdigest())

    def cancel(self, payment_hash: str) -> None:
        self.canceled.append(payment_hash)

    # Client side.
    def pay(self, bolt11: str, **bounds: Any) -> str:  # noqa: ANN401
        invoice = self.invoices[bolt11]
        assert bounds["invoice_binding"].payment_hash == invoice["hash"]
        assert bounds["min_final_expiry_height"] <= TIP + invoice["cltv"] + 10
        self.payments.append({"bolt11": bolt11, **bounds})
        self.paid.add(invoice["hash"])
        return "IN_FLIGHT"


class FakeChain:
    """One shared chain: the provider funds, the client sees and claims."""

    def __init__(self) -> None:
        self.funded: dict[str, tuple[bytes, bytes, int]] = {}
        self.provider_broadcasts: list[str] = []
        self.claims: list[bytes] = []
        self.claim_txids: list[str] = []

    def tip_height(self) -> int:
        return TIP

    def fund_output(self, script_pubkey: bytes, value_sat: int, *, max_fee_sat: int) -> Any:  # noqa: ANN401
        from rill_provider.core_tx_bytes import FundedOutput  # noqa: PLC0415

        assert max_fee_sat >= 300
        raw = FakeWallet().fund(script_pubkey, value_sat, fee_rate_sat_vb=1).raw_transaction
        txid = hashlib.sha256(hashlib.sha256(raw).digest()).digest()[::-1].hex()
        self.funded[txid] = (raw, script_pubkey, value_sat)
        return FundedOutput(txid, 0, raw, 300, "41" * 32, 1)

    def broadcast(self, raw: bytes, txid: str) -> str:
        assert self.funded[txid][0] == raw
        self.provider_broadcasts.append(txid)
        return txid

    def confirmations(self, txid: str) -> int:
        return 2 if txid in self.provider_broadcasts else 0

    def find_spender(self, txid: str, vout: int, *, from_height: int, to_height: int) -> Any:  # noqa: ANN401
        from rill_provider.core_tx_bytes import SpendObservation, SpendScan  # noqa: PLC0415

        assert (vout, from_height <= to_height) == (0, True)
        for raw in self.claims:
            claim_txid, witness = _segwit_claim(raw)
            if bytes.fromhex(txid)[::-1] == raw[7:39]:
                return SpendScan(SpendObservation(claim_txid, witness, None), to_height)
        return SpendScan(None, to_height)

    def fee_rate_sat_vb(self, _target: int) -> float | None:
        return None

    def observe_cooperative_claim_outpoint(
        self,
        binding: Any,  # noqa: ANN401
        terms: Any,  # noqa: ANN401
        *,
        keys: Any,  # noqa: ANN401
    ) -> Any:  # noqa: ANN401 - provider Core evidence double
        from rill_core.settlement import check_funding_binding_transaction  # noqa: PLC0415
        from rill_provider.core_tx_bytes import CooperativeClaimOutpoint  # noqa: PLC0415

        raw, _script, _value = self.funded[binding.funding_txid]
        depth = max(terms.funding_confirmations, 2)
        return CooperativeClaimOutpoint(
            terms.network_identity,
            check_funding_binding_transaction(raw, binding, terms, keys=keys),
            binding.funding_txid,
            binding.contract_vout,
            int(binding.contract_value_sat),
            bytes.fromhex(binding.contract_script_pubkey),
            TIP_HASH,
            TIP,
            depth,
            TIP - depth + 1,
            "62" * 32,
        )

    def observe_cooperative_fee_policy(self, blocks: int, **_options: Any) -> Any:  # noqa: ANN401
        from rill_provider.core_tx_bytes import CooperativeFeePolicy  # noqa: PLC0415

        return CooperativeFeePolicy(NETWORK, TIP_HASH, TIP, blocks, 100, 1000, 1000, blocks)

    # The client's wallet view.
    def new_destination_script(self) -> bytes:
        return bytes.fromhex("5120" + "33" * 32)

    def confirmed_output(self, txid: str, vout: int) -> ConfirmedOutput | None:
        if txid not in self.provider_broadcasts or vout != 0:
            return None
        _raw, script, value = self.funded[txid]
        return ConfirmedOutput(value, script, 2)

    def unspent_on_chain(self, txid: str, vout: int) -> bool:
        return (txid, vout) in {(t, 0) for t in self.provider_broadcasts} and not self.claims

    def wallet_confirmations(self, txid: str) -> int | None:
        return 1 if txid in self.claim_txids else None  # mined in the next block

    def broadcast_claim(
        self,
        raw: bytes,
        *,
        deadline: float | None = None,
        effect_allowed: Any = None,  # noqa: ANN401 - test honors the guarded wallet protocol
    ) -> str:
        if effect_allowed is not None:
            assert effect_allowed() is True
        if deadline is not None:
            assert time.monotonic() < deadline
        txid, _ = _segwit_claim(raw)
        if effect_allowed is not None:
            assert effect_allowed() is True
        if deadline is not None:
            assert time.monotonic() < deadline
        self.claims.append(raw)
        self.claim_txids.append(txid)
        return txid


@pytest.mark.native_crypto
@NATIVE
def test_native_ln_to_btc_swap_claims_and_settles_through_the_provider(  # noqa: PLR0915
    tmp_path: Path,
) -> None:
    sys.path.insert(0, str(PROVIDER_TESTS))
    from fake_relay import FakeRelay  # type: ignore[import-not-found]  # noqa: PLC0415
    from pyrage import x25519  # noqa: PLC0415
    from rill_core.wire.hashes import COOPERATIVE_CLAIM_FEATURE  # noqa: PLC0415
    from rill_crypto import Context  # noqa: PLC0415
    from rill_provider.handshake_service import HandshakeService, ServicePolicy  # noqa: PLC0415
    from rill_provider.handshake_store import HandshakePolicy  # noqa: PLC0415
    from rill_provider.live_session_store import (  # noqa: PLC0415
        AuthorityDeclaration,
        LiveSessionStore,
    )
    from rill_provider.provider_identity import ProviderIdentity  # noqa: PLC0415
    from rill_provider.quote_policy import QuoteSchedule  # noqa: PLC0415
    from rill_provider.relay_client import RelayConnection  # noqa: PLC0415
    from rill_provider.settlement_engine import SettlementEngine  # noqa: PLC0415

    custody, unlock = x25519.Identity.generate(), x25519.Identity.generate()
    credentials = X25519Credentials(str(unlock.to_public()), str(unlock))
    output = tmp_path / "swap.age"
    hold, chain = FakeHold(), FakeChain()
    recoveries: list[bytes] = []
    policy_store = HandshakePolicy(
        profile="ln-to-btc/v1",
        features=frozenset({COOPERATIVE_CLAIM_FEATURE}),
        encryption_suites=frozenset({"noise-xk-secp256k1-chachapoly-sha256/v1"}),
        capabilities=frozenset({"core/v1", "recovery/v1"}),
    )
    wallet = SimpleNamespace(
        tip_height=chain.tip_height,
        new_destination_script=chain.new_destination_script,
        confirmed_output=chain.confirmed_output,
        unspent_on_chain=chain.unspent_on_chain,
        wallet_confirmations=chain.wallet_confirmations,
        broadcast=chain.broadcast_claim,
    )

    async def scenario(crypto: Context) -> tuple[Any, str]:
        relay = FakeRelay()
        url = await relay.start()
        identity = ProviderIdentity.provision(
            tmp_path / "id.age", recipient=str(unlock.to_public()), crypto=crypto
        )
        signer = ProviderIdentity.load(
            tmp_path / "id.age",
            custody_identity=str(unlock),
            expected_xonly_public_key=identity,
            crypto=crypto,
        )
        LiveSessionStore.provision(
            tmp_path / "live.sqlite",
            NETWORK,
            identity,
            policy_store,
            AuthorityDeclaration("test", outside_restore_domain=True, single_host=True),
            custody_recipient=str(custody.to_public()),
        )
        policy = ServicePolicy(
            network=NETWORK,
            profiles=("ln-to-btc/v1",),
            profile="ln-to-btc/v1",
            amount_bands=((1000, 100_000),),
            base_fee_sat=50,
            proportional_millionths=1000,
            slot="e2e",
            relay_urls=(url,),
            provider_destination_script="5120" + "66" * 32,
            quote=QuoteSchedule(
                max_funding_fee_sat=500,
                max_claim_fee_sat=400,
                max_refund_fee_sat=600,
                max_refund_delay_blocks=288,
            ),
        )

        def write_recovery(document: bytes, previous: bytes | None) -> bytes:
            _write_recovery_snapshot(
                output, document, previous, NETWORK, credentials=credentials, crypto=crypto
            )
            suffix = ("", ".funded", ".fallback", ".disclosing")[len(recoveries)]
            target = tmp_path / f"swap.age{suffix}"
            verify_export_ciphertext(
                target.read_bytes(), document, NETWORK, credentials=credentials, crypto=crypto
            )
            assert not (tmp_path / "swap.age.paid").exists()
            recoveries.append(document)
            return document  # the trusted writer's exact acknowledgment

        stop = asyncio.Event()
        with LiveSessionStore.acquire(
            tmp_path / "live.sqlite",
            NETWORK,
            identity,
            policy_store,
            crypto=crypto,
            custody_identity=str(custody),
            public_keys=crypto,
        ) as store:
            engine = SettlementEngine(
                store,
                chain,  # type: ignore[arg-type]
                SimpleNamespace(),  # type: ignore[arg-type]
                crypto,
                hold_invoices=hold,
            )
            service = HandshakeService(
                store,
                signer,
                crypto,
                policy,
                chain_tip=lambda: TIP,
                invoice_decoder=hold.decode,
                settlement=engine,
                hold_invoices=hold,  # type: ignore[arg-type]
            )
            runner = asyncio.create_task(service.run(stop, tick_seconds=0.2))
            try:
                await asyncio.sleep(0.5)  # first announcement
                async with RelayConnection(url) as connection:
                    outcome = await run_reverse_swap(
                        connection,
                        identity=identity,
                        network=NETWORK,
                        payout_sat=PAYOUT,
                        decode_invoice=hold.decode,
                        payer=hold,
                        wallet=wallet,
                        write_recovery=write_recovery,
                        limits=ReverseSwapLimits(
                            max_success_fee_sat=1_000,
                            min_claim_fee_reserve_sat=500,
                            max_claim_fee_sat=5_000,
                            min_refund_delay_blocks=72,
                            max_incoming_htlc_delay_blocks=432,
                            max_routing_fee_sat=100,
                            claim_fee_rate_sat_vb=2,
                        ),
                        crypto=crypto,
                        timeout=10,
                        settle_timeout=120,
                    )
                async with asyncio.timeout(5):
                    while not hold.settled:  # noqa: ASYNC110 - polling a fake backend
                        await asyncio.sleep(0.1)
                (item,) = store._connection.execute(  # noqa: SLF001
                    "SELECT state FROM swaps"
                ).fetchall()
            finally:
                stop.set()
                await runner
                await relay.stop()
        return outcome, str(item[0])

    with Context(library_path=os.environ["RILL_CRYPTO_LIBRARY"]) as crypto:
        outcome, final_state = asyncio.run(scenario(crypto))

    assert final_state == "SETTLED"
    assert outcome.payout_sat > PAYOUT  # V = D + claim fee reserve
    assert chain.claim_txids == [outcome.claim_txid]
    assert set(chain.provider_broadcasts) == {outcome.funding_txid}  # idempotent rebroadcast
    # The hold was settled with the preimage revealed by the claim witness.
    initial = json.loads(recoveries[0])
    preimage = initial["monotonic_knowledge"]["preimage"]
    assert hold.settled == [hashlib.sha256(bytes.fromhex(preimage)).hexdigest()]
    assert hold.canceled == []
    # terms (with preimage), funded, signed fallback, then the disclosure reservation
    assert len(recoveries) == 4
    # The client claimed by key path with the provider's partial: no preimage on chain.
    (claim,) = chain.claims
    _, witness = _segwit_claim(claim)
    assert [len(item) for item in witness] == [64]
    assert bytes.fromhex(preimage) not in claim
    funded = json.loads(recoveries[1])
    (record,) = funded["funding_history"]
    assert record["binding"]["funder_role"] == "provider"
    assert record["binding"]["funding_txid"] == outcome.funding_txid
    # The client paid with a final expiry at or after the provider's minimum.
    (payment,) = hold.payments
    timing = initial["contract_terms"]["timing_policy"]
    assert payment["min_final_expiry_height"] == timing["min_incoming_htlc_expiry_height"]
    assert payment["fee_limit_sat"] == 100
