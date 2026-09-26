"""The live client against the real provider service over a relay (native crypto).

Chain and Lightning backends are fakes on both sides; everything else
(Nostr wrapping, handshake, firm terms, acceptance, funding authorization,
recovery inspection, settlement engine, claim signing) is the real code.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import sys
import time
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from pyrage import x25519
from rill_core.recovery.inspection import inspect_recovery_plaintext, inspect_recovery_successor
from rill_core.settlement import FundingPrevout, PlannedFundingOutput
from rill_core.wire.messages import InvoiceBinding
from rill_core.wire.types import NetworkIdentity

from rill_cli.live_swap import SwapLimits, run_swap
from rill_cli.wallet_rpc import WalletFunding

PROVIDER_TESTS = Path(__file__).resolve().parents[2] / "rill-provider" / "tests"
NATIVE = pytest.mark.skipif(
    os.environ.get("RILLSWAP_RUN_NATIVE_CRYPTO") != "1" or "RILL_CRYPTO_LIBRARY" not in os.environ,
    reason="set RILLSWAP_RUN_NATIVE_CRYPTO=1 and RILL_CRYPTO_LIBRARY",
)
NETWORK = NetworkIdentity.model_validate(
    json.loads((PROVIDER_TESTS / "fixtures" / "initial-btc-to-ln-v1.json").read_text())[
        "network_identity"
    ]
)
INVOICE = "lnbcrt500u1pclientexample"
PREIMAGE = "42" * 32
TIP = 850


def _invoice(now: int) -> InvoiceBinding:
    return InvoiceBinding(
        bolt11_sha256=hashlib.sha256(INVOICE.encode()).hexdigest(),
        payment_hash=hashlib.sha256(bytes.fromhex(PREIMAGE)).hexdigest(),
        amount_msat="50000000",
        payee_compressed_pubkey="02"
        "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
        created_at=now - 10,
        expires_at=now + 3600,
        min_final_cltv_delta=18,
    )


class FakeWallet:
    """Funds from one P2WPKH coin; records the broadcast."""

    def __init__(self) -> None:
        self.broadcasts: list[bytes] = []

    def tip_height(self) -> int:
        return TIP

    def new_destination_script(self) -> bytes:
        return bytes.fromhex("5120" + "33" * 32)

    def fund(self, script_pubkey: bytes, amount_sat: int, *, fee_rate_sat_vb: int) -> WalletFunding:
        assert fee_rate_sat_vb > 0
        coin = FundingPrevout(
            b"\x41" * 32, 1, amount_sat + 20_300, bytes.fromhex("0014" + "44" * 20)
        )
        change = PlannedFundingOutput(20_000, bytes.fromhex("5120" + "55" * 32))
        raw = (
            (2).to_bytes(4, "little")
            + b"\x01"
            + coin.txid[::-1]
            + coin.output_index.to_bytes(4, "little")
            + b"\x00\xff\xff\xff\xff\x02"
            + amount_sat.to_bytes(8, "little")
            + bytes([len(script_pubkey)])
            + script_pubkey
            + change.value_sat.to_bytes(8, "little")
            + bytes([len(change.script_pubkey)])
            + change.script_pubkey
            + b"\x00\x00\x00\x00"
        )
        return WalletFunding(raw, (coin,), (change,), 300)

    def broadcast(self, raw: bytes) -> str:
        self.broadcasts.append(raw)
        return hashlib.sha256(hashlib.sha256(raw).digest()).digest()[::-1].hex()


@pytest.mark.native_crypto
@NATIVE
@pytest.mark.parametrize("epoch_bound", [False, True])
def test_native_live_swap_settles_through_the_provider(  # noqa: PLR0915
    tmp_path: Path, *, epoch_bound: bool
) -> None:
    sys.path.insert(0, str(PROVIDER_TESTS))
    from fake_relay import FakeRelay  # type: ignore[import-not-found]  # noqa: PLC0415
    from rill_core.settlement.funding_authentication import (  # noqa: PLC0415
        SignedFundingBinding,
        verify_static_signed_funding_binding_history,
    )
    from rill_core.wire.hashes import EPOCH_SESSION_FEATURE  # noqa: PLC0415
    from rill_core.wire.messages import (  # noqa: PLC0415
        ContractTerms,
        FundingBinding,
        HandshakeAccept,
        HandshakeInit,
    )
    from rill_crypto import Context  # noqa: PLC0415
    from rill_provider.handshake_service import HandshakeService, ServicePolicy  # noqa: PLC0415
    from rill_provider.handshake_store import HandshakePolicy  # noqa: PLC0415
    from rill_provider.live_session_store import (  # noqa: PLC0415
        AuthorityDeclaration,
        LiveSessionStore,
    )
    from rill_provider.lnd_payment_send import PaymentOutcome, PreparedPayment  # noqa: PLC0415
    from rill_provider.provider_identity import ProviderIdentity  # noqa: PLC0415
    from rill_provider.quote_policy import QuoteSchedule  # noqa: PLC0415
    from rill_provider.relay_client import RelayConnection  # noqa: PLC0415
    from rill_provider.settlement_engine import SettlementEngine  # noqa: PLC0415

    now = int(time.time())
    binding = _invoice(now)
    custody, unlock = x25519.Identity.generate(), x25519.Identity.generate()
    wallet = FakeWallet()
    recoveries: list[bytes] = []
    sent: list[dict[str, Any]] = []
    policy_store = HandshakePolicy(
        profile="btc-to-ln/v1",
        features=frozenset({EPOCH_SESSION_FEATURE}) if epoch_bound else frozenset(),
        encryption_suites=frozenset({"noise-xk-secp256k1-chachapoly-sha256/v1"}),
        capabilities=frozenset({"core/v1", "recovery/v1"}),
    )

    async def scenario(crypto: Context) -> None:
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
            profiles=("btc-to-ln/v1",),
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
        chain = SimpleNamespace(broadcasts=[])
        chain.tip_height = lambda: TIP
        chain.observe_candidate_outpoint = lambda _b, _t, *, keys: SimpleNamespace(  # noqa: ARG005
            chain_only_confirmations=6, tip_height=TIP
        )
        chain.broadcast = lambda raw, txid: chain.broadcasts.append(raw) or txid
        chain.confirmations = lambda _txid: 0

        prepared: list[dict[str, Any]] = []

        def prepare(bolt11: str, **bounds: Any) -> PreparedPayment:  # noqa: ANN401
            prepared.append({"invoice": bolt11, **bounds})
            invoice = bounds["invoice_binding"]
            return PreparedPayment(
                b"route",
                invoice.payment_hash,
                invoice.expires_at,
                bounds["max_expiry_height"],
                invoice.min_final_cltv_delta,
            )

        def send(payment: PreparedPayment) -> PaymentOutcome:
            assert payment.request == b"route"
            sent.append(prepared.pop())
            return PaymentOutcome("SUCCEEDED", PREIMAGE)

        lightning = SimpleNamespace(
            track=lambda _h: (
                PaymentOutcome("SUCCEEDED", PREIMAGE) if sent else PaymentOutcome("UNKNOWN")
            ),
            send=send,
            prepare=prepare,
        )

        def write_recovery(document: bytes, previous: bytes | None) -> None:
            if previous is None:
                inspect_recovery_plaintext(document, NETWORK, crypto=crypto)
            else:
                inspect_recovery_successor(previous, document, NETWORK, crypto=crypto)
            recoveries.append(document)

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
            service = HandshakeService(
                store,
                signer,
                crypto,
                policy,
                chain_tip=lambda: TIP,
                invoice_decoder=lambda _invoice: binding,
                settlement=SettlementEngine(store, chain, lightning, crypto),
            )
            runner = asyncio.create_task(service.run(stop, tick_seconds=0.2))
            try:
                await asyncio.sleep(0.5)  # first announcement
                async with RelayConnection(url) as connection:
                    outcome = await run_swap(
                        connection,
                        identity=identity,
                        network=NETWORK,
                        invoice=INVOICE,
                        decode_invoice=lambda _invoice: binding,
                        wallet=wallet,
                        write_recovery=write_recovery,
                        limits=SwapLimits(max_success_fee_sat=1_000),
                        crypto=crypto,
                        timeout=10,
                        settle_timeout=10,
                    )
            finally:
                stop.set()
                await runner
                await relay.stop()
        assert outcome.payment_preimage == PREIMAGE
        assert len(recoveries) == 2  # terms first, then the funded snapshot
        context = json.loads(recoveries[0])["verification_context"]
        expected_features = [EPOCH_SESSION_FEATURE] if epoch_bound else []
        assert context["handshake_init"]["required_features"] == expected_features
        assert context["handshake_accept"]["required_features"] == expected_features
        funded = json.loads(recoveries[1])
        verify_static_signed_funding_binding_history(
            terms=ContractTerms.model_validate_json(json.dumps(funded["contract_terms"])),
            handshake_init=HandshakeInit.model_validate_json(json.dumps(context["handshake_init"])),
            handshake_accept=HandshakeAccept.model_validate_json(
                json.dumps(context["handshake_accept"])
            ),
            provider_identity_signature=context["provider_identity_signature"],
            provider_terms_signature=context["provider_terms_signature"],
            client_acceptance_signature=context["client_acceptance_signature"],
            signed_bindings=tuple(
                SignedFundingBinding(
                    FundingBinding.model_validate_json(json.dumps(item["binding"])),
                    item["funder_session_signature"],
                )
                for item in funded["funding_history"]
            ),
            expected_provider_identity=identity,
            expected_network=NETWORK,
            crypto=crypto,
        )
        assert len(wallet.broadcasts) == 1
        assert outcome.funding_txid == wallet.broadcast(wallet.broadcasts[0])
        assert [item["invoice"] for item in sent] == [INVOICE]  # paid exactly once
        assert len(chain.broadcasts) >= 1  # provider claimed with the preimage

    with Context(library_path=os.environ["RILL_CRYPTO_LIBRARY"]) as crypto:
        asyncio.run(scenario(crypto))
