"""Isolated real-backend story, not relay, client custody, or signing activation.

Native cryptography, sealed provider custody, Core funding and LND settlement
are real. Featured reverse acceptance uses the same explicit test-only guard
bypass as the component provenance fixtures. No provider MuSig nonce is created.
"""

from __future__ import annotations

import asyncio
import copy
import hashlib
import sys
import tempfile
import time
from dataclasses import replace
from pathlib import Path
from typing import TYPE_CHECKING, Any

import httpx
import pytest
from rill_core.settlement import FundingOutput, UnilateralAuthorization, build_cooperative_claim
from rill_core.wire.canonical import canonicalize
from rill_core.wire.hashes import (
    COOPERATIVE_CLAIM_FEATURE,
    client_acceptance_hash,
    contract_hash,
    handshake_accept_hash,
    provider_terms_hash,
)
from rill_core.wire.messages import ClientAcceptance, Envelope, HandshakeAccept, ProviderTerms
from rill_core.wire.quotes import TermsOfferPayload
from rill_core.wire.settlement_messages import FundingBindingPayload
from rill_crypto import Context
from test_handshake_hold_invoice import POLICY
from test_reverse_negotiation_origin import OriginHarness, _handshake
from test_reverse_proposal_reservation import NativeSigner, NativeVerifier
from test_reverse_quote_policy import REVERSE_FIRM, TERMS

from rill_provider.core_tx_bytes import CoreTransactionReader
from rill_provider.live_session_store import AcceptSwap
from rill_provider.quote_policy import FirmSigner
from rill_provider.reverse_cooperation import ReverseCooperationWindow
from rill_provider.reverse_settlement import ReverseSettlement
from rill_provider.settlement_policy import answer_client_request

if TYPE_CHECKING:
    from collections.abc import Callable

    from rill_core.wire.messages import InvoiceBinding
    from rill_core.wire.types import NetworkIdentity

    from rill_provider.live_session_store import Answer, RequestContext
    from rill_provider.lnd_hold_invoice import LndHoldInvoices

# ruff: noqa: SLF001, T201 - original-owner seams and secret-free phase diagnostics


def run_original_preflight(  # noqa: PLR0913, PLR0915 - one isolated original-session story
    *,
    network: NetworkIdentity,
    held: LndHoldInvoices,
    binding: InvoiceBinding,
    bolt11: str,
    preimage: bytes,
    synchronized: Callable[[int], None],
) -> dict[str, object]:
    """Fund, acquire debt, repay and preflight using unchanged real-clock authority."""
    with (
        tempfile.TemporaryDirectory(prefix="native-reverse-", dir="/tmp") as directory,
        pytest.MonkeyPatch.context() as patch,
        Context(library_path="/work/provider/tmp/native/librill_crypto.so") as crypto,
        httpx.Client(
            base_url="http://127.0.0.1:18443",
            auth=httpx.BasicAuth("rill-disposable", "disposable-regtest-only"),
            trust_env=False,
            follow_redirects=False,
            timeout=httpx.Timeout(30, connect=3),
        ) as wallet,
    ):
        native_allocations = 0
        original_begin = crypto.musig_begin

        def counted_begin(*args: Any, **kwargs: Any) -> Any:  # noqa: ANN401 - native test instrumentation
            nonlocal native_allocations
            native_allocations += 1
            return original_begin(*args, **kwargs)

        patch.setattr(crypto, "musig_begin", counted_begin)
        origin = OriginHarness(Path(directory), patch)
        assert origin.network == network
        origin.crypto = NativeVerifier(crypto)
        signer = NativeSigner(origin)
        acceptance = HandshakeAccept.model_validate_json(
            canonicalize(origin.source["verification_context"]["handshake_accept"]), strict=True
        )
        origin.envelopes[1]["payload"]["provider_identity_signature"] = crypto.schnorr_sign(
            (1).to_bytes(32, "big"), handshake_accept_hash(acceptance), b"\x55" * 32
        ).hex()
        # Handshake acceptance authenticates its nested identity signature;
        # the protocol explicitly requires an unsigned outer accept envelope.
        origin.envelopes[1]["signature"] = None
        origin.crypto.permit_confirm(origin.envelopes[2])
        origin.init, origin.accept, origin.confirm = map(canonicalize, origin.envelopes)

        def rpc(method: str, params: list[object]) -> Any:  # noqa: ANN401 - Core test JSON response
            response = wallet.post(
                "/wallet/fund", json={"jsonrpc": "2.0", "id": 1, "method": method, "params": params}
            )
            response.raise_for_status()
            body = response.json()
            assert body.get("error") is None
            return body["result"]

        chain = CoreTransactionReader(
            port=18443, cookie_path="/work/public/core.cookie", wallet="fund", network=network
        )
        with origin.acquire_at(origin.path, crypto=origin.crypto, public_keys=crypto) as store:
            print("PHASE: native_reverse_handshake", file=sys.stderr)
            _handshake(store, origin)
            # The session already has scalar 9. Generate legitimate sealed
            # contract custody with scalar 11 when the firm quote asks for it.
            origin.scalar = (11).to_bytes(32, "big")
            tip = chain.tip_height()
            firm = FirmSigner(
                network=network,
                provider_identity_key=origin.identity,
                provider_destination_script=POLICY.provider_destination_script,
                sign=lambda terms: crypto.schnorr_sign(
                    (1).to_bytes(32, "big"), provider_terms_hash(terms), b"\0" * 32
                ).hex(),
            )
            quote = replace(
                TERMS, tip_height=tip, now=int(time.time()), firm=firm, hold=(bolt11, binding)
            )

            def responder(
                request: Envelope, prior: tuple[Envelope, ...], context: RequestContext
            ) -> Answer:
                reply = answer_client_request(
                    request, prior, context, replace(quote, now=int(time.time())), crypto
                )
                if reply.message_type != "terms_offer":
                    return reply
                offered = TermsOfferPayload.model_validate_json(
                    canonicalize(reply.payload), strict=True
                )
                terms = offered.terms.contract_terms.model_copy(
                    update={"required_features": (COOPERATIVE_CLAIM_FEATURE,)}
                )
                provider = ProviderTerms(
                    contract_hash=contract_hash(terms).hex(),
                    contract_terms=terms,
                    handshake_hash=offered.terms.handshake_hash,
                )
                offered = offered.model_copy(
                    update={
                        "terms": provider,
                        "provider_terms_signature": crypto.schnorr_sign(
                            (1).to_bytes(32, "big"), provider_terms_hash(provider), b"\0" * 32
                        ).hex(),
                    }
                )
                return replace(
                    reply,
                    payload=offered.model_dump(mode="json"),
                    contract_hash=provider.contract_hash,
                )

            request = copy.deepcopy(origin.envelopes[2])
            payload = copy.deepcopy(REVERSE_FIRM)
            payload["payment_hash"] = binding.payment_hash
            payload["client_contract_compressed_key"] = crypto.public_key(
                (10).to_bytes(32, "big")
            ).hex()
            payload["limits"]["min_refund_lock_height"] = tip + 143
            payload["limits"]["max_incoming_htlc_expiry_height"] = tip + 185
            request.update(
                message_type="quote_request",
                sequence=2,
                message_id="66" * 32,
                in_reply_to=None,
                payload=payload | {"extensions": {}},
            )
            origin.crypto.permit_confirm(request)
            print("PHASE: native_reverse_quote", file=sys.stderr)
            store.answer_request(canonicalize(request), responder=responder, signer=signer)
            response = next(
                Envelope.model_validate_json(item.canonical_bytes, strict=True)
                for item in store.pending_outbox()
                if b'"message_type":"terms_offer"' in item.canonical_bytes
            )
            offered = TermsOfferPayload.model_validate_json(
                canonicalize(response.payload), strict=True
            )
            terms = offered.terms.contract_terms
            assert (
                terms.provider_contract_compressed_key
                == crypto.public_key((11).to_bytes(32, "big")).hex()
            )
            digest = offered.terms.contract_hash
            accepted = ClientAcceptance(
                contract_hash=digest,
                handshake_hash=offered.terms.handshake_hash,
                session_id=origin.session_id,
                client_session_xonly_key=request["sender_session_key"],
                provider_session_xonly_key=response.sender_session_key,
            )
            request.update(
                message_type="terms_accept",
                sequence=3,
                message_id="67" * 32,
                in_reply_to=response.message_id,
                contract_hash=digest,
                payload={
                    "acceptance": accepted.model_dump(mode="json"),
                    "client_acceptance_signature": crypto.schnorr_sign(
                        (8).to_bytes(32, "big"), client_acceptance_hash(accepted), b"\0" * 32
                    ).hex(),
                },
            )
            origin.crypto.permit_confirm(request)

            def isolated(
                _connection: object, incoming: Envelope, reply: Answer, _replied: object, _now: int
            ) -> None:
                assert incoming.message_type == "terms_accept"
                assert reply.message_type == "ack"
                assert isinstance(reply.effect, AcceptSwap)
                assert reply.effect.contract_hash == incoming.contract_hash

            patch.setattr(store, "_admit_claim_arbitration", isolated)
            print("PHASE: native_reverse_acceptance", file=sys.stderr)
            store.answer_request(canonicalize(request), responder=responder, signer=signer)
            assert store._has_original_reverse_negotiation(origin.session_id, digest)
            engine = ReverseSettlement(store, chain, held, crypto)

            async def exercise() -> dict[str, object]:
                async def advance(expected: str) -> None:
                    (item,) = store.settlement_work()
                    assert await engine.advance(item, int(time.time())) == expected

                await advance("LN_HELD")
                print("PHASE: native_reverse_funding", file=sys.stderr)
                await advance("FUNDING_SENT")
                mining = rpc("getnewaddress", ["", "bech32m"])
                rpc("generatetoaddress", [2, mining])
                synchronized(chain.tip_height())
                await advance("FUNDED")
                funded_message = next(
                    Envelope.model_validate_json(item.canonical_bytes, strict=True)
                    for item in store.pending_outbox()
                    if b'"message_type":"funding_binding"' in item.canonical_bytes
                )
                funded = FundingBindingPayload.model_validate_json(
                    canonicalize(funded_message.payload), strict=True
                ).binding
                authorization = UnilateralAuthorization.from_terms(
                    terms,
                    FundingOutput(
                        bytes.fromhex(funded.funding_txid),
                        funded.contract_vout,
                        int(funded.contract_value_sat),
                        bytes.fromhex(funded.contract_script_pubkey),
                    ),
                    "claim",
                    keys=crypto,
                )
                plan = build_cooperative_claim(authorization, fee_sat=300)
                proposal = copy.deepcopy(origin.envelopes[2])
                proposal.update(
                    message_type="action_request",
                    sequence=4,
                    message_id="ee" * 32,
                    in_reply_to=None,
                    contract_hash=digest,
                    payload={
                        "action": "cooperative_claim_propose",
                        "cooperation_id": "ff" * 32,
                        "unsigned_transaction": plan.base_transaction.hex(),
                        "public_nonce": (
                            crypto.public_key((7).to_bytes(32, "big"))
                            + crypto.public_key((8).to_bytes(32, "big"))
                        ).hex(),
                        "payment_preimage": preimage.hex(),
                        "deadline_at": int(time.time()) + 30,
                        "deadline_height": terms.refund_lock_height
                        - terms.timing_policy.claim_confirmation_blocks,
                    },
                )
                origin.crypto.permit_confirm(proposal)
                document = canonicalize(proposal)
                samples = []
                original_check = ReverseCooperationWindow.check_evidence_interval

                def audited(
                    window: ReverseCooperationWindow, *, started_at: float, completed_at: float
                ) -> None:
                    original_check(window, started_at=started_at, completed_at=completed_at)
                    samples.append((window, window._monotonic_high_water - started_at))

                patch.setattr(ReverseCooperationWindow, "check_evidence_interval", audited)
                print("PHASE: native_reverse_acquisition", file=sys.stderr)
                receipt = await engine._acquire_proposal_debt(document, int(time.time()))
                assert not receipt.replay
                window = store._reverse_proposals[origin.session_id].window
                assert window is not None
                deadline = window.monotonic_deadline
                print("PHASE: native_reverse_repayment", file=sys.stderr)
                await advance("SETTLED")

                def durable_fingerprint() -> tuple[str, ...]:
                    # Compare all durable state without printing private row
                    # contents if a characterization assertion fails.
                    return tuple(
                        hashlib.sha256(
                            repr(store._connection.execute(query).fetchall()).encode()
                        ).hexdigest()
                        for query in (
                            "SELECT * FROM swaps",
                            "SELECT * FROM cooperation_attempts",
                            "SELECT * FROM outbox",
                        )
                    )

                before = durable_fingerprint()
                print("PHASE: native_reverse_preflight", file=sys.stderr)
                await engine._preflight_paid_proposal(
                    document, configured_floor_sat=300, allow_regtest_fixed_fee=True
                )
                assert store._reverse_proposals[origin.session_id].window is window
                assert window.monotonic_deadline == deadline
                assert window.time_allowed()
                assert len(samples) == 2
                assert all(sample[0] is window for sample in samples)
                assert all(0 <= sample[1] < 1 for sample in samples)
                assert not store._cooperation_handles
                assert native_allocations == 0
                assert durable_fingerprint() == before
                assert store._connection.execute(
                    "SELECT state FROM cooperation_attempts"
                ).fetchone() == ("BURNED",)
                assert store._connection.execute(
                    "SELECT state FROM economic_reservations"
                ).fetchone() == ("RELEASED",)
                return {
                    "original_paid_preflight": True,
                    "original_window_preserved": True,
                    "native_allocations": native_allocations,
                    "contract_funding_txid": funded.funding_txid,
                    "contract_vout": funded.contract_vout,
                    "contract_value_sat": int(funded.contract_value_sat),
                    "acquisition_interval_seconds": samples[0][1],
                    "preflight_interval_seconds": samples[1][1],
                }

            return asyncio.run(exercise())
