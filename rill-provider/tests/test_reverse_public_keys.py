"""Owner-computed public curve snapshots keep Core workers away from native handles."""

from __future__ import annotations

import asyncio
import dataclasses
import json
import threading
from typing import TYPE_CHECKING

import httpx
import pytest
from rill_core.errors import ValidationError
from rill_core.networks import backend_names
from rill_core.settlement import reconstruct_taproot_contract
from rill_core.wire.canonical import canonicalize
from rill_core.wire.settlement_messages import FundingBindingPayload
from test_reverse_proposal_debt import _facts
from test_reverse_proposal_debt import (
    pytestmark as pytestmark,  # noqa: PLC0414 - native test policy
)
from test_reverse_proposal_reservation import reserved as reserved  # noqa: PLC0414 - fixture

from rill_provider import core_tx_bytes
from rill_provider.core_tx_bytes import CoreReadError, CoreTransactionReader
from rill_provider.live_session_store import StaleOwnerError
from rill_provider.reverse_operations import ReverseOperation
from rill_provider.reverse_settlement import _ReversePublicKeySnapshot

if TYPE_CHECKING:
    from pathlib import Path

    from test_reverse_proposal_reservation import ReservationCase


def test_snapshot_has_only_immutable_public_data_and_never_calls_native_in_worker(
    reserved: ReservationCase,
) -> None:
    terms, _, _ = _facts(reserved)
    owner_thread = threading.get_ident()
    calls = []
    native = reserved.origin.crypto.crypto

    class OwnerOnlyKeys:
        def musig_internal_key(self, user: bytes, provider: bytes) -> tuple[bytes, int]:
            assert threading.get_ident() == owner_thread
            calls.append("internal")
            return native.musig_internal_key(user, provider)

        def musig_output_key(self, user: bytes, provider: bytes, tweak: bytes) -> tuple[bytes, int]:
            assert threading.get_ident() == owner_thread
            calls.append("output")
            return native.musig_output_key(user, provider, tweak)

    snapshot = _ReversePublicKeySnapshot.capture(terms, keys=OwnerOnlyKeys())
    expected = reconstruct_taproot_contract(terms, keys=native)
    assert calls == ["internal", "output"]
    for field in dataclasses.fields(snapshot):
        value = getattr(snapshot, field.name)
        assert type(value) is bytes or (
            type(value) is tuple and type(value[0]) is bytes and type(value[1]) is int
        )
    with pytest.raises(dataclasses.FrozenInstanceError):
        snapshot.tweak = b"\x00" * 32

    async def exercise() -> None:
        async with reserved.store.reverse_operations.operation() as operation:
            actual = await operation.worker(
                lambda: reconstruct_taproot_contract(terms, keys=snapshot)
            )
            assert actual == expected

    asyncio.run(exercise())
    assert calls == ["internal", "output"]


@pytest.mark.parametrize(
    "fault", ["swap", "user parity", "provider parity", "user", "provider", "tweak"]
)
def test_snapshot_rejects_any_different_ordered_curve_input(
    reserved: ReservationCase,
    fault: str,
) -> None:
    terms, _, _ = _facts(reserved)
    snapshot = _ReversePublicKeySnapshot.capture(terms, keys=reserved.origin.crypto.crypto)
    user, provider, tweak = snapshot.user_key, snapshot.provider_key, snapshot.tweak
    if fault == "swap":
        user, provider = provider, user
    elif fault == "user parity":
        user = bytes([user[0] ^ 1]) + user[1:]
    elif fault == "provider parity":
        provider = bytes([provider[0] ^ 1]) + provider[1:]
    elif fault == "user":
        user = reserved.origin.crypto.crypto.public_key((12).to_bytes(32, "big"))
    elif fault == "provider":
        provider = reserved.origin.crypto.crypto.public_key((12).to_bytes(32, "big"))
    else:
        tweak = bytes([tweak[0] ^ 1]) + tweak[1:]
    with pytest.raises(ValidationError):
        snapshot.musig_output_key(user, provider, tweak)
    if fault != "tweak":
        with pytest.raises(ValidationError):
            snapshot.musig_internal_key(user, provider)


@pytest.mark.parametrize("field", ["payment hash", "refund height"])
def test_recomputed_contract_tweak_refuses_changed_script_commitments(
    reserved: ReservationCase,
    field: str,
) -> None:
    terms, _, _ = _facts(reserved)
    snapshot = _ReversePublicKeySnapshot.capture(terms, keys=reserved.origin.crypto.crypto)
    if field == "payment hash":
        changed = terms.model_copy(
            update={
                "invoice_binding": terms.invoice_binding.model_copy(
                    update={"payment_hash": "ab" * 32}
                ),
            }
        )
    else:
        changed = terms.model_copy(update={"refund_lock_height": terms.refund_lock_height + 1})
    with pytest.raises(ValidationError, match="tweak differs"):
        reconstruct_taproot_contract(changed, keys=snapshot)


@pytest.mark.parametrize(
    "fault",
    [
        None,
        "amount",
        "contract hash",
        "mempool spend",
        "block bytes",
        "closed owner",
        "canceled owner",
    ],
)
def test_core_worker_uses_snapshot_and_real_static_matcher_without_native_handles(  # noqa: PLR0915 - one seven-RPC fixture
    reserved: ReservationCase,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    fault: str | None,
) -> None:
    terms, expected, _ = _facts(reserved)
    snapshot = _ReversePublicKeySnapshot.capture(terms, keys=reserved.origin.crypto.crypto)
    documents = [json.loads(entry.canonical_bytes) for entry in reserved.store.pending_outbox()]
    funding = next(
        document for document in documents if document["message_type"] == "funding_binding"
    )
    selected = FundingBindingPayload.model_validate_json(
        canonicalize(funding["payload"]), strict=True
    )
    binding = selected.binding
    if fault == "amount":
        economics = terms.economics.model_copy(
            update={
                "contract_amount_sat": str(
                    int(terms.economics.model_dump()["contract_amount_sat"]) + 1
                ),
            }
        )
        terms = terms.model_copy(update={"economics": economics})
        # Curve inputs can match even when complete economic commitments differ.
        assert reconstruct_taproot_contract(terms, keys=snapshot).tap_tweak == snapshot.tweak
    elif fault == "contract hash":
        binding = binding.model_copy(update={"contract_hash": "ab" * 32})
    info = {
        "chain": backend_names(terms.network_identity).core_chain,
        "blocks": expected.tip_height,
        "bestblockhash": expected.tip_hash,
        "initialblockdownload": False,
    }
    output = {
        "bestblock": expected.tip_hash,
        "confirmations": expected.confirmations,
        "coinbase": False,
        "value": "SAT_VALUE",
        "scriptPubKey": {"hex": binding.contract_script_pubkey},
    }
    responses = [
        ("getblockchaininfo", [], info),
        ("getblockhash", [0], terms.network_identity.genesis_hash),
        ("getrawtransaction", [binding.funding_txid, False], selected.funding_transaction),
        (
            "gettxout",
            [binding.funding_txid, binding.contract_vout, True],
            None if fault == "mempool spend" else output,
        ),
        ("getblockhash", [expected.inclusion_height], expected.inclusion_block_hash),
        (
            "getrawtransaction",
            [binding.funding_txid, False, expected.inclusion_block_hash],
            "00" if fault == "block bytes" else selected.funding_transaction,
        ),
        ("getblockchaininfo", [], info),
    ]
    seen = []
    entered, release = threading.Event(), threading.Event()
    whole, fraction = divmod(int(binding.contract_value_sat), 100_000_000)
    btc_literal = f"{whole}.{fraction:08d}"

    def respond(request: httpx.Request) -> httpx.Response:
        payload = json.loads(request.content)
        seen.append(payload)
        request_id = len(seen)
        if fault in ("closed owner", "canceled owner") and request_id == 1:
            entered.set()
            assert release.wait(5)
        method, params, result = responses[request_id - 1]
        assert payload == {"jsonrpc": "2.0", "id": request_id, "method": method, "params": params}
        body = (
            json.dumps({"jsonrpc": "2.0", "id": request_id, "result": result})
            .replace(
                '"SAT_VALUE"',
                btc_literal,
            )
            .encode()
        )
        return httpx.Response(200, stream=httpx.ByteStream(body))

    real_client = httpx.Client
    transport = httpx.MockTransport(respond)

    def client(**kwargs: object) -> httpx.Client:
        return real_client(transport=transport, **kwargs)

    monkeypatch.setattr(core_tx_bytes.httpx, "Client", client)
    cookie = tmp_path / "cookie"
    cookie.write_text("__cookie__:password")
    cookie.chmod(0o600)
    reader = CoreTransactionReader(port=18443, cookie_path=cookie, network=terms.network_identity)

    async def exercise() -> None:
        async with reserved.store.reverse_operations.operation() as operation:

            def probe() -> object:
                return reader.observe_cooperative_claim_outpoint(binding, terms, keys=snapshot)

            if fault in (None, "closed owner", "canceled owner"):
                assert await operation.worker(probe) == expected
                assert len(seen) == 7
            else:
                with pytest.raises((ValidationError, CoreReadError)):
                    await operation.worker(probe)

    async def interrupt_during_rpc() -> None:
        draining = asyncio.Event()
        original_drain = ReverseOperation._drain  # noqa: SLF001 - synchronized cancellation

        async def checked_drain(token: ReverseOperation) -> None:
            assert token.submission_allowed() is False
            assert reserved.store.owner_is_open
            draining.set()
            await original_drain(token)

        if fault == "canceled owner":
            monkeypatch.setattr(ReverseOperation, "_drain", checked_drain)
        running = asyncio.create_task(exercise())
        try:
            assert await asyncio.to_thread(entered.wait, 2)
            if fault == "closed owner":
                reserved.store.close()
                assert not reserved.store.owner_is_open
            else:
                running.cancel()
                await asyncio.wait_for(draining.wait(), 2)
            assert not running.done()
            release.set()
            with pytest.raises(
                StaleOwnerError if fault == "closed owner" else asyncio.CancelledError
            ):
                await running
            assert len(seen) == 7
        finally:
            release.set()
            await asyncio.gather(running, return_exceptions=True)

    asyncio.run(
        interrupt_during_rpc() if fault in ("closed owner", "canceled owner") else exercise()
    )
