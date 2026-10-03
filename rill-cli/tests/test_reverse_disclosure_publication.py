"""Exact-ACK reverse disclosure snapshots remain local, immutable, and nonauthorizing."""

from __future__ import annotations

import asyncio
import json
import threading
from typing import TYPE_CHECKING

import pytest
from rill_core.recovery import REVERSE_DISCLOSURE_EXTENSION, REVERSE_FALLBACK_EXTENSION
from rill_core.settlement import FundingOutput, UnilateralAuthorization, build_cooperative_claim
from rill_core.wire.canonical import canonicalize
from rill_core.wire.hashes import COOPERATIVE_CLAIM_FEATURE, contract_hash
from rill_crypto import Context
from test_recovery_cli import NATIVE_LIBRARY, NATIVE_ONLY
from test_reverse_fallback_publication import _featured
from test_reverse_sdk_lifetime import NativeSdk

from rill_cli import live_reverse_swap as reverse
from rill_cli.live_swap import SwapError
from rill_cli.publication import RecoveryPublicationError

if TYPE_CHECKING:
    from pathlib import Path

    from rill_core.wire.messages import Envelope


async def _prepared(
    crypto: Context, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> tuple[NativeSdk, bytes, Envelope]:
    fixture = NativeSdk(crypto, tmp_path, monkeypatch)
    _featured(fixture, monkeypatch)

    def write(candidate: bytes, previous: bytes | None) -> bytes:
        fixture.write(candidate, previous)
        return candidate

    with pytest.raises(SwapError, match="not yet available"):
        await fixture.run(write)
    assert all(
        call.args[0].message_type != "action_request"
        for call in fixture.session.send.call_args_list
    )
    fixture.session.send.reset_mock()
    predecessor = fixture.documents[-1]
    funding = FundingOutput(
        bytes.fromhex(fixture.binding.funding_txid),
        fixture.binding.contract_vout,
        int(fixture.binding.contract_value_sat),
        bytes.fromhex(fixture.binding.contract_script_pubkey),
    )
    authorization = UnilateralAuthorization.from_terms(fixture.terms, funding, "claim", keys=crypto)
    plan = build_cooperative_claim(authorization, fee_sat=300)
    proposal = fixture.session.envelope(
        "action_request",
        {
            "action": "cooperative_claim_propose",
            "cooperation_id": "ff" * 32,
            "unsigned_transaction": plan.base_transaction.hex(),
            "public_nonce": (
                crypto.public_key((7).to_bytes(32, "big"))
                + crypto.public_key((8).to_bytes(32, "big"))
            ).hex(),
            "payment_preimage": fixture.preimage.hex(),
            "deadline_at": json.loads(predecessor)["updated_at"] + 20,
            "deadline_height": fixture.terms.refund_lock_height
            - fixture.terms.timing_policy.claim_confirmation_blocks,
        },
        contract=contract_hash(fixture.terms).hex(),
        required_features=(COOPERATIVE_CLAIM_FEATURE,),
    )
    return fixture, predecessor, proposal


@NATIVE_ONLY
@pytest.mark.native_crypto
def test_exact_acknowledged_predecessor_disclosure_is_create_only_encrypted_and_local(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def exercise(crypto: Context) -> None:
        fixture, previous, proposal = await _prepared(crypto, tmp_path, monkeypatch)
        initial = json.loads(previous)
        wall = initial["updated_at"] + 1.5
        monkeypatch.setattr(reverse.time, "time", lambda: wall)
        writes = []

        def write(candidate: bytes, predecessor: bytes | None) -> bytes:
            assert predecessor is previous
            writes.append(candidate)
            fixture.write(candidate, predecessor)
            return candidate

        async with reverse._ReverseLifetime(20) as lifetime:  # noqa: SLF001 - private publication gate
            lifetime.start()
            actual = await reverse._publish_reverse_disclosure(  # noqa: SLF001
                lifetime,
                acknowledged_fallback=previous,
                binding=fixture.binding,
                proposal=proposal,
                session=fixture.session,
                write_recovery=write,
            )
        assert writes == [actual]
        record = json.loads(actual)
        expected = {
            **initial,
            "updated_at": int(wall),
            "extensions": {
                **initial["extensions"],
                REVERSE_DISCLOSURE_EXTENSION: record["extensions"][REVERSE_DISCLOSURE_EXTENSION],
            },
        }
        assert record == expected
        assert record["extensions"][REVERSE_DISCLOSURE_EXTENSION][
            "proposal"
        ] == proposal.model_dump(mode="json")
        assert (tmp_path / "reverse.age.disclosing").exists()
        assert fixture.documents[-2] == previous
        assert fixture.broadcasts == []
        fixture.session.send.assert_not_called()
        # Destination collisions never overwrite the acknowledged file.
        ciphertext = (tmp_path / "reverse.age.disclosing").read_bytes()
        with pytest.raises(RecoveryPublicationError):
            fixture.write(actual, previous)
        assert (tmp_path / "reverse.age.disclosing").read_bytes() == ciphertext

    with Context(library_path=NATIVE_LIBRARY) as crypto:
        asyncio.run(exercise(crypto))


@NATIVE_ONLY
@pytest.mark.native_crypto
@pytest.mark.parametrize(
    "failure",
    [
        "expired",
        "backward",
        "expiry during write",
        "mutated deadline",
        "backward during write",
        "write then error",
        "wrong type",
        "wrong bytes",
        "missing fallback",
        "altered fallback",
        "partial disclosure",
        "existing disclosure",
        "wrong binding",
        "changed predecessor",
    ],
)
def test_uncertain_or_invalid_publication_never_acknowledges_disclosure_authority(  # noqa: PLR0915 - one publication failure matrix
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    failure: str,
) -> None:
    async def exercise(crypto: Context) -> None:  # noqa: PLR0915 - one failure matrix
        fixture, previous, proposal = await _prepared(crypto, tmp_path, monkeypatch)
        record = json.loads(previous)
        original_time = record["updated_at"]
        wall = original_time + 1.0
        binding = fixture.binding
        if failure == "expired":
            wall = proposal.payload["deadline_at"]
        elif failure == "backward":
            wall = original_time - 1.0
        elif failure == "missing fallback":
            del record["extensions"][REVERSE_FALLBACK_EXTENSION]
            previous = canonicalize(record)
        elif failure == "altered fallback":
            record["extensions"][REVERSE_FALLBACK_EXTENSION]["transaction"] = "00"
            previous = canonicalize(record)
        elif failure == "changed predecessor":
            record["monotonic_knowledge"]["preimage"] = "ab" * 32
            previous = canonicalize(record)
        elif failure in ("partial disclosure", "existing disclosure"):
            record["extensions"][REVERSE_DISCLOSURE_EXTENSION] = (
                {}
                if failure == "partial disclosure"
                else {
                    "version": 1,
                    "funding_binding_hash": "ab" * 32,
                    "proposal": proposal.model_dump(mode="json"),
                }
            )
            previous = canonicalize(record)
        elif failure == "wrong binding":
            binding = binding.model_copy(update={"funding_txid": "ab" * 32})
        monkeypatch.setattr(reverse.time, "time", lambda: wall)
        writes = []

        def write(candidate: bytes, predecessor: bytes | None) -> object:
            nonlocal wall
            assert predecessor is previous
            writes.append(candidate)
            if failure in (
                "expiry during write",
                "mutated deadline",
                "backward during write",
                "write then error",
            ):
                fixture.write(candidate, predecessor)
                if failure in ("expiry during write", "mutated deadline"):
                    wall = proposal.payload["deadline_at"]
                    if failure == "mutated deadline":
                        proposal.payload["deadline_at"] += 1000
                elif failure == "backward during write":
                    wall -= 0.5
                else:
                    raise OSError("uncertain disk state")
            if failure == "wrong type":
                return bytearray(candidate)
            if failure == "wrong bytes":
                return previous
            return candidate

        async with reverse._ReverseLifetime(20) as lifetime:  # noqa: SLF001
            lifetime.start()
            with pytest.raises(SwapError, match="reverse disclosure publication"):
                await reverse._publish_reverse_disclosure(  # noqa: SLF001
                    lifetime,
                    acknowledged_fallback=previous,
                    binding=binding,
                    proposal=proposal,
                    session=fixture.session,
                    write_recovery=write,
                )
        assert fixture.broadcasts == []
        fixture.session.send.assert_not_called()
        if failure in (
            "expired",
            "backward",
            "missing fallback",
            "altered fallback",
            "partial disclosure",
            "existing disclosure",
            "wrong binding",
            "changed predecessor",
        ):
            assert writes == []
        if failure in (
            "expiry during write",
            "mutated deadline",
            "backward during write",
            "write then error",
        ):
            assert (tmp_path / "reverse.age.disclosing").exists()

    with Context(library_path=NATIVE_LIBRARY) as crypto:
        asyncio.run(exercise(crypto))


@NATIVE_ONLY
@pytest.mark.native_crypto
def test_canceling_disclosure_publication_drains_writer_before_crypto_can_close(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def exercise(crypto: Context) -> None:
        fixture, previous, proposal = await _prepared(crypto, tmp_path, monkeypatch)
        entered, release = threading.Event(), threading.Event()
        cancellation_handled = asyncio.Event()
        monkeypatch.setattr(reverse.time, "time", lambda: json.loads(previous)["updated_at"] + 1.0)

        def write(candidate: bytes, predecessor: bytes | None) -> bytes:
            entered.set()
            assert release.wait(5)
            fixture.write(candidate, predecessor)
            return candidate

        async def publish() -> bytes:
            async with reverse._ReverseLifetime(20) as lifetime:  # noqa: SLF001
                lifetime.start()
                try:
                    return await reverse._publish_reverse_disclosure(  # noqa: SLF001
                        lifetime,
                        acknowledged_fallback=previous,
                        binding=fixture.binding,
                        proposal=proposal,
                        session=fixture.session,
                        write_recovery=write,
                    )
                except asyncio.CancelledError:
                    assert lifetime.allowed() is False
                    cancellation_handled.set()
                    raise

        running = asyncio.create_task(publish())
        try:
            assert await asyncio.to_thread(entered.wait, 2)
            running.cancel()
            await asyncio.wait_for(cancellation_handled.wait(), 2)
            assert not running.done()
            release.set()
            with pytest.raises(asyncio.CancelledError):
                await running
            assert (tmp_path / "reverse.age.disclosing").exists()
        finally:
            release.set()
            await asyncio.gather(running, return_exceptions=True)
        assert fixture.broadcasts == []
        fixture.session.send.assert_not_called()

    with Context(library_path=NATIVE_LIBRARY) as crypto:
        asyncio.run(exercise(crypto))
