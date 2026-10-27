"""The CLI burns a live reverse attempt before allocating its client nonce."""

from __future__ import annotations

import asyncio
import json
from typing import TYPE_CHECKING

import pytest
import test_reverse_cooperative_claim as cooperative
from rill_core.recovery import REVERSE_COOPERATIVE_RESERVATION_EXTENSION as BURN
from rill_core.recovery import REVERSE_DISCLOSURE_EXTENSION as DISCLOSURE
from rill_crypto import Context
from test_live_reverse_swap import _segwit_claim
from test_recovery_cli import NATIVE_LIBRARY, NATIVE_ONLY
from test_reverse_disclosure_publication import _prepared
from test_reverse_sdk_lifetime import NativeSdk

from rill_cli import live_reverse_swap as reverse

if TYPE_CHECKING:
    from pathlib import Path

    from rill_crypto.binding import MusigAttempt


@NATIVE_ONLY
@pytest.mark.native_crypto
@pytest.mark.parametrize("write_failure", [False, True])
def test_durable_burn_ack_precedes_client_nonce_allocation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, *, write_failure: bool
) -> None:
    fixtures: list[NativeSdk] = []
    events: list[str] = []

    def create(crypto: Context, path: Path, patch: pytest.MonkeyPatch) -> NativeSdk:
        fixture = NativeSdk(crypto, path, patch)
        fixtures.append(fixture)
        original_write = fixture.write

        def write(candidate: bytes, previous: bytes | None) -> None:
            if DISCLOSURE in json.loads(candidate)["extensions"]:
                assert previous is fixture.documents[-1]
                assert BURN in json.loads(previous)["extensions"]
            is_burn = (
                BURN in json.loads(candidate)["extensions"]
                and BURN not in json.loads(previous)["extensions"]
                if previous
                else False
            )
            if is_burn and write_failure:
                raise OSError("simulated reservation storage failure")
            original_write(candidate, previous)
            if is_burn:
                events.append("burn-ack")
                assert (path / "reverse.age.cooperating").exists()

        fixture.write = write  # type: ignore[method-assign]
        return fixture

    original_begin = Context.musig_begin

    def begin(  # noqa: PLR0913 - preserve the exact native call seam
        context: Context,
        *,
        secret_key: bytes,
        user_public_key: bytes,
        provider_public_key: bytes,
        tap_tweak: bytes,
        message: bytes,
        cooperation_id: bytes,
    ) -> tuple[MusigAttempt, bytes]:
        if secret_key != cooperative.PROVIDER_CONTRACT:
            record = json.loads(fixtures[0].documents[-1])
            assert record["extensions"][BURN]["cooperation_id"] == cooperation_id.hex()
            assert DISCLOSURE not in record["extensions"]
            events.append("client-nonce")
        return original_begin(
            context,
            secret_key=secret_key,
            user_public_key=user_public_key,
            provider_public_key=provider_public_key,
            tap_tweak=tap_tweak,
            message=message,
            cooperation_id=cooperation_id,
        )

    monkeypatch.setattr(cooperative, "NativeSdk", create)
    monkeypatch.setattr(Context, "musig_begin", begin)
    fixture, _outcome = cooperative._run(tmp_path, monkeypatch, "signed")  # noqa: SLF001
    if write_failure:
        assert events == []
        assert len(_segwit_claim(fixture.broadcasts[0])[1]) == 4
    else:
        assert events == ["burn-ack", "client-nonce"]
        assert len(_segwit_claim(fixture.broadcasts[0])[1]) == 1


@NATIVE_ONLY
@pytest.mark.native_crypto
@pytest.mark.parametrize("ack", ["missing", "wrong"])
def test_pre_nonce_reservation_requires_exact_durable_acknowledgment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, ack: str
) -> None:
    async def exercise(crypto: Context) -> None:
        fixture, previous, _proposal = await _prepared(crypto, tmp_path, monkeypatch)
        wall = json.loads(previous)["updated_at"] + 1
        monkeypatch.setattr(reverse.time, "time", lambda: wall)
        writes: list[bytes] = []

        def write(candidate: bytes, predecessor: bytes | None) -> bytes | None:
            assert predecessor is previous
            writes.append(candidate)
            return previous if ack == "wrong" else None

        async with reverse._ReverseLifetime(120) as lifetime:  # noqa: SLF001
            lifetime.start()
            with pytest.raises(reverse.SwapError, match="not acknowledged"):
                await reverse._publish_reverse_cooperation_reservation(  # noqa: SLF001
                    lifetime,
                    acknowledged_fallback=previous,
                    binding=fixture.binding,
                    cooperation_id=b"\xff" * 32,
                    session=fixture.session,
                    write_recovery=write,
                    check_window=lambda: None,
                )
        assert len(writes) == 1
        assert BURN in json.loads(writes[0])["extensions"]
        fixture.session.send.assert_not_called()

    with Context(library_path=NATIVE_LIBRARY) as crypto:
        asyncio.run(exercise(crypto))


@NATIVE_ONLY
@pytest.mark.native_crypto
@pytest.mark.parametrize(
    "scenario",
    [
        "slow preparation",
        "late burn ack",
        "late disclosure ack",
        "remaining window",
        "completion failure",
        "native failure",
    ],
)
def test_all_preparation_and_publication_spend_the_original_window(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, scenario: str
) -> None:
    fixtures: list[NativeSdk] = []
    begins: list[bytes] = []
    timeouts: list[float] = []
    original_build = reverse.build_cooperative_claim
    original_begin = Context.musig_begin

    def create(crypto: Context, path: Path, patch: pytest.MonkeyPatch) -> NativeSdk:
        fixture = NativeSdk(crypto, path, patch)
        fixtures.append(fixture)
        original_write = fixture.write

        def write(candidate: bytes, previous: bytes | None) -> None:
            original_write(candidate, previous)
            extensions = json.loads(candidate)["extensions"]
            if DISCLOSURE in extensions:
                fixture.offset += 26 if scenario == "late disclosure ack" else 2
            elif BURN in extensions:
                fixture.offset += 26 if scenario == "late burn ack" else 2

        async def send(envelope: object, _recipient: str) -> None:
            action = envelope.payload.get("action")
            if action == "cooperative_claim_propose":
                fixture.offset += 4
            elif action == "cooperative_claim_complete" and scenario == "completion failure":
                raise ConnectionError("completion delivery failed")

        # Keep AsyncMock's call recording while injecting publication time/failure.
        fixture.session.send.side_effect = send
        fixture.write = write  # type: ignore[method-assign]
        return fixture

    def build(*args: object, **kwargs: object) -> object:
        fixtures[0].offset += 26 if scenario == "slow preparation" else 3
        return original_build(*args, **kwargs)

    def begin(context: Context, **kwargs: object) -> tuple[MusigAttempt, bytes]:
        if kwargs["secret_key"] != cooperative.PROVIDER_CONTRACT:
            begins.append(kwargs["cooperation_id"])
            if scenario == "native failure":
                raise RuntimeError("native allocation refused")
        return original_begin(context, **kwargs)

    monkeypatch.setattr(cooperative, "NativeSdk", create)
    monkeypatch.setattr(reverse, "build_cooperative_claim", build)
    monkeypatch.setattr(Context, "musig_begin", begin)
    fixture, _outcome = cooperative._run(  # noqa: SLF001 - shared native live-session fixture
        tmp_path, monkeypatch, "signed", receive_timeouts=timeouts
    )
    proposals = [
        call.args[0]
        for call in fixture.session.send.call_args_list
        if call.args[0].payload.get("action") == "cooperative_claim_propose"
    ]
    if scenario in ("slow preparation", "late burn ack"):
        assert begins == []
    else:
        assert len(begins) == 1
    successful = scenario in ("remaining window", "completion failure")
    assert len(_segwit_claim(fixture.broadcasts[0])[1]) == (1 if successful else 4)
    assert len(proposals) == (1 if successful else 0)
    assert len(timeouts) == (1 if successful else 0)
    if successful:
        assert 0 < timeouts[0] <= 14
        assert len(fixture.bounds) == 1
        assert all(bound["deadline"] == fixture.bounds[0]["deadline"] for bound in fixture.bounds)
