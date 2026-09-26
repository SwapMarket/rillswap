"""The permissionless directory lists any verified provider and drops equivocators."""

from __future__ import annotations

import asyncio
import os
import time
from pathlib import Path
from typing import TYPE_CHECKING, Any

import pytest
from pyrage import x25519
from rill_core.wire.types import NetworkIdentity

from rill_cli import main, provider_directory

if TYPE_CHECKING:
    from collections.abc import AsyncIterator

NATIVE = pytest.mark.skipif(
    os.environ.get("RILLSWAP_RUN_NATIVE_CRYPTO") != "1" or "RILL_CRYPTO_LIBRARY" not in os.environ,
    reason="set RILLSWAP_RUN_NATIVE_CRYPTO=1 and RILL_CRYPTO_LIBRARY",
)
NETWORKS = Path(__file__).parents[2] / "rill-docs" / "networks"


def _ad(revision: int, **extra: Any) -> dict[str, Any]:  # noqa: ANN401
    return {"revision": revision, **extra}


def test_merge_keeps_highest_revision_across_relays() -> None:
    listing = provider_directory.merge(
        [
            {"aa" * 32: [_ad(1), _ad(3)], "bb" * 32: [_ad(2)]},
            {"aa" * 32: [_ad(3)]},
            {},
        ]
    )
    assert listing == [
        {
            "provider_identity_xonly_key": "aa" * 32,
            "relays_seen": 2,
            "status": "listed",
            "advertisement": _ad(3),
        },
        {
            "provider_identity_xonly_key": "bb" * 32,
            "relays_seen": 1,
            "status": "listed",
            "advertisement": _ad(2),
        },
    ]


def test_equivocation_excludes_only_that_provider() -> None:
    listing = provider_directory.merge(
        [{"aa" * 32: [_ad(5, fee=1)], "bb" * 32: [_ad(1)]}, {"aa" * 32: [_ad(5, fee=2)]}]
    )
    assert listing[0] == {
        "provider_identity_xonly_key": "aa" * 32,
        "relays_seen": 2,
        "status": "equivocating",
    }
    assert listing[1]["status"] == "listed"
    # An older conflicting revision is not equivocation at the latest revision.
    assert provider_directory.merge([{"aa" * 32: [_ad(4, fee=9), _ad(5)]}])[0]["status"] == (
        "listed"
    )


class _Relay:
    def __init__(self, events: list[bytes]) -> None:
        self.events_list = events
        self.filters: list[dict[str, Any]] = []

    async def subscribe(self, filters: list[dict[str, Any]]) -> None:
        self.filters = filters

    async def events(self) -> AsyncIterator[bytes]:
        for event in self.events_list:
            yield event
        await asyncio.sleep(3600)  # a live subscription never ends by itself


def test_query_has_no_author_allowlist_and_is_bounded(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(provider_directory, "MAX_DIRECTORY_EVENTS", 3)
    monkeypatch.setattr(
        provider_directory, "verify_announcement", lambda _raw, **kw: _ad(1, key=kw["identity"])
    )
    events = [b"not json", *(('{"pubkey": "%s"}' % (c * 64)).encode() for c in "abcd")]
    relay = _Relay(events)
    found = asyncio.run(
        provider_directory._query(  # noqa: SLF001
            relay,  # type: ignore[arg-type]
            network=None,  # type: ignore[arg-type]
            crypto=None,  # type: ignore[arg-type]
            now=1,
            timeout=1.0,
        )
    )
    assert "authors" not in relay.filters[0]
    assert sorted(found) == ["a" * 64, "b" * 64]  # the 4th event hit the cap


def test_cli_reports_when_no_relay_answers(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    argv = [
        "providers",
        "list",
        "--network",
        str(NETWORKS / "signet.json"),
        "--crypto-library",
        str(tmp_path / "missing.so"),
        "--relay",
        "ws://127.0.0.1:9/",
        "--allow-direct-relay",
    ]
    assert main.main(argv) == 2  # the native library is missing; nothing leaks
    assert capsys.readouterr().err == "Provider listing failed.\n"


@pytest.mark.native_crypto
@NATIVE
def test_native_directory_lists_anyone_on_the_selected_network(tmp_path: Path) -> None:
    from rill_crypto import Context  # noqa: PLC0415
    from rill_provider.provider_identity import AnnouncementTerms, ProviderIdentity  # noqa: PLC0415

    signet = NetworkIdentity.model_validate_json((NETWORKS / "signet.json").read_bytes())
    testnet4 = NetworkIdentity.model_validate_json((NETWORKS / "testnet4.json").read_bytes())
    now = int(time.time())
    with Context(library_path=os.environ["RILL_CRYPTO_LIBRARY"]) as crypto:
        raws: list[bytes] = []
        keys: list[str] = []
        for index, network in enumerate((signet, signet, testnet4)):
            custody = x25519.Identity.generate()
            path = tmp_path / f"identity-{index}.age"
            xonly = ProviderIdentity.provision(
                path, recipient=str(custody.to_public()), crypto=crypto
            )
            signer = ProviderIdentity.load(
                path, custody_identity=str(custody), expected_xonly_public_key=xonly, crypto=crypto
            )
            keys.append(xonly)
            raws.append(
                signer.build_announcement(
                    AnnouncementTerms(
                        network=network,
                        profiles=("btc-to-ln/v1",),
                        amount_bands=((1000, 100000),),
                        base_fee_sat=10,
                        proportional_millionths=1000,
                        transport_endpoints=("wss://relay.example.invalid/",),
                        epoch_inbox_xonly_keys=("cc" * 32,),
                        slot="main",
                        created_at=now,
                        expires_at=now + 3600,
                    )
                )
            )
        tampered = raws[1].replace(b"relay.example", b"relay.exampla")
        found = asyncio.run(
            provider_directory._query(  # noqa: SLF001
                _Relay([*raws, tampered]),  # type: ignore[arg-type]
                network=signet,
                crypto=crypto,
                now=now,
                timeout=2.0,
            )
        )
    # Both signet providers are listed with no prior trust; testnet4 and the
    # tampered copy are ignored.
    assert sorted(found) == sorted(keys[:2])
    assert all(len(ads) == 1 for ads in found.values())
