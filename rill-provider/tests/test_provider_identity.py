"""Provider identity custody: explicit, purpose-scoped, RS-005 compatible."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import time
from pathlib import Path
from typing import Any

import pytest
from pyrage import x25519  # type: ignore[import-untyped]
from rill_core.wire.canonical import canonicalize
from rill_core.wire.hashes import tagged_hash
from rill_core.wire.types import NetworkIdentity

from rill_provider import _nip01_event as nip01
from rill_provider import _transport_pow as transport_pow
from rill_provider import provider_identity as identity
from rill_provider.provider_identity import (
    AnnouncementTerms,
    ProviderIdentity,
    ProviderIdentityError,
)

ROOT = Path(__file__).parents[2]
VECTORS = ROOT / "rill-docs/vectors/discovery"
WEB_SCRIPT = ROOT / "rill-web/scripts/verify-announcement.ts"
NATIVE = pytest.mark.skipif(
    os.environ.get("RILLSWAP_RUN_NATIVE_CRYPTO") != "1",
    reason="set RILLSWAP_RUN_NATIVE_CRYPTO=1 with pinned native library",
)


def _vectors() -> tuple[dict[str, Any], dict[str, Any]]:
    manual = json.loads((VECTORS / "manual-advertisement-regtest-v1.json").read_text())
    event = json.loads((VECTORS / "nostr-announcement-regtest-v1.json").read_text())
    return manual, event


def _terms(advertisement: dict[str, Any], **changed: Any) -> AnnouncementTerms:  # noqa: ANN401
    values: dict[str, Any] = {
        "network": NetworkIdentity.model_validate(advertisement["network_identities"][0]),
        "profiles": tuple(advertisement["profiles"]),
        "amount_bands": tuple(
            (int(band["minimum_sat"]), int(band["maximum_sat"]))
            for band in advertisement["amount_bands"]
        ),
        "base_fee_sat": int(advertisement["indicative_fee_policy"]["base_sat"]),
        "proportional_millionths": advertisement["indicative_fee_policy"][
            "proportional_millionths"
        ],
        "transport_endpoints": tuple(advertisement["transport_endpoints"]),
        "epoch_inbox_xonly_keys": tuple(advertisement["epoch_inbox_xonly_keys"]),
        "slot": advertisement["slot"],
        "created_at": advertisement["created_at"],
        "expires_at": advertisement["expires_at"],
    }
    values.update(changed)
    return AnnouncementTerms(**values)


def test_advertisement_address_and_event_id_match_docs_vector() -> None:
    manual, event = _vectors()
    expected = manual["advertisement"]
    built = identity._advertisement(  # noqa: SLF001 - pure serialization seam
        expected["provider_identity_xonly_key"], _terms(expected)
    )
    # Policy: revision equals created_at (stateless strict increase). The
    # vector uses revision 1; every other member must match exactly. The
    # vector predates the always-announced funding depth, which clients treat
    # as unknown when absent.
    assert built["extensions"].pop(identity.FUNDING_CONFIRMATIONS_EXTENSION) == {"confirmations": 1}
    assert built["revision"] == expected["created_at"]
    assert {**built, "revision": expected["revision"]} == expected
    address = identity.announcement_address(_terms(expected).network, expected["slot"])
    assert ["d", address] in event["tags"]
    content = canonicalize(manual).decode("utf-8")
    assert (
        nip01._event_id(  # noqa: SLF001 - shared NIP-01 hash invariant
            event["pubkey"], event["created_at"], event["kind"], event["tags"], content
        )
        == event["id"]
    )


def test_advertisement_states_no_handshake_feature_requirement() -> None:
    # Every session is epoch-bound, so there is no optional requirement to announce.
    manual, _ = _vectors()
    ad = manual["advertisement"]
    advertised = identity._advertisement(ad["provider_identity_xonly_key"], _terms(ad))  # noqa: SLF001
    assert advertised["extensions"] == {
        identity.FUNDING_CONFIRMATIONS_EXTENSION: {"confirmations": 1},
    }


@pytest.mark.parametrize(
    "change",
    [
        {"profiles": ()},
        {"profiles": ("btc-to-ln/v1", "btc-to-ln/v1")},
        {"amount_bands": ((10, 5),)},
        {"epoch_inbox_xonly_keys": ()},
        {"epoch_inbox_xonly_keys": ("aa" * 32,) * 2},
        {"epoch_inbox_xonly_keys": tuple(f"{i:064x}" for i in range(5))},
        {"expires_at": 1},
        {"transport_endpoints": ("",)},
    ],
)
def test_unsupported_terms_are_refused(change: dict[str, Any]) -> None:
    manual, _ = _vectors()
    with pytest.raises(ProviderIdentityError):
        identity._advertisement("bb" * 32, _terms(manual["advertisement"], **change))  # noqa: SLF001


def test_identity_epoch_key_collision_and_non_regtest_refused() -> None:
    manual, _ = _vectors()
    advertisement = manual["advertisement"]
    key = advertisement["epoch_inbox_xonly_keys"][0]
    with pytest.raises(ProviderIdentityError):
        identity._advertisement(key, _terms(advertisement))  # noqa: SLF001
    mainnet = _terms(advertisement).network.model_copy(update={"name": "mainnet"})
    with pytest.raises(ProviderIdentityError):
        identity._advertisement("bb" * 32, _terms(advertisement, network=mainnet))  # noqa: SLF001


def _provisioned(tmp_path: Path, crypto: Any) -> tuple[Path, x25519.Identity, str]:  # noqa: ANN401
    custody = x25519.Identity.generate()
    path = tmp_path / "identity.age"
    xonly = ProviderIdentity.provision(path, recipient=str(custody.to_public()), crypto=crypto)
    assert path.stat().st_mode & 0o777 == 0o600
    return path, custody, xonly


@pytest.mark.native_crypto
@NATIVE
def test_native_identity_custody_is_explicit_and_bound(tmp_path: Path) -> None:
    from rill_crypto import Context  # noqa: PLC0415

    with Context(library_path=os.environ["RILL_CRYPTO_LIBRARY"]) as crypto:
        path, custody, xonly = _provisioned(tmp_path, crypto)
        with pytest.raises(ProviderIdentityError):
            ProviderIdentity.provision(path, recipient=str(custody.to_public()), crypto=crypto)
        loaded = ProviderIdentity.load(
            path, custody_identity=str(custody), expected_xonly_public_key=xonly, crypto=crypto
        )
        assert xonly in repr(loaded)
        assert "secret" not in repr(loaded)
        for kwargs in (
            {
                "custody_identity": str(x25519.Identity.generate()),
                "expected_xonly_public_key": xonly,
            },
            {"custody_identity": str(custody), "expected_xonly_public_key": "aa" * 32},
        ):
            with pytest.raises(ProviderIdentityError, match="not the configured key"):
                ProviderIdentity.load(path, crypto=crypto, **kwargs)
        with pytest.raises(ProviderIdentityError):
            ProviderIdentity.load(
                tmp_path / "absent.age",
                custody_identity=str(custody),
                expected_xonly_public_key=xonly,
                crypto=crypto,
            )


@pytest.mark.native_crypto
@NATIVE
def test_native_announcement_signatures_verify(tmp_path: Path) -> None:
    from rill_crypto import Context  # noqa: PLC0415
    from rill_crypto.binding import CryptoError  # noqa: PLC0415

    manual, _ = _vectors()
    with Context(library_path=os.environ["RILL_CRYPTO_LIBRARY"]) as crypto:
        path, custody, xonly = _provisioned(tmp_path, crypto)
        signer = ProviderIdentity.load(
            path, custody_identity=str(custody), expected_xonly_public_key=xonly, crypto=crypto
        )
        raw = signer.build_announcement(_terms(manual["advertisement"]))
        event = nip01._verify_signed_event(raw, verifier=crypto)  # noqa: SLF001
        assert (event.kind, event.pubkey) == (39417, xonly)
        wrapper = json.loads(event.content)
        assert canonicalize(wrapper).decode() == event.content
        crypto.schnorr_verify(
            bytes.fromhex(xonly),
            tagged_hash(identity.ADVERTISEMENT_TAG, canonicalize(wrapper["advertisement"])),
            bytes.fromhex(wrapper["signature"]),
        )
        assert wrapper["advertisement"]["extensions"] != {}
        wrapper["advertisement"]["extensions"] = {}
        with pytest.raises(CryptoError):
            crypto.schnorr_verify(
                bytes.fromhex(xonly),
                tagged_hash(identity.ADVERTISEMENT_TAG, canonicalize(wrapper["advertisement"])),
                bytes.fromhex(wrapper["signature"]),
            )


def _web_verify(bun: str, event: bytes, xonly: str, network: dict[str, Any]) -> dict[str, Any]:
    request = {
        "event": event.decode(),
        "identity": xonly,
        "network": network,
        "profile": "btc-to-ln/v1",
    }
    result = subprocess.run(  # noqa: S603 - local test script, no shell
        [bun, str(WEB_SCRIPT)],
        cwd=ROOT / "rill-web",
        input=json.dumps(request).encode(),
        capture_output=True,
        timeout=60,
        check=False,
    )
    assert result.returncode == 0, "web verifier refused provider announcement"
    verified: dict[str, Any] = json.loads(result.stdout)
    return verified


@pytest.mark.web_nip59_interop
@pytest.mark.skipif(
    os.environ.get("RILLSWAP_RUN_WEB_NIP59") != "1",
    reason="explicit local web/native opt-in required",
)
def test_provider_announcement_passes_the_web_verifier(tmp_path: Path) -> None:
    from rill_crypto import Context  # noqa: PLC0415

    bun = shutil.which("bun")
    assert bun is not None, "Bun required for web interop"
    manual, _ = _vectors()
    now = int(time.time())
    advertisement = manual["advertisement"]
    with Context(library_path=os.environ["RILL_CRYPTO_LIBRARY"]) as crypto:
        path, custody, xonly = _provisioned(tmp_path, crypto)
        signer = ProviderIdentity.load(
            path, custody_identity=str(custody), expected_xonly_public_key=xonly, crypto=crypto
        )
        terms = _terms(advertisement, created_at=now, expires_at=now + 3600)
        verified = _web_verify(
            bun, signer.build_announcement(terms), xonly, advertisement["network_identities"][0]
        )
    assert verified["epochInboxKeys"] == advertisement["epoch_inbox_xonly_keys"]
    assert verified["addressD"] == identity.announcement_address(terms.network, terms.slot)
    assert verified["revision"] == now


@pytest.mark.native_crypto
@NATIVE
def test_native_provider_terms_signature_verifies_and_is_scoped(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from rill_core.wire.hashes import provider_terms_hash  # noqa: PLC0415
    from rill_core.wire.messages import ProviderTerms  # noqa: PLC0415
    from rill_crypto import Context  # noqa: PLC0415

    vector = json.loads((ROOT / "rill-docs/vectors/wire/quote-v1.json").read_text())
    offer = ProviderTerms.model_validate_json(
        json.dumps(vector["valid"]["termsOffer"][0]["terms"]), strict=True
    )
    with Context(library_path=os.environ["RILL_CRYPTO_LIBRARY"]) as crypto:
        with monkeypatch.context() as patch:
            patch.setattr(identity.secrets, "token_bytes", lambda _n: (1).to_bytes(32, "big"))
            path, custody, xonly = _provisioned(tmp_path, crypto)
        assert xonly == offer.contract_terms.provider_identity_key
        signer = ProviderIdentity.load(
            path, custody_identity=str(custody), expected_xonly_public_key=xonly, crypto=crypto
        )
        signature = signer.sign_provider_terms(offer)
        crypto.schnorr_verify(
            bytes.fromhex(xonly), provider_terms_hash(offer), bytes.fromhex(signature)
        )
        foreign = offer.model_copy(
            update={
                "contract_terms": offer.contract_terms.model_copy(
                    update={"provider_identity_key": "aa" * 32}
                )
            }
        )
        with pytest.raises(ProviderIdentityError, match="identity"):
            signer.sign_provider_terms(foreign)


PUBLIC_NETWORKS = ("mainnet", "signet", "testnet4")


def _public(name: str) -> NetworkIdentity:
    return NetworkIdentity.model_validate_json(
        (ROOT / "rill-docs" / "networks" / f"{name}.json").read_bytes()
    )


@pytest.mark.parametrize("name", PUBLIC_NETWORKS)
def test_public_networks_are_advertisable(name: str) -> None:
    manual, _ = _vectors()
    terms = _terms(manual["advertisement"], network=_public(name))
    advertisement = identity._advertisement("bb" * 32, terms)  # noqa: SLF001
    assert advertisement["network_identities"] == [_public(name).model_dump(mode="json")]
    legacy = _public(name).model_copy(update={"name": "testnet3"})
    with pytest.raises(ProviderIdentityError):
        identity._advertisement("bb" * 32, _terms(manual["advertisement"], network=legacy))  # noqa: SLF001


@pytest.mark.native_crypto
@NATIVE
@pytest.mark.parametrize("name", PUBLIC_NETWORKS)
def test_native_public_announcement_tags_name_the_signed_network(tmp_path: Path, name: str) -> None:
    from rill_crypto import Context  # noqa: PLC0415

    manual, _ = _vectors()
    with Context(library_path=os.environ["RILL_CRYPTO_LIBRARY"]) as crypto:
        path, custody, xonly = _provisioned(tmp_path, crypto)
        signer = ProviderIdentity.load(
            path, custody_identity=str(custody), expected_xonly_public_key=xonly, crypto=crypto
        )
        terms = _terms(manual["advertisement"], network=_public(name))
        event = nip01._verify_signed_event(signer.build_announcement(terms), verifier=crypto)  # noqa: SLF001
    assert [list(tag) for tag in event.tags] == [
        ["rillswap", identity.BINDING_VERSION],
        ["network", name],
        ["d", identity.announcement_address(terms.network, terms.slot)],
    ]


@pytest.mark.web_nip59_interop
@pytest.mark.skipif(
    os.environ.get("RILLSWAP_RUN_WEB_NIP59") != "1",
    reason="explicit local web/native opt-in required",
)
@pytest.mark.parametrize("name", PUBLIC_NETWORKS)
def test_public_announcement_passes_the_web_verifier(tmp_path: Path, name: str) -> None:
    from rill_crypto import Context  # noqa: PLC0415

    bun = shutil.which("bun")
    assert bun is not None, "Bun required for web interop"
    manual, _ = _vectors()
    now = int(time.time())
    with Context(library_path=os.environ["RILL_CRYPTO_LIBRARY"]) as crypto:
        path, custody, xonly = _provisioned(tmp_path, crypto)
        signer = ProviderIdentity.load(
            path, custody_identity=str(custody), expected_xonly_public_key=xonly, crypto=crypto
        )
        terms = _terms(
            manual["advertisement"], network=_public(name), created_at=now, expires_at=now + 3600
        )
        network = _public(name).model_dump(mode="json")
        verified = _web_verify(bun, signer.build_announcement(terms), xonly, network)
    assert verified["addressD"] == identity.announcement_address(terms.network, terms.slot)


def test_evm_assets_are_advertised_in_the_rs010_extension() -> None:
    from evm_fixtures import evm_terms  # noqa: PLC0415
    from rill_core.wire.types import EvmAssetIdentity  # noqa: PLC0415

    manual, _event = _vectors()
    asset = evm_terms("erc20-to-ln/v1").evm_asset
    terms = _terms(manual["advertisement"], profiles=("erc20-to-ln/v1",), evm_assets=(asset,))
    advertisement = identity._advertisement("bb" * 32, terms)  # noqa: SLF001
    (advertised,) = advertisement["extensions"][identity.EVM_ASSETS_EXTENSION]
    assert EvmAssetIdentity.model_validate(advertised) == asset
    plain = identity._advertisement("bb" * 32, _terms(manual["advertisement"]))  # noqa: SLF001
    assert identity.EVM_ASSETS_EXTENSION not in plain["extensions"]
    with pytest.raises(ProviderIdentityError):
        identity._advertisement(  # noqa: SLF001
            "bb" * 32, _terms(manual["advertisement"], evm_assets=(asset.model_dump(),))
        )


def test_funding_confirmations_are_always_advertised_and_zero_only_pays_lightning() -> None:
    manual, _event = _vectors()
    key = identity.FUNDING_CONFIRMATIONS_EXTENSION
    ad = manual["advertisement"]
    forward = ("btc-to-ln/v1",)
    for depth in (0, 1, 6):
        terms = _terms(ad, profiles=forward, funding_confirmations=depth)
        built = identity._advertisement("bb" * 32, terms)  # noqa: SLF001
        assert built["extensions"][key] == {"confirmations": depth}
    for profile in ("ln-to-btc/v1", "erc20-to-ln/v1", "ln-to-erc20/v1"):
        terms = _terms(ad, profiles=(profile,), funding_confirmations=1)
        assert identity._advertisement("bb" * 32, terms)["extensions"][key] == {  # noqa: SLF001
            "confirmations": 1
        }
        with pytest.raises(ProviderIdentityError):  # only the paying provider may take 0-conf risk
            identity._advertisement(  # noqa: SLF001
                "bb" * 32, _terms(ad, profiles=(profile,), funding_confirmations=0)
            )
    with pytest.raises(ProviderIdentityError):  # the vector also lists ln-to-btc/v1
        identity._advertisement("bb" * 32, _terms(ad, funding_confirmations=0))  # noqa: SLF001
    for depth in (-1, True, 1.0, 2**53):
        with pytest.raises(ProviderIdentityError):
            identity._advertisement(  # noqa: SLF001
                "bb" * 32, _terms(ad, profiles=forward, funding_confirmations=depth)
            )


def test_transport_work_is_advertised_only_when_required() -> None:
    manual, _event = _vectors()
    key = transport_pow.TRANSPORT_POW_EXTENSION
    plain = identity._advertisement("bb" * 32, _terms(manual["advertisement"]))  # noqa: SLF001
    assert key not in plain["extensions"]  # off: byte-identical to older announcements
    terms = _terms(manual["advertisement"], transport_pow_bits=16)
    required = identity._advertisement("bb" * 32, terms)  # noqa: SLF001
    assert required["extensions"][key] == {"bits": 16}
    assert transport_pow.requirement(required["extensions"]) == 16
    for bits in (-1, transport_pow.MAX_WORK_BITS + 1, True):
        with pytest.raises(ProviderIdentityError):
            identity._advertisement(  # noqa: SLF001
                "bb" * 32, _terms(manual["advertisement"], transport_pow_bits=bits)
            )
