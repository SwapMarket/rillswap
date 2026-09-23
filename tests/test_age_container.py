from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path

import pyrage
import pytest
from pyrage import x25519
from rill_core.wire.canonical import canonicalize
from rill_core.wire.hashes import funding_binding_hash
from rill_core.wire.messages import FundingBinding
from rill_core.wire.types import NetworkIdentity

from rill_cli import age_container
from rill_cli.age_container import (
    PassphraseCredentials,
    RecoveryContainerError,
    X25519Credentials,
    validate_age_profile,
)


def _b64(length: int) -> bytes:
    return base64.b64encode(bytes(length)).rstrip(b"=")


def _synthetic_scrypt_header(work: bytes) -> bytes:
    return (
        b"age-encryption.org/v1\n-> scrypt "
        + _b64(16)
        + b" "
        + work
        + b"\n"
        + _b64(32)
        + b"\n--- "
        + _b64(32)
        + b"\n"
        + bytes(16)
        + b"ciphertext"
    )


def test_age_x25519_ciphertexts_allow_bounded_grease_and_reject_other_modes() -> None:
    identity = x25519.Identity.generate()
    ciphertext = pyrage.encrypt(b"public test data", [identity.to_public()])
    validate_age_profile(ciphertext, "X25519")
    with pytest.raises(RecoveryContainerError):
        validate_age_profile(ciphertext, "scrypt")
    assert pyrage.decrypt(ciphertext, [identity]) == b"public test data"


def test_scrypt_header_is_bounded_before_decryption(monkeypatch: pytest.MonkeyPatch) -> None:
    called = False

    def forbidden_decrypt(_ciphertext: bytes, _password: str) -> bytes:
        nonlocal called
        called = True
        raise AssertionError("native KDF must not be invoked")

    monkeypatch.setattr(age_container.passphrase, "decrypt", forbidden_decrypt)
    validate_age_profile(_synthetic_scrypt_header(b"19"), "scrypt")
    for work in (b"20", b"999999999999999999999", b"019", b"0", b"-1", b"1.5", b"18 "):
        ciphertext = _synthetic_scrypt_header(work)
        with pytest.raises(RecoveryContainerError):
            age_container.inspect_container(
                ciphertext,
                object(),  # type: ignore[arg-type]
                credentials=PassphraseCredentials("never log this password"),
                crypto=object(),  # type: ignore[arg-type]
            )
        assert not called


def test_passphrase_export_fails_before_any_kdf_even_for_valid_input(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def forbidden_encrypt(_plaintext: bytes, _password: str) -> bytes:
        raise AssertionError("unbounded passphrase export must not call pyrage")

    monkeypatch.setattr(age_container.passphrase, "encrypt", forbidden_encrypt)
    # Validation must fail before the export backend; the public entry point
    # catches all secret-bearing errors without exposing a context or cause.
    with pytest.raises(RecoveryContainerError) as error:
        age_container.encrypt_verified_plaintext(
            b"{}",
            object(),  # type: ignore[arg-type]
            credentials=PassphraseCredentials("do not log"),
            crypto=object(),  # type: ignore[arg-type]
        )
    assert error.value.__context__ is None
    assert error.value.__cause__ is None


def test_selected_binding_projection_bounds_plaintext_and_redacts_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    expected = b"synthetic canonical plaintext handled by core"
    network = NetworkIdentity.model_validate(
        json.loads((Path(__file__).parent / "fixtures" / "initial-btc-to-ln-v1.json").read_text())[
            "network_identity"
        ]
    )
    credentials = PassphraseCredentials("test-only password")
    selected = object()
    observed: list[tuple[bytes, str, int]] = []

    def project(
        plaintext: bytes,
        _network: NetworkIdentity,
        *,
        funding_attempt_id: str,
        binding_revision: int,
        crypto: object,
    ) -> object:
        assert crypto is selected
        observed.append((plaintext, funding_attempt_id, binding_revision))
        return selected

    monkeypatch.setattr(age_container, "_decrypt", lambda *_args: expected)
    monkeypatch.setattr(age_container, "inspect_recovery_selected_funding_binding", project)
    assert (
        age_container.inspect_container_selected_funding_binding(
            b"test ciphertext",
            network,
            credentials=credentials,
            funding_attempt_id="11" * 32,
            binding_revision=1,
            crypto=selected,  # type: ignore[arg-type]
        )
        is selected
    )
    assert observed == [(expected, "11" * 32, 1)]

    monkeypatch.setattr(
        age_container, "_decrypt", lambda *_args: b"x" * (age_container.MAX_PLAINTEXT_BYTES + 1)
    )
    with pytest.raises(
        RecoveryContainerError, match="recovery decryption or static inspection failed"
    ):
        age_container.inspect_container_selected_funding_binding(
            b"test ciphertext",
            network,
            credentials=credentials,
            funding_attempt_id="11" * 32,
            binding_revision=1,
            crypto=selected,  # type: ignore[arg-type]
        )
    assert len(observed) == 1

    def fail(*_args: object, **_kwargs: object) -> object:
        raise RuntimeError("secret-bearing failure")

    monkeypatch.setattr(age_container, "_decrypt", fail)
    with pytest.raises(
        RecoveryContainerError, match="recovery decryption or static inspection failed"
    ) as error:
        age_container.inspect_container_selected_funding_binding(
            b"test ciphertext",
            network,
            credentials=credentials,
            funding_attempt_id="11" * 32,
            binding_revision=1,
            crypto=selected,  # type: ignore[arg-type]
        )
    assert error.value.__cause__ is None
    assert error.value.__context__ is None
    assert "secret-bearing" not in repr(error.value)

    monkeypatch.setattr(age_container, "_decrypt", lambda *_args: expected)
    monkeypatch.setattr(age_container, "inspect_recovery_selected_funding_context", fail)
    with pytest.raises(
        RecoveryContainerError, match="recovery decryption or static inspection failed"
    ) as error:
        age_container.inspect_container_selected_funding_context(
            b"test ciphertext",
            network,
            credentials=credentials,
            funding_attempt_id="11" * 32,
            binding_revision=1,
            crypto=selected,  # type: ignore[arg-type]
        )
    assert error.value.__cause__ is None
    assert error.value.__context__ is None
    assert "secret-bearing" not in repr(error.value)


@pytest.mark.native_crypto
@pytest.mark.skipif(
    not os.environ.get("RILL_CRYPTO_LIBRARY"),
    reason="set RILL_CRYPTO_LIBRARY for selected signed binding age interoperability",
)
def test_native_age_selected_binding_is_a_public_candidate_not_live_funding() -> None:
    from rill_crypto import Context  # noqa: PLC0415

    package = json.loads(
        (Path(__file__).parent / "fixtures" / "initial-btc-to-ln-v1.json").read_text()
    )
    context = package["verification_context"]
    network = NetworkIdentity.model_validate_json(json.dumps(package["network_identity"]))
    session_secret = (2).to_bytes(32, "big")  # Pinned test-only session key.
    binding = FundingBinding.model_validate_json(
        json.dumps(
            {
                "contract_hash": package["contract_hash"],
                "funding_attempt_id": "cc" * 32,
                "binding_revision": 0,
                "funder_role": "client",
                "lineage_anchor_txid": "dd" * 32,
                "lineage_anchor_vout": 1,
                "funding_txid": "aa" * 32,
                "contract_vout": 0,
                "contract_value_sat": package["contract_terms"]["economics"]["contract_amount_sat"],
                "contract_script_pubkey": package["taproot_contract"]["script_pubkey"],
                "replaces_txid": None,
                "created_at": 1700000200,
            }
        )
    )
    with Context(library_path=os.environ["RILL_CRYPTO_LIBRARY"]) as crypto:
        assert crypto.public_key(session_secret)[1:].hex() == context["client_session_xonly_key"]
        signature = crypto.schnorr_sign(session_secret, funding_binding_hash(binding), b"\x33" * 32)
        package["funding_history"].append(
            {
                "binding": binding.model_dump(mode="json"),
                "funder_session_signature": signature.hex(),
            }
        )
        plaintext = canonicalize(package)
        identity = x25519.Identity.generate()
        ciphertext = pyrage.encrypt(plaintext, [identity.to_public()])
        credentials = X25519Credentials(str(identity.to_public()), str(identity))
        selected = age_container.inspect_container_selected_funding_binding(
            ciphertext,
            network,
            credentials=credentials,
            funding_attempt_id="cc" * 32,
            binding_revision=0,
            crypto=crypto,
        )
        assert selected == binding
        assert package["user_secret"]["contract_secret_key"] not in repr(selected)
        context_selected = age_container.inspect_container_selected_funding_context(
            ciphertext,
            network,
            credentials=credentials,
            funding_attempt_id="cc" * 32,
            binding_revision=0,
            crypto=crypto,
        )
        assert context_selected.binding == selected
        assert context_selected.terms.network_identity == network
        assert package["user_secret"]["contract_secret_key"] not in repr(context_selected)
        with pytest.raises(
            RecoveryContainerError, match="recovery decryption or static inspection failed"
        ):
            age_container.inspect_container_selected_funding_binding(
                ciphertext,
                network,
                credentials=credentials,
                funding_attempt_id="cc" * 32,
                binding_revision=1,
                crypto=crypto,
            )


@pytest.mark.parametrize(
    "alteration",
    [
        lambda value: b"-----BEGIN AGE ENCRYPTED FILE-----\n" + value,
        lambda value: value.replace(b"age-encryption.org/v1\n", b"age-encryption.org/v2\n", 1),
        lambda value: value.replace(b"age-encryption.org/v1\n", b"age-encryption.org/v1\r\n", 1),
        lambda value: value.replace(b"-> X25519 ", b"-> scrypt ", 1),
        lambda value: value.replace(b"-> X25519 ", b"-> X25519 !!!!", 1),
        lambda value: value.replace(
            b"-> X25519 ", b"-> X25519 A\n" + _b64(32) + b"\n-> X25519 ", 1
        ),
        lambda value: value.replace(b"--- ", b"--- incorrect ", 1),
        lambda value: value[:16],
        lambda _value: b"x" * (age_container.MAX_CIPHERTEXT_BYTES + 1),
    ],
)
def test_invalid_or_mixed_age_headers_fail_before_decryption(alteration: object) -> None:
    identity = x25519.Identity.generate()
    ciphertext = pyrage.encrypt(b"test data", [identity.to_public()])
    modified = alteration(ciphertext)  # type: ignore[operator]
    with pytest.raises(RecoveryContainerError):
        validate_age_profile(modified, "X25519")


def test_unknown_stanzas_and_scrypt_grease_mix_are_not_accepted() -> None:
    scrypt = _synthetic_scrypt_header(b"19")
    grease = b"-> #grease-grease\n\n"
    with pytest.raises(RecoveryContainerError):
        validate_age_profile(scrypt.replace(b"--- ", grease + b"--- ", 1), "scrypt")
    unknown = scrypt.replace(b"-> scrypt ", b"-> plugin ", 1)
    with pytest.raises(RecoveryContainerError):
        validate_age_profile(unknown, "scrypt")


def test_x25519_profile_allows_bounded_grease_but_never_a_second_recipient() -> None:
    identity = x25519.Identity.generate()
    original = pyrage.encrypt(b"synthetic", [identity.to_public()])
    native_line = next(line for line in original.split(b"\n") if line.startswith(b"-> X25519 "))
    native_body = original.split(native_line + b"\n", 1)[1].split(b"\n", 1)[0]
    native_stanza = native_line + b"\n" + native_body + b"\n"
    extra = b"-> #fixture-grease\n" + base64.b64encode(bytes(48)) + b"\n\n"
    # The MAC is intentionally unchanged: preflight checks structure, not
    # authentication; pyrage must still reject a tampered header afterward.
    before = original.replace(native_stanza, extra + native_stanza, 1)
    after = original.replace(b"--- ", extra + b"--- ", 1)
    validate_age_profile(before, "X25519")
    validate_age_profile(after, "X25519")
    with pytest.raises(RecoveryContainerError):
        validate_age_profile(original.replace(b"--- ", native_stanza + b"--- ", 1), "X25519")
    with pytest.raises(RecoveryContainerError):
        validate_age_profile(original.replace(b"--- ", extra * 5 + b"--- ", 1), "X25519")
    with pytest.raises(RecoveryContainerError):
        validate_age_profile(original.replace(b"--- ", b"-> plugin unknown\n\n--- ", 1), "X25519")


def test_age_profile_rejects_noncanonical_base64_and_oversized_header() -> None:
    identity = x25519.Identity.generate()
    original = pyrage.encrypt(b"synthetic", [identity.to_public()])
    encoded = base64.b64encode(bytes(1025)).rstrip(b"=")
    oversized_body = b"\n".join(encoded[index : index + 64] for index in range(0, len(encoded), 64))
    for injected in (
        b"-> #fixture-grease\nAA==\n",
        b"-> #fixture-grease\n" + oversized_body + b"\n",
        b"-> #fixture-grease " + b"x" * 250 + b"\n\n",
        b"-> #fixture-grease\n" + b"A" * 8192 + b"\n",
    ):
        with pytest.raises(RecoveryContainerError):
            validate_age_profile(original.replace(b"--- ", injected + b"--- ", 1), "X25519")


def test_wrong_recipient_is_refused_before_exporting_ciphertext() -> None:
    first, second = x25519.Identity.generate(), x25519.Identity.generate()
    assert str(first.to_public()) != str(second.to_public())
    credentials = X25519Credentials(str(first.to_public()), str(second))
    ciphertext = pyrage.encrypt(b"public test", [first.to_public()])
    with pytest.raises(RecoveryContainerError):
        age_container.inspect_container(
            ciphertext,
            object(),  # type: ignore[arg-type]
            credentials=credentials,
            crypto=object(),  # type: ignore[arg-type]
        )


@pytest.mark.native_crypto
@pytest.mark.skipif(
    not os.environ.get("RILL_CRYPTO_LIBRARY"),
    reason="set RILL_CRYPTO_LIBRARY to verify pinned Go scrypt fixture with native crypto",
)
def test_independent_go_scrypt_fixture_decrypts_with_native_inspection(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from rill_crypto import Context  # noqa: PLC0415

    fixtures = Path(__file__).parent / "fixtures"
    manifest = json.loads((fixtures / "manifest.json").read_text())
    ciphertext = (fixtures / manifest["scrypt_fixture"]).read_bytes()
    assert hashlib.sha256(ciphertext).hexdigest() == manifest["scrypt_sha256"]
    package = json.loads((fixtures / manifest["ln_fixture"]).read_bytes())
    network = NetworkIdentity.model_validate(package["network_identity"])
    password = manifest["scrypt_passphrase"]

    with Context(library_path=os.environ["RILL_CRYPTO_LIBRARY"]) as crypto:
        report = age_container.inspect_container(
            ciphertext, network, credentials=PassphraseCredentials(password), crypto=crypto
        )
        assert report.profile_id == "ln-to-btc/v1"
        assert report.recorded_binding_count == 0
        assert "export durability, age decryptability, and snapshot freshness" in report.unproven
        for altered_password in ("wrong", ""):
            with pytest.raises(RecoveryContainerError) as error:
                age_container.inspect_container(
                    ciphertext,
                    network,
                    credentials=PassphraseCredentials(altered_password),
                    crypto=crypto,
                )
            assert error.value.__cause__ is None
            assert error.value.__context__ is None
            assert password not in str(error.value)

        def forbidden_encrypt(_plaintext: bytes, _password: str) -> bytes:
            raise AssertionError("unbounded passphrase KDF must not run")

        monkeypatch.setattr(age_container.passphrase, "encrypt", forbidden_encrypt)
        with pytest.raises(RecoveryContainerError):
            age_container.encrypt_verified_plaintext(
                canonicalize(package),
                network,
                credentials=PassphraseCredentials(password),
                crypto=crypto,
            )
