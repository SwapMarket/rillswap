"""Original owner orchestration; synthetic SDK/crypto except the explicit native case."""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import secrets
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from importlib import import_module
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, Mock

import pytest
from pyrage import x25519
from rill_core.wire.canonical import canonicalize
from rill_core.wire.hashes import client_acceptance_hash, contract_hash, provider_terms_hash
from rill_core.wire.messages import ClientAcceptance, ContractTerms, ProviderTerms
from rill_crypto import Context
from rill_provider.payment_dispatch_record import PaymentAuthority

from rill_cli import reverse_conversion as module
from rill_cli import swap_command as snapshots
from rill_cli.age_container import X25519Credentials, verify_export_ciphertext
from rill_cli.conversion_journal import (
    Allocation,
    ConversionJournal,
    ConversionRequest,
    SourceAuthority,
    SourceCredit,
    WalletAvailability,
)
from rill_cli.live_reverse_swap import ReverseSwapLimits, ReverseSwapOutcome
from rill_cli.publication import RecoveryPublicationError

PACKAGE = json.loads(
    (Path(__file__).parent / "fixtures/initial-ln-to-btc-no-prepayment-v1.json").read_bytes()
)
TERMS = ContractTerms.model_validate_json(canonicalize(PACKAGE["contract_terms"]))
NOW = 1_700_000_110
BOLT11 = "lnbcrt1syntheticownerinvoice"
LIMITS = ReverseSwapLimits(2000, 500, 500, 200, 250, 1000, 1)  # reserve <= claim fee cap
_UNLOCK = x25519.Identity.generate()
CREDENTIALS = X25519Credentials(str(_UNLOCK.to_public()), str(_UNLOCK))


class Harness:
    def __init__(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        self.clock = [100.0]
        self.wall = [NOW]
        monkeypatch.setattr(time, "time", lambda: self.wall[0])
        monkeypatch.setattr(time, "monotonic", lambda: self.clock[0])
        self.authority = SourceAuthority(
            source_node=TERMS.invoice_binding.payee_compressed_pubkey,
            network=TERMS.network_identity,
            source_epoch="a" * 64,
            exclusive_wallet=True,
            commitments_known=True,
            fixed_reserve_msat=1000,
            treasury_script="5120" + TERMS.provider_identity_key,
            provider_identity=TERMS.provider_identity_key,
        )
        directory = tmp_path / "journal"
        directory.mkdir(mode=0o700)
        self.journal = ConversionJournal.provision(
            directory, tmp_path / "source-owner.json", self.authority
        )
        self.credit = SourceCredit(
            payment_hash="c" * 64, invoice_sha256="d" * 64, amount_msat=200_000_000
        )
        self.request = ConversionRequest(
            operation_id="reverse_owner_01",
            allocations=(
                Allocation(payment_hash=self.credit.payment_hash, amount_msat=105_000_000),
            ),
            requested_payout_sat=100_000,
            minimum_output_sat=100_000,
            max_source_debit_msat=105_000_000,
            max_fee_msat=5_000_000,
            max_routing_fee_msat=1_000_000,
            confirmation_blocks=1,
            expires_at=NOW + 3600,
        )
        self.reservation = self.journal.reserve(
            self.request,
            credits=(self.credit,),
            availability=WalletAvailability(
                source_node=self.authority.source_node,
                network=self.authority.network,
                query=self.journal.begin_capacity_query(),
                observed_at=NOW,
                spendable_msat=250_000_000,
                commitments_known=True,
            ),
        )
        self.plain = json.loads(json.dumps(PACKAGE))
        self.plain["contract_terms"]["client_destination_script"] = self.authority.treasury_script
        self.plain["contract_terms"]["invoice_binding"]["bolt11_sha256"] = hashlib.sha256(
            BOLT11.encode()
        ).hexdigest()
        self.wallet = Mock()
        self.wallet.tip_height.return_value = 900
        self.payer = Mock()
        self.payer.pay.return_value = "IN_FLIGHT"
        self.decode = Mock()
        self.config = module.ReverseExecutionConfig(
            10009,
            tmp_path / "lnd.cert",
            tmp_path / "read.mac",
            tmp_path / "pay.mac",
            18443,
            tmp_path / "core.cookie",
            "owned-treasury",
        )
        self.encrypted: dict[bytes, bytes] = {}

        def encrypt(document: bytes, *_args: Any, **_kwargs: Any) -> bytes:  # noqa: ANN401 - instrument static inspection dependency
            ciphertext = b"synthetic-encrypted-" + hashlib.sha256(document).digest()
            self.encrypted[ciphertext] = document
            return ciphertext

        def verify(ciphertext: bytes, document: bytes, *_args: Any, **_kwargs: Any) -> object:  # noqa: ANN401 - synthetic readback, no crypto claim
            assert self.encrypted[ciphertext] == document
            return object()

        monkeypatch.setattr(module, "encrypt_verified_plaintext", encrypt)
        monkeypatch.setattr(module, "verify_export_ciphertext", verify)
        monkeypatch.setattr(module, "LndInvoiceDecoder", lambda **_kwargs: self.decode)
        monkeypatch.setattr(module, "WalletRpc", lambda **_kwargs: self.wallet)

        def pinned_payer(**kwargs: Any) -> object:  # noqa: ANN401 - concrete construction wiring
            assert kwargs["expected_payer"] == PaymentAuthority(
                self.authority.source_node, self.authority.network
            )
            return self.payer

        monkeypatch.setattr(module, "LndHoldPayer", pinned_payer)

    def owner(self) -> module._Invocation:
        wallet = module._DestinationWallet(  # noqa: SLF001 - focused original owner fault tests
            self.wallet, bytes.fromhex(self.authority.treasury_script)
        )
        wallet.tip_height()
        right = self.journal.invoke(self.reservation)
        return module._Invocation(  # noqa: SLF001 - original invocation owner under test
            self.journal,
            right,
            self.reservation,
            wallet,
            self.payer,
            LIMITS,
            CREDENTIALS,
            Mock(),
            3700,
        )

    def checkpoint(self, owner: module._Invocation) -> bytes:
        document = canonicalize(self.plain)
        assert owner.write_recovery(document, None) == document
        return document

    def pay(self, owner: module._Invocation, **updates: Any) -> str:  # noqa: ANN401 - malformed callback matrix
        assert owner.terms is not None
        arguments: dict[str, Any] = {
            "invoice_binding": owner.terms.invoice_binding,
            "min_final_expiry_height": 1130,
            "max_expiry_height": 1150,
            "fee_limit_sat": 1000,
            "deadline": 4000.0,
            "submission_allowed": lambda: True,
        } | updates
        return owner.pay(BOLT11, **arguments)


@pytest.fixture
def harness(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Harness:
    return Harness(tmp_path, monkeypatch)


def test_owner_durably_invokes_checkpoints_dispatches_and_never_completes(
    harness: Harness, monkeypatch: pytest.MonkeyPatch
) -> None:
    async def runner(_connection: object, **kwargs: Any) -> ReverseSwapOutcome:  # noqa: ANN401 - synthetic SDK boundary
        assert harness.journal.status(harness.request.operation_id).state == "invoked"
        assert kwargs["identity"] == harness.authority.provider_identity
        assert kwargs["network"] == harness.authority.network
        wallet = kwargs["wallet"]
        assert wallet.tip_height() == 900
        assert wallet.new_destination_script().hex() == harness.authority.treasury_script
        harness.checkpoint(kwargs["payer"])
        assert harness.journal.status(harness.request.operation_id).state == "prepared"
        harness.payer.pay.side_effect = lambda *_args, **_kwargs: (
            "IN_FLIGHT"
            if harness.journal.status(harness.request.operation_id).state == "dispatched"
            else "FAILED"
        )
        assert harness.pay(kwargs["payer"]) == "IN_FLIGHT"
        return ReverseSwapOutcome(
            "session", PACKAGE["contract_hash"], "e" * 64, "f" * 64, 100500, 500
        )

    monkeypatch.setattr(module, "run_reverse_swap", runner)
    outcome = asyncio.run(
        module.run_reserved_conversion(
            harness.journal,
            harness.reservation,
            Mock(),
            config=harness.config,
            limits=LIMITS,
            credentials=CREDENTIALS,
            crypto=Mock(),
        )
    )
    assert outcome.payout_sat == 100500  # contract value, NOT journal completion/net receipt
    assert harness.journal.status(harness.request.operation_id).state == "dispatched"
    harness.payer.pay.assert_called_once()
    assert harness.payer.pay.call_args.kwargs["deadline"] == 3700


@pytest.mark.parametrize(
    "fault",
    [
        "provider",
        "handshake",
        "destination",
        "payout",
        "birthday",
        "funded",
        "successor",
        "unknown_preimage",
        "dangerous",
        "expired_terms",
        "refund_delay",
    ],
)
def test_substituted_initial_document_never_prepares_or_pays(harness: Harness, fault: str) -> None:
    owner = harness.owner()
    terms = harness.plain["contract_terms"]
    if fault == "provider":
        terms["provider_identity_key"] = "b" * 64
    elif fault == "handshake":
        harness.plain["verification_context"]["handshake_init"][
            "expected_provider_identity_xonly_key"
        ] = "b" * 64
    elif fault == "destination":
        terms["client_destination_script"] = "5120" + "b" * 64
    elif fault == "payout":
        terms["economics"]["nominal_payout_sat"] = "99999"
    elif fault == "birthday":
        harness.plain["chain_scan_birthday_height"] = 901
    elif fault == "funded":
        harness.plain["funding_history"] = [{"unverified": True}]
    elif fault == "successor":
        harness.plain["extensions"] = {"late-state": True}
    elif fault == "unknown_preimage":
        harness.plain["monotonic_knowledge"]["preimage_known"] = False
    elif fault == "dangerous":
        harness.plain["monotonic_knowledge"]["dangerous_signature_issued"] = True
    elif fault == "expired_terms":
        terms["terms_expiry"] = NOW
    else:
        terms["refund_lock_height"] = 1099
    with pytest.raises((ValueError, TypeError)):
        harness.checkpoint(owner)
    assert harness.journal.status(harness.request.operation_id).state == "invoked"
    assert not list((harness.journal.directory / "recovery").iterdir())
    harness.payer.pay.assert_not_called()


@pytest.mark.native_crypto
@pytest.mark.skipif(
    os.environ.get("RILLSWAP_RUN_NATIVE_CRYPTO") != "1",
    reason="explicit native SDK owner conformance opt-in",
)
def test_actual_native_sdk_binds_fresh_quote_and_checkpoint_to_original_owner(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from rill_cli import age_container  # noqa: PLC0415
    from rill_cli import live_reverse_swap as reverse  # noqa: PLC0415

    harness = Harness(tmp_path, monkeypatch)
    # Existing untyped test scaffolding is loaded only for the opt-in case.
    # It is not a production API or a request to execute/modify old tests.
    native_sdk = import_module("test_reverse_sdk_lifetime").NativeSdk
    featured = import_module("test_reverse_fallback_publication")._featured  # noqa: SLF001 - signed handshake fixture helper
    original_check, original_draw = reverse._check_offer, secrets.token_bytes  # noqa: SLF001 - restore actual quote gate and fresh preimage
    with Context(library_path=os.environ["RILL_CRYPTO_LIBRARY"]) as crypto:
        fixture = native_sdk(crypto, tmp_path, monkeypatch)
        featured(fixture, monkeypatch)
        # The helper's static quote gate/preimage are not conformance evidence.
        # Restore actual validation and fresh draws; answer the actual request.
        monkeypatch.setattr(reverse, "_check_offer", original_check)
        monkeypatch.setattr(secrets, "token_bytes", original_draw)
        monkeypatch.setattr(
            module, "encrypt_verified_plaintext", age_container.encrypt_verified_plaintext
        )
        monkeypatch.setattr(
            module, "verify_export_ciphertext", age_container.verify_export_ciphertext
        )
        harness.wallet = fixture.wallet
        harness.payer.pay.return_value = "FAILED"
        harness.decode.decode.side_effect = lambda _invoice: fixture.terms.invoice_binding

        async def reply(envelope: object, kind: str) -> object:
            if kind != "terms_offer":
                return object()
            request = envelope.payload  # type: ignore[attr-defined]
            fixture.terms = fixture.terms.model_copy(
                update={
                    "client_destination_script": request["client_destination_script"],
                    "client_contract_compressed_key": request["client_contract_compressed_key"],
                    "recovery_authorization_xonly_key": request["recovery_authorization_xonly_key"],
                    "refund_lock_height": request["limits"]["min_refund_lock_height"],
                    "invoice_binding": fixture.terms.invoice_binding.model_copy(
                        update={"payment_hash": request["payment_hash"]}
                    ),
                    "timing_policy": fixture.terms.timing_policy.model_copy(
                        update={
                            "min_incoming_htlc_expiry_height": request["limits"][
                                "max_incoming_htlc_expiry_height"
                            ]
                        }
                    ),
                }
            )
            signed = ProviderTerms(
                contract_hash=contract_hash(fixture.terms).hex(),
                contract_terms=fixture.terms,
                handshake_hash=fixture.offer.terms.handshake_hash,
            )
            fixture.offer = fixture.offer.model_copy(
                update={
                    "terms": signed,
                    "provider_terms_signature": crypto.schnorr_sign(
                        (1).to_bytes(32, "big"), provider_terms_hash(signed), b"\x56" * 32
                    ).hex(),
                }
            )
            return SimpleNamespace(
                payload=fixture.offer.model_dump(mode="json"),
                message_id="55" * 32,
                contract_hash=signed.contract_hash,
            )

        fixture.session.reply_to = AsyncMock(side_effect=reply)
        with pytest.raises(module.ReverseConversionError):
            asyncio.run(
                module.run_reserved_conversion(
                    harness.journal,
                    harness.reservation,
                    Mock(),
                    config=harness.config,
                    limits=LIMITS,
                    credentials=fixture.credentials,
                    crypto=crypto,
                )
            )
        job = harness.journal.status(harness.request.operation_id)
        assert job.state == "dispatched"
        assert job.prepared is not None
        assert job.prepared.payment_hash == fixture.terms.invoice_binding.payment_hash
        assert job.prepared.payment_hash != TERMS.invoice_binding.payment_hash
        harness.payer.pay.assert_called_once()
        call = harness.payer.pay.call_args.kwargs
        assert call["max_expiry_height"] == 1000 + LIMITS.max_incoming_htlc_delay_blocks
        assert call["invoice_binding"] == fixture.terms.invoice_binding
        fixture.funding.assert_not_called()
        stored = (
            harness.journal.directory / "recovery" / (harness.request.operation_id + ".age")
        ).read_bytes()
        from rill_cli.age_container import _decrypt  # noqa: PLC0415 - exact test readback only

        plaintext = _decrypt(stored, fixture.credentials)
        value = json.loads(plaintext)
        assert (
            value["contract_terms"]["client_destination_script"]
            == harness.authority.treasury_script
        )
        assert value["contract_hash"] == job.prepared.contract_hash
        verify_export_ciphertext(
            stored,
            plaintext,
            harness.authority.network,
            credentials=fixture.credentials,
            crypto=crypto,
        )
        assert hashlib.sha256(stored).hexdigest() == job.recovery_sha256


@pytest.mark.parametrize(
    "field", ["max_expiry_height", "min_final_expiry_height", "fee_limit_sat", "invoice_binding"]
)
def test_payer_requires_exact_original_quote_arguments(harness: Harness, field: str) -> None:
    owner = harness.owner()
    harness.checkpoint(owner)
    assert owner.terms is not None
    bad = (
        owner.terms.invoice_binding.model_copy(update={"amount_msat": "1"})
        if field == "invoice_binding"
        else 999
    )
    with pytest.raises(module.ReverseConversionError, match="exact original"):
        harness.pay(owner, **{field: bad})
    assert harness.journal.status(harness.request.operation_id).state == "prepared"
    harness.payer.pay.assert_not_called()


def test_later_tip_cannot_refresh_original_maximum_expiry(harness: Harness) -> None:
    owner = harness.owner()
    harness.wallet.tip_height.return_value = 905
    assert owner.wallet.tip_height() == 905
    harness.checkpoint(owner)
    assert owner.max_expiry == 1150
    with pytest.raises(module.ReverseConversionError):
        harness.pay(owner, max_expiry_height=1155)
    harness.payer.pay.assert_not_called()


@pytest.mark.parametrize("phase", ["checkpoint", "dispatch"])
def test_expired_original_approval_retains_hold_and_never_delegates(
    harness: Harness, phase: str
) -> None:
    owner = harness.owner()
    if phase == "dispatch":
        harness.checkpoint(owner)
    harness.wall[0] = NOW + 3600
    with pytest.raises(module.ReverseConversionError, match="expired"):
        harness.checkpoint(owner) if phase == "checkpoint" else harness.pay(owner)
    harness.payer.pay.assert_not_called()


def test_concurrent_duplicate_pay_callbacks_delegate_only_once(harness: Harness) -> None:
    owner = harness.owner()
    harness.checkpoint(owner)
    gate = threading.Barrier(2)

    def pay() -> str:
        gate.wait()
        try:
            return harness.pay(owner)
        except module.ReverseConversionError:
            return "REFUSED"

    with ThreadPoolExecutor(max_workers=2) as pool:
        result = list(pool.map(lambda _: pay(), range(2)))
    assert sorted(result) == ["IN_FLIGHT", "REFUSED"]
    harness.payer.pay.assert_called_once()


def test_reopened_or_replayed_job_never_starts_new_sdk(
    harness: Harness, monkeypatch: pytest.MonkeyPatch
) -> None:
    harness.owner()
    opened = ConversionJournal.open(
        harness.journal.directory, harness.journal.source_fence, harness.authority
    )
    replay = opened.reserve(
        harness.request,
        credits=(harness.credit,),
        availability=WalletAvailability(
            source_node=harness.authority.source_node,
            network=harness.authority.network,
            query=opened.begin_capacity_query(),
            observed_at=NOW,
            spendable_msat=250_000_000,
            commitments_known=True,
        ),
    )
    runner = Mock()
    monkeypatch.setattr(module, "run_reverse_swap", runner)
    with pytest.raises(module.ReverseConversionError) as failure:
        asyncio.run(
            module.run_reserved_conversion(
                opened,
                replay,
                Mock(),
                config=harness.config,
                limits=LIMITS,
                credentials=CREDENTIALS,
                crypto=Mock(),
            )
        )
    assert failure.value.__cause__ is None
    assert failure.value.__context__ is None
    runner.assert_not_called()
    assert opened.status(harness.request.operation_id).state == "invoked"


@pytest.mark.parametrize("uncertain", [False, True])
def test_checkpoint_failure_never_grants_payment_or_republishes(
    harness: Harness, monkeypatch: pytest.MonkeyPatch, *, uncertain: bool
) -> None:
    owner = harness.owner()
    original = harness.journal.checkpoint

    def failing(*args: Any, **kwargs: Any) -> object:  # noqa: ANN401 - injected publication uncertainty
        if uncertain:
            original(*args, **kwargs)
        raise RuntimeError("SECRET_CANARY")

    monkeypatch.setattr(harness.journal, "checkpoint", failing)
    with pytest.raises(RuntimeError):
        harness.checkpoint(owner)
    assert owner.previous is None
    with pytest.raises(module.ReverseConversionError):
        owner.pay(
            BOLT11,
            invoice_binding=TERMS.invoice_binding,
            min_final_expiry_height=1130,
            max_expiry_height=1150,
            fee_limit_sat=1000,
            deadline=4000,
            submission_allowed=lambda: True,
        )
    monkeypatch.setattr(harness.journal, "checkpoint", original)
    with pytest.raises(module.ReverseConversionError):
        harness.checkpoint(owner)
    harness.payer.pay.assert_not_called()


def test_successor_acknowledgement_requires_exact_predecessor_and_successful_publication(
    harness: Harness, monkeypatch: pytest.MonkeyPatch
) -> None:
    owner = harness.owner()
    initial = harness.checkpoint(owner)
    successor = initial + b" "  # fake semantic transition, synthetic publisher only
    writer = Mock(side_effect=RuntimeError("SECRET_CANARY"))
    monkeypatch.setattr(module, "_write_recovery_snapshot", writer)
    with pytest.raises(module.ReverseConversionError):
        owner.write_recovery(successor, b"foreign")
    writer.assert_not_called()
    with pytest.raises(RuntimeError):
        owner.write_recovery(successor, initial)
    assert owner.previous == initial
    writer.side_effect = None
    assert owner.write_recovery(successor, initial) == successor
    assert owner.previous == successor
    with pytest.raises(module.ReverseConversionError):
        owner.write_recovery(initial, initial)


def test_actual_successor_publication_with_lost_acknowledgement_refuses_overwrite(
    harness: Harness,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    owner = harness.owner()
    initial = harness.checkpoint(owner)
    candidate = json.loads(initial)
    candidate["funding_history"] = [{"synthetic-binding": True}]
    successor = canonicalize(candidate)
    # Real durable publication and filename selection, synthetic static crypto.
    # Independent native coverage below establishes initial crypto validation;
    # this case establishes owner behavior after actual publication/ACK loss.
    monkeypatch.setattr(snapshots, "inspect_recovery_successor", Mock(return_value=object()))

    def encrypt(document: bytes, *_args: Any, **_kwargs: Any) -> bytes:  # noqa: ANN401 - synthetic static crypto only
        ciphertext = b"synthetic-successor-" + hashlib.sha256(document).digest()
        harness.encrypted[ciphertext] = document
        return ciphertext

    def verify(stored: bytes, document: bytes, *_args: Any, **_kwargs: Any) -> object:  # noqa: ANN401 - publication round-trip assertion
        assert harness.encrypted[stored] == document
        return object()

    monkeypatch.setattr(snapshots, "encrypt_verified_plaintext", encrypt)
    monkeypatch.setattr(snapshots, "verify_export_ciphertext", verify)
    real_writer = snapshots._write_recovery_snapshot  # noqa: SLF001 - real durable sibling publication

    def lost_ack(*args: Any, **kwargs: Any) -> None:  # noqa: ANN401 - exact post-publication failure
        real_writer(*args, **kwargs)
        raise RuntimeError("SECRET_CANARY")

    monkeypatch.setattr(module, "_write_recovery_snapshot", lost_ack)
    with pytest.raises(RuntimeError):
        owner.write_recovery(successor, initial)
    assert owner.path is not None
    sibling = owner.path.with_name(owner.path.name + ".funded")
    info, contents = sibling.stat(), sibling.read_bytes()
    assert owner.previous == initial
    assert harness.journal.status(harness.request.operation_id).state == "prepared"
    with pytest.raises(RecoveryPublicationError):
        owner.write_recovery(successor, initial)
    assert sibling.stat().st_ino == info.st_ino
    assert sibling.read_bytes() == contents
    assert owner.previous == initial
    assert harness.journal.status(harness.request.operation_id).state == "prepared"
    harness.payer.pay.assert_not_called()


def test_concurrent_initial_callbacks_acknowledge_only_one_checkpoint(harness: Harness) -> None:
    owner = harness.owner()
    gate = threading.Barrier(2)

    def write(_index: int) -> str:
        gate.wait()
        try:
            harness.checkpoint(owner)
        except module.ReverseConversionError:
            return "REFUSED"
        else:
            return "ACK"

    with ThreadPoolExecutor(max_workers=2) as pool:
        assert sorted(pool.map(write, range(2))) == ["ACK", "REFUSED"]
    assert len(list((harness.journal.directory / "recovery").iterdir())) == 1
    assert harness.journal.status(harness.request.operation_id).state == "prepared"


def test_locally_invalid_recovery_credentials_refuse_before_consuming_invocation(
    harness: Harness,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runner = Mock()
    monkeypatch.setattr(module, "run_reverse_swap", runner)
    with pytest.raises(module.ReverseConversionError) as failure:
        asyncio.run(
            module.run_reserved_conversion(
                harness.journal,
                harness.reservation,
                Mock(),
                config=harness.config,
                limits=LIMITS,
                credentials=X25519Credentials("SECRET_CANARY", "SECRET_CANARY"),
                crypto=Mock(),
            )
        )
    assert failure.value.__cause__ is None
    assert failure.value.__context__ is None
    assert "SECRET_CANARY" not in str(failure.value)
    runner.assert_not_called()
    assert harness.journal.status(harness.request.operation_id).state == "reserved"


@pytest.mark.native_crypto
@pytest.mark.skipif(
    os.environ.get("RILLSWAP_RUN_NATIVE_CRYPTO") != "1",
    reason="explicit native recovery verification opt-in",
)
def test_initial_journal_checkpoint_uses_real_encryption_static_inspection_and_readback(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Start with historical public inputs, then separately sign a new Taproot
    # package below; the existing signing vector/manifest remains unchanged.
    harness = Harness(tmp_path, monkeypatch)
    monkeypatch.undo()
    monkeypatch.setattr(time, "time", lambda: NOW)
    monkeypatch.setattr(time, "monotonic", lambda: 100.0)
    owner = harness.owner()
    identity = x25519.Identity.generate()
    owner.credentials = X25519Credentials(str(identity.to_public()), str(identity))
    with Context(library_path=os.environ["RILL_CRYPTO_LIBRARY"]) as crypto:
        owner.crypto = crypto
        # A separately signed test-time package, not a rewritten historical
        # vector. Changing destination changes the contract/context signatures.
        value = json.loads(json.dumps(PACKAGE))
        value["contract_terms"]["client_destination_script"] = harness.authority.treasury_script
        terms = ContractTerms.model_validate_json(canonicalize(value["contract_terms"]))
        value["contract_hash"] = contract_hash(terms).hex()
        context = value["verification_context"]
        init, accept = context["handshake_init"], context["handshake_accept"]
        assert crypto.public_key((1).to_bytes(32, "big"))[1:].hex() == terms.provider_identity_key
        assert (
            crypto.public_key((8).to_bytes(32, "big"))[1:].hex() == init["client_session_xonly_key"]
        )
        provider = ProviderTerms(
            contract_hash=value["contract_hash"],
            contract_terms=terms,
            handshake_hash=context["handshake_hash"],
        )
        client = ClientAcceptance(
            contract_hash=value["contract_hash"],
            handshake_hash=context["handshake_hash"],
            session_id=init["session_id"],
            client_session_xonly_key=init["client_session_xonly_key"],
            provider_session_xonly_key=accept["provider_session_xonly_key"],
        )
        context["provider_terms_signature"] = crypto.schnorr_sign(
            (1).to_bytes(32, "big"), provider_terms_hash(provider), b"\x55" * 32
        ).hex()
        context["client_acceptance_signature"] = crypto.schnorr_sign(
            (8).to_bytes(32, "big"), client_acceptance_hash(client), b"\x56" * 32
        ).hex()
        document = canonicalize(value)
        assert owner.write_recovery(document, None) == document
        assert owner.path is not None
        inspection = verify_export_ciphertext(
            owner.path.read_bytes(),
            document,
            harness.authority.network,
            credentials=owner.credentials,
            crypto=crypto,
        )
        assert inspection.profile_id == "ln-to-btc/v1"
        assert inspection.recorded_binding_count == 0
    assert harness.journal.status(harness.request.operation_id).state == "prepared"
    harness.payer.pay.assert_not_called()
