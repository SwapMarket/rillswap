"""Explicit regtest historical receipt acquisition, NEVER completion authority.

No receipt, checkpoint, marker, wallet recognition or missing state establishes
destination spending-key custody. This read-only operation requires an explicit
independently established operator assertion, original encrypted journal anchor,
signed funding continuity, actual authorized claim bytes and successful source
debit. Returned receipts are copyable history, not durable release capabilities.
"""

from __future__ import annotations

import hashlib
import math
import time
from typing import TYPE_CHECKING, Annotated, Literal

from pydantic import Field, StringConstraints, field_validator
from rill_core.networks import REGTEST_CONSENSUS_PROFILE, require_funding_release
from rill_core.recovery.inspection import (
    inspect_recovery_selected_funding_context,
    inspect_recovery_successor,
)
from rill_core.settlement import (
    FundingOutput,
    UnilateralAuthorization,
    check_funding_binding_transaction,
    inspect_transaction_outputs,
    validate_cooperative_claim,
    validate_unilateral_spend,
)
from rill_core.wire.hashes import contract_hash
from rill_core.wire.messages import LnToBtcEconomics
from rill_core.wire.types import Hex32, NetworkIdentity, ScriptHex, StrictModel
from rill_provider.core_tx_bytes import CoreTransactionReader
from rill_provider.lnd_treasury_observation import LndTreasuryObserver

from rill_cli.age_container import MAX_CIPHERTEXT_BYTES, decrypt_verified_plaintext
from rill_cli.conversion_journal import ConversionReceipt, _read_private
from rill_cli.wallet_rpc import WalletRpc

if TYPE_CHECKING:
    from pathlib import Path

    from rill_crypto import Context

    from rill_cli.age_container import X25519Credentials
    from rill_cli.conversion_journal import ConversionJournal
    from rill_cli.reverse_conversion import ReverseExecutionConfig

MAX_ACQUISITION_SECONDS = 30
MAX_COMPONENT_SECONDS = 10
TAPROOT_SCRIPT_HEX_LENGTH = 68
HASH_HEX_LENGTH = 64


class ReverseReconciliationError(ValueError):
    """Unavailable evidence, never permission to retry, release or repair state."""


class DestinationCustody(StrictModel):
    """Trusted operator's independently established retained destination keys.

    This assertion must match the exact destination/network/named Core wallet.
    Never derive it from ismine, solvability, wallet-wide flags or a stored script
    pin. Public-only recognition is compatible with this assertion ONLY if the
    operator independently controls retained spending keys elsewhere. This is an
    operational premise, not cryptographic proof or a persisted upgrade marker.
    """

    network: NetworkIdentity
    script: ScriptHex
    core_wallet: Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9_-]{1,64}$")]
    destination_keys_controlled: Literal[True]

    @field_validator("destination_keys_controlled", mode="before")
    @classmethod
    def affirmative_keys(cls, value: object) -> object:
        """Missing, coerced or inferred custody grants no approval."""
        if value is not True:
            raise ValueError("independently established destination keys required")
        return value

    @field_validator("script")
    @classmethod
    def taproot_destination(cls, value: str) -> str:
        """Require the explicit pinned Taproot destination."""
        if len(value) != TAPROOT_SCRIPT_HEX_LENGTH or not value.startswith("5120"):
            raise ValueError("explicit Taproot destination required")
        return value


class BlockHint(StrictModel):
    """Explicit lookup coordinates, not proof of inclusion or discovery rights."""

    height: Annotated[int, Field(strict=True, ge=1, le=499_999_999)]
    block_hash: Hex32


def collect_conversion_receipt(  # noqa: PLR0913 - explicit original evidence inputs, no defaults learning authority
    journal: ConversionJournal,
    operation_id: str,
    *,
    config: ReverseExecutionConfig,
    credentials: X25519Credentials,
    crypto: Context,
    funding_recovery_path: Path,
    funding_attempt_id: str,
    binding_revision: int,
    funding_block: BlockHint,
    claim_txid: str,
    claim_path: Literal["cooperative", "unilateral"],
    custody: DestinationCustody,
    deadline_seconds: float = 30,
) -> ConversionReceipt:
    """Collect one original dispatched job's historical receipt without writes.

    Expired original approval/invoice timers do not prohibit historical reads.
    Unknown hints/state or missing custody cause no automatic migration, scan,
    provisioning, signing, payment, recovery writing or replacement session.
    Final source/block correspondence requires one common sampled Core tip; this
    conservatively refuses tip movement, not an atomic or reorg-proof snapshot.
    Generation detects observed concurrency, not restoring database and fence.
    The returned timestamp-free receipt must NOT be saved as release authority.
    """
    receipt = None
    try:
        receipt = _collect(
            journal,
            operation_id,
            config=config,
            credentials=credentials,
            crypto=crypto,
            funding_recovery_path=funding_recovery_path,
            funding_attempt_id=funding_attempt_id,
            binding_revision=binding_revision,
            funding_block=funding_block,
            claim_txid=claim_txid,
            claim_path=claim_path,
            custody=custody,
            deadline_seconds=deadline_seconds,
        )
    except Exception:  # noqa: BLE001 - detach credentials/recovery/transport/crypto diagnostics
        receipt = None
    if receipt is None:
        raise ReverseReconciliationError("historical conversion receipt unavailable")
    return receipt


def _collect(  # noqa: PLR0913, PLR0915 - cohesive evidence join, no effects or generic adapters
    journal: ConversionJournal,
    operation_id: str,
    *,
    config: ReverseExecutionConfig,
    credentials: X25519Credentials,
    crypto: Context,
    funding_recovery_path: Path,
    funding_attempt_id: str,
    binding_revision: int,
    funding_block: BlockHint,
    claim_txid: str,
    claim_path: Literal["cooperative", "unilateral"],
    custody: DestinationCustody,
    deadline_seconds: float,
) -> ConversionReceipt:
    if (
        type(deadline_seconds) not in (int, float)
        or not 0 < deadline_seconds <= MAX_ACQUISITION_SECONDS
        or not math.isfinite(deadline_seconds)
        or claim_path not in ("cooperative", "unilateral")
        or type(claim_txid) is not str
        or len(claim_txid) != HASH_HEX_LENGTH
        or any(c not in "0123456789abcdef" for c in claim_txid)
        or type(binding_revision) is not int
        or binding_revision < 0
        or not isinstance(custody, DestinationCustody)
        or not isinstance(funding_block, BlockHint)
    ):
        raise ReverseReconciliationError("explicit historical conversion inputs required")
    started_at, deadline = time.time(), time.monotonic() + deadline_seconds
    if not math.isfinite(started_at):
        raise ReverseReconciliationError("historical conversion interval unavailable")

    def remaining() -> float:
        value = deadline - time.monotonic()
        if not math.isfinite(value) or value <= 0:
            raise ReverseReconciliationError("historical conversion acquisition expired")
        return min(value, MAX_COMPONENT_SECONDS)

    query = journal.begin_capacity_query()
    job, authority = journal.status(operation_id), journal.authority
    prepared, request = job.prepared, job.request
    require_funding_release(authority.network)
    if (
        authority.network.name != "regtest"
        or authority.network.consensus_profile != REGTEST_CONSENSUS_PROFILE
        or job.state != "dispatched"
        or prepared is None
        or job.recovery_sha256 is None
        or custody.network != authority.network
        or custody.script != authority.treasury_script
        or custody.core_wallet != config.core_wallet
        or custody.destination_keys_controlled is not True
    ):
        raise ReverseReconciliationError(
            "original dispatched conversion and independent custody required"
        )
    initial_ciphertext = _read_private(
        journal.directory / "recovery" / (operation_id + ".age"), MAX_CIPHERTEXT_BYTES
    )
    if hashlib.sha256(initial_ciphertext).hexdigest() != job.recovery_sha256:
        raise ReverseReconciliationError("original encrypted checkpoint differs")
    initial = decrypt_verified_plaintext(
        initial_ciphertext, authority.network, credentials=credentials, crypto=crypto
    )
    candidate = decrypt_verified_plaintext(
        _read_private(funding_recovery_path, MAX_CIPHERTEXT_BYTES),
        authority.network,
        credentials=credentials,
        crypto=crypto,
    )
    inspect_recovery_successor(initial, candidate, authority.network, crypto=crypto)
    selected = inspect_recovery_selected_funding_context(
        candidate,
        authority.network,
        funding_attempt_id=funding_attempt_id,
        binding_revision=binding_revision,
        crypto=crypto,
    )
    terms, binding = selected.terms, selected.binding
    economics, invoice = terms.economics, terms.invoice_binding
    if (
        terms.profile_id != "ln-to-btc/v1"
        or not isinstance(economics, LnToBtcEconomics)
        or terms.network_identity != authority.network
        or terms.provider_identity_key != authority.provider_identity
        or terms.client_destination_script != authority.treasury_script
        or contract_hash(terms).hex() != prepared.contract_hash
        or invoice.payment_hash != prepared.payment_hash
        or invoice.bolt11_sha256 != prepared.invoice_sha256
        or int(invoice.amount_msat) != prepared.invoice_amount_msat
        or int(economics.nominal_payout_sat) != request.requested_payout_sat
        or int(economics.contract_amount_sat) - int(terms.max_claim_fee_sat)
        != prepared.minimum_net_output_sat
        or prepared.routing_fee_ceiling_msat > request.max_routing_fee_msat
    ):
        raise ReverseReconciliationError("funded recovery differs from original approval")
    remaining()
    core = CoreTransactionReader(
        port=config.core_port, cookie_path=config.core_cookie_path, network=authority.network
    )
    wallet = WalletRpc(
        port=config.core_port,
        cookie_path=config.core_cookie_path,
        wallet=config.core_wallet,
        network=authority.network,
    )
    payer = LndTreasuryObserver(
        host="127.0.0.1",
        port=config.lnd_port,
        tls_certificate_path=config.lnd_tls_root_path,
        read_macaroon_path=config.lnd_read_macaroon_path,
        network=authority.network,
        expected_node_pubkey=authority.source_node,
    )
    funding = core.observe_block_transaction(
        binding.funding_txid,
        block_height=funding_block.height,
        block_hash=funding_block.block_hash,
        deadline_seconds=remaining(),
    )
    check_funding_binding_transaction(funding.raw_transaction, binding, terms, keys=crypto)
    actual_funding = inspect_transaction_outputs(funding.raw_transaction).outputs[
        binding.contract_vout
    ]
    authorization = UnilateralAuthorization.from_terms(
        terms,
        FundingOutput(
            bytes.fromhex(binding.funding_txid),
            binding.contract_vout,
            actual_funding.value_sat,
            actual_funding.script_pubkey,
        ),
        "claim",
        keys=crypto,
    )
    history = wallet.observe_historical_wallet_output(
        claim_txid, bytes.fromhex(authority.treasury_script), deadline_seconds=remaining()
    )
    claim = core.observe_block_transaction(
        claim_txid,
        block_height=history.block_height,
        block_hash=history.block_hash,
        deadline_seconds=remaining(),
    )
    validated = (
        validate_cooperative_claim(claim.raw_transaction, authorization, verifier=crypto)
        if claim_path == "cooperative"
        else validate_unilateral_spend(claim.raw_transaction, authorization, verifier=crypto)
    )
    output = inspect_transaction_outputs(claim.raw_transaction).outputs[0]
    if (
        funding.configured_network != authority.network
        or claim.configured_network != authority.network
        or history.network != authority.network
        or validated.txid != claim_txid
        or history.txid != claim_txid
        or history.vout != 0
        or history.script_pubkey.hex() != authority.treasury_script
        or output.script_pubkey.hex() != authority.treasury_script
        or output.value_sat != history.value_sat
        or output.value_sat != actual_funding.value_sat - validated.fee_sat
        or funding.block_height > claim.block_height
    ):
        raise ReverseReconciliationError("authorized claim and historical destination differ")
    payment = payer.observe_completed_payment(
        prepared.payment_hash, prepared.invoice_amount_msat, deadline_seconds=remaining()
    )
    context = payment.context
    if (
        context.configured_network != authority.network
        or context.observed_node_pubkey != authority.source_node
        or context.observed_network_label != "regtest"
        or payment.payment_hash != prepared.payment_hash
        or payment.amount_msat != prepared.invoice_amount_msat
        or type(payment.routing_fee_msat) is not int
        or payment.routing_fee_msat < 0
    ):
        raise ReverseReconciliationError("successful source debit differs")
    debit = payment.amount_msat + payment.routing_fee_msat
    if (
        payment.routing_fee_msat
        > min(prepared.routing_fee_ceiling_msat, request.max_routing_fee_msat)
        or debit > request.max_source_debit_msat
        or max(0, debit - output.value_sat * 1000) > request.max_fee_msat
        or output.value_sat < max(prepared.minimum_net_output_sat, request.minimum_output_sat)
    ):
        raise ReverseReconciliationError("actual source debit or destination exceeds approval")
    blocks = {
        (funding.block_height, funding.block_hash),
        (claim.block_height, claim.block_hash),
        (context.before_tip.height, context.before_tip.block_hash),
        (context.after_tip.height, context.after_tip.block_hash),
    }
    final_tip = None
    depth = min(history.confirmations, claim.minimum_sampled_confirmations)
    for height, expected_hash in sorted(blocks):
        snapshot = core.observe_source(height, deadline_seconds=remaining())
        tip = (snapshot.tip_height, snapshot.tip_hash)
        if (
            snapshot.configured_network != authority.network
            or snapshot.genesis_hash != authority.network.genesis_hash
            or snapshot.source_height != height
            or snapshot.source_block_hash != expected_hash
            or (final_tip is not None and tip != final_tip)
        ):
            raise ReverseReconciliationError("source and contract chain observations contradict")
        final_tip = tip
        depth = min(depth, snapshot.tip_height - claim.block_height + 1)
    if depth < request.confirmation_blocks:
        raise ReverseReconciliationError("historical claim depth below approval")
    ended_at = time.time()
    final_query = journal.begin_capacity_query()
    if (
        journal.status(operation_id) != job
        or final_query.journal_id != query.journal_id
        or final_query.generation != query.generation
        or not math.isfinite(ended_at)
        or ended_at < started_at
    ):
        raise ReverseReconciliationError("conversion observations changed during acquisition")
    receipt = ConversionReceipt(
        source_node=authority.source_node,
        network=authority.network,
        payment_hash=payment.payment_hash,
        invoice_sha256=prepared.invoice_sha256,
        amount_msat=payment.amount_msat,
        routing_fee_msat=payment.routing_fee_msat,
        destination_txid=claim_txid,
        destination_vout=0,
        destination_script=authority.treasury_script,
        destination_value_sat=output.value_sat,
        confirmation_blocks=depth,
    )
    remaining()
    return receipt
