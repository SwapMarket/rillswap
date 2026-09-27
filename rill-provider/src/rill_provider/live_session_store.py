"""Authoritative single-owner RS-001 handshake session store.

This is the only provider store whose rows may authorize exposing a
handshake_accept or admitting a handshake_confirm. Its guarantees are
conditional on a deployment fact it cannot verify: the database and its owner
lock live on an explicitly provisioned volume OUTSIDE the application's backup
and restore domain, used by exactly one host. The operator attests to that at
provisioning time.

What it enforces locally:
- explicit provisioning only; absent, partial, foreign, or newer files refuse;
- one lifetime exclusive owner (flock on a stable lock inode, no takeover);
- a generation counter bumped per owner and checked in every write;
- copied or file-restored databases (different inode) refuse to open;
- the exact accept bytes are durably committed before they may be exposed;
- confirm admission requires the full static transcript over those bytes.

It does NOT detect an in-place rollback of the authoritative volume, a clone
on another host, or authorize any economic effect. Confirmation grants no
funding, payment, or claim authority.
"""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
import re
import secrets
import sqlite3
import stat
import time
import uuid
from collections.abc import Callable
from contextlib import contextmanager, suppress
from dataclasses import dataclass, replace
from pathlib import Path
from typing import TYPE_CHECKING, Any, Protocol, Self, cast

import pyrage  # type: ignore[import-untyped]
from pyrage import x25519
from rill_core.settlement import (
    CooperativeClaimPlan,
    FundingOutput,
    UnilateralAuthorization,
    build_cooperative_claim,
    finalize_cooperative_claim,
    reconstruct_taproot_contract,
)
from rill_core.wire import verify_static_handshake_accept, verify_static_handshake_transcript
from rill_core.wire.canonical import canonicalize, parse_json_strict, parse_model_json
from rill_core.wire.cooperative_messages import (
    CooperativeClaimDeclined,
    CooperativeClaimPropose,
    CooperativeClaimSigned,
    check_cooperative_action_context,
    parse_cooperative_payload,
)
from rill_core.wire.envelope_authentication import verify_static_signed_envelope
from rill_core.wire.hashes import (
    COOPERATIVE_CLAIM_FEATURE,
    EPOCH_SESSION_FEATURE,
    contract_hash,
    funding_binding_hash,
    handshake_hash,
    handshake_init_hash,
    unsigned_envelope_hash,
)
from rill_core.wire.messages import (
    Envelope,
    FundingBinding,
    HandshakeAccept,
    HandshakeAcceptPayload,
    HandshakeInit,
    require_supported_contract_features,
)
from rill_core.wire.quotes import TermsOfferPayload
from rill_core.wire.settlement_messages import FundingBindingPayload, TermsAcceptPayload
from rill_core.wire.types import NetworkIdentity

from rill_provider._nip59_receive import _decode_gift_wrap_candidate
from rill_provider._nip59_send import _wrap_envelope
from rill_provider.handshake_store import HandshakePolicy, _expected, _features, _require_policy
from rill_provider.issuance_reservation import _policy_bytes
from rill_provider.payment_dispatch_record import PaymentAuthority, bound_payer

if TYPE_CHECKING:
    from collections.abc import Iterator
    from os import PathLike

    from rill_core.settlement.taproot import TaprootKeyOperations
    from rill_core.wire.envelope_authentication import EnvelopeSchnorrVerifier
    from rill_core.wire.messages import ContractTerms
    from rill_crypto import Context
    from rill_crypto.binding import MusigAttempt

    from rill_provider.handshake_custody_offline import CustodyPublicKeys
    from rill_provider.provider_identity import ProviderIdentity

APPLICATION_ID = 0x524C5331  # RLS1, distinct from all diagnostic stores.
SCHEMA_VERSION = 13  # v8-v12 upgrade on acquire; v5-v7 need explicit upgrade; v1-v4 refused.
CONTRACT_KEY_RECORD_KIND = "rillswap-provider-contract-key"
OPEN_PHASES = ("CONFIRMED", "ACCEPTED")  # sessions that may still send requests
SWAP_TRANSITIONS = frozenset(
    {
        ("ACCEPTED", "FAILED"),  # never funded before the payment deadline
        ("FUNDING_SEEN", "PAYING"),
        ("FUNDING_SEEN", "FAILED"),
        ("PAYING", "PAID"),
        ("PAYING", "FAILED"),
        ("PAID", "CLAIMING"),
        ("CLAIMING", "CLAIMED"),
        ("CLAIMING", "LOST"),  # the client's refund spent the contract; no claim confirmed
    }
)
# LN to BTC (RS-004): the provider funds after the hold invoice is accepted and
# settles it with the preimage the client's claim reveals, or refunds.
REVERSE_SWAP_TRANSITIONS = frozenset(
    {
        ("ACCEPTED", "LN_HELD"),  # every HTLC accepted, amount and expiry checked
        ("ACCEPTED", "ABORTED"),  # hold canceled or expired before funding
        ("LN_HELD", "FUNDING_SENT"),  # the one funding grant: signed funding recorded
        ("LN_HELD", "ABORTED"),  # hold no longer accepted, or the window closed
        ("FUNDING_SENT", "FUNDED"),
        ("FUNDING_SENT", "SETTLED"),  # a claim revealed the preimage before our depth check
        ("FUNDED", "SETTLED"),
        ("FUNDED", "REFUNDING"),  # past the refund lock, still unspent: refund broadcast
        ("REFUNDING", "SETTLED"),  # the claim won the race: settle, the hold pays for it
        ("REFUNDING", "REFUNDED"),  # refund at depth, hold canceled
    }
)
REVERSE_STATES = (
    "LN_HELD",
    "FUNDING_SENT",
    "FUNDED",
    "SETTLED",
    "REFUNDING",
    "REFUNDED",
    "ABORTED",
)
CLIENT_REQUEST_TYPES = ("quote_request", "terms_accept", "funding_binding")
SWAP_COLUMNS = (
    "session_id, contract_hash, terms_offer, terms_accept, state, funding_binding, "
    "preimage, claim_txid"
)
FIRST_REQUEST_SEQUENCE = 2  # RS-001: first client message after the confirm
MAX_REQUESTS_PER_SESSION = 16  # further requests are refused unanswered
DEFAULT_MAX_SESSIONS = 1000  # live (unexpired) sessions
DEFAULT_MAX_TOMBSTONES = 1_000_000  # permanent expired-session IDs (~100 bytes each)
DEFAULT_MAX_ACTIVE_RESERVATIONS = 4  # unreleased firm offers and swaps (financial exposure)
DEFAULT_NEW_SESSIONS_PER_MINUTE = 60  # global admission rate; known sessions exempt
MAX_DOCUMENT_BYTES = 65_536
MAX_CHALLENGE_TRIES = 4
MAX_LABEL_CHARS = 256
HEX32 = re.compile(r"[0-9a-f]{64}\Z")
LOCK_SUFFIX = ".owner-lock"
MAX_OUTER_EVENT_BYTES = 128 * 1024
COMPRESSED_KEY_BYTES = 33
KEY_RECORD_KIND = "rill-provider/live-session-key/v1"
EPOCH_RECORD_KIND = "rill-provider/epoch-inbox-key/v1"
MAX_ADVERTISED_EPOCHS = 4  # RS-005 epoch_inbox_xonly_keys maximum
MAX_INSPECTION_PAGE = 1000
SWAPS_V9_SCHEMA = (
    "CREATE TABLE swaps (session_id TEXT PRIMARY KEY, contract_hash TEXT NOT NULL UNIQUE, "
    "terms_offer BLOB NOT NULL, terms_accept BLOB NOT NULL, state TEXT NOT NULL CHECK "
    "(state IN ('ACCEPTED', 'FUNDING_SEEN', 'PAYING', 'PAID', 'FAILED', 'CLAIMING', "
    "'CLAIMED')), funding_binding BLOB, preimage TEXT, claim_txid TEXT, claim_tx BLOB, "
    "updated_at INTEGER NOT NULL)"
)
# v10: LOST is terminal for a CLAIMING swap whose contract output was spent on
# the confirmed chain by something other than a recorded claim attempt (the
# client's refund) and stayed spent for refund_resolution_confirmations
# blocks. outpoint_spent_height/block are the tip height and hash at which
# that spend was first observed (the anchor must stay on the active chain);
# NULL while the output is unspent or a recorded attempt is mined.
SWAPS_V10_SCHEMA = (
    "CREATE TABLE swaps (session_id TEXT PRIMARY KEY, contract_hash TEXT NOT NULL UNIQUE, "
    "terms_offer BLOB NOT NULL, terms_accept BLOB NOT NULL, state TEXT NOT NULL CHECK "
    "(state IN ('ACCEPTED', 'FUNDING_SEEN', 'PAYING', 'PAID', 'FAILED', 'CLAIMING', "
    "'CLAIMED', 'LOST')), funding_binding BLOB, preimage TEXT, claim_txid TEXT, claim_tx BLOB, "
    "updated_at INTEGER NOT NULL, outpoint_spent_height INTEGER "
    "CHECK (outpoint_spent_height > 0), outpoint_spent_block TEXT "
    "CHECK ((outpoint_spent_block IS NULL) = (outpoint_spent_height IS NULL)))"
)
# v11 adds the LN to BTC states and the provider's own funding and refund
# transactions (RS-004): funding_* is the signed funding the provider
# broadcast, refund_* its refund spend, spend_scan_height the last block
# scanned for a client claim spending the contract.
SWAPS_SCHEMA = (
    "CREATE TABLE swaps (session_id TEXT PRIMARY KEY, contract_hash TEXT NOT NULL UNIQUE, "
    "terms_offer BLOB NOT NULL, terms_accept BLOB NOT NULL, state TEXT NOT NULL CHECK "
    "(state IN ('ACCEPTED', 'FUNDING_SEEN', 'PAYING', 'PAID', 'FAILED', 'CLAIMING', "
    "'CLAIMED', 'LOST', 'LN_HELD', 'FUNDING_SENT', 'FUNDED', 'SETTLED', 'REFUNDING', "
    "'REFUNDED', 'ABORTED')), funding_binding BLOB, preimage TEXT, claim_txid TEXT, "
    "claim_tx BLOB, updated_at INTEGER NOT NULL, outpoint_spent_height INTEGER "
    "CHECK (outpoint_spent_height > 0), outpoint_spent_block TEXT "
    "CHECK ((outpoint_spent_block IS NULL) = (outpoint_spent_height IS NULL)), "
    "funding_txid TEXT, funding_vout INTEGER CHECK (funding_vout >= 0), funding_tx BLOB, "
    "refund_txid TEXT, refund_tx BLOB, spend_scan_height INTEGER CHECK (spend_scan_height > 0), "
    "CHECK ((funding_txid IS NULL) = (funding_tx IS NULL) AND "
    "(funding_txid IS NULL) = (funding_vout IS NULL)), "
    "CHECK ((refund_txid IS NULL) = (refund_tx IS NULL)))"
)
SCHEMA_V5 = (
    (
        "CREATE TABLE meta (singleton INTEGER PRIMARY KEY CHECK (singleton = 1), "
        "schema_version INTEGER NOT NULL, store_uuid TEXT NOT NULL, network_jcs BLOB NOT NULL, "
        "provider_identity TEXT NOT NULL, policy_jcs BLOB NOT NULL, authority_jcs BLOB NOT NULL, "
        "db_inode INTEGER NOT NULL, lock_inode INTEGER NOT NULL, generation INTEGER NOT NULL, "
        "custody_recipient TEXT NOT NULL)"
    ),
    (
        "CREATE TABLE sessions (session_id TEXT PRIMARY KEY, init_bytes BLOB NOT NULL, "
        "init_message_id TEXT NOT NULL, client_key TEXT NOT NULL, "
        "provider_challenge TEXT NOT NULL UNIQUE, provider_session_key TEXT NOT NULL UNIQUE, "
        "session_secret_age BLOB NOT NULL, key_state TEXT NOT NULL CHECK "
        "(key_state IN ('LIVE', 'RETIRED')), accept_bytes BLOB, accept_message_id TEXT, "
        "transcript_digest TEXT, phase TEXT NOT NULL CHECK "
        "(phase IN ('RESERVED', 'ACCEPT_COMMITTED', 'CONFIRMED', 'ACCEPTED')), "
        "blocked INTEGER NOT NULL CHECK (blocked IN (0, 1)), revision INTEGER NOT NULL, "
        "next_client_seq INTEGER NOT NULL, next_provider_seq INTEGER NOT NULL, "
        "active_at INTEGER NOT NULL)"
    ),
    (
        "CREATE TABLE inbox (session_id TEXT NOT NULL, sender_key TEXT NOT NULL, "
        "message_id TEXT NOT NULL, seq INTEGER NOT NULL, unsigned_digest TEXT NOT NULL, "
        "canonical_bytes BLOB NOT NULL, admitted_revision INTEGER NOT NULL, "
        "PRIMARY KEY (session_id, sender_key, message_id), "
        "UNIQUE (session_id, sender_key, seq))"
    ),
    (
        "CREATE TABLE outbox (message_id TEXT PRIMARY KEY, session_id TEXT NOT NULL, "
        "seq INTEGER NOT NULL, in_reply_to TEXT, canonical_bytes BLOB NOT NULL, "
        "committed_revision INTEGER NOT NULL, delivery_state TEXT NOT NULL CHECK "
        "(delivery_state IN ('PENDING', 'ACKED', 'RECONCILED')), UNIQUE (session_id, seq))"
    ),
    (
        "CREATE TABLE conflicts (session_id TEXT NOT NULL, kind TEXT NOT NULL CHECK "
        "(kind IN ('init', 'confirm', 'request')), evidence_bytes BLOB NOT NULL, "
        "PRIMARY KEY (session_id, kind))"
    ),
    (
        "CREATE TABLE epochs (epoch_key TEXT PRIMARY KEY, secret_age BLOB NOT NULL, "
        "created_at INTEGER NOT NULL, retire_after INTEGER NOT NULL)"
    ),
    ("CREATE TABLE expired (session_id TEXT PRIMARY KEY, expired_at INTEGER NOT NULL)"),
    (
        "CREATE TABLE announcements (slot INTEGER PRIMARY KEY CHECK (slot = 1), "
        "created_at INTEGER NOT NULL)"
    ),
    (
        "CREATE TABLE contract_keys (session_id TEXT PRIMARY KEY, "
        "compressed_key TEXT NOT NULL UNIQUE, secret_age BLOB NOT NULL)"
    ),
    # Accepted contracts are never idle-expired (RS-003 acceptance).
    SWAPS_V9_SCHEMA,
    # Never deleted: a payment hash is offered at most once, forever (RS-003).
    (
        "CREATE TABLE payment_hashes (payment_hash TEXT PRIMARY KEY, "
        "session_id TEXT NOT NULL, reserved_at INTEGER NOT NULL)"
    ),
)
PAYMENT_DISPATCH_SCHEMA = (
    "CREATE TABLE payment_dispatch (session_id TEXT PRIMARY KEY, "
    "payment_hash TEXT NOT NULL UNIQUE, "
    "state TEXT NOT NULL CHECK (state IN ('UNSENT', 'SUBMITTED')), request BLOB)"
)
SCHEMA_V6 = (*SCHEMA_V5, PAYMENT_DISPATCH_SCHEMA)
EPOCH_ADMISSION_SCHEMA = (
    "CREATE TABLE epoch_admissions (session_id TEXT PRIMARY KEY, epoch_key TEXT NOT NULL, "
    "retire_after INTEGER NOT NULL, expired INTEGER NOT NULL CHECK (expired IN (0, 1)))"
)
EPOCH_RETIREMENT_SCHEMA = (
    "CREATE TABLE epoch_retirement (singleton INTEGER PRIMARY KEY CHECK (singleton = 1), "
    "retired_through INTEGER NOT NULL CHECK (retired_through >= 0))"
)
EPOCH_KEY_HISTORY_SCHEMA = "CREATE TABLE epoch_key_history (epoch_key TEXT PRIMARY KEY)"
SCHEMA_V7 = (
    *SCHEMA_V6,
    EPOCH_ADMISSION_SCHEMA,
    EPOCH_RETIREMENT_SCHEMA,
    EPOCH_KEY_HISTORY_SCHEMA,
)
# One row per payment-hash reservation, kept forever. Only RELEASED rows stop
# counting against financial capacity, and only with versioned closure evidence.
ECONOMIC_RESERVATION_SCHEMA = (
    "CREATE TABLE economic_reservations (payment_hash TEXT PRIMARY KEY, "
    "session_id TEXT NOT NULL, state TEXT NOT NULL CHECK (state IN "
    "('UNKNOWN', 'UNSENT', 'DISPATCHED', 'RELEASED')), release_evidence BLOB, "
    "CHECK ((state = 'RELEASED') = (release_evidence IS NOT NULL)))"
)
SCHEMA_V8 = (*SCHEMA_V7, ECONOMIC_RESERVATION_SCHEMA)
# Every signed claim a CLAIMING swap may have broadcast, kept forever: any of
# them can confirm. swaps.claim_tx/claim_txid mirror the latest attempt until
# CLAIMED, then the attempt that confirmed. NULL fee or height means a
# migrated attempt not yet validated or observed; neither authorizes a bump.
CLAIM_ATTEMPT_SCHEMA = (
    "CREATE TABLE claim_attempts (session_id TEXT NOT NULL, "
    "attempt INTEGER NOT NULL CHECK (attempt >= 0), txid TEXT NOT NULL UNIQUE, "
    "raw BLOB NOT NULL, fee_sat INTEGER CHECK (fee_sat >= 0), "
    "first_seen_height INTEGER CHECK (first_seen_height > 0), "
    "PRIMARY KEY (session_id, attempt))"
)
SCHEMA_V9 = (*SCHEMA_V8, CLAIM_ATTEMPT_SCHEMA)
SCHEMA_V10 = tuple(
    SWAPS_V10_SCHEMA if statement is SWAPS_V9_SCHEMA else statement for statement in SCHEMA_V9
)
SCHEMA_V11 = tuple(
    SWAPS_SCHEMA if statement is SWAPS_V10_SCHEMA else statement for statement in SCHEMA_V10
)
COOPERATION_ATTEMPT_SCHEMA = (
    "CREATE TABLE cooperation_attempts (cooperation_id BLOB PRIMARY KEY NOT NULL CHECK "
    "(typeof(cooperation_id)='blob' AND length(cooperation_id)=32), session_id TEXT NOT NULL, "
    "owner_generation INTEGER NOT NULL CHECK (typeof(owner_generation)='integer' AND "
    "owner_generation > 0), binding BLOB NOT NULL "
    "CHECK (typeof(binding)='blob' AND length(binding) BETWEEN 1 AND 65536), "
    "created_at INTEGER NOT NULL CHECK (typeof(created_at)='integer' AND created_at >= 0), "
    "deadline_at INTEGER NOT NULL CHECK (typeof(deadline_at)='integer' AND "
    "deadline_at > created_at), state TEXT NOT NULL CHECK "
    "(state IN ('BURNED','NONCE_READY','SIGNING','COMPLETE','ABANDONED')), "
    "local_nonce BLOB CHECK (local_nonce IS NULL OR (typeof(local_nonce)='blob' AND "
    "length(local_nonce)=66)), peer_nonce BLOB CHECK (peer_nonce IS NULL OR "
    "(typeof(peer_nonce)='blob' AND length(peer_nonce)=66)), partial_signature BLOB CHECK "
    "(partial_signature IS NULL OR (typeof(partial_signature)='blob' AND "
    "length(partial_signature)=32)), nonce_response_id TEXT, partial_response_id TEXT, "
    "CHECK ((local_nonce IS NULL)=(nonce_response_id IS NULL)), "
    "CHECK ((partial_signature IS NULL)=(partial_response_id IS NULL)), "
    "CHECK ((state='BURNED' AND local_nonce IS NULL AND peer_nonce IS NULL) OR "
    "(state='NONCE_READY' AND local_nonce IS NOT NULL AND peer_nonce IS NULL) OR "
    "(state='SIGNING' AND local_nonce IS NOT NULL AND peer_nonce IS NOT NULL) OR "
    "(state='COMPLETE' AND local_nonce IS NOT NULL AND peer_nonce IS NOT NULL AND "
    "partial_signature IS NOT NULL) OR "
    "(state='ABANDONED' AND partial_signature IS NULL)), "
    "CHECK (state='COMPLETE' OR partial_signature IS NULL))"
)
SCHEMA_V12 = (*SCHEMA_V11, COOPERATION_ATTEMPT_SCHEMA)
# Arbitration is distinct from nonce custody: an affirmative admission row
# alone grants no waiting period or signing authority. A complete presigned
# unilateral bundle is required before any future runtime can open a window.
CLAIM_ARBITRATION_SCHEMA = (
    "CREATE TABLE claim_arbitration (session_id TEXT PRIMARY KEY NOT NULL, "
    "contract_hash TEXT NOT NULL CHECK (typeof(contract_hash)='text' AND "
    "length(contract_hash)=64), version INTEGER NOT NULL CHECK "
    "(typeof(version)='integer' AND version=1), state TEXT NOT NULL CHECK "
    "(state IN ('ADMITTED','WAITING','CLOSED')), owner_generation INTEGER "
    "CHECK (owner_generation IS NULL OR (typeof(owner_generation)='integer' AND "
    "owner_generation>0)), prepared_at INTEGER CHECK (prepared_at IS NULL OR "
    "(typeof(prepared_at)='integer' AND prepared_at>=0)), deadline_at INTEGER "
    "CHECK (deadline_at IS NULL OR (typeof(deadline_at)='integer' AND "
    "deadline_at>prepared_at)), deadline_height INTEGER CHECK "
    "(deadline_height IS NULL OR (typeof(deadline_height)='integer' AND "
    "deadline_height>0)), fallback_raw BLOB CHECK (fallback_raw IS NULL OR "
    "(typeof(fallback_raw)='blob' AND length(fallback_raw)>0)), fallback_txid TEXT "
    "CHECK (fallback_txid IS NULL OR (typeof(fallback_txid)='text' AND "
    "length(fallback_txid)=64)), fallback_fee_sat INTEGER CHECK "
    "(fallback_fee_sat IS NULL OR (typeof(fallback_fee_sat)='integer' AND "
    "fallback_fee_sat>=0)), cooperative_raw BLOB CHECK (cooperative_raw IS NULL OR "
    "(typeof(cooperative_raw)='blob' AND length(cooperative_raw)>0)), "
    "cooperative_txid TEXT CHECK (cooperative_txid IS NULL OR "
    "(typeof(cooperative_txid)='text' AND length(cooperative_txid)=64)), "
    "CHECK ((owner_generation IS NULL)=(prepared_at IS NULL) AND "
    "(owner_generation IS NULL)=(deadline_at IS NULL) AND "
    "(owner_generation IS NULL)=(deadline_height IS NULL) AND "
    "(owner_generation IS NULL)=(fallback_raw IS NULL) AND "
    "(owner_generation IS NULL)=(fallback_txid IS NULL) AND "
    "(owner_generation IS NULL)=(fallback_fee_sat IS NULL)), "
    "CHECK ((cooperative_raw IS NULL)=(cooperative_txid IS NULL) AND "
    "(cooperative_raw IS NULL OR owner_generation IS NOT NULL)), "
    "CHECK ((state='ADMITTED' AND owner_generation IS NULL AND "
    "cooperative_raw IS NULL) OR (state='WAITING' AND owner_generation IS NOT NULL "
    "AND cooperative_raw IS NULL) OR state='CLOSED'))"
)
SCHEMA = (*SCHEMA_V12, CLAIM_ARBITRATION_SCHEMA)
MAX_CLAIM_ATTEMPTS = 32
COOPERATION_BUDGET_SECONDS = 30
COOPERATION_OBSERVATION_MAX_AGE_SECONDS = 5
ADMISSION_INDEXES = (
    "CREATE INDEX epoch_admissions_expiry ON epoch_admissions (expired, retire_after)",
)
RESERVATION_INDEXES = (
    "CREATE INDEX economic_reservations_state ON economic_reservations (state, session_id)",
)
COOPERATION_INDEXES = (
    (
        "CREATE UNIQUE INDEX cooperation_unfinished_session ON cooperation_attempts (session_id) "
        "WHERE state IN ('BURNED','NONCE_READY','SIGNING')"
    ),
)


@dataclass(frozen=True, slots=True)
class EpochInitiation:
    """Canonical init and authenticated recipient provenance from open_epoch_frame()."""

    document: bytes
    epoch_key: str


class LiveSessionStoreError(ValueError):
    """No authoritative session fact was established; nothing may be exposed."""


class StaleOwnerError(LiveSessionStoreError):
    """The handle no longer owns the store; stop all exposure immediately."""


class SessionCapacityError(LiveSessionStoreError):
    """No new session fits; existing sessions and replays are unaffected."""


class SessionExpiredError(LiveSessionStoreError):
    """The session expired; its recorded result is final and keys are gone."""


class SessionBlockedError(LiveSessionStoreError):
    """Durable conflict evidence blocks new risk for this session."""


@dataclass(frozen=True, slots=True)
class AuthorityDeclaration:
    """Operator attestation of the deployment boundary this store relies on."""

    volume_label: str
    outside_restore_domain: bool
    single_host: bool

    def jcs(self) -> bytes:
        """Return canonical attestation bytes, refusing anything not explicit."""
        if not (
            type(self.volume_label) is str
            and 0 < len(self.volume_label) <= MAX_LABEL_CHARS
            and self.volume_label.isprintable()
            and self.outside_restore_domain is True
            and self.single_host is True
        ):
            raise LiveSessionStoreError("explicit authority attestation required")
        return canonicalize(
            {
                "volume_label": self.volume_label,
                "outside_restore_domain": True,
                "single_host": True,
            }
        )


@dataclass(frozen=True, slots=True)
class SessionReservation:
    """A reserved challenge; permits only building and committing one accept."""

    session_id: str
    init_message_id: str
    provider_challenge: str
    provider_session_key: str
    revision: int


@dataclass(frozen=True, slots=True)
class AcceptCommit:
    """Exact accept bytes durably committed; only now may they be published."""

    session_id: str
    message_id: str
    canonical_bytes: bytes
    transcript_digest: str
    revision: int


@dataclass(frozen=True, slots=True)
class ConfirmAdmission:
    """Client confirmation admitted; grants no economic authority."""

    session_id: str
    message_id: str
    transcript_digest: str
    revision: int
    replay: bool


@dataclass(frozen=True, slots=True)
class RequestAnswer:
    """A client request admitted with its recorded, signed answer (not yet sent)."""

    session_id: str
    request_message_id: str
    response_message_id: str
    replay: bool


@dataclass(frozen=True, slots=True)
class CooperativeResultAdmission:
    """Durable peer disposition, never permission to produce our partial."""

    session_id: str
    message_id: str
    status: str
    replay: bool


@dataclass(frozen=True, slots=True)
class CooperativeClaimObservation:
    """Trusted runtime's fresh, mempool-aware claim sample, not a wire model.

    The store cannot independently acquire chain or LND facts. A future
    runtime must obtain these from its configured Core and payment backends,
    bound to one named tip, immediately before invoking the signer. No caller
    exists yet, and this type must not be deserialized from a peer message.
    """

    network: NetworkIdentity
    funding_txid: str
    funding_vout: int
    funding_value_sat: int
    funding_script_pubkey: bytes
    tip_height: int
    tip_hash: str
    confirmations: int
    sampled_at: int
    mempool_unspent: bool
    fee_floor_sat: int


class EnvelopeSigner(Protocol):
    """BIP-340 signing, e.g. ``rill_crypto.Context``."""

    def schnorr_sign(self, secret_key: bytes, message: bytes, auxiliary_random: bytes) -> bytes:
        """Sign a 32-byte digest."""
        ...


@dataclass(frozen=True, slots=True)
class RequestContext:
    """Session facts a responder may bind into its answer."""

    handshake_hash: str
    provider_contract_key: str  # compressed; fresh per session, sealed like the session key
    is_payment_hash_reserved: Callable[[str], bool]
    replied_to: Envelope | None = None  # our outbox message named by in_reply_to
    swap: SwapRecord | None = None
    # False when a new firm offer would exceed unreleased economic capacity.
    economic_capacity_available: bool = True


@dataclass(frozen=True, slots=True)
class SwapRecord:
    """Durable accepted-swap state; byte fields are exact canonical envelopes."""

    session_id: str
    contract_hash: str
    terms_offer: bytes
    terms_accept: bytes
    state: str
    funding_binding: bytes | None
    preimage: str | None
    claim_txid: str | None


@dataclass(frozen=True, slots=True)
class SettlementItem:
    """One funded swap the settlement engine still has to move forward."""

    session_id: str
    state: str
    blocked: bool
    terms_offer: bytes
    funding_binding: bytes | None  # None before the client's binding (or for LN to BTC)
    invoice: str
    preimage: str | None
    claim_tx: bytes | None
    claim_txid: str | None
    payment_dispatch: str = "UNKNOWN"
    # Provenance of a committed version 1 dispatch record, never send permission.
    payment_payer: PaymentAuthority | None = None
    # Tip (height, hash) at which the contract output was first seen spent by
    # a non-attempt; the hash anchors the wait to the active chain.
    outpoint_spent_height: int | None = None
    outpoint_spent_block: str | None = None
    # LN to BTC (RS-004): the provider's own funding and refund, and the scan cursor.
    funding_txid: str | None = None
    funding_vout: int | None = None
    funding_tx: bytes | None = None
    refund_txid: str | None = None
    refund_tx: bytes | None = None
    spend_scan_height: int | None = None


@dataclass(frozen=True, slots=True)
class ClaimAttempt:
    """One recorded signed claim; ``None`` fee or height is not yet observed."""

    attempt: int
    txid: str
    raw: bytes
    fee_sat: int | None
    first_seen_height: int | None


@dataclass(frozen=True, slots=True)
class SwapInspection:
    """Offline custody summary, never live chain evidence or dispatch authority."""

    session_id: str
    contract_hash: str
    state: str
    session_present: bool
    blocked: bool | None
    dispatch_state: str
    dispatch_recorded: bool
    funding_binding_recorded: bool
    preimage_recorded: bool
    claim_recorded: bool
    claim_txid: str | None


@dataclass(frozen=True, slots=True)
class SwapInspectionPage:
    """Bounded keyset page; cursor does not claim a snapshot across invocations."""

    swaps: tuple[SwapInspection, ...]
    next_after: str | None


class StaleSwapError(LiveSessionStoreError):
    """The swap is no longer in the state the caller observed."""


@dataclass(frozen=True, slots=True)
class AcceptSwap:
    """Effect: record acceptance of the replied-to terms offer."""

    contract_hash: str


@dataclass(frozen=True, slots=True)
class BindFunding:
    """Effect: record the client's funding binding for the accepted swap."""


@dataclass(frozen=True, slots=True)
class Answer:
    """A responder's answer; ``payment_hash`` is reserved forever with it."""

    message_type: str
    payload: dict[str, Any]
    payment_hash: str | None = None
    contract_hash: str | None = None  # envelope binding, e.g. for terms_offer
    effect: AcceptSwap | BindFunding | None = None


if TYPE_CHECKING:
    from collections.abc import Callable

    # Policy: (request, earlier admitted requests, session context) -> answer.
    Responder = Callable[[Envelope, tuple[Envelope, ...], RequestContext], Answer]


@dataclass(frozen=True, slots=True)
class OutboxEntry:
    """Committed provider bytes awaiting application acknowledgment."""

    message_id: str
    session_id: str
    canonical_bytes: bytes


def _canonical_envelope(document: bytes) -> Envelope:
    if type(document) is not bytes or not 0 < len(document) <= MAX_DOCUMENT_BYTES:
        raise LiveSessionStoreError("envelope size unsupported")
    if canonicalize(parse_json_strict(document, max_bytes=MAX_DOCUMENT_BYTES)) != document:
        raise LiveSessionStoreError("canonical envelope bytes required")
    return parse_model_json(Envelope, document)


def _stable_file(directory: int, name: str, *, create: bool) -> int:
    flags = os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC
    if create:
        flags |= os.O_CREAT | os.O_EXCL
    descriptor = os.open(name, flags, 0o600, dir_fd=directory)
    if not stat.S_ISREG(os.fstat(descriptor).st_mode):
        os.close(descriptor)
        raise LiveSessionStoreError("store path is not a regular file")
    return descriptor


class LiveSessionStore:
    """Single owner of authoritative handshake sessions for one provider."""

    def __init__(  # noqa: PLR0913 - explicit owned resources
        self,
        *,
        path: Path,
        lock_fd: int,
        connection: sqlite3.Connection,
        generation: int,
        network: NetworkIdentity,
        identity: str,
        policy: HandshakePolicy,
        crypto: EnvelopeSchnorrVerifier,
        store_uuid: str,
        custody_identity: x25519.Identity,
        public_keys: CustodyPublicKeys,
        max_sessions: int,
        max_tombstones: int,
        new_sessions_per_minute: int,
        max_active_reservations: int,
    ) -> None:
        """Use provision() or acquire(); never construct directly."""
        self.path = path
        self._lock_fd: int | None = lock_fd
        self._connection = connection
        self._generation = generation
        self._network = network
        self._identity = identity
        self._policy = policy
        self._crypto = crypto
        self._store_uuid = store_uuid
        self._custody_identity = custody_identity
        self._public_keys = public_keys
        self._max_sessions = max_sessions
        self._max_tombstones = max_tombstones
        self._max_active_reservations = max_active_reservations
        self._admission = _TokenBucket(new_sessions_per_minute)
        self._pid = os.getpid()
        # Allocation IDs outlive failures for this owner. Native handles and
        # the secret nonce itself never cross a process or storage boundary.
        self._allocated_cooperation_ids: set[bytes] = set()
        self._cooperation_handles: dict[bytes, MusigAttempt] = {}

    @staticmethod
    def provision(  # noqa: PLR0913 - independent provisioning facts explicit
        path: str | PathLike[str],
        network: NetworkIdentity,
        provider_identity: str,
        policy: HandshakePolicy,
        authority: AuthorityDeclaration,
        *,
        custody_recipient: str,
    ) -> None:
        """Explicitly create a new empty store and owner lock; never overwrite.

        Session secrets are age-encrypted to ``custody_recipient``. Its identity
        must be kept outside this volume's images, or encryption adds nothing.
        """
        network_jcs, identity = _expected(network, provider_identity)
        recipient = _recipient(custody_recipient)
        policy_jcs = _policy_bytes(policy)
        authority_jcs = authority.jcs()
        location = Path(path).absolute()
        directory = os.open(location.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            lock_fd = _stable_file(directory, location.name + LOCK_SUFFIX, create=True)
            try:
                db_fd = _stable_file(directory, location.name, create=True)
                db_inode = os.fstat(db_fd).st_ino
                os.close(db_fd)
                lock_inode = os.fstat(lock_fd).st_ino
                os.fsync(lock_fd)
            finally:
                os.close(lock_fd)
            connection = sqlite3.connect(
                location.as_uri() + "?mode=rw", uri=True, isolation_level=None
            )
            try:
                _configure(connection)
                connection.execute("BEGIN IMMEDIATE")
                for statement in SCHEMA:
                    connection.execute(statement)
                for statement in (*ADMISSION_INDEXES, *RESERVATION_INDEXES, *COOPERATION_INDEXES):
                    connection.execute(statement)
                connection.execute("INSERT INTO epoch_retirement VALUES (1, 0)")
                connection.execute(
                    "INSERT INTO meta VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?)",
                    (
                        SCHEMA_VERSION,
                        str(uuid.uuid4()),
                        network_jcs,
                        identity,
                        policy_jcs,
                        authority_jcs,
                        db_inode,
                        lock_inode,
                        recipient,
                    ),
                )
                connection.execute(f"PRAGMA application_id={APPLICATION_ID}")
                connection.execute(f"PRAGMA user_version={SCHEMA_VERSION}")
                connection.execute("COMMIT")
            finally:
                connection.close()
            os.fsync(directory)
        except LiveSessionStoreError:
            raise
        except Exception:  # noqa: BLE001 - partial files are left for the operator
            raise LiveSessionStoreError("live session store provisioning refused") from None
        finally:
            os.close(directory)

    @classmethod
    def acquire(  # noqa: PLR0912, PLR0913, PLR0915 - independent custody guards explicit
        cls,
        path: str | PathLike[str],
        network: NetworkIdentity,
        provider_identity: str,
        policy: HandshakePolicy,
        *,
        crypto: EnvelopeSchnorrVerifier,
        custody_identity: str,
        public_keys: CustodyPublicKeys,
        max_sessions: int = DEFAULT_MAX_SESSIONS,
        max_tombstones: int = DEFAULT_MAX_TOMBSTONES,
        new_sessions_per_minute: int = DEFAULT_NEW_SESSIONS_PER_MINUTE,
        max_active_reservations: int = DEFAULT_MAX_ACTIVE_RESERVATIONS,
        upgrade_from_v5: bool = False,
    ) -> Self:
        """Take lifetime exclusive ownership; refuse any unknown or copied state.

        ``max_sessions`` caps pre-acceptance sessions, which ``expire_idle``
        reclaims. ``max_active_reservations`` caps unreleased economic
        reservations (firm offers and accepted swaps); only evidenced closure
        releases one. The historical ``upgrade_from_v5=True`` spelling
        authorizes supported v5-v7 schema upgrades and adding the epoch-bound
        admission feature.
        No old payment or handshake gains new authority from the migration.
        """
        if not all(
            type(limit) is int and limit >= 1
            for limit in (
                max_sessions,
                max_tombstones,
                new_sessions_per_minute,
                max_active_reservations,
            )
        ):
            raise LiveSessionStoreError("session capacity unsupported")
        network_jcs, identity = _expected(network, provider_identity)
        try:
            unlocking = x25519.Identity.from_str(custody_identity)
        except Exception:  # noqa: BLE001 - never echo credential material
            raise LiveSessionStoreError("custody identity malformed") from None
        _require_policy(policy)
        policy_jcs = _policy_bytes(policy)
        location = Path(path).absolute()
        lock_fd = -1
        connection: sqlite3.Connection | None = None
        try:
            directory = os.open(location.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                lock_fd = _stable_file(directory, location.name + LOCK_SUFFIX, create=False)
                try:
                    fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                except BlockingIOError:
                    raise LiveSessionStoreError("store owned by another process") from None
                db_fd = _stable_file(directory, location.name, create=False)
                db_inode = os.fstat(db_fd).st_ino
                os.close(db_fd)
            finally:
                os.close(directory)
            connection = sqlite3.connect(
                location.as_uri() + "?mode=rw", uri=True, isolation_level=None
            )
            connection.execute("PRAGMA busy_timeout=5000")
            version = _check_schema(connection, allow_v5=upgrade_from_v5 is True)
            _configure(connection)
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT schema_version, network_jcs, provider_identity, policy_jcs, "
                "db_inode, lock_inode, generation, store_uuid, authority_jcs, custody_recipient "
                "FROM meta"
            ).fetchall()
            if len(row) != 1 or row[0][:3] != (version, network_jcs, identity):
                raise LiveSessionStoreError("store namespace or policy mismatch")  # noqa: TRY301
            if row[0][3] != policy_jcs and not (
                upgrade_from_v5 is True
                and EPOCH_SESSION_FEATURE in policy.features
                and row[0][3]
                == _policy_bytes(
                    replace(policy, features=policy.features - {EPOCH_SESSION_FEATURE})
                )
            ):
                raise LiveSessionStoreError("store namespace or policy mismatch")  # noqa: TRY301
            _check_provisioning(row[0][7], row[0][8])
            if row[0][9] != str(unlocking.to_public()):
                raise LiveSessionStoreError("custody identity does not match store")  # noqa: TRY301
            if row[0][4:6] != (db_inode, os.fstat(lock_fd).st_ino):
                raise LiveSessionStoreError(  # noqa: TRY301 - copied or restored file
                    "store files are not the provisioned authoritative copy"
                )
            if version == 5:  # noqa: PLR2004 - exact legacy schema
                _upgrade_v5(connection)
            if version in (5, 6):
                _upgrade_v6(connection)
            if version in (5, 6, 7):
                _upgrade_v7(connection)
            if version in (5, 6, 7, 8):
                _upgrade_v8(connection)
            if version in (5, 6, 7, 8, 9):
                _upgrade_v9(connection)
            if version in (5, 6, 7, 8, 9, 10):
                _upgrade_v10(connection)
            if version not in (12, SCHEMA_VERSION):
                _upgrade_v11(connection)
            if version != SCHEMA_VERSION:
                _upgrade_v12(connection)
            if version != SCHEMA_VERSION:
                connection.execute("UPDATE meta SET schema_version=?", (SCHEMA_VERSION,))
                connection.execute(f"PRAGMA user_version={SCHEMA_VERSION}")
            _epoch_watermark(connection)
            if connection.execute(
                "SELECT 1 FROM epochs e LEFT JOIN epoch_key_history h "
                "ON h.epoch_key=e.epoch_key WHERE h.epoch_key IS NULL LIMIT 1"
            ).fetchone():
                raise LiveSessionStoreError("epoch key history unavailable")  # noqa: TRY301
            # Native one-shot nonce handles never survive process ownership.
            # Abandon every unfinished burn before this generation is usable;
            # absence of a live handle never authorizes recreating one.
            connection.execute(
                "UPDATE cooperation_attempts SET state='ABANDONED' "
                "WHERE state IN ('BURNED','NONCE_READY','SIGNING')"
            )
            # No process-local deadline worker or native handle survives owner
            # change. Closing eligibility does not itself dispatch or spend.
            connection.execute("UPDATE claim_arbitration SET state='CLOSED' WHERE state='WAITING'")
            connection.execute("UPDATE meta SET policy_jcs=?", (policy_jcs,))
            generation = row[0][6] + 1
            connection.execute("UPDATE meta SET generation=?", (generation,))
            connection.execute("COMMIT")
            owned = cls(
                path=location,
                lock_fd=lock_fd,
                connection=connection,
                generation=generation,
                network=NetworkIdentity.model_validate_json(network_jcs, strict=True),
                identity=identity,
                policy=policy,
                crypto=crypto,
                store_uuid=row[0][7],
                custody_identity=unlocking,
                public_keys=public_keys,
                max_sessions=max_sessions,
                max_tombstones=max_tombstones,
                new_sessions_per_minute=new_sessions_per_minute,
                max_active_reservations=max_active_reservations,
            )
        except LiveSessionStoreError:
            _discard(connection, lock_fd)
            raise
        except Exception:  # noqa: BLE001 - never echo storage details
            _discard(connection, lock_fd)
            raise LiveSessionStoreError("live session store unavailable") from None
        return owned

    def close(self) -> None:
        """Release ownership; the handle can never write again."""
        lock_fd, self._lock_fd = self._lock_fd, None
        if os.getpid() != self._pid:
            # Inherited across fork: never touch the parent's SQLite connection.
            # Closing our descriptor copy does not release the parent's flock.
            if lock_fd is not None:
                os.close(lock_fd)
            return
        try:
            for attempt in self._cooperation_handles.values():
                attempt.close()
        finally:
            self._cooperation_handles.clear()
            _discard(self._connection, -1 if lock_fd is None else lock_fd)

    def __enter__(self) -> Self:
        """Own the store for the block."""
        return self

    def __exit__(self, *_exc: object) -> None:
        """Release ownership."""
        self.close()

    @property
    def generation(self) -> int:
        """Owner generation; increases on every acquire."""
        return self._generation

    @contextmanager
    def _write(self) -> Iterator[sqlite3.Connection]:
        if os.getpid() != self._pid:
            raise StaleOwnerError("store handle inherited across fork; reacquire")
        if self._lock_fd is None:
            raise StaleOwnerError("store handle closed")
        connection = self._connection
        try:
            connection.execute("BEGIN IMMEDIATE")
        except sqlite3.Error:
            raise LiveSessionStoreError("live session store busy or unavailable") from None
        try:
            if connection.execute("SELECT generation FROM meta").fetchone() != (self._generation,):
                raise StaleOwnerError("store owned by a newer generation")  # noqa: TRY301
            yield connection
        except BaseException:
            try:
                connection.execute("ROLLBACK")
            except sqlite3.Error:
                self.close()  # transaction state unknown; this handle may not continue
            raise
        try:
            connection.execute("COMMIT")
        except sqlite3.Error:
            # Outcome unknown: the write may or may not be durable. Release
            # ownership so the caller must reacquire and re-read the truth.
            with suppress(sqlite3.Error):
                connection.execute("ROLLBACK")
            self.close()
            raise StaleOwnerError("commit outcome uncertain; ownership released") from None

    def _burn_cooperative_claim(  # noqa: PLR0913 - frozen attempt identity and two deadlines
        self,
        session_id: str,
        cooperation_id: bytes,
        plan: CooperativeClaimPlan,
        *,
        now: int,
        deadline_at: int,
        deadline_height: int,
    ) -> None:
        """Reserve one immutable ID before any native MuSig nonce allocation.

        INTERNAL ONLY. A committed burn is not permission to allocate a nonce,
        sign, send a message, or act on a supplied chain view. Future callers
        must independently validate current chain and Lightning facts and use
        separate durable response/outbox methods. Uncertain commits never
        return an authorization. Existing swaps without the signed feature
        cannot reach this path, and abandoned IDs are never reused.
        """
        if (
            not isinstance(cooperation_id, bytes)
            or len(cooperation_id) != 32  # noqa: PLR2004 - BIP327 context length
            or cooperation_id == bytes(32)
            or not isinstance(plan, CooperativeClaimPlan)
            or type(now) is not int
            or type(deadline_at) is not int
            or type(deadline_height) is not int
            or now < 0
            or not now < deadline_at <= now + COOPERATION_BUDGET_SECONDS
            or deadline_height <= 0
        ):
            raise LiveSessionStoreError("cooperative attempt parameters refused")
        try:
            with self._write() as connection:
                row = connection.execute(
                    "SELECT s.init_bytes, s.accept_bytes, s.transcript_digest, s.phase, "
                    "s.blocked, w.contract_hash, w.terms_offer, w.terms_accept, w.state, "
                    "w.funding_binding, w.funding_txid, w.funding_vout, w.preimage "
                    "FROM sessions s JOIN swaps w ON s.session_id=w.session_id "
                    "WHERE s.session_id=?",
                    (session_id,),
                ).fetchone()
                if row is None:
                    raise LiveSessionStoreError("no accepted cooperative swap")  # noqa: TRY301
                (
                    init_bytes,
                    accept_bytes,
                    transcript,
                    phase,
                    blocked,
                    recorded_hash,
                    offer,
                    accepted,
                    state,
                    binding_bytes,
                    funding_txid,
                    funding_vout,
                    preimage,
                ) = row
                if (
                    phase != "ACCEPTED"
                    or blocked
                    or accept_bytes is None
                    or COOPERATIVE_CLAIM_FEATURE not in self._policy.features
                    or connection.execute(
                        "SELECT 1 FROM cooperation_attempts WHERE session_id=? LIMIT 1",
                        (session_id,),
                    ).fetchone()
                    is not None
                ):
                    raise LiveSessionStoreError("cooperative attempt unavailable")  # noqa: TRY301
                init_envelope = _canonical_envelope(init_bytes)
                accept_envelope = _canonical_envelope(accept_bytes)
                initiation = parse_model_json(HandshakeInit, canonicalize(init_envelope.payload))
                acceptance = parse_model_json(
                    HandshakeAccept, canonicalize(accept_envelope.payload["accept"])
                )
                terms = _offer_terms(offer)
                client_acceptance = parse_model_json(
                    TermsAcceptPayload, canonicalize(_canonical_envelope(accepted).payload)
                ).acceptance
                digest = contract_hash(terms).hex()
                transcript_hash = handshake_hash(initiation, acceptance).hex()
                require_supported_contract_features(terms, initiation, acceptance)
                acceptance.validate_against(initiation, supported_features=self._policy.features)
                if (
                    COOPERATIVE_CLAIM_FEATURE not in terms.required_features
                    or session_id != initiation.session_id
                    or transcript_hash != transcript
                    or digest != recorded_hash
                    or terms.network_identity != self._network
                    or terms.profile_id != self._policy.profile
                    or client_acceptance.contract_hash != digest
                    or client_acceptance.handshake_hash != transcript_hash
                    or client_acceptance.session_id != session_id
                    or client_acceptance.client_session_xonly_key
                    != initiation.client_session_xonly_key
                    or client_acceptance.provider_session_xonly_key
                    != acceptance.provider_session_xonly_key
                    or deadline_height > terms.refund_lock_height
                    or not isinstance(preimage, str)
                    or re.fullmatch(r"[0-9a-f]{64}", preimage) is None
                    or hashlib.sha256(bytes.fromhex(preimage)).hexdigest()
                    != terms.invoice_binding.payment_hash
                ):
                    raise LiveSessionStoreError("cooperative authority unavailable")  # noqa: TRY301
                funding = plan.authorization.funding
                if terms.profile_id == "btc-to-ln/v1":
                    if state not in ("PAID", "CLAIMING") or binding_bytes is None:
                        raise LiveSessionStoreError("payment not claimable")  # noqa: TRY301
                    signed_binding = parse_model_json(
                        FundingBindingPayload,
                        canonicalize(_canonical_envelope(binding_bytes).payload),
                    ).binding
                    if (
                        signed_binding.contract_hash != digest
                        or signed_binding.funding_txid != funding.txid.hex()
                        or signed_binding.contract_vout != funding.output_index
                        or int(signed_binding.contract_value_sat) != funding.value_sat
                        or signed_binding.contract_script_pubkey != funding.script_pubkey.hex()
                    ):
                        raise LiveSessionStoreError("funding binding mismatch")  # noqa: TRY301
                elif (
                    state != "SETTLED"
                    or funding_txid != funding.txid.hex()
                    or funding_vout != funding.output_index
                ):
                    # Reverse SETTLED currently follows a witnessed claim. A
                    # pre-spend settle path must be separately designed first.
                    raise LiveSessionStoreError("reverse claim not settled")  # noqa: TRY301
                keys = cast("TaprootKeyOperations", self._public_keys)
                authorization = UnilateralAuthorization.from_terms(
                    terms, funding, "claim", keys=keys
                )
                frozen = build_cooperative_claim(authorization, fee_sat=plan.fee_sat)
                if plan != frozen:
                    raise LiveSessionStoreError("cooperative transaction differs")  # noqa: TRY301
                taproot = reconstruct_taproot_contract(terms, keys=keys)
                immutable = canonicalize(
                    {
                        "version": 1,
                        "session_id": session_id,
                        "cooperation_id": cooperation_id.hex(),
                        "contract_hash": digest,
                        "network_identity": terms.network_identity.model_dump(mode="json"),
                        "claimant": terms.claimant,
                        "user_key": terms.client_contract_compressed_key,
                        "provider_key": terms.provider_contract_compressed_key,
                        "tap_tweak": taproot.tap_tweak.hex(),
                        "funding_txid": funding.txid.hex(),
                        "funding_vout": funding.output_index,
                        "funding_value_sat": funding.value_sat,
                        "funding_script_pubkey": funding.script_pubkey.hex(),
                        "unsigned_transaction": frozen.base_transaction.hex(),
                        "signature_hash": frozen.signature_hash.hex(),
                        "fee_sat": frozen.fee_sat,
                        "deadline_at": deadline_at,
                        "deadline_height": deadline_height,
                    }
                )
                connection.execute(
                    "INSERT INTO cooperation_attempts "
                    "(cooperation_id, session_id, owner_generation, binding, "
                    "created_at, deadline_at, state) VALUES (?, ?, ?, ?, ?, ?, 'BURNED')",
                    (
                        cooperation_id,
                        session_id,
                        self._generation,
                        immutable,
                        now,
                        deadline_at,
                    ),
                )
        except LiveSessionStoreError:
            raise
        except Exception:  # noqa: BLE001 - never echo stored credentials or wire data
            raise LiveSessionStoreError("cooperative attempt refused") from None

    def _commit_cooperative_proposal_nonce(
        self,
        session_id: str,
        cooperation_id: bytes,
        public_nonce: bytes,
        *,
        signer: EnvelopeSigner,
        now: int,
    ) -> str:
        """Commit a native public nonce and signed BTC-to-LN proposal before exposure.

        INTERNAL ONLY. The native handle must have been allocated AFTER the
        durable burn. On failure/uncertain commit destroy it and fall back; do
        not regenerate for this ID. The returned ID names a committed outbox
        message, not delivery or permission to disclose a partial signature.
        """
        if (
            not isinstance(cooperation_id, bytes)
            or len(cooperation_id) != 32  # noqa: PLR2004 - BIP327 context length
            or not isinstance(public_nonce, bytes)
            or len(public_nonce) != 66  # noqa: PLR2004 - BIP327 public nonce length
            or type(now) is not int
            or now < 0
        ):
            raise LiveSessionStoreError("cooperative nonce parameters refused")
        try:
            with self._write() as connection:
                row = connection.execute(
                    "SELECT a.binding,a.owner_generation,a.created_at,a.deadline_at,a.state,"
                    "s.phase,s.blocked,w.state,w.preimage,w.contract_hash,"
                    "w.terms_offer,w.funding_binding "
                    "FROM cooperation_attempts a JOIN sessions s ON s.session_id=a.session_id "
                    "JOIN swaps w ON w.session_id=a.session_id "
                    "WHERE a.session_id=? AND a.cooperation_id=?",
                    (session_id, cooperation_id),
                ).fetchone()
                if row is None:
                    raise LiveSessionStoreError("cooperative burn unavailable")  # noqa: TRY301
                (
                    binding_bytes,
                    generation,
                    created_at,
                    deadline_at,
                    state,
                    phase,
                    blocked,
                    swap_state,
                    preimage,
                    recorded_hash,
                    offer_bytes,
                    funding_binding_bytes,
                ) = row
                binding = parse_json_strict(binding_bytes)
                if not isinstance(binding, dict) or (
                    generation != self._generation
                    or state != "BURNED"
                    or phase != "ACCEPTED"
                    or blocked
                    or swap_state not in ("PAID", "CLAIMING")
                    or not created_at <= now < deadline_at
                    or binding.get("version") != 1
                    or binding.get("session_id") != session_id
                    or binding.get("cooperation_id") != cooperation_id.hex()
                    or binding.get("contract_hash") != recorded_hash
                    or binding.get("claimant") != "provider"
                    or binding.get("deadline_at") != deadline_at
                    or not isinstance(preimage, str)
                    or re.fullmatch(r"[0-9a-f]{64}", preimage) is None
                    or funding_binding_bytes is None
                    or COOPERATIVE_CLAIM_FEATURE not in self._policy.features
                ):
                    raise LiveSessionStoreError("cooperative nonce unavailable")  # noqa: TRY301
                terms = _offer_terms(offer_bytes)
                retained_funding = parse_model_json(
                    FundingBindingPayload,
                    canonicalize(_canonical_envelope(funding_binding_bytes).payload),
                ).binding
                if (
                    contract_hash(terms).hex() != recorded_hash
                    or COOPERATIVE_CLAIM_FEATURE not in terms.required_features
                    or hashlib.sha256(bytes.fromhex(preimage)).hexdigest()
                    != terms.invoice_binding.payment_hash
                    or retained_funding.contract_hash != recorded_hash
                    or retained_funding.funding_txid != binding.get("funding_txid")
                    or retained_funding.contract_vout != binding.get("funding_vout")
                    or int(retained_funding.contract_value_sat) != binding.get("funding_value_sat")
                    or retained_funding.contract_script_pubkey
                    != binding.get("funding_script_pubkey")
                ):
                    raise LiveSessionStoreError("cooperative nonce binding changed")  # noqa: TRY301
                # Production supplies native rill-crypto.Context and checks both
                # nonce points before any signed envelope can leave the store.
                cast("Context", self._crypto).musig_public_nonce_validate(public_nonce)
                proposal = CooperativeClaimPropose.model_validate_json(
                    canonicalize(
                        {
                            "action": "cooperative_claim_propose",
                            "cooperation_id": cooperation_id.hex(),
                            "unsigned_transaction": binding["unsigned_transaction"],
                            "payment_preimage": preimage,
                            "public_nonce": public_nonce.hex(),
                            "deadline_at": deadline_at,
                            "deadline_height": binding["deadline_height"],
                        }
                    ),
                    strict=True,
                )
                message_id = self._record_observation(
                    connection,
                    session_id,
                    proposal.model_dump(mode="json"),
                    signer,
                    now,
                    message_type="action_request",
                    required_features=(COOPERATIVE_CLAIM_FEATURE,),
                )
                if (
                    connection.execute(
                        "UPDATE cooperation_attempts SET state='NONCE_READY',local_nonce=?,"
                        "nonce_response_id=? WHERE cooperation_id=? AND session_id=? "
                        "AND state='BURNED' AND owner_generation=?",
                        (public_nonce, message_id, cooperation_id, session_id, self._generation),
                    ).rowcount
                    != 1
                ):
                    raise LiveSessionStoreError("cooperative nonce state changed")  # noqa: TRY301
        except LiveSessionStoreError:
            raise
        except Exception:  # noqa: BLE001 - never echo nonce or stored state
            raise LiveSessionStoreError("cooperative nonce commit refused") from None
        return message_id

    def _begin_and_commit_cooperative_proposal(  # noqa: PLR0912 - custody and burn checks share one transaction
        self,
        session_id: str,
        cooperation_id: bytes,
        *,
        now: int,
    ) -> str:
        """Allocate one store-owned native handle after burn, then commit its nonce.

        INTERNAL ONLY. The caller must already have durably burned the exact
        claim, verified current chain state, and planned independent fallback.
        The scalar stays inside the store; neither it nor the opaque signing
        handle is returned. A failed begin/commit permanently prevents another
        native allocation for this ID in this owner process. A new owner
        abandons the BURNED row before it can allocate anything.
        """
        from rill_crypto import Context  # noqa: PLC0415 - native boundary is opt-in

        if (
            not isinstance(self._crypto, Context)
            or self._public_keys is not self._crypto
            or not isinstance(cooperation_id, bytes)
            or len(cooperation_id) != 32  # noqa: PLR2004 - unique BIP327 ID
            or type(now) is not int
            or now < 0
        ):
            raise LiveSessionStoreError("native cooperative custody unavailable")
        crypto = self._crypto
        if cooperation_id in self._allocated_cooperation_ids:
            raise LiveSessionStoreError("cooperative nonce allocation already attempted")
        try:
            with self._write() as connection:
                row = connection.execute(
                    "SELECT a.binding,a.owner_generation,a.created_at,a.deadline_at,a.state,"
                    "s.phase,s.blocked,w.state,w.contract_hash,w.terms_offer,"
                    "k.compressed_key,k.secret_age "
                    "FROM cooperation_attempts a "
                    "JOIN sessions s ON s.session_id=a.session_id "
                    "JOIN swaps w ON w.session_id=a.session_id "
                    "LEFT JOIN contract_keys k ON k.session_id=a.session_id "
                    "WHERE a.session_id=? AND a.cooperation_id=?",
                    (session_id, cooperation_id),
                ).fetchone()
                if row is None:
                    raise LiveSessionStoreError("cooperative burn unavailable")  # noqa: TRY301
                (
                    binding_bytes,
                    generation,
                    created_at,
                    deadline_at,
                    state,
                    phase,
                    blocked,
                    swap_state,
                    recorded_hash,
                    offer_bytes,
                    compressed,
                    sealed,
                ) = row
                binding = parse_json_strict(binding_bytes)
                if not isinstance(binding, dict) or (
                    cooperation_id in self._allocated_cooperation_ids
                    or generation != self._generation
                    or state != "BURNED"
                    or phase != "ACCEPTED"
                    or blocked
                    or swap_state not in ("PAID", "CLAIMING")
                    or not created_at <= now < deadline_at
                    or binding.get("version") != 1
                    or binding.get("cooperation_id") != cooperation_id.hex()
                    or binding.get("session_id") != session_id
                    or binding.get("deadline_at") != deadline_at
                    or binding.get("contract_hash") != recorded_hash
                    or binding.get("claimant") != "provider"
                    or compressed != binding.get("provider_key")
                    or sealed is None
                    or COOPERATIVE_CLAIM_FEATURE not in self._policy.features
                ):
                    raise LiveSessionStoreError("cooperative nonce allocation unavailable")  # noqa: TRY301
                terms = _offer_terms(offer_bytes)
                if (
                    contract_hash(terms).hex() != recorded_hash
                    or COOPERATIVE_CLAIM_FEATURE not in terms.required_features
                    or terms.client_contract_compressed_key != binding.get("user_key")
                    or terms.provider_contract_compressed_key != compressed
                    or terms.network_identity.model_dump(mode="json")
                    != binding.get("network_identity")
                ):
                    raise LiveSessionStoreError("cooperative signer terms changed")  # noqa: TRY301
                user_key = binding.get("user_key")
                tweak = binding.get("tap_tweak")
                message = binding.get("signature_hash")
                if (
                    not isinstance(user_key, str)
                    or re.fullmatch(r"(02|03)[0-9a-f]{64}", user_key) is None
                    or not isinstance(tweak, str)
                    or re.fullmatch(r"[0-9a-f]{64}", tweak) is None
                    or not isinstance(message, str)
                    or re.fullmatch(r"[0-9a-f]{64}", message) is None
                ):
                    raise LiveSessionStoreError("cooperative signing context malformed")  # noqa: TRY301
                plaintext = pyrage.decrypt(sealed, [self._custody_identity])
                key_record = parse_json_strict(plaintext)
                if not isinstance(key_record, dict):
                    raise LiveSessionStoreError("cooperative contract custody differs")  # noqa: TRY301
                scalar_hex = key_record.get("secret_scalar")
                if (
                    key_record.get("kind") != CONTRACT_KEY_RECORD_KIND
                    or key_record.get("store_uuid") != self._store_uuid
                    or key_record.get("session_id") != session_id
                    or key_record.get("compressed_public_key") != compressed
                    or not isinstance(scalar_hex, str)
                    or re.fullmatch(r"[0-9a-f]{64}", scalar_hex) is None
                ):
                    raise LiveSessionStoreError("cooperative contract custody differs")  # noqa: TRY301
                scalar = bytes.fromhex(scalar_hex)
                del plaintext, key_record, scalar_hex
                try:
                    if crypto.public_key(scalar).hex() != compressed:
                        raise LiveSessionStoreError("cooperative contract key differs")
                    # The burn committed in an earlier transaction. Never
                    # remove this tombstone, including if native begin raises.
                    self._allocated_cooperation_ids.add(cooperation_id)
                    attempt, public_nonce = crypto.musig_begin(
                        secret_key=scalar,
                        user_public_key=bytes.fromhex(user_key),
                        provider_public_key=bytes.fromhex(compressed),
                        tap_tweak=bytes.fromhex(tweak),
                        message=bytes.fromhex(message),
                        cooperation_id=cooperation_id,
                    )
                    self._cooperation_handles[cooperation_id] = attempt
                finally:
                    del scalar
            # The private storage primitive rechecks the current owner, state,
            # funding, preimage and deadline in its own durable write. It may
            # only publish the exact nonce bound to the live handle above.
            return self._commit_cooperative_proposal_nonce(
                session_id, cooperation_id, public_nonce, signer=crypto, now=now
            )
        except BaseException as error:
            live = self._cooperation_handles.pop(cooperation_id, None)
            if live is not None:
                with suppress(Exception):
                    live.close()
            if isinstance(error, Exception) and not isinstance(error, LiveSessionStoreError):
                raise LiveSessionStoreError("cooperative native proposal refused") from None
            raise

    def _expectations(self) -> dict[str, object]:
        return {
            "expected_provider_identity": self._identity,
            "expected_profile": self._policy.profile,
            "expected_network": self._network,
            "supported_features": _features(self._policy.features),
            "supported_encryption_suites": _features(self._policy.encryption_suites),
            "supported_capabilities": _features(self._policy.capabilities),
            "crypto": self._crypto,
        }

    def _init(self, document: bytes) -> tuple[Envelope, HandshakeInit]:
        outer = _canonical_envelope(document)
        init = HandshakeInit.model_validate_json(canonicalize(outer.payload), strict=True)
        policy = self._policy
        if not (
            outer.message_type == "handshake_init"
            and outer.sequence == 0
            and outer.in_reply_to is None
            and outer.contract_hash is None
            and outer.signature is None
            and outer.session_id == init.session_id
            and outer.sender_session_key == init.client_session_xonly_key
            and outer.profile_id == init.profile_id == policy.profile
            and outer.network_identity == init.network_identity == self._network
            and init.expected_provider_identity_xonly_key == self._identity
            and set(outer.required_features).issubset(policy.features)
            and set(init.required_features).issubset(policy.features)
            and bool(set(init.requested_encryption_suites) & policy.encryption_suites)
        ):
            raise LiveSessionStoreError("untrusted or unsupported handshake initiation")
        return outer, init

    @property
    def requires_epoch_bound_sessions(self) -> bool:
        """Whether all new sessions require epoch binding (legacy replays remain valid)."""
        return EPOCH_SESSION_FEATURE in self._policy.features

    def reserve(  # noqa: PLR0912, PLR0915 - replay, provenance, and capacity share one transaction
        self, initiation: bytes | EpochInitiation, *, now: int | None = None
    ) -> SessionReservation:
        """Reserve one fresh provider challenge per session; replay is stable.

        The init is unsigned, so different bytes for a known session may come
        from a stranger. They are kept as bounded conflict evidence and block
        new risk for that session (an availability cost, never exposure).
        Legacy expired IDs remain tombstoned forever. Epoch-bound idle sessions
        keep a temporary tombstone until their epoch has durably retired. That
        mode rejects every new unbound initiation, so legacy input cannot reuse
        a retired epoch-bound ID. Existing legacy records still replay exactly.
        """
        now = int(time.time()) if now is None else now
        ingress = initiation if isinstance(initiation, EpochInitiation) else None
        init_document = (
            initiation.document if isinstance(initiation, EpochInitiation) else initiation
        )
        try:
            outer, init = self._init(init_document)
            with self._write() as connection:
                if _session_expired(connection, init.session_id):
                    raise SessionExpiredError("session expired")  # noqa: TRY301
                epoch = init.epoch_inbox_xonly_key
                retire_after = None
                if epoch is not None:
                    if ingress is None or ingress.epoch_key != epoch:
                        raise LiveSessionStoreError("epoch admission provenance unavailable")  # noqa: TRY301
                    epoch_row = connection.execute(
                        "SELECT retire_after FROM epochs WHERE epoch_key=? AND retire_after > ?",
                        (epoch, max(now, _epoch_watermark(connection))),
                    ).fetchone()
                    if epoch_row is None:
                        raise SessionExpiredError("admission epoch retired")  # noqa: TRY301
                    retire_after = epoch_row[0]
                admission = connection.execute(
                    "SELECT epoch_key, retire_after FROM epoch_admissions WHERE session_id=?",
                    (init.session_id,),
                ).fetchone()
                row = connection.execute(
                    "SELECT init_bytes, provider_challenge, blocked, revision FROM sessions "
                    "WHERE session_id=?",
                    (init.session_id,),
                ).fetchone()
                if admission is not None and (row is None or admission != (epoch, retire_after)):
                    # An unbound or differently bound init must not poison a
                    # known epoch session through the legacy conflict path.
                    raise LiveSessionStoreError("epoch admission custody unavailable")  # noqa: TRY301
                if row is not None and epoch is not None and admission is None:
                    raise LiveSessionStoreError("epoch admission custody unavailable")  # noqa: TRY301
                if row is not None:
                    if row[0] == init_document and not row[2]:
                        # Replay reuses the key; broken custody is never replaced.
                        key = self._require_custody(connection, init.session_id)
                        return SessionReservation(
                            init.session_id, outer.message_id, row[1], key, row[3]
                        )
                    if row[0] != init_document:
                        _record_conflict(connection, init.session_id, "init", init_document)
                    blocked = True
                else:
                    blocked = False
                    if self.requires_epoch_bound_sessions and epoch is None:
                        raise LiveSessionStoreError("new session requires epoch-bound admission")  # noqa: TRY301
                    # Accepted sessions are retained forever but hold economic
                    # reservations instead; only pre-acceptance sessions count here.
                    (live,) = connection.execute(
                        "SELECT COUNT(*) FROM sessions WHERE phase IN "
                        "('RESERVED', 'ACCEPT_COMMITTED', 'CONFIRMED')"
                    ).fetchone()
                    if epoch is None:
                        (dead,) = connection.execute("SELECT COUNT(*) FROM expired").fetchone()
                    else:
                        (dead,) = connection.execute(
                            "SELECT COUNT(*) FROM epoch_admissions WHERE expired=1"
                        ).fetchone()
                    if live >= self._max_sessions or dead >= self._max_tombstones:
                        raise SessionCapacityError("session capacity reached")  # noqa: TRY301
                    if not self._admission.take(now):
                        raise SessionCapacityError("session admission rate exceeded")  # noqa: TRY301
                    challenge = _fresh_challenge(connection, init)
                    key, sealed = self._new_session_key(init, challenge)
                    connection.execute(
                        "INSERT INTO sessions VALUES (?, ?, ?, ?, ?, ?, ?, 'LIVE', "
                        "NULL, NULL, NULL, 'RESERVED', 0, 0, 1, 0, ?)",
                        (
                            init.session_id,
                            init_document,
                            outer.message_id,
                            init.client_session_xonly_key,
                            challenge,
                            key,
                            sealed,
                            now,
                        ),
                    )
                    if epoch is not None:
                        connection.execute(
                            "INSERT INTO epoch_admissions VALUES (?, ?, ?, 0)",
                            (init.session_id, epoch, retire_after),
                        )
        except LiveSessionStoreError:
            raise
        except Exception:  # noqa: BLE001 - never echo caller documents
            raise LiveSessionStoreError("session reservation refused") from None
        if blocked:
            raise SessionBlockedError("session initiation conflict is durable")
        return SessionReservation(init.session_id, outer.message_id, challenge, key, 0)

    def _key_record(
        self, session_id: str, init_digest: str, challenge: str, scalar: bytes, xonly: str
    ) -> bytes:
        return canonicalize(
            {
                "kind": KEY_RECORD_KIND,
                "secret_scalar": scalar.hex(),
                "xonly_public_key": xonly,
                "store_uuid": self._store_uuid,
                "network_identity": self._network.model_dump(mode="json"),
                "provider_identity": self._identity,
                "session_id": session_id,
                "handshake_init_digest": init_digest,
                "provider_challenge": challenge,
            }
        )

    def _new_session_key(self, init: HandshakeInit, challenge: str) -> tuple[str, bytes]:
        scalar = _new_session_scalar()
        xonly = _xonly(self._public_keys, scalar)
        record = self._key_record(
            init.session_id, handshake_init_hash(init).hex(), challenge, scalar, xonly
        )
        sealed = pyrage.encrypt(record, [self._custody_identity.to_public()])
        if type(sealed) is not bytes or pyrage.decrypt(sealed, [self._custody_identity]) != record:
            raise LiveSessionStoreError("session key custody not verifiable")
        return xonly, sealed

    def _require_custody(self, connection: sqlite3.Connection, session_id: str) -> str:
        """Return the bound public key only if its sealed secret is intact and usable."""
        _, xonly = self._unseal(connection, session_id)
        return xonly

    def _unseal(self, connection: sqlite3.Connection, session_id: str) -> tuple[bytes, str]:
        row = connection.execute(
            "SELECT init_bytes, provider_challenge, provider_session_key, session_secret_age, "
            "key_state FROM sessions WHERE session_id=?",
            (session_id,),
        ).fetchone()
        try:
            init_bytes, challenge, xonly, sealed, state = row
            _, init = self._init(init_bytes)
            plaintext = pyrage.decrypt(sealed, [self._custody_identity])
            record = json.loads(plaintext)
            scalar = bytes.fromhex(record["secret_scalar"])
            valid = (
                state == "LIVE"
                and plaintext
                == self._key_record(
                    session_id, handshake_init_hash(init).hex(), challenge, scalar, xonly
                )
                and _xonly(self._public_keys, scalar) == xonly
            )
        except Exception:  # noqa: BLE001 - never echo secret material or library errors
            valid = False
        if not valid:
            raise LiveSessionStoreError("session key custody unavailable")
        return scalar, str(xonly)

    def wrap_pending(self, message_id: str, *, transport: Context) -> bytes:
        """Return a fresh NIP-59 wrap of one committed, still-owed outbox message.

        Each call re-randomizes seal and wrapper around the unchanged logical
        message. The recipient is the peer's session mailbox from the
        committed transcript, never a caller-chosen key.
        """
        try:
            with self._write() as connection:
                row = connection.execute(
                    "SELECT o.session_id, o.canonical_bytes, s.client_key FROM outbox o "
                    "JOIN sessions s ON s.session_id = o.session_id "
                    "WHERE o.message_id=? AND o.delivery_state='PENDING'",
                    (message_id,),
                ).fetchone()
                if row is None:
                    raise LiveSessionStoreError("no pending outbox message")  # noqa: TRY301
                session_id, document, recipient = row
                scalar, _ = self._unseal(connection, session_id)
                try:
                    return _wrap_envelope(
                        document,
                        sender_session_secret=scalar,
                        recipient_xonly_key=recipient,
                        crypto=transport,
                    )
                finally:
                    del scalar
        except LiveSessionStoreError:
            raise
        except Exception:  # noqa: BLE001 - never echo secret material or library errors
            raise LiveSessionStoreError("outbox wrap refused") from None

    def open_mailbox_frame(self, outer_event: bytes, *, transport: Context) -> bytes:
        """Decode a gift wrap sent to one of our session mailboxes.

        Returns the exact canonical envelope bytes only if the seal author is
        that session's client key and the envelope names that session. This is
        NOT admission: the caller must still pass the bytes to the matching
        admission method (for example ``admit_confirm``).
        """
        try:
            recipient = _routing_recipient(outer_event)
            with self._write() as connection:
                row = connection.execute(
                    "SELECT session_id, client_key FROM sessions WHERE provider_session_key=?",
                    (recipient,),
                ).fetchone()
                if row is None:
                    raise LiveSessionStoreError("mailbox frame for unknown session")  # noqa: TRY301
                session_id, client = row
                scalar, mailbox = self._unseal(connection, session_id)
                try:
                    candidate = _decode_gift_wrap_candidate(
                        outer_event,
                        recipient_mailbox_secret=scalar,
                        expected_recipient_xonly_key=mailbox,
                        expected_network=self._network,
                        expected_profile_id=self._policy.profile,
                        crypto=transport,
                    )
                finally:
                    del scalar
            if not (
                candidate.seal_author_xonly_key == client
                and candidate.envelope.sender_session_key == client
                and candidate.envelope.session_id == session_id
            ):
                raise LiveSessionStoreError("mailbox frame sender not bound to session")  # noqa: TRY301
        except LiveSessionStoreError:
            raise
        except Exception:  # noqa: BLE001 - uniform, redacted refusal (RS-006)
            raise LiveSessionStoreError("mailbox frame refused") from None
        return candidate.envelope_bytes

    def create_accept(
        self,
        session_id: str,
        *,
        identity: ProviderIdentity,
        transport_endpoints: tuple[str, ...],
    ) -> AcceptCommit:
        """Build, identity-sign, and durably commit this session's one accept.

        Negotiation picks the client's most preferred supported suite and the
        requested capabilities we support, in the client's order. A session
        that already committed an accept returns that record, never a new one.
        Nothing is exposed here; publish only via ``wrap_pending``.
        """
        try:
            with self._write() as connection:
                row = connection.execute(
                    "SELECT init_bytes, provider_challenge, accept_bytes, blocked "
                    "FROM sessions WHERE session_id=?",
                    (session_id,),
                ).fetchone()
                if row is None:
                    raise LiveSessionStoreError("no reservation for session")  # noqa: TRY301
                init_bytes, challenge, stored, blocked = row
                key = (
                    None
                    if stored is not None or blocked
                    else self._require_custody(connection, session_id)
                )
            if stored is not None:
                return self.commit_accept(stored)
            if blocked or key is None:
                raise SessionBlockedError("session blocked by conflict evidence")  # noqa: TRY301
            outer, init = self._init(init_bytes)
            if identity.xonly_public_key != self._identity:
                raise LiveSessionStoreError("identity is not this store's provider")  # noqa: TRY301
            policy = self._policy
            suites = [s for s in init.requested_encryption_suites if s in policy.encryption_suites]
            capabilities = tuple(c for c in init.requested_capabilities if c in policy.capabilities)
            if not suites or not capabilities:
                raise LiveSessionStoreError("no mutually supported selection")  # noqa: TRY301
            selection = HandshakeAccept(
                handshake_init_hash=handshake_init_hash(init).hex(),
                protocol="rillswap",
                wire_version="1",
                profile_id=init.profile_id,
                network_identity=init.network_identity,
                session_id=init.session_id,
                client_challenge=init.client_challenge,
                provider_challenge=challenge,
                client_session_xonly_key=init.client_session_xonly_key,
                provider_session_xonly_key=key,
                provider_identity_xonly_key=self._identity,
                selected_encryption_suite=suites[0],
                selected_capabilities=capabilities,
                transport_endpoints=tuple(transport_endpoints),
                required_features=(EPOCH_SESSION_FEATURE,) if init.epoch_inbox_xonly_key else (),
                extensions={},
            )
            payload: dict[str, Any] = {
                "accept": selection.model_dump(mode="json"),
                "provider_identity_signature": identity.sign_handshake_accept(selection),
            }
            document = canonicalize(
                {
                    "protocol": "rillswap",
                    "wire_version": "1",
                    "profile_id": init.profile_id,
                    "network_identity": init.network_identity.model_dump(mode="json"),
                    "session_id": init.session_id,
                    "message_id": _new_message_id(),
                    "sender_session_key": key,
                    "sequence": 0,
                    "in_reply_to": outer.message_id,
                    "contract_hash": None,
                    "message_type": "handshake_accept",
                    "payload": payload,
                    "required_features": [],
                    "extensions": {},
                    "signature": None,
                }
            )
        except LiveSessionStoreError:
            raise
        except Exception:  # noqa: BLE001 - never echo secret material or library errors
            raise LiveSessionStoreError("accept construction refused") from None
        # A concurrent identical build is impossible (single owner); a crash
        # before this commit leaves nothing exposed and simply rebuilds.
        return self.commit_accept(document)

    def commit_accept(self, accept_document: bytes) -> AcceptCommit:
        """Durably commit exact accept bytes BEFORE any publication.

        Only after this returns may the bytes be exposed. At most one accept is
        ever committed per session; identical resubmission returns the record.
        """
        try:
            outer = _canonical_envelope(accept_document)
            accepted = HandshakeAcceptPayload.model_validate_json(
                canonicalize(outer.payload), strict=True
            )
            with self._write() as connection:
                row = connection.execute(
                    "SELECT init_bytes, provider_challenge, accept_bytes, accept_message_id, "
                    "transcript_digest, phase, blocked, revision FROM sessions "
                    "WHERE session_id=?",
                    (outer.session_id,),
                ).fetchone()
                if row is None:
                    raise LiveSessionStoreError("no reservation for session")  # noqa: TRY301
                init_bytes, challenge, stored, stored_id, digest, phase, blocked, revision = row
                if phase != "RESERVED":
                    if stored != accept_document:
                        raise LiveSessionStoreError(  # noqa: TRY301
                            "a different accept is already committed"
                        )
                    return AcceptCommit(
                        outer.session_id,
                        stored_id,
                        stored,
                        digest,
                        _accept_revision(connection, stored_id),
                    )
                if blocked:
                    raise SessionBlockedError("session blocked by conflict evidence")  # noqa: TRY301
                transcript = verify_static_handshake_accept(
                    init_bytes,
                    accept_document,
                    **self._expectations(),  # type: ignore[arg-type]
                ).hex()
                if accepted.accept.provider_challenge != challenge:
                    raise LiveSessionStoreError("accept challenge not reserved")  # noqa: TRY301
                custody_key = self._require_custody(connection, outer.session_id)
                if accepted.accept.provider_session_xonly_key != custody_key:
                    raise LiveSessionStoreError(  # noqa: TRY301
                        "accept session key is not the reserved custody key"
                    )
                committed = revision + 1
                connection.execute(
                    "INSERT INTO outbox VALUES (?, ?, 0, ?, ?, ?, 'PENDING')",
                    (
                        outer.message_id,
                        outer.session_id,
                        outer.in_reply_to,
                        accept_document,
                        committed,
                    ),
                )
                connection.execute(
                    "UPDATE sessions SET accept_bytes=?, accept_message_id=?, "
                    "transcript_digest=?, phase='ACCEPT_COMMITTED', revision=?, "
                    "next_provider_seq=1 WHERE session_id=?",
                    (accept_document, outer.message_id, transcript, committed, outer.session_id),
                )
        except LiveSessionStoreError:
            raise
        except Exception:  # noqa: BLE001 - never echo caller documents or crypto details
            raise LiveSessionStoreError("accept commit refused") from None
        return AcceptCommit(
            outer.session_id, outer.message_id, accept_document, transcript, committed
        )

    def admit_confirm(self, confirm_document: bytes, *, now: int | None = None) -> ConfirmAdmission:
        """Atomically admit the signed confirm over the committed transcript.

        Unverifiable documents are refused without any record. A second,
        different, validly signed confirm is client equivocation: it is kept
        as evidence and blocks the session.
        """
        try:
            outer = _canonical_envelope(confirm_document)
            with self._write() as connection:
                row = connection.execute(
                    "SELECT init_bytes, accept_bytes, accept_message_id, transcript_digest, "
                    "client_key, phase, blocked, revision FROM sessions WHERE session_id=?",
                    (outer.session_id,),
                ).fetchone()
                if row is None and _session_expired(connection, outer.session_id):
                    raise SessionExpiredError("session expired")  # noqa: TRY301
                if row is None or row[5] == "RESERVED":
                    raise LiveSessionStoreError("no committed accept for session")  # noqa: TRY301
                init_bytes, accept_bytes, accept_id, digest, client, phase, blocked, revision = row
                admitted = None
                if phase in OPEN_PHASES:
                    admitted = connection.execute(
                        "SELECT message_id, canonical_bytes, admitted_revision, unsigned_digest "
                        "FROM inbox WHERE session_id=? AND sender_key=? AND seq=1",
                        (outer.session_id, client),
                    ).fetchone()
                    if admitted is not None and admitted[1] == confirm_document and not blocked:
                        return ConfirmAdmission(
                            outer.session_id, admitted[0], digest, admitted[2], replay=True
                        )
                if blocked:
                    raise SessionBlockedError("session blocked by conflict evidence")  # noqa: TRY301
                transcript = verify_static_handshake_transcript(
                    init_bytes,
                    accept_bytes,
                    confirm_document,
                    **self._expectations(),  # type: ignore[arg-type]
                ).hex()
                if transcript != digest:
                    raise LiveSessionStoreError("confirm transcript differs")  # noqa: TRY301
                # RS-001 conflicts are defined over unsigned canonical bytes: a
                # different valid signature over the same content is a replay,
                # answered with the originally recorded result.
                if admitted is not None and unsigned_envelope_hash(outer).hex() == admitted[3]:
                    return ConfirmAdmission(
                        outer.session_id, admitted[0], digest, admitted[2], replay=True
                    )
                equivocation = phase in OPEN_PHASES
                if equivocation:
                    _record_conflict(connection, outer.session_id, "confirm", confirm_document)
                else:
                    admitted_revision = revision + 1
                    connection.execute(
                        "INSERT INTO inbox VALUES (?, ?, ?, 1, ?, ?, ?)",
                        (
                            outer.session_id,
                            client,
                            outer.message_id,
                            unsigned_envelope_hash(outer).hex(),
                            confirm_document,
                            admitted_revision,
                        ),
                    )
                    connection.execute(
                        "UPDATE sessions SET phase='CONFIRMED', revision=?, next_client_seq=2, "
                        "active_at=? WHERE session_id=?",
                        (
                            admitted_revision,
                            int(time.time()) if now is None else now,
                            outer.session_id,
                        ),
                    )
                    # The confirm is the application acknowledgment of the accept.
                    connection.execute(
                        "UPDATE outbox SET delivery_state='ACKED' "
                        "WHERE message_id=? AND delivery_state='PENDING'",
                        (accept_id,),
                    )
        except LiveSessionStoreError:
            raise
        except Exception:  # noqa: BLE001 - never echo caller documents or crypto details
            raise LiveSessionStoreError("confirm admission refused") from None
        if equivocation:
            raise SessionBlockedError("conflicting signed confirm is durable")
        return ConfirmAdmission(
            outer.session_id, outer.message_id, digest, admitted_revision, replay=False
        )

    def rotate_epochs(
        self, *, now: int, period: int, retention: int, advertise_for: int
    ) -> tuple[str, ...]:
        """Ensure a current epoch inbox key; return keys to advertise, newest first.

        A new epoch starts when the newest is ``period`` seconds old. Each key
        keeps decoding until ``created_at + period + retention``; set
        ``retention`` to at least the announcement lifetime so late inits
        still decode. Only keys that stay decodable for ``advertise_for``
        more seconds are returned (announcement lifetime plus delivery grace),
        so a valid announcement never names a key about to retire. Epoch keys
        only receive public inits (availability, not authority), and their
        sealed secrets bind this store.
        """
        if not (
            type(now) is int
            and type(period) is int
            and type(retention) is int
            and type(advertise_for) is int
            and 0 <= advertise_for <= retention
            and now > 0
            and period > 0
            and retention >= 0
        ):
            raise LiveSessionStoreError("epoch schedule unsupported")
        try:
            with self._write() as connection:
                newest = connection.execute("SELECT MAX(created_at) FROM epochs").fetchone()[0]
                if now < _epoch_watermark(connection) or (newest is not None and now < newest):
                    raise LiveSessionStoreError("clock is behind the newest epoch")  # noqa: TRY301
                _retire_epochs(connection, now)
                if newest is None or now >= newest + period:
                    xonly, sealed = self._new_epoch_key(now)
                    connection.execute("INSERT INTO epoch_key_history VALUES (?)", (xonly,))
                    connection.execute(
                        "INSERT INTO epochs VALUES (?, ?, ?, ?)",
                        (xonly, sealed, now, now + period + retention),
                    )
                rows = connection.execute(
                    "SELECT epoch_key FROM epochs WHERE retire_after > ? "
                    "ORDER BY created_at DESC LIMIT ?",
                    (now + advertise_for, MAX_ADVERTISED_EPOCHS),
                ).fetchall()
        except LiveSessionStoreError:
            raise
        except Exception:  # noqa: BLE001 - never echo secret material or library errors
            raise LiveSessionStoreError("epoch rotation refused") from None
        return tuple(row[0] for row in rows)

    def _epoch_record(self, scalar: bytes, xonly: str, created_at: int) -> bytes:
        return canonicalize(
            {
                "kind": EPOCH_RECORD_KIND,
                "secret_scalar": scalar.hex(),
                "xonly_public_key": xonly,
                "store_uuid": self._store_uuid,
                "created_at": created_at,
            }
        )

    def _new_epoch_key(self, created_at: int) -> tuple[str, bytes]:
        scalar = _new_epoch_scalar()
        xonly = _xonly(self._public_keys, scalar)
        if xonly == self._identity:
            raise LiveSessionStoreError("epoch key collides with identity")
        record = self._epoch_record(scalar, xonly, created_at)
        sealed = pyrage.encrypt(record, [self._custody_identity.to_public()])
        if type(sealed) is not bytes or pyrage.decrypt(sealed, [self._custody_identity]) != record:
            raise LiveSessionStoreError("epoch key custody not verifiable")
        return xonly, sealed

    def open_epoch_frame(
        self, outer_event: bytes, *, now: int, transport: Context
    ) -> EpochInitiation:
        """Decode a gift-wrapped handshake_init sent to an unretired epoch inbox.

        Returns exact canonical init bytes whose envelope sender is the seal
        author, plus its recipient epoch. Pass this result to ``reserve``,
        which applies every init rule. Refusals are uniform and redacted.
        """
        try:
            recipient = _routing_recipient(outer_event)
            with self._write() as connection:
                row = connection.execute(
                    "SELECT secret_age, created_at FROM epochs "
                    "WHERE epoch_key=? AND retire_after > ?",
                    (recipient, max(now, _epoch_watermark(connection))),
                ).fetchone()
            if row is None:
                raise LiveSessionStoreError("frame for unknown or retired epoch")  # noqa: TRY301
            plaintext = pyrage.decrypt(row[0], [self._custody_identity])
            scalar = bytes.fromhex(json.loads(plaintext)["secret_scalar"])
            try:
                if not (
                    plaintext == self._epoch_record(scalar, recipient, row[1])
                    and _xonly(self._public_keys, scalar) == recipient
                ):
                    raise LiveSessionStoreError("epoch key custody unavailable")
                candidate = _decode_gift_wrap_candidate(
                    outer_event,
                    recipient_mailbox_secret=scalar,
                    expected_recipient_xonly_key=recipient,
                    expected_network=self._network,
                    expected_profile_id=self._policy.profile,
                    crypto=transport,
                )
            finally:
                del scalar
            if not (
                candidate.envelope.message_type == "handshake_init"
                and candidate.envelope.sender_session_key == candidate.seal_author_xonly_key
            ):
                raise LiveSessionStoreError("epoch frame is not a sender-bound init")  # noqa: TRY301
        except LiveSessionStoreError:
            raise
        except Exception:  # noqa: BLE001 - uniform, redacted refusal (RS-006)
            raise LiveSessionStoreError("epoch frame refused") from None
        return EpochInitiation(candidate.envelope_bytes, recipient)

    def expire_idle(self, *, now: int, idle_timeout: int) -> int:
        """Expire idle pre-economic sessions without discarding replay protection.

        A session idle for ``idle_timeout`` (reserved, accepted, or confirmed
        with nothing after the confirm) loses its key, messages, and conflict
        evidence (SQLite ``secure_delete``). Legacy IDs stay in ``expired``
        forever. Epoch-bound IDs stay in ``epoch_admissions`` until their
        recipient epoch has durably retired. Accepted contracts never enter
        this deletion path. Returns how many sessions expired.
        """
        if not (type(now) is int and type(idle_timeout) is int and idle_timeout > 0):
            raise LiveSessionStoreError("expiry schedule unsupported")
        try:
            with self._write() as connection:
                _retire_epochs(connection, now)
                idle = [
                    (row[0],)
                    for row in connection.execute(
                        "SELECT session_id FROM sessions WHERE phase IN "
                        "('RESERVED', 'ACCEPT_COMMITTED', 'CONFIRMED') AND active_at <= ?",
                        (now - idle_timeout,),
                    )
                ]
                # Release before deletion: an idle session's open offer can never
                # be accepted again. Its payment hash stays reserved forever.
                # UNKNOWN (migrated) rows of a pre-acceptance session never had a
                # contract either: nothing was dispatched for a hash with no swap.
                connection.executemany(
                    "UPDATE economic_reservations SET state='RELEASED', release_evidence=? "
                    "WHERE session_id=? AND state IN ('UNSENT', 'UNKNOWN') "
                    "AND session_id NOT IN (SELECT session_id FROM swaps)",
                    [(_release_evidence("expired-offer", expired_at=now), sid) for (sid,) in idle],
                )
                for (sid,) in idle:
                    marked = connection.execute(
                        "UPDATE epoch_admissions SET expired=1 WHERE session_id=?", (sid,)
                    ).rowcount
                    if not marked:
                        connection.execute("INSERT INTO expired VALUES (?, ?)", (sid, now))
                for table in ("inbox", "outbox", "conflicts", "contract_keys", "sessions"):
                    connection.executemany(
                        f"DELETE FROM {table} WHERE session_id=?",  # noqa: S608 - fixed names
                        idle,
                    )
                connection.execute(
                    "DELETE FROM epoch_admissions WHERE expired=1 AND retire_after <= ?",
                    (_epoch_watermark(connection),),
                )
        except LiveSessionStoreError:
            raise
        except Exception:  # noqa: BLE001 - never echo storage details
            raise LiveSessionStoreError("session expiry refused") from None
        return len(idle)

    def receiving_epochs(self, *, now: int) -> tuple[str, ...]:
        """Return every still-decodable epoch key, advertised or not."""
        try:
            with self._write() as connection:
                rows = connection.execute(
                    "SELECT epoch_key FROM epochs WHERE retire_after > ? ORDER BY created_at DESC",
                    (max(now, _epoch_watermark(connection)),),
                ).fetchall()
        except LiveSessionStoreError:
            raise
        except Exception:  # noqa: BLE001 - never echo storage details
            raise LiveSessionStoreError("epoch keys unavailable") from None
        return tuple(row[0] for row in rows)

    def record_announcement(self, created_at: int) -> None:
        """Durably order an RS-005 announcement revision before publishing it.

        Revisions equal ``created_at`` and must strictly increase across
        restarts; a clock rollback is refused rather than published lower.
        """
        if type(created_at) is not int or created_at <= 0:
            raise LiveSessionStoreError("announcement time unsupported")
        try:
            with self._write() as connection:
                row = connection.execute(
                    "SELECT created_at FROM announcements WHERE slot=1"
                ).fetchone()
                if row is not None and created_at <= row[0]:
                    raise LiveSessionStoreError("announcement revision would not increase")  # noqa: TRY301
                connection.execute(
                    "INSERT OR REPLACE INTO announcements VALUES (1, ?)", (created_at,)
                )
        except LiveSessionStoreError:
            raise
        except Exception:  # noqa: BLE001 - never echo storage details
            raise LiveSessionStoreError("announcement ordering refused") from None

    def answer_request(  # noqa: PLR0912, PLR0915 - one admission transaction
        self,
        request_document: bytes,
        *,
        responder: Responder,
        signer: EnvelopeSigner,
        now: int | None = None,
    ) -> RequestAnswer:
        """Admit one signed client request and durably record its signed answer.

        One transaction checks the client session-key signature and the
        contiguous sequence, calls the pure ``responder`` for the answer
        payload, signs it with the session key, and records both. Only then may
        the answer be published (via ``pending_outbox``). An exact replay,
        even with a fresh signature, returns the recorded answer. A different
        validly signed message reusing a message ID or sequence is kept as
        evidence and blocks the session. Anything unverifiable, out of order,
        or over budget is refused with no record and no reply.
        """
        now = int(time.time()) if now is None else now
        conflict = False
        try:
            outer = _canonical_envelope(request_document)
            with self._write() as connection:
                row = connection.execute(
                    "SELECT client_key, provider_session_key, phase, blocked, revision, "
                    "next_client_seq, next_provider_seq, transcript_digest "
                    "FROM sessions WHERE session_id=?",
                    (outer.session_id,),
                ).fetchone()
                if row is None and _session_expired(connection, outer.session_id):
                    raise SessionExpiredError("session expired")  # noqa: TRY301
                if row is None or row[2] not in OPEN_PHASES:
                    raise LiveSessionStoreError("no confirmed session")  # noqa: TRY301
                client, key, _, blocked, revision, client_seq, provider_seq, transcript = row
                if blocked:
                    raise SessionBlockedError("session blocked by conflict evidence")  # noqa: TRY301
                digest = verify_static_signed_envelope(
                    request_document,
                    expected_session_id=outer.session_id,
                    expected_profile=self._policy.profile,
                    expected_network=self._network,
                    expected_sender_key=client,
                    supported_features=self._policy.features,
                    crypto=self._crypto,
                ).hex()
                # Unlike a request, a cooperative result has no response
                # outbox and has its own conflict admission boundary.
                if outer.message_type == "action_result":
                    raise LiveSessionStoreError("request not admissible")  # noqa: TRY301
                seen = connection.execute(
                    "SELECT message_id, seq, unsigned_digest FROM inbox "
                    "WHERE session_id=? AND sender_key=? AND (message_id=? OR seq=?)",
                    (outer.session_id, client, outer.message_id, outer.sequence),
                ).fetchall()
                if seen:
                    if seen == [(outer.message_id, outer.sequence, digest)]:
                        if outer.message_type not in CLIENT_REQUEST_TYPES:
                            raise LiveSessionStoreError("request not admissible")  # noqa: TRY301
                        answer = connection.execute(
                            "SELECT message_id FROM outbox WHERE session_id=? AND in_reply_to=?",
                            (outer.session_id, outer.message_id),
                        ).fetchone()
                        return RequestAnswer(
                            outer.session_id, outer.message_id, answer[0], replay=True
                        )
                    _record_conflict(connection, outer.session_id, "request", request_document)
                    connection.execute(
                        "UPDATE sessions SET blocked=1, revision=revision + 1 WHERE session_id=?",
                        (outer.session_id,),
                    )
                    conflict = True
                else:
                    replied = None
                    if outer.in_reply_to is not None:
                        replied = connection.execute(
                            "SELECT canonical_bytes FROM outbox "
                            "WHERE session_id=? AND message_id=?",
                            (outer.session_id, outer.in_reply_to),
                        ).fetchone()
                    if not (
                        outer.sequence == client_seq
                        and outer.message_type in CLIENT_REQUEST_TYPES
                        and (outer.in_reply_to is None or replied is not None)
                        and client_seq - FIRST_REQUEST_SEQUENCE < MAX_REQUESTS_PER_SESSION
                    ):
                        raise LiveSessionStoreError("request not admissible")  # noqa: TRY301
                    prior = tuple(
                        _canonical_envelope(document)
                        for (document,) in connection.execute(
                            "SELECT canonical_bytes FROM inbox WHERE session_id=? "
                            "AND sender_key=? AND seq>=? ORDER BY seq",
                            (outer.session_id, client, FIRST_REQUEST_SEQUENCE),
                        )
                    )
                    context = RequestContext(
                        handshake_hash=transcript,
                        provider_contract_key=self._contract_key(connection, outer.session_id),
                        replied_to=None if replied is None else _canonical_envelope(replied[0]),
                        swap=_swap(connection, outer.session_id),
                        economic_capacity_available=self._economic_capacity(
                            connection, outer.session_id
                        ),
                        is_payment_hash_reserved=lambda digest: (
                            connection.execute(
                                "SELECT 1 FROM payment_hashes WHERE payment_hash=?", (digest,)
                            ).fetchone()
                            is not None
                        ),
                    )
                    reply = responder(outer, prior, context)
                    if reply.effect is not None:
                        _apply_effect(connection, outer, reply.effect, replied, now)
                    if reply.payment_hash is not None:
                        connection.execute(
                            "INSERT INTO payment_hashes VALUES (?, ?, ?)",
                            (reply.payment_hash, outer.session_id, now),
                        )
                        self._reserve_offer(connection, outer.session_id, reply.payment_hash)
                    scalar, _ = self._unseal(connection, outer.session_id)
                    try:
                        response = self._signed_envelope(
                            outer, key, provider_seq, reply, scalar, signer, outer.message_id
                        )
                    finally:
                        del scalar
                    admitted = revision + 1
                    connection.execute(
                        "INSERT INTO inbox VALUES (?, ?, ?, ?, ?, ?, ?)",
                        (
                            outer.session_id,
                            client,
                            outer.message_id,
                            outer.sequence,
                            digest,
                            request_document,
                            admitted,
                        ),
                    )
                    connection.execute(
                        "INSERT INTO outbox VALUES (?, ?, ?, ?, ?, ?, 'PENDING')",
                        (
                            response.message_id,
                            outer.session_id,
                            provider_seq,
                            outer.message_id,
                            canonicalize(response.model_dump(mode="json")),
                            admitted,
                        ),
                    )
                    connection.execute(
                        "UPDATE sessions SET revision=?, next_client_seq=?, "
                        "next_provider_seq=?, active_at=? WHERE session_id=?",
                        (admitted, client_seq + 1, provider_seq + 1, now, outer.session_id),
                    )
        except LiveSessionStoreError:
            raise
        except Exception:  # noqa: BLE001 - never echo caller documents or crypto details
            raise LiveSessionStoreError("request refused") from None
        if conflict:
            raise SessionBlockedError("conflicting signed request is durable")
        return RequestAnswer(outer.session_id, outer.message_id, response.message_id, replay=False)

    def _admit_cooperative_result(  # noqa: PLR0912, PLR0915 - one signed admission transaction
        self, document: bytes, *, now: int
    ) -> CooperativeResultAdmission:
        """Record one authenticated client disposition without signing or replying.

        INTERNAL ONLY. An admitted partial is not permission to sign: the
        process-local native handle, current chain facts, deadline, and exact
        spending policy must be checked again by a later signing operation.
        Exact signed replays, even after restart, return a receipt only.
        Invalid replies are rejected without consuming sequence or changing
        the attempt. A future runtime must independently trigger unilateral
        fallback on refusal, invalid response, or the bounded timeout.
        """
        if type(now) is not int or now < 0:
            raise LiveSessionStoreError("cooperative result time unsupported")
        abandon: bytes | None = None
        conflict = False
        status = ""
        try:
            outer = _canonical_envelope(document)
            with self._write() as connection:
                session = connection.execute(
                    "SELECT client_key,phase,blocked,revision,next_client_seq,"
                    "init_bytes,accept_bytes FROM sessions WHERE session_id=?",
                    (outer.session_id,),
                ).fetchone()
                if session is None or session[1] != "ACCEPTED":
                    raise LiveSessionStoreError("no accepted cooperative session")  # noqa: TRY301
                client, _, blocked, revision, client_seq, init_bytes, accept_bytes = session
                digest = verify_static_signed_envelope(
                    document,
                    expected_session_id=outer.session_id,
                    expected_profile=self._policy.profile,
                    expected_network=self._network,
                    expected_sender_key=client,
                    supported_features=self._policy.features,
                    crypto=self._crypto,
                ).hex()
                if outer.message_type != "action_result":
                    raise LiveSessionStoreError("cooperative result type unsupported")  # noqa: TRY301
                seen = connection.execute(
                    "SELECT message_id,seq,unsigned_digest FROM inbox "
                    "WHERE session_id=? AND sender_key=? AND (message_id=? OR seq=?)",
                    (outer.session_id, client, outer.message_id, outer.sequence),
                ).fetchall()
                if seen:
                    if seen == [(outer.message_id, outer.sequence, digest)]:
                        replay = parse_cooperative_payload(
                            "action_result", canonicalize(outer.payload)
                        )
                        if not isinstance(
                            replay, (CooperativeClaimSigned, CooperativeClaimDeclined)
                        ):
                            raise LiveSessionStoreError("cooperative replay type unsupported")  # noqa: TRY301
                        return CooperativeResultAdmission(
                            outer.session_id, outer.message_id, replay.status, replay=True
                        )
                    _record_conflict(connection, outer.session_id, "request", document)
                    connection.execute(
                        "UPDATE cooperation_attempts SET state='ABANDONED' "
                        "WHERE session_id=? AND state IN ('BURNED','NONCE_READY','SIGNING')",
                        (outer.session_id,),
                    )
                    attempt = connection.execute(
                        "SELECT cooperation_id FROM cooperation_attempts WHERE session_id=?",
                        (outer.session_id,),
                    ).fetchone()
                    abandon = None if attempt is None else attempt[0]
                    conflict = True
                else:
                    if (
                        blocked
                        or outer.sequence != client_seq
                        or client_seq - FIRST_REQUEST_SEQUENCE >= MAX_REQUESTS_PER_SESSION
                    ):
                        raise LiveSessionStoreError("cooperative result out of sequence")  # noqa: TRY301
                    payload = parse_cooperative_payload(
                        "action_result", canonicalize(outer.payload)
                    )
                    if not isinstance(payload, (CooperativeClaimSigned, CooperativeClaimDeclined)):
                        raise LiveSessionStoreError("cooperative result status unsupported")  # noqa: TRY301
                    status = payload.status
                    cooperation_id = bytes.fromhex(payload.cooperation_id)
                    row = connection.execute(
                        "SELECT a.binding,a.owner_generation,a.created_at,a.deadline_at,a.state,"
                        "a.local_nonce,a.nonce_response_id,w.contract_hash,w.terms_offer,"
                        "w.funding_binding,w.preimage,w.state "
                        "FROM cooperation_attempts a JOIN swaps w ON w.session_id=a.session_id "
                        "WHERE a.session_id=? AND a.cooperation_id=?",
                        (outer.session_id, cooperation_id),
                    ).fetchone()
                    if row is None:
                        raise LiveSessionStoreError("cooperative proposal unavailable")  # noqa: TRY301
                    (
                        binding_bytes,
                        generation,
                        created_at,
                        deadline_at,
                        state,
                        local_nonce,
                        proposal_id,
                        recorded_hash,
                        offer_bytes,
                        funding_bytes,
                        preimage,
                        swap_state,
                    ) = row
                    binding = parse_json_strict(binding_bytes)
                    if not isinstance(binding, dict) or (
                        generation != self._generation
                        or state != "NONCE_READY"
                        or not created_at <= now < deadline_at
                        or swap_state not in ("PAID", "CLAIMING")
                        or not isinstance(local_nonce, bytes)
                        or not isinstance(proposal_id, str)
                        or binding.get("version") != 1
                        or binding.get("session_id") != outer.session_id
                        or binding.get("cooperation_id") != payload.cooperation_id
                        or binding.get("contract_hash") != recorded_hash
                        or binding.get("deadline_at") != deadline_at
                        or funding_bytes is None
                        or not isinstance(preimage, str)
                        or re.fullmatch(r"[0-9a-f]{64}", preimage) is None
                    ):
                        raise LiveSessionStoreError("cooperative proposal no longer current")  # noqa: TRY301
                    terms = _offer_terms(offer_bytes)
                    funding = parse_model_json(
                        FundingBindingPayload,
                        canonicalize(_canonical_envelope(funding_bytes).payload),
                    ).binding
                    if (
                        contract_hash(terms).hex() != recorded_hash
                        or COOPERATIVE_CLAIM_FEATURE not in terms.required_features
                        or hashlib.sha256(bytes.fromhex(preimage)).hexdigest()
                        != terms.invoice_binding.payment_hash
                        or funding.contract_hash != recorded_hash
                        or funding.funding_txid != binding.get("funding_txid")
                        or funding.contract_vout != binding.get("funding_vout")
                        or int(funding.contract_value_sat) != binding.get("funding_value_sat")
                        or funding.contract_script_pubkey != binding.get("funding_script_pubkey")
                    ):
                        raise LiveSessionStoreError("cooperative funding differs")  # noqa: TRY301
                    saved = connection.execute(
                        "SELECT canonical_bytes FROM outbox WHERE session_id=? AND message_id=?",
                        (outer.session_id, proposal_id),
                    ).fetchone()
                    if saved is None:
                        raise LiveSessionStoreError("cooperative proposal transcript missing")  # noqa: TRY301
                    proposal = _canonical_envelope(saved[0])
                    original = parse_cooperative_payload(
                        "action_request", canonicalize(proposal.payload)
                    )
                    if not isinstance(original, CooperativeClaimPropose) or (
                        proposal.message_id != proposal_id
                        or original.cooperation_id != payload.cooperation_id
                        or original.public_nonce != local_nonce.hex()
                        or original.unsigned_transaction != binding.get("unsigned_transaction")
                        or original.payment_preimage != preimage
                        or original.deadline_at != deadline_at
                        or original.deadline_height != binding.get("deadline_height")
                    ):
                        raise LiveSessionStoreError("cooperative proposal differs")  # noqa: TRY301
                    initiation = parse_model_json(
                        HandshakeInit,
                        canonicalize(_canonical_envelope(init_bytes).payload),
                    )
                    acceptance = parse_model_json(
                        HandshakeAccept,
                        canonicalize(_canonical_envelope(accept_bytes).payload["accept"]),
                    )
                    checked = check_cooperative_action_context(
                        outer, terms, initiation, acceptance, prior_request=proposal
                    )
                    if checked != payload:
                        raise LiveSessionStoreError("cooperative result context differs")  # noqa: TRY301
                    if isinstance(payload, CooperativeClaimSigned):
                        from rill_crypto import Context  # noqa: PLC0415 - native partial boundary

                        if (
                            not isinstance(self._crypto, Context)
                            or cooperation_id not in self._cooperation_handles
                        ):
                            raise LiveSessionStoreError("cooperative signer custody lost")  # noqa: TRY301
                        crypto = self._crypto
                        peer_nonce = bytes.fromhex(payload.public_nonce)
                        crypto.musig_public_nonce_validate(local_nonce)
                        crypto.musig_public_nonce_validate(peer_nonce)
                        crypto.musig_partial_verify(
                            user_public_key=bytes.fromhex(terms.client_contract_compressed_key),
                            provider_public_key=bytes.fromhex(
                                terms.provider_contract_compressed_key
                            ),
                            tap_tweak=bytes.fromhex(str(binding["tap_tweak"])),
                            message=bytes.fromhex(str(binding["signature_hash"])),
                            user_public_nonce=peer_nonce,
                            provider_public_nonce=local_nonce,
                            signer_index=0,
                            partial_signature=bytes.fromhex(payload.partial_signature),
                        )
                        update: tuple[str, bytes | None] = ("SIGNING", peer_nonce)
                    else:
                        update = ("ABANDONED", None)
                        abandon = cooperation_id
                    connection.execute(
                        "INSERT INTO inbox VALUES (?,?,?,?,?,?,?)",
                        (
                            outer.session_id,
                            client,
                            outer.message_id,
                            outer.sequence,
                            digest,
                            document,
                            revision + 1,
                        ),
                    )
                    if (
                        connection.execute(
                            "UPDATE cooperation_attempts SET state=?,peer_nonce=? "
                            "WHERE session_id=? AND cooperation_id=? AND state='NONCE_READY' "
                            "AND owner_generation=?",
                            (*update, outer.session_id, cooperation_id, self._generation),
                        ).rowcount
                        != 1
                    ):
                        raise LiveSessionStoreError("cooperative attempt changed")  # noqa: TRY301
                    connection.execute(
                        "UPDATE sessions SET next_client_seq=?,revision=?,active_at=? "
                        "WHERE session_id=?",
                        (client_seq + 1, revision + 1, now, outer.session_id),
                    )
        except LiveSessionStoreError:
            raise
        except Exception:  # noqa: BLE001 - never echo nonce, partial or signed documents
            raise LiveSessionStoreError("cooperative result refused") from None
        if abandon is not None:
            live = self._cooperation_handles.pop(abandon, None)
            if live is not None:
                live.close()
        if conflict:
            raise SessionBlockedError("conflicting signed cooperative result is durable")
        return CooperativeResultAdmission(outer.session_id, outer.message_id, status, replay=False)

    def _commit_cooperative_claim_partial(  # noqa: PLR0912, PLR0915 - one-shot custody transition
        self,
        session_id: str,
        cooperation_id: bytes,
        observation: CooperativeClaimObservation,
        *,
        now: int,
    ) -> str:
        """Consume one live handle and commit the signed completion before exposure.

        INTERNAL ONLY. A future runtime must obtain a fresh, named-tip,
        mempool-aware sample immediately before invocation and independently
        schedule unilateral fallback. This method never broadcasts.
        """
        from rill_crypto import Context  # noqa: PLC0415 - native signer only

        if (
            not isinstance(self._crypto, Context)
            or self._public_keys is not self._crypto
            or not isinstance(cooperation_id, bytes)
            or len(cooperation_id) != 32  # noqa: PLR2004 - burned ID length
            or not isinstance(observation, CooperativeClaimObservation)
            or type(now) is not int
            or now < 0
            or observation.network != self._network
            or type(observation.sampled_at) is not int
            or not 0 <= observation.sampled_at <= now
            or now - observation.sampled_at > COOPERATION_OBSERVATION_MAX_AGE_SECONDS
            or type(observation.tip_height) is not int
            or observation.tip_height <= 0
            or type(observation.confirmations) is not int
            or observation.confirmations < 0
            or type(observation.fee_floor_sat) is not int
            or observation.fee_floor_sat < 0
            or type(observation.funding_vout) is not int
            or observation.funding_vout < 0
            or type(observation.funding_value_sat) is not int
            or observation.funding_value_sat <= 0
            or type(observation.funding_script_pubkey) is not bytes
            or observation.mempool_unspent is not True
            or type(observation.tip_hash) is not str
            or HEX32.fullmatch(observation.tip_hash) is None
            or type(observation.funding_txid) is not str
            or HEX32.fullmatch(observation.funding_txid) is None
        ):
            raise LiveSessionStoreError("cooperative signing observation unavailable")
        crypto = self._crypto
        consumed = False
        try:
            with self._write() as connection:
                row = connection.execute(
                    "SELECT a.binding,a.owner_generation,a.created_at,a.deadline_at,a.state,"
                    "a.local_nonce,a.peer_nonce,a.nonce_response_id,s.phase,s.blocked,"
                    "s.client_key,w.state,w.contract_hash,w.terms_offer,w.funding_binding,"
                    "w.preimage FROM cooperation_attempts a "
                    "JOIN sessions s ON s.session_id=a.session_id "
                    "JOIN swaps w ON w.session_id=a.session_id "
                    "WHERE a.session_id=? AND a.cooperation_id=?",
                    (session_id, cooperation_id),
                ).fetchone()
                if row is None:
                    raise LiveSessionStoreError("cooperative signer attempt unavailable")  # noqa: TRY301
                (
                    binding_bytes,
                    generation,
                    created_at,
                    deadline_at,
                    state,
                    local_nonce,
                    peer_nonce,
                    proposal_id,
                    phase,
                    blocked,
                    client_key,
                    swap_state,
                    recorded_hash,
                    offer_bytes,
                    funding_bytes,
                    preimage,
                ) = row
                binding = parse_json_strict(binding_bytes)
                if not isinstance(binding, dict) or (
                    generation != self._generation
                    or state != "SIGNING"
                    or phase != "ACCEPTED"
                    or blocked
                    or swap_state not in ("PAID", "CLAIMING")
                    or cooperation_id not in self._cooperation_handles
                    or not created_at <= now < deadline_at
                    or binding.get("version") != 1
                    or binding.get("session_id") != session_id
                    or binding.get("cooperation_id") != cooperation_id.hex()
                    or binding.get("contract_hash") != recorded_hash
                    or binding.get("claimant") != "provider"
                    or binding.get("deadline_at") != deadline_at
                    or not isinstance(local_nonce, bytes)
                    or not isinstance(peer_nonce, bytes)
                    or not isinstance(proposal_id, str)
                    or funding_bytes is None
                    or not isinstance(preimage, str)
                    or re.fullmatch(r"[0-9a-f]{64}", preimage) is None
                ):
                    raise LiveSessionStoreError("cooperative signing custody unavailable")  # noqa: TRY301
                terms = _offer_terms(offer_bytes)
                fee_sat = binding.get("fee_sat")
                deadline_height = binding.get("deadline_height")
                if (
                    type(fee_sat) is not int
                    or fee_sat < 0
                    or type(deadline_height) is not int
                    or deadline_height <= 0
                ):
                    raise LiveSessionStoreError("cooperative signing plan malformed")  # noqa: TRY301
                retained = parse_model_json(
                    FundingBindingPayload,
                    canonicalize(_canonical_envelope(funding_bytes).payload),
                ).binding
                if (
                    contract_hash(terms).hex() != recorded_hash
                    or terms.network_identity != self._network
                    or COOPERATIVE_CLAIM_FEATURE not in terms.required_features
                    or hashlib.sha256(bytes.fromhex(preimage)).hexdigest()
                    != terms.invoice_binding.payment_hash
                    or retained.contract_hash != recorded_hash
                    or retained.funding_txid != binding.get("funding_txid")
                    or retained.contract_vout != binding.get("funding_vout")
                    or int(retained.contract_value_sat) != binding.get("funding_value_sat")
                    or retained.contract_script_pubkey != binding.get("funding_script_pubkey")
                    or observation.funding_txid != retained.funding_txid
                    or observation.funding_vout != retained.contract_vout
                    or observation.funding_value_sat != int(retained.contract_value_sat)
                    or observation.funding_script_pubkey.hex() != retained.contract_script_pubkey
                    or observation.confirmations < terms.funding_confirmations
                    or observation.tip_height >= terms.refund_lock_height
                    or observation.tip_height >= deadline_height
                    or fee_sat < observation.fee_floor_sat
                ):
                    raise LiveSessionStoreError("cooperative signing facts changed")  # noqa: TRY301
                funding = FundingOutput(
                    txid=bytes.fromhex(retained.funding_txid),
                    output_index=retained.contract_vout,
                    value_sat=int(retained.contract_value_sat),
                    script_pubkey=bytes.fromhex(retained.contract_script_pubkey),
                )
                authorization = UnilateralAuthorization.from_terms(
                    terms, funding, "claim", keys=crypto
                )
                plan = build_cooperative_claim(authorization, fee_sat=fee_sat)
                taproot = reconstruct_taproot_contract(terms, keys=crypto)
                if (
                    plan.base_transaction.hex() != binding.get("unsigned_transaction")
                    or plan.signature_hash.hex() != binding.get("signature_hash")
                    or terms.client_contract_compressed_key != binding.get("user_key")
                    or terms.provider_contract_compressed_key != binding.get("provider_key")
                    or taproot.tap_tweak.hex() != binding.get("tap_tweak")
                ):
                    raise LiveSessionStoreError("cooperative claim plan differs")  # noqa: TRY301
                saved = connection.execute(
                    "SELECT canonical_bytes FROM outbox WHERE session_id=? AND message_id=?",
                    (session_id, proposal_id),
                ).fetchone()
                if saved is None:
                    raise LiveSessionStoreError("cooperative proposal missing")  # noqa: TRY301
                proposal = _canonical_envelope(saved[0])
                original = parse_cooperative_payload(
                    "action_request", canonicalize(proposal.payload)
                )
                if not isinstance(original, CooperativeClaimPropose) or (
                    original.cooperation_id != cooperation_id.hex()
                    or original.public_nonce != local_nonce.hex()
                    or original.unsigned_transaction != plan.base_transaction.hex()
                ):
                    raise LiveSessionStoreError("cooperative proposal differs")  # noqa: TRY301
                matches: list[CooperativeClaimSigned] = []
                for (admitted,) in connection.execute(
                    "SELECT canonical_bytes FROM inbox WHERE session_id=? AND sender_key=? "
                    "AND seq>=? ORDER BY seq",
                    (session_id, client_key, FIRST_REQUEST_SEQUENCE),
                ):
                    candidate = _canonical_envelope(admitted)
                    if (
                        candidate.message_type != "action_result"
                        or candidate.in_reply_to != proposal_id
                    ):
                        continue
                    verify_static_signed_envelope(
                        admitted,
                        expected_session_id=session_id,
                        expected_profile=self._policy.profile,
                        expected_network=self._network,
                        expected_sender_key=client_key,
                        supported_features=self._policy.features,
                        crypto=crypto,
                    )
                    result = parse_cooperative_payload(
                        "action_result", canonicalize(candidate.payload)
                    )
                    if isinstance(result, CooperativeClaimSigned) and (
                        result.cooperation_id == cooperation_id.hex()
                        and result.public_nonce == peer_nonce.hex()
                    ):
                        matches.append(result)
                if len(matches) != 1:
                    raise LiveSessionStoreError("cooperative admitted partial unavailable")  # noqa: TRY301
                result = matches[0]
                crypto.musig_public_nonce_validate(peer_nonce)
                crypto.musig_partial_verify(
                    user_public_key=bytes.fromhex(terms.client_contract_compressed_key),
                    provider_public_key=bytes.fromhex(terms.provider_contract_compressed_key),
                    tap_tweak=taproot.tap_tweak,
                    message=plan.signature_hash,
                    user_public_nonce=peer_nonce,
                    provider_public_nonce=local_nonce,
                    signer_index=0,
                    partial_signature=bytes.fromhex(result.partial_signature),
                )
                # Popping BEFORE native consumption makes every failure one-shot.
                handle = self._cooperation_handles.pop(cooperation_id)
                consumed = True
                try:
                    partial = handle.partial_sign_once(peer_nonce)
                finally:
                    handle.close()
                crypto.musig_partial_verify(
                    user_public_key=bytes.fromhex(terms.client_contract_compressed_key),
                    provider_public_key=bytes.fromhex(terms.provider_contract_compressed_key),
                    tap_tweak=taproot.tap_tweak,
                    message=plan.signature_hash,
                    user_public_nonce=peer_nonce,
                    provider_public_nonce=local_nonce,
                    signer_index=1,
                    partial_signature=partial,
                )
                signature = crypto.musig_aggregate(
                    user_public_key=bytes.fromhex(terms.client_contract_compressed_key),
                    provider_public_key=bytes.fromhex(terms.provider_contract_compressed_key),
                    tap_tweak=taproot.tap_tweak,
                    message=plan.signature_hash,
                    user_public_nonce=peer_nonce,
                    provider_public_nonce=local_nonce,
                    user_partial_signature=bytes.fromhex(result.partial_signature),
                    provider_partial_signature=partial,
                )
                finalize_cooperative_claim(plan, signature, verifier=crypto)
                completion = {
                    "action": "cooperative_claim_complete",
                    "cooperation_id": cooperation_id.hex(),
                    "partial_signature": partial.hex(),
                }
                message_id = self._record_observation(
                    connection,
                    session_id,
                    completion,
                    crypto,
                    now,
                    message_type="action_request",
                    required_features=(COOPERATIVE_CLAIM_FEATURE,),
                )
                if (
                    connection.execute(
                        "UPDATE cooperation_attempts SET state='COMPLETE',"
                        "partial_signature=?,partial_response_id=? "
                        "WHERE session_id=? AND cooperation_id=? AND state='SIGNING' "
                        "AND owner_generation=?",
                        (partial, message_id, session_id, cooperation_id, self._generation),
                    ).rowcount
                    != 1
                ):
                    raise LiveSessionStoreError("cooperative signing state changed")  # noqa: TRY301
        except BaseException as error:
            if consumed and os.getpid() == self._pid and self._lock_fd is not None:
                # A rollback cannot restore a consumed native handle.
                with suppress(Exception), self._write() as connection:
                    connection.execute(
                        "UPDATE cooperation_attempts SET state='ABANDONED' "
                        "WHERE session_id=? AND cooperation_id=? AND state='SIGNING' "
                        "AND owner_generation=?",
                        (session_id, cooperation_id, self._generation),
                    )
            if isinstance(error, Exception) and not isinstance(error, LiveSessionStoreError):
                raise LiveSessionStoreError("cooperative signing refused") from None
            raise
        return message_id

    def _signed_envelope(  # noqa: PLR0913, PLR0917 - one envelope's explicit parts
        self,
        request: Envelope,
        key: str,
        sequence: int,
        reply: Answer,
        scalar: bytes,
        signer: EnvelopeSigner,
        in_reply_to: str | None,
        *,
        required_features: tuple[str, ...] = (),
    ) -> Envelope:
        unsigned = Envelope.model_validate_json(
            canonicalize(
                {
                    "protocol": "rillswap",
                    "wire_version": "1",
                    "profile_id": request.profile_id,
                    "network_identity": request.network_identity.model_dump(mode="json"),
                    "session_id": request.session_id,
                    "message_id": _new_message_id(),
                    "sender_session_key": key,
                    "sequence": sequence,
                    "in_reply_to": in_reply_to,
                    "contract_hash": reply.contract_hash,
                    "message_type": reply.message_type,
                    "payload": reply.payload,
                    "required_features": list(required_features),
                    "extensions": {},
                    "signature": None,
                }
            ),
            strict=True,
        )
        digest = unsigned_envelope_hash(unsigned)
        signature = signer.schnorr_sign(scalar, digest, secrets.token_bytes(32))
        self._crypto.schnorr_verify(bytes.fromhex(key), digest, signature)
        return unsigned.model_copy(update={"signature": signature.hex()})

    def _contract_key(self, connection: sqlite3.Connection, session_id: str) -> str:
        """Return this session's provider contract key, creating it once."""
        row = connection.execute(
            "SELECT compressed_key FROM contract_keys WHERE session_id=?", (session_id,)
        ).fetchone()
        if row is not None:
            return str(row[0])
        scalar = _new_session_scalar()
        compressed = bytes(self._public_keys.public_key(scalar)).hex()
        record = canonicalize(
            {
                "kind": CONTRACT_KEY_RECORD_KIND,
                "secret_scalar": scalar.hex(),
                "compressed_public_key": compressed,
                "session_id": session_id,
                "store_uuid": self._store_uuid,
            }
        )
        del scalar
        sealed = pyrage.encrypt(record, [self._custody_identity.to_public()])
        if type(sealed) is not bytes or pyrage.decrypt(sealed, [self._custody_identity]) != record:
            raise LiveSessionStoreError("contract key custody not verifiable")
        connection.execute(
            "INSERT INTO contract_keys VALUES (?, ?, ?)", (session_id, compressed, sealed)
        )
        return compressed

    def classify_request(self, request_document: bytes) -> str:
        """Read-only preflight: ``"new"``, ``"replay"``, or ``"conflict"``.

        Lets the caller skip expensive work (e.g. invoice decoding) for
        replays and unadmissible messages. ``answer_request`` rechecks
        everything; this grants nothing and records nothing.
        """
        try:
            outer = _canonical_envelope(request_document)
            with self._write() as connection:
                row = connection.execute(
                    "SELECT client_key, phase, blocked, next_client_seq FROM sessions "
                    "WHERE session_id=?",
                    (outer.session_id,),
                ).fetchone()
                if row is None or row[1] not in OPEN_PHASES or row[2]:
                    raise LiveSessionStoreError("no open confirmed session")  # noqa: TRY301
                client, _, _, client_seq = row
                digest = verify_static_signed_envelope(
                    request_document,
                    expected_session_id=outer.session_id,
                    expected_profile=self._policy.profile,
                    expected_network=self._network,
                    expected_sender_key=client,
                    supported_features=self._policy.features,
                    crypto=self._crypto,
                ).hex()
                seen = connection.execute(
                    "SELECT message_id, seq, unsigned_digest FROM inbox "
                    "WHERE session_id=? AND sender_key=? AND (message_id=? OR seq=?)",
                    (outer.session_id, client, outer.message_id, outer.sequence),
                ).fetchall()
        except LiveSessionStoreError:
            raise
        except Exception:  # noqa: BLE001 - never echo caller documents or crypto details
            raise LiveSessionStoreError("request refused") from None
        if seen:
            return "replay" if seen == [(outer.message_id, outer.sequence, digest)] else "conflict"
        if outer.sequence != client_seq:
            raise LiveSessionStoreError("request not admissible")
        return "new"

    def settlement_work(self, *, session_id: str | None = None) -> tuple[SettlementItem, ...]:
        """Return funded work, optionally restricted to one exact retained session."""
        if session_id is not None and (
            type(session_id) is not str or HEX32.fullmatch(session_id) is None
        ):
            raise LiveSessionStoreError("settlement session ID unsupported")
        selected = "AND w.session_id=? " if session_id is not None else ""
        parameters = (
            (FIRST_REQUEST_SEQUENCE, session_id)
            if session_id is not None
            else (FIRST_REQUEST_SEQUENCE,)
        )
        try:
            with self._write() as connection:
                rows = connection.execute(
                    "SELECT w.session_id, w.state, s.blocked, w.terms_offer, w.funding_binding, "  # noqa: S608 - only static SQL fragments; bound session ID
                    "i.canonical_bytes, w.preimage, w.claim_tx, w.claim_txid, "
                    "COALESCE(p.state, 'UNKNOWN'), p.payment_hash, p.request, "
                    "w.outpoint_spent_height, w.outpoint_spent_block, w.funding_txid, "
                    "w.funding_vout, w.funding_tx, w.refund_txid, w.refund_tx, "
                    "w.spend_scan_height FROM swaps w "
                    "JOIN sessions s ON s.session_id = w.session_id "
                    "LEFT JOIN payment_dispatch p ON p.session_id = w.session_id "
                    "JOIN inbox i ON i.session_id = w.session_id AND i.sender_key = s.client_key "
                    "AND i.seq = ? WHERE w.state IN ('ACCEPTED', 'FUNDING_SEEN', 'PAYING', 'PAID', "
                    "'CLAIMING', 'LN_HELD', 'FUNDING_SENT', 'FUNDED', 'REFUNDING') "
                    + selected
                    + "ORDER BY w.updated_at, w.session_id",
                    parameters,
                ).fetchall()
                items = tuple(
                    SettlementItem(
                        session_id,
                        state,
                        bool(blocked),
                        offer,
                        binding,
                        # LN to BTC requests carry a payment hash, not an invoice.
                        str(_canonical_envelope(request).payload.get("invoice", "")),
                        preimage,
                        claim_tx,
                        claim_txid,
                        payment_dispatch,
                        bound_payer(record, payment_hash=hashed, network=self._network)
                        if payment_dispatch == "SUBMITTED"
                        else None,
                        spent_height,
                        spent_block,
                        *provider_transactions,
                    )
                    for (
                        session_id,
                        state,
                        blocked,
                        offer,
                        binding,
                        request,
                        preimage,
                        claim_tx,
                        claim_txid,
                        payment_dispatch,
                        hashed,
                        record,
                        spent_height,
                        spent_block,
                        *provider_transactions,
                    ) in rows
                )
        except LiveSessionStoreError:
            raise
        except Exception:  # noqa: BLE001 - never echo storage details
            raise LiveSessionStoreError("settlement work unavailable") from None
        return items

    def advance_reverse_swap(  # noqa: PLR0912, PLR0913 - one atomic transition's explicit parts
        self,
        session_id: str,
        *,
        from_state: str,
        to_state: str,
        signer: EnvelopeSigner,
        now: int,
        funding: tuple[FundingBinding, bytes] | None = None,
        refund: tuple[str, bytes] | None = None,
        preimage: str | None = None,
        refund_confirmations: int | None = None,
        observation: dict[str, Any] | None = None,
    ) -> None:
        """Move one LN to BTC swap forward (RS-004) in one transaction.

        ``LN_HELD`` to ``FUNDING_SENT`` is the one funding grant: it records
        the signed funding ``(binding, raw)``, marks the reservation
        ``DISPATCHED`` in the same transaction (refusing when the reservation
        is not open, so a funding can never be signed twice for one swap),
        and queues the RS-003 ``funding_binding`` message signed with the
        session key so the client can record it in its recovery file.
        ``SETTLED`` needs the preimage of the terms' payment hash (checked
        here, whatever reported it) and releases the reservation: the hold
        invoice pays for the contract. ``REFUNDING`` records the refund
        ``(txid, raw)``; ``REFUNDED`` releases on the refund's depth;
        ``ABORTED`` releases an undispatched reservation (nothing was funded).
        """
        _check_reverse_transition(
            (from_state, to_state),
            funding=funding,
            refund=refund,
            preimage=preimage,
            refund_confirmations=refund_confirmations,
        )
        try:
            with self._write() as connection:
                (offer_bytes,) = connection.execute(
                    "SELECT terms_offer FROM swaps WHERE session_id=? AND state=?",
                    (session_id, from_state),
                ).fetchone() or (None,)
                if offer_bytes is None:
                    raise StaleSwapError("swap state changed")  # noqa: TRY301
                terms = _offer_terms(offer_bytes)
                payment_hash = terms.invoice_binding.payment_hash
                if terms.profile_id != "ln-to-btc/v1":
                    raise LiveSessionStoreError("not an LN to BTC swap")  # noqa: TRY301
                if preimage is not None and (
                    type(preimage) is not str
                    or len(preimage) != 64  # noqa: PLR2004 - hex preimage
                    or hashlib.sha256(bytes.fromhex(preimage)).hexdigest() != payment_hash
                ):
                    raise LiveSessionStoreError("preimage does not match the payment hash")  # noqa: TRY301
                columns = "state=?, preimage=COALESCE(?, preimage), updated_at=?"
                values: list[Any] = [to_state, preimage, now]
                if funding is not None:
                    binding, raw = funding
                    if (
                        binding.contract_hash != _canonical_envelope(offer_bytes).contract_hash
                        or binding.funder_role != "provider"
                    ):
                        raise LiveSessionStoreError("funding binding is for another swap")  # noqa: TRY301
                    columns += ", funding_txid=?, funding_vout=?, funding_tx=?"
                    values.extend((binding.funding_txid, binding.contract_vout, raw))
                if refund is not None:
                    columns += ", refund_txid=?, refund_tx=?"
                    values.extend(refund)
                updated = connection.execute(
                    f"UPDATE swaps SET {columns} WHERE session_id=? AND state=?",  # noqa: S608 - static column list
                    (*values, session_id, from_state),
                ).rowcount
                if updated != 1:
                    raise StaleSwapError("swap state changed")  # noqa: TRY301
                if to_state == "FUNDING_SENT":
                    granted = connection.execute(
                        "UPDATE economic_reservations SET state='DISPATCHED' "
                        "WHERE payment_hash=? AND session_id=? AND state IN ('UNSENT', 'UNKNOWN')",
                        (payment_hash, session_id),
                    ).rowcount
                    if granted != 1:
                        raise LiveSessionStoreError("funding grant refused")  # noqa: TRY301
                if to_state in ("ABORTED", "SETTLED", "REFUNDED"):
                    _release_reverse_terminal(
                        connection,
                        session_id,
                        to_state,
                        now,
                        terms=terms,
                        refund_confirmations=refund_confirmations,
                    )
                if funding is not None:
                    self._record_funding_binding(connection, session_id, funding, signer, now)
                if observation is not None:
                    self._record_observation(connection, session_id, observation, signer, now)
        except LiveSessionStoreError:
            raise
        except Exception:  # noqa: BLE001 - never echo storage details
            raise LiveSessionStoreError("swap transition refused") from None

    def _record_funding_binding(
        self,
        connection: sqlite3.Connection,
        session_id: str,
        funding: tuple[FundingBinding, bytes],
        signer: EnvelopeSigner,
        now: int,
    ) -> None:
        binding, raw = funding
        scalar, _ = self._unseal(connection, session_id)
        try:
            signature = signer.schnorr_sign(
                scalar, funding_binding_hash(binding), secrets.token_bytes(32)
            )
        finally:
            del scalar
        payload = {
            "binding": binding.model_dump(mode="json"),
            "funding_binding_signature": signature.hex(),
            "funding_transaction": raw.hex(),
        }
        self._record_observation(
            connection, session_id, payload, signer, now, message_type="funding_binding"
        )

    def record_spend_scan(self, session_id: str, height: int) -> None:
        """Remember the last block scanned for a spend of this swap's contract."""
        if type(height) is not int or height <= 0:
            raise LiveSessionStoreError("scan height must be a positive block height")
        try:
            with self._write() as connection:
                connection.execute(
                    "UPDATE swaps SET spend_scan_height=? WHERE session_id=? "
                    "AND (spend_scan_height IS NULL OR spend_scan_height < ?)",
                    (height, session_id, height),
                )
        except LiveSessionStoreError:
            raise
        except Exception:  # noqa: BLE001 - never echo storage details
            raise LiveSessionStoreError("scan cursor refused") from None

    def advance_swap(  # noqa: PLR0913 - one atomic transition's explicit parts
        self,
        session_id: str,
        *,
        from_state: str,
        to_state: str,
        signer: EnvelopeSigner,
        now: int,
        preimage: str | None = None,
        claim_tx: bytes | None = None,
        claim_txid: str | None = None,
        claim_fee_sat: int | None = None,
        claim_height: int | None = None,
        failed_by_payer: str | None = None,
        observation: dict[str, Any] | None = None,
    ) -> None:
        """Move one swap forward and record its observation in one transaction.

        ``PAID`` to ``CLAIMING`` records the claim as attempt 0 (with its fee
        and the tip it was built at). ``CLAIMING`` to ``CLAIMED`` must name a
        recorded attempt, which becomes the mirrored claim. ``FAILED`` with
        ``failed_by_payer`` (the node public key that attested the terminal
        failure) also releases a dispatched reservation when that key is the
        dispatch record's bound payer; any other failure keeps capacity.

        Raises ``StaleSwapError`` unless the swap is still in ``from_state``,
        so a crash or a concurrent tick can never apply a transition twice.
        The observation is committed to the outbox before anything sends it.
        """
        if (from_state, to_state) not in SWAP_TRANSITIONS:
            raise LiveSessionStoreError("swap transition unsupported")
        if to_state in ("CLAIMING", "CLAIMED") and (claim_tx is None or claim_txid is None):
            raise LiveSessionStoreError("claim transition needs the exact claim")
        try:
            with self._write() as connection:
                if to_state == "CLAIMED" and connection.execute(
                    "SELECT raw FROM claim_attempts WHERE session_id=? AND txid=?",
                    (session_id, claim_txid),
                ).fetchone() != (claim_tx,):
                    raise LiveSessionStoreError("claim is not a recorded attempt")  # noqa: TRY301
                updated = connection.execute(
                    "UPDATE swaps SET state=?, preimage=COALESCE(?, preimage), "
                    "claim_tx=COALESCE(?, claim_tx), claim_txid=COALESCE(?, claim_txid), "
                    "updated_at=? WHERE session_id=? AND state=?",
                    (to_state, preimage, claim_tx, claim_txid, now, session_id, from_state),
                ).rowcount
                if updated != 1:
                    raise StaleSwapError("swap state changed")  # noqa: TRY301
                if to_state == "CLAIMING":
                    connection.execute(
                        "INSERT INTO claim_attempts VALUES (?, 0, ?, ?, ?, ?)",
                        (session_id, claim_txid, claim_tx, claim_fee_sat, claim_height),
                    )
                if (from_state, to_state) == ("FUNDING_SEEN", "PAYING"):
                    (offer_bytes,) = connection.execute(
                        "SELECT terms_offer FROM swaps WHERE session_id=?", (session_id,)
                    ).fetchone()
                    offer = parse_model_json(
                        TermsOfferPayload, canonicalize(_canonical_envelope(offer_bytes).payload)
                    )
                    connection.execute(
                        "INSERT INTO payment_dispatch VALUES (?, ?, 'UNSENT', NULL)",
                        (session_id, offer.terms.contract_terms.invoice_binding.payment_hash),
                    )
                if to_state in ("FAILED", "CLAIMED", "LOST"):
                    _release_terminal(
                        connection,
                        session_id,
                        to_state,
                        now,
                        failed_by_payer=failed_by_payer,
                        network=self._network,
                    )
                if observation is not None:
                    self._record_observation(connection, session_id, observation, signer, now)
        except LiveSessionStoreError:
            raise
        except Exception:  # noqa: BLE001 - never echo storage or crypto details
            raise LiveSessionStoreError("swap transition refused") from None

    def claim_attempts(self, session_id: str) -> tuple[ClaimAttempt, ...]:
        """Return every recorded claim attempt of one CLAIMING swap, oldest first."""
        try:
            with self._write() as connection:
                rows = connection.execute(
                    "SELECT a.attempt, a.txid, a.raw, a.fee_sat, a.first_seen_height "
                    "FROM claim_attempts a JOIN swaps w ON w.session_id=a.session_id "
                    "WHERE a.session_id=? AND w.state='CLAIMING' ORDER BY a.attempt",
                    (session_id,),
                ).fetchall()
        except Exception:  # noqa: BLE001 - never echo storage details
            raise LiveSessionStoreError("claim attempts unavailable") from None
        return tuple(ClaimAttempt(*row) for row in rows)

    def observe_claim_attempt(
        self, session_id: str, attempt: int, *, fee_sat: int, height: int
    ) -> None:
        """Fill a migrated attempt's validated fee and first-seen height, once.

        Values already recorded are never overwritten, so a restart cannot move
        the escalation anchor.
        """
        try:
            with self._write() as connection:
                connection.execute(
                    "UPDATE claim_attempts SET fee_sat=COALESCE(fee_sat, ?), "
                    "first_seen_height=COALESCE(first_seen_height, ?) "
                    "WHERE session_id=? AND attempt=? AND session_id IN "
                    "(SELECT session_id FROM swaps WHERE state='CLAIMING')",
                    (fee_sat, height, session_id, attempt),
                )
        except Exception:  # noqa: BLE001 - never echo storage details
            raise LiveSessionStoreError("claim attempt update refused") from None

    def record_claim_attempt(  # noqa: PLR0913 - one replacement's explicit parts
        self,
        session_id: str,
        *,
        attempt: int,
        txid: str,
        raw: bytes,
        fee_sat: int,
        height: int,
    ) -> None:
        """Durably add the next fee-bumped claim before it is broadcast.

        Raises ``StaleSwapError`` unless the swap is CLAIMING and ``attempt``
        directly follows the latest recorded one, so a concurrent or repeated
        tick cannot fork the history. Earlier attempts are kept: any may confirm.
        """
        if not 0 < attempt < MAX_CLAIM_ATTEMPTS:
            raise LiveSessionStoreError("claim attempt budget exhausted")
        try:
            with self._write() as connection:
                (latest,) = connection.execute(
                    "SELECT MAX(a.attempt) FROM claim_attempts a JOIN swaps w "
                    "ON w.session_id=a.session_id WHERE a.session_id=? AND w.state='CLAIMING'",
                    (session_id,),
                ).fetchone()
                if latest != attempt - 1:
                    raise StaleSwapError("claim attempts changed")  # noqa: TRY301
                connection.execute(
                    "INSERT INTO claim_attempts VALUES (?, ?, ?, ?, ?, ?)",
                    (session_id, attempt, txid, raw, fee_sat, height),
                )
                connection.execute(
                    "UPDATE swaps SET claim_tx=?, claim_txid=? WHERE session_id=?",
                    (raw, txid, session_id),
                )
        except (LiveSessionStoreError, StaleSwapError):
            raise
        except Exception:  # noqa: BLE001 - never echo storage details
            raise LiveSessionStoreError("claim attempt refused") from None

    def unfunded_swaps(self) -> list[tuple[str, bytes]]:
        """Return (session_id, terms_offer) for accepted swaps still awaiting funding."""
        try:
            with self._write() as connection:
                return [
                    (row[0], row[1])
                    for row in connection.execute(
                        "SELECT session_id, terms_offer FROM swaps WHERE state='ACCEPTED' "
                        "ORDER BY session_id"
                    )
                ]
        except Exception:  # noqa: BLE001 - never echo storage details
            raise LiveSessionStoreError("swap listing refused") from None

    def unreleased_claims(self, *, after: str = "", limit: int = 16) -> list[tuple[str, str, int]]:
        """Return (session_id, claim_txid, required depth) for claimed, unreleased swaps.

        These are historical rows (for example migrated UNKNOWN reservations).
        Only a fresh chain observation passed to release_claim can close them.
        Pages by session ID after ``after`` so unconfirmable rows cannot starve
        later ones; callers wrap around when a page is short.
        """
        try:
            with self._write() as connection:
                rows = connection.execute(
                    "SELECT w.session_id, w.claim_txid, w.terms_offer FROM swaps w "
                    "JOIN economic_reservations r ON r.session_id=w.session_id "
                    "WHERE w.state='CLAIMED' AND w.claim_txid IS NOT NULL "
                    "AND r.state IN ('DISPATCHED', 'UNKNOWN') AND w.session_id > ? "
                    "ORDER BY w.session_id LIMIT ?",
                    (after, limit),
                ).fetchall()
                return [
                    (sid, txid, _offer_terms(offer).settlement_confirmations)
                    for sid, txid, offer in rows
                ]
        except Exception:  # noqa: BLE001 - never echo storage details
            raise LiveSessionStoreError("claim listing refused") from None

    def expirable_exposure_pending(self) -> bool:
        """Whether any terminal swap still holds a reservation (worth asking the tip)."""
        try:
            with self._write() as connection:
                row = connection.execute(
                    "SELECT 1 FROM economic_reservations r JOIN swaps w "
                    "ON w.session_id=r.session_id WHERE r.state<>'RELEASED' "
                    "AND w.state IN ('FAILED', 'CLAIMED', 'LOST') LIMIT 1"
                ).fetchone()
        except LiveSessionStoreError:
            raise
        except Exception:  # noqa: BLE001 - never echo storage details
            raise LiveSessionStoreError("exposure check refused") from None
        return row is not None

    def release_expired_exposure(self, tip_height: int) -> int:
        """Release reservations of terminal swaps whose exposure windows have all closed.

        Once the tip is past both the signed ``max_outgoing_htlc_expiry_height``
        (no Lightning HTLC of this swap can still be pending) and
        ``refund_lock_height`` (the client could refund), plus
        ``refund_resolution_confirmations``, nothing can change what this
        swap cost. This is the only release for migrated ``UNKNOWN`` rows of
        ``FAILED`` swaps and for ``FAILED`` swaps whose failure no payer
        attested. Non-terminal swaps are never touched. Returns the count.
        """
        if type(tip_height) is not int or tip_height <= 0:
            raise LiveSessionStoreError("tip height must be a positive block height")
        try:
            with self._write() as connection:
                rows = connection.execute(
                    "SELECT r.payment_hash, w.state, w.terms_offer FROM economic_reservations r "
                    "JOIN swaps w ON w.session_id=r.session_id "
                    "WHERE r.state<>'RELEASED' AND w.state IN ('FAILED', 'CLAIMED', 'LOST')"
                ).fetchall()
                released = 0
                for payment_hash, state, offer in rows:
                    terms = _offer_terms(offer)
                    policy = terms.timing_policy
                    htlc_expiry = getattr(policy, "max_outgoing_htlc_expiry_height", None)
                    if type(htlc_expiry) is not int:
                        continue  # another profile: no rule here
                    closed = (
                        max(htlc_expiry, terms.refund_lock_height)
                        + terms.refund_resolution_confirmations
                    )
                    if tip_height < closed:
                        continue
                    evidence = _release_evidence(
                        "exposure-expired",
                        swap_state=state,
                        tip_height=tip_height,
                        htlc_expiry_height=htlc_expiry,
                        refund_lock_height=terms.refund_lock_height,
                        required_confirmations=terms.refund_resolution_confirmations,
                    )
                    released += connection.execute(
                        "UPDATE economic_reservations SET state='RELEASED', release_evidence=? "
                        "WHERE payment_hash=? AND state<>'RELEASED'",
                        (evidence, payment_hash),
                    ).rowcount
        except LiveSessionStoreError:
            raise
        except Exception:  # noqa: BLE001 - never echo storage details
            raise LiveSessionStoreError("exposure release refused") from None
        return released

    def release_claim(self, session_id: str, claim_txid: str, *, confirmations: int) -> bool:
        """Release a claimed swap's reservation on fresh evidence of claim depth.

        Refuses anything but the retained claim txid of a CLAIMED swap observed
        at no less than its signed ``settlement_confirmations``. This accepts
        Bitcoin's depth-based reorganization risk, like the claim itself.
        """
        if type(confirmations) is not int or confirmations < 0:
            raise LiveSessionStoreError("confirmations unsupported")
        try:
            with self._write() as connection:
                row = connection.execute(
                    "SELECT terms_offer FROM swaps WHERE session_id=? AND state='CLAIMED' "
                    "AND claim_txid=?",
                    (session_id, claim_txid),
                ).fetchone()
                if row is None or confirmations < _offer_terms(row[0]).settlement_confirmations:
                    return False
                return _release_terminal(connection, session_id, "CLAIMED", None, confirmations)
        except LiveSessionStoreError:
            raise
        except Exception:  # noqa: BLE001 - never echo storage details
            raise LiveSessionStoreError("claim release refused") from None

    def _economic_capacity(self, connection: sqlite3.Connection, session_id: str) -> bool:
        """Whether one more firm offer in this session fits unreleased capacity."""
        if connection.execute(
            "SELECT 1 FROM economic_reservations WHERE session_id=?", (session_id,)
        ).fetchone():
            return False  # RS-003: at most one firm offer per session
        (active,) = connection.execute(
            "SELECT COUNT(*) FROM economic_reservations WHERE state <> 'RELEASED'"
        ).fetchone()
        return bool(active < self._max_active_reservations)

    def _reserve_offer(
        self, connection: sqlite3.Connection, session_id: str, payment_hash: str
    ) -> None:
        """Reserve capacity for a new firm offer, refusing anything over budget.

        RS-003 allows one firm offer per session, and a session with a swap is
        never offered again. The policy enforces both; this is the backstop.
        """
        if connection.execute(
            "SELECT 1 FROM economic_reservations WHERE session_id=? UNION ALL "
            "SELECT 1 FROM swaps WHERE session_id=?",
            (session_id, session_id),
        ).fetchone():
            raise LiveSessionStoreError("session already has a firm offer")
        if not self._economic_capacity(connection, session_id):
            raise SessionCapacityError("economic capacity reached")
        connection.execute(
            "INSERT INTO economic_reservations VALUES (?, ?, 'UNSENT', NULL)",
            (payment_hash, session_id),
        )

    def commit_payment_dispatch(self, session_id: str, payment_hash: str, request: bytes) -> bool:
        """Durably consume one explicit UNSENT grant before its external effect.

        Missing state is never permission to send. This transaction also orders
        authorization against conflict blocking: a blocked session cannot gain
        a new grant. A later conflict cannot undo an already committed dispatch.
        Lost responses and interrupted callers must reconcile, never recreate
        the grant or resubmit the saved request automatically.
        """
        if type(request) is not bytes or not 0 < len(request) <= MAX_DOCUMENT_BYTES:
            raise LiveSessionStoreError("payment request size unsupported")
        try:
            with self._write() as connection:
                if (
                    connection.execute(
                        "UPDATE payment_dispatch SET state='SUBMITTED', request=? "
                        "WHERE session_id=? AND payment_hash=? AND state='UNSENT' "
                        "AND EXISTS (SELECT 1 FROM swaps w JOIN sessions s "
                        "ON s.session_id=w.session_id "
                        "WHERE w.session_id=payment_dispatch.session_id "
                        "AND w.state='PAYING' AND s.blocked=0)",
                        (request, session_id, payment_hash),
                    ).rowcount
                    != 1
                ):
                    return False
                # Same transaction: a dispatch always marks its unreleased
                # reservation. Missing or released reservations abort the grant.
                if (
                    connection.execute(
                        "UPDATE economic_reservations SET state='DISPATCHED' "
                        "WHERE payment_hash=? AND session_id=? AND state IN ('UNSENT', 'UNKNOWN')",
                        (payment_hash, session_id),
                    ).rowcount
                    != 1
                ):
                    raise LiveSessionStoreError("economic reservation unavailable")  # noqa: TRY301
                return True
        except LiveSessionStoreError:
            raise
        except Exception:  # noqa: BLE001 - never echo routing or payment details
            raise LiveSessionStoreError("payment dispatch refused") from None

    def _record_observation(  # noqa: PLR0913 - one queued message's parts
        self,
        connection: sqlite3.Connection,
        session_id: str,
        payload: dict[str, Any],
        signer: EnvelopeSigner,
        now: int,
        *,
        message_type: str = "observation",
        required_features: tuple[str, ...] = (),
    ) -> str:
        offer_bytes, contract, key, revision, provider_seq = connection.execute(
            "SELECT w.terms_offer, w.contract_hash, s.provider_session_key, s.revision, "
            "s.next_provider_seq FROM swaps w JOIN sessions s ON s.session_id = w.session_id "
            "WHERE w.session_id=?",
            (session_id,),
        ).fetchone()
        reply = Answer(message_type, payload, contract_hash=contract)
        scalar, _ = self._unseal(connection, session_id)
        try:
            envelope = self._signed_envelope(
                _canonical_envelope(offer_bytes),
                key,
                provider_seq,
                reply,
                scalar,
                signer,
                None,
                required_features=required_features,
            )
        finally:
            del scalar
        connection.execute(
            "INSERT INTO outbox VALUES (?, ?, ?, NULL, ?, ?, 'PENDING')",
            (
                envelope.message_id,
                session_id,
                provider_seq,
                canonicalize(envelope.model_dump(mode="json")),
                revision + 1,
            ),
        )
        connection.execute(
            "UPDATE sessions SET revision=?, next_provider_seq=?, active_at=? WHERE session_id=?",
            (revision + 1, provider_seq + 1, now, session_id),
        )
        return envelope.message_id

    def sign_with_contract_key(
        self, session_id: str, digest: bytes, signer: EnvelopeSigner
    ) -> bytes:
        """BIP340-sign one digest with this swap's sealed provider contract key.

        Only for a swap that reached ``PAID`` or ``CLAIMING`` (the claim leaf),
        or an LN to BTC swap that is ``FUNDED`` or ``REFUNDING`` (the refund
        leaf); the scalar never leaves the store.
        """
        try:
            with self._write() as connection:
                row = connection.execute(
                    "SELECT k.compressed_key, k.secret_age FROM contract_keys k "
                    "JOIN swaps w ON w.session_id = k.session_id "
                    "WHERE k.session_id=? "
                    "AND w.state IN ('PAID', 'CLAIMING', 'FUNDED', 'REFUNDING')",
                    (session_id,),
                ).fetchone()
                if row is None or type(digest) is not bytes or len(digest) != 32:  # noqa: PLR2004
                    raise LiveSessionStoreError("no claimable swap")  # noqa: TRY301
                compressed, sealed = row
                plaintext = pyrage.decrypt(sealed, [self._custody_identity])
                record = json.loads(plaintext)
                scalar = bytes.fromhex(record["secret_scalar"])
                try:
                    if (
                        record["session_id"] != session_id
                        or record["store_uuid"] != self._store_uuid
                        or bytes(self._public_keys.public_key(scalar)).hex() != compressed
                    ):
                        raise LiveSessionStoreError("contract key custody differs")
                    signature = signer.schnorr_sign(scalar, digest, secrets.token_bytes(32))
                finally:
                    del scalar
                self._crypto.schnorr_verify(bytes.fromhex(compressed)[1:], digest, signature)
        except LiveSessionStoreError:
            raise
        except Exception:  # noqa: BLE001 - never echo secret material
            raise LiveSessionStoreError("contract key signing refused") from None
        return bytes(signature)

    def session_mailboxes(self) -> tuple[str, ...]:
        """Return our mailbox keys for sessions that may still send to us."""
        try:
            with self._write() as connection:
                rows = connection.execute(
                    "SELECT provider_session_key FROM sessions WHERE blocked=0 "
                    "AND phase IN ('ACCEPT_COMMITTED', 'CONFIRMED', 'ACCEPTED') ORDER BY revision"
                ).fetchall()
        except LiveSessionStoreError:
            raise
        except Exception:  # noqa: BLE001 - never echo storage details
            raise LiveSessionStoreError("session mailboxes unavailable") from None
        return tuple(row[0] for row in rows)

    def awaiting_confirm_mailboxes(self) -> tuple[str, ...]:
        """Return our session mailbox keys that still expect a client confirm."""
        try:
            with self._write() as connection:
                rows = connection.execute(
                    "SELECT provider_session_key FROM sessions "
                    "WHERE phase='ACCEPT_COMMITTED' AND blocked=0 ORDER BY revision"
                ).fetchall()
        except LiveSessionStoreError:
            raise
        except Exception:  # noqa: BLE001 - never echo storage details
            raise LiveSessionStoreError("session mailboxes unavailable") from None
        return tuple(row[0] for row in rows)

    def observe_outpoint_spent(
        self, session_id: str, tip_height: int | None, block_hash: str | None = None
    ) -> None:
        """Record the tip (height and hash) at which a CLAIMING swap's output was seen spent.

        ``None`` clears it (the output is unspent again, a recorded attempt is
        mined, or the anchor block left the active chain). A recorded anchor
        is never replaced: the first observation anchors the resolution wait.
        """
        if tip_height is not None and (
            type(tip_height) is not int
            or tip_height <= 0
            or type(block_hash) is not str
            or not HEX32.fullmatch(block_hash)
        ):
            raise LiveSessionStoreError("spent anchor must be a positive height and block hash")
        try:
            with self._write() as connection:
                if tip_height is None:
                    connection.execute(
                        "UPDATE swaps SET outpoint_spent_height=NULL, outpoint_spent_block=NULL "
                        "WHERE session_id=? AND state='CLAIMING'",
                        (session_id,),
                    )
                else:
                    connection.execute(
                        "UPDATE swaps SET "
                        "outpoint_spent_height=COALESCE(outpoint_spent_height, ?), "
                        "outpoint_spent_block=COALESCE(outpoint_spent_block, ?) "
                        "WHERE session_id=? AND state='CLAIMING'",
                        (tip_height, block_hash, session_id),
                    )
        except LiveSessionStoreError:
            raise
        except Exception:  # noqa: BLE001 - never echo storage details
            raise LiveSessionStoreError("spent observation refused") from None

    def payment_hash_reserved(self, payment_hash: str) -> bool:
        """Whether ``payment_hash`` is already reserved (pre-check before opening a hold).

        The authoritative check runs inside ``answer_request``; this only
        avoids opening a hold invoice an offer could never bind.
        """
        if type(payment_hash) is not str or len(payment_hash) != 64:  # noqa: PLR2004 - hex digest
            raise LiveSessionStoreError("payment hash must be 32 bytes of hex")
        try:
            with self._write() as connection:
                row = connection.execute(
                    "SELECT 1 FROM payment_hashes WHERE payment_hash=?", (payment_hash,)
                ).fetchone()
        except LiveSessionStoreError:
            raise
        except Exception:  # noqa: BLE001 - never echo storage details
            raise LiveSessionStoreError("reservation check refused") from None
        return row is not None

    def firm_capacity_available(self) -> bool:
        """Whether any session could still receive a firm offer (global count only).

        A cheap pre-check so a full provider skips route preflight; the
        authoritative per-session check runs inside ``answer_request``.
        """
        try:
            with self._write() as connection:
                (active,) = connection.execute(
                    "SELECT COUNT(*) FROM economic_reservations WHERE state <> 'RELEASED'"
                ).fetchone()
        except LiveSessionStoreError:
            raise
        except Exception:  # noqa: BLE001 - never echo storage details
            raise LiveSessionStoreError("capacity check refused") from None
        return bool(active < self._max_active_reservations)

    def pending_outbox(self) -> tuple[OutboxEntry, ...]:
        """Return committed bytes still owed to peers; current owner only."""
        try:
            with self._write() as connection:
                rows = connection.execute(
                    "SELECT message_id, session_id, canonical_bytes FROM outbox "
                    "WHERE delivery_state='PENDING' ORDER BY committed_revision, message_id"
                ).fetchall()
        except LiveSessionStoreError:
            raise
        except Exception:  # noqa: BLE001 - never echo storage details
            raise LiveSessionStoreError("outbox unavailable") from None
        return tuple(OutboxEntry(*row) for row in rows)

    def inspect_swaps(
        self, *, session_id: str | None = None, after: str | None = None, limit: int = 100
    ) -> SwapInspectionPage:
        """Return bounded, secret-free retained state under the exclusive owner.

        This neither runs settlement nor interprets absent payment records as
        authority. Index-ordered pagination avoids rescanning past pages. No
        invoice, preimage, key, route, or exact dispatch request is returned.
        """
        if (
            type(limit) is not int
            or not 1 <= limit <= MAX_INSPECTION_PAGE
            or (session_id is not None and after is not None)
            or any(
                value is not None and (type(value) is not str or HEX32.fullmatch(value) is None)
                for value in (session_id, after)
            )
        ):
            raise LiveSessionStoreError("swap inspection bounds unsupported")
        predicate = "w.session_id = ?" if session_id is not None else "w.session_id > ?"
        try:
            with self._write() as connection:
                rows = connection.execute(
                    "SELECT w.session_id, w.contract_hash, w.state, s.session_id IS NOT NULL, "
                    "s.blocked, COALESCE(p.state, 'UNKNOWN'), p.request IS NOT NULL, "
                    "w.funding_binding IS NOT NULL, w.preimage IS NOT NULL, "
                    "w.claim_tx IS NOT NULL, w.claim_txid "
                    "FROM swaps w LEFT JOIN sessions s ON s.session_id=w.session_id "
                    "LEFT JOIN payment_dispatch p ON p.session_id=w.session_id WHERE "
                    + predicate
                    + " ORDER BY w.session_id LIMIT ?",
                    (session_id if session_id is not None else after or "", limit + 1),
                ).fetchall()
            result = []
            for row in rows[:limit]:
                (
                    sid,
                    contract,
                    state,
                    present,
                    blocked,
                    dispatch,
                    request,
                    funding,
                    preimage,
                    claim,
                    txid,
                ) = row
                if not (
                    type(sid) is str
                    and HEX32.fullmatch(sid)
                    and type(contract) is str
                    and HEX32.fullmatch(contract)
                    and (txid is None or (type(txid) is str and HEX32.fullmatch(txid)))
                    and state
                    in {
                        "ACCEPTED",
                        "FUNDING_SEEN",
                        "PAYING",
                        "PAID",
                        "FAILED",
                        "CLAIMING",
                        "CLAIMED",
                        "LOST",
                    }
                    and dispatch in {"UNKNOWN", "UNSENT", "SUBMITTED"}
                    and blocked in (None, 0, 1)
                ):
                    raise LiveSessionStoreError("swap inspection state unsupported")  # noqa: TRY301
                result.append(
                    SwapInspection(
                        sid,
                        contract,
                        state,
                        bool(present),
                        None if blocked is None else bool(blocked),
                        dispatch,
                        bool(request),
                        bool(funding),
                        bool(preimage),
                        bool(claim),
                        txid,
                    )
                )
        except LiveSessionStoreError:
            raise
        except Exception:  # noqa: BLE001 - never echo retained financial or custody material
            raise LiveSessionStoreError("swap inspection unavailable") from None
        return SwapInspectionPage(
            tuple(result), result[-1].session_id if len(rows) > limit else None
        )


def _configure(connection: sqlite3.Connection) -> None:
    connection.execute("PRAGMA busy_timeout=5000")
    if connection.execute("PRAGMA journal_mode=WAL").fetchone() != ("wal",):
        raise LiveSessionStoreError("WAL unavailable")
    connection.execute("PRAGMA synchronous=FULL")
    if connection.execute("PRAGMA synchronous").fetchone() != (2,):
        raise LiveSessionStoreError("FULL sync unavailable")
    connection.execute("PRAGMA secure_delete=ON")  # expired sealed keys leave no old pages


def _check_schema(connection: sqlite3.Connection, *, allow_v5: bool = False) -> int:
    (version,) = connection.execute("PRAGMA user_version").fetchone()
    if connection.execute("PRAGMA application_id").fetchone() != (
        APPLICATION_ID,
    ) or version not in (
        (5, 6, 7, 8, 9, 10, 11, 12, SCHEMA_VERSION)
        if allow_v5
        else (8, 9, 10, 11, 12, SCHEMA_VERSION)
    ):
        raise LiveSessionStoreError("live session store version unsupported")
    objects = {
        (kind, name): definition
        for kind, name, definition in connection.execute(
            "SELECT type, name, sql FROM sqlite_master WHERE name NOT GLOB 'sqlite_*'"
        )
    }
    schema = {
        5: SCHEMA_V5,
        6: SCHEMA_V6,
        7: SCHEMA_V7,
        8: SCHEMA_V8,
        9: SCHEMA_V9,
        10: SCHEMA_V10,
        11: SCHEMA_V11,
        12: SCHEMA_V12,
        SCHEMA_VERSION: SCHEMA,
    }[version]
    indexes = {
        7: ADMISSION_INDEXES,
        8: (*ADMISSION_INDEXES, *RESERVATION_INDEXES),
        9: (*ADMISSION_INDEXES, *RESERVATION_INDEXES),
        10: (*ADMISSION_INDEXES, *RESERVATION_INDEXES),
        11: (*ADMISSION_INDEXES, *RESERVATION_INDEXES),
        12: (*ADMISSION_INDEXES, *RESERVATION_INDEXES, *COOPERATION_INDEXES),
        SCHEMA_VERSION: (*ADMISSION_INDEXES, *RESERVATION_INDEXES, *COOPERATION_INDEXES),
    }
    expected = {("table", statement.split()[2]): statement for statement in schema}
    expected.update(
        {
            (
                "index",
                sql.split()[3] if sql.startswith("CREATE UNIQUE INDEX ") else sql.split()[2],
            ): sql
            for sql in indexes.get(version, ())
        }
    )
    if objects != expected:
        raise LiveSessionStoreError("live session store schema incompatible")
    if connection.execute("PRAGMA quick_check").fetchone() != ("ok",):
        raise LiveSessionStoreError("live session store integrity unavailable")
    return int(version)


def _upgrade_v5(connection: sqlite3.Connection) -> None:
    """Add dispatch custody inside the verified owner's existing transaction.

    No old swap is labeled UNSENT. Only a future FUNDING_SEEN to PAYING
    transition can create that affirmative marker, before any send occurs.
    """
    connection.execute(PAYMENT_DISPATCH_SCHEMA)


def _upgrade_v6(connection: sqlite3.Connection) -> None:
    """Add empty epoch custody explicitly, without reclassifying any old session."""
    connection.execute(EPOCH_ADMISSION_SCHEMA)
    connection.execute(EPOCH_RETIREMENT_SCHEMA)
    connection.execute(EPOCH_KEY_HISTORY_SCHEMA)
    # v5/v6 kept every epoch row, including retired ones. Preserve that complete
    # public-key history before any v7 secret retirement becomes possible.
    connection.execute("INSERT INTO epoch_key_history SELECT epoch_key FROM epochs")
    for statement in ADMISSION_INDEXES:
        connection.execute(statement)
    # Explicit migration proves only that no epoch retirement has been recorded
    # under this format. It never converts old sessions to the new admission lane.
    connection.execute("INSERT INTO epoch_retirement VALUES (1, 0)")


def _upgrade_v7(connection: sqlite3.Connection) -> None:
    """Backfill the economic ledger from retained reservations, conservatively.

    Every payment-hash reservation gets one row. A still-open offer (a
    pre-acceptance session with no swap) becomes UNSENT, exactly like a new
    offer, so idle expiry can close it. A tombstoned session with neither
    session nor swap rows is an expired unaccepted offer that can never be
    accepted; it is RELEASED with migration evidence. Everything else, notably
    every accepted swap and every hash without affirmative provenance, is
    UNKNOWN and keeps its capacity until later evidenced closure. A swap
    without a reservation is inconsistent custody and refuses the upgrade.
    """
    connection.execute(ECONOMIC_RESERVATION_SCHEMA)
    for statement in RESERVATION_INDEXES:
        connection.execute(statement)
    for session_id, offer in connection.execute("SELECT session_id, terms_offer FROM swaps"):
        # The exact hash bound by the accepted offer, not any hash of the session.
        accepted = _offered_payment_hash(offer)
        if not connection.execute(
            "SELECT 1 FROM payment_hashes WHERE payment_hash=? AND session_id=?",
            (accepted, session_id),
        ).fetchone():
            raise LiveSessionStoreError("swap without payment-hash reservation")
    connection.execute(
        "INSERT INTO economic_reservations SELECT h.payment_hash, h.session_id, CASE "
        "WHEN w.session_id IS NULL AND s.phase IN ('RESERVED', 'ACCEPT_COMMITTED', "
        "'CONFIRMED') THEN 'UNSENT' "
        "WHEN w.session_id IS NULL AND s.session_id IS NULL AND (h.session_id IN "
        "(SELECT session_id FROM expired) OR h.session_id IN (SELECT session_id FROM "
        "epoch_admissions WHERE expired=1)) THEN 'RELEASED' ELSE 'UNKNOWN' END, "
        "CASE WHEN w.session_id IS NULL AND s.session_id IS NULL AND (h.session_id IN "
        "(SELECT session_id FROM expired) OR h.session_id IN (SELECT session_id FROM "
        "epoch_admissions WHERE expired=1)) THEN ? ELSE NULL END "
        "FROM payment_hashes h LEFT JOIN swaps w ON w.session_id=h.session_id "
        "LEFT JOIN sessions s ON s.session_id=h.session_id",
        (_release_evidence("expired-offer", source="migration"),),
    )


def _upgrade_v8(connection: sqlite3.Connection) -> None:
    """Record each CLAIMING swap's retained claim as its attempt 0.

    Additive and cheap, so it runs on ordinary acquire. Fee and first-seen
    height stay NULL: the engine validates the bytes and records the height it
    first observes before any fee bump. A CLAIMING swap without exact claim
    bytes gets no attempt, so the engine isolates it for the operator instead
    of inventing one; other swaps keep settling. CLAIMED swaps keep their
    confirmed claim_txid and need no attempt history.
    """
    connection.execute(CLAIM_ATTEMPT_SCHEMA)
    connection.execute(
        "INSERT INTO claim_attempts SELECT session_id, 0, claim_txid, claim_tx, NULL, NULL "
        "FROM swaps WHERE state='CLAIMING' AND claim_tx IS NOT NULL AND claim_txid IS NOT NULL"
    )


def _upgrade_v9(connection: sqlite3.Connection) -> None:
    """Rebuild ``swaps`` with the LOST state and the outpoint-spent height.

    Additive: every row is copied unchanged with a NULL spent height, so no
    swap changes state and the engine starts observing from scratch. The
    table is rebuilt because SQLite cannot alter a CHECK constraint; nothing
    references ``swaps`` by foreign key.
    """
    connection.execute("ALTER TABLE swaps RENAME TO swaps_v9")
    connection.execute(SWAPS_V10_SCHEMA)
    connection.execute(
        "INSERT INTO swaps SELECT session_id, contract_hash, terms_offer, terms_accept, state, "
        "funding_binding, preimage, claim_txid, claim_tx, updated_at, NULL, NULL "
        "FROM swaps_v9"
    )
    connection.execute("DROP TABLE swaps_v9")


def _upgrade_v10(connection: sqlite3.Connection) -> None:
    """Rebuild ``swaps`` with the LN to BTC states and provider transaction columns.

    Additive: every row is copied unchanged with NULL provider transactions;
    no swap changes state. Existing stores only ever held BTC to LN swaps.
    """
    connection.execute("ALTER TABLE swaps RENAME TO swaps_v10")
    connection.execute(SWAPS_SCHEMA)
    connection.execute(
        "INSERT INTO swaps SELECT *, NULL, NULL, NULL, NULL, NULL, NULL FROM swaps_v10"
    )
    connection.execute("DROP TABLE swaps_v10")


def _upgrade_v11(connection: sqlite3.Connection) -> None:
    """Add durable cooperation burns without retrofitting legacy swaps.

    The empty table proves storage capability, never an affirmative signing
    grant. Only a newly authenticated, signed cooperative contract may later
    insert a fresh burned attempt before allocating an opaque nonce handle.
    """
    connection.execute(COOPERATION_ATTEMPT_SCHEMA)
    for statement in COOPERATION_INDEXES:
        connection.execute(statement)


def _upgrade_v12(connection: sqlite3.Connection) -> None:
    """Add arbitration storage without granting any existing swap eligibility.

    An absent row proves nothing. No row is backfilled, no claim is delayed,
    and no transaction is published or signed by the migration.
    """
    connection.execute(CLAIM_ARBITRATION_SCHEMA)


def _check_reverse_transition(
    transition: tuple[str, str],
    *,
    funding: tuple[FundingBinding, bytes] | None,
    refund: tuple[str, bytes] | None,
    preimage: str | None,
    refund_confirmations: int | None,
) -> None:
    """Refuse an LN to BTC transition that lacks, or carries, the wrong evidence."""
    to_state = transition[1]
    if transition not in REVERSE_SWAP_TRANSITIONS:
        raise LiveSessionStoreError("swap transition unsupported")
    if (to_state == "FUNDING_SENT") != (funding is not None):
        raise LiveSessionStoreError("funding transition needs the exact funding")
    if (to_state == "REFUNDING") != (refund is not None):
        raise LiveSessionStoreError("refund transition needs the exact refund")
    if (to_state == "SETTLED") != (preimage is not None):
        raise LiveSessionStoreError("settlement needs the preimage")
    if to_state == "REFUNDED" and refund_confirmations is None:
        raise LiveSessionStoreError("refund release needs observed confirmations")


def _release_reverse_terminal(  # noqa: PLR0913 - explicit terminal evidence
    connection: sqlite3.Connection,
    session_id: str,
    to_state: str,
    now: int,
    *,
    terms: ContractTerms,
    refund_confirmations: int | None,
) -> None:
    """Release an LN to BTC swap's reservation with the evidence its terminal state carries.

    ABORTED releases only an undispatched reservation (no funding was ever
    signed). SETTLED releases a dispatched one: the verified preimage means
    the hold invoice pays for the contract. REFUNDED releases on the retained
    refund txid at its signed depth, like a BTC to LN claim.
    """
    payment_hash = terms.invoice_binding.payment_hash
    if to_state == "ABORTED":
        evidence = _release_evidence("hold-canceled", aborted_at=now)
        allowed = ("UNSENT", "UNKNOWN")
    elif to_state == "SETTLED":
        evidence = _release_evidence("hold-settled", settled_at=now)
        allowed = ("DISPATCHED", "UNKNOWN")
    else:
        (refund_txid,) = connection.execute(
            "SELECT refund_txid FROM swaps WHERE session_id=?", (session_id,)
        ).fetchone()
        if type(refund_txid) is not str:
            raise LiveSessionStoreError("refund evidence unavailable")
        evidence = _release_evidence(
            "refund-confirmed",
            refund_txid=refund_txid,
            required_confirmations=terms.refund_resolution_confirmations,
            observed_confirmations=int(refund_confirmations or 0),
        )
        allowed = ("DISPATCHED", "UNKNOWN")
    connection.execute(
        "UPDATE economic_reservations SET state='RELEASED', release_evidence=? "
        "WHERE payment_hash=? AND session_id=? AND state IN (?, ?)",
        (evidence, payment_hash, session_id, *allowed),
    )


def _release_terminal(  # noqa: PLR0913 - explicit terminal evidence
    connection: sqlite3.Connection,
    session_id: str,
    to_state: str,
    now: int | None,
    confirmations: int | None = None,
    *,
    failed_by_payer: str | None = None,
    network: NetworkIdentity | None = None,
) -> bool:
    """Release a terminal swap's reservation when its history proves closure.

    FAILED releases an UNSENT reservation: every dispatch marks its
    reservation DISPATCHED in the same transaction, and FAILED is terminal,
    so UNSENT proves no payment was or can be sent. A DISPATCHED reservation
    is released only when the failure was attested by the dispatch record's
    own bound payer (``failed_by_payer``): that node reports no HTLC of the
    sole authorized attempt in flight. A migrated UNKNOWN reservation or a
    failure without attributable payer keeps its capacity. CLAIMED (entered
    only at signed claim depth) releases a DISPATCHED or UNKNOWN
    reservation: the claim proves the provider recovered its funds. LOST
    releases the same: the exposure was realized as a loss and nothing
    further can happen to it.
    """
    (offer, claim_txid) = connection.execute(
        "SELECT terms_offer, claim_txid FROM swaps WHERE session_id=?", (session_id,)
    ).fetchone()
    terms = _offer_terms(offer)
    if to_state == "FAILED":
        evidence = _release_evidence("failed-before-dispatch", failed_at=int(now or 0))
        allowed = ("UNSENT", "UNSENT")
        row = connection.execute(
            "SELECT request FROM payment_dispatch WHERE session_id=? AND state='SUBMITTED'",
            (session_id,),
        ).fetchone()
        payer = (
            bound_payer(row[0], payment_hash=terms.invoice_binding.payment_hash, network=network)
            if row is not None and network is not None
            else None
        )
        if failed_by_payer is not None and payer is not None:
            if payer.node_pubkey != failed_by_payer:
                raise LiveSessionStoreError("failure attributed to another payer")
            evidence = _release_evidence(
                "failed-after-dispatch", failed_at=int(now or 0), payer=payer.node_pubkey
            )
            allowed = ("UNSENT", "DISPATCHED")
    elif to_state == "LOST":
        (spent_height, spent_block) = connection.execute(
            "SELECT outpoint_spent_height, outpoint_spent_block FROM swaps WHERE session_id=?",
            (session_id,),
        ).fetchone()
        if type(spent_height) is not int or type(spent_block) is not str:
            raise LiveSessionStoreError("loss evidence unavailable")
        evidence = _release_evidence(
            "claim-lost",
            outpoint_spent_height=spent_height,
            outpoint_spent_block=spent_block,
            required_confirmations=terms.refund_resolution_confirmations,
        )
        allowed = ("DISPATCHED", "UNKNOWN")
    else:
        if type(claim_txid) is not str:
            raise LiveSessionStoreError("claim evidence unavailable")
        facts: dict[str, str | int] = {
            "claim_txid": claim_txid,
            "required_confirmations": terms.settlement_confirmations,
        }
        if confirmations is not None:
            facts["observed_confirmations"] = confirmations
        evidence = _release_evidence("claim-confirmed", **facts)
        allowed = ("DISPATCHED", "UNKNOWN")
    return bool(
        connection.execute(
            "UPDATE economic_reservations SET state='RELEASED', release_evidence=? "
            "WHERE payment_hash=? AND session_id=? AND state IN (?, ?)",
            (evidence, terms.invoice_binding.payment_hash, session_id, *allowed),
        ).rowcount
    )


def _offer_terms(offer: bytes) -> ContractTerms:
    """Return the contract terms of one retained canonical terms offer."""
    return parse_model_json(
        TermsOfferPayload, canonicalize(_canonical_envelope(offer).payload)
    ).terms.contract_terms


def _offered_payment_hash(offer: bytes) -> str:
    """Return the payment hash bound by one retained canonical terms offer."""
    return parse_model_json(
        TermsOfferPayload, canonicalize(_canonical_envelope(offer).payload)
    ).terms.contract_terms.invoice_binding.payment_hash


def _release_evidence(reason: str, **facts: str | int) -> bytes:
    """Versioned, canonical closure evidence for one RELEASED reservation."""
    return canonicalize({"version": 1, "reason": reason, **facts})


def _epoch_watermark(connection: sqlite3.Connection) -> int:
    rows = connection.execute("SELECT retired_through FROM epoch_retirement").fetchall()
    if len(rows) != 1 or type(rows[0][0]) is not int or rows[0][0] < 0:
        raise LiveSessionStoreError("epoch retirement custody unavailable")
    return int(rows[0][0])


def _retire_epochs(connection: sqlite3.Connection, now: int) -> None:
    """Retire affirmative expired epochs and persist the barrier before pruning.

    Caller owns the transaction. Neither an absent row nor the watermark alone
    permits deleting session history. Session deletion still requires idle,
    pre-economic state; only its epoch-tagged tombstone can later be pruned.
    """
    watermark = _epoch_watermark(connection)
    if type(now) is not int or now < watermark:
        raise LiveSessionStoreError("clock is behind retired epochs")
    (expired_through,) = connection.execute(
        "SELECT MAX(retire_after) FROM epochs WHERE retire_after <= ?", (now,)
    ).fetchone()
    if expired_through is not None and expired_through > watermark:
        watermark = expired_through
        connection.execute("UPDATE epoch_retirement SET retired_through=?", (watermark,))
    connection.execute("DELETE FROM epochs WHERE retire_after <= ?", (watermark,))


def _session_expired(connection: sqlite3.Connection, session_id: str) -> bool:
    return (
        connection.execute(
            "SELECT 1 FROM expired WHERE session_id=? UNION ALL "
            "SELECT 1 FROM epoch_admissions WHERE session_id=? AND expired=1 LIMIT 1",
            (session_id, session_id),
        ).fetchone()
        is not None
    )


class _TokenBucket:
    """In-memory global admission rate (a restart refills it; capacity still binds)."""

    def __init__(self, per_minute: int) -> None:
        self._capacity = float(per_minute)
        self._tokens = float(per_minute)
        self._rate = per_minute / 60.0
        self._last: int | None = None

    def take(self, now: int) -> bool:
        if self._last is not None and now > self._last:
            self._tokens = min(self._capacity, self._tokens + (now - self._last) * self._rate)
        self._last = now if self._last is None else max(self._last, now)
        if self._tokens < 1:
            return False
        self._tokens -= 1
        return True


def _new_session_scalar() -> bytes:
    return secrets.token_bytes(32)


def _new_epoch_scalar() -> bytes:
    return secrets.token_bytes(32)


def _routing_recipient(outer_event: bytes) -> str:
    """Return the single ``p`` tag as a routing hint; the decoder re-verifies it."""
    if type(outer_event) is not bytes or len(outer_event) > MAX_OUTER_EVENT_BYTES:
        raise LiveSessionStoreError("frame size unsupported")
    tags: list[Any] = json.loads(outer_event)["tags"]
    recipients = [
        tag[1]
        for tag in tags
        if type(tag) is list and len(tag) >= 2 and tag[0] == "p"  # noqa: PLR2004
    ]
    if len(recipients) != 1 or type(recipients[0]) is not str:
        raise LiveSessionStoreError("frame recipient unsupported")
    return recipients[0]


def _new_challenge() -> str:
    return secrets.token_hex(32)


def _new_message_id() -> str:
    return secrets.token_hex(32)


def _recipient(value: str) -> str:
    try:
        parsed = x25519.Recipient.from_str(value)
    except Exception:  # noqa: BLE001 - never echo caller input
        raise LiveSessionStoreError("custody recipient malformed") from None
    if str(parsed) != value:
        raise LiveSessionStoreError("custody recipient malformed")
    return value


def _xonly(public_keys: CustodyPublicKeys, scalar: bytes) -> str:
    key = public_keys.public_key(scalar)
    if type(key) is not bytes or len(key) != COMPRESSED_KEY_BYTES or key[0] not in (2, 3):
        raise LiveSessionStoreError("session public key derivation failed")
    return key[1:].hex()


def _check_provisioning(store_uuid: object, authority_jcs: object) -> None:
    try:
        parsed = uuid.UUID(str(store_uuid))
        authority: dict[str, object] = json.loads(authority_jcs)  # type: ignore[arg-type]
        declared = AuthorityDeclaration(
            authority["volume_label"],  # type: ignore[arg-type]
            outside_restore_domain=authority["outside_restore_domain"],  # type: ignore[arg-type]
            single_host=authority["single_host"],  # type: ignore[arg-type]
        )
        valid = str(parsed) == store_uuid and declared.jcs() == authority_jcs
    except Exception:  # noqa: BLE001 - malformed metadata is simply not trusted
        valid = False
    if not valid:
        raise LiveSessionStoreError("store provisioning metadata untrusted")


def _discard(connection: sqlite3.Connection | None, lock_fd: int) -> None:
    if connection is not None:
        with suppress(sqlite3.Error):
            connection.close()
    if lock_fd >= 0:
        os.close(lock_fd)  # closing the descriptor releases the flock


def _fresh_challenge(connection: sqlite3.Connection, init: HandshakeInit) -> str:
    for _ in range(MAX_CHALLENGE_TRIES):
        challenge = _new_challenge()
        if (
            HEX32.fullmatch(challenge) is not None
            and challenge not in (init.session_id, init.client_challenge)
            and connection.execute(
                "SELECT 1 FROM sessions WHERE provider_challenge=?", (challenge,)
            ).fetchone()
            is None
        ):
            return challenge
    raise LiveSessionStoreError("independent challenge unavailable")


def _record_conflict(
    connection: sqlite3.Connection, session_id: str, kind: str, evidence: bytes
) -> None:
    # One bounded evidence row per session and kind; later conflicts add nothing.
    connection.execute(
        "INSERT OR IGNORE INTO conflicts VALUES (?, ?, ?)", (session_id, kind, evidence)
    )
    connection.execute(
        "UPDATE sessions SET blocked=1, revision=revision+1 WHERE session_id=? AND blocked=0",
        (session_id,),
    )


def _accept_revision(connection: sqlite3.Connection, message_id: str) -> int:
    row = connection.execute(
        "SELECT committed_revision FROM outbox WHERE message_id=?", (message_id,)
    ).fetchone()
    if row is None:
        raise LiveSessionStoreError("committed accept missing from outbox")
    return int(row[0])


def _swap(connection: sqlite3.Connection, session_id: str) -> SwapRecord | None:
    row = connection.execute(
        f"SELECT {SWAP_COLUMNS} FROM swaps WHERE session_id=?",  # noqa: S608 - fixed columns
        (session_id,),
    ).fetchone()
    return None if row is None else SwapRecord(*row)


def _apply_effect(
    connection: sqlite3.Connection,
    request: Envelope,
    effect: AcceptSwap | BindFunding,
    replied: tuple[bytes] | None,
    now: int,
) -> None:
    """Apply one responder effect inside the admitting transaction."""
    document = canonicalize(request.model_dump(mode="json"))
    if isinstance(effect, AcceptSwap):
        if replied is None or request.contract_hash != effect.contract_hash:
            raise LiveSessionStoreError("acceptance not bound to an offer")
        offered = _offered_payment_hash(replied[0])
        if not connection.execute(
            "SELECT 1 FROM economic_reservations WHERE payment_hash=? AND session_id=? "
            "AND state IN ('UNSENT', 'UNKNOWN')",
            (offered, request.session_id),
        ).fetchone():
            raise LiveSessionStoreError("offer reservation is closed")
        connection.execute(
            "INSERT INTO swaps VALUES (?, ?, ?, ?, 'ACCEPTED', NULL, NULL, NULL, NULL, ?, "
            "NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL)",
            (request.session_id, effect.contract_hash, replied[0], document, now),
        )
        connection.execute(
            "UPDATE sessions SET phase='ACCEPTED' WHERE session_id=?", (request.session_id,)
        )
        return
    updated = connection.execute(
        "UPDATE swaps SET funding_binding=?, state='FUNDING_SEEN', updated_at=? "
        "WHERE session_id=? AND contract_hash=? AND state='ACCEPTED'",
        (document, now, request.session_id, request.contract_hash),
    ).rowcount
    if updated != 1:
        raise LiveSessionStoreError("funding binding not bound to an accepted swap")
