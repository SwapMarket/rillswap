"""BOLT 11 reading and InvoiceBinding admission without a Lightning node.

This mirrors ``rill-payments/src/bolt11.ts``, the browser's decoder, rule for
rule, so Python and TypeScript clients admit exactly the same invoices; both
consume ``rill-docs/vectors/bolt11/cases-v1.json``. ``decode_bolt11`` follows
the specification's reader rules; ``invoice_binding`` then applies the same
admission policy as rill-provider's LND adapter and returns the RS-001
``InvoiceBinding`` the provider must echo exactly. Signature math stays in
libsecp256k1 through an injected binding (``rill_crypto.Context`` fits).
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, replace
from typing import TYPE_CHECKING, Final, Protocol

from rill_core.errors import ValidationError
from rill_core.networks import backend_names
from rill_core.wire.messages import InvoiceBinding

if TYPE_CHECKING:
    from collections.abc import Sequence

    from rill_core.wire.types import NetworkIdentity

MAX_INVOICE_CHARS: Final = 2048
_SIGNATURE_WORDS: Final = 104
_TIMESTAMP_WORDS: Final = 7
_CHECKSUM_CHARS: Final = 6
_DEFAULT_EXPIRY_SECONDS: Final = 3600
_DEFAULT_MIN_FINAL_CLTV: Final = 18
_HASH_WORDS: Final = 52
_PAYEE_WORDS: Final = 53
_MAX_INTEGER_WORDS: Final = 10
_MULTIPLIER: Final = {"": 100_000_000_000, "m": 100_000_000, "u": 100_000, "n": 100}
_ACCEPTED_FEATURES: Final = frozenset({8, 9, 14, 15, 17, 25})
_TAG_PAYMENT_HASH: Final = 1
_TAG_FEATURES: Final = 5
_TAG_EXPIRY: Final = 6
_TAG_PAYMENT_SECRET: Final = 16
_TAG_PAYEE: Final = 19
_TAG_BLINDED_PATH: Final = 20
_TAG_DESCRIPTION_HASH: Final = 23
_TAG_MIN_FINAL_CLTV: Final = 24
# s, x, n, c feed the binding and payment; readers disagree on repeats (LND
# keeps the first), so they must appear at most once. A repeated 9 is last-wins.
_BINDING_TAGS: Final = frozenset(
    {_TAG_PAYMENT_SECRET, _TAG_EXPIRY, _TAG_PAYEE, _TAG_MIN_FINAL_CLTV}
)
_CHARSET: Final = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
_GENERATOR: Final = (0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3)
_HUMAN_PART: Final = re.compile(r"ln([a-z]+?)((?:[0-9]+[a-z]?)?)")
_AMOUNT: Final = re.compile(r"([1-9][0-9]*)([munp]?)")
_LOWERCASE_INVOICE: Final = re.compile(r"ln[a-z0-9]{1,2046}")
_MIN_PRINTABLE: Final = 33
_MAX_PRINTABLE: Final = 126
_MAX_RECOVERY_ID: Final = 3


class EcdsaAuthenticator(Protocol):
    """libsecp256k1 compact ECDSA; failures raise (``rill_crypto.Context`` fits)."""

    def ecdsa_recover(self, message: bytes, signature: bytes, recovery_id: int) -> bytes:
        """Return the compressed key; accept high and low S."""
        ...

    def ecdsa_verify(self, public_key: bytes, message: bytes, signature: bytes) -> None:
        """Verify a low-S signature or raise."""
        ...


class InvoiceRejectedError(ValidationError):
    """The invoice is malformed, unauthenticated, or outside admission policy."""

    def __init__(self, reason: str) -> None:
        """Prefix the stable reason exactly as the browser decoder does."""
        super().__init__(f"Invoice refused: {reason}")


@dataclass(frozen=True, slots=True)
class DecodedInvoice:
    """Reader-level BOLT 11 facts, before admission policy."""

    currency: str
    amount_msat: int | None
    timestamp: int
    payment_hash: str | None
    payment_secret: str | None
    payee: str
    expiry_seconds: int
    min_final_cltv_delta: int
    features: frozenset[int]
    blinded_paths: bool


@dataclass(slots=True)
class _Fields:
    payment_hash: str | None = None
    payment_secret: str | None = None
    payee: bytes | None = None
    expiry: int | None = None
    min_final_cltv: int | None = None
    features: frozenset[int] = frozenset()
    blinded_paths: bool = False


def _polymod(values: Sequence[int]) -> int:
    checksum = 1
    for value in values:
        top = checksum >> 25
        checksum = (checksum & 0x1FFFFFF) << 5 ^ value
        for index, generator in enumerate(_GENERATOR):
            if (top >> index) & 1:
                checksum ^= generator
    return checksum


def _bech32_decode(invoice: str) -> tuple[str, list[int]]:
    """BIP-173 bech32 without the 90-character limit (BOLT 11)."""
    lowered = invoice.lower()
    if (
        len(invoice) < 8  # noqa: PLR2004 - BIP-173 minimum, as @scure/base
        or not invoice.isascii()
        or (invoice not in {lowered, invoice.upper()})
    ):
        raise InvoiceRejectedError("bech32 invalid")
    separator = lowered.rfind("1")
    human, data = lowered[:separator], lowered[separator + 1 :]
    if separator < 1 or len(data) < _CHECKSUM_CHARS:
        raise InvoiceRejectedError("bech32 invalid")
    if any(not _MIN_PRINTABLE <= ord(char) <= _MAX_PRINTABLE for char in human):
        raise InvoiceRejectedError("bech32 invalid")
    try:
        words = [_CHARSET.index(char) for char in data]
    except ValueError:
        raise InvoiceRejectedError("bech32 invalid") from None
    expanded = [ord(char) >> 5 for char in human] + [0] + [ord(char) & 31 for char in human]
    if _polymod(expanded + words) != 1:
        raise InvoiceRejectedError("bech32 invalid")
    return human, words[:-_CHECKSUM_CHARS]


def _words_to_int(words: Sequence[int]) -> int:
    value = 0
    for word in words:
        value = value * 32 + word
    return value


def _words_to_bytes(words: Sequence[int], *, exact: bool) -> bytes:
    """5-bit groups to bytes, zero-padding the final partial byte unless exact."""
    out = bytearray()
    accumulator = 0
    bits = 0
    for word in words:
        accumulator = (accumulator << 5) | word
        bits += 5
        while bits >= 8:  # noqa: PLR2004 - one byte
            bits -= 8
            out.append((accumulator >> bits) & 0xFF)
        accumulator &= (1 << bits) - 1
    if bits > 0 and not exact:
        out.append((accumulator << (8 - bits)) & 0xFF)
    return bytes(out)


def _amount_msat(amount: str) -> int | None:
    if not amount:
        return None
    match = _AMOUNT.fullmatch(amount)
    if match is None:
        raise InvoiceRejectedError("amount malformed")
    value, unit = int(match[1]), match[2]
    if unit == "p":
        if value % 10:
            raise InvoiceRejectedError("sub-millisatoshi amount")
        return value // 10
    return value * _MULTIPLIER[unit]


def _feature_bits(words: Sequence[int]) -> frozenset[int]:
    last = len(words) - 1
    return frozenset(
        (last - index) * 5 + bit
        for index, word in enumerate(words)
        for bit in range(5)
        if word & (1 << bit)
    )


def _parse_fields(words: Sequence[int]) -> _Fields:  # noqa: PLR0912 - one tagged-field reader
    fields = _Fields()
    seen: set[int] = set()
    index = 0
    while index < len(words):
        if index + 3 > len(words):
            raise InvoiceRejectedError("tagged field truncated")
        tag = words[index]
        length = words[index + 1] * 32 + words[index + 2]
        value = words[index + 3 : index + 3 + length]
        if len(value) != length:
            raise InvoiceRejectedError("tagged field truncated")
        index += 3 + length
        # BOLT 11 readers reject every wrong-length p/h/s/n occurrence.
        if tag == _TAG_PAYMENT_HASH:
            if length != _HASH_WORDS:
                raise InvoiceRejectedError("payment hash length invalid")
            if fields.payment_hash is not None:
                raise InvoiceRejectedError("multiple payment hashes")
        if (tag in {_TAG_PAYMENT_SECRET, _TAG_DESCRIPTION_HASH} and length != _HASH_WORDS) or (
            tag == _TAG_PAYEE and length != _PAYEE_WORDS
        ):
            raise InvoiceRejectedError("fixed-length field invalid")
        if tag in _BINDING_TAGS:
            if tag in seen:
                raise InvoiceRejectedError("duplicate binding field")
            seen.add(tag)
        if tag == _TAG_PAYMENT_HASH:
            fields.payment_hash = _words_to_bytes(value, exact=False)[:32].hex()
        elif tag == _TAG_PAYMENT_SECRET:
            fields.payment_secret = _words_to_bytes(value, exact=False)[:32].hex()
        elif tag == _TAG_PAYEE:
            fields.payee = _words_to_bytes(value, exact=False)[:33]
        elif tag == _TAG_EXPIRY and 0 < length <= _MAX_INTEGER_WORDS:
            fields.expiry = _words_to_int(value)
        elif tag == _TAG_MIN_FINAL_CLTV and 0 < length <= _MAX_INTEGER_WORDS:
            fields.min_final_cltv = _words_to_int(value)
        elif tag == _TAG_FEATURES:
            fields.features = _feature_bits(value)
        elif tag == _TAG_BLINDED_PATH:
            fields.blinded_paths = True
    return fields


def _authenticate(
    signature: bytes, digest: bytes, payee: bytes | None, crypto: EcdsaAuthenticator
) -> str:
    compact, recovery_id = signature[:64], signature[64]
    if payee is None and recovery_id > _MAX_RECOVERY_ID:
        raise InvoiceRejectedError("signature invalid")
    try:
        if payee is not None:
            # With an explicit payee the signature must verify, in low-S form.
            crypto.ecdsa_verify(payee, digest, compact)
            return payee.hex()
        return crypto.ecdsa_recover(digest, compact, recovery_id).hex()
    except Exception:  # noqa: BLE001 - every native refusal is one rejection
        raise InvoiceRejectedError("signature invalid") from None


def _read(invoice: str) -> tuple[DecodedInvoice, bytes, bytes, _Fields]:
    """Apply every reader rule except signature math.

    Returns the facts (payee empty), the signed digest, the signature, and the
    fields as written (``None`` where absent). Never return these facts to a
    caller unchecked.
    """
    if type(invoice) is not str or not 0 < len(invoice) <= MAX_INVOICE_CHARS:
        raise InvoiceRejectedError("length unsupported")
    human, words = _bech32_decode(invoice)
    match = _HUMAN_PART.fullmatch(human)
    if match is None:
        raise InvoiceRejectedError("prefix malformed")
    amount = _amount_msat(match[2])
    if len(words) < _TIMESTAMP_WORDS + _SIGNATURE_WORDS:
        raise InvoiceRejectedError("too short")
    data = words[:-_SIGNATURE_WORDS]
    signature = _words_to_bytes(words[-_SIGNATURE_WORDS:], exact=True)
    fields = _parse_fields(data[_TIMESTAMP_WORDS:])
    digest = hashlib.sha256(human.encode() + _words_to_bytes(data, exact=False)).digest()
    facts = DecodedInvoice(
        currency=match[1],
        amount_msat=amount,
        timestamp=_words_to_int(data[:_TIMESTAMP_WORDS]),
        payment_hash=fields.payment_hash,
        payment_secret=fields.payment_secret,
        payee="",
        expiry_seconds=_DEFAULT_EXPIRY_SECONDS if fields.expiry is None else fields.expiry,
        min_final_cltv_delta=(
            _DEFAULT_MIN_FINAL_CLTV if fields.min_final_cltv is None else fields.min_final_cltv
        ),
        features=fields.features,
        blinded_paths=fields.blinded_paths,
    )
    return facts, digest, signature, fields


def decode_bolt11(invoice: str, *, crypto: EcdsaAuthenticator) -> DecodedInvoice:
    """Decode and authenticate one BOLT 11 string (reader rules only, no policy)."""
    facts, digest, signature, fields = _read(invoice)
    return replace(facts, payee=_authenticate(signature, digest, fields.payee, crypto))


def require_wire_agreement(  # noqa: PLR0913 - every fact a node reports is compared
    invoice: str,
    *,
    payment_hash: str,
    payment_secret: str,
    amount_msat: int,
    payee: str,
    timestamp: int,
    expiry_seconds: int,
    min_final_cltv_delta: int,
    features: frozenset[int],
    blinded_paths: bool,
) -> None:
    """Refuse unless this reader sees exactly what an authenticating node reported.

    For a node (LND) that already verified the signature over these same
    bytes, so no signature math runs here, and nothing is returned: this can
    only refuse, never admit unauthenticated facts. Repeated or wrong-length
    binding fields are refused by the reader rules. A repeated field that a
    first-wins node reads differently from this reader (``9`` is last-wins
    here) changes a fact and is refused too. An explicit ``n`` must name
    ``payee``; without one the recovered payee is the node's.

    Without a ``c`` field BOLT 11 lets a payer assume any final delta of at
    least 18 (LND assumes 24); a larger one only gives the payee more time.
    Every other default, the expiry included, must match exactly.
    """
    facts, _digest, _signature, fields = _read(invoice)
    reported = (
        payment_hash,
        payment_secret,
        amount_msat,
        timestamp,
        expiry_seconds,
        features,
        blinded_paths,
    )
    read = (
        facts.payment_hash,
        facts.payment_secret,
        facts.amount_msat,
        facts.timestamp,
        facts.expiry_seconds,
        facts.features,
        facts.blinded_paths,
    )
    final_delta_agrees = (
        min_final_cltv_delta >= _DEFAULT_MIN_FINAL_CLTV
        if fields.min_final_cltv is None
        else min_final_cltv_delta == fields.min_final_cltv
    )
    if (
        read != reported
        or not final_delta_agrees
        or (fields.payee is not None and fields.payee.hex() != payee)
    ):
        raise InvoiceRejectedError("decoders disagree on the invoice fields")


def invoice_binding(
    invoice: str, network: NetworkIdentity, *, crypto: EcdsaAuthenticator
) -> InvoiceBinding:
    """Admit one invoice for ``network`` under rill-provider's LND policy.

    Returns its binding. ``network`` must be a supported identity. Expiry
    against the clock is the caller's check.
    """
    currency = backend_names(network).invoice_prefix.removeprefix("ln")
    if type(invoice) is not str or _LOWERCASE_INVOICE.fullmatch(invoice) is None:
        raise InvoiceRejectedError("not lowercase BOLT11")
    decoded = decode_bolt11(invoice, crypto=crypto)
    if decoded.currency != currency:
        raise InvoiceRejectedError("invoice is not for the selected network")
    features = decoded.features
    if (
        not features <= _ACCEPTED_FEATURES
        or (8 in features) == (9 in features)  # noqa: PLR2004 - var_onion_optin pair
        or (14 in features) == (15 in features)  # noqa: PLR2004 - payment_secret pair
    ):
        raise InvoiceRejectedError("feature bits unsupported")
    if decoded.payment_secret is None or decoded.payment_hash is None or decoded.blinded_paths:
        raise InvoiceRejectedError("payment secret, hash, or route form unsupported")
    amount = decoded.amount_msat
    if amount is None or amount <= 0 or amount % 1000:
        raise InvoiceRejectedError("amount must be a positive whole number of satoshis")
    if decoded.expiry_seconds <= 0 or decoded.min_final_cltv_delta <= 0:
        raise InvoiceRejectedError("expiry or final CLTV unsupported")
    try:
        return InvoiceBinding(
            bolt11_sha256=hashlib.sha256(invoice.encode("ascii")).hexdigest(),
            payment_hash=decoded.payment_hash,
            amount_msat=str(amount),
            payee_compressed_pubkey=decoded.payee,
            created_at=decoded.timestamp,
            expires_at=decoded.timestamp + decoded.expiry_seconds,
            min_final_cltv_delta=decoded.min_final_cltv_delta,
        )
    except ValueError:
        raise InvoiceRejectedError("binding fields unsupported") from None
