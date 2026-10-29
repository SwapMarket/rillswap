"""Signed BOLT11 test invoices, including deliberately ambiguous ones.

Test-only. Signs with the public secp256k1 key 1 (payee ``PAYEE``), so the
invoices are genuine to any reader, LND included. Pure Python on purpose: the
provider has no signing dependency, and the pinned LND sidecar imports this
module too. Never use this arithmetic for real keys (it is not constant time).
"""

from __future__ import annotations

import hashlib
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Sequence

_P = 2**256 - 2**32 - 977
_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
_G = (
    0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
    0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8,
)
_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
_GENERATOR = (0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3)
KEY = 1
PAYEE = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"

Point = tuple[int, int] | None


def _add(a: Point, b: Point) -> Point:
    if a is None:
        return b
    if b is None:
        return a
    if a[0] == b[0] and (a[1] + b[1]) % _P == 0:
        return None
    if a == b:
        slope = 3 * a[0] * a[0] * pow(2 * a[1], -1, _P)
    else:
        slope = (b[1] - a[1]) * pow(b[0] - a[0], -1, _P)
    x = (slope * slope - a[0] - b[0]) % _P
    return x, (slope * (a[0] - x) - a[1]) % _P


def _multiply(scalar: int, point: Point = _G) -> Point:
    result: Point = None
    while scalar:
        if scalar & 1:
            result = _add(result, point)
        point = _add(point, point)
        scalar >>= 1
    return result


def _sign(digest: bytes, key: int) -> bytes:
    """Low-S compact signature plus recovery id, with a deterministic nonce."""
    z = int.from_bytes(digest, "big")
    k = int.from_bytes(hashlib.sha256(key.to_bytes(32, "big") + digest).digest(), "big") % _N
    point = _multiply(k)
    assert point is not None
    r = point[0] % _N
    s = pow(k, -1, _N) * (z + r * key) % _N
    recovery = point[1] & 1
    if s > _N // 2:
        s, recovery = _N - s, recovery ^ 1
    return r.to_bytes(32, "big") + s.to_bytes(32, "big") + bytes([recovery])


def _to_words(data: bytes) -> list[int]:
    words, accumulator, bits = [], 0, 0
    for byte in data:
        accumulator, bits = (accumulator << 8) | byte, bits + 8
        while bits >= 5:
            bits -= 5
            words.append((accumulator >> bits) & 31)
        accumulator &= (1 << bits) - 1
    if bits:
        words.append((accumulator << (5 - bits)) & 31)
    return words


def _to_bytes(words: Sequence[int]) -> bytes:
    out, accumulator, bits = bytearray(), 0, 0
    for word in words:
        accumulator, bits = (accumulator << 5) | word, bits + 5
        while bits >= 8:
            bits -= 8
            out.append((accumulator >> bits) & 0xFF)
        accumulator &= (1 << bits) - 1
    if bits:
        out.append((accumulator << (8 - bits)) & 0xFF)
    return bytes(out)


def _polymod(values: Sequence[int]) -> int:
    checksum = 1
    for value in values:
        top = checksum >> 25
        checksum = (checksum & 0x1FFFFFF) << 5 ^ value
        for index, generator in enumerate(_GENERATOR):
            if (top >> index) & 1:
                checksum ^= generator
    return checksum


def _integer(value: int) -> list[int]:
    words = [value & 31]
    while value := value >> 5:
        words.insert(0, value & 31)
    return words


def tag(kind: int, words: Sequence[int]) -> list[int]:
    """One tagged field: type, 10-bit length, data words."""
    return [kind, len(words) // 32, len(words) % 32, *words]


def payment_hash(value: str) -> list[int]:
    return tag(1, _to_words(bytes.fromhex(value)))


def payment_secret(value: bytes) -> list[int]:
    return tag(16, _to_words(value))


def description(text: str) -> list[int]:
    return tag(13, _to_words(text.encode()))


def expiry(seconds: int) -> list[int]:
    return tag(6, _integer(seconds))


def final_cltv(delta: int) -> list[int]:
    return tag(24, _integer(delta))


def payee(pubkey: str = PAYEE) -> list[int]:
    return tag(19, _to_words(bytes.fromhex(pubkey)))


def features(*bits: int) -> list[int]:
    words = [0] * (max(bits) // 5 + 1)
    for bit in bits:
        words[len(words) - 1 - bit // 5] |= 1 << (bit % 5)
    return tag(5, words)


def invoice(
    fields: Sequence[Sequence[int]],
    *,
    hrp: str = "lnbcrt500u",
    timestamp: int = 1_700_000_000,
    key: int = KEY,
) -> str:
    """Return the signed lowercase BOLT11 string for exactly these fields, in order."""
    data = [(timestamp >> (5 * shift)) & 31 for shift in range(6, -1, -1)]
    data += [word for field in fields for word in field]
    signature = _sign(hashlib.sha256(hrp.encode() + _to_bytes(data)).digest(), key)
    data += _to_words(signature)
    expanded = [ord(char) >> 5 for char in hrp] + [0] + [ord(char) & 31 for char in hrp]
    checksum = _polymod([*expanded, *data, 0, 0, 0, 0, 0, 0]) ^ 1
    data += [(checksum >> (5 * (5 - index))) & 31 for index in range(6)]
    return hrp + "1" + "".join(_CHARSET[word] for word in data)
