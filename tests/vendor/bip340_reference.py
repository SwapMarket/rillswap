"""Test-only BIP340 reference implementation.

Derived from bitcoin/bips bip-0340/reference.py at commit
f98774a68c23269d9bfa78c8d9c4671ebf4ceb69 under its CC0-1.0 option.
This intentionally slow implementation is not suitable for production use.
"""

from __future__ import annotations

import hashlib

type Point = tuple[int, int] | None

FIELD_PRIME = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
GROUP_ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
GENERATOR: Point = (
    0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
    0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8,
)


def tagged_hash(tag: str, message: bytes) -> bytes:
    """Return the BIP340 tagged hash of a message."""
    tag_hash = hashlib.sha256(tag.encode()).digest()
    return hashlib.sha256(tag_hash + tag_hash + message).digest()


def _point_add(first: Point, second: Point) -> Point:
    if first is None:
        return second
    if second is None:
        return first
    first_x, first_y = first
    second_x, second_y = second
    if first_x == second_x and first_y != second_y:
        return None
    if first == second:
        slope = 3 * first_x * first_x * pow(2 * first_y, FIELD_PRIME - 2, FIELD_PRIME)
    else:
        slope = (second_y - first_y) * pow(
            second_x - first_x,
            FIELD_PRIME - 2,
            FIELD_PRIME,
        )
    slope %= FIELD_PRIME
    result_x = (slope * slope - first_x - second_x) % FIELD_PRIME
    return result_x, (slope * (first_x - result_x) - first_y) % FIELD_PRIME


def _point_multiply(point: Point, scalar: int) -> Point:
    result = None
    for bit in range(256):
        if (scalar >> bit) & 1:
            result = _point_add(result, point)
        point = _point_add(point, point)
    return result


def _bytes_from_int(value: int) -> bytes:
    return value.to_bytes(32, byteorder="big")


def _lift_x(x_coordinate: int) -> Point:
    if x_coordinate >= FIELD_PRIME:
        return None
    y_squared = (pow(x_coordinate, 3, FIELD_PRIME) + 7) % FIELD_PRIME
    y_coordinate = pow(y_squared, (FIELD_PRIME + 1) // 4, FIELD_PRIME)
    if pow(y_coordinate, 2, FIELD_PRIME) != y_squared:
        return None
    if y_coordinate & 1:
        y_coordinate = FIELD_PRIME - y_coordinate
    return x_coordinate, y_coordinate


def public_key(secret_key: bytes) -> bytes:
    """Derive the BIP340 x-only public key for a fixture secret."""
    secret = int.from_bytes(secret_key, byteorder="big")
    if not 1 <= secret < GROUP_ORDER:
        raise ValueError("secret key is outside the secp256k1 scalar range")
    point = _point_multiply(GENERATOR, secret)
    if point is None:
        raise AssertionError("valid scalar produced the point at infinity")
    return _bytes_from_int(point[0])


def sign(message: bytes, secret_key: bytes, auxiliary_random: bytes) -> bytes:
    """Produce the deterministic fixture signature from explicit auxiliary input."""
    secret = int.from_bytes(secret_key, byteorder="big")
    if not 1 <= secret < GROUP_ORDER:
        raise ValueError("secret key is outside the secp256k1 scalar range")
    if len(auxiliary_random) != 32:
        raise ValueError("auxiliary input must contain 32 bytes")
    public_point = _point_multiply(GENERATOR, secret)
    if public_point is None:
        raise AssertionError("valid scalar produced the point at infinity")
    adjusted_secret = secret if public_point[1] % 2 == 0 else GROUP_ORDER - secret
    secret_mask = tagged_hash("BIP0340/aux", auxiliary_random)
    masked_secret = bytes(
        left ^ right
        for left, right in zip(_bytes_from_int(adjusted_secret), secret_mask)
    )
    public_key_bytes = _bytes_from_int(public_point[0])
    nonce = (
        int.from_bytes(
            tagged_hash("BIP0340/nonce", masked_secret + public_key_bytes + message),
            byteorder="big",
        )
        % GROUP_ORDER
    )
    if nonce == 0:
        raise RuntimeError("BIP340 nonce generation produced zero")
    nonce_point = _point_multiply(GENERATOR, nonce)
    if nonce_point is None:
        raise AssertionError("valid nonce produced the point at infinity")
    adjusted_nonce = nonce if nonce_point[1] % 2 == 0 else GROUP_ORDER - nonce
    nonce_x = _bytes_from_int(nonce_point[0])
    challenge = (
        int.from_bytes(
            tagged_hash("BIP0340/challenge", nonce_x + public_key_bytes + message),
            byteorder="big",
        )
        % GROUP_ORDER
    )
    signature = nonce_x + _bytes_from_int(
        (adjusted_nonce + challenge * adjusted_secret) % GROUP_ORDER,
    )
    if not verify(message, public_key_bytes, signature):
        raise RuntimeError("generated BIP340 signature did not verify")
    return signature


def verify(message: bytes, public_key_bytes: bytes, signature: bytes) -> bool:
    """Verify a BIP340 signature using independent pure-Python arithmetic."""
    if len(public_key_bytes) != 32 or len(signature) != 64:
        return False
    public_point = _lift_x(int.from_bytes(public_key_bytes, byteorder="big"))
    nonce_x = int.from_bytes(signature[:32], byteorder="big")
    scalar = int.from_bytes(signature[32:], byteorder="big")
    if public_point is None or nonce_x >= FIELD_PRIME or scalar >= GROUP_ORDER:
        return False
    challenge = (
        int.from_bytes(
            tagged_hash(
                "BIP0340/challenge",
                signature[:32] + public_key_bytes + message,
            ),
            byteorder="big",
        )
        % GROUP_ORDER
    )
    nonce_point = _point_add(
        _point_multiply(GENERATOR, scalar),
        _point_multiply(public_point, GROUP_ORDER - challenge),
    )
    return (
        nonce_point is not None
        and nonce_point[1] % 2 == 0
        and nonce_point[0] == nonce_x
    )
