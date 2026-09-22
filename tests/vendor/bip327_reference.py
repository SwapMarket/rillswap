"""Test-only ordered BIP327 key aggregation subset.

Derived from bitcoin/bips bip-0327/reference.py at commit
acdce4d50c61f81d9ec6534a804b1fb14e84e565 under BSD-3-Clause.
Copyright (c) 2022 Jonas Nick, Tim Ruffing, and Elliott Jin.
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
    """Return the BIP340-style tagged hash used by BIP327 and BIP341."""
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


def _lift_x(value: bytes) -> Point:
    x_coordinate = int.from_bytes(value, "big")
    if x_coordinate >= FIELD_PRIME:
        return None
    y_squared = (pow(x_coordinate, 3, FIELD_PRIME) + 7) % FIELD_PRIME
    y_coordinate = pow(y_squared, (FIELD_PRIME + 1) // 4, FIELD_PRIME)
    if pow(y_coordinate, 2, FIELD_PRIME) != y_squared:
        return None
    if y_coordinate & 1:
        y_coordinate = FIELD_PRIME - y_coordinate
    return x_coordinate, y_coordinate


def _compressed_point(encoded: bytes) -> Point:
    if len(encoded) != 33 or encoded[0] not in (2, 3):
        raise ValueError("invalid compressed public key")
    point = _lift_x(encoded[1:])
    if point is None:
        raise ValueError("compressed public key is not on secp256k1")
    if (point[1] & 1) != (encoded[0] & 1):
        return point[0], FIELD_PRIME - point[1]
    return point


def _compressed_bytes(point: Point) -> bytes:
    if point is None:
        raise ValueError("cannot serialize the point at infinity")
    return bytes([2 | (point[1] & 1)]) + point[0].to_bytes(32, "big")


def individual_public_key(secret_key: bytes) -> bytes:
    """Return the compressed public key corresponding to a fixture secret."""
    scalar = int.from_bytes(secret_key, "big")
    if not 1 <= scalar < GROUP_ORDER:
        raise ValueError("secret key is outside the secp256k1 scalar range")
    return _compressed_bytes(_point_multiply(GENERATOR, scalar))


def key_aggregate(public_keys: list[bytes]) -> tuple[bytes, int]:
    """Aggregate ordered compressed keys and return x-only key and full parity."""
    if not public_keys:
        raise ValueError("at least one public key is required")
    second_key = next(
        (key for key in public_keys[1:] if key != public_keys[0]), b"\x00" * 33
    )
    key_list_hash = tagged_hash("KeyAgg list", b"".join(public_keys))
    aggregate = None
    for public_key in public_keys:
        point = _compressed_point(public_key)
        coefficient = (
            1
            if public_key == second_key
            else int.from_bytes(
                tagged_hash("KeyAgg coefficient", key_list_hash + public_key),
                "big",
            )
            % GROUP_ORDER
        )
        aggregate = _point_add(aggregate, _point_multiply(point, coefficient))
    if aggregate is None:
        raise ValueError("key aggregation produced the point at infinity")
    return aggregate[0].to_bytes(32, "big"), aggregate[1] & 1


def xonly_tweak_add(internal_key: bytes, tweak: bytes) -> tuple[bytes, int]:
    """Apply a BIP341 x-only tweak and return output x-coordinate and parity."""
    internal_point = _lift_x(internal_key)
    tweak_scalar = int.from_bytes(tweak, "big")
    if internal_point is None or tweak_scalar >= GROUP_ORDER:
        raise ValueError("invalid x-only tweak input")
    output = _point_add(internal_point, _point_multiply(GENERATOR, tweak_scalar))
    if output is None:
        raise ValueError("x-only tweak produced the point at infinity")
    return output[0].to_bytes(32, "big"), output[1] & 1
