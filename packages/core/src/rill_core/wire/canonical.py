"""Bounded duplicate-safe JSON parsing and RFC8785 serialization."""

from __future__ import annotations

import json
from typing import Never, cast

import rfc8785
from pydantic import BaseModel

from rill_core.errors import CanonicalizationError

type JsonScalar = None | bool | int | str
type JsonValue = JsonScalar | list[JsonValue] | dict[str, JsonValue]

MAX_JSON_BYTES = 16 * 1024
MAX_DEPTH = 16
MAX_OBJECT_MEMBERS = 128
MAX_ARRAY_MEMBERS = 256
MAX_STRING_BYTES = 16 * 1024
MAX_EXACT_INTEGER = 9_007_199_254_740_991


def _reject_float(value: str) -> Never:
    raise CanonicalizationError(f"floating-point JSON value is forbidden: {value}")


def _reject_constant(value: str) -> Never:
    raise CanonicalizationError(f"non-finite JSON value is forbidden: {value}")


def _unique_object(pairs: list[tuple[str, JsonValue]]) -> dict[str, JsonValue]:
    result: dict[str, JsonValue] = {}
    for key, value in pairs:
        if key in result:
            raise CanonicalizationError(f"duplicate JSON object key: {key}")
        result[key] = value
    return result


def _validate_bounds(value: JsonValue, *, depth: int = 0) -> None:
    if depth > MAX_DEPTH:
        raise CanonicalizationError("JSON nesting exceeds the protocol limit")
    if isinstance(value, str):
        if len(value.encode("utf-8")) > MAX_STRING_BYTES:
            raise CanonicalizationError("JSON string exceeds the protocol limit")
        return
    if isinstance(value, bool) or value is None:
        return
    if isinstance(value, int):
        if not -MAX_EXACT_INTEGER <= value <= MAX_EXACT_INTEGER:
            raise CanonicalizationError("JSON integer exceeds the exact wire range")
        return
    if isinstance(value, list):
        if len(value) > MAX_ARRAY_MEMBERS:
            raise CanonicalizationError("JSON array exceeds the protocol limit")
        for item in value:
            _validate_bounds(item, depth=depth + 1)
        return
    if isinstance(value, dict):
        if len(value) > MAX_OBJECT_MEMBERS:
            raise CanonicalizationError("JSON object exceeds the protocol limit")
        for key, item in value.items():
            _validate_bounds(key, depth=depth + 1)
            _validate_bounds(item, depth=depth + 1)
        return
    raise CanonicalizationError(f"unsupported JSON value type: {type(value).__name__}")


def parse_json_strict(document: bytes) -> JsonValue:
    """Parse bounded UTF-8 JSON while rejecting duplicates and floats."""
    if not isinstance(document, bytes):
        raise CanonicalizationError("JSON document must be bytes")
    if len(document) > MAX_JSON_BYTES:
        raise CanonicalizationError("JSON document exceeds the protocol limit")
    try:
        text = document.decode("utf-8", errors="strict")
        value = json.loads(
            text,
            object_pairs_hook=_unique_object,
            parse_float=_reject_float,
            parse_constant=_reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise CanonicalizationError("invalid UTF-8 JSON document") from error
    typed_value = cast("JsonValue", value)
    _validate_bounds(typed_value)
    return typed_value


def canonicalize(value: JsonValue) -> bytes:
    """Validate and serialize a value using RFC8785 JCS."""
    _validate_bounds(value)
    try:
        return rfc8785.dumps(value)
    except (rfc8785.CanonicalizationError, rfc8785.FloatDomainError) as error:
        raise CanonicalizationError("value cannot be canonicalized") from error


def parse_and_canonicalize(document: bytes) -> tuple[JsonValue, bytes]:
    """Parse a document once and return its value and canonical bytes."""
    value = parse_json_strict(document)
    return value, canonicalize(value)


def parse_model_json[ModelT: BaseModel](model: type[ModelT], document: bytes) -> ModelT:
    """Strictly parse JSON once and validate it as a closed wire model."""
    parsed = parse_json_strict(document)
    return model.model_validate_json(canonicalize(parsed), strict=True)
