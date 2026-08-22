from __future__ import annotations

import hashlib
import json
import math
import unicodedata
from collections.abc import Mapping, Sequence
from typing import Any


MAX_SAFE_INTEGER = 9_007_199_254_740_991
MAX_CANONICAL_DEPTH = 8
MAX_CANONICAL_ITEMS = 256
MAX_CANONICAL_STRING_BYTES = 16_384


class CanonicalizationError(ValueError):
    pass


def _reject_float(_value: str) -> None:
    raise CanonicalizationError("floating-point JSON values are not permitted")


def _reject_constant(value: str) -> None:
    raise CanonicalizationError(f"non-finite JSON value is not permitted: {value}")


def _object_without_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise CanonicalizationError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _canonical_value(value: Any, *, depth: int = 0, active: set[int] | None = None) -> Any:
    if depth > MAX_CANONICAL_DEPTH:
        raise CanonicalizationError("canonical value exceeds nesting limit")
    if value is None or isinstance(value, bool):
        return value
    if isinstance(value, int):
        if abs(value) > MAX_SAFE_INTEGER:
            raise CanonicalizationError("integer exceeds the interoperable exact range")
        return value
    if isinstance(value, float):
        # Protocol numbers are integer-only. The JSON parsers already reject
        # floating-point tokens; rejecting them here as well guarantees that
        # programmatically built objects can never disagree with parsed
        # objects, or with the TypeScript implementation, about numeric form.
        raise CanonicalizationError("floating-point values are not permitted")
    if isinstance(value, str):
        if unicodedata.normalize("NFC", value) != value:
            raise CanonicalizationError("strings must already be Unicode NFC")
        if len(value.encode("utf-8")) > MAX_CANONICAL_STRING_BYTES:
            raise CanonicalizationError("string exceeds canonical byte limit")
        return value

    if active is None:
        active = set()
    identity = id(value)
    if identity in active:
        raise CanonicalizationError("cyclic values are not permitted")

    if isinstance(value, Mapping):
        if len(value) > MAX_CANONICAL_ITEMS:
            raise CanonicalizationError("object exceeds canonical item limit")
        active.add(identity)
        try:
            output: dict[str, Any] = {}
            keys = list(value)
            if any(not isinstance(key, str) for key in keys):
                raise CanonicalizationError("object keys must be strings")
            for key in sorted(keys):
                canonical_key = _canonical_value(key, depth=depth + 1, active=active)
                output[canonical_key] = _canonical_value(value[key], depth=depth + 1, active=active)
            return output
        finally:
            active.remove(identity)

    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        if len(value) > MAX_CANONICAL_ITEMS:
            raise CanonicalizationError("array exceeds canonical item limit")
        active.add(identity)
        try:
            return [_canonical_value(item, depth=depth + 1, active=active) for item in value]
        finally:
            active.remove(identity)
    raise CanonicalizationError(f"unsupported canonical value: {type(value).__name__}")


def canonical_bytes(value: Any) -> bytes:
    canonical = _canonical_value(value)
    return json.dumps(
        canonical,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def strict_json_loads(data: str | bytes, *, require_canonical: bool = False) -> Any:
    try:
        text = data.decode("utf-8", errors="strict") if isinstance(data, bytes) else data
        value = json.loads(
            text,
            object_pairs_hook=_object_without_duplicates,
            parse_float=_reject_float,
            parse_constant=_reject_constant,
        )
    except UnicodeDecodeError as exc:
        raise CanonicalizationError("JSON is not valid UTF-8") from exc
    except json.JSONDecodeError as exc:
        raise CanonicalizationError("JSON is malformed or contains trailing data") from exc
    encoded = canonical_bytes(value)
    if require_canonical and encoded != text.encode("utf-8"):
        raise CanonicalizationError("JSON input is not in canonical form")
    return value


def digest(value: Any) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()
