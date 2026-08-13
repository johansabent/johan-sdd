"""Deterministic JSON primitives used by lifecycle artifacts.

The public contracts contain strings, integers, booleans, nulls, arrays, and
objects.  Floats are intentionally rejected: accepting them would require the
ECMAScript number serialization part of RFC 8785 and lifecycle contracts have
no floating-point fields.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping, Sequence
from typing import Any


class CanonicalizationError(ValueError):
    """Raised when a value is outside the contract's canonical JSON subset."""


def _utf16_sort_key(value: str) -> bytes:
    return value.encode("utf-16-be", errors="surrogatepass")


def _normalize(value: Any) -> Any:
    if value is None or isinstance(value, (str, bool)):
        return value
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        raise CanonicalizationError("floating-point values are not allowed in lifecycle artifacts")
    if isinstance(value, Mapping):
        normalized: dict[str, Any] = {}
        for key in sorted(value, key=lambda item: _utf16_sort_key(_require_string_key(item))):
            normalized[key] = _normalize(value[key])
        return normalized
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return [_normalize(item) for item in value]
    raise CanonicalizationError(f"unsupported canonical JSON value: {type(value).__name__}")


def _require_string_key(value: object) -> str:
    if not isinstance(value, str):
        raise CanonicalizationError("canonical JSON object keys must be strings")
    return value


def canonical_bytes(value: Any) -> bytes:
    """Return RFC 8785-compatible bytes for the contract's JSON subset."""

    normalized = _normalize(value)
    try:
        rendered = json.dumps(
            normalized,
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
        )
        return rendered.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise CanonicalizationError("lone Unicode surrogates are not valid JSON strings") from exc


def canonical_digest(value: Any) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()
