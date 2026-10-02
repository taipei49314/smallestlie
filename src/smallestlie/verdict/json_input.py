"""Read a single unambiguous JSON value from verifier output."""

from __future__ import annotations

import json
from typing import Any


def _object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _constant(value: str) -> Any:
    raise ValueError(f"nonstandard JSON constant: {value}")


def read_json(text: str) -> Any:
    try:
        return json.loads(text, object_pairs_hook=_object, parse_constant=_constant)
    except RecursionError as exc:
        raise ValueError("verifier JSON exceeds supported nesting depth") from exc
