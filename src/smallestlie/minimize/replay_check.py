"""Replay stability helpers for minimized witnesses."""

from __future__ import annotations

from typing import Any, Callable

from smallestlie.models import ComparisonResult


def is_false_accept(comparison_result: str | ComparisonResult) -> bool:
    value = (
        comparison_result.value
        if isinstance(comparison_result, ComparisonResult)
        else str(comparison_result)
    )
    return value == ComparisonResult.FALSE_ACCEPT_OBSERVED.value


def confirm_reproductions(
    run_once: Callable[[], dict[str, Any]],
    *,
    attempts: int = 3,
) -> dict[str, Any]:
    successes = 0
    details: list[dict[str, Any]] = []
    for i in range(attempts):
        result = run_once()
        cmp_result = result.get("comparison", {}).get("result")
        ok = is_false_accept(cmp_result)
        if ok:
            successes += 1
        details.append(
            {
                "attempt": i + 1,
                "result": cmp_result,
                "target_accepted": result.get("target_accepted"),
                "oracle_valid": result.get("oracle_valid"),
            }
        )
    return {
        "attempts": attempts,
        "reproduced": successes,
        "stable": successes == attempts,
        "details": details,
    }
