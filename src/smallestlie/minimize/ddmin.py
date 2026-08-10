"""Delta-debugging minimizer for mutation sequences."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable


Predicate = Callable[[list[dict[str, Any]]], bool]


@dataclass
class MinimizeResult:
    original_steps: int
    minimal_steps: int
    minimal_mutations: list[dict[str, Any]]
    rounds: int
    interesting_cache_hits: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "original_steps": self.original_steps,
            "minimal_steps": self.minimal_steps,
            "minimal_mutations": self.minimal_mutations,
            "rounds": self.rounds,
            "interesting_cache_hits": self.interesting_cache_hits,
        }


def ddmin(mutations: list[dict[str, Any]], interesting: Predicate) -> MinimizeResult:
    """
    Classic ddmin over mutation step lists.

    `interesting(subset)` must return True iff the subset still reproduces the
    target property (typically FALSE_ACCEPT_OBSERVED).
    """
    if not mutations:
        return MinimizeResult(0, 0, [], 0, 0)

    # Ensure full set is interesting; otherwise return original.
    if not interesting(list(mutations)):
        return MinimizeResult(
            original_steps=len(mutations),
            minimal_steps=len(mutations),
            minimal_mutations=list(mutations),
            rounds=0,
            interesting_cache_hits=0,
        )

    cache: dict[str, bool] = {}
    hits = 0
    rounds = 0

    def cached(subset: list[dict[str, Any]]) -> bool:
        nonlocal hits
        key = repr(subset)
        if key in cache:
            hits += 1
            return cache[key]
        val = interesting(subset)
        cache[key] = val
        return val

    work = list(mutations)
    n = 2
    while len(work) >= 2:
        rounds += 1
        subsets = _split(work, n)
        reduced = False
        for subset in subsets:
            complement = [s for s in work if s not in subset]
            # Prefer complement that remains interesting (remove subset)
            if complement and cached(complement):
                work = complement
                n = max(n - 1, 2)
                reduced = True
                break
            if cached(subset):
                work = subset
                n = 2
                reduced = True
                break
        if not reduced:
            if n >= len(work):
                break
            n = min(len(work), n * 2)

    # Single-step granularity pass
    changed = True
    while changed and len(work) > 1:
        changed = False
        rounds += 1
        for i in range(len(work)):
            candidate = work[:i] + work[i + 1 :]
            if candidate and cached(candidate):
                work = candidate
                changed = True
                break

    return MinimizeResult(
        original_steps=len(mutations),
        minimal_steps=len(work),
        minimal_mutations=work,
        rounds=rounds,
        interesting_cache_hits=hits,
    )


def _split(items: list[dict[str, Any]], n: int) -> list[list[dict[str, Any]]]:
    if n <= 1:
        return [list(items)]
    n = min(n, len(items))
    size = len(items) // n
    subsets: list[list[dict[str, Any]]] = []
    start = 0
    for i in range(n):
        end = start + size if i < n - 1 else len(items)
        # distribute remainder to earlier chunks
        if i < len(items) % n:
            end += 1
        if start < end:
            subsets.append(items[start:end])
        start = end
    return [s for s in subsets if s]
