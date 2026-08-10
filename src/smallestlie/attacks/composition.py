"""Bounded composition grammar for compound attacks."""

from __future__ import annotations

import hashlib
import itertools
import json
from dataclasses import dataclass
from typing import Any, Iterable

from smallestlie.attacks.schema import AttackSpec, parse_attack_spec


DEFAULT_MAX_DEPTH = 2
DEFAULT_MAX_COMPOUND = 32


@dataclass(frozen=True)
class CompositionLimits:
    max_depth: int = DEFAULT_MAX_DEPTH
    max_compound_runs: int = DEFAULT_MAX_COMPOUND
    max_mutations_total: int = 16
    require_distinct_families: bool = False
    require_distinct_ids: bool = True


def compose_pair(
    left: AttackSpec,
    right: AttackSpec,
    *,
    seed: int,
    limits: CompositionLimits | None = None,
) -> AttackSpec:
    """SEQUENCE(left, right) as a deterministic compound AttackSpec."""
    limits = limits or CompositionLimits()
    if limits.require_distinct_ids and left.attack_id == right.attack_id:
        raise ValueError("compound parents must be distinct attack ids")
    if limits.require_distinct_families and left.family == right.family:
        raise ValueError("compound parents must be distinct families")

    mutations = list(left.mutations) + list(right.mutations)
    if len(mutations) > limits.max_mutations_total:
        raise ValueError(
            f"compound mutations {len(mutations)} exceed max {limits.max_mutations_total}"
        )

    compound_id = f"CMP-{left.attack_id}+{right.attack_id}"
    raw = {
        "schema_version": "smallestlie.attack/v1",
        "attack_id": compound_id,
        "name": f"compound:{left.attack_id}+{right.attack_id}",
        "family": "composition",
        "purpose": (
            f"Compound SEQUENCE of {left.attack_id} then {right.attack_id}. "
            f"Parents: {left.name} | {right.name}"
        ),
        "authorization_requirements": {
            "local_only": True,
            "network": "denied",
            "disposable_workspace": "required",
        },
        "applies_when": {
            "parent_attacks": [left.attack_id, right.attack_id],
            "composition": "SEQUENCE",
            "depth": 2,
        },
        "preconditions": _merge_preconditions(left.preconditions, right.preconditions),
        "mutations": mutations,
        "execute": dict(left.execute),  # same command_ref family expected
        "oracle": {
            "type": "composite",
            "plugins": [dict(left.oracle), dict(right.oracle)],
        },
        "false_accept_condition": {
            "target_accepted": True,
            "oracle_valid": False,
        },
        "minimization": {
            "remove_steps": True,
            "required_replays": 3,
            "compound": True,
            "parents": [left.attack_id, right.attack_id],
        },
        "regression_export": {
            "type": "smallestlie_fixture",
            "expected_future_verdict": "rejected",
        },
        "parents": [left.attack_id, right.attack_id],
        "composition": {
            "form": "SEQUENCE",
            "depth": 2,
            "seed": seed,
            "lineage": {
                "left": left.attack_id,
                "right": right.attack_id,
            },
        },
    }
    # Prefer right.execute timeout if larger
    lt = int(left.execute.get("timeout_seconds", 60))
    rt = int(right.execute.get("timeout_seconds", 60))
    raw["execute"]["timeout_seconds"] = max(lt, rt)
    if left.execute.get("command_ref") != right.execute.get("command_ref"):
        # Fail closed: mixed command refs need explicit declarative compound.
        raise ValueError(
            f"cannot auto-compose different command_ref: "
            f"{left.execute.get('command_ref')} vs {right.execute.get('command_ref')}"
        )
    return parse_attack_spec(raw, source_path=f"compose:{compound_id}")


def _merge_preconditions(
    a: list[dict[str, Any]], b: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    seen: set[str] = set()
    out: list[dict[str, Any]] = []
    for pre in list(a) + list(b):
        key = json.dumps(pre, sort_keys=True, default=str)
        if key in seen:
            continue
        seen.add(key)
        out.append(pre)
    return out


def pairwise_candidates(
    attacks: list[AttackSpec],
    *,
    seed: int,
    limits: CompositionLimits | None = None,
    allowlist_pairs: list[tuple[str, str]] | None = None,
) -> list[AttackSpec]:
    """
    Deterministic pairwise SEQUENCE candidates.

    If allowlist_pairs is set, only those ordered pairs are composed.
    Otherwise all ordered pairs i!=j are considered, pruned, then truncated
    to max_compound_runs with a stable seed-based order.
    """
    limits = limits or CompositionLimits()
    if limits.max_depth < 2:
        return []

    by_id = {a.attack_id: a for a in attacks}
    pairs: list[tuple[str, str]] = []
    if allowlist_pairs is not None:
        pairs = list(allowlist_pairs)
    else:
        ids = [a.attack_id for a in attacks]
        for a, b in itertools.product(ids, ids):
            if a == b and limits.require_distinct_ids:
                continue
            pairs.append((a, b))

    # Stable shuffle by seed (not random module — pure hash order)
    def pair_key(p: tuple[str, str]) -> str:
        payload = f"{seed}:{p[0]}:{p[1]}"
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    pairs_sorted = sorted(set(pairs), key=pair_key)

    compounds: list[AttackSpec] = []
    truncated = False
    for left_id, right_id in pairs_sorted:
        if left_id not in by_id or right_id not in by_id:
            continue
        left, right = by_id[left_id], by_id[right_id]
        if limits.require_distinct_families and left.family == right.family:
            continue
        # Redundancy pruning: skip if mutation lists are identical
        if left.mutations == right.mutations:
            continue
        try:
            compounds.append(compose_pair(left, right, seed=seed, limits=limits))
        except ValueError:
            continue
        if len(compounds) >= limits.max_compound_runs:
            truncated = True
            break

    # Stash truncation signal on first compound via raw if needed by planner
    if truncated and compounds:
        # Planner reads this from return metadata separately
        pass
    return compounds


def composition_fingerprint(spec: AttackSpec, *, seed: int) -> str:
    payload = {
        "attack_id": spec.attack_id,
        "parents": (spec.raw or {}).get("parents") or spec.applies_when.get("parent_attacks"),
        "mutations": spec.mutations,
        "seed": seed,
    }
    return hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
    ).hexdigest()
