"""Deterministic campaign planner (single + pairwise compound)."""

from __future__ import annotations

import hashlib
import json
from typing import Any, Literal

from smallestlie.attacks.catalog import AttackCatalog
from smallestlie.attacks.composition import (
    CompositionLimits,
    compose_pair,
    composition_fingerprint,
    pairwise_candidates,
)
from smallestlie.attacks.schema import AttackSpec, load_attack_spec


PlanMode = Literal["single", "pairwise", "mixed"]


def plan_campaign(
    catalog: AttackCatalog,
    *,
    seed: int,
    baseline_digest: str,
    authorization_digest: str,
    allowed_families: set[str],
    mode: PlanMode = "single",
    composition_limits: CompositionLimits | None = None,
    pairwise_allowlist: list[tuple[str, str]] | None = None,
    compound_specs: list[AttackSpec] | None = None,
) -> dict[str, Any]:
    """
    Build a deterministic campaign plan.

    Modes:
      - single: catalog attacks only
      - pairwise: auto-composed ordered pairs from applicable singles
      - mixed: singles first, then declarative compounds, then pairwise fill
    """
    limits = composition_limits or CompositionLimits()
    runs: list[dict[str, Any]] = []
    run_idx = 0
    composed_registry: dict[str, AttackSpec] = {}

    def add_run(attack: AttackSpec, *, kind: str, reason: str, status: str = "PLANNED") -> None:
        nonlocal run_idx
        if status == "PLANNED" and attack.family not in allowed_families:
            status = "INAPPLICABLE"
            reason = f"family {attack.family} not in authorization"
        run_idx += 1
        run_id = f"RUN-{run_idx:05d}"
        parents = None
        if kind != "single":
            parents = (attack.raw or {}).get("parents") or attack.applies_when.get(
                "parent_attacks"
            )
        entry = {
            "run_id": run_id,
            "attack_id": attack.attack_id,
            "family": attack.family,
            "name": attack.name,
            "kind": kind,
            "status": status,
            "reason": reason,
            "parents": parents,
            "mutation_fingerprint": (
                composition_fingerprint(attack, seed=seed)
                if kind != "single"
                else mutation_fingerprint(attack, seed=seed)
            ),
            "mutation_count": len(attack.mutations),
        }
        runs.append(entry)
        if kind != "single":
            composed_registry[attack.attack_id] = attack

    singles = catalog.singles() if hasattr(catalog, "singles") else [
        a for a in catalog.ordered() if a.family != "composition"
    ]
    if mode in ("single", "mixed"):
        for attack in singles:
            add_run(attack, kind="single", reason="catalog single")

    # Declarative compound specs (corpus)
    declared = compound_specs
    if declared is None and hasattr(catalog, "compounds"):
        declared = catalog.compounds()
    if mode in ("pairwise", "mixed") and declared:
        for spec in declared:
            add_run(spec, kind="compound_declared", reason="declarative compound corpus")

    truncated = False
    pairwise_generated = 0
    if mode in ("pairwise", "mixed"):
        # Only compose from non-composition singles that would be applicable
        applicable = [a for a in singles if a.family in allowed_families]
        # Budget remaining
        remaining = limits.max_compound_runs
        if mode == "mixed" and declared:
            remaining = max(0, limits.max_compound_runs - len(declared))
        pair_limits = CompositionLimits(
            max_depth=limits.max_depth,
            max_compound_runs=remaining,
            max_mutations_total=limits.max_mutations_total,
            require_distinct_families=limits.require_distinct_families,
            require_distinct_ids=limits.require_distinct_ids,
        )
        pairs = pairwise_candidates(
            applicable,
            seed=seed,
            limits=pair_limits,
            allowlist_pairs=pairwise_allowlist,
        )
        # Avoid duplicating declarative compound ids
        declared_ids = {s.attack_id for s in (declared or [])}
        for spec in pairs:
            if spec.attack_id in declared_ids:
                continue
            add_run(spec, kind="compound_pairwise", reason="auto pairwise SEQUENCE")
            pairwise_generated += 1
        # Detect truncation: if full product larger than remaining
        n = len(applicable)
        if pairwise_allowlist is not None:
            full = len(pairwise_allowlist)
        else:
            full = n * (n - 1) if n > 1 else 0
        if full > remaining:
            truncated = True

    plan = {
        "schema_version": "smallestlie.plan/v1",
        "catalog": catalog.name,
        "seed": seed,
        "mode": mode,
        "baseline_digest": baseline_digest,
        "authorization_digest": authorization_digest,
        "composition": {
            "max_depth": limits.max_depth,
            "max_compound_runs": limits.max_compound_runs,
            "max_mutations_total": limits.max_mutations_total,
            "pairwise_generated": pairwise_generated,
            "declared_compounds": len(compound_specs or []),
            "truncated": truncated,
            "truncation_disclosed": truncated,
        },
        "runs": runs,
    }
    plan["plan_digest"] = hashlib.sha256(
        json.dumps(plan, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
    ).hexdigest()
    # Attach in-memory registry for runner (not serialized to disk by default)
    plan["_composed_specs"] = composed_registry
    return plan


def mutation_fingerprint(attack: AttackSpec, *, seed: int) -> str:
    payload = {
        "attack_id": attack.attack_id,
        "mutations": attack.mutations,
        "seed": seed,
    }
    return hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
    ).hexdigest()


def load_compound_corpus(paths: list[str] | list[Any]) -> list[AttackSpec]:
    specs: list[AttackSpec] = []
    for p in paths:
        specs.append(load_attack_spec(p))
    return specs


def interaction_report(plan: dict[str, Any], run_results: list[dict[str, Any]]) -> dict[str, Any]:
    """Summarize single vs compound outcomes and parent lineage."""
    by_id = {r.get("attack_id"): r for r in run_results}
    compounds = []
    for planned in plan.get("runs") or []:
        if planned.get("kind") == "single":
            continue
        rid = planned.get("attack_id")
        result = by_id.get(rid) or {}
        parents = planned.get("parents") or []
        parent_results = {
            pid: (by_id.get(pid) or {}).get("comparison", {}).get("result") for pid in parents
        }
        compounds.append(
            {
                "attack_id": rid,
                "parents": parents,
                "parent_results": parent_results,
                "result": (result.get("comparison") or {}).get("result"),
                "minimal_steps": (result.get("minimization") or {}).get("minimal_steps"),
                "compound_only": _is_compound_only(parent_results, result),
            }
        )
    return {
        "schema_version": "smallestlie.interaction/v1",
        "compound_count": len(compounds),
        "compound_only_false_accepts": [
            c
            for c in compounds
            if c.get("compound_only") and c.get("result") == "FALSE_ACCEPT_OBSERVED"
        ],
        "compounds": compounds,
        "plan_truncated": bool((plan.get("composition") or {}).get("truncated")),
    }


def _is_compound_only(
    parent_results: dict[str, Any], compound_result: dict[str, Any]
) -> bool:
    """True if compound FA while no parent alone was FA (when parent results known)."""
    cmp_res = (compound_result.get("comparison") or {}).get("result")
    if cmp_res != "FALSE_ACCEPT_OBSERVED":
        return False
    if not parent_results:
        return False
    # If any parent missing from run results, cannot claim compound-only
    if any(v is None for v in parent_results.values()):
        return False
    return all(v != "FALSE_ACCEPT_OBSERVED" for v in parent_results.values())
