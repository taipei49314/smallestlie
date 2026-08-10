"""Deterministic campaign planner."""

from __future__ import annotations

import hashlib
import json
from typing import Any

from smallestlie.attacks.catalog import AttackCatalog
from smallestlie.attacks.schema import AttackSpec


def plan_campaign(
    catalog: AttackCatalog,
    *,
    seed: int,
    baseline_digest: str,
    authorization_digest: str,
    allowed_families: set[str],
) -> dict[str, Any]:
    runs: list[dict[str, Any]] = []
    for idx, attack in enumerate(catalog.ordered()):
        if attack.family not in allowed_families:
            status = "INAPPLICABLE"
            reason = f"family {attack.family} not in authorization"
        else:
            status = "PLANNED"
            reason = "family authorized"
        run_id = f"RUN-{idx + 1:05d}"
        runs.append(
            {
                "run_id": run_id,
                "attack_id": attack.attack_id,
                "family": attack.family,
                "name": attack.name,
                "status": status,
                "reason": reason,
                "mutation_fingerprint": mutation_fingerprint(attack, seed=seed),
            }
        )

    plan = {
        "schema_version": "smallestlie.plan/v1",
        "catalog": catalog.name,
        "seed": seed,
        "baseline_digest": baseline_digest,
        "authorization_digest": authorization_digest,
        "runs": runs,
    }
    plan["plan_digest"] = hashlib.sha256(
        json.dumps(plan, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
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
