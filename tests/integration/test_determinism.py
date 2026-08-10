"""Plan determinism under fixed seed."""

from __future__ import annotations

from pathlib import Path

from smallestlie.attacks.catalog import load_catalog
from smallestlie.attacks.planner import plan_campaign
from smallestlie.policy.authorization import ALLOWED_FAMILIES


ROOT = Path(__file__).resolve().parents[2]


def test_identical_seed_produces_identical_plan() -> None:
    catalog = load_catalog(
        ROOT / "catalogs" / "canonical-m1.yaml",
        attacks_root=ROOT / "attacks",
    )
    p1 = plan_campaign(
        catalog,
        seed=49314,
        baseline_digest="abc",
        authorization_digest="def",
        allowed_families=set(ALLOWED_FAMILIES),
    )
    p2 = plan_campaign(
        catalog,
        seed=49314,
        baseline_digest="abc",
        authorization_digest="def",
        allowed_families=set(ALLOWED_FAMILIES),
    )
    assert p1["plan_digest"] == p2["plan_digest"]
    assert [r["mutation_fingerprint"] for r in p1["runs"]] == [
        r["mutation_fingerprint"] for r in p2["runs"]
    ]
