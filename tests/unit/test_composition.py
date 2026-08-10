"""M4 composition grammar and planner tests."""

from __future__ import annotations

from pathlib import Path

from smallestlie.attacks.catalog import load_catalog
from smallestlie.attacks.composition import CompositionLimits, compose_pair, pairwise_candidates
from smallestlie.attacks.planner import interaction_report, plan_campaign
from smallestlie.policy.authorization import ALLOWED_FAMILIES


ROOT = Path(__file__).resolve().parents[2]


def test_compose_pair_sequences_mutations() -> None:
    catalog = load_catalog(
        ROOT / "catalogs" / "canonical-m1.yaml",
        attacks_root=ROOT / "attacks",
    )
    a = catalog.attacks["PATH-002"]
    b = catalog.attacks["EVD-002"]
    c = compose_pair(a, b, seed=49314)
    assert c.family == "composition"
    assert c.attack_id == "CMP-PATH-002+EVD-002"
    assert len(c.mutations) == len(a.mutations) + len(b.mutations)
    assert c.raw["parents"] == ["PATH-002", "EVD-002"]


def test_pairwise_respects_budget_and_is_deterministic() -> None:
    catalog = load_catalog(
        ROOT / "catalogs" / "canonical-m1.yaml",
        attacks_root=ROOT / "attacks",
    )
    singles = catalog.singles()[:5]
    limits = CompositionLimits(max_compound_runs=3)
    p1 = pairwise_candidates(singles, seed=49314, limits=limits)
    p2 = pairwise_candidates(singles, seed=49314, limits=limits)
    assert len(p1) == 3
    assert [x.attack_id for x in p1] == [x.attack_id for x in p2]


def test_plan_mixed_discloses_truncation() -> None:
    catalog = load_catalog(
        ROOT / "catalogs" / "canonical-m1.yaml",
        attacks_root=ROOT / "attacks",
    )
    plan = plan_campaign(
        catalog,
        seed=1,
        baseline_digest="b",
        authorization_digest="a",
        allowed_families=set(ALLOWED_FAMILIES),
        mode="mixed",
        composition_limits=CompositionLimits(max_compound_runs=2),
        compound_specs=[],
    )
    assert plan["composition"]["truncated"] is True
    assert plan["composition"]["truncation_disclosed"] is True
    # drop private registry for digest stability check
    p1 = {k: v for k, v in plan.items() if k != "_composed_specs"}
    plan2 = plan_campaign(
        catalog,
        seed=1,
        baseline_digest="b",
        authorization_digest="a",
        allowed_families=set(ALLOWED_FAMILIES),
        mode="mixed",
        composition_limits=CompositionLimits(max_compound_runs=2),
        compound_specs=[],
    )
    assert p1["plan_digest"] == plan2["plan_digest"]


def test_interaction_report_compound_only() -> None:
    plan = {
        "runs": [
            {"attack_id": "PATH-002", "kind": "single"},
            {"attack_id": "EVD-002", "kind": "single"},
            {
                "attack_id": "CMP-001",
                "kind": "compound_declared",
                "parents": ["PATH-002", "EVD-002"],
            },
        ]
    }
    results = [
        {"attack_id": "PATH-002", "comparison": {"result": "ATTACK_REJECTED"}},
        {"attack_id": "EVD-002", "comparison": {"result": "ATTACK_REJECTED"}},
        {"attack_id": "CMP-001", "comparison": {"result": "FALSE_ACCEPT_OBSERVED"}},
    ]
    ix = interaction_report(plan, results)
    assert len(ix["compound_only_false_accepts"]) == 1
    assert ix["compound_only_false_accepts"][0]["attack_id"] == "CMP-001"
