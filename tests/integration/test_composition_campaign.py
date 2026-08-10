"""M4 compound campaign against composition_blind_gate."""

from __future__ import annotations

from pathlib import Path

import pytest

from smallestlie.campaign.runner import run_campaign
from smallestlie.models import ComparisonResult


ROOT = Path(__file__).resolve().parents[2]


@pytest.mark.integration
def test_composition_blind_requires_compound(tmp_path: Path) -> None:
    summary = run_campaign(
        target=ROOT / "fixtures" / "composition_blind_gate",
        catalog_path=ROOT / "catalogs" / "canonical-m4-compound.yaml",
        output_root=tmp_path / "outputs",
        seed=49314,
        project_root=ROOT,
        plan_mode="mixed",
    )
    assert summary["source_immutable"] is True
    assert summary["ledger_ok"] is True

    by_id = {r["attack_id"]: r for r in summary["runs"] if not r.get("skipped")}

    # Parents alone must not false-accept
    for parent in ("PATH-001", "PATH-002", "EVD-002"):
        assert parent in by_id, parent
        assert (
            by_id[parent].get("comparison", {}).get("result")
            == ComparisonResult.ATTACK_REJECTED.value
        ), (parent, by_id[parent].get("comparison"))

    # Declared compound must false-accept
    assert "CMP-001" in by_id
    assert (
        by_id["CMP-001"].get("comparison", {}).get("result")
        == ComparisonResult.FALSE_ACCEPT_OBSERVED.value
    )
    replay = by_id["CMP-001"].get("replay") or {}
    assert replay.get("reproduced") == 3
    # Minimizer should be able to run on multi-step compound
    mini = by_id["CMP-001"].get("minimization") or {}
    assert mini.get("original_steps", 0) >= 2
    assert mini.get("minimal_steps", 99) <= mini.get("original_steps", 0)

    ix = summary.get("interaction") or {}
    compound_only = ix.get("compound_only_false_accepts") or []
    assert any(c.get("attack_id") == "CMP-001" for c in compound_only)

    # Truncation must be disclosed if it happened
    assert "plan_truncated" in ix
