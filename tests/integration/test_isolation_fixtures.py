"""Isolation fixtures: each surface yields FA for its catalog only."""

from __future__ import annotations

from pathlib import Path

import pytest

from smallestlie.campaign.runner import run_campaign
from smallestlie.models import ComparisonResult


ROOT = Path(__file__).resolve().parents[2]


@pytest.mark.integration
@pytest.mark.parametrize(
    "fixture,catalog,expect_fa",
    [
        ("stale_evidence_gate", "catalogs/isolation-stale.yaml", {"EVD-002", "TIME-001"}),
        ("path_blind_gate", "catalogs/isolation-path.yaml", {"PATH-001", "PATH-002"}),
        ("authority_blind_gate", "catalogs/isolation-authority.yaml", {"AUTH-001"}),
    ],
)
def test_isolation_fixture_false_accepts(
    tmp_path: Path, fixture: str, catalog: str, expect_fa: set[str]
) -> None:
    summary = run_campaign(
        target=ROOT / "fixtures" / fixture,
        catalog_path=ROOT / catalog,
        output_root=tmp_path / "outputs",
        seed=49314,
        project_root=ROOT,
    )
    assert summary["source_immutable"] is True
    by_id = {
        r["attack_id"]: (r.get("comparison") or {}).get("result")
        for r in summary["runs"]
        if not r.get("skipped")
    }
    for aid in expect_fa:
        assert by_id.get(aid) == ComparisonResult.FALSE_ACCEPT_OBSERVED.value, (
            fixture,
            aid,
            by_id,
        )


@pytest.mark.integration
def test_vrf_001_false_accept_on_honest(tmp_path: Path) -> None:
    """VRF-001 disables revision rule + stale evidence → FA on honest_gate."""
    cat_path = tmp_path / "vrf.yaml"
    cat_path.write_text(
        "name: vrf-only\nmode: single\nattacks:\n  - VRF-001\n",
        encoding="utf-8",
    )
    summary = run_campaign(
        target=ROOT / "fixtures" / "honest_gate",
        catalog_path=cat_path,
        output_root=tmp_path / "out",
        seed=49314,
        project_root=ROOT,
    )
    by_id = {r["attack_id"]: r for r in summary["runs"] if not r.get("skipped")}
    assert "VRF-001" in by_id
    assert (
        by_id["VRF-001"].get("comparison", {}).get("result")
        == ComparisonResult.FALSE_ACCEPT_OBSERVED.value
    )
