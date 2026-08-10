"""M5 CI gate integration."""

from __future__ import annotations

from pathlib import Path

import pytest

from smallestlie.ci.gate import CiGateConfig, CiProfile, run_ci_gate
from smallestlie.ci.status import CiProjection


ROOT = Path(__file__).resolve().parents[2]


@pytest.mark.integration
def test_ci_gate_offline_expectations(tmp_path: Path) -> None:
    cfg = CiGateConfig(
        budget_seconds=300,
        output_root=str(tmp_path / "outputs" / "ci"),
        artifact_dir=str(tmp_path / "artifacts" / "smallestlie"),
        seed=49314,
    )
    profiles = [
        CiProfile(
            name="naive_expect_false_accept",
            target="fixtures/naive_gate",
            catalog="catalogs/ci-offline-fast.yaml",
            expect="fail_false_accept",
            seed=49314,
        ),
        CiProfile(
            name="honest_expect_clean",
            target="fixtures/honest_gate",
            catalog="catalogs/ci-offline-fast.yaml",
            expect="pass_no_false_accept",
            seed=49314,
        ),
    ]
    summary = run_ci_gate(project_root=ROOT, config=cfg, profiles=profiles)
    assert summary["exit_code"] == 0
    assert summary["projection"] == CiProjection.PASS_NO_FALSE_ACCEPT_OBSERVED.value
    assert summary["gha_conclusion"] == "success"
    by_name = {p["name"]: p for p in summary["profiles"]}
    assert by_name["naive_expect_false_accept"]["expectation_met"] is True
    assert by_name["naive_expect_false_accept"]["false_accept_count"] >= 1
    assert by_name["honest_expect_clean"]["expectation_met"] is True
    assert by_name["honest_expect_clean"]["false_accept_count"] == 0
    # Artifacts staged
    art = Path(summary["artifacts"]["staging_dir"])
    assert (art / "ci-summary.json").is_file()
    assert (art / "ci-summary.md").is_file()


@pytest.mark.integration
def test_ci_gate_budget_skip_is_not_pass(tmp_path: Path) -> None:
    cfg = CiGateConfig(
        budget_seconds=0,  # force skip
        output_root=str(tmp_path / "outputs" / "ci"),
        artifact_dir=str(tmp_path / "artifacts" / "smallestlie"),
    )
    profiles = [
        CiProfile(
            name="naive_expect_false_accept",
            target="fixtures/naive_gate",
            catalog="catalogs/ci-offline-fast.yaml",
            expect="fail_false_accept",
        ),
    ]
    summary = run_ci_gate(project_root=ROOT, config=cfg, profiles=profiles)
    assert summary["exit_code"] != 0
    assert summary["projection"] == CiProjection.SKIPPED_NOT_RUN.value
    assert summary["gha_conclusion"] == "failure"
