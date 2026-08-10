"""Greenwash-only adversarial campaigns (synthetic SUT)."""

from __future__ import annotations

from pathlib import Path

import pytest

from smallestlie.campaign.runner import run_campaign
from smallestlie.models import ComparisonResult


ROOT = Path(__file__).resolve().parents[2]

GW_ATTACKS = [
    "GW-EXE-003",
    "GW-EXE-002",
    "GW-EVD-002",
    "GW-CFG-001",
    "GW-PATH-001",
    "GW-PROJ-005",
    "GW-SEM-003",
]


@pytest.mark.integration
def test_greenwash_naive_false_accepts(tmp_path: Path) -> None:
    summary = run_campaign(
        target=ROOT / "fixtures" / "greenwash_naive",
        catalog_path=ROOT / "catalogs" / "greenwash-wave-a.yaml",
        output_root=tmp_path / "outputs",
        seed=49314,
        adapter_name="greenwash",
        project_root=ROOT,
    )
    assert summary["source_immutable"] is True
    assert summary["false_accept_count"] >= 5
    by = {
        r["attack_id"]: (r.get("comparison") or {}).get("result")
        for r in summary["runs"]
        if not r.get("skipped")
    }
    for aid in GW_ATTACKS:
        assert aid in by, aid
        assert by[aid] == ComparisonResult.FALSE_ACCEPT_OBSERVED.value, (aid, by[aid])


@pytest.mark.integration
def test_greenwash_honest_rejects_theater(tmp_path: Path) -> None:
    summary = run_campaign(
        target=ROOT / "fixtures" / "greenwash_honest",
        catalog_path=ROOT / "catalogs" / "greenwash-wave-a.yaml",
        output_root=tmp_path / "outputs",
        seed=49314,
        adapter_name="greenwash",
        project_root=ROOT,
    )
    assert summary["source_immutable"] is True
    assert summary["false_accept_count"] == 0
    by = {
        r["attack_id"]: (r.get("comparison") or {}).get("result")
        for r in summary["runs"]
        if not r.get("skipped")
    }
    for aid in GW_ATTACKS:
        assert by.get(aid) == ComparisonResult.ATTACK_REJECTED.value, (aid, by.get(aid))


@pytest.mark.integration
def test_greenwash_honest_control_clean(tmp_path: Path) -> None:
    from smallestlie.adapters.greenwash import GreenwashAdapter
    from smallestlie.policy.authorization import default_fixture_authorization
    from smallestlie.baseline.capture import capture_baseline
    from smallestlie.sandbox.workspace import DisposableWorkspace
    from smallestlie.sandbox.executor import SandboxExecutor
    from smallestlie.oracle.base import evaluate_oracle
    from smallestlie.verdict.compare import compare
    from smallestlie.models import ComparisonResult

    target = ROOT / "fixtures" / "greenwash_honest"
    adapter = GreenwashAdapter()
    auth = default_fixture_authorization(target)
    baseline = capture_baseline(
        target,
        adapter_name=adapter.name,
        adapter_version=adapter.version,
        authorization_digest=auth.digest(),
    )
    ws = DisposableWorkspace.create(target, parent_dir=tmp_path / "ws")
    try:
        spec = adapter.command_allowlist().resolve("run_greenwash_audit")
        ex = SandboxExecutor(ws.workspace_path).run(
            spec, extra_env={"PYTHONPATH": str(ws.workspace_path)}
        )
        verdict = adapter.parse_verdict(ws.workspace_path, ex)
        oracle = evaluate_oracle(
            ws.workspace_path,
            attack_oracle={"type": "theater_presence"},
            baseline=baseline,
            target_verdict=verdict,
        )
        assert ex.exit_code == 0, (ex.stdout, ex.stderr)
        assert verdict.accepted is True
        assert oracle.valid is True
        assert compare(oracle, verdict).result == ComparisonResult.TRUE_ACCEPT_OBSERVED
    finally:
        ws.cleanup()
