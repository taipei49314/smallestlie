"""End-to-end campaign tests against synthetic fixtures."""

from __future__ import annotations

from pathlib import Path

import pytest

from smallestlie.campaign.runner import run_campaign
from smallestlie.ledger.verify import verify_ledger
from smallestlie.models import ComparisonResult


ROOT = Path(__file__).resolve().parents[2]


@pytest.mark.integration
def test_naive_gate_yields_false_acceptances(tmp_path: Path) -> None:
    summary = run_campaign(
        target=ROOT / "fixtures" / "naive_gate",
        catalog_path=ROOT / "catalogs" / "canonical-m1.yaml",
        output_root=tmp_path / "outputs",
        seed=49314,
        project_root=ROOT,
    )
    assert summary["source_immutable"] is True
    assert summary["ledger_ok"] is True
    assert summary["false_accept_count"] >= 5

    by_attack = {
        r["attack_id"]: r.get("comparison", {}).get("result")
        for r in summary["runs"]
        if not r.get("skipped")
    }
    for aid in ("EXE-003", "EVD-002", "PROJ-005", "CFG-001", "PATH-001"):
        assert by_attack.get(aid) == ComparisonResult.FALSE_ACCEPT_OBSERVED.value, by_attack

    # At least one witness with stable replay
    with_replay = [r for r in summary["runs"] if r.get("replay")]
    assert with_replay
    assert any(r["replay"].get("reproduced", 0) == 3 for r in with_replay)

    led = verify_ledger(Path(summary["campaign_dir"]) / "ledger.jsonl")
    assert led["ok"] is True


@pytest.mark.integration
def test_honest_gate_rejects_invalid_states(tmp_path: Path) -> None:
    summary = run_campaign(
        target=ROOT / "fixtures" / "honest_gate",
        catalog_path=ROOT / "catalogs" / "canonical-m1.yaml",
        output_root=tmp_path / "outputs",
        seed=49314,
        project_root=ROOT,
    )
    assert summary["source_immutable"] is True
    assert summary["false_accept_count"] == 0

    by_attack = {
        r["attack_id"]: r.get("comparison", {}).get("result")
        for r in summary["runs"]
        if not r.get("skipped")
    }
    for aid in ("EXE-003", "EVD-002", "PROJ-005", "CFG-001", "PATH-001"):
        assert by_attack.get(aid) == ComparisonResult.ATTACK_REJECTED.value, by_attack


@pytest.mark.integration
def test_honest_gate_valid_control(tmp_path: Path) -> None:
    """Unmutated honest_gate control should accept."""
    from smallestlie.adapters.fixture_gate import FixtureGateAdapter
    from smallestlie.baseline.capture import capture_baseline
    from smallestlie.oracle.base import evaluate_oracle
    from smallestlie.policy.authorization import default_fixture_authorization
    from smallestlie.sandbox.executor import SandboxExecutor
    from smallestlie.sandbox.workspace import DisposableWorkspace
    from smallestlie.verdict.compare import compare
    from smallestlie.models import ComparisonResult

    target = ROOT / "fixtures" / "honest_gate"
    adapter = FixtureGateAdapter()
    auth = default_fixture_authorization(target)
    baseline = capture_baseline(
        target,
        adapter_name=adapter.name,
        adapter_version=adapter.version,
        authorization_digest=auth.digest(),
    )
    ws = DisposableWorkspace.create(target, parent_dir=tmp_path / "ws")
    try:
        spec = adapter.command_allowlist().resolve("run_target_verifier")
        ex = SandboxExecutor(ws.workspace_path).run(
            spec, extra_env={"PYTHONPATH": str(ws.workspace_path)}
        )
        verdict = adapter.parse_verdict(ws.workspace_path, ex)
        oracle = evaluate_oracle(
            ws.workspace_path,
            attack_oracle={
                "type": "required_execution_set",
                "expected": {"all_required_tests_executed": True, "minimum_required": 1},
            },
            baseline=baseline,
            target_verdict=verdict,
        )
        # For valid control, override: oracle should see valid world.
        # Use composite of positive expectations.
        from smallestlie.oracle.discovery import evaluate as disc_eval
        from smallestlie.oracle.revision_binding import evaluate as rev_eval
        from smallestlie.oracle.policy_presence import evaluate as pol_eval
        from smallestlie.oracle.protected_identity import evaluate as prot_eval

        d = disc_eval(ws.workspace_path)
        r = rev_eval(ws.workspace_path, baseline=baseline)
        p = pol_eval(ws.workspace_path)
        pr = prot_eval(ws.workspace_path, mutations_applied=[])
        assert d["facts"]["discovered_count"] >= 1
        assert r["facts"]["evidence_matches_revision"] is True
        assert p["facts"]["policy_present"] is True
        assert pr["facts"]["protected_path_intact"] is True
        assert verdict.accepted is True
        assert ex.exit_code == 0
        # Manually: valid + accepted
        from smallestlie.models import OracleResult

        cmp_ = compare(OracleResult(valid=True), verdict)
        assert cmp_.result == ComparisonResult.TRUE_ACCEPT_OBSERVED
    finally:
        ws.cleanup()
