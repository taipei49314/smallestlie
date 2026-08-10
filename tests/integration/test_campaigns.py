"""End-to-end campaign tests against synthetic fixtures."""

from __future__ import annotations

from pathlib import Path

import pytest

from smallestlie.campaign.runner import run_campaign
from smallestlie.ledger.verify import verify_ledger
from smallestlie.models import ComparisonResult


ROOT = Path(__file__).resolve().parents[2]

M1_ATTACKS = [
    "EVD-001",
    "EVD-002",
    "EVD-003",
    "EXE-001",
    "EXE-002",
    "EXE-003",
    "SEM-001",
    "SEM-003",
    "PATH-001",
    "PATH-002",
    "TIME-001",
    "WF-001",
    "AUTH-001",
    "CFG-001",
    "PROJ-005",
]


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
    assert summary["false_accept_count"] == len(M1_ATTACKS)

    by_attack = {
        r["attack_id"]: r
        for r in summary["runs"]
        if not r.get("skipped")
    }
    for aid in M1_ATTACKS:
        assert aid in by_attack, f"missing run for {aid}"
        assert (
            by_attack[aid].get("comparison", {}).get("result")
            == ComparisonResult.FALSE_ACCEPT_OBSERVED.value
        ), (aid, by_attack[aid].get("comparison"))
        # Stable replay for false accepts
        replay = by_attack[aid].get("replay") or {}
        assert replay.get("reproduced") == 3, (aid, replay)
        assert by_attack[aid].get("regression", {}).get("exported") is True

    # At least one multi-step attack was minimized
    multi = [
        r
        for r in summary["runs"]
        if (r.get("minimization") or {}).get("original_steps", 0) > 1
    ]
    assert multi
    assert any(
        (r.get("minimization") or {}).get("minimal_steps", 99)
        <= (r.get("minimization") or {}).get("original_steps", 0)
        for r in multi
    )

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
    for aid in M1_ATTACKS:
        assert by_attack.get(aid) == ComparisonResult.ATTACK_REJECTED.value, (
            aid,
            by_attack.get(aid),
            next(
                (r for r in summary["runs"] if r.get("attack_id") == aid),
                None,
            ),
        )


@pytest.mark.integration
def test_honest_gate_valid_control(tmp_path: Path) -> None:
    """Unmutated honest_gate control should accept."""
    from smallestlie.adapters.fixture_gate import FixtureGateAdapter
    from smallestlie.baseline.capture import capture_baseline
    from smallestlie.models import ComparisonResult, OracleResult
    from smallestlie.policy.authorization import default_fixture_authorization
    from smallestlie.sandbox.executor import SandboxExecutor
    from smallestlie.sandbox.workspace import DisposableWorkspace
    from smallestlie.verdict.compare import compare

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
        assert ex.exit_code == 0, (ex.stdout, ex.stderr)
        assert verdict.accepted is True

        from smallestlie.oracle.discovery import evaluate as disc_eval
        from smallestlie.oracle.revision_binding import evaluate as rev_eval
        from smallestlie.oracle.policy_presence import evaluate as pol_eval
        from smallestlie.oracle.protected_identity import evaluate as prot_eval
        from smallestlie.oracle.artifact_hash import evaluate as art_eval
        from smallestlie.oracle.authority import evaluate as auth_eval

        assert disc_eval(ws.workspace_path)["facts"]["discovered_count"] >= 1
        assert rev_eval(ws.workspace_path, baseline=baseline)["facts"][
            "evidence_matches_revision"
        ]
        assert pol_eval(ws.workspace_path)["facts"]["policy_present"]
        assert prot_eval(ws.workspace_path, mutations_applied=[])["facts"][
            "protected_path_intact"
        ]
        assert art_eval(ws.workspace_path)["facts"]["artifact_matches_manifest"]
        assert auth_eval(ws.workspace_path)["facts"]["approver_authorized"]

        cmp_ = compare(OracleResult(valid=True), verdict)
        assert cmp_.result == ComparisonResult.TRUE_ACCEPT_OBSERVED
    finally:
        ws.cleanup()
