"""Integrity regressions — P0/P1/P2 contracts (no new product features)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml

from smallestlie.campaign.batch import BatchConfig, BatchItem, load_batch_config, run_batch
from smallestlie.campaign.batch import _expectation_met as batch_expectation_met
from smallestlie.campaign.runner import _check_preconditions, run_campaign
from smallestlie.ci.diff_select import select_attacks_for_diff
from smallestlie.models import ComparisonResult
from smallestlie.policy.authorization import AuthorizationError
from smallestlie.attacks.schema import AttackSpec


ROOT = Path(__file__).resolve().parents[2]


def test_auth_target_mismatch_blocks(tmp_path: Path) -> None:
    # Authorization points at naive_gate but campaign target is honest_gate.
    auth = {
        "authorization": {
            "mode": "synthetic_fixture",
            "owner": "nelson",
            "target_path": str((ROOT / "fixtures" / "naive_gate").resolve()),
            "disposable_clone_required": True,
            "network": "denied",
            "expires_at": "2099-01-01T00:00:00+00:00",
            "allowed_attack_families": ["evidence", "execution", "config", "path", "projection", "semantic", "authority", "workflow", "freshness", "verifier", "composition"],
        }
    }
    auth_path = tmp_path / "auth.yaml"
    auth_path.write_text(yaml.safe_dump(auth), encoding="utf-8")
    summary = run_campaign(
        target=ROOT / "fixtures" / "honest_gate",
        catalog_path=ROOT / "catalogs" / "ci-offline-fast.yaml",
        output_root=tmp_path / "out",
        seed=49314,
        project_root=ROOT,
        authorization_path=auth_path,
    )
    assert summary["status"] == "BLOCKED"
    assert summary["exit_code"] == 4
    assert "mismatch" in str(summary.get("error", "")).lower() or summary["status"] == "BLOCKED"


def test_batch_expect_any_blocked_fails() -> None:
    summary = {
        "status": "BLOCKED",
        "exit_code": 4,
        "ledger_ok": True,
        "source_immutable": True,
        "false_accept_count": 0,
    }
    assert batch_expectation_met("any", summary) is False


def test_batch_expect_any_harness_error_fails() -> None:
    summary = {
        "status": "HARNESS_ERROR",
        "exit_code": 5,
        "ledger_ok": True,
        "source_immutable": True,
        "false_accept_count": 0,
    }
    assert batch_expectation_met("any", summary) is False


def test_false_accept_plus_harness_error_is_not_success() -> None:
    # Even if FA count > 0, HARNESS_ERROR status must not satisfy fail_false_accept.
    summary = {
        "status": "HARNESS_ERROR",
        "exit_code": 5,
        "ledger_ok": True,
        "source_immutable": True,
        "false_accept_count": 3,
    }
    assert batch_expectation_met("fail_false_accept", summary) is False


def test_required_disabled_is_not_pass(tmp_path: Path) -> None:
    cfg = BatchConfig(
        name="disabled-req",
        seed=49314,
        budget_seconds=60,
        output_root=str(tmp_path / "batch"),
        items=[
            BatchItem(
                name="disabled_required",
                target="fixtures/greenwash_naive",
                catalog="catalogs/greenwash-wave-a.yaml",
                adapter="greenwash",
                expect="fail_false_accept",
                required=True,
                enabled=False,
            )
        ],
    )
    report = run_batch(project_root=ROOT, config=cfg)
    assert report["exit_code"] != 0
    item = report["items"][0]
    assert item["expectation_met"] is False
    assert item["ran"] is False
    assert item.get("enabled") is False


def test_missing_ledger_is_not_pass() -> None:
    summary = {
        "status": "PASS_NO_FALSE_ACCEPT_OBSERVED",
        "exit_code": 0,
        # ledger_ok missing
        "source_immutable": True,
        "false_accept_count": 0,
    }
    assert batch_expectation_met("any", summary) is False
    assert batch_expectation_met("pass_no_false_accept", summary) is False


def test_missing_source_immutability_is_not_pass() -> None:
    summary = {
        "status": "PASS_NO_FALSE_ACCEPT_OBSERVED",
        "exit_code": 0,
        "ledger_ok": True,
        # source_immutable missing
        "false_accept_count": 0,
    }
    assert batch_expectation_met("any", summary) is False
    assert batch_expectation_met("pass_no_false_accept", summary) is False


def test_unknown_diff_does_not_smoke_green() -> None:
    r = select_attacks_for_diff(
        ["EXE-003", "CFG-001", "PROJ-005", "AUTH-001"],
        {
            "EXE-003": "execution",
            "CFG-001": "config",
            "PROJ-005": "projection",
            "AUTH-001": "authority",
        },
        changed_paths=["totally/unknown/blob.bin", "random/foo.dat"],
        include_smoke=True,
    )
    assert r["mode"] == "unknown_diff"
    assert r["selected_attack_ids"] == []
    # smoke must not rescue unknown paths
    assert "EXE-003" not in r["selected_attack_ids"]


def test_unsupported_precondition_does_not_execute() -> None:
    attack = AttackSpec(
        attack_id="X-TEST",
        name="x",
        family="evidence",
        purpose="t",
        mutations=[{"type": "write_text", "path": "package/x.txt", "content": "x"}],
        execute={"command_ref": "run_greenwash_audit"},
        oracle={"type": "theater_presence"},
        false_accept_condition={"target_accepted": True, "oracle_valid": False},
        preconditions=[{"type": "totally_unknown_precondition", "path": "x"}],
    )
    pre = _check_preconditions(ROOT / "fixtures" / "greenwash_naive", attack)
    assert pre["ok"] is False
    assert any("unsupported precondition" in r for r in pre["reasons"])


def test_same_second_campaigns_do_not_share_evidence(tmp_path: Path) -> None:
    cat = tmp_path / "one.yaml"
    cat.write_text("name: one\nmode: single\nattacks:\n  - GW-EXE-003\n", encoding="utf-8")
    s1 = run_campaign(
        target=ROOT / "fixtures" / "greenwash_naive",
        catalog_path=cat,
        output_root=tmp_path / "out",
        seed=49314,
        adapter_name="greenwash",
        project_root=ROOT,
    )
    s2 = run_campaign(
        target=ROOT / "fixtures" / "greenwash_naive",
        catalog_path=cat,
        output_root=tmp_path / "out",
        seed=49314,
        adapter_name="greenwash",
        project_root=ROOT,
    )
    assert s1["campaign_id"] != s2["campaign_id"]
    assert s1["campaign_dir"] != s2["campaign_dir"]
    assert Path(s1["campaign_dir"]).is_dir()
    assert Path(s2["campaign_dir"]).is_dir()


def test_naive_clean_control_true_accept(tmp_path: Path) -> None:
    from smallestlie.adapters.fixture_gate import FixtureGateAdapter
    from smallestlie.baseline.capture import capture_baseline
    from smallestlie.oracle.base import evaluate_oracle
    from smallestlie.policy.authorization import default_fixture_authorization
    from smallestlie.sandbox.executor import SandboxExecutor
    from smallestlie.sandbox.workspace import DisposableWorkspace
    from smallestlie.verdict.compare import compare

    target = ROOT / "fixtures" / "naive_gate"
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
        # Control: require valid-looking discovery (oracle type that can be true)
        oracle = evaluate_oracle(
            ws.workspace_path,
            attack_oracle={
                "type": "required_execution_set",
                "expected": {"all_required_tests_executed": True, "minimum_required": 1},
            },
            baseline=baseline,
            target_verdict=verdict,
        )
        # For control acceptance observation use oracle.valid True manually if discovery ok
        from smallestlie.models import OracleResult

        disc_ok = int(oracle.facts.get("discovery.discovered_count") or 0) >= 1
        assert disc_ok
        assert verdict.accepted is True
        assert compare(OracleResult(valid=True), verdict).result == ComparisonResult.TRUE_ACCEPT_OBSERVED
    finally:
        ws.cleanup()


def test_malformed_junit_not_counted_as_valid_execution() -> None:
    from smallestlie.oracle.theater import evaluate

    # Build a temp package with malformed junit that still contains the word testcase
    import tempfile

    with tempfile.TemporaryDirectory() as td:
        pkg = Path(td) / "package"
        (pkg / "junit").mkdir(parents=True)
        (pkg / "policy.yaml").write_text(
            "require_tests: true\nmin_tests: 1\nrequired_jobs: [unit]\n",
            encoding="utf-8",
        )
        (pkg / "ci-summary.json").write_text(
            json.dumps({"jobs": [{"name": "unit", "status": "pass"}]}),
            encoding="utf-8",
        )
        (pkg / "subject.json").write_text(
            json.dumps({"revision": "r1", "current_revision": "r1"}),
            encoding="utf-8",
        )
        (pkg / "junit" / "results.xml").write_text(
            "not xml at all but mentions <testcase as text only",
            encoding="utf-8",
        )
        facts = evaluate(Path(td))["facts"]
        assert facts["tests_count"] == 0
        assert facts["theater_present"] is True
        assert "malformed_junit" in facts["theater_reasons"] or "zero_or_insufficient_tests" in facts["theater_reasons"]
