"""Execution failures remain unknown through campaigns, replay and CI gates."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Callable

import pytest

from smallestlie.adapters.fixture_gate import FixtureGateAdapter
from smallestlie.attacks.schema import load_attack_spec
from smallestlie.baseline.capture import capture_baseline
from smallestlie.campaign import runner
from smallestlie.campaign.batch import _expectation_met as batch_expectation_met
from smallestlie.ci.gate import _aggregate_profiles
from smallestlie.ci.gate import _expectation_met as ci_expectation_met
from smallestlie.ci.status import CiProjection
from smallestlie.models import ComparisonResult
from smallestlie.policy.authorization import default_fixture_authorization
from smallestlie.policy.command_allowlist import CommandSpec
from smallestlie.sandbox.executor import ExecutionResult, SandboxExecutor


ROOT = Path(__file__).resolve().parents[2]


def fake_execution(
    monkeypatch: pytest.MonkeyPatch,
    *,
    exit_code: int,
    timed_out: bool,
    report: str | None,
) -> None:
    def stopped(self: SandboxExecutor, spec: CommandSpec, **kwargs: object) -> ExecutionResult:
        workspace = self.guard.root
        if report is not None:
            output = workspace / "outputs"
            output.mkdir(exist_ok=True)
            (output / "report.json").write_text(report, encoding="utf-8")
        return ExecutionResult(
            command_id=spec.command_id,
            argv=list(spec.argv),
            cwd=str(workspace),
            exit_code=exit_code,
            stdout="partial verifier output",
            stderr="timeout" if timed_out else "",
            timed_out=timed_out,
        )

    def must_not_evaluate(*args: object, **kwargs: object) -> None:
        pytest.fail("incomplete execution reached the truth oracle")

    monkeypatch.setattr(SandboxExecutor, "run", stopped)
    monkeypatch.setattr(runner, "evaluate_oracle", must_not_evaluate)


@pytest.mark.integration
@pytest.mark.parametrize(
    "exit_code,timed_out,report",
    [
        (124, True, '{"accepted": true, "status": "VERIFIED"}'),
        (2, False, '{"accepted": false, "status": "REJECTED"}'),
        (1, False, None),
        (0, False, "[]"),
        (0, False, '{"accepted": true, "execution_binding": {"run_id": "prior", "input_sha256": "prior"}}'),
        (1, False, '{"accepted": false, "execution_binding": {"run_id": "prior", "input_sha256": "prior"}}'),
    ],
)
def test_campaign_cannot_turn_incomplete_execution_into_success(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    exit_code: int,
    timed_out: bool,
    report: str | None,
) -> None:
    fake_execution(monkeypatch, exit_code=exit_code, timed_out=timed_out, report=report)
    catalog = tmp_path / "one-attack.yaml"
    catalog.write_text("name: execution-failure\nattacks:\n  - EVD-001\n", encoding="utf-8")
    summary = runner.run_campaign(
        target=ROOT / "fixtures" / "naive_gate",
        catalog_path=catalog,
        output_root=tmp_path / "campaigns",
        project_root=ROOT,
    )
    assert summary["false_accept_count"] == 0
    assert summary["inconclusive_count"] == 1
    assert summary["exit_code"] == 3
    assert summary["ledger_ok"] is True
    assert summary["source_immutable"] is True
    result = summary["runs"][0]
    assert result["comparison"]["result"] == ComparisonResult.INCONCLUSIVE.value
    assert result["comparison"]["target_accepted"] is None
    assert result["target_verdict"]["execution_error"]
    assert "witness_id" not in result
    assert "regression" not in result
    stored = json.loads(
        (Path(summary["campaign_dir"]) / "runs" / result["run_id"] / "target-verdict.json")
        .read_text(encoding="utf-8")
    )
    assert stored["execution_error"] == result["target_verdict"]["execution_error"]
    assert result["execution"]["execution_binding"]["run_id"]
    assert batch_expectation_met("pass_no_false_accept", summary) is False
    assert ci_expectation_met("pass_no_false_accept", summary) is False
    aggregate = _aggregate_profiles(
        [{
            "name": "incomplete_honest",
            "ran": True,
            "expect": "pass_no_false_accept",
            "expectation_met": False,
            "projection": CiProjection.PASS_WITH_WARNINGS.value,
        }],
        any_ran=True,
        budget_exceeded=False,
    )
    assert aggregate["projection"] == CiProjection.HARNESS_ERROR.value
    assert aggregate["gha_conclusion"] == "failure"
    assert aggregate["exit_code"] == 5


@pytest.mark.integration
@pytest.mark.parametrize("exit_code,timed_out,report,error", [
    (124, True, '{"accepted": true, "status": "VERIFIED"}', "timed_out"),
    (0, False, '{"accepted": true, "execution_binding": {"run_id": "prior", "input_sha256": "prior"}}', "report_execution_binding_mismatch"),
    (1, False, '{"accepted": true, "execution_binding": {"run_id": "prior", "input_sha256": "prior"}}', "report_execution_binding_mismatch"),
])
def test_incomplete_report_cannot_reproduce_a_false_accept_witness(
    monkeypatch: pytest.MonkeyPatch, exit_code: int, timed_out: bool, report: str, error: str,
) -> None:
    fake_execution(
        monkeypatch,
        exit_code=exit_code,
        timed_out=timed_out,
        report=report,
    )
    target = ROOT / "fixtures" / "naive_gate"
    adapter = FixtureGateAdapter()
    authorization = default_fixture_authorization(target)
    baseline = capture_baseline(
        target,
        adapter_name=adapter.name,
        adapter_version=adapter.version,
        authorization_digest=authorization.digest(),
    )
    attack = load_attack_spec(ROOT / "attacks" / "evidence" / "EVD-001.yaml")
    result = runner._run_mutant_once(
        mutations=attack.mutations,
        attack=attack,
        target_path=target,
        baseline=baseline,
        adapter=adapter,
        allowlist=adapter.command_allowlist(),
    )
    assert result["comparison"]["result"] == ComparisonResult.INCONCLUSIVE.value
    assert result["execution_error"] == error
    assert result["target_accepted"] is None
    replay = runner._replay_false_accept(
        attack=attack,
        target_path=target,
        baseline=baseline,
        adapter=adapter,
        allowlist=adapter.command_allowlist(),
        attempts=1,
    )
    assert replay["stable"] is False
    assert replay["reproduced"] == 0
    assert replay["details"][0]["target_accepted"] is None
    assert replay["details"][0]["execution_error"] == error


@pytest.mark.parametrize("expectation", [batch_expectation_met, ci_expectation_met])
def test_complete_clean_campaign_still_meets_confidence_gate(
    expectation: Callable[[str, dict[str, Any]], bool],
) -> None:
    summary = {
        "status": "PASS_NO_FALSE_ACCEPT_OBSERVED",
        "exit_code": 0,
        "false_accept_count": 0,
        "ledger_ok": True,
        "source_immutable": True,
    }
    assert expectation("pass_no_false_accept", summary) is True


def test_blocked_required_profile_keeps_blocked_ci_status() -> None:
    aggregate = _aggregate_profiles(
        [{
            "name": "blocked_honest",
            "ran": True,
            "expect": "pass_no_false_accept",
            "expectation_met": False,
            "projection": CiProjection.BLOCKED.value,
        }],
        any_ran=True,
        budget_exceeded=False,
    )
    assert aggregate["projection"] == CiProjection.BLOCKED.value
    assert aggregate["gha_conclusion"] == "failure"
    assert aggregate["exit_code"] == 4
