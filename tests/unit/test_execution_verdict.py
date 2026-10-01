"""Incomplete executions cannot supply a defense or a false-accept witness."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from smallestlie.adapters.fixture_gate import FixtureGateAdapter
from smallestlie.models import ComparisonResult, OracleResult, TargetVerdict
from smallestlie.sandbox.executor import ExecutionResult
from smallestlie.verdict.compare import compare


def execution(exit_code: int = 0, *, timed_out: bool = False) -> ExecutionResult:
    return ExecutionResult(
        command_id="run_target_verifier",
        argv=["python", "-m", "fixture_gate", "verify"],
        cwd=".",
        exit_code=exit_code,
        stdout="partial output",
        stderr="",
        timed_out=timed_out,
    )


@pytest.mark.parametrize("exit_code,timed_out", [(0, True), (1, True), (124, True), (2, False), (-9, False)])
def test_incomplete_execution_never_reads_target_report(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    exit_code: int,
    timed_out: bool,
) -> None:
    adapter = FixtureGateAdapter()

    def must_not_parse(*args: object, **kwargs: object) -> TargetVerdict:
        pytest.fail("partial target output was parsed")

    monkeypatch.setattr(adapter, "parse_verdict", must_not_parse)
    verdict = adapter.read_verdict(tmp_path, execution(exit_code, timed_out=timed_out))
    assert verdict.execution_error is not None
    assert verdict.to_dict()["execution_error"] == verdict.execution_error
    assert verdict.channels["exit_code"] == exit_code
    assert compare(OracleResult(valid=False), verdict).result == ComparisonResult.INCONCLUSIVE


@pytest.mark.parametrize("valid", [True, False, None])
@pytest.mark.parametrize("accepted", [True, False])
def test_execution_error_cannot_be_a_truth_table_outcome(valid: bool | None, accepted: bool) -> None:
    verdict = TargetVerdict(
        accepted=accepted,
        raw_status="PASS" if accepted else "REJECTED",
        exit_code=124,
        execution_error="timed_out",
    )
    result = compare(OracleResult(valid=valid), verdict)
    assert result.result == ComparisonResult.INCONCLUSIVE
    assert result.target_accepted is None
    assert "timed_out" in result.rationale


@pytest.mark.parametrize("exit_code", [0, 1])
@pytest.mark.parametrize("accepted", [True, False])
def test_completed_report_keeps_channel_disagreement(
    tmp_path: Path, exit_code: int, accepted: bool
) -> None:
    output = tmp_path / "outputs"
    output.mkdir()
    (output / "report.json").write_text(
        json.dumps({"status": "VERIFIED" if accepted else "REJECTED", "accepted": accepted}),
        encoding="utf-8",
    )
    verdict = FixtureGateAdapter().read_verdict(tmp_path, execution(exit_code))
    assert verdict.execution_error is None
    assert verdict.accepted is accepted
    assert verdict.channels["exit_accepted"] is (exit_code == 0)
    assert verdict.channels["report_accepted"] is accepted
    assert compare(OracleResult(valid=False), verdict).result == (
        ComparisonResult.FALSE_ACCEPT_OBSERVED if accepted else ComparisonResult.ATTACK_REJECTED
    )


@pytest.mark.parametrize("exit_code", [0, 1])
def test_missing_report_is_not_an_exit_only_verdict(tmp_path: Path, exit_code: int) -> None:
    verdict = FixtureGateAdapter().read_verdict(tmp_path, execution(exit_code))
    assert verdict.execution_error == "missing_report"
    assert compare(OracleResult(valid=False), verdict).result == ComparisonResult.INCONCLUSIVE


@pytest.mark.parametrize(
    "report,error",
    [
        ("{", "invalid_report_json"),
        ("[]", "invalid_report_type"),
        ("null", "invalid_report_type"),
        ("true", "invalid_report_type"),
        ("{}", "invalid_report_verdict"),
        ('{"status": []}', "invalid_report_verdict"),
        ('{"accepted": "false"}', "invalid_report_verdict"),
        ('{"accepted": null}', "invalid_report_verdict"),
        ('{"status": "UNKNOWN"}', "invalid_report_verdict"),
    ],
)
def test_invalid_report_cannot_be_a_rejection(tmp_path: Path, report: str, error: str) -> None:
    output = tmp_path / "outputs"
    output.mkdir()
    (output / "report.json").write_text(report, encoding="utf-8")
    verdict = FixtureGateAdapter().read_verdict(tmp_path, execution(1))
    assert verdict.execution_error == error
    assert compare(OracleResult(valid=False), verdict).result == ComparisonResult.INCONCLUSIVE


def test_unreadable_report_cannot_be_a_rejection(tmp_path: Path) -> None:
    output = tmp_path / "outputs"
    output.mkdir()
    (output / "report.json").write_bytes(b"\xff")
    verdict = FixtureGateAdapter().read_verdict(tmp_path, execution(1))
    assert verdict.execution_error == "unreadable_report"
    assert compare(OracleResult(valid=False), verdict).result == ComparisonResult.INCONCLUSIVE


@pytest.mark.parametrize("status,accepted", [("VERIFIED", True), ("REJECTED", False)])
def test_known_status_only_report_remains_supported(tmp_path: Path, status: str, accepted: bool) -> None:
    output = tmp_path / "outputs"
    output.mkdir()
    (output / "report.json").write_text(json.dumps({"status": status}), encoding="utf-8")
    verdict = FixtureGateAdapter().read_verdict(tmp_path, execution(0 if accepted else 1))
    assert verdict.execution_error is None
    assert verdict.accepted is accepted
