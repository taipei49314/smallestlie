"""Fresh execution reports cannot be confused with cached fixture output."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from smallestlie.adapters.fixture_gate import FixtureGateAdapter
from smallestlie.models import ComparisonResult, OracleResult
from smallestlie.policy.command_allowlist import CommandSpec
from smallestlie.policy.path_guard import PathGuardError
from smallestlie.sandbox.executor import ExecutionResult, SandboxExecutor
from smallestlie.sandbox.workspace import DisposableWorkspace
from smallestlie.verdict.compare import compare


def _result(spec: CommandSpec, exit_code: int) -> ExecutionResult:
    return ExecutionResult(spec.command_id, list(spec.argv), ".", exit_code, "", "")


def _report(env: dict[str, str], accepted: bool) -> dict:
    return {"accepted": accepted, "status": "VERIFIED" if accepted else "REJECTED",
            "execution_binding": {"run_id": env["SMALLESTLIE_RUN_ID"],
                                  "input_sha256": env["SMALLESTLIE_INPUT_SHA256"]}}


def _write(workspace: Path, report: dict) -> None:
    out = workspace / "outputs"
    out.mkdir(exist_ok=True)
    (out / "report.json").write_text(json.dumps(report), encoding="utf-8")


@pytest.mark.parametrize("exit_code,accepted", [(0, True), (1, False), (0, False), (1, True)])
def test_fresh_bound_report_keeps_both_verdict_channels(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, exit_code: int, accepted: bool,
) -> None:
    (tmp_path / "input.txt").write_text("current inputs", encoding="utf-8")

    def fresh(self: SandboxExecutor, spec: CommandSpec, *, extra_env: dict[str, str]) -> ExecutionResult:
        _write(self.guard.root, _report(extra_env, accepted))
        return _result(spec, exit_code)

    monkeypatch.setattr(SandboxExecutor, "run", fresh)
    adapter = FixtureGateAdapter()
    execution = adapter.execute(tmp_path, SandboxExecutor(tmp_path), adapter.command_allowlist().resolve("run_target_verifier"))
    verdict = adapter.read_verdict(tmp_path, execution)
    assert verdict.execution_error is None
    assert verdict.accepted is accepted
    assert verdict.channels["exit_accepted"] is (exit_code == 0)
    assert execution.to_dict()["execution_binding"] == verdict.channels["execution_binding"]


def test_old_report_and_trace_are_cleared_only_in_disposable_copy(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    _write(source, {"accepted": True, "execution_binding": {"run_id": "old", "input_sha256": "old"}})
    (source / "outputs" / "execution_trace.json").write_text("old trace", encoding="utf-8")
    (source / "outputs" / "keep.txt").write_text("unrelated artifact", encoding="utf-8")
    (source / "input.txt").write_text("inputs", encoding="utf-8")
    original = (source / "outputs" / "report.json").read_bytes()
    ws = DisposableWorkspace.create(source, parent_dir=tmp_path / "copies")

    def no_output(self: SandboxExecutor, spec: CommandSpec, **kwargs: object) -> ExecutionResult:
        assert not (self.guard.root / "outputs" / "report.json").exists()
        assert not (self.guard.root / "outputs" / "execution_trace.json").exists()
        assert (self.guard.root / "outputs" / "keep.txt").read_text() == "unrelated artifact"
        return _result(spec, 0)

    monkeypatch.setattr(SandboxExecutor, "run", no_output)
    try:
        adapter = FixtureGateAdapter()
        execution = adapter.execute(ws.workspace_path, SandboxExecutor(ws.workspace_path),
                                    adapter.command_allowlist().resolve("run_target_verifier"))
        verdict = adapter.read_verdict(ws.workspace_path, execution)
        assert verdict.execution_error == "missing_report"
        assert (source / "outputs" / "report.json").read_bytes() == original
        assert (source / "outputs" / "execution_trace.json").read_text() == "old trace"
    finally:
        ws.cleanup()


@pytest.mark.parametrize("exit_code", [0, 1])
def test_copying_a_valid_prior_report_cannot_complete_a_new_execution(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, exit_code: int,
) -> None:
    saved: dict = {}

    def first(self: SandboxExecutor, spec: CommandSpec, *, extra_env: dict[str, str]) -> ExecutionResult:
        saved.update(_report(extra_env, True))
        _write(self.guard.root, saved)
        return _result(spec, 0)

    monkeypatch.setattr(SandboxExecutor, "run", first)
    adapter = FixtureGateAdapter()
    spec = adapter.command_allowlist().resolve("run_target_verifier")
    old = adapter.execute(tmp_path, SandboxExecutor(tmp_path), spec)
    assert adapter.read_verdict(tmp_path, old).execution_error is None

    def cached(self: SandboxExecutor, spec: CommandSpec, **kwargs: object) -> ExecutionResult:
        _write(self.guard.root, saved)
        return _result(spec, exit_code)

    monkeypatch.setattr(SandboxExecutor, "run", cached)
    current = adapter.execute(tmp_path, SandboxExecutor(tmp_path), spec)
    assert current.execution_binding["run_id"] != old.execution_binding["run_id"]
    assert current.execution_binding["input_sha256"] == old.execution_binding["input_sha256"]
    verdict = adapter.read_verdict(tmp_path, current)
    assert verdict.execution_error == "report_execution_binding_mismatch"
    assert compare(OracleResult(valid=False), verdict).result == ComparisonResult.INCONCLUSIVE


@pytest.mark.parametrize("fault", ["missing", "nonce", "digest", "input_rewrite"])
def test_bound_output_failure_is_unknown(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fault: str,
) -> None:
    inputs = tmp_path / "input.txt"
    inputs.write_text("before", encoding="utf-8")

    def corrupted(self: SandboxExecutor, spec: CommandSpec, *, extra_env: dict[str, str]) -> ExecutionResult:
        report = _report(extra_env, False)
        if fault == "missing":
            del report["execution_binding"]
        elif fault == "nonce":
            report["execution_binding"]["run_id"] = "different-run"
        elif fault == "digest":
            report["execution_binding"]["input_sha256"] = "0" * 64
        else:
            inputs.write_text("after", encoding="utf-8")
        _write(self.guard.root, report)
        return _result(spec, 1)

    monkeypatch.setattr(SandboxExecutor, "run", corrupted)
    adapter = FixtureGateAdapter()
    execution = adapter.execute(tmp_path, SandboxExecutor(tmp_path), adapter.command_allowlist().resolve("run_target_verifier"))
    verdict = adapter.read_verdict(tmp_path, execution)
    assert verdict.execution_error == (
        "input_changed_during_execution" if fault == "input_rewrite" else "report_execution_binding_mismatch"
    )
    assert compare(OracleResult(valid=False), verdict).target_accepted is None


def test_unbound_direct_execution_cannot_adjudicate(tmp_path: Path) -> None:
    _write(tmp_path, {"accepted": True, "execution_binding": {"run_id": "untrusted", "input_sha256": "0" * 64}})
    adapter = FixtureGateAdapter()
    execution = _result(adapter.command_allowlist().resolve("run_target_verifier"), 0)
    assert adapter.read_verdict(tmp_path, execution).execution_error == "missing_execution_binding"


def test_output_directory_cannot_alias_a_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    output = tmp_path / "outputs"
    output.write_text("source file", encoding="utf-8")

    def must_not_run(*args: object, **kwargs: object) -> None:
        pytest.fail("unsafe output path reached execution")

    monkeypatch.setattr(SandboxExecutor, "run", must_not_run)
    adapter = FixtureGateAdapter()
    with pytest.raises(PathGuardError):
        adapter.execute(tmp_path, SandboxExecutor(tmp_path), adapter.command_allowlist().resolve("run_target_verifier"))
    assert output.read_text() == "source file"


def test_wrong_executor_root_cannot_clear_output(tmp_path: Path) -> None:
    other = tmp_path / "other"
    other.mkdir()
    _write(tmp_path, {"accepted": True})
    adapter = FixtureGateAdapter()
    with pytest.raises(PathGuardError):
        adapter.execute(tmp_path, SandboxExecutor(other), adapter.command_allowlist().resolve("run_target_verifier"))
    assert (tmp_path / "outputs" / "report.json").is_file()
