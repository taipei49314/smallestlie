"""Adapter for synthetic naive_gate / honest_gate fixtures."""

from __future__ import annotations

import uuid
from pathlib import Path
from typing import Any

from smallestlie.adapters.base import Adapter
from smallestlie.models import TargetVerdict
from smallestlie.policy.command_allowlist import CommandAllowlist, CommandSpec
from smallestlie.policy.path_guard import PathGuardError
from smallestlie.sandbox.executor import ExecutionResult, SandboxExecutor
from smallestlie.sandbox.fixture_binding import input_sha256, report_paths
from smallestlie.verdict.json_input import read_json


class FixtureGateAdapter(Adapter):
    name = "fixture_gate"
    version = "0.2.0"

    def command_allowlist(self) -> CommandAllowlist:
        return CommandAllowlist.from_mapping(
            {
                "run_target_verifier": {
                    "argv": ["${PYTHON}", "-m", "fixture_gate", "verify"],
                    "cwd": ".",
                    "timeout_seconds": 60,
                },
                "run_control_verify": {
                    "argv": ["${PYTHON}", "-m", "fixture_gate", "verify"],
                    "cwd": ".",
                    "timeout_seconds": 60,
                },
            }
        )

    def capabilities(self) -> list[str]:
        return [
            "test_discovery",
            "target_verdict",
            "evidence_files",
            "policy_file",
            "protected_paths",
            "revision_file",
        ]

    def execute(
        self,
        workspace: Path,
        executor: SandboxExecutor,
        spec: CommandSpec,
        *,
        extra_env: dict[str, str] | None = None,
    ) -> ExecutionResult:
        if workspace.resolve() != executor.guard.root:
            raise PathGuardError("fixture workspace and executor root differ")
        binding: dict[str, Any] = {"run_id": uuid.uuid4().hex, "input_sha256": input_sha256(workspace)}
        # Validate both paths before deleting either. Only disposable generated
        # output is cleared; source inputs and unrelated artifacts are retained.
        paths = report_paths(workspace)
        for path in paths:
            path.unlink(missing_ok=True)
        env = dict(extra_env or {})
        env.update({"SMALLESTLIE_RUN_ID": binding["run_id"],
                    "SMALLESTLIE_INPUT_SHA256": binding["input_sha256"]})
        execution = executor.run(spec, extra_env=env)
        try:
            binding["input_sha256_after"] = input_sha256(workspace)
        except (OSError, PathGuardError) as exc:
            binding["input_error"] = str(exc)
        execution.execution_binding = binding
        return execution

    def parse_verdict(self, workspace: Path, execution: ExecutionResult) -> TargetVerdict:
        report_path = workspace / "outputs" / "report.json"
        report: dict = {}
        error = "missing_report"
        try:
            report_paths(workspace)
        except (OSError, PathGuardError):
            error = "unsafe_report_path"
        if error != "unsafe_report_path" and report_path.is_file():
            try:
                loaded = read_json(report_path.read_text(encoding="utf-8"))
                if not isinstance(loaded, dict):
                    error = "invalid_report_type"
                else:
                    report = loaded
                    status = report.get("status")
                    if "accepted" in report:
                        error = None if isinstance(report["accepted"], bool) else "invalid_report_verdict"
                    elif isinstance(status, str) and status in {
                        "VERIFIED", "PASS", "OK", "REJECTED", "FAIL", "BLOCKED"
                    }:
                        error = None
                    else:
                        error = "invalid_report_verdict"
            except (OSError, UnicodeDecodeError):
                error = "unreadable_report"
            except ValueError:
                error = "invalid_report_json"

        if error is None:
            expected = execution.execution_binding
            observed = report.get("execution_binding")
            if (not isinstance(expected.get("run_id"), str) or not expected["run_id"]
                    or not isinstance(expected.get("input_sha256"), str)
                    or not expected["input_sha256"]):
                error = "missing_execution_binding"
            elif expected.get("input_error") or expected.get("input_sha256_after") != expected["input_sha256"]:
                error = "input_changed_during_execution"
            elif (not isinstance(observed, dict)
                    or any(observed.get(key) != expected[key] for key in ("run_id", "input_sha256"))):
                error = "report_execution_binding_mismatch"

        raw_status = str(report.get("status", "UNKNOWN"))
        report_accepted = (
            bool(report.get("accepted", raw_status in {"VERIFIED", "PASS", "OK"}))
            if error is None else False
        )
        exit_ok = execution.exit_code == 0

        # Preserve channel disagreement; do not collapse prematurely.
        channels = {
            "exit_code": execution.exit_code,
            "exit_accepted": exit_ok,
            "report_status": raw_status,
            "report_accepted": report_accepted,
            "execution_binding": execution.execution_binding,
            "report_execution_binding": report.get("execution_binding"),
            "stdout_tail": (execution.stdout or "")[-500:],
            "stderr_tail": (execution.stderr or "")[-500:],
        }

        # A fixture verifier must emit a usable report. Exit 1 without one may
        # be a Python crash; exit 0 alone does not establish an accepting claim.
        # A valid report still leads the target verdict, preserving report/exit
        # disagreement for the independent oracle.
        accepted = report_accepted
        if error is not None:
            raw_status = "INVALID_REPORT" if report_path.is_file() else "MISSING_REPORT"

        evidence_refs = []
        if isinstance(report.get("evidence_refs"), list):
            evidence_refs = [str(x) for x in report["evidence_refs"]]
        elif (workspace / "evidence" / "evidence.json").is_file():
            evidence_refs = ["evidence/evidence.json"]

        warnings = []
        if isinstance(report.get("warnings"), list):
            warnings = [str(w) for w in report["warnings"]]

        return TargetVerdict(
            accepted=accepted,
            raw_status=raw_status,
            exit_code=execution.exit_code,
            report_path="outputs/report.json" if report_path.is_file() else None,
            evidence_refs=evidence_refs,
            warnings=warnings,
            raw=report,
            channels=channels,
            execution_error=error,
        )
