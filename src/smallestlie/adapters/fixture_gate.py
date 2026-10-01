"""Adapter for synthetic naive_gate / honest_gate fixtures."""

from __future__ import annotations

import json
from pathlib import Path

from smallestlie.adapters.base import Adapter
from smallestlie.models import TargetVerdict
from smallestlie.policy.command_allowlist import CommandAllowlist
from smallestlie.sandbox.executor import ExecutionResult


class FixtureGateAdapter(Adapter):
    name = "fixture_gate"
    version = "0.1.0"

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

    def parse_verdict(self, workspace: Path, execution: ExecutionResult) -> TargetVerdict:
        report_path = workspace / "outputs" / "report.json"
        report: dict = {}
        error = "missing_report"
        if report_path.is_file():
            try:
                loaded = json.loads(report_path.read_text(encoding="utf-8"))
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
            except json.JSONDecodeError:
                error = "invalid_report_json"
            except (OSError, UnicodeDecodeError):
                error = "unreadable_report"

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
