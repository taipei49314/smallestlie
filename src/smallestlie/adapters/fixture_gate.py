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
        if report_path.is_file():
            try:
                report = json.loads(report_path.read_text(encoding="utf-8"))
            except json.JSONDecodeError:
                report = {"status": "INVALID_REPORT", "accepted": False}

        raw_status = str(report.get("status", "UNKNOWN"))
        report_accepted = bool(report.get("accepted", raw_status in {"VERIFIED", "PASS", "OK"}))
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

        # Target's own aggregator (what the gate claims) lives in report if present,
        # otherwise exit code. This is the *target* verdict, not oracle truth.
        if report_path.is_file():
            accepted = report_accepted
        else:
            accepted = exit_ok
            raw_status = "EXIT_ONLY"

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
        )
