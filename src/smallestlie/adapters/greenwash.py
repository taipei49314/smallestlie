"""Adapter for synthetic Greenwash SUT (audit package mode)."""

from __future__ import annotations

import json
from pathlib import Path

from smallestlie.adapters.base import Adapter
from smallestlie.models import TargetVerdict
from smallestlie.policy.command_allowlist import CommandAllowlist
from smallestlie.sandbox.executor import ExecutionResult


class GreenwashAdapter(Adapter):
    name = "greenwash"
    version = "0.1.0"

    def command_allowlist(self) -> CommandAllowlist:
        return CommandAllowlist.from_mapping(
            {
                "run_target_verifier": {
                    "argv": [
                        "${PYTHON}",
                        "-m",
                        "greenwash",
                        "audit",
                        "--package",
                        "package",
                        "--json",
                    ],
                    "cwd": ".",
                    "timeout_seconds": 60,
                },
                "run_greenwash_audit": {
                    "argv": [
                        "${PYTHON}",
                        "-m",
                        "greenwash",
                        "audit",
                        "--package",
                        "package",
                        "--json",
                    ],
                    "cwd": ".",
                    "timeout_seconds": 60,
                },
            }
        )

    def capabilities(self) -> list[str]:
        return [
            "target_verdict",
            "ci_summary",
            "test_reports",
            "coverage_reports",
            "policy_file",
            "report_json",
            "offline_audit",
            "theater_classification",
        ]

    def preflight(self, workspace: Path) -> dict:
        ok = (workspace / "greenwash").is_dir() and (workspace / "package").is_dir()
        return {
            "ok": ok,
            "greenwash_module": (workspace / "greenwash").is_dir(),
            "package": (workspace / "package").is_dir(),
        }

    def parse_verdict(self, workspace: Path, execution: ExecutionResult) -> TargetVerdict:
        report: dict = {}
        # Prefer stdout JSON
        stdout = (execution.stdout or "").strip()
        if stdout:
            try:
                report = json.loads(stdout.splitlines()[-1])
            except json.JSONDecodeError:
                report = {}
        if not report:
            for rel in ("outputs/audit-report.json", "package/audit-report.json"):
                p = workspace / rel
                if p.is_file():
                    try:
                        report = json.loads(p.read_text(encoding="utf-8"))
                        break
                    except json.JSONDecodeError:
                        continue

        classification = str(report.get("classification") or report.get("status") or "UNKNOWN")
        # Greenwash "accepted" means it accepts the claim "not greenwashed" / clean
        report_accepted = bool(
            report.get("accepted", classification.lower() in {"clean", "pass", "ok"})
        )
        exit_ok = execution.exit_code == 0
        channels = {
            "exit_code": execution.exit_code,
            "exit_accepted": exit_ok,
            "report_classification": classification,
            "report_accepted": report_accepted,
            "theater_reasons": report.get("theater_reasons") or [],
            "stdout_tail": (execution.stdout or "")[-500:],
            "stderr_tail": (execution.stderr or "")[-500:],
        }
        raw_status = str(report.get("status") or classification).upper()
        return TargetVerdict(
            accepted=report_accepted,
            raw_status=raw_status,
            exit_code=execution.exit_code,
            report_path="outputs/audit-report.json"
            if (workspace / "outputs" / "audit-report.json").is_file()
            else None,
            evidence_refs=["package/"],
            warnings=[str(x) for x in (report.get("theater_reasons") or [])],
            raw=report if isinstance(report, dict) else {},
            channels=channels,
        )
