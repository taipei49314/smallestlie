"""Report vs exit-code consistency oracle."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from smallestlie.models import TargetVerdict


def evaluate(workspace: Path, verdict: TargetVerdict) -> dict[str, Any]:
    exit_accepted = verdict.exit_code == 0
    report_accepted = bool(verdict.raw.get("accepted")) if verdict.raw else exit_accepted
    if verdict.report_path is None:
        # No report channel — consistency N/A, treat as consistent single channel.
        consistent = True
    else:
        # Also consider raw_status tokens.
        status = str(verdict.raw_status).upper()
        status_accept = status in {"VERIFIED", "PASS", "OK", "ACCEPTED"}
        report_accepted = bool(verdict.raw.get("accepted", status_accept))
        consistent = exit_accepted == report_accepted

    return {
        "facts": {
            "exit_code": verdict.exit_code,
            "exit_accepted": exit_accepted,
            "report_accepted": report_accepted,
            "raw_status": verdict.raw_status,
            "consistent": consistent,
            "report_path_exists": (workspace / "outputs" / "report.json").is_file(),
        }
    }
