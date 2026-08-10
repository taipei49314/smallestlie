"""Report vs exit-code consistency oracle."""

from __future__ import annotations

import json
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

    forced = False
    evidence_path = workspace / "evidence" / "evidence.json"
    if evidence_path.is_file():
        try:
            data = json.loads(evidence_path.read_text(encoding="utf-8"))
            forced = bool(data.get("force_channel_disagree"))
        except json.JSONDecodeError:
            forced = False
    if (workspace / "outputs" / ".force_channel_disagree").is_file():
        forced = True

    # Valid only when channels agree and no adversarial disagreement marker remains.
    channels_sound = consistent and not forced

    return {
        "facts": {
            "exit_code": verdict.exit_code,
            "exit_accepted": exit_accepted,
            "report_accepted": report_accepted,
            "raw_status": verdict.raw_status,
            "consistent": consistent,
            "force_channel_disagree": forced,
            "channels_sound": channels_sound,
            "report_path_exists": (workspace / "outputs" / "report.json").is_file(),
        }
    }
