"""Evidence ↔ revision binding oracle."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def evaluate(workspace: Path, *, baseline: dict[str, Any]) -> dict[str, Any]:
    rev_file = workspace / "REVISION"
    if not rev_file.is_file():
        rev_file = workspace / "revision.txt"
    current_revision = rev_file.read_text(encoding="utf-8").strip() if rev_file.is_file() else None
    baseline_revision = baseline.get("revision")

    evidence_path = workspace / "evidence" / "evidence.json"
    evidence_revision = None
    evidence_present = evidence_path.is_file()
    if evidence_present:
        try:
            data = json.loads(evidence_path.read_text(encoding="utf-8"))
            evidence_revision = data.get("target_revision") or data.get("revision")
        except json.JSONDecodeError:
            evidence_revision = None

    matches = (
        evidence_present
        and evidence_revision is not None
        and current_revision is not None
        and str(evidence_revision) == str(current_revision)
    )

    return {
        "facts": {
            "current_revision": current_revision,
            "baseline_revision": baseline_revision,
            "evidence_present": evidence_present,
            "evidence_revision": evidence_revision,
            "evidence_matches_revision": bool(matches),
        }
    }
