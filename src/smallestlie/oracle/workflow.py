"""Workflow / matrix completeness oracle."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml


def evaluate(workspace: Path) -> dict[str, Any]:
    matrix = {}
    mpath = workspace / "config" / "matrix.yaml"
    if mpath.is_file():
        raw = yaml.safe_load(mpath.read_text(encoding="utf-8")) or {}
        if isinstance(raw, dict):
            matrix = raw
    required = list(matrix.get("required_jobs") or [])

    workflow = {}
    wpath = workspace / "config" / "workflow.yaml"
    if wpath.is_file():
        raw = yaml.safe_load(wpath.read_text(encoding="utf-8")) or {}
        if isinstance(raw, dict):
            workflow = raw

    jobs = workflow.get("jobs") if isinstance(workflow.get("jobs"), dict) else {}
    executed: list[str] = []
    skipped: list[str] = []
    for name, body in jobs.items():
        if not isinstance(body, dict):
            continue
        if body.get("if") is False or str(body.get("if", "")).strip().lower() in {
            "false",
            "0",
            "skip",
        }:
            skipped.append(name)
            continue
        if body.get("skip") is True:
            skipped.append(name)
            continue
        executed.append(name)

    gate_skipped = "gate" in skipped or workflow.get("run_gate") is False
    missing = [j for j in required if j not in executed]
    complete = len(required) > 0 and not missing and not gate_skipped

    return {
        "facts": {
            "required_jobs": required,
            "executed_jobs": executed,
            "skipped_jobs": skipped,
            "missing_jobs": missing,
            "gate_skipped": gate_skipped,
            "required_jobs_complete": complete,
        }
    }
