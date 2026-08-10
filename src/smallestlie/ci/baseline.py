"""Baseline comparison between campaign summaries."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def load_summary(path: str | Path) -> dict[str, Any]:
    p = Path(path)
    if p.is_dir():
        p = p / "campaign-report.json"
        if not p.is_file():
            p = Path(path) / "ci-summary.json"
    data = json.loads(p.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"summary must be object: {p}")
    return data


def compare_to_baseline(
    current: dict[str, Any],
    baseline: dict[str, Any],
) -> dict[str, Any]:
    """
    Compare current campaign/ci summary to a stored baseline.

    Detects:
    - new false accepts
    - resolved false accepts
    - status regression/improvement
    - coverage shrink (fewer runs without disclosure)
    """
    cur_fa = _false_accept_ids(current)
    base_fa = _false_accept_ids(baseline)
    new_fa = sorted(cur_fa - base_fa)
    resolved_fa = sorted(base_fa - cur_fa)

    cur_status = _status(current)
    base_status = _status(baseline)

    cur_runs = _run_count(current)
    base_runs = _run_count(baseline)

    regressions: list[str] = []
    improvements: list[str] = []
    if new_fa:
        regressions.append(f"new_false_accepts:{','.join(new_fa)}")
    if resolved_fa:
        improvements.append(f"resolved_false_accepts:{','.join(resolved_fa)}")
    if base_status == "PASS_NO_FALSE_ACCEPT_OBSERVED" and cur_status == "FAIL_FALSE_ACCEPT_OBSERVED":
        regressions.append("status_regressed_to_false_accept")
    if base_status == "FAIL_FALSE_ACCEPT_OBSERVED" and cur_status == "PASS_NO_FALSE_ACCEPT_OBSERVED":
        improvements.append("status_improved_no_false_accept")
    if base_runs is not None and cur_runs is not None and cur_runs < base_runs:
        regressions.append(f"run_count_shrunk:{base_runs}->{cur_runs}")

    return {
        "schema_version": "smallestlie.baseline_compare/v1",
        "baseline_status": base_status,
        "current_status": cur_status,
        "baseline_false_accepts": sorted(base_fa),
        "current_false_accepts": sorted(cur_fa),
        "new_false_accepts": new_fa,
        "resolved_false_accepts": resolved_fa,
        "baseline_run_count": base_runs,
        "current_run_count": cur_runs,
        "regressions": regressions,
        "improvements": improvements,
        "ok": len(new_fa) == 0 and "status_regressed_to_false_accept" not in regressions,
    }


def _status(summary: dict[str, Any]) -> str:
    return str(
        summary.get("status")
        or summary.get("projection")
        or (summary.get("ci") or {}).get("projection")
        or "UNKNOWN"
    )


def _false_accept_ids(summary: dict[str, Any]) -> set[str]:
    ids: set[str] = set()
    runs = summary.get("runs") or (summary.get("campaigns") or {})
    if isinstance(runs, dict):
        # ci-summary nested
        for camp in runs.values() if runs else []:
            if isinstance(camp, dict):
                ids |= _false_accept_ids(camp)
        # also profiles
        for camp in (summary.get("profiles") or []):
            if isinstance(camp, dict):
                ids |= _ids_from_runs(camp.get("runs") or [])
                if camp.get("false_accept_attack_ids"):
                    ids |= set(camp["false_accept_attack_ids"])
        return ids
    if isinstance(runs, list):
        return _ids_from_runs(runs)
    if summary.get("false_accept_attack_ids"):
        return set(summary["false_accept_attack_ids"])
    return ids


def _ids_from_runs(runs: list[Any]) -> set[str]:
    out: set[str] = set()
    for r in runs:
        if not isinstance(r, dict):
            continue
        if (r.get("comparison") or {}).get("result") == "FALSE_ACCEPT_OBSERVED":
            aid = r.get("attack_id")
            if aid:
                out.add(str(aid))
    return out


def _run_count(summary: dict[str, Any]) -> int | None:
    runs = summary.get("runs")
    if isinstance(runs, list):
        return len(runs)
    if summary.get("run_count") is not None:
        return int(summary["run_count"])
    profiles = summary.get("profiles")
    if isinstance(profiles, list):
        return sum(int(p.get("run_count") or 0) for p in profiles if isinstance(p, dict))
    return None
