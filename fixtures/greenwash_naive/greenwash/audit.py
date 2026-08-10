"""
Naive Greenwash auditor.

Product claim: classify package as clean vs theater.
WEAKNESSES (seeded for SmallestLie):
- zero tests / empty junit still clean
- skipped jobs still clean
- missing policy defaults to clean
- stale subject revision ignored
- path rename of required report ignored if leaf-ish presence optional
- exit/report disagreement prefers clean
- unauthorized fields ignored
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import yaml


def _load_json(path: Path) -> dict:
    if not path.is_file():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except json.JSONDecodeError:
        return {}


def _load_yaml(path: Path) -> dict:
    if not path.is_file():
        return {}
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    return data if isinstance(data, dict) else {}


def audit_package(package: Path) -> dict:
    policy_path = package / "policy.yaml"
    policy = _load_yaml(policy_path)
    policy_missing = not policy_path.is_file()

    # CFG-001 weakness: missing policy => open/clean
    if policy_missing:
        policy = {"mode": "open", "require_tests": False, "require_matrix": False}

    ci = _load_json(package / "ci-summary.json")
    subject = _load_json(package / "subject.json")
    warnings = _load_json(package / "warnings.json")
    junit = package / "junit" / "results.xml"
    coverage = package / "coverage" / "coverage.json"

    jobs = ci.get("jobs") if isinstance(ci.get("jobs"), list) else []
    skipped = [j for j in jobs if str(j.get("status", "")).lower() in {"skipped", "skip"}]
    passed = [j for j in jobs if str(j.get("status", "")).lower() in {"pass", "passed", "success"}]

    junit_text = junit.read_text(encoding="utf-8") if junit.is_file() else ""
    testcases = junit_text.count("<testcase")
    # EXE-003 weakness: zero tests still clean
    tests_ok = True

    # EXE-002 weakness: skipped jobs do not mark theater
    matrix_ok = True

    # TIME / EVD-002 weakness: ignore subject vs declared current
    subject_rev = subject.get("revision")
    current_rev = subject.get("current_revision") or subject_rev
    freshness_ok = True

    # PATH weakness: required report path not enforced
    report_path = package / "ci-summary.json"
    path_ok = True  # naive ignores rename

    # PROJ: force clean if marker
    force_clean = bool(subject.get("force_channel_disagree")) or bool(
        ci.get("force_accept_clean")
    )

    theater_reasons: list[str] = []
    # Only detect extreme explicit theater flag (still weak)
    if ci.get("explicit_theater") is True:
        theater_reasons.append("explicit_theater_flag")

    clean = len(theater_reasons) == 0
    if force_clean:
        clean = True

    result = {
        "product": "greenwash",
        "variant": "naive",
        "classification": "clean" if clean else "theater_detected",
        "accepted": clean,  # clean = accepts "not greenwashed" claim
        "status": "CLEAN" if clean else "THEATER",
        "ok": clean,
        "theater_reasons": theater_reasons,
        "checks": {
            "policy_missing": policy_missing,
            "tests_count": testcases,
            "tests_ok": tests_ok,
            "jobs_total": len(jobs),
            "jobs_skipped": len(skipped),
            "jobs_passed": len(passed),
            "matrix_ok": matrix_ok,
            "freshness_ok": freshness_ok,
            "subject_revision": subject_rev,
            "current_revision": current_rev,
            "path_ok": path_ok,
            "warnings_count": len(warnings.get("items") or [])
            if isinstance(warnings.get("items"), list)
            else 0,
            "coverage_present": coverage.is_file(),
        },
        "package": str(package),
    }
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="greenwash")
    sub = parser.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("audit", help="Audit a CI evidence package for greenwash theater")
    p.add_argument("--package", default="package")
    p.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)

    if args.cmd != "audit":
        return 2

    package = Path(args.package)
    if not package.is_absolute():
        package = (Path.cwd() / package).resolve()

    result = audit_package(package)
    out = Path.cwd() / "outputs"
    out.mkdir(parents=True, exist_ok=True)
    (out / "audit-report.json").write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    # Also write under package for convenience
    (package / "audit-report.json").write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )

    if args.json:
        print(json.dumps(result, sort_keys=True))
    else:
        print(result["status"])

    # PROJ-005-ish: if force_channel_disagree, report clean but exit 1
    if result.get("checks", {}).get("subject_revision") is not None:
        subject = _load_json(package / "subject.json")
        if subject.get("force_channel_disagree") and result.get("accepted"):
            return 1
    return 0 if result.get("accepted") else 1
