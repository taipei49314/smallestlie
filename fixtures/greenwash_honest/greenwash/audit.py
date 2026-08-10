"""
Honest Greenwash auditor — detects the Wave A theater set.
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
    reasons: list[str] = []
    policy_path = package / "policy.yaml"
    if not policy_path.is_file():
        reasons.append("required_policy_missing")
        policy = {}
    else:
        policy = _load_yaml(policy_path)

    if "require_tests" not in policy and policy_path.is_file():
        reasons.append("require_tests_default_must_not_open")
    require_tests = bool(policy.get("require_tests", True))
    require_matrix = bool(policy.get("require_matrix", True))
    require_fresh = bool(policy.get("require_fresh_subject", True))
    require_summary = bool(policy.get("require_ci_summary", True))
    min_tests = int(policy.get("min_tests", 1))
    required_jobs = list(policy.get("required_jobs") or ["unit", "integration", "gate"])

    ci_path = package / "ci-summary.json"
    if require_summary and not ci_path.is_file():
        reasons.append("ci_summary_missing")
    ci = _load_json(ci_path)

    jobs = ci.get("jobs") if isinstance(ci.get("jobs"), list) else []
    job_by_name = {str(j.get("name")): j for j in jobs if isinstance(j, dict)}
    skipped = []
    for name in required_jobs:
        j = job_by_name.get(name)
        if j is None:
            reasons.append(f"required_job_missing:{name}")
            continue
        st = str(j.get("status", "")).lower()
        if st in {"skipped", "skip"}:
            skipped.append(name)
            reasons.append(f"required_job_skipped:{name}")
        elif st not in {"pass", "passed", "success"}:
            reasons.append(f"required_job_not_pass:{name}")

    if require_matrix and skipped:
        reasons.append("matrix_incomplete")

    junit = package / "junit" / "results.xml"
    junit_text = junit.read_text(encoding="utf-8") if junit.is_file() else ""
    testcases = junit_text.count("<testcase")
    if require_tests and testcases < min_tests:
        reasons.append("zero_or_insufficient_tests")

    subject = _load_json(package / "subject.json")
    if require_fresh:
        sub_rev = subject.get("revision")
        cur_rev = subject.get("current_revision")
        if sub_rev is None or cur_rev is None or str(sub_rev) != str(cur_rev):
            reasons.append("stale_subject_revision")
        if subject.get("force_channel_disagree"):
            reasons.append("channel_disagreement_forced")

    # PATH: required summary must be at canonical path
    if require_summary and not ci_path.is_file():
        reasons.append("canonical_summary_missing")

    # Coverage materiality (simple): if claimed, file must exist and lines > 0
    cov_claim = ci.get("coverage_claimed")
    cov_path = package / "coverage" / "coverage.json"
    if cov_claim:
        cov = _load_json(cov_path)
        if not cov_path.is_file() or int(cov.get("lines_covered") or 0) <= 0:
            reasons.append("hollow_coverage")

    warnings = _load_json(package / "warnings.json")
    items = warnings.get("items") if isinstance(warnings.get("items"), list) else []
    if policy.get("require_decision_warnings") and not items:
        # only if policy asks
        reasons.append("decision_warnings_missing")

    # Explicit theater flag always dirty
    if ci.get("explicit_theater") is True:
        reasons.append("explicit_theater_flag")

    clean = len(reasons) == 0
    result = {
        "product": "greenwash",
        "variant": "honest",
        "classification": "clean" if clean else "theater_detected",
        "accepted": clean,
        "status": "CLEAN" if clean else "THEATER",
        "ok": clean,
        "theater_reasons": reasons,
        "checks": {
            "policy_present": policy_path.is_file(),
            "tests_count": testcases,
            "jobs_total": len(jobs),
            "jobs_skipped": len(skipped),
            "required_jobs": required_jobs,
            "subject_revision": subject.get("revision"),
            "current_revision": subject.get("current_revision"),
            "coverage_present": cov_path.is_file(),
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
    (package / "audit-report.json").write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )

    if args.json:
        print(json.dumps(result, sort_keys=True))
    else:
        print(result["status"])

    return 0 if result.get("accepted") else 1
