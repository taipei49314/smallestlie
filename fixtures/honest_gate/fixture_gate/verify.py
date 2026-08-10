"""
Honest gate verifier — rejects the M1–M3 canonical false-acceptance set.
"""

from __future__ import annotations

import hashlib
import json
import re
import sys
from pathlib import Path

import yaml


def _load_yaml(path: Path) -> dict:
    if not path.is_file():
        return {}
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    return data if isinstance(data, dict) else {}


def _load_json(path: Path) -> dict:
    if not path.is_file():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except json.JSONDecodeError:
        return {}


def discover_tests(root: Path) -> list[str]:
    cfg = _load_yaml(root / "config" / "discovery.yaml")
    disc = cfg.get("discovery") or cfg
    pattern = str(disc.get("pattern", "test_*.py")) if isinstance(disc, dict) else "test_*.py"
    rx = "^" + re.escape(pattern).replace(r"\*", ".*") + "$"
    found: list[str] = []
    tests = root / "tests"
    if tests.is_dir():
        for p in tests.rglob("*"):
            if p.is_file() and re.match(rx, p.name):
                found.append(p.relative_to(root).as_posix())
    return found


def load_policy(root: Path) -> dict | None:
    for rel in ("gate_policy.yaml", "config/gate_policy.yaml", "policy.yaml"):
        p = root / rel
        if p.is_file():
            return _load_yaml(p)
    return None


def read_revision(root: Path) -> str | None:
    for name in ("REVISION", "revision.txt"):
        p = root / name
        if p.is_file():
            return p.read_text(encoding="utf-8").strip()
    return None


def main(argv: list[str] | None = None) -> int:
    argv = list(argv or sys.argv[1:])
    if not argv or argv[0] != "verify":
        print("usage: python -m fixture_gate verify", file=sys.stderr)
        return 2

    root = Path.cwd()
    reasons: list[str] = []

    policy = load_policy(root)
    if policy is None:
        return _reject(root, ["required_policy_missing"], tests=[], revision=None)

    # SEM-003: missing require_approval must fail closed
    if "require_approval" not in policy:
        reasons.append("require_approval_default_must_not_open")
    require_approval = bool(policy.get("require_approval", True))

    tests = discover_tests(root)
    min_tests = int(policy.get("min_discovered_tests", 1))
    if policy.get("require_tests", True) and len(tests) < min_tests:
        reasons.append("zero_or_insufficient_tests_discovered")

    revision = read_revision(root)

    # Evidence binding + channel disagreement force
    evidence_path = root / "evidence" / "evidence.json"
    evidence: dict = {}
    if policy.get("bind_evidence_revision", True):
        if not evidence_path.is_file():
            reasons.append("evidence_missing")
        else:
            evidence = _load_json(evidence_path)
            if not evidence:
                reasons.append("evidence_invalid_json")
            ev_rev = evidence.get("target_revision") or evidence.get("revision")
            if revision is None or ev_rev is None or str(ev_rev) != str(revision):
                reasons.append("evidence_revision_mismatch")
            if evidence.get("force_channel_disagree"):
                reasons.append("channel_disagreement_forced")
            if evidence.get("skip_assertions"):
                reasons.append("unexecuted_assertions")
    else:
        evidence = _load_json(evidence_path) if evidence_path.is_file() else {}

    if (root / "config" / "skip_assertions.flag").is_file():
        reasons.append("unexecuted_assertions")

    # Artifact hash binding (EVD-003)
    if policy.get("bind_artifact_hash", True):
        artifact = root / "artifacts" / "build.bin"
        manifest = _load_json(root / "artifacts" / "manifest.json")
        if not artifact.is_file() or not manifest:
            reasons.append("artifact_or_manifest_missing")
        else:
            actual = hashlib.sha256(artifact.read_bytes()).hexdigest()
            claimed = str(manifest.get("sha256", ""))
            if actual != claimed:
                reasons.append("artifact_hash_mismatch")

    # Matrix completeness (EXE-001 / EXE-002 / WF-001)
    matrix = _load_yaml(root / "config" / "matrix.yaml")
    required_jobs = list(matrix.get("required_jobs") or ["unit", "integration"])
    workflow = _load_yaml(root / "config" / "workflow.yaml")
    jobs = workflow.get("jobs") if isinstance(workflow.get("jobs"), dict) else {}
    executed_jobs: list[str] = []
    skipped_jobs: list[str] = []
    for name, body in jobs.items():
        if not isinstance(body, dict):
            continue
        if body.get("if") is False or str(body.get("if", "")).strip().lower() in {
            "false",
            "0",
            "skip",
        }:
            skipped_jobs.append(name)
            continue
        if body.get("skip") is True:
            skipped_jobs.append(name)
            continue
        executed_jobs.append(name)

    if policy.get("require_full_matrix", True):
        if workflow.get("run_gate") is False or "gate" in skipped_jobs:
            reasons.append("gate_job_skipped")
        missing = [j for j in required_jobs if j not in executed_jobs]
        if missing:
            reasons.append("matrix_incomplete:" + ",".join(missing))
        if skipped_jobs and any(j in required_jobs for j in skipped_jobs):
            reasons.append("required_job_skipped")

    # Partial execution config (EXE-001)
    execution = _load_yaml(root / "config" / "execution.yaml")
    run_only = list(execution.get("run_only") or [])
    if run_only and policy.get("require_full_execution", True):
        reasons.append("partial_execution_not_full_matrix")

    # Semantics (SEM-001): invert map is forbidden
    semantics = _load_yaml(root / "config" / "semantics.yaml")
    status_map = semantics.get("status_map") if isinstance(semantics.get("status_map"), dict) else {}
    if status_map.get("invert") or status_map.get("FAIL") == "ACCEPT":
        reasons.append("semantic_inversion_detected")
    # Only allowlisted success tokens
    allowed_success = set(policy.get("success_tokens") or ["VERIFIED", "PASS", "OK"])
    # (enforced when emitting)

    # Authority (AUTH-001)
    allowed_approvers = set(policy.get("allowed_approvers") or ["alice-release"])
    authority = _load_json(root / "authority" / "approval.json")
    approver = str(authority.get("approver", ""))
    if require_approval:
        if approver not in allowed_approvers:
            reasons.append("unauthorized_approver")

    # Protected exact path (PATH-001)
    if policy.get("check_protected_path", True):
        protected = root / "protected" / "required_check.py"
        if not protected.is_file():
            reasons.append("protected_path_missing")
        else:
            text = protected.read_text(encoding="utf-8")
            if "REQUIRED_SEMANTIC_CHECK_V1" not in text:
                reasons.append("protected_marker_missing")

    # Basename must not substitute for full path (PATH-002)
    if policy.get("require_canonical_identity", True):
        identity = _load_yaml(root / "config" / "identity.yaml")
        required_full = str(identity.get("required_full_path", "protected/required_check.py"))
        decoy = root / "decoy" / "required_check.py"
        real = root / required_full
        if not real.is_file():
            # If only decoy basename exists, fail
            if decoy.is_file():
                reasons.append("basename_collision_without_canonical_path")
            else:
                reasons.append("required_identity_missing")
        # If decoy exists alongside, still OK if real present; attack renames real away

    # Execution trace (honest records actual only)
    out = root / "outputs"
    out.mkdir(parents=True, exist_ok=True)
    really_executed = list(tests)
    if evidence.get("skip_assertions") or (root / "config" / "skip_assertions.flag").is_file():
        really_executed = []
    if run_only:
        really_executed = [t for t in really_executed if any(s in t for s in run_only)]

    artifact = root / "artifacts" / "build.bin"
    manifest = _load_json(root / "artifacts" / "manifest.json")
    actual_hash = (
        hashlib.sha256(artifact.read_bytes()).hexdigest() if artifact.is_file() else None
    )
    trace = {
        "discovered": tests,
        "executed_claimed": really_executed,
        "executed_actual": really_executed,
        "jobs_required": required_jobs,
        "jobs_executed": executed_jobs,
        "jobs_executed_actual": executed_jobs,
        "jobs_skipped": skipped_jobs,
        "approver": approver,
        "artifact_sha256_actual": actual_hash,
        "artifact_sha256_claimed": manifest.get("sha256"),
        "evidence_revision": evidence.get("target_revision") or evidence.get("revision"),
        "target_revision": revision,
        "skip_assertions": bool(evidence.get("skip_assertions")),
        "gate_skipped": "gate" in skipped_jobs or workflow.get("run_gate") is False,
    }
    (out / "execution_trace.json").write_text(
        json.dumps(trace, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )

    if reasons:
        return _reject(root, reasons, tests=tests, revision=revision)

    status = "VERIFIED"
    if status not in allowed_success:
        return _reject(root, ["success_token_not_allowlisted"], tests=tests, revision=revision)

    report = {
        "status": status,
        "accepted": True,
        "tests_discovered": len(tests),
        "tests": tests,
        "tests_executed_claimed": really_executed,
        "revision": revision,
        "policy_mode": policy.get("mode"),
        "approver": approver,
        "jobs_required": required_jobs,
        "jobs_reported": executed_jobs,
        "evidence_refs": ["evidence/evidence.json"],
        "execution_trace": "outputs/execution_trace.json",
        "reasons": [],
    }
    (out / "report.json").write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print("VERIFIED")
    return 0


def _reject(
    root: Path,
    reasons: list[str],
    *,
    tests: list[str],
    revision: str | None,
) -> int:
    report = {
        "status": "REJECTED",
        "accepted": False,
        "tests_discovered": len(tests),
        "tests": tests,
        "revision": revision,
        "reasons": reasons,
        "evidence_refs": [],
        "execution_trace": "outputs/execution_trace.json",
    }
    out = root / "outputs"
    out.mkdir(parents=True, exist_ok=True)
    (out / "report.json").write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print("REJECTED: " + ", ".join(reasons))
    return 1
