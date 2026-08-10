"""
Naive gate verifier with intentionally seeded weaknesses for M1–M3 attacks.

Weaknesses include empty discovery, stale evidence, hash ignore, partial matrix,
skipped jobs, semantic inversion, open defaults, path blindness, workflow skip,
unauthorized approver, channel disagreement, unexecuted assertions.
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


def load_policy(root: Path) -> dict:
    for rel in ("gate_policy.yaml", "config/gate_policy.yaml", "policy.yaml"):
        p = root / rel
        if p.is_file():
            return _load_yaml(p)
    # CFG-001 / SEM-003: missing policy => open defaults
    return {"mode": "open", "missing": True}


def read_revision(root: Path) -> str | None:
    for name in ("REVISION", "revision.txt"):
        p = root / name
        if p.is_file():
            return p.read_text(encoding="utf-8").strip()
    return None


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    h.update(path.read_bytes())
    return h.hexdigest()


def main(argv: list[str] | None = None) -> int:
    argv = list(argv or sys.argv[1:])
    if not argv or argv[0] != "verify":
        print("usage: python -m fixture_gate verify", file=sys.stderr)
        return 2

    root = Path.cwd()
    policy = load_policy(root)
    mode = str(policy.get("mode", "open"))
    tests = discover_tests(root)
    revision = read_revision(root)

    # Matrix / workflow fixtures
    matrix = _load_yaml(root / "config" / "matrix.yaml")
    required_jobs = list(matrix.get("required_jobs") or ["unit", "integration"])
    workflow = _load_yaml(root / "config" / "workflow.yaml")
    jobs = workflow.get("jobs") if isinstance(workflow.get("jobs"), dict) else {}
    executed_jobs = []
    skipped_jobs = []
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

    # Partial run claim: naive treats any non-empty executed set (or empty) as full
    partial = _load_yaml(root / "config" / "execution.yaml")
    run_subset = list(partial.get("run_only") or [])

    # Authority
    authority = _load_json(root / "authority" / "approval.json")
    approver = str(authority.get("approver", "unknown"))

    # Artifact / hash
    artifact_path = root / "artifacts" / "build.bin"
    manifest = _load_json(root / "artifacts" / "manifest.json")
    artifact_bytes = artifact_path.read_bytes() if artifact_path.is_file() else b""
    actual_hash = hashlib.sha256(artifact_bytes).hexdigest() if artifact_path.is_file() else None
    claimed_hash = manifest.get("sha256")

    # Evidence
    evidence = _load_json(root / "evidence" / "evidence.json")
    evidence_revision = evidence.get("target_revision") or evidence.get("revision")
    force_disagree = bool(evidence.get("force_channel_disagree"))
    # Unexecuted assertion marker
    skip_assertions = bool(evidence.get("skip_assertions")) or (
        root / "config" / "skip_assertions.flag"
    ).is_file()

    # Semantics
    semantics = _load_yaml(root / "config" / "semantics.yaml")
    status_map = semantics.get("status_map") if isinstance(semantics.get("status_map"), dict) else {}
    # SEM-003: missing require_approval defaults to allow in naive
    require_approval = policy.get("require_approval")
    if require_approval is None:
        require_approval = False  # open default

    # Basename inventory (PATH-002): naive collapses to basename only
    identity_cfg = _load_yaml(root / "config" / "identity.yaml")
    required_leaf = str(identity_cfg.get("required_leaf", "required_check.py"))
    found_by_leaf = False
    for p in root.rglob(required_leaf):
        if p.is_file():
            found_by_leaf = True
            break

    # Protected path (PATH-001): naive ignores exact path
    protected_ok = True

    # Workflow skip of gate job (WF-001)
    gate_skipped = "gate" in skipped_jobs or workflow.get("run_gate") is False

    # Build internal "reality-ish" flags that naive mostly ignores
    out_dir = root / "outputs"
    out_dir.mkdir(parents=True, exist_ok=True)

    # Fake execution trace that may claim more than reality
    claimed_executed = list(tests)
    if skip_assertions:
        # EVD-001: tests present in source discovery but marked not executed
        really_executed: list[str] = []
    else:
        really_executed = list(tests)

    if run_subset:
        really_executed = [t for t in really_executed if any(s in t for s in run_subset)]
        # EXE-001: still claim full required set
        claimed_executed = list(tests) if tests else list(required_jobs)

    # Write independent-looking but liar-friendly trace for naive report
    trace = {
        "discovered": tests,
        "executed_claimed": claimed_executed,
        "executed_actual": really_executed,  # truth leaked for oracle; naive ignores
        "jobs_required": required_jobs,
        "jobs_executed": executed_jobs if executed_jobs else required_jobs,  # may inflate
        "jobs_executed_actual": executed_jobs,
        "jobs_skipped": skipped_jobs,
        "approver": approver,
        "artifact_sha256_actual": actual_hash,
        "artifact_sha256_claimed": claimed_hash,
        "evidence_revision": evidence_revision,
        "target_revision": revision,
        "skip_assertions": skip_assertions,
        "gate_skipped": gate_skipped,
        "basename_hit": found_by_leaf,
    }
    (out_dir / "execution_trace.json").write_text(
        json.dumps(trace, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )

    # --- Naive acceptance (almost always accept) ---
    if mode == "closed":
        return _emit(root, accepted=False, status="REJECTED", tests=tests, revision=revision, extra={"mode": mode})

    # SEM-001: if inverted, map FAIL token to accept
    inverted = bool(status_map.get("invert")) or status_map.get("FAIL") == "ACCEPT"

    if force_disagree:
        report = {
            "status": "VERIFIED",
            "accepted": True,
            "tests_discovered": len(tests),
            "tests": tests,
            "revision": revision,
            "policy_mode": mode,
            "policy_missing": bool(policy.get("missing")),
            "jobs": required_jobs,
            "approver": approver,
            "channels": {"report": "VERIFIED", "exit_code_intent": 1, "aggregator": "prefer_accept"},
            "warnings": ["channel_disagreement_internal"],
            "evidence_refs": ["evidence/evidence.json"],
            "execution_trace": "outputs/execution_trace.json",
        }
        if inverted:
            report["status"] = "FAIL"
            report["accepted"] = True  # inverted semantics treat FAIL as accept
        (out_dir / "report.json").write_text(
            json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        print("VERIFIED (naive aggregator; exit will be 1)")
        return 1

    # Always VERIFIED under naive open mode — ignore all integrity checks
    status = "VERIFIED"
    accepted = True
    if inverted and not tests:
        # still accept empty with inverted map noise
        status = "FAIL"
        accepted = True

    report = {
        "status": status,
        "accepted": accepted,
        "tests_discovered": len(tests),
        "tests": tests,
        "tests_executed_claimed": claimed_executed,
        "revision": revision,
        "policy_mode": mode,
        "policy_missing": bool(policy.get("missing")),
        "require_approval": require_approval,
        "approver": approver,
        "jobs_required": required_jobs,
        "jobs_reported": required_jobs if (executed_jobs or gate_skipped or True) else [],
        "jobs_skipped": skipped_jobs,
        "artifact_manifest_sha256": claimed_hash,
        "protected_ok": protected_ok,
        "basename_ok": found_by_leaf or True,  # PATH-002 weak
        "evidence_refs": ["evidence/evidence.json"],
        "execution_trace": "outputs/execution_trace.json",
        "notes": [
            "naive_gate accepts empty discovery",
            "naive_gate does not bind evidence revision",
            "naive_gate ignores artifact hash mismatch",
            "naive_gate ignores protected path identity",
            "naive_gate ignores unauthorized approver",
            "naive_gate projects skipped jobs as green",
            "naive_gate treats partial runs as full",
        ],
    }
    (out_dir / "report.json").write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(status if not inverted else f"{status} (inverted accept)")
    return 0


def _emit(root: Path, *, accepted: bool, status: str, tests: list, revision, extra: dict) -> int:
    out = root / "outputs"
    out.mkdir(parents=True, exist_ok=True)
    report = {
        "status": status,
        "accepted": accepted,
        "tests_discovered": len(tests),
        "tests": tests,
        "revision": revision,
        **extra,
    }
    (out / "report.json").write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(status)
    return 0 if accepted else 1
