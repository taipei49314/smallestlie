"""
Honest gate verifier — rejects invalid states that naive_gate accepts.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

import yaml


def discover_tests(root: Path) -> list[str]:
    cfg_path = root / "config" / "discovery.yaml"
    pattern = "test_*.py"
    if cfg_path.is_file():
        cfg = yaml.safe_load(cfg_path.read_text(encoding="utf-8")) or {}
        disc = (cfg.get("discovery") or cfg) if isinstance(cfg, dict) else {}
        if isinstance(disc, dict) and disc.get("pattern"):
            pattern = str(disc["pattern"])
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
            data = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
            return data if isinstance(data, dict) else {}
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
        reasons.append("required_policy_missing")
        return _reject(root, reasons, tests=[], revision=None, exit_code=1)

    tests = discover_tests(root)
    min_tests = int(policy.get("min_discovered_tests", 1))
    if policy.get("require_tests", True) and len(tests) < min_tests:
        reasons.append("zero_or_insufficient_tests_discovered")

    revision = read_revision(root)
    if policy.get("bind_evidence_revision", True):
        evidence_path = root / "evidence" / "evidence.json"
        if not evidence_path.is_file():
            reasons.append("evidence_missing")
        else:
            try:
                data = json.loads(evidence_path.read_text(encoding="utf-8"))
            except json.JSONDecodeError:
                reasons.append("evidence_invalid_json")
                data = {}
            ev_rev = data.get("target_revision") or data.get("revision")
            if revision is None or ev_rev is None or str(ev_rev) != str(revision):
                reasons.append("evidence_revision_mismatch")
            if data.get("force_channel_disagree"):
                reasons.append("channel_disagreement_forced")

    if policy.get("check_protected_path", True):
        protected = root / "protected" / "required_check.py"
        if not protected.is_file():
            reasons.append("protected_path_missing")
        else:
            text = protected.read_text(encoding="utf-8")
            if "REQUIRED_SEMANTIC_CHECK_V1" not in text:
                reasons.append("protected_marker_missing")

    # Channel agreement: never emit accepting report with failing exit (or reverse).
    if reasons:
        return _reject(root, reasons, tests=tests, revision=revision, exit_code=1)

    report = {
        "status": "VERIFIED",
        "accepted": True,
        "tests_discovered": len(tests),
        "tests": tests,
        "revision": revision,
        "policy_mode": policy.get("mode"),
        "evidence_refs": ["evidence/evidence.json"],
        "reasons": [],
    }
    out = root / "outputs"
    out.mkdir(parents=True, exist_ok=True)
    (out / "report.json").write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print("VERIFIED")
    return 0


def _reject(
    root: Path,
    reasons: list[str],
    *,
    tests: list[str],
    revision: str | None,
    exit_code: int,
) -> int:
    report = {
        "status": "REJECTED",
        "accepted": False,
        "tests_discovered": len(tests),
        "tests": tests,
        "revision": revision,
        "reasons": reasons,
        "evidence_refs": [],
    }
    out = root / "outputs"
    out.mkdir(parents=True, exist_ok=True)
    (out / "report.json").write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print("REJECTED: " + ", ".join(reasons))
    return exit_code
