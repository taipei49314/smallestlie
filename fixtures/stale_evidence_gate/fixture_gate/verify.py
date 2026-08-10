"""
Isolation fixture: stale_evidence_gate

Intentionally does NOT bind evidence to revision (EVD-002 / TIME-001 surface).
Still enforces path identity and approval for control hygiene.
"""

from __future__ import annotations

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


def main(argv: list[str] | None = None) -> int:
    argv = list(argv or sys.argv[1:])
    if not argv or argv[0] != "verify":
        print("usage: python -m fixture_gate verify", file=sys.stderr)
        return 2

    root = Path.cwd()
    reasons: list[str] = []
    policy = _load_yaml(root / "gate_policy.yaml")
    if not policy:
        return _emit(root, False, "REJECTED", ["required_policy_missing"])

    # Honest-shaped guard (VRF surface); this fixture does not bind even when true.
    if policy.get("bind_evidence_revision", True):
        pass  # WEAKNESS: no revision binding performed

    revision = (root / "REVISION").read_text(encoding="utf-8").strip() if (root / "REVISION").is_file() else None
    evidence = _load_json(root / "evidence" / "evidence.json")
    # Explicitly ignore evidence revision mismatch (isolation weakness)
    _ = evidence.get("target_revision") or evidence.get("revision")
    _ = revision

    protected = root / "protected" / "required_check.py"
    if not protected.is_file() or "REQUIRED_SEMANTIC_CHECK_V1" not in protected.read_text(encoding="utf-8"):
        reasons.append("protected_path_missing")

    approval = _load_json(root / "authority" / "approval.json")
    allowed = set(policy.get("allowed_approvers") or ["alice-release"])
    if str(approval.get("approver", "")) not in allowed:
        reasons.append("unauthorized_approver")

    # discovery nonempty soft check
    pattern = "test_*.py"
    cfg = _load_yaml(root / "config" / "discovery.yaml")
    disc = cfg.get("discovery") or cfg
    if isinstance(disc, dict) and disc.get("pattern"):
        pattern = str(disc["pattern"])
    rx = "^" + re.escape(pattern).replace(r"\*", ".*") + "$"
    tests = []
    tdir = root / "tests"
    if tdir.is_dir():
        tests = [p.relative_to(root).as_posix() for p in tdir.rglob("*") if p.is_file() and re.match(rx, p.name)]
    if policy.get("require_tests", True) and len(tests) < 1:
        reasons.append("zero_tests")

    if reasons:
        return _emit(root, False, "REJECTED", reasons, tests=tests, revision=revision)
    return _emit(root, True, "VERIFIED", [], tests=tests, revision=revision)


def _emit(root: Path, accepted: bool, status: str, reasons: list, tests=None, revision=None) -> int:
    out = root / "outputs"
    out.mkdir(parents=True, exist_ok=True)
    report = {
        "status": status,
        "accepted": accepted,
        "reasons": reasons,
        "tests": tests or [],
        "revision": revision,
        "notes": ["stale_evidence_gate ignores evidence/revision binding"],
        "evidence_refs": ["evidence/evidence.json"],
    }
    (out / "report.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    (out / "execution_trace.json").write_text(
        json.dumps({"discovered": tests or [], "executed_actual": tests or [], "skip_assertions": False}, indent=2)
        + "\n",
        encoding="utf-8",
    )
    print(status if accepted else f"REJECTED: {', '.join(reasons)}")
    return 0 if accepted else 1


if __name__ == "__main__":
    raise SystemExit(main())
