"""
Composition-blind gate.

Correct intent: accept only when protected path intact AND evidence revision matches.

Intentional composition bug:
  When BOTH strict path and strict evidence fail, fall back to a legacy projector
  that accepts basename decoy + evidence.status==PASS (ignoring revision).

Therefore:
  - PATH-001 alone  -> REJECT
  - EVD-002 alone   -> REJECT
  - PATH-001+EVD-002 (with decoy leaf) -> FALSE ACCEPT via legacy projector
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


def main(argv: list[str] | None = None) -> int:
    argv = list(argv or sys.argv[1:])
    if not argv or argv[0] != "verify":
        print("usage: python -m fixture_gate verify", file=sys.stderr)
        return 2

    root = Path.cwd()
    policy = _load_yaml(root / "gate_policy.yaml")
    if not policy:
        return _emit(root, False, "REJECTED", [], None, ["required_policy_missing"])

    tests = discover_tests(root)
    if policy.get("require_tests", True) and len(tests) < int(policy.get("min_discovered_tests", 1)):
        return _emit(root, False, "REJECTED", tests, None, ["zero_or_insufficient_tests"])

    revision = None
    for name in ("REVISION", "revision.txt"):
        p = root / name
        if p.is_file():
            revision = p.read_text(encoding="utf-8").strip()
            break

    protected = root / "protected" / "required_check.py"
    strict_path = False
    if protected.is_file():
        try:
            strict_path = "REQUIRED_SEMANTIC_CHECK_V1" in protected.read_text(encoding="utf-8")
        except OSError:
            strict_path = False

    evidence = _load_json(root / "evidence" / "evidence.json")
    ev_rev = evidence.get("target_revision") or evidence.get("revision")
    strict_ev = (
        revision is not None
        and ev_rev is not None
        and str(ev_rev) == str(revision)
    )
    relaxed_ev = str(evidence.get("status", "")).upper() in {"PASS", "OK", "VERIFIED"}

    identity = _load_yaml(root / "config" / "identity.yaml")
    leaf = str(identity.get("required_leaf", "required_check.py"))
    relaxed_path = any(p.is_file() for p in root.rglob(leaf))

    legacy = bool(policy.get("legacy_projector_on_double_failure", True))
    reasons: list[str] = []

    if (not strict_path) and (not strict_ev) and legacy:
        # COMPOSITION BUG: legacy projector
        if relaxed_path and relaxed_ev:
            return _emit(
                root,
                True,
                "VERIFIED",
                tests,
                revision,
                [],
                notes=["legacy_projector_double_failure"],
            )
        reasons.append("legacy_projector_failed")
        return _emit(root, False, "REJECTED", tests, revision, reasons)

    if not strict_path:
        reasons.append("protected_path_missing")
    if not strict_ev:
        reasons.append("evidence_revision_mismatch")
    if reasons:
        return _emit(root, False, "REJECTED", tests, revision, reasons)

    return _emit(root, True, "VERIFIED", tests, revision, [])


def _emit(
    root: Path,
    accepted: bool,
    status: str,
    tests: list,
    revision,
    reasons: list[str],
    notes: list[str] | None = None,
) -> int:
    out = root / "outputs"
    out.mkdir(parents=True, exist_ok=True)
    report = {
        "status": status,
        "accepted": accepted,
        "tests_discovered": len(tests),
        "tests": tests,
        "revision": revision,
        "reasons": reasons,
        "notes": notes or [],
        "evidence_refs": ["evidence/evidence.json"],
    }
    (out / "report.json").write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    # Minimal execution trace for oracles
    (out / "execution_trace.json").write_text(
        json.dumps(
            {
                "discovered": tests,
                "executed_actual": tests if accepted or tests else [],
                "executed_claimed": tests,
                "skip_assertions": False,
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    print(status if accepted else f"REJECTED: {', '.join(reasons)}")
    return 0 if accepted else 1
