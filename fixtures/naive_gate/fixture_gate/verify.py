"""
Naive gate verifier with seeded weaknesses:

1. Zero discovered tests still produce VERIFIED (EXE-003)
2. Stale evidence (wrong revision) still accepted (EVD-002)
3. Exit/report disagreement: prefers accepting channel (PROJ-005)
4. Missing policy defaults to open (CFG-001)
5. Renamed protected path ignored (PATH-001)
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


def load_policy(root: Path) -> dict:
    for rel in ("gate_policy.yaml", "config/gate_policy.yaml", "policy.yaml"):
        p = root / rel
        if p.is_file():
            data = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
            return data if isinstance(data, dict) else {}
    # WEAKNESS CFG-001: missing policy => open/accept
    return {"mode": "open", "missing": True}


def read_revision(root: Path) -> str | None:
    for name in ("REVISION", "revision.txt"):
        p = root / name
        if p.is_file():
            return p.read_text(encoding="utf-8").strip()
    return None


def evidence_ok(root: Path, revision: str | None) -> bool:
    path = root / "evidence" / "evidence.json"
    if not path.is_file():
        # Still accept in naive mode if policy open.
        return True
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return True  # weak
    # WEAKNESS EVD-002: do not bind evidence revision to target revision
    _ = data.get("target_revision") or data.get("revision")
    _ = revision
    return True


def protected_ok(root: Path) -> bool:
    # WEAKNESS PATH-001: ignore rename of protected path
    return True


def main(argv: list[str] | None = None) -> int:
    argv = list(argv or sys.argv[1:])
    if not argv or argv[0] != "verify":
        print("usage: python -m fixture_gate verify", file=sys.stderr)
        return 2

    root = Path.cwd()
    policy = load_policy(root)
    tests = discover_tests(root)
    revision = read_revision(root)
    ev_ok = evidence_ok(root, revision)
    prot_ok = protected_ok(root)

    # WEAKNESS EXE-003: zero tests still VERIFIED
    tests_ok = True

    # Internal "true" failure signal for PROJ-005 demo path:
    # If special marker file requests channel disagreement, report accepts while exit fails
    # OR report fails while we still set accepted True in aggregator.
    disagree = (root / "outputs" / ".force_channel_disagree").is_file()
    # Also trigger disagreement when marker content present in evidence note
    evidence_path = root / "evidence" / "evidence.json"
    if evidence_path.is_file():
        try:
            ed = json.loads(evidence_path.read_text(encoding="utf-8"))
            if ed.get("force_channel_disagree"):
                disagree = True
        except json.JSONDecodeError:
            pass

    # Naive acceptance logic: almost always accept if policy open
    mode = str(policy.get("mode", "open"))
    internal_fail = False
    if mode == "closed":
        internal_fail = True
    if not ev_ok:
        internal_fail = True
    if not prot_ok:
        internal_fail = True
    # Still ignore empty tests.

    out_dir = root / "outputs"
    out_dir.mkdir(parents=True, exist_ok=True)

    if disagree:
        # WEAKNESS PROJ-005: report says VERIFIED/accepted, exit code non-zero
        # Aggregator chooses the accepting channel for "accepted" field.
        report = {
            "status": "VERIFIED",
            "accepted": True,  # aggregator prefers accepting channel
            "tests_discovered": len(tests),
            "tests": tests,
            "revision": revision,
            "policy_mode": mode,
            "policy_missing": bool(policy.get("missing")),
            "channels": {
                "report": "VERIFIED",
                "exit_code_intent": 1,
                "aggregator": "prefer_accept",
            },
            "warnings": ["channel_disagreement_internal"],
            "evidence_refs": ["evidence/evidence.json"],
        }
        (out_dir / "report.json").write_text(
            json.dumps(report, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        print("VERIFIED (naive aggregator; exit will be 1)")
        return 1

    if internal_fail:
        report = {
            "status": "REJECTED",
            "accepted": False,
            "tests_discovered": len(tests),
            "tests": tests,
            "revision": revision,
            "policy_mode": mode,
        }
        (out_dir / "report.json").write_text(
            json.dumps(report, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        print("REJECTED")
        return 1

    report = {
        "status": "VERIFIED",
        "accepted": True,
        "tests_discovered": len(tests),
        "tests": tests,
        "revision": revision,
        "policy_mode": mode,
        "policy_missing": bool(policy.get("missing")),
        "evidence_refs": ["evidence/evidence.json"],
        "notes": [
            "naive_gate accepts empty discovery",
            "naive_gate does not bind evidence revision",
            "naive_gate ignores protected path identity",
        ],
    }
    (out_dir / "report.json").write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print("VERIFIED")
    return 0
