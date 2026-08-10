"""Test discovery oracle — independent of target verdict."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import yaml


def evaluate(workspace: Path) -> dict[str, Any]:
    config_path = workspace / "config" / "discovery.yaml"
    pattern = "test_*.py"
    if config_path.is_file():
        cfg = yaml.safe_load(config_path.read_text(encoding="utf-8")) or {}
        if isinstance(cfg, dict):
            disc = cfg.get("discovery") or cfg
            if isinstance(disc, dict) and disc.get("pattern"):
                pattern = str(disc["pattern"])

    tests_dir = workspace / "tests"
    discovered: list[str] = []
    if tests_dir.is_dir():
        # Glob-like: support simple * patterns only.
        for p in sorted(tests_dir.rglob("*")):
            if not p.is_file():
                continue
            if _match(p.name, pattern):
                discovered.append(p.relative_to(workspace).as_posix())

    # Required tests declared by fixture.
    required_path = workspace / "config" / "required_tests.yaml"
    required: list[str] = []
    if required_path.is_file():
        raw = yaml.safe_load(required_path.read_text(encoding="utf-8")) or {}
        if isinstance(raw, dict):
            required = [str(x) for x in (raw.get("required_tests") or [])]

    return {
        "facts": {
            "pattern": pattern,
            "discovered_count": len(discovered),
            "discovered": discovered,
            "required_tests": required,
            "discovery_nonempty": len(discovered) > 0,
            "all_required_present": all(
                any(r in d or d.endswith(r) or Path(d).name == Path(r).name for d in discovered)
                for r in required
            )
            if required
            else len(discovered) > 0,
        }
    }


def _match(name: str, pattern: str) -> bool:
    # Convert simple glob to regex.
    rx = "^" + re.escape(pattern).replace(r"\*", ".*").replace(r"\?", ".") + "$"
    return re.match(rx, name) is not None
