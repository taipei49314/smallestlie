"""Mutation primitives."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from smallestlie.attacks.primitives import MutationError, apply_mutations
from smallestlie.policy.path_guard import PathGuardError


def test_structured_set_and_source_protection(tmp_path: Path) -> None:
    src = tmp_path / "src"
    ws = tmp_path / "ws"
    src.mkdir()
    ws.mkdir()
    (ws / "config").mkdir()
    cfg = ws / "config" / "discovery.yaml"
    cfg.write_text("discovery:\n  pattern: test_*.py\n", encoding="utf-8")

    applied = apply_mutations(
        ws,
        [
            {
                "type": "structured_set",
                "path": "config/discovery.yaml",
                "pointer": "/discovery/pattern",
                "value": "__none__",
            }
        ],
        source_path=src,
    )
    assert applied[0]["type"] == "structured_set"
    data = yaml.safe_load(cfg.read_text(encoding="utf-8"))
    assert data["discovery"]["pattern"] == "__none__"

    with pytest.raises(PathGuardError):
        apply_mutations(src, [{"type": "delete_path", "path": "x"}], source_path=src)


def test_traversal_blocked(tmp_path: Path) -> None:
    with pytest.raises(PathGuardError):
        apply_mutations(
            tmp_path,
            [{"type": "write_text", "path": "../evil.txt", "content": "x"}],
        )
