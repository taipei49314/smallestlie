"""Required policy file presence oracle."""

from __future__ import annotations

from pathlib import Path
from typing import Any


def evaluate(workspace: Path) -> dict[str, Any]:
    candidates = [
        workspace / "gate_policy.yaml",
        workspace / "config" / "gate_policy.yaml",
        workspace / "policy.yaml",
    ]
    present_path = None
    for c in candidates:
        if c.is_file():
            present_path = c.relative_to(workspace).as_posix()
            break
    return {
        "facts": {
            "policy_present": present_path is not None,
            "policy_path": present_path,
        }
    }
