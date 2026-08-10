"""Artifact/hash binding oracle — independent of target verdict."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any


def evaluate(workspace: Path) -> dict[str, Any]:
    artifact = workspace / "artifacts" / "build.bin"
    manifest_path = workspace / "artifacts" / "manifest.json"
    actual = None
    claimed = None
    present = artifact.is_file() and manifest_path.is_file()
    if artifact.is_file():
        actual = hashlib.sha256(artifact.read_bytes()).hexdigest()
    if manifest_path.is_file():
        try:
            data = json.loads(manifest_path.read_text(encoding="utf-8"))
            claimed = data.get("sha256")
        except json.JSONDecodeError:
            claimed = None
    matches = present and actual is not None and claimed is not None and actual == claimed
    return {
        "facts": {
            "artifact_present": artifact.is_file(),
            "manifest_present": manifest_path.is_file(),
            "actual_sha256": actual,
            "claimed_sha256": claimed,
            "artifact_matches_manifest": bool(matches),
        }
    }
