"""Read-only git facts for materialized workspaces.

Reports what the workspace's own git history says changed between the
baseline commit and the mutant commit. Facts only — never a judgement about
whether a change is theater (that judgement belongs to the attack's
declaration and, independently, to the engine under test).
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path
from typing import Any


def _git(workspace: Path, *args: str) -> tuple[int, str, str]:
    keep = ("PATH", "SYSTEMROOT", "SYSTEMDRIVE", "WINDIR", "COMSPEC", "PATHEXT")
    env = {k: os.environ[k] for k in keep if k in os.environ}
    proc = subprocess.run(
        ["git", *args],
        cwd=str(workspace),
        env=env,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
    )
    return proc.returncode, proc.stdout or "", proc.stderr or ""


def evaluate(workspace: Path) -> dict[str, Any]:
    rc_init, _, _ = _git(workspace, "rev-parse", "--git-dir")
    if rc_init != 0:
        return {
            "facts": {"git_repo": False, "diff_present": False, "changed_files": []},
            "ok": False,
        }

    rc_log, out_log, _ = _git(workspace, "rev-list", "--count", "HEAD")
    commit_count = int(out_log.strip()) if rc_log == 0 else 0

    rc_diff, out_diff, _ = _git(workspace, "diff", "--name-only", "HEAD~1..HEAD")
    changed = [line.strip().replace("\\", "/") for line in out_diff.splitlines() if line.strip()]
    if rc_diff != 0:
        # Single-commit repo (no range yet) is not an error — just no diff.
        changed = []

    return {
        "facts": {
            "git_repo": True,
            "commit_count": commit_count,
            "diff_present": bool(changed),
            "changed_files": sorted(changed),
        },
        "ok": True,
    }
