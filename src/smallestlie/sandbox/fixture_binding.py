"""Bind fixture reports to the inputs of one harness-owned execution.

This detects stale/cross-run output; it does not attest a verifier's honesty.
"""

from __future__ import annotations

import hashlib
import json
import os
import stat
from pathlib import Path

from smallestlie.policy.path_guard import PathGuard, PathGuardError


def _plain_path(path: Path) -> None:
    attrs = path.lstat()
    reparse = getattr(attrs, "st_file_attributes", 0) & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    if stat.S_ISLNK(attrs.st_mode) or reparse:
        raise PathGuardError(f"fixture binding refuses linked/reparse path: {path}")


def report_paths(workspace: Path) -> tuple[Path, Path]:
    guard = PathGuard(workspace)
    output = workspace / "outputs"
    if output.exists() or output.is_symlink():
        _plain_path(output)
        if not output.is_dir():
            raise PathGuardError("fixture outputs must be a directory")
    paths = tuple(output / name for name in ("report.json", "execution_trace.json"))
    for path in paths:
        if path.exists() or path.is_symlink():
            _plain_path(path)
            if not path.is_file():
                raise PathGuardError(f"fixture generated output must be a file: {path}")
        guard.ensure_inside(path, label="fixture generated output")
    return paths


def input_sha256(workspace: Path) -> str:
    """Content/path digest excluding root outputs, VCS and runtime caches."""
    guard = PathGuard(workspace)
    digest = hashlib.sha256(b"smallestlie.fixture-input.v1\0")
    excluded = {".git", "__pycache__", ".pytest_cache", ".venv", "venv"}
    def unreadable(error: OSError) -> None:
        raise error

    for directory, dirs, files in os.walk(workspace, followlinks=False, onerror=unreadable):
        parent = Path(directory)
        dirs[:] = sorted(name for name in dirs if name not in excluded
                         and not (parent == workspace and name == "outputs"))
        for name in dirs:
            path = parent / name
            _plain_path(path)
            guard.ensure_inside(path)
            record = ["directory", path.relative_to(workspace).as_posix()]
            digest.update((json.dumps(record, ensure_ascii=True) + "\n").encode("ascii"))
        for name in sorted(files):
            if name in excluded or name.endswith(".pyc"):
                continue
            path = parent / name
            _plain_path(path)
            guard.ensure_inside(path)
            if not path.is_file():
                raise PathGuardError(f"fixture input must be a regular file: {path}")
            record = ["file", path.relative_to(workspace).as_posix(), hashlib.sha256(path.read_bytes()).hexdigest()]
            digest.update((json.dumps(record, ensure_ascii=True) + "\n").encode("ascii"))
    return digest.hexdigest()
