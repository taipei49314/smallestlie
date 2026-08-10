"""Disposable workspace manager — never mutate the source path."""

from __future__ import annotations

import hashlib
import os
import shutil
import tempfile
import uuid
from dataclasses import dataclass
from pathlib import Path

from smallestlie.policy.path_guard import PathGuard, PathGuardError


@dataclass
class DisposableWorkspace:
    source_path: Path
    workspace_path: Path
    workspace_id: str
    path_guard: PathGuard

    @classmethod
    def create(
        cls,
        source: str | Path,
        *,
        parent_dir: str | Path | None = None,
        prefix: str = "smallestlie-",
    ) -> DisposableWorkspace:
        source_path = PathGuard.canonicalize(source)
        if not source_path.is_dir():
            raise PathGuardError(f"source is not a directory: {source_path}")

        workspace_id = uuid.uuid4().hex[:12]
        parent = Path(parent_dir) if parent_dir else Path(tempfile.gettempdir()) / "smallestlie-workspaces"
        parent.mkdir(parents=True, exist_ok=True)
        dest = parent / f"{prefix}{workspace_id}"
        if dest.exists():
            raise PathGuardError(f"workspace already exists: {dest}")

        # Copy tree; ignore common VCS/cache noise but keep fixture content.
        shutil.copytree(
            source_path,
            dest,
            ignore=shutil.ignore_patterns(
                ".git",
                "__pycache__",
                ".pytest_cache",
                ".venv",
                "venv",
                "*.pyc",
            ),
            symlinks=False,  # materialize files; avoid symlink escape from source
        )
        guard = PathGuard(dest)
        guard.assert_not_source(source_path, dest)
        return cls(
            source_path=source_path,
            workspace_path=dest,
            workspace_id=workspace_id,
            path_guard=guard,
        )

    def ensure_inside(self, path: str | Path) -> Path:
        return self.path_guard.ensure_inside(path)

    def resolve_relative(self, relative: str | Path) -> Path:
        return self.path_guard.ensure_relative_inside(relative)

    def assert_not_source(self) -> None:
        self.path_guard.assert_not_source(self.source_path, self.workspace_path)

    def fingerprint_source(self) -> str:
        """Stable content fingerprint of source for immutability checks."""
        return inventory_digest(self.source_path)

    def cleanup(self) -> None:
        if self.workspace_path.exists():
            shutil.rmtree(self.workspace_path, ignore_errors=False)


def inventory_digest(root: str | Path) -> str:
    """SHA-256 over sorted relative paths and file digests."""
    root_p = Path(root)
    h = hashlib.sha256()
    for dirpath, dirnames, filenames in os.walk(root_p):
        dirnames[:] = sorted(d for d in dirnames if d not in {".git", "__pycache__", ".pytest_cache"})
        for name in sorted(filenames):
            if name.endswith(".pyc"):
                continue
            full = Path(dirpath) / name
            rel = full.relative_to(root_p).as_posix()
            h.update(rel.encode("utf-8"))
            h.update(b"\0")
            try:
                data = full.read_bytes()
            except OSError:
                h.update(b"<unreadable>")
            else:
                h.update(hashlib.sha256(data).digest())
            h.update(b"\n")
    return h.hexdigest()
