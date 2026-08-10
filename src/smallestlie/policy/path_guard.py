"""Canonical path guards for workspace containment."""

from __future__ import annotations

import os
from pathlib import Path


class PathGuardError(Exception):
    """Raised when a path escapes the authorized root."""


class PathGuard:
    """Ensure all resolved paths remain under a single root."""

    def __init__(self, root: str | Path) -> None:
        self.root = self.canonicalize(root)
        if not self.root.exists():
            raise PathGuardError(f"root does not exist: {self.root}")
        if not self.root.is_dir():
            raise PathGuardError(f"root is not a directory: {self.root}")

    @staticmethod
    def canonicalize(path: str | Path) -> Path:
        """Resolve to absolute path with strict symlink resolution when present."""
        p = Path(path)
        # Expand user only for absolute diagnostics; prefer absolute inputs.
        try:
            resolved = p.resolve(strict=False)
        except OSError as exc:
            raise PathGuardError(f"cannot resolve path: {path}") from exc
        return resolved

    def ensure_inside(self, path: str | Path, *, label: str = "path") -> Path:
        candidate = self.canonicalize(path)
        try:
            candidate.relative_to(self.root)
        except ValueError as exc:
            raise PathGuardError(
                f"{label} escapes root: path={candidate} root={self.root}"
            ) from exc
        # Extra Windows/UNC/relative-segment defense after resolution.
        root_s = str(self.root)
        cand_s = str(candidate)
        if os.name == "nt":
            root_s = os.path.normcase(root_s)
            cand_s = os.path.normcase(cand_s)
        if not (cand_s == root_s or cand_s.startswith(root_s + os.sep)):
            raise PathGuardError(
                f"{label} escapes root after norm: path={candidate} root={self.root}"
            )
        return candidate

    def ensure_relative_inside(self, relative: str | Path) -> Path:
        rel = Path(relative)
        if rel.is_absolute():
            raise PathGuardError(f"absolute path not allowed as relative: {relative}")
        # Reject traversal tokens before join.
        parts = rel.parts
        if any(p in ("..",) for p in parts):
            raise PathGuardError(f"path traversal rejected: {relative}")
        joined = self.root / rel
        return self.ensure_inside(joined, label="relative path")

    def assert_not_source(self, source: str | Path, candidate: str | Path) -> None:
        src = self.canonicalize(source)
        cand = self.canonicalize(candidate)
        if src == cand:
            raise PathGuardError(
                f"refusing to mutate source path in place: {cand}"
            )

    def check_symlink_escape(self, path: str | Path) -> Path:
        """If path is a symlink, ensure its target stays inside root."""
        p = Path(path)
        if not p.exists() and not p.is_symlink():
            # May not exist yet; still constrain parent chain.
            return self.ensure_inside(p.parent, label="symlink parent")
        if p.is_symlink() or p.exists():
            return self.ensure_inside(p, label="symlink path")
        return self.ensure_inside(p, label="path")
