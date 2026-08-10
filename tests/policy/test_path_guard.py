"""Containment path guard tests."""

from __future__ import annotations

from pathlib import Path

import pytest

from smallestlie.policy.path_guard import PathGuard, PathGuardError


def test_relative_inside_ok(tmp_path: Path) -> None:
    guard = PathGuard(tmp_path)
    (tmp_path / "a").mkdir()
    p = guard.ensure_relative_inside("a")
    assert p == (tmp_path / "a").resolve()


def test_path_traversal_rejected(tmp_path: Path) -> None:
    guard = PathGuard(tmp_path)
    with pytest.raises(PathGuardError):
        guard.ensure_relative_inside("../escape")


def test_absolute_escape_rejected(tmp_path: Path, tmp_path_factory: pytest.TempPathFactory) -> None:
    guard = PathGuard(tmp_path)
    outside = tmp_path_factory.mktemp("outside")
    with pytest.raises(PathGuardError):
        guard.ensure_inside(outside / "x", label="escape")


def test_source_mutation_refused(tmp_path: Path) -> None:
    guard = PathGuard(tmp_path)
    with pytest.raises(PathGuardError):
        guard.assert_not_source(tmp_path, tmp_path)
