"""Disposable workspace does not mutate source."""

from __future__ import annotations

from pathlib import Path

from smallestlie.attacks.primitives import apply_mutations
from smallestlie.sandbox.workspace import DisposableWorkspace, inventory_digest


def test_source_byte_identical_after_mutation(tmp_path: Path) -> None:
    src = tmp_path / "fixture"
    src.mkdir()
    (src / "file.txt").write_text("original\n", encoding="utf-8")
    before = inventory_digest(src)

    ws = DisposableWorkspace.create(src, parent_dir=tmp_path / "workspaces")
    try:
        apply_mutations(
            ws.workspace_path,
            [{"type": "write_text", "path": "file.txt", "content": "mutated\n"}],
            source_path=src,
        )
        assert (ws.workspace_path / "file.txt").read_text(encoding="utf-8") == "mutated\n"
        after = inventory_digest(src)
        assert before == after
        assert (src / "file.txt").read_text(encoding="utf-8") == "original\n"
    finally:
        ws.cleanup()
