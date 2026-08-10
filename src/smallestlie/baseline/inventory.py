"""File inventory helpers."""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
from typing import Any


def file_sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def build_inventory(root: str | Path, *, max_files: int = 10000) -> dict[str, Any]:
    root_p = Path(root)
    files: list[dict[str, Any]] = []
    for dirpath, dirnames, filenames in os.walk(root_p):
        dirnames[:] = sorted(
            d for d in dirnames if d not in {".git", "__pycache__", ".pytest_cache", ".venv"}
        )
        for name in sorted(filenames):
            if name.endswith(".pyc"):
                continue
            full = Path(dirpath) / name
            rel = full.relative_to(root_p).as_posix()
            try:
                st = full.stat()
                digest = file_sha256(full)
            except OSError:
                continue
            files.append(
                {
                    "path": rel,
                    "size": st.st_size,
                    "sha256": digest,
                }
            )
            if len(files) >= max_files:
                break
        if len(files) >= max_files:
            break
    digest = hashlib.sha256(
        json_lines(files).encode("utf-8")
    ).hexdigest()
    return {
        "file_count": len(files),
        "files": files,
        "inventory_digest": digest,
    }


def json_lines(files: list[dict[str, Any]]) -> str:
    import json

    return "\n".join(json.dumps(f, sort_keys=True) for f in files)
