"""Deterministic mutation primitives (allowlisted operations only)."""

from __future__ import annotations

import json
import shutil
from pathlib import Path
from typing import Any

import yaml

from smallestlie.policy.path_guard import PathGuard, PathGuardError


class MutationError(Exception):
    pass


def apply_mutations(
    workspace_root: str | Path,
    mutations: list[dict[str, Any]],
    *,
    source_path: str | Path | None = None,
) -> list[dict[str, Any]]:
    """Apply mutations inside workspace; return applied step records."""
    guard = PathGuard(workspace_root)
    if source_path is not None:
        guard.assert_not_source(source_path, workspace_root)

    applied: list[dict[str, Any]] = []
    for i, step in enumerate(mutations):
        record = _apply_one(guard, step, index=i)
        applied.append(record)
    return applied


def _apply_one(guard: PathGuard, step: dict[str, Any], *, index: int) -> dict[str, Any]:
    mtype = step["type"]
    if mtype == "replace_text":
        path = guard.ensure_relative_inside(step["path"])
        old = step["old"]
        new = step["new"]
        text = path.read_text(encoding="utf-8")
        count = text.count(old)
        if count < 1:
            raise MutationError(f"replace_text[{index}]: old text not found in {step['path']}")
        if step.get("expected_count") is not None and count != int(step["expected_count"]):
            raise MutationError(
                f"replace_text[{index}]: expected {step['expected_count']} matches, got {count}"
            )
        path.write_text(text.replace(old, new), encoding="utf-8")
        return {"index": index, "type": mtype, "path": step["path"], "replacements": count}

    if mtype == "structured_set":
        path = guard.ensure_relative_inside(step["path"])
        pointer = str(step["pointer"])  # JSON-pointer-like /a/b
        value = step["value"]
        data = _load_structured(path)
        _set_pointer(data, pointer, value)
        _dump_structured(path, data)
        return {
            "index": index,
            "type": mtype,
            "path": step["path"],
            "pointer": pointer,
            "value": value,
        }

    if mtype == "delete_path":
        path = guard.ensure_relative_inside(step["path"])
        if path.is_dir():
            shutil.rmtree(path)
        elif path.exists():
            path.unlink()
        else:
            raise MutationError(f"delete_path[{index}]: not found {step['path']}")
        return {"index": index, "type": mtype, "path": step["path"]}

    if mtype == "rename_path":
        src = guard.ensure_relative_inside(step["from"])
        dest = guard.ensure_relative_inside(step["to"])
        if not src.exists():
            raise MutationError(f"rename_path[{index}]: source missing {step['from']}")
        dest.parent.mkdir(parents=True, exist_ok=True)
        if dest.exists():
            raise MutationError(f"rename_path[{index}]: dest exists {step['to']}")
        src.rename(dest)
        return {
            "index": index,
            "type": mtype,
            "from": step["from"],
            "to": step["to"],
        }

    if mtype == "duplicate_path":
        src = guard.ensure_relative_inside(step["from"])
        dest = guard.ensure_relative_inside(step["to"])
        if not src.exists():
            raise MutationError(f"duplicate_path[{index}]: source missing {step['from']}")
        dest.parent.mkdir(parents=True, exist_ok=True)
        if src.is_dir():
            shutil.copytree(src, dest)
        else:
            shutil.copy2(src, dest)
        return {
            "index": index,
            "type": mtype,
            "from": step["from"],
            "to": step["to"],
        }

    if mtype == "write_text":
        path = guard.ensure_relative_inside(step["path"])
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(str(step["content"]), encoding="utf-8")
        return {"index": index, "type": mtype, "path": step["path"]}

    if mtype == "write_json":
        path = guard.ensure_relative_inside(step["path"])
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps(step["content"], indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        return {"index": index, "type": mtype, "path": step["path"]}

    raise MutationError(f"unsupported mutation type: {mtype}")


def _load_structured(path: Path) -> Any:
    text = path.read_text(encoding="utf-8")
    if path.suffix.lower() in {".yaml", ".yml"}:
        return yaml.safe_load(text)
    if path.suffix.lower() == ".json":
        return json.loads(text)
    # Try YAML then JSON.
    try:
        return yaml.safe_load(text)
    except Exception:
        return json.loads(text)


def _dump_structured(path: Path, data: Any) -> None:
    if path.suffix.lower() in {".yaml", ".yml"}:
        path.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")
    else:
        path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _set_pointer(data: Any, pointer: str, value: Any) -> None:
    if not pointer.startswith("/"):
        raise MutationError(f"pointer must start with /: {pointer}")
    parts = [p for p in pointer.split("/")[1:] if p != ""]
    if not parts:
        raise MutationError("empty pointer")
    cur = data
    for part in parts[:-1]:
        if isinstance(cur, dict):
            if part not in cur:
                cur[part] = {}
            cur = cur[part]
        else:
            raise MutationError(f"cannot traverse pointer at {part}")
    last = parts[-1]
    if isinstance(cur, dict):
        cur[last] = value
    else:
        raise MutationError(f"cannot set pointer leaf {last}")
