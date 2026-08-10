"""Immutable baseline capture for a campaign target."""

from __future__ import annotations

import hashlib
import json
import platform
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from smallestlie import __version__
from smallestlie.baseline.inventory import build_inventory
from smallestlie.sandbox.workspace import inventory_digest


def capture_baseline(
    target: str | Path,
    *,
    adapter_name: str,
    adapter_version: str,
    authorization_digest: str,
) -> dict[str, Any]:
    root = Path(target).resolve()
    inv = build_inventory(root)
    revision = _read_revision(root)
    content_digest = inventory_digest(root)
    baseline = {
        "schema_version": "smallestlie.baseline/v1",
        "captured_at": datetime.now(timezone.utc).isoformat(),
        "target_path": str(root),
        "revision": revision,
        "content_digest": content_digest,
        "inventory_digest": inv["inventory_digest"],
        "file_count": inv["file_count"],
        "files": inv["files"],
        "adapter": {
            "name": adapter_name,
            "version": adapter_version,
        },
        "authorization_digest": authorization_digest,
        "tool_version": __version__,
        "environment": {
            "python": sys.version.split()[0],
            "platform": platform.platform(),
            "machine": platform.machine(),
        },
    }
    baseline["baseline_digest"] = hashlib.sha256(
        json.dumps(
            {
                "content_digest": content_digest,
                "inventory_digest": inv["inventory_digest"],
                "revision": revision,
                "adapter": baseline["adapter"],
                "authorization_digest": authorization_digest,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()
    return baseline


def _read_revision(root: Path) -> str:
    for candidate in ("REVISION", "revision.txt", "fixture_revision.txt"):
        p = root / candidate
        if p.is_file():
            return p.read_text(encoding="utf-8").strip()
    return "unknown"
