"""Append-only hash-chained campaign ledger."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from smallestlie import __version__


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def payload_digest(payload: dict[str, Any]) -> str:
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


@dataclass
class Ledger:
    path: Path
    tool_version: str = __version__
    _seq: int = 0
    _prev_digest: str = "0" * 64

    def __post_init__(self) -> None:
        self.path = Path(self.path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if self.path.exists() and self.path.stat().st_size > 0:
            # Resume sequence from existing file.
            last = None
            with self.path.open("r", encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if line:
                        last = json.loads(line)
            if last:
                self._seq = int(last["seq"])
                self._prev_digest = last["entry_digest"]

    def append(self, event_type: str, payload: dict[str, Any]) -> dict[str, Any]:
        self._seq += 1
        entry = {
            "schema_version": "smallestlie.ledger/v1",
            "seq": self._seq,
            "timestamp": _utc_now(),
            "event_type": event_type,
            "tool_version": self.tool_version,
            "payload": payload,
            "payload_digest": payload_digest(payload),
            "previous_entry_digest": self._prev_digest,
        }
        entry["entry_digest"] = payload_digest(
            {
                "seq": entry["seq"],
                "timestamp": entry["timestamp"],
                "event_type": entry["event_type"],
                "tool_version": entry["tool_version"],
                "payload_digest": entry["payload_digest"],
                "previous_entry_digest": entry["previous_entry_digest"],
            }
        )
        with self.path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry, sort_keys=True, default=str) + "\n")
        self._prev_digest = entry["entry_digest"]
        return entry

    def read_entries(self) -> list[dict[str, Any]]:
        if not self.path.exists():
            return []
        entries: list[dict[str, Any]] = []
        with self.path.open("r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    entries.append(json.loads(line))
        return entries
