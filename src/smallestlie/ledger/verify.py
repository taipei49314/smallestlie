"""Verify append-only ledger integrity."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from smallestlie.ledger.chain import payload_digest


def verify_ledger(path: str | Path, *, required_protocol: str | None = None,
                  expected_lock: dict | None = None) -> dict[str, Any]:
    p = Path(path)
    if not p.is_file():
        return {
            "ok": False,
            "error": f"ledger not found: {p}",
            "entries_checked": 0,
        }

    entries: list[dict[str, Any]] = []
    raw_lines: list[str] = []
    with p.open("r", encoding="utf-8") as fh:
        for lineno, line in enumerate(fh, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                entries.append(json.loads(line))
                raw_lines.append(line)
            except json.JSONDecodeError as exc:
                return {
                    "ok": False,
                    "error": f"invalid JSON at line {lineno}: {exc}",
                    "entries_checked": len(entries),
                }

    prev = "0" * 64
    for i, entry in enumerate(entries):
        expected_seq = i + 1
        if int(entry.get("seq", -1)) != expected_seq:
            return {
                "ok": False,
                "error": f"sequence gap at entry {expected_seq}: got {entry.get('seq')}",
                "entries_checked": i,
            }
        if entry.get("previous_entry_digest") != prev:
            return {
                "ok": False,
                "error": f"chain break at seq {expected_seq}",
                "entries_checked": i,
            }
        pd = payload_digest(entry.get("payload") or {})
        if entry.get("payload_digest") != pd:
            return {
                "ok": False,
                "error": f"payload digest mismatch at seq {expected_seq}",
                "entries_checked": i,
            }
        recomputed = payload_digest(
            {
                "seq": entry["seq"],
                "timestamp": entry["timestamp"],
                "event_type": entry["event_type"],
                "tool_version": entry["tool_version"],
                "payload_digest": entry["payload_digest"],
                "previous_entry_digest": entry["previous_entry_digest"],
            }
        )
        if entry.get("entry_digest") != recomputed:
            return {
                "ok": False,
                "error": f"entry digest mismatch at seq {expected_seq}",
                "entries_checked": i,
            }
        prev = entry["entry_digest"]

    chain_result = {
        "ok": True,
        "error": None,
        "entries_checked": len(entries),
        "head_digest": prev if entries else None,
    }
    from smallestlie.ledger.protocol import M12_EVENTS, PROTOCOL, verify_m12_protocol
    markers = [entry.get("payload", {}).get("protocol") for entry in entries
               if entry.get("event_type") == "campaign_created" and isinstance(entry.get("payload"), dict)
               and "protocol" in entry["payload"]]
    new_events = any(entry.get("event_type") in M12_EVENTS for entry in entries)
    if markers or new_events or required_protocol is not None or expected_lock is not None:
        from smallestlie.verdict.json_input import read_json
        try:
            for line in raw_lines:
                read_json(line)
        except ValueError as exc:
            return {**chain_result, "ok": False, "chain_ok": True, "protocol_ok": False,
                    "complete": False, "error": f"ambiguous formal ledger JSON: {exc}"}
        if markers != [PROTOCOL] or required_protocol not in (None, PROTOCOL):
            return {**chain_result, "ok": False, "chain_ok": True, "protocol_ok": False,
                    "complete": False, "error": "missing/unknown formal protocol marker"}
        protocol_result = verify_m12_protocol(entries, expected_lock=expected_lock)
        return {**chain_result, **protocol_result, "chain_ok": True, "protocol_ok": protocol_result["ok"]}
    return chain_result
