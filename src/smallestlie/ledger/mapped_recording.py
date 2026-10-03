"""Strict follow-up journal protocol; separate from both legacy M12 ledgers."""

from __future__ import annotations

from smallestlie.attacks.adjudication import mapping, sha256
from smallestlie.campaign.preregistration import PreregistrationError, canonical_digest, integer, json_mapping
from smallestlie.ledger.lifecycle import artifact_ref

SCHEMA = "smallestlie.mapped-recording/v1"
KEYS = {"schema_version", "seq", "event", "payload", "previous_sha256", "entry_sha256"}


def journal_entry(seq: int, event: str, payload: dict, previous: str) -> dict:
    body = {"schema_version": SCHEMA, "seq": seq, "event": event,
            "payload": payload, "previous_sha256": previous}
    return {**body, "entry_sha256": canonical_digest(body)}


def read_mapped_journal(data: bytes, case_ids: list[str]) -> tuple[dict, ...]:
    """Check syntax/order/chain only. This function grants no source authority."""
    if (type(data) is not bytes or not data or len(data) > 10_000_000
            or not data.endswith(b"\n") or b"\r" in data):
        raise PreregistrationError("mapped_journal_requires_bounded_complete_native_bytes")
    if (type(case_ids) is not list or not case_ids
            or any(type(cid) is not str or not cid for cid in case_ids)
            or len(set(case_ids)) != len(case_ids)):
        raise PreregistrationError("mapped_journal_requires_complete_unique_frozen_roster")
    expected = [("mapped_recording_started", None)]
    expected.extend((event, cid) for cid in case_ids for event in ("mapped_review_disposed", "mapped_case_adjudicated"))
    expected.append(("mapped_summary", None))
    lines = data.splitlines()
    if len(lines) != len(expected):
        raise PreregistrationError("mapped_journal_incomplete_duplicate_or_post_summary_event")
    entries, previous = [], "0" * 64
    for seq, (line, (event, cid)) in enumerate(zip(lines, expected), 1):
        row = json_mapping(line, "mapped journal entry")
        mapping(row, "mapped journal entry", KEYS)
        integer(row["seq"], "mapped journal sequence", minimum=1)
        sha256(row["previous_sha256"], "mapped previous entry")
        sha256(row["entry_sha256"], "mapped entry")
        if (row["schema_version"] != SCHEMA or row["seq"] != seq or row["event"] != event
                or row["previous_sha256"] != previous
                or row["entry_sha256"] != canonical_digest({key: row[key] for key in KEYS - {"entry_sha256"}})):
            raise PreregistrationError("mapped_journal_chain_or_order_mismatch")
        payload = row["payload"]
        if event == "mapped_recording_started":
            mapping(payload, "mapped recording anchor", {"case_ids", "request_sha256", "lock_digest",
                "snapshot_sha256", "snapshot"})
            if payload["case_ids"] != case_ids:
                raise PreregistrationError("mapped_journal_frozen_roster_mismatch")
            for name in ("request_sha256", "lock_digest", "snapshot_sha256"):
                sha256(payload[name], name)
            artifact_ref(payload["snapshot"], present=True)
        elif event == "mapped_review_disposed":
            mapping(payload, "mapped review disposition", {"case_id", "raw_review", "validation"})
            artifact_ref(payload["raw_review"])
            artifact_ref(payload["validation"], present=True)
        elif event == "mapped_case_adjudicated":
            mapping(payload, "mapped adjudicated row", {"case_id", "row"})
            artifact_ref(payload["row"], present=True)
        else:
            mapping(payload, "mapped summary", {"report"})
            artifact_ref(payload["report"], present=True)
        if cid is not None and payload["case_id"] != cid:
            raise PreregistrationError("mapped_journal_case_order_or_identity_mismatch")
        entries.append(row)
        previous = row["entry_sha256"]
    return tuple(entries)
