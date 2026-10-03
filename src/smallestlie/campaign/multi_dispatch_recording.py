"""Full-roster multi-dispatch recording and fresh GET-only re-verification.

J is independently addressed by its externally supplied raw digest. Neither
J's hash chain nor its artifact store can supply an observation/review grant.
No launch, subprocess, legacy ledger append or authority discovery occurs.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
import os
from pathlib import Path
import stat
from typing import Mapping

from smallestlie.adjudication.engine import AdjudicationError
from smallestlie.adjudication.multi_dispatch_engine import MultiDispatchAdjudicationReport, adjudicate_multi_dispatch_campaign
from smallestlie.attacks.adjudication import sha256
from smallestlie.campaign.lifecycle import ArtifactStore, _mkdir, _plain_path, _sync_directory, encoded
from smallestlie.campaign.preregistration import PreparedRun, PreregistrationError, digest
from smallestlie.campaign.multi_dispatch_sources import EcMultiDispatchSourceMapAuthority
from smallestlie.ledger.multi_dispatch_recording import journal_entry, read_multi_dispatch_journal


@dataclass(frozen=True)
class MultiDispatchRecording:
    journal_sha256: str
    report: MultiDispatchAdjudicationReport


def _payloads(report, reviews):
    snapshot = report.snapshot
    items = [("multi_dispatch_recording_started", {
        "case_ids": [item.case_id for item in report.cases],
        "request_sha256": snapshot.request_sha256, "lock_digest": snapshot.lock_digest,
        "plan_sha256": snapshot.plan_sha256, "session_sha256": snapshot.session_sha256,
        "snapshot_sha256": snapshot.validation_sha256,
        "snapshot": ArtifactStore.reference(encoded(asdict(snapshot)))})]
    artifacts = [encoded(asdict(snapshot))]
    for row in report.cases:
        raw = reviews.get(row.case_id)
        validation, data = encoded(asdict(row.review)), encoded(row.to_dict())
        artifacts.extend([raw, validation, data])
        items.extend([
            ("multi_dispatch_review_disposed", {"case_id": row.case_id,
                "raw_review": ArtifactStore.reference(raw), "validation": ArtifactStore.reference(validation)}),
            ("multi_dispatch_case_adjudicated", {"case_id": row.case_id, "row": ArtifactStore.reference(data)})])
    data = encoded(report.to_dict())
    artifacts.append(data)
    items.append(("multi_dispatch_summary", {"report": ArtifactStore.reference(data)}))
    return items, artifacts


def _journal(items):
    entries, previous = [], "0" * 64
    for seq, (event, payload) in enumerate(items, 1):
        row = journal_entry(seq, event, payload, previous)
        entries.append(row)
        previous = row["entry_sha256"]
    return b"".join(encoded(row) + b"\n" for row in entries)


def record_multi_dispatch_adjudication(root: str | Path, prepared: PreparedRun,
                               reviews: Mapping[str, bytes | None], *,
                               source_authority: EcMultiDispatchSourceMapAuthority,
                               review_authority=None) -> MultiDispatchRecording:
    """Compute all rows before creating a fresh single-writer follow-up root.

    Refuse any existing root, including an interrupted prior recording. Each
    artifact is synchronized and read back before the complete journal is
    synchronized. Windows storage durability still requires external adoption.
    """
    root = Path(root).absolute()
    _plain_path(root)
    if root.exists():
        raise PreregistrationError("multi_dispatch_recording_requires_fresh_root")
    # Capture caller bytes once; no custom mapping can switch reviews after
    # adjudication but before raw artifact persistence.
    if not isinstance(reviews, Mapping):
        raise AdjudicationError("multi_dispatch_reviews_require_raw_bytes_or_missing")
    reviews = dict(reviews)
    report = adjudicate_multi_dispatch_campaign(prepared, reviews,
        source_authority=source_authority, review_authority=review_authority)
    items, artifacts = _payloads(report, reviews)
    data = _journal(items)
    ArtifactStore.reference(data)
    read_multi_dispatch_journal(data, [row.case_id for row in report.cases])
    _mkdir(root, exist_ok=False)
    store = ArtifactStore(root / "artifacts")
    for raw in artifacts:
        store.put(raw)
    path = root / "journal.jsonl"
    _plain_path(path)
    with path.open("xb") as fh:
        fh.write(data)
        fh.flush()
        os.fsync(fh.fileno())
    _sync_directory(root)
    if path.read_bytes() != data:
        raise PreregistrationError("multi_dispatch_journal_durable_readback_mismatch")
    return MultiDispatchRecording(digest(data), report)


def verify_multi_dispatch_recording(root: str | Path, prepared: PreparedRun, *, expected_journal_sha256: str,
                            source_authority: EcMultiDispatchSourceMapAuthority,
                            review_authority=None) -> MultiDispatchRecording:
    """Reacquire sources and compare every persisted artifact; never rerun work.

    The expected digest must come from the trusted caller's external J
    reference. Reading it from this journal or calculating it from the bundle
    is not evidence of original raw-journal identity/publication acceptance.
    """
    sha256(expected_journal_sha256, "external exact multi-dispatch journal digest")
    root = Path(root).absolute()
    path = root / "journal.jsonl"
    _plain_path(path)
    if not stat.S_ISREG(path.lstat().st_mode):
        raise PreregistrationError("multi_dispatch_journal_requires_regular_file")
    with path.open("rb") as fh:
        if not stat.S_ISREG(os.fstat(fh.fileno()).st_mode):
            raise PreregistrationError("multi_dispatch_journal_requires_regular_file")
        data = fh.read(10_000_001)
    if digest(data) != expected_journal_sha256:
        raise PreregistrationError("multi_dispatch_journal_external_raw_digest_mismatch")
    return _verify_raw_recording(data, prepared, ArtifactStore(root / "artifacts", create=False),
        expected_journal_sha256=expected_journal_sha256,
        source_authority=source_authority, review_authority=review_authority)


def _verify_raw_recording(data, prepared, store, *, expected_journal_sha256,
                          source_authority, review_authority=None):
    """Shared private core; public readers supply their independently read bytes."""
    sha256(expected_journal_sha256, "external exact multi-dispatch journal digest")
    if type(data) is not bytes:
        raise PreregistrationError("multi_dispatch_journal_requires_raw_bytes")
    ArtifactStore.reference(data)
    if digest(data) != expected_journal_sha256:
        raise PreregistrationError("multi_dispatch_journal_external_raw_digest_mismatch")
    ids = [case["case_id"] for case in prepared.lock()["cases"]]
    entries = read_multi_dispatch_journal(data, ids)
    reviews = {cid: store.read(entries[1 + index * 2]["payload"]["raw_review"]) for index, cid in enumerate(ids)}
    report = adjudicate_multi_dispatch_campaign(prepared, reviews,
        source_authority=source_authority, review_authority=review_authority)
    items, artifacts = _payloads(report, reviews)
    if data != _journal(items):
        raise PreregistrationError("multi_dispatch_recording_recomputed_journal_mismatch")
    # Check raw content too: an intact chain cannot make a missing/swapped
    # snapshot, raw review, validation, row or report file valid.
    for raw in artifacts:
        if store.read(ArtifactStore.reference(raw)) != raw:
            raise PreregistrationError("multi_dispatch_recording_recomputed_artifact_mismatch")
    return MultiDispatchRecording(expected_journal_sha256, report)
