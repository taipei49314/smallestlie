"""Exact review identity for the independent multi-dispatch consumer."""

from __future__ import annotations

from dataclasses import asdict, dataclass
import json

from smallestlie.adjudication.reviews import review_content
from smallestlie.attacks.adjudication import mapping
from smallestlie.attacks.schema import AttackSchemaError
from smallestlie.campaign.multi_dispatch_observations import MultiDispatchObservationSnapshot
from smallestlie.campaign.preregistration import (
    PreparedRun, PreregistrationError, canonical_digest, case_binding, digest, json_mapping,
)

SCHEMA = "smallestlie.multi-dispatch-case-review/v1"
CONTENT_KEYS = {"source_reviews", "citations", "theater", "scope", "residual", "twin"}


def multi_dispatch_review_context(prepared: PreparedRun, case_id: str,
                                  snapshot: MultiDispatchObservationSnapshot) -> dict:
    """Describe all source roles and own/twin semantics; confer no authority."""
    if type(snapshot) is not MultiDispatchObservationSnapshot:
        raise PreregistrationError("exact_multi_dispatch_snapshot_required")
    twin_id = prepared.binding(case_id)["twin_case_id"]
    linked = [case_id] + ([twin_id] if twin_id else [])
    cases = {item.case_id: item for item in snapshot.cases}
    return {"snapshot_sha256": snapshot.validation_sha256,
        "request_sha256": snapshot.request_sha256, "lock_digest": snapshot.lock_digest,
        "plan_sha256": snapshot.plan_sha256, "session_sha256": snapshot.session_sha256,
        "index_sha256": snapshot.index_sha256, "ledger_sha256": snapshot.ledger_sha256,
        "sources": {"archive_dispatch": json.loads(snapshot.archive_dispatch_json),
            "anchor": snapshot.prelaunch_anchor_ref, "archive": snapshot.final_archive_ref,
            "mapping": snapshot.mapping_evidence_ref, "mapping_sha256": snapshot.mapping_sha256,
            "archive_index_sha256": snapshot.archive_index_sha256,
            "coordinator_journal_sha256": snapshot.coordinator_journal_sha256,
            "contracts": json.loads(snapshot.source_contract_json),
            "roles": [asdict(item) for item in snapshot.source_roles],
            "acceptance_refs": list(snapshot.acceptance_refs),
            "actions": [asdict(item) for item in snapshot.actions]},
        "cases": {cid: asdict(cases[cid]) for cid in linked}}


@dataclass(frozen=True)
class MultiDispatchCaseReview:
    case_id: str
    review_sha256: str | None
    context_sha256: str
    provenance_ref: str | None
    semantic_approval_ref: str | None
    theater: str | None
    scope: str | None
    residual: str | None
    row_refs: tuple[str, ...]
    twin_relation: str | None
    twin_fingerprints: tuple[str, ...]
    reasons: tuple[str, ...]


def validate_multi_dispatch_case_review(prepared: PreparedRun, case_id: str,
        review_bytes: bytes | None, snapshot: MultiDispatchObservationSnapshot, *, authority) -> MultiDispatchCaseReview:
    """Check raw review content. Formal entry points reacquire their own snapshot."""
    from smallestlie.campaign.multi_dispatch_review_source import GitHubMultiDispatchReviewAuthority

    context = multi_dispatch_review_context(prepared, case_id, snapshot)
    context_sha = canonical_digest(context)
    review_sha = digest(review_bytes) if type(review_bytes) is bytes else None
    try:
        if review_sha is None:
            raise PreregistrationError("multi_dispatch_post_run_review_missing")
        raw = json_mapping(review_bytes, "multi-dispatch case review")
        mapping(raw, "multi-dispatch case review", CONTENT_KEYS | {
            "schema_version", "binding", "engine", "residual_index_sha256", "context"})
        lock = prepared.lock()
        expected = {"schema_version": SCHEMA, "binding": case_binding(lock, case_id),
            "engine": lock["engine"], "residual_index_sha256": lock["residual_index_sha256"], "context": context}
        if canonical_digest({key: raw[key] for key in expected}) != canonical_digest(expected):
            raise PreregistrationError("multi_dispatch_review_identity_or_observation_mismatch")
        if type(authority) is not GitHubMultiDispatchReviewAuthority:
            raise PreregistrationError("configured_multi_dispatch_review_authority_required")
        approved = GitHubMultiDispatchReviewAuthority._verify(authority, prepared, case_id, review_sha, context)
        if approved is None:
            raise PreregistrationError("multi_dispatch_independent_exact_semantic_review_missing")
        return MultiDispatchCaseReview(case_id, review_sha, context_sha, approved.immutable_ref,
            approved.semantic_approval_ref, *review_content(prepared, case_id, raw, lock=lock), ())
    except (ValueError, TypeError, KeyError, OSError, StopIteration, AttributeError, AttackSchemaError) as exc:
        return MultiDispatchCaseReview(case_id, review_sha, context_sha, None, None,
                                       None, None, None, (), None, (), (str(exc),))
