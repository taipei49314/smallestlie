"""Versioned review identity for independently reacquired mapped observations."""

from __future__ import annotations

from dataclasses import asdict, dataclass

from smallestlie.adjudication.reviews import review_content
from smallestlie.attacks.adjudication import mapping
from smallestlie.attacks.schema import AttackSchemaError
from smallestlie.campaign.mapped_observations import MappedObservationSnapshot
from smallestlie.campaign.preregistration import (
    PreparedRun, PreregistrationError, canonical_digest, case_binding, digest, json_mapping,
)

SCHEMA = "smallestlie.mapped-case-review/v1"
CONTENT_KEYS = {"source_reviews", "citations", "theater", "scope", "residual", "twin"}


def mapped_review_context(prepared: PreparedRun, case_id: str, snapshot: MappedObservationSnapshot) -> dict:
    """Describe review input; constructing this dictionary grants no authority."""
    twin_id = prepared.binding(case_id)["twin_case_id"]
    linked = [case_id] + ([twin_id] if twin_id else [])
    cases = {item.case_id: item for item in snapshot.cases}
    return {"snapshot_sha256": snapshot.validation_sha256,
            "request_sha256": snapshot.request_sha256, "lock_digest": snapshot.lock_digest,
            "plan_sha256": snapshot.plan_sha256, "index_sha256": snapshot.index_sha256,
            "sources": {"anchor": snapshot.prelaunch_anchor_ref, "archive": snapshot.final_archive_ref,
                        "mapping": snapshot.mapping_evidence_ref, "mapping_sha256": snapshot.mapping_sha256,
                        "mapping_acceptance_ref": snapshot.mapping_acceptance_ref,
                        "actions": [asdict(item) for item in snapshot.actions]},
            "cases": {cid: asdict(cases[cid]) for cid in linked}}


@dataclass(frozen=True)
class MappedCaseReview:
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


def validate_mapped_case_review(prepared: PreparedRun, case_id: str, review_bytes: bytes | None,
                                snapshot: MappedObservationSnapshot, *, authority) -> MappedCaseReview:
    """A content check only; formal consumers obtain their own snapshot first."""
    # Local import keeps the provider/type dependencies separate from v1.
    from smallestlie.campaign.mapped_review_source import GitHubMappedReviewAuthority

    context = mapped_review_context(prepared, case_id, snapshot)
    context_sha = canonical_digest(context)
    review_sha = digest(review_bytes) if type(review_bytes) is bytes else None
    try:
        if review_sha is None:
            raise PreregistrationError("mapped_post_run_review_missing")
        raw = json_mapping(review_bytes, "mapped case review")
        mapping(raw, "mapped case review", CONTENT_KEYS | {
            "schema_version", "binding", "engine", "residual_index_sha256", "context"})
        lock = prepared.lock()
        expected = {"schema_version": SCHEMA, "binding": case_binding(lock, case_id),
                    "engine": lock["engine"], "residual_index_sha256": lock["residual_index_sha256"],
                    "context": context}
        if canonical_digest({key: raw[key] for key in expected}) != canonical_digest(expected):
            raise PreregistrationError("mapped_review_identity_or_observation_mismatch")
        if type(authority) is not GitHubMappedReviewAuthority:
            raise PreregistrationError("configured_mapped_review_authority_required")
        approved = GitHubMappedReviewAuthority._verify(authority, prepared, case_id, review_sha, context)
        if approved is None:
            raise PreregistrationError("mapped_independent_exact_semantic_review_missing")
        return MappedCaseReview(case_id, review_sha, context_sha, approved.immutable_ref,
                                approved.semantic_approval_ref, *review_content(prepared, case_id, raw, lock=lock), ())
    except (ValueError, TypeError, KeyError, OSError, StopIteration, AttributeError, AttackSchemaError) as exc:
        return MappedCaseReview(case_id, review_sha, context_sha, None, None,
                                None, None, None, (), None, (), (str(exc),))
