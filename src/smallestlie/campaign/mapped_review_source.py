"""Independent exact semantic grants for the new mapped review schema.

The registry is supplied by the trusted integration, never discovered in a
review, request or recording bundle. No legacy review envelope is produced.
"""

from __future__ import annotations

from dataclasses import dataclass

from smallestlie.adjudication.mapped_reviews import SCHEMA
from smallestlie.attacks.adjudication import sha256, string
from smallestlie.campaign.preregistration import PreparedRun, canonical_digest, case_binding, json_mapping
from smallestlie.campaign.provenance import GitHubGovernanceStore, GovernanceReference, ProvenanceError


@dataclass(frozen=True)
class MappedPostRunReviewGrant:
    reference: str
    request_sha256: str
    lock_digest: str
    case_id: str
    review_sha256: str
    snapshot_sha256: str
    context_sha256: str
    semantic_approval_ref: str

    def __post_init__(self):
        GovernanceReference.parse(self.reference)
        for name in ("request_sha256", "lock_digest", "review_sha256", "snapshot_sha256", "context_sha256"):
            sha256(getattr(self, name), name)
        string(self.case_id, "mapped reviewed case")
        string(self.semantic_approval_ref, "independent exact mapped semantic approval")


@dataclass(frozen=True)
class _ApprovedReview:
    immutable_ref: str
    semantic_approval_ref: str


class GitHubMappedReviewAuthority:
    def __init__(self, store: GitHubGovernanceStore, *, grants: tuple[MappedPostRunReviewGrant, ...]):
        if type(store) is not GitHubGovernanceStore or store.root.reviews is None:
            raise ProvenanceError("independent mapped review repository/account role required")
        if (type(grants) is not tuple or not grants
                or any(type(grant) is not MappedPostRunReviewGrant for grant in grants)):
            raise ProvenanceError("independent exact mapped semantic grants required")
        identities = [(grant.request_sha256, grant.lock_digest, grant.case_id) for grant in grants]
        if len(set(identities)) != len(identities):
            raise ProvenanceError("ambiguous mapped semantic review registry")
        if any(GovernanceReference.parse(grant.reference).repository != store.root.reviews.full_name for grant in grants):
            raise ProvenanceError("mapped semantic grant outside approved review role")
        self.store, self.grants = store, grants

    def _verify(self, prepared: PreparedRun, case_id: str, review_sha256: str, context: dict) -> _ApprovedReview | None:
        try:
            lock = prepared.lock()
            grant = next((item for item in self.grants
                          if item.request_sha256 == canonical_digest(prepared.request.payload())
                          and item.lock_digest == lock["lock_digest"] and item.case_id == case_id), None)
            if (grant is None or grant.review_sha256 != review_sha256
                    or grant.snapshot_sha256 != context["snapshot_sha256"]
                    or grant.context_sha256 != canonical_digest(context)):
                raise ProvenanceError("exact mapped post-run review not independently approved")
            blob = GitHubGovernanceStore.approved_blob(self.store, grant.reference, role="review")
            raw = json_mapping(blob.data, "approved mapped review")
            expected = {"schema_version": SCHEMA, "binding": case_binding(lock, case_id),
                        "engine": lock["engine"], "residual_index_sha256": lock["residual_index_sha256"],
                        "context": context}
            if (blob.sha256 != review_sha256
                    or canonical_digest({key: raw[key] for key in expected}) != canonical_digest(expected)):
                raise ProvenanceError("approved mapped review binding/context mismatch")
            sources = context["sources"]
            action_refs = {action["action_receipt_ref"] for action in sources["actions"]}
            if blob.merge_commit in action_refs | {sources["anchor"], sources["archive"], sources["mapping"]}:
                raise ProvenanceError("mapped review must be independent of observation sources")
            return _ApprovedReview(blob.merge_commit, grant.semantic_approval_ref)
        except (ValueError, TypeError, KeyError, OSError, AttributeError):
            return None
