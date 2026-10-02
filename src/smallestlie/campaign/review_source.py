"""Exact, independently approved post-run semantic review bytes.

A request approval or an allowed GitHub account is not a semantic review grant.
The trusted caller supplies a distinct review role and exact post-run grants.
"""

from __future__ import annotations

from dataclasses import dataclass

from smallestlie.adjudication.reviews import TrustedReviewEnvelope
from smallestlie.attacks.adjudication import sha256, string
from smallestlie.campaign.preregistration import PreparedRun, canonical_digest, case_binding, json_mapping
from smallestlie.campaign.provenance import (
    GitHubGovernanceStore, GovernanceReference, ProvenanceError,
)


@dataclass(frozen=True)
class PostRunReviewGrant:
    reference: str
    request_sha256: str
    lock_digest: str
    case_id: str
    review_sha256: str
    observations_sha256: str
    semantic_approval_ref: str

    def __post_init__(self) -> None:
        GovernanceReference.parse(self.reference)
        for key in ("request_sha256", "lock_digest", "review_sha256", "observations_sha256"):
            sha256(getattr(self, key), key)
        string(self.case_id, "reviewed case")
        string(self.semantic_approval_ref, "independent exact semantic approval")


class GitHubReviewAuthority:
    def __init__(self, store: GitHubGovernanceStore, *, grants: tuple[PostRunReviewGrant, ...]):
        if not isinstance(store, GitHubGovernanceStore) or store.root.reviews is None:
            raise ProvenanceError("independent review repository/account role required")
        if (type(grants) is not tuple or not grants
                or any(not isinstance(grant, PostRunReviewGrant) for grant in grants)):
            raise ProvenanceError("independent exact post-run semantic grants required")
        identities = [(grant.request_sha256, grant.lock_digest, grant.case_id) for grant in grants]
        if len(identities) != len(set(identities)):
            raise ProvenanceError("ambiguous semantic review registry")
        if any(GovernanceReference.parse(grant.reference).repository != store.root.reviews.full_name
               for grant in grants):
            raise ProvenanceError("semantic review grant outside approved review role")
        self.store, self.grants = store, grants

    def verify(self, prepared: PreparedRun, case_id: str, review_sha256: str) -> TrustedReviewEnvelope | None:
        try:
            binding = case_binding(prepared.lock(), case_id)
            request_sha = canonical_digest(prepared.request.payload())
            grant = next((item for item in self.grants if item.request_sha256 == request_sha
                          and item.lock_digest == prepared.lock()["lock_digest"] and item.case_id == case_id), None)
            if grant is None or grant.review_sha256 != review_sha256:
                raise ProvenanceError("exact post-run review not independently approved")
            blob = self.store.approved_blob(grant.reference, role="review")
            raw = json_mapping(blob.data, "approved post-run review")
            if (blob.sha256 != grant.review_sha256 or raw.get("schema_version") != "smallestlie.case-review/v1"
                    or raw.get("binding") != binding or raw.get("engine") != prepared.lock()["engine"]
                    or raw.get("residual_index_sha256") != prepared.lock()["residual_index_sha256"]
                    or not isinstance(raw.get("observations"), dict)
                    or canonical_digest(raw["observations"]) != grant.observations_sha256):
                raise ProvenanceError("approved semantic review binding/observations mismatch")
            # validate_case_review separately checks the actual observations,
            # complete pinned documents, citations, residual coverage and twin.
            return TrustedReviewEnvelope("github-post-run-review/v1", blob.merge_commit,
                                         canonical_digest(binding), blob.sha256)
        except (ValueError, TypeError, KeyError, OSError):
            return None
