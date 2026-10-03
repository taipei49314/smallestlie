"""Independent raw GitHub review reader for multi-dispatch semantics.

The trusted integration supplies human and semantic grants outside every
recording. Reviews use a repository distinct from product, request and EC roles.
Original changed blobs are reacquired on every verification; instance overrides
and old schemas/envelopes cannot approve this consumer.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass

from smallestlie.adjudication.multi_dispatch_reviews import SCHEMA
from smallestlie.attacks.adjudication import sha256, string
from smallestlie.campaign.preregistration import PreparedRun, canonical_digest, case_binding, json_mapping
from smallestlie.campaign.provenance import (
    GitHubGovernanceStore, GovernanceReference, GovernanceTrustRoot, HumanMergeApproval,
    ProvenanceError, RepositoryTrust,
)


@dataclass(frozen=True)
class MultiDispatchPostRunReviewGrant:
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
        string(self.case_id, "multi-dispatch reviewed case")
        string(self.semantic_approval_ref, "independent exact multi-dispatch semantic approval")


@dataclass(frozen=True)
class _ApprovedReview:
    immutable_ref: str
    semantic_approval_ref: str


def _fresh_governance_store(store):
    if type(store) is not GitHubGovernanceStore or type(store.root) is not GovernanceTrustRoot:
        raise ProvenanceError("exact independent multi-dispatch governance store required")
    root = store.root
    if (any(type(item) is not RepositoryTrust for item in (root.product, root.requests, root.reviews))
            or type(root.human_approvals) is not tuple
            or any(type(item) is not HumanMergeApproval for item in root.human_approvals)):
        raise ProvenanceError("exact repository roles and human grants required")
    # Reconstruct immutable configuration and use class implementations on a
    # fresh store. The explicitly configured external transport remains trusted.
    product, requests, reviews = (RepositoryTrust(**asdict(item))
                                  for item in (root.product, root.requests, root.reviews))
    if (reviews.full_name.casefold() in {product.full_name.casefold(), requests.full_name.casefold()}
            or reviews.repository_id in {product.repository_id, requests.repository_id}):
        raise ProvenanceError("multi-dispatch reviews require an independent repository role")
    fresh = GovernanceTrustRoot(product, requests,
        tuple(HumanMergeApproval(**asdict(item)) for item in root.human_approvals), reviews)
    return GitHubGovernanceStore(fresh, transport=store.transport)


def _independent_sources(store, grant, blob, context):
    sources, trust = context["sources"], store.root.reviews
    roles, archive_dispatch = sources["roles"], sources["archive_dispatch"]
    if (trust.full_name.casefold() == archive_dispatch["repository"].casefold()
            or trust.repository_id == archive_dispatch["repository_id"]):
        raise ProvenanceError("review repository aliases EC archive role")
    product = next(item for item in roles if item["role"] == "product_source")
    if product["repository"].casefold() != store.root.product.full_name.casefold():
        raise ProvenanceError("review and source product trust roots differ")
    for role in roles:
        if ((role["repository"] is not None and role["repository"].casefold() == trust.full_name.casefold())
                or (role["repository_id"] is not None and role["repository_id"] == trust.repository_id)):
            raise ProvenanceError("review repository aliases a source/input role")
    revisions = {role["commit"] for role in roles if role["commit"] is not None}
    revisions.update(item.merge_commit for item in store.root.human_approvals
        if item.repository_id in {store.root.product.repository_id, store.root.requests.repository_id})
    if blob.merge_commit in revisions:
        raise ProvenanceError("review merge aliases a source/input/admission commit")
    refs = set(sources["acceptance_refs"])
    if (grant.reference in refs or grant.semantic_approval_ref in refs or blob.human_approval_ref in refs):
        raise ProvenanceError("source acceptance cannot supply independent review approval")


class GitHubMultiDispatchReviewAuthority:
    def __init__(self, store: GitHubGovernanceStore, *, grants: tuple[MultiDispatchPostRunReviewGrant, ...]):
        fresh = _fresh_governance_store(store)
        if (type(grants) is not tuple or not grants
                or any(type(grant) is not MultiDispatchPostRunReviewGrant for grant in grants)):
            raise ProvenanceError("independent exact multi-dispatch semantic grants required")
        identities = [(grant.request_sha256, grant.lock_digest, grant.case_id) for grant in grants]
        if len(set(identities)) != len(identities):
            raise ProvenanceError("ambiguous multi-dispatch semantic review registry")
        if any(GovernanceReference.parse(grant.reference).repository != fresh.root.reviews.full_name for grant in grants):
            raise ProvenanceError("multi-dispatch semantic grant outside approved review role")
        self.store, self.grants = store, grants

    def _verify(self, prepared: PreparedRun, case_id: str, review_sha256: str, context: dict) -> _ApprovedReview | None:
        try:
            fresh = _fresh_governance_store(self.store)
            if (type(self.grants) is not tuple or not self.grants
                    or any(type(item) is not MultiDispatchPostRunReviewGrant for item in self.grants)):
                raise ProvenanceError("exact multi-dispatch semantic registry required")
            grants = tuple(MultiDispatchPostRunReviewGrant(**asdict(item)) for item in self.grants)
            identities = [(item.request_sha256, item.lock_digest, item.case_id) for item in grants]
            if len(set(identities)) != len(identities):
                raise ProvenanceError("ambiguous multi-dispatch semantic registry")
            lock = prepared.lock()
            grant = next((item for item in grants
                if item.request_sha256 == canonical_digest(prepared.request.payload())
                and item.lock_digest == lock["lock_digest"] and item.case_id == case_id), None)
            if (grant is None or grant.review_sha256 != review_sha256
                    or grant.snapshot_sha256 != context["snapshot_sha256"]
                    or grant.context_sha256 != canonical_digest(context)
                    or GovernanceReference.parse(grant.reference).repository != fresh.root.reviews.full_name):
                raise ProvenanceError("exact multi-dispatch post-run review not independently approved")
            blob = GitHubGovernanceStore.approved_blob(fresh, grant.reference, role="review")
            raw = json_mapping(blob.data, "approved multi-dispatch review")
            expected = {"schema_version": SCHEMA, "binding": case_binding(lock, case_id),
                "engine": lock["engine"], "residual_index_sha256": lock["residual_index_sha256"], "context": context}
            if (blob.sha256 != review_sha256
                    or canonical_digest({key: raw[key] for key in expected}) != canonical_digest(expected)):
                raise ProvenanceError("approved multi-dispatch review binding/context mismatch")
            _independent_sources(fresh, grant, blob, context)
            return _ApprovedReview(blob.merge_commit, grant.semantic_approval_ref)
        except (ValueError, TypeError, KeyError, OSError, AttributeError, StopIteration):
            return None
