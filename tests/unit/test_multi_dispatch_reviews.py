"""Exact independent multi-dispatch review registry; no actual human grants."""

from dataclasses import replace
import json

import pytest

from multi_dispatch_helpers import (
    approve_reviews, drop_source, ec_context, make_map, make_multi_map, multi_map_templates,
    native_multi, native_templates, plan, read,
)
from smallestlie.adjudication.multi_dispatch_engine import adjudicate_multi_dispatch_campaign
from smallestlie.adjudication.multi_dispatch_reviews import multi_dispatch_review_context, validate_multi_dispatch_case_review
from smallestlie.campaign.mapped_review_source import GitHubMappedReviewAuthority, MappedPostRunReviewGrant
from smallestlie.campaign.multi_dispatch_review_source import GitHubMultiDispatchReviewAuthority
from smallestlie.campaign.preregistration import canonical_digest
from smallestlie.campaign.provenance import GitHubGovernanceStore, ProvenanceError, RepositoryTrust


@pytest.fixture
def reviewed(native_multi):
    return approve_reviews(native_multi())


def run(bundle, authority=None):
    ctx = bundle["ctx"]
    return adjudicate_multi_dispatch_campaign(ctx["plan"], bundle["reviews"], source_authority=ctx["authority"],
        review_authority=bundle["review_authority"] if authority is None else authority)


@pytest.mark.parametrize("field", ["request_sha256", "lock_digest", "review_sha256", "snapshot_sha256", "context_sha256"])
def test_changed_exact_grant_cannot_lend_semantic_approval(reviewed, field):
    grants = (replace(reviewed["grants"][0], **{field: "0" * 64}), reviewed["grants"][1])
    authority = GitHubMultiDispatchReviewAuthority(reviewed["store"], grants=grants)
    report = run(reviewed, authority)
    assert report.cases[0].verdict == "unknown" and report.to_dict()["paired_defect_case_count"] == 0


@pytest.mark.parametrize("damage", ["schema", "case", "missing_slot", "roles", "own", "twin", "source_review", "quote", "row"])
def test_reapproved_raw_content_needs_exact_context_and_complete_source_review(native_multi, damage):
    def mutate(cid, raw):
        if cid != "D":
            return
        if damage == "schema": raw["schema_version"] = "smallestlie.mapped-case-review/v1"
        elif damage == "case": raw["binding"]["case_id"] = "C"
        elif damage == "missing_slot": raw["context"]["sources"]["actions"].pop()
        elif damage == "roles": raw["context"]["sources"]["roles"].pop()
        elif damage == "own": raw["context"]["cases"]["D"]["verifier"]["accepted"] = False
        elif damage == "twin": raw["context"]["cases"].pop("C")
        elif damage == "source_review": raw["source_reviews"].pop()
        elif damage == "quote": raw["citations"][0]["quote_sha256"] = "0" * 64
        else: raw["residual"].update(status="matched_residual", row_refs=["not-frozen"], row_reviews=[])
    report = run(approve_reviews(native_multi(), mutate=mutate))
    assert report.cases[0].verdict == "unknown" and report.cases[0].review.reasons


def test_unrelated_missing_slot_changes_full_context_and_invalidates_old_review(reviewed):
    ctx, previous = reviewed["ctx"], reviewed["snapshot"]
    before = multi_dispatch_review_context(ctx["plan"], "D", previous)
    drop_source(ctx, ("C", "runner_command", "repair"))
    after = multi_dispatch_review_context(ctx["plan"], "D", read(ctx))
    assert canonical_digest(before) != canonical_digest(after)
    assert run(reviewed).cases[0].verdict == "unknown"
    assert len(after["sources"]["actions"]) == len(before["sources"]["actions"])
    assert run(approve_reviews(ctx)).cases[0].verdict == "confirmed_defect"
    assert not run(approve_reviews(ctx)).cases[0].paired_headline


@pytest.mark.parametrize("role", ["anchor", "archive", "mapping", "configured_ec_source", "configured_receipt",
                                  "configured_admission", "recorded_receipt", "coordinator_claimed_receipt"])
def test_review_merge_cannot_alias_inputs_or_claims_including_missing_source(native_multi, role):
    ctx = native_multi()
    drop_source(ctx, ("C", "runner_command", "repair"))
    snapshot = read(ctx)
    match = next(item for item in snapshot.source_roles
        if item.role == role or item.role.endswith(":" + role) or item.role.startswith(role + ":"))
    assert match.commit is not None
    report = run(approve_reviews(ctx, review_commit=match.commit))
    assert report.cases[0].verdict == "unknown" and report.cases[0].review.provenance_ref is None


@pytest.mark.parametrize("damage", ["unmerged", "actor", "human", "changed_blob"])
def test_account_membership_and_framework_merge_do_not_create_review_approval(reviewed, damage):
    store, ctx = reviewed["store"], reviewed["ctx"]
    if damage == "unmerged": ctx["api"].prs["example/reviews", 88]["merged"] = False
    elif damage == "actor": ctx["api"].prs["example/reviews", 88]["merged_by"]["id"] = 8
    elif damage == "human":
        store = GitHubGovernanceStore(replace(store.root, human_approvals=store.root.human_approvals[1:]), transport=ctx["api"])
    else:
        ctx["api"].files["example/reviews", 88, 1][0]["sha"] = "0" * 40
    report = run(reviewed, GitHubMultiDispatchReviewAuthority(store, grants=reviewed["grants"]))
    assert report.cases[0].verdict == "unknown"


def test_review_fresh_store_ignores_instance_hooks_and_rechecks_original_merge(reviewed):
    store, ctx = reviewed["store"], reviewed["ctx"]
    for name in ("approved_blob", "_merged", "_blob_at"):
        setattr(store, name, lambda *_args, **_kwargs: pytest.fail("caller governance hook used"))
    reviewed["review_authority"]._verify = lambda *_args: pytest.fail("caller review hook used")
    ctx["api"].calls.clear()
    assert run(reviewed).cases[0].paired_headline
    assert ("pr", "example/reviews", 88) in ctx["api"].calls
    ctx["api"].prs["example/reviews", 88]["merged"] = False
    assert run(reviewed).cases[0].verdict == "unknown"


@pytest.mark.parametrize("role,alias", [("requests", "name"), ("requests", "id"), ("ec", "name"), ("ec", "id")])
def test_review_repository_role_is_independent_by_name_and_numeric_id(reviewed, role, alias):
    store, ctx = reviewed["store"], reviewed["ctx"]
    reference = store.root.requests if role == "requests" else RepositoryTrust(
        ctx["root"].repository, ctx["root"].repository_id, "main", frozenset({8}))
    if role == "requests":
        requests = replace(store.root.requests, full_name=store.root.reviews.full_name.upper()) if alias == "name" else replace(
            store.root.requests, repository_id=store.root.reviews.repository_id)
        root = replace(store.root, requests=requests)
        with pytest.raises(ProvenanceError, match="independent repository"):
            GitHubMultiDispatchReviewAuthority(GitHubGovernanceStore(root, transport=ctx["api"]), grants=reviewed["grants"])
    else:
        # Configure a coherent original review repository then let the EC role
        # exclusion, rather than grant-reference mismatch, reject it.
        name = reference.full_name if alias == "name" else store.root.reviews.full_name
        rid = reference.repository_id if alias == "id" else store.root.reviews.repository_id
        repo = replace(store.root.reviews, full_name=name, repository_id=rid)
        approvals = tuple(replace(item, repository_id=rid) for item in store.root.human_approvals)
        grants = tuple(replace(item, reference=item.reference.replace("example/reviews", name)) for item in reviewed["grants"])
        for cid, number, revision in (("D", 88, "c" * 40), ("C", 89, "7" * 40)):
            ctx["api"].add(name, rid, number, 9, revision, f"multi-dispatch/{cid}.json", reviewed["reviews"][cid])
        root = replace(store.root, reviews=repo, human_approvals=approvals)
        authority = GitHubMultiDispatchReviewAuthority(GitHubGovernanceStore(root, transport=ctx["api"]), grants=grants)
        assert run(reviewed, authority).cases[0].verdict == "unknown"


def test_old_registry_envelope_and_duplicate_grants_are_rejected(reviewed):
    old = tuple(MappedPostRunReviewGrant(**item.__dict__) for item in reviewed["grants"])
    assert run(reviewed, GitHubMappedReviewAuthority(reviewed["store"], grants=old)).cases[0].verdict == "unknown"
    with pytest.raises(ProvenanceError):
        GitHubMultiDispatchReviewAuthority(reviewed["store"], grants=old)
    with pytest.raises(ProvenanceError):
        GitHubMultiDispatchReviewAuthority(reviewed["store"], grants=reviewed["grants"] + reviewed["grants"][:1])


def test_opaque_source_acceptance_is_not_an_independent_semantic_grant(reviewed):
    grant = replace(reviewed["grants"][0], semantic_approval_ref=reviewed["snapshot"].acceptance_refs[0])
    authority = GitHubMultiDispatchReviewAuthority(reviewed["store"], grants=(grant, reviewed["grants"][1]))
    assert run(reviewed, authority).cases[0].verdict == "unknown"
