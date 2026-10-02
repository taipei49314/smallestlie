"""Synthetic exact semantic approval; no human or formal approval is minted."""

from dataclasses import replace
import json

import pytest

from m12_helpers import encoded
from test_adjudication import add_reviews
from test_evidence_sources import ctx, plan  # pytest fixtures, synthetic API only
from smallestlie.adjudication.engine import CaseInputs, adjudicate_campaign
from smallestlie.campaign.evidence_sources import EcExecutionAuthority, EcVerifierAuthority
from smallestlie.campaign.preregistration import canonical_digest, digest
from smallestlie.campaign.provenance import (
    GitHubGovernanceStore, GovernanceTrustRoot, HumanMergeApproval, ProvenanceError, RepositoryTrust,
)
from smallestlie.campaign.review_source import GitHubReviewAuthority, PostRunReviewGrant


@pytest.fixture
def reviews(ctx):
    items, grants, approvals = {}, [], []
    for cid in ("D", "C"):
        row = next(row for row in ctx["supervisor"]["cases"] if row["binding"]["case_id"] == cid)
        receipt = ctx["files"][row["runner"]["receipt"]["path"]]
        raw = json.loads(receipt)
        artifacts = {ref["path"]: ctx["files"][ref["path"]] for arm in raw["arms"].values()
                     for ref in (arm["stdout"], arm["stderr"], arm["report"])}
        captured = row["verifier"]
        items[cid] = CaseInputs(receipt, artifacts, *(ctx["files"][captured[key]["path"]]
            for key in ("metadata", "stdout", "stderr")))
    ra, va = EcExecutionAuthority(ctx["store"]), EcVerifierAuthority(ctx["store"])
    add_reviews(ctx["plan"], items, ra, va)
    repo = RepositoryTrust("example/reviews", 303, "main", frozenset({9}))
    for cid, number, revision in (("D", 88, "c" * 40), ("C", 89, "d" * 40)):
        data = items[cid].review
        raw = json.loads(data)
        path = f"reviews/{cid}.json"
        ctx["api"].add(repo.full_name, repo.repository_id, number, 9, revision, path, data)
        grants.append(PostRunReviewGrant(f"github-pr://{repo.full_name}/{number}/{path}",
            canonical_digest(ctx["plan"].request.payload()), ctx["plan"].lock()["lock_digest"], cid,
            digest(data), canonical_digest(raw["observations"]), f"synthetic-human-semantic-approval:{cid}"))
        approvals.append(HumanMergeApproval(repo.repository_id, number, revision, 9, f"synthetic-human-merge:{cid}"))
    root = GovernanceTrustRoot(RepositoryTrust("example/product", 101, "main", frozenset({7})),
        RepositoryTrust("example/requests", 404, "main", frozenset({8})), tuple(approvals), reviews=repo)
    store = GitHubGovernanceStore(root, transport=ctx["api"])
    return {"ctx": ctx, "items": items, "runner": ra, "verifier": va, "store": store, "grants": tuple(grants)}


def run(reviews, authority):
    return adjudicate_campaign(reviews["ctx"]["plan"], reviews["items"], runner_authority=reviews["runner"],
        verifier_authority=reviews["verifier"], review_authority=authority)


def test_two_pass_adjudication_with_independent_capture_and_semantic_sources(reviews):
    authority = GitHubReviewAuthority(reviews["store"], grants=reviews["grants"])
    report = run(reviews, authority).to_dict()
    assert report["paired_defect_case_count"] == 1
    assert report["frozen_case_count"] == 2
    assert report["cases"][0]["verdict"] == "confirmed_defect"
    assert report["cases"][1]["verdict"] == "control_rejected"
    assert report["cases"][0]["review"]["provenance_ref"] == "c" * 40
    reordered = {cid: reviews["items"][cid] for cid in ("C", "D")}
    reviews["items"] = reordered
    assert run(reviews, authority).to_dict() == report


@pytest.mark.parametrize("field,value", [("review_sha256", "0" * 64), ("request_sha256", "0" * 64),
    ("lock_digest", "0" * 64), ("case_id", "other"), ("observations_sha256", "0" * 64)])
def test_exact_semantic_grant_bound_to_actual_case_and_observations(reviews, field, value):
    grants = (replace(reviews["grants"][0], **{field: value}), reviews["grants"][1])
    authority = GitHubReviewAuthority(reviews["store"], grants=grants)
    report = run(reviews, authority).to_dict()
    assert report["paired_defect_case_count"] == 0
    assert report["cases"][0]["verdict"] == "unknown"


@pytest.mark.parametrize("damage", ["unmerged", "wrong_actor", "wrong_branch", "wrong_commit", "inherited", "missing_human"])
def test_github_user_or_request_role_cannot_supply_semantic_approval(reviews, damage):
    store = reviews["store"]
    api = reviews["ctx"]["api"]
    pr = api.prs["example/reviews", 88]
    if damage == "unmerged": pr["merged"] = False
    elif damage == "wrong_actor": pr["merged_by"]["id"] = 8
    elif damage == "wrong_branch": pr["base"]["ref"] = "feature"
    elif damage == "wrong_commit": pr["merge_commit_sha"] = "a" * 40
    elif damage == "inherited": api.files["example/reviews", 88, 1] = []
    else: store = GitHubGovernanceStore(replace(store.root, human_approvals=store.root.human_approvals[1:]), transport=api)
    assert run(reviews, GitHubReviewAuthority(store, grants=reviews["grants"])).to_dict()["paired_defect_case_count"] == 0


@pytest.mark.parametrize("field,value", [("engine", {}), ("residual_index_sha256", "0" * 64), ("binding", {}),
    ("observations", {}), ("schema_version", "smallestlie.case-review/v0")])
def test_approved_review_bytes_do_not_override_frozen_context(reviews, field, value):
    data = json.loads(reviews["items"]["D"].review)
    data[field] = value
    raw = encoded(data)
    reviews["ctx"]["api"].add("example/reviews", 303, 88, 9, "c" * 40, "reviews/D.json", raw)
    reviews["items"]["D"] = replace(reviews["items"]["D"], review=raw)
    grant = replace(reviews["grants"][0], review_sha256=digest(raw))
    authority = GitHubReviewAuthority(reviews["store"], grants=(grant, reviews["grants"][1]))
    assert run(reviews, authority).cases[0].verdict == "unknown"


def test_actual_observation_change_cannot_borrow_previous_semantic_decision(reviews):
    authority = GitHubReviewAuthority(reviews["store"], grants=reviews["grants"])
    reviews["items"]["C"] = replace(reviews["items"]["C"], verifier_stdout=b"{}")
    assert run(reviews, authority).to_dict()["paired_defect_case_count"] == 0


def test_no_implicit_review_role_semantic_grant_or_duplicate_registry(reviews):
    store, grants = reviews["store"], reviews["grants"]
    # Existing request governance, even with exact human merge registry, cannot
    # activate the review role or authorize post-run semantic coverage.
    root = replace(store.root, reviews=None, requests=store.root.reviews)
    with pytest.raises(ProvenanceError): GitHubReviewAuthority(GitHubGovernanceStore(root), grants=grants)
    with pytest.raises(ProvenanceError): GitHubReviewAuthority(store, grants=())
    with pytest.raises(ProvenanceError): GitHubReviewAuthority(store, grants=grants + grants[:1])
    with pytest.raises(ProvenanceError): GitHubReviewAuthority(store, grants=(
        replace(grants[0], reference="github-pr://example/product/88/reviews/D.json"),))
    with pytest.raises(ProvenanceError): replace(store.root, reviews=store.root.product)


def test_complete_source_review_and_citations_still_required_after_approval(reviews):
    raw = json.loads(reviews["items"]["D"].review)
    raw["source_reviews"].pop()
    data = encoded(raw)
    reviews["ctx"]["api"].add("example/reviews", 303, 88, 9, "c" * 40, "reviews/D.json", data)
    reviews["items"]["D"] = replace(reviews["items"]["D"], review=data)
    grants = (replace(reviews["grants"][0], review_sha256=digest(data)), reviews["grants"][1])
    row = run(reviews, GitHubReviewAuthority(reviews["store"], grants=grants)).cases[0]
    assert row.verdict == "unknown"
    assert "partial_index_absence_is_not_complete_source_review" in row.review.reasons
