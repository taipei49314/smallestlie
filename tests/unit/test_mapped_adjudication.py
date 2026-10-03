"""Offline mapped semantic approvals; no real human approval or W3 result."""

from dataclasses import asdict, replace
import json

import pytest

from m12_helpers import INDEX
from test_mapped_observations import plan, report_state
from test_source_map import assemble, drop_source, ec_context, make_map
from smallestlie.adjudication.engine import AdjudicationError
from smallestlie.adjudication.mapped_engine import SCHEMA, adjudicate_mapped_campaign
from smallestlie.adjudication.mapped_reviews import SCHEMA as REVIEW_SCHEMA, mapped_review_context
from smallestlie.adjudication.reviews import frozen_spec
from smallestlie.attacks.schema import AttackSchemaError
from smallestlie.campaign.lifecycle import encoded
from smallestlie.campaign.mapped_observations import read_mapped_observations
from smallestlie.campaign.mapped_review_source import GitHubMappedReviewAuthority, MappedPostRunReviewGrant
from smallestlie.campaign.preregistration import canonical_digest, case_binding, digest
from smallestlie.campaign.provenance import (
    GitHubGovernanceStore, GovernanceTrustRoot, HumanMergeApproval, ProvenanceError, RepositoryTrust,
)
from smallestlie.campaign.review_source import GitHubReviewAuthority, PostRunReviewGrant


def approve_reviews(ctx, *, mutate=None, review_commit=None):
    """Use actual configured GitHub store with synthetic independent API facts."""
    prepared = ctx["plan"]
    snapshot = read_mapped_observations(prepared, authority=ctx["authority"])
    assert snapshot is not None
    index = json.loads(prepared.asset(INDEX))
    source = index["sources"][0]
    repo = RepositoryTrust("example/reviews", 303, "main", frozenset({9}))
    reviews, grants, approvals = {}, [], []
    for cid, number, revision in (("D", 88, "c" * 40), ("C", 89, "7" * 40)):
        if cid == "D" and review_commit is not None:
            revision = review_commit
        binding = prepared.binding(cid)
        before, after = binding["arms"]["baseline"]["files"], binding["arms"]["attack"]["files"]
        twin = frozen_spec(prepared, cid)["adjudication"]["twin"]
        raw = {"schema_version": REVIEW_SCHEMA, "binding": case_binding(prepared.lock(), cid),
            "engine": prepared.lock()["engine"], "residual_index_sha256": prepared.lock()["residual_index_sha256"],
            "context": mapped_review_context(prepared, cid, snapshot),
            "source_reviews": [{"source_id": item["id"], "sha256": item["sha256"],
                "rationale": "Synthetic complete-source assessment."} for item in index["sources"]],
            "citations": [{"source_id": source["id"], "start_line": 1, "end_line": 1,
                "quote_sha256": digest(prepared.asset(source["path"]).splitlines(keepends=True)[0])}],
            "theater": {"status": "confirmed", "rationale": "Synthetic cheating shape.",
                "changed_paths": sorted(path for path in before.keys() | after.keys() if before.get(path) != after.get(path))},
            "scope": {"status": "in_scope", "rationale": "Synthetic reviewed scope."},
            "residual": {"status": "no_match_reviewed", "row_refs": [], "row_reviews": [],
                "rationale": "Synthetic complete-document residual decision."},
            "twin": {"status": "confirmed", "rationale": "Synthetic effective same bug/cheating near shape.",
                "contrast_sha256": digest(twin["contrast"].encode()), "finding_fingerprints": ["blocking"]} if twin else None}
        if mutate:
            mutate(cid, raw)
        data, path = encoded(raw), f"mapped/{cid}.json"
        ctx["api"].add(repo.full_name, 303, number, 9, revision, path, data)
        reviews[cid] = data
        grants.append(MappedPostRunReviewGrant(f"github-pr://{repo.full_name}/{number}/{path}",
            canonical_digest(prepared.request.payload()), prepared.lock()["lock_digest"], cid, digest(data),
            snapshot.validation_sha256, canonical_digest(raw["context"]), f"synthetic-mapped-semantic-approval:{cid}"))
        approvals.append(HumanMergeApproval(303, number, revision, 9, f"synthetic-review-human-merge:{cid}"))
    root = GovernanceTrustRoot(RepositoryTrust("example/product", 101, "main", frozenset({7})),
        RepositoryTrust("example/requests", 404, "main", frozenset({8})), tuple(approvals), reviews=repo)
    store = GitHubGovernanceStore(root, transport=ctx["api"])
    return {"ctx": ctx, "reviews": reviews, "grants": tuple(grants), "store": store,
            "review_authority": GitHubMappedReviewAuthority(store, grants=tuple(grants))}


@pytest.fixture
def reviewed(make_map):
    return approve_reviews(make_map(semantic=True))


def run(bundle, *, reviews=None, authority=None):
    ctx = bundle["ctx"]
    return adjudicate_mapped_campaign(ctx["plan"], bundle["reviews"] if reviews is None else reviews,
        source_authority=ctx["authority"],
        review_authority=bundle["review_authority"] if authority is None else authority)


def test_full_pair_reacquires_sources_and_preserves_findings_and_own_references(reviewed):
    ctx = reviewed["ctx"]
    calls = len(ctx["api"].calls)
    report = run(reviewed)
    result = report.to_dict()
    assert len(ctx["api"].calls) > calls
    assert result["schema_version"] == SCHEMA
    assert result["frozen_case_count"] == 2
    assert result["confirmed_defect_case_count"] == result["paired_defect_case_count"] == 1
    assert [row["verdict"] for row in result["cases"]] == ["confirmed_defect", "control_rejected"]
    assert result["cases"][1]["observation"]["verifier"]["findings"][0]["future_attachment"] == {"preserved": True}
    assert report.cases[0].review.provenance_ref == "c" * 40
    assert report.cases[1].review.provenance_ref == "7" * 40
    assert all(not row.review.reasons for row in report.cases)
    assert report.cases[0].review.context_sha256 == reviewed["grants"][0].context_sha256
    assert result["snapshot_sha256"] == canonical_digest(asdict(report.snapshot))
    assert run(reviewed, reviews=dict(reversed(list(reviewed["reviews"].items())))).to_dict() == result


@pytest.mark.parametrize("field", ["request_sha256", "lock_digest", "review_sha256", "snapshot_sha256", "context_sha256"])
def test_changed_exact_grant_cannot_lend_review(reviewed, field):
    grants = (replace(reviewed["grants"][0], **{field: "0" * 64}), reviewed["grants"][1])
    report = run(reviewed, authority=GitHubMappedReviewAuthority(reviewed["store"], grants=grants))
    assert report.cases[0].verdict == "unknown"
    assert report.to_dict()["paired_defect_case_count"] == 0


@pytest.mark.parametrize("damage", ["schema", "case", "snapshot", "sources", "own", "twin", "source_review", "quote", "row"])
def test_reapproved_raw_review_still_needs_full_actual_context_and_content(make_map, damage):
    def mutate(cid, raw):
        if cid != "D": return
        if damage == "schema": raw["schema_version"] = "smallestlie.case-review/v1"
        elif damage == "case": raw["binding"]["case_id"] = "C"
        elif damage == "snapshot": raw["context"]["snapshot_sha256"] = "0" * 64
        elif damage == "sources": raw["context"]["sources"]["actions"][0]["action_receipt_ref"] = "f" * 40
        elif damage == "own": raw["context"]["cases"]["D"]["verifier"]["accepted"] = False
        elif damage == "twin": raw["context"]["cases"].pop("C")
        elif damage == "source_review": raw["source_reviews"].pop()
        elif damage == "quote": raw["citations"][0]["quote_sha256"] = "0" * 64
        else: raw["residual"].update(status="matched_residual", row_refs=["not-frozen"], row_reviews=[])
    report = run(approve_reviews(make_map(semantic=True), mutate=mutate))
    assert report.cases[0].verdict == "unknown"
    assert report.cases[0].review.reasons


@pytest.mark.parametrize("damage", ["unmerged", "actor", "branch", "human", "request_role"])
def test_request_actor_or_missing_independent_merge_cannot_grant_semantics(reviewed, damage):
    store, ctx = reviewed["store"], reviewed["ctx"]
    pr = ctx["api"].prs["example/reviews", 88]
    if damage == "unmerged": pr["merged"] = False
    elif damage == "actor": pr["merged_by"]["id"] = 8
    elif damage == "branch": pr["base"]["ref"] = "feature"
    elif damage == "human":
        store = GitHubGovernanceStore(replace(store.root, human_approvals=store.root.human_approvals[1:]), transport=ctx["api"])
    else:
        with pytest.raises(ProvenanceError):
            GitHubMappedReviewAuthority(GitHubGovernanceStore(replace(store.root, reviews=None)), grants=reviewed["grants"])
        return
    assert run(reviewed, authority=GitHubMappedReviewAuthority(store, grants=reviewed["grants"])).cases[0].verdict == "unknown"


def test_legacy_review_registry_and_caller_verify_hook_do_not_supply_new_authority(reviewed):
    grants = tuple(PostRunReviewGrant(grant.reference, grant.request_sha256, grant.lock_digest, grant.case_id,
        grant.review_sha256, grant.context_sha256, grant.semantic_approval_ref) for grant in reviewed["grants"])
    old = GitHubReviewAuthority(reviewed["store"], grants=grants)
    assert run(reviewed, authority=old).cases[0].verdict == "unknown"
    with pytest.raises(ProvenanceError): GitHubMappedReviewAuthority(reviewed["store"], grants=grants)
    with pytest.raises(ProvenanceError):
        GitHubMappedReviewAuthority(reviewed["store"], grants=reviewed["grants"] + reviewed["grants"][:1])
    reviewed["review_authority"]._verify = lambda *args: pytest.fail("caller verify hook used")
    assert run(reviewed).cases[0].paired_headline


@pytest.mark.parametrize("role", ["anchor", "archive", "mapping", "action"])
def test_review_source_cannot_alias_any_observation_source(make_map, role):
    ctx = make_map(semantic=True)
    snapshot = read_mapped_observations(ctx["plan"], authority=ctx["authority"])
    revision = {"anchor": snapshot.prelaunch_anchor_ref, "archive": snapshot.final_archive_ref,
                "mapping": snapshot.mapping_evidence_ref, "action": snapshot.actions[-1].action_receipt_ref}[role]
    assert run(approve_reviews(ctx, review_commit=revision)).cases[0].verdict == "unknown"


def test_structural_source_rejection_cannot_borrow_constructed_snapshot_or_previous_pass(reviewed):
    ctx = reviewed["ctx"]
    previous = run(reviewed)
    ctx["authority"].verify = lambda *_: previous.snapshot
    ctx["authority"]._verify = lambda *_: previous.snapshot
    assert run(reviewed).cases[0].paired_headline
    ctx["authority"].grant = replace(ctx["authority"].grant, evidence_sha256="0" * 64)
    with pytest.raises(AdjudicationError, match="source_reacquisition"): run(reviewed)
    with pytest.raises(TypeError):
        adjudicate_mapped_campaign(ctx["plan"], reviewed["reviews"], snapshot=previous.snapshot,
                                  source_authority=ctx["authority"])


@pytest.mark.parametrize("missing", [("C", "runner_command", "attack"), ("C", "verifier_command", "attack"),
    ("C", "verifier_materialize", "baseline"), ("D", "runner_command", "twin")])
def test_control_cannot_borrow_parent_arm_or_fixture_identity(make_map, missing):
    ctx = make_map(semantic=True)
    drop_source(ctx, missing)
    report = run(approve_reviews(ctx))
    assert report.to_dict()["paired_defect_case_count"] == 0
    assert report.to_dict()["frozen_case_count"] == 2


def test_irrelevant_reviewed_finding_does_not_earn_headline(make_map):
    def mutate(cid, raw):
        if cid == "D": raw["twin"]["finding_fingerprints"] = ["unrelated"]
    report = run(approve_reviews(make_map(semantic=True), mutate=mutate))
    assert report.cases[0].verdict == "confirmed_defect"
    assert not report.cases[0].paired_headline


@pytest.mark.parametrize("status,row_id,expected", [
    ("matched_residual", "SPEC:SUBJECT_NORMALIZED:two-hop", "documented_residual"),
    ("reopened_closed", "THREATMODEL:5", "confirmed_defect"),
    ("unresolved", "THREATMODEL:108", "boundary"),
])
def test_reviewed_residual_reopened_row_and_boundary_have_separate_counts(make_map, status, row_id, expected):
    def mutate(cid, raw):
        if cid == "D":
            raw["residual"].update(status=status, row_refs=[row_id],
                row_reviews=[{"row_id": row_id, "rationale": "Synthetic case-specific coverage."}])
    result = run(approve_reviews(make_map(semantic=True), mutate=mutate)).to_dict()
    assert result["cases"][0]["verdict"] == expected
    assert result["paired_defect_case_count"] == (1 if expected == "confirmed_defect" else 0)
    assert result["frozen_case_count"] == 2


@pytest.mark.parametrize("role,state", [("baseline", "green"), ("attack", "red")])
def test_refuted_def_is_killed_before_missing_review_repair_or_twin(make_map, plan, role, state):
    ctx = make_map(semantic=True, mutate_native=report_state(plan, role, state))
    drop_source(ctx, ("D", "runner_command", "repair"))
    drop_source(ctx, ("D", "runner_command", "twin"))
    report = adjudicate_mapped_campaign(plan, {}, source_authority=ctx["authority"])
    assert report.cases[0].verdict == "killed_candidate"
    assert report.cases[0].review.reasons == ("mapped_post_run_review_missing",)
    assert report.to_dict()["frozen_case_count"] == 2


def test_missing_semantic_sources_and_reviews_keep_every_case_unknown(make_map):
    ctx = make_map(selected=set(), semantic=True)
    result = adjudicate_mapped_campaign(ctx["plan"], {}, source_authority=ctx["authority"]).to_dict()
    assert result["frozen_case_count"] == result["verdict_counts"]["unknown"] == 2
    assert result["paired_defect_case_count"] == 0


def test_raw_review_api_rejects_report_carriers_and_extra_cases(reviewed):
    with pytest.raises(AdjudicationError, match="raw_bytes"):
        run(reviewed, reviews={"D": run(reviewed)})
    with pytest.raises(AdjudicationError, match="undeclared"):
        run(reviewed, reviews={**reviewed["reviews"], "extra": b"{}"})


def test_content_schema_failure_remains_an_explicit_unknown_review_row(reviewed, monkeypatch):
    def broken_spec(*args): raise AttackSchemaError("synthetic invalid frozen spec")
    monkeypatch.setattr("smallestlie.adjudication.reviews.frozen_spec", broken_spec)
    report = run(reviewed)
    assert report.cases[0].verdict == "unknown"
    assert report.cases[0].review.reasons == ("synthetic invalid frozen spec",)
    assert report.to_dict()["frozen_case_count"] == 2
