"""Full rows, honest kills and qualified detectable twins from original sources."""

from dataclasses import asdict, replace
import json

import pytest

from multi_dispatch_helpers import (
    approve_reviews, case, drop_source, ec_context, make_map, make_multi_map, multi_map_templates,
    native_multi, native_templates, plan, read, report_state,
)
from smallestlie.adjudication.engine import AdjudicationError
from smallestlie.adjudication.multi_dispatch_engine import SCHEMA, adjudicate_multi_dispatch_campaign
from smallestlie.campaign.lifecycle import encoded
from smallestlie.campaign.preregistration import canonical_digest, digest


def run(bundle, *, reviews=None):
    ctx = bundle["ctx"]
    return adjudicate_multi_dispatch_campaign(ctx["plan"], bundle["reviews"] if reviews is None else reviews,
        source_authority=ctx["authority"], review_authority=bundle["review_authority"])


def test_full_pair_has_own_sources_full_rows_independent_reviews_and_separate_counts(native_multi):
    bundle = approve_reviews(native_multi())
    calls = len(bundle["ctx"]["api"].calls)
    report = run(bundle)
    result = report.to_dict()
    assert len(bundle["ctx"]["api"].calls) > calls
    assert result["schema_version"] == SCHEMA
    assert result["frozen_case_count"] == 2
    assert result["confirmed_defect_case_count"] == result["paired_defect_case_count"] == 1
    assert [row["verdict"] for row in result["cases"]] == ["confirmed_defect", "control_rejected"]
    assert result["cases"][1]["observation"]["verifier"]["findings"][0]["future_attachment"] == {"preserved": True}
    assert [row.review.provenance_ref for row in report.cases] == ["c" * 40, "7" * 40]
    assert all(not row.review.reasons for row in report.cases)
    assert result["snapshot_sha256"] == canonical_digest(asdict(report.snapshot))
    assert run(bundle, reviews=dict(reversed(list(bundle["reviews"].items())))).to_dict() == result


@pytest.mark.parametrize("missing", [("D", "runner_command", "twin"), ("C", "runner_command", "attack"),
    ("C", "runner_command", "repair"), ("C", "verifier_command", "attack"), ("C", "verifier_materialize", "baseline")])
def test_twin_qualification_requires_own_effectiveness_materialization_and_block(native_multi, missing):
    ctx = native_multi()
    drop_source(ctx, missing)
    result = run(approve_reviews(ctx)).to_dict()
    assert result["frozen_case_count"] == 2
    assert result["confirmed_defect_case_count"] == 1 and result["paired_defect_case_count"] == 0
    assert result["cases"][0]["verdict"] == "confirmed_defect"


@pytest.mark.parametrize("damage", ["rule", "path", "fingerprint", "allowlist"])
def test_unrelated_or_allowlisted_control_finding_is_not_headline_credit(native_multi, damage):
    def native(child):
        ticket, facts = child["ticket"], child["facts"]
        if (ticket.case_id, ticket.kind) != ("C", "verifier_command"):
            return
        ref = facts["outputs"]["stdout"]
        payload = json.loads(child["files"][ref["path"]])
        payload["findings"][0][{"allowlist": "allowlisted"}.get(damage, damage)] = (
            True if damage == "allowlist" else "unrelated" if damage != "path" else "tests/elsewhere.py")
        data = encoded(payload)
        child["files"][ref["path"]] = data
        ref["sha256"] = digest(data)
        meta = facts["outputs"]["metadata"]
        metadata = json.loads(child["files"][meta["path"]])
        metadata["stdout_sha256"] = digest(data)
        data = encoded(metadata)
        child["files"][meta["path"]] = data
        meta["sha256"] = digest(data)
    result = run(approve_reviews(native_multi(native_change=native))).to_dict()
    assert result["confirmed_defect_case_count"] == 1 and result["paired_defect_case_count"] == 0
    assert result["frozen_case_count"] == 2


@pytest.mark.parametrize("role,state", [("baseline", "green"), ("attack", "red")])
def test_real_DEF_refutation_precedes_missing_repair_twin_and_review(native_multi, plan, role, state):
    ctx = native_multi(native_change=report_state(plan, role, state))
    for arm in ("repair", "twin"):
        drop_source(ctx, ("D", "runner_command", arm))
    report = adjudicate_multi_dispatch_campaign(ctx["plan"], {}, source_authority=ctx["authority"])
    assert report.cases[0].verdict == "killed_candidate"
    assert report.cases[0].review.reasons
    assert report.to_dict()["frozen_case_count"] == 2
    assert report.to_dict()["paired_defect_case_count"] == 0


@pytest.mark.parametrize("status,row_id,expected", [
    ("matched_residual", "SPEC:SUBJECT_NORMALIZED:two-hop", "documented_residual"),
    ("reopened_closed", "THREATMODEL:5", "confirmed_defect"),
    ("unresolved", "THREATMODEL:108", "boundary"),
])
def test_reviewed_residual_and_boundary_tables_have_separate_counts(native_multi, status, row_id, expected):
    def mutate(cid, raw):
        if cid == "D":
            raw["residual"].update(status=status, row_refs=[row_id],
                row_reviews=[{"row_id": row_id, "rationale": "Synthetic case-specific coverage."}])
    result = run(approve_reviews(native_multi(), mutate=mutate)).to_dict()
    assert result["cases"][0]["verdict"] == expected
    assert result["paired_defect_case_count"] == (1 if expected == "confirmed_defect" else 0)
    assert result["frozen_case_count"] == 2


def test_structural_rejection_or_caller_snapshot_cannot_borrow_previous_PASS(native_multi):
    bundle = approve_reviews(native_multi())
    previous = run(bundle)
    with pytest.raises(TypeError):
        adjudicate_multi_dispatch_campaign(bundle["ctx"]["plan"], bundle["reviews"], snapshot=previous.snapshot,
                                          source_authority=bundle["ctx"]["authority"])
    with pytest.raises(AdjudicationError, match="raw_bytes"):
        run(bundle, reviews={"D": previous.cases[0].review})
    bundle["ctx"]["authority"].grant = replace(bundle["ctx"]["authority"].grant, evidence_sha256="0" * 64)
    with pytest.raises(AdjudicationError, match="source_reacquisition"):
        run(bundle)


def test_missing_review_and_undeclared_input_preserve_or_reject_the_denominator(native_multi):
    bundle = approve_reviews(native_multi())
    result = run(bundle, reviews={}).to_dict()
    assert result["frozen_case_count"] == 2 and result["cases"][0]["verdict"] == "unknown"
    assert result["cases"][1]["verdict"] == "control_rejected"
    with pytest.raises(AdjudicationError, match="undeclared_case"):
        run(bundle, reviews={"outside": None})
