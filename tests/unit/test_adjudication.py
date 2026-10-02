"""Synthetic raw captures and authorities only; never formal W3 evidence."""

from dataclasses import asdict, replace
import json

import pytest

from m12_helpers import CaptureAuthority, INDEX, capture, encoded, prepared
from smallestlie.adjudication.engine import AdjudicationError, CaseInputs, adjudicate_campaign
from smallestlie.adjudication.observations import TrustedVerifierEnvelope, validate_verifier_observation
from smallestlie.adjudication.reviews import TrustedReviewEnvelope, frozen_spec
from smallestlie.campaign.preregistration import canonical_digest, case_binding, digest
from smallestlie.oracle.runner_evidence import validate_runner_receipt


class SyntheticAuthority:
    def __init__(self, envelopes):
        self.envelopes = envelopes

    def verify(self, plan, cid, receipt_sha):
        return self.envelopes.get(cid)


def finding(rule="TEST_DISABLED", path="tests/test_billing.py", severity="high",
            allowlisted=False, fingerprint="blocking"):
    return {"rule": rule, "path": path, "severity": severity, "allowlisted": allowlisted,
            "fingerprint": fingerprint, "unit": None, "message": "synthetic finding",
            "before": {"text": "assert total", "span": [1, 13]}, "after": None,
            "escalators": ["synthetic"], "deescalators": [], "shape": "synthetic",
            "future_attachment": {"preserved": True}}


def verifier_capture(plan, cid, findings=(), *, code=None, fail_on="high", verdict=None,
                     config_errors=(), **envelope_overrides):
    blocked = any(not item["allowlisted"] and ("info", "warn", "high", "critical").index(item["severity"])
                  >= ("info", "warn", "high", "critical").index(fail_on) for item in findings)
    code = (1 if blocked else 0) if code is None else code
    payload = {"checkwash_findings_version": 2,
        "run": {"base": "HEAD~1", "head": "HEAD", "checkwash_version": plan.lock()["engine"]["version"]},
        "findings": list(findings), "summary": {severity: sum(item["severity"] == severity for item in findings)
            for severity in ("critical", "high", "warn", "info")}, "config_errors": list(config_errors),
        "skipped_files": [], "verdict": verdict or ("block" if blocked else "pass")}
    stdout, stderr = encoded(payload), b""
    case = plan.binding(cid)
    metadata = {"schema_version": "smallestlie.verifier-observation/v1", "binding": case_binding(plan.lock(), cid),
        "arm": "attack", "adapter": "checkwash", "engine": plan.lock()["engine"],
        "baseline_tree_sha256": case["arms"]["baseline"]["tree_sha256"],
        "attack_tree_sha256": case["arms"]["attack"]["tree_sha256"],
        "base_commit": "a" * 40, "head_commit": "b" * 40,
        "argv": ["python", "checkwash.pyz", "check", "HEAD~1..HEAD", "--format", "json"],
        "cwd": ".", "fail_on": fail_on, "termination_kind": "completed", "exit_code": code,
        "truncated": False, "stdout_sha256": digest(stdout), "stderr_sha256": digest(stderr)}
    data = encoded(metadata)
    envelope = TrustedVerifierEnvelope("synthetic-verifier", "c" * 40,
        canonical_digest(metadata["binding"]), digest(data), digest(stdout), digest(stderr),
        metadata["baseline_tree_sha256"], metadata["attack_tree_sha256"], plan.lock()["engine"]["artifact_sha256"],
        metadata["base_commit"], metadata["head_commit"], tuple(metadata["argv"]), ".", fail_on,
        "completed", code, 1, 3)
    return data, stdout, stderr, replace(envelope, **envelope_overrides)


def add_reviews(plan, items, runner_authority, verifier_authority, *, change=None):
    validations = {}
    for cid in [case["case_id"] for case in plan.lock()["cases"]]:
        raw = items.get(cid, CaseInputs())
        run = validate_runner_receipt(plan, cid, raw.runner_receipt, raw.runner_artifacts, authority=runner_authority)
        observed = validate_verifier_observation(plan, cid, raw.verifier_metadata,
            raw.verifier_stdout, raw.verifier_stderr, authority=verifier_authority)
        validations[cid] = {"runner_validation_sha256": canonical_digest(asdict(run)),
                            "verifier_validation_sha256": observed.validation_sha256}
    envelopes = {}
    index = json.loads(plan.asset(INDEX))
    for cid, raw in list(items.items()):
        case, spec = plan.binding(cid), frozen_spec(plan, cid)
        linked = [cid] + ([case["twin_case_id"]] if case["twin_case_id"] else [])
        before, after = case["arms"]["baseline"]["files"], case["arms"]["attack"]["files"]
        changes = sorted(path for path in before.keys() | after.keys() if before.get(path) != after.get(path))
        source = index["sources"][0]
        quote = plan.asset(source["path"]).splitlines(keepends=True)[0]
        twin = spec["adjudication"]["twin"]
        review = {"schema_version": "smallestlie.case-review/v1", "binding": case_binding(plan.lock(), cid),
            "engine": plan.lock()["engine"], "residual_index_sha256": plan.lock()["residual_index_sha256"],
            "observations": {key: validations[key] for key in linked},
            "source_reviews": [{"source_id": entry["id"], "sha256": entry["sha256"],
                "rationale": "Synthetic complete-document review, not a real coverage claim."} for entry in index["sources"]],
            "citations": [{"source_id": source["id"], "start_line": 1, "end_line": 1, "quote_sha256": digest(quote)}],
            "theater": {"status": "confirmed", "rationale": "Synthetic cheating shape.", "changed_paths": changes},
            "scope": {"status": "in_scope", "rationale": "Synthetic scope only."},
            "residual": {"status": "no_match_reviewed", "row_refs": [], "row_reviews": [],
                         "rationale": "Synthetic full-source coverage decision."},
            "twin": {"status": "confirmed", "rationale": "Synthetic same cheating/bug near shape.",
                "contrast_sha256": digest(twin["contrast"].encode()), "finding_fingerprints": ["blocking"]} if twin else None}
        if change:
            change(cid, review)
        review_data = encoded(review)
        envelopes[cid] = TrustedReviewEnvelope("synthetic-review", "d" * 40,
            canonical_digest(review["binding"]), digest(review_data))
        items[cid] = replace(raw, review=review_data)
    return SyntheticAuthority(envelopes)


def context(tmp_path, *, control_findings=None, control_options=None, states=None, design_change=None):
    plan = prepared(tmp_path, twin=True, change=design_change)
    items, runner_envelopes, verifier_envelopes = {}, {}, {}
    for cid in ("D", "C"):
        receipt, artifacts = capture(plan, cid, states=(states or {}).get(cid))
        runner_envelopes[cid] = CaptureAuthority(plan, cid, receipt).envelope
        native_findings = (control_findings if control_findings is not None else [finding()]) if cid == "C" else []
        metadata, stdout, stderr, envelope = verifier_capture(plan, cid, native_findings,
            **((control_options or {}) if cid == "C" else {}))
        verifier_envelopes[cid] = envelope
        items[cid] = CaseInputs(encoded(receipt), artifacts, metadata, stdout, stderr)
    ra, va = SyntheticAuthority(runner_envelopes), SyntheticAuthority(verifier_envelopes)
    reviews = add_reviews(plan, items, ra, va)
    return plan, items, ra, va, reviews


def result(plan, items, ra, va, reviews):
    return adjudicate_campaign(plan, items, runner_authority=ra, verifier_authority=va, review_authority=reviews)


def test_complete_effective_pair_has_one_case_headline_and_preserves_all_finding_details(tmp_path):
    plan, items, ra, va, reviews = context(tmp_path)
    report = result(plan, items, ra, va, reviews)
    row, control = report.cases
    assert row.verdict == "confirmed_defect" and row.paired_headline
    assert control.verdict == "control_rejected" and not control.paired_headline
    data = report.to_dict()
    assert data["frozen_case_count"] == 2
    assert data["confirmed_defect_case_count"] == data["paired_defect_case_count"] == 1
    assert data["cases"][1]["verifier"]["findings"][0] == finding()
    assert row.preregistered_class == "DEF"  # YAML scope was unresolved; post-review is separate.


@pytest.mark.parametrize("findings,options", [
    ([finding(severity="warn"), finding(rule="UNRELATED", severity="critical", fingerprint="other")], {}),
    ([finding(path="tests/other.py"), finding(rule="OTHER", fingerprint="other")], {}),
    ([finding(allowlisted=True), finding(rule="OTHER", fingerprint="other")], {}),
    ([finding(), finding(rule="OTHER", severity="critical", fingerprint="other")], {"fail_on": "critical"}),
    ([finding(fingerprint="unreviewed")], {}),
    ([finding(path="")], {}),
    ([], {}),
])
def test_irrelevant_allowlisted_below_threshold_or_unreviewed_finding_cannot_pair(tmp_path, findings, options):
    plan, items, ra, va, reviews = context(tmp_path, control_findings=findings, control_options=options)
    row = result(plan, items, ra, va, reviews).cases[0]
    assert row.verdict == "confirmed_defect" and not row.paired_headline


@pytest.mark.parametrize("missing", ["control_runner", "parent_twin", "control_verifier"])
def test_fixture_equality_cannot_borrow_missing_independent_arm_or_control_capture(tmp_path, missing):
    plan, items, ra, va, reviews = context(tmp_path)
    if missing == "control_runner":
        items["C"] = replace(items["C"], runner_receipt=None)
    elif missing == "parent_twin":
        receipt = json.loads(items["D"].runner_receipt)
        del receipt["arms"]["twin"]
        items["D"] = replace(items["D"], runner_receipt=encoded(receipt))
        ra.envelopes["D"] = CaptureAuthority(plan, "D", receipt).envelope
    else:
        items["C"] = replace(items["C"], verifier_metadata=None)
    reviews = add_reviews(plan, items, ra, va)
    row = result(plan, items, ra, va, reviews).cases[0]
    assert row.verdict == "confirmed_defect" and not row.paired_headline


@pytest.mark.parametrize("options", [
    {"code": 0}, {"code": 2}, {"verdict": "pass"},
    {"config_errors": ["bad config"]}, {"command_sequence": 1}, {"engine_sha256": "0" * 64},
])
def test_control_engine_errors_channels_config_or_execution_binding_cannot_pair(tmp_path, options):
    plan, items, ra, va, reviews = context(tmp_path, control_options=options)
    assert not result(plan, items, ra, va, reviews).cases[0].paired_headline
    assert result(plan, items, ra, va, reviews).cases[1].verifier.accepted is None


def test_real_refutation_kills_def_even_when_verifier_is_missing(tmp_path):
    plan, items, ra, va, reviews = context(tmp_path,
        states={"D": {"baseline": "red", "attack": "red", "repair": "green", "twin": "skip"}})
    items["D"] = replace(items["D"], verifier_metadata=None)
    row = result(plan, items, ra, va, reviews).cases[0]
    assert row.verdict == "killed_candidate" and not row.paired_headline


def test_missing_provenance_or_all_inputs_never_kills_or_drops_denominator(tmp_path):
    plan, items, ra, va, reviews = context(tmp_path)
    for report in (adjudicate_campaign(plan, {}), adjudicate_campaign(plan, items)):
        assert [row.case_id for row in report.cases] == ["D", "C"]
        assert all(row.verdict == "unknown" for row in report.cases)
        assert report.to_dict()["paired_defect_case_count"] == 0


@pytest.mark.parametrize("kind", ["missing_source", "stale_observations", "pin", "citation", "self_auth", "wrong_row"])
def test_partial_index_absence_or_stale_self_declared_review_never_promotes(tmp_path, kind):
    plan, items, ra, va, reviews = context(tmp_path)
    def change(cid, review):
        if cid != "D":
            return
        if kind == "missing_source":
            review["source_reviews"].pop()
        elif kind == "stale_observations":
            review["observations"]["C"]["runner_validation_sha256"] = "0" * 64
        elif kind == "pin":
            review["engine"]["version"] = "dev"
        elif kind == "citation":
            review["citations"][0]["quote_sha256"] = "0" * 64
        elif kind == "self_auth":
            review["authenticated"] = True
        else:
            review["residual"].update(status="matched_residual", row_refs=["THREATMODEL:5"],
                row_reviews=[{"row_id": "THREATMODEL:5", "rationale": "Closed is not residual."}])
    reviews = add_reviews(plan, items, ra, va, change=change)
    row = result(plan, items, ra, va, reviews).cases[0]
    assert row.verdict == "unknown" and not row.paired_headline


@pytest.mark.parametrize("status,row_id,expected", [
    ("matched_residual", "SPEC:SUBJECT_NORMALIZED:two-hop", "documented_residual"),
    ("reopened_closed", "THREATMODEL:5", "confirmed_defect"),
    ("unresolved", "THREATMODEL:108", "boundary"),
])
def test_documented_residual_reopened_closed_and_mixed_are_distinct(tmp_path, status, row_id, expected):
    plan, items, ra, va, reviews = context(tmp_path)
    def change(cid, review):
        if cid == "D":
            review["residual"].update(status=status, row_refs=[row_id],
                row_reviews=[{"row_id": row_id, "rationale": "Synthetic case-specific coverage."}])
    reviews = add_reviews(plan, items, ra, va, change=change)
    row = result(plan, items, ra, va, reviews).cases[0]
    assert row.verdict == expected
    assert row.paired_headline is (expected == "confirmed_defect")


def test_order_repetition_and_multiple_findings_do_not_change_case_counts(tmp_path):
    plan, items, ra, va, reviews = context(tmp_path, control_findings=[finding(), finding(fingerprint="other")])
    first = result(plan, items, ra, va, reviews).to_dict()
    second = result(plan, dict(reversed(list(items.items()))), ra, va, reviews).to_dict()
    assert first == second and first["paired_defect_case_count"] == 1
    with pytest.raises(AdjudicationError, match="undeclared"):
        result(plan, {**items, "invented": CaseInputs()}, ra, va, reviews)


def test_review_requires_separate_authority_even_with_valid_runner_and_verifier(tmp_path):
    plan, items, ra, va, reviews = context(tmp_path)
    row = result(plan, items, ra, va, None).cases[0]
    assert row.verdict == "unknown" and "post_review_provenance_missing" in row.reasons


@pytest.mark.parametrize("scope,theater,relation", [
    ("out_of_scope", "confirmed", "confirmed"),
    ("unresolved", "confirmed", "confirmed"),
    ("in_scope", "refuted", "confirmed"),
    ("in_scope", "confirmed", "refuted"),
])
def test_post_review_boundaries_and_refuted_near_shape_are_visible(tmp_path, scope, theater, relation):
    plan, items, ra, va, reviews = context(tmp_path)
    def change(cid, review):
        if cid == "D":
            review["scope"]["status"] = scope
            review["theater"]["status"] = theater
            review["twin"]["status"] = relation
    reviews = add_reviews(plan, items, ra, va, change=change)
    row = result(plan, items, ra, va, reviews).cases[0]
    assert row.verdict == ("confirmed_defect" if relation == "refuted" else "boundary")
    assert not row.paired_headline


def test_bnd_preregistration_is_retained_when_post_review_confirms_in_scope_defect(tmp_path):
    def change(manifest, assets):
        path = manifest["cases"][0]["spec_path"]
        spec = json.loads(assets[path])
        spec["adjudication"]["preregistered_class"] = "BND"
        assets[path] = encoded(spec)
    plan, items, ra, va, reviews = context(tmp_path, design_change=change)
    row = result(plan, items, ra, va, reviews).cases[0]
    assert row.preregistered_class == "BND" and row.verdict == "confirmed_defect" and row.paired_headline


def test_control_receipt_cannot_be_relabelled_as_parent(tmp_path):
    plan, items, ra, va, reviews = context(tmp_path)
    items["D"] = replace(items["D"], runner_receipt=items["C"].runner_receipt,
                         runner_artifacts=items["C"].runner_artifacts)
    assert result(plan, items, ra, va, reviews).cases[0].verdict == "unknown"


def test_individually_valid_capture_changed_after_review_cannot_reuse_old_review(tmp_path):
    plan, items, ra, va, reviews = context(tmp_path)
    data, stdout, stderr, envelope = verifier_capture(plan, "D", [finding(rule="WARNING", severity="warn")])
    items["D"] = replace(items["D"], verifier_metadata=data, verifier_stdout=stdout, verifier_stderr=stderr)
    va.envelopes["D"] = envelope
    # Capture is individually valid; the review still names the previous observation.
    assert result(plan, items, ra, va, reviews).cases[0].verdict == "unknown"


@pytest.fixture(scope="module")
def observation_plan(tmp_path_factory):
    return prepared(tmp_path_factory.mktemp("observation-contract"))


def rebound_payload(metadata, payload, stderr, envelope):
    stdout = encoded(payload)
    raw = json.loads(metadata)
    raw["stdout_sha256"] = digest(stdout)
    data = encoded(raw)
    return data, stdout, stderr, replace(envelope, metadata_sha256=digest(data), stdout_sha256=digest(stdout))


@pytest.mark.parametrize("wrong_range", [False, True])
def test_native_resolved_commit_range_must_match_independent_envelope(observation_plan, wrong_range):
    metadata, stdout, stderr, envelope = verifier_capture(observation_plan, "B")
    payload = json.loads(stdout)
    payload["run"].update(base=("e" * 40 if wrong_range else envelope.base_commit), head=envelope.head_commit)
    metadata, stdout, stderr, envelope = rebound_payload(metadata, payload, stderr, envelope)
    observed = validate_verifier_observation(observation_plan, "B", metadata, stdout, stderr,
        authority=SyntheticAuthority({"B": envelope}))
    assert observed.accepted is (None if wrong_range else True)


@pytest.mark.parametrize("kind", [
    "case", "baseline", "attack_tree", "threshold", "stdout", "stderr",
    "missing_metadata", "missing_stdout", "missing_stderr", "truncated", "bool_exit", "timeout",
])
def test_raw_verifier_capture_and_supervisor_disagreements_remain_unknown(observation_plan, kind):
    metadata, stdout, stderr, envelope = verifier_capture(observation_plan, "B")
    raw = json.loads(metadata)
    if kind == "case":
        raw["binding"]["spec_sha256"] = "0" * 64
    elif kind == "baseline":
        raw["baseline_tree_sha256"] = "0" * 64
    elif kind == "attack_tree":
        raw["attack_tree_sha256"] = "0" * 64
    elif kind == "threshold":
        raw["fail_on"] = "critical"
    elif kind == "truncated":
        raw["truncated"] = True
    elif kind == "bool_exit":
        raw["exit_code"] = False
        envelope = replace(envelope, exit_code=False)
    elif kind == "timeout":
        raw.update(termination_kind="timeout", exit_code=None)
        envelope = replace(envelope, termination_kind="timeout", exit_code=None)
    metadata = encoded(raw)
    if kind in {"bool_exit", "timeout"}:
        envelope = replace(envelope, metadata_sha256=digest(metadata))
    if kind == "stdout":
        stdout += b"tampered"
    elif kind == "stderr":
        stderr = b"unbound diagnostic"
    elif kind == "missing_metadata":
        metadata = None
    elif kind == "missing_stdout":
        stdout = None
    elif kind == "missing_stderr":
        stderr = None
    observed = validate_verifier_observation(observation_plan, "B", metadata, stdout, stderr,
        authority=SyntheticAuthority({"B": envelope}))
    assert observed.accepted is None and observed.provenance_ref is None


@pytest.mark.parametrize("path,fingerprint,accepted", [
    ("../tests/test_billing.py", "opaque", None),
    ("tests/test_billing.py", "", None),
    ("", "opaque:global", False),
])
def test_invalid_finding_identity_is_unknown_and_global_path_is_preserved(observation_plan, path, fingerprint, accepted):
    metadata, stdout, stderr, envelope = verifier_capture(observation_plan, "B",
        [finding(path=path, fingerprint=fingerprint)])
    observed = validate_verifier_observation(observation_plan, "B", metadata, stdout, stderr,
        authority=SyntheticAuthority({"B": envelope}))
    assert observed.accepted is accepted
    if path == "":
        assert observed.findings[0].path == ""
        assert observed.findings[0].fingerprint == "opaque:global"
