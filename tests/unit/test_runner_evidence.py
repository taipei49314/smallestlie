from dataclasses import replace
import json

import pytest

from m12_helpers import ApprovalAuthority, CaptureAuthority, capture, design, encoded, native_report, prepared
from smallestlie.campaign.preregistration import digest, prepare_run
from smallestlie.oracle.runner_evidence import assess_effectiveness, validate_runner_receipt


def observation(plan, cid, receipt, artifacts, **envelope_overrides):
    return validate_runner_receipt(plan, cid, encoded(receipt), artifacts,
        authority=CaptureAuthority(plan, cid, receipt, **envelope_overrides))


@pytest.mark.parametrize("report_format", ["junit", "mocha-json"])
def test_native_red_skip_green_and_repair_confirm_effectiveness(tmp_path, report_format):
    plan = prepared(tmp_path, twin=True, report_format=report_format)
    receipt, artifacts = capture(plan, "D")
    evidence = observation(plan, "D", receipt, artifacts)
    result = assess_effectiveness(plan, evidence)
    assert result.attack == result.twin == "confirmed"
    assert evidence.arm("baseline").tests[0][2] == "assertion"
    # The JUnit baseline is a pytest-style failure with no type attribute.
    if report_format == "junit":
        assert b'type="AssertionError"' not in artifacts["baseline/report"]


def test_hashes_and_self_claimed_authentication_do_not_supply_provenance(tmp_path):
    plan = prepared(tmp_path)
    receipt, artifacts = capture(plan, "B")
    evidence = validate_runner_receipt(plan, "B", encoded(receipt), artifacts, authority=None)
    assert assess_effectiveness(plan, evidence).attack == "unknown"
    assert "execution_provenance_missing" in evidence.reasons
    receipt["authenticated"] = True
    evidence = observation(plan, "B", receipt, artifacts)
    assert evidence.provenance_ref is None


@pytest.mark.parametrize("kind", ["fixture", "argv", "environment", "dependencies", "bool_exit", "truncated", "log_hash", "green_native_failure", "supervisor_exit", "late_lock"])
def test_tamper_or_incomplete_capture_is_unknown_never_refuted(tmp_path, kind):
    plan = prepared(tmp_path)
    receipt, artifacts = capture(plan, "B")
    arm = receipt["arms"]["attack"]
    overrides = {}
    if kind == "fixture":
        arm["fixture"]["files"] = {"wrong.py": "f" * 64}
    elif kind == "argv":
        arm["argv"].append("--different-suite")
    elif kind == "environment":
        arm["semantic_env"] = {"TEST_MODE": "other"}
    elif kind == "dependencies":
        arm["dependencies"]["lock_sha256"] = "f" * 64
    elif kind == "bool_exit":
        arm["exit_code"] = False
    elif kind == "truncated":
        arm["truncated"] = True
    elif kind == "log_hash":
        artifacts["attack/stdout"] += b"unbound log change"
    elif kind == "green_native_failure":
        artifacts["attack/report"] = native_report("red", "junit")
        arm["report"]["sha256"] = digest(artifacts["attack/report"])
    elif kind == "supervisor_exit":
        overrides["arm_exits"] = tuple((role, item["termination_kind"], 5 if role == "attack" else item["exit_code"])
                                       for role, item in receipt["arms"].items())
    else:
        overrides.update(lock_sequence=3, first_command_sequence=2)
    evidence = observation(plan, "B", receipt, artifacts, **overrides)
    assert assess_effectiveness(plan, evidence).attack == "unknown"


@pytest.mark.parametrize("baseline,attack,repair,expected", [
    ("green", "skip", "green", "refuted"),
    ("red", "red", "green", "refuted"),
    ("red", "typeerror", "green", "unknown"),
    ("typeerror", "skip", "green", "unknown"),
    ("red", "skip", "skip", "unknown"),
])
def test_real_refutation_is_distinct_from_runner_errors_or_uncalibrated_repair(tmp_path, baseline, attack, repair, expected):
    plan = prepared(tmp_path)
    receipt, artifacts = capture(plan, "B", states={"baseline": baseline, "attack": attack, "repair": repair})
    assert assess_effectiveness(plan, observation(plan, "B", receipt, artifacts)).attack == expected


def test_missing_baseline_and_timeout_cannot_kill(tmp_path):
    plan = prepared(tmp_path)
    receipt, artifacts = capture(plan, "B")
    del receipt["arms"]["baseline"]
    assert assess_effectiveness(plan, observation(plan, "B", receipt, artifacts)).attack == "unknown"
    receipt, artifacts = capture(plan, "B")
    receipt["arms"]["attack"].update(termination_kind="timeout", exit_code=None)
    assert assess_effectiveness(plan, observation(plan, "B", receipt, artifacts)).attack == "unknown"


def test_missing_twin_does_not_erase_confirmed_attack(tmp_path):
    plan = prepared(tmp_path, twin=True)
    receipt, artifacts = capture(plan, "D")
    del receipt["arms"]["twin"]
    result = assess_effectiveness(plan, observation(plan, "D", receipt, artifacts))
    assert result.attack == "confirmed" and result.twin == "unknown"


def test_validated_evidence_cannot_be_rebound_to_another_formal_request(tmp_path):
    first = prepared(tmp_path / "first")
    receipt, artifacts = capture(first, "B")
    evidence = observation(first, "B", receipt, artifacts)
    request, _ = design(tmp_path / "second")
    request = replace(request, run_id="trial-2")
    second = prepare_run(tmp_path / "second", "manifest.json", request, authority=ApprovalAuthority(request))
    assert assess_effectiveness(second, evidence).attack == "unknown"


def test_ambiguous_native_counts_fail_closed(tmp_path):
    plan = prepared(tmp_path / "mocha", report_format="mocha-json")
    receipt, artifacts = capture(plan, "B")
    report = json.loads(artifacts["baseline/report"])
    report["stats"]["tests"] = True
    artifacts["baseline/report"] = encoded(report)
    receipt["arms"]["baseline"]["report"]["sha256"] = digest(artifacts["baseline/report"])
    assert assess_effectiveness(plan, observation(plan, "B", receipt, artifacts)).attack == "unknown"


def test_junit_entities_fail_closed(tmp_path):
    plan = prepared(tmp_path)
    receipt, artifacts = capture(plan, "B")
    artifacts["baseline/report"] = b'<!DOCTYPE testsuite [<!ENTITY secret "fake">]><testsuite/>'
    receipt["arms"]["baseline"]["report"]["sha256"] = digest(artifacts["baseline/report"])
    assert assess_effectiveness(plan, observation(plan, "B", receipt, artifacts)).attack == "unknown"


@pytest.mark.parametrize("report_format", ["junit", "mocha-json"])
def test_raw_exception_name_cannot_impersonate_internal_assertion_kind(tmp_path, report_format):
    plan = prepared(tmp_path, report_format=report_format)
    receipt, artifacts = capture(plan, "B")
    if report_format == "junit":
        artifacts["baseline/report"] = artifacts["baseline/report"].replace(b"<failure ", b'<failure type="assertion" ').replace(b"assert 75 == 78.75", b"unrelated failure")
    else:
        report = json.loads(artifacts["baseline/report"])
        for key in ("tests", "failures"):
            report[key][0]["err"] = {"name": "assertion", "code": "OTHER", "message": "unrelated failure"}
        artifacts["baseline/report"] = encoded(report)
    receipt["arms"]["baseline"]["report"]["sha256"] = digest(artifacts["baseline/report"])
    assert assess_effectiveness(plan, observation(plan, "B", receipt, artifacts)).attack == "unknown"


@pytest.mark.parametrize("conflicting_error", [{}, {"name": "TypeError", "message": "not callable"}])
def test_mocha_duplicate_arrays_must_agree_on_failure_identity(tmp_path, conflicting_error):
    plan = prepared(tmp_path, report_format="mocha-json")
    receipt, artifacts = capture(plan, "B")
    report = json.loads(artifacts["baseline/report"])
    report["tests"][0]["err"] = conflicting_error
    artifacts["baseline/report"] = encoded(report)
    receipt["arms"]["baseline"]["report"]["sha256"] = digest(artifacts["baseline/report"])
    assert assess_effectiveness(plan, observation(plan, "B", receipt, artifacts)).attack == "unknown"


@pytest.mark.parametrize("invalid_error", [False, 0, [], ""])
@pytest.mark.parametrize("array,role", [("passes", "repair"), ("pending", "attack"), ("tests", "attack")])
def test_mocha_falsey_non_mapping_errors_are_unknown(tmp_path, invalid_error, array, role):
    plan = prepared(tmp_path, report_format="mocha-json")
    receipt, artifacts = capture(plan, "B")
    path = role + "/report"
    report = json.loads(artifacts[path])
    report[array][0]["err"] = invalid_error
    artifacts[path] = encoded(report)
    receipt["arms"][role]["report"]["sha256"] = digest(artifacts[path])
    assert assess_effectiveness(plan, observation(plan, "B", receipt, artifacts)).attack == "unknown"


@pytest.mark.parametrize("report_format", ["junit", "mocha-json"])
def test_matching_assertion_message_cannot_override_an_exception_type(tmp_path, report_format):
    plan = prepared(tmp_path, report_format=report_format)
    receipt, artifacts = capture(plan, "B")
    if report_format == "junit":
        artifacts["baseline/report"] = artifacts["baseline/report"].replace(b"<failure ", b'<failure type="TypeError" ')
    else:
        report = json.loads(artifacts["baseline/report"])
        for key in ("tests", "failures"):
            report[key][0]["err"]["name"] = "TypeError"
        artifacts["baseline/report"] = encoded(report)
    receipt["arms"]["baseline"]["report"]["sha256"] = digest(artifacts["baseline/report"])
    assert assess_effectiveness(plan, observation(plan, "B", receipt, artifacts)).attack == "unknown"
