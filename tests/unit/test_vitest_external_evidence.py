"""Synthetic Vitest 3.2.7 JUnit records; no Node/Vitest runner is invoked.

Reporter source: vitest v3.2.7 packages/vitest/src/node/reporters/junit.ts.
All approval/supervisor envelopes below are test doubles, not formal receipts.
"""

import xml.etree.ElementTree as ET

import pytest

from m12_helpers import CaptureAuthority, VITEST_TARGET, capture, encoded, prepared
from smallestlie.campaign.preregistration import PreregistrationError, digest, validate_profile
from smallestlie.oracle.runner_evidence import assess_effectiveness, validate_runner_receipt


def observed(plan, receipt, artifacts):
    return validate_runner_receipt(plan, "D", encoded(receipt), artifacts,
        authority=CaptureAuthority(plan, "D", receipt))


def change_report(receipt, artifacts, role, mutate):
    root = ET.fromstring(artifacts[role + "/report"])
    mutate(root)
    artifacts[role + "/report"] = ET.tostring(root, encoding="utf-8")
    receipt["arms"][role]["report"]["sha256"] = digest(artifacts[role + "/report"])


def test_vitest_nested_name_skip_and_assertion_repair_contract(tmp_path):
    plan = prepared(tmp_path, twin=True, report_format="vitest-junit")
    receipt, artifacts = capture(plan, "D")
    # Vitest's testsuites wrapper surrounds file suites; nested names flatten
    # with " > ", while classname is the relative filename by default.
    for role in receipt["arms"]:
        suite = ET.fromstring(artifacts[role + "/report"])
        wrapper = ET.Element("testsuites", **suite.attrib)
        wrapper.append(suite)
        artifacts[role + "/report"] = ET.tostring(wrapper, encoding="utf-8")
        receipt["arms"][role]["report"]["sha256"] = digest(artifacts[role + "/report"])
    evidence = observed(plan, receipt, artifacts)
    assert evidence.arm("baseline").tests == ((VITEST_TARGET, "failed", "assertion"),)
    assert evidence.arm("attack").tests == ((VITEST_TARGET, "skipped", None),)
    result = assess_effectiveness(plan, evidence)
    assert result.attack == result.twin == "confirmed"
    assert validate_runner_receipt(plan, "D", encoded(receipt), artifacts,
                                   authority=None).provenance_ref is None


@pytest.mark.parametrize("change", ["missing_type", "runtime_exception", "wrong_target", "collection_error",
                                   "multiple_errors", "summary_mismatch", "duplicate_identity"])
def test_vitest_incomplete_or_non_assertion_baseline_is_unknown(tmp_path, change):
    plan = prepared(tmp_path, twin=True, report_format="vitest-junit")
    receipt, artifacts = capture(plan, "D")

    def mutate(root):
        case, failure = root.find("testcase"), root.find("testcase/failure")
        if change == "missing_type":
            del failure.attrib["type"]
        elif change == "runtime_exception":
            failure.set("type", "TypeError")
        elif change == "wrong_target":
            case.set("name", "another assertion")
        elif change == "collection_error":
            case.set("name", "tests/billing.test.js")
            failure.set("type", "SyntaxError")
        elif change == "multiple_errors":
            ET.SubElement(case, "failure", type="TypeError", message="afterEach failed")
        elif change == "summary_mismatch":
            root.set("failures", "0")
        else:
            root.append(ET.fromstring(ET.tostring(case)))
            root.set("tests", "2")
            root.set("failures", "2")

    change_report(receipt, artifacts, "baseline", mutate)
    assert assess_effectiveness(plan, observed(plan, receipt, artifacts)).attack == "unknown"


def test_vitest_still_red_is_refuted_but_runner_failure_does_not_kill(tmp_path):
    plan = prepared(tmp_path, twin=True, report_format="vitest-junit")
    receipt, artifacts = capture(plan, "D", states={"baseline": "red", "attack": "red", "repair": "green"})
    assert assess_effectiveness(plan, observed(plan, receipt, artifacts)).attack == "refuted"
    change_report(receipt, artifacts, "attack", lambda root:
                  root.find("testcase/failure").set("type", "TypeError"))
    assert assess_effectiveness(plan, observed(plan, receipt, artifacts)).attack == "unknown"


@pytest.mark.parametrize("field,value", [("version", "5.0.0"), ("version", "synthetic"), ("name", "pytest")])
def test_vitest_profile_refuses_other_runner_contracts(tmp_path, field, value):
    plan = prepared(tmp_path, twin=True, report_format="vitest-junit")
    profile = plan.profile("D")
    profile["runner"][field] = value
    with pytest.raises(PreregistrationError, match="contract"):
        validate_profile(encoded(profile))


def test_vitest_receipt_cannot_replace_locked_version(tmp_path):
    plan = prepared(tmp_path, twin=True, report_format="vitest-junit")
    receipt, artifacts = capture(plan, "D")
    receipt["arms"]["attack"]["runner"] = {**receipt["arms"]["attack"]["runner"], "version": "5.0.0"}
    assert assess_effectiveness(plan, observed(plan, receipt, artifacts)).attack == "unknown"
