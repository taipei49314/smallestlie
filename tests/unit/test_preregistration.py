from dataclasses import replace
import json

import pytest

from m12_helpers import ApprovalAuthority, commit_all, design, encoded, prepared
from smallestlie.campaign.preregistration import PreregistrationError, derive_variant, digest, prepare_run


def test_frozen_pair_has_complete_bindings_and_owns_bytes(tmp_path):
    plan = prepared(tmp_path, twin=True)
    assert [case["case_id"] for case in plan.lock()["cases"]] == ["D", "C"]
    assert plan.binding("D")["arms"]["twin"] == plan.binding("C")["arms"]["attack"]
    original = plan.asset("variants/D/baseline/tests/test_billing.py")
    (tmp_path / "variants/D/baseline/tests/test_billing.py").write_bytes(b"later change\n")
    assert plan.asset("variants/D/baseline/tests/test_billing.py") == original
    altered_lock = plan.lock()
    altered_lock["cases"].clear()
    assert len(plan.lock()["cases"]) == 2


def test_no_authority_and_wrong_approval_cannot_self_authorize(tmp_path):
    request, authority = design(tmp_path)
    with pytest.raises(PreregistrationError, match="authority_missing"):
        prepare_run(tmp_path, "manifest.json", request, authority=None)
    with pytest.raises(PreregistrationError, match="approval_mismatch"):
        prepare_run(tmp_path, "manifest.json", replace(request, run_id="different"), authority=authority)


def test_clean_descendant_can_add_results_without_changing_frozen_design(tmp_path):
    request, _ = design(tmp_path)
    (tmp_path / "results.txt").write_bytes(b"external result attachment\n")
    request = replace(request, source_commit=commit_all(tmp_path))
    assert prepare_run(tmp_path, "manifest.json", request, authority=ApprovalAuthority(request)).request == request


@pytest.mark.parametrize("path", ["attacks/B.json.yaml", "profiles/runner.json", "variants/B/baseline/tests/test_billing.py",
                                  "contracts/collector.py", "locks/runner.lock"])
def test_descendant_cannot_change_frozen_input(tmp_path, path):
    request, _ = design(tmp_path)
    target = tmp_path / path
    target.write_bytes(target.read_bytes() + b"\nchanged\n")
    request = replace(request, source_commit=commit_all(tmp_path))
    with pytest.raises(PreregistrationError, match="frozen asset"):
        prepare_run(tmp_path, "manifest.json", request, authority=ApprovalAuthority(request))


def test_clean_descendant_cannot_add_unlisted_fixture_file(tmp_path):
    request, _ = design(tmp_path)
    (tmp_path / "variants/B/baseline/extra.py").write_bytes(b"extra input\n")
    request = replace(request, source_commit=commit_all(tmp_path))
    with pytest.raises(PreregistrationError, match="closure"):
        prepare_run(tmp_path, "manifest.json", request, authority=ApprovalAuthority(request))


def test_manifest_change_and_requested_digest_rewrite_still_fail_phase1(tmp_path):
    request, _ = design(tmp_path)
    path = tmp_path / "manifest.json"
    path.write_bytes(path.read_bytes() + b"\n")
    request = replace(request, source_commit=commit_all(tmp_path), manifest_sha256=digest(path.read_bytes()))
    with pytest.raises(PreregistrationError, match="Phase 1"):
        prepare_run(tmp_path, "manifest.json", request, authority=ApprovalAuthority(request))


@pytest.mark.parametrize("kind", ["unrelated_attack", "bug_changed", "repair_tests_changed", "dropped_case", "bad_exit", "wrong_report", "wrong_collector"])
def test_invalid_design_is_rejected_before_any_execution(tmp_path, kind):
    def change(manifest, assets):
        if kind == "unrelated_attack":
            assets["variants/B/attack/tests/test_billing.py"] = b"different unregistered mutation\n"
        elif kind == "bug_changed":
            assets["variants/B/attack/src/billing.py"] = b"bug fixed in attack\n"
        elif kind == "repair_tests_changed":
            assets["variants/B/repair/tests/test_billing.py"] = b"weakened repair tests\n"
        elif kind == "dropped_case":
            catalog = json.loads(assets["catalogs/frozen.yaml"])
            catalog["attacks"].append("missing")
            assets["catalogs/frozen.yaml"] = encoded(catalog)
        else:
            profile = json.loads(assets["profiles/runner.json"])
            if kind == "bad_exit":
                profile["assertion_exit_codes"] = [2]
            elif kind == "wrong_report":
                profile["runner"]["name"] = "mocha"
            else:
                profile["collector_sha256"] = "f" * 64
            assets["profiles/runner.json"] = encoded(profile)
    request, authority = design(tmp_path, change=change)
    with pytest.raises(PreregistrationError):
        prepare_run(tmp_path, "manifest.json", request, authority=authority)


def test_derivation_checks_occurrences_and_does_not_write_to_inputs():
    base = {"test.py": b"honest honest\n"}
    assert derive_variant(base, [{"type": "replace_text", "path": "test.py", "old": "honest", "new": "skip", "expected_count": 2}]) == {"test.py": b"skip skip\n"}
    assert base["test.py"] == b"honest honest\n"
    with pytest.raises(PreregistrationError):
        derive_variant(base, [{"type": "replace_text", "path": "test.py", "old": "honest", "new": "skip", "expected_count": True}])
    with pytest.raises(PreregistrationError, match="unsupported"):
        derive_variant(base, [{"type": "structured_set", "path": "test.py", "pointer": "/x", "value": 1}])
