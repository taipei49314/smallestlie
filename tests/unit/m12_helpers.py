"""Synthetic contract records. No runner is invoked and no W3 result is implied."""

from dataclasses import replace
import hashlib
import json
from pathlib import Path
import subprocess
import xml.etree.ElementTree as ET

from smallestlie.campaign.preregistration import (
    PreregistrationApproval, RunRequest, canonical_digest, case_binding, digest, prepare_run,
)
from smallestlie.oracle.runner_evidence import TrustedExecutionEnvelope

ROOT = Path(__file__).resolve().parents[2]
INDEX = "catalogs/residual-rows-checkwash-v0.5.0.json"
TARGET = "tests.test_billing::test_total"
VITEST_TARGET = "tests/billing.test.js::billing > total includes tax"


def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2) + "\n").encode("utf-8")


def git(root, *args):
    return subprocess.run(["git", "-C", str(root), *args], check=True, capture_output=True).stdout.decode().strip()


def commit_all(root):
    git(root, "add", ".")
    git(root, "-c", "user.name=contract-test", "-c", "user.email=contract@example.invalid", "commit", "-m", "fixture")
    return git(root, "rev-parse", "HEAD")


class ApprovalAuthority:
    def __init__(self, request):
        self.approval = PreregistrationApproval("synthetic-test-authority", request.authorization_ref,
            request.phase1_commit, request.manifest_sha256, canonical_digest(request.payload()))

    def verify(self, request):
        return self.approval


def design(root, *, twin=False, report_format="junit", change=None):
    root.mkdir(parents=True, exist_ok=True)
    asset_bytes = {}
    for path in (INDEX, "verifiers/checkwash.pyz", "provenance/checkwash-v0.5.0/SPEC.md",
                 "provenance/checkwash-v0.5.0/THREATMODEL.md", "pyproject.toml", "uv.lock"):
        asset_bytes[path] = (ROOT / path).read_bytes()
    for source in (ROOT / "src/smallestlie").rglob("*.py"):
        asset_bytes[source.relative_to(ROOT).as_posix()] = source.read_bytes()
    asset_bytes["contracts/collector.py"] = b"# synthetic collector asset, never executed\n"
    asset_bytes["locks/runner.lock"] = b"synthetic pinned dependencies\n"
    target = VITEST_TARGET if report_format == "vitest-junit" else TARGET
    runner = {"junit": "pytest", "mocha-json": "mocha", "vitest-junit": "vitest"}[report_format]
    profile = {"schema_version": "smallestlie.runner-profile/v1", "profile_id": "contract-profile",
        "baseline_assertion": target, "report_format": report_format, "assertion_exit_codes": [1],
        "assertion_failure": {"message_contains": "assert 75 == 78.75", "text_contains": "E       assert 75 == 78.75"} if report_format in {"junit", "vitest-junit"} else {"message_contains": "Expected 78.75"},
        "runner": {"name": runner, "version": "3.2.7" if report_format == "vitest-junit" else "synthetic", "artifact_sha256": "1" * 64},
        "runtime": {"name": "synthetic-runtime", "version": "test", "artifact_sha256": "2" * 64},
        "dependencies": {"lock_path": "locks/runner.lock", "installed_sha256": "3" * 64},
        "collector_path": "contracts/collector.py", "collector_sha256": digest(asset_bytes["contracts/collector.py"]),
        "semantic_env": {"TEST_MODE": "contract"},
        "arms": {role: {"argv": ["${RUNTIME}", "test"], "cwd": ".", "config_paths": []}
                 for role in ("baseline", "attack", "twin", "repair")}}
    asset_bytes["profiles/runner.json"] = encoded(profile)
    profile_sha = digest(asset_bytes["profiles/runner.json"])
    cases, closed = [], ["contracts", "profiles", "src/smallestlie"]
    for cid in (["D", "C"] if twin else ["B"]):
        is_control = cid == "C"
        mutation_text = "skip twin\n" if is_control else "skip attack\n"
        spec = {"schema_version": "smallestlie.attack/v2", "attack_id": cid, "name": "synthetic design",
            "family": "verifier", "purpose": "contract test only", "mutations": [
                {"type": "write_text", "path": "tests/test_billing.py", "content": mutation_text}],
            "execute": {"command_ref": "run_checkwash_check", "timeout_seconds": 120},
            "oracle": {"type": "git_diff_theater", "expected": {"no_theater": False, "paths": ["tests/test_billing.py"]}},
            "false_accept_condition": {"target_accepted": True, "oracle_valid": False},
            "adjudication": {"preregistered_class": "CTL" if is_control else ("DEF" if twin else "BND"),
                "expected_verifier_outcome": "block" if is_control else "accept",
                "control_role": "detectable_attack_control" if is_control else None,
                "claim_scope": {"status": "unresolved", "rationale": "Synthetic contract."},
                "residual_mapping": {"status": "unresolved", "row_refs": [], "rationale": "Synthetic contract."},
                "twin": {"case_id": "C", "role": "detectable_attack_control", "contrast": "Synthetic near shape",
                         "detection": {"rule_ids": ["TEST_DISABLED"], "paths": ["tests/test_billing.py"]}} if cid == "D" else None},
            "runner_protocol": {"profile_id": profile["profile_id"], "profile_sha256": profile_sha, "baseline_assertion": target}}
        spec_path = f"attacks/{cid}.json.yaml"
        asset_bytes[spec_path] = encoded(spec)
        variants = {}
        roles = ["baseline", "attack", "repair"] + (["twin"] if cid == "D" else [])
        for role in roles:
            ref = f"variants/{cid}/{role}"
            closed.append(ref)
            test_bytes = ("honest\n" if role in {"baseline", "repair"} else
                          "skip twin\n" if role == "twin" or is_control else "skip attack\n").encode()
            asset_bytes[ref + "/tests/test_billing.py"] = test_bytes
            asset_bytes[ref + "/src/billing.py"] = b"return 78.75\n" if role == "repair" else b"return 75\n"
            variants[role] = {"root": ref, "production_paths": ["src/billing.py"]}
        cases.append({"case_id": cid, "spec_path": spec_path, "profile_path": "profiles/runner.json", "variants": variants})
    index = json.loads(asset_bytes[INDEX])
    asset_bytes["catalogs/frozen.yaml"] = encoded({"schema_version": "smallestlie.catalog/v2", "name": "synthetic",
        "attacks": [case["case_id"] for case in cases], "engine": {key: index["engine"][key] for key in ("version", "artifact_sha256", "source_revision")}, "residual_index": INDEX})
    manifest = {"schema_version": "smallestlie.preregistration/v1", "campaign_id": "contract-study",
        "catalog_path": "catalogs/frozen.yaml", "assets": {}, "closed_roots": closed, "cases": cases,
        "engine_path": "verifiers/checkwash.pyz", "residual_index_path": INDEX,
        "contract_paths": ["contracts/collector.py", *[path for path in asset_bytes if path.startswith("src/smallestlie/")]]}
    if change:
        change(manifest, asset_bytes)
    for path, data in asset_bytes.items():
        target = root / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
        blob = hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()
        manifest["assets"][path] = {"sha256": digest(data), "git_blob": blob}
    manifest_bytes = encoded(manifest)
    (root / "manifest.json").write_bytes(manifest_bytes)
    (root / ".gitattributes").write_bytes(b"* -text\n")
    git(root, "init")
    phase1 = commit_all(root)
    request = RunRequest("contract-study", "request-1", "trial-1", phase1, phase1,
                         digest(manifest_bytes), "synthetic-human-merge")
    return request, ApprovalAuthority(request)


def prepared(root, **kwargs):
    request, authority = design(root, **kwargs)
    return prepare_run(root, "manifest.json", request, authority=authority)


def native_report(state, report_format):
    if report_format == "mocha-json":
        record = {"fullTitle": TARGET, "err": {"name": "AssertionError", "code": "ERR_ASSERTION", "message": "Expected 78.75, observed 75"} if state == "red" else {}}
        passes, failures, pending = ([record] if state == "green" else [], [record] if state == "red" else [], [record] if state == "skip" else [])
        return encoded({"stats": {"tests": 1, "passes": len(passes), "failures": len(failures), "pending": len(pending)},
                        "tests": [record], "passes": passes, "failures": failures, "pending": pending})
    suite = ET.Element("testsuite", tests="1", failures="1" if state in {"red", "typeerror"} else "0", errors="0", skipped="1" if state == "skip" else "0")
    case = ET.SubElement(suite, "testcase",
        classname="tests/billing.test.js" if report_format == "vitest-junit" else "tests.test_billing",
        name="billing > total includes tax" if report_format == "vitest-junit" else "test_total")
    if state == "red":
        failure = ET.SubElement(case, "failure", message="assert 75 == 78.75")
        if report_format == "vitest-junit":
            failure.set("type", "AssertionError")
        failure.text = "E       assert 75 == 78.75"
    elif state == "typeerror":
        ET.SubElement(case, "failure", type="TypeError", message="not callable").text = "TypeError"
    elif state == "skip":
        ET.SubElement(case, "skipped", message="synthetic skip")
    return ET.tostring(suite, encoding="utf-8")


def capture(plan, cid, *, states=None):
    states = states or {"baseline": "red", "attack": "skip", "repair": "green", "twin": "skip"}
    binding, profile = plan.binding(cid), plan.profile(cid)
    receipt = {"schema_version": "smallestlie.runner-receipt/v1", "binding": case_binding(plan.lock(), cid),
               "source_run_id": "pool-100", "job_id": "job-100", "host": "LAPTOP-50KP71KA", "arms": {}}
    artifacts = {}
    for role, expected in binding["arms"].items():
        state = states.get(role, "skip")
        code = 1 if state in {"red", "typeerror"} else 0
        command = profile["arms"][role]
        arm = {"fixture": {key: expected[key] for key in ("files", "tree_sha256", "production")},
            "runner": profile["runner"], "runtime": profile["runtime"],
            "dependencies": {**profile["dependencies"], "lock_sha256": binding["dependency_lock_sha256"]},
            "semantic_env": profile["semantic_env"], "workspace_root": "/synthetic/workspace",
            "runtime_path": "/synthetic/runtime", "argv": ["/synthetic/runtime", "test"],
            "cwd": "/synthetic/workspace", "config": expected["config"], "termination_kind": "completed",
            "exit_code": code, "truncated": False}
        for key, data in (("stdout", b"synthetic stdout\n"), ("stderr", b""), ("report", native_report(state, profile["report_format"]))):
            path = role + "/" + key
            artifacts[path] = data
            arm[key] = {"path": path, "sha256": digest(data)}
        receipt["arms"][role] = arm
    return receipt, artifacts


class CaptureAuthority:
    def __init__(self, plan, cid, receipt, **overrides):
        envelope = TrustedExecutionEnvelope("synthetic-capture", "a" * 40,
            canonical_digest(plan.request.payload()), plan.binding(cid)["run_id"], "pool-100", "job-100",
            "LAPTOP-50KP71KA", plan.request.phase1_commit, plan.request.source_commit,
            plan.lock()["lock_digest"], digest(encoded(receipt)), plan.profile(cid)["collector_sha256"], 1, 2,
            tuple((role, arm["termination_kind"], arm["exit_code"]) for role, arm in receipt["arms"].items()))
        self.envelope = replace(envelope, **overrides)

    def verify(self, prepared_run, case_id, receipt_sha256):
        return self.envelope
