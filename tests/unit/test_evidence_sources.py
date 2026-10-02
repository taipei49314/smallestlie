"""Synthetic independent API/publication contracts, never real W3 evidence."""

import base64
from copy import deepcopy
from dataclasses import replace
import hashlib

import pytest

from m12_helpers import capture, encoded, native_report, prepared
from test_adjudication import finding, verifier_capture
from test_governance_provenance import Api
from smallestlie.adjudication.observations import validate_verifier_observation
from smallestlie.campaign.evidence_sources import (
    EcExecutionAuthority, EcPublicationGrant, EcReceiptStore, EcReceiptTrustRoot,
    EcVerifierAuthority, ProvenanceError,
)
from smallestlie.campaign.preregistration import canonical_digest, case_binding, digest
from smallestlie.oracle.runner_evidence import assess_effectiveness, validate_runner_receipt


class ReceiptApi(Api):
    def __init__(self):
        super().__init__()
        self.runs, self.jobs = {}, {}

    def workflow_run(self, repo, number, attempt):
        self.calls.append(("run", repo, number, attempt))
        return deepcopy(self.runs[repo, number, attempt])

    def workflow_job(self, repo, number):
        self.calls.append(("job", repo, number))
        return deepcopy(self.jobs[repo, number])

    def install(self, repo, revision, files):
        directories = {"": []}
        for path, data in files.items():
            parts = path.split("/")
            for index in range(1, len(parts)):
                directories.setdefault("/".join(parts[:index]), [])
            oid = hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()
            self.blobs[repo, oid] = {"sha": oid, "size": len(data), "encoding": "base64",
                                    "content": base64.b64encode(data).decode() + "\n"}
            parent = "/".join(parts[:-1])
            directories[parent].append({"path": parts[-1], "sha": oid, "type": "blob", "mode": "100644"})
        ids = {path: digest(f"{repo}:{revision}:{path}".encode())[:40] for path in directories}
        for path in directories.keys() - {""}:
            parts = path.split("/")
            directories["/".join(parts[:-1])].append({"path": parts[-1], "sha": ids[path], "type": "tree", "mode": "040000"})
        for path, items in directories.items():
            self.trees[repo, ids[path]] = {"sha": ids[path], "truncated": False, "tree": items}
        self.commits[repo, revision] = {"sha": revision, "tree": {"sha": ids[""]}}
        return ids


@pytest.fixture(scope="module")
def plan(tmp_path_factory):
    return prepared(tmp_path_factory.mktemp("independent-captures"), twin=True)


def republish(ctx):
    files, supervisor, api, root = ctx["files"], ctx["supervisor"], ctx["api"], ctx["root"]
    if supervisor is not None:
        files["m12-supervisor.json"] = encoded(supervisor)
    publication = {"schema_version": 1, "status": "preserved", "context": {
        "GITHUB_RUN_ID": "600", "GITHUB_RUN_ATTEMPT": "1", "GITHUB_SHA": "e" * 40,
        "GITHUB_JOB": "run", "COMPUTERNAME": root.host, "EC_JOB_STATUS": "success"},
        "files": [{"path": path, "bytes": len(data), "sha256": digest(data)}
                  for path, data in sorted(files.items()) if path != "ec-publication.json"]}
    files["ec-publication.json"] = encoded(publication)
    grant = replace(root.publications[0], publication_sha256=digest(files["ec-publication.json"]),
                    supervisor_sha256=digest(files["m12-supervisor.json"]) if supervisor is not None else None,
                    supervisor_acceptance_ref="synthetic-external-acceptance:collector" if supervisor is not None else None)
    ctx["root"] = replace(root, publications=(grant,))
    ctx["trees"] = api.install(root.repository, grant.receipt_commit, files)
    ctx["store"] = EcReceiptStore(ctx["root"], transport=api)
    return ctx["store"]


@pytest.fixture
def ctx(plan):
    api, files, cases, sequence = ReceiptApi(), {}, [], 4
    root = EcReceiptTrustRoot("example/ec", 202, "example/product", 300, ".github/workflows/pool.yml",
        digest(b"synthetic external workflow"), "main", "run", "LAPTOP-50KP71KA", 33, "synthetic-pool",
        "synthetic-generation", "formal-contract", "4" * 64, "trusted/collector.py",
        plan.profile("D")["collector_sha256"], "synthetic-python", "3.12.10", "5" * 64,
        (("TEST_MODE", "contract"),), (EcPublicationGrant(canonical_digest(plan.request.payload()),
            plan.lock()["lock_digest"], plan.request.source_commit, "e" * 40, 600, 1, 700, "f" * 40,
            "6" * 64, "synthetic-external-acceptance:publication", "7" * 64,
            "synthetic-external-acceptance:collector"),))
    api.install(root.repository, "e" * 40, {root.workflow_path: b"synthetic external workflow",
                root.collector_path: plan.asset("contracts/collector.py")})
    api.runs[root.repository, 600, 1] = {"id": 600, "run_attempt": 1, "workflow_id": 300,
        "repository": {"id": 202, "full_name": root.repository}, "head_sha": "e" * 40, "head_branch": "main",
        "path": root.workflow_path, "event": "workflow_dispatch", "status": "completed", "conclusion": "success"}
    api.jobs[root.repository, 700] = {"id": 700, "run_id": 600, "run_attempt": 1, "runner_id": 33,
        "runner_name": root.runner_name, "head_sha": "e" * 40, "name": "run", "status": "completed", "conclusion": "success"}
    files["ec-workload.json"] = encoded({"schema_version": 1, "repository": root.product_repository,
        "sha": plan.request.source_commit, "ec_sha": "e" * 40, "run_id": "600", "run_attempt": "1",
        "host": root.host, "runner": root.runner_name, "generation": root.generation, "workload": root.workload,
        "declaration_sha256": root.declaration_sha256, "mode": "single", "cache": False,
        "result": {"conclusion": "success", "exit_code": 0}})
    files["invalid-utf8.stdout"] = b"\xff\r\n\x00"
    for cid in ("D", "C"):
        receipt, artifacts = capture(plan, cid)
        receipt.update(source_run_id="600", job_id="700", host=root.host)
        arms = {}
        for role, observation in receipt["arms"].items():
            for key in ("stdout", "stderr", "report"):
                ref = observation[key]
                files[cid + "/" + ref["path"]] = artifacts[ref["path"]]
                ref["path"] = cid + "/" + ref["path"]
            arms[role] = {"observation": deepcopy(observation), "command_sequence": sequence,
                "termination_kind": observation["termination_kind"], "exit_code": observation["exit_code"],
                "output_complete": True, "descendants_reaped": True}
            sequence += 1
        runner_path = cid + "/runner.json"
        files[runner_path] = encoded(receipt)
        metadata, stdout, stderr, _ = verifier_capture(plan, cid, [finding()] if cid == "C" else [])
        from smallestlie.campaign.preregistration import json_mapping
        raw = json_mapping(metadata, "synthetic verifier")
        raw["argv"][:2] = ["/synthetic/python", "/synthetic/engine.pyz"]
        refs = {}
        for key, data in (("metadata", encoded(raw)), ("stdout", stdout), ("stderr", stderr)):
            path = f"{cid}/verifier-{key}"
            files[path] = data
            refs[key] = {"path": path, "sha256": digest(data)}
        observed = {**refs, "baseline_files": plan.binding(cid)["arms"]["baseline"]["files"],
            "attack_files": plan.binding(cid)["arms"]["attack"]["files"],
            "engine_sha256": plan.lock()["engine"]["artifact_sha256"], "runtime": {
                "name": root.verifier_runtime_name, "version": root.verifier_runtime_version,
                "artifact_sha256": root.verifier_runtime_sha256}, "runtime_path": "/synthetic/python",
            "engine_path": "/synthetic/engine.pyz", "semantic_env": dict(root.verifier_semantic_env),
            "workspace_root": f"/synthetic/verifier/{cid}", "argv": raw["argv"],
            "cwd": f"/synthetic/verifier/{cid}", "logical_cwd": ".", "base_commit": raw["base_commit"],
            "head_commit": raw["head_commit"], "fail_on": "high", "command_sequence": sequence,
            "termination_kind": "completed", "exit_code": raw["exit_code"],
            "output_complete": True, "descendants_reaped": True}
        sequence += 1
        cases.append({"binding": case_binding(plan.lock(), cid), "runner": {
            "receipt": {"path": runner_path, "sha256": digest(files[runner_path])}, "arms": arms}, "verifier": observed})
    supervisor = {"schema_version": "smallestlie.outer-supervisor/v1", "request": plan.request.payload(),
        "request_sha256": canonical_digest(plan.request.payload()), "lock_digest": plan.lock()["lock_digest"],
        "collector_sha256": root.collector_sha256, "source_run_id": "600", "job_id": "700", "host": root.host,
        "lock_sequence": 3, "cases": cases}
    result = {"api": api, "root": root, "files": files, "supervisor": supervisor, "plan": plan}
    republish(result)
    return result


def runner_validation(ctx, cid="D"):
    from smallestlie.campaign.preregistration import json_mapping
    data = ctx["files"][cid + "/runner.json"]
    raw = json_mapping(data, "synthetic runner")
    artifacts = {ref["path"]: ctx["files"][ref["path"]]
                 for arm in raw["arms"].values() for ref in (arm["stdout"], arm["stderr"], arm["report"])}
    return validate_runner_receipt(ctx["plan"], cid, data, artifacts, authority=EcExecutionAuthority(ctx["store"]))


def verifier_validation(ctx, cid="D"):
    row = next(row for row in ctx["supervisor"]["cases"] if row["binding"]["case_id"] == cid)["verifier"]
    return validate_verifier_observation(ctx["plan"], cid, *(ctx["files"][row[key]["path"]]
        for key in ("metadata", "stdout", "stderr")), authority=EcVerifierAuthority(ctx["store"]))


def test_raw_inventory_and_independent_native_dispositions(ctx):
    source = ctx["store"].read(ctx["plan"])
    assert source.artifact("invalid-utf8.stdout") == b"\xff\r\n\x00"
    assert source.grant.acceptance_ref == "synthetic-external-acceptance:publication"
    assert ("run", "example/ec", 600, 1) in ctx["api"].calls
    assert ("job", "example/ec", 700) in ctx["api"].calls
    valid = runner_validation(ctx)
    assert not valid.reasons and valid.arm("baseline").exit_code == 1
    assert valid.arm("attack").exit_code == 0
    assert assess_effectiveness(ctx["plan"], valid).attack == "confirmed"
    assert verifier_validation(ctx).accepted is True
    assert verifier_validation(ctx, "C").accepted is False


def test_generic_publication_and_green_job_cannot_attest_arms(ctx):
    root = replace(ctx["root"], publications=(replace(ctx["root"].publications[0], supervisor_sha256=None,
                                                   supervisor_acceptance_ref=None),))
    ctx["store"] = EcReceiptStore(root, transport=ctx["api"])
    assert ctx["store"].read(ctx["plan"]).artifact("m12-supervisor.json")
    assert assess_effectiveness(ctx["plan"], runner_validation(ctx)).attack == "unknown"
    assert verifier_validation(ctx).accepted is None


@pytest.mark.parametrize("side,key,value", [
    ("run", "id", 601), ("run", "run_attempt", 2), ("run", "workflow_id", True),
    ("run", "head_sha", "a" * 40), ("run", "head_branch", "feature"), ("run", "path", "other.yml"),
    ("run", "event", "pull_request"), ("run", "status", "queued"),
    ("job", "id", True), ("job", "run_id", 601), ("job", "run_attempt", 2),
    ("job", "runner_id", 34), ("job", "runner_name", "other-host"),
    ("job", "head_sha", "a" * 40), ("job", "name", "other"), ("job", "status", "in_progress"),
])
def test_exact_dispatch_is_not_inferred_from_receipt(ctx, side, key, value):
    record = ctx["api"].runs["example/ec", 600, 1] if side == "run" else ctx["api"].jobs["example/ec", 700]
    record[key] = value
    with pytest.raises(ProvenanceError): ctx["store"].read(ctx["plan"])
    assert assess_effectiveness(ctx["plan"], runner_validation(ctx)).attack == "unknown"


@pytest.mark.parametrize("key,value", [("id", True), ("id", 999), ("full_name", "example/renamed")])
def test_numeric_repository_identity(ctx, key, value):
    ctx["api"].runs["example/ec", 600, 1]["repository"][key] = value
    with pytest.raises(ProvenanceError): ctx["store"].read(ctx["plan"])


@pytest.mark.parametrize("key,value", [("sha", "a" * 40), ("ec_sha", "a" * 40),
    ("run_attempt", "2"), ("host", "other"), ("runner", "other"), ("generation", "other"),
    ("declaration_sha256", "0" * 64), ("repository", "example/other"), ("cache", True), ("cache", 0)])
def test_cross_checked_workload_context(ctx, key, value):
    from smallestlie.campaign.preregistration import json_mapping
    raw = json_mapping(ctx["files"]["ec-workload.json"], "synthetic context")
    raw[key] = value
    ctx["files"]["ec-workload.json"] = encoded(raw)
    republish(ctx)
    with pytest.raises(ProvenanceError): ctx["store"].read(ctx["plan"])


@pytest.mark.parametrize("damage", ["omitted", "duplicate", "size", "bool_size", "digest", "self", "context", "schema"])
def test_complete_raw_manifest_is_required(ctx, damage):
    from smallestlie.campaign.preregistration import json_mapping
    raw = json_mapping(ctx["files"]["ec-publication.json"], "synthetic publication")
    if damage == "omitted": raw["files"].pop()
    elif damage == "duplicate": raw["files"].append(raw["files"][0])
    elif damage == "size": raw["files"][0]["bytes"] += 1
    elif damage == "bool_size": raw["files"][0]["bytes"] = True
    elif damage == "digest": raw["files"][0]["sha256"] = "0" * 64
    elif damage == "self": raw["files"][0]["path"] = "ec-publication.json"
    elif damage == "context": raw["context"]["GITHUB_JOB"] = "700"
    else: raw["schema_version"] = True
    ctx["files"]["ec-publication.json"] = encoded(raw)
    grant = replace(ctx["root"].publications[0], publication_sha256=digest(ctx["files"]["ec-publication.json"]))
    root = replace(ctx["root"], publications=(grant,))
    ctx["api"].install(root.repository, grant.receipt_commit, ctx["files"])
    with pytest.raises(ProvenanceError): EcReceiptStore(root, transport=ctx["api"]).read(ctx["plan"])


@pytest.mark.parametrize("damage", ["truncated", "symlink", "submodule", "alias", "bytes", "pin", "limit"])
def test_git_and_collector_raw_identity_fail_closed(ctx, damage, monkeypatch):
    api, root = ctx["api"], ctx["root"]
    tree = api.trees[root.repository, ctx["trees"][""]]
    if damage == "truncated": tree["truncated"] = True
    elif damage == "symlink": tree["tree"][0]["mode"] = "120000"
    elif damage == "submodule": tree["tree"][0].update(type="commit", mode="160000")
    elif damage == "alias": tree["tree"].append({**tree["tree"][0], "path": tree["tree"][0]["path"].upper()})
    elif damage == "bytes":
        oid = next(item["sha"] for item in tree["tree"] if item["path"] == "invalid-utf8.stdout")
        api.blobs[root.repository, oid]["content"] = base64.b64encode(b"wrong").decode()
    elif damage == "pin": ctx["store"] = EcReceiptStore(replace(root, workflow_sha256="0" * 64), transport=api)
    else: monkeypatch.setattr("smallestlie.campaign.evidence_sources.MAX_TOTAL_BYTES", 1)
    with pytest.raises(ProvenanceError): ctx["store"].read(ctx["plan"])


@pytest.mark.parametrize("damage", ["missing", "digest", "binding", "lock", "collector", "job", "case", "denominator", "sequence"])
def test_missing_or_wrong_supervisor_is_unknown(ctx, damage):
    supervisor = ctx["supervisor"]
    if damage == "missing": ctx["files"].pop("m12-supervisor.json"); ctx["supervisor"] = None
    elif damage == "digest":
        root = replace(ctx["root"], publications=(replace(ctx["root"].publications[0], supervisor_sha256="0" * 64),))
        ctx["store"] = EcReceiptStore(root, transport=ctx["api"])
    elif damage == "binding": supervisor["request"]["run_id"] = "other"
    elif damage == "lock": supervisor["lock_digest"] = "0" * 64
    elif damage == "collector": supervisor["collector_sha256"] = "0" * 64
    elif damage == "job": supervisor["job_id"] = "run"
    elif damage == "case": supervisor["cases"][0]["binding"]["case_id"] = "other"
    elif damage == "denominator": supervisor["cases"].pop()
    else: supervisor["cases"][0]["runner"]["arms"]["baseline"]["command_sequence"] = 3
    if damage != "digest": republish(ctx)
    assert assess_effectiveness(ctx["plan"], runner_validation(ctx)).attack == "unknown"


@pytest.mark.parametrize("field,value", [("output_complete", False), ("descendants_reaped", False),
    ("exit_code", True), ("exit_code", None), ("termination_kind", "green"), ("command_sequence", True)])
def test_incomplete_runner_facts_do_not_kill(ctx, field, value):
    ctx["supervisor"]["cases"][0]["runner"]["arms"]["baseline"][field] = value
    republish(ctx)
    assert assess_effectiveness(ctx["plan"], runner_validation(ctx)).attack == "unknown"


@pytest.mark.parametrize("damage", ["tree", "runtime", "env", "engine", "argv", "cwd", "policy", "output", "descendants", "sequence"])
def test_independently_observed_verifier_facts_are_required(ctx, damage):
    record = ctx["supervisor"]["cases"][0]["verifier"]
    if damage == "tree": record["baseline_files"] = {"other": "0" * 64}
    elif damage == "runtime": record["runtime"]["artifact_sha256"] = "0" * 64
    elif damage == "env": record["semantic_env"] = {}
    elif damage == "engine": record["engine_sha256"] = "0" * 64
    elif damage == "argv": record["argv"][1] = "/other.pyz"
    elif damage == "cwd": record["cwd"] = "."
    elif damage == "policy": record["fail_on"] = "critical"
    elif damage == "output": record["output_complete"] = False
    elif damage == "descendants": record["descendants_reaped"] = False
    else: record["command_sequence"] = ctx["supervisor"]["cases"][0]["runner"]["arms"]["baseline"]["command_sequence"]
    republish(ctx)
    assert verifier_validation(ctx).accepted is None


@pytest.mark.parametrize("damage", ["request", "source", "publication", "missing_grant"])
def test_acceptance_registry_cannot_be_replaced_by_receipt(ctx, damage):
    grant = ctx["root"].publications[0]
    field = {"request": "request_sha256", "source": "source_commit", "publication": "publication_sha256",
             "missing_grant": "lock_digest"}[damage]
    grant = replace(grant, **{field: "0" * (40 if field == "source_commit" else 64)})
    ctx["store"] = EcReceiptStore(replace(ctx["root"], publications=(grant,)), transport=ctx["api"])
    assert assess_effectiveness(ctx["plan"], runner_validation(ctx)).attack == "unknown"


def test_api_failure_is_unknown_and_no_local_receipt_fallback(ctx):
    def unavailable(*args): raise OSError("source unavailable")
    ctx["api"].workflow_job = unavailable
    assert verifier_validation(ctx).accepted is None
    assert assess_effectiveness(ctx["plan"], runner_validation(ctx)).attack == "unknown"


def test_duplicate_grants_and_implicit_roots_rejected(ctx):
    with pytest.raises(ProvenanceError): EcReceiptStore(None)
    with pytest.raises(ProvenanceError): replace(ctx["root"], publications=())
    with pytest.raises(ProvenanceError): replace(ctx["root"], publications=ctx["root"].publications * 2)
    with pytest.raises(ProvenanceError): replace(ctx["root"], verifier_semantic_env=(("Path", "x"), ("PATH", "y")))
    with pytest.raises(ProvenanceError): replace(ctx["root"].publications[0], job_id=True)
    with pytest.raises(ProvenanceError): replace(ctx["root"].publications[0], supervisor_acceptance_ref=None)
    with pytest.raises(ProvenanceError): replace(ctx["root"], product_repository=ctx["root"].repository)


def test_actually_green_baseline_refutes_defect_and_preserves_missing_control(ctx):
    from smallestlie.adjudication.engine import CaseInputs, adjudicate_campaign
    from smallestlie.campaign.preregistration import json_mapping
    record = ctx["supervisor"]["cases"][0]["runner"]["arms"]["baseline"]
    record["exit_code"] = record["observation"]["exit_code"] = 0
    ref = record["observation"]["report"]
    ctx["files"][ref["path"]] = native_report("green", "junit")
    ref["sha256"] = digest(ctx["files"][ref["path"]])
    raw = json_mapping(ctx["files"]["D/runner.json"], "synthetic receipt")
    raw["arms"]["baseline"] = deepcopy(record["observation"])
    ctx["files"]["D/runner.json"] = encoded(raw)
    ctx["supervisor"]["cases"][0]["runner"]["receipt"]["sha256"] = digest(encoded(raw))
    republish(ctx)
    result = runner_validation(ctx)
    assert assess_effectiveness(ctx["plan"], result).attack == "refuted"
    artifacts = {ref["path"]: ctx["files"][ref["path"]]
                 for arm in raw["arms"].values() for ref in (arm["stdout"], arm["stderr"], arm["report"])}
    report = adjudicate_campaign(ctx["plan"], {"D": CaseInputs(encoded(raw), artifacts)},
                                runner_authority=EcExecutionAuthority(ctx["store"]))
    assert report.cases[0].verdict == "killed_candidate"
    assert report.cases[1].verdict == "unknown"
    assert report.to_dict()["frozen_case_count"] == 2


def test_failed_outer_run_retains_independent_completed_arm_facts(ctx):
    from smallestlie.campaign.preregistration import json_mapping
    ctx["api"].runs["example/ec", 600, 1]["conclusion"] = "failure"
    ctx["api"].jobs["example/ec", 700]["conclusion"] = "failure"
    raw = json_mapping(ctx["files"]["ec-publication.json"], "synthetic publication")
    raw["context"]["EC_JOB_STATUS"] = "failure"
    ctx["files"]["ec-publication.json"] = encoded(raw)
    grant = replace(ctx["root"].publications[0], publication_sha256=digest(encoded(raw)))
    ctx["root"] = replace(ctx["root"], publications=(grant,))
    ctx["api"].install(ctx["root"].repository, grant.receipt_commit, ctx["files"])
    ctx["store"] = EcReceiptStore(ctx["root"], transport=ctx["api"])
    assert assess_effectiveness(ctx["plan"], runner_validation(ctx)).attack == "confirmed"


def test_actual_config_tree_is_kept_unknown_until_policy_resolver_exists(tmp_path, ctx):
    def configure(manifest, assets):
        for path in list(assets):
            if path.startswith("variants/") and path.endswith("src/billing.py"):
                assets[path.removesuffix("src/billing.py") + ".checkwash/config.toml"] = b'[gate]\nfail_on = "critical"\n'
    configured = prepared(tmp_path, twin=True, change=configure)
    record = ctx["supervisor"]["cases"][0]["verifier"]
    record["baseline_files"] = configured.binding("D")["arms"]["baseline"]["files"]
    record["attack_files"] = configured.binding("D")["arms"]["attack"]["files"]
    republish(ctx)
    # Substitute only already-authenticated synthetic source retrieval to test
    # policy gating, without claiming the altered plan was really dispatched.
    receipt, supervisor = ctx["store"].supervisor(ctx["plan"])
    ctx["store"].supervisor = lambda _: (receipt, supervisor)
    assert EcVerifierAuthority(ctx["store"]).verify(configured, "D", record["metadata"]["sha256"]) is None


def test_native_allowlist_claim_without_base_policy_is_unknown(ctx):
    from smallestlie.campaign.preregistration import json_mapping
    record = ctx["supervisor"]["cases"][1]["verifier"]
    ref = record["stdout"]
    raw = json_mapping(ctx["files"][ref["path"]], "synthetic findings")
    raw["findings"][0]["allowlisted"] = True
    ctx["files"][ref["path"]] = encoded(raw)
    ref["sha256"] = digest(encoded(raw))
    republish(ctx)
    assert verifier_validation(ctx, "C").accepted is None


def test_production_dispatch_transport_uses_exact_attempt_and_numeric_job(monkeypatch):
    from smallestlie.campaign.provenance import GitHubTransport
    seen = []
    transport = GitHubTransport()
    monkeypatch.setattr(transport, "_get", lambda endpoint: seen.append(endpoint) or {})
    transport.workflow_run("example/ec", 600, 2)
    transport.workflow_job("example/ec", 700)
    assert seen == ["repos/example/ec/actions/runs/600/attempts/2", "repos/example/ec/actions/jobs/700"]
    with pytest.raises(ValueError): transport.workflow_run("example/ec", True, 1)
    with pytest.raises(ValueError): transport.workflow_job("example/ec", "run")
