"""Synthetic offline semantic contracts, with no actual admission or launch."""

from copy import deepcopy
from dataclasses import asdict, replace
import json

import pytest

from m12_helpers import native_report, prepared
from test_adjudication import finding
from test_source_map import assemble, drop_source, ec_context, make_map, rewrite_ledger, verify
from smallestlie.adjudication.observations import validate_verifier_observation
from smallestlie.campaign.completion_source import EcLifecycleCompletionAuthority
from smallestlie.campaign.lifecycle import ArtifactStore, encoded
from smallestlie.campaign.mapped_observations import SCHEMA, read_mapped_observations
from smallestlie.campaign.preregistration import canonical_digest, digest
from smallestlie.ledger.lifecycle import slots
from smallestlie.oracle.runner_evidence import validate_runner_receipt


@pytest.fixture(scope="module")
def plan(tmp_path_factory, request):
    return prepared(tmp_path_factory.mktemp("mapped-semantics"), twin=True,
                    report_format=getattr(request, "param", "junit"))


@pytest.fixture
def semantic(make_map):
    return make_map(semantic=True)


def read(ctx):
    return read_mapped_observations(ctx["plan"], authority=ctx["authority"])


def case(snapshot, cid="D"):
    assert snapshot is not None
    return next(item for item in snapshot.cases if item.case_id == cid)


def report_state(plan, role, state):
    def change(child):
        if child["ticket"].case_id != "D" or child["ticket"].kind != "runner_command" or child["ticket"].arm != role:
            return
        facts = child["facts"]
        ref = facts["outputs"]["report"]
        data = native_report(state, plan.profile("D")["report_format"])
        child["files"][ref["path"]] = data
        ref["sha256"] = digest(data)
        facts["exit_code"] = 1 if state in {"red", "typeerror"} else 0
    return change


def replace_capture(inputs, cid, field, mutation):
    raw = getattr(inputs[cid], field)
    decoded = json.loads(raw)
    mutation(decoded)
    inputs[cid] = replace(inputs[cid], **{field: encoded(decoded)})


def change_index(ctx, mutation):
    entries = [json.loads(line) for line in ctx["files"]["archive/ledger.jsonl"].splitlines()]
    ref = entries[-1]["payload"]["index"]
    index = json.loads(ctx["files"]["artifacts/" + ref["sha256"]])
    mutation(index)
    data = encoded(index)
    ctx["files"]["artifacts/" + digest(data)] = data
    rewrite_ledger(ctx, lambda rows: rows[-1]["payload"].update(index=ArtifactStore.reference(data)))


@pytest.mark.parametrize("plan", ["junit", "mocha-json", "vitest-junit"], indirect=True)
def test_native_reports_from_distinct_sources_and_detectable_near_shape(make_map):
    ctx = make_map(semantic=True)
    snapshot = read(ctx)
    attack, twin = case(snapshot), case(snapshot, "C")
    assert snapshot.schema_version == SCHEMA
    assert [item.slot for item in snapshot.actions] == slots(ctx["plan"].lock())
    assert [item.case_id for item in snapshot.cases] == ["D", "C"]
    assert attack.effectiveness.attack == attack.effectiveness.twin == "confirmed"
    assert twin.effectiveness.attack == "confirmed"
    assert attack.verifier.accepted is True and twin.verifier.accepted is False
    assert twin.verifier.findings[0].rule == "TEST_DISABLED"
    assert twin.verifier.findings[0].to_dict()["future_attachment"] == {"preserved": True}
    binding = ctx["plan"].binding("D")
    assert binding["arms"]["baseline"]["production"] == binding["arms"]["attack"]["production"] == binding["arms"]["twin"]["production"]
    sources = [item.action_receipt_ref for item in snapshot.actions]
    assert len(sources) == len(set(sources))
    assert not set(sources) & {snapshot.prelaunch_anchor_ref, snapshot.final_archive_ref, snapshot.mapping_evidence_ref}
    assert all(arm.evidence.valid for arm in attack.runner.arms)
    assert attack.runner.arms[0].captures
    assert snapshot.validation_sha256 == canonical_digest(asdict(snapshot))
    assert snapshot.validation_sha256 != snapshot.mapping_sha256


def test_raw_only_map_is_not_semantic_evidence(make_map):
    ctx = make_map()
    assert verify(ctx) is not None
    snapshot = read(ctx)
    assert snapshot is not None
    assert all(item.runner.receipt_sha256 is None and item.verifier.accepted is None for item in snapshot.cases)
    assert case(snapshot).effectiveness.attack == "unknown"
    assert len(snapshot.actions) == len(slots(ctx["plan"].lock()))


def test_all_missing_sources_stay_in_the_denominator(make_map):
    ctx = make_map(selected=set(), semantic=True)
    snapshot = read(ctx)
    assert snapshot is not None
    assert all(item.state == "source_missing" and item.action_receipt_ref is None for item in snapshot.actions)
    assert [item.case_id for item in snapshot.cases] == ["D", "C"]
    assert all(item.effectiveness.attack == "unknown" and item.verifier.accepted is None for item in snapshot.cases)


@pytest.mark.parametrize("missing", ["repair", "twin"])
@pytest.mark.parametrize("role,state", [("baseline", "green"), ("attack", "red")])
def test_independent_refutation_survives_missing_twin_or_repair(make_map, plan, missing, role, state):
    ctx = make_map(semantic=True, mutate_native=report_state(plan, role, state))
    drop_source(ctx, ("D", "runner_command", missing))
    observed = case(read(ctx))
    assert observed.effectiveness.attack == "refuted"
    assert not observed.runner.arm(missing).valid
    assert observed.runner.arm(role).valid


@pytest.mark.parametrize("missing", ["repair", "twin"])
def test_missing_qualification_arm_does_not_invent_success(semantic, missing):
    drop_source(semantic, ("D", "runner_command", missing))
    observed = case(read(semantic))
    assert observed.effectiveness.attack == ("unknown" if missing == "repair" else "confirmed")
    assert observed.effectiveness.twin == "unknown"
    assert observed.runner.arm("baseline").valid and observed.runner.arm("attack").valid


@pytest.mark.parametrize("kind,role", [("runner_materialize", "attack"), ("verifier_materialize", "baseline"), ("verifier_materialize", "attack")])
def test_own_command_proof_requires_completed_materialization(semantic, kind, role):
    drop_source(semantic, ("D", kind, role))
    snapshot = read(semantic)
    observed = case(snapshot)
    command = next(item for item in snapshot.actions if item.slot == ("D", kind.replace("materialize", "command"), "attack"))
    assert command.action_receipt_ref is not None and not command.eligible
    assert "independently_completed_materialization_missing" in command.reasons
    if kind.startswith("runner"):
        assert not observed.runner.arm("attack").valid and observed.effectiveness.attack == "unknown"
    else:
        assert observed.verifier.accepted is None


@pytest.mark.parametrize("status", ["timeout", "signal", "quota", "internal_error"])
def test_eligible_noncompleted_command_cannot_supply_green(make_map, status):
    def change(child):
        if child["ticket"].case_id == "D" and child["ticket"].kind == "runner_command" and child["ticket"].arm == "attack":
            child["facts"].update(termination_kind=status, exit_code=None)
    ctx = make_map(semantic=True, mutate_native=change)
    observed = case(read(ctx))
    arm = next(item for item in observed.runner.arms if item.evidence.role == "attack")
    assert arm.command.eligible and arm.command.termination_kind == status
    assert not arm.evidence.valid and observed.effectiveness.attack == "unknown"


def test_incomplete_native_outputs_remain_unknown(make_map):
    ctx = make_map(semantic=True, incomplete=("D", "runner_command", "attack"))
    observed = case(read(ctx))
    arm = next(item for item in observed.runner.arms if item.evidence.role == "attack")
    assert arm.command.termination_kind == "output_incomplete"
    assert dict(arm.captures)["report"] is None
    assert not arm.evidence.valid and observed.effectiveness.attack == "unknown"


def test_rejected_source_retains_unrelated_semantics(semantic):
    slot = ("D", "runner_materialize", "attack")
    child = semantic["children"][slot]
    wrong = EcLifecycleCompletionAuthority(child["store"], replace(child["admission"], collector_acceptance_ref="unaccepted"), (child["action"],))
    semantic["members"] = tuple(replace(item, authority=wrong) if item.slot == slot else item for item in semantic["members"])
    assemble(semantic)
    snapshot = read(semantic)
    observed = case(snapshot)
    assert next(item for item in snapshot.actions if item.slot == slot).state == "source_rejected"
    assert observed.runner.arm("baseline").valid and observed.runner.arm("repair").valid
    assert observed.verifier.accepted is True
    assert case(snapshot, "C").effectiveness.attack == "confirmed"


@pytest.mark.parametrize("damage", ["runtime", "env", "fixture", "bool_exit", "argv", "arm_swap", "truncated"])
def test_aggregate_arm_cannot_replace_independently_measured_facts(make_map, damage):
    def change(inputs):
        def edit(raw):
            arm = raw["arms"]["attack"]
            if damage == "runtime": arm["runtime"] = {**arm["runtime"], "version": "forged"}
            elif damage == "env": arm["semantic_env"] = {"FORGED": "1"}
            elif damage == "fixture": arm["fixture"] = deepcopy(raw["arms"]["repair"]["fixture"])
            elif damage == "bool_exit": arm["exit_code"] = False
            elif damage == "argv": arm["argv"] = ["/synthetic/runtime", "not-tests"]
            elif damage == "arm_swap": raw["arms"]["attack"] = deepcopy(raw["arms"]["baseline"])
            else: arm["truncated"] = True
        replace_capture(inputs, "D", "runner_receipt", edit)
    observed = case(read(make_map(semantic=True, mutate_inputs=change)))
    assert not observed.runner.arm("attack").valid
    assert observed.runner.arm("baseline").valid and observed.runner.arm("repair").valid
    assert observed.effectiveness.attack == "unknown" and observed.verifier.accepted is True


@pytest.mark.parametrize("damage", ["dispatch", "case", "schema"])
def test_aggregate_header_cannot_borrow_another_run_or_case(make_map, damage):
    def change(inputs):
        def edit(raw):
            if damage == "dispatch": raw["job_id"] = "another-job"
            elif damage == "case": raw["binding"]["case_id"] = "C"
            else: raw["schema_version"] = "smallestlie.runner-receipt/v0"
        replace_capture(inputs, "D", "runner_receipt", edit)
    observed = case(read(make_map(semantic=True, mutate_inputs=change)))
    assert observed.runner.reasons and not any(arm.evidence.valid for arm in observed.runner.arms)
    assert observed.effectiveness.attack == "unknown" and observed.verifier.accepted is True


def test_raw_report_bytes_cannot_be_replaced_by_another_arm(make_map):
    def change(inputs):
        raw = inputs["D"]
        receipt = json.loads(raw.runner_receipt)
        artifacts = dict(raw.runner_artifacts)
        artifacts[receipt["arms"]["attack"]["report"]["path"]] = artifacts[receipt["arms"]["baseline"]["report"]["path"]]
        inputs["D"] = replace(raw, runner_artifacts=artifacts)
    observed = case(read(make_map(semantic=True, mutate_inputs=change)))
    assert not observed.runner.arm("attack").valid
    assert "raw_output_mismatch" in observed.runner.arm("attack").reasons[0]


@pytest.mark.parametrize("damage", ["case", "argv", "cwd", "engine", "range", "bool_exit", "threshold", "reencode"])
def test_verifier_metadata_must_match_own_native_command_bytes(make_map, damage):
    def change(inputs):
        raw = inputs["D"]
        metadata = json.loads(raw.verifier_metadata)
        if damage == "case": metadata["binding"]["case_id"] = "C"
        elif damage == "argv": metadata["argv"] = ["python", "forged"]
        elif damage == "cwd": metadata["cwd"] = "/synthetic/verifier/D"
        elif damage == "engine": metadata["engine"]["artifact_sha256"] = "0" * 64
        elif damage == "range": metadata["head_commit"] = metadata["base_commit"]
        elif damage == "bool_exit": metadata["exit_code"] = False
        elif damage == "threshold": metadata["fail_on"] = "critical"
        data = json.dumps(metadata, indent=2).encode() if damage == "reencode" else encoded(metadata)
        inputs["D"] = replace(raw, verifier_metadata=data)
    snapshot = read(make_map(semantic=True, mutate_inputs=change))
    observed = case(snapshot)
    assert observed.verifier.accepted is None
    assert observed.effectiveness.attack == "confirmed"
    assert case(snapshot, "C").verifier.accepted is False


@pytest.mark.parametrize("damage", ["schema", "drop_case", "reorder", "drop_action", "capture_alias", "bool_bytes", "first_pass", "first_pass_missing"])
def test_reaccepted_F_index_cannot_borrow_source_map_authority(semantic, damage):
    def change(index):
        if damage == "schema": index["schema_version"] = "forged"
        elif damage == "drop_case": index["cases"].pop()
        elif damage == "reorder": index["cases"].reverse()
        elif damage == "drop_action": index["actions"].pop(next(iter(index["actions"])))
        elif damage == "capture_alias": index["cases"][0]["captures"]["runner.attack.report"] = index["cases"][0]["captures"]["runner.baseline.report"]
        elif damage == "bool_bytes": index["cases"][0]["captures"]["runner.receipt"]["bytes"] = True
        elif damage == "first_pass": index["cases"][0]["validations"].pop("runner")
        else: index["cases"][0]["validations"]["runner"] = {"state": "missing", "sha256": None, "bytes": None}
    change_index(semantic, change)
    assert verify(semantic) is not None  # Structural map alone does not attest the index's semantics.
    assert read(semantic) is None


@pytest.mark.parametrize("damage", ["critical_green", "wrong_verdict", "allowlist", "range", "config_errors"])
def test_native_verifier_channel_disagreements_preserve_complete_findings(make_map, damage):
    def change(child):
        if child["ticket"].case_id != "D" or child["ticket"].kind != "verifier_command":
            return
        facts = child["facts"]
        ref = facts["outputs"]["stdout"]
        payload = json.loads(child["files"][ref["path"]])
        if damage in {"critical_green", "allowlist"}:
            payload["findings"] = [finding(severity="critical", allowlisted=damage == "allowlist")]
            payload["summary"]["critical"] = 1
        if damage == "wrong_verdict": payload["verdict"] = "block"
        if damage == "range": payload["run"]["base"] = "unrelated"
        if damage == "config_errors": payload["config_errors"] = ["synthetic diagnostic"]
        payload["skipped_files"] = ["tests/ignored.py"]
        data = encoded(payload)
        child["files"][ref["path"]] = data
        ref["sha256"] = digest(data)
        meta_ref = facts["outputs"]["metadata"]
        metadata = json.loads(child["files"][meta_ref["path"]])
        metadata["stdout_sha256"] = digest(data)
        child["files"][meta_ref["path"]] = encoded(metadata)
        meta_ref["sha256"] = digest(child["files"][meta_ref["path"]])
    observed = case(read(make_map(semantic=True, mutate_native=change)))
    assert observed.verifier.accepted is None and observed.verifier.reasons
    assert observed.verifier.skipped_files == ("tests/ignored.py",)
    if damage in {"critical_green", "allowlist"}:
        assert observed.verifier.findings[0].severity == "critical"
        assert observed.verifier.findings[0].to_dict()["before"]["span"] == [1, 13]
        assert observed.verifier.findings[0].to_dict()["future_attachment"] == {"preserved": True}


def test_old_first_pass_results_are_retained_but_recomputed(semantic):
    snapshot = read(semantic)
    observed = case(snapshot)
    ref = dict(observed.first_pass_validations)["runner"]
    old = json.loads(semantic["files"]["artifacts/" + ref])
    assert old["provenance_ref"] is None and old["reasons"]
    assert observed.effectiveness.attack == "confirmed"


def test_constructed_mapped_results_and_verify_hooks_cannot_authorize_reads(semantic):
    source = verify(semantic)
    assert source is not None
    assert read_mapped_observations(semantic["plan"], authority=source) is None
    assert read_mapped_observations(semantic["plan"], authority=source.runner("D")) is None
    semantic["authority"].verify = lambda prepared: source
    semantic["authority"].grant = replace(semantic["grant"], assembler_sha256="0" * 64)
    assert read(semantic) is None


def test_new_mapped_snapshots_do_not_open_legacy_authority(semantic):
    snapshot = read(semantic)
    observed = case(snapshot)
    class Carrier:
        def __init__(self, value): self.value = value
        def verify(self, *args): return self.value
    vchild = semantic["children"]["D", "verifier_command", "attack"]
    data = {role: vchild["files"][ref["path"]] for role, ref in vchild["facts"]["outputs"].items()}
    runner_data = json.loads(semantic["files"]["artifacts/" + observed.runner.receipt_sha256])
    artifacts = {ref["path"]: semantic["files"]["artifacts/" + ref["sha256"]]
        for arm in runner_data["arms"].values() for ref in (arm["stdout"], arm["stderr"], arm["report"])}
    runner = validate_runner_receipt(semantic["plan"], "D", encoded(runner_data), artifacts, authority=Carrier(observed.runner))
    verifier = validate_verifier_observation(semantic["plan"], "D", data["metadata"], data["stdout"], data["stderr"], authority=Carrier(observed.verifier))
    assert runner.reasons and verifier.accepted is None


def test_reader_writes_nothing_and_summary_binds_own_sources(semantic):
    session = semantic["session"]
    before = session.ledger.path.read_bytes(), {p.name: p.read_bytes() for p in session.artifacts.root.iterdir()}
    original = read(semantic)
    drop_source(semantic, ("D", "runner_command", "repair"))
    changed = read(semantic)
    assert original is not None and changed is not None
    assert original.validation_sha256 != changed.validation_sha256
    assert before == (session.ledger.path.read_bytes(), {p.name: p.read_bytes() for p in session.artifacts.root.iterdir()})
