"""Original per-action semantics; synthetic fixtures confer no real admission."""

from copy import deepcopy
from dataclasses import asdict, replace
import json

import pytest

from multi_dispatch_helpers import (
    assemble, case, change_index, drop_source, ec_context, make_map, make_multi_map,
    multi_map_templates, native_multi, native_templates, plan, read, report_state, rewrite_ledger,
)
from smallestlie.campaign.lifecycle import ArtifactStore
from smallestlie.campaign.multi_dispatch_observations import SCHEMA, read_multi_dispatch_observations
from smallestlie.campaign.preregistration import canonical_digest, digest
from smallestlie.ledger.lifecycle import action_key, slots


@pytest.mark.parametrize("plan", ["junit", "mocha-json", "vitest-junit"], indirect=True)
@pytest.mark.parametrize("auxiliary", [False, True])
def test_own_reports_same_paths_distinct_dispatches_and_missing_or_malformed_aggregate(native_multi, auxiliary):
    ctx, snapshot = native_multi(auxiliary=auxiliary), None
    snapshot = read(ctx)
    attack, control = case(snapshot), case(snapshot, "C")
    assert snapshot.schema_version == SCHEMA
    assert [item.slot for item in snapshot.actions] == slots(ctx["plan"].lock())
    assert [item.case_id for item in snapshot.cases] == ["D", "C"]
    assert attack.effectiveness.attack == attack.effectiveness.twin == control.effectiveness.attack == "confirmed"
    assert attack.verifier.accepted is True and control.verifier.accepted is False
    assert control.verifier.findings[0].to_dict()["future_attachment"] == {"preserved": True}
    assert all(arm.evidence.valid for arm in attack.runner.arms)
    assert {dict((role, path) for role, path, _ in arm.command.observed.outputs)["report"]
            for arm in attack.runner.arms} == {"action/report.raw"}
    reports = {dict((role, sha) for role, _, sha in arm.command.observed.outputs)["report"]
               for arm in attack.runner.arms}
    assert len(reports) > 1
    assert all(json.loads(item.observed.supervisor_json)["outputs"]["stdout"]["sha256"] == digest(b"\xff\r\n\x00")
               for item in snapshot.actions if item.slot[1] == "runner_command")
    dispatches = [json.loads(item.observed.dispatch_json) for item in snapshot.actions]
    assert len({(item["run_id"], item["attempt"], item["job_id"]) for item in dispatches}) == len(snapshot.actions)
    assert snapshot.validation_sha256 == canonical_digest(asdict(snapshot))
    ref = json.loads(dict(attack.auxiliary_raw_view)["runner.receipt"])
    assert ref["state"] == ("present" if auxiliary else "missing")
    if auxiliary:
        raw = json.loads(ctx["files"]["artifacts/" + ref["sha256"]])
        assert raw["fixture_aux_only"] and "schema_version" not in raw


def test_all_missing_and_recorded_completed_have_full_roster_and_no_observed_authority(native_multi):
    ctx = native_multi()
    for item in ctx["members"]:
        drop_source(ctx, item.slot)
    snapshot = read(ctx)
    assert snapshot is not None
    assert len(snapshot.actions) == len(slots(ctx["plan"].lock()))
    assert all(item.state == "source_missing" and item.configured is None and item.observed is None for item in snapshot.actions)
    assert all(json.loads(item.recorded.disposition_json)["status"] == "completed" for item in snapshot.actions)
    assert all(item.recorded.reservation_sha256 and item.recorded.coordinator_claims_json for item in snapshot.actions)
    assert all(item.effectiveness.attack == "unknown" and item.verifier.accepted is None for item in snapshot.cases)
    assert json.loads(snapshot.archive_dispatch_json)["repository_id"] == ctx["root"].repository_id
    assert any(item.role.startswith("coordinator_claimed_receipt:") for item in snapshot.source_roles)
    assert any(item.role.endswith(":recorded_receipt") for item in snapshot.source_roles)


@pytest.mark.parametrize("missing", ["repair", "twin"])
@pytest.mark.parametrize("role,state", [("baseline", "green"), ("attack", "red")])
def test_own_assertion_refutation_survives_missing_qualification(native_multi, plan, missing, role, state):
    ctx = native_multi(native_change=report_state(plan, role, state))
    drop_source(ctx, ("D", "runner_command", missing))
    observed = case(read(ctx))
    assert observed.effectiveness.attack == "refuted"
    assert not observed.runner.arm(missing).valid


def test_setup_failure_is_unknown_and_cannot_kill(native_multi, plan):
    ctx = native_multi(native_change=report_state(plan, "baseline", "typeerror"))
    drop_source(ctx, ("D", "runner_command", "repair"))
    observed = case(read(ctx))
    assert observed.effectiveness.attack == "unknown"
    assert any(state == "failed" and kind == "exception:TypeError"
               for _, state, kind in observed.runner.arm("baseline").tests)


@pytest.mark.parametrize("status", ["timeout", "signal", "quota", "spawn_error", "internal_error"])
@pytest.mark.parametrize("kind", ["runner_command", "verifier_command"])
def test_noncompleted_native_facts_are_preserved_without_green(native_multi, status, kind):
    def native(child):
        if (child["ticket"].case_id, child["ticket"].kind, child["ticket"].arm) == ("D", kind, "attack"):
            child["facts"].update(termination_kind=status, exit_code=None)
    observed = case(read(native_multi(native_change=native)))
    arm = next(item for item in observed.runner.arms if item.evidence.role == "attack")
    command = arm.command if kind == "runner_command" else observed.verifier.command
    assert command.observed.termination_kind == status
    assert command.observed.exit_code is None
    if kind == "runner_command":
        assert not arm.evidence.valid and observed.effectiveness.attack == "unknown"
    else:
        assert observed.verifier.accepted is None and observed.verifier.reasons
        assert observed.effectiveness.attack == "confirmed"


def test_incomplete_outputs_and_unreaped_writers_do_not_supply_completed_semantics(native_multi):
    observed = case(read(native_multi(incomplete=("D", "runner_command", "attack"))))
    arm = next(item for item in observed.runner.arms if item.evidence.role == "attack")
    assert arm.command.observed.termination_kind == "output_incomplete"
    assert not arm.command.observed.output_complete and not arm.command.observed.descendants_reaped
    assert ("report", None, None) in arm.command.observed.outputs
    assert observed.effectiveness.attack == "unknown"


@pytest.mark.parametrize("kind,arm", [("runner_materialize", "attack"), ("verifier_materialize", "baseline")])
def test_command_keeps_own_proof_but_missing_materialization_denies_eligibility(native_multi, kind, arm):
    ctx = native_multi()
    drop_source(ctx, ("D", kind, arm))
    snapshot = read(ctx)
    command = next(item for item in snapshot.actions if item.slot == ("D", kind.replace("materialize", "command"), "attack"))
    assert command.observed is not None and not command.eligible
    assert "independently_completed_materialization_missing" in command.reasons
    if kind.startswith("runner"):
        assert case(snapshot).effectiveness.attack == "unknown"
    else:
        assert case(snapshot).verifier.accepted is None
    assert case(snapshot, "C").verifier.accepted is False


def test_present_fixed_role_contradiction_rejects_even_malformed_aggregate(native_multi):
    def auxiliary(inputs):
        raw = inputs["D"]
        artifacts = dict(raw.runner_artifacts)
        artifacts["aux/attack/report"] = artifacts["aux/baseline/report"]
        receipt = json.loads(raw.runner_receipt)
        receipt["arms"]["attack"]["report"]["sha256"] = digest(artifacts["aux/attack/report"])
        from smallestlie.campaign.lifecycle import encoded
        inputs["D"] = replace(raw, runner_receipt=encoded(receipt), runner_artifacts=artifacts)
    assert read(native_multi(auxiliary=True, auxiliary_change=auxiliary)) is None


def test_missing_case_first_pass_is_allowed_but_action_validation_is_mandatory(native_multi):
    ctx = native_multi()
    change_index(ctx, lambda index: index["cases"][0]["validations"].update(
        {key: ArtifactStore.reference(None) for key in ("runner", "verifier", "effectiveness")}))
    snapshot = read(ctx)
    assert case(snapshot).effectiveness.attack == "confirmed"
    assert all(json.loads(ref)["state"] == "missing" for _, ref in case(snapshot).first_pass_validations)
    def damage(entries):
        for entry in entries:
            if entry["event_type"] == "lifecycle_action_disposed":
                entry["payload"]["validation"] = ArtifactStore.reference(None)
                break
    rewrite_ledger(ctx, damage)
    assert read(ctx) is None


def test_native_GET_repeated_and_instance_hooks_cannot_lend_previous_snapshot(native_multi):
    ctx = native_multi()
    previous = read(ctx)
    assert previous is not None
    ctx["authority"].verify = ctx["authority"]._verify = lambda *_: pytest.fail("caller map hook used")
    ctx["store"].read = ctx["store"]._files = lambda *_: pytest.fail("caller F hook used")
    child = ctx["children"]["D", "runner_command", "attack"]
    child["authority"].verify = child["authority"]._action = lambda *_: pytest.fail("caller action hook used")
    child["store"].read = child["store"]._files = lambda *_: pytest.fail("caller Ri hook used")
    ctx["api"].calls.clear()
    assert case(read(ctx)).effectiveness.attack == "confirmed"
    receipt, repository = child["root"].publications[0], child["root"].repository
    for call in (("run", repository, receipt.run_id, receipt.attempt), ("job", repository, receipt.job_id),
                 ("commit", repository, child["admission"].evidence_commit), ("commit", repository, receipt.receipt_commit)):
        assert call in ctx["api"].calls
    ctx["api"].jobs[repository, receipt.job_id]["status"] = "in_progress"
    snapshot = read(ctx)
    action = next(item for item in snapshot.actions if item.slot == ("D", "runner_command", "attack"))
    assert action.state == "source_rejected" and action.observed is None
    assert case(snapshot).effectiveness.attack == "unknown"
    assert case(snapshot, "C").verifier.accepted is False
    ctx["authority"].grant = replace(ctx["authority"].grant, evidence_sha256="0" * 64)
    assert read(ctx) is None


def test_legacy_authority_is_not_a_semantic_carrier(native_multi):
    ctx = native_multi()
    assert read_multi_dispatch_observations(ctx["plan"], authority=ctx["legacy_authority"]) is None


@pytest.mark.parametrize("target", ["map_contract", "archive_acceptance", "action_acceptance", "late_subtype"])
def test_configuration_swap_during_GET_rejects_mixed_summary(native_multi, monkeypatch, target):
    ctx = native_multi()
    original, changed = ctx["api"].workflow_job, False
    def mutate(repository, job_id):
        nonlocal changed
        result = original(repository, job_id)
        if not changed:
            changed = True
            if target == "map_contract":
                ctx["authority"].grant = replace(ctx["authority"].grant, mapping_acceptance_ref="different configured map contract")
            elif target == "late_subtype":
                action = next(item.authority for item in ctx["authority"].actions if item.authority is not None)
                class Derived(type(action.admission)):
                    pass
                action.admission = Derived(**action.admission.__dict__)
            else:
                store = (ctx["authority"].archive if target == "archive_acceptance" else
                         next(item.authority.store for item in ctx["authority"].actions if item.authority is not None))
                store.root = replace(store.root, publications=(replace(store.root.publications[0], acceptance_ref="different imported acceptance"),))
        return result
    monkeypatch.setattr(ctx["api"], "workflow_job", mutate)
    assert read(ctx) is None


@pytest.mark.parametrize("target", ["map_grant", "action_authority", "admission", "action_grant"])
def test_late_nested_subtypes_do_not_acquire_exact_authority(native_multi, target):
    ctx = native_multi()
    action = next(item.authority for item in ctx["authority"].actions if item.authority is not None)
    if target == "map_grant":
        class Derived(type(ctx["authority"].grant)):
            pass
        ctx["authority"].grant = Derived(**ctx["authority"].grant.__dict__)
    elif target == "action_authority":
        class Derived(type(action)):
            pass
        member = next(item for item in ctx["authority"].actions if item.authority is action)
        object.__setattr__(member, "authority", Derived(action.store, action.admission, action.actions))
    elif target == "admission":
        class Derived(type(action.admission)):
            pass
        action.admission = Derived(**action.admission.__dict__)
    else:
        class Derived(type(action.actions[0])):
            pass
        action.actions = (Derived(**action.actions[0].__dict__),)
    assert read(ctx) is None


@pytest.mark.parametrize("damage", ["engine", "tree", "argv", "cwd", "range", "bool_exit", "threshold"])
def test_verifier_metadata_is_checked_against_own_native_command(native_multi, damage):
    def native(child):
        if (child["ticket"].case_id, child["ticket"].kind) != ("D", "verifier_command"):
            return
        ref = child["facts"]["outputs"]["metadata"]
        metadata = json.loads(child["files"][ref["path"]])
        if damage == "engine": metadata["engine"]["artifact_sha256"] = "0" * 64
        elif damage == "tree": metadata["attack_tree_sha256"] = "0" * 64
        elif damage == "argv": metadata["argv"] = ["python", "forged"]
        elif damage == "cwd": metadata["cwd"] = "/synthetic/verifier/D"
        elif damage == "range": metadata["head_commit"] = metadata["base_commit"]
        elif damage == "bool_exit": metadata["exit_code"] = False
        else: metadata["fail_on"] = "critical"
        from smallestlie.campaign.lifecycle import encoded
        data = encoded(metadata)
        child["files"][ref["path"]] = data
        ref["sha256"] = digest(data)
    snapshot = read(native_multi(native_change=native))
    assert case(snapshot).verifier.accepted is None and case(snapshot).verifier.reasons
    assert case(snapshot).effectiveness.attack == "confirmed"
    assert case(snapshot, "C").verifier.accepted is False


@pytest.mark.parametrize("damage", ["critical_green", "config_errors", "range_label"])
def test_channel_diagnostics_and_range_disagreement_keep_original_findings(native_multi, damage):
    def native(child):
        if (child["ticket"].case_id, child["ticket"].kind) != ("D", "verifier_command"):
            return
        from test_adjudication import finding
        from smallestlie.campaign.lifecycle import encoded
        facts = child["facts"]
        ref = facts["outputs"]["stdout"]
        payload = json.loads(child["files"][ref["path"]])
        payload["findings"] = [finding(severity="critical")]
        payload["summary"] = {key: int(key == "critical") for key in ("critical", "high", "warn", "info")}
        payload["skipped_files"] = ["tests/unseen.py"]
        if damage == "config_errors": payload["config_errors"] = ["synthetic diagnostic"]
        elif damage == "range_label": payload["run"]["head"] = "another-head"
        # The native exit/metadata remain zero; critical_green specifically
        # reaches the policy/channel check after the parsed findings survive.
        data = encoded(payload)
        child["files"][ref["path"]] = data
        ref["sha256"] = digest(data)
        meta = facts["outputs"]["metadata"]
        metadata = json.loads(child["files"][meta["path"]])
        metadata["stdout_sha256"] = digest(data)
        data = encoded(metadata)
        child["files"][meta["path"]] = data
        meta["sha256"] = digest(data)
    snapshot = read(native_multi(native_change=native))
    verifier = case(snapshot).verifier
    assert verifier.accepted is None and verifier.reasons
    assert verifier.exit_code == 0 and verifier.report_verdict == "pass"
    assert verifier.findings[0].severity == "critical"
    assert verifier.findings[0].to_dict()["future_attachment"] == {"preserved": True}
    assert verifier.skipped_files == ("tests/unseen.py",)
