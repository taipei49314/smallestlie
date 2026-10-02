"""Synthetic single-action source contracts, never real collector admission."""

from copy import deepcopy
from dataclasses import replace
import json

import pytest

from test_evidence_sources import ctx as ec_context, plan, republish
from test_formal_lifecycle import begin, finish_action
from smallestlie.campaign.completion_source import (
    ADMISSION_SCHEMA, JOURNAL_SCHEMA, PUBLICATION_SCHEMA, SOURCE_SCHEMA,
    EcLifecycleCompletionAuthority, LifecycleActionGrant, LifecycleCollectorAdmission,
)
from smallestlie.campaign.lifecycle import COMPLETION_SCHEMA, encoded, output_roles, validate_completion
from smallestlie.campaign.preregistration import canonical_digest, digest
from smallestlie.campaign.provenance import ProvenanceError
from smallestlie.ledger.chain import Ledger
from smallestlie.ledger.lifecycle import action_key, prerequisites


def publish(ctx):
    """Explicitly rebuild synthetic immutable identities after fixture changes."""
    files, facts, ticket, dispatch = ctx["files"], ctx["facts"], ctx["ticket"], ctx["dispatch"]
    prefix_sha = digest(files["action/prefix.jsonl"])
    facts["prefix"] = {"path": "action/prefix.jsonl", "sha256": prefix_sha}
    journal = {"schema_version": JOURNAL_SCHEMA, "dispatch": dispatch, "epoch": "contract-epoch",
        "action_id": "contract-action", "reservation_sha256": canonical_digest(ticket.to_dict()),
        "prefix_sha256": prefix_sha, "context_sha256": ticket.context_sha256, "events": []}
    measurements = [
        ("ticket_durable_ack", {"prefix_sha256": prefix_sha, "reservation": ticket.to_dict()}),
        ("work_started", {key: facts[key] for key in ("context_sha256", "files", "command")}),
        ("termination_observed", {key: facts[key] for key in ("termination_kind", "exit_code")}),
        ("writer_disposition", {"descendants_reaped": facts["descendants_reaped"]}),
        ("outputs_sealed", {key: facts[key] for key in ("output_complete", "outputs")}),
    ]
    for seq, (name, measurement) in enumerate(measurements, 10):
        journal["events"].append({"event": name, "seq": seq, "facts_sha256": canonical_digest(measurement)})
    if ctx.get("journal_change"):
        ctx["journal_change"](journal)
    files["action/journal.json"] = encoded(journal)
    facts["journal"] = {"path": "action/journal.json", "sha256": digest(files["action/journal.json"])}
    files["action/facts.json"] = encoded(facts)
    closure = {"action/facts.json", "action/prefix.jsonl", "action/journal.json"}
    closure.update(ref["path"] for ref in facts["outputs"].values() if ref is not None)
    publication = {"schema_version": PUBLICATION_SCHEMA, "dispatch": dispatch,
        "reservation_sha256": canonical_digest(ticket.to_dict()), "files": [
            {"path": path, "bytes": len(files[path]), "sha256": digest(files[path])} for path in sorted(closure)]}
    if ctx.get("publication_change"):
        ctx["publication_change"](publication)
    files["action/publication.json"] = encoded(publication)
    wrapper = {"schema_version": COMPLETION_SCHEMA, "binding": ctx["context"]["binding"],
        "reservation": ticket.to_dict(), "context_sha256": ticket.context_sha256,
        **{key: facts[key] for key in ("files", "termination_kind", "exit_code", "output_complete", "descendants_reaped")},
        "outputs": {key: ref["sha256"] if ref is not None else None for key, ref in facts["outputs"].items()},
        "publication_sha256": digest(files["action/publication.json"]), "supervisor_sha256": digest(files["action/facts.json"])}
    files["action/completion.json"] = encoded(wrapper)
    if ctx.get("completion_change"):
        files["action/completion.json"] = ctx["completion_change"](files["action/completion.json"])
    action = LifecycleActionGrant(canonical_digest(ticket.to_dict()), "action/completion.json",
        digest(files["action/completion.json"]), "action/facts.json", digest(files["action/facts.json"]),
        "action/publication.json", digest(files["action/publication.json"]), "contract-epoch", "contract-action", 10, 14)
    ctx["action"] = action
    ctx["supervisor"] = None
    republish(ctx)
    ctx["authority"] = EcLifecycleCompletionAuthority(ctx["store"], ctx["admission"], (action,))


@pytest.fixture
def source(ec_context, tmp_path, plan, request):
    kind = getattr(request, "param", "runner_materialize")
    arm = "baseline" if kind.endswith("materialize") else "attack"
    session = begin(tmp_path, plan)
    for key in prerequisites("D", kind, arm):
        dep = session.plan[key]
        materialize = session.reserve_action("D", kind=dep["kind"], arm=dep["arm"])
        assert finish_action(session, materialize).valid
    ticket = session.reserve_action("D", kind=kind, arm=arm)
    context = session.plan[action_key("D", kind, arm)]
    ctx = ec_context
    root, grant = ctx["root"], ctx["root"].publications[0]
    dispatch = {"repository": root.repository, "repository_id": 202, "workflow_id": 300,
        "workflow_sha256": root.workflow_sha256, "collector_sha256": root.collector_sha256,
        "source_commit": plan.request.source_commit, "ec_source_commit": "e" * 40,
        "request_sha256": canonical_digest(plan.request.payload()), "lock_digest": plan.lock()["lock_digest"],
        "run_id": 600, "attempt": 1, "job_id": 700, "host": root.host, "generation": root.generation}
    contracts = {"collector": "synthetic accepted reservation-aware collector",
        "host_storage": "synthetic accepted host/storage durability",
        "prelaunch_journal": "synthetic accepted no-ACK-no-launch coordinator"}
    admission_bytes = encoded({"schema_version": ADMISSION_SCHEMA, "dispatch": dispatch, "contracts": contracts})
    ctx["api"].install(root.repository, "b" * 40, {"admissions/lifecycle.json": admission_bytes})
    admission = LifecycleCollectorAdmission(grant.request_sha256, grant.lock_digest, grant.source_commit,
        grant.ec_source_commit, 600, 1, 700, 202, 300, root.workflow_sha256, root.collector_sha256,
        root.host, root.generation, "b" * 40, "admissions/lifecycle.json", digest(admission_bytes),
        contracts["collector"], contracts["host_storage"], contracts["prelaunch_journal"])
    outputs, command = {}, None
    if kind == "runner_command":
        raw = json.loads(ctx["files"]["D/runner.json"])["arms"][arm]
        command = {key: raw[key] for key in ("runner", "runtime", "dependencies", "semantic_env", "workspace_root",
            "runtime_path", "argv", "cwd", "config")}
        outputs = {key: deepcopy(raw[key]) for key in output_roles(kind)}
    elif kind == "verifier_command":
        raw = next(item for item in ctx["supervisor"]["cases"] if item["binding"]["case_id"] == "D")["verifier"]
        command = {key: raw[key] for key in ("runtime", "engine_sha256", "semantic_env", "workspace_root",
            "runtime_path", "engine_path", "argv", "cwd", "logical_cwd", "base_commit", "head_commit", "fail_on")}
        outputs = {key: deepcopy(raw[key]) for key in output_roles(kind)}
    ctx.update(ticket=ticket, context=context, facts={"schema_version": SOURCE_SCHEMA, "dispatch": dispatch,
        "reservation": ticket.to_dict(), "context_sha256": ticket.context_sha256, "prefix": None, "journal": None,
        "files": deepcopy(context["files"]), "command": command, "termination_kind": "completed", "exit_code": 0,
        "output_complete": True, "descendants_reaped": True, "outputs": outputs},
        dispatch=dispatch, admission=admission, session=session)
    ctx["files"].pop("m12-supervisor.json")
    ctx["files"]["action/prefix.jsonl"] = session.ledger.path.read_bytes()
    publish(ctx)
    return ctx


def approval(ctx, **kwargs):
    return ctx["authority"].verify(ctx["plan"], kwargs.get("ticket", ctx["ticket"]),
        kwargs.get("sha", ctx["action"].completion_sha256))


def coherent_prefix(ctx, entries):
    """Regrant the changed chain/ticket so the deeper source guard is exercised."""
    ledger = Ledger(ctx["session"].ledger.path.parent / "coherent-prefix.jsonl")
    for entry in entries:
        last = ledger.append(entry["event_type"], entry["payload"])
    ctx["ticket"] = replace(ctx["ticket"], seq=last["seq"], entry_digest=last["entry_digest"])
    ctx["facts"]["reservation"] = ctx["ticket"].to_dict()
    ctx["files"]["action/prefix.jsonl"] = ledger.path.read_bytes()


@pytest.mark.parametrize("source", ["runner_materialize", "verifier_materialize", "runner_command", "verifier_command"], indirect=True)
def test_single_action_raw_sources_reach_completion_validator(source):
    envelope = approval(source)
    assert envelope is not None
    assert envelope.immutable_ref == "f" * 40
    assert envelope.collector_acceptance_ref == source["admission"].collector_acceptance_ref
    files, facts = source["files"], source["facts"]
    observed = validate_completion(source["plan"], source["ticket"], files["action/completion.json"],
        {"publication": files["action/publication.json"], "supervisor": files["action/facts.json"]},
        {key: files[ref["path"]] for key, ref in facts["outputs"].items()}, authority=source["authority"])
    assert observed.valid and observed.status == "completed", observed.reasons
    assert ("job", "example/ec", 700) in source["api"].calls
    assert source["store"].root.publications[0].supervisor_sha256 is None  # No v1 bridge.


@pytest.mark.parametrize("field,value", [
    ("job_id", 701), ("run_id", 601), ("attempt", 2), ("collector_sha256", "0" * 64),
    ("workflow_sha256", "0" * 64), ("host", "other-host"), ("generation", "other-generation"),
    ("source_commit", "0" * 40), ("request_sha256", "0" * 64), ("lock_digest", "0" * 64),
    ("evidence_sha256", "0" * 64), ("host_storage_acceptance_ref", "different-storage"),
    ("journal_acceptance_ref", "different-journal"),
])
def test_external_admission_requires_exact_dispatch_and_contracts(source, field, value):
    source["authority"] = EcLifecycleCompletionAuthority(source["store"], replace(source["admission"], **{field: value}), (source["action"],))
    assert approval(source) is None


def test_execution_archive_cannot_supply_its_own_admission(source):
    source["authority"] = EcLifecycleCompletionAuthority(source["store"],
        replace(source["admission"], evidence_commit="f" * 40), (source["action"],))
    assert approval(source) is None


def test_typed_grants_reject_bool_missing_admissions_and_identity_reuse(source):
    with pytest.raises(ValueError, match="job_id"):
        replace(source["admission"], job_id=True)
    with pytest.raises(ValueError, match="host_storage_acceptance_ref"):
        replace(source["admission"], host_storage_acceptance_ref="")
    with pytest.raises(ValueError, match="distinct"):
        replace(source["admission"], journal_acceptance_ref=source["admission"].collector_acceptance_ref)
    with pytest.raises(ProvenanceError, match="unique"):
        EcLifecycleCompletionAuthority(source["store"], source["admission"], (source["action"], source["action"]))
    with pytest.raises(ProvenanceError, match="unique"):
        EcLifecycleCompletionAuthority(source["store"], source["admission"], ())
    other = replace(source["action"], reservation_sha256="0" * 64, action_id="second-action",
        completion_path="second/completion.json", supervisor_path="second/facts.json", publication_path="second/publication.json")
    with pytest.raises(ProvenanceError, match="overlap"):
        EcLifecycleCompletionAuthority(source["store"], source["admission"], (source["action"], other))


@pytest.mark.parametrize("field,value", [("seq", True), ("seq", 9), ("entry_digest", "0" * 64),
    ("case_id", "C"), ("kind", "runner_command"), ("arm", "attack"), ("context_sha256", "0" * 64)])
def test_grant_cannot_be_borrowed_by_nearby_ticket(source, field, value):
    assert approval(source, ticket=replace(source["ticket"], **{field: value})) is None
    assert approval(source, sha="0" * 64) is None


@pytest.mark.parametrize("mutation", ["missing_ack", "late_ack", "bool_sequence", "reused_sequence", "wrong_epoch",
    "wrong_action", "wrong_prefix", "wrong_dispatch", "wrong_fact"])
def test_even_regranted_journal_requires_complete_prelaunch_order(source, mutation):
    def change(journal):
        if mutation == "missing_ack": journal["events"].pop(0)
        elif mutation == "late_ack": journal["events"][0]["seq"] = 99
        elif mutation == "bool_sequence": journal["events"][0]["seq"] = True
        elif mutation == "reused_sequence": journal["events"][1]["seq"] = journal["events"][0]["seq"]
        elif mutation == "wrong_epoch": journal["epoch"] = "borrowed-epoch"
        elif mutation == "wrong_action": journal["action_id"] = "borrowed-action"
        elif mutation == "wrong_prefix": journal["prefix_sha256"] = "0" * 64
        elif mutation == "wrong_dispatch": journal["dispatch"]["job_id"] = True
        else: journal["events"][2]["facts_sha256"] = "0" * 64
    source["journal_change"] = change
    # Deepcopy prevents mutating shared dispatch/facts while building the source.
    original = source["dispatch"]
    source["dispatch"] = deepcopy(original)
    publish(source)
    assert approval(source) is None


@pytest.mark.parametrize("mutation", ["chain", "bool_sequence", "tail", "v1", "plan", "lock", "missing_first"])
def test_even_regranted_prefix_must_be_full_exact_chain_and_final_ticket(source, mutation):
    entries = source["session"].ledger.read_entries()
    if mutation == "chain": entries[-1]["previous_entry_digest"] = "0" * 64
    elif mutation == "bool_sequence": entries[0]["seq"] = True
    elif mutation == "tail": entries.append(deepcopy(entries[-1]))
    elif mutation == "v1": entries[0]["payload"]["protocol"] = "smallestlie.m12/v1"
    elif mutation == "plan": entries[2]["payload"]["action_plan"] = {}
    elif mutation == "lock": entries[2]["payload"]["lock"]["source_commit"] = "0" * 40
    else: entries.pop(0)
    if mutation in {"chain", "bool_sequence"}:
        source["files"]["action/prefix.jsonl"] = b"".join(encoded(entry) + b"\n" for entry in entries)
    else:
        coherent_prefix(source, entries)
    publish(source)
    assert approval(source) is None


@pytest.mark.parametrize("source", ["runner_command"], indirect=True)
def test_prefix_cannot_reference_its_own_containing_final_commit(source):
    # Rebuild a coherent chain AND current ticket, avoiding a mere stale-hash failure.
    entries = source["session"].ledger.read_entries()
    for entry in entries:
        if entry["event_type"] == "lifecycle_action_disposed":
            entry["payload"]["provenance_ref"] = "f" * 40
    coherent_prefix(source, entries)
    publish(source)
    assert approval(source) is None


@pytest.mark.parametrize("mutation", ["extra", "missing", "duplicate", "wrapper", "global", "supervisor_self"])
def test_action_inventory_requires_exact_acyclic_closure(source, mutation):
    def change(publication):
        item = deepcopy(publication["files"][0])
        if mutation == "missing": publication["files"].pop()
        elif mutation == "duplicate": publication["files"].append(item)
        else:
            item["path"] = {"extra": "irrelevant", "wrapper": "action/completion.json",
                "global": "ec-publication.json", "supervisor_self": "action/publication.json"}[mutation]
            publication["files"].append(item)
    source["publication_change"] = change
    publish(source)
    assert approval(source) is None


@pytest.mark.parametrize("source", ["runner_command", "verifier_command"], indirect=True)
@pytest.mark.parametrize("field,value", [("runtime", {}), ("semantic_env", {}), ("argv", ["forged"]), ("cwd", "/elsewhere")])
def test_measured_runtime_and_command_cannot_be_replaced_by_expected_context_hash(source, field, value):
    source["facts"]["command"][field] = value
    publish(source)
    assert approval(source) is None


@pytest.mark.parametrize("field,value", [("exit_code", True), ("output_complete", 1), ("descendants_reaped", 1),
    ("termination_kind", "unknown"), ("files", {"baseline": {}}), ("command", {})])
def test_observed_fact_shapes_and_completed_dispositions_are_strict(source, field, value):
    source["facts"][field] = value
    publish(source)
    assert approval(source) is None


@pytest.mark.parametrize("source", ["runner_command"], indirect=True)
def test_partial_output_disposition_keeps_its_actual_status(source):
    source["facts"].update(termination_kind="output_incomplete", exit_code=None,
        output_complete=False, descendants_reaped=False)
    source["facts"]["outputs"]["report"] = None
    publish(source)
    envelope = approval(source)
    assert envelope is not None and envelope.termination_kind == "output_incomplete"
    assert envelope.output_complete is False and envelope.descendants_reaped is False
    assert envelope.exit_code is None


@pytest.mark.parametrize("source", ["runner_command"], indirect=True)
def test_raw_inventory_and_outputs_cannot_borrow_existing_grant(source):
    path = source["facts"]["outputs"]["stdout"]["path"]
    source["files"][path] += b"\xff\r\n"
    source["api"].install("example/ec", "f" * 40, source["files"])
    assert approval(source) is None


@pytest.mark.parametrize("source", ["runner_command"], indirect=True)
def test_new_outer_inventory_cannot_hide_changed_output_from_action_source(source):
    path = source["facts"]["outputs"]["stdout"]["path"]
    source["files"][path] += b"\xff\r\n"
    republish(source)  # Only the generic outer inventory is newly accepted.
    source["authority"] = EcLifecycleCompletionAuthority(source["store"], source["admission"], (source["action"],))
    assert approval(source) is None


@pytest.mark.parametrize("source", ["runner_command"], indirect=True)
def test_accepted_raw_output_is_preserved_without_utf8_or_line_ending_normalization(source):
    path = source["facts"]["outputs"]["stdout"]["path"]
    raw = b"\xff\r\n\x00"
    source["files"][path] = raw
    source["facts"]["outputs"]["stdout"]["sha256"] = digest(raw)
    publish(source)
    envelope = approval(source)
    assert envelope is not None
    assert source["store"].read(source["plan"]).artifact(path) == raw
    assert envelope.outputs_sha256 == canonical_digest({
        key: ref["sha256"] for key, ref in source["facts"]["outputs"].items()})


def test_semantically_equivalent_completion_reencoding_cannot_borrow_raw_authority(source):
    original = source["files"]["action/completion.json"]
    source["completion_change"] = lambda data: (json.dumps(json.loads(data), indent=2) + "\n").encode()
    publish(source)  # Even accepting the new digest cannot skip the measured raw wrapper contract.
    assert source["files"]["action/completion.json"] != original
    assert approval(source) is None


def test_generic_v1_supervisor_and_self_claimed_approval_are_not_sources(source):
    source["facts"]["schema_version"] = "smallestlie.outer-supervisor/v1"
    source["facts"]["approved"] = True
    publish(source)
    assert approval(source) is None
