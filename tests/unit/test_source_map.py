"""Offline synthetic source-map contracts; no real publisher/collector adoption."""

from copy import deepcopy
from dataclasses import asdict, replace
import json

import pytest

from m12_helpers import capture
from test_evidence_sources import ctx as ec_context, plan, republish
from test_formal_lifecycle import begin
from smallestlie.adjudication.observations import validate_verifier_observation
from smallestlie.campaign.completion_source import (
    ADMISSION_SCHEMA, JOURNAL_SCHEMA as ACTION_JOURNAL, PUBLICATION_SCHEMA, SOURCE_SCHEMA,
    EcLifecycleCompletionAuthority, LifecycleActionGrant, LifecycleCollectorAdmission, _dispatch,
)
from smallestlie.campaign.evidence_sources import EcReceiptStore
from smallestlie.campaign.lifecycle import ArtifactStore, COMPLETION_SCHEMA, encoded, output_roles
from smallestlie.campaign.preregistration import canonical_digest, digest
from smallestlie.campaign.provenance import ProvenanceError
from smallestlie.campaign.source_map import (
    ANCHOR_SCHEMA, ARCHIVE_SCHEMA, JOURNAL_SCHEMA, MAP_SCHEMA,
    EcLifecycleSourceMapAuthority, LifecycleAnchorGrant, LifecycleMappedAction,
    LifecycleSourceMapGrant, MappedRunnerSources, MappedVerifierSources,
)
from smallestlie.ledger.lifecycle import action_key, slots
from smallestlie.oracle.runner_evidence import validate_runner_receipt


class SourceRegistry:
    """Fixture routing to actual independent single-action readers, not JSON approval."""

    def __init__(self):
        self.authorities = {}

    def verify(self, prepared, ticket, completion_sha):
        authority = self.authorities.get(canonical_digest(ticket.to_dict()))
        return None if authority is None else authority.verify(prepared, ticket, completion_sha)


def publish_action(ctx, first, identity):
    files, facts, ticket = ctx["files"], ctx["facts"], ctx["ticket"]
    prefix_sha = digest(files["action/prefix.jsonl"])
    facts["prefix"] = {"path": "action/prefix.jsonl", "sha256": prefix_sha}
    journal = {"schema_version": ACTION_JOURNAL, "dispatch": ctx["dispatch"], "epoch": "map-epoch",
        "action_id": identity, "reservation_sha256": canonical_digest(ticket.to_dict()),
        "prefix_sha256": prefix_sha, "context_sha256": ticket.context_sha256, "events": []}
    measurements = [
        ("ticket_durable_ack", {"prefix_sha256": prefix_sha, "reservation": ticket.to_dict()}),
        ("work_started", {key: facts[key] for key in ("context_sha256", "files", "command")}),
        ("termination_observed", {key: facts[key] for key in ("termination_kind", "exit_code")}),
        ("writer_disposition", {"descendants_reaped": facts["descendants_reaped"]}),
        ("outputs_sealed", {key: facts[key] for key in ("output_complete", "outputs")}),
    ]
    for seq, (event, measurement) in enumerate(measurements, first):
        journal["events"].append({"event": event, "seq": seq, "facts_sha256": canonical_digest(measurement)})
    files["action/journal.json"] = encoded(journal)
    facts["journal"] = {"path": "action/journal.json", "sha256": digest(files["action/journal.json"])}
    files["action/facts.json"] = encoded(facts)
    closure = {"action/prefix.jsonl", "action/journal.json", "action/facts.json"}
    closure.update(ref["path"] for ref in facts["outputs"].values() if ref is not None)
    publication = {"schema_version": PUBLICATION_SCHEMA, "dispatch": ctx["dispatch"],
        "reservation_sha256": canonical_digest(ticket.to_dict()), "files": [
            {"path": path, "bytes": len(files[path]), "sha256": digest(files[path])} for path in sorted(closure)]}
    files["action/publication.json"] = encoded(publication)
    wrapper = {"schema_version": COMPLETION_SCHEMA, "binding": ctx["context"]["binding"],
        "reservation": ticket.to_dict(), "context_sha256": ticket.context_sha256,
        **{key: facts[key] for key in ("files", "termination_kind", "exit_code", "output_complete", "descendants_reaped")},
        "outputs": {role: ref["sha256"] if ref is not None else None for role, ref in facts["outputs"].items()},
        "publication_sha256": digest(files["action/publication.json"]), "supervisor_sha256": digest(files["action/facts.json"])}
    files["action/completion.json"] = encoded(wrapper)
    action = LifecycleActionGrant(canonical_digest(ticket.to_dict()), "action/completion.json",
        digest(files["action/completion.json"]), "action/facts.json", digest(files["action/facts.json"]),
        "action/publication.json", digest(files["action/publication.json"]), "map-epoch", identity, first, first + 4)
    republish(ctx)
    ctx["action"] = action
    ctx["authority"] = EcLifecycleCompletionAuthority(ctx["store"], ctx["admission"], (action,))


def record(member):
    source = None
    if member.authority is not None:
        action = member.authority.actions[0]
        source = {"receipt_commit": member.authority.store.root.publications[0].receipt_commit,
            "completion": {"path": action.completion_path, "sha256": action.completion_sha256},
            "supervisor": {"path": action.supervisor_path, "sha256": action.supervisor_sha256},
            "publication": {"path": action.publication_path, "sha256": action.publication_sha256},
            "publication_sequence": member.publication_sequence}
    return {"slot": {"case_id": member.case_id, "kind": member.kind, "arm": member.arm},
        "reservation": member.ticket.to_dict() if member.ticket is not None else None, "source": source}


def assemble(ctx, *, index_change=None, evidence_change=None):
    """Reaccept outer synthetic bytes, keeping per-action admissions unchanged."""
    files, anchor = ctx["files"], ctx["anchor"]
    records = [record(item) for item in ctx["members"]]
    index = {"schema_version": ARCHIVE_SCHEMA, "dispatch": ctx["dispatch"], "anchor": asdict(anchor),
        "ledger": {"path": "archive/ledger.jsonl", "sha256": digest(files["archive/ledger.jsonl"])},
        "journal": {"path": "archive/publisher.json", "sha256": digest(files["archive/publisher.json"])}, "actions": records}
    if index_change:
        index_change(index)
    files["archive/index.json"] = encoded(index)
    republish(ctx)
    evidence = {"schema_version": MAP_SCHEMA, "dispatch": ctx["dispatch"], "contracts": ctx["contracts"],
        "assembler": {"path": "trusted/assembler.py", "sha256": digest(ctx["assembler"])},
        "anchor": asdict(anchor), "final_archive": {"commit": ctx["root"].publications[0].receipt_commit,
            "publication_sha256": ctx["root"].publications[0].publication_sha256,
            "index": {"path": "archive/index.json", "sha256": digest(files["archive/index.json"])}}, "actions": records}
    if evidence_change:
        evidence_change(evidence)
    evidence_bytes = encoded(evidence)
    ctx["api"].install(ctx["root"].repository, "d" * 40, {"admissions/map.json": evidence_bytes})
    ctx["grant"] = LifecycleSourceMapGrant("d" * 40, "admissions/map.json", digest(evidence_bytes),
        "archive/index.json", digest(files["archive/index.json"]), "archive/ledger.jsonl", digest(files["archive/ledger.jsonl"]),
        "archive/publisher.json", digest(files["archive/publisher.json"]), "trusted/assembler.py", digest(ctx["assembler"]),
        anchor, ctx["contracts"]["anchor"], ctx["contracts"]["publisher"], ctx["contracts"]["mapping"])
    ctx["authority"] = EcLifecycleSourceMapAuthority(ctx["store"], ctx["grant"], ctx["members"])


@pytest.fixture
def make_map(ec_context, tmp_path, plan):
    def make(*, selected=None, incomplete=None):
        template, api, root = ec_context, ec_context["api"], ec_context["root"]
        registry = SourceRegistry()
        session = begin(tmp_path, plan, source=registry)
        locked_prefix = session.ledger.path.read_bytes()
        dispatch = _dispatch(template["store"], root.publications[0])
        anchor_bytes = encoded({"schema_version": ANCHOR_SCHEMA, "dispatch": dispatch,
            "lock_digest": plan.lock()["lock_digest"], "plan_sha256": canonical_digest(session.plan),
            "locked_prefix": {"path": "anchor/locked.jsonl", "sha256": digest(locked_prefix)}})
        api.install(root.repository, "a" * 40, {"anchor/record.json": anchor_bytes, "anchor/locked.jsonl": locked_prefix})
        anchor = LifecycleAnchorGrant("a" * 40, "anchor/record.json", digest(anchor_bytes),
            "anchor/locked.jsonl", digest(locked_prefix), "map-epoch", 1)
        contracts = {"collector": "synthetic collector accepted", "host_storage": "synthetic storage accepted",
            "prelaunch_journal": "synthetic ticket coordinator accepted"}
        admission_bytes = encoded({"schema_version": ADMISSION_SCHEMA, "dispatch": dispatch, "contracts": contracts})
        api.install(root.repository, "b" * 40, {"admissions/actions.json": admission_bytes})
        grant = root.publications[0]
        admission = LifecycleCollectorAdmission(grant.request_sha256, grant.lock_digest, grant.source_commit,
            grant.ec_source_commit, 600, 1, 700, 202, 300, root.workflow_sha256, root.collector_sha256,
            root.host, root.generation, "b" * 40, "admissions/actions.json", digest(admission_bytes),
            contracts["collector"], contracts["host_storage"], contracts["prelaunch_journal"])
        members, children, events, first = [], {}, [{"event": "anchor_durable_ack", "seq": 1,
            "facts": {"anchor_commit": anchor.commit, "anchor_sha256": anchor.sha256,
                "locked_prefix_sha256": anchor.prefix_sha256}}], 2
        for index, slot in enumerate(slots(plan.lock()), 1):
            cid, kind, arm = slot
            if selected is not None and slot not in selected:
                members.append(LifecycleMappedAction(*slot, None, None, None))
                continue
            ticket = session.reserve_action(cid, kind=kind, arm=arm)
            context = session.plan[action_key(*slot)]
            outputs, command, code = {}, None, 0
            if kind == "runner_command":
                raw = json.loads(template["files"][cid + "/runner.json"])["arms"][arm]
                command = {key: raw[key] for key in ("runner", "runtime", "dependencies", "semantic_env",
                    "workspace_root", "runtime_path", "argv", "cwd", "config")}
                outputs = {key: deepcopy(raw[key]) for key in output_roles(kind)}
                code = raw["exit_code"]
            elif kind == "verifier_command":
                raw = next(row for row in template["supervisor"]["cases"] if row["binding"]["case_id"] == cid)["verifier"]
                command = {key: raw[key] for key in ("runtime", "engine_sha256", "semantic_env", "workspace_root",
                    "runtime_path", "engine_path", "argv", "cwd", "logical_cwd", "base_commit", "head_commit", "fail_on")}
                outputs = {key: deepcopy(raw[key]) for key in output_roles(kind)}
                code = raw["exit_code"]
            child_files = {"ec-workload.json": template["files"]["ec-workload.json"],
                "action/prefix.jsonl": session.ledger.path.read_bytes()}
            for role, ref in outputs.items():
                data = b"\xff\r\n\x00" if kind == "runner_command" and role == "stdout" else template["files"][ref["path"]]
                child_files[ref["path"]] = data
                ref["sha256"] = digest(data)
            status = "output_incomplete" if slot == incomplete else "completed"
            if slot == incomplete:
                outputs["report"] = None
                code = None
            child = {"api": api, "root": replace(root, publications=(replace(grant, receipt_commit=f"{index:040x}"),)),
                "files": child_files, "supervisor": None, "ticket": ticket, "context": context, "admission": admission,
                "dispatch": dispatch, "facts": {"schema_version": SOURCE_SCHEMA, "dispatch": dispatch,
                    "reservation": ticket.to_dict(), "context_sha256": ticket.context_sha256, "prefix": None, "journal": None,
                    "files": deepcopy(context["files"]), "command": command, "termination_kind": status, "exit_code": code,
                    "output_complete": slot != incomplete, "descendants_reaped": slot != incomplete, "outputs": outputs}}
            publish_action(child, first, f"action-{index}")
            registry.authorities[canonical_digest(ticket.to_dict())] = child["authority"]
            validation = session.complete_action(ticket, child_files["action/completion.json"],
                sources={"publication": child_files["action/publication.json"], "supervisor": child_files["action/facts.json"]},
                outputs={role: child_files[ref["path"]] if ref is not None else None for role, ref in outputs.items()})
            assert validation.valid, validation.reasons
            receipt = child["root"].publications[0]
            events.append({"event": "action_publication_durable_ack", "seq": first + 5, "facts": {
                "reservation_sha256": canonical_digest(ticket.to_dict()), "receipt_commit": receipt.receipt_commit,
                "completion_sha256": child["action"].completion_sha256,
                "action_publication_sha256": child["action"].publication_sha256, "publication_sha256": receipt.publication_sha256}})
            members.append(LifecycleMappedAction(*slot, ticket, child["authority"], first + 5))
            children[slot] = child
            first += 6
        session.seal_observations({})  # Raw actions only; deliberately no semantic aggregate acceptance.
        files = {"ec-workload.json": template["files"]["ec-workload.json"],
            "archive/ledger.jsonl": session.ledger.path.read_bytes(),
            "archive/publisher.json": encoded({"schema_version": JOURNAL_SCHEMA, "dispatch": dispatch,
                "epoch": "map-epoch", "events": events})}
        files.update({"artifacts/" + path.name: path.read_bytes() for path in session.artifacts.root.iterdir()})
        assembler = b"synthetic externally accepted offline assembler and publisher contract"
        api.install(root.repository, "e" * 40, {root.workflow_path: b"synthetic external workflow",
            root.collector_path: plan.asset("contracts/collector.py"), "trusted/assembler.py": assembler})
        result = {"api": api, "root": root, "files": files, "supervisor": None, "plan": plan,
            "dispatch": dispatch, "anchor": anchor, "members": tuple(members), "children": children,
            "session": session, "assembler": assembler, "contracts": {"anchor": "synthetic anchor readback accepted",
                "publisher": "synthetic receipt delivery accepted", "mapping": "synthetic complete mapping accepted"}}
        assemble(result)
        return result
    return make


@pytest.fixture
def mapped(make_map):
    return make_map()


def verify(ctx):
    return ctx["authority"].verify(ctx["plan"])


def drop_source(ctx, slot):
    ctx["members"] = tuple(replace(item, authority=None, publication_sequence=None) if item.slot == slot else item
        for item in ctx["members"])
    assemble(ctx)


def change_publisher(ctx, mutation):
    raw = json.loads(ctx["files"]["archive/publisher.json"])
    mutation(raw)
    ctx["files"]["archive/publisher.json"] = encoded(raw)
    assemble(ctx)


def rewrite_ledger(ctx, mutation):
    """Recompute a coherent final chain, keeping the actual anchor and earlier sources."""
    from smallestlie.ledger.chain import payload_digest
    entries = [json.loads(line) for line in ctx["files"]["archive/ledger.jsonl"].splitlines()]
    mutation(entries)
    previous = "0" * 64
    for entry in entries:
        entry["payload_digest"] = payload_digest(entry["payload"])
        entry["previous_entry_digest"] = previous
        entry["entry_digest"] = payload_digest({key: entry[key] for key in
            ("seq", "timestamp", "event_type", "tool_version", "payload_digest", "previous_entry_digest")})
        previous = entry["entry_digest"]
    # Preserve native JSONL encoding, including Windows CRLF. Otherwise an unrelated
    # raw prefix reencoding would reject before the changed last disposition is checked.
    original = ctx["files"]["archive/ledger.jsonl"].splitlines(keepends=True)
    ctx["files"]["archive/ledger.jsonl"] = b"".join(original[:3]) + b"".join(
        json.dumps(entry, sort_keys=True, default=str).encode() + (b"\r\n" if line.endswith(b"\r\n") else b"\n")
        for entry, line in zip(entries[3:], original[3:]))
    assemble(ctx)


def test_distinct_acyclic_action_sources_preserve_full_slots_and_raw_bytes(mapped):
    result = verify(mapped)
    assert result is not None
    assert [item.slot for item in result.actions] == slots(mapped["plan"].lock())
    assert all(item.state == "observed" and item.eligible for item in result.actions)
    refs = {item.proof.action_receipt_ref for item in result.actions}
    assert len(refs) == len(result.actions)
    assert refs.isdisjoint({result.prelaunch_anchor_ref, result.final_archive_ref, result.mapping_evidence_ref})
    baseline = next(item for item in result.actions if item.slot == ("D", "runner_command", "baseline"))
    assert baseline.proof.validation.exit_code == 1
    assert dict(baseline.proof.outputs)["stdout"] == b"\xff\r\n\x00"
    attack = next(item for item in result.actions if item.slot == ("D", "runner_command", "attack"))
    assert attack.proof.validation.exit_code == 0
    assert isinstance(result.runner("D"), MappedRunnerSources)
    assert isinstance(result.verifier("D"), MappedVerifierSources)
    with pytest.raises(ProvenanceError, match="undeclared"):
        result.runner("undeclared")
    for child in mapped["children"].values():
        # Own Ri never serializes an ActionValidation with provenance_ref=Ri.
        assert all(not path.startswith("artifacts/") for path in child["files"])


def test_unobserved_slots_remain_in_complete_denominator(make_map):
    ctx = make_map(selected={("D", "runner_materialize", "baseline"), ("D", "runner_command", "baseline")})
    result = verify(ctx)
    assert result is not None
    assert [item.slot for item in result.actions] == slots(ctx["plan"].lock())
    assert all(item.state == "source_missing" and not item.eligible for item in result.actions if item.proof is None)
    assert next(item for item in result.actions if item.slot == ("D", "runner_command", "baseline")).eligible


def test_all_missing_does_not_create_authority_from_generic_green_archive(make_map):
    ctx = make_map(selected=set())
    result = verify(ctx)
    assert result is not None and result.actions
    assert all(item.state == "source_missing" and item.proof is None and not item.eligible for item in result.actions)


@pytest.mark.parametrize("slot", [("D", "runner_command", "repair"), ("C", "verifier_command", "attack")])
def test_unrelated_missing_proof_keeps_valid_baseline_attack_evidence(mapped, slot):
    drop_source(mapped, slot)
    result = verify(mapped)
    assert result is not None
    assert [item.slot for item in result.actions] == slots(mapped["plan"].lock())
    pair = [item for item in result.actions if item.slot[0] == "D" and item.slot[1] == "runner_command"
        and item.slot[2] in {"baseline", "attack"}]
    assert all(item.eligible and item.proof is not None for item in pair)
    assert next(item for item in result.actions if item.slot == slot).state == "source_missing"


@pytest.mark.parametrize("slot,dependent", [
    (("D", "runner_materialize", "baseline"), ("D", "runner_command", "baseline")),
    (("D", "verifier_materialize", "baseline"), ("D", "verifier_command", "attack")),
])
def test_missing_materialization_keeps_command_proof_but_denies_eligibility(mapped, slot, dependent):
    drop_source(mapped, slot)
    result = verify(mapped)
    assert result is not None
    observed = next(item for item in result.actions if item.slot == dependent)
    assert observed.state == "observed" and observed.proof is not None and not observed.eligible
    assert observed.reasons == ("independently_completed_materialization_missing",)


def test_native_incomplete_status_and_missing_output_are_preserved(make_map):
    slot = ("D", "runner_command", "attack")
    ctx = make_map(incomplete=slot)
    result = verify(ctx)
    assert result is not None
    proof = next(item for item in result.actions if item.slot == slot).proof
    assert proof.validation.status == "output_incomplete" and proof.validation.exit_code is None
    assert dict(proof.outputs)["report"] is None


@pytest.mark.parametrize("damage", ["drop", "extra", "duplicate"])
def test_full_map_cannot_filter_undeclared_or_duplicate_slots(mapped, damage):
    members = mapped["members"]
    if damage == "duplicate":
        with pytest.raises(ProvenanceError, match="unique"):
            EcLifecycleSourceMapAuthority(mapped["store"], mapped["grant"], members + members[:1])
        return
    mapped["members"] = members[:-1] if damage == "drop" else members + (
        LifecycleMappedAction("extra", "runner_materialize", "baseline", None, None, None),)
    assemble(mapped)
    assert verify(mapped) is None


@pytest.mark.parametrize("damage", ["evidence_sha256", "ledger_sha256", "journal_sha256", "archive_sha256", "assembler_sha256"])
def test_outer_green_cannot_replace_external_raw_grants(mapped, damage):
    grant = replace(mapped["grant"], **{damage: "0" * 64})
    assert EcLifecycleSourceMapAuthority(mapped["store"], grant, mapped["members"]).verify(mapped["plan"]) is None


def test_typed_mapping_grants_reject_bool_sequences_and_role_aliases(mapped):
    with pytest.raises(ValueError, match="ACK sequence"):
        replace(mapped["anchor"], ack_sequence=True)
    with pytest.raises(ProvenanceError, match="roles"):
        replace(mapped["anchor"], prefix_path=mapped["anchor"].path)
    with pytest.raises(ProvenanceError, match="roles"):
        replace(mapped["grant"], journal_path=mapped["grant"].ledger_path)
    with pytest.raises(ProvenanceError, match="separate"):
        replace(mapped["grant"], publisher_acceptance_ref=mapped["grant"].mapping_acceptance_ref)
    with pytest.raises(ProvenanceError, match="sequence"):
        replace(mapped["members"][0], publication_sequence=True)


@pytest.mark.parametrize("damage", ["anchor", "receipt"])
def test_source_roles_cannot_alias_final_archive(mapped, damage):
    if damage == "anchor":
        mapped["anchor"] = replace(mapped["anchor"], commit="f" * 40)
    else:
        member = mapped["members"][0]
        child = mapped["children"][member.slot]
        changed_root = replace(child["root"], publications=(replace(child["root"].publications[0], receipt_commit="f" * 40),))
        authority = EcLifecycleCompletionAuthority(EcReceiptStore(changed_root, transport=child["api"]), child["admission"], (child["action"],))
        mapped["members"] = (replace(member, authority=authority),) + mapped["members"][1:]
    assemble(mapped)
    assert verify(mapped) is None


@pytest.mark.parametrize("role", ["anchor", "map", "archive", "action"])
@pytest.mark.parametrize("input_role", ["ec", "product", "phase1"])
def test_output_roles_cannot_alias_immutable_inputs(mapped, role, input_role):
    ref = ("e" * 40 if input_role == "ec" else mapped["plan"].request.source_commit if input_role == "product" else
        mapped["plan"].lock()["phase1_commit"])
    if role == "anchor":
        mapped["anchor"] = replace(mapped["anchor"], commit=ref)
        assemble(mapped)
    elif role == "map":
        mapped["authority"] = EcLifecycleSourceMapAuthority(mapped["store"],
            replace(mapped["grant"], evidence_commit=ref), mapped["members"])
    elif role == "archive":
        root = replace(mapped["root"], publications=(replace(mapped["root"].publications[0], receipt_commit=ref),))
        # Synthetic install also preserves the pinned executed inputs when commits alias.
        files = dict(mapped["files"])
        if input_role == "ec":
            files.update({root.workflow_path: b"synthetic external workflow",
                root.collector_path: mapped["plan"].asset("contracts/collector.py"), "trusted/assembler.py": mapped["assembler"]})
        changed = {**mapped, "root": root, "files": files}
        republish(changed)
        mapped["authority"] = EcLifecycleSourceMapAuthority(changed["store"], mapped["grant"], mapped["members"])
    else:
        member = mapped["members"][0]
        child = mapped["children"][member.slot]
        root = replace(child["root"], publications=(replace(child["root"].publications[0], receipt_commit=ref),))
        authority = EcLifecycleCompletionAuthority(EcReceiptStore(root, transport=child["api"]), child["admission"], (child["action"],))
        mapped["members"] = (replace(member, authority=authority),) + mapped["members"][1:]
        assemble(mapped)
    assert verify(mapped) is None


def test_one_use_identity_cannot_be_reused_across_distinct_receipts(mapped):
    first, second = mapped["members"][:2]
    child = mapped["children"][second.slot]
    action = replace(child["action"], action_id=first.authority.actions[0].action_id)
    authority = EcLifecycleCompletionAuthority(child["store"], child["admission"], (action,))
    mapped["members"] = (first, replace(second, authority=authority)) + mapped["members"][2:]
    assemble(mapped)
    assert verify(mapped) is None


@pytest.mark.parametrize("field,value", [("job_id", 701), ("ec_source_commit", "0" * 40)])
def test_mapped_source_dispatch_cannot_be_borrowed_from_another_job(mapped, field, value):
    member = mapped["members"][0]
    child = mapped["children"][member.slot]
    root = replace(child["root"], publications=(replace(child["root"].publications[0], **{field: value}),))
    authority = EcLifecycleCompletionAuthority(EcReceiptStore(root, transport=child["api"]), child["admission"], (child["action"],))
    mapped["members"] = (replace(member, authority=authority),) + mapped["members"][1:]
    assemble(mapped)
    assert verify(mapped) is None


@pytest.mark.parametrize("damage", ["missing", "late_anchor", "wrong_anchor", "bool", "epoch", "duplicate", "seal_order",
    "next_work", "receipt", "completion", "publication", "ticket", "reverse"])
def test_reaccepted_publisher_journal_still_requires_native_acyclic_order(mapped, damage):
    def change(raw):
        events = raw["events"]
        if damage == "missing": events.pop(1)
        elif damage == "late_anchor": events[0]["seq"] = events[1]["seq"]
        elif damage == "wrong_anchor": events[0]["facts"]["anchor_commit"] = "0" * 40
        elif damage == "bool": events[1]["seq"] = True
        elif damage == "epoch": raw["epoch"] = "other-epoch"
        elif damage == "duplicate": events[2] = deepcopy(events[1])
        elif damage in {"seal_order", "next_work"}:
            seq = (mapped["members"][0].authority.actions[0].last_event_sequence if damage == "seal_order" else
                   mapped["members"][1].authority.actions[0].first_event_sequence)
            events[1]["seq"] = seq
            mapped["members"] = (replace(mapped["members"][0], publication_sequence=seq),) + mapped["members"][1:]
        elif damage == "receipt": events[1]["facts"]["receipt_commit"] = "f" * 40
        elif damage == "completion": events[1]["facts"]["completion_sha256"] = "0" * 64
        elif damage == "publication": events[1]["facts"]["publication_sha256"] = "0" * 64
        elif damage == "ticket": events[1]["facts"]["reservation_sha256"] = "0" * 64
        else: events[1], events[2] = events[2], events[1]
    change_publisher(mapped, change)
    assert verify(mapped) is None


@pytest.mark.parametrize("side", ["index", "map"])
def test_reaccepted_mapping_bytes_cannot_add_commit_backreferences(mapped, side):
    mutation = lambda raw: raw.update(self_commit="f" * 40 if side == "index" else "d" * 40)
    assemble(mapped, **{side + "_change" if side == "index" else "evidence_change": mutation})
    assert verify(mapped) is None


@pytest.mark.parametrize("damage", ["receipt", "validation", "reasons", "status"])
def test_known_disposition_contradiction_rejects_entire_map_after_coherent_rehash(mapped, damage):
    def change(entries):
        # Last action has no later reservation to invalidate first; inspect its proof directly.
        payload = next(entry["payload"] for entry in reversed(entries) if entry["event_type"] == "lifecycle_action_disposed")
        if damage == "receipt": payload["provenance_ref"] = "9" * 40
        elif damage == "validation":
            fake = encoded({"forged": "canonical validation"})
            payload["validation"] = ArtifactStore.reference(fake)
            mapped["files"]["artifacts/" + digest(fake)] = fake
        elif damage == "reasons": payload["reasons"] = ["fabricated reason"]
        else: payload["status"] = "timeout"
    rewrite_ledger(mapped, change)
    assert verify(mapped) is None


def test_missing_source_publication_cannot_reuse_known_receipt_identity(mapped):
    last = mapped["members"][-1]
    borrowed = mapped["members"][0].authority.store.root.publications[0].receipt_commit
    drop_source(mapped, last.slot)
    def change(entries):
        payload = next(entry["payload"] for entry in reversed(entries) if entry["event_type"] == "lifecycle_action_disposed")
        payload["provenance_ref"] = borrowed
    rewrite_ledger(mapped, change)
    change_publisher(mapped, lambda raw: raw["events"][-1]["facts"].update(receipt_commit=borrowed))
    assert verify(mapped) is None


@pytest.mark.parametrize("field,value", [("timestamp", True), ("tool_version", 1), ("event_type", True)])
def test_rehashed_ledger_envelope_requires_native_string_fields(mapped, field, value):
    rewrite_ledger(mapped, lambda entries: entries[-1].update(**{field: value}))
    assert verify(mapped) is None


def test_accepted_outer_inventory_cannot_replace_known_archived_raw_bytes(mapped):
    child = mapped["children"]["D", "runner_command", "baseline"]
    raw = child["files"][child["facts"]["outputs"]["stdout"]["path"]]
    mapped["files"]["artifacts/" + digest(raw)] = b"normalized text\n"
    assemble(mapped)
    assert verify(mapped) is None


def test_json_equivalence_cannot_replace_final_raw_action_prefixes(mapped):
    lines = mapped["files"]["archive/ledger.jsonl"].splitlines(keepends=True)
    mapped["files"]["archive/ledger.jsonl"] = b"".join(lines[:3]) + b"".join(
        encoded(json.loads(line)) + b"\n" for line in lines[3:])
    assemble(mapped)
    assert verify(mapped) is None


def test_coherent_final_ledger_fork_cannot_borrow_original_action_sources(mapped):
    def change(entries):
        entries[3]["timestamp"] = "2099-01-01T00:00:00Z"
    rewrite_ledger(mapped, change)
    assert verify(mapped) is None


def test_rejected_source_retains_other_proofs_and_complete_denominator(mapped):
    child = mapped["children"]["D", "runner_command", "repair"]
    changed = EcLifecycleCompletionAuthority(child["store"], replace(child["admission"],
        collector_acceptance_ref="not independently accepted"), (child["action"],))
    mapped["members"] = tuple(replace(item, authority=changed) if item.slot == ("D", "runner_command", "repair") else item
        for item in mapped["members"])
    assemble(mapped)
    result = verify(mapped)
    assert result is not None
    assert [item.slot for item in result.actions] == slots(mapped["plan"].lock())
    rejected = next(item for item in result.actions if item.slot == ("D", "runner_command", "repair"))
    assert rejected.state == "source_rejected" and rejected.proof is None
    assert all(item.eligible for item in result.actions if item.slot in {
        ("D", "runner_command", "baseline"), ("D", "runner_command", "attack")})


def test_mapped_carriers_do_not_open_legacy_runner_or_verifier_authority(mapped):
    result = verify(mapped)
    assert result is not None
    class CarrierAuthority:
        def __init__(self, carrier): self.carrier = carrier
        def verify(self, *args): return self.carrier
    receipt, artifacts = capture(mapped["plan"], "D")
    runner = validate_runner_receipt(mapped["plan"], "D", encoded(receipt), artifacts,
        authority=CarrierAuthority(result.runner("D")))
    assert runner.reasons
    vchild = mapped["children"]["D", "verifier_command", "attack"]
    data = {role: vchild["files"][ref["path"]] for role, ref in vchild["facts"]["outputs"].items()}
    verifier = validate_verifier_observation(mapped["plan"], "D", data["metadata"], data["stdout"], data["stderr"],
        authority=CarrierAuthority(result.verifier("D")))
    assert verifier.accepted is None
