"""Synthetic independent GET-only contracts, never actual coordinator admission."""

from copy import deepcopy
from dataclasses import asdict, replace
import json

import pytest

import test_source_map as v1_fixture
from test_evidence_sources import ctx as ec_context, plan
from test_source_map import make_map
from smallestlie.campaign.completion_source import ADMISSION_SCHEMA, EcLifecycleCompletionAuthority, _dispatch
from smallestlie.campaign.evidence_sources import EcReceiptStore
from smallestlie.campaign.lifecycle import ActionValidation, ArtifactStore, encoded
from smallestlie.campaign.multi_dispatch_sources import (
    ANCHOR_SCHEMA, ARCHIVE_SCHEMA, MAP_SCHEMA, PROVIDER, EcMultiDispatchSourceMapAuthority,
    MultiDispatchAnchorGrant, MultiDispatchSourceMapGrant, TerminalMappedAction, VerifiedMultiDispatchSourceMap,
)
from smallestlie.campaign.preregistration import canonical_digest, digest
from smallestlie.campaign.provenance import ProvenanceError
from smallestlie.campaign.publication_order import JOURNAL_SCHEMA
from smallestlie.campaign.source_map import EcLifecycleSourceMapAuthority, VerifiedLifecycleSourceMap
from smallestlie.ledger.lifecycle import action_key, slots

DEFAULT_SLOTS = {("D", "runner_materialize", "baseline"), ("D", "runner_command", "baseline"),
                 ("D", "runner_materialize", "attack"), ("D", "runner_command", "attack")}


def publish(ctx):
    """Preserve this synthetic grant's own dispatch, including non-default attempts."""
    root, files = ctx["root"], ctx["files"]
    grant = root.publications[0]
    job = ctx["api"].jobs[root.repository, grant.job_id]
    outer = {"schema_version": 1, "status": "preserved", "context": {
        "GITHUB_RUN_ID": str(grant.run_id), "GITHUB_RUN_ATTEMPT": str(grant.attempt),
        "GITHUB_SHA": grant.ec_source_commit, "GITHUB_JOB": root.job_name,
        "COMPUTERNAME": root.host, "EC_JOB_STATUS": job["conclusion"]},
        "files": [{"path": path, "bytes": len(raw), "sha256": digest(raw)}
                  for path, raw in sorted(files.items()) if path != "ec-publication.json"]}
    files["ec-publication.json"] = encoded(outer)
    ctx["root"] = replace(root, publications=(replace(grant, publication_sha256=digest(files["ec-publication.json"])),))
    ctx["api"].install(root.repository, grant.receipt_commit, files)
    ctx["store"] = EcReceiptStore(ctx["root"], transport=ctx["api"])


def session(ctx):
    grant = ctx["root"].publications[0]
    return {"request_sha256": grant.request_sha256, "lock_digest": grant.lock_digest,
        "source_commit": grant.source_commit, "phase1_commit": ctx["plan"].lock()["phase1_commit"],
        "plan_sha256": canonical_digest(ctx["session"].plan),
        "trust_root_sha256": canonical_digest({key: val for key, val in asdict(ctx["root"]).items()
                                             if key != "publications"}), "coordinator_epoch": "map-epoch"}


def source(member):
    if member.authority is None:
        return None
    authority = member.authority
    action, receipt = authority.actions[0], authority.store.root.publications[0]
    return {"dispatch": _dispatch(authority.store, receipt), "receipt_commit": receipt.receipt_commit,
        "publication_sha256": receipt.publication_sha256, "admission": asdict(authority.admission),
        "completion": {"path": action.completion_path, "sha256": action.completion_sha256},
        "supervisor": {"path": action.supervisor_path, "sha256": action.supervisor_sha256},
        "publication": {"path": action.publication_path, "sha256": action.publication_sha256},
        "identity": {"action_epoch": action.journal_epoch, "action_id": action.action_id,
            "first_event_sequence": action.first_event_sequence, "last_event_sequence": action.last_event_sequence},
        "journal_sha256": member.journal_sha256, "release_sequence": member.release_sequence,
        "publication_sequence": member.publication_sequence}


def assemble(ctx, *, index_change=None, evidence_change=None):
    anchor, files, common = ctx["anchor"], ctx["files"], session(ctx)
    records = [{"slot": {"case_id": item.case_id, "kind": item.kind, "arm": item.arm},
                "reservation": item.ticket.to_dict() if item.ticket is not None else None, "source": source(item)}
               for item in ctx["members"]]
    index = {"schema_version": ARCHIVE_SCHEMA, "session_sha256": canonical_digest(common),
        "archive_dispatch": ctx["dispatch"], "anchor": asdict(anchor),
        "ledger": {"path": "archive/ledger.jsonl", "sha256": digest(files["archive/ledger.jsonl"])},
        "journal": {"path": "archive/publisher.json", "sha256": digest(files["archive/publisher.json"])}, "actions": records}
    if index_change:
        index_change(index)
    files["archive/index.json"] = encoded(index)
    publish(ctx)
    evidence = {"schema_version": MAP_SCHEMA, "session": common, "archive_dispatch": ctx["dispatch"],
        "contracts": ctx["contracts"], "assembler": {"path": "trusted/assembler.py", "sha256": digest(ctx["assembler"])},
        "anchor": asdict(anchor), "final_archive": {"commit": ctx["root"].publications[0].receipt_commit,
            "publication_sha256": ctx["root"].publications[0].publication_sha256,
            "index": {"path": "archive/index.json", "sha256": digest(files["archive/index.json"])}}, "actions": records}
    if evidence_change:
        evidence_change(evidence)
    raw = encoded(evidence)
    ctx["api"].install(ctx["root"].repository, "d" * 40, {"admissions/map.json": raw})
    ctx["grant"] = MultiDispatchSourceMapGrant("d" * 40, "admissions/map.json", digest(raw),
        "archive/index.json", digest(files["archive/index.json"]), "archive/ledger.jsonl", digest(files["archive/ledger.jsonl"]),
        "archive/publisher.json", digest(files["archive/publisher.json"]), "trusted/assembler.py", digest(ctx["assembler"]),
        anchor, *(ctx["contracts"][name] for name in ("anchor", "publisher", "coordinator", "mapping")))
    ctx["authority"] = EcMultiDispatchSourceMapAuthority(ctx["store"], ctx["grant"], ctx["members"])


def change_order(ctx, mutation):
    raw = json.loads(ctx["files"]["archive/publisher.json"])
    mutation(raw)
    ctx["files"]["archive/publisher.json"] = encoded(raw)
    assemble(ctx)


def rewrite_ledger(ctx, mutation):
    """Coherently rehash a fixture fork without changing original anchor bytes."""
    from smallestlie.ledger.chain import payload_digest
    original = ctx["files"]["archive/ledger.jsonl"].splitlines(keepends=True)
    entries = [json.loads(line) for line in original]
    mutation(entries)
    previous = "0" * 64
    for entry in entries:
        entry["payload_digest"] = payload_digest(entry["payload"])
        entry["previous_entry_digest"] = previous
        entry["entry_digest"] = payload_digest({key: entry[key] for key in
            ("seq", "timestamp", "event_type", "tool_version", "payload_digest", "previous_entry_digest")})
        previous = entry["entry_digest"]
    ctx["files"]["archive/ledger.jsonl"] = b"".join(original[:3]) + b"".join(
        json.dumps(entry, sort_keys=True, default=str).encode() + (b"\r\n" if line.endswith(b"\r\n") else b"\n")
        for entry, line in zip(entries[3:], original[3:]))
    assemble(ctx)


def drop_source(ctx, slot):
    ctx["members"] = tuple(replace(item, authority=None, release_sequence=None, publication_sequence=None,
                                  journal_sha256=None) if item.slot == slot else item for item in ctx["members"])
    assemble(ctx)


def verify(ctx):
    return ctx["authority"].verify(ctx["plan"])


@pytest.fixture
def make_multi_map(make_map, monkeypatch):
    original_publish_action = v1_fixture.publish_action
    monkeypatch.setattr(v1_fixture, "republish", publish)
    monkeypatch.setattr(v1_fixture, "publish_action", lambda child, first, identity:
                        original_publish_action(child, 1, identity))

    def make(*, selected=DEFAULT_SLOTS, incomplete=None, mutate_native=None):
        def move(child):
            api, root = child["api"], child["root"]
            old = root.publications[0]
            index = int(old.receipt_commit, 16)
            run_id, job_id, attempt, ec = 1000 + index, 2000 + index, 1 + index % 2, f"{10000 + index:040x}"
            changed = replace(old, ec_source_commit=ec, run_id=run_id, job_id=job_id, attempt=attempt)
            child["root"] = replace(root, publications=(changed,))
            child["dispatch"] = _dispatch(EcReceiptStore(child["root"], transport=api), changed)
            child["facts"]["dispatch"] = child["dispatch"]
            api.runs[root.repository, run_id, attempt] = {**deepcopy(api.runs[root.repository, 600, 1]),
                "id": run_id, "run_attempt": attempt, "head_sha": ec}
            api.jobs[root.repository, job_id] = {**deepcopy(api.jobs[root.repository, 700]),
                "id": job_id, "run_id": run_id, "run_attempt": attempt, "head_sha": ec}
            # The collector bytes are already frozen in the original synthetic
            # EC commit; use its reader, never install or execute a collector.
            from smallestlie.campaign.provenance import GitHubObjectReader
            collector = GitHubObjectReader(transport=api).blob_at(root.repository, "e" * 40, root.collector_path)
            api.install(root.repository, ec, {root.workflow_path: b"synthetic external workflow", root.collector_path: collector})
            workload = json.loads(child["files"]["ec-workload.json"])
            workload.update(ec_sha=ec, run_id=str(run_id), run_attempt=str(attempt))
            child["files"]["ec-workload.json"] = encoded(workload)
            contracts = {"collector": child["admission"].collector_acceptance_ref,
                         "host_storage": child["admission"].host_storage_acceptance_ref,
                         "prelaunch_journal": child["admission"].journal_acceptance_ref}
            admission = encoded({"schema_version": ADMISSION_SCHEMA, "dispatch": child["dispatch"], "contracts": contracts})
            admission_commit = f"{20000 + index:040x}"
            api.install(root.repository, admission_commit, {child["admission"].evidence_path: admission})
            child["admission"] = replace(child["admission"], ec_source_commit=ec, run_id=run_id, attempt=attempt,
                job_id=job_id, evidence_commit=admission_commit, evidence_sha256=digest(admission))
            if mutate_native:
                mutate_native(child)

        ctx = make_map(selected=selected, incomplete=incomplete, mutate_native=move)
        ctx["legacy_authority"] = ctx["authority"]
        old_anchor = ctx["anchor"]
        # Preserve the original exact prefix from the session ledger.
        lines = ctx["files"]["archive/ledger.jsonl"].splitlines(keepends=True)
        locked = b"".join(lines[:3])
        common = session(ctx)
        raw_anchor = encoded({"schema_version": ANCHOR_SCHEMA, "session": common,
            "locked_prefix": {"path": old_anchor.prefix_path, "sha256": digest(locked)}})
        ctx["api"].install(ctx["root"].repository, old_anchor.commit,
            {old_anchor.path: raw_anchor, old_anchor.prefix_path: locked})
        ctx["anchor"] = MultiDispatchAnchorGrant(old_anchor.commit, old_anchor.path, digest(raw_anchor),
            old_anchor.prefix_path, digest(locked), old_anchor.journal_epoch, old_anchor.ack_sequence)
        events = [{"event": "anchor_durable_ack", "seq": 1, "facts": {"anchor_commit": old_anchor.commit,
            "anchor_sha256": digest(raw_anchor), "locked_prefix_sha256": digest(locked)}}]
        members = []
        for old_member in ctx["members"]:
            if old_member.authority is None:
                members.append(TerminalMappedAction(*old_member.slot, old_member.ticket, None, None, None, None))
                continue
            child = ctx["children"][old_member.slot]
            action, receipt = child["action"], child["root"].publications[0]
            release_seq = len(events) + 1
            release = {"event": "action_release", "seq": release_seq, "facts": {
                "reservation_sha256": canonical_digest(old_member.ticket.to_dict()),
                "prefix_sha256": digest(child["files"]["action/prefix.jsonl"]),
                "context_sha256": old_member.ticket.context_sha256, "dispatch": child["dispatch"],
                "action_epoch": action.journal_epoch, "action_id": action.action_id,
                "first_event_sequence": action.first_event_sequence, "last_event_sequence": action.last_event_sequence,
                "previous_ack_sha256": canonical_digest(events[-1])}}
            events.append(release)
            ack_seq = len(events) + 1
            events.append({"event": "action_publication_durable_ack", "seq": ack_seq, "facts": {
                "release_sha256": canonical_digest(release), "reservation_sha256": action.reservation_sha256,
                "dispatch": child["dispatch"], "receipt_commit": receipt.receipt_commit,
                "completion_sha256": action.completion_sha256, "action_publication_sha256": action.publication_sha256,
                "publication_sha256": receipt.publication_sha256,
                "action_journal_sha256": digest(child["files"]["action/journal.json"])}})
            members.append(TerminalMappedAction(*old_member.slot, old_member.ticket, child["authority"],
                release_seq, ack_seq, digest(child["files"]["action/journal.json"])))
        ctx["members"] = tuple(members)
        ctx["contracts"]["coordinator"] = "synthetic externally accepted serial coordinator enforcement"
        ctx["files"]["archive/publisher.json"] = encoded({"schema_version": JOURNAL_SCHEMA,
            "session_sha256": canonical_digest(common), "epoch": "map-epoch", "events": events})
        assemble(ctx)
        return ctx
    return make


@pytest.fixture
def multi_mapped(make_multi_map):
    return make_multi_map()


def test_distinct_terminal_dispatches_keep_original_sources_and_full_denominator(multi_mapped):
    result = verify(multi_mapped)
    assert type(result) is VerifiedMultiDispatchSourceMap and result.provider_id == PROVIDER
    assert not isinstance(result, VerifiedLifecycleSourceMap)
    assert [item.slot for item in result.actions] == slots(multi_mapped["plan"].lock())
    for item in result.actions:
        if item.slot in DEFAULT_SLOTS:
            assert item.state == "observed" and item.eligible
            child = multi_mapped["children"][item.slot]
            assert dict(item.proof.dispatch) == child["dispatch"]
            assert dict(item.proof.dispatch) != multi_mapped["dispatch"]
            assert item.proof.journal == child["files"]["action/journal.json"]
            assert item.proof.action_receipt_ref == child["root"].publications[0].receipt_commit
        else:
            assert item.state == "source_missing" and item.proof is None and not item.eligible
    baseline = next(item.proof for item in result.actions if item.slot == ("D", "runner_command", "baseline"))
    assert baseline.validation.exit_code == 1 and dict(baseline.outputs)["stdout"] == b"\xff\r\n\x00"
    old = multi_mapped["legacy_authority"]
    legacy = EcLifecycleSourceMapAuthority(multi_mapped["store"], old.grant, old.actions)
    with pytest.raises(ProvenanceError, match="dispatch"):
        EcLifecycleSourceMapAuthority._verify(legacy, multi_mapped["plan"])
    assert all(json.loads(child["files"]["action/journal.json"])["events"][-1]["seq"] == 5
               for child in multi_mapped["children"].values())


def test_all_missing_retains_denominator_without_publication_authority(make_multi_map):
    ctx = make_multi_map(selected=set())
    result = verify(ctx)
    assert result is not None and result.actions
    assert all(item.state == "source_missing" and not item.eligible and item.proof is None for item in result.actions)


def test_missing_materialization_preserves_command_proof_without_dependency_authority(multi_mapped):
    drop_source(multi_mapped, ("D", "runner_materialize", "baseline"))
    result = verify(multi_mapped)
    assert result is not None
    command = next(item for item in result.actions if item.slot == ("D", "runner_command", "baseline"))
    assert command.state == "observed" and command.proof is not None and not command.eligible
    assert command.reasons == ("independently_completed_materialization_missing",)
    assert next(item for item in result.actions if item.slot == ("D", "runner_command", "attack")).eligible


def test_final_released_missing_completion_preserves_ticket_and_other_sources(multi_mapped):
    target = ("D", "runner_command", "attack")
    member = next(item for item in multi_mapped["members"] if item.slot == target)
    drop_source(multi_mapped, target)
    missing = ActionValidation(canonical_digest(member.ticket.to_dict()), None, False, "completion_missing",
                               None, None, None, None, None, None, ("completion_missing",))
    validation = encoded(asdict(missing))
    multi_mapped["files"]["artifacts/" + digest(validation)] = validation
    def mutate(entries):
        payload = next(entry["payload"] for entry in entries if entry["event_type"] == "lifecycle_action_disposed"
                       and action_key(entry["payload"]["binding"]["case_id"], entry["payload"]["kind"],
                                      entry["payload"]["arm"]) == member.key)
        payload.update(status="completion_missing", completion=ArtifactStore.reference(None),
            validation=ArtifactStore.reference(validation), provenance_ref=None, reasons=list(missing.reasons),
            sources={role: ArtifactStore.reference(None) for role in payload["sources"]},
            outputs={role: ArtifactStore.reference(None) for role in payload["outputs"]})
    rewrite_ledger(multi_mapped, mutate)
    change_order(multi_mapped, lambda journal: journal["events"].pop())
    result = verify(multi_mapped)
    assert result is not None
    final = next(item for item in result.actions if item.slot == target)
    assert final.state == "source_missing" and final.proof is None and not final.eligible
    assert next(item for item in multi_mapped["members"] if item.slot == target).ticket == member.ticket
    assert next(item for item in result.actions if item.slot == ("D", "runner_command", "baseline")).eligible


@pytest.mark.parametrize("field,value", [("status", "in_progress"), ("run_attempt", True), ("head_sha", "0" * 40)])
def test_each_terminal_source_is_reacquired_without_erasing_other_proofs(multi_mapped, field, value):
    slot = ("D", "runner_materialize", "baseline")
    child = multi_mapped["children"][slot]
    pub = child["root"].publications[0]
    multi_mapped["api"].jobs[child["root"].repository, pub.job_id][field] = value
    result = verify(multi_mapped)
    assert result is not None
    assert next(item for item in result.actions if item.slot == slot).state == "source_rejected"
    command = next(item for item in result.actions if item.slot == ("D", "runner_command", "baseline"))
    assert command.proof is not None and not command.eligible
    assert next(item for item in result.actions if item.slot == ("D", "runner_command", "attack")).eligible


@pytest.mark.parametrize("field,value", [("generation", "other"), ("collector_sha256", "0" * 64),
                                       ("verifier_runtime_sha256", "0" * 64)])
def test_cross_dispatch_does_not_relax_common_trust_root(multi_mapped, field, value):
    member = next(item for item in multi_mapped["members"] if item.authority is not None)
    authority = member.authority
    changed = EcLifecycleCompletionAuthority(EcReceiptStore(replace(authority.store.root, **{field: value}),
        transport=authority.store.transport), authority.admission, authority.actions)
    multi_mapped["members"] = tuple(replace(item, authority=changed) if item is member else item
                                    for item in multi_mapped["members"])
    assemble(multi_mapped)
    assert verify(multi_mapped) is None


def test_instance_verify_and_store_hooks_cannot_supply_a_completion(multi_mapped):
    member = next(item for item in multi_mapped["members"] if item.authority is not None)
    member.authority.verify = lambda *args: pytest.fail("caller completion hook invoked")
    member.authority._action = lambda *args: pytest.fail("caller action hook invoked")
    member.authority.store.read = lambda *args: pytest.fail("caller store hook invoked")
    multi_mapped["store"].read = lambda *args: pytest.fail("caller archive hook invoked")
    result = verify(multi_mapped)
    assert result is not None and next(item for item in result.actions if item.slot == member.slot).proof is not None


@pytest.mark.parametrize("status", ["timeout", "quota", "output_incomplete"])
def test_native_incomplete_dispositions_and_nonzero_are_not_relabelled_green(make_multi_map, status):
    target = ("D", "runner_command", "attack")
    def mutate(child):
        if (child["ticket"].case_id, child["ticket"].kind, child["ticket"].arm) == target:
            child["facts"].update(termination_kind=status, exit_code=None, output_complete=False, descendants_reaped=False)
    ctx = make_multi_map(incomplete=target, mutate_native=mutate)
    result = verify(ctx)
    assert result is not None
    proof = next(item.proof for item in result.actions if item.slot == target)
    assert proof.validation.status == status and proof.validation.exit_code is None
    assert dict(proof.outputs)["report"] is None and proof.validation.output_complete is False


@pytest.mark.parametrize("damage", ["drop", "duplicate", "legacy", "journal", "contract"])
def test_exact_v2_configuration_cannot_filter_or_alias_authority(multi_mapped, damage):
    members = multi_mapped["members"]
    if damage == "duplicate":
        with pytest.raises(ProvenanceError, match="unique"):
            EcMultiDispatchSourceMapAuthority(multi_mapped["store"], multi_mapped["grant"], members + members[:1])
    elif damage == "legacy":
        with pytest.raises(ProvenanceError, match="v2"):
            EcMultiDispatchSourceMapAuthority(multi_mapped["store"], multi_mapped["legacy_authority"].grant, members)
    elif damage == "contract":
        with pytest.raises(ProvenanceError, match="acceptances"):
            replace(multi_mapped["grant"], coordinator_acceptance_ref=multi_mapped["grant"].publisher_acceptance_ref)
    else:
        multi_mapped["members"] = members[:-1] if damage == "drop" else tuple(
            replace(item, journal_sha256="0" * 64) if item.authority is not None else item for item in members)
        assemble(multi_mapped)
        assert verify(multi_mapped) is None


@pytest.mark.parametrize("field", ["completion_sha256", "supervisor_sha256", "publication_sha256"])
@pytest.mark.parametrize("unavailable", [False, True])
def test_known_raw_source_grant_conflict_is_not_downgraded_to_rejected_source(multi_mapped, field, unavailable):
    member = next(item for item in multi_mapped["members"] if item.authority is not None)
    original = member.authority
    action = replace(original.actions[0], **{field: "0" * 64})
    changed = EcLifecycleCompletionAuthority(original.store, original.admission, (action,))
    multi_mapped["members"] = tuple(replace(item, authority=changed) if item is member else item
                                    for item in multi_mapped["members"])
    if unavailable:
        receipt = original.store.root.publications[0]
        multi_mapped["api"].jobs[original.store.root.repository, receipt.job_id]["status"] = "in_progress"
    assemble(multi_mapped)
    assert verify(multi_mapped) is None


def test_known_admission_dispatch_conflict_rejects_whole_map(multi_mapped):
    member = next(item for item in multi_mapped["members"] if item.authority is not None)
    original = member.authority
    changed = EcLifecycleCompletionAuthority(original.store, replace(original.admission, job_id=999999), original.actions)
    multi_mapped["members"] = tuple(replace(item, authority=changed) if item is member else item
                                    for item in multi_mapped["members"])
    assemble(multi_mapped)
    assert verify(multi_mapped) is None


def test_unavailable_original_admission_preserves_other_proofs(multi_mapped):
    member = next(item for item in multi_mapped["members"] if item.authority is not None)
    admission = member.authority.admission
    multi_mapped["api"].install(member.authority.store.root.repository, admission.evidence_commit,
                                {admission.evidence_path: b"replaced unaccepted admission"})
    result = verify(multi_mapped)
    assert result is not None
    assert next(item for item in result.actions if item.slot == member.slot).state == "source_rejected"
    assert next(item for item in result.actions if item.slot == ("D", "runner_command", "attack")).eligible


def test_missing_source_cannot_borrow_known_admission_commit_in_coherent_ledger_and_ack(multi_mapped):
    target = ("D", "runner_command", "attack")
    borrowed = next(item.authority.admission.evidence_commit for item in multi_mapped["members"]
                    if item.authority is not None and item.slot != target)
    drop_source(multi_mapped, target)
    def mutate(entries):
        payload = next(entry["payload"] for entry in entries if entry["event_type"] == "lifecycle_action_disposed"
                       and (entry["payload"]["binding"]["case_id"], entry["payload"]["kind"], entry["payload"]["arm"]) == target)
        payload["provenance_ref"] = borrowed
    rewrite_ledger(multi_mapped, mutate)
    change_order(multi_mapped, lambda raw: raw["events"][-1]["facts"].update(receipt_commit=borrowed))
    with pytest.raises(ProvenanceError, match="role mismatch"):
        EcMultiDispatchSourceMapAuthority._verify(multi_mapped["authority"], multi_mapped["plan"])
    assert verify(multi_mapped) is None


@pytest.mark.parametrize("damage", ["receipt", "validation", "reasons", "status"])
def test_known_disposition_conflict_survives_coherent_final_rehash(multi_mapped, damage):
    target = ("D", "runner_command", "attack")
    def mutate(entries):
        payload = next(entry["payload"] for entry in entries if entry["event_type"] == "lifecycle_action_disposed"
                       and (entry["payload"]["binding"]["case_id"], entry["payload"]["kind"], entry["payload"]["arm"]) == target)
        if damage == "receipt": payload["provenance_ref"] = "9" * 40
        elif damage == "validation":
            fake = encoded({"forged": "validation"})
            payload["validation"] = ArtifactStore.reference(fake)
            multi_mapped["files"]["artifacts/" + digest(fake)] = fake
        elif damage == "reasons": payload["reasons"] = ["invented reason"]
        else: payload["status"] = "timeout"
    rewrite_ledger(multi_mapped, mutate)
    assert verify(multi_mapped) is None


@pytest.mark.parametrize("side", ["index", "map"])
def test_reaccepted_outer_json_cannot_add_own_commit_backreference(multi_mapped, side):
    assemble(multi_mapped, **{("index_change" if side == "index" else "evidence_change"):
                              lambda raw: raw.update(self_commit="f" * 40 if side == "index" else "d" * 40)})
    assert verify(multi_mapped) is None


@pytest.mark.parametrize("damage", ["evidence_sha256", "ledger_sha256", "journal_sha256", "archive_sha256", "assembler_sha256"])
def test_outer_publication_does_not_override_external_raw_pins(multi_mapped, damage):
    grant = replace(multi_mapped["grant"], **{damage: "0" * 64})
    assert EcMultiDispatchSourceMapAuthority(multi_mapped["store"], grant, multi_mapped["members"]).verify(
        multi_mapped["plan"]) is None


@pytest.mark.parametrize("input_role", ["action_ec", "product", "phase1", "admission"])
def test_map_output_cannot_alias_any_known_input_role(multi_mapped, input_role):
    member = next(item for item in multi_mapped["members"] if item.authority is not None)
    ref = (member.authority.store.root.publications[0].ec_source_commit if input_role == "action_ec" else
           multi_mapped["plan"].request.source_commit if input_role == "product" else
           multi_mapped["plan"].lock()["phase1_commit"] if input_role == "phase1" else
           member.authority.admission.evidence_commit)
    grant = replace(multi_mapped["grant"], evidence_commit=ref)
    authority = EcMultiDispatchSourceMapAuthority(multi_mapped["store"], grant, multi_mapped["members"])
    assert authority.verify(multi_mapped["plan"]) is None


def test_reaccepted_archive_cannot_normalize_original_raw_output(multi_mapped):
    child = multi_mapped["children"]["D", "runner_command", "baseline"]
    raw = child["files"][child["facts"]["outputs"]["stdout"]["path"]]
    multi_mapped["files"]["artifacts/" + digest(raw)] = b"normalized output\n"
    assemble(multi_mapped)
    assert verify(multi_mapped) is None


def test_json_equivalence_cannot_replace_original_prefix_encoding(multi_mapped):
    lines = multi_mapped["files"]["archive/ledger.jsonl"].splitlines(keepends=True)
    multi_mapped["files"]["archive/ledger.jsonl"] = b"".join(lines[:3]) + b"".join(
        encoded(json.loads(line)) + b"\n" for line in lines[3:])
    assemble(multi_mapped)
    assert verify(multi_mapped) is None


def test_rehashed_final_ledger_cannot_borrow_original_ticket_prefixes(multi_mapped):
    rewrite_ledger(multi_mapped, lambda entries: entries[3].update(timestamp="2099-01-01T00:00:00Z"))
    assert verify(multi_mapped) is None


@pytest.mark.parametrize("future", ["archive_dispatch", "future_receipt", "self_commit"])
def test_prospective_anchor_cannot_name_future_dispatches_or_receipts(multi_mapped, future):
    anchor = multi_mapped["anchor"]
    raw = {"schema_version": ANCHOR_SCHEMA, "session": session(multi_mapped),
           "locked_prefix": {"path": anchor.prefix_path, "sha256": anchor.prefix_sha256},
           future: multi_mapped["dispatch"] if future == "archive_dispatch" else "f" * 40}
    data = encoded(raw)
    locked = b"".join(multi_mapped["files"]["archive/ledger.jsonl"].splitlines(keepends=True)[:3])
    multi_mapped["api"].install(multi_mapped["root"].repository, anchor.commit,
                                {anchor.path: data, anchor.prefix_path: locked})
    multi_mapped["anchor"] = replace(anchor, sha256=digest(data))
    change_order(multi_mapped, lambda journal: journal["events"][0]["facts"].update(anchor_sha256=digest(data)))
    assert verify(multi_mapped) is None
