"""Fresh per-action semantics; raw namespaces belong to each original receipt.

Canonical JSON fields below are immutable summary views, never new raw receipts.
Raw digests, recorded claims, imported contracts and observed facts are distinct.
No legacy aggregate receipt or first-pass validation can authorize an action.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, replace
import json

from smallestlie.adapters.checkwash import _findings_error
from smallestlie.adjudication.observations import Finding, SEVERITIES
from smallestlie.attacks.adjudication import mapping, relative_path, string
from smallestlie.campaign.completion_source import EcLifecycleCompletionAuthority, _dispatch, _same
from smallestlie.campaign.evidence_sources import EcReceiptStore
from smallestlie.campaign.lifecycle import ArtifactStore, _read_frozen, _read_observations
from smallestlie.campaign.multi_dispatch_sources import (
    ARCHIVE_SCHEMA, MAP_SCHEMA, EcMultiDispatchSourceMapAuthority, TerminalMappedAction,
    _fresh_store, _record, _session,
)
from smallestlie.campaign.preregistration import (
    PreparedRun, PreregistrationError, canonical_digest, case_binding, digest, json_mapping,
)
from smallestlie.campaign.provenance import GovernanceReference, ProvenanceError
from smallestlie.campaign.source_map import _entries
from smallestlie.ledger.lifecycle import action_key, action_plan, artifact_ref, slots, verify_lifecycle_protocol
from smallestlie.oracle.runner_evidence import ArmEvidence, EffectivenessAssessment, _arm, assess_bound_change

SCHEMA = "smallestlie.multi-dispatch-observations/v1"


def _json(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=True, allow_nan=False, separators=(",", ":"))


@dataclass(frozen=True)
class MultiDispatchSourceRole:
    role: str
    repository: str | None
    repository_id: int | None
    commit: str | None
    reference: str | None = None


@dataclass(frozen=True)
class MultiDispatchRecordedAction:
    reservation_json: str | None
    reservation_sha256: str | None
    disposition_json: str
    coordinator_claims_json: tuple[str, ...]


@dataclass(frozen=True)
class MultiDispatchConfiguredAction:
    source_json: str
    publication_acceptance_ref: str
    supervisor_acceptance_ref: str | None


@dataclass(frozen=True)
class MultiDispatchObservedAction:
    action_receipt_ref: str
    dispatch_json: str
    reservation_sha256: str
    completion_sha256: str
    supervisor_sha256: str
    publication_sha256: str
    prefix_sha256: str
    child_journal_sha256: str
    validation_sha256: str
    supervisor_json: str
    termination_kind: str
    exit_code: int | None
    output_complete: bool
    descendants_reaped: bool
    outputs: tuple[tuple[str, str | None, str | None], ...]


@dataclass(frozen=True)
class MultiDispatchActionObservation:
    slot: tuple[str, str, str]
    state: str
    eligible: bool
    reasons: tuple[str, ...]
    recorded: MultiDispatchRecordedAction
    configured: MultiDispatchConfiguredAction | None
    observed: MultiDispatchObservedAction | None


@dataclass(frozen=True)
class MultiDispatchRunnerArm:
    evidence: ArmEvidence
    command: MultiDispatchActionObservation
    materialization: MultiDispatchActionObservation


@dataclass(frozen=True)
class MultiDispatchRunnerObservation:
    case_id: str
    binding_sha256: str
    arms: tuple[MultiDispatchRunnerArm, ...]

    def arm(self, role: str) -> ArmEvidence:
        return next((item.evidence for item in self.arms if item.evidence.role == role),
                    ArmEvidence(role, False, ("arm_missing",)))


@dataclass(frozen=True)
class MultiDispatchVerifierObservation:
    case_id: str
    binding_sha256: str
    command: MultiDispatchActionObservation
    materializations: tuple[MultiDispatchActionObservation, ...]
    captures: tuple[tuple[str, str | None, str | None], ...]
    accepted: bool | None
    report_verdict: str | None
    exit_code: int | None
    fail_on: str | None
    findings: tuple[Finding, ...]
    skipped_files: tuple[str, ...]
    reasons: tuple[str, ...]


@dataclass(frozen=True)
class MultiDispatchCaseObservation:
    case_id: str
    runner: MultiDispatchRunnerObservation
    verifier: MultiDispatchVerifierObservation
    effectiveness: EffectivenessAssessment
    first_pass_validations: tuple[tuple[str, str], ...]
    auxiliary_raw_view: tuple[tuple[str, str], ...]


@dataclass(frozen=True)
class MultiDispatchObservationSnapshot:
    schema_version: str
    request_sha256: str
    lock_digest: str
    plan_sha256: str
    session_sha256: str
    archive_dispatch_json: str
    prelaunch_anchor_ref: str
    final_archive_ref: str
    mapping_evidence_ref: str
    mapping_sha256: str
    archive_index_sha256: str
    ledger_sha256: str
    index_sha256: str
    coordinator_journal_sha256: str
    source_contract_json: str
    source_roles: tuple[MultiDispatchSourceRole, ...]
    acceptance_refs: tuple[str, ...]
    actions: tuple[MultiDispatchActionObservation, ...]
    cases: tuple[MultiDispatchCaseObservation, ...]

    @property
    def validation_sha256(self) -> str:
        return canonical_digest(asdict(self))


class _ArchiveArtifacts:
    def __init__(self, archive):
        self.archive = archive

    def read(self, ref):
        artifact_ref(ref)
        if ref["state"] == "missing":
            return None
        data = self.archive.artifact("artifacts/" + ref["sha256"])
        if ArtifactStore.reference(data) != ref:
            raise ProvenanceError("multi-dispatch auxiliary raw reference mismatch")
        return data


def _summary(item, state, configured, member, events):
    ticket = state["reservation"]
    ticket_sha = canonical_digest(ticket) if ticket is not None else None
    claims = tuple(_json(event) for event in events
                   if ticket_sha is not None and event["facts"].get("reservation_sha256") == ticket_sha)
    recorded = MultiDispatchRecordedAction(_json(ticket) if ticket is not None else None,
        ticket_sha, _json(state["disposition"]), claims)
    imported = None
    if configured is not None:
        publication = member.authority.store.root.publications[0]
        imported = MultiDispatchConfiguredAction(_json(configured), publication.acceptance_ref,
                                                  publication.supervisor_acceptance_ref)
    observed, proof = None, item.proof
    if proof is not None:
        sources = dict(proof.sources)
        facts = json_mapping(sources["supervisor"], "multi-dispatch original supervisor")
        outputs = tuple((role, ref["path"] if ref is not None else None,
                         ref["sha256"] if ref is not None else None)
                        for role, ref in sorted(facts["outputs"].items()))
        observed = MultiDispatchObservedAction(proof.action_receipt_ref, _json(dict(proof.dispatch)),
            canonical_digest(proof.reservation.to_dict()), digest(proof.completion), digest(sources["supervisor"]),
            digest(sources["publication"]), digest(proof.prefix), digest(proof.journal),
            canonical_digest(asdict(proof.validation)), _json(facts), proof.validation.status,
            proof.validation.exit_code, proof.validation.output_complete, proof.validation.descendants_reaped, outputs)
    return MultiDispatchActionObservation(item.slot, item.state, item.eligible, item.reasons,
                                           recorded, imported, observed)


def _completed(item):
    proof = item.proof
    if proof is None or item.eligible is not True:
        raise PreregistrationError("multi_dispatch_command_ineligible: " + "; ".join(item.reasons))
    fact = proof.validation
    if (not fact.valid or fact.status != "completed" or type(fact.exit_code) is not int
            or fact.output_complete is not True or fact.descendants_reaped is not True):
        raise PreregistrationError("multi_dispatch_command_not_completed: " + fact.status)
    return json_mapping(dict(proof.sources)["supervisor"], "multi-dispatch original supervisor")


def _payloads(item, facts):
    # This local map belongs to one original R_i, never to the whole case or F.
    outputs, artifacts = dict(item.proof.outputs), {}
    if set(outputs) != set(facts["outputs"]):
        raise PreregistrationError("multi_dispatch_output_roles_mismatch")
    for role, ref in facts["outputs"].items():
        data = outputs[role]
        if ref is None or type(data) is not bytes or digest(data) != ref["sha256"]:
            raise PreregistrationError("multi_dispatch_original_output_missing_or_mismatched")
        if ref["path"] in artifacts:
            raise PreregistrationError("multi_dispatch_reused_output_role")
        artifacts[ref["path"]] = data
    return outputs, artifacts


def _runner(prepared, cid, mapped, summaries):
    binding, profile = prepared.binding(cid), prepared.profile(cid)
    arms = []
    for role, expected in binding["arms"].items():
        command_key = action_key(cid, "runner_command", role)
        material_key = action_key(cid, "runner_materialize", role)
        item = mapped[command_key]
        try:
            facts = _completed(item)
            _, artifacts = _payloads(item, facts)
            _same(facts["files"], {role: expected["files"]}, "multi_dispatch_runner_measured_files_mismatch")
            # Frozen tree/production labels follow a complete measured file match.
            # truncated=False is the parser interface after the native writer gate.
            # This temporary adapter is never published as a native receipt.
            record = {**facts["command"], "fixture": {"files": facts["files"][role],
                "tree_sha256": expected["tree_sha256"], "production": expected["production"]},
                "termination_kind": item.proof.validation.status, "exit_code": item.proof.validation.exit_code,
                **facts["outputs"], "truncated": False}
            evidence = _arm(role, record, expected, profile, artifacts,
                (item.proof.validation.status, item.proof.validation.exit_code), binding["dependency_lock_sha256"])
        except (ValueError, TypeError, KeyError, AttributeError) as exc:
            evidence = ArmEvidence(role, False, (str(exc),))
        arms.append(MultiDispatchRunnerArm(evidence, summaries[command_key], summaries[material_key]))
    return MultiDispatchRunnerObservation(cid, canonical_digest(case_binding(prepared.lock(), cid)), tuple(arms))


def _verifier(prepared, cid, mapped, summaries):
    command_key = action_key(cid, "verifier_command", "attack")
    item, command = mapped[command_key], summaries[command_key]
    materials = tuple(summaries[action_key(cid, "verifier_materialize", role)] for role in ("baseline", "attack"))
    captures = command.observed.outputs if command.observed is not None else ()
    findings, skipped, verdict, code, threshold = (), (), None, None, None
    try:
        facts = _completed(item)
        outputs, _ = _payloads(item, facts)
        metadata = json_mapping(outputs["metadata"], "multi-dispatch verifier metadata")
        mapping(metadata, "multi-dispatch verifier metadata", {"schema_version", "binding", "arm", "adapter", "engine",
            "baseline_tree_sha256", "attack_tree_sha256", "base_commit", "head_commit", "argv", "cwd", "fail_on",
            "termination_kind", "exit_code", "truncated", "stdout_sha256", "stderr_sha256"})
        lock, binding, measured = prepared.lock(), prepared.binding(cid), facts["command"]
        expected = {"schema_version": "smallestlie.verifier-observation/v1", "binding": case_binding(lock, cid),
            "arm": "attack", "adapter": "checkwash", "engine": lock["engine"],
            "baseline_tree_sha256": binding["arms"]["baseline"]["tree_sha256"],
            "attack_tree_sha256": binding["arms"]["attack"]["tree_sha256"],
            "base_commit": measured["base_commit"], "head_commit": measured["head_commit"], "argv": measured["argv"],
            "cwd": measured["logical_cwd"], "fail_on": measured["fail_on"],
            "termination_kind": item.proof.validation.status, "exit_code": item.proof.validation.exit_code,
            "truncated": False, "stdout_sha256": digest(outputs["stdout"]), "stderr_sha256": digest(outputs["stderr"])}
        _same(metadata, expected, "multi_dispatch_verifier_measured_metadata_mismatch")
        code, threshold = metadata["exit_code"], metadata["fail_on"]
        if type(code) is not int or code not in {0, 1}:
            raise PreregistrationError("verifier_not_completed_verdict")
        payload = json_mapping(outputs["stdout"], "multi-dispatch Checkwash stdout")
        error = _findings_error(payload, lock["engine"]["version"], 2)
        if error:
            raise PreregistrationError(error)
        normalized = []
        for finding in payload["findings"]:
            for key in ("rule", "message", "fingerprint"):
                string(finding[key], "finding." + key)
            if finding["path"]:
                relative_path(finding["path"], "finding.path")
            normalized.append(Finding(finding["rule"], finding["path"], finding["severity"], finding["fingerprint"],
                finding["allowlisted"], finding["unit"], json.dumps(finding, sort_keys=True, ensure_ascii=True, allow_nan=False)))
        findings, skipped, verdict = tuple(normalized), tuple(payload["skipped_files"]), payload["verdict"]
        if any(finding.allowlisted is not False for finding in findings):
            raise PreregistrationError("multi_dispatch_default_policy_allowlist_contradiction")
        if (payload["run"]["base"] not in {"HEAD~1", measured["base_commit"]}
                or payload["run"]["head"] not in {"HEAD", measured["head_commit"]}):
            raise PreregistrationError("report_range_label_mismatch")
        if payload["config_errors"]:
            raise PreregistrationError("verifier_configuration_diagnostics")
        if threshold not in SEVERITIES:
            raise PreregistrationError("unsupported_verifier_policy")
        blocked = any(finding.blocks(threshold) for finding in findings)
        if verdict != ("block" if blocked else "pass") or code != (1 if blocked else 0):
            raise PreregistrationError("verifier_policy_or_channel_disagreement")
        return MultiDispatchVerifierObservation(cid, canonical_digest(case_binding(lock, cid)), command, materials,
            captures, not blocked, verdict, code, threshold, findings, skipped, ())
    except (ValueError, TypeError, KeyError, AttributeError) as exc:
        return MultiDispatchVerifierObservation(cid, canonical_digest(case_binding(prepared.lock(), cid)), command, materials,
            captures, None, verdict, code, threshold, findings, skipped, (str(exc),))


def _auxiliary(row, mapped, store):
    cid = row["binding"]["case_id"]
    # Every role/ref is already closed by _read_observations. Missing auxiliary
    # captures are permitted, but a present own-role claim must match own bytes.
    for key, ref in row["captures"].items():
        parts = key.split(".")
        slot = ((cid, "runner_command", parts[1]) if parts[0] == "runner" and len(parts) == 3 else
                (cid, "verifier_command", "attack") if parts[0] == "verifier" else None)
        if slot is None or ref["state"] == "missing":
            continue
        proof = mapped[action_key(*slot)].proof
        if proof is not None and store.read(ref) != dict(proof.outputs).get(parts[-1]):
            raise ProvenanceError("multi_dispatch_auxiliary_role_contradicts_original_output")
    return tuple(sorted([(role, _json(ref)) for role, ref in row["captures"].items()] +
                        [("runner_artifact:" + path, _json(ref)) for path, ref in row["runner_artifacts"].items()]))


def _roles(prepared, store, archive, grant, records, states, events):
    repository, rid = store.root.repository, store.root.repository_id
    roles = [MultiDispatchSourceRole("product_source", store.root.product_repository, None, prepared.request.source_commit),
        MultiDispatchSourceRole("phase1", store.root.product_repository, None, prepared.lock()["phase1_commit"]),
        MultiDispatchSourceRole("archive_ec_source", repository, rid, archive.grant.ec_source_commit),
        MultiDispatchSourceRole("anchor", repository, rid, grant.anchor.commit),
        MultiDispatchSourceRole("archive", repository, rid, archive.grant.receipt_commit),
        MultiDispatchSourceRole("mapping", repository, rid, grant.evidence_commit)]
    authorization = prepared.request.authorization_ref
    try:
        request_repository = GovernanceReference.parse(authorization).repository
    except ValueError:
        request_repository = None
    roles.append(MultiDispatchSourceRole("run_authorization", request_repository, None, None, authorization))
    refs = {authorization, archive.grant.acceptance_ref,
            *[getattr(grant, name + "_acceptance_ref") for name in ("anchor", "publisher", "coordinator", "mapping")]}
    if archive.grant.supervisor_acceptance_ref is not None:
        refs.add(archive.grant.supervisor_acceptance_ref)
    for record in records:
        key = action_key(**record["slot"])
        configured = record["source"]
        if configured is not None:
            dispatch = configured["dispatch"]
            for name, revision in (("configured_ec_source", dispatch["ec_source_commit"]),
                    ("configured_receipt", configured["receipt_commit"]),
                    ("configured_admission", configured["admission"]["evidence_commit"])):
                roles.append(MultiDispatchSourceRole(key + ":" + name, dispatch["repository"],
                                                    dispatch["repository_id"], revision))
            refs.update(configured["admission"][name] for name in
                        ("collector_acceptance_ref", "host_storage_acceptance_ref", "journal_acceptance_ref"))
        revision = states[key]["disposition"]["provenance_ref"]
        if revision is not None:
            roles.append(MultiDispatchSourceRole(key + ":recorded_receipt", repository, rid, revision))
    for event in events:
        facts = event["facts"]
        if "dispatch" not in facts:
            continue
        dispatch = facts["dispatch"]
        roles.append(MultiDispatchSourceRole("coordinator_ec_source:" + str(event["seq"]),
            dispatch["repository"], dispatch["repository_id"], dispatch["ec_source_commit"]))
        if "receipt_commit" in facts:
            roles.append(MultiDispatchSourceRole("coordinator_claimed_receipt:" + str(event["seq"]),
                dispatch["repository"], dispatch["repository_id"], facts["receipt_commit"]))
    return tuple(roles), refs


def _configuration(authority):
    """Bind imported settings too, including refs absent from the raw map."""
    # Constructor checks exact outer/nested source types before acquisition.
    EcMultiDispatchSourceMapAuthority(authority.archive, authority.grant, authority.actions)
    for item in authority.actions:
        TerminalMappedAction(item.case_id, item.kind, item.arm, item.ticket, item.authority,
                            item.release_sequence, item.publication_sequence, item.journal_sha256)
    return canonical_digest({"archive_root": asdict(authority.archive.root),
        "grant": asdict(authority.grant), "actions": [{"record": _record(member),
            "root": asdict(member.authority.store.root) if member.authority is not None else None}
            for member in authority.actions]})


def _stable_authority(original):
    def store_copy(store):
        fresh = _fresh_store(store)
        root = replace(fresh.root, publications=tuple(replace(item) for item in fresh.root.publications))
        return EcReceiptStore(root, transport=fresh.transport)

    members = []
    for item in original.actions:
        # Recheck exact nested types after construction of the caller carrier.
        TerminalMappedAction(item.case_id, item.kind, item.arm, item.ticket, item.authority,
                            item.release_sequence, item.publication_sequence, item.journal_sha256)
        action = item.authority
        copied = None if action is None else EcLifecycleCompletionAuthority(store_copy(action.store),
            replace(action.admission), tuple(replace(grant) for grant in action.actions))
        members.append(TerminalMappedAction(item.case_id, item.kind, item.arm,
            replace(item.ticket) if item.ticket is not None else None, copied,
            item.release_sequence, item.publication_sequence, item.journal_sha256))
    grant = replace(original.grant, anchor=replace(original.grant.anchor))
    return EcMultiDispatchSourceMapAuthority(store_copy(original.archive), grant, tuple(members))


def read_multi_dispatch_observations(prepared: PreparedRun, *,
        authority: EcMultiDispatchSourceMapAuthority) -> MultiDispatchObservationSnapshot | None:
    """Reacquire configured original sources before computing a full snapshot.

    Structural contradictions reject the whole snapshot. Missing, rejected or
    semantically invalid observations remain in the complete frozen denominator.
    Constructors, caller snapshots, flat F captures and instance hooks grant nothing.
    """
    try:
        if type(authority) is not EcMultiDispatchSourceMapAuthority or type(prepared) is not PreparedRun:
            raise ProvenanceError("exact multi-dispatch source authority and frozen preparation required")
        original_authority = authority
        configuration_sha = _configuration(authority)
        authority = _stable_authority(authority)
        source = EcMultiDispatchSourceMapAuthority._verify(authority, prepared)
        store, grant = _fresh_store(authority.archive), authority.grant
        archive = EcReceiptStore.read(store, prepared)
        dispatch = _dispatch(store, archive.grant)
        mapping_bytes = store.reader.blob_at(store.root.repository, grant.evidence_commit, grant.evidence_path)
        raw_map = json_mapping(mapping_bytes, "multi-dispatch original mapping")
        archive_bytes = archive.artifact(grant.archive_path)
        archive_index = json_mapping(archive_bytes, "multi-dispatch original archive index")
        if (archive.grant.receipt_commit != source.final_archive_ref or grant.evidence_commit != source.mapping_evidence_ref
                or digest(mapping_bytes) != source.mapping_sha256 or digest(mapping_bytes) != grant.evidence_sha256
                or digest(archive_bytes) != grant.archive_sha256):
            raise ProvenanceError("multi-dispatch source changed during semantic acquisition")
        _same(raw_map["archive_dispatch"], dispatch, "multi-dispatch archive dispatch changed")
        _same(raw_map["final_archive"], {"commit": source.final_archive_ref,
            "publication_sha256": archive.grant.publication_sha256,
            "index": {"path": grant.archive_path, "sha256": digest(archive_bytes)}}, "multi-dispatch archive pin changed")
        if raw_map["schema_version"] != MAP_SCHEMA or canonical_digest(raw_map["session"]) != source.session_sha256:
            raise ProvenanceError("multi-dispatch session/schema changed")
        _same(raw_map["session"], _session(prepared, store, grant.anchor), "multi-dispatch current session changed")
        _same(raw_map["anchor"], grant.anchor.payload(), "multi-dispatch current anchor changed")
        _same(raw_map["contracts"], {name: getattr(grant, name + "_acceptance_ref")
            for name in ("anchor", "publisher", "coordinator", "mapping")}, "multi-dispatch contracts changed")
        _same(raw_map["assembler"], {"path": grant.assembler_path, "sha256": grant.assembler_sha256},
              "multi-dispatch current assembler changed")
        records = raw_map["actions"]
        members = {item.key: item for item in authority.actions}
        _same(records, [_record(members[action_key(*slot)]) for slot in slots(prepared.lock())],
              "multi-dispatch configured records changed during semantic acquisition")
        _same(archive_index, {"schema_version": ARCHIVE_SCHEMA, "session_sha256": source.session_sha256,
            "archive_dispatch": dispatch, "anchor": raw_map["anchor"],
            "ledger": {"path": grant.ledger_path, "sha256": grant.ledger_sha256},
            "journal": {"path": grant.journal_path, "sha256": grant.journal_sha256}, "actions": records},
            "multi-dispatch original archive index changed")
        ledger, journal = archive.artifact(grant.ledger_path), archive.artifact(grant.journal_path)
        if digest(ledger) != grant.ledger_sha256 or digest(journal) != source.coordinator_journal_sha256:
            raise ProvenanceError("multi-dispatch ledger/journal changed")
        entries, _ = _entries(ledger)
        state = verify_lifecycle_protocol(entries, expected_lock=prepared.lock(), expected_plan=action_plan(prepared))
        if not state["ok"] or entries[-1]["event_type"] != "observations_sealed":
            raise ProvenanceError("multi-dispatch original sealed ledger invalid")
        artifacts = _ArchiveArtifacts(archive)
        _read_frozen(prepared, entries, artifacts)
        index_bytes = artifacts.read(entries[-1]["payload"]["index"])
        index = json_mapping(index_bytes, "multi-dispatch observation index")
        _read_observations(prepared, index, state["action_states"], artifacts)
        _same(index["actions"], {key: value["disposition"] for key, value in state["action_states"].items()},
              "multi-dispatch index changes sealed actions")
        events = json_mapping(journal, "multi-dispatch coordinator journal")["events"]
        mapped = {action_key(*item.slot): item for item in source.actions}
        summaries = {action_key(**record["slot"]): _summary(mapped[action_key(**record["slot"])],
            state["action_states"][action_key(**record["slot"])], record["source"],
            members[action_key(**record["slot"])], events) for record in records}
        roles, acceptance_refs = _roles(prepared, store, archive, grant, records, state["action_states"], events)
        for summary in summaries.values():
            if summary.configured is not None:
                acceptance_refs.add(summary.configured.publication_acceptance_ref)
                if summary.configured.supervisor_acceptance_ref is not None:
                    acceptance_refs.add(summary.configured.supervisor_acceptance_ref)
        cases = []
        for row in index["cases"]:
            cid = row["binding"]["case_id"]
            auxiliary = _auxiliary(row, mapped, artifacts)
            runner = _runner(prepared, cid, mapped, summaries)
            attack, attack_reasons = assess_bound_change(prepared.profile(cid), runner.arm("baseline"),
                                                         runner.arm("attack"), runner.arm("repair"))
            twin, twin_reasons = (assess_bound_change(prepared.profile(cid), runner.arm("baseline"),
                runner.arm("twin"), runner.arm("repair")) if "twin" in prepared.binding(cid)["arms"] else (None, ()))
            cases.append(MultiDispatchCaseObservation(cid, runner, _verifier(prepared, cid, mapped, summaries),
                EffectivenessAssessment(cid, attack, twin, attack_reasons, twin_reasons),
                tuple(sorted((name, _json(ref)) for name, ref in row["validations"].items())), auxiliary))
        if _configuration(original_authority) != configuration_sha or _configuration(authority) != configuration_sha:
            raise ProvenanceError("multi-dispatch configuration changed during semantic acquisition")
        return MultiDispatchObservationSnapshot(SCHEMA, source.request_sha256, source.lock_digest,
            source.plan_sha256, source.session_sha256, _json(dispatch), source.prelaunch_anchor_ref,
            source.final_archive_ref, source.mapping_evidence_ref, source.mapping_sha256, digest(archive_bytes),
            digest(ledger), digest(index_bytes), digest(journal), _json({"contracts": raw_map["contracts"],
                "anchor": raw_map["anchor"], "assembler": raw_map["assembler"]}), roles,
            tuple(sorted(acceptance_refs)), tuple(summaries[action_key(*slot)] for slot in slots(prepared.lock())), tuple(cases))
    except (ValueError, TypeError, KeyError, OSError, AttributeError, StopIteration):
        return None
