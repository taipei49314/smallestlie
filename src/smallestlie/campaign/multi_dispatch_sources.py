"""GET-only cross-terminal source map, separate from all v1 authority carriers."""

from __future__ import annotations

from dataclasses import asdict, dataclass

from smallestlie.attacks.adjudication import choice, sha256, string
from smallestlie.campaign.completion_source import (
    EcLifecycleCompletionAuthority, LifecycleActionGrant, LifecycleCollectorAdmission, _dispatch, _same,
)
from smallestlie.campaign.evidence_sources import EcPublicationGrant, EcReceiptStore, EcReceiptTrustRoot, _artifact_path
from smallestlie.campaign.lifecycle import ActionValidation, ArtifactStore, encoded, validate_completion
from smallestlie.campaign.preregistration import PreparedRun, canonical_digest, commit, digest, integer, json_mapping
from smallestlie.campaign.provenance import ProvenanceError
from smallestlie.campaign.publication_order import verify_publication_order
from smallestlie.campaign.source_map import LifecycleAnchorGrant, _entries
from smallestlie.ledger.lifecycle import (
    KINDS, ActionReservation, action_key, action_plan, prerequisites, slots, verify_lifecycle_protocol,
)

PROVIDER = "ec-multi-dispatch-source-map/v2"
MAP_SCHEMA = "smallestlie.lifecycle-source-map/v2"
ARCHIVE_SCHEMA = "smallestlie.lifecycle-source-archive/v2"
ANCHOR_SCHEMA = "smallestlie.lifecycle-source-anchor/v2"


@dataclass(frozen=True)
class MultiDispatchAnchorGrant:
    commit: str
    path: str
    sha256: str
    prefix_path: str
    prefix_sha256: str
    journal_epoch: str
    ack_sequence: int

    def __post_init__(self):
        # Reuse path/hash/native-integer checks, not the v1 anchor schema.
        LifecycleAnchorGrant(**asdict(self))

    def payload(self):
        return asdict(self)


@dataclass(frozen=True)
class MultiDispatchSourceMapGrant:
    """Imported exact contracts; constructors/hashes cannot establish admission."""

    evidence_commit: str
    evidence_path: str
    evidence_sha256: str
    archive_path: str
    archive_sha256: str
    ledger_path: str
    ledger_sha256: str
    journal_path: str
    journal_sha256: str
    assembler_path: str
    assembler_sha256: str
    anchor: MultiDispatchAnchorGrant
    anchor_acceptance_ref: str
    publisher_acceptance_ref: str
    coordinator_acceptance_ref: str
    mapping_acceptance_ref: str

    def __post_init__(self):
        commit(self.evidence_commit, "external map evidence")
        if type(self.anchor) is not MultiDispatchAnchorGrant or self.anchor.commit == self.evidence_commit:
            raise ProvenanceError("distinct v2 prospective anchor and map evidence required")
        paths = [self.evidence_path, self.archive_path, self.ledger_path, self.journal_path, self.assembler_path]
        for path in paths:
            _artifact_path(path)
        if len({path.casefold() for path in paths}) != len(paths) or "ec-publication.json" in paths:
            raise ProvenanceError("map source paths need separate acyclic roles")
        for name in ("evidence_sha256", "archive_sha256", "ledger_sha256", "journal_sha256", "assembler_sha256"):
            sha256(getattr(self, name), name)
        refs = [getattr(self, name + "_acceptance_ref") for name in ("anchor", "publisher", "coordinator", "mapping")]
        for ref in refs:
            string(ref, "independent v2 contract acceptance")
        if len(set(refs)) != len(refs):
            raise ProvenanceError("anchor, publisher, coordinator and mapping acceptances must differ")


def _fresh_store(store):
    if (type(store) is not EcReceiptStore or type(store.root) is not EcReceiptTrustRoot
            or len(store.root.publications) != 1
            or any(type(item) is not EcPublicationGrant for item in store.root.publications)):
        raise ProvenanceError("one exact independently configured store/publication required")
    return EcReceiptStore(store.root, transport=store.transport)


@dataclass(frozen=True)
class TerminalMappedAction:
    case_id: str
    kind: str
    arm: str
    ticket: ActionReservation | None
    authority: EcLifecycleCompletionAuthority | None
    release_sequence: int | None
    publication_sequence: int | None
    journal_sha256: str | None

    def __post_init__(self):
        string(self.case_id, "terminal mapped case")
        choice(self.kind, "terminal mapped action", KINDS)
        choice(self.arm, "terminal mapped arm", {"baseline", "attack", "twin", "repair"})
        if self.ticket is not None and (type(self.ticket) is not ActionReservation
                or (self.ticket.case_id, self.ticket.kind, self.ticket.arm) != self.slot):
            raise ProvenanceError("terminal ticket belongs to another slot")
        if self.authority is None:
            if any(value is not None for value in (self.release_sequence, self.publication_sequence, self.journal_sha256)):
                raise ProvenanceError("missing independent source cannot invent accepted sequences or raw journal")
        else:
            authority = self.authority
            if (type(authority) is not EcLifecycleCompletionAuthority or self.ticket is None
                    or type(authority.admission) is not LifecycleCollectorAdmission
                    or type(authority.actions) is not tuple or len(authority.actions) != 1
                    or type(authority.actions[0]) is not LifecycleActionGrant
                    or authority.actions[0].reservation_sha256 != canonical_digest(self.ticket.to_dict())):
                raise ProvenanceError("one exact typed independent source per terminal slot required")
            _fresh_store(authority.store)
            integer(self.release_sequence, "coordinator release sequence", minimum=1)
            integer(self.publication_sequence, "coordinator publication sequence", minimum=1)
            if self.publication_sequence <= self.release_sequence:
                raise ProvenanceError("publication ACK must follow its release")
            sha256(self.journal_sha256, "independently granted child journal")

    @property
    def slot(self):
        return self.case_id, self.kind, self.arm

    @property
    def key(self):
        return action_key(*self.slot)


@dataclass(frozen=True)
class TerminalActionProof:
    slot: tuple[str, str, str]
    action_receipt_ref: str
    dispatch: tuple[tuple[str, str | int], ...]
    reservation: ActionReservation
    validation: ActionValidation
    completion: bytes
    sources: tuple[tuple[str, bytes], ...]
    outputs: tuple[tuple[str, bytes | None], ...]
    prefix: bytes
    journal: bytes


@dataclass(frozen=True)
class TerminalActionResult:
    slot: tuple[str, str, str]
    state: str
    proof: TerminalActionProof | None
    eligible: bool
    reasons: tuple[str, ...]


@dataclass(frozen=True)
class VerifiedMultiDispatchSourceMap:
    provider_id: str
    session_sha256: str
    request_sha256: str
    lock_digest: str
    plan_sha256: str
    prelaunch_anchor_ref: str
    final_archive_ref: str
    mapping_evidence_ref: str
    mapping_sha256: str
    mapping_acceptance_ref: str
    coordinator_journal_sha256: str
    actions: tuple[TerminalActionResult, ...]


def _session(prepared, store, anchor):
    grant = store.root.publications[0]
    return {"request_sha256": grant.request_sha256, "lock_digest": grant.lock_digest,
            "source_commit": grant.source_commit, "phase1_commit": prepared.lock()["phase1_commit"],
            "plan_sha256": canonical_digest(action_plan(prepared)),
            "trust_root_sha256": canonical_digest({key: val for key, val in asdict(store.root).items()
                                                  if key != "publications"}),
            "coordinator_epoch": anchor.journal_epoch}


def _source(member):
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
                         "first_event_sequence": action.first_event_sequence,
                         "last_event_sequence": action.last_event_sequence},
            "journal_sha256": member.journal_sha256, "release_sequence": member.release_sequence,
            "publication_sequence": member.publication_sequence}


def _record(member):
    return {"slot": {"case_id": member.case_id, "kind": member.kind, "arm": member.arm},
            "reservation": member.ticket.to_dict() if member.ticket is not None else None,
            "source": _source(member)}


class _ExactApproval:
    """Private raw-validation bridge populated only by a fresh native reader."""

    def __init__(self, prepared, ticket, completion_sha, approval):
        self.prepared, self.ticket_sha, self.completion_sha = prepared, canonical_digest(ticket.to_dict()), completion_sha
        self.approval = approval

    def verify(self, prepared, ticket, completion_sha):
        return self.approval if (prepared is self.prepared and canonical_digest(ticket.to_dict()) == self.ticket_sha
                                 and completion_sha == self.completion_sha) else None


def _proof(prepared, member):
    # Reconstruct readers rather than invoking a caller's instance verify/read
    # hook or using an already constructed proof/result as source authority.
    original = member.authority
    authority = EcLifecycleCompletionAuthority(_fresh_store(original.store), original.admission, original.actions)
    try:
        receipt = EcReceiptStore.read(authority.store, prepared)
        action = authority.actions[0]
        completion = receipt.artifact(action.completion_path)
        approval = EcLifecycleCompletionAuthority.verify(authority, prepared, member.ticket, digest(completion))
        if approval is None:
            return None
        facts = json_mapping(receipt.artifact(action.supervisor_path), "terminal action facts")
        sources = {"publication": receipt.artifact(action.publication_path),
                   "supervisor": receipt.artifact(action.supervisor_path)}
        outputs = {role: receipt.artifact(ref["path"]) if ref is not None else None
                   for role, ref in facts["outputs"].items()}
        validation = validate_completion(prepared, member.ticket, completion, sources, outputs,
            authority=_ExactApproval(prepared, member.ticket, digest(completion), approval))
        if not validation.valid or validation.provenance_ref != receipt.grant.receipt_commit:
            return None
        journal = receipt.artifact(facts["journal"]["path"])
        prefix = receipt.artifact(facts["prefix"]["path"])
    except (ValueError, TypeError, KeyError, OSError, AttributeError):
        return None
    if digest(journal) != member.journal_sha256:
        raise ProvenanceError("known independent child journal contradicts exact map grant")
    return TerminalActionProof(member.slot, receipt.grant.receipt_commit,
        tuple(sorted(_dispatch(authority.store, receipt.grant).items())), member.ticket, validation, completion,
        tuple(sorted(sources.items())), tuple(sorted(outputs.items())), prefix, journal)


def _archived(archive, ref):
    if ref["state"] == "missing":
        return None
    data = archive.artifact("artifacts/" + ref["sha256"])
    if ArtifactStore.reference(data) != ref:
        raise ProvenanceError("final archive changes content-addressed raw ledger artifact")
    return data


class EcMultiDispatchSourceMapAuthority:
    """Exact separate GET-only contract; no legacy authority or launch driver."""

    def __init__(self, archive: EcReceiptStore, grant: MultiDispatchSourceMapGrant,
                 actions: tuple[TerminalMappedAction, ...]):
        _fresh_store(archive)
        if type(grant) is not MultiDispatchSourceMapGrant:
            raise ProvenanceError("exact v2 external source-map grant required")
        if (type(actions) is not tuple or not actions or any(type(item) is not TerminalMappedAction for item in actions)
                or len({item.key for item in actions}) != len(actions)):
            raise ProvenanceError("unique explicit full-slot terminal configuration required")
        self.archive, self.grant, self.actions = archive, grant, actions

    def verify(self, prepared: PreparedRun) -> VerifiedMultiDispatchSourceMap | None:
        try:
            if type(prepared) is not PreparedRun:
                raise ProvenanceError("exact frozen preparation required")
            return EcMultiDispatchSourceMapAuthority._verify(self, prepared)
        except (ValueError, TypeError, KeyError, OSError, AttributeError, StopIteration):
            return None

    def _verify(self, prepared):
        store, grant = _fresh_store(self.archive), self.grant
        archive = EcReceiptStore.read(store, prepared)
        dispatch = _dispatch(store, archive.grant)
        plan = action_plan(prepared)
        members = {item.key: item for item in self.actions}
        if members.keys() != plan.keys():
            raise ProvenanceError("terminal map omits or adds frozen slots")
        sources = [item for item in self.actions if item.authority is not None]
        roles = [grant.anchor.commit, grant.evidence_commit, archive.grant.receipt_commit,
                 *[item.authority.store.root.publications[0].receipt_commit for item in sources]]
        input_refs = {prepared.request.source_commit, prepared.lock()["phase1_commit"], archive.grant.ec_source_commit,
                      *[item.authority.store.root.publications[0].ec_source_commit for item in sources]}
        authority_input_refs = {item.authority.admission.evidence_commit for item in sources}
        if len(set(roles)) != len(roles) or set(roles) & input_refs:
            raise ProvenanceError("anchor/map/archive/action roles must differ from every immutable input")
        common = {key: val for key, val in asdict(store.root).items() if key != "publications"}
        for member in sources:
            root = member.authority.store.root
            _same({key: val for key, val in asdict(root).items() if key != "publications"}, common,
                  "terminal trust-root/pin/host differs from final archive")
            publication = root.publications[0]
            _same({key: getattr(publication, key) for key in ("request_sha256", "lock_digest", "source_commit")},
                  {key: getattr(archive.grant, key) for key in ("request_sha256", "lock_digest", "source_commit")},
                  "terminal action belongs to a different frozen campaign")
            action_dispatch = _dispatch(member.authority.store, publication)
            _same({key: getattr(member.authority.admission, key) for key in action_dispatch if key != "repository"},
                  {key: val for key, val in action_dispatch.items() if key != "repository"},
                  "configured action admission contradicts its exact dispatch")
            if member.authority.admission.evidence_commit in set(roles) | input_refs:
                raise ProvenanceError("action admission must remain outside input/output roles")

        session = _session(prepared, store, grant.anchor)
        session_sha = canonical_digest(session)
        anchor_prefix = store.reader.blob_at(store.root.repository, grant.anchor.commit, grant.anchor.prefix_path)
        anchor_bytes = store.reader.blob_at(store.root.repository, grant.anchor.commit, grant.anchor.path)
        if digest(anchor_prefix) != grant.anchor.prefix_sha256 or digest(anchor_bytes) != grant.anchor.sha256:
            raise ProvenanceError("prospective v2 anchor raw bytes mismatch")
        anchor_entries, _ = _entries(anchor_prefix)
        initial = verify_lifecycle_protocol(anchor_entries, expected_lock=prepared.lock(), expected_plan=plan)
        if (not initial["ok"] or not initial["locked"] or initial["action_states"]
                or anchor_entries[-1]["event_type"] != "preregistration_locked"):
            raise ProvenanceError("v2 anchor must end at the original pre-reservation lock")
        _same(json_mapping(anchor_bytes, "prospective v2 anchor"), {"schema_version": ANCHOR_SCHEMA,
            "session": session, "locked_prefix": {"path": grant.anchor.prefix_path, "sha256": digest(anchor_prefix)}},
            "prospective anchor cannot name future dispatches, receipts or its own commit")
        if digest(store.reader.blob_at(store.root.repository, archive.grant.ec_source_commit,
                grant.assembler_path)) != grant.assembler_sha256:
            raise ProvenanceError("final-archive assembler source pin mismatch")
        records = [_record(members[action_key(*slot)]) for slot in slots(prepared.lock())]
        contracts = {name: getattr(grant, name + "_acceptance_ref")
                     for name in ("anchor", "publisher", "coordinator", "mapping")}
        evidence = store.reader.blob_at(store.root.repository, grant.evidence_commit, grant.evidence_path)
        if digest(evidence) != grant.evidence_sha256:
            raise ProvenanceError("external v2 mapping evidence raw bytes mismatch")
        _same(json_mapping(evidence, "cross-dispatch map"), {"schema_version": MAP_SCHEMA,
            "session": session, "archive_dispatch": dispatch, "contracts": contracts,
            "assembler": {"path": grant.assembler_path, "sha256": grant.assembler_sha256},
            "anchor": grant.anchor.payload(), "final_archive": {"commit": archive.grant.receipt_commit,
                "publication_sha256": archive.grant.publication_sha256,
                "index": {"path": grant.archive_path, "sha256": grant.archive_sha256}}, "actions": records},
            "external v2 map exact session/source binding mismatch")
        index = archive.artifact(grant.archive_path)
        if digest(index) != grant.archive_sha256:
            raise ProvenanceError("v2 archive index raw bytes mismatch")
        _same(json_mapping(index, "cross-dispatch archive index"), {"schema_version": ARCHIVE_SCHEMA,
            "session_sha256": session_sha, "archive_dispatch": dispatch, "anchor": grant.anchor.payload(),
            "ledger": {"path": grant.ledger_path, "sha256": grant.ledger_sha256},
            "journal": {"path": grant.journal_path, "sha256": grant.journal_sha256}, "actions": records},
            "v2 archive index changes earlier roles or contains a final/map backreference")
        ledger = archive.artifact(grant.ledger_path)
        if digest(ledger) != grant.ledger_sha256 or not ledger.startswith(anchor_prefix):
            raise ProvenanceError("v2 archive does not extend the original raw anchor")
        entries, lines = _entries(ledger)
        state = verify_lifecycle_protocol(entries, expected_lock=prepared.lock(), expected_plan=plan)
        if (not state["ok"] or not state["locked"] or state["snapshot_sha256"] is None
                or entries[-1]["event_type"] != "observations_sealed" or state["action_states"].keys() != plan.keys()):
            raise ProvenanceError("v2 final ledger must seal the complete frozen denominator before reviews")
        states, expectations = state["action_states"], {}
        for key, member in members.items():
            _same(states[key]["reservation"], member.ticket.to_dict() if member.ticket is not None else None,
                  "terminal ticket contradicts the sealed raw ledger")
            record = states[key]["disposition"]
            if record is None or record["provenance_ref"] in roles[:3]:
                raise ProvenanceError("missing disposition or cyclic source role")
            source = _source(member)
            if source is not None:
                _same({"completion": record["completion"]["sha256"],
                       "supervisor": record["sources"]["supervisor"]["sha256"],
                       "publication": record["sources"]["publication"]["sha256"],
                       "provenance_ref": record["provenance_ref"]},
                      {"completion": source["completion"]["sha256"], "supervisor": source["supervisor"]["sha256"],
                       "publication": source["publication"]["sha256"], "provenance_ref": source["receipt_commit"]},
                      "configured source contradicts preserved ledger raw digests/provenance")
            for ref in (record["completion"], record["validation"], *record["sources"].values(), *record["outputs"].values()):
                _archived(archive, ref)
            if member.ticket is not None:
                expectations[canonical_digest(member.ticket.to_dict())] = {"ticket_seq": member.ticket.seq,
                    "prefix_sha256": digest(b"".join(lines[:member.ticket.seq])),
                    "context_sha256": member.ticket.context_sha256, "status": record["status"],
                    "completion_sha256": record["completion"]["sha256"],
                    "action_publication_sha256": record["sources"]["publication"]["sha256"],
                    "provenance_ref": record["provenance_ref"], "source": _source(member)}
        _archived(archive, entries[-1]["payload"]["index"])
        journal = archive.artifact(grant.journal_path)
        if digest(journal) != grant.journal_sha256:
            raise ProvenanceError("accepted coordinator raw journal mismatch")
        verify_publication_order(journal, session_sha256=session_sha, epoch=grant.anchor.journal_epoch,
            anchor=grant.anchor.payload(), anchor_sequence=grant.anchor.ack_sequence, expectations=expectations,
            common_dispatch=dispatch, input_refs=input_refs, authority_input_refs=authority_input_refs,
            output_refs=set(roles))

        proofs, rejected = {}, {}
        for key, member in members.items():
            if member.authority is None:
                continue
            proof = _proof(prepared, member)
            if proof is None:
                rejected[key] = ("independent_terminal_source_rejected",)
                continue
            if proof.prefix != b"".join(lines[:member.ticket.seq]):
                raise ProvenanceError("terminal source uses a different original ledger prefix")
            validation, context = proof.validation, plan[key]
            expected = {"binding": context["binding"], "kind": member.kind, "arm": member.arm,
                "context_sha256": member.ticket.context_sha256, "reservation": member.ticket.to_dict(),
                "status": validation.status, "completion": ArtifactStore.reference(proof.completion),
                "validation": ArtifactStore.reference(encoded(asdict(validation))),
                "sources": {role: ArtifactStore.reference(raw) for role, raw in proof.sources},
                "outputs": {role: ArtifactStore.reference(raw) for role, raw in proof.outputs},
                "provenance_ref": proof.action_receipt_ref, "reasons": list(validation.reasons)}
            _same(states[key]["disposition"], expected, "known terminal proof contradicts sealed disposition")
            for raw in (proof.completion, encoded(asdict(validation)), *(value for _, value in proof.sources),
                        *(value for _, value in proof.outputs)):
                if raw is not None and _archived(archive, ArtifactStore.reference(raw)) != raw:
                    raise ProvenanceError("final archive changed original independently proven bytes")
            proofs[key] = proof
        results = []
        for slot in slots(prepared.lock()):
            key, proof = action_key(*slot), proofs.get(action_key(*slot))
            reasons = rejected.get(key, ("independent_terminal_source_missing",)) if proof is None else ()
            if proof is not None and any(dep not in proofs or proofs[dep].validation.status != "completed"
                                         for dep in prerequisites(*slot)):
                reasons = ("independently_completed_materialization_missing",)
            results.append(TerminalActionResult(slot, "source_rejected" if key in rejected else
                "source_missing" if proof is None else "observed", proof, proof is not None and not reasons, reasons))
        return VerifiedMultiDispatchSourceMap(PROVIDER, session_sha, archive.grant.request_sha256,
            archive.grant.lock_digest, session["plan_sha256"], grant.anchor.commit, archive.grant.receipt_commit,
            grant.evidence_commit, digest(evidence), grant.mapping_acceptance_ref, digest(journal), tuple(results))
