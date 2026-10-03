"""Offline cross-action sources, with distinct anchors, receipts and archives.

Only externally imported exact grants configure this reader. The typed mapped
results are deliberately not legacy completion/runner/verifier envelopes and
do not activate FormalLifecycle or a launch driver.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass

from smallestlie.attacks.adjudication import choice, mapping, sha256, string
from smallestlie.campaign.completion_source import EcLifecycleCompletionAuthority, _dispatch, _same
from smallestlie.campaign.evidence_sources import EcReceiptStore, _artifact_path
from smallestlie.campaign.lifecycle import ActionValidation, ArtifactStore, encoded, validate_completion
from smallestlie.campaign.preregistration import PreparedRun, canonical_digest, commit, digest, integer, json_mapping
from smallestlie.campaign.provenance import ProvenanceError
from smallestlie.ledger.chain import payload_digest
from smallestlie.ledger.lifecycle import (
    KINDS, OBSERVED, ActionReservation, action_key, action_plan, prerequisites, slots, verify_lifecycle_protocol,
)

PROVIDER = "ec-lifecycle-source-map/v1"
MAP_SCHEMA = "smallestlie.lifecycle-source-map/v1"
ARCHIVE_SCHEMA = "smallestlie.lifecycle-source-archive/v1"
ANCHOR_SCHEMA = "smallestlie.lifecycle-source-anchor/v1"
JOURNAL_SCHEMA = "smallestlie.lifecycle-publication-journal/v1"


@dataclass(frozen=True)
class LifecycleAnchorGrant:
    commit: str
    path: str
    sha256: str
    prefix_path: str
    prefix_sha256: str
    journal_epoch: str
    ack_sequence: int

    def __post_init__(self):
        commit(self.commit, "prospective anchor commit")
        for value in (self.path, self.prefix_path):
            _artifact_path(value)
        if self.path.casefold() == self.prefix_path.casefold() or "ec-publication.json" in (self.path, self.prefix_path):
            raise ProvenanceError("separate prospective anchor and locked-prefix roles required")
        sha256(self.sha256, "anchor digest")
        sha256(self.prefix_sha256, "locked prefix digest")
        string(self.journal_epoch, "publisher journal epoch")
        integer(self.ack_sequence, "native anchor ACK sequence", minimum=1)

    def payload(self):
        return asdict(self)


@dataclass(frozen=True)
class LifecycleSourceMapGrant:
    """Exact external mapping/anchor/publisher acceptance, never bundle discovery.

    The trusted caller accepts the actual pinned assembler/publisher, including
    durable anchor readback and receipt delivery before the next action. Hashes,
    native sequence values and this constructor cannot establish that fact.
    """

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
    anchor: LifecycleAnchorGrant
    anchor_acceptance_ref: str
    publisher_acceptance_ref: str
    mapping_acceptance_ref: str

    def __post_init__(self):
        commit(self.evidence_commit, "independent map evidence commit")
        if type(self.anchor) is not LifecycleAnchorGrant or self.evidence_commit == self.anchor.commit:
            raise ProvenanceError("independent map evidence and prospective anchor required")
        for name in ("evidence_path", "archive_path", "ledger_path", "journal_path", "assembler_path"):
            _artifact_path(getattr(self, name))
        paths = [self.archive_path, self.ledger_path, self.journal_path]
        if len({p.casefold() for p in paths}) != len(paths) or "ec-publication.json" in paths:
            raise ProvenanceError("archive, ledger, journal and final EC publication roles must differ")
        for name in ("evidence_sha256", "archive_sha256", "ledger_sha256", "journal_sha256", "assembler_sha256"):
            sha256(getattr(self, name), name)
        refs = [self.anchor_acceptance_ref, self.publisher_acceptance_ref, self.mapping_acceptance_ref]
        for ref in refs:
            string(ref, "independent mapping contract acceptance")
        if len(set(refs)) != len(refs):
            raise ProvenanceError("anchor, publisher and mapping contracts need separate acceptances")


@dataclass(frozen=True)
class LifecycleMappedAction:
    case_id: str
    kind: str
    arm: str
    ticket: ActionReservation | None
    authority: EcLifecycleCompletionAuthority | None
    publication_sequence: int | None

    def __post_init__(self):
        string(self.case_id, "mapped case")
        choice(self.kind, "mapped action", KINDS)
        choice(self.arm, "mapped arm", {"baseline", "attack", "twin", "repair"})
        if self.ticket is not None and (type(self.ticket) is not ActionReservation
                or (self.ticket.case_id, self.ticket.kind, self.ticket.arm) != self.slot):
            raise ProvenanceError("mapped ticket belongs to a different slot")
        if self.authority is None:
            if self.publication_sequence is not None:
                raise ProvenanceError("missing source cannot invent an accepted publication sequence")
        elif (type(self.authority) is not EcLifecycleCompletionAuthority or self.ticket is None
                or len(self.authority.actions) != 1
                or len(self.authority.store.root.publications) != 1
                or self.authority.actions[0].reservation_sha256 != canonical_digest(self.ticket.to_dict())):
            raise ProvenanceError("one exact independently configured source per observed slot required")
        else:
            integer(self.publication_sequence, "native publication ACK sequence", minimum=1)

    @property
    def slot(self):
        return self.case_id, self.kind, self.arm

    @property
    def key(self):
        return action_key(*self.slot)


@dataclass(frozen=True)
class MappedActionProof:
    slot: tuple[str, str, str]
    action_receipt_ref: str
    reservation: ActionReservation
    validation: ActionValidation
    completion: bytes
    sources: tuple[tuple[str, bytes], ...]
    outputs: tuple[tuple[str, bytes | None], ...]
    prefix: bytes


@dataclass(frozen=True)
class MappedActionResult:
    slot: tuple[str, str, str]
    state: str
    proof: MappedActionProof | None
    eligible: bool
    reasons: tuple[str, ...]


@dataclass(frozen=True)
class MappedCaseSources:
    case_id: str
    prelaunch_anchor_ref: str
    final_archive_ref: str
    mapping_evidence_ref: str
    mapping_sha256: str
    actions: tuple[MappedActionResult, ...]


@dataclass(frozen=True)
class MappedRunnerSources(MappedCaseSources):
    """Per-command proof refs, not TrustedExecutionEnvelope/immutable_ref."""


@dataclass(frozen=True)
class MappedVerifierSources(MappedCaseSources):
    """Per-materialization/command refs, not TrustedVerifierEnvelope."""


@dataclass(frozen=True)
class VerifiedLifecycleSourceMap:
    provider_id: str
    request_sha256: str
    lock_digest: str
    prelaunch_anchor_ref: str
    final_archive_ref: str
    mapping_evidence_ref: str
    mapping_sha256: str
    mapping_acceptance_ref: str
    actions: tuple[MappedActionResult, ...]

    def _case(self, case_id, prefix, carrier):
        if case_id not in {item.slot[0] for item in self.actions}:
            raise ProvenanceError("undeclared mapped case")
        return carrier(case_id, self.prelaunch_anchor_ref, self.final_archive_ref,
            self.mapping_evidence_ref, self.mapping_sha256,
            tuple(item for item in self.actions if item.slot[0] == case_id and item.slot[1].startswith(prefix)))

    def runner(self, case_id: str) -> MappedRunnerSources:
        return self._case(case_id, "runner_", MappedRunnerSources)

    def verifier(self, case_id: str) -> MappedVerifierSources:
        return self._case(case_id, "verifier_", MappedVerifierSources)


def _entries(data):
    if type(data) is not bytes or not data or len(data) > 10_000_000 or not data.endswith(b"\n"):
        raise ProvenanceError("complete bounded raw ledger required")
    lines = data.splitlines(keepends=True)
    if len(lines) > 10_000 or any(not line.strip() for line in lines):
        raise ProvenanceError("complete nonblank raw ledger entries required")
    result, previous = [], "0" * 64
    for seq, line in enumerate(lines, 1):
        entry = json_mapping(line, "mapped raw ledger entry")
        mapping(entry, "mapped ledger entry", {"schema_version", "seq", "timestamp", "event_type", "tool_version",
            "payload", "payload_digest", "previous_entry_digest", "entry_digest"})
        for field in ("timestamp", "event_type", "tool_version"):
            string(entry[field], "mapped ledger " + field)
        if (integer(entry["seq"], "native ledger sequence", minimum=1) != seq
                or entry["previous_entry_digest"] != previous
                or entry["payload_digest"] != payload_digest(entry["payload"])
                or entry["entry_digest"] != payload_digest({key: entry[key] for key in
                    ("seq", "timestamp", "event_type", "tool_version", "payload_digest", "previous_entry_digest")})):
            raise ProvenanceError("mapped raw ledger chain mismatch")
        result.append(entry)
        previous = entry["entry_digest"]
    return result, lines


def _record(member):
    source = None
    if member.authority is not None:
        authority = member.authority
        action, receipt = authority.actions[0], authority.store.root.publications[0]
        source = {"receipt_commit": receipt.receipt_commit,
            "completion": {"path": action.completion_path, "sha256": action.completion_sha256},
            "supervisor": {"path": action.supervisor_path, "sha256": action.supervisor_sha256},
            "publication": {"path": action.publication_path, "sha256": action.publication_sha256},
            "publication_sequence": member.publication_sequence}
    return {"slot": {"case_id": member.case_id, "kind": member.kind, "arm": member.arm},
            "reservation": member.ticket.to_dict() if member.ticket is not None else None, "source": source}


class EcLifecycleSourceMapAuthority:
    """GET-only sealed offline mapping; intentionally not CompletionAuthority."""

    def __init__(self, archive: EcReceiptStore, grant: LifecycleSourceMapGrant,
                 actions: tuple[LifecycleMappedAction, ...]):
        if type(archive) is not EcReceiptStore or type(grant) is not LifecycleSourceMapGrant:
            raise ProvenanceError("independent archive store and mapping grant required")
        if (type(actions) is not tuple or not actions or any(type(item) is not LifecycleMappedAction for item in actions)
                or len({item.key for item in actions}) != len(actions) or len(archive.root.publications) != 1):
            raise ProvenanceError("unique explicit full-slot source configuration required")
        self.archive, self.grant, self.actions = archive, grant, actions

    def verify(self, prepared: PreparedRun) -> VerifiedLifecycleSourceMap | None:
        try:
            return self._verify(prepared)
        except (ValueError, TypeError, KeyError, OSError, AttributeError, StopIteration):
            return None

    def _verify(self, prepared):
        store, grant = self.archive, self.grant
        archive = store.read(prepared)
        dispatch = _dispatch(store, archive.grant)
        plan = action_plan(prepared)
        members = {item.key: item for item in self.actions}
        if members.keys() != plan.keys():
            raise ProvenanceError("source map drops or adds frozen slots")
        sources = [item for item in self.actions if item.authority is not None]
        receipt_refs = [item.authority.store.root.publications[0].receipt_commit for item in sources]
        roles = [grant.anchor.commit, grant.evidence_commit, archive.grant.receipt_commit, *receipt_refs]
        input_refs = {archive.grant.ec_source_commit, prepared.request.source_commit, prepared.lock()["phase1_commit"]}
        if len(set(roles)) != len(roles) or set(roles) & input_refs:
            raise ProvenanceError("anchor, map evidence, final archive and each action receipt must differ")
        for item in sources:
            root = item.authority.store.root
            if len(root.publications) != 1:
                raise ProvenanceError("one exact receipt per mapped action required")
            _same({key: value for key, value in asdict(root).items() if key != "publications"},
                  {key: value for key, value in asdict(store.root).items() if key != "publications"},
                  "mapped action trust-root/pin/host differs from archive")
            _same(_dispatch(item.authority.store, root.publications[0]), dispatch, "mapped source dispatch mismatch")
            action = item.authority.actions[0]
            if action.journal_epoch != grant.anchor.journal_epoch:
                raise ProvenanceError("mapped action journal epoch mismatch")
        identities = [(item.authority.actions[0].journal_epoch, item.authority.actions[0].action_id) for item in sources]
        if len(set(identities)) != len(identities):
            raise ProvenanceError("one-use identity reused across independent action receipts")

        anchor_prefix = store.reader.blob_at(store.root.repository, grant.anchor.commit, grant.anchor.prefix_path)
        anchor_bytes = store.reader.blob_at(store.root.repository, grant.anchor.commit, grant.anchor.path)
        if digest(anchor_prefix) != grant.anchor.prefix_sha256 or digest(anchor_bytes) != grant.anchor.sha256:
            raise ProvenanceError("prospective anchor raw bytes mismatch")
        anchor_entries, _ = _entries(anchor_prefix)
        locked = verify_lifecycle_protocol(anchor_entries, expected_lock=prepared.lock(), expected_plan=plan)
        if (not locked["ok"] or not locked["locked"] or locked["action_states"]
                or anchor_entries[-1]["event_type"] != "preregistration_locked"):
            raise ProvenanceError("anchor must end at the original lock before any reservation")
        _same(json_mapping(anchor_bytes, "prospective anchor"), {"schema_version": ANCHOR_SCHEMA, "dispatch": dispatch,
            "lock_digest": prepared.lock()["lock_digest"], "plan_sha256": canonical_digest(plan),
            "locked_prefix": {"path": grant.anchor.prefix_path, "sha256": digest(anchor_prefix)}},
            "prospective anchor cannot include future tickets, receipts or own commit")
        if digest(store.reader.blob_at(store.root.repository, archive.grant.ec_source_commit,
                grant.assembler_path)) != grant.assembler_sha256:
            raise ProvenanceError("independently accepted mapping/publisher source pin mismatch")

        records = [_record(members[action_key(*slot)]) for slot in slots(prepared.lock())]
        evidence = store.reader.blob_at(store.root.repository, grant.evidence_commit, grant.evidence_path)
        if digest(evidence) != grant.evidence_sha256:
            raise ProvenanceError("external mapping evidence raw bytes mismatch")
        contracts = {"anchor": grant.anchor_acceptance_ref, "publisher": grant.publisher_acceptance_ref,
                     "mapping": grant.mapping_acceptance_ref}
        _same(json_mapping(evidence, "independent source map"), {"schema_version": MAP_SCHEMA, "dispatch": dispatch,
            "contracts": contracts, "assembler": {"path": grant.assembler_path, "sha256": grant.assembler_sha256},
            "anchor": grant.anchor.payload(), "final_archive": {"commit": archive.grant.receipt_commit,
                "publication_sha256": archive.grant.publication_sha256,
                "index": {"path": grant.archive_path, "sha256": grant.archive_sha256}}, "actions": records},
            "independent source map exact binding mismatch")
        index_bytes = archive.artifact(grant.archive_path)
        if digest(index_bytes) != grant.archive_sha256:
            raise ProvenanceError("source archive index raw bytes mismatch")
        _same(json_mapping(index_bytes, "source archive index"), {"schema_version": ARCHIVE_SCHEMA, "dispatch": dispatch,
            "anchor": grant.anchor.payload(), "ledger": {"path": grant.ledger_path, "sha256": grant.ledger_sha256},
            "journal": {"path": grant.journal_path, "sha256": grant.journal_sha256}, "actions": records},
            "archive index must contain exact earlier roles, not final/map backreferences")
        ledger_bytes = archive.artifact(grant.ledger_path)
        if digest(ledger_bytes) != grant.ledger_sha256 or not ledger_bytes.startswith(anchor_prefix):
            raise ProvenanceError("archive ledger does not extend the exact locked anchor")
        entries, lines = _entries(ledger_bytes)
        state = verify_lifecycle_protocol(entries, expected_lock=prepared.lock(), expected_plan=plan)
        if (not state["ok"] or not state["locked"] or state["snapshot_sha256"] is None
                or entries[-1]["event_type"] != "observations_sealed"
                or state["action_states"].keys() != plan.keys()):
            raise ProvenanceError("source archive must seal every frozen action before reviews")
        states = state["action_states"]
        for key, member in members.items():
            expected_ticket = member.ticket.to_dict() if member.ticket is not None else None
            _same(states[key]["reservation"], expected_ticket, "mapped ticket differs from sealed ledger")
            record = states[key]["disposition"]
            if record is None or record["provenance_ref"] in roles[:3]:
                raise ProvenanceError("missing disposition or cyclic/misassigned provenance role")
            for ref in (record["completion"], record["validation"], *record["sources"].values(), *record["outputs"].values()):
                self._archived(archive, ref)
        self._archived(archive, entries[-1]["payload"]["index"])
        self._publisher(archive, dispatch, members, states, input_refs)

        proofs, rejected = {}, {}
        for key, member in members.items():
            if member.authority is None:
                continue
            proof = self._proof(prepared, member)
            if proof is None:
                rejected[key] = ("independent_action_source_rejected",)
                continue
            if proof.prefix != b"".join(lines[:member.ticket.seq]):
                raise ProvenanceError("action prefix is not the exact final-ledger byte prefix")
            validation = proof.validation
            context = plan[key]
            expected = {"binding": context["binding"], "kind": member.kind, "arm": member.arm,
                "context_sha256": member.ticket.context_sha256, "reservation": member.ticket.to_dict(),
                "status": validation.status, "completion": ArtifactStore.reference(proof.completion),
                "validation": ArtifactStore.reference(encoded(asdict(validation))),
                "sources": {role: ArtifactStore.reference(data) for role, data in proof.sources},
                "outputs": {role: ArtifactStore.reference(data) for role, data in proof.outputs},
                "provenance_ref": proof.action_receipt_ref, "reasons": list(validation.reasons)}
            _same(states[key]["disposition"], expected, "sealed known disposition contradicts independent action proof")
            for data in (proof.completion, encoded(asdict(validation)),
                         *(value for _, value in proof.sources), *(value for _, value in proof.outputs)):
                if data is not None and self._archived(archive, ArtifactStore.reference(data)) != data:
                    raise ProvenanceError("final archive changes earlier independently proven raw bytes")
            proofs[key] = proof
        results = []
        for slot in slots(prepared.lock()):
            key = action_key(*slot)
            proof = proofs.get(key)
            reasons = rejected.get(key, ("independent_action_source_missing",)) if proof is None else ()
            if proof is not None:
                missing = [dep for dep in prerequisites(*slot) if dep not in proofs
                           or proofs[dep].validation.status != "completed"]
                if missing:
                    reasons = ("independently_completed_materialization_missing",)
            results.append(MappedActionResult(slot, "source_rejected" if key in rejected else
                "source_missing" if proof is None else "observed", proof, proof is not None and not reasons, reasons))
        return VerifiedLifecycleSourceMap(PROVIDER, archive.grant.request_sha256, archive.grant.lock_digest,
            grant.anchor.commit, archive.grant.receipt_commit, grant.evidence_commit, digest(evidence),
            grant.mapping_acceptance_ref, tuple(results))

    @staticmethod
    def _archived(archive, ref):
        if ref["state"] == "missing":
            return None
        data = archive.artifact("artifacts/" + ref["sha256"])
        if ArtifactStore.reference(data) != ref:
            raise ProvenanceError("archive content-addressed ledger artifact mismatch")
        return data

    @staticmethod
    def _proof(prepared, member):
        authority = member.authority
        action = authority.actions[0]
        try:
            receipt = authority.store.read(prepared)
            data = receipt.artifact(action.completion_path)
            facts = json_mapping(receipt.artifact(action.supervisor_path), "mapped action facts")
            sources = {"publication": receipt.artifact(action.publication_path),
                       "supervisor": receipt.artifact(action.supervisor_path)}
            outputs = {role: receipt.artifact(ref["path"]) if ref is not None else None
                       for role, ref in facts["outputs"].items()}
            validation = validate_completion(prepared, member.ticket, data, sources, outputs, authority=authority)
            if not validation.valid or validation.provenance_ref != receipt.grant.receipt_commit:
                return None
            return MappedActionProof(member.slot, receipt.grant.receipt_commit, member.ticket, validation, data,
                tuple(sorted(sources.items())), tuple(sorted(outputs.items())), receipt.artifact(facts["prefix"]["path"]))
        except (ValueError, TypeError, KeyError, OSError, AttributeError):
            return None

    def _publisher(self, archive, dispatch, members, states, input_refs):
        grant = self.grant
        data = archive.artifact(grant.journal_path)
        if digest(data) != grant.journal_sha256:
            raise ProvenanceError("independent publisher journal raw bytes mismatch")
        journal = json_mapping(data, "publisher journal")
        mapping(journal, "publisher journal", {"schema_version", "dispatch", "epoch", "events"})
        _same({key: value for key, value in journal.items() if key != "events"},
            {"schema_version": JOURNAL_SCHEMA, "dispatch": dispatch, "epoch": grant.anchor.journal_epoch},
            "publisher journal dispatch/epoch mismatch")
        events = journal["events"]
        if not isinstance(events, list) or not events or len(events) > len(members) + 1:
            raise ProvenanceError("bounded complete publisher journal required")
        _same(events[0], {"event": "anchor_durable_ack", "seq": grant.anchor.ack_sequence,
            "facts": {"anchor_commit": grant.anchor.commit, "anchor_sha256": grant.anchor.sha256,
                "locked_prefix_sha256": grant.anchor.prefix_sha256}}, "independent anchor readback ACK mismatch")
        tickets = {canonical_digest(item.ticket.to_dict()): item for item in members.values() if item.ticket is not None}
        seen, receipts, previous, prior_ticket_seq = set(), set(), grant.anchor.ack_sequence, 0
        non_action_refs = {grant.anchor.commit, grant.evidence_commit, archive.grant.receipt_commit,
                          *input_refs}
        for event in events[1:]:
            mapping(event, "publication ACK", {"event", "seq", "facts"})
            seq = integer(event["seq"], "native publisher sequence", minimum=1)
            facts = mapping(event["facts"], "publication readback facts", {"reservation_sha256", "receipt_commit",
                "completion_sha256", "action_publication_sha256", "publication_sha256"})
            for key in ("reservation_sha256", "completion_sha256", "action_publication_sha256", "publication_sha256"):
                sha256(facts[key], key)
            commit(facts["receipt_commit"], "publisher observed action receipt")
            member = tickets.get(facts["reservation_sha256"])
            if (event["event"] != "action_publication_durable_ack" or seq <= previous or member is None
                    or member.key in seen or member.ticket.seq <= prior_ticket_seq
                    or facts["receipt_commit"] in non_action_refs or facts["receipt_commit"] in receipts):
                raise ProvenanceError("publication ACK ordering, identity or source role mismatch")
            record = states[member.key]["disposition"]
            if (record["completion"]["state"] != "present" or record["sources"]["publication"]["state"] != "present"
                    or record["completion"]["sha256"] != facts["completion_sha256"]
                    or record["sources"]["publication"]["sha256"] != facts["action_publication_sha256"]
                    or record["provenance_ref"] is not None and record["provenance_ref"] != facts["receipt_commit"]):
                raise ProvenanceError("publisher ACK contradicts actual ledger artifacts/provenance")
            if member.authority is not None:
                action = member.authority.actions[0]
                source = member.authority.store.root.publications[0]
                if (seq != member.publication_sequence or seq <= action.last_event_sequence
                        or action.first_event_sequence <= previous or source.receipt_commit != facts["receipt_commit"]
                        or source.publication_sha256 != facts["publication_sha256"]):
                    raise ProvenanceError("publication must follow seal/readback and precede the next accepted action")
            seen.add(member.key)
            receipts.add(facts["receipt_commit"])
            previous, prior_ticket_seq = seq, member.ticket.seq
        if any(member.authority is not None and member.key not in seen for member in members.values()) or any(
                state["disposition"]["status"] in OBSERVED and key not in seen for key, state in states.items()):
            raise ProvenanceError("publisher journal omits an observed action receipt readback")
