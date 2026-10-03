"""Offline reservation-aware sources; no collector, launch driver or adoption.

The trusted caller imports exact admissions and action grants independently of
the product/bundle. A final EC inventory archives a separate action publication,
facts, journal, prefix, outputs and completion wrapper. The action publication
excludes itself and the wrapper: neither facts nor inventory hash the wrapper
that hashes them. Existing lifecycle provenance guards are unchanged.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import PureWindowsPath

from smallestlie.attacks.adjudication import choice, mapping, relative_path, sha256, string
from smallestlie.campaign.evidence_sources import EcReceiptStore, _artifact_path
from smallestlie.campaign.lifecycle import (
    COMPLETION_SCHEMA, TrustedActionCompletion, encoded, output_roles,
)
from smallestlie.campaign.preregistration import (
    PreparedRun, canonical_digest, commit, digest, integer, json_mapping,
)
from smallestlie.campaign.provenance import ProvenanceError
from smallestlie.ledger.chain import payload_digest
from smallestlie.ledger.lifecycle import (
    OBSERVED, ActionReservation, action_key, action_plan, reservation,
    verify_lifecycle_protocol,
)
from smallestlie.oracle.runner_evidence import _absolute

PROVIDER = "ec-lifecycle-source/v1"
SOURCE_SCHEMA = "smallestlie.lifecycle-source/v1"
PUBLICATION_SCHEMA = "smallestlie.action-publication/v1"
JOURNAL_SCHEMA = "smallestlie.prelaunch-journal/v1"
ADMISSION_SCHEMA = "smallestlie.lifecycle-admission/v1"


@dataclass(frozen=True)
class LifecycleCollectorAdmission:
    """Externally accepted code, host/storage and prelaunch contracts.

    The referenced immutable governance bytes bind the exact dispatch as well
    as the three separately accepted contracts. Reading/hashing those bytes
    cannot establish their acceptance; only the trusted external caller can.
    """

    request_sha256: str
    lock_digest: str
    source_commit: str
    ec_source_commit: str
    run_id: int
    attempt: int
    job_id: int
    repository_id: int
    workflow_id: int
    workflow_sha256: str
    collector_sha256: str
    host: str
    generation: str
    evidence_commit: str
    evidence_path: str
    evidence_sha256: str
    collector_acceptance_ref: str
    host_storage_acceptance_ref: str
    journal_acceptance_ref: str

    def __post_init__(self) -> None:
        for key in ("request_sha256", "lock_digest", "workflow_sha256", "collector_sha256", "evidence_sha256"):
            sha256(getattr(self, key), key)
        for key in ("source_commit", "ec_source_commit", "evidence_commit"):
            commit(getattr(self, key), key)
        for key in ("run_id", "attempt", "job_id", "repository_id", "workflow_id"):
            integer(getattr(self, key), key, minimum=1)
        _artifact_path(self.evidence_path)
        for key in ("host", "generation", "collector_acceptance_ref", "host_storage_acceptance_ref", "journal_acceptance_ref"):
            string(getattr(self, key), key)
        if len({self.collector_acceptance_ref, self.host_storage_acceptance_ref, self.journal_acceptance_ref}) != 3:
            raise ProvenanceError("collector, host/storage and journal admissions must be distinct")


@dataclass(frozen=True)
class LifecycleActionGrant:
    """One exact ticket/source imported outside the receipt, never discovered."""

    reservation_sha256: str
    completion_path: str
    completion_sha256: str
    supervisor_path: str
    supervisor_sha256: str
    publication_path: str
    publication_sha256: str
    journal_epoch: str
    action_id: str
    first_event_sequence: int
    last_event_sequence: int

    def __post_init__(self) -> None:
        for key in ("reservation_sha256", "completion_sha256", "supervisor_sha256", "publication_sha256"):
            sha256(getattr(self, key), key)
        paths = [self.completion_path, self.supervisor_path, self.publication_path]
        for path in paths:
            _artifact_path(path)
        if len({path.casefold() for path in paths}) != 3 or "ec-publication.json" in paths:
            raise ProvenanceError("action source roles must be separate from the final inventory")
        string(self.journal_epoch, "journal epoch")
        string(self.action_id, "one-use action identity")
        integer(self.first_event_sequence, "first journal event", minimum=1)
        integer(self.last_event_sequence, "last journal event", minimum=1)
        if self.last_event_sequence <= self.first_event_sequence:
            raise ProvenanceError("action requires a nonempty bounded journal interval")


def _dispatch(store, grant) -> dict:
    root = store.root
    return {"repository": root.repository, "repository_id": root.repository_id,
        "workflow_id": root.workflow_id, "workflow_sha256": root.workflow_sha256,
        "collector_sha256": root.collector_sha256, "source_commit": grant.source_commit,
        "ec_source_commit": grant.ec_source_commit, "request_sha256": grant.request_sha256,
        "lock_digest": grant.lock_digest, "run_id": grant.run_id, "attempt": grant.attempt,
        "job_id": grant.job_id, "host": root.host, "generation": root.generation}


def _same(actual, expected, label):
    # bool cannot equal an integer identity through Python's equality rules.
    if canonical_digest(actual) != canonical_digest(expected):
        raise ProvenanceError(label)


def _prefix(data: bytes, prepared, ticket, final_ref) -> dict:
    if not data or len(data) > 10_000_000 or not data.endswith(b"\n"):
        raise ProvenanceError("bounded complete raw ledger prefix required")
    lines = data.splitlines()
    if not lines or len(lines) > 10_000 or any(not line.strip() for line in lines):
        raise ProvenanceError("ledger prefix must contain every entry once")
    entries, previous = [], "0" * 64
    for seq, line in enumerate(lines, 1):
        entry = json_mapping(line, "persisted ledger prefix entry")
        mapping(entry, "ledger entry", {"schema_version", "seq", "timestamp", "event_type", "tool_version",
            "payload", "payload_digest", "previous_entry_digest", "entry_digest"})
        if integer(entry["seq"], "prefix sequence", minimum=1) != seq:
            raise ProvenanceError("persisted prefix sequence gap")
        string(entry["timestamp"], "prefix timestamp")
        string(entry["tool_version"], "prefix version")
        string(entry["event_type"], "prefix event")
        if (entry["previous_entry_digest"] != previous or entry["payload_digest"] != payload_digest(entry["payload"])
                or entry["entry_digest"] != payload_digest({key: entry[key] for key in
                    ("seq", "timestamp", "event_type", "tool_version", "payload_digest", "previous_entry_digest")})):
            raise ProvenanceError("persisted prefix raw hash chain mismatch")
        # A Git tree cannot include a prefix that embeds its own final commit.
        # Prior dispositions must have their own earlier independent sources;
        # this action's grant never endorses their artifacts or authority.
        if (final_ref is not None and entry["event_type"] == "lifecycle_action_disposed"
                and entry["payload"].get("provenance_ref") == final_ref):
            raise ProvenanceError("prefix references its containing final receipt")
        entries.append(entry)
        previous = entry["entry_digest"]
    plan = action_plan(prepared)
    result = verify_lifecycle_protocol(entries, expected_lock=prepared.lock(), expected_plan=plan)
    key = action_key(ticket.case_id, ticket.kind, ticket.arm)
    if (not result["ok"] or not result["locked"] or result["snapshot_sha256"] is not None
            or entries[-1]["event_type"] != "lifecycle_action_reserved"
            or entries[-1]["seq"] != ticket.seq or entries[-1]["entry_digest"] != ticket.entry_digest):
        raise ProvenanceError("source prefix must end at the exact persisted reservation")
    _same(reservation(prepared.lock(), plan[key], entries[-1]).to_dict(), ticket.to_dict(), "prefix ticket mismatch")
    _same(result["action_states"][key]["reservation"], ticket.to_dict(), "prefix action identity mismatch")
    return result


def _measured_command(prepared, ticket, observed, root) -> None:
    if ticket.kind.endswith("materialize"):
        if observed is not None:
            raise ProvenanceError("materialization cannot claim command/runtime facts")
        return
    if ticket.kind == "runner_command":
        mapping(observed, "observed runner command", {"runner", "runtime", "dependencies", "semantic_env",
            "workspace_root", "runtime_path", "argv", "cwd", "config"})
        profile, binding = prepared.profile(ticket.case_id), prepared.binding(ticket.case_id)
        if profile["collector_sha256"] != root.collector_sha256:
            raise ProvenanceError("runner collector differs from frozen profile")
        for key in ("runner", "runtime", "semantic_env"):
            _same(observed[key], profile[key], "observed " + key + " mismatch")
        _same(observed["dependencies"], {**profile["dependencies"], "lock_sha256": binding["dependency_lock_sha256"]},
              "observed dependencies mismatch")
        workspace = _absolute(observed["workspace_root"]).rstrip("/\\")
        runtime = _absolute(observed["runtime_path"])
        command = profile["arms"][ticket.arm]
        argv = [arg.replace("${WORKSPACE}", workspace).replace("${RUNTIME}", runtime) for arg in command["argv"]]
        separator = "\\" if PureWindowsPath(workspace).is_absolute() else "/"
        cwd = workspace if command["cwd"] == "." else workspace + separator + command["cwd"].replace("/", separator)
        _same(observed["config"], binding["arms"][ticket.arm]["config"], "observed runner config mismatch")
    else:
        mapping(observed, "observed verifier command", {"runtime", "engine_sha256", "semantic_env", "workspace_root",
            "runtime_path", "engine_path", "argv", "cwd", "logical_cwd", "base_commit", "head_commit", "fail_on"})
        runtime = {"name": root.verifier_runtime_name, "version": root.verifier_runtime_version,
                   "artifact_sha256": root.verifier_runtime_sha256}
        _same(observed["runtime"], runtime, "observed verifier runtime mismatch")
        _same(observed["semantic_env"], dict(root.verifier_semantic_env), "observed verifier environment mismatch")
        if (observed["engine_sha256"] != prepared.lock()["engine"]["artifact_sha256"]
                or observed["logical_cwd"] != "." or observed["fail_on"] != "high"
                or commit(observed["base_commit"], "measured base") == commit(observed["head_commit"], "measured head")):
            raise ProvenanceError("observed verifier engine/range/default policy mismatch")
        if any(path == name or path.startswith(name + "/") for path in prepared.binding(ticket.case_id)["arms"]["baseline"]["files"]
               for name in (".checkwash", ".greenwash")):
            raise ProvenanceError("configured Checkwash policy not yet supported")
        cwd = _absolute(observed["workspace_root"])
        argv = [_absolute(observed["runtime_path"]), _absolute(observed["engine_path"]),
                "check", "HEAD~1..HEAD", "--format", "json"]
    _same(observed["argv"], argv, "observed argv mismatch")
    _same(observed["cwd"], cwd, "observed cwd mismatch")


class EcLifecycleCompletionAuthority:
    """GET-only, single-action offline revalidation with explicit independent roots."""

    def __init__(self, store: EcReceiptStore, admission: LifecycleCollectorAdmission,
                 actions: tuple[LifecycleActionGrant, ...]):
        if not isinstance(store, EcReceiptStore) or not isinstance(admission, LifecycleCollectorAdmission):
            raise ProvenanceError("independent receipt store and lifecycle admission required")
        if (type(actions) is not tuple or not actions or any(not isinstance(item, LifecycleActionGrant) for item in actions)
                or len({item.reservation_sha256 for item in actions}) != len(actions)
                or len({(item.journal_epoch, item.action_id) for item in actions}) != len(actions)):
            raise ProvenanceError("unique external ticket and one-use action grants required")
        paths = [path.casefold() for item in actions for path in
                 (item.completion_path, item.supervisor_path, item.publication_path)]
        if len(set(paths)) != len(paths):
            raise ProvenanceError("source artifacts cannot be reused across action grants")
        intervals = sorted((item.journal_epoch, item.first_event_sequence, item.last_event_sequence) for item in actions)
        if any(left[0] == right[0] and left[2] >= right[1] for left, right in zip(intervals, intervals[1:])):
            raise ProvenanceError("journal event intervals cannot overlap within an epoch")
        self.store, self.admission, self.actions = store, admission, actions

    def verify(self, prepared: PreparedRun, ticket: ActionReservation,
               completion_sha256: str) -> TrustedActionCompletion | None:
        try:
            sha256(completion_sha256, "raw completion digest")
            if not isinstance(ticket, ActionReservation):
                raise ProvenanceError("typed action ticket required")
            action = next(item for item in self.actions if item.reservation_sha256 == canonical_digest(ticket.to_dict())
                          and item.completion_sha256 == completion_sha256)
            receipt = self.store.read(prepared)  # Intentionally not supervisor()/v1.
            if self.admission.evidence_commit == receipt.grant.receipt_commit:
                raise ProvenanceError("lifecycle admission cannot come from the execution archive")
            dispatch = _dispatch(self.store, receipt.grant)
            admission = self.admission
            _same({key: getattr(admission, key) for key in dispatch if key != "repository"},
                  {key: value for key, value in dispatch.items() if key != "repository"}, "lifecycle admission dispatch mismatch")
            accepted = self.store.reader.blob_at(self.store.root.repository, admission.evidence_commit, admission.evidence_path)
            if digest(accepted) != admission.evidence_sha256:
                raise ProvenanceError("immutable lifecycle admission bytes mismatch")
            raw_admission = json_mapping(accepted, "independent lifecycle admission")
            mapping(raw_admission, "independent lifecycle admission", {"schema_version", "dispatch", "contracts"})
            _same(raw_admission, {"schema_version": ADMISSION_SCHEMA, "dispatch": dispatch,
                "contracts": {"collector": admission.collector_acceptance_ref,
                    "host_storage": admission.host_storage_acceptance_ref, "prelaunch_journal": admission.journal_acceptance_ref}},
                "independent lifecycle admission contract mismatch")
            return self._action(prepared, ticket, action, receipt, dispatch)
        except (ValueError, TypeError, KeyError, OSError, StopIteration, AttributeError):
            return None

    def _action(self, prepared, ticket, action, receipt, dispatch):
        facts_bytes = receipt.artifact(action.supervisor_path)
        publication_bytes = receipt.artifact(action.publication_path)
        completion_bytes = receipt.artifact(action.completion_path)
        if any(digest(data) != expected for data, expected in (
                (facts_bytes, action.supervisor_sha256), (publication_bytes, action.publication_sha256),
                (completion_bytes, action.completion_sha256))):
            raise ProvenanceError("accepted action raw bytes mismatch")
        facts = json_mapping(facts_bytes, "lifecycle source facts")
        mapping(facts, "lifecycle source facts", {"schema_version", "dispatch", "reservation", "context_sha256",
            "prefix", "journal", "files", "command", "termination_kind", "exit_code", "output_complete",
            "descendants_reaped", "outputs"})
        if facts["schema_version"] != SOURCE_SCHEMA:
            raise ProvenanceError("unsupported reservation-aware source schema")
        _same(facts["dispatch"], dispatch, "source dispatch mismatch")
        _same(facts["reservation"], ticket.to_dict(), "source ticket mismatch")
        context = action_plan(prepared)[action_key(ticket.case_id, ticket.kind, ticket.arm)]
        if ticket.context_sha256 != canonical_digest(context) or facts["context_sha256"] != ticket.context_sha256:
            raise ProvenanceError("source context mismatch")
        _measured_command(prepared, ticket, facts["command"], self.store.root)
        closure = {action.supervisor_path: facts_bytes}
        def artifact(ref):
            mapping(ref, "action raw artifact", {"path", "sha256"})
            path = _artifact_path(ref["path"])
            sha256(ref["sha256"], "action artifact digest")
            if path in closure or path in {action.completion_path, action.publication_path, "ec-publication.json"}:
                raise ProvenanceError("cyclic or reused action artifact role")
            data = receipt.artifact(path)
            if digest(data) != ref["sha256"]:
                raise ProvenanceError("action source raw artifact mismatch")
            closure[path] = data
            return data
        prefix = artifact(facts["prefix"])
        _prefix(prefix, prepared, ticket, receipt.grant.receipt_commit)
        journal = json_mapping(artifact(facts["journal"]), "independent prelaunch journal")
        self._journal(journal, facts, dispatch, ticket, action, digest(prefix))
        mapping(facts["outputs"], "observed output roles", set(output_roles(ticket.kind)))
        outputs = {key: digest(artifact(ref)) if ref is not None else None for key, ref in facts["outputs"].items()}
        mapping(facts["files"], "observed file roles", set(context["files"]))
        for files in facts["files"].values():
            if not isinstance(files, dict):
                raise ProvenanceError("observed complete file map required")
            for path, value in files.items():
                relative_path(path, "measured file path")
                sha256(value, "measured file digest")
        kind = choice(facts["termination_kind"], "observed termination", OBSERVED)
        code = facts["exit_code"]
        if code is not None and type(code) is not int:
            raise ProvenanceError("observed exit must be integer, never bool")
        if type(facts["output_complete"]) is not bool or type(facts["descendants_reaped"]) is not bool:
            raise ProvenanceError("native output/writer disposition requires booleans")
        if kind == "completed":
            _same(facts["files"], context["files"], "completed action changed measured files")
            if code is None or not facts["output_complete"] or not facts["descendants_reaped"] or any(value is None for value in outputs.values()):
                raise ProvenanceError("completed action lacks outputs/writer disposition")
            if ticket.kind.endswith("materialize") and code != 0:
                raise ProvenanceError("completed materialization must exit zero")
        publication = json_mapping(publication_bytes, "independent action publication")
        mapping(publication, "action publication", {"schema_version", "dispatch", "reservation_sha256", "files"})
        _same(publication, {"schema_version": PUBLICATION_SCHEMA, "dispatch": dispatch,
            "reservation_sha256": action.reservation_sha256,
            "files": [{"path": path, "bytes": len(data), "sha256": digest(data)} for path, data in sorted(closure.items())]},
            "action publication must cover its exact acyclic source closure")
        wrapper = {"schema_version": COMPLETION_SCHEMA, "binding": context["binding"], "reservation": ticket.to_dict(),
            "context_sha256": ticket.context_sha256, "files": facts["files"], "termination_kind": kind,
            "exit_code": code, "output_complete": facts["output_complete"], "descendants_reaped": facts["descendants_reaped"],
            "outputs": outputs, "publication_sha256": digest(publication_bytes), "supervisor_sha256": digest(facts_bytes)}
        # Canonical raw wrapper is the byte contract; semantic JSON equivalence
        # cannot borrow the independently accepted wrapper's digest.
        if completion_bytes != encoded(wrapper):
            raise ProvenanceError("raw completion wrapper differs from independent measured facts")
        return TrustedActionCompletion(PROVIDER, receipt.grant.receipt_commit, self.admission.collector_acceptance_ref,
            action.reservation_sha256, digest(completion_bytes), ticket.context_sha256, canonical_digest(facts["files"]),
            kind, code, facts["output_complete"], facts["descendants_reaped"], canonical_digest(outputs),
            digest(publication_bytes), digest(facts_bytes))

    @staticmethod
    def _journal(journal, facts, dispatch, ticket, action, prefix_sha):
        mapping(journal, "prelaunch journal", {"schema_version", "dispatch", "epoch", "action_id", "reservation_sha256",
            "prefix_sha256", "context_sha256", "events"})
        _same({key: value for key, value in journal.items() if key != "events"}, {
            "schema_version": JOURNAL_SCHEMA, "dispatch": dispatch, "epoch": action.journal_epoch,
            "action_id": action.action_id, "reservation_sha256": canonical_digest(ticket.to_dict()),
            "prefix_sha256": prefix_sha, "context_sha256": ticket.context_sha256}, "journal action/epoch/prefix mismatch")
        names = ["ticket_durable_ack", "work_started", "termination_observed", "writer_disposition", "outputs_sealed"]
        events = journal["events"]
        if not isinstance(events, list) or len(events) != len(names):
            raise ProvenanceError("complete prelaunch-to-seal journal required")
        if events[0].get("seq") != action.first_event_sequence or events[-1].get("seq") != action.last_event_sequence:
            raise ProvenanceError("journal outside independently granted event interval")
        previous = 0
        for event, name in zip(events, names):
            mapping(event, "journal event", {"event", "seq", "facts_sha256"})
            seq = integer(event["seq"], "native journal sequence", minimum=1)
            if event["event"] != name or seq <= previous:
                raise ProvenanceError("journal ACK/work/termination/writer/seal order mismatch")
            expected = ({"prefix_sha256": prefix_sha, "reservation": ticket.to_dict()} if name == names[0] else
                {key: facts[key] for key in ("context_sha256", "files", "command")} if name == names[1] else
                {key: facts[key] for key in ("termination_kind", "exit_code")} if name == names[2] else
                {"descendants_reaped": facts["descendants_reaped"]} if name == names[3] else
                {key: facts[key] for key in ("output_complete", "outputs")})
            if event["facts_sha256"] != canonical_digest(expected):
                raise ProvenanceError("journal event contradicts independent measured facts")
            previous = seq
