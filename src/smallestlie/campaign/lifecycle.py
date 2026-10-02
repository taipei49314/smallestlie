"""Durable lifecycle recording and raw evidence verification, with no launch driver.

Configured authorities are integration trust boundaries outside the product and
bundle. Existing outer-supervisor/v1 providers cannot authenticate the new
reservation identity. These APIs do not activate the legacy v2 campaign gates.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, replace
import json
import os
from pathlib import Path
import stat
from typing import Protocol

from smallestlie.adjudication.engine import CaseInputs, adjudicate_campaign
from smallestlie.adjudication.observations import TrustedVerifierEnvelope, validate_verifier_observation
from smallestlie.adjudication.reviews import validate_case_review
from smallestlie.attacks.adjudication import choice, mapping, relative_path, sha256, string
from smallestlie.campaign.preregistration import (
    PreparedRun, PreregistrationApproval, PreregistrationError, _plain, canonical_digest,
    case_binding, commit, digest, integer, json_mapping,
)
from smallestlie.ledger.chain import Ledger
from smallestlie.ledger.lifecycle import (
    OBSERVED, PROTOCOL, ActionReservation, action_key, action_plan, artifact_ref,
    declaration, prerequisites, reservation, slots, summary_counts, verify_lifecycle_protocol,
)
from smallestlie.ledger.verify import verify_ledger
from smallestlie.oracle.runner_evidence import (
    TrustedExecutionEnvelope, assess_effectiveness, validate_runner_receipt,
)

COMPLETION_SCHEMA = "smallestlie.lifecycle-completion/v1"
MAX_ARTIFACT = 10_000_000


def encoded(value: dict) -> bytes:
    return json.dumps(value, sort_keys=True, ensure_ascii=True, separators=(",", ":"), allow_nan=False).encode("ascii")


def _plain_path(path: Path) -> None:
    for item in [*reversed(path.absolute().parents), path.absolute()]:
        if item.exists() or item.is_symlink():
            _plain(item)


def _sync_directory(path: Path) -> None:
    # Python exposes a directory fsync on POSIX. This recording API does not
    # supply a Windows directory-entry power-loss primitive; collector adoption
    # must separately establish its host/storage durability contract.
    if os.name == "posix":
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(fd)
        finally:
            os.close(fd)


def _mkdir(path: Path, *, exist_ok: bool) -> None:
    missing = [item for item in [path, *path.parents] if not item.exists()]
    path.mkdir(parents=True, exist_ok=exist_ok)
    for item in missing:
        _sync_directory(item)
        _sync_directory(item.parent)


class ArtifactStore:
    """Content-addressed local bytes. A digest addresses content, never authority."""

    def __init__(self, root: str | Path, *, create: bool = True):
        self.root = Path(root).absolute()
        _plain_path(self.root)
        if create:
            _mkdir(self.root, exist_ok=True)
        elif not self.root.is_dir():
            raise PreregistrationError("artifact store missing")
        _plain_path(self.root)

    def read(self, ref: dict) -> bytes | None:
        artifact_ref(ref)
        if ref["state"] == "missing":
            return None
        path = self.root / ref["sha256"]
        _plain_path(path)
        with path.open("rb") as fh:
            if not stat.S_ISREG(os.fstat(fh.fileno()).st_mode):
                raise PreregistrationError("artifact is not a regular file")
            data = fh.read(MAX_ARTIFACT + 1)
        if len(data) > MAX_ARTIFACT or len(data) != ref["bytes"] or digest(data) != ref["sha256"]:
            raise PreregistrationError("artifact raw size/digest mismatch")
        return data

    @staticmethod
    def reference(data: bytes | None) -> dict:
        if data is None:
            return {"state": "missing", "sha256": None, "bytes": None}
        if type(data) is not bytes or len(data) > MAX_ARTIFACT:
            raise PreregistrationError("artifact requires bounded raw bytes")
        return {"state": "present", "sha256": digest(data), "bytes": len(data)}

    def put(self, data: bytes | None) -> dict:
        ref = self.reference(data)
        if data is None:
            return ref
        path = self.root / ref["sha256"]
        _plain_path(path)
        try:
            with path.open("xb") as fh:
                fh.write(data)
                fh.flush()
        except FileExistsError:
            pass
        if self.read(ref) != data:
            raise PreregistrationError("artifact persistence/readback mismatch")
        # A previous write may have left matching bytes after fsync failed.
        # Retrying that digest must synchronize the file again, not just read it.
        with path.open("r+b") as fh:
            fh.flush()
            os.fsync(fh.fileno())
        _sync_directory(self.root)
        if self.read(ref) != data:
            raise PreregistrationError("artifact persistence/readback mismatch")
        return ref


@dataclass(frozen=True)
class TrustedActionCompletion:
    provider_id: str
    immutable_ref: str
    collector_acceptance_ref: str
    reservation_sha256: str
    completion_sha256: str
    context_sha256: str
    files_sha256: str
    termination_kind: str
    exit_code: int | None
    output_complete: bool
    descendants_reaped: bool
    outputs_sha256: str
    publication_sha256: str
    supervisor_sha256: str


class CompletionAuthority(Protocol):
    def verify(self, prepared: PreparedRun, ticket: ActionReservation,
               completion_sha256: str) -> TrustedActionCompletion | None:
        """Independently authenticate actual launch/materialization/completion.

        The accepted new collector must have received this exact durable ticket
        before starting, measured context/files/outputs and writer termination,
        and published immutable raw sources. Never synthesize this approval
        from a receipt or from existing supervisor/v1 sequence numbers.
        """
        ...


@dataclass(frozen=True)
class ActionValidation:
    reservation_sha256: str | None
    completion_sha256: str | None
    valid: bool
    status: str
    provenance_ref: str | None
    provider_id: str | None
    acceptance_ref: str | None
    exit_code: int | None
    output_complete: bool | None
    descendants_reaped: bool | None
    reasons: tuple[str, ...]


def output_roles(kind: str) -> tuple[str, ...]:
    return (("stdout", "stderr", "report") if kind == "runner_command" else
            ("metadata", "stdout", "stderr") if kind == "verifier_command" else ())


def validate_completion(prepared: PreparedRun, ticket: ActionReservation, data: bytes,
                        sources: dict[str, bytes | None], outputs: dict[str, bytes | None], *,
                        authority: CompletionAuthority | None) -> ActionValidation:
    """Preserve rejected raw bytes; unsupported/incomplete sources never create facts."""
    raw_sha = digest(data)
    ticket_sha = canonical_digest(ticket.to_dict())
    try:
        plan = action_plan(prepared)
        context = plan[action_key(ticket.case_id, ticket.kind, ticket.arm)]
        if (ticket.protocol != PROTOCOL or ticket.context_sha256 != canonical_digest(context)
                or ticket.binding_sha256 != canonical_digest(context["binding"])
                or ticket.lock_digest != prepared.lock()["lock_digest"]):
            raise PreregistrationError("completion ticket context mismatch")
        integer(ticket.seq, "reservation sequence", minimum=1)
        sha256(ticket.entry_digest, "reservation entry")
        raw = json_mapping(data, "lifecycle completion")
        mapping(raw, "lifecycle completion", {"schema_version", "binding", "reservation", "context_sha256", "files",
                "termination_kind", "exit_code", "output_complete", "descendants_reaped", "outputs",
                "publication_sha256", "supervisor_sha256"})
        if (raw["schema_version"] != COMPLETION_SCHEMA or raw["reservation"] != ticket.to_dict()
                or raw["binding"] != context["binding"] or raw["context_sha256"] != ticket.context_sha256):
            raise PreregistrationError("completion must bind exact persisted reservation and context")
        mapping(raw["files"], "measured file-map roles", set(context["files"]))
        for files in raw["files"].values():
            if not isinstance(files, dict):
                raise PreregistrationError("measured file map must be a mapping")
            for path, value in files.items():
                relative_path(path, "measured file path")
                sha256(value, "measured file digest")
        mapping(sources, "raw completion sources", {"publication", "supervisor"})
        mapping(outputs, "raw completion outputs", set(output_roles(ticket.kind)))
        hashes = {key: digest(value) if type(value) is bytes else None for key, value in outputs.items()}
        if raw["outputs"] != hashes:
            raise PreregistrationError("completion actual output bytes mismatch")
        for key in ("publication", "supervisor"):
            if type(sources[key]) is not bytes or raw[key + "_sha256"] != digest(sources[key]):
                raise PreregistrationError("completion immutable source bytes missing/mismatched")
        kind = choice(raw["termination_kind"], "completion termination", OBSERVED)
        if kind == "completed" and raw["files"] != context["files"]:
            raise PreregistrationError("completed action changed the measured frozen files")
        code = raw["exit_code"]
        if code is not None and type(code) is not int:
            raise PreregistrationError("completion exit requires native integer")
        if type(raw["output_complete"]) is not bool or type(raw["descendants_reaped"]) is not bool:
            raise PreregistrationError("completion output/descendant disposition requires booleans")
        if kind == "completed" and (code is None or not raw["output_complete"] or not raw["descendants_reaped"]
                or any(value is None for value in hashes.values())):
            raise PreregistrationError("completed action lacks complete outputs/descendant disposition")
        if ticket.kind.endswith("materialize") and (kind != "completed" or code != 0):
            # Failed materialization is a valid observed disposition; it cannot
            # satisfy a later command's materialization prerequisite.
            if kind == "completed":
                raise PreregistrationError("completed materialization must exit zero")
        if authority is None:
            raise PreregistrationError("new collector reservation authority missing")
        approval = authority.verify(prepared, ticket, raw_sha)
        if not isinstance(approval, TrustedActionCompletion):
            raise PreregistrationError("new collector reservation authority missing")
        string(approval.provider_id, "completion provider")
        string(approval.collector_acceptance_ref, "independent new collector acceptance")
        commit(approval.immutable_ref, "completion immutable source")
        expected = {"reservation_sha256": ticket_sha, "completion_sha256": raw_sha,
            "context_sha256": ticket.context_sha256, "files_sha256": canonical_digest(raw["files"]),
            "termination_kind": kind, "exit_code": code, "output_complete": raw["output_complete"],
            "descendants_reaped": raw["descendants_reaped"], "outputs_sha256": canonical_digest(hashes),
            "publication_sha256": raw["publication_sha256"], "supervisor_sha256": raw["supervisor_sha256"]}
        if any(canonical_digest(getattr(approval, key)) != canonical_digest(value) for key, value in expected.items()):
            raise PreregistrationError("independent completion envelope disagrees with actual facts")
        return ActionValidation(ticket_sha, raw_sha, True, kind, approval.immutable_ref, approval.provider_id,
            approval.collector_acceptance_ref, code, raw["output_complete"], raw["descendants_reaped"], ())
    except (ValueError, KeyError, TypeError, OSError) as exc:
        return ActionValidation(ticket_sha, raw_sha, False, "completion_rejected", None, None, None, None, None, None, (str(exc),))


def _missing_validation(ticket: dict | None) -> ActionValidation:
    status = "completion_missing" if ticket is not None else "not_run"
    return ActionValidation(canonical_digest(ticket) if ticket is not None else None, None, False, status,
                            None, None, None, None, None, None, (status,))


def _read_action(prepared, state, store, authority) -> ActionValidation:
    record = state["disposition"]
    if record["completion"]["state"] == "missing":
        return _missing_validation(state["reservation"])
    return validate_completion(prepared, ActionReservation(**state["reservation"]), store.read(record["completion"]),
        {key: store.read(ref) for key, ref in record["sources"].items()},
        {key: store.read(ref) for key, ref in record["outputs"].items()}, authority=authority)


class _CachedAuthority:
    def __init__(self, source):
        self.source, self.values = source, {}

    def verify(self, prepared, cid, sha):
        key = cid, sha
        if key not in self.values:
            self.values[key] = self.source.verify(prepared, cid, sha) if self.source is not None else None
        return self.values[key]


class _EligibleAuthority(_CachedAuthority):
    def __init__(self, source, prepared, states, validations, captures, *, verifier=False):
        super().__init__(source)
        self.prepared, self.states, self.validations, self.captures = prepared, states, validations, captures
        self.verifier = verifier

    def verify(self, prepared, cid, sha):
        key = cid, sha
        if key in self.values:
            return self.values[key]
        prefix = "verifier_" if self.verifier else "runner_"
        needed = [slot for slot in slots(prepared.lock()) if slot[0] == cid and slot[1].startswith(prefix)]
        eligible_slots = {}
        for slot in needed:
            ident = action_key(*slot)
            validation = self.validations[ident]
            record = self.states[ident]["disposition"]
            eligible = validation.valid and (not slot[1].endswith("materialize") or validation.status == "completed")
            for role, ref in record["outputs"].items():
                capture_role = f"verifier.{role}" if self.verifier else f"runner.{slot[2]}.{role}"
                if ref != self.captures[cid][capture_role]:
                    eligible = False
            eligible_slots[ident] = eligible
        commands = [action_key(*slot) for slot in needed if slot[1] == "runner_command"]
        eligible_commands = [ident for ident in commands if eligible_slots[ident]
                             and all(eligible_slots[dep] for dep in prerequisites(cid, "runner_command", self.states[ident]["reservation"]["arm"]))]
        eligible = all(eligible_slots.values()) if self.verifier else bool(eligible_commands)
        envelope = super().verify(prepared, cid, sha) if eligible else None
        lock_seq = next(entry["seq"] for entry in self.entries if entry["event_type"] == "preregistration_locked")
        if self.verifier:
            ident = action_key(cid, "verifier_command", "attack")
            validation = self.validations[ident]
            ticket = self.states[ident]["reservation"]
            if (not isinstance(envelope, TrustedVerifierEnvelope) or envelope.lock_sequence != lock_seq
                    or envelope.command_sequence != ticket["seq"] or envelope.immutable_ref != validation.provenance_ref
                    or envelope.termination_kind != validation.status or envelope.exit_code != validation.exit_code):
                envelope = None
        else:
            exits = {self.states[ident]["reservation"]["arm"]: (self.validations[ident].status, self.validations[ident].exit_code)
                     for ident in eligible_commands}
            supplied = dict((arm, (kind, code)) for arm, kind, code in envelope.arm_exits) if isinstance(envelope, TrustedExecutionEnvelope) else {}
            if (not isinstance(envelope, TrustedExecutionEnvelope) or envelope.lock_sequence != lock_seq
                    or envelope.first_command_sequence != min((self.states[ident]["reservation"]["seq"] for ident in commands
                                                               if self.states[ident]["reservation"] is not None
                                                               and self.states[ident]["reservation"]["arm"] in supplied), default=-1)
                    or len(supplied) != len(envelope.arm_exits) or supplied.keys() - prepared.binding(cid)["arms"].keys()
                    or any(kind not in OBSERVED or (code is not None and type(code) is not int)
                           for arm, kind, code in envelope.arm_exits)
                    or any(supplied.get(arm) != value for arm, value in exits.items())
                    or any(envelope.immutable_ref != self.validations[ident].provenance_ref for ident in eligible_commands)):
                envelope = None
            else:
                # Retain independently proven refutations from any eligible arm.
                # Other arms stay arm_missing; they cannot provide green/repair
                # evidence merely because the old receipt names them.
                envelope = replace(envelope, arm_exits=tuple((arm, kind, code) for arm, (kind, code) in exits.items()))
        self.values[key] = envelope
        return envelope


def _capture_refs(prepared, cid, raw, store, *, persist=True):
    if not isinstance(raw, CaseInputs) or raw.review is not None:
        raise PreregistrationError("observation seal accepts raw observations without a pre-seal review")
    put = store.put if persist else ArtifactStore.reference
    artifacts = {}
    for path, data in raw.runner_artifacts.items():
        relative_path(path, "runner artifact path")
        if type(data) is not bytes:
            raise PreregistrationError("runner artifacts require raw bytes")
        artifacts[path] = put(data)
    captures = {"runner.receipt": put(raw.runner_receipt), "verifier.metadata": put(raw.verifier_metadata),
                "verifier.stdout": put(raw.verifier_stdout), "verifier.stderr": put(raw.verifier_stderr)}
    arms = {}
    if raw.runner_receipt is not None:
        try:
            candidate = json_mapping(raw.runner_receipt, "runner receipt").get("arms", {})
            arms = candidate if isinstance(candidate, dict) else {}
        except ValueError:
            pass  # Preserve malformed-but-present receipt bytes and every artifact.
    for arm in prepared.binding(cid)["arms"]:
        record = arms.get(arm, {})
        for role in output_roles("runner_command"):
            ref = record.get(role, {}) if isinstance(record, dict) else {}
            path = ref.get("path") if isinstance(ref, dict) else None
            captures[f"runner.{arm}.{role}"] = artifacts.get(path, put(None)) if isinstance(path, str) else put(None)
    return {"binding": case_binding(prepared.lock(), cid), "captures": captures, "runner_artifacts": artifacts}


def _raw_inputs(case, store):
    captures = case["captures"]
    return CaseInputs(store.read(captures["runner.receipt"]), {path: store.read(ref) for path, ref in case["runner_artifacts"].items()},
        store.read(captures["verifier.metadata"]), store.read(captures["verifier.stdout"]), store.read(captures["verifier.stderr"]))


def _evaluate(prepared, entries, states, case_index, store, completion_authority, runner_authority, verifier_authority):
    validations = {key: _read_action(prepared, state, store, completion_authority) for key, state in states.items()}
    captures = {case["binding"]["case_id"]: case["captures"] for case in case_index}
    runner = _EligibleAuthority(runner_authority, prepared, states, validations, captures)
    verifier = _EligibleAuthority(verifier_authority, prepared, states, validations, captures, verifier=True)
    runner.entries = verifier.entries = entries
    inputs, facts = {}, {}
    for case in case_index:
        cid = case["binding"]["case_id"]
        raw = inputs[cid] = _raw_inputs(case, store)
        run = validate_runner_receipt(prepared, cid, raw.runner_receipt, raw.runner_artifacts, authority=runner)
        observed = validate_verifier_observation(prepared, cid, raw.verifier_metadata, raw.verifier_stdout, raw.verifier_stderr, authority=verifier)
        facts[cid] = {"runner": asdict(run), "verifier": asdict(observed), "effectiveness": asdict(assess_effectiveness(prepared, run))}
    return validations, inputs, facts, runner, verifier


def _observation_map(prepared, cid, facts):
    twin = prepared.binding(cid)["twin_case_id"]
    return {key: {"runner_validation_sha256": canonical_digest(facts[key]["runner"]),
                  "verifier_validation_sha256": canonical_digest(facts[key]["verifier"])}
            for key in [cid] + ([twin] if twin else [])}


def _read_frozen(prepared, entries, store):
    wrapper = next(entry["payload"] for entry in entries if entry["event_type"] == "preregistration_locked")
    frozen = json_mapping(store.read(wrapper["frozen_inputs"]), "frozen input index")
    mapping(frozen, "frozen input index", {"manifest", "lock", "profiles", "assets"})
    if store.read(frozen["manifest"]) != prepared.manifest_bytes or store.read(frozen["lock"]) != prepared.lock_bytes:
        raise PreregistrationError("original manifest/lock bytes differ from trusted preparation")
    for role, expected in (("profiles", dict(prepared.profiles)), ("assets", dict(prepared.assets))):
        if not isinstance(frozen[role], dict) or set(frozen[role]) != set(expected):
            raise PreregistrationError("frozen input index omits/adds trusted bytes")
        for key, ref in frozen[role].items():
            if store.read(ref) != expected[key]:
                raise PreregistrationError("frozen profile/asset raw bytes mismatch")
    policy = next(entry["payload"] for entry in entries if entry["event_type"] == "policy_validated")
    policy_raw = json_mapping(store.read(policy["artifact"]), "policy artifact")
    lock = prepared.lock()
    expected_policy = {"schema_version": "smallestlie.lifecycle-policy/v1", "ok": True,
                       "request_sha256": lock["request_sha256"], "authorization_ref": lock["authorization_ref"],
                       "provider_id": lock["approval_provider"]}
    if canonical_digest(policy_raw) != canonical_digest(expected_policy):
        raise PreregistrationError("policy artifact/request mismatch")


def _read_observations(prepared, index, states, store):
    mapping(index, "observation index", {"schema_version", "lock_digest", "plan_sha256", "cases", "actions"})
    lock = prepared.lock()
    ids = [case["case_id"] for case in lock["cases"]]
    if (index["schema_version"] != "smallestlie.observation-index/v1" or index["lock_digest"] != lock["lock_digest"]
            or index["plan_sha256"] != canonical_digest(action_plan(prepared)) or not isinstance(index["cases"], list)
            or [case.get("binding", {}).get("case_id") for case in index["cases"]] != ids
            or index["actions"] != {key: state["disposition"] for key, state in states.items()}):
        raise PreregistrationError("observation index denominator/action binding mismatch")
    for case in index["cases"]:
        mapping(case, "observation case", {"binding", "captures", "runner_artifacts", "validations"})
        cid = case["binding"]["case_id"]
        if case["binding"] != case_binding(lock, cid):
            raise PreregistrationError("observation case binding mismatch")
        roles = {"runner.receipt", "verifier.metadata", "verifier.stdout", "verifier.stderr"}
        roles.update(f"runner.{arm}.{role}" for arm in prepared.binding(cid)["arms"] for role in output_roles("runner_command"))
        mapping(case["captures"], "fixed capture roles", roles)
        mapping(case["validations"], "first-pass validation roles", {"runner", "verifier", "effectiveness"})
        if not isinstance(case["runner_artifacts"], dict):
            raise PreregistrationError("raw runner artifact index must be a mapping")
        for artifact_path, ref in case["runner_artifacts"].items():
            relative_path(artifact_path, "raw runner artifact path")
            artifact_ref(ref, present=True)
            store.read(ref)
        for ref in [*case["captures"].values(), *case["validations"].values()]:
            store.read(ref)
    for record in index["actions"].values():
        for ref in [record["completion"], record["validation"], *record["sources"].values(), *record["outputs"].values()]:
            store.read(ref)


@dataclass(frozen=True)
class ObservationSnapshot:
    lock_digest: str
    index_sha256: str
    case_ids: tuple[str, ...]


class FormalLifecycle:
    """Single-writer recording API. No subprocess, callback or automatic launch."""

    def __init__(self, prepared, ledger, artifacts, *, completion_authority=None,
                 runner_authority=None, verifier_authority=None):
        self.prepared, self.ledger, self.artifacts = prepared, ledger, artifacts
        self.plan = action_plan(prepared)
        self.completion_authority = completion_authority
        self.runner_authority, self.verifier_authority = runner_authority, verifier_authority
        self._sealed = None

    @classmethod
    def begin(cls, prepared: PreparedRun, output_dir: str | Path, *, policy_bytes: bytes,
              completion_authority=None, runner_authority=None, verifier_authority=None):
        plan = action_plan(prepared)
        policy = json_mapping(policy_bytes, "trusted caller policy result")
        mapping(policy, "policy result", {"schema_version", "ok", "request_sha256", "authorization_ref", "provider_id"})
        lock = prepared.lock()
        if (policy["schema_version"] != "smallestlie.lifecycle-policy/v1" or policy["ok"] is not True
                or policy["request_sha256"] != lock["request_sha256"] or policy["authorization_ref"] != lock["authorization_ref"]
                or policy["provider_id"] != lock["approval_provider"]):
            raise PreregistrationError("trusted caller policy result/request mismatch")
        root = Path(output_dir).absolute()
        _plain_path(root)
        _mkdir(root, exist_ok=False)
        store, ledger = ArtifactStore(root / "artifacts"), Ledger(root / "ledger.jsonl")
        session = cls(prepared, ledger, store, completion_authority=completion_authority,
                      runner_authority=runner_authority, verifier_authority=verifier_authority)
        frozen = {"manifest": store.put(prepared.manifest_bytes), "lock": store.put(prepared.lock_bytes),
                  "profiles": {cid: store.put(data) for cid, data in prepared.profiles},
                  "assets": {path: store.put(data) for path, data in prepared.assets}}
        session._append("campaign_created", declaration(lock, plan))
        session._append("policy_validated", {"ok": True, "artifact": store.put(policy_bytes)})
        session._append("preregistration_locked", {"lock": lock, "action_plan": plan, "frozen_inputs": store.put(encoded(frozen))})
        return session

    def _state(self):
        result = verify_ledger(self.ledger.path, required_protocol=PROTOCOL, expected_lock=self.prepared.lock())
        if (not result["ok"] or self.ledger._seq != result["entries_checked"]
                or self.ledger._prev_digest != (result["head_digest"] or "0" * 64)):
            raise PreregistrationError("lifecycle requires a current single-writer handle")
        result = verify_lifecycle_protocol(self.ledger.read_entries(), expected_lock=self.prepared.lock(), expected_plan=self.plan)
        if not result["ok"]:
            raise PreregistrationError(result["error"])
        return result

    def _append(self, event, payload):
        before = self._state() if self.ledger._seq else None
        if before and before["complete"]:
            raise PreregistrationError("lifecycle already finalized")
        candidate = {"schema_version": "smallestlie.ledger/v1", "seq": self.ledger._seq + 1,
                     "entry_digest": "0" * 64, "event_type": event, "payload": payload}
        check = verify_lifecycle_protocol([*self.ledger.read_entries(), candidate], expected_lock=self.prepared.lock(), expected_plan=self.plan)
        if not check["ok"]:
            raise PreregistrationError(check["error"])
        entry = self.ledger.append(event, payload)
        # append() closes its writer. fsync the file before issuing any ticket;
        # an fsync/readback failure leaves a used reservation, never a retry.
        _plain_path(self.ledger.path)
        with self.ledger.path.open("r+b") as fh:
            fh.flush()
            os.fsync(fh.fileno())
        _sync_directory(self.ledger.path.parent)
        after = self._state()
        if self.ledger._prev_digest != entry["entry_digest"] or not after["ok"]:
            raise PreregistrationError("durable lifecycle append/readback mismatch")
        return entry

    def reserve_action(self, case_id: str, *, kind: str, arm: str) -> ActionReservation:
        state = self._state()
        key = action_key(case_id, kind, arm)
        if not state["locked"] or state["snapshot_sha256"] is not None or key not in self.plan:
            raise PreregistrationError("reservation requires an open locked declared action")
        for dep in prerequisites(case_id, kind, arm):
            prior = state["action_states"].get(dep)
            if prior is None or prior["disposition"] is None:
                raise PreregistrationError("command requires independently completed materialization")
            fact = _read_action(self.prepared, prior, self.artifacts, self.completion_authority)
            if not fact.valid or fact.status != "completed":
                raise PreregistrationError("command requires independently completed materialization")
        context = self.plan[key]
        entry = self._append("lifecycle_action_reserved", {"binding": context["binding"], "kind": kind, "arm": arm,
                              "context_sha256": canonical_digest(context)})
        return reservation(self.prepared.lock(), context, entry)

    def complete_action(self, ticket: ActionReservation, completion_bytes: bytes, *,
                        sources: dict[str, bytes | None], outputs: dict[str, bytes | None]) -> ActionValidation:
        state = self._state()
        key = action_key(ticket.case_id, ticket.kind, ticket.arm)
        current = state["action_states"].get(key)
        if (current is None or current["reservation"] != ticket.to_dict() or current["disposition"] is not None
                or state["snapshot_sha256"] is not None):
            raise PreregistrationError("completion needs an unused exact durable reservation")
        refs = {"completion": self.artifacts.put(completion_bytes),
                "sources": {key: self.artifacts.put(value) for key, value in sources.items()},
                "outputs": {key: self.artifacts.put(value) for key, value in outputs.items()}}
        validation = validate_completion(self.prepared, ticket, completion_bytes, sources, outputs, authority=self.completion_authority)
        context = self.plan[key]
        payload = {"binding": context["binding"], "kind": ticket.kind, "arm": ticket.arm,
                   "context_sha256": ticket.context_sha256, "reservation": ticket.to_dict(), "status": validation.status,
                   **refs, "validation": self.artifacts.put(encoded(asdict(validation))),
                   "provenance_ref": validation.provenance_ref, "reasons": list(validation.reasons)}
        self._append("lifecycle_action_disposed", payload)
        return validation

    def _dispose_missing(self, key, state):
        context = self.plan[key]
        ticket = state.get("reservation")
        fact = _missing_validation(ticket)
        self._append("lifecycle_action_disposed", {"binding": context["binding"], "kind": context["kind"], "arm": context["arm"],
            "context_sha256": canonical_digest(context), "reservation": ticket, "status": fact.status,
            "completion": self.artifacts.put(None), "validation": self.artifacts.put(encoded(asdict(fact))),
            "sources": {role: self.artifacts.put(None) for role in ("publication", "supervisor")},
            "outputs": {role: self.artifacts.put(None) for role in output_roles(context["kind"])},
            "provenance_ref": None, "reasons": list(fact.reasons)})

    def seal_observations(self, inputs: dict[str, CaseInputs]) -> ObservationSnapshot:
        state = self._state()
        ids = [case["case_id"] for case in self.prepared.lock()["cases"]]
        if state["snapshot_sha256"] is not None or set(inputs) - set(ids):
            raise PreregistrationError("duplicate seal or undeclared observation case")
        index = [_capture_refs(self.prepared, cid, inputs.get(cid, CaseInputs()), self.artifacts) for cid in ids]
        for key in self.plan:
            action = self._state()["action_states"].get(key, {"reservation": None, "disposition": None})
            if action["disposition"] is None:
                self._dispose_missing(key, action)
        state = self._state()
        validations, raw_inputs, facts, ra, va = _evaluate(self.prepared, self.ledger.read_entries(), state["action_states"],
            index, self.artifacts, self.completion_authority, self.runner_authority, self.verifier_authority)
        for case in index:
            cid = case["binding"]["case_id"]
            case["validations"] = {key: self.artifacts.put(encoded(value)) for key, value in facts[cid].items()}
        raw_index = {"schema_version": "smallestlie.observation-index/v1", "lock_digest": self.prepared.lock()["lock_digest"],
                     "plan_sha256": canonical_digest(self.plan), "cases": index,
                     "actions": {key: value["disposition"] for key, value in state["action_states"].items()}}
        ref = self.artifacts.put(encoded(raw_index))
        self._append("observations_sealed", {"lock_digest": raw_index["lock_digest"],
            "case_ids_sha256": canonical_digest(ids), "index": ref})
        snapshot = ObservationSnapshot(raw_index["lock_digest"], ref["sha256"], tuple(ids))
        self._sealed = snapshot, ref, raw_index, validations, raw_inputs, facts, ra, va
        return snapshot

    def finalize(self, snapshot: ObservationSnapshot, reviews: dict[str, bytes | None], *, review_authority=None) -> dict:
        state = self._state()
        if (self._sealed is None or snapshot != self._sealed[0] or snapshot.index_sha256 != state["snapshot_sha256"]
                or state["reviews"] or state["rows"] or set(reviews) - set(snapshot.case_ids)):
            raise PreregistrationError("finalize requires this exact complete observation snapshot once")
        _, ref, raw_index, _, inputs, facts, ra, va = self._sealed
        if self.artifacts.read(ref) != encoded(raw_index):
            raise PreregistrationError("sealed observation bytes changed")
        # Freeze the accepted source readings, but re-read every bound raw byte
        # before emitting the first review/adjudication event. A cached authority
        # cannot hide a deleted completion/source/auxiliary artifact.
        _read_frozen(self.prepared, self.ledger.read_entries(), self.artifacts)
        _read_observations(self.prepared, raw_index, state["action_states"], self.artifacts)
        review_source = _CachedAuthority(review_authority)
        review_facts = {}
        with_reviews = {cid: replace(raw, review=reviews.get(cid)) for cid, raw in inputs.items()}
        for cid in snapshot.case_ids:
            data = reviews.get(cid)
            if data is not None and type(data) is not bytes:
                raise PreregistrationError("review requires raw bytes or an explicit missing value")
            observations = _observation_map(self.prepared, cid, facts)
            result = validate_case_review(self.prepared, cid, data, observations, authority=review_source)
            review_facts[cid] = {"binding": case_binding(self.prepared.lock(), cid), "snapshot_sha256": snapshot.index_sha256,
                "observation_map_sha256": canonical_digest(observations), "review": self.artifacts.put(data),
                "validation": self.artifacts.put(encoded(asdict(result))), "provenance_ref": result.provenance_ref,
                "reasons": list(result.reasons)}
        report = adjudicate_campaign(self.prepared, with_reviews, runner_authority=ra, verifier_authority=va,
                                     review_authority=review_source).to_dict()
        for cid in snapshot.case_ids:
            self._append("review_disposed", review_facts[cid])
        rows = {}
        for row in report["cases"]:
            cid = row["case_id"]
            payload = {"binding": case_binding(self.prepared.lock(), cid), "snapshot_sha256": snapshot.index_sha256,
                "review_validation_sha256": review_facts[cid]["validation"]["sha256"], "row": self.artifacts.put(encoded(row)),
                "verdict": row["verdict"], "paired_headline": row["paired_headline"]}
            self._append("case_adjudicated", payload)
            rows[cid] = payload
        self._append("campaign_summary", {"protocol": PROTOCOL, "lock_digest": snapshot.lock_digest,
            "snapshot_sha256": snapshot.index_sha256, "case_ids_sha256": canonical_digest(list(snapshot.case_ids)),
            "report": self.artifacts.put(encoded(report)), "counts": summary_counts(self.prepared.lock(), rows)})
        return report


def verify_formal_lifecycle(prepared: PreparedRun, ledger_path: str | Path, *,
                            preregistration_authority=None, completion_authority=None,
                            runner_authority=None, verifier_authority=None, review_authority=None) -> dict:
    """Read raw artifacts and reacquire external authority; a bundle cannot self-authorize.

    `prepared` must come from the trusted caller's own exact-source preparation,
    not from reconstructing a trusted object using the bundle's lock. Authority
    objects are likewise configured outside the recording/bundle. Verification
    never launches a collector, runner, engine or replay command.
    """
    result = {"ok": False, "chain_ok": False, "protocol_ok": False, "complete": False,
              "artifact_ok": False, "authority_ok": False, "semantic_ok": False, "errors": []}
    try:
        path = Path(ledger_path)
        _plain_path(path)
        chain = verify_ledger(path, required_protocol=PROTOCOL, expected_lock=prepared.lock())
        result.update(chain_ok=chain.get("chain_ok", chain["ok"]), protocol_ok=chain.get("protocol_ok", False),
                      complete=chain.get("complete", False))
        if not chain["ok"]:
            raise PreregistrationError(chain["error"])
        with path.open("rb") as fh:
            entries = [json_mapping(line, "lifecycle ledger entry") for line in fh if line.strip()]
        protocol = verify_lifecycle_protocol(entries, expected_lock=prepared.lock(), expected_plan=action_plan(prepared))
        result["protocol_ok"] = protocol["ok"]
        if not protocol["ok"] or not protocol["complete"]:
            raise PreregistrationError(protocol.get("error") or "lifecycle_not_finalized")
        store = ArtifactStore(path.parent / "artifacts", create=False)
        _read_frozen(prepared, entries, store)
        lock = prepared.lock()
        sealed = next(entry["payload"] for entry in entries if entry["event_type"] == "observations_sealed")
        index = json_mapping(store.read(sealed["index"]), "observation index")
        ids = [case["case_id"] for case in lock["cases"]]
        _read_observations(prepared, index, protocol["action_states"], store)
        for review in protocol["reviews"].values():
            store.read(review["review"])
            store.read(review["validation"])
        for row in protocol["rows"].values():
            store.read(row["row"])
        summary = entries[-1]["payload"]
        report_raw = json_mapping(store.read(summary["report"]), "adjudication report")
        result["artifact_ok"] = True

        # Each configured source is read at most once per exact digest in this
        # verification. This cache never escapes to another request/replay.
        action_validations, inputs, facts, ra, va = _evaluate(prepared, entries, protocol["action_states"],
            index["cases"], store, completion_authority, runner_authority, verifier_authority)
        semantic = True
        for key, value in action_validations.items():
            state = protocol["action_states"][key]
            record = state["disposition"]
            expected = asdict(value)
            if (store.read(record["validation"]) != encoded(expected) or record["status"] != value.status
                    or record["provenance_ref"] != value.provenance_ref or record["reasons"] != list(value.reasons)):
                semantic = False
        for case in index["cases"]:
            cid = case["binding"]["case_id"]
            # Reconstruct fixed native roles from the original receipt/path map,
            # rather than trusting aliases provided by the observation index.
            if _capture_refs(prepared, cid, inputs[cid], store, persist=False)["captures"] != case["captures"]:
                semantic = False
            for role, value in facts[cid].items():
                if store.read(case["validations"][role]) != encoded(value):
                    semantic = False
        review_source = _CachedAuthority(review_authority)
        review_facts = {}
        for cid in ids:
            record = protocol["reviews"][cid]
            raw = store.read(record["review"])
            inputs[cid] = replace(inputs[cid], review=raw)
            observations = _observation_map(prepared, cid, facts)
            reviewed = review_facts[cid] = validate_case_review(prepared, cid, raw, observations, authority=review_source)
            if (record["observation_map_sha256"] != canonical_digest(observations)
                    or store.read(record["validation"]) != encoded(asdict(reviewed))
                    or record["provenance_ref"] != reviewed.provenance_ref or record["reasons"] != list(reviewed.reasons)):
                semantic = False
        report = adjudicate_campaign(prepared, inputs, runner_authority=ra, verifier_authority=va,
                                     review_authority=review_source).to_dict()
        if canonical_digest(report_raw) != canonical_digest(report):
            semantic = False
        for row in report["cases"]:
            record = protocol["rows"][row["case_id"]]
            if (store.read(record["row"]) != encoded(row) or record["verdict"] != row["verdict"]
                    or record["paired_headline"] is not row["paired_headline"]):
                semantic = False
        result["semantic_ok"] = semantic
        if not semantic:
            result["errors"].append("raw evidence/authority revalidation contradicts sealed validations or adjudication")
        approval = preregistration_authority.verify(prepared.request) if preregistration_authority is not None else None
        approved = (isinstance(approval, PreregistrationApproval) and approval.provider_id == lock["approval_provider"]
                    and approval.reference == prepared.request.authorization_ref
                    and approval.phase1_commit == prepared.request.phase1_commit
                    and approval.manifest_sha256 == prepared.request.manifest_sha256
                    and approval.request_sha256 == canonical_digest(prepared.request.payload()))
        result["authority_ok"] = bool(approved and all(value.valid for value in action_validations.values())
            and all(facts[cid][role]["provenance_ref"] is not None and not facts[cid][role]["reasons"]
                    for cid in ids for role in ("runner", "verifier"))
            and all(not reviewed.reasons and reviewed.provenance_ref is not None for reviewed in review_facts.values()))
        if not result["authority_ok"]:
            result["errors"].append("independent preregistration/completion/observation/review authority incomplete")
        result["ok"] = all(result[key] for key in ("chain_ok", "protocol_ok", "complete", "artifact_ok", "authority_ok", "semantic_ok"))
        result["counts"] = summary["counts"]
    except (ValueError, KeyError, TypeError, OSError, StopIteration, AttributeError) as exc:
        result["errors"].append(str(exc))
    return result
