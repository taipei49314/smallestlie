"""GET-only mapped semantic snapshots, separate from legacy authority envelopes.

The configured source-map authority is revalidated for every snapshot. Frozen
slots, raw captures and per-action references are retained; no caller supplied
observation, first-pass validation or constructed mapped carrier is authority.
This reader neither records adjudication nor activates a lifecycle/launcher.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
import json

from smallestlie.adapters.checkwash import _findings_error
from smallestlie.adjudication.observations import Finding, SEVERITIES
from smallestlie.attacks.adjudication import mapping, relative_path, string
from smallestlie.campaign.lifecycle import (
    ArtifactStore, _capture_refs, _raw_inputs, _read_frozen, _read_observations,
)
from smallestlie.campaign.preregistration import (
    PreparedRun, PreregistrationError, canonical_digest, case_binding, digest, json_mapping,
)
from smallestlie.campaign.provenance import ProvenanceError
from smallestlie.campaign.source_map import EcLifecycleSourceMapAuthority, _entries
from smallestlie.ledger.lifecycle import action_key, action_plan, artifact_ref, verify_lifecycle_protocol
from smallestlie.oracle.runner_evidence import ArmEvidence, EffectivenessAssessment, _arm, assess_bound_change

SCHEMA = "smallestlie.mapped-observations/v1"


@dataclass(frozen=True)
class MappedActionObservation:
    slot: tuple[str, str, str]
    state: str
    eligible: bool
    action_receipt_ref: str | None
    reservation_sha256: str | None
    completion_sha256: str | None
    supervisor_sha256: str | None
    publication_sha256: str | None
    prefix_sha256: str | None
    validation_sha256: str | None
    termination_kind: str | None
    exit_code: int | None
    outputs: tuple[tuple[str, str | None], ...]
    reasons: tuple[str, ...]


@dataclass(frozen=True)
class MappedRunnerArm:
    evidence: ArmEvidence
    command: MappedActionObservation
    materialization: MappedActionObservation
    captures: tuple[tuple[str, str | None], ...]


@dataclass(frozen=True)
class MappedRunnerObservation:
    case_id: str
    binding_sha256: str
    receipt_sha256: str | None
    reasons: tuple[str, ...]
    arms: tuple[MappedRunnerArm, ...]

    def arm(self, role: str) -> ArmEvidence:
        return next((item.evidence for item in self.arms if item.evidence.role == role),
                    ArmEvidence(role, False, ("arm_missing",)))


@dataclass(frozen=True)
class MappedVerifierObservation:
    case_id: str
    binding_sha256: str
    command: MappedActionObservation
    materializations: tuple[MappedActionObservation, ...]
    captures: tuple[tuple[str, str | None], ...]
    accepted: bool | None
    report_verdict: str | None
    exit_code: int | None
    fail_on: str | None
    findings: tuple[Finding, ...]
    skipped_files: tuple[str, ...]
    reasons: tuple[str, ...]


@dataclass(frozen=True)
class MappedCaseObservation:
    case_id: str
    runner: MappedRunnerObservation
    verifier: MappedVerifierObservation
    effectiveness: EffectivenessAssessment
    first_pass_validations: tuple[tuple[str, str], ...]


@dataclass(frozen=True)
class MappedObservationSnapshot:
    schema_version: str
    request_sha256: str
    lock_digest: str
    plan_sha256: str
    index_sha256: str
    prelaunch_anchor_ref: str
    final_archive_ref: str
    mapping_evidence_ref: str
    mapping_sha256: str
    mapping_acceptance_ref: str
    actions: tuple[MappedActionObservation, ...]
    cases: tuple[MappedCaseObservation, ...]

    @property
    def validation_sha256(self) -> str:
        """Future review must bind this whole denominator/source/result summary."""
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
            raise ProvenanceError("mapped capture raw reference mismatch")
        return data


def _summary(item):
    proof = item.proof
    if proof is None:
        return MappedActionObservation(item.slot, item.state, item.eligible, None, None, None,
            None, None, None, None, None, None, (), item.reasons)
    sources = dict(proof.sources)
    return MappedActionObservation(item.slot, item.state, item.eligible, proof.action_receipt_ref,
        canonical_digest(proof.reservation.to_dict()), digest(proof.completion), digest(sources["supervisor"]),
        digest(sources["publication"]), digest(proof.prefix), canonical_digest(asdict(proof.validation)),
        proof.validation.status, proof.validation.exit_code,
        tuple((role, digest(data) if data is not None else None) for role, data in proof.outputs), item.reasons)


def _completed(item):
    proof = item.proof
    if proof is None or not item.eligible:
        raise PreregistrationError("mapped_command_ineligible: " + "; ".join(item.reasons))
    fact = proof.validation
    if (not fact.valid or fact.status != "completed" or type(fact.exit_code) is not int
            or fact.output_complete is not True or fact.descendants_reaped is not True):
        raise PreregistrationError("mapped_command_not_completed: " + fact.status)
    return json_mapping(dict(proof.sources)["supervisor"], "mapped native supervisor")


def _same(left, right, reason):
    # Canonical comparison preserves bool/integer distinctions in observed data.
    if canonical_digest(left) != canonical_digest(right):
        raise PreregistrationError(reason)


def _outputs(item, captures):
    expected = dict(item.proof.outputs)
    if set(captures) != set(expected) or any(type(data) is not bytes for data in captures.values()):
        raise PreregistrationError("mapped_command_capture_missing")
    if captures != expected:
        raise PreregistrationError("mapped_command_raw_output_mismatch")


def _runner(prepared, cid, raw, index, mapped, summaries, dispatch):
    binding, profile = prepared.binding(cid), prepared.profile(cid)
    receipt_sha = digest(raw.runner_receipt) if raw.runner_receipt is not None else None
    reasons, arms, header = (), [], None
    try:
        if raw.runner_receipt is None:
            raise PreregistrationError("runner_receipt_missing")
        header = json_mapping(raw.runner_receipt, "mapped runner receipt")
        mapping(header, "mapped runner receipt", {"schema_version", "binding", "source_run_id", "job_id", "host", "arms"})
        _same({key: header[key] for key in ("schema_version", "binding", "source_run_id", "job_id", "host")},
            {"schema_version": "smallestlie.runner-receipt/v1", "binding": case_binding(prepared.lock(), cid),
             "source_run_id": str(dispatch["source_run_id"]), "job_id": str(dispatch["job_id"]), "host": dispatch["host"]},
            "mapped_runner_header_mismatch")
        if not isinstance(header["arms"], dict) or header["arms"].keys() - binding["arms"].keys():
            raise PreregistrationError("mapped_runner_undeclared_arm")
    except (ValueError, TypeError, KeyError) as exc:
        reasons, header = (str(exc),), None
    for role, expected in binding["arms"].items():
        command_key, materialize_key = action_key(cid, "runner_command", role), action_key(cid, "runner_materialize", role)
        item = mapped[command_key]
        captures = tuple((name, index["captures"][f"runner.{role}.{name}"]["sha256"])
                         for name in ("stdout", "stderr", "report"))
        evidence = ArmEvidence(role, False, reasons or ("arm_missing",))
        try:
            if header is None:
                raise PreregistrationError(reasons[0])
            facts = _completed(item)
            record = header["arms"].get(role)
            if not isinstance(record, dict):
                raise PreregistrationError("arm_missing")
            _same({key: record[key] for key in facts["command"]}, facts["command"], "mapped_runner_measured_command_mismatch")
            _same({key: record[key] for key in ("termination_kind", "exit_code")},
                {"termination_kind": item.proof.validation.status, "exit_code": item.proof.validation.exit_code},
                "mapped_runner_measured_exit_mismatch")
            _same({key: record[key] for key in facts["outputs"]}, facts["outputs"], "mapped_runner_output_reference_mismatch")
            payloads = {key: raw.runner_artifacts.get(record[key]["path"]) for key in facts["outputs"]}
            _outputs(item, payloads)
            evidence = _arm(role, record, expected, profile, raw.runner_artifacts,
                (item.proof.validation.status, item.proof.validation.exit_code), binding["dependency_lock_sha256"])
        except (ValueError, TypeError, KeyError) as exc:
            evidence = ArmEvidence(role, False, (str(exc),))
        arms.append(MappedRunnerArm(evidence, summaries[command_key], summaries[materialize_key], captures))
    return MappedRunnerObservation(cid, canonical_digest(case_binding(prepared.lock(), cid)), receipt_sha, reasons, tuple(arms))


def _verifier(prepared, cid, raw, index, mapped, summaries):
    command_key = action_key(cid, "verifier_command", "attack")
    item = mapped[command_key]
    command = summaries[command_key]
    materials = tuple(summaries[action_key(cid, "verifier_materialize", role)] for role in ("baseline", "attack"))
    captures = tuple((name, index["captures"]["verifier." + name]["sha256"]) for name in ("metadata", "stdout", "stderr"))
    findings, skipped, verdict, code, threshold = (), (), None, None, None
    try:
        facts = _completed(item)
        _outputs(item, {"metadata": raw.verifier_metadata, "stdout": raw.verifier_stdout, "stderr": raw.verifier_stderr})
        metadata = json_mapping(raw.verifier_metadata, "mapped verifier metadata")
        mapping(metadata, "mapped verifier metadata", {"schema_version", "binding", "arm", "adapter", "engine",
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
            "truncated": False, "stdout_sha256": digest(raw.verifier_stdout), "stderr_sha256": digest(raw.verifier_stderr)}
        _same(metadata, expected, "mapped_verifier_measured_metadata_mismatch")
        code, threshold = metadata["exit_code"], metadata["fail_on"]
        if type(code) is not int or code not in {0, 1}:
            raise PreregistrationError("verifier_not_completed_verdict")
        payload = json_mapping(raw.verifier_stdout, "mapped Checkwash stdout")
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
            raise PreregistrationError("mapped_default_policy_allowlist_contradiction")
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
        return MappedVerifierObservation(cid, canonical_digest(case_binding(lock, cid)), command, materials, captures,
            not blocked, verdict, code, threshold, findings, skipped, ())
    except (ValueError, TypeError, KeyError) as exc:
        return MappedVerifierObservation(cid, canonical_digest(case_binding(prepared.lock(), cid)), command, materials,
            captures, None, verdict, code, threshold, findings, skipped, (str(exc),))


def read_mapped_observations(prepared: PreparedRun, *, authority: EcLifecycleSourceMapAuthority) -> MappedObservationSnapshot | None:
    """Reacquire GET-only source authority and compute a full, versioned snapshot.

    Structural source/index contradictions reject the snapshot. Missing or
    semantically rejected case/arm captures remain unknown in its denominator.
    The old F first-pass validation bytes are referenced, never adopted.
    """
    try:
        if type(authority) is not EcLifecycleSourceMapAuthority or type(prepared) is not PreparedRun:
            raise ProvenanceError("configured source-map authority and prepared run required")
        # Revalidate the provider's contract, not a caller-replaced verify hook
        # or a previously constructed VerifiedLifecycleSourceMap carrier.
        source = EcLifecycleSourceMapAuthority._verify(authority, prepared)
        archive = authority.archive.read(prepared)
        ledger = archive.artifact(authority.grant.ledger_path)
        if digest(ledger) != authority.grant.ledger_sha256 or archive.grant.receipt_commit != source.final_archive_ref:
            raise ProvenanceError("mapped archive changed during semantic read")
        entries, _ = _entries(ledger)
        state = verify_lifecycle_protocol(entries, expected_lock=prepared.lock(), expected_plan=action_plan(prepared))
        if not state["ok"]:
            raise ProvenanceError("mapped semantic ledger invalid")
        store = _ArchiveArtifacts(archive)
        _read_frozen(prepared, entries, store)
        index_bytes = store.read(entries[-1]["payload"]["index"])
        index = json_mapping(index_bytes, "mapped observation index")
        _read_observations(prepared, index, state["action_states"], store)
        _same(index["actions"], {key: value["disposition"] for key, value in state["action_states"].items()},
              "mapped index changes sealed action types or facts")
        mapped = {action_key(*item.slot): item for item in source.actions}
        summaries = {key: _summary(item) for key, item in mapped.items()}
        cases = []
        for row in index["cases"]:
            for ref in row["validations"].values():
                artifact_ref(ref, present=True)
            cid = row["binding"]["case_id"]
            raw = _raw_inputs(row, store)
            reconstructed = _capture_refs(prepared, cid, raw, None, persist=False)
            _same(reconstructed["captures"], row["captures"], "mapped capture role alias mismatch")
            _same(reconstructed["runner_artifacts"], row["runner_artifacts"], "mapped artifact role alias mismatch")
            runner = _runner(prepared, cid, raw, row, mapped, summaries, {
                "source_run_id": archive.grant.run_id, "job_id": archive.grant.job_id, "host": authority.archive.root.host})
            attack, attack_reasons = assess_bound_change(prepared.profile(cid), runner.arm("baseline"), runner.arm("attack"), runner.arm("repair"))
            twin, twin_reasons = (assess_bound_change(prepared.profile(cid), runner.arm("baseline"), runner.arm("twin"), runner.arm("repair"))
                                 if "twin" in prepared.binding(cid)["arms"] else (None, ()))
            effectiveness = EffectivenessAssessment(cid, attack, twin, attack_reasons, twin_reasons)
            cases.append(MappedCaseObservation(cid, runner, _verifier(prepared, cid, raw, row, mapped, summaries), effectiveness,
                tuple(sorted((name, ref["sha256"]) for name, ref in row["validations"].items()))))
        return MappedObservationSnapshot(SCHEMA, source.request_sha256, source.lock_digest, canonical_digest(action_plan(prepared)),
            digest(index_bytes), source.prelaunch_anchor_ref, source.final_archive_ref, source.mapping_evidence_ref,
            source.mapping_sha256, source.mapping_acceptance_ref, tuple(summaries[action_key(*item.slot)] for item in source.actions), tuple(cases))
    except (ValueError, TypeError, KeyError, OSError, AttributeError, StopIteration):
        return None
