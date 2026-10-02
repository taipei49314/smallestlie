"""Pure validation of independently captured Checkwash observations.

The provider is an integration trust boundary, not a self-attestation flag.
It must obtain actual fixture, source, supervisor and effective-policy facts
independently. This module never executes the engine or reads workspace files.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
import json
from typing import Protocol

from smallestlie.adapters.checkwash import _findings_error
from smallestlie.attacks.adjudication import choice, mapping, relative_path, string
from smallestlie.campaign.preregistration import (
    PreparedRun, PreregistrationError, canonical_digest, case_binding, commit,
    digest, integer, json_mapping,
)

SEVERITIES = ("info", "warn", "high", "critical")


@dataclass(frozen=True)
class Finding:
    rule: str
    path: str
    severity: str
    fingerprint: str
    allowlisted: bool
    unit: str | None
    raw_json: str

    def to_dict(self) -> dict:
        # Preserve source spans, strength/shape and unknown attachment fields.
        return json.loads(self.raw_json)

    def blocks(self, fail_on: str) -> bool:
        return not self.allowlisted and SEVERITIES.index(self.severity) >= SEVERITIES.index(fail_on)


@dataclass(frozen=True)
class TrustedVerifierEnvelope:
    provider_id: str
    immutable_ref: str
    binding_sha256: str
    metadata_sha256: str
    stdout_sha256: str
    stderr_sha256: str
    baseline_tree_sha256: str
    attack_tree_sha256: str
    engine_sha256: str
    base_commit: str
    head_commit: str
    argv: tuple[str, ...]
    cwd: str
    fail_on: str
    termination_kind: str
    exit_code: int | None
    lock_sequence: int
    command_sequence: int


class VerifierAuthority(Protocol):
    def verify(self, prepared: PreparedRun, case_id: str,
               metadata_sha256: str) -> TrustedVerifierEnvelope | None:
        """Authenticate actual execution/configuration independently of metadata.

        Verify the published artifact, interpreter/environment, complete frozen
        baseline and attack trees, resolved commits, command and effective
        fail_on (including frozen base config/allowlist), and supervisor exit.
        Do not copy expected or receipt fields and call them observed facts.
        """
        ...


@dataclass(frozen=True)
class VerifierObservation:
    case_id: str
    binding_sha256: str
    metadata_sha256: str | None
    provenance_ref: str | None
    stdout_sha256: str | None
    stderr_sha256: str | None
    accepted: bool | None
    report_verdict: str | None
    exit_code: int | None
    fail_on: str | None
    findings: tuple[Finding, ...]
    skipped_files: tuple[str, ...]
    reasons: tuple[str, ...]

    @property
    def validation_sha256(self) -> str:
        return canonical_digest(asdict(self))


def validate_verifier_observation(
    prepared: PreparedRun, case_id: str, metadata_bytes: bytes | None,
    stdout_bytes: bytes | None, stderr_bytes: bytes | None, *,
    authority: VerifierAuthority | None,
) -> VerifierObservation:
    binding = case_binding(prepared.lock(), case_id)
    binding_sha = canonical_digest(binding)
    metadata_sha = digest(metadata_bytes) if type(metadata_bytes) is bytes else None
    stdout_sha = digest(stdout_bytes) if type(stdout_bytes) is bytes else None
    stderr_sha = digest(stderr_bytes) if type(stderr_bytes) is bytes else None
    findings: tuple[Finding, ...] = ()
    skipped: tuple[str, ...] = ()
    report_verdict = code = fail_on = None
    try:
        if any(type(data) is not bytes for data in (metadata_bytes, stdout_bytes, stderr_bytes)):
            raise PreregistrationError("verifier_capture_missing")
        raw = json_mapping(metadata_bytes, "verifier metadata")
        mapping(raw, "verifier metadata", {"schema_version", "binding", "arm", "adapter", "engine",
                "baseline_tree_sha256", "attack_tree_sha256", "base_commit", "head_commit",
                "argv", "cwd", "fail_on", "termination_kind", "exit_code", "truncated",
                "stdout_sha256", "stderr_sha256"})
        case, lock = prepared.binding(case_id), prepared.lock()
        if (raw["schema_version"] != "smallestlie.verifier-observation/v1"
                or raw["binding"] != binding or raw["arm"] != "attack"
                or raw["adapter"] != "checkwash" or raw["engine"] != lock["engine"]
                or raw["baseline_tree_sha256"] != case["arms"]["baseline"]["tree_sha256"]
                or raw["attack_tree_sha256"] != case["arms"]["attack"]["tree_sha256"]
                or raw["stdout_sha256"] != stdout_sha or raw["stderr_sha256"] != stderr_sha
                or raw["truncated"] is not False):
            raise PreregistrationError("verifier_formal_binding_mismatch")
        if authority is None:
            raise PreregistrationError("verifier_provenance_missing")
        envelope = authority.verify(prepared, case_id, metadata_sha)
        if not isinstance(envelope, TrustedVerifierEnvelope):
            raise PreregistrationError("verifier_provenance_missing")
        if (envelope.binding_sha256 != binding_sha or envelope.metadata_sha256 != metadata_sha
                or envelope.stdout_sha256 != stdout_sha or envelope.stderr_sha256 != stderr_sha
                or envelope.engine_sha256 != lock["engine"]["artifact_sha256"]
                or envelope.baseline_tree_sha256 != raw["baseline_tree_sha256"]
                or envelope.attack_tree_sha256 != raw["attack_tree_sha256"]
                or envelope.base_commit != raw["base_commit"] or envelope.head_commit != raw["head_commit"]
                or list(envelope.argv) != raw["argv"] or envelope.cwd != raw["cwd"]
                or envelope.fail_on != raw["fail_on"] or envelope.exit_code != raw["exit_code"]
                or envelope.termination_kind != raw["termination_kind"]):
            raise PreregistrationError("independent_verifier_envelope_mismatch")
        string(envelope.provider_id, "verifier provider")
        commit(envelope.immutable_ref, "immutable verifier receipt")
        commit(envelope.base_commit, "resolved base")
        commit(envelope.head_commit, "resolved head")
        if envelope.base_commit == envelope.head_commit:
            raise PreregistrationError("verifier_range_has_no_mutant")
        integer(envelope.lock_sequence, "lock sequence", minimum=1)
        integer(envelope.command_sequence, "command sequence", minimum=1)
        if envelope.lock_sequence >= envelope.command_sequence:
            raise PreregistrationError("verifier_command_preceded_lock")
        if (not isinstance(raw["argv"], list) or len(raw["argv"]) != 6
                or raw["argv"][2:] != ["check", "HEAD~1..HEAD", "--format", "json"]
                or raw["cwd"] != "."):
            raise PreregistrationError("unsupported_verifier_command")
        for arg in raw["argv"]:
            string(arg, "verifier argv")
        fail_on = choice(raw["fail_on"], "effective fail_on", set(SEVERITIES))
        code = raw["exit_code"]
        if type(code) is not int or type(envelope.exit_code) is not int:
            raise PreregistrationError("verifier_exit_not_integer")
        if raw["termination_kind"] != "completed" or code not in {0, 1}:
            raise PreregistrationError("verifier_not_completed_verdict")
        payload = json_mapping(stdout_bytes, "Checkwash stdout")
        error = _findings_error(payload, lock["engine"]["version"], 2)
        if error:
            raise PreregistrationError(error)
        normalized = []
        for item in payload["findings"]:
            for key in ("rule", "message", "fingerprint"):
                string(item[key], "finding." + key)
            # Global findings may have an empty path. Such findings cannot match
            # a preregistered confined path for twin qualification.
            if item["path"]:
                relative_path(item["path"], "finding.path")
            normalized.append(Finding(item["rule"], item["path"], item["severity"],
                item["fingerprint"], item["allowlisted"], item["unit"],
                json.dumps(item, sort_keys=True, ensure_ascii=True, allow_nan=False)))
        findings = tuple(normalized)
        skipped = tuple(payload["skipped_files"])
        report_verdict = payload["verdict"]
        run = payload["run"]
        if (run["base"] not in {"HEAD~1", envelope.base_commit}
                or run["head"] not in {"HEAD", envelope.head_commit}):
            raise PreregistrationError("report_range_label_mismatch")
        if payload["config_errors"]:
            raise PreregistrationError("verifier_configuration_diagnostics")
        blocked = any(finding.blocks(fail_on) for finding in findings)
        if (report_verdict != ("block" if blocked else "pass")
                or code != (1 if blocked else 0)):
            raise PreregistrationError("verifier_policy_or_channel_disagreement")
        return VerifierObservation(case_id, binding_sha, metadata_sha, envelope.immutable_ref,
            stdout_sha, stderr_sha, not blocked, report_verdict, code, fail_on, findings, skipped, ())
    except (ValueError, TypeError, KeyError, OSError) as exc:
        return VerifierObservation(case_id, binding_sha, metadata_sha, None, stdout_sha, stderr_sha,
            None, report_verdict, code, fail_on, findings, skipped, (str(exc),))
