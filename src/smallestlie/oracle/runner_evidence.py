"""Validate externally captured runner observations, without executing runners.

Receipt integrity is not provenance. A configured independent provider supplies
the collector envelope. No provider means unknown; a receipt cannot trust itself.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import PurePosixPath, PureWindowsPath
from typing import Protocol
import xml.etree.ElementTree as ET

from smallestlie.attacks.adjudication import mapping, relative_path, string
from smallestlie.campaign.preregistration import (
    PreparedRun, PreregistrationError, canonical_digest, case_binding, commit, digest, integer, json_mapping,
)


@dataclass(frozen=True)
class TrustedExecutionEnvelope:
    provider_id: str
    immutable_ref: str
    request_sha256: str
    run_id: str
    source_run_id: str
    job_id: str
    host: str
    phase1_commit: str
    source_commit: str
    lock_digest: str
    receipt_sha256: str
    collector_sha256: str
    lock_sequence: int
    first_command_sequence: int
    arm_exits: tuple[tuple[str, str, int | None], ...]


class ExecutionAuthority(Protocol):
    def verify(self, prepared_run: PreparedRun, case_id: str,
               receipt_sha256: str) -> TrustedExecutionEnvelope | None:
        """Retrieve supervisor/dispatch facts independently of the receipt body."""
        ...


@dataclass(frozen=True)
class ArmEvidence:
    role: str
    valid: bool
    reasons: tuple[str, ...]
    termination_kind: str | None = None
    exit_code: int | None = None
    tests: tuple[tuple[str, str, str | None], ...] = ()


@dataclass(frozen=True)
class RunnerEvidenceValidation:
    case_id: str
    receipt_sha256: str | None
    provenance_ref: str | None
    reasons: tuple[str, ...]
    arms: tuple[ArmEvidence, ...]
    lock_digest: str | None = None
    spec_sha256: str | None = None
    profile_sha256: str | None = None

    def arm(self, role: str) -> ArmEvidence:
        return next((arm for arm in self.arms if arm.role == role),
                    ArmEvidence(role, False, ("arm_missing",)))


@dataclass(frozen=True)
class EffectivenessAssessment:
    case_id: str
    attack: str
    twin: str | None
    attack_reasons: tuple[str, ...]
    twin_reasons: tuple[str, ...]


def _junit(data: bytes, predicate: dict, *, require_assertion_type: bool = False
           ) -> tuple[tuple[str, str, str | None], ...]:
    if len(data) > 10_000_000 or b"<!DOCTYPE" in data.upper() or b"<!ENTITY" in data.upper():
        raise PreregistrationError("unsafe or oversized JUnit")
    root = ET.fromstring(data)
    if root.tag not in {"testsuite", "testsuites"}:
        raise PreregistrationError("unsupported JUnit root")
    result, ids = [], set()
    for test in root.iter("testcase"):
        name = string(test.get("name"), "JUnit test name")
        classname = test.get("classname", "")
        test_id = f"{classname}::{name}" if classname else name
        if test_id in ids:
            raise PreregistrationError("ambiguous JUnit test identity")
        ids.add(test_id)
        outcomes = [node for node in test if node.tag in {"failure", "error", "skipped"}]
        if len(outcomes) > 1:
            raise PreregistrationError("contradictory JUnit outcomes")
        state, failure_kind = "passed", None
        if outcomes:
            node = outcomes[0]
            state = {"failure": "failed", "error": "error", "skipped": "skipped"}[node.tag]
            matched = (predicate["message_contains"] in node.get("message", "")
                       and predicate["text_contains"] in (node.text or ""))
            assertion_types = {"AssertionError"} if require_assertion_type else {None, "AssertionError"}
            assertion = node.tag == "failure" and matched and node.get("type") in assertion_types
            failure_kind = "assertion" if assertion else (
                "exception:" + (node.get("type") or "unspecified") if node.tag in {"failure", "error"} else None)
        result.append((test_id, state, failure_kind))
    for suite in [root, *list(root.iter("testsuite"))]:
        cases = list(suite.iter("testcase"))
        counts = {"tests": len(cases), "failures": sum(test.find("failure") is not None for test in cases),
                  "errors": sum(test.find("error") is not None for test in cases),
                  "skipped": sum(test.find("skipped") is not None for test in cases)}
        for key, expected in counts.items():
            if key in suite.attrib and (not suite.attrib[key].isdigit() or int(suite.attrib[key]) != expected):
                raise PreregistrationError("JUnit summary contradicts testcase records")
    return tuple(result)


def _mocha_error(test: dict) -> dict:
    error = test.get("err")
    if error is None:
        return {}
    if not isinstance(error, dict):
        raise PreregistrationError("invalid Mocha failure")
    return error


def _mocha(data: bytes, predicate: dict) -> tuple[tuple[str, str, str | None], ...]:
    raw = json_mapping(data, "Mocha report")
    stats = raw.get("stats")
    if not isinstance(stats, dict):
        raise PreregistrationError("Mocha stats missing")
    result, ids, errors = [], set(), {}
    for key, state in (("passes", "passed"), ("failures", "failed"), ("pending", "skipped")):
        records = raw.get(key)
        if not isinstance(records, list):
            raise PreregistrationError("Mocha test arrays missing")
        for test in records:
            if not isinstance(test, dict):
                raise PreregistrationError("invalid Mocha test")
            tid = string(test.get("fullTitle"), "Mocha fullTitle")
            if tid in ids:
                raise PreregistrationError("ambiguous Mocha test identity")
            ids.add(tid)
            error = _mocha_error(test)
            if state != "failed" and error:
                raise PreregistrationError("Mocha non-failure has an exception")
            if "pending" in test and (type(test["pending"]) is not bool or test["pending"] != (state == "skipped")):
                raise PreregistrationError("Mocha pending flag contradicts outcome")
            errors[tid] = canonical_digest(error)
            matched = predicate["message_contains"] in error.get("message", "")
            assertion_identity = (error.get("name") in {None, "AssertionError"}
                and error.get("code") in {None, "ERR_ASSERTION"}
                and (error.get("name") == "AssertionError" or error.get("code") == "ERR_ASSERTION"))
            kind = "assertion" if matched and assertion_identity else "exception:" + str(error.get("name") or "unspecified")
            result.append((tid, state, kind if state == "failed" else None))
        count_key = {"passes": "passes", "failures": "failures", "pending": "pending"}[key]
        if integer(stats.get(count_key), "Mocha count") != len(records):
            raise PreregistrationError("Mocha stats contradict test arrays")
    tests = raw.get("tests")
    if not isinstance(tests, list) or len(tests) != len(ids):
        raise PreregistrationError("Mocha complete test array missing")
    test_ids = [string(test.get("fullTitle"), "Mocha test ID") for test in tests if isinstance(test, dict)]
    if len(test_ids) != len(ids) or len(set(test_ids)) != len(ids) or set(test_ids) != ids:
        raise PreregistrationError("Mocha test arrays disagree")
    states = {tid: state for tid, state, _ in result}
    for test in tests:
        tid = test["fullTitle"]
        if canonical_digest(_mocha_error(test)) != errors[tid]:
            raise PreregistrationError("Mocha duplicate arrays contradict exception identity")
        if "pending" in test and (type(test["pending"]) is not bool or test["pending"] != (states[tid] == "skipped")):
            raise PreregistrationError("Mocha complete array contradicts outcome")
    if integer(stats.get("tests"), "Mocha tests") != len(ids):
        raise PreregistrationError("Mocha total mismatch")
    return tuple(result)


def _absolute(value: str) -> str:
    string(value, "actual path")
    if not (PurePosixPath(value).is_absolute() or PureWindowsPath(value).is_absolute()):
        raise PreregistrationError("actual execution paths must be absolute")
    return value


def _arm(role: str, record: dict, expected: dict, profile: dict,
         artifacts: dict[str, bytes], supervisor: tuple[str, int | None], dependency_lock_sha256: str) -> ArmEvidence:
    try:
        mapping(record, "receipt arm", {"fixture", "runner", "runtime", "dependencies", "semantic_env",
                "workspace_root", "runtime_path", "argv", "cwd", "config", "termination_kind", "exit_code",
                "stdout", "stderr", "report", "truncated"})
        if record["truncated"] is not False:
            raise PreregistrationError("truncated evidence")
        if record["fixture"] != {key: expected[key] for key in ("files", "tree_sha256", "production")}:
            raise PreregistrationError("fixture/production identity mismatch")
        for key in ("runner", "runtime", "semantic_env"):
            if record[key] != profile[key]:
                raise PreregistrationError(f"{key} mismatch")
        if record["dependencies"] != {**profile["dependencies"], "lock_sha256": dependency_lock_sha256}:
            raise PreregistrationError("dependency lock/installed identity mismatch")
        command = profile["arms"][role]
        workspace = _absolute(record["workspace_root"]).rstrip("/\\")
        runtime = _absolute(record["runtime_path"])
        argv = [arg.replace("${WORKSPACE}", workspace).replace("${RUNTIME}", runtime) for arg in command["argv"]]
        separator = "\\" if PureWindowsPath(workspace).is_absolute() else "/"
        cwd = workspace if command["cwd"] == "." else workspace + separator + command["cwd"].replace("/", separator)
        if record["argv"] != argv or record["cwd"] != cwd or record["config"] != expected["config"]:
            raise PreregistrationError("command/cwd/configuration mismatch")
        kind, code = record["termination_kind"], record["exit_code"]
        if kind not in {"completed", "timeout", "spawn_error", "signal", "internal_error"}:
            raise PreregistrationError("unknown termination kind")
        if code is not None and type(code) is not int:
            raise PreregistrationError("exit code must be numeric, never bool")
        if kind == "completed" and code is None:
            raise PreregistrationError("completed execution requires a numeric exit")
        if (kind, code) != supervisor:
            raise PreregistrationError("exit contradicts the independent supervisor")
        payloads = {}
        for key in ("stdout", "stderr", "report"):
            ref = mapping(record[key], "artifact reference", {"path", "sha256"})
            path = relative_path(ref["path"], "artifact path")
            data = artifacts.get(path)
            if type(data) is not bytes or digest(data) != ref["sha256"]:
                raise PreregistrationError(f"missing/mismatched {key} bytes")
            payloads[key] = data
        if profile["report_format"] in {"junit", "vitest-junit"}:
            tests = _junit(payloads["report"], profile["assertion_failure"],
                           require_assertion_type=profile["report_format"] == "vitest-junit")
        else:
            tests = _mocha(payloads["report"], profile["assertion_failure"])
        if code == 0 and any(state in {"failed", "error"} for _, state, _ in tests):
            raise PreregistrationError("green exit contradicts native test results")
        return ArmEvidence(role, True, (), kind, code, tests)
    except (ValueError, KeyError, TypeError, ET.ParseError) as exc:
        return ArmEvidence(role, False, (str(exc),))


def validate_runner_receipt(prepared_run: PreparedRun, case_id: str, receipt_bytes: bytes | None,
                            artifact_bytes: dict[str, bytes], *,
                            authority: ExecutionAuthority | None) -> RunnerEvidenceValidation:
    """Hash and parse each captured bytes object once; missing trust never refutes."""
    receipt_sha = digest(receipt_bytes) if type(receipt_bytes) is bytes else None
    try:
        binding, lock = prepared_run.binding(case_id), prepared_run.lock()
        if receipt_bytes is None:
            raise PreregistrationError("receipt_missing")
        raw = json_mapping(receipt_bytes, "runner receipt")
        mapping(raw, "receipt", {"schema_version", "binding", "source_run_id", "job_id", "host", "arms"})
        if raw["schema_version"] != "smallestlie.runner-receipt/v1":
            raise PreregistrationError("unsupported runner receipt")
        expected_binding = case_binding(lock, case_id)
        if raw["binding"] != expected_binding:
            raise PreregistrationError("receipt formal binding mismatch")
        if authority is None:
            raise PreregistrationError("execution_provenance_missing")
        envelope = authority.verify(prepared_run, case_id, receipt_sha)
        profile = prepared_run.profile(case_id)
        if (not isinstance(envelope, TrustedExecutionEnvelope)
                or envelope.request_sha256 != canonical_digest(prepared_run.request.payload())
                or envelope.run_id != binding["run_id"]
                or envelope.source_run_id != raw["source_run_id"] or envelope.job_id != raw["job_id"]
                or envelope.host != raw["host"] or envelope.phase1_commit != lock["phase1_commit"]
                or envelope.source_commit != lock["source_commit"] or envelope.lock_digest != lock["lock_digest"]
                or envelope.receipt_sha256 != receipt_sha or envelope.collector_sha256 != profile["collector_sha256"]):
            raise PreregistrationError("independent execution envelope mismatch")
        for value in (envelope.provider_id, envelope.source_run_id, envelope.job_id, envelope.host):
            string(value, "execution provenance")
        commit(envelope.immutable_ref, "immutable receipt commit")
        integer(envelope.lock_sequence, "lock sequence", minimum=1)
        integer(envelope.first_command_sequence, "first command sequence", minimum=1)
        if envelope.lock_sequence >= envelope.first_command_sequence:
            raise PreregistrationError("formal command preceded the lock")
        if not isinstance(raw["arms"], dict) or raw["arms"].keys() - binding["arms"].keys():
            raise PreregistrationError("undeclared receipt arm")
        exits = {}
        for role, kind, code in envelope.arm_exits:
            if role in exits or role not in binding["arms"] or (code is not None and type(code) is not int):
                raise PreregistrationError("invalid supervisor arm identity/exit")
            exits[role] = (kind, code)
        arms = tuple(_arm(role, raw["arms"][role], expected, profile, artifact_bytes, exits[role], binding["dependency_lock_sha256"])
                     if role in raw["arms"] and role in exits else ArmEvidence(role, False, ("arm_missing",))
                     for role, expected in binding["arms"].items())
        return RunnerEvidenceValidation(case_id, receipt_sha, envelope.immutable_ref, (), arms,
                                        lock["lock_digest"], binding["spec_sha256"], binding["profile_sha256"])
    except (ValueError, KeyError, TypeError, OSError) as exc:
        return RunnerEvidenceValidation(case_id, receipt_sha, None, (str(exc),), ())


def assess_effectiveness(prepared_run: PreparedRun,
                         evidence: RunnerEvidenceValidation) -> EffectivenessAssessment:
    binding = prepared_run.binding(evidence.case_id)
    profile = prepared_run.profile(evidence.case_id)
    assertion = profile["baseline_assertion"]
    def green(arm: ArmEvidence, *, target: bool = False) -> bool:
        return (arm.valid and arm.termination_kind == "completed" and arm.exit_code == 0
                and not any(state in {"failed", "error"} for _, state, _ in arm.tests)
                and (not target or any(tid == assertion and state == "passed" for tid, state, _ in arm.tests)))
    def red(arm: ArmEvidence) -> bool:
        return (arm.valid and arm.termination_kind == "completed" and arm.exit_code in profile["assertion_exit_codes"]
                and any(tid == assertion and state == "failed" and kind == "assertion" for tid, state, kind in arm.tests)
                and not any(state == "error" for _, state, _ in arm.tests))
    def assess(role: str) -> tuple[str, tuple[str, ...]]:
        if (evidence.lock_digest != prepared_run.lock()["lock_digest"]
                or evidence.spec_sha256 != binding["spec_sha256"]
                or evidence.profile_sha256 != binding["profile_sha256"]):
            return "unknown", (*evidence.reasons, "evidence_prepared_run_mismatch")
        if evidence.reasons or evidence.provenance_ref is None:
            return "unknown", evidence.reasons or ("execution_provenance_missing",)
        base, changed, repaired = evidence.arm("baseline"), evidence.arm(role), evidence.arm("repair")
        if green(base, target=True):
            return "refuted", ("baseline_target_already_green",)
        if not red(base):
            return "unknown", ("baseline_assertion_red_unproved", *base.reasons)
        if red(changed):
            return "refuted", ("changed_target_assertion_still_red",)
        if not green(changed):
            return "unknown", ("changed_green_unproved", *changed.reasons)
        if not green(repaired, target=True):
            return "unknown", ("repair_target_green_unproved", *repaired.reasons)
        return "confirmed", ("bound_assertion_red_to_green_with_repair_calibration",)
    attack, attack_reasons = assess("attack")
    twin, twin_reasons = assess("twin") if "twin" in binding["arms"] else (None, ())
    return EffectivenessAssessment(evidence.case_id, attack, twin, attack_reasons, twin_reasons)
