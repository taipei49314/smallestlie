"""Versioned lifecycle ordering; neither a hash chain nor a disposition attests execution."""

from __future__ import annotations

from collections import Counter
from dataclasses import asdict, dataclass
from typing import Any

from smallestlie.attacks.adjudication import choice, mapping, sha256, string, strings
from smallestlie.campaign.preregistration import (
    PROTOCOL as LOCK_PROTOCOL, PreparedRun, PreregistrationError, canonical_digest,
    case_binding, commit, digest, integer, validate_profile,
)
from smallestlie.ledger.protocol import validate_m12_lock

PROTOCOL = "smallestlie.m12/v2"
EVENTS = {"lifecycle_action_reserved", "lifecycle_action_disposed", "observations_sealed",
          "review_disposed", "case_adjudicated"}
KINDS = {"runner_materialize", "runner_command", "verifier_materialize", "verifier_command"}
OBSERVED = {"completed", "timeout", "spawn_error", "signal", "quota", "output_incomplete", "internal_error"}
UNOBSERVED = {"not_run", "completion_missing", "completion_rejected"}
VERDICTS = {"confirmed_defect", "documented_residual", "boundary", "killed_candidate",
            "ineffective_candidate", "attack_rejected", "control_accepted", "control_rejected", "unknown"}


def action_key(case_id: str, kind: str, arm: str) -> str:
    return canonical_digest({"case_id": case_id, "kind": kind, "arm": arm})


def slots(lock: dict) -> list[tuple[str, str, str]]:
    result = []
    for case in lock["cases"]:
        cid = case["case_id"]
        for arm in ("baseline", "attack", "twin", "repair"):
            if arm in case["arms"]:
                result.extend((cid, kind, arm) for kind in ("runner_materialize", "runner_command"))
        result.extend([(cid, "verifier_materialize", "baseline"),
                       (cid, "verifier_materialize", "attack"), (cid, "verifier_command", "attack")])
    return result


def expected_files(lock: dict, case_id: str, kind: str, arm: str) -> dict:
    case = next(item for item in lock["cases"] if item["case_id"] == case_id)
    roles = ("baseline", "attack") if kind == "verifier_command" else (arm,)
    return {role: case["arms"][role]["files"] for role in roles}


def verifier_command(lock: dict) -> dict:
    return {"engine": lock["engine"], "argv": ["${RUNTIME}", "${ENGINE}", "check", "HEAD~1..HEAD", "--format", "json"],
            "cwd": "."}


def action_plan(prepared: PreparedRun) -> dict:
    lock = validate_m12_lock(prepared.lock())
    if prepared.request.payload() != {key: lock[key] for key in prepared.request.payload()}:
        raise PreregistrationError("prepared request/lock mismatch")
    profiles = {}
    for case in lock["cases"]:
        raw = [data for cid, data in prepared.profiles if cid == case["case_id"]]
        if len(raw) != 1 or digest(raw[0]) != case["profile_sha256"]:
            raise PreregistrationError("lifecycle requires exact frozen profile bytes")
        profiles[case["case_id"]] = validate_profile(raw[0])
    plan = {}
    for cid, kind, arm in slots(lock):
        case = prepared.binding(cid)
        command = (profiles[cid]["arms"][arm] if kind == "runner_command" else
                   verifier_command(lock) if kind == "verifier_command" else None)
        plan[action_key(cid, kind, arm)] = {"binding": case_binding(lock, cid), "kind": kind, "arm": arm,
            "files": expected_files(lock, cid, kind, arm), "profile_sha256": case["profile_sha256"],
            "command_sha256": canonical_digest(command) if command is not None else None}
    return plan


def declaration(lock: dict, plan: dict) -> dict:
    return {"protocol": PROTOCOL, "lock_protocol": LOCK_PROTOCOL,
            **{key: lock[key] for key in ("campaign_id", "request_sha256", "phase1_commit", "manifest_sha256", "lock_digest")},
            "case_ids_sha256": canonical_digest([case["case_id"] for case in lock["cases"]]),
            "plan_sha256": canonical_digest(plan)}


def artifact_ref(value: Any, *, present: bool = False) -> dict:
    mapping(value, "artifact reference", {"state", "sha256", "bytes"})
    choice(value["state"], "artifact state", {"present"} if present else {"present", "missing"})
    if value["state"] == "present":
        sha256(value["sha256"], "raw artifact digest")
        integer(value["bytes"], "raw artifact size")
    elif value["sha256"] is not None or value["bytes"] is not None:
        raise PreregistrationError("missing artifact cannot claim bytes")
    return value


@dataclass(frozen=True)
class ActionReservation:
    protocol: str
    case_id: str
    kind: str
    arm: str
    binding_sha256: str
    context_sha256: str
    lock_digest: str
    seq: int
    entry_digest: str

    def to_dict(self) -> dict:
        return asdict(self)


def reservation(lock: dict, context: dict, entry: dict) -> ActionReservation:
    return ActionReservation(PROTOCOL, context["binding"]["case_id"], context["kind"], context["arm"],
        canonical_digest(context["binding"]), canonical_digest(context), lock["lock_digest"],
        entry["seq"], entry["entry_digest"])


def prerequisites(case_id: str, kind: str, arm: str) -> list[str]:
    if kind == "runner_command":
        return [action_key(case_id, "runner_materialize", arm)]
    if kind == "verifier_command":
        return [action_key(case_id, "verifier_materialize", role) for role in ("baseline", "attack")]
    return []


def summary_counts(lock: dict, rows: dict) -> dict:
    counts = Counter(row["verdict"] for row in rows.values())
    return {"frozen_case_count": len(lock["cases"]), "verdict_counts": dict(sorted(counts.items())),
            "confirmed_defect_case_count": counts["confirmed_defect"],
            "paired_defect_case_count": sum(row["paired_headline"] for row in rows.values())}


def _validate_plan(lock: dict, plan: dict) -> None:
    if not isinstance(plan, dict) or set(plan) != {action_key(*slot) for slot in slots(lock)}:
        raise PreregistrationError("action plan drops or adds a frozen slot")
    for cid, kind, arm in slots(lock):
        context = plan[action_key(cid, kind, arm)]
        mapping(context, "planned context", {"binding", "kind", "arm", "files", "profile_sha256", "command_sha256"})
        case = next(case for case in lock["cases"] if case["case_id"] == cid)
        if (context["binding"] != case_binding(lock, cid) or context["kind"] != kind or context["arm"] != arm
                or context["files"] != expected_files(lock, cid, kind, arm)
                or context["profile_sha256"] != case["profile_sha256"]):
            raise PreregistrationError("planned context contradicts frozen case")
        if kind.endswith("materialize"):
            if context["command_sha256"] is not None:
                raise PreregistrationError("materialization is not a command")
        else:
            sha256(context["command_sha256"], "planned command")
            if kind == "verifier_command" and context["command_sha256"] != canonical_digest(verifier_command(lock)):
                raise PreregistrationError("unsupported verifier command plan")


def verify_lifecycle_protocol(entries: list[dict], *, expected_lock: dict | None = None,
                              expected_plan: dict | None = None) -> dict:
    """Validate ordering and references only. Artifacts/authority are separate checks."""
    lock = None
    plan = {}
    actions, reviews, rows = {}, {}, {}
    snapshot = counts = None
    finalized = policy = False
    try:
        if expected_lock is not None:
            validate_m12_lock(expected_lock)
        if not entries or entries[0].get("event_type") != "campaign_created":
            raise PreregistrationError("lifecycle requires declaration first")
        marker = entries[0]["payload"]
        mapping(marker, "lifecycle declaration", {"protocol", "lock_protocol", "campaign_id", "request_sha256",
                "phase1_commit", "manifest_sha256", "lock_digest", "case_ids_sha256", "plan_sha256"})
        if marker["protocol"] != PROTOCOL or marker["lock_protocol"] != LOCK_PROTOCOL:
            raise PreregistrationError("unsupported lifecycle/lock protocol")
        string(marker["campaign_id"], "lifecycle campaign")
        commit(marker["phase1_commit"], "Phase1")
        for key in ("request_sha256", "manifest_sha256", "lock_digest", "case_ids_sha256", "plan_sha256"):
            sha256(marker[key], key)
        if expected_lock is not None and any(marker[key] != expected_lock[key]
                for key in ("campaign_id", "request_sha256", "phase1_commit", "manifest_sha256", "lock_digest")):
            raise PreregistrationError("external lifecycle lock mismatch")
        for seq, entry in enumerate(entries, 1):
            if (type(entry.get("seq")) is not int or entry["seq"] != seq
                    or entry.get("schema_version") != "smallestlie.ledger/v1"):
                raise PreregistrationError("lifecycle ledger envelope mismatch")
            sha256(entry["entry_digest"], "entry digest")
            event, payload = entry["event_type"], entry["payload"]
            if finalized or not isinstance(payload, dict):
                raise PreregistrationError("event after summary or invalid payload")
            if event == "campaign_created":
                if seq != 1:
                    raise PreregistrationError("duplicate lifecycle declaration")
                continue
            if event == "policy_validated":
                mapping(payload, "policy result", {"ok", "artifact"})
                if policy or lock is not None or payload["ok"] is not True:
                    raise PreregistrationError("policy must pass once before lock")
                artifact_ref(payload["artifact"], present=True)
                policy = True
                continue
            if event == "preregistration_locked":
                mapping(payload, "lifecycle lock wrapper", {"lock", "action_plan", "frozen_inputs"})
                if lock is not None or not policy:
                    raise PreregistrationError("duplicate lock or lock before policy")
                lock = validate_m12_lock(payload["lock"])
                plan = payload["action_plan"]
                artifact_ref(payload["frozen_inputs"], present=True)
                _validate_plan(lock, plan)
                if declaration(lock, plan) != marker or (expected_plan is not None and plan != expected_plan):
                    raise PreregistrationError("lifecycle declaration/plan mismatch")
                if expected_lock is not None and lock != expected_lock:
                    raise PreregistrationError("external exact lifecycle lock mismatch")
                continue
            if lock is None:
                raise PreregistrationError("lifecycle event before lock")
            ids = [case["case_id"] for case in lock["cases"]]
            if event in {"lifecycle_action_reserved", "lifecycle_action_disposed"}:
                if snapshot is not None:
                    raise PreregistrationError("action after observation seal")
                binding = payload.get("binding")
                if not isinstance(binding, dict) or binding != case_binding(lock, binding.get("case_id")):
                    raise PreregistrationError("lifecycle action case binding mismatch")
                cid, kind, arm = binding["case_id"], payload.get("kind"), payload.get("arm")
                key = action_key(cid, kind, arm)
                if key not in plan or payload.get("context_sha256") != canonical_digest(plan[key]):
                    raise PreregistrationError("undeclared action or context mismatch")
                state = actions.setdefault(key, {"reservation": None, "disposition": None})
                if state["disposition"] is not None:
                    raise PreregistrationError("action identity is permanently disposed")
                if event == "lifecycle_action_reserved":
                    mapping(payload, "reservation", {"binding", "kind", "arm", "context_sha256"})
                    if state["reservation"] is not None:
                        raise PreregistrationError("action identity already reserved")
                    if any((actions.get(dep, {}).get("disposition") or {}).get("status") != "completed"
                           for dep in prerequisites(cid, kind, arm)):
                        raise PreregistrationError("command requires completed materialization")
                    state["reservation"] = reservation(lock, plan[key], entry).to_dict()
                else:
                    mapping(payload, "action disposition", {"binding", "kind", "arm", "context_sha256", "reservation",
                            "status", "completion", "validation", "sources", "outputs", "provenance_ref", "reasons"})
                    status = choice(payload["status"], "disposition", OBSERVED | UNOBSERVED)
                    artifact_ref(payload["completion"])
                    artifact_ref(payload["validation"], present=True)
                    mapping(payload["sources"], "completion sources", {"publication", "supervisor"})
                    for ref in payload["sources"].values():
                        artifact_ref(ref)
                    output_roles = {"stdout", "stderr", "report"} if kind == "runner_command" else (
                        {"metadata", "stdout", "stderr"} if kind == "verifier_command" else set())
                    mapping(payload["outputs"], "command outputs", output_roles)
                    for ref in payload["outputs"].values():
                        artifact_ref(ref)
                    reasons = strings(payload["reasons"], "disposition reasons", allow_empty=True)
                    if status == "not_run":
                        if state["reservation"] is not None or payload["reservation"] is not None:
                            raise PreregistrationError("reserved action cannot become not_run")
                    elif state["reservation"] is None or payload["reservation"] != state["reservation"]:
                        raise PreregistrationError("completion lacks exact persisted reservation")
                    if status in OBSERVED:
                        artifact_ref(payload["completion"], present=True)
                        for ref in payload["sources"].values():
                            artifact_ref(ref, present=True)
                        commit(payload["provenance_ref"], "completion provenance")
                        if reasons:
                            raise PreregistrationError("observed action has validation failures")
                    elif payload["provenance_ref"] is not None or not reasons:
                        raise PreregistrationError("unobserved disposition needs explicit reasons")
                    if status in {"not_run", "completion_missing"} and any(ref["state"] != "missing"
                            for ref in [payload["completion"], *payload["sources"].values(), *payload["outputs"].values()]):
                        raise PreregistrationError("unexecuted/missing completion claims output bytes")
                    if status == "completion_rejected":
                        artifact_ref(payload["completion"], present=True)
                    state["disposition"] = payload
                continue
            if event == "observations_sealed":
                mapping(payload, "observation seal", {"lock_digest", "case_ids_sha256", "index"})
                if snapshot is not None or set(actions) != set(plan) or any(state["disposition"] is None for state in actions.values()):
                    raise PreregistrationError("observation seal drops pending/frozen actions")
                if payload["lock_digest"] != lock["lock_digest"] or payload["case_ids_sha256"] != marker["case_ids_sha256"]:
                    raise PreregistrationError("observation seal denominator mismatch")
                artifact_ref(payload["index"], present=True)
                snapshot = payload["index"]["sha256"]
                continue
            if event in {"review_disposed", "case_adjudicated"}:
                binding = payload.get("binding")
                if (snapshot is None or not isinstance(binding, dict)
                        or binding != case_binding(lock, binding.get("case_id")) or payload.get("snapshot_sha256") != snapshot):
                    raise PreregistrationError("review/adjudication requires the full sealed observation map")
                cid = binding["case_id"]
                if event == "review_disposed":
                    mapping(payload, "review disposition", {"binding", "snapshot_sha256", "observation_map_sha256", "review",
                            "validation", "provenance_ref", "reasons"})
                    if cid in reviews or rows:
                        raise PreregistrationError("duplicate or late review")
                    sha256(payload["observation_map_sha256"], "review observation map")
                    artifact_ref(payload["review"])
                    artifact_ref(payload["validation"], present=True)
                    reasons = strings(payload["reasons"], "review reasons", allow_empty=True)
                    if payload["provenance_ref"] is not None:
                        commit(payload["provenance_ref"], "review provenance")
                        artifact_ref(payload["review"], present=True)
                        if reasons:
                            raise PreregistrationError("trusted review has validation failures")
                    elif not reasons:
                        raise PreregistrationError("untrusted review lacks a reason")
                    reviews[cid] = payload
                else:
                    mapping(payload, "case adjudication", {"binding", "snapshot_sha256", "review_validation_sha256", "row",
                            "verdict", "paired_headline"})
                    if set(reviews) != set(ids) or cid in rows:
                        raise PreregistrationError("adjudication requires every review disposition once")
                    if payload["review_validation_sha256"] != reviews[cid]["validation"]["sha256"]:
                        raise PreregistrationError("adjudication/review binding mismatch")
                    artifact_ref(payload["row"], present=True)
                    choice(payload["verdict"], "research verdict", VERDICTS)
                    if type(payload["paired_headline"]) is not bool or (payload["paired_headline"] and payload["verdict"] != "confirmed_defect"):
                        raise PreregistrationError("invalid paired headline")
                    rows[cid] = payload
                continue
            if event == "campaign_summary":
                mapping(payload, "lifecycle summary", {"protocol", "lock_digest", "snapshot_sha256", "case_ids_sha256", "report", "counts"})
                if set(rows) != set(ids) or payload["protocol"] != PROTOCOL or payload["lock_digest"] != lock["lock_digest"]:
                    raise PreregistrationError("summary drops frozen cases or lock")
                if payload["snapshot_sha256"] != snapshot or payload["case_ids_sha256"] != marker["case_ids_sha256"]:
                    raise PreregistrationError("summary snapshot/denominator mismatch")
                artifact_ref(payload["report"], present=True)
                counts = summary_counts(lock, rows)
                if canonical_digest(payload["counts"]) != canonical_digest(counts):
                    raise PreregistrationError("summary counts contradict complete case rows")
                finalized = True
                continue
            raise PreregistrationError(f"unsupported lifecycle event: {event}")
        return {"ok": True, "error": None, "protocol": PROTOCOL, "locked": lock is not None, "complete": finalized,
                "action_states": actions, "snapshot_sha256": snapshot, "reviews": reviews, "rows": rows, "counts": counts}
    except (ValueError, KeyError, TypeError, StopIteration, AttributeError) as exc:
        return {"ok": False, "error": str(exc), "protocol": PROTOCOL, "locked": lock is not None, "complete": False}
