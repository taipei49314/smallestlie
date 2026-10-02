"""Opt-in formal-run ordering/binding; the chain is not execution attestation."""

from __future__ import annotations

from typing import Any

from smallestlie.adapters.checkwash import PINNED_SHA256, PINNED_SOURCE_REVISION, PINNED_VERSION
from smallestlie.adjudication.residuals import PINNED_INDEX_SHA256
from smallestlie.attacks.adjudication import choice, mapping, relative_path, sha256, string, strings
from smallestlie.campaign.preregistration import PROTOCOL, PreparedRun, PreregistrationError, canonical_digest, case_binding, commit

RECEIPTS = {"runner_receipt_verified": "verified", "runner_receipt_rejected": "rejected",
            "runner_receipt_missing": "missing"}
M12_EVENTS = set(RECEIPTS) | {"preregistration_locked", "effectiveness_assessed", "formal_action_started"}
EXECUTION_EVENTS = {"formal_action_started", "mutant_created", "mutation_applied", "command_executed", "target_verdict_parsed",
                    "oracle_evaluated", "comparator_result", "blocked", "harness_error"}
ACTIONS = {"workspace_create", "workspace_prepare", "mutation_apply", "verifier_command"}


def _new_state() -> dict:
    return {"started": [], "pending": None, "created": False, "prepared": False,
            "mutated": False, "phase": 0, "stopped": False}


def _require_action(state: dict, action: str) -> None:
    choice(action, "formal action", ACTIONS)
    if state["stopped"] or state["pending"] is not None or action in state["started"]:
        raise PreregistrationError("duplicate, pending or stopped formal action")
    ready = {
        "workspace_create": not state["created"],
        "workspace_prepare": state["created"] and not state["mutated"],
        "mutation_apply": state["created"] and not state["mutated"],
        "verifier_command": state["mutated"] and state["phase"] == 0,
    }
    if not ready[action]:
        raise PreregistrationError("formal action prerequisites are incomplete")


def validate_m12_lock(raw: dict) -> dict:
    mapping(raw, "lock", {"protocol", "campaign_id", "request_id", "run_id", "phase1_commit", "source_commit",
            "manifest_sha256", "authorization_ref", "request_sha256", "catalog_sha256", "engine",
            "residual_index_sha256", "approval_provider", "cases", "lock_digest"})
    choice(raw["protocol"], "lock protocol", {PROTOCOL})
    for key in ("campaign_id", "request_id", "run_id", "authorization_ref", "approval_provider"):
        string(raw[key], key)
    for key in ("phase1_commit", "source_commit"):
        commit(raw[key], key)
    for key in ("manifest_sha256", "request_sha256", "catalog_sha256", "residual_index_sha256", "lock_digest"):
        sha256(raw[key], key)
    if canonical_digest({key: value for key, value in raw.items() if key != "lock_digest"}) != raw["lock_digest"]:
        raise PreregistrationError("lock digest mismatch")
    request = {key: raw[key] for key in ("campaign_id", "request_id", "run_id", "phase1_commit",
                                        "source_commit", "manifest_sha256", "authorization_ref")}
    if canonical_digest(request) != raw["request_sha256"]:
        raise PreregistrationError("request digest mismatch")
    if (raw["engine"] != {"version": PINNED_VERSION, "artifact_sha256": PINNED_SHA256,
                          "source_revision": PINNED_SOURCE_REVISION}
            or raw["residual_index_sha256"] != PINNED_INDEX_SHA256):
        raise PreregistrationError("lock published pin mismatch")
    if not isinstance(raw["cases"], list) or not raw["cases"]:
        raise PreregistrationError("lock must preserve the case denominator")
    cases, runs = {}, set()
    for case in raw["cases"]:
        mapping(case, "locked case", {"case_id", "run_id", "spec_sha256", "profile_id", "profile_sha256",
                "dependency_lock_sha256", "preregistered_class", "control_role", "twin_case_id", "arms"})
        cid, run = string(case["case_id"], "case id"), string(case["run_id"], "run id")
        if cid in cases or run in runs or run != raw["run_id"] + ":" + cid:
            raise PreregistrationError("duplicate/incorrect case run identity")
        cases[cid], runs = case, runs | {run}
        for key in ("spec_sha256", "profile_sha256", "dependency_lock_sha256"):
            sha256(case[key], key)
        string(case["profile_id"], "profile id")
        klass = choice(case["preregistered_class"], "preregistered class", {"CTL", "DEF", "BND", "RES"})
        if klass == "CTL":
            choice(case["control_role"], "control role", {"detectable_attack_control", "honest_control", "repair_control"})
        elif case["control_role"] is not None:
            raise PreregistrationError("non-control case has a control role")
        twin = case["twin_case_id"]
        if klass == "DEF" and twin is None:
            raise PreregistrationError("DEF lock lacks twin")
        if twin is not None and (string(twin, "twin id") == cid):
            raise PreregistrationError("self twin")
        roles = {"baseline", "attack", "repair"} | ({"twin"} if twin else set())
        mapping(case["arms"], "locked arms", roles)
        for arm in case["arms"].values():
            mapping(arm, "locked arm", {"files", "tree_sha256", "production", "config"})
            if not isinstance(arm["files"], dict) or not arm["files"]:
                raise PreregistrationError("empty frozen fixture")
            for path, value in arm["files"].items():
                relative_path(path, "fixture path")
                sha256(value, "fixture file")
            if canonical_digest(arm["files"]) != arm["tree_sha256"]:
                raise PreregistrationError("fixture tree mismatch")
            for key in ("production", "config"):
                if not isinstance(arm[key], dict) or (key == "production" and not arm[key]):
                    raise PreregistrationError("production/config map missing")
                for path, value in arm[key].items():
                    if arm["files"].get(path) != value:
                        raise PreregistrationError("production/config file not in frozen fixture")
        base, repair = case["arms"]["baseline"], case["arms"]["repair"]
        for role in roles - {"baseline", "repair"}:
            if case["arms"][role]["production"] != base["production"]:
                raise PreregistrationError("changed bug production")
        if repair["production"].keys() != base["production"].keys() or repair["production"] == base["production"]:
            raise PreregistrationError("repair production is not calibrated")
        without_prod = lambda arm: {key: val for key, val in arm["files"].items() if key not in arm["production"]}
        if without_prod(base) != without_prod(repair):
            raise PreregistrationError("repair changes baseline tests/inputs")
    for case in cases.values():
        if case["twin_case_id"] is None:
            continue
        twin = cases.get(case["twin_case_id"])
        if (twin is None or twin["preregistered_class"] != "CTL"
                or twin["control_role"] != "detectable_attack_control" or twin["twin_case_id"] is not None
                or twin["profile_sha256"] != case["profile_sha256"] or twin["profile_id"] != case["profile_id"]
                or case["arms"]["twin"] != twin["arms"]["attack"]
                or case["arms"]["baseline"] != twin["arms"]["baseline"]
                or case["arms"]["repair"] != twin["arms"]["repair"]):
            raise PreregistrationError("locked twin mismatch")
    return raw


def campaign_declaration(prepared: PreparedRun) -> dict:
    lock = prepared.lock()
    return {key: lock[key] for key in ("protocol", "campaign_id", "request_sha256", "phase1_commit", "manifest_sha256")}


def verify_m12_protocol(entries: list[dict], *, expected_lock: dict | None = None) -> dict[str, Any]:
    lock = None
    receipts, effects, states = {}, {}, {}
    counts = None
    finalized = False
    try:
        if expected_lock is not None:
            validate_m12_lock(expected_lock)
        if not entries or entries[0]["event_type"] != "campaign_created":
            raise PreregistrationError("M12 requires the campaign declaration first")
        marker = entries[0]["payload"]
        mapping(marker, "campaign declaration", {"protocol", "campaign_id", "request_sha256", "phase1_commit", "manifest_sha256"})
        choice(marker["protocol"], "campaign protocol", {PROTOCOL})
        string(marker["campaign_id"], "campaign id")
        commit(marker["phase1_commit"], "declared Phase 1")
        sha256(marker["request_sha256"], "declared request")
        sha256(marker["manifest_sha256"], "declared manifest")
        if expected_lock is not None and marker != {key: expected_lock[key] for key in marker}:
            raise PreregistrationError("external expected declaration mismatch")
        policy_seen = False
        for seq, entry in enumerate(entries, 1):
            if not isinstance(entry, dict):
                raise PreregistrationError("invalid M12 entry")
            if type(entry.get("seq")) is not int or entry["seq"] != seq or entry.get("schema_version") != "smallestlie.ledger/v1":
                raise PreregistrationError("M12 ledger envelope mismatch")
            event, payload = entry["event_type"], entry["payload"]
            if not isinstance(payload, dict):
                raise PreregistrationError("M12 payload must be a mapping")
            if finalized:
                raise PreregistrationError("event after finalized summary")
            if event == "campaign_created":
                if seq != 1:
                    raise PreregistrationError("duplicate campaign declaration")
                continue
            if event == "policy_validated":
                if policy_seen or lock is not None or payload.get("ok") is not True:
                    raise PreregistrationError("policy must pass once before lock")
                policy_seen = True
                continue
            if event == "preregistration_locked":
                if lock is not None or not policy_seen:
                    raise PreregistrationError("duplicate lock or lock before policy")
                lock = validate_m12_lock(payload)
                if marker != {key: lock[key] for key in marker}:
                    raise PreregistrationError("campaign declaration/lock mismatch")
                if expected_lock is not None and lock["lock_digest"] != expected_lock["lock_digest"]:
                    raise PreregistrationError("external expected lock mismatch")
                continue
            if lock is None:
                raise PreregistrationError("case event before preregistration lock")
            if event == "campaign_summary":
                mapping(payload, "M12 summary", {"protocol", "lock_digest", "counts"})
                if set(effects) != {case["case_id"] for case in lock["cases"]}:
                    raise PreregistrationError("summary drops declared cases")
                counts = {"declared_case_count": len(lock["cases"]),
                    "preregistered_classes": {key: sum(case["preregistered_class"] == key for case in lock["cases"])
                                              for key in ("CTL", "DEF", "BND", "RES")},
                    "receipts": {key: sum(value == key for value in receipts.values()) for key in ("verified", "rejected", "missing")},
                    "attack_effectiveness": {key: sum(value[0] == key for value in effects.values()) for key in ("confirmed", "refuted", "unknown")},
                    "twin_effectiveness": {key: sum((value[1] or "not_applicable") == key for value in effects.values())
                                           for key in ("confirmed", "refuted", "unknown", "not_applicable")}}
                if (payload["protocol"] != PROTOCOL or payload["lock_digest"] != lock["lock_digest"]
                        or canonical_digest(payload["counts"]) != canonical_digest(counts)):
                    raise PreregistrationError("summary distributions contradict frozen denominator/events")
                finalized = True
                continue
            if event not in EXECUTION_EVENTS | set(RECEIPTS) | {"effectiveness_assessed"}:
                raise PreregistrationError(f"unsupported M12 event: {event}")
            binding = payload.get("binding", {})
            if not isinstance(binding, dict):
                raise PreregistrationError("case binding must be a mapping")
            cid = binding.get("case_id")
            if binding != case_binding(lock, cid):
                raise PreregistrationError("case event binding mismatch")
            if cid in effects:
                raise PreregistrationError("case event after terminal effectiveness")
            state = states.setdefault(cid, _new_state())
            if event in EXECUTION_EVENTS and (cid in receipts or (state["stopped"] and event not in {"blocked", "harness_error"})):
                raise PreregistrationError("execution after receipt disposition or stopped case")
            if event in RECEIPTS:
                mapping(payload, "receipt disposition", {"binding", "receipt_sha256", "validation_sha256", "provenance_ref", "reasons"})
                if cid in receipts:
                    raise PreregistrationError("duplicate receipt disposition")
                sha256(payload["validation_sha256"], "validation digest")
                if payload["receipt_sha256"] is not None:
                    sha256(payload["receipt_sha256"], "receipt digest")
                reasons = strings(payload["reasons"], "receipt reasons", allow_empty=True)
                status = RECEIPTS[event]
                if status == "verified":
                    sha256(payload["receipt_sha256"], "verified receipt")
                    commit(payload["provenance_ref"], "verified provenance")
                    if reasons:
                        raise PreregistrationError("verified receipt has core validation errors")
                elif not reasons or payload["provenance_ref"] is not None:
                    raise PreregistrationError("missing/rejected receipt needs an untrusted reason")
                if status == "missing" and payload["receipt_sha256"] is not None:
                    raise PreregistrationError("missing receipt claims bytes")
                receipts[cid] = status
            elif event == "effectiveness_assessed":
                mapping(payload, "effectiveness", {"binding", "attack", "twin", "reasons", "assessment_sha256"})
                if cid not in receipts:
                    raise PreregistrationError("effectiveness before receipt disposition")
                attack = choice(payload["attack"], "attack effectiveness", {"confirmed", "refuted", "unknown"})
                case = next(case for case in lock["cases"] if case["case_id"] == cid)
                twin = payload["twin"]
                if case["twin_case_id"] is not None:
                    choice(twin, "twin effectiveness", {"confirmed", "refuted", "unknown"})
                elif twin is not None:
                    raise PreregistrationError("effectiveness for undeclared twin")
                if receipts[cid] != "verified" and (attack != "unknown" or twin not in {None, "unknown"}):
                    raise PreregistrationError("untrusted/missing receipt cannot confirm or refute")
                reasons = mapping(payload["reasons"], "effectiveness reasons", {"attack", "twin"})
                strings(reasons["attack"], "attack reasons")
                strings(reasons["twin"], "twin reasons", allow_empty=twin is None)
                expected = {"case_id": cid, "attack": attack, "twin": twin,
                            "attack_reasons": reasons["attack"], "twin_reasons": reasons["twin"]}
                if payload["assessment_sha256"] != canonical_digest(expected):
                    raise PreregistrationError("assessment digest mismatch")
                effects[cid] = (attack, twin)
            elif event == "formal_action_started":
                mapping(payload, "action reservation", {"binding", "action"})
                if cid in receipts:
                    raise PreregistrationError("formal action after receipt disposition")
                action = payload["action"]
                _require_action(state, action)
                state["started"].append(action)
                state["pending"] = action
            elif event == "mutant_created":
                stage = choice(payload.get("stage"), "workspace stage", {"created", "prepared"})
                expected_action = "workspace_create" if stage == "created" else "workspace_prepare"
                if state["pending"] != expected_action or state[stage] or state["mutated"]:
                    raise PreregistrationError("unreserved/duplicate workspace stage")
                state[stage], state["pending"] = True, None
            elif event == "mutation_applied":
                if state["pending"] != "mutation_apply" or state["mutated"]:
                    raise PreregistrationError("unreserved/duplicate mutation")
                state["mutated"], state["pending"] = True, None
            elif event in {"command_executed", "target_verdict_parsed", "oracle_evaluated", "comparator_result"}:
                step = {"command_executed": 1, "target_verdict_parsed": 2, "oracle_evaluated": 3, "comparator_result": 4}[event]
                if (not state["mutated"] or state["phase"] != step - 1 or state["stopped"]
                        or (step == 1 and state["pending"] != "verifier_command")
                        or (step > 1 and state["pending"] is not None)):
                    raise PreregistrationError("verifier observation order/duplicate mismatch")
                state["phase"], state["pending"] = step, None
            elif event in {"blocked", "harness_error"}:
                if state["stopped"]:
                    raise PreregistrationError("duplicate stopped execution")
                state["stopped"] = True
        return {"ok": True, "error": None, "protocol": PROTOCOL, "complete": finalized,
                "locked": lock is not None, "terminal_cases": sorted(effects), "counts": counts,
                "action_states": states}
    except (ValueError, KeyError, TypeError) as exc:
        return {"ok": False, "error": str(exc), "protocol": PROTOCOL, "complete": False, "locked": lock is not None}


def _append_checked(ledger: Any, prepared: PreparedRun, event: str, payload: dict) -> dict:
    """Single-writer append: reject stale handles and verify the persisted head."""
    from smallestlie.ledger.verify import verify_ledger
    before = verify_ledger(ledger.path, required_protocol=PROTOCOL, expected_lock=prepared.lock())
    if (not before["ok"] or ledger._seq != before["entries_checked"]
            or ledger._prev_digest != (before["head_digest"] or "0" * 64)):
        raise PreregistrationError("formal append requires a current single-writer ledger handle")
    entry = ledger.append(event, payload)
    after = verify_ledger(ledger.path, required_protocol=PROTOCOL, expected_lock=prepared.lock())
    if not after["ok"] or after["head_digest"] != entry["entry_digest"]:
        raise PreregistrationError("formal append was not persisted as the valid current head")
    return entry


def persist_preregistration_lock(ledger: Any, prepared: PreparedRun) -> dict:
    from smallestlie.ledger.verify import verify_ledger
    chain = verify_ledger(ledger.path, required_protocol=PROTOCOL, expected_lock=prepared.lock())
    if not chain["ok"]:
        raise PreregistrationError("cannot append a lock to an invalid ledger")
    entries = ledger.read_entries()
    result = verify_m12_protocol(entries, expected_lock=prepared.lock())
    if not result["ok"] or result["locked"] or not any(entry["event_type"] == "policy_validated" for entry in entries):
        raise PreregistrationError("ledger is not ready for a unique preregistration lock")
    return _append_checked(ledger, prepared, "preregistration_locked", prepared.lock())


def require_locked_run(ledger: Any, prepared: PreparedRun, case_id: str, *, action: str) -> dict:
    """Reserve one formal action durably before Slice D invokes any external work.

    Requires a single writer. A reservation is not retried after crashes; a new
    bounded request is required instead of reusing this case's action identity.
    """
    from smallestlie.ledger.verify import verify_ledger
    result = verify_ledger(ledger.path, required_protocol=PROTOCOL, expected_lock=prepared.lock())
    if (not result["ok"] or not result["locked"] or result["complete"]
            or case_id in result["terminal_cases"]):
        raise PreregistrationError("formal execution requires the persisted current lock and an open case")
    binding = case_binding(prepared.lock(), case_id)
    state = result["action_states"].get(case_id, _new_state())
    if any(entry["event_type"] in RECEIPTS and entry["payload"]["binding"]["case_id"] == case_id
           for entry in ledger.read_entries()):
        raise PreregistrationError("formal action after receipt disposition")
    _require_action(state, action)
    _append_checked(ledger, prepared, "formal_action_started", {"binding": binding, "action": action})
    return binding
