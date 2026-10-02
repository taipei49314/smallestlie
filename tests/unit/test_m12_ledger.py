from copy import deepcopy

import pytest

from m12_helpers import prepared
from smallestlie.campaign.preregistration import PROTOCOL, PreregistrationError, canonical_digest, case_binding
from smallestlie.ledger.chain import Ledger
from smallestlie.ledger.protocol import campaign_declaration, persist_preregistration_lock, require_locked_run
from smallestlie.ledger.verify import verify_ledger


def start(tmp_path, plan, *, locked=True):
    ledger = Ledger(tmp_path / "ledger.jsonl")
    ledger.append("campaign_created", campaign_declaration(plan))
    ledger.append("policy_validated", {"ok": True})
    if locked:
        persist_preregistration_lock(ledger, plan)
    return ledger


def missing_case(ledger, plan, cid, *, forged_attack="unknown"):
    binding = case_binding(plan.lock(), cid)
    ledger.append("runner_receipt_missing", {"binding": binding, "receipt_sha256": None,
        "validation_sha256": "a" * 64, "provenance_ref": None, "reasons": ["receipt_missing"]})
    twin = "unknown" if plan.binding(cid)["twin_case_id"] else None
    reasons = {"attack": ["receipt_missing"], "twin": ["receipt_missing"] if twin else []}
    assessment = {"case_id": cid, "attack": forged_attack, "twin": twin,
                  "attack_reasons": reasons["attack"], "twin_reasons": reasons["twin"]}
    ledger.append("effectiveness_assessed", {"binding": binding, "attack": forged_attack, "twin": twin,
        "reasons": reasons, "assessment_sha256": canonical_digest(assessment)})


def summary(plan):
    cases = plan.lock()["cases"]
    size = len(cases)
    return {"protocol": PROTOCOL, "lock_digest": plan.lock()["lock_digest"], "counts": {
        "declared_case_count": size,
        "preregistered_classes": {key: sum(case["preregistered_class"] == key for case in cases) for key in ("CTL", "DEF", "BND", "RES")},
        "receipts": {"verified": 0, "rejected": 0, "missing": size},
        "attack_effectiveness": {"confirmed": 0, "refuted": 0, "unknown": size},
        "twin_effectiveness": {"confirmed": 0, "refuted": 0, "unknown": sum(case["twin_case_id"] is not None for case in cases),
                               "not_applicable": sum(case["twin_case_id"] is None for case in cases)}}}


def test_finalized_missing_receipts_preserve_all_preregistered_cases(tmp_path):
    plan = prepared(tmp_path / "design", twin=True)
    ledger = start(tmp_path, plan)
    for cid in ("D", "C"):
        missing_case(ledger, plan, cid)
    ledger.append("campaign_summary", summary(plan))
    result = verify_ledger(ledger.path, required_protocol=PROTOCOL, expected_lock=plan.lock())
    assert result["ok"] and result["complete"]
    assert result["counts"]["preregistered_classes"] == {"DEF": 1, "CTL": 1, "BND": 0, "RES": 0}
    with pytest.raises(PreregistrationError):
        require_locked_run(ledger, plan, "D", action="workspace_create")


def test_valid_partial_ledger_does_not_claim_completion(tmp_path):
    plan = prepared(tmp_path / "design")
    ledger = start(tmp_path, plan)
    result = verify_ledger(ledger.path, expected_lock=plan.lock())
    assert result["ok"] and not result["complete"]
    assert require_locked_run(ledger, plan, "B", action="workspace_create")["case_id"] == "B"


def test_guard_stops_before_callback_without_persisted_lock(tmp_path):
    plan = prepared(tmp_path / "design")
    ledger = start(tmp_path, plan, locked=False)
    invoked = []
    with pytest.raises(PreregistrationError):
        require_locked_run(ledger, plan, "B", action="workspace_create")
        invoked.append("would execute")
    assert invoked == []


def workspace(ledger, plan, *, prepare=False, mutate=False):
    binding = require_locked_run(ledger, plan, "B", action="workspace_create")
    ledger.append("mutant_created", {"binding": binding, "stage": "created"})
    if prepare:
        require_locked_run(ledger, plan, "B", action="workspace_prepare")
        ledger.append("mutant_created", {"binding": binding, "stage": "prepared"})
    if mutate:
        require_locked_run(ledger, plan, "B", action="mutation_apply")
        ledger.append("mutation_applied", {"binding": binding})
    return binding


@pytest.mark.parametrize("kind", ["missing_mutation", "duplicate_mutation", "second_creation", "unreserved_command"])
def test_formal_workspace_and_command_stages_cannot_be_skipped_or_duplicated(tmp_path, kind):
    plan = prepared(tmp_path / "design")
    ledger = start(tmp_path, plan)
    binding = workspace(ledger, plan, mutate=kind in {"duplicate_mutation", "unreserved_command"})
    if kind == "missing_mutation":
        ledger.append("formal_action_started", {"binding": binding, "action": "verifier_command"})
    elif kind == "duplicate_mutation":
        ledger.append("mutation_applied", {"binding": binding})
    elif kind == "second_creation":
        require_locked_run(ledger, plan, "B", action="workspace_prepare")
        ledger.append("mutant_created", {"binding": binding, "stage": "created"})
    else:
        ledger.append("command_executed", {"binding": binding})
    result = verify_ledger(ledger.path, expected_lock=plan.lock())
    assert result["chain_ok"] and not result["protocol_ok"]


@pytest.mark.parametrize("kind", ["workspace", "pending_command", "completed_command", "stopped", "receipt"])
def test_guard_reserves_once_and_stops_before_repeated_callback(tmp_path, kind):
    plan = prepared(tmp_path / "design")
    ledger = start(tmp_path, plan)
    binding = workspace(ledger, plan, prepare=True, mutate=kind != "workspace")
    action = "workspace_create" if kind == "workspace" else "verifier_command"
    if kind in {"pending_command", "completed_command"}:
        require_locked_run(ledger, plan, "B", action=action)
        if kind == "completed_command":
            ledger.append("command_executed", {"binding": binding})
    elif kind == "stopped":
        ledger.append("harness_error", {"binding": binding, "error": "synthetic error"})
    elif kind == "receipt":
        ledger.append("runner_receipt_missing", {"binding": binding, "receipt_sha256": None,
            "validation_sha256": "a" * 64, "provenance_ref": None, "reasons": ["receipt_missing"]})
    invoked = []
    with pytest.raises(PreregistrationError):
        require_locked_run(ledger, plan, "B", action=action)
        invoked.append("would execute")
    assert invoked == []


def test_complete_reserved_verifier_observation_is_a_valid_partial_run(tmp_path):
    plan = prepared(tmp_path / "design")
    ledger = start(tmp_path, plan)
    binding = workspace(ledger, plan, prepare=True, mutate=True)
    require_locked_run(ledger, plan, "B", action="verifier_command")
    for event in ("command_executed", "target_verdict_parsed", "oracle_evaluated", "comparator_result"):
        ledger.append(event, {"binding": binding})
    result = verify_ledger(ledger.path, expected_lock=plan.lock())
    assert result["ok"] and not result["complete"]


@pytest.mark.parametrize("operation", ["lock", "action"])
def test_stale_writer_cannot_claim_persistence_or_start_external_work(tmp_path, operation):
    plan = prepared(tmp_path / "design")
    stale = Ledger(tmp_path / "ledger.jsonl")
    current = start(tmp_path, plan, locked=operation == "action")
    head = current._prev_digest
    invoked = []
    with pytest.raises(PreregistrationError, match="single-writer"):
        if operation == "lock":
            persist_preregistration_lock(stale, plan)
        else:
            require_locked_run(stale, plan, "B", action="workspace_create")
        invoked.append("would execute")
    assert invoked == []
    assert verify_ledger(current.path, expected_lock=plan.lock())["head_digest"] == head


@pytest.mark.parametrize("kind", ["before_lock", "duplicate_lock", "binding", "missing_confirmed", "missing_refuted", "summary_drops_case", "summary_lies", "post_summary"])
def test_chain_valid_but_protocol_invalid_cannot_be_promoted(tmp_path, kind):
    plan = prepared(tmp_path / "design", twin=True)
    ledger = start(tmp_path, plan, locked=kind != "before_lock")
    if kind == "before_lock":
        ledger.append("mutant_created", {"binding": case_binding(plan.lock(), "D")})
    elif kind == "duplicate_lock":
        ledger.append("preregistration_locked", plan.lock())
    elif kind == "binding":
        binding = case_binding(plan.lock(), "D")
        binding["profile_sha256"] = "f" * 64
        ledger.append("mutant_created", {"binding": binding})
    elif kind in {"missing_confirmed", "missing_refuted"}:
        missing_case(ledger, plan, "D", forged_attack=kind.split("_")[1])
    else:
        missing_case(ledger, plan, "D")
        if kind != "summary_drops_case":
            missing_case(ledger, plan, "C")
        data = summary(plan)
        if kind == "summary_lies":
            data["counts"]["declared_case_count"] = True
        ledger.append("campaign_summary", data)
        if kind == "post_summary":
            ledger.append("mutant_created", {"binding": case_binding(plan.lock(), "D")})
    result = verify_ledger(ledger.path, expected_lock=plan.lock())
    assert result["chain_ok"] and not result["protocol_ok"]


def test_externally_expected_lock_detects_a_coherently_rewritten_lock(tmp_path):
    plan = prepared(tmp_path / "design")
    ledger = start(tmp_path, plan, locked=False)
    rewritten = deepcopy(plan.lock())
    rewritten["cases"][0]["profile_sha256"] = "f" * 64
    rewritten["lock_digest"] = canonical_digest({key: value for key, value in rewritten.items() if key != "lock_digest"})
    ledger.append("preregistration_locked", rewritten)
    assert not verify_ledger(ledger.path, expected_lock=plan.lock())["ok"]


def test_m12_events_cannot_be_silently_treated_as_legacy(tmp_path):
    ledger = Ledger(tmp_path / "ledger.jsonl")
    ledger.append("runner_receipt_missing", {"reason": "no protocol"})
    assert not verify_ledger(ledger.path)["ok"]


def test_legacy_order_and_result_format_remain_unchanged(tmp_path):
    ledger = Ledger(tmp_path / "ledger.jsonl")
    ledger.append("policy_validated", {"ok": True})
    ledger.append("campaign_created", {"id": "legacy"})
    result = verify_ledger(ledger.path)
    assert result["ok"] and set(result) == {"ok", "error", "entries_checked", "head_digest"}
    assert not verify_ledger(ledger.path, required_protocol=PROTOCOL)["ok"]
