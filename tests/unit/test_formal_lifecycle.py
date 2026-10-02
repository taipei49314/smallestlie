"""Synthetic lifecycle/authority contracts; no real collector or W3 approval."""

from copy import deepcopy
from dataclasses import replace
import json
import os

import pytest

from m12_helpers import ApprovalAuthority, CaptureAuthority, capture, prepared
from test_adjudication import SyntheticAuthority, add_reviews, finding, verifier_capture
from smallestlie.adjudication.engine import CaseInputs
from smallestlie.campaign.lifecycle import (
    COMPLETION_SCHEMA, ArtifactStore, FormalLifecycle, TrustedActionCompletion,
    encoded, output_roles, verify_formal_lifecycle,
)
from smallestlie.campaign.preregistration import PreregistrationError, canonical_digest, case_binding, digest
from smallestlie.ledger.chain import Ledger
from smallestlie.ledger.lifecycle import PROTOCOL, action_key, slots
from smallestlie.ledger.verify import verify_ledger


@pytest.fixture(scope="module")
def plan(tmp_path_factory):
    return prepared(tmp_path_factory.mktemp("lifecycle-design"), twin=True)


def policy(plan):
    lock = plan.lock()
    return encoded({"schema_version": "smallestlie.lifecycle-policy/v1", "ok": True,
                    "request_sha256": lock["request_sha256"], "authorization_ref": lock["authorization_ref"],
                    "provider_id": lock["approval_provider"]})


class CompletionSource:
    """Explicit external fixture grants, not a provider that trusts input JSON."""
    def __init__(self):
        self.grants, self.calls = {}, []

    def verify(self, plan, ticket, completion_sha):
        key = canonical_digest(ticket.to_dict()), completion_sha
        self.calls.append(key)
        return self.grants.get(key)


class CountedSource(SyntheticAuthority):
    def __init__(self, envelopes):
        super().__init__(envelopes)
        self.calls = []

    def verify(self, plan, cid, raw_sha):
        self.calls.append((cid, raw_sha))
        return super().verify(plan, cid, raw_sha)


def begin(tmp_path, plan, *, source=None, runner=None, verifier=None):
    source = source if source is not None else CompletionSource()
    return FormalLifecycle.begin(plan, tmp_path / "recording", policy_bytes=policy(plan),
        completion_authority=source, runner_authority=runner, verifier_authority=verifier)


def finish_action(session, ticket, *, outputs=None, code=0, status="completed", change=None, grant=True):
    context = session.plan[action_key(ticket.case_id, ticket.kind, ticket.arm)]
    sources = {"publication": b"synthetic external publication\r\n", "supervisor": b"synthetic new collector proof\n"}
    outputs = outputs if outputs is not None else {role: b"synthetic raw output" for role in output_roles(ticket.kind)}
    raw = {"schema_version": COMPLETION_SCHEMA, "binding": context["binding"], "reservation": ticket.to_dict(),
           "context_sha256": ticket.context_sha256, "files": deepcopy(context["files"]),
           "termination_kind": status, "exit_code": code, "output_complete": status != "output_incomplete",
           "descendants_reaped": True, "outputs": {key: digest(value) if value is not None else None for key, value in outputs.items()},
           "publication_sha256": digest(sources["publication"]), "supervisor_sha256": digest(sources["supervisor"])}
    if change:
        change(raw)
    data = encoded(raw)
    approval = TrustedActionCompletion("synthetic-new-collector", "c" * 40 if ticket.kind.startswith("verifier_") else "a" * 40,
        "synthetic independent collector-v2 acceptance", canonical_digest(ticket.to_dict()), digest(data),
        raw["context_sha256"], canonical_digest(raw["files"]), raw["termination_kind"], raw["exit_code"],
        raw["output_complete"], raw["descendants_reaped"], canonical_digest(raw["outputs"]),
        raw["publication_sha256"], raw["supervisor_sha256"])
    if grant and session.completion_authority is not None:
        session.completion_authority.grants[canonical_digest(ticket.to_dict()), digest(data)] = approval
    return session.complete_action(ticket, data, sources=sources, outputs=outputs)


def observations(plan, *, states=None, invalid_stdout=False):
    items, runners, verifiers = {}, {}, {}
    for cid in ("D", "C"):
        receipt, artifacts = capture(plan, cid, states=(states or {}).get(cid))
        if invalid_stdout and cid == "D":
            path = receipt["arms"]["attack"]["stdout"]["path"]
            artifacts[path] = b"\xff\r\n\x00"
            receipt["arms"]["attack"]["stdout"]["sha256"] = digest(artifacts[path])
        runners[cid] = CaptureAuthority(plan, cid, receipt).envelope
        metadata, stdout, stderr, envelope = verifier_capture(plan, cid, [finding()] if cid == "C" else [])
        verifiers[cid] = envelope
        items[cid] = CaseInputs(encoded(receipt), artifacts, metadata, stdout, stderr)
    return items, CountedSource(runners), CountedSource(verifiers)


def complete_all(session, items, runners, verifiers, *, skip=()):
    tickets = {}
    for cid, kind, arm in slots(session.prepared.lock()):
        if (cid, kind, arm) in skip:
            continue
        ticket = session.reserve_action(cid, kind=kind, arm=arm)
        tickets[cid, kind, arm] = ticket
        outputs, code = {}, 0
        if kind == "runner_command":
            record = json.loads(items[cid].runner_receipt)["arms"][arm]
            outputs = {role: items[cid].runner_artifacts[record[role]["path"]] for role in output_roles(kind)}
            code = record["exit_code"]
        elif kind == "verifier_command":
            raw = items[cid]
            outputs = {"metadata": raw.verifier_metadata, "stdout": raw.verifier_stdout, "stderr": raw.verifier_stderr}
            code = verifiers.envelopes[cid].exit_code
        assert finish_action(session, ticket, outputs=outputs, code=code).valid
    for cid in items:
        first = min(ticket.seq for (key, kind, arm), ticket in tickets.items() if key == cid and kind == "runner_command")
        runners.envelopes[cid] = replace(runners.envelopes[cid], lock_sequence=3, first_command_sequence=first)
        verifiers.envelopes[cid] = replace(verifiers.envelopes[cid], lock_sequence=3,
            command_sequence=tickets[cid, "verifier_command", "attack"].seq)
    return tickets


def sealed_reviews(session, items, runners, verifiers):
    entry = next(entry for entry in session.ledger.read_entries() if entry["event_type"] == "observations_sealed")
    index = json.loads(session.artifacts.read(entry["payload"]["index"]))
    refs = {case["binding"]["case_id"]: {
        "runner_validation_sha256": case["validations"]["runner"]["sha256"],
        "verifier_validation_sha256": case["validations"]["verifier"]["sha256"]} for case in index["cases"]}
    def bind(cid, review):
        review["observations"] = {key: refs[key] for key in review["observations"]}
    return add_reviews(session.prepared, items, runners, verifiers, change=bind)


def finalized(tmp_path, plan, *, states=None, invalid_stdout=False):
    items, ra, va = observations(plan, states=states, invalid_stdout=invalid_stdout)
    session = begin(tmp_path, plan, runner=ra, verifier=va)
    tickets = complete_all(session, items, ra, va)
    snapshot = session.seal_observations(items)
    reviews = sealed_reviews(session, items, ra, va)
    report = session.finalize(snapshot, {cid: raw.review for cid, raw in items.items()}, review_authority=reviews)
    return session, snapshot, report, tickets, ra, va, reviews


def verify(session, ra=None, va=None, reviews=None, *, prereg=True, completions=True):
    return verify_formal_lifecycle(session.prepared, session.ledger.path,
        preregistration_authority=ApprovalAuthority(session.prepared.request) if prereg else None,
        completion_authority=session.completion_authority if completions else None,
        runner_authority=ra, verifier_authority=va, review_authority=reviews)


def rewrite_tail(ledger, index, payloads):
    entries = ledger.read_entries()
    ledger.path.write_bytes(b"".join(encoded(entry) + b"\n" for entry in entries[:index]))
    current = Ledger(ledger.path)
    for entry in entries[index:]:
        current.append(entry["event_type"], payloads.get(entry["seq"], entry["payload"]))


def test_complete_pair_revalidates_raw_artifacts_and_each_own_action(tmp_path, plan):
    session, snapshot, report, tickets, ra, va, reviews = finalized(tmp_path, plan, invalid_stdout=True)
    assert report["frozen_case_count"] == 2 and report["paired_defect_case_count"] == 1
    assert report["cases"][1]["verifier"]["findings"][0] == finding()
    assert tickets["D", "runner_command", "twin"] != tickets["C", "runner_command", "attack"]
    assert tickets["D", "runner_materialize", "twin"] != tickets["C", "runner_materialize", "attack"]
    assert verify(session, ra, va, reviews)["ok"]
    index_entry = next(entry for entry in session.ledger.read_entries() if entry["event_type"] == "observations_sealed")
    index = json.loads(session.artifacts.read(index_entry["payload"]["index"]))
    raw = next(case for case in index["cases"] if case["binding"]["case_id"] == "D")
    assert session.artifacts.read(raw["captures"]["runner.attack.stdout"]) == b"\xff\r\n\x00"


def test_true_effectiveness_refutation_stays_killed_in_final_rows(tmp_path, plan):
    states = {"D": {"baseline": "green", "attack": "skip", "repair": "green", "twin": "skip"}}
    session, _, report, _, ra, va, reviews = finalized(tmp_path, plan, states=states)
    assert report["cases"][0]["verdict"] == "killed_candidate"
    assert report["paired_defect_case_count"] == report["confirmed_defect_case_count"] == 0
    assert verify(session, ra, va, reviews)["ok"]


@pytest.mark.parametrize("baseline,attack,reason", [
    ("green", "skip", "baseline_target_already_green"),
    ("red", "red", "changed_target_assertion_still_red"),
])
def test_proven_refutation_survives_unrelated_missing_twin_and_repair(tmp_path, plan, baseline, attack, reason):
    items, ra, va = observations(plan, states={"D": {"baseline": baseline, "attack": attack, "repair": "green", "twin": "skip"}})
    session = begin(tmp_path, plan, runner=ra, verifier=va)
    skip = {("D", kind, arm) for arm in ("twin", "repair") for kind in ("runner_materialize", "runner_command")}
    complete_all(session, items, ra, va, skip=skip)
    snapshot = session.seal_observations(items)
    reviews = sealed_reviews(session, items, ra, va)
    report = session.finalize(snapshot, {cid: raw.review for cid, raw in items.items()}, review_authority=reviews)
    row = report["cases"][0]
    assert row["verdict"] == "killed_candidate" and reason in row["reasons"]
    assert report["paired_defect_case_count"] == report["confirmed_defect_case_count"] == 0
    result = verify(session, ra, va, reviews)
    assert result["artifact_ok"] and result["semantic_ok"] and not result["authority_ok"]


@pytest.mark.parametrize("damage", ["pre_lock", "wrong_first", "duplicate", "undeclared", "bool_exit"])
def test_partial_arm_filter_cannot_clean_bad_original_execution_envelope(tmp_path, plan, damage):
    items, ra, va = observations(plan, states={"D": {"baseline": "green", "attack": "skip", "repair": "green", "twin": "skip"}})
    session = begin(tmp_path, plan, runner=ra, verifier=va)
    skip = {("D", kind, arm) for arm in ("twin", "repair") for kind in ("runner_materialize", "runner_command")}
    complete_all(session, items, ra, va, skip=skip)
    original = ra.envelopes["D"]
    if damage in {"pre_lock", "wrong_first"}:
        ra.envelopes["D"] = replace(original, first_command_sequence=1 if damage == "pre_lock" else original.first_command_sequence + 1)
    elif damage == "duplicate":
        ra.envelopes["D"] = replace(original, arm_exits=original.arm_exits + (original.arm_exits[0],))
    elif damage == "undeclared":
        ra.envelopes["D"] = replace(original, arm_exits=original.arm_exits + (("other", "completed", 0),))
    else:
        ra.envelopes["D"] = replace(original, arm_exits=tuple((arm, kind, True if arm == "repair" else code)
                                                            for arm, kind, code in original.arm_exits))
    snapshot = session.seal_observations(items)
    report = session.finalize(snapshot, {})
    assert report["cases"][0]["verdict"] == "unknown" and report["paired_defect_case_count"] == 0


def test_unobserved_earlier_command_cannot_hide_a_later_proven_refutation(tmp_path, plan):
    items, ra, va = observations(plan, states={"D": {"baseline": "green", "attack": "skip", "repair": "green", "twin": "skip"}})
    session = begin(tmp_path, plan, runner=ra, verifier=va)
    materialize = session.reserve_action("D", kind="runner_materialize", arm="attack")
    assert finish_action(session, materialize).valid
    pending = session.reserve_action("D", kind="runner_command", arm="attack")
    skip = {("D", kind, arm) for arm in ("attack", "twin", "repair") for kind in ("runner_materialize", "runner_command")}
    tickets = complete_all(session, items, ra, va, skip=skip)
    original = ra.envelopes["D"]
    ra.envelopes["D"] = replace(original, arm_exits=tuple(value for value in original.arm_exits if value[0] != "attack"))
    assert pending.seq < tickets["D", "runner_command", "baseline"].seq
    snapshot = session.seal_observations(items)
    reviews = sealed_reviews(session, items, ra, va)
    report = session.finalize(snapshot, {cid: raw.review for cid, raw in items.items()}, review_authority=reviews)
    assert report["cases"][0]["verdict"] == "killed_candidate"
    result = verify(session, ra, va, reviews)
    assert result["semantic_ok"] and not result["authority_ok"]


def test_missing_repair_cannot_confirm_or_kill_an_effective_looking_attack(tmp_path, plan):
    items, ra, va = observations(plan)
    session = begin(tmp_path, plan, runner=ra, verifier=va)
    complete_all(session, items, ra, va, skip={("D", kind, "repair") for kind in ("runner_materialize", "runner_command")})
    snapshot = session.seal_observations(items)
    reviews = sealed_reviews(session, items, ra, va)
    report = session.finalize(snapshot, {cid: raw.review for cid, raw in items.items()}, review_authority=reviews)
    assert report["cases"][0]["verdict"] == "unknown" and report["paired_defect_case_count"] == 0


def test_recording_missing_and_pending_slots_preserves_denominator_and_unknown(tmp_path, plan):
    session = begin(tmp_path, plan)
    ticket = session.reserve_action("D", kind="runner_materialize", arm="baseline")
    snapshot = session.seal_observations({})
    report = session.finalize(snapshot, {})
    chain = verify_ledger(session.ledger.path, required_protocol=PROTOCOL, expected_lock=plan.lock())
    assert chain["ok"] and chain["complete"] and report["frozen_case_count"] == 2
    states = chain["action_states"]
    assert len(states) == len(slots(plan.lock()))
    assert states[action_key("D", "runner_materialize", "baseline")]["disposition"]["status"] == "completion_missing"
    assert states[action_key("D", "runner_command", "baseline")]["disposition"]["status"] == "not_run"
    assert all(row["verdict"] == "unknown" for row in report["cases"])
    result = verify(session)
    assert result["artifact_ok"] and result["semantic_ok"] and not result["authority_ok"] and not result["ok"]
    with pytest.raises(PreregistrationError):
        session.reserve_action(ticket.case_id, kind=ticket.kind, arm=ticket.arm)


@pytest.mark.parametrize("failure", ["timeout", "spawn_error", "signal", "quota", "output_incomplete", "internal_error"])
def test_observed_incomplete_dispositions_cannot_release_command_prerequisite(tmp_path, plan, failure):
    session = begin(tmp_path, plan)
    ticket = session.reserve_action("D", kind="runner_materialize", arm="baseline")
    value = finish_action(session, ticket, status=failure, code=None,
                          change=lambda raw: raw["files"].update(baseline={}))
    assert value.valid and value.status == failure
    with pytest.raises(PreregistrationError, match="completed materialization"):
        session.reserve_action("D", kind="runner_command", arm="baseline")
    snapshot = session.seal_observations({})
    assert all(row["verdict"] == "unknown" for row in session.finalize(snapshot, {})["cases"])


@pytest.mark.parametrize("damage", ["seq", "entry", "case", "context", "files", "bool_exit", "outputs", "old_schema"])
def test_even_a_matching_synthetic_grant_cannot_authorize_misbound_completion(tmp_path, plan, damage):
    session = begin(tmp_path, plan)
    ticket = session.reserve_action("D", kind="runner_materialize", arm="baseline")
    def change(raw):
        if damage == "seq":
            raw["reservation"]["seq"] += 1
        elif damage == "entry":
            raw["reservation"]["entry_digest"] = "f" * 64
        elif damage == "case":
            raw["binding"] = case_binding(plan.lock(), "C")
        elif damage == "context":
            raw["context_sha256"] = "f" * 64
        elif damage == "files":
            raw["files"]["baseline"]["src/billing.py"] = "f" * 64
        elif damage == "bool_exit":
            raw["exit_code"] = True
        elif damage == "outputs":
            raw["outputs"] = {"report": "f" * 64}
        else:
            raw["schema_version"] = "smallestlie.outer-supervisor/v1"
    value = finish_action(session, ticket, change=change)
    assert not value.valid and value.status == "completion_rejected"
    with pytest.raises(PreregistrationError):
        session.reserve_action("D", kind="runner_materialize", arm="baseline")
    with pytest.raises(PreregistrationError):
        session.reserve_action("D", kind="runner_command", arm="baseline")


def test_plain_raw_completion_and_old_authorities_cannot_bridge_reservations(tmp_path, plan):
    items, ra, va = observations(plan)
    session = begin(tmp_path, plan, runner=ra, verifier=va)
    ticket = session.reserve_action("D", kind="runner_materialize", arm="baseline")
    assert not finish_action(session, ticket, grant=False).valid
    snapshot = session.seal_observations(items)
    reviews = sealed_reviews(session, items, ra, va)
    report = session.finalize(snapshot, {cid: item.review for cid, item in items.items()}, review_authority=reviews)
    assert all(row["verdict"] == "unknown" for row in report["cases"])
    assert report["paired_defect_case_count"] == 0
    result = verify(session, ra, va, reviews)
    assert result["semantic_ok"] and not result["authority_ok"] and not result["ok"]


def test_fsync_failure_never_returns_ticket_and_reservation_cannot_retry(tmp_path, plan, monkeypatch):
    session = begin(tmp_path, plan)
    returned = []
    def failing(fd):
        raise OSError("synthetic disk sync failure")
    with monkeypatch.context() as patch:
        patch.setattr(os, "fsync", failing)
        with pytest.raises(OSError, match="disk sync failure"):
            returned.append(session.reserve_action("D", kind="runner_materialize", arm="baseline"))
    assert returned == []
    with pytest.raises(PreregistrationError, match="already reserved"):
        session.reserve_action("D", kind="runner_materialize", arm="baseline")
    snapshot = session.seal_observations({})
    session.finalize(snapshot, {})
    states = verify_ledger(session.ledger.path)["action_states"]
    assert states[action_key("D", "runner_materialize", "baseline")]["disposition"]["status"] == "completion_missing"


def test_existing_artifact_cannot_bypass_a_previous_or_current_fsync_failure(tmp_path, monkeypatch):
    store = ArtifactStore(tmp_path / "artifacts")
    data = b"raw bytes left after failed sync"
    calls = []
    def failing(fd):
        calls.append(fd)
        raise OSError("synthetic artifact sync failure")
    with monkeypatch.context() as patch:
        patch.setattr(os, "fsync", failing)
        for _ in range(2):
            with pytest.raises(OSError, match="artifact sync failure"):
                store.put(data)
    assert len(calls) == 2
    assert store.read(store.put(data)) == data


@pytest.mark.parametrize("role", ["completion", "publication", "supervisor", "auxiliary", "policy"])
@pytest.mark.parametrize("damage", ["delete", "replace"])
def test_finalize_reads_all_sealed_sources_before_any_review_event(tmp_path, plan, role, damage):
    items, ra, va = observations(plan)
    items["D"].runner_artifacts["auxiliary/raw.txt"] = b"raw auxiliary source not used by a capture"
    session = begin(tmp_path, plan, runner=ra, verifier=va)
    complete_all(session, items, ra, va)
    snapshot = session.seal_observations(items)
    entries = session.ledger.read_entries()
    index = json.loads(session.artifacts.read(entries[-1]["payload"]["index"]))
    action = index["actions"][action_key("D", "runner_command", "attack")]
    ref = (action["completion"] if role == "completion" else
           action["sources"][role] if role in {"publication", "supervisor"} else
           index["cases"][0]["runner_artifacts"]["auxiliary/raw.txt"] if role == "auxiliary" else
           entries[1]["payload"]["artifact"])
    path = session.artifacts.root / ref["sha256"]
    if damage == "delete":
        path.unlink()
    else:
        path.write_bytes(b"changed after seal")
    with pytest.raises((PreregistrationError, OSError)):
        session.finalize(snapshot, {})
    assert session.ledger.read_entries() == entries
    assert not any(entry["event_type"] in {"review_disposed", "case_adjudicated", "campaign_summary"} for entry in entries)


def test_stale_writer_stops_before_reserving_work(tmp_path, plan):
    session = begin(tmp_path, plan)
    stale = FormalLifecycle(plan, Ledger(session.ledger.path), session.artifacts)
    ticket = session.reserve_action("D", kind="runner_materialize", arm="baseline")
    with pytest.raises(PreregistrationError, match="single-writer"):
        stale.reserve_action("C", kind="runner_materialize", arm="baseline")
    assert verify_ledger(session.ledger.path)["head_digest"] == ticket.entry_digest


def test_review_before_seal_duplicate_seal_and_second_finalization_fail(tmp_path, plan):
    session = begin(tmp_path, plan)
    with pytest.raises(PreregistrationError, match="without a pre-seal review"):
        session.seal_observations({"D": CaseInputs(review=b"premature")})
    snapshot = session.seal_observations({})
    with pytest.raises(PreregistrationError, match="duplicate seal"):
        session.seal_observations({})
    session.finalize(snapshot, {})
    with pytest.raises(PreregistrationError):
        session.finalize(snapshot, {})


def test_capture_substitution_cannot_borrow_a_valid_command_output(tmp_path, plan):
    items, ra, va = observations(plan)
    session = begin(tmp_path, plan, runner=ra, verifier=va)
    complete_all(session, items, ra, va)
    items["D"] = replace(items["D"], verifier_stdout=items["C"].verifier_stdout)
    snapshot = session.seal_observations(items)
    reviews = sealed_reviews(session, items, ra, va)
    report = session.finalize(snapshot, {cid: item.review for cid, item in items.items()}, review_authority=reviews)
    assert report["cases"][0]["verdict"] == "unknown" and report["paired_defect_case_count"] == 0
    result = verify(session, ra, va, reviews)
    assert result["semantic_ok"] and not result["authority_ok"]


@pytest.mark.parametrize("missing", ["preregistration", "completion", "runner", "verifier", "review"])
def test_complete_ledger_cannot_authorize_itself_on_evidence_reverification(tmp_path, plan, missing):
    session, _, _, _, ra, va, reviews = finalized(tmp_path, plan)
    result = verify(session, None if missing == "runner" else ra, None if missing == "verifier" else va,
                    None if missing == "review" else reviews, prereg=missing != "preregistration", completions=missing != "completion")
    assert result["chain_ok"] and result["protocol_ok"] and result["complete"] and result["artifact_ok"]
    assert not result["authority_ok"] and not result["ok"]


def test_read_only_verification_never_creates_or_replaces_artifacts(tmp_path, plan, monkeypatch):
    session, _, _, _, ra, va, reviews = finalized(tmp_path, plan)
    def forbidden(*args, **kwargs):
        raise AssertionError("verification attempted to write evidence")
    monkeypatch.setattr(ArtifactStore, "put", forbidden)
    assert verify(session, ra, va, reviews)["ok"]


def test_raw_artifact_replacement_fails_beyond_a_valid_complete_hash_chain(tmp_path, plan):
    session, _, _, _, ra, va, reviews = finalized(tmp_path, plan)
    sealed = next(entry["payload"] for entry in session.ledger.read_entries() if entry["event_type"] == "observations_sealed")
    index = json.loads(session.artifacts.read(sealed["index"]))
    ref = index["cases"][0]["captures"]["runner.attack.report"]
    (session.artifacts.root / ref["sha256"]).write_bytes(b"replacement raw report")
    assert verify_ledger(session.ledger.path)["ok"]
    result = verify(session, ra, va, reviews)
    assert result["chain_ok"] and result["protocol_ok"] and not result["artifact_ok"] and not result["ok"]


def test_coherent_new_row_and_report_hashes_still_require_semantic_reverification(tmp_path, plan):
    session, _, report, _, ra, va, reviews = finalized(tmp_path, plan)
    entries = session.ledger.read_entries()
    target = next(index for index, entry in enumerate(entries) if entry["event_type"] == "case_adjudicated")
    payload = deepcopy(entries[target]["payload"])
    fake_row = deepcopy(report["cases"][0])
    fake_row["reasons"] = ["fabricated reviewed result"]
    payload["row"] = session.artifacts.put(encoded(fake_row))
    fake_report = deepcopy(report)
    fake_report["cases"][0] = fake_row
    summary = deepcopy(entries[-1]["payload"])
    summary["report"] = session.artifacts.put(encoded(fake_report))
    rewrite_tail(session.ledger, target, {entries[target]["seq"]: payload, entries[-1]["seq"]: summary})
    assert verify_ledger(session.ledger.path)["ok"]
    result = verify(session, ra, va, reviews)
    assert result["artifact_ok"] and result["authority_ok"] and not result["semantic_ok"] and not result["ok"]


@pytest.mark.parametrize("damage", ["marker", "denominator", "post_summary"])
def test_lifecycle_cannot_downgrade_or_finalize_an_incomplete_denominator(tmp_path, plan, damage):
    session = begin(tmp_path, plan)
    snapshot = session.seal_observations({})
    session.finalize(snapshot, {})
    entries = session.ledger.read_entries()
    if damage == "marker":
        payload = deepcopy(entries[0]["payload"])
        del payload["protocol"]
        rewrite_tail(session.ledger, 0, {1: payload})
    elif damage == "denominator":
        payload = deepcopy(entries[-1]["payload"])
        payload["counts"]["frozen_case_count"] = 1
        rewrite_tail(session.ledger, len(entries) - 1, {entries[-1]["seq"]: payload})
    else:
        Ledger(session.ledger.path).append("observations_sealed", entries[-1]["payload"])
    result = verify_ledger(session.ledger.path)
    assert result["chain_ok"] and not result["protocol_ok"]


def test_original_lock_protocol_bytes_and_legacy_ledger_remain_unchanged(tmp_path, plan):
    original = plan.lock_bytes
    session = begin(tmp_path, plan)
    wrapper = session.ledger.read_entries()[2]["payload"]
    assert plan.lock_bytes == original and wrapper["lock"]["protocol"] == "smallestlie.m12/v1"
    assert session.ledger.read_entries()[0]["payload"]["protocol"] == PROTOCOL
    legacy = Ledger(tmp_path / "legacy.jsonl")
    legacy.append("campaign_created", {"id": "legacy"})
    legacy.append("policy_validated", {"ok": True})
    result = verify_ledger(legacy.path)
    assert result["ok"] and set(result) == {"ok", "error", "entries_checked", "head_digest"}
