"""Synthetic follow-up/replay contracts; no launcher, admission or publication."""

from dataclasses import replace
import json

import pytest

from multi_dispatch_helpers import (
    approve_reviews, drop_source, ec_context, make_map, make_multi_map,
    multi_map_templates, native_multi, native_templates, plan, report_state,
)
from smallestlie.adjudication.engine import AdjudicationError
from smallestlie.campaign.lifecycle import ArtifactStore, encoded
from smallestlie.campaign.multi_dispatch_recording import record_multi_dispatch_adjudication, verify_multi_dispatch_recording
from smallestlie.campaign.multi_dispatch_review_source import GitHubMultiDispatchReviewAuthority
from smallestlie.campaign.preregistration import PreregistrationError, digest
from smallestlie.ledger.multi_dispatch_recording import journal_entry, read_multi_dispatch_journal


def record(root, bundle, *, reviews=None):
    ctx = bundle["ctx"]
    return record_multi_dispatch_adjudication(root, ctx["plan"], bundle["reviews"] if reviews is None else reviews,
        source_authority=ctx["authority"], review_authority=bundle["review_authority"])


def replay(root, bundle, expected, *, authority=None):
    ctx = bundle["ctx"]
    return verify_multi_dispatch_recording(root, ctx["plan"], expected_journal_sha256=expected,
        source_authority=ctx["authority"],
        review_authority=bundle["review_authority"] if authority is None else authority)


def rewrite(root, mutation):
    """Coherently rehash damage; expected digest alone must not bless semantics."""
    path = root / "journal.jsonl"
    rows = [json.loads(line) for line in path.read_bytes().splitlines()]
    mutation(rows)
    previous, rewritten = "0" * 64, []
    for index, row in enumerate(rows, 1):
        entry = journal_entry(index, row["event"], row["payload"], previous)
        rewritten.append(entry)
        previous = entry["entry_sha256"]
    data = b"".join(encoded(row) + b"\n" for row in rewritten)
    path.write_bytes(data)
    return digest(data)


@pytest.fixture
def reviewed(native_multi):
    return approve_reviews(native_multi())


@pytest.fixture
def recorded(tmp_path, reviewed):
    root = tmp_path / "followup"
    result = record(root, reviewed)
    return root, reviewed, result


def test_record_and_replay_retain_all_raw_reviews_rows_sources_and_immutable_f(recorded):
    root, bundle, result = recorded
    ctx = bundle["ctx"]
    archive = dict(ctx["files"])
    before = len(ctx["api"].calls)
    verified = replay(root, bundle, result.journal_sha256)
    assert verified == result
    assert len(ctx["api"].calls) > before
    assert ctx["files"] == archive
    assert ctx["files"]["archive/ledger.jsonl"].splitlines()[-1].find(b"observations_sealed") >= 0
    rows = read_multi_dispatch_journal((root / "journal.jsonl").read_bytes(), ["D", "C"])
    assert [row["event"] for row in rows] == ["multi_dispatch_recording_started", "multi_dispatch_review_disposed",
        "multi_dispatch_case_adjudicated", "multi_dispatch_review_disposed", "multi_dispatch_case_adjudicated", "multi_dispatch_summary"]
    store = ArtifactStore(root / "artifacts", create=False)
    assert store.read(rows[1]["payload"]["raw_review"]) == bundle["reviews"]["D"]
    assert store.read(rows[3]["payload"]["raw_review"]) == bundle["reviews"]["C"]
    assert json.loads(store.read(rows[-1]["payload"]["report"])) == json.loads(encoded(result.report.to_dict()))
    assert all("journal_sha256" not in json.loads(store.read(row["payload"]["row"])) for row in (rows[2], rows[4]))
    assert rows[0]["payload"]["plan_sha256"] == result.report.snapshot.plan_sha256
    assert rows[0]["payload"]["session_sha256"] == result.report.snapshot.session_sha256
    snapshot = json.loads(store.read(rows[0]["payload"]["snapshot"]))
    assert snapshot["coordinator_journal_sha256"] == result.report.snapshot.coordinator_journal_sha256
    assert snapshot["actions"]
    assert result.report.to_dict()["cases"][1]["observation"]["verifier"]["findings"][0]["future_attachment"] == {"preserved": True}


@pytest.mark.parametrize("role,state", [("baseline", "green"), ("attack", "red")])
def test_killed_def_survives_missing_repair_twin_and_reviews(tmp_path, native_multi, plan, role, state):
    ctx = native_multi(native_change=report_state(plan, role, state))
    for arm in ("repair", "twin"):
        drop_source(ctx, ("D", "runner_command", arm))
    bundle, root = approve_reviews(ctx), tmp_path / "killed"
    result = record(root, bundle, reviews={})
    assert result.report.cases[0].verdict == "killed_candidate"
    assert result.report.to_dict()["frozen_case_count"] == 2
    assert result.report.to_dict()["paired_defect_case_count"] == 0
    assert replay(root, bundle, result.journal_sha256) == result


def test_reviewed_candidate_and_qualified_headline_stay_distinct(tmp_path, native_multi):
    ctx = native_multi()
    drop_source(ctx, ("C", "runner_command", "attack"))
    bundle, root = approve_reviews(ctx), tmp_path / "unqualified"
    result = record(root, bundle)
    report = result.report.to_dict()
    assert report["confirmed_defect_case_count"] == 1
    assert report["paired_defect_case_count"] == 0
    assert replay(root, bundle, result.journal_sha256) == result


def test_missing_source_retains_consumed_ticket_and_claims_in_raw_snapshot(tmp_path, native_multi):
    ctx = native_multi()
    slot = ("D", "runner_command", "attack")
    drop_source(ctx, slot)
    bundle, root = approve_reviews(ctx), tmp_path / "missing-source"
    result = record(root, bundle)
    observed = next(item for item in result.report.snapshot.actions if item.slot == slot)
    assert observed.state == "source_missing" and observed.observed is None
    assert observed.recorded.reservation_json is not None
    assert observed.recorded.coordinator_claims_json
    rows = read_multi_dispatch_journal((root / "journal.jsonl").read_bytes(), ["D", "C"])
    store = ArtifactStore(root / "artifacts", create=False)
    snapshot = json.loads(store.read(rows[0]["payload"]["snapshot"]))
    saved = next(item for item in snapshot["actions"] if item["slot"] == list(slot))
    assert saved["recorded"]["reservation_json"] == observed.recorded.reservation_json
    assert saved["observed"] is None
    assert replay(root, bundle, result.journal_sha256) == result


@pytest.mark.parametrize("kind", ["runner_command", "verifier_command"])
def test_native_timeout_stays_visible_without_confirmed_credit(tmp_path, native_multi, kind):
    def incomplete(child):
        if (child["ticket"].case_id, child["ticket"].kind, child["ticket"].arm) == ("D", kind, "attack"):
            child["facts"].update(termination_kind="timeout", exit_code=None)
    bundle = approve_reviews(native_multi(native_change=incomplete))
    root = tmp_path / "timeout"
    result = record(root, bundle)
    report = result.report.to_dict()
    assert report["confirmed_defect_case_count"] == report["paired_defect_case_count"] == 0
    observed = next(item for item in result.report.snapshot.actions if item.slot == ("D", kind, "attack"))
    assert observed.observed.termination_kind == "timeout" and observed.observed.exit_code is None
    assert replay(root, bundle, result.journal_sha256) == result


def test_oversize_review_is_rejected_before_creating_root(tmp_path, reviewed):
    root = tmp_path / "oversize"
    with pytest.raises(PreregistrationError, match="bounded"):
        record(root, reviewed, reviews={"D": b" " * 10_000_001})
    assert not root.exists()


def test_caller_report_or_snapshot_cannot_supply_recording_authority(recorded, tmp_path):
    root, bundle, result = recorded
    ctx = bundle["ctx"]
    output = tmp_path / "injected"
    with pytest.raises(TypeError):
        record_multi_dispatch_adjudication(output, ctx["plan"], bundle["reviews"],
            source_authority=ctx["authority"], report=result.report)
    assert not output.exists()
    with pytest.raises(TypeError):
        verify_multi_dispatch_recording(root, ctx["plan"], expected_journal_sha256=result.journal_sha256,
            source_authority=ctx["authority"], snapshot=result.report.snapshot)


def test_missing_review_is_explicit_and_retained_with_complete_unknown_denominator(tmp_path, native_multi):
    bundle = approve_reviews(native_multi(selected=set()))
    root = tmp_path / "missing"
    result = record(root, bundle, reviews={})
    rows = read_multi_dispatch_journal((root / "journal.jsonl").read_bytes(), ["D", "C"])
    assert all(rows[index]["payload"]["raw_review"] == ArtifactStore.reference(None) for index in (1, 3))
    assert result.report.to_dict()["verdict_counts"] == {"unknown": 2}
    assert replay(root, bundle, result.journal_sha256) == result


def test_second_recording_refused_and_does_not_touch_closed_bytes(recorded):
    root, bundle, result = recorded
    original = (root / "journal.jsonl").read_bytes()
    with pytest.raises(PreregistrationError, match="fresh_root"): record(root, bundle)
    assert (root / "journal.jsonl").read_bytes() == original
    assert digest(original) == result.journal_sha256


def test_rejected_source_creates_no_partial_recording(tmp_path, reviewed):
    ctx = reviewed["ctx"]
    ctx["authority"].grant = replace(ctx["authority"].grant, evidence_sha256="0" * 64)
    root = tmp_path / "rejected"
    with pytest.raises(AdjudicationError, match="source_reacquisition"): record(root, reviewed)
    assert not root.exists()


@pytest.mark.parametrize("container", [list, tuple])
def test_nonmapping_duplicate_review_pairs_are_not_silently_folded(tmp_path, reviewed, container):
    root = tmp_path / "duplicates"
    pairs = container([("D", reviewed["reviews"]["D"]), ("D", b"{}")])
    with pytest.raises(AdjudicationError, match="raw_bytes"): record(root, reviewed, reviews=pairs)
    assert not root.exists()


def test_interrupted_artifact_sync_cannot_be_resumed_as_a_success(tmp_path, reviewed, monkeypatch):
    root = tmp_path / "interrupted"
    def broken_put(*args): raise OSError("synthetic failed artifact durability")
    monkeypatch.setattr(ArtifactStore, "put", broken_put)
    with pytest.raises(OSError, match="durability"): record(root, reviewed)
    assert not (root / "journal.jsonl").exists()
    with pytest.raises(PreregistrationError, match="fresh_root"): record(root, reviewed)


@pytest.mark.parametrize("damage", ["drop", "duplicate", "reorder", "post_summary", "missing_summary"])
def test_coherent_chain_cannot_drop_duplicate_reorder_or_append_cases(recorded, damage):
    root, bundle, _ = recorded
    def mutation(rows):
        if damage == "drop": rows.pop(2)
        elif damage == "duplicate": rows.insert(2, rows[2])
        elif damage == "reorder": rows[1], rows[3] = rows[3], rows[1]
        elif damage == "post_summary": rows.append(rows[2])
        else: rows.pop()
    changed = rewrite(root, mutation)
    with pytest.raises(PreregistrationError, match="journal"): replay(root, bundle, changed)


@pytest.mark.parametrize("damage", ["snapshot", "row", "validation", "summary", "roster", "plan", "session"])
def test_coherent_artifact_substitution_or_counts_cannot_override_recomputation(recorded, damage):
    root, bundle, _ = recorded
    store = ArtifactStore(root / "artifacts")
    def mutation(rows):
        if damage == "roster": rows[0]["payload"]["case_ids"] = ["C", "D"]
        elif damage in {"plan", "session"}: rows[0]["payload"][damage + "_sha256"] = "0" * 64
        else:
            index, name = {"snapshot": (0, "snapshot"), "row": (2, "row"),
                           "validation": (1, "validation"), "summary": (5, "report")}[damage]
            raw = json.loads(store.read(rows[index]["payload"][name]))
            if damage == "snapshot": raw["acceptance_refs"] = ["synthetic-other-acceptance"]
            elif damage == "row": raw["paired_headline"] = False
            elif damage == "validation": raw["semantic_approval_ref"] = "synthetic-other-approval"
            else: raw["paired_defect_case_count"] = 999
            rows[index]["payload"][name] = store.put(encoded(raw))
    changed = rewrite(root, mutation)
    with pytest.raises(PreregistrationError, match="journal"): replay(root, bundle, changed)


@pytest.mark.parametrize("damage", ["delete", "swap"])
def test_raw_artifact_damage_rejects_even_with_an_intact_journal(recorded, damage):
    root, bundle, result = recorded
    entries = read_multi_dispatch_journal((root / "journal.jsonl").read_bytes(), ["D", "C"])
    path = root / "artifacts" / entries[2]["payload"]["row"]["sha256"]
    if damage == "delete": path.unlink()
    else: path.write_bytes(b"{}")
    with pytest.raises((OSError, PreregistrationError)): replay(root, bundle, result.journal_sha256)


def test_review_source_rejection_during_replay_cannot_borrow_recorded_pass(recorded):
    root, bundle, result = recorded
    bundle["ctx"]["api"].prs["example/reviews", 88]["merged"] = False
    with pytest.raises(PreregistrationError, match="recomputed_journal"): replay(root, bundle, result.journal_sha256)


def test_changed_semantic_grant_during_replay_rejects_previous_adjudication(recorded):
    root, bundle, result = recorded
    grants = (replace(bundle["grants"][0], semantic_approval_ref="synthetic-different-approval"), bundle["grants"][1])
    authority = GitHubMultiDispatchReviewAuthority(bundle["store"], grants=grants)
    with pytest.raises(PreregistrationError, match="recomputed_journal"):
        replay(root, bundle, result.journal_sha256, authority=authority)


def test_archive_source_rejection_during_replay_aborts(recorded):
    root, bundle, result = recorded
    ctx = bundle["ctx"]
    ctx["authority"].grant = replace(ctx["authority"].grant, evidence_sha256="0" * 64)
    with pytest.raises(AdjudicationError, match="source_reacquisition"): replay(root, bundle, result.journal_sha256)


def test_external_raw_digest_is_required_and_not_inferred_from_journal(recorded):
    root, bundle, result = recorded
    with pytest.raises(PreregistrationError, match="external_raw_digest"): replay(root, bundle, "0" * 64)
    with pytest.raises(TypeError):
        verify_multi_dispatch_recording(root, bundle["ctx"]["plan"], source_authority=bundle["ctx"]["authority"])


def test_raw_reencoding_with_new_external_digest_cannot_replace_native_journal(recorded):
    root, bundle, _ = recorded
    path = root / "journal.jsonl"
    data = b"".join(json.dumps(json.loads(line)).encode("ascii") + b"\n" for line in path.read_bytes().splitlines())
    path.write_bytes(data)
    with pytest.raises(PreregistrationError, match="recomputed_journal"):
        replay(root, bundle, digest(data))


def test_regular_journal_is_required_before_reading(recorded):
    root, bundle, result = recorded
    path = root / "journal.jsonl"
    path.unlink()
    path.mkdir()
    with pytest.raises(PreregistrationError, match="regular_file"):
        replay(root, bundle, result.journal_sha256)


@pytest.mark.parametrize("damage", ["bool_sequence", "duplicate_key", "no_final_newline", "blank_line", "crlf"])
def test_native_journal_parser_is_strict(recorded, damage):
    root, _, _ = recorded
    data = (root / "journal.jsonl").read_bytes()
    if damage == "bool_sequence":
        rows = [json.loads(line) for line in data.splitlines()]
        rows[0]["seq"] = True
        body = {key: value for key, value in rows[0].items() if key != "entry_sha256"}
        from smallestlie.campaign.preregistration import canonical_digest
        rows[0]["entry_sha256"] = canonical_digest(body)
        data = b"".join(encoded(row) + b"\n" for row in rows)
    elif damage == "duplicate_key": data = data.replace(b'"seq":1', b'"seq":1,"seq":1', 1)
    elif damage == "no_final_newline": data = data[:-1]
    elif damage == "crlf": data = data.replace(b"\n", b"\r\n")
    else: data += b"\n"
    with pytest.raises(PreregistrationError): read_multi_dispatch_journal(data, ["D", "C"])
