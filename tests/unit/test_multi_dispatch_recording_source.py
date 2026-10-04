"""Synthetic accepted J publication contracts; no actual publication/adoption."""

from copy import deepcopy
from dataclasses import replace
import json

import pytest

from multi_dispatch_helpers import (
    approve_reviews, drop_source, ec_context, make_map, make_multi_map,
    multi_map_templates, native_multi, native_templates, plan, report_state,
)
from test_multi_dispatch_recording import record, recorded, replay, reviewed, rewrite
from smallestlie.campaign.evidence_sources import EcReceiptStore, VerifiedEcReceipt
from smallestlie.campaign.lifecycle import encoded
from smallestlie.campaign.multi_dispatch_recording_source import (
    EcMultiDispatchRecordingAuthority, MultiDispatchRecordingLocation,
    verify_published_multi_dispatch_recording,
)
from smallestlie.campaign.preregistration import PreregistrationError, digest
from smallestlie.campaign.provenance import ProvenanceError


def publish_j(root, bundle, *, conclusion="success", revision="9" * 40):
    ctx, files = bundle["ctx"], {}
    original, api = ctx["root"], ctx["api"]
    old = original.publications[0]
    grant = replace(old, run_id=9000, attempt=2, job_id=9001, receipt_commit=revision,
        acceptance_ref="synthetic separate J publication acceptance",
        supervisor_sha256=None, supervisor_acceptance_ref=None)
    api.runs[original.repository, 9000, 2] = {**deepcopy(api.runs[original.repository, old.run_id, old.attempt]),
        "id": 9000, "run_attempt": 2, "conclusion": conclusion}
    api.jobs[original.repository, 9001] = {**deepcopy(api.jobs[original.repository, old.job_id]),
        "id": 9001, "run_id": 9000, "run_attempt": 2, "conclusion": conclusion}
    files["ec-workload.json"] = encoded({**json.loads(ctx["files"]["ec-workload.json"]),
        "run_id": "9000", "run_attempt": "2"})
    files["J/journal.jsonl"] = (root / "journal.jsonl").read_bytes()
    for path in (root / "artifacts").iterdir():
        files["J/artifacts/" + path.name] = path.read_bytes()
    result = {"root": replace(original, publications=(grant,)), "api": api, "files": files,
        "bundle": bundle, "local_root": root,
        "location": MultiDispatchRecordingLocation("J/journal.jsonl", digest(files["J/journal.jsonl"]), "J/artifacts")}
    republish_j(result)
    return result


def republish_j(ctx):
    root, files, api = ctx["root"], ctx["files"], ctx["api"]
    grant = root.publications[0]
    files["ec-publication.json"] = encoded({"schema_version": 1, "status": "preserved", "context": {
        "GITHUB_RUN_ID": str(grant.run_id), "GITHUB_RUN_ATTEMPT": str(grant.attempt),
        "GITHUB_SHA": grant.ec_source_commit, "GITHUB_JOB": root.job_name, "COMPUTERNAME": root.host,
        "EC_JOB_STATUS": api.jobs[root.repository, grant.job_id]["conclusion"]},
        "files": [{"path": path, "bytes": len(raw), "sha256": digest(raw)}
                  for path, raw in sorted(files.items()) if path != "ec-publication.json"]})
    ctx["root"] = replace(root, publications=(replace(grant, publication_sha256=digest(files["ec-publication.json"])),))
    api.install(root.repository, grant.receipt_commit, files)
    ctx["store"] = EcReceiptStore(ctx["root"], transport=api)
    ctx["authority"] = EcMultiDispatchRecordingAuthority(ctx["store"], ctx["location"])


def verify(ctx, *, recording_authority=None):
    bundle, prepared = ctx["bundle"], ctx["bundle"]["ctx"]["plan"]
    return verify_published_multi_dispatch_recording(prepared,
        recording_authority=ctx["authority"] if recording_authority is None else recording_authority,
        source_authority=bundle["ctx"]["authority"], review_authority=bundle["review_authority"])


@pytest.fixture
def published(recorded):
    root, bundle, result = recorded
    ctx = publish_j(root, bundle)
    ctx["original_recording"] = result
    return ctx


@pytest.mark.parametrize("conclusion", ["success", "failure", "cancelled", "timed_out"])
def test_accepted_own_j_matches_local_fresh_verification_without_supervisor(recorded, conclusion):
    root, bundle, result = recorded
    ctx = publish_j(root, bundle, conclusion=conclusion)
    before = dict(bundle["ctx"]["files"])
    verified = verify(ctx)
    assert verified.recording == replay(root, bundle, result.journal_sha256) == result
    assert (verified.run_id, verified.attempt, verified.job_id) == (9000, 2, 9001)
    assert verified.receipt_commit != result.report.snapshot.final_archive_ref
    assert bundle["ctx"]["files"] == before
    assert not any("supervisor" in path for path in ctx["files"])
    assert verified.recording.report.to_dict()["paired_defect_case_count"] == 1


@pytest.mark.parametrize("field,value", [
    ("journal_path", "J/other.jsonl"), ("journal_sha256", "0" * 64), ("artifacts_prefix", "other/artifacts"),
])
def test_exact_external_j_location_cannot_be_inferred_from_acquired_bytes(published, field, value):
    authority = EcMultiDispatchRecordingAuthority(published["store"], replace(published["location"], **{field: value}))
    with pytest.raises(PreregistrationError):
        verify(published, recording_authority=authority)


@pytest.mark.parametrize("journal,prefix", [
    ("ec-publication.json", "J/artifacts"), ("ec-workload.json", "J/artifacts"),
    ("J/artifacts/journal", "J/artifacts"), ("J/journal.jsonl", "EC-PUBLICATION.JSON"),
    ("J/journal.jsonl", "J/NUL"), ("J/journal.jsonl", "../artifacts"),
])
def test_j_paths_keep_raw_and_metadata_roles_separate(journal, prefix):
    with pytest.raises(PreregistrationError):
        MultiDispatchRecordingLocation(journal, "0" * 64, prefix)


def test_separate_f_and_j_registries_keep_duplicate_request_lock_rejection(published):
    original = published["bundle"]["ctx"]["root"].publications[0]
    with pytest.raises(ProvenanceError, match="ambiguous publication registry"):
        replace(published["root"], publications=(original, published["root"].publications[0]))
    assert verify(published).recording == published["original_recording"]


def test_saved_receipt_or_output_carrier_cannot_supply_j_authority(published):
    verified = verify(published)
    for carrier in (verified, VerifiedEcReceipt(published["root"].publications[0], tuple(published["files"].items()))):
        with pytest.raises(ProvenanceError, match="exact external immutable J authority"):
            verify(published, recording_authority=carrier)


def test_caller_store_hooks_are_ignored_and_native_gets_are_required(published):
    store, api = published["store"], published["api"]
    store.read = store._files = lambda *args: pytest.fail("instance hook acquired authority")
    store.reader = object()
    before = len(api.calls)
    assert verify(published).recording == published["original_recording"]
    assert len(api.calls) > before
    assert ("run", store.root.repository, 9000, 2) in api.calls


@pytest.mark.parametrize("changed", ["location", "publication", "source", "review", "transport"])
def test_imported_configuration_swap_during_j_get_is_rejected(published, monkeypatch, changed):
    api, bundle = published["api"], published["bundle"]
    original = api.workflow_run
    switched = False

    def acquire(repo, run, attempt):
        nonlocal switched
        result = original(repo, run, attempt)
        if run == 9000 and not switched:
            switched = True
            if changed == "location":
                published["authority"].location = replace(published["location"], journal_sha256="0" * 64)
            elif changed == "publication":
                root = published["store"].root
                published["store"].root = replace(root, publications=(replace(root.publications[0], acceptance_ref="changed"),))
            elif changed == "source":
                authority = bundle["ctx"]["authority"]
                authority.grant = replace(authority.grant, mapping_acceptance_ref="changed")
            elif changed == "review":
                authority = bundle["review_authority"]
                authority.grants = (replace(authority.grants[0], semantic_approval_ref="changed"), *authority.grants[1:])
            else:
                published["store"].transport = object()
        return result

    monkeypatch.setattr(api, "workflow_run", acquire)
    with pytest.raises(PreregistrationError):
        verify(published)
    assert switched


def test_transient_review_registry_restore_cannot_lend_previously_saved_approval(published, monkeypatch):
    api, authority = published["api"], published["bundle"]["review_authority"]
    accepted = authority.grants
    revoked = (replace(accepted[0], review_sha256="0" * 64), *accepted[1:])
    authority.grants = revoked
    workflow_run, pull_request = api.workflow_run, api.pull_request
    switched, restored = False, False

    def source_get(repo, run, attempt):
        nonlocal switched
        result = workflow_run(repo, run, attempt)
        if run != 9000:
            authority.grants = accepted
            switched = True
        return result

    def review_get(repo, number):
        nonlocal restored
        result = pull_request(repo, number)
        if number == 89:
            authority.grants = revoked
            restored = True
        return result

    monkeypatch.setattr(api, "workflow_run", source_get)
    monkeypatch.setattr(api, "pull_request", review_get)
    with pytest.raises(PreregistrationError, match="recomputed_journal_mismatch"):
        verify(published)
    assert switched and restored and authority.grants == revoked


@pytest.mark.parametrize("damage", ["missing", "bytes", "extra", "case_alias", "truncated_tree"])
def test_accepted_publication_still_requires_exact_j_artifact_closure(published, damage):
    files = published["files"]
    path = next(path for path in files if path.startswith("J/artifacts/"))
    if damage == "missing":
        del files[path]
    elif damage == "bytes":
        files[path] += b"damage"
    elif damage == "extra":
        files["J/artifacts/" + digest(b"unreferenced")] = b"unreferenced"
    elif damage == "case_alias":
        files[path.upper()] = files[path]
    republish_j(published)
    if damage == "truncated_tree":
        oid = published["api"].commits[published["root"].repository, "9" * 40]["tree"]["sha"]
        published["api"].trees[published["root"].repository, oid]["truncated"] = True
    with pytest.raises(PreregistrationError):
        verify(published)


@pytest.mark.parametrize("role", ["product", "phase1", "archive", "mapping", "anchor", "action", "admission", "ec", "review"])
def test_known_j_output_alias_rejects_before_unavailable_get(published, role):
    ctx = published["bundle"]["ctx"]
    child = next(item.authority for item in ctx["authority"].actions if item.authority is not None)
    revisions = {"product": ctx["plan"].request.source_commit, "phase1": ctx["plan"].lock()["phase1_commit"],
        "archive": ctx["root"].publications[0].receipt_commit, "mapping": ctx["grant"].evidence_commit,
        "anchor": ctx["anchor"].commit, "action": child.store.root.publications[0].receipt_commit,
        "admission": child.admission.evidence_commit, "ec": child.store.root.publications[0].ec_source_commit,
        "review": published["bundle"]["store"].root.human_approvals[0].merge_commit}
    root = replace(published["root"], publications=(replace(published["root"].publications[0], receipt_commit=revisions[role]),))
    authority = EcMultiDispatchRecordingAuthority(EcReceiptStore(root, transport=published["api"]), published["location"])
    published["api"].calls.clear()
    with pytest.raises(ProvenanceError, match="J output aliases"):
        verify(published, recording_authority=authority)
    assert not published["api"].calls


@pytest.mark.parametrize("kind", ["semantic", "human", "source"])
def test_j_acceptance_cannot_borrow_other_approval_roles(published, kind):
    bundle = published["bundle"]
    reference = (bundle["grants"][0].semantic_approval_ref if kind == "semantic" else
        bundle["store"].root.human_approvals[0].reference if kind == "human" else
        bundle["ctx"]["root"].publications[0].acceptance_ref)
    root = replace(published["root"], publications=(replace(published["root"].publications[0], acceptance_ref=reference),))
    with pytest.raises(ProvenanceError, match="J acceptance aliases"):
        verify(published, recording_authority=EcMultiDispatchRecordingAuthority(
            EcReceiptStore(root, transport=published["api"]), published["location"]))


@pytest.mark.parametrize("changes", [{"repository": "EXAMPLE/PRODUCT"}, {"repository_id": 303}, {"repository_id": 404}])
def test_j_repository_role_alias_rejects_before_native_get(published, changes):
    root = replace(published["root"], **changes)
    authority = EcMultiDispatchRecordingAuthority(EcReceiptStore(root, transport=published["api"]), published["location"])
    published["api"].calls.clear()
    with pytest.raises(ProvenanceError, match="repository"):
        verify(published, recording_authority=authority)
    assert not published["api"].calls


def test_fresh_semantic_revocation_cannot_borrow_closed_j_pass(published):
    authority = published["bundle"]["review_authority"]
    authority.grants = authority.grants[1:]
    with pytest.raises(PreregistrationError, match="recomputed_journal_mismatch"):
        verify(published)


def test_fresh_source_rejection_cannot_borrow_closed_j_pass(published):
    ctx = published["bundle"]["ctx"]
    item = next(item for item in ctx["authority"].actions if item.slot == ("D", "runner_command", "attack"))
    grant = item.authority.store.root.publications[0]
    ctx["api"].jobs[item.authority.store.root.repository, grant.job_id]["status"] = "in_progress"
    with pytest.raises(PreregistrationError, match="recomputed_journal_mismatch"):
        verify(published)


def test_coherent_accepted_j_substitution_still_fails_fresh_engine(published):
    expected = rewrite(published["local_root"], lambda rows: rows[0]["payload"].update(plan_sha256="0" * 64))
    published["files"]["J/journal.jsonl"] = (published["local_root"] / "journal.jsonl").read_bytes()
    published["location"] = replace(published["location"], journal_sha256=expected)
    republish_j(published)
    with pytest.raises(PreregistrationError, match="recomputed_journal_mismatch"):
        verify(published)


def test_complete_missing_sources_and_reviews_remain_unknown_in_accepted_j(tmp_path, native_multi):
    ctx = native_multi()
    for item in ctx["members"]:
        drop_source(ctx, item.slot)
    bundle, root = approve_reviews(ctx), tmp_path / "unknown"
    result = record(root, bundle, reviews={})
    published = publish_j(root, bundle)
    verified = verify(published).recording
    assert verified == result
    report = verified.report.to_dict()
    assert report["frozen_case_count"] == 2 and report["paired_defect_case_count"] == 0
    assert all(row.verdict == "unknown" for row in verified.report.cases)


def test_true_kill_with_missing_twin_repair_and_reviews_survives_publication(tmp_path, native_multi, plan):
    ctx = native_multi(native_change=report_state(plan, "attack", "red"))
    for arm in ("repair", "twin"):
        drop_source(ctx, ("D", "runner_command", arm))
    bundle, root = approve_reviews(ctx), tmp_path / "killed"
    result = record(root, bundle, reviews={})
    verified = verify(publish_j(root, bundle)).recording
    assert verified == result and verified.report.cases[0].verdict == "killed_candidate"
    assert verified.report.to_dict()["paired_defect_case_count"] == 0


def test_unobserved_recorded_receipt_cannot_be_reused_as_j_output(tmp_path, native_multi):
    ctx = native_multi()
    slot = ("D", "runner_command", "attack")
    original = ctx["children"][slot]["root"].publications[0].receipt_commit
    drop_source(ctx, slot)
    bundle, root = approve_reviews(ctx), tmp_path / "missing-claim"
    record(root, bundle)
    with pytest.raises(ProvenanceError, match="J output aliases"):
        verify(publish_j(root, bundle, revision=original))
